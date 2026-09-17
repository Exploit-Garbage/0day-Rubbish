# Devolutions Server (DVLS) — Bypassable PAM Entitlement Gate Exposes the `test-script` PowerShell Sink: Administrator to `NT AUTHORITY\SYSTEM`

## Summary

Devolutions Server (DVLS) 2026.2.14.0 gates its PAM module behind the `[ProductRequired]` attribute, which returns `403 {"message":"License  is required"}` when no PAM entitlement is present. The gate's helper `ProductRequiredAttribute.IsCredentialFromPamSystemVault()` decides whether a request concerns a PAM system-vault credential by substring-matching `uri.AbsoluteUri` — built from `Request.GetDisplayUrl()`, and therefore including the **query string** — against `PamConstants.PamSystemVaultIds`, a `static readonly` list of eight GUIDs hard-coded in the binary and identical on every installation (`PamSystemVaultID = ff7b757a-cdca-4a11-9dc6-d59989647279`). Appending that constant as a query parameter makes the check true, and because `PamIsAvailable()` contains the early return `if (flag && IsCredentialFromPamSystemVault(context, sessionContext)) return true;` — where `flag` is `HasInfrastructureVaultAccess`, i.e. administrative permission 3000 or 3001, which every `IsAdministrator` user holds automatically along with all other `AdministrativePermission` values — the gate passes with no licence validation at all. Licence signature verification (`DevolutionsLicenseManager.DecodeToken`) is never reached and was never forgeable; the defect is the early return above it.

Behind the gate sits `PamProviderTemplateController.TestCommandScript` (`POST /api/pam/provider-templates/test-script`), which passes the fully user-controlled `[FromBody]` field `Script` to `PowershellScriptRunner` with no filtering, allow-list or sandbox. `UseNewWinRm` is hard-coded `true`, so execution goes through `ExecuteWinRMScript()`; with `CustomCredential=null` the unset `Hostname` falls back to `Environment.MachineName`, i.e. WinRM to localhost on port 5985. Because DVLS runs as the Windows service `DevolutionsServerKestrel` under `LocalSystem`, the script executes as `NT AUTHORITY\SYSTEM` on the vault host.

Verified dynamically on a Windows Server 2025 lab host with a full DVLS 2026.2.14.0 install, SQL Server Express back end, HTTP management endpoint on `127.0.0.1:9444`, default-enabled WinRM (5985/http) and **no PAM licence** (`GET /api/security/licenses` → `[]`; DB `AppSettings.LicenseStateDayCounters={"DaysInFree":1,"DaysInPaid":0,"DaysInTrial":0}`). With one administrator token and one identical request body, the baseline returned `HTTP 403 {"message":"License  is required"}` and the GUID-injected request returned `HTTP 200 [" : nt authority\\system"]`; `whoami /groups` confirmed `S-1-5-18` and `Mandatory Label\System Mandatory Level S-1-16-16384`; a marker file written to `C:\Windows\Temp\poc_marker.txt` contained `PWNED-BY-POC-SYSTEM`, was owned by `NT AUTHORITY\SYSTEM`, was re-read over an independent SSH session, and the WinRM output reported `Home : C:\Windows\system32\config\systemprofile`. Two independent review passes (six-dimension falsification attempt plus from-scratch re-analysis with a unique timestamp-derived marker in the 200 response, ruling out caching) both CONFIRMED.

**Target A (unauthenticated RCE) was not achieved and is reported as a negative result:** all 11 `[AllowAnonymous]` endpoints are sink-free, authentication is enforced twice (middleware principal plus the DB-backed `LoginHistory` lookup in `TokenManager.IsTokenValid()`), and seven constructed bypass paths were excluded with two independent reviews agreeing. This finding is therefore an authenticated privilege-boundary defect, not an unauthenticated one.

This is a privilege-boundary and entitlement-gate security defect: the PAM web-administration scope must not be equivalent to OS-level `SYSTEM` execution on the vault host, and the gate protecting that capability must not be answerable by echoing a constant recovered from the product's own binaries.

## CVSS Score

- **Score**: 9.1 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
- **Rationale**: `PR:H` — a DVLS administrator account is genuinely required and the product ships no default credential (the administrator password is set at installation). `S:C` — impact crosses out of the PAM application's security scope into the host operating system, where the attacker gains `SYSTEM`, the vault's storage and cryptographic material, and trusted reach into every managed system. Conservative alternative reading: if a PAM administrator is judged unable to exceed their authorized scope, `S:U` applies and the same vector scores **7.2**.
- **CWE**: CWE-862 (Missing Authorization), CWE-285 (Improper Authorization), CWE-78 (OS Command Injection)

## Affected Products

- **Product**: Devolutions Server (DVLS) — credential vault / PAM / remote-session broker
- **Vendor**: Devolutions (Canada)
- **Version verified**: 2026.2.14.0
- **Likely affected more broadly**: any release sharing this gate implementation — an entitlement check that substring-matches the full request URL (query string included) against the hard-coded `PamConstants.PamSystemVaultIds` GUIDs, combined with the `Environment.MachineName` localhost WinRM fallback in `PowershellScriptRunner.ExecuteWinRMScript()`. Other releases were not tested; the version range is not documented in the research record.
- **Prerequisites**: a DVLS administrator account (`IsAdministrator=true`), HTTP reachability of the management port (9444 default). No PAM licence, no special PAM role, no MITM, no default credentials required. Default configuration is sufficient.

## Impact

- **Execution identity**: `NT AUTHORITY\SYSTEM` (S-1-5-18, System Mandatory Level S-1-16-16384) on the vault host — full control of the OS: files, registry, services, local credential stores (LSA secrets, SAM), persistence, security-product tampering.
- **Confidentiality**: the vault application's configuration, its SQL Server back-end connection, and the on-disk and cryptographic material protecting stored credentials all become readable — the host OS *is* the boundary protecting the vault.
- **Integrity**: stored credentials, vault configuration and host state become fully writable; the attacker controls both the vault's contents and what it reports.
- **Availability**: the vault service and the host can be stopped or destroyed at will.
- **Lateral movement**: a PAM vault holds privileged credentials for the infrastructure it manages (servers, network devices, databases, service accounts) and the session-broker role gives it trusted reach toward exactly those systems — host compromise converts one web-admin account into a pivot across the managed estate.
- **Who is affected**: any DVLS administrator, including low-trust or shared administrative accounts; installations with no PAM licence are affected too, contradicting the assumption that unlicensed modules are inert attack surface.
- **Detectability**: the bypass request differs from a legitimate script test only by a meaningless extra query parameter, and execution occurs inside a localhost WinRM session outside the application's own audit view.

## Mitigation

1. Decide entitlement from the resource, not from the request URL: match the path only (`context.HttpContext.Request.Path.Value`) or bind the vault/checkout identifier as a route parameter (`{vaultId:guid}`) / take it from the body object the action consumes, so a bystander query parameter cannot supply it.
2. Never use a fixed constant as an authorization input: the `PamSystemVaultIds` GUIDs are identical on every installation and recoverable from the binaries; replace the constant comparison with a data-store lookup that verifies the credential actually belongs to the system vault.
3. Decouple host-execution capability from the licence gate: run user-controlled script testing under a restricted identity, in a sandbox or constrained-language mode, with an explicit target host and explicit credentials required, and log/audit the script content — entitlement alone must never be the only protection on a PowerShell sink.
4. Remove the silent `Environment.MachineName` localhost fallback: require an explicit target host, refuse local execution unless the operator deliberately selects it, and use a least-privilege account rather than `LocalSystem`.
5. Operator hardening until a fix ships: restrict the management port to a dedicated administration network; treat every DVLS administrator account as holding SYSTEM on the vault host; prune administrative accounts; enable WinRM session-creation auditing and PowerShell script-block logging on the vault host; run the vault on a dedicated, isolated host.
