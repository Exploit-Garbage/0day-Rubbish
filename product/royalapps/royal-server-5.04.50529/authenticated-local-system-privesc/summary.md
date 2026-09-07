# Royal Server — Authenticated Local Privilege Escalation to LocalSystem

## Summary

Royal Server 5.04.50529.0 (Royal Apps GmbH, Germany; .NET 10 / ASP.NET Core, Windows MSI) registers the Windows service `RoyalServer` running as **LocalSystem**, listening on 54899/TCP HTTPS. The Script module has two execution paths in its sink (`oclor.cs`): the remote path `fmgvg` sets Domain/UserName/Password on `ProcessStartInfo` before `Process.Start`, but the local path **`fmgvf` — selected when a request carries no destination credentials, with empty destinations auto-filled to `localhost` — spawns its child process with no credential override**, so the child inherits the service process token. The WorkerAccount impersonation wrapper (`ufwmz.ExecuteAs`, `LogonType.NewCredentials` = 9) only substitutes outbound network credentials and never changes the local execution identity.

An authenticated member of the "Royal Server Users" role (the product's design-intended module-access role, granted by an administrator) submits a script at `POST /managementendpoint` with empty destination fields; when WorkerAccount is configured and psexec.exe is present (hardcoded call at `oclor.cs:43`), the script executes as **LocalSystem** on the gateway host. Verified end-to-end: HTTP 200 + PsExec banner in the response, marker file `nt authority\system` (hex-confirmed), service StartName=LocalSystem. Conditional, honestly-scoped privesc — the role grant itself is by-design access, the defect is the execution identity (CWE-250/CWE-269, explicitly not CWE-862).

## CVSS Score

- **Score**: 7.2 High
- **Vector**: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H
- **Class**: authenticated local privilege escalation, conditional (3 preconditions below)

## Affected Products

- **Product**: Royal Server (enterprise remote-management gateway, Windows)
- **Versions**: 5.04.50529.0 verified; any build where `fmgvf` spawns child processes without credential override is affected
- **Vendor**: Royal Apps GmbH (Germany)
- **Preconditions** (all three): authenticated user in "Royal Server Users" role (granted by an admin); WorkerAccountSettings non-empty; psexec.exe available on the host

## Impact

- **Privilege**: LocalSystem — the highest local Windows privilege: full file system/registry/SAM access, service installation, persistence, logon-session credential capture
- **Position**: the gateway brokers script/process execution toward managed hosts and holds destination connection data — LocalSystem enables tampering with management operations and pivoting to every host it manages

## Mitigation

1. Force the credential context on the local path: `fmgvf` must set WorkerAccount Domain/UserName/Password on `ProcessStartInfo` before `Process.Start`, mirroring `fmgvg`
2. Restrict script execution strictly to the WorkerAccount: reject requests without destination credentials instead of silently degrading to the service token
3. Review the role model: whether "Royal Server Users" may trigger Script-module execution, and under which identity, should be an explicit configuration decision
4. Correct the impersonation semantics: `LogonType.NewCredentials` cannot constrain local child processes — use a full logon plus `CreateProcessAsUser`
5. Defense in depth: run the service under a dedicated low-privilege account instead of LocalSystem; audit the hardcoded PsExec dependency
