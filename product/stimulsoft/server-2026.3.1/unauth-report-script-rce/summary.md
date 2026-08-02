# Stimulsoft Server Unauthenticated Report Script RCE

## Summary

A critical remote code execution vulnerability in Stimulsoft Server allows unauthenticated remote attackers to achieve arbitrary code execution as `NT AUTHORITY\SYSTEM` by abusing the default-open `/1/signup` registration (no email activation required) to obtain a Supervisor role, uploading a malicious `.mrt` report template containing an embedded C# script, and triggering the report-script engine which compiles the script with `CSharpCodeProvider` in full trust (no AppDomain isolation, no CAS sandbox) and instantiates the report class, executing the attacker-controlled constructor.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Stimulsoft Server
- **Versions**: 2026.3.1 and versions with the same default-open signup and `AllowReportCompilation=true` configuration
- **Vendor**: Stimulsoft

## Impact

- **Confidentiality**: Full system compromise; the report task executes in the backend service process `Stimulsoft.Server.Agent.exe` running as `NT AUTHORITY\SYSTEM`, giving the attacker full read access to all report data, configuration, and the underlying host
- **Integrity**: Arbitrary code execution as `NT AUTHORITY\SYSTEM`; ability to create/modify files anywhere on the host, alter report templates, and pivot to other services
- **Availability**: Full control of the backend service and host; ability to terminate processes, delete data, or ransomware the host

## Exploitation Prerequisites

This **is** a default-configuration unauthenticated RCE. A pristine install of Stimulsoft Server 2026.3.1 ships with `/1/signup` open by default (`ShowSignUp=true`) and email activation disabled (`ActivationByEmail=false`), so an anonymous attacker registers and immediately receives a Supervisor account (`IsSupervisor`/`IsAdministrator`/`IsSystem` all true, `ItemReportTemplates:All`). The default database is SqlCe (no external DB required), the default `AllowReportCompilation=true` permits the C# script engine, and the report task runs in the backend service process as `NT AUTHORITY\SYSTEM`. No credentials, no SMTP, no administrator action, and no non-default configuration is required. The only network prerequisite is reachability of the Stimulsoft Server port (default 40010, bound to `0.0.0.0` in production).

## Mitigation

1. Disable default-open registration: set `ShowSignUp=false` (or add administrator approval / enforce `ActivationByEmail=true` with strict verification)
2. Downgrade the registered-user role: new signups should default to `Guest`, not `Supervisor`; `Supervisor` should only be created manually by an administrator at install time
3. Sandbox the report-script engine: use a restricted AppDomain with a `PermissionSet` granting only execution (no File/Process/Reflection), plus a class allowlist; or disable `AllowReportCompilation` entirely (Interpretation mode only)
4. Downgrade the backend service: `StimulsoftServerAgent` should not run as `LocalSystem`; use a low-privileged service account
5. Audit script content before compilation: scan for dangerous sinks (`Process.Start`, `File.IO`, `Reflection`, `Assembly.Load`) and reject scripts containing them

## Timeline

- **Discovered**: 2026-07-31
- **Public Disclosure**: 2026-08-10

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
