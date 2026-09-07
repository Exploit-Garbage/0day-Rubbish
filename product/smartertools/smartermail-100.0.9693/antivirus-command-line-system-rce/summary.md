# SmarterMail — Antivirus Command-Line Configuration → RCE as NT AUTHORITY\SYSTEM

## Summary

SmarterMail 100.0.9693 (Build 9693) runs its mail engine — delivery, spool processing and virus scanning — inside the Windows service `MailService.exe` as **NT AUTHORITY\SYSTEM**. The antivirus feature exposes two command settings to the SysAdmin role: `commandLine` (persisted as `virus_command_path`) and `spoolCommandLineFile` (persisted as `virus_spool_exe_command_line`). Both are resolved as script paths relative to the product's `Settings\Assets\` directory and both are launched with `Process.Start()` by the SYSTEM service when mail flows through the pipeline. The only containment is a path-canonicalization guard that blocks `..\` traversal *out of* Assets — it builds no barrier against a script *planted inside* that directory, and nothing validates that the configured value is a known antivirus engine rather than an arbitrary batch file.

A SysAdmin who places a BAT inside Assets and sets `commandLine` to its bare filename converts a product-scope configuration write into full OS command execution as the Windows super-identity. One inbound email (SMTP `AUTH LOGIN`, EICAR body) triggers the virus scanner; a second, independent vector exists through the spool processor's `spoolCommandLineFile`. Verified end-to-end in a lab: markers written as `nt authority\system` by both code paths. No NVD match — historical SmarterMail CVEs are deserialization/SQLi classes on different surfaces; this is a distinct configuration-driven SYSTEM execution flaw.

## CVSS Score

- **Score**: 7.2 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
- **Class**: authenticated privilege escalation (web SysAdmin role → OS SYSTEM), Target B

## Affected Products

- **Product**: SmarterMail (enterprise mail server, Windows)
- **Versions**: 100.0.9693 verified; any build whose antivirus `commandLine` / `spoolCommandLineFile` settings are resolved relative to `Settings\Assets\` and spawned by MailService.exe as SYSTEM is likely affected
- **Vendor**: SmarterTools Inc. (USA)
- **Prerequisites**: valid SysAdmin credentials; a script file inside `Settings\Assets\` (the PoC plants it through the product's authenticated upload surface, with a manual-placement fallback)

## Impact

- **Confidentiality**: SYSTEM on a mail server reads every mailbox, TLS key material, spool contents and OS credentials — organization-wide blast radius
- **Integrity / persistence**: tamper with stored mail and mail-flow rules; the malicious `virus_command_path` persists in `settings.json` and re-executes on every inbound email until reverted
- **Availability**: mail service, spool and domains can be stopped, corrupted or wiped

## Mitigation

1. Allowlist the command: validate `commandLine` / `spoolCommandLineFile` against vendor-signed, known-good scanner binaries — absolute path, fingerprint re-verified before every spawn (CWE-78)
2. Drop privileges: run MailService.exe under a dedicated low-privilege service account, spawn scanner children with restricted tokens (CWE-250 root fix)
3. Lock the `Settings\Assets\` directory: vendor-signed assets only, no write/execute ACLs for other identities, reject uploads of executable content
4. Harden the settings path: re-authentication for antivirus-setting changes, alert on non-default `virus_command_path` values
5. Detect: audit SYSTEM-spawned interpreters whose parent is MailService.exe and whose command line resides under `Settings\Assets\`
