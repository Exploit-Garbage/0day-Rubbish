# Veeam ONE Reporter — Authenticated RCE / Privilege Escalation via CommandExecutor

## 1. Product & Attack Surface

Veeam ONE Reporter 13.1 (Veeam Software, IT monitoring/reporting, .NET 10 + ASP.NET Core 10 + IIS + SQL Server) exposes a self-hosted Web API service `Veeam.Reporter.Service.exe` listening on HTTPS:1345 via HTTP.sys. Reverse engineering 13,738 .cs files (ILSpy/ilspycmd) and scanning PROCESS/deserialization/SQL sinks identified `CommandExecutor.RunCommandAsync` as the only real command-execution sink.

## 2. Sink Analysis: CommandExecutor

`CommandExecutor.RunCommandAsync(reportValues, outputFolder, command, scriptCredentialId, cancelToken)`:

- **FormatCommand**: replaces placeholders (`%DashboardName%`/`%JobName%`/`%ReportFileName%`/`%ReportsFolder%`) in `command`
- **ParseCommand**: if command starts with `"`, extracts the quoted portion as FileName, rest as Arguments; otherwise splits on spaces (first token FileName, rest Arguments)
- **MakeProcess**: constructs `ProcessStartInfo(FileName, Arguments)`
- **process.Start()**: launches the process

**Key flaws**:
1. **ValidateCommand not called**: it only checks `File.Exists(exe)` when saving a schedule; the execution path never validates and does not restrict script extensions → `cmd.exe`/`powershell.exe` pass
2. **No privilege drop**: the process inherits the Reporter Service context = `.\VeeamSvc` (local Administrators member)
3. **Command fully user-controlled**: `taskConfig.ReportSettings.Command` comes from the schedule-creation request body with no whitelist/escaping

## 3. Trigger Chain: JobReportingDashboard.Execute

```
Generate (screenshot PNG) → SendMail → [OutputFolder empty? return] → CopyToOutputFolder (save PNG) → [Command empty? skip] → RunScript → CommandExecutor.RunCommandAsync
```

**Key gates and bypasses**:
- **SendMail runs before RunScript**: if SendMail throws, Execute aborts and the command never runs. The early attempts' root cause was unset `emailSettings` → `new ReportEmailMessage(null)` NRE (`emailSettings.Subject` null) → `InternalErrorException`.
- **Bypass**: set `emailSettings` with empty recipients (`to/cc/bcc=""`) → `EmailService.HaveAnyRecipient(msg)` returns false → SendMail returns early ("Email recipient is not set") without throwing → Execute continues.
- **Generate timeout still produces PNG**: `Veeam.Capture.exe` WaitToLoad 5min timeout does not throw; it still writes the PNG to temp → `CopyToOutputFolder` saves it → RunScript triggers.
- **OutputFolder must be non-empty**: otherwise Execute returns after SendMail ("No output folder").

## 4. Authentication & Role Gates

- Login: `POST /api/token` (grant_type=password) → JWT HS256 (per-install random key)
- PostSchedule role gate: `[AllowRoles(AccessTokenRole.Admin, AccessTokenRole.PowerUser, AccessTokenRole.BackupAdministrator)]` = (1, 2, 12)
  - ILSpy could not decode attribute args; Mono.Cecil metadata `ConstructorArguments` confirmed = (1, 2, 12)
- **PowerUser (role 2)**: a Reporter delegated application role assignable to non-OS-admin domain users (authentication via Windows/AD/SAML; roles assigned in Reporter user management, independent of OS privileges)

## 5. Privilege Escalation Argument (CWE-269)

- The Admin/PowerUser role distinction implies PowerUser should not have admin-level OS privileges
- The Command field executes as the local-admin service account (VeeamSvc) with no privilege drop, no whitelist
- Delegating a non-OS-admin PowerUser → local-admin command execution breaks the Admin/PowerUser boundary

## 6. Dynamic Verification

### 6.1 Environment

Veeam ONE 13.1 Community edition on Windows Server (license/signature gates patched with Cecil for research only).

### 6.2 Steps

1. `POST /api/token` login to obtain a JWT (grant_type=password).
2. Create dashboard (name="RCE_<nonce>").
3. `POST /api/v2.3/dashboards/<id>/schedules` create a 1-min periodic schedule with this body:

```json
{"scheduleSettings":{"periodically":{"interval":"Minutes","period":1},"disabled":false,"timeZoneId":"UTC","startTime":"<ISO_TIME>","scheduleType":"Periodic"},
 "emailSettings":{"subject":"rce","to":"","cc":"","bcc":""},
 "reportSettings":{"command":"\"C:\\Windows\\System32\\cmd.exe\" /c whoami > C:\\Windows\\Temp\\veeam_rce_proof.txt 2>&1","outputFolder":"C:\\Windows\\Temp"}}
```

4. Wait for the 1-min schedule to fire.

### 6.3 Evidence

- Marker file `C:\Windows\Temp\veeam_rce_proof.txt` = `whoami` output showing `veeamsvc`; mtime matches the scheduled run
- Task log: `-->RunScript` → `"Trying to execute ..."` → `-->RunCommandImplAsync Executing batch file` → `State changed to "FinishedWithSuccess"`
- PNG saved by CopyToOutputFolder (19,306 bytes)
- `net localgroup administrators` confirms `VeeamSvc` is a local Administrators member

### 6.4 Key Gates and Bypasses

- **SendMail before RunScript**: if SendMail throws, Execute aborts and the command never runs. Empty-recipient `emailSettings` makes `HaveAnyRecipient` return false, so SendMail returns early without throwing.
- **Generate timeout still produces PNG**: `Veeam.Capture.exe` WaitToLoad 5-min timeout does not throw; the PNG is still written.
- **OutputFolder must be non-empty**: otherwise Execute returns after SendMail.

### 6.5 Reproduction Commands

```bash
# 1. Login
curl -k -X POST "https://<TARGET_IP>:1345/api/token" -d "grant_type=password&username=<USER>&password=<PASSWORD>&ui_login=true"

# 2. Create a dashboard, then a 1-min schedule with reportSettings.command
#    (see the PoC script for the full flow)
python3 veeam_one_commandexecutor_rce.py --host <TARGET_IP> --port 1345 \
  --user '<DOMAIN>\<USER>' --pass '<PASSWORD>' \
  --cmd 'whoami > C:\Windows\Temp\veeam_rce_proof.txt 2>&1' \
  --marker 'C:\Windows\Temp\veeam_rce_proof.txt'
```

## 7. Unauthenticated RCE Exhaustion (Target A stop-loss)

By the FUE Gate 8 dimensions: no unauthenticated business endpoints, authentication not bypassable (JWT random key + DB role read + jti revocation + SAML signature + no default password), no unauthenticated hardcoded credentials, no non-HTTP unauthenticated surface. Target A is architecturally unreachable → this is a Target B (post-auth) vulnerability.

## 8. Impact & Fix Recommendations

**Impact**: Post-auth RCE / privilege escalation: low-privilege PowerUser → local admin code execution on the Reporter server.

**Fix recommendations**:
1. Drop privileges before executing the Command field
2. Whitelist allowed executables/scripts or sandbox execution
3. Restrict the Command feature to Admin (role 1); PowerUser should not reach it
4. Validate command extensions and paths at runtime

## 9. Timeline & Disclosure Status

- Research completed and dynamically verified: 2026-08
- Vendor notification, CVE, and public disclosure channels: pending operator approval (Batch #6)
