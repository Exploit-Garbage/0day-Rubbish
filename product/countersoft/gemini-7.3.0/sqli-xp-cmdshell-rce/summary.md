# Countersoft Gemini Authenticated SQL Injection to xp_cmdshell RCE

## Summary

An authenticated SQL injection vulnerability in Countersoft Gemini allows a user with valid credentials to achieve remote code execution on the database server. The `MakeSafeLike` function used for LIKE-query sanitization escapes only the `[` character and not the single quote, so an attacker-controlled `term` parameter in `GET /workspace/{id}/item/get/customfield` breaks out of the SQL string literal. Because the application connects to SQL Server as `sa` (sysadmin), stacked queries can enable `xp_cmdshell` and execute OS commands. Combined with the shipped default credentials `manager/manager` (VULN-002), a default installation is close to unauthenticated RCE.

## CVSS Score

- **Score**: 8.8 High (authenticated; low-privilege role to OS command execution)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Countersoft Gemini (ITSM / helpdesk / project management)
- **Versions**: 7.3.0 (build 7.6.2.8445) (other versions with the same MakeSafeLike implementation are likely affected)
- **Vendor**: Countersoft

## Impact

- **Confidentiality**: Full database access (sa/sysadmin); OS command execution via xp_cmdshell
- **Integrity**: Database modification; OS command execution as `nt service\mssql$sqlexpress` (High integrity, SeImpersonate privilege → SYSTEM via potato)
- **Availability**: Full control of database server and application

## Mitigation

1. Fix `MakeSafeLike` to escape single quotes or use parameterized queries
2. Use a least-privilege database account instead of `sa`/sysadmin
3. Enforce password change on first login (default manager/manager)
4. Restrict IIS/web app to trusted networks
