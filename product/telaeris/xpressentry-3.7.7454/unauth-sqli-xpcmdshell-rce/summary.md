# Telaeris XPressEntry Unauthenticated SQL Injection RCE

## Summary

Telaeris XPressEntry 3.7.7454 exposes an unauthenticated HTTP API on port 30000 (`RequireReaderCredentials=False` by default). The `SaveVerifyActivity` handler concatenates the attacker-controlled `message_content`/`sNotes` value raw into an INSERT statement. On SQL Server backends the application connection is `sysadmin`; a crafted stacked-query payload uses a COMMIT-breakout to escape the queue transaction, then enables `xp_cmdshell` and executes commands — unauthenticated RCE as `NT SERVICE\MSSQL$SQLEXPRESS`. Dynamically verified over a real HTTP request with no credentials.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Telaeris XPressEntry
- **Versions**: 3.7.7454
- **Vendor**: Telaeris Inc

## Impact

- **Confidentiality**: Full read of the SQL Server database as the service account
- **Integrity**: Arbitrary command execution via `xp_cmdshell`
- **Availability**: Full control of the XPressEntry host and database

## Exploitation Prerequisites

Default configuration (`RequireReaderCredentials=False`); SQL Server backend (enterprise/DoD deployments); application DB account with `sysadmin`; network reachability to port 30000.

## Mitigation

1. Parameterize the INSERT in `SaveVerifyActivity`
2. Run the application DB account as least privilege (revoke `sysadmin`, disable `xp_cmdshell`)
3. Default `RequireReaderCredentials` to True and enforce auth on write endpoints
4. Validate/whitelist `message_content` before queue insertion

## Timeline

- **Discovered**: 2026-07-24
- **Public Disclosure**: 2026-08-12 (batch #4)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble.
