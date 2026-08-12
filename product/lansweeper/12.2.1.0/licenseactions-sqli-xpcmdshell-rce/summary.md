# Lansweeper LicenseActions Second-Order SQL Injection Authenticated RCE

## Summary

Lansweeper 12.2.1.0 contains a second-order SQL injection in `LicenseActions.GetSqlServers` (L1482): a database value (`tblSqlSubServers.Name`) is concatenated raw into `AND Name NOT LIKE '<Name>'`. The write path (`AddSqlServer`) stores attacker-controlled text without calling the project's special-character check, so a crafted `Name` containing `%'` and a stacked-query payload survives into the vulnerable read query. Because the database account `lansweeperuser` is SQL Server `sysadmin` and `xp_cmdshell` is enabled by default, stacked queries reach `EXEC xp_cmdshell` — authenticated RCE as the SQL service account. Dynamically verified (marker file written).

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Lansweeper
- **Versions**: 12.2.1.0 (web reports 12.2.1.6)
- **Vendor**: Lansweeper

## Impact

- **Confidentiality**: Full read of the SQL Server database and host as the sysadmin account
- **Integrity**: Arbitrary command execution via `xp_cmdshell`
- **Availability**: Full control of the Lansweeper host and database

## Exploitation Prerequisites

Valid Lansweeper administrator credentials; the default `LicenseID=1` exists on install; database account is `sysadmin` with `xp_cmdshell` enabled (default). The two vulnerable endpoints do not call the CSRF validator.

## Mitigation

1. Parameterize the `NOT LIKE` clause in `GetSqlServers` (use `@name`)
2. Run `AddSqlServer` input through the special-character check / whitelist
3. Drop the database account to least privilege and disable `xp_cmdshell`
4. Add CSRF validation to `AddSqlServer`/`GetSqlServers`

## Timeline

- **Discovered**: 2026-07-29
- **Public Disclosure**: 2026-08-12 (batch #4)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble.
