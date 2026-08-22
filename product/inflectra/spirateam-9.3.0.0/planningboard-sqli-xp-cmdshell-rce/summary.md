# Inflectra SpiraTeam — PlanningBoard yAxisKey SQLi → xp_cmdshell RCE

## Summary

An authenticated SQL injection to RCE vulnerability in Inflectra SpiraTeam 9.3.0.0. The WCF method `PlanningBoard_MoveItems` passes the user-controlled `yAxisKey` un-sanitized into `RequirementManager.RetrieveByIndentLevel` (line 1820), which concatenates it into `REQ.INDENT_LEVEL = '<yAxisKey>'` and forwards it as the `@FilterSort` parameter of stored procedure `REQUIREMENT_RETRIEVE_CUSTOM`, where it is spliced raw into dynamic SQL executed via `EXEC(@SQL)`. The bundled `spirateam_admin` DB account is a sysadmin and `xp_cmdshell` is enabled, so `; EXEC xp_cmdshell '...'` runs OS commands as `NT SERVICE\MSSQL$SQLEXPRESS` (CWE-89).

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Inflectra SpiraTeam (Planning Board)
- **Versions**: 9.3.0.0 (other versions with the same `RetrieveByIndentLevel` implementation are likely affected)
- **Vendor**: Inflectra

## Impact

- **Confidentiality**: Full read of the SpiraTeam database as sysadmin
- **Integrity**: OS command execution via xp_cmdshell
- **Availability**: Full control of the application and database server

## Mitigation

1. Parameterize `RetrieveByIndentLevel` (use the LINQ form used by `RetrieveByIndentLevel2`) or `sp_executesql`
2. Grant `spirateam_admin` least privilege (db_datareader/db_datawriter on the app DB only, no sysadmin/CONTROL SERVER)
3. Disable `xp_cmdshell` on the SQL Server instance
4. Validate `yAxisKey` as a legal indent-level format
