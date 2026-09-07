# DBxtra .NET — Unauthenticated SOAP xp_cmdshell RCE

## Summary

DBxtra .NET 13.1.1.0's Report Web Service is a Windows service running as LocalSystem that self-hosts a Cassini HTTP server and publishes `DBxtraService.asmx` — 346 SOAP `[WebMethod]` operations with no class-level authentication. Although `web.config` declares Windows authentication, nothing enforces a principal on the ASMX surface: every operation is anonymously callable.

An unauthenticated attacker chains four calls into arbitrary command execution: `ProjectConnectionInsertDB` registers an arbitrary backend datasource (connection strings are only DES-encrypted at rest with the product's hardcoded key, so any `Integrated Security=SSPI` connection string can be pre-computed and submitted — the LocalSystem web service then connects to the co-hosted SQL Server instance as sysadmin); `ProjectObjectInsertDB` stores an attacker-authored SQL report object that enables and calls `xp_cmdshell`, flagged `AnonymousAccess=true`; `UpdateDatabaseVersion` rewrites the metadata version to satisfy the report viewer's gate; and `GET /DataGrid.aspx?Id=<ObjectId>` makes the viewer execute the stored SQL server-side. The command runs as the SQL Server service account (`NT Service\MSSQL$SQLEXPRESS`, high integrity, sysadmin of the instance). Verified end-to-end on a default installation with a marker file (`whoami` output + `RCE_OK`) produced by a single unauthenticated script run.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: DBxtra .NET (Report Web Service)
- **Versions**: 13.1.1.0 verified; other 13.x releases sharing the unauthenticated `Service` class and report-execution path are likely affected
- **Vendor**: DBxtra Software (Advisionario S.A. de C.V.)
- **Prerequisite**: default installation with a reachable SQL Server instance on which the web service account authenticates as sysadmin (the common co-hosted SQL Server Express deployment); service reachable (loopback-only installs still allow any local low-privilege user; exposed installs are remotely exploitable)

## Impact

- **Confidentiality**: command execution as the SQL Server service account, plus decryption of every registered BI datasource connection string (hardcoded DES key) — full read access to the reporting data estate
- **Integrity**: attacker-authored SQL stored and executed inside the product's metadata/execution engine; arbitrary filesystem writes on the host
- **Availability**: arbitrary service disruption or destruction on the DBxtra / SQL Server host

## Mitigation

1. Require authentication on all 346 SOAP `[WebMethod]` operations (class-level filter on the ASMX `Service` class)
2. Whitelist datasource registration; reject loopback/intranet targets and `Integrated Security=SSPI` from anonymous callers
3. Authenticate and validate SQL object creation (reject `xp_cmdshell` and other extended stored procedures)
4. Require administrator authentication for `UpdateDatabaseVersion`
5. Disable `xp_cmdshell` / run the SQL Server instance under least privilege
6. Run the web service under a low-privilege account, not LocalSystem; keep port 8765 off any unauthenticated reverse proxy
