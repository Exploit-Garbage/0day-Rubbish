# SearchBlox Enterprise Search 12.1.2 - JDBC Connection-String Injection through the Admin "Database URL String" Field Executing OS Commands as the SearchBlox Service Account

Advisory: https://0day-rubbish.com/blog/jdbc-url-injection-h2-init-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

SearchBlox Enterprise Search is a Java enterprise search appliance. The analyzed release is 12.1.2,
build 202607202005, running on Jetty 12.1.5 and a Temurin JDK 25.0.2 runtime, and it ships the H2
embedded database engine as a bundled JDBC driver: `WEB-INF/lib/h2-2.3.232.jar`, 2,651,157 bytes, in
the deployed web application's own library directory. A DATABASE collection in this product is
configured on the management plane through a field labelled "Database URL String". The product stores
that value verbatim in the collection property `cdata-settings` and later hands it to the JDBC layer
unchanged: the connector's `rawUrl` accessor reads the property and returns it after a `trim()`
(`AbstractJdbcConnector.java:15`, `:22`, `:33`), and `buildJdbcUrl` returns the raw string on both of
its return paths (`SimpleJdbcConnector.java:67` and `:76`) without adding so much as a `jdbc:` prefix.
HikariCP then receives that string through `setJdbcUrl` (`PooledDatabaseConnection.java:139`) and opens
a connection.

Because H2 evaluates the connection-string settings that follow the database name, an administrator who
can write that field can append `;INIT=...` and have H2 execute arbitrary SQL at connection time. H2's
`INIT` setting is a documented feature of the driver, and it permits `CREATE ALIAS`, which compiles a
Java method inside the product's own JVM; from there `Runtime.getRuntime().exec(new
String[]{"/bin/sh","-c",cmd})` runs an operating-system command as the account that owns the product
process. The vendor's code contains no reference to `INIT=` or `RUNSCRIPT` at all: the strings appear
zero times across the 2,049 Java files of the decompiled corpus, and there is no scheme whitelist, no
URL-parameter deny list and no re-assembly of the URL from its host, port and database components on
this path. The vulnerability is therefore an input-validation defect in how the product forwards an
administrator-supplied string into a JDBC URL, not an intentional feature of the administration
console.

The measured result is arbitrary command execution as `uid=999(searchblox)`: the product service
account, not root. The command's output is written by the injected Java method into
`/opt/searchblox/webapps/ROOT/console/<name>.txt`, inside the deployed web root, and is then read back
with a completely unauthenticated `GET /console/<name>.txt` that returns HTTP 200 with the header
`Server: Jetty(12.1.5)`. Two semantically independent carriers were exercised end to end: an inline
`INIT=` clause carried entirely inside the connection string, and an external `RUNSCRIPT FROM '<path>'`
clause whose SQL text is first planted on disk through a path-traversal upload.

The authentication class is authenticated: the write endpoint and the trigger endpoint are both inside
the product's UI security filter, and an anonymous request to either returns `40005 Token Not found
Re-login`. The chain therefore includes one login call and obtains a `super_admin` session. A separate
weakness, disclosed on its own, is that the appliance ships with a factory-default `admin`/`admin` pair
(CWE-798) and no forced password change; that pair is not the vector described here, and this advisory
does not claim that the injection can be reached without a session.

Verification was performed end to end over HTTPS against a disposable instance built from the vendor's
own installation package inside an isolated container on a research host, with the product files
unmodified. A control request carrying no injected clause, issued in the same container against the
same collection 1.2 seconds before the first carrier and 15.6 seconds before the second, returned a
successful connection and produced no marker file at all, while each carrier produced a 130-byte marker
whose content included the process identity and a fresh random nonce. No physical appliance and no
customer deployment was touched. No CVE identifier has been assigned to this finding.

- Component: the collection configuration endpoint `PUT /ui/v1/collection/database/update-path` and the
  connection test endpoint `GET /ui/v1/collection/database/test/{colId}` of SearchBlox Enterprise Search
  12.1.2, plus the database connector classes under `com/searchblox/database/`
- Source: the "Database URL String" value of a DATABASE collection, persisted as `cdata-settings` and
  read back by `AbstractJdbcConnector.rawUrl` with only a `trim()` applied
- Sink: `HikariConfig.setJdbcUrl` at `PooledDatabaseConnection.java:139`, fed by the verbatim string
  from `SimpleJdbcConnector.buildJdbcUrl`, and evaluated by the bundled H2 2.3.232 driver
- Weapon shipped by the vendor: `h2-2.3.232.jar` (2,651,157 bytes, recorded digest
  `756154ae197457f2995b89c11bc9b2c3`), present in the release package's `WEB-INF/lib` alongside 933
  jars in total, 216 of which are `cdata.jdbc.*` third-party data-source drivers
- Sanitisation: none on this path; `DatabaseUtils.escapeIdentifier` (`:660-:668`) serves identifier
  quoting only, and neither the raw-URL branch nor the host/port/name assembly branch calls it
- Achieved identity: `uid=999(searchblox) gid=999(searchblox) groups=999(searchblox)`, confirmed from
  the marker body; this is the product service account and not root
- Recorded score: 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network - the management plane is HTTP(S); nothing in the chain requires adjacency,
  physical access or a local account on the appliance
- Attack Complexity: Low - one authenticated `PUT` writes the connection string and one authenticated
  `GET` opens the connection that evaluates it; there is no race, no memory groom and no state machine
- Privileges Required: High - both the write endpoint and the trigger endpoint sit behind the product's
  UI security filter and require a `super_admin` session; an anonymous request is rejected with
  `40005 Token not found Re-login` before any handler runs
- User Interaction: None - the credential holder drives both requests directly
- Scope: Unchanged - the command executes inside the same security authority as the vulnerable web
  application, as its own service account, with no crossing into another component's authority
- Confidentiality, Integrity, Availability: all High - arbitrary command execution as the service
  account yields the deployed application tree, the collection configuration, every indexed
  collection's content and the ability to change or destroy either
- Arithmetic: ISS = 1 - (1 - 0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119; Exploitability =
  8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827, rounded up to 7.2

Privileges Required is High rather than the neighbouring Low tier because the privileges in question are
administrative control of the vulnerable component itself. The affected surface is not a per-user
feature with a lower-privileged owner: the collection configuration plane is the product's top
administrative tier, and the only account class the record shows reaching `update-path` or
`test/{colId}` is the `super_admin` session itself. CVSS 3.1 assigns High when the attacker must be an
administrator of the vulnerable component, which is exactly what that session is here, so the lower
tier would describe a principal the evidence does not establish. The same reasoning keeps the score
at 7.2 rather than 8.8: the injection is real and the impact is complete once reached, but reaching it
requires the strongest credential the product issues.

Rejected reading, recorded so that it is not quoted as the headline: a Low-privilege reading of the
same impact profile, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High. Its arithmetic is ISS
0.914816, Impact 5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, sum 8.708373
rounded up to 8.8. It is rejected because no non-administrative account class was observed reaching
either endpoint; using it would silently assume a lower-privileged account that the evidence does not
establish.

Rejected reading, second form: a Scope-Changed reading,
`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = 9.1 Critical, whose arithmetic is ISS 0.914816,
Impact 7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 - 0.02)^13 = 6.128026, Exploitability
8.22 x 0.85 x 0.77 x 0.50 x 0.85 = 2.286496, and 1.08 x (6.128026 + 2.286496) = 9.087684 rounded up to
9.1. It is rejected because the command runs as the same service account, inside the same operating
system boundary and under the same authority as the vulnerable web application; no security scope is
crossed, so Scope is Unchanged.

## Affected Products

- SearchBlox Enterprise Search 12.1.2, build 202607202005, on Jetty 12.1.5 with a Temurin JDK 25.0.2
  runtime and the bundled H2 2.3.232 driver - the release analyzed end to end, statically and
  dynamically
- Affected component: the DATABASE collection configuration plane, specifically
  `PUT /ui/v1/collection/database/update-path` (write of `cdata-settings`) and
  `GET /ui/v1/collection/database/test/{colId}` (connection attempt), together with the connectors
  `AbstractJdbcConnector`, `SimpleJdbcConnector` and `PooledDatabaseConnection` in the deployed
  `WEB-INF/lib` classpath
- Prerequisite inside the deployment: `h2-2.3.232.jar` is part of the release package
  (`./opt/searchblox/webapps/ROOT/WEB-INF/lib/h2-2.3.232.jar`, 2,651,157 bytes, recorded digest
  `756154ae197457f2995b89c11bc9b2c3`), so no attacker-supplied driver is needed and none can be
  introduced by this chain
- Authentication context required: one `super_admin` session. The chain obtains it with the product's
  shipped factory-default pair in the verification environment; that default-credential weakness is a
  separate finding (CWE-798) and is not the vector of this advisory
- Not claimed: other SearchBlox releases and builds were not tested; no statement is made about builds
  before or after 12.1.2, about other deployment topologies, or about whether a hardened deployment
  removes the bundled H2 driver from the classpath
- Verification method and its boundary: end-to-end HTTP(S) against a disposable instance built from the
  vendor's installation package in an isolated container, with the product files unmodified, one
  same-container control, and two independent carriers each fired by a separate process. Static
  evidence comes from the decompiled product tree and the shipped package inventory. No physical
  appliance was driven, and no customer or third-party instance was involved at any point
- Privilege ceiling: command execution as `uid=999(searchblox)`, the account the product process runs
  as. Root was not obtained and is not claimed; the container runtime's own root account was never
  reachable through this chain
- Identifier: no CVE identifier has been assigned to this finding, and the research record names none

## Impact

- Arbitrary operating-system command execution as the SearchBlox service account on the appliance that
  hosts the search deployment, from a management-plane credential that was only ever meant to configure
  a data source
- Full read and write access to the deployed application tree, because the command runs as the account
  that owns `/opt/searchblox/webapps/ROOT`. The research record identifies this as a route to
  persistent server-side code in the web root; that path is part of the deployment's writable
  filesystem rather than a temporary mount, so a file placed there is not cleared by a restart of the
  product process
- Access to the collection configuration store, including `WEB-INF/config.xml`, and to every indexed
  collection's data. An enterprise search appliance aggregates content from file shares, databases,
  intranets and document management systems, so the confidentiality impact extends to whatever the
  deployment has indexed rather than to the appliance alone
- Access to the data-source connection settings that the product stores for its connectors, and to
  `/tmp`, which the service account can both read and write
- Integrity and availability impact at will: the service account can modify or delete the deployed
  application, its configuration and its indexes, so recovery requires a rebuild rather than a restart
- The marker is retrievable anonymously. The chain ends with `GET /console/<name>.txt` returning HTTP
  200 without any token, which means the output of the command is exfiltrated over the same port the
  management plane already uses and needs no additional egress path
- The activity is quiet in product terms: the only administrative artefact is a database URL change,
  which the product already logs through `logParameterSetting` (`DatabaseServices.java:331`) as an
  ordinary configuration edit
- No memory corruption, no authentication bypass and no transport defect is involved: the defect is
  entirely the absence of validation between an administrator-editable field and a JDBC URL parser,
  which is why the fix belongs in the product's connector layer rather than in the driver

## Mitigation / Fix Recommendations

1. Stop returning the administrator-supplied string verbatim from
   `SimpleJdbcConnector.buildJdbcUrl`. Parse the value, accept only a scheme the selected connector
   supports, and rebuild the URL from validated `host`, `port` and `database` components, discarding
   every URL setting rather than passing settings through
2. Reject the reserved settings outright: `INIT`, `RUNSCRIPT`, `TRACE_LEVEL_SYSTEM_OUT`,
   `TRACE_LEVEL_FILE` and `AUTO_SERVER` have no place in an administrator-typed data-source locator and
   should fail validation with a clear error
3. Remove the embedded, script-capable drivers from the path that accepts an administrator-supplied URL.
   The release ships `h2-2.3.232.jar`, `sqlite-jdbc-3.49.1.0.jar` and `duckdb_jdbc-1.3.1.0.jar`
   in-process; if H2 must stay for a legitimate deployment mode, restrict it to `jdbc:h2:tcp://` remote
   form and refuse `mem:` and `file:` URLs
4. Fix the upload primitive used by the second carrier: reject filenames containing `..` or absolute
   paths in `PUT /ui/v1/plugin/upload`, bind the accepted extension to the content type, and above all
   do not leave a file on disk when the request is answered with HTTP 400
5. Add the missing authorisation annotation to the licence-signing endpoint
   (`LicenseService.java:416-419` is the only method in that class without `@RolesAllowed`), so the
   pre-authentication gate cannot be cleared anonymously
6. Force a password change on first login and remove the shipped `admin`/`admin` pair from new
   installations, so that a default credential cannot supply the `super_admin` session this chain needs
7. Constrain the service account: it already runs as `uid=999` rather than root, which is correct, but
   it can still write into the deployed web root and execute `/bin/sh`. A seccomp or AppArmor profile
   that denies `execve` from the application process, plus a read-only application tree, would contain
   this class of defect even if a validation gap remained
8. Alert on the configuration event rather than only recording it: `logParameterSetting`
   (`DatabaseServices.java:331`) already captures old and new values for "Database URL String", so a
   SIEM rule matching `INIT=`, `RUNSCRIPT` or a semicolon in that field turns the last step of this
   chain into a detection
9. Add a regression test that submits a connection string containing `INIT=CREATE ALIAS` and asserts
   that the request is rejected before any connection is opened, and a second test asserting that the
   connection test endpoint refuses a URL whose scheme does not match the selected connector

## References

- https://0day-rubbish.com/blog/jdbc-url-injection-h2-init-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com
- Vendor: SearchBlox (product: SearchBlox Enterprise Search)
- Identifier: no CVE identifier has been assigned to this finding

---

Written by the 0day Rubbish Research Team.
