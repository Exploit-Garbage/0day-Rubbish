# Delta DIAEnergie IEMS — Authenticated CommandTag SQL Injection → VBScript → RCE

## Summary

Delta DIAEnergie IEMS V1.11 (industrial energy management system) contains a SQL injection in the `API.CommandTag` method of the `CEBC.exe` engineering-station communication service (TCP 928 raw socket). The `tid` parameter is concatenated **verbatim** into a SQL query:

```sql
SELECT DIAE_eq.pt,... FROM DIAE_eq INNER JOIN DIAE_tag ON DIAE_eq.eid=DIAE_tag.eid
WHERE tid=" + tid + " AND DIAE_tag.del='0' ... AND DIAE_tag.kid='" + Define.KeyID + "' ...
```

No parameterization, no `int.TryParse`, no escaping. T-SQL's semicolon-free stacked-statement syntax lets an attacker insert a row into `DIAE_script` with attacker-controlled VBScript, which the `RecalculateScript` trigger then executes via the MSScriptControl COM engine (`AddCode`). The trigger reads **all** rows from `DIAE_script` (no WHERE clause).

The socket protocol has no user authentication — the only gate is the AES encryption key `Define.PK`. Because `PK` is randomly regenerated (~30 s rotation), the attacker must hold DB read access or another leak path to freeze/obtain it (Target B, conditional RCE). Verified end-to-end: `whoami > C:\Windows\Temp\m.txt` executed as the CEBC service account. CVSS 8.8.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Delta DIAEnergie IEMS (industrial energy management system)
- **Version**: V1.11 (latest, post-patch)
- **Vendor**: Delta Electronics
- **Component**: `CEBC.exe` (.NET Framework WinForms) engineering-station service, TCP 928

## Impact

- **Confidentiality**: command execution as the CEBC service account; energy-management data exposed
- **Integrity**: arbitrary VBScript/command execution in the EMS service context
- **Availability**: full control of the engineering-station service and its PLC/data connectivity

## Mitigation

1. Add `int.TryParse` validation and parameterized queries to `CommandTag` (consistent with the patched `Recalculate*` handlers)
2. Add a `kid`/`scid` WHERE filter to `RecalculateScript()` (consistent with `RecalculateScriptNew()`)
3. Introduce an authentication layer to the TCP 928 protocol (currently keyed only by encryption)
4. Whitelist/sandbox VBScript before executing `DIAE_script` rows
