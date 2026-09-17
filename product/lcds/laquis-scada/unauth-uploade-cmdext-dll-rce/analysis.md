# LCDS Laquis SCADA — Unauthenticated `/uploade.html` File Write Chained with Startup `CMDEXT*.DLL` Autoload Yields Pre-Auth Remote Code Execution

## 1. Overview
LCDS Laquis SCADA (vendor: LCDS, Brazil) is a closed-source commercial SCADA/HMI platform deployed in critical-infrastructure and industrial-control environments. The product ships a Windows-native stack: a Delphi GUI controller (`aq.exe`) for engineering/operator use, and a Delphi console web component (`mili.exe`) that serves the remote HMI web interface alongside the plant-facing protocol services. `mili.exe` binds `0.0.0.0:11234` for HTTP and `0.0.0.0:502` for Modbus TCP, so wherever the web/HMI feature is enabled, the same process that talks to field devices also exposes a plain HTTP management API directly to the network.

This advisory documents a fully unauthenticated remote code execution chain in `mili.exe`. The HTTP dispatcher implements **no authentication gate in the default configuration** — roughly twenty management endpoints, including file upload, configuration save/delete, tag read/write, IP reconfiguration and process shutdown, are reachable by any network client without credentials. Two of them combine into code execution:

1. `POST /uploade.html` writes an attacker-controlled file into the `mili` application data directory (the directory the process uses as its working directory), echoing only `ok`. The destination filename is taken verbatim from the `Content-Disposition` header, and the base directory is traversable with `..`.
2. At startup a plugin loader enumerates its own data directory for the glob `CMDEXT*.DLL` and passes every match to `LoadLibraryA` through an indirect `driverserver` callback. `LoadLibraryA` runs the DLL's `DllMain` at load time — arbitrary attacker code executes inside the SCADA process.
3. `GET /reset.html`, also unauthenticated, sets the accept-loop stop flag and halts the process. The resulting outage is precisely what prompts an operator, a supervisor service or a maintenance window to restart `mili` — the moment the planted `CMDEXT*.DLL` is loaded.

The attacker controls steps 1 and 2 with no credentials at all, and step 3 is a standard operational event the attacker can themselves induce: a pre-auth "plant + reboot" RCE against an ICS product. It was confirmed end-to-end by dynamic verification on the real product binary — an unauthenticated upload produced a byte-identical `CMDEXT001.DLL` on disk (matching SHA-256), an unauthenticated `/reset.html` killed the process, and on restart the marker file written by the implanted `DllMain` appeared within one second with the expected content `LAQUIS_UNAUTH_RCE_OK`.

The research ran in four stages, and the sections below trace that path: **(a) surface discovery** — port and endpoint enumeration, locating the HTTP dispatcher `fcn.0043c550` and its ~20 routed endpoints (§3); **(b) authentication-boundary establishment** — recovering the dispatcher's password gate and proving it is disengaged by default configuration rather than bypassed by an exploit (§4); **(c) sink localization and chain construction** — following `/uploade.html` to its file-write primitive, then locating the `CMDEXT*.DLL` / `ComandosDLLDireta` plugin loader and its `LoadLibraryA` sink (§5, §6); **(d) dynamic verification** — a live end-to-end run recorded with byte-level artifact hashing and the target-side marker file (§8), preceded by an adversarial review round (independent re-analysis plus a dedicated falsification pass) whose single disputed point is adjudicated by that live run (§8.4).

## 2. Vulnerability Summary
- **Type**: unauthenticated arbitrary file upload (CWE-434) chained with uncontrolled library load / code execution (CWE-78) — pre-authentication remote code execution
- **Entry points**: `POST /uploade.html` (arbitrary file write) and `GET /reset.html` (unauthenticated process shutdown), both served by `mili.exe` on TCP 11234
- **Sink**: the `CMDEXT*.DLL` plugin loader at `0x4998c0`, calling `FindFirstFileExW("CMDEXT*.DLL")` then `LoadLibraryA` via the indirect callback `call [0x5171c4]`; `DllMain` executes at load time
- **Preconditions**: none credential-related. The Laquis web server feature must be active (the operator-enabled state used for remote HMI/web access); the restart of `mili` is a normal operational event, provokable by the attacker through `/reset.html`
- **Root cause**: the HTTP dispatcher performs no authentication check when no password is configured (the default), and the upload handler applies no validation to file content, filename or destination directory
- **Result**: arbitrary native code execution inside the SCADA web/HMI process. CVSS 9.8 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Affected**: LCDS Laquis SCADA, as installed from the installer under test (`LAquisSetupenge1.exe`, 1237 files extracted with `innoextract`). The vulnerable component is the web server binary `mili.exe` (PE32 Delphi console, 1129984 bytes, 32-bit x86). The exact marketed version or build number is **not documented in our research record**, so this advisory claims no specific version — it describes the release that was under test. Any deployment whose `mili.exe` contains both the `CMDEXT*.DLL` plugin loader and the ungated `/uploade.html` handler carries the same defect.
- **Independence**: no matching public disclosure was found ("uploade.html", "CMDEXT*.DLL" and "ComandosDLLDireta" carry no published CVE association), and the known Laquis CVEs reviewed in this research all concern LQS file parsing rather than the web component. Independently discovered 0-day chain.

## 3. Product & Architecture
Components under test: `aq.exe` (PE32 Delphi GUI, 7.5 MB) — the engineering/operator controller that drives runtime state, including the web-server enable flag; and `mili.exe` (PE32 Delphi console, 1129984 bytes / ~1.1 MB, 32-bit x86, stripped-to-PDB) — the web/HMI server and protocol host, the component carrying this vulnerability. Static layout of `mili.exe`: `ImageBase = 0x400000`, `.text` at VA `0x401000` / file offset `0x400`, hence `file_offset = VA - 0x400c00`. All addresses quoted below are VAs in `mili.exe`.

Listening sockets documented in the research record: `0.0.0.0:11234` (HTTP web/HMI service; the port comes from `var.ini`, section `[MODE]`, key `PORT=11234`) and `0.0.0.0:502` (Modbus TCP). Both bind all interfaces. In an ICS deployment that means the HTTP management API is reachable from the operator/DMZ side of the plant network while `mili.exe` itself holds the device-facing role — code execution here lands on a host with reach into the control network.

One architectural detail matters for reproduction: the web dispatch is gated by a **runtime flag**, set when the operator switches the web server on from the `aq.exe` GUI control `ServidorWEB1Click`; the flag lives in shared memory and is not persisted by `mili.exe` itself. In production this is simply the state of any Laquis deployment using remote HMI/web access — the normal, intended state of the feature. Our dynamic verification reproduced that state deterministically on the product binary; §8.1 discloses exactly how.

### Attack surface (3.1): HTTP dispatcher and endpoint inventory
Dispatch is a single large Delphi function, `fcn.0043c550` (15132 bytes, 451 CFG edges), with the pipeline: URL substring extraction (`fcn.00408d10`) → string comparison (`fcn.00408a60`) → query-parameter parsing (`fcn.0043bd40`) → handler call. The full routed endpoint set (~20) recovered from it:
```
/config.html      /configmulti.html /delete1.html     /fast.html
/index.html       /logdelete1.html  /mode.html        /reset.html
/s_mode.html      /save.html        /saveconfig.html  /setip.html
/tagget.html      /tags.lhtml       /tagset.html      /tagsetmulti.html
/tagsvalue.lhtml  /update.html      /uploade.html     /edit.lhtml
```
Several are individually high-value primitives: `/setip.html` (handler `0x43d1f9`, parameters `SERVER` / `SSID` / `PASSWD` / `COUNTRY` into `fcn.0043b730`) is a candidate network-reconfiguration path (a `netsh`-style sink, not pursued further); `/save.html`, `/saveconfig.html`, `/delete1.html` and `/logdelete1.html` offer path-traversal write/delete primitives; `/tagset.html` and `/tagget.html` take a `NOME` parameter into a driver trigger. They were enumerated but not needed — `/uploade.html` alone reaches code execution, so the chain below uses only `/uploade.html` and `/reset.html`.

## 4. Authentication Boundary
### 4.1 The password gate exists — and is disengaged by default
The dispatcher does contain an authentication check, at `0x43ccf4`–`0x43cd45`, executed before routing:
```
0x43ccf4:  cmp  dword [0x517bc0], 0     ; is a password configured?
0x43ccfb:  je   0x43cda0                ; == 0 -> jump straight to dispatch entry (NO auth check)
0x43cd11:  mov  edx, 0x4f5e20           ; "PWD"
           ...                          ; extract the ?PWD= query parameter
0x43cd32:  call 0x408a60                ; string compare against the configured password
0x43cda0:  <dispatch entry>
```
The password backing `[0x517bc0]` is loaded from `var.ini`, section `[MODE]`, key `PASSWD` (loader at `0x433f64`). **The shipped `var.ini` contains no `PASSWD` key**, so `[0x517bc0]` is 0, the conditional jump at `0x43ccfb` is taken, and control reaches the dispatch entry at `0x43cda0` with no credential verification of any kind. This is not an authentication bypass in the exploit sense — there is no protected state to break out of. Authentication is *absent by default configuration* (bypass-by-default).

When an operator does set `PASSWD`, the gate requires the `?PWD=<password>` query parameter on each request. That scheme has no cookie, no session, no HTTP authentication header and no per-request token: a single static string compared with `fcn.00408a60`, transmitted in the URL (and therefore recorded by any log or proxy that keeps request lines). Either way, the endpoints in this chain are reachable without credentials on a default installation.

### 4.2 How "unauthenticated" was established
Two independent lines of evidence:
- **Static**: the whole-dispatcher review found no other authentication check in front of routing; the only gate is the password test above, short-circuited when no password is configured. The independent re-analysis pass scored this conclusion 0.95 (§8.4).
- **Dynamic**: `POST /uploade.html` issued with **no Cookie, no Authorization header, no `?PWD=` parameter and no session of any kind** returned `HTTP/1.1 200 OK` with body `ok`; `GET /reset.html`, likewise credential-free, shut the process down (observed: PID 6748 terminated, port 11234 no longer listening). Both are reproduced verbatim in §8.2 and §8.3.

The `CMDEXT*.DLL` plugin loader (§5.2) has no internal gate either — no authentication, no signature check, no hash verification, no allow-list: it loads whatever matches the filename glob in its own data directory. Both halves of the chain are fully exposed on their own.

## 5. Root-Cause Analysis
### Source identification (5.1): `/uploade.html` unauthenticated arbitrary file write
Dispatch reaches the handler through a string compare against the literal `/uploade.html` (string at `0x4f6120`, comparison point `0x43d329`, via `fcn.00408a60`). Reconstructed handler behaviour:
```
handler entry (compare point 0x43d329)
  read <= 0xffff bytes of request body   via fcn.00407d00  -> var_6ch
  call fcn.00425530 ; read again                          -> var_78h (part content)
  filename from header:  0x43cc8e  mov al, 0x22           ; search for '"'
                         lea ecx, [eax+0xb]               ; skip 11 chars of 'filename="'
  call fcn.00437f30 (eax = content, edx = var_14h = filename)   ; perform the write
  respond "ok"  (HTTP/1.1 200 OK, Content-length: 2)
```
The write base directory is `[0x51a530]`, populated at runtime by `GetCurrentDir` (`0x412de0`) — the process working directory, i.e. the `app\data\` folder of the installation. The documented write behaviour is `base + filename` with **no sanitization of `..`**, so the filename is a path-traversal primitive that can reach outside the data directory; with no traversal at all, the file lands in exactly the directory the plugin loader scans. Three defects are stacked, none of them subtle: no authentication in front of the handler (§4); no content validation (the body is written as opaque bytes, so a PE image survives intact — adversarial angle F7 in §8.4 confirms the Delphi I/O path is length-based on `AnsiString` and binary-safe, not null-terminated); and no filename validation (attacker-controlled path component, traversal-capable, with no extension restriction, so a `*.DLL` name is accepted). The handler reads at most `0xffff` (65535) bytes of body — far more than the 1024-byte payload DLL used in verification.

### Sink identification (5.2): the `CMDEXT*.DLL` startup plugin loader
Two string constants anchor the sink: `CMDEXT*.DLL` at `0x50999c` and `ComandosDLLDireta` at `0x5099a8`. The loading routine is `0x4998c0`, referenced from a Delphi vtable at `0x4e71c0` whose method set covers the plugin lifecycle (`init` / `load` / `unload` / `finalize`):
```
0x4998c0:
    GetCurrentDir            (0x412de0)  -> [0x51a530] = "...\app\data\"   (== CWD)
    FindFirstFileExW         (0x425610 -> 0x4301c0 -> 0x4015b0), pattern "CMDEXT*.DLL"
    loop over matches:
        LoadLibraryA         via indirect callback:  call [0x5171c4]
                             (driverserver.dll LoadLibraryA thunk:
                              0x45ab00 -> 0x4109f0 -> call [0x5171c4])
                             ==> DllMain of the loaded image runs NOW
        GetProcAddress       "ComandosDLLDireta" (0x5099a8)   ; may return NULL,
                                                              ; loader tolerates it
        FindNextFile         (0x425610)
    FindClose                (0x4256d0)
```
The execution primitive is `LoadLibraryA` itself: Windows runs a DLL entry point (`DllMain` with `DLL_PROCESS_ATTACH`) during load, before any export is resolved and before any caller code runs. The loader makes no attempt to distinguish a legitimate command plugin from an attacker-planted image — no Authenticode check, no allow-list, no path restriction beyond "whatever is in my own data directory" — and that same directory is the destination of the unauthenticated `/uploade.html` write. That coincidence is the vulnerability. `GetProcAddress("ComandosDLLDireta")` is looked up *after* the load and its failure is tolerated, so the planted DLL needs no exports at all: hence the PoC payload is a minimal 1024-byte PE32 image importing only `kernel32!CreateFileA / WriteFile / CloseHandle` and exporting nothing.

**Timing.** The loader is reached through Delphi vtable method dispatch rather than a direct `e8` call site, so its exact invocation point cannot be proven from a single static read. The independent re-analysis scored the static portion of this claim 0.70, and the live test (§8.3) confirmed the timing empirically: on restart of `mili`, the marker written by the implanted `DllMain` appeared within one second of process start. The adversarial pass disputed precisely this static point (F3, §8.4); the dynamic run is the authority, and the end-to-end result is not in dispute — attacker code inside a `CMDEXT*.DLL` file in the data directory ran in the `mili` process.

### 5.3 Trigger: `/reset.html` unauthenticated shutdown
The handler at `0x43cff2` sets the accept-loop stop flag `[0x517b50] = 0`, then `Sleep(1000)`, then halts via `0x40e500` — process exit. An earlier static hypothesis that this endpoint spawns a `reset1.exe` process was explicitly corrected during analysis: the handler sets the stop flag and halts. The effect is an immediate, unauthenticated denial of service against the SCADA web/HMI process (observed: PID 6748 dead, port 11234 gone). Its role in the RCE chain is to create the restart.

### Data flow (5.4): complete path from HTTP request to DLL load
```
attacker (no credentials)
  +-(1) POST /uploade.html
  |      dispatcher fcn.0043c550 -> password gate 0x43ccf4: [0x517bc0]==0 -> je 0x43cda0 (no auth)
  |      -> handler 0x43d329 -> filename from Content-Disposition (0x43cc8e, +0xb past 'filename="')
  |      -> fcn.00437f30(content, filename) -> write base [0x51a530] (= app\data\, CWD)
  |      -> "CMDEXT001.DLL" (arbitrary PE32) on disk            ==> HTTP 200, body "ok"
  +-(2) GET /reset.html
  |      -> handler 0x43cff2 -> [0x517b50] = 0 -> Sleep(1000) -> halt   ==> mili exits (DoS)
  +-(3) restart (operator response / supervisor / routine maintenance / crash recovery)
         -> mili start -> loader 0x4998c0 -> GetCurrentDir -> [0x51a530]
         -> FindFirstFileExW("CMDEXT*.DLL") -> match CMDEXT001.DLL
         -> call [0x5171c4] (LoadLibraryA via driverserver) -> DllMain
         ==> ARBITRARY NATIVE CODE EXECUTION IN THE SCADA PROCESS
```

## 6. Exploit Chain Construction
Constructing the chain required solving one non-obvious problem: getting attacker-chosen native code executed **without** a command-injection sink anywhere in the dispatcher. `/mode.html?run=` was tested and confirmed a dead end during research — `run` is interpreted as an integer mode selector, not a command string (record finding P6). The tag endpoints route into a driver trigger whose shell-execution syntax could not be resolved. The payload therefore had to be delivered as *data* and executed by the product's own plugin mechanism. Three construction decisions followed.

**Decision 1 — name the payload so the loader picks it up.** The glob is `CMDEXT*.DLL`, matched in the process working directory. The PoC supplies `filename="CMDEXT001.DLL"` in the `Content-Disposition` header of the multipart POST — no traversal needed, since the default destination *is* the scanned directory. (Traversal via `..` remains available for other placements but is not required for RCE, and the PoC does not use it.)

**Decision 2 — build a PE image without a compiler.** The payload must be a valid 32-bit DLL, and a public PoC should not depend on a toolchain. The PoC constructs the image entirely in memory from `struct` packs: a minimal PE32 with `ImageBase = 0x10000000`, `SectionAlignment = 0x1000`, `FileAlignment = 0x200`, one `.text` section, an import directory for `kernel32.dll` (`CreateFileA`, `WriteFile`, `CloseHandle`) plus IAT, and hand-emitted x86 for `DllMain`. The entry point checks `fdwReason == DLL_PROCESS_ATTACH` (`cmp dword [ebp+12], 1`), then calls `CreateFileA(marker_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)` → `WriteFile(handle, marker_text, len, &written, NULL)` → `CloseHandle(handle)`, and returns `TRUE` (`mov eax, 1` / `ret 12`). No export directory is emitted, because the loader tolerates a NULL `GetProcAddress("ComandosDLLDireta")`. The resulting image is 1024 bytes.

**Decision 3 — make the restart happen on the attacker's schedule.** Rather than waiting for a maintenance window, the chain sends unauthenticated `GET /reset.html`, which halts `mili` immediately. In an operating plant the outage is answered by a restart — from the operator, from a supervisor/watchdog, or at the machine's next boot. The DLL persists on disk, so every subsequent start re-triggers the load. The chain is therefore: unauthenticated write → unauthenticated crash-out → automatic load on next start. Both attacker-controlled steps need zero credentials and the third is a standard operational event — the classical plant-and-reboot RCE class, here with the "reboot" provoked by the attacker through a second unauthenticated endpoint.

## 7. PoC Usage
The advisory ships a self-contained, standard-library-only Python 3 PoC at `exploit/laquis_scada_unauth_uploade_rce.py`, using only `socket`, `struct`, `argparse` and `sys` — no third-party packages, no compiler, no HTTP library. Output is pure ASCII English.
```bash
# default target 127.0.0.1:11234, default marker C:\Windows\Temp\laquis_rce_marker.txt
python3 exploit/laquis_scada_unauth_uploade_rce.py
# explicit target, marker path and marker text
python3 exploit/laquis_scada_unauth_uploade_rce.py --host <target-ip> --port 11234 \
        --marker 'C:\Windows\Temp\laquis_rce_marker.txt' --text LAQUIS_UNAUTH_RCE_OK
# deliver the implant without provoking a shutdown (wait for a natural restart)
python3 exploit/laquis_scada_unauth_uploade_rce.py --host <target-ip> --no-reset
```
In order the script: builds the 1024-byte marker DLL in memory → sends unauthenticated `POST /uploade.html` with `filename="CMDEXT001.DLL"` → checks the response for `200 OK` plus the exact body `ok` (anything else aborts with exit status 2 and states the web dispatch is probably inactive) → sends unauthenticated `GET /reset.html` unless `--no-reset` was given → prints the verification procedure. Verification after the target's `mili` process next starts is `type C:\Windows\Temp\laquis_rce_marker.txt`, and the expected content is `LAQUIS_UNAUTH_RCE_OK`. The marker file existing with that content is deterministic proof that `DllMain` executed inside the SCADA process. This PoC is published for authorized security testing and coordinated disclosure only: running it against a live plant stops the HMI web service and implants a DLL on a control-system host, so do not use it outside an isolated test environment or without written authorization.

## 8. Verification Evidence
### 8.1 Verification environment, disclosed in full
Honesty about conditions: **this was the real product binary, not an emulation and not a reimplementation** — with one clearly-scoped deviation, stated here.
- Target host: Windows Server 2025. Binary: `mili.exe` from the Laquis SCADA installation under test (PE32 Delphi console, 1129984 bytes, 32-bit x86), run from `<install-dir>\app\data\`.
- Configuration: pristine `config.xml` (2141 bytes, all drivers randomized) plus `var.ini` with `[MODE] PORT=11234 RUN=1` — the documented default HTTP port and **no `PASSWD` key**, i.e. the default authentication state of §4.1.
- The exploit ran from the target itself over loopback (`127.0.0.1:11234`) inside a single SSH session, so `mili` was not killed by session teardown and the restart could be observed and controlled.
- Deviation: the binary was started as `mili_patched.exe`, carrying a **3-byte research-environment activation patch** reproducing the runtime flag normally set when the operator enables the web server from the `aq.exe` GUI control `ServidorWEB1Click`. Patched bytes: VA `0x453995` (file offset `0x52d95`) `0x74` → `0xeb` (`je` → `jmp`), and VA `0x4539a9` / `0x453ae9` (file offsets `0x52da9` / `0x52ee9`) `0xee` → `0xe8` (`d9 ee fldz` → `d9 e8 fld1`). This forces only the documented "web server enabled" feature state so the HTTP dispatch is active without a GUI session — equivalent to the production state of any Laquis deployment using remote HMI/web access. It does **not** touch the authentication gate, the upload handler, the plugin loader or any protection mechanism, and it is deliberately **not** part of the published PoC. In production no patch is involved: the operator enables the feature.

### 8.2 Step 1 — unauthenticated upload accepted (no credentials of any kind)
Request: `POST /uploade.html HTTP/1.0`, `Content-Type: multipart/form-data`, `filename="CMDEXT001.DLL"`, **no Cookie, no Authorization header, no `?PWD=` parameter**. PoC stdout, recorded verbatim:
```
[*] Target: 127.0.0.1:11234
[*] Marker path on target: C:\Windows\Temp\laquis_rce_marker.txt
[+] Built marker DLL: 1024 bytes (DllMain writes marker on load)
[*] Sending unauthenticated POST /uploade.html ...
[*] Upload response:
    HTTP/1.1 200 OK
    Content-length: 2
    Content-type: text/html; charset=utf-8
    Accept-Ranges: bytes
    Connection: close

    ok
[+] DLL delivered to the mili application data directory (no credentials used).
[*] Sending unauthenticated GET /reset.html to shut mili down ...
```
**Byte-level delivery proof.** The DLL is hashed in memory before transmission and again after it lands on the server:

| Artifact | Size | SHA-256 |
|---|---|---|
| Built in memory by the PoC | 1024 bytes | `a0ed51cbcfa4c55095fe604ebfb708754ef33b3723a9032a0ae24a2349ae37b0` |
| Written on target at `<install-dir>\app\data\CMDEXT001.DLL` | 1024 bytes | `A0ED51CBCFA4C55095FE604EBFB708754EF33B3723A9032A0AE24A2349AE37B0` |

Identical (case-insensitive digest comparison). A complete binary PE image therefore traversed the unauthenticated HTTP write intact — no null truncation, no encoding corruption. That is the empirical confirmation of the binary-safe I/O path described in §5.1.

### 8.3 Steps 2 and 3 — unauthenticated shutdown, restart, code execution
Shutdown, before and after the credential-free `GET /reset.html`:
```
mili_patched running: PID=6748, port 11234 listening
after GET /reset.html (no credentials):
    mili alive: False | 11234 listening: False
```
Restart (simulating an operator's response to the outage) brought `mili_patched.exe` back as `PID=24624`. On startup the plugin loader enumerated `CMDEXT*.DLL`, matched the planted `CMDEXT001.DLL`, loaded it, and `DllMain` executed; the marker file appeared within one second. Target-side verification output, recorded verbatim:
```
MARKER_EXISTS=True
MARKER_CONTENT=LAQUIS_UNAUTH_RCE_OK
DLL_EXISTS=True  (<install-dir>\app\data\CMDEXT001.DLL, 1024 bytes)
```
`MARKER_CONTENT` equals the `--text` argument passed to the PoC exactly. Nothing on the target could have produced that file except execution of the attacker-supplied `DllMain` inside the `mili` process — a deterministic, non-AI-verifiable execution marker. The chain is confirmed end-to-end (record verdict: PDU G4 PASS).

### 8.4 Adversarial review round
Two independent review passes ran over the static analysis before the live run:
- **Re-analyst** (independent re-derivation, 177 tool calls): overall CONFIRMED 0.80. Per-task: authentication gate 0.95 (default bypass), `/uploade.html` write primitive 0.90, `CMDEXT` loader 0.70 (loader exists and is ungated; invocation timing deferred to the dynamic test), `/reset.html` shutdown 0.95.
- **Falsifier** (dedicated refutation attempt, 94 tool calls): overall NOT-REFUTED 0.55, surviving 6 of 7 angles. F1 authentication gate — not refuted (default has no `PASSWD`, gate skipped); F2 feature gate — not refuted (the activation patch enables a documented user feature, not a DRM/protection bypass); F4 write location — not refuted; F5 restart requirement — not refuted ("plant + reboot" is an accepted RCE class); F6 known-vulnerability check — not refuted (no public CVE; the 24 Laquis CVEs reviewed all concern LQS parsing); F7 binary integrity — not refuted (Delphi `AnsiString` length-based I/O is binary-safe). **F3 — the single refutation claim (0.82)**: the falsifier argued that `0x4998c0` in `mili.exe` merely builds a name table and that the real `LoadLibrary` happens in `driverserver.dll` on command invocation (`0x555600`) rather than at startup.

Adjudication was left to the live run, the only deterministic authority available. The dynamic result — the `DllMain` marker appearing on restart, with no command ever issued to the product — resolves the disagreement: whatever the precise static call path, a file matching `CMDEXT*.DLL` in the data directory **is** loaded and executed at `mili` startup. The re-analyst's deeper trace (`0x45ab00` → `0x4109f0` → `call [0x5171c4]`, i.e. `LoadLibraryA` reached indirectly through the `driverserver` callback) is consistent with both readings, placing the actual load call in `driverserver.dll` while showing `mili.exe` invokes it. Residual uncertainty is confined to static call-graph detail and does not affect exploitability.

One source-level inconsistency is recorded for transparency: the upload write base is documented as `[0x51a530]` (the runtime `GetCurrentDir` result) in the analysis sections, while the re-analyst address list in the same record notes `[0x4e7fd0]` as the write base / CWD. Both denote the process working directory (`app\data\`), and the dynamic evidence in §8.2 — the file landing exactly at `<install-dir>\app\data\CMDEXT001.DLL` — fixes the effective value empirically. The published claim is the behaviour, not the address: unauthenticated uploads land in the directory the plugin loader scans.

## 9. Reachability and Security Impact
`mili.exe` is the SCADA web/HMI service and a Modbus TCP host; code execution inside it is, practically, code execution on the control-system server.
- **No authentication barrier.** On default configuration nothing separates a network client from an arbitrary file write inside the application directory, or from killing the HMI service. No login, no session, no token to obtain. Any host that can reach TCP 11234 — engineering workstation, operator PC, compromised DMZ host, or a device on a flat plant network — can run the chain.
- **Confidentiality (High).** Native code in the SCADA process can read tag databases, driver and protocol configuration, `config.xml` / `var.ini`, log files and any credential material reachable from the host (`/setip.html` alone accepts `PASSWD`-style parameters). The process is a legitimate consumer of plant data, so its read reach is broad by design.
- **Integrity (High).** The attacker owns the process that writes tag values and issues commands to field devices. Tag write endpoints (`/tagset.html`, `/tagsetmulti.html`) are unauthenticated on the same dispatcher, and the planted DLL runs with the product's own privileges — setpoints, alarm thresholds, stored records and device commands can all be altered while the operator UI keeps reporting normal values. An implant loaded from disk at every start persists across service restarts and reboots, inside a trusted process that monitoring tooling expects to exist. Because the artifact's name (`CMDEXT*.DLL`) is the product's own legitimate plugin naming scheme and it is loaded by the product's own loader at a normal lifecycle point, it produces no anomalous child process and no shell-spawn telemetry, and the restart that activates it looks like routine operational recovery from an outage.
- **Availability (High — demonstrated as a primitive in its own right).** `GET /reset.html` alone is an unauthenticated denial of service against the HMI/web server: issued repeatedly it prevents operator visibility and control through that interface indefinitely, whether or not the RCE step is used. In a plant relying on Laquis for supervision and alarming, losing the HMI during a process upset removes the operators' view at the worst possible moment.
- **Lateral and safety consequence.** A host running `mili.exe` reaches field devices (Modbus TCP 502 is served by the same process) and typically the rest of the control network. Untrusted code at this position is a pivot into ICS territory — engineering workstations, PLCs, gateways, record-keeping systems. Because tag values and commands mediate physical actuation, tampering is not confined to information: it can propagate to the physical process, with the attendant safety risk to personnel and equipment.

## 10. Mitigation
Vendor-side fixes, in priority order:
1. **Authenticate the dispatcher by default.** Remove the `[0x517bc0] == 0` short-circuit at `0x43ccf4`–`0x43ccfb`. When no password is configured the dispatcher must deny state-changing endpoints rather than serve them — fail closed, not open. Require first-run password setup, and move the credential out of a `?PWD=` query-string comparison (`0x43cd11`, `0x43cd32`) into a proper session mechanism: HTTP digest or TLS auth, or a signed session token — never a URL parameter, never a single static string with no lockout.
2. **Validate the upload handler.** At `/uploade.html` (`0x43d329`): reject any filename containing a path separator or `..` (normalize and confine to the data directory), enforce an extension allow-list that never permits `*.dll`, `*.exe`, `*.ocx` or any other loadable image type, and validate content per declared type. Restrict the endpoint to authenticated engineering sessions — remote file upload into the application directory has no legitimate unauthenticated use.
3. **Break the load sink.** The `CMDEXT*.DLL` loader (`0x4998c0`) must not load anything from a directory writable over the network. At minimum verify Authenticode signatures (or a vendor signature/hash allow-list) before `LoadLibraryA`, and move plugin discovery to a directory the web component cannot write to. Treat this as untrusted-library loading (DLL planting), not a benign extension mechanism.
4. **Gate `/reset.html`.** An unauthenticated request must not be able to terminate the SCADA web service (`0x43cff2`, stop flag `[0x517b50]`). Require authentication, add rate limiting and audit logging so a remote party cannot induce outages — and so the outage that drives the restart in this chain is not freely available.
5. **Separate the trust zones.** Do not serve the HTTP management API on `0.0.0.0` from the same process that hosts Modbus TCP and device drivers. Bind to configured management interfaces, require TLS, and run the web component under a low-privilege service account with no device-write rights the HMI does not strictly need.
6. **Audit the rest of the dispatcher.** `/save.html`, `/saveconfig.html`, `/delete1.html` and `/logdelete1.html` carry path-traversal write/delete primitives and `/setip.html` accepts network parameters; each needs the same authentication and confinement. On a default install all are unauthenticated.

Operator-side measures until a fix ships:
- Bind port 11234 to trusted interfaces only, or block it at the ICS firewall/DMZ boundary; never expose the Laquis web server to untrusted networks or the internet. If remote HMI web access is not required, leave the web server feature disabled in the `aq.exe` GUI.
- Configure `[MODE] PASSWD` in `var.ini` so the dispatcher's password gate is at least engaged (understanding that the `?PWD=` scheme of §4.1 remains weak).
- Apply a file-integrity baseline over `<install-dir>\app\data\`: any `CMDEXT*.DLL` you did not deploy should be treated as evidence of compromise. This is the single highest-value detective control for this chain.
- Alert on unauthenticated `POST /uploade.html`, on `GET /reset.html` in web/HMI access logs, and on repeated unexplained `mili` restarts.

## 11. CWE & CVSS
**CWE classification.**

| CWE | Where it applies |
|---|---|
| **CWE-434** — Unrestricted Upload of File with Dangerous Type (documented in the research record) | `POST /uploade.html` accepts arbitrary binary content with an attacker-chosen filename; the PoC delivers a PE32 DLL. Content and extension are both unvalidated. |
| **CWE-78** — Improper Neutralization of Special Elements used in an OS Command (documented in the research record, the execution half of the chain) | The planted image reaches `LoadLibraryA` → `DllMain`, yielding attacker-controlled execution in the SCADA process. |
| **CWE-427** — Uncontrolled Search Path Element (mapped in this advisory) | The loader `FindFirstFileExW("CMDEXT*.DLL")`s its own current directory and loads every match — untrusted-search-path DLL planting. |
| **CWE-306** — Missing Authentication for Critical Function (mapped in this advisory) | The dispatcher skips its only credential check when no password is configured, leaving file upload, process shutdown and configuration endpoints open to anonymous clients by default. |
| **CWE-22** — Path Traversal (contributing, mapped in this advisory) | The `Content-Disposition`-derived filename is concatenated onto the base directory without neutralizing `..`; not required for this chain, but it extends the write primitive beyond the data directory. |
| **CWE-400 / CWE-770** (contributing, mapped in this advisory) | Unauthenticated `/reset.html` lets an anonymous party terminate the service repeatedly. |

**CVSS — Base Score 9.8 (Critical)**, vector as documented in the research record: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- `AV:N` — reachable over the network on TCP 11234 (bound `0.0.0.0`). `AC:L` — both attacker-controlled steps are single unauthenticated HTTP requests with no race, no memory-corruption guesswork and no environmental dependency; the payload is a self-contained 1024-byte PE image built in memory.
- `PR:N` — no privileges and no credentials are required; the default configuration performs no authentication.
- `UI:N` — no victim interaction is needed for delivery or for the crash-out; the remaining step, restart of `mili`, is a routine operational event in SCADA deployments (maintenance, supervisor watchdog, crash recovery, reboot) and is itself provoked by the attacker through the unauthenticated `/reset.html` DoS. The "plant + reboot" pattern is an accepted RCE class and was explicitly tested and not refuted in the adversarial review (§8.4, F5).
- `S:U` — execution occurs within the vulnerable component's authority (the `mili.exe` process); downstream field devices are reached through that same component's normal interfaces.
- `C:H / I:H / A:H` — arbitrary native code as the SCADA/HMI process: full read access to plant and configuration data, full ability to alter tags/commands/records, and full ability to stop the service (the shutdown alone is already demonstrated as an unauthenticated primitive).

---

*This advisory is published at https://0day-rubbish.com/blog/lcds-laquis-scada-unauth-uploade-cmdext-dll-rce as part of batch-11-2026-09. Disclosure status is tracked in DISCLOSURE-STATUS.md. Research enquiries: disclosure@0day-rubbish.com.*
