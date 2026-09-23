# MultiTech Conduit AEP 6.3.6 — Authenticated Command Injection in `import_config` via Uploaded Filename → Root RCE

## 1. Overview

The MultiTech Conduit family (`mtcdt` / `mtcdtip` / `mtcdtiphp`) is an ARM-based IoT gateway running the vendor's mLinux distribution. The device analysed here ships firmware mLinux 5.4.199 (Yocto/OpenEmbedded build) with Access Edge Platform (AEP) 6.3.6 and mpower 6.3.12, on ARM 32-bit EABI5 hardware (NXP i.MX7, Cortex-A7).

The management interface is served by lighttpd 1.4.67 with `mod_fastcgi`. All API traffic under `/api/*` is proxied to a Unix socket at `/var/run/api/rcell_api.sock`, which is served by `/usr/bin/rcell_api` — a proprietary, stripped ARM32 ELF FastCGI daemon of roughly 2.4 MB that identifies itself as "MTS XAVIER API" (the embedded version string in the analysed image reads 6.3.5 inside a 6.3.6 firmware package). lighttpd is configured with `server.port=8080` and no `server.bind` restriction, so the management API listens on `0.0.0.0:8080` and is reachable from any interface that can route to the device.

The firmware image was recovered for analysis by treating the distributed `.bin` as a POSIX tar archive, which contains a 101 MB little-endian JFFS2 root filesystem image; that image was then unpacked for static and dynamic study. Static analysis was performed with a headless Ghidra 12.1.2 project against the daemon and its companion `libmts.so.0` runtime library.

Within the daemon, a command-controller layer (referred to in its own log strings as `CMDCTRLR`) dispatches the `/api/command/*` endpoints. One of those commands, `upload_config`, accepts a configuration archive via `multipart/form-data`. The handler that processes the upload builds a shell command by wrapping the **client-supplied filename** in single quotes and passing the result to a helper that ultimately calls `popen()`. No shell quoting or escaping is applied to the filename anywhere along the path, so a filename containing a single quote breaks out of the quoted context and injects arbitrary shell syntax. Because the daemon runs as root, the injected command executes as uid 0.

### Overview of the layered architecture

```
L1 External access   : HTTP/HTTPS management interface (lighttpd, 0.0.0.0:8080)
L2 Edge              : lighttpd 1.4.67 mod_fastcgi (no WAF, no TLS-inspection layer)
L3 Gateway           : FastCGI authorizer (per-request auth gate) + responder (/api/*)
                       -> /var/run/api/rcell_api.sock
L4 AuthN/AuthZ       : rcell_api FUN_001d15ac (5-step check: backend authentication /
                       logged-in IP binding / session room / role permission / login),
                       session bound to client IP
L5 Business logic    : command controller (CMDCTRLR), /api/command/* dispatch table —
                       import_config, app_upload, custom-app-upload-callback, passwd, ...
L6 Storage           : /var/config/db.json (fallback /etc/db_default.json, OEM /var/oem/db.json),
                       users=[] by default (no accounts provisioned at the factory)
```

The crux of the finding sits at L5: the command controller concatenates an uploaded configuration filename directly into the shell command `import_config '<filename>'`, which reaches `MTS::System::cmd` → `popen` → `/bin/sh -c`. Since single quotes in the filename are never escaped, the quoting boundary is broken and shell metacharacters are interpreted.

## 2. Vulnerability Summary

- **Type**: authenticated OS command injection leading to root-level remote code execution (CWE-78, with CWE-88 argument/quoting breakout as the enabling mechanism).
- **Root cause 1 (CWE-78)**: the `import_config` handler at `FUN_000899a8` (0x899a8) composes `import_config '<filename>'` from an unsanitised client value and executes it through a shell.
- **Root cause 2 (CWE-116)**: the `multipart/form-data` parser at `FUN_001ef560` (0x1ef560) strips only surrounding double quotes and reduces the value to a basename; it performs no single-quote escaping. The daemon contains no shell-quoting helper at all.
- **Root cause 3 (CWE-250)**: `rcell_api` runs as root, so injected commands inherit uid 0 — there is no privilege boundary between an authenticated web role and the operating system.
- **Execution primitive confirmed**: `MTS::System::cmd` is `popen(cmd, "r")`, i.e. `/bin/sh -c cmd`, not an `execvp`-style direct execution. This is the linchpin that makes the single-quote breakout effective.
- **Result**: an administrator can execute arbitrary OS commands as root on the gateway. CVSS 7.2 (High) under the documented vector — see section 12.
- **A second, unfixed sink of the same class** was identified statically: `custom-app-upload-callback` (`FUN_0008caf4`, 0x8caf4) builds `cp -f '<filename>' /.fota;` and runs it via `system()`, which is the identical quoting defect. It is reported here as static evidence only; it was not exercised during verification. A third candidate, `export_config` (`FUN_00089738`, 0x89738), was located but its command template was not resolved.

## 3. Authentication Boundary

This is a **post-authentication** vulnerability requiring a session with the **administrator** role. Two independent pieces of evidence establish the boundary.

First, the role-based permission files under `/etc/api/` — `permissions-admin.json`, `permissions-user.json`, `permissions-guest.json` — encode each endpoint as a five-element tuple of the form `[read, write, execute, <reserved>, visible]`. For `command/upload_config` the guest profile is `[false,false,false,false,true]` (visible but wholly denied), while the admin profile is `[true,true,true,true,true]`. The endpoint is therefore reachable only by an admin-role session, not by a user-role or guest-role session. `command/app_upload` shows the same shape. By contrast `command/passwd` is granted `[true,true,true,true,true]` even to guest, but its underlying helper (`mts-ubpasswd`) uses a fixed command string with no interpolated input, so it offers no injection surface.

Second, every request passes the FastCGI authorizer and the daemon's own session validator (`FUN_001d15ac`), which performs a five-stage check: backend authentication service validation, IP binding of an already-logged-in identity, session-room bookkeeping, role permission lookup, and login state. Sessions are bound to the client IP, so a captured session cannot simply be replayed from a different source address. The login response observed during verification confirms the resulting role and the remote (non-IPC) nature of the session:

```json
{"code":200,"result":{"address":"<client-ip>","isipcuser":false,"isremoteuser":false,
 "permission":"admin","port":"12345","timestamp":"<elided>",
 "token":"<session-token>","user":"admin"},"status":"success"}
```

**How the administrator role is obtained.** The device ships **without factory-default credentials**. The configuration database `/var/config/db.json` (with defaults in `/etc/db_default.json` and OEM overlays in `/var/oem/db.json`) contains `users=[]` in its default state, meaning no accounts exist out of the box. The administrator account and its password are established by the deployer during device commissioning. Consequently the attack does not depend on well-known default credentials, and there is no hard-coded backdoor account in this path; it requires a valid credential that a legitimate operator provisioned. An exhaustive review of the unauthenticated attack surface across eight dimensions found no route to this sink without a valid admin session, so the finding remains post-authentication.

## 4. Attack Surface

- **Entry point**: `POST /api/command/upload_config` on the management API (lighttpd, TCP 8080, `0.0.0.0`), `Content-Type: multipart/form-data`.
- **Attacker-controlled value**: the `filename` parameter of the `Content-Disposition` header in the uploaded part. The part body itself is not required to be a valid archive for the injection to occur.
- **Authentication needed**: an administrator session (`permission: "admin"`), obtained by provisioning credentials at commissioning and authenticating via `POST /api/login`.
- **Transport**: plain HTTP/HTTPS end to end. No man-in-the-middle position, no RMI/JNDI-style remote interface, and no default-credential dependency are required.
- **Privilege of the injected command**: root — `rcell_api` runs as uid 0 and its children inherit that privilege.
- **Payload character budget**: the injection needs only `'`, `;`, `#` and ordinary command text. The basename reduction step truncates everything before the **last** `/` or `\` in the filename, so the injected command must avoid a literal slash unless it is produced indirectly (for example `$(printf '\x2f')`) or the payload uses relative paths and bare command names.
- **Discovery method**: cross-referencing nine command-template strings extracted from the binary led to fourteen decompiled functions, of which two were confirmed as command-injection sinks (`import_config`, `custom-app-upload-callback`). A third function, `export_config`, was located as a candidate but its command template was never resolved, so it is not counted among the confirmed sinks.

## 5. Sink Identification

### Sink identification: command construction

The `import_config` handler `FUN_000899a8` (0x899a8) builds the command with three consecutive `std::__ostream_insert` calls into a stream buffer, then hands the result to the execution helper:

```c
// DAT_00089db8 = 0x212e00 -> .rodata "import_config '"  (length 0xf)
std::__ostream_insert(ostream, "import_config '", 0xf);
// *param_3 is the caller-supplied filename (std::string data pointer + length)
std::__ostream_insert(ostream, *param_3, param_3[1]);      // NO ESCAPING
// DAT_00089dbc = 0x223770 -> .rodata "'"  (length 1)
std::__ostream_insert(ostream, "'", 1);

MTS::System::cmd(output, cmd);                             // -> popen -> /bin/sh -c
```

The resulting command string is exactly `import_config '<*param_3>'`. The value is wrapped in single quotes but is never escaped, so any `'` inside it terminates the quoted context.

The handler is registered in the command-controller dispatch table. The table entry at 0x9aa08 is `{0xb1980, 0x271e34, 0x899a8, 0x26fd4c}`, pointing at `FUN_000899a8` as the handler and referencing the log string at 0x26ebf4, `"[CMDCTRLR] Receiving Configuration Upload"`, which identifies the code path in runtime traces.

### Sink identification: shell execution is confirmed, not assumed

The whole finding depends on whether `MTS::System::cmd` executes through a shell. If it used `execvp` with an argument vector, the single-quote breakout would be inert. Disassembly of `libmts.so.0` settles the question — the mangled symbol `_ZN3MTS6System3cmdERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERS6_` at 0xc780 is:

```asm
0xc7ac:  bl sym.imp.popen     ; popen(cmd, "r")  ==  /bin/sh -c cmd
0xc7cc:  bl sym.imp.fgets     ; read command output
0xc7ec:  bl sym.imp.pclose    ; close the stream
```

`popen(cmd, "r")` is defined to run `/bin/sh -c cmd`, so full shell parsing (quotes, `;`, `#`, redirection, command substitution) applies to the constructed string. This is the decisive confirmation that removes the main falsification risk for the finding.

## 6. Source Identification

### Source identification: the multipart parser

The tainted value originates in the `multipart/form-data` parser `FUN_001ef560` (0x1ef560), which extracts `filename=` from the `Content-Disposition` header into a local `std::string`. Before the value is used, it undergoes exactly three transformations:

1. `MTS::Text::replace` (string constant at 0x20be9c) strips surrounding double-quote (`"`) characters.
2. `find_last_of("/")` (0x21097c) reduces the value to a basename — an anti-path-traversal measure.
3. `find_last_of("\\")` (0x23381c) does the same for Windows-style separators.

**No single-quote handling exists.** A global search for shell-quoting or single-quote escaping logic in the daemon found none; the only escape-like routines are `curl_easy_unescape` and an `escape_seq` helper, both unrelated to shell safety. The byte 0x27 is neither removed, encoded nor rejected at any point.

A branch at 0x1efbc0 checks whether a filename was supplied (`local_214 != 0`). If present, the **client's filename** is used verbatim; a generated `tmp_<timestamp>` name (prefix constant at 0x23388c) is substituted **only when no filename is provided**. The safe fallback therefore exists in the code but is not applied to the attacker-chosen case.

### Source identification: controllability assessment

Both decisive questions resolve in favour of exploitability. Is the filename attacker-controlled? Yes — the `Content-Disposition` value flows straight into the parser's local string and is appended to a base directory for storage. Is the single quote sanitised? No — only double-quote stripping and basename reduction occur, and neither touches 0x27. The attacker thus controls the breakout character, the injected command text, and the terminator, subject only to the no-literal-slash constraint imposed by the basename step.

## 7. Data Flow

### Data flow: six stages from HTTP request to shell

```
(1) FUN_001ef560  multipart/form-data parser @ 0x1ef560
        extracts Content-Disposition filename=  -> attacker-controlled string
(2) save-path construction @ 0x1efbe0
        path = <base_dir at param_1+0x2d8> + "/" + <filename>
(3) JSON "filename" key @ 0x1f0220
        filename and full path are stored as JSON values
(4) FUN_001f66cc  HTTP handler @ 0x1f66cc
        routes the request to the upload_config command
(5) FUN_0009a740  upload_config wrapper @ 0x9a740
        reads the JSON value back out into param_3
(6) FUN_001ec958  executor @ 0x1ec958
        Json::Value::asString() -> param_3 -> FUN_000899a8 (sink)
        sink builds: import_config '<filename>'
        MTS::System::cmd -> popen -> /bin/sh -c   (root)
```

The filename crosses a JSON serialisation boundary between stages (3) and (5), which is worth noting because JSON encoding does not neutralise shell metacharacters — it only escapes characters meaningful to JSON. The single quote survives the round trip intact, as does the semicolon and the comment character.

### Data flow: end-to-end interaction

```
[attacker] --HTTP/HTTPS--> [lighttpd 0.0.0.0:8080] --FastCGI--> [rcell_api.sock]
  (a) POST /api/login  {"user":"admin","password":"<provisioned>"}
        -> Set-Cookie session token, permission=admin, session bound to client IP
  (b) POST /api/command/upload_config   (Cookie: <session>)
        Content-Disposition: form-data; name="config"; filename="x'; <CMD> ;#"
        -> parser keeps the single quote
        -> handler builds: import_config 'x'; <CMD> ;#'
        -> MTS::System::cmd -> popen -> /bin/sh -c
        -> <CMD> executes with uid 0
```

## 8. Exploit Construction

### Exploit construction: the payload

The minimal payload wraps the command between a quote-semicolon prefix and a trailing comment:

```
Content-Disposition: form-data; name="config"; filename="x'; <CMD> ;#"
```

After parsing, the daemon produces:

```sh
import_config 'x'; <CMD> ;#'
```

The shell reads this as three tokens: `import_config 'x'` (which fails harmlessly — no such utility is on the path — but its failure does not stop the rest of the line), then `<CMD>`, which is the injected command, then `;#` where `#` comments out the trailing single quote from the template so the line remains syntactically valid. A command-substitution variant such as `x'$(<CMD>)'.tar.gz` also works where output capture is preferred.

The hard constraint is the absence of a literal `/` in `<CMD>`: because the parser takes everything after the last slash as the basename, a payload such as `touch /tmp/x` is truncated to `x` before it ever reaches the sink. Working forms therefore use relative paths, bare command names, redirection to a relative filename, or an encoded slash produced at runtime with `$(printf '\x2f')`.

### Exploit construction: tooling

The published proof-of-concept script (`exploit/multitech_conduit_import_config_rce.py`, Python standard library only) implements both transports and takes the target, port, credentials and payload as command-line arguments:

```sh
python3 multitech_conduit_import_config_rce.py --host <target-host> --port 8080 \
    --user admin --password '<provisioned-admin-password>' --verify
```

The `--verify` mode injects `id > <marker>` using a relative filename, so the payload contains no slash and survives basename truncation, and the marker lands in the daemon's working directory. A `--socket` mode speaks FastCGI directly to `rcell_api.sock` (useful when the front-end web server is not running, as in an emulation environment); both modes traverse the same daemon code path, so the injection semantics are identical. `--tls` switches to HTTPS, `--cmd` supplies an arbitrary payload, and `--field-name` and `--remote-addr` parameterise the multipart field and the presented client address.

`--remote-addr` defaults to `192.0.2.10`, a documentation-range address, so a default socket-mode invocation simulates a non-loopback remote client. The `SERVER_ADDR` value sent alongside it stays fixed at `127.0.0.1` independently of the client address, matching the configuration under which the verified run was made. Passing a loopback client address instead would select a designed-in IPC trust path that maps the session straight to the administrator role without a credential; that path is a local trust design and is explicitly outside the scope of this finding, which is why the script does not default to it.

## 9. Dynamic Verification

### Dynamic verification: shell-level replication

The exact command string the handler constructs was reconstructed and executed inside the target's own ARM shell environment — busybox `sh` from the extracted root filesystem, run under `qemu-arm-static` with the rootfs as the library path:

```sh
malicious="x'; touch <marker> ;#"
cmd="import_config '${malicious}'"      # becomes: import_config 'x'; touch <marker> ;#'
qemu-arm-static -L <lab-rootfs> <lab-rootfs>/bin/busybox sh -c "$cmd"
```

The malicious filename created the marker file. The `import_config not found` error is expected and irrelevant: the shell still executes the segment following `;`. The negative control with a benign filename (`benign.txt` → `import_config 'benign.txt'`) created no marker, confirming the artifact is produced only by the injected segment. This step ran the command directly and so did not traverse the multipart basename reduction; that is why this replication used an absolute marker path while the HTTP-level test used a relative one.

### Dynamic verification: end-to-end against the running daemon

The daemon was then run for real — the root filesystem extracted from the AEP 6.3.6 image under a chroot, started through its `angel` supervisor with the socket flag, exposing `rcell_api.sock`. The proof-of-concept was executed against it in socket mode with an administrator account created at commissioning and a **non-loopback** `REMOTE_ADDR`, so the resulting session is a genuine remote session rather than a loopback/IPC shortcut; the login response reported `isipcuser: false` and `permission: "admin"`.

Observed sequence:

- `POST /api/login` → `code 200`, `status success`, `permission "admin"`, session token issued and bound to the presented client IP.
- `POST /api/command/upload_config` with filename `x'; id > <marker> ;#` → the daemon constructed `import_config 'x'; id > <marker> ;#'` and returned:

```json
{"code":200,"status":"success","type":"upload"}
```

- Server-side artifact confirming execution:

```
-rw-r--r-- 1 root root 39 <marker>
uid=0(root) gid=0(root) groups=0(root)
```

The marker is owned by root and contains `id` output showing uid 0, gid 0 and group 0 — the injected command ran with full root privileges. Because the command's output was redirected into the file rather than echoed back into the HTTP response, the injection is **blind** at the protocol level: the response body contains no `uid=`. Confirmation therefore rests on the server-side artifact. A control run with a benign filename was rejected with HTTP 400 `"Config file not found in archive"` and created no marker.

### Dynamic verification: convergence of independent passes

Two further independent re-analysis passes — each rebuilding the decompilation and disassembly from scratch and repeating the shell replication — reached the same conclusion with high confidence, and an additional full end-to-end emulation run reproduced the root-owned marker using a different payload pair (`touch` plus `id` redirection) with the same benign controls. Together with the proof-of-concept run described above, four independent evidence sources converge on the same result: command injection through the uploaded filename yields root-level code execution.

## 10. Reachability and Security Impact

### Reachability

Reachability requires network access to the management API and valid administrator credentials provisioned at commissioning. Given those, the path is deterministic and unauthenticated by nothing else: no race, no memory-corruption primitive, no unusual configuration and no user interaction are involved, and the request completes in a single HTTP exchange. The management API binds to all interfaces by default, so reachability from remote networks depends only on how the deployment exposes or firewalls TCP 8080. An exhaustive review of the unauthenticated attack surface found no route to this sink without a valid admin session; the finding is therefore scoped as post-authentication.

### Security impact

Once triggered, the attacker has arbitrary command execution as root on the gateway, which is the same privilege the management daemon itself holds. Practical consequences include full takeover of the device, reading and rewriting the configuration database that stores device identity and credentials, installing persistent implants in the root filesystem, and using the gateway — whose function is to bridge constrained field devices and networks with IP infrastructure — as a pivot point into the segments it connects. There is no privilege separation or containment layer between the authenticated web role and the operating system, so the "administrator" web role trivially becomes full system control on a device whose whole purpose is to be reachable from operational networks.

### Affected versions and the evidentiary basis

The distinction between what was executed and what is inferred matters here:

- **AEP 6.3.6** (mLinux 5.4.199, mpower 6.3.12) — **verified by execution**. This is the firmware whose root filesystem was extracted, whose `rcell_api` was decompiled, and against whose running daemon the end-to-end exploitation succeeded. Note that the daemon's embedded self-identification string inside this image reads 6.3.5; the verified artifact is the 6.3.6 firmware package.
- **AEP 6.3.0** — **supported by direct binary comparison**. A patch-level diff between 6.3.0 and 6.3.6 shows the `import_config` handler unchanged, so the same sink is present in 6.3.0.
- **The continuous range 6.3.0 through 6.3.6** — **claimed on the basis of that endpoint comparison, not individually executed**. Intermediate releases were not each exploited; the range statement follows from the handler being byte-stable across the two diffed endpoints.

The diff evidence itself is strong. Between 6.3.0 and 6.3.6 the `app-manager` binary is byte-identical (matching SHA-256), while `rcell_api` grew by 20,488 bytes with the decompiled function count moving from 3607 to 3621 — and every change examined is feature addition rather than hardening. Specifically: the `import_config` handler is unchanged; the `custom-app-upload-callback` handler is unchanged; the `ping` command is unchanged; authorizer, session, loopback and commissioning strings are identical with zero additions and zero deletions; the five newly introduced `MTS::System::cmd` call sites all use hard-coded static strings (package-management feed install/update/list-upgradable, `df`, `du`) and interpolate no user input; the counts of `system()`, `popen()` and related process-execution calls are unchanged between the two versions; and a new `command/update_pkg` endpoint was added together with an SNMP printable-character check using `isprint`, which blocks non-printable bytes but explicitly does **not** block shell metacharacters such as `'`, `;` or `|`. The conclusion is that 6.3.0 → 6.3.6 is a functional release, not a security release, and the injection surface persists unfixed in the latest version examined.

### Independence

This analysis is original work on the `rcell_api` command controller. The only previously public vulnerability in this product line referenced by the research is CVE-2023-25201, which concerns the separate `app-manager` component and its application install/upload logic. The patch diff notes that `app-manager` is byte-identical across the compared versions, meaning that component's behaviour is unchanged, but that earlier public work describes a different binary and a different code path from the `import_config` sink documented here. The public vulnerability record for this product line is very small (two entries were identified in the national vulnerability database at the time of research), and none of them describes command injection through the configuration-upload filename in `rcell_api`. No CVE identifier is claimed for this finding; CVE-2023-25201 is cited here only to distinguish that earlier work from this one.

## 11. Fix Recommendations

1. **Stop invoking a shell for filename-bearing commands.** Replace the `popen`-backed `MTS::System::cmd` call in the `import_config` path with a parameter-array execution (`execv`/`posix_spawn` passing `import_config` and the filename as separate arguments), which removes shell parsing entirely and makes quoting breakout impossible.
2. **If shell invocation must be retained, quote defensively.** Escape every `'` as the sequence `'\''`, or reject outright any filename containing `'`, `;`, `|`, `&`, `$`, backtick, `<`, `>`, `(`, `)`, newline or carriage return before it is interpolated.
3. **Validate the filename against a strict allowlist** (for example `^[A-Za-z0-9._-]+(\.tar\.gz)?$`) and enforce it twice: at the multipart parser and again immediately before command construction, so no future caller can bypass the check.
4. **Never reuse the client-supplied name for shell construction.** The parser already generates a safe `tmp_<timestamp>` name when no filename is supplied; extend that behaviour to all uploads and keep the client name only as display metadata.
5. **Fix the sibling sink of the same class.** `custom-app-upload-callback` builds `cp -f '<filename>' /.fota;` and passes it to `system()` with the identical defect, and it is unchanged in the latest release; resolve the unresolved `export_config` template and audit every remaining command-template site for interpolated input. An `isprint`-style printable-character filter is **not** sufficient, since it permits all shell metacharacters.
6. **Reduce privilege.** Run the FastCGI daemon and its command children as a non-root service account where the device architecture allows, so that an injection in a management handler does not immediately confer uid 0.

## 12. CWE and CVSS

### CWE and CVSS classification

- **CWE-78** — Improper Neutralization of Special Elements used in an OS Command: the client-supplied filename is concatenated into a command string executed by `/bin/sh -c`.
- **CWE-88** — Improper Neutralization of Argument Delimiters in a Command: the single-quote wrapping is broken because 0x27 is never escaped.
- **CWE-116** — Improper Encoding or Escaping of Output: no shell-escaping layer exists between the parsed value and the constructed command.
- **CWE-250** — Execution with Unnecessary Privileges: the management daemon runs as root and its children inherit uid 0.

### CWE and CVSS score

The vector documented from the evidence is:

```
Vector, CVSS version 3.1
AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  =  7.2 (High)
```

Computed from that vector: impact sub-score 6.42 × (1 − 0.44³) = 5.873, exploitability sub-score 8.22 × 0.85 (AV:N) × 0.77 (AC:L) × 0.27 (PR:H, scope unchanged) × 0.85 (UI:N) = 1.235, base score = round-up-to-tenths(5.873 + 1.235) = round-up-to-tenths(7.108) = **7.2**.

Two clarifications about the numbering, because this finding is easy to mis-score:

- **Why `PR:H` and not `PR:L`.** The permission files restrict `command/upload_config` to the admin profile; a user-role or guest-role session is denied. The correct privilege-required value is therefore High, which yields **7.2**. The 8.8 figure often quoted for "authenticated device RCE" corresponds to `PR:L`; substituting `PR:L` into this same vector does compute to 8.8, but that substitution contradicts the documented permission model, so it is not used here. The research notes also carry a conditional statement that an unauthenticated route would score 9.8 under `PR:N`; the unauthenticated-surface review found no such route, so 9.8 is not claimed either. **7.2 is the figure used throughout this advisory.**
- **Scope.** `S:U` is retained: the vulnerable component and the impacted component are both the gateway itself. The pivotal value to adjacent networks described in section 10 is a consequence of root control of the device, not a separate vulnerable security authority, so no scope change is asserted.

---

*Research and write-up by the 0day Rubbish team. Technical detail published with a working proof of concept.*

- Advisory: https://0day-rubbish.com/blog/multitech-conduit-import-config-command-injection
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com
