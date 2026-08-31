# DrayTek Vigor 2960 v1.5.1.6 — uploadlangs Command Injection → Root RCE

## 1. Overview

DrayTek Vigor 2960 is an SMB enterprise router/firewall/VoIP gateway (CII-class edge infrastructure). Firmware v1.5.1.6 runs lighttpd 1.4.35 (`usr/sbin/lighttpd`, ARM) serving `/cgi-bin/*` via mod_cgi; the core management CGI `mainfunction.cgi` (217,812 bytes, ARM A32, non-PIE, stripped) runs as **root**. The CGI contains 292 `system()` + 92 `popen()` shell sinks (384 total).

The `action=uploadlangs` handler (`fcn.0001157c`) retrieves the uploaded multipart file, runs the **filename** through `cgiEscape`, extracts the basename, and embeds it **unquoted** into `system("mv %s /www/langs/%s")`. `cgiEscape` (libcgi.so.1 @ 0x3ad0) is an **HTML** escaper that only encodes `<`, `>`, `&` — every shell metacharacter (`;`, `$`, backtick, `|`, space, `(`, `)`, `{`, `}`, `~`, `^`, `#`, `?`, `*`) passes through unchanged. A sibling handler (`/trustcaupload`) applies a real shell sanitizer (`fcn.0000ad8c` replaces `; % \` `| > space ' " $ \t \n \r` with `+`), but `uploadlangs` does not — a developer omission.

An authenticated admin (privilege > 3) uploads a file whose filename is `;id|tee /tmp/m_draytek_uploadlangs;#`; the shell splits on `;`, runs `id|tee` as root, and `#` comments out the trailing ` /www/langs/<temp>`. Verified on the real ARM binary under qemu with an interposer hooking only the CGI file-access functions (the real `cgiEscape`, `snprintf`, and `system` all executed), producing a root-owned marker.

## 2. Vulnerability Summary

- **Type**: Authenticated OS command injection → root RCE (CWE-78)
- **Root cause 1 (CWE-78)**: the `uploadlangs` handler embeds `basename(cgiEscape(filename))` unquoted into `system("mv %s /www/langs/%s")` — `/bin/sh -c` splits on injected `;`
- **Root cause 2 (CWE-116)**: `cgiEscape` is an HTML escaper (only `<`/`>`/`&`), not a shell escaper — shell metacharacters pass through
- **Root cause 3 (CWE-20)**: the shell sanitizer `fcn.0000ad8c` is applied to the `/trustcaupload` filename but **omitted** from `uploadlangs` (developer omission)
- **Result**: authenticated admin → root RCE. CVSS 8.8.

## 3. Authentication Boundary

The `uploadlangs` sink is reached from `main` after a privilege check: `main` calls `fcn.00019164` (privilege check) at 0x23b78, `cmp r0, 3` at 0x23b7c, and `ble 0x24040` (skip if privilege ≤ 3). The handler therefore requires **privilege > 3 (admin)**. The action dispatch table at 0x23fdc has no privilege gate for `action=` paths in general, but `uploadlangs` is reached only through the privileged branch in `main` — there is no unauthenticated path to this sink (confirmed by a full FUE surface-exhaustion gate: 49 pre-auth handlers reviewed, 0 reachable with attacker-controlled input to a shell sink under default configuration).

## 4. Attack Surface

- **Entry**: `POST /cgi-bin/mainfunction.cgi` with `action=uploadlangs` and a multipart file whose `filename` is the payload
- **Controllable parameter**: the multipart upload filename (passed through `cgiEscape` then embedded unquoted)
- **No shell sanitizer**: `cgiEscape` only encodes `<>&`; `;`, `|`, `#`, space, etc. pass through
- **Privilege**: root — `mainfunction.cgi` runs as root
- **Non-PIE binary**: function pointers are absolute addresses (not directly relevant to this injection, but noted for the research context)

## 5. Sink Identification

`uploadlangs` handler (`fcn.0001157c`):

```asm
0x11590  bl cgiGetFiles          ; r8 = file list (NULL-terminated array of file-struct pointers)
0x115ac  bl cgiGetFile           ; r6 = file struct ([r6+8]=filename, [r6+0xc]=temp_path)
0x115b8  ldr r0, [r6, 8]         ; r0 = filename (attacker-controlled multipart filename)
0x115bc  bl cgiEscape            ; r4 = cgiEscape(filename)  -- encodes ONLY < > &
0x115d4..0x115ec                 ; basename extraction (last '\' 0x5c)
0x11608  str r4, [sp]            ; 1st %s = basename(cgiEscape(filename))
0x1160c  ldr r3, [r6, 0xc]       ; 2nd %s = temp_path (server-generated, not attacker-controlled)
0x11614  ldr r2, "mv %s /www/langs/%s" @0x32188
0x1161c  bl snprintf
0x11624  bl system               ; SINK (root)
```

`cgiEscape` (libcgi.so.1 @ 0x3ad0, 336 bytes) behavior: first pass computes output length (`<`/`>` → +4, `&` → +5, others +1); second pass copies — `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, everything else byte-for-byte. Only HTML contexts are protected; shell contexts are not.

The real shell sanitizer `fcn.0000ad8c` (applied to `/trustcaupload` filenames) replaces `; % \` `| > space ' " $ \t \n \r` with `+` — it is **not called** in the `uploadlangs` path.

## 6. Source Identification & Controllability

The source is the multipart upload filename. The attacker controls the exact bytes (subject to `cgiEscape`'s `<>&` encoding); because the payload avoids `<>&`, it passes through `cgiEscape` unchanged. The basename extraction only strips a trailing backslash path component, so a payload without `\` survives intact. The temp_path (second `%s`) is server-generated and not injectable, but the first `%s` is fully controlled.

## 7. Data Flow

1. Authenticated admin POSTs `action=uploadlangs` with a multipart file whose filename is the payload
2. `cgiGetFiles`/`cgiGetFile` return the file structure
3. `cgiEscape(filename)` encodes only `<>&` (payload without those characters passes unchanged)
4. basename extraction keeps the full payload (no backslash)
5. `snprintf("mv %s /www/langs/%s", basename, temp_path)` builds the command
6. `system()` → `/bin/sh -c` splits on `;` and executes the injected command as root
7. `#` comments out the trailing path

## 8. Exploit Construction

```
filename = ;id|tee /tmp/m_draytek_uploadlangs;#
```

Expanded command:

```sh
system("mv ;id|tee /tmp/m_draytek_uploadlangs;# /www/langs/<temp>")
```

- `mv` (no args, errors harmlessly)
- `id|tee /tmp/m_draytek_uploadlangs` → executes as root, writes the marker
- `# /www/langs/<temp>` (comment, harmless)

The payload contains no `<`, `>`, or `&` (so `cgiEscape` leaves it unchanged) and no backslash (so basename keeps it whole).

## 9. Dynamic Verification

The real ARM binary was run under qemu-arm-static with an `LD_PRELOAD` interposer that hooks only `cgiGetFiles`/`cgiGetFile`/`cgiFreeList` (returning a fake file struct with the attacker filename); `cgiEscape`, `snprintf`, and `system` all executed as real code:

```
qemu-arm-static -L rootfs -E LD_PRELOAD=<interposer> mainfunction.cgi
```

Result: marker `/tmp/m_draytek_uploadlangs` = `uid=0(root) gid=0(root) groups=0(root)`, owner root:root — **ROOT_RCE_CONFIRMED**. The benign control (filename `english.lang`) produced no marker. The `>`-encoding behavior of `cgiEscape` was separately confirmed: a payload containing `>` produced `sh: 1: gt: not found`, while `;id|tee <marker>;#` (no `<>&`) executed cleanly.

## 10. Reachability & Impact

- **Reachability**: requires an authenticated admin session (privilege > 3); the sink executes on language-pack upload. The device has no default credentials (forced password change), so a real admin session is required — Target B.
- **Impact**: root command execution on the SMB edge gateway — VPN keys, firewall rules, routing state, VoIP services, and proxied traffic all under attacker control. Full takeover of the network edge.
- **Scope**: Vigor 2960 v1.5.1.6 and other firmware sharing the same `mainfunction.cgi` upload handler; no CVE covers this sink (CVE-2024-12987 covers a different, already-sanitized sink).

The language-pack upload is a routine administrator operation on the device, so the injection does not depend on an obscure feature: the same page that installs UI translations is the one that carries the shell payload. Because the CGI runs as root and the sanitizer omission is in a default handler, the exposure is direct on every unmodified v1.5.1.6 deployment — no feature flag, no non-default configuration, and no prior compromise is required beyond the admin session itself.

## 11. Fix Recommendations

1. Apply the `fcn.0000ad8c` shell-metacharacter sanitizer to the `uploadlangs` filename, matching `/trustcaupload`
2. Quote the filename in the `mv` command and prefer parameter-array execution (no `/bin/sh -c`)
3. Never route HTML-escaper output into a shell command; use a dedicated shell-escaper or validation
4. Apply the sanitizer audit to all 384 shell sinks in `mainfunction.cgi`

## 12. CWE & CVSS

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command — unquoted filename in `system()`
- **CWE-116**: Improper Encoding or Escaping of Output — HTML escaper used for a shell context
- **CWE-20**: Improper Input Validation — sanitizer omitted from the `uploadlangs` handler
- **CVSS**: 8.8 High — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
