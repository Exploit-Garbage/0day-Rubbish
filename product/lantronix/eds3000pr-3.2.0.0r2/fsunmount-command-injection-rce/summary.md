# Lantronix EDS3000PR — Authenticated Command Injection in FsUnmount → Root RCE

## Summary

Lantronix EDS3000PR industrial serial device server (firmware 3.2.0.0R2) contains an authenticated OS command injection in the `FsUnmount` web handler (`FUN_0005475c` in `/bin/ltrx_evo`). The handler validates the `path` parameter with a character bitmask that **allows single quotes and newlines**, then builds `/sbin/ltrx_usb_umount '/ltrx_user<path>'` and executes it via `system()` (shell-parsed) as root.

An authenticated administrator with filesystem write permission submits `path = x'\n<cmd> #` — the newline breaks out of the single-quoted command, the injected command runs on its own shell line, and `#` comments out the trailing quote. The payload passes the bitmask validator (which rejects `;`, `$`, `&`, `>`, `<`, `|`, backtick, backslash, but allows `'` and `\n`). Verified with a root-owned marker in a qemu-arm chroot using the real rootfs `/bin/sh`.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Lantronix EDS3000PR (8-port industrial serial device server)
- **Versions**: firmware 3.2.0.0R2 verified; other NUEVO-2 firmware with the same handler is likely affected
- **Vendor**: Lantronix
- **Prerequisite**: authenticated admin with filesystem write permission (default admin credential is derived from the device serial number)

## Impact

- **Confidentiality**: root access to the serial device server — connected industrial devices and their data reachable
- **Integrity**: arbitrary command execution as root on the device; configuration, forwarding, and device-management state under attacker control
- **Availability**: full takeover of the industrial network gateway

## Mitigation

1. Add `'` (0x27) and `\n` (0x0a) to the rejected-character bitmask in the path validator
2. Execute `ltrx_usb_umount` via parameter-array `execv` instead of a shell command
3. Audit the `IseUSB` grep sink for the same injection class
