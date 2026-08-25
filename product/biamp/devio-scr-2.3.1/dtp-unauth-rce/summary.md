# Biamp Devio SCR-20/25 — Unauthenticated DTP Protocol Quote-Injection → Root RCE

## Summary

Biamp Devio SCR-20/25 (firmware 2.3.1) is a closed-source meeting-room DSP controller with a proprietary plaintext protocol (`biampdtp`, TCP 4030). The `DevioSCR` supervisor binds `0.0.0.0:4030` with no firewall and dispatches `DEVICE`-instance commands **without any authentication gate** (CWE-306).

The `DEVICE set password/location <value>` handler builds an `echo -e 'biamp:<value>' | chpasswd` command and passes it to `popen()` as root (CWE-78). The value is wrapped in single quotes but the quote character is not escaped: a value of `';id>/tmp/m;#` closes the quote, injects `id>/tmp/m`, and comments out the trailing quote and pipe, achieving arbitrary command execution as **root**.

Verified with a fresh zero-byte TCP connection (no session, no credentials): `+OK` response, marker `uid=0(root)`, and strace-confirmed `execve("/usr/bin/id")`. No MITM, no default-credential dependency, remotely reachable. CVSS 9.8.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Biamp Devio SCR-20/25 (meeting-room DSP controller)
- **Firmware**: 2.3.1 (devioscr_2-3-1.dfa)
- **Vendor**: Biamp Systems
- **Protocol**: proprietary `biampdtp` plaintext protocol, TCP 4030 (`0.0.0.0` bind, no iptables)

## Impact

- **Confidentiality**: Full device compromise as root; room audio configuration and environment data exposed
- **Integrity**: Arbitrary command execution on the DSP controller
- **Availability**: Full control of the meeting-room AV infrastructure

## Mitigation

1. Add an authentication gate to every `DEVICE`-instance command handler (the `SESSION` instance already has one)
2. Escape the single quote (and all shell metacharacters) in values passed to the echo/chpasswd sink
3. Replace the shell-based `echo | chpasswd` pattern with direct system calls or a hardened helper
4. Bind the DTP service to loopback or restrict it with firewall rules
5. Run `DevioSCR` with the least privilege required, not root
