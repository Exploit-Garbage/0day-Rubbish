# nanoDLP Unauthenticated Root RCE via G-code Injection

## Summary

A critical unauthenticated remote code execution vulnerability in nanoDLP (3D SLA print server) arises because the Guest (unauthenticated) endpoint `POST /formula` exposes a live nanoDLP config object through its embedded Otto JS sandbox (`nanodlpContext()`). The `Config` object is writable and `Config.Save()` persists changes to `db/machine.json`. An attacker injects malicious G-code `[[Exec <cmd>]]` into the `Config.ShieldUnpause` field (the G-code executed when the print engine unpauses) and saves it; the also-unauthenticated `GET /printer/unpause` endpoint then triggers the print engine to execute that G-code, reaching `os/exec` with shell semantics as root. Both steps are unauthenticated, exploitable in the default configuration, with no `[[Exec]]` allowlist/switch and no sanitization in `Config.Save()`. Dynamically verified with `uid=0(root)`.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: nanoDLP (3D SLA print control server)
- **Versions**: stable Linux amd64 build #10729 (2025-04); other builds sharing the same Guest /formula + /printer/unpause + Config persistence behavior are likely affected
- **Vendor**: nano3dtech.com

## Impact

- **Confidentiality**: Full read of the host filesystem and configuration as root
- **Integrity**: Arbitrary OS command execution as root
- **Availability**: Full control of the print server and host; ability to persist (injected G-code re-executes on every unpause)

## Exploitation Prerequisites

Default configuration; network reachability to the nanoDLP HTTP listener. Both `POST /formula` and `GET /printer/unpause` are unauthenticated; the server runs as root by default. The injected `[[Exec]]` G-code has no allowlist or kill switch, and `Config.Save()` does not sanitize. The chain was dynamically verified with `uid=0(root)`.

## Mitigation

1. Require authentication on `/formula` and `/printer/unpause` (or gate them behind an admin session)
2. Add an allowlist/switch for `[[Exec]]` G-code commands, or disable it entirely
3. Sanitize `Config.Save()` to reject `[[Exec]]` patterns before persisting
4. Do not run the server as root; run under a dedicated low-privilege user
5. Restrict network exposure of the print server to trusted management networks

## Timeline

- **Discovered**: 2026-08-07
- **Public Disclosure**: 2026-08-09 (batch #3)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
