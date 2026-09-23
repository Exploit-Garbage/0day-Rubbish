# Lantronix SGX5150 — Authenticated Command Injection in FsBrowseClean → Root RCE

Advisory: https://0day-rubbish.com/blog/lantronix-sgx5150-fsbrowseclean-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com
## Summary

Lantronix SGX5150 firmware 9.13.0.0R7 contains an authenticated OS command injection in the `FsBrowseClean` AJAX handler (`0x5eea0`) of `/bin/ltrx_evo`. A per-character filter blocks `&`, `|`, `<`, `;`, `!`, `$`, backslash, backtick and `>` but permits single quote, `#` and newline. The `path` POST parameter is concatenated into `/sbin/ltrx_usb_umount '%s'` and run through `/bin/sh -c` as root.

Sending `path=x'%0a<cmd>%20%23` closes the quoted argument, opens a new shell line carrying the attacker's command, and comments out the trailing quote. The sink is blind. Verified by replicating filter and sink in a chroot of the extracted ARM rootfs under `qemu-arm-static`: the marker was created owned by `root`. No physical device was used.

## CVSS Score

Vectors are CVSS version 3.1, written without a version prefix so each base score checks against the metric string beside it.

- **Primary, adopted — 7.2 High**: `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2. `PR:H` rests on a genuine privileged web session being required. The factory administrator is recorded as `admin` with a password placeholder described as serial-derived; that derivation was never reversed and no credential artifact was examined, so it is a record assertion rather than a verified fact. What was proved end to end is the sink chain reaching root under emulation; the session precondition is static analysis.
- **Conditional, NOT verified — 9.8 Critical**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8. Applies only if the serial number is obtainable, which would make the factory credential no secret and the chain effectively unauthenticated. Serial recovery was NOT verified, and neither was the derivation itself.
- **Rejected hypothetical — 8.8**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8, but no lower-privileged account passing the filesystem write test was enumerated, so this is not claimed. See the scoring note below.
- **Secondary non-default Digest defect — 9.8 Critical**: reachable only where Digest authentication is configured.

Scoring note: the research record attached 8.8 to the `PR:H` vector used for the primary rating. That vector does not compute to 8.8; it computes to 7.2. This advisory recomputes the base score from the vector printed beside it and reports 7.2, leaving 8.8 in place only as the labelled `PR:L` hypothetical above.

## Affected Products

Lantronix SGX5150, firmware 9.13.0.0R7 verified. Other versions and EVO-framework sibling models were not verified; the shared helper script is an unaudited lead. Prerequisite: a session passing `IsGroupListWritable(identity, "filesystem")`, and no mounted USB volume. The research notes record the factory administrator as `admin` with a password described as serial-derived, and also record a forced password change at the administrator's first login; both are recorded properties of the product, not behaviours this research verified, and no hard-coded credential was encountered in the code paths analysed.

## Impact

Root execution on an IT/OT gateway: full read of configuration and serial traffic, arbitrary root modification, persistent implantation, total availability loss, and a pivot into segmented networks.

## Mitigation

1. Replace the shell call with fixed-argv `execv`.
2. Add `0x0a`, `0x0d` and `0x27` to the filter reject set.
3. Require `path` to canonicalize inside the USB mount namespace.
4. Enforce authentication in the AJAX dispatcher, not per handler.

## Secondary Finding

The Digest username extractor at `0xff838` performs only `strstr("username=")` + `strchr('"')` + `strncpy`, with no nonce, realm or response verification, and is a separate CWE-287 improper-authentication defect. When an administrator has configured Digest authentication (so the runtime URI table gains auth-type `2`/`5` entries), a forged `Authorization: Digest username="admin", response="garbage"` header alone sets `context[0]` to `admin` and makes `IsAdminUser` return 1, reaching the same sink with no password. Vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical). The defect depends on a non-default configuration and is independent of, and not additive to, the primary finding.
