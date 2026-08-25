# VitalPBX — Authenticated Root RCE via asterisk_cli → dialplan System() (Privilege Escalation)

## Summary

VitalPBX 4.5.2 (closed-source on-prem IP PBX / contact center built on Asterisk) allows a web administrator to reach a **root shell on the PBX host** through the "Asterisk CLI Emulator" feature. The `asterisk_cli runCommand` dispatcher passes the `data` field **verbatim** to the Asterisk CLI with no filter, whitelist, or escaping (CWE-78).

Because `asterisk-pbx 20.20.1` runs as **root**, an admin can inject a dialplan extension containing the `System()` application:

```
dialplan add extension 7777,1,System(id>/tmp/dp_rce_clean) into rcectx_clean
```

`dialplan add` takes effect immediately in the in-memory dialplan (no reload). A subsequent `channel originate Local/7777@rcectx_clean application hangup` triggers the extension, and `System()` executes `sh -c "id>/tmp/dp_rce_clean"` as **root** (CWE-269 privilege escalation). Verified: marker file `uid=0(root)`.

Requires only a valid VitalPBX admin session (no default credentials, no MITM, no SIP/AMI access). CVSS 8.8.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: VitalPBX (on-prem IP PBX + contact center)
- **Versions**: vitalpbx 4.5.3-8 / vitalpbx-api 4.5.1-2 / asterisk-pbx 20.20.1 (VitalPBX 4.5.2)
- **Vendor**: VitalPBX LLC
- **Stack**: nginx + php-fpm 8.2.32 (ioncube-encrypted) + MariaDB 10.11 + Asterisk 20 (running as root)

## Impact

- **Confidentiality**: root shell on the PBX host — call recordings, SIP credentials, CDRs, server data
- **Integrity**: arbitrary command execution as root; call routing and IVR tampering
- **Availability**: full PBX and host control; communications disruption

## Mitigation

1. Restrict `asterisk_cli runCommand` to a read-only command whitelist (`core show ...`); block `dialplan add`, `channel originate`, `module load`
2. Run `asterisk-pbx` as a non-root user (e.g., `asterisk`)
3. Disable or sandbox the `System()`/`TrySystem()` dialplan applications
4. Audit-log every `runCommand` invocation with the full command string and caller
