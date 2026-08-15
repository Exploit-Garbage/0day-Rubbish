# HiveMQ Platform Data Hub Zip-Slip to Root RCE

## Summary

A critical remote code execution vulnerability in HiveMQ Platform allows an attacker using the shipped default credentials `admin:hivemq` to upload a malicious Data Hub custom module ZIP. The module extraction routine resolves ZIP entry names with `path.resolve()` without any traversal validation, enabling a classic Zip-Slip (CWE-22) write to arbitrary filesystem locations. Combined with the ability to write into `/etc/cron.d`, an attacker can plant a cron job that executes arbitrary commands as `root`.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: HiveMQ Platform (Control Center)
- **Versions**: 4.54.0 (earlier versions using the same Data Hub custom module upload path are likely affected)
- **Vendor**: HiveMQ

## Impact

- **Confidentiality**: Full system compromise; `root` access to the host
- **Integrity**: Arbitrary file write on the host filesystem via Zip-Slip, including cron, systemd units, or SSH keys
- **Availability**: Full control of the HiveMQ Platform host and all hosted services

## Mitigation

1. Change the Control Center default credentials immediately after installation; enforce a strong password policy for the `admin` account
2. Validate every ZIP entry name against the extraction base directory using canonical path containment checks before writing
3. Run HiveMQ Platform and Control Center as an unprivileged service account instead of `root`
4. Restrict Control Center access to trusted networks and never expose it to the public Internet

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
