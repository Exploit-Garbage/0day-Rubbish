# Biamp Vocia MS-1 Unauthenticated Root RCE via Hardcoded FTPS Credentials

## Summary

A critical unauthenticated remote code execution vulnerability in the Biamp Vocia MS-1 IP paging/intercom device allows remote attackers to achieve root code execution using the hardcoded FTPS service credentials `ftpsuser:ftpsuser` (CWE-798), baked into the firmware and shared across all deployments worldwide. The `ftpsuser` account is exempt from chroot, allowing writes to `/var/opt/vocia/Bins/`. The `mum` supervisor process, running as `root`, scans this directory every ~10 seconds and executes any file it finds without sanitization or signature verification, resulting in default-configuration unauthenticated root RCE.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Biamp Vocia MS-1 (IP PA / paging / intercom CII device)
- **Versions**: MS-1 firmware 1.2.27
- **Vendor**: Biamp Systems

## Impact

- **Confidentiality**: Full device compromise; arbitrary command execution as `root`
- **Integrity**: Full control of the device filesystem and audio infrastructure
- **Availability**: Disruption of public-address and intercom services in transportation hubs, government, schools, and hospitals

## Mitigation

1. Replace the hardcoded FTPS credentials with per-device randomized credentials at provisioning time
2. Enforce signature verification for files executed by the `mum` supervisor
3. Run the `mum` supervisor under a least-privilege account
4. Restrict management network access to these devices

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
