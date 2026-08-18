# Wavestore VMS venusd /simple/export Command Injection to Root RCE

## Summary

An authenticated command injection vulnerability in Wavestore VMS 6.48.809 allows an attacker with valid credentials (including the shipped default `install:a`) to execute arbitrary commands as `root`. The `venusd` daemon's `/simple/export` endpoint (HTTPS 443/8443) passes the URL query parameter `user=` through `simpleExportArgs` directly into `strsystemf`, which builds a command string and executes it via `popen(sh -c ...)` without sanitizing shell metacharacters. The daemon retains real UID 0 and full capabilities after dropping to the `dvr` user, so command substitution executes with root-equivalent privileges.

## CVSS Score

- **Score**: 8.8 High (authenticated; root command execution)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Wavestore VMS (video management system)
- **Versions**: 6.48.809 (other versions with the same venusd /simple/export handling are likely affected)
- **Vendor**: Wavestore Ltd

## Impact

- **Confidentiality**: Full system compromise as root (real UID 0 + full capabilities)
- **Integrity**: Arbitrary command execution on the VMS appliance
- **Availability**: Full control of video surveillance infrastructure

## Mitigation

1. Sanitize shell metacharacters in the `user=` parameter (apply the same sanitize() used elsewhere in venusd)
2. Run venusd without retaining real UID 0 and full capabilities after privilege drop
3. Change the shipped default credentials (admin:admin, install:a)
4. Restrict the management ports to trusted networks and use TLS
