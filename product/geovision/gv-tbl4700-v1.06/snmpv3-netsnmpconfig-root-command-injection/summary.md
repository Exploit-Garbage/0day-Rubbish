# GeoVision GV-TBL4700 — SNMPv3 User Config → net-snmp-config Command Injection → Root RCE

## Summary

GeoVision GV-TBL4700 (firmware V1.06) is an IP camera / access-control device whose `mwareserver` daemon (ARM, running as root) contains two identical command-injection sinks in the SNMPv3 user configuration path. The `szAuthKey` and `szPrivKey` fields are passed with **no sanitization** into `IMOS_system("net-snmp-config --create-snmpv3-user -ro -a %s -A MD5 -x %s -X DES admin")`, which runs `/bin/sh -c` as root.

Unlike sibling GeoVision models whose `libbp.so` contains a `BP_TransMetaCharacter` sanitizer (that only misses newline/tab), the TBL4700's `libbp.so` **contains no sanitizer at all** — classic shell metacharacters such as `;` work directly. An authenticated admin submits `szAuthKey = MD5;<cmd>;#` through the SNMPv3 configuration API; the shell splits on `;`, executes `<cmd>` as root, and `#` comments out the remainder. Verified with a root-owned marker via sink reproduction with the device's real ARM busybox `/bin/sh`.

## CVSS Score

- **Score**: 8.8 High (9.8 if the default credentials are unchanged)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: GeoVision GV-TBL4700 (IP camera / access control)
- **Versions**: firmware V1.06 verified
- **Vendor**: GeoVision
- **Prerequisite**: authenticated admin session (LAPI HTTP Digest auth)

## Impact

- **Confidentiality**: root access to the camera/access-control device — video, credentials, and configuration readable
- **Integrity**: arbitrary command execution as root on the device
- **Availability**: full takeover of the surveillance/access-control device

## Mitigation

1. Sanitize `szAuthKey`/`szPrivKey` with a metacharacter filter before embedding in the `net-snmp-config` command
2. Replace `system()` with parameter-array execution for `net-snmp-config`
3. Enforce a strict password charset for SNMPv3 user creation
