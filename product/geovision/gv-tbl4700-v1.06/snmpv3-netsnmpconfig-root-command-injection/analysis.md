# GeoVision GV-TBL4700 V1.06 — SNMPv3 User Config → net-snmp-config Command Injection → Root RCE

## 1. Overview

GeoVision GV-TBL4700 (V1.06) is a closed-source IP camera / access-control device (Taiwan vendor) whose main daemon `mwareserver` (ARM EABI5, uClibc, stripped, 3.27 MB, running as root) handles the LAPI HTTP interface. The SNMPv3 user configuration path contains two identical command-injection sinks: the `szAuthKey` and `szPrivKey` fields flow un-sanitized into `IMOS_system("net-snmp-config --create-snmpv3-user -ro -a %s -A MD5 -x %s -X DES admin")`, which resolves to libc `system()` → `/bin/sh -c` as root.

The critical difference from sibling GeoVision models (TBL4711, EBD4700, ABL4712, AVD2700) is that the TBL4700's `libbp.so` (SHA256 `aa6f6676...`) **contains no `BP_TransMetaCharacter` sanitizer at all** — the sibling libraries contain the sanitizer (missing only `\n`/tab), while TBL4700 lets classic `;` metacharacters pass through directly. An authenticated admin submits `szAuthKey = MD5;<cmd>;#`; the shell splits on `;`, executes `<cmd>` as root, and `#` comments out the remainder. Verified with a root-owned marker via sink reproduction with the device's real ARM busybox `/bin/sh`.

## 2. Vulnerability Summary

- **Type**: Authenticated OS command injection → root RCE (CWE-78)
- **Root cause 1 (CWE-78)**: `snprintf(buf, len, "net-snmp-config --create-snmpv3-user -ro -a %s -A MD5 -x %s -X DES admin", szAuthKey, szPrivKey)` followed by `IMOS_system` (libc `system`) — `/bin/sh -c` re-interprets the attacker-controlled fields
- **Root cause 2 (CWE-20)**: no sanitizer — `libbp.so` has zero `BP_TransMetaCharacter` symbols, so `;`, `$`, backticks, etc. flow into the command unchanged
- **Root cause 3 (CWE-250)**: `mwareserver` runs as root — injected commands execute with uid 0
- **Result**: authenticated admin → root RCE. CVSS 8.8 (9.8 with unchanged default credentials).

## 3. Authentication Boundary

The device's LAPI HTTP interface (liblightapi.so) enforces Digest authentication for the admin role. The SNMP configuration dispatch (`MW_CTRL_MsgProc`) reaches the sinks only through an authenticated admin session — Target B (authenticated RCE). If the default credentials are not changed, the effective privilege requirement drops to none (PR:N → CVSS 9.8).

The session model is the standard GeoVision LAPI flow: the client authenticates with the admin account (Digest), receives a session token, and uses it for subsequent control-plane requests. The SNMPv3 user-creation request is a normal authenticated configuration operation — there is no separate authorization check on which configuration endpoints an admin may call, and no privilege boundary between "manage SNMP users" and "execute commands". The only thing separating an authenticated admin from root is the (missing) input sanitization.

## 4. Attack Surface

- **Entry**: LAPI HTTP SNMPv3 user configuration API (Digest auth, admin)
- **Controllable parameters**: `szAuthKey` and `szPrivKey` (both attacker-controlled POST fields)
- **Sinks**: two identical instances — `fcn.0002e954` @ 0x2e954 and `MW_CTRL_SetSNMPV3Cfg` `fcn.0006980c` @ 0x6980c
- **Privilege**: root — `mwareserver` runs as root
- **No sanitization**: `libbp.so` contains no metacharacter filter

Both sinks are reachable from the same SNMPv3 user-management flow: `fcn.0002e954` handles the direct user-creation request path, while `MW_CTRL_SetSNMPV3Cfg` is the configuration-set handler that stores and applies the same fields. Because the two share one format string and one `IMOS_system` thunk, a single patch that sanitizes the shared input fields closes both instances; leaving either one unfixed keeps the vulnerability exploitable. The web entry is the admin SNMP settings page, so no debugging interface or hidden endpoint is required.

## 5. Sink Identification

Sink #1 (`fcn.0002e954` @ 0x2e954):

```asm
0x2e978  blx snprintf     ; snprintf(buf, len, "net-snmp-config --create-snmpv3-user -ro -a %s -A MD5 -x %s -X DES admin", szAuthKey, szPrivKey)
0x2e97c  blx fcn.00024844 ; IMOS_system thunk → libc system → /bin/sh -c, root
```

- `szAuthKey` = struct+0x3c, `szPrivKey` = struct+0x94 (attacker-controlled HTTP POST fields)
- `fcn.00024844` = the `IMOS_system` thunk (GOT @ 0x316684, 234 cross-references)

Sink #2 (`MW_CTRL_SetSNMPV3Cfg` @ 0x6980c):

```asm
0x69916  blx snprintf     ; same format string
0x6991e  blx fcn.00024844 ; IMOS_system thunk → libc system, root
```

Both sinks use the same format string and the same `IMOS_system` thunk — one root cause (un-sanitized `szAuthKey`/`szPrivKey`), two instances, one 0-day.

Proof of no sanitizer:

```
$ strings libbp.so | grep -i transmeta
(empty — NO BP_TransMetaCharacter)
```

Sibling EBD4700 `libbp.so` contains `BP_TransMetaCharacter` (7-check escaping of `&'()*,;<,>?[\]^{|}~"#$ ` + backtick, missing only 0x0a/0x09/0x0d); TBL4700's `libbp.so` has none — bytes flow to the sink verbatim.

## 6. Source Identification & Controllability

The source is the SNMPv3 user configuration request: `szAuthKey` and `szPrivKey` are fully attacker-controlled POST fields. They reach `snprintf`'s `%s` slots with no filtering, no escaping, and no charset validation. The attacker controls the exact command bytes executed by `/bin/sh -c`.

There is no length-based restriction that would stop a typical payload either: the fields are standard configuration strings carried in the request body, and the injected command appears after the `-a MD5;` prefix, well within the buffer. The only requirement is that the payload avoid breaking the surrounding command syntax before the `;` — achieved trivially by starting the value with a benign token such as `MD5` and then injecting `;<cmd>;#`. The `#` comment ensures the remainder of the `net-snmp-config` argument list is ignored, so the command executes cleanly even though `net-snmp-config` itself receives truncated arguments.

## 7. Data Flow

```
LAPI HTTP (liblightapi.so, Digest auth admin)
  → MW_CTRL_MsgProc (SNMP configuration dispatch)
  → MW_CTRL_SetSNMPV3Cfg (fcn.0006980c)  [sink #2]
  → or fcn.0002e954                      [sink #1]
  → snprintf("net-snmp-config ... -a <szAuthKey> -x <szPrivKey> ...")
  → IMOS_system → libc system → /bin/sh -c (root)
```

## 8. Exploit Construction

```
szAuthKey = MD5;<cmd>;#
```

Expanded sink string:

```sh
net-snmp-config --create-snmpv3-user -ro -a MD5;<cmd>;# -A MD5 -x MD5 -X DES admin
```

The shell splits on `;`, executes `<cmd>` as root, and `#` comments out the remainder. Example: `MD5;id>/tmp/marker;#`.

## 9. Dynamic Verification

Sink reproduction with the device's real ARM busybox `/bin/sh` under qemu-arm-static (`QEMU_LD_PREFIX` pointing at the device rootfs):

```
qemu-arm-static $R/bin/sh -c 'net-snmp-config --create-snmpv3-user -ro -a MD5;id>/tmp/marker_tbl4700_snmp;# -A MD5 -x MD5 -X DES admin'
```

Result:
- marker `/tmp/marker_tbl4700_snmp` exists, content `uid=0(root) gid=0(root) groups=0(root)`, exit 0

Benign control: `szAuthKey = MD5valid` (no metacharacters) → no marker (no false positive).

The reproduction deliberately ran the exact format string from the firmware — `net-snmp-config --create-snmpv3-user -ro -a MD5;id>/tmp/marker_tbl4700_snmp;# -A MD5 -x MD5 -X DES admin` — so the shell behavior matches what the device's `system()` call would produce. The `#` terminates the remainder of the command line after the injected `id`, mirroring the in-firmware string exactly. Because the SNMPv3 configuration API submits both `szAuthKey` and `szPrivKey` through the same handler, either field can carry the payload; the PoC uses `szAuthKey` as the primary vector and notes that `szPrivKey` is an equivalent injection point in both sink instances.

## 10. Reachability & Impact

- **Reachability**: requires an authenticated admin session on the LAPI HTTP interface (Target B); with unchanged default credentials the effective requirement is none. The sink runs on SNMPv3 user creation with no additional preconditions.
- **Impact**: root command execution on the IP camera / access-control device — video, credentials, configuration, and device state under attacker control; a foothold inside the surveillance/access-control network.
- **Scope**: GV-TBL4700 firmware V1.06; sibling models share the same sink pattern with a weaker sanitizer.

## 11. Fix Recommendations

1. Sanitize `szAuthKey`/`szPrivKey` with a complete metacharacter filter (the sibling `BP_TransMetaCharacter` pattern, fixed to also cover newline/tab) before building the command
2. Replace `system()` with parameter-array execution for `net-snmp-config` (no `/bin/sh -c` parsing)
3. Enforce a strict password charset for SNMPv3 user creation
4. Run `mwareserver` with least privilege where the architecture allows

## 12. CWE & CVSS

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command — `system()` with un-sanitized SNMPv3 fields
- **CWE-20**: Improper Input Validation — missing metacharacter sanitizer
- **CWE-250**: Execution with Unnecessary Privileges — daemon runs as root
- **CVSS**: 8.8 High — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (9.8 with unchanged default credentials)
