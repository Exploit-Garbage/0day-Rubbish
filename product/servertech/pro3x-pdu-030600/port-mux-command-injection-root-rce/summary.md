# Server Technology PRO3X Rack PDU - port_mux Listener Program Override to Root Command Execution

## Summary

PRO3X rack PDUs from Server Technology (Legrand group) run `port_mux`, an inetd-style launcher that starts every protocol listener with `fork` + `execv` and never drops privileges, so listeners run as root. The executable path is `proto_listener_entry.program` in `cfg_pmux.cdl`, typed `nctl_nspc_nempty_str_512` - a free-form string with no whitelist - and an authenticated **administrator** rewrites it through `setConfiguration` (`POST /J/cfg`). Pointing the port 80 `http` listener at `/bin/sh` with arguments `-c "<cmd>"` applies at runtime; the next TCP connection to port 80 executes the attacker's command as uid 0, confirmed by a root-owned marker file containing `uid=0(root)`. Administrator rights are required and the gate was verified unbypassed, but a shipped default administrator credential exists, leaving unrotated units open with no privileged secret.

## CVSS Score

- **Score**: 7.2 High (authenticated administrator required); **9.8 Critical** where the factory default credential is unchanged
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (metric-by-metric derivation in analysis section 12)
- **CWE**: CWE-78, CWE-269; CWE-798 reported separately
- **Class**: post-authentication, administrator to root

## Affected Products

- Server Technology Inc. (Legrand group), PRO3X series intelligent rack PDU
- Firmware `spdu-pro3x-030600`, build 46640 - ARM 32-bit uClibc Linux
- Only this build was tested; no other build or model is claimed
- Verification method: analysis of the firmware image plus emulated execution of the device's own daemons. No physical PRO3X hardware was used, and the three-step HTTP chain (`POST /J/auth`, `POST /J/cfg`, TCP trigger) was verified component by component rather than end to end on a device

## Impact

- Root (uid 0) on the rack power distribution controller, a critical-infrastructure power monitoring and control appliance
- Full configuration control; the disabled `modbus` (502) and `mbusd` (503) listeners can be armed with attacker-chosen programs
- Outlet switching and power cycling were not separately exercised by this PoC

## Mitigation

1. `setgid`/`setuid` to a per-protocol service account before `execv`; never start a listener as uid 0
2. Constrain `program` to a closed enumeration of known listener binaries; reject shell metacharacters in `setConfiguration`
3. Block configuration writes while the factory credential is set; ship per-device unique administrator passwords

## References

- https://0day-rubbish.com/blog/servertech-pro3x-port-mux-command-injection
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com
