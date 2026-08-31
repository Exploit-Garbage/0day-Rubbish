# Minuteman UPS NMC — Unauthenticated Command Injection in system_param.csp → Root RCE

## Summary

Minuteman UPS Network Management Cards (2G_RPM series PDU, firmware 1.60.3) contain an unauthenticated OS command injection in the `system_param.csp` WAN configuration handler. The handler builds shell commands with attacker-controlled `Wan_IPAddr`, `Wan_Gateway`, and DHCP hostname values via `sprintf` and executes them with `system()` (which runs `/bin/sh -c`) as **root**, with zero input filtering (no blacklist, no whitelist, no escaping).

Authentication on the device is per-handler opt-in via session cookies; the `system_param.csp` handler never calls the session-validation function — there is no global auth gate, no HTTP basic-auth layer, and no redirect-to-login. An unauthenticated attacker can POST a single crafted request (e.g. `Wan_IPAddr=1.1.1.1;touch /tmp/marker;#`) and execute arbitrary commands as root on the UPS power-management card. Three injection points exist: the static-IP `ifconfig` command, the `route add default gw` command, and the DHCP `udhcpc -H` hostname command.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Minuteman UPS NMC (2G_RPM series PDU management cards)
- **Versions**: firmware 1.60.3 (`2G_RPM_1.60.3.bin`) verified; other firmware with the same WAN handler is likely affected
- **Vendor**: Minuteman (Para Systems)
- **Prerequisite**: default configuration; no credentials required

## Impact

- **Confidentiality**: root access to the power-management card — telemetry, configuration, and credentials readable
- **Integrity**: arbitrary command execution as root; power infrastructure settings under attacker control
- **Availability**: an unauthenticated attacker can disrupt UPS/PDU management, affecting power availability for critical equipment

## Mitigation

1. Add a session-authentication check at the entry of the `system_param.csp` handler
2. Validate `Wan_IPAddr`/`Wan_NetMask`/`Wan_Gateway` strictly as IP formats before use in commands
3. Replace `system()` + `sprintf` with parameter-array `execve()` calls (no shell parsing)
