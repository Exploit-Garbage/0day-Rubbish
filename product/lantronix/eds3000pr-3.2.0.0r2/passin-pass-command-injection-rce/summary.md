# Lantronix EDS3000PR — Authenticated Command Injection in SSL `-passin pass:%s` → Root RCE

## Summary

Lantronix EDS3000PR industrial serial device server (firmware 3.2.0.0R2) contains an authenticated OS command injection in the SSL certificate import handler and the ping/traceroute diagnostics handler. The SSL handler (`fcn.00078070`) builds `openssl rsa|dsa|ec|pkcs12 -passin pass:%s ...` commands with the attacker-controlled certificate password (`certpasswd`/`keypasswd`) and executes them via `system()` (shell-parsed) as root — with **no shell-character sanitization**.

The diagnostics handler builds `ping ... %s ... | grep ...` and `traceroute ... %s | tail ...` commands with the attacker-controlled host field, also executed via `system()`. An authenticated admin submits `;id;#` or `$(id)` in the password/host field, and the injected command runs as root. Verified with 8/8 sink-level tests (5 SSL vectors + 3 ping/traceroute vectors, `;` and `$()` injections) all producing root markers; benign controls produced none.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Lantronix EDS3000PR (8-port industrial serial device server)
- **Versions**: firmware 3.2.0.0R2 verified; other NUEVO-2 firmware with the same EVO daemon is likely affected
- **Vendor**: Lantronix
- **Prerequisite**: authenticated session (session-based login with `/tmp/.web_login_%s` files)

## Impact

- **Confidentiality**: root access to the serial device server; SSL private keys, certificates, and connected industrial device data accessible
- **Integrity**: arbitrary command execution as root — device configuration, certificates, and forwarding state under attacker control
- **Availability**: full takeover of the industrial network gateway

## Mitigation

1. Sanitize the password and host fields before embedding them in `openssl`/`ping`/`traceroute` commands
2. Replace `system()` with parameter-array execution (no `/bin/sh -c` parsing)
3. Validate the certificate password as a strict password charset and the diagnostics host as a strict hostname/IP format
