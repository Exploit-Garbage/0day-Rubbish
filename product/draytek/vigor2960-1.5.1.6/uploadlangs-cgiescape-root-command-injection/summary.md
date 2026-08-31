# DrayTek Vigor 2960 — uploadlangs Command Injection → Root RCE

## Summary

DrayTek Vigor 2960 (firmware v1.5.1.6), an SMB enterprise router/firewall/VoIP gateway running lighttpd 1.4.35 with the `mainfunction.cgi` management CGI as root, contains an authenticated OS command injection in the `uploadlangs` handler (`fcn.0001157c`). The handler takes the multipart upload **filename** (fully attacker-controlled), runs it through `cgiEscape` — an **HTML** escaper that only encodes `<`, `>`, `&` and leaves every shell metacharacter untouched — then embeds it unquoted into `system("mv %s /www/langs/%s")`.

A sibling upload handler (`/trustcaupload`) applies a real shell-metacharacter sanitizer (`fcn.0000ad8c`), but `uploadlangs` does not — a developer omission. An authenticated admin (privilege > 3) uploads a file whose filename is `;id|tee /tmp/marker;#`; the shell splits on `;`, executes `id|tee` as root, and `#` comments out the rest. Verified on the real ARM binary under qemu with a root-owned marker.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: DrayTek Vigor 2960 (SMB enterprise router/firewall/VoIP gateway)
- **Versions**: firmware v1.5.1.6 verified (EoL product)
- **Vendor**: DrayTek
- **Prerequisite**: authenticated admin session (privilege > 3); no default credentials (forced password change)

## Impact

- **Confidentiality**: root access to the router/firewall — VPN keys, credentials, routing state, and proxied traffic accessible
- **Integrity**: arbitrary command execution as root on the gateway
- **Availability**: full takeover of the edge gateway — firewall, routing, and VoIP services under attacker control

## Mitigation

1. Apply the `fcn.0000ad8c` shell-metacharacter sanitizer to the `uploadlangs` filename (as already done for `/trustcaupload`)
2. Quote the filename in the `mv` command and use parameter-array execution
3. Use a shell-safe escaper (not the HTML `cgiEscape`) for any value entering `system()`
