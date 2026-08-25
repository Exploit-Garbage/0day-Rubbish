# CacheGuard — Authenticated Config-Import Eval Injection → RCE

## Summary

CacheGuard Gateway-F10-R5 + Manager-G2 (CacheGuard-OS UF-2.5.2) is a closed-source UTM/reverse-proxy/WAF appliance with a Bash-based admin GUI. An authenticated administrator can upload a configuration file through the `conf-load-save` page; the `inject-conf` routine writes each line into a transaction file preserving `$(cmd)` **literally** (the `echo ${args[*]}` expansion does not trigger command substitution), and the `transaction commit` loop later executes each line with `eval "set -- ${line}"` — so `$(cmd)` is executed as code (CWE-94/CWE-78).

The command-name blacklist in `inject-conf` filters only the first token (`apply|conf|exit|...`), never the values: a line like `ip external 1.2.3.4$(/bin/sh -c "id > /tmp/marker")` passes. The admin restricted shell (`bash --restricted`) does not stop the `conf inject` command from reaching the eval sink.

Result: an authenticated admin escalates from a restricted shell to arbitrary command execution as the CacheGuard web user (uid 1001 inside the chroot). Verified end-to-end: marker file created via `$(/bin/sh -c "...")` through the real `inject-conf → transaction commit` chain. CVSS 8.8 (authenticated).

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: CacheGuard Gateway-F10-R5 (data plane) + Manager-G2 (control plane)
- **Version**: CacheGuard-OS UF-2.5.2
- **Vendor**: CacheGuard Technologies
- **Stack**: Apache httpd mod_cgi + ModSecurity, Bash CGI (`.apl`), admin chroot

## Impact

- **Confidentiality**: arbitrary file read/command output as the CacheGuard web user
- **Integrity**: arbitrary command execution in the appliance chroot
- **Availability**: full control of the UTM/WAF gateway configuration and runtime

## Mitigation

1. Filter shell metacharacters (`$`, `` ` ``, `(`, `)`, `;`, `|`, `&`, `>`, `<`, `\`, `"`) in `inject-conf` config values, or use `printf %s` instead of `echo ${args[*]}`
2. Replace `eval "set -- ${line}"` in `transaction commit` with `read -r -a` + direct array assignment
3. Validate config values with strict regex (e.g., `check-ip` accepts only `\d+\.\d+\.\d+\.\d+`) before writing the transaction file
