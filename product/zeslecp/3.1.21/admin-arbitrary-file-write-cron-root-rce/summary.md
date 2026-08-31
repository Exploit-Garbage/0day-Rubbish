# ZesleCP — Authenticated Arbitrary File Write → Cron → Root RCE

## Summary

ZesleCP 3.1.21 (self-hosted hosting control panel) contains an authenticated root RCE via unrestricted file write. The `zesle-agent` (Go, running as **root**) exposes `POST /file-manager/save-file`, which writes attacker-controlled content to an attacker-chosen absolute path. For admin sessions the handler applies **no path restriction** (regular users are jailed to `/home/<user>`, but admins are not) — a validation gap (CWE-73), not intended admin functionality.

An admin with a `zeslecp_session` cookie writes a cron file to `/etc/cron.d/zesle-rce` with content `* * * * * root sh -c '<cmd>'`; crond executes it as root within 60 seconds. The admin account has `shell=/bin/false` (no direct OS shell), so the file manager is the admin's only path to OS-level execution — and the path restriction gap makes it unrestricted. Verified end-to-end with a unique marker file showing `uid=0(root)` and the container hostname.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: ZesleCP (hosting control panel)
- **Versions**: 3.1.21 verified
- **Vendor**: ZesleCP
- **Prerequisite**: authenticated admin session

## Impact

- **Confidentiality**: root file read/write on the hosting control panel host — all hosted accounts, databases, and credentials accessible
- **Integrity**: arbitrary file write as root → cron-based code execution, config tampering, backdoors
- **Availability**: full compromise of the hosting server

## Mitigation

1. Restrict `save-file` to a path allowlist (webroot/home/temp) for admins too
2. Forbid writes to `/etc`, `/root`, `/var/spool/cron`, `/etc/cron.d`, and other system-sensitive paths
3. Apply the same path jail to admins as to regular users
4. Run the agent as a dedicated low-privilege user, not root
