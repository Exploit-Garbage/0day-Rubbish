# core-admin — Systemic Shell Command Injection via Ineffective Quote Escaping → Authenticated Root RCE

## Summary

core-admin 1.0.164 (build 16468, Core-Admin Professional by ASPL, Spain) is a closed-source Linux server-management panel whose main service runs as root (Python 2.7 Turbulence BEEP framework, TCP 602, Apache2 reverse proxy on 80/443). Its two sanitization helpers, `security.sanitize_input` and `_params.escape_param`, escape the single quote as `'` → `\'` — a transformation that is useless in a POSIX shell single-quoted context: a backslash is literal inside single quotes, so the `'` inside `\'` simply closes the enclosing quote. On the execution side, the shared `command.run` helper is `subprocess.Popen(command, shell=True)` with an empty command mapping — nothing is blocked. An audit of all 861 `command.run` call sites identified **32 sinks (E1–E32)** that concatenate user-controllable values into shell commands under this same pattern.

An authenticated administrator issues a BEEP op (e.g. `internet_access_manager.set_configure` with `proxy_localnets = x'|id > /tmp/marker|echo test #`); after sanitization the payload closes the sed template's single quote, pipes the injected command, and comments out the trailing syntax — the command executes as root. Seven of the 32 sinks were dynamically verified against the REAL product `.pyc` bytecode: 7/7 executed as uid=0. Fixing the escaping defect at the framework level is mandatory — patching sinks one by one cannot cover the class.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **Class**: authenticated (administrator) systemic command injection → root

## Affected Products

- **Product**: core-admin / Core-Admin Professional (Linux server management panel, Debian/CentOS)
- **Versions**: 1.0.164 (build 16468) verified; any release sharing the `sanitize_input`/`escape_param` + `command.run(shell=True)` pattern is likely affected
- **Vendor**: ASPL (Advanced Software Production Line, S.L., Spain)
- **Prerequisites**: valid administrator credentials (BEEP ADMIN profile); defined at install time, not hardcoded defaults

## Impact

- **Privilege**: arbitrary command execution as root on the managed server — `/etc/shadow`, SSH keys, persistence, lateral movement all in reach
- **Scope**: systemic — 32 sinks across multiple feature modules (internet access/proxy, log watcher, Prestashop manager, webhosting management, …); the attacker can pick the least-monitored module to trigger
- **Position**: core-admin is the management plane for the host (and typically webhosting estates) — compromising it compromises the servers it administers

## Mitigation

1. Break the `shell=True` pattern across all 32 sinks: argv-array execution (`subprocess.Popen([...], shell=False)`) in `command.run` and every E1–E32 call site
2. Fix the quote escaping: `'` → `\'` must become the POSIX-standard `'\''` sequence or `shlex.quote`, in both `security.sanitize_input` and `_params.escape_param`
3. Fix the data flow: sink modules must use the already-escaped `params_prepared` values instead of re-reading raw `params`
4. Validate at the sink: whitelist expected formats (e.g. CIDR lists for `proxy_localnets`) before command construction
