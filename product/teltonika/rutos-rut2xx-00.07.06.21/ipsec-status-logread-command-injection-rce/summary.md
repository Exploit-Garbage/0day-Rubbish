# Teltonika RutOS 00.07.06.21 (RUT2XX / RUT200 + RUT9XX) — Authenticated Command Injection in the `ipsec.lua` logread Sink: Root RCE With Reflected Output

## Summary

Teltonika Networks (Lithuania) RUT2XX/RUT200 industrial 4G/LTE routers run RutOS, an OpenWrt-derived firmware on MIPS32 big-endian / musl soft-float, whose web management plane is uhttpd fronting a VuCI Lua REST API under `/api` (177 modules), MIPS CGI under `/cgi-bin` and ubus-over-HTTP under `/ubus`. In RutOS 00.07.06.21, the `status` handler of the `ipsec` service module assembles a syslog-filter command by concatenating the caller-supplied `sid` URL path segment **twice** into a single-quoted shell argument — `vuci.util.exec("logread -e '<sid>-<sid>_c|'")` — without ever passing it through the `vuci.util.shellquote()` helper the same framework ships and uses correctly elsewhere. Since `vuci.util.exec()` is `io.popen(cmd):read("*a")` (i.e. `/bin/sh -c cmd`), a single quote in `sid` closes the quoted argument and the remainder is parsed as new shell commands. Sending `GET /api/ipsec/status/%27;id;echo%20%27` with a valid Bearer JWT therefore executes `id` as **root** — uhttpd carries no user-drop directive — and the captured stdout is stored into the response object as `.logs`, so `.data.logs` in the HTTP JSON response returns `uid=0(root) gid=0(root) groups=0(root)` straight to the attacker. This is non-blind root RCE: no exfiltration channel, timing oracle or second request is required. Reachability is amplified by a second ordering defect — `GET_TYPE_status` calls `instances_status()` *before* checking whether the referenced ipsec section exists, so the sink fires even when IPSec is not configured at all. A sibling sink with the identical root cause exists in a different file and function (`openvpn.lua:1660`, `string.format("logread -e %s", sid)`), where the argument is not quoted at all and a bare semicolon suffices. The `/api` JWT gate itself holds and no unauthenticated path to this sink exists: the unauthenticated allowlist was audited in full and is sink-free, so an unauthenticated RCE was **not** achieved and is not claimed. The vulnerability was verified dynamically under QEMU MIPS user-mode emulation against the real firmware binaries inside the extracted rootfs, calling the device's own `vuci.util.exec`, with a `uid=0(root)` marker written and output reflected; end-to-end HTTP exploitation on physical hardware is not claimed.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **CWE**: CWE-78 — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

## Affected Products

| Family | Firmware | Evidence |
|---|---|---|
| RUT2XX / RUT200 | RutOS 00.07.06.21 (`RUT2_R_00.07.06.21_WEBUI.bin`) | researched and dynamically verified |
| RUT9XX | RutOS 00.07.06.21 (`RUT9_R_00.07.06.21_WEBUI.bin`) | byte-identity: its `ipsec.lua` is byte-identical to the RUT2 copy (md5 `894c460ff3cece4ce0d5894199d8c07f`, confirmed in both directions) and 177/177 shared Lua modules are byte-identical |

- **Vendor**: Teltonika Networks, Lithuania
- **Product class**: industrial 4G/LTE router (CII / OT deployment), MIPS32 big-endian, musl soft-float, OpenWrt-derived
- **Merge rationale**: same vulnerable source at the same firmware version, so both families are reported as ONE advisory rather than counted per family
- **Prerequisites**: a valid JWT bearer token (post-authentication). Note: the firmware ships a default credential `admin01` (CWE-798), mitigated by a forced password change at first login, which lowers the bar for obtaining that token. Web management is LAN-facing by default (`_httpWanAccess=0`).
- **Other branches**: RutOS branches shipping the same VuCI `/api` stack with the same `services/ipsec.lua` are expected to be affected, but this was not individually confirmed and is not documented in the research record.
- **Prior CVE coverage**: none for this sink. CVE-2023-32350 is the `packages.lua` package-name injection (different file, different function, already shellquoted); CVE-2023-32349 is the `cgi-tcpdump` filter (different component).

## Impact

- **Execution identity**: root — `uid=0(root) gid=0(root) groups=0(root)` observed directly; no privilege boundary remains
- **Network transit control**: routing, NAT, firewall rules and DNS on the WAN edge can be rewritten at will — traffic for every host behind the router can be redirected, dropped or silently intercepted
- **VPN termination compromise**: the sinks live in the IPSec and OpenVPN modules, i.e. exactly the components that terminate site-to-site and remote-access tunnels. Root yields tunnel configuration, pre-shared keys and certificates, enabling peer impersonation, decryption of captured traffic, and pivoting into networks that explicitly trusted this router — an intrusion that is among the hardest for an IPSec peer to detect
- **Industrial / OT reach (RUT9XX)**: root on the router means root on the Modbus, digital I/O (`io_juggler`) and GPS field devices reachable through it; process data can be read and, where the router holds write access to PLCs or serial endpoints, actuated. (The vulnerability itself is in the shared VPN modules — the RUT9-unique industrial modules were reviewed exhaustively and contain zero `exec` sinks.)
- **Cellular persistence**: cellular APN and WAN configuration can be rewritten, implants placed in writable partitions or startup scripts, and exfiltration routed over the cellular link — often the only path out of an otherwise isolated OT network, and rarely monitored
- **Output reflected**: command stdout returns in the HTTP JSON `.data.logs` field, so data theft completes in a single authenticated GET that looks like an ordinary status poll

## Mitigation

1. Quote the argument — pass `sid` through the existing `vuci.util.shellquote(sid)` before concatenating it into the `logread` line in `instances_status()`
2. Apply the same fix to `openvpn.lua:1660`, whose argument is unquoted and thus injectable with a bare `;`
3. Remove the shell from the path — invoke `logread` with an argument array instead of composing a string for `io.popen`, making the bug class unreachable rather than patched
4. Validate `sid` at the dispatcher boundary to a legal UCI section name (`[a-zA-Z0-9_]+`), before `populate_endpoint` copies it into the endpoint object — the single choke point every `/api` service module traverses
5. Check section existence **before** calling `instances_status()`, so a non-existent section returns a clean `Section not found` instead of executing a command
6. Audit the remaining `exec` call sites across all 177 modules for the same pattern
7. Operator hardening pending patched firmware: keep `_httpWanAccess=0` / `_httpsWanAccess=0`, segment router management onto a dedicated tightly controlled VLAN, enforce the first-login password change, alert on `/api/ipsec/status/` or `/api/openvpn/...` requests whose `sid` segment contains `%27`, `%3B` or `%20` (never present in legitimate UCI section names), and audit VPN tunnel configuration for unauthorized changes

---
*Maintained by 0day Rubbish Research Team. Contact: disclosure@0day-rubbish.com*
