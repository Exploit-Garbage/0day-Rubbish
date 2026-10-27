# NETGEAR RAX120 (Nighthawk AX12) V1.2.5.18 - SOAP InstallApp apName Dollar-Parentheses Command Injection Executing as the Root-Configured Web Stack (CWE-78, CWE-20)

Advisory: https://0day-rubbish.com/blog/soap-installapp-apname-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

NETGEAR is a United States consumer-networking vendor whose Nighthawk line belongs to the most widely
deployed classes of home and small-office routers. The RAX120 (Nighthawk AX12) is a WiFi 6 router built
on the Qualcomm IPQ8074 platform; its administrative web plane is a lighttpd server fronting the vendor's
DNI-framework CGI handler `/usr/sbin/net-cgi`, and its SOAP control plane dispatches every action through
`/soap/server_XMLresp.cgi`. Among those actions is the app-installation control
`urn:NETGEAR-ROUTER:service:AppSystem:1` with its `InstallApp` operation, which requires the router
administrator's session. The operation takes a `NewAppName` argument and passes it through a blocklist
validator whose "apname" mode rejects `@`, the backtick, the semicolon, both quote characters and the
backslash - a set that blocks the classic injection breakouts - but passes `$`, `(` and `)` untouched.
The handler then embeds the validated name, unquoted, into three shell command lines (two `rm -rf`
constructions and an `rm -rf / mkdir / tar -zxf` pipeline) and hands each one to `system()` or `popen()`,
both of which execute through `/bin/sh -c`. A second parse therefore happens inside the shell, and a name
of the shape `x$(cmd)` substitutes attacker-chosen command text before the `rm` words ever run. The
research record identifies, from the firmware image's own lighttpd configuration, the web server's
configured runtime user as root, so command text supplied this way inherits device-root authority on the
appliance. Verification was a sink-level replication on an isolated cloud-hosted sandbox: a native-compiled
C program reproducing the disassembled validator, the CRLF-normalizing string processor and all three
command lines produced markers containing `uid=0(root) gid=0(root) groups=0(root)` for each of the three
injected vectors, while a benign control name produced none. The same payload, the same handler family and
a strictly more permissive validator were confirmed in the sibling R7800 platform with an identical
sink-level replication; the two platforms differ in binary, instruction set and validator function but share
the root cause. This finding is not a default-credential finding: it consumes a legitimate administrator
session and is unaffected by any administrator password change. There is no memory corruption and no
transport-layer defect in this chain; the entire defect is a metacharacter-class gap between a blocklist
validator and a shell parser.

- Component: the SOAP app-installation action `InstallApp` of service `urn:NETGEAR-ROUTER:service:AppSystem:1`,
  dispatched through `/soap/server_XMLresp.cgi` (HTTP POST, XML body, administrator session required), handled
  by `/usr/sbin/net-cgi` in the DNI lighttpd web stack of firmware V1.2.5.18 on the Qualcomm IPQ8074 platform
  (aarch64, musl libc, stripped image; recorded handler binary size 1,042,120 bytes, recorded digest beginning
  d7035dd3)
- Sink: three command constructions inside the InstallApp handler - `system("rm -rf /sw-apps/<name>/version.txt > /dev/console")`,
  `system("rm -rf /sw-apps/<name> > /dev/console")` and `popen("rm -rf /tmp/<name>_tmp; mkdir /tmp/<name>_tmp; tar -zxf ...")` - each executed
  via `/bin/sh -c`, which re-parses the interpolated name and interprets `$( )` as command substitution
- Source: the `NewAppName` SOAP element, extracted ahead of a length gate (maximum 255 characters) and a
  value gate on the companion `NewUpdate` element, then screened only by the "apname" blocklist
- Sanitization: the blocklist validator rejects `@`, backtick, `;`, `"`, `'` and `\`, and its downstream
  string processor performs only CRLF-to-space normalization; `$`, `(`, `)` and a dozen other shell-relevant
  characters reach the shell unfiltered, so the only protections this path has are exactly the ones the
  `$( )` breakout does not need

## CVSS Score

- Score: 6.8 Medium
  (`CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - a client holding the router administrator's
  credential on the same network as the device converts an intended app-management action into arbitrary
  command execution as the web stack identity, which the firmware image's lighttpd configuration sets to root
- Attack Vector: Adjacent - the SOAP control plane belongs to the router's local administrative service; no
  shipped artifact examined during this research establishes that the app-installation action answers on the
  wide-area side of an unmodified deployment, so the published vector assumes an adjacent (LAN-side) network
  position and the network-exposed variant appears below only as a labelled conditional reading
- Attack Complexity: Low - a single well-formed authenticated POST is the whole detonation; there is no race,
  no timing window, no memory-corruption groom and no multi-step state machine
- Privileges Required: High - the operation is gated behind the administrator's session, which the research
  record identifies as the SOAP login bound to the requesting station's MAC address and failing closed; the
  router's web plane has no lower-privilege account tier that reaches this action
- User Interaction: None - no victim action is involved; the credential holder drives the request directly, so
  the MAC-bound session binding is not an obstacle but part of the legitimate control flow being exercised
- Scope: Unchanged - the substituted command runs within the router itself, inside the authority of the
  component whose interface was abused; no crossing into a beyond-device security authority is claimed
- Impact C/I/A: all High - arbitrary command execution as the root-configured web stack yields the device's
  complete configuration store (including any credentials stored by the firmware), full control of the
  control and data plane semantics of the router, and total control of service availability
- CWE: CWE-78 primary (OS command injection through a shell-interpreted argument); CWE-20 co-equal
  (blocklist-style improper input validation); CWE-426 contributing and reported without raising any metric
- Recorded score: the internal research ledger behind this advisory recorded 8.8 for this chain; recomputation
  rejects it. 8.8 is the arithmetic of a Low-privilege reading of this exact impact profile, and the chain
  documented here requires the device administrator, so the recorded figure cannot be produced from any
  vector with the authentication boundary this evidence supports
- Conditional reading A - device's management plane deliberately exposed beyond the adjacent network
  (remote administration enabled, a port forward directing traffic at the SOAP responder, or a management
  host relaying it): `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 High. ISS 0.914816, Impact 5.873119,
  Exploitability 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708, sum 7.107827 rounded up to 7.2. Labelled
  conditional on a deployment choice this research did not measure; not the headline
- Rejected reading B - a hypothetical lower-privilege web tier reaching the action: the network variant of
  that reading is `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High. Rejected because the
  app-installation control plane is administrator-only on this firmware: no secondary account class with web
  access to this service is documented in the artifacts, so no principal other than the device administrator
  exists to justify Low privileges
- Rejected reading C - the same hypothetical lower tier without network exposure:
  `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.0 High, whose Exploitability term assumes an adjacent
  attacker with basic privileges that this product does not offer. Rejected on the same principal-account
  grounds as reading B
- Published arithmetic (headline): ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.62 x 0.77 x 0.27 x 0.85 = 0.900610; sum 6.773729, rounded up to 6.8

## Affected Products

- NETGEAR RAX120 (Nighthawk AX12) WiFi 6 router, firmware V1.2.5.18 (the version analyzed end to end at
  binary level in this research), Qualcomm IPQ8074, aarch64, musl libc; affected component: the
  app-installation action of the SOAP app-system service in `/usr/sbin/net-cgi` (1,042,120-byte stripped
  handler, recorded image digest beginning d7035dd3), reached through `/soap/server_XMLresp.cgi` behind the
  administrator session
- NETGEAR R7800 (Nighthawk X4S) router, firmware V1.0.2.68, Broadcom BCM4709 platform, 32-bit ARM, same DNI
  lighttpd plus net-cgi service stack (recorded handler digest beginning c5a9f2b3): tier-2 same-root-cause
  merge. Its own app-name validator (a different function in a different binary on a different instruction
  set) rejects only `"`, `'` and `\`, which is a strictly smaller reject set than the RAX120 one, and the
  identical `x$(cmd)` payload passed it and executed through the same handler family in its own sink-level
  replication (three root markers, clean control). The merge is at root-cause level, not build identity, and
  the platform differences are stated rather than smoothed over
- Not claimed: other models shipping the DNI net-cgi app-system code were not audited, RAX120 hardware
  generations other than the analyzed image are not claimed by inference, and NETGEAR's older R6700/R7000/R8000
  generation runs a different self-built httpd lineage that does not contain this handler
- Verification method and its boundary: firmware-level disassembly established the handler, the validator, the
  string processor and the three command constructions; dynamic evidence comes from a sink-level replication -
  a native-compiled C program on an isolated cloud-hosted sandbox re-implementing the disassembled validator
  logic, the CRLF normalization and the three command lines - in which each injected vector created a marker
  containing `uid=0(root) gid=0(root) groups=0(root)` and a benign control name created none. No physical
  router was driven during verification: no live SOAP request was fired at device hardware, so the request
  path, the session gate and the parameter extraction are established at disassembly level while the
  injection behavior at the sink is established by the replication. The device-side landing identity is read
  from the firmware image's lighttpd configuration (runtime user root), which the replication harness mirrored
  by design
- Privilege ceiling: arbitrary command execution as the web stack identity, which the firmware image's
  lighttpd configuration sets to root; the markers above are the measured proof of that identity inside the
  replication. Not reached and not claimed: escape from the router to attached hosts, persistence across
  factory reset or reflash, radio-firmware specifics, and any memory-corruption primitive

## Impact

- Complete compromise of the router's operating system by a credential holder who was never meant to hold a
  shell: the app-management interface becomes an arbitrary-command channel running as the root-configured web
  stack, giving the attacker everything the device itself can do - interface reconfiguration, routing and DNS
  semantics, firewall state and the complete configuration store
- Exposure of every secret the device holds for its own operation, within the device's readable filesystem
  scope at root authority, including configuration data and any material the app subsystem stages under its
  working directories
- Full control of the data plane at the router's discretion: an attacker with root on the device can redirect
  or observe LAN traffic according to the platform's own capabilities, turning a network infrastructure
  device into an interior attack position
- Persistence consistent with root command execution on an embedded Linux system (startup scripts, user
  accounts, scheduled tasks) up to the limits of the device's writable filesystem; what survives a factory
  reset or reflash was not tested and is not claimed
- Availability impact at will, both coarse (reboot, service control from the shell) and surgical (filesystem
  corruption from the `rm -rf` constructions themselves)
- Multi-platform footprint: the same payload shape and the same handler family were confirmed on the R7800
  platform, so remediation scoped to a single model line would leave the sibling vulnerable
- The chain is silent in product terms: one authenticated POST inside a legitimate management action, no
  log-relevant traffic pattern beyond ordinary app-management use

## Mitigation / Fix Recommendations

1. Replace the blocklist with an allowlist for the application name: restrict `NewAppName` to
   `[A-Za-z0-9][A-Za-z0-9._-]*` with the existing length cap, and reject everything else before any
   filesystem or command use. Both known blocklist sets (the RAX120 six-character set and the more permissive
   R7800 three-character set) are provably insufficient
2. Stop interpolating the application name into shell command lines at all: implement the cleanup,
   directory-creation and extraction steps with `unlink()`, `mkdir()`, `rmdir()` and `execve()`-family calls
   with argument arrays, none of which involve a shell parser. This removes the entire class on this surface
   rather than chasing metacharacter sets
3. If a shell stays in the path short-term, pass the controlled values only through single-quoted expansions
   with literal single-quote escaping, and add a direct assertion in the handler that the compiled command
   contains no `$` after construction
4. Drop web-stack privileges: the image's lighttpd currently runs as its root user per its configuration
   file; a dedicated unprivileged CGI identity would not fix the injection but caps the blast radius of this
   and every other web-plane defect
5. Audit every remaining `popen()` and dynamically constructed `system()` call in the handler family for the
   same pattern; the sweep that found this one also enumerated around fifty `popen()` call sites in the same
   binary, and only an argument-array migration closes them as a class
6. Add a regression test at the handler level: submit an install request whose name contains `$(true)` and
   assert the action either rejects the name or produces no shell-out; repeat with the semicolon and backtick
   forms as guards against future validator regressions; run the same suite against every model shipping the
   app-system service, not only the flagship
7. Until a patch exists: operators should treat the router's administrator credential as the boundary it is,
   keep the management plane off any wide-area-facing interface, and prefer disabling the remote-management
   and app-installation surfaces entirely where not used

## References

- https://0day-rubbish.com/blog/soap-installapp-apname-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
