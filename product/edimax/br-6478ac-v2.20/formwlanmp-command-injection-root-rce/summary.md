# Edimax BR-6478AC v2.20 - Authenticated Command Injection in the formWlanMP Manufacturing-Test Handler Reaching root Command Execution (CWE-78)

Advisory: https://0day-rubbish.com/blog/edimax-br-6478ac-formwlanmp-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The Edimax BR-6478AC is a dual-band AC1750 SOHO wireless router from Edimax
Technology Co., Ltd. of New Taipei City, Taiwan, shipped as closed-source firmware;
the image analysed here is `BR6478AC_v2.20.bin`, whose SquashFS root filesystem
carries one embedded HTTP server binary, `bin/webs` (ELF 32-bit big-endian MIPS,
MIPS-I, uClibc, stripped, 762904 bytes, SHA256
`ec39c0f9332361e37ab92f1999ac5f00f5742dd6db75f7cb26c0652cfedb32a1`), which serves
the management interface on TCP port 80 and reads the same configuration file as the
boa HTTP server it embeds. That binary still registers a manufacturing / ATE
(radio automatic test equipment) form handler that has no business existing on a
production device: `websFormDefine("formWlanMP", ...)` at `0x477a1c` publishes
`POST /goform/formWlanMP`, whose handler at `0x462a24` reads thirty radio-calibration
fields through `websGetVar` (`0x412a7c`, reached via the function-pointer table entry
at `0x4c6b18`) - `ateFunc`, `ateGain`, `ateTxCount`, `ateChan`, `ateRate`,
`ateMacID`, `e2pTxPower1` through `e2pTxPower7`, `e2pTx2Power1` through
`e2pTx2Power7`, `ateTxFreqOffset`, `ateMode`, `ateBW`, `ateAntenna`,
`e2pTxFreqOffset`, `e2pTxPwDeltaB`, `e2pTxPwDeltaG`, `e2pTxPwDeltaMix`,
`e2pTxPwDeltaN` and `readE2P` - and formats every one of them, raw, into a single
command line: `sprintf(buf, "/bin/rftest_old.sh %s %s ...", <the 30 raw strings>)`
at `0x462fd0` with the format string stored at `0x4a0d98`, immediately followed by
`system(buf)` at `0x46308c` (the `system` PLT stub at `0x490020`, relocation
`0x18b`). Between `websGetVar` and `system` there is no validation of any kind: no
`atoi`, no `inet_aton`, no `strchr`, no `isdigit`, no `strcspn`, no character
filter, no length check beyond buffer capacity, no argument quoting and no
switch to an argv-style `exec`. The only transformation is cosmetic - an empty
field is replaced with the literal word `null` so the argument positions stay
aligned - which makes every shell metacharacter that a POST body can carry
survive into the command line. `system()` hands the string to `/bin/sh -c`, so
command substitution is evaluated by the shell before `/bin/rftest_old.sh` is ever
looked up; a single field such as `ateFunc=$(id > /tmp/marker)` therefore runs `id`
first and only afterwards fails on the missing script, which the shipped rootfs
does not contain (it ships `rftest.sh`, not `rftest_old.sh`), so the shell's
exit status 127 is a harmless residue of a command that already executed. The
process that executes it is `webs`, started by the device's own boot scripts and
running as root because the shipped `etc/boa/boa.conf` declares `User root`, so
the landing identity is `uid=0(root)`. Reaching the handler requires a valid
administrative session: the access gate `auth_authorize` at `0x404d00` reads
configuration object `0x1bc` (the setup-wizard flag) through `apmib_get`, and once
the device is past setup its security store at `0x4c7004` - a single `/` entry of
type `Basic`, populated from the `Auth / /etc/boa/boa.passwd` directive by the `Auth`
handler at `0x40814c` - covers every `/goform/` path with HTTP Basic authentication.
`/goform/formWlanMP` is not one of the four routes that carry a post-boot uptime
gate (`/mp.asp`, `/goform/mp`, `/advanced_management.asp`,
`/goform/formAdvManagement`, which redirect to `/index.asp` once `/proc/uptime`
exceeds 600 seconds), so unlike the neighbouring manufacturing handler it is
reachable at any time while the device is running. This advisory is about the
injection; the factory credential the product ships with is a separate weakness
reported in its own right below and is not part of the exploitation path we rate,
and no privilege escalation was involved - the executing process is already root.

- **Component**: `bin/webs`, the embedded GoAhead-style HTTP server in firmware
  `BR6478AC_v2.20.bin`, serving the management interface on TCP port 80 and
  dispatching `/goform/` form handlers through a registration table built by
  `websFormDefine`; it reads the boa configuration (`etc/boa/boa.conf`, whose
  `Auth / /etc/boa/boa.passwd` entry defines the single Basic realm and whose
  `AddType application/x-httpd-cgi asp` entry binds `.asp` pages as CGI), writes
  `/var/run/webs.pid`, is kept alive by the boot path `cleanlog.sh:131` invoked
  from `init.sh:1115`, and runs as root
- **Sink**: `system(buf)` at `0x46308c` inside `formWlanMP` (`0x462a24`), where
  `buf` is the output of `sprintf` at `0x462fd0` using the format string
  `/bin/rftest_old.sh %s %s ...` (thirty `%s` conversions, string at `0x4a0d98`)
  filled with the thirty raw request fields; `system()` re-parses that line
  through `/bin/sh -c`
- **Source**: the URL-encoded body of an authenticated
  `POST /goform/formWlanMP`, all thirty ATE / EEPROM calibration fields listed
  above (plus the `submit-url` field the handler also reads), each returned
  verbatim by `websGetVar` after a trailing carriage return or line feed is
  stripped and an empty value is replaced by the literal `null`
- **Sanitization**: none. No character filter, no numeric coercion, no allowlist,
  no shell quoting and no argv-style execution anywhere on the path from
  `websGetVar` to `system`; the empty-to-`null` substitution is argument-position
  filler and does not remove any metacharacter. `$(...)`, backticks, `;`, `|`,
  `&` and an embedded newline all reach `/bin/sh`

## CVSS Score

- **Score**: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - one
  authenticated POST from a host that can address the management interface
  produces arbitrary command execution as root on the router, with no second step
  and nothing outside the attacker's control to wait for
- **Attack Vector: Network** - the vulnerable service is a TCP port 80 HTTP
  listener bound to the device's own IP stack, reachable by any host that can
  route to the management interface (the wired LAN, an associated wireless client,
  anything bridged onto that segment), so the attacker is more than one hop away
  from the vulnerable component in the CVSS sense. We do not claim default
  internet exposure: the shipped firewall script (`firewall.sh:180`,
  `firewall.sh:187`, `firewall.sh:189`) sets `iptables -P INPUT DROP`, drops
  WAN-originated `SYN` and accepts non-WAN input, so on a stock device the
  practical position is a client on the attached LAN or Wi-Fi segment; the
  adjacent-only reading is published below as a labelled alternative, and WAN-side
  exposure is an operator configuration (remote management or a port forward)
  rather than the shipped default
- **Attack Complexity: Low** - success needs one deterministic request against a
  running device: no race, no timing window, no memory-layout knowledge, no
  gadget hunting, no user-specific state, and the handler does not depend on the
  radio, on the WAN mode or on the uptime gate. The payload can be re-sent
  unchanged and works every time
- **Privileges Required: High** - the route sits behind the single HTTP Basic
  realm that covers `/`, and the shipped image contains exactly one authenticated
  principal, the device administrator (`etc/boa/boa.passwd`, one MD5-crypt
  account entry). That principal can rewrite WAN and WLAN configuration, start a
  firmware upgrade and reboot the device, which is the definition of significant
  control over the component's configuration; there is no second, lower-privileged
  authenticated role in the product that could make this a Low reading.
  `PR:L` was considered and rejected, with its arithmetic below
- **User Interaction: None** - the injected request is issued by the attacker
  directly; no administrator has to click, visit a page or be present
- **Scope: Unchanged** - the web server already runs as root under the same
  authority as the device operating system (`User root` in the shipped
  `etc/boa/boa.conf`), so executing a command in its stead crosses no
  authorisation boundary; the commands land on the very component the service
  already owns. Scope Changed was considered and rejected, with its arithmetic
  below
- **Impact C/I/A: all High** - root command execution on the router exposes every
  stored secret (the administrator password file, wireless pre-shared keys and
  per-client material, VPN and PPP credentials kept in the configuration store,
  any certificate on the device), permits rewriting configuration and firmware
  persistence, and permits stopping the routing, wireless and DNS services at
  will
- **CWE**: CWE-78 primary. CWE-798 (the factory credential that ships in the
  read-only root filesystem) and CWE-250 (the web server runs with full root
  privileges rather than a separated account) are real weaknesses of the same
  product, are reported separately below, and do not raise any metric used for the
  score above
- **Recorded score**: the research notes behind this advisory carried `8.8`
  written next to a `PR:H` vector. `8.8` is the arithmetic of `PR:L`, not of
  `PR:H`; recomputed from the vector itself with the CVSS 3.1 base formula and its
  round-up-to-the-tenth convention - ISS 1 - 0.44^3 = 0.914816, Impact(S:U)
  6.42 x 0.914816 = 5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.27 x 0.85 =
  1.234708, base = min(5.873119 + 1.234708, 10) = 7.107826 - the published score
  is **7.2 (High)**. No figure was inherited
- **Rejected reading 1 - `PR:L`**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High
  (Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, base
  5.873119 + 2.835255 = 8.708373, rounded up to 8.8). Rejected: `PR:L` describes
  basic user capabilities, and this product has no basic-user role. The realm
  holds one account, the security store holds one `/` entry, the `Allow` directive
  handler in this build is a non-functional stub that answers "This version of Boa
  doesn't support access controls", the shipped configuration carries one `Auth`
  directive and no `Allow` directive, and our reading of it found no per-user or
  per-group access restriction that would separate a low-privileged caller from the
  administrator
- **Rejected reading 2 - Scope Changed**:
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = 9.1 High (Impact(S:C) =
  7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 - 0.02)^13 = 6.128026,
  Exploitability 8.22 x 0.85 x 0.77 x 0.50 x 0.85 = 2.286496, base 1.08 x
  8.414522 = 9.087684, rounded up to 9.1). Rejected: the vulnerable component is
  not running under a reduced authority, so nothing is escaped. `webs` is root
  before the attack and root after it
- **Rejected reading 3 - adjacent-only reach**:
  `CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.8 High (Exploitability
  8.22 x 0.62 x 0.77 x 0.27 x 0.85 = 0.900610, base 6.773729, rounded up to 6.8).
  This is the honest reading for a stock device whose WAN-side input policy drops
  new connections; we do not adopt it as the headline because the service is
  bound to the device's network stack and is addressable over IP by every host on
  the segment the router serves, including wireless clients and any bridged or
  compromised LAN device, and because operators routinely expose it
- **Rejected reading 4 - `AC:H`**:
  `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.6 High (Exploitability
  8.22 x 0.85 x 0.44 x 0.27 x 0.85 = 0.705547, base 6.578666, rounded up to 6.6).
  Rejected: nothing about the attack depends on a condition beyond the attacker's
  control. There is no window to win, unlike the neighbouring uptime-gated
  manufacturing route
- **Conditional reading A - the factory credential was never rotated**:
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical (Exploitability
  8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043, base 5.873119 + 3.887043 =
  9.760161, rounded up to 9.8). Applies to a deployment that still accepts the
  credential the firmware ships with, where the administrator "privilege" costs one
  guess and no privilege has to be obtained at all. **Reasoned, not demonstrated**:
  we never authenticated to a physical device, so this path is an inference from
  the shipped password file in the read-only root filesystem plus the injection
  proven at the sink, not a detonation we performed. Its Scope-Changed variant
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` computes to 10.0 and is not
  published, for the Scope reason above
- **Conditional reading B - the device is still in its pre-configuration setup
  state**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical. In
  `auth_authorize`, when configuration object `0x1bc` reads zero the handler for
  any path outside a small set (`/mp.asp`, `/index.asp`, `/`) returns success
  without issuing a challenge (`0x4052d0`), while `/generate_204` answers `204` -
  the captive-portal behaviour of an unconfigured device. Three shipped artefacts
  identify that state as the setup wizard rather than normal operation:
  `formwizResetDefault` at `0x44cdbc` resets the device and displays
  `Resettowizard`, `formWizSetup` prints `NO - LOGIN-WEB` when the flag is set to
  1, and management pages such as `web/inter_wan.asp:214` and
  `web/admin_timezone.asp:95` read the same flag to switch their interface. An
  early pass of this research misread that branch as an unauthenticated
  post-setup state; it is the setup state, and we rated the finding down to
  `PR:H` accordingly. **Structural inference only**: the unauthenticated setup-state
  branch was read from the shipped binary, never exercised, and the state ends
  when setup completes. If the window has to be contested rather than simply
  found open, the reading is
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.1 High (Exploitability
  2.221167, base 8.094286)

## Affected Products

- Edimax BR-6478AC, a dual-band AC1750 SOHO wireless router from Edimax
  Technology Co., Ltd. (New Taipei City, Taiwan), closed-source firmware. The
  product identity string recorded in the material we analysed is
  `BR-6478AC_v2.20`, and the firmware image is `BR6478AC_v2.20.bin`
- Firmware artefacts examined: `BR6478AC_v2.20.bin`, containing a SquashFS root
  filesystem of roughly 2.3 MB for a MIPS 32-bit big-endian MIPS-I target with a
  uClibc C library, all binaries stripped, with an internal build timestamp from
  2015. The management server is `bin/webs`, ELF 32-bit MSB MIPS, 762904 bytes,
  SHA256 `ec39c0f9332361e37ab92f1999ac5f00f5742dd6db75f7cb26c0652cfedb32a1`
- Affected component: the `/goform/` form-handler dispatcher of `bin/webs`, and
  specifically the `formWlanMP` manufacturing / ATE handler at `0x462a24`
  registered at `0x477a1c`, together with the helper `/bin/rftest*.sh` family it
  tries to invoke. This handler surface is a factory calibration tool exposed on a
  production management interface: our count of the shipped binary's registration
  table found 91 `/goform/form*` handlers, of which roughly 85 reach a
  `system()` or `popen()` call, so `formWlanMP` is one instance of a broad pattern
  rather than an isolated slip
- Runtime stack: `bin/webs` on TCP port 80 handling `/goform/` and `/gen*.cgi`
  plus 31 ASP handlers, sharing `etc/boa/boa.conf`; a second helper HTTP server
  (`axhttpd`, started by `iQsetup_set()` through `scriptlib.sh:1184` as
  `axhttpd -w /tmp/www &`) that only runs during the setup state; a UPnP IGD
  daemon (`miniigd`, miniupnpd-derived) on UDP/TCP port 52869; and an outbound
  cloud-connect daemon, which opens no inbound listener
- Only this firmware build was examined. Other `BR6478AC` firmware versions, the
  separately marketed BR-6478AC V2 hardware revision with its own firmware line
  (for example `BR6478ACV2_v1.23`, a different little-endian MIPS-II build of
  `webs`), and other Edimax models were not tested for this handler, and no claim
  is made for them
- **Verification method, and its boundary**: the HTTP leg - request parsing,
  authentication gate, form registration and dispatch - is evidenced at
  instruction level from the shipped binary, using disassembly and decompilation
  of `bin/webs`, `etc/boa/boa.conf`, the root filesystem layout and the boot
  scripts. The execution leg is evidenced dynamically, but by replication rather
  than by detonation: because a MIPS big-endian uClibc userspace could not be
  booted end to end in our environment (full-system emulation was abandoned after
  the user-mode translator faulted), we reconstructed the exact string that
  `sprintf` produces at `0x462fd0` and handed it to `/bin/sh -c` in an isolated
  POSIX sandbox running as root, which is what `system()` does on the device. That
  run produced a 39-byte marker file owned by `root:root` containing
  `uid=0(root) gid=0(root) groups=0(root)`, with shell exit status 127 from the
  absent `rftest_old.sh`; the same replication run under an ordinary user account
  on a workstation reproduced the semantics at that identity. A benign control
  (`ateFunc=11b`, no metacharacter) produced no marker. **No physical device was
  powered on and no end-to-end HTTP request was ever accepted by the product**, so
  the on-device landing identity is argued from the shipped `User root` directive
  and from the replication, not observed on hardware
- Privilege ceiling: arbitrary operating-system command execution as root on the
  router. **Not claimed**: no privilege escalation (the executing process is
  already root), no unauthenticated variant in the normal-operation state, no
  cross-host movement, no persistence mechanism installed by us, and no exploit of
  the neighbouring uptime-gated manufacturing route, which we examined and
  deliberately excluded from this advisory

## Impact

- Arbitrary root command execution on the router from a single authenticated POST,
  with no payload upload, no race and no second vulnerability required
- Disclosure of every secret the device stores: the administrator password file,
  wireless pre-shared keys and per-station key material, the PPP / PPTP / L2TP
  usernames and passwords kept in the configuration store, VPN parameters, and
  any certificate or key present on the filesystem
- Complete control of configuration and of the routing plane: firewall and NAT
  rules, DNS resolution handed to clients, DHCP leases, port forwards, wireless
  SSIDs and channels, and the WAN uplink itself - enough to redirect, drop or
  silently forward traffic for every host behind the device
- Firmware-level persistence: root on the device permits writing to the flash
  configuration area and installing a boot-time startup mechanism, so the
  compromise survives reboots and can survive a partial configuration reset;
  recovery then requires a full reflash of known-good firmware
- The manufacturing handler makes exploitation quieter than a normal management
  action: the request it imitates is a factory radio-calibration submission, so a
  `POST /goform/formWlanMP` with thirty ATE fields is unremarkable traffic for
  this device, and the injected command runs inside a shell that also reports a
  missing script - an exit status 127 line that reads as ordinary product breakage
- Availability at will: root can stop the wireless, routing, DHCP, DNS and
  management services, or reboot the device repeatedly
- The attack is repeatable and idempotent from the attacker's side, and it leaves
  no rate limit, no lockout and no alert behind: the shipped HTTP Basic gate showed
  no throttling in our reading of the configuration, so an operator who has
  rotated away from the factory password still faces dictionary pressure on a
  single-account realm
- Two further weaknesses of the same product are reported here without being
  folded into the score. First, a factory credential: the shipped root filesystem
  contains a populated `etc/boa/boa.passwd` for the single Basic realm (one
  MD5-crypt account entry), and the model's published factory login is `admin:1234`
  (CWE-798). The single account entry in that file is recorded under the name
  `root` in the image we examined while the model's published management login is
  `admin`; no device was authenticated against, so which name the realm accepts was
  not established, and nothing rated here depends on it. This is a serious weakness in its own right - it is what makes
  Conditional reading A above reachable - but it is not the vector we rate, because
  both the injection and the authentication requirement exist independently of it.
  Second, privilege separation is absent: `bin/webs` serves untrusted HTTP input
  while running as root (CWE-250), so any injection anywhere in the 91-handler
  surface starts at the highest identity the device has
- A second, independent injection on the same product is published as a companion
  advisory: the WAN-configuration handler `setWAN` reaches the same
  `sprintf`-then-`system()` shape at `0x441ee8` and `0x441f1c` through
  `POST /goform/setWAN`. Different handler, different format string, different
  (semicolon-only) sanitiser - see
  https://0day-rubbish.com/blog/edimax-br-6478ac-setwan-command-injection-root-rce

## Mitigation / Fix Recommendations

1. **Remove the manufacturing surface from production firmware** - `formWlanMP`
   is an ATE radio-calibration handler. Do not compile it into, or do not
   register it in, a shipping image: build it under a factory-only target, gate it
   behind a signed local token read from the serial console, or drop the
   `websFormDefine("formWlanMP", ...)` registration at `0x477a1c` from release
   builds entirely. A field that names a shell script and takes thirty
   unvalidated parameters should never be exposed on a management port
2. **Stop building command lines with `sprintf`** - replace the
   `sprintf` + `system` pair at `0x462fd0` / `0x46308c` with a direct
   `execve("/bin/rftest_old.sh", argv, envp)` where each request field becomes one
   argv element. `execve` has no shell, so no metacharacter means anything. This
   is the single change that removes the class of bug, and it applies to the whole
   `system()` / `popen()` population in `bin/webs`, of which we counted roughly 85
   instances
3. **Validate every ATE field on entry** - these thirty fields have narrow,
   knowable domains: integer gains, channel numbers, rate indices, MAC index,
   power deltas, bandwidth and antenna selectors. Parse them with `strtol` /
   `strtoul` plus an explicit range check, or match them against a strict
   allowlist (`^[0-9A-Za-z._-]+$`); reject the request otherwise. Do not rely on a
   character blacklist - the sibling `setWAN` handler blacklists only `;` and is
   still injectable, and blacklists decay silently as the payload grammar grows
4. **Quote or encode wherever a shell must remain** - if a helper script call has
   to stay, pass values through the environment (`setenv` in the child, read as
   `"$VAR"`) or single-quote each argument with every embedded quote escaped.
   Never interpolate a raw request value into a shell string
5. **Enforce privilege separation for the HTTP server** - `etc/boa/boa.conf`
   currently declares `User root`. Bind the low port as root, then drop to a
   dedicated unprivileged account before serving requests; keep only the specific
   operations that truly need elevation behind a small, separately audited
   privileged helper. This converts a future injection from full-device takeover
   into a contained one (CWE-250)
6. **Separate the administrative realm into roles, or state that there is only
   one** - because a single administrator credential unlocks every handler
   including factory test routes, consider a distinct authenticated role (or a
   separate serial-console-only path) for manufacturing and diagnostic handlers,
   so that a stolen management credential does not also buy a factory tool
7. **Replace the factory credential on first use** - force a password change at
   the first authenticated session, or provision a unique random password per
   unit at manufacturing, so that the shipped `etc/boa/boa.passwd` entry does not
   remain valid in the field (CWE-798). Store it with a memory-hard digest rather
   than MD5-crypt, and add rate limiting and lockout on the Basic challenge, which
   is currently a single-account realm
8. **Restrict and audit the management plane** - keep WAN-side management access
   off by default and make the shipped `INPUT DROP` policy explicit rather than
   incidental to a firewall script; allow management from named source addresses
   only; log every `/goform/` submission that carries shell metacharacters in a
   field that is supposed to be numeric
9. **Add a regression test to the firmware build** - submit
   `ateFunc=$(id)` (and the `;`, `|`, backtick variants) to
   `POST /goform/formWlanMP` against a build image and assert that the request is
   rejected with a validation error, that no marker file appears, and that no
   shell is spawned; separately assert that a benign `ateFunc=11b` still reaches
   the calibration path, so the fix cannot silently disable the handler
10. **Operator measures until patched firmware exists** - change the factory
    password immediately; never expose the management interface to a WAN address,
    a reverse proxy or a port forward; place the router's management address in a
    dedicated management VLAN or restrict it to named hosts at the upstream
    firewall; disable remote management; treat any device still running 2015-era
    firmware as end-of-support and plan replacement, because the vendor's ability
    to ship a fix for a build this old is limited

## References

- https://0day-rubbish.com/blog/edimax-br-6478ac-formwlanmp-command-injection-root-rce
- https://0day-rubbish.com/blog/edimax-br-6478ac-setwan-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com
- CWE-78 Improper Neutralization of Special Elements used in an OS Command
  (https://cwe.mitre.org/data/definitions/78.html)
- CWE-798 Use of Hard-coded Credentials
  (https://cwe.mitre.org/data/definitions/798.html)
- CWE-250 Execution with Unnecessary Privileges
  (https://cwe.mitre.org/data/definitions/250.html)
- CVSS 3.1 specification, First.org
  (https://www.first.org/cvss/v3.1/specification-document)

---
Written by the 0day Rubbish Research Team.
