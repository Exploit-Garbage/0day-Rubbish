# Edimax BR-6478AC v2.20 - Authenticated Command Injection in the setWAN WAN-Configuration Handler Reaching root Command Execution (CWE-78)

Advisory: https://0day-rubbish.com/blog/edimax-br-6478ac-setwan-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The Edimax BR-6478AC is a dual-band AC1750 SOHO wireless router from Edimax
Technology Co., Ltd. of New Taipei City, Taiwan, shipped as closed-source
firmware; the image analysed here is `BR6478AC_v2.20.bin`, whose SquashFS root
filesystem carries one embedded HTTP server, `bin/webs` (ELF 32-bit big-endian
MIPS, MIPS-I, uClibc, stripped, 762904 bytes, SHA256
`ec39c0f9332361e37ab92f1999ac5f00f5742dd6db75f7cb26c0652cfedb32a1`), serving the
management interface on TCP port 80. That binary registers the WAN
configuration handler `websFormDefine("setWAN", ...)` at `0x478484` (handler
`0x441cec`, name string `0x4a6250`), publishing `POST /goform/setWAN`. Inside
that handler the WAN mode is read and dispatched - `websGetVar(wp, "wanMode", "")`
at `0x441d3c`, `atoi` at `0x441d44`, `apmib_set(0x102, &wanMode)` at
`0x441d54`, then `addiu v1, zero, 2` at `0x441d60` and `beq v0, v1, 0x441e74` at
`0x441d6c` - and on the PPP branch (`wanMode` 2) the username field is taken
from the request: `websGetVar(wp, "pppUserName", "")` at `0x441e74` (name
string `0x4953f4`), copied with `strcpy` at `0x441e94` into a fixed stack
buffer, measured with `strlen` at `0x441ea8`, and then scanned by an inline
byte loop between `0x441ebc` and `0x441ee4` whose only comparison is
`addiu a0, zero, 0x3b` - a semicolon. Finding one, the loop writes a NUL and
stops. That single-character scan is the entire sanitisation on the path. The
value then goes into `sprintf(buf2, "echo %s > /tmp/UserName", buf)` at
`0x441ee8` (format string `0x49a510`) and from there into `system(buf2)` at
`0x441f1c` (`system` via the PLT slot `0x4c6d60`), which hands the line to
`/bin/sh -c`. A pipe, an ampersand, a backtick, a dollar sign with parentheses
and an embedded newline are never inspected, so a username of
`|id > /tmp/marker #` produces the command
`echo |id > /tmp/marker # > /tmp/UserName`: the shell treats `#` as a comment
that swallows the sink's own redirect, and runs `id` as the right-hand side of a
pipeline. The process is root, because the shipped `etc/boa/boa.conf` declares
`User root`, so the landing identity is `uid=0(root)`. The escape loop that
neutralises `#` does exist in this handler - it runs between `0x441f4c` and
`0x441fb0` - but the instruction order puts it after `system()`, and its output
goes to a different buffer, the configuration store written by
`apmib_set(0x6d, ...)` at `0x44200c`; the developer clearly knew about the hash
character and applied the defence too late and in the wrong place. Two further
instances of the same construction sit in the same handler: `pptpUserName` on
`wanMode` 3 and `L2TPUserName` on `wanMode` 6, each with the same semicolon scan
and the same `echo %s > /tmp/UserName` sink, so one root cause yields three
reachable parameters. Reaching the handler requires a valid administrative
session: the gate `auth_authorize` at `0x404d00` reads configuration object
`0x1bc` (the setup-wizard flag) through `apmib_get`, and once the device is past
setup its security store at `0x4c7004` - a single `/` entry of type `Basic`,
populated from `Auth / /etc/boa/boa.passwd` - covers every `/goform/` path with
HTTP Basic authentication. `/goform/setWAN` is not one of the four routes carrying
a post-boot uptime gate (`/mp.asp`, `/goform/mp`, `/advanced_management.asp`,
`/goform/formAdvManagement`), so it is reachable at any time the device is up.
This advisory rates the injection; the factory credential the product ships with
is a separate weakness reported in its own right below and is not the vector, and
no privilege escalation is involved - the executing process is already root.

- **Component**: `bin/webs`, the embedded GoAhead-style HTTP server in firmware
  `BR6478AC_v2.20.bin`, serving the management interface on TCP port 80 and
  dispatching `/goform/` form handlers registered at run time by
  `websFormDefine`; it reads the boa configuration (`etc/boa/boa.conf`, whose
  `Auth / /etc/boa/boa.passwd` entry defines the single Basic realm), writes
  `/var/run/webs.pid`, is kept alive by the boot path `cleanlog.sh:131` invoked
  from `init.sh:1115`, and runs as root
- **Sink**: `system(buf2)` at `0x441f1c` inside the `setWAN` WAN-configuration
  handler (`0x441cec`), where `buf2` is the output of `sprintf` at `0x441ee8`
  using the format string `echo %s > /tmp/UserName` (`0x49a510`) filled with the
  raw `pppUserName` request field; `system()` re-parses the line through
  `/bin/sh -c`
- **Source**: the URL-encoded body of an authenticated `POST /goform/setWAN` -
  `wanMode` selects the branch, and `pppUserName` (or `pptpUserName` on
  `wanMode` 3, or `L2TPUserName` on `wanMode` 6) carries the payload, returned
  verbatim by `websGetVar` at `0x441e74` after a trailing carriage return or line
  feed is stripped
- **Sanitization**: one byte. An inline loop between `0x441ebc` and `0x441ee4`
  compares each character against immediate `0x3b` (`;`) and truncates the buffer
  there; no validator function is called on the path. `|` (`0x7c`), `&` (`0x26`),
  a backtick (`0x60`), `$` (`0x24`), a newline (`0x0a`) and `#` (`0x23`) are not
  checked and pass through to the shell. The `inet_aton` calls at `0x441dd0` and
  `0x441e14` belong to the static-IP branch (`wanMode` 1) and never execute on the
  PPP path. The `#`-escaping loop at `0x441f4c` runs after the sink and writes the
  configuration buffer, not the command buffer

## CVSS Score

- **Score**: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - one
  authenticated POST that looks like an ordinary WAN settings submission produces
  arbitrary command execution as root on the router, with no second step and
  nothing outside the attacker's control to wait for
- **Attack Vector: Network** - the vulnerable service is a TCP port 80 HTTP
  listener bound to the device's own network stack, addressable by any host that
  can reach the management interface (the wired LAN, an associated wireless
  client, anything bridged onto that segment), which is more than one hop in the
  CVSS sense. We do not claim default internet exposure: the shipped firewall
  script (`firewall.sh:180`, `firewall.sh:187`, `firewall.sh:189`) sets
  `iptables -P INPUT DROP`, drops WAN-originated `SYN` and accepts non-WAN input,
  so on a stock device the practical position is a client on the attached LAN or
  Wi-Fi segment; the adjacent-only reading is published below with its arithmetic,
  and WAN-side exposure is an operator configuration (remote management or a port
  forward) rather than the shipped default
- **Attack Complexity: Low** - one deterministic request against a running device.
  No race, no timing window, no memory layout, no gadget, no user-specific state;
  the only branch to satisfy is `wanMode`, which the attacker supplies
- **Privileges Required: High** - the route sits behind the single HTTP Basic
  realm that covers `/`, and the shipped image contains exactly one authenticated
  principal, the device administrator (`etc/boa/boa.passwd`, one MD5-crypt
  account entry). That principal can rewrite WAN and WLAN configuration, start a
  firmware upgrade and reboot the device - significant control over the
  component's configuration by definition. There is no second, lower-privileged
  authenticated role, so `PR:L` was considered and rejected, with its arithmetic
  below
- **User Interaction: None** - the attacker issues the request; no administrator
  action, click or visit is required at any step
- **Scope: Unchanged** - the web server already runs as root under the same
  authority as the device operating system (`User root` in the shipped
  `etc/boa/boa.conf`), so executing a command in its stead crosses no
  authorisation boundary. Scope Changed was considered and rejected, with its
  arithmetic below
- **Impact C/I/A: all High** - root command execution on the router exposes every
  stored secret (the administrator password file, wireless pre-shared keys and
  per-client key material, and precisely the PPP / PPTP / L2TP credentials this
  handler writes into configuration objects `0x6d`, `0xf3` and `0x128`), permits
  rewriting configuration, firewall and NAT rules and installing firmware-level
  persistence, and permits stopping routing, wireless, DHCP, DNS and the
  management service at will
- **CWE**: CWE-78 primary. CWE-798 (the factory credential shipped in the
  read-only root filesystem), CWE-250 (the web server runs with full root
  privileges) and CWE-20 (a field documented as a username is accepted as free
  text) are reported separately below and do not raise any metric used for the
  score above
- **Recorded score**: the research notes behind this advisory carried `8.8`
  written next to a `PR:H` vector. `8.8` is the arithmetic of `PR:L`, not of
  `PR:H`; recomputed from the vector with the CVSS 3.1 base formula and its
  round-up-to-the-tenth convention - ISS 1 - 0.44^3 = 0.914816, Impact(S:U)
  6.42 x 0.914816 = 5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.27 x 0.85 =
  1.234708, base = min(5.873119 + 1.234708, 10) = 7.107826 - the published score
  is **7.2 (High)**. No figure was inherited
- **Rejected reading 1 - `PR:L`**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High
  (Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, base
  5.873119 + 2.835255 = 8.708373, rounded up to 8.8). Rejected: `PR:L` describes
  basic user capabilities, and the product has no basic-user role. One realm entry,
  one password file, one account, an `Allow` directive handler at `0x407688` that
  is a stub answering "This version of Boa doesn't support access controls", a
  type-`None` string at `0x49070c` that is never passed to `auth_add`, and a shipped
  configuration carrying one `Auth` directive and no `Allow` directive, in which our
  reading found no per-user or per-group access restriction
- **Rejected reading 2 - Scope Changed**:
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = 9.1 High (Impact(S:C) =
  7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 - 0.02)^13 = 6.128026,
  Exploitability 8.22 x 0.85 x 0.77 x 0.50 x 0.85 = 2.286496, base 1.08 x
  8.414522 = 9.087684, rounded up to 9.1). Rejected: the vulnerable component
  already holds the whole authority it is said to escape. `webs` is root before
  the attack and root after it
- **Rejected reading 3 - adjacent-only reach**:
  `CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.8 High (Exploitability
  8.22 x 0.62 x 0.77 x 0.27 x 0.85 = 0.900610, base 6.773729, rounded up to 6.8).
  This is the honest reading for a stock device whose WAN-side input policy drops
  new connections; it is not adopted as the headline because the service is bound
  to the device's network stack and is addressable over IP by every host on the
  segment the router serves, including guest wireless clients
- **Rejected reading 4 - `AC:H`**:
  `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.6 High (Exploitability
  8.22 x 0.85 x 0.44 x 0.27 x 0.85 = 0.705547, base 6.578666, rounded up to 6.6).
  Rejected: nothing about success depends on a condition outside the attacker's
  control; the `wanMode` branch is attacker-supplied, and unlike the four
  uptime-gated routes on this device there is no boot window
- **Conditional reading A - the factory credential was never rotated**:
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical (Exploitability
  8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043, base 5.873119 + 3.887043 =
  9.760161, rounded up to 9.8). Applies to a deployment that still accepts the
  credential the firmware ships with, where the administrator privilege costs one
  guess. **Reasoned, not demonstrated**: we never authenticated to a physical
  device, so this path is an inference from the shipped password file in the
  read-only root filesystem plus the injection proven at the sink, not a
  detonation we performed. Its Scope-Changed variant
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` computes to 10.0 and is not
  published, for the Scope reason above
- **Conditional reading B - the device is still in its pre-configuration setup
  state**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical. When
  configuration object `0x1bc` reads zero, `auth_authorize` returns success with
  no challenge for any path outside `/mp.asp`, `/index.asp` and `/` (at
  `0x4052d0`) and answers `/generate_204` with `204` - captive-portal behaviour.
  Three shipped artefacts identify that state as the setup wizard: `formwizResetDefault`
  at `0x44cdbc` resets the device and displays `Resettowizard`; `formWizSetup`
  prints `NO - LOGIN-WEB` when the flag is set to 1; and management pages such as
  `web/inter_wan.asp:214` and `web/admin_timezone.asp:95` read the same flag to
  switch their interface. **Structural inference only**: that branch was read from
  the shipped binary and never exercised, and the state ends when setup completes.
  If the window has to be contested rather than found open, the reading is
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.1 High (Exploitability
  2.221167, base 8.094286)

## Affected Products

- Edimax BR-6478AC, a dual-band AC1750 SOHO wireless router from Edimax
  Technology Co., Ltd. (New Taipei City, Taiwan), closed-source firmware. The
  product identity string recorded in the material analysed is
  `BR-6478AC_v2.20`, and the firmware image is `BR6478AC_v2.20.bin`
- Firmware artefacts examined: `BR6478AC_v2.20.bin`, containing a SquashFS root
  filesystem of roughly 2.3 MB for a MIPS 32-bit big-endian MIPS-I target with a
  uClibc C library, all binaries stripped, internal build timestamp from 2015.
  Management server: `bin/webs`, ELF 32-bit MSB MIPS, 762904 bytes, SHA256
  `ec39c0f9332361e37ab92f1999ac5f00f5742dd6db75f7cb26c0652cfedb32a1`
- Affected component: the `/goform/` form-handler dispatcher of `bin/webs`, and
  specifically the WAN-configuration handler `setWAN` at `0x441cec`, registered at
  `0x478484`. Three parameters of that handler are affected through one
  construction: `pppUserName` on `wanMode` 2 (sink address range
  `0x441e74`-`0x441f1c`, configuration object `0x6d`), `pptpUserName` on
  `wanMode` 3 (`0x4420d0` onward, configuration object `0xf3`) and `L2TPUserName`
  on `wanMode` 6 (`0x44246c` onward, configuration object `0x128`). We analysed
  the `wanMode` 2 path at instruction level and verified its sink; the other two
  are reported as the same construction read from the same handler, which is a
  structural rather than a demonstrated claim
- Runtime stack: `bin/webs` on TCP port 80 handling `/goform/` and `/gen*.cgi`
  plus 31 ASP handlers and sharing `etc/boa/boa.conf`; a second helper HTTP server
  (`axhttpd`, started by `iQsetup_set()` through `scriptlib.sh:1184`) that only
  runs during the setup state; a UPnP IGD daemon (`miniigd`) on port 52869; and an
  outbound cloud-connect daemon that opens no inbound listener
- Only this firmware build was examined, and only for this handler. Other
  `BR6478AC` firmware versions, the separately marketed BR-6478AC V2 hardware
  revision with its own firmware line (for example `BR6478ACV2_v1.23`, a different
  little-endian MIPS-II build of `webs`), and other Edimax models were not tested
- **Sibling-model observation, static only**: while confirming the sink we also
  compared a second Edimax firmware image, `BR-6208AC_V2_1.03`, whose `webs` is a
  different build (ELF 32-bit MSB MIPS-I, 816568 bytes, SHA256
  `3ad10a41d11c8cd59185eab6c9ce67b18cd2118942eb2201f48540d7846a0328`) but whose
  `setWAN` implementation matches instruction for instruction: handler at
  `0x448710`, `websGetVar(pppUserName)` at `0x4488b8`, `strcpy` at `0x4488bc`,
  the same immediate-`0x3b` inline scan at `0x4488dc`-`0x4488fc`, the same
  `echo %s > /tmp/UserName` sprintf at `0x448920` (format string `0x4a6954`) and
  `system()` at `0x448940`, with the same three parameters on the same three
  `wanMode` values. We report this to the vendor as evidence that the defect lives
  in a shared software component rather than in one product's build; we did not
  test that model, and no score in this advisory covers it
- **Verification method, and its boundary**: the HTTP leg - request parsing,
  authentication gate, form registration, mode dispatch and the PPP branch
  selection - is evidenced at instruction level from the shipped binary, its
  configuration and its boot scripts. The execution leg is evidenced dynamically by
  replication rather than by detonation: because a MIPS big-endian uClibc userspace
  could not be booted end to end in our environment (full-system emulation was
  abandoned after the user-mode translator faulted), we reconstructed the exact
  string that `sprintf` produces at `0x441ee8` and handed it to `/bin/sh -c` in an
  isolated POSIX sandbox running as root. That run produced a 39-byte marker file
  owned by `root:root` containing `uid=0(root) gid=0(root) groups=0(root)` with
  shell exit status 0, and the sink's own `/tmp/UserName` destination was *not*
  created, which is what proves the trailing `#` reached the shell as a comment.
  A benign control (`echo validuser` into a second destination) created that
  destination containing `validuser` and produced no marker. The same replication
  was run under an ordinary user account on a workstation with the same semantics
  at that identity. **No physical device was powered on and no end-to-end HTTP
  request was ever accepted by the product**, so the on-device landing identity is
  argued from the shipped `User root` directive plus the root-identity replication,
  not observed on hardware
- Privilege ceiling: arbitrary operating-system command execution as root on the
  router. **Not claimed**: no privilege escalation (the executing process is
  already root), no unauthenticated variant in the normal-operation state, no
  cross-host movement, no persistence installed by us, and no exploit developed for
  the adjacent observations recorded in this analysis (the unbounded `strcpy` into
  a fixed stack buffer, and the uptime-gated `/goform/mp` sink)

## Impact

- Arbitrary root command execution on the router from a single authenticated POST
  that is indistinguishable from a legitimate WAN settings submission: the payload
  travels in the PPP username field of the form the product's own `wan.asp` page
  posts
- Disclosure of every secret the device stores, including the credentials this very
  handler writes into configuration objects `0x6d` (PPP), `0xf3` (PPTP) and `0x128`
  (L2TP) - so an attacker who reaches the device can read the ISP or VPN account
  details the owner entered, together with the administrator password file, wireless
  pre-shared keys and per-station key material
- Complete control of the configuration and routing plane: firewall and NAT rules,
  the DNS resolver handed out to clients, DHCP, port forwards, wireless SSIDs, and
  the WAN uplink itself - including rewriting the WAN mode, which is exactly the
  configuration path this handler owns
- Firmware-level persistence: root permits writing to the flash-backed
  configuration area and installing a boot-time startup mechanism, so the
  compromise survives reboots and can survive a partial configuration reset;
  recovery then requires a full reflash of known-good firmware
- Detection is poor by construction: a submitted WAN configuration produces ordinary
  product behaviour, and the sink's own visible effect - a username written into
  `/tmp/UserName` and then into the configuration store - is exactly what a
  legitimate submission does. The most reliable indicator is the *absence* of the
  expected `/tmp/UserName` destination on a submission that should have created it,
  because the payload commented the redirect out
- The injection also corrupts the stored configuration in a way the owner may not
  notice: the semicolon scanner truncates at the first `;`, so a username containing
  one is silently shortened before it is stored, and a payload using `|` and `#`
  stores a username the WAN link cannot authenticate with - a self-inflicted
  availability event that doubles as a fingerprint
- Availability at will: root can stop wireless, routing, DHCP, DNS and the
  management service, or reboot the device repeatedly
- Two further weaknesses of the same product are reported here without being folded
  into the score. First, a factory credential: the shipped root filesystem contains
  a populated `etc/boa/boa.passwd` for the single Basic realm (one MD5-crypt account
  entry), and the model's published factory login is `admin:1234` (CWE-798). The
  single account entry in that file is recorded under the name `root` in the image we
  examined while the model's published management login is `admin`; no device was
  authenticated against, so which name the realm accepts was not established, and
  nothing rated here depends on it. That weakness is what
  makes Conditional reading A reachable, but not the vector we rate. Second,
  privilege separation is absent: `bin/webs` serves untrusted HTTP input while
  running as root (CWE-250), so any injection in this handler population starts at
  the highest identity the device has
- A second, independent injection on the same product is published as a companion
  advisory: the manufacturing-test handler `formWlanMP` reaches
  `sprintf`-then-`system()` at `0x462fd0` and `0x46308c` through
  `POST /goform/formWlanMP` with no sanitisation at all across thirty calibration
  fields. Different handler, different format string, no sanitiser - see
  https://0day-rubbish.com/blog/edimax-br-6478ac-formwlanmp-command-injection-root-rce

## Mitigation / Fix Recommendations

1. **Stop writing configuration through a shell.** The sink exists because the
   handler persists a value with `echo %s > /tmp/UserName` instead of writing the
   file with `fopen`/`fwrite` or storing it directly through `apmib_set`, which the
   same function already calls at `0x44200c`. Delete the `sprintf` + `system` pair
   at `0x441ee8` / `0x441f1c` and write the value with a file API; that removes the
   shell from the path entirely and fixes all three isomorphic instances
   (`pppUserName`, `pptpUserName`, `L2TPUserName`) at once
2. **Where a shell call must stay, use argv.** Replace the interpolation with
   `execve` and pass the value as one argv element, or pass it through the child's
   environment. Neither has a shell in the loop, so no metacharacter means
   anything. Apply the same change across the `system()` / `popen()` population in
   `bin/webs` (our count of the registration table is 91 `/goform/form*` handlers,
   roughly 85 of which reach a command execution call)
3. **Validate the username fields against their real domain.** A PPP, PPTP or L2TP
   username is a printable token of bounded length: enforce a maximum length,
   reject control characters, and allowlist
   `^[A-Za-z0-9._@/+-]+$`. Reject the request rather than truncate it - silent
   truncation is itself a defect, since it stores a credential the WAN link cannot
   use
4. **Move the existing `#` escape to before the sink, and to the right buffer.**
   The handler already escapes `#` between `0x441f4c` and `0x441fb0`, but only for
   the configuration store and only after `system()` has run. Escaping for storage
   is not sanitisation for execution, and no character-level escaping should be the
   primary defence against command construction
5. **Bound the copy.** `strcpy` at `0x441e94` writes attacker-controlled bytes into
   a fixed stack buffer with no length argument. Use `strncpy` plus explicit
   termination, or validate the length before copying. We did not develop an overflow
   and make no exploitability claim; the missing bound is reported so it is fixed in
   the same pass
6. **Enforce privilege separation for the HTTP server** - `etc/boa/boa.conf`
   declares `User root`. Bind the low port as root, then drop to a dedicated
   unprivileged account before serving requests, keeping elevation inside a small
   audited helper (CWE-250)
7. **Replace the factory credential on first use** - force a password change at the
   first authenticated session or provision a unique per-unit password at
   manufacturing; store it with a memory-hard digest rather than MD5-crypt; and add
   rate limiting plus lockout on the Basic challenge, which is a single-account realm
   (CWE-798)
8. **Restrict and audit the management plane** - keep WAN-side management off by
   default as a documented product decision rather than a firewall-script side
   effect; allow management from named source addresses only; and log any
   `/goform/` submission whose username field contains a pipe, a dollar sign, a
   backtick, a hash or a newline
9. **Add a regression test to the firmware build** - submit
   `pppUserName=|id > /tmp/x #` (and the `$()`, backtick, `&`, embedded-newline
   variants) to `POST /goform/setWAN` on an instrumented build for each of
   `wanMode` 2, 3 and 6, and assert that the request is rejected with a validation
   error, that no marker file appears, and that no child shell is spawned; then
   submit `pppUserName=validuser` and assert the legitimate path still stores the
   username, so the fix cannot be satisfied by silently disabling WAN configuration
10. **Operator measures until patched firmware exists** - change the factory
    password immediately; never expose the management interface to a WAN address, a
    reverse proxy or a port forward, and turn remote management off; keep guest
    wireless clients on their own segment away from the management subnet, because
    they are the most likely starting position for an attacker who already holds a
    credential; treat any device still running 2015-era firmware as end-of-support
    and plan replacement

## References

- https://0day-rubbish.com/blog/edimax-br-6478ac-setwan-command-injection-root-rce
- https://0day-rubbish.com/blog/edimax-br-6478ac-formwlanmp-command-injection-root-rce
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
