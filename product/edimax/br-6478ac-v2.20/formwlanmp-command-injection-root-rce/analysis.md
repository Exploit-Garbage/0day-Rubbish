# Edimax BR-6478AC v2.20 - formWlanMP Manufacturing-Test Handler: Authenticated Command Injection to root Command Execution (full technical analysis)

## 1. Overview

### Overview — the finding in one paragraph

Firmware `BR6478AC_v2.20.bin` for the Edimax BR-6478AC dual-band AC1750 wireless
router ships a management HTTP server, `bin/webs`, whose registered form handlers
include a factory radio-calibration endpoint that should never have survived into a
production image. `POST /goform/formWlanMP` reaches the handler `formWlanMP` at
`0x462a24`, which reads thirty automatic-test-equipment (ATE) and EEPROM fields
straight out of the request body and concatenates all of them, unmodified, into one
command line with `sprintf` at `0x462fd0`, then passes that line to `system()` at
`0x46308c`. Nothing between the request and the shell inspects a single character:
there is no numeric coercion, no allowlist, no character filter, no quoting and no
argv-style execution. Because `system()` re-parses its argument through
`/bin/sh -c`, a field value of `$(id > /tmp/marker)` is evaluated by the shell
before the calibration script named in the format string is ever resolved. The
process is root - the shipped `etc/boa/boa.conf` declares `User root` - so the
landing identity is `uid=0(root)`. The handler sits behind the product's single
HTTP Basic realm, which after device setup covers every `/goform/` path, so an
attacker needs one valid administrative credential; that credential is *not* the
factory password for the purposes of this rating, and the factory password is
reported separately. Unlike the neighbouring manufacturing handler on this device,
this route carries no post-boot uptime window, so it is reachable any time the
device is up.

### Overview — the product and the firmware artefact

- Product: Edimax BR-6478AC, a dual-band AC1750 SOHO wireless router with a wired
  LAN and a management interface on TCP port 80. Vendor: Edimax Technology Co.,
  Ltd., New Taipei City, Taiwan. Closed-source firmware.
- Product identity string recorded in the material analysed: `BR-6478AC_v2.20`.
- Firmware image: `BR6478AC_v2.20.bin`, containing a SquashFS root filesystem of
  roughly 2.3 MB.
- Target architecture recovered from the binaries: MIPS 32-bit big-endian, MIPS-I
  instruction set, uClibc C library, all binaries stripped, internal build
  timestamp from 2015.
- Management server binary: `bin/webs`, ELF 32-bit MSB MIPS, 762904 bytes, SHA256
  `ec39c0f9332361e37ab92f1999ac5f00f5742dd6db75f7cb26c0652cfedb32a1`. Every
  address cited in this document is an address in that binary, so a reader holding
  the same image can reproduce each step with any MIPS-capable disassembler.
- The `webs` binary is a GoAhead-lineage embedded HTTP server that also parses the
  boa configuration file; the device therefore presents one listener on port 80
  with two configuration vocabularies, and the `/goform/` dispatcher is the part
  that matters here.

### Overview — the runtime stack on the device

The root filesystem carries four HTTP-capable components plus several ordinary
daemons. `bin/webs` serves the management interface: static content, `.asp` pages
bound as CGI through `AddType application/x-httpd-cgi asp` in `etc/boa/boa.conf`,
and the `/goform/` form handlers registered at run time by `websFormDefine`. A
second lightweight server, `axhttpd`, is started only during the setup wizard
(`iQsetup_set()` invokes it as `axhttpd -w /tmp/www &` from `scriptlib.sh:1184`)
and serves only generated static pages. A UPnP Internet-Gateway-Device daemon
(`miniigd`, derived from miniupnpd) listens on port 52869 and exposes SOAP
actions. An outbound cloud-connect daemon maintains a session to the vendor's
cloud service and opens no inbound listener. `webs` is kept alive by the boot path
`cleanlog.sh:131`, called from `init.sh:1115`, and writes `/var/run/webs.pid`.

### Overview — what evidence class each claim in this document rests on

This analysis separates three evidence classes explicitly, because the difference
drives the score and drives what we assert about impact.

1. **Artefact evidence, from the shipped firmware image**: the configuration files
   (`etc/boa/boa.conf` with `Auth / /etc/boa/boa.passwd`, `User root`,
   `AddType application/x-httpd-cgi asp`), the root filesystem layout (including
   the presence of `rftest.sh` and the absence of `rftest_old.sh`), the boot and
   firewall scripts (`init.sh`, `cleanlog.sh`, `firewall.sh`), the shipped password
   file, and every instruction and string address in `bin/webs`. Everything in
   sections 3 to 7 is of this class.
2. **Dynamic evidence, from replication of the sink**: the exact command line that
   `sprintf` produces was reconstructed and handed to `/bin/sh -c` in an isolated
   POSIX sandbox, once as root and once under an ordinary user account on a
   workstation, together with benign control runs. This is section 9. It proves
   what `system()` does with the injected string; it does not prove that a physical
   device accepted an HTTP request from us, because none did.
3. **Reasoned inference, labelled as such**: the on-device landing identity
   (`uid=0(root)`) follows from the shipped `User root` directive plus the
   root-identity replication; the unauthenticated setup-state branch follows from
   reading `auth_authorize` and was never exercised; the conditional readings that
   depend on a deployment state follow from those two. Each is marked where it
   appears.

### Overview — independence and the companion finding

Two independent command-injection sinks were found in this firmware and are
published as two advisories for the same product, because a fix to one does not
fix the other. This document covers `formWlanMP`. Its companion covers the
WAN-configuration handler `setWAN` at `0x441cec`, which reaches
`sprintf(buf2, "echo %s > /tmp/UserName", buf)` at `0x441ee8` and `system(buf2)`
at `0x441f1c` through `POST /goform/setWAN`. The two differ in handler, in format
string, in sink address and in sanitiser: `formWlanMP` applies none at all, while
`setWAN` scans for a single character, `;` (immediate `0x3b`), and truncates there - a filter that a payload containing `|`
and a trailing `#` defeats completely.
They share only the architectural root cause: a management server that builds shell
command lines by string interpolation. Neither finding is a variant of the other,
and the vendor's engineers should not expect one patch point to close both.

We also examined prior public advisories for this product family. We found no
published advisory whose root cause is command injection in the `formWlanMP`
manufacturing handler of the BR-6478AC, and we therefore treat this as previously
undisclosed. We deliberately do not list adjacent Edimax identifiers here, beyond
noting that published records for other Edimax models concern different handlers
on different firmware lines; an identifier that names a neighbouring product is not
evidence about this one.

### Overview — affected scope

Only firmware `BR6478AC_v2.20.bin` was examined. The handler is registered
unconditionally in that image, so every device running it carries the route. We
did not test other firmware builds for this product, the separately marketed
BR-6478AC V2 hardware revision (whose firmware line, for example
`BR6478ACV2_v1.23`, is a different little-endian MIPS-II build of `webs`), or any
other Edimax model, and we make no claim about them. Because the registration
table and the calibration scripts are part of a vendor-common software base, other
models built from the same base may well carry the same handler; that is a question
for the vendor's firmware build system, not a claim we have substantiated.

## 2. Vulnerability Summary

### Vulnerability Summary — one table

| Item | Value |
|---|---|
| Product | Edimax BR-6478AC (identity string `BR-6478AC_v2.20`) |
| Firmware image | `BR6478AC_v2.20.bin` (SquashFS rootfs, roughly 2.3 MB) |
| Vulnerable binary | `bin/webs`, ELF 32-bit MSB MIPS, 762904 bytes, SHA256 `ec39c0f9332361e37ab92f1999ac5f00f5742dd6db75f7cb26c0652cfedb32a1` |
| Route | `POST /goform/formWlanMP` |
| Handler | `formWlanMP` at `0x462a24`, registered by `websFormDefine("formWlanMP", ...)` at `0x477a1c` |
| Tainted fields | 30 ATE / EEPROM form fields read by `websGetVar` (`0x412a7c`, FP slot `0x4c6b18`) |
| Sink construction | `sprintf(buf, "/bin/rftest_old.sh %s ...", <30 raw strings>)` at `0x462fd0`, format string at `0x4a0d98` |
| Sink call | `system(buf)` at `0x46308c` (`system` PLT stub at `0x490020`, relocation `0x18b`) |
| Sanitisation on the path | none |
| Authentication | HTTP Basic, single `/` realm, required in normal operation |
| Execution identity | `webs` running as root (`User root` in `etc/boa/boa.conf`); landing identity `uid=0(root)` |
| Uptime gate | not applicable - the route is not one of the four gated paths |
| Class | CWE-78 OS command injection |
| Published score | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 High |

### Vulnerability Summary — mechanics, step by step

1. An authenticated client submits `POST /goform/formWlanMP` with a URL-encoded
   body containing the ATE fields. The `Content-Type` is
   `application/x-www-form-urlencoded`, which is what the product's own
   `wlan_mp.asp` page uses.
2. `process_header_end` at `0x40c4d4` runs the access gate `auth_authorize`
   (`0x404d00`). In normal operation the gate resolves the request path against the
   security store at `0x4c7004`, whose only entry is `/` with type `Basic`, and
   issues a `401` challenge unless a valid credential arrives.
3. `handleForm` at `0x412440` looks up the registered name `formWlanMP` and calls
   the handler at `0x462a24`.
4. The handler calls `websGetVar` thirty times, once per field. `websGetVar`
   returns the decoded value; it strips a trailing carriage return or line feed and
   performs no other transformation. The handler replaces an empty result with the
   literal word `null`.
5. `sprintf` at `0x462fd0` formats the constant prefix `/bin/rftest_old.sh ` (the
   format string lives at `0x4a0d98`) followed by thirty `%s` conversions, and
   appends each raw field value in order.
6. `system(buf)` at `0x46308c` executes the resulting line. `system()` spawns
   `/bin/sh -c <line>`, so the shell parses the whole thing: it performs command
   substitution, honours pipes and separates statements before it attempts to run
   `/bin/rftest_old.sh` at all.
7. The shell child inherits the identity of `webs`, which is root. Whatever the
   attacker substituted executes as root, writes files as root, and can open
   sockets, modify flash-backed configuration or kill processes.
8. The named script `/bin/rftest_old.sh` does not exist in this root filesystem
   (the image ships `rftest.sh`), so the shell reports command-not-found and
   exits 127 - after the injected command has already run. This is cosmetic.

### Vulnerability Summary — preconditions

- The device must be up and past its setup wizard, with the management interface
  reachable from the attacker's position. In the shipped firewall posture
  (`firewall.sh:187` sets `iptables -P INPUT DROP`, `firewall.sh:180` drops
  WAN-originated `SYN`, `firewall.sh:189` accepts non-WAN input) that means a host
  on the device's LAN or Wi-Fi segment unless the operator has enabled remote
  management or a port forward.
- The attacker must hold a valid credential for the single HTTP Basic realm. This
  is the privilege requirement the score reflects (`PR:H`). Any credential that the
  realm accepts is sufficient; we do not rely on the factory password, which is
  reported as a separate weakness and drives only the labelled conditional reading.
- No other precondition: no particular WAN mode, no radio state, no uptime window,
  no reboot, no user interaction, no memory-layout knowledge.

### Vulnerability Summary — why the root cause is a design choice, not a typo

A single missing `strchr` call would be a typo. This is not that. The handler's
design is to accept thirty free-form strings from an HTTP request and paste them
into a shell command line as though they were command-line arguments typed by a
factory operator. That design is only safe if the caller is trusted, which is true
on a calibration bench connected by serial cable and false on a TCP port that
serves browsers. Two structural facts make it worse: the server process has root,
so there is no privilege floor to fall to; and the same pattern is not unique to
this handler, since our count of the shipped registration table found 91
`/goform/form*` handlers of which roughly 85 reach a `system()` or `popen()` call.
The fix that matters is therefore architectural - remove the manufacturing surface
from production builds and stop interpolating request data into shell strings -
even though the minimal fix is a validator in this one function.

## 3. Authentication Boundary

### Authentication Boundary — the gate function

The gate is `auth_authorize` at `0x404d00`, called from `process_header_end` at
`0x40c4d4` for every request the `/goform/` dispatcher will handle. Its logic,
read from the disassembly rather than from a decompiler rendering (the decompiler
inverts one of the branches, so the instruction order is the ground truth):

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

The security store is populated at run time from the configuration file: the `Auth`
directive handler at `0x40814c` calls the function pointer in the global-offset
slot `0x4c6cd4`, which resolves to `auth_add` at `0x40549c`, as
`auth_add(url, password_file, "Basic")`. The shipped `etc/boa/boa.conf` contains
exactly one `Auth` directive - `Auth / /etc/boa/boa.passwd` - so the finished store
has exactly one entry: prefix `/`, type `Basic`, password file
`/etc/boa/boa.passwd`. A prefix entry of `/` matches every request path on the
listener, which is how the realm comes to cover all of `/goform/`.

### Authentication Boundary — what the configuration flag means, and how that was established

MIB object `0x1bc` is read through `apmib_get` and decides which of the branches
above runs. Its meaning is not printed anywhere in the binary, so three independent
shipped artefacts were used to pin it down, and all three agree on the same
reading: value `0` is the setup wizard, value `1` is normal operation.

1. `formwizResetDefault` at `0x44cdbc` calls
   `/bin/scriptlib_util.sh flashDefault`, then `reboot.sh 2 &`, then resets the
   configuration store, and displays the string `Resettowizard` through
   `showText`. A factory-default restore therefore drives the flag to `0`, and the
   product's own text calls that state "wizard".
2. When the flag is `0`, a request for `/generate_204` is answered `204 No Content`
   by the gate itself. `/generate_204` is the connectivity probe a captive portal
   answers; a configured management interface would not answer it at all. That is
   first-run behaviour.
3. `formWizSetup` assigns `_obj.wizardEnabled = atoi(websGetVar(wp, "wizEnabled", ""))`
   and prints `NO - LOGIN-WEB` when the value is `1` - the product's own wording
   for "authentication is now active". Management pages read the same flag to switch
   their interface, for example `web/inter_wan.asp:214` and
   `web/admin_timezone.asp:95` both render
   `var wizardEnabled = <%getVar("wizardEnabled","","");%>;`, and
   `setup_3wizard_2.asp` posts its "reset to defaults" control to
   `/goform/formwizResetDefault`.

This matters directly to the rating. The instruction-level reading above was
arrived at after an earlier pass reached the opposite conclusion: that pass treated
"flag `0` means the wizard has finished" and therefore read block B as an
unauthenticated *post-setup* path, which would have made this finding an
unauthenticated root RCE. The three artefacts just listed refute that reading, so
the finding is rated `PR:H` and the flag-`0` branch is documented in section 12 as
a labelled conditional inference about a transient setup state, not as the
headline. We also note for completeness that the authentication model of other
Edimax models is irrelevant here: the neighbouring BR6478GN uses the GoAhead 2.1.8
user-management API (`umAddAccessLimit`), a different mechanism whose behaviour
cannot be transferred to a build that parses boa directives into a security store.

### Authentication Boundary — the realm and its single principal

The realm is defined by `/etc/boa/boa.passwd` in the read-only root filesystem.
Three consequences follow, and each of them constrains the score.

- One realm, one prefix, one type. There is no second security-store entry, and
  the alternative type string `None` (stored at `0x49070c`) is referenced only by
  the gate's comparison, never passed to `auth_add`; no configuration directive in
  the shipped file produces a `None` entry.
- No per-user access control. The `Allow` directive handler at `0x407688` is a
  non-functional stub whose body prints "This version of Boa doesn't support
  access controls. Please recompile with --enable-access-control.", and the shipped
  `boa.conf` contains a single `Auth` directive and no `Allow` directive, and our
  reading of that configuration found no per-user or per-group access restriction
  that would create a low-privileged class of authenticated caller.
- One credential. The password file is the product's single credential store, and
  the management interface's own form surface (including its password-change form)
  operates on that one account. There is no read-only or operator role.

Any caller who presents a credential this realm accepts is, by construction, the
device administrator. That is precisely the situation CVSS 3.1 describes as
`PR:H`: privileges that provide significant control over the vulnerable
component's configuration. Section 12 works the arithmetic for both readings.

### Authentication Boundary — why this route is not uptime-gated

Four routes in this firmware carry a 600-second post-boot gate: `/mp.asp`,
`/goform/mp`, `/advanced_management.asp` and `/goform/formAdvManagement`. For
those, the handler reads `/proc/uptime` and redirects to `/index.asp` once the
device has been running longer than 600 seconds, which confines them to a
ten-minute window after every boot. `/goform/formWlanMP` is not in that set. Its
handler contains no uptime read and no redirect, so an authenticated caller can
reach it at any time while the device is up - including months after boot, and
including after any reconfiguration that leaves the credential alone. The
neighbouring manufacturing route `/goform/mp` is therefore *not* what this
advisory describes, even though the two look alike: `/goform/mp` (handler at
`0x448e9c`) reads a `command` field, truncates it at the first `;` through a
`strchr` call at `0x448fe8`, formats
`sprintf(buf, "/bin/rftest.sh %s > /tmp/rftest.out", command)` at `0x449108` and
calls `system(buf)` at `0x44911c`. It is also exploitable in principle, but the
boot window and its factory-test character put it outside what we publish here; we
mention it so the vendor sees it in the same fix pass.

### Authentication Boundary — the branch we do not treat as a supported path

When the setup-wizard flag reads `0`, block B of the gate returns success with no
challenge for any path except `/mp.asp`, `/index.asp` and `/`. In that state a
client needs no credential at all to reach `/goform/formWlanMP`. We are not
rating the product on that state and we are not claiming an unauthenticated
exploit, for three reasons: the state is the install wizard, which is transient
and ends when setup completes; we never exercised it; and treating a first-run
provisioning path as an unauthenticated remote-code-execution primitive would
inflate a finding that is already severe enough at `PR:H`. It is published as a
conditional reading in section 12 with its arithmetic, and it is an important
operator fact - a device that has been reset to defaults and left unconfigured is
exposed in a way a configured device is not.

### Authentication Boundary — what is deliberately not claimed

- No authentication bypass is claimed. The gate is a hard `401` challenge in the
  normal-operation state, the password file is a real digest store, and we found no
  path that makes the gate accept a request without a valid credential.
- No CSRF is claimed either way. We did not establish whether the management
  interface issues a same-site token alongside Basic authentication; an attacker who
  can get the target administrator's browser to submit this form would not need a
  credential of their own, and we flag that to the vendor as unexamined surface
  rather than as a finding.
- No session or cookie mechanism is claimed: the gate is per-request Basic
  authentication, which means a client that caches the credential resends it on
  every request, and there is no logout primitive that would invalidate it
  server-side.

## 4. Attack Surface

### Attack Surface — listeners and who owns what

| Listener | Owner | Reach | Role in this finding |
|---|---|---|---|
| TCP port 80 | `bin/webs` (boa configuration shared) | LAN / Wi-Fi by default; WAN only if the operator enables remote management or forwards the port | the vulnerable surface |
| TCP port 52869 | `miniigd` (UPnP IGD, miniupnpd-derived) | LAN only, because the shipped firewall policy drops WAN-originated input | examined, not part of this finding |
| axhttpd port | second helper HTTP server, started by `iQsetup_set()` via `scriptlib.sh:1184` | setup state only | examined, not part of this finding |
| outbound cloud session | cloud-connect daemon to the vendor's cloud service | egress only, no inbound listener | excluded |
| SSH / DHCP / DNS daemons | standard third-party daemons | - | out of scope for this analysis |

The default firewall posture is worth stating precisely because it bounds the
network metric. From the shipped `firewall.sh`: `firewall.sh:187` installs
`iptables -P INPUT DROP`, `firewall.sh:180` installs a rule dropping `SYN` packets
arriving on the WAN interface, and `firewall.sh:189` accepts input arriving on any
other interface. A stock device is therefore not answering new connections from
its WAN side, while everything behind it - wired clients, associated wireless
clients, and anything bridged onto that segment - can reach port 80. That posture
is incidental to a firewall script rather than an explicit product statement about
management-plane exposure, which is why section 12 publishes `AV:N` as the headline
with `AV:A` as a labelled alternative rather than the reverse of the Abyss-style
treatment where a shipped allowlist decides the metric.

### Attack Surface — the /goform/ handler population

Counting registrations in the shipped `webs` binary gives 91 `/goform/form*`
handlers plus 31 ASP handlers, for well over 100 distinct HTTP endpoints on the
management interface, of which roughly 85 handlers reach a `system()` or `popen()`
call. The handlers divide usefully into three groups. Configuration setters write
into the configuration store and, as a side effect of applying the configuration,
invoke helper scripts - most are not directly controllable because the interpolated
values come from the store or from the device's own interfaces rather than from the
request. Diagnostic handlers interpolate request data into shell commands, and
these are the interesting class: `formWlanMP` is one, `setWAN` (the companion
advisory) is another, and `/goform/mp` is a third that we excluded on its boot
window. Manufacturing handlers exist for factory calibration and should not be
registered at all in a production image; `formWlanMP` is exactly such a handler,
and `wlan_mp.asp` is the page that posts to it.

### Attack Surface — routes that bypass the realm, and why none of them matters here

Three request paths are exempt from the gate's challenge: `/upnp/APDesc.xml`,
`/wpad.dat` and `/file/*`. All three serve static content - a UPnP device
description, a proxy auto-configuration file, and files from `web/file/` such as
`APP.gif`, `jquery.js` and `set.css`. None of them reaches a `system()` or
`popen()` call and none of them runs a CGI or a form handler, so they widen the
information available to an unauthenticated caller but they do not provide an
execution primitive. They were enumerated precisely so that the reachability
question - "is the unauthenticated surface really empty of executable sinks?" -
could be answered with a list rather than an assertion.

The one genuinely unauthenticated execution primitive we found is in `miniigd`,
not in the management interface: its `AddPortMapping` SOAP action is handled
without authentication (as UPnP specifies), and the vendor's handler interpolates
`NewInternalClient` into `sprintf(acStack_f8, "echo \"%s,...\" >> /tmp/upnp_info", ...)`
before calling `system()`. It is excluded from this advisory because port 52869 is
only reachable from the LAN under the shipped firewall policy - the daemon binds
every interface (`INADDR_ANY` at `main` `0x4040b0`), but WAN-side input is
dropped. It is reported to the vendor here as a real, separately exploitable
weakness on the LAN side, since a guest wireless client reaches it.

### Attack Surface — surfaces examined and excluded

- `formrefresh` (a network-neighbourhood refresh): its interpolated value is the
  device's own bridge address, obtained from the interface and converted with
  `inet_ntoa`, not request data. Dead end.
- `formAutoFWupgrade` (firmware upgrade over TFTP): the arguments come from the
  configuration store and from a fixed vendor host name rather than from the
  request directly. Weak, and not published.
- `formPreventionSetup` (denial-of-service prevention settings): a configuration
  setter with no direct command interpolation of request data.
- `edx_cloud`: outbound only.
- `wscd`, the Wi-Fi protected-setup registrar: its `system()` calls interpolate a
  fixed interface name (`wlan0` / `wlan1`) into a fixed `iwpriv` command, not
  network input.

### Attack Surface — how the surface was mapped

The mapping was done against the shipped image, not against a running device:
extract the SquashFS root filesystem; enumerate the configuration files
(`etc/boa/boa.conf`, the boot scripts, the firewall script); enumerate the
registration table in `bin/webs` by locating `websFormDefine` call sites and
reading their string arguments; enumerate the ASP handler table the same way; and
for each registered name, disassemble the handler and follow its data to any
`system()`, `popen()` or `execve` call, checking every intermediate function for
validation. Where the disassembly and the decompiler disagreed - notably in
`auth_authorize`, where the decompiler inverts the `/generate_204` branch - the
instruction stream was treated as ground truth.

## 5. Sink Identification

### Sink Identification — finding the sink

The sink was found by enumerating every call site of `system` in the binary and
walking backwards to the arguments. The `system` PLT stub sits at `0x490020` and
is bound by relocation `0x18b`, so the call at `0x46308c` resolves to the real
libc `system` rather than to a wrapper. Its single argument is a stack buffer
filled immediately before by the `sprintf` at `0x462fd0`, whose format string at
`0x4a0d98` is `/bin/rftest_old.sh ` followed by thirty `%s` conversions. Each of
those thirty conversions is fed by the return value of a `websGetVar` call earlier
in the same function, with no intervening function other than the empty-to-`null`
substitution. That is the whole story of the sink: thirty unvalidated request
values, one constant prefix, one shell.

### Sink Identification — the sink construction, instruction by instruction

```
formWlanMP                      @ 0x462a24   handler entry
  websGetVar(wp, "ateFunc", "")  x30 fields   via FP slot 0x4c6b18 -> 0x412a7c
  (empty -> "null")                            alignment filler, not filtering
  sprintf(buf, fmt, f1..f30)     @ 0x462fd0   fmt = "/bin/rftest_old.sh %s ... "
                                              fmt string @ 0x4a0d98
  system(buf)                    @ 0x46308c   -> PLT 0x490020 (reloc 0x18b)
                                              -> /bin/sh -c <buf>
```

No validation function appears anywhere between the first `websGetVar` and the
`system` call. The comparison that makes this stark is inside the same firmware:
the `setWAN` handler at least scans for one character before interpolating
(`0x3b`, the semicolon), and `/goform/mp` calls `strchr` at `0x448fe8` and
truncates. `formWlanMP` does neither. Whatever the request body carried arrives in
the shell's input buffer byte for byte, subject only to URL decoding performed by
the request parser.

### Sink Identification — the format string and its thirty conversions

The format string at `0x4a0d98` is a constant: the literal script path
`/bin/rftest_old.sh` followed by thirty space-separated `%s` conversions. There
are no field-width or precision specifiers, so there is no length defence either,
and no quoting characters around any conversion - not a single `"` or `'` in the
format string, which is the property that would have made even a partial blacklist
survivable. The thirty conversions consume, in order, the values of `ateFunc`,
`ateGain`, `ateTxCount`, `ateChan`, `ateRate`, `ateMacID`, `e2pTxPower1` through
`e2pTxPower7`, `e2pTx2Power1` through `e2pTx2Power7`, `ateTxFreqOffset`,
`ateMode`, `ateBW`, `ateAntenna`, `e2pTxFreqOffset`, `e2pTxPwDeltaB`,
`e2pTxPwDeltaG`, `e2pTxPwDeltaMix`, `e2pTxPwDeltaN` and `readE2P`. The handler
also reads a `submit-url` field, which identifies the page that posted the form
and is not interpolated into the command line.

### Sink Identification — execution identity of the process that calls system

The process is `webs`, and it is root. Three pieces of shipped evidence:
`etc/boa/boa.conf` declares `User root`, which is the directive that would
otherwise drop privileges; the boot path that starts the server
(`cleanlog.sh:131`, invoked from `init.sh:1115`) runs during early init as root;
and the server writes `/var/run/webs.pid`, a location that requires root to create
on this root filesystem. There is no privilege-separation step, no `setuid` to an
unprivileged account before serving requests, and no chroot or namespace. Whatever
`system()` spawns is root, which is why the impact metrics are all High without any
privilege-escalation step appearing in the chain.

### Sink Identification — sibling sinks in the same handler family, and whether they are proven

| Sink | Address | Interpolated value | Sanitisation | Published here |
|---|---|---|---|---|
| `formWlanMP` | `sprintf` `0x462fd0` / `system` `0x46308c` | 30 ATE fields, raw | none | yes - this advisory |
| `setWAN` | `sprintf` `0x441ee8` / `system` `0x441f1c` | `pppUserName` (and two isomorphic fields) | inline scan for `;` only | companion advisory |
| `mp` | `sprintf` `0x449108` / `system` `0x44911c` | `command` | `strchr` at `0x448fe8`, truncates at `;` | no - 600-second boot gate and factory-test character |
| `miniigd` `AddPortMapping` | `sprintf` into `/tmp/upnp_info` / `system` | `NewInternalClient`, unauthenticated | none | no - LAN-only reach under the shipped firewall policy |

Each of the four was identified from the shipped binary. The first two are proven
at the sink by replication and are published; the third and fourth are reported to
the vendor as observations with their limiting conditions stated, and neither
carries a score in this advisory. That distinction is deliberate: an observation
about a gated or LAN-only path is not the same claim as a rated vulnerability.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The source is the URL-encoded body of `POST /goform/formWlanMP`. The product's own
management page `wlan_mp.asp` submits this form, so the request shape is ordinary
for the device: `Content-Type: application/x-www-form-urlencoded` with one
name-value pair per ATE field plus a `submit-url` field naming
`/wlan_mp.asp`. Because the transport is a POST body and not a query string, the
payload is not written into web-server access logs in most embedded
configurations, which reduces the forensic footprint of an exploitation attempt.
Nothing about the request needs to imitate a browser: the gate is per-request Basic
authentication with no session cookie, no referer check, no custom header
requirement and no CSRF token that we found, so a single `curl` invocation with a
credential can drive it.

### Source Identification — what websGetVar does and does not do

`websGetVar` is reached through the function-pointer table entry at `0x4c6b18`,
resolving to `0x412a7c`. Its behaviour, read from the disassembly: decode the
URL-encoded value for the named field out of the request's form-variable table and
return a pointer to it; strip a trailing carriage return and/or line feed if
present; return the supplied default (here, an empty string) when the field is
absent. It performs no character filtering and no length clamping beyond what the
parser already did. This is the same accessor every handler in the binary uses, so
its behaviour is the reason a per-field validation step cannot be assumed to exist
anywhere in the product.

### Source Identification — the empty-to-null substitution

The only transformation `formWlanMP` applies is a substitution: an empty field
value is replaced with the literal four-character string `null`. Reading the
disassembly, this is argument-position filler - it keeps the thirty `%s`
conversions aligned with the ATE script's expected argument count when a
calibration page omits fields. It is explicitly not sanitisation, and it is worth
naming because a reviewer skimming the decompilation could mistake it for one: the
string `null` contains no shell metacharacter, but the substitution does not
inspect what it replaces. A field carrying `$(id)` is not empty, so the
substitution leaves it exactly as it arrived.

### Source Identification — the thirty field names

```
ateFunc          ateGain          ateTxCount       ateChan
ateRate          ateMacID         e2pTxPower1..7   e2pTx2Power1..7
ateTxFreqOffset  ateMode          ateBW            ateAntenna
e2pTxFreqOffset  e2pTxPwDeltaB    e2pTxPwDeltaG    e2pTxPwDeltaMix
e2pTxPwDeltaN    readE2P                          (+ submit-url, not interpolated)
```

Every one of these names is an ATE or EEPROM parameter: transmit function selector,
gain, packet count, channel, rate index, MAC index, per-channel transmit power for
two chains, transmit frequency offset, bandwidth and antenna selectors, per-band
power deltas, and an EEPROM read flag. Every one has a narrow, machine-checkable
domain - most are small integers, one is a two-character mode token, one is a
boolean. The absence of any numeric parsing on fields whose entire legitimate value
space is numeric is what makes the missing validation a defect rather than a design
intention: there is no legitimate request in which `ateChan` contains a dollar
sign.

### Source Identification — validation that is absent

Enumerated explicitly, because "no sanitisation" is a claim a vendor's engineers
will want to check against their own source:

- No numeric coercion (`atoi`, `strtol`, `strtoul`) on any of the thirty fields,
  although the calibration script expects numbers.
- No address or pattern validation (`inet_aton`, `inet_pton`, regular expressions).
- No character filtering of any kind - no `strchr`, `strcspn`, `strpbrk`, no
  inline byte loop, no deny list, no allow list.
- No length validation beyond the destination buffer's capacity, and the format
  string carries no width or precision specifiers that would have clamped it.
- No shell quoting: neither single quotes nor double quotes appear around any
  conversion in the format string, and no escaping pass runs over the values.
- No switch to an argv-style execution primitive (`execve`, `execv`,
  `posix_spawn`), which is the only structural fix.
- No request-level checks that would make the route harder to drive: no referer
  validation, no session token, no rate limit on the handler.

## 7. Data Flow

### Data Flow — end to end

```
attacker (LAN / Wi-Fi, holds one valid Basic credential)
  |  POST /goform/formWlanMP
  |  Content-Type: application/x-www-form-urlencoded
  |  Authorization: Basic <credential>
  |  body: ateFunc=$(id > /tmp/marker)&ateGain=&ateTxCount=&... (30 fields)
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
handleForm                    @ 0x412440   (looks up "formWlanMP")
  v
formWlanMP                    @ 0x462a24
  websGetVar x 30             @ 0x412a7c   (FP slot 0x4c6b18)
  empty -> "null"                          (alignment filler only)
  v
sprintf(buf, fmt, f1..f30)    @ 0x462fd0   fmt @ 0x4a0d98
  buf = "/bin/rftest_old.sh $(id > /tmp/marker) null null ... " (30 args)
  v
system(buf)                   @ 0x46308c   PLT 0x490020, reloc 0x18b
  v
/bin/sh -c "/bin/rftest_old.sh $(id > /tmp/marker) null null ..."
  shell evaluates $(id > /tmp/marker) FIRST -> id runs as root, writes marker
  shell then resolves /bin/rftest_old.sh -> absent from this rootfs -> status 127
  v
marker file: 39 bytes, owner root:root, "uid=0(root) gid=0(root) groups=0(root)"
```

### Data Flow — the request, verbatim

```
POST /goform/formWlanMP HTTP/1.1
Host: <target>
Authorization: Basic YWRtaW46MTIzNA==
Content-Type: application/x-www-form-urlencoded
Content-Length: <length>
Connection: close

ateFunc=$(id>/tmp/marker)&ateGain=&ateTxCount=&ateChan=&ateRate=&ateMacID=&
e2pTxPower1=&e2pTxPower2=&e2pTxPower3=&e2pTxPower4=&e2pTxPower5=&e2pTxPower6=&
e2pTxPower7=&e2pTx2Power1=&e2pTx2Power2=&e2pTx2Power3=&e2pTx2Power4=&
e2pTx2Power5=&e2pTx2Power6=&e2pTx2Power7=&ateTxFreqOffset=&ateMode=&ateBW=&
ateAntenna=&e2pTxFreqOffset=&e2pTxPwDeltaB=&e2pTxPwDeltaG=&e2pTxPwDeltaMix=&
e2pTxPwDeltaN=&readE2P=&submit-url=/wlan_mp.asp
```

The body is shown line-wrapped for reading only; it is transmitted as one
URL-encoded string, with `(`, `)`, `$`, `>` and `/` percent-encoded as required by
the sender. The credential line uses the factory password so that the request
shape is self-documenting; the injection does not depend on it, and the PoC in this
directory takes `--username` and `--password` so that a tester uses a credential
they are authorised to use.

### Data Flow — shell grammar that makes the payload work

`system()` is not an exec of the named program; it is `fork` plus
`execl("/bin/sh", "sh", "-c", string, NULL)`. Everything in the shell grammar is
therefore available to the payload, and no quoting exists to escape out of:

- **Command substitution `$(...)`**: evaluated during expansion, before the simple
  command is looked up. This is the payload used here and in the PoC, because its
  output becomes an argument and the substitution runs regardless of what the
  command word resolves to.
- **Backticks**: equivalent to `$(...)`, and equally unfiltered.
- **`;`**: terminates the current command and starts another, so
  `ateFunc=;id>/tmp/marker;#` also works, with the trailing `#` commenting out the
  remaining twenty-nine `null` arguments.
- **`|` and `&`**: turn the line into a pipeline or a backgrounded job; a trailing
  `#` neutralises the rest of the format string, which is the technique the
  companion `setWAN` advisory relies on because that handler blacklists `;`.
- **Newline**: an embedded newline is a command separator in the shell grammar and
  is not stripped by `websGetVar`, which removes only a trailing one.

The practical consequence for a vendor reviewing this: any deny-list approach is
doomed here, because the payload space is the entire shell grammar and the
interpolation is unquoted. Only removing the interpolation or removing the shell
helps.

### Data Flow — why the missing script does not save the device

The root filesystem ships `rftest.sh` but not `rftest_old.sh`, so the command word
in the constructed line does not resolve. This is a common misreading worth
addressing head-on, because it looks like a mitigation. It is not one, for the
reason above: `/bin/sh -c` performs expansion before execution, so `$(...)` in any
argument position has already run by the time the shell tries `execvp` on
`/bin/rftest_old.sh` and reports status 127. Our root-identity replication produced
exactly that status alongside a correctly written marker file. A vendor that
believes the missing script closes the hole should test it with the shipped image:
substitute any of the thirty arguments and observe that the injected command's
effect precedes the shell's failure.

### Data Flow — properties of the chain worth naming

- Single request, single response. There is no multi-stage state to establish.
- The sink is reached on every submission of the form, not on a rare error path.
  The handler's normal job is to run the calibration script; the attacker only
  supplies arguments.
- Output is blind by default. The shell's stdout goes to the server process's
  output, not into the HTTP response, so results must be read back through a file,
  a second request, a serial console or an out-of-band channel of the attacker's
  choosing.
- No cleanup is left behind by the injection itself: a marker file in `/tmp` is
  volatile on a router, since `/tmp` is a tmpfs and does not survive a reboot.
- Persistence is nevertheless one command away: root on the device can write to
  the flash-backed configuration area and to init-time scripts.

## 8. Exploit Construction

### Exploit Construction — step sequence

1. **Confirm the credential.** Send any authenticated request; a `401` with a
   `WWW-Authenticate: Basic realm=...` challenge confirms the realm, and a
   `302`/`200` on a management page confirms the credential is accepted. Nothing
   about this step is specific to the vulnerability.
2. **Confirm the route exists.** `POST /goform/formWlanMP` with all fields empty and
   a valid credential should be dispatched rather than rejected; the response is the
   management page's normal post-submission redirect. A `404` means the build under
   test does not register the handler.
3. **Choose the payload shape.** Default: `ateFunc=$(<command> > <marker> 2>&1)` so
   that both stdout and stderr land in a file the attacker can read back. Field
   choice is arbitrary - all thirty reach the same `sprintf` - and the PoC exposes
   `--field`.
4. **Build the body.** Fill the remaining twenty-nine fields with benign values or
   leave them empty; the handler substitutes `null` for empty fields, which is
   harmless filler in the argument list. Include `submit-url=/wlan_mp.asp` so the
   request is indistinguishable from the page's own submission.
5. **Send the request** with the Basic credential and a short timeout (the PoC uses
   8 seconds). The server may close the connection without a useful body; that is
   expected and is not a failure signal.
6. **Read the result back.** From a device the attacker can also drive, the marker
   can be retrieved by any second injection that cats it into a file the web
   server serves, or by a serial console or SSH session. The PoC does not attempt
   retrieval, and says so.
7. **Restore state.** The handler is a calibration tool; a successful submission
   may change radio settings stored in the configuration area. Record the device's
   wireless configuration before testing and restore it afterwards.

### Exploit Construction — payload engineering constraints

- No character filtering exists on this path, so no encoding tricks, no delimiter
  avoidance and no length juggling are needed: the shortest working payload is
  `ateFunc=$(id)` and the PoC's default adds a redirect so the result is durable.
- The payload must survive URL encoding, so `$`, `(`, `)`, `>`, spaces and `#` are
  percent-encoded. `websGetVar` returns the decoded bytes.
- The payload must not depend on the calibration script existing, which it does not:
  prefer command substitution or a leading `;` over an appended second command if
  the goal is simply to run something.
- Shell quoting in the payload is unnecessary and can be harmful: because there is
  no enclosing quote or apostrophe in the format string, the payload sits in an
  ordinary word position, so a stray quote can break the parse without adding
  anything.
- For a blind channel, a file in `/tmp` is the natural choice: it is writable by
  root, it is tmpfs so it disappears on reboot, and the device's own diagnostic
  paths read from it.

### Exploit Construction — reading the result back

Because the response body carries no shell output, this is a blind injection unless
the attacker chooses a channel. The options, in the order a tester would try them:
write to `/tmp` and read it with a second injection that copies it under the web
root or into a path served statically; exfiltrate over the network from the device
itself (an outbound connection from the router is not blocked by the WAN input
policy); or use physical access - serial console or SSH with the same credential.
The PoC in `exploit/` implements none of the exfiltration channels: it writes a
marker and reports that reading it back is the tester's job.

### Exploit Construction — what the exploit deliberately does not do

- It does not install persistence, does not modify the boot path and does not
  write to the flash configuration area.
- It does not open a callback listener, does not attempt a reverse shell and does
  not download anything.
- Its default command is `id`, which merely writes a marker; nothing destructive
  runs unless the tester passes `--cmd`.
- It refuses to contact any non-loopback target unless `--allow-remote` is given,
  and prints the raw request without sending it under `--print-request`.
- It removes the marker and scratch files it created on the local host before
  exiting.
- It does not attempt the setup-state branch of the authentication gate. That path
  would need no credential, and using it would change what this advisory claims.

## 9. Dynamic Verification

### Dynamic Verification — environment

The verification we performed is a sink-semantics replication, and it is important
to be precise about why. The firmware targets MIPS 32-bit big-endian with a uClibc
C library and a board-specific bootloader; our environment could not boot that
userspace end to end - an attempt to run the extracted binaries under the available
user-mode translator faulted with SIGBUS, and full-system emulation of the board was
not brought up. Rather than publish a static-only claim, we replicated the
operation that the vulnerability consists of. The reasoning that licenses the
replication is narrow and explicit: what is under test is not the device, it is the
question "does the shell evaluate a command substitution inside the argument list
of a command whose program word does not resolve, when that string is handed to
`/bin/sh -c`?" That question is answered by POSIX shell semantics, which are
architecture-independent, and by the exact format string and argument order read
out of the shipped binary. Everything else in the chain - request parsing, the
authentication gate, form registration, handler dispatch - is evidenced from the
firmware artefacts at instruction level, as section 5 and section 6 document.

Two runs were performed. The first, in an isolated cloud sandbox where the invoking
shell ran as root, tests the identity claim. The second, on a workstation under an
ordinary unprivileged user account, tests that the semantics do not depend on the
invoking identity. Neither run involved the product.

### Dynamic Verification — what was run

The command string handed to `/bin/sh -c` is byte-for-byte what `sprintf` produces
at `0x462fd0` given a request whose `ateFunc` field is `$(id > /tmp/marker_fwmp)`
and whose other twenty-nine fields are empty (hence `null`):

```
rm -f /tmp/marker_fwmp
/bin/sh -c '/bin/rftest_old.sh $(id>/tmp/marker_fwmp) null null null null null
  null null null null null null null null null null null null null null null
  null null null null null null null null null'
echo EXIT=$?
cat /tmp/marker_fwmp
ls -la /tmp/marker_fwmp
```

The control run repeats the same invocation with `ateFunc=11b`, a benign
two-character calibration token containing no shell metacharacter, and then checks
for the marker's absence.

### Dynamic Verification — observed output

```
=== formWlanMP injected run: $(id) ===
/bin/sh: line 1: /bin/rftest_old.sh: No such file or directory
EXIT=127
--- marker ---
uid=0(root) gid=0(root) groups=0(root)

-rw-r--r-- 1 root root 39 <redacted timestamp> /tmp/marker_fwmp
=== benign control (ateFunc=11b, no injected metacharacter) ===
EXIT=127
--- control marker (must not exist) ---
(none)
=== invoking identity of the sandbox ===
root
uid=0(root) gid=0(root) groups=0(root)
```

Read against the claim, each line matters:

- The marker was created and contains `uid=0(root) gid=0(root) groups=0(root)`,
  39 bytes, owned by `root:root` - so the substituted command executed with the
  invoking identity, which on the device is root by the `User root` directive.
- `EXIT=127` is the shell's command-not-found status for the absent
  `/bin/rftest_old.sh`, and it confirms rather than undermines the finding: the
  script never ran, yet the injection did, which is exactly the ordering claim
  (expansion precedes program lookup).
- The benign control produced no marker with the same exit status, so status 127
  and marker creation are independent facts and the harness does not emit false
  positives.
- The workstation run under an ordinary user account produced the same marker
  semantics at that account's identity, which rules out the alternative
  explanation that something about running as root caused the marker to appear.

The same replication is compiled into the PoC in this directory
(`exploit/edimax_br6478ac_formwlanmp_command_injection_root_rce.py`), which
performs the injected run and the control run on demand, asserts marker presence
with `uid=` in it and control-marker absence, and prints `RESULT: PASS` only when
both assert as expected.

### Dynamic Verification — the negative control and why it matters

A marker appearing after a run that also invokes a shell proves very little on its
own: the harness itself could have created the file, an earlier run could have
left it, or the shell could have written it while parsing something benign. Three
controls remove those explanations. The benign value `11b` runs through the
identical code path and produces no marker. The PoC removes any pre-existing marker
before each run and deletes its scratch directory afterwards. And the two
independent runs - one as root, one as an ordinary user - produced different
ownership on the marker, which is what a genuinely executed `id` would do and what
a harness artefact would not.

### Dynamic Verification — what was not run, stated plainly

- **No physical device was powered on.** We never booted `BR6478AC_v2.20.bin`, and
  we never sent an HTTP request to an Edimax product.
- **No end-to-end HTTP detonation.** The request, the authentication challenge, the
  form dispatch and the handler entry are evidenced from the shipped binary and its
  configuration, not from observed HTTP exchange. If a vendor's build-time step
  strips the `formWlanMP` registration in some field build we did not obtain, that
  build would not be vulnerable; the image we analysed registers it.
- **No radio or calibration behaviour was tested.** We make no claim about what
  `rftest.sh` does with the arguments.
- **No setup-state request was sent.** The flag-`0` branch of `auth_authorize` is a
  reading of the code, never an observation.
- **No dictionary or credential attack was attempted**, and no rate-limit
  measurement was taken beyond reading the configuration.

### Dynamic Verification — independent review of the static chain

The static chain was reviewed twice by independent passes before publication: one
re-deriving the sink from the binary without reference to the original analysis,
and one attempting to refute it - searching for a missed validation function
between `websGetVar` and `system`, for a second sanitising branch inside the
handler, for evidence that the registration is inert or that the path is not
dispatched. Both passes concluded that no sanitisation exists on the path and that
the sink is reachable from an authenticated request in the normal-operation state;
the refutation attempt returned no refuting evidence. The same two-pass review is
what caught the authentication error described in section 3: the classification of
the route was corrected from unauthenticated to authenticated, which lowered the
published score rather than raising it, and the corrected reading is what appears
in section 12.

### Dynamic Verification — boundaries of what was verified

| Claim | Evidence class | Status |
|---|---|---|
| `sprintf` fills the command line with 30 raw fields, format at `0x4a0d98` | firmware artefact, instruction level | established |
| `system(buf)` at `0x46308c` executes that line | firmware artefact, instruction level | established |
| No validation between `websGetVar` and `system` | firmware artefact, two independent review passes | established |
| The route requires Basic authentication in normal operation | firmware artefact (`auth_authorize`, security store, `boa.conf`) | established |
| The route is not uptime-gated | firmware artefact (absence of a `/proc/uptime` read in the handler) | established |
| Command substitution inside the argument list executes and precedes program lookup | dynamic replication, root and non-root | demonstrated |
| The injected command runs as root on the device | `User root` in `etc/boa/boa.conf` plus root-identity replication | inferred, strongly |
| A physical device accepts the request end to end | none | not demonstrated |
| The flag-`0` setup state is unauthenticated | firmware artefact, single reading | structural inference only |

## 10. Reachability and Security Impact

### Reachability and impact — network position

The management interface listens on TCP port 80 on the device's own addresses. The
shipped firewall script installs a default `DROP` input policy
(`firewall.sh:187`), drops WAN-originated `SYN` packets (`firewall.sh:180`) and
accepts input on other interfaces (`firewall.sh:189`), so on a stock device the
attacker's position is a host on the wired LAN or an associated wireless client.
That position is not benign in a SOHO context: it includes guest-network clients,
any compromised IoT device behind the router, anything bridged onto the segment,
and any host that reaches the LAN through a VPN or an existing misconfiguration.
Two operator actions move the position to the open internet - enabling remote
management on the WAN side, or forwarding port 80 - and both are ordinary,
documented product features rather than exotic misconfiguration. Once a credential
exists, the attack needs one packet exchange and no user interaction, and the
response does not need to be read for the injection to have already executed.

### Reachability and impact — what root on this device controls

A root shell on a SOHO router is the whole trust domain of the network behind it.
Concretely, from the configuration store and the filesystem the identity reached
here can read the administrator password file, read every stored wireless
pre-shared key and per-station key material, read PPP / PPTP / L2TP credentials
(the same configuration objects the companion `setWAN` advisory writes to as
`0x6d`, `0xf3` and `0x128`), read VPN settings and any certificate present;
rewrite firewall and NAT rules to expose or hide hosts; redirect client DNS to an
attacker-chosen resolver, which converts one compromised router into a credential
and browser-hijack primitive for every device behind it; alter DHCP to hand out a
malicious default gateway; disable or re-point the WAN uplink; and read or modify
the flash-backed configuration so that the changes survive a reboot and, in the
case of a written boot path, survive a configuration reset.

### Reachability and impact — the privilege question, answered in full

There is no privilege boundary in this chain to cross, and that is exactly why the
impact metrics are all High without any escalation step appearing in the analysis.
`webs` is started during early init and stays root because the shipped
`etc/boa/boa.conf` says `User root`; it writes `/var/run/webs.pid`; no `setuid`,
`chroot`, namespace or capability drop appears in its startup path. The shell that
`system()` spawns therefore inherits uid 0, and our replication of that shell as
root produced a marker owned by `root:root` containing
`uid=0(root) gid=0(root) groups=0(root)`. We state the on-device identity as
`uid=0(root)` on the strength of the shipped directive plus the replication; we do
not claim to have observed it on hardware, and we make no claim about any other
Edimax model's runtime identity.

### Reachability and impact — detection notes

Detection is poor by construction, and a defender should know what to look for:

- The request imitates the product's own calibration form. A
  `POST /goform/formWlanMP` with thirty ATE fields and `submit-url=/wlan_mp.asp`
  is precisely what the shipped management page sends, so the request alone is not
  anomalous; the anomaly is that a non-factory user is submitting a factory form,
  and that one field of a numeric-only form contains `$(`, a backtick, `;`, `|` or
  a newline.
- Shell diagnostics are the most reliable indicator: a `/bin/sh` reporting that
  `/bin/rftest_old.sh` does not exist is the fingerprint of this specific payload
  reaching this specific sink, because the shipped image does not contain that
  script.
- Marker files under `/tmp` disappear on reboot, so a reboot is also an
  anti-forensic measure available to the attacker.
- A new outbound connection from the router, or a change in the DNS resolver being
  handed out by DHCP, are post-exploitation indicators rather than request-level
  ones.

### Reachability and impact — repeatability and persistence

The route can be driven as often as the attacker likes: there is no rate limit on
the handler, no lockout in the Basic realm that we found, and no state consumed by
a successful submission other than whatever the calibration handler itself stores.
An attacker who reaches root has several independent persistence choices - a
modified init script, a changed boot-time configuration value, a replacement
helper script, a cron-equivalent startup entry - and none of them requires touching
the product's web interface again. Recovery for an owner who suspects compromise
is a full reflash from a trusted image plus a credential change, since a
configuration reset does not undo a written boot path.

## 11. Fix Recommendations

### Fix Recommendations — vendor side, ordered by root cause

1. **Delete the manufacturing surface from release builds.** `formWlanMP` is an
   ATE calibration handler. Compile it only into factory images, or guard the
   `websFormDefine("formWlanMP", ...)` registration at `0x477a1c` behind a
   build-time flag that release builds clear. If a field service path is genuinely
   needed, expose it on the serial console with a signed local token rather than on
   the management port.
2. **Stop interpolating request data into shell strings.** Replace the
   `sprintf`/`system` pair at `0x462fd0` / `0x46308c` with
   `execve("/bin/rftest_old.sh", argv, envp)` where each validated field becomes
   one argv element. No shell is involved, so no metacharacter means anything. Audit
   the remaining `system()` and `popen()` population in `bin/webs` - our count is
   roughly 85 handlers - and convert them the same way.
3. **Parse every ATE field to its domain.** These are small integers, indices and
   two-character tokens: use `strtol`/`strtoul` with an explicit range check, or a
   strict allowlist regular expression, and reject the request otherwise. A field
   named `ateChan` has no legitimate value containing `$`.
4. **If a shell call must stay, quote every interpolation.** Single-quote each
   argument and escape embedded single quotes, or pass values through the child's
   environment. This is a weaker fix than (2) but it is a real one, and it is cheap.
5. **Do not rely on a character deny list.** The companion `setWAN` sink scans for
   `;` alone and is trivially injectable with `|` plus a trailing `#`. Any
   blacklist over shell grammar will decay silently as payloads change.
6. **Separate privileges for the HTTP server.** `etc/boa/boa.conf` currently says
   `User root`. Bind port 80 as root and drop to a dedicated unprivileged account
   before serving, keeping elevation only inside a small audited helper. That
   converts the next injection in this family from device takeover into a contained
   incident (CWE-250).
7. **Rotate the factory credential out of the field.** Force a password change on
   first authenticated session, or provision a per-unit random password at
   manufacturing; replace MD5-crypt with a memory-hard digest; add rate limiting
   and lockout to the Basic challenge, which is a single-account realm (CWE-798).
8. **Make management-plane exposure explicit rather than incidental.** State and
   enforce that WAN-side management access is off by default, keep the shipped
   `INPUT DROP` policy as a documented product decision, and allow management from
   named source addresses only. Add role separation so that the credential which
   reaches configuration forms is not the same credential that reaches factory and
   diagnostic handlers.
9. **Add request-level logging.** Log every `/goform/` submission whose fields
   contain shell metacharacters where the field is documented as numeric, and log
   the credential name used. Today an exploitation attempt leaves no trace beyond a
   shell's stderr.

### Fix Recommendations — a regression test the vendor should add

A build-image test that fails the release if this class returns:

- Submit `ateFunc=$(id > /tmp/x)` (and the `;`, backtick, `|`,
  embedded-newline variants) to `POST /goform/formWlanMP` on an instrumented build
  and assert: the request is rejected with a validation error; no marker file
  appears anywhere in the filesystem; and no child shell is spawned (assert on the
  process table or on an instrumented `system`/`execve` hook).
- Submit `ateFunc=11b` and assert that the legitimate calibration path is still
  reached, so the fix cannot be satisfied by silently disabling the handler.
- Repeat the first case against `/goform/setWAN` with
  `pppUserName=|id > /tmp/x #`, which is the companion advisory's payload and
  would catch the deny-list regression the moment it is reintroduced.
- Assert from a fresh, unconfigured image that `/goform/formWlanMP` is either not
  registered or rejected before setup completes, so the setup-state branch cannot be
  used as an unauthenticated path.

### Fix Recommendations — operator side, until firmware exists

1. Change the factory password immediately; assume it is public.
2. Never expose the management interface to a WAN address, a reverse proxy or a
   port forward. Turn remote management off and verify it is off.
3. Place the router's management address on a dedicated management VLAN, or
   restrict access to it at the upstream firewall to named hosts.
4. Segment guest wireless clients away from the LAN management subnet; they are the
   most likely authenticated-less starting point for an attacker who already holds a
   credential elsewhere.
5. Treat any device still running a 2015-era build as end-of-support: the vendor's
   ability to ship fixes for a firmware line this old is limited, and the practical
   remediation may be replacement.
6. If compromise is suspected, reflash from a trusted image and re-enter all
   credentials - wireless, PPP and administration - because root access exposes all
   of them, and a configuration reset does not undo a written boot path.

## 12. CWE and CVSS

### CWE and CVSS — classification

| Classification | Assignment | Justification |
|---|---|---|
| Primary | **CWE-78** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | thirty raw request fields are interpolated unquoted into a string passed to `system()`, which hands it to `/bin/sh -c`; shell metacharacters are therefore commands |
| Reported separately | **CWE-798** Use of Hard-coded Credentials | the firmware image ships a populated `etc/boa/boa.passwd` for its single Basic realm and the model's published factory login is `admin:1234`. Real and serious, but not the vector rated here: the injection and the authentication requirement both exist independently of it |
| Contributing | **CWE-250** Execution with Unnecessary Privileges | the HTTP server that parses untrusted input runs as root (`User root`), so there is no privilege floor beneath any injection in this process |
| Contributing | **CWE-20** Improper Input Validation | fields whose entire legitimate domain is numeric are accepted as free text, which is the enabling defect underneath CWE-78 |
| Contributing | **CWE-1188** Insecure Default Initialization of Resource | the manufacturing handler is registered by default in a production image, and the default firewall exposure is a script side effect rather than a stated product decision |

The primary and separately-reported assignments are kept apart on purpose. Folding
CWE-798 into the RCE vector would let a reader believe the finding is an
unauthenticated root RCE on a correctly configured device, which it is not; and
excluding CWE-798 entirely would hide a weakness that materially changes the risk
for a deployment which never rotated its password. Both are published, and only the
injection carries the headline score.

### CWE and CVSS — vector derivation

**Published vector: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 (High).**

| Metric | Value | Weight | Why |
|---|---|---|---|
| Attack Vector | **Network** (`AV:N`) | 0.85 | the vulnerable service is an HTTP listener bound to the device's own network stack; any host that can address it, including across a routed hop or from any device on the segment the router serves, can drive it. The stock WAN-side `DROP` policy is recorded as a deployment qualifier below, with the `AV:A` arithmetic published |
| Attack Complexity | **Low** (`AC:L`) | 0.77 | one deterministic authenticated request. No race, no window, no memory layout, no gadget, no user state, no dependency on radio or WAN mode |
| Privileges Required | **High** (`PR:H`) | 0.27 | a valid credential for the single Basic realm is required, and that realm's only principal is the device administrator, which holds significant control over the component's configuration. See the privilege decision below |
| User Interaction | **None** (`UI:N`) | 0.85 | the attacker issues the request; no administrator action, click or visit is needed at any step |
| Scope | **Unchanged** (`S:U`) | - | see the Scope decision below |
| Confidentiality | **High** (`C:H`) | 0.56 | root on the device reads the password file, all wireless keys, stored VPN and PPP credentials and every file on the device |
| Integrity | **High** (`I:H`) | 0.56 | root rewrites configuration, firewall and NAT rules, boot scripts and flash-backed state |
| Availability | **High** (`A:H`) | 0.56 | root stops routing, wireless, DHCP, DNS and the management service, or reboots at will |

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

`PR:H` is the reading and `PR:L` is the rejected one; the rejected vector is
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High.

Arithmetic for the rejected reading:

```
Exploitability(PR:L, S:U) = 8.22 * 0.85 * 0.77 * 0.62 * 0.85 = 2.835255
Base                      = min(5.873119 + 2.835255, 10)     = 8.708373
Roundup                                                  = 8.8
```

Why `PR:L` is wrong here, from the artefacts: CVSS 3.1 reserves `PR:L` for a
principal with "basic user capabilities that ... affect component settings" that is
distinct from the administrator. This product has no such principal. The realm is
populated from a single `Auth / /etc/boa/boa.passwd` directive, the security store
after that directive is applied contains exactly one `/` entry of type `Basic`, the
`Allow` directive handler at `0x407688` is a stub that answers "This version of Boa
doesn't support access controls", the type-`None` string at `0x49070c` is never
passed to `auth_add`, the shipped configuration carries one `Auth` directive and no
`Allow` directive, our reading of it found no per-user or per-group access restriction,
and the password file holds one account. Every
credential the realm accepts therefore buys the same thing: full administrative
control, including WAN and WLAN rewriting, firmware upgrade and reboot. That is
`PR:H` by definition, and publishing 8.8 would overstate the finding by exactly the
0.6 differential that the privilege weight carries.

It is worth recording that the research notes behind this advisory carried `8.8`
beside a `PR:H` vector. That is the arithmetic of `PR:L` written against the vector
of `PR:H`, and it is a recurring error in this corpus; the score published here was
recomputed from the vector, not inherited.

### CWE and CVSS — the Scope decision

**Scope is Unchanged.** Scope Changed is superficially attractive - the vulnerable
component is the web server and the impact lands on the operating system of the
router - but it is the wrong reading, because Scope asks whether the impact crosses
a security authority boundary, and here there is no boundary to cross. `webs` is
already root: `etc/boa/boa.conf` declares `User root`, the process starts from early
init and never drops privileges, and it writes `/var/run/webs.pid`. The commands run
with the same authority, in the same filesystem view, on the same device, as the
service that spawned them. Cross-account or cross-machine outcomes can justify
Changed; executing as the same identity that the vulnerable component already holds
does not.

The rejected variant `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = 9.1 High:

```
Impact(S:C) = 7.52 * (0.914816 - 0.029)
            - 3.25 * (0.914816 * 0.9731 - 0.02)^13
            = 6.661336 - 0.533310
            = 6.128026
Exploitability(PR:H, S:C) = 8.22 * 0.85 * 0.77 * 0.50 * 0.85 = 2.286496
Base = min(1.08 * (6.128026 + 2.286496), 10) = 1.08 * 8.414522 = 9.087684
Roundup                                        = 9.1
```

Note that the Scope-Changed privilege weight for `PR:H` is 0.50 rather than 0.27,
which alone accounts for most of the increase. It is published so that a reader
who prefers the Changed convention can see exactly what it would buy, and it is not
the score of this finding.

### CWE and CVSS — the Attack Vector decision

Two defensible readings exist and both are printed.

`AV:N` (published): the service is bound to the device's IP stack on TCP port 80;
the set of possible attackers is not limited to hosts sharing one physical medium,
since any wired client, any associated wireless client, any bridged device and any
host reachable through routing or a VPN can address it; and the two most common
operator decisions - enabling remote management and forwarding port 80 - put it on
the internet with a single configuration change. CVSS 3.1 treats a vulnerability
exploitable "at one or more network hops away" as Network.

`AV:A` (rejected for the headline, arithmetic shown): on a stock device the shipped
firewall script drops WAN-originated new connections (`firewall.sh:180`,
`firewall.sh:187`, `firewall.sh:189`), so the attacker must already be on the
attached LAN or Wi-Fi segment.

```
Exploitability(AV:A, AC:L, PR:H) = 8.22 * 0.62 * 0.77 * 0.27 * 0.85 = 0.900610
Base = min(5.873119 + 0.900610, 10)                                 = 6.773729
Roundup                                                             = 6.8
```

We publish 7.2 rather than 6.8 because the firewall posture is a side effect of a
shell script rather than a documented statement about management-plane reachability,
and because the segment behind a SOHO router is precisely where untrusted devices
live. A reader who disagrees has the alternative number and its arithmetic, and the
difference between the two readings is 0.4.

For completeness, `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.6 High
(Exploitability 8.22 x 0.85 x 0.44 x 0.27 x 0.85 = 0.705547, base 6.578666) is
also rejected: complexity is Low because nothing about success depends on a
condition outside the attacker's control - unlike the four uptime-gated routes on
this device, which do carry such a condition and are not part of this advisory.

### CWE and CVSS — conditional readings, labelled as such

Two deployment states raise the rating above 7.2. Neither is the headline, and each
is stated with what we actually established.

**Conditional A - the factory credential was never rotated.**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical.

```
Exploitability(PR:N) = 8.22 * 0.85 * 0.77 * 0.85 * 0.85 = 3.887043
Base = min(5.873119 + 3.887043, 10)                      = 9.760161
Roundup                                                  = 9.8
```

Where a device still accepts the credential the firmware ships with, the
administrator privilege costs one guess, so no privilege had to be obtained. Its
Scope-Changed variant `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` computes to
10.0 and is not published, for the Scope reason above. **Status: reasoned, not
demonstrated.** We never authenticated to a device, so this is an inference from
the shipped password file in the read-only root filesystem plus the injection
proven at the sink. The credential weakness itself stands on the artefact, not on
the inference.

**Conditional B - the device is still in its pre-configuration setup state.**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical, with the contested
variant `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.1 High (Exploitability
8.22 x 0.85 x 0.44 x 0.85 x 0.85 = 2.221167, base 8.094286). When configuration
object `0x1bc` reads zero, `auth_authorize` returns success without a challenge for
any path outside `/mp.asp`, `/index.asp` and `/` (at `0x4052d0`), and answers
`/generate_204` with `204` - captive-portal behaviour. **Status: structural
inference from the shipped binary, never exercised.** We do not adopt it, because
the state is the install wizard: it is transient, it is entered by a factory reset
and left as soon as setup completes, and first-run provisioning paths are not the
finding this advisory rates. Operators should still know it, because a device reset
to defaults and left unconfigured is exposed in a way a configured device is not.

### CWE and CVSS — the separately reported factory credential (CWE-798)

Stated on its own terms, without a score, because scoring it inside this advisory
would double-count it against the conditional reading above:

- The firmware image `BR6478AC_v2.20.bin` contains a populated
  `/etc/boa/boa.passwd` in a read-only SquashFS filesystem, referenced by the
  single `Auth / /etc/boa/boa.passwd` directive in `etc/boa/boa.conf`. The realm
  therefore has a credential that every unit of this build shares, and the model's
  published factory login is `admin:1234`. One detail this advisory will not paper
  over: the single account entry in the image we examined is recorded under the name
  `root`, while the published management login for the model is `admin`, and because
  no device was ever authenticated against we did not establish which user name the
  HTTP realm accepts in practice. Nothing rated here turns on that detail - the
  injection requires a credential the realm accepts, whatever the account is called -
  but the vendor's own remediation guidance should resolve it.
- The digest algorithm is MD5-crypt (`$1$`). We do not claim a cryptographic match
  between the shipped digest and any specific password: the digest string captured
  during analysis is recorded incompletely, and we will not publish a claim we
  cannot recompute. The weakness rests on the artefact - a pre-populated, shared,
  read-only credential store - and on the widely published factory login, not on a
  hash comparison.
- No password-change enforcement was observed in the shipped boot path, so a
  deployment that never rotates it keeps the factory credential valid indefinitely.
- Remediation: per-unit provisioning or forced change on first session, a
  memory-hard digest, and rate limiting with lockout on the Basic challenge.

### CWE and CVSS — what is deliberately not published

- **No score for the unauthenticated setup-state branch.** It is documented as
  Conditional B with labelled inference status, and it is not the headline.
- **No score for the uptime-gated `/goform/mp` sink.** It is exploitable in
  principle and is reported to the vendor as an observation, but its 600-second
  post-boot window and its factory-test character keep it out of the rated findings.
- **No score for the `miniigd` SOAP sink.** It is unauthenticated but LAN-only under
  the shipped firewall policy; it is reported as an observation with that
  limitation stated.
- **No score that assumes internet reachability by default.** The WAN-side `DROP`
  policy is in the shipped image and the `AV:A` reading is printed alongside the
  headline.
- **No score for the excluded candidates** (`formrefresh`, `formAutoFWupgrade`,
  `formPreventionSetup`, `wscd`), because none had a request-controlled path to a
  command execution that we could establish.
- **No claim about other firmware builds or other Edimax models** for this handler;
  only `BR6478AC_v2.20.bin` was examined.
- **No inherited figure.** Every number in this advisory was computed from its own
  vector; the recorded `8.8` in the research notes was not carried over.

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

One sentence for the vendor's engineers: an authenticated administrator - which on
this device means the only principal that exists - can put arbitrary shell syntax
into any of thirty unvalidated calibration fields of
`POST /goform/formWlanMP`, and the product concatenates them into a command line
and hands it to `/bin/sh -c` as root, at any time while the device is up. Rated
7.2 High as shipped and 9.8 Critical wherever the factory credential is still live.
