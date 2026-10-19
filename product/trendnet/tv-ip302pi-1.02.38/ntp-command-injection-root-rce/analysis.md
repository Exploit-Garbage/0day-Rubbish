# TRENDnet TV-IP302PI 1.02.38 — Command Injection in the NTP Server Address, Consumed Unquoted by a Root Shell-Form system() Call (uid=0 root)

Author: 0day Rubbish Research Team
Advisory: https://0day-rubbish.com/blog/trendnet-tv-ip302pi-ntp-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

The TRENDnet TV-IP302PI is a closed-source network camera. Its firmware is not a TRENDnet-native
code base: the application daemon inside the image is `/hunt/hunt_server`, and the binary's string
pool carries `hunt_camera`, `HuntAudioConverter`, `HuntDataDirect` and `PPPoE_TV-IP302PI` next to
the vendor's own brand identifier, which identifies a Hunt Electronic camera platform OEM'd into
this model and running on an FA626TE-class HiSilicon ARM part. That provenance matters twice: it
tells an operator that the same construction may exist in other products built on the same
platform, and it tells a reader that this finding is specific to that platform's binary, its
configuration-key name and its command template rather than to a generic NTP client.

In firmware 1.02.38, an authenticated administrator who sets the NTP server address has that
address stored verbatim into the configuration parameter `c64_Ntp_Server`. The only validation
applied on the way in is a length cap — 48 bytes on the HTTP form path, 64 on the ONVIF SOAP path.
No character is rejected. The same field, at offset `0x9c` in the configuration structure, is
later read back by the time-synchronisation path and formatted, unquoted and unescaped, into the
command template `/hunt/msntp -ts %d -r %s &` and passed to `system()`. `system()` runs the string
through `/bin/sh -c`, and the shell re-parses it, so shell metacharacters inside an address are not
data any more: they are syntax. Three injection forms — a leading value terminated with `;`, a
`$(...)` command substitution and a backtick pair — each produced execution of an external command
as `uid=0(root)`, and a fourth run with a benign address containing no metacharacter produced
nothing.

The root cause is a single one: a configuration-sourced network address is interpolated into a
command string that is handed to a shell (CWE-78), in a daemon that runs as root (CWE-250,
CWE-269). It is not a missing authentication problem. The product's HTTP gate is present,
centralised and fail-closed, and we credit that in section 3 rather than working around it.

### Overview of the product and its runtime stack

Everything in this subsection was read out of the shipped image.

```text
FW_TV-IP302PI_V1.02.38_20160202.bin        7.85 MB
  -> unencrypted ZIP container, five zip streams
  -> root filesystem located in the third stream, EOCD at 0x5b8941
  -> extracted tree (251 files): /bin/busybox (ARM), /etc/, /www/, /hunt/
/hunt/hunt_server                          4.5 MB, stripped
  ARM 32-bit EABI5, version 5TE, soft-float, dynamically linked
  interpreter /lib/ld-linux.so.3, built for GNU/Linux 2.6.28
  platform strings: TRENDNET, PPPoE_TV-IP302PI, hunt_camera,
                    HuntAudioConverter, HuntDataDirect
boa + boa.conf                             no privilege-drop directive in the configuration
/hunt/msntp                                the NTP client the sink invokes through a shell
ONVIF                                      tds:SetNTP SOAP operation in the same daemon
```

Two facts follow from that and neither needs a device to establish. First, the daemon that formats
and executes the command runs as root: `boa.conf` declares no privilege drop, and the runtime
configuration model recovered from the binary gives no lower-privilege domain for the web tier.
There is therefore no privilege-escalation stage in this chain and none is claimed or needed — any
injection inside this daemon is already a root injection, which is what turns an input-validation
slip into full device control. Second, the NTP client is invoked in shell form rather than argv
form. That invocation style is the whole mechanism: an `execve`-style call with the address as its
own argument element would have made this finding impossible, because no shell would have been
present to re-parse the value.

### Overview of the testbed and of what that implies

This is a firmware and binary-analysis case, and the sink half of it was verified dynamically. The
verification environment was **not a physical camera, not a full-system boot and not a running
`hunt_server`**. It was a faithful re-instantiation of the extracted root filesystem under
user-mode emulation, on an isolated cloud sandbox:

- the extracted root filesystem from the vendor image, with the vendor binaries unmodified;
- `qemu-arm-static` as the user-mode ARM interpreter, launched through `chroot` into that tree, via
  the explicit form `qemu-arm-static /lib/ld-linux.so.3 --library-path /lib /bin/busybox sh -c
  "<command string>"`, because invoking `sh` directly or with `-L` failed under this toolchain;
- `binfmt_misc` registered for ARM ELF binaries pointing at the same interpreter, so that a shell
  inside the chroot could fork and exec the *external* ARM binaries in the tree, which is precisely
  the capability an injection payload needs. Without that registration, qemu-user could run shell
  builtins but external commands failed with `Exec format error` — a harness defect we hit first,
  diagnosed and fixed, and describe here so the reader can see why the early negative result was
  not evidence;
- an ABI-compatible soft-float libc copied into the tree from an ABI-matched donor — another
  IP-camera root filesystem, not a TRENDnet artifact, its name kept out of this advisory because it
  is not implicated in anything (`/lib/ld-linux.so.3`, `libc.so.6`, `libm`, `libdl`,
  `libpthread`, `libgcc_s`, GLIBC 2.4 through 2.8). The firmware ZIP ships no userspace `/lib` —
  only kernel modules under `/lib/modules` — so a compatible library set had to come from
  elsewhere. This is the one substituted component in the environment and it is a substitution of
  the C library, not of anything in the chain: no vendor code was patched, stubbed, widened or
  replaced;
- `/dev` and `/proc` bind-mounted, so that the process could see a usable device and proc view.

What was executed under that harness was the product's own command string, built by the product's
own template with attacker-chosen bytes in the NTP slot, and run by the product's own busybox shell
in the product's own root filesystem. That is a strong result and a bounded one, and section 9
states the boundary in full. The short form is: **the shell re-parsing property and the root
execution context are measured; the path from an HTTP request to that command string is static
analysis**. No HTTP request was sent to a running daemon during the dynamic phase, and no request
in any phase came from a second host. Nothing in this advisory is presented as a live-device
exploit.

### Overview of affected scope

The affected component is the time-synchronisation module of `/hunt/hunt_server` together with the
configuration parameter that feeds it, in firmware 1.02.38 for the TV-IP302PI. Only that image was
analysed and only that image is claimed. We did not diff against another TV-IP302PI build, because
none was available offline, so we make no statement about earlier firmware and none about later
firmware.

Two scope statements are worth making explicitly, because both are the kind of thing that gets
over-read downstream. Other camera models built on the same Hunt Electronic platform may carry the
same construction — the platform strings, the configuration-key naming convention and the daemon's
structure suggest a shared lineage — but we examined one binary, so we claim one model. And the
build identity available to us proves a firmware version, not a maintenance status: the artifact
filename carries the build stamp, and 1.02.38 is the current release this model's own artifact names.
Nothing in the material available to us indicates the release line has advanced past it, and no vendor
download page was reachable from this environment, so "current" here means "the newest build this
model's published artifact names" and not "re-verified newest at publication". The consequence
for an operator is a patch-availability problem — with no newer build to move to, mitigation has to
come from configuration and network placement rather than from an upgrade. The consequence for the
evidence is nothing at all: an old release line is not itself proof of a defect, and every claim
here rests on the binary and on the detonation rather than on the age of the image.

### Overview of independence

This is not a re-published public issue on this platform, and we say so with the precision the
claim needs. No published advisory record known to us describes an injection into the NTP
server-address argument of a Hunt Electronic-derived camera image — a value stored under
`c64_Ntp_Server`, formatted into `/hunt/msntp -ts %d -r %s &` and executed by `system()`. NTP
argument injection has been reported against other camera vendors' firmware, and those reports are
different implementations on different binaries with different configuration models: they neither
cover nor contradict this one.

We deliberately cite no identifier numbers in this advisory. Attaching a neighbouring CVE to an
implementation it does not describe misleads both readers and vendors, and we would rather state
the negative precisely than decorate the finding with numbers we have not resolved against the
vendor's own records. If an identifier is later shown to describe this same construction in this
same binary, it should be recorded against this advisory at that point.

There is one adjacent item that is being disclosed alongside this finding and is counted as none
of it: the factory administrator credential class weakness in this release line (CWE-798). It is a
real weakness with real consequences for a fleet that never rotated it, it is disclosed so the
vendor can fix it, and it is deliberately excluded from this finding's rating, its chain and its
proof. Section 10 and section 12 both return to why that separation is load-bearing rather than
cosmetic.

## 2. Vulnerability Summary

### Vulnerability Summary table

| field | value |
|---|---|
| Vendor | TRENDnet (United States) |
| Product | TV-IP302PI network camera |
| Platform | Hunt Electronic camera platform, OEM'd; FA626TE-class HiSilicon ARM |
| Firmware | 1.02.38 (`FW_TV-IP302PI_V1.02.38_20160202.bin`, 7.85 MB, unencrypted ZIP) |
| Vulnerable component | time-synchronisation module of `/hunt/hunt_server` (4.5 MB, ARM 32-bit EABI5 v5TE soft-float, stripped) |
| Configuration parameter | `c64_Ntp_Server`, stored at `config+0x9c` |
| Sink | `system("/hunt/msntp -ts %d -r %s &")`; `system` resolved through GOT `0xc274`; command builder at `0x2760d0`, format string reached from `0x371eb4` to `0x3ded60` |
| Entry points | HTTP POST parameter `NtpIP` to `apply.cgi` / `SetTime.cgi` (set callback `0x2b668c`), and ONVIF SOAP `tds:SetNTP` at `0x286218`-`0x286264` |
| Root cause | a network address is interpolated unquoted and unescaped into a command string executed by a shell as root |
| Validation present | length only — 48 bytes (`0x30`, via `func_0x002a9ae0`) on the HTTP path, 64 bytes on the ONVIF path |
| Validation absent | address parsing, character allow-list, quoting, escaping |
| Classification | CWE-78 primary; CWE-20, CWE-250, CWE-269 contributing |
| Authentication | required. HTTP Digest and Basic, fail-closed `401`; administrator role per the recovered privilege model `i_UserPrivilege01`-`05` |
| Privileges gained | `uid=0(root) gid=0(root) groups=0(root)` |
| Interaction | none required |
| Output channel | blind on the HTTP response: the injected command is backgrounded with `&` inside the template and its stdout is not returned; confirmation needs an out-of-band channel or on-device file access |
| Requests required | one authenticated configuration write |
| Score | 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| Status | present in the analysed build; no identifier assigned; vendor not yet notified at the time this package was written |

### Vulnerability Summary mechanics

The chain is three links and one execution, and each link is a normal product behaviour.

Link 1 is a configuration write. The parameter table maps the HTTP form field to the key
`c64_Ntp_Server`, whose set callback at `0x2b668c` compares the incoming value against the stored
one, returns early if they match, and otherwise copies it into the slot. A length check caps the
value at 48 bytes. On a change, the callback dispatches an event — event 2, via `func_0x001ecddc`
— which is how the rest of the daemon learns that time synchronisation needs re-doing.

Link 2 is command construction. The event handler at `0x371d88`, registered inside `fcn.002b700c`,
and the builder at `0x2760d0` (called from `0x286264`) both read the same configuration offset
`config+0x9c` — the same offset link 1 wrote — and format it:

```c
/* decompiled shape of fcn.002760d0 / fcn.00371d88 */
snprintf(buf, 0x100,
         *p_fmt_at_0x3ded60,      /* "/hunt/msntp -ts %d -r %s &" */
         *(cfg + 0xe4),           /* the -ts flag: server-derived, not attacker-controlled */
         cfg + 0x9c);             /* NtpIP: attacker-controlled, no quoting, no escaping */
func_0x001efbac(handle, 10, buf); /* enqueue for the worker that executes it */
```

The write offset and the read offset being the same value is the single most load-bearing detail in
the static half of this work, because it is what ties the tainted input to the tainted argument
without needing to guess at a data structure's layout.

Link 3 is execution. The enqueue helper `func_0x001efbac` hands the finished string to a queue
worker that calls `system()`. `system()` is not `execve`: it forks and then `execl("/bin/sh",
"sh", "-c", buf, ...)`, so the string is parsed by a shell. Everything the value can express in
shell syntax, it expresses.

The fourth element is context. The daemon runs as root, so the shell and the command it starts run
as root. There is no drop, no capability restriction and no chroot standing between the injection
and the device.

### Vulnerability Summary preconditions

To reach the sink an attacker needs three things and only three: reachability to the camera's HTTP
management interface (or its ONVIF service), a valid administrator credential, and the ability to
put a shell metacharacter into a configuration value that is 48 or 64 bytes long. There is no
version-specific memory layout, no race, no timing window, no need for the camera to be in a
particular state, no dependency on the device's hardware layer and no dependency on outbound
network access for the injection itself — outbound access is only needed if the attacker wants a
callback channel rather than an on-device marker.

What is not required is worth stating as plainly as what is: no memory corruption, no
authentication bypass, no session forgery, no second vulnerability to chain with this one, and no
factory credential. The credential the attacker presents can be one they were legitimately given,
one recovered from a configuration backup, one sniffed from a cleartext management session, or one
guessed — the chain does not care where it came from, and the rating assumes the attacker has to
obtain it.

## 3. Authentication Boundary

### Authentication Boundary — how credentials are checked

The gate lives inside `hunt_server` and is fail-closed.

- `fcn.0026be70` at `0x26be70` generates the Digest nonce from `gettimeofday` plus a counter,
  emits `WWW-Authenticate: Digest ...` and returns `401` for an unauthenticated request. Basic is
  also accepted, which is the weaker of the two schemes and is noted again in section 10.
- The connection handler `fcn.0026ed54` at `0x26ed54` calls that challenge function at entry, and
  credentials are evaluated through `fcn.00268afc`. An absent or wrong credential yields `401`;
  the handler does not fall through to the request's business logic. This is the correct design and
  we credit it: the finding is not that the product forgot to ask who the caller is.
- `.cgi` URIs are routed through an authentication check `func_0x0026c248`.

### Authentication Boundary — what the unauthenticated allow-list actually contains

The exception list recovered from the binary is a static-content list plus one dynamic path:
`**.html`, `**.htm`, `**.jpg`, `**.css`, `**.js`, `**.png`, `**.gif`, `**.txt`, `**.asp`,
`**.avi`, `**.bmp`, `**.cab`, `**.exe`, `**.mov`, `**.swf`, `**.xpi`, and the snapshot path
`CamImg*.jpg`. No member of that list is a configuration write, and none of them reaches the NTP
sink. The two `.cgi` routes that do — `apply.cgi` and `SetTime.cgi` — are outside it.

Two genuinely unauthenticated `.cgi` routes exist and neither is dangerous: `GetVer.cgi` returns a
version XML document and `GetLanguage.cgi` returns a language pack. Both were examined for
command-execution sinks and neither calls `system()` or `popen()`. They are useful to an attacker
only as fingerprinting, and they are not part of this finding.

The exhaustive sweep of the unauthenticated surface for a path into the sink is what makes the
"authentication required" statement here a finding rather than an assumption. It came out negative,
so this advisory is published as an authenticated finding and rated as one, and no unauthenticated
variant of it is claimed.

### Authentication Boundary — the principal required by the sink

An administrator. The configuration model recovered from the image defines five privilege levels
(`i_UserPrivilege01` through `i_UserPrivilege05`) and places NTP configuration behind the
administrator role. Two properties of that statement deserve to be separated, because they carry
different evidential weight:

- **The credential requirement is structural and fail-closed.** It is read out of the gate's own
  control flow, and the shape of the code — challenge, evaluate, refuse — is not ambiguous.
- **The role requirement is read out of the privilege model, not differentially tested.** We did
  not have an account below administrator to test with, so we did not compare a low-privilege
  write against an administrative write at runtime. The honest status of the `PR:H` rating is
  therefore "supported by the recovered privilege model", and section 12 publishes the `PR:L`
  alternative as a labelled conditional reading for exactly that reason.

Neither property is the same as a bypass, and none is claimed. If a future reader confirms that a
lower privilege level can write `c64_Ntp_Server`, the correct response is to move the rating to the
conditional reading published below, not to reinterpret this one.

### Authentication Boundary — what is deliberately not claimed

- No authentication bypass. The gate refuses without credentials, and we say so.
- No unauthenticated route to the NTP configuration. We swept for one and did not find one.
- No claim that the Digest implementation itself is cryptographically sound or unsound. Nonce
  generation from `gettimeofday` plus a counter is a predictable-nonce construction and is worth a
  vendor look, but we did not analyse the Digest verification arithmetic instruction by
  instruction, so we publish no opinion on it in either direction.
- No claim about the factory credential as a vector. It exists as a separately disclosed weakness
  and is excluded from this finding's chain and score.
- No claim that a physical camera refused our credentials. No daemon was run, so no live `401` was
  observed in this work; the fail-closed behaviour is a control-flow reading of the shipped binary.
  That is stated here so that nobody downstream upgrades it into a measured response code.

## 4. Attack Surface

### Attack Surface — the served surface and how it is protected

The inbound surface is the camera's HTTP management interface plus an ONVIF SOAP service in the
same daemon. The Digest challenge, the connection handler and the `.cgi` dispatch all live inside
`hunt_server`, which is what indicates that daemon owns the HTTP conversation; `boa` and its
`boa.conf` ship in the same image, and that configuration declares no privilege drop. Because no
daemon was ever started during this work, we do not assert a listener-ownership split between the
two and nothing in the chain needs one: whichever process accepts the request, the process that
formats the command string and calls `system()` is the root-privileged application daemon.

Static content under `/www` is served through the extension allow-list described in section 3.
Everything else — in particular every `.cgi` route — is behind the gate.

### Attack Surface — the two write paths into the same configuration slot

| entry point | parameter / field | value cap | how it reaches the sink |
|---|---|---|---|
| HTTP form: `POST apply.cgi` or `POST SetTime.cgi` | `NtpIP` | 48 bytes (`func_0x002a9ae0`) | parameter table maps it to `c64_Ntp_Server`; set callback `0x2b668c` stores it and raises event 2; handler `0x371d88` / builder `0x2760d0` format it into the command |
| ONVIF SOAP: `tds:SetNTP` | NTP host fields | 64 bytes | handler at `0x286218`-`0x286264` stores into the same `config+0x9c` slot and then calls `fcn.002760d0` directly |

This is one vulnerability with two sources, not two vulnerabilities. They share a storage slot, a
command template and a sink, and a fix that patches only the HTTP form leaves the ONVIF path open —
which is why recommendation 1 in section 11 places the validation in the set callback rather than
in either caller.

The ONVIF path carries a slightly larger cap (64 rather than 48 bytes), which makes it the more
comfortable carrier for a longer payload. Its authentication uses the same administrator account
model, through a username token or HTTP Digest. Its exact transport binding — the endpoint path and
the security-token form — was not recovered at instruction level, so the proof-of-concept ships
that mode labelled as a statically derived starting point rather than as verified working code.

### Attack Surface — components that narrow the surface

Three things limit this finding, and they are stated here rather than buried so that a reader can
weigh them against the impact section.

- **Authentication.** Only a holder of an administrator credential can write the value. The
  unauthenticated surface was swept and offers no path in.
- **Value length.** 48 bytes on the HTTP path constrains payload engineering. It does not prevent
  the injection — a bare backtick form needs only 17 bytes, and the three payloads actually
  payload values as rendered in section 9 run 28 to 36 bytes, comfortably inside the cap — but it does
  rule out long single-value stagers, which is why section 8 treats the cap as the central payload
  constraint and why the ONVIF path's 64 bytes is worth noting.
- **Blind output.** The command template ends with `&`, so the injected command is backgrounded and
  its stdout is not captured into the HTTP response. Confirmation of execution therefore needs an
  out-of-band channel (a callback connection) or read access to the device filesystem. This is a
  reporting inconvenience for an attacker and an observability advantage for nobody: the command
  still runs, and it runs as root.

## 5. Sink Identification

### Sink Identification — how the sink was found

The sink was found by following a configuration key rather than by hunting for dangerous functions.
Starting from the parameter name the web form posts, the decompilation was walked backwards and
forwards through the parameter table until the key `c64_Ntp_Server` resolved to a set callback, and
from there to the code that consumes the field the callback writes. That direction of travel is
deliberate: a search for `system()` in a 4.5 MB stripped daemon returns many candidates, most of
which interpolate only server-derived constants, and the useful question is which of them consumes
something a user typed into a form.

The chain that fell out:

```text
HTTP POST NtpIP  (apply.cgi / SetTime.cgi)
   -> parameter table key c64_Ntp_Server
   -> set callback 0x2b668c        strcmp -> early return if unchanged, else copy into the slot
                                    length cap 0x30 (48) via func_0x002a9ae0
   -> event 2 dispatched via func_0x001ecddc
   -> event handler fcn.00371d88 (registered inside fcn.002b700c)
      and builder fcn.002760d0 (call site 0x286264)
   -> snprintf(buf, 0x100, *[0x3ded60], *(cfg + 0xe4), cfg + 0x9c)
      with the format string at 0x3ded60 = "/hunt/msntp -ts %d -r %s &"
   -> func_0x001efbac enqueues buf
   -> queue worker calls system(buf)      [system referenced through GOT 0xc274]
   -> /bin/sh -c re-parses buf            <- the injection point
```

The GOT reference at `0xc274` is what settles the executor question: the call is to `system`, not
to `execve` with a prepared argv. That distinction is the entire vulnerability. Under argv-style
execution the address would have arrived at `msntp` as one argument element, and shell syntax
inside it would have been inert text passed to a resolver.

### Sink Identification — the vulnerable construction

```c
/* fcn.002b668c - the c64_Ntp_Server set callback, decompiled shape */
uVar3 = *(arg2 + 0x48);              /* the stored NtpIP slot */
if (strcmp(uVar3, arg1) == 0) return; /* unchanged: no work, no event */
strcpy(uVar3, arg1);                 /* stored verbatim; no character filtering */
/* value length capped at 0x30 (48) bytes by func_0x002a9ae0 - length only */
/* the change then raises event 2 through func_0x001ecddc */
```

Two observations belong together here. The copy is a bare `strcpy` into a configuration slot, and
we do **not** read a buffer-overflow primitive into that: the parameter table applies a 48-byte cap
before the value is usable, we did not recover the declared size of the destination slot, and
nothing was tested with an over-length value. Whether an over-length `NtpIP` could corrupt
adjacent configuration state is therefore an unexamined question, not a claim in either direction,
and it is not part of this finding. The finding is the missing *content* validation, and it needs
no overflow to be fatal.

The second observation is the one that makes this a live defect rather than a theoretical one:
the `%s` interpolation sits inside a string that is later handed to a shell, with no quoting
around it — not single quotes, not double quotes, not any escaping. In C terms the code is
correct; in shell terms it is an invitation.

### Sink Identification — execution identity of the child process

Root. The daemon performs no privilege drop, `boa.conf` in the image declares none, and the runtime
configuration model recovered from the binary contains no unprivileged identity for the web tier to
switch to. The busybox shell that `system()` starts therefore inherits `uid 0`, and so does every
command injected through it. This was measured in the dynamic phase: the markers written by the
injected command were owned by `root:root` and their content was the output of `id` run inside the
emulated tree, reading `uid=0(root) gid=0(root) groups=0(root)`.

### Sink Identification — sibling sinks, and whether they are proven

One correction belongs on the record because it changed the conclusion during analysis and a
reader deserves to see it rather than only the final answer. An early pass identified
`fcn.001efc80` at `0x1efc80` as the runner of the queued `msntp` command. It is not: that site is
an independent audio-path `system()` call whose command is
`echo %d > /proc/asound/adda300_BTL_mode`, with a server-derived integer interpolated and no user
input at all. The `msntp` path goes through `func_0x001efbac` into the queue, and the dynamic
verification in section 9 is what fixed the identification of `system()` as the final executor. The
audio site is worth naming to the vendor as the same construction with different arguments — a
shell used to write a sysfs file — but it is **not** injectable, it is **not** part of this finding
and it is **not** counted in the score.

More broadly: this daemon contains multiple shell-form command sites. Only the one consuming
`c64_Ntp_Server` was proven injectable, and only that one is claimed. A census of every `system()`
site against every configuration-derived value would be the natural next step for whoever patches
this, and recommendation 8 in section 11 asks for it in the form of a build rule rather than
another manual pass.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted value is the NTP server address, and it has two transports into one storage slot.

On the HTTP path it arrives as the POST form field `NtpIP` to `apply.cgi` or `SetTime.cgi`,
`Content-Type: application/x-www-form-urlencoded`, inside an authenticated session. The parameter
table maps that field name to the configuration key `c64_Ntp_Server`; the set callback at
`0x2b668c` performs the store. The field-name-to-key binding is read from the decompiled parameter
table, which is static evidence — no request was replayed against a running daemon during this
work, so the surrounding form fields the vendor's own web client sends alongside `NtpIP` were not
confirmed empirically. The proof of concept therefore takes them as an argument, and section 9
lists this as one of the boundaries.

On the ONVIF path the same slot is written by the `tds:SetNTP` handler at `0x286218`-`0x286264`,
which applies a 64-byte length check and no content check, and then calls `fcn.002760d0` directly —
so on that path the sink is one call away from the entry point rather than reached through the
event dispatch.

### Source Identification — sanitization that exists, and what it is for

There is exactly one check, and it is a length check: 48 bytes (`0x30`) applied by
`func_0x002a9ae0` on the HTTP path, 64 bytes on the ONVIF path. Length caps of that kind exist to
protect the fixed-size configuration slot from overrunning, and on that job it appears to work.
It has nothing to say about content. A cap of 48 bytes admits every metacharacter this injection
needs, several times over: the shortest payload value as rendered in section 9 is 28 bytes against
that cap, and a bare backtick form is 17.

The set callback's `strcmp` early-return is also worth naming as a sanitization-shaped behaviour
that is not one: it suppresses the event when the value has not changed, so re-posting an identical
payload does not re-arm the sink. An attacker who knows this simply varies the payload, for example
by changing the marker filename between attempts, which costs one byte and changes nothing.

### Source Identification — validation that is absent

All of the validations that would have closed this finding are absent, and none of them is exotic:

- no `inet_aton` / `inet_pton` parse of the value as a numeric address, and no hostname-syntax
  check followed by re-serialisation of the resolved name;
- no character allow-list. For an NTP server field the correct alphabet is roughly
  `[A-Za-z0-9._:-]`, which excludes every metacharacter in this chain;
- no deny-list for `;`, `|`, `&`, `$`, backtick, `(`, `)`, `<`, `>`, newline, carriage return or
  quotes — so nothing rejects even the crudest payload;
- no quoting or escaping at the interpolation site, which is where the last line of defence would
  normally sit;
- no argv-form invocation of `/hunt/msntp`, which would have removed the shell from the picture
  entirely and made every one of the above unnecessary.

The asymmetry is worth putting plainly, because it is the shape of the defect: the value is checked
for how *long* it is and never for what it *is*.

## 7. Data Flow

### Data Flow — end-to-end chain

```text
attacker (holds an administrator credential)
  |  POST /apply.cgi  NtpIP=<payload>            (or POST /SetTime.cgi, or ONVIF tds:SetNTP)
  v
HTTP gate: Digest/Basic challenge (0x26be70) -> credential check (0x268afc) -> 401 without one
  v
.cgi dispatch (func_0x0026c248) -> parameter table -> key c64_Ntp_Server
  v
set callback 0x2b668c: strcmp against the stored value, length-capped copy into config+0x9c
  v
event 2 (func_0x001ecddc) -> handler fcn.00371d88 / builder fcn.002760d0 (call site 0x286264)
  v
snprintf(buf, 0x100, "/hunt/msntp -ts %d -r %s &", *(cfg+0xe4), cfg+0x9c)
  v
func_0x001efbac -> queue worker -> system(buf)   [GOT 0xc274]
  v
/bin/sh -c  ->  re-parses <payload>  ->  injected command starts as uid 0
```

The measured part of this diagram is the bottom rung: the shell re-parsing attacker bytes out of a
command string of exactly this shape, running as root, in the product's own root filesystem. The
rungs above it are static — decompilation of the shipped daemon, with the write offset and the read
offset agreeing at `0x9c` as the tie between them. Section 9 keeps those two categories separate
throughout.

### Data Flow — properties of the chain worth naming

- **The taint survives the configuration store.** The value is not consumed in the request that
  wrote it; it is stored, and a later code path reads the stored copy. That makes the payload
  durable rather than momentary — which is the structural basis of the persistence inference in
  section 10.
- **The write itself is the trigger.** The set callback raises the change event, so the ordinary
  case needs no wait for a scheduled resynchronisation. If a deployment only ever syncs
  periodically, the payload simply fires at the next sync; waiting is available to the attacker and
  is not a condition outside their control. This is why section 12 keeps `AC:L`.
- **Two protocols, one slot.** The HTTP form and ONVIF `SetNTP` converge on `config+0x9c`, so a
  single fix at the storage boundary closes both and a fix in either caller alone leaves the other
  open.
- **The `-ts` argument is not attacker-controlled.** It comes from `cfg+0xe4`, a server-derived
  flag, so the injection has to come after the address argument — which is exactly where the `%s`
  is. Only one argument in the template is tainted, and that one is tainted completely.
- **The output is blind.** The trailing `&` backgrounds the command inside the shell, so nothing in
  its stdout returns to the HTTP client. Confirmation requires an out-of-band channel or read
  access to the device filesystem; neither changes what executes.

## 8. Exploit Construction

### Exploit Construction — step sequence

1. Authenticate to the camera's management interface with an administrator credential. The gate
   answers `401` and challenges with Digest; the proof of concept uses the standard library's Digest
   handler and registers a Basic handler as a fallback, because the daemon accepts both.
2. Write the payload into the NTP server address. `POST /apply.cgi` with
   `NtpIP=<payload>`; `/SetTime.cgi` is the second candidate route, and the ONVIF `tds:SetNTP`
   operation is the third entry point into the same slot.
3. Let the product do the rest. The store raises the change event, the builder formats the
   template, the worker calls `system()`, and the shell starts the injected command as root.
4. Confirm execution out of band — a connection back to a listener the attacker controls — or read
   the marker from the device filesystem. The HTTP response gives no confirmation either way,
   because the command is backgrounded.

Steps 2 and 3 are one action from the attacker's point of view: there is no separate "apply" or
"trigger" request that the chain depends on, although a synchronisation trigger field may exist in
the vendor's own form and the proof of concept can attach one.

### Exploit Construction — payload engineering constraints

The 48-byte cap on the HTTP path is the binding constraint, and it interacts with the template in
a way worth spelling out. The command that runs is

```text
/bin/sh -c "/hunt/msntp -ts <flag> -r <value> &"
```

so a payload must (a) keep `msntp` from rejecting the invocation in a way that matters — it does
not need to; the injected command runs regardless of whether the NTP client succeeds — (b) survive
being followed by ` &`, and (c) fit in 48 bytes. The three verified forms, shortest first:

| form | shape | example | bytes | notes |
|---|---|---|---|---|
| backtick | `` `<cmd>` `` | `` `/bin/busybox id` `` | 17 | shortest; the substitution result becomes `msntp`'s argument, which is irrelevant because the command already ran |
| command substitution | `$(<cmd>)` | `$(/bin/busybox id)` | 18 | same property; needs no leading literal address |
| semicolon | `<addr>;<cmd>;#` | `1.1.1.1;/bin/busybox id;#` | 25+ | the leading address keeps `msntp` syntactically happy and the trailing `#` comments out the template's ` &` |

The budget is the practical limiter on what can be injected in one value. A marker write such as
`1.1.1.1;/bin/busybox id > /tmp/m;#` fits comfortably; a long callback fetch is where the cap
starts to bite, and the ONVIF path's 64 bytes is exactly the relief valve for it. Nothing about
this constrains the *power* of the injection — a 48-byte payload can start a downloader that
fetches a longer second stage from a host the attacker controls — and nothing about it constrains
the identity the payload runs under.

### Exploit Construction — what the exploit deliberately does not do

- It assumes no factory credential. Both credential arguments are required, because this advisory
  rates the finding on the authentication the handler actually demands and keeps the shipped
  credential weakness as a separate item.
- Its default device-side command is a non-destructive identity write to a marker path. No reverse
  shell, no persistence installation, no firmware tampering, no credential harvesting and no
  destructive payload is provided or was run.
- It refuses a non-loopback target unless the operator passes an explicit override, so that a
  mistyped command cannot point it at a camera the operator does not own.
- It carries a `--control` mode that posts the benign address `1.1.1.1` and asserts that nothing
  fires, mirroring the negative control used during verification, and a `--restore` mode that
  writes a benign value back through the same primitive so an operator can leave the unit as they
  found it. Restore does not recover the camera's previous NTP server, because this research never
  recovered a configuration-read route for it; the operator should put the real value back through
  the vendor interface.
- Its `--dry-run` mode renders every request without sending anything. That is how the tool's own
  request shaping was validated during packaging: against a local stub HTTP server on the research
  workstation, never against a camera. An operator should therefore treat the first live run as
  the first real exercise of the HTTP leg, and the tool's diagnostics for `401` and `404` answers
  exist to help them converge on their own unit's form contract.

## 9. Dynamic Verification

### Dynamic Verification — environment

```text
host            x86-64 Linux, an isolated cloud sandbox, operator account with root in the sandbox
image           FW_TV-IP302PI_V1.02.38_20160202.bin, 7.85 MB
                -> unencrypted ZIP, five streams, root filesystem in the third, EOCD at 0x5b8941
                -> extracted tree, 251 files (/bin/busybox, /etc/, /www/, /hunt/)
method          chroot into the extracted root filesystem, with the ARM interpreter invoked
                explicitly: qemu-arm-static /lib/ld-linux.so.3 --library-path /lib
                /bin/busybox sh -c "<command string>"
binfmt_misc     registered for ARM ELF -> qemu-arm-static, so that a shell inside the chroot
                can fork and exec the external ARM binaries in the same tree
libc            an ABI-compatible soft-float set copied into the tree (/lib/ld-linux.so.3,
                libc.so.6, libm, libdl, libpthread, libgcc_s; GLIBC 2.4 through 2.8) because
                the update ZIP ships no userspace /lib - only kernel modules under /lib/modules
mounts          /dev and /proc bind-mounted
changes         none to any vendor binary, configuration or code path. The C library set is the
                only substituted component and it substitutes nothing in the chain under test
not present     no running hunt_server, no HTTP listener, no network client, no second host
```

The `binfmt_misc` registration is described here in detail because it is the difference between a
faithful harness and a misleading one, and because the harness initially lacked it. Before the
registration, the shell inside the chroot could execute builtins but any attempt to fork and exec
an external ARM binary failed with `Exec format error`. An attacker's payload is precisely an
external-binary execution, so under that early configuration the harness could only ever produce
negative results, for a reason that had nothing to do with the product. Once ARM ELF was registered
against the interpreter, `/bin/busybox id` executed normally. That sequence is recorded here so
that the negative result observed along the way is not mistaken for evidence about the device.

### Dynamic Verification — the replicated command

The command string given to the shell in each run is the one the product's own builder produces
from the template `/hunt/msntp -ts %d -r %s &` with the attacker-chosen value in the address slot:

```bash
R=/path/to/extracted-rootfs
RUN() { chroot "$R" /usr/bin/qemu-arm-static /lib/ld-linux.so.3 --library-path /lib \
          /bin/busybox sh -c "$1" 2>&1; sleep 1; }

RUN "/hunt/msntp -ts 1 -r 1.1.1.1;/bin/busybox id > /tmp/v_a;# &"
RUN "/hunt/msntp -ts 1 -r \$(/bin/busybox id > /tmp/v_b) &"
RUN "/hunt/msntp -ts 1 -r \`/bin/busybox id > /tmp/v_c\` &"
RUN "/hunt/msntp -ts 1 -r 1.1.1.1 &"
```

Four runs, one per cell: three injection forms and one control. Marker filenames are rendered here
in shortened form; the recorded names carried an internal stage prefix that means nothing to a
reader, and the ownership, content and presence of each marker are reported exactly as recorded.

### Dynamic Verification — observed output

```text
semicolon form, value 1.1.1.1;/bin/busybox id > /tmp/v_a;#
    marker content   uid=0(root) gid=0(root) groups=0(root)
    marker owner     root:root
command-substitution form, value $(/bin/busybox id > /tmp/v_b)
    marker content   uid=0(root) gid=0(root) groups=0(root)
    marker owner     root:root
backtick form, value `/bin/busybox id > /tmp/v_c`
    marker content   uid=0(root) gid=0(root) groups=0(root)
    marker owner     root:root
control, value 1.1.1.1
    marker           absent - no file created
```

Three conclusions follow, and each is narrower than it first sounds:

1. All three injection forms caused the shell to execute an **external** command — `/bin/busybox
   id`, a separate ARM binary in the tree, not a shell builtin — and the byte content of each
   marker is that binary's output. This is what proves shell re-parsing of the value rather than
   inert interpolation, and it is the property that makes this a command injection rather than a
   malformed-argument bug.
2. The execution context was root, evidenced twice over: the marker content says `uid=0(root)` and
   the markers are owned by `root:root`. Two independent witnesses to the same fact, since content
   comes from inside the injected process and ownership comes from the filesystem.
3. The control produced no marker, so the markers are attributable to the metacharacters in the
   value and to nothing else in the environment.

### Dynamic Verification — the negative control and why it matters

The control run is not decoration. The command template itself invokes an external binary
(`/hunt/msntp`), so a harness in a chroot is a place where a marker could in principle have been
created by something other than the injection — by a leftover file, by the harness's own tooling,
or by a misattributed side effect of the `msntp` invocation. Posting the same template with a
benign address and finding no marker removes every one of those readings at once, and it does so
with the harness held identical: same chroot, same interpreter, same shell, same tree, one variable
changed.

Its second job is to bound the claim. Because the control shows the harness is not spontaneously
creating markers, the three positive runs can be read as "the metacharacter caused the execution"
rather than "the harness caused the execution". Without it, the positive results would be
unfalsifiable, and an unfalsifiable result is not evidence.

### Dynamic Verification — boundaries of what was verified

Stated in full, in one place, so that no downstream summary can quietly drop a limitation.

**Measured.** The shell re-parsing property of the command string this product builds; the
execution of an external command injected through the value; the root identity of that execution;
and the absence of all three effects for a metacharacter-free value. All of it inside the product's
own extracted root filesystem, run by the product's own busybox shell, with no vendor binary
modified.

**Static, not executed.** Everything above the command string: the HTTP request, the Digest/Basic
gate, the parameter-table binding of `NtpIP` to `c64_Ntp_Server`, the set callback's store and
event dispatch, the builder's `snprintf`, the enqueue and the worker's `system()` call. These are
decompilation readings of the shipped daemon. The tie between them and the measured half is the
agreement of the write offset and the read offset on `config+0x9c`, plus the identity of the format
string at `0x3ded60` as the template whose command form was executed.

**Not done at all.** No physical camera was tested. No firmware was booted. No `hunt_server`
process was started, so no HTTP request was ever issued to this daemon and no request came from a
second host — the AV:N metric in section 12 is argued from the product's transport and its
recovered authentication model, not from a demonstration. No `msntp` network traffic was generated
or observed. The `-ts` flag value used in the replicated string is the value the flag takes for a
resynchronisation, read from the configuration slot rather than observed on a device. The
form-field contract of `apply.cgi` / `SetTime.cgi` (which accompanying fields the vendor's own web
client sends) was not confirmed empirically. The ONVIF transport binding — endpoint path and
security-token form — was not recovered at instruction level. No second firing of a persisted
payload was observed, because no daemon ran long enough to resynchronise twice; the persistence
statement in section 10 is a structural inference and is labelled as one.

**Inferred.** That the same construction exists on devices other than the one image we analysed,
on the basis of the platform strings and the shared lineage of the daemon. We claim one model and
one firmware build.

The correct reading of that list is not "therefore the finding is weak". It is "therefore the
finding is a static taint chain closed by a dynamic proof of the last rung, in a root filesystem
taken from the vendor's own image". That is a materially stronger position than a static-only claim
and a materially weaker one than a live-device exploit, and this advisory is written to sit exactly
between the two.

## 10. Reachability and Security Impact

### Reachability and impact — network position

The chain is delivered over the camera's own management transport: HTTP to the management interface,
or ONVIF SOAP to the same daemon. Both are addressed by the camera's IP, and neither requires
link-layer adjacency, physical access or a local foothold on the device. An attacker who can reach
the management port — from the same segment, from a routed corporate network, or from the internet
where the camera has been published for remote viewing, which is a routine deployment for network
cameras — is in a position to send the one request the chain needs.

Two honesty notes attach to that sentence. Remote reachability is a property of the transport and
of how such devices are deployed; we did not drive a request from a second host, so we are not
asserting a measured two-machine exploit. And we did not enumerate the daemon's configuration for a
source-address filter; the absence of one is not claimed as a proven fact. What supports AV:N in
section 12 is that the delivery path is an IP-addressed application protocol with no adjacency
requirement in it, not a measurement of internet exposure for any particular fleet.

### Reachability and impact — what the achieved identity controls

Root on this camera is root on a surveillance device with a network stack, a media pipeline and a
credential store:

- **Video and audio.** The live streams, any recording or snapshot path, and the imaging parameters.
  Tampering here is qualitatively worse than tampering with an ordinary embedded host, because the
  device's entire purpose is to produce evidence: an attacker at root can blind, loop, freeze,
  redirect or selectively record the feed, and nothing in the product distinguishes that from
  normal operation.
- **Accounts.** The ONVIF and RTSP account data held by the daemon, which is how an attacker keeps
  the stream after the injected value is removed — and how they read other users' video.
- **Network credentials.** The stored wireless keys, the PPPoE credentials implied by the
  platform's `PPPoE_TV-IP302PI` string, and any FTP, mail or upload destination the camera posts
  snapshots to. A camera on a segmented network is often trusted to reach a destination that
  nothing else on that segment can.
- **Filesystem and firmware.** Root can read and write the whole tree and can replace the image the
  device next boots. That is durability beyond any configuration payload.
- **Position.** Cameras are routinely installed on flat office, retail and operational networks and
  routinely given inbound reachability for viewing. Root on one is a foothold in a segment that has
  no reason to expect a camera to originate a scan. We note the deployment pattern, not a product
  default, and it is not folded into the score.

### Reachability and impact — the authentication question, answered in full

This section exists because the answer determines the headline number, and because both directions
of error are possible: overstating it to unauthenticated inflates the finding, and understating it
to "any user" hides that an administrator credential is the actual entry ticket.

What is established: the `.cgi` dispatch and the ONVIF handler both sit behind a gate that
challenges with Digest (and also accepts Basic), evaluates credentials through `fcn.00268afc`, and
answers `401` without them. The unauthenticated allow-list is a static-content extension list plus
one snapshot path, and it contains no path into the NTP configuration. The two genuinely
unauthenticated `.cgi` routes in the image (`GetVer.cgi`, `GetLanguage.cgi`) were examined and
carry no `system` or `popen` sink. So `PR:N` is not this finding, and no unauthenticated variant of
it is claimed anywhere in this advisory.

What is read rather than tested: that the write requires the **administrator** role specifically,
as opposed to any valid session. The privilege model in the image defines five levels
(`i_UserPrivilege01`-`05`) and places NTP configuration on the administrative one. We did not
possess a sub-administrator account and therefore did not run the differential test that would
settle it: post the same payload as a low-privilege user and observe a refusal. `PR:H` is rated on
the recovered model with that gap named, and the `PR:L` reading is published as a labelled
conditional so that anyone who closes the gap can move the rating without having to reinterpret
this text.

One amplifier belongs in the discussion and out of the arithmetic. This release line also ships a
factory administrator credential class weakness, disclosed alongside this advisory under CWE-798.
On a device whose password was never rotated, the "attacker must hold an administrator credential"
assumption dissolves in practice, and the effective privilege requirement collapses to none. That
is why section 12 publishes a `PR:N` conditional reading at all — and equally why it is labelled
conditional and explicitly undemonstrated: no step of this work used a factory credential, and
rating the injection on a second weakness would compound two defects into a number neither one
earns alone.

### Reachability and impact — persistence

Structurally available, and labelled as a structural inference rather than an observation. The
injected value is stored in a persisted configuration parameter, so a payload written there is
re-read whenever the synchronisation path runs again, and it survives a reboot. The consequence is
that a single authenticated write can be a standing execution primitive rather than a one-shot: the
payload re-arms on each resynchronisation, and an operator who removes the attacker's session
without reading the NTP configuration leaves the payload in place.

We ran no daemon and therefore observed zero repeat firings. The claim is that the product's own
parameter model makes this possible and that nobody should assume a one-shot impact; it is not a
claim that we watched a second execution. The obvious hardening that follows is to prefer a payload
that does not rely on re-firing, and the obvious detection that follows is to audit the stored
value — see recommendation 9 in section 11.

### Reachability and impact — detection notes

The chain is quiet by construction, because every step in it is ordinary product use: an
administrator writing a supported setting, through the vendor's own interface, with valid
credentials. There is no failed login, no session anomaly, no privilege change and no unusual
response code to alert on.

The indicators that do exist are content-shaped rather than behaviour-shaped:

- the stored NTP server address containing shell syntax or simply not being an address — the single
  cheapest detection available, and one an operator can check on every unit today;
- a `msntp` process whose `-r` argument does not parse as a host or address;
- an outbound connection from the camera to a host that is not an NTP server, which is what a
  callback payload produces and what the majority of real payloads will need in order to report
  back or to fetch a second stage;
- unexpected children of the web daemon — anything other than `msntp` in its process ancestry is
  already anomalous on a camera.

Blind output cuts both ways for a defender. Because the template backgrounds the command, an
attacker gets no confirmation in the HTTP response and is pushed toward exactly the outbound
callback that egress filtering would surface. Restricting camera egress to the time servers
actually in use therefore has a detection benefit out of proportion to its cost.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

1. **Validate the value at the storage boundary.** In the `c64_Ntp_Server` set callback at
   `0x2b668c`, parse the incoming string with `inet_pton` (accepting AF_INET and AF_INET6) or
   resolve it as a hostname and re-serialise the canonical name, rejecting anything that is
   neither. Placing the check in the callback rather than in either caller is what makes it correct
   by construction: the HTTP form, the ONVIF `SetNTP` handler and any future entry point all inherit
   it, and no new caller can forget it.
2. **Add an explicit character policy alongside it.** For this field the correct alphabet is
   `[A-Za-z0-9._:-]`; reject `;`, `|`, `&`, `$`, backtick, `(`, `)`, `<`, `>`, quotes, newline and
   carriage return outright. A length cap is not validation, and the 48-byte cap that currently
   stands alone is what admitted every injection form.
3. **Remove the shell from the invocation.** Replace the `system()` call fed by
   `func_0x001efbac` with `fork` plus the `execv` family, passing `/hunt/msntp`, `-ts`, the flag
   and `-r` with the address as separate argv elements. Keep the background semantics with the
   `fork` rather than with a `&` inside a command string. This single change makes metacharacter
   injection structurally impossible at this site, independent of how good the validation in (1)
   and (2) turns out to be.
4. **Convert the remaining shell-form sites.** The audio path at `0x1efc80` uses `system()` to run
   `echo %d > /proc/asound/adda300_BTL_mode`; it interpolates a server-derived integer and is not
   injectable, but it should be a direct `write` to the sysfs file. Where a shell invocation truly
   cannot be removed anywhere in the daemon, route every interpolated value through one escaping
   helper that single-quotes and escapes, so that correctness is a property of one function rather
   than of every call site.
5. **Introduce privilege separation.** Run the web and application tier as a dedicated unprivileged
   user holding only the capabilities it actually needs, and reserve root for what requires it.
   This does not fix the injection, but it changes every future injection in this daemon from
   "root on the device" to "the media daemon's account", which is the difference between an
   incident and a compromise.
6. **Retire the factory credential class weakness (CWE-798).** Require an administrator password to
   be set at first login instead of shipping a usable one, and refuse authenticated configuration
   operations until it exists.
7. **Harden the gate that is already correct in shape.** It fails closed, which deserves credit;
   what it lacks is resistance to guessing. Add rate limiting, backoff and lockout on Digest and
   Basic failures, and prefer Digest — or better, a TLS-terminated session — over Basic, since
   Basic carries the credential in a form that only transport protection can save. Fixing the
   predictable nonce construction (`gettimeofday` plus a counter) is part of the same work.
8. **Adopt a build rule rather than another audit.** Fail the build on any `system()`, `popen()` or
   shell-form invocation whose format string interpolates a value traceable to a configuration key
   or a request field. This daemon is 4.5 MB of stripped code; a mechanical rule generalises to the
   sites nobody has read yet, including the ones added in the next release.

### Fix Recommendations — a regression test the vendor should add

One test would have caught this and would keep it caught:

- post `1.1.1.1;id;#`, `$(id)`, a backtick pair around `id`, and single-metacharacter variants
  using `|`, `&`, `<`, `>`, newline and a double quote to **both** entry points — the HTTP form and
  ONVIF `SetNTP` — and assert that each is rejected with an input-validation error;
- assert in the same run that a plain address and a plain hostname are still accepted, so the test
  fails loudly if validation is implemented by refusing everything;
- assert that the value which is accepted reaches `msntp`'s argument list intact, which is what
  catches an escaping implementation that silently mangles legitimate hostnames;
- assert that no `msntp` invocation on the device carries a `-r` argument containing any character
  outside the field's alphabet.

The first two assertions are the important pair. A validator that rejects metacharacters and a
validator that rejects the field are indistinguishable until the accept case is tested.

### Fix Recommendations — operator-side, until a patch exists

Assume no firmware fix is available, because the release line this model names has not advanced
past the analysed build; every measure below is configuration or placement.

1. **Rotate the administrator password on every unit**, and treat any camera that ran with the
   factory credential as potentially compromised — nothing in the product's logging would have shown
   it, so the absence of an alert is not reassurance.
2. **Keep the management interface off untrusted networks.** A dedicated management VLAN, a VPN for
   remote administration, and no port-forward of the management port from the internet. Where
   remote *viewing* is genuinely required, front it with an authenticating proxy rather than
   publishing the camera itself.
3. **Audit the stored NTP server address on every unit.** Reject or alert on any value that is not
   a plain address or hostname. This is a five-line check an operator can run today and it detects
   the entire class.
4. **Restrict camera egress** to the time servers and upload destinations actually in use, by
   address and port. Since payloads are blind, most real payloads need an outbound callback or a
   second-stage fetch, and egress filtering is what turns that need into a detection event.
5. **Prefer internal time sources.** Pointing cameras at a trusted internal NTP server reduces the
   reason to change this setting in the field, which shrinks the number of people who ever touch it.
6. **Baseline the process tree.** On a healthy unit the web daemon's only child in this path is
   `msntp`; anything else in its ancestry is already anomalous and worth an immediate look.
7. **If compromise is suspected, do not restore a single binary.** Re-image the unit, rotate every
   credential it holds, and audit the network segment it sat on — root on the camera means the
   filesystem and the boot image were both writable.

## 12. CWE and CVSS

### CWE and CVSS — classification

- **CWE-78 — Improper Neutralization of Special Elements used in an OS Command ("OS Command
  Injection").** The primary classification, and the precise one: a value crossing a trust boundary
  is placed into a string that is passed to a shell, without neutralising the special elements that
  give it meaning in that shell. The neutralisation gap is total for characters and partial only for
  length.
- **CWE-20 — Improper Input Validation.** Contributing, and the more useful label for the vendor's
  code review, because it names exactly what the field has: a length check where a format check
  belongs.
- **CWE-250 — Execution with Unnecessary Privileges** and **CWE-269 — Improper Privilege
  Management.** Contributing, and the architectural amplifier: a time-synchronisation helper has no
  need of `uid 0`, yet the daemon that formats and executes its command line never drops privilege.
  This is why the impact metrics are all High rather than a partial reading, and it is not itself
  part of the vector arithmetic.

Deliberately **not** classified:

- **not CWE-306** (Missing Authentication for Critical Function) and **not CWE-862** (Missing
  Authorization). Authentication is present, centralised and fail-closed, and the NTP write sits
  behind an administrator-gated configuration path. Naming either would describe a different
  product and would point the vendor at the wrong fix — the gate works, the argument construction
  does not. The underlying research notes carried a CWE-306 "context" annotation and it is dropped
  here for that reason, in favour of stating the opposite in section 3.
- **not CWE-798** as part of this finding. The factory credential weakness in this release line is
  real and is being disclosed alongside this advisory, but it is a separate weakness with a
  separate fix, it is not the vector used here, and folding it in would compound two defects.
- **not a memory-safety CWE.** The bare `strcpy` at the set callback is noted but the destination
  slot's declared size was not recovered and no over-length value was tested, so no CWE-120-family
  label is asserted in either direction.

### CWE and CVSS — vector derivation

Computed from the vector with the CVSS 3.1 formula and rounded up to the nearest tenth.

```text
vector: AV:N / AC:L / PR:H / UI:N / S:U / C:H / I:H / A:H

Impact Sub-Score
  ISS = 1 - ((1 - 0.56) * (1 - 0.56) * (1 - 0.56))
      = 1 - (0.44 * 0.44 * 0.44)
      = 1 - 0.085184
      = 0.914816
  Impact (Scope Unchanged) = 6.42 * 0.914816 = 5.873119

Exploitability
  = 8.22 * AV(0.85) * AC(0.77) * PR(0.27) * UI(0.85)
  = 8.22 * 0.85 = 6.987000
  = 6.987000 * 0.77 = 5.379990
  = 5.379990 * 0.27 = 1.452597
  = 1.452597 * 0.85 = 1.234708

Base (Scope Unchanged)
  = min(Impact + Exploitability, 10)
  = min(5.873119 + 1.234708, 10)
  = 7.107827   ->  Roundup  ->  ceil(71.07827) / 10 = 72 / 10 = 7.2
```

Per-metric reasoning:

- **AV:N** — the delivery transport is HTTP to the camera's management interface, with ONVIF SOAP
  as a second network entry into the same slot. Both are addressed by the camera's IP, and nothing
  in the injection requires adjacency, physical access or local execution. This metric is argued
  from the transport and the recovered authentication model rather than demonstrated between two
  hosts, because no request was issued to a running daemon at any point in this work.
- **AC:L** — no condition outside the attacker's control. One authenticated request; no race, no
  timing window, no memory-layout dependency, no on-path position, no hardware-layer dependency, no
  requirement that the device be in any particular state. The 48-byte value cap is attacker-side
  payload engineering (section 8 shows three forms that fit, the shortest at 17 bytes for a bare
  command, 28 to 36 bytes for the payload values rendered in section 9), not an
  environmental condition. If a deployment only resynchronises periodically, waiting is available
  to the attacker, which also does not qualify as `AC:H`.
- **PR:H** — see the dedicated decision below.
- **UI:N** — no administrator action, no browser session, no induced click. The attacker sends the
  configuration write themselves.
- **S:U** — see the Scope decision below.
- **C:H / I:H / A:H** — root on the camera: every stored account and network credential, the live
  and recorded media, the filesystem and the boot image, and full control of availability. All
  three confidentiality, integrity and availability impacts are complete for the device.

### CWE and CVSS — the PR decision, argued in both directions

`PR` is the only metric in this vector where a defensible reading exists on both sides, and it moves
the score by 1.6 points, so it is worth the space.

**The reading we publish: PR:H.** The write is an authenticated configuration operation, and the
privilege model recovered from the image defines five levels with NTP configuration assigned to the
administrator one. A camera's account model exists precisely to separate "may look at the video"
from "may change how the device behaves", and this operation is on the second side of that line. On
the evidence available, the attacker needs significant control over the vulnerable component, not
basic user capabilities.

**The reading we did not adopt: PR:L.** It would apply if any valid session, at any of the five
levels, can write `c64_Ntp_Server`. We could not test this: no sub-administrator account was
available, so no differential was run between a low-privilege write and an administrative one. The
gap is disclosed rather than papered over, and the conditional reading is published below with its
own vector and arithmetic so that closing the gap later is a one-line change to the rating rather
than a rewrite of the finding.

**What neither reading touches: the credential requirement itself.** `PR:N` is not the finding, and
section 3 shows why: the gate is fail-closed, the unauthenticated allow-list contains no path to
the sink, and the two genuinely anonymous `.cgi` routes carry no execution sink. The only route to
a `PR:N` number is through the factory credential weakness, which is a different defect and is
published below as a labelled, explicitly undemonstrated conditional.

### CWE and CVSS — the Scope decision

**Published reading: Scope Unchanged.** The vulnerable component is the camera's application daemon
and the impacted component is the camera's operating system. Ordinarily those are different
components, but on this product no authority boundary separates them: the daemon already runs as
`uid 0`, `boa.conf` declares no privilege drop, and the configuration model offers no
lower-privilege domain for the web tier. The chain therefore does not cross into another authority
— it exercises, through a defect, an authority the vulnerable component already held. The attacker
moves from "root daemon that parses my configuration request" to "root shell", and the granting
authority for both is the device's own init running the same uid. That is Scope Unchanged, and it
is the convention applied consistently across this project's advisories: running as the same
service identity on the same host is not a scope change.

**Considered and rejected: Scope Changed.** A network-facing management service on a surveillance
device yielding root over the operating system, the media pipeline and the credential store is the
sort of outcome Scope Changed exists to express, and an evaluator could reasonably publish the
Scope-Changed variant of the same metrics. We do not, for the same-uid reason above: there is no
partitioned authority to leave. Publishing the higher figure would attribute a boundary crossing to
the vulnerability that the product's own architecture does not have, and it would obscure the more
useful message to the vendor — that the privilege separation which would make Scope Unchanged the
comfortable answer is itself a fix worth making (recommendation 5). The arithmetic is printed in
the rejected-reading list below so that the difference cannot be mistaken for an error.

### CWE and CVSS — conditional and rejected readings, each with its own arithmetic

- **Recorded figure, corrected.** The verification record carried 8.8 against a vector reading
  `PR:H` with Scope Unchanged. That vector computes to 7.2 — Impact 5.873119 plus Exploitability
  1.234708 equals 7.107827, rounded up to 7.2 — and 8.8 is the value of the same vector with
  `PR:L`. The recorded figure therefore belonged to a different privilege reading than the vector
  beside it. Published here as 7.2, computed from the vector, with the discrepancy recorded rather
  than silently overwritten.
- **Conditional A — any valid session rather than the administrator role:
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High.** Exploitability becomes 8.22 x 0.85
  x 0.77 x 0.62 x 0.85 = 2.835255; 5.873119 + 2.835255 = 8.708374, rounded up to 8.8. Applies if a
  privilege level below administrator can write `c64_Ntp_Server`. **Not demonstrated**, and the
  recovered model argues against it. Labelled conditional; not the headline.
- **Conditional B — an unrotated factory administrator password:
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical.** Exploitability becomes 8.22 x
  0.85 x 0.77 x 0.85 x 0.85 = 3.887043; 5.873119 + 3.887043 = 9.760162, rounded up to 9.8. Applies
  only on a device still carrying the credential it shipped with — the CWE-798 weakness disclosed
  separately alongside this finding. **Not demonstrated:** no step of the injection work used a
  factory credential, the daemon was never run, and the primary rating assumes the attacker must
  obtain a credential. This figure is the compounded value of two weaknesses and must never be
  quoted as the value of this one.
- **Rejected C — Scope: Changed: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = 9.1 High.**
  Impact becomes 7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 - 0.02)^13 = 6.128026;
  Exploitability with the Scope-Changed privilege weight is 8.22 x 0.85 x 0.77 x 0.50 x 0.85 =
  2.286496; 1.08 x (6.128026 + 2.286496) = 9.087684, rounded up to 9.1. Rejected on the same-uid
  grounds argued above.
- **Rejected D — Attack Vector: Adjacent: `AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.8 Medium.**
  Exploitability becomes 8.22 x 0.62 x 0.77 x 0.27 x 0.85 = 0.900610; 5.873119 + 0.900610 =
  6.773729, rounded up to 6.8. Rejected because the transport is an IP-addressed application
  protocol with no adjacency requirement. Recorded with the caveat that we did not enumerate the
  daemon's configuration for a source-address filter, so this rests on the transport rather than on
  a proven absence of access control.
- **Rejected E — Attack Complexity: High:
  `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.6 Medium.** Exploitability becomes 8.22 x
  0.85 x 0.44 x 0.27 x 0.85 = 0.705547; 5.873119 + 0.705547 = 6.578666, rounded up to 6.6.
  Rejected because `AC:H` requires conditions beyond the attacker's control and none was found: no
  race, no timing window, no layout dependency, and the change event is raised by the write itself.

### CWE and CVSS — adjacent disclosures that are not part of this score

- **Factory administrator credential (CWE-798).** Disclosed alongside this advisory as its own
  item. Materially changes the exposure profile of any fleet that never rotated it, which is exactly
  why it is kept out of this finding's rating: compounding it would let a single number describe two
  defects and would obscure which one to fix first.
- **Predictable Digest nonce construction.** The challenge nonce is generated from `gettimeofday`
  plus a counter at `0x26be70`. That is worth hardening and may matter to an attacker positioned to
  predict challenges, but we did not analyse the Digest verification arithmetic and we publish no
  exploitability opinion about it in either direction.
- **Basic authentication accepted alongside Digest.** A credential-carrying scheme with no transport
  protection of its own on a device whose management port is routinely exposed is a weakness in its
  own right; it is not part of this chain and not counted here.
- **A second shell-form `system()` site** in the same daemon, the audio path at `0x1efc80` writing
  `echo %d > /proc/asound/adda300_BTL_mode` with a server-derived integer. Same construction, not
  injectable, disclosed so the vendor converts it in the same pass rather than in the next audit.
- **No privilege separation in the web tier** (CWE-250, CWE-269). The amplifier that makes every
  injection in this daemon a root injection. Reported separately from the vector arithmetic.

None of these is included in the CVSS vector or the score above, and none is presented as
established beyond what its own evidence supports.

### CWE and CVSS — what is deliberately not published

- Only a non-destructive marker payload is published. The proof of concept writes `id` output to a
  marker path or performs an out-of-band fetch, and it exits. No reverse shell, no persistence
  installer, no firmware-tampering payload, no credential-dumping payload and no destructive command
  is provided, and none was run.
- No credential-guessing, dictionary or brute-force capability is included, and the tool requires
  credentials as arguments so that it cannot be pointed at a camera with an assumed factory value.
- No factory credential value is printed in this advisory or in the tool. The CWE-798 item is
  disclosed to the vendor as a weakness class with its fix, not published here as a usable password.
- The persistence path is described structurally and not weaponised. No payload that re-arms across
  reboots was installed, and none is provided.
- The Digest nonce construction is named without an attack. We did not build a challenge-prediction
  primitive and we do not imply that one is trivial.
- Nothing here identifies an individual. The vendor is named as a company with its country; the
  platform originator is named as a company because it is load-bearing for the scoping statement.
  No employee, developer or contact is credited or implicated.

### CWE and CVSS — summary

- **Score**: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- **Conditional readings, labelled and undemonstrated**: 8.8 High with `PR:L` if any valid session
  can write the field; 9.8 Critical with `PR:N` on a device whose factory password was never
  rotated, which is a compound of this finding and the separately disclosed CWE-798 weakness
- **Rejected readings**: 9.1 High under Scope Changed; 6.8 Medium under AV:A; 6.6 Medium under AC:H
- **Recorded figure corrected**: the 8.8 carried in the research record beside a `PR:H` vector is
  not what that vector computes to; 8.8 belongs to the `PR:L` variant
- **Primary CWE**: CWE-78. **Contributing**: CWE-20, CWE-250, CWE-269. **Not** CWE-306, **not**
  CWE-862, **not** CWE-798 as part of this finding, and no memory-safety CWE asserted
- **Privilege ceiling**: `uid=0(root) gid=0(root) groups=0(root)`, observed in the marker content
  and in the markers' ownership inside the emulated root filesystem. No cross-host movement, no
  escalation from an unprivileged account, no unauthenticated entry and no memory-corruption
  primitive is claimed
- **Verification boundary in one line**: the shell re-parsing and the root context are measured in
  the product's own extracted root filesystem under user-mode emulation; the request-to-sink path
  is static analysis of the shipped daemon; no camera was driven and no daemon was run
- **Status**: present in the analysed build; no identifier assigned; vendor not yet notified at the
  time this package was written
