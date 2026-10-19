# TRENDnet TV-IP302PI 1.02.38 - Command Injection in the NTP Server Address Reaching Root Execution Through a Shell-Form system() Call (CWE-78)

Advisory: https://0day-rubbish.com/blog/trendnet-tv-ip302pi-ntp-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The TRENDnet TV-IP302PI is a closed-source network camera sold by TRENDnet (United States) whose
firmware is built on a Hunt Electronic camera platform: the application daemon in the image is
`/hunt/hunt_server`, and its string pool carries `hunt_camera`, `HuntAudioConverter`,
`HuntDataDirect` and `PPPoE_TV-IP302PI` next to the vendor's own brand identifier. In firmware
1.02.38 (`FW_TV-IP302PI_V1.02.38_20160202.bin`), an authenticated administrator who sets the NTP
server address stores that address in the configuration parameter `c64_Ntp_Server`, and the only
check applied to the value on the way in is a length cap - 48 bytes on the HTTP form path, 64 on
the ONVIF SOAP path. No character is filtered. The same field, at offset `0x9c` inside the
configuration structure, is then read back by the time-synchronisation path and formatted -
unquoted, unescaped, with `%s` - into the command template `/hunt/msntp -ts %d -r %s &` and handed
to `system()`, which runs the string through `/bin/sh -c`. The shell re-parses it. A semicolon, a
`$(...)` command substitution or a backtick pair inside the address therefore terminates the NTP
client invocation and starts an arbitrary command in the daemon's own context, and that context is
`uid=0(root)`: the web tier performs no privilege drop, and the image's `boa.conf` declares none.
Three injection forms were detonated and each executed an external command as root, writing a
marker owned by `root:root` and containing `uid=0(root) gid=0(root) groups=0(root)`, while a benign
address with no metacharacter - `1.1.1.1` - produced no marker at all. Those detonations ran the
command string this product's own builder produces, inside this product's own extracted root
filesystem under user-mode ARM emulation: no camera was driven, no firmware was booted and no daemon
was started, so nothing here is a live-device exploit. The boundary is stated in full under Affected
Products below.

What this chain is not is as important as what it is. It is **not** an unauthenticated
vulnerability: every `.cgi` request passes a fail-closed HTTP Digest/Basic gate that answers `401`
without credentials, and the unauthenticated allow-list recovered from the binary covers static
file extensions plus a snapshot path and nothing else, so there is no anonymous route to the NTP
write. It does **not** depend on the factory credential that this release line ships; that
weakness is disclosed alongside this advisory as a separate item under CWE-798 and is deliberately
kept out of the rating, which assumes the attacker already holds a valid administrator credential.
It involves no memory corruption: the write-back at `0x2b668c` is a bare `strcpy`, but we do not
claim an overflow primitive from it, because the parameter table applies the length cap first and
we did not recover the destination slot's declared size - that question is unexamined, not
answered. And there is no file upload, no deserialisation gadget and no privilege-escalation step:
the primitive is the product's own configuration parameter and the sink is the product's own shell
invocation of its own NTP client.

- **Component**: `/hunt/hunt_server` - ARM 32-bit EABI5 version 5TE soft-float, dynamically linked
  against `/lib/ld-linux.so.3`, built for GNU/Linux 2.6.28, 4.5 MB and stripped - inside firmware
  `FW_TV-IP302PI_V1.02.38_20160202.bin` (7.85 MB; an unencrypted ZIP with five streams, the root
  filesystem in the third, whose end-of-central-directory record sits at `0x5b8941`; the extracted
  tree carries `/bin/busybox`, `/etc/`, `/www` and `/hunt/`)
- **Sink**: `system("/hunt/msntp -ts %d -r %s &")`, reached from the enqueue helper
  `func_0x001efbac` whose queue worker performs the call; `system` is referenced through the GOT
  entry at `0xc274`, which is what distinguishes this from an `execve` call site - argv-style
  execution would not re-parse the value and would not be injectable
- **Source**: the NTP server address supplied by an authenticated administrator, arriving either as
  HTTP POST parameter `NtpIP` to `apply.cgi` / `SetTime.cgi` (stored under configuration key
  `c64_Ntp_Server` by the set callback at `0x2b668c`) or as the ONVIF SOAP `tds:SetNTP` host
  fields at `0x286218`-`0x286264`; both entry points write the same slot at `config+0x9c`, and the
  sync path reads that same offset, which is how the write side and the read side were tied
  together
- **Sanitization**: none on content. The only validation is a length cap - 48 bytes (`0x30`)
  applied by `func_0x002a9ae0` on the HTTP path and 64 bytes on the ONVIF path. There is no address
  parsing (`inet_aton` / `inet_pton`), no character allow-list, no quoting and no escaping, so
  `;`, `|`, `&`, `$(`, `)` and backtick all pass through to the shell intact

## CVSS Score

- **Score**: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an authenticated
  administrator converts a time-synchronisation setting into root command execution on the camera,
  deterministically and with no memory-safety, timing or on-path dependency
- **Attack Vector: Network** - the chain rides the camera's HTTP management interface and an ONVIF
  SOAP operation, both of them network services addressed by the camera's own IP, and nothing in
  the injection requires link-layer adjacency, physical access or a local foothold. Stated at this
  level of precision because of what was measured: **no request in our verification was issued over
  a network**, since the dynamic phase replicated the sink's command string inside the extracted
  root filesystem rather than driving the daemon, so this metric is argued from the product's
  transport and its recovered authentication model rather than demonstrated between two hosts
- **Attack Complexity: Low** - deterministic. Writing the configuration value itself raises the
  change event that reaches the command builder, so there is no race to win; there is no
  memory-layout dependency, no on-path position, no hardware-abstraction dependency and no
  dependency on a particular device state. The 48-byte cap is attacker-side payload engineering,
  not an environmental condition
- **Privileges Required: High** - the write path is an authenticated configuration operation, and
  the privilege model recovered from the image (`i_UserPrivilege01`-`05`) gates NTP configuration
  on the administrator role. The `PR:L` reading and the `PR:N` reading that would apply to a
  device still carrying its factory password are published below as labelled conditional readings,
  neither of which was demonstrated, and neither is the headline
- **User Interaction: None** - no administrator action, no browser session and no induced click;
  the attacker sends the configuration request directly
- **Impact C/I/A: all High** - root on the camera means every stored account and network
  credential, the live and recorded video and audio paths, the network configuration, the
  filesystem and the firmware image, plus complete control of availability
- **Scope: Unchanged** - the vulnerable component is the camera's application daemon and the
  impacted component is the camera's operating system, but those two are not separated by any
  authority boundary here: the daemon already runs as `uid 0`, there is no privilege separation to
  leave, and the extracted root filesystem offers no lower-privilege domain to cross into. The
  chain exercises an authority the vulnerable component already held. The Scope-Changed reading of
  the same metric set computes to 9.1 and is published below as rejected, not as an alternative
  headline
- **CWE**: CWE-78 primary. CWE-20 contributing (the value is length-checked but never
  format-checked, which is exactly the validation gap), and CWE-250 with CWE-269 contributing (a
  time-synchronisation helper running as root with no privilege drop). Explicitly **not** CWE-306
  or CWE-862: authentication is present, centralised and fail-closed, so labelling this as a
  missing gate would send the vendor to the wrong fix and misdescribe the product, which gets the
  gate right and the argument construction wrong
- **Recorded score, corrected rather than inherited**: the verification record behind this advisory
  carried 8.8 next to a vector reading `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`. That vector computes
  to 7.2, not 8.8 - Impact Sub-Score 0.914816, Impact (Scope Unchanged) 6.42 x 0.914816 =
  5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708, sum 7.107827, rounded up
  to 7.2 - and 8.8 is the value of the same vector with `PR:L`. The published figure here is 7.2,
  computed from the vector, with the disagreement recorded rather than quietly overwritten
- **Conditional reading A - any valid session instead of the administrator role**:
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High. Exploitability becomes 8.22 x 0.85 x
  0.77 x 0.62 x 0.85 = 2.835255, the sum is 8.708374, rounded up to 8.8. This applies if a
  privilege level below administrator can write `c64_Ntp_Server`. **Not demonstrated**: no account
  below administrator was tested against the write path, and the recovered privilege model gates it
  on admin, which is why the headline is `PR:H` and this reading stays conditional
- **Conditional reading B - a factory administrator password that was never rotated**:
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical. Exploitability becomes 8.22 x
  0.85 x 0.77 x 0.85 x 0.85 = 3.887043, the sum is 9.760162, rounded up to 9.8. This applies only
  where a camera still carries the credential it shipped with - the weakness disclosed separately
  alongside this advisory. **Not demonstrated**: no step of the injection work used a factory
  credential, the rating above does not assume one, and this figure is the compounded value of two
  separate weaknesses rather than the value of either on its own
- **Rejected reading C - Scope: Changed**: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = 9.1
  High. Impact becomes 7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 - 0.02)^13 =
  6.128026, Exploitability with the Scope-Changed privilege weight is 8.22 x 0.85 x 0.77 x 0.50 x
  0.85 = 2.286496, and 1.08 x (6.128026 + 2.286496) = 9.087684, rounded up to 9.1. Rejected for
  the same-uid reason given in the Scope bullet above
- **Rejected reading D - Attack Vector: Adjacent**: `AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.8
  Medium. Exploitability becomes 8.22 x 0.62 x 0.77 x 0.27 x 0.85 = 0.900610, the sum is 6.773729,
  rounded up to 6.8. Rejected because the delivery transport is HTTP and ONVIF over the camera's IP
  address with nothing tying either to a link-local segment; what we can say with certainty is that
  we did not enumerate the daemon's configuration for a source-address filter, so this rejection
  rests on the transport and on the absence of an adjacency requirement in the protocol, not on a
  proven absence of every possible access control
- **Rejected reading E - Attack Complexity: High**: `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H`
  = 6.6 Medium. Exploitability becomes 8.22 x 0.85 x 0.44 x 0.27 x 0.85 = 0.705547, the sum is
  6.578666, rounded up to 6.6. Rejected because `AC:H` requires a condition outside the attacker's
  control, and none was found: if a deployment only resynchronises periodically, waiting is inside
  the attacker's control, and the write-side event dispatch recovered at `0x2b668c` means the
  ordinary case needs no wait at all

## Affected Products

- TRENDnet TV-IP302PI network camera, firmware 1.02.38, as shipped in the vendor image
  `FW_TV-IP302PI_V1.02.38_20160202.bin` (7.85 MB, unencrypted ZIP, five streams, root filesystem in
  the third at an end-of-central-directory record of `0x5b8941`). Vendor TRENDnet, United States
- Affected component: the time-synchronisation module inside `hunt_server` - the command builder at
  `0x2760d0` with its caller at `0x286264` and the registered change-event handler at `0x371d88`
  (format string resolved from `0x371eb4` to `0x3ded60`) - together with the `c64_Ntp_Server` set
  callback at `0x2b668c`, the length check at `func_0x002a9ae0`, the enqueue helper
  `func_0x001efbac` and the two write entry points that reach it: the authenticated HTTP form
  (`apply.cgi`, `SetTime.cgi`, parameter `NtpIP`) and the ONVIF SOAP `tds:SetNTP` operation
- Runtime stack: busybox userland on ARM (`/bin/busybox`); a `boa` web server whose `boa.conf`
  carries no privilege-drop directive; `hunt_server` as the application daemon handling the
  Digest/Basic challenge, the `.cgi` dispatch and the ONVIF SOAP service, running as root;
  `/hunt/msntp` as the NTP client, invoked through a shell rather than through argv
- Platform provenance: the daemon and its string table identify a Hunt Electronic camera platform
  (`hunt_camera`, `HuntAudioConverter`, `HuntDataDirect`, `PPPoE_TV-IP302PI`) OEM'd into this
  TRENDnet model. The configuration key `c64_Ntp_Server`, the command template
  `/hunt/msntp -ts %d -r %s &` and this binary are specific to that platform, which is what
  separates the finding from NTP-argument injection classes published for other camera vendors'
  firmware
- Only this firmware image was analysed and only this image is claimed. The build stamp in the
  artifact filename is the identity we can prove from the image itself, and 1.02.38 is the release
  that this model's own current artifact names. Nothing in the material available to us - which
  included no reachable vendor download page - shows the release line having advanced past it, so
  "current" means the newest build this model's published artifact names rather than a figure
  re-verified at publication. **What that implies for an operator is a patch-availability problem,
  not extra evidence**: with no newer build in the line there is no fixed firmware to move to, so the
  mitigation list below is what stands in for a patch until the vendor publishes one. No claim is
  made about other TRENDnet models, other Hunt Electronic-derived products, or earlier or later
  TV-IP302PI firmware - none was examined. We also state plainly that the age of a release line is
  never itself evidence of a defect: every claim in this advisory rests on the binary and on the
  detonation, not on the image's age
- Verification method and its boundary: this is firmware and binary analysis. The image was
  unpacked, the daemon disassembled and decompiled, and the sink was then executed - on an isolated
  cloud sandbox, the extracted root filesystem was run under `chroot` with `qemu-arm-static`
  user-mode ARM emulation, with `binfmt_misc` registered for ARM ELF so that a shell inside the
  chroot could fork and exec the external ARM binaries in the same tree, with an ABI-compatible
  soft-float libc (`/lib/ld-linux.so.3`, `libc.so.6`, `libm`, `libdl`, `libpthread`, `libgcc_s`,
  GLIBC 2.4 through 2.8) copied in from an ABI-matched donor root filesystem, because the update
  ZIP ships no userspace `/lib` - only kernel
  modules under `/lib/modules` - and with `/dev` and `/proc` bind-mounted. **This is user-mode
  emulation of an extracted root filesystem. It is not a physical camera, not a full-system boot
  and not a running `hunt_server`**: no HTTP request was sent to the daemon during the dynamic
  phase and no request came from a second host. What was executed is the exact command string the
  product's own builder produces, with attacker-chosen bytes in the NTP slot, run by the product's
  own busybox shell in the product's own root filesystem
- Privilege ceiling reached: `uid=0(root) gid=0(root) groups=0(root)` - observed both in the marker
  content and in the markers' `root:root` ownership inside the emulated root filesystem. Not
  reached and not claimed: no cross-host movement, no attack on any other device, no escalation
  from an unprivileged account (none was needed, the daemon is already root), no memory-corruption
  primitive, and no unauthenticated entry into the chain
- Adjacent item, disclosed separately and counted as none of this finding: the factory
  administrator credential in this release line (CWE-798). It is a real weakness, it materially
  changes the exposure profile of a fleet that never rotated it, and it is **not** the vector here

## Impact

- Root command execution on the camera for anyone holding a valid administrator credential. The
  practical effect is that every administrative setting that reaches this daemon's shell becomes a
  command-execution primitive, and time synchronisation is the one that was proven
- What root controls on a network camera: the live video and audio feeds and any recording or
  snapshot path, the ONVIF and RTSP account data, stored network credentials - the platform's PPPoE
  client, wireless keys, and any FTP or mail destination used for snapshot delivery - the
  filesystem, and the firmware image the device will next boot
- The target is a surveillance device, so tampering with it is worse than tampering with an
  ordinary embedded host: an attacker who reaches root can blind, loop, redirect or selectively
  record the very evidence the camera exists to produce, and no product-level audit event
  distinguishes that from normal operation
- Persistence is structurally available and is stated as a structural inference rather than an
  observation: the injected value is written into a persisted configuration parameter, so a payload
  stored there would be re-read on each subsequent resynchronisation and would survive a reboot.
  We ran the daemon zero times and therefore observed zero repeat firings; the claim is that the
  product's own parameter model makes this possible, not that we watched it happen
- Network placement multiplies the outcome. Cameras are routinely put on flat office and
  operational networks and are routinely made reachable from outside for viewing, so root on one is
  a foothold into segments that do not expect a camera to be a pivot point. That is a statement
  about how such devices get deployed, not a claim about this product's default configuration, and
  it is not folded into the score
- Detection is quiet by construction. The whole chain is an authenticated administrator writing a
  supported configuration value, so the useful indicators are the stored NTP address containing
  shell syntax, a `msntp` child argument list that does not parse as an address, and any outbound
  connection from the camera to a host that is not an NTP server
- Amplifiers reported separately and not folded into the score: the factory credential weakness
  (CWE-798); the absence of privilege separation in the web tier (CWE-250, CWE-269), which is why
  an injection in a configuration handler lands as root rather than as a service account; a second
  `system()` site in the same daemon driving a shell `echo` into `/proc/asound/adda300_BTL_mode` at
  `0x1efc80`, which is the same construction with different arguments; and the fact that the
  unsanitised parameter is reachable from two protocols, so a fix applied only to the HTTP form
  leaves the ONVIF `SetNTP` entry point open

## Mitigation / Fix Recommendations

1. **Validate the address as an address, at the point of storage.** Parse the value with
   `inet_pton` or `inet_aton` (or resolve it as a hostname and re-serialise the result) and reject
   anything that is not a valid numeric address or a syntactically valid host name. Enforce it in
   the `c64_Ntp_Server` set callback at `0x2b668c` so that the HTTP form, the ONVIF `SetNTP`
   operation and any future third entry point all inherit the check, instead of patching one caller
2. **Reject the metacharacter set explicitly as a second layer** - `;`, `|`, `&`, `$`, `` ` ``,
   `(`, `)`, `<`, `>`, newline, carriage return and quote characters - and reject any value
   containing whitespace runs. A length cap is not input validation, and the 48-byte cap currently
   serving as the only check is what let every injection form through
3. **Stop invoking `/hunt/msntp` through a shell.** Replace the `system()` call fed by
   `func_0x001efbac` with the `execv` family, passing the address as its own argv element so no
   shell ever re-parses it. Keep the trailing-background behaviour with `fork` rather than with a
   `&` inside a command string. Apply the same conversion to the other shell-form sites in the
   daemon, including the `echo` into `/proc/asound/adda300_BTL_mode`, which should be a `write` to
   the sysfs file
4. **Where a shell invocation genuinely cannot be removed**, quote and escape the interpolated
   value (single quotes with embedded-quote escaping) as defence in depth, and add a daemon-wide
   rule that no configuration-sourced string reaches `system()` without passing through one
   escaping helper
5. **Introduce privilege separation.** Run the web and application tier as a dedicated unprivileged
   user with only the capabilities it needs, and reserve root for what actually requires it, so a
   configuration-injection defect yields a service account rather than the device. This also makes
   Scope Unchanged the comfortable answer and lowers the ceiling of every future injection in this
   daemon
6. **Remove the factory credential class weakness (CWE-798) shipped with this release line**: force
   an administrator password to be set at first login rather than pre-seeded, and refuse to serve
   authenticated configuration operations until one exists
7. **Add lockout and rate limiting on the Digest/Basic gate.** The gate itself is fail-closed and
   correct, which is worth crediting; what it lacks is resistance to credential guessing, which is
   what turns a `PR:H` finding into a `PR:N` one in the field
8. **Add a regression test that would have caught this.** Post `1.1.1.1;id;#`, `$(id)`, a backtick
   pair, a pipe, an ampersand and a newline variant to both entry points and assert that each is
   rejected while a plain address is still accepted; assert that the resulting configuration value
   reaches the `msntp` argument list intact; and add a static rule that fails the build on any
   `system()` or `popen()` call whose format string interpolates a configuration-derived value
9. **Operator measures until a patch exists:** rotate the administrator password on every unit and
   treat any camera that ever ran with the factory credential as potentially compromised, because
   nothing in the product's logging would show it; keep the management interface off untrusted
   networks - a management VLAN or VPN, and no port-forward from the internet; audit the stored NTP
   server address on each unit for shell metacharacters and for values that are not addresses;
   restrict outbound traffic from camera subnets to the NTP servers actually in use; and alert on
   any outbound connection from a camera to a host that is not a time server

## PoC

`exploit/trendnet_tv_ip302pi_ntp_command_injection_root_rce.py` - standard library only. It
authenticates with HTTP Digest and falls back to Basic, writes the injected NTP address through
`apply.cgi` or `SetTime.cgi` (or through the ONVIF SetNTP shape), and confirms execution by an
out-of-band request to a listener it can start itself. `--form` selects the injection form
(`semicolon`, `command-substitution`, `backtick`, or `auto` for shortest-that-fits) and warns when a
payload would exceed the 48-byte or 64-byte cap of the entry point in use. `--control` posts the
benign address `1.1.1.1` and asserts that nothing fires, mirroring the negative control used during
verification. `--restore` writes a benign value back through the same primitive. `--dry-run` renders
every request without sending anything, which is how the tool's own request shaping was validated:
against a local stub server, never against a camera. Credentials are required arguments - the tool
deliberately assumes no factory password, since the advisory keeps that weakness separate from this
finding. Refuses a non-loopback `--target` unless `--allow-remote` is given, and the default device-side
command is a non-destructive marker write.

## Independence

No published advisory record known to us carries this root cause on this platform: an injection
into the NTP server-address argument of a Hunt Electronic-derived camera image, stored under
`c64_Ntp_Server` and consumed by `/hunt/msntp` through `system()`. NTP-argument injection has been
reported for other camera vendors' firmware and those reports are different implementations on
different binaries, so they neither cover nor contradict this finding. We deliberately cite no
identifier numbers here, because an adjacent CVE attached to the wrong implementation misleads a
reader and a vendor; if an identifier is later shown to describe this same construction in this
same binary, that should be recorded against this advisory rather than assumed now.

## References

- https://0day-rubbish.com/blog/trendnet-tv-ip302pi-ntp-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
