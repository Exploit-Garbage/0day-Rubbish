# D-Link DNR-326 v2.70b04 - dsk_mgr.cgi f_sethdsize command injection into the diskmgr shell pipeline

Advisory: https://0day-rubbish.com/blog/dsk-mgr-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

D-Link is a networking vendor whose DNR-326 is a 16-channel network video recorder: a
Linux appliance that ingests camera streams, writes them to internal disks and exposes a web
interface for live view, playback and storage administration. The analyzed firmware image is
`DNR-326_Ax_v2.70b04.bin` (v2.70b04). Its rootfs is a CramFS image of 2407 files carrying a
2.6.31.8 Linux kernel on 32-bit ARM, and its web plane is a lighttpd server that serves a PHP
application for pages and thirteen CGI binaries for control actions. The firmware is a rebranded
platform: the lighttpd configuration names `document-root=/NUUO/web/` and aliases the CGI
directory with `alias.url += ( "/cgi-bin/" => "/NUUO/bin/" )`, and the device identifies itself
with `sw_ver_1=2.70b04` and `ServerType=DNR-326`.

One of those thirteen handlers is `cgi/dsk_mgr.cgi`, the disk-management CGI. It is the busiest
shell user in the firmware: it contains 66 `system()` call sites, far more than any other CGI on
the device. Like the rest of the codebase it dispatches on a form parameter named `cmd`, and one
of its dispatch values, `FMT_expan_diskmgr`, reaches the stripped handler function recorded at
`fcn.0000d5e8`. That function reads the disk-size field `f_sethdsize` with
`cgiFormStringNoNewlines` into a 0x40 buffer, and then does something the rest of the firmware
deliberately avoids: it interpolates the field into a shell command line with `sprintf` and hands
the result to `system()`.

The command it builds is the volume-expansion call for the secondary disk:

```c
sprintf(&uStack_280, "diskmgr -s %s -y sdb > /dev/null &", auStack_60);   /* 0xd698 */
system(&uStack_280);                                                      /* 0xd6c8 */
```

The field is not quoted and is not escaped. The only filter between the HTTP request and that
`sprintf` is `cgiFormStringNoNewlines`, the libcgic helper recorded at `0x5420` in
`lib/libcgic.so` - a wrapper around `fcn.0000576c` whose entire transformation is to strip
carriage return (compared against 0xd at `0x57dc`) and line feed (compared against 0xa at
`0x57e8`) and to collapse runs of them. Every shell metacharacter survives that pass verbatim:
the semicolon, the pipe, the ampersand, the dollar sign, backticks and the parentheses. The helper
name is accurate and the guarantee it offers is much narrower than the one the handler assumes -
it is a newline stripper, not a shell sanitizer. Inserting `;` therefore ends the `diskmgr -s`
argument, the text that follows is parsed by `/bin/sh` as a new command, and a trailing `#`
comments out the rest of the original line.

Three further handlers in the same binary repeat the pattern with different parameters and
different `diskmgr` invocations: `FMT_expan_replace_diskmgr` at `fcn.0000d754` with
`f_sethdsize`, `cgi_create_diskmgr` at `fcn.0000e8fc` with `f_filesystem` and `f_sethdsize`, and
`FMT_rebild_diskmgr` at `fcn.0000edd8` with `f_dev`. They are one root cause with four entry
points, and a fix that touches only `FMT_expan_diskmgr` leaves the other three live.

The authentication boundary is the device's own administrator session, so the finding is
Authenticated: the disk-management handlers are dispatched only after the `cgiMain`
login check at `fcn.0000aa64` returns success, and that check is a session cookie read plus
`wto_check_login` from the vendor's session library. The record also documents a localhost-trust
branch inside `wto_check_login` - the function compares the request's `REMOTE_ADDR` against the
string `127.0.0.1` at `0x3ac8` and returns "authenticated" on a match - but that branch is not
remotely reachable, because the device's lighttpd configuration loads only `mod_alias`,
`mod_fastcgi` and `mod_cgi`, with no `mod_extforward` and no `mod_proxy`, so `REMOTE_ADDR` is the
TCP peer address and cannot be set through a header. The published chain consumes an
administrator session; it does not bypass authentication, and it is not affected by any
administrator password change.

On the device the CGI handler is launched by the lighttpd configuration that sets its runtime user
to root, so command text delivered this way inherits device-root authority. That identity is a
reading of the firmware's own launch configuration, not a hardware measurement, and section 9 of
the analysis keeps the distinction explicit: the dynamic evidence in this record comes from a
sink-level replication of the exact construction `diskmgr -s %s -y sdb > /dev/null &` behind a
local HTTP endpoint on the researcher's workstation, where each recorded vector executed and a
benign control did not. The identity observed inside that replication was the
workstation's own unprivileged account - it is not a root observation. Root on the appliance
remains a firmware-derived inference, and this advisory states it as such rather than presenting
it as a live-device result.

- Component: `/cgi-bin/dsk_mgr.cgi` in firmware v2.70b04 of the D-Link DNR-326 network video
  recorder (32-bit ARM, CramFS rootfs of 2407 files, kernel 2.6.31.8), served by lighttpd with
  `document-root=/NUUO/web/` and the CGI alias to `/NUUO/bin/`; dispatch value
  `cmd=FMT_expan_diskmgr`, handler `fcn.0000d5e8`
- Sink: `system("diskmgr -s %s -y sdb > /dev/null &")` with the request field interpolated
  unquoted - the `sprintf` at `0xd698` and the `system` call at `0xd6c8` - executed through
  `/bin/sh -c`
- Source: the form field `f_sethdsize`, read by `cgiFormStringNoNewlines` into a 0x40-byte stack
  buffer, with the companion field `f_web` (0x20 bytes) selecting between a static-copy branch and
  the interpolating branch
- Sanitization: `cgiFormStringNoNewlines` (`lib/libcgic.so` at `0x5420`, wrapper around
  `fcn.0000576c`) strips only CR and LF; no shell metacharacter is filtered anywhere between the
  HTTP field and `system()`
- Sibling instances: `FMT_expan_replace_diskmgr` (`fcn.0000d754`), `cgi_create_diskmgr`
  (`fcn.0000e8fc`) and `FMT_rebild_diskmgr` (`fcn.0000edd8`), same root cause, same binary
- Public record: no identifier assigned

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network - the vulnerable action is an ordinary form POST to the NVR's web
  interface, a service that answers over the network the appliance is installed on; nothing in the
  chain requires local console access, physical proximity or a same-link position
- Attack Complexity: Low - one well-formed authenticated POST is the entire detonation; there is no
  race, no timing window, no memory groom, no second request and no state that must already exist
- Privileges Required: High - the request must carry a valid administrator session cookie for the
  NVR web interface, and the disk-management dispatch is gated behind that check, so the attacker
  is the device administrator acting through the interface the firmware intends for exactly this
  operation
- User Interaction: None - the credential holder drives the request directly; no second party is
  asked to click, open or confirm anything
- Scope: Unchanged - the injected command runs on the appliance itself, inside the authority of the
  CGI process whose parameter was abused; no crossing into another security authority is claimed
- Confidentiality, Integrity, Availability: all High - arbitrary command execution as the
  root-configured CGI identity yields the appliance's recorded video, its configuration and
  credential material, its storage layout, and the ability to stop or destroy the recording service
- CWE: CWE-78 (improper neutralization of special elements used in an OS command)

Privileges Required is High and not Low because the neighbouring tier does not exist on this
product. The gate recorded in the firmware is a single administrator session check - `cgiMain`
calls `fcn.0000aa64`, which reads the session cookie and validates it through `wto_check_login` -
and the research record identifies no second account class on the DNR-326 web interface with reach
to `/cgi-bin/dsk_mgr.cgi`. There is no viewer, operator or guest tier documented in the artifacts
that can invoke a disk-management action. Filing this as Low would require inventing a
lower-privileged principal that the device does not ship, and PR:L is precisely that invention.
The honest reading is that this is a full-administrator finding whose severity comes from what the
administrator session is allowed to do to the shell, not from who can obtain the session.

A rejected reading, printed here so the arithmetic can be checked against it: treating the same
chain as if a hypothetical lower-privileged web user could reach it gives
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High, with ISS = 1 - (1-0.56)^3 = 0.914816,
Impact = 6.42 x 0.914816 = 5.873119, Exploitability = 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255,
and the sum 8.708373 rounded up to 8.8. That reading is rejected because PR:L would require the
low-privilege principal this firmware does not define; 8.8 is the arithmetic of a population the
product does not have, and it is not the published score.

The published arithmetic for the headline reading: ISS = 1 - (1-0.56)^3 = 0.914816, so
Impact = 6.42 x 0.914816 = 5.873119, and Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 =
1.234708; the sum is 7.107826, rounded up to 7.2. Scope is Unchanged, so no scope multiplier
applies and the formula caps at 10.0 without being reached.

## Affected Products

- D-Link DNR-326 16-channel network video recorder, firmware v2.70b04, image
  `DNR-326_Ax_v2.70b04.bin`, 32-bit ARM, CramFS rootfs of 2407 files, kernel 2.6.31.8 - the version
  analyzed at binary level end to end. Affected component: `cgi/dsk_mgr.cgi`, reached as
  `/cgi-bin/dsk_mgr.cgi` behind the administrator session, with four vulnerable dispatch paths
  (`FMT_expan_diskmgr`, `FMT_expan_replace_diskmgr`, `cgi_create_diskmgr`, `FMT_rebild_diskmgr`)
- Authentication class: Authenticated. The vulnerable dispatch is reachable only after the
  `cgiMain` login gate at `fcn.0000aa64` returns success, which means a valid administrator session
  on the NVR web interface. The localhost-trust branch in `wto_check_login` is recorded as
  a secondary observation and is not remotely reachable on this firmware, so it is not part of the
  affected path
- Not claimed: no other D-Link model and no other DNR-326 firmware version was analyzed for this
  handler family; the four sibling handlers are claimed as the same root cause inside the analyzed
  binary, not as an inference about other builds. The rebrand provenance of the platform is
  described as a firmware observation, not as a statement about the originating vendor's products
- Verification method and its boundary: firmware-level disassembly established the handler, the
  dispatch values, the source parameter, the sanitizer's exact behaviour and the shell
  construction; dynamic evidence comes from a sink-level replication - a local HTTP endpoint on the
  researcher's workstation reproducing `diskmgr -s %s -y sdb > /dev/null &` and executing it
  through `/bin/sh` - in which each recorded vector created a marker and a benign control did
  not. No physical DNR-326 was driven, no live request was fired at device hardware,
  and the replication ran under an unprivileged local account, so no root marker was observed
  anywhere in this record
- Privilege ceiling: arbitrary command execution as the CGI identity, which the firmware's
  lighttpd launch configuration sets to root, therefore device-root authority on the appliance.
  Not reached and not claimed: escape from the appliance to camera networks or attached hosts,
  persistence across factory reset or reflash, and any memory-corruption primitive

## Impact

- Complete operating-system compromise of a surveillance recorder by someone who was only ever
  meant to hold a web session on it: the disk-management page becomes an arbitrary-command channel,
  and with it the whole appliance - recording service, retention policy, disk layout and network
  configuration
- Loss of the recorded video itself, which on an NVR is usually the most sensitive data on the
  device: at root authority an attacker can read, copy, stage or destroy the footage the appliance
  exists to protect, including footage recorded before the attacker's session began
- Disclosure of every credential the appliance stores for its own operation - administrator
  accounts, camera and share credentials, and any configuration material readable at root - which
  hands over the surrounding surveillance network as a second stage
- Integrity impact on the evidentiary record: an attacker with shell access can manipulate the
  disk-management and recording state this very interface reports, so what the operator sees in the
  web console is no longer trustworthy
- Availability impact at will, coarse and surgical: the recording service can be stopped outright,
  or the disk-management path that this chain lives in can be driven with arguments that leave the
  storage subsystem in a state the operator must rebuild by hand
- Persistence consistent with root command execution on an embedded Linux system - startup
  scripts, accounts, scheduled work - within the writable areas of the appliance. What survives a
  factory reset or a firmware reflash was not tested and is not claimed
- The finding materially changes what an administrator password is worth on this product. Before
  it, a leaked NVR web password bought footage review and configuration changes; after it, the same
  password buys a shell on the recorder, and the recorder is normally the most trusted host on a
  camera VLAN
- The chain is quiet in product terms: one authenticated POST inside a legitimate storage-management
  action, with no malformed request, no crash and no response anomaly that the appliance would
  surface as an error

## Mitigation / Fix Recommendations

1. Treat `f_sethdsize`, `f_filesystem` and `f_dev` as untrusted tokens, not as text. Validate each
   against an allowlist of the shape the `diskmgr` command actually needs - digits for a size, a
   device identifier from a fixed set for `f_dev` - and reject anything else before the value is
   used. A size field has no legitimate reason to contain a semicolon, a pipe or a dollar sign, so
   set membership is a complete control here where a blocklist is not
2. Remove the shell from the disk-management path. The handler already has `diskmgr` available as a
   program; the correct construction is an argument-array execution (`execv`/`execvp`, or the
   `safe_system`/`safe_exec` helper the same binary already uses elsewhere) with `-s`, the size, and
   `-y sdb` as separate arguments. That removes the parsing layer entirely instead of trying to
   predict which characters matter to it
3. If a shell string has to survive one release cycle, single-quote every interpolated value with
   literal single-quote escaping, and add a post-construction assertion in the handler that the
   finished command contains no byte from a shell-metacharacter set; fail the request when the
   assertion trips rather than logging and continuing
4. Fix all four handlers in one change, not one at a time. `FMT_expan_diskmgr` (`fcn.0000d5e8`),
   `FMT_expan_replace_diskmgr` (`fcn.0000d754`), `cgi_create_diskmgr` (`fcn.0000e8fc`) and
   `FMT_rebild_diskmgr` (`fcn.0000edd8`) share the root cause, so a single-handler patch would leave
   three equivalent entry points and would misrepresent the fix as complete
5. Audit the remaining shell surface of the same binary rather than this call site alone.
   `dsk_mgr.cgi` carries 66 `system()` call sites, and the research record distinguishes the ones
   that pass static string pointers from the ones that interpolate request data. The ones that
   interpolate are the workload; the ones that do not should be left alone so the change stays
   reviewable
6. Drop the CGI privilege level. The firmware launches the web stack's CGI handlers as root, which
   is why an injection in this handler is a root compromise rather than a service compromise. A
   dedicated unprivileged identity for the CGI, with only the device nodes the disk-management
   action needs, does not fix the injection but caps what the next one in this family costs
7. For operators with no patch available: keep the NVR web interface off any untrusted network,
   never expose it to the internet, restrict management access to an administrative VLAN or a
   jump host, rotate the administrator credential if the interface has ever answered on a shared
   network, and treat an unexpected `diskmgr` invocation or an unexpected disk-management state
   change in appliance logs as a possible command-execution indicator rather than a storage fault
8. Add a regression test at the handler level: submit a disk-management request whose size field is
   `;id;#` and assert that the handler either rejects the value or produces no shell execution;
   repeat with the pipe and command-substitution forms, and run the suite against every dispatch
   value of the CGI rather than only the one this advisory names

## References

- https://0day-rubbish.com/blog/dsk-mgr-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
