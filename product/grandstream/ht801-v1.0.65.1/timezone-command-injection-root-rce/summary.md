# Grandstream HT801 SIP ATA v1.0.65.1 - time-zone setting command injection in gs_cpe's echo construction

Advisory: https://0day-rubbish.com/blog/timezone-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Grandstream Networks ships the HT series of SIP analog telephone adapters, the small gateways that put
ordinary analog handsets onto a SIP service: the HT801 is the single-port member, the HT802 adds a second
port, the HT818 carries eight FXS ports, and the earlier HT701 shares the same codebase. The relevant
software is not a web application but `app/bin/gs_cpe` - a 32-bit ARM ELF, dynamically linked against
uClibc and stripped - which is the device's TR-069 CPE management daemon. It processes
`SetParameterValues` from an auto-configuration server and it also processes the configuration changes an
administrator makes on the local webadmin pages. Both of those inputs end up in the same parameter
handlers, and one of those handlers is where this finding lives.

The handler is `set_selfdefinedtimezone_value` at 0x289f8. It does three things with the time-zone string
it is given: it derives the parameter's NVRAM key and stores the value there through `nvram_set_data()`,
it builds a shell command line into a stack buffer under a 0x100-byte bound with `snprintf()`, and it runs that line with
`system()`. The format string is `echo "%s">%s`, held in rodata at 0x655a1 and reached through the
pointer at 0x28a2c; the second conversion is the constant configuration-file path held at 0x28a28, which
the recorded command trace for this build expands to `/etc/config_tz`. The purpose is mundane - persist a
setting by echoing it into a file - and the implementation is the defect: the administrator's value is
interpolated between a pair of double quotes with no escaping, no character screening and no length
validation, and the assembled string is handed to `system()`, which executes it through `/bin/sh -c`.

Everything downstream of that call is ordinary shell parsing. A time-zone value containing a double quote
terminates the `echo` operand early; a semicolon starts a new command; a trailing `#` comments out the
redirect the vendor intended. The payload recorded during this research, `BM"; id > /tmp/gs_cpe_c13; #`,
assembles into `echo "BM"; id > /tmp/gs_cpe_c13; #">/etc/config_tz`, and the run recorded for that
payload produced a marker containing `uid=0(root) gid=0(root) groups=0(root)`. The benign control value
`UTC-0800` assembled into `echo "UTC-0800">/etc/config_tz`, created no marker, and wrote the
configuration file correctly - the negative half of the evidence, and the reason the marker is
attributable to the injected text rather than to the surrounding construction. Because `gs_cpe` runs with
device-root authority, the injected command inherits that authority; `system()` does not drop privileges
and the daemon has none to drop.

The authentication boundary is the one the product defines, and the advisory states it rather than
arguing around it: reaching the time-zone setting page requires an administrator session on the device's
webadmin interface, which is the only account class that reaches this handler. Nothing in the chain
bypasses, forges or replays that session - it is consumed exactly as designed, and the defect is what a
legitimate authenticated request does with its parameter. The shipped default administrative credential
is `admin/admin`, but the finding does not depend on it: an administrator who has changed the password
still reaches the same page and the same handler, so credential rotation narrows nothing here. What the
chain does change is the meaning of the credential: it converts an operator of a settings page into an
operating-system-level principal on the gateway, which is a materially larger grant than the webadmin
interface was designed to convey.

The verification boundary matters and is stated in the same words used throughout this package. The
dynamic evidence in the research record is a sink-level replication: the recorded run reproduces the
handler's `snprintf()` construction and its `system()` execution, and observes the root marker inside
that replication environment. The record does not document a detonation against device hardware - no
webadmin request fired at a physical HT801 appears in it - so the request path (page to daemon to
handler) and the source of the value are established from the firmware analysis and the handler
reconstruction, while the execution behaviour at the sink is established by the replication. The root
identity is an observation from the replication environment, not a live-device reading, and no statement
in this advisory should be widened past that.

The finding is a plain metacharacter defect with no memory-safety component: the value never overflows
anything, the buffer is sized and the copy is bounded, and the injection needs no heap grooming, no race
and no second request. It is one authenticated form submission. That simplicity is why the fix is
architectural rather than cosmetic: the shell-out exists only to write one string into one file, and it
can be removed instead of sanitized.

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an authenticated administrator's
  time-zone value is executed as a shell command by a root-running management daemon, converting a
  settings-page write into arbitrary command execution on the device
- Attack Vector: Network - the value arrives over the device's network management plane on both recorded
  paths: the webadmin session that edits the time-zone page, and the TR-069 `SetParameterValues`
  exchange with the auto-configuration server the same daemon serves
- Attack Complexity: Low - one well-formed authenticated request, no race, no timing window, no memory
  corruption, no state machine, no second stage required
- Privileges Required: High - the handler is behind the administrator session; no lower-privileged
  account class reaches the time-zone page in the artifacts examined
- User Interaction: None - the credential holder drives the request directly
- Scope: Unchanged - the command runs inside the device, within the authority of the daemon whose
  interface was abused; no crossing into another security authority is claimed
- Impact C/I/A: all High - root command execution on the gateway yields the configuration and
  provisioning state the daemon itself manages, control of the processes and services on the device, and
  the ability to destroy or degrade its operation at will
- CWE: CWE-78

Privileges Required is High rather than the neighbouring Low tier because of what the product actually
exposes, not because of how the request is shaped. The research record's authentication verdict places
the sink behind the webadmin administrator account; the same sink is fed by the TR-069
`SetParameterValues` pipeline, which is an auto-configuration-server-to-device exchange and is likewise
not a lower-privileged principal's channel. No guest, user or read-only account class with reach to the
time-zone page was found in the artifacts examined, so there is no principal in this product to attach
Low privileges to. The distinction is not cosmetic: it separates "anyone on the LAN who can log in with a
limited account gets root" from "the device's administrator gets root", and only the second is supported
by the evidence.

The published score is the arithmetic value of the published vector. Impact Sub-Score is
1 - (1 - 0.56)^3 = 0.914816; Impact is 6.42 x 0.914816 = 5.873119; Exploitability is
8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; the sum is 7.107827, which CVSS rounds up to 7.2.

One rejected reading belongs here, with its own vector and its own arithmetic, so that it is not mistaken
later for an unstated alternative. Rejected reading A - the same chain with a hypothetical
lower-privileged web account: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High, whose
Exploitability is 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255 and whose sum with the same 5.873119 Impact
is 8.708374, rounded up to 8.8. It is rejected because the time-zone page has no such account class in
the artifacts examined, so the metric would describe a principal the product does not have. Rejected
reading B - an adjacent-network-only reachability assumption for the same authenticated principal:
`CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.8 High, whose Exploitability is
8.22 x 0.62 x 0.77 x 0.27 x 0.85 = 0.900611 and whose sum is 6.773730, rounded up to 6.8. It is rejected
because the recorded surface is not confined to a directly adjacent segment: the TR-069 path is a
server-to-device exchange across the routed network by design, and the published vector describes that
surface. Neither rejected figure is the headline and neither should be quoted as the rating of this
finding.

## Affected Products

- Grandstream HT801 single-port SIP ATA, firmware v1.0.65.1 - the version this advisory is scoped to;
  its shared `gs_cpe` time-zone handler is the one analyzed below, with the binary work performed on the
  HT802 proxy image listed further down
- Grandstream HT818 eight-port FXS SIP ATA, firmware v1.0.65.1 - same `gs_cpe` codebase and same
  vulnerable handler, at the same firmware version string
- Grandstream HT802 two-port SIP ATA, firmware v1.0.10.6 - the pre-extracted rootfs image the binary
  analysis in this advisory was performed on; it is the binary-analysis proxy for the shared codebase and
  contains the same handler
- Grandstream HT701 single-port SIP ATA - shares the same `gs_cpe` codebase; merged at root-cause level
  rather than claimed as an independently analyzed build
- Component: `app/bin/gs_cpe`, ARM 32-bit ELF, dynamically linked uClibc, stripped; vulnerable function
  `set_selfdefinedtimezone_value` at 0x289f8; format string `echo "%s">%s` in rodata at 0x655a1
- Not claimed: firmware versions other than those listed were not analyzed, and no statement is made
  about whether any particular later build is fixed or still affected; no other Grandstream product line
  was surveyed for this handler
- Verification method and its boundary: the request path, the parameter source and the handler are
  established by firmware-level binary analysis and handler reconstruction; the execution behaviour at
  the sink is established by a sink-level replication in which the injected value produced a
  `uid=0(root)` marker and a benign control value produced none. The root identity in the marker is an
  observation from the replication environment, not from device hardware
- Privilege ceiling: arbitrary command execution as the identity the daemon runs under, which the record
  states as device root; the marker above is the measured proof of that identity inside the replication.
  Not reached and not claimed: persistence across factory reset or reflash, effects on other hosts
  reached through the device, and any memory-corruption primitive

## Impact

- Arbitrary command execution as root on the gateway: the time-zone setting page becomes a shell, and
  everything the device can do the injected command can do - read and rewrite the configuration the
  daemon manages, replace binaries in the writable filesystem, start and stop services, and change the
  device's addressing, routing or name resolution where the platform allows it
- Exposure of the device's provisioning and service state to the credential holder: the same NVRAM store
  that `nvram_set_data()` writes, and the configuration file the vulnerable handler itself rewrites, are
  readable at root authority, so material the operator expected the web interface to summarise is
  available in full
- Control of the voice service the device terminates: a SIP analog telephone adapter exists to register
  handsets against a service provider, and root on the adapter is root on the component that holds and
  applies that service configuration
- A pivot position inside the network the adapter serves: the device sits on the customer premises
  network by definition, and code running as root on it can act from that position against the hosts and
  services the platform can reach
- Availability impact at will, coarse and surgical: services can be stopped, the configuration can be
  corrupted, and the device can be made to stop carrying calls without any further precondition
- Persistence consistent with root command execution on an embedded Linux system, within the limits of
  the device's writable filesystem; what survives a factory reset or a reflash was not tested and is not
  claimed
- Silence in product terms: the whole chain is one authenticated form submission against a page an
  administrator is entitled to use, with no crash, no malformed request and no traffic pattern that
  ordinary configuration logging would flag

## Mitigation / Fix Recommendations

1. Remove the shell from the write path. The handler's only purpose is to place one string into one file,
   and it does that by assembling `echo "<value>">/<path>` and calling `system()`. Open the configuration
   file directly and write the value with `open()`/`write()` (or the platform's NVRAM commit path if that
   is the intended store); a file write cannot be re-parsed by a shell, so the entire class disappears
   from this handler rather than being filtered for
2. If a shell construction must survive one release cycle, stop interpolating the raw value: pass it
   through single quotes with literal single-quote escaping, and assert after construction that the
   command contains no `"`, `;`, `#` or newline; fail the request on assertion. This is a stopgap, not a
   fix, because it leaves a shell parser between the administrator and the filesystem
3. Validate the value against the grammar the feature actually has. A time-zone setting is a bounded
   identifier - the benign control used in this research, `UTC-0800`, is representative - so an allowlist
   over the accepted forms plus an explicit maximum length is both sufficient and stable. Reject
   everything outside it before the value reaches any command, log or store
4. Drop the daemon's privilege. The record states `gs_cpe` runs as root, which is why the marker reads
   `uid=0`. A dedicated unprivileged identity with write access restricted to the configuration path it
   needs would not repair the injection, but it caps the blast radius of this and every future defect in
   the same daemon
5. Audit the daemon's remaining shell sites as a category, not a case. The record enumerates three
   `system()` imports and one `popen()`, and the same audit already examined two further constructions:
   `cpe_download_end` at 0x355c0/0x35608 (`prov_config_dec /proc/gxp/dev_info/dev_data <path>`) and
   `delete_upload_tmp_file` at 0x361ac (`rm /tmp/<name>`, where the name resolves to a hardcoded literal
   and is therefore not attacker-controlled). The first was left uncounted because the controllability of
   its path argument was not proven; that is a gap in the audit, not a clearance
6. Add a handler-level regression test: submit a time-zone value containing `";` and a value containing a
   bare `"` and assert that neither reaches a shell; repeat with the benign `UTC-0800` control and assert
   the configuration file is still written correctly. Run the same test against every model that shares
   the `gs_cpe` codebase, not only the HT801
7. For operators, until a patch exists: keep the webadmin interface and the TR-069 management channel off
   untrusted network segments, disable remote management where the deployment does not need it, keep the
   administrator credential out of shared use, and treat an unexpected shell marker or an unexplained
   configuration change on an adapter as a possible command-execution indicator. Changing the default
   `admin/admin` password is worth doing, but it is hygiene rather than mitigation - this chain consumes a
   legitimate session and does not care what the password is

## References

- https://0day-rubbish.com/blog/timezone-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
