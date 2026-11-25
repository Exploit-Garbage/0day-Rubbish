# NETGEAR R9000 (Nighthawk X10) - plex_net_dev MAC Argument Command Injection Executing as the Root-Configured CGI Stack

Advisory: https://0day-rubbish.com/blog/plex-net-dev-mac-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The NETGEAR R9000 (Nighthawk X10) is a flagship consumer router whose administrative plane is served
by the vendor's `uhttpd` web server on ports 80 and 443, with CGI dispatch under the `/cgi-bin` prefix.
Configuration on this platform lives in a shared key/value store, and one of the consumers of that store
is the helper program `/usr/sbin/plex_net_dev`, which the CGI handler `/usr/sbin/net-cgi` invokes to add,
edit and delete the "network drive" entries behind the Plex-related pages of the management interface.
The handler does not invoke that helper through an argument vector. It builds a command line by string
formatting, and it builds it in three steps: `config_get("plex_changed_mac")` is copied into a 32-byte
stack buffer, `/usr/sbin/plex_net_dev --add --mac %s --num %s >/dev/console` is formatted into a
128-byte stack buffer, and the result is handed to `system()`. There is no filter, no escaping and no
character-class check anywhere between the configuration store and the shell.

The value that fills the `%s` arrives from the management interface as the `hidden_net_mac` form field of
an authenticated POST to `/apply.cgi`. The add-handler at `0xa3e50` reads the field with the form getter
at `0x12c40`, applies a NULL check and nothing else, and stores it in the configuration key
`plex_changed_mac` through the setter wrapper at `0x21334`. The research record is explicit that this
path performs no MAC-format validation, no length gate on the value and no shell escaping. Because the
dispatch-setup stage of the same request (`0x13700`) raises the per-request dispatch flag at
`[0x141678+0x178]`, the sink function `fcn.000207e0` then runs inside that very request, in the
dispatch loop at `0x13850`. A single authenticated POST therefore both stores the attacker-supplied
string and executes it.

The sink is a textbook CWE-78 construction: an unquoted `%s` interpolated into a command line that is
handed to `system()` at PLT `0x0000afac`, which runs its argument through `/bin/sh -c` and thereby
re-parses the interpolated text as shell syntax. The recorded payload is `;id>/tmp/r9000_marker_v3;#`.
It is twenty-eight bytes long, so the 32-byte copy truncates nothing. Its leading semicolon terminates
the `--mac` argument and starts a new statement, the `id` redirection executes as that statement, and
the trailing `#` comments out everything the handler appended after the value, including the `--num`
argument and the console redirection. `plex_net_dev` itself never needs to run: the injected command is
a sibling statement, and the shell reaches it before the helper is ever looked up.

The privilege story is a post-authentication story, and it is worth stating precisely because it fixes
the severity arithmetic. `/apply.cgi` is gated by the `auth_token` cookie, which the binary enforces
fail-closed: the "Unauthorized" string sits at `0x000a6f32`, and login state is tracked through
`/tmp/is_login_%s`. The recorded request carries a legitimate administrator session. There is no
authentication bypass, no session forgery, no credential leak and no default-credential dependency in
this chain, and changing the administrator password does not narrow it by one character. What the chain
does is convert an administrator session into operating-system command execution: `/usr/sbin/net-cgi`
runs as root on this platform - the record attributes that identity to the web server configuration,
whose user is root - so command text substituted this way inherits root authority on the appliance.

The verification boundary belongs in the same breath as the impact. The dynamic evidence for this
finding is a sink-level replication: on a cloud-hosted x86-64 Linux sandbox, a native
`/bin/sh -c` was handed the exact `system()` argument reconstructed from the disassembly. The marker
file `/tmp/r9000_marker_v3` was created there with the content
`uid=0(root) gid=0(root) groups=0(root)`, and a benign control value produced no marker. Root was
observed inside the replication environment, not on R9000 hardware. No live request was fired at a
device, so the HTTP request path, the session gate and the parameter extraction are established at
disassembly level while the injection behaviour at the sink is established by the replication. The
`plex_net_dev` binary does not exist on the sandbox, which does not affect the result: the semicolon
ends the helper invocation before the shell reaches it, so the injected command runs independently of
the helper's presence, and a "not found" diagnostic from the helper would not suppress it.

- Component: the network-drive configuration handler of `/usr/sbin/net-cgi` (933403-byte ARM EABI5 ELF,
  stripped), the CGI handler behind `uhttpd` on the R9000, reached by an authenticated POST to
  `/apply.cgi` with `submit_flag=config_plex_net_add`
- Sink: `fcn.000207e0`, which copies the `plex_changed_mac` configuration value into a 32-byte buffer
  with `strlcpy` and formats `/usr/sbin/plex_net_dev --add --mac %s --num %s >/dev/console` into a
  128-byte buffer before calling `system()` (PLT `0x0000afac`), i.e. `/bin/sh -c`
- Source: the `hidden_net_mac` POST field, read at `0xa3fb0` through the getter at `0x12c40`, checked
  only for NULL at `0xa3fbc`, and written at `0xa4038` to the configuration key `plex_changed_mac`
  through the setter wrapper at `0x21334`
- Sanitization: none on this path - no MAC-format check, no character-class blocklist and no shell
  quoting between the form field and `system()`; the only bound is the 32-byte `strlcpy`, which the
  28-byte recorded payload does not approach
- Authentication: an administrator session, with the `auth_token` cookie enforced fail-closed; this is
  a post-authentication finding, not a bypass
- Observed identity: `uid=0(root) gid=0(root) groups=0(root)`, measured in the sink-level replication
  environment and attributed to the device through the web server's configured root user
- Classification: CWE-78 (improper neutralization of special elements used in an OS command)
- Published score: 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`

## CVSS Score

- Score: 7.2 High - `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
- Attack Vector: Network - the vulnerable handler is reached by an HTTP POST to the device's web plane
  on ports 80 and 443, so no physical or console access is part of the chain; the research record
  imposes no locality condition on that request path and does not examine whether the plane answers on
  a wide-area interface, and this advisory claims no deployment exposure beyond what the record states
- Attack Complexity: Low - one well-formed authenticated POST is the entire detonation; there is no
  race, no timing window, no memory-corruption groom and no multi-step state machine, and the sink runs
  in the same request that stores the value
- Privileges Required: High - the request is gated behind the administrator session the `auth_token`
  cookie represents, enforced fail-closed, and no lower-privilege account class into this CGI appears
  in the analysed artifacts
- User Interaction: None - no victim action is involved; the credential holder drives the request
  directly
- Scope: Unchanged - the substituted command runs on the router itself, inside the authority of the
  component whose interface was abused; no crossing into a beyond-device security authority is claimed
- Confidentiality, Integrity, Availability: all High - command execution as the root-configured CGI
  process yields the device's configuration store, its filesystem and its service availability
- Authenticated class: administrator session with the `auth_token` cookie, fail-closed
- CWE: CWE-78, OS command injection through a shell-interpreted argument

Why the privilege metric is High and not the neighbouring tier: the neighbouring tier is Low, and a Low
reading would describe a principal with reduced rights who can still reach the vulnerable handler. The
research record documents the opposite shape. The only gate on `/apply.cgi` is the `auth_token` cookie
obtained by logging in to the management plane, the check fails closed, and no second account class
with web access to this CGI appears anywhere in the analysed artifacts - the login is the device
administrator's login, and every request that reaches `fcn.000207e0` has already been made with
administrator authority. A privilege metric of High therefore describes the boundary the evidence
supports; Low would describe a boundary the record does not contain. High is also the highest tier
available, so no higher reading exists to consider.

Rejected reading, printed with its own vector and its own arithmetic: the research record itself
recorded this chain at 8.8, which is the arithmetic of the same impact profile scored at Low privileges,
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8. Its terms are ISS = 1 - (1-0.56)^3 = 0.914816,
Impact = 6.42 x 0.914816 = 5.873119, Exploitability = 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.836077, and
the sum 8.709196 rounds up to 8.8. That reading is rejected here, and the correction is the one
difference between the recorded figure and the published figure: 8.8 requires a principal holding
reduced rights on the web plane, and the artifacts document no such principal for this CGI, so a
request that reaches the handler carries administrator authority whatever vector is drawn around it.
The published arithmetic, for completeness: ISS = 0.914816, Impact = 5.873119,
Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708, and the sum 7.107827 rounds up to 7.2.

## Affected Products

- NETGEAR R9000 (Nighthawk X10) router, the image analysed end to end at binary level in this research:
  `/usr/sbin/net-cgi`, 933403 bytes, ARM EABI5 ELF, stripped symbols, served by `uhttpd` on ports 80 and
  443 with CGI dispatch under `/cgi-bin`. The research record identifies the model, the binary and the
  handler path but states no firmware version string for the image; this advisory therefore makes no
  version claim and instead pins the finding to those artifact properties, so that a reader can compare
  their own image's handler size, architecture and sink layout before treating it as affected
- Affected component within that image: the network-drive management path - the `config_plex_net_add`
  dispatch case, the add-handler at `0xa3e50`, the configuration key `plex_changed_mac`, and the sink
  function `fcn.000207e0` that formats the `plex_net_dev` command line
- Not claimed: other NETGEAR models are not asserted to share this handler because no other image was
  analysed here; the presence of a `plex_net_dev` helper on some other model would not by itself
  establish the same unvalidated source-to-sink path, and no such inference is made
- Not claimed: firmware versions other than the analysed image, including later builds that may have
  added validation to the `hidden_net_mac` field or changed the helper invocation
- Verification method and its boundary: firmware-level disassembly established the handler, the source
  field, the configuration key and the sink; dynamic evidence comes from a sink-level replication on a
  cloud-hosted sandbox in which the exact reconstructed `system()` argument was executed
  through a native `/bin/sh -c` and produced a marker containing
  `uid=0(root) gid=0(root) groups=0(root)`, with a benign control value producing none. No physical
  R9000 was driven: no live HTTP request was fired at device hardware, so the request path and the
  session gate are disassembly-level claims while the injection behaviour at the sink is a measured
  replication result. The replication ran as root by design, mirroring the root identity the record
  reads from the device's web server configuration
- Privilege ceiling: command execution as the CGI process identity, which the record identifies as root
  on this platform. Not reached and not claimed: escape from the router to attached hosts, persistence
  across factory reset or reflash, and any memory-corruption primitive - the chain contains no memory
  safety defect at all

## Impact

- Conversion of an administrator session into an operating-system shell: the management interface
  becomes an arbitrary-command channel running as the root-configured CGI process, which is a materially
  larger authority than the settings interface the session was issued for. The whole point of the
  finding is that the administrator of a settings page is not, by that fact alone, root on the appliance
- Exposure of every secret the device holds within the readable filesystem scope of that identity,
  including the configuration store that holds the credentials and keys the firmware needs for its own
  operation, and including any material staged under the temporary paths the CGI uses
- Full control of the device's networking semantics: interface configuration, routing, firewall state
  and the name resolution the attached network depends on, all of which a root shell on a router can
  rewrite at will. On a chokepoint device this is an interior attack position rather than a single-host
  compromise
- Persistence consistent with root command execution on an embedded Linux system - startup scripts,
  account changes, scheduled tasks - up to the limits of the writable filesystem. What survives a
  factory reset or a reflash was not tested and is not claimed
- Availability impact at will, both coarse (service control, reboot from the shell) and surgical
  (filesystem destruction from the shell the injected command now owns)
- The chain is quiet in product terms: one authenticated POST inside an ordinary management action,
  with no malformed request, no oversized body and no protocol anomaly that a request-shape heuristic
  would flag. The only distinguishing feature is a form field whose content is shell syntax, which is
  exactly the feature the handler fails to inspect

## Mitigation / Fix Recommendations

1. Validate the MAC field as a MAC field. The handler should accept `hidden_net_mac` only if it matches
   `^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`, and reject everything else before the value is written to
   the configuration store. The record establishes that today the only check is a NULL test, so an
   allowlist on this field is both the smallest and the most complete change available
2. Remove the shell from the helper invocation. `plex_net_dev` takes its arguments as `--add --mac
   <value> --num <index>`; that is an argument vector, and it should be executed with an
   `execve()`-family call and a real `char *argv[]` rather than formatted into a string and handed to
   `system()`. With no shell in the path, no metacharacter in the MAC value has any meaning, and the
   entire class disappears from this surface rather than being filtered
3. Stop storing a request value in a key that the sink trusts. `plex_changed_mac` is written from the
   form and read back by the sink, so validation has to happen at both ends or, better, the value
   should be passed in memory from the handler to the helper invocation and never round-tripped through
   the configuration store
4. If a shell-based invocation must survive one release cycle, single-quote the interpolated value with
   literal single-quote escaping, and add a post-construction assertion in `fcn.000207e0` that the
   compiled command line contains no byte outside the MAC alphabet and the fixed literal text; fail the
   request when the assertion trips instead of calling `system()`
5. Drop web-stack privilege. The record reads the CGI's runtime identity as root from the web server
   configuration. A dedicated unprivileged identity for `net-cgi` and its helpers would not fix the
   injection, but it would cap the blast radius of this defect and of every future one in the same
   binary, which is the component with the largest request-facing surface on the device
6. Audit the sibling paths in the same binary for the same shape. The `plex_net_action` value selects an
   `add`, `edit` or `delete` branch in `fcn.000207e0`, and all three branches interpolate values into
   the same command construction, so a fix applied only to the `add` branch would leave two live. The
   same audit should cover every `config_get()` result that reaches `system()` in `net-cgi`
7. Add a regression test at the handler level: submit `config_plex_net_add` with
   `hidden_net_mac=;id>/tmp/marker;#` and assert that the request is rejected or that no marker is
   produced, then run the same case with a benign `AA:BB:CC:DD:EE:FF` value to confirm the normal path
   still works. The control matters as much as the attack case, because the failure mode here is a
   handler that silently accepts everything
8. Until a patch ships, operators should keep the management plane off untrusted network segments,
   disable remote administration where it is not required, and treat the administrator credential as
   equivalent to a root shell on the device when deciding who holds it

## References

- https://0day-rubbish.com/blog/plex-net-dev-mac-command-injection
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
