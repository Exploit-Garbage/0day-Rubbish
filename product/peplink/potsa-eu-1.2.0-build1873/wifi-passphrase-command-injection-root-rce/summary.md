# Peplink PotSa EU fw-potsa_eu-1.2.0-build1873 - Unauthenticated WiFi Passphrase Command Injection in web_httpd Executing with Root Authority

Advisory: https://0day-rubbish.com/blog/wifi-passphrase-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Peplink is a networking vendor whose product line includes the PotSa EU, a point-of-sale terminal security
appliance: a compact Linux/ARM device deployed on a retail network to mediate and protect the network
access of point-of-sale terminals. The firmware analyzed for this advisory is
fw-potsa_eu-1.2.0-build1873, distributed as the uImage package APB2-EU_PKG-v1.2.0. Its management plane is
not a stock web server. The device runs `/usr/sbin/web_httpd`, a Peplink-authored HTTP daemon
(598548 bytes, stripped, ARM 32-bit EABI5 little-endian, hard-float, BuildID `ba6a2fe9`, SHA256
`cd3936518c670f86bd3c8d3ba42a735ed6e15799e2d9027bc813b65dfa940969`), which both serves the administrative
pages and dispatches the device's form actions. Every WiFi configuration page on the appliance ends at one
of those actions, and the handler behind the basic WiFi setup form extracts the WPA/WPA2 mixed-mode
passphrase as a plain string and forwards it to a small internal helper without ever leaving the process.

That helper is recorded at `fcn.00021430`, at address `0x21430` in the stripped image. Its stated purpose
is modest: percent-decode three characters (`%3C` to `<`, `%3E` to `>`, `%26` to `&`) out of a
caller-supplied string. It implements that decode by shelling out. A `snprintf` call at `0x214d4` formats
the pipeline `/bin/echo '%s' | /bin/sed 's/%s/</g' | /bin/sed 's/%s/>/g' | /bin/sed 's/%s/\&/g'` from the
format literal at `0x6d828`, and the finished string is handed to `popen(buf, "r")` at `0x21500`. The
attacker-controlled passphrase is substituted for the first `%s`, inside single quotes, and the helper
escapes nothing: not the single quote, and not the semicolon, the pipe, the backtick, the dollar-parenthesis
form or the bare parentheses. A passphrase that contains a single quote therefore closes the quoted
argument of `/bin/echo`, and the remainder of the passphrase is parsed by `/bin/sh` as further commands.
`web_httpd` runs with root authority - the firmware image launches it without any setuid or setgid
transition - so the shell pipeline, and any command injected into it, runs as root.

The path that reaches this helper carries no session requirement, and that is the part of the finding that
raises it above an authenticated misconfiguration. In the daemon's main request handler, the URL
classifier at `fcn.0000eba0` returns 1 for the `/mtadmin-goform/` prefix, and the comparison at `0x12d60`
branches past the `logged_in=yes` cookie check at `0x12d78` for every request under that prefix. The
dispatch cascade that follows reaches `0x13e0c`, a call into the action dispatcher at `fcn.00010490`, with
no authentication call anywhere on the way. The daemon does contain digest-authentication routines and a
401 response string, but the routines have no cross-references in the image and the 401 string is unused;
the response helper that references the digest challenge is a generic HTTP response sender, not a
validator. The consequence is a WiFi setup action that answers a request with no cookie and no
`Authorization` header, and hands the passphrase straight to the shell. The device's factory-default
`admin`/`admin` pair is a separate weakness disclosed on its own (CWE-798) and is not the vector here:
this chain needs no credential at all, and changing every administrator password on the device does not
narrow it.

The verification boundary belongs in the summary rather than in a footnote. The dynamic evidence for this
advisory is a sink-level replication on an isolated sandbox: the recorded exploit reproduces, byte for
byte, the command string that `fcn.00021430` constructs - the format literal from `0x6d828` with the
passphrase, `%3C`, `%3E` and `%26` substituted - and executes it through `/bin/sh -c`. A benign passphrase
with no shell metacharacters produced no marker and exited 0; the injective payload produced a marker file
containing `uid=0(root) gid=0(root) groups=0(root)`, owned by root (uid 0, gid 0), 39 bytes. Full-device
emulation of the appliance was attempted and did not succeed, because the firmware's ARM hard-float
userland depends on private NVRAM and factory data that the image does not carry; the unauthenticated
reachability of the action is therefore established at disassembly level, from the request handler, the
URL classifier, the cookie gate and the dispatch path, and the injection behaviour at the sink is
established by the replication. No live device was driven and no HTTP request was sent to device hardware
during verification.

- Component: `/usr/sbin/web_httpd`, the Peplink management daemon of firmware fw-potsa_eu-1.2.0-build1873,
  reached over the appliance's administrative HTTP plane through the form action
  `/mtadmin-goform/basic_wifi_setup.action`
- Sink: `popen()` at `0x21500`, fed by `snprintf` at `0x214d4` with the format literal at `0x6d828`, in
  the helper recorded as `fcn.00021430` at `0x21430` (debug name `decodeURIComponentLite`)
- Source: the `text_wpawpa2_mixed_mode_passphrase` form field (literal at `0x6efd4`), read by the action
  handler at `0x2484c` through the generic form getter at `0x24970`, gated only by a branch on
  `select_network_auth` at `0x24b40`
- Missing sanitization: the passphrase is copied with `strncpy` (limit `0x7f`) at `0x24b98` and then
  embedded unescaped inside single quotes, so a single quote in the passphrase is a complete breakout;
  nine call sites of the same helper exist in the daemon, all with the same root cause
- Authentication: none required - the `/mtadmin-goform/` prefix skips the cookie check at `0x12d78`, and
  no authentication call exists on the path to the dispatcher at `fcn.00010490`
- Observed identity: `uid=0(root) gid=0(root) groups=0(root)`, marker file 39 bytes, owner root (uid 0,
  gid 0), produced by the injected `id` inside the sink-level replication
- Verification method: sink-level replication on an isolated sandbox (exact sink command string executed
  through `/bin/sh -c`) with a benign control; request path and reachability established at disassembly
  level; no live-device HTTP round trip
- Classification: CWE-78 primary, CWE-798 adjacent and disclosed separately
- Score: 9.8 Critical, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Identifier: no CVE identifier assigned; the research record names none and requests none here

In operational terms the finding is a short one. A device of this class usually sits inside the retail
network it is meant to protect, is administered from a management station, and holds the configuration
that governs how point-of-sale terminals reach the store's payment infrastructure. An attacker who reaches
its management plane over HTTP does not need to log in, does not need to know any password, and does not
need to win a race; one form post carrying a passphrase with a single quote in it is the whole detonation,
and what executes is a root shell command inside the appliance. The technical analysis that follows
documents each link of that chain at instruction level, states which links are disassembly-level and which
were observed dynamically, and closes with concrete remediation.

## CVSS Score

- Score: 9.8 Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- Arithmetic of that vector: ISS 0.914816, Impact 5.873119, Exploitability 3.887041, base sum 9.760160,
  rounded up to 0.1 precision gives 9.8
- Attack Vector: Network - the sink is reached by an ordinary HTTP form POST to the appliance's management
  daemon, so the attacker's position is a network position rather than a local console or a physical port
- Attack Complexity: Low - a single well-formed POST with one form field set is sufficient; there is no
  race, no heap groom, no state machine and no second request needed to trigger execution
- Privileges Required: None - the `/mtadmin-goform/` prefix is classified as an administrative URL by
  `fcn.0000eba0` and the handler branches past the `logged_in=yes` cookie check at `0x12d78`, so an
  unauthenticated request is dispatched to the action handler at `0x2484c`; no credential of any kind is
  consumed
- User Interaction: None - the attacker sends the request directly; no administrator has to open a page,
  click a link or approve anything
- Scope: Unchanged - the injected command runs inside the appliance, within the authority of the component
  whose interface was abused; no crossing into another security authority is claimed
- Impact C/I/A: all High - root command execution on the appliance yields the complete configuration store,
  full control of the network functions the device performs for its terminals, and total control of
  availability
- CWE: CWE-78 primary (OS command injection through a shell-interpreted argument); CWE-798 adjacent and
  reported separately (factory-default administrative credentials), not part of this chain

Why Privileges Required is None rather than the neighbouring tier: the metric asks what an attacker must
hold before using the vulnerable component, and the answer on this path is nothing. The WiFi setup action
is dispatched to its handler without a session, without a cookie and without an `Authorization` header,
because the URL classifier at `fcn.0000eba0` returns an administrative classification for the
`/mtadmin-goform/` prefix that causes the request handler to branch past the cookie gate at `0x12d78`, and
because the dispatch cascade that follows contains no authentication call before `fcn.00010490`. The
daemon's own authentication routines (`web_handle_auth` at `0x7e1b0`, `cgi_login_auth` at `0x80fa8`,
`dig_do_authentication` at `0x818f8`) have no cross-references in the image, and the 401 string at
`0x6b7c0` is unreferenced, so this is an absent gate rather than a gate that can be defeated. A
Low-privilege reading would be right only if a session were structurally required and merely
circumventable; the record shows the opposite.

One rejected reading is recorded here so it cannot be mistaken for an alternative published score. If the
WiFi setup action were treated as requiring a session, the vector would be
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, which computes to 8.8 (ISS 0.914816, Impact 5.873119,
Exploitability 2.835256, base sum 8.708375, rounded up to 8.8). That reading is rejected because it
assumes a gate that the analysed handler does not have; it is printed here only to make the choice of
Privileges Required auditable, and 8.8 is not an alternative severity for this finding.

## Affected Products

- Peplink PotSa EU (Point-of-Sale Terminal Security Appliance), firmware fw-potsa_eu-1.2.0-build1873,
  distributed as the uImage package APB2-EU_PKG-v1.2.0 - the image analysed at instruction level for this
  advisory, running Linux on 32-bit ARM (EABI5 little-endian, hard-float)
- Affected component: `/usr/sbin/web_httpd`, 598548 bytes, stripped, BuildID `ba6a2fe9`, SHA256
  `cd3936518c670f86bd3c8d3ba42a735ed6e15799e2d9027bc813b65dfa940969`; specifically the WiFi setup action
  handler at `0x2484c` and the decoding helper `fcn.00021430` at `0x21430` that it calls at `0x24bac`
- Dispatch entries involved: `basic_wifi_setup.action` (name literal at `0x67134`, dispatch table entry at
  `0x84d30`, handler `0x2484c`) and `advanced_wifi_setup.action` (name literal at `0x6714c`, table entry at
  `0x84d40`, handler `0x25430`), the latter reaching the same helper from `0x25e94`
- Same root cause, broader surface: nine call sites of `fcn.00021430` in the same binary -
  `0x24bac`, `0x25e94`, `0x282ec`, `0x2a670`, `0x2a798`, `0x2bb14`, `0x2c01c`, `0x61c34` and `0x61d88` -
  distributed across the WiFi setup form handlers; only the first was carried through dynamic replication,
  the other eight are established at call-site level
- Not claimed: firmware versions other than fw-potsa_eu-1.2.0-build1873 were not analysed, no other Peplink
  product line was assessed for this helper, and no deployment statistic for the appliance is asserted.
  The reachability of the management plane from a given network position is a property of the deployment,
  not a property this research measured on hardware
- Verification boundary: firmware-level disassembly established the format literal, the `snprintf` and
  `popen` calls, the caller chain, the URL classification and the absent cookie gate; dynamic evidence
  comes from a sink-level replication on an isolated sandbox in which the exact sink command string
  executed through `/bin/sh -c` produced a root-owned marker for the injective payload and none for the
  benign control. No physical appliance was driven: no live HTTP request was sent to device hardware, so
  the request path and the unauthenticated reachability are disassembly-level findings while the injection
  behaviour at the sink is a replication result. Root authority was observed inside the replication
  environment, under a harness that mirrors the image's launch context (no setuid or setgid transition);
  it was not observed on a physical unit

## Impact

- Complete compromise of the appliance by an attacker who never authenticated: the WiFi setup form becomes
  an arbitrary-command channel running as root, giving the attacker everything the device itself can do -
  interface and network reconfiguration, routing and filtering changes, and the full configuration store
- Exposure of every secret the appliance holds for its own operation, within the readable filesystem scope
  that root authority provides, including the configuration data that governs how it treats the terminals
  it protects
- Loss of the security function the product exists to provide: a device that mediates point-of-sale
  terminal network access, once under attacker control, can be made to admit, redirect or observe the
  traffic it was deployed to constrain
- Persistence consistent with root command execution on an embedded Linux system - startup scripts,
  accounts, scheduled tasks - up to the limits of the writable filesystem; what survives a factory reset
  or a reflash was not tested and is not claimed
- Availability impact at will, both coarse (service or device restart from the shell) and surgical
  (deletion or corruption of specific files from the same root context)
- Silent in product terms: the trigger is one form POST to a legitimate management action, with no
  authentication event, no failed-login record and no protocol anomaly for a monitoring system to key on
- Compounding effect: the same helper is called from nine sites in the daemon, so a fix applied only to the
  basic WiFi setup handler would leave the advanced and guest setup forms on the same code path

## Mitigation / Fix Recommendations

1. Remove the shell from the decode path. `fcn.00021430` exists to translate three percent-encoded
   characters; that is a five-line in-process substitution. Replace the `snprintf` plus `popen` construction
   with a direct memory transformation and delete the helper's dependence on `/bin/sed` and `/bin/echo`
   entirely. This removes the injection class on this surface instead of narrowing it
2. If a shell must remain in the path as an interim measure, quote correctly rather than not at all: wrap
   the value in single quotes and replace every literal single quote in the value with the four-character
   sequence that closes and reopens the quoted string, and reject the value outright if it still contains
   shell metacharacters after that transformation
3. Validate the passphrase against the character set a WPA/WPA2 passphrase is actually allowed to contain
   (printable ASCII, length 8 to 63, no control characters), and enforce it before the value reaches any
   command construction. A passphrase validator that rejects the single quote, the semicolon, the pipe, the
   backtick, the dollar sign and both parentheses makes every one of the nine call sites non-injectable
4. Fix the authentication model at the handler, not at the URL prefix. Each `.action` handler should assert
   a valid session itself, so that a prefix-classification mistake cannot silently expose a handler again.
   The dispatch path from `0x13e0c` into `fcn.00010490` currently performs no check at all
5. Either wire up or delete the dead authentication code. `web_handle_auth` at `0x7e1b0`, `cgi_login_auth`
   at `0x80fa8`, `dig_do_authentication` at `0x818f8` and the 401 string at `0x6b7c0` have no
   cross-references in the image; unreferenced security code is a standing hazard, because it makes the
   binary look protected while nothing calls it
6. Drop the daemon's privilege. `web_httpd` runs as root with no setuid or setgid transition; a dedicated
   unprivileged identity for the web plane would not fix the injection but would cap the blast radius of
   this and every future web-plane defect on the device
7. Until a firmware update is available: keep the appliance's management plane off any untrusted network
   segment, restrict administrative access to a dedicated management network or VPN, and treat the device
   as a perimeter component whose compromise is a store-network compromise. None of these measures removes
   the defect, and none of them should be reported as a fix

## References

- https://0day-rubbish.com/blog/wifi-passphrase-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com
- https://cwe.mitre.org/data/definitions/78.html
- https://cwe.mitre.org/data/definitions/798.html
- https://www.first.org/cvss/v3.1/specification-document

---
Written by the 0day Rubbish Research Team.
