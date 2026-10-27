# Raritan PX3 PDU G4 Firmware 4.3.14 - Diagnostics Ping and TraceRoute Command Injection through an Inverted Hostname-Validation Return Check, Reachable by Every Authenticated Session (CWE-78, CWE-20)

Advisory: https://0day-rubbish.com/blog/raritan-px3-pdu-g4-diag-ping-traceroute-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The Raritan PX3 PDU G4 from Raritan (a Legrand company, United States) is an intelligent rack power
distribution unit: per-outlet metering and switching, environmental sensing, and remote management over
its HTTPS web interface, a role-based CLI, and a large JSON/IDL-RPC API surface. Firmware 4.3.14
implements the ping and traceroute diagnostics by building a shell command string from the
operator-supplied hostname and handing it to /bin/sh: the strings, the shell invocation and the
command templates are all recoverable in the C++ library that services them. A hostname validation
function is called before the command is built - it walks the hostname character by character,
rejects percent signs and every character above ASCII colon, and rejects anything name resolution
fails on - and every one of its rejection paths returns the same value, three. The caller then makes a
single comparison against that value with a branch that rejects only strictly-greater results, so a
return of three - the function's rejection verdict - falls through, the rejected hostname is spliced
into the command template verbatim, and /bin/sh interprets it: this inverted return-value check is the
vulnerability, and it arms both the ping and the traceroute paths identically. The validators that
should have mattered are conspicuous by their absence: the same library exports a strict
fully-qualified-name validator elsewhere in the image, but the web daemon does not import it and the
diagnostics library does not link it on this code path. The shipped CLI configuration grants the ping
and traceroute commands to every authenticated user - the parallel netstat command carries an explicit
admin-only attribute - so the injector is reachable with a low-privilege session and not only with
the administrator account. The verification for this advisory is two-layered: the complete
root-cause chain is measured statically at instruction level out of the firmware image (every address
cited below is an image address), and the command-sink semantics of the recovered templates were
confirmed in a command-level replication on an isolated research host in which the three injection
shapes each spawned the marker command while the metacharacter-free control did not. Full-system
emulation of the management web stack was not performed and no physical unit was available, so
execution identity on the appliance was not measured at runtime and no headline claim about it is
made. The factory default credential recorded in the image is disclosed here as a separate adjacent
weakness, not as this finding's vector: the chain shown requires an authenticated session, and the
published vector scores it accordingly.

- Component: the diagnostics service of the product stack under test - /bin/httpd (the 1.8 MB C++ aarch64
  web daemon), /lib/libisys.so.1.0 (the isys system library whose isys::net::diag::ping and
  isys::net::diag::traceRoute implementations build the vulnerable commands), and /etc/clish/netdiag.xml
  (the shipped CLI instantiation of the same diagnostics), in firmware version 4.3.14
- Sink: the shell invocation opened as pp::BackgroundCommand::open(bgCmd, "/bin/sh", argv) at 0x36170,
  reached through runShellCommandAndGetResults() at 0x36094, which executes the template
  ping -c <count> -W <timeout> <HOST> 2>&1 and its traceroute sibling
  traceroute -w <timeout> -m 30 <HOST> 2>&1 via /bin/sh
- Source: the host parameter of the net.Diagnostics.ping and net.Diagnostics.traceroute RPC methods and
  the hostname argument of the corresponding CLI commands - operator-controlled, attacker-supplied when
  the attacker holds any authenticated session
- Sanitization: present but inverted, and therefore worse than none on this path -
  validateAndResolveHostName() at 0x5a3f4 does detect shell metacharacters (characters above ASCII
  colon, percent signs) and unresolved names, and returns the same three on each rejection - but the
  caller at 0x5a9fc accepts every result that is not strictly greater than three, so every rejection
  verdict is executed on rather than refused; the strict name validator exported by libnetwork.so is
  never consulted on this path

## CVSS Score

- Score: 8.8 High (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) - any holder of an ordinary
  authenticated session can convert one diagnostics request into operating-system command execution in
  the product's web-service context
- Attack Vector: Network - the management interface (HTTPS on the standard management port) is network
  reachable, and the JSON-RPC methods carrying the host parameter are exercised over it; the firmware is
  a remote-management product by definition
- Attack Complexity: Low - the injection needs no race, no environment condition and no parsing quirk;
  hostname rejection is not only survivable but is the exact state that carries the payload through
- Privileges Required: Low - the shipped CLI configuration /etc/clish/netdiag.xml defines ping and
  traceroute with no access attribute while the neighbouring netstat command carries access="admin",
  which documents the vendor's own intent to expose these two commands to every authenticated user;
  the web methods sit behind the framework's per-method authentication and we did not separately
  measure a role restriction below "authenticated" on the RPC channel beyond that documented
  equivalence
- User Interaction: None - no victim action is entailed; the attacker's own session drives the request
- Scope: Unchanged - the injected command executes in the process context of the web service that
  received the request; this advisory claims no crossing into a further authority
- Impact C-I-A: all High - one request gives command output exfiltration through the diagnostics
  response path, arbitrary command execution with the web service's account on the appliance, and full
  control of the appliance's availability - on a power distribution product, availability is the
  physical machine state, including outlet power
- CWE: CWE-78 (OS Command Injection) primary; CWE-20 (Improper Input Validation) co-equal in the form
  measured here - validation exists, produces the correct verdict, and the verdict is then discarded;
  the factory default credential is disclosed as a separate adjacent weakness (CWE-798 class) and is
  not folded into any score below
- Arithmetic: the source records carried 8.8 against this vector and the value was re-derived rather
  than inherited - ISS is 1 - (1 - 0.56) x (1 - 0.56) x (1 - 0.56) = 0.914816, impact is
  6.42 x 0.914816 = 5.869119, exploitability is 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, and
  5.869119 + 2.835255 = 8.704374 rounded up to 8.8
- Rejected reading: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical (impact 5.869119 +
  exploitability 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043, sum 9.756162 rounded up to 9.8) -
  rejected as this finding's score: the diagnostics methods sit behind the framework's per-method
  authentication, and no authentication bypass was measured, so the finding itself does not confer an
  unauthenticated primitive
- Conditional reading A - deployment still carrying the factory default account: the image records a
  default credential pair in its configuration default area for first-boot administrative access, and
  where an operator has never changed it, the practical bar for a network attacker collapses from
  "an authenticated session" to "the documented credential"; the same
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical then applies to the chain of the
  adjacent weakness plus this injection - labelled conditional because a changed credential removes
  it, and it is never the headline score; the default credential is reported as a separate weakness
  and this advisory's vector does not depend on it
- Conditional reading B - closed deployments with only administrative accounts: no low-privilege
  account is provisioned and no account exists outside the administrator role, so effectively every
  caller holds administrator privileges - `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 High
  (exploitability 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708, plus impact 5.869119, total 7.103826
  rounded up to 7.2) - conditional on a deployment choice the shipped CLI artifact does not reflect
  (the vendor's own ACL intent grants diag to all authenticated users), so it is not the headline score

## Affected Products

- Raritan PX3 PDU G4, firmware version 4.3.14, an intelligent rack power distribution unit (per-outlet
  metering and switching) from Raritan, a Legrand company - the aarch64 embedded Linux firmware image
  whose file set carries the affected /bin/httpd, /lib/libisys.so.1.0 and /etc/clish/netdiag.xml; only
  this firmware version was examined, and the finding is claimed only for it
- Affected components: the isys::net::diag::ping implementation at 0x5a988 and the
  isys::net::diag::traceRoute implementation at 0x5ab64 in /lib/libisys.so.1.0, their shared
  hostname-validation callee at 0x5a3f4, and the two RPC methods that reach them across the web
  management interface; the shipped CLI instantiations of the same two commands belong to the affected
  outer surface by the vendor's own ACL intent
- Adjacent weakness disclosed separately and not part of this advisory's vector: the firmware's
  default-configuration area records a factory default credential pair for first-boot administrative
  access. It is disclosed because it trivially compounds the injection in unconfigured deployments, and
  because it is a distinct defect with a distinct fix (forced first-login change). This advisory's
  finding - the inverted-validation command injection - does not depend on it and is scored with an
  ordinary authenticated session
- Verification method and its boundary: every static claim is measured from the firmware image - the
  command templates, the character loop, the converging rejection blocks, the caller's compare-and-branch
  sequence and the shell open are all cited at image addresses, and the two import checks (the web
  daemon's import list for the strict name validator; the diagnostics library's recorded dependencies)
  are binary-level facts. The dynamic layer is a command-level replication of the recovered sink
  semantics: the exact command templates were executed through a shell on an isolated research host
  under the three injection shapes, each producing the marker command's output, and a
  metacharacter-free control producing nothing. What was not done is end-to-end exploitation through
  the management interface of a physical unit: full-system emulation of the web stack was not
  performed because the management daemon's startup chain depends on the hardware storage layer that
  an image-only extraction does not provide, and no physical unit was available to this work -
  appliance-side execution identity was therefore not measured at runtime and no claim is made about it
- Privilege ceiling: the injected command runs with the privileges of the process hosting the
  diagnostics implementation - the web management daemon. Its identity on a unit was not measured in
  this work; the replication measured the invoking shell's account on the research host (its privileged
  account) and nothing about the appliance. Whether the daemon on the appliance runs as the system
  superuser is an appliance property that this advisory neither measures nor claims, and the score is
  deliberately written to hold whichever account that is. Not reached and not claimed: any escalation
  from the daemon's account, and any effect beyond the command output returned through the diagnostics
  response path

## Impact

- Operating-system command execution from the management interface of a power distribution product -
  the injected command is executed in the web service's process context rather than through any
  product-sanctioned facility, which removes the product's own authority model from the transaction
- Confidentiality of the appliance's management state within the web service's reach: the diagnostics
  response path returns command output to the requesting session, so arbitrary secrets readable to
  that account - configuration data, recorded credentials, network information - can be exfiltrated in
  the same channel that ping output arrives in
- Integrity of the appliance's management state: constructed commands run with whatever the web
  service's account lets them touch, which on a rack PDU firmware image includes the product's own
  configuration and state stores - the integrity impact is bounded by that account's reach and is not
  claimed beyond it
- Availability as a physical action: a PDU is the on-off switch of an entire rack, and the web
  service is the privileged path to outlet switching - so shell-level compromise of the service
  context implies the ability to power-cycle, and thereby to hard-stop, every machine fed by the unit;
  this consequence is an inference from the product's function (the same daemon hosts the outlet
  control surface) and is labelled as such, since the injected command's reach was measured only at
  the sink level
- Re-entry at will: both diagnostics methods accept repeated calls with fresh hostnames, so follow-up
  commands - staging, reading results, cleanup - are one request each, and the attacker never needs
  persistence inside the product to keep executing
- Weak detection surface: the triggering request is a legitimate diagnostics call that the product
  logs as a shell command, and the difference between an operator's ping and this injection is a single
  field value; shell-command log review for these two templates is the strongest available signal
- Compounding adjacent weakness, is disclosed separately: the factory default credential, where left in
  place, converts this authenticated injection into an unauthenticated-effect chain against unconfigured
  units - the conditional reading above exists for exactly that deployment state
- No claim beyond the measured chain: neither superuser execution on the appliance, nor lasting
  persistence, nor network pivot beyond the unit is asserted; each would require measurements this work
  did not make

## Mitigation

1. Stop building diagnostics commands as shell command strings: perform ping and traceroute through
   their library or raw-socket interfaces, or at minimum through an argv array passed to the binary
   with no shell interpreting the hostname at all - the entire CWE-78 class in this handler disappears
   with the /bin/sh round trip
2. Invert the inverted check today, as a one-line containment: the caller must reject every validation
   result outside the documented success set (the resolved-IPv4 and resolved-IPv6 returns), rather than
   accepting everything not strictly greater than the rejection value; the current comparison accepts
   the rejection verdict itself, which is the measured defect
3. Route both diagnostics entry channels - web RPC and CLI - through one hostname allow-list that
   accepts dotted-quad literals and strict fully-qualified names only, and reject before any command
   text is assembled; the firmware already contains a strict fully-qualified-name validator, and this
   path never consults it
4. Audit every other caller of the shared validation function for the same accept-on-reject
   comparison: the rejection value is a shared constant, and any caller comparing against it with a
   greater-than test reproduces this finding's shape
5. Remove the factory default credential from the shipped configuration and force a first-login change
   (or ship per-unit random credentials), which independently closes the conditional unauthenticated
   chain disclosed here
6. Add regression tests that drive the two diagnostics methods with an injection corpus - semicolon,
   subshell, newline, percent, pipe, backtick, space-padded and unresolved forms - and assert that no
   process is spawned and the response contains only diagnostics output; assert the same corpus through
   the CLI channel
7. Log diagnostics calls with the exact command text that was executed, so the shell-template logging
   the product already performs becomes an alertable signal rather than background noise
8. As operator measure until patched: change the factory default immediately, restrict management
   interface access to the operations network, prefer read-only or Role-Based accounts for monitoring
   integrations that invoke diagnostics, and alert on shell-command log lines that follow the two
   templates with any hostname that is not a literal address or strict name

## References

- https://0day-rubbish.com/blog/raritan-px3-pdu-g4-diag-ping-traceroute-command-injection
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
