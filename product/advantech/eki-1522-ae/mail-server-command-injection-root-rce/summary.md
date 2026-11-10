# Advantech EKI-1522-AE Serial Device Server D1.99_r3510 - Mail-Alarm Command Injection Through the Web Management Plane

Advisory: https://0day-rubbish.com/blog/mail-server-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Advantech is a Taiwan-based industrial automation and embedded computing vendor whose EKI line of serial
device servers connects legacy RS-232, RS-422 and RS-485 equipment to Ethernet and IP networks. The
EKI-1522-AE is a two-port member of that family: a small DIN-rail appliance built on a Winbond W90N740
ARM7TDMI system-on-chip, running uClinux 2.4.31 on a processor with no MMU, no address-space layout
randomization, no non-executable stack, no stack canary and no position-independent code. Its entire
administrative interface is a BoA 0.93 web server on port 80, and that server dispatches the configuration
forms to a CGI program, `/cgi-bin/index.cgi`, a uClinux BFLT flat binary of 299,384 bytes. A second
program, the daemon `edgserver` (a BFLT binary of 468,884 bytes), is started as root by the device's init
script and owns the event, alarm and notification machinery - including the notification path that shells
out to the system mail client.

The web plane authenticates with HTTP Basic Auth against a single password file that covers the whole
document root, and that file carries a single entry. Behind that gate, the alarm configuration form
writes operator-supplied values into the device's configuration store: the SMTP server address used for
notification, the sender address and one or more recipient addresses. The CGI handler
copies those values byte for byte into the configuration file after URL decoding, with a 128-byte
per-value limit, and performs no metacharacter screening of any kind. The configuration store itself keeps
them as raw strings; these fields are not addresses that get converted to integers, so nothing between the
request body and the shell collapses or normalizes the value.

The defect appears at the point of use. Both the CGI program and the daemon build the notification command
with `sprintf` from a fixed format string, `mail -s '%s (date) %s' -S %s -H %s -f %s %s`, and hand the
result to a `system()` wrapper whose disassembly is the textbook construction `execve("/bin/sh", ["sh",
"-c", command])`. Only the two subject fields sit inside single quotes. The SMTP server (`-S`), the sender
(`-f`) and the recipient list (the trailing `%s`) are interpolated outside any quoting, as is `-H`, which
carries the device's own address rather than operator input. A semicolon, a newline, a pipe or a `$( )`
substitution in any of those three operator fields is parsed by `/bin/sh -c` as command syntax rather than
as mail-client arguments. The substituted command runs in the daemon's own context,
which the device's init script establishes as root.

Exploitation is two authenticated POST requests, not one. The first writes the payload into the
configuration file through the alarm form; the second triggers a warm start, which writes the daemon's
warm-start sentinel and runs `killall edgserver`. At the next start, `edgserver` imports the configuration
file into its mail configuration structure and fires the notification path on the pass-change event,
which is where the string finally reaches the shell. A payload of the form `1.1.1.1$(id>/tmp/marker)`
in the SMTP server field therefore executes `id` as root after the device comes back up.

Verification was a sink-level replication on an isolated sandbox, not a live appliance. The shell command
line, the argument positions and the `system()` semantics were reproduced natively as `/bin/sh -c`, which
is architecture independent; the injected value was carried through all three unquoted fields - SMTP
server, sender and recipient - and each run produced a marker containing
`uid=0(root) gid=0(root) groups=0(root)`, while a benign control value with no metacharacters produced no
marker. The two-step boot-triggered data flow was established by static reconstruction of both binaries
rather than by driving hardware: no physical EKI-1522-AE, and no working emulation of the W90N740 platform
or of the mixed-endianness BFLT format, was available during this research. The record states that boundary
plainly, and this advisory keeps it.

This is an authenticated finding. It is not an authentication bypass and it is not a default-credential
finding: the factory-default `root:1234` credential pair on this product is disclosed separately as
CWE-798, and it is not the vector here. The vector is the command injection itself, which any holder of an
administrator session can reach, including a holder who has changed the password. No CVE identifier has
been assigned to this finding.

- Component: the alarm-notification command construction of the device web management plane - the CGI
  handler `fcn.0001d30c` in `/cgi-bin/index.cgi` (format string at `0x400a4`, five live call sites) and the
  daemon handler `fcn.000397cc` in `edgserver` (format string at `0x65bc4`), the latter being the one that
  fires at boot
- Sink: `system("mail -s '<subject> (date) <name>' -S <mailserver> -H <ip> -f <from_mail> <to_mail>")`,
  reaching `execve("/bin/sh", ["sh", "-c", command])` through the wrapper `fcn.00054140` at `0x4c548`
  in `edgserver` and the equivalent wrapper `fcn.0002e0e4` at `0x280d8` in `/cgi-bin/index.cgi`
- Source: the `func=setalarm` form fields `mailserver`, `from_mail` and `to_mail%d`, read by the parameter
  reader `fcn.00000998` after a standard CGI URL decode, stored through `fcn.0000fcd4` and committed to
  `/var/other1/edg.conf` by `fcn.0000f690`
- Sanitization: none on this path - the fields are limited to 128 bytes and URL decoded, but never screened
  for `;`, `|`, `&`, `$`, backtick or newline, and the configuration reader `fcn.0002d744` copies the stored
  string into the daemon's mail structure with a raw copy that applies no filter of its own

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network - the vulnerable plane is the device's HTTP management service on port 80, a TCP
  listener that answers over the routed network; the chain's transport is ordinary HTTP POST requests plus
  the device's own reboot cycle, with no adjacency requirement and no physical access
- Attack Complexity: Low - the exploit is a fixed two-request sequence against a documented form, with no
  race, no memory-corruption groom, no address leak and no configuration-dependent precondition beyond the
  mail alarm surface being present in the firmware
- Privileges Required: High - both requests require a valid administrator session on the web UI, the only
  account the device's password file defines; the credential is the boundary the vendor drew, and the
  finding consumes it rather than bypassing it
- User Interaction: None - the credential holder drives both requests directly, and the only other event in
  the chain is the device's own restart
- Scope: Unchanged - the executing authority is the device's own root daemon acting within the appliance;
  no crossing into another security authority is claimed
- Impact C/I/A: all High - command execution as the root daemon yields the complete configuration store,
  the password files, full control of the serial-port data path and service availability
- Published arithmetic: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827, rounded up to 7.2
- Why Privileges Required is High rather than the neighbouring tier: the injected command does not run until
  the daemon re-executes the notification path, and every write that arms that path is gated by the web
  login on the device's single password file. The credentials in that file belong to the administrator; the
  record identifies no second web account with access to the alarm form. A Low reading would
  assert an operator-level login that this product does not define, so the only defensible principal for
  this chain is the administrator, which is High. The fact that the factory image ships with a known default
  does not move the metric: CVSS scores the privileges an attacker must possess, not the difficulty of
  acquiring them, and the injection stays fully reachable after the administrator changes the password
- Rejected reading, recorded for completeness: the research record for this finding carried 8.8 for this
  chain, and 8.8 is the arithmetic of a Low-privilege reading of the same impact profile -
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High, whose Exploitability term is
  8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255 and whose sum with the same Impact of 5.873119 is 8.708374.
  That reading is rejected because the record identifies no lower-privilege web principal on this firmware
  to justify the Low value; it is printed here so the published 7.2 cannot be confused with it, and it must not be quoted
  as the rating for this finding
- CWE: CWE-78 primary (OS command injection through a shell-interpreted argument); CWE-798 adjacent and
  disclosed separately (factory-default administrator credential), reported without raising any metric

## Affected Products

- Advantech EKI-1522-AE two-port serial device server, firmware D1.99_r3510 (the image analyzed end to end
  at instruction level in this research): Winbond W90N740 ARM7TDMI, uClinux 2.4.31, BoA 0.93 on port 80,
  CGI `/cgi-bin/index.cgi` (299,384 bytes, sha256
  `e7cc5df6bf84710b2ee9c9a124416de2b3fc7e4707a740eb37921d8ba90078e8`) and daemon `edgserver` (468,884
  bytes, sha256 `a52ce55e3b0feb5f25432b035452b2957759c806b33554ec4d8d4bee2f5147f4`); the affected code is
  the mail-alarm construction in both binaries
- Same code family, not audited in this research: the sibling port counts of the EKI-1521 and EKI-1524
  models are recorded as an open item rather than a claim. The record lists them as a re-activation
  condition - a shared code base would carry the same construction - and this advisory does not assert that
  they are affected, because no binary from those models was examined here
- Not claimed: other Advantech product lines, firmware revisions of this model other than D1.99_r3510, and
  any behaviour on hardware configurations that differ from the analyzed image
- Verification method and its boundary, stated exactly: the finding was verified by sink-level replication -
  the recorded `system()` argument construction replayed natively as `/bin/sh -c` on an isolated
  cloud-hosted sandbox, which reproduces the shell's parsing of the command line without depending on the
  target's instruction set. All three unquoted fields were exercised (SMTP server, sender, recipient), each
  producing a marker containing `uid=0(root) gid=0(root) groups=0(root)`, and a benign control value
  produced none, so there is no false positive in the harness. Full-device emulation was not possible: no
  QEMU machine definition exists for the W90N740 platform, and converting the BFLT binaries to ELF is
  blocked by their mixed endianness. The request path, the configuration store, the boot-time re-read and
  the sink location are therefore established by instruction-level reconstruction of both binaries, while
  the shell-level behaviour is established by the replication. The privileged identity in the markers is
  measured inside the replication harness, which was run as root deliberately; the mapping to the appliance
  rests on the init script starting `edgserver` as root, read from the firmware as a product artifact, and
  not on a live-device observation
- Privilege ceiling: arbitrary command execution as the `edgserver` daemon, which the firmware's init
  script starts as root. Not reached and not claimed: persistence across a factory reset or reflash, escape
  from the appliance to attached serial or network hosts, effects on the serial protocol stacks, and any
  memory-corruption primitive

## Impact

- Complete operating-system compromise of the appliance by a credential holder who was never meant to hold
  a shell. The alarm-notification form becomes an arbitrary command channel running as root: the attacker
  obtains the full configuration store, the device password files, and the ability to rewrite every setting
  the web interface exposes, plus everything it does not
- Loss of the serial-port data path as a trust boundary. An EKI-1522-AE exists to carry raw serial traffic
  between attached industrial equipment and the IP network; root on the device means the attacker can
  observe, inject into or disrupt that traffic at will, and can reconfigure the serial operating modes so
  the change is not obvious from the equipment side
- Persistence consistent with root command execution on an embedded Linux system - modification of startup
  behaviour, of the account files, and of the configuration store that the boot sequence re-reads. What
  survives a factory reset or a reflash was not tested and is not claimed
- Availability impact at will: the device's own warm-start mechanism, which the exploit uses as its second
  step, is a legitimate management action; an attacker with this channel can restart the appliance, stop
  the daemon, or disturb the configuration until the device no longer serves its serial ports
- The chain is quiet in product terms. The requests are ordinary authenticated form posts inside the
  documented configuration workflow, the payload is a short string in a field that legitimately holds
  arbitrary text, and the configuration file that carries it is a file the administrator is expected to
  write. Log review that only records successful logins sees nothing unusual
- The two-step, boot-triggered nature limits timing - the command runs when the device restarts - but it
  also means the injected value persists in the configuration store, so the payload survives a power cycle
  and executes on every subsequent notification event until the field is cleared

## Mitigation / Fix Recommendations

1. Stop constructing the notification command with `sprintf`. Build the mail client's argument vector
   directly with `execve()` (or the device's own process-spawn helper) so that the SMTP server, sender and
   recipient values are passed as separate arguments and are never parsed by a shell. This removes the
   entire class from this surface, and it is the only change that does not depend on enumerating
   metacharacters correctly
2. If a shell must remain in the path for one release, single-quote all three fields with literal
   single-quote escaping, and reject any value containing `;`, `|`, `&`, `$`, backtick, newline, carriage
   return, `<` or `>` before the command is built. Add a post-construction assertion in the handler that the
   compiled command string contains no `$` outside the quoted subject, and fail the request on assertion
3. Validate the three fields by type rather than by character class. The SMTP server field should accept
   only a hostname or an IPv4 literal and be checked with the resolver or `inet_pton()`; the sender and
   recipient fields should be parsed against a strict address grammar and length-capped. Fields that hold
   addresses have no legitimate reason to carry shell metacharacters
4. Screen at both ends of the store. The web handler already knows the value is destined for a command
   line; the daemon's configuration import should not trust the file either. Adding the same validation at
   `fcn.0002d744`, where the value is copied into the mail structure, closes the path against a
   configuration file written by any other means
5. Drop the daemon's privilege. `edgserver` is started as root by the init script, but the alarm
   notification path needs no root authority. Running the daemon, or at least a notifier child, as an
   unprivileged identity does not fix the injection but caps the blast radius of this defect and of every
   future one in the same binary
6. Add a regression test at the handler level: submit an alarm form whose SMTP server field contains
   `$(true)`, whose sender contains a semicolon and whose recipient contains a newline, and assert that
   either the request is rejected or no child process is spawned. Run the same suite against every model
   that shares this CGI and daemon code base
7. For operators, until a patch exists: change the factory-default administrator credential, keep port 80
   off any untrusted network segment, and treat unexpected edits to the mail-alarm fields in
   `/var/other1/edg.conf` as an arbitrary-code-execution indicator rather than a configuration mistake.
   Restricting who can reach the web plane reduces exposure but does not fix the defect, because any
   administrator session remains a full command channel
8. Vendor note: the record finds no patch for these fields in any released firmware for this line, and it
   identifies D1.99_r3510 as the last release of the line. A fix therefore needs to be authored rather than
   backported, and the sibling port counts of the family should be reviewed against the same code

## References

- https://0day-rubbish.com/blog/mail-server-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
