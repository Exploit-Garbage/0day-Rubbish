# StoneFly SCVM 8.0.4.29 - iSNS Server Configuration ipaddress Command Injection Executing as Root

Advisory: https://0day-rubbish.com/blog/ff-isns-ipaddress-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

StoneFly SCVM (Storage Concentrator Virtual Machine) is the vendor's virtual storage appliance: an OVA
image that is imported into VMware ESXi, VirtualBox or KVM and administered through an HTTPS management
GUI on ports 80 and 443. That GUI is an Apache plus mod_perl deployment in which each screen is a Perl CGI
program under `/StoneFly/bin/`. The iSNS server configuration screen, `/StoneFly/bin/ff_isns.pl`, carries a
form field named `ipaddress` whose value is meant to identify an iSNS server. The script does not validate
that value as an address. It reads the field and interpolates it, with no escaping, into an argument
string for `StoneFly::firefly::sf_ping()`, the shared ping helper. The helper builds a ping command line,
writes it into a wrapper shell script under `/tmp` and executes the wrapper through
`sudo /usr/local/StoneFly/bin/command.pl`, an entry that `/etc/sudoers` authorizes for the Apache account
without a password. The wrapper therefore runs as root in a shell, and a value containing `$( )` is command
substituted by that root shell before `ping` is reached.

The result is a single-request escalation from a legitimate administrator session to arbitrary command
execution as root on the storage appliance. The payload
`127.0.0.1$(id >/usr/local/StoneFly/log/SF_isns_ROOT 2>&1)8.8.8.8` was submitted once through the form,
and the substituted command wrote a marker owned by `root:root` and containing
`uid=0(root) gid=0(root) groups=0(root)`. No CVE identifier has been assigned to this finding, and this
advisory attributes none.

- Component: the iSNS server configuration screen `/StoneFly/bin/ff_isns.pl` of the SCVM 8.0.4.29
  management GUI (Apache plus mod_perl, CentOS 6 based appliance stack, kernel
  2.6.32-696.el6.SF1.x86_64)
- Source: the `ipaddress` form parameter, read inside the `submit_form` branch and used with no address
  parser and no character filter between the request and the command string
- Sink: `StoneFly::firefly::sf_ping()` in `firefly.pm` (recorded at line 7917), which assembles
  `/bin/ping <arguments>`, writes the assembly into `/tmp/pingcommand.<ppid>.sh`, marks it executable and
  runs it through `sudo /usr/local/StoneFly/bin/command.pl`
- Privilege hop: `/etc/sudoers` carries `apache ALL=NOPASSWD: /usr/local/StoneFly/bin/command.pl`, and
  `command.pl` writes its argument into a file and executes that file, so the assembled string becomes a
  root shell script
- Authentication: a valid administrator session plus the CSRF token rendered into the iSNS page; the
  parameter names of this form are registered as administrator parameters in the shared session check.
  The request is one authenticated POST
- Verification: end-to-end against the vendor's own `SCVM.ova`, booted under QEMU system mode on an
  isolated host with the management port forwarded to a loopback-bound host port. Login, the CSRF token
  retrieval, the form POST and the marker file were all executed against the running appliance, and the
  marker was read back from the guest filesystem after a clean shutdown; root was observed inside that
  replication environment, not on physical hardware
- Family: the appliance-wide sweep recorded for this research found 44 CGI scripts reaching a shell
  through the same ping helper; `dns_server.pl` (primary and secondary DNS server addresses) and
  `ff_network_route.pl` (ping target address) are recorded as carrying the same root cause and were
  identified statically, not exploited separately

## CVSS Score

- Score: 7.2 High (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H) - an administrator of the storage
  appliance converts a routine address field in the iSNS configuration form into arbitrary command
  execution as root inside the appliance
- Attack Vector: Network - the management GUI is the appliance's administrative network service, reached
  over HTTPS on port 443 by administrators across the network; the loopback binding used during this
  research was an isolation measure of the test bed and is not a property of the product
- Attack Complexity: Low - one well-formed authenticated POST is the whole detonation; there is no race,
  no timing window, no memory groom and no multi-step state machine
- Privileges Required: High - the endpoint sits behind the management session and additionally requires
  that session's page CSRF token, and the form's parameter names are registered as administrator
  parameters in the shared session check; the record documents no lower-privilege account tier on this
  appliance that reaches this screen
- User Interaction: None - the credential holder drives the request directly; the CSRF token is read from
  the page the same client fetches, so it is a normal step of the legitimate flow rather than a victim
  action
- Scope: Unchanged - the substituted command runs inside the appliance, under the authority of the
  component whose interface was abused; no crossing into a separate security authority is claimed
- Impact C/I/A: all High - root on a storage appliance yields its complete configuration and credential
  material for the storage fabric, the data on the volumes it serves, and control over whether those
  volumes are served at all
- CWE: CWE-78, improper neutralization of special elements used in an OS command

Privileges Required is High rather than the neighbouring Low tier because the interface genuinely requires
the appliance administrator: the login is the management GUI's own login, the screen carries an
administrator-only parameter set in the shared session check, and the record identifies no secondary
account class with web access to this screen. A Low rating would require a principal who is authorized to
use the interface but is not an administrator, and no such principal is documented here. The neighbouring
tier below High - Low - is therefore not merely conservative to reject; it describes an account that this
product does not offer on this surface.

A reading that treated the same impact profile as reachable by a lower-privileged web user was considered
and rejected. Its vector is `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High, with ISS 0.914816,
Impact 5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, and a sum of 8.708374 rounded
up to 8.8. The arithmetic is correct for that vector; what is rejected is the privilege premise, because
the record establishes that the iSNS screen is administered by the appliance administrator and that no
lesser account reaches it.

Published arithmetic for the headline vector: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 =
5.873119; Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827, rounded up to 7.2.

## Affected Products

- StoneFly SCVM (Storage Concentrator Virtual Machine), version 8.0.4.29, the OVA distribution for VMware
  ESXi, VirtualBox and KVM; the analyzed image runs a CentOS 6 based appliance stack with kernel
  2.6.32-696.el6.SF1.x86_64. Affected component: `/StoneFly/bin/ff_isns.pl` in the Apache plus mod_perl
  management GUI, together with the `sf_ping` helper in `firefly.pm` and the privileged `command.pl`
  wrapper it calls
- The same root cause family is recorded in sibling screens of the same GUI: `dns_server.pl`, which feeds
  the primary and secondary DNS server addresses into the same helper, and `ff_network_route.pl`, which
  feeds a ping target address into it. Both were identified statically from the appliance's own scripts;
  neither was taken through a separate dynamic run
- Also recorded: 44 CGI scripts on the appliance reach a shell through the same ping pattern. The count is
  the recorded static sweep result, not a list of confirmed exploits
- Not claimed: StoneFly hardware appliances, other SCVM firmware versions, other StoneFly product lines,
  and any behaviour of a deployment whose management plane has been modified by the operator. No test was
  run against physical hardware
- Verification method and its boundary: the verification reproduced in this advisory is an end-to-end run
  against the vendor's shipped `SCVM.ova`, converted to a raw disk and booted under QEMU system mode with
  the kernel loaded directly, on an isolated host, with the guest management port forwarded to a
  loopback-bound host port. The appliance performed its own authentication and CSRF check; the marker was
  read from the guest filesystem after a clean shutdown and was owned by `root:root`. Root was therefore
  observed inside the QEMU appliance replication environment, on the vendor image, and not on physical
  hardware
- Privilege ceiling: arbitrary command execution as root on the appliance. Not reached and not claimed:
  escape from the appliance to the hypervisor or to iSCSI initiators, persistence across reinstall or
  re-import of the OVA, and any memory-corruption primitive

## Impact

- Complete compromise of the storage appliance by an account that was only ever meant to configure it: the
  iSNS address field becomes an arbitrary-command channel running as root, giving the attacker everything
  the appliance itself can do, including the configuration of the storage services it exports
- Exposure of the material the appliance holds for its own operation, within its readable filesystem scope
  at root authority: the storage configuration, any credential material the appliance stores for its own
  operation, and the appliance's own administrative state
- Access to the data on the volumes the appliance serves, in the sense that root on a storage controller
  can reach the backing storage it manages; the exact reachable scope depends on how the deployment maps
  volumes and was not measured during this research
- Availability impact at will: an attacker with root can stop, reconfigure or corrupt the storage services
  the appliance exports, which affects every initiator that depends on them rather than only the appliance
- Persistence consistent with root command execution on a Linux appliance (startup scripts, accounts,
  scheduled tasks) up to the limits of the writable filesystem; survival of a reinstall or a fresh OVA
  import was not tested and is not claimed
- The chain is quiet in product terms: one authenticated POST inside a routine configuration action, with
  no traffic pattern beyond ordinary management use
- The authentication requirement does not bound the outcome: a credential obtained by phishing, reuse or a
  shared account yields root rather than a configuration panel, and a password change afterwards does not
  evict an attacker who already holds a root shell

## Mitigation / Fix Recommendations

1. Validate `ipaddress` as an address before use: accept only a well-formed IPv4 or IPv6 literal and reject
   everything else at the form handler, before the `sf_ping` call. An allowlist parser is the control that
   fits; a character blocklist does not
2. Remove the shell from the ping path: have `sf_ping` execute `ping` with an argument vector and no shell
   in between, so that no request-derived text is ever parsed as shell source
3. Take root out of the ping path: a reachability test does not need root. If raw sockets are genuinely
   required, grant that capability narrowly instead of routing arbitrary text through `sudo command.pl`
4. Change `command.pl` so that it never writes its argument to a file and executes it. If the interface must
   remain a command string, restrict it to fixed operation identifiers with validated parameters and refuse
   anything it cannot attribute to a known operation
5. Scope the sudoers entry: `apache ALL=NOPASSWD: /usr/local/StoneFly/bin/command.pl` hands the web account
   a general root execution primitive. Limit it to the operations the GUI performs and remove it from paths
   that only need to send an ICMP echo
6. Audit every screen that shares the pattern, including the recorded `dns_server.pl` and
   `ff_network_route.pl` instances and the wider set of 44 CGI scripts that reach a shell through the same
   helper. Fixing only the iSNS screen leaves the family in place
7. Add a handler-level regression test: submit an `ipaddress` containing `$(true)` and assert that the
   request is rejected or that no shell-out occurs, then repeat with the backtick and semicolon forms so a
   future validator change cannot silently reopen the path
8. Until a fix ships, operators should keep the management interface on a dedicated administrative network,
   avoid shared administrator accounts, and treat any administrator credential for this appliance as
   equivalent to root on it

## References

- https://0day-rubbish.com/blog/ff-isns-ipaddress-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
