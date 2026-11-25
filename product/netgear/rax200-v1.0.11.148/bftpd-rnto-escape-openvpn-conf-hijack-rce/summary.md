# NETGEAR RAX200 V1.0.11.148 - bftpd RNTO rename escape hijacking the OpenVPN configuration

Advisory: https://0day-rubbish.com/blog/bftpd-rnto-escape-openvpn-conf-hijack-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

NETGEAR is a consumer-networking vendor whose Nighthawk line is among the most widely deployed classes of
home and small-office routers. The RAX200 (Nighthawk AX12) is a WiFi 6 router of that line, built on the
Broadcom v8A platform with a 32-bit ARM userland, Linux 4.1.4, bftpd 4.8 as the ReadyShare file-sharing
daemon and OpenVPN 2.5.4 as the site-to-site and remote-access VPN service. Firmware V1.0.11.148 is the
build analyzed end to end for this advisory, and two independent weaknesses in it compose into a chain that
ends in command execution with the device root identity.

The first weakness is in the account domain behind ReadyShare. The management plane keeps account material
in NVRAM and rebuilds the system password file from it with a routine that renders each account into a
passwd-format line using a fixed `sprintf` format whose uid and gid fields are hard-wired to zero. The
routine performs no field-level escaping: it does not reject the colon that separates fields, and it does
not reject the line feed that separates records. An account or password value that carries a newline and a
seven-field line therefore contributes a second, forged account - one whose declared identity is uid 0 and
gid 0. The passwd file it is written into is the same file `/etc/passwd` resolves to on the device, and the
FTP daemon the ReadyShare feature exposes authenticates against that file.

The second weakness is in that FTP daemon. bftpd 4.8 confines uploads correctly: `do_stor` maps the
requested name inside the chroot, compares the result against the literal `/shares/` prefix at 0x155b4 and
answers 550 for anything else. Its rename command does not repeat that discipline. `command_rnto` holds the
old name from `RNFR` in session state, maps the new name, compares only the *old* path against the
`/shares/` prefix at 0x161c0, and then calls `rename(old, new)` at 0x1621c with the destination never
examined. The daemon's chroot is the device's `/tmp`, so an authenticated FTP session can move a file it
uploaded inside `/shares/` to any path inside `/tmp` - including `/tmp/server_tap.conf`, the configuration
file from which the router's service supervisor starts OpenVPN.

The two weaknesses meet at that path. The supervisor function at fcn.0001d8ac checks that the OpenVPN
certificate files exist, prepares `/dev/net/tun`, and then runs
`system("/usr/local/sbin/openvpn /tmp/server_tap.conf &")` at 0x1daa4 as root. It does not regenerate the
configuration file, does not check its owner or mode, and does not compare it against any generated copy;
the file is an input it trusts. OpenVPN 2.5.4 then honors `script-security 3` together with an `up`
directive, so the uploaded configuration causes the daemon to run `/bin/sh /tmp/shares/p` - a script the
FTP session placed on the device - with the daemon's identity, which is root. The hook needs no execute bit
because the interpreter is named explicitly, and the upload cannot set one anyway: this configuration
leaves `SITE CHMOD` disabled. The rename preserves ownership and mode, so the planted configuration ends up
root-owned and 0644, indistinguishable in `ls -l` from a file the device's own configuration path wrote.

- Component: the ReadyShare FTP service, bftpd 4.8 at `/usr/sbin/bftpd` (recorded md5
  `03b8a49698dfe167c3f8c68999e06d38`), and the VPN service supervisor at fcn.0001d8ac in the firmware's
  service userland, on RAX200 firmware V1.0.11.148
- Sink: `system("/usr/local/sbin/openvpn /tmp/server_tap.conf &")` at 0x1daa4, executed as root, consuming
  a configuration file that a network service can replace
- Source: the `RNTO` destination operand of the FTP rename command, unvalidated at 0x161c0/0x1621c, and the
  ReadyShare account value that becomes a passwd line through `sprintf("%s:%s:0:0:%s:/:/bin/sh\n")`
- Sanitization: the upload prefix gate (`/shares/`, eight-byte `strncmp`) is present and effective; the
  rename destination check is absent; the account rebuild performs no separator handling at all
- Authentication: this is an authenticated finding, not a default-credential finding. It consumes a
  legitimate administrator session on the management plane and a legitimate FTP login derived from the
  administrator-maintained account store. No authentication bypass, session forgery or credential
  disclosure is involved anywhere in the chain, and changing the administrator password does not narrow it
- Verification boundary: the static work covers the analyzed image at disassembly and source-line level;
  all dynamic evidence was produced inside a firmware-root replication environment - the image's own
  bftpd 4.8, OpenVPN 2.5.4 and service binaries, executed under user-mode 32-bit ARM emulation on an
  isolated host. Root (`uid=0`) was observed inside that replication environment only. No physical RAX200
  was driven, no live management request was fired at device hardware, and no root shell, marker or command
  execution was observed on a router
- Identifier: no identifier assigned

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an administrator who can reach the
  router's management plane and its file-sharing service converts two intended administrative operations
  into arbitrary command execution as root on the device
- Attack Vector: Network - every step is carried by network protocol exchanges against listening services
  (the FTP service on port 21 and the management plane); no console access, physical proximity or local
  account is required at any point. Which interfaces reach those services is decided by each deployment's
  firewall and remote-management policy, and this research did not measure that policy; the qualification is
  a deployment fact stated here rather than a change to the vector
- Attack Complexity: Low - the chain is a fixed sequence of documented FTP commands, one account value and
  one management action; there is no race, no timing window, no memory-corruption groom and no probabilistic
  element
- Privileges Required: High - the account domain and the VPN service controls are administrator surfaces,
  and the FTP login the chain uses is an entry in the account database the administrator maintains. The
  product offers no lower-privilege account class with reach to either surface
- User Interaction: None - the credential holder drives every request directly; no victim action is needed
- Scope: Unchanged - the executed script runs on the router itself, inside the authority of the service whose
  configuration was hijacked; no crossing into a beyond-device security authority is claimed
- Impact C/I/A: all High - command execution as root gives the complete configuration store (including the
  VPN key material the supervisor itself checks), control of the accounts, startup scripts and services the
  writable filesystem retains, control of routing and name resolution for everything behind the device, and
  availability impact at will
- Why Privileges Required is High and not the neighbouring tier: the only principals that can reach the
  account domain, the VPN service controls or an FTP login on this device are the administrator and the
  accounts the administrator creates. The account rebuild writes every entry as `0:0`, so the FTP account is
  not a lower tier in any meaningful sense - it is a root-equivalent identity inside the chroot by
  construction. A Low reading would require a web or FTP principal that exists independently of the
  administrator and reaches these surfaces with less authority, and no such principal is documented in the
  artifacts examined
- Rejected reading: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High. This is the arithmetic of a
  Low-privilege reading of the same impact profile, and it is rejected because the chain has no step a
  non-administrator can perform: seeding the account value requires the management plane, and the FTP login
  requires an account only the administrator can create. Its arithmetic is ISS 0.914816, Impact 5.873119,
  Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, sum 8.708374, rounded up to 8.8
- Published arithmetic: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827, rounded up to the published
  score of 7.2

## Affected Products

- NETGEAR RAX200 (Nighthawk AX12) WiFi 6 router, firmware V1.0.11.148 (image
  `RAX200-V1.0.11.148_1.0.82.chk`, board U12H390T00_NETGEAR), Broadcom v8A, 32-bit ARM EABI5, Linux 4.1.4:
  affected components are bftpd 4.8 at `/usr/sbin/bftpd` (recorded md5
  `03b8a49698dfe167c3f8c68999e06d38`) and the OpenVPN service supervisor at fcn.0001d8ac, with the account
  rebuild routine at fcn.000c0d44 in the management plane
- The vulnerable configuration is the shipped one: `ROOTDIR="/tmp"`, `DO_CHDIR=yes`,
  `AUTO_CHDIR="/shares"`, `AUTH="PASSWD"`, `LOG_WTMP="no"`, `ALLOWCOMMAND_SITE` not enabled. The chain does
  not depend on a non-default setting of the FTP daemon
- The trigger condition is a device whose OpenVPN service has been provisioned, so that the four
  certificate files the supervisor checks are present and `/tmp/server_tap.conf` exists. A device missing any
  of those certificate files returns from the supervisor before the `system()` call, so there is nothing to
  hijack
- Not claimed: other RAX200 hardware revisions or firmware versions, other models of the Nighthawk line, and
  any firmware branch other than V1.0.11.148. This advisory analyzes one image end to end and makes no claim
  about any other build by inference
- Verification method and its boundary: firmware-level disassembly and DWARF line information established
  the upload gate, the rename asymmetry, the account rebuild format, the supervisor's command line and the
  OpenVPN configuration semantics; the dynamic evidence is a firmware-root replication - the analyzed
  image's own binaries under user-mode ARM emulation - in which the six FTP primitives completed against
  the real daemon, the escaping rename produced a 53-byte attacker configuration at `/tmp/server_tap.conf`,
  and the supervisor's command line, replayed verbatim, executed the uploaded hook as `uid=0`. A control run
  with a configuration carrying no `up` directive opened the tunnel device without creating a marker.
  Privileged execution was not observed on device hardware
- Privilege ceiling reached in the replication: root inside the emulated device userland, which is the
  identity the supervisor runs as. Not reached and not claimed: escape from the router to attached hosts,
  persistence across factory reset or reflash, and any memory-corruption primitive

## Impact

- Complete compromise of the router's operating system through two legitimate administrative features: the
  account dialog and the VPN service control. The attacker obtains what the device itself can do -
  interface and route reconfiguration, firewall and name-resolution semantics, service control and the
  complete configuration store
- Exposure of the key material the device holds for its own operation, including the OpenVPN certificate and
  private-key files that the supervisor checks before starting the tunnel, and any credentials the firmware
  retains for management, file sharing or update services
- A durable interior position: root on the local network's chokepoint device allows traffic to be redirected
  or observed within the platform's own capabilities, which turns a compromised router into a foothold for
  everything behind it
- Persistence consistent with root command execution on an embedded Linux system - startup scripts, account
  entries and scheduled tasks within the writable filesystem - up to the limits of what survives a reboot,
  which was not tested on hardware and is not claimed
- Availability impact at will, from stopping or reconfiguring services to corrupting the writable
  filesystem, without any exploit-shaped traffic on the wire
- Silent in product terms: one authenticated FTP rename and one ordinary VPN service action, both inside
  the traffic profile a legitimate administrator produces. `LOG_WTMP="no"` in the FTP configuration means
  the session is not recorded in the login accounting file
- Blast radius beyond the single defect: the rename destination is unchecked for every path inside the
  chroot, so the same primitive reaches any other file the device keeps in `/tmp` and any service that
  consumes one of those files as root

## Mitigation / Fix Recommendations

1. Apply the shares-prefix rule to the rename destination, not only to the source. `command_rnto` should
   canonicalize the mapped destination inside the chroot and reject it unless it resolves under `/shares/`,
   exactly as `do_stor` does for uploads. This is a two-line class of fix and it closes the escape primitive
   regardless of what the destination file is used for
2. Stop generating passwd lines from user-supplied text. Reject `:` and line feeds in the account and
   password fields, and prefer an allowlist for the account name; better still, replace the `sprintf`-based
   rebuild at fcn.000c0d44 with a real account backend so separators are handled by a parser
3. Stop creating root accounts for the file-sharing service. Every entry the rebuild writes is `0:0`, and
   the FTP daemon logs in with that identity. A dedicated unprivileged account, with shares owned
   accordingly, limits what a failed path check can reach
4. Keep root-consumed service inputs out of writable, service-reachable directories. `/tmp/server_tap.conf`
   should be generated atomically into a directory the FTP chroot cannot address, and the supervisor should
   verify owner, mode and freshness against the generated copy before starting the daemon
5. Replace the shell-mediated start with an argument-array exec. The `system()` call at 0x1daa4 gives a
   writable configuration file the weight of a command line; an `execve`-family call with a fixed argument
   vector, and a configuration path the caller cannot influence, removes the class rather than the instance
6. Constrain the VPN configuration semantics. `script-security 3` plus an `up` directive in a file any local
   writer can replace is what turns a configuration hijack into command execution. Pin `script-security` to
   the minimum the feature needs and reject `up` in configurations the device did not generate
7. Add regression tests at both boundaries: `RNTO` to an absolute path outside `/shares/` must fail and
   `STOR` outside `/shares/` must keep failing; an account or password value containing a newline or colon
   must be rejected and the resulting passwd file must contain exactly one line per account
8. For operators until a fix ships: keep the management plane off any wide-area interface, disable the
   ReadyShare FTP service where it is not needed, rotate the administrator credential on any device whose
   management network admits untrusted stations, and treat an unexpected change to the VPN configuration as
   a compromise indicator rather than a settings anomaly

## References

- https://0day-rubbish.com/blog/bftpd-rnto-escape-openvpn-conf-hijack-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
