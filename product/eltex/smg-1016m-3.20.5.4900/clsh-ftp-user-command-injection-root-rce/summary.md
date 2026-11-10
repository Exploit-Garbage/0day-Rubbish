# Eltex SMG-1016M 3.20.5.4900 - clish ftpd `user add` Unquoted-Argument Command Injection Through Vendor Helper Scripts

Advisory: https://0day-rubbish.com/blog/clsh-ftp-user-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com
Identifier: none assigned

## Summary

Eltex is a vendor of telecommunications equipment, and the SMG-1016M is its closed-source carrier-grade
VoIP media gateway in a 16-port analog gateway form factor. The firmware analysed here is version
3.20.5.4900, an ARM build running Linux-2.6.22.18 with a GoAhead-family web management plane, a busybox
`/bin/login` console, the vendor's restricted CLI shell `/usr/bin/smg/clish`, and the vendor's own
telecommunications daemon set. The image itself is a plain gzip container with no encryption and no
signature verification, so the entire root filesystem - `/bin`, `/sbin`, `/etc`, `/usr`, `/var` - is
readable after decompression, including the command-tree definitions the CLI is generated from.

The finding is a command-injection defect that sits behind the administrator console and crosses two
layers of the same mistake. The console authenticates against the real `/etc/shadow` through busybox
`/bin/login`, and a successful `admin` login spawns that account's login shell, which `/etc/passwd` pins
to `/usr/bin/smg/clish`. Inside the CLI, the command `config > ftpd > user add` is defined in
`/usr/bin/smg/xml/ftpd-view.xml`. Its `USER_NAME` parameter carries `ptype` `TYPE_STRING_63` with the
pattern `.{1,63}`, and the command element declares `escape_chars=""`, an empty set: there is no
metacharacter filtering at all. The action builtin `clish_add_ftp_user`, at offset 0x36b24 in libclish,
forwards the arguments over the msgcore message bus, and networkd turns them into a `system()` call at
offset 0x2e02c whose format string interpolates the parameters without quotes:

```
system("/sbin/adduser.sh %s %s [silent]")
system("/sbin/passwdch.sh %s %s")
system("/sbin/deluser.sh %s")
```

Each of those three vendor scripts then re-expands the same values without quotes a second time.
`/sbin/adduser.sh` assigns `USER=$1` and `PASSWD=$2`, uses the name unquoted as a `grep` pattern
(`USER_MASK="^"$USER":"`), passes it unquoted to `/bin/adduser -h /ftp -s /bin/nologin -D $USER`, and
feeds the password through `echo -en $PASSWD"\n"$PASSWD | passwd $USER`. `/sbin/passwdch.sh` repeats the
password pattern, and `/sbin/deluser.sh` runs `/bin/deluser $USER` with the name unquoted. Because
`system()` executes through `/bin/sh -c`, a user name containing `;`, `>` and `#` is split into separate
commands by the shell that the vendor scripts were written for but never defended against.

A single-token payload is enough. The recorded user name `c264x;id>/M2;#` turns the helper invocation into
`/sbin/adduser.sh c264x;id>/M2;# vpw rw rw rw rw silent`: the first segment runs the script with too few
arguments and prints its own usage line, the second segment executes `id` with the console session's
credentials and redirects the output into a marker file, and the trailing `#` comments out the rest of the
constructed command line. The same construction works through the password field, and the delete branch
re-triggers it because `user del` resolves an index to a name and passes that name unquoted into
`/sbin/deluser.sh`. A parallel web surface exists in the same image: webspp's `ftpUserView::saveData` at
offset 0xd48d0 escapes only backslash and double quote through a function at offset 0x1b618c, screens the
value with a blocklist at offset 0x1b3e3c that rejects `<`, `>`, `'`, `&`, `"` and the backtick but leaves
`;`, `$`, parentheses, the pipe character and the space intact, and then builds the same
`/sbin/passwdch.sh` and `/sbin/adduser.sh` command lines at offsets 0xd49b8 and 0xd4a64. That web twin is
the same root cause on the same scripts and is described here as one finding rather than counted twice.

Verification was performed on an extracted-firmware reproduction: the 85 MB ext2 initrd root filesystem
was chrooted and its ARM userland executed under user-mode QEMU emulation (`qemu-arm-static`) inside a
dedicated network namespace with loopback only, with msgcore, cfgmngr, networkd and webspp resident. The
console was driven end to end through `/bin/login` over a PTY, so the authentication step, the clish
command tree, the messaging layer and the vendor scripts were all the image's own code. Inside that
replication environment the injected segment produced marker files reading
`uid=0(root) gid=0(root) groups=0(root),502(admin)` at all three injection sites, a benign control user
add produced no marker change through the identical chain, and the replication environment was restored to
its factory FTP user pair and shadow state afterwards. Root was observed inside that replication environment; no
physical appliance was driven during this research, and the advisory does not claim device hardware
behaviour beyond what the extracted image and its execution under emulation establish.

- Component: the clish FTP-user management command tree in `/usr/bin/smg/xml/ftpd-view.xml`, driven from
  the authenticated console (`/bin/login` -> `/usr/bin/smg/clish`), executed through libclish builtin
  `clish_add_ftp_user` at 0x36b24, the msgcore bus and networkd's `system()` call site at 0x2e02c in
  firmware 3.20.5.4900
- Sink: three command constructions in networkd - `/sbin/adduser.sh %s %s`, `/sbin/passwdch.sh %s %s` and
  `/sbin/deluser.sh %s` - each with unquoted parameter interpolation, executed via `/bin/sh -c`, whose
  second shell parse splits on `;`
- Sink amplification: the three vendor helper scripts themselves re-expand `$USER` and `$PASSWD` unquoted,
  so the value is handled as a word sequence without quotes at both layers
- Source: the `USER_NAME` and `PASSWD` parameters of `user add`, and the resolved name of `user del`, whose
  only input gate is a `.{1,63}` pattern with an empty `escape_chars` set
- Sanitization: none on the console path - `;`, `>`, `#`, `$`, backtick and space all reach the shell; the
  web twin's blocklist is broader but still misses `;`, `$`, `(`, `)`, `|` and the space
- Verification boundary: authenticated-console end-to-end reproduction of the extracted firmware under
  user-mode QEMU emulation in an isolated namespace, with marker files as evidence; root authority was
  reached and observed inside that environment, not on physical hardware

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an administrator who is entitled to
  manage FTP users turns an intended account-management command into arbitrary command execution with the
  console session's own credentials, which the replication measured as uid 0
- Attack Vector: Network - the console chain is exercised over the device's management transport; the
  research record documents the authenticated console as reachable on TCP 23, TCP 22 and the serial line
  in production form, so the attacker's position is a network position rather than a physical one; the
  equivalent web handler reaches the same scripts, a chain the record establishes statically
- Attack Complexity: Low - one command typed into an existing, legitimately obtained session is the whole
  detonation; no race, no timing window, no memory-corruption groom and no multi-step state machine
- Privileges Required: High - the vulnerable setter lives behind a real `/etc/shadow` authentication step
  and the administrator's clish shell; the analysis below explains why no lower tier exists
- User Interaction: None - the credential holder drives the console or the equivalent authenticated web
  request directly; no second party is involved
- Scope: Unchanged - the injected command runs inside the gateway, within the authority of the component
  whose interface was abused; no crossing into a beyond-device security authority is claimed
- Impact C/I/A: all High - command execution under a uid 0 console identity yields the gateway's full
  configuration, its voice-routing and subscriber semantics, its management plane and its availability
- CWE: CWE-78 primary (OS command injection through unquoted interpolation into a shell), with CWE-20
  recorded for the empty console-side input-sanitization declaration
- Published arithmetic: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827, rounded up to 7.2
- Rejected reading: a hypothetical console principal below the administrator would rate
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High. It is rejected because this firmware offers
  no such principal on the console path

The Privileges Required metric is High rather than Low because the privilege boundary in front of the sink
is the device administrator's own account, not a role that can be obtained or delegated within the product.
The image's `/etc/passwd` contains `admin` with uid 0 and the restricted shell `/usr/bin/smg/clish`, `root`
with `/bin/sh`, and an FTP-only account whose shell is `/bin/nologin`; the FTP account has no console, and
no other console-capable account tier was found in the artefact. A Low reading would require a principal
that can reach the `ftpd` command tree while being denied administrator authority, and no such principal
exists to measure. The same reasoning fixes PR at High for the web twin: webspp's `/jx/*` handlers answer
only to a session that the login wall has already admitted, and that wall failed closed for every
unauthenticated request the research fired at it.

The rejected reading is rejected on evidence, not on preference. Its arithmetic is Exploitability =
8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255 against the unchanged Impact of 5.873119, summing to 8.708374
and rounding up to 8.8. Publishing 8.8 would claim an attacker class this product does not contain on this
path. The rejected vector and score are recorded here so that the figure can be recognised if it appears
in derived material, and they are not to be quoted as the rating of this finding.

## Affected Products

- Eltex SMG-1016M VoIP gateway, firmware 3.20.5.4900 (the build analysed end to end in this research):
  ARM, Linux-2.6.22.18, 85 MB ext2 initrd root filesystem; affected component is the clish FTP-user command
  tree plus the networkd command constructions and the `/sbin/adduser.sh`, `/sbin/passwdch.sh` and
  `/sbin/deluser.sh` helper scripts, with the webspp `ftpUserView::saveData` path as the web twin
- The same defect is present on two interfaces of the same image: the authenticated console
  (`/bin/login` -> clish -> `config > ftpd > user add`) and the web handler that feeds
  `POST /jx/ftp_user`, both converging on the same vendor scripts; the console path is the one executed
  end to end, and the web path is established statically
- Not claimed: other models of the SMG family, including SMG-100, SMG-1204 and SMG-1016E, were not
  collected or compared for this advisory. The research record explicitly defers their inclusion until the
  CLI view file and the helper-script digests are compared fingerprint by fingerprint, so no inference is
  made here about them either way
- Not claimed: earlier or later firmware releases of the SMG-1016M. Only 3.20.5.4900 was decompressed,
  statically analysed and executed; no other build was examined
- Privilege ceiling: arbitrary command execution with the console session's credentials, measured in the
  replication as uid 0 with the administrator's supplementary group. Not reached and not claimed: escape
  from the gateway into the voice network, persistence across reflash, and any memory-corruption primitive
- Verification boundary: an extracted-firmware reproduction - user-mode QEMU emulation of the image's ARM
  userland in a chroot under a loopback-only network namespace - driven end to end through `/bin/login`
  and clish. No physical gateway was driven, so the request path, the authentication step and the command
  tree are established on the image's own code under emulation, and the execution identity is the one that
  environment produced

## Impact

- The administrator's account-management interface becomes a general command channel at uid 0. The FTP user
  table is an ordinary configuration object, so the operation an operator performs while provisioning
  accounts is the same operation that carries the payload; nothing about the request looks exceptional on
  the console
- Complete control of the gateway's own authority: the full configuration store, the voice-routing and
  subscriber configuration held by the vendor's daemons, the management plane itself, and the SIP, H.323 and
  media functions the device exposes to the carrier network
- Exposure of every secret the device holds for its operation, within the readable filesystem scope of a
  uid 0 process, including the configuration engine's working data under `/etc` and `/var` and any
  credential material the management plane stores
- Configuration-level persistence: an injected name and password remain in the FTP user table and in the
  configuration engine's staged state after the console session ends, so the malformed values outlive the
  session that introduced them. The research record notes this as a persistence path in the configuration
  store; boot-time re-execution was not tested and is not claimed
- Consistency across the product's own management surfaces: the console path and the web path of the same
  image reach the same helper scripts, so a fix applied to only one of them leaves the other intact
- Availability impact at will through the same channel, and a silent footprint in product terms: the
  console echo of a legitimate FTP user creation is indistinguishable from a benign one apart from the
  helper script's usage line, which is an artifact of the payload rather than a security control

## Mitigation / Fix Recommendations

1. Replace the console-side input gate: change `USER_NAME` and `PASSWD` in `ftpd-view.xml` from the
   `.{1,63}` string pattern to an explicit allowlist such as `[A-Za-z0-9_.-]{1,63}`, and populate
   `escape_chars` with the shell metacharacters instead of leaving it empty. The image already contains a
   working precedent for this style of gate in the ping handler, whose hostname whitelist at offset 0x1b4300
   restricts the character set to `[0-9a-zA-Z.-]` with a length bound
2. Remove the shell from the path entirely at the C layer: convert the `system()` call sites at networkd
   0x2e02c and webspp 0xd49b8 / 0xd4a64 to `execve()`-family calls with argument arrays, so no second
   parse of the value can occur. This closes the class on these surfaces rather than chasing characters
3. Enforce quoting discipline in the vendor helper scripts: quote every expansion (`"$USER"`, `"$PASSWD"`,
   `"$USER_MASK"`), and pass `--` before the value where the tool accepts it (`grep -q --`, `passwd --`) so
   a leading dash cannot be read as an option. Apply the same edit to every script in that directory that
   consumes console-supplied values, including the account-existence checker
4. Fix the web twin in the same release: extend the escape routine at 0x1b618c and the blocklist at
   0x1b3e3c to reject `;`, `|`, `$`, `(`, `)`, the space and the newline, or better, route the web path
   through the same argument-array implementation as the console path so both surfaces share one validated
   entry point
5. Add a regression test at the command level: submit `user add` whose name contains a semicolon and assert
   that the CLI rejects the value before the messaging layer is reached; repeat for the password field and
   for `user del` with a name carrying metacharacters. Run the same test through the web endpoint so a
   future divergence between the two surfaces is caught by the suite rather than by a researcher
6. Reduce blast radius in the meantime: treat the console administrator credential as root-equivalent, which
   this image makes literal (the account is uid 0 with a restricted shell), restrict console reachability to
   a dedicated management network, and alert on FTP user table changes whose names or passwords contain
   shell metacharacters
7. Until a fixed build exists, operators who do not use the FTP user management feature should avoid
   creating accounts through `config > ftpd > user add` from any session that a less-trusted party can
   reach, and should review existing FTP user entries for characters outside `[A-Za-z0-9_.-]`

## References

- https://0day-rubbish.com/blog/clsh-ftp-user-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
