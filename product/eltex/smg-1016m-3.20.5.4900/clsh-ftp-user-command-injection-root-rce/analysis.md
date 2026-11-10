# Eltex SMG-1016M 3.20.5.4900 - clish ftpd `user add` Unquoted-Argument Command Injection Through Unquoted Vendor Helper Scripts

Advisory: https://0day-rubbish.com/blog/clsh-ftp-user-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### 1.1 The finding in one pass

The SMG-1016M exposes an FTP-user management command tree to an authenticated administrator console. The
tree's parameter definition declares an empty `escape_chars` set and a `.{1,63}` string pattern, so a
semicolon passes into the management layer untouched. That layer is the vendor's own message bus: libclish
packages the arguments, msgcore carries them to networkd, and networkd builds three `system()` command
lines in which the parameters are interpolated without quotes. The three vendor helper scripts that receive
those arguments re-expand them without quotes a second time, and because `system()` goes through
`/bin/sh -c`, the value is parsed by a shell twice. A user name of the form `name;command;#` therefore
executes `command` with the credentials of the console session and discards the rest of the constructed
command line as a comment.

The result is not a memory-safety defect, not a credential weakness and not a transport flaw. It is a
quoting defect that was never fixed at any of the three layers where quoting was needed, plus an input
validator that was declared but left empty. The exploitation primitive is a single command typed by a
credential holder, which is why the published rating uses the High privilege tier rather than the Low one.

### 1.2 The product and the image

The SMG-1016M is a closed-source carrier-grade VoIP media gateway in a 16-port analog gateway form factor.
The firmware analysed here is version 3.20.5.4900. The update container is a plain gzip stream with no
encryption and no signature verification; decompressing it yields a POSIX tar archive with eight entries -
`image/image.hash`, `image/version`, `image/buildinfo`, `smg1016m_kernel`, `smg1016m_initrd`, `smg1016m_fs`
and `smg1016m_fs_upd`. The kernel is an uncompressed uImage of Linux-2.6.22.18 for ARM with entry point
0x8000, and `smg1016m_initrd` is an 85 MB ext2 filesystem that is the true root filesystem: `/bin`, `/sbin`,
`/etc`, `/usr` and `/var` are all present and complete. The second tar entry, `smg1016m_fs`, supplies the
updated binary set that overlays the initrd in production.

Two properties of this layout matter for the analysis. First, the archive being unencrypted and unsigned
means the command-tree definitions, the vendor helper scripts and the daemons can be read exactly as the
device reads them, rather than inferred from strings in a packed blob. Second, the daemons are ordinary ARM
ELF binaries that can be executed under user-mode emulation, which is what makes the end-to-end
reproduction described in section 9 possible without physical hardware.

The runtime layout places the application under `/usr/bin/smg/`, with `mgapp`, an `application/` directory
and `smg_pa_sip/`, plus `/usr/bin/smg/xml/` holding the clish command-tree definitions - more than 160 view
files. Vendor scripts live in `/usr/local/scripts/` and `/sbin/`, and the init system is SysV under
`/etc/rc.d/init.d/`. The daemon set includes webspp with libwebs.so (the GoAhead-family web server),
msgcore (the IPC bus and the creator of the `/tmp/*.sock` endpoints), cfgmngr (the configuration engine
working on `cfg.yaml` and `cfg_tmp.yaml`), networkd (the network-plane setter and the component that
executes the FTP helper scripts), clish itself, and mgapp with the H.323, RTP proxy, SNMP, switch-control,
system-monitor, SSH-guard and lawful-intercept components that a carrier gateway of this class carries.

### 1.3 Public-record independence

No public vulnerability identifier exists for the SMG product line, and the research record's public-source
sweep found no entry for the SMG family in the national vulnerability database or in exploit archives. The
vendor has a public history on other product lines, including a set of identifiers on an earlier product line
and two identifiers describing an authenticated OS-command injection in a network-diagnostics handler. That
precedent is a same-vendor, same-genre data point, not the same chain: this finding's sink is the FTP-user
helper-script family and its source is the clish FTP command tree, whereas the earlier public entries
concern a ping command construction reached from a diagnostics form. No identifier has been assigned for the defect
described here, and none is claimed. The record's fingerprint search over the
vendor's own artefacts - the CLI view file, the helper scripts, the clish builtin and the webspp handler -
returned no earlier match, so the sink is treated as first described here.

### 1.4 Scope of the merged surfaces

Two management surfaces of the same image reach the same helper scripts. The console path is clish ->
libclish -> msgcore -> networkd -> `/sbin/*.sh`. The web path is webspp `ftpUserView::saveData` at 0xd48d0
-> `/sbin/passwdch.sh` and `/sbin/adduser.sh` at 0xd49b8 and 0xd4a64. Both interpolate the value without
quotes, both land on the same three scripts, both require an administrator session, and both fail on the
same missing quoting discipline. The research record merges them as one finding and this advisory keeps
that merge: the console path is the one that was executed end to end, the web path is established
statically and is described in section 5.4 as the twin rather than as a second finding.

## 2. Vulnerability Summary

### 2.1 Summary table

| Element | Value |
|---------|-------|
| Product | Eltex SMG-1016M VoIP gateway |
| Firmware | 3.20.5.4900, ARM, Linux-2.6.22.18, 85 MB ext2 initrd root filesystem |
| Entry point | authenticated console (`/bin/login` -> `/usr/bin/smg/clish`), and the authenticated web session (webspp `POST /jx/ftp_user`) |
| Vulnerable command | `config` -> `ftpd` -> `user add <USER_NAME> <PASSWD> <CDR> <LOG> <MNT> <CFG>`, plus `user del <IDX>` |
| Command tree | `/usr/bin/smg/xml/ftpd-view.xml`, `COMMAND name="user add"`, `escape_chars=""`, `USER_NAME` pattern `.{1,63}` |
| Builtin | `clish_add_ftp_user`, libclish 0x36b24 |
| Transport | msgcore IPC over `/tmp/*.sock` |
| Sink | networkd `system()` at 0x2e02c with `/sbin/adduser.sh %s %s`, `/sbin/passwdch.sh %s %s`, `/sbin/deluser.sh %s` |
| Second expansion | `/sbin/adduser.sh`, `/sbin/passwdch.sh`, `/sbin/deluser.sh` re-expand `$USER` and `$PASSWD` unquoted |
| Web twin | webspp `ftpUserView::saveData` 0xd48d0, escape 0x1b618c, blocklist 0x1b3e3c, sinks 0xd49b8 and 0xd4a64 |
| Classification | CWE-78 (CWE-20 recorded for the empty console-side sanitizer) |
| Rating | 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root),502(admin)` in marker files, inside the emulated-firmware replication |

### 2.2 Mechanics

The defect is best described as a chain of three omissions that individually look like style and together
form an execution primitive. At the top, the command definition lets a semicolon through because the
declared escape set is empty and the pattern is a length-bounded wildcard. In the middle, the C layer
composes a shell command line by string formatting with `%s` and no quoting, and hands it to `system()`,
which invokes `/bin/sh -c`. At the bottom, the vendor scripts, written in `sh`, dereference `$USER` and
`$PASSWD` without quotes in five distinct places in `/sbin/adduser.sh` alone, with the same pattern repeated
in the other two scripts. The gate and the unquoted C-layer construction are each sufficient on their own to
break the chain; quoting the scripts is also required, because they re-expand the value inside their own
shell and are reachable from more than one caller. All three layers are present in this build.

### 2.3 Preconditions

The attacker needs a valid console credential for an account whose login shell is clish, or an
authenticated web session with access to the FTP-user handler. Nothing else is required: no particular
interface state, no FTP service enabled, no file upload, no separate service listening. The FTP user
subsystem does not need to be in use; the command tree exists as soon as the device boots. The research
record's authentication step is `/etc/shadow`, so the attacker's credential is a real device credential and
the defect therefore survives every password change - it is not a default-credential finding.

## 3. Authentication Boundary

### 3.1 What the gate is

The console transport in production form is telnet on TCP 23, SSH on TCP 22, or the serial line. All of
them terminate in busybox `/bin/login`, which authenticates against the real `/etc/shadow` with busybox's
crypt implementation. A successful login for the `admin` account - uid 0 in this image - spawns the login
shell that `/etc/passwd` pins for that account, `/usr/bin/smg/clish`, which presents the `SMG1016M>` prompt
and the restricted configuration tree. The account is not a normal unprivileged user with a shell; it is a
uid 0 account deliberately constrained to the vendor CLI, and the CLI is the boundary that the vulnerability
crosses.

The web transport is the GoAhead-family webspp server on TCP 80, with 443 served from the same stack. Its
authentication was measured in the research record and failed closed in three independent ways: the user
table query succeeds and finds `admin`, but the session gate at `[sp,0x1c]` reads a `.bss` singleton field
at 0x452bf0 that is zero at runtime and has no store anywhere in webspp's text; forcing past that gate
reaches `pam_start("login")`, which returns 26 (PAM_ABORT) because the factory image ships neither
`/etc/pam.d` nor `/etc/pam.conf`; and the RADIUS fallback configured under `/etc/config/radius` has nothing
listening on its authentication port. A proxy capture of the login flow shows three frames and no
credential leaving the device.

### 3.2 What the unauthenticated path does

Two gate checks were run against the reproduction and both deny the unauthenticated route. A wrong console
password ends the session with `Login incorrect` and never reaches clish, so no sink is reachable. An
unauthenticated `POST /jx/ftp_user` returns `{"status":"error","error":"noAuth"}`, so the webspp twin is
unreachable without a session as well; other `/services/*` paths answer with a redirect to `/login`. The
only unauthenticated read the record notes is `GET /disk_info`, which is registered with permission level
zero and returns status information without a credential - it is not on this chain and is not part of this
finding.

### 3.3 Why the boundary does not soften the impact

An authenticated finding is often discounted on the theory that the credential holder already owns the
device. That theory does not hold for this product. The administrator account is deliberately constrained:
its shell is clish, a vocabulary of configuration verbs, and the vendor's design intent is that an
administrator can provision service but cannot run a shell. This defect converts that constrained identity
into unrestricted command execution with the same uid, so the impact is precisely the difference between
"can configure the gateway" and "can execute anything the gateway can". The research record measured the
difference rather than asserting it: the injected segment's `id` output is
`uid=0(root) gid=0(root) groups=0(root),502(admin)`, which is the console session's own credential set with
the administrator's supplementary group, not a separate service account. Because the account is uid 0, the
conversion is total; because the payload is a configuration value, the conversion leaves a trace in the
configuration store.

The privilege metric follows from the same fact. `admin` is the highest authority the product defines for
human use; there is no console-capable role beneath it, and the FTP account that exists in `/etc/passwd`
has `/bin/nologin` as its shell and therefore no console at all. A Low-privilege reading would need a
principal that can reach the `ftpd` tree while being denied administrator authority. The image contains no
such principal, so the published score takes PR:H and the Low variant is recorded in the summary only as a
rejected reading with its own arithmetic.

## 4. Attack Surface

### 4.1 The console and its command tree

The console is the surface this finding lives on. clish's command tree is generated from the XML view files
under `/usr/bin/smg/xml/`, and the FTP view is `ftpd-view.xml`. Entering `config` moves the prompt to
`SMG1016M-[CONFIG]>`, `ftpd` moves it to `SMG1016M-[CONFIG]-[FTPd]>`, and the `user` verb exposes `add`,
`del` and password-modification operations. Every one of those operations ends in the same helper-script
family, which is why the record treats the three injection sites as one finding rather than three.

### 4.2 The web plane

The web plane carries the same parameters. `ftpUserView::saveData` reads `userName` and `userPass`, runs the
password through a string-cleanup routine at 0x1b618c that only doubles backslashes and double quotes, then
checks the value against a blocklist at 0x1b3e3c. That blocklist rejects `<`, `>`, `'`, `&`, `"` and the
backtick. It does not reject `;`, `$`, `(`, `)`, `|` or the space, and the resulting command lines at
0xd49b8 and 0xd4a64 are the same `passwdch.sh` and `adduser.sh` constructions as the console path, again
without quotes. The web plane is therefore not a second defect but the same defect at a second entry, and
in this image it is additionally blocked from unauthenticated use by the login wall described above. The
record states this explicitly: the console instance is the one executed end to end, and the web instance is
retained as a complete static chain because the web login wall prevented a dynamic replay.

### 4.3 Components that narrowed out

The audit that produced this finding also examined the obvious neighbouring candidates, and the record
documents two of them as safe counter-examples, which is what bounds the claim:

- The ping handler behind `POST /jx/ping` with `act=Ping` and an `ip` parameter does build
  `sprintf(buf, "ping -c 5 %s", ip)` at 0x18a9cc and runs it through `popen(buf, "r")` at 0x18a9e4, but a
  hostname whitelist at 0x1b4300 restricts the value to the character class `[0-9a-zA-Z.-]` with a length
  bound of 1 to 64. That path is confirmed safe and is not part of this finding.
- `/sbin/date_set.sh`, invoked with a `%02d` format at 0x24464, receives a pure numeric value and is safe.

The record's conclusion from that sweep is narrow and worth restating: the FTP-user path is the only setter
group on this image that interpolates a console-supplied string into a vendor shell script without
sanitization. Other candidate surfaces - SIP and H.323 on 5060, 5061 and 1720, and SNMP on 161 - are
different protocol planes and are not part of this chain.

| Surface | Transport | Gate | Status for this finding |
|---------|-----------|------|--------------------------|
| console | TCP 23, TCP 22, serial | busybox `/bin/login`, `/etc/shadow` | entry point (executed) |
| web | TCP 80, TCP 443 | webspp login wall, `noAuth` on `/jx/*` | same sink, statically established |
| ping handler | same web stack | `[0-9a-zA-Z.-]` whitelist at 0x1b4300 | confirmed safe, excluded |
| date setter | local script | numeric `%02d` at 0x24464 | confirmed safe, excluded |

## 5. Sink Identification

### 5.1 The command definition

The first element of the sink is the command definition itself, read from the root filesystem:

```xml
<COMMAND name="user add"
     help="add ftp user"
     escape_chars="">                          <!-- sanitizer set is empty -->
     <PARAM  name="USER_NAME" ptype="TYPE_STRING_63" help="name"/>   <!-- .{1,63} -->
     <PARAM  name="PASSWD"    ptype="TYPE_PASSWORD"  help="password"/>
     <PARAM  name="CDR_ACCESS"  ptype="T_ACCESS" .../>
     <PARAM  name="LOG_ACCESS"  ptype="T_ACCESS" .../>
     <PARAM  name="MNT_ACCESS"  ptype="T_ACCESS" .../>
     <PARAM  name="CFG_ACCESS"  ptype="T_ACCESS" .../>
<ACTION builtin="clish_add_ftp_user">"0" ${USER_NAME} ${PASSWD}
     ${CDR_ACCESS} ${LOG_ACCESS} ${MNT_ACCESS} ${CFG_ACCESS} "add"</ACTION>
</COMMAND>
<COMMAND name="user del" ...>
     <PARAM name="IDX" ptype="TYPE_USERS_1_4" .../>
     <ACTION builtin="clish_del_ftp_user">${IDX}</ACTION>
</COMMAND>
```

The empty `escape_chars` attribute is the declaration of what the CLI will not escape, and it declares
nothing. The action passes the parameters as six separate arguments plus the literal `add`, which is
correct as a clish-level design; the defect begins where those arguments are re-serialized into a shell
string downstream.

### 5.2 The C layer

The builtin `clish_add_ftp_user` is at 0x36b24 in libclish. It packages the arguments into a message and
sends it over the msgcore bus, whose endpoints are the `/tmp/*.sock` sockets that msgcore creates at
startup. networkd receives the message and composes the helper invocation. The record identifies the same
format string at networkd 0x2e02c and describes the three constructions that matter:

```
system("/sbin/adduser.sh %s %s [silent]")     /* add path, networkd 0x2e02c */
system("/sbin/passwdch.sh %s %s")             /* password-change path */
system("/sbin/deluser.sh %s")                 /* delete path, name unquoted */
```

`system()` is defined to invoke `/bin/sh -c` with the given string. That is the second parse, and it is the
step that converts a semicolon in a configuration value into a statement separator. Note that the delete
path passes a single `%s`: the index that the administrator types is resolved back to a stored name before
the format is applied, so the stored name - not the index - is what reaches the shell.

### 5.3 The vendor scripts

The third layer is the helper scripts, read as files from the root filesystem:

```sh
# /sbin/adduser.sh
#!/bin/sh
if [ $# -lt 2 ]; then echo Usage: $0 USER PASSWORD; exit 1; fi
USER=$1
USER_MASK="^"$USER":"        # name concatenated into a grep pattern
PASSWD=$2
cat /etc/passwd | grep $USER_MASK > /dev/null      # unquoted
/bin/adduser -h /ftp -s /bin/nologin -D $USER      # unquoted
echo -en $PASSWD"\n"$PASSWD | passwd $USER 2>/dev/null   # unquoted twice

# /sbin/passwdch.sh
echo -en $PASSWD"\n"$PASSWD | passwd $USER >/dev/null 2>&1   # same shape

# /sbin/deluser.sh
USER=$1
/bin/deluser $USER            # unquoted delete-argument
```

Three observations follow from reading these files. First, the split that matters happens in the shell that
`system()` starts, so the decisive fix belongs at the C layer; the scripts nonetheless require quoting,
because they re-expand the value in their own shell and are reachable from more than one caller. Second, `grep $USER_MASK` is an additional hazard of the same kind, since
the name is concatenated into a regular expression and then into an argument position where a leading dash
would be read as an option. Third, the `if [ $# -lt 2 ]` guard is what makes the payload's first segment
print a usage line instead of failing silently, and that usage line is the observable that proves the
semicolon split the command.

### 5.4 The web twin

webspp's `ftpUserView::saveData` at 0xd48d0 takes the same two values by a different route. The password
passes through the cleanup routine at 0x1b618c, which only escapes backslashes and double quotes, and then
through the blocklist at 0x1b3e3c, whose reject set is `<`, `>`, `'`, `&`, `"` and the backtick. The
constructed command lines are at 0xd49b8 for the password-change branch and 0xd4a64 for the new-user
branch when the edit flag is zero. The semicolon, the dollar sign, the parentheses and the pipe are all
accepted, so the same payload shape reaches the same scripts by a second door. The record keeps this as a
static chain because the web login wall refused every unauthenticated attempt; the fact that the entry is
gated is a statement about exploitability from outside, not about the absence of the defect.

### 5.5 Execution identity

The identity that matters for impact is the identity of the process that calls `system()`. On the console
path the caller is networkd, which runs on the device, and the record's marker content - uid 0 with the
administrator's supplementary group - is the measured identity of the process tree that carried the
injected segment. That is the strongest statement the evidence supports: the command ran as the console
session's credential set inside the replication environment, not as a sandboxed or deduplicated service
identity.

## 6. Source Identification

### 6.1 The parameters

Two parameters carry attacker-controlled text into the sink: `USER_NAME` on `user add`, `PASSWD` on
`user add` and on the password-modification flow, and, for the delete branch, the stored name that the
index resolves to. `USER_NAME` is typed `TYPE_STRING_63`, whose pattern is `.{1,63}` - one to sixty-three
characters of anything. `PASSWD` is typed `TYPE_PASSWORD`, which the record shows restricts the backtick,
the question mark and the double quote, and bounds the length at 63 characters, and which explicitly
permits the semicolon. The four access flags are typed `T_ACCESS`, a selector type, and are not part of the
injection.

### 6.2 The validator, character by character

For the console path the answer to "which characters are filtered" is "none". `escape_chars` is the empty
string, so no character is escaped; the pattern is a length check, not a character check. This is worth
stating plainly because the XML looks like it contains a security control: it contains the *declaration of
one*, with an empty character set, which is a control that admits everything.

The web twin is closer to a real control and still insufficient. Its reject set covers the characters that
break out of a quoted context or start a substitution in the common cases: `<`, `>`, `'`, `&`, `"` and the
backtick. It does not cover `;`, which ends a command; `$` together with `(`, which starts a command
substitution; `|`, which starts a pipeline; the space, which separates arguments; or a newline. A
blocklist that enumerates the ways a shell can start a new command would have to cover the shell's entire
grammar, which is why the fix in section 11 is an allowlist and an argument array rather than a longer
list.

### 6.3 What the payload must respect

The payload must survive two constraints. It must be a single clish token, because clish splits its input
on whitespace and the console line is typed by a human; the recorded payloads therefore contain no spaces.
And it must be acceptable to `TYPE_PASSWORD` when it travels in the password field, which means no
backtick, no question mark and no double quote. The characters that survive both constraints and are
sufficient for the injection are the semicolon, the greater-than sign and the hash: the semicolon splits,
the redirect writes, the hash comments out the remainder of the constructed line. Nothing else is needed.

## 7. Data Flow

### 7.1 End to end

The complete path, with the layer at which each transformation happens:

1. The administrator authenticates on the console. busybox `/bin/login` verifies the credential against
   `/etc/shadow`; the `admin` entry's shell is `/usr/bin/smg/clish`.
2. clish reads the FTP view from `/usr/bin/smg/xml/ftpd-view.xml`, tokenizes the typed line, checks
   `USER_NAME` against `.{1,63}` and `PASSWD` against the password type, and performs no escaping because
   `escape_chars` is empty.
3. The builtin `clish_add_ftp_user` at 0x36b24 serializes the six arguments plus the literal `add` into a
   message.
4. msgcore carries the message from clish to networkd over the `/tmp/*.sock` bus.
5. networkd applies the format string at 0x2e02c, producing a command line in which the name and password
   appear as bare words.
6. `/bin/sh -c` parses that line. The semicolon ends the helper invocation; the next segment runs.
7. The helper script is also a shell, and it dereferences `$USER` and `$PASSWD` unquoted, so the value is
   expanded as bare words a second time inside the script.
8. The injected segment executes as a child of the process tree that called `system()`, inheriting its
   credentials, and its output is redirected wherever the payload says.

### 7.2 Properties worth naming

Three properties of that flow explain the finding's shape. The value is never re-encoded: each layer
receives the previous layer's string and treats it as a word sequence. The quoting decision is delegated
downward three times - clish delegates to networkd, networkd delegates to `/bin/sh -c`, and the shell
delegates to the script - so a missing quote wherever the value meets a shell is sufficient, and no layer
actually supplies one.
And the comment character makes the tail of the constructed line disappear, which is why the payload can be
a single token with no trailing cleanup: `# vpw rw rw rw rw silent` is parsed as a comment, and the script
never complains about the argument count it would otherwise have received.

The delete branch adds a fourth property: the name is stored first and interpreted later. The administrator
types an index, the configuration layer resolves it to the name that was stored at creation time, and that
stored name - which may itself contain metacharacters - is what the format string interpolates. A user
created with an injected name is therefore a persistent carrier: deleting it re-runs the injection. The
research record uses exactly this to demonstrate the third site, removing the first marker before the
delete so that the recreated marker can only have come from `/sbin/deluser.sh`.

## 8. Exploit Construction

### 8.1 Payload engineering

The payload for the user-name field is:

```
c264x;id>/M2;#
```

Interpolated into the recorded command line it becomes:

```
/sbin/adduser.sh c264x;id>/M2;# vpw rw rw rw rw silent
```

and the shell splits it into three parts. The first part, `/sbin/adduser.sh c264x`, runs the helper with one
argument, so the `[ $# -lt 2 ]` guard prints `Usage: /sbin/adduser.sh USER PASSWORD` and exits. The second
part, `id>/M2`, runs `id` and writes its output to `/M2`. The third part, `# vpw rw rw rw rw silent`, is a
comment. The console therefore shows both the usage line, which is the fingerprint of a successful split,
and the ordinary `NEW 'FTPD-USERS' [02]: successfully created` line that the caller's return path produces.

The marker content is the evidence of identity rather than the evidence of execution: `id` reports the
credential set of the process that ran it, and in the recorded run all three sites produced the identical
line `uid=0(root) gid=0(root) groups=0(root),502(admin)`.

### 8.2 The three vectors

The recorded verification exercises three distinct injection sites, all reachable from the same command
tree and all landing on the same shell:

- Username segment: `user add c264x;id>/M2;# vpw rw rw rw rw`, producing `/M2`.
- Password segment: `user add p264c pp;id>/M2b;# rw rw rw rw`, producing `/M2b`. The password field has a
  narrower accepted character set than the name field, and the semicolon is inside it, so the same split
  occurs one argument position to the right.
- Delete branch: `user del <IDX>` on the injected name, producing `/M2` again through
  `/sbin/deluser.sh c264x;id>/M2;#`.

The recorded console output for the three vectors, reduced to the lines that identify each split (the
password-prompt chatter is elided):

```
SMG1016M> config
SMG1016M-[CONFIG]> ftpd
SMG1016M-[CONFIG]-[FTPd]> user add c264x;id>/M2;# vpw rw rw rw rw
Usage: /sbin/adduser.sh USER PASSWORD
NEW 'FTPD-USERS' [02]: successfully created
SMG1016M-[CONFIG]-[FTPd]> user add p264c pp;id>/M2b;# rw rw rw rw
Changing password for p264c
Password for p264c changed by root
NEW 'FTPD-USERS' [03]: successfully created
SMG1016M-[CONFIG]-[FTPd]> user del 2
deluser: unknown user c264x
REMOVED 'FTPD-USERS' [02]
```

### 8.3 The control

A benign user add is the control that binds execution to the metacharacters rather than to the command:
`user add zctl2 zpwd2 rw rw rw rw` traverses the identical chain - clish, libclish, msgcore, networkd,
`/sbin/adduser.sh` - and the console reports the same success line, but no marker appears and no existing
marker changes. The recorded control compares the marker fingerprint (existence, modification time and the
first sixteen hexadecimal characters of the SHA-256 digest) before and after the benign add and finds it
unchanged. That is the difference between "the chain ran" and "the payload executed", which is the only
attribution a replication of this kind can offer.

### 8.4 What the PoC does not do

The published proof of concept drives a console session over the management transport, issues the three
recorded vectors and the control, and reports the console observables for each. It creates only the FTP
users its own payloads name and deletes them through the same interface afterwards; apart from those
accounts, it asks the device to write nothing except the marker files it names. It does not open a listener, does not
modify an account, does not touch the routing or voice configuration, and does not attempt to persist. When
it is pointed at a reproduction whose root filesystem is available to the operator, it reads back the
markers and prints their contents; when it is pointed at a remote console, the console echo is the
observable and the marker is left for the operator to inspect, because a clish session cannot read a file.

## 9. Dynamic Verification

### 9.1 Environment and method, stated exactly

Verification was an authenticated-console, end-to-end execution of the extracted firmware under user-mode
emulation:

- The 85 MB ext2 initrd root filesystem was extracted from the update container and chrooted on a research
  host, with the image's own ARM binaries executed through `qemu-arm-static`.
- The chroot ran inside a dedicated network namespace whose only interface is loopback, so nothing on the
  chain was reachable from a network during the run.
- The image's own daemons were resident in that namespace: msgcore, cfgmngr, networkd, snmpd and webspp on
  port 80, which is what the console chain and the web gate check both require.
- The console was driven through a PTY as `/bin/login`, so the authentication step, the shell assignment,
  the clish command tree, the msgcore hop and the vendor scripts were all the device's own code and data.
- The administrator principal was created for the run by placing a known md5-crypt hash in the chroot's
  `/etc/shadow`, with the factory line backed up and restored afterwards; the factory hashes themselves
  could not be inverted and were not needed.

Root was reached and observed inside that emulated-firmware replication environment. No physical SMG-1016M
was driven, no live console connection was made to device hardware, and no claim in this advisory depends
on hardware behaviour that the extracted image does not itself contain.

### 9.2 Gates

Both authentication gates were re-run inside the same environment and both deny the unauthenticated route;
the two lines below are excerpts of the recorded output:

```
[+] GATE-A: console /bin/login with wrong password rejected ('Login incorrect') - no clish session, no sink
[+] GATE-B: web POST /jx/ftp_user without session cookie returns {"status":"error","error":"noAuth"}
```

GATE-A establishes that a wrong password produces no clish session and therefore no path to the sink.
GATE-B establishes that the webspp twin refuses an unauthenticated request in the same image, which is why
the web chain is described statically in section 5.4 rather than executed.

### 9.3 Vectors and results

All three injection sites produced a marker with the same content; the marker lines below are reproduced as
recorded:

```
[+] MARKER #1 (username segment) /M2 contents:
uid=0(root) gid=0(root) groups=0(root),502(admin)
[+] MARKER #2 (password segment) /M2b contents:
uid=0(root) gid=0(root) groups=0(root),502(admin)
[+] MARKER #3 (user-del branch, deluser.sh) /M2 contents:
uid=0(root) gid=0(root) groups=0(root),502(admin)
```

The run's closing summary line records the chain as verified end to end - authenticated admin console,
unquoted parameters, helper-script re-expansion, root-level command execution - with markers at all three
sites. The three markers are one identity text because they are one identity: the console session's credential
set, with the administrator's supplementary group resolved through the image's `/etc/group`. For the delete
branch the run removed `/M2` before issuing `user del`, so the marker's reappearance can only be attributed
to `/sbin/deluser.sh` re-expanding the stored name. The console line `deluser: unknown user c264x` is
consistent with that: the name does not exist as a system account because the add segment failed on its
argument count, yet the delete helper was invoked with `c264x` as its argument and reported it as an
unknown user.

### 9.4 The control and the cleanup

The benign control user add reached the same scripts and produced the same success line with no marker
change, as described in section 8.3. After evidence collection the run deleted the created FTP users
through the same management interface, restored the factory `/etc/shadow` line, and removed the markers;
the final FTP user table was the factory pair, `ftpuser` and `bctrl`, and the terminal state of the run
reports the artefact restored. One iteration detail is worth recording because it is a property of the
evidence rather than of the defect: an early cleanup pass used a stale index snapshot and left one control
user behind after the indices shifted, which was corrected by re-reading `show user` before each delete.
The published PoC re-reads the table before every delete for the same reason.

### 9.5 What the method establishes and what it does not

The method establishes that the image's own code, given a valid console session, converts the recorded
parameter values into command execution with the session's credentials, and that the conversion is
attributable to the metacharacters rather than to the command. It does not establish behaviour of a
production chassis beyond what the image contains: no hardware watchdog, licensing state, licensed capacity,
hardware revision or carrier-network integration was exercised. Where this advisory says "root", it means
uid 0 as measured inside the replication environment, which is the same identity the image's `/etc/passwd`
assigns to the console account.

## 10. Reachability and Security Impact

### 10.1 Reachability

Reachability is the availability of an administrator console session, and in carrier operations that is an
ordinary working condition rather than an exotic one: the console is the provisioning interface, reachable
on TCP 23, TCP 22 or the serial line, and the equivalent web handler reaches the same scripts, a chain the
record establishes statically but did not replay. Nothing about the vulnerable command is unusual, and that
is the point: the injection rides on a legitimate account-management operation, from a legitimate session,
with legitimate intent at the CLI level. An attacker who has obtained an administrator credential - through
credential reuse, an exposed management network, or a compromised management workstation - does not need to
find a second vulnerability to obtain a shell, because this one is one command away.

### 10.2 Impact in concrete terms

The gateway's own authority is the impact boundary. A uid 0 process on this device can read and write the
configuration store that cfgmngr manages, the voice-routing and subscriber configuration that mgapp and the
SIP and H.323 components apply, the management plane's own state, the SNMP configuration and the
lawful-intercept module configuration present in the image. It can change what the device does with calls
rather than merely observe it, and it can stop the device from doing anything at all. For a media gateway
at a carrier edge, that is control of a voice-plane element, not of a peripheral appliance.

The persistence property is the second half of the impact and it comes from the product's own data model
rather than from any technique: the injected name and password are stored in the FTP user table and staged
by the configuration engine, so the malformed values remain after the console session that created them
ends, and the delete path re-expands the stored name. The record documents that persistence path and stops
short of claiming boot-time re-execution, and this advisory stops in the same place.

The third property is silence. On the console, the recorded transcript shows the helper's usage line next to
the normal creation line; a log that records only successful operations sees a successful FTP user
creation. There is no separate service, no listening socket and no distinctive request that a network
monitor could key on, because the entire exchange is an ordinary configuration command.

### 10.3 Limits of the claim

Four limits are stated so the finding is not read more broadly than the evidence. The first is hardware:
the verification ran the image's userland under emulation, so device-specific behaviour outside the image
was not measured. The second is product scope: only the SMG-1016M on 3.20.5.4900 was analysed, and the
sibling models were deliberately left unclaimed pending artefact comparison. The third is the web path: it
is a complete static chain with the same sinks, but it was not executed, and this advisory does not present
it as dynamically confirmed. The fourth is the boundary of "root": the marker shows uid 0 with the
administrator's supplementary group inside the replication, which is the identity the image defines for the
console account; it is not a claim about a separate privileged daemon context.

## 11. Fix Recommendations

1. Fix the input gate at the command definition. Replace the `.{1,63}` pattern on `USER_NAME` with an
   allowlist such as `[A-Za-z0-9_.-]{1,63}`, and give `PASSWD` a character policy that is enforced rather
   than described. Populate `escape_chars` with the shell metacharacters instead of leaving it empty. The
   image already contains a working model for this: the ping handler's whitelist at 0x1b4300 restricts its
   value to `[0-9a-zA-Z.-]` with a length bound, and that handler is safe.
2. Remove the shell from the path at the C layer. Convert the `system()` sites at networkd 0x2e02c and the
   webspp sites at 0xd49b8 and 0xd4a64 to `execve()`-family calls with argument arrays. With an argument
   array there is no second parse, so the class disappears at these surfaces regardless of what characters
   the value contains.
3. Fix the helper scripts as defence in depth. Quote every expansion - `"$USER"`, `"$PASSWD"`,
   `"$USER_MASK"` - pass `--` before the value where the tool accepts it, use `grep -q --` rather than a
   pipeline into `/dev/null`, and apply the same edit to every script in that directory that consumes
   console-supplied values, including the account-existence checker.
4. Fix the web twin in the same release. Extend the escape routine at 0x1b618c and the blocklist at
   0x1b3e3c with `;`, `|`, `$`, `(`, `)`, space and newline, or route the web path through the same
   argument-array implementation as the console path so that one validated construction serves both.
5. Add regression coverage at the command level. Submit `user add` with a semicolon in the name and assert
   that the CLI rejects it before the message is built; repeat with the password field and with `user del`
   on a name containing metacharacters; run the same cases through the web handler so a future divergence
   between the two entry points fails the suite rather than waiting for a researcher.
6. Reduce blast radius operationally. Treat the console administrator credential as root-equivalent, which
   this image makes literal, keep console reachability on a dedicated management network, and alert on FTP
   user table changes whose names or passwords contain characters outside `[A-Za-z0-9_.-]`.
7. Until a fixed build exists, audit existing FTP user entries for metacharacters, and avoid creating FTP
   accounts from a session that a less-trusted party can reach.

## 12. CWE

### 12.1 CWE-78

CWE-78, improper neutralization of special elements used in an OS command, is the primary classification and
the record's own choice. The construction matches the definition at every element: a value that originates
from an authenticated user, a downstream component that assembles an operating-system command by string
concatenation, and a shell that interprets the assembled string a second time. The two-layer structure -
`system()` in networkd and unquoted expansions in the vendor scripts - is still one weakness class, because
both layers fail to do the same thing: keep a value a value rather than a word sequence.

### 12.2 CWE-20

The record also classifies the console-side sanitizer as CWE-20, improper input validation, and this advisory
keeps that co-classification. The evidence for it is the XML declaration itself: a command element that
declares an escape set with an empty character list, and a parameter pattern that constrains length but not
content. That is not a missing validation in the sense of an oversight in one branch; it is a validation
control that was declared in the command definition and never given a policy, which is exactly the shape of
weakness CWE-20 describes. It is reported alongside CWE-78 rather than instead of it, because the input
validation gap explains why the value reached the sink and the injection explains what happened there.

### 12.3 What the finding is not

The finding is not a memory-safety defect: there is no buffer, no length arithmetic and no pointer
lifetime involved, and the 63-character bound in the parameter type is a length policy rather than a memory
bound. It is not an authentication bypass: both gates were re-run during verification and both deny. It is
not a default-credential finding: the credential is the device administrator's real `/etc/shadow` entry,
and changing that password does not remove the defect. And it is not a configuration error on the
operator's part: the vulnerable command tree is part of the shipped firmware and is reachable from the
shipped console, with the sanitizer left empty in the shipped view file.

---

Written by the 0day Rubbish Research Team.
