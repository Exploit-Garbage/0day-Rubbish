# NETGEAR RAX200 V1.0.11.148 - bftpd RNTO rename escape hijacking the OpenVPN configuration

## 1. Overview

### Overview of the finding

The NETGEAR RAX200 (Nighthawk AX12) is a consumer WiFi 6 router, and firmware V1.0.11.148 is the build
analyzed end to end here. Two unrelated-looking weaknesses in that build compose into a single remote chain
that ends in command execution with the device root identity. The first is in
the account domain behind the ReadyShare feature: the management-side routine that rebuilds the system
password file renders account values into passwd-format lines with a fixed `sprintf` format whose uid and
gid fields are hard-wired to zero, and it performs no field-level escaping, so a value that carries a line
feed and a colon-delimited seven-field line forges an additional root account. The second is in the FTP
daemon the same feature exposes: bftpd 4.8 confines uploads to the `/shares/` subtree, but its rename
command validates only the *source* operand against that prefix and never inspects the destination, so an
authenticated FTP session can move an uploaded file to any path inside the daemon's chroot. Because that
chroot is the device's `/tmp`, the destination space includes `/tmp/server_tap.conf` - the configuration
file that the router's service supervisor hands to OpenVPN. The supervisor executes
`/usr/local/sbin/openvpn /tmp/server_tap.conf` through `system()` as root, and OpenVPN 2.5.4 honors
`script-security 3` together with an `up` directive, so the configuration the FTP session planted causes
the daemon to run an attacker-supplied script with uid 0.

The chain is a post-authentication chain in the narrow sense and a privilege collapse in the practical
sense. Everything it consumes is a legitimate administrator capability: an administrator session on the
management plane, and an FTP account created through the administrator-maintained account store. Nothing
in the chain bypasses authentication, forges a session or depends on a default password. What it does is
convert two intended administrative surfaces - "manage the ReadyShare account list" and "manage the VPN
service" - into a file-write primitive that reaches a root-consumed configuration file, and then into
arbitrary command execution.

One boundary statement belongs at the top of any reading of this advisory. All dynamic evidence was
produced inside a firmware-root replication environment: the analyzed image's own userland, with its real
bftpd 4.8, its real OpenVPN 2.5.4 and its real service binaries, executed under user-mode ARM emulation on
an isolated host. No physical RAX200 was driven, no live management request was fired at device hardware,
and the root identity reported in section 9 was observed inside that replication environment, not on a
router. Section 9 keeps the static half and the dynamic half of the evidence explicitly separated, and
section 10 states what the reachability reading does and does not cover.

### Overview of the product and the analyzed image

The analyzed artifact is the firmware image `RAX200-V1.0.11.148_1.0.82.chk`, whose board identifier is
U12H390T00_NETGEAR. The platform is Broadcom v8A, 32-bit ARM EABI5, running Linux 4.1.4. The image carries
bftpd 4.8 at `/usr/sbin/bftpd` and OpenVPN 2.5.4 at `/usr/local/sbin/openvpn` (a 730 KB ARM binary), and
the root filesystem is a UBI volume carrying a squashfs payload. The bftpd binary is not stripped and
retains DWARF line information, which is why several findings below can be anchored to source lines
(`commands.c:754-758` for the upload prefix gate, `commands.c:1868-1910` for the rename command) as well as
to instruction addresses; the recorded md5 of that binary is `03b8a49698dfe167c3f8c68999e06d38`.

Two properties of the image shape everything that follows. First, `/etc/passwd` is a relative symbolic link
to `../tmp/samba/private/passwd`, so the system account database lives in the same writable subtree that
the FTP service exposes, and the management plane writes it through its own routine rather than through a
system account tool. Second, `/tmp` in the shipped root is an absolute symbolic link to `/var/tmp`, so the
FTP chroot root and the service configuration directory are the same storage. Both facts were confirmed by
inspecting the extracted image, and both matter for reproduction: a replication environment has to
materialize `/tmp` as a real directory, because leaving the absolute symlink in place silently redirects
every write to the emulation host's own `/var/tmp`.

### Overview of the two defects and their composition

The account defect and the FTP defect were found by different routes and are worth keeping distinct,
because they have different fixes and different severities in isolation. The account defect is a
file-format injection: a value controlled by whoever administers the account list becomes a line in a
colon-delimited file whose parser has no concept of quoting. On its own it yields an FTP login with the
identity the forged line declares - and the routine's format string declares zero. The FTP defect is an
asymmetric path check: one operand of a two-operand filesystem operation is validated, the other is not.
On its own it lets an FTP session write outside its intended subtree, but only into the daemon's chroot.

Composed, they are sufficient. The forged account supplies a session that the FTP daemon accepts; the
daemon's chroot is the device `/tmp`; the rename primitive reaches the OpenVPN configuration path; the
service supervisor consumes that path as root on the next VPN service action. Section 7 traces the data
flow through all four steps, and section 8 shows how the shipped proof of concept exercises each one.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | NETGEAR |
| Product | RAX200 (Nighthawk AX12), WiFi 6 router |
| Version analyzed | V1.0.11.148 (image `RAX200-V1.0.11.148_1.0.82.chk`, board U12H390T00_NETGEAR) |
| Platform | Broadcom v8A, 32-bit ARM EABI5, Linux 4.1.4 |
| Authentication class | Authenticated (Target B): an administrator session on the router's management plane |
| Account component | management-side rebuild routine at fcn.000c0d44 writing `/tmp/samba/private/passwd` |
| FTP component | bftpd 4.8 at `/usr/sbin/bftpd`, md5 `03b8a49698dfe167c3f8c68999e06d38` |
| Upload gate | `strncmp(mapped, "/shares/", 8)` at 0x155b4 in `do_stor` (0x1558c, `commands.c:754-758`) |
| Rename command | `command_rnto` at 0x1616c (`commands.c:1868-1910`); old-path check at 0x161c0, `rename` at 0x1621c |
| Trigger component | service supervisor `acos_service` at fcn.0001d8ac, `system()` at 0x1daa4 |
| Hijacked file | `/tmp/server_tap.conf` (recorded hijack artifact: 53 bytes) |
| Hook script | `/tmp/shares/p` (recorded artifact: 144 bytes) |
| Command interpreter | OpenVPN 2.5.4 with `script-security 3` and `up "/bin/sh /tmp/shares/p"` |
| Observed identity | `uid=0`, inside the replication environment only |
| Primary CWE | CWE-78 |
| Published score | 7.2 High - `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| CVE identifier | none assigned |

### Vulnerability Summary mechanics

The first half is the account rebuild. The management plane keeps account material in NVRAM under keys
whose names the image exposes as `user_setup_num`, `user_setup_user%d` and `user_setup_pwd%d` (string
addresses 0x12db57 and 0x12db69), together with an alphabetic index family `user_setup_user%c`. The
rebuild routine at fcn.000c0d44 reads those values and renders one line per account with the format string
at 0x12e90b, referenced from 0xc0f44 and 0xc1034:

```c
/* fcn.000c0d44 - rebuild of the account database, reconstructed from the image */
sprintf(line, "%s:%s:0:0:%s:/:/bin/sh\n", user, passwd, gecos);   /* 0x12e90b */
/* disabled-account variant, same shape: */
sprintf(line, "%s:*:0:0:%s:/:/bin/sh\n", user, gecos);            /* 0x12e8b7 */

f = fopen64("/tmp/samba/private/passwd", "w+");                   /* 0xc0da8 */
fwrite(line, ...);
/* and the Samba copy */
fopen64("/tmp/samba/private/smbpasswd", ...);                     /* 0xc1250 */
```

The uid and gid fields are literals `0`, so every account this routine writes is a root account as far as
the passwd file is concerned; that is a design decision of the consumer account model, not the defect.
The defect is that `%s` receives unvalidated text: a password or account value containing a newline
contributes a complete additional line, and because the reader of the file is the C library's passwd
parser, that additional line needs exactly seven colon-separated fields to be accepted. A value of the
form `x\nROOT2:<sha256 of the chosen password>:0:0:g:/tmp:/bin/sh` therefore yields one ordinary account
line and one forged root line whose home directory is `/tmp` and whose shell is `/bin/sh`.

The second half is the rename. bftpd's upload path is properly bounded. `do_stor` maps the requested name
into the chroot, compares the mapped path against the literal `/shares/` (string at 0xc4b4) for eight
bytes at 0x155b4, and answers 550 with the string at 0xbdb8 when the comparison fails. `command_rnto` does
not repeat that check on both of its operands: it stores the old name from `RNFR` in session state, maps
the new name, and compares only the stored old path against the same eight-byte prefix at 0x161c0 before
calling `rename(old, new)` at 0x1621c. The destination is never examined. Inside a chroot whose root is
`/tmp`, the destination `/server_tap.conf` resolves to `/tmp/server_tap.conf` on the device.

### Vulnerability Summary preconditions

1. The attacker holds the router administrator's credential and can drive the management plane. This is the
   whole privilege story: no authentication bypass, no session forgery and no credential disclosure is
   involved anywhere in the chain.
2. The ReadyShare account domain accepts a value containing a line feed and colon-delimited text, and the
   FTP login derived from the resulting passwd line succeeds. The FTP service must be enabled, which is a
   management-plane setting.
3. The OpenVPN service has been configured at least once, so that the supervisor's certificate presence
   gate passes and `/tmp/server_tap.conf` exists as a file the rename can replace. Where no certificates
   exist, the supervisor returns before reaching the `system()` call.
4. No memory groom, no reboot window, no timing race and no client software beyond an FTP client and a
   browser session.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The chain sits behind the management plane of the router. An administrator session is required to reach
the ReadyShare account configuration and to reach the VPN service controls, and the FTP account the chain
uses is itself an artifact of the administrator-maintained account store: the rebuild routine writes every
account with uid 0 and gid 0, and bftpd's login path applies `setgid(0)`, `chroot(ROOTDIR)` and `setuid(0)`
in that order at 0x182b8, so a session established with a forged entry runs with root identity inside the
chroot. The FTP daemon's configuration in this image sets `ROOTDIR="/tmp"`, `DO_CHDIR=yes`,
`AUTO_CHDIR="/shares"`, `AUTH="PASSWD"` and `LOG_WTMP="no"`; authentication is a password comparison in
`checkpass` at 0x17ff0 against the SHA-256 hex digest recorded in the passwd line.

Two consequences follow. First, this is a post-authentication finding by construction: the FTP session
that exercises the rename is a session the daemon granted, with credentials the device's own account
database contains. Second, the account model has no least-privilege tier to reach for: every account the
ReadyShare rebuild produces is written with uid 0 and gid 0 because the format string hard-codes those
fields, and the FTP daemon's own confinement is the chroot, not a dropped identity. The privilege boundary
this chain crosses is therefore not the passwd-file boundary - which the product's design makes
permeable - but the boundary between "write inside `/shares/`" and "write anywhere inside `/tmp`", and
then the boundary between "a file in a writable directory" and "a root-consumed service configuration".

### Authentication Boundary - the one link the record does not pin to a request

Honesty requires naming the weakest link in the chain's evidence rather than smoothing it. The dynamic
work seeded the forged passwd line directly into the replication mirror's account database, which
reproduces the semantics of the rebuild routine exactly but does not exercise an HTTP request. On a live
device the seeding step is an administrator action in the management interface whose value reaches NVRAM
and is then rendered by fcn.000c0d44; the research record does not identify the request-level parameter
names for the account dialog on this 2020-era build. The sibling product's parameter family
(`user_setup_tmp_user` / `user_setup_tmp_pwd`) has no same-named string in this image, whose account
surface instead exposes a form-getter at fcn.00056ff0 and a 26 KB USB dispatcher at fcn.00016a4c that was
not fully triaged within the research budget. The chain's FTP half, its trigger half and the
"passwd-line-to-forged-account" semantics are each established statically and dynamically; the exact
HTTP key that carries the value on this build is the part left open, and the shipped proof of concept
therefore treats account seeding as an operator step in the management interface rather than as an
automated request.

### Authentication Boundary - why that boundary does not soften the impact

An administrator of a consumer router can already change settings, so it is fair to ask what the chain
adds. The answer is the difference between a settings interface and an operating system. The product's
management surface exposes a finite set of operations; "run this program as root" is not one of them, and
neither is "replace the configuration file the VPN daemon will be started with". The chain crosses that
line and returns with the authority of the service supervisor, which runs the VPN daemon as root. The
practical distinction matters for deployment as well: a household or small-office administrator may
legitimately delegate the web password to a family member, a managed-service operator or a monitoring
integration, and none of those delegates is supposed to obtain a root shell on the network's chokepoint.
This finding is exactly the collapse of the assumption that the settings administrator is not, by that
fact alone, root on the device.

## 4. Attack Surface

### Attack Surface - the two services and the file that joins them

The reachable surface is the ReadyShare FTP service on TCP port 21 and the management plane's account and
VPN pages. Neither is exotic. The FTP service is the consumer file-sharing daemon of the product line,
bftpd 4.8, running with a chroot into `/tmp` and an automatic `cd` into `/shares`; the management plane is
the vendor's own httpd, which both writes the account database and owns the VPN configuration lifecycle.
The join between them is a file path. `/tmp/server_tap.conf` is produced by the OpenVPN configuration
save/apply path on the httpd side (the image carries the `openvpn_make_config_file` string there), it lives
in the writable subtree that the FTP chroot exposes, and the service supervisor reads it on the next VPN
service start.

### Attack Surface - the supervisor and its command lines

The supervisor function at fcn.0001d8ac is the component that turns the file into a process. Reconstructed
from the disassembly, its sequence before starting the tunnel daemons is:

```c
/* fcn.0001d8ac - OpenVPN service start, reconstructed from the disassembly */
access("/tmp/openvpn/ca.crt", ...);      /* 0x1d954 - 0x1d9e0 */
access("/tmp/openvpn/client.crt", ...);
access("/tmp/openvpn/server.crt", ...);
access("/tmp/openvpn/server.key", ...);
/* missing -> log "is not exist" -> return (fail closed on the certificates) */

system("mkdir /dev/net");                                     /* 0x1da70 */
system("mknod -m0600 /dev/net/tun c 10 200");                 /* 0x1da7c */
system("abFifo /tmp/openvpn_log_tap ... &");                  /* 0x1da84 neighbourhood */
system("/usr/local/sbin/openvpn /tmp/server_tap.conf &");     /* 0x1daa4  <-- sink */
system("/usr/local/sbin/openvpn /tmp/server_tun.conf &");     /* 0x1dab8 */
/* teardown: "ps | grep abFifo | grep openvpn | awk ... | xargs kill -9" */
```

The start function deliberately does not regenerate the configuration file: the record notes that it
performs the certificate checks and a copy of the result to `/tmp/openvpn_zip`, and contains no write to
`/tmp/server_tap.conf`. The file is therefore an input, not an output, of this function - which is exactly
what makes it a sink operand. It is also worth being precise about the gate: the only test the record shows
between the entry of the function and the `system()` call is the existence of four certificate files. There is no
ownership check, no mode check, no signature check and no comparison against a generated copy. The function
fails closed on absent certificates and open on a present configuration file.

### Attack Surface - what narrowed out and why it matters

- The upload prefix gate is not broken and was not bypassed. `STOR /dev/null` and every other destination
  outside `/shares/` answers 550, which the dynamic record confirms as a negative control. The chain never
  needs an upload outside the subtree; it uploads inside `/shares/` and moves the file afterwards.
- The command channel cannot set an execute bit: `ALLOWCOMMAND_SITE` is not enabled in this configuration,
  so there is no `SITE CHMOD` path. The chain does not need one, because OpenVPN's `up` directive invokes
  the hook as `/bin/sh <path>`, and a shell script does not have to be executable for the interpreter to
  read it. The uploaded script is therefore left at the default 0644, which the rename preserves.
- The FTP daemon has no writable-path allowlist beyond the upload prefix, and no post-rename check. There
  is no second line of defense between `rename` and the filesystem.
- The management plane's own file-writing surfaces (firmware upload, configuration restore) are separate
  features with their own validation and are not part of this chain; the chain needs only the account
  domain and the VPN service toggle.

## 5. Sink Identification

### Sink Identification - the command-execution sink

There are two sinks in the chain and only one of them executes commands. The command-execution sink is the
`system()` call at 0x1daa4 inside fcn.0001d8ac: a fixed string, no interpolation, no attacker bytes in the
command text itself. What the attacker controls is not the command but the argument file it names - and
`system()` runs through `/bin/sh`, so the child inherits the supervisor's identity, which for a service
start on this platform is root. The chain therefore does not need command injection in the classic sense;
it needs control of an input a root process trusts, which is a weaker requirement and a more durable
defect, because no amount of quoting inside the fixed string would help.

The second sink is the file write itself: `rename(old, new)` at 0x1621c in `command_rnto`. This is the
sink that the FTP session calls directly, and it is the one whose operand validation is missing. Its
effect is a path substitution inside a chroot that contains a root-consumed configuration file.

### Sink Identification - why the hook fires

OpenVPN 2.5.4 reads the hijacked file and honors two directives in it: `script-security 3`, which permits
user-defined scripts, and `up "/bin/sh /tmp/shares/p"`, which names a command to run when the tunnel device
comes up. The recorded hook line shows when and how the daemon invokes it, and with which arguments:
`/bin/sh /tmp/shares/p tun0 1500 1500 init` - the tunnel device has been opened, and the interface name,
the MTU values and the `init` argument are passed to the command. The script the FTP session uploaded is at
`/tmp/shares/p` - inside the chroot, outside the hijacked file, and reachable by the absolute path the
configuration names. The daemon's child runs as uid 0 because the daemon itself does.

### Sink Identification - ownership and appearance of the planted artifacts

Two details make the planted file hard to distinguish from a legitimate one. First, the FTP session's
identity is uid 0 inside the chroot, because `bftpd_login` applies `setgid(0)`, `chroot(ROOTDIR)` and
`setuid(0)` for the passwd entry, and the forged entry's uid is 0. Files the session creates are therefore
root-owned. Second, `rename` preserves ownership and mode, so `/tmp/server_tap.conf` ends up root-owned and
0644 - the ownership and mode a configuration file written by the device's own configuration path would
have. A reviewer looking only at `ls -l` sees nothing anomalous.

## 6. Source Identification

### Source Identification - the rename operands

The source of the escape is the pair of operands to the FTP rename command: the `RNFR` argument, which the
daemon stores in session state, and the `RNTO` argument, which the daemon maps and passes to `rename`.
Reconstructed from the disassembly, the two commands read:

```c
/* do_stor, 0x1558c, commands.c:754-758 */
mapped = mappath(name);
if (strncmp(mapped, "/shares/", 8) != 0)      /* 0xc4b4, 0x155b4 */
    reply(550, "Error: Access Denied.");      /* 0xbdb8 */
...
/* command_rnto, 0x1616c, commands.c:1868-1910 */
newpath = mappath(newname);                   /* r5 */
oldpath = session->rnfr_path;                 /* r6 */
if (strncmp(oldpath, "/shares/", 8) == 0)     /* 0x161c0 - OLD operand only */
    rename(oldpath, newpath);                 /* 0x1621c - NEW operand unchecked */
else
    reply(550, ...);
```

The asymmetry is visible in the register discipline as well as the source: the comparison at 0x161c0 is
applied to r6, the stored old path, while r5, the freshly mapped destination, flows into the call at
0x1621c without ever being compared. The check that guards the upload path is correct; the check that
guards the rename destination is absent.

### Source Identification - the account value

The source of the forged account is the account/password value in the management plane. It reaches NVRAM
under the `user_setup_pwd%d` family and is rendered by fcn.000c0d44 with `%s` into a passwd line. There is
no escaping of `:` (the field separator) and no rejection of `\n` (the record separator) anywhere between
the NVRAM value and the `fwrite`, so the value can contribute fields and lines. The seven-field shape is
not an accident of the exploit but a requirement of the consumer: the C library's passwd parser splits on
colons and expects seven fields, and a shorter line is discarded. A working forged line therefore carries
user, hash, `0`, `0`, gecos, home and shell in that order.

### Source Identification - what the payload must respect

The rename destination must be an absolute path inside the chroot, and the practical target is the
configuration file the supervisor will read. Because `mappath` resolves inside the chroot and the rename
does not follow the prefix rule, an absolute destination such as `/server_tap.conf` is enough; no `../`
traversal is required, and none is used. The upload that precedes it must stay inside `/shares/`, which
costs the attacker nothing: the staging directory is the working directory the daemon enters automatically
(`AUTO_CHDIR="/shares"`), and both the hook script and the configuration file are small.

## 7. Data Flow

### Data Flow - end to end

```
[ADMINISTRATOR SIDE]                        [RAX200, V1.0.11.148]
admin session (management plane)
        |
        |  ReadyShare account value:
        |  "x\nROOT2:<sha256(password)>:0:0:g:/tmp:/bin/sh"
        v
   NVRAM user_setup_pwd%d  ->  httpd fcn.000c0d44
        sprintf("%s:%s:0:0:%s:/:/bin/sh\n")  @0x12e90b
        fwrite -> /tmp/samba/private/passwd  (= /etc/passwd)
        |
        |  FTP :21 login ROOT2 / password
        v
   bftpd 4.8  ->  bftpd_login @0x182b8
        setgid(0); chroot("/tmp"); setuid(0)
        |
        |  CWD /shares
        |  STOR p        (up-hook script, 0644, root-owned)
        |  STOR c.conf   (dev tun / script-security 3 / up "/bin/sh /tmp/shares/p")
        |  RNFR /shares/c.conf   -> 350
        |  RNTO /server_tap.conf -> 250   (destination unchecked @0x161c0/@0x1621c)
        v
   /tmp/server_tap.conf  <- attacker-controlled, root-owned, 0644
        |
        |  admin action that starts the VPN service
        v
   acos_service fcn.0001d8ac
        access() certificate gate  @0x1d954-0x1d9e0
        system("/usr/local/sbin/openvpn /tmp/server_tap.conf &")  @0x1daa4
        v
   OpenVPN 2.5.4 reads the hijacked configuration
        script-security 3
        up "/bin/sh /tmp/shares/p"
        v
   /bin/sh /tmp/shares/p tun0 1500 1500 init      ->  uid 0
```

### Data Flow - properties worth naming

- The taint never crosses a memory-safety boundary. There is no overflow, no use-after-free and no
  type confusion anywhere in this chain; every step is an ordinary string or path operation whose
  validation is incomplete.
- The decisive re-parse is not performed by an attacker component. `/bin/sh` is the product's own choice
  of execution interface for the `system()` call, and the `up` directive is the product's own feature.
- Every hop is a product feature used as designed: the account store, the FTP rename, the service
  supervisor and the OpenVPN hook. Nothing is malformed at the protocol level, and no packet needs to be
  crafted at all.
- The chain is order-sensitive only in one place: the configuration file must be in place before the
  service action, and the hook script must be in place before the daemon starts. Both are satisfied by
  staging the files before the escape and by the escape before the service action.
- The `/tmp` to `/var/tmp` relationship in the shipped image means the on-device path `/tmp/server_tap.conf`
  resolves through a symbolic link to `/var/tmp/server_tap.conf`. Both the writer and the reader go through
  the same link, so the substitution is transparent to the supervisor.

## 8. Exploit Construction

The shipped proof of concept is `exploit/netgear_rax200_bftpd_rnto_poc.py`. It is a standard-library-only
FTP client that stages the two files and performs the escaping rename, and that prints the forged account
line the operator has to place in the account field beforehand. It does not attempt the account seeding
over HTTP - section 3 explains why, and the reason is evidential rather than a limitation of the tool - and
it does not attempt the VPN service action, because that is a management-plane operation the operator
performs with the session they already hold. Its defaults are a documentation-range target (`192.0.2.10`),
port 21 and the marker-only hook; `--stage-only` performs the two uploads without the escaping rename.

### Exploit Construction - the staged artifacts

The two files are the whole payload. The configuration below is 53 bytes and is byte-for-byte the file the
recorded run planted; the hook script follows the recorded payload's shape with the marker path and the
identifier text changed to the ones the shipped PoC uses, so that its output is unambiguous in an
operator's own environment (the recorded run's hook was 144 bytes):

```text
dev tun
script-security 3
up "/bin/sh /tmp/shares/p"
```

```sh
#!/bin/busybox sh
/bin/busybox echo RAX200-BFTPD-RNTO-MARKER > /tmp/rax200_bftpd_marker.txt
/bin/busybox id >> /tmp/rax200_bftpd_marker.txt
```

The hook writes one marker file and the identity of the process that wrote it. It contains no destructive
action, no persistence and no network callback; an operator extending it for an authorized test replaces
the two lines deliberately. The configuration names the interpreter explicitly (`/bin/sh`) so that the
script does not need an execute bit, which matters because the session cannot set one.

### Exploit Construction - the FTP dialogue

The session below is the six-step primitive set the research record exercised against the real daemon, with
the artifact sizes that run recorded; the shipped PoC drives the same command sequence, and its hook differs
only in the marker text it writes:

```text
[+] banner   : 220 bftpd %4.8 at %127.0.0.1 ready.
[+] login    : 230 User logged in.
[+] cwd      : 250 OK
[+] STOR p        (hook script, 0644) ok
[+] STOR c.conf   (attacker OpenVPN config) ok
[+] rnfr     : 350 File exists, ready for destination name
[+] rnto     : 250 OK                            <- destination not validated
[+] artifact /tmp/server_tap.conf exists=True size=53
[+] artifact /tmp/shares/p        exists=True size=144
```

Two steps in that transcript are load-bearing. `STOR` succeeds only inside `/shares/`, so the payload never
touches the escape path during upload; and `RNTO` answers 250 for a destination that is not under
`/shares/`, which is the vulnerability. The negative control in the same session - `STOR /dev/null`
answering `550 Error: Access Denied.` - is what establishes that the prefix gate is real and that the
escape is reached only through the rename.

### Exploit Construction - what the PoC deliberately does not do

- It does not brute-force, guess or collect credentials. The FTP account and password are operator-supplied
  arguments, and the account named in the forged line is a placeholder the operator chooses.
- Its default marker is non-destructive: one file under `/tmp` containing a fixed string and the output of
  `id`. There is no file deletion, no service termination, no account modification and no callback.
- It does not automate the management-plane steps. The operator seeds the account value and triggers the
  VPN service action; the tool states both prerequisites in its output instead of pretending to satisfy
  them.
- It keeps an audit trail: it prints the target, the forged passwd line, the FTP responses and the two
  destination paths, so an authorized test is reproducible from the console log alone.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Verification environment | firmware-root replication mirror on an isolated cloud host |
| Userland | the analyzed image's own: bftpd 4.8, OpenVPN 2.5.4, busybox, service binaries |
| Execution | user-mode 32-bit ARM emulation, daemon started as `chroot <mirror> /qemu-arm /usr/sbin/bftpd -D -c /tmp/bftpd.conf` on port 2121 |
| Mirror preparation | `/tmp` replaced by a real directory (the image's `/tmp` is an absolute symlink to `/var/tmp`); `/var/log`, `/var/run` and `/var/tmp` recreated; `/dev/net/tun` created with `mknod c 10 200` |
| Account state | forged line written into the mirror's `/tmp/samba/private/passwd`, the same file `/etc/passwd` links to on the device |
| Root sink | the supervisor's command line replayed verbatim inside `unshare -n -m` plus `chroot`: `/usr/local/sbin/openvpn /tmp/server_tap.conf` |
| Not performed | any request against device hardware; no physical RAX200 was driven and no live management session was used |
| Observation channel | marker file written by the hook and read from the mirror filesystem |

### Dynamic Verification - results

The six-step primitive set completed against the real daemon:

```text
[+] banner   : 220 bftpd %4.8 at %127.0.0.1 ready.
[+] login    : 230 User logged in.              <- forged uid-0 entry accepted
[+] cwd      : 250 OK                           <- chroot(/tmp), AUTO_CHDIR=/shares
[+] STOR p (root payload script, 0644) ok       <- /tmp/shares/p, the up-hook payload
[+] STOR c.conf (attacker openvpn server conf) ok
[+][neg]     STOR outside /shares/ rejected: 550 Error: Access Denied.
[+] rnfr     : 350 File exists, ready for destination name
[+] rnto     : 250 OK                           <- destination not validated
[+] artifact /tmp/server_tap.conf exists=True size=53
[+] artifact /tmp/shares/p exists=True size=144
```

The root sink then ran the supervisor's own command line and produced:

```text
OpenVPN 2.5.4 arm-glibc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] ...
TUN/TAP device tun0 opened
/bin/sh /tmp/shares/p tun0 1500 1500   init
[C13 PASS] marker /tmp/rax200c13/tmp/RAX200_C13_EXEC_TRIGGER:
uid=0(RAX200C13) gid=0(nobody) groups=0(nobody)
```

The first four lines are the daemon's own output, the fifth is the harness's marker-detection line quoted as
it was produced, and the last is the contents of the marker file. The identity line is the measured proof
of this advisory: the hook executed as uid 0, inside the replication environment. It is not a live-device
observation, and the account name in the parentheses is the mirror's forged account name, not a device
artifact.

### Dynamic Verification - the control that makes the result attributable

A second run replaced only the configuration file: same sink, same daemon, same command line, but a
configuration with `script-security 2` and no `up` directive. The tunnel device opened normally and no
marker was created. Because the only difference between the two runs is the content of the injected
configuration, the marker is attributable to the hijacked file and not to the restart of the daemon or to
the marker path being writable for other reasons. The negative control on the upload path (`STOR` outside
`/shares/` answered 550) plays the same role for the rename: the escape is not an artifact of a permissive
upload gate.

### Dynamic Verification - boundary statements

- Root was observed inside a replication environment only. No root shell, marker or command execution was
  observed on RAX200 hardware, and this advisory does not claim any.
- The account seeding step was performed by writing the forged line into the mirror's account database,
  not by an HTTP request. The rebuild routine's behavior is established statically at fcn.000c0d44; the
  request-level parameter names for this build were not identified.
- The VPN service action was not performed on hardware. The supervisor's command line was executed
  verbatim under namespace and chroot isolation, which reproduces the sink's argument handling and the
  daemon's configuration consumption, not the supervisor's own control flow around them.
- The OpenVPN process in the mirror exited shortly after the hook because the mirror has no entropy source
  for its RNG initialization. The record notes this and does not read it as a device behavior; the hook had
  already run, which is the fact the marker records.
- The mirror's `/etc/group` names gid 0 `nobody`; the group name in the recorded identity line is a mirror
  artifact and carries no device meaning.

## 10. Reachability and Security Impact

### Reachability - network position

The chain is delivered entirely over the network to two services: the FTP service on port 21 and the
management plane. Nothing in it requires console access, physical proximity or a local account. The
published vector therefore uses `AV:N`, reflecting an attack that is carried by network protocol exchanges
against listening services. The qualification belongs in prose rather than in the vector: which interfaces
reach those services is decided by each deployment's own firewall and remote-management policy, and this
research did not measure that policy. Where the FTP service is confined to a local segment, an attacker's
position is that segment or a routed path to it; where an operator has exposed the management plane or the
file service beyond it, the position widens accordingly. Neither configuration was measured, and this
advisory makes no claim about a default.

### Reachability - who the affected population is

The credential requirement defines the population precisely rather than shrinking it to nothing. Every
legitimate holder of the administrator credential is in scope - the owner, a delegated household or office
administrator, a managed-service operator, an integration or monitoring account - and so is any party who
has obtained that credential by other means, for whom this chain converts a web password into a root shell
with no further step. The consumer router is the network's chokepoint for everything behind it, which is
why the impact of a root identity on it is disproportionate to the device's own value.

### Reachability - impact in concrete terms

Root on the device yields the complete configuration store, including the credentials and key material the
firmware keeps for its own operation - among them the OpenVPN certificate and key files that the supervisor
itself checks before starting the tunnel. It yields the ability to create or modify accounts, startup
scripts and scheduled tasks within the writable filesystem, subject to what survives a reboot on this
platform, which was not tested. It yields control of interfaces, routes and the DNS resolver the local
network depends on, and therefore the ability to redirect or observe traffic within the platform's own
capabilities. It yields availability impact at will, from stopping services to corrupting the writable
filesystem. And it yields all of that from a position that produces no exploit-shaped traffic: an
authenticated FTP rename and an ordinary VPN service action.

## 11. Fix Recommendations

1. Validate both operands of the rename. `command_rnto` should canonicalize the destination inside the
   chroot and apply the same `/shares/` prefix rule that `do_stor` already applies to uploads, failing the
   command otherwise. A destination that resolves outside the shares subtree, whether by absolute path or
   by traversal, must be rejected before `rename` is called. The existing check on the source operand is
   correct and should be kept; the missing half is the destination.
2. Stop writing account lines from user-supplied text. The rebuild routine at fcn.000c0d44 should reject
   `:` and newline in the account and password fields (an allowlist for the account name is preferable),
   or, better, should not generate passwd lines at all: use the platform's account database through a real
   backend so that field and record separators are handled by a parser rather than by `sprintf`.
3. Do not create root accounts for the file-sharing service. Every entry this routine writes is `0:0`, and
   bftpd logs in with that identity. A dedicated unprivileged account, with the shares owned accordingly,
   caps what an FTP session can do even when its path validation fails.
4. Keep privileged service inputs out of writable, service-reachable directories. `/tmp/server_tap.conf`
   should be generated atomically into a directory that the FTP chroot cannot address - a root-owned
   subdirectory outside `ROOTDIR`, or a path handed to the daemon through a file descriptor - and the
   supervisor should verify ownership, mode and freshness against the generated copy before executing it.
5. Replace the shell-mediated start with an argument-array exec. `system("/usr/local/sbin/openvpn
   /tmp/server_tap.conf &")` gives the configuration file the same weight as a command line; an
   `execve`-family call with a fixed argument vector, and a configuration path the caller cannot influence,
   removes the class rather than the instance.
6. Harden the OpenVPN configuration consumption. `script-security 3` together with an `up` directive in a
   file that any local writer can replace is the property that turns a configuration hijack into command
   execution. If the product does not need user scripts for the tunnel, pin `script-security` to the
   minimum the feature requires and forbid `up` in configurations the supervisor did not generate.
7. Add regression tests at both boundaries. For the FTP daemon: `RNTO` to an absolute path outside
   `/shares/` must fail, and `STOR` outside `/shares/` must keep failing. For the account domain: an
   account or password value containing a newline or a colon must be rejected, and the resulting passwd
   file must contain exactly one line per configured account.
8. For operators until a fix is available: keep the management plane off any wide-area interface, disable
   the ReadyShare FTP service where it is not needed, and treat an unexpected change to the VPN
   configuration as a compromise indicator rather than a settings anomaly.

## 12. CWE

### CWE - classification rationale

- CWE-78 (Improper Neutralization of Special Elements used in an OS Command) is the primary class, and it
  is the class the research record assigns to the chain. The final step is command execution by a root
  service whose command line names a file the attacker controls, and the executed text is a shell script
  the attacker authored. The neutralization failure is upstream of the shell: the product neither keeps the
  configuration file out of the attacker's reach nor validates it before use.
- CWE-22 (Improper Limitation of a Pathname to a Restricted Directory, path traversal) is co-equal for the
  FTP half. The defect is precisely that one operand of a two-operand path operation is confined to
  `/shares/` and the other is not, so a relative-to-chroot destination escapes the intended subtree. It is
  a path-confinement failure, not a string-escaping failure.
- CWE-20 (Improper Input Validation) is the contributing class for the account half: a value crossing into
  a structured file format without separator handling, which is what makes the forged account possible.
- CWE-73 (External Control of File Name or Path) describes the sink relationship - the supervisor executes
  a path whose content an external party can set - and is reported here as a reading of the same defect,
  not as an additional score-bearing weakness.
- CWE-306 (Missing Authentication) and CWE-288 (Authentication Bypass) are explicitly not applicable: the
  chain consumes a legitimate administrator session and a legitimate FTP login, and section 3 states that
  boundary in full.
- The research record's summary line also carries a secondary path-equivalence tag (CWE-47). This advisory
  does not repeat it: the mechanism here is the absence of validation on the destination operand, not the
  equivalence of two spellings of one path, and no step of the chain depends on filename equivalence.
  CWE-22 is the class that describes what the rename actually does.

### CWE - why the primary tag is CWE-78 and not a file-write class

A reader could argue that the chain should be filed as an arbitrary file write, since the FTP primitive
writes a file and everything after it is the product behaving normally. That reading understates the
finding in the direction that matters for remediation: the write is only interesting because the file is
consumed by a root process as a command-bearing configuration, and because the daemon executes a script
named inside it. Filing it as a file write would invite a fix that hardens one path while leaving the
consumption pattern intact. Filing it as CWE-78 keeps both halves in view and matches the record's own
classification.

---

Written by the 0day Rubbish Research Team.
