# D-Link DAP-2310B (DAP-2660 byte-identical merge) - atp ExeShell Dollar-Parentheses Command Injection Executing as Root

## 1. Overview

### Overview of the finding

D-Link's DAP-2310B is a Wireless N300 business access point: an SMB-oriented indoor unit with an HTTP
management interface, deployed as interior wireless infrastructure rather than as an edge router. Its web
plane is a D-Link build rather than a packaged open-source stack. `sbin/httpd` (228756 bytes, appweb-derived)
carries the session and access-control templates, and behind it sits a self-built template processor,
`sbin/atp` (51296 bytes, stripped MIPS 32-bit MSB, MIPS32 rel2, uClibc). That processor implements a PHP-style
instruction set - query, set, get, anchor, fwrite, fread - and one of its builtins, `ExeShell`, executes a
shell command. `sbin/xgi` and `sbin/sgi` are symbolic links to the same binary, and the server configuration
template `/etc/templates/httpd/httpd.php` declares the extension mapping
`External { /sbin/atp { php txt} /sbin/xgi { xgi bin dcf log} /sbin/sgi { sgi } }`, so any `.xgi` URL is
dispatched to `atp`.

The defect is entirely inside `ExeShell`. Its argument is screened by a three-character blocklist, then
interpolated into the fixed format string `"%s > /dev/console"` and handed to `system()`, which executes it
through `/bin/sh -c`. The blocklist rejects `;`, `&` and `|` and requires a `submit` prefix per segment; it
does not reject `$`, `(`, `)` or the backtick, and `$( )` is a complete command container that needs no
separator at all. The value reaching the blocklist is already URL-decoded, and the parameter name is matched
case-insensitively, so the whole chain is reachable with one authenticated GET.

Two boundaries belong at the top of this document. First, the request must carry a valid administrator
session: the `.xgi` route is behind `SessionControl On` with `SessionFilter { php xgi _int }` and HTTP Basic
authentication, and the `atp` layer performs no authentication of its own. Second, the dynamic evidence is a
sink-level replication on an isolated sandbox, not an appliance: MIPS big-endian execution under
`qemu-mips-static` ended in SIGBUS for both `atp` and the device's busybox `ash`, so the end-to-end path was
not executed on emulated or physical hardware. The sections below keep those two halves of the evidence
separate: the request path, the decoder, the validator and the parameter gates are established by
disassembly and reconstruction; the substitution behaviour and the landing identity are established by the
replication.

### Overview of the product, platform and image

The analyzed firmware is DAP-2310B v3.00r048, delivered as `DAP-2310_REVB_FIRMWARE_3.00R048.zip` containing
`DAP-2310B_firmware_v3.00r048.bin` (9314496 bytes). The image uses a vendor header `wapn25_dkbs_dap2310b` at
`0x0`, an lzma stream at `0xa0`, and an unencrypted squashfs at `0xf00c0` (hsqs v4, 8330512 bytes, 1074
inodes), so the root filesystem is extractable directly with no protection layer to defeat. The device's
factory address is 192.168.0.50, and its factory credential pair, read from `etc/config/defaultvalue.gz`, is
`admin`/`admin` - recorded separately as CWE-798 and deliberately not treated as part of this chain.

The two facts that decide the reachability of the sink are worth naming at this point. First, `atp` is the
only component in the request path with a shell builtin; the httpd in front of it does not execute commands.
Second, `xgi_main` at `0x405304` decompiles to `arg1 = getenv("REQUEST_URI"); if (arg1) fcn.0040478c(arg1);
return 0;` - it processes the query string directly and never opens a template file. A `.xgi` URL therefore
does not need to exist on disk. The www trees of both affected models contain no `.xgi` file at all and
`cfg_valid` is a `.php` page; the extension alone selects the handler. This is what makes the sink reachable
from a bare query string rather than from a template the device happens to ship.

### Overview of public-record independence

The research record classifies the defect as a vendor-specific `atp` handler rather than as a known CVE in a
third-party component, and its NVD review of the DAP-2310 family found no entry describing `atp`/`ExeShell`
command injection; the historical D-Link identifiers for that model concern other subsystems. No identifier
is assigned for this finding, and none is claimed. The validator logic, the charset measurement and the
format-string construction are all read from the analyzed binary rather than from published material, so the
chain stands on its own evidence base.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value |
|------|-------|
| Product | D-Link DAP-2310B, firmware v3.00r048; DAP-2660, firmware v2.00r140 (byte-identical merge) |
| Affected component | `sbin/atp`, the `ExeShell` builtin at `0x405860` |
| Entry point | `.xgi` extension route, `exeshell` query parameter, authenticated GET |
| Sanitization | `fcn.00405690` at `0x405690`: three-byte separator set and a `submit` prefix |
| Sink | `system()` on `"%s > /dev/console"` formatted with the unsanitized value |
| Landing context | root, the context the record attributes to `atp` because httpd performs no setuid drop |
| Boundary | HTTP Basic administrator session plus the `.xgi` session predicate |
| Weakness class | CWE-78 primary; CWE-798 adjacent and disclosed separately |
| Verification | instruction-level disassembly plus sink-level replication (root marker; clean control) |

### Vulnerability Summary mechanics

The mechanism is a metacharacter-class gap, not a memory-safety defect and not a transport flaw. `ExeShell`
receives a string that the parser has already decoded and the validator has already accepted. The validator's
model of the input is "a sequence of `submit`-prefixed segments separated by `;`, `&` or `|`", and within that
model a value without separators is inert. The shell's model of the same string is "words with expansions",
and within that model `$(...)` is an expression evaluated before the surrounding command runs. The validator
never consults the shell's model: it does not look for `$`, does not look for parentheses, does not look for
the backtick or the newline, and applies no quoting when the string is built into the command line. Both
parties believe they are describing the same string; they are not.

The consequence is confined to the string's role. Nothing about the request is unusual by the time it
reaches the sink: the parameter name is the one the handler expects, the value begins with the expected
`submit` word, and the page is an ordinary management page. The payload differs from a legitimate value only
in characters the validator does not model.

### Vulnerability Summary preconditions

Four conditions gate the branch, all of them satisfied by the recorded request: the parameter name must match
`ExeShell` case-insensitively; an `=` must be present in the examined segment; the page must not be
`remotemainte.xgi`; and the
value must not contain the string `telnetd`. The request-level filter adds one more: a request is blocked only
when `%60` and `telnetd` are both present. A separate precondition is authentication, covered in the next
section. Nothing in the list constrains `$`, `(`, `)` or the backtick.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The web server template `/etc/templates/httpd/httpd_server.php` sets `SessionControl On` and
`SessionFilter { php xgi _int }`, which places the `.xgi` extension - the extension the sink lives behind -
under session control, and it configures HTTP Basic authentication with a realm and `UserFile
/var/etc/httpasswd`. That password file is produced by `httpasswd.php` from the `rgdb` key `/sys/user`, so the
administrator account material is generated by the device from its own configuration store at boot rather
than shipped as a static file.

The effect is a single gate in front of the whole `.xgi` route: a request without a valid session and a valid
Basic credential does not reach `xgi_main` at all. The route is therefore an authenticated administrator
surface, and this advisory scores it as such with Privileges Required: High.

### Authentication Boundary - what the chain does not do

The `atp` binary adds no authentication of its own. `xgi_main` at `0x405304` takes `REQUEST_URI` from the
environment and passes it to the parser at `fcn.0040478c`; no session identifier, no user record and no
permission check appears in that path. The value-shape gates described in section 6 are all that stands
between the parsed parameter and `ExeShell`, and none of them is an authorization check. In practical terms
the boundary is exactly the one httpd enforces, and no additional defense-in-depth layer exists behind it.

The record's gate list for this branch contains no token, nonce or re-authentication step beyond the session
predicate and the Basic credential, and the gates it does list are value-shape checks, not authorization
checks. That is stated as what the record shows, not as a claim about every httpd feature in the image.

### Authentication Boundary - why that boundary does not soften the impact

An administrator credential is a legitimate way to manage an access point; it is not a legitimate way to
obtain a root shell on one. The interface being abused is a management page whose contract is "reconfigure
this device", and the chain silently widens the contract to "execute this command". The boundary raises the
score's Privileges Required weight and thereby lowers the number, but it does not change what the attacker
obtains once past it: root-context command execution, with no interaction and no visible response.

Two further points keep the boundary from being read as mitigation. Changing the administrator password does
not remove the defect, because the defect consumes whatever valid credential the operator has set; and the
factory-default pair is a separate CWE-798 finding, so neither of the two issues is a substitute for the
other. An operator who rotates the default password has closed the default-credential exposure and has
changed nothing about this injection.

## 4. Attack Surface

### Attack Surface - the web plane and its dispatch model

The request path is short and fully documented in the image's own templates:

```
GET /<page>.xgi?...          -> sbin/httpd (session predicate + Basic auth)
                             -> External { /sbin/xgi { xgi bin dcf log } }
                             -> sbin/xgi (symlink to sbin/atp)
                             -> xgi_main @0x405304 -> fcn.0040478c(REQUEST_URI)
                             -> key match -> ExeShell @0x405860 -> system()
```

Because `xgi_main` never opens a file, the surface is not the set of `.xgi` templates on disk - there are
none - but the set of query strings the parser accepts. That widens the practical surface compared with a
template-driven handler: any path ending in `.xgi` that the server routes reaches the parser, and the parser
decides what to do with the query.

### Attack Surface - why the surface audit narrowed here

`atp` contains a small number of shell-mediated sinks relative to the surrounding binaries, and most of them
are not reachable with an attacker-controlled string on this path. `ExeShell` is the exception in kind, not
only in degree: it is a general-purpose command runner exposed as a template builtin, whose only guard is a
validator that models three characters. That combination - unconditional shell-out, attacker-controlled
argument, token-level validator - is what made this the finding rather than one of the fixed-string call
sites.

The dispatch question was examined and answered: the `.php` route (`atp_main` into `procPage`) does not reach
`ExeShell`, and the `.xgi` route (`xgi_main` into the query parser) does. The second route is the one the
device actually serves for `.xgi` extensions, and it is the one this chain uses.

### Attack Surface - components that narrowed out

- `ConfigGetOnly` at `0x405998` is a second sink the record identifies: it builds `rgdb -s %s '%s'` with the
  interpolated value inside single quotes. It is a weaker construction than `ExeShell` - the quoting changes
  what the shell does with the value - and it is recorded as a secondary observation rather than as the
  primary chain.
- `fcn.004041dc`, `fcn.004076f0` and `fcn.0040799c` are further shell call sites named in the record as
  candidates for the same audit; none is shown to receive an attacker-controlled value on this path, so none
  is claimed here.
- The request-level filter that blocks `%60` together with `telnetd` narrowed out as a defense: it requires
  both tokens, so it does not fire on `$()` and does not fire on a backtick payload that never mentions
  `telnetd`.
- The `remotemainte.xgi` page exclusion narrowed out as a constraint, not as a defense: it removes one page
  from the reachable set and leaves the rest.

## 5. Sink Identification

### Sink Identification - the construction at 0x405860

The reconstruction of the handler is short enough to quote in full:

```c
uint sym.ExeShell(char *s) {
    if (fcn.00405690(s) != 0) {
        sprintf(buf, "%s > /dev/console", s);
        system(buf);
    }
    return 1;
}
```

Three properties are load-bearing. The validator is the only gate, and it is called once. The format string is
a constant at `0x409c80` and contributes nothing but a console redirection, so the argument occupies the
command position itself - the string starts executing. And the result of `system()` is not inspected, so a
payload whose primary command fails still completes whatever its substitution did.

### Sink Identification - the resolved callees

The two calls were resolved through the GOT rather than assumed from the disassembly text: `0x41b920` holds
`0x4088b0`, the `sprintf` entry, and `0x41ba2c` holds `0x4085a0`, the `system` entry. `system()` is libc's
`system`, which on this platform invokes `/bin/sh -c` with the constructed string; the shell is therefore an
explicit part of the data flow and not an implementation detail. The `strcasecmp` used by the key match is
resolved the same way, through `0x41ba04` to `0x408610`.

### Sink Identification - the string processor is not a control

The URL decoder is not a sanitizer and must not be read as one. It converts `%XX` into the literal byte and
stores the decoded pointer; it does not reject bytes, does not escape them and does not restrict the range it
produces. Its only role in the chain is to make the encoded request equivalent to a literal one, so the
validator sees the same characters the shell will later see. There is no second decoding pass and no
re-encoding between the decoder and the sink.

### Sink Identification - execution identity

The landing identity is the identity of the `atp` process. The record's finding is that `atp` runs as root
because the httpd path performs no setuid privilege drop, so `system()` inherits the root context. That
identity was observed inside the replication environment - the marker contains `uid=0(root) gid=0(root)
groups=0(root)` - and it is the record's conclusion for the device, drawn from the absence of a privilege drop
in the shipped path rather than from a measured device shell. This advisory states it in those terms and no
stronger ones.

## 6. Source Identification

### Source Identification - the parameter and its gates

The source is the value of the `exeshell` query parameter. The parser `fcn.0040405c` splits the query on `&`,
calls the decoder in place on each segment, and stores the decoded pointer; the key extracted before `=` is
then matched:

```c
if (strcasecmp(key, "ExeShell") == 0) {
    p = strchr(value, '=');
    if (p != NULL && strncasecmp(page, "remotemainte.xgi", 16) != 0
        && strstr(value, "telnetd") == NULL) {
        ExeShell(p + 1);
    }
}
```

Two details in that branch matter for payload construction. The comparison is `strcasecmp`, so
`exeshell=...` in lowercase reaches the same handler as `ExeShell=...`. And the handler is called with `p + 1`,
the bytes after the `=` that `strchr` located in the examined segment; in the recorded request that `=` is the
one separating the parameter name from its value, so `ExeShell` receives the value exactly:
`submit$(id>/tmp/marker)`. The record describes the condition as "value contains `=`" and the recorded payload
passes it, which is consistent with the separator being the `=` in question.

### Source Identification - the validator, character by character

```c
uint fcn.00405690(char *arg1) {
    s0 = arg1;
    while (isblank(*s0)) s0++;
    while (strchr(";&|", *s0)) s0++;
    while (isblank(*s0)) s0++;
    while (true) {
        if (strncmp(s0, "submit", 6) != 0) return 0;
        s0 = strpbrk(s0, ";&|");
        if (s0 == NULL) return 1;
        while (isblank(*s0)) s0++;
        while (*s0 && strchr(";&|", *s0)) s0++;
        while (isblank(*s0)) s0++;
        if (*s0 == 0) return 1;
    }
}
```

The charset is three bytes at `0x409c40`, measured directly as `3b 26 7c 00` - `;`, `&`, `|`, terminated. The
`submit` literal sits at `0x409c44`. `isblank` matches only space (`0x20`) and tab (`0x09`). The loop's
termination conditions are the only reason a normal management value ever passes: a value with no separator
returns 1 immediately after the prefix check. For `submit$(id>/tmp/marker)`, `strncmp` succeeds on the first
six bytes and `strpbrk` finds no separator, so the function returns 1 - allow.

### Source Identification - what the payload must respect

The accepted shape is therefore narrow but not restrictive: start with `submit` (case-sensitive), contain no
`;`, `&` or `|`, contain an `=`, avoid the literal `telnetd`, and avoid the `%60`-plus-`telnetd` combination
at the request level. Everything else is available. `$`, `(`, `)`, the backtick, the newline, quotes and
spaces all pass the validator untouched, and the decoder has already converted any percent-encoding before
the validator runs, so an encoded metacharacter is indistinguishable from a literal one by the time it
matters.

## 7. Data Flow

### Data Flow - end to end

1. The administrator session sends `GET /cfg_valid.xgi?exeshell=submit%24%28...%29` to port 80 of the device.
2. `sbin/httpd` applies the `.xgi` session predicate and the Basic credential check, then dispatches on the
   extension through the `External` mapping to `/sbin/xgi`.
3. `sbin/xgi` is the symlink to `sbin/atp`; execution enters `xgi_main` at `0x405304`, which reads
   `REQUEST_URI` with `getenv` and calls `fcn.0040478c` with it. No file is opened.
4. The parser `fcn.0040405c` splits the query on `&`; for each segment it calls `fcn.00401c90`, which decodes
   `%XX` in place and stores the decoded pointer.
5. The key is extracted with a `sscanf`-style `"%[^=]="` split and compared to `ExeShell` with `strcasecmp`;
   the lowercase `exeshell` matches.
6. An `=` is present in the examined segment; the page must not be `remotemainte.xgi`; the value must not
   contain `telnetd`. All three pass.
7. `ExeShell` is called with the bytes after the `=` located in that segment: `submit$(id>/tmp/marker)`.
8. `fcn.00405690` accepts the string: `submit` prefix matches, no `;&|` present, return 1.
9. `sprintf` builds `submit$(id>/tmp/marker) > /dev/console`; `system()` runs it through `/bin/sh -c`; the
   shell substitutes `id>/tmp/marker`, which executes as root; the `submit` stub then fails as an unknown
   command; the trailing redirection applies only to that stub.

### Data Flow - the decoder

```c
void fcn.00401c90(char *dst, char *src) {
    do {
        c = *src;
        if (c == 0) { *dst = 0; return; }
        if (c == '%') {
            *dst = hexval(src[1]) * 16 + hexval(src[2]);
            src += 2;
        } else {
            *dst = c;
        }
        dst++; src++;
    } while (true);
}
```

### Data Flow - properties worth naming

The decode happens once, in place, before every inspection that matters. The validator and `system()` see the
same bytes, so there is no encoded-versus-literal mismatch to exploit and no normalization gap between the
check and the use. The page gate compares only against `remotemainte.xgi` and is a string comparison, not a
grammar; the `telnetd` gate is a substring search on the value. Neither operator changes the string. And
because the command is constructed immediately before it is executed, with no intermediate store, there is no
window and no second consumer to reason about.

## 8. Exploit Construction

### Exploit Construction - request shape

```http
GET /cfg_valid.xgi?exeshell=submit%24%28cat%20/etc/passwd%20%3E%20/tmp/pwned_dap2310%29 HTTP/1.1
Host: 192.168.0.50
Authorization: Basic <base64 of administrator:credential>
User-Agent: Mozilla/5.0
Connection: close
```

The parameter name is written in lowercase on purpose: the comparison is `strcasecmp`, and the lowercase form
demonstrates that the match is case-insensitive rather than accidental. The value is percent-encoded for `$`,
`(`, `)` and `>` so that the request line stays a syntactically ordinary URI while the decoder reconstructs
the literal command for the validator and the shell.

### Exploit Construction - payload engineering

The default payload writes a marker rather than reading anything back, because the channel is blind: the
command's output is redirected to `/dev/console`, not to the HTTP response, so the response body carries no
evidence of execution and the only reliable confirmation is a device-side side effect. The recorded default
copies `/etc/passwd` to `/tmp/pwned_dap2310`; the PoC in this package writes a marker file instead and
supports only a marker path, deliberately narrower than the record's `--cmd` form.

Two device-specific details shaped the payload. The root filesystem's `bin/` contains 78 busybox applet
symlinks - `cat`, `echo`, `touch`, `cp`, `ls`, `sh`, `tar` among them - and no `id` applet, so an `id`-based
payload would fail on the device even though it succeeded in the replication, where `id` exists. The recorded
payload therefore uses applets that are demonstrably present. Second, the `submit` stub that follows the
substitution does not exist either; it fails as an unknown command, produces rc 32512 (`127 << 8`) and is
harmless, while `$(...)` has already run.

Alternative separators are available and were analysed rather than executed: a newline (`submit%0a<cmd>`,
which the validator does not inspect) and a backtick pair (`submit%60<cmd>%60`, which does not trigger the
`%60`-plus-`telnetd` request filter because the payload never mentions `telnetd`).

### Exploit Construction - what the PoC deliberately does not do

The script sends one GET, prints the status and a short body prefix, and writes only the marker it is told to
write. It does not attempt a reverse shell, does not modify configuration, does not upload a payload, does not
enumerate the filesystem beyond the marker write, and does not loop or retry aggressively. Its default target
is the documentation address 192.0.2.10 rather than any device address, and the administrator credential is a
required argument with no default, so the script carries no built-in credential. Against an unauthorized
target the script is a single malformed management request and nothing more.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

The verification boundary is instruction-level disassembly plus a native replication at the sink, executed on
an isolated x86-64 Linux sandbox. Full-device execution was attempted first and failed for platform reasons:

```text
chroot /tmp/dap2310_rootfs /usr/bin/qemu-mips-static /bin/busybox ash -c 'submit$(echo PWNED>/tmp/m1) > /dev/null 2>&1'
Bus error (core dumped)

REQUEST_URI=/cfg_valid.xgi?exeshell=submit%24%28id%3e/tmp/marker_dap_atp%29 qemu-mips-static ./sbin/xgi
core dumped (SIGBUS)
```

The `atp` binary and the device's busybox both core-dumped under `qemu-mips-static`; the MIPS big-endian
qemu-user SIGBUS limitation is recorded in this research line as a known blocker. Consequently no HTTP request
path was executed end to end, no emulated appliance served the request, and no physical access point was
driven. What remains is the sink-level replication: a native C program compiled on the sandbox that
reproduces the recorded construction exactly, including the fixed format string and the `system()` call.

### Dynamic Verification - vectors and results

```c
snprintf(buf, sizeof(buf), "%s > /dev/console", "submit$(id>/tmp/marker_dap_c13)");
system(buf);
system("submit id > /dev/console");
```

The replication used a bounded `snprintf` where the disassembly shows `sprintf`; the format string, the
argument and the `system()` call are identical, and the bounds difference does not affect the shell's
interpretation of the string. The recorded run produced:

```text
[C13] system() arg: submit$(id>/tmp/marker_dap_c13) > /dev/console
[C13] system() rc=32512
[C13-control] system() arg: submit id > /dev/console
[C13] MARKER CREATED -> $(id) executed (RCE confirmed)
  marker> uid=0(root) gid=0(root) groups=0(root)
sh: line 1: submit: command not found
```

Three results carry the finding. The marker file exists and contains `uid=0(root) gid=0(root) groups=0(root)`,
which proves the command substitution executed and executed as root in the replication environment. The
`system()` return value 32512 is `127 << 8`, the failing `submit` stub, and it proves the surrounding command
line did run to completion rather than aborting before the substitution. And the `> /dev/console`
redirection applied only to the stub, since the marker was still written where the substitution pointed.

### Dynamic Verification - the negative control

The benign control `system("submit id > /dev/console")` created no marker. That negates the most likely false
positive - a harness that writes the marker unconditionally - and it also demonstrates that the injection
depends on the `$()` construct rather than on the `submit` prefix, the redirection or the newline handling of
the harness. Both the injected and the control command produced the same `submit: command not found` line,
which is the expected shape: the difference between them is only whether a substitution ran first.

### Dynamic Verification - independence of the analysis

The record documents two independent re-analysis passes over the binary, one adversarial (attempting to refute
the chain) and one a from-scratch reconstruction, both concluding the same result. The adversarial pass
re-read the validator charset directly as `3b 26 7c 00` at `0x409c40`, confirmed that `$()` is not inspected,
confirmed the decode-then-check order, and confirmed that the authentication gate sits on the httpd side
rather than in `atp`. The reconstruction pass produced a fourteen-step data-flow description and independently
located the second sink at `0x405998`. The two passes agree, and no counter-hypothesis survived.

## 10. Reachability and Security Impact

### Reachability - network position

The injection point is the device's HTTP management interface. The record establishes the service on port 80
of the appliance's management plane and records the factory address 192.168.0.50; it does not establish that
an unmodified deployment exposes that plane to the wide-area side, and this advisory does not claim it. The
Network vector therefore describes the class of position the interface answers on - an IP service reachable
according to the deployment's own configuration (management VLAN, deliberate port forward, or an attacker
already positioned on the local segment) - rather than a measured wide-area exposure.

### Reachability - the request path is complete

Every hop between the query string and `system()` is present in the shipped artifacts: the `.xgi` extension
mapping in `httpd.php`, the `xgi` symlink to `atp`, the `xgi_main` entry that reads `REQUEST_URI` without
opening a file, the parser, the case-insensitive key match, the four value conditions, the validator and the
sink. Nothing in that list is conditional on a non-default configuration, and nothing requires a template file
that the device does not ship.

### Reachability - impact in concrete terms

Root command execution on an access point is control of the device: the `rgdb` configuration store, the
management account set generated from `/sys/user`, the wireless and bridge state, the firmware update path,
and the availability of the segment the device serves. On an embedded Linux system with a writable filesystem,
root also implies persistence in the ordinary sense - startup scripts, accounts, scheduled work - up to the
limits of that filesystem; survival of a factory reset or reflash was not tested and is not claimed. The
channel is silent by construction: one authenticated GET that looks like management traffic, a response that
carries no command output, and evidence that exists only if the operator chooses to leave a side effect.

The impact is not softened by the authentication requirement. The principal who can send the request is the
principal who is trusted to reconfigure the device; the defect converts that trust into a shell. A credential
holder who is malicious, or an attacker who has obtained the credential by any other means, obtains the same
root context that the device's own management software runs in.

## 11. Fix Recommendations

1. Remove `ExeShell` from the shipped binary, or make it inert. It is a general-purpose command runner
   reachable from an HTTP query string; no management page needs that capability, and deleting it closes the
   class rather than one instance of it.
2. If the builtin must stay, replace the `sprintf`/`system` construction with an `execve`-family call over a
   constant argument vector. No shell, no second parse, no metacharacter problem - the argument becomes data
   by construction.
3. If a shell cannot be removed immediately, single-quote the argument with correct single-quote escaping and
   reject `$`, `(`, `)`, backtick and newline before the command is built. Those are exactly the characters
   the validator at `0x405690` does not inspect, and rejecting them is a stopgap, not a design.
4. Replace the prefix-plus-blocklist scheme with a closed grammar. A value must be one of a fixed set of
   tokens for the interface to mean anything; accepting any string that begins with `submit` and contains no
   separator is the reason this defect exists.
5. Drop privileges on the `atp` process. The record attributes root context to it because httpd performs no
   setuid drop; an unprivileged identity would not prevent the injection but would bound what it reaches.
6. Audit the remaining shell sinks for the same pattern: `ConfigGetOnly` at `0x405998`, which builds
   `rgdb -s %s '%s'` with single quotes around the interpolated value, and the call sites at `fcn.004041dc`,
   `fcn.004076f0` and `fcn.0040799c`. A migration to argument vectors is the only fix that closes them
   together.
7. Add a regression test at the handler level. Send `submit$(true)` and assert that either the value is
   rejected or no shell-out occurs; repeat with `submit%0a`, with the backtick form, and with a value
   containing `=` inside the substitution. Run the same suite against both affected models, since they share
   the binary and both httpd templates.
8. Until a patch ships: keep the management plane off wide-area interfaces, restrict it to the administration
   segment, and treat the administrator credential as the boundary it now is - while noting that rotating the
   password addresses only the separate default-credential finding, not this injection.

## 12. CWE

### CWE - classification rationale

CWE-78, Improper Neutralization of Special Elements used in an OS Command, is the primary class and the only
one that describes the defect precisely: an attacker-influenced string reaches a shell-interpreted command
without neutralization of the shell's special elements. The specific gap is narrow - the neutralization that
exists covers `;`, `&` and `|` and omits the substitution operators - but the class is exactly CWE-78, and the
fix that closes it is the CWE-78 fix.

CWE-798, Use of Hard-coded Credentials, is adjacent and is disclosed separately. The `admin`/`admin` pair in
`etc/config/defaultvalue.gz` is a real weakness in the same product, and it matters to operators; it is not
part of this chain, it does not raise any metric of this vector, and a fix for it does not fix this. Keeping
the two findings apart is deliberate: merging them would misstate both the precondition of this injection
(a valid administrator session, which a patched default does not remove) and the reach of the default
credential (which is a login, not a shell).

No other weakness class is claimed. The defect is not a memory-safety issue, not a transport-layer defect and
not an authorization flaw: the authorization gate behaves as designed, and the failure is in how the
authorized input is handled after the gate. The research record classifies the finding as CWE-78 with
CWE-798 as the separate default-credential item, and that classification is adopted here without extension.

---

Written by the 0day Rubbish Research Team.
