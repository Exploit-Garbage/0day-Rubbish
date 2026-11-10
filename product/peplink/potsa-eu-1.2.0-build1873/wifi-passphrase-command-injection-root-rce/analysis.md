# Peplink PotSa EU fw-potsa_eu-1.2.0-build1873 - Unauthenticated WiFi Passphrase Command Injection in web_httpd Executing with Root Authority

## 1. Overview

### Overview of the finding

The Peplink PotSa EU is a point-of-sale terminal security appliance: a compact Linux appliance that sits on
a retail network and governs how point-of-sale terminals reach the store's payment infrastructure. Its
administrative plane is served by a Peplink-authored HTTP daemon, `/usr/sbin/web_httpd`, rather than by a
stock web server, and that daemon dispatches the device's configuration forms as named `.action` resources.
One of those resources is the basic WiFi setup form, `basic_wifi_setup.action`. It accepts the WPA/WPA2
mixed-mode passphrase as a form field, copies the field into a stack buffer, and calls an internal helper
whose job is to percent-decode three characters out of it.

The helper is the defect. It performs the decode by constructing a shell pipeline - `/bin/echo` into three
`/bin/sed` stages - with `snprintf`, and it executes that pipeline with `popen()`. The caller's string is
placed inside single quotes in the pipeline and is escaped nowhere: a single quote in the passphrase ends
the quoted word, and everything the attacker placed after it is parsed by `/bin/sh` as further commands.
`web_httpd` is started by the firmware without a setuid or setgid transition, so it runs with root
authority, and the injected command inherits that authority. The chain needs no authentication: the
`/mtadmin-goform/` URL prefix is classified as administrative by the daemon's own URL classifier, and the
request handler branches past the `logged_in=yes` cookie check for that prefix. A request with no cookie
and no `Authorization` header reaches the action handler, and the action handler forwards the passphrase to
the shell.

Three properties make this finding what it is, and each is documented at instruction level in the sections
that follow. The sink is a `popen()` call whose argument is built from user data with no quoting discipline.
The source is a single form field with no character validation, read by a generic form getter that performs
no filtering. And the authentication boundary is not weak but absent on this path: the daemon contains
digest-authentication code and a 401 response string, and neither participates in the dispatch of this
handler.

### Overview of the product, platform and web stack

The analyzed image is firmware fw-potsa_eu-1.2.0-build1873, distributed as the uImage package
APB2-EU_PKG-v1.2.0, a Linux system for 32-bit ARM. The management daemon is a 598548-byte stripped ELF,
ARM 32-bit EABI5 little-endian, hard-float, with build ID `ba6a2fe9` and SHA256
`cd3936518c670f86bd3c8d3ba42a735ed6e15799e2d9027bc813b65dfa940969`. Its strings identify it as the HTTP
responder for the appliance: the `Server: web_httpd` response header literal at `0x66748`, the URL prefixes
`/mtadmin-goform/` at `0x668e8` and `/mtadmin/` at `0x668fc`, the CGI and goform prefixes at `0x6b010` and
`0x6b018`, the digest challenge at `0x6a910`, the session cookie literal `logged_in=yes` at `0x7a96c`, the
login redirect to `/login.html` at `0x6ad98`, and the log line recorded at `0x6ada4`. Because the daemon is
vendor-authored rather than a packaged third-party server, its request handling, its URL classification and
its form parsing are all in scope for this analysis; there is no upstream patch to defer to.

Two structural observations shaped the audit. First, the daemon does not use a templating or CGI-exec
mechanism for its forms: the `.action` resources are entries in an in-binary dispatch table at `0x84d00`,
which pairs an action-name string pointer with a handler function pointer, so every action is reachable only
through the daemon's own routing and every handler is a function inside the same process. Second, the
daemon hosts a small family of shell-mediated helpers, of which the percent-decoder at `fcn.00021430` is
one; the decoder is not an isolated curiosity but a utility called from nine sites, all in the WiFi setup
form handlers. A defect in it is therefore a defect in the configuration surface as a whole, not in one
page.

### Overview of the image and its extraction

The firmware image does not unpack with standard tooling: its squashfs metadata is obfuscated, and
`unsquashfs` fails on the image as shipped. The root filesystem was recovered by working one layer lower -
carving the UBI volume layer out of the full image using the UBI magic `0x85190000` and the volume table,
extracting the volumes, and unpacking the squashfs that the carve yields. That produced a complete 81 MB
root filesystem, from which `/usr/sbin/web_httpd` was taken for disassembly. The extraction technique is
recorded here for reproducibility; it is not itself a vulnerability and is not part of the chain.

### Overview of what the verification covers

The evidence in this advisory has two halves and they are not interchangeable. The request path - the
dispatch table, the URL classifier, the cookie gate, the action handler, the form getter, the length gate
and the call into the decoder - is established by disassembly of the stripped binary, with the instruction
addresses quoted throughout. The execution behaviour at the sink is established dynamically, by a
sink-level replication on an isolated sandbox: the recorded exploit reproduces the exact command string
that `fcn.00021430` builds and executes it through `/bin/sh -c`, once with a benign passphrase and once with
an injective one. Full-device emulation was attempted and did not succeed, because the firmware's ARM
hard-float userland depends on private NVRAM and factory data that the image does not carry. There was no
live-device HTTP round trip: no request was sent to appliance hardware, and the unauthenticated
reachability of the action is a disassembly-level conclusion, stated as such. Root authority was observed
inside the replication environment, which mirrors the daemon's launch context, not on a physical unit.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Peplink |
| Product | PotSa EU (Point-of-Sale Terminal Security Appliance) |
| Version analyzed | firmware fw-potsa_eu-1.2.0-build1873 (uImage APB2-EU_PKG-v1.2.0) |
| Platform | Linux, 32-bit ARM, EABI5 little-endian, hard-float |
| Component | `/usr/sbin/web_httpd`, 598548 bytes, stripped, BuildID `ba6a2fe9` |
| Component digest | SHA256 `cd3936518c670f86bd3c8d3ba42a735ed6e15799e2d9027bc813b65dfa940969` |
| Vulnerable action | `basic_wifi_setup.action`, handler at `0x2484c` |
| Parameter | `text_wpawpa2_mixed_mode_passphrase` (literal at `0x6efd4`) |
| Gate on the parameter | branch on `select_network_auth` at `0x24b40`; `strncpy` limit `0x7f` at `0x24b98` |
| Sink function | `fcn.00021430` at `0x21430` (debug name `decodeURIComponentLite`) |
| Sink calls | `snprintf` at `0x214d4`, format literal at `0x6d828`; `popen(buf, "r")` at `0x21500` |
| Escaping applied | none: no single-quote escape, no metacharacter filter |
| Breakout | `x';<command>;echo 'x` - single-quote termination, no separator needed |
| Authentication gate | absent for this path: prefix classification skips the cookie check at `0x12d78` |
| Execution identity | root (daemon started with no setuid or setgid transition) |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)`, marker 39 bytes, owner root |
| Verification method | sink-level replication on an isolated sandbox, plus instruction-level disassembly |
| Primary CWE | CWE-78 |
| Adjacent CWE | CWE-798 (factory-default credentials, disclosed separately, not this vector) |
| Published score | 9.8 Critical - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

The decoder's whole implementation, as recovered from the disassembly of `fcn.00021430`, is a format string
and a process launch:

```c
// fcn.00021430 @0x21430    fcn.00021430(char *user_input, int len)
snprintf(buf, 0x400,
    "/bin/echo '%s' | /bin/sed 's/%s/</g' | /bin/sed 's/%s/>/g' | /bin/sed 's/%s/\&/g'",
    user_input, "%3C", "%3E", "%26");                 // snprintf @0x214d4
popen(buf, "r");                                       // popen   @0x21500
```

The first `%s` is the caller's string. It is inserted between two literal single quotes, and nothing in the
function transforms it before insertion: there is no escape routine, no character class filter and no
length-driven sanitization beyond the copy the caller already performed. The remaining three `%s`
substitutions are the fixed decoder arguments `%3C`, `%3E` and `%26`, which is why the pipeline looks more
complicated than the decode it performs. The decode is therefore implemented by handing a string built from
untrusted input to a shell, which is the definition of the CWE-78 pattern this advisory reports.

Three of the function's decisions carry the finding:

1. The untrusted value is placed inside single quotes, which is the correct instinct, but the quote
   character itself is never escaped or rejected. In a single-quoted shell word, the only character with
   special meaning is the single quote; escaping exactly that one character is the whole of the required
   work, and it is absent.
2. The construction is executed with `popen()`, which invokes `/bin/sh -c` on its argument. The value is
   therefore parsed twice: once as form data by the daemon, and once as shell syntax by the child shell. No
   filtering exists between those two parses.
3. The function exists only to translate three percent-encoded characters. It could be a loop over the
   string comparing three two-byte sequences. The choice to implement it as a shell pipeline is what
   converts a cosmetic decoding task into a root command injection primitive.

### Vulnerability Summary preconditions

1. The attacker can send an HTTP request to the appliance's management daemon. No credential, cookie or
   token is required; the request is an ordinary form POST.
2. The attacker supplies the WiFi setup form with a passphrase containing a single quote followed by the
   command to run. The value must fit the `strncpy` limit of `0x7f` bytes, which is ample for a marker
   write, and must be consistent with whatever the form's `select_network_auth` switch requires to reach
   the decoder call - value `0` (WPA/WPA2 mixed mode) is the path documented in this advisory.
3. Nothing else. No memory grooming, no timing window, no second request, no reboot and no user action on
   the device.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is supposed to be

`web_httpd` presents the conventional shape of an authenticated management plane. Its strings include a
digest challenge (`WWW-Authenticate: Digest` at `0x6a910`), a session cookie literal (`logged_in=yes` at
`0x7a96c`), a login page (`/login.html` at `0x6ad98`), a log line that reads as an access decision at
`0x6ada4`, and a 401 reason string (`Authorization required` at `0x6b7c0`). Disassembly also recovers named
authentication functions: `web_handle_auth` at `0x7e1b0`, `dig_do_authentication` at `0x818f8` and
`cgi_login_auth` at `0x80fa8`. On the strength of that inventory alone, the daemon looks protected.

### Authentication Boundary - what the request path actually does

The request handler at `fcn.00012b70` (`0x12b70`) does not use any of them for this URL class. Its control
flow, as recovered section by section, is this:

```
0x12b70  main request handler (fcn.00012b70)
0x12d0c  strstr(conn_buf+0x20a4, "127.0.0.1")      source IP, kernel-derived, not spoofable
         external client -> 0x13704 -> 0x13718 fcn.0000e560 (session lookup, 0 when absent)
                         -> 0x1373c logout flag set (bookkeeping) -> 0x12d54
0x12d5c  cmp r0, 0                                 URL classification result
0x12d60  bne 0x13560                               /mtadmin-goform/ skips the cookie check
0x12d78  logged_in=yes cookie check                reached only by non-admin URL classes
0x13560  cascade of page-name comparisons          .action URLs match none of them
0x136a4  strncmp(url+1, "cgi-bin", 7)              no match
0x136ac  bne 0x13d80
0x13d9c  strncasecmp(url, "mtadmin-goform/", 0xf)  match
0x13e0c  bl fcn.00010490                           dispatcher entry, no auth call
```

Three points in that flow decide the boundary. First, the `127.0.0.1` test at `0x12d0c` compares the
connection's source address, which the record establishes is derived by the kernel and therefore not
forgable by a remote client; external clients are routed to `0x13704`, where a session lookup runs, a
logout flag is set when no session exists, and control returns to `0x12d54`. That flag is session-expiry
bookkeeping - the flag-already-set branch at `0x13cc0` loads the constant `0x1afffe91` and jumps back to
`0x13718`, converging on the same point - and it does not reject the request. Second, the URL classifier
at `fcn.0000eba0` (`0xeba0`) tests the request path with `strncasecmp` against `/mtadmin-goform/` for
`0x10` bytes and returns 1 on a
match; the comparison at `0x12d5c` and the branch at `0x12d60` then take the request to `0x13560`, which is
past the `logged_in=yes` cookie check at `0x12d78`. The cookie check is not defeated; it is not reached.
Third, the cascade from `0x13560` compares the URL against HTML page names and matches none of them for an
`.action` resource, fails the `cgi-bin` test at `0x136a4`, takes the branch at `0x136ac` to `0x13d80`, and
there matches the `mtadmin-goform/` prefix at `0x13d9c` before calling the dispatcher at `fcn.00010490`
from `0x13e0c`. No authentication function is called anywhere between the socket and the dispatcher.

### Authentication Boundary - the dead code that makes the gap easy to miss

`web_handle_auth`, `dig_do_authentication` and `cgi_login_auth` have no cross-references in the image, and
neither does the 401 string at `0x6b7c0`. The function that does reference the digest challenge literal,
`fcn.000123fc`, is a generic HTTP response sender that takes a status code in its first argument - it is
used for 403 at `0x13d74`, 500 at `0x138f4` and 302 elsewhere - and it is not on the `/mtadmin-goform/`
path. The authentication code is therefore present, named and unreachable: a reader who greps the binary
for `auth` finds a convincing-looking gate that the request path never enters. This is why the advisory
describes the gate as structurally absent for this handler rather than as bypassable.

### Authentication Boundary - why the absent gate is not softened by the default credentials

The appliance also ships a factory-default `admin`/`admin` administrative pair (CWE-798). That weakness is
disclosed separately and is not this vector. It matters here only as a contrast: this chain consumes no
credential at all, so an operator who has changed every password on the device has not narrowed it, and a
patch that only forces a password change would leave it intact. The two findings share a product and
nothing else - one is a command injection on an unauthenticated path, the other a credential hygiene defect
on an authenticated one.

## 4. Attack Surface

### Attack Surface - the daemon and its dispatch model

`web_httpd` serves both the administrative HTML pages and the `.action` resources that those pages submit
to. The actions are resolved through the table at `0x84d00`, whose entries pair a name literal with a
handler address:

```
0x84d00  dispatch table, (action_name_ptr, handler_fn_ptr) pairs
0x84d30  "basic_wifi_setup.action"    @0x67134  ->  0x2484c
0x84d40  "advanced_wifi_setup.action" @0x6714c  ->  0x25430
```

Because resolution is a table lookup inside the daemon, the reachable action set is closed and enumerable,
and every handler executes in the daemon's own address space with the daemon's authority. There is no CGI
boundary, no privilege separation and no per-handler worker identity; a defect in any handler is a defect
in a root process.

### Attack Surface - why the WiFi setup handlers are the interesting class

The WiFi configuration surface is where the daemon accepts the one class of input that a shell must handle
literally: passphrases. A passphrase is attacker-chosen text by design - it is the field a user is invited
to fill with anything - and it is the field most likely to be forwarded into a command construction
unchanged, because its content is not obviously a command. The audit of the daemon's WiFi setup handlers
found the decoder `fcn.00021430` called from nine sites: `0x24bac`, `0x25e94`, `0x282ec`, `0x2a670`,
`0x2a798`, `0x2bb14`, `0x2c01c`, `0x61c34` and `0x61d88`. The first of these is the basic setup handler
documented here; `0x25e94` is the advanced setup handler behind `advanced_wifi_setup.action`; the rest are
distributed across the other WiFi form handlers, including the guest setup forms. Only the basic setup site
was carried through dynamic replication, so the advisory claims nine call sites at code level and one
verified instance.

### Attack Surface - components that narrowed out

Two candidate paths were examined and excluded from the chain, and the exclusions are part of the result.
The `127.0.0.1` source-address test at `0x12d0c` is a genuine control - it distinguishes local requests
from remote ones - but the record shows both branches converging on `0x12d54` with only a logout flag set
for the remote case, so it is not an access gate for this URL class. The digest-authentication family is
dead code as described in section 3, so it neither protects nor exposes the handler. What remains is the
dispatch table and the handlers behind it, which is where the sink sits.

## 5. Sink Identification

### Sink Identification - the format literal, verified byte by byte

The format string is not inferred from the decompiler's rendering. It was read directly from the image at
file offset `0x6d828` and confirmed to be null-terminated at that offset, including the closing single
quote that makes the surrounding pipeline syntactically valid:

```
file offset 0x6d828, null-terminated:
/bin/echo '%s' | /bin/sed 's/%s/</g' | /bin/sed 's/%s/>/g' | /bin/sed 's/%s/\&/g'
hex tail 262f6727  =  & / g '   followed by NUL
```

That byte-level check matters for the injection argument. The trailing `'` in `262f6727` is the quote that
closes the word opened before `%s`; because the format provides the closing quote itself, a value that
contains its own closing quote terminates the word early and leaves the remainder of the pipeline to be
reinterpreted. There is no ambiguity about where the quoted region ends: it ends at the attacker's first
single quote.

### Sink Identification - the launch call and its parser

The constructed string is passed to `popen(buf, "r")` at `0x21500`. `popen` in glibc and in the musl-style
libc used by embedded ARM builds both invoke `/bin/sh -c` with the argument, so the string is parsed once
more, in a fresh shell process, with full shell grammar: command separators, pipelines, redirections,
substitutions and comments are all live. The pipeline shape chosen by the developer guarantees that this
second parse is not a formality - the string contains a pipe and two redirections by construction, so the
shell is already doing structural work on a string that contains attacker text.

### Sink Identification - execution identity

`web_httpd` is launched by the firmware's init path with no setuid or setgid transition: there is no
privilege change between the process start and the `popen` call, and the child shell inherits the daemon's
uid and gid. The daemon therefore runs as root, and the injected command runs as root. The replication in
section 9 confirms the mechanism and the identity it produces under a harness that mirrors that launch
context; on-device identity was not directly observed, because no live request was sent to hardware.

## 6. Source Identification

### Source Identification - the parameter and its gates

The action handler at `0x2484c` reads the passphrase before it makes any decision about the request:

```c
// basic_wifi_setup.action handler @0x2484c
[sp+0x38] = get_form(ctx, "text_wpawpa2_mixed_mode_passphrase");   // @0x24970, literal @0x6efd4
switch (strtol(get_form(ctx, "select_network_auth"), 0, 10)) {      // @0x24b40, literal @0x6efc0
  case 0:                                                            // @0x24b78  WPA/WPA2 mixed mode
    memset(sb, 0, 0x80);                                             // @0x24b88
    strncpy(sb, [sp+0x38], 0x7f);                                    // @0x24b98  127-byte copy
    len = strlen(sb);                                                // @0x24ba0
    fcn.00021430(sb, len);                                           // @0x24bac  -> popen sink
}
```

The getter at `0x24970` is the daemon's generic form-extraction routine (`fcn.0000d228`), which locates the
named field in the parsed form body and returns its value. It performs no character validation, no
normalization and no length policy of its own; those are the caller's responsibility, and the caller
exercises none of them. The only transformations applied to the value between the request body and the sink
are the `memset` at `0x24b88` and the `strncpy` at `0x24b98`.

### Source Identification - what the length gate actually does

`strncpy(sb, value, 0x7f)` into a `0x80`-byte buffer truncates the passphrase at 127 bytes and
null-terminates it as a side effect of the zeroed buffer, so the effective payload limit is 127 bytes. That
limit is a constraint on payload design, not a defense: the recorded payload is 41 bytes, leaving room for a
longer command, and truncation happens at the tail of the value, so a payload that terminates itself - by
closing its last construct - is unaffected. The `strlen` at `0x24ba0` then measures the truncated string, and
that length is what the decoder receives.

### Source Identification - the branch that selects the vulnerable path

The `switch` on `select_network_auth` at `0x24b40` routes value `0` (WPA/WPA2 mixed mode) to the case at
`0x24b78`, which is the path to the decoder. That is the request shape the exploit uses, and it is also the
default selection for a mixed-mode configuration, which is why the payload carries `select_network_auth=0`
explicitly. Other values of the field lead to other cases in the same handler; those cases were not
analysed individually for this advisory, and the nine call sites enumerated in section 4 are the reason not
to assume the basic handler is the only one that reaches the decoder.

## 7. Data Flow

### Data Flow - end to end

The complete path from the network to the shell is short enough to enumerate in order:

1. A TCP connection arrives at the daemon and is parsed into a request by `web_httpd`; the request URL and
   the form body are held in the connection context.
2. `fcn.00012b70` classifies the URL: `fcn.0000eba0` matches `/mtadmin-goform/` and returns 1, the branch at
   `0x12d60` skips the cookie gate at `0x12d78`, and the cascade reaches `0x13e0c`.
3. `fcn.00010490` is called as the dispatcher, looks up `basic_wifi_setup.action` in the table at `0x84d00`,
   and calls the handler at `0x2484c`.
4. The handler extracts `text_wpawpa2_mixed_mode_passphrase` through the generic getter at `0x24970`; the
   value is untrusted and unfiltered.
5. The handler switches on `select_network_auth` at `0x24b40`; value `0` selects the case at `0x24b78`.
6. The value is copied with `memset`/`strncpy` into a `0x80`-byte buffer at `0x24b88` and `0x24b98`,
   truncated to 127 bytes.
7. `fcn.00021430` is called at `0x24bac` with the buffer and its length.
8. The decoder formats the pipeline string with `snprintf` at `0x214d4`, inserting the value inside single
   quotes.
9. The pipeline is launched with `popen` at `0x21500`; the child shell parses it.
10. The attacker's single quote closes the quoted word; the text after it is executed as a command, with
    the daemon's root authority, and the remainder of the passphrase closes the construct so that the
    pipeline still parses.

### Data Flow - properties worth naming

Nothing in that path evaluates the value's content. The daemon does not know that a passphrase is a string
with a restricted alphabet; it treats the field as opaque bytes and forwards it. The only length-aware step
is the copy, and it truncates rather than rejects. The only quoting step is the format literal, and it
quotes without escaping. The only execution step is `popen`, and it does not know that its argument
contains untrusted text. Every stage does exactly what it was written to do, and the composition is a root
command injection.

### Data Flow - what the flow does not contain

There is no memory-safety defect in this chain: the copy is bounded and the buffer is zeroed. There is no
format-string defect: the attacker's text is an argument, not a format. There is no authentication step to
bypass: the path does not contain one. This matters for remediation, because the fix is a quoting and API
change, not a memory-safety patch.

## 8. Exploit Construction

### Exploit Construction - request shape

The request is one form POST to the action resource, with no session material of any kind:

```
POST /mtadmin-goform/basic_wifi_setup.action HTTP/1.1
Content-Type: application/x-www-form-urlencoded

select_network_auth=0&text_wpawpa2_mixed_mode_passphrase=x';id > /tmp/peplink_potsa_marker;echo 'x
(no Cookie header, no Authorization header)
```

The two fields are the ones the handler reads: `select_network_auth` selects the code path, and
`text_wpawpa2_mixed_mode_passphrase` carries the payload. The payload is
`x';id > /tmp/peplink_potsa_marker;echo 'x`: a single quote to close the quoted word, a marker write to
prove execution, and a trailing `'x` that reopens a quoted region so the rest of the pipeline still parses
cleanly.

### Exploit Construction - payload engineering

The payload must satisfy three constraints, all of them consequences of the code in sections 5 and 6:

- It must contain a single quote, because that is the only character that breaks out of the quoted word. No
  separator and no substitution syntax is required; the semicolons in the payload are ordinary shell
  separators for the commands that follow the breakout.
- It must fit 127 bytes after truncation, which the recorded payload does at 41 bytes.
- It should close the construct it opened, so that the tail of the pipeline - the three `/bin/sed` stages -
  parses without a syntax error and the shell does not abort before running the injected command. The
  trailing `'x` provides the opening quote that the pipeline's own closing quote then terminates.

The alternates were considered and are not needed: a backtick or `$()` substitution would work where the
value is not quoted at all, and a newline would work where the shell is line-oriented, but neither is
required here, because the value is already inside a quoting context the attacker can terminate. The
absence of a metacharacter filter means no encoding tricks, no alternate separators and no whitespace
substitutes are involved.

### Exploit Construction - what the PoC deliberately does not do

The published PoC sends the injection and nothing else. The command it injects writes an identity marker
under `/tmp`; it does not delete, modify, disable or persist anything on the target, and it does not read
back any file. Its default target is the documentation address `192.0.2.10`, so an unconfigured run goes
nowhere, and it carries no credential of any kind because the vulnerability requires none. A `--self-verify`
mode reproduces the sink-level replication locally - building the exact command string and running it
through `/bin/sh -c` as the recorded exploit does - so that the injection primitive can be confirmed
without a device.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Method | sink-level replication on an isolated sandbox |
| Replicated element | the exact command string of `fcn.00021430`: format literal at `0x6d828`, `snprintf` substitution at `0x214d4`, `popen` execution at `0x21500` |
| Execution | the string is passed to `/bin/sh -c`, mirroring `popen`'s own parser |
| Privilege model | root, mirroring the daemon's launch context (no setuid or setgid transition) |
| Observation channel | a marker file written by the injected command and read from the sandbox filesystem |
| Control | a benign passphrase with no shell metacharacters, through the identical construction |
| Not performed | full-device emulation (blocked by the ARM hard-float userland's private NVRAM and factory dependencies); any HTTP request to appliance hardware |

### Dynamic Verification - the two generated commands

The replication produced both command strings, and they are the load-bearing artifacts of this section
because they show exactly where the attacker's text lands:

```
benign   : /bin/echo 'MySecurePass123' | /bin/sed 's/%3C/</g' | /bin/sed 's/%3E/>/g' | /bin/sed 's/%26/\&/g'
injected : /bin/echo 'x';id > /tmp/peplink_potsa_marker;echo 'x' | /bin/sed 's/%3C/</g' | /bin/sed 's/%3E/>/g' | /bin/sed 's/%26/\&/g'
```

In the benign string the passphrase sits inside one quoted word and the pipeline runs as written. In the
injected string the quoted word ends at the first `'`, `id > /tmp/peplink_potsa_marker` becomes a separate
command, and the trailing `'x` reopens a quoted region that the pipeline's own closing quote terminates,
so the `/bin/sed` stages still parse. `/bin/sh -c` therefore executes three commands: an `echo`, the
injected `id` redirection, and the `echo`/`sed` pipeline.

### Dynamic Verification - results

```
benign   : exit code 0, marker created? False (expected NO)
injected : exit code 0
marker   : /tmp/peplink_potsa_marker
content  : uid=0(root) gid=0(root) groups=0(root)
stat     : owner=root uid=0 gid=0 size=39
```

The control run is the load-bearing negative: an ordinary passphrase traversing the identical construction
created no marker, so the marker in the second run is attributable to the injected command and not to the
surrounding pipeline. The injected run exited 0, the marker exists, its 39 bytes are the `id` output plus a
newline, and its ownership is root - the identity the injection ran under inside the replication
environment. The same primitive was not exercised against appliance hardware.

### Dynamic Verification - negatives, stated

- No end-to-end HTTP verification was performed. The request path - URL classification, cookie-gate skip,
  dispatch, form extraction, length gate, decoder call - is disassembly-level evidence, not a live
  observation.
- No physical appliance was driven, no firmware was emulated to the point of serving HTTP, and no
  appliance-side marker was read from a device.
- The eight remaining call sites of `fcn.00021430` were not replicated individually; they are established
  at call-site level by the same argument as the first.
- No persistence, no cross-device movement and no impact on attached point-of-sale terminals was tested;
  none is claimed.
- Firmware versions other than fw-potsa_eu-1.2.0-build1873 were not analysed.

## 10. Reachability and Security Impact

### Reachability - what is established, and at what level

The action is reachable by any client that can send an HTTP request to the daemon's management plane, and
the analysis establishes that no authentication is required for that request at disassembly level: the URL
classifier returns the administrative classification for the prefix, the branch at `0x12d60` skips the
cookie check, and no authentication call exists on the path to `fcn.00010490`. What the research does not
establish is a live round trip on hardware, and the advisory does not imply one. Network position is
therefore a property of the deployment: an appliance whose management plane is reachable from an untrusted
segment is exposed to any client on that segment, while one confined to a dedicated management network
exposes the defect to that network. The Attack Vector metric in the published vector, Network, follows the
record's reading of the request as an ordinary HTTP POST on the management plane; a deployment that
confines that plane to an adjacent segment would lower the metric, and the advisory states the score for
the vector as published rather than for every deployment.

### Reachability - impact in concrete terms

Root command execution on this appliance is not a partial result. The device's purpose is to govern how
point-of-sale terminals reach the store's payment infrastructure, and root on the device means control of
that governance: which terminals are admitted, how their traffic is routed and filtered, and what the
device reports about them. The complete configuration store is readable at that authority, including the
material the device holds to perform its own function. Availability is controllable at will, from service
restarts to the deletion of specific files. Persistence consistent with root on an embedded Linux system -
startup scripts, accounts, scheduled tasks - is available up to the limits of the writable filesystem;
what survives a factory reset or a reflash was not tested and is not claimed. And the trigger is quiet: a
single form POST to a legitimate management action, with no authentication event to log and no protocol
anomaly to alert on.

### Reachability - why the nine call sites matter to the impact

Because the decoder is called from nine sites across the WiFi setup handlers, the exposure is not limited to
the one form this advisory drives. An operator who avoids the basic WiFi setup page has not avoided the
surface, and a vendor fix applied only to `basic_wifi_setup.action` would leave the advanced and guest setup
handlers on the same code path. The remediation section therefore addresses the helper, not the page.

## 11. Fix Recommendations

1. Delete the shell from the decoder. Reimplement `fcn.00021430` as an in-process replacement of `%3C`,
   `%3E` and `%26` - a single pass over the string with a bounded output buffer - and remove the
   `/bin/echo`/`/bin/sed` pipeline entirely. This eliminates the injection class at all nine call sites at
   once, which no amount of character filtering achieves as cleanly.
2. If the pipeline must remain as an interim measure, escape the one character that matters: replace every
   `'` in the value with the four-character close-reopen sequence, and reject any value that still contains
   shell metacharacters after that transformation. Quoting is only a defense when the quote character
   itself is handled.
3. Validate the passphrase against the alphabet a WPA/WPA2 passphrase can actually contain: printable
   ASCII, length 8 to 63, no control characters, and no shell metacharacters. Enforce the policy in the
   form getter's caller at `0x2484c` before the `strncpy` at `0x24b98`, and give the decoder its own
   precondition so that a future caller cannot reintroduce the primitive.
4. Enforce authentication per handler, not per URL prefix. Each `.action` entry should assert a valid
   session at entry, so that a change to `fcn.0000eba0`'s classification cannot silently expose a handler
   again. The dispatch path from `0x13e0c` into `fcn.00010490` currently performs no check, and that is the
   structural defect behind the missing gate.
5. Repair or remove the dead authentication code. `web_handle_auth` at `0x7e1b0`, `cgi_login_auth` at
   `0x80fa8`, `dig_do_authentication` at `0x818f8` and the 401 string at `0x6b7c0` are unreferenced in the
   image; unreferenced security code makes a binary look protected while nothing calls it, and it misled
   the surface audit until the call graph was walked.
6. Drop the daemon's privilege. Running `web_httpd` as an unprivileged identity does not fix the injection,
   but it converts a root compromise into a bounded one, and it caps the blast radius of every other
   web-plane defect on the device.
7. Audit the other shell-mediated helpers in the same binary for the same pattern - a format string that
   interpolates request data into a command line - and add a handler-level regression test that submits a
   passphrase containing a single quote and asserts that no shell is invoked or that the value is rejected.
8. Until a fixed firmware is available, operators should keep the management plane off untrusted segments,
   restrict administrative access to a management network or VPN, and treat the appliance as a component
   whose compromise is a compromise of the store network. None of these measures removes the defect.

## 12. CWE

### CWE - primary classification

CWE-78, Improper Neutralization of Special Elements used in an OS Command ("OS Command Injection"), is the
primary classification. The vulnerable function constructs a command string that contains a request
parameter, does not neutralize the single quote that delimits the parameter's quoting context, and executes
the string through `popen()`, which invokes a shell. The defect is not the shell use alone - the pipeline
could be built safely with a quoting discipline - but the combination of untrusted input, an unescaped
delimiter and a shell-mediated execution primitive.

### CWE - the adjacent credential finding

CWE-798, Use of Hard-coded Credentials, applies to the appliance's factory-default `admin`/`admin`
administrative pair. It is reported as an adjacent finding because it belongs to the same product and the
same administrative plane, and it is deliberately not folded into this chain: this vector consumes no
credential, so the two defects have different preconditions, different fixes and different severities. An
operator who changes the administrative password has addressed the CWE-798 finding and has not addressed
this one.

### CWE - why not a neighbouring class

The chain is not CWE-79, because the injected content is not reflected into a document. It is not CWE-88
or CWE-77 in a distinct sense, because the injection target is a shell command line built by the daemon
itself rather than an argument array. It is not a memory-safety class, because the copy into the 0x80-byte
buffer is bounded and the buffer is zeroed first. The single missing control is quote neutralization at a
shell boundary, which is exactly CWE-78.

### CWE - mapping table

| Weakness | Role in this advisory |
|---|---|
| CWE-78 | primary: unescaped parameter in a shell command executed by `popen()` |
| CWE-798 | adjacent, separate disclosure: factory-default `admin`/`admin` pair, not required by this chain |
| CWE-20 | contributing character: absence of any input validation on the passphrase field |

---
Written by the 0day Rubbish Research Team.
