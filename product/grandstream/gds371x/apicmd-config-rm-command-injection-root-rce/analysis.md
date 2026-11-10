# Grandstream GDS371x (Release_GDS371x_1.0.13.10) - apicmd Config-File Removal Command Injection

## 1. Overview

### Overview of the finding

Grandstream Networks builds the GDS371x series video door system, a SIP door station used at building
entrances and reception points. The firmware analyzed for this advisory is `Release_GDS371x_1.0.13.10`.
Its administrative web plane is served by `bin/web/webs`, a 722,060-byte stripped ELF binary for ARM
32-bit little-endian EABI5 hard-float, glibc-linked, with recorded md5 digest
`02ba4f122cd99b10c13266d167cf0792`. The binary is a GoAhead embedded web server build. GoAhead
registers form handlers by URL against a C callback through its `websFormDefine` API, and the string
`/goform/apicmd` lives in the image's read-only data at `0xad868`, registered that way.

`/goform/apicmd` is not a single-purpose handler. It is a generic integer dispatcher: a request carries
`cmd=N`, and `N` selects a branch inside one very large function that runs from `0x41bf0` to roughly
`0x923dc` - about 330 KB of code - and answers with one of roughly a hundred P-code status strings
(`P14002` through `P14206`). One of those branches, at `0x805f8`, performs config-file housekeeping. It
builds a filename out of a request-derived string, prefixes it with `/tmp/`, prefixes the result with
`rm -rf `, and hands the finished line to `system()`. The request-derived string is not quoted, and the
only transformation applied to it beforehand is a `tolower()` loop at `0x80500`-`0x80570`. There is no
`strchr`, `strspn`, `strcspn` or `isalnum` screening anywhere between the request and the shell. A
semicolon, an ampersand, a pipe, a dollar-parenthesis and a backtick all survive to the command line,
and `system()` executes its argument through `/bin/sh -c`, so the shell parses the injected text as a
second command.

The consequence is that an authenticated administrative request to `/goform/apicmd` converts the
product's config-file cleanup step into an arbitrary command channel. The request-side gate is real and
is not bypassed: `/goform/apicmd` sits behind GoAhead's user-management authentication, described in the
research record as HTTP Digest (`WWW-Authenticate: Digest realm=`) combined with a cookie session
(`session`, `uname=%s`, `level=%d`), enforced at handler entry by `wsSecurityHandler`. This is therefore
an authenticated finding, not a pre-authentication one. What the finding changes is what an authenticated
administrative request is able to do: not merely read or write settings through the product's own
management vocabulary, but execute shell commands in the web process's context.

### Overview of the verification boundary

Two kinds of evidence stand behind this advisory, and they are deliberately kept apart.

The static half is instruction-level: the sink chain at `0x805f8` and the absence of character screening
between `0x80500` and `0x80570` were confirmed by disassembling the shipped `bin/web/webs` image with
Capstone in ARM Thumb mode, and the handler's registration and entry gate were read from the same image.

The dynamic half is a sink-level replication on an isolated cloud-hosted sandbox, not a device run. The research
record re-created the exact argument string that the firmware builds after its `sprintf` chain and fed it
to `/bin/sh -c` in a disposable environment:

```
CMD="rm -rf /tmp/cfgnormal;id>/tmp/gds_m1;#"
/bin/sh -c "$CMD"
```

That run produced a marker file containing `uid=0(root) gid=0(root) groups=0(root)`, while the benign
control `rm -rf /tmp/cfgbenign` - the same construction without the injected separator - produced no
marker at all. The identity in the marker is the identity of the sandbox shell that ran the replicated
command line; it is not a measurement of the device's web-process user, because no GDS371x unit was
driven and no emulated appliance was booted during this work. The record characterises the sink itself as
root-level command execution, and this advisory repeats that characterisation inside exactly that
boundary: the shell-level behaviour is measured, the device-side landing identity is the record's
characterisation and is reported as such.

### Overview of the product, platform and web stack

Three properties of this stack shaped the audit and explain why the finding sits where it does:

- The dispatch model is integer-based and monolithic. Because `/goform/apicmd` multiplexes roughly a
  hundred branches through `cmd=N`, a request's effect depends entirely on which sub-handler the integer
  selects, and the interesting branches are buried inside 330 KB of contiguous code rather than in
  separately named functions. Grepping for dangerous calls in this binary does not bound the surface; the
  dispatcher does.
- The web plane is a GoAhead build with the framework's own conventions intact, including the `webs_t`
  request structure and the form-variable storage it carries. That structure is what makes the source
  identification in section 6 possible at all, and it is also what limits how far that identification can
  be pushed without a full backward walk.
- The binary is stripped. There are no symbol names to lean on for the handler, the dispatcher or the
  sink; every statement in sections 5 and 6 is anchored to a virtual address in the shipped image rather
  than to a function name.

### Overview of the disclosure position

The record for this finding names no CVE identifier, and none was requested or assigned, so this advisory
states plainly: no identifier assigned. Nothing in this document is derived from a third-party write-up,
and the sink, the filter gap and the authentication model are all read from the vendor's own shipped
binary.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Grandstream Networks |
| Product | GDS371x series video door system (SIP door station) |
| Version analyzed | `Release_GDS371x_1.0.13.10` |
| Platform | ARM 32-bit little-endian EABI5 hard-float, glibc, stripped |
| Web stack | GoAhead; `bin/web/webs`, 722,060 bytes, md5 `02ba4f122cd99b10c13266d167cf0792` |
| Vulnerable endpoint | `/goform/apicmd`, string at rodata `0xad868`, registered via `websFormDefine` |
| Dispatch | `cmd=N` integer dispatcher; handler body `0x41bf0` to about `0x923dc` (~330 KB); status strings `P14002`..`P14206` |
| Sink | `0x805f8`: `cfg%s.xml` -> `/tmp/%s` -> `rm -rf %s` -> `system()` |
| Source | `*(r7+0x6008)`, the GoAhead `webs_t` form-variable storage (convention-based inference, see section 6) |
| Screening | `tolower()` loop at `0x80500`-`0x80570` only; no `strchr`, `strspn`, `strcspn`, `isalnum` |
| Breakout characters that pass | semicolon, ampersand, pipe, dollar-parenthesis, backtick |
| Authentication | HTTP Digest plus cookie session on `/goform/apicmd` |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)` marker, sink-level replication |
| CWE | CWE-78 |
| Published score | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 (High) |

### Vulnerability Summary mechanics

Reconstructed from the record's disassembly listing, the sink branch reads as follows:

```c
/* sub-handler at 0x805f8 in bin/web/webs (ARM Thumb, stripped) */
Y = *(r7 + 0x6008);                  /* request-derived form-variable string */
for (i = 0; i < len; i++)
    Y[i] = tolower(Y[i]);            /* 0x80500-0x80570: the only transformation */

sprintf(buf1, "cfg%s.xml", Y);       /* buf1 = "cfg<Y>.xml"                    */
sprintf(buf2, "/tmp/%s", buf1);      /* buf2 = "/tmp/cfg<Y>.xml"               */
sprintf(buf3, "rm -rf %s", buf2);    /* buf3 = "rm -rf /tmp/cfg<Y>.xml"        */
system(buf3);                        /* /bin/sh -c; the record calls this root-level */
```

Four decisions in that sequence carry the whole finding:

1. The value is lowercased and nothing else. Lowercasing is a case-normalisation step appropriate for a
   filename; it is not a metacharacter filter, and it leaves every shell-significant byte untouched.
2. The value is concatenated into a filename with `%s` and no quoting, so any byte the shell treats
   specially keeps that meaning in the constructed path.
3. The path is then embedded into a command string with a second `%s` and again no quoting, so the shell
   metacharacter sits in command position rather than inside a filename argument.
4. The command string is executed with `system()`, which on this platform is `/bin/sh -c`. The library
   call, not the handler, guarantees that a shell parses the string.

The result is that a request whose form variable begins with a semicolon terminates the `rm -rf` word
immediately, runs the attacker's command, and uses the trailing `#` to comment out the `.xml` suffix the
handler appends. For the value `;id>/tmp/gds_marked;#` the record's chain yields
`rm -rf /tmp/cfg;id>/tmp/gds_marked;#.xml`, in which `id>/tmp/gds_marked` executes and `.xml` never
reaches the parser as a word.

### Vulnerability Summary preconditions

1. The requester holds a valid administrative session for the device's web plane. The record's
   authentication class for `/goform/apicmd` is HTTP Digest plus a cookie session, so the request must
   carry both.
2. The request reaches `/goform/apicmd` with a `cmd=N` value that selects the sub-handler at `0x805f8`,
   plus the form variable that sub-handler reads. The record does not fix a single value of `N`; it
   describes the payload shape as `cmd=<N>&<formvar>=<payload>` and states that `N` must be the branch
   appropriate to that sub-handler.
3. Nothing else. No race, no memory grooming, no reboot window, no client-side interaction, no
   particular firmware configuration beyond the web plane being enabled.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

`/goform/apicmd` is registered as a GoAhead form handler and protected by the framework's user-management
authentication. The record describes two components that both apply: HTTP Digest, advertised with a
`WWW-Authenticate: Digest realm=` challenge, and a cookie session whose values the record lists as
`session`, `uname=%s` and `level=%d`. The check happens at handler entry, in `wsSecurityHandler`, before
any `cmd=N` dispatch takes place. That placement matters: the injection point is downstream of the gate,
so there is no path to `0x805f8` that does not first satisfy it.

Two consequences follow. First, this is a post-authentication finding by construction. Second, the
privilege level associated with the session is the device's administrative tier: the record's session
model carries a `level` value, and no lower-privilege web account with access to `/goform/apicmd` is
described anywhere in the record.

### Authentication Boundary - what the chain does not do

- It does not bypass authentication. The Digest challenge and the session cookie are satisfied, not
  defeated, and no part of the exploit construction touches the credential exchange.
- It does not depend on default credentials. The recorded exploit script offers the vendor default
  `admin`/`admin` as its initial value because a factory-state lab unit is the normal test target, but the
  chain works identically with any valid administrative credential; a changed password narrows nothing.
  The record's own note that a working default would make the chain effectively unauthenticated is a
  statement about deployment hygiene, not about the vulnerability class, and this advisory does not
  publish the finding as a default-credential issue.
- It does not attack the session mechanism, the Digest implementation, the cookie format or the
  transport. The request is an ordinary, well-formed form POST.
- It does not require the attacker to be a different principal from the one the product intends to serve.
  The attacker is the administrator, or someone holding that credential.

### Authentication Boundary - why that boundary does not soften the impact

An administrator can already change settings, so the fair question is what a shell adds. The answer is the
difference between the product's management vocabulary and the operating system underneath it. The
administrative web plane exposes a finite, defined set of operations - network configuration, SIP account
settings, door-control parameters, firmware operations - and none of them is "run this command". The
injection crosses that line and returns with the web process's full authority: the filesystem the process
can read and write, the configuration store it can reach, and every binary the device ships. A deployment
that treats the door station's web password as "the ability to adjust settings" is relying on a boundary
this finding removes.

The authentication requirement does define the affected population precisely, and that is the useful way
to read it: every legitimate holder of the administrative credential, plus every party who has obtained
it by other means - for whom this finding is the step that turns web-console access into operating-system
command execution.

## 4. Attack Surface

### Attack Surface - the web stack and its dispatch model

`bin/web/webs` is a GoAhead build, and GoAhead's model is uniform: URLs are bound to C callbacks at
startup, and the callback receives the framework's per-request structure (`webs_t`, passed in the first
argument register, held in `r7` in the disassembled handler). `/goform/apicmd` is bound that way from the
string at `0xad868`. The callback is the framework's generic command endpoint for this product: it reads
an integer `cmd` parameter and routes to one of roughly a hundred branches, each of which answers with a
P-code status string in the `P14002`..`P14206` range. For an auditor the consequence is that the reachable
behaviour of `/goform/apicmd` cannot be read off a handler table - it has to be read out of one enormous
function.

### Attack Surface - why the surface audit narrowed here

The audit question for this endpoint is narrow and answerable: which branches inside the dispatcher build
a string from request data and hand it to something that parses strings? The sweep that produced this
finding walked the dispatcher body for exactly that pattern, and the branch at `0x805f8` is the one that
combines all the necessary elements in a single, short sequence - a request-derived value, a `sprintf`
chain that preserves it verbatim into a command line, and a `system()` call. The filter between the two
is a lowercasing loop, which is to say there is no filter.

### Attack Surface - components that narrowed out

- The authentication handler itself is not part of the chain: the Digest and cookie logic is upstream and
  is exercised as intended, not subverted.
- The other dispatcher branches answer with status strings and configuration reads and do not reach a
  shell; they are not claimed here.
- The device's SIP, door-control and provisioning planes are separate surfaces with their own parsing
  concerns; nothing in this advisory depends on them, and no claim is made about them.
- The finding is not a memory-safety issue. There is no overflow, no format string, and no
  use-after-free in this chain; it is string data flowing into a shell parser by design.

## 5. Sink Identification

### Sink Identification - the construction

The sink is the four-call sequence at `0x805f8`, reconstructed in section 2 and reproduced here in the
record's own shape:

```c
sprintf(buf1, "cfg%s.xml", Y);      /* Y = *(r7+0x6008) */
sprintf(buf2, "/tmp/%s", buf1);
sprintf(buf3, "rm -rf %s", buf2);
system(buf3);
```

Two properties make it a reliable sink rather than merely untidy code. The value is interpolated
unquoted, so the shell's word-splitting and metacharacter rules apply to it in full; and the final call is
`system()`, the library interface that guarantees a `/bin/sh -c` parse between the handler and the kernel.
The record characterises the `system()` call as root-level command execution, which is the basis for the
severity reading in section 10 and for the title of this advisory, with the replication boundary stated
alongside it in section 9.

### Sink Identification - the lowercasing loop is not a control

The research record is explicit that the value passes through a `tolower()` loop at `0x80500`-`0x80570`
and through nothing else before the `sprintf` chain: no `strchr`, `strspn`, `strcspn` or `isalnum` call
sits on that path. That enumeration is the load-bearing negative of this finding. A lowercasing loop
changes the case of bytes; it does not remove, escape or reject any byte, and the shell's metacharacters
are not case-sensitive. The loop is quoted here precisely so that no downstream sanitisation is credited
that does not exist.

```c
/* the entire filter, 0x80500-0x80570 */
for (i = 0; i < strlen(Y); i++)
    Y[i] = tolower(Y[i]);
```

### Sink Identification - execution identity

`system()` children inherit the identity of the process that calls them, and the record describes that
process as running with root-level authority. The measured evidence is the replication marker,
`uid=0(root) gid=0(root) groups=0(root)`, produced in the isolated cloud-hosted sandbox described in section 9. The
device-side user context was not measured directly during this work, so the table in section 2 records
the observed identity with the replication qualifier attached rather than presenting it as a device
observation.

## 6. Source Identification

### Source Identification - the value and its origin

The value consumed at `0x805f8` is `*(r7+0x6008)`, where `r7` holds the `webs_t` request structure the
GoAhead framework passes to every handler. Offset `0x6008` is, by the framework's convention, inside the
structure's form-variable storage area, which makes the value a form variable submitted with the POST,
retrieved in the normal way through the framework's variable lookup. The record states this identification
as a convention-based inference and states its own limit in the same breath: the full backward trace from
the `cmd=N` integer dispatch through the P-code branch to the form-variable read was not completed across
the 330 KB handler body, and no symbol names exist in the stripped image to shortcut it.

### Source Identification - the inference and its falsifier

The record is unusually careful here and this advisory preserves that care. The claim is: the tainted
value is a request form variable, on the strength of the GoAhead `webs_t` layout convention at offset
`0x6008`. The falsifier the record itself names is equally specific: if a completed backward walk were to
show that the value is instead an internal constant, or state set by configuration rather than by the HTTP
request, the finding would be revoked. That is the correct form for this kind of inference, and it is why
every statement in this advisory about the source is phrased as "the record's identified source" rather
than as a proven taint path. Nothing else in the chain depends on the inference: the sink, the missing
character screening and the authentication gate are all direct observations of the shipped image.

### Source Identification - what the payload must respect

Because the only transformation is lowercasing, the payload's freedom is essentially total. The injected
text may contain any shell-significant byte, and the recorded payloads use three at once: the semicolon to
terminate the `rm -rf` word, the redirection operator to write the marker, and the `#` to comment out the
`.xml` suffix the handler appends. Nothing needs to be quoted, doubled or encoded. The only structural
constraint is that the handler's own `sprintf` calls run first, which is why the payload is placed at the
front of the value: everything after the `#` is discarded by the shell before it can matter.

## 7. Data Flow

### Data Flow - end to end

```
[operator station]                        [GDS371x web plane: bin/web/webs]
administrative session: HTTP Digest + session cookie
        |
        |  POST /goform/apicmd
        |  body: cmd=<N>&<formvar>=;id>/tmp/gds_m1;#
        v
        GoAhead form dispatch
        wsSecurityHandler: Digest realm + session cookie gate        [pass]
        |
        cmd=<N> integer dispatch inside 0x41bf0..0x923dc
        |
        sub-handler at 0x805f8
        Y = *(r7+0x6008)                  form-variable storage of webs_t wp
        tolower loop 0x80500-0x80570      lowercasing only, no screening
        |
        sprintf(buf1, "cfg%s.xml", Y)     -> "cfg;id>/tmp/gds_m1;#.xml"
        sprintf(buf2, "/tmp/%s", buf1)    -> "/tmp/cfg;id>/tmp/gds_m1;#.xml"
        sprintf(buf3, "rm -rf %s", buf2)  -> "rm -rf /tmp/cfg;id>/tmp/gds_m1;#.xml"
        system(buf3)
                |
                /bin/sh -c: ";" ends the rm, "id>/tmp/gds_m1" runs,
                            "#" comments out the appended ".xml"
                v
        marker file /tmp/gds_m1
```

### Data Flow - properties worth naming

- The taint never crosses a memory-safety boundary. It is plain string data carried from the request
  structure into a buffer, from the buffer into a command line, and from the command line into a shell.
- The decisive re-parse is performed by the component the handler itself chooses, `/bin/sh -c`, not by
  anything the attacker supplies or controls. The product selects the shell interface.
- The handler's own suffixes are what make the trailing `#` useful. Because the code appends `.xml` after
  the value, a payload that does not comment out the remainder would leave a stray word on the command
  line; the comment character removes it and the command still runs.
- Nothing in the chain depends on HTTP-layer oddities, content-type quirks or parameter ordering. The
  request is an ordinary form POST with one integer field and one string field.

## 8. Exploit Construction

The PoC shipped with this advisory is `exploit/grandstream_gds371x_apicmd_poc.py`. It is a single-request
client built on the Python standard library: `argparse` for the target address, port, credentials, marker
path and dispatch integer; `urllib.request` with `HTTPDigestAuthHandler` for the Digest exchange; a cookie
jar attached to the same opener because the record describes the gate as Digest plus cookie session; and
one POST to `/goform/apicmd`.

### Exploit Construction - request shape

```http
POST /goform/apicmd HTTP/1.1
Host: <device>:<port>
Content-Type: application/x-www-form-urlencoded
Authorization: Digest username="admin", realm="<advertised realm>", nonce="<nonce>", uri="/goform/apicmd", response="<digest>"
Cookie: session=<session id>

cmd=<N>&<formvar>=;id>/tmp/gds_m1;#
```

The Digest header is produced by the client library from the `401` challenge, not written by hand; the
cookie is whatever the device's session established. Both are ordinary parts of the product's documented
control flow.

### Exploit Construction - payload engineering

The payload is the literal string

```
;id>/tmp/gds_m1;#
```

and its three components each have a job:

- the leading `;` terminates the `rm -rf /tmp/cfg<value>.xml` word that the handler is building, so what
  follows is a new command rather than a filename fragment;
- `id>/tmp/gds_m1` is the command body. It writes the identity of the executing process to a marker file
  and nothing else - no network egress, no state change beyond that one file;
- the trailing `#` begins a shell comment, so the `.xml` suffix and any quoting the handler would have
  appended are discarded before the parser reaches them.

The same shape generalises by substitution of the middle element; the recorded exploit script instead
prefixes four ordinary characters (`A` repeated) before the semicolon, which produces a well-formed initial
filename and reads as a slightly more ordinary request in any product-side logging. Both forms exercise
the identical sink. The record's own transcribed vector, `rm -rf /tmp/cfgnormal;id>/tmp/gds_m1;#`, is the
artifact that was actually replayed.

### Exploit Construction - what the PoC deliberately does not do

- It does not guess, brute-force or harvest credentials; the administrator password is an operator-supplied
  argument whose default is the vendor default recorded for the product, not a captured secret.
- It performs one request and reports the HTTP status; it does not read the marker back, because doing so
  would require a second channel the tool does not have.
- It writes exactly one marker file per run and contains no option to run an arbitrary command. The
  command body is fixed to an identity capture precisely so that a mistyped invocation cannot become a
  destructive one.
- It does not attempt to disable logging, alter configuration, install persistence or open an interactive
  channel.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Verification method | sink-level replication on an isolated cloud-hosted sandbox, plus instruction-level disassembly of the shipped image |
| Static evidence | `bin/web/webs` (722,060 bytes, md5 `02ba4f122cd99b10c13266d167cf0792`) disassembled with Capstone in ARM Thumb mode |
| Replicated element | the exact `system()` argument the firmware builds after the `sprintf` chain at `0x805f8` |
| Not performed | no HTTP request against device hardware; no physical GDS371x unit driven; no QEMU or other appliance emulation booted |
| Observation channel | marker file created by the injected command, read from the sandbox filesystem |
| Control | the same construction with the separator removed, run through the same harness |
| Identity measured | `uid=0(root) gid=0(root) groups=0(root)` - the sandbox shell's identity, not a device measurement |

### Dynamic Verification - vectors and results

The replication is recorded as a shell transcript that re-creates the constructed command line verbatim:

```
rm -f /tmp/gds_m1
CMD="rm -rf /tmp/cfgnormal;id>/tmp/gds_m1;#"
/bin/sh -c "$CMD" 2>/dev/null
# control: the same construction without the injection
/bin/sh -c "rm -rf /tmp/cfgbenign" 2>/dev/null
sleep 1; cat /tmp/gds_m1
```

The recorded outcomes are:

```
vector  : /tmp/gds_m1 contains uid=0(root) gid=0(root) groups=0(root)
control : /tmp/gds_m1 absent
```

The control is the load-bearing negative. The benign string has the same prefix, the same `rm -rf`
construction and the same `/tmp` target as the vector, and differs only in the absence of the injected
separator and command; it produced no marker. That isolates the marker creation to the injected text
rather than to the surrounding `rm -rf`, which is exactly what a sink-level replication can establish.

### Dynamic Verification - negatives, stated

- No end-to-end HTTP round trip was performed against a GDS371x. The request-side claims - the handler
  registration at `0xad868`, the `wsSecurityHandler` gate, the `cmd=N` dispatch, the form-variable read at
  offset `0x6008` - are disassembly-level and, for the source, convention-based inference.
- No device-side process identity was measured. The root identity appears in the replication marker; the
  record characterises the sink as root-level; the mapping between the two was not independently verified
  on hardware.
- No routing, NAT, SIP, provisioning or door-control behaviour was tested, and none is claimed.
- No other firmware version was analyzed. `Release_GDS371x_1.0.13.10` is the only image examined, and no
  inference is made about earlier or later builds.

## 10. Reachability and Security Impact

### Reachability - network position

`/goform/apicmd` belongs to the device's administrative web plane. That plane is reached over the network
the device is deployed on - typically a building's internal network, since the product is a door station
mounted at an entrance and administered from inside. Nothing in the analyzed image establishes that the
endpoint answers on an untrusted wide-area interface in an unmodified deployment, so the published vector
assumes network reach to the device's web plane, which is the ordinary case for an administrative
interface of this class. Deployments that expose the web plane through a port forward or a remote-access
feature widen the population that can attempt the request, but the credential requirement remains in both
cases.

The credential requirement defines the affected population precisely: every holder of the administrative
credential, on any station that can reach the web plane, plus anyone who has obtained that credential by
other means. For that second group the finding is a privilege escalation in the practical sense - from
"can log into the door station's web console" to "can run commands in the device's operating-system
context".

### Reachability - impact in concrete terms

Command execution in the web process's context, at the authority the record describes as root-level, means
in practice: the device's configuration store, including any credential material that store holds; the ability to change network settings, SIP registration and door-control behaviour
from outside the product's own management vocabulary; the ability to create files and, within the limits
of the writable filesystem, alter startup behaviour; and the ability to degrade or stop service at will,
including through the very `rm -rf` construction the injection rides on. The finding changes the meaning of
the door station's administrative password from "control of a settings interface" to "operating-system
access on a device that sits on the building network and can observe and affect the door it controls".

## 11. Fix Recommendations

1. Stop building the command line at all. The cleanup step needs to remove a file under `/tmp`; `unlink()`
   with the constructed path performs exactly that operation with no shell in the path. If a recursive
   removal is genuinely required, `nftw()` or an explicit directory walk does the job without
   `system()`.
2. Validate by allowlist, not by transformation. If the filename component must stay request-derived,
   constrain it to a documented set - for example `[A-Za-z0-9._-]{1,32}` - and reject everything else
   before the `sprintf` chain, rather than lowercasing and hoping.
3. If a shell must remain in the path for one release, quote the interpolated value with single quotes and
   escape embedded single quotes, and assert after construction that the resulting string contains no byte
   outside the expected filename alphabet. The assertion is cheap and fails closed.
4. Extend the same review to every branch of the `/goform/apicmd` dispatcher. The endpoint multiplexes
   roughly a hundred branches through `cmd=N`; the sweep that found this one walked the dispatcher for
   request-data-to-string-to-exec patterns, and the same walk should be a release gate rather than a
   one-off exercise, because the next branch of this shape will be equally invisible to a call-site grep.
5. Drop the web process's privilege. A dedicated unprivileged identity for `bin/web/webs` does not fix the
   injection, but it bounds what any web-plane defect can reach, and this finding is a direct demonstration
   of why that bound matters.
6. Reduce the sink's blast radius by construction: the `rm -rf` on a path built from request data is
   dangerous even when the value is well-formed. Deleting only a known-suffix file inside a fixed directory,
   with the value used solely as a filename component validated against the directory, removes the
   recursive delete from the attacker's reach.
7. For operators, until a fix ships: keep the door station's web plane on a management network that does
   not admit arbitrary stations, do not expose it through port forwarding or remote-access features, use a
   non-default administrative password, and treat any unexpected `/goform/apicmd` request carrying
   punctuation in a filename field as a command-execution indicator rather than a malformed request.

## 12. CWE

### CWE - classification rationale

- CWE-78 (Improper Neutralization of Special Elements used in an OS Command, commonly OS command
  injection) is the classification. The request-derived value reaches a command line built by string
  interpolation, and a shell parser turns part of that value into executed command text. Every element of
  the chain - the unquoted `%s` into `rm -rf`, the `system()` execution interface, the metacharacter
  breakout - is this class.
- A validation-gap reading (CWE-20) describes the same defect from the other end: the only processing
  between the request and the shell is a `tolower()` loop, and lowercasing is not validation. It is noted
  for completeness and does not displace CWE-78, because the harm is the command execution rather than the
  acceptance of malformed input.
- CWE-88 (Argument Injection) and CWE-426 (Untrusted Search Path) were considered and do not fit: the value
  is interpolated into the command string rather than appended as an argument word, and the handler does
  not resolve an executable through it.
- The authentication posture does not make CWE-284 (Improper Access Control) applicable: the endpoint's
  authorisation is what it claims to be - administrative - and the defect is not who may call it but what
  the call does with its parameter.

---

Written by the 0day Rubbish Research Team.
