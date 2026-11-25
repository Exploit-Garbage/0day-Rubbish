# Grandstream GDS371x Camera Firmware 1.0.13.10 - ldc.cgi query-parameter command injection into the test_ldc system() command line

Advisory: https://0day-rubbish.com/blog/ldc-cgi-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

The Grandstream GDS371x is an IP door and access camera whose firmware ships a web management interface
for installer and operator use. The image analyzed in this research is firmware 1.0.13.10. Within that
image, the web tree carries a CGI program at `/webSvr/web/cgi-bin/ldc.cgi`. The binary is small and
unambiguous about its purpose: 4,892 bytes, ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV),
dynamically linked and stripped, linked against uClibc and libclearsilver, the HDF template engine. It is
the endpoint behind the camera's LDC tuning controls, and its only job is to
translate a handful of geometry values from the HTTP request into an invocation of a helper binary at
`/usr/local/bin/test_ldc`.

The read path is the standard ClearSilver CGI idiom: `cgi_init()` establishes the CGI environment,
`hdf_get_value()` returns the value of a named HTTP query parameter, `snprintf()` formats a command string,
and `system()` runs it. The design fault sits at the last two steps. Six parameter values are interpolated
into a printf-style template as unquoted `%s` conversions, and the finished string is handed to a library
function that executes through `/bin/sh -c`. The template, exactly as recorded from the binary, is:

```c
/usr/local/bin/test_ldc -F %d -R %d -m %s -h %s -v -C %sx%s -z %s/%s -f /tmp/ldc/ldc >> /tmp/ldc/ldc_config &
```

The six `%s` positions correspond to `mode`, `pano_h_fov`, `X`, `Y`, `zoom_num` and `zoom_denum`, in that
order, and none of them is quoted. Because the shell parses the assembled string a second time, a value
such as `1;id>/tmp/c13_ldc_marker;#` terminates the intended `test_ldc` call at the first semicolon, runs
`id` redirected into a marker file, and comments out the remainder of the command line - including the
`>> /tmp/ldc/ldc_config` redirection and the trailing `&`. A value of the shape `1$(id>/tmp/marker)` needs
no separator at all: the shell performs command substitution inside the substituted word.

Nothing between the parameter read and the shell hand-off filters shell metacharacters. The research record
states this explicitly for the ClearSilver path: `hdf_get_value()` returns the raw URL-decoded string, and
no validation function was found between that read and the `snprintf()` call, despite the parameters being
labeled as numbers (`mode`, field of view, width, height, zoom numerator, zoom denominator).

The authentication boundary is real, and this advisory states it before any impact claim. The camera's web
server is a GoAhead build using Basic/Digest authentication, and it enforces authentication before CGI
dispatch; the research record describes the gate as fail-closed. A request reaches `ldc.cgi` only after the
web server has accepted a valid session on the camera's management interface. This is an authenticated
finding: the attacker is a party who already holds a legitimate web session. It is not a pre-auth defect,
and rotating the administrator credential does not remediate it, because the defect is in what the CGI does
with parameters it was always allowed to receive.

The rest of this advisory keeps one boundary visible at all times. No camera was driven during
verification. The dynamic evidence is a sink-level replication: the exact `snprintf()`-to-`system()`
pattern was reimplemented in C, compiled natively with gcc on an isolated cloud-hosted x86-64 Ubuntu host,
and executed there, with the injection markers and a benign control observed on that host. Root was
observed inside that replication environment, by a process the replica deliberately ran as root to mirror
a CGI that the research record classifies as root-run on the device. The device-side runtime identity is
the record's classification, not a hardware measurement. Section 9 separates the binary-level evidence from
the replication evidence line by line.

### Overview of the product, platform and web stack

Three properties of this stack shaped the audit and explain why the finding sits where it does.

- The management plane is a CGI application, not a monolithic handler. GoAhead dispatches each CGI program
  as its own process, so every one of them is a separate attack surface with its own input handling. The
  audit therefore had to enumerate CGI binaries rather than reason about a single request router.
- The CGI programs share a parsing library. ClearSilver's HDF API is what turns a query string into named
  values, and it performs URL decoding only. It is not a sanitizer, it is not documented as one, and using
  it as the only barrier between a request and a shell is the root cause here.
- The parameter names are misleading. `mode`, `pano_h_fov`, `X`, `Y`, `zoom_num` and `zoom_denum` all read
  as geometry or enumeration values, which is presumably why nobody quoted them; the code never checks that
  they are numeric, so the names describe intent rather than enforced type.

The helper the CGI drives, `/usr/local/bin/test_ldc`, takes fixed flags and writes its output to
`/tmp/ldc/ldc_config`. That path matters for exploit construction: because the CGI's own command line ends
with `>> /tmp/ldc/ldc_config &`, a naive injection would have its output appended to a log the operator can
read, and an injected `#` comment can remove that redirection so the attacker's own redirect takes effect
instead. Both recorded payloads exploit exactly this.

### Overview of public-record independence

The research record states that the public vulnerability record carries no entry for a command injection in
`ldc.cgi` on the GDS371x, and that the vendor's published CVE history concentrates on a different product
line - the GXP series of IP phones, where the recorded issues are primarily authentication bypass and
information disclosure. The GDS371x is an access-control product, not a voice product, and `ldc.cgi` is
specific to the camera and image-processing features of that line. The record concludes that this is an
independent finding rather than a variant of a published one, and no identifier has been assigned to it:
this advisory carries no CVE number and claims none.

That conclusion rests on a scope statement rather than on an exhaustive search of every public source, and
it is repeated here in those terms. What the evidence supports is narrower and sufficient: the endpoint,
the six-parameter set, the format string and the three `system()` callsites documented below are read from
the firmware image's own binary, and no public advisory describing this construction was identified in the
record's independence assessment.

### Overview of the evidence split

Two kinds of evidence appear in this document and they must not be mixed.

- Binary-level evidence: the file path, the size and format of the binary, its libraries, the parsing
  chain (`cgi_init()`, `hdf_get_value()`, `snprintf()`, `system()`), the command template with its six
  `%s` positions, and the three `system()` callsites, including the fact that one of them uses a fixed
  string. All of this comes from the firmware image as analyzed.
- Replication evidence: the behaviour of that exact construction when a payload is placed in one of the
  six positions. This comes from a native x86-64 C program built to reproduce the pattern, run on an
  isolated host, with markers and a control observed there.

The request path and the authentication gate are asserted at the first level; the execution behaviour at
the second. The device-side identity of the executing process is at neither level - it is the research
record's classification, and it is labeled as such wherever it appears.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Grandstream Networks |
| Product | GDS371x door/access camera |
| Version analyzed | firmware 1.0.13.10 |
| Component | `/webSvr/web/cgi-bin/ldc.cgi` |
| Binary | 4,892 bytes, ELF 32-bit LSB, ARM, EABI5 version 1 (SYSV), dynamically linked, stripped |
| Libraries | uClibc, libclearsilver (HDF template engine) |
| Endpoint | `GET /cgi-bin/ldc.cgi` on the camera's authenticated web interface |
| Parser chain | `cgi_init()` then `hdf_get_value()` per parameter |
| Builder | `snprintf()` with a fixed template and six unquoted `%s` conversions |
| Sink | `system()`, executed through `/bin/sh -c` |
| Helper driven | `/usr/local/bin/test_ldc`, output to `/tmp/ldc/ldc_config` |
| Injectable parameters | `mode`, `pano_h_fov`, `X`, `Y`, `zoom_num`, `zoom_denum` |
| Sanitization | none on the ClearSilver path; raw URL-decoded strings |
| Breakout | `;` statement separation, `$()` command substitution |
| Session gate | valid web session on the management interface, enforced before CGI dispatch |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)` markers inside the replication environment |
| Primary CWE | CWE-78 |
| Published score | 7.2 High - `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| Identifier | no CVE assigned |

### Vulnerability Summary mechanics

The defect is a missing second-parse model. The developer's mental model is that `snprintf()` produces one
argument string for one helper program, and that the parameter values are data inside that string. The
shell's model is that the string it receives is a program: words are split on whitespace, operators are
recognized, substitutions are expanded, and redirections are applied - before the helper ever starts. Any
byte that the shell treats as syntax rather than data therefore changes which program runs. The template
offers six places to supply such bytes.

Two properties make this worse than a theoretical concern in this particular binary. First, the values are
interpolated without any quoting, so a value need not even break out of a quoted context; the whitespace
after the preceding flag already separates the injected text into shell words. Second, the CGI runs the
helper with a trailing `&`, so the shell is already being used as a job-control mechanism and there is no
opportunity to intercept the string between construction and execution.

The record documents a second construction as well: one `system()` call builds a command of the form
`echo "%s"` with a parameter interpolated inside double quotes. Inside double quotes the shell still
performs command substitution, so `$()` executes there even though a semicolon would be inert. The record
does not transcribe the full string of that construction, and this advisory does not reconstruct it; it
records only the property the record states - double-quoted context, `$()` works, `;` does not break out.

### Vulnerability Summary preconditions

- A valid web session on the camera's management interface, obtained through the GoAhead server's
  Basic/Digest authentication. No other privilege is required: the record documents no authorization check
  inside the CGI; the gate it describes is the web server's.
- Network reachability to the management interface. The replication did not measure which interfaces the
  web server binds to, and this advisory makes no claim about exposure beyond what the record states: the
  interface is the camera's management web plane, reached over the network.
- No special configuration of the LDC feature is needed beyond reaching the CGI; the six parameters are
  part of its ordinary request shape.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The gate is the camera's web server. The research record identifies it as a GoAhead build performing
Basic/Digest authentication, with the check enforced at the server level before any CGI process is spawned.
That placement is the strongest form of this particular control: because the CGI is a child process created
after the decision, there is no path in which a request body or query string reaches `ldc.cgi` without the
server having accepted a credential first. The record further describes the gate as fail-closed, which is
the property that matters for scoring - a failure of the authentication state does not degrade into
anonymous access.

The recorded exploit matches that model: it sends `Authorization: Basic <base64 of user:password>` on the
request line for `/cgi-bin/ldc.cgi`, and it does nothing else to establish trust. There is no token, no
session cookie dance and no signature. Whatever the web server accepted as a credential is the whole of the
attacker's standing, which is exactly why this advisory prices the finding at PR:H.

### Authentication Boundary - what the chain does not do

- It does not bypass the gate. No request in the record reaches the CGI without a credential, and no
  technique for reaching it unauthenticated is described. This is not an authentication-bypass finding.
- It does not escalate from a low-privilege account. The record documents no secondary account tier with
  web access to this CGI. The principal is the one the web server admits, and the camera's management
  plane is administered as a single class.
- It does not depend on the shipped credential. The record notes that default credentials may exist on
  some deployments, classifies that as a separate weakness with its own CWE, and states that they are not
  this chain's vector. This advisory does not use them and does not need them.

### Authentication Boundary - why the boundary does not soften the impact

An authenticated gate limits who can attack; it does not limit what the attack does once the request is
accepted. The party that holds a management session is, in the product's own model, the party trusted to
configure the camera. That trust is bounded by the interfaces the product offers, and the LDC controls are
one of them. This defect converts that bounded trust into a shell in the identity of the CGI process, which
is a different and much larger authority than "may tune LDC parameters". The gap between the two is the
vulnerability, and it is present for every legitimate session holder, including one whose credential was
obtained by phishing, reuse or a support workflow - precisely the cases where a management interface is
expected to remain a management interface.

The practical consequence for prioritization is straightforward: the finding is not urgent because it is
pre-auth, it is urgent because the boundary it crosses is the operating-system boundary on an
access-control device, and because the crossing requires a single request with no timing or grooming
constraint.

## 4. Attack Surface

### Attack Surface - the web stack and its dispatch model

GoAhead maps URLs under its document root to files and CGI programs. The analyzed image places the web
tree under `/webSvr/web`, and the CGI directory under it as `cgi-bin`, so the on-disk path
`/webSvr/web/cgi-bin/ldc.cgi` is served as the URL path `/cgi-bin/ldc.cgi`. The distinction matters for
reproduction: the filesystem path is what the analyst extracts from the image, the URL path is what the
exploit sends. This advisory uses each in its own context and does not conflate them.

Each CGI program inherits the server's environment, its file descriptors and its runtime identity, and it
parses its own input. That is the structural reason the audit proceeded binary by binary: the request
router cannot normalize input it never sees.

### Attack Surface - why the surface audit narrowed here

The research record's independence assessment established three facts that bound the surface.

- The six-`%s` LDC template appears in `ldc.cgi` and not in the other CGI binaries on the device. That
  makes this endpoint the unique carrier of the construction, and it is why the finding is scoped to
  `ldc.cgi` rather than to the CGI directory as a whole.
- The `gs_cpe` TR-069 daemon was examined and its sinks use fixed command strings rather than interpolated
  request data, so it does not offer this path.
- `device_service` executes through an argument vector rather than a shell, which is architecturally immune
  to shell injection: no shell ever parses its arguments.

Those three results are what turned a broad "the web plane runs CGIs" observation into a single named
endpoint with six named parameters. They also set the expectation for remediation: the same enumeration should be
repeated on any other build before assuming the template is absent there.

### Attack Surface - components that narrowed out

Components that were considered and excluded are worth naming, because exclusion is evidence too. Fixed
`system()` callsites inside `ldc.cgi` itself are not injectable - notably
`system("/bin/mkdir -p /tmp/ldc")`, which is a constant and cannot carry request data. The
`echo "%s"` construction is injectable only through command substitution, as described above. And no
argument-parsing path in the examined components turns request text into an `execve()` argument in a way
that would matter here; argument-vector execution does not reinterpret metacharacters.

## 5. Sink Identification

### Sink Identification - the three constructions

`ldc.cgi` contains three `system()` callsites, and their differences are the whole analysis.

1. `system("/bin/mkdir -p /tmp/ldc")` - a fixed string constant. No request data, no injection. This callsite
   is safe and is named here precisely so that it is not mistaken for part of the finding.
2. A construction of the form `echo "%s"` with a parameter interpolated inside double quotes, executed via
   `system()`. Inside double quotes the shell performs command substitution, so `$( )` executes; a semicolon
   is inert because it is quoted. The record records this callsite as a working vector and does not
   transcribe its full command string.
3. The LDC command itself, built with `snprintf()` from the template below and executed via `system()`.
   Here the six values are interpolated unquoted, so both `;` and `$( )` work, and whitespace alone is
   enough to introduce new shell words.

```c
snprintf(cmd, sizeof(cmd),
    "/usr/local/bin/test_ldc -F %d -R %d -m %s -h %s -v -C %sx%s -z %s/%s -f /tmp/ldc/ldc >> /tmp/ldc/ldc_config &",
    1, 1, mode, "1", "1", "1", "1", "1");
system(cmd);
```

### Sink Identification - why `system()` is the defect and not a detail

`system()` is specified to pass its argument to `/bin/sh -c`. That is not an implementation quirk; it is the
function's contract, and it means the argument is a shell program, not an argv array. Every consequence
follows from that: word splitting, operator recognition, expansion of `$`, `` ` ``, `$( )` and `${ }`,
redirection, pipelines, and comments introduced by `#`. A construction that assembles a string and hands it
to `system()` has therefore opted into shell parsing for every byte it interpolated, whether or not the
author intended it.

The alternative - `execve()` with an argument vector - appears in the same firmware family, per the
record's note on `device_service`, which is what makes this a fixable design error rather than a platform
limitation.

### Sink Identification - execution identity

The identity of the process that calls `system()` becomes the identity of the injected command, because
`/bin/sh` forks and executes as its caller. The research record classifies `ldc.cgi` as running with root
authority on the device and labels the finding as authenticated root code execution. The replication
mirrored that by running the replica as root, so the markers it produced read
`uid=0(root) gid=0(root) groups=0(root)`. That marker measures the replica's identity, not the camera's;
the camera-side identity is the record's classification, and section 9 states the difference.

## 6. Source Identification

### Source Identification - the parameters and how they are read

Every parameter arrives on the query string of a `GET` request, is URL-decoded by the web server or the CGI
library, and is then returned by `hdf_get_value()` under its `QueryString.` name. The record describes the
read as raw: what the client sent, after percent-decoding, is what the CGI holds. That is the correct
behaviour for a data API and the wrong behaviour for anything that will be concatenated into a shell
program.

The recorded exploit sends `STRENGTH=1` alongside the six values. `STRENGTH` is not one of the six `%s`
positions, and the record does not document what the CGI does with it, so this advisory does not assign it a
role; it is reproduced in the request for fidelity to the working script and nothing is claimed about it.

### Source Identification - parameter map

| Position in template | Parameter | Intended meaning per the record |
|---|---|---|
| `-m %s` | `mode` | LDC mode |
| `-h %s` | `pano_h_fov` | panoramic horizontal field of view |
| `-C %sx%s` (first) | `X` | image width |
| `-C %sx%s` (second) | `Y` | image height |
| `-z %s/%s` (first) | `zoom_num` | zoom numerator |
| `-z %s/%s` (second) | `zoom_denum` | zoom denominator |

All six are injectable in the third callsite. The record's working payloads use `mode`, which is the first
`%s` and therefore the earliest point at which the command line can be terminated.

### Source Identification - what is missing between source and sink

- No quoting. The `%s` conversions are bare, so the values are not wrapped in single or double quotes.
- No escaping. No function rewrites shell metacharacters before the `snprintf()` call.
- No type validation. Despite the numeric-sounding names, the record found no check that any value is an
  integer, and no range check on field of view, dimensions or zoom terms.
- No allowlist. Nothing restricts `mode` to a known set of modes.
- No length gate that would matter. Even a short value such as `1;id;#` is enough; the defect does not
  require a long payload.

## 7. Data Flow

### Data Flow - end to end

```text
HTTP GET /cgi-bin/ldc.cgi?STRENGTH=1&X=1&Y=1&mode=1;id>/tmp/c13_ldc_marker;#&pano_h_fov=1&zoom_num=1&zoom_denum=1
  -> GoAhead web server: authenticate the session, then dispatch the CGI
    -> ldc.cgi main()
      -> cgi_init()                      build the CGI environment
        -> hdf_get_value("QueryString.mode")   raw, URL-decoded value
          -> snprintf(cmd, sizeof(cmd), template, ...)   six unquoted %s
            -> system(cmd)               /bin/sh -c re-parses the whole string
              -> test_ldc ... ; id>/tmp/c13_ldc_marker ; # ...
```

The last line is the point of the finding: the shell sees a different program than the CGI author wrote.
The intended `test_ldc` invocation ends at the first `;`, `id` runs with the shell's identity and its output
goes to the marker path, and the `#` discards the remainder of the line, including the redirection to
`/tmp/ldc/ldc_config` and the trailing `&`. Because the record's payload ends in `;#`, the shell does not
background anything and returns after the injected command.

### Data Flow - the request as recorded

```http
GET /cgi-bin/ldc.cgi?STRENGTH=1&X=1&Y=1&mode=1%3Bid%3E%2Ftmp%2Fc13_ldc_marker%3B%23&pano_h_fov=1&zoom_num=1&zoom_denum=1 HTTP/1.1
Host: <target>
Authorization: Basic <base64 of user:password>
Connection: close
```

The recorded exploit builds this request with a socket, percent-encodes the parameters with the standard
library's URL encoder, and reads the response until the server closes the connection. It does not depend on
a response body: execution happens on the device side of the request, and the record's own note is that the
output may be found in `/tmp/ldc/ldc_config` on the device. That note is an inference about where the helper
writes, not a measured read-back, and this advisory treats it as such.

### Data Flow - properties worth naming

- The payload needs no response channel. Injecting a redirect into a marker file is sufficient for
  verification, which is why the recorded tests used marker files rather than exfiltrated output.
- The `&` at the end of the template means the CGI does not wait for the helper. An injection placed before
  it is unaffected, because the shell reaches the injected command before the background operator.
- URL encoding is the only transformation between the client and the CGI. The record's payload survives it
  because `;`, `>`, `/` and `#` all have standard percent-encodings, and the CGI decodes them back to the
  bytes the shell needs.

## 8. Exploit Construction

### Exploit Construction - payload shapes

Two shapes are recorded, and both are reproduced from the record rather than derived.

```text
semicolon form:      mode=1;id>/tmp/c13_ldc_marker;#
substitution form:   mode=1$(id>/tmp/c13_ldc_dollar_marker)
```

The semicolon form is the more general one: any command can be placed between the separators, and the
trailing `#` removes the rest of the template so that no leftover arguments disturb it. The substitution
form needs no separator and survives a double-quoted context as well, which is why the record keeps it as
the alternative and why it works against the `echo "%s"` callsite too.

### Exploit Construction - the replica that was actually run

The recorded verification program is a small C file that reproduces the template and calls `system()` on
it, with the parameter values held in local arrays so that the exact bytes are visible in the source.

```c
char mode[] = "1;id>/tmp/c13_ldc_marker;#";
snprintf(cmd, sizeof(cmd),
    "/usr/local/bin/test_ldc -F %d -R %d -m %s -h %s -v -C %sx%s -z %s/%s -f /tmp/ldc/ldc >> /tmp/ldc/ldc_config &",
    1, 1, mode, "1", "1", "1", "1", "1");
system(cmd);
```

The other five values are the safe value `1`, so the only difference between the vulnerable run and the
control run is the content of `mode`. That single-variable design is what makes the control meaningful.

### Exploit Construction - what the PoC does and does not do

The proof of concept in this package is adapted from the recorded script and keeps its shape: one
authenticated `GET` to `/cgi-bin/ldc.cgi`, the payload in `mode`, every other parameter set to `1`, and a
Basic authorization header built from operator-supplied credentials. It differs from the record in two
deliberate ways. It takes its target and port from `argparse`, so the same script can be pointed at a lab
device or at a documentation address without editing, and it fixes the command it injects to a single
marker write rather than accepting an arbitrary command line. The marker path is a constant in the script;
there is no option to change it and no option to run anything other than the identity marker.

That restriction is intentional and belongs in the advisory rather than only in the code: a proof of
concept that executes arbitrary operator-supplied commands is a weapon, and the claim being demonstrated -
that the parameter reaches a shell - is fully established by writing one file. The script performs no
destructive action, does not read credentials from the environment, and does not store them anywhere.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

The record's execution environment is an isolated cloud-hosted host: x86-64, gcc, Ubuntu. The method is
sink-level replication, which the record names as such. A C program was written to reproduce the exact
`snprintf()`-to-`system()` pattern with the same template string, compiled natively and executed. The
compiler invocation and the run are as recorded:

```bash
gcc -o /tmp/ldc_c13 /tmp/ldc_c13.c
/tmp/ldc_c13
```

This is the boundary, and it should be read literally: the program that executed the payload is the
replica, not the camera's CGI. Nothing in this section is a request against a GDS371x. What the
replication establishes is that the construction is injectable at the shell - that a payload placed in one
of the six positions executes - and that is the half of the chain that hardware would otherwise be needed
to confirm. The request path, the parameter names, the template and the authentication gate come
from the firmware image, and the replication assumes them rather than proving them.

### Dynamic Verification - vector 1, semicolon

The record's captured output for the semicolon payload is reproduced verbatim:

```text
[C13] system() arg: "/usr/local/bin/test_ldc -F 1 -R 1 -m 1;id>/tmp/c13_ldc_marker;# -h 1 -v -C 1x1 -z 1/1 -f /tmp/ldc/ldc >> /tmp/ldc/ldc_config &"
[C13] system() returned 0 (sh -c: test_ldc fails, but ;id executes)
[C13] VULN: marker file EXISTS - command injection CONFIRMED
[C13] uid = uid=0(root) gid=0(root) groups=0(root)
```

Read the first line carefully: the assembled string is exactly what the template produces with `mode` set
to the payload, and the other five positions hold `1`. That is the artifact the camera's CGI would build
from the same request. The marker existence check and the identity read are the two observations that
matter; the shell's exit status does not, because `test_ldc` failing is expected and irrelevant - the
injected `id` has already run.

### Dynamic Verification - vector 2, command substitution

The substitution payload produced the same result through a different shell mechanism:

```text
[C13] $() marker EXISTS - command substitution CONFIRMED
uid=0(root) gid=0(root) groups=0(root)
```

The record's verdict for this vector is that `$()` was expanded by `sh -c` and the command executed with
root identity. The distinction from vector 1 is worth keeping: `$()` works inside double quotes, so it also
reaches the `echo "%s"` callsite, whereas `;` does not.

### Dynamic Verification - the control

The control run used `mode = "1"` with all other parameters at `1`, i.e. the benign request shape:

```text
[C13] CONTROL: no marker file found (expected)
```

The record's verdict is that safe input produces no marker, which is what makes the two positive results
attributable to the payload rather than to the harness. A control that also produced a marker would
invalidate the whole test; this one did not.

### Dynamic Verification - results table and negatives

| Vector | Result | Identity observed | Recorded note |
|---|---|---|---|
| `;` semicolon | marker created | `uid=0(root) gid=0(root) groups=0(root)` | `sh -c` re-parses `;` as a separator |
| `$()` substitution | marker created | `uid=0(root) gid=0(root) groups=0(root)` | `sh -c` expands the subshell |
| control, all values `1` | no marker | not applicable | safe input produces no injection |

Negatives stated explicitly: no camera was driven; no firmware was reflashed; no live HTTP request was sent
to device hardware; the device-side process identity was not measured; and no test attempted to read
`/tmp/ldc/ldc_config` back from a device. The `uid=0` value is the identity of the replica's own process,
which the operator ran as root by design to mirror a root-run CGI. Anyone quoting this finding should say
that root was observed inside the replication environment, not that a camera was rooted on a bench, because
only the first is what the record contains.

## 10. Reachability and Security Impact

### Reachability

The reachable surface is the camera's management web interface, and the CGI is dispatched from it after the
web server accepts a session. The record establishes the request shape, the endpoint path and the parameter
names; it does not measure which network interfaces the web server binds to on a shipped device, and this
advisory therefore does not claim a wide-area exposure. What can be said is bounded and sufficient for
prioritization: any party who can reach the management interface and authenticate to it can reach the sink,
and the request is an ordinary `GET` that looks like LDC tuning to anything inspecting the URL.

### Impact in concrete terms

- Command execution in the identity of the CGI process, which the record classifies as root on the device.
  That is the device's own authority, not a sandboxed web account.
- Disclosure of the device's configuration and any material it holds in readable storage at that identity,
  which for an access-control product includes the credentials and service settings the device needs for
  its own operation.
- Integrity loss across configuration and services, with changes that look like ordinary administrative
  tuning and require no crash or reboot to take effect.
- Availability at will: process and service control from the shell, plus write access to the LDC working
  files under `/tmp/ldc` that the same command line writes to.
- Persistence consistent with root command execution on an embedded Linux system, within the limits of the
  writable filesystem; survival of a factory reset or a firmware reflash was not tested.

### What is not claimed

No memory-corruption primitive, no authentication bypass, no pre-auth path, no lateral movement to other
hosts, no control of the physical door or relay hardware, and no claim about firmware versions other than
1.0.13.10. Those are the places where an advisory of this kind usually overreaches, and the record does not
support any of them.

## 11. Fix Recommendations

1. Replace the six bare `%s` conversions with a validated representation: parse `mode` as an enumeration
   and the other five as bounded integers, reject anything that does not parse, and only then format them
   with `%d` into the template. This removes the metacharacter class at the source.
2. Remove the shell from the path. Call `/usr/local/bin/test_ldc` with `execve()`-family semantics and an
   argument vector built from the parsed values. The `device_service` component in the same firmware
   already demonstrates that this style is available on the platform.
3. If a shell must remain short-term, single-quote every interpolated value with correct embedded-quote
   escaping, and assert after construction that the command contains no `$`, `;`, backtick, newline or
   `#`. This is a containment measure, not a fix, because it depends on the assertion being complete.
4. Drop privileges for the CGI. Run the web server's CGI children under a dedicated unprivileged account
   with access only to `/tmp/ldc`. This caps the damage from this defect and from any future one on the
   same plane without changing the injection itself.
5. Harden the parse boundary generally: treat every `hdf_get_value()` result that reaches `snprintf()` as
   untrusted, and audit the remaining CGI binaries for the same template pattern. The record's assessment found
   the six-specifier template only in `ldc.cgi`; that result should be re-established for each build
   shipped, not assumed.
6. Add regression coverage: a test that submits `;id`, `$(id)` and a backtick form in each of the six
   parameters and asserts rejection or non-execution, run as part of the firmware build for every model
   that ships the binary.
7. Until a fix ships, restrict the management interface to trusted segments, avoid exposing it to untrusted
   networks, and disable the LDC tuning surface where the deployment does not use it.

## 12. CWE

### CWE - classification rationale

The published classification is CWE-78, Improper Neutralization of Special Elements used in an OS Command
("OS Command Injection"). The mapping is direct rather than analogical: request-controlled strings are
concatenated into a command line that is executed by a shell, with no neutralization between the two, and
the record's own heading classifies the issue as OS command injection via HTTP query parameters. The child
weakness that best describes the specific mechanism inside CWE-78 is the absence of any quoting or escaping
of the interpolated values before the `snprintf()` call, which is what allows both the separator and the
substitution forms to work.

The record names no secondary CWE for this issue, and this advisory does not invent one. Two related classes
are deliberately kept out of the classification. CWE-20, improper input validation, is a fair description of
the missing checks, but the record does not name it and the primary mapping already carries the mechanism;
adding it would be an editorial choice presented as a finding. CWE-798, use of hard-coded credentials, is
mentioned once in the record only to separate shipped default credentials from this chain; those credentials
are not this vulnerability's vector, are not relied on here, and are not claimed as part of this advisory.

The fix implication of CWE-78 is the one stated in section 11: neutralization at the shell boundary is the
wrong layer, and the correct remediation is to stop constructing a shell program from request data at all.
