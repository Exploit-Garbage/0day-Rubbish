# NETGEAR ProSafe Managed Switch 12.0.19.23 - REST agent download fwUrl OS command injection

Advisory: https://0day-rubbish.com/blog/restagent-fwurl-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

The ProSafe M4300 is a managed switch line whose management plane in firmware 12.0.19.23 is split
between a small sidecar process tree called appmgr and a lighttpd web server that loads `mod_cgi`.
The same lighttpd instance answers the browser interface and the switch's REST v1 API: TLS on port
8443 and cleartext on port 8080, with the REST agent executables mapped into the URL space through an
`agent_cgi.conf` alias file and stored under `/usr/local/appmgr/usr/lib/cgi-bin/restagent/`. The
lighttpd configuration carries no `mod_auth` directive, so authorization is the CGI's own problem, and
each REST agent implements it by validating a Bearer token against a session file.

The download agent is `device.cgi`: an ARMv7, stripped binary with md5
`35de649755e2341ea1f41f8b1fa4948c`, taken from the firmware image `M4300_V12.0.19.23.zip` whose
`fit.itb` has md5 `b5d3f4536ec9c98e1147209cd74f5b34`. It serves `POST /api/v1/download`, an endpoint
whose JSON body names a firmware or configuration file to fetch, and it does that fetching with
`curl`. Between the JSON parser and `curl` there is a shell, and between the shell and the JSON value
there is nothing at all.

The core of the finding is therefore small enough to state in one sentence: the `fwUrl` member of the
`device_download` object is interpolated unquoted into two command lines that `/bin/sh -c` parses, so
a semicolon inside the URL ends the `curl` command and starts an attacker-chosen one, executed in the
handler's forked download child under the identity the appmgr CGI stack runs as - root on this
firmware.

Two evidence classes support that sentence, and the boundary between them matters for how the
advisory should be read. The static class is disassembly of the vendor binary with r2ghidra: the
handler function, its two format strings in `.rodata`, its `popen()` and `system()` call sites, the
route dispatch that precedes it and the authentication function that gates it. The dynamic class is a
replication: the real `device.cgi`, not a rewritten model of it, executed inside an ARM chroot under
QEMU with the device's own initramfs, appmgr tree and shared libraries, and with the RPC client
symbols neutralised at the PLT so that the handler can get past its connectivity wait and reach its
shell calls. In that environment the injected command ran and left a marker file, and the REST call
returned success.

Nothing in this advisory rests on a physical switch. The record states plainly that no hardware shell
was available for an end-to-end device run, that the device-side path was established by analysis of
the same binary and the same lighttpd CGI conventions, and that the live-device mode of the recorded
client is logically equivalent but was not executed. Section 9 keeps that boundary explicit, including
what the replication did and did not prove about the executing account.

## 2. Vulnerability Summary

- Class: OS command injection (CWE-78) through unquoted interpolation of a request-controlled URL into
  shell command lines executed by `popen()` and `system()`
- Product and version: NETGEAR ProSafe M4300 managed switch, firmware 12.0.19.23
- Component: `/usr/local/appmgr/usr/lib/cgi-bin/restagent/device.cgi`, the REST agent download handler
- Endpoint: `POST /api/v1/download` on the appmgr lighttpd stack, TCP 8443 (TLS) or 8080
- Source: the `fwUrl` member of the `device_download` JSON object, read from stdin according to
  `CONTENT_LENGTH`
- Sinks: `popen("curl -k -sI <fwUrl> | grep -i content-length | awk '{print $2}'")` and
  `system("curl -k -m <timeout> -o /mnt/download/<name> <fwUrl> > /dev/null 2>&1")`
- Authentication: a valid management session obtained from `POST /api/v1/login` and presented as
  `Authorization: Bearer <token>`; the record classes the finding as authenticated
- Executing identity: root, the identity of the appmgr CGI stack and of the `/mnt/download` and
  `/tmp/restsession` directories it owns
- Impact: arbitrary command execution as root on the switch from a single authenticated request
- Identifier: none assigned; the source record names no CVE and none is claimed here
- Fix status: the command construction is present in the analysed build; no vendor fix is documented
  in the record, and no patched build was tested

The mechanics are worth separating from the impact because they explain why no exotic primitive is
involved. There is no memory corruption, no deserialization, no authentication bypass, no race and no
second request. A correctly authenticated administrator asks the switch to download a file from a URL;
the URL contains a semicolon; the shell that builds the `curl` command treats everything after that
semicolon as a new command; that new command runs as root. The entire defect is the absence of a
boundary between data and code in a string that two different parsers read.

## 3. Authentication Boundary

The gate is real and it is the first thing the request meets. lighttpd does not authenticate REST
requests on this build; the agent does. Every REST request carries `Authorization: Bearer <token>`,
and the handler chain calls `fcn.0000f5a0` with that token before route dispatch. That function opens
`/tmp/restsession/<token>` to confirm the session exists, then runs a shell pipeline over the session
directory to confirm the entry is the one the token names, and finally takes a lock and refreshes the
file's timestamp.

The session check itself was observed under strace during the replication, and it is worth quoting
because it shows both that the gate executed for real and how the check is built:

```
execve("/bin/sh", ["sh", "-c",
  "ls -l /tmp/restsession/ | grep '/tmp/restsession/abc127.0.0.1' | awk '{print $9}'"])
flock(3, 2) = 0
read(3, ..., 17) = 17
sysinfo(...)
flock(3, 8) = 0
```

The `fopen()` on the session file is the existence gate; the `ls | grep | awk` pipeline is the
identity check; the `read()` of seventeen bytes matches the two-line session file used in the
replication (a user name and an epoch timestamp); `flock` and `sysinfo` are the bookkeeping that
follows a successful check. The record describes this gate as a token-existence test combined with an
IP-suffix test, and the harness honoured that combination: the session file was
`/tmp/restsession/abc127.0.0.1`, the request carried `HTTP_AUTHORIZATION: Bearer abc127.0.0.1` and
`REMOTE_ADDR=127.0.0.1`.

In production the token comes from `POST /api/v1/login`. The recorded client posts a JSON body of the
form `{"login":{"user_name":"<user>","password":"<password>"}}` and reads the session token from the
`token` key of the response; that client path was not exercised against hardware, so the login body
shape should be treated as the shape the recorded client emits rather than as a verified device
contract for every firmware revision. What the replication did verify is the CGI side: a request
without a matching session file never reaches the handler, and a request with one proceeds.

Two consequences follow, and they pull in opposite directions. The first is that this is not a
pre-authentication vulnerability: no unauthenticated path to the command sink was established, and
the record is explicit that the unauthenticated class does not hold here. The second is that the
credential requirement is not much of a control on a managed switch, because the account that can call
`/api/v1/download` is the administrator account, and that account already owns the device's
configuration. What the injection adds is not access but *shape*: it converts a bounded, schema-checked
management operation into an arbitrary shell, which is the difference between "the administrator can
change settings through the API" and "the administrator's session can run anything as root, quietly,
in a child process that the API never intended to expose".

The record also notes how an attacker who does not already hold the credential could get one: by
compromising the web interface first - phishing the administrator or obtaining a leaked credential -
and then using this endpoint, which turns web-plane access into a root shell. That chain is a
plausibility argument about credential acquisition, not a verified exploit path, and it is presented
as such.

## 4. Attack Surface

The REST v1 API is a large surface, and most of it is not interesting. Requests arrive as CGI
invocations: lighttpd sets the usual CGI environment (`REQUEST_METHOD`, `REQUEST_URI`,
`CONTENT_LENGTH`, `CONTENT_TYPE`, `HTTP_AUTHORIZATION`, `REMOTE_ADDR`), the agent reads the body from
stdin, and `main` hands the request to a route dispatcher at `fcn.0000faa8`, which validates the
Bearer token and then selects a handler by path.

The download route is one of the handlers that needs to run an external program, and that is what
narrows the audit to it. `POST /api/v1/download` accepts a JSON document whose `device_download` object
describes the transfer:

- `type` selects firmware or backup-configuration handling
- `protocol` selects the transfer scheme; `http` and `https` take the `curl` path, while the `tftp`
  branch never reaches `curl` and therefore never reaches these sinks
- `fwUrl` is the source URL
- `fwDownloadTimeout` bounds the transfer
- `rebootNow` and `signatureVerify` are flags; under `http` and `https`, `signatureVerify` must be `0`,
  which is what allows an unsigned payload to be fetched at all
- `image` selects one of two image slots and is numeric

Of those members, only `fwUrl` is a free-form string, and only `fwUrl` reaches a command line. The
protocol and type checks constrain *which branch* runs; they do not constrain the characters inside
the URL, and the record shows no length or charset validation between the JSON parse and the shell
composition. Components that narrow out are worth naming so the boundary of this finding is clear: the
`tftp` transfer branch does not use `curl`, non-download routes do not consume `fwUrl`, and the
authentication function precedes dispatch, so none of the other agents' endpoints are implicated by
this analysis.

## 5. Sink Identification

Disassembly of the handler at `fcn.00018e78` shows the whole construction in one function. The
following is the recorded pseudocode, with the addresses the record gives:

```
/* fcn.00018e78 - /api/v1/download handler ("device_download") */
pcVar13 = *(iVar3 + 0x10);                                  /* JSON field "fwUrl", raw value */
strncpy(&stack0xfffff7b0, pcVar13, strlen(pcVar13) + 1);    /* unfiltered copy */

fork();                                                     /* download child */
  openapiClientRegister(...);                               /* 0x19148 */
  while (rpcclt_openapiConnectivityCheck(...))              /* 0x19158 */
      sleep(1);
  snprintf(&stack0xfffff5b0, 0x100,
      "%s -k -sI %s | grep -i content-length | awk '{print $2}'",   /* .rodata 0x1ee24 */
      "/usr/local/appmgr/usr/sbin/curl", /* fwUrl verbatim */);
  stream = popen(&stack0xfffff5b0, "r");                    /* SINK #1, blx popen @ 0x192cc */
  fscanf(stream, "%u", &remote_size);
  ...
  sprintf(&stack0xfffff5b0,
      "%s -k -m %d -o %s/%s %s > /dev/null 2>&1",           /* .rodata 0x1ee80 */
      "/usr/local/appmgr/usr/sbin/curl", timeout, "/mnt/download", fname,
      /* fwUrl verbatim */);
  system(&stack0xfffff5b0);                                 /* SINK #2, blx system @ 0x19283/0x19293 */
```

Three properties of this listing carry the vulnerability. First, the URL is copied out of the JSON
value into a stack buffer with no content inspection at all; the copy is a transfer of bytes, not a
validation point. Second, the URL is placed into the format string as a bare `%s`, with no quotes
around it in either construction, so the shell sees it as syntax rather than as a word. Third, both
runtimes are shell-mediated: `popen()` and `system()` execute their argument with `/bin/sh -c` on this
platform, exactly as they do on any glibc or musl target, so the composed line is parsed by a shell in
the child, after the handler has already committed to it.

The first sink is the size probe. It runs `curl -k -sI <fwUrl>` and pipes the headers into `grep -i
content-length` and `awk '{print $2}'` to learn the remote object's length before downloading it. The
second sink is the transfer itself: `curl -k -m <timeout> -o /mnt/download/<name> <fwUrl>`, with output
discarded. The record notes that both the header probe and the download path are injectable, and that
the `snprintf` bound of `0x100` bytes caps the composed first line at 255 characters - enough for a
normal payload, and also a reason a long URL can truncate the trailing pipeline away. The second
construction is recorded as `sprintf` into the same buffer, with no length argument in the pseudocode.

The executing identity is the handler's own. The CGI and its forked child run as root on this
firmware, `/mnt/download` and `/tmp/restsession` are root-owned, and the appmgr lighttpd stack is
root-owned as well. The record states that identity as a property of the stack, and the replication
inherited it by construction, because it ran the real binary as root inside the chroot.

## 6. Source Identification

The source is a single JSON member, and the request that carries it is unremarkable:

```
POST /api/v1/download HTTP/1.1
Host: <switch>
Authorization: Bearer <token>
Content-Type: application/json

{"device_download":{"type":"firmware","protocol":"http",
 "fwUrl":"<string>","fwDownloadTimeout":10,"rebootNow":0,
 "signatureVerify":0,"image":2}}
```

The CGI reads the body from stdin for `CONTENT_LENGTH` bytes and parses it with the firmware's own
JSON helper. The handler then performs five field lookups on the parsed object; the record lists four
of their addresses - `0x18f24` for `protocol`, `0x18f38` for `fwUrl`, `0x18f4c` for
`fwDownloadTimeout` and `0x18f60` for `rebootNow` - and the fifth is not itemized in the record. The
value the `fwUrl` lookup returns is the string that becomes `pcVar13` in the sink listing, which is to
say the source and the sink are separated by a copy and a fork, and by nothing that validates.

The enclosing checks are the only checks. `protocol` must be `http` or `https` for the `curl` branch to
run, so a `tftp` request does not reach these sinks at all; `type` must be firmware or backup-config;
`image` must be one of two numeric slots; and under `http`/`https` the `signatureVerify` flag must be
`0`, which is a condition on the request rather than on the URL. None of these examines the URL's
characters, scheme-vs-string consistency, host, path or length beyond what the JSON parser and the
fixed buffers impose. A URL that begins with `http://` and then contains a semicolon satisfies every
one of them.

This is the point at which a reader should notice what is absent. There is no allowlist, no
metacharacter reject set, no quoting helper, no URL parser and no length check between the parse and
the `snprintf`. The record's sink listing shows the raw pointer flowing from the JSON lookup to the
format string, and the dynamic run shows the same value being interpreted by the shell. The source is
not misparsed or smuggled past a filter; it is simply data that later becomes code.

## 7. Data Flow

The chain is linear and short enough to draw:

```
stdin (CONTENT_LENGTH bytes)
  -> main
  -> fcn.0000faa8                 route dispatch; Bearer session gate first
  -> fcn.00018e78                 "device_download" handler
       field lookups: 0x18f24 "protocol", 0x18f38 "fwUrl",
                      0x18f4c "fwDownloadTimeout", 0x18f60 "rebootNow"
  -> strncpy                      URL bytes copied, no filtering
  -> fork()                       download child
       -> openapiClientRegister / rpcclt_openapiConnectivityCheck loop
       -> snprintf 0x100          "curl -k -sI <fwUrl> | grep -i content-length | awk ..."
       -> popen                   SINK #1
       -> sprintf                 "curl -k -m <t> -o /mnt/download/<name> <fwUrl> ..."
       -> system                  SINK #2
  -> /bin/sh -c parses the URL a second time, unquoted
```

Three properties of this flow deserve naming. The value is copied, not transformed: whatever bytes
the JSON decoder produced are the bytes the shell sees, apart from the terminator the copy adds. The
value is used twice, in two different command shapes, so a payload has to survive both constructions
or be scoped to one of them; the recorded payload survives both, because a semicolon is a separator in
either. And the child waits before it composes anything: `rpcclt_openapiConnectivityCheck` is polled in
a `sleep(1)` loop until the OpenAPI RPC layer is reachable, so the injected command runs after that
wait rather than at request time, which is worth knowing when timing a test against a real device.

There is no point in the chain where the URL is parsed as a URL. That absence is the whole defect: a
component that had parsed the value and re-serialized a scheme, host and path would have had an
opportunity to reject or escape the semicolon, and no such component exists on this path.

## 8. Exploit Construction

The payload is a URL whose first command is harmless and whose remainder is the command to run:

```
fwUrl = http://127.0.0.1/x;echo PWNED>/tmp/WIN;#

popen  : curl -k -sI http://127.0.0.1/x;echo PWNED>/tmp/WIN;# | grep -i content-length | awk '{print $2}'
system : curl -k -m 10 -o /mnt/download/<name> http://127.0.0.1/x;echo PWNED>/tmp/WIN;# > /dev/null 2>&1
```

The leading `http://127.0.0.1/x` exists to satisfy the `http` protocol branch and to give `curl`
something to fail on quickly; the semicolon ends that command and starts the injected one. The record
names two terminators for the injected sequence - a trailing `;#` or a bare `;` - and the PoC emits
`;#`, which closes the injected statement and turns the rest of the composed line into a comment, so
the pipeline that the format string appends cannot be parsed as part of the injected command. On the
`system` sink the trailing comment also removes the output redirection, which is immaterial to whether
the command runs.

Both sinks are built from the same value, so a single request exercises the header probe and the
download. The header-probe construction is bounded: `snprintf` writes at most `0x100` bytes, of which
the curl path and the ` -k -sI ` flag consume about forty, leaving on the order of two hundred
characters for the URL and the injected command before the trailing pipeline is truncated away. A
payload longer than that budget is not rejected; it is silently shortened, which is a behaviour to
keep in mind when constructing a payload rather than a defence.

The published PoC emits exactly this request shape. It logs in to `POST /api/v1/login` with a supplied
user name and password, takes the token from the response, and posts the `device_download` document
above with `fwUrl` carrying the injected sequence. Its default command writes a single marker file,
`/tmp/fwurl_marker`, containing a fixed string, and its default target is the documentation address
`192.0.2.10`, so that an unconfigured run reaches TEST-NET-1 rather than a real device. It performs no
second stage, no persistence, no file deletion and no credential use beyond the session the operator
supplies, and it prints the response body for the operator to correlate with the marker. Section 9
explains what the recorded evidence for that marker actually was.

## 9. Dynamic Verification

The verification environment was a QEMU ARM chroot assembled from the device's own firmware
components: the initramfs tree, the appmgr tree, the shared libraries under the switch root, and a
minimal set of host tools. The binary under test was the real `device.cgi` (ARMv7, md5
`35de649755e2341ea1f41f8b1fa4948c`), executed inside that chroot as root. Two adjustments made the
handler runnable outside a switch. The first was RPC stubbing: the handler calls into `rpcclt_*` and
`openapi*` client functions that a chroot cannot provide, so 92 of those PLT stubs were rewritten to
`mov r0, #0; bx lr` by a small patch script, which makes the calls return success without touching any
product logic. The second was a session file: `/tmp/restsession/abc127.0.0.1` was created with the two
lines the gate expects, and the CGI was invoked with lighttpd's conventions - `REQUEST_METHOD=POST`,
`REQUEST_URI=/api/v1/download`, `CONTENT_LENGTH` set to the body length, `CONTENT_TYPE=application/json`,
`HTTP_AUTHORIZATION: Bearer abc127.0.0.1` and `REMOTE_ADDR=127.0.0.1` - with the body on stdin.

The recorded run used this payload:

```
{"device_download": {"type": "firmware", "protocol": "http",
 "fwUrl": "http://127.0.0.1/x;echo PWNED>/tmp/WIN;id>/tmp/WINID;",
 "fwDownloadTimeout": 10, "rebootNow": 0, "signatureVerify": 0, "image": 2}}
```

The strace trace shows the gate executing, the body being read, and the handler forking and reaching
its shell calls:

```
execve("/bin/sh", ["sh", "-c", "ls -l /tmp/restsession/ | grep '/tmp/restsession/abc127.0.0.1' | awk '{print $9}'"])
flock(3, 2) = 0
read(3, ..., 17) = 17
sysinfo(...)
flock(3, 8) = 0
read(0, ..., 183) = 183
pipe2(...) = 0
clone(...) = <pid>
... execve("/bin/sh", ...) from popen() and system()
```

The REST call answered with the ordinary success document, and the injected command left its marker:

```
{"resp":{"status":"success","respCode":0,"respMsg":"Operation success"}}

$ cat /tmp/WIN
PWNED
```

Two details of that result deserve to be stated precisely rather than rounded off. The first is the
executing identity. The command ran in the CGI's forked child, and the CGI runs as root in this stack,
so the command ran as root; the record states the identity that way, from process ownership, and the
replication inherited it because the binary was launched as root inside the chroot. The second is what
the marker does not show. The payload also contained `id>/tmp/WINID`, and `/tmp/WINID` was never
created, because the harness's minimal userland ships no `id` binary; `echo` succeeded because it is a
shell builtin. The record therefore reports the injection as proven by the marker and the identity as
root from the process context, and it does not claim a captured `uid=0` line - none exists in the
record, and this advisory does not present one.

What the run establishes is that the real binary, driven through the real CGI conventions with a real
session file, interprets the request-controlled URL as shell syntax and executes the injected command
in its download child. What it does not establish is device-hardware behaviour: no physical switch was
driven, no live request was sent to a switch's management port, and the device-side reachability rests
on the record's analysis that the same binary, the same lighttpd CGI conventions and the same
stdin/`CONTENT_LENGTH` semantics apply on the product. The recorded client's device mode is described
as logically equivalent to the harness request - same endpoint, same body - and was not executed
because no device shell was available.

## 10. Reachability and Security Impact

On the device, the record places the REST v1 service on the same lighttpd instance that serves the
management interface: TLS on 8443, cleartext on 8080, both from appmgr. It identifies REST v1 as the
product's documented RESTful API, describes it as enabled by default, and notes that SNMP or the CLI
can enable it. The consequence is that an administrator - meaning anyone holding a web login on the
switch - can obtain a Bearer token and reach `/api/v1/download`, and a single request then executes an
arbitrary command as root. That is the whole reachability argument:
one authenticated request, no preconditions beyond a management session, no reliance on the download
actually succeeding, because the injected command runs after the semicolon regardless of what `curl`
does.

The record also sketches the wider compromise path, and it is worth repeating with its status
attached. An attacker who does not hold the credential can try to obtain it by compromising the web
interface first - phishing the administrator, or using a leaked or reused credential - and this
endpoint then converts that web-plane access into a root shell. That is a plausibility argument about
how the required session might be acquired, not a verified exploitation chain, and it is not counted
as part of the verified finding.

The impact is the impact of root on a managed switch, which is larger than the impact of root on an
endpoint. The configuration store holds the device's own credentials and its management-plane
settings; the shell can rewrite VLAN and interface configuration, authentication configuration,
logging and management access; the device sits in the path of everything it switches, so a
compromised switch is an interior position rather than an isolated host; and the presence of a root
shell permits persistence consistent with embedded Linux, up to the limits of the writable filesystem.
Survival of a factory reset or a firmware reflash was not tested and is not claimed. The chain is also
quiet: one authenticated POST inside a legitimate management action, with the command running in a
short-lived child, which is a poor fit for request-shape anomaly detection.

Scope boundaries worth stating alongside the impact. No pre-authentication path was established, so
this is not a wormable or internet-scan-reachable defect by itself. No execution on physical hardware
was performed, so the device-side claim is an analysis claim supported by a faithful replication
rather than a hardware observation. No memory-corruption primitive is claimed anywhere in this chain,
and the `sprintf` in the second construction is named as recorded rather than exploited. And no
statement is made here about models the record did not analyse: it notes that a later build of the
successor M4350 line carries the same construction - the same header-probe format string, the same
`/mnt/download` destination, the same `fwUrl` key and live `system`/`popen` imports, with a digest
beginning `09d1d91d` - and that a GSM_XSM4300 V12.0.2.15 image was obtained but not triaged. Neither
is presented as a verified second target; the first is a static observation about shared code and the
second is an open question.

## 11. Fix Recommendations

1. Replace both command constructions with argument-vector execution. `curl` needs no shell: build
   `{"curl", "-k", "-sI", fwUrl, NULL}` and `{"curl", "-k", "-m", timeout, "-o", dest, fwUrl, NULL}`
   and run them with `execvp()` or `posix_spawn()`, dropping the `grep`/`awk` size probe in favour of
   parsing `Content-Length` in process. This removes the second parser from the path entirely, which
   is the only fix that closes the class rather than the instance
2. Validate `fwUrl` as a URL before use. Parse it, accept only `http` and `https`, require a
   syntactically valid scheme and authority, reject control characters and shell metacharacters, and
   build the request from the parsed components rather than from the original string. The record's
   recommended shape is a schema check on scheme and host ahead of any interpolation
3. If a shell must stay in the path short-term, single-quote the URL with literal single-quote
   escaping, and assert after construction that the composed line contains no unquoted `;`, backtick,
   `$` or newline. Both current constructions interpolate the value bare, so neither has such an
   assertion today
4. Rewrite the session check in `fcn.0000f5a0` the same way. It composes `ls | grep | awk` around the
   raw token; `readdir()` and `stat()` answer the same question without a shell, and the record marks
   that interpolation as raw, so it belongs in the same migration even though this advisory claims no
   exploit through it
5. Drop the privilege of the web stack. appmgr and its CGI children run as root on this firmware; a
   dedicated unprivileged identity would not fix the injection but would cap what any web-plane defect
   can reach, and the download path needs write access only beneath `/mnt/download`
6. Sweep the agent family for the same compose-shell pattern. The record points to constructions such
   as `cat %s %s > %s` and `echo -n '%s' >> %s` in the same CGI family; an argument-array migration is
   the only change that closes them as a group
7. Add a regression test at the handler level: submit a `fwUrl` containing `;` and assert that either
   the request is rejected or no shell execution occurs, and run that test against every build that
   carries this agent. Operationally, restrict reachability to the REST ports, disable REST v1 where
   it is not used, and treat administrator credentials on these switches as root credentials

## 12. CWE

CWE-78, "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
is the exact mapping. The definition requires that the product construct all or part of an OS command
using externally influenced input and then execute it, and that is what happens here twice over: the
`fwUrl` member is externally influenced input, it is concatenated into a command string, and `popen()`
and `system()` hand that string to `/bin/sh -c`. The CWE's guidance is also the fix guidance - build
commands from separately validated arguments rather than from strings - which is why section 11 leads
with the argument-vector migration.

No secondary CWE is claimed. The reporting defect is not a blocklist gap or a parsing bug, because
there is no validation to bypass at all; it is the direct interpolation of request data into a shell
command. Likewise, no CVE identifier is attached: the source record names none, and this advisory
therefore records the identifier as unassigned rather than inferring one.
