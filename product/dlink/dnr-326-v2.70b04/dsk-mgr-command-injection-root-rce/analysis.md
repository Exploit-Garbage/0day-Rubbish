# D-Link DNR-326 v2.70b04 - dsk_mgr.cgi f_sethdsize command injection into the diskmgr shell pipeline

## 1. Overview

### The finding

The D-Link DNR-326 is a 16-channel network video recorder: a Linux appliance that ingests camera
streams, writes them to internal disks, and serves a web interface for live view, playback and
storage administration. On firmware v2.70b04, the disk-management CGI `cgi/dsk_mgr.cgi` accepts a
form field named `f_sethdsize`, interpolates it into a shell command line without quoting it, and
executes the result through `system()` - which is `/bin/sh -c`. The only filter between the HTTP
request and that command line is `cgiFormStringNoNewlines`, a libcgic helper that strips carriage
returns and line feeds and does nothing else. A semicolon therefore ends the intended argument and
whatever follows is parsed by the shell as a new command, in the identity of the CGI process.

The construction is recorded at two offsets in the stripped handler `fcn.0000d5e8`: the
interpolating `sprintf` at `0xd698` and the `system` call at `0xd6c8`. The format string is the
volume-expansion call for the secondary disk, `diskmgr -s %s -y sdb > /dev/null &`, and the `%s`
is the request field. Three further handlers in the same binary repeat the pattern with different
parameters and different `diskmgr` invocations, so this is one root cause with four entry points
rather than four separate defects.

### The product, platform and web stack

The analyzed artifact is `DNR-326_Ax_v2.70b04.bin`. Its rootfs is a CramFS image holding 2407
files on a 32-bit ARM Linux kernel 2.6.31.8. The web plane is lighttpd plus thirteen CGI binaries
under `/cgi-bin/` and a PHP fastcgi application for the pages. The firmware is a rebranded
platform, and the rebrand is visible in the configuration rather than inferred: the lighttpd
configuration sets `document-root=/NUUO/web/` and aliases the CGI directory with
`alias.url += ( "/cgi-bin/" => "/NUUO/bin/" )`, the version string is `sw_ver_1=2.70b04`, and the
server type is declared as `ServerType=DNR-326`. Two consequences matter for this analysis. The
first is that the binary paths a reader should look at are the ones the device actually serves, so
the alias is stated here rather than left implicit. The second is that the platform's shell idioms
are inherited from a lineage of recorder firmware, which is why the disk-management CGI is the
densest concentration of shell calls on the device.

### Why this finding sits where it does in the codebase

The codebase has a real, deliberate command-injection hardening, and it needs describing because
it explains why the audit narrowed to one CGI. The dominant pattern is user input flowing to
`safe_system()`, then `safe_exec()`, then `execvp(argv)` with an argument array - no shell ever
sees the value. The direct `system()` calls elsewhere in the firmware pass static string pointers:
the format is a constant loaded by address, with no `%s` interpolation of request data. Request
fields are read with a size limit matching their destination buffer, so the source side is bounded.
All thirteen CGI binaries carry a `__stack_chk_fail` reference count of zero, which means no stack
canaries, but that is a buffer-overflow concern rather than a command-injection one and it is not
the subject of this advisory.

Against that background `dsk_mgr.cgi` is the outlier. It contains 66 `system()` call sites, far
more than any other CGI on the device, and its disk-management handlers do the one thing the rest
of the codebase avoids: they build a shell string with `sprintf` around a request field and hand
it to `system()`. The hardening that holds everywhere else is simply absent on this path.

### Public-record independence

The public vulnerability record was swept for this sink before the analysis was accepted. The
sweep covered the product name alone; the product name combined with the CGI name, each dispatch
value, the parameter names and the command family; and the rebrand lineage of the platform. The
result is that no record found in the sweep names `dsk_mgr.cgi`, `FMT_expan_diskmgr`,
`f_sethdsize`, or the `diskmgr -s` command form. The public records that do exist for this vendor's
recorders name other CGIs - the system-management CGI, the account-management CGI, an upload
endpoint - and the records that exist for the originating recorder platform name an entry point
that is a zero-byte stub in this firmware. None of them is this handler, this parameter or this
construction, and the sanitizer gap described here is a distinct root cause rather than a variant
of any of them.

No identifier has been assigned to this finding. The advisory therefore carries none, and readers
should not read the absence of a CVE as an absence of a report.

### Verification boundary, stated before anything else

Firmware-level disassembly established the handler, the dispatch value, the source parameter, the
sanitizer's exact behaviour and the shell construction. Dynamic evidence comes from a sink-level
replication: a local HTTP endpoint on the researcher's workstation that reproduces the exact
construction `diskmgr -s %s -y sdb > /dev/null &` and executes it through `/bin/sh`, with the
exploit sent over HTTP end to end and a marker file as the observation channel. Full-device
emulation was not possible - the rootfs is CramFS on 32-bit ARM inside a rebranded recorder
platform with no board-level support in the available emulators - and no physical DNR-326 unit was
available, so no live request was fired at device hardware.

The replication ran under the workstation's own unprivileged account. The identity it recorded is
therefore that account, not root. Root on the appliance is a firmware-derived inference: the
lighttpd launch configuration gives the CGI handlers uid 0, so command text delivered through a CGI
handler inherits device-root authority. That inference is labelled as an inference throughout, and
section 9 keeps it separate from what was measured.

## 2. Vulnerability Summary

### Summary table

| Item | Value established by this research |
|---|---|
| Vendor | D-Link, network video recorders |
| Product | DNR-326, 16-channel network video recorder |
| Version analyzed | firmware v2.70b04, image `DNR-326_Ax_v2.70b04.bin` |
| Platform | 32-bit ARM, CramFS rootfs of 2407 files, kernel 2.6.31.8 |
| Web stack | lighttpd, `document-root=/NUUO/web/`, CGI alias to `/NUUO/bin/`, PHP fastcgi |
| Component | `cgi/dsk_mgr.cgi`, served as `/cgi-bin/dsk_mgr.cgi` |
| Vulnerable dispatch | `cmd=FMT_expan_diskmgr` |
| Handler | `fcn.0000d5e8` in the stripped CGI |
| Parameter | `f_sethdsize`, read into a 0x40-byte buffer |
| Sanitizer | `cgiFormStringNoNewlines`, `lib/libcgic.so` at `0x5420`, strips CR and LF only |
| Sink | `sprintf` at `0xd698` into `diskmgr -s %s -y sdb > /dev/null &`, `system` at `0xd6c8` |
| Breakout | `;` statement separator, with trailing `#` to comment the rest of the line |
| Sibling handlers | `fcn.0000d754`, `fcn.0000e8fc`, `fcn.0000edd8` |
| Authentication | administrator session, `cgiMain` gate at `fcn.0000aa64` |
| Device identity | CGI launched with uid 0 per the lighttpd configuration (firmware reading) |
| Primary CWE | CWE-78 |
| Identifier | none assigned |

### The vulnerable construction

The decompiled handler, with the two offsets that carry the finding marked:

```c
/* cgi/dsk_mgr.cgi, handler fcn.0000d5e8, dispatched by cmd=FMT_expan_diskmgr */
cgiFormStringNoNewlines("f_sethdsize", auStack_60, 0x40);   /* 64-byte buffer  */
cgiFormStringNoNewlines("f_web",      &cStack_80, 0x20);

/* static-string system() calls in the same function are not the finding */
sprintf(buf, "rm -f %s > /dev/null", "/var/www/xml/dm_bar.xml");
system(buf);

if ((cStack_80 == '1') && (cStack_7f == '\0')) {
    /* static copy branch - the field is not used to build a command */
} else {
    /* injection: unquoted interpolation of a request field into a shell line */
    sprintf(&uStack_280, "diskmgr -s %s -y sdb > /dev/null &", auStack_60);  /* 0xd698 */
}

system("kill_running_process > /dev/null");
system(&uStack_280);                                                         /* 0xd6c8 */
system("touch /tmp/hdd_formating");
```

Three decisions in that function carry the whole finding. The field is read with a helper whose
name suggests sanitization but whose behaviour is newline stripping. The field is interpolated
without quoting into a command line that the handler then executes. And the branch that does the
interpolation is the default branch - it is taken for any `f_web` value other than the single
static-copy case, which means the reachable path is the vulnerable one for ordinary requests.

### Same root cause, four entry points

| Dispatch value | Handler | Request parameter | Shell format |
|---|---|---|---|
| `FMT_expan_diskmgr` | `fcn.0000d5e8` | `f_sethdsize` | `diskmgr -s %s -y sdb > /dev/null &` |
| `FMT_expan_replace_diskmgr` | `fcn.0000d754` | `f_sethdsize` | `diskmgr -s %s -y %s ...` |
| `cgi_create_diskmgr` | `fcn.0000e8fc` | `f_filesystem`, `f_sethdsize` | `diskmgr -m raid0 -f %s -s %s ...` |
| `FMT_rebild_diskmgr` | `fcn.0000edd8` | `f_dev` | `diskmgr -t %s ...` |

All four share the identical defect: a request parameter reaches `sprintf(%s)` and then `system()`
without neutralization, bypassing the `safe_system`/`execvp` hardening the rest of the codebase
uses. They are described as one root cause with four instances because the fix is one decision -
stop interpolating request data into shell strings in this CGI - applied four times.

### Preconditions

1. A valid administrator session on the NVR web interface. The dispatch is gated on the login check
   and there is no path to the handler without it.
2. Network reach to the web interface. Nothing else - no default credential, no session forgery, no
   memory groom, no reboot window, no particular client software, and no requirement that any
   disk-management operation be in progress.

## 3. Authentication Boundary

### The gate

The handler is dispatched only after authentication. The `cgiMain` structure is:

```c
iVar1 = fcn.0000aa64();      /* check_login wrapper */
if (iVar1 == 1) {            /* authenticated              */
    /* cmd dispatch -> FMT_expan_diskmgr -> fcn.0000d5e8 -> system() */
}
```

`fcn.0000aa64` resolves to `check_login()`, which is a `cgiCookieString` read of the session cookie
followed by `wto_check_login` from the platform's session library `lib/libwto.so`. The disk
management handlers are therefore reachable only with a session the device has already accepted.
This is the Authenticated class: the attacker is the administrator, exercising an
interface the firmware provides for exactly this operation.

### What the chain does not do

- It does not bypass authentication. The session gate is consumed, not defeated.
- It does not depend on default or weak credentials. The same request works whatever the
  administrator's password is, and rotating that password narrows nothing.
- It does not forge, replay or fixate a session. The cookie used is a legitimate session the
  attacker obtained by logging in.
- It does not attack request parsing. The POST body is a well-formed
  `application/x-www-form-urlencoded` document with three ordinary fields.

### The localhost-trust branch, and why it is not part of this chain

`wto_check_login` carries a second, independent behaviour recorded at `lib/libwto.so` offset
`0x2de8`:

```asm
0x2e08: ldr r1, [0x2e58]        ; literal pool entry 0xffff7e78
0x2e0c: add r1, r3, r1          ; 0x3ac8 -> "127.0.0.1"
0x2e10: bl strcmp               ; strcmp(REMOTE_ADDR, "127.0.0.1")
0x2e14: cmp r0, 0
0x2e18: bne 0x2e24
0x2e1c: add r0, r0, 1           ; return 1 (authenticated) when the compare matches
```

If `REMOTE_ADDR` equals `127.0.0.1`, the function returns "authenticated" regardless of the session
cookie. That is a genuine localhost-trust assumption, and it is not remotely reachable on this
firmware: `default/nvr/lighttpd.conf` loads only `mod_alias`, `mod_fastcgi` and `mod_cgi`. There is
no `mod_extforward` and no `mod_proxy`, so `REMOTE_ADDR` is derived from the TCP peer address and
cannot be influenced by `X-Forwarded-For` or any other request header. Reaching that branch would
require a request that originates on the appliance itself - an on-device server-side request forgery
primitive that this research did not establish. It is recorded as a secondary observation, it is
not used by the published chain, and it is not claimed as a pre-authentication path.

### Why the boundary does not soften the impact

A reader could argue that an administrator who can already reconfigure the recorder does not gain
much from a shell on it. The evidence contradicts that reading in three ways. First, the web
interface's authority and the operating system's authority are different sets: the interface
exposes recording, storage and network settings, while a shell exposes the filesystem the footage
lives on, the credentials the appliance holds for cameras and shares, and the binaries the
appliance runs. Second, the appliance is normally the most trusted host on a camera VLAN, so a
shell on it is a position rather than an action. Third, administrator credentials are shared,
reused and phished far more often than they are rotated, and the population that holds one is not
the population that was trusted with root on the recorder. That is exactly why the privilege metric
is High and the score is 7.2 rather than higher.

## 4. Attack Surface

### The web plane and its dispatch model

The DNR-326 web plane is lighttpd serving PHP pages plus thirteen CGI binaries. Control actions
land on those CGIs under `/cgi-bin/`, and each CGI dispatches internally on a `cmd` field. This is a coarse dispatch model: one CGI covers a whole subsystem, so
a single binary's parameter handling is the entire attack surface of that subsystem. The
disk-management subsystem is `dsk_mgr.cgi`, and it is the largest CGI on the device.

Two structural properties of the arrangement are worth naming. The CGI alias maps `/cgi-bin/` onto
`/NUUO/bin/`, so the URL space and the filesystem layout are not the same thing, and a reader
auditing the firmware has to follow the alias to find the binary. And the CGI handlers are launched
by the lighttpd configuration, which is where the process identity comes from - the same
configuration decides both what is reachable and who executes it.

### Why the surface audit narrowed here

Against a codebase whose dominant pattern is argument-array execution, the audit question is not
"does any request field reach a shell" but "which handlers build a shell string dynamically". The
per-CGI `system()` census answers it: `dsk_mgr.cgi` carries 66 call sites, and the disk-management
handlers are the ones that interpolate a request field into the format string. The other handlers
either use `safe_system`/`safe_exec`/`execvp` with an argument array, or call `system()` with a
static pointer whose contents no request can influence. That distinction is the reason this
advisory names one CGI and four handlers rather than a firmware-wide pattern.

### Components that narrowed out

- The PHP fastcgi pages were not the sink here. They form the presentation layer, and the control
  actions they post to are the CGIs.
- The static-string `system()` calls inside `dsk_mgr.cgi` itself - the `rm -f` of
  `/var/www/xml/dm_bar.xml`, `kill_running_process`, `touch /tmp/hdd_formating` - are not
  reachable by a request field and are not part of the finding.
- `safe_system`/`safe_exec` callers elsewhere in the firmware are immune by construction: the
  command is executed through `execvp` with an argument vector, so no shell parses it.
- The `wto_check_login` localhost-trust branch narrowed out of the chain for the reason given in
  section 3: without `mod_extforward` or `mod_proxy`, the address it compares is the TCP peer.
- Stack protection absence (`__stack_chk_fail` count zero across all thirteen CGIs) is a real
  hardening gap but a different vulnerability class, and it is not claimed here.

## 5. Sink Identification

### The three constructions in one function

`fcn.0000d5e8` contains three kinds of command construction, and separating them is what makes the
finding precise rather than a blanket claim about a CGI with 66 `system()` calls:

```c
/* kind 1: static format, static argument - not reachable by a request field    */
sprintf(buf, "rm -f %s > /dev/null", "/var/www/xml/dm_bar.xml");
system(buf);

/* kind 2: static literal - no formatting at all                                 */
system("kill_running_process > /dev/null");
system("touch /tmp/hdd_formating");

/* kind 3: dynamic - request field interpolated into a shell line               */
sprintf(&uStack_280, "diskmgr -s %s -y sdb > /dev/null &", auStack_60);   /* 0xd698 */
system(&uStack_280);                                                      /* 0xd6c8 */
```

Only kind 3 is the finding. The `%s` receives `auStack_60`, the 0x40-byte buffer that
`cgiFormStringNoNewlines` filled from the `f_sethdsize` form field. Nothing between that read and
the `sprintf` transforms the value, and nothing quotes it.

### Execution identity

The sink is reached inside a CGI process. The firmware's lighttpd configuration launches those
handlers with uid 0, so the shell that `system()` spawns - `/bin/sh -c` per the C library's
documented behaviour - runs with device-root authority, and the injected command inherits it. This
is the single most consequential property of the finding and the one with the weakest direct
measurement: it is read from the firmware's own launch configuration, not observed on hardware.
Section 9 states the boundary in the same terms.

### The string processor is not a control

There is a temptation to treat `cgiFormStringNoNewlines` as a sanitizer because its name contains a
filtering word. It is not one on this path, and the reason is mechanical: its input alphabet
restriction is two bytes wide. It also collapses runs of CR and LF into a single newline, which is
a formatting convenience for the caller, not a security transformation. Everything a shell cares
about - `;`, `|`, `&`, `$`, backticks, parentheses, `#` - passes through byte for byte.

## 6. Source Identification

### The parameter and its bounds

`f_sethdsize` is the disk-size field posted by the volume-expansion form. The handler reads it with
`cgiFormStringNoNewlines("f_sethdsize", auStack_60, 0x40)`, so the destination is 64 bytes, and
reads `f_web` into 0x20 bytes. The companion field is a mode selector: the handler compares
`cStack_80` against `'1'` and requires `cStack_7f` to be NUL, which is a one-character string
comparison, and takes the static-copy branch only in that exact case.

The size bound means an injected command is limited to roughly 60 bytes of field payload. That is
ample for the operation this advisory demonstrates - a shell command that writes a marker or
performs a single action - and it is also ample for a short second-stage fetch, which is why the
bound is a constraint on payload style rather than a mitigation.

### The sanitizer, character by character

The helper is `cgiFormStringNoNewlines` at `0x5420` in `lib/libcgic.so`, a thin wrapper around
`fcn.0000576c`. Its whole transformation:

```asm
0x57dc: cmp r3, 0xd         ; carriage return  -> dropped
0x57e8: cmp r3, 0xa         ; line feed        -> dropped
                            ; all other bytes  -> copied verbatim
```

So the helper removes two bytes out of the shell's metacharacter vocabulary and keeps the rest. The
name is accurate - it strips newlines - and the guarantee it provides is a formatting guarantee.
The vulnerable handler treats it as if it were a sanitizer, which is the entire defect in one
sentence: a newline stripper was mistaken for a shell filter.

### What the payload has to respect

Three constraints follow from the source side, and they are weak:

1. No CR or LF in the value. A single-line command satisfies this trivially.
2. At most about 60 bytes of payload, given the 0x40 destination.
3. The value must be URL-encoded in the request body, since it is read as a form field - which is a
   transport requirement, not a filter.

Nothing else. The character set the shell needs for a separator, a pipe or a substitution container
is entirely available.

## 7. Data Flow

The chain is short enough to state as a sequence, which is the clearest way to see that no step in
it is conditional:

1. The administrator's browser, or a script holding the administrator's session cookie, posts a
   form body to `/cgi-bin/dsk_mgr.cgi` with `cmd=FMT_expan_diskmgr`, `f_sethdsize` set to a value
   containing `;`, and `f_web` set to `0`.
2. lighttpd routes the request through its CGI module to the `dsk_mgr.cgi` binary, which runs under
   the identity the lighttpd configuration assigns.
3. `cgiMain` checks the session via `fcn.0000aa64`, which reads the session cookie and calls
   `wto_check_login`. The check succeeds because the session is legitimate.
4. `cgiMain` dispatches on `cmd` and enters `fcn.0000d5e8`.
5. `cgiFormStringNoNewlines` copies `f_sethdsize` into the 0x40 buffer at `auStack_60`, removing
   only CR and LF. The `;` survives.
6. The `f_web` comparison fails the static-copy case, so control reaches the interpolating branch.
7. `sprintf` at `0xd698` produces `diskmgr -s ;<payload>;# -y sdb > /dev/null &`.
8. `system` at `0xd6c8` passes that string to `/bin/sh -c`.
9. The shell parses the line. `diskmgr -s` runs with an empty argument and fails; the `;` starts a
   new command, which is the payload; the `#` comments out the remainder of the original line,
   including the trailing `&`, so the injected command runs in the foreground of the shell.
10. The payload executes with the CGI process's identity, and the handler returns its ordinary
    redirect page.

Two properties of that flow are worth naming. First, it is deterministic: there is no branch that
depends on device state, no timing window, and no second request - the injected command runs on the
first POST. Second, the failure of `diskmgr` is irrelevant to the attack. The record's replication
observed exactly this: the shell reported that `diskmgr` was not found, then executed the
semicolon-separated command anyway, which is the same ordering the device would follow.

## 8. Exploit Construction

The PoC shipped with this advisory is `exploit/dlink_dnr326_dsk_mgr_poc.py`. It is a single-request
client: standard library only, argparse for the target address and port, a session cookie supplied
by the operator, and a command argument whose default writes a marker file. It builds the payload,
posts it, and prints the status line and the first bytes of the response. It does not interpret
device state, does not chain a second stage and does not attempt to read the marker back.

### Request shape

```http
POST /cgi-bin/dsk_mgr.cgi HTTP/1.1
Host: 192.0.2.10
Cookie: sessionid=<administrator session>
Content-Type: application/x-www-form-urlencoded

cmd=FMT_expan_diskmgr&f_sethdsize=%3Bid%20%3E%20%2Ftmp%2Fdnr326_dsk_mgr_marker%3B%23&f_web=0
```

Decoded, the injected field is `;id > /tmp/dnr326_dsk_mgr_marker;#` and the command line the
handler constructs is `diskmgr -s ;id > /tmp/dnr326_dsk_mgr_marker;# -y sdb > /dev/null &`.

### Payload engineering

The payload is three parts:

```
;  <command>  ;#
```

The leading `;` terminates the `diskmgr -s` argument so the shell sees an empty size. The trailing
`;` separates the injected command from what follows, and the `#` comments out the rest of the
original line - `-y sdb > /dev/null &` - which has two effects worth stating: it removes the
`diskmgr` arguments that would otherwise become the injected command's arguments, and it removes
the trailing `&`, so the command is not backgrounded and the CGI does not return before it runs.
The `;` before the `#` is what keeps the construct readable in either order; a `#` alone at the end
of the command would also work, but the explicit separator makes the payload's shape unambiguous
in a request log.

Because the field is capped at roughly 60 bytes, the practical payload style is a short command.
The PoC's default writes the output of `id` to a marker file under `/tmp`, which is a
non-destructive identity capture and the same observation channel the record used.

### What the PoC deliberately does not do

- It does not brute-force, guess or collect credentials. The session cookie is an argument the
  operator supplies, obtained by logging in legitimately.
- It performs one request and prints what came back. It does not open an interactive channel, does
  not install persistence and does not modify device configuration.
- Its default command touches one file under `/tmp`. It contains no `rm`, no format, no write to a
  device node and no service action, so a mis-aimed default run cannot destroy storage.
- It has no default that could be mistaken for a live target: the default address is the
  documentation range, and the default port is 80.

## 9. Dynamic Verification

### Environment and method, stated exactly

| Element | Value |
|---|---|
| Method | sink-level replication: a local HTTP endpoint reproducing the exact sink |
| Sink reproduced | `system("diskmgr -s %s -y sdb > /dev/null &")` |
| Endpoint | `127.0.0.1:18923`, `http.server` request handler |
| Execution | `subprocess.call(..., shell=True, executable="/bin/sh")`, equivalent to `/bin/sh -c` |
| Transport | the exploit sent over HTTP to the replica, form-encoded, as against the device |
| Observation channel | marker file created by the injected command, read from the harness filesystem |
| Control | a benign value through the same construction path |
| Not performed | any request against DNR-326 hardware; no physical unit was available |
| Harness privilege | the workstation's ordinary unprivileged account |

The replication is faithful in the only respect that matters for this finding: the string handed to
the shell is byte-for-byte the string the handler builds. What it cannot reproduce is the device's
process identity, and the record does not pretend otherwise.

### Vectors and results

The record's result matrix, with the marker path shown as the published PoC names it:

| Test | Injected command | `f_sethdsize` value | Marker created | Verdict |
|---|---|---|---|---|
| 1 | `id > /tmp/dnr326_dsk_mgr_marker` | `;id > /tmp/dnr326_dsk_mgr_marker;#` | yes | separator class executes `id` |
| 2 | `echo PWNED_DOLLAR > /tmp/dnr326_dsk_mgr_marker` | `;echo PWNED_DOLLAR > ...;#` | yes | dollar-sign-bearing argument executes |
| 3 | `echo PWNED_PIPE \| tee /tmp/dnr326_dsk_mgr_marker` | `;echo PWNED_PIPE \| tee ...;#` | yes | pipe metacharacter class |
| 4 (control) | `1234` | `;1234;#` | no | benign value does not execute |

The record classifies the three vectors as the separator class, the command-substitution class and
the pipe class. The literal payloads above are what the transcripts show, and this advisory reports
the payloads rather than the label: vector 2 carries a dollar sign inside an ordinary word and a
separator in front of it, so it exercises the separator a second time rather than command
substitution. Vector 1 is the one that proves arbitrary command execution, because `id` is a real
command whose output is the marker content. Vector 3 proves that the pipe reaches the shell as a
pipe. Nothing here depends on the second vector being something other than what it is.

Representative transcript, vector 1:

```
[*] Local sink replica listening on 127.0.0.1:18923
[*] Target URL : http://127.0.0.1:18923/cgi-bin/dsk_mgr.cgi
[*] cmd        : FMT_expan_diskmgr
[*] f_sethdsize: ;id > /tmp/dnr326_dsk_mgr_marker;#
[replica] system() argument: 'diskmgr -s ;id > /tmp/dnr326_dsk_mgr_marker;# -y sdb > /dev/null &'
[+] HTTP 200, 71 bytes response
[+] SUCCESS: marker file /tmp/dnr326_dsk_mgr_marker created by injected command
[+] Marker content:
uid=501(<workstation account, redacted>) gid=20(staff) groups=20(staff),12(everyone)
```

The `/bin/sh: diskmgr: command not found` line in the same run is the load-bearing detail rather
than a defect: it shows the shell parsed `diskmgr -s` as a real command, failed on it, and then
continued past the `;` to execute the injected command, which is exactly the ordering the device
would follow - on the device `diskmgr` is present in `/NUUO/bin/`, so the first command would run
and the injected one would run after it.

The marker content is the harness account's `id` output, redacted here for the operator's account
name and preserved in its technical parts. It is not a root marker and it is not presented as one.

### The control, and why it matters

The control run posts `;1234;#`, which is the identical wrapper around a value that is not a
command. The shell reports `1234: command not found` and no marker file is created. That negative
is what makes the three positives attributable: the marker in vectors 1 to 3 was created by the
injected command, not by a side effect of the replica, the transport or the harness.

### Negatives, stated

- No request was sent to DNR-326 hardware. The request path, the session gate, the dispatch, the
  parameter extraction and the sanitizer behaviour are disassembly-level findings.
- No root marker was observed. The replication ran unprivileged, and the identity it recorded is
  the harness account. Device-root authority is inferred from the lighttpd launch configuration and
  is labelled as an inference everywhere it appears.
- No persistence, no escape to camera or management networks and no memory-corruption behaviour
  were tested or claimed.
- Firmware versions other than v2.70b04 were not analyzed, and no other D-Link model was surveyed
  for this handler family.
- Full-device emulation was not achieved: CramFS rootfs on 32-bit ARM inside a rebranded recorder
  platform, with no board-level support in the available emulators.

## 10. Reachability and Security Impact

The handler answers on the appliance's management web interface, over the network the recorder is
installed on. That is the reachability the published vector codes: `AV:N`, network. The credential
requirement does not make reachability moot - it defines the affected population, which is every
holder of an administrator session on any host the interface admits, plus anyone who has obtained
such a session by other means. For that second group this finding is the step that converts web
console access into operating-system access on the device.

The impact at root authority on a network video recorder is concrete rather than abstract:

- The footage. An NVR exists to hold video, and root access means the attacker can read, copy,
  stage or destroy it. Footage recorded before the attacker arrived is reachable, which is the
  property that makes an NVR compromise different from a generic appliance compromise.
- The credentials. The appliance holds credentials for the cameras it records and for the shares it
  writes to; at root they are readable, and the camera network is a second stage.
- The recording service. It can be stopped, its retention altered, or the disk-management path this
  chain lives in driven into a state the operator must rebuild.
- The evidentiary record. An attacker with shell access can change the very disk and recording
  state the web console reports, so the operator's view of the device stops being trustworthy.
- Persistence. Startup scripts, accounts and scheduled work within the writable areas of the
  appliance, to the extent a CramFS-based platform permits writes; durability across reflash was
  not tested.

What was not established is the far side of that authority: escape from the appliance into the
camera network by any specific mechanism, persistence across factory reset, and any memory
corruption primitive. Those are stated as out of scope rather than implied.

The security meaning is a change in what a credential is worth. Before this finding, an NVR
administrator password bought configuration changes and footage review through an interface that
the vendor designed for those purposes. After it, the same password buys a shell on the host that
sits at the centre of the surveillance deployment, and that host is normally the most trusted
machine on the camera VLAN. The escalation is not from unauthenticated to authenticated; it is from
authenticated-and-constrained to authenticated-and-unconstrained.

## 11. Fix Recommendations

1. Validate the source field by set membership, not by absence of bad characters. A disk size is
   digits; a device selector is a member of a fixed list. Reject anything else at the handler.
2. Remove the shell from the disk-management path: execute `diskmgr` with an argument array
   (`execv`/`execvp`, or the `safe_system`/`safe_exec` helper the same binary already uses) with
   `-s`, the size and `-y sdb` as distinct arguments. This eliminates the parsing layer instead of
   predicting it.
3. If the shell must stay for one release, single-quote each interpolated value with literal
   single-quote escaping and assert after construction that the command string contains no
   metacharacter; fail the request when the assertion trips.
4. Fix all four handlers in one change: `fcn.0000d5e8`, `fcn.0000d754`, `fcn.0000e8fc` and
   `fcn.0000edd8`. One handler patched, three live, is a fix that misreports itself.
5. Sweep the remaining shell surface of `dsk_mgr.cgi` (66 `system()` sites) and classify each as
   static or interpolating; migrate the interpolating ones, leave the static ones alone so the diff
   stays reviewable.
6. Reduce the CGI privilege level. Root CGI handlers turn every injection in the web plane into a
   device compromise; a dedicated unprivileged identity with access only to the nodes the
   disk-management action needs caps the next one.
7. Add a handler-level regression test: post `;id;#` as the size field and assert either rejection
   or no shell execution; repeat with the pipe and substitution forms, across all four dispatch
   values.
8. For operators without a patch: keep the interface off untrusted networks, never expose it to the
   internet, restrict management to an administrative VLAN, rotate the administrator credential if
   the interface has ever answered on a shared network, and treat unexpected `diskmgr` invocations
   or disk-state changes as possible command-execution indicators rather than storage faults.

## 12. CWE

CWE-78, Improper Neutralization of Special Elements used in an OS Command, is the primary and only
classification applied here. Every element of the chain is exactly this class: a request field
reaches a command line built by string interpolation, the command line is executed through
`system()` and therefore `/bin/sh -c`, and shell parsing turns part of the attacker's value into
executed command text. The unquoted `%s` at `0xd698`, the `system` call at `0xd6c8` and the
semicolon breakout are the three canonical ingredients of the class.

CWE-20, Improper Input Validation, was considered as a co-equal reading and is recorded here as
contributing rather than co-equal. The distinction is substantive: the defect is not that a
validator was too permissive in some general sense - it is that the value was never validated at
all before being placed in a context with its own parser. The helper on the path strips newlines,
which is a formatting transformation, not a validation decision. Describing this as an input
validation problem would place the fix in the validator and leave the interpolation in place, which
is the wrong fix.

CWE-88, Argument Injection, was considered and rejected. The value is interpolated into the command
string rather than appended as an argument word, so the attacker is not constrained to supplying
options to `diskmgr`; the semicolon ends the command outright and a new one begins.

CWE-284, Improper Access Control, was considered and rejected as the primary class. The
authorization on the action is what it claims to be - administrator-only - and the defect is not
who may call it but what the call does with its parameter. The privilege story matters for the
score, not for the classification.

CWE-250, Execution with Unnecessary Privileges, is the accurate label for the amplifying condition
rather than the defect: the CGI handlers run as root where a dedicated identity would suffice. It
is recorded because the fix list includes it, and it is not merged into the primary class because a
privilege reduction would not close the injection.

---

Written by the 0day Rubbish Research Team.
