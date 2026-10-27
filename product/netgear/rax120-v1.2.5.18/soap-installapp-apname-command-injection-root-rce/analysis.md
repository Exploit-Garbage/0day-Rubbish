# NETGEAR RAX120 (Nighthawk AX12) V1.2.5.18 - SOAP InstallApp apName Dollar-Parentheses Command Injection (command execution as the root-configured web stack; uid=0(root) observed in sink-level replication)

## 1. Overview

### Overview of the finding

NETGEAR's RAX120 (Nighthawk AX12) is a consumer WiFi 6 router built on the Qualcomm IPQ8074
system-on-chip. Its administrative plane is not the vendor's older self-built httpd: it is a lighttpd
server fronting `/usr/sbin/net-cgi`, the CGI handler of the DNI framework generation, and every SOAP
action a management client can invoke is dispatched through `/soap/server_XMLresp.cgi`. One of those
actions is `InstallApp`, the app-installation operation of the service registered under
`urn:NETGEAR-ROUTER:service:AppSystem:1`. It is an administrator-gated control - the research record
identifies its session gate as the administrative SOAP login bound to the requesting station's MAC
address, failing closed - and it accepts an application name in the `NewAppName` element.

The defense between that element and the operating system is a single blocklist. The handler screens the
name through a validator whose "apname" mode rejects six characters: `@`, the backtick, the semicolon, the
double quote, the single quote and the backslash. That set was evidently chosen with shell injection in
mind - it covers the classic statement-separator and quote-context breakouts - but it does not reject
`$`, `(` or `)`. After validation, the handler interpolates the name, unquoted, into three shell command
lines and passes each to `system()` or `popen()`. Both of those library functions execute their argument
through `/bin/sh -c`, which means the name is parsed a second time, by a shell, in a context the validator
never modeled. A name of the shape `x$(cmd)` therefore performs command substitution before the
surrounding `rm -rf` words run - the shell never needs the semicolon or the backtick the validator
blocks, because `$( )` is itself a complete statement container.

The landing identity of the substituted command is the web stack's identity, and the firmware image's
own lighttpd configuration sets that identity to root (the configuration file's server user directive).
The dynamic portion of this research verified exactly that at the sink: a sink-level replication - a
native-compiled C program reproducing the disassembled validator logic, the CRLF-normalizing string
processor and all three command lines - produced markers containing `uid=0(root) gid=0(root) groups=0(root)`
for each of the three injected vectors, while a benign control name produced none. The R7800 sibling
platform, whose handler family shares this construction and whose validator is strictly more permissive,
passed the same payload with its own identical replication and its own clean control.

One boundary statement belongs at the very top of any reading of this advisory: verification was a
sink-level replication on an isolated cloud-hosted sandbox, on native commodity hardware, not a live
device. No physical router was driven during verification, no live SOAP request was fired at device
hardware, and the request path, the session gate and the parameter extraction are established at
disassembly level while the substitution-execution behavior is established by the replication. Section 9
keeps those two halves of the evidence explicitly separated.

### Overview of the product, platform and web stack

The analyzed image is RAX120 firmware V1.2.5.18: Qualcomm IPQ8074 SoC, aarch64, musl libc, stripped
binaries. The web service is lighttpd plus the DNI-framework CGI handler `/usr/sbin/net-cgi` - a
1,042,120-byte stripped binary whose recorded image digest begins d7035dd3. Two properties of this stack
shaped the whole audit and need stating, because they explain why this finding is where it is:

- `net-cgi` contains a framework helper that executes commands through `vfork()` plus `execve()` with an
  argument vector. That path is architecturally immune to shell injection - no shell ever sees the
  string - and large parts of the firmware use it, which is why the attack surface is narrower than the
  same binary's raw call count would suggest.
- The remaining shell-mediated surface consists of direct `system()` and `popen()` call sites. A full
  enumeration found on the order of 150+ `system()` sites in this binary, almost all of them fixed string
  constants loaded by address-arithmetic (no `%s` interpolation), and about 54 `popen()` sites. The
  app-installation handler is the exception that constructs its command lines dynamically, and it is the
  finding of this advisory.

### Overview of public-record independence

Before drafting this advisory, the public vulnerability record was swept along every axis available:
model name alone; model name combined with the action (`InstallApp`, `apName`), the service
(scheme `AppSystem`), the transport (SOAP), the handler (`net-cgi`) and the session mechanism; the
parameter name (`NewAppName`); and the sibling model. The totals: the model name matches seventy public
records. Their families are stored cross-site scripting (the overwhelming majority, a long
multi-model advisory block), five command-injection records (three authenticated, two unauthenticated),
one server-side injection record, three buffer-overflow records, a TLS certificate private-key
disclosure, a missing-SSL-validation record and a missing-function-level-access-control record. None of
them names the app-installation action, its parameter, its service, its validator or its handler; multi-axis
keyword searches combining the model names with those feature terms return zero records. And the five
command-injection records that do name this model were all fixed in firmware generations at or below
1.2.3.28 - older than the V1.2.5.18 analyzed here, in which the app-installation sink is present and
live. For the sibling: the only public record naming the R7800's `net-cgi` handler is a memory-corruption
(out-of-bounds write) issue of a different vulnerability class. The vendor's SOAP interface has public
authentication-bypass and command-execution records on other models of the line; none of those records
names either model analyzed here. The nearest-family public findings are therefore different endpoints,
different sinks, different mechanisms and, for the two matching command-injection families, fixed in
firmware lines that predate the analyzed image. No public record covering this action, this parameter or
this validator exists in the sources available to us, and nothing in this finding is a repackage of one.

### Overview of the cross-platform scope

The same root cause was tier-2-merged into the R7800 (Nighthawk X4S, firmware V1.0.2.68) - a different
SoC generation (Broadcom BCM4709), a different instruction set (32-bit ARM), a different handler binary
(recorded digest beginning c5a9f2b3) and a different validator function. What the two share is the
service stack (the same DNI lighttpd plus net-cgi arrangement), the same handler family for the
app-installation action, the same command construction family, and - decisively - a validator that in the
R7800 case is strictly more permissive (its reject set is only `"`, `'`, `\`). The identical `x$(cmd)`
payload passed the R7800 validator and executed through the handler with three root markers and a clean
control in that platform's own sink-level replication. The merge is argued at the level of root cause, not
of build identity, and the digest and instruction-set differences are stated rather than hidden.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | NETGEAR, United States, consumer networking |
| Product | RAX120 (Nighthawk AX12), WiFi 6 router |
| Version analyzed | firmware V1.2.5.18 |
| Platform | Qualcomm IPQ8074, aarch64, musl libc, stripped |
| Web stack | lighttpd plus `/usr/sbin/net-cgi` (DNI framework), SOAP via `/soap/server_XMLresp.cgi` |
| Handler binary | 1,042,120 bytes, recorded digest beginning d7035dd3 |
| Vulnerable action | `InstallApp` of `urn:NETGEAR-ROUTER:service:AppSystem:1` |
| Parameter | `NewAppName` (application name) |
| Handler function | internal function at fcn.000b32f8 in the stripped image |
| Validator | "apname" mode of the validation routine at fcn.000407d8 (mode string at 0xc3058) |
| Reject set | `@`, backtick, `;`, `"`, `'`, `\` |
| Allowed set (relevant) | `$ ( ) \ | & < > # ~ ! * ?` and whitespace |
| Sinks | 2 x `system()`, 1 x `popen()`, all via `/bin/sh -c` |
| Breakout | `x$(cmd)` - command substitution, no separator needed |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)` markers, sink-level replication |
| Session gate | administrator SOAP session, MAC-bound, fails closed |
| Primary CWE | CWE-78 |
| Co-equal CWE | CWE-20 |
| Published score | 6.8 Medium - `CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

The handler's control flow, recovered from the disassembly of the stripped aarch64 image, reads as
follows:

```c
void installapp_handler(session, request) {
    name = soap_get_arg(970000, request);        /* NewAppName   */
    update = soap_get_arg(0xed0f0, request);     /* NewUpdate    */

    if (strlen(name) - 1 >= 0x100) return;      /* 255-char cap  */
    if (!is_valid_0_1(update)) return;          /* "0" or "1"   */
    if (!fcn_000407d8(0xc3058, name)) return;   /* "apname" gate */

    snprintf(tmp_path, sizeof(tmp_path), "/tmp/%s_tmp", name);
    snprintf(sw_path,  sizeof(sw_path),  "/sw-apps/%s", name);

    /* all three sinks below interpolate name unquoted */
    snprintf(buf, 0x200, "rm -rf %s/version.txt > /dev/console", sw_path);
    normalize_and_dispatch(buf);                     /* system() */
    snprintf(buf, 0x200, "rm -rf %s > /dev/console", sw_path);
    normalize_and_dispatch(buf);                     /* system() */
    snprintf(buf, 0x200, "rm -rf %s;mkdir %s;tar -zxf /tmp/%s -C %s",
             tmp_path, tmp_path, tarball, tmp_path);
    popen(normalize(buf), "r");                      /* /bin/sh -c */
}
```

Three of its decisions carry the whole finding:

1. The validator rejects the semicolon and the backtick - the two characters that would let a single
   argument break out of its word and start a new statement - but passes the dollar sign and both
   parentheses.
2. The handler builds two working paths by direct string interpolation of the validated name, then
   builds three shell command lines by a second interpolation of those paths, and executes them through
   library calls that invoke `/bin/sh -c`.
3. An intermediate string processor (the routine recorded at fcn.00079060) normalizes carriage returns
   and line feeds to spaces and performs no other transformation, so nothing between the validator and
   the shell strips or escapes `$`.

The chain is therefore four steps long and needs no special conditions: send an authenticated SOAP
request whose app name is `x$(cmd)` - with `cmd` avoiding only the six blocked characters - and the
shell that the handler itself invokes executes `cmd` before it attempts the `rm`.

### Vulnerability Summary preconditions

1. The attacker holds the router administrator's credential - the legitimate administrative session the
   action was designed for. This is the whole privilege story: there is no bypass, no session forgery
   and no credential leak in this chain.
2. The attacker's station is on the network the device's management plane serves - the adjacent, local
   network of a consumer router in an unmodified deployment.
3. Nothing else. No default credential is needed (a changed administrator password does not narrow this
   finding by one character), no memory groom, no reboot window, no specific client software.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The `InstallApp` action belongs to the administrative SOAP control plane, dispatched at
`/soap/server_XMLresp.cgi`. The research record identifies its gate as the administrative SOAP login
bound to the requesting station's MAC address - the session mechanism the record names
`soap_login_mac` - and describes the MAC comparison as failing closed. Two consequences follow. First, the finding is a
post-authentication finding by construction: the request reaches the handler only with a legitimate
administrator session behind it. Second, there is no second web-account tier on this control plane in
any artifact examined: the administrator is the web plane's only named principal, and no guest, user
or viewer class with SOAP reach was found or recorded. That absence is what fixes the CVSS
privilege metric at High, which section 2 of the summary argues from arithmetic rather than from
convention.

### Authentication Boundary - what the chain does not do

- It does not bypass authentication. The session gate is consumed, not defeated.
- It does not depend on default credentials in any way. The same request succeeds whatever the
  administrator's password is; the earlier coarse habit of filing this vendor's findings under a
  default-credential family is contradicted by the evidence axis here, and this advisory states the
  correction.
- It does not involve the session's MAC binding as an obstacle. The MAC binding defends against a
  cross-station request replay; the attacker here is the credential holder on the station the session
  already belongs to, so the binding is part of the normal control flow the attack rides.
- It does not attack SOAP parsing, XML entity handling or transport security; the request is a
  well-formed, schema-conformant instance document.

### Authentication Boundary - why that boundary does not soften the impact

An administrator of a consumer router can already change settings, so it is fair to ask what the
injection adds. The answer is the difference between the product's intended administrative surface and
the operating system underneath it: the vendor's management plane - web forms and SOAP actions alike -
exposes a defined and finite set of operations, none of which is "arbitrary shell". The chain crosses
that boundary and returns with the full authority of the root-configured web stack: configuration
secrecy, filesystem access and process control beyond what any legitimate management action offers. A
well-run deployment assumes the administrator of the settings is not, by that fact alone, root on the
operating system; this finding is exactly the collapse of that assumption.

## 4. Attack Surface

### Attack Surface - the web stack and its dispatch model

The DNI generation replaces the older httpd entirely: lighttpd terminates HTTP/HTTPS and hands SOAP
requests to `/usr/sbin/net-cgi`, a single large handler binary that interprets the action element of the
SOAP instance document and dispatches to internal functions. In the analyzed image, that binary is
1,042,120 bytes, stripped, aarch64, musl, with its recorded image digest beginning d7035dd3. The
`InstallApp` action is one entry in the app-system service family, whose service identifier is
`urn:NETGEAR-ROUTER:service:AppSystem:1`; the transport request is an HTTP POST of an XML document to
`/soap/server_XMLresp.cgi` carrying the SOAP action header
`urn:NETGEAR-ROUTER:service:AppSystem:1#InstallApp`.

### Attack Surface - why the surface audit narrowed here

The framework's exec style meant the audit could not simply grep for dangerous-looking calls; it had to
classify all of them. The full sweep of the handler binary went as follows:

- `dni_system` helper at fcn.000779f0: `vfork()` plus `execve()`, argument-array, no shell in the path.
  Architecturally safe from metacharacter injection for every caller that uses it correctly.
- Direct `system()` sites (on the order of 150+ across the binary, clustered in two large service
  functions): fixed string literals loaded from constant pools by address-arithmetic - command strings
  the attacker cannot influence by any request. No `%s` interpolation anywhere in this family.
- `popen()` sites (about 54 in the binary): the last large shell-mediated family, each requiring a
  source analysis. One of them - a wireless diagnostics construction that interpolates a MAC address -
  was checked and found guarded by an upstream MAC-format validator that blocks the shell-relevant
  characters for that field.
- The one `system()`/`popen()` family that interpolates an attacker-controlled SOAP argument: the
  app-installation handler of this advisory.

This classification is what the independence argument rests on: within this stack, the app-installation
handler is not an instance of a widespread sloppy pattern; it is the single SOAP-argument-driven shell
construction in the analyzed image.

### Attack Surface - components that narrowed out

- The `dni_ping` shell script uses unquoted `$var` expansions, but every variable in it is sourced from
  controlled forms rather than from request content, and it is not reachable with attacker text in this
  chain.
- Stored cross-site scripting surfaces exist in this product family's public history and are real
  findings of other kinds; they are not part of this chain, which needs no victim browser and no user
  interaction.
- Firmware-update, factory-reset and diagnostic SOAP actions answer to the same administrator session
  but construct their command lines from fixed literals in the analyzed image, per the sweep above.

## 5. Sink Identification

### Sink Identification - the three constructions

The handler interpolates the validated name into two working paths and then into three command lines.
Reconstructed from the disassembly, the constructions are:

```c
/* path construction */
snprintf(tmp_path, size, "/tmp/%s_tmp", name);
snprintf(sw_path,  size, "/sw-apps/%s",  name);

/* sink 1 - via system(), i.e. /bin/sh -c */
snprintf(buf, 0x200, "rm -rf %s/version.txt > /dev/console", sw_path);
dispatch(buf);

/* sink 2 - via system(), i.e. /bin/sh -c */
snprintf(buf, 0x200, "rm -rf %s > /dev/console", sw_path);
dispatch(buf);

/* sink 3 - via popen(), i.e. /bin/sh -c */
snprintf(buf, 0x200, "rm -rf %s;mkdir %s;tar -zxf /tmp/%s -C %s",
         tmp_path, tmp_path, tarball, tmp_path);
popen(normalize(buf), "r");
```

Two properties make these reliable sinks rather than merely untidy code. Each embeds the name unquoted,
so the shell's word-splitting and substitution logic apply to it in full; and each is executed through
`/bin/sh -c`, the library-level interface that guarantees a shell parser between the handler and the
kernel. The command-substitution breakout does not care which of the three fires first or whether the
surrounding `rm` succeeds or fails: the `sh` parser performs the substitution pass over the whole
command line before executing any word of it, so the injected command runs even where the surrounding
operation errors out.

### Sink Identification - the string processor is not a control

A reader might hope that the recorded post-construction string processor (fcn.00079060) neutralizes
something. It does not: the routine walks the command string and rewrites carriage returns and line
feeds to spaces, copying everything else verbatim into a working buffer. Its purpose is line-oriented
hygiene for the console device the commands redirect to, not input sanitization; it leaves `$`, `|`,
`&`, `<`, `>` and every other metacharacter untouched. It is quoted here precisely so that no
downstream mitigation is credited that does not exist.

### Sink Identification - execution identity

`system()` and `popen()` children inherit the identity of the web stack that calls them. The research
record identifies, from the firmware image's own lighttpd configuration, the server's configured
runtime user as root - the DNI stack in this image runs its CGI handlers with device-root authority.
That is why the substituted command lands as root rather than as a confined service identity, and it
is why the advisory title carries the root claim with the replication evidence stated alongside it.

## 6. Source Identification

### Source Identification - the parameter and its gates

The source is the `NewAppName` element of the `InstallApp` instance document. Its extraction runs behind
two gates before the validator ever sees the value, both recovered from the handler disassembly: a
length cap (`strlen(name) - 1 >= 0x100` rejects, bounding the value at 255 characters) and a value gate
on the companion `NewUpdate` element, which must be exactly `0` or `1`. Neither gate filtering on
character classes, both gates are compatible with the payload - the working payload in this advisory is
well under 30 characters.

### Source Identification - the validator, character by character

The "apname" mode of the validation routine (recovered at fcn.000407d8, selected by the mode string at
0xc3058) is a reject-list loop. Its decisions, with the disassembled conditions:

| Byte | Disposition | Condition in the routine |
|---|---|---|
| 0x40 `@` | reject | uppercase-fold comparison equals 0x40 |
| 0x60 backtick | reject | same fold catches 0x60 with it |
| 0x3b `;` | reject | direct comparison |
| 0x22 `"` | reject | comparison window |
| 0x27 `'` | reject | direct comparison |
| 0x5c `\` | reject | direct comparison |
| 0x24 `$` | allow | no matching condition |
| 0x28 `(` | allow | no matching condition |
| 0x29 `)` | allow | no matching condition |
| `\|`, `&`, `<`, `>`, `#`, `~`, `!`, `*`, `?`, space, newline | allow | no matching condition |

The design intent is legible in the table: someone enumerated shell-injection characters and built the
rejection list from them. The list is simply incomplete, and the characters missing from it - the
dollar sign and both parentheses - are the entire grammar of command substitution. The validator
implements CWE-20 in its least defensive form, and the sink converts that validation gap into CWE-78.

### Source Identification - what the payload must respect

Because the reject list is fixed and narrow, the injected command body has almost full freedom: it must
merely avoid the six blocked bytes, and for the marker writes used in this research that constraint
costs nothing. A payload author works around the `$`-ban's absence, not around anything present: no
quoting tricks, no separator smuggling, no double-encoding - the substitution container does not need
any of them.

## 7. Data Flow

### Data Flow - end to end

```
[ADMINISTRATOR SIDE]                        [ROUTER, DNI web stack]
admin session (login, station MAC bound)
        |
        |  HTTP POST /soap/server_XMLresp.cgi
        |  SOAPAction: ...AppSystem:1#InstallApp
        |  body: NewAppName = x$(cmd), NewUpdate = 0
        v
        lighttpd -> /usr/sbin/net-cgi -> InstallApp handler (fcn.000b32f8)
        arg extraction: NewAppName (id 970000), NewUpdate (id 0xed0f0)
        length gate: strlen(x$(cmd)) - 1 < 0x100           [pass]
        value gate: NewUpdate in {"0","1"}                 [pass]
        validator: fcn.000407d8("apname", x$(cmd))         [pass - $ ( ) not in reject set]
        |
        snprintf: tmp_path = /tmp/x$(cmd)_tmp
        snprintf: sw_path  = /sw-apps/x$(cmd)
        |
        snprintf -> "rm -rf /sw-apps/x$(cmd)/version.txt > /dev/console"
        fcn.00079060: CRLF -> space, everything else verbatim
        system(...) -> /bin/sh -c "rm -rf /sw-apps/x$(cmd)/version.txt ..."
                        |
                        sh parse: $( ) found -> subshell executes cmd
                        substitution result re-embedded
                        rm -rf proceeds on the re-parsed line
        (same mechanics at the two remaining constructions,
         system() and popen(), in the same handler)
```

### Data Flow - properties worth naming

- The taint never crosses a memory-safety boundary: it is plain string data carried argument-to-buffer,
  buffer-to-command, command-to-shell. There is no overflow anywhere in this chain, and none is needed.
- The decisive re-parse is performed by the component the handler itself invokes, not by any attacker
  machinery: `/bin/sh -c` is the product's own choice of execution interface for all three sinks.
- The three sinks give a free redundancy property to the exploit: an operator patch that silenced any
  one construction would leave the other two live unless the interpolation itself is removed (which is
  what the fix section recommends).
- Nothing in the chain depends on validator-parsing quirks of trailing bytes, valid SOAP envelope
  subtleties or HTTP-layer oddities; the instance document is ordinary.

## 8. Exploit Construction

The PoC shipped with this advisory is
`exploit/netgear_installapp_apname_command_injection_poc.py`. It is a single-request client: standard
library only, HTTPS with certificate verification disabled for lab devices, argparse for the target
address, port, administrator password and command, with a pre-flight check that refuses to send any
command containing the six characters the validator rejects (so mistyped payloads fail loudly on the
operator's own machine instead of silently being dropped at the gate).

### Exploit Construction - request shape

```http
POST /soap/server_XMLresp.cgi HTTP/1.1
Authorization: Basic <admin credentials>
Content-Type: text/xml; charset=UTF-8
SOAPAction: urn:NETGEAR-ROUTER:service:AppSystem:1#InstallApp

<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
 <SOAP-ENV:Body>
  <M1:InstallApp xmlns:M1="urn:NETGEAR-ROUTER:service:AppSystem:1">
   <NewAppName>x$(id>/tmp/marker)</NewAppName>
   <NewUpdate>0</NewUpdate>
  </M1:InstallApp>
 </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

### Exploit Construction - payload engineering

The payload is a single substitution container with a leading ordinary-character word:

```
x$(cmd)
```

The leading `x` exists so that the enclosing `rm -rf /sw-apps/<name>/...` construction has a well-formed
word to operate on after substitution - the shell exits the substitution, re-embeds its output and
proceeds to the `rm` regardless, but a clean word shape keeps the request indistinguishable from an
ordinary app-management operation in any product-side logging. The `cmd` body must avoid `@`, backtick,
`;`, `"`, `'` and `\`, which in practice excludes almost nothing an attacker needs - the marker command
used throughout this research (`id>/tmp/marker`) uses none of them. For arbitrary command text longer
than the cap, the 255-character bound on the application name is the only constraint, and even it can
be dispatched around by short payload that writes a longer second-stage file by redirection from an
attached reply stream - a standard embedded-device idiom, stated here for completeness rather than
shipped in the PoC.

### Exploit Construction - what the PoC deliberately does not do

- It does not brute-force, guess or collect credentials; the administrator password is a supplied
  argument.
- It performs one request and reports the raw HTTP and SOAP response bytes; it does not interpret
  device-side state, does not install persistence, does not open interactive channels.
- Its default command is a non-destructive identity capture written to `/tmp` on the target; the
  operator overrides it explicitly for authorized testing.
- It keeps a lab-rail: the intended use is an operator's own equipment, and the pre-flight character
  gate makes accidental destructive payloads less likely rather than more.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Verification method | sink-level replication on an isolated cloud-hosted sandbox, native gcc |
| Replicated elements | the "apname" validator's reject logic (from disassembly of fcn.000407d8), the CRLF-normalizing string processor, and all three command constructions of the InstallApp handler |
| Not performed | any live SOAP request against device hardware; no physical RAX120 or R7800 unit was driven, reimplemented as firmware, or emulated |
| Privilege model of the harness | executed as root deliberately, mirroring the root web-stack user that the firmware image's lighttpd configuration records |
| Observation channel | marker files created by the substituted command, read from the harness filesystem |
| Control | a benign application name passing the same validator and the same construction path |

### Dynamic Verification - vectors and results

Three vectors were replicated in the main model's harness, one per sink, each carrying the payload
`x$(id>/tmp/<marker>)` through the replicated validator and construction:

```
VECTOR 1: system returned 0        -> marker 1: uid=0(root) gid=0(root) groups=0(root)
VECTOR 2: system returned 0        -> marker 2: uid=0(root) gid=0(root) groups=0(root)
VECTOR 3: pclose returned 512      -> marker 3: uid=0(root) gid=0(root) groups=0(root)
CONTROL: system returned 0     -> control marker: NOT FOUND
```

The `pclose` value on the third vector is the `tar` child failing on an absent tarball; it is
irrelevant to the substitution, which had already executed - the marker proves it. The control run is
the load-bearing negative: an ordinary name traversing the identical code path created no marker, so
the marker creation is attributable to the substitution content alone and not to the surrounding
construction.

The identity in every marker - `uid=0(root) gid=0(root) groups=0(root)` - is the measured replication
result under the harness privilege model described above; the mapping to device behavior rests on the
firmware image's lighttpd configuration naming root as its server user, read as a product artifact,
not on a live-device observation. The summary and the disclosure status both keep that boundary
labeled.

### Dynamic Verification - the R7800 tier-2 replication

The sibling model's replication reproduced the same construction family with the R7800's own recorded
validator (reject set `"`, `'`, `\` only - three characters more permissive than the main model's six)
and its recorded `rm -rf`/`mkdir`/`tar` constructions. The identical payload
`x$(id>/tmp/<marker>)` passed that validator, and the run produced the same result set: three markers,
each `uid=0(root) gid=0(root) groups=0(root)`, and a clean control. Combined with the
digest-and-instruction-set differences stated in section 1, this is exactly what supports a same
root cause, both models statement in the affected list - and nothing stronger.

### Dynamic Verification - negatives, stated

- No end-to-end HTTP-round-trip verification against device hardware was performed for either model;
  the request-side claims (dispatch path, session gate, argument extraction, validator location) are
  disassembly-level.
- No cross-station, cross-network detonation exists in the record; the reachability reading in
  section 10 follows that boundary.
- No persistence, no radio-firmware or hardware-adjacent effects, and no memory-corruption behavior
  were tested or claimed.
- Firmware versions other than V1.2.5.18 (main model) and V1.0.2.68 (sibling) were not analyzed, and no
  other model line was surveyed for this handler family.

## 10. Reachability and Security Impact

### Reachability - network position

The `InstallApp` action answers through the SOAP responder of a consumer router's management plane. In
an unmodified deployment that plane serves the device's local network; none of the shipped artifacts
examined here shows the action answering on a wide-area interface. The published vector therefore
assumes an adjacent-network attacker - a station on the LAN or the management network, which for this
product class includes every wireless client the router itself admits - and the conditional network
reading (7.2) is reserved for deployments that deliberately expose the management plane: enabled
remote administration, a port forward aimed at the SOAP responder, or a management relay. Those shapes
are argued, labelled conditional, and were not measured.

The credential requirement would seem to make reachability moot, but it defines the affected population
precisely: every legitimate holder of the administrator credential (owner, delegated household or
office administrator, managed-service operator) on any station admitted to the management plane, plus
any party who has already obtained that credential by other means - for whom this finding converts web
console access into operating-system shell without a further step.

### Reachability - impact in concrete terms

Command execution as the root-configured web stack means: the complete configuration store, including
credentials retained by the firmware; creation or modification of accounts, startup scripts and
scheduled tasks within the writable filesystem; reconfiguration of interfaces, routes and the DNS
resolver the LAN depends on; and the ability to degrade service at will or destroy filesystem state
through the very `rm -rf` constructions this chain lives in. The finding changes the trust meaning of
the administrator credential from operator of a settings interface to de facto operating-system
administrator on the network's chokepoint device, which is a material escalation of what a
compromised web password alone previously purchased.

## 11. Fix Recommendations

1. Allowlist the application name: `[A-Za-z0-9][A-Za-z0-9._-]*`, existing length cap, hard reject
   otherwise. Both existing blocklist variants are known-insufficient, so validating by set membership
   rather than by absence of bad characters is the only durable form of this control.
2. Remove the shell from the app-installation path entirely: `unlink()` for the version file,
   `mkdir()` with a mode argument for the staging directory, argument-array `execve()`-family calls for
   extraction - or the framework's own existing exec helper. This closes the class for every caller
   pattern in this handler, present and future, instead of enumerating today's metacharacters.
3. If a shell-based implementation must survive one release cycle: single-quote every interpolated
   value with literal single-quote escaping, plus a post-construction assertion in the handler that the
   final command string contains no `$` byte; fail the request on assertion.
4. Split web-stack privilege: run lighttpd and its CGI handlers as a dedicated non-root identity and
   grant only the app-installation path's directories. Not a fix for the injection, but a cap on the
   blast radius of this class of defect platform-wide.
5. Remediate the sibling model line with the same patch set: the R7800's validator is strictly more
   permissive, so a main-model-only patch leaves a trivially reachable sibling, and a single
   cross-model regression test (submit `$(true)` as an app name; assert no shell-out) protects both.
6. Fold the app-installation constructions into the platform's release test suite as a
   category, not a case: any newly added `system()`/`popen()` site that interpolates request data fails
   the build. The sweep behind this advisory enumerated on the order of 54 `popen()` sites in one
   binary; keeping the whole category honest requires a build-time rule, not a per-bug review.
7. For operators, until a patch ships: keep the management plane local, disable remote administration
   and unused app features, rotate the administrator credential on any device whose management network
   admits untrusted stations, and treat a suspicious app-install request in device logs as an
   arbitrary-code-execution indicator rather than a management-action anomaly.

## 12. CWE

### CWE - classification rationale

- CWE-78 (Improper Neutralization of Special Elements used in an OS Command, OS command injection) is
  the primary class: the attacker-supplied value reaches a shell command line created by
  string interpolation, and shell parsing turns part of the value into executed command text. Every
  element of the chain - the unquoted interpolation into `rm -rf` constructions, the `system()`/
  `popen()` execution interfaces, the metacharacter-class breakout - is exactly this class.
- CWE-20 (Improper Input Validation) is co-equal here rather than contributing: the entire defense on
  this path was a reject-list validator, and the finding is precisely that reject-list validation of
  string arguments intended for shell contexts fails by construction - the reject set enumerated
  yesterday's injection characters while the language of the executing parser contains a substitute
  container the list never modeled.
- CWE-426 (Untrusted Search Element) and CWE-88 (Argument Injection) were both considered and not
  applied: the handler does not resolve executables through the supplied value, and the value is
  interpolated into the command string, not appended as an argument word.
- The authentication posture of the action also makes CWE-284 (Improper Access Control) a candidate
  reading; it is rejected: the action's authorization is what it claims to be (administrator-only),
  and the defect is not who may call it but what the call does with its parameter.

---
Written by the 0day Rubbish Research Team.
