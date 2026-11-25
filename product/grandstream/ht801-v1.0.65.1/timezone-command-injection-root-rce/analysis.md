# Grandstream HT801 SIP ATA v1.0.65.1 - time-zone setting command injection in gs_cpe's echo construction

## 1. Overview

### Overview - the finding in one paragraph

A Grandstream HT-series analog telephone adapter accepts a time-zone string from its administrator and
persists it by assembling a shell command, `echo "<value>">/<config path>`, in a stack buffer bounded at 0x100 bytes
and passing it to `system()`. The value is not escaped, not screened and not length-checked. A time-zone
string that contains a double quote closes the `echo` operand, a semicolon opens a second command, and a
`#` comments out the vendor's own redirect, so the administrator's setting is executed by `/bin/sh -c` as
the daemon's identity - which the research record states is device root. The handler is
`set_selfdefinedtimezone_value` at 0x289f8 in `app/bin/gs_cpe`, the TR-069 CPE management daemon of the
HT-series firmware, and the format string is `echo "%s">%s` at rodata 0x655a1. This advisory documents the
sink, the source, the data flow, the working payload, the verification the research record actually
performs and its exact boundary.

### Overview - product, firmware and binary

The affected product family is Grandstream's HT line of SIP analog telephone adapters: the HT801
(single-port), the HT802 (two-port), the HT818 (eight-port FXS) and the earlier HT701, which shares the
same codebase. The version analyzed end to end for this advisory is v1.0.65.1, the firmware string
recorded for the HT801 and the HT818; the binary analysis itself was performed on a pre-extracted rootfs
image of HT802 v1.0.10.6, which the record uses as the binary-analysis proxy for the shared `gs_cpe`
codebase, and the same handler is present there.

`app/bin/gs_cpe` is a 32-bit ARM ELF, dynamically linked against uClibc and stripped. Its role is the
TR-069 CPE management daemon: it answers `SetParameterValues` from an auto-configuration server and it
applies the configuration changes an administrator makes locally on the device's webadmin pages. The
record counts three `system()` imports and one `popen()` in the binary, and the `system()` import at PLT
0x34014 is referenced from 0x288e0, 0x289f8 and 0x355c0. That import list is the whole shell-mediated
surface of the daemon in this build, which is what makes the enumeration in section 5 tractable: there is
no large family of dynamically constructed command lines to sift, only a small number of sites.

### Overview - what the two input paths have in common

The daemon has two ways to receive a parameter value, and the record names both as feeders of this sink.
The first is the local webadmin interface: an administrator opens the Time Zone setting page and saves a
value, and the daemon applies it. The second is TR-069: an auto-configuration server sends
`SetParameterValues`, and the daemon applies it through the same handler. The two paths differ in
transport and in who initiates them; they converge on `set_selfdefinedtimezone_value`, which is why the
defect is a property of the handler rather than of one front end. It is also why the published CVSS
vector reads Network rather than Adjacent: the TR-069 exchange is a server-to-device conversation across
the routed network by design, so the sink is not confined to a directly attached segment.

### Overview - the verification boundary, stated first

The dynamic evidence in this package is a sink-level replication, and the record labels it exactly that.
The recorded run reproduces the handler's `snprintf()` construction and its `system()` execution with the
payload `BM"; id > /tmp/gs_cpe_c13; #` and with the benign control `UTC-0800`, and it observes the
resulting root marker inside that replication environment. The record does not document a detonation
against device hardware: no webadmin request fired at a physical HT801 appears in it. Consequently the
request path, the parameter source and the handler location are firmware-analysis claims, while the
execution behaviour at the sink - that this exact construction turns that exact value into a root-owned
command - is a replication claim. Section 9 keeps the two halves apart. Everywhere in this advisory the
root identity carries that qualification; it is an observation from the replication environment, not a
live-device reading.

### Overview - public-record independence

The record's own finding history states that no Grandstream HT801 or HT802 vulnerability on record
matches this sink: public identifiers for the HT line exist for buffer overflows and for IAX handling,
but none for command injection through the time-zone parameter. The record therefore names no CVE for
this finding, and this advisory assigns none - the correct statement is that no identifier has been
assigned. Independence also holds mechanically: a different product from the other findings in this
product tree, a different binary (`gs_cpe` rather than a scripting runtime or an application server), and
a different sink function and command construction. Nothing here is a repackaging of a public record.

## 2. Vulnerability Summary

### Vulnerability Summary - table

| Item | Value established by this research |
|---|---|
| Vendor | Grandstream Networks |
| Product | HT801 single-port SIP ATA (HT701/HT802/HT818 shared codebase) |
| Version analyzed | v1.0.65.1 |
| Binary-analysis image | HT802 v1.0.10.6 pre-extracted rootfs, shared codebase proxy |
| Component | `app/bin/gs_cpe`, ARM 32-bit ELF, uClibc, stripped |
| Role of component | TR-069 CPE management daemon; also applies local webadmin changes |
| Vulnerable function | `set_selfdefinedtimezone_value` at 0x289f8 |
| Format string | `echo "%s">%s` at rodata 0x655a1, loaded via the pointer at 0x28a2c |
| Command buffer bound | 0x100 bytes, stack destination |
| Config path operand | constant at 0x28a28; the recorded trace expands it to `/etc/config_tz` |
| Shell sites in binary | three `system()` imports, one `popen()`; `system()` import at PLT 0x34014 |
| Execution interface | `system()`, i.e. `/bin/sh -c` |
| Source of value | webadmin Time Zone setting page; TR-069 `SetParameterValues` |
| Sanitization | none - no escaping, no character screening, no length rejection |
| Payload | `BM"; id > /tmp/gs_cpe_c13; #` |
| Observed marker | `uid=0(root) gid=0(root) groups=0(root)`, sink-level replication |
| Authentication | administrator session on the webadmin time-zone page |
| Primary CWE | CWE-78 |
| Published score | 7.2 High - `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary - mechanics

The handler's body, reconstructed from the binary analysis, is short enough to read in full:

```c
uint set_selfdefinedtimezone_value(void *s, uint32_t arg2, uint noname_2, int32_t arg3)
{
    arg1_00 = *(arg1 * 0x28 + ***0x28a24 + 0x24);      /* nvram key for this parameter */
    if (arg1_00 != NULL && arg3 != NULL) {              /* arg3 = timezone string value  */
        nvram_set_data(arg1_00, arg3);                  /* persist to NVRAM              */
        snprintf(acStack_110, 0x100, *0x28a2c, arg3, *0x28a28);
                                                        /* "echo \"%s\">%s"              */
        system(acStack_110);                            /* shell executes the line       */
        cpe_check_parameter_need_reboot(arg1);
        return 0;
    }
}
```

Four properties of this body carry the finding.

First, the only conditions on the value are non-nullness: `arg1_00 != NULL` checks that the NVRAM key
was resolved, and `arg3 != NULL` checks that a value was supplied at all. Neither condition looks at the
value's content, and no test anywhere between the parameter extraction and `system()` looks at its
content either.

Second, the value is interpolated into a double-quoted operand inside a format string that also appends a
redirection. The shell will therefore treat the bytes of the value as shell source between the opening
quote of `echo "` and the closing quote the format string supplies - unless the value closes that quote
first, which is precisely what a double quote in the value does.

Third, the copy is bounded (0x100 bytes) but not validated: an over-long value is truncated by
`snprintf()`, which protects the stack and does nothing for the shell. Length is not a control here; the
working payload is 28 bytes.

Fourth, `system()` is the execution interface. It runs the string through `/bin/sh -c`, so the shell
parses the assembled line again, after the daemon has finished treating it as data. The daemon's own
choice of interface is what turns a quoting mistake into command execution.

### Vulnerability Summary - preconditions

1. The attacker holds the device administrator's session - the legitimate credential the time-zone page
   requires. There is no bypass, no forgery and no credential leak in this chain.
2. The attacker can reach the webadmin interface, or can influence the TR-069 `SetParameterValues`
   exchange for the deployment (a rogue or compromised auto-configuration server is the obvious shape of
   the second case, and it is named here because the record names that pipeline as a feeder of the same
   sink).
3. Nothing else: no memory grooming, no reboot window, no race, no specific client software, and no
   dependence on the shipped default credential.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The gate is the webadmin administrator session. The record's authentication verdict is unambiguous: the
time-zone setting page is an administrator page, reached with an administrator login, and the sink is
behind it. The same handler is also reached through the daemon's TR-069 role, where the gate is whatever
trust relationship the deployment has established with its auto-configuration server - a management
channel, not an anonymous one. In both cases the request that reaches `set_selfdefinedtimezone_value` is
an authorized management request, and the finding is post-authentication by construction.

The record also notes that the device ships with `admin/admin` as its default administrative credential.
That fact belongs in the affected-product discussion and in operator guidance, not in the vulnerability
mechanism: this chain does not need the default password, does not test it, and is not narrowed by
changing it.

### Authentication Boundary - what the chain does not do

- It does not bypass authentication. The session is consumed, not defeated.
- It does not depend on default credentials. An administrator who has rotated the password still reaches
  the page and still supplies the value; the payload is indifferent to the credential's value.
- It does not attack session handling, request parsing, transport security or the TR-069 protocol
  encoding. The value is a well-formed parameter in both paths.
- It does not require any second request, any replayed token or any cross-site trick.

### Authentication Boundary - why the boundary does not soften the impact

It is fair to ask what an administrator gains, given that an administrator can already change settings. The
answer is the difference between the product's management surface and the operating system underneath it.
The webadmin interface exposes a finite, enumerated set of operations - set a time zone, set a SIP
account, change a network setting - and none of them is "run this program as root". The chain crosses that
boundary: the settings page becomes a shell with the daemon's authority, which means the configuration
store, the filesystem and the process table rather than a form. A deployment that assumes its administrator
is an operator of a settings page, and not by that fact the operating-system owner of the appliance, has
that assumption broken by this finding. The CVSS privilege metric consequently reads High - the credential
is real and the boundary is real - while the impact metrics read High as well, because what sits behind the
boundary is root.

## 4. Attack Surface

### Attack Surface - the daemon and its shell sites

`gs_cpe` is the single management daemon of the HT-series firmware, and the record's import count - three
`system()` and one `popen()` - bounds the shell-mediated surface. The audit that produced this advisory
classified every reference to the `system()` import at PLT 0x34014, which the record lists as 0x288e0,
0x289f8 and 0x355c0:

- the time-zone handler of this advisory, reached from the local webadmin time-zone page and from TR-069
  `SetParameterValues`; its format string is the interpolating one;
- `cpe_download_end` at 0x355c0/0x35608, whose construction is
  `prov_config_dec /proc/gxp/dev_info/dev_data %s` with a 0x7f size argument followed by `system()`, reached
  only when the download's file type is the vendor configuration file; its second argument is a
  downloaded-config path, and the record explicitly leaves its controllability unproven because the
  dispatcher trace that would connect the RPC's `TargetFileName` to the local save path was not completed;
- `delete_upload_tmp_file` at 0x361ac, whose construction is `rm /tmp/%s` with a 0x3f size argument followed
  by `system()`, where the interpolated name is read from the provisioning lock structure at 0x91bf0
  offset 0x20, resolves to 0x709d0, and is the literal string `config` - hardcoded, not attacker-supplied,
  and therefore refuted.

That leaves the time-zone handler as the one demonstrated attacker-controlled shell construction in this
daemon, and the `cpe_download_end` site as an open question rather than a second finding. Stating the
unproven one is not padding: it tells a reader that the enumeration was complete and where its evidence
stops.

### Attack Surface - the two front ends

On the webadmin side the surface is the Time Zone settings page: an authenticated HTML form whose saved
value the daemon applies. On the TR-069 side the surface is the `SetParameterValues` RPC, which the same
daemon implements for its auto-configuration server. Both front ends are network services - the webadmin
listener directly, the TR-069 exchange across whatever path the deployment provides between the ACS and the
device - and both deliver a free-form string to a handler that neither quotes nor validates it. Nothing in
the chain depends on which front end is used; the CWEs, the payload and the result are identical.

### Attack Surface - what narrowed out

- The `popen()` site faces the same classification problem as the `system()` sites and was examined in the
  same sweep; it is not part of this chain.
- The webadmin interface's other configuration pages are separate handlers with their own storage paths;
  they were not shown to share this construction, and no claim is made about them.
- No memory-corruption primitive is involved anywhere: the buffer is bounded and the copy is bounded, so
  the classic stack-overflow reading of a fixed stack array does not apply here.

## 5. Sink Identification

### Sink Identification - the construction

The sink is one line of C and the shell grammar it invokes:

```c
/* format string at rodata 0x655a1, loaded via the pointer at 0x28a2c */
snprintf(acStack_110, 0x100, "echo \"%s\">%s", arg3, *0x28a28);
system(acStack_110);
```

With `arg3` equal to the benign control and the recorded config path substituted, the assembled line is:

```
echo "UTC-0800">/etc/config_tz
```

With `arg3` equal to the recorded payload, the assembled line is:

```
echo "BM"; id > /tmp/gs_cpe_c13; #">/etc/config_tz
```

The second form is the finding. Three bytes do all the work: the double quote ends the operand the format
string opened, the semicolon terminates the `echo` command and starts a new one, and the `#` begins a
comment that swallows the vendor's closing quote and redirect. The shell executes `echo "BM"` (harmless
and visible only as an ordinary time-zone write attempt), then executes `id > /tmp/gs_cpe_c13` as the
daemon's user, then discards the rest of the line as a comment.

### Sink Identification - why the sink is reliable rather than merely untidy

Three properties make this a dependable sink. The interpolation is unquoted in the shell sense - the
format string's double quotes are literal characters of the command line, not an escaping mechanism - so
the value's own bytes are shell source. The execution interface is `system()`, which guarantees
`/bin/sh -c` between the daemon and the kernel; there is no argument-array path that could bypass the
parser. And
the construction runs unconditionally whenever a value is supplied, before any
`cpe_check_parameter_need_reboot()` bookkeeping, so no later validation stands between the sink and
execution. The injected command runs whether or not the surrounding `echo` succeeds and whether or not the
configuration write completes - in the recorded payload the redirect is commented out entirely, so the
only file written is the attacker's marker.

### Sink Identification - execution identity

`system()` children inherit the calling process's identity, and the record states that `gs_cpe` runs as
root on this platform. That is why the marker reads `uid=0(root) gid=0(root) groups=0(root)` and why the
advisory treats the finding as root command execution rather than as a confined service-identity bug. The
identity is a property of the daemon, not of the payload: any command text placed in this position
inherits it.

### Sink Identification - the other shell sites, and why they are not this finding

The record's enumeration is worth reproducing in full because it closes the question of whether the
time-zone handler is an instance of a widespread pattern or a lone construction. Of the three `system()`
references, one belongs to this handler. `cpe_download_end` builds
`prov_config_dec /proc/gxp/dev_info/dev_data %s` with a 0x7f size argument and executes it, but only for
the vendor configuration file type, and the record marks its path argument's controllability as unproven.
`delete_upload_tmp_file` builds `rm /tmp/%s` with a 0x3f size argument, but the argument resolves through the
provisioning lock at 0x91bf0 plus 0x20 to 0x709d0, which holds the constant `config`; the record refuted
it after checking that the structure slot has no attacker-data writer. Neither is counted, and neither
should be described as a second vulnerability.

## 6. Source Identification

### Source Identification - the parameter and how it arrives

The source is the time-zone value: the string an administrator saves on the webadmin Time Zone settings
page, or the string an auto-configuration server supplies for the corresponding TR-069 parameter. It
reaches `set_selfdefinedtimezone_value` as the fourth argument, `arg3`, and the handler resolves the
parameter's NVRAM key from the per-parameter table first -
`*(arg1 * 0x28 + ***0x28a24 + 0x24)` in the record's rendering - then writes the raw value into NVRAM with
`nvram_set_data()` before it builds the command. Note the ordering: the value is persisted before it is
executed, so even a failed injection leaves the attacker's bytes in the configuration store until the
parameter is rewritten.

### Source Identification - the gates, such as they are

There are two conditions on the value and neither is a validation gate:

- the NVRAM key must resolve (`arg1_00 != NULL`), which is a property of the parameter table, not of the
  value;
- the value must be present (`arg3 != NULL`), which rejects an absent parameter and nothing else.

There is no character class check, no length rejection, no escaping and no comparison against the list of
time zones the web interface offers. The only bound on the value is `snprintf()`'s 0x100-byte size argument,
which truncates rather than rejects: a value longer than the buffer is silently cut, and a value that fits,
such as the recorded payload at 28 bytes, passes through unchanged.

### Source Identification - what the payload must respect

Almost nothing. The three characters that make the breakout work - `"`, `;`, `#` - are all permitted by
every layer between the form field and the shell, because there is no layer. The only practical constraints
are the 0x100-byte bound and the need for the assembled line to remain syntactically valid shell up to the
point of the injected command, which the recorded payload achieves with a leading `BM` that reads as a
plausible time-zone label. That choice is cosmetic in effect and deliberate in intent: it keeps the stored
value looking like an ordinary setting to anyone reading the configuration afterwards.

## 7. Data Flow

### Data Flow - end to end

```
[ADMINISTRATOR SIDE]                      [DEVICE: gs_cpe, root]
webadmin Time Zone page  ──┐
                           ├─► set_selfdefinedtimezone_value(arg3)
TR-069 SetParameterValues ─┘        (0x289f8)
                                     |
                                     | nvram key = *(arg1*0x28 + ***0x28a24 + 0x24)
                                     | nvram_set_data(key, arg3)          [value persisted]
                                     |
                                     | snprintf(acStack_110, 0x100,
                                     |          "echo \"%s\">%s", arg3, *0x28a28)
                                     v
                     echo "BM"; id > /tmp/gs_cpe_c13; #">/etc/config_tz
                                     |
                                     | system() -> /bin/sh -c
                                     v
                     sh parse: echo "BM"      [command 1]
                               id > /tmp/gs_cpe_c13   [command 2]
                               #">/etc/config_tz      [comment]
                                     |
                                     v
                     /tmp/gs_cpe_c13 contains uid=0(root) gid=0(root) groups=0(root)
```

### Data Flow - properties worth naming

- The taint is plain string data the whole way: parameter to argument, argument to format string, format
  string to buffer, buffer to shell. There is no memory-safety boundary crossed anywhere in this chain.
- The decisive re-parse is performed by the product's own execution interface. `/bin/sh -c` is what
  `system()` does; the daemon asked for shell semantics and got them.
- The value is written to NVRAM before it is executed, so the injection has a persistent artifact even if
  the command's own output is discarded - a property that matters for both detection and clean-up.
- The `#` in the payload suppresses the intended redirect, so the configuration file named at 0x28a28 is
  not overwritten by the attack. That is a side effect of the payload's shape, not a safety property of the
  handler, and a payload without it would overwrite the file with attacker-chosen text.
- Nothing in the chain depends on encoding tricks, truncation behaviour or a particular byte order; the
  instance is ordinary text in an ordinary form field.

## 8. Exploit Construction

The PoC shipped with this advisory is `exploit/grandstream_ht801_timezone_poc.py`. It is a standard-library
client: `argparse` for the target, port, credentials, request path and marker path; one HTTP request
carrying the time-zone value; a dry-run mode that prints the assembled payload without sending anything;
and a pre-flight check that refuses a marker command containing a byte the construction cannot carry.

### Exploit Construction - payload anatomy

```
BM"; id > /tmp/gs_cpe_c13; #
```

- `BM` - an ordinary leading token, so the stored value still reads like a time-zone label.
- `"` - closes the double-quoted operand that the format string opened.
- `;` - statement separator: the `echo` ends here and a new command begins.
- `id > /tmp/gs_cpe_c13` - the injected command, writing its output to a file because the HTTP response
  carries no command output.
- `#` - comment: it swallows the vendor's closing quote and its `>/etc/config_tz` redirect.

### Exploit Construction - request shape

The recorded exploit submits the value as a form-encoded field to the daemon's configuration endpoint,
authenticated with HTTP Basic credentials:

```http
POST /cgi-bin/update HTTP/1.1
Host: 192.0.2.10:80
Authorization: Basic <base64 of admin:password>
Content-Type: application/x-www-form-urlencoded
User-Agent: Grandstream-HT801-PoC/1.0

page=ts&tz=BM%22%3B+id+%3E+%2Ftmp%2Fgs_cpe_c13%3B+%23
```

The record is explicit that the endpoint and the field names are model-dependent - the recorded script
carries them as a "typical endpoint" comment and exposes them as options - so the PoC treats the path, the
page selector and the field name as parameters rather than as constants of the vulnerability. The
vulnerability is the handler's construction, not the spelling of the form.

### Exploit Construction - what the PoC deliberately does not do

- It does not guess, brute-force or harvest credentials; the administrator password is a supplied argument.
- It sends one request and prints the status line and a bounded prefix of the response body; it does not
  interpret device state, install persistence or open an interactive channel.
- Its default command writes one identity marker file under `/tmp` on the target. There is no `rm`, no
  reboot, no configuration overwrite and no second stage.
- It does not attempt to read back the marker itself; the operator retrieves it over an authorized channel.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, exactly as recorded

| Element | Value recorded |
|---|---|
| Method | sink-level replication of the handler's construction and execution |
| Injection vector | time-zone value `BM"; id > /tmp/gs_cpe_c13; #` |
| Control vector | time-zone value `UTC-0800` |
| Replicated elements | the `snprintf()` into the stack buffer with a 0x100 bound and the format string `echo "%s">%s`, and the `system()` execution of the result |
| Observation channel | a marker file created by the injected command and read back from the replication environment |
| Privilege model | the replication runs the daemon's role as the recorded root identity, so the marker reports `uid=0(root)` |
| Not performed | any request against device hardware; no physical HT801 was driven and no firmware emulation is recorded |

### Dynamic Verification - vectors and results

```
INJECTION  value : BM"; id > /tmp/gs_cpe_c13; #
           line  : echo "BM"; id > /tmp/gs_cpe_c13; #">/etc/config_tz
           marker: uid=0(root) gid=0(root) groups=0(root)          [FOUND]

CONTROL    value : UTC-0800
           line  : echo "UTC-0800">/etc/config_tz
           marker: none                                            [NOT FOUND]
           note  : configuration file written correctly
```

The control run is the load-bearing negative. The same construction, the same buffer, the same
`system()` call and the same config path produced no marker when the value was an ordinary time-zone
string, and produced a correctly written configuration file. The only difference between the two runs is
the value's content, so the marker is attributable to the injected text and not to the surrounding `echo`
or to some incidental behaviour of the replication harness.

### Dynamic Verification - what this does and does not establish

Established by the replication: that this exact format string, this exact buffer size and this exact
`system()` call turn that exact value into a command executing with the daemon's identity, and that a
benign value of the same parameter does not. Established by the firmware analysis: that the handler
exists in `gs_cpe`, that it is reached from the time-zone parameter on both recorded paths, and that the
format string and the config path constant are where the record places them. Not established anywhere in
this package: that the same bytes sent to a physical device over the webadmin form produce the same
marker. That last step is inference from the two halves, and it is labelled as such wherever this advisory
touches it.

### Dynamic Verification - negatives, stated

- No end-to-end HTTP round trip against device hardware is recorded, for any of the four versions named in
  the affected list.
- No cross-network or cross-tenant detonation is recorded; section 10's reachability reading stays inside
  that boundary.
- No persistence test, no factory-reset test, no reflash test and no memory-corruption test was performed.
- The `cpe_download_end` site was left unproven rather than tested; its controllability remains an open
  question in this record, and it is not counted as a finding.

## 10. Reachability and Security Impact

### Reachability - network position

The time-zone handler answers on the device's management surface. In the webadmin path, that surface is the
local administrative interface of a customer-premises adapter: reachable from the network the device
serves and, in a deployment that exposes it, from further away. In the TR-069 path, the surface is the
management channel between the device and its auto-configuration server, which is by design a
server-to-device exchange over the routed network. The published vector therefore reads Network, and the
adjacent-only reading appears in the summary as a rejected alternative with its own arithmetic. The
affected population is defined by the credential requirement rather than narrowed by it: every legitimate
holder of the administrator credential on any station admitted to the management interface, every operator
of the auto-configuration server that provisions the device, and any party who has obtained the credential
by other means - for whom this finding converts a settings-page login into an operating-system shell on
the gateway.

### Reachability - impact in concrete terms

Root on a SIP analog telephone adapter is root on the box that connects an organization's analog handsets
to its voice service. Concretely, that means: the configuration and provisioning state the daemon itself
manages, including the service parameters the device applies at boot; the ability to start, stop or
replace the processes that carry calls; the ability to change the device's addressing, routing or name
resolution where the platform permits it; and the ability to destroy or degrade service at will, either
coarsely by stopping what runs or surgically by corrupting what is stored. Because the adapter sits inside
the premises network by definition, code running as root on it also holds an interior position from which
the hosts and services the platform can reach are reachable. None of those consequences requires a second
vulnerability: they are what the first one's privilege level already grants.

The impact statement that matters most for a reader deciding what to do is the change in the credential's
meaning. Before this finding, the administrator credential bought a settings interface with a finite
vocabulary. After it, the same credential buys the operating system of a device that sits in the voice and
data path of the site. That is the gap the CVSS impact metrics describe, and it is why a finding whose
precondition is "authenticated administrator" is still rated High rather than dismissed as
administrator-equals-root.

## 11. Fix Recommendations

1. Delete the shell from the persistence path. The handler wants to write one string into one file; do that
   with `open()`/`write()` (or the platform's NVRAM commit routine if that is the intended store) and the
   shell parser is no longer part of the data path. This is the only fix that removes the class rather than
   filtering for it.
2. If the construction must survive a release cycle, single-quote the value with literal single-quote
   escaping and assert after construction that the command contains no `"`, `;`, `#` or newline, failing
   the request on assertion. A stopgap, because a shell parser remains between the administrator and the
   filesystem.
3. Validate the value against the grammar of a time zone rather than against a list of bad characters. The
   accepted forms are few and bounded; an allowlist plus an explicit maximum length is stable, auditable
   and cheap. Reject before the value reaches any command, log or store.
4. Reduce the daemon's privilege. `gs_cpe` runs as root per the record, which is why the marker reads
   `uid=0`. A dedicated identity with write access limited to the configuration path it needs would not
   repair this injection, but it would cap what any injection in this daemon can reach.
5. Treat the remaining shell sites as a category. The record's enumeration - three `system()` references
   and one `popen()` - should be closed out in code: either migrated to argument-array execution or
   documented as fixed-constant command lines. The `cpe_download_end` path is the one site in this record
   whose controllability was never settled, and it deserves the dispatcher trace that would settle it.
6. Add a regression test at the handler level: a value containing `";`, a value containing a bare `"`, and
   the benign `UTC-0800` control, asserting that no shell is reached and that the configuration file is
   still written correctly for the control. Run it across every model sharing the `gs_cpe` codebase.
7. For operators, until a patch exists: keep the webadmin interface and the TR-069 management channel off
   untrusted segments, disable remote management where it is not required, restrict who holds the
   administrator credential, and watch for unexpected files under `/tmp` on adapters as a possible
   command-execution indicator. Replacing the shipped `admin/admin` default is hygiene, not mitigation -
   this chain is indifferent to the password's value.

## 12. CWE

### CWE - classification rationale

- CWE-78, Improper Neutralization of Special Elements used in an OS Command, is the primary and only
  claimed class. Every element of the definition is present: an externally supplied string
  (the time-zone value), a command line built by string interpolation (`echo "%s">%s`), an execution
  interface that re-parses the string (`system()` through `/bin/sh -c`), and a metacharacter - the double
  quote - that lets the supplied string escape its intended operand and contribute executable command
  text.
- CWE-20, Improper Input Validation, describes the same defect from the other end and was considered as a
  secondary label. It is not claimed here: the record's finding is one sink with one missing neutralization,
  and adding an input-validation label would describe the same bytes twice. The absence of validation is
  stated in the source analysis instead.
- CWE-88 (Argument Injection) was considered and rejected: the value is interpolated into the command
  string as shell source, not appended as an argument word to a fixed command, so the mechanism is command
  injection proper.
- CWE-426 (Untrusted Search Path) was considered and rejected: nothing in this handler resolves an
  executable through the supplied value; the binary executed is the platform's own `sh`.
- CWE-269 (Improper Privilege Management) was considered as a framing for the root-running daemon and
  rejected as a classification of this defect: the privilege level is what makes the impact severe, not
  what makes the injection possible. It appears in the fix recommendations as a hardening measure for
  exactly that reason.

---
Written by the 0day Rubbish Research Team.
