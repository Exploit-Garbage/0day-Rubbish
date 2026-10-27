# Moxa MAR-2000 — IPsec Tunnel Address Injection: an Unvalidated VPN Field Feeds Four Shell-Interpreted Route-Management Commands

## 1. Overview

### Overview — the finding

Moxa, an industrial networking vendor in Taiwan, ships the MAR-2000 series industrial
4G/LTE cellular router with a configuration backend in which each subsystem is implemented
as a Python model that both stores its settings and acts on the operating system. This
advisory documents the finding in the IPsec model: the same subsystem that builds the
router's VPN tunnels assembles the tunnel's address and route management commands from
stored configuration values, executes them through a shell, and never checks that the
values are addresses at all.

The IPsec model at `/home/model/network/ipsec/ipsec.py` stores `tunnelModeTable` — with
`localVpnIp`, `tunnelRemoteVpnIp`, `tunnelRemoteVpnInterface` — and `transModeTable` as
JSON configuration, written through the authenticated `PUT /api/v1/network/ipsec` of the
management application. When the IPsec service applies the tunnel, the model calls its
lifecycle functions — `add_ip`, `del_ip`, `add_route`, `del_route` — each of which
interpolates the stored fields into an `ip` command line and hands it to
`subprocess.call` with `shell=True`. The write side applies one filter, `clean_data()`,
and the filter's entire behaviour is to drop dictionary keys it does not recognise: no
value is examined, an address format is never checked, and metacharacters pass through to
the command template. An administrator who stores `10.10.10.1; <command>; #` in
`localVpnIp` has therefore authored a command line of the shape
`ip addr add 10.10.10.1; <command>; #/24 dev eth0` — the first segment fails harmlessly
as an address assignment, the injected segment executes under the shell, and the hash
sign comments away the remainder of the template. The same stored field appears in
`del_ip`'s operand and twice inside `add_route`'s `ip route add to ... via ... src ...`
construction, so a single stored value arms several commands at once and fires in
whichever of them the tunnel lifecycle reaches first.

A fifth related write — `update_config_file()`, which assembles IPsec configuration lines
interpolating `transModeTable`'s `transServerIp` and `transClientIp` — sits in the same
model and exhibits the same unvalidated-field pattern. It was not exercised in this
research record; this advisory presents it as structure, alongside the four replicable
sinks, and does not claim a detonation it did not perform.

### Overview — the product and its runtime stack

The artefact characterised is firmware `FWR_MAR2000_V1.0_Build_15010909` for the
MAR-2000 series industrial 4G/LTE cellular router, which extracts to an ARM Debian 6.0.8
root filesystem running the MIRF (Mobile Intelligent Routing Framework) stack. The
management plane, as established from the firmware's own application files, is an
Express 4.0 application listening on port 80 with the binding covering every interface;
the express-sanji middleware translates each REST resource into a message on a local
MQTT broker at localhost:1883; and Python 2.6 model daemons under `/home/model/` both
persist the configuration and perform the operating-system operations it describes.

Authentication lives entirely at the HTTP layer: the `validateUser` middleware requires
a server-side session for non-GET methods, and login is `POST /api/login` compared
against bcrypt-hashed entries in an SQLite user table. Two adjacent properties are noted
for context and deliberately kept out of this chain: the broker itself accepts
unauthenticated publishes, and every `GET` across `/api/v1/*` is answered without a
session. The finding documented here needs neither.

### Overview — the evidence base and its boundary

Two evidence classes carry this advisory, labelled wherever used. The first is the
firmware's application source: the model file, its resource wiring, `clean_data()`'s
filtering scope, and the four command constructions quoted in section 5. This is
structural evidence about shipped software, complete for what the product does with the
fields. The second is sink-level replication: each of the four constructions — the same
format template, the same stored-field position, the same `shell=True` hand-off — was
re-implemented and executed on an isolated cloud Linux sandbox, carrying an injected
address value and a benign control; section 9 quotes the results, which include a marker
reading `uid=0(root)`. That figure is the identity of the sandbox harness running the
replication, not a measurement of the device; the on-device model process identity was
not measured and is not claimed. End-to-end detonation against powered-on MAR-2000
hardware — including observing the exact tunnel-apply moment at which the model consumes
the stored value — is outside this research record, and the claims of this advisory are
scoped accordingly: the write path, the filter's scope and the sink constructions are
established as structure, and the shell behaviour of those constructions is established
by replication.

### Overview — independence: existing records, and how they were searched

Before drafting, the public record was searched over the vulnerability database's keyword
interface along separate axes — the vendor name alone; the vendor name combined with the
product name; the product name alone; and the vendor name combined with the handler
terms naming this finding's entry route (`executer`, `ipsec`, `scenario`). The search we
were able to complete returned two hundred and sixty-eight records under the vendor axis,
describing command-injection and authorisation findings concentrated in the vendor's
other product families. The product axis and the vendor-plus-product axis each returned
no record, and the handler-axis searches returned no record naming this product, this
model, or this root cause. No public record was found, in the searches we completed, that
names the MAR-2000 series, its IPsec model, or this defect shape — a VPN address field
interpolated into shell-interpreted `ip` management commands. The claim is stated with
its boundary: the searches were keyword-based over record description text, and this
advisory claims originality for the finding rather than asserting a universal absence.

This finding is one of three documented for this product and released as a set. It is
independent of the other two on every counting axis: a different model file
(`ipsec.py`), a different REST resource (`/api/v1/network/ipsec`), a different
configuration field (`tunnelModeTable.localVpnIp` and the fields beside it), a different
sink family (network-management shell commands), and a different execution occasion (the
IPsec tunnel lifecycle), sharing with them only the entry architecture.

## 2. Vulnerability Summary

### Vulnerability Summary — table

| Item | Value established by this research |
|---|---|
| Vendor | Moxa, industrial networking vendor, Taiwan |
| Product | MAR-2000 series industrial 4G/LTE cellular router |
| Firmware | `FWR_MAR2000_V1.0_Build_15010909` |
| Platform | ARM Debian 6.0.8 with the MIRF stack |
| Entry | `PUT /api/v1/network/ipsec` — tunnel and transport tables written verbatim |
| Validation on entry | `clean_data()` drops unknown keys only; no value is ever inspected |
| Sink family | `add_ip`, `del_ip`, `add_route`, `del_route` — each `subprocess.call(cmd, shell=True)` |
| Related structure, not detonated | `update_config_file()` interpolating `transServerIp` / `transClientIp` into the IPsec configuration file |
| Storage | JSON configuration, persisted and reread at each tunnel application |
| Authentication | administrator session required; factory default pair exists in the shipped user table |
| Verified by | firmware source analysis plus sink-level replication of all four constructions with payload and control |
| Primary CWE | CWE-78 |
| Published score | 7.2 High — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary — mechanics in four facts

**One** — the validation is a key filter, not a value filter. `clean_data()`'s job is to
keep the JSON shape familiar; it deletes keys the model does not know. The result is that
every value the model does know — including the one about to be interpolated into shell
command lines — enters storage exactly as sent.

**Two** — the sinks are operating-system state changes, not incidental log writes. The
four functions exist to assign and remove addresses and routes for the VPN tunnel; the
command template is the product's real machinery, which is why the injected bytes are
not merely interpreted but interpreted by a component whose purpose is to alter
forwarding state on a communication-infrastructure device.

**Three** — one stored value arms several commands. The same `localVpnIp` field is the
address operand of `add_ip` and `del_ip` and both the `via` and `src` operands of
`add_route`, so the attacker does not need to predict which lifecycle function runs
first; whichever runs carries the payload.

**Four** — the delivery occasion is a product lifecycle step, not an attacker request.
The stored value executes when the IPsec service applies the tunnel - at start or
restart. The attacker's request commits the payload; the product's own behaviour
delivers it, which is the property that makes the finding quiet and the stored payload
reliable.

### Vulnerability Summary — preconditions

1. an administrator session on the management application (the credential prerequisite;
   the shipped firmware's default pair collapses it in deployments that never changed
   it — scored separately, never folded in);
2. the write must pass the key filter — trivial, since the payload rides a key the
   model expects (`tunnelModeTable.localVpnIp`);
3. the IPsec service must apply the configuration — a product lifecycle step that the
   research establishes as the consumption point of the stored values, not something
   the attacker races.

## 3. Authentication Boundary

### Authentication Boundary — what the gate enforces

The `validateUser` middleware is the only authentication check on the REST surface: it
requires a server-side session for every non-GET method, and `PUT /api/v1/network/ipsec`
is a mutating request, so the session is required for the write that plants the payload.
Login is `POST /api/login` with a bcrypt-compared pair from the SQLite user table. Once
past the session check, the request has full reach into the tunnel configuration: there
is no further authorisation layer in the middleware chain, no identity carried on the
broker leg, and no permission model inside the model layer. The management application's
single administrator role is therefore the entire security boundary for this finding,
exactly as for the product's other mutating resources.

### Authentication Boundary — the default credential and how it is handled in scoring

The research record documents that the shipped firmware's user table carries a factory
default administrator pair (bcrypt-hashed at rest). This advisory treats that pair, as
this repository's other industrial-router advisories do, as a deployment condition with
its own labelled conditional reading, never as a metric of the vulnerability itself:
the published vector measures the finding with the credential prerequisite in place
(`PR:H`, the product's single top role and the CVSS guide's canonical example of High),
and the conditional reading measures the deployment state where the pair was never
changed. The two populations are described by two numbers, and neither borrows the
other's severity.

### Authentication Boundary — adjacent properties not claimed

Three nearby authentication-related observations are not part of this finding: the
unauthenticated readability of `GET /api/v1/*`, which exposes stored tunnel settings to
anonymous readers and is a read-exposure issue in its own right; the broker's absence of
authentication, a design property relevant only given some other on-device foothold;
and the session store being server-side, which is why the hardcoded cookie-signing
secret does not assist this chain. None is scored here, and each is reported
independently where reported at all.

## 4. Attack Surface

### Attack Surface — listeners and routes

| Surface | Default | Authentication | Role in this chain |
|---|---|---|---|
| Express management application | port 80, all interfaces | session for non-GET methods | entry for the write |
| IPsec resource (`/api/v1/network/ipsec`) | REST | administrator session | payload delivery |
| MQTT broker | localhost:1883 | none | internal transport, no gate of its own |
| IPsec model daemon | `/home/model/network/ipsec/ipsec.py` | none | sink at tunnel application |

The web application binds all interfaces on port 80 in the shipped firmware. Whether a
deployment exposes that listener beyond its immediate management network is an operator
decision not field-audited by this research; the published vector scores the network
position of the listener without assuming WAN exposure, and the conditional reading
changes only the privilege prerequisite.

### Attack Surface — how the surface was read

The surface was mapped from the firmware's application files: the Express route and
middleware order for the HTTP tier, the express-sanji topic mapping for the transport,
and the IPsec model's `put()` handler and lifecycle functions for the backend. Every
quoted artefact — the resource path, the model file path, the table and key names, the
command templates — comes from that reading of shipped software.

### Attack Surface — what the IPsec resource is for

The product's intended purpose for this surface is exactly what the attacker borrows:
configuring VPN tunnels on a cellular router that forwards for other people. That
purpose explains why the field is free-text-ish (an address plus subnet in one field)
and why the model is eager to act on it. It does not explain the absence of address
validation, which is the defect, and it is why the fix that matters is value validation
at the model's boundary rather than a more restrictive web form.

## 5. Sink Identification

### Sink Identification — the address sinks, quoted from the model

The tunnel-assignment path interpolates the stored local VPN address and the interface
selector into `ip addr` commands:

```python
def add_ip(self, ipRange):
    cmd = 'ip addr add %s dev eth%s' % (
        self.config['tunnelModeTable']['localVpnIp'] + '/' + ipRange.split('/')[1],
        self.config['tunnelModeTable']['tunnelRemoteVpnInterface'])
    return subprocess.call(cmd, shell=True)

def del_ip(self, ipRange):
    # the same construction with the del verb and the same stored fields
    cmd = 'ip addr del %s dev eth%s' % (...)
    return subprocess.call(cmd, shell=True)
```

Two properties make the concatenation a command-injection sink. The format string places
the stored value at the start of an `ip` command line, ahead of every literal token the
product contributes (`/24 dev eth0` follows the payload), so a `;` inside the value ends
the `ip` command before any product-intended token can interfere with the injected
statement. And `shell=True` delegates the parsing to `/bin/sh -c`, where the semicolon,
the background operator, backticks and `$(...)` all have their ordinary meaning. The
interface operand (`tunnelRemoteVpnInterface`) rides the same construction and is
likewise unvalidated; the research record's detonations put the payload in the address
field, which is sufficient and which the sibling evidence covers.

### Sink Identification — the route sinks, quoted from the model

The route path interpolates the same stored address twice into a single line:

```python
def add_route(self, ipRange):
    cmd = 'ip route add to %s via %s src %s' % (
        ipRange,
        self.config['tunnelModeTable']['localVpnIp'],
        self.config['tunnelModeTable']['localVpnIp'])
    return subprocess.call(cmd, shell=True)

def del_route(self, ipRange):
    cmd = 'ip route del %s' % ipRange
    return subprocess.call(cmd, shell=True)
```

`add_route` is the clearest illustration of the defect's blast radius: one stored value
appears in two operand positions, so a single field write arms a line whose first operand
(`ipRange`, derived from the configured ranges) or either `via`/`src` operand can carry
the injection, and any of the three firing yields execution. `del_route`'s template is
minimal — the operand alone — which makes it the cleanest sink to reason about: whatever
reaches `%s` is the first word of the command line, and a leading `;` is parsed before
`ip` itself even runs.

### Sink Identification — the related configuration-file write, and its status

`update_config_file()` assembles IPsec configuration lines of the shape:

```python
lines.append('add %s %s ah 10000 -A hmac-md5' % (
    transModeTable['transServerIp'], transModeTable['transClientIp']))
```

This is the same unvalidated-field pattern landing in a configuration file rather than
in a shell, and its exploitation shape depends on how the IPsec service subsequently
consumes that file. The research record did not exercise this write, so this advisory
reports its existence and pattern, claims no detonation for it, and counts only the four
replicated command constructions among the finding's sinks.

### Sink Identification — how the sinks were confirmed

The four constructions were confirmed by tracing their inputs (section 6) and by
replicating each construction verbatim — same template, same field position, same
`shell=True` call — on an isolated cloud sandbox with an injected value and a benign
control, quoted in section 9. The point of replicating each of the four separately is
that the finding does not depend on which of them a given firmware revision happens to
reach first in its lifecycle ordering.

## 6. Source Identification

### Source Identification — the write path and the filter's scope, quoted from the model

The configuration write arrives through the model's `put()` handler, which applies one
cleaning step before persisting:

```python
def clean_data(self, raw_data):
    # Only removes unknown dictionary keys; does NOT validate values
    for key in raw_data.keys():
        if key not in self.config_key_whitelist:
            del raw_data[key]
    return raw_data
```

The filter is a whitelist of dictionary keys. Its effect is that the request body cannot
introduce unknown keys — and its non-effect, which is the load-bearing fact, is that the
value of every known key passes through unexamined. The payload rides
`tunnelModeTable.localVpnIp`, a key the whitelist expects, so the filter is not even
encountered as an obstacle; the value moves from the HTTP body through express-sanji's
translation, through the broker, through `clean_data()` untouched, into the persisted
JSON, and from there into every command construction in section 5.

### Source Identification — the taint summary

- tainted parameter: `tunnelModeTable.localVpnIp` (with the interface selector and the
  configured ranges beside it, and `transModeTable`'s fields on the file-write path);
- transport: the authenticated REST write, translated onto the broker, persisted as JSON;
- sink reach: read at tunnel application by `add_ip`, `del_ip`, `add_route` and
  `del_route`, interpolated, shell-executed.

Sanitisation on this path is none. The nearest text processing is the model's dictionary
key bookkeeping, which is state management, not input hygiene. No address-format check
exists anywhere between the HTTP request and the shell - the product trusts its own web
form to have produced a well-formed address, and the form is not the only writer the
backend serves.

## 7. Data Flow

### Data Flow — end to end

```
[1] attacker logs in
    POST /api/login  {username, password}
    --> server-side session; validateUser admits mutations

[2] attacker writes the tunnel table
    PUT /api/v1/network/ipsec
        {"data": {"tunnelModeTable": {
                      "localVpnIp": "10.10.10.1; <command>; #",
                      "localVpnSubnet": "255.255.255.0",
                      "tunnelRemoteVpnIp": "10.10.10.10",
                      "tunnelRemoteVpnSubnet": "255.255.255.0",
                      "tunnelRemoteVpnInterface": "0"}}}
    --> clean_data() drops unknown keys only; values persist as JSON

[3] IPsec service applies the tunnel (start or restart)
    model reads stored JSON, calls its lifecycle functions

[4] shell semantics, per construction
    ip addr add 10.10.10.1; <command>; #/24 dev eth0
                  fork: 'ip addr add 10.10.10.1' (fails as an address operation)
                        '<command>'            (executes under /bin/sh)
                        '#/24 dev eth0'        (comment tail)
    ip route add to <range> via 10.10.10.1; <command>; # src ...
    ip route del <range-built-from-configured-fields>
    --> whichever runs first executes the injected statement
```

### Data Flow — properties worth naming

The chain's write and its delivery are separated by storage and a lifecycle step, which
gives the attack an unusually forgiving shape: the payload is committed once, sits in
persisted JSON across reboots, and executes whenever the tunnel is applied — an
occasion the product itself initiates and an operator expects to be routine. No second
request is needed after the write, and no attacker-controlled timing has to succeed. The
same property cuts the other way for detection: the command that executes is one the
device's own model daemon issues as part of its job, so infrastructure logs show the
model's normal subject, not a request, doing the executing. The negative control
property is mechanical rather than interpreted: with a benign address in the field, the
identical constructions run the identical `ip` commands and produce no side effects,
which is what section 9 demonstrates.

## 8. Exploit Construction

### Exploit Construction — payload shape

The payload is placed in the address field as:

```
10.10.10.1; <command>; #
```

The leading address is chosen to keep the poisoned row plausible to a human reviewing the
tunnel table; the `;` ends the `ip` operation the product intends; the injected command
follows; the `#` comments out whatever template tail the construction appends
(`/24 dev eth0`, `src ...`). Because the value sits at the front of the command line
ahead of every product-contributed token, no quoting guesswork is needed, and the same
payload shape serves all four constructions. A command that produces observable output is
all verification requires; the research record used a redirection to a marker path
(`id > <marker path>`) and the shipped PoC defaults to the same shape. One construction
note: the address-and-subnet field is split by the model itself when building the `ip
addr add` operand (`localVpnIp + '/' + <computed subnet part>`), so the payload should
not rely on text after the first `/` surviving — the leading `10.10.10.1; <command>; #`
form keeps everything the attacker needs before that split.

### Exploit Construction — the delivered PoC

`exploit/moxa_mar_2000_ipsec_config_address_injection.py` is a standard-library-only
Python 3 client that drives the entry path: it logs in, reads the current IPsec
configuration, writes `tunnelModeTable.localVpnIp` carrying the payload, and reports
what the stored value will do at each construction in section 5, naming the lifecycle
occasion at which the model consumes it. It takes target, credential, command and
timeout arguments; its default target is loopback; it verifies each response and exits
non-zero with an explicit message on failure. It does not attempt to drive the tunnel
lifecycle itself: a start-restart of the IPsec service is the device's own action, and
the research record establishes the consumption point structurally rather than by
timing a live tunnel. No persistence, reverse shell or destructive action is
implemented; the default command writes a single marker file.

### Exploit Construction — engineering notes for anyone reproducing this

Two practical points. First, confirm the field reaches storage by reading the
configuration back after the write - the resource serves a `GET` of the same data, so
the write's persistence is cheaply observable, and mis-addressed key paths (a
misspelled table name) otherwise fail silently because the model ignores unknown keys
rather than rejecting them. Second, when testing on real hardware, remember that the
delivery occasion is the tunnel lifecycle: the write alone proves storage, and the
execution claims of this advisory are about the constructions the model runs at apply
time, which section 9 establishes by replication rather than by racing a device.

## 9. Dynamic Verification

### Dynamic Verification — environment and method

Each of the four route-management constructions was replicated verbatim on an isolated
cloud Linux sandbox (x86-64, native shell): the same format template, the same field
position, the same `shell=True` call through `subprocess.call`, executed with an
injected address value and separately with a benign control. This is sink-level
replication, labelled as such: it proves what each construction does with the value that
reaches it. It does not drive the device's HTTP tier or its tunnel lifecycle end to end,
and the identity recorded in the marker is the sandbox harness's own identity.

### Dynamic Verification — observed results

For the address-assignment construction, with the injection payload in the address
position:

```
cmd = 'ip addr add %s/%s dev eth%s' % ('1.1.1.1; id > <marker>; #', '24', '0')
subprocess.call(cmd, shell=True)
--> marker file created, contents: uid=0(root) gid=0(root) groups=0(root)
```

The same method was applied to the other three constructions — the address deletion
template, the route-addition template carrying the payload, and the bare
`ip route del %s` template - and each produced the same marker result: the injected
statement executed at the point of the shell hand-off, and the leading `ip` operation
either failed as a harmless address operation or was commented away. The control, with
the same constructions carrying the benign value `1.1.1.1`, produced no marker and no
side effect of any kind - the constructions ran their intended `ip` commands and
nothing else, which is the false-positive check the record requires.

### Dynamic Verification — what the results establish and what they do not

The replications establish: that every one of the four constructions hands the stored
value to a shell (payload executes at each); that the execution is caused by the injected
bytes and not by the constructions (controls produce nothing); and that all four sinks
of this model behave identically under this payload family. They do not establish: the
on-device model process identity (the marker's `uid=0(root)` is the replication
sandbox's identity, because the harness ran privileged; this advisory never claims
device-side root); the live web tier's end-to-end behaviour including the exact
tunnel-apply moment (established structurally from the firmware's model source);
the behaviour of the configuration-file write in section 5's third subsection (not
exercised); or any behaviour of other MAR-2000 firmware builds. Each unsupported
boundary is stated rather than smoothed over, and the advisory's title and score rest
only on what is established.

## 10. Reachability and Security Impact

### Reachability — position and population

Any client that can reach the management listener and hold an administrator credential
can plant this payload; the listener binds all interfaces on port 80 in the shipped
firmware, and the write needs no special protocol position. The population for which
the credential prerequisite collapses - deployments that never changed the factory
default pair - is exactly the population conditional reading A describes, and the two
figures are kept separate because they describe different deployment states.

### Reachability — impact ceiling

The executed command runs as the identity of the IPsec model daemon, and the impact is
stated with that ceiling: the attacker gains every file the process can act on, every
configuration write the product performs - including the router's VPN and forwarding
state, which this very model manages - and the ability to interrupt a device deployed as
communication infrastructure at will. The on-device identity was not measured; nothing
in this record establishes privilege escalation beyond the model process, and none is
claimed. Because the payload persists as configuration and re-executes at each tunnel
application, the attacker's control does not depend on any single execution surviving.

### Reachability — detection notes

The configuration write is indistinguishable in shape from an administrator's ordinary
tunnel change, and the executing process is the device's own model daemon performing a
routine-sounding job - this class is structurally quiet. The readable signals are
content-level: a `localVpnIp` (or interface, or range) value containing `;`, `|`, `$(`,
backticks or newlines in the stored tunnel table; unexplained child processes under the
model daemon; and `ip` command failures in device logs whose operand text contains
shell metacharacters. All three can be audited today without vendor changes.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side

1. Manage addresses and routes without a shell: build each `ip` operation as an argument
   vector launched without `/bin/sh -c`, which removes the metacharacter question for
   all four constructions and any future sibling in the same pattern.
2. Validate address-shaped fields at the model's write boundary: IP address form, subnet
   form, interface selector - enforcement at the component that interpolates the value,
   not solely at a web form that the backend cannot assume is the only writer.
3. Turn `clean_data()` into a value validator: it is the natural single choke point; it
   currently enforces key familiarity only, and widening it to value semantics is one
   check per field.
4. Treat the configuration-file assembly with the same rule: `transServerIp` and
   `transClientIp` are interpolated into consumed configuration lines, and whatever
   consumes those lines inherits whatever this write lets through.
5. Add a product regression test that stores a metacharacter-bearing `localVpnIp`,
   drives a tunnel apply, and asserts that the stored value was rejected at write time
   or executed as an argument vector with no shell interpretation.

### Fix Recommendations — operator-side, until a patch exists

1. Change the factory default administrator credential at commissioning - this alone
   moves a deployment out of the conditional reading's population.
2. Keep the management listener off WAN-facing addresses and behind management-network
   controls.
3. Audit stored IPsec tunnel tables for fields containing shell metacharacters; a
   legitimate address never contains `;`, `|`, `$(` or a newline.
4. On deployments that do not use IPsec tunnels, disable the feature so the model's
   lifecycle has nothing to apply.

## 12. CWE and CVSS

### CWE and CVSS — classification

| Classification | Assignment | Justification |
|---|---|---|
| Primary | CWE-78 Improper Neutralization of Special Elements used in an OS Command | the stored VPN address value reaches four `shell=True` command templates verbatim; the injection bytes execute as shell statements |
| Contributing | CWE-20 Improper Input Validation | the one ingress check, `clean_data()`, filters key names only; address-shaped values are never checked anywhere on the path |
| Reported separately, never scored in | CWE-798 Use of Hard-Coded Credentials | the shipped user table carries a factory default administrator pair; it is the condition of the conditional reading, not a metric of the chain |

### CWE and CVSS — published vector

**`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 High.** Metric by metric:

- **Attack Vector Network** — the entry listener binds all interfaces on port 80 in the
  shipped firmware; the attack is ordinary HTTP against it. No WAN exposure is assumed.
- **Attack Complexity Low** — deterministic write, full control of the injected bytes, no
  race; the delivery occasion is a product lifecycle step the model performs on its own.
- **Privileges Required High** — the chain requires the device administrator session;
  the product has one documented role and it is this one, which the CVSS guide calls High.
- **User Interaction None** — the attacker performs every step of the request side.
- **Scope Unchanged** — the model daemon belongs to the same single-purpose appliance;
  managing the appliance's interfaces and routes through it is the product's design.
- **C/I/A all High** — command execution as the model process yields full compromise of
  the appliance's function, its configuration and its VPN state, plus on-demand denial
  of the device's forwarding role.

Arithmetic:

```
ISS          = 1 - (0.44 * 0.44 * 0.44) = 0.914816
Impact (S:U) = 6.42 * 0.914816          = 5.873119
Exploitability = 8.22 * 0.85 * 0.77 * 0.27 * 0.85 = 1.234708
Base (S:U)   = min(5.873119 + 1.234708, 10) = 7.107826
Roundup      = 7.2
```

### CWE and CVSS — conditional and rejected readings

- Conditional A — factory default credentials unchanged: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  = **9.8** Critical. Exploitability 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043; base
  9.760161, rounded up to 9.8. Labelled conditional on a deployment state; it is not the
  headline score.
- Rejected B — management account treated as Low: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  = **8.8** High (Exploitability 2.835255, base 8.708373). This is the figure the source
  research record carried; it is not adopted, because no artefact evidences a
  lower-privileged product role that can reach the field, and it appears here only as the
  rejected variant's arithmetic.
- Rejected C — Scope Changed: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = **9.1**
  (ISS 0.914816, Impact 6.128026, Exploitability 2.286496, 1.08 x 8.414522 = 9.087684).
  Not published: the executing process belongs to the same appliance authority.
- Recorded score note — the source record behind this advisory carried 8.8 for all three
  same-product findings; none is inherited here, and every number in this section is
  computed from the vector next to it.

### CWE and CVSS — summary of readings

| Reading | Vector | Score | Status |
|---|---|---|---|
| Published | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 7.2 High | the vulnerability itself, credential prerequisite intact |
| Conditional A | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 Critical | deployments that never changed the factory default pair |
| Rejected B | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 High | source-recorded figure; no evidence for a lower product role |
| Rejected C | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 High | scope-changed reading considered and rejected |

One sentence for the vendor's engineers: the IPsec model of the MAR-2000 series firmware
`FWR_MAR2000_V1.0_Build_15010909` interpolates unvalidated tunnel address fields into
four `shell=True` route-management commands, so an authenticated administrator stores
`10.10.10.1; command; #` once and it executes when the tunnel applies - in whichever of
the address, deletion or route commands the lifecycle reaches. Rated 7.2 High with the
credential prerequisite intact, and 9.8 for the deployment state that never changed the
factory default pair.
