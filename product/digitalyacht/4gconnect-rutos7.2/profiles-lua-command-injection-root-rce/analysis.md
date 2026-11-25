# DigitalYacht 4GConnect RutOS 7.2.x - unquoted profile name command injection in the profiles.lua apply_profile handler

Advisory: https://0day-rubbish.com/blog/profiles-lua-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

The DigitalYacht 4GConnect is a 4G cellular router built for marine and remote-site connectivity, and it
runs RutOS 7.2.x, the OpenWrt-derived router operating system maintained upstream by Teltonika. The
analyzed build is `4GConnect_R_GPL_07.02.08`, a MIPS32 big-endian image with musl libc and the standard
OpenWrt userspace. The 4GConnect exposes its configuration through a web management plane whose
server-side modules include Lua services under `/usr/lib/lua/ubus/`. One of those
modules is the system profiles module at `/usr/lib/lua/ubus/system/profiles.lua`, which implements the
device's profile management: a profile is a named bundle of settings that the device can switch between,
and the module exposes the ubus method `system.profiles.apply_profile` to activate one, reached over the
management HTTP interface as `POST /api/system/profiles/apply` with a JSON body of the shape
`{"name": "<profile name>"}`.

The handler that implements the activation builds its shell command by literal string concatenation:

```lua
local function apply_profile(name)
  if name then
    os.execute("/usr/sbin/profile.sh -c " .. name)  -- NO shellquote!
    uci:set("profiles", "general", "profile", name)
    uci:commit("profiles")
    return true
  end
  return false
end
```

There is no quoting wrapper on `name`, no character filter, no length gate and no allowlist. Lua's
`os.execute()` is not an exec-family call with an argument vector: it hands its single string argument to
the C library's `system()`, which runs `/bin/sh -c <string>`. The concatenated command is therefore parsed
a second time, by a shell, and every metacharacter inside `name` is live. A profile name of
`x;id>/tmp/dy_marker_vuln;#` becomes the command line
`/usr/sbin/profile.sh -c x;id>/tmp/dy_marker_vuln;#`, which a POSIX shell reads as three things: a call to
the profile helper with the argument `x`, a second, independent command `id>/tmp/dy_marker_vuln`, and a
comment introduced by `#` that absorbs the remainder.

The same module in later RutOS releases - the record compares against 7.6.x, the generation shipped on
Teltonika's RUT2 and RUT9 hardware - carries the missing wrapper:

```lua
-- RutOS 7.6.x (PATCHED version)
os.execute("/usr/sbin/profile.sh -c " .. _UPVALUE0_.shellquote(name))
```

`shellquote()` escapes shell metacharacters before concatenation, and the injection stops working. The
difference between the two generations is therefore not a redesign but a single sanitization call that is
absent in the 7.2.x build analyzed here, and the record's version comparison states exactly that.

One boundary belongs at the top of any reading of this advisory, because it governs every impact statement
that follows. Verification was a sink-level replication: the `os.execute()` sink was reproduced directly as
`sh -c` on an isolated cloud-hosted server running Ubuntu on x86-64, not on 4GConnect hardware. The marker
that the injected command produced contained `uid=0(root) gid=0(root) groups=0(root)`, and a benign control
name produced no marker at all. That marker documents the sink's behaviour when the process that evaluates
it runs with root authority - the replication session itself was a root session on the test host - and not
a measurement of the identity of the process that evaluates `profiles.lua` on a 4GConnect device. The
device-side identity is not measured in this record; the accompanying exploit script asserts it as root,
and this advisory reports that assertion as unverified rather than as an observation. Section 9 keeps the
two halves of the evidence separated. No 4GConnect hardware was driven, no HTTP request was fired at a
device, and the end-to-end path is established from the Lua source and the request/response shape recorded
in the research material, while the injection behaviour at the sink is established by the replication.

### Overview of the product and the module layout

RutOS 7.2.x organizes its management logic as ubus service modules. The HTTP front end (`uhttpd` in a
stock OpenWrt build) exposes `/api/login`, which authenticates a client and issues a session token, and the
API layer maps subsequent `/api/...` requests onto ubus method calls. The profiles module is one such service:
its methods are reached as `system.profiles.*`, and the HTTP path the record documents for activation is
`POST /api/system/profiles/apply`. The module keeps its state in a UCI configuration section named
`profiles`, whose `general` section stores the currently selected profile name, and it delegates the actual
switching work to the shell helper `/usr/sbin/profile.sh`, which takes the profile name after a `-c` flag.
That delegation is the reason the module has a shell in its data path at all, and it is the reason the
missing quote wrapper is exploitable.

Two properties of this layout matter for the analysis that follows. First, the command string crosses a
language boundary: the profile name arrives as JSON, becomes a Lua string, is concatenated into a shell
command line, and is then re-tokenized by `/bin/sh`. Each boundary is an opportunity for a filter, and none
exists on this path. Second, the module is part of the authenticated management plane. Reaching
`apply_profile` requires a valid session, which is what fixes the privilege metric in the published score
and what separates this finding from an unauthenticated one.

### Overview of scope and of what is not claimed

The finding is scoped to the profile-activation path of the profiles module in RutOS 7.2.x as shipped on
the 4GConnect. This advisory does not claim that other ubus modules of the same firmware are exploitable by
the same payload, does not claim a memory-corruption primitive, does not claim a transport-layer or
authentication-bypass defect, and does not claim persistence across a factory reset or a reflash. The
factory `admin:admin` credential pair that ships on these devices is an adjacent weakness of a different
class: it makes the authenticated boundary cheaper to cross, but it is not the vector analyzed here, it is
not needed to exercise the injection, and changing the administrator password does not remove the defect.
The chain documented in this analysis consumes a legitimate administrator session and abuses an intended
configuration action.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Digital Yacht (United Kingdom), marine and remote-site connectivity |
| Product | DigitalYacht 4GConnect, 4G cellular router |
| Version analyzed | RutOS 7.2.x, build `4GConnect_R_GPL_07.02.08` |
| Platform | MIPS32 big-endian, musl libc, OpenWrt userspace |
| Management plane | RutOS web API, session token from `/api/login`, port 443 |
| Vulnerable module | `/usr/lib/lua/ubus/system/profiles.lua` |
| Vulnerable function | `apply_profile()` |
| ubus method | `system.profiles.apply_profile` |
| HTTP endpoint | `POST /api/system/profiles/apply` |
| Parameter | `name` (JSON body field) |
| Sink | `os.execute("/usr/sbin/profile.sh -c " .. name)` |
| Sanitization | none on this path: no `shellquote()`, no allowlist, no length gate |
| Breakout | `x;id>/tmp/dy_marker_vuln;#` (also `|` and `$()` forms) |
| Authentication | authenticated: session token issued by `/api/login` |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)`, sink-level replication only |
| Primary CWE | CWE-78 |
| Published score | 7.2 High - `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

Three properties combine to make the defect. The first is the sink's semantics: `os.execute()` in Lua is
`system()` in C, and `system()` always involves a shell, so the argument is a command language string
rather than a program plus arguments. The second is the absence of quoting: the profile name is appended
to a fixed prefix with `..`, so any byte the shell treats specially is interpreted rather than passed
through. The third is the absence of validation: `apply_profile` accepts the name as delivered, while its
sibling `create_profile` in the same module enforces both a length cap and a character class. Any one of
the three, removed, would close the issue; all three are present in 7.2.x.

The consequence is classic CWE-78 command injection with zero sanitization. Semicolon, pipe and command
substitution all reach the shell intact, and the replication confirms all three classes (Section 9). The
trailing `#` in the published payload is an engineering convenience rather than a requirement: it turns
the residual text of the command line into a comment, so the helper's own failure mode cannot interfere
with the injected command, and it lets the payload end cleanly inside a JSON string.

### Vulnerability Summary preconditions

The chain requires a reachable management interface (the record's request shape is HTTPS on port 443), a
valid session token obtained from `/api/login` with an administrator credential, and a firmware image that
contains the unquoted 7.2.x generation of the profiles module. No user interaction is involved: the
credential holder sends the request directly. There is no race, no timing window, no multi-step state
machine and no memory grooming.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The gate is the RutOS web API login: a JSON `POST /api/login` carrying a username and password, answered
with a session token. The recorded exploit parses the token out of the login response body, taking it from
`data.token` or `data.ubus_rpc_session` (with the same fields accepted at the top level), and presents it
on the exploit request as `Authorization: Bearer <token>`. The profile activation endpoint is inside that
boundary, which is why the published vector carries `PR:H`: the session belongs to the device
administrator, and the record identifies no lower-privilege account class with access to the profiles
method. The exploitation therefore begins from the highest web-plane privilege the product offers, and it
escalates from configuration authority to command execution rather than from an unprivileged foothold.

### Authentication Boundary - what the chain does not do

The chain does not bypass authentication, does not forge or steal a token, does not rely on a default
credential to work, and does not require any interaction from a second party. The `admin:admin` factory
pair is disclosed separately in this advisory as an adjacent weakness, because it lowers the cost of
obtaining the session that the injection needs; but the injection itself is exercised with whatever
administrator credential the device has, and a device whose administrator password has been changed is
still vulnerable to the same request from the same authenticated position. The two issues are independent:
fixing the credential pair does not fix the injection, and fixing the injection does not fix the
credential pair.

### Authentication Boundary - why that boundary does not soften the impact

An administrator session is a configuration authority, not a shell. The intended semantics of the
profiles interface are "select one of the stored profiles"; the realized semantics after this defect are
"run an arbitrary command". That gap is the vulnerability: the device grants a bounded authority and the
implementation hands it an unbounded one. For a router that is the uplink of a vessel or a remote site,
the difference between "can change settings" and "can run commands as the management process" is the
difference between a misconfiguration and a compromise, and Section 10 enumerates what the second one
yields.

## 4. Attack Surface

### Attack Surface - the web API and the ubus dispatch model

The externally reachable surface is the RutOS web API: an HTTP server that terminates TLS and dispatches
`/api/<service>/...` paths onto ubus methods. Every JSON body field on such a path is attacker-controlled
with respect to the module that receives it, because the API layer's job is to deserialize and forward. The security of the whole plane therefore depends on per-module discipline, and
the profiles module is where that discipline fails. The dispatch model also explains the reachability
argument: the same endpoint is reachable from any host that can open the management port, which for a
cellular router is typically the LAN side but is a deployment choice rather than a hardware constraint.

### Attack Surface - why the surface audit narrowed here

Within the profiles module the record documents two request-driven operations: `create_profile`, which
registers a new profile, and `apply_profile`, which activates one. Both take the profile name from the
request. Only one of them reaches a shell with that name, and only one of them validates it. That
asymmetry is the finding: the module's author knew the name needed validation (the `create_profile` path
proves it) and did not apply the same gate on the activation path. The audit narrowed to
`apply_profile` because it is the only documented member of this module whose request-derived string is
concatenated into `os.execute()`, and because that concatenation is visible in the module source without
any decompilation.

### Attack Surface - components that narrowed out

The `uci:set` and `uci:commit` calls that follow the sink in `apply_profile` are data-plane writes to the
`profiles` configuration: they store the supplied name but they do not interpret it as code, so they are a
side effect of the exploit rather than a second sink. The shell helper `/usr/sbin/profile.sh` is a
consumer of the name, not a sanitizer; whether it succeeds or fails is irrelevant to the injection, since
the injected command is a separate statement that runs regardless. The login endpoint is an
authentication surface, not an injection surface, and no injection is claimed there.

## 5. Sink Identification

### Sink Identification - the construction

The sink is a single statement inside `apply_profile()` in
`/usr/lib/lua/ubus/system/profiles.lua`:

```lua
os.execute("/usr/sbin/profile.sh -c " .. name)
```

The fixed prefix is `/usr/sbin/profile.sh -c `, including the trailing space; the variable part is `name`,
concatenated with Lua's `..` operator. The resulting single string is passed to `os.execute()`. In the
POSIX C library that Lua binds to, `os.execute()` with a string argument calls `system()`, which forks a
shell and executes `/bin/sh -c <string>`. The string is therefore not a program name with arguments but a
small program in the shell language, and it is interpreted as such.

### Sink Identification - what that means for a name

Three shell constructs are available to any name that reaches the sink. A semicolon (`;`) ends the current
command and starts a new one, so `x;id>/tmp/dy_marker_vuln` runs `id` after the helper call. A pipe (`|`)
makes the helper's output the input of the injected command. Command substitution (`$(...)`) evaluates the
inner command and splices its output into the surrounding command, and needs no separator at all. All
three were exercised in the record's replication with the forms `x;id>/tmp/m1;#`, `x|id>/tmp/m2` and
`x$(id>/tmp/m3)`, and all three produced `uid=0(root)`. A backtick form is equally available in principle
because the sink performs no filtering whatever; the record's replication table lists the three classes it
executed and this advisory claims exactly those three.

### Sink Identification - execution identity

The identity under which the injected command runs is the identity of the process that evaluates the
profiles module, and the record does not measure that identity on a device. What the record does contain is
the replication's own marker, produced by running the sink as `sh -c` inside a root session on the test
host, plus the exploit script's stated expectation that `os.execute()` from the ubus handler lands as root.
This advisory states both, and claims neither as a device-side measurement. The impact discussion in
Section 10 is written so that its conclusions hold for any identity with which a RutOS ubus module
evaluates its request handlers, and it flags the root case as the record's expectation rather than as an
observation.

## 6. Source Identification

### Source Identification - the parameter and its path

The source is the `name` field of the JSON body of `POST /api/system/profiles/apply`, forwarded by the API
layer into the ubus call `system.profiles.apply_profile`. The recorded request is minimal:

```
POST /api/system/profiles/apply HTTP/1.1
Host: <target>
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{"name":"x;id>/tmp/dy_marker_vuln;#"}
```

Nothing in the request constrains the field: it is JSON, so any byte that survives JSON encoding reaches
the Lua string, and the only bytes JSON cannot carry directly are the quote, the backslash and control
characters, none of which the payload needs.

### Source Identification - the validation that exists elsewhere in the same file

The module's `create_profile` function does validate its name, and the contrast is the clearest statement
of the defect in the record:

```lua
if #name == 0 or #name > 20 or not name:match("^[%w_]+$") then
  ubus.reply(req, {res = 1}) -- Invalid name
  return
end
```

That gate rejects empty names, names longer than twenty characters, and names containing anything outside
`[A-Za-z0-9_]`. The activation function that is the subject of this advisory contains no equivalent: no
length test, no pattern test, no escaping, no canonicalization. A payload of `x;id>/tmp/dy_marker_vuln;#`
is longer than twenty characters and contains `;`, `#` and `/`, so it would be refused outright by
`create_profile`; it is accepted without comment by `apply_profile`. The same author, the same file, the
same parameter name, two different postures.

### Source Identification - what the payload must respect

Because the activation path applies no validation, the only constraints on the payload are the ones the
transport imposes. It must be valid JSON, which the PoC guarantees by encoding with a JSON serializer. It
must keep the whole injected program inside the single command line, which the `#` terminator guarantees by
turning the helper invocation's remains into a comment. It should keep the helper's own argument plausible
so that the first statement does not abort the shell before the injected one; the single character `x` used
by the record satisfies that, and POSIX shells do not abort a command list on failure of an earlier
element anyway.

## 7. Data Flow

### Data Flow - end to end

The transformation of the value is worth writing out in full, because every step is a place a filter could
have existed:

```
JSON body          {"name":"x;id>/tmp/dy_marker_vuln;#"}
Lua argument       name = "x;id>/tmp/dy_marker_vuln;#"
Concatenation      "/usr/sbin/profile.sh -c " .. name
Command string     /usr/sbin/profile.sh -c x;id>/tmp/dy_marker_vuln;#
os.execute         system("/usr/sbin/profile.sh -c x;id>/tmp/dy_marker_vuln;#")
Shell invocation   /bin/sh -c "/usr/sbin/profile.sh -c x;id>/tmp/dy_marker_vuln;#"
Shell parse        statement 1: /usr/sbin/profile.sh -c x
                   statement 2: id>/tmp/dy_marker_vuln
                   remainder:   # ... (comment)
```

The shell's second parse is the whole vulnerability. The Lua layer believes it is invoking a helper with
one argument; the shell sees two commands separated by a semicolon, one of which the request supplied.

### Data Flow - properties worth naming

There is no canonicalization step on the path, so no encoding trick is needed to preserve the
metacharacters. There is no shell quoting wrapper, so no escape sequence is needed to break out of a quoted
context. There is no allowlist, so the payload does not have to be composed of permitted characters. There
is no length gate, so the payload can be as long as the JSON body allows. And there is no second sink
involved: the injection happens on the first and only shell invocation, which is why the replication can
reproduce the whole defect with a single `sh -c` line and why the reproduction is a faithful model of the
device-side behaviour rather than an approximation of it.

## 8. Exploit Construction

### Exploit Construction - request shape

The recorded exploit is a short chain over TLS. The two requests that carry the exploitation are the
authentication that harvests the token and the activation that delivers the payload:

```
POST /api/login           {"username":"admin","password":"<administrator password>"}
      -> session token
POST /api/system/profiles/apply
      Authorization: Bearer <token>
      {"name":"x;id>/tmp/dy_marker_vuln;#"}
```

The recording script speaks raw HTTP/1.1 over a TLS socket with certificate verification disabled, the
usual arrangement for embedded devices that present self-signed certificates; it extracts the token from
the JSON response body and uses it verbatim. The delivered package's PoC keeps that structure but implements it with the
standard library's HTTP client, and it takes the administrator credential from the command line instead of
assuming one.

### Exploit Construction - payload engineering

The payload `x;id>/tmp/dy_marker_vuln;#` has four parts, each doing a job. `x` is a plausible profile name
for the helper, so the first statement is a normal-looking activation attempt. `;` ends that statement.
`id>/tmp/dy_marker_vuln` is the injected program, deliberately non-destructive: it writes the identity of
the executing process into a file under `/tmp` and changes nothing else. `#` comments out whatever remains
of the command line, including the shell's own reconstruction of the helper's arguments, so the command
line parses cleanly no matter how the shell would otherwise have continued. The same shape works with
`|` and with `$( )` by swapping the separator, which is what the record's three-vector table demonstrates.

### Exploit Construction - what the PoC deliberately does not do

The PoC creates one marker file and nothing else. Its payload keeps the recorded shape but redirects the
identity write to `/www/dy_4gconnect_profiles_marker.txt`, the web document root, which is the read-back
mechanism the record itself uses when it copies a marker to `/www/` and fetches it over HTTP with a `GET`.
Writing the marker there means the probe needs no second file and no second injection to observe the
result. It does not read the device's configuration, does not change any setting, does not add an account,
does not install persistence and does not attempt to remove anything: there is no destructive command in
the script, and its only write is the marker that proves execution. It sends one login request and one
injection request, prints what the device returned, and stops. It does not attempt credential guessing, and
its default credential values are the factory pair that the vendor ships and that this advisory discusses
separately, not a personal or harvested credential. It
carries no comment lines and no non-ASCII text, and it defaults to the documentation address `192.0.2.10`
so that a run without arguments cannot reach a real device. An operator who wants the marker gone after the
run removes that one path by hand; the probe issues no deletion itself.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

The record describes a sink-level replication performed on an isolated cloud-hosted server: Ubuntu on
x86-64, reached over SSH, with the sink reproduced directly as a `sh -c` invocation of the exact command
string that `os.execute()` would produce. The target firmware named in the record is
`4GConnect_R_GPL_07.02.08` (RutOS 7.2.x). No 4GConnect hardware was used, and full QEMU emulation of the
MIPS32 big-endian RutOS image was not performed: the record states that the Realtek/MediaTek Wi-Fi driver
dependency blocks a complete network stack and that `uhttpd` needs the full OpenWrt userspace (`procd`,
`ubusd`, `rpcd`, `nvram`) to come up. The replication therefore isolates the one component under test - the
shell interpretation of the concatenated command - and says nothing about the device's HTTP layer.

### Dynamic Verification - vectors and results

The vulnerable run and the control run are reproduced here exactly as recorded:

```
VULN:     sh -c "/usr/sbin/profile.sh -c x;id>/tmp/dy_marker_vuln;#"
CONTROL:  sh -c "/usr/sbin/profile.sh -c default"
```

The vulnerable run created `/tmp/dy_marker_vuln`, and reading it back produced:

```
uid=0(root) gid=0(root) groups=0(root)
```

The control run created nothing, and the record's read-back of the control path returned:

```
ls: cannot access '/tmp/dy_marker_control': No such file or directory
```

| Test | Marker created | `uid=0` | Verdict |
|---|---|---|---|
| VULN (injection) | yes | yes | injection reached the shell and executed |
| CONTROL (benign name) | no | n/a | no execution without metacharacters |

The verdict recorded is PASS: the injected payload creates the marker and the benign control does not,
which confirms injectability of the sink and rules out the marker being an artifact of the harness.

### Dynamic Verification - the three metacharacter classes

The record's additional sink verification exercised each separator class against the same sink:

| Vector | Payload | Result |
|---|---|---|
| semicolon | `x;id>/tmp/m1;#` | `uid=0(root)` |
| pipe | `x\|id>/tmp/m2` | `uid=0(root)` |
| command substitution | `x$(id>/tmp/m3)` | `uid=0(root)` |

All three returned root identity inside the replication, which is what "zero sanitization" predicts: the
payload does not have to defeat a filter, because there is none to defeat.

### Dynamic Verification - negatives, stated

Four negatives belong in the record. First, no end-to-end HTTP verification was performed against a
device: the request path, the endpoint and the token handling are established from the module source and
the recorded request shape, not from a live exchange with 4GConnect hardware. Second, the `uid=0(root)`
marker was produced by a replication session that was itself root on the test host, so it measures the
sink's behaviour under a root parent process and not the device-side identity; the exploit script's
assertion that the device-side identity is root is unverified. Third, no persistence, no lateral movement
and no data-plane effect was tested. Fourth, the markers were removed from the test host after the run, and
the record's cleanup command lists exactly the five paths it deleted, so the replication left nothing
behind.

## 10. Reachability and Security Impact

### Reachability - network position

The endpoint is part of the authenticated web management plane and answers on the device's HTTPS port; the
record's request shape targets port 443. Reachability from a given network position is a deployment
property, not a firmware property: a 4GConnect whose management interface is confined to its LAN side is
reachable by anyone on that LAN, and one whose management interface is exposed to its uplink is reachable
from wherever that uplink is reachable. The published vector uses `AV:N` because the request is an ordinary
network request against a management service and no additional network position - adjacency, same broadcast
domain, same link - is required by the mechanism itself.

### Reachability - impact in concrete terms

An authenticated actor who can reach this endpoint converts a profile-selection action into arbitrary
command execution inside the device's management context. On a RutOS device that context is the plane that
owns the configuration store, the network interfaces, the routing and firewall state, the cellular uplink
and the management daemon itself. The realistic consequences are therefore: read and modification of the
device's full configuration, including the credentials and keys the firmware stores there; control over
the device's routing, DNS and firewall semantics, which for a router means control over the traffic of
everything behind it; the ability to run the device's own tooling as the management process, which is what
turns a settings change into a compromise; and availability impact at will, up to and including making the
device unreachable. Because a 4GConnect is frequently the only uplink of a vessel or a remote
installation, compromise of the device is compromise of the site's network edge rather than of one host.

The honest ceiling on all of that is the identity question in Section 9: the record demonstrates command
execution with full effect inside the replication, and it expects - but does not measure on hardware - that
the device-side identity is root. Even at a lower identity, the command channel sits inside the
management plane and yields the configuration and service control described above; the root case is the
record's expectation and is reported as such.

## 11. Fix Recommendations

1. Apply the upstream fix. Wrap the name in `shellquote()` before concatenation, exactly as later RutOS
   generations do: `os.execute("/usr/sbin/profile.sh -c " .. shellquote(name))`. This is a one-line change
   that closes the class on this sink and is the fix the record's version comparison documents.
2. Validate the name on the activation path with the gate the module already owns. `apply_profile` should
   apply the same test `create_profile` applies - a non-empty name, a length cap, and a `^[%w_]+$` match -
   and refuse with the module's existing error reply when it fails. Defence in depth: the allowlist and the
   quoting wrapper are independent controls.
3. Remove the shell from the path entirely. Replace `os.execute()` with an exec-family call that takes an
   argument vector, so the profile name can never be parsed as shell syntax. On OpenWrt a small helper
   invoked with `nixio.exec()` or an equivalent argument-array API achieves the same activation with no
   command language in the data path; this is the only fix that removes the vulnerability class rather than
   the instance.
4. Audit the rest of the Lua tree for the same pattern. Search `/usr/lib/lua/ubus/` for `os.execute`,
   `io.popen` and any other shell-mediated call whose argument is built by concatenation, and apply the
   same two controls to each. A single module was analyzed here; the pattern is cheap to grep for and
   expensive to leave behind.
5. Reduce the blast radius. Run the web management plane and its helpers under a dedicated unprivileged
   identity, so that a future injection on this plane lands with bounded authority instead of the
   management daemon's. This does not fix the injection and should not be presented as a fix.
6. Add regression coverage at the module level. Submit an activation request whose name contains `$(true)`,
   one containing `;`, one containing `|` and one containing a backtick, and assert that each is rejected
   or produces no shell effect. Run the same suite on every RutOS build the vendor ships.
7. For operators, until a fixed build is available: keep the management plane on a trusted segment, do not
   expose it to the cellular uplink, change the factory `admin:admin` pair, and treat any account that can
   reach the profiles endpoint as holding device-level authority. The credential change is hygiene against
   the adjacent weakness; it does not mitigate this injection.

## 12. CWE

### CWE - classification rationale

The defect is CWE-78, Improper Neutralization of Special Elements used in an OS Command ('OS Command
Injection'). The rationale follows the data flow in Section 7: a request-supplied string reaches a
command-language interpreter (`/bin/sh` via `system()`) without neutralization, and the interpreter then
executes attacker-chosen syntax. All the required properties are present - the source is remote and
request-driven, the sink is a shell invocation, and the missing control is neutralization of shell
metacharacters - so the classification is not a judgement call between neighbouring categories.

Two taxonomy notes. CWE-78 is the child of CWE-77 (Command Injection), and the case is a textbook instance
of the parent as well; the published classification uses the child because the shell is the interpreter
involved, which is exactly what CWE-78 names. And the missing validation is not a separate weakness class
here: it is the mechanism by which neutralization is absent, not an independent input-validation defect
with its own impact, so the advisory does not publish a second CWE alongside CWE-78.

No CVE identifier has been assigned to this issue. No identifier is named in the research record, and none
is claimed here.

---

Written by the 0day Rubbish Research Team.
