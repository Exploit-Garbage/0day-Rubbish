# Lantronix LSS2200-8P v2.1.0.0R2 - Percepxion registration response command injection in the root provisioning client

## 1. Overview

### Overview of the finding

The Lantronix LSS2200-8P is an eight-port serial console server. Its purpose is to put the serial
consoles of routers, switches, firewalls and other infrastructure onto the network so that they can be
administered remotely, which places the appliance inside the management path of everything cabled to its
ports. The analyzed firmware is v2.1.0.0R2, distributed as the image `LSS2200-8P_2.1.0.0R2_image.tgz`.
Like the rest of this vendor's EOS line, it is an OpenWrt/LEDE-derived distribution that identifies itself
as "Eland 2.1.0.0R2", built for 64-bit ARM with musl libc and stripped binaries.

The appliance ships a client for the vendor's Percepxion cloud service, `eos/modules/percepxion_client.py`,
which the init script starts as root. That client performs a registration handshake with the configured
service and then launches the local `webcontrol` helper. The command line for that launch is assembled by
string concatenation from two fields of the JSON answer the registration request received -
`remote_access_host` and `auth_token` - and is handed to `os.system()`. Because `os.system()` executes its
argument through `/bin/sh -c`, the JSON field is interpreted a second time, by a shell. A responder that
answers the registration with

`{"remote_access_host": "$(id>/tmp/marker)x", "auth_token": "attacker-token", ...}`

therefore causes the appliance to run `id` as root during shell expansion, before `webcontrol` is even
started. The construction is recorded at `percepxion_client.py:2170`, and a second construction with the
same defect sits in the `status_update` thread at `percepxion_client.py:2274-2281`, where `auth_token` is
additionally injectable.

Reaching that code requires an authenticated administrator: the Percepxion endpoint is a configuration
value, exposed through the REST resource `PercepxionConnectionConfig` (`percepxion_v1.py:321`, POST
handler at line 366), which is guarded by `@jwt_required()` plus `check_group_auth` for
`AUTH_ALLOW_CONFIG`. The administrator sets `HOST` to a host they control, sets `PORT`, disables
`SECURE_PORT` and disables `VALIDATE_CERTIFICATES`; the root daemon then registers with that host, the
attacker answers with the crafted JSON, and the sink fires. This is a trust defect inside the provisioning
protocol, not a network interception: the endpoint was configured explicitly, and the device had no
sanitization between the server's JSON and its own shell.

One boundary sentence belongs at the top of any reading of this advisory. Root was observed inside a
replication environment only. The recorded dynamic run executed the exact sink line inside a writable
chroot of the appliance's own root filesystem on a cloud-hosted machine, entered as root, and the marker
landed inside that chroot; no physical LSS2200-8P was driven, and no configuration request was fired at
appliance hardware. Section 9 keeps the source-level half and the dynamic half of the evidence separated.

### Overview of the product, platform and web stack

The firmware image is a `.tgz` wrapping a 272 MiB DOS/MBR disk image with three partitions; the second
partition carries the root filesystem, which is what this research read and what the replication ran on.
The userspace is an EOS build with the vendor's own web serving arrangement:

- nginx-ssl runs as root, terminates TLS on 443 with a self-signed certificate and also listens on 80,
  and serves the React single-page application from `/www`
- the REST API behind it is a Flask-RESTX application on the gevent WSGIServer, bound to
  `0.0.0.0:8000`, fronted by nginx
- authentication is PAM-based, with `flask_jwt_extended` issuing the session token; the application
  secret comes from `os.urandom(24)` rather than a static value
- a documented default credential (`admin` / `ltrx-admin`, stored as a SHA256 crypt hash) exists, but
  first login forces a password change: while `AuthHelper.is_default_login()` reports true, no JWT is
  issued and the CLI wrapper blocks as well
- the device's configuration and control surface also includes the klish v2.2.4 CLI and a set of root
  daemons managed by procd

Two properties of this stack shape the rest of the analysis. First, every REST method is authenticated:
a per-method sweep found 199 of 199 wrapped in `jwt_required()`, with only the four routes in
`login_v1.py` free of the gate, so the unauthenticated HTTP attack surface is empty. Second, the Python
userspace is shipped as readable source under `usr/lib/python3.10/site-packages/eos/`, which is what made
a complete sink census possible rather than a sampled one.

### Overview of public-record independence

Before this advisory, the public record was swept along the axes that matter here: the product name, the
version, the Percepxion service name, the `remote_access_host` field, the `connect_server` function, and
the vendor's EOS platform generally. No published record covers this sink. No identifier has been
assigned to this finding. The nearest published record naming this vendor's EOS platform is the EDS5000
CVE-2025-67034, which describes a different defect in a different product - command injection through the
`name` parameter of a REST SSL-certificate-delete operation - and does not overlap with the Percepxion
registration response path analyzed here: different product, different function, different parameter,
different sink. Nothing in this advisory is a repackage of that record or of any other.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Lantronix, United States, device networking and out-of-band management |
| Product | LSS2200-8P, eight-port serial console server |
| Version analyzed | v2.1.0.0R2 (image `LSS2200-8P_2.1.0.0R2_image.tgz`) |
| Platform | ARM aarch64, musl libc, stripped binaries, EOS "Eland 2.1.0.0R2" on an OpenWrt/LEDE base |
| Web stack | nginx-ssl (443, self-signed; 80) serving a React SPA; Flask-RESTX on gevent at `0.0.0.0:8000` |
| Session mechanism | PAM login issuing a JWT (`flask_jwt_extended`, secret `os.urandom(24)`) |
| Configuration resource | `PercepxionConnectionConfig` (`percepxion_v1.py:321`, POST at line 366) |
| Required group | `AUTH_ALLOW_CONFIG`, via `check_group_auth` in addition to `@jwt_required()` |
| Settings used | `HOST`, `PORT`, `SECURE_PORT`, `VALIDATE_CERTIFICATES` |
| Constraint on `HOST` | `ltrx-eos-percepxion.yang:212`: plain string, length 0..256, no character set |
| Registration call | `curlConnection.register()` (`percepxion_client.py:615`) to `http{secure}://{HOST}:{PORT}/api/v1/device/register` |
| Injected field | `remote_access_host` of the registration JSON response; `auth_token` at the second sink |
| Sinks | `percepxion_client.py:2170` and `percepxion_client.py:2274-2281`, both `os.system`, both root |
| Sanitization | none; the field is concatenated into the command line unmodified |
| Breakout | `$(cmd)` command substitution inside the `-h` argument |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)` marker, replication environment |
| Authentication class | Authenticated (Target B) |
| Primary CWE | CWE-78 |
| Published score | 7.2 High for `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

The defect is a two-hop trust inversion. In the intended design the Percepxion service is a trusted
party: the device asks to be enrolled, and the service answers with the host the device should expose its
remote-access channel through, plus the token to use. The device treats both answer fields as opaque
strings and interpolates them into a shell command. That is a category error twice over - a network
response is not shell-safe text, and host and token values have grammars that the code could have
enforced but does not. The only transformation applied to the response is JSON decoding, and the
registration call is considered successful whenever the body carries no `status` of 400 or 401 and no
`code` key, which means an attacker-controlled responder does not need any privileged state, enrolment
record or valid tenant to reach the sink: a 200 response with the right two fields is enough.

### Vulnerability Summary preconditions

- The attacker has administrator access to the REST API, or can convince an administrator to change the
  Percepxion connection settings. The API is fully authenticated and the resource additionally requires
  the `AUTH_ALLOW_CONFIG` group
- The appliance can reach the attacker's registration responder on the configured host and port, which
  normally means outbound network access, or an attacker host inside the management network
- The attacker's responder answers `POST /api/v1/device/register` with a JSON body that carries
  `remote_access_host` and no error markers
- Nothing else. No race, no memory grooming, no second-stage payload, no interaction with the serial
  ports, and no cooperation from the clients whose consoles the appliance fronts

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The whole REST API is behind JWT authentication. The research record's per-method sweep enumerated 199
methods and found `@jwt_required()` on all 199, with only the four routes of `login_v1.py` reachable
without a token; those four are the login entry point, not attack surface. The Percepxion configuration
resource adds a second gate on top: `check_group_auth` restricts it to the `AUTH_ALLOW_CONFIG` group.
Login itself is PAM-backed, and the token signing secret comes from `os.urandom(24)` rather than a
static value, so there is no fixed key to recover and no predictable token. The documented default
credential exists in the image as a SHA256 crypt hash, but the first-login path refuses to issue a JWT
while `AuthHelper.is_default_login()` is true, and the CLI blocks in the same state.

### Authentication Boundary - what the chain does not do

It does not bypass that gate, and this advisory makes no such claim. There is no unauthenticated path to
the sink: the sink is not reachable over HTTP at all, it is reached inside the root daemon after the
daemon has been pointed at an attacker-chosen service by an authenticated configuration change. It is
also not a man-in-the-middle finding. Certificate validation can be turned off, and an on-path attacker
against a device that has already been configured could in principle exploit the same missing validation,
but the recorded chain does not require an on-path position: the endpoint is a configuration value the
administrator sets, so the adversary only needs the configuration change plus a reachable responder.

### Authentication Boundary - why that boundary does not soften the impact

Three considerations. First, the crossing is real: an administrator of this appliance is given a
configuration interface, not a shell, and the interface is designed to keep configuration values as data.
Turning a documentation field into root command execution is a boundary violation even when the principal
holds the highest privilege the product offers. Second, the principal is often not the party that
operates the cloud service: the endpoint value is exactly the kind of setting that gets filled in from
documentation, a support instruction, a migration checklist or a vendor portal, so the practical attack
is "get the administrator to paste an endpoint", which is a familiar social-engineering shape and is why
`HOST` being an unrestricted 0..256 string matters. Third, the daemon runs as root, so the outcome is not
"the administrator can administer the device" - it is arbitrary command execution with the appliance's
own authority, which is a different and larger capability than anything the web interface exposes.

Saying all of that plainly: the CVSS privileges metric is High because the gate is the administrator
account, and the impact metrics are all High because the gate, once passed, no longer constrains what
runs.

## 4. Attack Surface

### Attack Surface - the web stack and its dispatch model

nginx-ssl owns 443 and 80 and serves the SPA; API calls are reverse-proxied to the Flask-RESTX
application listening on `0.0.0.0:8000`. Because the API is a Python application in a readable
`site-packages` tree, the audit could enumerate handlers rather than guess at them: 199 methods across
the `*_v1.py` modules, each with its decorators visible. That readability also made a complete
shell-execution sink census possible.

### Attack Surface - why the surface audit narrowed here

Every shell-execution construction in the `eos/` tree was classified one by one, by input source and by
whether a shell is involved at all:

| Sink | Input source | Verdict |
|---|---|---|
| `network_ops_v1.py:139` `TraceRouteApiWorker`, `subprocess.run(command.split())` | host screened by `is_valid_ipv4_addr` / `is_valid_dns_name` (`re.fullmatch` over `[a-zA-Z0-9_.-]`); `local_if` always None because the INTERFACE field is ignored; list form, no shell | dead / safe |
| `network_ops_v1.py` ping and nslookup paths | same screening, list form (`subprocess.check_output(["/usr/bin/nslookup", host])`) | safe |
| `percepxion_client.py:1107/1129` nslookup and ip helpers | list form, host screened | safe |
| clish `${param}` expansion (klish 2.2.4) | the CLI escapes `! # $ ^ & * ( ) \| \ " ; < >` and the backtick, and the `__full_line` parameter type is confined to a structured dispatcher with no shell sink | refuted |
| `percepxion_client.py:2170` `connect_server` `os.system` | registration response JSON, server-controlled, unfiltered | live, root |
| `percepxion_client.py:2274-2281` `status_update` thread | same response fields, unfiltered | live, root |

The pattern in the safe rows is worth naming: where the developers used argument arrays and input
grammars, the surface is dead, and in several places they demonstrably knew the difference. The one
place where a network response is concatenated into a shell string is the finding.

### Attack Surface - components that narrowed out

The klish CLI deserves its own sentence because it is the most obvious place to look for a command
injection on a device like this. Its parameter expansion escapes the full shell metacharacter set,
including the parentheses, which blocks the `python -c` style injection that a weaker escaping routine
would permit, and the one unbounded parameter type (`__full_line`) feeds a structured dispatcher rather
than a shell. The trace-route and name-lookup helpers are similarly closed by validation plus argument
arrays. Both were assessed and excluded; neither is claimed to be exploitable.

## 5. Sink Identification

### Sink Identification - the constructions

The first construction is recorded at `percepxion_client.py:2170`:

```python
# eos/modules/percepxion_client.py, PercepxionClient.connect_server()
result, self.reg_response = curl.register(data)                              # line 2168
...
os.system("webcontrol -r 0 -h " + self.reg_response["remote_access_host"]     # line 2170
          + " -s -p 443 -a " + self.reg_response["auth_token"]
          + " -d " + self.device_id + " &")
```

The second is the same pattern in the `status_update` thread at
`percepxion_client.py:2274-2281`, which additionally concatenates `auth_token` into a shell string, so
that field is injectable through that path as well. Both are `os.system` calls: the argument string is
passed to `/bin/sh -c`, and the shell therefore performs its own parse of everything the device
concatenated. A `$( )` inside `remote_access_host` is command substitution, executed while the shell
expands the argument, before `webcontrol` runs and independent of whether `webcontrol` succeeds. The
trailing `&` backgrounds the helper, and the recorded run shows that the substitution has already
completed by the time the helper's own noise appears.

### Sink Identification - why the shell wrapper is the whole defect

Nothing in this chain depends on a parser bug, a buffer, a race or a privileged helper with an
unusual argument grammar. The device built a command string out of network data and gave it to a
function whose documented behaviour is to run a shell. Any value in that string that the shell
recognises as syntax becomes syntax. Sanitization is absent, quoting is absent, and the value is never
validated as a hostname or as a token.

### Sink Identification - execution identity

`/etc/init.d/eos_launcher.init:34` sets `procd_set_param user root` for the daemon, and the launcher
configuration carries `USERNAME: 'root'` at line 83, so the Python process that reaches `os.system` runs
as root on the appliance. The marker evidence from the replication (`uid=0(root) gid=0(root)
groups=0(root)`, file owned `root:root`, 39 bytes) is consistent with that identity, and the identity
itself is established statically from the init script rather than inferred from the marker.

## 6. Source Identification

### Source Identification - the registration response

The source of the injected value is the JSON body returned by the enrollment endpoint. `curlConnection`
(`percepxion_client.py:615`) performs a real pycurl POST to
`http{secure}://{HOST}:{PORT}/api/v1/device/register`, with `FOLLOWLOCATION`, a 60-second timeout, and
`SSL_VERIFYPEER` / `SSL_VERIFYHOST` controlled by the `VALIDATE_CERTIFICATES` setting. It parses the body
as JSON into `reg_response`. The registration is treated as successful when the parsed object carries
neither a `status` of 400 or 401 nor a `code` key; the recorded responder needed nothing more than a 200
and the two fields:

```
POST /api/v1/device/register HTTP/1.1
Content-Type: application/json

{"device_id": "LSS2200-TEST-DEVICE"}

HTTP/1.1 200 OK
Content-Type: application/json

{"remote_access_host": "$(id>/tmp/marker_px_root)x", "auth_token": "attacker-token",
 "entry_id": "entry-1", "project_id": "proj-1", "tenant_id": ["tenant-1"],
 "telemetry_mqtt_host": "127.0.0.1"}
```

### Source Identification - how the responder is selected

The host the device talks to is not chosen by the device at runtime; it is a stored configuration value
written through `PercepxionConnectionConfig` (`percepxion_v1.py:321`, POST handler at line 366, gated by
`@jwt_required()` and `check_group_auth`). The settings the chain uses are `HOST`, `PORT`,
`SECURE_PORT` and `VALIDATE_CERTIFICATES`; setting `SECURE_PORT` false makes the registration plain
HTTP, and setting `VALIDATE_CERTIFICATES` false removes certificate checking, which matters when the
responder is reached over HTTPS. The YANG model that types the setting, `ltrx-eos-percepxion.yang:212`,
declares `host` as a string of length 0..256 with no character restriction and with a source comment
marking the type as not yet restricted, so the appliance accepts an arbitrary host value - including one
chosen so that a `$( )` payload will survive JSON encoding and reach the sink intact.

### Source Identification - properties of the value that matter

The payload must survive three encodings on its way to the shell: JSON string escaping in the response,
Python string concatenation with its neighbours on the command line, and the shell's own parse. In the
recorded vector the value is `$(id>/tmp/marker_px_root)x`, and each part has a reason: `$( )` supplies
the substitution container, the redirection writes the marker, the path must contain no whitespace
because the value is unquoted inside a shell word, and the trailing `x` keeps the `-h` argument non-empty
after substitution so that `webcontrol` receives a syntactically ordinary command line.

## 7. Data Flow

### Data Flow - end to end

1. An authenticated administrator issues the Percepxion configuration change over the REST API:
   `HOST` set to an attacker-controlled address, `PORT` set to the responder's port, `SECURE_PORT`
   false, `VALIDATE_CERTIFICATES` false. The request carries the JWT and passes `check_group_auth`.
2. The EOS configuration is written; the YANG-typed `host` leaf accepts the value because nothing in the
   model constrains its characters.
3. The root daemon `percepxion_client` picks the change up - on its periodic cycle and on configuration
   change - and calls `connect_server()`.
4. `connect_server()` calls `curl.register(data)`, which POSTs to
   `http{secure}://{HOST}:{PORT}/api/v1/device/register` with the device identifier in the body.
5. The attacker's responder returns a 200 with a JSON body carrying `remote_access_host` (and
   `auth_token`) and no error markers, so `register()` classifies the answer as SUCCESS.
6. `reg_response` now holds attacker-chosen strings. `connect_server()` concatenates
   `remote_access_host` into the `-h` argument of the `webcontrol` command line and `auth_token` into the
   `-a` argument, and passes the result to `os.system`.
7. `/bin/sh -c` parses the string. The `$( )` in the `-h` argument is command substitution: the shell
   runs the embedded command as the daemon's user, which is root, and substitutes its output into the
   argument.
8. `webcontrol` then starts (and is backgrounded by the trailing `&`), exactly as the code intended -
   after the injected command has already run.

### Data Flow - properties worth naming

The two hops are separate trust decisions and the device gets both wrong in the same way. At the first
hop it trusts the administrator's endpoint value without a grammar; at the second it trusts the endpoint's
answer without a grammar. The daemon then re-enters the boundary a third time by asking a shell to decide
what the answer means. The result is that the security of the provisioning channel depends on the
honesty of whoever terminates it - an inversion of the direction trust is supposed to flow - and that
the periodic timer converts the configuration change into repeated execution opportunities rather than a
single event.

## 8. Exploit Construction

### Exploit Construction - the configuration request

The chain starts with one ordinary authenticated request. The device's session token is obtained through
its own login flow and is passed as `Authorization: Bearer <jwt>`; the body carries the four settings in
the vocabulary the record states for this resource:

```
POST <PercepxionConnectionConfig path> HTTP/1.1
Host: <appliance>
Authorization: Bearer <administrator JWT>
Content-Type: application/json

{"HOST": "<attacker host>", "PORT": 8443, "SECURE_PORT": false, "VALIDATE_CERTIFICATES": false}
```

The responder then answers the device's registration POST with the JSON shown in section 6. The PoC in
`exploit/lantronix_lss2200_percepxion_poc.py` implements both sides: it starts the responder, posts the
configuration, and waits for the device's registration request, reporting when the daemon has taken the
bait.

### Exploit Construction - payload engineering

The value has to be a legal JSON string, a legal fragment of a shell command line, and non-empty after
substitution. Those constraints produce the recorded shape:

- `$( )` rather than a separator: the value lands inside the `-h` argument of a command the device is
  already building; command substitution needs no statement separator, so the injection does not depend
  on the shell still being in "argument" position after a `;`
- execution at expansion time: the substitution runs while the shell builds the argument list, before
  `webcontrol` exists as a process, so the injected command completes even if the helper fails to
  connect - which the recorded run shows it did, since the injected host was nonsense
- the trailing `x`: it keeps the `-h` argument non-empty and syntactically valid after substitution
- no whitespace in the marker path: the value is unquoted in a shell word, so the redirection target must
  not split the word
- a body with no `status` and no `code`: the device's success test is the absence of those markers, so
  the responder has to look like a happy enrollment, not like an error

### Exploit Construction - what the PoC deliberately does not do

The PoC performs exactly one action on the device: it causes a marker file to be written containing the
output of `id`. It does not delete files, stop services, change accounts, install anything or alter the
configuration again after the request. It also carries a `--replay` mode that reproduces the recorded
laboratory verification locally, without any device, so that the claim can be re-checked in a sandbox: the
responder is stood up on loopback, the registration POST is performed, the recorded `os.system` line is
executed verbatim, and the marker is read back. `--target` defaults to a documentation address
(192.0.2.10) rather than a real host, and no credential is embedded in the script - the operator supplies
the JWT on the command line.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

The verification ran on a cloud-hosted Linux machine (x86-64) against the appliance's own root
filesystem, not against appliance hardware. The second partition of the disk image was copied to a
writable file and mounted, `/proc`, `/dev` and `/sys` were bind-mounted into it, and the resulting tree at
`/tmp/lss_chroot` was entered as root, sharing the host network namespace. The vulnerable Python inside
that tree is architecture-independent, so no instruction-set emulator was needed for it. The recorded
script is pure standard library, English-only on stdout under `LC_ALL=C`.

### Dynamic Verification - the recorded run

```
$ ssh root@<verification-host> 'fuser -k 8443/tcp; cp /tmp/02_exploit.py /tmp/lss_chroot/tmp/02_exploit.py; \
      chroot /tmp/lss_chroot /usr/bin/python3 /tmp/02_exploit.py'
[*] Lantronix LSS2200 Percepxion remote_access_host command injection (CWE-78)
[*] Starting fake Percepxion register server on 127.0.0.1:8443
[*] POST register -> 127.0.0.1:8443/api/v1/device/register
[*] register result: SUCCESS
[*] server-controlled remote_access_host: '$(id>/tmp/marker_px_root)x'
[*] server-controlled auth_token:        'attacker-token'
[*] Executing EXACT os.system sink (percepxion_client.py:2170)
[*] Checking marker /tmp/marker_px_root
[*] MARKER_CONTENT: uid=0(root) gid=0(root) groups=0(root)
[+] VERDICT: ROOT_RCE_CONFIRMED (uid=0 root via os.system injection)
=== EXIT_CODE=0 ===
```

The marker was then inspected from the verification host:

```
$ cat /tmp/lss_chroot/tmp/marker_px_root
uid=0(root) gid=0(root) groups=0(root)
```

It was a regular file owned `root:root`, 39 bytes, containing the output of `id`, written by the
substituted command rather than by any part of the harness. The `webcontrol` helper's libuv/lws notices
and its trailing connection error are noise: the substituted host did not exist, so the helper failed
after the substitution had already completed, which is exactly the ordering the payload relies on.

### Dynamic Verification - the second pass through the real client code

The run above reproduces the sink line but not the HTTP client around it. A second harness therefore used
the real `curlConnection` class from `eos.modules.percepxion_client` - pycurl, the real request
construction, the real response parsing - against the same local responder, and executed the same sink
line. The result was identical: `register result: SUCCESS`, the same two attacker-chosen values in
`reg_response`, and a marker containing `uid=0(root) gid=0(root) groups=0(root)`. The responder's log
confirmed that the request had genuinely been issued by the client code
(`POST /api/v1/device/register`, body carrying the device identifier), so the parsing path that feeds the
sink is exercised, not simulated.

### Dynamic Verification - negatives, stated honestly

What the record establishes is a positive result and the identity of the writer. It does not contain a
recorded benign-payload control run: the script exits non-zero when the marker is absent (exit 3) or
present without a `uid=0` prefix (exit 2), but those branches were not exercised in the recorded run, so
this advisory does not claim a measured negative control. What it does claim is bounded and specific:
inside a replication environment, with the recorded sink line and the recorded response, the injected
command ran with uid 0 and produced the marker. No claim is made that a physical LSS2200-8P was driven,
that the REST configuration step was exercised against hardware, or that any behaviour outside the
recorded run was observed.

## 10. Reachability and Security Impact

### Reachability - network position

The initial step is an authenticated REST request to the management interface, so the attacker needs
either administrator credentials or a way to have an administrator make the change, plus network reach to
the appliance's HTTPS interface. The second step is outbound: the appliance must be able to reach the
responder on the configured host and port, which is an ordinary property of a device that is designed to
enrol with a cloud service, and which an attacker sitting inside the management network can satisfy
without any egress at all. The injection itself needs no further interaction: the daemon retries on its
timer, so the sink is reachable repeatedly once the endpoint is set.

### Reachability - impact in concrete terms

Root command execution on a serial console server is a management-path compromise. The appliance exists
to give its administrator console access to the devices cabled to its ports, and root on the appliance is
the authority mediating that access and the records of it. Concretely, an attacker with this capability
holds the appliance's configuration store and any credentials in it, can change how the appliance
presents its ports and what it reports, can disable or degrade the services it offers, and can persist
through the mechanisms any embedded Linux root account can use, up to the limits of the writable
filesystem. The compromise is quiet: the device-side events are an ordinary configuration update and an
ordinary enrollment callback, both inside the legitimate provisioning flow.

Not claimed: escape from the appliance to the devices on its serial ports, survival of a factory reset or
reflash, and any memory-corruption primitive. The impact statement is bounded by what the recorded
evidence and the source review support.

## 11. Fix Recommendations

1. Remove the shell. Invoke `webcontrol` with an argument vector (`subprocess.run([...])` or an
   `execv`-family call) instead of `os.system`, at both `percepxion_client.py:2170` and
   `percepxion_client.py:2274-2281`. This removes the class rather than a character set
2. Validate the response as data before use: `remote_access_host` against a hostname or address grammar
   (or parsed into an address object), `auth_token` against the alphabet the protocol needs. Reject the
   answer and log it when validation fails
3. Enforce service authentication: refuse `VALIDATE_CERTIFICATES = False` for a cloud connection, pin the
   expected service identity, and constrain `HOST` in `ltrx-eos-percepxion.yang` to an allowlisted domain
   or an explicit address instead of the unrestricted 0..256 string recorded at line 212
4. Fix both sinks in the same change. The `status_update` construction is the same defect and patching
   `connect_server()` alone leaves an equivalent path
5. Reduce privilege: the connection client needs outbound HTTP and a little state, not root. Run it under
   a dedicated account and expose the helper through a narrow interface
6. Add regression tests that feed the two functions a response containing `$(true)`, the backtick form
   and the semicolon form, and assert no shell invocation and a rejected value; cover both sinks
7. For operators, until a fix ships: disable the cloud connection where it is unused, keep certificate
   validation on where it is used, and restrict reach to the management interface to a dedicated
   administration network

## 12. CWE

CWE-78, Improper Neutralization of Special Elements used in an OS Command ("OS Command Injection"), is
the correct primary classification. The device constructs a command line by concatenating a value that
originates outside the trust boundary - a field of a network response - and passes it to `os.system`,
which by definition hands the string to a shell. The neutralization that CWE-78 describes is missing at
every layer: no character screening on the field, no quoting when the command is assembled, and no
argument-array interface that would keep the value out of a shell parse.

Two neighbouring classifications were considered and are not used as the primary. CWE-20, Improper Input
Validation, describes a contributing condition - the `host` leaf's unrestricted 0..256 string at
`ltrx-eos-percepxion.yang:212` and the absence of any grammar check on the response - but on its own it
understates what happens: the value does not merely fail validation, it is interpreted as code. CWE-77,
Improper Neutralization of Special Elements used in a Command, is the parent class and would be the
fallback if the shell context were disputed, which it is not: the recorded call is `os.system`. The
second sink at `percepxion_client.py:2274-2281` is the same weakness through the same data, with
`auth_token` added, and belongs to the same CWE-78 entry rather than to a separate finding.

---

Written by the 0day Rubbish Research Team.
