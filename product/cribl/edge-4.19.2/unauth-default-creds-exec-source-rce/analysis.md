# Cribl Edge 4.19.2-89cac507 - unauthenticated remote code execution through factory-default admin credentials and the Exec Source command field

## 1. Overview

### Overview of the finding

Cribl Edge is the closed-source edge-collection product of Cribl, Inc. It receives events from input
sources and routes them onward to destinations, and it does that from hosts and edge locations that the
operator controls. The build analyzed here is `4.19.2-89cac507`, distributed as
`cribl-4.19.2-89cac507-linux-x64.tgz`: 2729 archive entries, no license file, a self-contained tree that
unpacks into an installation home and runs as a single-instance process. The management plane of that process
is an HTTP API. The configuration the product writes for itself, `cribl.yml`, carries `api.host: 0.0.0.0`
and port 9000, so a fresh installation answers on port 9000 of every address the host holds, in the
standalone, bucket and Edge Node shapes alike.

The finding is that two product decisions compose into unauthenticated remote code execution. The first is
the credential: the API is guarded by a pair the product ships, `admin` / `admin`, and nothing in the request
path forces a replacement before the API answers. The login route `POST /api/v1/auth/login` returns HTTP 200
and a JSON Web Token, and the response body also carries `forcePasswordChange:true` - a flag that turns out to
be advisory, because the token issued with it is accepted by every administrative route exercised during this
research, including the route that creates input sources, with no authorisation failure anywhere. The second
is the feature: the same API manages input sources, and its `exec` type takes a `command` field that the
product runs as a shell command on a recurring schedule. Vendor documentation states that the field "supports
Bourne shell syntax" and that the companion `script` field can feed multi-line standard input to an
interpreter, citing `python3 -` and `powershell -` as examples.

Neither decision is a bug on its own. A collector that can run an operator-supplied command is a legitimate
product capability, and a first-boot credential is a common convenience. The defect appears where they meet:
because the only thing standing between an anonymous network peer and that capability is a credential the
product publishes about itself, the "administrator-only" property of the exec source is satisfied by anyone.
The shell execution is intended; the audience is not.

### Overview of the verification shape

Verification was end to end. The shipped archive was unpacked into a disposable Debian bookworm container on
a cloud host, the container was started with no external network and no published ports, and the API was
reached through a tunnel bound to `127.0.0.1`. Every request in the chain travelled the product's own HTTP
stack, its own login route and its own input-management route, the product's own scheduler then executed the
command, and the effect was read from the container filesystem. Two independent runs, with different input identifiers and different command
strings, each produced a 39-byte marker, which is the byte length of the output of `id`.

One boundary statement belongs at the top of any reading of this advisory. Root was observed inside the
replication environment - the container - and that is the exact scope of the dynamic claim. A customer
deployment's identity is an inference from the vendor's documented systemd unit mode, which runs the Cribl
Edge process as root; it was not measured on customer hardware here, and section 9 keeps the measured and the
inferred halves of the identity claim in separate paragraphs.

### Overview of what the record does and does not establish

The record establishes, dynamically: that the factory pair authenticates, that the returned token is accepted
on the input-management route, that the input is persisted to `$CRIBL_HOME/local/cribl/inputs.yml`, that the
scheduler executes the `command` field, that the resulting process identity inside the replication container
is root, and that the behaviour repeats across two independent payloads. It establishes, by documentation
reference: that the `command` field is shell syntax and that the `script` field accepts multi-line input. It
does not establish: which release introduced the factory credential pair, whether the same chain works on
builds older than `4.19.2` (vendor documentation places Exec Source in the `3.2.x` line, and the compatibility
line down to that generation was not tested), or what identity the process holds in any specific customer
deployment. Those three gaps are stated wherever they bear on a claim.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Cribl, Inc. |
| Product | Cribl Edge, closed source |
| Version analyzed | `4.19.2-89cac507` |
| Artifact | `cribl-4.19.2-89cac507-linux-x64.tgz`, 2729 entries, license-free |
| Installation shape | single instance, unpacked into an installation home, `local/cribl` generated at first run |
| API binding | `api.host: 0.0.0.0`, port 9000, written by the product into `cribl.yml` |
| Authentication scheme | JSON Web Token from `POST /api/v1/auth/login`, presented as a bearer token |
| Factory credential | the pair `admin` / `admin` |
| Forced rotation | none on the request path; `forcePasswordChange:true` is returned but not enforced |
| Login rate limit | two attempts per second; the corresponding rejection was measured |
| Configuration route | `POST /api/v1/system/inputs` |
| Sink | the `command` field of an `exec`-type input, run as a Bourne shell command |
| Scheduler | `scheduleType: interval` with `interval` in seconds |
| Execution identity | the Cribl Edge process; `uid=0(root)` observed inside the replication container |
| Observed marker | 39 bytes at `/tmp/CRB-PWNED-D11` and at `/tmp/CRB-PWNED-1` |
| Primary CWE | CWE-78 |
| Adjacent CWE | CWE-798 |
| Published score | 9.8 Critical - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

The chain has four links, and the record carries dynamic evidence for each of them.

```http
POST /api/v1/auth/login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"admin"}
```

The reply is HTTP 200 with a JSON Web Token; in the recorded run the token string was 177 characters. The
body also carries `forcePasswordChange:true`. The token is used unchanged for the second request:

```http
POST /api/v1/system/inputs HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/json
cache-control: invalidate=/system/inputs*

{"id":"probeExec","disabled":false,"type":"exec","command":"id > /tmp/CRB-PWNED-1","scheduleType":"interval","interval":10}
```

The reply is HTTP 200 with an echoed item. The product then writes the source into
`$CRIBL_HOME/local/cribl/inputs.yml` and its scheduler picks it up; the record measured a 245-byte
`/c/local/cribl/inputs.yml` on disk after the request. Within the first interval the `command` string was
executed by a shell, and the redirect the attacker chose created the marker. Reading that marker returned
`uid=0(root) gid=0(root) groups=0(root)`.

The mechanics matter more than the sequence. There is no injection into a query string, no deserialization
step, no template evaluation and no memory corruption anywhere in the chain: both requests are ordinary,
well-formed JSON over HTTP, and both are answered with 200. The only thing the attacker has to know is a
credential the product publishes, and the only thing the attacker has to do is use a documented field for
what it is documented to do.

### Vulnerability Summary preconditions

1. The attacker can reach TCP port 9000 on the host. In a default installation that is any network that can
   route to the host, because `api.host` is `0.0.0.0`.
2. The installation still holds the factory credential pair, which is the state of every fresh installation
   and of any installation whose operator never replaced the password.
3. Nothing else. There is no precondition on the attacker's identity, no prior access to a source or a
   destination, no browser, no victim action and no timing window.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The gate on the management API is a bearer token from `POST /api/v1/auth/login`. The route accepts a JSON body
with a user name and a password, and on success returns HTTP 200 with a token that the remaining routes accept
in an `Authorization: Bearer` header. Two additional controls sit on the same route: a rate limit of two
attempts per second, whose rejection was measured during the research, and the `forcePasswordChange:true`
field in the response body.

The rate limit is not a control against this chain. The chain needs exactly one successful login per
execution, and one attempt against a published credential is not a guessing problem; a two-per-second ceiling
costs the attacker nothing at all. The `forcePasswordChange` field is not a control either, and this is the
measured part of the finding: routes for `packs`, `system/settings`, `system/users`, `system/keys` and
`system/inputs` were each exercised with the token returned alongside that flag, and each answered 200, or
500 past the authentication layer, and never 401. A rotation prompt that the server does not act on is a
message to a human, and the attacker is not a human cooperating with the message.

### Authentication Boundary - what the chain does not do

- It does not bypass authentication. The login route is used as designed, with a credential the product
  ships.
- It does not defeat the token scheme, forge a token, guess a secret or exploit token validation. The token
  is genuine and is validated correctly; the problem is who could obtain one.
- It does not need a browser, an interactive session, cross-site request forgery or a stolen cookie. Both requests
  are made directly by the attacker's own HTTP client.
- It does not depend on a second factor that is absent, a misconfiguration outside the product's defaults, or
  an expired certificate. Everything in the chain is the product's shipped state.
- It does not read, crack or reuse any operator-chosen password; the credential it uses is the factory
  default, identical across installations.

### Authentication Boundary - why that boundary does not soften the impact

It is fair to ask what an attacker gains, given that the entry point is described as an administrator feature.
The answer is the difference between a credential that identifies an operator and a credential that
identifies the product. The API is designed so that a party holding the administrator credential may manage
input sources, and one of the input types runs a command. When the credential is a factory default that the
product neither rotates nor withholds, the population holding it is "everyone who can reach the port", and
the administrative feature becomes an anonymous remote code execution primitive. The boundary that matters is
not the token check - which behaves correctly - but the issuance of the token to a party whose only
qualification is knowing a published string. That is the crossing this chain performs, and it is a crossing
from unauthenticated network access into the authority of the service account.

## 4. Attack Surface

### Attack Surface - the API and its dispatch model

The attack surface is the management API on port 9000. The routes exercised here are small in number and
uniform in shape: a login route that returns a bearer token, a health route that reports process liveness, and
a set of administrative routes, of which the input-management route is the one that matters. The route used
is `POST /api/v1/system/inputs`, and its body is a JSON object describing a source: an identifier, a disabled
flag, a type, and the type's own parameters. The `exec` type's parameters are a `command` field and a
scheduling policy.

The dispatch model is the important part of the surface description: the API does not treat an input
definition as data to be interpreted later by a constrained engine. For the `exec` type it treats the
`command` field as a program to run, on the schedule the definition names. The product's own documentation
states the field "supports Bourne shell syntax" and offers the companion `script` field for multi-line
standard input with interpreter examples such as `python3 -` and `powershell -`. The surface therefore ends,
by design, at the host's shell.

### Attack Surface - why the audit narrowed here

An API of this size has many administrative routes, and most of them are interesting only to an attacker who
already holds a session. The question the audit asked of each route was narrow: does it require anything
beyond the factory credential, and does it reach the host's shell? Two properties had to coincide, and in this
product they coincide on the input-management route alone:

- The route must be reachable with the token that the factory credential produces. Measured: it is, with no
  intermediate authorisation step.
- The route must accept a value that the product later executes rather than interprets. The `exec` source
  type's `command` field is exactly that; the field's documented semantics are shell semantics.

### Attack Surface - components that narrowed out

- The token issuance route is not itself a vulnerability: it validates credentials correctly and it rate
  limits attempts. Its contribution to the chain is that the credential it accepts is published.
- The remaining administrative routes exercised during the research (`packs`, `system/settings`,
  `system/users`, `system/keys`) answered with the same token and are relevant to the impact discussion - they
  are what an anonymous party can reach after the first request - but they are not needed to obtain execution.
- Surfaces outside the API were not exercised and are not part of this chain; the exec source needs no
  traffic of its own to fire, only the scheduler, which the product runs on the input's interval.
- Nothing in the chain depends on a parsing defect, an unusual encoding, a header quirk or a malformed body.
  Both requests are ordinary instances of the API's own schema.

## 5. Sink Identification

### Sink Identification - the exec source command field

The sink is the `command` field of an input of type `exec`. The product persists the value into the
installation's input configuration and its scheduler then executes it with shell semantics on the interval
the definition specifies. The record measured the persistence and the execution separately: first the write
of `/c/local/cribl/inputs.yml` at 245 bytes, then, inside the first scheduling interval, the marker file the
command created.

```yaml
inputs:
  probeExec01:
    disabled: false
    type: exec
    command: id > /tmp/CRB-PWNED-D11
    scheduleType: interval
    interval: 10
    sendToRoutes: true
    pqEnabled: false
    streamtags: []
    retries: 10
    staleChannelFlushMs: 10000
```

The block above is the on-disk record of the second run, read from the container filesystem. It is worth
reading closely, because it is the whole exploit in the product's own configuration format: the field name
`command`, the unmodified attacker string, and the scheduling parameters that make the value fire without
further interaction. The product normalises the definition - `sendToRoutes`, `pqEnabled`, `streamtags`,
`retries` and `staleChannelFlushMs` are filled in by the product, not by the request - but it does not
sanitise, quote or restrict the command string.

### Sink Identification - what kind of sink it is, and what it is not

This is not a memory-safety sink, not a parser-confusion sink and not a sink that becomes reachable through a
malformed request. It is a documented execution surface whose contract is "the operator's command text is run
by a shell", and the product honours that contract exactly. That framing matters for remediation: there is no
escaping bug to patch at the sink, because the sink is the feature. What can be fixed at the sink is who is
allowed to reach it and what identity it runs under; what must be fixed at the head of the chain is the
credential boundary.

### Sink Identification - execution identity and the scheduling property

`exec` children inherit the identity of the Cribl Edge process. In the replication container that identity was
root, and the marker's content - `uid=0(root) gid=0(root) groups=0(root)` - is direct evidence of it. On a
bare-metal installation the vendor documents a systemd unit mode that runs the product as root; the record
treats that as the expected same-authority case rather than as a measurement, and this advisory does the same.

The scheduler adds a property that plain command execution does not have: the value is not a one-shot
payload. An `exec` input with `scheduleType: interval` and `interval: 10` re-runs on its own schedule for as
long as the definition exists, so the effect of the single configuration request persists in the product's
own state, and observing it does not require the attacker to keep a connection open or to send a second
request.

## 6. Source Identification

### Source Identification - the request body

The source is the JSON body of `POST /api/v1/system/inputs`. Its fields are an input identifier, a disabled
flag, a type discriminator, a `command` string and a scheduling policy. Nothing in the record shows a filter
between that body and the executed command: the value arrives as JSON, is persisted verbatim into
`inputs.yml` as the `command` key, and is executed by the product's scheduler. There is no length limit, no
character-class rejection, no allowlist of executables and no quoting step recorded between the request and
the shell.

### Source Identification - the gate in front of the source

The only gate in front of the source is authentication, and it is satisfied by the factory credential. That
is the structural reason this finding exists: the source is attacker-controlled, the sink is a documented
shell, and the single control between them is a token that the product hands out to anyone who presents the
pair it ships.

### Source Identification - what the payload must respect

Almost nothing. The value is a shell command, so the payload author's constraints are the target shell's, not
the product's. In practice the payload used throughout this research is a one-line redirect: `id` writing to a
path under `/tmp`. The only product-side constraint the record establishes is that the definition must be
accepted by the input-management route, which it is when it carries an identifier, a type of `exec`, a
command and a scheduling policy. The `interval` value is also the attacker's choice and controls how soon the
command runs.

## 7. Data Flow

### Data Flow - end to end

```
[ATTACKER, network position]                 [HOST, Cribl Edge 4.19.2]

  POST /api/v1/auth/login
  {"username":"admin","password":"admin"}
        |
        v
  login route -> credential check against the factory pair   [accepted]
  <- HTTP 200, JWT (177 chars in the recorded run), forcePasswordChange:true

  POST /api/v1/system/inputs
  Authorization: Bearer <token>
  {"id":"probeExec01","type":"exec",
   "command":"id > /tmp/CRB-PWNED-D11",
   "scheduleType":"interval","interval":10}
        |
        v
  authorisation check with the same token                    [passes: no 401]
  input definition validated and echoed                      [HTTP 200]
  cache-control: invalidate=/system/inputs*
        |
        v
  persisted to $CRIBL_HOME/local/cribl/inputs.yml (245 bytes measured)
        |
        v
  scheduler fires on interval: 10
        |
        v
  Command field executed by a shell, as the Cribl Edge process identity
        |
        v
  /tmp/CRB-PWNED-D11 written, 39 bytes = output of id
  read back: uid=0(root) gid=0(root) groups=0(root)
```

### Data Flow - properties worth naming

- The taint never crosses a memory-safety boundary. It is string data travelling from a JSON body to a YAML
  document to a shell command line; there is no buffer, no length arithmetic and no parser state to corrupt.
- The decisive step is the product's own scheduling and execution of a value it was explicitly asked to store
  and run. No attacker machinery survives on the host: the shell that runs the command is the product's own
  shell invocation, launched on the product's own timer.
- The persistence step is what makes the chain quiet. The observable product events are a login, a
  configuration change and a scheduled execution - all first-class operations that the product expects to
  serve and, in the ordinary case, logs.
- The chain is idempotent in the attacker's favour: the input definition survives the request that created
  it, so the execution repeats on every interval without further traffic.
- Removing any single link breaks the chain, and the links are independent: fixing the credential boundary
  breaks it even though the exec feature is untouched; removing the exec capability breaks it even though the
  credential boundary is untouched.

## 8. Exploit Construction

The PoC shipped with this advisory is `exploit/cribl_edge_default_creds_exec_poc.py`. It is a single-file
client that uses only the Python standard library, takes `--target` and `--port`, defaults the target to a
documentation address (`192.0.2.10`) and the port to the product's default of 9000, performs the login,
creates one exec input and reads the health route after a wait long enough for the first scheduling interval.

### Exploit Construction - request shape

```python
base = "http://%s:%d" % (args.target, args.port)

status, body = call(base, "POST", "/api/v1/auth/login",
                    {"username": args.user, "password": args.password})
token = json.loads(body).get("token", "")

payload = {
    "id": "criblExecProbe",
    "disabled": False,
    "type": "exec",
    "command": "id > /tmp/cribl_exec_marker",
    "scheduleType": "interval",
    "interval": 10,
}
status, body = call(base, "POST", "/api/v1/system/inputs", payload, token=token)
```

The field names are the ones the product accepts, and the payload is the smallest definition that produces
execution: an identifier, `disabled` false, the `exec` type, the command, and an interval.

### Exploit Construction - payload engineering

The default command is a redirect of `id` into a file under `/tmp`, which is the least invasive proof of
execution available on a host the tester may not otherwise have shell access to. It writes one file, it reads
nothing sensitive, it changes no product configuration beyond the input the request itself creates, and its
39-byte result is trivially verifiable. Nothing about the mechanism requires clever construction: there is no
metacharacter to smuggle, no quoting to escape and no filter to bypass, because the field's documented
purpose is to carry shell syntax. The constraint that shapes the payload is therefore operational rather than
technical - keep the effect minimal and observable - and the PoC reflects that with a refusal to accept a
command containing destructive fragments, so a mistyped invocation fails on the operator's own machine rather
than on the target.

For an operator who needs more than a marker, the same single request carries any command the shell accepts,
and the `script` field documented for the same source type accepts multi-line standard input for an
interpreter. That is stated here for completeness; the PoC does not implement it, and this advisory ships no
second-stage payload.

### Exploit Construction - what the PoC deliberately does not do

- It does not brute-force, guess or harvest credentials. The factory pair is the product's shipped default,
  and it is the default value of the `--password` argument; an operator can override both fields.
- It does not enumerate the API, does not read configuration beyond the creation reply, and does not use any
  route other than login, input creation and health.
- It installs no persistence of its own. Persistence is a property of the input definition it creates, which
  the operator is expected to remove.
- It refuses destructive command fragments and an empty command, so its tests are non-destructive by
  construction rather than by operator discipline.
- It writes nothing to the local filesystem. Its only effect on the target is the marker file the default
  command redirects into.

## 9. Dynamic Verification

### Dynamic Verification - environment, stated exactly

| Element | Value |
|---|---|
| Verification method | end-to-end against the shipped product, inside a disposable container |
| Host environment | Debian bookworm container on a cloud host, no external network, no published ports |
| Product instance | `cribl-4.19.2-89cac507-linux-x64.tgz` unpacked to `/c`, standalone single instance |
| API binding inside the container | `0.0.0.0:9000`, the product's factory configuration |
| Access path | tunnel bound to `127.0.0.1` on the host, forwarded to the container's API port |
| Observation channel | marker files written by the executed command, read from the container filesystem |
| Control | a second, distinct input identifier and command; both runs produced the same 39-byte result |
| Boundary | root was observed inside this container; the customer-deployment identity is inferred from the vendor's documented unit mode |

The recorded invocation was:

```
python3 /root/d11/02.py --host 127.0.0.1 --port 29000 --cmd 'id > /tmp/CRB-PWNED-D11'
```

### Dynamic Verification - the recorded result

The transcript below is the ASCII rendering of the run record. The driver's own status lines were localised in
the original, one of them spelled the archive path `$CRIBl_HOME`, the record's ellipses are three dots here,
its arrows are rendered as `->`, its coloured hit marker is omitted, and the file listing's timestamp column
is elided. Every other byte - status codes, token length, the echoed body, the marker size and the identity
string - is as recorded.

```
[+] login OK http=200 token-len=177
[+] POST /api/v1/system/inputs -> HTTP 200
    body='{"items":[{"id":"probeExec01","type":"exec","command":"id > /tmp/CRB-PWNED-D11","interval":10,...}]}'
[+] Exec Source written to $CRIBL_HOME/local/cribl/inputs.yml, fires within 10s
[i] GET /api/v1/health -> HTTP 200 {"status":"healthy",...}
(16 s later, inside the container)
-rw-r--r--  39 /tmp/CRB-PWNED-D11
uid=0(root) gid=0(root) groups=0(root)
```

Two details in that transcript carry weight. The login answered 200 and the token it returned was 177
characters long, which is the length of a token the product treats as valid - not an error page, not a
redirect to a change-password form. And the creation route answered 200 while echoing the exec definition back
with the attacker's command string intact, which is the product confirming the write rather than rejecting it.

### Dynamic Verification - the second, independent run

The first probe used the identifier `probeExec` and the command `id > /tmp/CRB-PWNED-1`, and produced a
39-byte marker at that path. The second used the identifier `probeExec01` and the command
`id > /tmp/CRB-PWNED-D11`, and produced a 39-byte marker at its path. Two different input identifiers, two
different commands, the same result: the execution is a property of the mechanism, not of one particular
definition. The record treats the two runs as one vulnerability, since the root cause, the routes and the sink
are identical and only the payload strings differ.

The 39-byte size is itself a check. The output of `id` is a fixed-length identity string, and 39 bytes is its
length on this platform; a marker of that size whose contents are a root identity is not a coincidence of
file creation, it is the command's own output.

### Dynamic Verification - negatives, stated

- No customer deployment, no production host and no third-party system was involved: the product ran in a
  disposable container created for the test, with no external network and no published ports, and access was
  bound to `127.0.0.1` throughout.
- The root identity is a container observation. Nothing in this research measured the identity of the process
  in a customer's installation; the same-authority claim there rests on the vendor's documented unit mode and
  is labelled as inference, not as measurement.
- No version below `4.19.2` was tested. The `3.2.x` presence of Exec Source comes from vendor documentation,
  and the release that introduced the factory credential pair is not established here.
- No persistence, no privilege escalation beyond the process identity, and no change to the product's
  event-forwarding behaviour beyond the definition created were tested or claimed.
- The teardown of the container is part of the record: the tunnel was closed and the environment removed after
  the run, so no listening management port was left behind.

## 10. Reachability and Security Impact

### Reachability - network position

The API binds `0.0.0.0:9000` in the configuration the product writes for itself, and the record states that
the standalone, bucket and Edge Node shapes all ship that value. A default installation is therefore reachable
from any network that can route to the host: a flat internal network, a management segment, a cloud subnet
with a permissive security group, or the public internet where the port is exposed. This is not a
conditional reading that requires the operator to have enabled a remote-administration option; it is the
shipped default. That fact is what removes the "local only" argument from this finding, and it is also why
the score carries a network attack vector rather than an adjacent one.

The population affected is correspondingly broad: every installation of the analyzed build that still holds
the factory credential and has not bound the API to loopback. The record does not estimate a count, and this
advisory does not either.

### Reachability - impact in concrete terms

Command execution in the Cribl Edge process identity is, in practice, control of a host that sits in the
middle of an organisation's telemetry. Three consequences follow directly.

First, confidentiality: the process reads the `$CRIBL_HOME` tree, including the `local/cribl` configuration
store the product generates there, and the administrative routes for users, keys, packs and settings answer to
the same token the attacker holds.

Second, integrity of the configuration that steers the events: input definitions, including the
`sendToRoutes` behaviour, are configurable with the same token, so events leaving the collector can be
dropped, altered or redirected without any change to the systems that produce them. A collector sits between
the systems that produce events and the systems that consume them, and this chain hands an anonymous party
control of that position.

Third, availability and persistence: the process, its scheduled inputs and its local state can be
reconfigured or stopped, and the exec input's own interval makes re-execution a property of the product rather
than of the attacker's tooling. What survives a reinstall was not tested and is not claimed.

The one thing this finding does not need is a second vulnerability. Every step is a documented, first-class
product operation, performed with a credential the product itself publishes, and answered with success.

## 11. Fix Recommendations

1. Enforce the credential change on the server. `forcePasswordChange:true` is already emitted, so the intent
   exists; while the flag is outstanding, the token must authorise the credential-change route and nothing
   else, and every administrative route must refuse it. An advisory flag is not a boundary.
2. Generate the administrator credential instead of shipping one. A random value written at first start, or
   one supplied by the installer, refuses to open the API listener until it exists. A fixed `admin` / `admin`
   pair combined with a `0.0.0.0` listener is the entire precondition for this finding.
3. Bind the API to loopback by default. `api.host: 0.0.0.0` should be an explicit operator choice with a
   startup warning, not the value the product writes into a fresh installation.
4. Treat the exec source type as a privileged capability. Require an explicit enablement step separate from
   input creation, show it in the management interface as command execution rather than as one source option among many,
   and run exec children under a dedicated unprivileged identity. The environment-level switch that bears on
   exec sources exists but is not engaged in a default deployment, which is exactly why the chain works as it
   does; for installations that never need exec, that posture should be the default.
5. Do not rely on the login rate limit. Two attempts per second was measured and it is irrelevant here: the
   chain needs one attempt, against a credential the product publishes.
6. Add a startup exposure check: warn when the API listener is not loopback, and refuse to serve
   administrative routes while the account still holds a factory credential. Either check alone breaks this
   chain, and both are visible to the operator who runs the product.
7. For operators until a fixed build is available: replace the factory credential on every installation, bind
   the API to loopback or restrict port 9000 to trusted management networks, remove any `type: exec` input
   nobody intentionally created, and treat an unexpected `POST /api/v1/system/inputs` in the product's logs as
   a code-execution indicator rather than routine configuration churn.

## 12. CWE

### CWE - classification rationale

- CWE-78 (Improper Neutralization of Special Elements used in an OS Command) is the primary class, and it is
  the class of the effect: an attacker-supplied string reaches a shell and the shell executes part of it as a
  command. The mechanism is not a bug in the string handling - the product documents the field as shell
  syntax - but the outcome the attacker obtains is precisely CWE-78, and it is the outcome that a defender,
  a scanner and a patch process need to name.
- CWE-798 (Use of Hard-coded or Default Credentials) is the adjacent class, and it is the class of the cause:
  the API authenticates with a credential pair the product ships and does not force anyone to replace. It is
  where the repair belongs, because the execution surface is intended and the credential is not.
- The record's own annotation of the chain reads default credential, then improper authentication, then shell
  execution. CWE-287 (Improper Authentication) is the intermediate link in that annotation: the product does
  perform authentication, and it performs it correctly against a secret that is not secret, which is why the
  two endpoint classes above carry the finding rather than CWE-287 alone.
- CWE-94 (Improper Control of Generation of Code) was considered and not applied. The value is not evaluated
  as code in the application's own language; it is handed to the operating system's shell, which is the
  distinction between CWE-94 and CWE-78.
- CWE-306 (Missing Authentication for Critical Function) was considered and not applied. The critical function
  is not unauthenticated in the product's design - it is behind a login that works - and describing it as
  missing authentication would misdirect the fix toward adding a check that already exists rather than toward
  the credential lifecycle and the listener binding, which is what actually has to change.
- No memory-safety class applies, and none is claimed: this chain contains no buffer handling, no parser state
  and no corruption primitive.

---

Written by the 0day Rubbish Research Team.
