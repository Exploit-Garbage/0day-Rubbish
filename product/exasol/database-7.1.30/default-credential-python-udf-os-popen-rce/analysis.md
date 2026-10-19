# Exasol Database 7.1.30 (docker-db deployment form) — Shipped Default SYS Credential Reaching a PYTHON3 UDF `os.popen` Command Execution with Output Returned Through SELECT (command execution as uid=500(exadefusr) with root as a supplementary group; uid=0 was not reached and is not claimed)

## 1. Overview

### Overview of the finding

Exasol Database 7.1.30, examined in the `docker-db` single-container deployment form published by
Exasol AG (Germany), accepts the credential pair `sys` / `exasol` on its SQL service, and the
documentation that ships alongside that deployment form publishes the pair verbatim: the upstream
`docker-db` README states, under the heading `Connecting to the Database`, that a client can
"authenticate with username `sys` and password `exasol`". No initialisation flag, no environment
variable and no configuration entry is needed to obtain it, the initialisation path does not supply an
alternative SYS password hash, and the deployment performs no forced rotation, so the constant still
answers on a freshly initialised database that nobody has configured. `SYS` is the database
administrator. That administrator may create script objects, and the database's script engine runs a
`PYTHON3` scalar UDF body as ordinary Python with the standard library available, so a body that
calls `os.popen("<cmd>").read()` executes an operating-system command and a following `SELECT`
returns its stdout to the caller through the ordinary result set. Three independent detonations
against a running instance returned real system data, and the identity line reported by `id` was
`uid=500(exadefusr) gid=500(exausers) groups=500(exausers),0(root)`.

That identity is the whole of what was measured. It is not `uid=0(root)`, and this advisory does not
claim it. No escalation from `uid=500` with `gid 0` as a supplementary group to an effective root
identity was attempted, and the root group membership and the documented requirement for privileged
container mode are described below as an untested escalation position rather than as an achieved
outcome.

### Overview of the product and its deployment form

The product is Exasol's in-memory MPP analytical database. Its SQL engine is a proprietary C
implementation named EXASolution, the server process is `exacs`, and clients speak a proprietary
binary SQL protocol on port 8563 rather than HTTP; the vendor's own console client `exaplus` sits
under `/usr/opt/EXASuite-7/EXASolution-7.1.30/bin/Console/exaplus` inside the image. Three other
services are present in the same container: ConfD, an HTTPS JSON-RPC management daemon; BucketFS, an
HTTP file service; and an OpenSSH server. The image additionally carries the UDF framework, which the
upstream README lists among the deployment's "Currently supported features" as "use the UDF
framework".

The deployment form examined here is the container image, and three statements the vendor makes about
that form belong in the advisory because they bound it rather than enlarge it. The upstream
repository warns that the docker distribution "is an open source project that is __not officially
supported__ by Exasol"; that the underlying base image is an end-of-life CentOS 7 release, that
"official support for docker-db 7 is no longer available" and that users should move to a newer
release line; and that the repository "only contains __documentation__" now while the binaries are
distributed through Docker Hub, with issues disabled because the project is "mainly intended for
automatic testing of Exasol deployments". None of that reduces the mechanism - the credential is a
property of the shipping database and the script engine is a supported core feature - but it does mean
that no patch is going to arrive for this image, which raises the operator's exposure rather than
lowering it, and it means the operator-side mitigations in section 11 carry more weight than they
would for a supported release.

### Overview of what the vendor's own artifacts establish

Two load-bearing claims in this advisory are hung on product artifacts rather than on the state of
the instance used for verification, because a default-configuration claim built from a research
instance is not evidence about the product.

- The credential claim is established twice over. The upstream `docker-db` README publishes
  `sys` / `exasol` as the way to connect to the database inside the container. Image-internal test
  scripts recorded from the running container use the same pair on the same port:
  `basic_test.sh:112` carries `$X -c n11:8563 -u sys -P exasol -jdbcparam validateservercertificate=0`,
  and `basic_sc_test.sh:98` uses `-u sys -P exasol` as well. Those two files are not in the current
  upstream repository, which now carries documentation only, so they are cited as artifacts observed
  inside the 7.1.30 image at
  `/usr/opt/EXASuite-7/EXAClusterOS-7.1.30/docker/test/`, not as repository contents.
- The exposure claim could not be established in the form the research notes originally asserted, and
  section 4 states exactly what happened to it. In short: the listener inside the container binds all
  interfaces, which was observed; the documented stand-alone run publishes that port on loopback only;
  the documented multi-node run uses host networking, under which the vendor notes that all ports are
  "accessible on the host"; and no shipped artifact establishes that a single-container deployment
  binds 8563 on `0.0.0.0` by default. The reachability metric was derived from that artifact set, not
  from the researcher's harness.

### Overview of the testbed and of what that implies

Verification ran against one container instance built from the vendor's image on an isolated cloud
sandbox, started with the privileged flag the vendor's README says is required ("Docker privileged
mode is required for permissions management, UDF support and environment configuration and
validation"), with its data directory mounted from the host and its SQL port published onto the host
loopback only. The three detonations drove the vendor client inside the container against the
container's own loopback at 8563. No step of the chain was driven from a separate network host. That
is stated again in section 9 and it is the reason the headline Attack Vector is Adjacent rather than
Network.

Our notes record the host-side port publication inconsistently across two files - one records the
container port as 8562, the other as 8563 - and because every measured leg ran through the container
loopback that discrepancy is not load-bearing for anything claimed here. It is recorded so that the
reader can see the boundary of the evidence rather than infer it.

### Overview of affected scope

Only 7.1.30 in the docker deployment form was executed. The mechanism - a documented constant SYS
credential plus an unrestricted script language in the UDF engine - is a property of the EXASolution
database rather than of the container packaging, so other 7.1.x releases and the non-container
installation are plausibly affected; they were not tested and are not claimed here. The vendor's newer
release line was not examined.

### Overview of independence

The chain needs no second vulnerability, no memory corruption, no deserialisation gadget, no file
upload and no local foothold. Leg one is a documented product constant. Leg two is a documented
product feature. What makes the pair a vulnerability is that the product neither rotates the constant
nor restricts what a holder of it may execute.

## 2. Vulnerability Summary

### Vulnerability Summary table

- **Product**: Exasol Database, docker deployment form, version 7.1.30
- **Vendor**: Exasol AG (Germany)
- **Component**: the EXASolution SQL service on port 8563, its `SYS` database account, and the UDF
  script engine's `PYTHON3` language
- **Root cause 1**: a deployment-invariant default credential that the vendor documents and that
  nothing rotates or forces to change (CWE-1392, CWE-798)
- **Root cause 2**: a script engine that hands the SQL caller unrestricted Python, including the `os`
  module and therefore `os.popen` (CWE-94, reaching CWE-78)
- **Authentication**: none required beyond the constant; negative control confirms that wrong
  passwords are refused with `[28000] authentication failed`
- **Sink**: `os.popen("<attacker command>").read()` inside a `PYTHON3` scalar UDF body
- **Source**: the `CREATE ... SCALAR SCRIPT ... AS` statement body, submitted over the binary SQL
  protocol as `sys`
- **Output channel**: the UDF's return value, delivered by the `SELECT` result set - execution is not
  blind
- **Measured identity**: `uid=500(exadefusr) gid=500(exausers) groups=500(exausers),0(root)`
- **Verification**: three live rounds, all returning real system data
- **Recorded CVSS**: 8.8 High, `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, computed here from the
  vector

### Vulnerability Summary mechanics

The attacker connects to 8563 and authenticates with a value read out of the vendor's documentation.
The server certificate is self-signed and carries no subjectAltName, so the vendor client needs the
SHA256 fingerprint of the presented certificate embedded in its connection string as
`host/FINGERPRINT:port`; that fingerprint comes from an unauthenticated TLS handshake and is therefore
not a barrier. Once authenticated as `SYS`, the attacker submits four statements: create a schema,
open it, create or replace a `PYTHON3` scalar script whose `run(ctx)` body pops a command and
returns its output behind a marker, and select the script. The engine terminates the script body at a
line containing only a forward slash, which is why the payload in section 8 has that terminator. The
result set carries the command's stdout back to the caller.

### Vulnerability Summary preconditions

- Port 8563 reachable from the attacker's position. Inside the container the listener binds all
  interfaces; reaching it from another host requires a deployment choice, which section 4 documents
  in both of its vendor-described forms.
- The SYS password still at its shipped value. This is the only precondition that an operator
  controls, and it is the precondition that section 12 turns into a labelled conditional reading.
- Nothing else. No prior account, no local access, no user interaction, no race window and no second
  service.

### Vulnerability Summary - why the two legs are separable but jointly decisive

Leg one on its own is a data breach: `SYS` over the SQL protocol already reads every warehouse table,
writes every schema and stops the database. Leg two on its own is a documented feature: an
administrator who can create scripts is meant to be able to run Python. Neither leg is interesting
separately in the way the pair is. What the pair produces is an entry point that requires no
provisioning decision by the defender - nobody ever created the account the attacker uses - and that
converts SQL-layer administrative access into operating-system command execution inside the
deployment, with the command's output returned in-band so no exfiltration channel needs to be built.

## 3. Authentication Boundary

### Authentication Boundary - the four remote authentication surfaces

The container presents four listeners. Each was characterised, and three of them are not the door.

- **EXASolution 8563** - the binary SQL protocol. Authentication is a username and password pair.
  This is the only surface whose credential is a shipping constant.
- **ConfD 443** - HTTPS JSON-RPC management, authenticated with `Authorization: Bearer <token>`. The
  token is the `AuthenticationToken` field of `EXAConf` and is generated per deployment as a random
  string, so it is not guessable and not constant. It is not a door.
- **BucketFS 2580** - HTTP file service on the listener observed in the running container; the image's README documents 2581 as the default BucketFS port inside the container for HTTPS. The `default` bucket is `Public=True`, which yields
  unauthenticated read listing; a write attempt returned `403` because the bucket `WritePasswd` is
  likewise a per-deployment random, and a path traversal attempt returned `400`. Unauthenticated
  read-only disclosure of one bucket is a real but separate and much smaller finding, and it does not
  reach execution.
- **OpenSSH 22** - ordinary host authentication, nothing product-specific observed.

The distinction matters because it is the reason the finding is a credential-hygiene defect rather
than an authentication-bypass defect. The vendor generated per-deployment randoms for two of its
three service credentials and did not do so for the most privileged one.

### Authentication Boundary - what the credential actually is

The pair is not a placeholder that the deployment is expected to overwrite. Three pieces of evidence
inside the product describe it as the shipped value.

- The upstream `docker-db` README, section `Connecting to the Database`, instructs the reader to
  "authenticate with username `sys` and password `exasol`". This is publication, not leakage.
- Image-internal CI test scripts authenticate a freshly created database with the same pair at
  `basic_test.sh:112` and `basic_sc_test.sh:98`.
- The mechanism by which it survives initialisation was traced rather than assumed. The running
  `controller` process command line carries no `-defaultSysPasswordHash` argument. The `[DB:DB1]`
  stanza of `EXAConf` carries no `DefaultSysPasswdHash` key. In the image's Python provisioning code,
  `db_jobs.py:104` sets `self.sys_passwd_text = secrets.token_hex(20)`, which generates an additional
  random password rather than replacing the built-in one, and `database.py:57` passes
  `-defaultSysPasswordHash` only when `EXAConf` configures it explicitly. The container's
  `init-sc` path does not configure it.

The conclusion drawn from that trace, and it was corrected once during the research before being
accepted, is that the accepted value is a built-in default of the database engine rather than a hash
handed to the engine by the container initialiser. The additional per-deployment random exists as well
and both are accepted, which is why the presence of random generation in the provisioning code is not
a defence.

### Authentication Boundary - the negative control

Six candidate credentials were tried against the same transport before the constant was accepted:
`admin`, `password`, `EXASOL`, `exasol123` and `123456` alongside the constant itself. All five incorrect candidates returned `[28000] authentication failed`. The control establishes two things at once:
the server does authenticate rather than accept anything, and the acceptance of `exasol` is not an
artifact of a lax or broken check. Section 9 repeats the control with the PoC's `--control` mode.

### Authentication Boundary - why no forced-rotation gate exists

Nothing in the container's start path presents a first-login change-password step, sets a
must-change flag on the `SYS` account, or refuses service while the constant remains in place. The
service reaches its running state with the constant accepted and continues to accept it indefinitely.
This is the specific defect that separates the finding from an ordinary "remember to set a password"
note: products that ship a documented initial credential usually pair it with a forced rotation on
first use, and this deployment form does not. The upstream README does contain guidance about
persistent volumes, hugepages, resource limits and license mounting, and contains no instruction to
change the `SYS` password; the absence is as load-bearing as the presence of the constant.

### Authentication Boundary - what is deliberately not claimed

No claim is made that authentication is missing, that the protocol can be bypassed, that the ConfD or
BucketFS credentials can be recovered without reading `EXAConf`, or that the `SYS` account can be
reached without supplying the password. Every step of the chain was performed while authenticated as
`SYS` with the shipped constant. This is why section 12 argues the Privileges Required metric
explicitly instead of inheriting a rating.

## 4. Attack Surface

### Attack Surface - listeners observed in the shipped image

A socket inventory taken inside the running container reported `exacs` on 8563, `bucketfsd` on 2580,
`confd` on 443 and `sshd` on 22, each bound to all interfaces within the container's network
namespace. A listener bound to all interfaces inside a container is not the same thing as a listener
reachable from a network, and the rest of this section is about that difference.

### Attack Surface - the documented deployment forms, stated precisely

The upstream README documents two ways to run the image, and they differ exactly on the question that
matters.

- **Stand-alone container.** The documented command is
  `docker run --name exasoldb -p 127.0.0.1:9563:8563 --detach --privileged --stop-timeout 120 exasol/docker-db:<version>`,
  followed by "In this example port 8563 (within the container) is exposed on the local port 9563.
  Use this port to connect to the DB." The published port is bound to the host loopback. The
  persistent-volume variant on the same page uses the same loopback-bound publication.
- **Multi-node cluster across hosts.** The documented command is
  `docker run --detach --network=host --privileged -v "$CONTAINER_EXA:/exa" exasol/docker-db:<version> init-sc --node-id 11`,
  with the note "This example uses the host network stack, i.e., the containers are directly
  accessing a host interface to connect to each other. There is no need to expose ports in this mode:
  they are all accessible on the host."

The image's FAQ adds that "if you want to check from outside the Docker network, you need port
forwarding", which confirms that host-side reachability is an explicit operator action.

### Attack Surface - what no shipped artifact establishes

Stated plainly: no shipped artifact establishes that a single-container deployment binds 8563 on
`0.0.0.0` by default. The research notes originally asserted that the production deployment exposes
8563 to remote attackers by default; that assertion rested on the state of our own harness and on a
general expectation about how databases are deployed, not on an artifact, and it has been demoted.
What the artifacts do establish, and what section 12 uses, is narrower and firmer:

- the in-container listener binds all interfaces, and no source-address restriction was observed in the product's own configuration or listener behaviour;
- under the documented host-networking form, 8563 is on the host's interfaces and the vendor says so;
- under default bridge networking with no port publication - which is what several of the README's own
  example commands use, including the license-mount example and the resource-limit example - the port
  is reachable from the host and from every other container attached to the same bridge network, a
  logically adjacent topology;
- under the documented loopback-only publication, reachability requires local access to the host.

The headline Attack Vector is therefore Adjacent. Network and Local both appear as labelled
conditional readings in section 12, each with its own complete vector and arithmetic.

### Attack Surface - components that narrow the surface

Two things narrow it and are worth naming because a reader assessing exposure will look for them. TLS
is terminated on 8563 with a self-signed certificate that has no SAN, so a client must either trust
the presented certificate or supply its fingerprint; the vendor client supports the fingerprint form,
and the fingerprint is readable by anyone who can complete a handshake, so it is a compatibility
requirement and not an access control. Second, the container must run privileged for UDF support
according to the README, which means the UDF engine is present and enabled in the documented
deployment rather than being an optional add-on an operator might have skipped.

### Attack Surface - how the surface was mapped

The listeners were inventoried from inside the running container. Each authentication surface was
then characterised by attempting to use it: the SQL port by credential trial including a negative
control, ConfD by inspecting the `AuthenticationToken` generation and format, BucketFS by listing the
default bucket anonymously and then attempting a write and a traversal. The documentation artifacts
quoted above were read from the upstream repository rather than reconstructed from behaviour.

## 5. Sink Identification

### Sink Identification - how the sink was found

The UDF framework is advertised in the image's own feature list, and script engines that expose a
general-purpose language to the query layer are a standing execution primitive. Rather than search the
C engine for a flaw, the research asked what the engine is documented to do and then verified it: a
`SYS` session may create a script in a supported language, and the body of that script is executed by
the engine. The vulnerability is not a bug in the script engine. It is the combination of that engine
being reachable by a credential nobody had to be given.

### Sink Identification - the vulnerable construction: the PYTHON3 scalar UDF

The sink is this body, submitted as part of a `CREATE OR REPLACE` statement:

```sql
CREATE SCHEMA IF NOT EXISTS poc_schema;
OPEN SCHEMA poc_schema;
CREATE OR REPLACE PYTHON3 SCALAR SCRIPT poc_udf() RETURNS VARCHAR(2000000) AS
import os
def run(ctx):
    out = os.popen("id").read()
    return 'RCE_OUT:' + out
/
SELECT poc_udf();
```

Three properties of this construction are what make it a sink rather than a curiosity. The `os`
module is importable with no declaration, allow-list or capability request. The command string is an
ordinary Python literal built from attacker input, so shell metacharacters, pipelines and quoting all
work - the measured round used `cat /etc/passwd | head -3` and the pipeline was honoured by the shell
that `os.popen` starts. And the return value crosses the trust boundary back to the caller, which is
what removes the need for any separate exfiltration channel.

### Sink Identification - the language alias resolution that proves the sink is a first-class engine feature

The language keyword must be `PYTHON3`. Submitting `PYTHON` produces the engine's own diagnostic,
"no definition found for language: PYTHON". That error is a useful artifact rather than an
inconvenience: it demonstrates that script languages are resolved through a named alias table inside
the engine, that the table is populated with standard script-language-container aliases including
`PYTHON3`, `LUA`, `JAVA` and `R`, and that the engine refuses an unregistered name instead of falling
back to something permissive. `EXAConf` carries no `[ScriptLanguages]` stanza customising that table,
which means the aliases come from the standard installation and are present in a default deployment.
The consequence for the finding is that reachability of the sink is not conditional on an operator
having installed or enabled a language pack.

### Sink Identification - execution identity of the UDF process

`id` executed inside the UDF printed
`uid=500(exadefusr) gid=500(exausers) groups=500(exausers),0(root)`. The command was not run as the
database's own service identity and not as root. It ran as the dedicated script-execution account
`exadefusr`, which nevertheless carries `root` as a supplementary group. `uname -a` executed in the
same context printed the host's kernel release, `5.10.134-19.2.al8.x86_64`, and `cat /etc/passwd |
head -3` printed ordinary Linux account entries beginning with `root:x:0:0:root:/root:/bin/bash`.
The build stamp that follows the release string in that `uname` output is elided here so that this
document carries no dates; the release and architecture were recorded in full.

Two readings of those three outputs have to be kept apart. The kernel release proves the UDF process
shares the host kernel, which is expected for a container and is not an escape. The `/etc/passwd`
output proves that files are readable from the UDF process, but not that the file read was the
container's own or the host's, because a separate write-marker test showed the UDF's filesystem view
is a distinct namespace whose writes did not appear in the container's view. Section 10 states this
boundary again; it is the reason the confirmed impact rests primarily on the SQL-layer authority of
`SYS` and on command execution inside the script engine, and not on an established cross-namespace
file primitive.

### Sink Identification - sibling sinks, and whether they are proven

`os.system`, the `subprocess` module and the other languages in the same alias table are all
plausible siblings, and none of them was detonated. They are named here as structural inference only
and are excluded from the score and from the impact statement. Only `os.popen` under `PYTHON3` was
measured.

## 6. Source Identification

### Source Identification - the tainted input and its transport

The tainted input is the script body carried in the `CREATE ... SCALAR SCRIPT ... AS` statement,
transmitted as a SQL statement over the binary SQL protocol on 8563. Every character of a command the
attacker chooses travels inside that body, which is the point: there is no parameter, no header and no
file involved, and no injection is required because the language the statement declares is a
general-purpose one that the engine executes as written.

### Source Identification - the credential as the source

The second source is the credential that authorises the statement. It is unusual as a taint source
because it is not attacker-supplied secret material: it is a constant published by the vendor. From a
data-flow standpoint it behaves like a hardcoded key in the product, which is why CWE-798 is recorded
alongside CWE-1392.

### Source Identification - sanitization that exists, and what it is for

The engine does check the language alias, as the `PYTHON` diagnostic shows, and it does enforce SQL
syntax and the forward-slash script terminator. Both checks exist to make script definitions
well-formed and resolvable. Neither is a security control over what the body does, and both were
satisfied by the payload without any evasion.

### Source Identification - validation that is absent

No allow-list or deny-list restricts the imported modules. No policy forbids `os` or `subprocess`. No
capability gate, no per-statement approval, no audit prompt and no separate privilege beyond `SYS`
itself are required to create a script that executes operating-system commands. The command string is
not filtered, quoted or escaped by the engine; it is placed into a Python literal by the caller and
executed. There is likewise no rate limit or lockout observed on SQL authentication, which is what
makes the six-password negative control in section 3 practical to run at all.

## 7. Data Flow

### Data Flow - end-to-end chain

```
attacker
  |  binary SQL protocol, port 8563, TLS with a self-signed certificate whose
  |  fingerprint is readable by an unauthenticated handshake
  |  AUTH: sys / exasol        <- published constant, never rotated (CWE-1392)
  v
exacs, the EXASolution engine
  |  CREATE SCHEMA / OPEN SCHEMA / CREATE OR REPLACE PYTHON3 SCALAR SCRIPT ... AS <body> /
  v
UDF script engine, separate kernel namespace, uid=500(exadefusr) groups=500(exausers),0(root)
  |  run(ctx): os.popen("<cmd>").read()      <- CWE-94 reaching CWE-78
  |  return '<marker>' + out
  v
SELECT poc_udf()  -> result set carries the command stdout back to the attacker (not blind)
```

### Data Flow - properties of the chain worth naming

- **In-band return.** The output path is the product's own result-set mechanism. No DNS, HTTP or ICMP
  channel is needed, so no egress filtering on the host defeats it.
- **Idempotent and repeatable.** The statement is `CREATE OR REPLACE`, so the same UDF can be
  re-pointed at a new command on every round, and the three verification rounds did exactly that. This
  also means the attacker leaves a single reusable object rather than one artifact per command.
- **No timing dependency.** Nothing races an administrator or waits for a window. The chain works as
  long as the constant is accepted.
- **No privilege transition inside the product.** The account used to reach the sink is the highest
  privileged database account that exists, so there is no escalation step inside the database to
  detect or to fail.

## 8. Exploit Construction

### Exploit Construction - step sequence

The PoC in `exploit/` performs four steps and reports each: resolve the transport and refuse a
non-loopback target unless `--allow-remote` is passed; acquire the certificate fingerprint without
credentials; assert the credential gate with `SELECT 1`; then create and select the UDF once per
requested command. `--rounds 3` reproduces the verification method by cycling through three different
commands. `--control` runs the negative control alone and creates nothing, `--gate` probes only the
credential, and `--cleanup` drops the schema the run created.

### Exploit Construction - the TLS fingerprint prerequisite

Because the certificate has no SAN, the connection string must carry the fingerprint:
`host/FINGERPRINT:port`. The PoC obtains it with an `openssl s_client` handshake, which is
unauthenticated, and prints only the first and last few hex characters so that a per-deployment value
is not written into a research log. `--no-encryption` exists for a deployment that disabled TLS, and
`--fingerprint` exists so the value can be supplied rather than fetched.

### Exploit Construction - payload engineering constraints

The command is embedded as a Python double-quoted string literal, so backslashes and double quotes
are escaped and nothing else is. The script body is terminated by a line containing only a forward
slash, which is the engine's terminator for script definitions; a payload that omits it leaves the
statement unfinished. The return type is a wide `VARCHAR` so that command output is not truncated by
the declared width. The marker prefix distinguishes the returned value from the echoed statement text.

### Exploit Construction - the stdout capture engineering

Two client behaviours had to be engineered around, and both are recorded because they are what made
the difference between a hanging tool and a working one. The vendor client's single-statement mode
rejects a multi-statement payload that contains the slash terminator and reports an unfinished
command, so the payload is fed on stdin instead. The client does not exit at end of file on stdin, so
the tool starts it with a pipe, waits a bounded interval, kills it, and keeps the partial stdout - by
which point the result set has already been printed. A first attempt at parsing the transcript
matched the marker inside the echoed `CREATE SCRIPT` source; the fix filters matches followed by a
quote, a space or a plus sign, which is how the echoed source differs from a real result.

### Exploit Construction - what the exploit deliberately does not do

It establishes no listener, opens no reverse shell, writes no file, installs no persistence, touches
no other container or host service, does not attempt to reach `uid=0`, and does not attempt to cross
the UDF namespace boundary. The default command is `id`. Those omissions are deliberate: the finding
is that command execution is reachable at all from a documented constant, and demonstrating more
would add risk without adding evidence.

## 9. Dynamic Verification

### Dynamic Verification - environment

One container from the vendor's `docker-db` image at 7.1.30, pulled onto an isolated cloud sandbox,
run privileged as the vendor documents, with a host directory mounted at `/exa` and the SQL port
published to the host loopback. The vendor client was invoked inside the container against the
container loopback on 8563. Researcher-side commands ran under an ordinary unprivileged user account
on the workstation; nothing in the chain depended on elevated privileges on the researcher's host.

### Dynamic Verification - the triggering statements

The statements sent were the four in section 7's chain: `CREATE SCHEMA`, `OPEN SCHEMA`,
`CREATE OR REPLACE PYTHON3 SCALAR SCRIPT ... AS <body> /` and `SELECT`. Per round only the command
inside the body changed.

### Dynamic Verification - observed output

The three rounds returned, verbatim and in order:

```
uid=500(exadefusr) gid=500(exausers) groups=500(exausers),0(root)
```

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

```
Linux n11 5.10.134-19.2.al8.x86_64 [...] x86_64 GNU/Linux
```

The third line's bracketed section is the kernel build stamp and machine field, elided here to keep
this document free of dates; the release, architecture and the node name `n11` are as recorded, and
`n11` is the node identifier the product's own configuration assigns rather than a host we chose. The
first line is the identity claim in full and is reproduced exactly as returned.

### Dynamic Verification - the negative control and why it matters

Five incorrect passwords (`admin`, `password`, `EXASOL`, `exasol123`, `123456`) were rejected with
`[28000] authentication failed` over the same transport and the same client invocation that the
constant succeeded with. Without this control, "the constant worked" is consistent with a broken or
disabled authentication check; with it, the acceptance is specific to the shipped value. The PoC's
`--control` mode reproduces the same kind of control on demand, using a wrong password that is deliberately not the documented value.

### Dynamic Verification - number of successful detonations, stated exactly

Three. Each was an independent create-and-select cycle with a different command, and each returned
real system data through the result set. There was no fourth round, and no round was repeated to
demonstrate determinism beyond the fact that three successes with three different commands are
themselves evidence of repeatability.

### Dynamic Verification - what was driven from a separate network host, and what was not

Nothing was driven from a separate network host. All three rounds ran the vendor client inside the
container against the container's loopback, and the host-side publication was loopback-restricted. The
cross-host legs of this chain - that a client on another machine can complete the same TLS handshake,
retrieve the fingerprint, authenticate and submit the same statements over 8563 - follow from the
protocol being a network protocol and the listener binding all interfaces inside the container, and
they are argued from the artifacts in section 4. They were not demonstrated between two machines, and
this advisory says so wherever the reachability metric is derived.

### Dynamic Verification - boundaries of what was verified

- Verified: authentication with the shipped constant; rejection of wrong passwords; creation of a
  `PYTHON3` scalar UDF by `SYS`; execution of `os.popen` inside it; return of command stdout through
  the result set; the executing identity; visibility of the host kernel release; readability of
  `/etc/passwd` from the UDF process.
- Not verified: cross-host remote detonation; escalation to `uid=0`; any write or execute that
  crosses from the UDF namespace into the container's or the host's filesystem view; persistence;
  the effect of the chain on a non-container installation or on another 7.1.x release; the sibling
  sinks named in section 5.
- Read from source or documentation rather than detonated: the absence of
  `-defaultSysPasswordHash` on the controller command line, the absence of `DefaultSysPasswdHash` in
  `EXAConf`, the behaviour of `db_jobs.py:104` and `database.py:57`, the contents of the image's test
  scripts, the ConfD token generation scheme, and every documented deployment command quoted in
  section 4.

## 10. Reachability and Security Impact

### Reachability and impact - network position

The attacker needs a TCP path to 8563 and nothing else. In the vendor's documented stand-alone form
that path exists from the host itself, because the port is published on the host loopback. In the
vendor's documented multi-host form the container uses host networking and the vendor states that all
ports are then accessible on the host. Under default bridge networking the port is reachable from the
host and from other containers on the same bridge. Under an operator publication without a loopback
restriction, or under a firewall rule that admits a management network, or on the supported
non-container installation whose entire purpose is to accept client connections on 8563, the path
exists from anywhere the routing does. No source-address restriction of the product's own was observed at any point in that list.

### Reachability and impact - what the achieved identity controls

Two layers, and the first does not depend on the sink at all.

- **Through the SQL channel as SYS**: the complete warehouse - every schema, table and view,
  including whatever an analytical platform holds, which is typically the organisation's consolidated
  business data; the ability to write and drop any of it; the user and privilege catalogue, so further
  accounts can be created with the privileges the attacker wants; and the ability to stop the
  database. This layer alone justifies a high rating on all three impact metrics.
- **Through the UDF sink**: operating-system command execution as `uid=500(exadefusr)` with `root` as
  a supplementary group, inside the script engine's namespace, with stdout returned in-band. What that
  reaches beyond the SQL layer was not fully mapped, and section 9's boundary list says which parts
  were tested.

### Reachability and impact - the privilege question, answered in full

The measured identity is `uid=500(exadefusr)` with `gid 0` present as a supplementary group. Two
facts make that combination worth naming without inflating it. The container runs privileged because
the vendor's README says privileged mode is required for permissions management, UDF support and
environment configuration, which is the documented posture rather than an unusual one. And root group
membership on a Linux system governs access to files and devices whose group is `root`. Inside a
privileged container that combination is widely understood to be an escalation position. It is not an
escalation, and no escalation to `uid=0` was attempted, observed or is claimed by this advisory. The
conditional sentence is the whole of what can be said from the evidence: if an attacker in that
position could write a setuid binary, or reach a device node exposed by privileged mode, an effective
root identity would follow; neither was tested. What was tested is that the group membership is
present, which the `id` output states.

### Reachability and impact - the isolation question: namespace vs escape

The UDF engine runs in a separate kernel namespace, and that isolation is real but partial in a way
that this advisory must not gloss. A file written by the UDF did not appear in the container's own
filesystem view, so the two views are distinct mount namespaces. Yet `uname` from inside the UDF
returned the host kernel release, which is expected - a namespace is not a hypervisor and the kernel
is shared. The consequence for impact is precise: command execution inside that namespace is
confirmed and non-blind, and it is a substantial capability on its own because the namespace has
network access and a root-supplementary group; a host or container escape is not confirmed, not
attempted and not claimed. The `id` output's account names come from the namespace's own view, so even
the reading of `/etc/passwd` is not asserted to have been the container's or the host's file.

### Reachability and impact - detection notes

Detection is weak by construction because every step is legitimate product usage. A connection as
`SYS` from an unexpected address is the only network-level signal, and it is indistinguishable from a
legitimate administrator. The durable artifact is the schema and the script object the attacker
created: it survives the session, it is enumerable with ordinary SQL, and `CREATE OR REPLACE` means
re-running the attack rewrites the same object rather than accumulating evidence. Audit trails that
record script creation are therefore the highest-value signal available, and their absence from the
default deployment is itself part of the problem. An operator who never rotated the constant has no
way to distinguish an attacker's `SYS` session from their own.

## 11. Fix Recommendations

### Fix Recommendations - vendor-side, ordered by root cause

1. **Do not let the initialisation path leave a constant in place.** Generate a per-deployment random
   SYS password during container initialisation, exactly as the product already does for the ConfD
   `AuthenticationToken` and the BucketFS `WritePasswd`, and report it to the operator through a
   channel the operator must have local access to read. The provisioning code already calls
   `secrets.token_hex(20)` at `db_jobs.py:104`; making that value the only accepted password rather
   than an additional one is a small change with the largest effect of anything on this list.
2. **Remove the built-in acceptance of the constant**, or require an explicit
   `--sys-passwd` initialisation argument with no default. A documented constant credential that
   nothing rotates is the defect; the script engine is a feature.
3. **Add a forced first-login rotation gate.** If a constant initial credential is retained for
   compatibility, refuse to serve SQL until the password has been changed once, and log the refusal.
4. **Restrict the script engine by default.** Make the module set available to UDFs an allow-list
   that excludes `os`, `subprocess`, `socket` and equivalents, with an explicit
   per-database or per-session opt-in to enable them, and log the opt-in. Script engines that expose a
   general-purpose language to the query layer should treat process creation as a privilege that is
   granted, not as a library that is present.
5. **Stop granting the script-execution account root group membership** unless a specific
   documented function requires it, and say in the documentation which one it is. Nothing measured
   here needed `gid 0`.
6. **Document the exposure explicitly.** The README's stand-alone example already publishes on
   loopback; add a warning next to the host-networking example that 8563 accepts SQL from the
   network, that the default credential must be rotated before that form is used, and that BucketFS's
   public-read default discloses bucket contents without authentication.
7. **Add an authenticated-session anomaly signal**: log or expose new script-object creation with the
   creating user and source address, since that event is the only durable artifact the chain leaves.

### Fix Recommendations - a regression test the vendor should add

Initialise a container with no arguments, then assert from a remote client that (a) the documented
constant no longer authenticates and the response is an authentication failure, (b) a connection
succeeds only with the value the initialiser reported, (c) once connected, creating a
`PYTHON3` script whose body calls `os.popen` fails with a policy error naming the restricted module,
and (d) the script-execution account's supplementary groups, read from inside a permitted script, do
not include `gid 0`.

### Fix Recommendations - operator-side, until a patch exists

- Rotate the `SYS` password immediately after initialisation, and treat any deployment still
  answering the constant as compromised until audited. The rotation is the single control that breaks
  this chain.
- Do not publish 8563 without a loopback or named-address restriction. Prefer the documented
  loopback publication, front remote access with a VPN or a mutually authenticated proxy, and audit
  any deployment using `--network=host`.
- Enumerate and review script objects: list schemas and `CREATE SCRIPT` definitions, remove any the
  operator did not author, and compare against a known-good inventory periodically, because
  `CREATE OR REPLACE` leaves no accumulation to alert on.
- Restrict who can reach `SYS` at the network layer, since no source-address control of the product's own was observed, and monitor authentication failures on 8563 for trial sequences against `sys`.
- Treat the out-of-support status of this release line as a reason to plan migration on its own
  merits; the vendor's README directs users of docker version 7 to a newer release.

## 12. CWE and CVSS

### CWE and CVSS - classification

- **CWE-1392 (Use of Default Credentials)** - primary. The credential is the vendor's default, it is
  documented, and no gate rotates it.
- **CWE-94 (Improper Control of Generation of Code)** - co-equal. The engine generates and runs code
  whose content the SQL caller fully controls, with no restriction on what it may do.
- **CWE-798 (Use of Hard-coded Credentials)** - recorded alongside CWE-1392 because the constant is
  built into the product rather than generated per deployment.
- **CWE-78 (OS Command Injection)** - the realised effect of leg two: `os.popen` starts a shell on an
  attacker-chosen string, and the measured round used a pipeline.
- **CWE-1188 (Insecure Default Initialization of Resource)** - the initialisation path leaves the
  database in a state where a published constant is sufficient.
- **CWE-250 (Execution with Unnecessary Privileges)** - the script-execution account carries `root`
  as a supplementary group although nothing measured required it.
- **CWE-284 and CWE-862** - reported separately for the absence of any observed source-address restriction on 8563 and of any authorisation check distinguishing script creation from ordinary SQL. Neither
  raises a metric above.

### CWE and CVSS - vector derivation

The published vector is `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Working through it: the
impact sub-score is ISS = 1 - ((1-0.56) x (1-0.56) x (1-0.56)) = 1 - 0.44^3 = 0.914816; with Scope
Unchanged, Impact = 6.42 x 0.914816 = 5.873119; Exploitability = 8.22 x AV(A: 0.62) x AC(L: 0.77) x
PR(N: 0.85) x UI(N: 0.85) = 2.835255; Base = Impact + Exploitability = 8.708373 rounded up to the
nearest tenth, which is 8.8. Nothing in the sources behind this advisory carried a computed figure
that was inherited; every number in this section was derived from its vector with the CVSS 3.1
formula.

- **Attack Vector: Adjacent** - the in-container listener binds all interfaces and no source-address restriction was observed in the product's own configuration, but no shipped artifact establishes a `0.0.0.0` host bind for the
  documented single-container form; that form's own example publishes on the host loopback, while the
  documented multi-host form uses `--network=host` under which the vendor states all ports are
  accessible on the host, and default bridge networking makes the port reachable from the host and
  from sibling containers. Adjacent is the reading the artifacts support for the deployment form
  examined. Network and Local are published below as labelled conditionals.
- **Attack Complexity: Low** - the constant is published, the certificate fingerprint is obtainable
  by an unauthenticated handshake, the alias `PYTHON3` is registered by default, and there is no race,
  no window and no operator action to wait for. Every round succeeded on the first attempt.
- **Privileges Required: None** - see the dedicated argument below.
- **User Interaction: None** - no administrator click, browser session or user action is involved.
- **Scope: Unchanged** - see the dedicated argument below.
- **Confidentiality: High** - `SYS` over the SQL channel reads the entire warehouse; the sink
  adds file reads and command output in-band. High does not depend on whether the namespace shares the
  host's file view, which was not established.
- **Integrity: High** - `SYS` can write and drop any schema, table, view, user and privilege; the
  sink adds command execution whose file-writing reach inside the namespace was demonstrated only as
  a negative result.
- **Availability: High** - the database can be stopped, schemas dropped and resources consumed at
  will by the same session.

### CWE and CVSS - the Privileges Required decision

This is the metric worth arguing rather than inheriting, and the argument runs as follows. The
attacker does type a password, so a naive reading says `PR:L`. But CVSS 3.1 defines `PR:N` as the
attacker being "unauthorized prior to attack" and not requiring "any access to settings or files of
the vulnerable system to carry out an attack". Both halves hold here. No account was ever provisioned
to the attacker and no trust decision by the defender admitted them: the value is a constant the
vendor publishes, identical on every deployment. And the attacker does not need to read anything from
the target - not `EXAConf`, not a startup log - to obtain it, which is exactly what separates it from
the ConfD token and the BucketFS `WritePasswd`, both of which are per-deployment randoms that do have
to be read out of the deployment's own settings. A credential that every installation shares and that
its documentation prints is not a privilege the defender granted; it is the absence of a credential
requirement wearing one's shape. That is the reasoning behind `PR:N`, and it is why the project counts
this finding in its unauthenticated class for batch composition.

The two metric readings are nevertheless published in full, because a reader who disagrees about
`PR:N` should be able to see what the difference costs, and because batch-composition bookkeeping and
the CVSS metric are separate questions:

- **Rejected reading - PR:L**, treating the constant as a credential the attacker supplies:
  8.0 High (`CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`). Exploitability = 8.22 x 0.62 x 0.77 x
  0.62 x 0.85 = 2.068068, Base = 5.873119 + 2.068068 = 7.941187 rounded up, which is 8.0. Rejected as
  the headline because it charges the attacker for a privilege nobody granted them.
- **Rejected reading - PR:H**, noting that `SYS` is the database's most privileged account and reading
  the metric as the authority level the successful attack needs: 6.8 Medium
  (`CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`). Exploitability = 8.22 x 0.62 x 0.77 x 0.27 x 0.85
  = 0.900610, Base = 5.873119 + 0.900610 = 6.773729 rounded up, which is 6.8. Rejected for the same
  reason and more strongly: the reading would rate a constant that requires no grant as though it were
  a personal administrator account. For reference the same metric under a Network vector,
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, computes to 7.2 Medium.

### CWE and CVSS - the Attack Vector decision, and the demoted claim

The research notes originally asserted that the production docker deployment exposes 8563 on all
interfaces by default and scored the chain as remotely reachable on that basis. That assertion was
built from the state of our own harness and from a general expectation about database deployments, not
from a product artifact, and it does not survive contact with the vendor's documentation: the
documented stand-alone run command publishes `-p 127.0.0.1:9563:8563`, and the image's FAQ notes that
reaching the service from outside the docker network requires port forwarding. The claim is therefore
withdrawn in that form and replaced by the narrower set of statements in section 4. The headline
metric is Adjacent, and both alternative reachability positions are published as conditionals:

- **Conditional reading A - 8563 reachable from another host**: 9.8 Critical
  (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). Exploitability = 8.22 x 0.85 x 0.77 x 0.85 x 0.85
  = 3.887043, Base = 5.873119 + 3.887043 = 9.760161 rounded up, which is 9.8. This applies to the
  documented multi-host `--network=host` form, to any operator publication without a loopback
  restriction, to a deployment reachable across a management network or NAT, and to the supported
  non-container installation whose purpose is to answer client connections on 8563. It is the reading
  most operators of a real warehouse will be in, and it is labelled conditional because the deployment
  form actually executed in this research published loopback-only and the cross-host leg was argued
  from artifacts rather than detonated.
- **Conditional reading B - loopback-only publication exactly as the stand-alone quickstart
  documents**: 8.4 High (`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). Exploitability = 8.22 x
  0.55 x 0.77 x 0.85 x 0.85 = 2.515145, Base = 5.873119 + 2.515145 = 8.388264 rounded up, which is
  8.4. This applies to a container whose only publication is the documented loopback one and where the
  attacker therefore needs local access to the host - which is a realistic position for anything else
  already running on that host, including a sibling container.

### CWE and CVSS - the Scope decision

Unchanged. The vulnerable component and the impacted component are the same product on the same host:
the SQL service, its script engine and the database it administers are one system, and executing a
script is what the engine is built to do, so reaching the operating system from inside it does not
cross an authority boundary the product itself maintains. Changed was considered, on the argument that
the UDF runs in a separate namespace with root group membership under a privileged container and that
command execution there affects an OS outside the database's own authority. That argument has force,
which is why the reading is published rather than discarded:

- **Rejected reading - Scope Changed**, 9.7 High (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`).
  With Scope Changed the impact term is 7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 -
  0.02)^13 = 6.128026, Base = 1.08 x (6.128026 + 2.835255) = 9.680344 rounded up, which is 9.7. The
  same reading under a Network vector, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, is capped by
  the formula and comes to 10.0 Critical. Rejected as the headline because the namespace boundary was
  measured to be a boundary in one direction and not the other - a file written inside it did not
  appear outside - and because no cross-boundary effect was demonstrated, so charging Scope Changed on
  the strength of an untested escalation position would be exactly the kind of inflation this section
  exists to avoid.

### CWE and CVSS - conditional readings, labelled as such

Every reading above carries its own complete vector and its own arithmetic. The three conditional or
rejected readings that are not the headline are: Reachability Network at 9.8 Critical; Reachability
Local at 8.4 High; Privileges Required Low at 8.0 High and High at 6.8 Medium; Scope Changed at 9.7
High or 10.0 Critical when combined with a Network vector. A fourth state deserves a separate
sentence because it is the one an operator can enter deliberately: **with the factory credential
rotated, this finding does not arise for an unauthenticated attacker at all**. If the SYS password has
been changed and no other account holds script-creation privilege, there is no path from the network to
the sink, and the script engine is then simply a documented feature used by authorised administrators.
If the password has been rotated but a provisioned non-administrative account has been granted the
ability to create scripts, the reachable score is the Privileges Required Low reading, 8.0 High
(`CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), computed above. Rotation is therefore the single
control that moves this finding from 8.8 to not-applicable, which is why it heads the operator list in
section 11.

### CWE and CVSS - what is deliberately not published

No score is published for the sibling sinks (`os.system`, `subprocess`, the `LUA`, `JAVA` and `R`
aliases) because none was detonated. No score is published for the BucketFS anonymous read of the
default bucket, which was observed but is a separate, smaller finding with its own root cause and
would need its own vector. No score is published for other 7.1.x releases or for the non-container
installation, neither of which was executed. And no figure is quoted for escalation to `uid=0`,
because it was not attempted.

### CWE and CVSS - summary

The published rating is 8.8 High on `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, derived above
from first principles. It rests on one measured leg - three successful rounds of command execution
with output returned in-band under a documented constant credential - and on one adjacent leg argued
from vendor artifacts rather than from a cross-host detonation. The reachability claim that our own
earlier notes stated too broadly has been withdrawn and replaced with the narrower artifact-backed
version, and the identity is reported as `uid=500(exadefusr)` with `root` as a supplementary group, not
as root.

Regarding prior public coverage: a keyword search of the NVD for the vendor name returns exactly one
record, and it concerns a client-side JDBC driver component rather than the database server; separate
searches for the database product name and for the docker deployment name return no records at all. We
found no published advisory whose root cause is either leg of this chain - neither the shipped
constant credential nor the unrestricted script-language sink. No neighbouring identifier is cited
here, and none should be inferred as related.
