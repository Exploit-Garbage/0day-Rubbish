# Royal Render 9.1.26b — Default-Unauthenticated Job Submission on rrServer Port 7773, Reaching a Worker-Side `source` of an Attacker-Named Shell Script (command execution as the worker identity; uid=0(root) observed)

## 1. Overview

### Overview of the finding

Royal Render 9.1.26b, the render-farm job manager sold by Holistic IT GmbH of Darmstadt, Germany, ships a
central scheduler that accepts job submissions from any TCP client without asking who it is. The product's own
help page says so, and says so as the expected condition rather than as a warning: `files/help/Authorization.html`,
inside the installation tree, states

> "By default, the rrServer does NOT check for a valid user if you connect to the rrServer."

Authorization exists in the product as a feature an operator switches on - either a submission whitelist or an
"Authorization required for all connections" setting - and the configuration file that the vendor's own
`rrSetup_linux` installer writes into the tree leaves both of them off:

```ini
[Network]
nTCPRequiresAuth=false

[NetWork]
nAuthWhiteList=
```

Among the job types the product ships is one called `Execute` with renderer name `Once`. It is not a renderer.
`render_apps/_config/E01__ExecuteOnce.cfg` defines its Linux command line as a template that, for a scene path
ending in `.sh`, resolves to

```sh
source "<Scene>" <AdditionalCommandlineParam>
```

So an anonymous client that submits an `Execute` / `Once` job chooses a file path, and a worker - a different
process, in production a different host - opens a shell and `source`s that path with whatever privileges the
worker was started with. In the verified deployment the worker `rrClientconsole` ran as root, and the result
was a marker file owned `root:root` containing `uid=0(root) gid=0(root) groups=0(root)`.

The distance between "connect to port 7773" and "a shell runs your file as root" is therefore one submitted
record. Nothing in that path is a parsing error, a memory-safety failure or an unintended code path. Each step
is the product's documented behaviour: anonymous connection is the documented default, job submission is the
documented purpose of the listener, `Execute` / `Once` is a documented job type shipped in the default job-type
set, and shell execution of a scene file is what that job type is specified to do. The defect is that the
product's most powerful primitive is reachable by a caller whose identity was never established.

### Overview of the product and its runtime stack

Royal Render is a closed-source commercial render farm manager for VFX and animation studios. It is not related
to the Royal Server gateway product sold by Royal Apps GmbH of Austria, which is a different vendor, a different
codebase and a different purpose; the two share one word in their names and nothing else. The installation tree
we examined credits the product to Royal Render and its author Holger Bünck, and the job record inside the
verified capture carries the server version text `rr9.1.26b`, which independently corroborates the version.
We did not obtain a commercial-registry extract for Holistic IT GmbH, so the company name in this advisory is
carried by the vendor's own product documentation and no claim beyond that documentation is made.

The component set, from the shipped tree:

- `rrServerconsole` - the scheduler. A 4.4 MB ELF x86-64 Linux binary that listens on TCP 7773 and speaks a
  custom binary protocol. It accepts submissions, holds the job queue, and dispatches work to workers
- `rrClient` / `rrClientconsole` - the worker. Receives dispatched jobs and executes the resulting command
  line; `rrClientconsole` is the headless variant used in this research
- `rrSubmitter` / `rrSubmitterconsole` - submission clients, GUI and console
- `rrPythonconsole` - a Python console for scripted farm interaction
- `rrWebsite` - generates statistics content (images and status pages). It is not an HTTP server and does not
  listen on a web port, so no web attack surface participates in this finding
- `SDK/External/Python/` - a shipped Python SDK containing `rr_python_utils/connection.py`,
  `_Info__ServerAuthorization.txt` and example scripts including `submit_job.py`

Scene files are expected to live on storage shared between submitters and workers. That architectural fact is
not incidental to this finding; it is the reason the job record carries a *path* rather than file *content*, and
it is the boundary that determines how much work an attacker must do, which is discussed under Attack
Complexity below.

### Overview of the testbed and of what that implies

The target was a complete installation made with the vendor's own `rrSetup_linux` Linux installer, on
x86-64 Linux, left in the configuration the installer produced. No authorization setting was changed, no
configuration key was edited, and no licence was installed - so `rrServer` ran in the product's two-client
demonstration mode. The worker `rrClientconsole` was started from a root shell, which is why the executed
command ran as root; that is a property of our deployment and not something the product decided for us, and this
advisory treats it as such everywhere it matters.

Two consequences follow. First, the demonstration-mode question has to be answered, because a reader is entitled
to ask whether the missing identity check is an artefact of running unlicensed. Authorization is governed by a
configuration key (`nTCPRequiresAuth`) that is present in the shipped `globalconfig.ini` and that the shipped
documentation describes as the switch for this behaviour. The behaviour we observed followed that key. We found
no coupling between licence state and authorization in the observed behaviour, and we make no claim about the
internal construction of the binary, which is closed-source and was not disassembled for this advisory. We
therefore say precisely what we can support: authentication is configuration-driven in the shipped artefacts,
the shipped documentation states the unauthenticated default unconditionally, and no difference was observed
between the demonstration run and that documentation. A licensed instance was not tested, so no claim is made
about licensed builds in either direction.

Second, root execution has to be reported as measured rather than as a shipped default. The verdict is
"arbitrary shell execution as the worker's identity, measured as `uid=0(root)`", with the reason the identity
was root stated openly: the worker was started by root, and Royal Render enforces no privilege separation
between the dispatch identity and the operating system. We did not find a shipped artefact fixing a non-root
default worker identity, and a worker designed to run arbitrary render commands inherits whatever its operator
granted, so the ceiling is deployment-dependent.

### Overview of affected scope

Only version 9.1.26b on Linux x86-64 was executed. The Windows question is answered by an artefact rather than
by a detonation: the same shipped `E01__ExecuteOnce.cfg` carries a `CommandLine_Win` template that resolves to
`call "<Scene>"` for `.bat` and `.cmd` scenes, which is the same construction with the Windows command
interpreter. We report that as read from the file and not as verified by execution, and we do not claim the
Windows build as tested. Earlier versions were not tested and are not claimed as affected; the evidence for
the unauthenticated default is the shipped documentation and the shipped configuration file of this version, and
we did not diff either across versions.

### Overview of independence

This finding does not reuse, restate or extend a published vendor advisory. Nothing in the shipped
documentation treats an anonymous submission that reaches shell execution as a known or accepted limitation;
the documentation describes the missing check as the default state of the product. We cite no existing
identifier for this product because we did not verify one, and per our own rule we do not list neighbouring
identifiers whose product attribution or root cause we have not confirmed.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Property | Value | Evidence class |
| --- | --- | --- |
| Product | Royal Render 9.1.26b | vendor tree; job record carries `rr9.1.26b` |
| Vendor | Holistic IT GmbH, Darmstadt, Germany | vendor product documentation |
| Component | `rrServer` / `rrServerconsole`, TCP 7773 | shipped SDK hardcodes the port |
| Second component | `rrClient` / `rrClientconsole` worker | shipped binary in the tree |
| Missing control | identity check on connection and on submission | `files/help/Authorization.html`; `globalconfig.ini` |
| Switch | `nTCPRequiresAuth` (default `false`), `nAuthWhiteList` (default empty) | shipped configuration file |
| Job type | `Execute` with renderer name `Once` | `render_apps/_config/E01__ExecuteOnce.cfg` |
| Sink | `source "<Scene>" <AdditionalCommandlineParam>` via a shell | same file, `CommandLine_Lx` |
| Attacker-controlled field | `execOnce.file` dataset, a scene path | decoded from the verified job record |
| Validation on that field | none observed | decoded record plus observed acceptance |
| Credentials required | none | vendor documentation; verified submission |
| Execution identity | worker's identity; measured `uid=0(root)` | verified detonation |
| Remote reach | yes, driven from a second host on another segment | verified detonation |
| Memory safety involved | no | no crash, no corruption, functional reply |
| CWE | CWE-306 primary, CWE-1188 co-equal, CWE-73 | classification and reasons below |
| CVSS 3.1 | 8.1 High (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) | computed, four conditional readings |

### Vulnerability Summary mechanics

The mechanism is a straight composition of two product behaviours, each individually defensible:

1. `rrServer` accepts a connection and a job-submission record without establishing who sent it. This is the
   documented default, controlled by `nTCPRequiresAuth` and the whitelist, both off as shipped
2. The `Execute` / `Once` job type converts a submitted scene path into a shell command. For a `.sh` scene on
   Linux the worker runs `source "<Scene>" <AdditionalCommandlineParam>`; the worker does not check where the
   file lives or who asked for it

Compose them and the product is an unauthenticated remote command-execution channel whose only remaining
question is how the attacker gets a script onto a path the worker can read. In a render farm the product's own
answer to that question is shared storage: submitters and workers mount the same project filesystem, which is
how scene files reach workers at all. That is why the finding is rated with `AC:H` rather than `AC:L` - the
placement step was provided by our test setup in the verified run, not by the product, and we will not claim a
primitive we did not demonstrate - and why reading A of the conditional set exists.

### Vulnerability Summary preconditions

Stated without softening, because the strength of this finding depends on being exact about them:

- The attacker can open a TCP connection to `rrServer` on port 7773. Nothing in the protocol restricts the
  source; the server accepted a submission from a second host whose address and hostname were both foreign to
  it, and the all-interface bind we measured was on the test instance
- Authorization is in its shipped state, i.e. `nTCPRequiresAuth=false` and an empty whitelist. If an operator
  enabled it, this exact chain requires a valid RR user instead, which is published as conditional reading C
- A worker is online and polling. This is the normal state of any farm that is being used
- The scene path named in the job record resolves to a file readable by the worker, and for attacker-chosen
  commands that file's content must be attacker-chosen too. In the verified run our setup wrote that file on
  the worker host. We demonstrated no product primitive that writes it over port 7773

### Vulnerability Summary — why the root cause is architectural rather than a coding slip

There is no function to point at where a check was forgotten. The submission handler behaves as documented: it
is designed to accept work from any client on the farm, because a render farm's ordinary submitters are artist
workstations and pipeline scripts on hosts the scheduler has no reason to distrust individually. The job-type
system is likewise designed to be data-driven, so that studios can add their own renderers and post-processing
tasks by dropping configuration files into `render_apps/_config/` - which is why `Execute` / `Once` exists as a
configuration entry rather than as a hard-coded code path, and why its command line is a string template that
gets handed to a shell. Each decision is reasonable in isolation. Together they mean the product's authorization
model is the only thing standing between an anonymous socket and a root shell, and by default that model is
switched off. That is why CWE-1188 sits alongside CWE-306: the defect is as much an insecure default as a
missing check.

## 3. Authentication Boundary

### Authentication Boundary — the load-bearing artefact

This section carries the claim the whole advisory rests on, so it is grounded in vendor artefacts and not in
the state of our test instance. Our test instance's configuration is the weakest possible evidence for a
"ships this way" claim, and this project has previously had to correct a published advisory for exactly that
error - a laboratory configuration was described as a product default, and the CVSS and privilege values moved
with the correction. So the ordering below is deliberate: documentation first, shipped configuration second,
shipped SDK third, our instance last.

Artefact one, the vendor's own shipped help page `files/help/Authorization.html`, states verbatim:

> "By default, the rrServer does NOT check for a valid user if you connect to the rrServer."

That sentence is a statement about the shipped product made by the vendor, in the product's own documentation
tree, with no reference to a licence state, a trial, an evaluation or an unusual configuration. It is the
primary evidence, and it would be sufficient on its own.

Artefact two, the configuration file the installer writes, corroborates it. `sub/cfg_global/globalconfig.ini`
in the installed tree contains a `nTCPRequiresAuth=false` key and an empty `nAuthWhiteList`. Two details are
worth noting: the key is spelled `false` rather than absent, so the unauthenticated state is an explicitly
written default and not an unwritten fallback; and the two section headers appear with different capitalisation
(`[Network]` and `[NetWork]`) in the installed file, which is how the key was read from it. We report this as
an installed-tree artefact produced by the vendor's installer, which is one step weaker than the shipped
documentation because an installer could in principle be parameterised.

Artefact three, the shipped Python SDK, treats an anonymous connection as the ordinary case rather than as a
degraded one:

```python
def server_connect(user_name=None, password=None, askForlogin=False):
    ...
    tcp.setServer(rr_server, 7773)
```

The vendor's own utility defaults both `user_name` and `password` to `None`, and the port is hardcoded to 7773
for connecting to a remote server. The SDK's authorization note `_Info__ServerAuthorization.txt` describes what
an anonymous caller becomes:

> "If you do NOT specify any user, it works like in rrControl with no user set. You either get the rights of
> user *Anonymous*..."

So anonymous is a subject in the product's model with rights attached to it, not an error condition.

### Authentication Boundary — what the gate actually checks

With authorization off, the answer is nothing. There is no handshake that establishes a principal, no token in
the submission record that the server would have to accept or reject, and no per-job-type capability check,
because a capability check requires a subject and the default configuration never produces one. The verified
exchange is: connect, send one job-submission record, receive a 346-byte reply, connection closed. The reply is
a normal functional response - it echoes the connection prefix and the submitter hostname - not an error and not
a challenge.

When authorization is enabled, the model changes shape rather than merely tightening: a principal exists, the
whitelist can constrain which subjects may submit, and passwords are stored as Argon2 digests rather than in
clear. We did not test that mode. Whether an ordinary authenticated user may submit an `Execute` / `Once` job,
or whether that job type is reserved to administrators, is unknown to us, and we do not guess: conditional
reading C publishes both privilege levels with their arithmetic so an operator can pick the one that matches
their farm.

### Authentication Boundary — the principal required by the sink

None in the default configuration. That is the finding. The sink - a worker's shell executing
`source "<Scene>"` - is reached from a submission that carried no credential. Note the asymmetry that makes
this severe rather than merely untidy: the product's authorization model is defined at the *connection* and
*submission* layer, while its most dangerous capability is enforced at the *job type* layer, where no principal
exists by default. Turning authorization on introduces a principal; it does not by itself restrict which job
types that principal may submit, and whether it does is not something we tested.

### Authentication Boundary — what is deliberately not claimed

- Not a credential bypass. There is no credential to bypass in the default configuration; a bypass framing
  would wrongly imply that a working authentication path exists and was evaded
- Not a default-credential finding. No password, no vendor account, no well-known token is involved, and
  nothing was guessed
- Not a race with a first-run window. There is no setup phase that closes; the unauthenticated state persists
  indefinitely until an operator switches it on, which is a materially different exposure profile from a
  first-run class of issue and is why no attack-complexity cost was taken for timing
- Not an authentication *mode* confusion. We did not find a client-supplied flag that selects the anonymous
  path on a server that requires authorization; we found a server whose shipped default does not require it
- No claim about licensed builds. Our installation was unlicensed and therefore in two-client demonstration
  mode. The authorization key is a configuration key, and observed behaviour followed it; a licensed instance
  was not run in either direction

### Authentication Boundary — the credential model in one paragraph

Royal Render's authorization is opt-in at the connection layer, configured through `nTCPRequiresAuth` and
`nAuthWhiteList` in `sub/cfg_global/globalconfig.ini`, with Argon2-hashed passwords when enabled, and an
`Anonymous` subject that carries rights when it is not. The shipped default is the unauthenticated one, stated
in the vendor's own documentation. Because the product's most powerful job type executes a shell command on a
worker, the default configuration is an unauthenticated remote execution channel whose only limiting factor is
the reachability of the scene file. That single sentence is the finding, and everything below is its evidence.

## 4. Attack Surface

### Attack Surface — listeners, and their protection

The surface relevant here is one TCP listener:

- `rrServer` on TCP 7773, custom binary protocol, not HTTP, no TLS in the observed exchange, no identity check
  in the default configuration. This is the whole attack surface used by the finding
- Workers connect back to the scheduler and receive dispatched jobs. The worker side is reached *through* the
  scheduler's job dispatch, which is the product's normal function, so no separate worker listener was
  addressed directly and none is claimed as an independent entry point
- `rrWebsite` is not a listener. It generates statistics content and images; no web port participates, and
  readers who arrived expecting an HTTP surface will not find one in this advisory

### Attack Surface — the bind default, stated precisely

Our instance bound `*:7773` - every interface - and the source note recorded that as the observed state. That is
an observation about a machine we operated, not an artefact, so it is not offered as evidence that the shipped
product binds every interface by default, and no claim is built on it alone. What is offered instead is
architectural and artefact-backed: a render-farm scheduler exists to accept submissions from submitter hosts
that are not the scheduler's own host, and to dispatch work to worker hosts that are likewise elsewhere. The
shipped SDK hardcodes port 7773 for connecting to a remote `rrServer` by address
(`tcp.setServer(rr_server, 7773)`), which is only meaningful if remote connections are an intended mode. A
loopback-only scheduler could not perform its stated function.

Because "measured on our instance" and "shipped default" are different claims, the narrower network position is
published as conditional reading D (`AV:A`, 7.5 keeping high complexity or 8.8 at low complexity) for
installations that bind or firewall 7773 to a management segment.

### Attack Surface — how the surface was mapped

The mapping was documentary and behavioural, not disassembly-based, and it is worth stating which because it
bounds what we can claim:

- The shipped job-type configuration directory `render_apps/_config/` enumerates job types as data files, so
  the available primitives were read directly from them rather than inferred from a binary
- `E01__ExecuteOnce.cfg` names the `Execute` / `Once` type and gives the exact Linux and Windows command
  templates, including which template substitutions exist (`<Scene>`, `<AdditionalCommandlineParam>`,
  `<CustomFlags>`)
- The shipped Python SDK documents connection defaults, the port, the anonymous subject and a complete
  `submit_job.py` example
- The wire protocol was recovered from a captured submission record and by decompressing the job data it carries,
  as detailed in Source Identification. No vendor binary was disassembled and no symbol-level claim is made

### Attack Surface — components that narrow the surface

Recorded so that the reader can price the exposure:

- The scene path must resolve to a file the worker can read, and for attacker-chosen commands that file must
  contain attacker-chosen content. Port 7773 delivered a path; it delivered no bytes
- The `Execute` / `Once` type requires a `.sh` scene path on Linux to hit the `source` branch of the template
  (`<EndsWith(<Scene> , .sh) source >`); a path with any other extension does not select that branch
- Workers must be online and polling for dispatch to occur. In a farm that is the steady state, but it is a
  precondition rather than a given
- Reachability of TCP 7773 is a deployment question that this advisory does not answer for any particular
  reader's network; a scheduler published to the internet is reachable from the internet, and one behind a
  management VLAN is not

## 5. Sink Identification

### Sink Identification — how the sink was found

The sink was found in configuration, not in code. Royal Render's job types are data files under
`render_apps/_config/`, and the file that defines the primitive is `E01__ExecuteOnce.cfg`:

```ini
Name= Execute
rendererName= Once
ExecuteJobType=Once
SceneFileExtension= *.bat;*.sh;
CommandLine_Lx= <EndsWith(<Scene> , .sh) source >  "<Scene>" <AdditionalCommandlineParam>
CommandLine_Win= <EndsWith(<Scene> , .bat) call > <EndsWith(<Scene> , .cmd) call > "<Scene>" <AdditionalCommandlineParam> <CustomFlags>
```

Four elements of this file are load-bearing:

- `Name= Execute` and `rendererName= Once` together name the job type. A submission carrying those two values
  selects this definition, and both values were confirmed present in the decompressed verified job record
  (`Execute` at job offset 32, `;Once` at offset 596)
- `SceneFileExtension= *.bat;*.sh;` shows the job type is explicitly designed to accept *script* files as
  "scenes". This is not a renderer that happens to take a shell script; it is a job type whose declared
  purpose is executing one
- `CommandLine_Lx` contains the conditional template `<EndsWith(<Scene> , .sh) source >`, which emits `source`
  only when the scene path ends in `.sh`, followed by the scene path in double quotes
- `<AdditionalCommandlineParam>` is appended outside the quotes

### Sink Identification — why `source` is worse than executing a script

`source` in a POSIX shell runs the file *in the current shell* rather than as a child process. Two consequences
matter here:

- The commands execute with the worker's full environment and identity, so it is not merely the script's own
  permissions that apply but everything the worker's shell session holds
- The executed statement list runs in-sequence in that shell, so control flow inside the file - loops, traps,
  exits - acts on the worker's shell itself. A worker that `source`s a hostile file does not have the option of
  "the script returned non-zero, so continue"

The distinction is worth stating because it changes the recovery options: a child-process execution could at
least be killed as a process group, whereas an in-shell `source` can alter the running worker's own state
before any watchdog sees an anomaly.

### Sink Identification — execution identity of the executed command

The command runs as the worker process. In the verified deployment `rrClientconsole` was started from a root
shell and the executed identity was measured, not assumed: the marker file it created was owned `root:root` and
the `id` output it wrote was `uid=0(root) gid=0(root) groups=0(root)`. Royal Render enforces no privilege
separation between the job-dispatch identity and the operating system, so the executed command inherits the
worker's privileges whole.

We report that as measured root with the cause stated, and we do not present root as a vendor-mandated default:
no shipped artefact we examined fixes a non-root worker identity, and none mandates root either. A worker whose
purpose is to run arbitrary render commands runs with whatever its operator granted, which makes this a
deployment-dependent ceiling that mitigation item 5 addresses directly.

### Sink Identification — the job data confirms which field feeds the sink

Decompressing the captured job record shows the field that carries the scene path. The dataset key is
`execOnce.file` - present twice, at job offsets 7818 and 8324 - and the value is a length-prefixed UTF-16LE
string:

```
job offset 3788:  14 00 00 00                         little-endian uint32 = 20, the character count
job offset 3792:  "/tmp/rr_clean_poc.sh"              20 UTF-16LE characters (40 bytes), the scene path
job offset 3832:  00 00 00 ...                        NUL padding up to the next field
```

The same record contains a job label at offset 36692 that folds both facts into one string -
`-/8/8EVG_pyKF7h_Execute__tmprr_clean_po` - so the scheduler itself names the job by its type and its scene,
which is a useful detection artefact and is cited under Reachability.

### Sink Identification — sibling sinks, and whether they are proven

- The Windows template `<EndsWith(<Scene> , .bat) call > <EndsWith(<Scene> , .cmd) call > "<Scene>"` in the same
  shipped file is the same construction against `cmd.exe`. **Read from the artefact, not executed**; no Windows
  build was run, and it is reported as a structural reading of a shipped configuration file
- `<AdditionalCommandlineParam>`, populated by the SDK's `AddCmdFlags` custom data-set field
  (`newJob.customDataSet_Str("AddCmdFlags", ...)` in the shipped `submit_job.py` example), is appended to the
  shell command *outside* any quoting: `source "<Scene>" <AdditionalCommandlineParam>`. Shell metacharacters in
  that value - `;`, `$()`, backticks, redirection - would therefore be interpreted by the worker's shell. This
  is a **structural inference from the shipped template**. It was not executed: the verified capture contains no
  `AddCmdFlags` field at all (a search of the decompressed job record for that string, in both ASCII and
  UTF-16LE, returns nothing), so this advisory does not rate it, does not put it in Impact, and does not add it
  to the headline score. It is published because a vendor fixing the primary defect should fix this one in the
  same pass, and because if it were confirmed it would remove the scene-file precondition entirely and move the
  chain to conditional reading A
- `<CustomFlags>` appears in `CommandLine_Win` only. Whether it is substituted on Linux, and what it expands to,
  was not determined
- Post-processing tasks named in the verified job record - `PPAllExecuteFirst`, `PPDeleteJob`,
  `PPDeletebroken`, `PPFFmpeg-264`, `PPFFmpeg-ffv1`, `PPAssembleTiles`, `PPSequenceCheck`,
  `PPHoudiniStopSimServer`, `PPCreateFullVideo`, `PPCreateSmallVideo`, `PPOcioConvertSequence`,
  `PPOiiToolConvertSequenc`, `PPShotgun-pre-updateSt`, `PPDeleteJob` - are additional job-semantics primitives
  an anonymous submitter can select. Two of them (`PPDeleteJob`, `PPDeletebroken`) are destructive to queue
  state and are cited as an independent integrity and availability impact, not as an execution path

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted input is a job-submission record sent to TCP 7773, of which the attacker-controlled part relevant
to the sink is the `execOnce.file` dataset holding the scene path. There is no HTTP request, no header, no
cookie, no query string and no form field: the transport is a single custom binary message on one TCP
connection, and the server's response to an anonymous submission is a normal functional reply.

The verified capture is 1387 bytes. It was obtained by capturing one legitimate anonymous submission, and the
published PoC replays it - so the claim "this reaches an executing worker" rests on an observed wire exchange,
and the protocol facts below were recovered by us from that capture and are independently reproducible.

### Source Identification — packet layout as decoded

```
offset   size  field                                             value in the verified capture
------   ----  ------------------------------------------------  ---------------------------------
0x00     4     protocol prefix                                   07 0d 01 00
0x04     8     per-message value                                 1d 55 e2 9f 91 52 ab f6
0x0c     2     constant                                          01 00
0x0e     4     uint32 LE, length of the trailing compressed block 1047  (= 1387 - 340)
0x12     4     uint32 LE, decompressed length of that block       55252
0x16     8     small constant fields                             01 00 04 03 00 ...
0x1b     2     uint16 LE, length prefix of the submitter hostname 0x0017 = 23
0x1d     23    submitter hostname, ASCII, zero-padded buffer      (the submitting host's name)
...            fixed header fields, zero-padded
0x154    1047  zlib stream, RFC 1950 header                      78 5e   (FLEVEL 1)
```

Three of these are verifiable statements rather than guesses, and a reader can check them from the published
PoC:

- The uint32 at offset 0x0e equals the byte length from offset 0x154 to the end of the packet, exactly
- The uint32 at offset 0x12 equals the length of the decompressed job data, exactly (55252)
- A scan of every uint16 and uint32 at every byte offset in the 340-byte header for a value equal to the packet length, the
  header length, the compressed length or the decompressed length found *only* offsets 0x0e and 0x12. Nothing in
  the header encodes the total packet length, so a payload of a different compressed size only requires the
  single field at 0x0e to be updated

The 8 bytes at offset 0x04 are not a content integrity field. The server's own reply begins with the same
`07 0d 01 00` prefix and carries a *different* 8-byte value (`c9 a9 6e 6c d4 6b b1 79`), which is the behaviour
of a per-message nonce or identifier rather than of a checksum over content. Stated explicitly because the
published PoC rewrites one field inside the payload, and a reader is entitled to know whether that invalidates
an integrity check: no integrity check over content was identified in the header, and the rewritten field is
the submitter hostname, which the server demonstrably does not validate.

### Source Identification — the job record inside

Decompressing from offset 0x154 yields 55252 bytes of job data containing length-prefixed UTF-16LE strings. The
fields relevant to this finding, at their byte offsets in the decompressed record:

| Offset | Length prefix | Value | Meaning |
| --- | --- | --- | --- |
| 32 | - | `Execute` | job type name |
| 596 | - | `;Once` | renderer-name fragment |
| 3688 | - | `25-rr9.1.26b` | server version text, ASCII |
| 3788 | `14 00 00 00` = 20 | `/tmp/rr_clean_poc.sh` | the scene path - the tainted value |
| 6812 | - | `/tmp/` | path fragment |
| 6824 | - | `Folder>/` | path fragment |
| 7818 | `0d 00 00 00` = 13 | `execOnce.file` | dataset key naming the file to execute |
| 8324 | `0d 00 00 00` = 13 | `execOnce.file` | same key, second occurrence |
| 25692 | - | `*rrEnvFile` | environment-file field |
| 25703 | - | `<CompanyProjectRootFolder>renderfarm.rrEnv` | environment file path as a template |
| 31484 | `04 00 00 00` = 4 | `root` | a user-shaped field - see the non-claim below |
| 31702 | - | submitter hostname | second occurrence, inside the job record |
| 31982 | - | `PPAllExecuteFirst` and the other post-processing task names | task list |
| 36624 | - | submitter hostname | third occurrence |
| 36692 | `27 00 00 00` = 39 | `-/8/8EVG_pyKF7h_Execute__tmprr_clean_po ` | job label folding type and scene together |

Every string field in the job record carries the same framing: a little-endian uint32 giving
the character count, immediately followed by that many UTF-16LE characters. The verified record shows 7 for
`Execute`, 5 for `;Once`, 20 for the scene path, 13 for `execOnce.file`, 4 for the `root` field and 39 for the
job label. That regularity is what makes the record readable without vendor documentation and without
disassembly, and the published proof of concept reproduces every offset in the table above through its
`--dump-record` mode, so a reviewer can check them independently.

Two clarifications that a reader might otherwise draw wrongly:

- The `root` string at offset 31484 is an observed field. We do **not** claim that it, or the packet, requests
  root execution, because we did not determine which of the several adjacent user-shaped fields it is - a
  requesting user, a per-job run-as identity or a farm account label. The verified root execution has a
  simpler and fully evidenced cause: the worker process itself ran as root
- The value `<CompanyProjectRootFolder>renderfarm.rrEnv` at offset 25703 shows the product resolving paths
  through a company-project-root template for its own environment file. The scene path field, by contrast, was
  accepted as a literal absolute path. We did not test whether the template variable is expanded for scene
  paths, and we make no claim either way

### Source Identification — sanitization that exists, and what it is for

There is quoting around the scene path - the template writes `"<Scene>"` - and that is real but narrow. It
protects against a scene path containing spaces or glob characters breaking the command apart. It does not
protect against anything an attacker would want to do, because the path is not being sanitized, only delimited.
The `AddCmdFlags` substitution sits *outside* those quotes, so the one field with genuine injection value is the
one that is not delimited at all - which is the structural CWE-78 observation above.

### Source Identification — validation that is absent

- No allow-list of scene directories against which the submitted path is resolved
- No canonicalisation, so a path outside project storage is accepted as given
- No owner, group or mount-point check tying the scene to storage the studio controls
- No signature or checksum verification of the scene file
- No restriction on which submitter may name which path, because the default configuration produces no
  submitter identity
- No rejection of a scene extension (`.sh`) that means "execute this as a shell script", even though the job
  type's own `SceneFileExtension` declares precisely that intent

## 7. Data Flow

### Data Flow — end-to-end chain

```
attacker (no credentials)
   |  TCP 7773, custom binary RR protocol
   |  one 1387-byte submission record
   |    header 0x00-0x153  (prefix, nonce, block lengths, submitter hostname)
   |    zlib   0x154-end   (job record, 55252 bytes decompressed)
   |      job type      = Execute / Once
   |      execOnce.file = /tmp/rr_clean_poc.sh      <-- attacker-chosen path
   v
rrServer (rrServerconsole, default config: nTCPRequiresAuth=false, empty whitelist)
   |  no identity check -> record accepted
   |  replies 346 bytes (functional reply, prefix + submitter hostname echoed)
   |  enqueues the job; dispatches it to an idle worker
   v
rrClientconsole (worker, started by root)
   |  reads render_apps/_config/E01__ExecuteOnce.cfg
   |  CommandLine_Lx template: <EndsWith(<Scene>,.sh) source > "<Scene>" <AdditionalCommandlineParam>
   |  scene path ends in .sh -> branch selected
   |  builds and runs a shell command:  source "/tmp/rr_clean_poc.sh"
   v
shell, uid=0(root)
      marker file created root:root (34 bytes)
      id -> uid=0(root) gid=0(root) groups=0(root)
```

### Data Flow — properties of the chain worth naming

- The tainted value crosses a trust boundary twice and is checked nowhere: network client to scheduler
  (no identity check), then scheduler to worker (no path check). The worker treats a value that originated on
  an anonymous socket as an instruction to execute
- The payload is a *reference*, not content. The record carries a path and the worker fetches the file itself.
  This is what makes shared render storage the natural placement vector, and it is the exact reason the chain is
  rated `AC:H`: the reference is fully attacker-controlled while the referent was, in our test, placed by us
- The chain needs no session, no token, no cookie, no CSRF protection to defeat and no cross-site context,
  because there is no web layer. It is one TCP write
- The server's reply is a normal reply. An operator watching the scheduler for authentication failures sees
  nothing, because no authentication was attempted and none failed
- One submission reaches whichever worker is idle, so the fan-out is to the farm rather than to a single host,
  and each worker's mounts come with it
- The job label at offset 36692 shows the scheduler names the job from its type and its scene path, so the
  tainted value propagates into logs and the management UI in a human-readable form. That is a detection
  opportunity, and the only one the chain creates by itself

## 8. Exploit Construction

### Exploit Construction — step sequence

The proof of concept published in this directory is `exploit/royal_render_default_unauthenticated_job_submission_root_rce.py`,
pure Python standard library, no third-party dependency. It performs:

1. Write the scene script - a POSIX shell script that creates a marker file, writes the output of `id` to a
   sibling file, and appends a confirmation string to the marker - to the path named inside the captured job
   record. This is the placement step, and the script is explicit that it is a local precondition the product
   did not provide
2. Remove any stale marker and identity file from a previous run, so that anything observed afterwards is
   attributable to this submission and not to leftovers
3. Open a TCP connection to `--target` on `--port` (default `127.0.0.1:7773`), send the submission record
   verbatim, and read the reply until the server closes the connection, reporting the reply length and its
   first 32 bytes
4. Poll for the marker file for the duration of `--timeout`, then report the marker's size, owner uid and gid,
   its content, and the captured `id` output
5. Exit non-zero if the submission produced no reply or no marker appeared within the timeout, distinguishing
   "the job was not accepted" from "the worker did not execute it"

### Exploit Construction — the captured record, and exactly what was changed in it

The record is a replay of one legitimate anonymous submission captured during research. It carries a submitter
hostname, which in the original capture was the name of the research host. Publishing that name would disclose
research infrastructure, so the field was rewritten - and because honesty about payload modification matters
more than the convenience of saying "this is the raw capture", the substitution is stated here and in the PoC:

- The submitter hostname occurs three times: once in the header as 23 ASCII bytes at offset 0x1d, and twice
  inside the compressed job record as length-prefixed UTF-16LE strings
- It was replaced with `rrpoc-submit-host-00001`, which is exactly 23 bytes ASCII and therefore exactly 46
  bytes UTF-16LE, so every length prefix remains correct and the decompressed job-record length stays 55252
- Because the compressed size changes when the content changes, the uint32 at offset 0x0e was updated from 1047
  to the new compressed length and the packet is 1383 bytes instead of 1387. As established in Source
  Identification, no other header field depends on payload size
- The replacement was compressed at a level that reproduces the captured stream's own zlib header `78 5e`, and
  the published packet round-trips: decompressing its payload yields the job record byte-for-byte, with
  `execOnce.file` and the scene path intact
- The substitution is safe *because* the field is not validated. The research established that the server
  accepted a submission from a second host whose hostname differed from its own. Whether a target rejects a
  rewritten packet can only be settled by running it against that target; the verified detonation that this
  advisory reports used the original captured record with all three occurrences of the research hostname, and
  the published packet differs from it only in those three occurrences, the one length field and the resulting
  total size

### Exploit Construction — payload engineering constraints

- The scene path inside the compressed job record cannot be edited by the PoC without recompressing the record
  and rewriting the length field, which the payload's own framing permits but the published script does not
  attempt. The path is therefore fixed at `/tmp/rr_clean_poc.sh` in the shipped script, and the script says so
  rather than accepting a `--scene-path` value it would silently fail to honour in the packet
- Consequently the marker and identity file paths are controlled by the *scene script content*, which the
  PoC writes, not by the packet. `--marker-path` changes what the script writes; it does not need to touch the
  record
- The `.sh` extension is mandatory to select the `source` branch of the template, so the scene path must end in
  `.sh`
- The reply has no documented success semantics that we could confirm, so the PoC treats "a non-empty reply
  arrived" as evidence of acceptance and defers the verdict to the marker file, which is unambiguous
- No payload obfuscation, no evasion of a security control, no timing constraint and no brute-force component
  exists in this chain; there was nothing to evade, which is itself a finding

### Exploit Construction — what the exploit deliberately does not do

- It does not use `AddCmdFlags` or any command-injection in `<AdditionalCommandlineParam>`. That angle is
  structural only, was not executed, and mixing an unverified primitive into a verified PoC would weaken both
- It does not attempt to write a file to the target over port 7773. No such primitive was demonstrated, and
  the precondition is stated instead of being hidden
- It does not enumerate or attack workers directly. The worker is reached through the scheduler's own dispatch
- It performs no destructive operation. The scene script creates a marker, records `id`, and exits; it does not
  modify the queue, does not delete jobs, does not touch project storage and does not install persistence
- It does not carry a licence check, a version fingerprint or any target-side probe beyond the single
  submission. Version evidence comes from the job record's own `rr9.1.26b` string and from the installed tree

## 9. Dynamic Verification

### Dynamic Verification — environment

- Target: a Linux x86-64 host in an isolated cloud sandbox environment running a full Royal Render 9.1.26b
  installation made with the vendor's `rrSetup_linux` installer, configuration unmodified after install, no
  licence installed (two-client demonstration mode)
- Scheduler: `rrServerconsole` listening on TCP 7773, measured bound to all interfaces on that host
- Worker: `rrClientconsole`, headless, started from a root shell and pointed at the scheduler
- Client: a Python standard-library socket program with no credentials
- Independent-host repetition: the same submission driven from a second client host on a different network
  segment from the target, in its own network namespace, whose source address was in the private range and whose
  hostname differed from the scheduler's

### Dynamic Verification — the triggering submission

One TCP connection, one write, no handshake first:

```
connect -> target:7773                       (no username, no password, no prior exchange)
send    -> 1387 bytes                        (Execute / Once, execOnce.file = /tmp/rr_clean_poc.sh)
recv    <- 346 bytes, first 32:
           070d0100c9a96e6cd46bb1790000060000000600000001000a01001700695a32
close                                        (server closes; single-shot exchange)
```

The reply's first four bytes repeat the connection prefix `07 0d 01 00`, its 8-byte per-message value differs
from the request's, and its trailer contains `00 17 00` followed by the submitter hostname - the server parsed
the record and answered with the hostname it read from it. No challenge, no error code, no rejection.

### Dynamic Verification — observed output

The proof of concept reported, on the successful run. Two provenance notes are owed here rather than left to
inference. The verified detonation used the original captured record, 1387 bytes, whose submitter hostname was
the research host's own name; the record published in this directory is that capture with the hostname
replaced, which is 1383 bytes, and so a run of the published tool reports its own length rather than 1387. The
research run's console output was also in the researcher's own language, and is rendered in English below; the
measurements themselves - the 346-byte reply, its first 32 bytes, the marker's size and ownership, and the `id`
output - are the values recorded at the time and are repeated verbatim in the target-side readout that
follows.

```
[*] target: 127.0.0.1:7773
[*] wrote scene script /tmp/rr_clean_poc.sh (the worker will `source` it)
[*] removed stale markers, triggering...
[*] record length: 1387 bytes
[*] connecting to 127.0.0.1:7773 (no username, no password; the default config performs no identity check)...
[+] submission record sent (Execute / Once job)
[+] server reply: 346 bytes, first 32 = 070d0100c9a96e6cd46bb1790000060000000600000001000a01001700695a32
[*] waiting for the worker to execute the scene script (up to 30s)...
[+] marker file created: /tmp/rr_clean_marker_UNAUTH_RCE
[+] marker size 34 bytes, owner uid=0 gid=0
[+] marker content: Royal-Render-unauth-RCE-confirmed
[+] execution identity (id output): uid=0(root) gid=0(root) groups=0(root)
```

Read back from the target independently of the PoC:

```
-rw-r--r-- 1 root root 34 ... /tmp/rr_clean_marker_UNAUTH_RCE
-rw-r--r-- 1 root root 36 ... /tmp/rr_clean_whoami.txt

uid=0(root) gid=0(root) groups=0(root)
Royal-Render-unauth-RCE-confirmed
```

The evidence set is: a marker file owned `root:root`, 34 bytes, with the confirmation string; an `id` output of
`uid=0(root) gid=0(root) groups=0(root)`; a 346-byte functional reply to a credential-free submission; and a
worker that executed a file it was told to execute by an anonymous socket.

### Dynamic Verification — the independent-host repetition, and why it matters

The chain was repeated from a second client host on a different network segment, with its own network namespace
and a private-range source address, using no credentials. That repetition answers the objection that would
otherwise be reasonable - "you demonstrated it from localhost, so you demonstrated a local issue":

- The scheduler accepted the submission from a foreign source address
- It also accepted a foreign submitter hostname, which is the fact that makes the published PoC's hostname
  substitution safe and is stated in Exploit Construction
- The worker still executed the scene script as root
- The authorization state was the shipped one, read from `globalconfig.ini` on the target rather than assumed

So the remote-reach claim in this advisory is not argued from a bind address alone. It is demonstrated across a
network boundary, which is a stronger position than an advisory that verifies on loopback and infers the rest.

### Dynamic Verification — what our harness provided, stated separately

This boundary is drawn explicitly because it is the one that changes the score:

- The scene script's *content* and its *presence* at `/tmp/rr_clean_poc.sh` on a worker-readable path were
  created by our test setup. The product delivered no bytes. No primitive reachable over TCP 7773 wrote that
  file, and none is claimed
- The worker's root identity came from starting it as root. Royal Render neither forced nor prevented that
- The scheduler's all-interface bind was measured on our instance. No shipped artefact states the default bind
- The demonstration-mode licence state was ours. The authorization key that governed observed behaviour is a
  shipped configuration key

Everything else in the chain - acceptance of the anonymous connection, acceptance of the submission record,
dispatch to the worker, template resolution, `source` of the named path, and execution identity inheritance -
is product behaviour observed, not harness state.

### Dynamic Verification — boundaries of what was verified

- One version (9.1.26b), one platform (Linux x86-64), one job type (`Execute` / `Once`), one sink branch
  (`source` for a `.sh` scene)
- Not verified: the Windows `call` branch; `AddCmdFlags` command injection; submission behaviour when
  authorization *is* enabled; whether a low-privileged RR user may submit this job type; whether a scene path
  outside project storage is treated differently by a hardened farm configuration; whether a licensed build
  differs; whether the `root` field at job offset 31484 has any effect on execution identity; whether a scene
  path resolves `<CompanyProjectRootFolder>`-style templates
- The number of successful detonations was more than one (a same-host run and the independent-host repetition),
  both producing root-owned markers. We do not report a count as a figure of merit; both runs are described
  above and neither is inflated into a broader claim

## 10. Reachability and Security Impact

### Reachability and impact — network position

The finding requires TCP reachability to port 7773 and nothing else from the network side. What that means in
practice depends on where the scheduler sits, and the advisory does not overstate it:

- A scheduler reachable from the studio's production network is reachable by anything with a foothold there - a
  compromised artist workstation, a pipeline host, or a contractor laptop. This is the common case, because
  submitters *are* workstations on that network, and an anonymous submission from one is indistinguishable from
  a normal one
- A scheduler published to the internet is reachable from the internet. We did not measure internet exposure
  of Royal Render installations and publish no exposure census; the point is conditional on the reader's own
  deployment
- A scheduler bound to a management segment is reachable from that segment, which is conditional reading D
- The protocol adds no restriction of its own: no source-address check, no hostname check (verified), no
  prior-session requirement, no TLS handshake to fail

### Reachability and impact — what the achieved primitive controls

An anonymous submitter who reaches a worker's shell controls everything the worker's identity controls, and
more than that:

- Every project asset readable from the worker, which on a farm means mounted project shares, cache volumes and
  any credentials stored alongside them
- The worker host itself, at the identity measured (root): OS configuration, installed packages, startup
  mechanisms, and every other service on that host
- The farm, transitively. Other workers are reachable from a compromised worker through the mounts they share,
  and the scheduler remains reachable for further anonymous submissions
- Queue integrity. Independently of code execution, the anonymous submitter can enqueue and cancel work using
  the product's own post-processing tasks, two of which (`PPDeleteJob`, `PPDeletebroken`) are destructive, and
  the verified job record contains the full task list, so this is a real capability of the demonstrated channel
  rather than a hypothetical one
- Render availability. A farm whose workers are running attacker-chosen work is a farm that is not rendering,
  and on a production schedule that is measured in delivery dates

### Reachability and impact — the privilege question, answered in full

The measured identity was root, and the reason is stated rather than glossed: the worker process ran as root
because it was started from a root shell, and Royal Render performs no privilege separation between the identity
that receives a job and the identity that executes it. Two claims are therefore kept distinct.

**Claimed**: arbitrary shell command execution as the identity of the worker process, measured as
`uid=0(root) gid=0(root) groups=0(root)`, with a `root:root` artefact as the evidence. The lack of privilege
separation is a real property of the product observed in this deployment: nothing interposed between the
dispatch identity and the executed command.

**Not claimed**: that root is Royal Render's vendor-mandated default worker identity. No shipped artefact we
examined - installer script, start-up configuration, documentation page - fixes a default worker identity in
either direction, and this advisory does not manufacture one. A worker whose documented purpose is to execute
render commands runs with whatever privileges its operator granted it; a studio that already runs workers as
root gets root here, and a studio that runs them as an unprivileged service account gets that account. The
consequence for scoring is that the impact ratings rest on arbitrary command execution on a farm host, which is
complete regardless of which account is involved, and the mitigation that removes the root case specifically is
listed as a named item rather than being folded into the score.

### Reachability and impact — the window, and what it costs an attacker

There is no window. This is not a first-run condition that closes when an administrator sets a password, and
not a state that a restart clears. The unauthenticated condition is the shipped default, it persists
indefinitely, and it is only changed by an operator who reads `files/help/Authorization.html` or the
`globalconfig.ini` key and acts on it. From the attacker's side the cost is: reach the port, hold a submission
record (the vendor's own SDK and example scripts are shipped in the installation tree and produce them), and
have a scene file somewhere the worker can read. The first two are trivial. The third is the entire attack
complexity, which is why the headline rating carries `AC:H` and why conditional reading A exists for farms
whose shared storage is writable from a segment an attacker has reached.

### Reachability and impact — detection notes

The chain produces almost no anomaly, because each step is normal product traffic. Concretely:

- The scheduler logs a job submission. That is what it is for, and the submission is not flagged as anonymous
  because anonymity is the default state
- The worker executes a command line. That is also what it is for
- The strongest available signal is the *content* of the submission: an `Execute` / `Once` job whose
  `execOnce.file` names a path outside recognised project storage. The job label the scheduler derives from
  the type and scene (`..._Execute__tmprr_clean_po` in the verified record) makes this visible in management
  views without decoding the protocol
- Configuration audit is the highest-value signal: `nTCPRequiresAuth=false` with an empty `nAuthWhiteList` in
  `sub/cfg_global/globalconfig.ini` on any farm that is reachable beyond a management segment is the finding,
  whether or not it has been exploited
- Filesystem audit on workers: shell scripts in world-writable directories such as `/tmp`, and worker processes
  whose parent is not the expected start-up path
- We publish no vendor-specific detection signature beyond these, because a signature would have to match a
  legitimate submission record, and there is no field in it that distinguishes hostile from normal use

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

1. **Ship with authorization on** (CWE-1188). `nTCPRequiresAuth=true` as the installer default, with an
   explicit opt-out that records the choice. The current documentation presents the unauthenticated state as
   the baseline; a scheduler that turns submitted paths into shell execution should not have an unauthenticated
   baseline
2. **Separate the `Execute` / `Once` job type from ordinary submission** (CWE-284). It is an arbitrary
   execution primitive wearing a job-type name. Require an administrator capability for it, deny that capability
   by default even with authorization enabled, log the submitting principal and resolved scene path, and
   consider removing it from the shipped job-type set in favour of an explicitly installed one
3. **Validate the scene path** (CWE-73). Canonicalise `execOnce.file`, resolve against configured project and
   shared-storage roots, reject anything outside them, reject symlink resolution leaving the allowed subtree,
   and reject world-writable directories outright
4. **Stop building shell command lines from job fields** (CWE-78). Pass job arguments as an argument vector
   instead of a template string, or shell-quote every substitution. `<AdditionalCommandlineParam>` and
   `<CustomFlags>` are appended outside quoting in both the Linux and Windows templates, so the one place the
   quoting exists is not the place injection value lives
5. **Enforce privilege separation on workers** (CWE-250). Drop to a dedicated unprivileged account before
   executing a job command line, and warn when a worker is started by root
6. **Authenticate the connection, not just the operation** (CWE-306). The anonymous connection is accepted
   before job semantics are examined, so the whitelist and `nTCPRequiresAuth` should apply at connect time for
   every client class - submitter, worker, admin tooling and SDK alike
7. **Verify scene provenance** (CWE-1392 / CWE-345 class). Where the deployment allows it, a signed or
   checksummed manifest for scene files a worker will execute, so a third party writing to shared storage does
   not obtain worker-privileged execution for free
8. **Bind narrowly and document 7773 as a management port** (CWE-284, CWE-1188). Bind to the render-management
   interface rather than every interface, and ship an installer firewall profile that reflects it

### Fix Recommendations — a regression test the vendor should add

From a default installation, open a TCP connection to 7773 with no credentials, submit the `Execute` / `Once`
record from this advisory whose `execOnce.file` names a script in a world-writable directory, and assert three
things: the server refuses the submission; the refusal is logged with the source address; and no worker receives
a dispatch. Then, with authorization enabled as a non-administrative user, repeat and assert the same refusal,
which is what separates fix 2 from fix 1. Finally, assert that an `AddCmdFlags` value of `; id` arrives at the
renderer as a single literal argument rather than as a second command, which is what separates fix 4 from a
cosmetic change.

### Fix Recommendations — operator-side, until a patch exists

1. Enable `nTCPRequiresAuth` and populate `nAuthWhiteList`; verify by attempting an anonymous submission and
   confirming rejection
2. Firewall TCP 7773 to named scheduler, worker and submitter addresses; never publish it through NAT, and
   treat any internet-facing 7773 as already compromised and investigate it as such
3. Run `rrClientconsole` as a dedicated unprivileged user with write access limited to output directories, and
   audit the start-up path that launches it
4. Read mount shared render storage on workers where the workflow allows it, and audit write permissions from
   workstation segments; shared storage that is writable from a workstation is writable from anything that
   compromises one
5. Review `render_apps/_config/` and remove any job type the studio does not use - `E01__ExecuteOnce.cfg` in
   particular, since deleting it removes the primitive without patching anything
6. Alert on `Execute` / `Once` jobs whose scene path is not inside a recognised project directory, and on shell
   scripts appearing in world-writable directories on worker hosts
7. Assume the identity of anything that ran on a worker before authorization was enabled: rotate credentials
   reachable from worker hosts, and review startup mechanisms on those hosts

## 12. CWE and CVSS

### CWE and CVSS — classification

- **CWE-306, Missing Authentication for Critical Function** (primary). The submission channel on TCP 7773 has
  no identity check in the shipped default configuration, and the function reached through it is shell
  execution on a worker. Not CWE-287 or CWE-288: there is no authentication mechanism that was incorrectly
  implemented or bypassed, there is no authentication by default at all
- **CWE-1188, Insecure Default Initialization of Resource** (co-equal). The vendor documents the missing check
  as the default and the installer writes `nTCPRequiresAuth=false` with an empty whitelist. The insecure state
  is the initial state, which is a distinct defect from the missing check and needs its own fix
- **CWE-73, External Control of File Name or Path**. The `execOnce.file` dataset carries a path from an
  external, unauthenticated source into a worker's shell command with no allow-list or canonicalisation
- **CWE-250, Execution with Unnecessary Privileges** (contributing, not raising any metric). The worker
  executed the command with its own root privileges and no separation was enforced. Reported as contributing
  because the identity is deployment-dependent, as covered under Reachability
- **CWE-284, Improper Access Control** (contributing). No principal-based restriction on a job type whose
  semantics are arbitrary execution; reported as contributing rather than primary so the classification does
  not blur into CWE-306
- **CWE-78, OS Command Injection** (structurally identified, not load-bearing). The unquoted
  `<AdditionalCommandlineParam>` append in `CommandLine_Lx` and `CommandLine_Win`. Reported and reasoned about
  above, not executed, not in Impact, and not reflected in any published score
- **CWE-1392 / CWE-345 class** (contributing). No verification of scene-file provenance before privileged
  execution

Deliberately not used: CWE-94 (no code was injected into an interpreter by us), CWE-502 (no deserialisation
gadget), CWE-787 and friends (no memory-safety defect), CWE-798 (no hardcoded credential), CWE-119 (no buffer
involvement), and CWE-862 (the missing control is authentication, not an authorization decision on a request
that had one).

### CWE and CVSS — vector derivation

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.1 High.

- **AV:N** - the vulnerable component is bound to the network stack and the protocol imposes no adjacency
  restriction; the chain was driven from a client host on a different network segment from the scheduler.
  Reachability beyond that is a deployment property, published as conditional reading D
- **AC:H** - a successful attack needs a script present at a worker-readable path with attacker-chosen content.
  The job record carries only a path, and that file was placed by our test setup, not delivered by the product.
  The condition is outside the submission primitive we demonstrated, so complexity is high rather than low
- **PR:N** - no credential exists in the verified exchange; the server accepts the connection and the record
  without a principal, in the documented default state
- **UI:N** - no operator, artist or administrator action is needed; workers poll for jobs as routine
- **S:U** - dispatching jobs to workers, including the `Execute` job type whose declared purpose is running a
  script, is the product's documented function, and the impacted resources sit inside the same product
  authority the missing gate was meant to protect. Changed is a reasonable alternative reading for an assessor
  who counts the worker's OS as a separate authority, and is published below with its arithmetic rather than
  used here
- **C:H / I:H / A:H** - arbitrary shell execution as the worker identity yields all project and host data
  readable from it, unrestricted modification of storage and queue state, and complete control of render
  availability

Arithmetic, computed from the vector with the CVSS 3.1 formula rather than copied from any source note:
ISS = 1 - ((1 - 0.56)(1 - 0.56)(1 - 0.56)) = 1 - 0.085184 = 0.914816. Impact(S:U) = 6.42 * 0.914816 =
5.873119. Exploitability = 8.22 * 0.85 (AV:N) * 0.44 (AC:H) * 0.85 (PR:N, S:U) * 0.85 (UI:N) = 2.221167.
Base = min(5.873119 + 2.221167, 10) = 8.094286, rounded up to the nearest tenth = **8.1**.

The research notes behind this advisory carried no CVSS figure for this finding. Nothing was inherited, nothing
was corrected, and no known systematic scoring error was carried forward.

### CWE and CVSS — the Scope decision

Changed was considered seriously here, more so than in a same-host finding, because the vulnerable component
(`rrServer`'s missing connection-time identity check) and the impact location (a worker's shell, in production a
different host with its own operating system) are literally different machines. The argument for Changed is
that the worker's OS is a separate security authority from the scheduler.

The argument against, which prevailed: crossing from scheduler to worker is not crossing out of the product's
authorization domain - it is what the product exists to do. The RR farm is one managed domain; workers are
registered to the scheduler, receive their work exclusively from it, and the submitted job is dispatched by the
product's own machinery using its own configuration. The missing gate was supposed to protect exactly the
resources that were reached, which is the definition of the authority being unchanged. Publishing Changed as the
headline would also overstate the finding's independence from ordinary product function.

So Scope: Unchanged is the headline, and `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` = 9.1 Critical is
published as conditional reading B for assessors who read the domain boundary differently, with its
lower-complexity companion `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L` deliberately *not* published - the
all-high variant of that vector is `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0, which caps, and a
partial-availability variant would be a different finding rather than a rating nuance.

### CWE and CVSS — conditional readings, labelled as such

Published with full vectors and arithmetic so that no reader has to guess which conditions attach to which
number. None of these is the headline score.

- **A - script placement available, or `AddCmdFlags` confirmed**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8
  Critical. Exploitability = 8.22 * 0.85 * 0.77 * 0.85 * 0.85 = 3.887043; base = 5.873119 + 3.887043 =
  9.760162, rounded up to 9.8. Applies where the attacker can write to the shared render storage the product's
  own scene-distribution model uses, or where the structural CWE-78 observation is confirmed and removes the
  scene-file precondition. We did not detonate either branch, which is exactly why the headline is `AC:H`
- **B - Scope Changed**: `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` = 9.1 Critical. ISS is unchanged at 0.914816;
  Impact(S:C) = 7.52 * (0.914816 - 0.029) - 3.25 * (0.914816 * 0.9731 - 0.02)^13 = 6.128026; base = 1.08 *
  (6.128026 + 2.221167) = 9.017... rounded up to 9.1. At low complexity the same vector is
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0 (base 1.08 * (6.128026 + 3.887043) = 10.816..., capped at 10.0)
- **C - authorization enabled by the operator**: a valid RR user is required. If any authenticated user may
  submit `Execute` jobs, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 (Exploitability = 8.22 * 0.85 * 0.77 * 0.62
  * 0.85 = 2.835255; base 8.708374, rounded up) and `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` = 7.5
  (Exploitability = 8.22 * 0.85 * 0.44 * 0.62 * 0.85 = 1.620146; base 7.493264, rounded up). If instead only a
  high-privileged user may submit this job type, `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 (Exploitability =
  8.22 * 0.85 * 0.77 * 0.27 * 0.85 = 1.234708; base 7.107826, rounded up) and
  `AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.6 (Exploitability = 8.22 * 0.85 * 0.44 * 0.27 * 0.85 = 0.705547;
  base 6.578666, rounded up). We did not test which privilege level applies with authorization on, so both are
  published and `PR:L` is explicitly the attacker-favourable bound. Note the pairing error worth naming: 8.8 is
  the `PR:L` value and 7.2 is the `PR:H` value at the same complexity - writing 8.8 next to a high-privilege
  vector is wrong and this project has published and corrected exactly that mistake before
- **D - management-network reach only**: `AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 7.5 (Exploitability = 8.22 *
  0.62 * 0.44 * 0.85 * 0.85 = 1.620146; base 7.493264) and `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.8
  (Exploitability = 8.22 * 0.62 * 0.77 * 0.85 * 0.85 = 2.835255; base 8.708374). Applies where an operator
  binds or firewalls 7773 to an internal management segment that an attacker must first join

### CWE and CVSS — what is deliberately not published

- No score for the `AddCmdFlags` injection. It was not executed, so it exists in this advisory as a
  structurally identified surface with its own CWE, and as one of the two routes into conditional reading A
- No score for the Windows `call` branch. Read from the shipped configuration file, never run
- No exposure census. We did not scan the internet for Royal Render installations and publish no count of
  reachable schedulers; a number like that would be a claim about other people's networks that we did not
  verify
- No claim that licensed builds behave identically. The unlicensed two-client demonstration mode is disclosed,
  the configuration-driven nature of the switch is stated, and the boundary stops there
- No inherited score. The research notes carried none, and none was invented to fill the gap

### CWE and CVSS — summary

Royal Render 9.1.26b ships a scheduler that performs no identity check by default, on a listener whose purpose
is to accept work that becomes shell execution on other hosts, and the vendor's own documentation states the
unauthenticated default. A credential-free client submits an `Execute` / `Once` job naming a script path; a
worker builds `source "<path>"` from the shipped job-type configuration and runs it with its own privileges,
measured as root. Headline `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.1 High, with four labelled
conditional readings reaching 9.8, 10.0, 8.8 and 7.5 under stated conditions. The gap between the headline and
conditional reading A is entirely the scene-file placement precondition, and it is published as a gap rather
than being closed by assumption, because the harness that satisfied it in testing was ours and not the
product's.
