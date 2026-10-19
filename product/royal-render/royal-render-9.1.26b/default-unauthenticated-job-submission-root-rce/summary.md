# Royal Render 9.1.26b - Default-Unauthenticated Job Submission on rrServer Port 7773 Reaching a Worker-Side Shell Script Execution as root (CWE-306, CWE-1188, CWE-73)

Advisory: https://0day-rubbish.com/blog/royal-render-default-unauthenticated-job-submission-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Royal Render 9.1.26b from Holistic IT GmbH (Darmstadt, Germany), the render-farm job manager that schedules
VFX and animation work across a pool of worker hosts, is a different product from the Royal Server gateway
sold by Royal Apps GmbH of Austria, and the two share nothing but a word in the name - this advisory is about
the German render manager only. Its central scheduler `rrServer` speaks a custom binary job protocol on TCP
7773 and, in the state the product ships in, performs no identity check on a connection whatsoever. That is
the vendor's own words, not ours: the help page shipped inside the installation tree at
`files/help/Authorization.html` states "By default, the rrServer does NOT check for a valid user if you
connect to the rrServer", and authorization is an opt-in feature - either a submission whitelist or an
"Authorization required for all connections" switch, both of which the `globalconfig.ini` that the vendor's
own `rrSetup_linux` installer writes into the installation tree leaves off (`nTCPRequiresAuth=false`,
`nAuthWhiteList=` empty). A client holding no credential of any kind can therefore submit a job of the
product's own `Execute` / `Once` job type, which is not a renderer at all. The shipped definition in
`render_apps/_config/E01__ExecuteOnce.cfg` sets its Linux command line to
`<EndsWith(<Scene> , .sh) source >  "<Scene>" <AdditionalCommandlineParam>`, so when the submitted scene path
ends in `.sh` the worker builds the shell command `source "<that path>"` and runs it. The scene path arrives
from the submitter as the length-prefixed UTF-16LE dataset field `execOnce.file` inside the compressed job
record, and nothing between the socket and the shell constrains it - no whitelist, no canonicalisation
against a project root, no owner check, no signature. Whatever privileges the worker `rrClientconsole` was
started with are the privileges the command gets; the verified detonation recorded
`uid=0(root) gid=0(root) groups=0(root)` in a marker file owned `root:root`. The whole chain was driven from
a separate client host on a different network segment, not only from the target's own loopback. There is no
memory corruption, no deserialisation gadget, no HTTP listener and no file-upload primitive in this finding:
the transport is the product's own documented submission protocol used exactly as documented, the payload
carrier is a path rather than bytes, and the only thing missing from an unauthenticated command-execution
channel is an identity check.

- **Component**: `rrServer` (the `rrServerconsole` image, a 4.4 MB ELF x86-64 Linux binary) listening on TCP
  7773 with a custom non-HTTP binary protocol, plus the worker process `rrClientconsole` that receives
  dispatched jobs and executes the resulting command line. Related binaries in the same tree -
  `rrClient`, `rrSubmitter`, `rrSubmitterconsole`, `rrPythonconsole` and `rrWebsite` - are not part of the
  verified path; `rrWebsite` generates statistics content and is not an HTTP server, so no web surface is
  involved at any point
- **Sink**: the shell construction emitted from the `CommandLine_Lx` template in
  `render_apps/_config/E01__ExecuteOnce.cfg` and executed by the worker - with a scene path ending in `.sh`
  the template resolves to `source "<Scene>" <AdditionalCommandlineParam>` and the worker runs it with its
  own privileges. The Windows sibling `CommandLine_Win` resolves to `call "<Scene>"` for `.bat`/`.cmd`
  scenes, which is the same construction and was read from the same shipped file rather than executed
- **Source**: an anonymous job-submission record accepted on TCP 7773. The verified capture is 1387 bytes:
  a 340-byte header carrying a two-byte length prefix (`0x17 0x00`) and the 23-byte submitter hostname at
  offset 29, a little-endian uint32 at offset 14 holding the exact length of the trailing compressed block
  (1047) and another at offset 18 holding its exact decompressed size (55252), and a zlib stream (RFC 1950
  header `0x78 0x5e`) beginning at offset 340. Inside the decompressed job record the scene path is a
  20-character length-prefixed UTF-16LE string `/tmp/rr_clean_poc.sh` at job offset 3792, named by the field
  key `execOnce.file` at job offsets 7818 and 8324, alongside the job-type strings `Execute` at offset 32
  and `;Once` at offset 596 and the server version text `rr9.1.26b`
- **Sanitization**: none on the path that was exercised. The server applies no identity check by default, so
  there is no principal against which a job type could be filtered; the job record's scene path is not
  checked against a project root, a share, or any allow-list; the command template quotes `<Scene>` but
  appends `<AdditionalCommandlineParam>` unquoted; and the worker performs no verification that the file it
  is about to `source` belongs to the studio's own project storage

## CVSS Score

- **Score**: 8.1 High (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) - an unauthenticated client that can
  reach port 7773 makes a worker execute a shell script whose path it chooses, as root, but the script's
  content has to be reachable by the worker first, and we did not demonstrate a product primitive that puts
  it there over 7773
- **Attack Vector: Network** - `rrServer` is a scheduler whose entire purpose is to accept submissions from
  separate submitter hosts and dispatch them to separate worker hosts over TCP 7773; the shipped Python SDK
  hardcodes that port for connecting to a remote server (`connection.py` calls `tcp.setServer(rr_server,
  7773)`), so a network-reachable listener is the product's intended operating mode rather than a
  configuration choice we made. The chain was driven end-to-end from a client on a different network segment
  from the target, whose hostname differed from the server's and was accepted. The protocol imposes no
  adjacency restriction of its own. The all-interface bind we observed was measured on the test instance and
  we did not locate a shipped artefact stating the default bind address, so a management-network-only
  deployment is published as a labelled conditional reading below
- **Attack Complexity: High** - the job record carries a *path*, never file content. Executing attacker-chosen
  commands therefore requires a script to exist at a worker-readable location, and in the verified run that
  file was written by our own test setup on the worker host; it was not delivered by the product and not by
  anything we sent over 7773. In a production farm the product's own scene-distribution model (shared render
  storage mounted by submitters and workers) makes that a placement problem rather than a hard blocker, but
  whether a network attacker can write to that share depends on the deployment. Both facts are stated
  plainly rather than smoothed over, and the lower-complexity reading is published as conditional reading A
- **Privileges Required: None** - no username, no password and no session token exist in the verified
  exchange. The default configuration accepts the connection and enqueues the job without a principal, and
  the vendor's SDK documents an anonymous server connection as its ordinary default (`server_connect()`
  takes `user_name=None, password=None`); its `_Info__ServerAuthorization.txt` describes the resulting
  subject as user `Anonymous`
- **User Interaction: None** - no operator, artist or administrator action, no browser session and no
  induced click is required; the worker polls the scheduler for work as a matter of routine
- **Impact C/I/A: all High** - arbitrary shell execution as the worker's identity yields every project asset
  and credential the worker host can read, unrestricted modification of the farm's storage and job queue, and
  total control of render availability (jobs can be deleted with the product's own `PPDeleteJob`
  post-processing task, which is present in the verified job record). The rating does not depend on whether
  that identity is root or a dedicated account
- **Scope**: Unchanged. `rrServer`'s missing identity check is the vulnerable component and the command it
  reaches runs on a worker, a second process on a second host in production; Changed was considered seriously
  for that reason and rejected as the headline, because dispatching jobs to workers is precisely the
  product's documented function and RR's own authorization model treats the farm as one managed domain, so
  the impacted resources sit inside the same product authority that the missing gate was supposed to
  protect. Its variant `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` computes to 9.1 and is not published as
  the finding's score
- **CWE**: CWE-306 primary, CWE-1188 co-equal and CWE-73 reported with it; CWE-250, CWE-284 and
  CWE-1392 contributing and reported separately without raising any metric; CWE-78 identified structurally
  from the shipped command template and explicitly not load-bearing in this rating
- **Recorded score**: the research notes behind this advisory carried no CVSS figure for this finding, so
  nothing was inherited and nothing needed correcting; every number published here was computed from its own
  vector with the CVSS 3.1 formula - ISS 0.914816, Impact(S:U) 5.873119, Exploitability 2.221167, base
  8.094286, rounded up to 8.1
- **Conditional reading A - script placement available**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` =
  9.8 Critical. Applies where the attacker can also write to the shared render storage the product's own
  scene-distribution model uses, or to any path the worker mounts, so that the path in the job record and the
  file at that path are both attacker-selected. It also applies if the structural observation about the
  unquoted `<AdditionalCommandlineParam>` append (CWE-78) is confirmed by execution, which would remove the
  scene-file precondition entirely. Labelled conditional; neither branch was detonated, so neither is the
  headline score
- **Conditional reading B - Scope Changed**: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` = 9.1 Critical,
  and with the lower complexity `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0 Critical. This is the
  reading an assessor who counts the worker's operating system as a separate security authority from
  `rrServer` would reach. Published for completeness and reasoning, not as the finding's score
- **Conditional reading C - authorization was enabled**: where an operator has switched on
  `nTCPRequiresAuth` or populated the whitelist, an anonymous submission is no longer accepted and the
  attacker needs a valid RR user. Which privilege level is required, and which complexity applies, were
  neither tested, so all four combinations are published one per line. Where any authenticated user may
  submit `Execute` jobs at low attack complexity, the vector
  is `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High.
  Where any authenticated user may submit `Execute` jobs and the headline's high attack complexity is kept,
  the vector is `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` = 7.5 High.
  Where only a high-privileged RR user may submit this job type at low attack complexity, the vector
  is `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 High.
  Where only a high-privileged RR user may submit it at high attack complexity, the vector
  is `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.6 Medium.
  `PR:L` is therefore the attacker-favourable bound and `PR:H` the conservative one. One pairing is worth
  naming because getting it wrong is easy and this project has previously published and corrected exactly
  this mistake: the value belonging to a low-privilege requirement is 8.8 at low complexity, and the value
  belonging to a high-privilege requirement at that same low complexity is 7.2
- **Conditional reading D - management network only**: `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` =
  7.5 High, or `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.8 High. Applies where an operator binds or
  firewalls port 7773 to an internal render-management segment that the attacker must first join. Labelled
  conditional on a deployment change we did not test

## Affected Products

- Royal Render version 9.1.26b from Holistic IT GmbH (Darmstadt, Germany), a closed-source commercial
  render-farm job manager for VFX and animation studios. The installation tree we examined credits the
  product to Royal Render and its author Holger Bünck, and the job record in the verified capture carries the
  server version text `rr9.1.26b`; we did not obtain a commercial-registry extract, so the company name used
  here is carried by the vendor's own product documentation and no claim beyond it is made. This is not the
  Royal Server product of Royal Apps GmbH (Austria)
- Affected components: `rrServer` / `rrServerconsole` on TCP 7773 in its default authorization state, and the
  `rrClient` / `rrClientconsole` worker that executes the dispatched `Execute` / `Once` command line
- Distribution artefacts: the Linux installer `rrSetup_linux` and its installation tree, including
  `bin/lx64/rrClientconsole`, `sub/cfg_global/globalconfig.ini`, `files/help/Authorization.html`,
  `render_apps/_config/E01__ExecuteOnce.cfg` and `SDK/External/Python/`
- Runtime architecture: `rrServer` as central scheduler on a custom binary protocol, workers that execute
  render commands, submitters (`rrSubmitter`, `rrSubmitterconsole`, or any socket client) that enqueue jobs, a
  Python SDK for scripted submission, and `rrWebsite` for generated statistics content. Scene files are
  expected to live on storage shared between submitters and workers
- Only 9.1.26b on Linux x86-64 was executed. The `CommandLine_Win` template in the same shipped
  `E01__ExecuteOnce.cfg` shows the `.bat` / `.cmd` equivalent using `call` instead of `source`, so the
  Windows build of the same version is characterised from that artefact and not from a detonation, and is not
  claimed as verified. Earlier Royal Render versions were not tested and are not claimed as affected; the
  shipped authorization documentation is the evidence for the default, and we did not diff it across versions
- Verification method and its boundary: live detonation against a running `rrServer` installed from the
  vendor's `rrSetup_linux` Linux installer with no configuration change, driven over a real TCP connection by
  a replay of a captured submission record - not an emulation, not a protocol replica and not a
  reimplementation. The vendor's binary is closed-source and we cite no disassembly; the protocol facts in
  this advisory come from the wire capture itself and from decompressing the job record it carries, both of
  which are reproducible from the published PoC. The installation ran unlicensed, which places `rrServer` in
  its two-client demonstration mode; authorization is governed by a configuration key in the shipped
  `globalconfig.ini` rather than by licence state, and the same key governed the behaviour observed, so we
  make no claim that a licensed build behaves differently and none that it behaves identically, since one was
  not tested
- Privilege ceiling: arbitrary shell execution as the identity of the worker process, measured as
  `uid=0(root) gid=0(root) groups=0(root)` written into a `root:root` marker file. Root was reached because
  the worker was started from a root shell in the verified deployment, and Royal Render enforces no privilege
  separation between the job-dispatch identity and the operating system. We did not locate a shipped artefact
  that fixes a non-root default worker identity, and a worker whose whole purpose is to run arbitrary render
  commands inherits whatever its operator granted - so the ceiling is deployment-dependent rather than
  vendor-mandated. **Not reached and not claimed**: no privilege escalation from an unprivileged account, no
  cross-host movement beyond the scheduler-to-worker dispatch the product performs by design, no container or
  sandbox escape, no memory-corruption primitive, and no write primitive over port 7773

## Impact

- Unauthenticated command execution on a worker host by any client that can reach TCP 7773, using the
  product's ordinary submission channel; the server enqueued the anonymous job and answered with a normal
  346-byte reply rather than a rejection, so nothing in the exchange marks it as hostile
- Command execution under the worker's identity, measured as root in the verified deployment: full read
  access to project assets, licence material and any credential the host holds, unrestricted modification of
  storage the worker mounts, and the ability to install an operating-system startup mechanism for persistence
  with no further product interaction
- A single submission primitive that fans out: `rrServer` dispatches to whichever workers are idle, so one
  anonymous submission is a path to every worker in the farm rather than to one host, and each worker's
  mounted shares are reachable from it
- Job-queue level integrity and availability impact independent of the execution chain - the verified job
  record includes the product's own post-processing tasks `PPDeleteJob` and `PPDeletebroken`, and an
  anonymous submitter can enqueue arbitrary work, exhausting render capacity or destroying queue state
- Persistence available in at least three ways: the executed script can install an OS-level startup
  mechanism; the scene path can point at a file the attacker returns to later, so one placement re-executes on
  every re-submission; and with authorization still off, a second submission is always available with no
  credential to rotate
- Detection is weak by construction. Every packet in the chain is legitimate product traffic: an anonymous
  connection, one job submission, one reply, one dispatch. The best available indicators are a submission
  whose `execOnce.file` dataset names a path outside project storage, a job of type `Execute` / `Once` that no
  artist submitted, a worker process with an unexpected parent shell, and `nTCPRequiresAuth=false` in
  `globalconfig.ini` during an audit
- Amplifiers reported separately and not folded into the score: authorization ships disabled and is
  documented as opt-in (CWE-1188); the job type that means "run this shell script" is not separated from
  ordinary render-job submission and no principal exists by default to separate it for (CWE-284); the worker
  ran as root with no privilege separation (CWE-250); the scene path is not validated against any project
  root or allow-list (CWE-73); and the command template appends `<AdditionalCommandlineParam>` unquoted,
  which is a structurally identified command-injection surface that we did not execute (CWE-78)
- The finding does not depend on a credential being guessed, on a race window, on an administrator being
  present, or on a licence state, which is what separates it from a first-run or default-credential class of
  issue: the gate is absent, not momentarily open

## Mitigation

1. **Make authorization the shipping default** - have the installer write `nTCPRequiresAuth=true` and require
   an explicit, separately confirmed decision to expose an unauthenticated scheduler. A job queue whose
   accepted jobs cause shell execution on other hosts is not a service that should listen for anonymous
   clients out of the box, and the current documentation presents the unauthenticated state as the baseline
   rather than as a risk the operator is accepting
2. **Refuse the `Execute` / `Once` job type from any submitter that is not an administrator** - this job type
   is not a renderer; it is an arbitrary shell execution primitive. Gate it on an explicit, per-user
   capability that is denied by default even when authorization is enabled, and log every such submission with
   the submitting principal, source address and resolved scene path
3. **Validate the scene path before it reaches a shell** - canonicalise `execOnce.file`, resolve it against
   the configured project roots and shared-storage roots, and reject anything outside them; reject paths that
   resolve through symlinks leaving the allowed subtree, and reject `.sh` / `.bat` / `.cmd` scene paths
   entirely for the `Execute` job type unless an operator allow-list names them
4. **Quote and escape the command template** - `<AdditionalCommandlineParam>` is appended unquoted in
   `CommandLine_Lx` and `CommandLine_Win`. Pass job arguments as an argument vector rather than through a
   shell string, or apply shell-quoting to every substituted field so that `;`, `$()`, backticks and
   redirection characters cannot leave the argument
5. **Enforce privilege separation on workers** - do not run `rrClientconsole` as root. Drop to a dedicated
   unprivileged account before executing a job command line, reserve privileges for the specific operations
   that need them, and warn in the installer and in the documentation when a worker is started by root
6. **Verify scene provenance** - require that scene files a worker will execute come from storage the studio
   controls, and where the deployment allows it, a signed or checksummed manifest so that a file placed by a
   third party on shared storage is not silently executed with worker privileges
7. **Authenticate the protocol handshakes, not just the submission** - the anonymous connection is accepted
   before any job semantics are examined. Require an authenticated handshake on connect for every client
   class (submitter, worker, admin tooling, SDK), and make the whitelist apply to the connection rather than
   only to selected operations
8. **Narrow the default exposure** - bind `rrServer` to the render-management interface rather than every
   interface, document port 7773 as a management service that must never be published to the internet, and
   ship a firewall profile with the installer that reflects that
9. **Add a regression test** - from a default installation, assert that an anonymous TCP connection to 7773
   cannot enqueue a job: connect with no credentials, submit the `Execute` / `Once` record whose
   `execOnce.file` names a script in a world-writable directory, and assert the server refuses it and logs
   the refusal. Separately assert that an `Execute` / `Once` submission naming a path outside the configured
   project roots is rejected even for an authenticated admin, and that an `AddCmdFlags` value containing
   `; id` reaches the renderer as a literal argument rather than as a second command
10. **Operator measures until a patch exists** - enable `nTCPRequiresAuth` and populate `nAuthWhiteList`;
    firewall TCP 7773 to named management and worker addresses and never publish it through NAT; run
    `rrClientconsole` as an unprivileged dedicated user with write access limited to output directories; audit
    shared render storage for write permissions from workstation segments and mount it read-only on workers
    where the workflow allows; review the `Execute` / `Once` job type in `render_apps/_config/` and remove it
    from the shipped job-type set if the studio does not use it; and alert on any `Execute` job whose scene
    path is not inside a recognised project directory

## References

- https://0day-rubbish.com/blog/royal-render-default-unauthenticated-job-submission-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
