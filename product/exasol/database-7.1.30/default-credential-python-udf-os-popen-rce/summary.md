# Exasol Database 7.1.30 (docker-db) - Shipped Default SYS Credential Reaching a PYTHON3 UDF os.popen Command Execution with Output Returned Through SELECT (CWE-1392, CWE-94)

Advisory: https://0day-rubbish.com/blog/exasol-database-default-credential-python-udf-os-popen-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Exasol Database 7.1.30 from Exasol AG (Germany), examined in the `docker-db` single-container
deployment form, accepts `sys` / `exasol` on its SQL service, and that pair is not a leak: the
documentation that ships with the deployment publishes it in words - the upstream `docker-db` README's
`Connecting to the Database` section instructs the reader to "authenticate with username `sys` and
password `exasol`", and the image's own CI test scripts connect a freshly initialised database with
`-u sys -P exasol` at `basic_test.sh:112` and `basic_sc_test.sh:98`. Nothing rotates it: the running
`controller` process carries no `-defaultSysPasswordHash` argument, the `[DB:DB1]` stanza of
`EXAConf` carries no `DefaultSysPasswdHash` key, the provisioning code's `db_jobs.py:104` generates an
additional random password rather than replacing the built-in one, `database.py:57` only passes the
hash flag when `EXAConf` configures it, the container's `init-sc` path does not configure it, and no
forced first-login change-password gate exists. `SYS` is the database administrator, so the constant
buys the whole warehouse over the SQL channel on its own - and it also buys the right to create script
objects, which converts that administrative access into operating-system command execution: a
`PYTHON3` scalar UDF body runs as ordinary Python with the standard library importable and no
allow-list, so `os.popen("<cmd>").read()` executes a command and the following `SELECT` returns its
stdout through the ordinary result set, making execution non-blind with no exfiltration channel to
build. Three independent live detonations returned real system data, and the identity reported by `id`
was `uid=500(exadefusr) gid=500(exausers) groups=500(exausers),0(root)` - a dedicated script-execution
account that nevertheless carries `root` as a supplementary group, inside a container the vendor's own
README says must run privileged for UDF support. This chain involves no memory corruption, no
deserialisation gadget, no file upload, no protocol bypass and no second vulnerability, and it makes no
claim of escalation to `uid=0`: no escalation was attempted, root group membership under privileged
mode is described as an untested escalation position, and a file written inside the UDF namespace did
not appear in the container's own filesystem view, so no cross-namespace primitive is asserted.

- **Component**: the EXASolution SQL service on port 8563 (proprietary binary SQL protocol over TLS,
  server process `exacs`, listener bound to all interfaces inside the container), its built-in `SYS`
  database-administrator account, and the UDF script engine's `PYTHON3` language alias with its client
  `/usr/opt/EXASuite-7/EXASolution-7.1.30/bin/Console/exaplus`
- **Sink**: `os.popen("<attacker command>").read()` inside the body of a `PYTHON3` scalar UDF created
  with `CREATE OR REPLACE ... AS`, whose return value is delivered to the caller by `SELECT`,
  executing as `uid=500(exadefusr) gid=500(exausers) groups=500(exausers),0(root)` in a separate
  kernel namespace that shares the host kernel
- **Source**: the script body carried in the `CREATE ... SCALAR SCRIPT ... AS` statement over the SQL
  protocol on 8563, authorised by the credential `sys` / `exasol`, which is a deployment-invariant
  constant published by the vendor rather than attacker-supplied secret material
- **Sanitization**: none over what the script body does. The engine resolves and validates the
  language alias - submitting `PYTHON` instead of `PYTHON3` yields its own diagnostic, "no definition
  found for language: PYTHON" - and enforces SQL syntax and the forward-slash script terminator, but
  applies no module allow-list, no denial of `os` or `subprocess`, no capability gate, no rate limit
  and no lockout; `EXAConf` carries no `[ScriptLanguages]` stanza, so the standard aliases `PYTHON3`,
  `LUA`, `JAVA` and `R` are present in a default deployment

## CVSS Score

- **Score**: 8.8 High (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) - a client that can reach the
  SQL port takes full administrative control of the warehouse and converts it into operating-system
  command execution with output returned in-band, using a credential the vendor publishes and nothing
  rotates, with no race, no window and no user interaction
- **Attack Vector: Adjacent** - the listener binds all interfaces inside the container and no source-address restriction was observed in the product's own configuration, but no shipped artifact establishes that a
  single-container deployment binds 8563 on `0.0.0.0` by default: the vendor's documented stand-alone
  run command publishes `-p 127.0.0.1:9563:8563`, and the image's FAQ notes that reaching the service
  from outside the docker network requires port forwarding. Adjacent is what the artifacts support -
  the documented multi-host form runs `--network=host`, under which the vendor states that all ports
  are "accessible on the host", and default bridge networking makes the port reachable from the host
  and from sibling containers. `AV:N` and `AV:L` are published below as labelled conditionals, and
  **no step of the chain was driven from a separate network host**
- **Attack Complexity: Low** - the credential is published, the self-signed certificate has no
  subjectAltName so the client needs a SHA256 fingerprint in the connection string as
  `host/FINGERPRINT:port`, but that fingerprint is readable from an unauthenticated TLS handshake; the
  `PYTHON3` alias is registered by default with no `[ScriptLanguages]` configuration required; and
  every one of the three rounds succeeded on its first attempt
- **Privileges Required: None** - CVSS 3.1 reads `PR:N` as the attacker being "unauthorized prior to
  attack" and not requiring "any access to settings or files of the vulnerable system". Both hold: no
  account was provisioned to the attacker and the defender made no trust decision, and the value is
  obtained from vendor documentation rather than from the target's own `EXAConf` or logs. The product
  demonstrates the contrast itself - its ConfD `AuthenticationToken` and BucketFS `WritePasswd` are
  per-deployment randoms that do have to be read out of the deployment's settings, while `sys` /
  `exasol` is a constant every installation shares. The `PR:L` and `PR:H` readings are computed and
  rejected below
- **User Interaction: None** - no administrator action, browser session or induced click is involved at
  any step
- **Impact C/I/A: all High** - `SYS` over the SQL channel reads and writes every schema, table, view,
  user and privilege in an analytical platform, which typically holds consolidated business data, and
  can stop the database; the sink adds command execution with stdout returned in-band and file reads
  inside the script namespace. All three ratings are grounded in the SQL-layer authority of `SYS`, so
  they do not depend on the cross-namespace reach that was not established
- **Scope**: Unchanged. The SQL service, its script engine and the database it administers are one
  product on one host, and executing a script is what the engine is built to do, so reaching the
  operating system from inside it does not cross an authority boundary the product itself maintains.
  Changed was considered on the strength of the separate namespace, the root supplementary group and
  the documented privileged mode; it is computed and rejected below, because a file written inside the
  namespace did not appear outside it and no cross-boundary effect was demonstrated
- **CWE**: CWE-1392 primary, CWE-94 co-equal, CWE-798, CWE-78, CWE-1188 and CWE-250 recorded
  alongside, with CWE-284 and CWE-862 reported separately for the absent source-address restriction on
  8563 and the absent authorisation distinction for script creation; none of them raises a metric
- **Recorded score**: the sources behind this advisory carried no computed CVSS figure, so nothing was
  inherited or corrected. Every number here was derived from its own vector with the CVSS 3.1 formula:
  ISS 0.914816, Impact under Scope Unchanged 5.873119, Exploitability 2.835255, base 8.708373 rounded
  up to the nearest tenth, which is 8.8
- **Conditional reading A - 8563 reachable from another host**: 9.8 Critical
  (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) - Exploitability 3.887043, base 9.760161 rounded
  up. Applies to the documented multi-host `--network=host` form, to any operator publication of the
  port without a loopback restriction, to a deployment reachable across a management network or NAT,
  and to the supported non-container installation whose purpose is to answer client connections on
  8563. Labelled conditional: the deployment form actually executed here published loopback-only, and
  the cross-host leg is argued from vendor artifacts rather than detonated
- **Conditional reading B - loopback-only publication exactly as the quickstart documents**: 8.4 High
  (`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) - Exploitability 2.515145, base 8.388264 rounded up.
  Applies where the only publication is the documented `-p 127.0.0.1:9563:8563` and the attacker
  therefore needs local access to the host, which realistic positions already provide, including
  anything else running on that host
- **Rejected reading - Privileges Required Low**: 8.0 High
  (`CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) - Exploitability 2.068068, base 7.941187 rounded up.
  Treating the constant as a credential the attacker supplies. Rejected: it charges the attacker for a
  privilege the defender never granted. This is also the reachable reading where the factory credential
  has been rotated but a provisioned non-administrative account still holds script-creation rights
- **Rejected reading - Privileges Required High**: 6.8 Medium
  (`CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - Exploitability 0.900610, base 6.773729 rounded up.
  Reading the metric as the authority level the successful attack needs, since `SYS` is the database's
  most privileged account. Rejected more strongly than `PR:L`: it would rate a constant requiring no
  grant as though it were a personal administrator account. The same metric under a Network vector,
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, computes to 7.2 Medium
- **Rejected reading - Scope Changed**: 9.7 High
  (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) - impact term 6.128026, base 9.680344 rounded up.
  Rejected as the headline for the reason given above; the same reading combined with a Network vector,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, is capped by the formula and comes to 10.0 Critical
- **Not-applicable state - factory credential rotated**: if the `SYS` password has been changed and no
  other account holds script-creation privilege, there is no path from the network to the sink and this
  finding does not arise; the script engine is then a documented feature used by authorised
  administrators. Rotation alone moves the finding from 8.8 to not applicable, which is why it heads
  the operator recommendations

## Affected Products

- Exasol Database version 7.1.30 from Exasol AG (Germany), an in-memory MPP analytical database,
  examined in the `docker-db` single-container deployment form; the container image as pulled is about 6 GB and is distributed through Docker Hub
- Affected components: the EXASolution SQL service on port 8563 and its built-in `SYS` account; the
  container initialisation path `init-sc`, which leaves the constant accepted; and the UDF script
  engine's `PYTHON3` language with no module restriction
- Vendor's own statements about this deployment form, reproduced because they bound the finding rather
  than enlarge it: the upstream repository warns that the docker distribution "is an open source
  project that is __not officially supported__ by Exasol"; that the base image is an end-of-life
  CentOS 7 release, that "official support for docker-db 7 is no longer available", and that users
  should move to a newer release line; that the repository "only contains __documentation__" with
  binaries on Docker Hub; and that the project is "mainly intended for automatic testing of Exasol
  deployments". The consequence for operators is that no patch is coming for this image, which raises
  exposure rather than lowering it
- Runtime stack: the proprietary C engine EXASolution running as `exacs`, a proprietary binary SQL
  protocol on 8563 rather than HTTP, TLS with a self-signed certificate carrying no subjectAltName,
  the vendor console client `exaplus`, the UDF framework with a separate kernel namespace per script
  execution, and in the same container ConfD (HTTPS JSON-RPC, per-deployment Bearer token), BucketFS
  (HTTP, per-deployment bucket passwords) and OpenSSH
- Only this version in this deployment form was tested. Other 7.1.x releases, the supported
  non-container installation and the vendor's newer release line share the mechanism - a constant `SYS`
  credential plus an unrestricted script language - and are plausibly affected, but none was executed
  and none is claimed here
- Verification method and its boundary: live verification against a container built from the vendor
  image on an isolated cloud sandbox, started privileged as the README requires, with a host directory
  mounted at `/exa` and the SQL port published to the host loopback only. The three rounds drove the
  vendor client inside the container against the container's own loopback on 8563, so the chain is a
  real product executing real commands and not an emulation or protocol replica; and the cross-host
  reachability of that same chain is argued from the documented deployment forms and the observed
  all-interface bind, not demonstrated between two machines
- Privilege ceiling: command execution as `uid=500(exadefusr) gid=500(exausers)
  groups=500(exausers),0(root)`, exactly as `id` returned it. **Not `uid=0`, and root is not
  claimed.** Root appears only as a supplementary group. **Not reached and not claimed**: escalation to
  an effective root identity, any cross-namespace or container escape, cross-host movement, and the
  sibling sinks `os.system`, `subprocess` and the `LUA`, `JAVA` and `R` aliases, none of which was
  detonated

## Impact

- Full administrative takeover of the database by anyone who can reach port 8563: the `SYS` credential
  requires no provisioning decision by the defender, so there is no account to have been created, no
  assignment to have been logged and no trust relationship to have been abused
- Complete read access to the warehouse over the SQL channel, independent of the sink. An analytical
  platform holds whatever the organisation consolidated into it, and `SYS` reads all of it - every
  schema, table and view - with no further exploit step and no unusual protocol activity
- Arbitrary operating-system command execution as `uid=500(exadefusr)` with `root` as a supplementary
  group, inside the script engine's namespace, with stdout returned through the ordinary `SELECT`
  result set. Because the return path is in-band, no DNS, HTTP or ICMP exfiltration channel is needed,
  so egress filtering on the host does not defeat it
- Complete integrity control at the SQL layer: any schema, table, view, user or privilege can be
  written, replaced or dropped, and further accounts can be created with chosen privileges, which
  gives the attacker a durable and legitimate-looking second entry point that survives rotation of the
  factory credential
- Availability at will: the database can be stopped, schemas dropped and resources consumed by the same session. The deployment runs privileged as the vendor documents, which widens what such consumption inside the container can reach beyond it; that widening was not tested here and is not scored
- Persistence through the SQL layer without leaving accumulating evidence: the payload uses
  `CREATE OR REPLACE`, so re-running the attack rewrites one script object rather than creating a new
  one per command, and the object itself is ordinary product state that survives the session and is
  only visible to someone who enumerates script definitions
- The root supplementary group under the vendor-documented privileged container mode is a recognised
  escalation position on Linux, since `gid 0` governs access to files and devices whose group is
  `root`. It is reported as an untested position, and the conditional statement is the whole of what
  the evidence supports: if an attacker there could write a setuid binary or reach a device node
  exposed by privileged mode, an effective root identity would follow. Neither was tested
- Detection is weak by construction. Every step is legitimate documented product usage: a TLS
  handshake, a `SYS` login, script creation, a `SELECT`. A `SYS` session from an unexpected address is
  indistinguishable from a real administrator, and an operator who never rotated the constant has no
  means of telling them apart. The single highest-value signal is script-object creation with the
  creating user and source address, which the default deployment does not surface
- Amplifiers reported separately and not folded into the score: no source-address restriction on 8563 was observed in the product (CWE-284); script creation is not authorised separately from ordinary
  SQL (CWE-862); the BucketFS `default` bucket is `Public=True`, which permits unauthenticated read
  listing - writes returned `403` and a path traversal returned `400` - a smaller separate finding
  with its own root cause; the ConfD token and BucketFS write password are per-deployment randoms and
  so are not constant-credential exposure; and this release line is out of vendor support, so no fix
  will be published for the image

## Mitigation

1. **Rotate the `SYS` password immediately after initialisation** - this single control breaks the
   chain, and it moves the finding from 8.8 to not applicable where no other account holds
   script-creation privilege. Treat any deployment still answering the constant as compromised until
   audited, since the credential is public and its use leaves no distinguishing trace
2. **Generate a per-deployment random SYS password during initialisation** (vendor-side) - the product
   already does exactly this for the ConfD `AuthenticationToken` and the BucketFS `WritePasswd`. The
   provisioning code already calls `secrets.token_hex(20)` at `db_jobs.py:104`; making that generated
   value the only accepted password instead of an additional one is the smallest change with the
   largest effect
3. **Remove the built-in acceptance of the constant**, or require an explicit `--sys-passwd`
   initialisation argument with no default (vendor-side). A documented constant that nothing rotates is
   the defect; the script engine itself is a feature
4. **Add a forced first-login rotation gate** - if a constant initial credential is retained for
   compatibility, refuse to serve SQL until it has been changed once, and log the refusal
5. **Restrict the script engine by default** - make the module set available to UDFs an allow-list that
   excludes `os`, `subprocess`, `socket` and equivalents, with an explicit per-database or per-session
   opt-in to enable them and a log entry for the opt-in. Process creation from the query layer should
   be a granted privilege, not a library that happens to be importable
6. **Stop granting the script-execution account root group membership** unless a specific documented
   function requires it, and state in the documentation which one; nothing measured here needed
   `gid 0`
7. **Do not publish 8563 without a loopback or named-address restriction** - prefer the documented
   `-p 127.0.0.1:9563:8563` publication, front remote access with a VPN or a mutually authenticated
   proxy, and audit every deployment running `--network=host`, where the vendor's own note says all
   ports are accessible on the host
8. **Document the exposure next to the host-networking example** (vendor-side) - state that 8563
   accepts SQL from the network, that the default credential must be rotated before that form is used,
   and that BucketFS's public-read default discloses bucket contents without authentication
9. **Enumerate and review script objects** - list schemas and script definitions, remove any the
   operator did not author, and compare against a known-good inventory periodically, because
   `CREATE OR REPLACE` leaves no accumulation for a volume-based alert to catch
10. **Add a regression test** (vendor-side) - initialise a container with no arguments, then assert
    from a remote client that the documented constant no longer authenticates, that a connection
    succeeds only with the value the initialiser reported, that creating a `PYTHON3` script calling
    `os.popen` fails with a policy error naming the restricted module, and that the script-execution
    account's supplementary groups, read from inside a permitted script, do not include `gid 0`
11. **Surface script-object creation in audit trails** (vendor-side) - record the creating user and
    source address, since that event is the only durable artifact the chain leaves behind
12. **Watch for credential trials against `sys` on 8563** - no rate limit or lockout was observed on
    SQL authentication, so a sequence of `[28000] authentication failed` responses against the `sys`
    user is both cheap for an attacker to generate and detectable if logged. Plan migration off this
    release line on its own merits, since the vendor directs users of docker version 7 to a newer
    release

## References

- https://0day-rubbish.com/blog/exasol-database-default-credential-python-udf-os-popen-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- https://github.com/exasol/docker-db
- https://docs.exasol.com
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
