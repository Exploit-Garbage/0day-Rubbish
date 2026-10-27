# Moxa MAR-2000 FWR_MAR2000_V1.0_Build_15010909 - Executer Program-Activation Command Injection Through the Program Table argument Field (CWE-78, CWE-20)

Advisory: https://0day-rubbish.com/blog/mar-2000-executer-program-argument-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The MAR-2000 series industrial 4G/LTE cellular router from Moxa, an industrial networking
vendor in Taiwan, manages its own configuration through a Node.js Express 4.0 application on
port 80 that the express-sanji middleware bridges onto a local MQTT broker; every configuration
resource is ultimately handled by a Python 2.6 model script inside the firmware's MIRF
(Mobile Intelligent Routing Framework) stack. One of those models, the Executer, keeps a table
of user programs in SQLite and, when a row is activated, builds a shell command as
`<user_program_dir>/<fileName>` followed by a space and the row's `argument` value, then hands
that string straight to `subprocess.Popen(..., shell=True)`. The `argument` value is written
verbatim by the authenticated `PUT /api/v1/system/executer/program/<id>` handler - the model's
generic row writer takes every key of the request's data object and commits it with a plain
SQL `UPDATE ... SET ...` - and no layer of the stack validates it: the Express layer checks
only the session, express-sanji translates the request, the MQTT broker carries it without
authentication, and the model checks nothing about the value. An administrator who uploads a
benign script through the product's own multipart upload route (which imposes no file type
restriction and which the activation path requires, because the model only runs a program whose
file exists under the user-program directory) can therefore store `; <command>; #` in the
`argument` field, call `PUT /api/v1/system/executer/activatedProgram` with `runBit` 1, and have
the activated row's command line interpreted by `/bin/sh`, where the semicolon reaches a second
statement and the hash sign swallows the remainder of the line. Sink-level replication of the
exact command construction - the string, the `shell=True` hand-off and the payload - produced
a marker containing `uid=0(root)`, which is the identity of the research sandbox and
establishes that the injected segment executes; it does not measure the identity of the model
process on the device, which this research did not measure and does not claim. The same model's
row deletion path builds `rm -rf <user_program_dir>/<fileName>` with the same unvalidated
column and executes it with `subprocess.call(..., shell=True)`, so a `fileName` value carrying
shell metacharacters is a second, structurally identical sink. The chain does not involve memory
corruption, does not involve an unauthenticated request, does not consume any credential other
than a management login, and does not claim privilege escalation beyond the identity of the
model process that runs the command. Where a deployment still runs the factory-installed
default administrator pair, the privilege prerequisite collapses entirely; that condition is
published separately below and is not folded into the score.

- **Component**: the Executer model at `/home/model/system/executer/executer.py` inside the
  ARM Debian 6.0.8 root filesystem of firmware `FWR_MAR2000_V1.0_Build_15010909`, reached
  through the Express 4.0 management application's REST resources
  `POST/PUT /api/v1/system/executer/program` and
  `PUT /api/v1/system/executer/activatedProgram`; the web application binds all interfaces
  on port 80
- **Sink**: `subprocess.Popen(full_command, shell=True, preexec_fn=os.setsid)` where
  `full_command` is `<user_program_dir>/<fileName>` plus the stored `argument` value; the row
  deletion path adds `subprocess.call("rm -rf %s" % execute_file, shell=True)`
- **Source**: the `argument` column (and, in the deletion path, the `fileName` column) of the
  Executer program table, committed verbatim by the model's generic `sql_put_row` writer from
  the authenticated `PUT` request body
- **Sanitization**: none on the path. The multipart upload applies only a filename
  sanitisation and no file type restriction; the activation path checks only that the
  executable file exists (`os.path.exists`), which the attacker satisfies with the product's
  own upload route; the row writer performs no value validation, and the effect of the
  `!= "/"` guard in the deletion path is limited to blocking the trivial single-slash case

## CVSS Score

- **Score**: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an authenticated
  administrator converts one configuration field into arbitrary command execution as the
  identity of the model process, and the rating does not assume that identity is privileged
  because the whole appliance is a single authority
- **Attack Vector: Network** - the management application binds all interfaces and listens on
  port 80 in the shipped firmware; the entry path is ordinary HTTP over that listener. Whether
  a given deployment exposes the management interface on the WAN side is an operator decision
  that this research did not measure and does not assume
- **Attack Complexity: Low** - the request sequence is deterministic, nothing is raced, and the
  attacker fully controls the injected bytes; the only precondition beyond the credential is a
  file under the user-program directory, which the product's own upload route provides
- **Privileges Required: High** - the management application has a single documented role,
  the device administrator, whose session (`validateUser` requires `session.user`) gates the
  mutating requests of this chain; under the CVSS 3.1 user guide, administrator privileges are
  the example of High, and the factory default credential is deliberately not folded in here
- **User Interaction: None** - the attacker performs both the configuration write and the
  activation request; no administrator action or browser session is involved
- **Scope: Unchanged** - the Python model that executes the command line is part of the same
  single-purpose appliance, and directing the appliance's operating system through these
  handlers is the management plane's documented intended behaviour; a Scope-Changed reading
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` computes to 9.1 (ISS 0.914816, Impact 6.128026,
  Exploitability 2.286496, 1.08 times 8.414522 = 9.087684) and is not published
- **Impact C/I/A: all High** - arbitrary command execution as the model process yields the
  router's complete configuration and any data the process can read, full control of the
  forwarding and cellular configuration, and control of availability of a device positioned as
  communication infrastructure
- **Conditional reading A - factory default credentials unchanged**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  = **9.8** Critical. The shipped firmware carries a default administrator pair in its SQLite
  user table; where a deployment never changed it, no credential owned by anybody is consumed
  and the prerequisite collapses. Arithmetic: Exploitability 8.22 x 0.85 x 0.77 x 0.85 x 0.85 =
  3.887043, Impact 5.873119, base 9.760161, rounded up to 9.8. Labelled conditional on a
  deployment state this research did not field-audit
- **Rejected reading B - management account treated as Low**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  = **8.8** High (Exploitability 2.835255, base 8.708373) is the figure the research record
  carried for this finding; it is not adopted because no artefact shows a lower-privileged
  product role that can reach this field, and 8.8 is published here only as the arithmetic of
  the rejected variant
- **Recorded score**: the source record behind this advisory carried 8.8 for all three
  same-product findings; this advisory does not inherit it, and every number above is computed
  from its own vector with the CVSS 3.1 formula

## Affected Products

- The Moxa MAR-2000 series industrial 4G/LTE cellular router, characterised from firmware
  `FWR_MAR2000_V1.0_Build_15010909`, which extracts to an ARM Debian 6.0.8 root filesystem
  running the MIRF (Mobile Intelligent Routing Framework) stack: an Express 4.0 management
  application on port 80 bound to all interfaces, express-sanji bridging REST resources onto a
  local MQTT broker, and Python 2.6 model scripts implementing the configuration handlers,
  including `/home/model/system/executer/executer.py`
- This is one of three command injection findings documented for this product, each in a
  different model, REST resource and sink family: the IPsec tunnel address injection
  (`mar-2000-network-ipsec-command-injection`) and the scenario ping condition injection
  (`mar-2000-scenario-ping-command-injection`) are published as sibling advisories; the three
  share the entry architecture but do not share a model file, a REST resource, a configuration
  field or a sink construction
- The finding is evidenced at two levels and this advisory states the boundary: the firmware's
  own application sources establish the entry path, the storage semantics and the exact sink
  construction, and sink-level replication of that construction (the concatenated command
  string, the `shell=True` hand-off, the payload and a benign control) establishes the shell
  behaviour and the negative control. End-to-end detonation against powered-on MAR-2000
  hardware was not part of this research record, and the identity of the model process on the
  device was not measured; the observed `uid=0(root)` is the identity of the replication
  sandbox and is not claimed as the on-device identity
- The research record documents a factory default administrator pair (bcrypt-hashed in the
  SQLite user table) for this firmware; deployments that changed it are not described by
  Conditional reading A. The web stack's separate property of answering unauthenticated `GET`
  requests across `/api/v1/*` is a read-exposure issue reported on its own and is not part of
  this chain
- No other MAR-2000 firmware build was examined, and no claim is made about any other Moxa
  product family

## Impact

- Arbitrary command execution as the identity of the Python model process, begun by one
  authenticated configuration write and one activation request, with no memory-corruption
  primitive and no protocol manipulation anywhere in the chain
- The command line is a stored configuration value, so the injected statement re-executes
  every time the same program row is activated, and the row survives reboots in the SQLite
  table - a persistence property the attacker does not need to re-create
- The deletion sink (`rm -rf` over a `fileName` column that is never validated) extends the
  same class to a field reachable without any upload, and allows destructive filesystem
  operations inside the user-program directory and beyond it wherever the injected
  metacharacters lead
- Full compromise of the appliance's function as communication infrastructure: forwarding,
  cellular and VPN configuration, interface state, and the ability to interrupt or exhaust the
  device at will
- Where the factory default administrator pair is unchanged, every one of the above is
  reachable by any client that can reach the management listener, with no credential owned by
  the operator consumed

## Mitigation / Fix Recommendations

1. Execute activated programs without a shell: take the executable path and the argument
   value as separate `execv`-style arguments, or at minimum reject any `argument` value
   containing shell metacharacters at the row-write boundary
2. Validate the program row at the model's writer, not only at the web form: `argument`
   should be a known-safe shape (the product's UI already intends it as a program argument),
   and `fileName` should be restricted to a basename matching the uploaded set
3. Apply the same two measures to the deletion path, where the `!= "/"` comparison blocks one
   value and nothing else - construct the `rm -rf` target as a path argument rather than a
   shell string
4. Restrict the multipart upload to executable-basename types and derive both the stored
   `fileName` and the on-disk name server-side, re-associating them by an opaque row id
5. Operator measure until a patch exists: change the factory default administrator credential
   at commissioning and keep the management listener off WAN-facing addresses; audit program
   table rows and user-program directory contents for unexpected entries

## References

- https://0day-rubbish.com/blog/mar-2000-executer-program-argument-command-injection
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
