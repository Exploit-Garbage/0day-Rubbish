# Moxa MAR-2000 FWR_MAR2000_V1.0_Build_15010909 - Scenario Ping Condition Command Injection Through the Auto-Executing Ping Thread (CWE-78, CWE-20)

Advisory: https://0day-rubbish.com/blog/mar-2000-scenario-ping-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The MAR-2000 series industrial 4G/LTE cellular router from Moxa, an industrial networking
vendor in Taiwan, lets an administrator define monitoring scenarios - named conditions,
saved through the management API and then evaluated periodically by the product's own
scenario machinery. A condition of type `ping` is served by a background `PingThread` in
the Scenario model at `/home/model/scenario/scenario.py`, which builds
`ping <ip> -c 1 -w 5 -I <interface>` from the condition's saved `parameter.ip` and
`parameter.interface` values and executes it through `subprocess.Popen(..., shell=True)`.
Those values arrive via the authenticated `PUT /api/v1/scenario`, and the model's write
handler checks only that the submitted data object exists and is non-empty - no
parameter value is inspected at any layer between the HTTP request and `/bin/sh`. An
administrator who saves a ping condition whose `parameter.ip` is `$(<command>)` therefore
has the shell execute the subshell during command expansion, before the `ping` binary
even starts; a newline-separated form keeps the ping flags attached to the ping command
and runs the injected text as a second line. The execution is automatic: once the
condition is saved, the scenario watchdog evaluates it on its schedule and the stored
payload delivers itself with no further request - which also makes the payload recur on
every evaluation cycle. Sink-level replication of the thread's command construction -
the same `ping %s -c 1 -w 5 -I %s ` template, the same `shell=True` launch - produced a
marker containing `uid=0(root)` under the subshell form and under the newline form, and
no marker for the benign-address control; the same record also shows that the naive
semicolon payload does not fit this template, because the `;` lands before the `-c`
count flag, leaving the spawned ping without a limit to block the evaluating thread.
The figure `uid=0(root)` is the identity of the research sandbox and establishes that
the injected segment executes; the identity of the model process on the device was not
measured and is not claimed. The chain does not involve memory corruption, does not
involve an unauthenticated request, and does not claim execution beyond the model
process identity. Where a deployment still runs the factory-installed default
administrator pair, the privilege prerequisite collapses entirely; that condition is
published separately below and is not folded into the score.

- **Component**: the Scenario model at `/home/model/scenario/scenario.py` inside the ARM
  Debian 6.0.8 root filesystem of firmware `FWR_MAR2000_V1.0_Build_15010909`, reached
  through the Express 4.0 management application's `PUT /api/v1/scenario` resource; the
  web application binds all interfaces on port 80
- **Sink**: `PingThread.run()`'s
  `subprocess.Popen("ping %s -c 1 -w 5 -I %s " % (ip, interface), shell=True,
  stdout=PIPE, stderr=PIPE)`, spawned by the model's periodic scenario evaluation
- **Source**: the `parameter.ip` (and `parameter.interface`) values of a saved ping-type
  condition, committed verbatim by a handler that only checks the presence of the data
  object
- **Sanitization**: none on the path. The write handler's entire validation is that
  `data` exists and is non-empty; IP address format is never checked; the thread
  interpolates the stored value directly into the command template

## CVSS Score

- **Score**: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an authenticated
  administrator converts one monitoring condition field into arbitrary command execution
  as the identity of the model process, and the rating does not assume that identity is
  privileged because the whole appliance is a single authority
- **Attack Vector: Network** - the management application binds all interfaces and
  listens on port 80 in the shipped firmware; the entry path is ordinary HTTP over that
  listener. Whether any given deployment exposes the management interface on the WAN side
  was not measured and is not assumed
- **Attack Complexity: Low** - the write is deterministic and fully attacker-controlled;
  the delivery moment belongs to a schedule the product runs on its own, and the payload
  forms that reach execution are simple and verified
- **Privileges Required: High** - the management application has a single documented role,
  the device administrator, whose session (`validateUser` requires `session.user`) gates
  the scenario write; under the CVSS 3.1 user guide, administrator privileges are the
  example of High, and the factory default credential is deliberately not folded in here
- **User Interaction: None** - the attacker performs the configuration write; the product's own
  watchdog performs the execution
- **Scope: Unchanged** - the Python model that executes the ping command is part of the
  same single-purpose appliance, and running connectivity checks through these handlers is
  the management plane's documented intended behaviour; a Scope-Changed reading
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` computes to 9.1 (ISS 0.914816, Impact
  6.128026, Exploitability 2.286496, 1.08 times 8.414522 = 9.087684) and is not published
- **Impact C/I/A: all High** - arbitrary command execution as the model process yields the
  router's complete configuration and any data the process can read, full control of a
  device positioned as communication infrastructure, and a recurring execution primitive
  under the product's own scheduling
- **Conditional reading A - factory default credentials unchanged**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  = **9.8** Critical. The shipped firmware carries a default administrator pair in its
  SQLite user table; where a deployment never changed it, no credential owned by anybody
  is consumed and the prerequisite collapses. Arithmetic: Exploitability 8.22 x 0.85 x
  0.77 x 0.85 x 0.85 = 3.887043, Impact 5.873119, base 9.760161, rounded up to 9.8.
  Labelled conditional on a deployment state this research did not field-audit
- **Rejected reading B - management account treated as Low**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  = **8.8** High (Exploitability 2.835255, base 8.708373) is the figure the research
  record carried for this finding; it is not adopted because no artefact shows a
  lower-privileged product role that can reach this field, and 8.8 appears here only as
  the arithmetic of the rejected variant
- **Recorded score**: the source record behind this advisory carried 8.8 for all three
  same-product findings; this advisory does not inherit it, and every number above is
  computed from its own vector with the CVSS 3.1 formula

## Affected Products

- The Moxa MAR-2000 series industrial 4G/LTE cellular router, characterised from firmware
  `FWR_MAR2000_V1.0_Build_15010909`, which extracts to an ARM Debian 6.0.8 root filesystem
  running the MIRF (Mobile Intelligent Routing Framework) stack: an Express 4.0 management
  application on port 80 bound to all interfaces, express-sanji bridging REST resources
  onto a local MQTT broker, and Python 2.6 model scripts implementing the configuration
  handlers, including `/home/model/scenario/scenario.py`
- This is one of three command injection findings documented for this product, each in a
  different model, REST resource and sink family: the Executer program-activation injection
  (`mar-2000-executer-program-argument-command-injection`) and the IPsec tunnel address
  injection (`mar-2000-network-ipsec-command-injection`) are published as sibling
  advisories; the three share the entry architecture but do not share a model file, a REST
  resource, a configuration field or a sink construction
- The finding is evidenced at two levels and this advisory states the boundary: the
  firmware's own application sources establish the scenario write path, the write
  handler's validation scope and the PingThread construction, and sink-level replication
  of that construction (the exact template, the `shell=True` hand-off, the working payload
  forms, the failing form and a benign control) establishes the shell behaviour including
  which payload shapes fit this template. End-to-end detonation against powered-on
  MAR-2000 hardware, including the watchdog's exact evaluation interval, was not part of
  this research record, and the on-device model process identity was not measured; the
  observed `uid=0(root)` is the identity of the replication sandbox
- The research record documents a factory default administrator pair (bcrypt-hashed in the
  SQLite user table) for this firmware; deployments that changed it are not described by
  Conditional reading A. The web stack's separate property of answering unauthenticated
  `GET` requests across `/api/v1/*` is a read-exposure issue reported on its own and is not
  part of this chain
- No other MAR-2000 firmware build was examined, and no claim is made about any other Moxa
  product family

## Impact

- Arbitrary command execution as the identity of the Python model process, begun by one
  authenticated configuration write and delivered by the product's own periodic
  evaluation, with no memory-corruption primitive and no protocol manipulation anywhere in
  the chain
- The execution is not a one-shot: the saved condition is re-evaluated by the product's
  scenario machinery on its schedule, so the stored payload delivers itself again on every
  cycle until the condition is deleted - a recurring scheduled-execution primitive that
  requires no persistence work from the attacker
- The payload is stored configuration and survives reboots, so a reboot does not clear
  the attacker's position; deleting the malicious condition is the only ordinary
  remediation short of a patch
- The `interface` operand rides the same construction and the same absence of validation,
  giving a second stored field of the same class within one condition
- Where the factory default administrator pair is unchanged, every one of the above is
  reachable by any client that can reach the management listener, with no credential
  owned by the operator consumed

## Mitigation / Fix Recommendations

1. Run connectivity checks without a shell: build the ping invocation as an argument
   vector (an `execv`-family launch or an equivalent library call), which removes the
   metacharacter question entirely from the thread
2. Validate the condition's parameters at the write boundary where they are stored: IP
   address form for `ip`, interface selector form for `interface`, numeric bounds for
   `times` - enforced in the model, not only in a web form
3. Have the write handler reject a condition whose parameter values fail that validation
   rather than storing them for the watchdog to consume
4. Add a product regression test that saves a ping condition with metacharacter-bearing
   parameters, waits an evaluation cycle, and asserts that the parameters were rejected at
   write time or executed with no shell interpretation
5. Operator measures until a patch exists: change the factory default administrator
   credential at commissioning, keep the management listener off WAN-facing addresses,
   and audit saved scenarios for ping conditions whose ip or interface values contain
   shell metacharacters or expansions

## References

- https://0day-rubbish.com/blog/mar-2000-scenario-ping-command-injection
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
