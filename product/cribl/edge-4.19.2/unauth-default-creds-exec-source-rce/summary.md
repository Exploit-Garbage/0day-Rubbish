# Cribl Edge 4.19.2-89cac507 - unauthenticated remote code execution through factory-default admin credentials and the Exec Source command field

Advisory: https://0day-rubbish.com/blog/unauth-default-creds-exec-source-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Cribl Edge is the closed-source edge-collection product of Cribl, Inc.: a telemetry agent that receives
input sources and routes them onward to destinations, from hosts and edge locations the operator controls. The analyzed build is `4.19.2-89cac507`, shipped as a self-contained archive
(`cribl-4.19.2-89cac507-linux-x64.tgz`, 2729 entries, license-free). It unpacks into an installation home and
runs as a single-instance process whose management plane is an HTTP API. In the configuration the product
writes for itself, that API binds to every interface: `cribl.yml` carries `api.host: 0.0.0.0` with port 9000,
so a default installation answers on port 9000 of every address the host owns. The standalone, bucket and
Edge Node deployment shapes share that factory binding.

The API is guarded by a credential pair that the product ships and does not force anyone to change. The pair
is `admin` / `admin`. The login route `POST /api/v1/auth/login` accepts it and answers HTTP 200 with a JSON
Web Token. The response body also carries `forcePasswordChange:true`, but that flag is not enforced anywhere
on the request path examined during this research: the token issued alongside the flag was accepted by every
administrative route exercised, including the route that creates input sources, and no route answered 401
while holding that token. An operator who never changes the password and an outside party who never asks
permission therefore see the same thing - a fully authorised API session obtained with a credential published
in the product itself.

That session is sufficient for command execution because the same API manages input sources.
`POST /api/v1/system/inputs` creates a source of a chosen type, and the `exec` type takes a `command` field
that the product itself runs as a shell command on the schedule named by its `scheduleType` and `interval`
fields. Vendor documentation states that this field "supports Bourne shell syntax", and that the companion
`script` field may be used to feed multi-line standard input to an interpreter, with `python3 -` and
`powershell -` given as worked examples. This is a documented administrative capability rather than an
accident: the product is designed to run operator-supplied command text. The defect is who is allowed to
supply it. Because the only credential the API requires is one the product ships, the capability is available
to an unauthenticated network peer, and the "administrator-only" label on the feature carries no weight.

The chain is two requests long and needs nothing else. First, log in with the factory pair and keep the
token. Second, create an `exec` input whose `command` writes a marker file. The marker is then read once the
scheduler has fired. During verification the final step completed inside the first scheduling interval: the
marker was 39 bytes, the exact byte length of the output of `id`, and reading it returned
`uid=0(root) gid=0(root) groups=0(root)`. Two independent runs, with two different input identifiers and two
different command strings, both produced a 39-byte marker, so the behaviour is stable rather than a single
successful execution.

Verification was end to end, against a real instance of the shipped archive rather than a reimplementation:
the tarball was unpacked into a disposable Debian bookworm container on a cloud host, with no network
interfaces beyond loopback and no published ports, and the API was reached only through a tunnel bound to
`127.0.0.1`. Every request travelled the product's own HTTP stack, its own login route and its own
input-management route; the product's own scheduler then ran the command, and the marker was read from the
container filesystem. One
boundary statement belongs beside that evidence: root was observed inside the replication environment, in
that container. The same authority in a customer deployment is an inference from the vendor's documented
systemd unit mode, which runs the process as root; it was not measured on customer hardware during this
research. Section 9 of the analysis keeps the two halves of that statement separated.

- Component: the management API of Cribl Edge `4.19.2-89cac507`, HTTP on `0.0.0.0:9000` by factory
  configuration, specifically `POST /api/v1/auth/login` and `POST /api/v1/system/inputs`
- Authentication class: Unauthenticated. The product ships a factory-default credential pair and does not
  force a rotation before the API answers, so no credential an attacker must obtain elsewhere is involved
- Sink: the `command` field of an `exec`-type input, executed by the product as a Bourne shell command on
  the input's `interval` schedule
- Source: the JSON body of `POST /api/v1/system/inputs` - `id`, `type`, `command`, `scheduleType`,
  `interval` - persisted verbatim into `$CRIBL_HOME/local/cribl/inputs.yml`
- Validation on that value: none. The field is documented as shell syntax and is handed to the shell as such,
  which is the designed behaviour of the feature and the reason the credential boundary is the whole boundary
- Execution identity: the identity of the Cribl Edge process - `uid=0(root)` observed inside the replication
  container; the vendor's documented unit mode runs the process as root on a bare-metal deployment
- Verification: end-to-end against the shipped archive, in a disposable container, loopback-only access,
  two independent payloads with a clean subsequent teardown
- Identifier: no identifier assigned. No CVE number has been requested or assigned for this finding

## CVSS Score

- Score: 9.8 Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network. The management API binds `0.0.0.0:9000` in the configuration the product writes for
  itself, so the two requests of the chain are ordinary network requests to a listening TCP port with no
  physical or adjacent-network precondition
- Attack Complexity: Low. Two well-formed HTTP requests, in a fixed order, with no race, no timing window, no
  state machine to satisfy and no memory-corruption groom; the health read that follows is only a liveness
  check
- Privileges Required: None, as argued in the paragraph below
- User Interaction: None. No operator clicks anything, approves anything or opens anything; the anonymous
  party drives every request
- Scope: Unchanged. The substituted command runs inside the Cribl Edge process, in the authority of the
  component whose own interface was used, with no crossing into a further security authority
- Confidentiality, Integrity, Availability: all High. The process that executes the command is the process
  that owns the installation's configuration and the administrative API itself, so read access, write access
  and service availability all follow from the same execution
- Published arithmetic: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043; sum 9.760162, rounded up to 9.8

Privileges Required is None rather than the neighbouring Low tier because the definition turns on what the
attacker must already hold before the attack, and here the attacker must hold nothing. The credential that
opens the session is one the product ships to every installation as its factory default and never forces
anyone to replace; it is knowledge published with the product, not a privilege granted to a principal. There
is no acquisition step in the chain - no credential harvesting, no reuse of a password from another system, no
account creation - and the first request the attacker sends is the login that succeeds. A Low reading would
describe a product in which some prior access to an account or an interface is the entry ticket; that is not this
product's default state, and the score would then understate the population that can reach the chain.

- Rejected reading - treating the factory-default credential as a privilege the attacker must first possess:
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High; its Impact term is unchanged at 5.873119 and its
  Exploitability term is 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, summing to 8.708373 and rounding up to
  8.8. Rejected because the credential is not a privilege held before the attack: it is a published default,
  identical on every installation, and the attacker performs no act to obtain it

- Rejected reading - a scope-changed reading in which the shell child is treated as a separate security
  authority from the API process: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0 Critical. Its Impact
  term is 7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 - 0.02)^13 = 6.128026 and its Exploitability
  term is 3.887043, so 1.08 x 10.015069 = 10.816275, capped at 10.0. Rejected because the child inherits the
  Cribl Edge process identity rather than crossing into an authority the vulnerable component does not already
  hold, which is what Scope: Unchanged means in CVSS 3.1

## Affected Products

- Cribl Edge `4.19.2-89cac507`, the primary entry: the shipped archive was unpacked and driven end to end
  during verification, covering the login route, the input-management route, the on-disk configuration write
  and the scheduled execution of the `command` field
- Cribl Stream `4.19.1`, merged at root-cause level: an independent container run answered
  `POST /api/v1/auth/login` for `admin` / `admin` with a token and exposed the same `cribl.yml` posture
  (`0.0.0.0:9000`, standalone). Its server binary md5 differs from the Edge build - the recorded md5
  prefix is `419c1c7206f` - but the authentication path and the exec-source feature are the same, and vendor
  documentation places Exec Source on self-hosted Stream releases from `3.3` onward. The merge is at root
  cause, not at build identity, and the digest difference is stated rather than smoothed over
- Deployment shapes covered by the factory binding: standalone, bucket and Edge Node installations all ship
  with `api.host: 0.0.0.0` in `cribl.yml`, so a default installation is reachable from any network that can
  route to the host
- Not claimed: builds below `4.19.2`. Only this version was exercised. Vendor documentation shows Exec Source
  present from the `3.2.x` line, and the version in which the factory-default credential pair was introduced
  is not established by this research, so the older-version compatibility line is stated as an open question
  rather than as an affected range
- Not claimed: Cribl's hosted and managed service offerings, and any deployment in which the operator has
  already replaced the factory credential, bound the API to loopback or removed the exec source type. Those
  configurations narrow this finding; they do not repair it, because the product itself still offers the pair
  and the feature on a fresh installation
- Verification method and its boundary: the whole chain was reproduced against the shipped product inside a
  disposable container, not against customer hardware. The container had no external network and no published
  ports, and access went through a tunnel bound to `127.0.0.1`. The root observation is therefore a statement
  about the replication environment; the mapping to a customer deployment rests on the vendor's documented
  unit mode, which runs the process as root, and is labelled as inference wherever it appears

## Impact

- Command execution in the identity of the Cribl Edge process, from an unauthenticated network position, on a
  host whose job is to collect and forward telemetry. This is not a read-only information leak: the
  chain hands an anonymous party the same authority the product's own administrator has, plus a shell
- Disclosure of everything the process can read: the `$CRIBL_HOME` tree and the `local/cribl` configuration
  store the product generates there, plus the administrative objects behind the routes that answered to the
  same token - users, keys, packs and settings
- Integrity impact on the product's own configuration: input definitions, including the `sendToRoutes`
  behaviour that decides whether an event is routed onward, can be added or changed with the same token, so
  the events that leave the collector can be altered, dropped or redirected without any change to the systems
  that produce them
- Availability impact on the collector itself, from the same authority: the process, its scheduled inputs and
  its local persistence can be stopped or reconfigured, and the exec input's own `interval` schedule makes
  re-execution a property of the product rather than something the attacker must maintain
- Lateral movement potential that follows from the collector's position: a host that receives events from
  many producers and forwards them onward is a natural foothold, and every file the process identity can read
  is available to the attacker
- Persistence consistent with command execution as the service account, up to the writable filesystem and the
  product's own configuration surfaces; what survives a reinstall was not tested and is not claimed
- The chain leaves normal product evidence rather than exploit-shaped traffic: a successful login, one
  input-creation request and an ordinary configuration write, all of which the product expects to serve

## Mitigation / Fix Recommendations

1. Enforce the credential change server-side. The login response already carries `forcePasswordChange:true`,
   so the intent exists; the token issued with that flag must be restricted to the credential-change route
   until the change is complete, and every other administrative route must answer an authorisation failure
   until then. An advisory flag is not a control
2. Stop shipping a fixed credential pair. Generate a unique administrator credential at first start - or
   require one to be supplied by the installer - and refuse to open the API listener until it exists. A
   product that ships `admin` / `admin` and answers on `0.0.0.0` is one default away from this finding
   regardless of how the rest of the API is written
3. Bind the API to loopback by default. `api.host: 0.0.0.0` should be an explicit opt-in with a warning at
   startup, not the value the product writes for itself; an operator who needs remote management can enable
   it deliberately and put it behind an authenticated proxy
4. Treat the exec source type as a privileged capability: require an explicit enablement step, surface it in
   the management interface as command execution rather than as a data-source option, and run exec children under a
   dedicated unprivileged identity instead of the service account. An environment-level switch named
   `CRIBL_NOEXEC` exists and the record notes that it does not change this chain, because a default
   deployment does not have it engaged; for installations that do not need exec sources it should be the
   default posture
5. Do not count on rate limiting. The login route enforces roughly two attempts per second, and the record
   measured the corresponding rejection during testing; the chain needs exactly one attempt, so the limit
   costs an attacker nothing
6. Add a startup self-check that reports the exposure: a warning when the API listener is not loopback, and a
   hard block on serving administrative routes while the account still holds a factory credential. Both are
   cheap, both are visible to the operator, and either one breaks this chain
7. For operators, until a fixed build is available: replace the factory credential on every installation,
   bind the API to loopback or restrict port 9000 to trusted management networks, audit
   `$CRIBL_HOME/local/cribl/inputs.yml` for `type: exec` entries that nobody intentionally created, and treat
   an unexpected `POST /api/v1/system/inputs` in the product's own logs as a command-execution indicator
   rather than a routine configuration change

## References

- https://0day-rubbish.com/blog/unauth-default-creds-exec-source-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
