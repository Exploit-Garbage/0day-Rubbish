# Moxa MAR-2000 FWR_MAR2000_V1.0_Build_15010909 - IPsec Tunnel Address Command Injection Through the Route-Management Shell Commands (CWE-78, CWE-20)

Advisory: https://0day-rubbish.com/blog/mar-2000-network-ipsec-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The MAR-2000 series industrial 4G/LTE cellular router from Moxa, an industrial networking
vendor in Taiwan, configures its IPsec VPN tunnels through the same backend all its
configuration lives in: an Express 4.0 management application bridged by express-sanji onto
a local MQTT broker and handled by Python 2.6 model scripts in the firmware's MIRF stack.
The IPsec model at `/home/model/network/ipsec/ipsec.py` stores the tunnel parameters
(`tunnelModeTable` with `localVpnIp`, `tunnelRemoteVpnIp`, `tunnelRemoteVpnInterface`) as
JSON and, when the IPsec service applies the tunnel, manages the device's addresses and
routes with shell commands built from those stored fields: `ip addr add`, `ip addr del`,
`ip route add` and `ip route del`, each executed through `subprocess.call(..., shell=True)`.
The fields arrive via the authenticated `PUT /api/v1/network/ipsec`, and the model's
ingress handler - `clean_data()` - removes unknown dictionary keys but never inspects any
value, so no layer between the HTTP request and `/bin/sh` checks that `localVpnIp` holds an
address rather than a command. An administrator who stores `10.10.10.1; <command>; #` in
that field therefore has the `ip addr add` command line split at the semicolon, the injected
statement executed, and the remainder of the line commented away - first when the
interface address is assigned, and again in each route command that interpolates the same
stored field, which the model uses twice in a single `ip route add to ... via ... src ...`
construction. A fifth related write appends the tunnel table's `transServerIp` and
`transClientIp` fields into the IPsec configuration file; it is the same unvalidated-field
pattern but was not exercised in this research record and is reported as structure, not as
a detonated sink. Sink-level replication of each of the four route-management
constructions, carrying `1.1.1.1; <command>; #` in the address position and a benign
address as control, produced a marker containing `uid=0(root)` for all four and no marker
for the control; that figure is the identity of the research sandbox and establishes that
the injected segment executes, while the identity of the model process on the device was
not measured and is not claimed. The chain does not involve memory corruption, does not
involve an unauthenticated request, does not tamper with any protocol, and does not claim
execution beyond the model process identity. Where a deployment still runs the
factory-installed default administrator pair, the privilege prerequisite collapses entirely;
that condition is published separately below and is not folded into the score.

- **Component**: the IPsec model at `/home/model/network/ipsec/ipsec.py` inside the ARM
  Debian 6.0.8 root filesystem of firmware `FWR_MAR2000_V1.0_Build_15010909`, reached
  through the Express 4.0 management application's `PUT /api/v1/network/ipsec` resource;
  the web application binds all interfaces on port 80
- **Sink**: four `subprocess.call(cmd, shell=True)` constructions in the tunnel lifecycle
  - `add_ip` (`ip addr add %s dev eth%s`), `del_ip` (`ip addr del %s dev eth%s`),
  `add_route` (`ip route add to %s via %s src %s`, interpolating the stored field twice)
  and `del_route` (`ip route del %s`)
- **Source**: `tunnelModeTable.localVpnIp` (and the interface and route operands built beside
  it), written verbatim by the model's `put()` handler after `clean_data()` removes unknown
  keys only
- **Sanitization**: none on any value. `clean_data()` is a key-name whitelist; IP address
  format is never checked; shell metacharacters (`;`, `|`, `$()`, backticks, newline) pass
  through unfiltered into the command template

## CVSS Score

- **Score**: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an authenticated
  administrator converts one VPN address field into arbitrary command execution as the
  identity of the model process; the rating does not assume that identity is privileged
  because the whole appliance is a single authority
- **Attack Vector: Network** - the management application binds all interfaces and listens
  on port 80 in the shipped firmware; the entry path is ordinary HTTP over that listener.
  Whether any given deployment exposes the management interface on the WAN side was not
  measured and is not assumed
- **Attack Complexity: Low** - the write is deterministic and fully attacker-controlled; no
  race and no parsing edge case is involved. The stored values are consumed by the IPsec
  tunnel lifecycle, and that consumption point is established from the firmware's model
  sources together with the replicated sink behaviour
- **Privileges Required: High** - the management application has a single documented role,
  the device administrator, whose session (`validateUser` requires `session.user`) gates
  the configuration write; under the CVSS 3.1 user guide, administrator privileges are the
  example of High, and the factory default credential is deliberately not folded in here
- **User Interaction: None** - the attacker performs the configuration write; no
  administrator action or browser session is involved
- **Scope: Unchanged** - the Python model that executes the route commands is part of the
  same single-purpose appliance, and managing the device's interfaces and routes through
  these handlers is the management plane's documented intended behaviour; a Scope-Changed
  reading `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` computes to 9.1 (ISS 0.914816,
  Impact 6.128026, Exploitability 2.286496, 1.08 times 8.414522 = 9.087684) and is not
  published
- **Impact C/I/A: all High** - arbitrary command execution as the model process yields the
  router's complete configuration and any data the process can read, full control of a
  device positioned as communication infrastructure and of its VPN tunnel state, and
  control of availability at will
- **Conditional reading A - factory default credentials unchanged**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  = **9.8** Critical. The shipped firmware carries a default administrator pair in its
  SQLite user table; where a deployment never changed it, no credential owned by anybody is
  consumed and the prerequisite collapses. Arithmetic: Exploitability 8.22 x 0.85 x 0.77 x
  0.85 x 0.85 = 3.887043, Impact 5.873119, base 9.760161, rounded up to 9.8. Labelled
  conditional on a deployment state this research did not field-audit
- **Rejected reading B - management account treated as Low**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  = **8.8** High (Exploitability 2.835255, base 8.708373) is the figure the research record
  carried for this finding; it is not adopted because no artefact shows a lower-privileged
  product role that can reach this field, and 8.8 appears here only as the arithmetic of the
  rejected variant
- **Recorded score**: the source record behind this advisory carried 8.8 for all three
  same-product findings; this advisory does not inherit it, and every number above is
  computed from its own vector with the CVSS 3.1 formula

## Affected Products

- The Moxa MAR-2000 series industrial 4G/LTE cellular router, characterised from firmware
  `FWR_MAR2000_V1.0_Build_15010909`, which extracts to an ARM Debian 6.0.8 root filesystem
  running the MIRF (Mobile Intelligent Routing Framework) stack: an Express 4.0 management
  application on port 80 bound to all interfaces, express-sanji bridging REST resources onto
  a local MQTT broker, and Python 2.6 model scripts implementing the configuration handlers,
  including `/home/model/network/ipsec/ipsec.py`
- This is one of three command injection findings documented for this product, each in a
  different model, REST resource and sink family: the Executer program-activation injection
  (`mar-2000-executer-program-argument-command-injection`) and the scenario ping condition
  injection (`mar-2000-scenario-ping-command-injection`) are published as sibling
  advisories; the three share the entry architecture but do not share a model file, a REST
  resource, a configuration field or a sink construction
- The finding is evidenced at two levels and this advisory states the boundary: the
  firmware's own application sources establish the configuration write, the key-only
  validation and the four shell-command constructions, and sink-level replication of each
  construction (the command template, the `shell=True` hand-off, the payload and a benign
  control) establishes the shell behaviour. End-to-end detonation against powered-on
  MAR-2000 hardware, including the exact tunnel-apply moment at which the stored values are
  consumed on the device, was not part of this research record, and the on-device model
  process identity was not measured; the observed `uid=0(root)` is the identity of the
  replication sandbox
- The research record documents a factory default administrator pair (bcrypt-hashed in the
  SQLite user table) for this firmware; deployments that changed it are not described by
  Conditional reading A. The web stack's separate property of answering unauthenticated
  `GET` requests across `/api/v1/*` is a read-exposure issue reported on its own and is not
  part of this chain
- No other MAR-2000 firmware build was examined, and no claim is made about any other Moxa
  product family

## Impact

- Arbitrary command execution as the identity of the Python model process, begun by one
  authenticated configuration write and delivered at a lifecycle moment the product performs
  on its own, with no memory-corruption primitive and no protocol manipulation anywhere in
  the chain
- The payload is stored configuration: it persists across reboots, it is read fresh at each
  tunnel application, and the same single field reaches two of the four sinks and appears
  twice in one of them - the attacker's statement executes in whichever management command
  runs first
- Reaching the route-management sinks also means owning the device's forwarding state
  implicitly: the same model the attacker has injected holds responsibility for the tunnel's
  addresses and routes on a device deployed as communication infrastructure
- The unvalidated-pattern family extends to the tunnel configuration file, whose assembled
  lines interpolate further unvalidated fields; that write was not exercised in this record
  and is reported as structure only
- Where the factory default administrator pair is unchanged, every one of the above is
  reachable by any client that can reach the management listener, with no credential owned
  by the operator consumed

## Mitigation / Fix Recommendations

1. Manage addresses and routes without a shell: build `ip` operations as argument vectors
   (an `execv`-family launch or a library API), which removes the metacharacter question
   from all four constructions at once
2. Validate every address-shaped field at the model's write boundary - IP address form,
   subnet form, interface selector - so a value that is not an address is rejected by the
   component that consumes it, not only by a web form
3. Make `clean_data()` a value validator, not a key filter: it currently removes unknown
   keys and is the natural single choke point where address semantics could be enforced
4. Add a product regression test that stores a metacharacter-bearing `localVpnIp` and
   asserts the write is rejected or that no shell interprets the value at apply time
5. Operator measures until a patch exists: change the factory default administrator
   credential at commissioning, keep the management listener off WAN-facing addresses, and
   audit stored IPsec tunnel tables for fields containing shell metacharacters

## References

- https://0day-rubbish.com/blog/mar-2000-network-ipsec-command-injection
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
