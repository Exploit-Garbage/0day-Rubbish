# HAProxy ALOHA VA 18.0.12-1820 - WUI File Manager Root File Write Into config.rc and Root Command Injection Through the sysset Field

Advisory: https://0day-rubbish.com/blog/wfm-configrc-sysset-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

HAProxy ALOHA VA (Virtual Appliance) is HAProxy Technologies' virtualized application delivery
controller, shipped as an 8 GB qcow2 image for KVM, VMware and HAProxy Cloud, with its management
plane served as plain HTTP on TCP 4444. The management interface is not a stock HAProxy front end: it
is an nginx instance fronting a purpose-built C web UI at `/opt/wui/bin/wui`, and that web UI embeds a
File Manager component, `wfm.cgi` (WFM v1.4.2). The File Manager's backend, `f2cgi_admin`, runs with
root authority and performs file reads and writes on behalf of any client that presents a valid WUI
session, with no path confinement. In the version analyzed here, 18.0.12-1820
(`aloha-albva-kvm.tgz`, HAProxy 3.3.0-aloha-bfd905b3-flx2.19_albva), that File Manager is therefore a
root-privileged arbitrary file read and write primitive reachable over the network from a web session.

The appliance ships with the factory credential pair `admin`/`admin`, and the first boot does not force
the operator to change it before the management UI becomes reachable; the record also notes that the
evaluation licence mode remains usable, so no licensing step stands in front of the interface. An
attacker who can reach TCP 4444 therefore obtains a WUI session with nothing that is not published in
the product documentation. The chain documented in this advisory uses that session and the File
Manager to turn the root file-write primitive into arbitrary command execution as root, in three
requests from a single client, with no race, no multi-stage residency and no second principal.

The device's runtime configuration, `/etc/config.rc`, is a bash-dialect file of `service` sections
that the appliance's own init framework executes rather than parses. `/etc/init.d/functions` line 1463
defines `load_config()`, which dispatches a configuration section through `run_stdin parse_cfg` fed by
an `awk` extraction from the config file. The section body is handed to a bash function dispatcher, so
shell syntax inside a section is not data - it is code. The chain therefore proceeds as follows: read
`/etc/config.rc` through the File Manager as root (11027 bytes in the analyzed image), graft a
`sysset` line carrying a command substitution into the `service network lo` section, write the file
back through the File Manager as root (the write answers HTTP 302), then ask the WUI to restart that
service instance over `POST /service/action`. The WUI dispatches the restart through `alohacore.so` and
its `cmdwrapper`, which executes `/etc/init.d/network restart` as root; `load_config()` re-enters the
`network` section in bash and evaluates the `$( )` substitution as root. The marker file written by the
substituted command, `/var/state/wui/CFG_PWN_6f9a`, is 37 bytes and owned by `root:adm`, with the exact
content `uid=0(root) gid=4(adm) groups=4(adm)`.

Verification was end-to-end against a running appliance: the official qcow2 release booted under QEMU
system mode in its factory first-boot state, with the management port forwarded to the host loopback
only. Two rounds were performed - an initial proof and a clean-reboot reproduction driven end to end by
a single script - and the root identity of the resulting marker was established three independent ways:
read back through the root File Manager channel, `stat` from the appliance's serial console showing
owner `root:adm` and size 37, and a guest RAM dump in which the marker text appears at offset
158390328. Root was observed inside that QEMU replication environment; no physical ALOHA appliance was
driven, and no claim is made about hardware units beyond the shared image. Because `/etc` and `/var` are
both tmpfs mounts on this appliance, the effect is runtime-only and does not survive a reboot; no
persistence is claimed.

This is not a memory-safety defect and not a transport-layer defect. The defect is architectural on two
counts that compose: a web-reachable file manager with root authority and no path confinement, and an
init framework that executes configuration text as shell instead of parsing it as data. The factory
default credential is disclosed separately as an adjacent weakness (CWE-798) that removes the last
obstacle in the shipped default state; the injection itself (CWE-78) would remain reachable for any
holder of a WUI session even after that credential is rotated, which is why the two are reported
separately rather than as one dependency. No identifier has been assigned.

## CVSS Score

- Score: 9.8 Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network - the management UI is a TCP service on port 4444, served as plain HTTP, and
  is the appliance's designed remote administration plane; no local attachment, console access or
  adjacent-network position is required by the chain
- Attack Complexity: Low - three ordinary HTTP requests from one client, in a fixed order, with no
  race, no timing window, no memory grooming and no dependency on a value the attacker cannot observe
- Privileges Required: None - the shipped appliance accepts the published factory pair `admin`/`admin`
  and does not force a change before the management UI is reachable, so the attacker supplies nothing
  that is not public product knowledge
- User Interaction: None - the attacker drives login, the two File Manager operations and the service
  action directly; no operator or browser is involved at any point
- Scope: Unchanged - the substituted command runs inside the appliance, within the authority of the
  component whose interface was abused; no crossing into another security authority is claimed
- Impact C/I/A: all High - command execution as root on the appliance yields its complete runtime
  configuration, the ability to rewrite any configuration section the init framework will execute, and
  full control of service availability
- CWE: CWE-78 primary (OS command injection through configuration text evaluated by bash); CWE-798
  adjacent and reported separately (use of a hardcoded default administrative credential)

The vector reads PR:N rather than the neighbouring PR:L tier because the privilege question is asked
about the shipped product, not about a hardened deployment. On an appliance as distributed, the
credential needed to obtain a WUI session is the factory pair printed in the product's own
documentation, the first boot does not require it to be replaced, and the record confirms that the
evaluation licence mode remains usable, so nothing stands between an unauthenticated network client and
the management UI. An attacker who has to guess, brute-force or steal a secret is paying a privilege
cost; an attacker who types a published default is not. A deployment in which the operator has already
replaced the default pair sits behind an authentication boundary and is outside the published vector;
that deployment is discussed below as a rejected reading, not as the headline.

Rejected reading, printed with its own vector so that a hardened deployment is not silently described by
the headline: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High, the reading in which the
operator has rotated the default administrative credential, so the chain head must be reached with a
valid secret. It is the neighbouring PR:L tier of the metric, taken as the arithmetic neighbour of the
published vector rather than as a claim that a lower-privileged account tier exists on this appliance.
Arithmetic for that reading: ISS 0.914816, Impact 6.42 x 0.914816 = 5.873119, Exploitability 8.22 x
0.85 x 0.77 x 0.62 x 0.85 = 2.835255, sum 8.708374, rounded up to 8.8. It is rejected as the published score because the
advisory describes the product as shipped: the factory state is the state the vendor distributes, and in
that state no credential beyond the published default is required.

Published arithmetic (headline): ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 =
5.873119; Exploitability = 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043; sum 9.760162, rounded up to
9.8.

## Affected Products

- HAProxy ALOHA VA (Virtual Appliance), version 18.0.12-1820, distribution archive `aloha-albva-kvm.tgz`,
  running HAProxy 3.3.0-aloha-bfd905b3-flx2.19_albva on the vendor's 8 GB qcow2 virtual appliance
  image; affected components: the WUI File Manager `wfm.cgi` (WFM v1.4.2) with its root backend
  `f2cgi_admin`, and the `/etc/config.rc` configuration store as consumed by `load_config()` in
  `/etc/init.d/functions`
- Deployment forms named in the record: KVM, VMware and HAProxy Cloud, with the management plane
  served as plain HTTP on TCP 4444
- Same-root-cause family, stated as inference rather than measurement: the record notes that the File
  Manager is a product-level component of the WUI, so the root read and write primitive is expected to
  apply across the ALOHA line, and that the bash dispatch of configuration sections in `load_config()`
  belongs to the Formilux/AHA init framework core, so any `.rc` or `.conf` file that is writable
  through the File Manager and read by any `/etc/init.d/*` script or by `alohactl` is of the same type
  (the record names network, syslog, haproxy, lvs, rhi and gslb as candidate scripts). Only version
  18.0.12-1820 was tested end to end; no other version or model was measured
- Not claimed: physical ALOHA hardware units beyond the shared image, appliances booted from a
  different build, persistence across reboot or reflash, and any second injection path in the WUI
  beyond the one documented here
- Verification method and its boundary: end-to-end execution against the official image booted under
  QEMU in system mode, in factory first-boot state, with the management port bound to the host loopback
  only. Root identity of the marker was confirmed inside that replication environment by three
  independent channels (root File Manager read-back, serial console `stat`, guest RAM dump). No
  physical appliance was driven; the root observation is therefore a replication-environment
  observation, and the appliance-side behaviour of a hardware unit is not independently claimed

## Impact

- Arbitrary command execution as root on a network-reachable management appliance from a single
  unauthenticated client: the File Manager supplies the write primitive and the init framework supplies
  the execution, so the attacker obtains everything the device itself can do
- Complete disclosure of the appliance's runtime configuration, including every credential and key
  material the device holds in the files it is able to read at root authority - the same File Manager
  channel that reads `/etc/config.rc` reads any other path
- Ability to rewrite the configuration sections the init framework evaluates, which means the attacker
  can shape every service the appliance manages (the record names network, syslog, haproxy, lvs, rhi
  and gslb as scripts of this type), including the load-balancing behaviour the appliance exists to
  provide
- Full control of availability: services can be restarted, reconfigured or broken at will, and the
  restart trigger used by the documented chain is itself an ordinary product action
- A direct path from the management plane to the data path: an attacker with root on a load balancer
  controls what is proxied, to where, and under which certificates, so every downstream service behind
  the appliance inherits the exposure
- Silent in product terms: three requests inside legitimate WUI functionality (login, File Manager
  save, service restart), no malformed traffic, no crash, no log-worthy anomaly beyond ordinary
  administrative use
- Boundary of the claim: the effect is runtime-only on this appliance, because `/etc` and `/var` are
  tmpfs mounts and are cleared by a reboot; persistence across reboot, reflash or factory reset was not
  tested and is not claimed

## Mitigation / Fix Recommendations

1. Remove root authority from the File Manager, or remove the File Manager's reachability from a web
   session. A root-privileged file manager should not be dispatchable by an HTTP request; if the
   component must stay, confine it to a fixed directory set with a path allowlist, reject traversal and
   absolute escapes, and run the backend under a dedicated unprivileged identity
2. Stop executing configuration text in `load_config()`. Replacing the `run_stdin parse_cfg` dispatch
   with a real parser that reads key/value fields and dispatches on a validated key set removes this
   class on every script of the framework at once, rather than patching one section name
3. Validate the `sysset` value field as data at the point of use, and reject shell metacharacters in
   configuration values before they are written, so that a config file that reaches the init framework
   from any other source is also inert
4. Force a credential change on first boot and refuse to serve the management UI until it has happened.
   This does not fix the injection, which remains reachable for any WUI session holder, but it removes
   the unauthenticated path to that session
5. Terminate the management plane over TLS and restrict it to an administrative network; plain HTTP on
   TCP 4444 means session cookies and the factory credential cross the wire in the clear, which turns
   an on-path observer into a session holder
6. Audit every other component that writes into the configuration store, and every `wfm.cgi` action, for
   the same pattern; the root read and write primitive is a product-level component, so a fix scoped to
   one section or one action leaves the primitive intact
7. Add a regression test at the appliance level: write a `sysset` value containing a command
   substitution through the File Manager, restart the service, and assert that no file is created and no
   output is produced by the substituted command

## References

- https://0day-rubbish.com/blog/wfm-configrc-sysset-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
