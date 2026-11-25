# Lantronix LSS2200-8P v2.1.0.0R2 - Percepxion registration response command injection in the root provisioning client

Advisory: https://0day-rubbish.com/blog/percepxion-remote-access-host-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Lantronix is a United States vendor of secure device networking and out-of-band management
equipment. The LSS2200-8P is an eight-port serial console server in that line: it places the serial
consoles of routers, switches, firewalls and other infrastructure onto the network so that they can be
administered remotely, which means the appliance normally sits inside the management path of everything
connected to its ports. Firmware v2.1.0.0R2 (image `LSS2200-8P_2.1.0.0R2_image.tgz`) runs the vendor's
EOS framework, an OpenWrt/LEDE-derived distribution that identifies itself as "Eland 2.1.0.0R2", on
64-bit ARM with musl libc and stripped binaries. The web plane is nginx-ssl listening on 443 with a
self-signed certificate and on 80, serving a React single-page application; the REST API behind it is a
Flask-RESTX application on gevent, bound to port 8000, and every REST method on it is wrapped in
`jwt_required()`.

The appliance also implements the vendor's Percepxion cloud connection, a provisioning channel through
which the device registers itself with a remote management service. The client that implements it,
`eos/modules/percepxion_client.py`, is started by the vendor init script as root. Its `connect_server()`
method posts a registration request to the configured service and then takes two fields out of the JSON
answer - `remote_access_host` and `auth_token` - and concatenates them, unfiltered and unquoted, into a
command line handed to `os.system()`, which is the construction recorded at
`percepxion_client.py:2170`. Because `os.system()` runs its argument through `/bin/sh -c`, that JSON
field is parsed a second time, by a shell, in a context the device never modeled. A registration answer
whose `remote_access_host` value is `$(id>/tmp/marker)x` therefore executes `id` on the appliance, and
the recorded dynamic verification shows the resulting marker carrying `uid=0(root) gid=0(root)
groups=0(root)`. A second construction with the same defect exists in the `status_update` thread of the
same module at `percepxion_client.py:2274-2281`, where `auth_token` is injectable through the same path.

Reaching the sink requires the appliance administrator. The Percepxion connection settings are exposed
by the REST resource `PercepxionConnectionConfig` (`percepxion_v1.py:321`, POST handler at line 366),
which is guarded by `@jwt_required()` plus `check_group_auth` for the `AUTH_ALLOW_CONFIG` group. The
administrator points `HOST` at a host they control, sets `PORT`, sets `SECURE_PORT` to false and
`VALIDATE_CERTIFICATES` to false, and the device's root daemon then registers with that host - on its
periodic timer as well as on configuration change. The YANG model behind the setting,
`ltrx-eos-percepxion.yang:212`, declares `host` as a plain string with a length bound of 0..256 and no
character restriction, so nothing constrains the value the administrator stores. This is not a
man-in-the-middle finding: the administrator explicitly configures the endpoint, and the defect is the
device trusting a server-controlled field inside a shell invocation.

- Authentication class: Authenticated (Target B) - a JWT-bearing session; the source record establishes
  that every REST method on the API carries `jwt_required()` (199 of 199 methods, verified one by one),
  with only the login routes free of the gate, and that the first-login password change is enforced so
  the documented default credential cannot be used as-is
- Component: `eos/modules/percepxion_client.py`, `PercepxionClient.connect_server()`, first sink at
  `percepxion_client.py:2170`; second sink in the `status_update` thread at
  `percepxion_client.py:2274-2281`
- Sink: `os.system("webcontrol -r 0 -h " + reg_response["remote_access_host"] + " -s -p 443 -a " +
  reg_response["auth_token"] + " -d " + self.device_id + " &")`, where `reg_response` is the parsed JSON
  body returned by the Percepxion registration endpoint
- Source: the `remote_access_host` (and, at the second sink, `auth_token`) JSON field of the registration
  response, fetched by `curlConnection.register()` at `percepxion_client.py:615` from
  `http{secure}://{HOST}:{PORT}/api/v1/device/register`, with certificate validation disabled by the
  configuration above
- Sanitization: none. The field is concatenated into the command line as-is; the only transformation the
  device applies is JSON decoding. The registration call is treated as successful whenever the answer
  carries no `status` of 400 or 401 and no `code` key, so an attacker-controlled responder needs no
  privileged state to reach the sink
- Breakout: `$(cmd)` command substitution inside the `-h` argument, which the shell expands before
  `webcontrol` runs, so the injected command executes whether or not the helper binary then succeeds or
  blocks
- Execution identity: root. `/etc/init.d/eos_launcher.init:34` sets `procd_set_param user root` for the
  daemon, and the launcher configuration carries `USERNAME: 'root'` (line 83)
- Verification boundary: root was observed inside a replication environment only. The dynamic run
  executed the recorded sink line inside a writable chroot of the firmware root filesystem on a
  cloud-hosted machine, entered as root, with the marker landing inside that chroot; no physical
  LSS2200-8P was driven, and no REST configuration request was fired at appliance hardware. The
  device-side root identity is established from the init script, and the sink behaviour from the
  replication
- Public record: no identifier assigned. The nearest published record naming this vendor's EOS platform,
  the EDS5000 CVE-2025-67034, describes a different sink (an SSL-certificate-delete `name` parameter) on
  a different product; nothing in the public record covers this field, this function or this sink

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network - the configuration request and the registration callback both cross a network
  boundary; nothing in the chain requires the attacker to be on the same link as the appliance, and the
  Percepxion endpoint is by design a remote host
- Attack Complexity: Low - the administrator stores a host and a port through one ordinary REST request,
  a responder answers one registration POST with a JSON body, and the shell does the rest; there is no
  race, no timing window, no memory-corruption groom and no second-stage payload to deliver
- Privileges Required: High - see the paragraph below
- User Interaction: None - the administrator drives the configuration change directly, and the root
  daemon's registration is automatic
- Scope: Unchanged - the substituted command executes inside the appliance, within the authority of the
  component whose configuration interface was abused; no crossing into a beyond-device security
  authority is claimed
- Impact C/I/A: all High - arbitrary command execution as root on the appliance that mediates management
  access to the attached consoles yields the device's complete configuration store, full control of its
  management semantics, and total control of its service availability

Privileges Required is High rather than Low or None because the only interface that reaches this sink is
the administrator configuration resource. The source record establishes that all 199 REST methods carry
`jwt_required()`, that `PercepxionConnectionConfig` additionally requires membership of the
`AUTH_ALLOW_CONFIG` group, and that the device enforces a password change on first login, so the
documented default credential does not open the console either. The product documents no secondary
account class with access to this resource, which means the principal that can reach the sink is the
highest-privileged account the appliance offers - the definition of PR:H - even though that principal
must have been convinced, socially or otherwise, to point the appliance at an attacker-controlled
service. The reading is deliberately conservative in the other direction as well: an administrator who
merely holds the console is not otherwise given a shell, so the vector does not collapse to "the
administrator already owns the box". It crosses a boundary the vendor intended to hold, from
configuration authority to operating-system command execution.

Rejected reading: a hypothetical lower-privilege web account able to reach the same configuration
resource would be `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, whose arithmetic is 8.8 High - ISS
0.914816, Impact 5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, sum 8.708373
rounded up to 8.8. That reading is rejected because the artifacts describe no such account class on this
firmware; the configuration resource is administrator-only, so no principal exists to justify Low
privileges. It is recorded here only so that the number cannot later be quoted as if it were the
headline. Published arithmetic for the assigned vector: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42
x 0.914816 = 5.873119; Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827,
rounded up to 7.2.

## Affected Products

- Lantronix LSS2200-8P eight-port serial console server, firmware v2.1.0.0R2 (firmware image
  `LSS2200-8P_2.1.0.0R2_image.tgz`), the version analyzed end to end in this research; ARM aarch64, musl
  libc, stripped binaries, EOS "Eland 2.1.0.0R2" userspace on an OpenWrt/LEDE base. Affected component:
  `eos/modules/percepxion_client.py`, both the `connect_server()` command construction at
  `percepxion_client.py:2170` and the identical construction in the `status_update` thread at
  `percepxion_client.py:2274-2281`
- The trigger surface is the Percepxion connection configuration resource `PercepxionConnectionConfig`
  (`percepxion_v1.py:321`, POST at line 366) and the registration endpoint the device then calls,
  `http{secure}://{HOST}:{PORT}/api/v1/device/register`, whose response body supplies the injected field
- Not claimed: firmware earlier or later than v2.1.0.0R2 was not available for comparison, so no
  statement is made about whether the same construction exists there; other Lantronix product lines that
  ship the EOS Percepxion client were not audited and are not claimed by inference; the sibling sink at
  `percepxion_client.py:1107/1129` uses an argument-array form and was assessed as safe rather than
  affected
- Verification method and its boundary: the static half of the evidence is a source-level review of the
  shipped Python and engine files plus a census of every shell-execution sink in the `eos/` tree. The
  dynamic half is a sink-level replication - the recorded exploit ran, inside a writable chroot of the
  appliance's own root filesystem on a cloud-hosted machine, the exact `os.system` line from
  `percepxion_client.py:2170` fed by a locally hosted registration responder, and the injected command
  wrote a marker containing `uid=0(root) gid=0(root) groups=0(root)` owned by `root:root`, 39 bytes, as
  the recorded run shows; the same sink was then exercised again through the real `curlConnection`
  class and pycurl with an identical result. No physical LSS2200-8P was driven, so the request path, the
  session gate and the parameter handling are established at source level, while the shell behaviour at
  the sink is established by the replication. Root was observed inside that replication environment
  only; on the device the daemon's identity is read from `/etc/init.d/eos_launcher.init:34`
  (`procd_set_param user root`) and the launcher configuration's `USERNAME: 'root'` at line 83
- Privilege ceiling: arbitrary command execution as root inside the appliance. Not reached and not
  claimed: escape from the console server to the devices attached to its serial ports, persistence
  across a factory reset or reflash, and any memory-corruption primitive

## Impact

- Command execution as root on the appliance that brokers management access. A serial console server is
  installed to give its administrator console access to the infrastructure cabled to its ports; root on
  that appliance is the authority which mediates that access, so the compromise sits on the management
  path rather than on an isolated leaf
- Disclosure of every secret the device holds for its own operation, within the readable filesystem
  scope at root authority: the configuration store, the local account material, and whatever credentials
  the EOS configuration holds for the network services it uses
- Full control of the appliance's behaviour: interface configuration, the serial-port and console
  semantics it presents to remote administrators, logging and alerting, and the availability of every
  service it offers
- Persistence consistent with root command execution on an embedded Linux system - startup hooks,
  accounts, scheduled tasks - up to the limits of the writable filesystem; survival of a factory reset
  or reflash was not tested and is not claimed
- Availability impact at will, both coarse (rebooting or stopping services from the shell) and surgical,
  including falsifying what the console server reports about the devices behind it
- The chain is quiet in product terms: the only device-side events are an ordinary configuration change
  and an ordinary registration callback, both inside the legitimate provisioning flow, and the injected
  command is expanded by the shell before the helper binary reports anything

## Mitigation / Fix Recommendations

1. Remove the shell from the path. Invoke the helper with an argument vector - `subprocess.run` or
   `os.execv`-family calls with a list, no `shell=True` - so that `remote_access_host` and `auth_token`
   can never be parsed as shell syntax. This eliminates the class on this surface instead of filtering
   characters
2. Validate the registration response as data before it is used anywhere: accept `remote_access_host`
   only if it matches a hostname or address grammar (for example `[A-Za-z0-9.-]{1,253}` for a hostname,
   or a parsed address object), and treat `auth_token` as an opaque token restricted to the alphabet the
   protocol actually needs
3. Enforce server authentication rather than offering the switch that turns it off. A firmware release
   should refuse `VALIDATE_CERTIFICATES = False` for a cloud connection, pin the expected service
   identity, and constrain `HOST` in `ltrx-eos-percepxion.yang` to a domain allowlist or explicit address
   rather than the unrestricted 0..256 string recorded at `ltrx-eos-percepxion.yang:212`
4. Audit the sibling construction: `percepxion_client.py:2274-2281` repeats the same pattern in the
   `status_update` thread, so a patch that only touches `connect_server()` leaves an equivalent path open
5. Drop the daemon's privileges. The connection client needs to write a small amount of state and to make
   outbound HTTP requests; it does not need root. Running it under a dedicated unprivileged account, with
   the helper invoked through a scoped interface, caps the blast radius of this and any future defect
6. Add a regression test at the unit level: feed `connect_server()` a response whose `remote_access_host`
   contains `$(true)`, the backtick form and the semicolon form, and assert that no shell is invoked and
   that the value is rejected before use. Run the same test against the `status_update` path
7. Until a fix ships, operators should treat the Percepxion configuration page as an administrative
   boundary: leave the cloud connection disabled where it is not used, keep it pointed only at the
   vendor's genuine service with certificate validation on, and restrict access to the management
   interface to a dedicated administration network

## References

- https://0day-rubbish.com/blog/percepxion-remote-access-host-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
