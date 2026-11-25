# DigitalYacht 4GConnect RutOS 7.2.x - unquoted profile name command injection in the profiles.lua apply_profile handler

Advisory: https://0day-rubbish.com/blog/profiles-lua-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The DigitalYacht 4GConnect is a 4G cellular router built for marine and remote-site connectivity, and it
runs RutOS 7.2.x, the OpenWrt-derived router operating system maintained upstream by Teltonika. The
analyzed build is `4GConnect_R_GPL_07.02.08` on MIPS32 big-endian hardware with musl libc. Its web
management plane is a RutOS API server that issues a session token from `/api/login` and forwards the
resulting `/api/...` requests to ubus service modules implemented in Lua under `/usr/lib/lua/ubus/`. One of
those modules is
`/usr/lib/lua/ubus/system/profiles.lua`, which manages the device's named configuration profiles: it
exposes an operation to create one and an operation to activate one, the latter through the ubus method
`system.profiles.apply_profile`, reached over the management interface as
`POST /api/system/profiles/apply` with a JSON body of the form
`{"name": "<profile name>"}`.

The activation handler builds the shell command that switches profiles by plain string concatenation:

`os.execute("/usr/sbin/profile.sh -c " .. name)`

There is no quoting wrapper on the name, no character filter, no length limit and no allowlist. Lua's
`os.execute()` does not take a program plus an argument vector: it passes its single string to the C
library's `system()`, which runs `/bin/sh -c` on it. The concatenated command is therefore parsed a second
time, by a shell, and every shell metacharacter inside the profile name is live. A name of the form
`x;id>/tmp/dy_marker_vuln;#` produces the command line
`/usr/sbin/profile.sh -c x;id>/tmp/dy_marker_vuln;#`, which the shell reads as a helper invocation with
argument `x`, a second independent command `id>/tmp/dy_marker_vuln`, and a comment introduced by `#` that
swallows the remainder. Semicolon, pipe and `$( )` substitution are all available; the record's replication
exercises all three classes.

The contrast inside the same file makes the defect unambiguous. The module's `create_profile` function
rejects empty names, names longer than twenty characters and names that do not match `^[%w_]+$`.
`apply_profile`, which handles the same name from the same request body, applies none of that. Later RutOS
generations (7.6.x, the generation shipped on Teltonika's RUT2 and RUT9 hardware) close the issue by
wrapping the name in `shellquote()` before concatenation, so the difference between the vulnerable and the
fixed module is a single sanitization call that the 7.2.x build does not make.

Verification was a sink-level replication: the `os.execute()` sink was reproduced directly as `sh -c` on an
isolated cloud-hosted server running Ubuntu on x86-64, not on 4GConnect hardware. The injected payload
created a marker containing `uid=0(root) gid=0(root) groups=0(root)`, and a benign control name created no
marker at all. The root identity was observed only inside the replication environment: it reflects the
identity under which that environment executed the sink, and it is not a measurement of the identity of the
process that evaluates `profiles.lua` on a device. The device-side identity is not measured in the record,
and the accompanying exploit script's assertion that it is root is reported as unverified. No 4GConnect
hardware was driven, no HTTP request was sent to a device, and full QEMU emulation of the MIPS32 RutOS
image was not performed because the Wi-Fi driver dependency and the full OpenWrt userspace requirement
(`procd`, `ubusd`, `rpcd`, `nvram`) block it.

The chain is authenticated, not pre-authentication. The published vector carries `PR:H` because the
endpoint is inside the administrator boundary, and the record identifies no lower-privilege account class
that can reach the profiles method. The factory `admin:admin` credential pair that ships on these devices
is disclosed here as an adjacent weakness of a different class: it lowers the cost of obtaining the
session the injection needs, but it is not the vector, the injection works with any administrator
credential, and changing the administrator password does not remove the defect.

Two final scoping notes. First, this is not a memory-corruption issue and not a transport or
authentication defect; the entire flaw is the absence of neutralization between a request field and a
shell, which is CWE-78. Second, no identifier has been assigned: no CVE identifier is named in the
research record and none is claimed in this advisory.

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network - the sink is reached by an ordinary HTTPS request to the device's management
  service on port 443; the mechanism needs no adjacency, no same-link position and no local access
- Attack Complexity: Low - one well-formed authenticated POST after one login request; no race, no timing
  window, no memory grooming and no multi-step state machine
- Privileges Required: High - the request is inside the administrator session boundary established by
  `/api/login`; the record identifies no secondary account class with access to the profiles method
- User Interaction: None - the credential holder drives both requests directly
- Scope: Unchanged - the injected command executes inside the device, within the authority of the component
  whose interface was abused; no crossing into another security authority is claimed
- Impact C/I/A: all High - command execution inside the management plane yields the device's configuration
  store, its routing and firewall semantics and its service availability
- CWE: CWE-78

The `PR:H` value, rather than the neighbouring `PR:L` tier, follows from the authentication boundary the
research record establishes. The profiles method is not reachable from an ordinary web session: it is
reachable from the administrator session that `/api/login` issues, and the record documents no
lower-privilege account tier on the 4GConnect web plane that can invoke it. A `PR:L` reading would require
a principal with only basic privileges who can nevertheless call the profile-activation endpoint, and no
such principal is documented in the artifacts; the metric therefore describes the administrator, one tier
higher, and the score falls to 7.2 rather than rising to the 8.8 the low-privilege reading would produce.

Rejected reading, printed separately so that it is never mistaken for the published figure: the exploit
script in the research record states the score 8.8, which is the arithmetic of the low-privilege reading of
this same impact profile, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High. Its arithmetic is
ISS = 1 - (1 - 0.56)^3 = 0.914816, Impact = 6.42 x 0.914816 = 5.873119, Exploitability = 8.22 x 0.85 x
0.77 x 0.62 x 0.85 = 2.835255, and the sum 8.708374 rounded up to 8.8. It is rejected because it assumes a
low-privilege principal that this product does not offer on this surface: the only session that reaches
`POST /api/system/profiles/apply` is the administrator's, so the exploitability term must use the
High-privilege weight and the published score is 7.2.

Published arithmetic, for completeness: ISS = 1 - (1 - 0.56)^3 = 0.914816, Impact = 6.42 x 0.914816 =
5.873119, Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708, and the sum 7.107827 rounded up to
7.2.

## Affected Products

- DigitalYacht 4GConnect, RutOS 7.2.x, analyzed build `4GConnect_R_GPL_07.02.08` (MIPS32 big-endian, musl
  libc, OpenWrt userspace). Affected component: `/usr/lib/lua/ubus/system/profiles.lua`, function
  `apply_profile()`, ubus method `system.profiles.apply_profile`, reached as
  `POST /api/system/profiles/apply` behind the administrator session issued by `/api/login`
- The defect is the unquoted, unvalidated concatenation of the `name` request field into
  `os.execute("/usr/sbin/profile.sh -c " .. name)`; later RutOS generations such as 7.6.x apply
  `shellquote()` at the same statement and are not exploitable by this payload
- Not claimed: other ubus modules of the same firmware are not shown to be exploitable by this payload, and
  no other Digital Yacht model, hardware revision or firmware build is claimed by inference. Only the
  profile-activation path of the analyzed build was followed end to end
- Verification method and its boundary: the sink was reproduced directly as `sh -c` on an isolated
  cloud-hosted server (Ubuntu, x86-64) with the exact command string `os.execute()` constructs. The
  injected payload created a marker containing `uid=0(root) gid=0(root) groups=0(root)` and a benign
  control name created none; semicolon, pipe and command-substitution forms were each confirmed. The root
  identity was observed only inside that replication environment - the replication session itself ran as
  root - so it documents the sink's behaviour under a root parent process and does not measure the
  device-side identity, which the record does not establish
- Not reached and not claimed: end-to-end HTTP execution against 4GConnect hardware, QEMU emulation of the
  MIPS32 RutOS image, persistence across factory reset or reflash, lateral movement from the device, and
  any memory-corruption primitive

## Impact

- Conversion of a bounded configuration action into an arbitrary command channel: an administrator who was
  meant to select a profile can instead run commands inside the device's management context, which is where
  the configuration store, the interface state and the service control of the device live
- Exposure of the secrets the device holds for its own operation within the readable scope of the
  management process, including the credentials and keys the firmware stores in its configuration
- Control of the device's data plane at the device's discretion: routing, DNS and firewall semantics are
  owned by the same plane, so a compromised 4GConnect is a compromised network edge for everything behind
  it - the common deployment is a vessel or a remote site whose only uplink is this device
- Persistence consistent with command execution in an embedded Linux management plane, up to the limits of
  the writable filesystem; survival across a factory reset or a reflash was not tested and is not claimed
- Availability impact at will, from taking the management plane down to making the device unreachable
- The chain is quiet in product terms: one login and one authenticated POST that looks like ordinary
  profile management, with no payload visible in the URL and nothing that a configuration diff would
  obviously flag beyond the stored profile name

## Mitigation / Fix Recommendations

1. Apply the upstream fix: wrap the name in `shellquote()` at the sink, as later RutOS generations do -
   `os.execute("/usr/sbin/profile.sh -c " .. shellquote(name))`. This is the one-line change that closes the
   class on this path
2. Validate the name on the activation path with the gate the module already implements for
   `create_profile`: reject empty names, names over the length cap, and names that do not match
   `^[%w_]+$`, and answer with the module's error reply
3. Remove the shell entirely: replace `os.execute()` with an exec-family call that takes an argument vector,
   so the profile name can never be parsed as shell syntax. This is the only change that removes the class
   rather than the instance
4. Sweep `/usr/lib/lua/ubus/` for `os.execute`, `io.popen` and any other shell-mediated call built by
   concatenation, and apply both controls to each; one module was analyzed and the pattern is cheap to
   find
5. Reduce the blast radius by running the management plane and its helpers under a dedicated unprivileged
   identity; this does not fix the injection and must not be presented as a fix
6. Add module-level regression tests: activation requests whose names contain `$(true)`, `;`, `|` and a
   backtick must be rejected or produce no shell effect, on every RutOS build shipped
7. Until a fixed build exists, operators should keep the management plane on a trusted segment, avoid
   exposing it to the cellular uplink, change the factory `admin:admin` pair as hygiene against the
   adjacent weakness, and treat any account that can reach the profiles endpoint as holding device-level
   authority

## References

- https://0day-rubbish.com/blog/profiles-lua-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
