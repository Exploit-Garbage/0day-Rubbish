# Grandstream GDS371x (Release_GDS371x_1.0.13.10) - apicmd Config-File Removal Command Injection Executing With Root-Level Sink Authority

Advisory: https://0day-rubbish.com/blog/apicmd-config-rm-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Grandstream Networks builds the GDS371x series video door system, a SIP door station deployed at building
entrances and reception points and administered over the network through its own web interface. The
firmware analyzed for this advisory is `Release_GDS371x_1.0.13.10`. Its web plane is served by
`bin/web/webs`, a 722,060-byte stripped ELF binary for ARM 32-bit little-endian EABI5 hard-float,
glibc-linked, with recorded md5 digest `02ba4f122cd99b10c13266d167cf0792`, built on the GoAhead embedded
web server. GoAhead binds URLs to C callbacks through its `websFormDefine` API, and one of those
bindings is the generic control endpoint `/goform/apicmd`, whose name string sits in the image's
read-only data at `0xad868`.

`/goform/apicmd` is a dispatcher rather than a single action. A request supplies `cmd=N`, and `N` selects a
branch inside one large function spanning `0x41bf0` to roughly `0x923dc` - about 330 KB of code - which
answers with one of roughly a hundred P-code status strings (`P14002` through `P14206`). One branch, at
`0x805f8`, performs config-file housekeeping: it builds a filename from a request-derived string, prefixes
it with `/tmp/`, prefixes the result with `rm -rf `, and calls `system()` on the finished line. The value
is interpolated with `%s` and no quoting at every step, and the only transformation applied to it before
the shell sees it is a `tolower()` loop at `0x80500`-`0x80570`. The research record is explicit that no
`strchr`, `strspn`, `strcspn` or `isalnum` screening sits on that path, which means a semicolon, an
ampersand, a pipe, a dollar-parenthesis and a backtick all reach the command line intact.

Because `system()` executes through `/bin/sh -c`, the shell parses the injected text as a second command.
A value of `;id>/tmp/gds_m1;#` terminates the `rm -rf` word, runs the injected command, and comments out
the `.xml` suffix the handler appends, producing the effective line
`rm -rf /tmp/cfg;id>/tmp/gds_m1;#.xml`. The result is that an authenticated administrative request becomes
an arbitrary command channel in the web process's context - the record characterises that context as
root-level, and the advisory title carries that characterisation with the evidence boundary stated below.

The request-side gate is real and is not bypassed. The record's authentication class for `/goform/apicmd`
is HTTP Digest (`WWW-Authenticate: Digest realm=`) combined with a cookie session (`session`, `uname=%s`,
`level=%d`), enforced at handler entry by `wsSecurityHandler` before any `cmd=N` dispatch. This is a
post-authentication finding: the Digest challenge and session cookie are satisfied, not defeated, and no
credential bypass, session forgery or default-credential assumption is part of the chain. What the finding
changes is what an authenticated administrative request can do - the product's management vocabulary does
not include "run this command", and this chain adds it.

Verification is stated here exactly as the record holds it. The static half is instruction-level:
`bin/web/webs` was disassembled with Capstone in ARM Thumb mode to confirm the `sprintf` chain and the
`system()` call at `0x805f8`, and to confirm the absence of character screening between `0x80500` and
`0x80570`. The dynamic half is a sink-level replication on an isolated cloud-hosted sandbox, not a device run: the exact
argument string the firmware builds was replayed through `/bin/sh -c`, producing a marker containing
`uid=0(root) gid=0(root) groups=0(root)`, while the benign control `rm -rf /tmp/cfgbenign` produced no
marker. No physical GDS371x was driven, no HTTP request was fired at device hardware, and no emulated
appliance was booted. The identity in the marker is the sandbox shell's identity; it is not a measurement
of the device's web-process user, and the root-level reading of the sink is the record's characterisation
rather than a hardware observation.

- Component: the GoAhead form handler `/goform/apicmd` in `bin/web/webs` (722,060 bytes, md5
  `02ba4f122cd99b10c13266d167cf0792`), a `cmd=N` integer dispatcher whose handler body spans `0x41bf0` to
  about `0x923dc` and whose sub-handler at `0x805f8` performs the config-file removal
- Sink: four calls at `0x805f8` - `sprintf(buf1, "cfg%s.xml", Y)`, `sprintf(buf2, "/tmp/%s", buf1)`,
  `sprintf(buf3, "rm -rf %s", buf2)` and `system(buf3)` - with `Y` interpolated unquoted and no filtering
  beyond a `tolower()` loop at `0x80500`-`0x80570`
- Source: `*(r7+0x6008)`, the form-variable storage area of the GoAhead `webs_t` request structure, an
  identification the record presents as convention-based inference because the full backward walk across
  the 330 KB handler body was not completed
- Boundary: the record states that if a completed backward trace were to show the value is not a request
  form variable but an internal constant or configuration-set state, the finding would be revoked; this
  advisory repeats that falsifier rather than smoothing it over
- Authentication: HTTP Digest plus cookie session on `/goform/apicmd`, so the requester must already hold
  the device's administrative credential

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an administrative credential holder
  who can reach the device's web plane converts an intended config-file cleanup step into arbitrary
  command execution in the web process's context, which the research record characterises as root-level
  and which the sink-level replication measured as `uid=0(root) gid=0(root) groups=0(root)` inside the
  sandbox
- Attack Vector: Network - `/goform/apicmd` is an HTTP endpoint of the device's administrative web plane,
  reached over the network the device is deployed on; the analyzed image does not establish that the
  endpoint answers on an untrusted wide-area interface in an unmodified deployment, so the published vector
  describes network reach to that web plane rather than a claim of internet-wide exposure
- Attack Complexity: Low - one well-formed authenticated POST with one integer field and one string field
  is the whole detonation; no race, no timing window, no memory groom and no multi-step state machine
- Privileges Required: High - the endpoint is gated behind the device's administrative session (HTTP
  Digest plus cookie session, enforced at handler entry), and the record documents no lower-privilege
  web account able to reach `/goform/apicmd`
- User Interaction: None - the credential holder drives the request directly; no victim action is involved
- Scope: Unchanged - the injected command runs inside the device, within the authority of the web process
  whose handler was abused; no crossing into a beyond-device security authority is claimed
- Impact C/I/A: all High - command execution in the web process's context yields the device's
  configuration store (including any credential material that store holds), control of network, SIP and
  door-control behaviour outside the product's own management vocabulary, and control of service
  availability
- CWE: CWE-78 primary (OS command injection through a shell-interpreted argument built by string
  interpolation)

On the privilege metric: the reason this vector carries PR:H rather than the neighbouring PR:L tier is
that the vulnerable call site is strictly downstream of the administrative gate. Every request that reaches
`0x805f8` has already satisfied the Digest challenge and presented a session cookie whose value set
includes an administrative `level`, and the record describes no second web-account class - no operator, no
viewer, no guest - with access to `/goform/apicmd`. A PR:L reading would require some principal that holds
web access but not administrative rights, and no such principal is documented in the artifacts examined.
The requirement is also not softened by the vendor default credential mentioned in the record: a factory
`admin`/`admin` device is still reached by an administrative login, and the chain is unchanged by any
password rotation.

Rejected reading: a Low-privilege variant of the same impact profile - a hypothetical non-administrative
web account able to invoke the endpoint - would be `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8
High. It is rejected because nothing in the analyzed image or the record establishes a lower web tier on
this endpoint, and publishing it would overstate the population that can actually reach the sink.

Published arithmetic (headline): ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827, rounded up to 7.2. The
rejected reading's Exploitability term is 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, which with the same
Impact yields 8.708374 and rounds up to 8.8.

## Affected Products

- Grandstream GDS371x series video door system, firmware `Release_GDS371x_1.0.13.10` - the image analyzed
  end to end at instruction level in this research, ARM 32-bit little-endian EABI5 hard-float, glibc,
  stripped; affected component: the GoAhead form handler `/goform/apicmd` in `bin/web/webs` (722,060 bytes,
  md5 `02ba4f122cd99b10c13266d167cf0792`), specifically the sub-handler at `0x805f8` that builds and
  executes `rm -rf /tmp/cfg<value>.xml`
- Access requirement: a valid administrative session for the device's web plane (HTTP Digest plus cookie
  session), and a `cmd=N` value selecting the `0x805f8` branch; the record describes the payload shape as
  `cmd=<N>&<formvar>=<payload>` without fixing a single value of `N`
- Not claimed: firmware versions other than `Release_GDS371x_1.0.13.10` were not analyzed, no inference is
  made about earlier or later builds, and other Grandstream product families were not audited for this
  handler; the GDS371x series name is used because that is how the analyzed firmware names the product
- Not claimed: no pre-authentication path is asserted. The record notes that a working vendor default
  credential would make the chain effectively unauthenticated on a factory-state unit, but that is a
  deployment observation, not a second vulnerability, and it is not published as one
- Verification method and its boundary: instruction-level disassembly of the shipped `bin/web/webs` image
  (Capstone, ARM Thumb) established the handler registration, the `sprintf` chain, the `system()` call and
  the `tolower()`-only filter; dynamic evidence is a sink-level replication on an isolated cloud-hosted
  sandbox in which the exact constructed `system()` argument was replayed through `/bin/sh -c`, producing a marker
  with `uid=0(root) gid=0(root) groups=0(root)` and a clean control. No device was driven, so the request
  path and the authentication gate are disassembly-level claims while the injection behaviour at the sink
  is established by the replication
- Privilege ceiling of the claim: the record characterises the sink as root-level command execution, and
  the replication marker recorded root identity inside the sandbox. The device-side user context was not
  measured; it is reported as the record's characterisation, not as a hardware observation. Escape from the
  device to other hosts, persistence across factory reset or reflash, and any memory-corruption primitive
  were not tested and are not claimed

## Impact

- Complete loss of the boundary between the product's management interface and the device's operating
  system: a request that the product presents as config-file housekeeping executes attacker-chosen shell
  text in the web process's context, at the authority the record describes as root-level
- Exposure of the device's configuration store, including any credential material that store holds,
  within the readable filesystem scope of the web process
- Control of device behaviour outside the product's own management vocabulary: network settings, SIP
  registration, door-control parameters and service state can be changed by command rather than by
  supported configuration action
- Availability impact at will - service stop, process termination, filesystem damage - including through
  the `rm -rf` construction the injection rides on, whose recursive delete is itself part of the sink
- Persistence consistent with command execution on an embedded Linux device, up to the limits of the
  writable filesystem; what survives a factory reset or reflash was not tested and is not claimed
- A trust collapse for the administrative credential: a password that a deployment treats as "may adjust
  the door station's settings" is, in fact, "may run commands on the device that sits on the building
  network and controls the door"
- The chain is quiet in product terms: one authenticated POST to an endpoint the product itself exposes,
  with no malformed request, no exploit payload signature beyond punctuation in a filename field, and no
  repeated traffic pattern

## Mitigation / Fix Recommendations

1. Remove the shell from the config-file cleanup path. The branch needs to delete a file under `/tmp`;
   `unlink()` on the constructed path does exactly that with no shell parser involved, and a recursive
   removal, if genuinely needed, is `nftw()` or an explicit directory walk rather than `system("rm -rf ...")`
2. Validate the request-derived component by allowlist before it reaches any `sprintf`: for example
   `[A-Za-z0-9._-]{1,32}`, hard reject otherwise. The current path applies a `tolower()` loop, which
   normalises case and screens nothing
3. If a shell-based implementation must survive one release cycle, single-quote the interpolated value with
   literal single-quote escaping, and assert after construction that the final command string contains no
   byte outside the expected filename alphabet, failing the request on assertion
4. Apply the same review to every branch of the `/goform/apicmd` dispatcher. The endpoint multiplexes
   roughly a hundred branches through `cmd=N` inside 330 KB of code; a call-site grep cannot bound this
   surface, so the request-data-to-string-to-exec pattern should be a release gate over the whole
   dispatcher rather than a one-off audit
5. Run `bin/web/webs` under a dedicated unprivileged identity. This does not fix the injection, but it caps
   what any web-plane defect can reach, and this finding shows what an unbounded web process costs
6. Shrink the sink itself: deleting only a known-suffix file inside a fixed directory, with the value used
   solely as a validated filename component, keeps a recursive delete out of an attacker's reach even if a
   future change reintroduces string construction
7. For operators, until a fix ships: keep the door station's web plane on a management network that does not
   admit arbitrary stations, do not expose it through port forwarding or remote-access features, use a
   non-default administrative password, and treat any `/goform/apicmd` request carrying shell punctuation in
   a filename field as a command-execution indicator rather than a malformed request

## References

- https://0day-rubbish.com/blog/apicmd-config-rm-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
