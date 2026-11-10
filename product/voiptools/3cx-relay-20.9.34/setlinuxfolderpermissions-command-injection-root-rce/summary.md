# VoIPTools Relay for 3CX 20.9.34 - SetLinuxFolderPermissions `permissions` OS Command Injection Executing as Root

Advisory: https://0day-rubbish.com/blog/setlinuxfolderpermissions-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

VoIPTools Relay for 3CX is a .NET service that is installed on a 3CX PBX server and extends it with a REST
API that forwards into the 3CX Call Control API, a SignalR real-time event API and a Blazor administrative
console. The service hosts all three interfaces in a self-hosted Kestrel web server that listens on
`https://0.0.0.0:8801` by default. One of its administrative helpers is `SetLinuxFolderPermissions`, an
endpoint intended to hand ownership or mode bits on a directory to one of two well-known service accounts
(`phonesystem`, `postgres`) or to an arbitrary numeric mode. The endpoint accepts two base64-encoded
parameters in a single JSON blob and decodes them server-side before use.

The defect is in how the second parameter, `permissions`, reaches the operating system. The Relay ships a
shell helper, `RelayServices.Utilities/ShellHelper.cs`, whose `Bash()` method executes its single string
argument as `/bin/bash -c "<cmd>"`. The caller in `ApiMethods.cs:3178` builds that string by interpolating
the decoded `permissions` value into a `sudo chmod` command line inside single quotes for the path but
without any quoting or validation for the mode. The only check applied to `permissions` before it is
concatenated is a null-or-whitespace test at `ApiMethods.cs:3172`. There is no allowlist, no character
screen and no numeric parse. A `;` therefore terminates the `chmod` command and starts a second one, which
`/bin/bash -c` executes as part of the same invocation. Because the command line is prefixed with `sudo`,
that second command runs with root authority on the PBX host.

The companion parameter, `folderPath`, is guarded in a way that makes it much harder to abuse: it must
satisfy `Directory.Exists` or `File.Exists` before the call site runs, so arbitrary path text is rejected
early. The module also contains a single-quote escaping step for that value at `ApiMethods.cs:3177`, but the
resulting string is assigned to a local variable that the following line never reads - the escaped form is
dead code and the original value is interpolated instead. That dead escaping matters for two reasons: it
misleads a reader into believing the path is protected, and it shows that the developers were aware of the
quoting problem on one parameter while leaving the other one entirely unquoted. The reachable, uninhibited
injection vector is `permissions`.

The sink is not reachable without a session. The Relay's REST controllers carry a class-level `[Authorize]`
attribute - `V1Controller` and `TablesController` among them - and only the three endpoints of
`AuthorizationController` are decorated `[AllowAnonymous]`. The legitimate path to a token is
`POST /api/Authenticate`, which issues an HS256 JWT to any caller presenting the configured `PublicKey`;
that key, together with its `PrivateKey` counterpart, is stored in plaintext in `appsettings.json` and
`settings.txt`. The web console, by contrast, authenticates against the 3CX administrator credential set.
This is therefore an authenticated finding: it consumes a legitimate administrative position in the Relay
web interface and is unaffected by any password change on the PBX itself, because no credential is guessed.

Dynamic verification used the vendor's own compiled service rather than a model of it. The Linux
`RelayServicesHost` build of Relay 20.9.34 (assembly version 20.9.32.35089) was deployed on an isolated
Linux host as a self-contained Kestrel service, with one documented substitution: a stub
`tcxpscom_native.so` stood in for the 3CX native library that a real PBX installation provides, so that the
service would start without a PBX underneath it. The exploit was then driven end to end against that
running service over loopback on a non-default TLS port. Authentication succeeded against
`POST /api/Authenticate`; the injected request returned HTTP 200 with a `false` body, which is the
endpoint's expected answer whenever the captured command output is non-empty; and the marker file created
by the injected command was confirmed through the service's own `FileExists` endpoint. Reading the marker
on the host produced `uid=0(root) gid=0(root) groups=0(root)`.

- Component: the Relay administrative helper `SetLinuxFolderPermissions`, reached as
  `GET /api/SetLinuxFolderPermissions/{json}` on the Kestrel listener of Relay 20.9.34 (assembly 20.9.32.35089)
- Sink: `RelayServices.Utilities/ShellHelper.cs` `Bash()`, which runs `/bin/bash -c "<cmd>"`, invoked from
  `ApiMethods.cs:3178` with a command line of the shape `sudo chmod {permissions} '{folderPath}'`
- Source: the base64-encoded `permissions` field of the JSON path segment, decoded by
  `DecodeBase64UTF8` in `V1Controller.cs:154` and passed through unchanged
- Sanitization: a null-or-whitespace check only (`ApiMethods.cs:3172`); the path parameter carries an
  escaping step at `ApiMethods.cs:3177` that is dead code, and the mode parameter carries nothing
- Execution identity: the command line is prefixed with `sudo`, and the `uid=0(root)` marker recorded
  during verification shows the injection landing at root inside the replication deployment
- Verification boundary: end-to-end exploitation of the real vendor service binary on an isolated Linux
  sandbox with a stubbed 3CX native library, driven over loopback; no physical 3CX appliance was used, and
  the appliance-side service account and its sudo policy were not measured

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an administrator of the Relay web
  interface, or any holder of the shared `PublicKey` that mints a REST token, converts an intended
  directory-permission helper into arbitrary command execution in the Relay host's root context
- Attack Vector: Network - the Relay listener is an HTTPS service bound to all interfaces on the PBX host,
  and every step of the chain is an ordinary HTTP request
- Attack Complexity: Low - two requests, one to mint a token and one to inject; no race, no timing window
  and no memory-corruption groom is involved
- Privileges Required: High - the endpoint sits behind the class-level `[Authorize]` attribute and the
  legitimate entry point is the Relay administrative surface; the research record documents no
  lower-privileged account class in the Relay web interface that reaches this controller
- User Interaction: None - the credential holder issues both requests directly
- Scope: Unchanged - the injected command executes inside the Relay host, within the authority of the
  component whose interface was abused; no crossing into a separate security authority is claimed
- Impact C/I/A: all High - root command execution on the PBX host yields its filesystem, its configuration
  and any credential material stored there, complete control over the Relay's behaviour, and the ability to
  stop or destroy the service at will
- CWE: CWE-78 (improper neutralization of special elements used in an OS command)

Privileges Required is High rather than Low because the gate on this endpoint is the Relay's own
administrative surface, not a user-facing tier. The controller carries a class-level `[Authorize]` attribute,
the alternative entry point is a shared `PublicKey` that is documented and stored as a server-side secret,
and the web console beside it authenticates against the 3CX administrator account set. The research record
identifies no secondary account class inside the Relay web interface that can reach `V1Controller`, so there
is no principal to justify a Low rating; assigning Low would describe a product tier that this evidence does
not show to exist.

A lower-privilege reading was considered and rejected. If a hypothetical non-administrative account could
reach the same controller, the vector would be `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High.
It is rejected because the premise is unproven: nothing in the reviewed artifacts describes a Relay web
account that is not an administrator, and the REST token is minted from a shared secret rather than from a
user identity. Assigning Low privileges would inflate the score by describing an account tier that this
evidence does not show to exist.

Arithmetic, rejected reading: ISS = 1 - (1-0.56)^3 = 0.914816, Impact = 6.42 x 0.914816 = 5.873119,
Exploitability = 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, sum 8.708374, rounded up to 8.8.

Arithmetic, published reading: ISS = 0.914816, Impact = 5.873119, Exploitability =
8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708, sum 7.107827, rounded up to 7.2.

## Affected Products

- VoIPTools Relay for 3CX, version 20.9.34 (assembly version 20.9.32.35089), Linux build
  (`RelayServicesHost`); affected component: the administrative helper `SetLinuxFolderPermissions` exposed
  as `GET /api/SetLinuxFolderPermissions/{json}` on the default Kestrel listener `https://0.0.0.0:8801`
- The defect is in the Relay service itself, not in 3CX: the vulnerable command construction, the shell
  helper, the JWT issuance path and the plaintext key storage all belong to the Relay distribution, which is
  installed alongside the PBX rather than shipped inside it
- Platform scope: Linux only. On Windows the helper returns `false` before any command is built
  (`ApiMethods.cs:3162`), so the same endpoint on a Windows Relay installation is not a command-injection
  vector; the Windows shell helpers in the licensing assembly (`cmd.exe /C`) were reviewed but are not on
  this path
- Version scope: 20.9.34 is the version analyzed end to end. Earlier or later builds were not obtained or
  tested, and no claim is made about whether the same construction is present in them; the fix guidance
  below applies to any build that still routes this helper through a shell
- Runtime precondition: the Relay process must be able to run the `sudo` prefix without an interactive
  password prompt, which is a deployment property of the host rather than of the product. In the
  verification deployment the service ran as root and the marker confirmed `uid=0(root)`; on a stock 3CX
  appliance the service account and its sudo policy were not measured in this research
- Not claimed: any 3CX PBX version, any other VoIPTools product or module, and any other Relay endpoint. The
  review covered the Relay 20.9.34 Linux build only, and the same shell helper is shared by other call
  sites that were not individually driven
- Verification method and its boundary: decompilation of the shipped .NET assembly plus end-to-end
  exploitation of the same compiled service, deployed on an isolated Linux sandbox with a stub
  `tcxpscom_native.so` replacing the 3CX native dependency and a research-supplied test `Jwt.PublicKey`.
  The exploit was driven over loopback against `https://127.0.0.1:18801`, the marker was confirmed through
  the service's own `FileExists` endpoint, and `uid=0(root) gid=0(root) groups=0(root)` was read back from
  the host. Root was observed inside that replication environment; no physical 3CX PBX was involved

## Impact

- Arbitrary command execution as root on the PBX host by a holder of a legitimate administrative position:
  the directory-permission helper becomes a general-purpose execution channel, and the attacker gains
  everything the host itself can do rather than anything the Relay was designed to expose
- Full read access to the Relay's own secrets at rest, including the plaintext `PublicKey` and `PrivateKey`
  in `appsettings.json` and `settings.txt`, so a single execution also yields durable token-minting
  capability that survives a password rotation on the PBX
- Access to the 3CX configuration and call-control material that the PBX host holds, because the Relay is
  co-resident with the PBX and runs with more authority than the PBX's own administrative interfaces grant
- Complete control of the Relay's behaviour: its REST responses, its SignalR event stream and its console
  can be altered, silenced or re-pointed, so downstream consumers of the integration receive attacker-chosen
  telephony events
- Availability impact at will, both coarse (service stop, host reboot) and surgical (the `chmod` and future
  commands can render directories unusable for the service accounts that depend on them)
- Persistence consistent with root on a Linux server: startup units, service definitions, scheduled jobs and
  additional accounts, up to the limits of the host's writable filesystem. What survives a rebuild or a
  reinstall of the Relay was not tested and is not claimed
- Blast radius beyond the Relay: the Relay is installed on the PBX host and forwards the PBX's Call
  Control API traffic and real-time events, so root on that host sits inside the PBX's own trust path -
  a telephony-facing position as well as a server compromise
- The chain is quiet in product terms: two ordinary authenticated HTTPS requests against endpoints the
  administrative interface already uses, with no crash, no malformed traffic and no log line that a Relay
  operator would recognize as anomalous

## Mitigation / Fix Recommendations

1. Stop constructing a shell command line for this operation. `chmod` and `chown` have direct managed and
   native equivalents - `File.SetUnixFileMode` on modern .NET, or `ProcessStartInfo.ArgumentList` with no
   shell in the path - and either removes the entire class of defect on this endpoint rather than filtering
   it
2. Validate `permissions` against a strict allowlist before any use: accept exactly `phonesystem`,
   `postgres`, or a mode matching `[0-7]{3,4}`, and reject everything else with a client error. The current
   null-or-whitespace test at `ApiMethods.cs:3172` is not a validation step
3. Validate `folderPath` positively as well: canonicalize it with `Path.GetFullPath`, require it to exist,
   and restrict it to the directory roots the helper is meant to serve, rather than relying on an existence
   check that only limits which paths can be named
4. Delete the dead escaping at `ApiMethods.cs:3177` or make it effective, and treat the current state as a
   correctness bug in its own right: a security-looking transform whose result is discarded is worse than
   no transform, because reviewers and future maintainers will assume the path is protected
5. Audit every other caller of `ShellHelper.Bash()` in the same assembly for the same pattern - the helper
   itself is a sharp edge, and any caller that interpolates a decoded request value into its argument
   inherits this vulnerability
6. Treat the JWT signing material as a secret management problem, not a configuration convenience: the
   `PublicKey`/`PrivateKey` pair is a shared symmetric secret in plaintext, it is distributed to every
   integration client, and it mints administrative tokens. Move to asymmetric signing or per-client
   credentials, and never store signing material in `appsettings.json` or `settings.txt`
7. Reduce the blast radius independently of the bug: run the Relay service under a dedicated unprivileged
   account with a narrowly scoped sudoers rule for exactly the `chmod`/`chown` operations the product needs,
   so that a future command-construction mistake does not land at uid 0
8. Add a regression test that submits a `permissions` value containing `;`, a backtick, `$(...)` and a
   newline, and asserts that no process is spawned and that the endpoint rejects the request; run it against
   every build that ships the helper
9. Until a patched build is available: restrict the Relay listener to the management network, rotate the
   `PublicKey`/`PrivateKey` pair if it may have been exposed, and review the host's `sudo` policy so that
   the service account cannot be used as a general privilege bridge

## References

- https://0day-rubbish.com/blog/setlinuxfolderpermissions-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- CWE-78, Improper Neutralization of Special Elements used in an OS Command: https://cwe.mitre.org/data/definitions/78.html
- Identifier: no CVE identifier has been assigned to this finding; none is claimed anywhere in this advisory
- Contact: disclosure@0day-rubbish.com
