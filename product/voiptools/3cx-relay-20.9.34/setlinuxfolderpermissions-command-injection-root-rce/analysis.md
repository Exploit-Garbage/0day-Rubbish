# VoIPTools Relay for 3CX 20.9.34 - SetLinuxFolderPermissions OS Command Injection Executing as Root

Advisory: https://0day-rubbish.com/blog/setlinuxfolderpermissions-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

VoIPTools Relay for 3CX is a .NET service that is installed on a 3CX PBX server and extends the PBX with
three interfaces hosted in a single self-hosted Kestrel web server: a REST API that forwards requests into
the 3CX Call Control API, a SignalR endpoint that streams real-time telephony events, and a Blazor
administrative console. Among the administrative helpers that the REST API exposes is
`SetLinuxFolderPermissions`, an operation whose purpose is narrow and unglamorous - give a directory to one
of two well-known service accounts (`phonesystem`, `postgres`) or set a numeric mode on it, because a Relay
deployment occasionally needs a folder to be readable or writable by the accounts the integration runs as.
It takes two base64-encoded values in one JSON document, decodes both server-side, and then asks the shell
to perform the change.

The defect is in the second of those two values. The Relay ships a shell helper,
`RelayServices.Utilities/ShellHelper.cs`, whose `Bash()` method executes its single string argument as
`/bin/bash -c "<cmd>"`. The call site at `ApiMethods.cs:3178` builds that string by interpolating the
decoded `permissions` value into a `sudo chmod` command line. The path operand is single-quoted; the mode
operand is not quoted, not parsed and not screened - the only check it passes is a null-or-whitespace test
at `ApiMethods.cs:3172`. A semicolon in `permissions` therefore ends the `chmod` command and begins another
one, and because the whole line runs under `sudo`, the second command inherits root authority on the PBX
host. No memory corruption, no authentication bypass and no transport weakness is involved: the entire
chain is one unvalidated string meeting one shell parser.

Two properties of the code around the sink are worth naming at the top, because they explain why the
injection is where it is. First, the companion path parameter is far better defended than the mode
parameter: it must satisfy `Directory.Exists` or `File.Exists` before the call site is reached
(`ApiMethods.cs:3177`), which rules out naming a path that does not already exist. Second, the module
contains a single-quote escaping step for that path at the same line, but the escaped value is assigned to a
local variable that the following line never reads - the escaping is dead code, and the raw value is
interpolated instead. The dead transform is not itself the vulnerability, but it is a strong signal: the
authors thought about quoting on one operand and left the other one entirely open.

### Overview of the product and the web stack

The analyzed distribution is Relay 20.9.34, Linux build, service executable `RelayServicesHost`, assembly
version 20.9.32.35089. The service is not embedded in the PBX: it is installed beside it, on the same host,
and it talks to the PBX through the 3CX Call Control API. That co-residency is what makes the landing
identity matter. The operation examined here shows that intent directly: it hands directories to
`phonesystem` or `postgres`, the two service accounts the product recognises, and it prefixes its command
line with `sudo`.

The Kestrel listener binds `https://0.0.0.0:8801` by default, and the deployment used for verification
served a self-signed certificate. Every interface the product advertises - REST, SignalR and the Blazor
console - is served from that one listener, which means the administrative surface of the integration is
reachable wherever the host is reachable on that port. Request parameters are frequently base64-encoded and packed
into a JSON document that travels in the URL path rather than in a body, a convention that shows up on many
of the administrative helpers including this one.

### Overview of the evidence and its boundary

The evidence has two halves, and they are kept separate throughout this document. The static half is a
decompilation of the shipped .NET assembly with `ilspycmd` 10.1.1, which produced 1004 `.cs` files; the
controller, the helper, the shell wrapper and the command construction in sections 3 through 8 are read from
that decompiled source. The dynamic half is exploitation of the vendor's own compiled service: the Linux
`RelayServicesHost` build of Relay 20.9.34 (assembly 20.9.32.35089) was deployed on an isolated Linux
sandbox as a self-contained Kestrel service, with one documented substitution - a stub `tcxpscom_native.so`
in place of the 3CX native library that a real PBX provides - and the exploit was driven end to end against
it over loopback. The marker produced by the injected command contained
`uid=0(root) gid=0(root) groups=0(root)`.

That boundary is stated once here and repeated where it matters: root was observed inside the replication
deployment, against the real vendor service binary, with the native PBX library stubbed out. No physical
3CX appliance was driven, and the service account and sudo policy of a stock appliance were not measured.
Section 9 separates what the replication establishes from what it does not.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | VoIPTools |
| Product | Relay for 3CX |
| Version analyzed | 20.9.34 (assembly version 20.9.32.35089) |
| Build analyzed | Linux, service executable `RelayServicesHost` |
| Web stack | self-hosted Kestrel, default listener `https://0.0.0.0:8801` |
| Interface | Relay REST API, JWT Bearer authentication (HS256) |
| Endpoint | `GET /api/SetLinuxFolderPermissions/{json}` |
| Parameters | `folderPath` and `permissions`, both base64 inside one JSON document |
| Vulnerable parameter | `permissions` (mode string, interpolated unquoted) |
| Shell wrapper | `RelayServices.Utilities/ShellHelper.cs` `Bash()` -> `/bin/bash -c "<cmd>"` |
| Call site | `ApiMethods.cs:3178`, command line `sudo chmod {permissions} '{folderPath}'` |
| Validation on the sink value | null-or-whitespace only, `ApiMethods.cs:3172` |
| Injection vector | `;` (statement separator inside `bash -c`) |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)`, in the replication deployment |
| Session gate | class-level `[Authorize]` on `V1Controller`, token from `POST /api/Authenticate` |
| Platform restriction | Linux only, Windows returns `false` at `ApiMethods.cs:3162` |
| CWE | CWE-78 |
| Published score | 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

The request arrives as a JSON document carried in the URL path. The controller parses it with
`JObject.Parse`, pulls `folderPath` and `permissions` out as dynamic members, and runs each through
`DecodeBase64UTF8`, which converts the base64 text back to a UTF-8 string. The decoded mode value then
travels as an ordinary `string` parameter through `ApiMethods.SetLinuxFolderPermissions` and into
`BashCmd`, which forwards it to `ShellHelper.Bash()` and finally to `/bin/bash -c`. At no point between the
base64 decode and the shell is the value compared against a set of legal modes, parsed as an octal number,
matched against a pattern, or escaped. The base64 step is often mistaken for a defense because it makes the
parameter look encoded on the wire; in this codebase it is purely a transport convention, and the decoded
text is what the shell receives.

The path operand is the opposite case. Before the call site runs, the code requires the path to exist, and
the command line quotes it. The existence requirement is a genuine constraint on what a caller can name,
and it is why the published payload uses `/tmp` - a directory that is guaranteed to exist on the host.
The quoting in the command line is undermined by the dead escaping described in section 6, but the
existence check survives it, so the practical injection vector on this endpoint is the mode string.

### Vulnerability Summary preconditions

Four preconditions, all of them ordinary for this deployment shape: the target must be a Linux Relay
installation, because the Windows branch returns `false` before a command is built; the caller must hold a
valid Relay session token, because the controller is `[Authorize]`-gated; the Relay must not be in free
mode, because that path returns `Unauthorized` early and the default is `false`; and the service must be
able to run its own `sudo` prefix, which is a property of the host's sudoers policy. In the replication
deployment all four held, and the marker confirmed `uid=0(root)`.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The Relay REST surface is protected at the controller level: `V1Controller` and `TablesController` both
carry a class-level `[Authorize]` attribute, and within the reviewed assembly the only members decorated
`[AllowAnonymous]` belong to `AuthorizationController` and number three. The token itself is an HS256 JWT
issued by `POST /api/Authenticate`. That endpoint does not authenticate a user in any meaningful sense: the
check inside `TokenHelpers.AuthenticateUser` is a comparison of the supplied `PublicKey` with the
configured `_mySettings.PublicKey`, and a match yields a signed token with no identity binding beyond the
claim set the service chooses to emit. Both halves of the signing material, `PublicKey` and `PrivateKey`,
are stored in plaintext in `appsettings.json` and `settings.txt`.

The web console beside the API is a different gate. It is a Blazor application whose session is established
against the 3CX administrator credential set, so the console's boundary is the PBX's own administrator
account. The finding in this advisory is reachable from both directions, but the REST direction is the one
that was driven during verification.

Authentication class for this advisory: Authenticated (target class B in the research classification) - an
authenticated administrator session in the Relay web interface, in the sense that the endpoint is reachable
only by a caller who has obtained a Relay session credential through the product's own authentication
mechanisms.

### Authentication Boundary - what the chain does not do

This is not an authentication bypass and it is not a default-credential finding. Nothing in this research
demonstrates that a shipped `PublicKey` is guessable, that a vendor default is common in the field, or that
the JWT signature can be forged. The token used during verification was a research-supplied test value
(`VULNTESTPUBLICKEY123`), installed in the service configuration for the duration of the test and not
observed in a vendor-shipped configuration. The only claim the evidence supports is the one that matters
for remediation: a caller who legitimately holds the administrative position can convert one directory
helper into arbitrary root command execution, and nothing in the product's design gives that caller a
lower-privileged alternative that would satisfy the same need.

### Authentication Boundary - why that boundary does not soften the impact

Three properties keep the gate from being a meaningful mitigation. The token is minted from a shared
symmetric secret rather than from an accountable identity, so nothing scopes that secret, or the tokens
minted from it, to the administration console alone. The secret is stored in plaintext next to the
service, so any read primitive on the host - including the one this advisory describes - converts into
durable token-minting capability that survives a password rotation on the PBX. And the endpoint's
legitimate purpose is exactly to change permissions on the directories the product's own service accounts
use, which means the operation is expected traffic on a healthy deployment and its abuse does not stand
out in a request log. The impact argument in section 10 rests on
those three properties, not on the difficulty of obtaining a token.

## 4. Attack Surface

### Attack Surface - the Relay HTTP plane

The Relay exposes its administrative helpers through a naming convention that mirrors the product's own
vocabulary: one route per helper, parameters packed into base64 inside a JSON document that rides in the
path segment. That convention has two practical consequences for a review. It makes every helper a
candidate with the same request shape, so enumeration is cheap; and it hides the decoded value from
anything that inspects URLs. The listener serves all of it from one Kestrel endpoint on
`https://0.0.0.0:8801` by default.

### Attack Surface - components that narrowed out

Several adjacent components were examined and excluded, and stating them keeps the finding honest.

- The Windows branch of the same helper returns `false` before any command is constructed
  (`ApiMethods.cs:3162`), so the equivalent endpoint on a Windows Relay installation is not a
  command-injection vector even though the request shape is identical.
- The licensing assembly's own shell helpers (`Bash()` and `DOS()` in `VoIPTools.Licensing/ShellHelper.cs`,
  the latter using `cmd.exe /C`) are not on this path; they were reviewed as part of the sink inventory and
  are mentioned here so that the inventory is not mistaken for a claim about this endpoint.
- `RelayServices.Utilities/SharedUtilities.cs:806` `RunCommand()` wraps `Process.Start`; it is a distinct
  execution mechanism from `Bash()` and was not the mechanism used by this call site.
- The SignalR hub and the Blazor console authenticate through the console session rather than the REST
  token; neither was driven during verification, and neither is claimed to be affected.
- `FileExists` is used in this research only as an authenticated read primitive to confirm the marker file
  exists; no vulnerability is claimed in it.

### Attack Surface - why the review settled here

The review started from the shell helpers, not from the controller surface: grepping the decompiled tree for
command execution produced the three helper families above, and then every call site that passed a
request-derived value into them was traced back to its handler. This call site is the one where a decoded
request parameter reaches `Bash()` with no validation whatsoever: the path operand is at least constrained
by an existence check, while the mode operand is concatenated directly. That asymmetry - one operand
screened, one not - is what made the endpoint worth driving.

## 5. Sink Identification

### Sink Identification - the three shell helpers

Three execution helpers exist in the decompiled tree. `RelayServices.Utilities/ShellHelper.cs` exposes
`Bash()`, which runs `/bin/bash -c "<cmd>"`. The licensing assembly's `ShellHelper.cs` exposes `Bash()` and
`DOS()`, the second of which runs `cmd.exe /C`. And `RelayServices.Utilities/SharedUtilities.cs:806`
exposes `RunCommand()`, which uses `Process.Start`. The sink for this finding is the first of them: a
`bash -c` wrapper whose argument is a single concatenated string, which means the shell parses the argument
a second time and any metacharacter in it is a control character rather than data.

### Sink Identification - the command construction

The call site at `ApiMethods.cs:3178` builds the command line with a three-way conditional, one branch per
supported target: the `phonesystem` account, the `postgres` account, and a numeric mode.

```csharp
empty = ((permissions == "phonesystem")
    ? _utils.BashCmd("sudo chown phonesystem:phonesystem '" + folderPath + "'")
    : ((!(permissions == "postgres"))
        ? _utils.BashCmd($"sudo chmod {permissions} '{folderPath}'")
        : _utils.BashCmd("sudo chown postgres:postgres '" + folderPath + "'")));
```

Two of the three branches quote the path and compare the mode against a literal, so they are safe as
written apart from the dead escaping discussed in section 6. The third branch - the one that handles every
mode that is not one of the two account names - interpolates the mode value directly into the command
string. This is the branch that a semicolon escapes from, and it is the branch that the recorded payload
exercises.

### Sink Identification - execution identity

The command line carries a `sudo` prefix, so the intended semantics are "the Relay service asks for root
authority for this one directory operation". Whatever runs after a semicolon inherits that authority,
because `sudo` applies to the command line it was given, and the shell splits that command line before
`sudo` ever sees it. In the replication deployment the marker read back as
`uid=0(root) gid=0(root) groups=0(root)`. The service in that deployment ran as root and the `sudo` prefix
therefore succeeded silently; on a stock 3CX appliance the service account and the sudoers policy were not
measured, and section 9 keeps that limitation explicit.

## 6. Source Identification

### Source Identification - the controller and its parameters

The source is the `SetLinuxFolderPermissions` action of `V1Controller`, at `V1Controller.cs:154`.

```csharp
[HttpGet("SetLinuxFolderPermissions/{json}", Name = "SetLinuxFolderPermissions")]
public ActionResult<bool> SetLinuxFolderPermissions(string json)
{
    if (_freeModeStateService.IsFreeMode) return Unauthorized(...);   // default false, does not block
    dynamic val = JObject.Parse(json);
    string encodedString = val.folderPath;
    encodedString = _apiMethods.DecodeBase64UTF8(encodedString);
    string encodedString2 = val.permissions;
    encodedString2 = _apiMethods.DecodeBase64UTF8(encodedString2);
    if (_apiMethods.SetLinuxFolderPermissions(encodedString, encodedString2)) flag = true;
}
```

Three properties of this action shape the exploit. The whole JSON document is a route parameter, so it must
be URL-encoded by the client before it is sent - the research record shows that omitting this step
produces a request that returns `false` and executes nothing. Both values are base64-decoded by the same
helper, so both must be valid base64 rather than plain text. And the free-mode gate in the first line does
not block anything by default: `IsFreeMode` is initialized `false` in `FreeModeStateService.cs:8`, and the
worker only sets it after a license failure has persisted for 72 hours, so an unlicensed or freshly
installed Relay still reaches the helper.

### Source Identification - the gates on the values

Inside `ApiMethods.SetLinuxFolderPermissions` the two values get very different treatment. The mode is
checked only for null or whitespace at `ApiMethods.cs:3172` - a guard against an empty parameter, not
against a dangerous one. The path is checked for existence at `ApiMethods.cs:3177`, which is a real
constraint: a caller cannot name a path that does not already exist on the host. Nothing parses the mode as
an octal number, nothing compares it against a pattern, and nothing rejects shell metacharacters.

### Source Identification - the dead escaping

The same line carries the module's only attempt at defensive quoting:

```csharp
string text = folderPath.Replace("'", "'\\''");
```

The result is assigned to `text`, and the very next line interpolates `folderPath` instead. The escaped
value is never read - it is dead code. Two conclusions follow. The escaping provides no protection and must
not be described as if it did. And the presence of the dead transform, next to an operand that received no
transform at all, tells a maintainer exactly where the reasoning went wrong: somebody knew the path could
contain a quote and stopped there, without asking what else could appear in either operand.

## 7. Data Flow

### Data Flow - end to end

The complete path from request to shell, in the order the bytes travel:

```
GET /api/SetLinuxFolderPermissions/{"folderPath":"<base64>","permissions":"<base64>"}
  -> [Authorize] class attribute on V1Controller -> JWT bearer validation
  -> SetLinuxFolderPermissions(string json) at V1Controller.cs:154
     -> JObject.Parse(json) -> dynamic member permissions
     -> DecodeBase64UTF8(permissions) -> decoded mode text
        -> ApiMethods.SetLinuxFolderPermissions(folderPath, permissions)
           -> platform check (Windows returns false here)
           -> whitespace check on permissions (ApiMethods.cs:3172)
           -> directory/file existence check on folderPath (ApiMethods.cs:3177)
              -> BashCmd($"sudo chmod {permissions} '{folderPath}'") at ApiMethods.cs:3178
                 -> ShellHelper.Bash() -> /bin/bash -c "sudo chmod <mode> '<path>'"
                    -> shell splits on ';' -> second command runs under sudo -> uid=0
```

### Data Flow - properties worth naming

The value crosses four layers - controller, helper method, `ApiMethods`, `ShellHelper` - and the only
transform applied anywhere on the path is a base64 decode. The parameter's type is `string` throughout, so
nothing in the call chain could constrain it even in principle; a mode string does not have a type that the
compiler can check, and no runtime validation stands in for the missing type. The decoded text is
interpolated into a composite format string at the call site, which is where the shell's second parse
becomes reachable. And the endpoint's return value is not a success signal: the call site assigns the
captured stdout into a variable named `empty`, and the recorded behaviour shows the endpoint answering
`false` whenever that output is non-empty, so a working injection reports `false` while the command still
ran. The recorded verification shows exactly that - HTTP 200 with a `false` body, and a marker file on
disk.

## 8. Exploit Construction

### Exploit Construction - request shape

The chain is two authenticated requests and one read-back. The first is `POST /api/Authenticate` with a
JSON body carrying `{"PublicKey": ...}`, answered with a token. The second is the injected request itself:
a `GET` whose path carries the URL-encoded JSON document, with `Authorization: Bearer <token>`. The
parameter pair is deliberately chosen - `folderPath` is set to `/tmp`, which exists, and `permissions`
carries the payload.

```python
payload = "777; id > /tmp/voiptools_relay_pwned.txt ; echo"
folder  = base64.b64encode(b"/tmp").decode()                      # L3RtcA==
mode    = base64.b64encode(payload.encode()).decode()
```

### Exploit Construction - payload engineering

The payload's first token, `777`, is a valid mode, so the `chmod` that the shell executes first is a
well-formed command rather than a syntax error that would abort the shell before the injected part runs.
The semicolon then ends that command, and `id > /tmp/voiptools_relay_pwned.txt` becomes a second command
in the same `bash -c` invocation. The trailing `; echo` closes the command list, and it also explains the
captured output: the endpoint reports `false` when the command's stdout is non-empty, and the recorded
response body is `false`, consistent with the endpoint's own success test rather than with a failure of the
injection.

The resulting command line, as the shell receives it, is:

```
sudo chmod 777; id > /tmp/voiptools_relay_pwned.txt ; echo '/tmp'
```

The base64 values that appear in the research record decode as follows, and the verification transcript in
section 9 uses exactly these strings:

- `L3RtcA==` decodes to `/tmp`, the `folderPath` value
- `Nzc3OyBpZCA+IC90bXAvdm9pcHRvb2xzX3JlbGF5X3B3bmVkLnR4dCA7IGVjaG8=` decodes to the mode payload above
- `L3RtcC92b2lwdG9vbHNfcmVsYXlfcHduZWQudHh0` decodes to `/tmp/voiptools_relay_pwned.txt`, the marker path

### Exploit Construction - what the PoC deliberately does not do

The published PoC writes one file and stops. Its default action is `id > /tmp/voiptools_relay_pwned.txt`,
it confirms the result through the service's own authenticated `FileExists` endpoint rather than by
assuming, and it performs no second-stage action, no persistence step, no file deletion and no change to
the Relay's configuration. The `--command` argument exists because a reader may want to run a different
benign diagnostic, and the documentation states that the marker check only applies to the default payload.
Nothing in the tool attempts to guess the `PublicKey`, to forge a token, or to enumerate the host; the
session credential is an input to the tool, which is the correct shape for an authenticated finding.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

The target was the vendor's own Linux build of Relay 20.9.34 (`RelayServicesHost`, assembly version
20.9.32.35089), deployed as a self-contained service on an isolated Linux sandbox host and reached over
loopback at `https://127.0.0.1:18801` with a self-signed TLS certificate. One substitution was necessary:
a stub `tcxpscom_native.so` stood in for the 3CX native library that a real PBX installation provides,
because the service will not start on a host with no PBX underneath it. The stub is not involved in the
vulnerable path - the injection happens in the Relay's own C# code and in `/bin/bash`, both of which were
the genuine vendor artifacts. The JWT signing key was a research-supplied test value
(`Jwt.PublicKey=VULNTESTPUBLICKEY123`), set in the service configuration for the test.

### Dynamic Verification - transcript and results

The three requests below are the recorded interaction, reproduced with the base64 values from section 8.

```
POST /api/Authenticate
  {"PublicKey":"VULNTESTPUBLICKEY123"}
  -> 200 {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}

GET /api/SetLinuxFolderPermissions/{"folderPath":"L3RtcA==","permissions":"Nzc3OyBpZCA+IC90bXAvdm9pcHRvb2xzX3JlbGF5X3B3bmVkLnR4dCA7IGVjaG8="}
  Authorization: Bearer <token>
  -> 200 false        (non-empty command stdout; the endpoint's expected answer)

GET /api/FileExists/{"filePath":"L3RtcC92b2lwdG9vbHNfcmVsYXlfcHduZWQudHh0"}
  Authorization: Bearer <token>
  -> 200 true
```

The marker was then read on the host:

```bash
$ cat /tmp/voiptools_relay_pwned.txt
uid=0(root) gid=0(root) groups=0(root)
```

### Dynamic Verification - negatives and iteration

Two negative results from the same session are part of the evidence. The first injection attempt used a
`curl` command line that did not URL-encode the JSON document in the path; the endpoint returned `false`
and no marker file was created. The cause was the missing encoding, not a mitigation in the product, and
the retry with `urllib.parse.quote` succeeded - which is why the published PoC percent-encodes the payload.
Separately, an initial signing key of 168 bits produced a `IDX10720` error from the JWT implementation,
because HS256 requires at least 256 bits of key material; a 64-character key then signed normally. Neither
result is a security property of the product, and both are recorded so that a reader reproducing this work
does not mistake them for one.

### Dynamic Verification - the boundary of the claim

The claim this advisory publishes is: the vendor's compiled Relay 20.9.34 service, running on an isolated
Linux host with a stubbed 3CX native library, executes an arbitrary command with `uid=0(root)` when an
authenticated caller supplies the recorded `permissions` payload. Root was observed inside that replication
environment. Not claimed: that a stock 3CX appliance runs the Relay service as root, that a stock sudoers
policy permits the prefix without a prompt, that the endpoint behaves identically on the appliance's own
network stack, or that any other Relay endpoint is exploitable. The static evidence in sections 5 through 7
is what makes the finding general; the dynamic evidence in this section is what makes the executed command
and the landing identity concrete.

## 10. Reachability and Security Impact

### Reachability - network position and gating

The listener binds all interfaces on port 8801 by default and carries the whole administrative surface, so
reachability reduces to reachability of the host on that port. The remaining gate is the token, which is
minted from a shared secret rather than from an accountable user, and the free-mode gate, which does not
block by default: `IsFreeMode` starts `false` at `FreeModeStateService.cs:8` and is only raised after a
license failure has persisted for 72 hours. An installation that has not yet accumulated 72 hours of
license failure therefore still exposes the helper. The Windows platform check at `ApiMethods.cs:3162` is the one hard blocker in the
chain, and it confines the finding to Linux deployments.

### Reachability - impact in concrete terms

- Root command execution on the PBX host from an administrative interface that was designed to change
  directory ownership: the interface's entire authority becomes the attacker's, and the operation needed no
  exploit primitive beyond a semicolon
- Immediate access to the Relay's own plaintext secrets, including the `PublicKey` and `PrivateKey` held in
  `appsettings.json` and `settings.txt`, which yields durable token-minting capability independent of any
  PBX password rotation
- A telephony-facing position rather than a mere server compromise: the Relay is installed on the 3CX PBX
  host and carries the PBX's Call Control API traffic and event stream, so root on that host reaches the
  data the integration moves between the PBX and its consumers
- Control of the integration's output: REST responses, SignalR events and console behaviour can be
  altered, so every downstream consumer receives attacker-chosen telephony data
- Availability impact at will, from stopping the service to rendering the directories it depends on
  unusable through the very operation the endpoint performs
- Persistence consistent with root on a Linux server - service definitions, startup units and scheduled
  jobs - up to the limits of the writable filesystem; survival of a rebuild or a Relay reinstall was not
  tested and is not claimed
- A quiet chain: two ordinary authenticated HTTPS requests against endpoints the product's own
  administration already uses, with no crash and no traffic pattern an operator would flag

## 11. Fix Recommendations

### Fix Recommendations - remove the shell, then constrain the values

1. Replace the `bash -c` invocation for this operation with a direct call: `File.SetUnixFileMode` for the
   numeric mode case, or `ProcessStartInfo.ArgumentList` with `/bin/chown` and `/bin/chmod` for the
   ownership cases. An argument list is not reparsed by a shell, so metacharacters in any operand become
   data and the class of defect disappears rather than being filtered.
2. Validate `permissions` against an explicit allowlist before any use: exactly `phonesystem`, exactly
   `postgres`, or a string matching `[0-7]{3,4}`. This is a two-line change and it closes the injected
   branch completely. The whitespace test at `ApiMethods.cs:3172` is not a substitute.
3. Constrain `folderPath` positively: canonicalize it with `Path.GetFullPath`, keep the existence check,
   and additionally require it to resolve under a configured set of Relay working directories. Existence
   alone limits naming, not authority.
4. Remove the dead escaping at `ApiMethods.cs:3177` or make it effective. Leaving a discarded
   security-looking transform in place is a correctness defect in its own right.
5. Audit every other caller of `ShellHelper.Bash()` in the same assembly with the same question - does a
   decoded request value reach the argument? The helper is a sharp edge, and the fix at one call site does
   not fix the helper.
6. Replace the symmetric shared-secret JWT with per-client credentials or asymmetric signing, and move the
   signing material out of `appsettings.json` and `settings.txt` into the platform's protected secret store.
   A token-minting secret that ships in plaintext next to the service is a standing second vulnerability.
7. Run the Relay service as a dedicated unprivileged account with a narrowly scoped sudoers entry for the
   exact `chmod` and `chown` operations the product performs, so that any future command-construction
   mistake lands with the least authority the deployment can tolerate.
8. Add a regression test that submits `permissions` values containing `;`, a backtick, `$(...)` and a
   newline, asserts that the endpoint rejects them, and asserts that no child process is spawned. Run it
   for every build that ships the helper.

The shape of the fix, in outline:

```csharp
if (!Regex.IsMatch(permissions, @"^(?:[0-7]{3,4}|phonesystem|postgres)$"))
    return false;
if (!Directory.Exists(folderPath) && !File.Exists(folderPath))
    return false;
var startInfo = new ProcessStartInfo("/bin/chmod") { UseShellExecute = false };
startInfo.ArgumentList.Add(permissions);
startInfo.ArgumentList.Add(Path.GetFullPath(folderPath));
```

## 12. CWE

### CWE - classification rationale

The finding is classified CWE-78, Improper Neutralization of Special Elements used in an OS Command. The
classification rests on the construction in `ApiMethods.cs:3178`, not on the absence of validation: the
product builds a command string from a request value and hands it to `/bin/bash -c`, so the shell parses
attacker-influenced text as syntax. A semicolon is a statement separator in that grammar, which is exactly
the neutralization failure the class describes.

Two neighbouring classifications were considered and not published as separate mappings. The missing
validation on `permissions` - a null-or-whitespace test where an allowlist belongs - is the enabling
condition, and it is of the improper-input-validation family; but the defect that produces the impact is
the shell construction, and reporting the validation gap as the primary class would point remediation at
the filter rather than at the shell. Argument injection was also considered, and rejected for the same
reason: the operand here is not merely a value that a program reinterprets, it is text parsed by a shell
with statement separators available. CWE-78 is the classification that names the fix - remove the shell, or
make the argument a data value - and it is the one this advisory publishes.

## References

- https://0day-rubbish.com/blog/setlinuxfolderpermissions-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- CWE-78, Improper Neutralization of Special Elements used in an OS Command: https://cwe.mitre.org/data/definitions/78.html
- Contact: disclosure@0day-rubbish.com
