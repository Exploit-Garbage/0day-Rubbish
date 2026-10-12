# Titan MFT Server 26.0.0 — First-Run Administrator Setup Window Chained to Job Post-Command Injection (LocalSystem RCE)

## 1. Overview

### Overview of the finding

Two independent defects in Titan MFT Server compose into an unauthenticated path from the network to `nt authority\system` on the Windows host. Neither one is interesting on its own at this severity, and this section is written so that the composition — not either half — is what the reader takes away.

The first defect is a state-conditioned missing authentication. A default installation of this product contains no administrator accounts: the user table of the administration database (`nxUserParams` inside `mftlasdb.db`) holds zero rows. In exactly that state, the WebAdmin application — a Blazor Server single-page application — renders an "Initial Admin User Setup" screen on `/Login` to any client that can reach the listener, and submitting that screen creates the first administrator and issues a console session in the same round trip. There is no bootstrap ticket, no CAPTCHA, no first-boot token, no localhost restriction and no IP restriction to satisfy, and the EULA acknowledgement checkbox does not block submission. The single predicate standing between an anonymous client and a new administrator account is a row count.

The second defect is an unsanitised command field. Every job in this product has a post-transfer custom process. The text an administrator types into it is persisted verbatim into the job document (`nxJobs.document.PostCommandText`) and, when the job runs, is handed to `MxUtilSvrJobHandler.RunCustomProcessAsync`, which splits it on the first space — or, when it starts with `cmd`, reconstitutes it as `cmd.exe /c <remainder>` — and starts it with a `ProcessStartInfo` whose `Arguments` is a plain string and whose `UseShellExecute` is `false`. There is no allow-list of executables, no argument-vector construction, no metacharacter rejection and no quoting. The transfer engine runs inside the service process, and the service process runs as LocalSystem, so the child process inherits LocalSystem.

Chained: an anonymous client creates an administrator, uses that administrator's own console session to create a job whose post-command is `cmd /c whoami > <marker>`, runs the job through the product's documented Run Job action, and the marker file is written by `nt authority\system`. That is exactly what we observed, and the marker content is the artifact that carries the identity claim.

Each half alone is materially less severe. A first-run setup screen that can only create the account the operator was going to create anyway is an exposure window and an account-takeover risk, but on its own it yields an administrator console, not code execution on the host. A post-command field writable only by a full administrator is a documented product feature — the vendor intends administrators to run scripts after transfers — and the honest framing of that field in isolation is "an administrator can execute code as the service account", which is a privilege-separation weakness rather than a remote code execution. It is precisely the fact that the administrator identity itself can be manufactured without credentials that turns a configuration feature into an unauthenticated SYSTEM shell, and it is also why the fix has to address the window and not only the command field.

One framing constraint governs the whole advisory and is repeated wherever it could be missed: **this is a first-run window, not a permanent unauthenticated condition.** The window opens when installation completes and the service becomes reachable, and it closes the moment the first administrator account exists. After that, `/Login` renders a credential form instead of the setup screen, and this chain's first half has no route at all. This product does authenticate; a configured deployment is not exposed to the account-creation half. Sections 9 and 10 give operators a concrete way to determine whether a given installation is inside the window, including the trap that a plain HTTP fetch of `/Login` cannot answer the question.

### Overview of the product and its runtime stack

Titan MFT Server is a commercial managed file transfer server from South River Technologies, a closed-source vendor based in Annapolis, Maryland, United States, whose product family also includes Titan FTP Server and the WebDrive client. An MFT server is a two-headed thing: a web administration plane in which operators configure domains, connectors, users and scheduled jobs, and a transfer engine that actually moves partner files according to those jobs. The compromise of such a host is categorically different from the compromise of a web application, because the administration plane is where an organisation's trading-partner credentials live.

The version verified here is 26.0.0.364, which self-reports as "Web Version 26.0.364" and belongs to the NextGen generation of the product. The same root cause was reproduced on 26.0.0.348, the immediately previous generation build, whose installer artifact is 312,248,120 bytes. The runtime stack, which matters for both the attack surface and the fix recommendations, is:

| Layer | Component as observed |
|---|---|
| Runtime | .NET 8, ASP.NET Core |
| Administration UI | Blazor Server with an in-process circuit; DevExpress `dxbl-*` component tree |
| Persistence | EF Core over SQLite in WAL mode |
| Databases | `mftlasdb.db` (administration: `nxUserParams`, `nxMembership`), `mftdb<domain-guid>.db` (domain: `nxJobs`, `NxDbJobHistory`), and a matching `-Quartz.db` scheduler database |
| Process model | One process, `titanmft.exe`, registered as the Windows service `SrtTitanMFTServerService`, running as LocalSystem over Kestrel |
| Listener | WebAdmin RAS on `0.0.0.0:47443` with TLS and a self-signed certificate; configuration carries `TlsRasHost{Enabled:1, Host:0.0.0.0, Port:47443}` and `IpAccess Enabled:0` |
| Management CLI | `nxcli`, a .NET 9 NativeAOT binary of roughly 92 MB, with a string-level localhost restriction on its administrative user parameter |
| Installer | BitRock package supporting unattended installation (`--mode unattended --prefix ...`); the artifact we used is 384,912,064 bytes |
| Legacy shim | `Srt.NextGen.LegacyApi.dll`, NativeAOT with no managed metadata; its string surface exposes `CreateProcessAsUserW` and `CreateProcessW` imports |

Two properties of this stack drive the analysis. First, the administration plane and the transfer engine are the same process with the same token, so there is no privilege boundary between them to cross — code execution "in the engine" is code execution "as LocalSystem". Second, Blazor Server means the UI logic executes on the server inside the circuit; the browser is a rendering and input surface, not a trust boundary. That is why the setup screen's server-side handler ran for our unauthenticated client without any client-side gate needing to be defeated: there was no client-side gate to defeat, and the server-side predicate was a row count.

For static analysis we extracted the BitRock package and decompiled `Srt.NextGen.ServerCore.dll` in full with `ilspycmd`, yielding 1,880 source files. String literals in `titanmft`/`ServerCore` are protected by ConfuserEx encryption, so recovering literal values is an obstacle; route structure, class layout and database access are nevertheless fully readable, which is what this analysis needed. `LegacyApi.dll` is NativeAOT and carries no managed metadata at all, so it was examined through its string surface.

### Overview of the testbed and of what that implies

The verification environment was a Windows host in our lab carrying a fresh default installation of 26.0.0.364, installed by the BitRock unattended package and left unconfigured, with the service registered as `SrtTitanMFTServerService` under LocalSystem. Four properties of that testbed must be stated plainly because they bound every claim in sections 9 and 10.

The first is that the single-pass replay **deliberately re-opened the first-run window**. An earlier verification pass had already completed first-time setup on this host, which creates an administrator and closes the window permanently for that installation. To exercise the whole chain in one scripted pass, our tooling stopped the service, deleted the administrator rows from the administration database and cleared the stale job and job-history rows, then restarted the service and confirmed that the user table held zero rows again before proceeding. So the exposed state we attacked was reproduced by an authorised local database reset on a machine we own, not observed on a factory-fresh machine at that exact moment. What survives that caveat is the state equivalence: the product derives the setup screen purely from `AdminUserExists()`, and a zero-row user table is the state a completed installation is left in. What does not survive is any claim about a specific live production installation's configuration, patch level or network placement.

The second is the network vantage point. Our HTTP probes and our browser ran against `https://127.0.0.1:47443` on the target host itself, and we added inbound firewall rules blocking remote access to ports 47443 and 37443 for the duration of the run (Windows Firewall exempts loopback traffic, so the rules isolated the host from remote clients without breaking the test). They were removed afterwards and the service was left stopped. Remote reachability from an untrusted network is therefore **argued from the shipped binding** (`0.0.0.0:47443`) **and the shipped IP-restriction state** (`IpAccess Enabled:0`), not measured from an external vantage point.

The third is the client. We drove the Blazor circuit through a headless Chromium-family browser over the DevTools protocol, using a raw-socket WebSocket client built from the Python standard library. We did not reimplement the Blazor `blazorpack` (MessagePack) circuit framing. That choice is conservative rather than clever: the setup screen's presence is only observable after the circuit boots and the component tree renders, so the authoritative check is a real client, and using one also means every step of the chain went through the product's own UI path rather than through a synthetic API call or a direct database write.

The fourth is payload discipline. The command we injected writes the output of `whoami` to a marker file. Nothing destructive, nothing persistent, nothing that leaves the host, and the marker's content is the identity evidence. The published proof of concept keeps that discipline, adds an explicit authorisation flag before any state-changing mode, defaults to a read-only window probe, and refuses to claim success when the marker cannot be read.

### Overview of affected scope

Two builds were involved and they are not supported by equally strong evidence:

- **Titan MFT Server 26.0.0.364** — verified end to end. The full chain, including the injection tail and the LocalSystem execution, was executed on this build, together with a negative control leg and a counter-gate leg in the same pass.
- **Titan MFT Server 26.0.0.348** — verified for the first-run half. We dynamically confirmed on the previous generation build that the setup screen is reachable with no preconditions and that the legacy `/WebApi` binding failure shape is identical. We did **not** separately replay the injection tail on that build. Its inclusion rests on the two builds sharing the same code base and the same surface shape, which is a structural argument rather than a measurement.

Beyond those two, the affected population is defined by state rather than by build: any installation of this generation that is inside the first-run window — that is, any installation that has been installed and made reachable but has not yet had its first administrator created. We did not obtain or test samples of Titan FTP Server, WebDrive, or the older 2.x generation, and we claim nothing about them. The installation method does not change the analysis: the window is a property of the shipped state, not of how the software was installed.

There is one variant we can name from static reading but cannot verify, because we never obtained a sample. The window predicate at `MxSvrParams.cs:518-520` suppresses the network wizard in favour of a console creation path when the product believes it is in a cloud environment:

```csharp
CreateAdminAtConsole = !nxUserParams.AdminUserExists()
                       && SrxRegCodeInfo.IsCloudEnvironment()
                       && (NxGlobals.IsLinux | flag);
RunWizard            = !nxUserParams.AdminUserExists() && !CreateAdminAtConsole;
```

with `flag` being whether the request arrived on the RAS port. On a normal on-premises deployment the cloud term is false, so `RunWizard` collapses to `!AdminUserExists()` and the window is unconditional. On a cloud deployment the console path is meant to take over. Our notes record that the legacy `CreateAdmin` route itself does not consult the cloud predicate, so whether a cloud-shaped installation is genuinely protected depends on facts we did not sample. We treat cloud deployments as unestablished rather than as either affected or exempt.

### Overview of independence

This is not a re-published public issue, and we can support that with three distinct kinds of evidence rather than one.

Public history for this vendor, as enumerated in our preparation notes, consists of nine older-generation identifiers plus one further installation-period issue, all of them post-authentication or installation-time vectors: the 45685–45690 series (archive-extraction path traversal, WebDAV write-through, session fixation on the vendor session cookie, an FTP `SIZE` format-string issue, a file-action handler issue and a hash-related issue), an SMTP relay issue numbered 44685, two authorisation issues numbered 27744 and 27745, and `CVE-2022-34006`, which concerns the bundled SQLExpress instance being installed as SYSTEM during setup. The nine are the series plus 44685, 27744 and 27745; the installation-period identifier is listed alongside them. We cite those numbers as they appear in our notes, which record the last five digits without confirming every year prefix; the load-bearing point does not depend on the prefixes. None of them describes an unauthenticated first-run window, and all of them belong to the superseded 2.x generation rather than to the .NET 8 NextGen rewrite examined here. A widely circulated attribution of `CVE-2019-13358` to this vendor was checked and disproved during preparation: that identifier belongs to an unrelated application's XML external entity issue.

The fingerprint search is the second kind of support. We case-insensitively grepped five root-cause fingerprints — `PostCommandText`, `CreateAdmin`, `first-run wizard`/`Initial Admin User`, `RunCustomProcess`, and `South River`/`Titan (MFT|FTP|SFTP)` — across the 208 product directories in our own prior-research corpus. Every fingerprint returned zero hits. There was no MFT-genre entry in that corpus at all at the time: no MOVEit, GoAnywhere, Cleo, Geneva or Axway material. The same search is what lets us state positively that this finding is not a duplicate of our own earlier work, which is the failure mode fingerprint searching exists to catch.

The third kind is the absence of prior exploitation. No public exploit or write-up covering this product's first-run setup screen or a job post-command field was found during preparation. We state that as an observation about what we found, not as proof of absence worldwide — it is entirely possible that a customer-side assessment touched this surface and never published. The honest summary is: no prior public issue in this product family matches the root cause, no entry in our own corpus shares it, and the closest prior art in this vendor's history is a set of post-authentication defects in a superseded code base.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Field | Value |
|---|---|
| Product | Titan MFT Server (managed file transfer server) |
| Vendor | South River Technologies, Annapolis, Maryland, United States |
| Version verified | 26.0.0.364 (NextGen generation); same root cause reproduced on 26.0.0.348 |
| Vulnerable components | WebAdmin Blazor Server administration application, `/Login` first-run setup screen; and the transfer engine's job post-command handler in `Srt.NextGen.ServerCore` |
| Vulnerability class | CWE-306 Missing Authentication for Critical Function, chained to CWE-78 OS Command Injection |
| Sink | `MxUtilSvrJobHandler.RunCustomProcessAsync` at `MxUtilSvrJobHandler.cs:991` (a second pass over the same decompilation records the routine at `:996`), reached from the predicate at `:970` by way of the call site at `:979-982` |
| Source | The setup form on `/Login` (unauthenticated, over the Blazor circuit) and the job editor field `Execute After File Transfer Task` (authenticated by the account the first source creates) |
| Sanitisation | None on the command field: first-space split, or a `cmd`-prefix special case that concatenates `"/c " + command.Substring(3).Trim()` |
| Execution identity | `nt authority\system` (child of the LocalSystem service process) |
| Privileges required to start the chain | None, while the target is inside the first-run window |
| Preconditions | Target inside the first-run window; TCP reachability to the WebAdmin listener; a job that can run (connectors present, scheduling not disabled) |
| Primary rating | 8.1 High, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Conditional reading | 9.8 Critical, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, applicable only to a target confirmed inside the window |
| Identifier | None assigned at the time of writing |

### Vulnerability Summary mechanics

The chain has four mechanical steps, each with an observable artifact rather than an inference.

Step one is the window itself, and it is defined by one expression. At `MxSvrParams.cs:518-520` the product computes `RunWizard = !nxUserParams.AdminUserExists() && !CreateAdminAtConsole`. On a normal deployment the second term is false, so the setup screen is shown whenever the user table is empty. That is the whole gate: a row count over `nxUserParams`. Our measurement of the obfuscating factors around it — EULA acknowledgement, a ticket query parameter, a CAPTCHA element, a first-boot token, an IP restriction — found every one of them absent, and the setup screen submitted successfully with the EULA checkbox untouched.

Step two is account creation through the product's live path. The legacy HTTP route that looks like the obvious target, `WebApiController.CreateAdmin` at `WebApiController.cs:674-690`, is reachable in the first-run state and gated only by the same `AdminUserExists()` predicate, but it is functionally broken: the JSON binding layer throws a `NullReferenceException` on any request carrying values, so it cannot be used to create an account. The same `CreateAdminUser` semantics are alive in the Blazor circuit, where `Login.razor`'s `OnDoLogin` handler takes a `RunWizard && IsAdmin` branch that calls `AppState.CreateAdminUser(ar)` and then `AppState.Login(ar)` and navigates to `SvrHome`. That is the path our tooling drives. The forensic artifact is the user table going from zero rows to three (discriminators `Ident`, `General`, `Name`, with `Name` holding the created administrator) and the browser URL landing on `/SvrHome/<guid>/<guid>` without any credential having been presented.

Step three is persisting the payload. A job is created from the Jobs toolbar, and the editor reached through the row's Actions menu exposes a collapsible `Post-Task Processes` group containing the field labelled `Execute After File Transfer Task`. Writing that field — through `input`, `change` and `blur` events, which is what the DevX components require to publish a value to the server circuit — stores it into `nxJobs.document.PostCommandText`. Two further checkboxes matter: `Execute custom post-process on file transfer task failure` maps to `ExecuteCustomPostProcessOnFileTransferTaskFailure`, and `Do Not Run` maps to `IsScheduleDisabled`, which must be false for the job to be runnable at all.

Step four is execution. Running the job drives the transfer pipeline; on completion the handler evaluates the predicate at `MxUtilSvrJobHandler.cs:970` and, if it is satisfied, logs the command and calls the custom-process routine:

```csharp
private bool G6kGVrDTVV(ApiResult P_0)
{
    if (P_0.IsSuccess() || Job.ExecuteCustomPostProcessOnFileTransferTaskFailure)
    {
        return !string.IsNullOrWhiteSpace(Job.PostCommandText);
    }
    return false;
}
```

```csharp
LogMsg("Post Command: " + Job.PostCommandText);
try { RunCustomProcessAsync(Job.PostCommandText, Job.PostWorkingDir, Job.PostTimeout).Wait(); }
```

The routine then either special-cases a `cmd` prefix into `cmd.exe` plus `"/c " + command.Substring(3).Trim()`, or splits the string on the first space into a file name and an argument string, and starts the result inside the service process. The marker file we recovered contained `nt authority\system`, which is the execution identity claim and nothing more than that.

### Vulnerability Summary preconditions

- The target must be inside the first-run window: zero rows in the administration database's user table. This is the shipped state of a completed installation, and it persists until somebody creates the first administrator.
- The WebAdmin listener must be reachable from the attacker. It binds `0.0.0.0:47443` and the product's own IP-restriction feature was disabled in the configuration we examined.
- The attacker must be able to run a browser-equivalent client against the listener, because the setup screen and the console are Blazor Server surfaces rendered client-side after circuit boot. A plain HTTP client can probe but cannot drive the chain.
- For the execution half, the job must be runnable: source and destination connectors selected (the editor's own client-side validation refuses to proceed with a missing connector, and is satisfied trivially by the built-in local filesystem connector) and scheduling not disabled.
- Nothing else is required: no credentials, no secrets, no parsing gadget, no memory corruption, and no interaction from a legitimate user.

## 3. Authentication Boundary

### Authentication Boundary — how sessions are issued

This product has three concurrent authentication surfaces, and conflating them is the easiest way to misjudge the finding.

The Blazor Server plane is the live one. `/Login` hosts a component tree; `Login.razor`'s `OnDoLogin` calls `AppState.Login(ar, "", ipData)` server-side, in process, over the circuit. The session is bound to the circuit for the connection's lifetime. Credentials are validated against `nxUserParams` — an `Ident` row whose document carries `PasswordHash` and digest fields. In the first-run state the same handler takes the wizard branch and calls `AppState.CreateAdminUser(ar)` first, then logs the new account in. There is no separate authentication channel for the setup screen: creating the account and authenticating as it are one server-side call sequence.

The legacy `/WebApi/*` plane is a JSON Model/Action batch protocol identified by an `SRTSessionId` GUID cookie. Credentials arrive as `user`/`pass` fields optionally transformed by `NxDecryptAPI`, an AES-ECB construction with a static key at `StringExtensions.cs:1008` that returns the value unchanged when the encryption prefix is absent — so plaintext is always accepted, and this construction is transport obfuscation rather than a security control. Requests without a session are refused by `NxWebApiModelAccess.IsModelAndActionAllowed` under a deny-by-default model-and-role matrix; the only pre-authorised family we found is the `ServerParams` read family, whose response includes the window-running flag and the server name. That leak is reported separately and is not part of this chain.

The REST `/api/*` plane is gated by `RESTEnableAdminApi`, which has no row in the database by default and therefore evaluates false, so the controller constructor throws `NotImplementedException` and the surface answers 500.

Sessions in all three planes are server-generated GUIDs or tokens. We found no offline-forgeable ticket, no predictable session primitive, no default or backdoor credential, and no rows of any kind in the user table on a fresh installation. The session-fixation issue published against the older generation's session cookie belongs to the superseded 2.x code base and does not apply here.

### Authentication Boundary — what the gate actually checks

There are two gates in this system and they guard different things with very different rigour.

The message-level gate is real and it works. An unauthenticated `POST /WebApi/Process` during our verification returned **401 with an empty body**, on both builds, and REST returned 500. Model-level access is deny-by-default with a role matrix (`ROLE_USERADMIN`, `GROUPADMIN`, `SERVERADMIN`), and the model/action pairs that would let an unauthenticated caller drive server behaviour are not pre-authorised. This is a properly closed boundary and it deserves to be stated, because it is what makes the counter-gate measurement in section 9 meaningful.

The initial-administrator gate is a row count. `WebApiController.CreateAdmin` shows the structure in its clearest form:

```csharp
[HttpPost] [Route("WebApi/CreateAdmin")]
public IActionResult CreateAdmin([FromBody] LoginInfo li)
{
    NxUserParams nxUserParams = ...AuthenticationServices.CreateUserParams();
    if (!nxUserParams.AdminUserExists())
    {
        NxResult<NxUserParamsPoco> nxResult =
            nxUserParams.CreateAdminUser(li.user.NxDecryptAPI(), li.pass.NxDecryptAPI());
    }
}
```

`AdminUserExists()` is the only condition. There is no attribute-level authorisation anywhere in the server assembly to fall back on either: we counted zero `[Authorize]` attributes across the 1,880 decompiled files of `ServerCore`, which means every authorisation decision in this product lives in application logic and, for the setup screen, that logic is the row count.

The obfuscating factors one might expect around a first-run screen were each checked individually and each was absent:

| Expected control | Observed |
|---|---|
| EULA acknowledgement required before submit | Checkbox present but non-blocking: submit succeeds with it untouched |
| One-shot bootstrap ticket or query token | Absent; no ticket parameter is consulted |
| CAPTCHA or proof-of-work | Absent; no such element exists on the page |
| First-boot token printed by the installer or written to a host-local file | Absent from the path we drove |
| Localhost or installer-console restriction | Absent on the RAS listener; the console creation path is only selected for cloud-shaped deployments |
| IP access restriction | `IpAccess Enabled:0`, and the listener is bound to `0.0.0.0` |

So the answer to "what does the gate check" is: it checks whether the installation has finished first-time setup, and nothing whatsoever about who is asking.

### Authentication Boundary — the principal required by the sink

The sink runs in the service process. `RunCustomProcessAsync` builds a `ProcessStartInfo` with `UseShellExecute = false` and starts it; a false shell-execute means the child is created with the parent's token unless the code explicitly impersonates, and this code does not impersonate. The parent is `titanmft.exe` under `SrtTitanMFTServerService`, configured as LocalSystem. The artifact confirming that chain is the marker content, `nt authority\system`, which is the output of `whoami` running as the child. The code-level statement that no impersonation happens is a reading of the decompiled construction; the identity itself is measured.

Writing the field requires an administrative console session over the Jobs page. Our role enumeration found `ROLE_USERADMIN`, `GROUPADMIN` and `SERVERADMIN` in the legacy access matrix, and the chain used a full administrator created through the setup screen. We therefore claim `PR:N` for the **chain start** — the setup screen needs nothing — and we do **not** claim that the sink is reachable by any lower-privileged role. Whether a user-administrator or group-administrator role can also write a job's post-command was not tested; if some lower role can, that is a separate finding about role separation rather than a change to this chain's score.

It is worth naming the shape of this precisely, because the scoring depends on it: the chain is a single-phase flow whose first half manufactures the credential its second half consumes. There is no second victim, no stored payload waiting for a privileged user to touch it, and no session forgery. The attacker's own session, obtained without credentials, is the principal at the sink.

### Authentication Boundary — what is deliberately not claimed

- We do not claim the product lacks authentication. It has three authentication planes; the message-level one is closed and we measured it closed.
- We do not claim configured deployments are exposed to the account-creation half. Once an administrator exists, the setup screen is not rendered and that half of the chain has no route. Our post-setup observation is the console login form appearing in place of the setup screen, and the created administrator's credentials being accepted.
- We do not claim `/Login` answers 401 after setup. The 401 measurements in this advisory are on `/WebApi/Process`; the REST measurement is a 500; the post-setup observation is a rendered credential form. An HTTP status sample from `/Login` after setup was not captured, and we are not going to invent one.
- We do not claim a persistent backdoor. The window is one-shot: it closes when the first administrator is created. In our testbed we re-opened it by deleting the administrator rows and restarting the service; whether the product's own console allows deleting the last administrator, and whether doing so re-opens the window on a production host, was not tested and is not claimed.
- We do not claim session forgery, session fixation, or default credentials in this generation.

## 4. Attack Surface

### Attack Surface — listeners, routes and their protection

| Face | Binding | Protection | First-run reachability as measured |
|---|---|---|---|
| WebAdmin Blazor Server SPA (`/Login`, `/SvrHome`, `/SvrNodeJobs/...`, `/_blazor/negotiate`) | `0.0.0.0:47443`, TLS, self-signed | No route-level authorisation attributes; authentication lives in the `AppState`/`Login` flow, which the setup screen replaces | Setup screen available to any network client; used as the chain's first half |
| Legacy `/WebApi/*` JSON Model/Action (`Process`, `ServerParams`, `CreateAdmin`, `Login`, `Logout`, `ForgotPassword`, `ResetPassword`, `IsSessionAlive`, `RemoteNodes`, plus viewer and reporting routes) | same 47443 | `NxWebApiModelAccess.IsModelAndActionAllowed`, deny-by-default; one pre-authorised read family (`ServerParams`) | `POST /WebApi/Process` without a session: **401**, empty body |
| REST `/api/*` v2 (`AuthenticateController` and peers) | same 47443 | `RESTEnableAdminApi`, default false | `POST /api/Authenticate/Login`: **500**, empty body |
| `/WebApi/CreateAdmin` (legacy administrator creation) | same 47443 | same `AdminUserExists()` predicate | Reachable and unauthenticated, but functionally broken by a `NullReferenceException` in model binding |
| FTP service | 21 | Service account model | Pre-authentication banner and command-sequence fingerprint; separate disclosure |
| WebDAV service | 8080 | Service account model | Requires authentication; the published write-through issue is fixed in this generation |
| User Web (share links, QuickSend, DropZone) | 80/443 | Ticket-gated by design | Design-intended public intake, not a defect |
| `nxcli` administrative port | 31443 | `_AdminUser` with a string-level localhost/`127.0.0.1` restriction | Local management only |
| Legacy local binding | `127.0.0.1:37443` | loopback bind | Not a remote face |

The Blazor SPA has no per-route authorisation filter, so the page tree is the enumeration unit rather than the route. Walking the console from a created administrator session exposed Home, Logging, Audit, Neo Settings, Files, Directories, Connectors, Dashboard, Jobs, Job History and Neo Query, with deep routes of the form `/SvrHome/<guid>/<guid>` and `/SvrNodeJobs/<domain-guid>/<node-guid>/<guid>`. Two GUIDs recur in the domain data: the local filesystem connector `db2112ad-2222-0000-0000-200000000001` used by the injection, and the fixed administrator group key `DB2112AD-1111-1111-1111-111111111111` that identifies administrator rows in the user table.

### Attack Surface — how the surface was mapped

Three independent methods, and the ordering matters because each one compensates for a weakness in the previous.

Static: the complete `ServerCore` assembly was decompiled out of the BitRock package with `ilspycmd` (1,880 files), which gives route attributes, controller shapes, database access and the job handler. ConfuserEx protects string literals, so the Model/Action pair names consumed by `NxWebApiModelAccess` cannot be exhaustively enumerated from strings; that limits static enumeration of the legacy plane and is precisely why the dynamic pass is authoritative for it.

Dynamic, unauthenticated: a first-run-state probe set of `GET /Login` (200, a 3,869-byte Blazor host shell), `POST /_blazor/negotiate` (circuit handoff advertising a connection token), `POST /WebApi/Process` with no session (401, empty), `POST /api/Authenticate/Login` (500, empty), and a four-state characterisation of `POST /WebApi/CreateAdmin`: an empty object or `null` body yields a graceful login-failure result; a body carrying values, an unknown field, or an empty string yields a single-frame `NullReferenceException` from the controller with a full stack trace and internal paths echoed to the unauthenticated caller; an all-`null` body reaches deeper and produces an `NxException` carrying an `E_POINTER` failure code. That four-state table is what proved the legacy administrator-creation route is dead rather than merely awkward, and the stack-trace echo is a separate disclosure in its own right.

Client-driven: the Blazor circuit protocol was documented during verification — `/_blazor/negotiate` issues a connection token and the circuit then speaks a MessagePack-based Blazor protocol over a WebSocket — and the chain was driven through a real headless browser over the DevTools protocol. This is the only method that can answer "is the setup screen actually rendered", because the raw HTTP response for `/Login` is the host shell and contains no setup text at all. Section 9 returns to that trap, since it is the single most likely way for a defender to reach the wrong conclusion about their own installation.

### Attack Surface — components that narrow the surface

Several things make this surface smaller than it first looks, and they should be counted in the product's favour.

The REST plane is off by default and throws in its constructor, so it contributes no remotely reachable behaviour. The legacy JSON plane is deny-by-default and its one pre-authorised family is read-only. The legacy administrator-creation route is broken. The management CLI is restricted to loopback by a string check, and the extra legacy binding is loopback-only. The WebDAV face still requires authentication, and the published archive-extraction traversal is guarded at the library layer in this generation.

Two apparent narrowing effects are weaker than they look. The job editor refuses to run a job whose source or destination connector is missing, which surfaces as a client-side toast; that is a usability guard, and we satisfied it rather than defeated it by selecting the built-in local filesystem connector for both ends. And the absence of IP restriction is a narrowing factor in reverse: `IpAccess Enabled:0` plus a `0.0.0.0` bind means the product ships with no listener-level restriction narrowing anything.

Finally, the setup screen's availability is not narrowed by TLS. The self-signed certificate means a client must ignore verification, which any tooling can do, and which browsers surface as a warning rather than as a block.

## 5. Sink Identification

### Sink Identification — how the sink was found

The sink was found by enumerating execution patterns across the decompiled server assembly rather than by following a single request handler, which is the right approach for a product whose dangerous operations are legitimate features. Sixteen execution-pattern families were scanned over the 1,880 decompiled `ServerCore` files, and fourteen of the sixteen were covered with a conclusion in either direction. The scan also produced a set of negative results that are worth recording, because they explain why the search converged on the job handler instead of somewhere more obvious:

- the archive-extraction family produced 73 string hits in the `nxcli` NativeAOT binary, all in the unpack path rather than in a command-execution path;
- a legacy job-execution mount option, the kind of construct that historically escaped quoting in this product family, produced zero hits in this generation — it exists only in the superseded code base;
- a scripting-agent password field is present but dead: no consumer of it exists in this generation;
- the `nxcli` administrative port creates users only under a localhost string check, so it is not a remote sink.

What remained productive was the job handler's custom-process routine, and it is productive for a structural reason worth stating: an MFT server must be able to run post-transfer scripts, so a command-execution primitive is part of the product's intended behaviour. The security question was never "does this product execute commands" — it is "who can write the command", which is why the interesting half of this finding lives in section 3 rather than in this one.

### Sink Identification — the vulnerable construction

The trigger predicate, call site and sink are three consecutive regions of `Srt.NextGen.ServerCore.Models/MxUtilSvrJobHandler.cs`:

```csharp
// MxUtilSvrJobHandler.cs:970-972  (post-process trigger predicate)
private bool G6kGVrDTVV(ApiResult P_0)
{
    if (P_0.IsSuccess() || Job.ExecuteCustomPostProcessOnFileTransferTaskFailure)
    {
        return !string.IsNullOrWhiteSpace(Job.PostCommandText);
    }
    return false;
}

// MxUtilSvrJobHandler.cs:979-982  (call site)
    ...LogMsg("Post Command: " + Job.PostCommandText);
    try { RunCustomProcessAsync(Job.PostCommandText, Job.PostWorkingDir, Job.PostTimeout).Wait(); ... }
```

```csharp
// MxUtilSvrJobHandler.cs:991 onward  (our notes also record this routine at :996
// in a second pass over the same decompilation)
public async Task<bool> RunCustomProcessAsync(string command, string workingDir, int timeoutSeconds)
{
    if (command.TrimStart().StartsWith("cmd", OrdinalIgnoreCase))
    {
        fileName  = "cmd.exe";
        arguments = "/c " + command.Substring(3).Trim();
    }
    else
    {
        int num = command.IndexOf(' ');
        fileName  = num > 0 ? command.Substring(0, num) : command;
        arguments = num > 0 ? command.Substring(num + 1) : "";
    }
    process = new Process { StartInfo = new ProcessStartInfo {
        FileName = fileName, Arguments = arguments,
        WorkingDirectory = workingDir, UseShellExecute = false, ... } };
    if (!process.Start()) throw new InvalidOperationException(...);
}
```

Four properties of this construction make it a command injection rather than a command launcher:

1. **The `cmd` prefix special case reconstructs full shell semantics.** Any value beginning with case-insensitive `cmd` is handed to `cmd.exe` with `/c` and the remainder as one string. That means `>` redirection, `&` chaining, `%VAR%` expansion and quoting behaviour are all live in the payload space. This is not a bug in itself — it is a convenience that makes the field a shell prompt — but it removes any argument that the field is "just a program name plus arguments".
2. **Otherwise the split is a naive first-space split**, so the file name is whatever precedes the first space and everything after it is one argument string. A path or program name containing a space is mishandled, and no quoting discipline is imposed on the caller.
3. **`Arguments` is a string, not a vector.** .NET offers `ProcessStartInfo.ArgumentList` precisely so that arguments are passed without re-parsing; using `Arguments` means the string goes through command-line parsing rules that the value was never validated against.
4. **There is no allow-list, no path canonicalisation, no executable-existence check and no metacharacter rejection.** The only inspection of the value is `IsNullOrWhiteSpace` in the predicate, which is a "should I run anything at all" test, not a "is this safe" test.

The routine also accepts a working directory and a timeout from the job document, and both are attacker-controlled once the job is — so there is no second-order defence available from the environment either.

### Sink Identification — execution identity of the child process

The calling process is `titanmft.exe`, hosted by the Windows service `SrtTitanMFTServerService` and configured as LocalSystem. Because `UseShellExecute` is `false`, `Process.Start` resolves to a `CreateProcess`-family call that gives the child the parent's token: no impersonation, no restricted token, no job object, no integrity-level downgrade appears anywhere in this path.

The measured artifact is the marker file: 21 bytes, content `nt authority\system`, written by the `whoami` child. Its modification time sits 76 milliseconds after the job-completion timestamp that the product recorded in `NxDbJobHistory` for the same run, which is the timing evidence that the file was written by the post-process step of that job rather than by anything else on the host. A first verification round on the same build produced an identical result with an independently named marker (also 21 bytes, also `nt authority\system`), so the identity observation is not a one-off sample.

What the identity means operationally is developed in section 10. Structurally, the point here is narrower: the child's privilege is the service's privilege, and the service's privilege is the highest available on a Windows host.

### Sink Identification — sibling sinks, and whether they are proven

Naming sibling constructions honestly, separated by evidence strength:

- **The pre-transfer counterpart of the same field.** Job documents carry a pre-command alongside `PostCommandText`, and the fix recommendations in section 11 cover both. We executed only the post-transfer path. The pre-transfer path is a structural inference from shared code shape, **not a measurement**, and we do not claim it as verified.
- **`WebApiController.CreateAdmin` at `WebApiController.cs:674-690`.** Same semantics as the live wizard path — `CreateAdminUser` behind the `AdminUserExists()` predicate, with `NxDecryptAPI` applied to the credentials. Proven *reachable and unauthenticated*, proven *broken* by the four-state binding characterisation. It is a dead sibling, not an alternative exploit path, and any vendor fix that repairs the binding without fixing the predicate would turn it into one.
- **The legacy job-execution mount option.** Zero hits in this generation; a real sink in the superseded code base only.
- **The scripting-agent password field.** Present, no consumer in this generation. Dead.
- **The archive-extraction path.** The library-layer traversal guard for the older published zip-slip issue is present in this build's unpack pipeline, so that specific defect is fixed. What remains is that the application layer applies no path filtering of its own and that overwrite-everything is the default behaviour, which admits in-directory overwrite and unbounded decompression. That is availability-grade, it is reported to the vendor separately, and it is **not** folded into this chain's score.
- **Stack-trace echo and window-state probe.** Unauthenticated callers receive full .NET stack traces with internal paths from the broken legacy routes (`CWE-209`/`CWE-200`), and the pre-authorised `ServerParams` family returns the window-running flag, which lets an unauthenticated caller determine whether a target is still in its first-run window. Neither is needed by the main chain; both are separately reportable and both make mass discovery of exposed installations easier, which is why they are mentioned here rather than buried.

## 6. Source Identification

### Source Identification — the tainted input and its transport

This chain has two sources, and they differ in the transport that carries them.

The first source is the setup form on `/Login`. Its fields are the DOM elements `login-username` and `login-password` plus a submit button, rendered by the Blazor component tree after circuit boot. Their transport is the Blazor Server circuit: the browser negotiates with `/_blazor/negotiate`, receives a connection token, opens a WebSocket, and exchanges MessagePack-encoded messages with the in-process circuit. Submitting the form reaches `Login.razor`'s `OnDoLogin`, which in the first-run state calls `AppState.CreateAdminUser(ar)` followed by `AppState.Login(ar)` and then navigates to `SvrHome`. No HTTP endpoint carries the credentials; that is why a REST-style attack against `/WebApi/CreateAdmin` is the wrong shape and why the browser-driven path is the right one.

The second source is the job editor field labelled `Execute After File Transfer Task`. In the DOM it is the input inside a `.dxbl-fl-item` whose `label.dxbl-fl-cpt` carries that text, of class `dxbl-text-edit-input`, inside the collapsible `Post-Task Processes` group. Its transport is the same circuit, and it lands in `nxJobs.document.PostCommandText`. The job document we captured after injection contained 166 keys, of which the ones that matter for the chain are `PostCommandText`, `IsScheduleDisabled`, `ExecuteCustomPostProcessOnFileTransferTaskFailure`, `ActualSourcePath`, `SourceConnectorId` (the local filesystem connector GUID `db2112ad-2222-0000-0000-200000000001`) and `DestinationConnectors[0].ActualDestinationPath`.

A transport detail that cost real effort and that any reproducer will hit: DevX `dxbl` components publish their value to the server-side circuit only when the standard DOM events fire. Setting `element.value` alone leaves the server-side model untouched. The working sequence is `focus()`, assign `value`, then dispatch `input`, `change` and `blur` with `bubbles: true`. Checkbox state is read from the `check-state` attribute of the enclosing `dxbl-check` element, where `1` means checked and `2` means unchecked, and the product's own group headers (`Task Execution`, `Post-Task Processes`, `Source Connector`, `Destination Connector`) must be expanded before their inputs exist in a settable state.

### Source Identification — sanitization that exists, and what it is for

Three things on the path could be mistaken for sanitisation. None of them constrains the payload.

`NxDecryptAPI` (AES-ECB with a static key, `StringExtensions.cs:1008`) is optional transport obfuscation of administrator credentials on the legacy plane. It returns the input unchanged when the encryption prefix is absent, so plaintext is accepted; the construction is static-keyed, so it provides no confidentiality against an attacker who has the binary; and it is applied to the *credential* fields, not to the command field. It grants no privilege and blocks nothing.

The DevX client-side validation on the job editor — which refuses a run when the source or destination connector is missing — is a usability guard. It prevented one of our earlier reproduction attempts from completing, and it is the reason the published tooling selects connectors explicitly. It has no security meaning: it is satisfied by choosing the built-in local filesystem connector, which is what a legitimate administrator would do anyway.

The `cmd` prefix special case looks like handling and is in fact an amplifier. It exists so that administrators can type `cmd /c ...` naturally; its effect is to widen the payload space from "program path plus argument string" to "arbitrary Windows shell command line".

What genuinely does not exist anywhere on the path: shell metacharacter filtering, quoting or escaping, argument-vector construction, an executable allow-list, a path canonicalisation or existence check, a length limit we could observe, and any server-side re-validation of the field's content between the point it is written to the job document and the point it is handed to the process start.

### Source Identification — validation that is absent

The absent validations group into three families, and the families have different owners in a fix.

Missing on the network edge: any authentication of the setup screen beyond the empty-table predicate. Specifically missing are channel binding (a one-shot bootstrap token issued at install time, presented once and invalidated), a listener restriction (loopback or management-interface-only binding while no administrator exists), and response-shape equality (the pre-authorised `ServerParams` family currently reveals whether an administrator exists, which turns window discovery into a single unauthenticated request).

Missing on the field: an allow-list of permitted executables, argument-vector construction, a metacharacter policy, and any server-side re-validation before execution. The product could keep the feature and still add all four.

Missing in the process model: privilege separation between the administration plane and the transfer engine, and a non-LocalSystem execution identity for spawned children. The `LegacyApi.dll` string surface already exposes `CreateProcessAsUserW`, so per-user token plumbing exists somewhere in the code base; it is simply not on the job post-command path.

## 7. Data Flow

### Data Flow — end-to-end chain

The end-to-end flow, with the observable artifact at each transition. This is the sequence our single-pass replay executed, in order, in one scripted run:

```text
Window state (shipped, not attacker-created)
  BitRock unattended install completes
    -> mftlasdb.nxUserParams holds 0 rows
    -> MxSvrParams.cs:518-520 evaluates RunWizard = !AdminUserExists() = true
    -> service SrtTitanMFTServerService starts, Kestrel listens on 0.0.0.0:47443 (TLS)
    -> IpAccess Enabled:0, so no listener-level restriction applies

1  unauthenticated GET /Login
     artifact: HTTP 200, 3869-byte Blazor host shell (no setup text in raw HTML)
2  circuit boot (/_blazor/negotiate -> WebSocket -> MessagePack frames)
     artifact: rendered page text contains "Initial Admin User Setup" and
               "Create Initial Admin User"; EULA/Ticket/CAPTCHA/IP all absent
3  set login-username + login-password, dispatch input/change/blur, click submit
     artifact: nxUserParams 0 -> 3 rows (Ident / General / Name, Name = new admin)
4  server-side AppState.CreateAdminUser then AppState.Login then NavigateTo
     artifact: browser URL becomes /SvrHome/<guid>/<guid> with no credential sent
5  console tree -> Jobs -> toolbar Add -> new Inbound job, Save
     artifact: nxJobs row created (Save keeps the editor page open)
6  grid row Actions -> Edit -> expand Task Execution and Post-Task Processes
     artifact: field "Execute After File Transfer Task" becomes settable
7  write the post-command via input/change/blur
     artifact: nxJobs.document.PostCommandText = "cmd /c whoami > <marker>"
     read back from the field byte-identical
8  check "Execute custom post-process on file transfer task failure";
   clear "Do Not Run"
     artifact: ExecuteCustomPostProcessOnFileTransferTaskFailure = true,
               IsScheduleDisabled = false
9  second editor pass: Source Connector and Destination Connector =
   Local Filesystem (db2112ad-2222-0000-0000-200000000001), directories set
     artifact: ActualSourcePath and DestinationConnectors[0].ActualDestinationPath
10 grid row Actions -> Run Job
     artifact: transfer pipeline runs; console output tab reports
               Task State Completed, Status Success, Total Files 1,
               Files Transferred 1, Percent Complete 100
11 MxUtilSvrJobHandler.cs:970 predicate true (success and non-blank command)
   -> :979-982 LogMsg("Post Command: ...") and RunCustomProcessAsync(...)
   -> :991 cmd-prefix case -> cmd.exe /c whoami > <marker>
     artifact: marker file, 21 bytes, content "nt authority\system",
               mtime = job completion timestamp + 76 ms
12 control leg: PostCommandText cleared, same job re-run
     artifact: job-history row 2 (Completed, success=1, files=0);
               marker size and mtime unchanged to the millisecond
```

### Data Flow — properties of the chain worth naming

**It is a single-phase chained flow.** The unauthenticated half produces the credential the authenticated half consumes, immediately and in the same session. That distinguishes it from three other shapes an analyst might assume: it is not a stored second-order flow (nothing waits for a privileged victim to act), it is not leftover installer residue (the window is created by a correct, complete installation, not by a forgotten setup directory — deleting a setup directory would not close it), and it depends on no hardcoded secret.

**The attacker supply side carries zero credentials and zero secrets.** Every input the attacker provides is invented at request time: an account name, a password of the attacker's choosing, a job name, a command line, two directory paths. Nothing is read from the product, decrypted, or replayed.

**It uses only documented product surfaces.** Every transition is a UI action an administrator performs routinely: open the console, complete the setup screen, add a job, edit it, set a post-transfer command, choose connectors, run it. There is no undocumented endpoint, no direct object write, no protocol abuse and no memory-safety defect. That is why the chain survived a fully closed message-level gate.

**The window is a race against deployment, not against a victim.** Whoever creates the first administrator owns it. There is no recovery semantics inside the product that revokes an account created through the setup screen, and no audit distinction between "the operator completed setup" and "an anonymous client completed setup". In our testbed the window was re-opened by deleting the administrator rows and restarting the service, which demonstrates the state dependency precisely; whether the product's own console permits deleting the last administrator, and whether doing so re-opens the window on a production host, was not tested.

**The post-process predicate decouples execution from transfer success.** It fires when the transfer succeeded *or* when the on-failure box is checked, as long as the command is non-blank. Our control run reached the same pipeline with zero files transferred and still completed, so with the box checked the injection does not need any file to move at all. That reading comes from the predicate at `MxUtilSvrJobHandler.cs:970` plus the observed control-row semantics; we did not separately execute a failing transfer with a payload, and we do not claim that specific combination as measured.

## 8. Exploit Construction

### Exploit Construction — step sequence

The published proof of concept follows the product's own UI, step for step, and prints a read-back for every state change. The ordering contains three constraints that a naive automation will get wrong, all of them discovered the hard way during verification:

1. **Negotiate and confirm the window before touching anything.** The tool issues the unauthenticated probe set — `GET /Login`, `POST /_blazor/negotiate`, `POST /WebApi/Process`, `POST /api/Authenticate/Login` — then launches a headless browser, boots the circuit on `/Login` and reads the rendered page text. If the setup strings are absent and a credential form is present, the window is closed and the tool exits non-zero without making any change. This is the difference between a scan and an attack, and it is the default mode.
2. **Create the account through the setup screen, then confirm the console landed.** Set the two inputs with the DOM event bridge, click the submit button, then poll the browser URL for `SvrHome`. A missing poll is how an automation convinces itself it succeeded when the circuit is still booting.
3. **Create the job, then re-open it.** The creation-mode form exposes only job identification. The collapsible groups that hold the post-command field, the checkboxes and the connectors exist only in the full editor, reached from the grid row's Actions menu. After Save the product keeps the editor open and does not re-render the grid, so creation must be confirmed from the grid after navigating back — checking the grid immediately is a false negative.
4. **Write the post-command, then read it back.** The tool reads the field after the event bridge and compares it character for character with the payload before proceeding. A field that silently reverted is the most common failure in DevX automation and the tool refuses to claim success in that case.
5. **Set the two checkboxes by state, not by click count.** Desired states are `check-state` 1 for the on-failure box and 2 for `Do Not Run`; the tool reads the attribute, clicks the label if it disagrees, verifies, and falls back to setting the inner input's `checked` plus a `change` event.
6. **Do the connector step in a second editor pass** with label-driven field selection — enumerate the `.dxbl-fl-item` labels in the connector group and pick the one matching a directory or path, then set and read it back. Positional selection writes the wrong field and leaves the job hung in a scanning state with no source path persisted.
7. **Run the job, then read the product's own output tab** for `Task State`, `Status`, `Total Files To Transfer`, `Files Transferred` and `Percent Complete`, and only then read the marker from disk.
8. **Run the control leg**: re-authenticate as the created administrator, clear the post-command, save, re-run the identical job, and compare marker size and modification time against the pre-control measurement.
9. **Clean up**: clear the post-command again and set `Do Not Run`, leaving the job inert. The tool cannot delete the administrator account it created — that requires operator action in the product console — and it says so in its output rather than pretending the target was restored.

An optional read-only forensic mode prints row counts from the administration database (`nxUserParams` discriminators and the administrator name) and the job document's post-command, source path and job history, opened in SQLite read-only mode. It performs no writes; the database reset used during verification is deliberately **not** part of the published tool, because re-opening the window is a lab operation and not something an exploit should do to a target.

### Exploit Construction — payload engineering constraints

- **Use the `cmd` prefix.** The predicate special-cases it into `cmd.exe /c <remainder>`, which is what makes redirection work: `cmd /c whoami > <marker>` produces a file whose content is the identity. Without the prefix the string is split on the first space, so a payload such as `powershell -c ...` would put everything after `powershell` into one argument string that PowerShell then has to parse — workable, but a needless second layer of quoting.
- **Working directories must exist.** The connector directories are the job's source and destination; in our run a 25-byte probe file in the source directory produced `Total Files To Transfer : 1`, `Files Transferred : 1` and `Percent Complete : 100`, and the same file appeared in the destination directory. The published tool can create these on the local host when asked, and says plainly when it cannot.
- **`Do Not Run` must be cleared** or the product refuses to execute the job.
- **The on-failure box removes the dependence on transfer success**, per the predicate at `MxUtilSvrJobHandler.cs:970`. Our control run completed with zero files transferred, demonstrating that the pipeline reaches its terminal state without any file moving.
- **The marker path is writable by SYSTEM by construction**, since the child runs as LocalSystem. Choose a path the operator can read back from whatever host is running the tool; if the tool runs remotely, the marker cannot be read and the tool reports the run as unverified instead of guessing.
- **Length budget unknown.** Our `cmd /c whoami > <path>` payload round-tripped byte-identically through the field. We did not probe a maximum length, so long payloads such as encoded shells carry an unmeasured risk of truncation and should be tested rather than assumed.
- **Marker over destruction.** The published default payload writes `whoami` output to a file. Nothing in the tool is destructive, and the tool does not offer a callback or exfiltration mode.

### Exploit Construction — what the exploit deliberately does not do

- It does not write to the product databases, and it does not re-open the first-run window. If the target is outside the window, the exploit leg is refused.
- It does not manage the Windows service, the firewall or any host configuration.
- It does not create persistence, add accounts beyond the single administrator the setup screen requires, move laterally, or touch anything outside the marker file and the two connector directories.
- It does not delete the administrator account it creates, and it does not claim to have restored the target.
- It requires an explicit authorisation flag for any state-changing mode, defaults to the read-only window probe, and exits with distinct non-zero codes for "window closed" and "not verified".
- It does not print success from an assumption: every state change is read back from the DOM, from the product's own output tab, or from the marker file, and a missing read-back produces an unverified verdict.

## 9. Dynamic Verification

### Dynamic Verification — environment

| Item | Value |
|---|---|
| Target | Windows host, fresh default installation of Titan MFT Server 26.0.0.364 via the BitRock unattended package |
| Service | `SrtTitanMFTServerService`, image `titanmft.exe`, principal LocalSystem |
| Listener exercised | `https://127.0.0.1:47443` (WebAdmin RAS, TLS, self-signed) |
| Network posture during the run | Inbound firewall rules blocking remote TCP and UDP on 47443 and 37443; loopback exempt on Windows Firewall, so the run stayed on the host. Rules removed afterwards; service left stopped |
| Databases | `mftlasdb.db` (administration), `mftdb<domain-guid>.db` (domain), matching `-Quartz.db`; SQLite WAL |
| Database location | `C:\ProgramData\South River Technologies\titanmft\database\` |
| Client | Headless Chromium-family browser driven over the DevTools protocol on the host; Python standard library only, raw-socket WebSocket client |
| Attack path | HTTP plus the product UI over the Blazor circuit. No direct database writes and no direct API calls on the attack path; database reads performed read-only for forensic comparison |
| Window state preparation | The administration database's administrator rows were removed and the service restarted, returning the installation to its shipped zero-administrator state before the run began |

### Dynamic Verification — the triggering request

There is no single triggering request, and saying so is part of the accuracy of this advisory. The unauthenticated half is a circuit-boot followed by one form submission; the authenticated half is a sequence of console actions ending in a menu command. The HTTP-level observations that bracket the run are:

```text
GET  /Login                    -> 200, 3869 bytes (Blazor host shell, no setup text)
POST /_blazor/negotiate        -> circuit handoff, connection token advertised
POST /WebApi/Process           -> 401, 0 bytes body, no session presented
POST /api/Authenticate/Login   -> 500, 0 bytes body (REST administration plane disabled)
```

After the circuit boots, the rendered page text is what distinguishes the two states, and this is the measurement that decides whether an installation is exposed:

```text
Inside the first-run window, /Login renders:
    "Initial Admin User Setup"
    "Username"  "Password"  "Create Initial Admin User"
    "(c) South River Technologies, Inc"  "EULA"  "SRT END USER LICENSE AGREEMENT"
    input count = 4

Outside the window, the same route renders:
    "Login to <server-name>"
    "Username"  "Password"  "Login"
```

The final trigger is the grid row's Actions menu, item `Run Job`, dispatched as a real mouse press and release over the circuit. The product then runs its own transfer pipeline and, on completion, evaluates the predicate at `MxUtilSvrJobHandler.cs:970` and calls `RunCustomProcessAsync` with the field's contents.

### Dynamic Verification — observed output

The product's own output tab after the run, with wall-clock timestamps elided by policy:

```text
Running Job : <job>
Job : <job>
Job Type : Inbound
Task State : Completed
Task Start Time : <elided>
Task Completion Time : <elided>
Status : Success
Error :
Total Files To Transfer : 1
Files Transferred : 1
Percent Complete : 100
```

The forensic evidence, all of it collected read-only from the product's own stores and from the filesystem:

| Evidence | Observed value |
|---|---|
| Marker file | 21 bytes; content `nt authority\system`; modification time 76 ms after the job-completion timestamp recorded for the same run |
| Job history row 1 | `jobstate=Completed`, `jobsuccess=1`, `joberror=""`, files 1, bytes 25; start to completion 1.1189523 s |
| Job history row 2 (control) | `jobstate=Completed`, `jobsuccess=1`, files 0, bytes 0; `joberror="Some files were not moved due to an overwrite condition. 1 file(s) skipped."`; start to completion 0.0495447 s |
| Administration database | `nxUserParams` 0 rows before setup, 3 rows after, discriminators `Ident`, `General`, `Name`, with `Name` holding the created administrator |
| Job document | 166 keys; `PostCommandText` equal to the injected string; `IsScheduleDisabled` false; on-failure flag true; `SourceConnectorId` = `db2112ad-2222-0000-0000-200000000001`; `ActualSourcePath` and `DestinationConnectors[0].ActualDestinationPath` equal to the two connector directories |
| Transfer artifacts | The 25-byte probe file present in both the source and the destination directory |
| Session artifact | Browser URL `/SvrHome/<guid>/<guid>` reached without any credential being presented |

The marker content is the identity claim: `whoami` printed `nt authority\system`, which is the LocalSystem service principal. The 76 ms offset between the recorded job-completion timestamp and the marker's modification time is the attribution evidence: at that precision, the file was written by the step that followed transfer completion in that job, not by anything else on the host.

An earlier verification round on the same build produced the same result through the same path with a differently named administrator, a differently named job and an independently named marker file — also 21 bytes, also `nt authority\system`, also immediately after its job's completion timestamp — so the outcome is not a property of one particular account or job name.

### Dynamic Verification — the negative control and why it matters

The control leg repeated the entire pipeline with one variable removed. Using the administrator created by the exploit itself, the tool re-opened the same job, cleared `PostCommandText` (confirmed empty in the field and in the job document), saved, and ran the identical job again. The job completed — control row 2 above — and the marker file was untouched: same byte length, same modification time to the millisecond.

This is the single most valuable piece of evidence in the package, because it eliminates every alternative explanation for the marker that does not involve the injected field:

- it was not written by the transfer engine or by any pipeline stage, because the same pipeline ran again and produced no new file activity;
- it was not a leftover artifact from an earlier experiment or from installation, because its modification time is bound to a specific job completion, and the second completion left it exactly as it was;
- it was not written by a scheduled task, a service restart or a background process, because the only difference between the two runs is one field's contents;
- it was not a coincidence in timing, because the two runs are 111.6 seconds apart and the marker's modification time matches the first one only.

Three further measurements constrain the interpretation in the opposite direction, and they are why we describe the finding as a window rather than as an authentication bypass:

**The counter-gate measurement.** In the same service instance, within the same pass, an unauthenticated `POST /WebApi/Process` returned 401 with an empty body and `POST /api/Authenticate/Login` returned 500, while `/Login` offered the setup screen to the same unauthenticated client. Message-level authentication was demonstrably intact and demonstrably irrelevant: the chain never traverses the message-level gate. This rules out "the vendor's API authorisation is broken" as a description of the defect and locates it in the setup screen's own predicate.

**The zero-precondition measurement of the setup screen.** The screen was submitted successfully with the EULA checkbox untouched, with no ticket parameter, with no CAPTCHA element present in the DOM, with no first-boot token, and from a client subject to no IP restriction (`IpAccess Enabled:0`, listener on `0.0.0.0`). This rules out "the wizard is gated and we defeated the gate".

**The full single-pass replay.** All of the above — window preparation, probe set, account creation, job creation, injection, run, marker verification, control run and teardown — executed inside one scripted pass whose stdout was captured to a file, so the pieces were not verified at different times against differently configured machines. That rules out the most common way a multi-step claim quietly becomes invalid: step N proven on a host that had been modified by step N-1's debugging.

### Dynamic Verification — boundaries of what was verified

These limits are as important as the results:

- **The window was re-opened by our own tooling.** We deleted the administrator rows from the administration database and restarted the service to return a previously configured host to its shipped state. A never-configured installation lands in that same state by construction, and the product's own predicate reads only the row count, but we did not observe this chain on a machine that had never been touched.
- **The vantage point was loopback.** The listener's `0.0.0.0` bind and disabled IP restriction are artifact facts, and remote reachability follows from them, but no request in this verification crossed an untrusted network boundary.
- **The second build's tail is not measured.** The first-run half was confirmed dynamically on 26.0.0.348; the injection tail on that build is a structural argument from a shared code base.
- **The pre-transfer command sibling was not executed**, so its exploitability is inference.
- **The failing-transfer-with-payload combination was not executed.** Only the successful transfer with payload, and the empty-command re-run, were measured.
- **No cloud-shaped installation was sampled**, so the `CreateAdminAtConsole` branch and its interaction with the legacy `CreateAdmin` route remain uncharacterised.
- **No post-setup HTTP status sample was taken from `/Login`.** Our post-window evidence is that the setup screen is no longer rendered and that a credential form is rendered instead, and that the created administrator's credentials were accepted through it.
- **Window duration in real deployments was not measured.** What we can say is definitional and deployment-dependent: the window lasts from installation completion until the first administrator is created, and its length is therefore a function of how quickly the operator or the deployment automation completes setup — including whether installation is scripted unattended and whether setup is deferred until after the listener is already reachable. We have no measurement of a typical duration and we do not estimate one.

## 10. Reachability and Security Impact

### Reachability and impact — network position

The attack requires one thing from the network: the ability to open a TCP session to the WebAdmin listener on port 47443 and complete a TLS handshake with a self-signed certificate. The shipped configuration binds that listener to `0.0.0.0` and leaves the product's IP-restriction feature disabled, so no listener-level narrowing is applied by default. Any host in the same segment, any partner network with a route to the management interface, and — where the listener is published — any internet client meets that requirement.

Two honesty notes belong here. First, our own verification ran from loopback on the target host with remote access firewalled off, so "reachable from an untrusted network" is a reading of the shipped binding rather than a measurement of an attack crossing one. Second, the observation that management ports on MFT servers are commonly reachable from partner networks, and sometimes from the internet, is a statement about this product genre's deployment practice; it is not a measurement of any particular deployment and should not be read as one.

The client requirement is the one thing that raises the bar slightly above a bare `curl`: the setup screen and the console are Blazor Server surfaces whose content appears only after a circuit boots, so the attacker needs a headless browser or an equivalent circuit client. That is ordinary tooling and it is what the published proof of concept implements; it is a few hundred lines of standard-library code plus a browser, not a research obstacle.

### Reachability and impact — what the achieved identity controls

The achieved identity is LocalSystem on the Windows host carrying the MFT server. For this class of product that is close to a worst case, because the host is the organisation's file-exchange hub:

- **Every trading partner's transfer credentials.** The administration and domain databases hold connector configurations, account material for SFTP/FTPS/WebDAV endpoints, and the product's SSH and PGP key material — including keys used to encrypt outbound partner files and to verify inbound ones. Reading them converts a single host compromise into the compromise of every exchange relationship the host participates in, including with parties who have no visibility into this incident.
- **The files themselves, in transit and at rest.** Source and destination directories for every connector are readable and writable from the service account. That permits silent reading of transferred content, silent modification of content between transfer and pickup, substitution of files presented to partners, and deletion of evidence.
- **Transfer configuration.** Jobs, schedules, connector paths, notification settings and audit configuration can all be rewritten. An attacker can redirect a recurring partner transfer to an attacker-chosen directory without any partner-visible change, or disable auditing for a job before abusing it.
- **Host-level persistence and lateral movement.** LocalSystem permits creating local accounts, installing services, writing to startup locations, reading the host's credential stores, and pivoting into whatever the host can reach — and MFT servers are frequently granted broad access to internal storage and to domain resources precisely so that they can collect and deliver files.
- **Availability of scheduled transfers.** Stopping the service, disabling jobs, corrupting the SQLite databases, filling the volume used by connectors, or leaving the transfer engine wedged halts every scheduled exchange. For an organisation whose partner agreements carry delivery windows, that is a business-continuity event and not merely a service outage.
- **Undetectability at the product layer.** Every step of this chain is a documented administrative action: completing setup, adding a job, setting a post-command, running the job. The product's own audit surface records legitimate administration, so an organisation looking for exploitation signatures in the MFT's logs will not find any.

### Reachability and impact — the unauthenticated question, answered in full

This is the question that decides whether this advisory reads as "critical" or as "conditional", so it gets a complete answer rather than a headline.

**What is true.** The account-creation half of this chain requires no credentials, no secret, no bypass and no interaction from any user. An anonymous client that can reach port 47443 while the installation is inside its first-run window becomes the administrator of that installation. The execution half requires an administrative session, and the first half supplies one. From the attacker's side the whole chain is credential-free, and the resulting identity is LocalSystem. That is why `PR:N` is the correct privileges-required value for the chain as a whole: the least privileged principal that reaches the sink is a principal that did not exist before the request.

**What is not true, and must not be inferred.** This product authenticates. Once an administrator exists — which is the state of every installation whose setup has been completed — `/Login` renders a credential form, the setup screen is not reachable, and this chain's first half has no route whatsoever. Nothing in this advisory supports the claim that configured deployments are exposed to it. A deployment that finished first-time setup before its listener became reachable to untrusted clients was never exposed at all.

**What determines exposure, then.** Two things, both deployment facts rather than product facts: whether the installation is inside the window, and who can reach the listener. The window opens when installation completes and the service starts; it closes the moment the first administrator account is created. Its length is therefore exactly the interval between "installed and listening" and "setup completed". What sets that interval in practice is deployment behaviour — whether installation is scripted or unattended, whether first-time setup is part of the same change window or deferred to a later one, whether the host is published to a management network or to partner networks before setup is done, and whether the installation is one of a batch where configuration happens after the whole batch is up. We did not measure a typical duration in any environment and we decline to estimate one; it is deployment-dependent, and the same build can be exposed for five minutes or for five days depending on the operator's process.

**How an operator checks, concretely.** Three methods, in order of increasing certainty:

1. **Load `/Login` in a real browser and look at the rendered text.** If the page says `Initial Admin User Setup` and offers a `Create Initial Admin User` button, the installation is inside the window. If it says `Login to <server-name>` and offers `Login`, it is outside. This is the authoritative check, and the published proof of concept's default mode is exactly this check, exiting non-zero when the window is closed.
2. **Do not use a plain HTTP fetch for check 1.** A `GET /Login` from `curl` returns the 3,869-byte Blazor host shell, which contains none of the setup text, because the component tree renders only after the circuit boots client-side. A grep of the raw response will report "no wizard" on an exposed installation. This is the single easiest way for an operator to reach a false negative, and it is why our own probe set prints the raw-HTML result and then labels the browser probe authoritative.
3. **Check from the host when you can.** Count the rows in the administration database's `nxUserParams` table (zero rows means inside the window), or confirm that an administrator account exists in the console's user list and was created by a known operator. Repeat the check after any administrator deletion, re-image or restore, since the window is a function of that table's contents and not a one-time installation event.

A fourth method — reading the window flag from the pre-authorised `ServerParams` family as an unauthenticated caller — is technically available and is how a mass scanner would do it, but it depends on a separate information-leak defect and is listed here only so that defenders know the discovery primitive exists.

### Reachability and impact — detection notes

Detection has to be built from anomaly rather than signature, because every action in the chain is a documented administrative operation.

- **Account provenance.** An administrator row appearing in the administration database with a creation timestamp and an immediate first-login timestamp, outside any change record, is the primary indicator of the first half. On the wire, a `/Login` circuit that transitions from setup submission to `/SvrHome` without any preceding credential exchange is the same event.
- **The product's own log line.** The job handler logs `Post Command: <text>` before spawning. Any occurrence whose text was not authorised through change control is a finding, and the text is preserved verbatim, so this is the highest-fidelity detection point available.
- **Process genealogy.** A `cmd.exe` (or any child process) whose parent is `titanmft.exe` and which runs as `nt authority\system` is anomalous: the service has no legitimate reason to spawn shells for anything other than administrator-configured post-commands. Alerting on any child of the service process is cheap and high-signal.
- **Job shape.** Jobs whose source and destination are both the local filesystem, which transfer zero or one file, which have a non-empty post-command, and which no operator scheduled are the classic injected-job shape. Our own control run produced exactly this footprint.
- **Job history anomalies.** New `NxDbJobHistory` rows for jobs that no schedule references; runs with `files=0` carrying a successful completion state.
- **Network context.** TLS sessions to 47443 from hosts outside the management segment, especially short-lived ones that navigate to `SvrHome` and `SvrNodeJobs` and then to the Jobs editor.
- **What will not detect it.** Looking for exploitation signatures, for authentication failures, for SQL injection or for deserialization payloads. There are none: no failed logins occur, because the attacker never needs to fail a login, and the payload is a legitimate configuration field.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

1. **Close the window on the network face (root cause).** Initial-administrator creation must not be reachable from the RAS listener. Three acceptable shapes, in order of preference: move it entirely into the installer's console/GUI step; require a one-shot bootstrap token produced at install time (printed to the installer transcript or written to a host-local file with a restrictive ACL), single-use and expiring; or bind the setup route to loopback and to the installer's own session. The code already contains the console-creation branch used for cloud-shaped deployments, which is the natural home for this on all deployments.
2. **Stop leaking window state.** Remove the window-running flag and any administrator-exists differential from responses served to unauthenticated callers, and make the response shape identical whether or not an administrator exists. This also removes the unauthenticated probe that makes mass discovery of exposed installations trivial.
3. **Suppress stack traces on the legacy plane.** Return a 400 with no body detail when model binding fails. The four-state behaviour we characterised — graceful on an empty or null body, single-frame `NullReferenceException` with internal paths on any valued body, deep `NxException` with `E_POINTER` on an all-null body — hands internal structure to unauthenticated callers.
4. **Constrain the command field (defence in depth).** Build the child process with `ProcessStartInfo.ArgumentList` rather than a single `Arguments` string, and remove the `cmd`-prefix special case that reconstitutes full shell semantics; add an allow-list of permitted executables (or a per-deployment switch that explicitly enables shell metacharacters, off by default); reject `& | < > ` % ^ ( )` and newlines in the default mode; validate the working directory against the job's connector paths.
5. **Separate the execution identity.** Do not run the transfer engine — and therefore post-commands — as LocalSystem. Use a virtual service account or a per-job token with only the connector paths granted. The shipped legacy shim already imports `CreateProcessAsUserW`, so per-user token plumbing exists in the code base and this is a wiring change rather than a new capability.
6. **Refuse to listen before setup is complete, or listen narrowly.** Either hold the network listener until first-time setup has been completed on the host, or bind it to loopback and the management interface until then. This converts a deployment race into a non-issue without requiring operators to coordinate installation and configuration.
7. **Reduce the pre-authentication fingerprint on the FTP face** — banner and command-sequence detail served before authentication.
8. **Ship regression tests for all four layers**, because three of these fixes are the kind that silently regress: (i) with a zero-row user table, a network request to the setup route must not be able to create a user; (ii) a post-command containing a shell metacharacter must be rejected or executed as a literal argument vector — assert that `cmd /c whoami > %TEMP%\x` produces no file; (iii) the documented supported configuration must not run the service process as LocalSystem; (iv) the `ServerParams` family must never return window state to an unauthenticated caller.

### Fix Recommendations — operator-side, until a patch exists

1. **Treat "installed but not configured" as an open exposure, not a pending task.** Complete first-time setup from the console in the same change window as the installation, before the listener is reachable from anywhere else.
2. **Block the listener until setup is done.** At the host firewall or upstream, block inbound TCP 47443 (and, as applicable, 37443, 8080, 21, 80 and 443) until an administrator exists; or restrict the listener to the management interface. Do not rely on the product's IP-restriction feature being enabled, because the configuration we examined had it disabled.
3. **Prove the window is closed, and re-prove it.** Run the read-only window probe shipped with this advisory, or load `/Login` in a browser and confirm the credential form rather than the setup screen. Repeat after any administrator deletion, restore or re-image.
4. **Put the administration listener behind an authenticating reverse proxy or a VPN** so that unauthenticated clients cannot reach the setup screen or the console at all. This is the single highest-value operator control, because it is indifferent to the window's state.
5. **Do not run the service as LocalSystem** where the deployment permits otherwise; grant the service account only the connector paths it needs.
6. **Audit job post-commands.** Enumerate job documents whose `PostCommandText` is non-empty and confirm each against change control. Pay particular attention to jobs whose source and destination are both local directories and which transfer nothing.
7. **Restrict job-creation rights** to named administrators, and review job history for runs no schedule accounts for.
8. **Alert on the three high-signal events**: new administrator rows outside change control, any child process of the service process, and any `Post Command:` log line not attributable to an authorised change.
9. **If the window was open on a reachable listener at any point**, treat the installation as potentially compromised rather than as merely exposed: audit the administrator list for accounts nobody created, review all jobs and their post-commands, review connector credentials for unexplained changes or access, and rotate partner credentials and SSH/PGP key material as the risk assessment warrants.

## 12. CWE and CVSS

### CWE and CVSS — classification

Two primary classifications, one per half of the chain, and reporting only one of them would misrepresent the finding:

- **CWE-306, Missing Authentication for Critical Function** — the creation of the product's first administrator account is reachable from the network with no authentication while the installation is inside its first-run window. Critical function is the right characterisation: this is not a read of configuration but the establishment of the account that will own every other administrative decision on the host.
- **CWE-78, Improper Neutralization of Special Elements used in an OS Command** — the job post-command field is passed to process creation without quoting or neutralisation, and the `cmd`-prefix special case explicitly hands the value to a command interpreter.

Contributing classifications, named but deliberately **not** folded into the score:

- **CWE-250 / CWE-269** — the sink executes as LocalSystem with no privilege separation between the administration plane and the transfer engine. This is what makes the outcome system-level rather than application-level, and it belongs in remediation priority; adding it into the vector would double-count the impact that `C:H/I:H/A:H` already expresses.
- **CWE-209 / CWE-200** — the unauthenticated stack-trace echo and the pre-authorised window-state leak. Separate defects, separately reported, no score attached here.
- **CWE-1188 is deliberately not used.** No insecure default credential ships with this product; the exposure is a state, not a secret. Using CWE-1188 would imply to a reader that rotating a password closes it, which is false — creating the first administrator closes it.

### CWE and CVSS — vector derivation

Base metrics for the chain as verified:

- **AV:N** — the setup screen is served on a listener bound to `0.0.0.0:47443`; the chain needs only network reachability plus a TLS handshake against a self-signed certificate. We verified from loopback, but the shipped binding and the disabled IP restriction are artifact facts and nothing in the chain depends on local presence.
- **PR:N** — no principal is required at the start. The administrative session consumed at the sink is created by the chain itself, from an unauthenticated request. Per the metric definition, the relevant question is the least privileged principal that can reach the sink by the documented attack path, and here that principal does not need to exist beforehand.
- **UI:N** — no legitimate user acts at any point. The attacker completes setup, creates the job and runs it.
- **C:H / I:H / A:H** — LocalSystem on an MFT host reads every partner credential, key and in-transit file; rewrites configuration, jobs and content; and can halt or corrupt scheduled transfers. All three are High and none is aspirational: the read and write capability follows directly from the identity, and the availability consequence follows from control of the service and its databases.
- **S:U** — see the next subsection; this is a deliberate decision and not a default.
- **AC** — the contested metric, argued below.

The Attack Complexity decision is where this advisory has to be careful, because both readings are defensible and only one of them is honest as a headline. Exploitation requires the target to be in a state the attacker cannot create: an installation that has not yet completed first-time setup. The attacker can *discover* such targets cheaply — the setup screen renders for anyone, and a separate information leak advertises the window flag — but cannot *bring about* the condition, cannot extend it, and cannot re-open it from the network. Once the operator completes setup, the first half of the chain is permanently gone.

CVSS 3.1 places "the attack depends on conditions beyond the attacker's control" and "the attacker must gather target-specific intelligence" in Attack Complexity High. A transient deployment state that the attacker must find rather than create is squarely that. It is also the case that we never measured a typical window duration, so we cannot support a claim that the condition is ordinarily satisfied; claiming AC:L as the headline would silently assume the very deployment fact we declined to measure. So:

- **Primary: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` computes to 8.1.** Arithmetic: ISS = 1 − ((1−0.56)(1−0.56)(1−0.56)) = 1 − 0.44³ = 0.914816; Impact(S:U) = 6.42 × 0.914816 = 5.87311872; Exploitability = 8.22 × 0.85 × 0.44 × 0.85 × 0.85 = 2.2211673; Base = min(5.87311872 + 2.2211673, 10) = 8.09428602; Roundup = 8.1. Severity band High.
- **Conditional: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` computes to 9.8**, and is the correct rating *for a target confirmed to be inside its first-run window*, where the state condition has already been satisfied and the remaining attack is four form submissions and a menu click with nothing beyond the attacker's control. Arithmetic: Exploitability = 8.22 × 0.85 × 0.77 × 0.85 × 0.85 = 3.887042775; Base = min(5.87311872 + 3.887042775, 10) = 9.760161495; Roundup = 9.8. Severity band Critical.

The conditional reading is published as conditional and is not the headline score. Defenders triaging a specific installation should use it when — and only when — they have confirmed the window is open, which section 10 explains how to do. Defenders triaging a fleet or a vendor should use the primary.

### CWE and CVSS — the Scope decision

Scope is **Unchanged**, and the reasoning is worth showing because the alternative looks attractive.

The vulnerable component is the product's administration surface: the setup screen whose only predicate is a row count, and the field-validation path that accepts an arbitrary command string. The resources impacted are the same service process on the same host, running under the same LocalSystem identity the service already holds. Nothing in this chain crosses an authorization boundary managed by a *different* component from the one that was exploited: the child process is created by the service, inside the service's own token, on the service's own host.

The Scope: Changed argument is available and we rejected it. It goes: the host operating system and everything else on it are governed by Windows' authorization, not by the product's, so escaping the product's intended authority over its own configuration into arbitrary OS execution crosses a boundary between two components. That is a coherent reading, and it is the reading that produces the larger numbers — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` computes to 9.1, and `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` computes to 10.0. We do not adopt either, for two reasons. The first is consistency with how this project scores every other service-identity RCE in this corpus: execution as the same service identity on the same host does not change scope, and adopting Changed here while leaving it Unchanged elsewhere would make our numbers incomparable across advisories. The second is that the Changed reading would push the conditional case to the top of the scale, and a 10.0 headline invites exactly the "the product has no authentication" misreading this advisory spends three sections preventing. Scope: Unchanged with AC:H keeps the published number at 8.1, which we believe is the honest one.

### CWE and CVSS — what is deliberately not published

- **No 10.0 or 9.8 headline.** The 9.8 figure appears explicitly labelled as conditional on a deployment state we did not measure in the wild, and the Scope: Changed variants (9.1 and 10.0) are named only as rejected readings with their arithmetic shown.
- **No `PR:N` claim for the sink in isolation.** The job post-command field requires an administrative session; `PR:N` is a property of the chain, and reading the second half alone would yield `PR:H`, i.e. 7.2 for `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` — an administrator reaching LocalSystem, which is a privilege-separation weakness rather than a remote code execution. We publish neither half in isolation as the finding.
- **No separate score for 26.0.0.348.** That build shares the affected listing on a structural argument for the tail, and giving it its own vector would imply a measurement we did not make.
- **No CVSS attached to the sibling disclosures** (stack-trace echo, window-state leak, FTP pre-authentication fingerprint, archive-extraction overwrite behaviour). They are reported to the vendor as defects, not scored as findings.
- **No claim about window duration.** We publish no probability, no typical-hours figure and no fleet-exposure estimate, because none was measured.

### CWE and CVSS — summary

| Reading | Vector | Score | When it applies |
|---|---|---|---|
| Primary | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.1 High | Fleet- or vendor-level triage: the chain requires a deployment state the attacker cannot create |
| Conditional | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 Critical | A specific installation confirmed to be inside its first-run window |
| Rejected (scope) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` | 9.1 High | Would require treating the host OS as a separate scope from the service that already runs as LocalSystem on it |
| Rejected (scope, conditional) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 Critical | Same objection, and it would become the headline |
| Rejected (sink-only) | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 7.2 High | The command field alone, which is a documented administrator feature |

No score or vector was inherited from anywhere. The material we worked from carries no CVSS vector and no base score for this finding, so both readings above were derived from the metric definitions and the measured facts, computed with the CVSS 3.1 base formula, and rounded up to the tenth as that formula specifies. There is therefore no recorded-score correction to disclose for this advisory: there was no recorded score to correct.

---

*Published by the 0day Rubbish Research Team. Advisory: https://0day-rubbish.com/blog/southriver-titan-mft-firstrun-admin-setup-job-command-injection — Repository: https://github.com/Exploit-Garbage/0day-Rubbish — Contact: disclosure@0day-rubbish.com*
