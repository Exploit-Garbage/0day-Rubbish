# CIRCUTOR PowerStudio SCADA WAVE JWT alg=none Identity Forgery (Cross-Microservice Authentication Bypass)

## Summary

An authentication-system-level vulnerability in CIRCUTOR PowerStudio SCADA WAVE 24.11.6.0 allows an unauthenticated attacker to forge any `alg=none` JSON Web Token (JWT) bearing any arbitrary `role` claim and have it accepted as a valid authenticated identity by every microservice's `AdminSecure` / `UserSecure` authorization policy. The root cause is a fail-open JWT Bearer configuration in the shared authentication library `PickData.MicroservicesShared.Infrastructure.Identity.IdentityExtensions.AddJWTBearerAuthentication`, which is referenced by every microservice's `Startup.ConfigureServices`: a custom `SignatureValidator` that always returns a non-null `JsonWebToken` without ever validating the signature, combined with `RequireSignedTokens=false`, `ValidateIssuerSigningKey=false`, `ValidateIssuer=false`, `ValidateAudience=false`, and an `OnAuthenticationFailed` handler that silently swallows exceptions. The net effect is that signature, issuer, audience, and signing-key validation are all short-circuited, so any attacker-crafted token — including an unsigned `alg=none` token — is accepted as an authenticated identity whose `role` claim decides which protected administrative endpoints it may call.

This is an authentication-bypass / identity-forgery primitive, NOT a full remote code execution by itself. It is disclosed independently because it compromises the product's entire authentication trust root: a single misconfiguration in one shared library defeats `AdminSecure` / `UserSecure` across every microservice (PSSAdministrator, PSSWidgets, PSSEvents, PSSLicense, PSSIdentity, PSSGenericDriver, PSSDataAnalytics, and others). It is also the auth-bypass primitive that enables the unauthenticated `shellExecute` SYSTEM RCE chain disclosed separately.

## CVSS Score

- **Score**: 8.6 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:L

> Rationale: this is an authentication-bypass / identity-forgery primitive, not a direct code-execution bug. Once a microservice port is reachable, an attacker can impersonate any role and call any `[Authorize]`-protected endpoint, yielding unauthorized disclosure of configuration/state (C:L), unauthorized modification of SCADA configuration, microservice/engine stop/start, and file upload/delete (I:H), and unauthorized service stop/DoS (A:L). Scope is Changed because the bypassed authentication governs multiple distinct microservice trust domains (engine control, file storage, license management, communication settings). The vector does NOT assume full SYSTEM RCE — that requires chaining additional primitives (path-traversal write + engine restart + condition-gate bypass) disclosed in a separate advisory.

## Affected Products

- **Product**: CIRCUTOR PowerStudio SCADA WAVE
- **Versions**: 24.11.6.0 and versions using the same shared JWT Bearer authentication library (`AddJWTBearerAuthentication` with the fail-open `SignatureValidator` / `RequireSignedTokens=false` configuration)
- **Vendor**: CIRCUTOR S.A. (Spain)

## Impact

- **Confidentiality**: Unauthorized read access to any `AdminSecure` / `UserSecure` endpoint across all microservices — engine state, microservice configuration, communication settings (Telegram/Mail), license status, file directory listings
- **Integrity**: Unauthorized modification of SCADA behavior — engine stop/start, microservice stop/start, configuration push, file upload/download/delete (path-traversal write precondition), external communication settings, license management. The attacker can impersonate any `Admin.<MicroserviceName>` or `User.<MicroserviceName>` role.
- **Availability**: Unauthorized stop of any microservice or the SCADA engine itself (DoS); unauthorized start/stop of administrative services running as `NT AUTHORITY\SYSTEM` (PSSAdministrator) or service accounts

## Exploitation Prerequisites

- **Authentication**: None. No credentials of any kind are required. The attacker crafts an unsigned `alg=none` JWT locally; no signing key, no issuer secret, no user account.
- **Network reachability**: The attacker must be able to reach the target microservice's HTTP/HTTPS port. Reachability varies per microservice and deployment:
  - PSSWidgets `8105` / gateway `8091`: bound to all interfaces — remotely reachable by default
  - PSSAdministrator `8089` (HTTPS): defaults to `127.0.0.1` loopback — reachable only via a same-host reverse proxy / SSRF forwarding path, a same-host entry point, an operator rebind, or a same trusted network segment
  - PSSEvents `8101` and other microservices: per deployment
- **Default configuration**: The vulnerability is present in the default configuration. The shared `AddJWTBearerAuthentication` library is referenced by every microservice, so the fail-open behavior ships by default — no operator action enables it.
- **This primitive alone does not yield RCE.** It yields unauthenticated invocation of any `[Authorize]`-protected microservice endpoint. RCE requires chaining with additional primitives (path-traversal file write + engine restart + condition-gate bypass) — see the separate `shellExecute` SYSTEM RCE advisory.

## Mitigation

1. **Remove the custom `SignatureValidator`** from the shared JWT Bearer configuration and restore the ASP.NET Core built-in signature validation. The custom delegate `(token, parameters) => new JsonWebToken(token)` is the root cause — it replaces the built-in signature check and always returns a non-null token without ever verifying the signature.
2. Set `ValidateIssuerSigningKey=true` and `RequireSignedTokens=true` so unsigned `alg=none` tokens are rejected and the issuer signing key is actually validated.
3. Set `ValidateIssuer=true` and `ValidateAudience=true`, bound to the PSSIdentity OpenIddict issuer and the known audience list, so tokens issued by any other authority are rejected.
4. In `OnAuthenticationFailed`, re-throw or fail the request instead of silently swallowing the exception and returning `Task.CompletedTask`. Authentication failures must propagate as hard failures, not be logged-and-ignored.
5. Short-term interim control: reject `alg=none` and any token with an empty signature segment at the reverse-proxy layer (PSSReverseProxy) before it reaches the microservices.
6. Remove the hardcoded default credentials (`admin` / `admin1234`, `user` / `user1234`) from the PSSIdentity seed data and force a password change on first install.
7. Rotate any previously-issued JWT signing keys after deploying the fix, on the assumption that the fail-open configuration may have allowed forged tokens to be accepted in production prior to the patch.

## Timeline

- **Discovered**: 2026-07-21
- **Public Disclosure**: 2026-08-10

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
