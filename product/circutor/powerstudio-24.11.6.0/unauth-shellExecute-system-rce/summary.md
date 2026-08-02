# CIRCUTOR PowerStudio SCADA WAVE Unauthenticated shellExecute SYSTEM RCE

## Summary

A critical remote code execution vulnerability in CIRCUTOR PowerStudio SCADA WAVE allows an unauthenticated attacker to execute arbitrary operating-system commands as `NT AUTHORITY\SYSTEM` by chaining a JWT `alg=none` authentication-bypass primitive (VULN-002) across two microservices: a path-traversal write of a malicious `default.xeve` events configuration containing a `<shellExecute>` action against PSSWidgets (port 8105), followed by an HTTP engine restart against PSSAdministrator (port 8089) that forces the `PwrStudio.exe` engine to reload the configuration and fire the shell action.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

> Note on the 8089 reachability precondition — see Exploitation Prerequisites. The 9.8 vector reflects the worst case where PSSAdministrator (8089) is reachable; under a strict default deployment where 8089 is loopback-only with no forwarding path, the chain does not close for a pure-remote unauthenticated attacker.

## Affected Products

- **Product**: CIRCUTOR PowerStudio SCADA WAVE
- **Versions**: 24.11.6.0 and versions using the same shared JWT Bearer authentication library and events `shellExecute` sink
- **Vendor**: CIRCUTOR S.A. (Spain)

## Impact

- **Confidentiality**: Full SYSTEM-level read access to the SCADA host, including configuration, project files, and any data accessible to LocalSystem
- **Integrity**: Arbitrary operating-system command execution as `NT AUTHORITY\SYSTEM`; ability to alter SCADA event configuration, engine behavior, and the underlying Windows host
- **Availability**: Full control of the `CircutorPowerStudioScadaServer` service (LocalSystem) and the host; engine stop/start and arbitrary process creation

## Exploitation Prerequisites

This is **not** a clean default-configuration remote unauthenticated 9.8. The full unauth SYSTEM RCE chain requires the attacker to reach **BOTH** microservices:

| Service | Port | Binding / Account | Role in chain |
|---------|------|-------------------|---------------|
| **PSSWidgets** | `8105` (gateway `8091`) | IIS in-process, `PSSWidgetsAppPool` (ApplicationPoolIdentity), bound to all interfaces = remotely reachable | Write `default.xeve` to `C:\ProgramData\Circutor\PowerStudio Scada\Cfg\` via `POST /api/storage/v1` path traversal (contains `<condition>1==1</condition>` + `<shellExecute>`) |
| **PSSAdministrator** | `8089` (HTTPS) | standalone .exe, `NT AUTHORITY\SYSTEM`, defaults to `127.0.0.1` (loopback) | HTTP engine restart: `PUT /api/engines/v1/{uuid}/stop\|start` forces `PwrStudio.exe` to reload `default.xeve` and trigger `shellExecute` |

- 8105 (PSSWidgets) writes the malicious configuration; 8089 (PSSAdministrator) triggers the engine restart that loads it. **Both are required**: 8105-only yields a written file that is never loaded; 8089-only has nothing malicious to load.
- **8089 reachability**: port 8089 defaults to loopback (`127.0.0.1`). It is reachable only via (a) a same-host reverse proxy / SSRF forwarding path (e.g. the PSSReverseProxy gateway on `:8091` or another microservice forwarding to `127.0.0.1:8089`), (b) a same-host entry point (e.g. after gaining local execution via the 8105 write), (c) an operator rebind to a non-loopback address or a reverse proxy exposing the admin plane, or (d) a same trusted network segment with the host firewall permitting 8089. **Under a strict default deployment (8089 loopback, no forwarding path) the chain breaks for a pure-remote unauthenticated attacker.**
- **License gate**: in a licensed paid-customer deployment the license gate already passes (no binary patch needed) — that is the real exploitable environment. The research environment required a license-gate binary patch to reproduce the `shellExecute` sink; that patch is a research reproduction aid, **NOT** an attack prerequisite.
- **JWT `alg=none` (role=Admin)** is the shared authentication-bypass primitive across both services (VULN-002 fail-open shared authentication library). No credentials of any kind are required.

## Mitigation

1. Remove the custom `SignatureValidator` from the shared JWT Bearer configuration; restore ASP.NET Core built-in signature validation and set `ValidateIssuerSigningKey=true`, `RequireSignedTokens=true`, `ValidateIssuer=true`, `ValidateAudience=true` bound to the PSSIdentity OpenIddict issuer
2. Reject `alg=none` and unsigned tokens at the reverse-proxy layer (PSSReverseProxy) as a short-term interim control
3. Require strong authentication (MFA / re-authentication) for the engine stop/start endpoints (`PUT /api/engines/v1/{uuid}/stop|start`) — these are high-risk administrative operations
4. Disable the `shellExecute` event action by default; require explicit license + administrator confirmation, and restrict it to a command allowlist
5. Run the engine (`PwrStudio.exe`) under a least-privilege service account instead of `LocalSystem`
6. Bind PSSAdministrator (8089) strictly to loopback and document that exposing it externally is unsupported; ensure no reverse-proxy rule forwards external traffic to `127.0.0.1:8089`

## Timeline

- **Discovered**: 2026-07-21
- **Public Disclosure**: 2026-08-10

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
