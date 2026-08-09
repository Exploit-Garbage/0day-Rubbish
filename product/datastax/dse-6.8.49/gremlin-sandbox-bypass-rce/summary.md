# DataStax Enterprise (DSE) Gremlin-Groovy Sandbox Bypass Unauthenticated RCE

## Summary

A critical unauthenticated remote code execution vulnerability in DataStax Enterprise (DSE) 6.8.49 arises because the Gremlin Server (WebSocket 8182, default `allowAll` no-auth) enables the gremlin-groovy sandbox (`DseGraphKohsukeSandboxFilter` + kohsuke `SandboxTransformer`), but the sandbox only applies to the top-level submitted script. `groovy.lang.Script.evaluate(String)` (inherited by `DseScript`) creates a fresh `GroovyShell` WITHOUT the `SandboxTransformer`, so a nested string is evaluated in a sandbox-free environment. An attacker submits a Gremlin script whose top level calls `this.evaluate("<nested script>")`; the nested script runs `["/bin/sh","-c","<cmd>"].execute().text`, yielding arbitrary system command execution as the `dse` user (uid=999, groups include 0(root)). Dynamically verified.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: DataStax Enterprise (DSE)
- **Versions**: 6.8.49 (Docker `datastax/dse-server:6.8.49` with DSE Graph enabled)
- **Vendor**: DataStax

## Impact

- **Confidentiality**: Full read of the host filesystem and configuration as the `dse` user (uid=999, groups include root)
- **Integrity**: Arbitrary OS command execution
- **Availability**: Full control of the DSE host and database services

## Exploitation Prerequisites

Default configuration: `gremlin_server:` `[authentication]` section commented out = TinkerPop default `allowAll` authenticator (no auth); `sandbox_enabled` defaults to `true` (`orElse(true)`), so the bypass works WITH the sandbox enabled (a real vulnerability, not a "disable sandbox" misconfiguration). Network reachability to the Gremlin WebSocket port (default 8182). Dynamically verified with `uid=999(dse)` + groups containing root.

## Mitigation

1. Enable Gremlin Server authentication (`[authentication]` with username/password or LDAP) so the WebSocket endpoint is not `allowAll`
2. Disable or sandbox `groovy.lang.Script.evaluate(String)` — the nested GroovyShell must carry the same `SandboxTransformer` (or the evaluate path must be blocked)
3. Run DSE under a dedicated non-root user without root group membership
4. Restrict network exposure of the Gremlin WebSocket port to trusted networks
5. Apply upstream patches when DataStax releases a fix for the sandbox bypass

## Timeline

- **Discovered**: 2026-08-08
- **Public Disclosure**: 2026-08-09 (batch #3)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
