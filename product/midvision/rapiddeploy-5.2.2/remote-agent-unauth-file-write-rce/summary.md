# MidVision RapidDeploy Remote Agent Unauthenticated Arbitrary File Write RCE

## Summary

MidVision RapidDeploy 5.2.2's remote agent (JBoss Remoting bisocket, port 20000) ships with `host=0.0.0.0` and an empty `auth.servers` in the default agent template. `SecureServerInvocationHandler.isAuthorised` returns `true` when `authServers` is empty (or in backward-compatibility mode with null credentials), so an unauthenticated attacker can invoke the `RapidDeployCopyHandler`, which writes attacker-controlled bytes to an attacker-controlled path as root. Writing a cron job into `/etc/cron.d/` yields root RCE. The built-in agent (127.0.0.1) uses the same code path and sink. Dynamically verified (`uid=0(root)`).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: MidVision RapidDeploy
- **Versions**: 5.2.2
- **Vendor**: MidVision

## Impact

- **Confidentiality**: Full read/write of host filesystem as root
- **Integrity**: Arbitrary file write as root (cron, webroot, startup scripts)
- **Availability**: Full control of the agent host

## Exploitation Prerequisites

Default remote-agent template: `host=0.0.0.0`, `auth.servers` commented out (empty); agent process runs as root; network reachability to port 20000 (or 20443 SSL).

## Mitigation

1. Do not default-open when `auth.servers` is empty — refuse to start or require configuration
2. Remove the `authServers.isEmpty() -> true` and backward-compatibility null-credential short-circuits
3. Whitelist `filePath` in `CopyHandler` (no absolute paths, no `/etc/cron.d`, webroot, or startup scripts)
4. Enable mutual TLS on bisocket by default
5. Change the remote-agent template default host to `127.0.0.1`

## Timeline

- **Discovered**: 2026-08-09
- **Public Disclosure**: 2026-08-12 (batch #4)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble.
