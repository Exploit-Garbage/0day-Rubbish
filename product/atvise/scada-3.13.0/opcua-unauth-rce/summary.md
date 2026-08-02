# atvise SCADA OPC UA Authentication Bypass Unauthenticated Root RCE

## Summary

A critical unauthenticated remote code execution vulnerability in atvise SCADA 3.13.0 allows attackers to execute arbitrary operating system commands as `root` by chaining an OPC UA authentication bypass with V8 script injection. The OPC UA binary protocol backend on port 4840 (`logonSessionUser` / `createAtvSession`) does not call the password-verification function and accepts any non-empty password for the built-in `root` user, independent of the WebMI HTTP authentication backend. After bypassing OPC UA authentication, the attacker overwrites a built-in WebMI method's V8 script code via an OPC UA write, then triggers the tampered script through an anonymous WebMI HTTP session (digest bypass). The V8 engine runs inside the `atserver` process, which executes as `root`, so the injected script inherits root privileges and can execute arbitrary commands through the `ChildProcess` class or write files through `FileSystem` / `OutputFileStream`.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: atvise SCADA
- **Versions**: 3.13.0 (build 4-22210f1a3) and versions using the same dual-backend authentication model
- **Vendor**: atvise GmbH / Bachmann Visutec GmbH

## Impact

- **Confidentiality**: Full read of any host file as root (verified by reading `/etc/shadow`); access to all SCADA process data, node configuration, and scripts
- **Integrity**: Arbitrary operating system command execution as root; ability to alter SCADA control logic, node values, and V8 method scripts
- **Availability**: Full control of the `atserver` process (root) and the host; ability to halt or tamper with the SCADA/HMI platform

## Exploitation Prerequisites

This is a **default-configuration unauthenticated root RCE**, but it carries one honest precondition specific to commercial SCADA licensing. Ports 4840 (OPC UA) and 80 (WebMI HTTP) bind to `0.0.0.0` by default, `root` is a built-in user, and `GetDataType` is a built-in WebMI method — all default. The chain is reachable even when a strong root password is set, because the OPC UA authentication backend does not verify the password at all (it is independent of the WebMI HTTP backend, which does verify passwords strictly). The one precondition is that the WEBACCESS module (which serves the HTTP endpoints on 80/443) must be loaded; on a licensed production deployment this is the normal running state. The research environment had no paid license, so a binary patch simulated the licensed state. Adversarial byte-level comparison confirmed that all six patches are license bypasses only — none touch the OPC UA authentication functions (`logonSessionUser` / `createAtvSession`) or the V8 execution path. The vulnerability is a native product defect present in a real licensed deployment under its default running configuration.

## Mitigation

1. Make `ServerConfigAtvise::logonSessionUser` call `checkUserPassword` (the same backend used by WebMI HTTP) and verify the `PasswordHasher` against the `UserNameIdentityToken` password field
2. Restrict write access to `SYSTEM.LIBRARY.ATVISE.WEBMIMETHODS.*` nodes to engineer/admin roles, and audit all writes to these nodes
3. Sandbox or restrict the V8 file-write API (`FileSystem` / `OutputFileStream`) — whitelist directories, disable, or require privilege
4. Require an authenticated session for built-in WebMI method dispatch; do not allow anonymous digest-bypass sessions to schedule methods such as `GetDataType`

## Timeline

- **Discovered**: 2026-07-25
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
