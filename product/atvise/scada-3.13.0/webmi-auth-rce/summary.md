# atvise SCADA WebMI Default-Credential Authenticated Root RCE

## Summary

A critical authenticated remote code execution vulnerability in atvise SCADA 3.13.0 allows attackers to execute arbitrary operating system commands as `root` by chaining a default-credential login on the WebMI HTTP backend with V8 script injection. The built-in `root` user ships with a factory default empty password. The WebMI `handleLogin` handler has a "password not set" branch: for an existing user whose password was never set, it grants the superuser session WITHOUT verifying the supplied password, so `POST /webMI/?login username=root&password=<anything>` authenticates as `root` while the factory default state is in place. After authenticating, the attacker writes a V8 ScriptCode node via `POST /webMI/?AddNode` and triggers it via `POST /webMI/?ReportRunConfiguration`. The Report engine loads the attacker-controlled script and executes it in the embedded V8 engine inside the `atserver` process, which runs as `root`, so the injected script inherits root privileges and can execute arbitrary commands through the `ChildProcess` class or write files through `FileSystem` / `OutputFileStream`. Setting a strong root password via `changepassword` closes the login bypass; this is a default-credential authenticated RCE, not a password-agnostic authentication bypass.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: atvise SCADA
- **Versions**: 3.13.0 (build 4-22210f1a3) and versions using the same WebMI login handler
- **Vendor**: atvise GmbH / Bachmann Visutec GmbH

## Impact

- **Confidentiality**: Full read of any host file as root (verified by running `cat /etc/shadow`); access to all SCADA process data, node configuration, and scripts
- **Integrity**: Arbitrary operating system command execution as root; ability to alter SCADA control logic, node values, and V8 method scripts
- **Availability**: Full control of the `atserver` process (root) and the host; ability to halt or tamper with the SCADA/HMI platform

## Exploitation Prerequisites

This is a **default-credential authenticated root RCE**. The built-in `root` user ships with a factory default empty password, and the WebMI `handleLogin` handler grants the superuser session for an existing user without verifying the password while that default state is in place. The chain is reachable over the WebMI HTTP port (80 or 443), which binds to `0.0.0.0` by default. The one additional precondition is that the WEBACCESS module (which serves the HTTP endpoints) must be loaded; on a licensed production deployment this is the normal running state. The research environment had no paid license, so a binary patch simulated the licensed state; the patches are license bypasses only and do not touch the login handler or the V8 execution path. Setting a strong root password via `changepassword` closes the login bypass and breaks the chain.

## Mitigation

1. Set a strong password for the built-in `root` user immediately after installation (via `changepassword`); never leave the factory default empty password in place
2. Make `handleLogin` call `checkUserPassword` for every existing user, including those whose password was never set; remove the "password not set" branch that grants a session without password verification
3. Require an authenticated, authorized session for `AddNode` writes to ScriptCode nodes, and audit all writes to `AGENT.OBJECTS.ATVISE.Report.*` and `SYSTEM.LIBRARY.ATVISE.WEBMIMETHODS.*` nodes
4. Sandbox or restrict the V8 command-execution API (`ChildProcess.execAsync`) and the file-write API (`FileSystem` / `OutputFileStream`) — whitelist directories, disable, or require privilege
5. Validate the script source in `ReportRunConfiguration`; do not execute arbitrary attacker-injected ScriptCode

## Timeline

- **Discovered**: 2026-07-24
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
