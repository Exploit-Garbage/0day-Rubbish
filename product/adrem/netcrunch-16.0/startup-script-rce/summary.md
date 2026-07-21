# AdRem NetCrunch Startup Script RCE

## Summary

An authenticated remote code execution vulnerability in AdRem NetCrunch v16.0.0.8397 RC. The `INcStartupScript.SetScriptOptions` RPC interface lets an authenticated user persist an arbitrary executable path plus command-line arguments to the registry (StartupScript.Cmd/Parameters/WaitFor/Timeout), with no command allowlist or path validation. The `INetCrunchServer.RestartNCServer` RPC interface then triggers an NCServer service restart, and the restart's Initializing phase runs `TStartupScriptExecutor.ExecuteScript` to execute the persisted cmd+params. NCServerSvc runs as LocalSystem, so this is SYSTEM-privilege arbitrary code execution. `RestartNCServer` is a pure RPC method that triggers the restart without needing shell / service-management privileges.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: AdRem NetCrunch (Windows-native network monitoring system)
- **Versions**: 16.0.0.8397 RC and versions exposing the same `INcStartupScript.SetScriptOptions` / `INetCrunchServer.RestartNCServer` RPC methods
- **Vendor**: AdRem Software

## Impact

- **Confidentiality**: Full SYSTEM-level read of the NetCrunch server host
- **Integrity**: Arbitrary SYSTEM command execution; ability to alter monitoring configuration and persisted data
- **Availability**: Full control of the NetCrunch server; can stop/disable the monitoring service

## Exploitation Model

This is a Target A (network service) vulnerability, on the authenticated path. The Node.js web layer listens on port 9443 by default. Authentication is enforced by the Delphi backend (NCServer.exe); any valid login credential works (admin or a normal user). Credentials are obtainable via `nccli.exe reset-admin-password` (resets the admin password to a random value) or via the default `admin`/`+` credentials in the factory state. `INcStartupScript.SetScriptOptions` and `INetCrunchServer.RestartNCServer` are available by default with no extra privilege check. Default install is vulnerable with no special configuration.

## Mitigation

1. Add an authorization check to `INcStartupScript.SetScriptOptions`: only admins may set the startup script
2. Enforce a command allowlist: restrict `cmd` to predefined script paths, disallow arbitrary executables
3. Filter arguments: disallow shell metacharacters (`&`/`|`/`>`/`<`/`;`, etc.)
4. Tighten `RestartNCServer` permissions: only admins may trigger a service restart
5. De-privilege the service: NCServerSvc should not run as LocalSystem; use a low-privilege service account

## Timeline

- **Discovered**: 2026-07-17
- **Public Disclosure**: 2026-07-18

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).