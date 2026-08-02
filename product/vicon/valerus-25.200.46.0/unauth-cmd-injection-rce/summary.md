# Vicon Valerus Unauthenticated Command Injection RCE

## Summary

A critical remote code execution vulnerability in Vicon Valerus ViconNet Gateway allows attackers to execute arbitrary operating system commands as `nt authority\system` without any authentication. The Web API endpoint `POST /NVR/api/v1/upgrades/multiformat-file-Execute/start` receives a user-supplied command string, concatenates it directly to `cmd.exe /c`, and executes it via `Process.Start`. The entire OWIN middleware pipeline has no authentication middleware, the `UpgradesController` lacks the `[Authorize]` attribute, and the `SetupExecuteCommand` method bypasses the `UpgradeAuthorizationFlag` gate that protects the sibling `Upgrade()` method. The service runs as `LocalSystem`, so an unauthenticated attacker with network access to the Web API port immediately obtains Windows highest-privilege remote code execution.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Vicon Valerus ViconNet Gateway (VMS)
- **Versions**: 25.200.46.0 and versions using the same `UpgradesController.SetupExecuteCommand` flow
- **Vendor**: Vicon Industries

## Impact

- **Confidentiality**: Full system compromise as `nt authority\system`; access to all recorded video, camera credentials, and VMS configuration
- **Integrity**: Arbitrary operating system command execution as `LocalSystem`; ability to alter video surveillance state and tamper with evidence
- **Availability**: Full control of the `VII ViconNet Gateway` Windows service and the underlying host

## Exploitation Prerequisites

This is a **default-configuration unauthenticated RCE**. The only prerequisite is network reachability to the Web API port (8084/8444 in the tested deployment, or whichever port is configured in `Data\network-settings.xml`). No credentials, session, cookie, or prior state are required. The vulnerable route is registered by default on `UpgradesController` and there is no configuration switch to disable it. Vicon Valerus is deployed in physical-security monitoring networks and is commonly paired with an Internet Gateway module for remote access, making public exposure a realistic scenario.

## Mitigation

1. Add an `[Authorize]` attribute to `UpgradesController`, or introduce a global authentication middleware in the OWIN pipeline — currently none of the 8 registered middlewares perform authentication
2. Make `SetupExecuteCommand` check `UpgradeAuthorizationFlag` the same way `Upgrade()` does, and require authentication on the flag-setting endpoint
3. Replace the `cmd.exe /c` + user-input pattern in `ExecuteCommandCommonHelper.ExecuteCommand` with a parameterized `ProcessStartInfo.FileName` + `ArgumentList` and a command whitelist
4. Run the `VII ViconNet Gateway` service under a dedicated low-privilege account instead of `LocalSystem`
5. Move upgrade/maintenance command execution off the HTTP Web API onto a local-only RPC channel with authentication, authorization, and audit logging

## Timeline

- **Discovered**: 2026-07-19
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).