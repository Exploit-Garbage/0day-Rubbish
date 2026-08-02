# CatDV Server Unauthenticated RMI Root RCE

## Summary

A critical unauthenticated remote code execution vulnerability in CatDV Server allows an attacker to execute arbitrary operating system commands as `root` (uid=0) without holding any product license key or user credentials. The chain combines three independent defects: an unauthenticated RMI `connect(null)` path that makes the server mint a `ClientID` using its own internal regcode, a `saveSettings` method gated only by a valid `ClientID` with no admin check, and a `ProcessUtils.exec` sink in the AAF export handler that runs an attacker-controlled `catdv.aaftoolPath` system property as root.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: CatDV Server
- **Versions**: 10.7.8 and versions using the same RMI `ConnectionManager.connect` / `RmiService.saveSettings` / `AAFExportHandler` flow
- **Vendor**: Square Box Systems (UK; MAM business acquired by Quantum)

## Impact

- **Confidentiality**: Full compromise of the media asset management server and any media/catalog metadata it holds; the CatDV process runs as root and can read any file on the host
- **Integrity**: Arbitrary operating system command execution as `root` (uid=0); ability to alter catalog data, server configuration, and system state
- **Availability**: Full control of the CatDV server process and host; ability to stop the service or destroy data

## Exploitation Prerequisites

This is an unauthenticated RCE on any **already-authorized deployment**. The single precondition is that the `client.regcode` system property is set (via `-Dclient.regcode=<license>`), which is the case for every authorized CatDV deployment — the server uses this internal regcode to mint a `ClientID` for an unauthenticated `connect(null)` caller. The attacker supplies zero credentials: Stage 1 is a zero-credential RMI call; Stage 2 uses the factory-default empty admin password (`create_catdv.sql:294` seeds `admin` with `password=0, passwordHash=NULL`). On deployments where the admin password has been changed, Stage 1 still succeeds (the unauthenticated `saveSettings` write of `aaftoolPath` does not depend on admin), but Stage 2's AAF trigger requires an admin session.

## Mitigation

1. `ConnectionManager.connect()` must not mint a `ClientID` from the server's own internal `client.regcode`; `allocateLicense` should validate licensing only and must not return the regcode for `ClientID` issuance. `ClientID` issuance must require explicit user credentials (username + password) validation.
2. `RmiService.saveSettings` must enforce an admin authorization check (`getRequestContext` should verify `currentUser.isSystemAdmin()`) before allowing writes to `type=23` server-config settings.
3. `ServerSettings.loadSettingsFromDatabase` must apply a property whitelist and reject arbitrary values for exec-path properties (`catdv.aaftoolPath`, `catdv.ffmpegPath`, `catdv.libreOfficePath`).
4. `AAFExportHandler` must not execute a path read from a mutable system property; `aaftoolPath` should be a fixed, validated binary path.
5. The factory default must not seed an empty-password `admin` account; first startup should force a password-change wizard.

## Timeline

- **Discovered**: 2026-07-27
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
