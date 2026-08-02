# CatDV Server Authenticated aaftoolPath Root RCE

## Summary

An authenticated remote code execution vulnerability in CatDV Server allows an administrator to execute arbitrary operating system commands as `root` (uid=0). The type-23 "server-config" setting is applied verbatim as JVM `System.setProperty(key, value)` pairs by `ServerSettings.loadSettingsFromDatabase` with no property whitelist, so an admin can inject `catdv.aaftoolPath` to point at an attacker-controlled script. `AAFExportHandler.java:97` reads that system property on every AAF export request and `ProcessUtils.exec`s it at L111 with the server process privileges (root). The injected property is auto-applied by `CacheManager.checkCaches` on the next request (1s throttle), so no server restart is needed. This is the authenticated variant of the CatDV root RCE problem; the unauthenticated chain is tracked separately.

## CVSS Score

- **Score**: 7.6 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: CatDV Server
- **Versions**: 10.7.8 and versions using the same `ServerSettings.loadSettingsFromDatabase` / `AAFExportHandler` flow
- **Vendor**: Square Box Systems (UK; MAM business acquired by Quantum)

## Impact

- **Confidentiality**: Full compromise of the media asset management server and any media/catalog metadata it holds; the CatDV process runs as root and can read any file on the host
- **Integrity**: Arbitrary operating system command execution as `root` (uid=0); ability to alter catalog data, server configuration, and system state
- **Availability**: Full control of the CatDV server process and host; ability to stop the service or destroy data

## Exploitation Prerequisites

This is an **authenticated** RCE. The attacker needs an admin session on the CatDV web API (port 8181). In practice the bar is low because the factory-default `admin` account is seeded with an empty password (`create_catdv.sql:294`), but that default-credential defect is tracked as a separate advisory; this advisory treats admin credentials as a given precondition. Once an admin session exists, the attacker (1) `PUT /catdv/api/1/settings/server-config/{id}` to inject `catdv.aaftoolPath=/tmp/evil.sh`, and (2) `GET /catdv/api/1/clips?fmt=aaf&clipListID=1` with an empty clipList to reach the `ProcessUtils.exec` sink. The CatDV process must run as root for the exec to yield root (the default deployment runs as root).

## Mitigation

1. `ServerSettings.loadSettingsFromDatabase` must apply a property whitelist and reject arbitrary values for exec-path properties (`catdv.aaftoolPath`, `catdv.ffmpegPath`, `catdv.libreOfficePath`).
2. `AAFExportHandler` must not execute a path read from a mutable system property; `aaftoolPath` should be a fixed, validated binary path, not a `System.getProperty` read.
3. The settings PUT handler should validate the admin identity and reject writes that set exec-path properties to non-whitelisted binaries.
4. The exec path should be validated as a known, trusted binary rather than accepting an arbitrary script path.
5. The factory default must not seed an empty-password `admin` account; first startup should force a password-change wizard.

## Timeline

- **Discovered**: 2026-07-27
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
