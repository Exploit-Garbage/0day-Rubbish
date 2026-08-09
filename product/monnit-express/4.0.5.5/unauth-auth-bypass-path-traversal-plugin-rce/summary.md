# iMonnit Express Unauthenticated Auth Bypass + Path Traversal + Plugin Load SYSTEM RCE

## Summary

A critical unauthenticated remote code execution chain in iMonnit Express 4.0.5.5 (ASP.NET Core 3.1 + Kestrel + SQLite, Windows service running as **LocalSystem**) combines three flaws, all reachable without credentials in the default configuration:

1. **Auth bypass (CWE-287)**: `AccountController.CheckAnswer` (line 177, no `[Authorize]`) iterates the user's `SecurityAnswer` list; when the list is empty (the default admin has a password but no security questions), the `foreach` loop is skipped and `SignInAsync` issues a valid admin cookie for any attacker.
2. **Path-traversal file write (CWE-22)**: `GatewayController.CertUpload` (line 700, `[Authorize]` but reachable with the forged cookie) computes `path = CertSaveFolder + file.FileName` with no sanitization and writes synchronously via `file.CopyTo`, so a filename like `..\..\..\Windows\Temp\evil.dll` writes an arbitrary file (the gateway-ID check is a bare `Redirect(...)` without `return`, so it is ineffective).
3. **Plugin-load RCE (CWE-502/915)**: `Plugin.StartPlugins` (line 197-233) does `Assembly.Load(File.ReadAllBytes(path))` then `Activator.CreateInstance(type)` on the plugin's parameterless constructor **before** the `is IExpressPlugin` check — the attacker-controlled `Path`/`Class` come from the unauthenticated `ConfigurePlugin` (line 25, no `[Authorize]`), and the ctor runs as **LocalSystem**.

Dynamically verified: marker file `owner=BUILTIN\Administrators`, `whoami` = `nt authority\system`, executed inside the `Express_Core` service process.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: iMonnit Express
- **Versions**: 4.0.5.5
- **Vendor**: Monnit / iMonnit

## Impact

- **Confidentiality**: Full read of the host filesystem and configuration as NT AUTHORITY\SYSTEM
- **Integrity**: Arbitrary OS command execution as SYSTEM
- **Availability**: Full control of the iMonnit Express host; ability to persist

## Exploitation Prerequisites

Default configuration; network reachability to the HTTPS port (default 8444). The plugin system exists by default (PluginID=1 default record); `EnablePlugins` can be turned on via the unauthenticated `SettingsEdit`; the service runs as LocalSystem by default. The auth bypass requires a **real existing user whose SecurityAnswer list is empty** — the default admin created at first-run has a password but no security questions, satisfying this. The attacker supplies all payloads (command file + runner DLL) through the same path-traversal primitive — no pre-existing file on the target is required. Dynamically verified as `nt authority\system`.

## Mitigation

1. Add a global `[Authorize]` filter (or `[Authorize]` on `CheckAnswer`, `ConfigurePlugin`, `TogglePlugin`, `SettingsEdit`, `CertUpload`)
2. Require the security-answer check to fail closed when the list is empty (do not sign in)
3. Sanitize/allowlist the upload filename in `CertUpload` (reject `..`, validate extension/path against the cert folder)
4. Move the `is IExpressPlugin` check BEFORE `Activator.CreateInstance`, and restrict plugin loading to a signed allowlist of assemblies
5. Run the service under a low-privilege account instead of LocalSystem

## Timeline

- **Discovered**: 2026-07-24
- **Public Disclosure**: 2026-08-09 (batch #3)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
