# vMix 29 ScriptStartDynamic VBScript Blocklist Bypass RCE

## Summary

A critical remote code execution vulnerability in vMix 29 allows attackers to execute arbitrary operating system commands by abusing the `ScriptStartDynamic` HTTP API function. vMix attempts to sandbox user-supplied VB.NET scripts with a 6-item substring blocklist, but the compilation template injects `Imports System.Diagnostics` into the code before the user's payload, so an attacker can call `Process.Start(...)` directly without ever writing the blocked substring `System.Diagnostics` in their own code. With the Web Controller's default blank password, the entire `/api` route is reachable without authentication, yielding an unauthenticated RCE as the user running `vMix64.exe` (commonly `administrator`).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: vMix 29
- **Versions**: 29.0.0.48 and versions using the same `ScriptStartDynamic` / `VBScriptProvider` blocklist template
- **Vendor**: Studio Coast Pty Ltd

## Impact

- **Confidentiality**: Arbitrary file read as the vMix64.exe run identity (commonly `administrator`); full host compromise
- **Integrity**: Arbitrary operating system command execution and arbitrary file write (`File.WriteAllText` via the same blocklist bypass)
- **Availability**: Full control of the host running the vMix64 process

## Exploitation Prerequisites

The RCE primitive (blocklist bypass -> arbitrary VB.NET compilation -> `Process.Start` -> OS command execution) was **dynamically confirmed** by loading the real `vMix64.exe` v29.0.0.48 assembly through a reflection isolation harness and invoking the real `vMix.Scripting.VBScriptProvider.Compile` end-to-end. The marker file written by `whoami` confirmed execution as `<windows-host>\administrator`.

The **unauthenticated HTTP route** (`/api` -> `ScriptStartDynamic` -> `VBScriptProvider.Compile(Value)`) was confirmed **statically** via decompilation plus an independent re-analysis adversarial gate. Each hop of the route chain was verified, and the default-blank-password authentication gate (`e()` returning `flag=true` when the password field is empty) was confirmed in the decompiled `szzzzzx.cs` and in the official vMix documentation ("If password is blank, no login will be required, regardless of the access settings").

The **full end-to-end HTTP E2E** (raw socket -> port 8088 -> RCE) was **not** dynamically run. vMix64.exe requires a GUI/D3D hardware initialization path to start the Web Controller; the available test environments (a cloud ECS instance without GPU, and an offline GPU VM) could not bring port 8088 to a listening state. The Python exploit script and a PowerShell PoC are provided to complete the HTTP E2E on a GPU-equipped Windows host.

Additional conditions: the target must be running a vMix edition that includes the `ScriptStartDynamic` dynamic scripting function (4K/Pro), the Web Controller must be enabled on port 8088 (default), and the attacker must be able to reach that port. The default "Restrict access to LAN only" setting is ON but is routinely disabled by operators for remote production, and LAN reachability is itself an unauthenticated RCE condition.

## Mitigation

1. Replace the substring blocklist with a whitelist sandbox; only explicitly declared safe APIs should be resolvable from user scripts. A blocklist is always behind the attacker.
2. Remove `Imports System.Diagnostics`, `Imports System.IO`, and `Imports System.Net` from the compilation template `b(code)`. If scripts need file/network/process capability, expose it through a controlled `API` object rather than importing entire .NET namespaces.
3. Do not default `WebServerPassword` to blank. Force the operator to set a password on first launch, or default `WebServerEnabled` to `False`.
4. Disable `ScriptStartDynamic` by default; dynamic script compilation from an HTTP parameter is a high-risk feature and should require explicit opt-in plus authentication.
5. Run `vMix64.exe` under a dedicated low-privilege service account rather than an operator/administrator account; the Web Controller should run reduced-privilege.

## Timeline

- **Discovered**: 2026-07-24
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
