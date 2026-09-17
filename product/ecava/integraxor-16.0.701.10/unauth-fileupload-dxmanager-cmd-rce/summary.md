# Ecava IntegraXor IGX — Unauthenticated /FileUpload Arbitrary Write Chained to dxmanager cmd.exe /C Sink: Administrator RCE

## Summary

Ecava IntegraXor IGX 16.0.701.10 (vendor: Ecava Sdn Bhd, Malaysia) is a closed-source 100% HTML5 Web SCADA HMI for manufacturing OT / CII environments. Its DX Web HMI server (`dxweb.exe`, ASP.NET Core 8.0 Kestrel, default port 8081) has zero authentication: the full decompiled routing module `WEB_Module.cs` (481 lines) carries no `[Authorize]`, no authentication middleware, and no auth filter, and its `/FileUpload` endpoint concatenates the attacker-controlled `copyTo` directory and `file.FileName` straight into `FileStream(..., FileMode.Create)` — unauthenticated arbitrary file write to any path the process can create. That write primitive chains into full RCE through the DX Manager orchestrator (`dxmanager.exe`): at startup, `GetTask()` enumerates every `*.json` file in the configuration directory (when `dxmanager.csv` is absent) and, for each entry whose `meta.name` is not `"dxmanager"`, `CreateProcess()` runs `cmd.exe /C <meta.name>` via `Process.Start` with no sanitization of any kind. Two unauthenticated `POST /FileUpload` requests — planting a `.bat` payload (e.g. `C:\Windows\Temp\igx_payload.bat`) and a JSON descriptor (`{"meta":{"name":"C:\\Windows\\Temp\\igx_payload.bat"}}`) into the dxmanager configuration directory — yield arbitrary command execution at the next dxmanager start/restart (system reboot, module update, crash auto-recovery via the igsvc watchdog, or unauthenticated MQTT `Command.Restart`). The chain was dynamically verified end-to-end on a default-configuration Windows Server 2025 lab target: both uploads returned HTTP 200 with no credentials sent, and the executed bat wrote a marker whose `whoami` line reads `<lab-host>\administrator` with file owner `BUILTIN\Administrators`. Both preconditions — dxweb exposed on 8081 and dxmanager running — are the product's default configuration. IntegraXor's six historical CVEs all target 4.x (2010–2014) and repeatedly featured unauthenticated file-write/path-traversal patterns; no public CVE covers the current v16 line to our knowledge.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Ecava IntegraXor IGX (Web SCADA HMI; dxweb + dxmanager components)
- **Versions**: 16.0.701.10 verified; releases shipping the same zero-authentication dxweb `/FileUpload` endpoint and dxmanager `GetTask`/`CreateProcess` logic are likely affected (not separately verified)
- **Vendor**: Ecava Sdn Bhd (Malaysia)
- **Prerequisites**: default configuration — dxweb exposed on port 8081 + dxmanager running; no credentials at any step; payload executes at the next dxmanager restart (inevitable in real deployments)

## Impact

- **Confidentiality**: administrator-level read access to process data reaching the HMI, project files (`.igx`), configuration, and licensing material on the SCADA server
- **Integrity**: HMI tampering — the attacker controls what operators see; production-process manipulation; potential damage to physical equipment through the control system in CII manufacturing settings
- **Availability**: HMI, orchestrator, and host can be stopped, corrupted, or repurposed at will
- **Execution identity**: administrator — verified marker `<lab-host>\administrator`, marker owner `BUILTIN\Administrators`
- **Lateral movement**: complete takeover of an ICS host positioned in the OT environment is a pivot into the control network
- Separately noted: an additional unauthenticated file-read primitive on the same dxweb component was observed during research and is documented separately; this advisory does not assert a verification status for it.

## Mitigation

1. Add authentication to dxweb (`[Authorize]` + middleware) on `/FileUpload` / `/FileDownload` and any state-changing endpoint
2. Whitelist `/FileUpload` paths: constrain `copyTo` to a project data directory; reject absolute paths, `..`, and special characters; enforce an extension whitelist
3. Harden the dxmanager sink: never execute `meta.name` as a raw command line — use a controlled module-name-to-path mapping with character whitelist and installation-directory containment
4. `GetTask` should load only modules declared in the trusted `dxmanager.csv`, not enumerate arbitrary `*.json`
5. Enable MQTT authentication by default (`pwdFile` must not be empty; broker auth on mosquitto:1883) so `Command.Restart` cannot be issued anonymously
6. Interim operator hardening: keep ports 8081 / 3881 / 4881 / 1883 off untrusted networks; restrict HMI access to the trusted operator segment
