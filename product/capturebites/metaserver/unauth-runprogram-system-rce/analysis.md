# CaptureBites MetaServer — Unauthenticated SYSTEM RCE Through the Workflow RunProgram Sink

## 1. Overview

CaptureBites MetaServer (vendor: CaptureBites) is a closed-source, commercial document-capture and distribution automation server: it ingests scanned documents and images, processes them through configurable workflows (import, metadata extraction and indexing, distribution by e-mail, link or folder drop), and hands the results to downstream back-office systems. It is delivered as a Windows service named `MetaServer` (executable `MetaService.exe`) that runs under `NT AUTHORITY\SYSTEM`. Its entire control plane is a self-hosted WCF SOAP service listening on `0.0.0.0:8733`, with every contract bound over `basicHttpBinding` at `security=None`.

Static analysis found that no `ServiceAuthorizationManager`-derived class is registered with the ServiceHost and that no custom `IParameterInspector` / `IDispatchMessageInspector` validates a caller token, so the WCF runtime performs no authorization at all: all six exposed services are anonymously reachable (CWE-306). On top of that anonymous surface, workflow management is itself unauthenticated — creating a workflow, uploading its definition, activating it and triggering document processing all succeed without credentials (CWE-862). A workflow definition may contain a `RunPrograms` action, and applying that action calls `Process.Start` on the attacker-supplied `Program` with the attacker-supplied `Arguments`, with no allowlist, no escaping and no privilege drop (CWE-78). Chained together, these three defects give an unauthenticated remote attacker code execution as `NT AUTHORITY\SYSTEM` over four plain-HTTP SOAP requests.

The research ran in four stages, and this advisory follows that path: (1) attack-surface discovery — the SOAP listener, its six endpoints, their bindings and the absence of any authorization hook were established from the decompiled assembly, and remote reachability was confirmed by Host-header testing against http.sys; (2) sink localization — the workflow action chain was traced to `RunProgramSettings.Apply()` and its `Process.Start` call, together with the service identity it inherits; (3) chain construction — a malicious `.CBMSWorkflow` definition was authored in the product's own TextSerializer format and the four anonymous operations were assembled into a working exploit script; (4) dynamic verification — the chain was executed against a running MetaServer deployment and confirmed by marker files written by the SYSTEM-side process.

## 2. Vulnerability Summary

- **Type**: unauthenticated remote code execution — anonymous WCF SOAP surface (CWE-306) + missing authorization on workflow upload/activate/trigger (CWE-862) + arbitrary program execution in the `RunPrograms` workflow action (CWE-78)
- **Entry points**: `POST /CaptureBites/MetaServer/Services/WorkflowService/`, `.../TransferService/`, `.../RestService/` on TCP 8733 (SOAP 1.1, `SOAPAction: "http://tempuri.org/I<Service>/<Operation>"`)
- **Preconditions**: network access to TCP 8733 only. No credentials, no default account, no session, no user interaction, no man-in-the-middle position
- **Root cause**: the WCF host registers no authorization manager and no inspector that authenticates callers, while the workflow engine exposes an unrestricted "run a program" action to whoever can write a workflow definition
- **Sink**: `RunProgramSettings.Apply()` -> `Process.Start(new ProcessStartInfo { FileName = Program, Arguments = Arguments, UseShellExecute = false })`, inheriting the `NT AUTHORITY\SYSTEM` token of `MetaService.exe`
- **Result**: arbitrary command execution as SYSTEM on the MetaServer host. CVSS 9.8 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Affected target**: MetaServer (.NET Framework 4.8, self-hosted WCF SOAP) — version as recorded in our research; the exact build is not stated in the research record. Any MetaServer deployment whose SOAP listener is network-reachable and whose workflow actions include `RunPrograms` is affected by the same design.
- **Target class**: A (unauthenticated RCE) — the full chain is anonymous, credential-free, MITM-free and remotely reachable

## 3. Product & Architecture

MetaServer is a Windows service, not a web application hosted in IIS. `MetaService.exe` runs as `NT AUTHORITY\SYSTEM` and self-hosts the WCF ServiceHost in-process; the HTTP listener is served by the kernel `http.sys` driver (PID 4). The binding observed in the decompiled configuration is `basicHttpBinding` with `security=None`: plain HTTP, no transport credentials, no message security. The listener is bound to `0.0.0.0:8733`, i.e. to every interface.

**Service identity.** The research record documents the service identity as `NT AUTHORITY\SYSTEM` for the `MetaServer` service (`MetaService.exe`). Two independent observations support it: the anonymous `ServerInfoService` reports the runtime user as `SYSTEM` (`user=SYSTEM`), and the `whoami` marker produced by the exploit contains `nt authority\system` (Section 8).

**Endpoints.** Six WCF services are published under the common path template `http://<host>:8733/CaptureBites/MetaServer/Services/<Service>/`:

| Service | Role in the product | Operations used by the chain |
|---|---|---|
| `ServerInfoService` | server information | (anonymous info disclosure: reports `user=SYSTEM`) |
| `DatabaseService` | database operations | not needed |
| `LicenseService` | license management | not needed |
| `WorkflowService` | workflow CRUD and activation | `CreateWorkflow`, `ChangeWorkflows` |
| `RestService` | document-processing trigger | `CreateDocument` |
| `TransferService` | definition upload/download | `UploadDefinition` |

**Remote reachability.** Because the listener sits behind http.sys, whether the service can be driven from another machine was verified directly rather than assumed: requests were replayed with arbitrary `Host:` headers and http.sys dispatched all of them, host-agnostically, to the same service set. Combined with the `0.0.0.0` binding, the SOAP surface is reachable from any host that can route to TCP 8733 — it is not a loopback-only interface.

**Workflow definitions.** A workflow is stored as a `.CBMSWorkflow` file in a line-based TextSerializer format (version marker 11; each line is `<value-length>,<value>`, CR-LF separated). A definition contains an ordered list of actions — among them `ImportFromWebService`, `RunPrograms` and `Distribute` — and each action carries its own settings block. Action settings are rehydrated by `WorkflowDefinition.Deserialize`. The embedded PoC definition also carries the product's distribution vocabulary (`Link_XML`, `Link_PDF`, `Link_HTML`, `Attachment_PDF`, `Body_PDF`, `Email_PDF`, `Email_EML`, `Email_MSG`, `Processed_PDF`, ...) and an output folder path `C:\CaptureBites\MetaServer\Log_Processed`, which is what identifies this server's role as the document-capture/distribution stage of a back-office pipeline.

## 4. Authentication Boundary

**What the record proves about the missing authentication.** The conclusion rests on static facts plus a dynamic check, not on inference:

- all service contracts use `basicHttpBinding` with `Security.None` — there is no transport-level or message-level authentication to satisfy;
- **no `ServiceAuthorizationManager`-derived class is registered with the ServiceHost**, so the WCF runtime never calls an authorization decision point;
- **no custom `IParameterInspector` or `IDispatchMessageInspector`** performs authentication-token validation anywhere in the dispatch pipeline;
- anonymously, `ServerInfoService` already answers with server information including the runtime user (`user=SYSTEM`);
- all four chain operations were driven with no authentication header and no credentials, and every one returned HTTP 200 (Section 8).

**What was excluded from the chain.** The finding deliberately does not rely on any of the usual shortcuts:

- **No hardcoded or default credentials.** The chain is purely anonymous WCF plus the `RunProgram` sink; nothing in it depends on a shipped account or a guessed password.
- **No man-in-the-middle position.** Everything travels over plain HTTP that the attacker originates; no relay, no interception, no downgrade is needed.
- **No user interaction.** No operator has to open anything; `CreateDocument` is self-triggered by the caller.
- **License gate — disclosed honestly.** `UploadDefinition` and `CreateDocument` sit behind the product's `LicenseManager` (`LicenseStatus` / `LicenseCount`). In the research environment this gate was neutralized by a Mono.Cecil bytecode patch (`LicenseStatus -> 2 (Licensed)`, `LicenseCount -> 1000`), and the dynamic verification in Section 8 ran against that patched DLL. The research record classifies the gate as a *commercial feature* gate rather than a security boundary and records it as not a precondition of the vulnerability; the published PoC contains no patch and performs only the four anonymous SOAP steps. Readers should weigh this when reasoning about unlicensed trial deployments.
- **Unauthenticated-surface exhaustion gate skipped.** Two further anonymous services (`DatabaseService`, `LicenseService`) exist and were not enumerated operation by operation. Per the research record, concluding a target as Target A (unauthenticated RCE) automatically skips the unauth-exhaustion gate: once a complete no-credential execution chain is demonstrated, exhaustively mapping the remaining anonymous surface is no longer required for the finding, and it was therefore left out of scope.

## 5. Root-Cause Analysis

### Attack surface (5.1): an anonymous management API

Decompiling `MetaServer.dll` (.NET Framework 4.8, x86) with ILSpy/dnSpy on a Windows research host revealed the whole control plane: a self-hosted ServiceHost publishing six contracts over `basicHttpBinding` with `security=None`, and — the decisive part — no authorization manager and no authenticating inspector. In WCF, `ServiceAuthorizationManagerType` is the documented hook for per-call authorization; leaving it unset means `CheckAccessCore` is never invoked and every dispatched call proceeds to the implementation. There is consequently no place in the request path where a caller identity could be checked even if the implementation wanted one.

### Source identification (5.2): the unauthenticated write path (CWE-862)

Four operations are enough to install and fire attacker code, and none of them performs an authorization check:

| Step | Service / operation | Effect | Authorization |
|---|---|---|---|
| 1 | `WorkflowService.CreateWorkflow` | register a workflow name, receive its Guid | none |
| 2 | `TransferService.UploadDefinition` | upload a workflow definition (base64 `Stream`) | none |
| 3 | `WorkflowService.ChangeWorkflows(activate)` | set the workflow `Enabled` / `Active` | none |
| 4 | `RestService.CreateDocument` | trigger processing, which walks the action chain | none |

Step 2 is the point where attacker content enters the product: the uploaded bytes are deserialized by `WorkflowDefinition.Deserialize` into a live workflow object, including its actions and their settings. Nothing constrains which action types a definition may contain.

### Sink identification (5.3): RunPrograms -> Process.Start (CWE-78)

In the uploaded definition, action `[0]` is an `ImportFromWebService` action that serves as the enabling step, and action `[1]` is a `RunPrograms` action. When the workflow processes a document, each action's settings object is applied; for `RunPrograms` that application is an unguarded process launch:

```csharp
// RunProgramSettings.Apply()  (reconstructed from the decompiled assembly)
Process.Start(new ProcessStartInfo {
    FileName    = this.Program,     // attacker-controlled, e.g. "cmd.exe"
    Arguments   = this.Arguments,   // attacker-controlled, e.g. "/c whoami>..."
    UseShellExecute = false
});
```

Three properties make this a direct execution primitive rather than a constrained "integration hook":

- **no allowlist** — the `Program` field accepts any value; there is no validation of the executable name or its path;
- **no privilege drop** — the process is spawned by `MetaService.exe`, which runs as `NT AUTHORITY\SYSTEM`, and `Process.Start` inherits that token;
- **no argument hygiene** — `Arguments` is passed through verbatim, so shell metacharacters such as `&`, `>` and `|` survive intact into `cmd.exe`, giving arbitrary command sequencing and output redirection.

`CreateDocument` in step 4 is what makes the definition run: it enqueues a document for the activated workflow, the engine advances from action `[0]` to action `[1]`, and `RunProgramSettings.Apply()` executes.

### Data flow (5.4): complete path

```
unauthenticated attacker (any host that can reach TCP 8733)
  |
  +-[SOAP] WorkflowService.CreateWorkflow(name)
  |           -> no ServiceAuthorizationManager, no inspector -> Guid returned
  |
  +-[SOAP] TransferService.UploadDefinition(Guid, base64 .CBMSWorkflow)
  |           -> WorkflowDefinition.Deserialize
  |              action[0] = ImportFromWebService (enabler)
  |              action[1] = RunPrograms { Program="cmd.exe",
  |                        Arguments="/c whoami>C:\Windows\Temp\cb_marker.txt & echo RCE_OK>C:\Windows\Temp\cb_marker2.txt" }
  |
  +-[SOAP] WorkflowService.ChangeWorkflows(apply=true, activateWorkflowIds=[Guid])
  |           -> workflow Enabled / Active
  |
  +-[SOAP] RestService.CreateDocument(workflowId=Guid, directory, fileNames)
              -> engine walks actions: ImportFromWebService -> RunPrograms
              -> RunProgramSettings.Apply()
              -> Process.Start("cmd.exe", "/c ...")   [token = NT AUTHORITY\SYSTEM]
              -> markers written under C:\Windows\Temp\
```

### 5.5 Research pitfall that nearly broke the chain

The definition payload encodes every value with a per-line length prefix, so one mistyped digit desynchronizes the whole stream. During construction a `2,10` field in the second `WebhookSettings` block was transcribed as `2010`, and `TextDeserializer.ReadInt32` threw a `FormatException` (the .NET "input string was not in a correct format" error). The name field was first suspected as the root cause; the stack trace is what localized the fault to `WebhookSettings.Deserialize -> ReadArrayStrings -> ReadInt32`. The fix was to regenerate the payload from the authoritative source workflow file and validate it by a base64 round-trip before embedding it. Recorded here because it explains why the PoC's exact byte length matters and why hand-editing this payload class is unsafe.

## 6. Exploit Chain Construction

**Step 1 — `CreateWorkflow`.** A SOAP POST to `WorkflowService` with `SOAPAction: "http://tempuri.org/IWorkflowService/CreateWorkflow"`, body `CreateWorkflow` (namespace `http://tempuri.org/`) carrying `<name>`, `<description>` and `<sourceWorkflowId>` set to the empty Guid `00000000-0000-0000-0000-000000000000`. The response contains the new workflow Guid, extracted with a Guid regex.

**Step 2 — `UploadDefinition`.** A SOAP POST to `TransferService` (`SOAPAction: "http://tempuri.org/ITransferService/UploadDefinition"`). `UploadDefinition` is a `[MessageContract]` operation, so the request carries custom headers plus a body: `<h:RequestInfo s:mustUnderstand="1">0<Guid></h:RequestInfo>` and `<h:RequestType s:mustUnderstand="1">0</h:RequestType>`, then `UploadDefinitionRequest` with the definition as a base64 `<Stream>` element. Two substitutions are made on the embedded 1995-byte definition before upload: the template Guid `1d4557c2-d189-43f5-9935-3f2b29dcc1fb` is replaced with the freshly returned Guid, and both occurrences of the template name/description record (`,pwn\r\n`) are replaced with the new workflow name — which is why the uploaded payload measures 1997 bytes when a 4-character name is used.

**Step 3 — `ChangeWorkflows(activate)`.** A SOAP POST to `WorkflowService` with `<apply>true</apply>`, an empty `<deleteWorkflowIds>` and an `<activateWorkflowIds>` array holding the workflow Guid (WCF array namespace `http://schemas.microsoft.com/2003/10/Serialization/Arrays`). The same operation with a populated `deleteWorkflowIds` array is used by the PoC to clean up a workflow whose upload failed.

**Step 4 — `CreateDocument`.** A SOAP POST to `RestService` with `<workflowId>`, `<directory>`, a `<fileNames>` string array and an empty `<mappedValues>` array. The PoC creates a temporary directory holding a dummy file, then triggers processing for that file — enough for the engine to walk the action chain.

**Retry loop.** The TextSerializer is intolerant of some short names: certain candidates deserialize cleanly while others raise a `FormatException`, a behaviour not fully explained by static analysis. The PoC therefore pairs steps 1 and 2 in a loop of up to 40 attempts using a random 4-character name, deleting any workflow whose upload failed, and proceeds as soon as an upload returns HTTP 200.

## 7. PoC Usage

The PoC (`exploit/capturebites_metaserver_unauth_runprogram_rce.py`) is pure Python 3 standard library (`http.client`, `base64`, `re`, `tempfile`, `random`, `argparse`) with English-only stdout, and performs all four anonymous SOAP steps plus marker verification:

```bash
# default target http://127.0.0.1:8733
python3 exploit/capturebites_metaserver_unauth_runprogram_rce.py

# explicit target
python3 exploit/capturebites_metaserver_unauth_runprogram_rce.py http://<target-ip>:8733
```

The embedded definition makes the `RunPrograms` action execute:

```
cmd.exe /c whoami>C:\Windows\Temp\cb_marker.txt & echo RCE_OK>C:\Windows\Temp\cb_marker2.txt
```

Steps 1-4 are pure network operations and work from any host that can reach TCP 8733. Step 5 of the script — reading `C:\Windows\Temp\cb_marker.txt` / `cb_marker2.txt` — requires local read access to the target filesystem, so the recorded verification ran the script on the target host itself; that is also what makes the marker evidence attributable to the SYSTEM-side process rather than to the caller. Exit codes: 0 = RCE confirmed, 2 = chain failure (create/upload or non-200 trigger), 3 = marker not found. The PoC is for authorized security testing and coordinated disclosure only, and it ships without the research environment's license-gate patch (see Section 4).

## 8. Verification Evidence

**Environment (stated honestly).** The verification target was a Windows Server 2025 host running the CaptureBites MetaServer Windows service (`MetaServer` / `MetaService.exe`, service state Running) under `NT AUTHORITY\SYSTEM`, with the SOAP listener reached at `http://127.0.0.1:8733`. The exploit script was executed *on the target host* so that it could read back the marker files written by the SYSTEM-side process; remote reachability of the same listener from another machine is argued from the `0.0.0.0` binding plus the host-agnostic http.sys dispatch verified by Host-header testing (Sections 3-4), not from a cross-host run. The deployment used for verification carried the research environment's Mono.Cecil license-gate patch (`LicenseStatus -> 2`, `LicenseCount -> 1000`); per the research record that gate is a commercial feature gate, not a security boundary, and is not a precondition of the vulnerability. The verification run is recorded in our research archive.

Marker files were removed before the run so that a positive result is attributable to this execution, and the service state was confirmed beforehand. Script stdout, verbatim:

```
[*] target: http://127.0.0.1:8733
[*] step 1: CreateWorkflow('rxqe') -> guid 434f16a8-5bb9-4d03-b184-2f26ab3a89f6
[*] step 2: UploadDefinition (malicious RunPrograms workflow, 1997 bytes) -> HTTP 200 (attempt 1)
[*] step 3: ChangeWorkflows(activate)
    HTTP 200
[*] step 4: CreateDocument trigger (src=<local temp dir>\cb_src_074lbc07)
    HTTP 200
[*] step 5: waiting for SYSTEM-side RunProgram execution...
============================================================
[+] RCE CONFIRMED as SYSTEM
[+] whoami output : nt authority\system
[+] marker2 tag   : RCE_OK
[+] marker path   : C:\Windows\Temp\cb_marker.txt
[*] exploit exit code: 0
```

**Target-side marker files, read back after the run:**

| File | Owner | Size | Content |
|---|---|---|---|
| `C:\Windows\Temp\cb_marker.txt` | `BUILTIN\Administrators` | 21 bytes | `nt authority\system` |
| `C:\Windows\Temp\cb_marker2.txt` | `BUILTIN\Administrators` | 8 bytes | `RCE_OK` |

`cb_marker.txt` holds the `whoami` output of the spawned process — `nt authority\system` — which is the direct proof of the execution identity, and `cb_marker2.txt` proves the second `echo` in the same command line ran, i.e. that the shell processed the attacker-supplied metacharacters (`&`, `>`) rather than a fixed built-in probe. Both files were written by the `cmd.exe /c ...` process created by the `RunPrograms` sink, which inherited the SYSTEM token of the MetaServer service; they did not exist before the run.

**Chain HTTP summary — every call anonymous (no authentication header, no credentials), plain HTTP, no MITM:**

| Step | Operation | HTTP |
|---|---|---|
| 1 | `CreateWorkflow` (WorkflowService) | 200 (Guid `434f16a8-5bb9-4d03-b184-2f26ab3a89f6`) |
| 2 | `UploadDefinition` (TransferService) | 200 |
| 3 | `ChangeWorkflows(activate)` (WorkflowService) | 200 |
| 4 | `CreateDocument` (RestService) | 200 |

**Reproducibility.** The script exits 0 and is re-runnable: each invocation creates a workflow with a fresh random 4-character name, so repeated runs do not collide on workflow names. In the recorded run the first candidate name (`rxqe`) was accepted, and the upload succeeded on attempt 1.

## 9. Reachability and Security Impact

- **Execution identity.** `NT AUTHORITY\SYSTEM` on the MetaServer host — verified, not assumed: the marker file contains `nt authority\system`, written by the process spawned from the sink, and the anonymous `ServerInfoService` independently reports the runtime user as SYSTEM. Code execution at this level is full host compromise, not a sandboxed or scoped capability.
- **The data this class of server holds.** A document-capture server is, by function, a concentration point for the documents an organization scans and extracts: inbound scanned images and PDFs, the OCR text and metadata pulled from them, indexing values, and the workflow configuration that says where each document class is routed. Reading that store yields the underlying business records themselves — invoices, contracts, identity and financial paperwork — in a single place rather than spread across the systems that eventually receive them.
- **Downstream integration reach.** The same server performs distribution: the product's own action vocabulary includes e-mail (`Email_PDF`, `Email_EML`, `Email_MSG`), link generation (`Link_XML`, `Link_PDF`, `Link_HTML`) and folder drops, and definitions reference output locations such as `C:\CaptureBites\MetaServer\Log_Processed`. Whatever credentials, SMTP endpoints or file shares the capture stage uses to push results into ERP/DMS and archiving systems are readable from the compromised host, and the capture stage itself sits *upstream* of those systems — so an attacker here can alter or forge what the back office subsequently ingests as trusted input, including by installing a persistent malicious workflow that fires on every document.
- **Integrity and availability.** As SYSTEM, arbitrary file write covers the product binaries, its configuration and its logs, so the compromise can be made persistent and the audit trail rewritten; the capture service, its database and the host itself can be stopped or corrupted on demand, halting document processing for the business.
- **Exposure.** No credentials, no session, no user interaction, no MITM: the barrier is network reachability of TCP 8733, which the product binds to `0.0.0.0`. A single four-request HTTP/SOAP sequence — the published PoC performs it automatically — converts an anonymous document-capture listener into a SYSTEM shell.

## 10. Mitigation

Vendor-side:

1. **Authenticate and authorize the SOAP surface.** Replace `basicHttpBinding` `security=None` with transport or message security (e.g. `basicHttpsBinding` with `TransportWithMessageCredential`), and register a `ServiceAuthorizationManager` so the WCF runtime actually reaches an authorization decision point on every call. Add an `IDispatchMessageInspector` / `IParameterInspector` that validates a caller token before any handler executes.
2. **Close CWE-862 on the state-changing operations.** `CreateWorkflow`, `UploadDefinition`, `ChangeWorkflows` and `CreateDocument` must be restricted to authenticated administrators; anonymous callers must receive a fault, not HTTP 200. Workflow definition upload additionally deserves integrity checks and action-type validation at deserialization time.
3. **Constrain the `RunPrograms` sink.** Validate `Program` against an administrator-configured allowlist of absolute paths, reject shell interpreters outright (`cmd.exe`, `powershell.exe`, `wscript.exe`), escape or reject shell metacharacters in `Arguments`, and execute the action under a dedicated low-privilege account instead of inheriting the service token.
4. **Leave SYSTEM.** Run `MetaService.exe` under a least-privilege service account, so a workflow-action compromise does not equal host compromise and cannot reach other services' secrets.
5. **Narrow the listener.** Do not bind the SOAP endpoint to `0.0.0.0`; bind loopback or a dedicated management interface, and require an authenticating reverse proxy for remote administration.

Deployment-side (interim, until a vendor fix):

- Firewall TCP 8733 to trusted management hosts only, and treat any MetaServer host exposed to a general user network or the internet as compromised-by-default pending a fix
- Monitor for unexpected workflow creations and definition uploads (`WorkflowService` / `TransferService` traffic) and for `cmd.exe` child processes of `MetaService.exe`

## 11. CWE & CVSS Rationale

- **CWE-306 — Missing Authentication for Critical Function.** The WCF host provides no authentication whatsoever: `basicHttpBinding` with `security=None`, no registered `ServiceAuthorizationManager`, no auth-validating inspector. The critical functions exposed include workflow definition upload and execution triggering.
- **CWE-862 — Missing Authorization.** Even taken independently of authentication, none of the four chain operations performs an authorization check: any caller may create a workflow, upload its definition, activate it and trigger processing.
- **CWE-78 — Improper Neutralization of Special Elements used in an OS Command.** The `RunPrograms` action passes the attacker-controlled `Program` and `Arguments` straight to `Process.Start` with no allowlist and no escaping, and the recorded payload uses `cmd.exe /c` with `&` and `>` to run a compound shell command line.
- **CVSS 3.1 = 9.8 (Critical), `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.** `AV:N` — the chain is pure HTTP/SOAP against a `0.0.0.0`-bound listener; `AC:L` — on a deployment where the licensed document-capture feature is active (the normal state for a paying customer installation), the chain is four deterministic requests with no race and no attacker-side preparation; the one condition outside the attacker's control is the licence gate disclosed in Section 4, which applies only to unlicensed or trial deployments; `PR:N` — anonymous, no credentials of any kind; `UI:N` — the caller triggers `CreateDocument` itself; `C:H/I:H/A:H` — SYSTEM-level execution on the host gives full read, write and shutdown capability over the capture server and the documents it holds.
- **Scope = Unchanged.** The research record listed the vector with `S:C` (Changed) alongside the score 9.8, which is internally inconsistent — that vector computes to 10.0 — so the Scope value has been corrected from Changed to Unchanged for consistency with the stated score, because the compromise remains within the MetaServer host's own security scope: the vulnerable component and the impacted component are the same host and the same SYSTEM authority, and the downstream document-flow impact described in Section 9 is exercised through that host rather than crossing into a separately authorized scope.
- **Target classification A (unauthenticated RCE).** Per the research record, a Target-A conclusion is reached only when the chain is demonstrated anonymous, credential-free, MITM-free and remotely reachable — all four hold here — and it automatically skips the unauth-exhaustion gate for the remaining anonymous surface.

---

*Contact for coordinated disclosure: disclosure@0day-rubbish.com. This advisory is published at https://0day-rubbish.com/blog/capturebites-metaserver-unauth-runprogram-system-rce as part of batch-11; disclosure status is tracked in DISCLOSURE-STATUS.md.*
