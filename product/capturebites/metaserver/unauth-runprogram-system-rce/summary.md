# CaptureBites MetaServer — Unauthenticated SYSTEM RCE Through the Workflow RunProgram Sink

## Summary

CaptureBites MetaServer is a closed-source document capture / distribution automation server. It runs as the Windows service `MetaServer` (`MetaService.exe`) under `NT AUTHORITY\SYSTEM` and publishes its entire control plane as a self-hosted WCF SOAP service bound to `0.0.0.0:8733`. Every service contract uses `basicHttpBinding` with `security=None`, no `ServiceAuthorizationManager`-derived class is registered with the ServiceHost, and no custom `IParameterInspector` / `IDispatchMessageInspector` validates a caller token — so all six services (`ServerInfoService`, `DatabaseService`, `LicenseService`, `WorkflowService`, `RestService`, `TransferService`) are reachable anonymously.

An unauthenticated attacker turns that anonymous surface into code execution with four plain-HTTP SOAP calls: `WorkflowService.CreateWorkflow` registers a workflow name and returns a Guid; `TransferService.UploadDefinition` uploads an attacker-authored `.CBMSWorkflow` definition whose second action is a `RunPrograms` action carrying `Program=cmd.exe` and attacker-controlled `Arguments`; `WorkflowService.ChangeWorkflows` activates the workflow; and `RestService.CreateDocument` triggers processing, which walks the action chain through `RunProgramSettings.Apply()` into `Process.Start(...)`. There is no program allowlist, no argument escaping and no privilege drop — the child process inherits the service token, so the command executes as `NT AUTHORITY\SYSTEM`. The chain was verified end-to-end in a lab deployment: all four anonymous calls returned HTTP 200, the `whoami` marker file written by the resulting `cmd.exe` process contained `nt authority\system`, and a second marker contained `RCE_OK`. No credentials, no session and no man-in-the-middle position were used at any point.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: CaptureBites MetaServer (document capture & distribution server)
- **Vendor**: CaptureBites
- **Version**: MetaServer (.NET Framework 4.8, self-hosted WCF SOAP) — version as recorded in our research; the exact build is not stated in the research record
- **Component**: self-hosted WCF SOAP control plane on `0.0.0.0:8733` — `WorkflowService`, `TransferService`, `RestService`; workflow definition handling (`.CBMSWorkflow`, TextSerializer format version 11) and the `RunPrograms` action (`RunProgramSettings.Apply()` -> `Process.Start`)
- **Prerequisites**: none beyond network reachability of TCP 8733 (bound to `0.0.0.0`; http.sys dispatches host-agnostically, confirmed by Host-header testing). No credentials, no default account and no user interaction are involved.

## Impact

- **Execution identity**: `NT AUTHORITY\SYSTEM` — verified by the marker file content `nt authority\system`, written by the `cmd.exe` process spawned from the `RunPrograms` sink, which inherits the MetaServer service token
- **Confidentiality**: full read access to the host, including the scanned documents and extracted/OCR data a document-capture server holds, the workflow definitions and configuration, and any credentials the server uses for its downstream distribution and ERP/DMS integrations
- **Integrity**: arbitrary file write and modification as SYSTEM; attacker-supplied workflow definitions are persisted and executed by the product; captured document data can be altered before it reaches downstream systems
- **Availability**: the capture service, its workflows and its host can be stopped, corrupted or repurposed at will
- **Exposure**: reachable anonymously over HTTP with no credentials and no user interaction; one script run drives the whole chain, and MetaServer hosts normally sit inside the document-processing path of the back office, which makes execution here a springboard toward downstream business systems

## Mitigation

1. Require authenticated callers on every WCF contract: replace `basicHttpBinding` `security=None` with transport (`basicHttpsBinding` + `TransportCredentialOnly` / `TransportWithMessageCredential`) or message security, and register a `ServiceAuthorizationManager` so the runtime enforces authorization instead of leaving it unimplemented
2. Enforce per-operation authorization on the state-changing surface — `CreateWorkflow`, `UploadDefinition`, `ChangeWorkflows` and `CreateDocument` must reject anonymous callers; add an `IDispatchMessageInspector` / `IParameterInspector` that validates a caller identity or token before the handler runs
3. Constrain the `RunPrograms` sink: validate `Program` against an administrator-configured allowlist of absolute paths, reject shell interpreters (`cmd.exe`, `powershell.exe`, `wscript.exe`), escape or reject shell metacharacters in `Arguments`, and execute the action under a dedicated low-privilege account instead of inheriting the service token
4. Stop running the service as `NT AUTHORITY\SYSTEM`; use a least-privilege service account so that a workflow-action compromise is not a host compromise
5. Do not bind the SOAP listener to `0.0.0.0`; restrict it to loopback or to a dedicated management interface, and require an authenticating reverse proxy where remote administration is needed
6. Treat `.CBMSWorkflow` definitions as untrusted input: validate action types and their settings during deserialization, and require administrator authentication for `TransferService.UploadDefinition`
