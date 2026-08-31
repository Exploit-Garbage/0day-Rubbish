# StreamSets DataCollector — Default Credentials + Shell Executor → Root RCE

## Summary

StreamSets DataCollector 6.4.1 (the official Docker image) ships with hard-coded default credentials (`admin:admin`, `guest:guest`, `creator:creator`) that are never forced to change on first login (CWE-798), and its built-in Shell Executor stage writes the attacker-controlled `config.script` field directly to a temporary shell script and executes it via `ProcessBuilder("sh", script)` with no sandbox, whitelist, or filtering (CWE-94). The container's `sdc` user has `NOPASSWD: ALL` in sudoers, so the script can escalate with `sudo -n` to `uid=0 (root)`.

An unauthenticated attacker needs only the publicly known default credentials to: create a pipeline (or update an existing one), inject a shell script into the `ShellDExecutor` stage configuration, and start the pipeline. A single record flows through the Dev Raw Source into the executor, which runs the script as `sdc` — or as root with a `sudo -n` prefix. Verified end-to-end on a default Docker deployment with dynamic markers confirming both `uid=20159(sdc)` and `uid=0(root)` execution.

## CVSS Score

- **Score**: 9.8 Critical (default credentials not changed → effectively unauthenticated)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: StreamSets DataCollector
- **Versions**: 6.4.1 verified (official `streamsets/datacollector:6.4.1` image); other versions with the same default realm and Shell Executor are likely affected
- **Vendor**: StreamSets (IBM)
- **Prerequisite**: default installation — no configuration hardening required

## Impact

- **Confidentiality**: arbitrary file read and data exfiltration as `sdc` or root (`/etc/shadow`, pipeline data, credentials)
- **Integrity**: arbitrary command execution on the DataCollector host/container, pipeline tampering
- **Availability**: full compromise of the data-pipeline engine and its host

## Mitigation

1. Remove default credentials — force a password change on first login (CWE-798)
2. Restrict or sandbox the Shell Executor stage (command allowlist, default-disabled, audit logging)
3. Remove `sdc ALL=(ALL) NOPASSWD: ALL` from sudoers (least privilege)
4. Validate stage configuration on `savePipeline`; require explicit admin enablement for high-risk stages
