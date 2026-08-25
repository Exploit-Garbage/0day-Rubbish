# Seeq Server — Unauthenticated Self-Registration + Data Lab Jupyter Missing Authorization → Arbitrary Python RCE

## Summary

Seeq Server R65.2.3 ships with two independently confirmed flaws that combine into an unauthenticated remote code execution chain on a default installation:

1. **Unauthenticated self-registration (CWE-306)** — `Features/UserRegistration/Enabled=true` by default, and `POST /api/users` is reachable without any authentication header. An anonymous attacker creates an arbitrary user account.
2. **Missing admin authorization in Data Lab Jupyter (CWE-862)** — the orchestrator's `getAuthorizedProjectData()` checks only project membership, not admin role, so any authenticated non-admin user can schedule a Data Lab Jupyter container and execute arbitrary Python. The Jupyter kernel has no sandbox (CWE-78).

Combined: an unauthenticated attacker registers a non-admin user, logs in, creates a Data Lab project, spawns a Jupyter container, and executes arbitrary OS commands as the `datalab` user (uid 9500). Verified end-to-end on a default R65.2.3 deployment; no MITM, no prior foothold, no researcher misconfiguration.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Seeq Server (industrial analytics platform)
- **Versions**: R65.2.3 (v202607141252) verified; other releases with `Features/UserRegistration/Enabled=true` and the same Data Lab orchestrator are likely affected
- **Vendor**: Seeq Corporation
- **Prerequisite**: Data Lab installed via the official `seeq data-lab install`/`start` CLI (standard Seeq analytics configuration)

## Impact

- **Confidentiality**: Arbitrary file read and data exfiltration as the `datalab` (uid 9500) user
- **Integrity**: Arbitrary OS command execution inside the Jupyter container context
- **Availability**: Full control of the Data Lab container and the analytics workloads it hosts

## Mitigation

1. Set `Features/UserRegistration/Enabled=false` by default, or require administrator approval for self-registered accounts
2. Remove the `checkIsFirstRegisteredUser` auto-admin logic; force administrator credential setup at install time
3. Add an admin-role check to the orchestrator `getAuthorizedProjectData()`; restrict Data Lab container scheduling to administrators
4. Sandbox the Jupyter kernel (block `subprocess`/`os.system` or run kernels in a restricted runtime)
