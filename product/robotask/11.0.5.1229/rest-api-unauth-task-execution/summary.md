# RoboTask REST API Unauthenticated Remote Task Execution (CWE-306)

## Summary

A missing-authentication vulnerability in RoboTask 11 allows a remote attacker to enumerate and trigger tasks via the built-in REST API without any credentials. The API key check is controlled by the registry switch `RestUseApiKeys`, which defaults to `0` (disabled), so all 12 REST endpoints are reachable without an `X-API-KEY` header. Combined with the default bind address `0.0.0.0:9999`, an attacker can call `GET /api/tasks` to enumerate tasks and `POST /api/tasks/{id}/run` to execute a pre-existing task with the privileges of the RoboTask process (typically Administrator), achieving arbitrary code execution.

## CVSS Score

- **Score**: 9.8 Critical (when the REST server is enabled and bound to a non-localhost interface)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: RoboTask (Windows task automation / job scheduler)
- **Versions**: 11.0.5.1229 (other versions with `RestUseApiKeys=0` default are likely affected)
- **Vendor**: Neowise Software

## Impact

- **Confidentiality**: Full access to task configuration, credentials embedded in tasks, and system information
- **Integrity**: Remote execution of pre-existing tasks (run programs, scripts, file/registry operations) with the RoboTask process privileges
- **Availability**: Full control of the host via task execution

## Mitigation

1. Enable API keys (`RestUseApiKeys=1`) and set a strong key
2. Bind the REST API to localhost or trusted LAN interfaces instead of `0.0.0.0`
3. Restrict port 9999 at the firewall to trusted hosts
4. Use TLS for the REST API and avoid storing credentials in tasks

**Note**: The REST API does not expose task creation/editing; exploitation requires a pre-existing task with a run-program or script action. In default installations the API is disabled (`RestIsEnabled=0`), so the exposure requires the operator to have enabled it.
