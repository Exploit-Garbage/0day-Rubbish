# JetBrains Datalore On-Premises Unauthenticated RCE via InteractiveReport READ-to-EXECUTE Access Mapping Flaw

## Summary

A critical unauthenticated remote code execution vulnerability in JetBrains Datalore On-Premises allows a remote attacker with no credentials to execute arbitrary code inside the Datalore agent container. The WebSocket RPC endpoint `/wsdp` accepts anonymous connections when the shipped-default `ALLOW_ANONYMOUS_RPC_ACCESS=true` flag is set. An access-control asymmetry in `InteractiveReportSessionAccessProvider` maps a READ-level permission on a publicly shared interactive report to EXECUTE, which gates four RPC methods including `installLibrary`. The `PipDriver.doInstall` sink passes an attacker-controlled package name directly to `pip install` without sanitization, so a malicious package URL executes arbitrary `setup.py` code during installation, resulting in code execution as the `datalore` user inside the agent container.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: JetBrains Datalore On-Premises (Datalore Server)
- **Versions**: 2026.2.3 (other versions shipping `ALLOW_ANONYMOUS_RPC_ACCESS=true` and the same access-checker mapping are likely affected)
- **Vendor**: JetBrains

## Impact

- **Confidentiality**: Full compromise of the Datalore agent container; notebook data, credentials, and source code accessible
- **Integrity**: Arbitrary code execution in the agent container; `pip install` of attacker-controlled packages
- **Availability**: Full control of the agent container; potential host escape when the container mounts the Docker socket

## Mitigation

1. Set `ALLOW_ANONYMOUS_RPC_ACCESS=false` unless anonymous RPC access is explicitly required
2. Fix the access-control mapping so READ permission on an interactive report maps to VIEW, not EXECUTE (align `InteractiveReportSessionAccessProvider` with `VfsRpcAccessChecker`)
3. Sanitize and restrict package names/URLs passed to `pip install` (whitelist known-good indexes, reject URLs)
4. Run agent containers without Docker socket mounts and with least-privilege service accounts
5. Restrict the management ports (8080/8081) to trusted networks
