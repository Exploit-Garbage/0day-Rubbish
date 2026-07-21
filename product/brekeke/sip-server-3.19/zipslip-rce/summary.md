# Brekeke SIP Server Unauthenticated Zip Slip Webshell RCE

## Summary

A critical unauthenticated remote code execution vulnerability in Brekeke SIP Server allows attackers to write a JSP webshell into the webroot through a Zip Slip path traversal in the `ProvisioningModelImport` bean's self-developed `Zip.extractAll` method, which performs no `..` filtering or canonical-path validation. A single unauthenticated POST writes the webshell and a single GET triggers it — remote code execution as the `tomcat` user, with no prerequisites, in the factory default configuration.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Brekeke SIP Server (SIP Proxy / SIP Registrar)
- **Versions**: v3.19.1.8p1 (Evaluation Edition) and versions using the same `ProvisioningModelImport` / `Zip.extractAll` code
- **Vendor**: Brekeke Software, Inc.

## Impact

- **Confidentiality**: Full command execution as the `tomcat` user; arbitrary system command output retrieval
- **Integrity**: Arbitrary file write into the webroot; persistent webshell deployment; ability to modify the SIP server installation
- **Availability**: Full control of the Tomcat process and host command execution

## Mitigation

1. Validate zip entry names against canonical paths: `Zip.extractAll` must reject any entry whose resolved path escapes the target directory (compare `getCanonicalPath()` against the extract root)
2. Fix the auth fail-open: `ProvisioningModelImport` must declare a scope via `setCheckScope(...)` so it is not reachable unauthenticated
3. Allowlist the `bean` parameter in `GateServlet` so attacker-controlled class loading is not possible
4. Restrict the model import feature to authenticated administrators and validate uploaded archive contents

## Timeline

- **Discovered**: 2026-07-15
- **Public Disclosure**: 2026-07-15

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).