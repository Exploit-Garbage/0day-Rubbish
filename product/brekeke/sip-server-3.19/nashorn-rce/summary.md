# Brekeke SIP Server Unauthenticated Nashorn JS Engine RCE

## Summary

A critical unauthenticated remote code execution vulnerability in Brekeke SIP Server allows attackers to execute arbitrary operating system commands as the `tomcat` user by passing user-controlled JavaScript to a Nashorn `ScriptEngine.eval()` call through the `ProvisioningTest` bean, which is reachable without authentication via the authentication fail-open primitive.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Brekeke SIP Server (SIP Proxy / SIP Registrar)
- **Versions**: v3.19.1.8p1 (Evaluation Edition) and versions using the same `ProvisioningTest` bean
- **Vendor**: Brekeke Software, Inc.

## Impact

- **Confidentiality**: Full command execution as the `tomcat` user; arbitrary system command output retrieval in the HTTP response
- **Integrity**: Arbitrary operating system command execution; ability to modify the SIP server installation
- **Availability**: Full control of the Tomcat process and host command execution

## Mitigation

1. Remove the eval sink: `ProvisioningTest` should not pass user input to `ScriptEngine.eval()`; the test bean should be removed or restricted to internal use
2. Sandbox Nashorn: if JS evaluation is genuinely required, configure Nashorn with a restrictive `ClassFilter` that denies access to `java.lang.Runtime`, `java.lang.ProcessBuilder`, and the reflection APIs
3. Fix the auth fail-open: `ProvisioningTest` must declare a scope via `setCheckScope(...)` so it is not reachable unauthenticated
4. Eliminate the temp-directory dependency coupling: do not gate a code-execution path on a writable temp directory that another unauthenticated primitive can create

## Timeline

- **Discovered**: 2026-07-15
- **Public Disclosure**: 2026-07-15

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).