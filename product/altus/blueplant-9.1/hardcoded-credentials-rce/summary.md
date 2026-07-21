# Altus BluePlant Hardcoded Credentials RCE

## Summary

An unauthenticated remote code execution vulnerability in Altus BluePlant 9.1.40. The TWebServer HTTP gateway (default port 3100) in-process hosts `T.InfoService.Service`, a WCF service (contract `T.Library.IContract`) configured with `<security mode="None"/>` (no authentication, no TLS). The service's `Connect` method performs authentication through a private validator `_0002()` that hardcodes three credential-bypass paths. An attacker uses any one of them to bypass `Connect` and obtain a valid `connectionHandle`, then drives the generic remote-method-invocation gateway `SendRequest` (which reflects and dispatches via `RemoteMethod.ExecuteInvoke`) to call `FileServer.RunProcess(path, arguments)` -> `Process.Start(path, arguments)`, achieving arbitrary remote command execution with no credentials, in the default configuration, as the service account (observed: `administrator`).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Altus BluePlant (SCADA HMI / industrial control system software)
- **Versions**: 9.1.40 and versions using the same `T.InfoService.Service` / `FileServer.RunProcess` path
- **Vendor**: Altus

## Impact

- **Confidentiality**: Full read of the host running TWebServer (service account privileges)
- **Integrity**: Arbitrary command execution; ability to alter the SCADA HMI configuration and process data
- **Availability**: Full control of the HMI server; can stop/disable the monitoring system

## Exploitation Model

This is a Target A (network service) vulnerability. TWebServer listens on port 3100 by default (HTTP.SYS urlacl `http://+:3100/`); if the deployment does not bind 127.0.0.1, the service is remotely reachable. `Service1` (`TProjectServer/service.svc`) is hosted in-process by TWebServer and does **not** depend on the TStartup runtime or a hardware dongle license, so the attack surface exists immediately after a default install. Authentication is absent (`<security mode="None"/>`) and the `Connect` validator hardcodes bypass credentials directly in code, so exploitation requires no credentials and no prerequisites.

## Mitigation

1. Remove the hardcoded bypass credentials in `ServiceBase._0002()`; force `Connect` validation through the database authentication path
2. Enable transport security: change `<security mode="None"/>` to `Transport` or `Message`, enforcing TLS plus Windows authentication
3. Restrict the service method surface: `RemoteMethod.ExecuteInvoke` must not reflect over all public methods; maintain an explicit allowlist that excludes dangerous methods such as `RunProcess` / `BeginSendFile` / `BeginReceiveFile`
4. Harden `FileServer.RunProcess`: remove the method or restrict `path` to an allowlist of known executables and escape `arguments`
5. Bind TWebServer to 127.0.0.1 by default to avoid exposing port 3100 externally
6. Disable MEX metadata exposure (`serviceMetadata httpGetEnabled="true"`) in production

## Timeline

- **Discovered**: 2026-07-18
- **Public Disclosure**: 2026-07-18

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).