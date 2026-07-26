# SonicWall SMA 1000 Pre-Auth Deserialization RCE Chain

## Summary

A critical unauthenticated remote code execution vulnerability chain in SonicWall SMA 1000 series appliances combines a Struts 1 `multipartRequestHandler` property-injection flaw (used to rewrite the Jetty authentication filter mappings and bypass authentication), an unauthenticated Single Sign-On token endpoint, and a Java deserialization sink in the `storedCommunity` field of `/configUserCommunityEPC.do` to execute arbitrary operating system commands as the `mgmt-server` user without any credentials.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: SonicWall SMA 1000 series (Secure Mobile Access)
- **Versions**: SMA 12.4.2 (firmware `ex_sra_vm_12.4.2-05082`, `Server: SMA/12.4`) and other 12.4.x releases sharing the same Struts 1 console and `multipartRequestHandler` property-binding surface
- **Vendor**: SonicWall

## Impact

- **Confidentiality**: Complete management-plane compromise; the `mgmt-server` process can read appliance configuration, user directories, credential snapshots, and any data accessible to the management service
- **Integrity**: Arbitrary operating system command execution as `mgmt-server` (uid=1011); ability to create administrator accounts, mint API keys, and alter appliance configuration through the unauthenticated `/Console` API
- **Availability**: Full control of the management process and host command execution; the appliance can be disabled or reconfigured at will

## Mitigation

1. Exclude `multipartRequestHandler`, `servletWrapper`, `servlet`, and `servletContext` from Struts 1 form property binding in `RequestProcessor#populate`; do not allow request parameters to traverse from an `ActionForm` into the servlet container's `ServletContext`, `ServletHandler`, or `filterMappings`
2. Enforce an allowlist (not a `class`/`classLoader` denylist) for bindable property paths; the current regex fails to block the `multipartRequestHandler → servlet → servletContext` traversal
3. Disable the SSO `Authorize` endpoint for unauthenticated callers, or require proof of administrative privilege before minting a Primary Administrator token; short token lifetime alone is not a sufficient control
4. Remove the deserialization sink in `BaseCommunityForm.setStoredCommunity`; do not `ObjectInputStream.readObject` on attacker-supplied `storedCommunity` values. If the field must be persisted, store it as an opaque string and deserialize only from trusted internal sources
5. Rebuild the Jetty filter chain cache on a tamper-detection signal so that runtime `filterMappings`/`filterChainsCached` mutations via property injection are rejected rather than honored

## Timeline

- **Discovered**: 2026-07-26
- **Public Disclosure**: 2026-07-26

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
