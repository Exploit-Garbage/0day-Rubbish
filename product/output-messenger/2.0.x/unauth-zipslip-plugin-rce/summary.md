# Output Messenger Server Unauthenticated Zip-Slip Plugin Planting RCE

## Summary

Output Messenger Server (2.0.x) exposes an unauthenticated XMPP control plane on TCP 14121: `ASActions.ProcessAnonymousData` sets `Authenticated=true` immediately on every new connection, and all XMPP handlers are reachable without credentials. An attacker registers as a linkserver, pushes a crafted ZIP over the SOCKS5 file listener (14135), and the server's `SyncLog.ProcessSyncLog` extracts it with an old SharpZipLib (0.85.4.369) that does not reject `..\` entries. A malicious plugin DLL is planted into the plugin directory; the next service restart triggers `Assembly.LoadFrom` and instantiates the plugin's constructor before the enabled-check — code execution as `NT AUTHORITY\SYSTEM`. Dynamically verified (SYSTEM proof file written).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Output Messenger Server
- **Versions**: 2.0.x (>= 2.0.63)
- **Vendor**: Output Technology

## Impact

- **Confidentiality**: Full control of the host as `SYSTEM`
- **Integrity**: Arbitrary file write and plugin code execution
- **Availability**: Full control of the messenger service and host

## Exploitation Prerequisites

Default installation: anonymous XMPP plane (14121) and SOCKS5 listener (14135) bound to 0.0.0.0; service runs as LocalSystem; old SharpZipLib; a service restart is required to trigger plugin loading (plant-and-restart pattern).

## Mitigation

1. Require SASL/credentials before setting `Authenticated=true`; validate linkserver key
2. Upgrade SharpZipLib to >= 1.3.0 or apply a `NameTransform`/`PathFilter` that rejects `..`
3. Validate ZIP entry paths before extraction; restrict extraction root
4. Instantiate plugins only after the enabled-check
5. Run the service under a least-privilege account; authenticate the file listener

## Timeline

- **Discovered**: 2026-08-04
- **Public Disclosure**: 2026-08-12 (batch #4)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble.
