# Cinegy Cinegize Unauthenticated BinaryFormatter Deserialization RCE

## Summary

Cinegy Cinegize (2026-02-05 installer) runs the `CinegizeService` as LocalSystem, listening on TCP 0.0.0.0:51140. The DotNetty pipeline deserializes client input with `new BinaryFormatter().Deserialize()` in the inbound decoder **before** the authorization handler runs. The client controls the `Encryptor` header field; setting it to `None` bypasses the password branch and reaches raw deserialization. A standard `TypeConfuseDelegate` gadget (ysoserial.net) executes arbitrary commands as LocalSystem. The protocol token is a hardcoded public GUID, not a secret. Dynamically verified (`nt authority\system` with full privileges).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Cinegy Cinegize
- **Versions**: 2026-02-05 installer
- **Vendor**: Cinegy GmbH

## Impact

- **Confidentiality**: Full control of the host as LocalSystem
- **Integrity**: Arbitrary command execution
- **Availability**: Full control of the Cinegize service and host

## Exploitation Prerequisites

Default installation: service runs as LocalSystem, port 51140 reachable (vendor firewall rule allows inbound by default); .NET Framework 4.8 with BinaryFormatter enabled; gadget assemblies available in GAC/install dir.

## Mitigation

1. Replace BinaryFormatter with a safe serializer (DataContractSerializer/protobuf) or a hardened binder with an allowlist
2. Move authorization before deserialization
3. Do not trust the client-controlled `Encryptor=None` branch for raw deserialization
4. Treat the message token as a protocol marker, not a credential; use per-session key negotiation
5. Run the service as a least-privilege account

## Timeline

- **Discovered**: 2026-07-26
- **Public Disclosure**: 2026-08-12 (batch #4)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble.
