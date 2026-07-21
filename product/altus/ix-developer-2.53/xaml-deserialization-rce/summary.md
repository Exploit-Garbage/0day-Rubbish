# Altus iX Developer XAML Deserialization RCE

## Summary

A remote code execution vulnerability in Altus iX Developer allows arbitrary command execution when a user opens a malicious `.ix` screen file. The screen file XML content is passed to the WPF `XamlReader.Load` deserializer without type sanitization, so an `ObjectDataProvider` gadget triggers `Process.Start(ProcessStartInfo)` at load time.

## CVSS Score

- **Score**: 7.3 High
- **Vector**: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Altus iX Developer (SCADA HMI engineering IDE)
- **Versions**: 2.53.65422 and versions using the same `ScreenXamlSerializer` / `XamlReader.Load` path
- **Vendor**: Altus

## Impact

- **Confidentiality**: Arbitrary code execution as the engineer user; access to OT engineering workstation data
- **Integrity**: Arbitrary command execution; ability to pivot into the OT network from a compromised engineering workstation
- **Availability**: Full control of the engineer's workstation

## Exploitation Model

This is a Target B (IDE-class) vulnerability: iX Developer is a pure desktop engineering IDE with no inbound network service, so unauthenticated RCE is not reachable. Exploitation requires a user to open a malicious project/screen file in the iX Developer IDE — the standard threat model for IDE products (social engineering, project sharing, supply chain). OT engineers frequently share SCADA projects, making a malicious project a supply-chain attack vector against OT engineering workstations.

## Mitigation

1. Sanitize XAML input before deserialization: restrict `XamlReader.Load` to a type allowlist that rejects `ObjectDataProvider` and other dangerous types
2. Use `XamlXmlReader` with a restrictive `XamlSchemaContext` instead of the unrestricted `XamlReader.Load`
3. Validate `.ix` screen file contents against an expected schema before deserialization
4. Sign project/screen files and verify signatures before opening

## Timeline

- **Discovered**: 2026-07-18
- **Public Disclosure**: 2026-07-18

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).