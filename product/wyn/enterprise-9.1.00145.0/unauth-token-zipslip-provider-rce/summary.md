# Wyn Enterprise Unauthenticated Root RCE (Token Forgery + Zip-Slip + Provider Load)

## Summary

A critical unauthenticated remote code execution chain in Wyn Enterprise 9.1.00145.0 combines three vulnerabilities, all reachable without credentials in the default configuration: (VULN-A) `ResourceOwnerValidator.cs:145` uses `JwtSecurityTokenHandler.ReadToken()` (parse-only, no signature validation) instead of `ValidateToken`, plus a hardcoded integration client secret (`ProductionClientProducer.cs:29`), yielding an unauthenticated 10-year admin reference token (CWE-347 + CWE-798); (VULN-B) `SecurityProviderService.ImportFiles` uses `Path.GetFullPath(Path.Combine(destFolder, entry.FullName))` + `ExtractToFile` without a containment check, allowing arbitrary file write of `EvilProvider.dll` into `/wyn/Server/SecurityProviders/` (CWE-22); (VULN-C) `SecurityProviderLoadService.LoadAssemblies` scans `SecurityProviders/*.dll` and calls `Activator.CreateInstance` on the parameterless constructor of `ISecurityProviderFactory` types, executing attacker code as root (CWE-502/915). Dynamically verified with root RCE.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Wyn Enterprise
- **Versions**: 9.1.00145.0 (and other versions sharing the same token-validation / import / provider-load behavior)
- **Vendor**: Mescius (GrapeCity)

## Impact

- **Confidentiality**: Full read of the host filesystem and configuration as root
- **Integrity**: Arbitrary OS command execution as root (dotnet container process)
- **Availability**: Full control of the Wyn server; ability to persist

## Exploitation Prerequisites

Default configuration; network reachability to the Wyn HTTP endpoint. No password, no operator action, no restart required. The chain is fully unauthenticated and HTTP-based. Dynamically verified with root RCE.

## Mitigation

1. Use `ValidateToken` with proper signature validation instead of parse-only `ReadToken`
2. Rotate/remove the hardcoded integration client secret; require real credentials for the password grant
3. Add a containment check (`IsSubDirectoryOf`) in `SecurityProviderService.ImportFiles` (the export path already has one — mirror it)
4. Restrict `SecurityProviderLoadService.LoadAssemblies` to an allowlist of known provider DLLs/assemblies
5. Do not run the server as root; run under a dedicated low-privilege user

## Timeline

- **Discovered**: 2026-08-09
- **Public Disclosure**: 2026-08-09 (batch #3)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
