# Wyn Enterprise Unauthenticated Root RCE (Token Forgery + Zip-Slip + Provider Load) — Technical Analysis

## Overview

Wyn Enterprise 9.1.00145.0 (Mescius/GrapeCity, .NET 8 Embedded BI & Reporting Server, Docker deployment, container dotnet runs as root, PID1=`dotnet Wyn.Server.dll --RunAsMonitor`) exposes an unauthenticated root RCE chain of three vulnerabilities:

- **VULN-A (CWE-347 + CWE-798)**: `ResourceOwnerValidator.cs:145` uses `JwtSecurityTokenHandler.ReadToken()` (parse-only, no signature validation) instead of `ValidateToken`, combined with a hardcoded integration client secret (`eunGKas3Pqd6FMwx9eUpdS7xmz`, `ProductionClientProducer.cs:29`) -> unauthenticated 10-year admin reference token.
- **VULN-B (CWE-22)**: `SecurityProviderService.ImportFiles` (`SecurityProviderService.cs:202-219`) uses `Path.GetFullPath(Path.Combine(destFolder, entry.FullName))` + `ExtractToFile` with no containment check -> arbitrary file write (drop `EvilProvider.dll` into `/wyn/Server/SecurityProviders/`).
- **VULN-C (CWE-502/915)**: `SecurityProviderLoadService.LoadAssemblies` scans `SecurityProviders/*.dll` and calls `Activator.CreateInstance` on the parameterless constructor of `ISecurityProviderFactory` types (root) -> RCE. Trigger: `POST /api/v2/identity/security-providers/reload` (forceReload:true).

All three are reachable without credentials in the default configuration. Dynamically verified with root RCE.

- **Authentication required**: None (unauthenticated)
- **Preconditions**: Default configuration; network reachability to the Wyn HTTP endpoint
- **Affected versions**: 9.1.00145.0
- **Privilege**: root (container dotnet process)

## Architecture

```
L1 external access: Wyn HTTP endpoint (container dotnet, root)
L2 auth: IdentityServer4 (integration client password grant) - VULN-A forges admin token
L3 VULN-A: ResourceOwnerValidator ReadToken (no signature check) + hardcoded secret -> 10y admin reference token
L4 VULN-B: POST admin/api/import (parse zip) -> GET admin/api/import/process/<sessionId> -> ImportFiles -> Zip-Slip write EvilProvider.dll
L5 VULN-C: POST /api/v2/identity/security-providers/reload -> LoadAssemblies -> Activator.CreateInstance (parameterless ctor, root)
L6 exec: ctor code runs as root -> arbitrary command
```

## VULN-A: Token Forgery (CWE-347 + CWE-798)

`ResourceOwnerValidator.cs:145` uses `JwtSecurityTokenHandler.ReadToken()` (parse-only) instead of `ValidateToken`. The integration client secret is hardcoded. An attacker crafts an unsigned JWT (`{"alg":"none","typ":"JWT"}` + `{"name":"admin","idp":"local"}`) and exchanges it at `/connect/token` with `grant_type=password&client_id=integration&client_secret=<hardcoded>&username=admin&jwt_token=<jwt>`, receiving a 10-year admin reference token. No password required.

## VULN-B: Zip-Slip Arbitrary File Write (CWE-22)

`SecurityProviderService.ImportFiles`:

```csharp
// SecurityProviderService.cs ImportFiles (ilspycmd decompiled)
string text = GetDestFolder(setting);  // = /wyn/Server/SecurityProviders/
foreach (ZipArchiveEntry entry in archive.Entries) {
    string fullPath = Path.GetFullPath(Path.Combine(text, entry.FullName));  // entry.FullName attacker-controlled
    // no IsSubDirectoryOf / containment check (ExportFiles:180-198 has it; ImportFiles does not = asymmetric bug)
    entry.ExtractToFile(fullPath, overwrite: false);  // arbitrary file write (new files only)
}
```

Reachable endpoints (`[Authorize("AdminOnly")]`):
- `POST admin/api/import` (line 389) — parses zip, stores ImportContext to `_importSession` (1h expiry), returns sessionId
- `GET admin/api/import/process/{sessionId}` (line 636) — triggers ProcessCore -> ImportSetting -> ImportFiles (file write before config read)

Import zip structure: outer = `export.manifest` (`{"Refs":[],"Docs":[],"Sets":[{Id,Type:"sys-secprovider",Name,NeedStream:true,Items:{}}]}`) + `<Set.Id>` entry (inner zip); inner = `securityProviders.config`=`[]` + payload entry (e.g. `EvilProvider.dll` direct filename, lands in SecurityProviders/).

## VULN-C: Provider Load RCE (CWE-502/915)

`SecurityProviderLoadService.LoadAssemblies`:

```csharp
// SecurityProviderLoadService.cs (ilspycmd decompiled)
string[] files = Directory.GetFiles(_folderPath, "*.dll");  // _folderPath = /wyn/Server/SecurityProviders
foreach (string file in files) {
    if (FilteredDlls.Contains(Path.GetFileName(file))) continue;  // 5 exclusions; EvilProvider not in them
    var assembly = new SecurityProviderLoadContext(file).LoadFromAssemblyPath(file);
    foreach (var type in assembly.GetTypes()) {
        if (typeof(ISecurityProviderFactory).IsAssignableFrom(type)
            || typeof(GrapeCity...ISecurityProviderFactory).IsAssignableFrom(type)) {
            try {
                Activator.CreateInstance(type);  // RCE sink: parameterless ctor, root
            } catch (Exception ex) {
                _logger.LogWarning(...);
            }
        }
    }
}
```

Trigger: `SecurityProviderV2Controller.cs:188-195` `[HttpPost("reload")] [Authorize("AdminOnly")]` -> `LoadProvidersAsync(forceReload:true)` -> `Initialize()` -> `_allProviderFactories.Clear()` + `LoadAssemblies()` -> re-CreateInstance. `SecurityProviderLoadContext.Load` returns null for assemblies outside the folder -> falls back to default context -> `System.Diagnostics.Process` / `System.IO.File` resolve correctly -> ctor can `Process.Start`.

## Exploitation Chain

1. **VULN-A**: forge admin reference token (unsigned JWT + hardcoded secret) at `/connect/token`
2. **VULN-B**: build import zip (outer manifest + inner zip with `securityProviders.config` + `EvilProvider.dll`), `POST admin/api/import` -> sessionId -> `GET admin/api/import/process/<sessionId>` -> DLL written to SecurityProviders/
3. **VULN-C**: `POST /api/v2/identity/security-providers/reload` -> `Activator.CreateInstance(EvilProvider)` parameterless ctor runs as root -> marker written, `Process.Start("/bin/sh","-c","id >> marker")`
4. Verify: marker file contains `CTOR-RAN-AS-ROOT` + `uid=0(root)`

## Dynamic Verification

Verified end-to-end: unauthenticated token forgery -> admin import (Zip-Slip write of EvilProvider.dll) -> security-provider reload -> `Activator.CreateInstance` ctor runs as root -> marker file confirms root RCE. All steps unauthenticated and HTTP-based.

## Mitigation

1. Use `ValidateToken` with proper signature validation instead of parse-only `ReadToken`
2. Rotate/remove the hardcoded integration client secret; require real credentials for the password grant
3. Add a containment check (`IsSubDirectoryOf`) in `SecurityProviderService.ImportFiles` (the export path already has one — mirror it)
4. Restrict `SecurityProviderLoadService.LoadAssemblies` to an allowlist of known provider DLLs/assemblies
5. Do not run the server as root; run under a dedicated low-privilege user

## CWEs

- CWE-347 (Improper Verification of Cryptographic Signature) - ReadToken without signature validation
- CWE-798 (Use of Hard-coded Credentials) - hardcoded integration client secret
- CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) - Zip-Slip in ImportFiles
- CWE-502/915 (Deserialization / Improperly Controlled Dynamic Code Loading) - Activator.CreateInstance of attacker DLL
- CWE-250 (Execution with Unnecessary Privileges) - server runs as root
