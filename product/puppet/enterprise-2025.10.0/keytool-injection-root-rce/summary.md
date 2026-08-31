# Puppet Enterprise — CVE-2025-5459 Patch-Bypass Variant → keytool Shell Injection → Root RCE

## Summary

Puppet Enterprise 2025.10.0 (a version that already fixes CVE-2025-5459) still contains an unpatched command-injection sink of the same family. The CVE-2025-5459 patch added sanitization to the `code_management` module parameters in `code_management.pp` but **missed** the `java_keystore_passwd` parameter in `master.pp` — the same shell-executed `keytool` pattern with no validation and no `Sensitive()` wrapping.

An administrator with node-group editing rights (the PE super-admin satisfies this by default) can set `java_keystore_passwd` on the `puppet_enterprise::profile::master` class via the classifier API, supply a `trusted_infra_cacert` to arm the `pe_java_keytool_import` exec, and trigger a puppet agent run. Because the exec command is a String (executed via `/bin/sh -c`) and the parameter is wrapped only in single quotes with no escaping, a single-quote breakout plus a semicolon injects arbitrary commands that run as **root** (the master puppet agent runs as root by default). Verified end-to-end with a root-owned marker file (`uid=0(root)`).

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Puppet Enterprise
- **Versions**: 2025.10.0 verified (post-CVE-2025-5459 patch); earlier versions with the same unvalidated `java_keystore_passwd` are also affected
- **Vendor**: Puppet (Perforce)
- **Prerequisite**: admin RBAC token + PE Master node-group edit rights (super-admin default)

## Impact

- **Confidentiality**: root access to the Puppet master — the control plane that manages the entire managed fleet
- **Integrity**: arbitrary command execution as root on the primary host; catalogs, certificates, and managed-node state under attacker control
- **Availability**: full compromise of the configuration-management server and its orchestration capabilities

## Mitigation

1. Apply the same sanitization used for `code_management` parameters to `java_keystore_passwd` (`pe_validate_absolute_path()` + `Sensitive()`)
2. Use Array-form `exec` commands instead of String commands to avoid `/bin/sh -c` parsing
3. Restrict node-group editing to least-privilege roles; audit all classifier class-parameter changes
