# Acumatica Customization Publish Webshell RCE

## Summary

An authenticated remote code execution vulnerability in Acumatica ERP 2026 R1 (build 26.101.0225). The Customization (customization package) publish framework lets an authenticated user (admin has the Customizer role by default) upload a zip customization package whose `project.xml` manifest declares the files to publish and their `AppRelativePath`. At publish time the framework writes each file's content to the absolute path `DestRoot (= IIS production webroot) + AppRelativePath`, with **no `..` path-traversal check, no allowlist, no extension check**. An attacker crafts a manifest declaring `AppRelativePath="Pages\acu_shell.aspx"` and embeds the matching webshell in the zip; after publish the webshell is written to `<webroot>\Pages\acu_shell.aspx` and served by IIS at `/Pages/acu_shell.aspx`, achieving authenticated RCE as the IIS AppPool identity.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Acumatica ERP (.NET ERP platform)
- **Versions**: 2026 R1 (build 26.101.0225) and versions using the same `CstRollbackList.WriteFile` / `CstFileWriter.UpdateFile` publish path
- **Vendor**: Acumatica

## Impact

- **Confidentiality**: Read/write the webroot and access the SQL Server database as the IIS AppPool identity
- **Integrity**: Arbitrary command execution as the IIS AppPool identity; ability to alter ERP configuration and persisted data
- **Availability**: Full control of the ERP web application; can stop/disable the service

## Exploitation Model

This is a Target A (network service) vulnerability, on the authenticated path. The IIS site listens on port 8080 by default (production deployments often bind 0.0.0.0 or a public IP). Authentication uses the admin default credentials (set by the deployment `-aup` parameter; usable if unchanged) plus the Customizer role (admin has it by default). The `/entity/auth/login` endpoint returns a soap-prefixed `.ASPXAUTH` ticket that satisfies the `CustomizationApiAccessFilter`, granting access to `Import` + `PublishBegin`. The exploit does not depend on the machineKey (pure file write + IIS .aspx parsing), so any default-config Acumatica instance where admin has the Customizer role is exploitable.

## Mitigation

1. Path validation: in `CstRollbackList.WriteFile` / `CstFileWriter.UpdateFile`, after concatenating `DestRoot + AppRelativePath`, normalize with `Path.GetFullPath` and verify the result stays within the `DestRoot` subtree; reject `AppRelativePath` values containing `..`
2. Extension allowlist: restrict published file extensions to business files (.css/.js/.png/.xml, etc.); reject executable/config extensions such as `.aspx`/`.asp`/`.ashx`/`.asmx`/`.config`
3. Publish-directory isolation: publish customization files to a separate subdirectory (e.g. `App_RuntimeCustomization/`) rather than directly into the webroot, and disable .aspx execution in that directory (remove the aspx handler from IIS `<handlers>`)
4. Role least-privilege: admin should not have the Customizer role by default; require explicit assignment
5. Default credentials: force a password change after deployment; do not leave default admin credentials

## Timeline

- **Discovered**: 2026-07-19
- **Public Disclosure**: 2026-07-19

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).