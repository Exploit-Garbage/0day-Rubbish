# KeyHelp Apache Custom Directive ErrorLog Pipe to Root RCE

## Summary

An authenticated remote code execution vulnerability in KeyHelp 26.0 allows an administrator to inject arbitrary Apache configuration directives through the "custom directives" field of the domain editor. The input is written into the per-domain vhost configuration without any filtering or allowlist. Apache accepts piped `ErrorLog "|/bin/sh -c '...'"` directives, and the Apache master process (running as `root`) spawns the piped program, resulting in arbitrary command execution as `root`. This breaks the intended admin-to-root boundary in the KeyHelp security model.

## CVSS Score

- **Score**: 7.2 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: KeyHelp (Keyweb AG hosting control panel)
- **Versions**: 26.0 Build 3624
- **Vendor**: Keyweb AG

## Impact

- **Confidentiality**: Full server compromise; `root` access
- **Integrity**: All hosted domains, customer data, panel data, and other host services at risk
- **Availability**: Full control of the hosting server

## Mitigation

1. Sanitize or block the custom Apache directives field; do not allow pipe-prefixed log directives
2. Run Apache master and workers under an unprivileged account
3. Apply a strict allowlist of permitted Apache directives in the panel
4. Restrict administrator access to trusted administrators only

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
