# Joget Workflow Enterprise JasperReports jrxml Expression Injection RCE

## Summary

A critical unauthenticated remote code execution vulnerability in Joget Workflow Enterprise 9.1.0.1 allows remote attackers to achieve root code execution through expression injection in the JasperReports `jrxml` template processed by the `JasperReportsMenu` enterprise plugin. The plugin service route is accessible to anonymous users (`ROLE_ANONYMOUS`) and performs no permission checks; a `textFieldExpression` in the attacker-supplied `jrxml` can invoke arbitrary Java including `Runtime.getRuntime().exec(...)`.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Joget Workflow Enterprise
- **Versions**: 9.1.0.1
- **Vendor**: Joget

## Impact

- **Confidentiality**: Full system compromise; arbitrary command execution as `root`
- **Integrity**: Full control of the low-code platform and all hosted applications/data
- **Availability**: Full control of the application server

## Mitigation

1. Remove anonymous access to the plugin service route and enforce per-plugin permission checks
2. Enable JasperReports `ReportClassFilter` or a strict expression allowlist
3. Validate `jrxml` input as a template, not executable code
4. Run Joget under an unprivileged account

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
