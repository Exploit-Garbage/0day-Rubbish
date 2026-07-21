# Brekeke SIP Server Authentication Fail-Open Primitive

## Summary

A critical authentication-bypass primitive in Brekeke SIP Server allows unauthenticated attackers to reach 23 business beans through a self-developed authentication framework that fails open for any bean that has not declared a scope, combined with a `GateServlet` dispatcher where the `bean` request parameter is fully attacker-controlled.

## CVSS Score

- **Score**: 9.1 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Brekeke SIP Server (SIP Proxy / SIP Registrar)
- **Versions**: v3.19.1.8p1 (Evaluation Edition) and versions using the same `ScopeBean.checkScope()` framework
- **Vendor**: Brekeke Software, Inc.

## Impact

- **Confidentiality**: Unauthenticated access to 23 beans including database recovery, license management, and configuration
- **Integrity**: Two of the exposed beans chain into full unauthenticated remote code execution as the `tomcat` user
- **Availability**: Unauthenticated access to high-availability actions, database recovery, and service configuration

## Mitigation

1. Fail-closed authentication: `ScopeBean.checkScope()` must fail closed — beans with an undeclared scope should be denied by default, not admitted
2. Mandatory scope declaration: every bean should be required to call `setCheckScope(...)` at construction; the framework should refuse to dispatch beans without a declared scope
3. Allowlist the `bean` parameter: `GateServlet` should not instantiate arbitrary classes from an attacker-controlled parameter; restrict dispatch to an explicit allowlist of bean names
4. Fix `isAdmin()`: invert the logic so anonymous callers are not treated as admins
5. Real `checkAuth()`: replace the always-true default with an enforced authentication check

## Timeline

- **Discovered**: 2026-07-15
- **Public Disclosure**: 2026-07-15

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).