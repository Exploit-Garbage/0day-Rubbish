# Apache Struts 2 RestfulActionMapper OGNL Injection Unauthenticated Root RCE

## Summary

A critical remote code execution vulnerability in Apache Struts 2 arises because `RestfulActionMapper.getMapping()` extracts the action name from the request URI without the `cleanupActionName` character-set sanitization that `DefaultActionMapper` adopted after S2-057. Under a documented REST mapper configuration combined with wildcard dynamic dispatch, attacker-controlled OGNL metacharacters flow through the wildcard `{1}` capture into `StrutsResultSupport.conditionalParse` → `TextParseUtil.translateVariables` OGNL evaluation, which bypasses `AcceptedPatternsChecker`. A novel `java.beans.Expression`/`Statement` internal-reflection primitive then defeats the `SecurityMemberAccess` sandbox (`java.beans` is not on the exclusion list and its internal `Method.invoke` is invisible to OGNL), yielding unauthenticated `Runtime.exec` and root RCE.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Apache Struts 2
- **Versions**: 6.11.0 (latest 6.x, released 2026-08-01) and earlier 6.x versions without the allowlist sandbox
- **Vendor**: Apache Software Foundation

## Impact

- **Confidentiality**: Full read of application data, configuration, and environment; arbitrary file read as the JVM user
- **Integrity**: Arbitrary operating system command execution as the JVM process user; ability to alter application state and persistence
- **Availability**: Full control of the JVM process and host command execution; ability to terminate or persist on the host

## Exploitation Prerequisites

This is **not** a default-configuration unauthenticated RCE. It requires an opt-in but documented configuration subset: `struts.mapper.class=restful` (the documented REST mapper, the actual root-cause bug — `RestfulActionMapper` never adopted the `cleanupActionName` sanitization that `DefaultActionMapper` gained after S2-057) combined with wildcard dynamic dispatch (`<action name="*">` as matcher and a result containing `{1}` substitution as delivery). Both are documented, common patterns in REST-style Struts2 applications, but the combination is an opt-in subset, not the default posture — not every Struts2 application is affected. `struts.ognl.allowStaticFieldAccess=true` is a framework default (`default.properties:225`) and need not be set explicitly. The chain was dynamically verified with `uid=0(root)` on a Tomcat 9 / OGNL 3.3.5 test deployment. Struts 7.3.0 is protected by the new default `struts.allowlist.enable=true` (allowlist sandbox), which blocks the `java.beans` bypass primitive.

## Mitigation

1. Unify action-name sanitization in `RestfulActionMapper.getMapping()` by calling `cleanupActionName` before returning the `ActionMapping`, matching `DefaultActionMapper`, so OGNL metacharacters are rejected at the mapper boundary
2. Add `java.beans` to `struts.excludedPackageNames` so the `Expression`/`Statement` reflection primitive is blocked by the sandbox
3. Route `translateVariables` OGNL evaluation of result locations through `AcceptedPatternsChecker`, or disable `%{}` evaluation in result locations by default
4. Backport the Struts 7.3.0 `struts.allowlist.enable=true` allowlist-sandbox default to the 6.x branch

## Timeline

- **Discovered**: 2026-08-02
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
