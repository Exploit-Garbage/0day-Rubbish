# Akana API Platform — Path-Normalization Filter/Dispatcher Discrepancy → Unauthenticated RCE

## Summary

Akana API Platform 8.4.29's Policy Manager console contains a classic path-normalization filter/dispatcher discrepancy. The authentication filter `SessionValidatorFilter` uses `request.getRequestURI()` (the client's raw, un-normalized URI) to decide which paths are exempt from authentication, matching the wildcard exception `/admin/*`. The underlying servlet router (embedded Jetty 7.6.10) normalizes `..` before dispatch. An attacker requests `/admin/../ext/scriptTestServ`: the filter sees `/admin/...`, matches the exempt `/admin/*`, and skips authentication; the dispatcher normalizes the path to `/ext/scriptTestServ` and routes to the protected `ScriptTestServlet`, which reaches `engine.eval()` with fully attacker-controlled script content.

`ScriptTestServlet` decodes a Base64 `script` parameter and evaluates it with the attacker-chosen engine (`js` → Nashorn, `python` → Jython 2.7.1, `beanshell` → BeanShell 2.1.8), with zero sanitization, whitelist, or sandbox. The result is unauthenticated remote code execution as the container's default `akanaAdmin` user on a default installation.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Akana API Platform (Policy Manager console)
- **Versions**: 8.4.29 verified; other 8.x releases with the same `SessionValidatorFilter` + `ScriptTestServlet` combination are likely affected
- **Vendor**: Akana (Perforce)
- **Prerequisite**: default configuration; Policy Manager console feature enabled

## Impact

- **Confidentiality**: arbitrary command execution as `akanaAdmin` — API gateway configurations, credentials, and proxied traffic accessible
- **Integrity**: full control of the API management console and policy engine
- **Availability**: host compromise of the API platform server

## Mitigation

1. Make `SessionValidatorFilter` decide authentication on the normalized path (`getServletPath()`) instead of raw `getRequestURI()`
2. Add a leading normalization filter that rejects `..` and encoded variants (`%2e%2e`, `%2e./`, `.%2e`)
3. Add an in-servlet authentication check and restrict `ScriptEngine` capabilities (block `Runtime`/`ProcessBuilder`/`import`)
4. Narrow the `/admin/*` exempt path to exact login paths
