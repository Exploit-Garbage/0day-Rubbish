# NCache Enterprise — Unauthenticated Assembly.LoadFrom RCE via Web Manager

## Summary

An unauthenticated remote code execution vulnerability in NCache Enterprise 5.3.6. The NCache Web Manager (ASP.NET Core Razor Pages on Kestrel, HTTP 8251) ships with security disabled by default (`security.ncconf enabled="false"`), and its custom `authMiddleware` only redirects to login when security is enabled — so every Web Manager handler is reachable without authentication (CWE-306). An attacker uploads a malicious .NET assembly via the `GenericTypeProvider` handler, then triggers `OnPostGetGenericHandlerType`, which calls `Assembly.LoadFrom` on the uploaded DLL and instantiates the attacker's class (`assembly.CreateInstance`), executing code as the `ncache` service user (CWE-94/CWE-434).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: NCache Enterprise (Web Manager)
- **Versions**: 5.3.6 (other versions with the same default-disabled security and handler logic are likely affected)
- **Vendor**: Alachisoft

## Impact

- **Confidentiality**: Full read access to cache data and host files as the `ncache` user
- **Integrity**: Arbitrary code execution in the Web Manager process context
- **Availability**: Full control of the caching node

## Mitigation

1. Enable security in `security.ncconf` (`enabled="true"`) and configure an admin account
2. Add `[Authorize]` to the management handlers instead of relying on the single middleware gate
3. Validate `configId` against real caches and restrict upload file types
4. Never `Assembly.LoadFrom` attacker-supplied DLLs; use metadata-only reflection or a sandboxed AppDomain
