# Brekeke PBX — Unauthenticated XmlTransBean Util.exec RCE

## Summary

An unauthenticated remote code execution vulnerability in Brekeke PBX 3.19.1.8. The `/pbx` web application has no container-level security constraints or filters, and the `Bean.checkAuth()` gate is fail-open for POST requests. The `GateServlet` maps `/gate` and dynamically instantiates any `com.brekeke.<bean>` class via the `bean=` parameter. The `web.XmlTransBean` handler parses an attacker-supplied XML body, loads an arbitrary class via `Class.forName`, and invokes any public static method matching the `act` attribute — reaching `com.brekeke.util.Util.exec(String[])`, which calls `Runtime.getRuntime().exec()` (CWE-306 + CWE-917). A single unauthenticated POST yields command execution as the `tomcat` user.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Brekeke PBX (`/pbx` web application)
- **Versions**: 3.19.1.8 (other versions with the same Bean dispatch model are likely affected)
- **Vendor**: Brekeke Software

## Impact

- **Confidentiality**: Full access to PBX configuration and call data as the `tomcat` user
- **Integrity**: Arbitrary command execution in the Tomcat process context
- **Availability**: Full control of the PBX host

## Mitigation

1. Require authentication for `XmlTransBean` (route it through the `pbxPageAccess` gate)
2. Fix `Bean.checkAuth()` to deny by default instead of fail-open
3. Whitelist classes allowed by `Class.forName` (XmlTransServer subclasses only)
4. Make `Util.exec` non-public (package-private) or verify the caller
