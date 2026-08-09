# ObjectDB JDOQL Filter Injection to Root RCE

## Summary

A critical remote code execution vulnerability in ObjectDB 2.9.5 server mode (port 6136, proprietary binary protocol) arises because JDOQL query filter evaluation allows arbitrary static-method reflective invocation (CWE-94). The factory default credentials `admin/admin` (CWE-798) grant full privileges with no forced change. A malicious JDOQL filter such as `java.lang.Runtime.getRuntime().exec(cmd) != null` is evaluated server-side: `QNF.q()` loads any class (no class-name allowlist), `MCN.l()` calls `Method.invoke` with `setAccessible(true)`, reaching `Runtime.exec` — the server-side Java process runs as root, yielding `uid=0(root)` RCE. Dynamically verified.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: ObjectDB
- **Versions**: 2.9.5 (server mode)
- **Vendor**: ObjectDB Software (Israel)

## Impact

- **Confidentiality**: Full read of the host filesystem and JVM environment as root
- **Integrity**: Arbitrary OS command execution as root (ObjectDB server process)
- **Availability**: Full control of the ObjectDB host and database

## Exploitation Prerequisites

Default credentials `admin/admin` (CWE-798, factory default, no forced change; the IP check accepts any source IP when the user has no `ip` attribute). Network reachability to port 6136. The JDOQL filter is supplied by the client via `Query.setFilter(filter)` and transported to the server over the proprietary protocol. Dynamically verified with `uid=0(root)`.

## Mitigation

1. Force a password change on first login; disallow the factory default `admin/admin`
2. Add a class-name allowlist to `QNF.q()` (currently only `Math`/`JDOHelper`/`String` are checked by `QMR.c()`, but arbitrary classes are loadable via `loadClass`)
3. Remove `setAccessible(true)` in `MCN.l()` so Java access control cannot be bypassed
4. Run the server under a dedicated low-privilege user, not root
5. Restrict network exposure of the ObjectDB server port

## Timeline

- **Discovered**: 2026-08-05
- **Public Disclosure**: 2026-08-09 (batch #3)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
