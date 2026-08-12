# GE PulseNET Enterprise ResourceFile Path Traversal Unauthenticated RCE

## Summary

GE Vernova PulseNET Enterprise 6.0.3 (build 6975) ships with a factory-default `admin:admin` account (`changePassword:false`, no forced password change) and a path-traversal arbitrary file write in the resource-management console. An attacker logs in with the shipped default credentials, uploads a JSP file, and sets a resource `path` containing `../` segments. `Resource.getFilePath()` concatenates the untrusted `path` and `name` into the filesystem path with no normalization, and `ResourceServiceImpl.saveResource()` writes the uploaded bytes via `FileOutputStream`. Because Tomcat runs as `root` with `autoDeploy=true`, the JSP lands in a new webapp directory and is compiled and executed by the JSP servlet — resulting in unauthenticated (default-credentials) root RCE. Dynamically verified (`uid=0(root)`).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: GE Vernova PulseNET Enterprise
- **Versions**: 6.0.3 (build 6975)
- **Vendor**: GE Vernova

## Impact

- **Confidentiality**: Full read of host filesystem as root
- **Integrity**: Arbitrary file write anywhere on disk as root
- **Availability**: Full control of the PulseNET host

## Exploitation Prerequisites

Default installation: shipped `admin:admin` credentials with no forced password change; Tomcat runs as `root`; `autoDeploy=true` (default); the management HTTPS port (8443) is reachable. The upload extension check (`.zip`) is client-side only; the server performs no extension validation and no path normalization.

## Mitigation

1. Force a password change on first login or generate a random admin password at install time
2. Normalize and validate `resource.path`/`name` in `Resource.getFilePath()` (reject `..`, force basename)
3. Enforce a server-side extension whitelist in `saveResource` (do not trust client-side checks)
4. Isolate resource writes outside webapp-reachable directories
5. Set `autoDeploy=false` in production
6. Run Tomcat under a dedicated non-root service account

## Timeline

- **Discovered**: 2026-08-12
- **Public Disclosure**: 2026-08-12 (batch #4)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble.
