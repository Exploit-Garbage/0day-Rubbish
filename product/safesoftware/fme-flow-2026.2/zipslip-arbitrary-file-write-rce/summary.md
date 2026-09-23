# FME Flow Zip-Slip Arbitrary File Write → Code Execution as LocalSystem

## Summary

FME Flow 2026.2 (build 26333), from Safe Software Inc., contains a path-traversal write inside archive extraction (Zip-Slip, CWE-22) in `COM.safe.web.upload.StoreManager.extract()`, shipped in `clients-webservicesutil-1.0.jar`. The sink builds each destination path from `ZipArchiveEntry.getName()` verbatim; commons-compress 1.26.2 does not normalise `..`, and the class's own canonical containment check `isPathValid()` is called only from the constructor, never from the extraction path. Any authenticated user — including the low-privilege `fmeuser` and `fmeguest` roles — can upload a crafted zip to `POST /fmedataupload/<repo>/<scope>` with `opt_extractarchive=true`; that branch performs no role or `isPermitted` check. A single entry name carrying enough `../` escapes the upload sandbox and writes an attacker-named file, with attacker-chosen content, anywhere the Tomcat process can write. On a default Windows single-machine install the repository root and `WEBAPPSDIR` share the ancestor `INSTALLDIR` on one volume, so the write can be aimed at an expanded web application's document root. With `unpackWARs=true`, no `/*` servlet mapping in `fmeserver.war`, and Tomcat installed as the `FMEFlowAppServer` service running as `.\LocalSystem`, requesting the dropped `.jsp` yields command execution as LocalSystem.

## CVSS Score

- **Score**: 8.8 High (post-authentication)
- **Vector**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Conditional upper bound**: 9.8 Critical (`PR:N`) where a public app is published with `requireAuthentication=false` and `allowTemporaryUploads=true` — not a shipped default.

## Affected Products

FME Flow 2026.2 build 26333 ( analysed from `fme-flow-2026.2-b26333-win-x64.exe` ). Other builds sharing the same extraction path are likely affected.

## Impact

- **Arbitrary file write**: an authenticated user creates an attacker-named file with attacker-chosen content anywhere the Tomcat process can write, outside the upload sandbox.
- **Code execution**: on a default single-machine Windows install the write reaches an expanded web application's document root, where the container's default JSP servlet compiles and executes the dropped `.jsp` on first request — under the Tomcat service account, `.\LocalSystem`.
- **Create-only primitive**: the copy is guarded by an existence test, so an existing file at the destination is left untouched and can be neither truncated nor overwritten.
- **Escalation**: a low-privilege FME user obtains the service account's authority over the host, its configuration and the bundled database.

## Independence

Distinct from the previously published CVE-2023-35801 and CVE-2022-38340 HTTP path-traversal issues, whose `..` sequences travel in the request URL and are collapsed by Tomcat's `CoyoteAdapter.normalize()`. Here the traversal travels in zip entry names inside the request body, which URL normalisation never inspects, so those fixes do not cover this vector.

## Mitigation

1. Apply a canonical-path containment check to every entry before writing; reuse the existing `isPathValid()` in `createNew()` / `createFileDesc()`.
2. Remove write access to `WEBAPPSDIR` from the service account's ACLs — the highest-value compensating control.
3. Run the Tomcat service as a least-privilege account instead of `.\LocalSystem`.
4. Add a resource-level authorisation check to the data-upload path.
5. Keep the repository tree and `WEBAPPSDIR` on separate volumes; place `*.jsp` under file-integrity monitoring.

## PoC

`exploit/fme_flow_zipslip_file_write_rce.py` — builds the traversal archive, delivers it with `opt_extractarchive=true` and an `FMEToken`, then requests the dropped JSP and verifies the execution marker. `--mode zip` builds and self-checks the archive only.

## References

- Advisory: https://0day-rubbish.com/blog/fme-flow-zipslip-arbitrary-file-write-rce
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com

---
*Maintained by the 0day Rubbish research team.*
