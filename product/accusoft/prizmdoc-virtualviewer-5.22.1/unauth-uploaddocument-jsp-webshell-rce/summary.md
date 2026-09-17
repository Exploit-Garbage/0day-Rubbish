# Accusoft / Apryse PrizmDoc for Java (VirtualViewer) 5.22.1 — Unauthenticated `uploadDocument` Arbitrary File Write to JSP Webshell to Root RCE

## Summary

PrizmDoc for Java, delivered as the VirtualViewer document-viewer web application (Snowbound lineage, US vendor), funnels its whole HTTP API through a single servlet — `com.snowbound.ajax.servlet.AjaxServlet` at `/AjaxServlet` — whose `service()` dispatches an `action` parameter across 28 actions. In build 5.22.1 the webapp's `WEB-INF/web.xml` declares exactly one servlet mapping and no security configuration at all: no `security-constraint`, no `filter-mapping`, no `login-config`, so every one of those 28 actions is reachable anonymously (CWE-306). One of them, `uploadDocument` (handler `ac.b()`), takes a user-controlled `filename` from the query string via `g.c(request, "filename")` plus the bytes of a multipart part named `file`, and hands both to the default content handler `FileContentHandler`. `FileContentHandler.createDocument` (FileContentHandler.java:380-394) turns that value into the on-disk name using a sanitizer — `FileContentHandler.a(String)` at FileContentHandler.java:1012-1030, i.e. `Paths.get(string).getFileName().toString()` — that only reduces the input to its last path element, and then writes the bytes with `ClientServerIO.saveFileBytes`. The sanitizer stops `../../` escapes but places no restriction on the extension, and the write target is `context.getRealPath("./sample-documents")`, a directory inside the deployed webapp root. Because Tomcat's container-wide descriptor maps `*.jsp` to the `JspServlet` (conf/web.xml:448) across the whole webapp tree, uploading a JSP webshell therefore drops directly into executable web space, and a follow-up `GET /virtualviewer/sample-documents/shell_<id>.jsp?cmd=<command>` compiles and runs it. Two unauthenticated HTTP requests yield arbitrary command execution; the license check in `service()` does not stop it either, because with no license loaded `LicenseManager.isLicenseLess()` returns `true` and the condition short-circuits, and the `disableUploadDocument` init-param ships as `false`. In the verified deployment the JVM ran as uid 0, so the chain produced root RCE — dynamically confirmed across three independent runs (`id`, `whoami; hostname; head -1 /etc/passwd`, and a fresh random marker written to `/tmp/vv_final_proof.txt` and read back over SSH as `root`), and validated by two adversarial passes (falsification NOT_REFUTED 0.98, independent re-analysis CONFIRMED 0.98).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Accusoft / Apryse PrizmDoc for Java (VirtualViewer) document-viewer server
- **Vendor**: Accusoft / Apryse (United States); product descends from the Snowbound code line
- **Version**: 5.22.1 (production build) verified. Other versions were not tested and are not documented in the research record
- **Runtime verified**: Apache Tomcat 9.0.104 with OpenJDK 17.0.19, `virtualviewer.war` deployed to `webapps/virtualviewer/`
- **Prerequisites**: network reachability of `/virtualviewer/AjaxServlet` only — no credentials, no session, no man-in-the-middle position, no dependence on an installation window. The tested deployment ran without a loaded license (the code-execution primitive itself does not depend on that)
- **Public CVE history**: the research record documents only CVE-2018-15805 (XXE in versions before v13.5, since fixed); this finding is unrelated to it

## Impact

- **Confidentiality**: arbitrary command output is returned in the HTTP response of the dropped webshell; hosted documents in the content-handler store (`./sample-documents`) are readable, as are the servlet container configuration, certificates, keystore material and backend connection strings on the host
- **Integrity**: attacker-controlled files are written into the web application root — documents can be altered, replaced or destroyed, and additional webshells can be planted for persistence; the host filesystem is writable at the privilege of the JVM
- **Availability**: the document service, the Tomcat instance and the host itself can be stopped, degraded or wiped
- **Execution identity**: uid=0 (root) in the verified deployment, where Tomcat ran as root. The unauthenticated webshell write-and-execute primitive holds under any service account; that account's privileges then set the blast radius
- **Pivot**: a document viewer is a backend called by other applications and typically sits in the same trust zone as the systems embedding it (the recovered action list includes document-handling actions such as `emailDocument`), so root on that host converts a viewing service into a lateral-movement foothold

## Mitigation

1. Declare authentication for `AjaxServlet`: add a `security-constraint` plus `login-config` covering `/AjaxServlet` in `WEB-INF/web.xml`, or register an authentication filter, so no action dispatches for anonymous callers
2. Enforce an extension allow-list in `FileContentHandler.createDocument` (for example `.pdf`, `.tif`, `.docx`) and reject anything the container can execute or deploy — `.jsp`, `.jspx`, `.war`. A deny-list is not sufficient
3. Move the document store out of the web application root, to a path the container neither serves nor compiles (for example `/var/lib/virtualviewer/docs/`) instead of `sample-documents/`
4. Narrow the JSP mapping so that it does not cover upload directories, or configure a `jsp-property-group` disabling scripting for paths where user-supplied files can land
5. Make the license gate fail closed: when `isLicenseLess()` is `true`, refuse every action except the minimal health / license-query set rather than short-circuiting the check
6. Operator hardening pending a vendor fix: never expose `/virtualviewer/AjaxServlet` to untrusted networks (front it with an authenticating reverse proxy or restrict it to trusted networks), run the JVM under a dedicated non-root account, disable document upload where unused (`disableUploadDocument` ships `false` — confirm the effect with the vendor), and alert on new `.jsp` files under `sample-documents/` plus on `uploadDocument` requests whose `filename` carries a server-executable extension
