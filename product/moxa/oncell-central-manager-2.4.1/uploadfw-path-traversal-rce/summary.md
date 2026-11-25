# Moxa OnCell Central Manager v2.4.1 - uploadFw path traversal writing an archive outside the firmware directory

Advisory: https://0day-rubbish.com/blog/uploadfw-path-traversal-rce

Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Moxa OnCell Central Manager is the central management server for Moxa's OnCell industrial cellular routers and gateways. The v2.4.1 build is a Windows application that installs Apache Tomcat 6.0.39 as a service named `oncell_central_web_server`, running under the `LocalSystem` account. The management application is deployed as `OnCellCentral.war` (package namespace `com.moxa.iw.*`), the browser front end talks to it over BlazeDS `flex-messaging` 4.7.3 AMF3 remoting at `/OnCellCentral/messagebroker/amf`, and the server keeps its state in an embedded Apache Derby 10.10.2.0 database. A Jersey REST interface is also published under `/v1/*` and `/v1/HTTP/*`.

The firmware upload handler in that application, `com.moxa.iw.service.FileUpload.uploadFw(String fileName, String desc, byte[] data)`, builds the destination file path by string concatenation and nothing else:

```java
String absoluteDiskPath = FlexContext.getServletConfig()
        .getServletContext().getRealPath("/fileUploadTmp");   // <webroot>\fileUploadTmp
StringBuffer fileLocation = new StringBuffer();
fileLocation.append(absoluteDiskPath);
fileLocation.append("\\");
String strDate = sdFormat.format(new Date());                 // yyyyMMdd-HHmmss
fileLocation.append(strDate);
fileLocation.append("_");
fileLocation.append(fileName);                                // client-controlled, not validated
FileOutputStream saveFile = new FileOutputStream(fileLocation.toString());
saveFile.write(data);
```

The `fileName` argument is appended verbatim to `<webroot>\fileUploadTmp\<timestamp>_`. There is no `File.getName()`, no `getCanonicalPath()`, no `normalize()`, no `replaceAll()`, no `Pattern` allowlist, and no check that the resolved path stays inside the upload directory. A `fileName` of `..\..\..\shell.jsp` is therefore resolved lexically out of `fileUploadTmp` and lands in the deployed web application root: the timestamp plus underscore prefix produces one literal path component named `<timestamp>_..`, which consumes the first traversal segment, and the remaining two `..` segments walk from `fileUploadTmp` up to `OnCellCentral`. The written bytes are attacker-chosen, the file name extension is attacker-chosen, and the destination is a directory the same Tomcat instance serves and compiles. The upload primitive is consequently a write-anywhere-inside-the-web-application primitive, which the JSP servlet turns into remote code execution on the next request (CWE-22 path traversal chained into CWE-434 unrestricted upload of a dangerous file type).

Reaching the handler requires an AMF session that carries the `flexclient-user` role, which is what the `FileUpload` destination's `<security-constraint ref="trusted-user"/>` demands. The login layer is uneven: the REST handler `AuthorizeLogin.Authorize_via_RESTFUL` contains an explicit branch that refuses the shipped default account with the hardcoded message `Can not use default`, while the BlazeDS path `RdbmsLoginCommand.doAuthentication` routes to `RequestController.DO_LOGIN`, compares the supplied password as an MD5 digest against the Derby `LOGIN_USER` table (`LOGIN_NAME`, `LOGIN_PWD`, `USER_ENABLE`), and grants the role to every successful login without any default-credential check. The shipped `admin` row holds `21232f297a57a5a743894a0e4a801fc3`, the MD5 digest of `admin`, and a research installation was able to authenticate over AMF with `admin` / `admin` while the REST login for the same account was refused. The documented weakness therefore sits on a path that an operator who believes the REST restriction is protective would not expect.

The transport detail that makes the chain work in practice is the BlazeDS `LegacyFilter`. A single `CommandMessage` or `RemotingMessage` sent as a bare AMF body is treated as a legacy message, converted into a `RemotingMessage` with an empty destination, and rejected with error code 10004 (`destination id not registered`). Wrapping the message object in an AMF3 dense array makes `LegacyFilter.isArray()` see the message, sets the legacy flag to false, and the payload passes through `MessageBrokerFilter.getDataAsMessage()` to `MessageBroker.serviceMessage()` unchanged. Both requests in the chain - the login `CommandMessage` with `operation=8` and a base64 `admin:admin` body, and the upload `RemotingMessage` with `destination=FileUpload` and `operation=uploadFw` - are array-wrapped for this reason.

The chain was executed end to end in an authorized laboratory installation over plain HTTP with no man-in-the-middle position: the login returned an `AcknowledgeMessage` carrying `onResult` and `success`, the upload returned an `AcknowledgeMessage` containing a `com.moxa.iw.model.UploadFile` object whose `filename` and `currentPath` fields echoed the traversal payload (`currentPath=/fileUploadTmp/20260819-110001_..\..\..\shell.jsp`) and thereby proved that no sanitization occurred anywhere between the wire and the filesystem, `fileUploadTmp` was empty afterwards, `shell.jsp` (394 bytes) was present in the web application root, and `GET /OnCellCentral/shell.jsp?cmd=whoami` returned `nt authority\system`. A second command wrote a 12-byte marker file into the same directory, confirming independent write capability rather than a single lucky request. The service account is `LocalSystem`, so the command execution is administrative over the host, not over the web application alone.

No published identifier covers this code path. The vendor's advisory history for OnCell Central Manager lists CVE-2017-5641 (BlazeDS AMF3 deserialization, whose `ClassDeserializationValidator` allowlist is present and enforced in this build), CVE-2015-3269 (XML external entity), and CVE-2015-6480 / CVE-2015-6481 (pre-2.2 authentication issues). This finding is a path traversal in Moxa's own application code, with AMF used only as a transport for allowlisted message classes, so none of those records applies.

## CVSS Score

- **Score**: 7.2 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
- **CWE**: CWE-22 (path traversal, primary) chained to CWE-434 (unrestricted upload of a file with a dangerous type); CWE-798 (use of hard-coded credentials) is a contributing condition, not the defect
- **Attack Vector: Network** - the AMF endpoint is reachable over the network; no local access, no user interaction, no man-in-the-middle position is needed
- **Attack Complexity: Low** - a single deterministic request pair; the traversal depth is fixed by the code (the timestamp prefix absorbs one `..`, two more climb out) and needs no guessing, race, or environment-specific precondition
- **Privileges Required: High** - a valid `flexclient-user` session is required; the handler is not reachable before the security constraint on the `FileUpload` destination is satisfied
- **Scope: Unchanged** - the vulnerable component and the impacted component are the same Tomcat service and the same host account
- **Confidentiality / Integrity / Availability: High** - arbitrary JSP execution as `LocalSystem` reads, rewrites and can disrupt everything the management server holds
- **9.8 Critical - deployment-conditional reading**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` applies where the installation still carries the shipped `admin` / `admin` account, because the BlazeDS login path accepts it and the privilege prerequisite then costs an attacker nothing; the technical chain is unchanged in either reading

## Affected Products

- **Vendor**: Moxa
- **Product**: OnCell Central Manager
- **Version verified**: v2.4.1, on a Windows Server installation of the shipped build
- **Vulnerable component**: `com.moxa.iw.service.FileUpload.uploadFw`, the firmware upload handler behind the BlazeDS `FileUpload` destination
- **Transport**: BlazeDS `flex-messaging` 4.7.3 AMF3 remoting, endpoint `/OnCellCentral/messagebroker/amf`, published on the Tomcat HTTP connector (8080 in the verified installation) alongside an AJP connector on 8009; both bound to all interfaces
- **Prerequisite**: an authenticated session holding `flexclient-user`; where the shipped default credential is unchanged, that prerequisite is satisfied with the default account
- **Scope of claim**: only v2.4.1 was executed. Earlier and later builds of OnCell Central Manager were not tested and are not claimed, although the handler's construction - bare string concatenation with no validation helper anywhere in the method - suggests the pattern is not version-specific and deserves its own review

## Impact

- **Remote code execution as `LocalSystem`**: the written JSP is compiled and executed by the same Tomcat service that runs as the Windows system account, so the attacker obtains administrative control of the management server host
- **Control of the managed fleet**: OnCell Central Manager is the enrollment, configuration and firmware-distribution point for OnCell industrial cellular routers and gateways; host compromise means read and rewrite of every managed device profile, credential and firmware image, and push of arbitrary firmware to the devices
- **Persistence**: a JSP under the web application root survives service restarts and, depending on the deployment, reboots; the same primitive can drop additional artefacts anywhere the service account can write
- **Lateral movement**: the server holds credentials and network reachability towards the managed cellular estate, which typically sits on operational technology segments
- **Stealth and detection gap**: the write is a normal AMF request to the documented firmware upload endpoint, and the resulting file is a page inside the application's own root, so log review sees an authenticated upload rather than an exploit
- **Availability**: arbitrary command execution permits service stop, database corruption and deletion of firmware repositories, with direct operational impact on the managed devices

## Mitigation / Fix Recommendations

- Sanitize at the sink: derive the stored name server-side, or at minimum reduce `fileName` to `new File(fileName).getName()`, reject any value containing `/`, `\`, `..` or a NUL byte, and verify after `getCanonicalPath()` that the result is still under the upload directory
- Store firmware uploads outside the deployed web application root, on a path the web server cannot serve and cannot execute
- Disable JSP (and all script) execution for the upload directory, and remove compile-on-demand from directories that receive user content
- Serve uploads with a fixed, non-executable extension chosen by the server, not by the client
- Remove the default-credential asymmetry: apply the same default-account refusal to the BlazeDS login path that the REST path already implements, force a password change on first login, and delete or disable the shipped `admin` row at install time
- Do not run the Tomcat service as `LocalSystem`; use a dedicated low-privilege service account with write access limited to the upload and log directories
- Replace Tomcat 6.0.39, which is end-of-life, and review the AMF attack surface: if the browser front end does not require it, restrict `/OnCellCentral/messagebroker/amf` to trusted management networks
- Restrict the HTTP and AJP connectors to management interfaces instead of all interfaces, and treat 8080 and 8009 as sensitive services
- For operators who cannot patch immediately: block requests whose AMF payload contains traversal sequences targeting `fileUploadTmp`, monitor the web application root for new `.jsp` files, and hunt for files in `fileUploadTmp` whose recorded names contain `..`

## References

- Moxa product security advisories (vendor advisory index, including MPSA-200301 referenced in the research record): https://www.moxa.com/en/support/product-support/security-advisory
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'): https://cwe.mitre.org/data/definitions/22.html
- CWE-434: Unrestricted Upload of File with Dangerous Type: https://cwe.mitre.org/data/definitions/434.html
- CWE-798: Use of Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html
- CVE-2017-5641 (BlazeDS AMF3 deserialization, fixed in this build): https://nvd.nist.gov/vuln/detail/CVE-2017-5641
- CVE-2015-3269 (XML external entity in OnCell Central Manager): https://nvd.nist.gov/vuln/detail/CVE-2015-3269
- CVE-2015-6480 and CVE-2015-6481 (pre-2.2 authentication issues in OnCell Central Manager): https://nvd.nist.gov/vuln/detail/CVE-2015-6480
- Project repository and published research: https://github.com/Exploit-Garbage/0day-Rubbish
