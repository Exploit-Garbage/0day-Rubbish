# GE PulseNET Enterprise ResourceFile Path Traversal Unauthenticated RCE — Full Technical Analysis

## Product Background

- **Vendor**: GE Vernova 🇺🇸 (formerly GE Digital Energy)
- **Product**: PulseNET Enterprise v6.0.3 (build 6975)
- **Category**: CII power-network management (SCADA-adjacent)
- **Stack**: Java / Tomcat 8.5.43 / Vaadin Flow 23.4.1 / Jersey REST / Weld CDI / MongoDB 6.0.6 / ActiveMQ 5.18.4
- **Deployment**: silent install to the PulseNET home, Tomcat runs as **root (uid=0)**, HTTPS `*:8443` (publicly reachable)
- **Namespaces**: `com.e2e.pulsenet` / `com.e2e.stingray` / `com.e2e.provisioner`
- **CVE**: 0-CVE blue ocean (no PulseNET-specific CVEs in NVD)
- **Default credentials**: `admin:admin` (shipped, `pnUsersDefaults.json` seed, `changePassword:false`, no forced change) → CWE-798

## Stage 0 — Prerequisites / Authentication Boundary

The PulseNET Web UI is a Vaadin Flow 23 SPA; all interaction goes through the UIDL RPC protocol (`GET /?v-r=init` returns a csrfToken, `POST /?v-r=uidl&v-uiId=0` sends `{"csrfToken":...,"rpc":[...],"syncId":N,"clientId":N}`; responses strip the `for(;;);[...]` prefix).

Login: `mSync(23,"admin")` + `mSync(22,"admin")` + `click(20)` authenticates (admin:admin is the shipped default, no forced-password-change gate, `changePassword:false`). Under the project convention, shipped default creds without forced change = effectively unauthenticated (Target A, CWE-798).

## Stage 1 — Sink Identification

`ResourceServiceImpl.saveResource()` (`ResourceServiceImpl.java (decompiled):61-77`):

```java
// ResourceServiceImpl.java:61
public void saveResource(Resource resource, InputStream inputStream) {
    String filePath = resource.getFilePath();          // <-- path from getFilePath(), unsanitized path+name
    try {
        Files.createDirectories(Paths.get(filePath).getParent());
        FileOutputStream out = new FileOutputStream(filePath);   // <-- file write sink
        byte[] bytes = new byte[1024];
        int read;
        while ((read = inputStream.read(bytes)) != -1) {
            out.write(bytes, 0, read);                 // <-- writes attacker-controlled JSP content
        }
        out.close();
    } catch (IOException e) {
        throw new RuntimeException("Unable to save resource " + resource.getName() + " : " + e.getMessage(), e);
    }
}
```

`Resource.getFilePath()` (`Resource.java (decompiled):74-77`) — pure string concatenation, no `normalize()` / `getCanonicalPath()` / `..` check:

```java
// Resource.java:74
public String getFilePath() {
    return home + File.separator + "resources" + File.separator + this.resourceType.getFolder()
         + (StringUtils.isNotEmpty(this.path) ? File.separator + this.path : "")
         + File.separator + this.name;          // <-- path + name concatenated raw, no sanitization
}
```

With `home=/opt/pulsenet/GE_MDS/PulseNET` and `resourceType.getFolder()="upgrades"` (SOFTWARE_UPGRADE), setting `path="../../apache-tomcat/webapps/rceXXX"` yields `getFilePath()` = `/opt/pulsenet/GE_MDS/PulseNET/resources/upgrades/../../apache-tomcat/webapps/rceXXX/s.jsp`, which normalizes to `/opt/pulsenet/GE_MDS/PulseNET/apache-tomcat/webapps/rceXXX/s.jsp`.

## Stage 2 — Source Identification

`ResourceFileViewImpl.java` (admin console "Manage Resource Files" add form):
- `path` TextField (`ResourceFileAddPath`) — **free text, no validator bound** (only name/model/vendor/version have validators)
- `upload` (Vaadin Upload, `ResourceFileAddUpload`) — `setAcceptedFileTypes({".zip"})` is a **client-side check**; the server-side `saveResource` has no extension validation
- `name` field is readOnly, set by the Upload `SucceededEvent` (the uploaded filename)

```java
// ResourceFileViewImpl.java:87
upload.setAcceptedFileTypes(new String[]{".zip"});   // client-side only; bypass via direct multipart POST
```

An attacker directly constructs a multipart POST to the upload URI (field name `file`, filename `sXXX.jsp`), bypassing the client-side `.zip` restriction.

## Stage 3 — Data Flow

```
HTTP multipart upload (filename=sXXX.jsp, JSP content)
  -> Vaadin Upload SucceededEvent (ResourceFileViewImpl)
  -> inputStream + name set on binder (UiSoftwareUpgrade bean)
  -> attacker mSync path="../../apache-tomcat/webapps/rceXXX"
  -> click Save (defaultFormSave)
  -> FormDialog.save(): binder.validate() + writeBean() + close() + fireSaveEvent()
  -> fireSaveEvent(): eventBus.fireEvent(new AddResourceFile(...))   [isNew=true]
  -> CDI @Observes AddResourceFile (ResourceFilePresenter.onAddDataFieldEvent)
  -> resourceService.addResource(resource)        // DB insert (stingray.resources)
  -> resourceService.saveResource(resource, inputStream)   // <-- Stage 1 sink
  -> FileOutputStream writes JSP into webapps/rceXXX/sXXX.jsp
```

`ResourceFilePresenter.java`:
```java
// onAddDataFieldEvent(@Observes AddResourceFile event)
try {
    resourceService.addResource(resource);          // DB
    resourceService.saveResource(resource, inputStream);  // file write (sink)
} catch (Exception e) {
    log("Failed to add resource file");
    resourceService.deleteResource(resource);       // cleanup (deleteResource also uses getFilePath; missing traversal path -> NoSuchFileException)
    userActionFailedModal();
}
```

## Stage 4 — Injection / Exploitation Construction

**Key obstacle**: the ROOT webapp's Vaadin servlet mapping `/*` (path prefix) has higher priority than `*.jsp` (extension) per Servlet spec SRV.11.1. Writing a JSP into the ROOT webapp would be intercepted by Vaadin and served as a static resource (source code, `Cache-Control: max-age=3600`, never executed).

**Bypass**: write the JSP into a **new webapp directory** `webapps/rceXXX/`. Tomcat `server.xml:165` `autoDeploy="true"` (default) deploys it as an independent context within ~10-12s (no Vaadin servlet), and the global `conf/web.xml` `*.jsp → JspServlet` compiles and executes it.

**DuplicateStringValidator bypass**: the `name` field validates against existing resource names in the DB; reusing a name makes the binder invalid and disables Save. Each run uses `uuid.uuid4().hex[:6]` to generate a unique JSPNAME.

**Full exploitation chain (3 steps, all unauthenticated via default creds)**:
1. login `admin:admin` (CWE-798)
2. navigate manage-resource-files → Add → upload `sXXX.jsp` (CWE-434, client-side `.zip` only) → mSync `path="../../apache-tomcat/webapps/rceXXX"` (CWE-22) → Save
3. wait ~13s for autoDeploy → `GET /rceXXX/sXXX.jsp?cmd=id` → JspServlet executes (CWE-78) → `uid=0(root)`

## Stage 5 — Dynamic Verification

The exploit script (stdlib-only) connects directly to `https://127.0.0.1:8443` (server.xml binds `*:8443`, production-exposed, real remote reachability, no MITM/local redirection).

Three independent runs (different APPDIR/JSPNAME):
- RUN1: `id` → `uid=0(root) gid=0(root) groups=0(root)`
- RUN2: `whoami; hostname; cat /etc/passwd | head -1` → `root`
- RUN3: marker written (`echo PNROOTRCE_<uniq> > /tmp/PNROOTRCE_<uniq>.txt`) → read back with owner=root, proving uid=0 write

## Stage 6 — Reachability

- **Auth gate**: `admin:admin` shipped default, `pnUsersDefaults.json` seed (`_id:admin`, `changePassword:false`, `system:true`); `PasswordServiceImpl` PBKDF2WithHmacSHA1/1024 recomputes `pbkdf2_hmac('sha1', b'admin', salt, 1024, 20)` and matches the DB `stingray.users` bytes. No forced-change gate = effectively unauthenticated (Target A).
- **Server-side sanitization**: `Resource.getFilePath()` pure concatenation; `saveResource` only `createDirectories`+`FileOutputStream`, no `..` check / normalize / basename. DB rows with `path='../../apache-tomcat/webapps/...'` prove no sanitization.
- **Extension validation**: `setAcceptedFileTypes({".zip"})` client-side only; `saveResource` has zero extension checks.
- **JSP execution**: new webapp dir auto-deployed; `conf/web.xml` `*.jsp → JspServlet`; independently verified `FRESHAPP_EXEC_OK`.
- **Execution identity**: Tomcat JVM uid=0 (installer default, no service-user drop).
- **Remote reachability**: `server.xml:77` binds 8443 on `*` (0.0.0.0), confirmed via `ss -tlnp`. No MITM/Redis/localhost-only dependencies.

## Stage 7 — Defense in Depth / Remediation

1. **Force password change**: remove `changePassword:false` / generate a random admin password at install time
2. **Path sanitization**: `Resource.getFilePath()` should use `Path.normalize()` + reject `..`, or force basename (`Paths.get(name).getFileName()`)
3. **Server-side extension whitelist**: `saveResource` must validate `name` extensions (`.zip` only), not rely on client-side `setAcceptedFileTypes`
4. **Write-directory isolation**: resource files should land under `resources/` outside any webapp-reachable path; add `web.xml` security-constraints blocking static/JSP access to `webapps/<dir>`
5. **autoDeploy=false**: disable automatic deployment in production to prevent new directories from becoming executable contexts
6. **Privilege drop**: run Tomcat as a dedicated non-root service user

## Adversarial Verification

Two independent subagents:
- **Falsification agent** (7 dimensions): VALID NOT-REFUTED, confidence 0.97 — all 7 refutation attempts failed (default creds real / no hidden sanitization / client-side extension check / no MITM / not install-wizard-gated / autoDeploy default / root real)
- **Independent re-analysis agent**: CONFIRMED, confidence 0.97 — rebuilt the data flow from scratch and independently ran the exploit to obtain `uid=0(root)`

## Reproduction

```bash
# 1. run the exploit (stdlib-only Python)
python3 exploit.py 127.0.0.1 8443 "id"
python3 exploit.py 127.0.0.1 8443 "whoami; hostname; cat /etc/passwd | head -1"
```

## CWE / CVSS

- CWE-798 (Use of Hard-coded Credentials) — shipped `admin:admin`
- CWE-22 (Path Traversal) — unsanitized `path`/`name` in `Resource.getFilePath()`
- CWE-434 (Unrestricted Upload of File with Dangerous Type) — client-side `.zip` only
- CWE-78 (OS Command Injection) — JSP `Runtime.exec` via JspServlet
- **CVSS 3.1**: ≈ 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — PR:N because default creds = effectively unauthenticated
