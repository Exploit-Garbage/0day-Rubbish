# FME Flow — Zip-Slip in `StoreManager.extract` → Arbitrary File Write → Code Execution as the Tomcat Service Account

## 1. Overview

FME Flow (formerly FME Server), from Safe Software Inc. (Canada), is a closed-source commercial data-integration platform that ships a Windows installer carrying its own servlet container, database and repository tree. The build examined here is **FME Flow 2026.2, build 26333**, taken from the distributed installer `fme-flow-2026.2-b26333-win-x64.exe` — a 3.7 GB self-extracting archive that unpacks to 61 cabinet files plus `fme-flow.msi`, totalling 46,089 files. Eighteen WAR files make up the web tier; all of them were decompiled with CFR for this analysis.

The finding is a **path-traversal write inside archive extraction** (Zip-Slip, CWE-22) in `COM.safe.web.upload.StoreManager.extract()`, located in the shipped library `clients-webservicesutil-1.0.jar`. When a client uploads an archive to the data-upload servlet with archive extraction enabled, the sink takes each entry name **verbatim** from the archive central directory and builds a destination `File` from it. No `..` sequence is normalised, rejected or resolved before the write. The canonical-containment check that the class does possess, `isPathValid()`, is invoked **only once, from the constructor**, and never from `extract()` or from the `createNew()` / `createFileDesc()` path the extraction takes. An entry name carrying enough `..` segments therefore escapes the upload sandbox and lands wherever the process can write.

On a default single-machine Windows installation the upload sandbox and the servlet container's `appBase` share a common ancestor directory on the same volume, so the escape can be aimed at a deployed web application's document root. Because the container is installed as a Windows service running as `.\LocalSystem`, and because its default JSP servlet compiles and executes any `*.jsp` found in an expanded document root, a single uploaded archive converts into **remote code execution with the privileges of the LocalSystem account**.

This is a **post-authentication** issue. Any authenticated principal that can reach the data-upload servlet — including the low-privilege built-in roles the installer template references — can trigger it; the filter guarding that servlet performs no authorisation or role check on this code path. No authentication bypass was found, and no unauthenticated route to this sink exists on a default installation. CVSS 3.1: **8.8 High**, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`.

## 2. Vulnerability Summary

- **Type**: Zip-Slip — improper limitation of a pathname to a restricted directory, carried inside archive *content* rather than in an HTTP request path (CWE-22), yielding an arbitrary file write (CWE-434 / CWE-73) that is weaponised into code execution.
- **CWE list**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-73 (External Control of File Name or Path), CWE-269 (Improper Privilege Management — the servlet container runs as LocalSystem).
- **CVSS 3.1**: **8.8 High** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (derivation in section 12).
- **Entry point**: `POST /fmedataupload/<repo>/<scope>` — multipart upload of a `.zip` file together with the form parameter `opt_extractarchive=true`.
- **Sink**: `StoreManager.extract(FileDesc, String)` in `clients-webservicesutil-1.0.jar`; the actual write is `java.nio.file.Files.copy(zinp, fTransient.toPath(), ...)`.
- **Precondition**: a valid FME authentication token for any authenticated user, and knowledge (or brute-force) of the directory depth between the upload sandbox and the target document root.
- **Result**: creation of an attacker-named file with attacker-controlled content outside the upload sandbox; demonstrated by dropping a JSP into a deployed web application's document root and requesting it, which executes OS commands as the Tomcat service account — `.\LocalSystem` on a default Windows deployment.
- **Affected**: FME Flow 2026.2 build 26333 was analysed. Other versions sharing the same `StoreManager` extraction path are likely affected; no other build was enumerated as tested in this research.

## 3. Authentication Boundary

The data-upload servlet is fronted by `AuthFilter`. Its `authenticate()` method dispatches on the presence of the `opt_serverapp` / `opt_arapp` parameters. For an ordinary data upload — no application parameter present — the flow is `authenticateUserForDataUpload` → `authenticateUser` → `ss.init(ci, directives)`, with the directive set carrying **only `CLIENT_ID` and `CLIENT_LOCALE`**. The token is validated, so the caller must be an authenticated user, but the path performs **no `isPermitted` call and no role check** against the `fmedataupload` resource. The authorisation helper that does exist, `ensureAppOwnerHasDataUploadPermissions` (which contains an `isPermitted("SERVER_ALL", ...)` test), sits in the **`authenticateApp` branch only** and is never reached by a plain upload.

The practical consequence: the privilege boundary here is "is this a valid authenticated principal", nothing more. Once a token is presented, the low-privilege built-in roles referenced in the product's installer template — **`fmeuser`** and **`fmeguest`**, named in `installer.json.tmpl` — satisfy the check and reach the extraction sink with the same rights as an administrator.

**Are those accounts reachable without prior enrolment?** The research record does not establish that they are. `fmeguest` and `fmeuser` are *roles* provisioned through the installer and the product's user store; obtaining a token in either role requires the account to be created and its credentials issued by the deployment's administrator. A dedicated pass over the unauthenticated attack surface — ten distinct unauthorised-endpoint patterns — came back clean, and a separate line of investigation specifically looking for an authentication bypass found none. **This chain therefore requires a provisioned account.**

A genuinely unauthenticated variant is possible only under a non-shipped configuration: if a server application is published as a public app with `requireAuthentication=false` **and** `allowTemporaryUploads=true`, the same upload path is reachable anonymously. That combination is **not part of the default installation**, so the headline scoring assumes an authenticated caller.

The JSP that is dropped also passes a filter: `FMEServerAuth` is mapped to `*.jsp`. It does not block the attack, because the attacker already holds a valid token from the upload step and presents it on the follow-up request.

## 4. Attack Surface

The product's request path is six layers deep, and nothing in it filters archive content:

| Layer | Components |
|---|---|
| External access | HTTP 80 / 443 / 8080 (Tomcat); REST API under `/fmeapiv4` |
| Edge | Tomcat 10 (Jakarta namespace) + Spring Security 6.5.9; no reverse proxy, no WAF in front |
| Gateways | 18 WARs — `fmeapiv4`, `fmeserver`, `fmedataupload`, `fmedatadownload`, `fmetoken`, `fmesaml`, and others |
| Authentication | default-deny; tokens are stateful database records (CSPRNG UUID, stored SHA-256); SAML via OpenSaml 5; SSO via MSAL4J |
| Business logic | FME Engine (C++, including the `SystemCaller` transformer) plus the Java web tier |
| Storage | bundled PostgreSQL; repository under `<repoRoot>/resources/...`; upload sandbox `UPLOAD_DIR = <repoRoot>/resources/system/temp/upload` |

Two properties of the servlet container's own configuration turn the file write into code execution. The rendered `server.xml` template sets **`unpackWARs="true"`** and **`autoDeploy="true"`** with `appBase` pointing at `WEBAPPSDIR`, so each web application exists on disk as an **expanded, writable directory** that the container monitors. And `fmeserver.war`'s `web.xml` maps its servlets to **specific paths only** — `/fmeauth`, `/REST/token`, `/login`, and similar — with **no `/*` catch-all**. There is therefore nothing to shadow an arbitrary `*.jsp` request: the container's default JSP servlet owns it and compiles it on first request.

The single sanitiser on the upload path is aimed at the wrong artefact. `FileDesc(StoreManager, Part)` runs the submitted multipart **file name** through `Pather.of(item.getSubmittedFileName()).leaf()`, which keeps only the last path segment and so strips traversal from the *upload* name. Zip entry names inside that upload are a completely separate namespace and receive no equivalent treatment.

## 5. Sink Identification

### Sink identification: `StoreManager.extract` takes entry names verbatim

The decompiled class shows a containment check that exists but is out of the extraction path, and an extraction loop that uses the raw entry name directly:

```java
public StoreManager(String sStoreLocation, String sCodePage, String subdirectoryPath) throws IOException {
    this.storage_ = new File(sStoreLocation, subdirectoryPath);
    ...
    if (!this.isPathValid(sStoreLocation, this.storage_.getAbsolutePath())) {
        throw new IOException("Illegal path supplied: " + subdirectoryPath);
    }
}

private boolean isPathValid(String sStoreLocation, String storage) {
    Path normalizedMpDir = Paths.get(sStoreLocation).normalize();
    Path normalizedPath  = Paths.get(storage).normalize();
    return normalizedPath.startsWith(normalizedMpDir);
}

public synchronized List<FileDesc> extract(FileDesc f, String sDir) throws IllegalArgumentException, IOException {
    if (f.getType() != FileEx.FileType.ZipFile) throw new IllegalArgumentException("Not a zip file");
    ...
    try (ZipArchiveInputStream zinp = new ZipArchiveInputStream(new FileInputStream(f), this.codePage_, true);) {
        ZipArchiveEntry zent;
        ...
        this.createDirectory(sDir);
        while (null != (zent = zinp.getNextZipEntry())) {
            if (zent.isDirectory()) continue;
            FileDesc fTransient = this.createNew(sDir + "/" + zent.getName());      // raw entry name
            if (!fTransient.exists()) {
                this.createDirectories(Pather.of(fTransient.getRelativePath()).parent().toRelativeString());
                Files.copy(zinp, fTransient.toPath(), new CopyOption[0]);            // write outside sandbox
            }
            entries.add(fTransient);
        }
    }
}
```

Four facts make this exploitable rather than merely sloppy:

1. **`zent.getName()` is unmodified.** `org.apache.commons.compress.archivers.zip.ZipArchiveEntry.getName()` returns the name exactly as recorded in the archive's central directory. commons-compress **1.26.2** applies no normalisation and no rejection of `..` — that responsibility is explicitly the caller's, which is precisely the Zip-Slip contract. An adversarial review disassembled `ZipArchiveInputStream.getNextZipEntry` and confirmed that the decoded bytes (`zipEncoding.decode(nameBytes)`, bytecode offsets 458–472) are handed to `ZipArchiveEntry.setName(String, byte[])` raw. The class does contain `ArchiveUtils.sanitize`, but it is reachable **only from an `EOFException` error-message path**, where it merely truncates to 255 characters and substitutes control characters; it never strips `..` and is never applied to an entry name.
2. **No Java-level normalisation.** `createNew(sPath)` → `createFileDesc(sName)` → `new FileDesc(this, sName)` → `new FileEx(storage_, sName)` → `new File(parent, sName)`. The `File` constructor is pure string concatenation; it does not resolve `..`. Resolution happens later, in the operating system, at the `Files.copy` syscall — by which point the path already points outside `storage_`.
3. **`isPathValid` is not on this path.** The canonical `startsWith` containment test runs once, in the constructor, against `subdirectoryPath`. Neither `extract()` nor `createNew()` nor `createFileDesc(String)` calls it.
4. **`Pather` does not help.** `Pather`, in `common-util-1.0.jar`, splits on `[/\\]+` and does not normalise `..`. `createDirectories` walks those segments issuing `mkdir`; traversal segments resolve to ancestors that already exist, so the calls succeed and nothing aborts.

**Precision on the write primitive.** The traversal happens through the **zip entry name**, not through the multipart file name (which is sanitised by `Pather...leaf()`). The destination is any path the Tomcat process can write, reached by climbing out of `<repoRoot>/resources/system/temp/upload/<session>/<extractSub>`. The copy is guarded by `if (!fTransient.exists())`, so the primitive is **create-a-new-file**, not truncate-or-overwrite: an existing file at the destination is left untouched and the write is skipped. An attacker must therefore choose a filename that does not already exist — trivially satisfied when dropping a web shell with a fresh name, but it does rule out silently rewriting an existing configuration file through this sink. The written content is the attacker's own bytes, taken from the archive stream.

## 6. Source Identification

### Source identification: what the attacker actually controls

Every input that reaches the sink is attacker-supplied, and no server-side configuration gate stands between them:

- **The archive bytes**, and therefore each entry's central-directory name. Traversal depth and landing directory are entirely the attacker's choice.
- **The `.zip` extension on the uploaded part.** `guessTypeFromName` maps it to `FileEx.FileType.ZipFile`, which is the only precondition the sink's type guard imposes.
- **`opt_extractarchive`.** `VolatileUploadServlet.createRequestInformation` reads the parameter, passes it through `Boolean.parseBoolean`, and exposes it as `RequestInformation.isExtractPaths()`. `UploadSVCImpl.doOperations` then branches directly on that flag into `extractTo` / `extractAll` — no additional server-side switch, no administrator opt-in, no per-application setting.
- **`<repo>`, `<scope>` and the optional namespace**, which appear in the upload path and influence the session directory the extraction is rooted under. This matters for weaponisation: because the attacker controls path segments above the sink's base directory, **the number of `..` segments needed can be computed rather than guessed**, and can be re-derived if a deployment lays its repository out differently.
- `validateNamespace` (`FMEServerUtils.isLegalName`) constrains only the **character set** of `opt_namespace`. It never inspects archive content.

## 7. Data Flow

### Data flow: HTTP request in, filesystem write out, no sanitisation anywhere

```
POST /fmedataupload/<repo>/<scope>
     multipart part "file" = crafted.zip      (entry name = "../"*N + <webapp>/<name>.jsp)
     form field     "opt_extractarchive" = true
     header         Authorization: FMEToken <token of any authenticated user>
  -> AuthFilter.authenticate()
       authenticateUserForDataUpload -> authenticateUser
       directives = { CLIENT_ID, CLIENT_LOCALE }      # token validated, no isPermitted, no role check
  -> VolatileUploadServlet.doPost()
       theman.populate(files)        # multipart FILE NAME sanitised via Pather.of(...).leaf()
       createRequestInformation()    # opt_extractarchive -> Boolean.parseBoolean -> isExtractPaths()
  -> UploadSVCImpl.doOperations()
       if (reqinfo.isExtractPaths()) -> extractTo / extractAll
  -> UploadSVCImpl.extract(theman, f)
  -> StoreManager.extract(f, sExtractionPath)
       zent.getName()  ......................... RAW entry name, "../"*N intact
       createNew(sDir + "/" + zent.getName()) -> new FileEx(storage_, name) -> new File(parent, name)
       createDirectories(...)  -> mkdir over Pather segments, traversal resolves to existing ancestors
       Files.copy(zinp, fTransient.toPath())   -> OS resolves ".." -> write OUTSIDE the upload sandbox
```

The sanitiser on the multipart file name is bypassed not by defeating it but by never meeting it: it protects the outer filename, while the traversal lives one level deeper, inside the archive.

The second leg of the flow is the container's own behaviour rather than product code:

```
wrote: <INSTALLDIR>\WEBAPPSDIR\fmeserver\<fresh-name>.jsp   (Tomcat process = .\LocalSystem, full write access)
  -> unpackWARs=true / autoDeploy=true  => docBase is a live, monitored, writable directory
  -> fmeserver.war web.xml maps servlets to specific paths only, no /*  => default JSP servlet owns *.jsp
  -> FMEServerAuth filter mapped to *.jsp  => passes, attacker presents the same valid token
GET /fmeserver/<fresh-name>.jsp
  -> Jasper compiles and executes the JSP inside the Tomcat JVM
  -> Runtime.getRuntime().exec(...)          => OS command execution as LocalSystem
```

## 8. Exploit Construction

### Exploit construction

Step one is choosing the landing path, which is a directory-layout question answered from the installer rather than from the running product. The MSI `Directory` table and the `SetRepositoryRootDir` custom action give:

```
INSTALLDIR              = C:\Program Files\FMEFlow
REPOSITORYSERVERROOTDIR = [FMEFLOWSHAREDDATA]
FMEFLOWSHAREDDATA       = INSTALLDIR\FMEFLOWSHAREDDATA
WEBAPPSDIR              = INSTALLDIR\WEBAPPSDIR
```

`UPLOAD_DIR` (under the repository root) and `WEBAPPSDIR` therefore share the ancestor `INSTALLDIR` **on the same volume**, which is what makes a relative-path escape possible at all. The research record places the extraction directory roughly eleven levels below `INSTALLDIR` and the target document root two levels below it, so approximately eleven `../` segments followed by `WEBAPPSDIR/fmeserver/<fresh-name>.jsp` resolve to a writable, served location. Because the attacker controls the repository, scope and namespace segments, the exact count is derivable per deployment.

Step two is building the archive. Python's standard-library `zipfile` writes `../` into an entry name without complaint, so no hand-crafted ZIP structures are needed — which is itself a useful proof that no normalisation happens at archive-creation time either.

Step three is delivery and trigger: one `POST` with `opt_extractarchive=true`, then one `GET` for the dropped JSP. The included proof of concept performs both, and verifies the marker string in the response.

```bash
python3 exploit/fme_flow_zipslip_file_write_rce.py \
        --host 127.0.0.1 --port 443 --scheme https \
        --token <any-valid-fme-token> \
        --repo repository --scope fmezipslip \
        --depth 11 --webapp fmeserver --marker fme_zipslip_marker.jsp \
        --mode exploit
```

`--mode zip` stops after building and self-checking the archive, writing it to disk for inspection or for manual upload; `--mode exploit` runs the full HTTP chain. Optional flags let the payload be replaced with any JSP of the operator's choosing, and `--target` accepts a full base URL instead of `--scheme/--host/--port`. TLS verification is disabled by default because appliance installs commonly carry private certificates; no other trust assumption is made.

## 9. Dynamic Verification

### Dynamic verification: the real shipped sink, not a model of it

Verification was performed on a Linux lab host (`<lab-host>`, Java 17.0.19) against a Tomcat 10.1.42 instance bound to `127.0.0.1:8099`. A **complete Windows FME Flow installation was not deployed** — that requires PostgreSQL plus a product licence — so the end-to-end HTTP delivery chain rests on the decompiled source rather than on a live run against the product. What *was* run live is the vulnerable code itself: a harness compiled against the **exact jars that ship with FME Flow 2026.2** and calling the real `StoreManager.extract`.

Classpath used for compilation:

```
clients-webservicesutil-1.0.jar   (StoreManager, FileEx, FileDesc)
commons-compress-1.26.2.jar
common-util-1.0.jar               (Pather)
commons-io-2.16.1.jar
servlet-api.jar                   (from Tomcat 10.1.42)
```

The harness built a zip whose single entry was named `../../../apache-tomcat-10.1.42/webapps/ROOT/fme_zipslip_marker.jsp` — three `../` segments being sufficient to climb out of the `upload/session1/extract1` sandbox used in the harness — then invoked the real constructor and the real sink:

```
new StoreManager(uploadDir, "CP437", "session1")
  -> sm.getFile("crafted.zip")     (FileDesc type == ZipFile)
  -> sm.extract(zipDesc, "extract1")

[*] crafted zip written: <lab-dir>/upload/session1/crafted.zip
[*] traversal entry name: ../../../apache-tomcat-10.1.42/webapps/ROOT/fme_zipslip_marker.jsp
[*] StoreManager storage_ = <lab-dir>/upload/session1
[*] zip FileDesc type = ZipFile (ZipFile expected)
[+] extract() returned without sanitization error
[+] VULN CONFIRMED: JSP written outside sandbox
    -> <lab-dir>/apache-tomcat-10.1.42/webapps/ROOT/fme_zipslip_marker.jsp
[+] size=504 bytes
```

`extract()` returned normally. No exception, no rejection, no logged warning: the containment check that would have caught this simply is not on the code path.

The written JSP was then executed by the real Tomcat:

```
GET http://127.0.0.1:8099/fme_zipslip_marker.jsp
MARKER_WRITTEN

marker file contents:
  uid=0(root) gid=0(root) groups=0(root)
  JSP executed. user.name=root
  Zip-Slip RCE confirmed.
```

The JSP invoked `Runtime.exec("id")` and recorded the result, proving that a file written by the traversal sink is compiled and executed by the container. (The lab process ran as root on Linux, so the `id` label for the group field appeared in the host locale and is rendered here in its English form.) On a real Windows deployment the Tomcat process identity is not root but `.\LocalSystem`, established from two independent product artefacts rather than assumed: `configureTomcat.bat` contains `sc config FMEFlowAppServer obj=".\LocalSystem"`, and the MSI property `FMEFLOWUSER=LocalSystem` says the same. The expected production marker is therefore `whoami = nt authority\system`.

### Adversarial review

An independent review pass attempted to falsify the chain from six angles and did not succeed on any of them:

| Angle | Question | Outcome |
|---|---|---|
| 1 | Does commons-compress 1.26.2 normalise or reject `..` in entry names? | **No.** Bytecode-level inspection of `getNextZipEntry` shows the raw decoded name reaching `setName`; `ArchiveUtils.sanitize` is only on an error-message path and does not strip `..`. Identified as the weakest link — and it holds. |
| 2 | Is `opt_extractarchive=true` sufficient, or is there a server-side gate? | **Sufficient.** `Boolean.parseBoolean` → `isExtractPaths()` → direct branch in `doOperations`. Only requirement is the `.zip` extension. |
| 3 | Can the traversal reach a writable *and served* location? | **Yes** on a default single-machine install: MSI `Directory` + `SetRepositoryRootDir` put the repository root and `WEBAPPSDIR` under a common `INSTALLDIR` on one volume. Second-weakest link; resolved from installer tables. |
| 4 | Will a `.jsp` at that location actually execute? | **Yes.** `unpackWARs`/`autoDeploy` give a writable expanded docBase; `fmeserver.war` has no `/*` mapping to shadow it; the `*.jsp` auth filter passes because the attacker holds a token. |
| 5 | Do `createDirectories` / `Files.copy` succeed on Windows? | **Yes.** `new File(parent, "../..")` produces a path the OS resolves; LocalSystem has full write access to `WEBAPPSDIR`. |
| 6 | Is there an authorisation check the primary analysis missed? | **No.** `isPermitted` lives only in the `authenticateApp` branch; the plain-upload branch validates the token and nothing else. |

## 10. Reachability and Security Impact

### Reachability

| Precondition | Default install? | Evidence |
|---|---|---|
| Data-upload servlet reachable over HTTP | yes | `fmedataupload` WAR, ports 80 / 443 / 8080 |
| Archive extraction enabled by request parameter | yes, attacker-set | `opt_extractarchive=true` → `isExtractPaths()`; no server-side gate |
| Caller holds a valid authentication token | **required** | `AuthFilter.authenticateUserForDataUpload`; no bypass found, unauthenticated surface clean |
| Caller needs elevated role or specific permission | **no** | no `isPermitted` / role check on this branch; low-privilege `fmeuser` / `fmeguest` pass |
| Repository root and `WEBAPPSDIR` on the same volume | yes for single-machine installs | MSI `Directory` table + `SetRepositoryRootDir` custom action |
| Target webapp docBase expanded and writable | yes | `unpackWARs=true`, `autoDeploy=true` |
| `*.jsp` handled by the container's JSP servlet | yes | `fmeserver.war` `web.xml` has no `/*` mapping |
| Unauthenticated variant | **no** | requires public app with `requireAuthentication=false` **and** `allowTemporaryUploads=true`, not shipped |

The residual uncertainty is deployment geometry, not code. A distributed install that places the repository root on a different volume or partition from `WEBAPPSDIR` breaks the relative-path escape to `WEBAPPSDIR` specifically — it does not remove the arbitrary file write, which still reaches any new file the LocalSystem process can create on the volume holding the repository tree. Our research record enumerates no write target other than the web-application document root demonstrated in section 9, so no other target is claimed here. Multi-engine deployments change the depth arithmetic but not the sink.

### Security impact

- **Execution identity**: code runs inside the Tomcat JVM, and the Tomcat service is configured as `.\LocalSystem`. On Windows that is the highest-privileged local account — it installs services, writes to `C:\Windows`, reads the SAM-backed local secret store, and acts as the machine account on the network.
- **Confidentiality: High.** Full read access to the FME repository — stored workspaces, connections, credentials held by the service, and every dataset staged through the platform — plus the whole filesystem from a LocalSystem shell.
- **Integrity: High.** The write primitive itself is generic (create any new file the process can write, with chosen content and chosen name), independently of the JSP route; combined with LocalSystem execution, arbitrary modification of product binaries, configuration and host state follows.
- **Availability: High.** The engine, the bundled database, the servlet container and the host can all be stopped or corrupted. FME Flow is frequently the integration point for scheduled data pipelines, so loss of the host propagates to downstream systems.
- **Privilege escalation**: this is a low-privilege-to-LocalSystem escalation. An account with no administrative rights in FME — for example one issued only to submit workspaces — obtains the service account's authority over the host.
- **Persistence**: the written JSP lands in the expanded, served document root alongside the product's own deployed web applications, and is thereafter requested over the same port as normal traffic — that placement is what section 9 demonstrated. Two further properties are inference rather than findings of this research, and neither was tested: that such a file would survive a service restart, and that its execution would be indistinguishable in the access log from an ordinary authenticated web request because the request carries a valid token.
- **Detection difficulty**: the malicious act is an ordinary, permitted feature — uploading a zip and asking for it to be extracted. The distinguishing artefact is the entry name inside the archive rather than anything carried in the HTTP request. Whether the product's request-level logging records archive entry names was not examined in this research, so no claim is made here about log visibility.

### Independence from previously published FME Flow CVEs

Safe Software has published fixes for traversal-class issues in this product, and this finding is **not** a recurrence of any of them:

| Published CVE | Class | Relationship to this finding |
|---|---|---|
| CVE-2023-35801 | HTTP path traversal (`..` in the URL) | **Different vector.** Collapsed by Tomcat's `CoyoteAdapter.normalize()` before it reaches application code. The traversal here lives in a zip entry name inside the request *body*, which URL normalisation never inspects. |
| CVE-2022-38340 | Path traversal via upload/download | **Different vector.** That issue is in the upload/download path handling; this one is in the extraction path, downstream of the (correctly sanitised) upload filename. |
| CVE-2022-38342 | XXE | Unrelated class. |

The distinction is load-bearing, not cosmetic. Fixes for HTTP-path traversal operate on the request URI and are ineffective against archive-content traversal, because the offending `..` never appears in the URL — it is read from the archive's central directory inside the sink. A deployment fully patched against all three published CVEs remains exposed to the code path documented here. The correct generalisation is that the two namespaces must be validated separately, and that any extractor must confine each entry to the intended base by a canonical-path containment test at write time.

## 11. Fix Recommendations

### Fix recommendations

**Vendor fixes, in priority order.**

1. **Confine every extracted entry with a canonical containment test at write time.** In `StoreManager.extract`, before creating directories or copying, resolve `new File(storage_, sDir + "/" + zent.getName()).getCanonicalPath()` and reject the entry unless it starts with the canonical path of `storage_`. The class already contains the right primitive — `isPathValid()` performs exactly this canonical `startsWith` check — it is simply never called from the extraction path.
2. **Move the check into the shared path factory.** Applying `isPathValid()` uniformly inside `createNew()` and `createFileDesc(String)` protects every caller, not just `extract()`, and prevents the same omission recurring in a future feature.
3. **Reject absolute and rooted entry names outright**, in addition to traversal sequences, and treat symlink/alternate-stream entries in an archive as untrusted.
4. **Strip the traversal instead of only refusing it**, where compatibility demands permissive behaviour: reduce each entry name to its leaf, exactly as the multipart filename already is via `Pather.of(...).leaf()`. The product already trusts this normalisation for the outer name; applying the same rule to inner names is consistent.
5. **Run the servlet container as a least-privilege service account.** Configuring `FMEFlowAppServer` as `.\LocalSystem` converts any file-write or web-tier bug into full host compromise. A dedicated low-privilege account without write access to `WEBAPPSDIR` would have stopped this chain at the JSP-write step even with the sink unpatched.
6. **Add authorisation to the data-upload path.** A resource-level `isPermitted` check on `fmedataupload`, mirroring what `ensureAppOwnerHasDataUploadPermissions` already does for application-scoped uploads, would keep `fmeguest` and other minimal roles away from archive extraction.
7. **Consider disabling JSP compilation in production web applications** that do not need it, or setting the JSP servlet to `development=false` with a read-only docBase, so a written `.jsp` is not automatically executable.

**Operator mitigations available today.**

8. Restrict who holds accounts on the platform; treat every FME user — including holders of `fmeuser` and `fmeguest` roles — as capable of writing files to the application-server host until a fix is deployed.
9. Set filesystem ACLs so the Tomcat service account **cannot write to `WEBAPPSDIR`** (and cannot write outside the repository's upload tree). This is the single highest-value compensating control, because it defeats the documented weaponisation without any code change.
10. Put `WEBAPPSDIR` and the repository's upload directory on **different volumes**, which blocks the relative-path escape to the document root.
11. Place file-integrity monitoring on the expanded web application directories and alert on any new `*.jsp`.
12. Do not expose ports 80 / 443 / 8080 to untrusted networks; terminate them behind a mutually authenticated or VPN-only boundary, and never publish a server application as a public app with `allowTemporaryUploads=true`, which would remove the authentication precondition entirely.

## 12. CWE and CVSS

### CWE classification

**CWE-22 — Improper Limitation of a Pathname to a Restricted Directory.** The primary defect: an entry name from an untrusted archive is used to construct a filesystem path with no confinement to the intended extraction base. The subclass is the well-known Zip-Slip / Tar-Slip family — traversal carried in archive *content* rather than in a request.

**CWE-434 — Unrestricted Upload of File with Dangerous Type.** The upload endpoint accepts an archive and, on request, expands it into the filesystem; the type check verifies only that the file is a zip, and the resulting written artefact is a server-executable JSP.

**CWE-73 — External Control of File Name or Path.** The destination path is composed from attacker-controlled input (entry name plus request path segments) with no server-side constraint on the resulting location.

**CWE-269 — Improper Privilege Management.** The container hosting the writable, served directory runs as `.\LocalSystem`, so the boundary between "web application user" and "host administrator" does not exist. This is a distinct, compounding weakness and the reason the write primitive becomes total host compromise.

### CVSS rationale

**CVSS 3.1 base score 8.8 (High) — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`.**

- **AV:N** — the entire chain is HTTP: one multipart `POST`, one `GET`. No local access or physical proximity is needed.
- **AC:L** — no race condition, no memory-corruption reliability question, no heap grooming, no dependence on a non-default setting. The attacker must supply a correct traversal depth, but that number is derivable from the installer's directory tables and from path segments the attacker controls; the reference implementation exposes it as a flag and the chain completes deterministically.
- **PR:L** — a valid token for *any* authenticated user suffices. No administrative role, no specific permission, and no `isPermitted` check stands in the way, so the lowest shipped privilege level is enough. It is `PR:L` and not `PR:N` because the research found no authentication bypass and no unauthenticated route on a default installation.
- **UI:N** — nothing requires another user's action; the attacker uploads and then requests the dropped file.
- **S:U** — the compromise is executed by, and remains within the authority of, the vulnerable product's own servlet-container process. The escalation from "FME user" to "LocalSystem on the FME host" is a privilege gain inside the same security authority, not a crossing into a different component's scope; the score deliberately does not claim a scope change.
- **C:H / I:H / A:H** — LocalSystem execution yields unrestricted read of the repository, staged datasets and stored credentials; the write primitive plus a LocalSystem shell yields unrestricted modification of product and host state; the engine, bundled database and host can all be stopped or destroyed.

**Alternative reading (public app with anonymous uploads).** Where an administrator has published a server application with `requireAuthentication=false` **and** `allowTemporaryUploads=true`, the same sink is reachable with no credentials at all, `PR` becomes `N`, and the base score rises to **9.8 Critical** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). That configuration is not shipped by default, so 8.8 is published as the headline and 9.8 is recorded here as the conditional upper bound for deployments that have enabled it.

---

*Research by the 0day Rubbish team. Advisory: https://0day-rubbish.com/blog/fme-flow-zipslip-arbitrary-file-write-rce — Repository and full PoC: https://github.com/Exploit-Garbage/0day-Rubbish — Contact: disclosure@0day-rubbish.com*
