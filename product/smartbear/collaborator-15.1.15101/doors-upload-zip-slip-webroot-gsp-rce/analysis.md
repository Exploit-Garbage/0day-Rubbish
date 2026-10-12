# SmartBear Collaborator Server 15.1.15101 - Zip-Slip in the DOORS/Simulink Review-File Upload Writes an Executable Groovy Server Page into the Webroot (Authenticated Non-Administrator to OS Command Execution as uid 1001)

Advisory: https://0day-rubbish.com/blog/smartbear-collaborator-doors-upload-zip-slip-webroot-gsp-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

Author: 0day Rubbish Research Team

## 1. Overview

### Overview of the finding

SmartBear Collaborator Server 15.1.15101 accepts, from any authenticated user, a zip archive attached to a code review through the JSON-API command `ReviewService.addDoorsFiles`. That archive is extracted by first-party code which never canonicalises an entry name against the destination directory. The extractor's only validation of a zip entry is that the entry object is not null; its only keyword filter is the string `__MACOSX`, which exists so that macOS resource-fork metadata is skipped and has nothing to do with path traversal. An entry name of the form `../../../../../webapps/ROOT/name.gsp` therefore escapes the per-review version directory and is written verbatim into the Tomcat webroot.

The webroot is not an inert place to land. The ROOT webapp's `web.xml` maps the URL pattern `*.gsp` to the upstream `groovy.servlet.TemplateServlet` at lines 271-278, and that mapping is reachable anonymously: the global authentication filter's single unconditional 401 branch is `secureContentList.contains(uri) || uri.startsWith("/webserver")`, and a `.gsp` path in the webroot matches neither operand. The written Groovy Server Page is compiled and executed by a plain unauthenticated HTTP GET, and that is what converts a file-write primitive into operating-system command execution inside the product's own JVM.

The two halves were verified separately and then together. End-to-end verification ran four independent times, in three deployment shapes, with a fresh random marker tag and a fresh review identifier on each of the last three runs, and once with a payload that executes a real operating-system command rather than a property read. The observed execution identity was `uid=1001(collab) gid=1001(collab) groups=1001(collab)`. That is not root and not a system account, and nothing in this advisory claims otherwise.

One deployment boundary is load-bearing and is stated here rather than buried later, because it decides whether any given installation is exposed at all. In the pristine official container image the chain is **blocked**: the destination mount point ships as `drwxr-xr-x 2 root root` while the service process runs as uid 1001, so the very first input/output operation in `HtmlBaseFilesUploadService.createUploadContext` - `Files.createDirectories(destVersionDir.toPath())` at line 77 - fails with `EACCES` and not one byte reaches any webroot. The chain succeeds where the upload tree is writable by the service uid, which is the native, non-container install shape and which is the shape produced when that directory is owned by the service account. Section 9 reports all three shapes with their verbatim service-layer responses, and section 10 states the reachability consequence.

### Overview of the product and its runtime stack

Collaborator Server is SmartBear's peer and technical code-review platform, formerly distributed under the name CodeCollaborator. It is a closed-source Java web application. The verified build self-identifies in its own startup log with the verbatim line `Starting Collaborator Enterprise 15.1.15101.220`, and four shipped artifacts carry the matching version suffix `*-15.1.15101.jar`, so the version is read from the product rather than inferred.

The runtime stack observed inside the shipped artifact:

| Layer | Observed value |
|---|---|
| Operating system base | Ubuntu 26.04 LTS |
| JVM | OpenJDK 11.0.31+11, launcher = install4j (`com.exe4j.runtime.LauncherEngine`, `install4j.org.apache.catalina.startup.Bootstrap`) |
| Servlet container | Apache Tomcat, connector `http-nio-8080`; `server.xml:25` sets `appBase="webapps"` and `autoDeploy="false"` |
| Service principal | uid 1001, account name `collab`, gid 1001, single supplementary group, effective capability set empty (`/proc/<pid>/status` field `CapEff: 0000000000000000`) |
| Entrypoint | `/bin/bash /usr/local/ccollab_server/start.sh`, itself running as `collab`, not as root |
| Web applications | `ROOT` (deployed, `smartbear-ccollab-server.war`) and `RtcService` (second war, fails to initialise - see section 4) |
| Webroot | `/usr/local/ccollab_server/tomcat/webapps/ROOT`, unpacked from `ROOT.xml:8 docBase=/usr/local/ccollab_server/wars/smartbear-ccollab-server.war` because `unpackWARs` is unset and therefore defaults to true |
| Template engine | upstream Groovy `groovy.servlet.TemplateServlet` mapped to `*.gsp` by the ROOT webapp's own `web.xml:271-278` |
| Database | HSQLDB in-process via `jdbc:hsqldb:file:`; no listening port; JNDI resource declared in `conf/Catalina/localhost/ROOT.xml` with `username="sa" password=""` at line 33 |
| Review-content volume | `content-webserver` context parameter, default value `collaborator-webserver`, resolved relative to the JVM working directory, measured as `/usr/local/ccollab_server/tomcat` by `readlink /proc/<pid>/cwd` |
| Reverse proxy | none; Tomcat serves HTTP directly, so there is exactly one URL-parsing layer plus the application's own filter |

The decompilation corpus used for source-level claims was 4457 `.java` files reconstructed from the shipped archives (3758 from the main archive set plus 699 from a companion set). Corpus validity was established with non-zero controls before any zero-result claim was accepted from it: `SystemGlobals` = 300 hits (324 in a second pass), `CollabReusable` = 101, `GitHubProcessor` = 3, `class [A-Z]` = 3196, `package com.smartbear` = 4386. Every zero-result statement in this advisory is scoped to that corpus and to the search string actually used.

### Overview of the testbed and of what that implies

Verification ran against the vendor's own published container image, loaded from a 1795588608-byte image archive. Instances were published on loopback addresses only; that binding is a research-side safety decision and not a product property. No instance was ever exposed to a network.

Seven conditions of the testbed were created by the researcher rather than shipped by the vendor, and each of them constrains what may be claimed:

1. **Loopback-only publication.** Every request in this record originated from `127.0.0.1`. A re-test from a non-loopback source address was not performed, so if the product holds any implicit exemption for private or loopback peers, that possibility is not excluded by this work.
2. **The mount-point ownership was pre-set by the researcher.** In the two shapes where the chain succeeds, the webserver directory was owned by uid 1001 because the researcher arranged it - in one case by bind-mounting a host-side directory that was created empty and chowned to `1001:1001`, in the other by an explicit in-container `chown`. The vendor's native install4j installer was never run on a real host. The claim that a native install leaves that directory owned by the service account is therefore a strong structural inference supported by three independent observations, not a measurement. Section 9 lists those observations.
3. **The instances were in a partial-schema state.** Anonymous initialisation creates the schema but a full product initialisation was never invoked, because doing so requires licence activation over the network. Two tables (`REMOTESYSTEM`, `ACTIVITY`) were absent, the product's own periodic services logged `object not found: REMOTESYSTEM`, and yet user creation, review creation and the DOORS upload all succeeded. A comparison against a fully licensed instance was not performed in either direction.
4. **The administrator account was created by the research procedure**, by an anonymous initialisation call that seeds `admin` with password `admin`. This is a bootstrap artefact of the testbed. It is **not** a vendor default credential, and nothing in this advisory treats it as one. Before that call the HSQLDB catalog contains no users at all.
5. **No socket inventory tool was available inside the container** (`ss` and `netstat` are both absent), so the statement that no AJP connector, shutdown port or JMX listener is exposed rests on the image's declared exposed ports and on the absence of the corresponding Tomcat configuration, not on a runtime socket enumeration.
6. **The second web application was never exercised.** `RtcService` fails during servlet initialisation because its bundled Jersey 1.x carries an ASM version that cannot read Java 11 class files (`major=55`); requesting its context path returns HTTP 500 with a 4716-byte body. Its interfaces therefore have zero coverage in this work.
7. **The `.jsp` alternative extension was never tested.** The shipped artifact contains exactly one Groovy template and no attacker-relevant `.jsp` handler mapping was exercised; the extension used throughout is `.gsp`.

### Overview of affected scope

Exactly one root cause is described: unvalidated zip entry names in the shared review-file upload extractor family. That root cause has two code instances, in `com.smartbear.ccollab.doors.DoorsFilesUploadService` at line 78 and in `com.smartbear.ccollab.matlab.SimulinkFilesUploadService` at line 188. Both are reached from the same dispatcher `ReviewServiceImpl.addZipFiles` at lines 969-1001 through the same shared parent-class destination computation, and the mode is chosen by the requester. Only the DOORS instance was exercised end to end. The Simulink instance is reported as sharing the root cause, is not claimed as an independently verified execution path, and carries two extra gates: `isSimulinkEnabled()` at `addZipFiles:975` and a first-entry-must-be-exactly-`webview.html` check in `checkArchive:157-161`. Its real-world exploitability is therefore strictly weaker than the DOORS path's, which is one more reason not to present it as a second finding.

The amplifier is a first-party integration decision and is reported separately from the traversal, because on its own it is not a vulnerability: the vendor maps an upstream template engine to `*.gsp` inside an anonymous-reachable, service-owned webroot, and ships its single template file (`ROOT/jsp/views/json_tester.gsp`, 2321 bytes, owned `collab collab`) in the webroot rather than under `WEB-INF`. Neither half is exploitable alone; the traversal needs somewhere executable to land, and the mapping needs a way to be fed.

### Overview of independence

This sink is not a re-published public issue. The prior-art search was run against the authoritative product axis rather than keyword text, because keyword search on this product name is heavily polluted by unrelated software: searching the vendor name returns ten records, while searching the product's display name returns eleven records of which exactly one belongs to this product, the rest being an intercepting proxy, a source-code host and two other unrelated projects.

| Axis | Query | Records | Verdict |
|---|---|---|---|
| CPE (primary) | `virtualMatchString=cpe:2.3:a:smartbear:collaborator` | 2 | CVE-2020-26118 (Collaborator Server through 13.3.13302, Google Web Toolkit API, authenticated Java deserialization via `UpdateMemento`) and CVE-2021-41657 (CodeCollaborator 6.1.6102, web UI clickjacking). Neither is a path-traversal root cause and neither is on this version line |
| CPE (former product name) | `virtualMatchString=cpe:2.3:a:smartbear:codecollaborator` | 0 | nothing additional |
| CPE (variant) | `virtualMatchString=cpe:2.3:a:smartbear:collaborator_server` | 0 | nothing additional |
| Channel control | `keywordSearch=SmartBear` | 10 | non-zero, so the query channel demonstrably works; ten records across several unrelated vendor products |
| Term control | `keywordSearch=ccollab` | 0 | no hits |
| Root-cause controls | zip slip / path traversal / Simulink / product-name-plus-major-version | 0 each | no hits on any of the four |
| Advisory database | GitHub Security Advisory API | 0 | no hits |

The nearest public precedent is CVE-2024-7565, a directory traversal in the `unpackageAll` routine of a different product from the same vendor. It is the same weakness class and the same vendor, and it is a different product line. Shared code was excluded positively rather than assumed away: the string `unpackageAll` returns zero hits across the 4457-file corpus, as does `soapui|readyapi`, while the same searches over `ZipProcessor|unzip|copyFilesFromZip` return four hits and over `smartbear` return 4386, so the corpus and the search channel were both demonstrably live when those zeros were recorded.

Two limits on the independence claim are stated rather than papered over. First, the search establishes absence of evidence within public indexes; it is not proof that no non-indexed report exists. Second, this work exercised exactly one build. No cross-version claim is made: it is not asserted that the defect exists or does not exist in builds before or after 15.1.15101, and the vendor release notes for this build were reviewed with no relevant fix found and no later build of this line located at the time.

### Overview of the two necessary halves

It is worth stating plainly what kind of defect this is, because it determines both the fix and the score. Neither half of the chain is, on its own, an exploitable condition:

| Half | What it is | Alone |
|---|---|---|
| Write primitive | `DoorsFilesUploadService:78` builds `new File(destVersionDir, fileName)` from an unsanitised entry name and opens a `FileOutputStream` on it at line 84 | Writes only inside a service-owned content tree that is served behind authentication at `/webserver/*` and is therefore not executed |
| Execution mapping | ROOT webapp `web.xml:271-278` maps `*.gsp` to upstream `groovy.servlet.TemplateServlet`, anonymously reachable | Needs a template file to exist in the webroot; the shipped image holds exactly one, at a fixed path, whose text is a constant and whose user data is bound as a value, not as template source |

The combination is the vulnerability: the traversal is aimed at a sibling of the content tree that happens to be the anonymous, template-executing webroot. That is a first-party integration and layout decision, and attribution belongs to the first party even though the class that evaluates the template comes from upstream Groovy. Tomcat does not map `*.gsp` by default, and Groovy ships no such mapping; the vendor placed it there.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Field | Value |
|---|---|
| Product | SmartBear Collaborator Server (peer / technical code-review platform, formerly CodeCollaborator) |
| Version verified | 15.1.15101, self-reported as `Collaborator Enterprise 15.1.15101.220` |
| Vulnerable component | `com.smartbear.ccollab.doors.DoorsFilesUploadService.upload(int, Version, byte[])`, reached from the JSON-API command `ReviewService.addDoorsFiles` |
| Sibling instance of the same root cause | `com.smartbear.ccollab.matlab.SimulinkFilesUploadService.copyFilesFromZip`, reached from `ReviewService.addSimulinkFiles` (not exercised end to end) |
| Weakness | CWE-22, path traversal via archive entry names (zip-slip) |
| Consequence | CWE-94, server-side code execution: the escaped file lands in the Tomcat webroot with a `.gsp` extension and is compiled by the mapped Groovy template servlet on an anonymous GET |
| Entry point | `POST /services/json/v1`, multipart, command array with `SessionService.authenticate` first and `ReviewService.addDoorsFiles` second |
| Authentication required | Yes. Any authenticated principal. A non-administrator account (`admin:false`) completed the whole chain |
| Authorisation required | None beyond being logged in. No role, group, review-ownership or per-object check is applied on this path |
| Execution identity | `uid=1001(collab) gid=1001(collab) groups=1001(collab)` - the product's own service account, not root |
| Privilege ceiling | uid 1001 with full read/write over `/usr/local/ccollab_server/**`; no privilege escalation to root was attempted, and the image supplies no path to it (no `sudo` binary, neither `/etc/sudoers` nor `/etc/sudoers.d` present, no first-party setuid binary, empty effective capability set) |
| Deployment precondition | `SystemGlobals.getWebserver()` (default `collaborator-webserver`, from the `content-webserver` context parameter at `ROOT.xml:92`) must be writable by the service uid. Blocked on the pristine official container image, which is the only shipped artifact that was exercised; argued from the shipped archive rather than observed in the native install shape, whose installer was never run on a real host |
| Edition precondition | `isDoorsEnabled()`, which resolves to `Product.getFeatures().supportsDoors()`. Open in the default Enterprise feature set; statically closed in Free and Professional (Reviewer) |
| Vector recorded during analysis | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, whose own arithmetic gives 8.8; published here as the labelled conditional reading |
| Score published here | 7.5 High on `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`, recomputed with the CVSS 3.1 round-up rule; the derivation, and the evidential reason Attack Complexity is High on the headline, are in section 12 |

### Vulnerability Summary mechanics

The mechanical sequence is five product behaviours chained together, each one of them individually ordinary:

1. `ReviewServiceImpl.addZipFiles` at lines 969-1001 requires only that a user be present (`requireUser()` at line 973), checks the edition gate at line 977, requires a non-empty `zipName` at line 980, and at line 982 creates a review on the requester's behalf when the caller omits `reviewId`. It then dispatches at line 989 to `HtmlBaseFilesUploadService.getService(uploadMode).upload(reviewId, version, is)`.
2. `HtmlBaseFilesUploadService.createUploadContext` computes the destination as `new File(SystemGlobals.getWebserver(), webServerFolder)` and appends a generated version directory, then calls `Files.createDirectories(destVersionDir.toPath())` at line 77. This is the first input/output operation of the whole feature, and it is why the destination tree exists whenever the feature is usable at all - the product creates `<webserver>/<mode>/<reviewId>/<zipName>/ver<N>` itself.
3. `DoorsFilesUploadService.upload` loops over `zis.getNextEntry()` (line 72), throws `IOException("File doesn't look like archive.")` if the first entry is missing (lines 73-75), rewrites square brackets to parentheses in the entry name (line 77), builds `new File(uploadContext.getDestVersionDir(), fileName)` (line 78), skips the entry only if it contains `__MACOSX` (line 79), creates parent directories (lines 81 and 83) and writes the bytes through `new FileOutputStream(entryDestination)` (line 84).
4. The escaped path resolves under the JVM working directory `/usr/local/ccollab_server/tomcat`, so five parent-directory segments from `ver<N>` reach that directory and the suffix `webapps/ROOT/name.gsp` lands in the webroot.
5. The ROOT webapp's `web.xml:271-278` maps `*.gsp` to `groovy.servlet.TemplateServlet`, and the global `AuthTicketFilter` does not protect it, so an anonymous GET compiles and runs the file in the service account's context.

### Vulnerability Summary preconditions

The chain needs three things to be true, and the honest statement of each is different in kind:

- **Authenticated session.** Proven. Anonymous invocation returns HTTP 200 with `AuthenticationError`; a non-administrator account completed the chain. See section 3.
- **Edition gate open.** Proven on the artifact under test, where the default edition resolves to `FeatureSetEnterprise` (`Product.java:62` and `:70`, `LicenseCode.java:96`) and `isDoorsEnabled()` returned true on two separate instances. Statically derived but not exercised for the Free and Professional (Reviewer) editions, which inherit `supportsDoors() = false` and would answer `RequestError` "Can't upload Doors archive as feature is not enabled."
- **Destination writable by the service uid.** This is the one to be careful about. It is *not* a product defence and it is *not* an unpredictable environmental accident either: the product itself creates the destination tree at `HtmlBaseFilesUploadService:77`. It failed on exactly one shipped shape, the pristine official container image, where a `VOLUME` declaration causes the runtime to create the mount point as root before the service account can use it. Section 9.2 tabulates all three shapes; sections 10 and 12 carry the reachability and scoring consequence.

### Vulnerability Summary - evidence status of every load-bearing claim

| Claim | Status | Basis |
|---|---|---|
| Entry names are not canonicalised | Proven from source | `DoorsFilesUploadService.java:77-84`; no `normalize()`, no `startsWith()`, no `..` rejection anywhere in the loop |
| The sink is reachable over HTTP by a non-administrator | Proven dynamically | four end-to-end runs with `admin:false` accounts; `UserService.findUserByLogin` returned `"admin":false` in a 268-byte response |
| Anonymous callers are refused | Proven dynamically | HTTP 200, 127 bytes, `AuthenticationError`, "You must be authenticated to call ReviewService.addDoorsFiles method." |
| The written `.gsp` executes anonymously | Proven dynamically | HTTP 200 with `X-Smart-Bear-Not-Logged-In: true`, a server-issued `JSESSIONID_COLLAB`, marker body and the `Generated by Groovy TemplateServlet` timing comment |
| Real operating-system command execution was reached | Proven dynamically | marker body contained the output `uid=1001(collab) gid=1001(collab) groups=1001(collab)` from `["id"].execute()` |
| The product creates the destination tree itself | Proven dynamically | a bind-mounted host directory that held zero entries before the run ended with four nested directories and one file, all owned by uid 1001 |
| The pristine image blocks the chain | Proven dynamically | `InternalError` carrying only the destination path, marker 404/653, filesystem-wide marker search returned zero hits |
| A native install leaves the directory owned by the service account | **Argued, not measured** | the vendor's native installer was never run on a real host; three structural observations support it (section 9.5) |
| The traversal depth is attacker-controllable | Proven dynamically | five segments with a flat zip name, six segments with a one-segment-deeper zip name; both markers executed |
| Persistence across restarts | **Not established** | the re-unpacking behaviour of `unpackWARs` was never tested; no restart was performed |
| Free / Professional editions are blocked | **Argued, not measured** | static reading of the feature-set inheritance only |
| No non-loopback exemption exists | **Not established** | no request was ever sent from a non-loopback source address |

## 3. Authentication Boundary

### Authentication Boundary - how sessions are issued

Authentication against the JSON-API is ticket-based and takes two calls, which is a direct consequence of how the product builds its command context. `CommandContext` is constructed per request (`JsonService.java:136`, `CommandContext.java:19` and `:44`, `SessionServiceImpl.java:149`), so a ticket obtained in one request does not survive into the next on its own. The working pattern is therefore a batch: the top-level array carries `SessionService.authenticate` as its **first** element and the privileged command as a later element, in a single POST.

```
POST /services/json/v1
Content-Type: application/json;charset=UTF-8

[{"command":"SessionService.getLoginTicket","args":{"login":"<user>","password":"<password>"}}]
```

The response is 63 bytes: `[{"result":{"loginTicket":"<32-hex-ticket>"}}]`. Both `SessionService.getLoginTicket` and `SessionService.authenticate` carry `@NoAuthRequired`, so the ticket request itself needs no prior session. `SessionService.login` is protected and is not the entry point. A wrong password is reported as `AuthenticationFailed` in a 119-byte response; eleven candidate passwords including the empty string were tried against an uninitialised database and all returned that same code, so the product does not fail open on credential checking.

Ticket values are withheld from this advisory. They are session credentials with a 30-day lifetime and were logged out at teardown.

### Authentication Boundary - what the gate actually checks

There are three layers of authorisation in this product, and only the innermost one matters for this finding.

**Layer one, the global filter.** `AuthTicketFilter` is bound to `/*` and is structurally fail-open. Inside `doFilter` at lines 108-129, line 118 performs opportunistic authentication only, line 122 is the single branch that can force a 401, and line 128 otherwise lets the request through. The 401 branch reads verbatim:

```java
secureContentList.contains(uri) || uri.startsWith("/webserver")
```

The list is `{/script/all-min.js, /script/all.js}` and is parsed at line 151. The exclusion pattern at line 105 is `Pattern.compile("\\/jsp\\/errors[\\w\\W]")` and is applied with an unanchored `find()` at lines 131-139 against the raw URI, so any URI containing `/jsp/errors` plus one further character skips the whole filter body. The filter also mixes two different URL views inside one class: line 145 (`isWebhookRequest`) uses `getServletPath()` while line 122 uses `getRequestURI()`, and line 474 exempts `/services/json/v1` for the single-sign-on forward. None of these is needed for this chain, but they explain why the filter cannot be trusted as the boundary for anything and why the per-command annotations exist.

One corpus-versus-runtime divergence is recorded for honesty: `AuthTicketFilter.java:126` sets the framing header to `SAMEORIGIN` in the decompiled source, while four separate observations of live responses returned `DENY`. Where this advisory cites a constant that describes runtime behaviour, it is paired with a dynamic observation, and where it is not, it is labelled as a source reading.

**Layer two, per-command annotations.** `CommandHandler.java:57-61` is the only enforcement point on the JSON-API: a command runs unauthenticated exactly when its handler method carries `@NoAuthRequired`. An exhaustive pass over `collaborator-json-api-15.1.15101.jar` found 17 such annotations - five on the `Examples` service (`checkLoggedIn`, `echo`, `dateEcho`, `doNothing`, `simulateError`), six on `ServerInfoService` (`getEdition`, `getVersion`, `getServerBuild`, `getMinimumJavaClientBuild`, `getSystemGlobalValues`, `getRemoteSystemIntegrations`), three on `SessionService` (`getLoginTicket`, `authenticate`, `setMetadata`), and one each on `UserService.findUserByLogin`, `AdminSsoService.isSSOEnabled` and `InitializationService.initDatabase`. Twelve of the seventeen were executed anonymously as a confirmation. The annotation is not a reliable indicator of true openness in the other direction: `getRemoteSystemIntegrations` carries it and then applies a second check inside its implementation. Critically, `ReviewService.addDoorsFiles` does **not** carry it, which is where the authentication requirement in this finding comes from.

**Layer three, programmatic checks inside the handler.** For the sibling upload servlet the check is verbatim at `VersionContentUploadServlet.doPost:66-70`:

```java
User currentUser = CollabReusable.getCurrentUser();
if (currentUser == null) { resp.setStatus(403); return; }
```

For the JSON-API path used here the equivalent is `ReviewServiceImpl.addZipFiles:973`, `User user = this.requireUser();`. Both ask only that a user exist. Neither asks what the user may do.

### Authentication Boundary - the principal required by the sink

The least privileged principal that demonstrably reaches the sink is **any authenticated user**, and the privilege requirement is `PR:L`, not `PR:H`. Three separate lines of evidence converge, and they are independent of one another:

1. **A non-administrator completed the entire chain, twice.** The account used in the primary verification was created by an administrator through `UserService.create`, and a subsequent `UserService.findUserByLogin` on that account returned a 268-byte body containing `"admin":false,"remoteSystemAdmin":false,"enabled":true`. A second, separately rebuilt instance repeated the whole run with a different non-administrator account, a different random marker tag and a freshly created review.
2. **The role gate is demonstrably present and demonstrably not on this path.** A low-privilege ticket calling an administrator-only method returns HTTP 200 with a 114-byte `AuthorizationError`, "You are not authorized to call this method."; the identical call with an administrator ticket returns HTTP 200 with a 29-byte success body. So the product can and does distinguish roles - it simply does not do so for `addDoorsFiles`.
3. **Administrator status is not a shortcut to this chain, and can be an obstacle.** An administrator calling `addDoorsFiles` with `reviewId` omitted falls into the auto-creation branch at `ReviewServiceImpl:982` and is refused with a 179-byte `ServiceException`, "User 'Administrator' not allowed to create Reviews: The system administrator is not allowed to perform Reviews". The gate itself is `datamodel/User.java:526-533`, whose line 532 reads verbatim `return "The system administrator is not allowed to perform Reviews";`, while the literal message string is assembled in `Collab7001.java:175-176`. This restriction is conditional: it is guarded by `!getAllowSysadminReviews()`, so an administrator *can* create reviews when `allow-sysadmin-reviews` is true, and it must not be described as an unconditional ban. It is also not what the low-privilege conclusion rests on - that conclusion rests on the dynamic evidence in items 1 and 2.

A citation hazard worth passing to the vendor's engineers: the corpus holds two distinct files named `User.java` - `service/api/v7001/data/User.java`, a 74-line API stub, and `datamodel/User.java`, 1604 lines. A bare `User.java:532` is ambiguous and was corrected during this work. All citations in this advisory are package-qualified where a duplicate name exists.

### Authentication Boundary - the second, route-specific session-key gate

There is an additional gate on the *sibling* HTTP upload route that does not apply to the route used here, and it is described in full because it is the kind of detail that could otherwise be mistaken for a higher privilege requirement.

`VersionContentUploadServlet`, mapped to `/versionupload`, requires at lines 75-79 that the HTTP session already hold a key of the form `save-request-<changelistId>`. That key is written by `RpcGwtServlet.createSaveChangelistRequest` at line 947 (the surrounding method begins around line 945), and it is also produced by three call sites in `UnversionedClientApiImpl` at lines 1109, 1160 and 1212. In other words the key is a by-product of the product's ordinary change-list save workflow, which any authenticated user performing a normal check-in triggers.

Two consequences follow, and both push the privilege requirement *down*, not up:

- The demonstrated entry point, `ReviewService.addDoorsFiles` over `POST /services/json/v1`, does not consult that session key at all. `addZipFiles` at lines 969-1001 contains no `save-request` lookup; the check exists only inside the servlet route.
- Even on the servlet route the key does not encode a role. It records that a change-list save was requested, which is an action any authenticated user performs in the normal course of using the product. Requiring it would not move this finding from `PR:L` to `PR:H`; it would add a workflow step.

The same asymmetry applies to the restricted-file-pattern check: `VersionContentUploadServlet:90-93` calls `getRestrictedFilePatterns()` and validates only the version's already-existing paths, not zip entry names; and the JSON-API dispatcher performs no extension validation anywhere in lines 969-1000. A restricted-pattern check that does exist elsewhere in the file (`ReviewServiceImpl:865`) sits inside a source-control change-list loop and is not on this path. That was a live hypothesis during this work and was refuted by reading the enclosing loop.

### Authentication Boundary - the edition feature gate

`ReviewServiceImpl.addZipFiles:977` evaluates `isDoorsEnabled()` before touching the archive. That resolves through `SystemGlobals:1251-1256` to `Product.getFeatures().supportsDoors()`, so the gate is derived from the licence edition and is not a configurable switch: no globals key, no setter, and no `doors-enabled` or `simulink-enabled` key exists anywhere in the product. The five `@NoAuthRequired` methods on `ServerInfoService` (`:17-18`, `:20-21`, `:23-24`, `:26-27`, `:29-30`) are all getters with no setter counterpart, so the gate cannot be flipped from the management surface either - anonymous or authenticated. Default resolution is `Product.DEFAULT_EDITION = FeatureSetEnterprise` (`Product.java:62`, `Product.java:70`, `LicenseCode.java:96`), where the gate is open; it was observed open on two separate instances. Enterprise, HostedServer and DemoServer also enable it. Free and Professional (Reviewer) inherit `FeatureSetEverything.supportsDoors() = false` and would be refused with `RequestError` "Can't upload Doors archive as feature is not enabled." - a static derivation that was never exercised against a licensed instance of those editions.

An operator consequence is worth naming: because there is no configuration key, an operator who wants to close this gate without a vendor patch has no supported way to do it.

### Authentication Boundary - the three-state discriminator

The gate structure was confirmed with a three-way discriminator rather than a single positive test, because a single "it worked" result cannot distinguish a role gate from a global outage:

| Caller | Call | HTTP | Bytes | JSON `code` | Meaning |
|---|---|---|---|---|---|
| Anonymous | `ReviewService.addDoorsFiles` | 200 | 127 | `AuthenticationError` | no session at all |
| Anonymous | `UserService.create` | 200 | 118 | `AuthenticationError` | no session at all |
| Non-administrator | `UserService.create` | 200 | 114 | `AuthorizationError` | session present, role insufficient |
| Non-administrator | `GroupService.create` | 200 | 114 | `AuthorizationError` | session present, role insufficient |
| Administrator | `UserService.create` | 200 | 29 | none, `[{"result":{}},{"result":{}}]` | permitted |
| Non-administrator | `ReviewService.addDoorsFiles` | 200 | 41 | none, `[{"result":{}},{"result":{"reviewId":1}}]` | **permitted - this is the sink** |

The discriminator is the `code` field. Response byte lengths are listed here only as auxiliary fingerprints: the product embeds the command name inside the error message text, so the same `AuthenticationError` is 118, 122, 123 or 127 bytes depending on which method was refused. Three distinct states are separable, which rules out both "everything is refused" and "everything is permitted".

### Authentication Boundary - what is deliberately not claimed

- No unauthenticated write is claimed. Section 10.3 explains in full why an available anonymous variant does not convert this finding into an unauthenticated one.
- No administrator-to-root escalation is claimed, attempted or implied.
- No default vendor credential is claimed. The `admin`/`admin` pair in this testbed was seeded by an anonymous initialisation call on an uninitialised instance and is an artefact of the research procedure.
- No cross-account or cross-tenant impact is claimed as part of this vector. All three impact metrics are justified by what the service account can already read and write on the same host and in the same JVM, which is why Scope is Unchanged.
- No claim is made that an account minted through a separate authorisation defect elsewhere in the product can reach this sink. That was considered, it is a plausible route, and it was not tested; the finding does not depend on it, and anonymous invocation of that separate defect returns `AuthenticationError` in any case.

## 4. Attack Surface

### Attack Surface - listeners, routes and their protection

The product exposes exactly one inbound listener. The image declares one exposed port, `8080/tcp`, served by the Tomcat `http-nio-8080` connector as uid 1001 with an empty effective capability set, and the container entrypoint script is itself run by the same unprivileged account. The database is an in-process HSQLDB file store reached over `jdbc:hsqldb:file:` with no port of its own, so nothing network-facing terminates there.

Parsing the shipped `ROOT/WEB-INF/web.xml` (27937 bytes) yields 43 `servlet-mapping` entries and 9 filters; all 43 servlet classes are first-party (`com.smartbear.ccollab.*`). A container-level `security-constraint` restricts only the methods `TRACE`, `HEAD`, `DELETE`, `OPTIONS` and `PUT`; the startup log states this explicitly, and a `security-constraint` that names only methods performs no authentication, so no authorisation decision anywhere in this product can be inferred from it. For the same reason an `OPTIONS` probe result was never treated as evidence of an authentication state.

Grouped by function, the mapped surface is:

| Group | Routes | Protection observed or read |
|---|---|---|
| JSON-API | `POST /services/json/v1` | single entry point; per-command `@NoAuthRequired` enforced at `CommandHandler.java:57-61`; 17 annotated commands, 12 executed anonymously during the survey |
| GWT RPC | `RpcGwtServlet` path | per-request deserialisation policy held by the servlet itself, which acts as its own `SerializationPolicyProvider` |
| Legacy XML-RPC | `/xmlrpc/server` | guarded by `SingleServerCheckFilter`; only two semantics are reachable anonymously, `*.getServerVersion` returning `15101` and `*.getMinimumJavaClientBuild` returning `15000`; every other method name falls into a first-party version gate that answers "Clients 4.0 and older are no longer supported." |
| Uploads | `/contentupload`, `/versionupload` | both refuse anonymous callers with HTTP 403 and a zero-length body |
| Review content | `/webserver/*` | the `startsWith("/webserver")` operand of the filter's 401 branch; anonymous retrieval returns 401 with a 657-byte body |
| Static and document surfaces | `/document`, `/data/server`, `/secure/data/server`, `/rss`, `/manual`, `/diagnostics`, `/externaldiff`, `/diff`, `/attachment`, `/report` | `/data/server` and `/secure/data/server` are indistinguishable - both return 403 with a 37-byte `text/plain` body reading "Access to this content is restricted.", the real gate being `RpcDataServlet.java:146` calling `CollabReusable.getCurrentUser()`, and the `secure` prefix is decorative |
| Integration callbacks | `/services/webhooks/*` for four source-control hosts, `/services/saml/*`, OAuth and directory-service callbacks | webhook signature validation is fail-open in at least one processor when the signature header is absent |
| UI and redirects | `/ui`, `/go`, `/public/go` | login page and controller dispatch |
| **Webroot resources** | **anything physically inside `webapps/ROOT`, including `*.gsp`** | **not covered by any unconditional 401 branch - this is the execution half of the chain** |

The last row is the one that matters. There is no route in the product that serves `webapps/ROOT/name.gsp`; Tomcat maps it by extension to the template servlet declared in the webapp's own `web.xml`, and the global filter's only 401 operand list is `{/script/all-min.js, /script/all.js}` plus the `/webserver` prefix. A `.gsp` request matches neither.

### Attack Surface - how the surface was mapped

Mapping proceeded from configuration outward, in three passes whose results were cross-checked against each other rather than trusted individually.

The first pass parsed the shipped deployment descriptor verbatim to enumerate all 43 mappings with their servlet classes and all 9 filters with their patterns, plus the container's own `server.xml` and the context descriptor `conf/Catalina/localhost/ROOT.xml` (4949 bytes), which supplies the JNDI datasource, the `content-cache` and `content-webserver` parameters and the `docBase`. The second pass exercised each route over HTTP with and without a session credential, recording status, length and - where JSON - the error `code`, on instances in different initialisation states, since the same route can behave differently on an uninitialised instance than on one with a schema. The third pass read the decompiled first-party corpus for authorisation primitives, so that a route observed to answer could be attributed to the check that actually permitted it.

Two methodological points from that exercise carry beyond this product. First, a zero result obtained from a corpus is only meaningful if a control search over the same corpus returns non-zero, and the control has to be run in the same session; several early "nothing in the whole repository" conclusions here were produced against the wrong subset and were later overturned. Second, "this sink is unreachable" cannot be established by searching for the sink class's own name: `SimulinkFilesUploadService` is reachable over HTTP even though no JSON-API service class in the 29-class API package is named after it, because it is reached through `ReviewService.addSimulinkFiles` and the shared dispatcher. Reachability claims in this advisory were made from the call graph, not from name searches.

### Attack Surface - components that narrow the surface

Several things that look like surface are not, and narrowing them is what made the write-primitive path the productive one.

Command-execution sinks in first-party code are absent in any HTTP-reachable, attacker-controllable form. Two `ProcessBuilder` uses exist (`CommandLine.java:121`, `CommandRunner.java:154`) and both take argument-vector lists with no shell, so shell metacharacters cannot be injected. A `/bin/sh -c` primitive exists at `CommandLine.java:307-334` and sanitises only carriage return and line feed, but it has zero callers: its sole invoker, `GuiLauncher.java:34`, uses an argument-vector overload. Search strings `ScriptEngine`, `javax.script`, `MVEL|JexlEngine|Ognl|SpelExpression|ExpressionParser|BeanShell`, `XMLDecoder|XStream`, `URLClassLoader` and `readUnshared|resolveClass|ObjectInputFilter` each returned zero hits across the 4457 files after the corpus was corrected. A `GroovyShell.evaluate(File)` call exists at `PluginConverterFactoryLoader.java:33-38` but its `pluginsRoot` has no reachable source: zero references in the extracted corpus, zero in the raw class bytes, zero across all 13 archived `META-INF/services` table-of-contents listings, and none of the 14 `Class.forName` / `newInstance` sites can be fed an externally composed class name.

Template injection is not in play either. The single shipped template's text is a fixed on-disk file referenced by a hardcoded constant at `BaseJsonServlet.java:146`; user data reaches it only as a bound attribute value, escaped for angle brackets, and a `${7*7}` probe was echoed literally with `<` escaped, never once producing `49`. That is a different defect class from this one and it is absent.

The other upload path is genuinely hardened and was refuted as a candidate. `/contentupload` writes through `ZipProcessor.process` into a content-addressed large-object store, not the webroot: entry names must be valid MD5 digests (`ZipProcessor.java:54`) and must equal the digest of their own content (`:43-47`), so arbitrary names are structurally impossible, and an extension blocklist exists at `:85-86`. That route's zip-slip is therefore not present. It does parse multipart bodies before checking the caller (`StreamingContentUploadServlet.java:47` before `:49`), which gives an unauthenticated temporary-file write of unknown exploitability; it is not part of this finding.

### Attack Surface - the sibling upload servlet and why it is not the entry point

`/versionupload` reaches the same extractor family and is more heavily gated, which is precisely why the JSON-API route was used. `VersionContentUploadServlet.doPost` imposes, in order: an authenticated user at lines 66-70; the `save-request-<changelistId>` session key at lines 75-79; an attacker-selectable `mode` parameter at line 82 choosing between `DOORS` and `SIMULINK`; a restricted-file-pattern check at lines 90-93 that validates the version's existing paths and not zip entry names; a required `Content-Type: application/octet-stream` at line 96; `isSimulinkEnabled()` at lines 118-123; and `isDoorsEnabled()` at lines 124-127. The JSON-API route shares the feature gate and the extractor and skips the session-key gate and the restricted-pattern gate, because both of those live in the servlet class only.

A route that imposes strictly more gates while reaching the same unsanitised sink is the clearest possible demonstration that the gates were written for a different threat than entry-name traversal.

### Attack Surface - coverage gaps in the mapping

Three gaps are stated rather than glossed:

- `RtcService`, the second web application (a 13.5 MB war), never initialised, and its context path returns HTTP 500 with a 4716-byte body echoing `Exception: Servlet.init() for servlet [rtc-service-servlet] threw exception`. Its route set has zero coverage; the failure is a vendor packaging defect rather than anything introduced by this research. The correct context path is `/RtcService` - requests to `/rtc/**` return 404 with 730 bytes and to `/services/rtc` return 404 with 738 bytes.
- The `/report` route is mapped and its `ReportAccessFilter` was not read, so its authorisation behaviour is unmapped.
- Nineteen of the 43 mappings were exercised with the canonical URI only; URI-variant testing (case folding, matrix parameters, encoded separators) was completed for a subset rather than for all of them. Three filter bypasses were nonetheless demonstrated during the survey, and they are reported as context in section 10.4 rather than folded into this finding.

## 5. Sink Identification

### Sink Identification - how the sink was found

The path to this sink ran through a negative result first. An initial structural survey of write primitives concluded that no write primitive existed that could feed an executable location, on the strength of three observations: `getRealPath` appears at only five sites, none of them a write; hardcoded `webapps` and `ccollab_server` literals appear nowhere; and none of the 23 web-layer write points uses the webroot as its base. Every one of those observations was correct, and the conclusion drawn from them was wrong, because the survey's addressing domain covered only writes *based at the webroot*. It never considered writes based at a different directory that then traverse relatively into the webroot. That is exactly the shape of this finding.

The lesson generalises and is the reason section 6.3 is phrased as "no further instance was found" rather than "no further instance exists": a negative survey must be re-run for each addressing scheme, not only for the obvious one. A later re-scan across all addressing bases was specified but never recorded as executed, so the claim in this advisory is bounded accordingly.

Once the addressing domain was widened, the candidate emerged from a straightforward inventory of archive-extraction sites: 14 files in the corpus touch `ZipInputStream` or `getNextEntry`, and the review-upload family among them extracts into a directory tree whose location is a sibling of the webroot, at a fixed and predictable depth.

### Sink Identification - the vulnerable construction

`com/smartbear/ccollab/doors/DoorsFilesUploadService.java`, method `upload(int, Version, byte[])`. The whole extraction loop, as reconstructed from the shipped class:

```java
ZipEntry zipEntry = zis.getNextEntry();
if (zipEntry == null) { throw new IOException("File doesn't look like archive."); }   // lines 73-75
while (zipEntry != null) {
    String fileName = Strings.replaceSquareBracketsToRound(zipEntry.getName());       // line 77
    File entryDestination = new File(uploadContext.getDestVersionDir(), fileName);    // line 78
    if (StringUtils.indexOfAny(fileName, IGNORE_FILES_KEYWORDS) == -1) {              // line 79
        if (zipEntry.isDirectory()) Files.createDirectories(entryDestination.toPath());
        else {
            Files.createDirectories(entryDestination.getParentFile().toPath());       // line 83
            try (FileOutputStream out = new FileOutputStream(entryDestination)) {     // line 84
                byte[] bytes = IOUtils.toByteArray(zis);
                out.write(bytes);                                                     // lines 85-86
                if (fileName.contains(".htm")) { splitDocument(fileName, bytes, uploadContext);
                                                 processFileArchive(reviewId, version, uploadContext.getPathVersion(), fileName, bytes); }
            }
        }
    }
    zipEntry = zis.getNextEntry();                                                     // line 72 continues the loop
}
```

`IGNORE_FILES_KEYWORDS` is declared at line 63 and contains exactly one element, `__MACOSX`.

Read as a control set, this loop provides one validation and one filter, and neither addresses traversal. The validation is that the archive contains at least one entry. The filter skips macOS metadata. Line 77 performs a cosmetic character substitution on the name. Line 78 is the defect: the two-argument `File(File, String)` constructor concatenates lexically and does not canonicalise, does not resolve the result against the base, and does not reject parent-directory segments. Line 83 then creates whatever parent directories the attacker's name implies, and line 84 opens the output stream. There is no `normalize()` call, no `startsWith(destDir)` containment test, no canonical-path comparison and no rejection of an absolute name anywhere in the method.

Line 88 carries an unrelated engineering constraint that matters for reproducing this: any entry whose name contains `.htm` is routed into `splitDocument`, which throws `IllegalStateException` unless the content is a well-formed DOORS export. The response for such a round is a 131-byte error body reading `Doors document can't be split. It is empty or not correct` - and yet the traversal entry, appearing earlier in the archive, has already been written and is already anonymously executable. The correct observation discipline for this sink is to judge the marker, not the status code.

### Sink Identification - the sibling implementation with the same root cause

`com/smartbear/ccollab/matlab/SimulinkFilesUploadService.java` shares the defect and shares its parent class. Its `checkArchive` at lines 157-161 throws `IOException("File doesn't look like Simulink archive.")` unless the *first* entry is exactly named `webview.html`:

```java
if (zipEntry == null || !Objects.equals(zipEntry.getName(), WEBVIEW_FILE)) { throw new IOException(...); }
```

Its `copyFilesFromZip` at lines 186-203 then treats every subsequent entry identically: `:188` resolves `destDir.resolve(zipEntry.getName()).toFile()`, `:193` creates parent directories, `:194-196` open a `FileOutputStream` and copy. No `normalize()`, no `startsWith(destDir)`, no `..` rejection. A check that constrains the first entry and then ignores the rest is not a containment control; it is a format assertion.

The two implementations were confirmed to be one root cause rather than two, on four verbatim grounds: a single dispatcher (`ReviewServiceImpl.addZipFiles`, mode selected by the requester, `HtmlBaseFilesUploadService.getService` at lines 81-90 switching `DOORS` to `DoorsFilesUploadService` and `SIMULINK` to `SimulinkFilesUploadService`); a single destination computation shared in the parent class; a single missing control (canonicalisation of entry names against the destination); and a single fix, since adding the containment assertion once in the shared parent repairs both. This advisory therefore reports one root cause with two code instances and does not treat the Simulink variant as separately verified - it was never exercised dynamically, and it carries two additional gates that make its practical exploitability strictly weaker.

A third dispatch site remains unexhausted: `HtmlBaseFilesUploadService:87` returns the Simulink service, and the full set of entry points that reach the same extractor family beyond `/versionupload` and the two JSON-API commands was not enumerated. That enumeration is a precondition for anyone who wants to argue these are multiple findings, and it has not been done.

### Sink Identification - the destination geometry the sink computes

The shared parent class fixes where the traversal starts. `HtmlBaseFilesUploadService.createUploadContext`, verbatim:

```java
protected String getWebServerFolder(int reviewId, String folderName) {
    return this.getUploadMode().name().toLowerCase() + "/" + reviewId + "/" + folderName; }   // lines 70-71
protected UploadContext createUploadContext(int reviewId, String versionFilePath) throws IOException {
    String webServerFolder = this.getWebServerFolder(reviewId, FilenameUtils.removeExtension(versionFilePath));
    File destDir = new File(SystemGlobals.getWebserver(), webServerFolder);                    // line 74
    String pathVersion = this.generatePathVersion(destDir);                                    // line 75
    File destVersionDir = new File(destDir, pathVersion);                                      // line 76
    Files.createDirectories(destVersionDir.toPath(), new FileAttribute[0]);                     // line 77
    return new UploadContext(webServerFolder, pathVersion, destVersionDir); }
```

`SystemGlobals.java:130` declares `private static String webserver = "collaborator-webserver";`, a **relative** path; `SystemGlobals.java:3375` returns it as a `File`. It is injected at startup only, by `CodeCollaborator.java:505` calling `SystemGlobals.setWebserver`, from the `content-webserver` context parameter declared at `ROOT.xml:92` with `override="false"`. That call site is the only one in the corpus, so no runtime interface can rewrite the value - which is also why the pristine-image blockage cannot be worked around from inside the product.

`generatePathVersion` at lines 47-54 returns `VER + index` with `VER = "ver"` (declared at `HtmlBaseFilesUploadService:34` and `SimulinkFilesUploadService:58`), where the index is 1 or one more than the highest existing `ver<N>`.

Because the base is relative, it resolves against the JVM working directory, measured by `readlink /proc/<pid>/cwd` as `/usr/local/ccollab_server/tomcat`. The full destination is therefore:

```
/usr/local/ccollab_server/tomcat/collaborator-webserver/<mode>/<reviewId>/<zipName without .zip>/ver<N>
```

An observed instance, from a run using zip name `marker.zip` and auto-created review 2, put the non-traversal control entry at exactly `/usr/local/ccollab_server/tomcat/collaborator-webserver/doors/2/<zipbase>/ver1/<safe>.txt`. The path segments below `tomcat/` are one for the webserver directory name, one for the mode, one for the review id, `n` for the zip-name segments and one for the version directory.

### Sink Identification - execution identity of the child process

The command executed by the generated Groovy code runs inside the product's JVM as the JVM's own account, and no separate process is created by the product on this path. The observed identity came from the marker template invoking `["id"].execute()` and echoing the result, and it was verbatim:

```
uid=1001(collab) gid=1001(collab) groups=1001(collab)
```

The same account owns the Tomcat process and the container entrypoint script, has exactly one group, and has an empty effective capability set (`CapEff: 0000000000000000`). Corroborating observations of the privilege ceiling: neither `/etc/sudoers` nor `/etc/sudoers.d` exists in the image, so there is no `sudo` route at all; no first-party setuid binary is installed, the only setuid executables being the stock system utilities `gpasswd`, `chsh`, `passwd`, `su`, `mount`, `umount` and `chfn`.

The significance of the ceiling is not that it is low but that it is a *boundary the product does not bridge*: there is no designed path from an application-level administrator to the operating-system root account. That means reaching an OS command with the service account's privileges is itself an escalation of authority relative to what an application user is supposed to be able to do, and it is not a restatement of a privilege the product intends to grant.

Because the JVM runs as uid 1001 and owns the whole installation tree, the achieved identity has full read and write over `/usr/local/ccollab_server/**`. That is enumerated in section 10.2.

### Sink Identification - sibling sinks, and whether they are proven

For the vendor's triage benefit, here is the state of the adjacent sink families. These counts are survey scope, reported so that the same class of defect can be looked for elsewhere; **none of the listed files is claimed to be vulnerable**, and the ones marked refuted were refuted with specific evidence rather than by absence of a test.

| Family | Corpus hits | Proven exploitable here | Notes |
|---|---|---|---|
| `ZipInputStream` or `getNextEntry` | **14 files** | one root cause, two instances (section 5.3) | the survey scope for this weakness class; the other twelve were not individually assessed for attacker control |
| `readObject` family | **9 files** | none | includes `triggers/TriggerStreamReader`, `triggers/AsynchTrigger`, `rpc/DocumentPageServlet` and the `client/impl/Abstract*ServerDMFactory` classes |
| File-write family | 27 files | one (`DoorsFilesUploadService`) | the remaining were not re-scanned under every addressing base; see the caveat below |
| `getRealPath` or `getPathOnDisk` | 7 files | none | all read-oriented or without callers |
| `.lookup(` | 5 files | not established | whether any is a JNDI lookup was never confirmed per file |
| `DriverManager` or `getConnection(` | 29 files | not applicable | the datasource is in-process |
| `ProcessBuilder` | 2 files | none | argument-vector form only, no shell |

The `readObject` family was specifically tested for reachability with attacker-controlled bytes and produced zero qualifying sites. `AsynchTrigger:30` is refuted structurally: its `PipedInputStream` and `PipedOutputStream` are both created inside the same constructor at lines 22-23 and the write end belongs to the server-side `TriggerStreamWriter` at line 24, so no external byte ever enters the stream; `TriggerStreamReader` contains no `readObject()` call at all, using only `readInt()` and `readUTF()`, and its four `expected magic` checks are constant comparisons rather than gadget filters. The strongest candidate, `DocumentPageServlet.java:224-225` (mapped to `/document` by the ROOT webapp's `web.xml:436-442`), is reachable but not controllable: all six callers of `saveAuxiliary` were read and none is an HTTP writer, the actual writer being `BinaryConversionWarnings.writeToFile():188` feeding `loadAuxiliaryPath(contentMD5,"warnings"):162` with a server-generated content digest and a fixed class graph; anonymous `GET /document` returns 401 with 721 bytes. The two `Abstract*SummaryServerDMFactory` sites (`:88`, `:258`) use a validating input stream with an explicit accept-list, and the collection sites are GWT `SerializationStreamReader` instances, not `java.io.ObjectInputStream`.

Two things follow that the vendor should weigh. First, the deserialisation *gadget* surface in this deployment is unusually rich - `bsh-2.0b6`, `commons-beanutils-1.11.0`, `commons-collections4-4.5.0-M1` and `groovy-2.5.23` are all present on the classpath - so any future controllable `readObject` site would land in a well-stocked environment. That is a warning, not a finding. Second, the file-write survey's negative result is incomplete by construction: it was scoped to one addressing base and later corrected once already, so the honest statement is that no second webroot-feeding write primitive was **found**, not that none exists.

## 6. Source Identification

### Source Identification - the tainted input and its transport

The tainted value is the **name of a zip entry**, transported inside a `multipart/form-data` HTTP request body to `POST /services/json/v1`. Nothing about the entry name is interpreted, decoded twice, taken from a header or derived from a session attribute: it is `zipEntry.getName()` at `DoorsFilesUploadService.java:77`, read straight from the archive central directory as the attacker wrote it.

This transport detail is why container-level and framework-level URL normalisation cannot help. Tomcat's URI normalisation collapses `..` sequences in the request path before dispatch, so a traversal carried in a URL is very often neutralised by the container. A traversal carried in a zip entry name inside a request body never passes through that code at all. The product's own `/contentupload` path is protected against exactly this class by a different means - content-addressing - which shows the vendor knew about the hazard in one place and did not carry the control to the review-upload family.

The request carries two parts. The first, named `json`, holds the command array. The second holds the archive bytes. The dispatcher is `ReviewServiceImpl.addZipFiles`, whose `getAndValidateAttachment` at line 981 pulls the stream through `getFileStreamProvider().getStream(zipName)` at line 1006.

### Source Identification - the multipart contract, stated exactly

Reproducing this reliably depends on three contract details that are not guessable from the API documentation shape alone, and getting one wrong produces a confusing failure:

- The command array part must be named `json`. `BaseJsonServlet.java:147` declares `public static final String PARAM_JSON = "json";` and the multipart handling at lines 233-251 reads it back with `req.getParameter(PARAM_JSON)` at line 251.
- **The file part's `name` must equal the declared `zipName` string verbatim.** `MultipartRequestWrapper.java:86` routes form fields to parameters and `:98` stores file parts in a map keyed by their part name; `getStream(fileName)` then returns null for any key that is absent. A mismatch does not produce a traversal failure - it produces the error "Zip archive must be provided in multipart request".
- The request must **not** carry a `testing` parameter, because `BaseJsonServlet.java:247` switches the request to `doGet` when that parameter is present.

The batch ordering rule from section 3.1 applies here: because the command context is rebuilt per request, `SessionService.authenticate` must be the first element of the same array as `ReviewService.addDoorsFiles`. Sending them as two requests does not work.

### Source Identification - sanitization that exists, and what it is for

Three transformations touch the entry name between the archive and the filesystem, and none of them is a path control:

| Site | Transformation | Actual purpose |
|---|---|---|
| `Strings.replaceSquareBracketsToRound` at `DoorsFilesUploadService.java:77` | rewrites `[` and `]` to `(` and `)` | requirement of the downstream DOORS document parser, which treats square brackets as markup |
| `StringUtils.indexOfAny(fileName, IGNORE_FILES_KEYWORDS)` at line 79, against the constant declared at line 63 | skips entries whose name contains `__MACOSX` | suppresses macOS resource-fork metadata that the HFS/zip toolchain emits |
| `FilenameUtils.removeExtension(versionFilePath)` in `createUploadContext` | strips the extension from the declared zip name to form the destination folder name | cosmetic folder naming per upload |

The first two are visible in the code as *something being done to the name*, which is exactly why they are easy to mistake for sanitisation. Both operate on characters that have no bearing on path resolution. Notably, the bracket substitution happens **before** the concatenation at line 78, so even a correct sanitiser inserted at line 77 would have to be re-validated after the substitution to be safe; a fix that only hardens line 77 leaves the ordering problem in place.

A separate and genuinely effective control exists on the sibling route: `VersionContentUploadServlet:90-93` calls `getRestrictedFilePatterns()`. It is a real check with a real purpose - blocking uploads of file types the deployment has restricted. It validates the paths that already belong to the version, not the names inside the archive, and it lives only in the servlet class. The JSON-API dispatcher performs no extension validation anywhere across lines 969-1000.

### Source Identification - validation that is absent

Against the standard containment recipe for archive extraction, the following are all absent from `DoorsFilesUploadService.upload` and from `SimulinkFilesUploadService.copyFilesFromZip`:

- no `Path.normalize()` or `File.getCanonicalPath()` on the resolved destination;
- no `startsWith(baseDir)` or equivalent containment assertion after resolution;
- no rejection of `..` segments in the entry name;
- no rejection of absolute entry names;
- no rejection of backslash-separated entry names, which some extraction routines normalise to separators;
- no allowlist or blocklist of destination extensions on this route (one exists on `/contentupload` at `ZipProcessor.java:85-86`, which is where a reviewer might wrongly assume it applies product-wide);
- no limit on entry count or on cumulative uncompressed size, so the same primitive also supports filling the volume;
- no per-object authorisation check that the caller may write into the review identified by `reviewId`, which means any authenticated principal may also target reviews belonging to others.

The last item deserves a sentence of its own. `addZipFiles` retrieves the review at line 982 with `requireReview(request.getReviewId())` when the caller supplies an identifier, and no ownership or participation test was observed. This advisory does not score that separately - it does not change the vector - but it does mean the write primitive is not confined to reviews the attacker created, which widens the abuse surface for overwriting other teams' review material even in deployments where the webroot write is impossible.

### Source Identification - what makes the taint fully attacker-controlled

Every component of the destination except the last is fixed by product logic and predictable, which is what makes a relative traversal practical rather than theoretical:

| Segment | Value | Predictability |
|---|---|---|
| Working directory | `/usr/local/ccollab_server/tomcat` | fixed for the shipped start script; measured by `readlink /proc/<pid>/cwd` |
| Webserver directory | `collaborator-webserver` | default constant at `SystemGlobals.java:130`, injected from `ROOT.xml:92` with `override="false"`, single segment, no runtime setter |
| Mode | `doors` or `simulink` | chosen by the attacker through the command name |
| Review identifier | integer | returned verbatim by `ReviewService.createReview` and by the auto-creation branch, so known before the upload |
| Folder name | zip name without extension | chosen by the attacker |
| Version directory | `ver<N>` | `N` is dynamic (1, or one more than the highest existing), but always exactly one segment |

The attacker therefore controls the final segment count of the traversal via the zip name, and knows every other segment. Section 7.3 turns that into the depth equation.

## 7. Data Flow

### Data Flow - end-to-end chain

The complete chain, from an authenticated session to command output returned to an anonymous client:

```
[1] POST /services/json/v1   (no session yet)
    [{"command":"SessionService.getLoginTicket",
      "args":{"login":"<user>","password":"<password>"}}]
      -> HTTP 200, 63 bytes, [{"result":{"loginTicket":"<32-hex>"}}]

[2] attacker builds an archive in memory:
    entry 1 : "../../../../../webapps/ROOT/<marker>.gsp"  ->  Groovy template source
    entry 2 : "<safe>.txt"                                 ->  non-traversal control entry

[3] POST /services/json/v1   multipart/form-data
    part "json"   = [{"command":"SessionService.authenticate",
                      "args":{"login":"<user>","ticket":"<32-hex>"}},
                     {"command":"ReviewService.addDoorsFiles",
                      "args":{"zipName":"<name>.zip"}}]
    part "<name>.zip" = archive bytes, Content-Type: application/octet-stream

      CommandHandler.java:57-61     annotation check passes: session present
      ReviewServiceImpl:973         requireUser() -> any authenticated principal
      ReviewServiceImpl:977         isDoorsEnabled() -> true on the Enterprise feature set
      ReviewServiceImpl:980         notEmpty("zipName")
      ReviewServiceImpl:981/1006    stream located by part name matching zipName
      ReviewServiceImpl:982         reviewId omitted -> createReview(user.getLogin())
      ReviewServiceImpl:984-986     version created with filePath = zipName
      ReviewServiceImpl:989         HtmlBaseFilesUploadService.getService(DOORS).upload(...)
      HtmlBaseFilesUploadService:70-77   destDir/destVersionDir computed,
                                         Files.createDirectories(destVersionDir)  <== first IO
      DoorsFilesUploadService:70    createUploadContext(reviewId, version.getFilePath())
      DoorsFilesUploadService:72    zis.getNextEntry()
      DoorsFilesUploadService:77    fileName = replaceSquareBracketsToRound(entry.getName())
      DoorsFilesUploadService:78    new File(destVersionDir, fileName)   <== TRAVERSAL RESOLVES HERE
      DoorsFilesUploadService:83    Files.createDirectories(parent)
      DoorsFilesUploadService:84    new FileOutputStream(entryDestination) -> bytes written
      -> HTTP 200, 41 bytes, [{"result":{}},{"result":{"reviewId":<N>}}]

[4] landed file:  <tomcat>/webapps/ROOT/<marker>.gsp   owner collab:collab

[5] GET /<marker>.gsp   (no cookie, no credential, no header)
      AuthTicketFilter:118          opportunistic auth only, no session -> continues
      AuthTicketFilter:122          neither operand matches a webroot .gsp path -> no 401
      ROOT webapp web.xml:271-278   *.gsp -> groovy.servlet.TemplateServlet
      TemplateServlet               compiles the page in memory and evaluates it
      -> HTTP 200, X-Smart-Bear-Not-Logged-In: true, Set-Cookie: JSESSIONID_COLLAB=<server-issued>
      -> body contains the marker string and the TemplateServlet timing comment
```

### Data Flow - properties of the chain worth naming

**The write succeeds even when the response reports an error.** Step 3's answer depends on which entries follow the traversal entry. With a clean archive the service layer returns HTTP 200 and a 41-byte success body. With a later entry whose name contains `.htm`, `DoorsFilesUploadService:88` routes into `splitDocument`, which throws and produces a 131-byte `IllegalStateException` body - after the traversal entry has already been written. Anyone verifying this by status code alone will record a failure on a machine that is in fact compromised.

**The write side and the execution side sit on opposite sides of the authentication boundary.** Step 3 requires a session; step 5 requires none and in fact issues a fresh one. The attacker who writes the file and the party who triggers execution need not be the same person, and the triggering request is indistinguishable in shape from any other anonymous page fetch. That is the property that makes this more than a self-injection primitive: a single low-privilege account can plant something that any unauthenticated client, crawler or scanner will subsequently execute.

**The product's own audit log records the write as normal activity.** Observed lines were of the form `review created: Review #<N>` and `<user> added 1 files(Version #1: /webserver/doors/<rid>/<name>) to Review #<N>`. Neither line references the entry name, the traversal or the webroot destination.

**Compilation leaves no residue on disk.** After execution, a search of the container work directory found zero GSP compilation artifacts, so a filesystem scan looking for compiled output will not see it. Groovy compiles the template in memory. The work directory is `1001:1001` in the pristine image and writable, but the chain does not depend on that: no artifact is created there.

**The destination tree is created by the product, which is why this precondition is not an accident of configuration.** `HtmlBaseFilesUploadService:77` runs before any entry is read. Any installation in which `addDoorsFiles` can return success at all is an installation in which the webserver directory is already writable by the service account.

### Data Flow - the depth equation and why it must be exact

From the geometry in section 5.4, the number of parent-directory segments needed to climb from the version directory to the Tomcat root is:

```
depth = 4 + n

  n = number of path segments in the declared zip name after stripping ".zip"
  4 = one for ver<N>, one for the mode segment, one for the review identifier,
      and one for the webserver directory-name segment itself
```

Two independent measurements agree with it, at two different values of `n`: a flat zip name (`n = 1`) required five segments, and a zip name of the form `<dir>/<name>.zip` (`n = 2`) required six, with the six-segment marker also executing anonymously. Both points were reached in separate instances.

An earlier formulation of this equation, recorded as `2 + <zip-name segments> + 1`, is wrong by exactly one layer and is retired. Its defect was omitting the webserver directory-name segment `collaborator-webserver` from the climb. Two independent measurement points being off by the same signed amount is a derivation error, not measurement noise, and the corrected constant was derived from source (`HtmlBaseFilesUploadService:70-78` and `:47-54`, `SystemGlobals.java:130`, `ROOT.xml:92`) and then confirmed against both measurements. Two independent reviewers derived the same corrected equation and both attempted to refute it without success. Three residual assumptions come with it and should travel with any reuse: the `content-webserver` value must be a single path segment (it is, by default, and there is no runtime setter, but a deployment that overrides it with a multi-segment relative path or moves it out of the Tomcat tree shifts the constant); `ver<N>` always contributes exactly one segment regardless of how large `N` grows; and a review identifier contributes exactly one segment however many digits it has, because it is an `int`.

**Overshooting is not a safety margin, and this deserves emphasis because it is the intuitive mistake.** POSIX path resolution clamps `..` at the filesystem root, so supplying nine segments where five are needed turns the target into the *absolute* path `/webapps/ROOT/<marker>.gsp`. The mandatory pre-write call at `DoorsFilesUploadService:83`, `Files.createDirectories(entryDestination.getParentFile().toPath())`, then asks uid 1001 to create `/webapps`, which fails with `EACCES`, and not a single byte is written. Undershooting is quieter and worse in a different way: the file lands inside the webserver content tree, is served behind the authenticated `/webserver/*` prefix where an anonymous client receives 401, and leaves an attacker file behind on disk. Depth must be exact in both directions.

### Data Flow - where the chain crosses the authentication boundary

It is worth stating precisely where authority is gained, because the score depends on it. Between step 3 and step 5 the chain crosses no operating-system privilege boundary and no component boundary: the write is performed by uid 1001 inside the product's own JVM, the file is created inside a directory the same uid already owns, and the execution in step 5 happens in the same JVM, the same web application and the same uid. What changes between the two steps is only *who triggers it* - an authenticated principal on the write side, an anonymous client on the execution side. Under CVSS 3.1 the identity of the party who pulls the trigger is captured by Attack Vector and User Interaction, not by Scope, and Scope is therefore Unchanged. Section 12.3 argues this at length because the opposite reading is defensible and was considered.

## 8. Exploit Construction

### Exploit Construction - step sequence

The reference implementation shipped with this advisory is `exploit/smartbear_collaborator_doors_upload_zip_slip_webroot_gsp_rce.py`, standard library only, six requests in the primary mode and four in control mode. Its sequence:

1. Resolve the target from `--scheme`, `--host` and `--port`, or from `--base-url`. The host default is `127.0.0.1` and the port default is `8080`; nothing in the script contains a real deployment address.
2. Refuse to run unless `--i-have-authorization` is present.
3. `POST /services/json/v1` with a single-element array calling `SessionService.getLoginTicket`; extract `loginTicket` from the first `result` object. Abort on failure and print the JSON error `code`, since a credential error here is `AuthenticationFailed`.
4. Generate an eight-character random tag and build the archive **in memory** with `io.BytesIO`, writing the traversal entry first and a non-traversal control entry second. Nothing is written to the analyst's disk at any point.
5. Compute depth with `resolve_depth`, which is the `depth = 4 + n` equation, overridable with `--depth`.
6. `POST /services/json/v1` as `multipart/form-data` with a hand-built body: the `json` part carrying `[authenticate, addDoorsFiles]` and the file part whose name is the declared `zipName`. Print status, length, extracted `reviewId` and every error `code`.
7. If an `InternalError` whose message is only a filesystem path appears, print the explanation that the destination tree is not writable by the service account and that this is the pristine-container-image shape.
8. `GET /<marker>.gsp` with no cookies and no headers; print status, length, the `X-Smart-Bear-Not-Logged-In` value and the body. Declare success on the presence of the round's marker string, and report separately whether the `Generated by Groovy TemplateServlet` timing comment is present, which distinguishes real evaluation from a file being echoed as text.
9. Run the two read-only controls (section 9.6).
10. Print a manual cleanup instruction. The script never deletes anything on the target, deliberately: removing the marker requires container or host access, and a verification tool that reaches into a host to clean up after itself is a tool with more authority than it needs.

### Exploit Construction - payload engineering constraints

Four constraints were discovered by failure rather than by reading, and each one is the difference between a reproducible exploit and a confusing one:

- **No `.htm` entry may appear in the archive.** `DoorsFilesUploadService:88` sends any entry whose name contains `.htm` into `splitDocument`, which throws `IllegalStateException("Doors document can't be split. It is empty or not correct")` and breaks the loop. Because the traversal entry is written before that throw, the round is simultaneously an error response and a successful compromise. The reference implementation never emits an `.htm` entry.
- **The traversal entry must come first**, or at least before anything that can throw, for the same reason.
- **The file part name must match `zipName` exactly**, including extension, or the stream lookup returns null and the product answers "Zip archive must be provided in multipart request".
- **The `testing` parameter must be absent**, or `BaseJsonServlet.java:247` converts the request into a GET.

The payload itself is a Groovy Server Page scriptlet. The harmless verification form echoes a JVM property:

```
<%= "COLLABFIRED_<tag>_" + System.getProperty("user.name") %>
```

and the command-execution form, which is what produced the observed `id` output, appends the standard output of an executed command:

```
<%= "COLLABFIRED_<tag>_" + System.getProperty("user.name") + "|UID=" + ["id"].execute().text.trim() %>
```

The `["id"].execute()` form is the Groovy JDK extension that runs an external process via a shell-free argument vector. Note for anyone building on this: because it is argument-vector execution, arbitrary shell syntax will not work as-is, and a payload needing redirection or pipes must invoke a shell explicitly. That constraint is a property of the technique, not of this product.

The marker text carries the round's random tag, which is what makes a positive result unfakeable by a leftover file from an earlier run. A verification result that cannot distinguish this round's write from last week's is not a verification result.

### Exploit Construction - the execution half

No second request primitive is needed to reach execution: an ordinary anonymous GET is sufficient. Confirmed by four independent observations that the mapping is anonymous in the shipped artifact:

1. Statically, the filter's only unconditional 401 branch is `secureContentList.contains(uri) || uri.startsWith("/webserver")` at `AuthTicketFilter.java:122`, and the list holds two script paths.
2. Dynamically as a diagonal: the same anonymous client received 401 with a 657-byte body for `GET /webserver/anything`, 401 for a control file placed inside the webserver content tree, and 200 with evaluated output for the webroot `.gsp`. The two paths differ only in which side of the webroot they sit on.
3. The triggering response carried `X-Smart-Bear-Not-Logged-In: true` and a `Set-Cookie` for a session the client had never presented, so the server itself confirmed the caller was anonymous.
4. On a **pristine, never-written-to** instance - the shape where the traversal is blocked - requesting the vendor's own shipped template `/jsp/views/json_tester.gsp` anonymously returned HTTP 302 to `/jsp/errors/ServerErrorPage.jsp?message=Cannot+invoke+method+replaceAll%28%29+on+null+object`, a Groovy runtime null-pointer from line 10 of that template, while the control path `/no-such-path-xyz.gsp` returned 404 with 653 bytes. Anonymous Groovy template evaluation is therefore an inherent property of the shipped artifact and not something this research introduced by writing a file.

### Exploit Construction - what the exploit deliberately does not do

- No reverse shell, no bind shell, no interactive session.
- No persistence: nothing is installed, no scheduled task, service, startup entry or product configuration is modified, and the product's own `setWebserver` value is neither read back nor changed.
- No destructive payload. The default marker writes one small text file whose only effect is to prove evaluation; the optional command defaults to `id`, which reads nothing and writes nothing.
- No scanning, no brute force, no credential stuffing, no directory enumeration beyond the two marker paths.
- No mass traversal. One archive, one traversal entry, one landing path. The script does not iterate depths looking for a hit, because iterating depths leaves attacker files behind at every undershoot.
- No absolute-path archive entries, which is a separate extraction hazard and not needed here.
- No modification of the analyst host: the archive is built in memory and nothing is written locally.
- No licence activation, no licence material read or forged, and the initialisation command that would complete product setup is never called.
- No deletion on the target. Cleanup is printed as an instruction and left to the operator.
- No attempt to escalate from uid 1001.

## 9. Dynamic Verification

### Dynamic Verification - environment

Four container instances were derived from the vendor's published image loaded from a 1795588608-byte image archive, each published on a loopback address only. The instances divide by the ownership of the webserver directory, which turned out to be the single discriminating variable:

| Instance role | Webserver directory before the run | Researcher intervention inside the container | Purpose |
|---|---|---|---|
| Pristine shape (two separate instances, same recipe) | `drwxr-xr-x 2 root root`, empty | none | establish that the shipped artifact blocks the chain |
| Repaired-ownership shape | `root root`, then recursively chowned to `1001:1001` by the researcher | `chown -R 1001:1001` | establish the chain works once the directory is writable; deliberately **not** representative of a default deployment because the ownership change was ours |
| Writable-mount shape (two separate instances) | host-side empty directory created and chowned to `1001:1001`, bind-mounted at the webserver path; zero entries before the first run | none inside the container | establish that the product itself creates the whole destination tree as the service account |

Service identity was confirmed from inside the container: `/proc/<pid>/status` for the JVM showed `Uid: 1001` and `CapEff: 0000000000000000`, and the entrypoint script's process showed the same. All requests originated from `127.0.0.1`; a re-test from a non-loopback source address was not performed.

Instances were in the partial-schema state described in section 1.3, and licence activation was never invoked.

### Dynamic Verification - the three deployment shapes

The pristine shape's exact blocking point was identified from the response rather than inferred. The service layer returned:

```
RESP_HTTP=200 RESP_LEN=127
[{"result":{}},{"errors":[{"code":"InternalError","message":"/usr/local/ccollab_server/tomcat/collaborator-webserver/doors"}]}]
```

The error message is a bare path with no explanation, which is the signature of `addZipFiles`'s `catch(IOException)` wrapping the first failing operation. That operation is `Files.createDirectories(destVersionDir.toPath())` at `HtmlBaseFilesUploadService:77`, and it fails with `EACCES` because the mount point is root-owned while the JVM runs as uid 1001. Confirmed mechanically: an attempt to create a directory inside the webserver path as uid 1001 on a pristine instance failed with `mkdir: Permission denied`, while the parent `tomcat/` directory itself is `1001:1001` and a `mkdir` inside it by uid 1001 exits zero. A subsequent filesystem-wide search for the marker returned zero hits, an anonymous GET of the marker path returned 404 with 653 bytes, and on the second pristine instance a case-insensitive search of the webroot for the round's tag returned zero. No traversal logic, no authentication gate and no feature gate was involved in that block - it is a filesystem permission on a packaging artefact.

The repaired-ownership shape returned HTTP 200 with a 131-byte body containing the `IllegalStateException` described in section 8.2, because that round's archive happened to include an `.htm` probe entry in third position:

```
HTTP=200 LEN=131
[{"result":{}},{"errors":[{"code":"IllegalStateException","message":"Doors document can't be split. It is empty or not correct"}]}]
```

The traversal entry was in first position, so it had already been written: a 56-byte marker file appeared in `webapps/ROOT/`, an anonymous GET returned HTTP 200 with a 95-byte body containing the marker string and the comment `Generated by Groovy TemplateServlet [create/get=77 ms, make=1 ms]`. This shape is reported because it produced the first positive result and because it demonstrates the error-response-with-successful-write behaviour, but it is explicitly **not** evidence about a default deployment: the ownership change was made by the researcher.

The writable-mount shape is the one that carries the deployment claim. The host-side directory held zero entries before the first run, no `chown`, `mkdir` or `chmod` was executed inside the container at any point, and the service layer returned a clean success:

```
RESP_HTTP=200  RESP_LEN=41
[{"result":{}},{"result":{"reviewId":1}}]
```

The anonymous GET returned:

```
ANON_HTTP=200  ANON_LEN=103
X-Smart-Bear-Not-Logged-In: true
Set-Cookie: JSESSIONID_COLLAB=<server-issued>

COLLABFIRED_<tag>_collab
<!-- Generated by Groovy TemplateServlet [create/get=158 ms, make=7 ms] -->
```

and the landed file was `-rw-r--r-- 1 collab collab 61 <tomcat>/webapps/ROOT/<marker>.gsp`. The product log recorded `review created: Review #1` followed by `<user> added 1 files(Version #1: /webserver/doors/1/<name>) to Review #1`.

A re-run on the same writable-mount instance with the `.htm` entry removed produced a clean 41-byte success and a second anonymous execution with body `COLLABFIRED_<tag>_collab` and comment `[create/get=54 ms, make=0 ms]`, and with the non-traversal control entry confirmed absent from the webroot.

Ownership of the mount point is what causes the pristine shape to fail, and that ownership is an artefact of how the image is built rather than a product decision. Reading the image history in execution order: the build first creates the service account and recursively chowns the installation home to it; then switches to `USER collab`, so the vendor's installer runs as uid 1001; then declares a `VOLUME` list covering the configuration directory, the JDBC directory, the database directory, `tomcat/collaborator-webserver` and `tomcat/collaborator-content-cache`. At the moment the `VOLUME` instruction executes, the webserver path does not exist - the installer never creates it - so the container runtime creates the mount point as root. Three corroborating observations make the attribution solid rather than convenient: of the twenty entries under `tomcat/`, only two are root-owned and both are `VOLUME`-declared paths; the database directory is also `VOLUME`-declared but *was* explicitly created and chowned earlier in the build, and it is consequently owned by the service account, so the ownership difference tracks build-time creation rather than anything about the product; and an independent check confirmed that both root-owned entries appear in the image's declared volume configuration. An attempted move of the mount point inside a running container failed with `mv: cannot move ...: Device or resource busy`, which is why the writable-mount shape was produced by bind-mounting rather than by relocating.

Evidence about the installer's own behaviour had to be corrected once. The initial statement that the installer never mentions the webserver directory name was a false zero, produced by searching an extracted tree rather than the installer archive itself. Reading the installer jar directly (115690 bytes, extracted read-only) shows the string `collaborator-webserver` exactly once, in the constant pool of a class whose role is writing configuration elements, with neither a `mkdirs` nor a `chown`; the classes that do hold `mkdirs` calls hold no `chown`. The corrected basis for the attribution is therefore: `chown` returns zero hits across the installer archive tree and across all five installer definition files, and neither of the two classes that create directories changes ownership. A control search over a sibling directory name returned one hit in an installer-only configuration file, so the search channel was live. The conclusion is unchanged and better supported: the root ownership is a packaging artefact.

### Dynamic Verification - the triggering request

Verbatim, with the archive attached as a second part whose name equals the declared zip name:

```
POST /services/json/v1 HTTP/1.1
Content-Type: multipart/form-data; boundary=<boundary>

--<boundary>
Content-Disposition: form-data; name="json"
Content-Type: application/json;charset=UTF-8

[{"command":"SessionService.authenticate","args":{"login":"<user>","ticket":"<32-hex>"}},
 {"command":"ReviewService.addDoorsFiles","args":{"zipName":"<name>.zip","reviewId":<N>}}]
--<boundary>
Content-Disposition: form-data; name="<name>.zip"; filename="<name>.zip"
Content-Type: application/octet-stream

<archive bytes>
--<boundary>--
```

Then, from a client holding no credential:

```
GET /<marker>.gsp HTTP/1.1
```

### Dynamic Verification - observed output

The strongest result was obtained on the second writable-mount instance, in an independently rebuilt container with a different random tag, a different non-administrator account and a freshly created review. The template executed `["id"].execute()` and the anonymous response was HTTP 200 with a 167-byte body:

```
COLLABFIRED_<tag>_collab|UID=uid=1001(collab) gid=1001(collab) groups=1001(collab)
<!-- Generated by Groovy TemplateServlet [create/get=309 ms, make=97 ms] -->
```

The service layer had returned 200 with 41 bytes, the product log recorded `<user> added 1 files(Version #1: /webserver/doors/1/<name>)`, and all four nested directories created during the run were owned by uid 1001. That output string is real operating-system command execution, not a property read, and it establishes the execution identity beyond argument.

The same instance confirmed the depth is attacker-controlled: a zip name with an extra directory segment required and used six parent-directory segments, and its marker also executed on an anonymous GET. The reference implementation shipped with this advisory was subsequently run end to end twice more against a writable-mount instance with a non-administrator account. Both runs used fresh random tags and fresh auto-created review identifiers, returned HTTP 200 with 41 bytes and no error code, and produced anonymous GETs of HTTP 200 with `X-Smart-Bear-Not-Logged-In: true` and bodies `COLLABFIRED_<tag>_collab` accompanied by `Generated by Groovy TemplateServlet` timing comments (150 ms and 140 ms respectively). So the finding rests on four mutually independent execution records, three of which used values that could not have been carried over from an earlier run.

One non-deterministic difference between records is logged for completeness rather than explained: the timing numbers inside the `Generated by Groovy TemplateServlet` comment vary between runs of the same payload (77, 54, 158, 309, 150 and 140 milliseconds were observed), and response body lengths for the same marker drift by a couple of bytes because that comment is embedded in the body and its digit count changes. Verification therefore never used body length as the criterion - only the presence of the round's random tag and the evaluation comment. One observed drift of two bytes between an in-script length and a separately measured download size was not root-caused; the marker file had been removed by then and it could not be re-examined. The two candidate explanations are the per-request timing digits and a difference between how the two measurements count the body.

### Dynamic Verification - ownership forensics for the directories the product created

The single most important positive observation for the deployment question is this listing, taken on the host side of the bind-mounted, initially empty directory after one run:

```
1001:1001 d <mount>/doors
1001:1001 d <mount>/doors/1
1001:1001 d <mount>/doors/1/<name>
1001:1001 d <mount>/doors/1/<name>/ver1
1001:1001 f <mount>/doors/1/<name>/ver1/<safe>.txt
```

The directory entry count before the run was zero, and no ownership, permission or directory-creation command was executed inside the container or against the mount point by the researcher at any point. Four levels of directory plus one file therefore came into existence owned by uid 1001, and the only code in the chain that creates them is `Files.createDirectories(destVersionDir.toPath())` at `HtmlBaseFilesUploadService:77`. The group is shown by numeric id here because the host maps uid and gid 1001 to an unrelated local account name; the numeric uid is the load-bearing value and it is the service account's.

Two verification habits came out of this and are worth passing on. A recursive listing must be used rather than a glob built from the expected review identifier, because `addZipFiles:982` creates a review when none is supplied and the resulting identifier depends on instance history; an initial non-recursive check at this stage appeared to show the control entry missing when it was in fact one review directory deeper. And the destination folder name is the declared zip name with its extension removed, which independently confirmed the zip-name term in the depth equation.

### Dynamic Verification - the independent reproduction

Independence here means more than "it worked again". The second writable-mount instance was a freshly created container, with a new random tag, a newly created non-administrator account, and a new review; its payload was upgraded from a property read to a real command execution; and it was accompanied by a paired pristine-shape instance built from the same recipe with no ownership intervention, which returned the 127-byte `InternalError`, a 404/653 marker GET and zero hits on a webroot search for the tag. Running both shapes from one recipe isolates ownership as the only variable.

Seven objection lines were pursued against this result and six failed:

| Objection | Outcome |
|---|---|
| Template execution depends on the work directory being writable | Refuted. The work directory is `1001:1001` in the pristine image, and after execution it holds zero GSP artifacts - compilation is in memory and the chain does not depend on it |
| The `VOLUME` attribution for the pristine block is wrong | Refuted, and strengthened by the three corroborating observations in section 9.2 |
| The restricted-file-pattern check blocks this path | Refuted. The one such check in the dispatcher file sits inside a source-control change-list loop; lines 969-1000 contain no extension validation |
| The five-segment depth is a fixed constant | Refuted, and self-defeating: six segments were demonstrated with a deeper zip name |
| The writable-mount shape involved an ownership change | **Sustained, at the level of wording only.** Inside the container there was no ownership or permission intervention; the mount point's ownership was pre-set on the host side to model a deployment where the service account owns its own installation directory, and the vendor's native installer was never run on a real host. All wording in this advisory reflects that distinction |
| The `*.gsp` mapping requires authentication | Refuted by the four observations in section 8.3 |
| The result is not reproducible | Refuted by the independent instance and by two further runs of the shipped implementation |

### Dynamic Verification - the negative control and why it matters

Controls were run for every positive claim, and the negative ones are reported with the same prominence as the positives.

| Control | Observation | What it excludes |
|---|---|---|
| A same-named entry **without** `..` in the same archive | zero hits for it in the webroot; it landed at `<webserver>/doors/1/<name>/ver1/<safe>.txt` | that arbitrary paths land in the webroot. Only traversal entry names escape |
| Same bytes, same location, extension changed to `.txt`, fetched anonymously | HTTP 200, 61 bytes, body is the verbatim template source with no evaluation and no `Generated by Groovy TemplateServlet` comment | that the 200 response means execution, and that any webroot file is served as code. The `.gsp` mapping is what evaluates |
| A `.gsp` path that does not exist | HTTP 404, 653 bytes | that every `.gsp` request returns 200 |
| **Anonymous** call to `ReviewService.addDoorsFiles` | HTTP 200, 127 bytes, `AuthenticationError` | that the write side is unauthenticated. This is the control that fixes the finding as post-authentication |
| Non-administrator calling an administrator-only method, and the same call with an administrator ticket | 114 bytes `AuthorizationError` versus 29 bytes success | that the sink path is simply globally open, and that a 114-byte answer means a broken instance |
| Webroot writability probe as uid 1001, independently of the traversal | `touch` in `webapps/ROOT/` succeeded, and the probe `.gsp` executed anonymously with the marker present exactly once | - establishes the amplifier half independently of the write half |
| Webserver writability probe as uid 1001 on a pristine instance | `mkdir: Permission denied` | that the pristine block is anything other than a filesystem permission |
| Template-injection probe `${7*7}` through normal request parameters | echoed literally, zero occurrences of `49`, `<` escaped | that this is server-side template injection. It is write-then-execute, a different mechanism |
| Feature-gate inspection | five `@NoAuthRequired` methods on `ServerInfoService`, all getters, no setter; no such configuration key exists in the product | that the edition gate can be flipped from the management surface |

The specific control the task of re-verification turns on is the **fresh-value re-run**: each of the last three positive runs used a newly generated random marker tag and a newly created review identifier, and each carried the non-traversal entry as an in-archive control. A null result there would mean the file was not written outside the version directory at all, and combined with the 404 for a non-existent `.gsp` and the source-echo for a `.txt` twin, a null result would leave no route to claiming execution. The paired pristine-shape run is the other half of the control: it produced exactly that null - zero marker hits filesystem-wide, 404/653 on the anonymous GET, zero tag hits in the webroot - and it is the observation that establishes the blocked deployment shape rather than an assumption about it.

### Dynamic Verification - boundaries of what was verified

Stated exhaustively, because each of these is a place where a reader could otherwise over-read the result:

- Only build 15.1.15101 was exercised. No other version or edition was tested, and no cross-version claim is made.
- No request was sent from a non-loopback source address. If the product exempts private or loopback peers anywhere in this path, that was not tested and cannot be excluded.
- A fully initialised and licensed instance was never used. The partial-schema state did not block user creation, review creation or the upload, but the licensed state was not compared.
- The native install4j installation shape was never produced on a real host. The claim that it leaves the webserver directory owned by the service account rests on three structural observations: the installer archive contains no `chown` at all and its two directory-creating classes change no ownership; the product code necessarily creates the tree itself at `HtmlBaseFilesUploadService:77`; and a directly comparable runtime directory in the same image (`collaborator-content-cache`) is likewise absent before startup and was observed to be created by the product as `1001:1001` after the service ran on an unmodified artifact. That is a strong argument and it is not a measurement.
- The Free and Professional (Reviewer) edition block is static inference only.
- Alternative executable extensions were not tested. `.jsp` in particular was not exercised, so nothing here says whether a `.jsp` landing would also execute; the shipped mapping that was proven is `*.gsp`.
- Depth behaviour with multi-digit review identifiers, backslashes in entry names and absolute entry names was not exercised.
- No exhaustiveness claim is made about a second webroot-feeding write primitive, about a switch that disables GSP evaluation, or about the origin of the observed `X-FRAME-OPTIONS: DENY` header, which is `SAMEORIGIN` in the decompiled source and was `DENY` in four live observations. That divergence is itself a reminder that corpus constants and runtime behaviour must be paired.
- Marker files were removed from the webroot after every run and the removal was confirmed by a follow-up anonymous GET returning 404/653 and by a filesystem search returning zero. The non-traversal control entries inside the webserver tree were left in place as evidence, and all instances were destroyed at teardown along with the sessions they held.

## 10. Reachability and Security Impact

### Reachability and impact - network position

The product presents one network listener, `8080/tcp`, and every request in the chain - session ticket, upload, and anonymous trigger - goes to it over ordinary HTTP. There is no requirement for local access, no requirement for a privileged network position, no requirement to reach a management interface on a separate port, and no requirement for the database to be reachable, since HSQLDB is in-process. An attacker who can open a TCP connection to the Collaborator web port can perform the whole chain, subject to holding one authenticated account.

Two qualifiers on reachability are stated here rather than in a footnote. First, all verification traffic came from loopback and a non-loopback re-test was not performed, so any product-side exemption for private or loopback peers is unexcluded. Second, and much more important for anyone assessing their own exposure: **whether the chain works at all is decided by the ownership of the webserver content directory**, and one shipped shape blocks it. An operator running the vendor's official container image with that mount point left as shipped - root-owned, service running as uid 1001 - is not exposed to code execution on this vector, because the first filesystem call fails. An operator on the native install shape, or on a container where that volume was created with service-account ownership, or where the volume was chowned during deployment automation, is exposed. This is not a subtle distinction and it should drive triage: check the ownership of the directory named by the `content-webserver` context parameter, default `collaborator-webserver`, relative to the Tomcat working directory.

The consequence of that asymmetry for the headline is worth stating plainly: **this advisory does not claim that every deployment of this product is exploitable.** It claims that the product contains an unsanitised archive-extraction sink reachable by any authenticated user, that the sink can be aimed at an anonymously executed webroot location, and that this was demonstrated end to end wherever the upload tree is writable by the service uid - with one shipped artifact shape blocking it on filesystem permissions. The same asymmetry is what the rating in section 12 expresses, and it is the reason the published headline carries Attack Complexity High: the shape that was actually tested blocks the chain, and the shape that permits it was never produced on a real host, so the Low reading is published separately and labelled as conditional rather than being allowed to set the headline.

### Reachability and impact - what the achieved identity controls

The achieved identity is uid 1001, account name `collab`, single group, empty capability set, with full read and write over the entire installation tree `/usr/local/ccollab_server/**`. Concretely:

- **Every user credential in the product.** The HSQLDB file `hsqldb/database.data` holds password digests computed as unsalted ASCII MD5, confirmed by reading the file. Unsalted MD5 over a password field is recoverable at scale with commodity hardware, so this is a disclosure of all account passwords rather than of opaque hashes.
- **The database's own superuser credential.** The JNDI datasource declared at `conf/Catalina/localhost/ROOT.xml:33` uses `username="sa" password=""`; before any initialisation the catalog contains `CREATE USER SA PASSWORD DIGEST 'd41d8cd98f00b204e9800998ecf8427e'` and `GRANT DBA TO SA`, that digest being MD5 of the empty string.
- **Every integration secret.** Source-control passwords, OAuth client secrets and licence user lists are stored encrypted under a constant key embedded in the application at `EncryptUtils.java:31-32`. An identity that can read the classpath can decrypt them, so every configured SCM and identity-provider integration is compromised along with the product.
- **All review content.** The review material, attachments, comments and the content-addressed cache are all inside the tree.
- **Application integrity and availability.** The webroot and the whole Tomcat directory are owned by the service account, so application classes, configuration and the database file itself can be overwritten or deleted. This supports the integrity and availability metrics rather than being asserted separately from them.
- **A second, independent read primitive.** A separate unauthenticated double-decoded traversal in the static content servlet (`WebserverServlet.java:208`, building `new File(root, URLDecoder.decode(pathInfo))` with no canonicalisation) was demonstrated during the survey and reads the same tree as the service account. It is a distinct root cause with a distinct fix, is not folded into this vector for scoring purposes, and is mentioned only because an attacker combining the two gets read access without needing an account.
- **What it does not control.** The host. No `sudo` binary or configuration exists in the image, no first-party setuid binary exists, the capability set is empty, and there is no designed path from an application administrator to the root account. Container escape was not attempted. Root was not reached and is not claimed.

Because the write primitive is not confined to reviews the caller owns - no per-object authorisation was observed on `addZipFiles` at line 982 - the same identity can also write into other teams' review material, which is an integrity impact on other users' data that does not depend on the webroot being reachable at all.

### Reachability and impact - the unauthenticated question, answered in full

There is an anonymous route into an administrator session on this product, and it is disclosed here with its qualifier, because it is the reason a reader might expect an unauthenticated classification and the reason that expectation would be wrong.

`InitializationService.initDatabase` carries `@NoAuthRequired`. An anonymous `POST /services/json/v1` with `[{"command":"InitializationService.initDatabase","args":{}}]` returns HTTP 200 with a 15-byte body `[{"result":{}}]`, creates the schema, and seeds an administrator account with the password `admin`. Observed effects: `database.data` grew from zero to 229376 bytes, the log grew from 78 to 312521 bytes, and the product's own log line reads `http-nio-8080-exec-7 ... Engine - user created: id=1; login=admin; name=Administrator` - note the HTTP worker thread, proving the call came in over the network rather than during startup. A ticket for that account was then obtainable, while eleven candidate passwords including the empty string all returned `AuthenticationFailed` in 119-byte responses, so this is a deterministic weak seeded credential rather than a fail-open check. Calling `initDatabase` on its own also leaves a partial schema: the product logs `SQLSyntaxErrorException -5501 user lacks privilege or object not found: REMOTESYSTEM`, the `ACTIVITY` table is also absent, and the product's own polling and webhook services fail with the same error.

**This route holds only on an instance that has never been initialised.** That is not an assumption; it was tested. The call was replayed twice against an instance whose state had already been enriched - a created second user, a created project under it, and, critically, a changed administrator password. Both replays were idempotent and harmless:

| Property | After anonymous replay |
|---|---|
| Second user and its identifier | unchanged |
| Administrator account's GUID | not recreated |
| Changed administrator password | still valid, ticket issued in a 63-byte response |
| Factory password `admin` | refused, `AuthenticationFailed`, 119 bytes |
| Project belonging to the second user | still present |
| `database.data` size | unchanged at 229376 bytes |
| Count of missing-table errors | no new occurrences |
| Web UI and static asset availability | unchanged |

So replaying the initialisation command does not wipe the database and does not reset the administrator password. A password an operator has changed stays changed. That is the whole reason this finding is published as post-authentication rather than unauthenticated: the anonymous variant is a real weakness, but its impact is confined to instances still sitting in the never-initialised state, which is a narrow and transient window, and it cannot be used to take over a configured production instance. Publishing an unauthenticated reading on the strength of it would be publishing a claim the evidence contradicts.

One direction remains untested in both senses. Because full product initialisation requires licence activation over the network, it was never invoked, so the behaviour of this command against a completely initialised and licensed instance is unknown. Neither an escalation nor a further restriction may be inferred from what was measured here.

### Reachability and impact - detection notes

Detection of this chain is harder than the response codes suggest, and the reasons are specific:

- **HTTP 200 on both success and failure.** The blocked shape returns 200 with an `InternalError`, the `.htm` variant returns 200 with an `IllegalStateException` after a successful write, and the clean shape returns 200 with a success body. Status-code alerting cannot separate these. The discriminating field is the JSON `code`, and even that is misleading in the `IllegalStateException` case because a write has succeeded.
- **Body length is not a reliable discriminator.** The product embeds the command name in its error text, so the same `AuthenticationError` appears at 118, 122, 123 and 127 bytes depending on the method, and template responses carry per-request timing digits that change the length of the same output.
- **The product's audit log looks normal.** The only entries are a review creation and a file-addition line naming a version directory under `/webserver/doors/`. Neither mentions the entry name, the traversal, or the webroot destination.
- **The triggering request is anonymous and unremarkable.** It is an ordinary GET for a `.gsp` path, carrying no session, and the server issues a fresh session cookie for it and marks it `X-Smart-Bear-Not-Logged-In: true`. In a log it is indistinguishable from a client requesting a static page that happens to exist.
- **Compilation leaves no artifact.** A scan of the Tomcat work directory for compiled template output will find nothing.
- **What does leave a trace.** A `.gsp` file in the webroot. The shipped artifact contains exactly one Groovy template in the entire installation, at `ROOT/jsp/views/json_tester.gsp`, so any other `.gsp` under `webapps/ROOT` is anomalous and is a high-confidence indicator on its own. File-integrity monitoring on the webroot is the single most effective detection control available to an operator today. Multipart bodies containing entry names with `..` are also detectable at the network layer, but only if the product's traffic is inspected in a way that decodes multipart bodies, which most deployments do not do.
- Three filter bypasses were demonstrated during the survey (a `/jsp/errors` substring that skips the filter body entirely, a matrix-parameter suffix that makes a protected script path answer anonymously with 200 and 246859 bytes of JavaScript, and encoded-separator variants of the `/webserver` prefix test). These are context for how much of this product's surface is anonymous; none of them is required by this chain, and none is folded into this vector.

### Reachability and impact - persistence

A written `.gsp` survives as long as the file survives, and the file is in the webroot owned by the service account. The chain therefore provides a persistence mechanism for anyone who has already achieved execution, using the same primitive: an account that can be revoked still leaves its marker behind. **Persistence across a service restart is not established.** The webroot is unpacked from the war at runtime because `unpackWARs` is unset and defaults to true, and whether a restart re-unpacks the war and thereby removes an injected file was never tested; no restart was performed during this work. Nothing in this advisory should be read as claiming that a planted template survives a restart, or that it does not.

## 11. Fix Recommendations

### Fix Recommendations - vendor-side, ordered by root cause

1. **Canonicalise every archive entry name against the destination directory, in both instances of the shared extractor family.** The containment test must run per entry, not once for the archive. The minimal correct form at `DoorsFilesUploadService.java:77-84` and `SimulinkFilesUploadService.java:186-203` is:

```java
Path base = destDir.toPath().normalize();
Path target = base.resolve(entryName).normalize();
if (!target.startsWith(base)) {
    throw new IOException("Archive entry escapes the destination directory: " + entryName);
}
```

   A `getCanonicalPath()` comparison is equivalent and also collapses symlinks, which is worth having. Placing this once in `HtmlBaseFilesUploadService` protects both subclasses and any future third dispatch site such as the one at line 87, and is strictly preferable to patching the two leaf classes, which is how the two came to diverge in the first place.

2. **Reject dangerous entry names explicitly, in addition to the containment test.** Defence in depth costs nothing here: refuse `..` segments, absolute paths, backslash separators and entry names resolving to a different filesystem. Apply the rejection *after* `Strings.replaceSquareBracketsToRound` at line 77, since that substitution currently runs before concatenation and a sanitiser inserted before it would be operating on a name that then changes.

3. **Move the review-content tree out of the traversal radius of the webroot.** The real defect is not only the missing check; it is that `content-webserver` resolves, by default, to a sibling of `webapps/ROOT` inside the Tomcat working directory, so a fixed handful of parent-directory segments converts a content write into a code write. Deploying the content volume on a separate mount or outside the Tomcat tree means a traversal of any depth cannot reach executable space.

4. **Stop the extracted content from being executable.** An extension allowlist on extraction output - or an explicit denylist covering `*.gsp`, `*.jsp`, `*.jspx`, `*.jspx`, `*.war`, `*.class` and `*.jar` - removes the amplifier even if a containment check is later bypassed. This also aligns the two upload routes: apply to `ReviewService.addDoorsFiles` and `addSimulinkFiles` the same restricted-file-pattern discipline that `/versionupload` already performs at lines 90-93.

5. **Narrow the `*.gsp` mapping.** Move templates under `WEB-INF` so they are not directly addressable, or bind the mapping to authenticated access, or remove it entirely if the single shipped template at `ROOT/jsp/views/json_tester.gsp` can be relocated. A suffix mapping to a code-evaluating servlet inside a service-owned webroot is a standing escalation surface for any future write defect, and it is the reason a file-write bug in this product becomes remote code execution rather than remote file write.

6. **Make the global filter default-deny.** `AuthTicketFilter.doFilter` currently authenticates opportunistically at line 118, forces a 401 on exactly one two-operand condition at line 122, and otherwise allows at line 128. Inverting that - explicit allowlist, deny by default - would have made the anonymous reachability of a webroot `.gsp` an opt-in decision rather than an emergent one, and would close the three demonstrated bypasses at the same time.

7. **Fix the packaging.** Every path declared `VOLUME` should be created and chowned to the service account during the image build, as the database directory already is. That removes the root-owned mount points for `collaborator-webserver` and the content cache, eliminates the inconsistency between two identically-declared volumes, and - it should be said plainly - removes the only thing currently preventing this chain from working in the container shape. Fixing it does not make the product less safe; the traversal is the bug, and a deployment that happens to fail on permissions is not a defence anyone should be relying on.

8. **Add per-object authorisation on review writes.** `addZipFiles` at line 982 accepts an arbitrary `reviewId` with no check that the caller may modify that review. Independent of the traversal, that permits writing into other users' reviews.

### Fix Recommendations - operator-side, until a patch exists

1. **Check the ownership of the content-webserver directory** relative to the Tomcat working directory, default `<tomcat>/collaborator-webserver`. If it is root-owned while the service runs as uid 1001, the chain is blocked at the first filesystem call. If it is service-owned, treat the installation as exposed. Do not "fix" the exposure by chowning it to root on a native install - that breaks the feature and is exactly the packaging defect in item 7 above, arrived at from the other side.
2. **Put file-integrity monitoring on the Tomcat webroot**, specifically alerting on any new file under `webapps/ROOT` and on any `.gsp` file other than the single shipped template. This is the highest-value compensating control available and it detects the write regardless of which route produced it.
3. **Restrict who can hold an account.** The write side requires one valid low-privilege login and nothing more. In an organisation where review participation is broad, treat every account holder as able to reach this sink. Where the product sits behind a gateway, require strong authentication for account issuance and audit existing accounts for dormant or service identities.
4. **Remove or restrict the `*.gsp` mapping at the container level** if it can be done without breaking the JSON tester view. Removing the mapping from the ROOT webapp's deployment descriptor eliminates the execution half of the chain, which reduces this to a file-write defect inside the content tree.
5. **Egress-filter the service.** The product contacts a licence host over the network and will contact source-control and identity-provider endpoints as configured. An attacker holding uid 1001 can use those channels. Restricting outbound connections limits exfiltration of anything recovered from the configuration and the database.
6. **Rotate every credential stored in the product** - source-control tokens, OAuth client secrets, directory-service bind credentials, and all Collaborator account passwords - on any instance where compromise is suspected, because all of them are readable or decryptable by the achieved identity and the password digests are unsalted MD5.
7. **Monitor for the two-part request shape**: a multipart `POST /services/json/v1` whose `json` part contains `ReviewService.addDoorsFiles`, closely followed by an anonymous `GET` for a `.gsp` path that was not part of the shipped installation. That pair is the entire chain in two lines of logs.
8. **Do not rely on the response code.** Alerting on non-200 responses from the JSON-API will miss this, and alerting on 200 will drown in normal traffic. The useful signal is the `code` field combined with a webroot change.

### Fix Recommendations - a regression test

A single test would have caught both code instances and would catch reintroduction:

```
build an in-memory zip containing exactly one entry named
    "../../<mode>/<rid>/<zipbase>/ver1/../../CANARY.gsp"
call the extractor under test with a destination inside a temporary directory
assert  (a) an IOException is raised mentioning containment, and
        (b) no file named CANARY.gsp exists anywhere outside that temporary directory
repeat for DoorsFilesUploadService and for SimulinkFilesUploadService
repeat with an absolute entry name and with a backslash-separated entry name
```

Assertion (b) matters more than (a): a test that only checks for a thrown exception passes when the exception is raised after the write, which is precisely the behaviour observed in the `.htm` variant during verification.

## 12. CWE and CVSS

### CWE and CVSS - classification

**Primary: CWE-22**, Improper Limitation of a Pathname to a Restricted Directory. The defect is that an externally supplied path component - an archive entry name - is used to construct a filesystem destination without neutralising parent-directory sequences, and the resulting path leaves the intended directory. That is the definition of the weakness and it is located at a single line, `DoorsFilesUploadService.java:78`, with the write at `:84`.

**Contributing, in decreasing order of proximity to the impact:**

- **CWE-94**, Improper Control of Generation of Code. The written file is subsequently compiled and executed because of a suffix mapping to a template-evaluating servlet. The traversal alone would give arbitrary file write; CWE-94 is what makes the outcome code execution.
- **CWE-732**, Incorrect Permission Assignment for a Critical Resource. The webroot is owned by the service account and writable by it, and the content volume is a sibling in the same tree. In the shipped container shape the same weakness appears inverted, as a `VOLUME` mount point created with root ownership, which is the packaging defect that blocks the chain.
- **CWE-693** / **CWE-285**, Protection Mechanism Failure and Improper Authorization. The global filter defaults to allow (`AuthTicketFilter.java:128`) and its single 401 branch does not cover webroot paths, which is what makes the execution step anonymous.
- **CWE-668**, Exposure of Resource to Wrong Sphere. The product's only template ships in the webroot rather than under `WEB-INF`, placing an evaluating suffix mapping on the anonymous surface.
- **CWE-916** / **CWE-522**, Use of Password Hash With Insufficient Computational Effort and Insufficiently Protected Credentials. Unsalted ASCII-MD5 password digests in `database.data`. This is a contributing weakness disclosed for operational completeness and is deliberately **not** folded into the vector, since it is a separate defect with a separate fix and folding it in would inflate a score that is already justified without it.

**Not claimed.** CWE-502 (deserialization) is not part of this finding: nine files in the corpus touch the `readObject` family and none was found to be both reachable and attacker-controllable (section 5.5), although the gadget libraries on the classpath make that a family worth watching. CWE-89, CWE-78 and CWE-917 were all assessed against the corpus and no HTTP-reachable attacker-controlled instance was found in first-party code.

### CWE and CVSS - vector derivation

Published headline vector, recomputed from first principles with CVSS 3.1 round-up (round up to the nearest tenth, i.e. `ceil(x*10)/10`):

```
CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H

ISS            = 1 - ((1 - 0.56) * (1 - 0.56) * (1 - 0.56))
               = 1 - (0.44 * 0.44 * 0.44)
               = 1 - 0.085184
               = 0.914816

Impact (S:U)   = 6.42 * 0.914816
               = 5.87311872

Exploitability = 8.22 * AV(0.85) * AC(0.44) * PR(0.62, Scope Unchanged) * UI(0.85)
               = 8.22 * 0.85 = 6.987
               * 0.44       = 3.07428
               * 0.62       = 1.9060536
               * 0.85       = 1.62014556

Base (S:U)     = min(5.87311872 + 1.62014556, 10)
               = 7.49326428
Roundup        = 7.5
```

Per metric:

| Metric | Value | Weight | Justification from the record |
|---|---|---|---|
| Attack Vector | Network | 0.85 | All three requests travel over TCP to the product's single HTTP listener; no local access, no adjacent-network requirement |
| Attack Complexity | High | 0.44 | See section 12.4. Success depends on the upload tree being writable by the service uid, a condition the attacker neither controls nor can establish from the product. On the only shipped artifact exercised - the official container image used exactly as shipped - it is false, and on the shape where it is believed to hold it was never observed. The traversal itself is not the difficult part: the depth equation is deterministic and derivable from values the attacker controls or is told |
| Privileges Required | Low | 0.62 | Any authenticated principal, and a non-administrator principal (`admin:false`) completed the chain twice. Administrator status is neither required nor helpful: an administrator is refused review creation by default |
| User Interaction | None | 0.85 | The triggering GET is issued by the attacker. No victim needs to click, open or approve anything |
| Scope | Unchanged | - | See section 12.3 |
| Confidentiality | High | 0.56 | Unsalted password digests for every account, the database superuser credential, all integration secrets decryptable via an embedded constant key, all review content |
| Integrity | High | 0.56 | Arbitrary code execution as the service account, plus arbitrary file write across the whole installation tree including application classes, configuration and the database |
| Availability | High | 0.56 | The service account owns the Tomcat tree; application and database files can be deleted or corrupted, terminating service |

One clarification about the recorded figures, so that no reader mistakes a rating decision for an arithmetic one. The vector carried during this analysis was the Attack Complexity Low one, and the figure carried alongside it agrees with that vector's own arithmetic: those metrics do compute to 8.8, and no correction is owed there. What differs in this advisory is which of the two readings is published as the headline, and that is an evidential decision about what was actually demonstrated, argued in section 12.4. The Attack Complexity Low vector is therefore published here in full, labelled as the conditional reading. The rejected Scope-Changed candidate does need an arithmetic correction, and it is given in section 12.5.

### CWE and CVSS - the Scope decision

Scope is **Unchanged**. This was the one genuinely contested metric and the reasoning is set out in full, including the strongest case against.

CVSS 3.1 defines Scope as Changed when an exploit of the vulnerable component affects resources beyond the security scope of that component - that is, when a different security authority's resources come under attack. Four facts decide it here:

| Question | Observation | Points to |
|---|---|---|
| Does execution leave the JVM, the web application or the process? | No. The same JVM, the same ROOT web application, and the same process perform the write and the evaluation, via a mapping in that application's own deployment descriptor | Unchanged |
| Does the operating-system principal change? | No. Before and after, the acting identity is uid 1001, gid 1001, one group, empty capabilities. The command output proves it | Unchanged |
| Are affected resources outside the vulnerable component's own authority? | No. The write lands in a directory the service account already owns, and the execution reads and writes within that account's existing reach | Unchanged |
| Does an anonymous party get to trigger it? | Yes - and that is a fact about *who pulls the trigger*, which CVSS captures in Attack Vector (Network) and User Interaction (None). Scope is not a measure of how weak the triggering party is | Unchanged, already priced |

The strongest argument for Changed is that the chain crosses from a *review-material storage* authority into a *server-side code execution* authority and hands that capability to a party - an anonymous client - that was never granted anything. That is a real crossing of authorization semantics, and it is the same reasoning that earns Scope Changed on some stored-cross-site-scripting findings. It was rejected for two reasons. First and decisively, no resource governed by a *different* security authority is affected: the code executes with the privileges the vulnerable component already holds, over files that component already owns, inside the process that component already is. Second, publishing a Scope-Changed reading here would put a score in the maximum band on a chain whose own evidence says the ceiling is one unprivileged uid - which invites exactly the challenge the evidence would lose.

### CWE and CVSS - the Attack Complexity decision, and the conditional reading

Attack Complexity High is the rating published here, and the argument matters more than most because a reader who has just been shown a complete, working, deterministic chain will reasonably ask why the score is not Low. The answer is not about how hard the traversal is. It is about what was actually exercised, and it is the same asymmetry that section 9 puts in front of the reader.

The CVSS meaning of High is that a successful attack depends on conditions beyond the attacker's control - a rare configuration, a specific race, a state that must be gathered first. The condition this chain depends on is of that kind, and the reason is evidential rather than mechanical: the upload tree must be writable by the service uid, the attacker cannot bring that about through the product, and the one shipped artifact that was actually run does not satisfy it.

What was run is the vendor's official container image, and used exactly as shipped it blocks the chain. The image declares the webserver directory as a `VOLUME` and the installer never creates it, so the container runtime creates the mount point itself, as `drwxr-xr-x 2 root root`, while the service runs as uid 1001. `HtmlBaseFilesUploadService.createUploadContext` line 77 calls `Files.createDirectories(destVersionDir.toPath())` - the first filesystem operation of the whole feature - and it fails with EACCES before any archive entry is read. The JSON-API answers HTTP 200 with a 127-byte `InternalError` whose message is only the destination path, a filesystem-wide search for the marker returns zero hits, and the anonymous GET for the planted path returns 404 with 653 bytes. Section 9.2 tabulates that as the blocked shape, and the negative controls in section 9.7 are what make it an observation rather than an assumption.

The shape in which the chain does work is the native, non-container install, and that shape was never verified. The vendor's native installer was never run on a real host. The claim that a native install leaves the webserver directory owned by the service account is a structural inference from the shipped archive, resting on three observations: the installer archive contains no `chown` at all and its two directory-creating classes change no ownership; the product necessarily creates that tree itself; and a comparable runtime directory in the same image, `collaborator-content-cache`, was observed to be created by the product as `1001:1001` after startup on an unmodified artifact. That is a strong argument and it is not a measurement. To rate exploitability Low on the strength of an installer that was never run would be to let the headline rest on the one deployment shape that was never tested, while the shape that was tested forbids the chain. High is the honest rating here and not a pessimistic one: the chain is complete and deterministic wherever the precondition holds, the severity band does not move, and the metric says only that the precondition was not demonstrated on a shipped artifact used as shipped.

The Low argument is nevertheless real, and it is preserved here in full as the justification for the conditional reading. It runs like this. The product creates the destination tree itself, on the line before it reads the first archive entry, so `<webserver>/<mode>/<reviewId>/<zipName>/ver<N>` exists as a service-account directory on every successful upload. Therefore **the precondition is implied by the usability of the attacked feature**: any installation in which DOORS review-file upload can return success is an installation in which that tree is already writable by uid 1001, there is no state to gather, no race to win and no unusual setting to hope for, and an attacker who can call `addDoorsFiles` and get anything other than a permission-derived `InternalError` is already in the exploitable shape. That is Low by the specification's own meaning, in the shapes where it applies. It is not the headline because those shapes were argued from the archive rather than run.

This is also why the blocked shape is not handled as an Environmental metric adjustment, and why it is not hidden in a footnote either. Environmental describes the scorer's own deployment and would leave the base score looking unconditional; the question here is which installation shapes permit a shipped feature to be used at all, which belongs in the base metric with a labelled conditional reading published beside it and the blocked shape stated prominently in sections 1, 9 and 10.

Accordingly, one conditional reading is published and labelled as conditional. It applies to installations in which the upload tree is writable by the service uid - the native install shape, and any container deployment where that volume was created with service-account ownership or chowned during deployment automation:

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

Exploitability = 8.22 * 0.85 * 0.77 * 0.62 * 0.85 = 2.83525473
Impact (S:U)   = 5.87311872
Base           = min(8.70837345, 10) = 8.70837345
Roundup        = 8.8
```

That conditional reading scores 8.8, still High. It is not the headline, and the headline is 7.5. An operator who wants a single number for a fleet of mixed shapes should note that the two readings differ only inside one severity band: both say High, and neither says this is remotely exploitable without an account. What they actually separate is a triage question the operator can answer directly, by checking the ownership of the directory named by the `content-webserver` context parameter - default `collaborator-webserver` - relative to the Tomcat working directory, and by checking whether that path is a runtime-created mount point.

### CWE and CVSS - the rejected Scope-Changed candidate, corrected

A Scope-Changed reading of this chain - `PR:L` with `S:C` and all three impact metrics High - was carried as a candidate during the analysis and is rejected on the merits set out in section 12.3. Recomputing it for the record, the CVSS 3.1 Scope-Changed impact term gives:

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

Impact (S:C)   = 7.52 * (0.914816 - 0.029) - 3.25 * ((0.914816 * 0.9731) - 0.02) ** 13
               = 6.66133 - 0.53368 = 6.12766
Exploitability = 8.22 * 0.85 * 0.77 * PR(0.68, Scope Changed) * 0.85 = 3.10963
Base (S:C)     = min(1.08 * (6.12766 + 3.10963), 10) = 9.97627
Roundup        = 10.0
```

That reading computes to 10.0 under CVSS 3.1, and we do not publish it.

A correction is due, and publishing it is the point of showing the arithmetic. The Scope-Changed figure recorded during this analysis was 9.9, and 9.9 is not what those metrics give under CVSS 3.1. It is what they give under the CVSS 3.0 Scope-Changed impact formula, whose polynomial term is `(ISS - 0.02)` raised to the 15th power; the 3.1 formula uses `(ISS * 0.9731 - 0.02)` raised to the 13th power. The two agree on every famous vector in this band - both cap `PR:N` with `S:C` at the maximum and both give 9.1 for `PR:H` with `S:C` - and they diverge only on `PR:L` with `S:C` and all-High impact. Applying the 3.0 term here gives 9.89013, which rounds up to 9.9; the 3.1 term gives 9.97627, which rounds up to 10.0. Anyone re-deriving a Scope-Changed score for this class of finding should check which formula their tool implements.

### CWE and CVSS - what is deliberately not published

- **No unauthenticated score.** An anonymous route to an administrator session exists (section 10.3) but holds only on a never-initialised instance, was tested twice and found idempotent and harmless - it neither wipes the database nor resets a changed administrator password - so it cannot support an unauthenticated reading of *this* finding. No `PR:N` vector is printed anywhere in this advisory, because printing one next to a chain whose published headline scores 7.5 would be an invitation to misread it.
- **No root or system-privilege claim**, in the score, the title, the directory name or the prose. The ceiling is uid 1001.
- **No folding of the contributing weaknesses into the vector.** Unsalted password hashing, the embedded constant encryption key, the fail-open global filter, the world-readable static-content traversal, the absence of privilege separation and the missing per-object authorisation on review writes are each real and each disclosed. None of them raises this vector's metrics, and none is used to raise them.
- **No cross-version or cross-edition score.** One build was tested.
- **No claim that the blocked shape is a defence.** Section 9.2 is explicit that the pristine-image block is a packaging artefact that the vendor is separately advised to fix, and fixing it does not make the product safer against this defect; it changes which installations happen to fail on permissions, and it would widen rather than narrow the exposed population. That is a separate question from the rating. The block is not treated as a product defence, but it is treated as evidence, and it is the reason the published headline carries Attack Complexity High with the Low reading published beside it as a labelled conditional - section 12.4.
- **No inflation from the sibling implementation.** Two code instances of one root cause are reported as one finding.

### CWE and CVSS - summary

| Item | Published value |
|---|---|
| Vector | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Score | 7.5 (High) |
| Arithmetic | Impact 5.87311872 plus Exploitability 1.62014556 equals 7.49326428, rounded up to 7.5 |
| Conditional reading | 8.8 (High) with Attack Complexity Low on `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, for installations where the upload tree is writable by the service uid; Low is argued there because the product creates the destination tree itself on the line before the first archive entry is read |
| Rejected reading | Scope Changed, which computes to 10.0 under CVSS 3.1 and to the 9.9 recorded during analysis under the CVSS 3.0 formula |
| Primary weakness | CWE-22 |
| Contributing weaknesses | CWE-94, CWE-732, CWE-693, CWE-668, CWE-916 |
| Privilege outcome | OS command execution as uid 1001 (`collab`), a non-privileged service account; no root |
| Authentication outcome | Post-authentication, any authenticated principal including a non-administrator |
| Deployment condition | Upload tree writable by the service uid; blocked in the pristine official container image, which is the only shipped artifact that was exercised, and argued rather than observed in the native install shape |

---

Maintained by the 0day Rubbish Research Team.
Contact: disclosure@0day-rubbish.com
Advisory: https://0day-rubbish.com/blog/smartbear-collaborator-doors-upload-zip-slip-webroot-gsp-rce
