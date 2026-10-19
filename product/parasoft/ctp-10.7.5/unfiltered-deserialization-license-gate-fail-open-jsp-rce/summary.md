# Parasoft Continuous Testing Platform 10.7.5-SNAPSHOT - Unfiltered Java Deserialization in the Database Restore Path Behind a Raw-URI License Gate Bypass and a Fail-Open Authentication Gate, Reaching Anonymous JSP Command Execution (CWE-502, CWE-436)

Advisory: https://0day-rubbish.com/blog/parasoft-ctp-unfiltered-deserialization-license-gate-fail-open-jsp-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Parasoft Continuous Testing Platform (CTP) from Parasoft (United States) is a service-virtualisation,
test-data-management and environment-management product whose `em` web application runs on Tomcat 10.1.57
inside the vendor's own container image. Three first-party defects compose into an unauthenticated
command-execution chain that needs two HTTP requests and nothing else. The first is an interpretation
conflict in the licensing filter: `EMLicenseFilter` decides whether to run at all by testing the raw,
un-normalised `request.getRequestURI()` against exemption clauses such as `endsWith("welcome")` that carry
no path-separator anchoring, and `isLicenseRequired()` has exactly one caller - `shouldNotFilter()` - so a
matching URI disables the entire filter, including its own unlicensed-instance redirect. Because the servlet
container strips `;`-delimited path parameters before it performs servlet mapping, a request target of
`/em/database/restore;welcome` is exempted by the filter and still routed to the restore handler by the
container. The second defect is what the handler does with the upload: `AbstractDatabaseBackup` wraps the
`database.ser` member of the submitted zip in `new ObjectInputStream(in)` and calls `readObject()` on it with
no `ObjectInputFilter` - and no instance of `ObjectInputFilter`, `jdk.serialFilter` or `serialFilter` exists
anywhere in the shipped product, against a positive control of 81 files containing `readObject`. The third is
the reason an anonymous client is allowed to reach either of them: the platform's three Spring Security chains
all register one remember-me service, and that service, when no external security provider has been
configured, returns an already-authenticated `admin` principal carrying `ROLE_ADMIN` for a request that
presented no credential of any kind. A `HashSet` carrying a `TiedMapEntry` over a `LazyMap` whose factory is
a `ConstantTransformer` holding attacker bytes, backed by aspectjweaver's `SimpleCache$StoreableCachingMap`,
then turns `readObject()` into an arbitrary-path arbitrary-content file write - the `folder` field, the map
key and the byte array are all stream-controlled and none is validated - and the chosen landing spot is
`webapps/em/images/<leaf>.jsp`, a directory the same unanchored filter exempts and which the product's own
`conf/web.xml` maps to the Jasper `*.jsp` servlet. One anonymous `GET` afterwards makes Tomcat compile and
execute the written page; the recorded runs returned `200` with a body containing the run marker
`RCE_OK <nonce>`, the server-evaluated arithmetic `JSP_EVAL=42` for the expression `6*7` (so this is
evaluation, not source echo), `/etc/passwd` content read by the product process, and
`uid=1000(parasoft) gid=1000(parasoft) groups=1000(parasoft)`, while a request for a never-written file in the
same directory returned `404` with the `Apache Tomcat/10.1.57` error page. The chain involves no memory
corruption, no vendor-supplied credential, no licence installation or forgery, no outbound connection, no DNS
or RMI callback, no cross-version payload adaptation and no privilege escalation: the upstream libraries that
carry the gadget are carriers and not the root cause, executing a `.jsp` is the product's own configuration,
and the landing identity is the product's unprivileged service account rather than root.

- **Component**: the `em` web application inside the vendor container image - HTTP on container port 8080 and
  HTTPS on 8443 (both mapped to loopback-only host ports by the testbed, which is a harness choice and not a
  product restriction), ten `/*` servlet filters in `conf/web.xml`, four servlet mappings (`/` to the Spring
  `DispatcherServlet`, `/api/*` to a Jersey `RestServletContainer`, `/tdm/api/*` to `TDMApiServletContainer`,
  `/services/*` to CXF), the `EMLicenseFilter`, the three Spring Security filter chains sharing
  `EMRememberMeServices`, and `EMDatabaseController` (1359 lines) with `AbstractDatabaseBackup` (518 lines)
  behind its `restore` mapping
- **Sink**: `ObjectInputStream.readObject()` at `AbstractDatabaseBackup.java:117` (runtime stack line 114),
  reached from `POST /em/database/restore` and preceded by `new ObjectInputStream(in)` at line 111 and
  `readInt()` at line 112; the write itself is
  `SimpleCache$StoreableCachingMap.writeToPath(folder + File.separator + key, bytes)`; the execution sink is
  the Jasper `*.jsp` servlet mapping declared at `conf/web.xml:274-275` and `448-450`, which compiled the
  dropped page into `work/Catalina/localhost/em/org/apache/jsp/images/<stem>_jsp.java` and `.class`
- **Source**: the `backup` part of an anonymous `multipart/form-data` POST - a zip whose member names are
  hard-compared against the literals `version.txt` and `database.ser` but whose `database.ser` content is
  entirely attacker-chosen and becomes the byte stream handed to `readObject()`; the `json` part is also
  attacker-controlled and is used only to point the connection parameters at a port that refuses
- **Sanitization**: none on the reachable path. The deserialisation has no `ObjectInputFilter`, no allow-list
  and no signature or provenance check on the submitted backup; the write primitive performs no
  `Path.normalize()`, no `File.getName()`, no `getCanonicalPath()`, no `startsWith()` prefix check and no
  forced file extension (0 hits for any of them in `writeToPath`); the license gate performs no
  normalisation and anchors nothing; and the remember-me gate that supplies the principal performs no
  credential check at all when no external provider is configured

## CVSS Score

- **Score**: 9.8 Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) - two anonymous HTTP requests
  against a network listener yield arbitrary operating-system command execution inside the product process,
  with no credential, no race, no outbound dependency and no licence state to satisfy
- **Attack Vector: Network** - the product serves the chain over ordinary TCP HTTP and HTTPS from listeners
  that accept connections from outside the container (the HTTPS listener was separately retested on the
  license-gate leg, `200` with the bypass and `302` to `/em/license` without it), and the product ships no
  reverse proxy, WAF or management-plane separation in front of `em`. The loopback-only publication of the
  test port was our harness's choice; no step of the chain was driven from a second network host, so the
  network reach is argued from the shipped listener topology rather than demonstrated between two machines
- **Attack Complexity: Low** - the chain is one multipart POST plus one GET. There is no timing window to win
  (this is the steady factory state, not a first-run race), no host-specific information to gather, no
  memory-layout condition, no database reachability requirement (`readObject()` at line 117 runs before
  `getConnection()` at line 126), no outbound callback and no cryptographic work; the only condition is a
  deployment state that the vendor's own image is in when no external security provider has been configured
- **Privileges Required: None** - no credential belonging to anybody is supplied or consumed. The
  authenticated subject that `CTPSecurityWebConfig.java:283` demands for `/database` is manufactured by the
  product itself: `EMRememberMeServices.java:148` returns `createAuthenticationToken("admin", "admin",
  EmUserInfo.Role.ADMIN, request)` when `PSTSecServiceClient.getInstance()` is null, and the resulting
  principal carries `ROLE_ADMIN` and is not the anonymous principal. An anonymous
  `GET /em/api/v3/users/current` returned `200` with `{"id":1,"login":"admin","role":"ADMIN"}` while the same
  request with `Authorization: Bearer garbage` returned `401`
- **User Interaction: None** - no administrator action, browser session, induced click or uploaded-by-a-human
  step exists anywhere in the chain
- **Impact C/I/A: all High** - command execution as the product process identity yields every environment
  definition, virtual-service definition and test-data record the platform manages, the HSQLDB database
  reachable from that process, and whatever else uid 1000 can read on the host filesystem (recorded runs read
  `/etc/passwd`); integrity is High because the primitive is an arbitrary-path arbitrary-content write before
  any command is run, which reaches configuration, the database file and the deployed web application;
  availability is High because arbitrary code inside the JVM can destroy or stop the platform's own data and
  service. The rating does not depend on the identity being root, which it is not
- **Scope**: Unchanged. The vulnerable component and the impacted component are one product in one JVM: the
  filter, the deserialising controller and the Jasper mapping that executes the written page all belong to the
  same application, and the executed command runs with the product process's own uid in the product's own
  filesystem view, so no different security authority is crossed. Changed was considered and rejected; its
  variant `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` computes to 10.0 (ISS 0.914816, Impact for Scope
  Changed 6.128026, Exploitability 3.887043, 1.08 times 10.015069 capped at the maximum) and is not published
  as this finding's score
- **CWE**: CWE-502 primary; CWE-436 co-equal; CWE-863 and CWE-287 contributing for the authorisation and
  authentication gates; CWE-321 and CWE-347 reported separately for the literal session-cookie signing key and
  its keyless signature scheme; CWE-22 reported separately for a sibling file-path primitive that is not part
  of this chain. None of the contributing items raises any metric of the published vector
- **Recorded score**: the research notes behind this advisory recorded `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  at 9.8. That figure was not inherited: it was recomputed from the vector with the CVSS 3.1 base formula -
  ISS 0.914816, Impact for Scope Unchanged 5.873119, Exploitability 3.887043, base 9.760161, rounded up to the
  nearest tenth - and the recorded value is correct, so the published score equals the recomputed one
- **Conditional reading A - external security provider configured, attacker holds a low-privilege account**:
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High (Exploitability 2.835255, base 8.708373). Where an
  operator has configured the external identity source, the fail-open branch that mints the anonymous `admin`
  principal no longer applies and both hops need a genuine authenticated subject; any authenticated subject
  satisfies the `authenticated()` matcher, so low privileges suffice. Labelled conditional on a deployment
  state we did not detonate against
- **Conditional reading B - external security provider configured, subject supplied by an offline-forged
  session cookie**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical. This reading is a static and
  structural inference and was **not verified**: the platform signs its remember-me cookie (`PST_LT_FEATURES_INFORMATION`) with a
  key that is a compile-time string literal (`"rememberMeAuthenticated"`) using bcrypt, which carries no
  secret, so a forgery is computable offline; forgery was only exercised in the unconfigured state where it is redundant,
  the combination "provider configured and the chain fired with a forged subject" was never dynamically
  tested, and building a fake security provider to test it was deliberately abandoned because it would have
  manufactured the evidence. It is published so an operator of a configured deployment knows the exposure to
  check, never as a demonstrated capability and never as the headline score
- **Conditional reading C - listeners reachable only from a management network**:
  `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.8 High (Exploitability 8.22 times 0.62 times 0.77 times
  0.85 times 0.85 = 2.835255, Impact 5.873119, base 8.708373). Applies where an operator fronts the platform
  with a firewall or places it on a segregated management segment. Labelled conditional on a deployment change
  we did not test

## Affected Products

- Parasoft Continuous Testing Platform (CTP) from Parasoft (United States), a closed-source commercial
  continuous-testing product bundling environment management, service virtualisation and test-data
  management. Affected component: the `em` web application - specifically the database restore path, the
  licence filter, the remember-me authentication service and the deployed `images` directory that Jasper
  compiles
- Verified build: the artefact self-identifies as version `10.7.5-SNAPSHOT` with `Build-Timestamp
  202608231700 +0000` and a buildId of the form `ctp<nightly stamp>-1000` (the nightly stamp is the date
  component of the Build-Timestamp; advisory text in this repository does not carry dates, so the value is
  described rather than printed here and is given to the vendor verbatim in the notification). First-party
  `com.parasoft.xtest.*` artefacts in the same image are stamped `10.7.4.20260808`, and 238 jars are present
  of which 42 are first-party `com.parasoft.*`
- What a `-SNAPSHOT` version means for this claim: in the Maven convention the product's own build system
  uses, `-SNAPSHOT` marks a build taken from an in-progress development line rather than an immutable
  released artefact, and it was obtained through the vendor's mutable `parasoft/ctp:latest` container tag
  (image id prefix `f99f7210fc67`, loaded from a saved 997,805,056-byte copy whose md5 is
  `47946c7d1e7d99a00d6c90f4ae675f90`). The affected-version claim is therefore stated as: this build is
  affected, and any other build that ships the same `AbstractDatabaseBackup` and `EMLicenseFilter` source
  carries the same construction. It is deliberately not stated as "all 10.x releases are affected"
- The vendor's public release naming for this train is CTP 2026.1.x. The vendor's own published release notes
  for that train enumerate security fixes exclusively as "resolved by updating" a third-party library, with no
  first-party security entry - documentation-level evidence that this root cause is not addressed there. This
  is not a measured claim: only one CTP build was available to execute, no second build or older release was
  obtained, and no cross-version detonation was performed
- Runtime stack of the verified build: Java 17 (`17.0.20.1`), Tomcat 10.1.57 with the Jasper JSP engine
  enabled, Jersey 3.1.12 with `jersey-mvc-freemarker`, Spring 6.2.19 and Spring Security 6.5.11, CXF 4.1.8,
  HSQLDB 2.7.4, FreeMarker 2.3.34, nashorn-core 15.7, aspectjweaver 1.9.25.1 and commons-collections4 4.5.0;
  a first-party JNI library `libxtest.so` (154,608 bytes for five platforms) is loaded by the licensing
  subsystem
- Only this build was tested. Windows-side variants of the same product line, the sibling `dtp` distribution
  (whose first-party jar set does not include `com.parasoft.ctp.core`, so it is not claimed here), earlier and
  later releases and any installation whose operator has altered the security configuration are outside the
  measured claim
- Verification method and its boundary: live black-box HTTP verification against a running instance started
  from the unmodified vendor image in an isolated container sandbox, with no setup step performed, plus
  source-level reading of the decompiled first-party classes and of the shipped `conf/web.xml` and
  `webapps/em/WEB-INF/web.xml`. It is not an emulation and not a protocol replica. No step of the chain was
  driven from a separate network host: the container ports were published to loopback on the sandbox host, so
  reach from another machine is argued from the listener topology rather than demonstrated
- Privilege ceiling: arbitrary command execution as `uid=1000(parasoft)` - the product's own unprivileged
  service account, confirmed both by `id` inside the executed page and by `/proc/1/status` of the product
  process (`Uid: 1000 1000 1000 1000`), and by the image running as user 1000. **Not reached and not
  claimed**: root, any privilege escalation, container escape, cross-host movement and any memory-corruption
  primitive

## Impact

- Unauthenticated remote code execution inside the product process from two ordinary HTTP requests, on a
  platform whose documented entry point for the same function is an administrator menu behind authentication
  and a valid licence
- Arbitrary file write to an arbitrary absolute path with arbitrary bytes, as a primitive in its own right
  before any command is executed: the `folder` field, the map key (which was observed to accept both
  `a/b/c.jsp` and `../../../x.jsp` forms) and the content array are all inside the serialised stream, and the
  only content restriction found is that the bytes must not be exactly the four-byte sequence `IDEM`
- Read access to everything the platform manages and everything uid 1000 can read on the host: environment
  and system definitions, virtual-service definitions, test-data-management records, the HSQLDB database
  files, configuration and any secret material stored through the product
- Persistence that survives naive cleanup: the recorded forensic re-fetch showed that after the dropped page
  and both of its Jasper compilation artefacts were deleted, the same URL still returned `200` because the
  compiled servlet instance stays loaded in the running JVM. Reliable removal requires a context reload or a
  JVM/container restart, and a defender who only deletes the file has not removed the web shell
- Integrity control of the product's own configuration and data plane from inside the process, including the
  ability to re-arm the licence and authentication state that the gates rely on
- Availability impact at will: arbitrary code in the JVM can stop the service, destroy the managed database or
  consume its resources; the arbitrary-path write alone permits filling a filesystem as a standalone
  primitive
- Weak detection by construction: hop 1 is a documented administrative function returning an ordinary `500`
  with the product's own "error occurred while applying changes to the database configuration" message, and
  hop 2 is an anonymous GET for a file under a static-assets path. The strongest indicators are a request
  target containing `;`, a `.jsp` file appearing under `webapps/em/images/`, and a product log line pairing
  `AbstractDatabaseBackup.restore` with `class java.util.HashSet cannot be cast to class ...TableMetadata`
- Amplifiers reported to the vendor separately and not folded into the score: the fail-open remember-me branch
  that issues an `admin` principal with no credential (CWE-287) and an authentication provider that does not
  verify the supplied password; the generic licence-gate bypass, which additionally exposes all of
  `/em/database/**` and the whole `/em/tdm/api/v*` tree anonymously; anonymous whole-database download and
  anonymous backup creation through `/em/api/v2/database/backups` and `/em/api/v3/database/backups`; anonymous
  arbitrary file read and arbitrary file delete through a temp-file handler that concatenates a query
  parameter into a path; and 28 hardcoded secret values of which 17 participate in security decisions,
  including a shipped TLS keystore whose store password is the industry default `changeit` and appears in
  plaintext in `server.xml`, three hardcoded AES-128 keys whose IV equals the key, and a literal Blowfish
  argument used to decode licence features

## Mitigation

1. **Filter the deserialisation, and fix all three sites** - install an `ObjectInputFilter` allow-list on the
   `ObjectInputStream` in `AbstractDatabaseBackup` covering line 117 and the two sibling call sites in
   `drainRows` and `bindAndExecuteRows`, permitting only the backup metadata classes the format actually
   needs. Better still, retire Java native serialisation for backups in favour of a schema-bearing format
   (protobuf, or JSON with explicit DTOs) so that no field in the file can name a class
2. **Make the licence gate decide on the mapped path, not the raw URI** - strip path parameters and resolve
   the request against the container's normalised servlet path (or the mapping result) before testing it,
   replace every unanchored `endsWith("welcome")` / `endsWith("about")` / `endsWith("notlicensed")` with a
   separator-anchored or exact match, and change the `Accept: application/json` branch that reassigns the
   exemption set with `=` so that it accumulates with `|=` instead of silently replacing the static list
3. **Remove the dead status write** - the filter flushes the response output stream and then calls
   `setStatus(403)`, so the status the client sees is `200` while the body says the platform is unlicensed.
   Either set the status before flushing or remove the unreachable write, so licence failures are visible to
   logs and monitoring
4. **Fail closed in the remember-me service** - when no external security provider is configured, an anonymous
   request must not receive an authenticated `admin` principal. Return no authentication (leaving the request
   anonymous, which the existing `.authenticated()` matchers already reject) or refuse the request, and emit a
   startup warning that the platform is serving administrative endpoints without an identity source
5. **Stop signing sessions with a compile-time literal and a keyless digest** - the remember-me signing key is
   the string `"rememberMeAuthenticated"` baked into the class file and the signature scheme is bcrypt, which
   carries no secret, so any party that reads the shipped class can mint a session. Replace it with an HMAC
   over a per-deployment random secret generated at install time and stored outside the image
6. **Constrain the restore surface** - accept only backups the server itself produced (signed, or verified
   against a server-side record), require an authenticated administrative principal plus an audit log entry,
   and reject zip members whose names are not exactly the two expected literals before any stream is opened
7. **Take JSP compilation out of the runtime** - precompile the application's own pages and disable
   development-mode compilation, or serve `/images/**` from a location that is not part of a JSP-mapped web
   application root. A static-asset directory that the container will compile and execute on request is an
   execution surface waiting for a write primitive, and it is what turned this write into code execution
8. **Fix the sibling path-handling defect** - the temp-file handler builds `new File(tempDir, fileID)` from a
   query parameter with no `FilenameUtils.getName()` or canonicalisation, which is what makes anonymous
   traversal reads and deletes possible; canonicalise, confine to the temp root and reject separators
9. **Rotate and stop shipping shared secrets** - generate a per-instance TLS keystore at install instead of
   shipping one with password `changeit`, derive encryption keys from a deployment secret rather than
   compiling them in, and never use the key as the IV
10. **Operator measures until a patch exists** - reject any request target containing `;` at the reverse proxy
    or WAF in front of the platform (which closes the `;welcome`, `;about` and `;notlicensed` exemptions at
    once, and needs regression testing of legitimate matrix-parameter use), restrict `/em/database/**` to named
    management addresses, configure the external security provider so the fail-open branch cannot apply,
    monitor `webapps/em/images/` for any file that is not a static asset, alert on the
    `HashSet cannot be cast to ...TableMetadata` log signature, and treat the removal of a dropped page as
    incomplete without a context reload or restart
11. **Add a regression test that pins the interpretation conflict** - assert that a request for
    `/em/database/currentConfig;welcome` and one for `/em/database/currentConfig` produce the *same* licensing
    decision, that a request whose path merely ends with `welcome` but is not the welcome page is not exempt,
    and that deserialising a `java.util.HashSet` where backup metadata is expected fails with a filtered-class
    rejection rather than a `ClassCastException`

## References

- https://0day-rubbish.com/blog/parasoft-ctp-unfiltered-deserialization-license-gate-fail-open-jsp-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
