# NUUO Crystal Server 3.19.0.85 — Unauthenticated PHP Web-Root Upload through the Bare copy() Endpoint in upload.php (web-side remote code execution as the product's PHP service account; appliance-side runtime identity not observed and not claimed)

## 1. Overview

### Overview of the finding

NUUO Crystal Server 3.19.0.85 from NUUO Inc. of Taipei, Taiwan is the vendor's flagship video management and
NVR server product, distributed as the Crystal virtual-machine appliance: an Ubuntu-based OVA whose web tier
is a lighttpd server fronting a PHP application, with .php requests dispatched to /usr/bin/php-cgi through
lighttpd's fastcgi mapping. The product sits in the management plane of physical-security and
critical-infrastructure video deployments, which makes its web surface a high-value target: it brokers
camera registration, recorder channels, and the management credentials of the surveillance network.

The finding is almost embarrassingly simple, and that simplicity is the point. Inside the web root that we
recovered from the appliance disk image, upload.php is three lines long:

```php
<?php
echo $_FILES['userfile']['name'];
copy($_FILES["userfile"]["tmp_name"],$_FILES['userfile']['name']);
?>
```

The handler echoes the client-supplied filename and calls copy() with a destination taken from that same
client-supplied filename. There is no session include, no login check, no extension denylist, no MIME
inspection, no path canonicalisation, and no storage directory of the product's own choosing. The web
server configuration recovered from the same disk image loads no authentication module at all - not in the
module list, not as a backend, not as a per-URL denial - because this product's architecture delegates
authentication to each PHP file individually (an include of utils.php plus a session validity check), and
upload.php is one of the files that never asks.

The chain that follows is the canonical form of the unauthenticated file-write primitive: an anonymous
multipart POST places a PHP payload file with an attacker-chosen destination name into the served
document root, and a single GET of that file makes the product's own fastcgi mapping execute it as PHP.
Both the write and the execution were confirmed to behave this way on a faithful replica built from the
appliance's own extracted web root and configuration semantics; three independent runs produced an
execution marker plus command output, a no-upload negative control produced nothing, and an
absolute-destination variant landed and executed identically. What this work did not obtain is a runtime
observation of a physical Crystal VM - no network path to the appliance was available during the study -
so the identity of the account that executes uploaded PHP on a shipped appliance was not measured, is not
claimed anywhere in this advisory, and does not determine the score: the rating rests on unauthenticated
server-side code execution and the accompanying arbitrary file write, whatever account the PHP service
turns out to run as.

### Overview of the source artifacts and the prior-record position

The appliance disk image is the anchor for every static claim. The Crystal VM ships as an OVA with a
stream-optimised 2 GB VMDK; converting it to a raw image showed that the boot partition's ext superblocks
(primary and backup) were zeroed, so the filesystem was recovered by carving: the raw image contains five
sequentially laid-out gzip-compressed squashfs 4.0 regions, and the region containing the PHP web root
(653 inodes, 575 files, about 1.7 MB) extracted cleanly and yielded the complete application, including
the byte-exact upload.php quoted above. The lighttpd configuration was recovered from the same raw image
by content search and read in full. Because these are shipped-product artifacts - not our lab state - the
"no authentication on this endpoint" claim of this advisory is artifact-anchored rather than
environment-anchored.

We also checked the public record before drafting, along four axes: vendor, vendor plus product,
product, and endpoint name. The vendor axis returns a rich history - this vendor's recorder lines have
carried a long record of unauthenticated web problems, including a known arbitrary file upload in the
same upload.php endpoint pattern recorded in the NVRmini lineage during 2018, and an older
2016-era record that lists a then-current product generation under the Crystal name for a different
endpoint (a daylight-saving handler that has since been removed from the shipped web root). Recent
records for the vendor's other product lines name different PHP endpoints - an import privilege handler
and an unrelated upload-style read - but none of the records returned by any axis names the Crystal
Server appliance line generations under test here, and none names upload.php on the Crystal Server line.
The precise statement this advisory makes is therefore: the public record contains no entry whose root
cause is an unauthenticated upload.php file write in the Crystal Server line, and the same endpoint
pattern has carried an arbitrary-file-upload record in the vendor's NVRmini lineage. Per this project's
citing discipline, no neighbouring record identifiers are listed here, because none of them is this
finding.

## 2. Vulnerability Summary

The defect is a stack of three independent omissions in one three-line handler, each of which is
individually sufficient to make the write dangerous and jointly sufficient to make it an execution
primitive:

1. Missing authentication for a critical function (CWE-306). The endpoint performs no session include and
   no login check. The shipped server configuration provides none either, as section 3 establishes from
   the config artifact. Any network client can call this handler.
2. Unrestricted upload with no type restriction (CWE-434). Nothing inspects the uploaded body's
   extension, content type or content, and nothing about the storage location keeps the file out of the
   executable path mapping: the .php suffix the attacker chooses is exactly the suffix the fastcgi
   mapping executes.
3. External control of the destination file name or path (CWE-73). The second argument of copy() is the
   raw client-supplied filename from the multipart disposition, which may be a plain relative name, and
   therefore land in the interpreter's working directory - the document root - or an absolute path,
   which lands wherever the attacker specifies regardless of any working directory.

The exploit does not require the three omissions to interact in a subtle way. Omission 2 plus omission 3
turn one POST into an arbitrary write into the served tree; omission 1 makes it anonymous; the product's
own fastcgi mapping converts the written file into code execution on the next GET. There is no parser
abuse, no encoding trick and no race anywhere in the chain.

## 3. Authentication Boundary

The authentication model of this product is per-file, not per-server, and that is the boundary the finding
lives on.

The shipped lighttpd configuration, recovered from the appliance disk image, declares its module list
explicitly:

```
server.modules = ( "mod_alias", "mod_fastcgi", "mod_cgi" )
server.document-root = "/NU20/web/vsphere/"
static-file.exclude-extensions = ( ".php", ".pl", ".fcgi" )
fastcgi.server = ( ".php" => ( "localhost" =>
                   ( "socket" => "/var/run/lighttpd/php-fastcgi.socket",
                     "bin-path" => "/usr/bin/php-cgi" ) ) )
$SERVER["socket"] == ":443" {
   server.document-root = "/NU20/web/"
   ssl.engine = "enable"
}
```

No authentication module appears in the module list. A content search of the recovered configuration for
an authentication backend declaration, an authentication module reference, a valid-user requirement and an
access-denial rule returns zero hits for all four patterns. The HTTPS listener binds :443 with the shared
document root /NU20/web/ and no per-address restriction. In other words, the server layer offers no gate
whatsoever; the gate, where it exists at all, is one include statement inside each PHP file. The recovered
web root demonstrates both halves of that convention: the session-protecting include (utils.php with its
session validity check) appears across the application's authenticated handlers, and upload.php carries
neither the include nor any check of its own. The authentication boundary of this product is therefore
exactly as strong as its most forgettable file, and upload.php is that file.

The boundary claim is deliberately conservative: we do not claim every other handler in the web root is
unauthenticated, and we did not enumerate them here; we claim only that this handler is - which the
byte-exact source plus the absent server-layer gate together establish.

## 4. Attack Surface

### Surface inventory

The web service reachable on the appliance is layer one of the surface: lighttpd on the standard ports
with the HTTPS listener on :443, serving a 575-file PHP application out of /NU20/web/ (with an
HTTP-vhost sibling under /NU20/web/vsphere/), and dispatching two CGI binaries under /cgi-bin/ per the
recovered alias configuration. The PHP layer is where this finding lives; the CGI layer was not part of
this study.

The recovered web root also exhibits the vendor's patching history directly, which is a surface fact worth
recording: the debugging-centre handler that carried a 2016-era command-execution record in this vendor's
recorder lines is absent from the shipped Crystal web root - the vendor removed it - while upload.php,
whose sibling-line architecturally identical pattern carried the 2018-era arbitrary-upload record, is
present with its full original behaviour. The surface today is what selective patching left behind, and
what it left behind includes a three-line anonymous file-write endpoint.

### Why this surface is reachable

Every prerequisite of the chain is a shipped default, established from artifacts rather than from our lab:

- the endpoint exists in the shipped web root (squashfs extraction, byte-exact);
- the endpoint requires no authentication (absent include plus absent server-layer gate, both artifacts);
- the uploaded file's destination is client-controlled (the copy() second argument is the multipart
  filename, from the endpoint source);
- the destination directory is served and executable (the document root and fastcgi mapping, both from
  the recovered configuration);
- the listener accepts connections from any address (no bind restriction in the recovered configuration).

None of these claims depends on a setting we changed, a debugging flag we enabled, or a state our own
instance happened to be in.

## 5. Sink Identification

The execution sink is not in the vulnerable file at all - it is the product's own script mapping. When a
request arrives for a path under the document root whose suffix is .php, the recovered lighttpd
configuration routes the request to the fastcgi handler bound to /usr/bin/php-cgi, and that mapping is the
mechanism that converts the file-write primitive into code execution, and it is important to the honesty
of this advisory that the mapping is the product's, not ours: it is in the recovered configuration, and it
is the documented manner in which every page of this application runs.

The write sink inside upload.php is copy(), reached with two arguments both under partial client control:
the first argument is the temporary path of the uploaded body (the standard PHP upload mechanism
populates it once the multipart body is accepted) and the second argument is the raw client filename
from the multipart disposition. copy() performs no filtering of its own; it writes the payload bytes to
the destination path with the destination name, inside the directory that the interpreter's working
directory or an absolute destination specifies. The handler also echoes the filename back, which is a
free oracle: the write confirmation arrives in the body of the 200 response, so the attacker does not
need blind probing to know the endpoint accepted the file.

## 6. Source Identification

The source is the multipart/form-data body of an unauthenticated POST to /upload.php, and specifically
two of its client-controlled parts:

- the file content part named userfile, whose bytes become the written file - in the exploit, a short PHP
  program that prints a marker and the output of one command through the shell-execution built-in;
- the filename parameter of that part's disposition, whose value becomes both the echo response and the
  copy() destination. The value is used verbatim: as a bearer of a .php suffix, as the relative name that
  resolves against the interpreter working directory, or as an absolute path such as
  /NU20/web/abs_marker.php that lands wherever it says regardless of any working directory.

No other request data enters the vulnerable decision. No header, cookie, or parameter beyond the
multipart disposition affects the destination, and nothing in the handler consults session state, because
there is none to consult.

## 7. Data Flow

The end-to-end data flow, from anonymous client to executed PHP:

```
attacker (no credentials, no session, no product interaction)
  |
  | 1) POST /upload.php            multipart/form-data
  |    part "userfile", body = <?php ...shell_exec...
  |    filename = "nuuo_rce_probe.php"      (or an absolute path)
  v
upload.php: echo filename; copy(tmp_path, filename)
  |    -> writes attacker PHP into /NU20/web/       (document root)
  |    -> HTTP 200, body echoes the chosen filename
  v
attacker
  |
  | 2) GET /nuuo_rce_probe.php
  v
lighttpd fastcgi -> /usr/bin/php-cgi executes the uploaded file
  |
  v
response body contains marker + command output   (code execution confirmed)
```

Two properties of this flow deserve emphasis. First, the write and the execution are decoupled in time,
which means the write primitive is independently useful even without the execution - a point the impact
section develops. Second, the flow inverts the usual direction of trust for an upload handler: the
product treats the client's filename as the authoritative storage decision, instead of treating it as
untrusted data about which the product makes its own storage decision.

## 8. Exploit Construction

The exploit is two requests with no special tooling, and it was built that way deliberately: every
sub-step uses only documented protocol behaviour, so a failure at any point is a clean negative and
success is unambiguous.

Construction of the upload request: a multipart body with a single file part named userfile; the part body
is a three-line PHP program that prints a fixed marker string and then the output of a
shell-execution built-in applied to a command supplied by the operator; the part's disposition filename
carries the chosen destination name, nuuo_rce_probe.php. No auth header is attached at any point, and no
session bootstrap precedes the request.

Construction of the trigger: a plain GET of the destination filename relative to the service root. The
expected success signal is the marker followed by the command output in the response body; the presence
of the marker is the pass criterion, so a servable-but-not-executing write (for instance if a deployment
statically served the root) would not false-positive.

Destination-name variants exercised: the relative form nuuo_rce_probe.php, which lands in the interpreter
working directory - the replica served the document root, which reproduces the document-root working
behaviour of the php-cgi setup the recovered configuration describes; and the absolute form
/NU20/web/abs_marker.php, which does not depend on working-directory behaviour at all. Both landed and
executed. The relative form's exact on-appliance resolution depends on the interpreter working directory
of the shipped fastcgi setup, which we could not observe on a physical unit - the absolute form exists so
that the write claim does not rest on it, and the analysis scripts carry both.

A hygiene constraint shaped the script: no reverse shell, no callback channel, no persistence - the
payload prints an id-style command's output and nothing more, and the operator chooses the command. The
exploit script in the exploit directory implements exactly this two-request construction with plain
standard-library HTTP, a configurable target, a configurable command, and explicit timeout and error
handling; nothing in it embeds an address, a credential, or any state of our verification environment.

## 9. Dynamic Verification

### Verification design and why it was built this way

No physical Crystal VM was reachable during this study - the appliance's virtually bridged network leg
did not acquire a lease in our environment - so the verification could not be a live blast against the
product's own listener. The design goal was therefore to make every product behaviour under test come
from the product's own artifacts, and only the transport come from us:

- the served application is the appliance's recovered web root itself, all 575 files including the real
  upload.php, not a reimplementation;
- the serving behaviour reproduces the semantics that the recovered configuration establishes: no
  authentication layer, .php executed by the PHP interpreter, document root /NU20/web/;
- the server process was bound to the loopback interface of an isolated research host, so nothing in the
  verification was reachable from any network.

This is a faithful replica of the measured artifacts, and it is labelled as such everywhere it appears.
What it is not is a physical appliance observation, and the advisory's identity claims are scoped
accordingly.

### Observed results

Three independent runs uploaded the probe file without any credential; in each run the endpoint answered
HTTP 200 echoing the chosen filename, the file was listed inside the served root, and a single GET
returned the marker plus the command output. The three runs' commands were the identity query, the
account-name query and the kernel banner query, and all three returned the marker. Two negative controls
eliminated the obvious false-positive classes: a GET against a name never uploaded returns 404 with no
marker, and a GET against a randomly named nonexistent PHP file likewise produces nothing, so the marker
cannot come from a pre-existing or collateral file. The absolute-destination variant landed at the path
it named and triggered on GET with its own marker, confirming the path-control half of the finding
independently of working-directory behaviour.

The command output in the runs identified the invoking account of the replica's PHP server - on that
research host, its privileged account. That measurement is a property of the replica environment, and it
is reported as such: it demonstrates that the executed code inherits the identity of the PHP service, and
the replica's PHP service ran as the host's privileged account. The corresponding identity on a shipped
appliance - the lighttpd / php-cgi service account of the VM - was not observed at runtime in this work.
No superuser claim about the shipped appliance appears anywhere in this advisory, and the execution
primitive, its score and its impact statements are written to be true whichever account that turns out
to be.

### What remains unverified

Three things this advisory does not claim, for completeness: first, end-to-end behaviour of a physical
appliance instance (including the exact working-directory resolution of a relative destination name on
the shipped fastcgi setup - the absolute-name result removes the chain's dependence on it); second, the
runtime identity of the PHP service account on the shipped appliance; third, anything about other
handlers in the recovered web root, which are named only as an audit recommendation, not as findings.

## 10. Reachability and Security Impact

### Reachability from the artifacts

The recovered configuration makes the chain reachable from any network client: the HTTPS listener binds
:443 across addresses with the shared /NU20/web/ document root, the endpoint handler inside that root
performs no authentication, and the server layer applies no gate of its own. Crystal VM appliances are
management-plane systems deployed at the edge of camera and recorder networks; that placement is what
turns the write primitive into infrastructure-level impact - the appliance brokers the registration and
credential state of the surveillance estate, and code execution on it inherits the visibility and the
trust that position confers. Two consequence classes follow directly and are claimed:

- arbitrary code execution in the product's PHP service context, with everything that account can read
  and write: the application's own state, its recorded media indices, its camera trees, and whatever the
  service account reaches on the appliance filesystem;
- an anonymous arbitrary file write into the served tree, which persists across service restarts, and
  which is a defacement, content-integrity and implant primitive on its own even where execution is
  somehow neutralised.

Two consequence classes are plausible but not claimed, because they were not measured: takeover of
downstream cameras and recorders through the appliance's stored management credentials (the credential
stores' readability to the web account was not enumerated), and lateral movement through the camera
network (the appliance's network position was not exercised).

### Position in the public record

The four-axis public-record sweep described in section 1 returned a vendor with a substantial history of
unauthenticated web findings in its recorder lines - including a 2018-era arbitrary-file-upload record
against this same upload.php endpoint pattern in the NVRmini lineage, and a removed 2016-era handler that
appears in older records alongside a then-current Crystal-named product generation - but nothing naming
upload.php on the Crystal Server line and nothing naming the appliance generations under test. The
vendor's own patching behaviour, visible inside the recovered web root (the 2016-era debugging handler is
gone; the upload pattern remained), is consistent with selective patching across product lines rather
than a class-level fix. This advisory therefore states the prior-record position as: the pattern is not
new to the vendor, the product line under test has shipped it forward, and the public record contains no
entry for it on the Crystal Server appliance line.

## 11. Fix Recommendations

1. Remove upload.php or place its function behind the authenticated session gate; a write handler has no
   anonymous calling case, and authentication alone severs the chain at request one.
2. Never build a storage destination from request data: generate the stored name server-side from an
   allow-listed extension set, append no client-supplied path components, and canonicalise the resolved
   destination against an intended storage root before writing.
3. Store uploads outside the served tree in a non-executable quarantine directory, and stage content into
   the application only after validating it.
4. Move authentication from the file level to the server or framework level so a forgotten include cannot
   reopen an anonymous handler; while that migration is pending, mechanically audit every handler in the
   web root for the missing-include pattern - in this product the pattern is one include, so the audit is
   a grep-sized task.
5. Add a shipped-image manifest of the document root and reconcile it at boot or on a schedule; for an
   appliance product this is a day-scale engineering effort that detects this class of implantment.
6. Add regression tests that express the three omissions as assertions: an unauthenticated upload with a
   .php destination is rejected; a session-less write to any handler is rejected; the destination that
   reaches storage differs from the client-supplied name.

## 12. CWE and CVSS

### CWE classification

CWE-306 (Missing Authentication for Critical Function) is primary: the file-write function is reachable
with no credentials, per the endpoint source and the recovered server configuration. CWE-434 (Unrestricted
Upload of File with Dangerous Type) is co-equal: no property of the upload is examined before the write,
and the written file is servable into an executable mapping. CWE-73 (External Control of File Name or
Path) is contributing: the destination is the client filename verbatim, relative or absolute. The
classification is reported without inflating any CVSS metric: the three classes describe one measured
endpoint behaviour from complementary angles, and the score below charges the endpoint once.

### CVSS with the arithmetic shown

Published vector, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`:

- ISS = 1 - (1 - 0.56) x (1 - 0.56) x (1 - 0.56) = 1 - 0.44 x 0.44 x 0.44 = 0.914816
- Impact (scope unchanged) = 6.42 x 0.914816 = 5.86911872, carried as 5.869119 in the arithmetic below
- Exploitability = 8.22 x 0.85 (AV:N) x 0.77 (AC:L) x 0.85 (PR:N) x 0.85 (UI:N) = 3.887043
- Base = 5.869119 + 3.887043 = 9.756162, roundup to the tenth = 9.8 Critical

The source records behind this advisory carried a 9.8 against this identical vector; it was re-derived
here and left standing rather than inherited. The known class of recorded-score errors this project has
previously published corrections for (a medium-privilege vector recorded at the low-privilege score, and
an unauthenticated scope-changed vector recorded at 9.8 where the formula gives 10.0) was checked
explicitly: this vector is AV:N/PR:N/S:U, and its correct value is 9.8.

Rejected reading: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0 Critical. Under the 3.1
scope-changed expression the impact term is 7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 - 0.02)
raised to the thirteenth power = 6.657336 - 0.533312 = 6.124024, exploitability remains 3.887043 (PR:N
under scope changed is still 0.85), and 1.08 x (6.124024 + 3.887043) = 10.812 capped at 10.0. Rejected
because scope changed would require the executed code to violate an authority beyond the vulnerable
component's own, and this work measured no such boundary crossing: the uploaded file executes in the
product's own PHP process context, and whether that process's account additionally holds host
privileges is an unmeasured deployment property that this advisory explicitly declines to claim.

Conditional reading: `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.8 High, by the same impact
5.869119 with exploitability 8.22 x 0.62 x 0.77 x 0.85 x 0.85 = 2.835255, giving 8.704374 rounded up
to 8.8. Conditional on a deployment that confines the appliance's management interface to a segmented
management network; the recovered shipped configuration establishes no such confinement, so the
published score uses the measured network bind.
