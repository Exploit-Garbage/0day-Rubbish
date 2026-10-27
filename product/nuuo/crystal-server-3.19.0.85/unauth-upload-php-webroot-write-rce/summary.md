# NUUO Crystal Server 3.19.0.85 - Unauthenticated PHP Web-Root Upload through a Bare copy() Endpoint in upload.php, Reaching Web-Side Remote Code Execution (CWE-306, CWE-434, CWE-73)

Advisory: https://0day-rubbish.com/blog/nuuo-crystal-server-unauth-upload-php-webroot-write-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

NUUO Crystal Server 3.19.0.85 from NUUO Inc. of Taipei, Taiwan is the vendor's flagship video management
and NVR server software, shipped as the Crystal virtual-machine appliance (an Ubuntu-based OVA running a
lighttpd web front end with PHP executed by php-cgi through lighttpd's fastcgi mapping). Inside the web
root recovered from the appliance disk image, upload.php is three lines long and does nothing except echo
the client-supplied filename and copy the uploaded temporary file to a destination taken from that same
client-supplied filename: there is no session include, no login check, no extension filter, no MIME
check, no path restriction. The web server configuration recovered from the same disk loads no
authentication module at all - authentication is delegated to each PHP file individually, and upload.php
is one of the files that never asks. An anonymous client on the network can therefore POST a PHP payload
with a destination filename of its own choosing, have copy() write that file under an attacker-controlled
name into the served document root, and then fetch the file once to have the product's own fastcgi
mapping execute it as PHP: an unauthenticated write primitive that converts directly into server-side
code execution over plain HTTP or HTTPS. The dynamic confirmation was performed on a faithful replica
built from the appliance's own extracted web root (all recovered PHP files, including the real
upload.php, served with the document-root behaviour and the unauthenticated php execution semantics of
the appliance's extracted lighttpd configuration): the upload landed in the document root and the
fetched file executed, returning a command marker - in that environment under the invoking PHP server
account. No network path to a physical Crystal VM was available during this work, so the runtime
identity of the executing account on a shipped appliance was not observed, is not claimed, and does not
carry the score: this chain involves no memory corruption, no deserialisation gadget, no default
credential and no action by any user of the product.

- Component: the PHP web service of the Crystal VM appliance - lighttpd with fastcgi mapping of .php to
  /usr/bin/php-cgi, document root /NU20/web/ for the HTTPS listener, recovered from the appliance disk
  image together with a 575-file PHP web root (squashfs, the sq4 region), inside which upload.php carries
  the vulnerable handler
- Sink: the fastcgi execution of an attacker-named .php file that copy() (the PHP file-copy primitive
  whose destination argument is the raw multipart filename) has written into the document root
- Source: the filename field of an anonymous multipart/form-data POST to /upload.php, whose value
  becomes both the echoed response text and the copy() destination verbatim
- Sanitization: none on the reachable path - no authentication gate in the endpoint, no extension or
  content-type filter on the upload, no canonicalisation or path confinement on the destination, and no
  authentication module anywhere in the extracted web server configuration

## CVSS Score

- Score: 9.8 Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) - a single anonymous request pair
  (write, then fetch) yields arbitrary PHP code execution in the product's own web service
- Attack Vector: Network - the extracted lighttpd configuration binds its HTTPS listener on :443 with the
  shared document root /NU20/web/ and no per-address bind restriction, so any network client that can
  reach the management interface can reach the endpoint
- Attack Complexity: Low - one multipart POST with a chosen filename and one GET; no race, no parsing
  quirk and no environmental condition beyond the shipped configuration
- Privileges Required: None - the endpoint source contains no session include and no login check, and
  the extracted server configuration contains no authentication module, no auth backend and no access
  denial rule, so the write succeeds without any credential
- User Interaction: None - no administrator action, no browser session and no interaction with any
  product user precedes or enables the write
- Scope: Unchanged - the executed code runs as the product's own PHP service in its own process
  context; this advisory claims no crossing into any authority beyond that service, and the
  scope-changed reading below is explicitly rejected
- Impact C-I-A: all High - server-side code execution plus an arbitrary-file-write primitive into the
  served tree yield full confidentiality of the video management data plane, arbitrary modification of
  served content and product configuration, and complete control of service availability
- CWE: CWE-306 primary (a critical file-write function reachable without authentication), CWE-434
  co-equal (an upload accepted into executable mapping without type restriction), CWE-73 contributing
  (the destination file name or path is externally controlled) - the two primary-vulnerability classes
  rest on measured artifacts and neither depends on the other being true: any one of them alone still
  yields the write into an executable location
- Arithmetic: the sources behind this advisory recorded a 9.8 against this same vector and the figure was
  re-derived rather than inherited - ISS is 1 - (1 - 0.56) x (1 - 0.56) x (1 - 0.56) = 0.914816,
  impact is 6.42 x 0.914816 = 5.869119, exploitability is 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043,
  the unrounded base is 5.869119 + 3.887043 = 9.756162 and the roundup rule gives 9.8
- Rejected reading: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0 Critical (impact under the
  scope-changed 3.1 expression 7.52 x (0.914816 - 0.029) - 3.25 x (0.914816 x 0.9731 - 0.02) to the
  thirteenth power = 6.124024; with exploitability 3.887043 the sum 10.011 caps at 10.0) - rejected
  because no violation of an authority beyond the web service itself was demonstrated: the executed PHP
  runs inside the product's own PHP process context, and this work does not measure or claim a sandbox,
  container or privilege boundary crossed by that execution
- Conditional reading - deployments that restrict the appliance to a management VLAN: the endpoint is
  then reachable only from the adjacent network, and `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  = 8.8 High by the same impact term with exploitability 8.22 x 0.62 x 0.77 x 0.85 x 0.85 =
  2.835255, giving 5.869119 + 2.835255 = 8.704374 rounded up to 8.8; the shipped configuration itself
  shows no such restriction, so this reading is conditional on an operator-applied segmentation that we
  did not test and it is not the headline score

## Affected Products

- NUUO Crystal Server version 3.19.0.85, the vendor's video management and NVR server software,
  distributed as the Crystal virtual-machine appliance: an Ubuntu-based OVA whose web tier is lighttpd
  with php-cgi fastcgi execution and whose web root carries the PHP application studied here. Only this
  version was examined and only this version is claimed
- Affected component: upload.php together with the fastcgi mapping of .php to /usr/bin/php-cgi and the
  /NU20/web/ document root of the extracted lighttpd configuration; the three-line endpoint source and
  the server configuration are both recovered product artifacts, and every load-bearing claim in this
  advisory is pinned to one of them
- Not claimed as affected: earlier or later Crystal Server versions (not examined; the file layout
  family resemblance to the vendor's recorder lines suggests they deserve the same audit, but that is
  a recommendation, not a finding), the vendor's CMS and recorder product lines themselves, and any
  endpoint other than upload.php
- Verification method and its boundary: static verification is anchored in the appliance disk image -
  the disk was converted to a raw image, the PHP web root was recovered from its squashfs region (the
  sq4 area, 575 PHP files including the byte-exact upload.php), and the lighttpd configuration was
  recovered from the same disk and read in full. Dynamic verification ran on a faithful replica: the
  appliance's own extracted web root served with the document-root and unauthenticated-execution
  semantics of the appliance's own extracted configuration, on an isolated research host. Three
  independent runs uploaded a probe PHP file without any credential, confirmed the file landing in the
  document root, fetched it once and received an execution marker together with command output; a
  no-upload negative control produced no marker, and an absolute-destination variant
  (/NU20/web/abs_marker.php) landed and executed identically, so the write does not depend on a
  working-directory coincidence. What was not obtained in this work is a runtime observation of a
  physical Crystal VM: no physical appliance network interface was reachable during the study, so
  appliance-side behaviour is argued from the extracted artifacts plus the replica, and the identity of
  the account that executes uploaded PHP on a shipped appliance was not measured and is not claimed
- Privilege ceiling: the executed code runs as the account that runs the product's PHP execution path.
  In the replica that account was the PHP server account of the research host and the marker read back
  that host's privileged account; on a shipped appliance the corresponding account is the lighttpd /
  php-cgi service account. Whether that account is a dedicated identity or the system superuser is a
  property of the appliance image that this work did not observe at runtime, so no root or superuser
  claim appears in this advisory's headline or score. Not reached and not claimed: any on-appliance
  privilege separation analysis, any lateral movement into the camera or recorder network, and any
  escalation from a dedicated service account

## Impact

- Unauthenticated arbitrary file write into the served document root, which is a standalone primitive
  even before execution is considered: served pages can be replaced, configuration and application
  files inside the web root can be overwritten, and a persistent implant can be dropped into a
  location the product itself serves
- Server-side code execution on the video management server through the product's own fastcgi mapping,
  with no payload delivery beyond plain HTTP or HTTPS and no credential at any point in the chain
- Full compromise of the management plane of the video surveillance infrastructure: the camera tree,
  recorder channels, credential stores reachable to the web account, applied configuration and
  whatever the web service account can read on the appliance are all exposed to code the attacker
  chose
- Persistent access that survives a service restart, because the dropped PHP file is an ordinary file
  inside the served tree until an operator finds and removes it, and nothing in the product's own
  response distinguishes the upload from any other request
- Cheap and reliable exploitation: the entire chain is two requests to a standard management port,
  fits in a single small script with no exploit-specific dependencies, and leaves no crash, error log
  or availability impact on the way in
- Detection difficulty by construction: both the write and the execution use the product's documented
  handlers and ordinary status codes; file-integrity monitoring of the web root and configuration-change
  review are the defenders' strongest signals
- Amplifying adjacent weakness reported separately and not folded into the score: authentication in
  this product is implemented file-by-file rather than at the server layer, so every PHP file that
  forgets the session include is unauthenticated by design; upload.php is the one measured here, and
  the same architecture argues for auditing every other handler in the recovered web root

## Mitigation

1. Delete upload.php or move its function behind the product's authenticated session gate: a
   file-write handler has no legitimate anonymous use, and this advisory's chain dies at the first
   request once the endpoint authenticates
2. Reject unsafe destination names at the handler: build the destination on the server side from an
   allow-listed extension set and a server-generated name, never from any part of the client-supplied
   filename, and confine it with realpath-style canonicalisation to an intended storage directory
3. Store uploads outside the served tree - a non-executable quarantine directory with randomized names
   - and only stage file data into the application after content validation
4. Centralise authentication at the server layer rather than per PHP file: apply an authentication
   module or a framework-level session gate in front of the entire application path space, so that one
   forgotten include cannot open an anonymous handler; audit every handler in the web root for the
   missing-include pattern while that migration is pending
5. Add a web-root integrity baseline and, on boot, restore or alarm on files under the document root
   that are not part of the shipped image - a cheap defence for an appliance product
6. Add a regression test that posts a .php body with a .php destination filename to every upload
   endpoint and asserts rejection of both the extension and the client-named destination, plus an
   unauthenticated snapshot test asserting that every handler either authenticates or refuses

## References

- https://0day-rubbish.com/blog/nuuo-crystal-server-unauth-upload-php-webroot-write-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
