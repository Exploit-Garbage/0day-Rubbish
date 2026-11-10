# Maian Cube 1.x - License-Generation Passphrase Command Injection Executing as the PHP Process User

Advisory: https://0day-rubbish.com/blog/license-gen-command-injection-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

Maian Cube is a PHP application published by Maian Script World and built on the vendor's shared Maian
Media framework. The framework is used across a family of products that sell, license or deliver
ionCube-encoded software; within that family Maian Cube occupies a single distinct role. It is the product
that *creates* licences. Its siblings are consumers - they read a licence file, validate it and run - while
Maian Cube is the administrative tool an integrator or vendor uses to produce the licence file in the first
place, bound to a domain, an address or a hardware identifier and sealed with an encryption passphrase.

That sealing step is not implemented in PHP. Maian Cube delegates it: it assembles a command line and hands
it to an external `make_license` binary through `shell_exec()`. The binary path, the licence parameters and
the operator-supplied passphrase all travel as text on that command line, and `shell_exec()` executes its
argument through `/bin/sh -c`. This is the structural precondition for the finding: any operator-supplied
value that reaches that string without being quoted for the shell is, in shell terms, not a value at all
but command syntax.

This advisory documents that precondition being met. The passphrase field of the licence-generation screen
is copied verbatim into a double-quoted shell argument, and a passphrase containing a double quote, a
semicolon and a hash terminates the pending invocation, executes arbitrary command text and comments out
the remainder of the original command. The result is authenticated remote command execution at the
privilege level of the PHP/Apache process, reachable from the ordinary admin panel with a single POST.

The verification boundary matters as much as the finding, so it is stated up front. The chain was verified
end to end against a complete deployment of the application rather than against a reduced model: a Docker
Compose stack carrying MySQL 8.0 and the application itself on PHP 8.2 / Apache 2.4, bound to loopback at
`127.0.0.1:8191`, running the real login handler, the real AJAX dispatcher and the real licensing class.
Four injected commands produced four marker files, each owned by `www-data` (uid=33) and each containing
the output of the injected command, with the markers read back through the container runtime that hosted
the vulnerable process. No physical or virtual appliance image was involved, no firmware was disassembled
and no vendor binary was reverse engineered: the evidence is application-level, from source review of the
shipped PHP to a live request that executed a command and left a file behind. The identity observed is the
Apache/PHP process user of that deployment; no execution as `root` was attempted or observed.

## 2. Vulnerability Summary

The defect is a missing neutralization on one variable, in one method, on one code path.

- **Class of defect**: OS command injection (CWE-78). The application composes a shell command line from an
  operator-supplied string and lets `/bin/sh` re-parse it.
- **Where**: `control/classes/class.licensing.php`, class `cubeLicense`. The `lock()` method builds the
  `--passphrase` argument by concatenating the raw passphrase between two literal double quotes, and
  `create()` passes the assembled argument list to `shell_exec()`.
- **Why it is exploitable**: inside a double-quoted shell word, a `"` ends the word. Everything the
  operator typed after that quote is parsed as command structure. A `;` starts a new command, and a `#`
  makes the shell discard the rest of the line - which is exactly what is needed to silence the trailing
  `--allowed-server`, `-o` and output arguments that the application still appends.
- **Why nothing stops it**: the handler performs no validation of the passphrase beyond a non-empty check,
  the `cubeLicense` constructor assigns the POST value directly, and the escaping helpers that the class
  already defines are never called for this field.
- **Why it is not self-limiting**: because PHP hands the whole string to a shell, the injected command runs
  before and independently of the `make_license` binary. Even with a nonexistent binary path - which is
  what the recorded run used - the interface reports a failure while the injected command has already
  executed.
- **Prerequisite**: an authenticated administrator session plus the per-install CSRF token. Nothing else -
  no upload, no plugin, no configuration toggle, no special file.

## 3. Authentication Boundary

The admin dispatcher is `admin/control/system/_ajax.php`. Its request gate sits at L15-23 and works on
three session/cookie flags - `cube_access`, `cube_access_user` and `cube_access_cookie`. If all three read
`no` and the requested operation is not `login`, the request is terminated with 403. The exemption list is
exactly one entry: `login`. The `generate` operation is not exempted, so an unauthenticated request does
not reach the licensing class at all; it is answered with the login page.

The session value itself is derived per installation: `cube_access` is set to `SECRET_KEY . time()`, where
`SECRET_KEY` is generated randomly by the installer rather than shipped as a fixed constant. Alongside it,
the panel issues a CSRF token that is published in the page's `x-header-csrf` meta tag and echoed back by
the panel's JavaScript in a `csrf` header; the recorded request carries it in the `cs_rf` form field. These
two facts are the reason the finding is documented as authenticated rather than as a bypass: the session
handling is not the defect, and defeating it is a separate research question that this advisory does not
address.

The boundary was confirmed by observation, not only by reading the gate. During verification an
unauthenticated request to the same `generate` operation returned the login page and produced no marker
file, while the authenticated request to the identical operation produced one. That is the negative control
this record contains; no benign-passphrase control was run, and none is claimed.

Three further points belong here because they shape how the finding should be triaged.

First, authentication is not a mitigation. The administrator is a legitimate user of this screen - a
store operator, an integrator shipping a licensed build, a contractor engaged for a migration - and the
screen's whole purpose is to accept operator text and turn it into an operating-system invocation. The
defect is that the screen trusts that text as shell syntax.

Second, this is not a default-credential finding and it is not affected by password hygiene. The recorded
deployment used an administrator password set by the installer at deployment time, but the credential is
incidental: any administrator password reaches the same sink, and rotating it changes nothing about the
vulnerability.

Third, the finding is not a privilege escalation. It does not grant administrator authority; it consumes
it. What it adds is a second, unintended authority - command execution on the host - at the process user's
level, which the administrative interface was never meant to expose.

## 4. Attack Surface

The entry point is the panel's AJAX dispatcher:

- Method and target: `POST /admin/index.php?ajax-ops=generate`, with the `X-Requested-With: XMLHttpRequest`
  header that the panel's own JavaScript sends.
- Fields consumed by the branch: `licfile` (licence file name), `passphrase` (the licence encryption
  passphrase), `licpath` (the path to the encoder/binary used for the invocation), the property arrays
  `key[]`, `value[]`, `exp[]` and `enf[]`, and the expiry fields `expire_on`, `expire_in` and `duration`.
- Precondition on the request: `licfile`, `passphrase` and `licpath` must all be non-empty. That is the
  entire client-side and server-side validation recorded at `_ajax.php:75-76`.
- Reachability from the UI: the licence-generation screen is a normal page of the store admin panel. There
  is no feature flag, no module installation and no elevated role beyond the administrator session.

The shape of the surface explains why the passphrase is the weakest field. A licence file name is
constrained by the filesystem, an encoder path is constrained by where the binary actually lives, and the
property arrays are name/value pairs whose characters are already narrowed by the UI. A passphrase, by
contrast, is a free-text secret with no natural character restriction at all: a user who wants a quote, a
semicolon or a hash in their passphrase has a legitimate reason to want it, and there is no obvious
allowlist that would not be rejected as a functional regression. That is precisely the field that needed
quoting, and precisely the field that was not quoted.

Because the binary path is wrapped by `mswMakeLicensePath('"', ...)`, the encoder path is enclosed in
double quotes at the point of use; it is a weaker vector than the passphrase, and this advisory does not
claim it. The passphrase is concatenated with quotes that the *attacker's own input* can close, which is a
different and more direct problem.

## 5. Sink Identification

The sink is a single `shell_exec()` call in the licensing class. Its arguments come from two places: the
binary path, quoted through a helper, and the argument list assembled by `lock()`.

```php
// control/classes/class.licensing.php:193  - cubeLicense::create()
shell_exec(mswMakeLicensePath('"', $this->settings) . " $string -o $output");
```

`mswMakeLicensePath($enclosed, $s)` is defined at `control/functions.php:123` and does nothing more than
return `$enclosed . $s->licpath . $enclosed`, so the call above evaluates to `"<licpath>"` followed by the
space-separated `$string`. The binary path is therefore a quoted word. `$string` is the joined contents of
`$lock`, and one of its entries is built by `lock()` at L57-60:

```php
// control/classes/class.licensing.php:57-58  - cubeLicense::lock()
$lock[] = '--passphrase "' . $this->passphrase . '"';
$lock[] = '--allowed-server ' . str_replace(',,', ',', $encString);
```

The first line is the defect in one statement. The passphrase is placed between two literal double quotes
and concatenated. No escaping function intervenes, and no character is rejected upstream. The value is
whatever the administrator typed.

The class is aware that shell escaping exists. It defines `escapeArg()` and `escapeCmd()` at L49-55. Those
helpers are called exactly once in the file, for the `--header-line` argument at L98. They are never
applied to `$this->passphrase`. A second helper, `mswCD()`, defined at `control/functions.php:152`, is a
no-op that returns its argument unchanged, so even where it appears in the path it cannot alter a character.

The call site is not behind a debug branch in normal operation. `create()` contains a debug path guarded by
`ENC_DEBUG`; with `ENC_DEBUG=0`, the shipped default recorded at `control/options.php:37`, execution goes
straight to the `shell_exec()` at L193.

Two properties of the sink deserve to be stated explicitly, because they determine how much of the surface
is affected. First, it is unconditional once reached: the command string is constructed and executed
whether or not the licence file is ultimately created and whether or not the external binary exists.
Second, it is the only such sink in this class - the same file builds the invocation in one place, so a
single fix at the construction point closes the whole path.

## 6. Source Identification

The source is the `generate` operation of the admin dispatcher, `admin/control/system/_ajax.php`, `case
'generate'` at L75-140.

```php
// admin/control/system/_ajax.php:75-76  - the only precondition: three fields are non-empty
if ($_POST['licfile'] && $_POST['passphrase'] && $_POST['licpath']) {

// admin/control/system/_ajax.php:106  - passphrase forwarded untouched into the licence object
new cubeLicense(array(
  'name'       => $_POST['licfile'],
  'server'     => $server,
  'encoder'    => $_POST['licpath'],
  'passphrase' => $_POST['passphrase'],
  ...
));
```

The preconditions at L75-76 test truthiness, not format. A passphrase of any length and any character
composition satisfies them as long as it is not empty. No length cap, no character class, no escape call
and no rejection path is applied to the value before it is placed in the constructor array.

Inside the class, the constructor does the second hop: at `class.licensing.php:32` the property is assigned
directly from the array element, `$this->passphrase = $license['passphrase'];`, again with no
transformation.

The absence of an upstream filter was checked rather than assumed. The dispatcher's include chain -
`control/system/core/mm.php`, `global.php`, `constants.php` and the top of `_ajax.php` itself - contains no
global sanitization of `$_POST`: no `escapeshell`, no `addslashes`, no `strip_tags`, no project-specific
character filter applied to the request body. There is therefore no intermediate layer between the HTTP
parameter and the concatenation in `lock()`. The data flow in section 7 is complete, not abridged.

## 7. Data Flow

The path from request to shell, with every hop named:

```text
$_POST['passphrase']
  -> admin/control/system/_ajax.php:106    'passphrase' => $_POST['passphrase']
  -> cubeLicense::__construct()  class.licensing.php:32    $this->passphrase = $license['passphrase']
  -> cubeLicense::create()       class.licensing.php:150   $lock = lock()
  -> cubeLicense::lock()         class.licensing.php:58    '--passphrase "' . $this->passphrase . '"'
  -> cubeLicense::create()       class.licensing.php:193   shell_exec('"<licpath>" --passphrase "<value>" ... -o <output>')
  -> /bin/sh -c                 whole string re-parsed as shell syntax
```

Each hop is an identity operation on the string. Nothing between the request body and the shell examines
the content, so the passphrase arrives at the parser exactly as submitted.

## 8. Exploit Construction

The payload only has to do three things: close the double quote that the application opened, terminate the
pending `make_license` invocation, and silence the arguments the application appends afterwards.

- `"` closes the `--passphrase "` word, so the shell sees an empty argument and the word ends.
- `;` separates that completed command from the next one, which the attacker supplies.
- `#` starts a comment, discarding the remaining `--allowed-server ... -o <output>` text, so the shell has
  no trailing syntax to complain about and no licence write to attempt.

The resulting command line, with the recorded deployment's placeholder binary path, is:

```text
"/tmp/x" --passphrase ""; <cmd> > /tmp/<marker> 2>&1 ;#" --allowed-server  -o /tmp/test_xxx.txt
```

`/bin/sh -c` parses this into three commands:

1. `"/tmp/x" --passphrase ""` - the intended invocation. `/tmp/x` is a placeholder binary path, so this
   fails immediately and harmlessly.
2. `<cmd> > /tmp/<marker> 2>&1` - the injected command, executed by the web server user, with its output
   captured into a uniquely named marker file.
3. `#" --allowed-server ... -o ...` - entirely commented out.

Three observations about this construction matter for anyone reproducing it.

First, the injection does not depend on the external binary existing. The shell parses the full string
before it executes any of it, so the failure of command 1 has no bearing on command 2. A deployment whose
`make_license` path is wrong, missing or non-executable is just as exposed as one where it is correct -
which is how the recorded run behaved, using a deliberately nonexistent path.

Second, the product's response is not evidence of failure. The `generate` operation answers with
`{"status":"rdr","txt":["System Error", ...],"url":"index.php?p=msg&code=1"}` because no licence file was
created. That envelope is produced after the shell has run. Anyone triaging from HTTP responses alone will
see an error and conclude the request did nothing.

Third, the marker name is unique per attempt, which is what makes the evidence meaningful: a pre-existing
file cannot be mistaken for a fresh execution, and the ownership and content of a newly created file
establish both *that* a command ran and *which* identity ran it.

## 9. Dynamic Verification

The application was deployed from its own distribution into a Docker Compose stack: MySQL 8.0 in a
container and the full Maian Cube application on `php:8.2-apache`, with the web port published on loopback
at `127.0.0.1:8191`. Three installer environment checks had to be satisfied before the application would
run - a `zip` extension adjustment that involved a change in `control/system/core/mm.php`, a
`session.save_path` correction, and renaming the installer directory after installation. None of those
mechanically concerns command construction: no line of `control/classes/class.licensing.php`, of the
`generate` branch, or of the authentication gate was modified for the test.

The verification script drives the real interface in five steps: it fetches the admin login page and
extracts the CSRF token from the `x-header-csrf` meta tag; it authenticates against
`/admin/index.php?ajax-ops=login`; it re-fetches the admin page for a fresh token; it posts the crafted
passphrase to `?ajax-ops=generate`; and it reads the marker back from inside the container. The token
observed on the recorded run began `44f0a0020c058007a285a5c8` (truncated in the record).

Four markers were produced and read back:

```console
$ docker exec maian-cube-web sh -c "cat /tmp/CUBE_RCE_MARKER_18e574ff83a4; stat -c '%U uid=%u' /tmp/CUBE_RCE_MARKER_18e574ff83a4"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data uid=33
```

That first run injected `id`; the marker holds 54 bytes and the complete `id` output. A second run injected
a multi-command string, `echo PROOF2; whoami; hostname; cat /etc/hostname`:

```console
$ docker exec maian-cube-web cat /tmp/CUBE_RCE_MARKER_45aef87f1e67
b9d83711110e
```

The marker holds 13 bytes, the container's hostname, and is owned by `www-data`. Only the final command in
that string survives into the file, because a single redirection applies to the last command of the group;
the fact that the file exists at all, with that content, still establishes that the shell executed the
injected sequence rather than the intended licence invocation. A third primary round repeated the `id`
injection and produced `/tmp/CUBE_RCE_MARKER_ee8e0b769a3c` with the same 54-byte `id` output and the same
`www-data uid=33` ownership. A fourth, separately run confirmation round produced
`/tmp/CUBE_RCE_MARKER_6358ac04f567` containing the literal string `FALSIFIER_LIVE_OK`, again owned by
`www-data` (uid=33).

The combined evidence is: four distinct marker files, each named with a freshly generated identifier, each
created by the vulnerable application during an authenticated request, each owned by the web server user,
and each containing either the output of the injected command or the command's requested literal. The
negative control recorded alongside them is the unauthenticated request described in section 3, which
returned the login page and created no marker.

What this establishes and what it does not: it establishes that the shipped code path executes attacker
text as shell syntax with the PHP process's authority, from the real login through the real dispatcher to
the real `shell_exec()`. It does not establish the identity of any other deployment's web user, it does not
establish execution as `root` in any environment, and it does not establish whether a given production
installation runs the panel behind a reverse proxy, IP restriction or extra authentication layer - those
are deployment choices this research did not measure.

## 10. Reachability and Security Impact

Reachability is short and does not branch. The admin panel is a web interface, published by default on the
application host; the `generate` operation is reachable once the administrator session exists; the sink is
reached unconditionally because `ENC_DEBUG` is `0` in the shipped options at `control/options.php:37`; and
the data flow has no intermediate filtering layer, as recorded in sections 6 and 7. There is no state that
has to be prepared, no file that has to exist and no second request that has to succeed.

The impact follows from the identity rather than from the injection. The command executes as the account
that runs PHP under Apache - measured as `www-data` with uid=33 - which is the account that reads the
application's configuration, opens its database connection and owns or can write the deployed code under
the document root. From that position an attacker can:

- read the configuration store and the database credentials the application uses, because they are files
  and values that same process reads on every request;
- write into the application tree - wherever that deployment's file permissions let the web user write -
  and therefore change what the store serves, including the licensing logic itself, which an attacker with
  this access can rewrite to accept licences it did not issue;
- alter or exfiltrate customer and order data through the application's own database connection;
- stop, restart or degrade the service at will;
- establish a foothold consistent with command execution as a service account, bounded by what that
  account can write in the deployment. Persistence across container rebuild or redeployment was not tested
  and is not claimed, and no attempt was made to escalate beyond `www-data`.

The severity is not reduced by the authentication requirement. CWE-78 exists in this code because an
administrative form accepted operator text and treated it as shell syntax; the administrator is the form's
intended user, not an intruder, and the interface is offered to every installation that generates licences.
An attacker who obtains an administrator session by any means - credential reuse, a leaked integration
account, a shared operations login - gains command execution in addition to the administrative access they
already had, on an interface where nothing in the product signals that this is possible.

The published score for this chain is `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, which evaluates to
7.2 High. The rejected lower-privilege reading and its arithmetic are documented in the advisory summary
and are not to be quoted as the rating.

## 11. Fix Recommendations

1. **Quote the passphrase with the shell's own rules.** Replace the hand-built double-quoted argument in
   `lock()` with `escapeshellarg($this->passphrase)`, which yields a single-quoted shell word with embedded
   quotes escaped correctly. Do the same for every other field that reaches the command line.

   ```php
   // control/classes/class.licensing.php:58  - corrected construction
   $lock[] = '--passphrase ' . escapeshellarg($this->passphrase);
   ```

2. **Remove the shell from the path.** Build the invocation with `proc_open()` and an argument array so
   that no shell parses the text. This is the durable fix: it eliminates the class of defect on this
   surface instead of filtering metacharacters one at a time.

   ```php
   $cmd = array(mswMakeLicensePath('', $this->settings), '--passphrase', $this->passphrase,
                '--allowed-server', $serverList, '-o', $output);
   $proc = proc_open($cmd, $descriptors, $pipes);
   ```

3. **Use the helpers the class already has.** `escapeArg()` and `escapeCmd()` exist at L49-55 and are
   applied only to `--header-line`. Either apply them to every interpolated value or delete them, so that
   their presence cannot be mistaken for coverage.

4. **Validate the passphrase as data.** Define and document an accepted character set for the licence
   passphrase, reject anything outside it with a field-level error, and enforce the rule server-side in the
   `generate` branch rather than only in the browser form. Reject the shell metacharacters explicitly even
   after quoting, as defence in depth.

5. **Reduce the blast radius independently of the fix.** Run the panel under an account that cannot write
   the application tree, keep the `make_license` binary outside any directory the web process can modify,
   and restrict the licence-generation screen to the administrators who actually use it.

6. **Add a regression test at the operation level.** Submit a `generate` request whose passphrase contains
   a double quote, a semicolon and a hash, and assert that the response is a validation error and that no
   file appears outside the intended output directory. Keep the test in the release suite so a future
   refactor of `lock()` cannot silently reintroduce the concatenation.

## 12. CWE

- **CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')** -
  primary and only mapping. The application constructs a command line from an operator-supplied string and
  passes it to `shell_exec()`, which executes it through `/bin/sh -c`; the string contains unescaped shell
  metacharacters supplied by the user.
- The mapping is deliberately narrow. This is not CWE-20 (improper input validation) at its root: the
  defect survives any validation rule that still permits ordinary passphrase characters, and it is fixed by
  quoting rather than by rejecting input. It is not CWE-89, CWE-94 or CWE-95: no SQL, no `eval()` and no
  dynamic code inclusion is involved. It is not a memory-safety defect and no such claim is made.

---
Written by the 0day Rubbish Research Team.
