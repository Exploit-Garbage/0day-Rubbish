# Maian Cube 1.x - License-Generation Passphrase Command Injection Executing as the PHP Process User

Advisory: https://0day-rubbish.com/blog/license-gen-command-injection-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Maian Cube is a PHP application published by Maian Script World and built on the vendor's shared Maian
Media framework. Inside that family it holds a distinct role: it is the only member that *generates*
licences for ionCube-encoded products. The sibling products consume a licence file; Maian Cube is the tool
an integrator runs to produce one. Generation is not implemented in PHP. The application assembles a
parameter string and hands it to an external `make_license` binary through `shell_exec()`, so every licence
field the operator types - including the encryption passphrase - becomes text on a `/bin/sh -c` command
line.

The passphrase is the defect. In `control/classes/class.licensing.php` the `lock()` method builds the
`--passphrase` argument by placing the raw submitted value inside double quotes and concatenating it into
the command string, and the class's own escaping helpers are never applied to it. A passphrase that carries
a double quote, a semicolon and a hash therefore closes the quote, terminates the pending `make_license`
invocation, runs attacker-chosen command text under the web server's identity and comments out the rest of
the original command line. The handler does not restrict the character set: the `generate` branch only
requires its three fields to be non-empty. Because PHP executes the whole string through a shell, the
injected command runs even when the external binary is missing or the licence file is never produced - the
interface reports failure while the command has already executed.

The action is authenticated. It sits behind the store administrator session, the per-install CSRF token and
a request gate that exempts only the `login` operation. It is not a default-credential finding and it is not
a privilege-escalation chain: it converts an administrative licence-creation screen into an arbitrary
command channel at the privilege level of the PHP/Apache process.

- Component: the licence-generation screen of the Maian Cube admin panel, reached by POST to
  `/admin/index.php?ajax-ops=generate` with the `X-Requested-With: XMLHttpRequest` header and handled by
  `admin/control/system/_ajax.php` in its `case 'generate'` branch
- Sink: `shell_exec()` inside `cubeLicense::create()` at `control/classes/class.licensing.php:193`, whose
  command string embeds the argument list assembled by `cubeLicense::lock()` at `class.licensing.php:57-60`
- Source: the `passphrase` POST parameter, forwarded unfiltered at `_ajax.php:106` and assigned unfiltered in
  the `cubeLicense` constructor at `class.licensing.php:32`
- Sanitization: none. No `escapeshellarg()`, `escapeshellcmd()`, `addslashes()`, `strip_tags()` or character
  allowlist is applied anywhere between the request and the shell; the class's `escapeArg()` and
  `escapeCmd()` helpers (L49-55) exist but are only used for the `--header-line` argument at L98
- Authentication class: Authenticated - the operation requires a store administrator session, and the
  request gate that protects the admin dispatcher exempts only `login`, not `generate`

The chain was verified end to end against a complete deployment of the application rather than against a
reduced model of it: a Docker Compose stack carrying MySQL and the application on PHP 8.2 / Apache, bound to
loopback at `127.0.0.1:8191`, running the real login handler, the real AJAX dispatcher and the real
licensing class. Four injected commands produced four marker files, each owned by `www-data` (uid=33) and
each holding the output of the injected command, with the markers read back inside the container that
executed them. No physical or virtual appliance image was involved and no firmware was disassembled; the
evidence is application-level, and the observed identity is the Apache/PHP process user of that deployment.

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network - the admin panel is an ordinary HTTP service on the application host; no adjacency
  requirement, no local shell, no physical access
- Attack Complexity: Low - a single authenticated POST carrying one crafted form field is the entire
  detonation; there is no race, no timing window and no multi-step state machine
- Privileges Required: High - the operation is gated behind an authenticated store administrator session,
  and no lower-privilege panel account is documented as reaching the licensing screen
- User Interaction: None - the credential holder drives the request directly; no victim action is required
- Scope: Unchanged - the substituted command executes as the application's own process user, inside the
  authority of the component whose interface was abused
- Impact C/I/A: all High - arbitrary command execution as the PHP process user yields the application's
  configuration store and database credentials, write access to the deployed code, and full control of
  service availability
- CWE: CWE-78 (improper neutralization of special elements used in an OS command)
- Published arithmetic: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107826, rounded up to 7.2

Privileges Required is High rather than the neighbouring lower tier because reaching this sink requires a
credential the product does not hand out to ordinary users. The `generate` operation is served by the admin
dispatcher only after the session flag `cube_access` is set, the gate at `admin/control/system/_ajax.php`
L15-23 rejects every operation except `login` when that flag is absent, and the licensing screen is part of
the administrator interface rather than a storefront or customer-facing page. The application does not ship
a second, less-privileged panel account class that can reach the licence generator: the account that opens
that screen is the account that administers the store. An attacker must therefore already hold
administrator-level authority, which is exactly what PR:H models, and the value of the finding is not that
it grants that authority but that it converts it into operating-system command execution that the
administrator interface was never intended to provide.

A rejected reading is recorded here so that no downstream channel quotes it as the headline. Reading the
same impact profile as though a low-privileged panel user could reach the licence generator gives
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High, whose arithmetic is ISS 0.914816, Impact
5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255 and sum 8.708361 rounded up to 8.8.
That vector is rejected: the artifacts examined for this advisory document one administrator account class
for the panel, and the `generate` branch is reachable only from it, so no principal exists to justify Low
privileges on this path.

## Affected Products

- Maian Cube 1.x, the PHP storefront and licence-generation product from Maian Script World, built on the
  Maian Media framework and deployed on PHP 8.2 with Apache 2.4 and MySQL 8.0; affected component:
  `control/classes/class.licensing.php` (class `cubeLicense`), reached through
  `admin/control/system/_ajax.php` operation `generate`
- The vulnerability is in shipped application code, not in the deployment: the escaping gap is present in
  `class.licensing.php` as delivered, and no configuration switch, plugin or theme removes it
- Not claimed: other Maian Media products. The family's remaining members consume licences rather than
  generate them, and a search for `class cubeLicense` and `mswMakeLicensePath` across the family returns no
  hits outside Maian Cube, so the sink is not shared by inheritance; the product versions other than the
  1.x line analyzed here were not audited
- Verification method and its boundary: end-to-end execution against a containerized deployment of the
  application on an isolated host, with the injected commands' output read back from inside the container
  that ran them. The observed command-execution identity is `www-data` (uid=33), the Apache/PHP process user
  of that deployment. No privilege escalation beyond that identity was attempted or observed, and the marker
  evidence is the measured proof of that identity inside that deployment only

## Impact

- Conversion of an administrative licence-creation screen into an arbitrary command channel: an attacker who
  holds - or has taken - an administrator session can execute operating-system commands as the PHP process
  user without any further interaction with the product's intended functionality
- Disclosure of every secret the application can read with that identity, including its database connection
  parameters and configuration files, because the command executes inside the document root's own runtime
  context
- Integrity loss across the deployed application: the command runs as the identity under which the
  application reads and writes its own files, so injected code, altered licensing logic or modified templates
  are within reach of the same request wherever that deployment's file permissions let the web user write
- Availability impact at will: the command can stop or restart the service, exhaust its resources or remove
  files the application needs, and the licence-generation response gives the attacker no obstacle in doing
  so
- A durable foothold consistent with command execution as a service account, bounded by what that account
  can write in the deployment; persistence across a rebuild of the container or a redeployment was not
  tested and is not claimed
- A quiet path: the malicious request is a normal authenticated AJAX call to the licensing screen, the
  interface answers with its ordinary error envelope, and the command has already run by the time that
  response is rendered

## Mitigation / Fix Recommendations

1. Quote the passphrase for the shell instead of wrapping it in literal double quotes. In `lock()`, replace
   the concatenation of `'--passphrase "'` with `escapeshellarg($this->passphrase)`, which produces a
   single-quoted argument whose embedded quotes are escaped correctly. Apply the same treatment to every
   other field that reaches the command line.
2. Remove the shell from the call path. Build the `make_license` invocation with `proc_open()` (or
   `exec()`-family functions) taking an argument array, so no shell parses the operator's text and the
   injection class disappears rather than being filtered. PHP's array form bypasses `/bin/sh` entirely and
   is the durable fix.
3. If a shell must stay in the path in the short term, pass every value through the class's existing
   `escapeArg()` helper - not only `--header-line` - and add a construction-time assertion that the compiled
   command line contains no unescaped `;`, `` ` ``, `$(`, `#` or quote character before it is handed to
   `shell_exec()`.
4. Validate the passphrase as data rather than as shell text: accept a documented character set for the
   licence passphrase, reject the rest with a field-level error, and enforce the same rule on the server
   side of the `generate` operation rather than in the browser form only.
5. Reduce the blast radius independently of the fix: run the admin panel under a dedicated account with no
   write access to the application tree, and keep the licence generator's `make_license` binary outside any
   directory the web process can modify.
6. Restrict the licensing screen to the smallest set of administrators who need it, and treat administrator
   sessions on installations that use licence generation as sensitive credentials until a patched build is
   available.

## References

- https://0day-rubbish.com/blog/license-gen-command-injection-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
