# Maian Cart 3.8 — Unrestricted `addBanners` Banner Upload Enables Webshell Write and RCE (Administrator Session Required)

Advisory: https://0day-rubbish.com/blog/maian-cart-addbanners-upload-extension-webshell-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Maian Cart is a self-hosted PHP shopping-cart system from Maian Media (Maian Script World), deployed inside a web server document root (the research record asserts Apache + mod_php as the default production deployment, without citing a vendor document). In version 3.8, the administration backend's Store Banners feature (`/admin/index.php?p=settings&s=9`) passes multipart uploads to `addBanners()` (`admin/control/classes/class.system.php:376-413`), which renames the stored file to `img_<id>.<ext>` while taking `<ext>` verbatim from the client-supplied filename — no extension allow-list, no MIME validation, no `getimagesize()` content check anywhere on the path. The file is written with `move_uploaded_file` (sink recorded at class.system.php:401) into `content/_theme_default/images/banners/` under the web root, before the database INSERT runs, so the write survives even a failing INSERT. Unlike the product's other sensitive directories — `admin/import/`, `admin/attachments/` and `content/_theme_default/cache/` each ship an `.htaccess` with `Deny from all` — the banners directory carries no deny rule, so a stored `img_<id>.php` is parsed by the PHP interpreter on a plain GET. A one-line `shell_exec` webshell therefore yields OS command execution as the web server user; the verified laboratory run returned `uid=0(root)` because its server ran as root. The same product already enforces an image allow-list (`$imgAllow = array('.jpg','.jpeg','.png','.gif')`, class.products.php:9) in its product-image upload handler — the banner handler simply lacks that check.

The upload endpoint sits behind the webmaster session gate (`mc_isWebmasterLoggedIn` at system-load.php:79) and the login form's `cs_rf` CSRF token flow, both handled by the exploit once administrator credentials are held. This advisory is classified as post-authentication: an exhaustive review ruled out every unauthenticated candidate — `ajax.php` reaches no RCE sink, forging the persistent admin cookie requires the per-installation `DB_NAME` inside `mc_encrypt(SECRET_KEY . DB_NAME)`, no POP gadget exists, and the login path is not injectable. No unauthenticated route to the sink is claimed. A separate deployment-state observation is reported alongside: the installer-provisioned administrator credential (`USERNAME`/`PASSWORD` written into `access.php` by the install wizard) is never forced to rotate, so installations retaining known or guessable credentials reduce the gate to a formality — that companion weakness (CWE-798-class) is the sole basis for the explicitly conditional PR:N reading below and does not reclassify the primary finding. The chain was verified end to end against a real 3.8 installation (product install wizard run to completion, MySQL 8.0.46 backend) in three independent recorded runs, including a from-scratch re-analysis that shipped a second shell (`img_3.php`) through the same handler.

## CVSS Score

- **Score**: 7.2 High (CVSS version 3.1) — primary classification, administrator session required
- **Vector**: AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2
- `PR:H` because the sink is reachable only through the webmaster gate; the unauthenticated surface was exhaustively reviewed and reaches no RCE sink (`ajax.php` sink-less; admin-cookie forgery blocked by the per-installation `DB_NAME` in `mc_encrypt(SECRET_KEY . DB_NAME)`)
- Conditional reading only (deployment state, not product state), and this advisory's own construction rather than a figure from the research record, which scores the finding only under the `PR:H` vector above and records the unauthenticated objective as not reached: if the installer-provisioned admin credential is never rotated and is known or guessable, the effective vector becomes AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 — published explicitly as conditional; it does not change the primary classification

## Affected Products

- Maian Cart 3.8 (PHP shopping cart, Maian Media / Maian Script World) in default configuration: `RENAME_BANNERS=1` (options.php:308), `BANNER_PREFIX='img_'` (options.php:307), `BANNER_FOLDER='{theme}/images/banners'` (control/options.php:489), `THEME_FOLDER='content/_theme_default'` (init.php:36) — every constant the exploit relies on ships in the state it expects
- Verified by execution: 3.8 — real installation, three independent dynamic runs against a loopback-bound laboratory instance
- Other versions: not tested; no claim is made beyond 3.8 from this research
- Prerequisite: an administrator account provisioned by the install wizard (no forced rotation — companion observation); unauthenticated reachability was investigated and ruled out
- Precondition whose provenance is unestablished: the banners directory `content/_theme_default/images/banners/` must already exist on disk. It was absent in the first laboratory iteration, the upload failed with "No such file or directory" until it was created manually, and no artifact examined here establishes which product component creates it — `move_uploaded_file` does not create directories and the handler guards only the destination file, so this advisory claims no first-upload directory creation

## Impact

A webshell written into an executing directory under the document root means arbitrary OS command execution as the web server process (`uid=0(root)` in the laboratory; typically www-data/apache in production mod_php deployments): full read/write access to store source, configuration and database credentials, the MySQL-backed orders and customer records, persistent implants that survive sessions and restarts, and a pivot point into adjacent network segments. For insiders or credential-holders the upload is audit-invisible — it appears in the interface as an ordinary banner addition.

## Mitigation

1. Enforce an extension allow-list in `addBanners()`/`updateBanners()` reusing the `$imgAllow` control already present in class.products.php (root-cause fix)
2. Validate uploaded content with `getimagesize()`/`finfo` MIME checks before persisting, rejecting image-extension polyglots
3. Discard the client-supplied extension entirely — name stored files server-side with a fixed extension derived from the validated type
4. Make banner storage non-executable: move `BANNER_FOLDER` outside the document root, or ship a deny configuration for the banners directory (`.htaccess` `php_flag engine off` / `Deny from all`, matching the pattern already shipped for `admin/import/`) plus documented nginx-equivalent guidance
5. Route every `move_uploaded_file` call site through one shared upload validator so handlers cannot drift apart
6. Force first-login rotation of the installer-provisioned administrator credential and promote the `access.php` hardening note into an enforced step
