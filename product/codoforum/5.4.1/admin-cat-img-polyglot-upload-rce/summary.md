# Codoforum — Admin Category-Image Polyglot Upload → www-data RCE

## Summary

Codoforum 5.4.1's admin category-image upload endpoint (`admin/modules/categories.php` `uploadFile()`) has an incomplete file-upload validation: it checks file content only with `getimagesize()` — **no extension whitelist** — and `move_uploaded_file()` uses the attacker-controlled `$_FILES['cat_img']['name']` directly (no `basename()`, no extension filtering). An admin uploads a GIF89a-header + PHP-body polyglot named `evil.php`; it bypasses `getimagesize`, lands in `sites/default/assets/img/cats/evil.php`, and Apache mod_php executes it → www-data RCE.

This is an **incomplete patch variant of CVE-2022-31854** (v5.1 logo-upload RCE): the vendor added a `.php` substring filter to the logo upload point, but the `cat_img` upload point was not fixed. Requires only an admin account (Target B) — no other preconditions on a default deployment.

## CVSS Score

- **Score**: 7.2 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Codoforum
- **Versions**: 5.4.1 verified; other versions with the same unpatched `cat_img` upload are likely affected
- **Vendor**: Codoforum
- **Prerequisite**: authenticated admin account

## Impact

- **Confidentiality**: arbitrary file read and data exfiltration as the web-server user (www-data)
- **Integrity**: arbitrary PHP code execution on the forum server
- **Availability**: full compromise of the forum application and commonly the underlying host

## Mitigation

1. Apply a unified extension whitelist (`gif,jpg,jpeg,png`) to every upload point, including `cat_img`
2. Use `basename()` plus a randomized server-generated filename, discarding the attacker-supplied name
3. Block PHP execution in the `cats/` upload directory (`.htaccess` `php_flag engine off` or FilesMatch deny)
4. Validate Content-Type + extension + content together (MIME sniffing defense)
