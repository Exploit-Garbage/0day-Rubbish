# Maian Gallery — Authenticated Admin RCE via Unrestricted File Upload (upload_thumbnail)

## Summary

Maian Gallery v2.1 (Maian Media, self-hosted PHP photo gallery) contains an authenticated arbitrary file upload in the "add images" admin flow. `upload_thumbnail()` calls `move_uploaded_file()` with **no extension whitelist** — `filter_file_path()` preserves the original extension (`.php` is kept). The MIME check uses the client-controlled `$_FILES['thumb']['type']` (`substr($type,0,5)=='image'`), not server-side finfo content detection, so a spoofed `image/gif` passes without a polyglot.

The file lands in `content/galleries/<folder>/<cat_folder>/`, which is web-reachable and ships **without** an `.htaccess` blocking PHP execution. The vulnerable `move_uploaded_file` path is the default deployment (installer seeds `autothumb=0`).

Result: an authenticated admin uploads a `.php` webshell and executes arbitrary commands as the web-server user (uid 0 root in the research deployment). CVSS 7.2 (authenticated admin to RCE).

## CVSS Score

- **Score**: 7.2 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Maian Gallery (self-hosted PHP photo gallery)
- **Version**: 2.1
- **Vendor**: Maian Media (David Ian Bennett)
- **Stack**: PHP + MySQL, admin control panel in `admin/`

## Impact

- **Confidentiality**: arbitrary command execution as the web-server user; gallery files and server data exposed
- **Integrity**: arbitrary file upload and command execution on the host
- **Availability**: full control of the gallery application and (typically) the underlying host

## Mitigation

1. Add an extension whitelist to `upload_thumbnail` (jpg/jpeg/png/gif/webp); reject `.php`/`.phtml`/`.phar`
2. Replace the client-supplied `$_FILES['type']` check with server-side `finfo_file()` content detection
3. Place an `.htaccess` (or equivalent) in upload directories to disable PHP execution
4. Force `filter_file_path` to rename uploads to whitelisted extensions instead of preserving the original
