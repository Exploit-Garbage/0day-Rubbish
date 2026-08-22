# myDBR — Admin File-Editor PHP Code Injection RCE

## Summary

An authenticated remote code execution vulnerability in myDBR 7.5.4 (Softronic Oy, self-hosted PHP reporting tool). The admin "Files" page file editor (`apps_v/fileedit_v.php`) writes attacker-controlled PHP content into arbitrary files under the web root; a crafted upload of a PHP file, followed by a direct request, executes PHP code as `www-data` (CWE-94). Authentication is the default admin credential `dba/dba` (challenge-response login; CWE-798).

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: myDBR (self-hosted reporting)
- **Versions**: 7.5.4 / build 5454 (other versions with the same file-editor are likely affected)
- **Vendor**: Softronic Oy

## Impact

- **Confidentiality**: Full read of report/database-facing data as `www-data`
- **Integrity**: Arbitrary PHP code execution in the web server context
- **Availability**: Full control of the reporting host

## Mitigation

1. Restrict the file editor to a dedicated, non-executable template directory
2. Reject PHP-extension writes from the editor
3. Force password change for the default `dba` account
4. Enforce least privilege on the web-server OS account
