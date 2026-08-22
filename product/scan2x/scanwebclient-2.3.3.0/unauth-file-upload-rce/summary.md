# Scan2x ScanWebClient — Unauthenticated File Upload → Webshell RCE

## Summary

An unauthenticated remote code execution vulnerability in Scan2x ScanWebClient 2.3.3.0. The `FileUploadHandler.ashx` handler saves any uploaded file (original extension preserved, no whitelist, no MIME/content check) to the web root `_ScannedFiles/` directory via `SaveAs`, and `_ScannedFiles/` ships without a `web.config` blocking handler, so IIS executes `.aspx` files placed there. An attacker uploads an ASPX webshell and reaches it directly, executing commands as the `iis apppool\scan2xscanwebclientpool` identity (CWE-434 → CWE-94). No authentication is required (`<allow users="*"/>` + empty `Application_BeginRequest`).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Scan2x ScanWebClient
- **Versions**: 2.3.3.0 (other versions with the same handler are likely affected)
- **Vendor**: Avantech Software (UK)

## Impact

- **Confidentiality**: Full read access to scanned documents and host files
- **Integrity**: Arbitrary ASPX execution in the IIS app pool context
- **Availability**: Full control of the ScanWebClient host

## Mitigation

1. Add an extension whitelist to `FileUploadHandler` (PDF/TIF/JPG/PNG scan formats only)
2. Store uploads outside the web root or add a `web.config` handler blocker to `_ScannedFiles/`
3. Validate MIME and content signatures before saving
4. Run the app pool with least privilege
