# ActFax Unauthenticated LPD Ghostscript %pipe% SYSTEM RCE

## Summary

A critical unauthenticated remote code execution vulnerability in ActFax (ActiveFax Server) v10.70 allows a remote attacker to execute arbitrary commands as `NT AUTHORITY\SYSTEM` by sending a crafted print job to the LPD/LPR service (TCP 515, no authentication). The bundled Ghostscript 9.22 (< 9.50) runs without `-dSAFER`, so a PostScript body containing the `%pipe%` operator executes a shell command with the privileges of the ActSrvNT service (LocalSystem). The LPD service accepts any queue name, so a default installation is exploitable.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: ActFax (ActiveFax Server)
- **Versions**: 10.70 Build 0609 (latest as of 2026-04-07; older versions with the same bundled Ghostscript are likely affected)
- **Vendor**: ActFax Communication Software

## Impact

- **Confidentiality**: Full system compromise as SYSTEM
- **Integrity**: Arbitrary command execution via Ghostscript %pipe%
- **Availability**: Full control of the ActFax host

## Mitigation

1. Upgrade the bundled Ghostscript to 9.50+ (SAFER sandbox enabled by default)
2. Restrict LPD port 515 to trusted networks or disable it if not required
3. Run the ActSrvNT service with least privilege instead of LocalSystem
4. Restrict unauthenticated LPD jobs and validate queue names
