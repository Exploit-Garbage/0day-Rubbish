# Disclosure Status — SonicWall SMA 1000

> This file records the public-disclosure and vendor-notification status for the vulnerability documented in this directory. It is the single source of truth for "is this finding public / disclosed / CVE'd?" within the repo.

## Finding

| Field | Value |
|---|---|
| Advisory # | #12 |
| Vendor | SonicWall |
| Product | SMA 1000 |
| Affected version | 12.4 |
| Vulnerability class | Pre-Authentication Deserialization RCE |
| CVSS | **9.8** |
| PoC | `exploit/` in this directory |

## Public disclosure

**Status: COMPLETE — publicly disclosed.**

- **Blog post**: <https://0day-rubbish.com/blog/sonicwall-sma-preauth-deserialization-rce>
- **Published**: July 26, 2026
- Full root-cause analysis + working, reproducible PoC are public. No details withheld.

## Vendor notification

NOT YET notified — vendor disclosure (psirt@sonicwall.com) pending. Blog published 2026-07-26; formal vendor notification not yet sent.

## CVE status

NOT YET submitted — CVE ID request to MITRE and/or SonicWall PSIRT CNA coordination pending.

## Channel separation (per project CONSTRAINTS)

- Public research (this blog post + PoC) is the **independent public channel** — free and disclosed.
- Any commercial hardening engagement with this vendor would be a **separate, NDA-protected channel** and is never implied by this disclosure.
- Disclosure correspondence uses `disclosure@0day-rubbish.com` only; sales correspondence uses `sales@0day-rubbish.com`. The two channels never mix.

---
*Last updated: 2026-08-02 by 0day Rubbish Research Team.*
