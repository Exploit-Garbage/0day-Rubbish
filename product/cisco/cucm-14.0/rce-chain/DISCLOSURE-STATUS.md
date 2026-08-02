# Disclosure Status — Cisco Unified Communications Manager (CUCM)

> This file records the public-disclosure and vendor-notification status for the vulnerability documented in this directory. It is the single source of truth for "is this finding public / disclosed / CVE'd?" within the repo.

## Finding

| Field | Value |
|---|---|
| Advisory # | #7 |
| Vendor | Cisco |
| Product | Unified Communications Manager (CUCM) |
| Affected version | 14.0 |
| Vulnerability class | Six-Stage Pre-Authentication RCE Chain |
| CVSS | **9.8** |
| PoC | `exploit/` in this directory |

## Public disclosure

**Status: COMPLETE — publicly disclosed.**

- **Blog post**: <https://0day-rubbish.com/blog/cisco-cucm-rce-chain>
- **Published**: July 8, 2026
- Full root-cause analysis + working, reproducible PoC are public. No details withheld.

## Vendor notification

Vendor PSIRT notified 2026-07-30 (psirt@cisco.com); initial inbound filter bounce → PGP-encrypted resend (Cisco PSIRT public key 081E 38F3 EB11 0265 A214 5141 24B3 EC61 E420 5802).

## CVE status

Cisco is a CNA — handled via Cisco PSIRT, NOT submitted to MITRE. Awaiting Cisco case/CVE.

## Channel separation (per project CONSTRAINTS)

- Public research (this blog post + PoC) is the **independent public channel** — free and disclosed.
- Any commercial hardening engagement with this vendor would be a **separate, NDA-protected channel** and is never implied by this disclosure.
- Disclosure correspondence uses `disclosure@0day-rubbish.com` only; sales correspondence uses `sales@0day-rubbish.com`. The two channels never mix.

---
*Last updated: 2026-08-02 by 0day Rubbish Research Team.*
