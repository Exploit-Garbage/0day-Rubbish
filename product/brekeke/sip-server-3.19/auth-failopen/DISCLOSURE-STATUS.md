# Disclosure Status — Brekeke SIP Server

> This file records the public-disclosure and vendor-notification status for the vulnerability documented in this directory. It is the single source of truth for "is this finding public / disclosed / CVE'd?" within the repo.

## Finding

| Field | Value |
|---|---|
| Advisory # | #8 |
| Vendor | Brekeke |
| Product | SIP Server |
| Affected version | v3.19.1.8p1 |
| Vulnerability class | Authentication Fail-Open → 23 Unauthenticated Beans |
| CVSS | **9.1** |
| PoC | `exploit/` in this directory |

## Public disclosure

**Status: COMPLETE — publicly disclosed.**

- **Blog post**: <https://0day-rubbish.com/blog/brekeke-sip-server-auth-failopen>
- **Published**: July 15, 2026
- Full root-cause analysis + working, reproducible PoC are public. No details withheld.

## Vendor notification

Vendor notified 2026-07-30 (info@brekeke.com).

## CVE status

Submitted to MITRE on 2026-07-30 (CWE-287, Incorrect Access Control). Awaiting CVE ID.

## Channel separation (per project CONSTRAINTS)

- Public research (this blog post + PoC) is the **independent public channel** — free and disclosed.
- Any commercial hardening engagement with this vendor would be a **separate, NDA-protected channel** and is never implied by this disclosure.
- Disclosure correspondence uses `disclosure@0day-rubbish.com` only; sales correspondence uses `sales@0day-rubbish.com`. The two channels never mix.

---
*Last updated: 2026-08-02 by 0day Rubbish Research Team.*
