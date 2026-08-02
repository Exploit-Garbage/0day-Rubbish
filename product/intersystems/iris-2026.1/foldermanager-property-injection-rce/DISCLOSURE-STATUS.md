# Disclosure Status — InterSystems IRIS

> This file records the public-disclosure and vendor-notification status for the vulnerability documented in this directory. It is the single source of truth for "is this finding public / disclosed / CVE'd?" within the repo.

## Finding

| Field | Value |
|---|---|
| Advisory # | #1 |
| Vendor | InterSystems |
| Product | IRIS |
| Affected version | 2026.1.0.234.1 |
| Vulnerability class | Unauthenticated RCE via FolderManager Property Injection |
| CVSS | **9.8** |
| PoC | `exploit/` in this directory |

## Public disclosure

**Status: COMPLETE — publicly disclosed.**

- **Blog post**: <https://0day-rubbish.com/blog/intersystems-iris-foldermanager-rce>
- **Published**: July 16, 2026
- Full root-cause analysis + working, reproducible PoC are public. No details withheld.

## Vendor notification

Vendor PSIRT notified 2026-07-30 via disclosure@0day-rubbish.com (psirt@intersystems.com).

## CVE status

Submitted to MITRE via cveform-legacy.mitre.org on 2026-07-30 (CWE-915). Awaiting CVE ID.

## Channel separation (per project CONSTRAINTS)

- Public research (this blog post + PoC) is the **independent public channel** — free and disclosed.
- Any commercial hardening engagement with this vendor would be a **separate, NDA-protected channel** and is never implied by this disclosure.
- Disclosure correspondence uses `disclosure@0day-rubbish.com` only; sales correspondence uses `sales@0day-rubbish.com`. The two channels never mix.

---
*Last updated: 2026-08-02 by 0day Rubbish Research Team.*
