# Disclosure Status — Altus Sistemas de Automação iX Developer

> This file records the public-disclosure and vendor-notification status for the vulnerability documented in this directory. It is the single source of truth for "is this finding public / disclosed / CVE'd?" within the repo.

## Finding

| Field | Value |
|---|---|
| Advisory # | #11 |
| Vendor | Altus Sistemas de Automação |
| Product | iX Developer |
| Affected version | 2.53.65422 |
| Vulnerability class | XAML Deserialization RCE via Malicious Screen File |
| CVSS | **7.3** |
| PoC | `exploit/` in this directory |

## Public disclosure

**Status: COMPLETE — publicly disclosed.**

- **Blog post**: <https://0day-rubbish.com/blog/altus-ix-developer-xaml-rce>
- **Published**: July 18, 2026
- Full root-cause analysis + working, reproducible PoC are public. No details withheld.

## Vendor notification

Vendor notified 2026-07-30 (altus@altus.com.br, cc cert@cert.br).

## CVE status

Submitted to MITRE on 2026-07-30 (CWE-502). Awaiting CVE ID.

## Channel separation (per project CONSTRAINTS)

- Public research (this blog post + PoC) is the **independent public channel** — free and disclosed.
- Any commercial hardening engagement with this vendor would be a **separate, NDA-protected channel** and is never implied by this disclosure.
- Disclosure correspondence uses `disclosure@0day-rubbish.com` only; sales correspondence uses `sales@0day-rubbish.com`. The two channels never mix.

---
*Last updated: 2026-08-02 by 0day Rubbish Research Team.*
