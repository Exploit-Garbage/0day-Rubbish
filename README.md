# 0day Rubbish

> **0day vulnerabilities have become rubbish in the AI era.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![0-days disclosed](https://img.shields.io/badge/0--days_disclosed-11-red)](https://0day-rubbish.com/blog)
[![Max CVSS](https://img.shields.io/badge/Max_CVSS-9.8-critical)](https://0day-rubbish.com/blog)
[![PoC](https://img.shields.io/badge/Every_advisory-working_PoC-blue)](https://0day-rubbish.com/blog)
[![Website](https://img.shields.io/badge/Website-0day--rubbish.com-brightgreen)](https://0day-rubbish.com)

**🌐 Official Website**: <https://0day-rubbish.com/blog>

---

## 📋 Disclosed Vulnerabilities

An AI-driven research process (multi-LLM ensemble: Claude, OpenAI, DeepSeek, GLM) discovers 0-days in real-world enterprise software. Every advisory below ships a **full root-cause analysis** plus a **working, reproducible exploit script** — no detection-only writeups, no withheld details.

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | InterSystems IRIS | 2026.1.0.234.1 | **9.8** | Unauth RCE | [FolderManager Property Injection → RCE](https://0day-rubbish.com/blog/intersystems-iris-foldermanager-rce) |
| 2 | AdRem NetCrunch | 16.0.0.8397 RC | **9.8** | Unauth RCE (SYSTEM) | [Cross-Session Hijack → RCE](https://0day-rubbish.com/blog/adrem-netcrunch-session-hijack-rce) |
| 3 | Altus BluePlant | 9.1.40 | **9.8** | Unauth RCE | [Hardcoded Credentials → RCE](https://0day-rubbish.com/blog/altus-blueplant-hardcoded-creds-rce) |
| 4 | Brekeke SIP Server | v3.19.1.8p1 | **9.8** | Unauth RCE | [Nashorn JS Engine → RCE](https://0day-rubbish.com/blog/brekeke-sip-server-nashorn-rce) |
| 5 | Brekeke SIP Server | v3.19.1.8p1 | **9.8** | Unauth RCE (Zip Slip) | [Zip Slip Webshell → RCE](https://0day-rubbish.com/blog/brekeke-sip-server-zipslip-rce) |
| 6 | DataSunrise Suite | 11.2.17.12820 | **9.8** | Unauth RCE | [Email Verification Brute Force → RCE](https://0day-rubbish.com/blog/datasunrise-email-bruteforce-rce) |
| 7 | Cisco CUCM | 14.0 | **9.8** | RCE Chain | [Multi-stage RCE Chain](https://0day-rubbish.com/blog/cisco-cucm-rce-chain) |
| 8 | Brekeke SIP Server | v3.19.1.8p1 | **9.1** | Auth Bypass | [Auth Fail-Open → 23 Unauth Beans](https://0day-rubbish.com/blog/brekeke-sip-server-auth-failopen) |
| 9 | Acumatica ERP | 2026 R1 | **8.8** | Auth RCE | [Customization Publish Webshell → RCE](https://0day-rubbish.com/blog/acumatica-customization-webshell-rce) |
| 10 | AdRem NetCrunch | 16.0.0.8397 RC | **8.8** | Auth RCE (SYSTEM) | [Startup Script → RCE](https://0day-rubbish.com/blog/adrem-netcrunch-startup-script-rce) |
| 11 | Altus iX Developer | 2.53.65422 | **7.3** | Local/UI RCE | [XAML Deserialization → RCE](https://0day-rubbish.com/blog/altus-ix-developer-xaml-rce) |

**Totals**: 11 advisories · 8 vendors · 7 critical (CVSS ≥ 9.0) · 9 unauthenticated · all with reproducible PoC.

---

## 🔁 This is an Ongoing Series — Not a One-Time Dump

This is **Batch #1**. The AI-driven discovery pipeline runs continuously, and new batches of verified 0-days with full PoCs are published on a regular cadence.

- **Last batch**: 2026-07-15 (11 advisories)
- **Next batch**: **August 2026** — coming soon
- **Future scope**: expanding beyond enterprise IT into **ICS / SCADA, energy, and aerospace** systems

If you want to catch the next drop the moment it lands:

[![Star](https://img.shields.io/badge/⭐_Star-bookmark_this_repo-yellow)](https://github.com/Exploit-Garbage/0day-Rubbish) [![Watch](https://img.shields.io/badge/👁_Watch-get_notified_on_new_batches-blue)](https://github.com/Exploit-Garbage/0day-Rubbish/subscription) [![Blog](https://img.shields.io/badge/🌐_Follow-0day--rubbish.com%2Fblog-brightgreen)](https://0day-rubbish.com/blog)

> ⭐ **Star** to bookmark · 👁 **Watch** (custom → Releases + Discussions) for new batches · 🌐 **Follow** the blog for per-advisory updates.

---

## 🎯 Why This Exists

Traditional vulnerability disclosure is broken. It's slow, bureaucratic, and ineffective. In the AI era, we can mass-produce 0days at scale—making individual vulnerabilities less valuable but more impactful when disclosed directly.

We believe **event-driven security hardening** is the most effective approach: only when vendors face real, exploitable threats do they prioritize fixes.

## 🔄 Our Disclosure Process

### Step 1: AI Discovery
Our automated AI systems continuously scan for vulnerabilities across real-world software, identifying potential 0days through pattern analysis, fuzzing, and intelligent code review.

### Step 2: Verification & PoC Development
Each finding undergoes manual validation. We develop working proof-of-concept exploits to confirm exploitability and assess real-world impact.

### Step 3: Irregular Public Disclosure
We periodically disclose verified, exploitable 0day vulnerabilities we've discovered and validated:
- Full technical analysis and root cause
- Working PoC exploit code
- Affected versions and systems
- Impact assessment
- Recommended mitigations

No delays. No bureaucracy. Just facts.

**To all vendors**: We hope you can complete fixes before hackers exploit these vulnerabilities.

## ⚡ Core Principles

- **Real-world impact only**: We disclose only vulnerabilities that affect real-world systems with actual user bases
- **No worthless targets**: Non-exploitable vulnerabilities or devices with negligible user adoption are excluded—they're rubbish with zero value
- **Speed over protocol**: Direct disclosure drives faster action than traditional channels
- **Proof over claims**: Every disclosure includes working exploits
- **Impact over quantity**: Focus on high-severity, widely-deployed vulnerabilities
- **Transparency**: Full technical details, no hidden agendas
- **Non-profit**: Driven by passion for security research, not financial gain

## 🤝 Collaboration

We partner with:
- Top AI model providers advancing automated security research
- Security researchers exploring AI-powered discovery

## 🤖 AI Models Used

Our automated vulnerability discovery leverages cutting-edge large language models:
- **GPT-5.5** - Advanced reasoning and code analysis
- **Claude Opus 4.8** - Deep security pattern recognition
- **DeepSeek V4** - Specialized vulnerability detection

## 📂 Vulnerability Submission Format

All disclosed vulnerabilities follow a standardized directory structure:

```
product/
└── <product_name>/
    └── <version>/
        └── <vulnerability_type>/
            ├── exploit/          # Exploit scripts and PoC code
            ├── analysis.md       # Detailed vulnerability analysis
            └── summary.md        # Brief vulnerability overview
```

### Directory Rules

- **product/**: Root directory for all vulnerabilities
- **<product_name>/**: Vendor or product name (e.g., `apache`, `microsoft`, `oracle`)
- **<version>/**: Affected version range (e.g., `2.4.49`, `11.0.12`)
- **<vulnerability_type>/**: CVE-style classification (e.g., `rce`, `sql-injection`, `auth-bypass`)

### Required Files in Each Vulnerability Directory

1. **exploit/**: Directory containing working exploit scripts and PoC code
2. **analysis.md**: Comprehensive technical analysis including root cause, attack vector, and impact
3. **summary.md**: Concise vulnerability overview with affected versions and quick mitigation steps

### Example

```
product/
└── apache/
    └── 2.4.49/
        └── path-traversal/
            ├── exploit/
            │   ├── poc.py
            │   └── exploit.sh
            ├── analysis.md
            └── summary.md
```

---

**Join us in redefining vulnerability disclosure for the AI era.**
