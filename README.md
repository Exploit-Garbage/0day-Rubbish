# 0day Rubbish

> **0day vulnerabilities have become rubbish in the AI era.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Latest batch](https://img.shields.io/badge/Latest_batch-8_advisories-red)](https://0day-rubbish.com/blog)
[![Max CVSS](https://img.shields.io/badge/Max_CVSS-9.8-critical)](https://0day-rubbish.com/blog)
[![PoC](https://img.shields.io/badge/Every_advisory-working_PoC-blue)](https://0day-rubbish.com/blog)
[![Website](https://img.shields.io/badge/Website-0day--rubbish.com-brightgreen)](https://0day-rubbish.com)
[![Watchers](https://img.shields.io/github/watchers/Exploit-Garbage/0day-Rubbish?style=flat&logo=github)](https://github.com/Exploit-Garbage/0day-Rubbish/subscription)
[![Discussions](https://img.shields.io/github/discussions/Exploit-Garbage/0day-Rubbish?logo=github)](https://github.com/Exploit-Garbage/0day-Rubbish/discussions)
[![Last commit](https://img.shields.io/github/last-commit/Exploit-Garbage/0day-Rubbish?style=flat&logo=git)](https://github.com/Exploit-Garbage/0day-Rubbish/commits)

**🌐 Official Website**: <https://0day-rubbish.com/blog>

---

## 🎯 Why This Exists

Traditional vulnerability disclosure is broken. It's slow, bureaucratic, and ineffective. In the AI era, we can mass-produce 0days at scale—making individual vulnerabilities less valuable but more impactful when disclosed directly.

We believe **event-driven security hardening** is the most effective approach: only when vendors face real, exploitable threats do they prioritize fixes.

## 🔄 Our Disclosure Process

### Step 1: AI Discovery
Our automated AI systems continuously scan for vulnerabilities across real-world software, identifying potential 0-days through pattern analysis, fuzzing, and intelligent code review.

### Step 2: Verification & PoC Development
Each finding undergoes manual validation. We develop working proof-of-concept exploits to confirm exploitability and assess real-world impact.

### Step 3: Periodic Public Disclosure
Roughly every two weeks we disclose a new batch of verified, exploitable 0-day vulnerabilities we've discovered and validated:
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

Our automated vulnerability discovery leverages cutting-edge large language models from leading AI providers:
- **Anthropic (Claude)** - Deep security pattern recognition and reasoning
- **OpenAI** - Advanced reasoning and code analysis
- **DeepSeek** - Specialized vulnerability detection
- **Z.ai (GLM)** - Long-context code analysis
- **Moonshot (Kimi)** - Long-context security analysis

---

## 📋 Disclosed Vulnerabilities

An AI-driven research process (multi-LLM ensemble: Claude, OpenAI, DeepSeek, GLM, Kimi) discovers 0-days in real-world enterprise software. Every advisory below ships a **full root-cause analysis** plus a **working, reproducible exploit script** — no detection-only writeups, no withheld details.

### Latest Batch — August 2026 (8 advisories)

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | GE PulseNET Enterprise | 6.0.3 | **9.8** | Default creds + Path Traversal (Root) | [ResourceFile Path Traversal → RCE](https://0day-rubbish.com/blog/ge-pulsenet-resource-file-path-traversal-rce) |
| 2 | Kerio Connect | 10.0.9 Patch 2 | **8.8** | Auth Cmd Injection (Root) | [Server.startEncryption Cmd Injection → RCE](https://0day-rubbish.com/blog/kerio-connect-startencryption-cmd-injection-rce) |
| 3 | Lansweeper | 12.2.1.0 | **8.8** | Auth 2nd-Order SQLi → xp_cmdshell | [LicenseActions SQLi → RCE](https://0day-rubbish.com/blog/lansweeper-licenseactions-sqli-xpcmdshell-rce) |
| 4 | Plixer Scrutinizer | 19.7.0 | **8.8** | Auth SQLi → pg_cron RCE | [ORDER BY SQLi → RCE](https://0day-rubbish.com/blog/plixer-scrutinizer-orderby-sqli-pgcron-rce) |
| 5 | Telaeris XPressEntry | 3.7.7454 | **9.8** | Unauth SQLi → xp_cmdshell | [Unauth SQLi → RCE](https://0day-rubbish.com/blog/telaeris-xpressentry-unauth-sqli-xpcmdshell-rce) |
| 6 | Output Messenger Server | 2.0.x | **9.8** | Unauth Zip-Slip (SYSTEM) | [Zip-Slip Plugin Plant → RCE](https://0day-rubbish.com/blog/output-messenger-unauth-zipslip-plugin-rce) |
| 7 | Cinegy Cinegize | 2026-02-05 | **9.8** | Unauth Deserialization (SYSTEM) | [BinaryFormatter → RCE](https://0day-rubbish.com/blog/cinegy-cinegize-unauth-binaryformatter-rce) |
| 8 | MidVision RapidDeploy | 5.2.2 | **9.8** | Unauth File Write (Root) | [Remote Agent Arbitrary File Write → RCE](https://0day-rubbish.com/blog/midvision-rapiddeploy-unauth-file-write-rce) |

**Totals**: 8 advisories · 8 vendors · 5 unauthenticated · 3 authenticated (deep-chain) · 5 root/SYSTEM · all with reproducible PoC.

*Earlier batches: [Batch #1 — July 2026](https://0day-rubbish.com/blog) · [Batch #2 — August 2026](https://0day-rubbish.com/blog) · [Batch #3 — August 2026](https://0day-rubbish.com/blog)*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: August 2026 — 8 advisories (live); cumulative 43 across 4 batches
- **Next drop**: weekly
- **Future scope**: expanding beyond enterprise IT into **ICS / SCADA, energy, and aerospace** systems

If you want to catch the next drop the moment it lands:

[![Star](https://img.shields.io/badge/⭐_Star-bookmark_this_repo-yellow)](https://github.com/Exploit-Garbage/0day-Rubbish) [![Watch](https://img.shields.io/badge/👁_Watch-get_notified_on_new_batches-blue)](https://github.com/Exploit-Garbage/0day-Rubbish/subscription) [![Blog](https://img.shields.io/badge/🌐_Follow-0day--rubbish.com%2Fblog-brightgreen)](https://0day-rubbish.com/blog)

> ⭐ **Star** to bookmark · 👁 **Watch** (custom → Releases + Discussions) for new batches · 🌐 **Follow** the blog for per-advisory updates.

---

## 📂 Vulnerability Submission Format

All disclosed vulnerabilities follow a standardized directory structure:

```
product/
└── <vendor>/
    └── <version>/
        └── <vulnerability_type>/
            ├── exploit/          # Exploit scripts and PoC code
            ├── analysis.md       # Detailed vulnerability analysis
            └── summary.md        # Brief vulnerability overview
```

### Directory Rules

- **product/**: Root directory for all vulnerabilities
- **<vendor>/**: Vendor or product name (e.g., `apache`, `cisco`, `sonicwall`)
- **<version>/**: Affected version range (e.g., `6.11.0`, `12.4.2`)
- **<vulnerability_type>/**: Classification (e.g., `unauth-rce`, `auth-bypass`, `deserialization-rce`)

### Required Files in Each Vulnerability Directory

1. **exploit/**: Directory containing working exploit scripts and PoC code
2. **analysis.md**: Comprehensive technical analysis including root cause, attack vector, and impact
3. **summary.md**: Concise vulnerability overview with affected versions and quick mitigation steps

### Example

```
product/
└── sonicwall/
    └── sma-12.4/
        └── preauth-deserialization-rce/
            ├── exploit/
            │   └── poc.py
            ├── analysis.md
            └── summary.md
```

---

**Join us in redefining vulnerability disclosure for the AI era.**
