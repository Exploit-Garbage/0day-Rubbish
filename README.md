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

### Latest Batch — Batch 10 (8 advisories)

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | DBxtra .NET | 13.1.1.0 | **9.8** | Unauth SOAP (346 anonymous WebMethods) → SSRF + xp_cmdshell → SYSTEM | [DataGrid.aspx → SYSTEM RCE](https://0day-rubbish.com/blog/dbxtra-unauth-soap-xp-cmdshell-rce) |
| 2 | Accurate Online Private Cloud | on-prem (current) | **9.8** | Unauth Hessian deserialization → JNDI → Administrator RCE | [/accurate/remote → JNDI RCE](https://0day-rubbish.com/blog/accurate-online-private-cloud-unauth-hessian-jndi-rce) |
| 3 | Jitterbit Agent | 12.8.1.6 | **9.8** | Unauth SOAP JdbcEngine + hardcoded PG superuser → COPY TO PROGRAM RCE | [dbExecute → COPY TO PROGRAM RCE](https://0day-rubbish.com/blog/jitterbit-agent-unauth-soap-copy-to-program-rce) |
| 4 | SmarterMail | 100.0.9693 | **7.2** | SysAdmin AV commandLine → SMTP trigger → SYSTEM privesc | [antivirus commandLine → SYSTEM RCE](https://0day-rubbish.com/blog/smartermail-antivirus-command-line-system-rce) |
| 5 | OSNexus QuantaStor | 6.8.3.018 | **8.8** | Auth alertConfigSet smtpPassword command injection → Root | [smtpPassword → Root RCE](https://0day-rubbish.com/blog/quantastor-alertconfigset-smtp-password-command-injection) |
| 6 | ITRS OP5 Monitor | 9.20 | **8.8** | CVE-2025-34115 OPT-IN patch bypass → command injection RCE | [contains_dangerous_characters gap → RCE](https://0day-rubbish.com/blog/op5-monitor-cve-2025-34115-patch-bypass-rce) |
| 7 | core-admin | 1.0.164 | **8.8** | Auth escape_param shell injection → Root (systemic, 32 sinks) | [escape_param → Root RCE](https://0day-rubbish.com/blog/core-admin-escape-param-command-injection-rce) |
| 8 | Royal Server | 5.04.50529 | **7.2** | Authenticated local privilege escalation to LocalSystem | [fmgvf credential gap → LocalSystem](https://0day-rubbish.com/blog/royal-server-authenticated-local-system-privesc) |

**Totals**: 8 advisories · 8 vendors · 3 unauthenticated · 5 authenticated (deep-chain) · 6 system-level (root/SYSTEM/LocalSystem/Administrator) · all with reproducible PoC.

*Earlier batches: [Batch #1](https://0day-rubbish.com/blog) · [Batch #2](https://0day-rubbish.com/blog) · [Batch #3](https://0day-rubbish.com/blog) · [Batch #4](https://0day-rubbish.com/blog) · [Batch #5](https://0day-rubbish.com/blog) · [Batch #6](https://0day-rubbish.com/blog) · [Batch #7](https://0day-rubbish.com/blog) · [Batch #8](https://0day-rubbish.com/blog) · [Batch #9](https://0day-rubbish.com/blog)*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 10 — 8 advisories (draft); cumulative 98 across 10 batches
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
