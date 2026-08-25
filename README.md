# 0day Rubbish

> **0day vulnerabilities have become rubbish in the AI era.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Latest batch](https://img.shields.io/badge/Latest_batch-10_advisories-red)](https://0day-rubbish.com/blog)
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

### Latest Batch — Batch 8 (10 advisories)

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | Seeq Server | R65.2.3 | **9.8** | Unauth self-registration + Data Lab Jupyter missing-auth RCE | [Jupyter kernel → RCE](https://0day-rubbish.com/blog/seeq-server-unauth-selfreg-datalab-jupyter-rce) |
| 2 | mySCADA PRO Runtime | 9.4.0 | **9.4** | Unauth upgrade Cmd Injection → Root | [/s.fcgi upgrade → Root RCE](https://0day-rubbish.com/blog/myscada-runtime-unauth-upgrade-cmd-injection) |
| 3 | Biamp Devio SCR-20/25 | 2.3.1 | **9.8** | Unauth DTP Protocol Quote Injection → Root | [DTP password sink → Root RCE](https://0day-rubbish.com/blog/biamp-devio-dtp-unauth-root-rce) |
| 4 | Leostream Broker (VULN-002) | 9.1.37.0 | **7.0** | Unauth Rogue-Agent Registration + SSRF | [Server.Register → SSRF](https://0day-rubbish.com/blog/leostream-unauth-server-register-ssrf) |
| 5 | Raritan EMX | emx_ecx_3.6.1 | **8.8** | Auth Config Injection → port_mux Root | [proto_listener → Root RCE](https://0day-rubbish.com/blog/raritan-emx-port-mux-proto-listener-root-rce) |
| 6 | Leostream Broker (VULN-001) | 9.1.37.0 | **9.1** | Auth SQLi → lo_export Webshell → Root | [_where SQLi → Root RCE](https://0day-rubbish.com/blog/leostream-postauth-sqli-lo-export-webshell-rce) |
| 7 | VitalPBX | 4.5.2 | **8.8** | Auth asterisk_cli → Dialplan System() Root | [CLI → System() → Root RCE](https://0day-rubbish.com/blog/vitalpbx-authed-asterisk-cli-root-rce) |
| 8 | Delta DIAEnergie IEMS | V1.11 | **8.8** | Auth CommandTag SQLi → VBScript RCE | [tid SQLi → VBScript RCE](https://0day-rubbish.com/blog/delta-diaenergie-iems-postauth-commandtag-sqli-rce) |
| 9 | CacheGuard | UF-2.5.2 | **8.8** | Auth Config-Import Eval Injection RCE | [conf inject eval → RCE](https://0day-rubbish.com/blog/cacheguard-authed-conf-inject-eval-rce) |
| 10 | Maian Gallery | 2.1 | **7.2** | Auth Admin Unrestricted Upload → Root | [upload_thumbnail → RCE](https://0day-rubbish.com/blog/maian-gallery-authed-upload-root-rce) |

**Totals**: 10 advisories · 10 vendors · 4 unauthenticated · 6 authenticated (deep-chain) · 7 system-level (root/SYSTEM) · all with reproducible PoC.

*Earlier batches: [Batch #1](https://0day-rubbish.com/blog) · [Batch #2](https://0day-rubbish.com/blog) · [Batch #3](https://0day-rubbish.com/blog) · [Batch #4](https://0day-rubbish.com/blog) · [Batch #5](https://0day-rubbish.com/blog) · [Batch #6](https://0day-rubbish.com/blog) · [Batch #7](https://0day-rubbish.com/blog)*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 8 — 10 advisories (live); cumulative 78 across 8 batches
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
