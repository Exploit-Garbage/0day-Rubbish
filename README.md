# 0day Rubbish

> **0day vulnerabilities have become rubbish in the AI era.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Latest batch](https://img.shields.io/badge/Latest_batch-12_advisories-red)](https://0day-rubbish.com/blog)
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

### Latest Batch — Batch 9 (12 advisories)

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | NoMachine Terminal Server (VULN-001) | 10.0.57 | **9.8** | Pre-auth heap corruption (CWE-787→416), RCE-capable | [parsePOST heap → corruption](https://0day-rubbish.com/blog/nomachine-terminal-server-preauth-heap-corruption) |
| 2 | NoMachine Terminal Server (VULN-002) | 10.0.57 | **9.8** | Pre-auth stack overflow, return-address control | [parsePOST sprintf → RIP control](https://0day-rubbish.com/blog/nomachine-terminal-server-preauth-stack-overflow) |
| 3 | StreamSets DataCollector | 6.4.1 | **9.8** | Default creds + Shell Executor → Root | [ShellDExecutor → Root RCE](https://0day-rubbish.com/blog/streamsets-datacollector-default-creds-shell-executor-root-rce) |
| 4 | Akana API Platform | 8.4.29 | **9.8** | Unauth path-normalization bypass → ScriptEngine RCE | [admin/../ext → engine.eval RCE](https://0day-rubbish.com/blog/akana-api-platform-path-normalization-unauth-rce) |
| 5 | Puppet Enterprise | 2025.10.0 | **8.8** | Auth keytool shell injection → Root (CVE-2025-5459 bypass) | [java_keystore_passwd → Root RCE](https://0day-rubbish.com/blog/puppet-enterprise-keytool-injection-root-rce) |
| 6 | Minuteman UPS NMC | 1.60.3 | **9.8** | Unauth system_param.csp Cmd Injection → Root | [WAN config → Root RCE](https://0day-rubbish.com/blog/minuteman-ups-nmc-system-param-unauth-command-injection) |
| 7 | Lantronix EDS3000PR (VULN-001) | 3.2.0.0R2 | **8.8** | Auth FsUnmount Cmd Injection → Root | [FsUnmount path → Root RCE](https://0day-rubbish.com/blog/lantronix-eds3000pr-fsunmount-command-injection) |
| 8 | Lantronix EDS3000PR (VULN-002) | 3.2.0.0R2 | **8.8** | Auth SSL `-passin pass:%s` Cmd Injection → Root | [keytool pass → Root RCE](https://0day-rubbish.com/blog/lantronix-eds3000pr-passin-pass-command-injection) |
| 9 | GeoVision GV-TBL4700 | V1.06 | **8.8** | Auth SNMPv3 net-snmp-config Cmd Injection → Root | [szAuthKey → Root RCE](https://0day-rubbish.com/blog/geovision-gv-tbl4700-snmpv3-command-injection) |
| 10 | DrayTek Vigor 2960 | v1.5.1.6 | **8.8** | Auth uploadlangs Cmd Injection → Root | [cgiEscape gap → Root RCE](https://0day-rubbish.com/blog/draytek-vigor2960-uploadlangs-command-injection) |
| 11 | Codoforum | 5.4.1 | **7.2** | Auth cat_img polyglot upload → www-data | [polyglot upload → RCE](https://0day-rubbish.com/blog/codoforum-admin-cat-img-polyglot-upload-rce) |
| 12 | ZesleCP | 3.1.21 | **8.8** | Auth arbitrary file write → cron → Root | [save-file → cron Root RCE](https://0day-rubbish.com/blog/zeslecp-admin-file-write-cron-root-rce) |

**Totals**: 12 advisories · 10 vendors · 4 unauthenticated · 8 authenticated (deep-chain) · 10 system-level (root/SYSTEM) · all with reproducible PoC.

*Earlier batches: [Batch #1](https://0day-rubbish.com/blog) · [Batch #2](https://0day-rubbish.com/blog) · [Batch #3](https://0day-rubbish.com/blog) · [Batch #4](https://0day-rubbish.com/blog) · [Batch #5](https://0day-rubbish.com/blog) · [Batch #6](https://0day-rubbish.com/blog) · [Batch #7](https://0day-rubbish.com/blog) · [Batch #8](https://0day-rubbish.com/blog)*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 9 — 12 advisories (draft); cumulative 90 across 9 batches
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
