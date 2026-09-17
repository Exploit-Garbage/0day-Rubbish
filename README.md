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

### Latest Batch — Batch 11 (8 advisories)

*Management and control planes running as root / SYSTEM / Administrator.*

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | TigerGraph Community Edition | 4.2.4 | **9.8** | Default creds + GSQL file write + unauth REST++ trigger → SSH RCE (service user) | [PRINT TO_CSV → authorized_keys → RCE](https://0day-rubbish.com/blog/tigergraph-default-creds-file-write-ssh-rce) |
| 2 | Devolutions Server (DVLS) | 2026.2.14.0 | **9.1** | Auth PAM entitlement-gate bypass → test-script PowerShell → SYSTEM | [hard-coded GUID → WinRM → SYSTEM](https://0day-rubbish.com/blog/devolutions-server-pam-license-bypass-system-rce) |
| 3 | Ecava IntegraXor IGX (ICS) | 16.0.701.10 | **9.8** | Unauth FileUpload → dxmanager `cmd.exe /C` sink → Administrator | [/FileUpload → CMDEXT sink → RCE](https://0day-rubbish.com/blog/ecava-integraxor-unauth-fileupload-dxmanager-rce) |
| 4 | LCDS Laquis SCADA (ICS) | as tested \* | **9.8** | Unauth `/uploade.html` write → `CMDEXT*.DLL` plugin load in `mili.exe` | [uploade → DLL autoload → RCE](https://0day-rubbish.com/blog/lcds-laquis-scada-unauth-uploade-cmdext-dll-rce) |
| 5 | CaptureBites MetaServer | as tested \* | **9.8** | Unauth WCF SOAP `RunPrograms` → `Process.Start` → SYSTEM | [4 anonymous SOAP ops → SYSTEM](https://0day-rubbish.com/blog/capturebites-metaserver-unauth-runprogram-system-rce) |
| 6 | Accusoft / Apryse PrizmDoc for Java | 5.22.1 | **9.8** | Unauth `uploadDocument` → JSP webshell in webapp root → root | [AjaxServlet → webshell → root](https://0day-rubbish.com/blog/accusoft-prizmdoc-unauth-uploaddocument-jsp-webshell-rce) |
| 7 | Teltonika RutOS (RUT2XX / RUT200, RUT9XX) | 00.07.06.21 | **8.8** | Auth `ipsec.lua` → `logread` command injection → root, output reflected | [instances_status sid → root](https://0day-rubbish.com/blog/teltonika-rutos-ipsec-status-logread-command-injection) |
| 8 | Opengear NGCS console manager | 25.11.8 | **8.8** | Auth PDU `name` → `ogpower` command injection → root (sanitizer present but uncalled) | [PDU name → shlex_quote gap → root](https://0day-rubbish.com/blog/opengear-ngcs-pdu-name-command-injection-root-rce) |

\* The exact marketed version is not documented in our research record for these two; the advisories state that explicitly rather than asserting a version number.

**Totals**: 8 advisories · 8 vendors · 5 unauthenticated · 3 authenticated (deep-chain) · 6 reaching root/SYSTEM/Administrator plus 2 application-context executions (a graph-database service user; the SCADA HMI process that also hosts Modbus TCP) · 4 ICS/OT-class products · all with reproducible PoC.

*Earlier batches: [Batch #1](https://0day-rubbish.com/blog) · [Batch #2](https://0day-rubbish.com/blog) · [Batch #3](https://0day-rubbish.com/blog) · [Batch #4](https://0day-rubbish.com/blog) · [Batch #5](https://0day-rubbish.com/blog) · [Batch #6](https://0day-rubbish.com/blog) · [Batch #7](https://0day-rubbish.com/blog) · [Batch #8](https://0day-rubbish.com/blog) · [Batch #9](https://0day-rubbish.com/blog) · [Batch #10](https://0day-rubbish.com/blog)*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 11 — 8 advisories (draft); cumulative 106 across 11 batches
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
