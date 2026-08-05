# 0day Rubbish

> **0day vulnerabilities have become rubbish in the AI era.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![0-days disclosed](https://img.shields.io/badge/0--days_disclosed-27-red)](https://0day-rubbish.com/blog)
[![Max CVSS](https://img.shields.io/badge/Max_CVSS-9.8-critical)](https://0day-rubbish.com/blog)
[![Batches](https://img.shields.io/badge/Batches-2_live-orange)](https://0day-rubbish.com/blog)
[![PoC](https://img.shields.io/badge/Every_advisory-working_PoC-blue)](https://0day-rubbish.com/blog)
[![Website](https://img.shields.io/badge/Website-0day--rubbish.com-brightgreen)](https://0day-rubbish.com)
[![GitHub stars](https://img.shields.io/github/stars/Exploit-Garbage/0day-Rubbish?style=flat&logo=github)](https://github.com/Exploit-Garbage/0day-Rubbish/stargazers)
[![Discussions](https://img.shields.io/github/discussions/Exploit-Garbage/0day-Rubbish?logo=github)](https://github.com/Exploit-Garbage/0day-Rubbish/discussions)
[![Latest batch](https://img.shields.io/github/v/release/Exploit-Garbage/0day-Rubbish?label=latest%20batch)](https://github.com/Exploit-Garbage/0day-Rubbish/releases)

**🌐 Official Website**: <https://0day-rubbish.com/blog>

<p align="center">
  <a href="https://star-history.com/#Exploit-Garbage/0day-Rubbish&Date">
    <img src="https://api.star-history.com/svg?repos=Exploit-Garbage/0day-Rubbish&type=Date" alt="Star History" width="600" />
  </a>
</p>

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

### Batch #1 — July 2026 (12 advisories)

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | InterSystems IRIS | 2026.1.0.234.1 | **9.8** | Unauth RCE | [FolderManager Property Injection → RCE](https://0day-rubbish.com/blog/intersystems-iris-foldermanager-rce) |
| 2 | AdRem NetCrunch | 16.0.0.8397 RC | **9.8** | Unauth RCE (SYSTEM) | [Cross-Session Hijack → RCE](https://0day-rubbish.com/blog/adrem-netcrunch-session-hijack-rce) |
| 3 | Altus BluePlant | 9.1.40 | **9.8** | Unauth RCE | [Hardcoded Credentials → RCE](https://0day-rubbish.com/blog/altus-blueplant-hardcoded-creds-rce) |
| 4 | Brekeke SIP Server | v3.19.1.8p1 | **9.8** | Unauth RCE | [Nashorn JS Engine → RCE](https://0day-rubbish.com/blog/brekeke-sip-server-nashorn-rce) |
| 5 | Brekeke SIP Server | v3.19.1.8p1 | **9.8** | Unauth RCE (Zip Slip) | [Zip Slip Webshell → RCE](https://0day-rubbish.com/blog/brekeke-sip-server-zipslip-rce) |
| 6 | DataSunrise Suite | 11.2.17.12820 | **9.8** | Unauth RCE | [Email Verification Brute Force → RCE](https://0day-rubbish.com/blog/datasunrise-email-bruteforce-rce) |
| 7 | Cisco CUCM | 14.0 | **9.8** | RCE Chain | [Multi-stage RCE Chain](https://0day-rubbish.com/blog/cisco-cucm-rce-chain) |
| 8 | SonicWall SMA 1000 | 12.4.2 | **9.8** | Pre-Auth RCE | [Struts 1 Property Injection → Deserialization RCE](https://0day-rubbish.com/blog/sonicwall-sma-preauth-deserialization-rce) |
| 9 | Brekeke SIP Server | v3.19.1.8p1 | **9.1** | Auth Bypass | [Auth Fail-Open → 23 Unauth Beans](https://0day-rubbish.com/blog/brekeke-sip-server-auth-failopen) |
| 10 | Acumatica ERP | 2026 R1 | **8.8** | Auth RCE | [Customization Publish Webshell → RCE](https://0day-rubbish.com/blog/acumatica-customization-webshell-rce) |
| 11 | AdRem NetCrunch | 16.0.0.8397 RC | **8.8** | Auth RCE (SYSTEM) | [Startup Script → RCE](https://0day-rubbish.com/blog/adrem-netcrunch-startup-script-rce) |
| 12 | Altus iX Developer | 2.53.65422 | **7.3** | Local/UI RCE | [XAML Deserialization → RCE](https://0day-rubbish.com/blog/altus-ix-developer-xaml-rce) |

### Batch #2 — August 2026 (15 advisories)

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 13 | Apache Struts 2 | 6.11.0 | **9.8** | Unauth RCE (Root) | [RestfulActionMapper OGNL Injection → RCE](https://0day-rubbish.com/blog/apache-struts2-restful-mapper-ognl-rce) |
| 14 | AOMEI Cyber Backup | 2.3.0 | **9.8** | Unauth RCE (Root) | [Thrift NAS Mount Injection → RCE](https://0day-rubbish.com/blog/aomei-cyber-backup-thrift-nas-mount-rce) |
| 15 | Xeams | 10.3 (build 6449) | **9.8** | Unauth RCE (Root) | [SMTP X-SM_SAVE_BODY File Write → RCE](https://0day-rubbish.com/blog/xeams-smtp-savebody-cron-rce) |
| 16 | Xeams | 10.3 (build 6449) | **9.8** | Unauth RCE (Root) | [SQLRunner Derby Hardcoded Creds → JSP Webshell](https://0day-rubbish.com/blog/xeams-unauth-sqlrunner-derby-jsp-rce) |
| 17 | atvise SCADA | 3.13.0 | **9.8** | Unauth RCE (Root) | [OPC UA Auth Bypass + V8 Injection → RCE](https://0day-rubbish.com/blog/atvise-scada-opcua-unauth-rce) |
| 18 | CIRCUTOR PowerStudio | 24.11.6.0 | **9.8** | Unauth RCE (SYSTEM) | [JWT alg=none + shellExecute → RCE](https://0day-rubbish.com/blog/circutor-powerstudio-unauth-shellExecute-rce) |
| 19 | CatDV Server | 10.7.8 | **9.8** | Unauth RCE (Root) | [RMI ClientID Minting → aaftoolPath RCE](https://0day-rubbish.com/blog/catdv-server-unauth-rmi-root-rce) |
| 20 | CatDV Server | 10.7.8 | **9.8** | Default Credentials | [Factory-Default Empty Admin Password](https://0day-rubbish.com/blog/catdv-server-admin-factory-default-empty-password) |
| 21 | Vicon Valerus | 25.200.46.0 | **9.8** | Unauth RCE (SYSTEM) | [OWIN Web API Command Injection → RCE](https://0day-rubbish.com/blog/vicon-valerus-unauth-cmd-injection-rce) |
| 22 | Stimulsoft Server | 2026.3.1 | **9.8** | Unauth RCE (SYSTEM) | [Signup + Report-Script Compilation → RCE](https://0day-rubbish.com/blog/stimulsoft-server-unauth-report-script-rce) |
| 23 | Plastic SCM (Unity) | 11.0.16.10303 | **9.8** | Unauth RCE | [Name-Only ACL 8087 Trigger → RCE](https://0day-rubbish.com/blog/plastic-scm-unauth-8087-rce) |
| 24 | vMix | 29.0.0.48 | **9.8** | Unauth RCE (Admin) | [VBScript Blocklist Bypass → RCE](https://0day-rubbish.com/blog/vmix-vbscript-blocklist-bypass-rce) |
| 25 | atvise SCADA | 3.13.0 | **8.8** | Default-Cred RCE (Root) | [WebMI Default Credential + V8 Injection → RCE](https://0day-rubbish.com/blog/atvise-scada-webmi-auth-rce) |
| 26 | CIRCUTOR PowerStudio | 24.11.6.0 | **8.6** | Auth Bypass | [JWT alg=none Identity Forgery](https://0day-rubbish.com/blog/circutor-powerstudio-jwt-alg-none-identity-forgery) |
| 27 | CatDV Server | 10.7.8 | **7.6** | Auth RCE (Root) | [aaftoolPath Property Injection → RCE](https://0day-rubbish.com/blog/catdv-server-aaftoolPath-root-rce) |

**Totals**: 27 advisories · 18 vendors · 21 critical (CVSS ≥ 9.0) · 20 unauthenticated · all with reproducible PoC.

---

## 🔁 An Ongoing Series — New Batch Every Two Weeks

This is a **continuous disclosure series**. The AI-driven discovery pipeline runs around the clock, and a new batch of verified 0-days with full PoCs lands **roughly every two weeks**.

- **Batch #1**: July 2026 — 12 advisories (live)
- **Batch #2**: August 2026 — 15 advisories (live)
- **Next drop**: late August 2026
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