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
Every week — Monday or Tuesday — we disclose a new batch of verified, exploitable 0-day vulnerabilities we've discovered and validated:
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

### Latest Batch — Batch 18 (12 advisories)

*Twelve findings, one theme again: a value an administrator is entitled to type, handed to a shell, a path or a deserializer that was never told the value was untrusted. Two are reachable with no session at all - a factory credential pair that opens the API, and a helpdesk field anonymous visitors can write - while the other ten need an admin session. Three come from NETGEAR's router and switch management planes; the rest spread across a helpdesk, a data pipeline, a console server, an NVR, two VoIP devices, a serial device server, a cellular router and Moxa's device-management console. Every advisory states its own verification boundary and ships a working PoC.*

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | Cribl Edge | 4.19.2-89cac507 | **9.8** | Factory-default administrator credentials open the API; the Exec Source command field then runs with the service's authority | [unauth default creds exec source rce](https://0day-rubbish.com/blog/unauth-default-creds-exec-source-rce) |
| 2 | Kayako Classic | 4.98.9 | **7.5** | An anonymous ticket's custom field is stored raw and later reaches a bare `mb_unserialize` on the staff SELECTLINKED path; a destructor chain ends in `system()` | [selectlinked unserialize rce](https://0day-rubbish.com/blog/selectlinked-unserialize-rce) |
| 3 | NETGEAR RAX200 | V1.0.11.148 | **7.2** | bftpd's RNTO rename escapes the FTP chroot and overwrites the OpenVPN configuration the router loads | [bftpd rnto escape openvpn conf hijack rce](https://0day-rubbish.com/blog/bftpd-rnto-escape-openvpn-conf-hijack-rce) |
| 4 | NETGEAR ProSafe | 12.0.19.23 | **7.2** | The REST agent's firmware-URL download value is interpolated into a shell command | [restagent fwurl command injection root rce](https://0day-rubbish.com/blog/restagent-fwurl-command-injection-root-rce) |
| 5 | NETGEAR R9000 | as shipped | **7.2** | A MAC address submitted to `plex_net_dev` reaches the root CGI's command line | [plex net dev mac command injection](https://0day-rubbish.com/blog/plex-net-dev-mac-command-injection) |
| 6 | Lantronix LSS2200-8P | v2.1.0.0R2 | **7.2** | The Percepxion registration response is parsed into a command executed by the root provisioning client | [percepxion remote access host rce](https://0day-rubbish.com/blog/percepxion-remote-access-host-rce) |
| 7 | D-Link DNR-326 | v2.70b04 | **7.2** | `dsk_mgr.cgi`'s `f_sethdsize` value lands in the diskmgr shell pipeline | [dsk mgr command injection root rce](https://0day-rubbish.com/blog/dsk-mgr-command-injection-root-rce) |
| 8 | Grandstream HT801 | v1.0.65.1 | **7.2** | The time-zone setting is echoed into a shell command by `gs_cpe` without quoting | [timezone command injection root rce](https://0day-rubbish.com/blog/timezone-command-injection-root-rce) |
| 9 | Grandstream GDS371x | 1.0.13.10 | **7.2** | An `ldc.cgi` query parameter reaches the `test_ldc` `system()` line | [ldc cgi command injection root rce](https://0day-rubbish.com/blog/ldc-cgi-command-injection-root-rce) |
| 10 | Advantech EKI-1224-CE | D1.06_r5772 | **7.2** | A ConfigImport bypass lets a value reach the `edgserver` `system()` call in the NTP-update thread | [edgserver configimport command injection root rce](https://0day-rubbish.com/blog/edgserver-configimport-command-injection-root-rce) |
| 11 | Moxa OnCell Central Manager | v2.4.1 | **7.2** | The `uploadFw` filename is concatenated into the destination path; traversal lands a JSP in the Tomcat webroot, which the service then serves | [uploadfw path traversal rce](https://0day-rubbish.com/blog/uploadfw-path-traversal-rce) |
| 12 | DigitalYacht 4GConnect | RutOS 7.2.x | **7.2** | The profile name is concatenated unquoted into `os.execute` in `profiles.lua` | [profiles lua command injection root rce](https://0day-rubbish.com/blog/profiles-lua-command-injection-root-rce) |

*Every previous batch and its advisories are listed under [Releases](https://github.com/Exploit-Garbage/0day-Rubbish/releases).*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 18 — 12 advisories; cumulative 167 across 18 batches
- **Next drop**: every Monday or Tuesday
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
