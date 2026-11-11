# 0day Rubbish

> **0day vulnerabilities have become rubbish in the AI era.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Latest batch](https://img.shields.io/badge/Latest_batch-11_advisories-red)](https://0day-rubbish.com/blog)
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

### Latest Batch — Batch 17 (11 advisories)

*Eleven findings that share one shape: a field an administrator is entitled to type, handed to a shell, a filesystem or a JDBC parser that was never told the field was untrusted. It is the oldest mistake in appliance engineering, and this batch is what it looks like when it is repeated across eleven vendors that each believe their management plane is a trusted environment. Two are reachable with no session at all — a session check that is simply absent from one handler, and an installer that will fetch and unpack an archive from any URL before the product is installed. The other nine sit behind an admin session, and that is exactly why they matter: the credential is the last line, not a mitigation.*

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | Peplink PotSa EU | firmware fw-potsa_eu-1.2.0-build1873 | **9.8** | The unauthenticated WiFi setup action formats the passphrase into a `popen` line inside single quotes; one apostrophe breaks out into the daemon's root shell, and the handler's cookie check is structurally absent | [WiFi passphrase → web_httpd root shell](https://0day-rubbish.com/blog/wifi-passphrase-command-injection-root-rce) |
| 2 | NetCat CMS / NetCat E-Commerce | 7.2.0 (build 26228) | **9.8** | The installer's restore-from-URL path fetches an attacker archive and extracts it over the document root of a pristine, uninstalled instance; one anonymous request pair writes an executable page and fetches it back | [installer restore-from-URL → web-root code execution](https://0day-rubbish.com/blog/installer-remote-archive-rce) |
| 3 | D-Link DAP-2310B (DAP-2660 byte-identical merge) | as shipped | **7.2** | The `atp` template processor's `ExeShell` expands `$( )` in a submitted value before the line reaches the shell | [ExeShell → root command injection](https://0day-rubbish.com/blog/exeshell-command-injection-root-rce) |
| 4 | Grandstream GDS371x | Release_GDS371x_1.0.13.10 | **7.2** | `/goform/apicmd`'s `cmd=` dispatcher builds `rm -rf /tmp/<name>` with `%s` and no quoting; `;` and `$(` survive a `tolower()`-only filter and reach `system()` | [apicmd config rm → shell](https://0day-rubbish.com/blog/apicmd-config-rm-command-injection-root-rce) |
| 5 | Eltex SMG-1016M | 3.20.5.4900 | **7.2** | `clish`'s `ftpd user add` passes unquoted user and password arguments into vendor `adduser`/`passwdch`/`deluser` scripts that re-expand them | [clish ftpd user add → helper-script shell](https://0day-rubbish.com/blog/clsh-ftp-user-command-injection-root-rce) |
| 6 | Advantech EKI-1522-AE | firmware D1.99_r3510 | **7.2** | The mail-alarm configuration fields are interpolated into a shell command the web management plane executes with root authority | [mail-server fields → root shell](https://0day-rubbish.com/blog/mail-server-command-injection-root-rce) |
| 7 | Cambium E410 / E510 / E600 / E700 | 4.2.3.3-r9 | **7.2** | A query parameter becomes a path inside `upload.sh`; traversal lands a script that the CGI trigger then runs as root | [upload.sh traversal → root execution](https://0day-rubbish.com/blog/uploadsh-path-traversal-root-rce) |
| 8 | SearchBlox Enterprise Search | 12.1.2 (build 202607202005) | **7.2** | The admin "Database URL String" field is concatenated into a JDBC URL; H2's `INIT=RUNSCRIPT` parses attacker SQL and a Java UDF reaches `Runtime.exec` as the service account — `uid=999`, not root, and the advisory says so | [database URL → JDBC injection → service-account execution](https://0day-rubbish.com/blog/jdbc-url-injection-h2-init-rce) |
| 9 | StoneFly SCVM | 8.0.4.29 | **7.2** | `ff_isns.pl` interpolates the `ipaddress` parameter into `sf_ping()`, which stages a root `ping` wrapper through a NOPASSWD `command.pl` | [iSNS ipaddress → root command injection](https://0day-rubbish.com/blog/ff-isns-ipaddress-command-injection-root-rce) |
| 10 | VoIPTools Relay for 3CX | 20.9.34 | **7.2** | `SetLinuxFolderPermissions` concatenates its `permissions` value into a shell command the Relay service executes as root | [permissions value → root shell](https://0day-rubbish.com/blog/setlinuxfolderpermissions-command-injection-root-rce) |
| 11 | Maian Cube | 1.x (PHP 8.2) | **7.2** | The license-generation passphrase field reaches `shell_exec` in the admin panel, executing as the PHP process user | [license passphrase → PHP process shell](https://0day-rubbish.com/blog/license-gen-command-injection-rce) |

*Every previous batch and its advisories are listed under [Releases](https://github.com/Exploit-Garbage/0day-Rubbish/releases).*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 17 — 11 advisories; cumulative 155 across 17 batches
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
