# 0day Rubbish

> **0day vulnerabilities have become rubbish in the AI era.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Latest batch](https://img.shields.io/badge/Latest_batch-7_advisories-red)](https://0day-rubbish.com/blog)
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

### Latest Batch — Batch 13 (7 advisories)

*Command execution reached from inside the product's own management surface — an unauthenticated report-upload page, a data-pipeline stage that compiles Scala, an energy gateway's event engine, a package-manager property, a media CGI, a banner uploader and a log viewer.*

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | Advantech WebAccess Node (SCADA/HMI) | 9.2.3 | **9.8** \* | Unauthenticated `CrystalRpt.aspx` file upload with path traversal → code execution in the IIS worker process | [CrystalRpt.aspx → webshell → code execution](https://0day-rubbish.com/blog/advantech-webaccess-crystalrpt-unauth-file-upload-rce) |
| 2 | StreamSets Transformer | 3.17.0 | **8.1** \* | `ScalaDTransform` code field compiled and run by the full Scala compiler in the service JVM, no sandbox → container root | [Scala stage → compiler → root](https://0day-rubbish.com/blog/streamsets-transformer-auth-none-scaladtransform-code-execution) |
| 3 | Circutor LineEds (industrial energy gateway) | 24.11.14-r0 | **9.8** \* | Unauthenticated `events.xml` write with a `shellExecute` action plus a restart trigger → `system()` in `pwrstudio` | [events.xml shellExecute → system()](https://0day-rubbish.com/blog/circutor-lineeds-pwrstudio-shellexecute-unauth-command-injection) |
| 4 | IPConfigure Orchid VMS | 26.3.0 | **7.2** \* | Authenticated `gpg_key` server property → DNF `rpm --import {}` → uid 0 | [server property → rpm --import → root](https://0day-rubbish.com/blog/ipconfigure-orchid-vms-dnf-gpg-key-command-injection) |
| 5 | Asustor ADM (AS602T) | 3.5.9.RWM1 | **8.8** \* | Authenticated `music.cgi` `act=live` → `As_System` = `system()` | [music.cgi act=live → As_System](https://0day-rubbish.com/blog/asustor-adm-music-cgi-live-command-injection) |
| 6 | Maian Cart | 3.8 | **7.2** \* | Authenticated `addBanners` upload with no extension allow-list → webshell in a served directory | [banner upload → PHP webshell](https://0day-rubbish.com/blog/maian-cart-addbanners-upload-extension-webshell-rce) |
| 7 | RCDevs WebADM (Freeware) | 2.4.14 | **7.2** | Authenticated `logfile_viewer.php` `sid` → `popen`, executing as `webadm` (uid 999) on an IAM/MFA platform | [sid → popen → webadm](https://0day-rubbish.com/blog/rcdevs-webadm-logfile-viewer-sid-command-injection) |

\* More than one reading is published. Each of these advisories carries every reading alongside its own full vector, and labels what was verified versus what is conditional, inferred or rejected:

> - **Finding 1** — primary **9.8** at `PR:N`, resting on the artifact-proven absence of any application-level authorization in the page plus the structural argument that the product's own login page must be anonymous. The advisory states plainly that no extracted installer artifact proves IIS anonymous authentication is enabled for that application path specifically, and publishes **8.8** at `PR:L` as the reading where it is not.
> - **Finding 2** — primary **8.1** at `AC:H`, because the shipped configuration file sets `http.authentication=aster`; anonymous access requires the `none` mode, which is a documented operator-selectable value and a code-level fallback rather than the shipped default. **9.8** at `AC:L` is published for deployments where that mode is in effect.
> - **Finding 3** — primary **9.8** at `PR:N` grounded on a census of the authorization gate's 197 call sites, neither of which is on the vulnerable path. The record's "security is disabled by default" assertion is published as unverified rather than as an artifact-proven factory setting, and **8.8** at `PR:L` is carried for the case where the gate applies.
> - **Finding 4** — primary **7.2** at `PR:H`: the shipped OpenAPI specification grants the `config` scope required by this endpoint to the Administrator role only. **9.8** is the reading where the installer's default administrator password is unchanged, which the packaged debconf template does evidence. The research record's 8.8 at `PR:L` is disclosed and explained as not adopted.
> - **Finding 5** — primary **8.8** at `PR:L`, the only session validity check standing between the caller and the handler, with no role or privilege attribute consulted on that path. **7.2** at `PR:H` is published as a conditional, untested reading.
> - **Finding 6** — primary **7.2** at `PR:H`, administrator session required. **9.8** at `PR:N` is labelled as this advisory's own construction, conditional on deployment credentials that were never shown to be guessable.
> - **Finding 7** — **7.2** is the only score published. The research record carried 8.8 against the same `PR:H` vector, which does not compute to 8.8; that is disclosed, and `PR:L`/8.8 is left as an open question for the vendor rather than adopted.

**Totals**: 7 advisories · 7 vendors · 3 in the unauthenticated class · 4 authenticated deep chains · every finding reaches operating-system command execution inside the product's own service or handler process. Executing identity is reported as measured where it was measured — uid 0 in a container (findings 2 and 4), `webadm` uid 999 (finding 7), uid 0 in a loopback lab process (finding 6) — and as a labelled inference where the device-side or shipped-pool identity was not measured (findings 1, 3, 5). No advisory prints a score its own vector does not compute to.

**How each finding was verified** — stated here because the seven differ, and because an advisory that blurs this is worth less than one that doesn't:

- **4 driven over HTTP against a real running instance of the product** — the official container image (finding 2), a real `dpkg -i` installation of the vendor package inside a Linux container (finding 4), a genuine installation served by the PHP built-in server (finding 6), and the vendor's Docker image over TLS (finding 7). Each of these reached the service from the same host over a loopback-bound port; none was driven from a separate network host.
- **1 against shipped components deployed into a real IIS host over loopback** (finding 1): the vulnerable code ran unmodified, but a stock installation was not achieved, so the public URL prefix is derived from a literal inside the decompiled page handler rather than from a request against a stock install.
- **2 with no live product traffic at all** — the shipped ARM binary under `qemu-arm-static` with the sink invoked through a debugger, and no HTTP request ever delivered (finding 3); and static analysis plus a faithful C replication of the sink run on an analysis host, with no physical device (finding 5).

Each advisory says which applies in its own section 9 and repeats it in its summary, and none presents an emulated, replicated or component-level run as an exploit against a live deployed device.

*Earlier batches: [Batch #1](https://0day-rubbish.com/blog) · [Batch #2](https://0day-rubbish.com/blog) · [Batch #3](https://0day-rubbish.com/blog) · [Batch #4](https://0day-rubbish.com/blog) · [Batch #5](https://0day-rubbish.com/blog) · [Batch #6](https://0day-rubbish.com/blog) · [Batch #7](https://0day-rubbish.com/blog) · [Batch #8](https://0day-rubbish.com/blog) · [Batch #9](https://0day-rubbish.com/blog) · [Batch #10](https://0day-rubbish.com/blog) · [Batch #11](https://0day-rubbish.com/blog) · [Batch #12](https://0day-rubbish.com/blog)*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 13 — 7 advisories; cumulative 121 across 13 batches
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
