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

### Latest Batch — Batch 12 (8 advisories)

*Management planes, device controllers and data-integration runtimes — where the authenticated administrator turns out to be one configuration write away from root.*

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | Lightstreamer Server (ENTERPRISE) | 7.4.8 build 3506 | **8.1** \* | Unauthenticated JMX diagnostic command → `jvmtiAgentLoad` → native code execution as the service user (root in the verified deployment) | [jvmtiAgentLoad → OS command execution](https://0day-rubbish.com/blog/lightstreamer-unauth-jmx-jvmti-agentload-rce) |
| 2 | Lightstreamer Server | 7.4.8 build 3506 | **9.8** \* | Shipped placeholder JMX/RMI credentials → `MLet` remote class loading → root | [placeholder creds → MLet → root](https://0day-rubbish.com/blog/lightstreamer-default-creds-jmx-rmi-mlet-rce) |
| 3 | Logo Netsis NetOpenX REST | 2.0.6.9 | **9.8** \* | Unauthenticated SQL injection in the OAuth token endpoint → `xp_cmdshell` → SYSTEM | [OAuth endpoint SQLi → xp_cmdshell → SYSTEM](https://0day-rubbish.com/blog/netsis-netopenx-unauth-sqli-xp-cmdshell-rce) |
| 4 | Safe Software FME Flow | 2026.2 build 26333 | **8.8** \* | Authenticated Zip-Slip in `StoreManager.extract` → arbitrary file write → JSP compiled and run under the Tomcat service account | [zip entry name → arbitrary write → code execution](https://0day-rubbish.com/blog/fme-flow-zipslip-arbitrary-file-write-rce) |
| 5 | MultiTech Conduit AEP | 6.3.6 | **7.2** | Authenticated `import_config` uploaded-filename command injection → root | [filename → `MTS::System::cmd` → root](https://0day-rubbish.com/blog/multitech-conduit-import-config-command-injection) |
| 6 | Lantronix SGX5150 | 9.13.0.0R7 | **7.2** \* | Authenticated `FsBrowseClean` command injection → root | [FsBrowseClean → newline vector → root](https://0day-rubbish.com/blog/lantronix-sgx5150-fsbrowseclean-command-injection) |
| 7 | Cambium cnMatrix EX3024F | 6.2.1-r4 | **7.2** \* | Authenticated SSL certificate CSR command injection (`COMMON_NAME`) → `system()` → root | [CSR COMMON_NAME → openssl req → root](https://0day-rubbish.com/blog/cambium-cnmatrix-ssl-csr-command-injection) |
| 8 | Server Technology PRO3X rack PDU | `spdu-pro3x-030600` build 46640 | **7.2** \* | Authenticated listener `program` override in `port_mux` → `execv` as root | [listener program → execv → root](https://0day-rubbish.com/blog/servertech-pro3x-port-mux-command-injection) |

\* More than one reading is published. Each of these advisories carries every reading alongside its own full vector, and labels what was verified versus what is conditional or assumed:
>
> - **Finding 1** — primary **8.1** with `AC:H`, because the endpoint only names a path for the native library; the agent file must already be reachable there by some other means. **9.8** with `AC:L` is the reading where that precondition is already satisfied, and the advisory states that in our verification the file was placed beforehand over an authenticated root session.
> - **Findings 6, 7, 8** — primary **7.2** at `PR:H`, a genuine administrator session being required. Findings 6 and 8 additionally carry **9.8** as the reading where the factory credential is unchanged: for finding 8 that credential is proven from extracted firmware artifacts, while for finding 6 it is a research-note assertion whose derivation was never reversed, and finding 7 carries **9.8** only as an operational-posture figure rather than as a scored reading.
> - **Finding 2** — **9.8** primary, because the placeholder credential ships inside the distribution archive and nothing randomizes it; **7.2** is the reading where an operator has rotated it.
> - **Finding 3** — **9.8** is the recorded figure and applies where the service's SQL login holds sysadmin; the advisory also publishes a **7.5** lower bound for a login that does not, and an **8.1** `AC:H` alternative, and declines to restate the research notes' unsourced 9.1 estimate as verified.
> - **Finding 4** — **8.8** for any authenticated principal, including the built-in low-privilege roles; **9.8** applies only under an explicitly non-shipped-default configuration.
>
> No advisory prints a score that its own vector does not compute to.

**Totals**: 8 advisories · 7 vendors · 3 in the unauthenticated class (2 pure pre-authentication, 1 shipped-placeholder credential) · 5 authenticated deep chains · every finding reaches root or SYSTEM in the execution context its own advisory documents (6 root, 2 SYSTEM — one of them through a Tomcat service running as LocalSystem) · 4 device-class products (industrial IoT gateway, serial device server, enterprise switch, rack PDU) · all with reproducible PoC.

**How each finding was verified** — stated here because the eight differ, and because an advisory that blurs this is worth less than one that doesn't:

- **2 reproduced against a live running instance of the shipped product** (both Lightstreamer findings) — the product was unpacked from its own distribution archive and started on the research host, reached over loopback.
- **5 reproduced against instrumented reconstructions or emulated firmware of the product's own components, with no physical device** — an IL-patched build of the shipped assemblies hosted in a loopback console process (Netsis), and `qemu`-emulated images or root filesystems in which the product's own daemons were run for real (MultiTech, Lantronix, Cambium, Server Technology).
- **1 verified at component level because a full product installation was not deployed** (FME Flow): the traversal and write primitive were proven against the shipped code path, and the full end-to-end HTTP delivery chain rests on decompiled source rather than a live run.

In the device-class findings the vulnerable sink was proven under emulation and the surrounding request chain was verified component by component, not end to end on hardware. Each advisory says which of these applies in its own section 9, and none of them presents an emulated or reconstructed run as an exploit against a live deployed device.


*Earlier batches: [Batch #1](https://0day-rubbish.com/blog) · [Batch #2](https://0day-rubbish.com/blog) · [Batch #3](https://0day-rubbish.com/blog) · [Batch #4](https://0day-rubbish.com/blog) · [Batch #5](https://0day-rubbish.com/blog) · [Batch #6](https://0day-rubbish.com/blog) · [Batch #7](https://0day-rubbish.com/blog) · [Batch #8](https://0day-rubbish.com/blog) · [Batch #9](https://0day-rubbish.com/blog) · [Batch #10](https://0day-rubbish.com/blog) · [Batch #11](https://0day-rubbish.com/blog)*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 12 — 8 advisories; cumulative 114 across 12 batches
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
