# 0day Rubbish

> **0day vulnerabilities have become rubbish in the AI era.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Latest batch](https://img.shields.io/badge/Latest_batch-6_advisories-red)](https://0day-rubbish.com/blog)
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

### Latest Batch — Batch 16 (6 advisories)

*Six findings that all took the auditor's own instruments to prove, and none of which claims more than the instruments showed: one anonymous upload pair against a PHP endpoint that never outgrew its 2007-era authentication model; one routing daemon's diagnostics endpoint that inverted its own hostname validator; one consumer router whose SOAP app-install field became a shell; and three separate entry points into an industrial cellular router's shell-built configuration surface. Four of the six publish a figure lower than the raw source record suggested, and each of those downgrades is printed with its arithmetic beside the score it corrects.*

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | NETGEAR RAX120 (Nighthawk AX12) | V1.2.5.18 | **6.8** \* | The SOAP InstallApp action on the LAN-side management plane builds an `rm -rf` shell command over the `apName` argument; a `$(...)` substitution reaches the root-configured web stack before the command word resolves | [InstallApp apName → shell command substitution](https://0day-rubbish.com/blog/soap-installapp-apname-command-injection-root-rce) |
| 2 | NUUO Crystal Server | 3.19.0.85 | **9.8** \* | A bare `copy()` upload endpoint with no session, no extension gate and no path check, carrying on a web-root landing pattern the vendor's discontinued line made famous; a single anonymous request pair writes an executable page and fetches it back | [upload.php → web-root write → web-side code execution](https://0day-rubbish.com/blog/nuuo-crystal-server-unauth-upload-php-webroot-write-rce) |
| 3 | Raritan PX3 PDU G4 | firmware 4.3.14 | **8.8** \* | A diagnostics `ping`/`traceroute` handler whose hostname validator inverts its own return check, reachable by every ordinary authenticated session while `netstat` carries an admin-only attribute the diagnostics pair is missing | [diag ping → return-value inversion → shell injection](https://0day-rubbish.com/blog/raritan-px3-pdu-g4-diag-ping-traceroute-command-injection) |
| 4 | Moxa MAR-2000 FWR_MAR2000 V1.0 Build 15010909 | V1.0 Build 15010909 | **7.2** \* | The management UI's program table passes its `argument` field straight into the user-program launcher's command line | [Executer argument → program-launch injection](https://0day-rubbish.com/blog/mar-2000-executer-program-argument-command-injection) |
| 5 | Moxa MAR-2000 (same product, same batch) | V1.0 Build 15010909 | **7.2** \* | Five separate `ipsec.py` handlers shell out into route-management commands carrying attacker text from the tunnel-address fields; one product's findings are never split across batches | [tunnel address → route-management shell](https://0day-rubbish.com/blog/mar-2000-network-ipsec-command-injection) |
| 6 | Moxa MAR-2000 (same product, same batch) | V1.0 Build 15010909 | **7.2** \* | A scenario engine periodically re-evaluates a saved `ping` condition, and the thread re-forms the shell command on each pass, so a stored payload fires without any request ever being resent by the attacker | [scenario ping → auto-execution thread](https://0day-rubbish.com/blog/mar-2000-scenario-ping-command-injection) |

\* All six publish more than one reading. Each advisory carries the readings it rejected or made conditional next to the one it stands behind, each with its own vector and arithmetic:

> - **Finding 1** — **6.8** published at `AV:A/PR:H`: no shipped artifact evidences WAN-side exposure, and the action belongs to the admin tier, so both halves of the naive 8.8-and-networked reading fell to artifact checks, and the source record's own 8.8 is shown inside as the PR:L variant with its arithmetic, not as the headline. `AV:N` at 7.2 is the labelled conditional for deployments whose management plane is deliberately exposed.
> - **Finding 2** — **9.8** at `PR:N`. A single anonymous request pair; the web tier re-serves whatever it wrote. Execution lands as the web service account of the replication environment and is reported exactly as such: the device-side service identity was never measured and is not claimed. `S:C` at 10.0 is printed with arithmetic and rejected; an `AV:A` 8.8 is the labelled conditional for management-VLAN isolation; a device-identity-unknown caveat prints prominently in the Summary and is repeated in the file-name and text: no "root" or "system" claim is carried anywhere in this finding's headline, slug or body. The family-model upload lineage in the vendor's discontinued line is described as a pattern without any identifiers, per this advisory-series house rule.
> - **Finding 3** — **8.8** at `PR:L`: the shipped `netstat` vs diagnostics attribute asymmetry is the artifact that proves any ordinary session is the intended principal class; the factory-default account pair is disclosed as a separate adjacent weakness with its own conditional `PR:N` 9.8 reading, never as this finding's vector. `PR:H` at 7.2 is printed and rejected.
> - **Findings 4-6** — all three **7.2** at `PR:H`, printed with the correction that the source record's 8.8 is the `PR:L` arithmetic under the corrected 881-relation family rule, shown as rejected-variant arithmetic alongside. The three factory-default credential conditionals (9.8 each, if unchanged) are labelled, never headlined, and `S:C` 9.1 is printed and rejected for all three. All three carry the honest negative result that a semicolon payload in the scenario-ping sink fails and blocks the evaluating thread, so the working forms (`$(...)`, newline) print with the test.
> - **Verify boundary, uniformly stated** — every sandbox marker `uid=0` in this batch is a property of the replication environment used to test it, and where a shipped image configures its own web stack as root, that is an in-image fact printed as such. No finding matrix-claims device-side identity, and no live-device claim is made anywhere in this batch: three findings were tested by `sink-level replication on an isolated cloud-hosted sandbox`, one (Crystal Server) by an end-to-end HTTP chain inside its own VM image, one (PX3) at instruction-level from the image and command-level replication of the sink (no end to end; the RPC→cfgd→hardware chain would not complete under emulation), and one (RAX120) by instruction-level request-path disassembly plus native-gcc sink replication for three mutually independent markers plus a benign control.
> - **Root and identity claims, verified one by one**: the published 9.8 (`Finding 2`) explicitly does not claim root or system; the Published `Findings 4-6` slug claims stop at "shell-injected into the management stack", with the replication sandbox identity disclosed as the source of the `uid=0` lines; the RAX120 finding's slug and inline claims are the only ones in the batch to carry the word root, and both its anchors are the in-image lighttpd `User root` configuration plus three zero-id markers and a control, never a live device.

**Totals**: 6 advisories · 4 products · 4 vendor organisations (NETGEAR, NUUO, Raritan/Legrand, Moxa), with the MAR-2000 series carrying three of them because one product's qualifying findings are never split across batches · 1 unauthenticated chain · 5 authenticated chains, of which four explicitly require an admin-class session and one any-ordinary-session. A single 6.8 carries the famous-brand slot's headline, and that is deliberately the batch's least dramatic number: `AV` and `PR` both fell to what the shipped artifacts proved, rather than what the naive-model template suggests, and the published `Totals` say so plainly. Four of the six publish at least one figure lower than the raw source record suggested — an un-evidenced WAN side twice over, a mis-entered PR tier four times over — and every one of those downgrades is printed where the reader will see it, with the rejected arithmetic, vector, rationale and correction history beside the surviving score.

**What the instruments actually showed** — stated because the batch's credibility rests on exactly this:

- **Two chains end to end, four to the sink.** Finding 2 ran a full anonymous HTTP request pair against the vendor's own VM image and confirmed execution of the written page; Finding 3's `diag` handler was verified instruction-level from the released firmware plus command-level injection of three payload shapes with a benign control; Findings 4-6 were verified by firmware-source analysis plus native-gcc shell replication of each exact sink construction, markers and benign controls included; Finding 1 was verified at the request-path line in disassembly and then by native-gcc sink replication for three independent markers plus a benign control. No end-to-end claim is made for any non-live finding, and the batch's README row for each says "disassembly" or "replication" in so many words.
- **Vantage point, uniformly:** requests or executions never crossed an untrusted network boundary in any finding of this batch. Where a finding claims scope broader than the replication environment, that claim is anchored to a shipped artifact — an in-image binding or in-image web-stack configuration — and says so in those words.
- **What our own harness supplied** — because a state we created is not a product default: the replication host environment (sandbox account identities measured as a property of the host, then mirrored into the findings' claims of what is NOT claimed on the device side); the benign controls that separate a finding from an accident; the single-use closure markers (a one-way window) where an entry point is closed after first use.

*Every previous batch and its advisories are listed under [Releases](https://github.com/Exploit-Garbage/0day-Rubbish/releases).*


*Every previous batch and its advisories are listed under [Releases](https://github.com/Exploit-Garbage/0day-Rubbish/releases).*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 16 — 6 advisories; cumulative 144 across 16 batches
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
