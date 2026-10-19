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

### Latest Batch — Batch 15 (7 advisories)

*Execution surfaces that trust their own operators and their own configuration: a license gate that compares a raw request URI instead of the routed path and then issues an administrative principal to a caller holding no credential, a database that ships its own system password and offers a scripting language to whoever holds it, a render farm whose job manager performs no identity check unless somebody switches one on, a firmware upgrade that is executed without ever being verified, and two appliances whose management forms format one user-supplied field straight into a shell. None of the seven needed a memory-corruption bug or a novel primitive. Each is a product doing precisely what it was written to do, with one check missing.*

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | Parasoft Continuous Testing Platform | 10.7.5-SNAPSHOT | **9.8** \* | Two anonymous HTTP requests: the license check compares the raw request URI rather than the routed path so the gate is walked around, the authentication filter fails open and hands out an administrative principal to a caller presenting no credential, and the database-restore path deserializes attacker-supplied Java objects in a product with zero `ObjectInputFilter` uses → a page written into the webroot and executed by the product's own container | [license gate bypass → fail-open → unfiltered deserialization → uid 1000](https://0day-rubbish.com/blog/parasoft-ctp-unfiltered-deserialization-license-gate-fail-open-jsp-rce) |
| 2 | Exasol Database (docker-db deployment) | 7.1.30 | **8.8** \* | The single-container form ships a documented `sys:exasol` credential that no first login forces anyone to change; that session can create a PYTHON3 user-defined function calling `os.popen`, and command output returns through the `SELECT` result instead of being blind | [shipped SYS credential → PYTHON3 UDF → non-blind execution](https://0day-rubbish.com/blog/exasol-database-default-credential-python-udf-os-popen-rce) |
| 3 | Royal Render | 9.1.26b | **8.1** \* | `rrServer` on port 7773 performs no identity check in its shipped configuration — authorization is opt-in and the vendor's own documentation states it is off by default — so a client that can place a scene file where a worker will read it submits an `Execute` once-job and gets a shell script run on that worker | [default-unauthenticated job submission → worker root](https://0day-rubbish.com/blog/royal-render-default-unauthenticated-job-submission-root-rce) |
| 4 | ProSoft RLX-IFH24E | v2.2.44 | **7.2** \* | An authenticated administrator's firmware upgrade is executed with no integrity check of any kind — no signature, no digest, only a platform string that the shipped firmware itself publishes — so a crafted package runs at uid 0 and additionally overwrites the account database | [unsigned upgrade package → root + account database overwrite](https://0day-rubbish.com/blog/prosoft-rlx-ifh24e-unsigned-upgrade-package-root-rce) |
| 5 | Edimax BR-6478AC | v2.20 | **7.2** \* | A manufacturing ATE-test handler reached with an authenticated session formats roughly thirty parameters into a command line with `sprintf` and hands it to `system()`, and this route is not one of the four the product gates on uptime → command substitution reaches the shell inside a web server that already runs as root | [formWlanMP → sprintf → system() → root](https://0day-rubbish.com/blog/edimax-br-6478ac-formwlanmp-command-injection-root-rce) |
| 6 | Edimax BR-6478AC | v2.20 | **7.2** \* | The WAN-configuration handler carries the same `sprintf` → `system()` shape in a different field, so the injected text is re-parsed by `/bin/sh -c` | [setWAN → sprintf → system() → root](https://0day-rubbish.com/blog/edimax-br-6478ac-setwan-command-injection-root-rce) |
| 7 | TRENDnet TV-IP302PI | 1.02.38 | **7.2** \* | The NTP server address is passed to a shell-form `system()` call inside a daemon that runs as root, behind an authentication gate that fails closed, so a semicolon, a command substitution or a backquote in one text field reaches the host shell | [NTP address → shell-form system() → root](https://0day-rubbish.com/blog/trendnet-tv-ip302pi-ntp-command-injection-root-rce) |

\* All seven publish more than one reading. Each advisory carries the readings it rejected alongside the one it stands behind, each with its own complete vector and its own arithmetic, and labels what was measured against what is conditional, inferred, or withdrawn:

> - **Finding 1** — **9.8** at `PR:N`. Two anonymous HTTP requests, no credential and no cookie. `S:C` at 10.0 is printed and rejected: the deserialising controller, the webroot and the page-servlet mapping are one application in one JVM, and execution carries the product's own uid. `PR:L` at 8.8 is published for deployments where an authentication provider actually is configured — the chain's two hops sit behind an authenticated() call, so the headline depends on the fail-open gate — and was not detonated. A third route, satisfying that call with an offline-forged session cookie whose key is a compile-time literal, appears **only** as a labelled static inference and is not part of the rated chain: building a fake security provider to demonstrate it would have been self-generated evidence, and the refusal to do so is stated in the advisory. `AV:A` at 8.8 is published as a downward conditional for management-network-only shapes. The version is a snapshot build, so the affected-version claim is scoped to that build and to any build shipping the same restore-path source, and no cross-version claim is made.
> - **Finding 2** — **8.8** at `AV:A`, not 9.8: the vendor's own docker-db documentation publishes the stand-alone form with the host port bound to loopback, so no shipped artifact establishes an all-interface host bind; the earlier working assumption was withdrawn inside the advisory rather than quietly dropped. `AV:N` at 9.8 and `AV:L` at 8.4 are published as labelled conditionals, and the facts that *are* artifact-backed are stated separately — the in-container listener binds all interfaces, and the documented multi-host form is `--network=host`. Executing identity is reported as measured: `uid=500(exadefusr)`, with root present only as a supplementary group, no escalation attempted, and the directory name was changed to stop claiming root. `PR:N` is defended on CVSS 3.1's own wording about settings that are deployment-invariant, and contrasted in-text against two credentials this same product does randomise per deployment; `PR:L` 8.0, `PR:H` 6.8 and `S:C` 9.7 are printed and rejected. The advisory also prints the vendor's statement that this deployment form is not officially supported and that no fix is planned for it, which is why the finding is published at all.
> - **Finding 3** — **8.1** at `AC:H`, not 9.8: the complexity carries the one condition the attacker cannot create — a scene file the worker will read, which our harness placed on the worker host. `AC:L` at 9.8 is published for shapes where placement is available, and neither was detonated. `S:C` at 9.1 (and 10.0 at `AC:L`) is printed and rejected because scheduler-to-worker dispatch is documented function inside one managed domain. Authorization-enabled conditionals are printed at 8.8, 7.5, 7.2 and 6.6 with an explicit note that which privilege level applies was never tested, because no non-administrative account was available. Root is reported exactly as measured, with its cause stated — the worker was started from a root shell — and is not claimed as a vendor-mandated default. A second injection point claimed by the earlier research record was **downgraded to structural inference**: new artifact evidence shows the captured job record carries no such field at all, so the verified chain is the scene-reference path alone.
> - **Finding 4** — **7.2** at `PR:H`. `PR:L` at 8.8 is rejected: a uid-500 entry shares the administrator's password hash, but no lower-privileged principal was demonstrated against this interface. `S:C` at 9.1 is rejected because the CGI and the installer are both already root, so no authority boundary is crossed. `AC:H` at 6.6 is rejected because the only precondition is a platform string the firmware itself publishes, and the benign control run isolates it. `PR:N` at 9.8 is printed as a labelled conditional and **not** demonstrated, since the base image containing the web server was not in hand. Verification ran inside a chroot: the firmware's own unmodified upgrade tool was executed against a staged payload with markers, plus a control run producing none. No HTTP request was ever issued at this product, no reboot could occur, and nothing in the advisory is presented as an exploit against a live device. The factory password hash is deliberately not printed.
> - **Findings 5 and 6** — both **7.2** at `PR:H`, each recomputed rather than inherited: the research records for this product family systematically write 8.8 where the vector computes to 7.2, and both advisories say so and publish the discrepancy. Rejected: `PR:L` at 8.8 (there is one realm and one account, and the authorization handler is a stub, so no ordinary-user role exists to demonstrate), `S:C` at 9.1 (the web server already runs as root), `AC:H` at 6.6 (these routes carry no uptime gate, unlike four sibling routes), `AV:A` at 6.8 (the stock WAN-side policy). Two conditionals at 9.8 are published and labelled — the factory password never rotated, which is reasoned rather than demonstrated, and the pre-configuration setup state, which is structural inference and was never exercised — with the note that an earlier research pass had read that state as a post-setup unauthenticated path, meaning the rating was lowered, not raised. The shipped default password is disclosed as its own weakness (CWE-798) and is not the vector for either finding; the recorded digest could not be reproduced, so that claim rests on the shipped password file and the model's published factory login, with an explicit non-claim printed about which account name the realm accepts.
> - **Finding 7** — **7.2** at `PR:H`, argued from the recovered privilege model gating NTP configuration plus an authentication gate that fails closed with 401. The recorded 8.8 belongs to that vector's `PR:L` value and the discrepancy is published rather than overwritten. Conditional 8.8 at `PR:L` (any valid session) and conditional 9.8 at `PR:N` (unrotated factory password) are both labelled undemonstrated; `S:C` 9.1, `AV:A` 6.8 and `AC:H` 6.6 are printed and rejected. The credential requirement is structural and the administrator-role requirement was read rather than differentially tested, because no sub-administrator account existed. The claim that `system()` is the final executor was re-attributed to static evidence — the replica itself invokes a shell, so crediting the detonation with proving shell-versus-argument form would be circular.

**Totals**: 7 advisories · 6 products · 6 vendor organisations, with the BR-6478AC carrying two of them because one product's findings are published together rather than split across batches · 3 in the unauthenticated class (finding 1 needs no credential at all, finding 2 needs only the password the product ships, finding 3 needs none while authorization stays off) · 4 authenticated chains · every finding reaches operating-system command execution inside the product's own service, handler or worker. Executing identity is reported as measured and the three readings differ: `uid=1000(parasoft)` in one, `uid=500(exadefusr)` with root as a supplementary group only in another, and uid 0 in the remaining five — of those five, one is uid 0 on a worker process and four are uid 0 inside a controlled replica rather than on the shipping device. The batch is deliberately modest at the top: a single 9.8, no finding claiming an identity above what was observed, and six of the seven publish at least one figure lower than the naive reading of the same chain would give — an unpublished host binding, a placement our own harness supplied, a privilege table that was read rather than tested, a base flash image we did not have, a single account realm, and a research record whose arithmetic we corrected downward.

**How each finding was verified** — stated here because the seven differ, and because naming what our own harness supplied is what makes the rest of it believable:

- **2 driven over HTTP against live product code.** Finding 1: a live instance built from the shipped release, driven with two anonymous HTTP requests, an evaluated expression returning 42 against a marker-tagged body, and a 404 control on a sibling path. Finding 2: three rounds against the vendor's published container image through the vendor's own client, with command output returning in-band through the result set.
- **1 driven from a second host against a live service.** Finding 3: the job manager on its shipped port, verified from a separate host on a different network segment using a private-range source address, with the marker written by a worker and a clean control run leaving none.
- **4 verified against unmodified product binaries, not against a live device.** Finding 4: the firmware's own upgrade tool executed in a chroot against a staged payload, markers plus a benign control, and the pre-execution identity captured. Findings 5 and 6: sink semantics replicated in an isolated sandbox — injected marker created, benign control absent, exit codes recorded — because full-device big-endian emulation failed to run at all, so the HTTP leg is instruction-level artifact evidence rather than a fired request. Finding 7: the vulnerable call replicated against an ABI-matched donor root filesystem whose vendor is deliberately withheld, with three metacharacter vectors each producing a root marker and a benign address producing none.
- **Vantage point:** in findings 1, 2, 4, 5, 6 and 7 the requests or executions never crossed an untrusted network boundary — ports were published to loopback by our harness, or the binary was invoked locally. Where an advisory claims network reachability it argues it from the product's own binding, transport and authentication model and says so in those words, rather than presenting it as a measurement. Finding 3 is the only one driven from a separate host.
- **What our own harness supplied** — because a state we created is not a product default: the scene file placement (finding 3), the staged package path that the CGI's own move operation would have created (finding 4), the replica host environments (findings 5, 6, 7), and loopback-only publication of container ports (findings 1 and 2).


*Every previous batch and its advisories are listed under [Releases](https://github.com/Exploit-Garbage/0day-Rubbish/releases).*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 15 — 7 advisories; cumulative 138 across 15 batches
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
