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

### Latest Batch — Batch 14 (10 advisories)

*Code execution reached from surfaces each product trusts by design: a zero-credential provisioning import on an IP-PBX, a low-privileged panel tenant writing nginx directives, any reviewer uploading a zip, a backup user uploading one chunk, a DICOM store choosing its own filename. Two of the ten belong to a class worth naming on its own — products that ship unarmed and hand administrative control to whichever client reaches them first.*

| # | Product | Affected Version | CVSS | Class | Advisory & PoC |
|---|---------|------------------|------|-------|-----------------|
| 1 | Auerswald COMmander 6000 / 6000R (IP-PBX) | 8.6D build 128154 | **9.8** \* | Two unauthenticated requests: the provisioning archive import extracts with unsanitised entry names as root and overwrites the `hping2` binary, then network diagnostics runs it through `sh -c` → uid 0 | [provisioning zip-slip → binary hijack → root](https://0day-rubbish.com/blog/auerswald-commander-provisioning-import-zip-slip-binary-hijack-root-rce) |
| 2 | CloudPanel | 2.5.4-3 | **8.8** \* | Authenticated `rootDirectory` site setting emitted unfiltered into the generated nginx virtual host → WebDAV write primitive → the product's own root php-fpm pool | [site setting → nginx directive → uid 0](https://0day-rubbish.com/blog/cloudpanel-site-rootdirectory-nginx-vhost-injection-root-rce) |
| 3 | SmartBear Collaborator Server | 15.1.15101 | **7.5** \* | Any authenticated reviewer's DOORS/Simulink zip upload slips a `.gsp` page into the webroot, where the Groovy template servlet executes it → uid 1001 | [review upload → webroot `.gsp` → Groovy](https://0day-rubbish.com/blog/smartbear-collaborator-doors-upload-zip-slip-webroot-gsp-rce) |
| 4 | Titan MFT Server (South River Technologies) | 26.0.0.364 | **8.1** \* | The first-run window exposes administrator creation with no credentials at all, then a job post-command reaches the OS unquoted inside the LocalSystem transfer engine | [first-run takeover → job post-command → SYSTEM](https://0day-rubbish.com/blog/southriver-titan-mft-firstrun-admin-setup-job-command-injection) |
| 5 | Dataedo Portal + Dataedo Agent | 26.2.8 | **8.1** \* | Authenticated repository connection-string export, decrypted offline with a static key → sysadmin repository credentials → scheduler job deserialisation executing on the Agent host | [connection string → static key → Agent host](https://0day-rubbish.com/blog/dataedo-portal-repository-connection-string-scheduler-job-agent-rce) |
| 6 | Abyss Web Server X1 (Aprelium) | 2.16.22.0 | **7.5** \* | The first-run window lets any client passing the console access rule register the administrator with no credentials; a console form then writes the server configuration so a log file is served as a `/bin/sh` CGI, and a User-Agent quote-context escape smuggles the command into that log | [console takeover → log-as-CGI → uid 0](https://0day-rubbish.com/blog/aprelium-abyss-web-server-firstrun-console-takeover-conf-to-cgi-rce) |
| 7 | Synametrics Syncrify | 6.2 build 1178 | **7.5** \* | Authenticated chunk upload takes its filename straight into a `File` constructor on the one branch with no separator check, while three sibling branches do filter → write into `/etc/cron.d`, and the server runs as root | [chunk filename → `/etc/cron.d` → root](https://0day-rubbish.com/blog/synametrics-syncrify-publiclink-chunk-upload-traversal-cron-root-rce) |
| 8 | PacsOne Server (RainbowFish) | 7.3.9 | **7.2** \* | DICOMweb STOW-RS uses the SOP Instance UID as a destination filename with no validation, and the rename runs before the database insert → traversal write into a served directory | [SOP Instance UID → traversal write](https://0day-rubbish.com/blog/rainbowfish-pacsone-stowrs-sop-instance-uid-traversal-rce) |
| 9 | Maian Guardian | 2.1 | **7.2** \* | Authenticated license-generator input reaches a shell, and the escaping routine the product ships is a no-op under its shipped debug setting → uid 33 | [license generator → no-op escaper](https://0day-rubbish.com/blog/maian-guardian-license-generator-command-injection) |
| 10 | Maian Pal | 2.1 | **7.2** \* | Authenticated product-image upload with no extension allow-list, into a served directory that alone among its peers carries no execution restriction → webshell as uid 33 | [product image → webshell](https://0day-rubbish.com/blog/maian-pal-product-image-upload-webshell-rce) |

\* Every one of the ten publishes more than one reading. Each advisory carries the readings it rejected alongside the one it stands behind, each with its own complete vector and its own arithmetic, and labels what was measured against what is conditional, inferred or withdrawn:

> - **Finding 1** — **9.8** at `PR:N`: two requests, zero cookies, zero credentials. The internal proof that authorization is the gap is a response-code asymmetry — the same handler answers 401 under its service-family route name and 200 under the route this chain uses. `S:C` is argued at length and **rejected at 10.0**, because the web tier already runs as uid 0 and the rootfs holds no suid binary, so there is no authority boundary left to cross. The chain was re-run with the administrator password set to a non-empty value, a tightening rather than a relaxation, and still reached uid 0, so it does not depend on password configuration.
> - **Finding 2** — **8.8** at `PR:L`, the panel role the product itself distinguishes from administrator. Scope Changed is discussed and deliberately kept out of the vector: the outcome is host root, but the panel already mediates that host, so the authority crossed is the one the product was granted at install. No factory panel credential exists — the product ships in a zero-user state and the installer creates the first administrator — and the account used in verification was ours, not a default.
> - **Finding 3** — **7.5** at `AC:H` is the headline, not 8.8: the only shipped artifact exercised was the vendor's official container image, and in that image used exactly as shipped **the chain does not work**, because its webserver volume is created root-owned while the service runs as uid 1001, so the first directory creation fails with `EACCES`. The shape where it does work is the native install, and that shape was never verified — the native installer was never run on a real host — so it stands as a labelled structural inference. **8.8** at `AC:L` is published as the conditional reading for deployments where the upload tree is writable by the service uid, which the product's own code creates on the line before it reads the first archive entry. The blocked shape is stated on the advisory's first screen, and it is why this finding is not the batch's second-highest score.
> - **Finding 4** — **8.1** at `AC:H`, not `AC:L`: the chain needs no credentials, but it needs a deployment state the attacker can discover and cannot create, extend or re-open, and window duration was never measured. **9.8** at `AC:L` is published for an installation confirmed to be inside its window. Both `S:C` readings are printed with arithmetic and rejected. The window is described as a state, never as an absence of authentication, and the advisory gives operators three concrete ways to check whether they are inside one.
> - **Finding 5** — **8.1** at `PR:H`, `AC:H` and `S:C`. Scope is Changed on component and host grounds: the vulnerable portal's authority ends at its own process and role model, while the outcome lands on a separately installed agent, in a separate process, under a separate identity, on a separate machine. `AC:H` carries the two conditions that remain after `PR:H` — an agent actually attached, and a network path to the repository listener. **9.1** at `AC:L` is the conditional for the topology that satisfies both; **6.6** at `S:U` is printed and rejected. An earlier anonymous zero-click reading of this chain is **withdrawn inside the advisory itself**, with the reversal argument: the agent reads its own configuration file and exposes no remote-configuration surface, so the propagation leg does not exist.
> - **Finding 6** — **7.5** published at `AV:A`, not `AV:N`: the shipped console access rule admits private ranges, so the honest reach is adjacent-network. `AC:H` carries the first-run window. Wider `AV:N` readings are published alongside it for deployments that expose the console, and none of them is the headline.
> - **Finding 7** — **7.5** at `AC:H`, where `AC:H` carries two conditions outside the attacker's control: that the listener serving this route is reachable from the attacker's position, and that the host runs a cron daemon scanning `/etc/cron.d`. **8.8** at `AC:L` is the labelled conditional for a reachable listener. Two further readings are printed with arithmetic and rejected — `S:C` at 8.6, and **`AV:L` at 7.8, which computes higher than the published score**, so rejecting it is not a way of raising the number. No shipped artifact establishes the factory listener binding in either direction and the advisory claims neither. The factory administration password is documented, is forced to change on first login, is treated strictly as a contributing fact, and is used nowhere in the reasoning or in any score.
> - **Finding 8** — **7.2** at `PR:H`: the privilege table in the tested instance held exactly one row, at the administrator group, and both installer-created database accounts failed the permission check. **8.8** at `PR:L` is published as a conditional, because the privilege is a per-row column and granting it to a non-administrator acquisition account is coherent by design — but no such grant was demonstrated, and the advisory says so plainly.
> - **Finding 9** — **7.2** at `PR:H`. Rejected readings are published with their own vectors: `PR:N` at 9.8, because no unauthenticated path reaches a sink and the remote API is gated by an install-time random key, and `PR:L` at 8.8, because no graduated back-end role was shown to reach the operation. The unsalted-MD5 comparison behind that API gate is reported as a separate weakness and folded into nothing.
> - **Finding 10** — **7.2** at `PR:H`, with four named rejected or conditional readings printed against it: unauthenticated at 9.8, a lower-privileged back-end role at 8.8, elevated complexity, and required user interaction. `S:C` at 9.1 is rejected because the outcome stays inside the same identity on the same host.

**Totals**: 10 advisories · 10 products · 9 vendor organisations, since Maian Guardian and Maian Pal come from the same seller · 3 in the unauthenticated class · 7 authenticated chains · every finding reaches operating-system command execution inside the product's own service, handler or transfer engine. Executing identity is reported as measured: uid 0 in four of them (findings 1, 2, 6, 7), Windows `NT AUTHORITY\SYSTEM` in two (finding 4 on its own host, finding 5 on the agent host), `uid=1001(collab)` in one (finding 3) and `uid=33(www-data)` in three (findings 8, 9, 10). No advisory prints a score its own vector does not compute to, and all ten publish at least one rejected or conditional reading next to the figure they stand behind. The batch is deliberately less top-heavy than its predecessors: one clean 9.8 rather than three. Nine of the ten publish a figure lower than the naive reading of the same chain would give — a shipped console access rule that admits only private ranges, an unproven listener binding, a first-run window whose duration was never measured, a privilege table holding a single row, an official container image that blocks the write outright, a cross-component precondition, and two products where the administration role is the only principal that was demonstrated — and every one of those downgrades is documented where it is made.

**How each finding was verified** — stated here because the ten differ, and because naming what our own harness supplied is what makes the rest of it believable:

- **9 driven over HTTP against real product code.** The vendor `.deb` installed inside a container with the vendor's own nginx, MariaDB and sudo present, five end-to-end rounds observed (finding 2); the vendor's published container image, four mutually independent execution records, three with fresh random marker tags (finding 3); a fresh default Windows install from the unattended package, driven through a real Blazor circuit over a raw-socket DevTools client (finding 4); the vendor's own binaries extracted from the vendor installers by parsing the single-file bundle manifest, run as a production Kestrel instance on a private container network with the real agent executable on Windows Server (finding 5); a live product instance in a network namespace whose only interface was loopback, three rounds green (finding 6); an instance installed from the distributed archive into `/opt/Syncrify` and started with the shipped run script (finding 7); the vendor-installed instance driven end to end through authentication, a `multipart/related` DICOM POST and execution of the written file (finding 8); one end-to-end run over HTTP against an instance built from the shipped source, with six further tainted fields on the same sink established by source reading only (finding 9); and the shipped archive installed to completion in a container, 32 tables created and the installer removed afterwards (finding 10).
- **1 against the shipped ARM rootfs under user-mode emulation** (finding 1): the filesystem was extracted from the vendor ROM image and run under `qemu-arm` with syscall tracing, the vendor binaries were unmodified and re-verified by digest, and the evidence set includes a four-quadrant cross of benign-versus-slipping archive against pristine-versus-hijacked binary. No physical appliance was used and no request came from a separate network host. The advisory says so in its own words and does not present the run as an exploit against a live device.
- **Vantage point, uniformly:** in every one of the ten, requests were issued from the target host itself or from a private container network that no external party can route to. No finding was driven across an untrusted network boundary. Where an advisory claims remote reachability, that claim rests on the product's own binding configuration, and each one says so in those words rather than presenting it as a measurement.
- **What our own harness supplied** — because a state we created is not a product default: a 35-line `systemctl` shim standing in for a container with no init as PID 1 (finding 2); an upload tree chowned to the service uid so the write primitive could be exercised at all, kept alongside the pristine shape that stays blocked (finding 3); a database reset back to the first-run state in order to re-open the window for a full-chain replay (finding 4); the portal started from extracted binaries rather than through the install wizard, which left one signing key at its shipped default (finding 5); a loopback listener binding we applied before testing, with no shipped artifact establishing the factory value in either direction (finding 7); database and administrator accounts chosen at the setup prompts and archive ownership restored, because the product ships no default web credentials (finding 8); and `/bin/echo` in place of a proprietary generator binary we did not possess, where the shell evaluates command substitution before it resolves the command word, so the stand-in cannot suppress the injection (finding 9).

*Every previous batch and its advisories are listed under [Releases](https://github.com/Exploit-Garbage/0day-Rubbish/releases).*

---

## 🔁 An Ongoing Series — Weekly Disclosures

This is a **continuous disclosure series**. Thanks to continuous optimization, the AI-driven discovery pipeline now produces new 0-day findings at a stable daily rate, and we disclose verified batches on a **weekly cadence**.

- **Latest batch**: Batch 14 — 10 advisories; cumulative 131 across 14 batches
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
