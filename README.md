# 0day Rubbish

> **0day vulnerabilities have become rubbish in the AI era.**

## 🎯 Why This Exists

Traditional vulnerability disclosure is broken. It's slow, bureaucratic, and ineffective. In the AI era, we can mass-produce 0days at scale—making individual vulnerabilities less valuable but more impactful when disclosed directly.

We believe **event-driven security hardening** is the most effective approach: only when vendors face real, exploitable threats do they prioritize fixes.

## 🔄 Our Disclosure Process

### Step 1: AI Discovery
Our automated AI systems continuously scan for vulnerabilities across real-world software, identifying potential 0days through pattern analysis, fuzzing, and intelligent code review.

### Step 2: Verification & PoC Development
Each finding undergoes manual validation. We develop working proof-of-concept exploits to confirm exploitability and assess real-world impact.

### Step 3: Irregular Public Disclosure
We periodically disclose verified, exploitable 0day vulnerabilities we've discovered and validated:
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

Our automated vulnerability discovery leverages cutting-edge large language models:
- **GPT-5.5** - Advanced reasoning and code analysis
- **Claude Opus 4.8** - Deep security pattern recognition
- **DeepSeek V4** - Specialized vulnerability detection

## 📂 Vulnerability Submission Format

All disclosed vulnerabilities follow a standardized directory structure:

```
product/
└── <product_name>/
    └── <version>/
        └── <vulnerability_type>/
            ├── exploit/          # Exploit scripts and PoC code
            ├── analysis.md       # Detailed vulnerability analysis
            └── summary.md        # Brief vulnerability overview
```

### Directory Rules

- **product/**: Root directory for all vulnerabilities
- **<product_name>/**: Vendor or product name (e.g., `apache`, `microsoft`, `oracle`)
- **<version>/**: Affected version range (e.g., `2.4.49`, `11.0.12`)
- **<vulnerability_type>/**: CVE-style classification (e.g., `rce`, `sql-injection`, `auth-bypass`)

### Required Files in Each Vulnerability Directory

1. **exploit/**: Directory containing working exploit scripts and PoC code
2. **analysis.md**: Comprehensive technical analysis including root cause, attack vector, and impact
3. **summary.md**: Concise vulnerability overview with affected versions and quick mitigation steps

### Example

```
product/
└── apache/
    └── 2.4.49/
        └── path-traversal/
            ├── exploit/
            │   ├── poc.py
            │   └── exploit.sh
            ├── analysis.md
            └── summary.md
```

---

**Join us in redefining vulnerability disclosure for the AI era.**
