# RCDevs WebADM 2.4.14 — OS Command Injection in the Log Viewer `sid` Parameter (Administrator Session to `webadm` uid 999)

Advisory: https://0day-rubbish.com/blog/rcdevs-webadm-logfile-viewer-sid-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

RCDevs WebADM is a closed-source identity and access management platform from RCDevs Security SA (Luxembourg). It is the management console and policy engine that sits in front of the vendor's authentication products — OpenOTP (one-time passwords and push MFA), SpanKey (SSH/OTP token management) and TiQR (mobile QR authentication) — so a compromise of the console is a compromise of the identity layer for every application behind it. The edition examined here is **WebADM 2.4.14, Freeware Edition**.

The finding is an operating system command injection (CWE-78) in the administrator log viewer, `admin/logfile_viewer.php`. The `sid` GET parameter — intended to carry a session identifier used as a filter pattern for the selected log file — is interpolated, without any escaping, into a single-quoted shell command of the form `grep -E '<sid>' <logfile> | tail -n 10000` which is then handed to PHP's `popen()`. A single apostrophe inside `sid` terminates the quoted grep pattern; everything that follows is parsed by `/bin/sh` as command text. Commands execute as the **`webadm` service account (uid=999)**, the identity the httpd workers run under.

Root was not achieved and is not claimed. The record of the verification run states explicitly that container root is a separate identity from `webadm`, and no privilege-escalation step was attempted. Severity in this advisory is therefore assessed for the identity the command actually runs under, and the qualitative weight of the finding comes from *what that identity controls* (an IAM/MFA platform's configuration, directory data and signing material) rather than from a numeric inflation of the score.

### Overview of the runtime stack

The stack matters twice in this advisory: once because it determines the execution identity of the injected command, and once because it determines how much analytical work was required before a single line of application logic could be read.

```text
webadm-httpd            Apache httpd, admin console + service endpoints vhosts
webadm-runphp           custom PHP 8.2 ZTS interpreter (build reported as 8.2.30)
                        decodes the application's Blowfish-encrypted opcache file_cache at load time
slapd                   OpenLDAP, port 389 (directory: users, OTP state, admin DNs)
mariadb                 MariaDB, port 3306 (application store)
webadm-sessiond         port 4000 (session service)
webadm-rsignd           port 5000 (libcrypto-based certificate signing daemon)
```

There is no plaintext PHP on disk. The application ships as an **opcache `file_cache` corpus that is Blowfish-encrypted at rest**, and `webadm-runphp` decrypts it in memory at load time. Section 5 documents how readable logic was recovered from that corpus, because the sink reconstruction in this advisory depends on the recovery method and its limits.

### Overview of the testbed and of what that implies

All dynamic work was performed against a Docker container named `webadm-dev` running WebADM 2.4.14 Freeware Edition, with the following host port mapping recorded for the container:

```text
container 80    -> 127.0.0.1:28080
container 443   -> 127.0.0.1:28443      (the endpoint used by the exploit run)
container 8080  -> 28081
container 8443  -> 28444
```

Two properties of this mapping are load-bearing for every reachability claim in this advisory, and section 10 returns to them:

- The two mappings recorded with an explicit address are bound to **loopback only**: `28080` carries container port 80 (plain HTTP) and `28443` carries container port 443 (TLS), as the table above shows. Every request in the verification run was issued from the container host to `https://127.0.0.1:28443`.
- Consequently, **no request in this research originated from a separate network host**. Remote reachability is therefore argued from the product's own binding configuration (an admin console vhost intended to be reached over a network), not observed from an external position. We state this as a boundary rather than presenting it as a demonstrated remote exploit.

### Overview of affected scope

Verified: **RCDevs WebADM 2.4.14, Freeware Edition**, admin console vhost, `admin/logfile_viewer.php`. No other version, edition or component is claimed. The Freeware Edition additionally required license registration (a reCAPTCHA step plus email activation) before the console endpoints became functional, and the research record documents working administrator credentials for the tested instance. No artefact establishes how that password came to be set: the record documents no vendor-shipped default administrator credential, and this research did not establish whether one exists, so none is assumed anywhere in this advisory.

### Overview of independence

The research phase recorded no prior published advisory entries for RCDevs WebADM in the sources checked, which is consistent with a product whose application logic does not exist in readable form on the target filesystem — an attacker or researcher must first defeat the encrypted-opcache packaging before any source-level analysis is possible. Neither this command injection nor the decoding method it rests on is a re-derivation of published work known to us. No identifier has been assigned to this finding at the time of writing; none is claimed here.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Field | Value |
|---|---|
| Product | RCDevs WebADM |
| Vendor | RCDevs Security SA (Luxembourg) |
| Version verified | 2.4.14, Freeware Edition |
| Component | `admin/logfile_viewer.php` (administrator console log viewer) |
| Vulnerability class | OS command injection (CWE-78) |
| Entry point | `GET /admin/<session>/logfile_viewer.php?log=<selector>&sid=<injection>` |
| Sink | `popen()` on a `grep -E '<sid>' <logfile> | tail -n 10000` command string |
| Sanitization applied to `sid` | none (no `escapeshellarg`, no `escapeshellcmd`, no quote stripping, no charset filter) |
| Authentication required | yes — administrator console session (`WAADMIN` cookie issued by `POST /admin/login_uid.php`) |
| Execution identity | `webadm`, uid=999, gid=999 (the httpd worker identity; no privilege drop) |
| Confirmation channel | out-of-band: marker appended to `/opt/webadm/logs/webadm.log`, read back over HTTP through the same endpoint with `log=webadm` |
| CVSS 3.1 base score | **7.2 (High)** |
| CVSS 3.1 vector | `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

The score line above is discussed in full in section 12, including a discrepancy with the score carried by the research record. In short: the record pairs a base score of 8.8 with a `PR:H` vector, and that pairing does not compute; this advisory publishes 7.2 for the vector it actually publishes.

### Vulnerability Summary mechanics

The mechanism is the classic quoted-context breakout. `grep -E` receives its pattern in single quotes, and the POSIX shell has no escape sequence inside a single-quoted string other than the closing quote itself. Supplying

```text
sid = ';echo MARKER $(id) $(whoami) $(hostname) >> /opt/webadm/logs/webadm.log;'
```

produces, after interpolation:

```text
grep -E '';echo MARKER $(id) $(whoami) $(hostname) >> /opt/webadm/logs/webadm.log;'' <logfile> | tail -n 10000
```

The first `'` closes the pattern (now the empty regex `''`), the `;` ends the `grep` command, the injected `echo` runs as its own command with `$(id)`, `$(whoami)` and `$(hostname)` evaluated by the shell, the trailing `''` re-opens an empty quoted string that swallows the remainder of the pipeline, and the whole line executes in the shell that `popen()` spawned. Because the endpoint does not echo command output back into its HTTP response, the appended log line is the observable proof — which is also why the exploit is self-verifying rather than interpretive (section 9).

### Vulnerability Summary preconditions

Three preconditions are documented, and all three are ordinary rather than exotic:

- a valid administrator console session (LDAP bind as the administrator DN; see section 3);
- knowledge of the random per-session URL path prefix, which the login response itself discloses in both the `Set-Cookie` `path` attribute and the `Location` header (section 3), so it is not an additional secret for an authenticated operator;
- write access to a log path the viewer can subsequently read back, which the `webadm` account has for its own log file.

## 3. Authentication Boundary

### Authentication Boundary — login flow and session issuance

The console login endpoint is `POST /admin/login_uid.php`. The recorded exchange:

```http
POST /admin/login_uid.php HTTP/1.1
Host: 127.0.0.1:28443
Content-Type: application/x-www-form-urlencoded
Content-Length: 63

login=1&username=admin&password=<redacted>&domain=Default

HTTP/1.1 302 Found
Set-Cookie: WAADMIN=<hex>; path=/admin/<RANDOMSESS>/
Location: <RANDOMSESS>/index.php
```

Properties established from the record:

- The credential check is an **LDAP bind** against the administrator DN (`uid=admin,dc=WebADM`) in the `Default` domain, so the password is verified server-side by the directory rather than compared against a value in the application. There is no client-side or application-side comparison to bypass cheaply.
- The session identifier is generated by the product's own `random_id(WA_SESSION_ID_LENGTH)` helper, described in the record as a CSPRNG construction. It is **not guessable or brute-forceable** on any realistic budget, and no weakness in session generation is claimed here.
- The console is additionally served from a **random per-session URL path prefix** — requests go to `/admin/<RANDOMSESS>/logfile_viewer.php`. The prefix is an obscurity layer, not an authorization layer: the routing rule `AliasMatch ^/admin/\w+/(.*)` maps the request to `admin/$1`, consuming the prefix and resolving the real file. For an authenticated attacker the prefix is handed over by the login response, and the exploit script parses it from `Set-Cookie: ... path=/admin/<PREFIX>/` or, failing that, from the `Location` header's `<PREFIX>/index.php`.
- The session cookie `WAADMIN` is scoped to `path=/admin/<RANDOMSESS>/`, i.e. it is only presented under the same prefix that discloses it.

### Authentication Boundary — effectiveness of the session gate

The gate was tested by behaviour, not by reading a status code. The decisive experiment is a **negative control**: the identical injection request was issued with **no session cookie at all**, and the marker was then looked for in `/opt/webadm/logs/webadm.log`. The record states the result plainly:

```text
condition          request                                              marker in webadm.log
no WAADMIN cookie  GET /admin/<RANDOMSESS>/logfile_viewer.php?...sid='; echo MARKER ...   ABSENT
valid admin session GET /admin/<RANDOMSESS>/logfile_viewer.php?...sid='; echo MARKER ...  PRESENT (uid=999)
```

The `popen()` sink is therefore reached only after the page's session check passes. The finding is **post-authentication**, and this advisory makes no unauthenticated claim for it.

### Authentication Boundary — what the HTTP 200 shell does not mean

One property of this product will mislead anyone writing a scanner or a detector, and it deserves its own statement because it produces false positives by design:

**Every `/admin/*.php` request returns HTTP 200 together with the WebADM HTML doctype, even when no session cookie is presented.** The framework renders the common HTML shell first and only afterwards runs the individual page's logic, which includes the session check. The observable consequences:

- Status code, response length and the presence of the WebADM doctype are **not** authorization signals for this application. A "200 OK with the product banner" against an admin page says nothing about whether the page's privileged logic executed.
- Detection and verification must therefore be based on a **side effect that only authenticated execution can produce** — in this research, a byte appearing in a log file that an unauthenticated request provably cannot write (the negative control above).
- Conversely, an unauthenticated request that does *not* produce the side effect is evidence the gate held, not evidence the request failed.

This is a general caution for IAM consoles that compose pages this way, and it is the reason section 9 relies on file-write-plus-readback rather than on HTTP semantics.

### Authentication Boundary — absence of a default-credential shortcut

The installation used for verification required license registration (reCAPTCHA plus email activation) before the endpoints became functional, and the record documents working administrator credentials for that tested instance. It does not document how that password came to be set, and it documents **no vendor-shipped default administrator credential**; this research did not establish whether one exists, and this advisory does not claim one either way. Two implications follow, and they are kept strictly separate: the chain requires a real administrator secret (`PR:H`), and no unauthenticated reading is published here, because the record carries no artefact that would support one.

## 4. Attack Surface

### Attack Surface — virtual hosts and listeners

The routing configuration lives in `/opt/webadm/lib/httpd.ini`. The recorded structure:

```text
vhost :443   DocumentRoot htroot/
             ^/(manag|monit|apikey|cacert|calist|srvurl|mycert|renew|ocsp|crl|ws)(/.*)?$  -> endpoints/$1.php
             /admin    -> admin/   behind a random per-session path prefix
             AliasMatch ^/admin/\w+/(.*)  ->  admin/$1

vhost :8443 and :8080   SOAP service hosts
             ^/(\w+)/?$  ->  websrvs/$1/www/index.php
             (no websrv modules are installed in the Freeware Edition -> 403)

backend listeners (not httpd vhosts)
             :389   slapd (OpenLDAP)
             :3306  MariaDB
             :4000  webadm-sessiond
             :5000  webadm-rsignd
```

The admin console — including `logfile_viewer.php` — sits on the `:443` vhost and is the surface that matters for this finding. The eleven endpoints exposed without a console session are enumerated in section 10's exhaustion discussion, since the research treated "can we reach any sink without authenticating?" as a question worth answering in full before accepting a post-authentication result.

### Attack Surface — PHP configuration that widens or limits the surface

`/opt/webadm/lib/php.ini` was recorded with the following security-relevant settings, each of which changes what an injection can and cannot do:

```ini
sendmail_path = ${ROOT}/libexec/sendmail
open_basedir  = ${INCLPATH}
display_errors = Off
expose_php     = Off
; disable_functions is NOT set
```

- **No `disable_functions`.** `exec`, `system`, `popen`, `shell_exec` and friends are all enabled in the runtime. A PHP-level injection into any string that reaches one of these is therefore a full OS command execution primitive, with no function-availability obstacle. This is the single most significant configuration fact behind the impact of the finding.
- **`open_basedir = ${INCLPATH}`** constrains PHP's own file APIs, which blocks local-file-inclusion style traversal from the PHP layer. It does **not** constrain the child process spawned by `popen()`: that child is an ordinary OS process running as `webadm` and is bound only by the filesystem permissions of uid 999, not by `open_basedir`. Any remediation reasoning that credits `open_basedir` as a mitigation for this finding is mistaken.
- **`sendmail_path` without `-t -i`** was recorded because the second shell-adjacent sink discovered in the console — `mail()` in `admin/support_ticket.php` — behaves differently than a PHPMailer-style sendmail transport would: the recipient list is delivered on the child's stdin rather than being appended to a command line. That property removed the `mail()` path from consideration as an injection sink and is documented here so the negative result is reproducible rather than merely asserted.
- `display_errors = Off` and `expose_php = Off` reduce information leakage; they have no bearing on the injection.

### Attack Surface — how the surface was mapped at all

Because no plaintext PHP exists on the target, attack-surface mapping was not `grep -r` over a source tree. It combined three artefacts: the httpd routing configuration (which enumerates URL space and handler mapping), the PHP configuration (which enumerates what the runtime permits), and the decoded opcache corpus described in section 5 (which enumerates string literals — function names, SQL fragments, shell fragments, parameter names — across all recovered admin pages). Section 6 explains why string-literal recovery was sufficient to identify both the sink and its parameter name, and section 5 states precisely what could not be recovered.

## 5. Sink Identification

### Sink Identification — recovering readable logic from the encrypted opcache corpus

This subsection exists because the rest of the advisory rests on it, and because the packaging is itself a security-relevant property of the product.

What is on disk is an opcache `file_cache`. The record documents the container format's observable structure and an entropy measurement consistent with encryption rather than with plaintext bytecode:

```text
opcache file_cache entry layout (as observed)
    01 00            format / version magic
    <size fields>    length metadata for the entry
    8d 3e 5f 60      product-specific magic, i.e. 0x605f3e8d in little-endian read order
    <payload>        Blowfish-encrypted opcache script payload
    measured entropy of payload: 7.99 bits/byte (of 8.00)
```

Recovery method, as performed:

```text
1. locate the decoder: disassemble webadm-runphp and search for references to the
   container magic 0x605f3e8d, which is the only reliable anchor in a stripped
   custom interpreter build
2. follow those cross-references to the decode routine; recover the Blowfish key
   material and the decryption flow (r2ghidra-assisted decompilation)
3. reimplement the container parser and the Blowfish decryption in Python
   (decode_webadm.py) so the corpus can be processed offline and repeatedly
4. run the decoder over the whole file_cache corpus: 315 files recovered as
   opcache bytecode carrying plaintext string literals
5. work from the string-literal layer: function names, parameter names, SQL
   fragments and shell command fragments survive decoding as readable strings
   even where the instruction layer is bytecode rather than PHP source
```

**What this recovery does and does not yield, stated plainly.** It yields the literal strings each page uses — enough to identify that a page calls `popen`, that it builds a `grep -E '...' | tail -n 10000` command, and that a parameter named `sid` is involved — but it does not yield original PHP source text. Every code sample in this section and the next is therefore labelled as a **reconstruction from decoded string literals plus observed dynamic behaviour**, not as extracted source. Where a claim depends on the exact form of a PHP statement rather than on its behaviour, that claim is flagged. The behaviour itself is not a reconstruction: it was observed directly (section 9), and the observed behaviour is what makes the reconstruction trustworthy.

### Sink Identification — sink hunting across the console pages

With the decoded corpus in hand, the console pages were swept for command-execution and file-write functions. The recorded result for `/admin/*.php`:

| Sink | Location | Authenticated? |
|---|---|---|
| `popen` building `grep -E` | `admin/logfile_viewer.php` (`sid` parameter) | yes — console session |
| `mail()` | `admin/support_ticket.php` | yes — console session |
| `Runtime`/`exec` (Java-style) | not applicable — this is a PHP application | — |

`logfile_viewer.php` is the highest-value of these: it is the only console page in the sweep where an externally supplied value reaches a shell command string. `support_ticket.php` reaches `mail()`, whose transport (per section 4) keeps the recipient off the command line, and whose remaining arguments were not shown to be attacker-controlled shell text.

### Sink Identification — the vulnerable construction

The reconstructed sink logic, assembled from the decoded string literals of `admin/logfile_viewer.php` and confirmed by the dynamic behaviour in section 9:

```php
// RECONSTRUCTION from decoded opcache string literals + observed behaviour,
// not verbatim extracted PHP source.
$log_selector = $_GET['log'];        // chooses which product log to display
$logfile      = /* resolved from the selector */;
$sid          = $_GET['sid'];        // filter pattern, no neutralization recorded

$cmd = "grep -E '" . $sid . "' " . $logfile . " | tail -n 10000";
$fp  = popen($cmd, "r");
// ... stream up to 10000 matching lines into the rendered page ...
```

Why this is an unambiguous command-injection sink rather than a merely dangerous-looking one:

- **`popen()` is a shell sink by definition.** PHP implements it on the same footing as `fopen` over `/bin/sh -c <string>`. The command string is parsed by a shell, so shell metacharacters in any interpolated value are syntax, not data.
- **The command string itself proves shell parsing**: it contains a pipeline (`|`) to `tail -n 10000`, which only has meaning to a shell. A direct `execve` of `grep` could not express it.
- **The interpolated value is inside single quotes**, the one quoting context from which there is no backslash escape — the only way out is another single quote, and the attacker fully controls whether one appears.
- **No neutralization exists** on the recorded path from `$_GET` to the concatenation: no `escapeshellarg`, no `escapeshellcmd`, no `str_replace` of quote characters, no regular-expression or charset validation, and no documented length cap on `sid`.

### Sink Identification — execution identity of the child process

The injected command inherits the identity of the httpd worker. The record is explicit on the mechanism and on the limit:

```text
httpd worker identity: webadm  (uid=999, gid=999, groups=999(webadm))
privilege drop:        none - no User= directive appears in /opt/webadm/lib/httpd.ini
root achieved:         no - container root is a separate identity and was not targeted
```

So the primitive is: arbitrary shell command execution as the application's own service account, on the host/container that runs the IAM platform. Everything that account can read or write is in scope for the attacker — configuration, directory-backed material, logs, and (over the local listeners on 389 and 3306) the LDAP and MariaDB backends, for which this account holds the application's own working access.

### Sink Identification — a second interpolation site, flagged as an unproven lead

The same command string interpolates the log file argument. In the recorded run, the shell line rendered that argument as the selector value itself (`sessiond`), which means the file operand originates from the `log` selector rather than being a fixed literal. Whether `log` is resolved through a closed enumeration of product logs or is itself attacker-influenced **was not established by this research**, and no claim is made either way. It is recorded here as a variant-analysis lead for the vendor: the fix in section 11 must cover both interpolation sites, because neutralizing only `sid` leaves the file operand of the same command line unexamined.

## 6. Source Identification

### Source Identification — the tainted input and its transport

| Property | Value |
|---|---|
| Attacker-controlled input | `sid` query parameter |
| Full source expression | `$_GET['sid']` in `admin/logfile_viewer.php` |
| Transport | HTTP GET query string, percent-decoded once by PHP's query-string parser |
| Encoding constraints | none observed: the recorded payload carried `'`, `;`, `$(`, `)`, spaces, `>>` and an absolute path |
| Neutralization on the path to the sink | none |
| Second candidate input | `log` query parameter (file operand of the same command; validation not established) |

The literal request that carried the payload during verification, with the run-unique marker elided (the recorded value embeds a per-run token, and per this project's publication rules the token is not reproduced here):

```http
GET /admin/<RANDOMSESS>/logfile_viewer.php?log=sessiond&sid=%27%3Becho%20<MARKER>%20%24(id)%20%24(whoami)%20%24(hostname)%20%3E%3E%20/opt/webadm/logs/webadm.log%3B%27 HTTP/1.1
Host: 127.0.0.1:28443
Cookie: WAADMIN=<redacted>
```

Note the encoding asymmetry, which is inherited from the verification run rather than introduced here: only the `$` is percent-encoded (`%24`), while the parentheses travel as literal bytes. PHP percent-decodes the query string once (section 5), so the decoded value below is what the handler concatenates.

Decoded `sid` value:

```text
';echo <MARKER> $(id) $(whoami) $(hostname) >> /opt/webadm/logs/webadm.log;'
```

### Source Identification — sanitization that exists, and what it is for

It is worth being precise here, because two of the three protections that *do* exist in this product are frequently mistaken for input sanitization:

- **The console session gate** (section 3) is an *authorization* control. It decides whether the page logic may run at all. It performs no validation of `sid`, and once the session check passes the parameter flows to the sink untouched. Authorization that is correctly enforced does not neutralize injection in the code it authorizes.
- **`open_basedir = ${INCLPATH}`** is a *PHP file-API confinement*. It does not apply to the child process that `popen()` creates, so it neither limits nor detects this injection.
- **The random per-session URL prefix** is *obscurity* against unauthenticated probing. It is disclosed to any authenticated operator by the login response and is irrelevant to an attacker who has just logged in.

No encoding, allow-listing, quoting or length restriction on `sid` was found anywhere on the recorded path. That absence — not a bypass of an existing filter — is the root cause.

## 7. Data Flow

### Data Flow — end-to-end chain

```text
attacker (authenticated administrator)
   |
   | (1) POST /admin/login_uid.php   login=1&username=admin&password=...&domain=Default
   |     LDAP bind as uid=admin,dc=WebADM  ->  302
   |     Set-Cookie: WAADMIN=<hex>; path=/admin/<RANDOMSESS>/
   |     Location: <RANDOMSESS>/index.php          <- attacker learns the path prefix
   |
   | (2) GET /admin/<RANDOMSESS>/logfile_viewer.php?log=sessiond&sid=';<cmd>;'
   v
httpd :443 vhost
   |  AliasMatch ^/admin/\w+/(.*)  ->  admin/$1
   v
webadm-runphp (PHP 8.2 ZTS) loads Blowfish-decoded opcache for admin/logfile_viewer.php
   |
   | (3) framework renders the common HTML shell (this is why the status is always 200)
   | (4) page logic: console session check -> PASSES (cookie present) / FAILS (no cookie: sink unreached)
   | (5) $sid = $_GET['sid']                       <- percent-decoded, not validated
   | (6) $cmd = "grep -E '" . $sid . "' " . $logfile . " | tail -n 10000"
   v
popen($cmd, "r")  ->  /bin/sh -c "$cmd"   running as uid=999 (webadm)
   |
   | (7) shell parses:  grep -E '' ; echo <MARKER> $(id) $(whoami) $(hostname)
   |                    >> /opt/webadm/logs/webadm.log ; '' sessiond | tail -n 10000
   |     $(id) $(whoami) $(hostname) are evaluated by the shell, in the child's context
   v
/opt/webadm/logs/webadm.log  gains one attacker-authored line
   |
   | (8) GET /admin/<RANDOMSESS>/logfile_viewer.php?log=webadm     <- same endpoint, second role
   |     the viewer greps/tails the very file the injected command appended to
   v
marker line rendered into the HTML response  ->  attacker confirms uid=999(webadm)
```

### Data Flow — properties of the chain worth naming

- **Taint does not cross a trust boundary on the way to the sink.** Steps (5) and (6) are in the same page and the same request; there is no queue, no storage round-trip, no worker hand-off between the parameter and the shell. That is why `AC:L` is the faithful complexity metric (section 12).
- **The chain is self-contained on one endpoint.** `logfile_viewer.php` is both the injection point and the readback channel: the attacker needs no second vulnerability, no second service and no direct filesystem access to observe the result. The `tail -n 10000` bound on the readback caps how much output can be recovered per request, but not whether execution occurred.
- **The write to a log file is what converts a blind sink into an observable one.** The endpoint does not return command output, so any verification method must supply its own observation channel; using the product's own log-viewing feature as that channel is what makes the proof deterministic (section 9).
- **The negative control is the authorization edge of the diagram.** Step (4) failing means step (6) never happens, which is the entirety of the post-authentication claim.

## 8. Exploit Construction

### Exploit Construction — step sequence

The proof-of-concept shipped with this advisory is `exploit/rcdevs_webadm_logfile_viewer_sid_command_injection_rce.py` (Python standard library only, argument-parameterized, no target address baked in). It performs:

1. **Authenticate.** `POST /admin/login_uid.php` with `login=1`, `username`, `password`, `domain` (default `Default`). Redirects are not followed, so the 302 and its headers are observable.
2. **Recover the session URL prefix.** Parse `path=/admin/([A-Za-z0-9]+)/` from the `Set-Cookie` header; if that is absent, fall back to `([A-Za-z0-9]+)/index\.php` from `Location`. Alternatively accept a prefix and cookie captured from a browser session (`--session-path`, `--cookie`), since the prefix is not a secret once authenticated.
3. **Choose a run-unique marker.** The marker must be unique per invocation: the target log accumulates lines, and reusing a marker would let a previous run's line satisfy the check. The script generates one when `--marker` is not supplied.
4. **Build the payload.** Wrap the command in the single-quote breakout: `';` + command + `;'`. The default command is the identity probe `echo <marker> $(id) $(whoami) $(hostname) >> /opt/webadm/logs/webadm.log`.
5. **Encode the parameter.** Percent-encode `sid` with `urllib.parse.quote(value, safe="/")`, which leaves `/` literal and encodes everything else. The result is *stricter* than the request form recorded from the verification run: for the same command the shipped tool emits `%24%28id%29` where the record shows `%24(id)`, i.e. it also encodes the parentheses. Both forms percent-decode once to the identical `sid` value (section 5), so the divergence changes the bytes on the wire and not the string PHP hands to the sink. The recorded run's own `%24(id)` is likewise not what `urllib.parse.quote(payload, "/")` produces, so this is an inherited difference in encoding style, not a difference in payload.
6. **Issue the injecting GET** to `/admin/<prefix>/logfile_viewer.php?log=sessiond&sid=<encoded payload>`. The response body is not the evidence; a non-200 or an aborted response does not by itself mean the command failed to run, and the script says so explicitly rather than treating an HTTP error as a failed exploit.
7. **Wait briefly** (`--readback-delay`, default one second) for the child process to flush its append.
8. **Read back** with `?log=webadm`, strip HTML tags from the response, and search for the marker.
9. **Report and exit by code.** Exit status 0 is returned in four situations: the marker was found in the read-back text (in which case the identity string `uid=...` is also extracted and printed), `--print-payload` was given (no socket is opened), `--no-readback` was given, and `--readback-log` is empty. The last three print an explicit warning that nothing has been proven about server-side execution, yet they still exit 0. Exit status alone is therefore **not** a success signal; the output text has to be read. Exit status 1 means "injected, marker not observed"; 2 means the session could not be established; 3 means a transport-level failure.

### Exploit Construction — payload engineering constraints

Two constraints on the command text were established empirically during the research and are preserved in the shipped script:

```text
payload shape that was verified:
    echo <MARKER> $(id) $(whoami) $(hostname) >> /opt/webadm/logs/webadm.log

constraints noted in the research record:
  - one command, no top-level parentheses and no statement separators inside it:
    the shell on the target rejected those constructs mid-command (recorded as
    dash behaviour); command substitution $(...) inside a single echo is accepted
  - the redirection target must be a path the webadm account can append to, and
    must be a file the same endpoint can display when asked for a different log
    selector - /opt/webadm/logs/webadm.log satisfies both
```

Exactly one command shape was executed against the target in this research, and it is the only one this advisory claims: a single `echo` carrying three command substitutions and a redirection, `echo <MARKER> $(id) $(whoami) $(hostname) >> /opt/webadm/logs/webadm.log`, read back over HTTP in the following request. The recorded constraint is narrow and specific to that run: no top-level parentheses and no statement separators inside the command, because the target's shell (recorded as `dash` behaviour) rejected those constructs mid-command, while a command substitution `$(...)` inside a single `echo` was accepted.

Everything beyond that executed form is inference, and the inference is not free. The following were **not tested** and are not claimed here:

- A nested `sh -c '...'` wrapper would have to collide with the breakout's own quoting: the payload is itself delimited by single quotes (`';` + command + `;'`), so an inner single-quoted argument has nothing left to close against. A double-quoted inner argument was never exercised.
- A pipeline was never exercised. An inner `|` would additionally bind against the pre-existing `| tail -n 10000` that the handler appends after the interpolation point, so the pipeline structure the sink builds is not free for an injected command to reuse.
- An `&&`-joined chain was never exercised, and neither was `printf ... > file` nor `python3 -c ...`.

What the record does establish is the punctuation limit, not a general capability statement: on the tested build the injected text may not contain top-level parentheses or statement separators. Readers who need another payload shape should test it rather than assume it.

### Exploit Construction — what the exploit deliberately does not do

- It does not attempt privilege escalation from uid 999. The finding is scoped to the identity the sink actually runs under.
- It does not write into the document root or plant a web shell. Writing to a path served by the `htroot/` document root would be an obvious next step for a real attacker, but it was **not attempted in this research** and is therefore not claimed as verified behaviour. The verified write target is the product log file, chosen because it doubles as the readback channel.
- It does not touch the unauthenticated endpoints. Section 10 records what was examined there and what was concluded.
- It does not print or reuse credentials in its output: the login body and any `Cookie` header are masked in the transcript, and the password can be supplied from a file (`--password-file`) to keep it out of process listings.

## 9. Dynamic Verification

### Dynamic Verification — environment

| Item | Value |
|---|---|
| Product | RCDevs WebADM 2.4.14 (Freeware Edition) |
| Deployment | Docker container `webadm-dev` |
| Endpoint exercised | `https://127.0.0.1:28443` (host mapping of container port 443) |
| PHP runtime | custom `webadm-runphp`, PHP 8.2.30 (ZTS) |
| HTTP server | `webadm-httpd` (Apache) |
| httpd worker identity | `webadm`, uid=999 — no privilege drop |
| Client | pure-standard-library Python, forcing `LC_ALL=C` for ASCII output |
| Request origin | the container host, over loopback |

### Dynamic Verification — the injecting request

The request as recorded during a verification run (marker elided for publication, as in section 6):

```text
GET /admin/<RANDOMSESS>/logfile_viewer.php?log=sessiond&sid=%27%3Becho%20<MARKER>%20%24(id)%20%24(whoami)%20%24(hostname)%20%3E%3E%20/opt/webadm/logs/webadm.log%3B%27
```

The command line the shell received:

```text
grep -E '';echo <MARKER> $(id) $(whoami) $(hostname) >> /opt/webadm/logs/webadm.log;'' sessiond | tail -n 10000
```

Note that the run-unique marker token is not reproduced in this advisory, and neither is the container hostname that the `$(hostname)` substitution returned. Both are artefacts of a specific run on a specific host, and this project publishes its evidence without publishing the operator's infrastructure. The load-bearing part of the evidence — the identity string — is reproduced verbatim below.

### Dynamic Verification — observed output

Standard output of a successful run, with the marker token elided and the trailing container-hostname field replaced by a placeholder; every other field is as recorded:

```text
[*] Target: <product base URL>
[+] Login OK, session path: <RANDOMSESS>
[*] Injecting command via sid single-quote breakout ...
[*] Reading webadm log back over HTTP to verify execution ...
[+] RCE CONFIRMED: <MARKER> uid=999(webadm) gid=999(webadm) groups=999(webadm) <whoami> <hostname>
[+] Executed as: uid=999(webadm) gid=999(webadm) groups=999(webadm)
[+] Vulnerability: post-auth command injection in logfile_viewer.php (sid param)
[+] Result: SUCCESS
```

Exit status: 0.

The three substituted fields in the confirmed line are attributable individually: `$(id)` produced `uid=999(webadm) gid=999(webadm) groups=999(webadm)`, `$(whoami)` produced the service account name `webadm`, and `$(hostname)` produced the container's own hostname. The presence of all three, in that order, is what distinguishes genuine command substitution by the shell from any string that could have been echoed by the application.

### Dynamic Verification — why this proof is deterministic

The verification is designed so that no human or model judgement sits inside the loop:

- **The marker can only be in the log if the shell wrote it.** Nothing in the product's normal operation emits an attacker-chosen random token, and the endpoint has no parameter that writes request data into the log verbatim.
- **The readback travels over HTTP through the product's own viewer**, so it proves the line exists *server-side* — not merely that the client believed something happened.
- **The negative control discriminates.** The same request without a session cookie produces no marker (section 3). A verification method with no negative control cannot distinguish "the sink executed" from "the check was too loose", and here the control was run.
- **Reproducibility was recorded across four independent runs**, each with its own marker, all returning `uid=999(webadm)`.

### Dynamic Verification — boundaries of what was verified

Stated as limits rather than as hedges:

- Every request originated on the container host against a **loopback-bound** mapping. No request crossed a network boundary, so remote reachability in section 10 is argued from configuration, not measured from a remote host.
- The endpoint does not return command output, so **no direct stdout/stderr evidence** exists. Proof is indirect by construction (file write plus HTTP readback of that file). An attacker who cannot write to a log the viewer can display would need a different observation channel.
- The sink's PHP source is a **reconstruction** (section 5). What is verified is behaviour — the injected command executed with the expected identity — and the string literals that identify the command's shape.
- Privilege escalation, persistence, lateral movement to slapd/MariaDB, and any effect on downstream OpenOTP/SpanKey/TiQR consumers were **reasoned about from the identity and the listener layout, not executed**. They are described as impact in section 10 with that provenance attached.
- Only WebADM 2.4.14 Freeware Edition was tested. Behaviour on other versions or on licensed editions with additional web service modules installed is unknown and unclaimed.

## 10. Reachability and Security Impact

### Reachability and impact — network position

WebADM is deployed as a management console and authentication front end, and its admin vhost exists to be reached over a network — by definition, an administrator must be able to log in to it from somewhere other than the host itself. That is the basis for assessing the attack vector as Network. The recorded testbed nevertheless bound the container's published ports to loopback, and the exploit was driven from the container host. The distinction to carry forward:

- **What was observed**: an authenticated administrator, from a host that could reach the console, obtained command execution as uid 999.
- **What was not observed**: the same chain driven from a separate host across a network segment. That requires the admin vhost to be published on a routable interface, which is the product's normal deployment form but not a property this research measured.
- **What follows for a defender**: an installation whose admin vhost is bound to a management VLAN, a VPN, or loopback shrinks the attacker population to whoever can reach that interface. It does not change the defect: any authenticated administrator — including one acting on stolen credentials, a compromised help-desk account, or a malicious insider — reaches the sink from wherever the console is reachable.

### Reachability and impact — the unauthenticated question, answered in full

Before accepting a post-authentication result, the research exhausted the unauthenticated attack surface, because an unauthenticated primitive in the same product would have dominated this finding. The work comprised the primary analysis, two independent adversarial review passes whose task was specifically to break the "you need a session" conclusion, and a final sweep. The eleven endpoints reachable without a console session, and the disposition of each:

| Endpoint | Function as recorded | Shell or file-write sink? |
|---|---|---|
| `/apikey` | API-key generation via CSPRNG `random_id`, storage through `sql_store_apikey`, plus a sendmail notification with a fixed command line and a configured sender | none |
| `/mycert`, `/renew` | certificate issuance/renewal via the PHP openssl extension (`openssl_csr_new` and related) backed by `webadm-rsignd` | none |
| `/cacert`, `/calist`, `/crl`, `/srvurl` | static readers of CA material, CA lists, CRLs and service URLs | none |
| `/ocsp` | OCSP responder built on a pure-PHP ASN.1/OCSP library | none |
| `/ws` | web-application / web-service dispatcher; the Freeware Edition installs no webapps, so it returns 501 | none |
| `/manag` | management access behind HTTP Basic plus an LDAP bind, fail-closed | gated |
| `/monit` | monitoring access behind a bearer token, fail-closed | gated |

Supporting findings from the same sweep, each of which closes a route rather than merely failing to open one:

- **Zero file-write sinks on the unauthenticated surface.** The final sweep across those endpoints found no `file_put_contents`, `fwrite`, `fopen`, `move_uploaded_file`, `copy`, `rename` or `tempnam` reachable from unauthenticated input — which removes file upload, log poisoning and web-shell placement from the unauthenticated menu.
- **Zero shell sinks on the unauthenticated surface.** No `popen`, `exec`, `system`, `passthru`, `shell_exec` or `proc_open` reachable from unauthenticated input in those eleven endpoints.
- **Every `include`/`require` hit was a static framework bootstrap**, not attacker-influenced, so the include path was not a route to code execution.
- **`webadm-rsignd` on port 5000 is libcrypto-based with no shell strings**, so the signing daemon reachable by the certificate endpoints does not provide a command path around the PHP layer.
- **The `mail()` transport keeps recipients off the command line** (section 4), which removes the notification path from `/apikey` and from `admin/support_ticket.php` as an injection route.
- **The `/admin` session gate was dynamically verified effective** (the negative control in section 3), not merely assumed from configuration.
- **The SOAP vhosts** (`:8443`, `:8080`) resolve `^/(\w+)/?$` to `websrvs/$1/www/index.php`, and the Freeware Edition installs no such modules, so they return 403 rather than exposing a second application layer. They remain unexamined in a licensed installation that does ship web service modules.

Conclusion: **unauthenticated remote code execution was not reached**, and this advisory presents the finding as post-authentication only. The table above is published so that the negative result is auditable — a reader can see which surfaces were closed and on what evidence, rather than being asked to trust an assertion.

### Reachability and impact — what uid 999 controls

Executing as `webadm` on the IAM platform is not a low-value position, even though it is not root. From that identity an attacker can, by ordinary filesystem and local-service access rather than by any further exploit:

- **Read and rewrite the platform's own configuration** under `/opt/webadm`, including the httpd and PHP configurations that define routing, authentication domains and backend connectivity. A configuration rewrite is a persistence mechanism that survives service restart without touching the operating system.
- **Reach the directory data.** The LDAP backend listens locally on port 389 and the application account holds working access to it. For an MFA platform that means user records, OTP state and the enrolment data that every downstream authentication decision depends on. Modification of that data can disable, redirect or re-enrol a user's second factor — an integrity impact on authentication itself, not merely on a log file.
- **Reach the application database** on the local MariaDB listener at port 3306 with the credentials the application itself carries.
- **Interact with the signing daemon** on port 5000 from inside the trust boundary, in a position where the network-level protections an operator might place on `webadm-rsignd` do not apply.
- **Write to product logs** — as this exploit demonstrates — which supports both anti-forensics (removing evidence of a session) and the observation channel used here.
- **Interfere with service availability** for the console and for the authentication path it fronts, which for an MFA platform means locking users out of everything it protects.

The distinction that determines the score versus the priority: all of this lies **inside the authorization domain the application already occupies**, which is why the vector keeps Scope Unchanged (section 12). But the *content* of that domain is the identity infrastructure of whatever WebADM was deployed to protect. An administrator of an IAM/MFA platform who gains OS command execution on it controls who may authenticate and how, across every relying application. Remediation priority should reflect that: this is not a 7.2 to be scheduled behind a 7.2 on a printer. It is a 7.2 on the thing that decides who is allowed in.

### Reachability and impact — detection notes

- The single reliable network indicator of exploitation is a console request to `logfile_viewer.php` whose `sid` parameter contains shell metacharacters — above all an apostrophe, since the breakout requires it. Section 3's caution applies to implementing that detection: the HTTP status of the response is not usable as part of the signal, because the admin pages return 200 regardless of whether the session check passed.
- On the host, an appended line in `/opt/webadm/logs/webadm.log` containing shell-substitution output (`uid=` fragments, a hostname field, or an attacker token) in a file whose normal entries are structured log records is a strong indicator. The child of `webadm-httpd` being a shell running `grep`/`tail` for the viewer is itself normal, so process ancestry alone is a weak signal; the payload shape in the request and the anomaly in the log content are the discriminating ones.
- Post-incident, treat any administrator session that made such a request as a full compromise of the platform: rotate the administrator password, rotate LDAP and database service credentials, re-inspect `/opt/webadm` configuration for rewrites, and audit second-factor enrolments for changes made since the request.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

**1. Neutralize the parameter at the sink (mandatory).** Apply `escapeshellarg()` to the value before concatenation. It wraps the argument in single quotes and neutralizes any embedded quote, which removes the breakout this advisory exploits:

```php
$cmd = "grep -E " . escapeshellarg($sid) . " " . escapeshellarg($logfile) . " | tail -n 10000";
$fp  = popen($cmd, "r");
```

`escapeshellcmd()` is **not** an acceptable substitute. It escapes a set of metacharacters but does not move a value out of the quoting context it was placed in, and PHP's own documentation warns against relying on it to make a string safe for a shell. A fix consisting only of `escapeshellcmd` leaves quote-context reasoning to the vendor's future readers and should be treated as incomplete.

**2. Remove the shell from the path entirely (recommended, defence-permanent).** The only reason a shell is involved is the pipeline to `tail`. Both halves can be expressed in PHP or, if an external `grep` is wanted, via an argument vector with no shell:

```php
$proc = proc_open(['/usr/bin/grep', '-E', '--', $sid, $logfile],
                  [1 => ['pipe', 'w']], $pipes);
// read at most N lines from $pipes[1] and close - no /bin/sh, no metacharacter semantics
```

Or without any child process: open the file with `SplFileObject`/`fopen`, iterate with a bounded tail counter, and filter with `preg_match` on a pattern compiled from the validated input. This removes the entire class rather than one instance of it, and it also fixes the second interpolation site (the file operand) as a side effect, because both operands become elements of an argument array.

**3. Validate `sid` against the shape the product itself generates.** `sid` is a session identifier filter, and the product's own `random_id()` output is alphanumeric. Enforce that at the boundary — for example `^[A-Za-z0-9]{1,64}$`, or a length cap plus a charset allow-list — return 400 on mismatch, and log the rejection. This is the cheapest correct fix and it makes the shell path unreachable with a hostile value even if recommendation 1 is later refactored away.

**4. Resolve the `log` selector through a closed enumeration.** The file operand of the same command derives from the `log` parameter. Map it through a fixed server-side table of known selectors to absolute log paths, reject anything absent from the table, and never build a path from request input. This closes the unproven second site (section 5) before it becomes a finding, and it also prevents a path from being steered to a file the service account should not display.

**5. Separate privileges and constrain the write surface.** Set an explicit worker identity in `/opt/webadm/lib/httpd.ini` (`User=`/`Group=` with a dedicated, minimal account) rather than relying on the ambient uid 999 for every part of the console, and remove the service account's ability to append to any log that the log viewer can display back to a client. As shipped, the same account can both write the log and read it to an authenticated user, which is precisely what turned a blind injection into a self-verifying one. Splitting write and display duties removes the attacker's cheapest observation channel.

**6. Constrain what the runtime can spawn.** The recorded `php.ini` sets no `disable_functions`, so `popen`, `exec`, `system`, `shell_exec`, `passthru` and `proc_open` are all available to every page in the console. Enumerate the pages that genuinely need to spawn a process, and disable the rest for the remainder — accepting that recommendation 2 requires `proc_open` for the viewer, so the durable ordering is: disable broadly, then re-enable narrowly per verified need.

**7. Add a regression test that fails on the metacharacter.** A single automated case — request `logfile_viewer.php` with `sid` containing an apostrophe, assert a 400 and assert that no shell child was spawned — would have caught this and will catch its recurrence. Pair it with an alert on console requests whose parameters contain shell metacharacters.

### Fix Recommendations — operator-side, until a patch exists

- **Restrict the admin vhost.** Bind the console to a management interface only, or place it behind a VPN or a mutually authenticated reverse proxy. Loopback/VLAN confinement does not fix the defect but it removes the population of attackers who hold stolen administrator credentials from the internet at large.
- **Treat console administrator credentials as tier-zero secrets**: unique per installation, rotated, and themselves protected by a second factor where the product's own configuration allows it. The chain starts at a valid administrator login, so credential theft is the realistic path in.
- **Enforce alerting on the indicators in section 10**: `sid` values containing an apostrophe, and unstructured lines appearing in `/opt/webadm/logs/webadm.log`.
- **Assume compromise of the identity layer, not of one service**, if exploitation is suspected: rotate the administrator password, the LDAP service credentials and the database credentials, re-verify `/opt/webadm` configuration against a known-good copy, and audit second-factor enrolments for the interval in question.

## 12. CWE and CVSS

### CWE and CVSS — classification

- **CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')** — the primary classification. An externally influenced value is placed into a string passed to `popen()` without neutralization of shell metacharacters, and the string is interpreted by `/bin/sh`.
- **CWE-20: Improper Input Validation** — contributing. The `sid` parameter, whose legitimate content is the product's own alphanumeric session identifier format, is accepted with no charset, format or length constraint.
- **CWE-116: Improper Encoding or Escaping of Output** — the mechanism-level family for the missing `escapeshellarg()` on a value destined for a command string.
- **CWE-732 / CWE-276: Incorrect Permission Assignment / Default Permissions** — applicable to the auxiliary condition that the service account can append to a log the same endpoint displays back, which is what made blind injection observable. This is a hardening finding, not the injection itself.
- **CWE-250: Execution with Unnecessary Privileges** — applicable in the narrow sense that every console page shares one worker identity with no privilege separation, so the log viewer's shell access is as broad as the platform's.
- Not applicable, and deliberately not listed: any authentication-bypass or default-credential CWE. The session gate held under dynamic test (section 3), and the research record documents no vendor-shipped default administrator credential (this research did not establish whether one exists).

### CWE and CVSS — vector derivation

Each metric below is taken from a documented fact in this advisory, and the vector is computed with the CVSS v3.1 base metric algorithm:

| Metric | Value | Documented basis |
|---|---|---|
| Attack Vector | Network (N) | The sink is reached over HTTP(S) against the admin console vhost. Caveat recorded in section 10: our own run was issued from a loopback-bound mapping on the container host, so N reflects the product's deployment form as a network-reachable console, not a measurement from a remote host |
| Attack Complexity | Low (L) | One deterministic GET after a normal login. No race, no memory layout, no brute force: the session id is CSPRNG-generated and the URL prefix is handed to the authenticated operator by the login response |
| Privileges Required | High (H) | A console administrator session is required, and the negative control proves the sink is unreachable without it. Authentication is an LDAP bind as the administrator DN |
| User Interaction | None (N) | No action by any other user is needed; the authenticated operator issues the request directly |
| Scope | Unchanged (U) | The command executes as `webadm` — the same identity, on the same host, with the same backend access the vulnerable application already legitimately holds. No authorization boundary is crossed by the injection itself |
| Confidentiality | High (H) | Command execution as the application account reads the platform's configuration, directory-backed material and database credentials |
| Integrity | High (I) | The same account can rewrite configuration and directory state, including authentication factors |
| Availability | High (A) | The same account can disrupt the console and the authentication path it fronts |

The computation, shown in full because the rounded result is counter-intuitive:

```text
ISS          = 1 - (1-0.56)(1-0.56)(1-0.56)          = 0.914816
Impact(S:U)  = 6.42 x 0.914816                        = 5.87311872
Exploitability = 8.22 x 0.85(AV:N) x 0.77(AC:L)
                      x 0.27(PR:H, scope unchanged) x 0.85(UI:N) = 1.234707705
BaseScore    = Roundup(min(5.87311872 + 1.234707705, 10))
             = Roundup(7.107826425)                   = 7.2
```

The CVSS `Roundup` function is defined as the smallest number of one decimal place that is greater than or equal to the input — a ceiling to the tenth, not a round-to-nearest. That distinction is the whole reason the value above is 7.2 and not 7.1: the raw sum 7.107826 is closer to 7.1 by ordinary rounding, but the specification's ceiling takes it to 7.2. Anyone reconciling this advisory against a calculator that reports 7.1 has found that discrepancy and nothing more.

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` computes to **7.2 (High)**.

### CWE and CVSS — the recorded score, and why this advisory does not print it

The research record for this finding states a base score of 8.8 and pairs it with the very same `PR:H` vector derived above. That pairing is arithmetically impossible, and it is disclosed here rather than quietly resolved, because a published advisory that prints a score its own vector cannot produce is worse than one that reports a lower score honestly.

The facts:

- The vector published in this advisory — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` — computes to 7.107826 raw, i.e. **7.2**. It cannot produce 8.8 under any CVSS 3.x formula.
- 8.8 is the base score of the `PR:L` variant: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` computes to 8.708373 raw, i.e. **8.8**. So the recorded number is not arbitrary — it is the correct score for a *different privilege metric*, transplanted next to a vector that contradicts it.
- `PR:L` asserts that an authenticated principal **below administrator** can reach the sink. **Our evidence does not support that assertion.** The console session is issued by an LDAP bind as the administrator DN; the negative control shows the sink is unreachable without that session; and the research documented no lower-privileged console role that can open `logfile_viewer.php`. On the record available, `PR:H` is the faithful metric and **7.2** is the faithful score.
- This is stated as an open question for the vendor rather than as a settled fact about the product, because the absence of a documented low-privileged role in our record is not the same as proof that none exists in the product's role model. **If a below-administrator console role (an auditor or help-desk profile, for example) can reach the log viewer in a shipped or supported configuration, then `PR:L` is correct and 8.8 is the right number.** We would amend this advisory on evidence either way; we will not claim the higher figure without it.
- The defect class is worth naming, since it recurs: a score recorded from an initial hypothesis and later left beside a vector that was corrected. Recomputing every published score from its vector, and treating any mismatch as a publication blocker, is the mechanical fix — and it is why the numbers in this section were produced by running the vector through the CVSS 3.1 algorithm rather than copied from the record.

The qualitative point in the record remains correct and is preserved in prose, not in the number: an administrator who obtains OS command execution on an IAM/MFA platform controls identity infrastructure for every relying application, so remediation urgency exceeds what a 7.2 in isolation suggests (section 10). Publishing 8.8 would not make that argument better; it would make the score untrustworthy.

### CWE and CVSS — the Scope decision

Changed scope was considered and rejected, and its arithmetic is reproducible so the rejection is visibly a judgement about evidence rather than about numbers. Under `S:C` the `PR:H` weight becomes 0.50 instead of 0.27:

```text
Impact(S:C)    = 7.52 x (0.914816 - 0.029)
                 - 3.25 x (0.914816 x 0.9731 - 0.02)^13        = 6.128026
Exploitability = 8.22 x 0.85 x 0.77 x 0.50 x 0.85              = 2.286496
BaseScore      = Roundup(1.08 x (6.128026 + 2.286496))
               = Roundup(9.087684)                              = 9.1
```

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` computes to **9.1 (High)**.

We reject it because no authorization boundary is crossed by the injection. The vulnerable component is the PHP console running as `webadm`; the injected command runs as the same `webadm`, on the same host, and the backends it can then reach (LDAP on 389, MariaDB on 3306, `webadm-rsignd` on 5000) are backends the application already holds working access to. Changed scope is reserved for cases where the vulnerable component affects resources outside its own security scope; here everything the attacker gains was already inside the application's scope, which is exactly the property that makes the finding severe without needing a scope change to express it.

### CWE and CVSS — what is deliberately not published

No `PR:N` figure appears in this advisory, unlike several of our other publications that carry a deployment-conditional second reading. The reason is evidential: those readings were justified by a shipped default credential or an authentication bypass demonstrated in the same research. Here, license registration was required to bring the endpoints up, the record documents working console administrator credentials for the tested instance without establishing how that password came to be set, the record documents no vendor-shipped default administrator credential and this research did not establish whether one exists, and the session gate held under dynamic test. An unauthenticated reading would therefore have no supporting artefact in this record, and inventing one to raise the headline number is precisely the failure mode section 12 exists to avoid. If a default credential or a session-gate bypass in this product is later demonstrated, the correct response is a separate finding with its own evidence and its own vector.

### CWE and CVSS — summary

Primary and only published score: **7.2 (High)** — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, post-authentication administrator to `webadm` (uid 999) command execution on an IAM/MFA platform. The record's 8.8 belongs to the `PR:L` vector, which the evidence here does not support; see the reconciliation subsection above.

---

- Advisory: https://0day-rubbish.com/blog/rcdevs-webadm-logfile-viewer-sid-command-injection
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com
