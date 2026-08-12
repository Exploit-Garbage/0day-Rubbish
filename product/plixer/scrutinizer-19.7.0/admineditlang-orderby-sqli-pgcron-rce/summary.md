# Plixer Scrutinizer adminEditLang ORDER BY SQL Injection Authenticated RCE

## Summary

Plixer Scrutinizer 19.7.0's `adminEditLang` handler passes the HTTP `orderBy` parameter directly into a SQL `ORDER BY` clause with no escaping. The injection-check only blocks unescaped semicolons, which an `ORDER BY` expression does not need. Because the `plixer` database user is PostgreSQL SUPERUSER and pg_cron is installed by default, an attacker schedules a `COPY ... TO PROGRAM` job via `cron.schedule_in_database()` — a single-statement expression that executes an OS command as the `postgres` user within ~60 seconds. Authenticated RCE using the default `admin/admin` credentials (or any admin session). Dynamically verified.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Plixer Scrutinizer
- **Versions**: 19.7.0
- **Vendor**: Plixer

## Impact

- **Confidentiality**: Full read of host filesystem and database as `postgres`
- **Integrity**: Arbitrary OS command execution via `COPY TO PROGRAM`
- **Availability**: Full control of the Scrutinizer host and database

## Exploitation Prerequisites

Default `admin/admin` credentials (or any admin session); pg_cron extension installed (default); `plixer` DB user is SUPERUSER (default); CSRF token obtainable during login.

## Mitigation

1. Escape or whitelist the `orderBy` parameter in `return_lang_table_data`
2. Run the `plixer` DB user as least privilege (revoke `COPY TO PROGRAM`, `cron.schedule`)
3. Extend the injection-check to block function calls in `ORDER BY` (or use parameterized placeholders)
4. Restrict `cron.schedule_in_database` to a maintenance role
5. Force a password change on first login

## Timeline

- **Discovered**: 2026-07-20
- **Public Disclosure**: 2026-08-12 (batch #4)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble.
