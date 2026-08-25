# Leostream Connection Broker — Authenticated SQL Injection → lo_export Webshell → sudo Root RCE

## Summary

Leostream Connection Broker 9.1.37.0 (a closed-source VDI connection broker) contains an authenticated SQL injection in `call_back.pl?action=user`: the user-controlled `_where` parameter is concatenated verbatim into a PostgreSQL `SELECT ... WHERE ... AND (<_where>)` statement.

The impact escalates to **root** because the default installation ships with:

1. DB user `leo` as a PostgreSQL **SUPERUSER**, with the postgres process running as OS user `leo` (uid 1000);
2. webroot `/home/leo/app` owned by `leo`, so postgres can write any web-routable `.pl` file;
3. `leo` configured with **NOPASSWD sudo**;
4. the `r=digest` request-signature scheme covering only parameters matching `^(mb_|action|r|[^=]*[u_]id)` — **`_where` is outside the signed scope**, so arbitrary SQL can be injected without breaking the signature.

Using the default credentials `admin/leo`, an attacker injects `lo_from_bytea` + `lo_export` to write a Perl webshell over `welcome.pl`, triggers it **unauthenticated** via `/welcome.pl?c=<cmd>` (RCE as `leo`), then escalates to **root** via NOPASSWD sudo. Verified end-to-end (`uid=0(root)`, `/etc/shadow` read, arbitrary file-write marker). CVSS 8.8+.

## CVSS Score

- **Score**: 9.1 (high) — authenticated SQL injection to root privilege escalation
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Leostream Connection Broker
- **Versions**: 9.1.37.0 verified; earlier 9.x releases with the same `_where` handling are likely affected
- **Vendor**: Leostream Corporation
- **Stack**: Perl 5.32 + Apache mod_perl + PostgreSQL 9.5.25 + Redis, self-contained RPM

## Impact

- **Confidentiality**: Full host compromise — `/etc/shadow`, broker database, VDI infrastructure
- **Integrity**: Arbitrary webroot file write (webshell) and OS command execution as root
- **Availability**: Full control of the connection broker and the VDI session infrastructure it manages

## Mitigation

1. Parameterize `call_back.pl` queries; never concatenate `_where` into SQL
2. Extend the `r=digest` signature to cover all user-controllable parameters (including `_where`)
3. Drop `leo` from PostgreSQL superuser; revoke `lo_export`/`lo_from_bytea` file-write functions
4. Run postgres as a separate OS user; make the webroot read-only
5. Remove `leo NOPASSWD: ALL`; enforce password change at install time
