# OSNexus QuantaStor — alertConfigSet smtpPassword Command Injection → Root RCE

## Summary

QuantaStor 6.8.3.018 (OSNexus SDS platform, Ubuntu 22.04 OVA) runs its storage backend `qs_service` (C++, 139 MB) as **root**. When an alert fires, `COsnAlertManager::sendEmail` builds the alert-mail command as a shell string and executes it via `execl("/bin/sh","/bin/sh","-c",<cmd>)`. The SMTP fields come from the authenticated `alertConfigSet` admin API: `CTaskAlertConfigSet::run` sanitizes `senderEmailAddress`/`smtpServerIpAddress`/`smtpUsername` with `removeChars` — but **skips `smtpPassword`**, which is stored raw and later interpolated into the `-w '<smtpPassword>'` single-quote slot with no escaping. One single quote in the stored password closes the slot; the remainder executes as a separate root command on the next alert dispatch.

Any authenticated administrator (any real password — the injection is independent of the value) converts a routine configuration write into root RCE via plain HTTP POSTs: `alertConfigSet` (malicious password + fail-fast SMTP pointing at closed 127.0.0.1:25, which still satisfies the `isSmtpConfigured` guard) → `alertRaise` → async `sendEmail` → `/bin/sh -c`. Verified against the REAL binary: five independent dynamic runs, every marker root-owned (`uid=0`; a root-only `/etc/shadow` read; host identification), plus a six-task adversarial falsification pass (all NOT_REFUTED, 0.92). The malicious config persists in osn.db — a self-sustaining backdoor that re-executes on every subsequent alert.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **Class**: authenticated (administrator) command injection → root

## Affected Products

- **Product**: OSNexus QuantaStor (software-defined storage management platform)
- **Versions**: 6.8.3.018 verified; any release whose `sendEmail` builds the mailer command as a shell string with an unescaped smtpPassword slot is likely affected
- **Vendor**: OSNexus (USA)
- **Prerequisites**: valid administrator credentials (HTTP Basic over the JSON-RPC endpoint). Adjunct findings (not the injection basis): factory default `admin:password`; the `/qstorapi` gateway fabricates those default credentials when no Authorization header is present

## Impact

- **Privilege**: root on a storage appliance — read/write all stored data, destroy or ransom storage pools, capture credentials, pivot into the storage network
- **Persistence**: the malicious `smtpPassword` persists in the configuration and re-executes on every alert dispatch until reverted
- **Vector**: pure HTTP against the standard management API — no MITM, no local access

## Mitigation

1. Preferred: argv-array execution — invoke the mailer without a shell (`qs_sendalert.py` already accepts `-w` as an argument)
2. If shell construction remains: complete shell escaping of every interpolated field (`'` `;` `|` `&` `$` `(` `)` backtick `#`)
3. The `removeChars` sanitization must cover all user-controlled SMTP fields, explicitly including `smtpPassword`
4. Defense in depth: run `qs_service` as a dedicated low-privilege account, escalating only for narrow operations
5. Operators (interim): audit the configured `smtpPassword` for shell metacharacters and revert the alert configuration if any is present
