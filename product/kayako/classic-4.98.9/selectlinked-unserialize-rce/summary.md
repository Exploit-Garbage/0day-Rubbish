# Kayako Classic 4.98.9 - SELECTLINKED custom field scalar into a bare mb_unserialize, chained through destructor gadgets to system() command execution

Advisory: https://0day-rubbish.com/blog/selectlinked-unserialize-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Kayako Classic, the Fusion-generation code base of the Kayako helpdesk product line, is a closed-source PHP
application that organisations deploy on their own infrastructure to run customer-support desks. Its 4.98.9
STABLE Build 10335 release is distributed as the source archive
`fusion_stable_sourceobf_4_98_9_10335_df7ca14.tar.gz` (41 MB), the final STABLE distribution of the 4.98
line. The "SOURCEOBF" label notwithstanding, the archive carries no obfuscation layer at all: the 4,434 PHP
files it contains were read across the application directories as ordinary source, with no protected or encoded
file among them, which is what allowed this research to follow the request path at source level rather than by
inference. The application runs on its own framework, SWIFT, whose
dispatch model is a thin bootstrap per entry interface: twelve such interfaces (index, staff, admin, visitor,
staffapi, api, cron, rss, winapp and console among them) each define `SWIFT_INTERFACE` and require
`__swift/swift.php`, which loads the router and resolves URIs of the form
`Interface-entry?/App/Controller/Action/args`.

The defect sits in the custom-field subsystem. A helpdesk custom field of type linked select (the internal
constant `SWIFT_CustomField::TYPE_SELECTLINKED`) stores its values in `swcustomfieldvalues.fieldvalue`. When a
value arrives as an array, the server serialises it itself and writes the row with `isserialized='1'`; when a
value arrives as a scalar - which is what an ordinary form submission of a single value produces, and what a
hand-crafted POST produces trivially - the value is written verbatim with `isserialized='0'`, subject only to
the field's required and scalar-shape checks. On the read side, the staff ticket advanced-search consumer for
that field type (`__swift/apps/base/library/CustomField/class.SWIFT_CustomFieldSearch.php:151-162`) selects
every stored value for the field with a query that applies no `isserialized` filter at all, and feeds each raw
value into `mb_unserialize()` (`__swift/includes/functions.php:194-204`). That helper's only gate is
`is_serialized()` (`__swift/includes/functions.php:226-253`), whose implementation accepts the `O:` object
token explicitly, and the `unserialize()` call it wraps is made without an `allowed_classes` restriction. A
serialised object graph stored in a ticket's linked-select field is therefore instantiated inside the staff
request that searches for it.

Three libraries bundled in the application's vendor pool supply the gadget chain. PHPExcel's
`PHPExcel_CachedObjectStorage_SQLite3::__destruct`
(`vendor/phpoffice/phpexcel/Classes/PHPExcel/CachedObjectStorage/SQLite3.php:322-330`) builds a SQL string by
concatenating a property into it and hands that string to a `DBHandle` object; Dwoo's `Dwoo\Core::__call`
(`vendor/dwoo/dwoo/lib/Dwoo/Core.php:1771-1778`) proxies any missing method to a plugin-proxy object and
invokes it through `call_user_func_array`; Zend's `Zend\Validator\Callback::getCallback`
(`vendor/kayako-zend/zend-validator-kayako/src/Callback.php:62-65`) returns a callback taken from a plain
option array. Serialised as a single object graph, the three compose into
`system('DROP TABLE kvp_x; <command>')`. The shell splits that line at the semicolon, the fixed `DROP` word
fails as an unknown command, and the attacker's command runs with the identity of the Apache worker process,
www-data.

Neither side of the chain needs an account the attacker owns. The write side is the product's own anonymous
ticket submission, which is open by default: the client interface issues a guest session to any visitor and
accepts a ticket from it, and the only shipped obstacle is `t_ccaptcha=1`, an anti-automation text challenge
rather than an authentication credential, which a deployment may legitimately disable and which the
verification environments disabled through the product's own administrative interface. The trigger side is a
staff member's ordinary ticket search or saved filter over that field. The attacker plants the serialised
graph and waits; the staff member's routine action completes the chain. This is a stored, second-order
object-injection finding, and no CVE identifier has been assigned to it: the public record for the 4.98 line
contains no unserialize, object-injection or command-execution entry.

Verification was performed end to end against two isolated Docker reconstructions of the product, not against a
vendor-operated deployment. Each reconstruction ran the same third-party components as a real installation
(php:7.4-apache, that is PHP 7.4.33 with Apache/2.4.54 on Debian, plus MariaDB 10.11), installed the product
through its own anonymous setup wizard, created a linked-select field through the product's administrative
interface, submitted the serialised value from an unauthenticated guest session, and triggered a staff search.
Both environments produced the command marker from the target webroot, owned by www-data, with the content
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`; each environment's same-chain control run, whose only
difference is the absence of the semicolon command segment, created no marker. A root identity (`uid=0(root)`) appeared only
in a command-line self-test inside the disposable container, where a CLI process runs as root by design;
that observation belongs to the container's CLI layer and is not the web-layer identity of this chain, and no
root result is claimed for the HTTP path.

- Component: the custom-field search consumer for linked-select fields, `SWIFT_CustomFieldSearch`, reached from
  the staff ticket advanced search (`__swift/apps/base/library/CustomField/class.SWIFT_CustomFieldSearch.php:151-162`)
  in Kayako Classic 4.98.9 STABLE Build 10335
- Sink: `mb_unserialize($_serializedData)` at `class.SWIFT_CustomFieldSearch.php:162`, whose shared helper
  `__swift/includes/functions.php:194-204` calls `unserialize()` with no `allowed_classes` argument
- Source: the scalar `swcustomfieldvalues.fieldvalue` value written by the anonymous ticket submission at
  `__apps/tickets/client/class.Controller_Submit.php:616`, stored with `isserialized='0'`
- Sanitization: none on this path. `Check()` at line 196 of the custom-field manager's update path validates
  scalar shape and required-ness for the select family, not content; the consumer's query has no
  `isserialized` filter, and `is_serialized()` accepts the `O:` token by design, so the object graph reaches
  `unserialize()` intact

## CVSS Score

- Score: 7.5 High (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H`) - an unauthenticated network party stores
  a PHP object graph through the public ticket form, and a staff search turns it into command execution as the
  web-server identity
- Attack Vector: Network - the write side is the ticket submission interface, which is reachable by any party
  who can reach the helpdesk; the trigger travels over the staff interface but is performed by the staff
  member, not by the attacker
- Attack Complexity: High - success depends on conditions outside the attacker's control: a linked-select
  custom field must exist, the deployment must run the PHP 7.4 track, and a staff member must run a search or
  saved filter that evaluates that field. No race, no memory groom and no timing window is involved, but the
  dependency on deployment shape and on a second party's action is what separates this from a
  single-request exploit
- Privileges Required: None - the attacker presents no credential on either side of the chain; the write side
  is anonymous by default and the trigger is executed by a different principal
- User Interaction: Required - the chain fires during a staff member's ordinary search or saved-filter
  submission; the payload stays dormant until that action occurs
- Scope: Unchanged - the command executes inside the helpdesk host, within the authority of the PHP process
  that was abused; no crossing into a separate security authority is claimed
- Impact C/I/A: all High - arbitrary command execution as www-data yields the helpdesk's stored support data,
  its application files and the trust of every session the application issues, plus full control of service
  availability on that host
- CWE: CWE-502 primary (deserialization of untrusted data, PHP object injection); CWE-78 secondary (the
  terminal `system()` command construction that the gadget chain reaches)
- Published arithmetic: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.44 x 0.85 x 0.62 = 1.620146; sum 7.493265, rounded up to 7.5

Vector and score as published: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` = 7.5 (High).

Privileges Required is None rather than the neighbouring Low tier because the metric scores the privileges the
attacker must already hold, not the privileges of the party whose action completes the chain. The attacker here
holds none: the ticket form is the product's public, credential-free input surface, and the staff session that
performs the search belongs to a different principal whose credential is never obtained, reused or replayed.
Reading the staff session as "the attacker's privilege" would misplace the principal, and it would also make
the score depend on which staff member happened to search rather than on what the attacker is able to do.

Rejected reading A - scoring the staff search as the attacker's privilege:
`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H` = 7.1 Medium. This reading is arithmetically coherent but
principal-confused: it charges the attacker for a credential the chain never uses, and it understates the
finding for every deployment whose ticket intake is public.
Exploitability becomes 8.22 x 0.85 x 0.44 x 0.62 x 0.62 = 1.181753, and 5.873119 + 1.181753 = 7.054872,
rounded up to 7.1.

Rejected reading B - treating the trigger as attacker-controlled in time:
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` = 8.8 High. Rejected because the attacker cannot schedule the
search, cannot supply the linked-select field, and cannot guarantee the PHP track; those dependencies are
exactly what Attack Complexity High records. It is quoted here so that no downstream channel upgrades the
published 7.5 to 8.8 by dropping the complexity metric.
Exploitability becomes 8.22 x 0.85 x 0.77 x 0.85 x 0.62 = 2.835255, and 5.873119 + 2.835255 = 8.708373,
rounded up to 8.8.

## Affected Products

- Kayako Classic 4.98.9 STABLE Build 10335 (the Fusion-generation helpdesk), analyzed end to end at source
  level from the `fusion_stable_sourceobf_4_98_9_10335_df7ca14.tar.gz` distribution; affected component: the
  linked-select branch of the staff custom-field search consumer and the `mb_unserialize()` helper it calls
- Deployment preconditions observed in the record: the PHP 7.4 runtime track (PHP 8.1.34 aborts on the first
  request with `Cannot use "parent" when current class scope has no parent in
  __swift/library/class.SWIFT.php:16`), at least one custom field of type linked select, guest ticket
  submission left at its shipped default, and staff accounts permitted to search tickets
- Not claimed: earlier 4.9x or 4.7x releases were not audited, other builds of the 4.98 line were not
  compared, and no claim is made that every installation exposes the required field type. A distribution of
  the sibling GFI HelpDesk product built on an earlier 4.93.20 source archive was inspected and could not be
  assessed: that package lacks the application body under `__swift/apps`, and its vendor pool contains neither
  phpoffice, nor dwoo, nor kayako-zend, so neither the sink nor the gadget chain exists there in verifiable
  form. No affected-product claim is made for it
- Verification method and its boundary: two isolated Docker reconstructions of the product (`php:7.4-apache`
  with PHP 7.4.33 and Apache/2.4.54, MariaDB 10.11, product installed through its own setup wizard, 230 tables
  created, a linked-select field created through the administrative interface). The full chain - anonymous
  guest write, staff search, marker retrieval - was driven over HTTP in both. The first reconstruction bound
  the target to `127.0.0.1:8115` and the second to `127.0.0.1:8116`; no vendor-operated or internet-facing
  deployment was touched, and no customer data was involved
- Privilege ceiling: the observed end-to-end identity is the Apache worker identity, www-data
  (`uid=33(www-data) gid=33(www-data) groups=33(www-data)` in the served marker). Not claimed: any root
  execution over HTTP, any escape from the webroot, any persistence mechanism, and any destructive effect -
  the recorded commands wrote marker files and read the executing identity only. The `uid=0(root)` observation
  in the record came from a CLI-layer self-test inside the disposable container and is labeled as such wherever
  it appears

## Impact

- Persistent, attacker-controlled PHP objects inside the helpdesk's own database, planted by a party who never
  authenticates: the serialised value is a ticket custom-field value, so it survives in the normal ticket
  record, appears in the staff ticket view, and requires no separate upload channel or filesystem write from
  the attacker
- Command execution as www-data on the helpdesk host when any staff member searches or saves a filter over
  that field, which is routine support work rather than an unusual action; the attacker needs no social
  engineering beyond the ticket that carries the payload
- Exposure of the support data the application is trusted with, within the file and database permissions of
  the web-server process: ticket bodies, customer contact records and uploaded attachments are exactly the
  material that identity was already allowed to read
- Integrity exposure of the application itself: the marker in the recorded runs was written into the target
  webroot, which demonstrates that the same authority can modify served application files and therefore
  persist by editing code rather than by any exotic mechanism
- Control of every session and account the application issues: an attacker with code execution in the PHP
  process can act with the application's own authority towards its users, including staff who hold broader
  helpdesk rights than the searching user
- Availability impact at will on the helpdesk host, from terminating the web process to corrupting the
  application's files or data
- The trigger is ordinary product behaviour, so the finding is quiet: a ticket submission followed later by a
  staff search produces no anomalous protocol pattern, no malformed request and no error page on the success
  path
- A stored payload remains retrievable by the consumer: the query selects every stored value for the field and
  iterates them, so the value does not have to be re-submitted for a later search to reach it. Whether a
  second search re-executed an earlier payload was not separately measured, because the second recorded run's
  marker check read an artifact the first run had already created

## Mitigation / Fix Recommendations

1. Filter at the consumer: add `AND customfieldvalues.isserialized = '1'` to the query at
   `class.SWIFT_CustomFieldSearch.php:151-162` and validate that the value is a numeric option identifier
   (`ctype_digit`) before any use, matching the gate the other read points in the product already apply. The
   linked-select branch is the only read point of its family that omits that filter
2. Remove object injection at its root: change `mb_unserialize()` (`__swift/includes/functions.php:194-204`) to
   `unserialize($string, ['allowed_classes' => false])`, and audit every other `unserialize()` call site in the
   application for the same argument. Object graphs must never be reconstructed from stored user input
3. Validate on the write side as well: for the select family, reject scalar submissions outright, require the
   submitted value to identify one of the field's configured options, and refuse values whose first bytes are
   an `O:` or `a:` serialisation header. Server-side serialisation of arrays is acceptable only because the
   server, not the submitter, builds the envelope
4. Reduce gadget depth: stop bundling PHPExcel's `CachedObjectStorage` classes, or at minimum ensure the
   destructor does not build SQL by string concatenation into a property; constrain Dwoo's plugin-proxy
   callback to a fixed allowlist of callables so that a serialised property cannot name `system` or any other
   process-execution function
5. Restrict process authority: run the helpdesk under a PHP-FPM or Apache identity that cannot write to the
   served application tree, and keep the application root read-only to the web user except for the specific
   upload directories. The recorded run wrote its marker into the webroot, which is the capability this change
   removes
6. Add a regression test at the consumer level: store `O:8:"stdClass":0:{}` as a linked-select field value,
   run a staff search over the field, and assert that no object is instantiated and that the raw value is
   rejected before `unserialize()` is reached. Run the same test for every custom-field type that stores
   serialised payloads
7. Interim operator measures: require registration or close anonymous ticket submission where support
   workflows allow it, and treat the text CAPTCHA as the anti-automation measure it is rather than as an input
   filter. Neither measure fixes the chain, which only needs one accepted ticket; both reduce the population
   that can plant it

## References

- https://0day-rubbish.com/blog/selectlinked-unserialize-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- https://cwe.mitre.org/data/definitions/502.html
- https://www.php.net/manual/en/function.unserialize.php
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
