# Abyss Web Server X1 2.16.22.0 - Missing Authentication for Console Credential Creation Reaching a Configuration-Write to Log-as-CGI Command Execution Chain (CWE-306, CWE-78)

Advisory: https://0day-rubbish.com/blog/aprelium-abyss-web-server-firstrun-console-takeover-conf-to-cgi-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Abyss Web Server X1 2.16.22.0 from Aprelium (Tunisia) leaves its HTML administration console
unarmed on first start: the generated `abyss.conf` carries a `<console>` node with no `<login>` and no
`<password>` element, and while that state holds any client whose source address passes the console's
`ipcontrol` rule receives `GET /console/credentials` as a `200` credential-creation form and can register
the administrator account with a credential-free `POST`, after which the same endpoint answers `401` and the
window is closed for everybody. The seized console's forms are a direct serialisation of the configuration
tree - each HTML control's `NAME` is the XML key path it writes - so three supported forms then convert the
configuration plane into an execution plane: a CGI script-path scope of `vpath=/`, a host access log
redirected to an arbitrary absolute path inside the document root, and an interpreter binding of extension
`log` to the executable `/bin/sh`. After `POST /` with `/restart=Restart` applies the change, the access log
*is* a shell script inside CGI scope; a request whose `User-Agent` is `zz"; <command>; #` smuggles a command
into it through the combined log format's double-quoted field (quote-context escape, semicolon statement
separator, trailing comment), and an anonymous `GET /x.log` makes the product start `/bin/sh x.log` as a CGI
child. Three independent detonations against a live instance produced a marker containing
`uid=uid=0(root) gid=0(root) groups=0(root)`; root was reached because the verified instance was started
with the product's `--allow-root` flag, and the shipped default runtime identity is deployment-dependent
rather than proven. There is no memory corruption, no deserialisation gadget and no file-upload primitive in
this chain: the write primitive is the product's own configuration form, and the interpreter mapping is what
turns an ordinary access log into an executable path.

- **Component**: the HTML administration console on default port 9999 (`bindip` `*`, HTTP Basic, no session
  cookie) plus the host service listener on default port 80, in the Linux release tree `abwsx1.tgz` -
  `abyssws-x64` (ELF64 stripped, 5700872 bytes, BuildID `d7545bad2f47fb7b9f269ae98cb7baea1594fa12`) and
  `abyssws-x86` (ELF32 i386 stripped, 6174164 bytes, BuildID `81b83c50c27df109282654730c52539a7db37cc2`);
  zero `.c` sources in the tree, OpenSSL 3.x, nghttp2, PCRE2 and zlib statically embedded, console HTML
  generated from templates compiled into the binary and `console.js` shipped as a zero-byte placeholder
- **Sink**: the CGI child `/bin/sh <log file>` started by the product's own scripting engine for a path whose
  extension is bound to an interpreter; the server's `cgi.log` names it directly as
  `CGI: [/bin/sh x.log ]  URI: /x.log` alongside the shell's own `x.log: line N: 127.0.0.1: command not found`
  diagnostics
- **Source**: the `User-Agent` request header on an ordinary anonymous `GET` to the host listener, written
  verbatim into a `.combined` access-log line inside a double-quoted field; and, upstream of it, the
  unauthenticated `POST /console/credentials` request that creates the administrator whose console forms
  write `abyss.conf`
- **Sanitization**: none on the path. The log writer performs no quote or shell-metacharacter escaping; the
  interpreter form applies no content-type or shell-interpreter restriction; the log form applies no path
  whitelist or canonicalisation; the script-path form accepts a scope of `/` without acknowledgement; and the
  `antihack` protection system that could have filtered the request defaults to `enabled no`

## CVSS Score

- **Score**: 7.5 High (`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) - an unauthenticated client on the
  same private network as the server can take over a freshly deployed instance and reach arbitrary command
  execution as the server process identity, but only inside the first-run window and only from an address
  the shipped console filter admits
- **Attack Vector: Adjacent** - the console binds every interface by default, but its `ipcontrol` block
  permits loopback, all three RFC1918 IPv4 ranges (`10.0.0.1-10.255.255.254`,
  `172.16.0.1-172.31.255.254`, `192.168.0.1-192.168.255.254`) and IPv6 unique-local/link-local, with no deny
  entries, and refuses public-internet sources; the check is evaluated on the connected socket peer and was
  measured not to be influenced by `X-Forwarded-For`/`X-Real-IP`. A default installation is therefore not
  internet-reachable, and `AV:N` appears only in the labelled conditional readings below
- **Attack Complexity: High** - success requires arriving before the administrator arms the console; the
  endpoint answers `401` from the moment a credential exists, which was measured in every verification round.
  The window's field duration is not established and is not estimated here
- **Privileges Required: None** - the chain head creates the credential rather than consuming one; the
  administrator used by the later forms is the one the unauthenticated request just minted, so no credential
  owned by anybody else is involved
- **User Interaction: None** - no administrator action, no browser session and no induced click is required
- **Impact C/I/A: all High** - arbitrary command execution as the server process identity yields every served
  document and TLS private key, the complete configuration tree and served content, and full control of
  service availability; the rating does not depend on whether that identity is root or a dedicated account
- **Scope**: Unchanged. The console and the host listener are one product and one process family, applying
  configuration to the serving plane is the product's documented intended behaviour, and the CGI child runs
  as the server process's own identity on the same host; Changed was considered and rejected (its variant
  `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` computes to 8.4 and is not published as the finding's score)
- **CWE**: CWE-306 primary; CWE-78 co-equal; CWE-284, CWE-73, CWE-362, CWE-352, CWE-328 and CWE-250
  contributing and reported separately without raising any metric above
- **Recorded score**: the sources behind this advisory carried no computed CVSS figure, so nothing was
  inherited or corrected; both published and conditional numbers were computed from their vectors with the
  CVSS 3.1 formula, ISS 0.914816, Impact(S:U) 5.873119, Exploitability 1.620146, base 7.493264, rounded up
  to 7.5
- **Conditional reading A - window left open indefinitely**: `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  = 8.8 High. Applies where automation installs and never arms the console, where appliances are staged
  before deployment, or where containers or host images regenerate a pristine configuration on every restart,
  so the attacker polls an unauthenticated state rather than racing a person. Labelled conditional; it is not
  the headline score
- **Conditional reading B - console also exposed to a network**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical,
  and with the window contested `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.1 High.
  Applies where an operator publishes port 9999 through NAT or a port forward, binds it on a publicly
  addressed host, or relays through a same-host reverse proxy whose forwarded traffic presents a permitted
  socket peer. Labelled conditional on a deployment change we did not test

## Affected Products

- Abyss Web Server X1 version 2.16.22.0 from Aprelium (Tunisia), a closed-source commercial
  web-server vendor whose Abyss family has shipped for more than twenty years; X1 is the free edition, X2 the
  paid edition. The product self-reports as `Abyss Web Server X1 (v 2.16.22.0)` and sends the banner
  `Abyss/2.16.22.0-X1-Linux AbyssLib/2.16.22.0`; the artefacts identify 2.16.22.0 as the vendor's current
  official release
- Affected component: the HTML administration console (default port 9999), its configuration-write forms for
  the CGI script-path scope, host access log and interpreter bindings, the `/restart` control, and the host
  service listener (default port 80) that executes the resulting CGI mapping
- Distribution artefacts: the official Linux release tree `abwsx1.tgz` (about 12 MB), containing both native
  images, with the same version distributed for Windows as `abwsx1.exe`
- Runtime stack: hand-written C HTTP stack (HTTP/1.x parsing, chunked transfer, Range and multipart ranges,
  `Expect`), statically embedded OpenSSL 3.x, nghttp2 for HTTP/2, PCRE2 and zlib; CGI, FastCGI, ISAPI and SSI
  scripting built in; three-tier process model of CLI master, `--slave --interactive` service process and
  platform daemon; XML configuration whose node names are also the console form key paths
- Only this version was tested. The Linux x64 image was executed; the x86 image in the same tree shares the
  release artefacts, the configuration model and the console templates and is characterised from them rather
  than from a detonation. The Windows build of the same version, the paid X2 edition and earlier 2.x versions
  were not tested and are not claimed as affected
- Verification method and its boundary: live-instance black-box and configuration-level verification against
  a running server built from the official release tree, inside a network namespace whose only interface was
  loopback - not an emulation, not a protocol replica and not a reimplementation. Because both images are
  stripped and the tree contains no sources, interface semantics were recovered behaviourally: fetching each
  console page and reading the emitted `FORM` control names (which are configuration key paths), indexing the
  shipped `lang/*.lng` UI semantic tables and a 47324-line string dump of the x64 image, then submitting each
  form and reading back the resulting configuration file. No disassembly-level symbol evidence is cited, and
  none is needed for the claims made. **No step of the chain was driven from a separate network host**: the
  server and the client shared one host and one loopback-only namespace, so the adjacent-network reach is
  argued from the shipped `bindip` `*` default and the `ipcontrol` allow ranges rather than demonstrated
  between two machines
- Privilege ceiling: arbitrary command execution as the identity of the server process, confirmed by a marker
  file containing `uid=uid=0(root) gid=0(root) groups=0(root)`. Root was reached because the verified
  instance was started with the product's `--allow-root` CLI flag. Root execution is **not** established as
  the shipped default on Linux: our notes describe a dedicated low-privilege `abyss` account as the intended
  production identity, and no shipped artefact we examined (install script, init unit, or a user-setting node
  in the generated default configuration) proves it, while the default host port 80 binding means the process
  must nevertheless start with root privileges or a bind capability. The privilege ceiling is therefore
  deployment-dependent. **Not reached and not claimed**: no privilege escalation from a service account to
  root, no cross-host movement, no container or sandbox escape, and no memory-corruption primitive

## Impact

- Full administrative takeover of the server by an unauthenticated client on the same private network, with a
  minted console credential that is structurally indistinguishable from the legitimate one - the same `root/console/login`
  node and the same MD5 digest storage - so the intended administrator is locked out with a `401` and no
  alert distinguishes what happened
- Arbitrary operating-system command execution as the server process identity through the product's own CGI
  mechanism, with no payload upload required: the access log is the payload carrier and it re-executes on
  every request to the log path until the log is rotated or truncated
- Read access to everything the server identity can read - all served content, TLS private keys reachable
  through the console's certificate management, and the host filesystem to that identity's limits; root
  identity means the entire host
- Complete control of the configuration tree of every virtual host: scripting and interpreter bindings,
  logging, TLS material, access control, proxying, and the console's own listener settings including the
  ability to widen `ipcontrol` or rebind the console port, which removes the defender's ability to re-narrow
  the surface remotely
- Persistence available in at least four independent ways: the minted console credential survives restarts;
  the interpreter binding and CGI scope survive restarts and are invisible to a casual audit; the smuggled
  command stays in the log file and fires on every request to that path; and the executed command can install
  an operating-system level startup mechanism with no further product interaction
- Availability impact at will - hosts can be stopped, the service restarted repeatedly, and the arbitrary-path
  log write alone permits filling a filesystem as a standalone primitive, independent of the execution chain
- The window is re-enterable rather than one-per-machine: the product's own documented recovery for a
  forgotten console password (stop the service and remove the credential nodes) reopens it, and so does any
  redeployment that regenerates the configuration
- Detection is weak by construction: every request in the chain is legitimate documented product usage -
  a setup form, ordinary authenticated configuration submissions, the product's own restart button, a `404`
  with an unusual `User-Agent`, and an anonymous `500` on a document-root file. The best indicators are
  `cgi.log` lines naming a shell invoked on a data file, `500` responses for `.log`/`.txt`/`.bak` paths, and
  configuration drift (a `<vpath>` of `/`, an interpreter pointing at `/bin/sh`, a log destination inside the
  document root)
- Amplifiers reported separately and not folded into the score: the console's default `ipcontrol` admits the
  entire private address space with the shipped documentation recommending an all-interface bind (CWE-284);
  configuration writes carry no CSRF token and the console has no session cookie (CWE-352); passwords are
  stored as MD5 (CWE-328); console Basic authentication showed no rate limiting, with `antihack` defaulting to
  off; the log form permits an arbitrary absolute destination and its file browser enumerates directories from
  the filesystem root (CWE-73); and no privilege separation is enforced

## Mitigation

1. **Refuse the colliding pair, at configuration-commit time** - reject any interpreter mapping whose
   extension or target coincides with a host log destination or with any server-written file, cross-checking
   every `<interpreters><interpreter><ext>` value against every `<log><file>` extension before the write is
   committed. This single check removes the mechanism that turns the log into an executable path
2. **Refuse to bind a general-purpose shell as an interpreter for a data extension** - `/bin/sh`,
   `/bin/bash`, `/bin/dash`, `cmd.exe`, `powershell` and equivalents should require an explicit, separately
   confirmed override, since a data extension bound to a shell has no legitimate purpose in a web server's own
   configuration
3. **Do not let a console form write an arbitrary vpath-to-interpreter pair in one action** - validate the
   scripting subtree as a unit, and require explicit acknowledgement for a CGI script-path scope of `/`, which
   is scope-wide by construction and should not be the value an ordinary form silently accepts
4. **Constrain the log destination and the file browser** - canonicalise console-supplied paths, resolve them
   against the server's own root, and reject destinations inside the document root, inside any CGI script path
   or outside an allowed log directory; restrict the console browser to the same allowed subtrees instead of
   enumerating from the filesystem root
5. **Make console credential creation unreachable from the network** - generate the initial credential locally
   at first start (a random password written into the configuration with root-only permissions and printed to
   the startup terminal, or a forced local/installer-bound setup) so the credential exists before the console
   listener can serve a creation form; if a network-visible creation step is retained, bind it to loopback or
   require a one-time setup token read from the local filesystem. The current startup message advertising
   `http://127.0.0.1:9999` to the operator is, on an all-interface bind, an invitation to any client that can
   see the port
6. **Narrow the console's default exposure** - bind to `127.0.0.1` by default, treat non-loopback binding as
   an explicit opt-in with a warning, replace the hardcoded RFC1918-wide and IPv6 ULA/link-local allow ranges
   with loopback-only plus per-range operator opt-in, and withdraw the documentation's "recommended" framing of
   an all-interface console bind
7. **Enforce privilege separation** - run the request-serving worker under a dedicated unprivileged account
   regardless of how the process was started, reserving root for the low-port bind or using
   `CAP_NET_BIND_SERVICE`, document the runtime identity so operators can audit it, and make `--allow-root`
   warn on use
8. **Add a regression test** - commit a configuration with a `log`-extension log destination inside the
   document root, an interpreter binding `ext=log` to `/bin/sh` and a `<vpath>` of `/`, and assert the commit
   is rejected naming the collision; separately assert that requesting such a log path returns its content as
   `200` `text/plain` rather than `500` with a `CGI: [/bin/sh ...]` entry in `cgi.log`; and assert from a
   first-run configuration that the credential already exists before the console listener accepts its first
   connection
9. **Modernise credential handling as defence in depth** - replace MD5 retention with a memory-hard or
   bcrypt-class digest, add rate limiting and lockout on console Basic authentication, and add a same-site
   CSRF token to every mutating console form
10. **Operator measures until a patch exists** - arm the console in the same automation step that installs the
    server and never redeploy from a pristine configuration without arming it; bind or firewall port 9999 to
    loopback or named management addresses and never publish it through NAT or a same-host reverse proxy
    without authentication in front; audit for the three collision signals (`<log><file>` inside the document
    root, an interpreter `<file>` that is a shell, a `<vpath>` of `/`); watch `cgi.log` for shells invoked on
    data files; run the server unprivileged without `--allow-root`; and re-arm from the local filesystem any
    deployment whose arming history is unknown, since a minted credential cannot be told apart from a
    legitimate one

## References

- https://0day-rubbish.com/blog/aprelium-abyss-web-server-firstrun-console-takeover-conf-to-cgi-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
