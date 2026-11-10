# Cambium E410 / E510 / E600 / E700 4.2.3.3-r9 - upload.sh URL-Query Path Traversal to Root Command Execution Through the Unauthenticated CGI Trigger

Advisory: https://0day-rubbish.com/blog/uploadsh-path-traversal-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Cambium Networks' E410, E510, E600 and E700 are Wi-Fi access points. Firmware 4.2.3.3-r9 is the build
analyzed here: the root filesystem is ARM 32-bit EABI5 with glibc 2.25 on Linux 4.4.60, extracted from the
signed vendor image `E410_E430_E510_E600_E700-4.2.3.3-r9.img`. The management plane is lighttpd 1.4.67 bound to TCP port 80
and started from the init table as `/usr/sbin/lighttpd -D` without any privilege drop. Three configuration
facts fix the security posture of that plane before any script runs. `etc/lighttpd/lighttpd.conf:103` leaves
`server.username` and `server.groupname` commented out, so the web server and every CGI or FastCGI child it
spawns inherit root. `etc/lighttpd/modules.conf:52` leaves `mod_auth` and `mod_authn_file` commented out, so
there is no authentication layer in the web server itself; whatever authentication exists is implemented
inside the individual handlers. And `server.chroot` is commented out, so the paths the handlers manipulate
are the appliance's real paths.

The icon-upload handler `var/www/cgi-bin/upload.sh` ends in a single `dd` invocation at
`var/www/cgi-bin/upload.sh:59` that splices the raw URL query string into an output path, unquoted and
unvalidated. A search of the script for `QUERY_STRING` returns that one line and nothing else, so no
fragment of the value is screened anywhere between the request line and the filesystem call. The write
target is `/tmp/icons/`, a tmpfs directory created at boot by `etc/init.d/S06PasspointIconsExtract:6` in
mode 1777. Because `$QUERY_STRING` is pasted into `of=` with no quoting, a value containing `../` sequences
resolves out of that directory, and the destination becomes any path the root-owned web server can write.
The most valuable destination on this appliance is the next script in the chain,
`var/www/cgi-bin/upgrade.sh`, which the same web server will later execute.

That execution is not a memory-safety event. `etc/lighttpd/cgi.conf` maps `/cgi-bin/upload.sh`,
`/cgi-bin/upgrade.sh`, `/cgi-bin/getfw.sh` and `/cgi-bin/apupload.sh` all to the interpreter `/bin/sh` in
its `cgi.assign` table. A `cgi.assign` entry names an interpreter to run with the script path as an
argument, not a binary to execute directly, so the mapped script needs no execute bit at all - and indeed
`upgrade.sh` ships as mode 644 - and the bytes the file contains are interpreted by busybox ash. Once the
traversal write has replaced that file with attacker-supplied text, an ordinary `GET
/cgi-bin/upgrade.sh` runs that text under `/bin/sh` as root, with no session, no token and no interaction.
This is the second half of the chain: the path traversal of CWE-22 delivers the payload, and the CGI
interpreter dispatch of CWE-78 executes it.

The upload step is not unauthenticated, and this advisory does not claim that it is. Before reaching the
`dd` sink, `var/www/cgi-bin/upload.sh:31` applies three checks to the concatenation of the `api_token`
cookie and the `X-XSRF-TOKEN` header: the combined string must match the character class `[a-z0-9]*$`, it
must be exactly 162 characters long, and a server-side `grep` against `/tmp/fcgi_cookies` must find it,
where that file is written only by a successful administrator login through the FastCGI backends `/api`
(scmd) or `/v1` (autopilot). The gate is sound - the character class admits no regex or glob
metacharacter, the length is pinned, and the server-side list cannot be satisfied by a client - so the
plant step requires a genuine administrator session on the management UI. The authentication class of this
finding is therefore Authenticated. The trigger step that follows requires nothing at all.

Verification was sink-level replication on an isolated sandbox, not a live appliance. The genuine
`upload.sh` and `upgrade.sh` extracted from the vendor image were executed under a standard-library CGI
shim that reproduces lighttpd's `cgi.assign` dispatch model, with the shim bound to loopback only,
and the shim's environment variables were set exactly as lighttpd would set them. The recorded run shows
the plant step returning HTTP 200 with the body `Icon imported`, which is the handler's own success string
and therefore evidence that the three-part gate passed and the `dd` write traversed; the trigger step then
returned HTTP 200 with a response body containing `uid=0(root) gid=0(root) groups=0(root)` and
`CapEff: 000001ffffffffff` between two markers. Root was observed inside that replication environment. On
a real device the same identity is fixed by the firmware artifact rather than by measurement: the
commented-out `server.username` directive is what makes the CGI child root, and the replication mirrored
that configuration deliberately. No physical E410, E510, E600 or E700 was driven during this research.

This is not a default-credential finding and it is unaffected by any administrator password change. The
factory configuration at `etc/default-config.txt:1` records the pair `admin` / `admin`, which is a distinct
exposure classified as CWE-798; it is excluded from this chain, no step of the exploit consumes it, and the
PoC shipped here does not guess, brute-force or collect any credential. There is no memory corruption, no
integer overflow and no transport-layer defect anywhere in this chain. The entire defect is that a value
the browser controls is pasted into a path without a quote and without a `..` check, and that the
resulting file is later interpreted by a root shell. No public identifier has been assigned for this
finding.

- Component: the icon-upload CGI `var/www/cgi-bin/upload.sh` of the lighttpd 1.4.67 management plane on
  firmware 4.2.3.3-r9, reached as `POST /cgi-bin/upload.sh` with a traversal payload in the query string;
  the overwrite destination is the sibling CGI `var/www/cgi-bin/upgrade.sh`
- Sink: `dd ibs=1 obs=512 count=$SIZE of=/tmp/icons/$QUERY_STRING` at `var/www/cgi-bin/upload.sh:59`,
  where `$QUERY_STRING` is the raw, unvalidated, unquoted URL query string, giving an arbitrary-path write
  under the root identity of the web server
- Source: the HTTP request target's query string, plus the request body, which supplies the bytes that `dd`
  copies from standard input into the traversed destination
- Execution primitive: `cgi.assign` in `etc/lighttpd/cgi.conf` maps `/cgi-bin/upgrade.sh` to `/bin/sh`, so
  the overwritten file is interpreted by busybox ash on the next request to that path, as root, without
  authentication
- Sanitization: none on the sink. The only control on the path is the three-part token gate at
  `var/www/cgi-bin/upload.sh:31`, which protects who can upload, not what path the upload lands on
- Boundary: root was observed in a sink-level replication on an isolated sandbox; the device-side identity
  is read from the firmware's lighttpd configuration
- CWE: CWE-22 primary, the path traversal at the sink, chained to CWE-78, the interpreter dispatch that turns
  the overwritten CGI into executed code

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- Attack Vector: Network - the management plane answers on TCP port 80 and the entire chain is carried in
  ordinary HTTP requests, with no adjacency, no man-in-the-middle position and no local access assumed
- Attack Complexity: Low - one authenticated POST plants the file and one unauthenticated GET executes it;
  there is no race, no heap groom, no timing window and no state machine beyond those two requests
- Privileges Required: High - the plant step is gated behind an administrator session on the management UI,
  verified by character class, by length and by a server-side token list that only an administrator login
  populates
- User Interaction: None - the administrator who drives the plant is the attacker; the trigger request needs
  no victim
- Scope: Unchanged - the executed payload runs inside the appliance, within the authority of the web
  component whose interface was abused; no crossing into a beyond-device security authority is claimed
- Impact C/I/A: all High - command execution as root yields the full configuration store, the ability to
  rewrite the device's behaviour, control of the wireless and network data plane, and total control of
  service availability
- Arithmetic: ISS = 1 - (1 - 0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum = 7.107827, rounded up to 7.2

Privileges Required is High rather than the neighbouring tier because the gate at
`var/www/cgi-bin/upload.sh:31` is not a formality. The three checks are independent: the character class
`[a-z0-9]*$` rejects every metacharacter, the length check pins the combined value at exactly 162
characters, and the `grep` against `/tmp/fcgi_cookies` consults state the device itself wrote after a
successful login through `/api` or `/v1`. Nothing on the management surface offers a lower-privilege
account that can reach this handler, so the only principal that can drive the plant is the device
administrator, and the Low-privilege weight does not describe it.

A rejected reading, printed here so that it is not mistaken for the published rating, is the
Low-privilege form of the same impact profile: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High.
Its arithmetic is the same Impact term, 5.873119, with Exploitability = 8.22 x 0.85 x 0.77 x 0.62 x 0.85 =
2.835255, summing to 8.708374 and rounding up to 8.8. It is rejected because no principal with Low
privileges can reach `var/www/cgi-bin/upload.sh` on this firmware; 8.8 describes a boundary the evidence
does not support.

## Affected Products

- Cambium Networks E410, E510, E600 and E700 access points running firmware 4.2.3.3-r9, the build analyzed
  end to end from the vendor image `E410_E430_E510_E600_E700-4.2.3.3-r9.img`; affected component: the
  lighttpd 1.4.67 CGI handlers `var/www/cgi-bin/upload.sh` and `var/www/cgi-bin/upgrade.sh` as shipped in
  that image
- Platform: Qualcomm Atheros Wi-Fi access point hardware, ARM 32-bit EABI5, glibc 2.25, Linux 4.4.60, with
  busybox ash as the shell that `cgi.assign` invokes for the affected CGI scripts
- Role of the product: Wi-Fi access point; the management plane is the device's administrative interface,
  and the CGI handlers under `/cgi-bin/` are the firmware's own icon-installation and firmware-upgrade
  controls
- Not claimed: access-point models outside the E410/E510/E600/E700 set, firmware versions other than
  4.2.3.3-r9, and any other Cambium product family
- Verification method and its boundary: sink-level replication on an isolated sandbox, using the genuine
  scripts taken from the firmware image under a standard-library CGI shim that reproduces lighttpd's
  `cgi.assign` dispatch; the recorded run observed `uid=0(root)` and `CapEff: 000001ffffffffff`. No
  physical access point was driven, so the device-side identity rests on the firmware's own lighttpd
  configuration (root, because `server.username` is commented out) and the on-device reachability rests on
  the shipped configuration files, while the traversal and the execution behaviour are established by the
  replication
- Privilege ceiling: arbitrary command execution as root. Not reached and not claimed: escape from the
  appliance to attached hosts, persistence across a factory reset or reflash, radio-firmware effects, and
  any memory-corruption primitive

## Impact

- Complete operating-system compromise of the access point by an administrator who was only ever meant to
  upload an icon file: the management interface becomes an arbitrary-command channel, and the attacker
  holds every capability the device itself holds
- Disclosure of every secret the appliance stores for its own operation, within the readable filesystem
  scope of the root identity, including the management credential store and any key material the firmware
  keeps on the writable partitions
- Full control of the wireless and network data plane: an attacker with root can reconfigure SSIDs, VLAN
  handling, bridging and upstream routing, which converts an access point into an interior network position
  from which client traffic can be observed or redirected
- Persistence consistent with root command execution on an embedded Linux system - startup scripts, account
  entries, scheduled jobs - up to the limits of the writable filesystem; what survives a factory reset or a
  reflash was not tested and is not claimed
- Availability impact at will, both coarse (process and service control from the shell) and surgical, since
  a root writer can also corrupt or remove the very CGI scripts that constitute the recovery path
- A repair-resistance property specific to this chain: the overwritten file is the firmware-upgrade handler,
  so an operator's normal remedy path passes through the same file the attacker now owns
- The chain is quiet in product terms: one file upload inside a legitimate icon-management action and one
  ordinary GET to a handler that is expected to be requested, with no malformed packets and no crash

## Mitigation / Fix Recommendations

1. Remove the traversal at the sink: derive the destination from a fixed table or from the basename of the
   query string after rejecting any value containing `/`, `\` or `..`, and quote the expansion. A positive
   allowlist of icon file names of the form `[A-Za-z0-9._-]+` with a length cap closes the class rather
   than filtering for the current payloads
2. Never let a client-supplied name select a path inside the CGI directory: write uploads to a dedicated
   directory that the CGI layer does not execute from, so that even a successful write cannot become code.
   Directory separation is what turns this chain from remote code execution back into a storage bug
3. Drop the web server's privilege. `etc/lighttpd/lighttpd.conf:103` should set `server.username` and
   `server.groupname` to a dedicated unprivileged identity. This does not fix the traversal, but it caps
   the blast radius of this defect and every future one in the same plane
4. Enable an authentication layer at the web server, or at minimum require it uniformly for `/cgi-bin/`.
   `etc/lighttpd/modules.conf:52` currently leaves `mod_auth` commented out, so every handler implements its
   own gate and any handler that forgets one is exposed; the overwritten `upgrade.sh` demonstrates exactly
   that failure mode
5. Stop dispatching scripts through an interpreter in `cgi.assign`. A `cgi.assign` entry of `/bin/sh` makes
   any writable script in that directory executable code; using a direct-execution mapping with an execute
   bit, or moving these handlers behind the FastCGI services that already perform authentication, removes
   the interpreter-dispatch half of the chain
6. Enforce a change of the factory credential recorded at `etc/default-config.txt:1`, and treat the
   management plane as an administrative surface: bind it to the management VLAN only, and do not expose it
   to client or uplink networks
7. Until a firmware fix exists, operators should restrict access to TCP port 80 on the management interface
   to a dedicated administrative network, and monitor for writes into `/var/www/cgi-bin/` that do not
   originate from a signed firmware update

## References

- https://0day-rubbish.com/blog/uploadsh-path-traversal-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
