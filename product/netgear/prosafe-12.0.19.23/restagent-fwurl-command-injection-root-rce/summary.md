# NETGEAR ProSafe Managed Switch 12.0.19.23 - REST agent download fwUrl OS command injection

Advisory: https://0day-rubbish.com/blog/restagent-fwurl-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The NETGEAR ProSafe managed-switch line runs its management services from an appmgr sidecar: a
lighttpd server with the mod_cgi module, serving the switch's web interface and its REST v1 API on
TCP 8443 (TLS) and 8080. Firmware 12.0.19.23 carries the REST agent CGI set under
`/usr/local/appmgr/usr/lib/cgi-bin/restagent/`, and the lighttpd configuration for that path defines
no `mod_auth` directive, so every REST call is authenticated - or refused - inside the CGI itself.
The download agent, `device.cgi` (ARMv7, stripped, md5 `35de649755e2341ea1f41f8b1fa4948c`), serves
`POST /api/v1/download` and reads a JSON document whose `device_download` object describes a firmware
or configuration download: a type, a protocol, a URL, a timeout and a reboot flag. The URL member is
named `fwUrl`.

That member is the vulnerability. The handler takes `fwUrl` out of the parsed JSON without any
content check and composes two shell command lines around it. The first probes the remote object's
size with `curl -k -sI` and pipes the response headers through `grep` and `awk`; it is executed with
`popen()`. The second performs the transfer into `/mnt/download` and is executed with `system()`. Both
constructions interpolate the URL unquoted, and nothing between the JSON parse and the shell call
inspects it for shell metacharacters. A `fwUrl` of the form `http://127.0.0.1/x;<command>;` therefore
closes the `curl` invocation at its first semicolon and leaves the remainder of the line to `/bin/sh`
as an independent command.

The command runs in the handler's forked download child, and the appmgr CGI stack executes as root on
the device - an identity the research record establishes from the ownership of `/mnt/download` and
`/tmp/restsession` and from the account under which the real CGI ran in the replication environment.
The outcome is arbitrary command execution at the highest privilege the operating system offers,
reached with one well-formed authenticated request, without memory corruption, without a race and
without a second stage.

The authentication boundary is real, and the finding is published as an authenticated issue. A client
must obtain a management session from `POST /api/v1/login` and present its token as
`Authorization: Bearer <token>`. The CGI's `fcn.0000f5a0` validates that token by opening
`/tmp/restsession/<token>` and by listing the session directory through a shell pipeline, then updates
the file's lock and timestamp. No request reaches the download handler without passing that gate, and
the record finds no unauthenticated path to a command sink. The credential is the switch
administrator's; the record documents no lower-privilege account tier that reaches this endpoint.

Verification combined static analysis with a dynamic reproduction. The static half recovered the
handler, the two format strings and the call sites from the vendor binary with r2ghidra. The dynamic
half ran that same binary - the real `device.cgi`, not a re-implementation - inside an ARM chroot
under QEMU, with the device's initramfs, its appmgr tree and its shared libraries around it, and with
the RPC client stubs neutralised at the PLT so the handler could proceed to its shell calls. The
injected command wrote a marker file and the REST call returned the ordinary success document. The
executing identity is root because the CGI and its children run as root; the `id` command included in
the test payload produced no output file because the harness's minimal userland ships no `id` binary,
so no `uid=0` string was captured and none is claimed here. No physical switch was driven: the request
path, the session gate and the field extraction rest on disassembly, while the injection itself rests
on the replication.

- Component: `restagent/device.cgi`, the REST agent download handler behind `POST /api/v1/download`
  on the appmgr lighttpd stack (TCP 8443 TLS and 8080) of ProSafe switch firmware 12.0.19.23
- Sink: `popen("curl -k -sI <fwUrl> | grep -i content-length | awk '{print $2}'")` and
  `system("curl -k -m <timeout> -o /mnt/download/<name> <fwUrl> > /dev/null 2>&1")`, each executed
  through `/bin/sh -c`, which parses the interpolated URL a second time
- Source: the `fwUrl` member of the `device_download` JSON object, read from stdin under
  `CONTENT_LENGTH` and accepted after no content validation beyond the enclosing protocol and type
  checks
- Sanitization: none on the URL text; `protocol` must be `http` or `https` for the `curl` branch to be
  taken and `signatureVerify` must be `0`, but neither constraint looks at the URL's characters
- Authentication: a valid management session from `POST /api/v1/login`; the record classifies the
  finding as an authenticated issue (Target B)
- Verification boundary: real product binary inside a QEMU ARM chroot; no physical device; root as the
  CGI's execution identity in that replication, not as a captured `uid=0` line

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an administrator who is entitled
  to use the download API converts that entitlement into arbitrary command execution as the web
  stack's identity, which this firmware runs as root
- Attack Vector: Network - the endpoint is a TCP service on the switch's management stack (8443 TLS,
  8080) and the attack is a single HTTP request over it; nothing in the request path requires local
  adjacency or physical access, and the credential requirement is expressed by PR rather than by AV
- Attack Complexity: Low - one authenticated POST carrying a crafted JSON member; no race, no timing
  window, no memory grooming, no multi-step state machine
- Privileges Required: High - the request must carry a management session token that `/api/v1/login`
  issues to the switch administrator; the record identifies no lower-privilege account class with
  access to `/api/v1/download`
- User Interaction: None - the credential holder drives the request directly; no victim action is part
  of the chain
- Scope: Unchanged - the substituted command runs on the switch, inside the authority of the component
  whose interface was abused; no crossing into a beyond-device security authority is claimed
- Impact C/I/A: all High - root command execution yields the configuration store and whatever
  credentials the device holds, permits arbitrary alteration of switch behaviour, and gives total
  control of service availability
- Arithmetic: ISS = 1 - (1 - 0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119; Exploitability =
  8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827, rounded up to 7.2

Privileges Required is High rather than the neighbouring tier because the CVSS privilege metric asks
what the attacker must already hold on the vulnerable component, not how much damage the result does.
The only principal this research observed reaching `/api/v1/download` is one holding a management
session issued to the switch administrator, and the record establishes no secondary account class
that can open a REST session at all. A Low rating would describe an account that can reach the
interface while being unable to administer the component; no such account is documented for this
firmware, so the lower tier is not available even though the resulting impact is total.

A lower-privilege reading is recorded here for completeness and rejected on that basis:
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High, with ISS 0.914816, Impact 5.873119,
Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, sum 8.708374, rounded up to 8.8. An
unauthenticated reading is rejected even more plainly:
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 High, with Exploitability 8.22 x 0.85 x 0.77 x
0.85 x 0.85 = 3.887040, sum 9.760159, rounded up to 9.8. Both readings assume a principal the firmware does not offer - a REST client without the
administrator's session, or with a lesser one - and the Bearer gate in `fcn.0000f5a0` sits in front of
route dispatch for every request, so neither describes this vulnerability.

## Affected Products

- NETGEAR ProSafe M4300 managed switch, firmware 12.0.19.23 (image `M4300_V12.0.19.23.zip`, `fit.itb`
  md5 `b5d3f4536ec9c98e1147209cd74f5b34`), the version analysed end to end at binary level here;
  affected component: `/usr/local/appmgr/usr/lib/cgi-bin/restagent/device.cgi`, the download agent of
  the REST v1 API, reached at `POST /api/v1/download` over TCP 8443 (TLS) or 8080 behind a management
  session
- The REST v1 interface as shipped on that build: lighttpd plus mod_cgi serving both the management web
  interface and the `/api/v1/` route family from the same appmgr instance, with authentication
  implemented inside the CGIs rather than by the web server
- Code-lineage note, not a second verified target: a later build of the successor M4350 line
  (V14.0.2.26, ARM aarch64, `restagent/device.cgi` digest beginning `09d1d91d`) was statically
  confirmed to carry the same header-probe format string, the same `/mnt/download` destination, the
  same `fwUrl` key and live `system`/`popen` imports; that build was not executed dynamically, so it is
  reported as a shared-construction observation rather than as an exploited product. The record also
  notes that the appmgr component is shared across the M4300/AV line and expects the same code in
  other 12.x minor versions; that expectation is not a verification result and is not claimed
- Not claimed: any model outside the analysed build; any unauthenticated path; any execution on
  physical switch hardware; any memory-corruption primitive
- Verification method and its boundary: firmware disassembly established the handler, the two command
  constructions, the call sites and the authentication function; dynamic evidence comes from running
  the real ARMv7 `device.cgi` in a QEMU chroot built from the device's own initramfs, appmgr tree and
  libraries, with the RPC client stubs neutralised so that the handler reaches its shell calls, and
  with the CGI driven through the lighttpd CGI conventions (`CONTENT_LENGTH`, `HTTP_AUTHORIZATION`,
  `REMOTE_ADDR`, body on stdin). In that environment the injected command wrote `/tmp/WIN` containing
  `PWNED`, and the REST call returned the ordinary success document (`status: success`,
  `respCode: 0`). The executing identity was root because that stack runs as root; the payload's `id`
  produced no file because the harness has no `id` binary. No physical switch was driven and no live
  request was sent to device hardware, so protocol-level reachability on a production switch rests on
  the record's device-path analysis rather than on a hardware run

## Impact

- Complete command execution as root on the switch, by a credential holder the product never intended
  to give a shell: the download interface becomes a general-purpose command channel, bounded only by
  what the device's own root account can do
- Exposure of every secret the switch holds for its own operation within readable filesystem scope at
  root, including its configuration store and any credentials the firmware persists there
- Full control of switching behaviour: VLAN and interface configuration, management-plane settings,
  authentication configuration and logging can all be rewritten from the shell, which converts a
  management-plane defect into a network-position problem for everything the switch carries
- Persistence consistent with root on an embedded Linux system - startup scripts, local accounts,
  scheduled tasks - up to the limits of the writable filesystem; survival of a factory reset or a
  firmware reflash was not tested and is not claimed
- Availability impact at will, both coarse (service control, reboot) and surgical (deleting or
  corrupting the files the download path writes under `/mnt/download`)
- A low-noise chain: one authenticated POST inside a legitimate management action, indistinguishable
  in shape from ordinary download use, with the command running in a short-lived child of the CGI
- The credential requirement is the mitigating factor and should not be read as a soft one: the
  administrator account is exactly the account an attacker reaches for, and the record notes that the
  credential could also be taken from the web interface first through phishing or credential leakage,
  after which this endpoint turns web management into a root shell

## Mitigation / Fix Recommendations

1. Remove the shell from the download path. Build both `curl` invocations as argument arrays and
   execute them with `execvp()` or `posix_spawn()`, so no shell ever parses the URL. This closes the
   class on this surface instead of chasing metacharacter sets
2. Validate `fwUrl` as a URL rather than as a string: parse it, accept only `http` and `https` schemes,
   require a syntactically valid authority, reject any control character or shell metacharacter, and
   only then use it. The record's recommended shape is a schema check on scheme and host before any
   interpolation
3. If a shell has to stay in the path short-term, single-quote the URL with literal single-quote
   escaping and assert after construction that the composed line contains no unquoted `;`, backtick,
   `$` or newline; both current constructions interpolate the value bare
4. Rewrite the session check in `fcn.0000f5a0` as well. It composes `ls | grep | awk` around the raw
   token; `readdir()`/`stat()` on `/tmp/restsession` gives the same answer without a shell, and the
   record marks that interpolation as raw
5. Drop the web stack's privilege. The CGI and its children run as root on this firmware; a dedicated
   unprivileged identity for appmgr would not fix the injection but would cap the blast radius of this
   and every other web-plane defect
6. Sweep the rest of the CGI family for the same compose-shell pattern. The record points at
   constructions such as `cat %s %s > %s` and `echo -n '%s' >> %s` in the same agent family; an
   argument-array migration is the only fix that closes them together
7. Add a handler-level regression test that submits a `fwUrl` containing `;` and asserts either
   rejection or the absence of any shell execution, and run it against every build carrying this
   agent. Until a fix ships, operators should restrict management access to the REST ports, disable
   the REST interface where it is not used, and treat administrator credentials on these switches as
   root credentials, because that is what they are

## References

- https://0day-rubbish.com/blog/restagent-fwurl-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- https://cwe.mitre.org/data/definitions/78.html
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
