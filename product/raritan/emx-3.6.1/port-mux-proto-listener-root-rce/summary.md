# Raritan EMX — Authenticated Config Injection into port_mux proto_listener → Root RCE

## Summary

Raritan EMX (firmware emx_ecx_3.6.1_46982) is a data-center PDU/rack power-management gateway (CII power infrastructure). Its `port_mux` daemon (PortMuxDaemon, inetd-style port multiplexer) runs as root and executes the `program`/`program_args` defined in the `proto_listener[<instance>]` configuration for each incoming TCP connection.

The `proto_listener` configuration is writable over HTTP via `/cgi-bin/raw_config_update.cgi` (admin-authenticated). `get_config -s` validates instance names but does **not** validate the `program` field value. An admin attacker (default `admin:raritan` credentials) uploads a config that modifies the existing `[http]` instance to `program=//bin/sh`, `program_args=[-c, <command>]`, and a new attacker-chosen port. `cfgnotifyd` notifies `port_mux` in real time (no reboot of the daemon needed); a plain TCP connection to the injected port triggers `fork + execv("//bin/sh", ["-c", "<cmd>"])` as **root**.

Verified end-to-end with real HTTP requests: root-owned marker `HTTP_RCE_OK` created by `port_mux` (pid running as root). CVSS 8.8 (authenticated admin to root).

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Raritan EMX (data-center PDU gateway, web GUI + SNMP)
- **Firmware**: emx_ecx_3.6.1_46982 (EOL); other EMX/ECX firmware with the same port_mux/proto_listener handling are likely affected
- **Vendor**: Raritan (Legrand)
- **Architecture**: ARM uClibc embedded Linux, BusyBox httpd + haserl CGI + port_mux (root)

## Impact

- **Confidentiality**: Full device compromise as root; PDU/power telemetry and network config exposed
- **Integrity**: Arbitrary command execution on the power-management gateway
- **Availability**: Full control of the PDU management plane and rack power infrastructure

## Mitigation

1. Validate `proto_listener[<inst>].program` against a whitelist of predefined binary paths
2. Restrict instance names to the predefined set (http/https/localhttp/mbusd/ssh)
3. Sanitize `program_args` (reject shell metacharacters / `-c` with arbitrary commands)
4. Drop privileges (setuid non-root) in `port_mux` before `execv`
5. Enforce a mandatory password change on first login (cover `raw_config_update.cgi`)
