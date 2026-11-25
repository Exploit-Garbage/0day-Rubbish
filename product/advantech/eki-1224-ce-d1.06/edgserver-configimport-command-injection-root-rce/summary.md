# Advantech EKI-1224-CE D1.06_r5772 - ConfigImport-Bypassed edgserver system() Command Injection in the NTP-Update Thread

Advisory: https://0day-rubbish.com/blog/edgserver-configimport-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Advantech is a Taiwan-based industrial automation and embedded computing vendor whose EKI line of serial
device servers bridges legacy RS-232, RS-422 and RS-485 equipment onto Ethernet and IP networks. The
EKI-1224-CE belongs to that line and is deployed in industrial control environments, where the serial ports
of controllers, meters and machine tools are carried over the plant network. The firmware image analyzed
here is `EKI-1224-CE_D1.06_r5772_850F8715.bin` (16.25MB), an AM335x ARM EABI5 hard-float build of
GNU/Linux 2.6.32. Its administrative plane is a BoA web server that dispatches configuration forms to
`/cgi-bin/index.cgi`, an ELF32 ARM EABI5 hard-float program that is not stripped and still carries DWARF
debug information. A second process, the daemon `edgserver` (270KB, stripped), is the device's
configuration and event engine: it re-reads the configuration store `/var/other1/edg.conf` at runtime and
drives the periodic tasks that act on the values it finds there.

One of those tasks is the NTP update thread, `sym.NtpUpdateThread` at `0x343e8`. It loads the configured NTP
server name from its configuration structure, checks that the value is acceptable to a validity helper,
formats the command line `ntpdate -b %s` around it with `snprintf`, and passes the result to `system()`. The
format string is a fixed rodata literal at `0x3a9a0`; the substitution is the raw configuration string.
Nothing between the store and the shell escapes, quotes or filters that string, so a semicolon in the NTP
server field terminates the `ntpdate` invocation and begins a new command, and the new command runs as root:
neither the web server nor the daemon ever drops privileges on this platform.

The write side of the chain is the web management plane. The time-and-network configuration screen posts to
`/cgi-bin/index.cgi` with `FORM_ACTION=SaveTimeInfo`, and the handler writes the `NTPSERVER` form field into
`/var/other1/edg.conf` through the firmware's INI parser, with no validation and no sanitization; the
`%NTPSERVER%` template-substitution token in the same binary confirms the key name. A second handler,
`ConfigImport` at `0x13198` with its `SaveImportInfo` worker at `0x13250`, writes imported configuration files
into the same store, so it bypasses the form-side `CheckInetValid(inet_pton)` check entirely - which is why
the same root cause reaches four further format-string sinks in `edgserver` and not only the NTP one. Those
five sinks share one setter mechanism and one sink mechanism, and they are published as a single finding
rather than five.

Verification is a sink-level replication, not a live appliance. The exact `system()` command line that the
daemon's NTP thread builds was replayed on an isolated cloud-hosted sandbox as `/bin/sh -c`; the injected run
produced a marker file containing `uid=0(root) gid=0(root) groups=0(root)`, a benign control run produced no
marker, and an alternate payload wrote a second marker. The request path, the configuration store, the
daemon's read of the key and the sink location are established statically: from the DWARF-bearing CGI binary
on the setter side, and from the daemon's rodata format strings and its `system()` PLT import on the sink
side. No HTTP request was fired at device hardware, and no emulation of the AM335x image was performed, so the
end-to-end request-to-shell chain was not observed dynamically. The record states that boundary plainly and
this advisory keeps it.

This is an authenticated finding. It is not an authentication bypass and it is not a default-credential
finding: the factory-default `admin/admin` pair on this product is a separate weakness disclosed on its own
terms, and the injection consumes a legitimate administrator session, so it survives any password change. No
identifier has been assigned to this finding.

- Component: the NTP update thread `sym.NtpUpdateThread` at `0x343e8` in `bin/edgserver`, together with the
  setters that write its input - `sym.SaveTimeInfo` in `/cgi-bin/index.cgi` for the `NTPSERVER` key, and the
  `ConfigImport` handler at `0x13198` with `SaveImportInfo` at `0x13250` for imported configuration files
- Sink: `system(buf)` at `0x34580` (imported at `0x115d4`), fed by
  `snprintf(buf, "ntpdate -b %s", NTPSERVER)` at `0x34578`, with the format string at rodata `0x3a9a0`
- Source: the `NTPSERVER` field of the `SaveTimeInfo` form posted to `/cgi-bin/index.cgi`, and the
  configuration file accepted by `ConfigImport`; both reach `/var/other1/edg.conf` as raw text
- Sanitization: none - no metacharacter screen precedes `IniParserAppendValue` and `IniParserSaveFile`
  (`0x24b20`), the store keeps the value as an ordinary string, and the daemon separately interpolates it
  raw into the `ntpdate -b %s` format

## CVSS Score

- Score: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - an authenticated administrator of the
  device's web management plane turns a configuration field into arbitrary command execution as root on the
  appliance
- Attack Vector: Network - the entry point is the device's HTTP management service, a TCP listener that
  answers over the routed network; the second hop is the daemon's own re-read of the configuration store, and
  neither hop requires adjacency, physical access or a local account
- Attack Complexity: Low - one authenticated form post writes the value, and the daemon's NTP thread then
  fires on its own schedule or on an NTP-server change; there is no race to win, no memory-corruption groom,
  no address leak and no multi-step state machine
- Privileges Required: High - both halves of the chain are gated behind the administrator session on the web
  management plane, and the firmware defines no second web account tier that reaches the setter path
- User Interaction: None - the credential holder drives the request directly; the only other event in the
  chain is the device's own scheduled task
- Scope: Unchanged - the injected command executes inside the appliance, in the authority of the component
  whose configuration field was abused; no crossing into a separate security authority is claimed
- Impact C/I/A: all High - command execution as root yields the complete configuration store including the
  device credentials, control of the serial-port data path, control of the network behaviour of the unit, and
  service availability at will
- Published arithmetic: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827, rounded up to 7.2
- Why Privileges Required is High rather than Low: the setter that writes the injected value is the
  administrator's own configuration form, protected by the web server's Basic Auth stanza over the whole
  document root, and the record identifies no operator-level or read-only web principal that can reach it.
  CVSS scores the privileges an attacker must already possess, not the difficulty of obtaining them, so the
  factory-default `admin/admin` pair does not lower this metric: it is a separate CWE-798 issue, and the
  injection remains equally reachable after the administrator sets a strong password. A Low reading would
  assert a non-administrative web account that this firmware does not define
- Rejected reading, recorded for completeness: the Low-privilege variant of the same impact profile is
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High, whose Exploitability term is
  8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255 and whose sum with the same Impact of 5.873119 is 8.708374,
  rounded up to 8.8. It is rejected because no lower-privilege principal reaches the setter path on this
  firmware. It is printed here so the published 7.2 cannot be confused with it, and it must not be quoted as
  the rating for this finding
- CWE: CWE-78 primary (OS command injection through a shell-interpreted argument); CWE-798 adjacent and
  disclosed separately (factory-default administrator credential), reported without raising any metric

## Affected Products

- Advantech EKI-1224-CE industrial serial device server, firmware D1.06_r5772 (image
  `EKI-1224-CE_D1.06_r5772_850F8715.bin`, 16.25MB): AM335x, ARM EABI5 hard-float, GNU/Linux 2.6.32, BoA web
  server with the CGI program `/cgi-bin/index.cgi` (ELF32 ARM, not stripped, DWARF debug information
  present) and the daemon `bin/edgserver` (270KB, stripped); the affected code is the NTP update thread's
  `system()` construction and the four further format-string sinks listed in the analysis
- Scope of the merged sinks: five `edgserver` sinks share one root cause - the `ntpdate -b %s` sink at
  `0x3a9a0` (primary, `NTPSERVER`), `route add default gw %s %s` at `0x4ca00` (`GATEWAY`, `IFACE`),
  `ifconfig %s hw ether %s` at `0x4d658` (`INTERFACE`, `MAC`), `ip route add %s dev %s src %s` at `0x4c89c`
  (`ROUTE_DST`, `ROUTE_DEV`, `ROUTE_SRC`) and `arping -I br0 -c 3 %s` at `0x4d604` (`ARPING_TARGET`). Each
  has a different format string, rodata address and config key, but the same setter mechanism and the same
  sink mechanism, so they are counted as one finding
- Not claimed: other models of the EKI line, other firmware revisions of this model, and the remaining
  `system()` and `popen()` call sites in the CGI program that the record lists as unexplored candidates
  (32 sites in total, of which `ExportSystemLog`, `SaveSyslogdInfo`, `InitSyslog`, `BootFromNewKernel`,
  `getAdvJITMonitorSharedMemory`, `GetMonitorSetting`, `GetMonitorStatistic`, `GetDNSServer`,
  `CheckSDExistTemp` and `CheckAliveWithPing` are named). Their reachability was not established and no
  statement is made about them
- Verification method and its boundary, stated exactly: static disassembly of `sym.NtpUpdateThread` with r2
  and capstone confirmed the format string, the substitution and the `system()` import; the dynamic evidence
  is a sink-level replication in which the exact recorded command line was replayed as `/bin/sh -c` on an
  isolated cloud-hosted sandbox, producing markers for the injected runs and none for the benign control. An
  end-to-end HTTP verification (authenticated `ConfigImport` POST with a malicious configuration file,
  followed by the daemon's configuration apply and the real `system()` call) was not performed and would
  require device emulation or a physical unit; a full instruction-level trace of the stripped ARM
  `edgserver` binary was likewise not completed, so the daemon-side call is established by rodata format
  strings, the PLT import and the configuration-key inference rather than by an executed trace
- Privilege ceiling: arbitrary command execution as root. The web server and the daemon both run as root and
  never drop privileges on this platform, which is why the marker identity is `uid=0(root)`. Not reached and
  not claimed: escape from the appliance to attached serial or network hosts, persistence across a factory
  reset or reflash, and any memory-corruption primitive

## Impact

- Complete operating-system compromise of the appliance by a credential holder who was never meant to hold a
  shell. A field that legitimately contains an NTP server name becomes an arbitrary command channel running
  as root, giving the attacker the full configuration store, the device credentials it holds, and the
  ability to rewrite every setting the web interface exposes and everything it does not
- Loss of the serial-port data path as a trust boundary. An EKI-1224-CE exists to carry raw serial traffic
  between attached industrial equipment and the IP network; root on the device means that traffic can be
  observed, injected into or disrupted at will, and the serial operating modes can be reconfigured so the
  change is not visible from the equipment side
- Control of the unit's network behaviour: addresses, routes, the default gateway and the resolver the plant
  segment depends on are all reachable from the same shell, which is enough to turn a serial bridge into a
  foothold on the industrial network rather than a passive converter
- Persistence consistent with root command execution on an embedded Linux system - startup behaviour,
  account files and the configuration store that the boot sequence re-reads. The payload itself lives in
  `/var/other1/edg.conf`, so it survives a power cycle and re-fires on the next NTP update tick until the
  field is cleared. What survives a factory reset or a reflash was not tested and is not claimed
- Availability impact at will: the device can be restarted, the daemon stopped, or the network configuration
  corrupted until the unit no longer serves its serial ports; the `route` and `ifconfig` sinks of the same
  root cause reach the same authority
- The chain is quiet in product terms. The request is an ordinary authenticated form post inside the
  documented configuration workflow, the value sits in a field that legitimately holds an arbitrary
  hostname, and the file that carries it is a file the administrator is expected to write. Log review that
  only records successful logins sees nothing unusual, and the command runs later, from the daemon

## Mitigation / Fix Recommendations

1. Remove the shell from the NTP path. Build the `ntpdate` invocation as an argument vector and execute it
   with an `execve()`-family call, so the configured server name is a single argument word that no shell ever
   parses. This closes the class for this sink rather than the instance, and the same change applies to the
   four merged `route`, `ifconfig` and `arping` sinks
2. If a shell implementation must remain for one release cycle, single-quote every interpolated configuration
   value with literal single-quote escaping, and add a post-construction assertion that the assembled command
   contains no `;`, `|`, `&`, `$`, backtick, newline or carriage return. Fail the update and log it when the
   assertion trips, rather than executing the line
3. Validate by type at the setter. An NTP server field is a hostname or an IPv4 literal: check it as one -
   `inet_pton()` for the literal form and a strict hostname grammar for the name form - and reject the rest
   with an explicit error. Address fields have no legitimate reason to carry shell metacharacters, so an
   allowlist is both simpler and stronger than a blocklist here
4. Close the import bypass that the same root cause relies on. `ConfigImport` at `0x13198` and
   `SaveImportInfo` at `0x13250` write raw values into `/var/other1/edg.conf` and never run the form-side
   `CheckInetValid(inet_pton)` check, so every key they accept is a fresh path to the same sinks. An imported
   file must pass exactly the same per-key validation as an interactive form, with a per-key type table
   rather than a shared string copy
5. Validate at both ends of the store. `edgserver` re-reads `/var/other1/edg.conf` and should not trust it:
   applying the same per-key checks at the daemon's import point closes the path against a configuration file
   written by any other means - an older firmware, a restored backup, or a different interface
6. Drop the daemon's privilege. The NTP update path needs no root authority; running `edgserver`, or at
   least the task thread's children, as an unprivileged identity does not fix the injection but caps what
   this defect and every future one in the same binary can do
7. Restrict the configuration store. `/var/other1/edg.conf` is written by the web layer and read by a root
   daemon; its ownership and permissions should allow writes only from the components that legitimately own
   it, which raises the cost of the second-order path
8. Add a handler-level regression test: post a time configuration whose `NTPSERVER` field contains `$(true)`,
   a semicolon and a backtick, then assert that the value is either rejected or never reaches a child
   process. Repeat through the `ConfigImport` path, and run the same suite against every model that shares
   this CGI and daemon code base
9. For operators, until a patch exists: keep port 80 off untrusted segments, change the factory-default
   administrator credential, disable the NTP client where it is not used, and treat unexpected edits to the
   `NTPSERVER`, `GATEWAY`, `IFACE`, `MAC`, `ROUTE_*` or `ARPING_TARGET` keys in `/var/other1/edg.conf` as an
   arbitrary-code-execution indicator rather than a configuration mistake. Network restriction reduces
   exposure; it does not fix the defect, because any administrator session remains a command channel

## References

- https://0day-rubbish.com/blog/edgserver-configimport-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- disclosure@0day-rubbish.com

---

Written by the 0day Rubbish Research Team.
