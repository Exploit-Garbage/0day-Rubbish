# Auerswald COMmander 6000 / 6000R 8.6D - Path Traversal in the Provisioning Archive Import Leading to Unauthenticated Root Code Execution (CWE-22)

Advisory: https://0day-rubbish.com/blog/auerswald-commander-provisioning-import-zip-slip-binary-hijack-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The Auerswald COMmander 6000 and COMmander 6000R are closed-source enterprise IP-PBX /
unified-communications appliances from Auerswald (Germany), running an ARM32 glibc embedded Linux
userland whose management interface is a stock lighttpd 1.4.64 fronting a 3,498,560-byte in-house
FastCGI application called `webserver` that is started by init as root and never drops privilege.
In firmware 8.6D build 128154, the unauthenticated route `/provisioning_data_import` stores a
`multipart/form-data` part at `/data/provisioning/import/<basename>` and then spawns, as root, the
vendor's bundled extractor `posix_spawn("../minizip/miniunz", "-o", "-x", <zip>, "-d",
"/data/provisioning/import/")`; neither the application nor the extractor inspects archive entry
names, so an entry named `../../../opt/auerswald/hping2` escapes the extraction directory and
overwrites a root-owned mode-0755 binary with attacker bytes. Because the write truncates an
existing file, the original permission bits survive and the result is immediately executable, with
no separate chmod primitive. A second unauthenticated request to `/netdiagnostic_execute` then makes
root run `/bin/sh -c "/opt/auerswald/hping2 -1 -I eth0  -c 3 <target> -p <port>"`; the diagnostics
character whitelist validates the target argument but cannot protect the bytes at a compile-time
constant path, so the kernel honours the attacker's `#!/bin/sh` shebang and the payload's stdout is
captured into the HTTP response body. Two requests, zero cookies and zero credentials yield
`uid=0(root) gid=0(root) groups=0(root)` on an appliance that holds extension credentials, SIP trunk
credentials, call detail records and voicemail for every user it serves.

- **Component**: the provisioning data-import handler in `webserver` (route entry `0x96818`
  tail-jumping to `FUNC 0x96400` in `auerweb_page_provisioning.c`, calling the extractor helper
  `FUNC 0xedf60` in `auerweb_minizip.c`) together with the bundled `/opt/auerswald/minizip/miniunz`
  (md5 `36eb80de5ac55a8bbfc31e77c1d10e3d`, 63,260 bytes) it invokes as root; the execution trigger is
  the `netdiagnostic_execute` handler `FUNC 0x87d8c` at call site `0x880c4`.
- **Sink and source**: the sink is `fopen(extract_dir + entry_name, "wb")` inside a root extraction
  with `-o` (overwrite, no prompt) and `-d /data/provisioning/import/`; the source is the entry
  names inside the uploaded archive, transported in the request body. The HTTP `h_ulfilename`
  parameter is *not* the vulnerable input - it is correctly sanitised.
- **Sanitization**: the product does sanitize HTTP filename parameters (lowercase, `basename`,
  metacharacters to `_`) and does whitelist the diagnostics target argument against
  `0-9A-Za-z.-:/`, and both work as intended. Nothing validates archive entry names, and nothing
  protects the contents of a binary path that appears as a constant in a root shell command.
- **Authorization**: both routes are declared AccessLevel 2 and both answered 200 to a cookie-less
  request. The product's gate (`web_auth` `0x15958`, sole caller of `web_checkAccess` `0xf5d68`)
  covers only the service-technician and DAA families - 12 of 750 routes - so this is a systemic
  authorization gap, proven internally by one shared handler at `0x3b018` returning 401 under
  `servicetrace.pcap` and `daemontools.pcap` but 200 under the level-2 route name
  `ethernettrace.pcap`.

## CVSS Score

- **Score**: 9.8 Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) - two unauthenticated
  HTTP requests give complete control of an appliance that terminates and records every call it
  serves.
- **AV:N** - both hops are inbound HTTP to the management listener; no local, adjacent or physical
  access is involved.
- **AC:L** - deterministic, no race, no timing window, no memory-layout dependency, no
  on-path position, no hardware abstraction layer dependency, and demonstrated in both the freshly
  initialised and the password-configured state. The one subtlety (the multipart part name must equal
  the filename) is attacker-side correctness recoverable from the vendor's own shipped JavaScript,
  not an environmental condition.
- **PR:N** - zero cookies, zero credentials; a control set of routes returned 401 in the same run, so
  the 200s are the product's own decision and not a permissive testbed.
- **UI:N** - no administrator action and no vendor-UI flow is required.
- **C/I/A all High** - root on the appliance reads every credential, call record, voicemail and
  provisioning template; writes the filesystem, firmware and telephony configuration; and controls
  availability including the voice path.
- **Scope**: Unchanged. The impacted operating system and telephony stack are not separated from the
  vulnerable web application by any authority boundary - the application already runs as uid 0 and
  the rootfs contains no suid or sgid binaries at all - so the chain exercises an authority the
  vulnerable component already held rather than crossing into another one. The Scope-Changed reading
  (a network-facing service yielding host-wide root on a different functional component) is argued in
  the analysis and would compute to 10.0; it is published as an alternative, not as the headline.
- **CWE**: CWE-22 primary (zip-slip path traversal in a root archive extraction); CWE-73, CWE-434,
  CWE-862 and CWE-250 contributing. Explicitly not CWE-78 - no command string was injected at either
  hop, so a command-injection fix would not close this chain.
- No CVSS value was recorded alongside our verification; the score above was computed from the vector
  for this advisory, so there is no recorded number to correct.

## Affected Products

- Auerswald COMmander 6000 and COMmander 6000R, firmware 8.6D build 128154, from Auerswald
  (Germany). Both models share one firmware image and one code base: `8_6D_000_COMmander60xx.rom`,
  60,719,362 bytes, md5 `0ba0ffbfa56bab00e7d12a4cb0b8fcd4`, containing a single ext2 filesystem at
  offset 588 inside a u-boot uImage, volume label `8.6D_000_128154.`.
- Affected component: the provisioning data-import handler in the vendor `webserver` binary plus the
  bundled minizip extractor it invokes; the execution trigger is the `netdiagnostic_execute` route
  and its constant-path invocation of `/opt/auerswald/hping2`.
- Runtime stack: embedded Linux ARM32 (armv7l, EABI5) against glibc, kernel 2.6.32-gds1.2 with 25
  `auer*` kernel modules as the hardware abstraction layer, busybox init, stock lighttpd 1.4.64
  speaking AF_UNIX FastCGI into the in-house `webserver`, and a `.data` route table of 750 entries
  whose authorization is self-managed by that binary.
- Only firmware 8.6D build 128154 was analysed and exercised. No other build, firmware line, edition
  or Auerswald product family (COMpact, COMfortel) is claimed, and no earlier image was available
  offline to diff against.
- Verification method and its boundary: the shipped rootfs was extracted with `debugfs rdump`,
  `/data` initialised by the vendor's own `data-setup`, and the vendor binaries - unmodified
  `webserver`, ARM `lighttpd/1.4.64`, `miniunz`, `hping2`, all re-verified by digest at conclusion -
  were run under `unshare -n -m` plus `chroot` with `qemu-arm` user-mode emulation and
  `-d strace` recording of every `execve`. The web server bound a loopback-only host port. **This is
  user-mode emulation of the ARM rootfs, not a physical appliance, and no request came from a
  separate network host.** No authentication, routing or sink behaviour was weakened; the one
  configuration change made during the work was a tightening (a non-empty password hash).
- Privilege ceiling reached: `uid=0(root) gid=0(root) groups=0(root)` on the appliance, observed in
  the product's own child process. Beyond the appliance nothing was reached or claimed - no handset,
  no upstream network host, no hypervisor. Persistence via the init-respawned `scripts/run-*` family
  is statically available through the same write primitive but was deliberately not exercised.

## Impact

- **Full administrative control of the PBX.** Root on this appliance means control of the SIP stack,
  the voicemail subsystem, DSP channels, trunk configuration and every extension the device serves:
  calls can be placed, redirected, recorded or dropped.
- **Credential exposure.** The configuration database under `/data/db/` carries fields including
  `cryptPasswd`, `passwd`, `passwdLdap`, `AdminPasswd`, `AdminPasswdHash`, `passwordHash` and
  `remote_access_token`; user certificate private keys sit under `/data/certs/user-certs`; SIP trunk
  and gateway credentials live in the provisioning data. Toll fraud is the standard monetisation of
  exactly this position.
- **Call metadata and voicemail content** for every user, i.e. who called whom, when, for how long
  and at what cost - a reportable data-breach event for organisations whose calls carry customer,
  legal, medical or financial content.
- **Managed-endpoint supply chain.** The appliance auto-provisions its phone fleet from templates
  under `/opt/auerswald/provisioning/` and `/data/provisioning/`, so root on the PBX becomes control
  of every managed handset's configuration.
- **Persistence and firmware survival.** The same root write primitive can replace
  `/opt/auerswald/scripts/run-*` scripts that busybox init respawns as root, giving execution that
  survives reboot; firmware and updater paths are root-accessible. None of this was installed during
  verification.
- **Pivot and interception.** The appliance sits on voice and management segments and ships
  `tcpdump`, `hping2` and `pcap` tooling, so root turns it into a sniffing point and a pivot into
  adjacent networks.
- **Availability.** The telephony stack can be stopped, the configuration database corrupted, or the
  web document root unmounted at will.
- **Detection is unusually quiet.** No failed login, no 401, no session creation and no
  privilege-change event occurs anywhere in the chain, because no authorization check runs. The
  product's own `run shell cmd:` log line records a completely ordinary diagnostics command, because
  the command string is ordinary. The observable indicators are the response body carrying foreign
  shell output, an `hping2` that is 256 bytes of text instead of 74,376 bytes, and root-owned
  mode-0666 files outside the data partitions.

## Mitigation

1. **Contain archive entries at the extractor boundary.** Before writing any entry, reject names
   containing a `..` component, reject absolute names, reject symlink entries, and require
   `realpath(extract_dir + entry)` to be a descendant of `realpath(extract_dir)`. Fix this in the
   helper that builds the `miniunz` invocation (`FUNC 0xedf60`) so both of its callers -
   `0x96400` and `0x948b8` (`auerweb_page_provisioning_downloadConfigurator`) - are covered.
2. **Stop passing `-o` to the extractor** and extract into a fresh empty directory, letting the
   application decide entry by entry whether a destination may be replaced. Overwrite-without-prompt
   is what made the replacement of a system binary silent.
3. **Allowlist provisioning archive contents.** The legitimate entry names are already compile-time
   constants in the binary (`/opt/auerswald/provisioning/*_template.xml`, `*_template.cfg`, device
   XML families); reject archives that contain anything else instead of extracting first.
4. **Hard-reject writes to executable locations from any upload path** - `/opt/**`, `/bin/**`,
   `/sbin/**`, `/usr/**`, `/etc/**`, `/lib/**` - as defence in depth that would have stopped this
   chain even with the containment bug intact.
5. **Close the authorization gap family-independently.** Make `web_checkAccess` default-deny for
   every route, with an explicit allowlist of genuinely public routes, and enforce the AccessLevel
   declared in the route table. Provisioning import and export, configuration backup export and
   restore, diagnostics execution, template renaming and language/locale changes must require the
   session they declare. The `0x3b018` handler - 200 under `ethernettrace.pcap`, 401 under
   `servicetrace.pcap` and `daemontools.pcap` - is the cleanest regression target.
6. **Introduce privilege separation.** Run `webserver` as a dedicated unprivileged user with the
   minimum capabilities, confine the extraction helper to `/data/provisioning/`, and mount `/opt`
   read-only or protect the vendor tree with dm-verity or IMA appraisal. The rootfs has no suid
   binaries, so creating a real boundary does not disturb any escalation surface.
7. **Stop invoking mutable root-owned binaries from a root shell.** Verify the tool's digest before
   invocation or move it to a read-only mount, and prefer the argv form of `posix_spawn` that the
   product already uses at 39 call sites; migrate the 16 sites of the shell-form wrapper
   `auer_systemf_insecure` (`0x2247f0`) to argv form.
8. **Add two regression tests, and fix the false-success admin-account route.** First, an
   archive-import test posting `../`, `../../`, `../../../`, absolute and symlink entries and
   asserting rejection while a benign archive still imports; second, an authorization census that walks the whole route table with no cookies, asserts 401 for every
   declared level above 0, and asserts that one handler registered under several names returns one
   status code. Alongside them, fix `admin_account_save`, which answers
   `{"success":"true"}` with a wrong old password and persists nothing, so that operators cannot
   believe a password was set when it was not.
9. **Operator-side until a patch exists**: restrict the management listener to a dedicated
    management VLAN or named hosts; front it with an authenticating reverse proxy that denies
    `/provisioning_data_import`, `/netdiagnostic_execute`, `/backupdata_export_cfg`,
    `/ethernettrace.pcap`, `/provisioning_data_rename_file` and `/languages_save`; verify the digests
    of `/opt/auerswald/hping2` (`afc33cdf96b060e636c463e622b6ae1b`) and
    `/opt/auerswald/minizip/miniunz` (`36eb80de5ac55a8bbfc31e77c1d10e3d`); put `/opt` and
    `/data/provisioning/` under file-integrity monitoring; alert on root-owned mode-0666 files under
    `/data/log/` and `/opt/auerswald/minizip/`; and if compromise is suspected, re-verify the whole
    vendor tree and rotate every credential the device holds rather than restoring one binary.

## Independence from Published Advisories

The public Auerswald lineage - CVE-2021-40856, CVE-2021-40857, CVE-2021-40858, CVE-2021-40859,
CVE-2021-40860 and related entries - contains no item with this root cause. The `/debug`
command-execution facet of CVE-2021-40859 has been removed from this build (no such route in the
750-entry table, `debug.conf` commented out); the `fileName=../../` traversal of CVE-2021-40858 has
become a SQL query key; and CVE-2021-40857 concerns a sub-admin password parameter, which this chain
never touches. Here the traversal travels inside archive entry names in a request body, against a
root extractor, on a different endpoint and a different sink. Separately, the `about_state`
unauthenticated information disclosure described by CVE-2021-40859 is still present in this build
and is disclosed alongside this finding as an adjacent item, explicitly not counted as part of it.

## PoC

`exploit/auerswald_commander_provisioning_zip_slip_binary_hijack_root_rce.py` - standard library
only. Builds the multipart request with the part name equal to the filename, stages an archive whose
entry slips to `/opt/auerswald/hping2`, triggers `/netdiagnostic_execute`, and reads the root marker
back out of the response body. Host, port, scheme, command, routes, target binary, traversal depth
and marker directory are all CLI arguments and default to loopback-safe values. `--control` repeats
the exchange with a benign archive and asserts that no marker appears; `--restore <file>` writes
pristine bytes back to the hijacked path through the same primitive and re-checks that the proof line
is gone, comparing against the recorded digest `afc33cdf96b060e636c463e622b6ae1b`.

## References

- Advisory: https://0day-rubbish.com/blog/auerswald-commander-provisioning-import-zip-slip-binary-hijack-root-rce
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com

---
*Maintained by the 0day Rubbish Research Team.*
