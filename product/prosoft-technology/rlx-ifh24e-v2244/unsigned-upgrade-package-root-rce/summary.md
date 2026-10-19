# ProSoft RLX-IFH24E v2.2.44 - Firmware Upgrade Package Executed Without Any Integrity Check, Reaching Root Command Execution and Full Overwrite of the Account Database (CWE-494, CWE-345)

Advisory: https://0day-rubbish.com/blog/prosoft-rlx-ifh24e-unsigned-upgrade-package-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

The ProSoft RLX-IFH24E - designated RLX-IH 24E in our material, and shipped by ProSoft Technology
(United States) as an industrial wireless radio - is a closed-source embedded appliance built on an
OEM platform from MicroHard Systems (the IPx21 family, board design "MHX-910") around an Intel
IXP425 XScale ARM big-endian processor running a Linux 2.4.24-uc0 kernel. Its management interface
is served by `/bin/boa` and `/bin/boa_ssl` over both HTTP and HTTPS by default, with static pages
under `/usr/web` and 57 ARM-big-endian CGI programs under `/usr/lib/cgi-bin/`. In the system
upgrade package `RLX-IFH24E_v2244.pkg` (version v2.2.44), the maintenance upload handler
`usr/lib/cgi-bin/tool_reprogramming.cgi` takes the `file1` part of a `multipart/form-data` POST,
moves the temporary file verbatim to `/upgrade/upgrade/<original filename>` with `/bin/mv`, and then
runs `/sbin/upgrade` with that original filename as its only argument. `/sbin/upgrade` is a POSIX
shell script that executes with the CGI's own privileges - root - and dispatches purely on the file
extension, and no branch of that dispatch performs any signature, hash or even CRC check on the
bytes it was handed. A `.pkg` file is passed through `gunzip -t` (a gzip stream-integrity test, not
an authenticity test), unpacked with `tar -xf`, and the only validation the script performs is a
string equality between `PRODUCT_NAME` read from the device's own `/etc/MHX_CONFIG` and `LOCK_NAME`
read from a file inside the supplied archive; when those two strings match - and the compared value
is taken from the very package being installed - the script executes `./pre` from the extracted
tree, extracts `extract/upgradepkg.tar` into `/` with `tar -C /`, executes `./post`, and reboots.
Two sibling branches are equally open: a `.passwd` upload is copied over both `/etc/passwd` and
`/etc/passwd_original`, replacing the entire account database with attacker text, and a `.factory`
upload overwrites `/etc/db1`, the device's configuration store. We ran the firmware's own
`/sbin/upgrade`, byte-for-byte unmodified, inside an isolated chroot sandbox on a
researcher-controlled cloud host. The crafted `.pkg` printed `Match image.` and `Upgrade Successful`,
left markers written by `./pre` and by `./post`, and recorded `PRE-RAN-AS-UID=0`; the crafted
`.passwd` replaced both copies of the account database, including a marker line granting a uid-0
account with `/bin/sh`; and a structurally identical control package whose only difference was a
wrong `LOCK_NAME` was refused with `This unit doesn't support the image.` and produced no markers at
all. The chain contains no memory corruption, no command injection and no shell-metacharacter abuse:
`SubProgram_Start` builds argv itself and calls `vfork`/`execvp` without ever invoking a shell, so
the defect is not string handling but the complete absence of an authenticity check on code the
product executes as root.

- **Component**: the maintenance upload CGI `usr/lib/cgi-bin/tool_reprogramming.cgi` (handler
  `HandleSubmit` at offset `0x8d1c`, format string at rodata offset `0x2b1c`) together with the
  installer script `/sbin/upgrade` from the system upgrade package `RLX-IFH24E_v2244.pkg`, and the
  shared helper `SubProgram_Start` in the platform UI library at offset `0xbd5c`. Both HTTP and
  HTTPS listeners of the management interface reach the same CGI directory
- **Sink**: `execvp("./pre")` and `execvp("./post")` plus `tar -xf extract/upgradepkg.tar -C /`
  performed by the POSIX shell script `/sbin/upgrade` while it runs with the privileges of the CGI
  that invoked it - root - on the appliance. On the `.passwd` branch the sink is
  `cp /upgrade/upgrade/$FILE /etc/passwd` and the same copy to `/etc/passwd_original`
- **Source**: the body and original filename of the `file1` part of a `multipart/form-data` POST to
  `/cgi-bin/tool_reprogramming.cgi`, plus the `LOCK_NAME` value the same archive carries about
  itself. Every byte of the installed image, including the code the installer later executes, comes
  from that one request
- **Sanitization**: none that bears on authenticity. The uploader performs no extension whitelist
  and no digest comparison; `SubProgram_Start` avoids a shell, which removes command injection but
  not code installation; `gunzip -t` proves only that the stream is well-formed gzip; and the
  product-name string comparison in the lockfile check reads its expected value from the device and
  its asserted value from the attacker's own package, so the check is satisfied by the attacker
  without possessing any secret

## CVSS Score

- **Score**: 7.2 High (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - one request from an
  authenticated administrative session installs attacker code that the product then runs as `uid=0`,
  but the published finding requires that administrative session and explicitly does not claim an
  unauthenticated path
- **Attack Vector: Network** - both management transports are enabled in the firmware's own default
  configuration record, so the reachable interface is a network service; no local console, adjacent
  segment or physical access is required by the chain. The transport, not the reachability, is what
  the shipped artefact establishes: we did not send any HTTP request to an appliance during this work
- **Attack Complexity: Low** - deterministic, with no race, no timing window, no memory-layout
  dependency, no on-path position and no hardware abstraction layer dependency. The single piece of
  environment knowledge required is the platform match string (`LOCK_NAME` must equal
  `IPx21PROSOFT`), which is a compile-time constant recoverable from the shipped firmware and from
  the device's own `/etc/MHX_CONFIG`; the control run proves that changing exactly that string is
  the only thing that stops the install, which makes it attacker-side correctness rather than an
  environmental condition
- **Privileges Required: High** - installing firmware is an administrative function of the product:
  the handler is named and wired as a maintenance CGI (`tool_reprogramming.cgi`, linked directly
  from the interface's menu pages), and the account model the package exposes is an `admin` entry
  with uid 0 plus a password-change page and a configurable RADIUS mode. We did not demonstrate
  that a non-administrative account can reach the uploader, so the conservative metric is used
- **User Interaction: None** - once a session holds administrative privilege, the POST, the move,
  the install, the execution of `./pre` and `./post` and the reboot all proceed without any further
  operator action, and no administrator click, approval dialog or confirmation step exists in the
  handler code path we recovered
- **Impact C/I/A: all High** - `uid=0` execution on the appliance reads the whole filesystem
  including the account database, the configuration store and any radio or credential material held
  on it, rewrites any file through `tar -C /`, and controls availability at will, including by
  forcing the reboot the installer performs unconditionally on success
- **Scope**: Unchanged. The vulnerable component and the impacted component are the same appliance
  operating system: the CGI already runs as root, `/sbin/upgrade` already runs as root, and the
  rootfs is extracted by a root process, so no authority boundary is crossed and no separate
  component is brought under attack. Scope Changed was considered and rejected
- **CWE**: CWE-494 primary (download of code without integrity check for the `.pkg` installer
  branch); CWE-345 and CWE-347 co-equal (the only authenticity check is a non-cryptographic string
  equality, and no signature is verified at all); CWE-434, CWE-73, CWE-250 and CWE-269 contributing
  and reported separately without raising any metric above. Explicitly not CWE-78 - no command
  string is injected at either hop, so a command-injection fix would not close this chain
- **Recorded score**: the research material behind this advisory carried no computed CVSS figure at
  all, so nothing was inherited and nothing had to be corrected. Every number in this section was
  computed from its own vector with the CVSS 3.1 formula. For readers comparing against other
  publications: an administrative-privilege, scope-unchanged finding with high impact on all three
  metrics is 7.2, and 8.8 is the value of the low-privilege variant; the two are not
  interchangeable
- **Rejected reading A - a low-privilege account instead**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  computes to 8.8 (ISS 0.914816, Impact 5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 =
  2.835255, base 8.708373, rounded up to 8.8). It is arguable: the shipped account database we
  recovered contains a second entry, `upgrade`, with uid 500 and home `/upgrade/upgrade`, sharing
  the `admin` password hash. We did not demonstrate that the management interface grants that
  account access to the reprogramming handler, and publishing 8.8 on that basis would assert an
  authority we did not test. Rejected in favour of the conservative reading
- **Rejected reading B - Scope Changed**: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` computes
  to 9.1 (ISS 0.914816, Impact 6.128026, Exploitability 2.286496 under the changed PR weight of
  0.50, base 9.087684, rounded up to 9.1). It would describe a network-facing management component
  yielding control of a separate functional component. The radio baseband image
  `RLX-IFH24E_v5089.mhx` and any attached control system are plausibly such components, but we
  demonstrated execution on the appliance's own rootfs only, and an unproven crossing may not raise
  the published score. Rejected
- **Rejected reading C - high attack complexity**: `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H`
  computes to 6.6. Rejected because nothing in the chain is conditional: the control run failed for
  exactly one deliberate reason, a wrong product string, and the correct string is published inside
  the firmware itself
- **Conditional reading D - unauthenticated HTTP layer, not demonstrated**:
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` computes to 9.8 Critical. This is the reading that
  would apply if the management listener does not gate `/cgi-bin/tool_reprogramming.cgi` at all. It
  is a structural inference and not a measured result, and it is published as a labelled conditional
  only: the binary that implements HTTP-layer authentication (`/bin/boa`) lives in the device's base
  flash, is not contained in this upgrade package, and therefore could be neither proved nor
  disproved from the artefacts we had. What we can state about the package is narrower - none of the
  57 shipped CGIs imports `crypt`, none parses a session cookie, and no login CGI exists in the
  directory, so the CGI layer adds no authentication of its own. That observation says nothing about
  what `boa` does before it forks a CGI, and the headline score does not rely on it
- **Conditional reading E - factory credential still in place, not demonstrated**: the shipped
  account database carries a DES-crypt password hash on the uid-0 `admin` entry, and the uid-500
  `upgrade` entry carries the same hash. If a deployed unit still carries that factory password and
  the product does not force a change at first login, any attacker who can reach the management
  listener already holds administrative credentials and no secret has to be discovered. This was not
  demonstrated: we did not authenticate to any appliance with a factory password, and we did not
  test whether first login forces a change. Under CVSS the metric scores the privilege level of the
  account used rather than whether the secret was public, so this reading changes the vector not at
  all - it remains 7.2 (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`) - and it is published as a
  deployment amplifier to be assessed by the operator, not as a higher score. Our own notes
  transcribe that hash in two differing upper/lower-case forms, so the literal string is withheld
  rather than published with a known-good chance of being wrong

## Affected Products

- ProSoft RLX-IFH24E, designated RLX-IH 24E in our research material, from ProSoft Technology
  (United States), an industrial wireless radio for process and machine networks. The appliance is
  an OEM build of the MicroHard Systems IPx21 platform ("MHX-910" board design): Intel IXP425
  XScale, ARM big-endian, Linux 2.4.24-uc0, with a MicroHard platform configuration identity of
  `PRODUCT_NAME=IPx21PROSOFT`
- Affected component: the maintenance upload CGI `usr/lib/cgi-bin/tool_reprogramming.cgi`, the
  installer `/sbin/upgrade` it invokes as root, and the two extension branches that carry the
  impact (`.pkg` for code execution, `.passwd` for account-database replacement). The `.factory`
  branch overwriting `/etc/db1` is the same defect on the configuration store and is disclosed as
  part of it
- Artefacts analysed: the system upgrade package `RLX-IFH24E_v2244.pkg` (system image, version
  v2.2.44), which contains the CGI directory, the account database, the installer and the
  configuration store, together with the separately distributed radio baseband image
  `RLX-IFH24E_v5089.mhx`, which was identified but not exercised. The base flash holding `/bin/boa`
  is not contained in the system upgrade package
- Runtime stack: embedded ARM big-endian Linux 2.4.24-uc0 on IXP425 XScale, `boa` and `boa_ssl` as
  the HTTP and HTTPS servers, static UI content under `/usr/web`, 57 CGI programs under
  `/usr/lib/cgi-bin/` retaining DWARF debug information (which is why handler names such as
  `HandleSubmit` and library symbols such as `SubProgram_Start` can be cited by name), a shared
  platform UI library, and `/sbin/upgrade` as a POSIX shell installer
- Only this system upgrade package was analysed. No other build of the RLX-IFH24E, no other version
  of the OEM IPx21 platform and no other MicroHard or ProSoft product is claimed as affected, even
  where the same installer lineage is plausible. The upgrade path is shared across base firmware of
  the same OEM platform, so a wider population is likely to share the root cause, and that is stated
  as a likelihood rather than as a verified scope
- Verification method and its boundary: the package was unpacked on a researcher workstation and
  rebuilt as an isolated `chroot` sandbox on a researcher-controlled cloud host whose root
  filesystem is the package's own rootfs copy. Inside that sandbox the firmware's `/sbin/upgrade`
  and the other scripts in `/sbin` were executed unmodified; an x86 busybox build stood in for the
  base-flash helpers the installer calls (`/bin/sh`, `tar`, `gunzip`, `mv`, `cp`), a stub replaced
  the platform `mhx` utility, `/etc/MHX_CONFIG` carried the product identity `IPx21PROSOFT`, and a
  three-entry factory-style account database was pre-seeded so the before/after state could be
  compared. The identity of that pre-seeded `/etc/passwd` was captured as an md5 digest before the
  run (`86bb53947974a34a9b10649ec3d5baae`) so the overwrite could be proved rather than assumed.
  **No physical appliance was used, no HTTP request was ever issued to this product, and nothing
  here is presented as an exploit against a live device.** Two lines of the installer's output
  (`logger: not found`, `mhx: not found`) are absent helpers in the sandbox PATH and are not
  product behaviour
- Privilege ceiling reached: `uid=0(root)`, recorded by the payload itself as `PRE-RAN-AS-UID=0` in
  a marker file, plus arbitrary file creation anywhere in the rootfs through `tar -C /`. Not reached
  and not claimed: no privilege escalation from an unprivileged account, no cross-host movement, no
  reach into the radio baseband or into any attached control system, and no unauthenticated request
  path

## Impact

- Root command execution on the appliance by an authenticated administrative session, through a
  single `multipart/form-data` POST followed by the product's own install sequence. The executed
  code is arbitrary: `./pre` and `./post` are attacker-authored shell scripts and the inner archive
  may write to any path in the rootfs
- Replacement of the entire account database. The `.passwd` branch copies the upload over both
  `/etc/passwd` and `/etc/passwd_original`, so the attacker decides which accounts exist, with
  which uid, which password hash and which shell. On this product the factory `admin` entry is uid 0
  with a restricted interactive shell, so an added uid-0 entry with `/bin/sh` converts an
  administratively restricted login into a full root shell on the next login
- Rewrite of the device configuration through the `.factory` branch (`/etc/db1`), which controls
  the management interface's own transports, accounts and radio behaviour - meaning the attacker can
  widen or narrow the exposure of the surface they arrived through and survive a later
  reconfiguration by the operator
- Persistence that is native to the product rather than improvised: a `.pkg` install writes the
  rootfs and the installer reboots afterwards, so whatever was installed is what comes back up.
  Nothing in the verified chain was retained after the run
- Availability control at will. A successful install ends in an unconditional reboot, and the same
  primitive can install content that prevents the device from serving traffic at all - a
  particular concern for a radio that carries traffic for field devices in a process network
- Detection is weak by construction: every step is documented product behaviour. The request is an
  ordinary firmware upload, the response is the vendor's own success page, and the device reboots
  because the installer always reboots. The installer's own success output (`Match image.`,
  `Upgrade Successful`) is identical to a legitimate upgrade, so it is not an indicator either. What
  remains is post-hoc and filesystem-level: an installed package whose `LOCK_NAME`/`VERSION` pair
  corresponds to no release the operator obtained, a file left behind under `/upgrade/upgrade/`, and
  account-database drift - specifically a uid-0 account with `/bin/sh` that the vendor did not ship
- Not claimed: no unauthenticated access, no remote code execution before a session is established,
  no escape from the appliance, and no impact on any system other than the appliance itself. Two
  adjacent structural observations are recorded in the analysis but were not exercised and are not
  part of this finding

## Mitigation / Fix Recommendations

1. **Verify authenticity before executing anything from an upgrade package.** Require a signature
   over the package, checked against vendor public keys held in the base flash rather than in the
   upgradable rootfs, and abort before `gunzip`, `tar`, `./pre` or `tar -C /` runs. A hash
   published alongside the package is not a substitute, because the attacker controls the download
   channel in this threat model
2. **Move the lockfile check out of the trust path.** The `PRODUCT_NAME`/`LOCK_NAME` comparison is
   a compatibility check, not an authentication check, and the script should say so - refuse to
   treat any value from inside the archive as evidence about the archive. If the platform identity
   must be compared, compare it against a value that cannot ship inside the same package
3. **Stop executing package-supplied scripts with the installer's privileges.** Run `./pre` and
   `./post` inside a chroot or mount namespace over the extracted staging tree only, with no access
   to the live rootfs, or replace them with a fixed vendor script set selected by a signed manifest
   so that no package-supplied code runs at all
4. **Constrain the inner extraction.** Extract `extract/upgradepkg.tar` into a staging directory and
   apply it through a path allowlist that rejects `..` components, absolute names, symlink entries
   and any destination outside the partitions a system image legitimately owns; never pass `-C /`
   with an unverified archive
5. **Separate the account database from the upload surface.** The `.passwd` branch should not exist
   as an HTTP-reachable primitive. Account provisioning belongs in an authenticated configuration
   operation that validates the file structure and rejects uid assignments the product does not
   ship; if a recovery import is genuinely required, gate it on physical presence (a button or a
   serial console) and log it unconditionally
6. **Treat the `.factory` branch the same way.** Overwriting `/etc/db1` from an upload rewrites the
   security configuration of the device together with everything else, so it needs the same
   authenticity requirement and its own audit record
7. **Introduce privilege separation between the web interface and the installer.** The CGI runs as
   root and hands that privilege straight to package content; running the uploader and the installer
   as a dedicated unprivileged user that can write only to `/upgrade/upgrade/` staging would confine
   a bad package to a directory, even before any signature check exists
8. **Validate the upload at the handler.** Whitelist accepted extensions in
   `tool_reprogramming.cgi` rather than dispatching on whatever suffix arrived, reject filenames
   containing path separators before the `/bin/mv` argument string is built, and record the digest of
   every uploaded package in a log that survives the reboot
9. **Add regression tests.** Assert that a package whose signature is absent, invalid, or signed by
   a key not in the base flash is rejected with a distinct error and that `./pre` is never executed;
   assert that a package whose inner archive contains `../` or absolute entries is rejected; and
   assert that an upload named `x.passwd` cannot alter `/etc/passwd` or `/etc/passwd_original`. The
   existing control case - a well-formed package with a wrong `LOCK_NAME` - already proves the
   harness for these tests exists and works
10. **Operator measures until a patch exists**: restrict the management listener to a dedicated
    management network and named hosts, front it with an authenticating proxy, and never expose it
    to a general user network or the internet; confirm that the factory password on the `admin` and
    `upgrade` accounts has been changed and that RADIUS mode is used where the product supports it;
    place `/etc/passwd`, `/etc/passwd_original` and `/etc/db1` under file-integrity monitoring and
    alert on any uid-0 account whose shell is not the vendor's restricted interface; and treat every
    firmware upgrade as a supply-chain event - obtain packages only through a channel whose integrity
    is independently established, and record the digest of what was installed

## Independence from Published Advisories

Searches of the public vulnerability catalogue by product designation, by the RLX-IH name and by the
OEM platform name returned no record for this appliance with this root cause. One record associated
with the vendor's RadioLinx engineering-software line concerns a pseudo-random number generator in
that software family, which is a different product and a different defect class, and it is cited
here only to state that it is unrelated. Records naming the OEM manufacturer's own product families
(IPn4Gii, BulletLTE and IPn3) concern different platforms and different chains, and none describes
an installer that executes unsigned package content with root privileges. We therefore publish this
as an original finding, and we deliberately list no identifier from any neighbouring family, because
an identifier is only worth printing when it is the same product and the same root cause.

## PoC

`exploit/prosoft_rlx_ifh24e_unsigned_upgrade_package_root_rce.py` - Python 3 standard library only.
It builds the crafted package (a gzip-compressed tar containing `file`, `lockfile`, `pre`, `post` and
`extract/upgradepkg.tar`), and can either write that package to disk for inspection or carry it in a
`multipart/form-data` POST to `/cgi-bin/tool_reprogramming.cgi`. Host, port, scheme, credentials,
command, lock name, product name, field name, marker token and output path are all CLI arguments and
default to loopback-safe values; the network send is a timeout-bounded HTTP request and the build
step has no network dependency at all. A `--control` mode builds the structurally identical package
with a wrong product string so that a legitimate operator can confirm on their own hardware that the
success path really is gated by that string and nothing else, and a `--passwd-mode` builds the
account-database variant as a file without sending it. The default payload is a non-destructive
marker: it touches one file and writes the executing uid into a second. **Because the network half
of this chain was never exercised against an appliance, running it against hardware you do not own
or have written authorisation to test will reboot and reimage that device.**

## References

- Advisory: https://0day-rubbish.com/blog/prosoft-rlx-ifh24e-unsigned-upgrade-package-root-rce
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com

---
*Maintained by the 0day Rubbish Research Team.*
