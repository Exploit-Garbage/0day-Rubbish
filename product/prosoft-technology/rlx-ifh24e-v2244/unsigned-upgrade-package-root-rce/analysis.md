# ProSoft RLX-IFH24E v2.2.44 — Unsigned Upgrade Package Executed With Root Privileges: Firmware Upload to Root Command Execution and Full Account-Database Overwrite (uid=0(root) recorded)

## 1. Overview

### Overview of the finding

The ProSoft RLX-IFH24E is an industrial wireless radio whose maintenance interface accepts a
firmware or configuration file over HTTP and hands it to an installer that decides what to do with
it by looking at the file extension. Nothing between the upload and the execution verifies that the
bytes came from the vendor. The system upgrade package `RLX-IFH24E_v2244.pkg` contains the CGI that
receives the upload (`usr/lib/cgi-bin/tool_reprogramming.cgi`), the installer it invokes
(`/sbin/upgrade`, a POSIX shell script), the factory account database (`/etc/passwd`), and the
default configuration record (`/etc/db1`). Read together, those four artefacts describe a complete
privilege path: one `multipart/form-data` POST from a session that can reach the maintenance page
places attacker bytes in `/upgrade/upgrade/`, and the installer then runs them as root - executes
`./pre` and `./post` out of an attacker-supplied archive, extracts an inner archive into `/`, and,
on two sibling branches, copies an attacker-supplied file over the account database or over the
configuration store. We verified the installer half of that path by executing the firmware's own
`/sbin/upgrade` unmodified inside an isolated `chroot` sandbox, and we verified the upload half by
disassembly only. The recorded landing identity is `uid=0(root)`, written by the payload itself.

The classification defect is CWE-494: code is downloaded - here, submitted - and then installed
without an integrity check. The product has no signature verification, no digest comparison against
a value the attacker cannot supply, and no version or platform check that is cryptographic. It does
have one check, and that check is the interesting part: the installer compares a product-name string
that it reads from the device against a product-name string that it reads from a file inside the
package being installed. Both sides of the comparison are therefore available to the attacker, one
from the published firmware and the other from their own archive, so the check constrains nothing
about authenticity and only rejects a package that does not bother to claim the right platform name.

### Overview of the product and its platform

The appliance is an OEM build. Our material identifies the vendor as ProSoft Technology (United
States) and the designation RLX-IH 24E, with the system image distributed as
`RLX-IFH24E_v2244.pkg` (version v2.2.44) and a separately distributed radio baseband image
`RLX-IFH24E_v5089.mhx`. Underneath the vendor branding sits a MicroHard Systems IPx21 platform on a
"MHX-910" board design: an Intel IXP425 XScale processor, ARM big-endian, with a Linux 2.4.24-uc0
kernel as recorded in the package metadata. The platform carries its own configuration identity
file `/etc/MHX_CONFIG`, and in this firmware that file contains `PRODUCT_NAME=IPx21PROSOFT` - the
string the installer expects to see echoed back at it.

The management interface is served by `boa` and `boa_ssl` from the device base flash, with static
pages under `/usr/web` and 57 ARM-big-endian CGI programs under `/usr/lib/cgi-bin/`. The default
configuration record in the firmware (`db1_default`) carries `UI_Access_HTTP=B`, `HTTPS=B` and
`Telnet`/`SSH` entries of `A`, which we read as the web interface being enabled on both HTTP and
HTTPS in the shipped default and the shell transports in their non-default state. The CGIs retain
DWARF debug information, which is why handler names such as `HandleSubmit` and library symbols such
as `SubProgram_Start` can be cited by name rather than by bare address.

### Overview of the testbed and what it does and does not prove

There are two halves to this finding, and they carry different evidential weight. This section
exists so that the reader never has to guess which is which.

The installer half is measured. The firmware's `/sbin/upgrade` and the other scripts in `/sbin`
were copied into a `chroot` sandbox whose root filesystem is a copy of the package's own rootfs, and
they were executed there byte-for-byte unmodified. An x86 busybox build provided the helper programs
the installer calls (`/bin/sh`, `tar`, `gunzip`, `mv`, `cp`) because the firmware's own copies are
ARM big-endian and the sandbox host is not; a stub replaced the platform `mhx` utility;
`/etc/MHX_CONFIG` was written with the product identity the firmware ships; and a three-entry
factory-style account database was pre-seeded so the before/after state could be compared. The
sandbox ran on a researcher-controlled cloud host with no route to any appliance.

The upload half is inferred. It rests on disassembly of the shipped ARM-big-endian CGI and of the
shared platform UI library, not on an observed request. The base flash that contains `/bin/boa` -
the component that decides whether an unauthenticated client is allowed to fork a CGI at all - is
not present inside this upgrade package, so its access control could be neither proved nor
disproved. No HTTP request was ever issued to this product during this work and no physical
appliance was used, so the reachability argument below is an argument, not a measurement.

### Overview of affected scope

Only `RLX-IFH24E_v2244.pkg` was analysed. No other build of the RLX-IFH24E, no other version of the
OEM IPx21 platform, and no other MicroHard or ProSoft product is claimed as affected. The upgrade
path is a shared platform component rather than a per-product script, so the same root cause plausibly
reaches other products built on the same OEM platform; we state that as a likelihood for the vendor's
benefit and we do not score it, because we did not test it.

### Overview of independence

Searches of the public vulnerability catalogue were run by product designation, by the RLX-IH name,
by the OEM platform name and by the vendor name. The product and platform searches returned no
records. The vendor's RadioLinx engineering-software line returned one record concerning a
pseudo-random number generator in that software family - a different product and a different defect
class. The OEM manufacturer's own catalogue entries concern the IPn4Gii, BulletLTE and IPn3
families, which are different platforms and do not overlap with the IPx21 lineage. We publish no
identifier from any of those families, because an identifier is worth printing only when it is the
same product and the same root cause, and none of them is.

## 2. Vulnerability Summary

### Vulnerability Summary table

| element | value |
|---|---|
| product | ProSoft RLX-IFH24E (designation RLX-IH 24E), OEM platform MicroHard IPx21 |
| artefact | system upgrade package `RLX-IFH24E_v2244.pkg`, version v2.2.44 |
| entry point | `usr/lib/cgi-bin/tool_reprogramming.cgi`, handler `HandleSubmit` at `0x8d1c` |
| privileged component | `/sbin/upgrade`, POSIX shell, executed with the CGI's privileges (root) |
| dispatch key | the file extension of the uploaded name |
| code-execution branch | `.pkg` — `./pre`, `tar -xf extract/upgradepkg.tar -C /`, `./post`, reboot |
| account branch | `.passwd` — copy over `/etc/passwd` and `/etc/passwd_original` |
| configuration branch | `.factory` — copy over `/etc/db1` |
| authenticity check | one string equality; expected value from the device, asserted value from the package |
| landing identity | `uid=0(root)`, recorded by the payload as `PRE-RAN-AS-UID=0` |
| CWE | CWE-494 primary; CWE-345, CWE-347, CWE-434, CWE-73, CWE-250, CWE-269 contributing |
| published score | 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

The installer is a short shell script that switches on `${FILE##*.}` and then performs an operation
appropriate to each extension. Every branch performs a destructive filesystem operation on a fixed
path, and none of them consults a signature, a digest list, a version table or any other artefact
that the attacker does not already control. The three branches that matter:

```sh
# /sbin/upgrade, reconstructed behaviour from the shipped script (POSIX sh, runs as root)
case "$EXT" in
  passwd)  cp /upgrade/upgrade/$FILE /etc/passwd
           cp /upgrade/upgrade/$FILE /etc/passwd_original ;;
  factory) cp /upgrade/upgrade/$FILE /etc/db1 ;;
  pkg)     gunzip -t /upgrade/upgrade/$FILE || exit 1
           tar -xf /upgrade/upgrade/$FILE -C <staging>
           # the only "validation": an equality between two strings the attacker can both read
           [ "$DEVICE_PRODUCT_NAME" = "$PKG_LOCK_NAME" ] || { echo "This unit doesn't support the image."; exit 1; }
           echo "Match image."
           ./pre
           tar -xf extract/upgradepkg.tar -C /
           ./post
           echo "Upgrade Successful"
           reboot ;;
esac
```

The `.pkg` branch is the code-execution primitive. `./pre` runs before anything else is applied, so
the attacker's code executes on the pristine filesystem with root privileges and can read the old
state; `tar -xf extract/upgradepkg.tar -C /` then applies an inner archive whose entry names are not
constrained, which is an arbitrary rootfs write; `./post` runs after the write, so the attacker's
code also sees the new state; and the branch ends in an unconditional reboot, which makes the change
persistent and destroys the runtime evidence. The `.passwd` branch is the account-database primitive
and needs no execution at all: it replaces both the live and the backup copy of `/etc/passwd` with
attacker text. The `.factory` branch is the same primitive against the configuration store.

### Vulnerability Summary preconditions

Four things must hold, and the strength of our evidence differs for each.

- A session must be able to reach `/cgi-bin/tool_reprogramming.cgi`. We assume an authenticated
  administrative session and we say why in the Authentication Boundary section; we could not test
  this precondition at all, because the component that enforces it is not in the package.
- The uploaded name must survive two hops intact: the CGI builds an argument string for `/bin/mv`
  and then passes the original filename to `/sbin/upgrade`, so a name containing a space or a path
  separator changes the token count and breaks the hand-off. Our payload name contains neither.
- For the `.pkg` branch, the archive must be well-formed gzip (`gunzip -t`) and must carry the
  platform string the device expects. Both are attacker-side correctness recovered from the shipped
  firmware, not environmental luck.
- The installer must run with the privileges we claim. It does: the CGIs are forked by the web
  server, and the account database in the package gives `admin` uid 0, which is the identity the
  management stack runs under.

### Vulnerability Summary — why the root cause is the absence of a step, not a broken step

It is tempting to describe this as a weak check that should be strengthened. That framing is wrong
and it leads to the wrong fix. The equality of `PRODUCT_NAME` and `LOCK_NAME` was never meant to
answer "did this come from the vendor" - it answers "is this the right platform", and it answers
that correctly, as the control run demonstrates. The product simply has no authenticity step
anywhere in the path between an HTTP request and root execution: no signature, no digest compared
against a value stored in base flash, no allowlist of package contents, no confinement of the
scripts inside the package. Adding strength to the compatibility check would change nothing,
because the attacker supplies both of its operands.

## 3. Authentication Boundary

### Authentication Boundary — what the artefacts show

The package exposes a real account model, and it is documented in the firmware rather than in our
testbed:

```
admin:   <DES-crypt hash>:0:0:admin:/:/bin/txtUI
upgrade: <same DES-crypt hash>:500:500:ftpupgrade:/upgrade/upgrade:/bin/sh
```

Three facts follow. The `admin` account is uid 0 - the management stack is not privilege-separated,
and an administrative login already holds the privilege the sink needs. Its shell is `/bin/txtUI`, a
restricted interactive interface rather than a general shell, which is a user-interface constraint
and not a security boundary once arbitrary code execution is available. And a second account exists
with uid 500, a working `/bin/sh` and the same password hash as `admin`, whose home directory is the
same `/upgrade/upgrade` staging path the uploader writes into - it looks like an account intended
for the vendor's file-transfer maintenance path. Alongside the account entries the interface carries
a password-change page and a configurable RADIUS mode, which is what makes the existence of an
authentication plane credible rather than speculative.

### Authentication Boundary — what the artefacts do not show

The HTTP-layer decision is made by `/bin/boa`, which lives in the device base flash and is not
contained in `RLX-IFH24E_v2244.pkg`. That is the single most important limitation of this research
and it cuts both ways. It means we cannot prove that the uploader requires a session, and it also
means we cannot prove that it does not.

What the package does let us say is narrower and worth stating precisely: none of the 57 CGIs under
`/usr/lib/cgi-bin/` contains authentication logic of its own. No CGI imports `crypt`, none parses or
sets a session cookie, and there is no login CGI in the directory; the menu pages link directly to
the CGIs. So whatever access control exists on this surface lives entirely in the web server's
request handling or not at all. It is not in the handlers.

### Authentication Boundary — the principal the sink requires

Given the above we scored the finding as requiring administrative privilege, and the reasoning is
conservative rather than triumphant. Firmware installation is an administrative function on this
product; the handler is a maintenance CGI that the interface's own menu pages link to directly; the
only account model the package documents for that interface is the uid-0 `admin` entry with its own
password-change page and optional RADIUS back end. We found no evidence that a lower-privileged or
unauthenticated principal can drive the reprogramming handler, and we decline to invent evidence we
do not have.

The uncomfortable detail is the `upgrade` account: uid 500, home inside the upload staging path, and
sharing the `admin` hash. If the management interface admits that account to the reprogramming
handler, the privilege requirement drops from High to Low. We did not test it, and an untested
authority may not raise a published score. The alternative reading is printed in full with its own
arithmetic in the CVSS section and labelled as rejected.

### Authentication Boundary — what is deliberately not claimed

- No claim that the surface is unauthenticated, even though the structural evidence leans that way.
- No claim that a factory credential was used, accepted, or forced to change. The default password
  situation is reported as a deployment amplifier with an explicit statement that it was not
  demonstrated.
- No claim about the `upgrade` account's web-interface authority.
- No claim that the same posture holds on any other build, platform version or product family.

## 4. Attack Surface

### Attack Surface — listeners and their default state

The management interface is served by `/bin/boa` on HTTP and by `/bin/boa_ssl` on HTTPS. The
firmware's own default configuration record enables the web interface on both transports
(`UI_Access_HTTP=B`, `HTTPS=B` in `db1_default`) while carrying non-default values for the `Telnet`
and `SSH` entries (`A`). We treat that record as a product artefact and therefore as admissible
evidence of a default, which is the standard we apply to every default claim in this advisory; the
record is inside the shipped package, not inside our testbed.

### Attack Surface — the CGI directory

`/usr/lib/cgi-bin/` contains 57 ARM big-endian executables. They retain DWARF debug information, so
function and file names survived compilation and the disassembly could be read at source-symbol
level rather than by guessing. One of them is the maintenance upload handler
`tool_reprogramming.cgi`. Others implement the ordinary configuration and status pages the menu
links to. The directory has no authentication helper, no shared session object and no login entry
point, as described above.

### Attack Surface — how the surface was mapped

The mapping was static and offline. The upgrade package was unpacked on a researcher workstation,
its rootfs inventoried, and the ARM big-endian CGI set disassembled with a capstone-based locator
driven off the ELF symbol and DWARF data. The upload handler's `HandleSubmit` routine was read to
recover the exact sequence of library calls, and the shared platform UI library was read to recover
how `SubProgram_Start` builds its argument vector. No live service was contacted at any point in
that process, and no interface was probed with a network request.

### Attack Surface — adjacent surfaces noted but not exercised

Two neighbouring observations are recorded here for the vendor and are explicitly excluded from this
finding's score and impact. First, the runtime startup configuration symlink-exposes three sensitive
paths into the web document root - `/etc/MHX_CONFIG`, `/var/log/messages` and `/etc/system.debug`,
presented as configuration, syslog and debug views - which is an information-disclosure surface
whose own access control depends on the same unexamined `boa` policy. Second, `request.cgi` is a
legacy debug CGI whose first-argument dispatch includes sending AT commands to the radio module;
whatever it is gated by, it is gated by the same unknown web-server policy. Neither was executed.
Both are structural observations and both are stated as such. We also note, without scoring it, that
the platform ships SNMP community strings `public` and `private`; those belong to the configuration
plane and are not part of this chain.

## 5. Sink Identification

### Sink Identification — how the sinks were found

The search started from the only interface the product offers for installing files, enumerated the
CGI directory, and read the upload handler. From there the question was simply what the handler does
with the bytes, and the answer was a two-command sequence ending in an invocation of a shell script
that shipped in the same package. Reading that script end to end - it is short - yielded every sink
below. No fuzzing and no dynamic probing of the device was involved, because the sinks are visible
in the shipped code path.

### Sink Identification — sink one, the uploader itself

The handler routine `HandleSubmit` at offset `0x8d1c` performs, in order:

```
cgiFormFileName("file1")        -> original filename of the uploaded part
cgiFormTempFileName             -> path of the temporary file holding the body
sprintf(buf, "%s /upgrade/upgrade/%s", tempfile, origfilename)   ; format string at rodata 0x2b1c
SubProgram_Start("/bin/mv", buf)          ; must succeed before the next step
SubProgram_Start("/sbin/upgrade", origfilename)
```

Two properties matter. The filename is used unmodified in a path built by `sprintf`, and the same
unmodified filename is handed to the installer as argv - so the extension that selects the installer
branch is entirely attacker-chosen, and the destination directory `/upgrade/upgrade/` is fixed. The
`/bin/mv` step must succeed for the installer to run, which is the only ordering constraint in the
chain.

### Sink Identification — sink two, the installer's execution steps

`/sbin/upgrade` executes `.pkg` content: `./pre` and `./post` from the extracted staging tree, with
`tar -xf extract/upgradepkg.tar -C /` in between. Those three operations are the sinks - two
executions of attacker-authored scripts and one unconstrained archive extraction into the root of
the filesystem, all performed by a root process.

### Sink Identification — sink three, the account-database copy

The `.passwd` branch's `cp /upgrade/upgrade/$FILE /etc/passwd`, repeated for
`/etc/passwd_original`, is a sink in the sense that matters for impact: it replaces the operating
system's account list wholesale, including userids, password hashes and login shells. Writing both
copies means the device's own recovery path restores the attacker's database rather than the
vendor's.

### Sink Identification — sink four, the configuration-store copy

The `.factory` branch's `cp /upgrade/upgrade/$FILE /etc/db1` replaces the configuration store that
holds the management interface's own settings, including the transport enable flags quoted earlier.
An attacker who writes `/etc/db1` can change how the device is administered afterwards.

### Sink Identification — execution identity

The installer runs with the privileges of whatever invoked it. In the product that is the CGI,
forked by `boa`; in our sandbox it is the interactive shell that ran the `chroot`. The payload
settled the question empirically rather than by argument: `./pre` wrote `PRE-RAN-AS-UID=0` into a
marker file, so the executing uid was 0 in the sandbox, and the account database in the package
shows `admin` as uid 0, so on the appliance the identity would be the same. We report the measured
value and the supporting artefact separately and do not merge them into a stronger claim.

### Sink Identification — the argument builder, and why it is not the bug

`SubProgram_Start` at offset `0xbd5c` in the shared platform UI library takes a caller-supplied
argument string, splits it on spaces with `strtok` into at most eight tokens, then `vfork`s and
calls `execvp(prog, argv)`. Because no shell is involved, shell metacharacters in a filename do not
become command injection - a naive reading of `sprintf(buf, "%s /upgrade/upgrade/%s", ...)` would
suggest injection and would be wrong. Two real consequences remain and both are engineering
constraints on an attacker rather than vulnerabilities: a filename containing spaces would be split
into more tokens than intended, and the eight-token ceiling bounds how much can be passed. Neither
is the finding. The finding is that the resulting program is a script that installs unsigned code as
root.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted input is the body and the original filename of the `file1` part of a
`multipart/form-data` POST to `/cgi-bin/tool_reprogramming.cgi`. Every byte that the installer later
executes or copies originates there. The filename is load-bearing twice - once as the destination of
the move, and once as the extension that selects the branch inside the installer.

### Source Identification — the self-asserted product identity

A second source deserves its own entry because it is the one that defeats the only check in the
path: the `lockfile` inside the `.pkg` archive. The installer reads `LOCK_NAME` from that file and
compares it against the device's `PRODUCT_NAME` in `/etc/MHX_CONFIG`. The expected value is a
compile-time constant shipped in public firmware (`IPx21PROSOFT`), so satisfying the comparison
requires reading the firmware once, not breaking anything. A package metadata set that is validated
against a value inside the same package is not a source of assurance, and this is the precise point
at which the authenticity question is decided in the attacker's favour.

### Source Identification — sanitization that exists and what it is for

There is real sanitization in this code, and it works for a different purpose. The argv
construction avoids a shell, so the product is not vulnerable to metacharacter injection at this
hop. The gzip stream test (`gunzip -t`) rejects a corrupt or truncated upload before unpacking, so
the product does not attempt to install a broken file. The `strtok` token ceiling bounds the
argument list. None of these checks was designed to answer "is this package authentic" and none of
them can be strengthened into such a check; listing them matters because a reader assessing a fix
needs to know which protections already exist and are irrelevant to this finding.

### Source Identification — validation that is absent

- No signature over the package, and no signature format, keyring or verification binary anywhere in
  the package's installer path.
- No digest of the package compared against a value the attacker cannot supply.
- No allowlist of what a `.pkg` may contain; `pre`, `post` and the inner archive are all executed or
  applied without restriction on path or content.
- No extension whitelist at the uploader; the branch is selected by whatever suffix arrived.
- No path canonicalisation of the uploaded filename before the destination string is built.
- No structural validation of a `.passwd` file: uid assignments, duplicate accounts, arbitrary
  shells and arbitrary hashes are all accepted, because the file is copied, not parsed.
- No audit record that survives the reboot the `.pkg` branch performs on success.

## 7. Data Flow

### Data Flow — end to end chain

```
attacker                                     appliance
   |                                            |
   |  POST /cgi-bin/tool_reprogramming.cgi      |
   |  multipart/form-data, part name "file1"    |
   |  filename "payload.pkg", body = gzip(tar)  |
   |------------------------------------------->|  boa (base flash; access control not in package)
   |                                            |  tool_reprogramming.cgi : HandleSubmit @ 0x8d1c
   |                                            |    cgiFormFileName / cgiFormTempFileName
   |                                            |    sprintf -> "/tmp/xxx /upgrade/upgrade/payload.pkg"
   |                                            |    SubProgram_Start("/bin/mv", ...)        [root]
   |                                            |    SubProgram_Start("/sbin/upgrade", "payload.pkg")
   |                                            |
   |                                            |  /sbin/upgrade  (POSIX sh)                 [root]
   |                                            |    ext == "pkg"
   |                                            |    gunzip -t                    (stream sanity only)
   |                                            |    tar -xf                      (unpack to staging)
   |                                            |    PRODUCT_NAME == LOCK_NAME    (both attacker-known)
   |                                            |    ./pre                        -> uid=0 exec
   |                                            |    tar -xf extract/upgradepkg.tar -C /
   |                                            |    ./post                       -> uid=0 exec
   |                                            |    reboot
   |<-------------------------------------------|  "Match image." / "Upgrade Successful"
```

The `.passwd` variant follows exactly the same path with a different extension, and ends at
`cp /upgrade/upgrade/payload.passwd /etc/passwd` plus the same copy to `/etc/passwd_original`.

### Data Flow — properties of the chain worth naming

- Every hop is intended product behaviour. Nothing crashes, nothing parses malformed input, and no
  undocumented interface is touched; the sequence is the vendor's own firmware upgrade procedure.
- Taint is never reduced. The bytes that arrive in the request body are the bytes that `./pre`
  executes; there is no transformation between upload and execution beyond a move and an unpack.
- The chain is deterministic and single-shot: one request, one install, one reboot.
- The success page is indistinguishable from a legitimate upgrade, and the two messages the
  installer prints (`Match image.`, `Upgrade Successful`) are the same in both cases.
- The evidence is destroyed by the final step. The reboot that follows a successful install clears
  the runtime state, which is why a forensic response has to rely on the persistent effects -
  the changed rootfs, the changed account database - rather than on process traces.

### Data Flow — where the chain is measured and where it is inferred

The boundary runs down the middle of the diagram. From `/sbin/upgrade` onwards, every step was
executed and observed, with marker files and the recorded uid as evidence. From the HTTP request to
the `/bin/mv` step, everything is recovered from disassembly of the shipped binaries and nothing was
observed in motion. A reader is entitled to weight those two halves differently, and the advisory is
written so that they can.

## 8. Exploit Construction

### Exploit Construction — step sequence

The published script performs three separable things, so that the package-building half can be
inspected or verified without ever touching a device.

- Build the outer package: a gzip-compressed tar containing `file` (the `IMAGEFILE` / `IMAGEPATH`
  metadata the installer reads), `lockfile` (carrying `LOCK_NAME=IPx21PROSOFT`), `pre` (the payload,
  mode 0755), `post` (a marker, mode 0755) and `extract/upgradepkg.tar` (the inner archive whose
  entries are applied to `/`).
- Optionally upload it: construct the `multipart/form-data` body with the part name `file1` and the
  attacker-chosen filename, POST it to `/cgi-bin/tool_reprogramming.cgi`, and send HTTP Basic
  credentials when the deployment uses them.
- Optionally build the account-database variant instead: a three-line file whose first line adds a
  uid-0 account with `/bin/sh`, written locally and uploadable under any `.passwd` name.

The default payload is deliberately inert. `./pre` is `#!/bin/sh` followed by a `touch` of one
marker file and an `echo` of `PRE-RAN-AS-UID=$(id -u)` into a second marker. No deletion, no
encryption, no modification of any other file, and no attempt to survive the reboot.

### Exploit Construction — payload engineering constraints

Three constraints come from the code and are worth recording because they are the difference between
a working and a non-working payload. The filename must not contain spaces, because `SubProgram_Start`
splits its argument string on spaces with `strtok` and extra tokens change what `/bin/mv` is asked to
do. The filename's extension selects the branch, so the same bytes under `.pkg`, `.passwd` and
`.factory` do three completely different things. And the `lockfile` must carry the platform string
exactly; the control run in the next section demonstrates what happens when it does not, which is a
clean refusal rather than a partial install.

On the device the payload scripts run under the vendor's own `/bin/sh`, so they must be POSIX
compatible; our sandbox used a busybox shell, which is a superset of what the appliance accepts in
practice but is not identical to it, and a payload relying on busybox-only syntax would be a
different risk. We used the intersection.

### Exploit Construction — what the exploit deliberately does not do

- It does not touch the inner archive's ability to overwrite system binaries beyond demonstrating
  that entries land at `/` - the verified inner archive carries a single marker file.
- It does not install persistence, does not add a boot service and does not modify `/etc/db1`.
- It does not attempt the account-database variant over the network by default; that mode writes a
  file locally and stops.
- It does not brute-force, replay or otherwise attack the authentication plane, and it does not
  attempt the `upgrade` account.
- It has no out-of-band channel: the script does not listen for a callback, contact any remote host
  other than the one given on the command line, or persist state between runs.

## 9. Dynamic Verification

### Dynamic Verification — environment

The sandbox was an isolated `chroot` root on a researcher-controlled cloud host. Its filesystem was
a copy of the rootfs from `RLX-IFH24E_v2244.pkg`. Four substitutions were made, all of them in the
harness and none of them in the code under test: an x86 busybox build supplied `/bin/sh`, `tar`,
`gunzip`, `mv` and `cp` in place of the firmware's ARM big-endian copies; a stub supplied `mhx`;
`/etc/MHX_CONFIG` was populated with the product identity `PRODUCT_NAME=IPx21PROSOFT`, matching what
the firmware ships; and `/etc/passwd` was pre-seeded with three factory-style entries. Before the
run the identity of that pre-seeded account database was captured as md5
`86bb53947974a34a9b10649ec3d5baae`, so the overwrite could be demonstrated by digest rather than by
assertion. The code under test - `/sbin/upgrade` and the other scripts in `/sbin` - came from the
firmware and was executed unmodified.

### Dynamic Verification — the account-database run

A file named `evil.passwd` carrying a marker line was placed in `/upgrade/upgrade`, which is the
state the uploader's `/bin/mv` step would have produced, and the installer was invoked with that
filename. Both `/etc/passwd` and `/etc/passwd_original` were replaced by the uploaded text: the
recorded md5 no longer matched the pre-run digest, and the marker line was present in both files.
The installer's own diagnostics included `logger: not found` and `mhx: not found`, which are absent
helpers in the sandbox PATH and are not product behaviour; they are reproduced here because
concealing output from a negative-looking line would misrepresent the transcript.

### Dynamic Verification — the package run

A crafted `evil.pkg` was built and placed in the same staging directory, and the installer was
invoked on it. The installer printed `Match image.`, then `Upgrade Successful`, and exited 0. Four
independent effects were then observed on the sandbox filesystem.

### Dynamic Verification — observed output

```
$ chroot <sandbox> /bin/sh -c "export PATH=/upgrade/upgrade:/bin:/sbin; /sbin/upgrade evil.pkg"
Match image.
Upgrade Successful
SCRIPT_EXIT=0

$ ls <sandbox>/RLXIFH_C13_TOKEN <sandbox>/RLXIFH_C13_POST_DONE <sandbox>/rootfs_marker.txt
RLXIFH_C13_TOKEN                 # ./pre executed
RLXIFH_C13_POST_DONE             # ./post executed
rootfs_marker.txt                # inner archive applied to /

$ cat <sandbox>/RLXIFH_C3_UID
PRE-RAN-AS-UID=0                 # executing uid, recorded by the payload itself

$ cat <sandbox>/rootfs_marker.txt
RLXIFH_C3_ROOTFS_OVERWRITE=1
```

The uid marker is the load-bearing line: the value was written by the payload into a file at runtime,
not read from a configuration, so it is the executing identity rather than an inference about it.

### Dynamic Verification — the control and why it matters

A control package was built with exactly the same structure - same outer tar layout, same metadata
files, same inner archive, same marker-writing scripts - and one deliberate difference:
`LOCK_NAME=WRONGPRODUCT`. The installer refused it with `This unit doesn't support the image.`, and
none of the four markers appeared anywhere in the sandbox. This matters for three reasons. It shows
that the markers are produced by the install path and not by the harness. It shows that the observed
success was conditional on the product-string comparison, which is the one check the script performs,
and therefore that the check is bypassable by supplying the documented string rather than being
irrelevant. And it establishes mutual exclusion between the positive and negative runs, so the
positive run cannot be explained by a sandbox in which everything appears to succeed.

### Dynamic Verification — number of successful detonations, stated exactly

One positive `.pkg` run, one positive `.passwd` run and one negative control run, in one sandbox on
one host. Each effect was observed once. We did not repeat the runs across multiple sandbox builds,
and we did not run them on hardware. Any statement in this advisory of the form "the installer
does X" is a statement about unmodified firmware code executed in this sandbox, and any statement of
the form "the product does X when a request arrives" is an inference from disassembly.

### Dynamic Verification — boundaries of what was verified

- No physical appliance was used at any point.
- No HTTP request was issued to the product, and the uploader hop was not executed: the file was
  placed in the staging directory by hand to reproduce the state the CGI's `/bin/mv` would have
  created.
- The web server, its access control, the CGI binaries and the firmware's own ARM helper utilities
  were not executed in the sandbox; the first because it is absent from the package, the last because
  of the architecture mismatch.
- The reboot that closes the `.pkg` branch did not happen, since the sandbox is a directory tree
  with no init; the code path leading to it was observed up to that point.
- The run is not presented as an exploit against a live device, and it should not be read as one.

## 10. Reachability and Security Impact

### Reachability and impact — network position

The interface is a network service. The firmware's default configuration record enables the web
interface on both HTTP and HTTPS, so an attacker who can reach the management address can reach the
handler. On an industrial wireless radio that address typically sits on the control-network segment
rather than on a general user network, and that is the honest description of who can reach it: an
attacker already positioned on, or able to route to, the management network. We scored the vector as
Network because the transport is a network service enabled by default in the shipped artefact, and we
note at the same time that we never demonstrated the reach by sending a request.

### Reachability and impact — what the achieved identity controls

`uid=0` on this appliance means the whole device: the radio configuration, the management
configuration in `/etc/db1`, the account database and its backup, the log files, the platform
identity file, and the persisted firmware itself through the inner archive applied to `/`. For a
device that carries traffic between a process network and its field instruments, root on the radio is
also a position on the path that traffic takes - an interception and disruption point, not merely a
configuration target. We did not test interception and do not claim it as a measured result; it is
the ordinary consequence of the identity that was measured.

### Reachability and impact — the privilege question, answered in full

The measured landing identity is `uid=0(root)`, recorded by the payload as `PRE-RAN-AS-UID=0`. The
supporting artefact for the same conclusion on real hardware is the shipped account database, which
gives `admin` uid 0: the administrative web identity is root, so a CGI forked for an administrative
session runs as root and hands root to the installer. We report the measured value from the sandbox
and the artefact from the package as two separate pieces of evidence for the same conclusion, and we
do not claim to have observed root on an appliance.

The account-database branch reaches the same ceiling by a different route and is worth separating
from it, because it works without executing anything: replacing `/etc/passwd` with an entry for a
uid-0 account whose shell is `/bin/sh` gives a full root shell to the next interactive login, where
the factory `admin` account's `/bin/txtUI` does not. That is a second, independent path to the same
ceiling, and it needs only file copy.

### Reachability and impact — detection notes

Every step is documented product behaviour, so nothing about the request pattern is anomalous: a
firmware upload from the maintenance page, the vendor's own success response, and a reboot that the
installer always performs. The two lines the installer prints on success are not an indicator either,
because a legitimate upgrade prints exactly the same `Match image.` and `Upgrade Successful`. The usable
indicators are therefore post-hoc and filesystem-level: an installed package whose `LOCK_NAME`/`VERSION`
pair does not correspond to any release the operator obtained, an unexpected file under
`/upgrade/upgrade/`, and account-database drift, specifically a uid-0 account with a general shell that
the vendor did not ship. An operator who records the digest of firmware before installing it has a
detection path; one who does not has none.

### Reachability and impact — what is not claimed

- No unauthenticated access to anything.
- No execution observed on real hardware, and no request sent to a device.
- No reach into the radio baseband image `RLX-IFH24E_v5089.mhx`, and no impact demonstrated on any
  attached control system, PLC or historian.
- No privilege escalation: the chain starts from the administrative identity that the product's own
  account database already grants uid 0.
- No use of the information-disclosure surfaces noted in the Attack Surface section, and no AT
  command was sent to any radio module.

## 11. Fix Recommendations

### Fix Recommendations — vendor side, ordered by root cause

- Add a cryptographic authenticity check before any package content is executed or applied. Require
  a signature over the package verified against vendor public keys stored in base flash, where they
  cannot be replaced by an upgrade, and fail closed before `gunzip`, `tar`, `./pre` or `tar -C /`.
- Remove the installer's reliance on package-supplied identity data. Keep
  `PRODUCT_NAME`/`LOCK_NAME` as the compatibility check it is, and stop allowing it to be the only
  gate before execution; if the check stays, document it as a compatibility check so nobody later
  mistakes it for authentication.
- Confine package-supplied code. Execute `./pre` and `./post` inside a staging chroot or mount
  namespace with no access to the live rootfs, or abolish package-supplied scripts in favour of a
  fixed vendor script set chosen by a signed manifest.
- Constrain the inner extraction. Extract `extract/upgradepkg.tar` to a staging directory and apply
  it through a path allowlist that rejects `..` components, absolute names, symlink entries, device
  nodes and any destination outside the partitions a system image legitimately owns; remove `-C /`.
- Take the account database off the upload surface. Delete the `.passwd` branch or restrict it to a
  physically gated recovery path (button hold or serial console) with unconditional logging, and
  validate structure, uid assignments and shell values against what the product actually ships.
- Apply the same authenticity requirement to the `.factory` branch, because rewriting `/etc/db1`
  rewrites the device's security configuration along with everything else.
- Separate privileges between the web interface and the installer. Run the uploader and the installer
  as a dedicated unprivileged user confined to the staging directory, escalating only for the single
  verified apply step, so that a bad package is contained even when the signature check is bypassed.
- Validate at the handler as well. Whitelist extensions in `tool_reprogramming.cgi` instead of
  dispatching on the arriving suffix, reject filenames containing path separators before the
  destination string is built, and log the digest and size of every accepted upload to storage that
  survives the reboot.
- Give the installer an audit trail that outlives it: record package digest, lock name, version and
  the outcome in a log partition that the reboot preserves, and expose it in the management
  interface.

### Fix Recommendations — a regression test the vendor should add

Assert that a package with an absent signature, an invalid signature, or a signature from a key not
present in base flash is rejected with a distinct error and that `./pre` is never executed. Assert
that an inner archive containing `../`, absolute or symlink entries is rejected. Assert that an
upload named `anything.passwd` cannot modify `/etc/passwd` or `/etc/passwd_original`, and that an
upload named `anything.factory` cannot modify `/etc/db1`. The control case described in
this advisory, a well-formed package whose `LOCK_NAME` does not match, already provides a
working harness for all of these, and each test should assert both the refusal and the
absence of every marker the positive case produces.

### Fix Recommendations — operator side, until a patch exists

- Restrict the management listener to a dedicated management network and named hosts; never expose
  it to a general user network or to the internet, and put an authenticating proxy in front where
  the deployment allows it.
- Change the factory passwords on both the `admin` and `upgrade` accounts, and enable the RADIUS
  mode the product offers where the environment supports it.
- Treat every firmware upgrade as a supply-chain event: obtain packages only through a channel whose
  integrity is independently established, record the digest of what was received, and compare it
  against the vendor's published value before installing.
- Put `/etc/passwd`, `/etc/passwd_original` and `/etc/db1` under file-integrity monitoring, and
  alert on any uid-0 account whose shell is not the vendor's restricted interface.
- Snapshot the device configuration before and after each upgrade so that a `.factory` overwrite is
  recoverable, and keep the account database copy out of band.
- If compromise is suspected, re-image from media whose integrity is independently verified and
  rotate every credential the device holds - restoring a single file is not sufficient, because the
  install path writes the whole rootfs.

## 12. CWE and CVSS

### CWE and CVSS — classification

The primary classification is CWE-494, Download of Code Without Integrity Check: the product accepts
code from a network client and installs and executes it without verifying its integrity or origin.
CWE-345 (Insufficient Verification of Data Authenticity) and CWE-347 (Improper Verification of
Cryptographic Signature) are co-equal, since the only check is a non-cryptographic string equality
and no signature is verified at any point. CWE-434 (Unrestricted Upload of File with Dangerous
Type) describes the uploader, which whitelists nothing and dispatches on the arriving suffix.
CWE-73 (External Control of File Name or Path) describes the extension-selected destination. CWE-250
and CWE-269 describe the privilege posture: a root CGI that hands root to package-supplied scripts,
and an account model in which the administrative interface identity is itself uid 0.

The finding is explicitly not CWE-78. No command string is injected at either hop - `SubProgram_Start`
builds argv itself and never invokes a shell - so a command-injection remediation, input filtering of
the filename, or shell escaping would not close this chain. Anyone triaging this by keyword should
note that: the defect is the missing authenticity step, not string handling.

### CWE and CVSS — vector derivation

The published vector is `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, computed from first
principles rather than inherited from any note:

- Impact sub-score: ISS = 1 - ((1 - 0.56) x (1 - 0.56) x (1 - 0.56)) = 1 - 0.44^3 = 0.914816.
- Impact, Scope Unchanged: 6.42 x 0.914816 = 5.873119.
- Exploitability: 8.22 x 0.85 (AV:N) x 0.77 (AC:L) x 0.27 (PR:H) x 0.85 (UI:N) = 1.234708.
- Base: 5.873119 + 1.234708 = 7.107826, rounded up to the next tenth = 7.2 High.

Each metric is justified against artefacts rather than preference. AV:N because the entry point is a
network service that the firmware's own default configuration record enables on both HTTP and HTTPS.
AC:L because the chain is deterministic: no race, no timing window, no memory-layout dependency, no
on-path position, and the only environment knowledge it needs is a platform string published in the
shipped firmware - the control run shows that changing exactly that string is what causes refusal,
which makes the string attacker-side correctness. PR:H because firmware installation is an
administrative function and the only account model documented in the package for that interface is
the uid-0 `admin` identity with its password-change page and optional RADIUS mode; we did not
demonstrate that any lower-privileged principal can drive the handler, and we decline to score a
privilege we did not test. UI:N because after a session holds that privilege, nothing further from a
human is required - the move, the install, both script executions and the reboot all follow from one
request. S:U as argued below. C/I/A all High because root on the appliance reads everything on it,
rewrites any file through `tar -C /` or through the account and configuration branches, and controls
availability including by means of the reboot the installer always performs.

The source material behind this advisory carried no computed score, so there was no recorded number
to inherit or correct. That absence is worth stating because the same privilege/scope combination is
frequently mis-stated in secondary write-ups as 8.8, which is the value of the low-privilege variant;
with administrative privilege and unchanged scope the correct value is 7.2.

### CWE and CVSS — the Scope decision

Scope Unchanged. The vulnerable component and the impacted component are the same appliance
operating system, and no authority boundary is crossed to move between them: the CGI already runs as
root, the installer already runs as root, and the archive extraction is performed by that root
process. The chain exercises an authority the vulnerable component already holds rather than moving
into one it does not. Scope Changed would describe a management component yielding control of a
separate functional component - the radio baseband, or an attached control system downstream of the
device - and while a replaced firmware image plausibly produces exactly that, we demonstrated
execution on the appliance's own rootfs and nothing beyond it. An unproven crossing cannot raise a
published score, so it is printed below as a rejected reading instead.

### CWE and CVSS — rejected and conditional readings, labelled as such

- **Rejected A — low privileges (8.8)**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, ISS
  0.914816, Impact 5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 = 2.835255, base
  8.708373, rounded up to 8.8. This reading is available because the shipped account database
  contains a second entry, `upgrade`, with uid 500 and home inside the upload staging path, sharing
  the `admin` password hash. We did not demonstrate that the management interface grants that
  account access to the reprogramming handler, so the higher number would assert an untested
  authority. Rejected.
- **Rejected B — Scope Changed (9.1)**: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`, ISS
  0.914816, Impact 6.128026 (changed-scope formula), Exploitability 8.22 x 0.85 x 0.77 x 0.50 x 0.85
  = 2.286496, base before the 1.08 factor 8.414522, base 9.087684, rounded up to 9.1. Rejected for
  the reasons in the Scope decision above.
- **Rejected C — high complexity (6.6)**: `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H`,
  Exploitability 0.705547, base 6.578666, rounded up to 6.6. Rejected: the only condition the chain
  depends on is a string that the shipped firmware publishes, and the control run isolates it as the
  single cause of refusal.
- **Conditional D — unauthenticated HTTP layer (9.8)**:
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, Exploitability 3.887043, base 9.760161, rounded
  up to 9.8. This is what the finding becomes if `boa` does not gate the handler. It is a structural
  inference and not a measurement, and it is not the headline: the binary that would answer the
  question is not in the package we had. The supporting observation - 57 CGIs, none importing
  `crypt`, none handling a session cookie, no login CGI in the directory - establishes only that the
  handler layer adds no authentication of its own, which is a weaker statement than the reading it
  is offered to support.
- **Conditional E — factory credential in place (7.2)**: the shipped account database carries a
  DES-crypt hash on the uid-0 `admin` entry and the same hash on the uid-500 `upgrade` entry. If a
  deployed unit still carries that factory password and the product does not force a change at first
  login, an attacker who can reach the management listener needs no secret. Not demonstrated: we did
  not authenticate to any appliance, and we did not test whether first login forces a change.
  CVSS scores the privilege level of the account used rather than whether the secret was public, so
  the vector is unchanged and this remains 7.2
  (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`). It is published as a deployment amplifier for
  the operator to assess. Our notes transcribe that hash in two differing case forms, so the literal
  string is withheld rather than published with a real chance of being wrong.

### CWE and CVSS — what is deliberately not published

No score is published for the adjacent information-disclosure surfaces (the symlink-exposed
configuration, syslog and debug paths under the web root) or for the legacy debug CGI, because
neither was exercised and both depend on the same unexamined access-control policy. No score is
published for the platform's SNMP community strings `public` and `private`, which are a
configuration-plane weakness of the same firmware and not part of this chain. No score is published
for "other products on the same OEM platform", because they were not tested. And no identifier from
a neighbouring product family is attached to this finding.

### CWE and CVSS — summary

7.2 High as published, computed from `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`; two rejected
readings at 8.8 and 9.1 and one rejected at 6.6, each with its own arithmetic; and two conditional
readings that are labelled as unproven - one that would score 9.8 if the web server's access control
turns out not to cover this handler, and one that leaves the score unchanged at 7.2 while removing
the need to know a secret. The honest headline is the conservative one: an administrative session can
install unsigned code that the device executes as root, and we proved the installation and execution
half of that against unmodified firmware code in a sandbox rather than against a live appliance.

Written by the 0day Rubbish Research Team.
