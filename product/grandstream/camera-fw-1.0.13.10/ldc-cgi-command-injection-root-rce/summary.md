# Grandstream GDS371x Camera Firmware 1.0.13.10 - ldc.cgi query-parameter command injection into the test_ldc system() command line

Advisory: https://0day-rubbish.com/blog/ldc-cgi-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Grandstream Networks builds the GDS371x series, an IP door and access camera line whose firmware ships an
embedded web management interface. The image analyzed in this research is firmware 1.0.13.10. Inside that
image, the web tree carries a CGI program at `/webSvr/web/cgi-bin/ldc.cgi`: 4,892 bytes, ELF 32-bit LSB
executable, ARM, EABI5 version 1 (SYSV), dynamically linked and stripped, built against uClibc and linked
with libclearsilver, the HDF template engine. The program exists to drive the camera's LDC
tuning: it reads a set of geometry values from the HTTP request and marshals them into a command line for
a helper binary, `/usr/local/bin/test_ldc`.

The read path is the ClearSilver HDF API. After `cgi_init()` establishes the CGI environment,
`hdf_get_value()` returns the value of each HTTP query parameter as a raw, URL-decoded string. Six of those
strings are then placed into a printf-style template with `snprintf()`, and the resulting string is handed
to `system()`. The template is:

`/usr/local/bin/test_ldc -F %d -R %d -m %s -h %s -v -C %sx%s -z %s/%s -f /tmp/ldc/ldc >> /tmp/ldc/ldc_config &`

The six `%s` specifiers are the parameters `mode`, `pano_h_fov`, `X`, `Y`, `zoom_num` and `zoom_denum`;
none of them is quoted, escaped or filtered before interpolation. Because `system()` executes its argument
through `/bin/sh -c`, every byte of those six values is parsed a second time, by a shell, in a context the
CGI never modeled. That second parse is the vulnerability. A semicolon ends the intended `test_ldc`
invocation and starts a new command, and a `$( )` sequence performs command substitution before the
intended command ever runs. No sanitization function sits between the parameter read and the shell hand-off.

The authentication boundary is real and it is stated plainly: the CGI is reachable only after the camera's
web server, a GoAhead build using Basic/Digest authentication, has accepted a session, and the research
record describes that gate as fail-closed and enforced before CGI dispatch. This is therefore an
authenticated finding - an attacker must already hold a valid web session against the camera's management
interface - and it is not a pre-authentication defect. The record also notes that shipped default
credentials may exist on some deployments and treats them as a separate, distinct issue class rather than
as part of this chain; default credentials were not used as the vector here, and no credential change
remediates this defect.

One verification boundary must be read with the rest of this advisory, and it is repeated in section 9 of
the analysis. No physical GDS371x device was driven during verification and no request was fired at
production hardware. The dynamic evidence is a sink-level replication: the exact `snprintf()`-to-`system()`
pattern, the six-`%s` template and the shell hand-off were reimplemented in C and compiled natively with gcc
on an isolated cloud-hosted x86-64 Ubuntu host, then executed there. The two injected vectors each created
a marker file, and the identity those markers captured was `uid=0(root) gid=0(root) groups=0(root)`. A
benign control input of `1` in every parameter created no marker. Root was therefore observed inside that
replication environment, by a process the replica operator ran as root in order to mirror a root-run CGI,
and not on a camera. The device-side identity is asserted by the research record's own classification of
the finding as authenticated root remote code execution; it was not measured on hardware. That distinction
is not a hedge on the defect - the injectivity of the sink is what the replication proves, and it proves it
completely - but it is the honest boundary of the evidence, and every claim in this package stays inside it.

The surface is narrow and the finding is independent. The research record states that the format string
appears only in `ldc.cgi` among the CGI binaries shipped on the GDS371x; that the `gs_cpe` TR-069 daemon's
sinks all use fixed commands rather than interpolated input; and that `device_service` executes through an
argument vector rather than a shell. The record further states that the public vulnerability record carries
no entry for an `ldc.cgi` command injection on the GDS371x and that the vendor's published CVE history
concentrates on a different product line, the GXP series of phones. No identifier has been assigned to this
issue. Nothing in this advisory is a repackage of a public finding: the endpoint, the parameter set, the
format string and the sink are all documented here from the firmware image's own binary.

- Component: `/webSvr/web/cgi-bin/ldc.cgi` in Grandstream GDS371x firmware 1.0.13.10 (4,892-byte stripped
  ARM EABI5 ELF, uClibc and libclearsilver), reached as `GET /cgi-bin/ldc.cgi` after web-server
  authentication
- Source: six HTTP query parameters - `mode`, `pano_h_fov`, `X`, `Y`, `zoom_num`, `zoom_denum` - read
  through `hdf_get_value()` as raw URL-decoded strings
- Sink: `system()` on a command line assembled with `snprintf()` from a fixed template that carries six
  unquoted `%s` specifiers, executed through `/bin/sh -c`
- Breakout: `;` for statement separation and `$()` for command substitution, both accepted because the
  template interpolates raw bytes
- Boundary: authenticated (a valid web session against the camera's management interface); not
  pre-authentication, and unaffected by credential rotation
- Observed identity: `uid=0(root) gid=0(root) groups=0(root)` in marker files produced inside the
  sink-level replication, not on a camera
- Classification: CWE-78, OS command injection; no CVE identifier assigned

## CVSS Score

- Score: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2 (High)
- Attack Vector: Network - the vulnerable component is the camera's HTTP management interface, and the
  research record poses the request as an ordinary HTTP GET against the device over the network
- Attack Complexity: Low - a single authenticated request carrying the payload in one query parameter is
  the entire detonation; there is no race, no heap groom, no multi-step state machine and no configuration
  prerequisite beyond an authenticated session
- Privileges Required: High - the CGI sits behind the camera's web-server authentication, which the record
  describes as enforced before dispatch and fail-closed; a valid administrative web session is the
  precondition for the request to reach `ldc.cgi` at all
- User Interaction: None - the credential holder issues the request directly; no second party is involved
- Scope: Unchanged - the injected command executes inside the camera, within the authority of the
  component whose interface was abused; no crossing into a beyond-device security authority is claimed
- Impact C/I/A: all High - arbitrary command execution in the identity of the CGI process yields the
  device's configuration store and service control, integrity of the same, and availability at will
- Published arithmetic: ISS = 1 - (1-0.56)^3 = 0.914816; Impact = 6.42 x 0.914816 = 5.873119;
  Exploitability = 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708; sum 7.107827, rounded up to 7.2

Privileges Required is High rather than the neighbouring Medium or Low tier because the evidence places a
real authentication gate in front of the sink and nothing in the research record shows a way around it.
The record's authentication model is explicit: authentication is enforced at the web-server level before
CGI dispatch, the gate fails closed, and the only principal that reaches `ldc.cgi` with a web request is
one holding a valid session on the management interface. CVSS 3.1 reserves PR:H for an attacker who needs
privileges conferring significant control over the vulnerable component, which is precisely an
administrative session on the device being attacked; Low would require a basic user account on the same
component to be sufficient, and no such account tier is documented for this camera's CGI surface. The
score is not softened by the existence of shipped default credentials either: the record classifies those
as a separate weakness with its own CWE, states that they are not this chain's vector, and this advisory
does not rely on them. Reading the gate as absent or as bypassable would be inventing a fact the record
does not contain, so the published vector keeps the gate and prices it at High.

A rejected reading exists and is printed here with its own arithmetic rather than buried, because the
research ledger itself carried it. The record's header states 8.8 with
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, and that vector really does compute 8.8: ISS 1 - (1-0.56)^3
= 0.914816, Impact 6.42 x 0.914816 = 5.873119, Exploitability 8.22 x 0.85 x 0.77 x 0.62 x 0.85 =
2.835255, sum 8.708074, rounded up to 8.8. The arithmetic is correct and the vector is wrong for this
finding: a Low-privileges reading implies an ordinary authenticated account tier sufficient to reach the
sink, and the record's own authentication model documents no such tier - it documents a fail-closed
administrative gate. The 8.8 figure is therefore rejected as a scoring error rather than as an alternative
deployment reading, and it must not be quoted as the headline anywhere. 7.2 High is the published score.

## Affected Products

- Grandstream GDS371x camera firmware 1.0.13.10 - the image analyzed end to end at binary level in this
  research. Affected component: `/webSvr/web/cgi-bin/ldc.cgi`, a 4,892-byte stripped 32-bit ARM EABI5 ELF
  linked against uClibc and libclearsilver, invoked as `GET /cgi-bin/ldc.cgi` behind the camera's
  authenticated web interface
- The vulnerable construction is the six-specifier command template handed to `system()`; any build that
  carries the same template is affected by the same mechanism, and this advisory does not by inference
  extend the claim to builds that were not examined
- Not claimed: firmware versions other than 1.0.13.10; GDS371x hardware revisions other than the image
  analyzed; other Grandstream product families; any unauthenticated reach of the CGI; and any execution
  path through the device's TR-069 or `device_service` components, which the record describes as not
  shell-injectable
- Verification method and its boundary: the request path, the parameter extraction, the format string and
  the three `system()` callsites are established from the firmware image's binary; the injection behaviour
  at the sink is established by a sink-level replication compiled and run on an isolated cloud-hosted
  x86-64 host. No camera was driven during verification, so the device-side runtime identity is stated as
  the record's classification rather than as a measurement, and the `uid=0(root)` markers are evidence
  gathered inside the replication environment
- Privilege ceiling: arbitrary command execution with the identity of the CGI process. The record
  classifies that identity as root on the device; the measured marker in the replication is root because
  the replica was deliberately run as root to mirror a root-run web stack. Not reached and not claimed:
  memory corruption, persistence across a factory reset or firmware reflash, and control of attached
  physical access-control hardware

## Impact

- Complete loss of the management/OS boundary on the camera for a party who holds a legitimate web
  session: the LDC tuning interface becomes an arbitrary-command channel in the identity of the CGI
  process, which the record classifies as root
- Exposure of the device's configuration store and any material the device keeps in its readable
  filesystem at that identity, which on an access-control product includes the credentials and service
  configuration the device holds for its own operation
- Integrity loss across the device's own configuration and services: an attacker at that identity can
  alter what the device reports and how it behaves, and the change is indistinguishable in product terms
  from ordinary administrative tuning
- Availability impact at will, both coarse (process and service control from the shell) and surgical
  (the LDC working files under `/tmp/ldc` are writable from the same identity)
- Persistence consistent with root command execution on an embedded Linux system, up to the limits of the
  device's writable filesystem; what survives a factory reset or reflash was not tested and is not claimed
- The chain is quiet in network terms: one authenticated request inside a legitimate administrative
  action, with no exploit payload visible in a response body and no crash required
- Physical access-control consequences were not tested and are not claimed; the finding is stated at the
  level of device operating-system authority, which is where the evidence ends

## Mitigation / Fix Recommendations

1. Constrain every parameter that reaches the template to the shape the helper actually consumes: `mode`
   to a fixed enumeration, and `pano_h_fov`, `X`, `Y`, `zoom_num`, `zoom_denum` to bounded decimal
   integers with explicit range checks, rejecting anything else before the value is used. Numeric
   allowlisting removes the entire metacharacter class rather than chasing individual characters
2. Stop assembling shell command lines at all: invoke `/usr/local/bin/test_ldc` with an `execve()`-family
   call and an argument vector, so no shell ever parses the parameter values. This is the only fix that
   closes the class on this surface, because the defect is the second parse, not any single character
3. If the shell must stay in the path short-term, pass every interpolated value through single-quoted
   expansion with literal single-quote escaping, and assert after construction that the compiled command
   contains no `$`, `;`, backtick or newline
4. Run the web server and its CGI children under a dedicated unprivileged identity. This does not fix the
   injection, but it caps the blast radius of this and every future web-plane defect on the device
5. Sweep the remaining CGI binaries for the same pattern - `hdf_get_value()` feeding `snprintf()` feeding
   `system()` or `popen()` - and treat every hit as the same class of defect; the record's own assessment found
   the template only in `ldc.cgi`, which is where the fix must start, not where it must end
6. Add a regression test at the CGI level: submit each of the six parameters with `;id`, `$(id)` and a
   backtick form, and assert that the request is rejected or that no command runs; run the same test on
   every firmware build that ships the binary
7. Until a patch exists, operators should treat the camera's web credential as the full-authority secret
   it is, keep the management interface off untrusted network segments, and disable unused management
   features where the deployment permits

## References

- https://0day-rubbish.com/blog/ldc-cgi-command-injection-root-rce
- https://github.com/Exploit-Garbage/0day-Rubbish
- https://cwe.mitre.org/data/definitions/78.html
- https://www.first.org/cvss/v3.1/specification-document
- disclosure@0day-rubbish.com

---
Written by the 0day Rubbish Research Team.
