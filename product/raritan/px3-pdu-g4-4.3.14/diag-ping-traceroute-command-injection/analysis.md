# Raritan PX3 PDU G4 (firmware 4.3.14) — Command Injection in the Diagnostics Ping and TraceRoute Handlers through an Inverted Hostname-Validation Return Check (any authenticated session; execution in the web service context; on-device identity not measured and not claimed)

## 1. Overview

### Overview of the finding and the product

The Raritan PX3 PDU G4 is an intelligent rack power distribution unit from Raritan, a Legrand company in
the United States: per-outlet power metering and switching, environmental sensing, and remote
management over an HTTPS web interface, a role-based CLI (clish), a large JSON/IDL-RPC API surface, and
a Redfish implementation. The firmware studied here is version 4.3.14, an aarch64 embedded Linux image
whose web tier is a custom 1.8 MB C++ daemon, /bin/httpd, built on an IDL-RPC framework: an
authentication subsystem referred to throughout the binary as pp::aaa, a JSON-RPC name service, and
generated service bindings. Seventy-five service namespaces are reachable over the API path, all
behind per-method authentication.

The diagnostics service lives in that API space and in the CLI. Its ping and traceroute
implementations are not socket-level implementations: they assemble a shell command string from the
operator-supplied hostname and execute it through /bin/sh, and recovering those implementations from
/lib/libisys.so.1.0 shows the hazard immediately - the string constants in the neighbourhood read
"ping", "ping6", "traceroute", "traceroute6", "2>&1", "/bin/sh" and a source file name
"DiagnosticsImpl.cpp" - and the assembled template is ping -c <count> -W <timeout> <HOST> 2>&1, with
<traceroute variants built the same way.

A hostname validation function is called before the command is assembled, and that function is not a
stub: it walks the hostname character by character, explicitly rejects the percent sign and every
character above the ASCII colon, cross-checks that the hostname resolves through the resolver service,
and on every one of its rejection outcomes returns the same constant, three. The defect is one
comparison away, in the caller: ping checks the validation result with a branch that fires only on a
strictly greater value, so a return of three - the function's rejection verdict - passes through, and
the rejected hostname is spliced into the shell template verbatim. The traceroute implementation calls
the same function with the same inverted comparison. One further binary-level fact completes the
picture: the image contains a strict fully-qualified-hostname validator in libnetwork.so, but the web
daemon does not import it and the diagnostics library neither links nor loads it on this code path.

The consequence is an OS command injection (CWE-78) whose success condition is the validator working
exactly as designed: the payload must be one the validator rejects (a semicolon is caught by the
character loop; a dollar or parenthesis survives the loop but fails resolution), because every
rejected hostname - and only rejected hostnames with the return value three - proceeds into the shell
command.

The verification behind this advisory is layered, and its boundary is stated precisely in section 9:
the full root-cause chain is measured statically at instruction level from the firmware image - every
address cited in this advisory is an image address - and the recovered command templates' sink
semantics were confirmed in a command-level replication in which all three injection shapes executed
a marker command under a shell while a metacharacter-free control run did not. No end-to-end
exploitation through a live management interface was performed, because no physical unit was
available to this work and full-system emulation of the management stack is blocked by its hardware
storage dependency; appliance-side execution identity was therefore not measured and is not claimed.
The shipped default credential for first-boot administrative access, recorded in the image's
configuration default area, is disclosed as a separate adjacent weakness that compounds this finding
in unconfigured deployments - it is not this finding's vector, and the published vector scores the
finding with an ordinary authenticated session.

### Overview of the public-record position

A four-axis keyword retrieval against the public vulnerability record (vendor axis, vendor plus
product, product, and product plus injected function) was completed before drafting; all queries
returned successfully. The vendor axis returns five records, none in this product line: an
authentication bypass in the earlier PX line of rack PDUs, structured-query injection findings in the
vendor's separate Power IQ management product, an XML external entity issue in a CommandCenter
management product, a denial-of-service in a Dominion KX switch, and a world-readable-configuration
finding in a Dominion SX console server. The product axis ("PX3") returns one unrelated consumer
product; the vendor-plus-product and the function axes ("Raritan ping", "Raritan traceroute", "pdu
ping command injection") return nothing that names this diagnostics path. Keyword semantics were
accounted for: multi-word queries intersect over record text, so zero-result phrase queries were
re-checked against the vendor term alone, which yields the union reported above. The precise statement
this advisory makes is therefore: the public record contains no entry for the PX3 PDU G4 line and no
entry naming the ping or traceroute diagnostics path of any Raritan product; the vendor has
prior records, but in other product lines and on unrelated components, and this finding has no
prior-public precedent in its own segment.

## 2. Vulnerability Summary

The root cause is a returned-verdict consumed with the wrong comparison.

The validation function's contract, recovered in full at 0x5a3f4, has exactly two success outcomes -
a resolver-confirmed IPv4 target and a resolver-confirmed IPv6 target - and one rejection outcome, the
constant three, shared by every failure path: the character loop's explicit percent rejection, the
character loop's above-colon rejection, and the resolution-failure exit. The rejection block
converges at 0x5a530 (the load of the constant) and returns at 0x5a54c.

The consumers, recovered at 0x5a988 (ping) and 0x5ab64 (traceroute), evaluate that verdict with an
unsigned strictly-greater branch. Anything that is not strictly greater than the rejection constant
continues into command assembly. Since the only values the validator ever produces are the two
success returns (below the comparison value) and the rejection constant itself, the branch
executes on every response of the validator except the ones it can never produce, and in particular
executes on the rejection verdict. The shell template receives the raw host parameter; /bin/sh
interprets the result.

Two properties make this finding more than a singular slip. First, both diagnostics handlers share the
same validator and the same inverted comparison shape, so one defect arms two remote entry points.
Second, the accepted-through-rejection path is paradoxically the easiest one to reach: hosts that
would validate successfully (plain literals) pass through normally; hosts that are rejected - which
includes every shell-metacharacter-bearing string - are exactly the ones the current code executes
on.

## 3. Authentication Boundary

The web API is authenticated per method through the framework's pp::aaa subsystem: every service
namespace reachable through the management interface, including the diagnostics namespace, requires
an established session, and no bypass of that boundary was measured or is claimed.

The privilege level within the authenticated population is the load-bearing artifact. The shipped CLI
configuration /etc/clish/netdiag.xml defines the two diagnostics commands and their neighbours:

```
ping         (no access attribute)
traceroute   (no access attribute)
netstat      access="admin"
```

In this framework's CLI grammar, an omitted access attribute means the command is available to every
authenticated CLI user, while the explicit admin marker restricts the neighbouring network-status
command to the administrator level. The vendor's own shipped artifact therefore documents that these
two functions were deliberately placed in the all-authenticated-users class - presumably on the
theory that a ping is harmless - and not in the admin-only class with netstat. That placement is the
published-vector privilege level: an ordinary authenticated user reaches the injector, and no
administrator credential is required.

The boundary is completed by disclosing the adjacent weakness that lives on it: the image's
configuration default area records a factory administrative credential pair for first-boot access.
Where an operator never changes it, a network attacker who knows the documentation-grade value holds
an authenticated session and the distinction between this finding's authenticated class and an
unauthenticated one collapses in practice. That is a separate defect with a separate fix (forced
first-login change or per-unit random shipping credentials); it is disclosed here, scored as a
conditional reading, and excluded from the published vector.

## 4. Attack Surface

### Surface inventory

The product's remote-management surfaces, in the order an attacker considers them:

- the HTTPS web interface served by /bin/httpd, whose request handling is the IDL-RPC dispatch: more
  than seventy-five JSON-RPC service namespaces, all authenticated per method, including the
  net.Diagnostics namespace carrying ping and traceroute;
- the CLI (clish), whose command definitions ship as XML in the image - the netdiag command set
  among them - and instantiate the same underlying isys service calls with the same arguments;
- Redfish, the DMTF REST profile, on the same listener;
- the CGI area: fewer than thirty POSIX shell scripts, of which the login-related ones are the only
  unauthenticated members.

The diagnostics surface is where this finding lives. One hostname parameter - typed identically by
an operator over the CLI or by an RPC client over the API - is the entire attack input.

### Why the input reaches a shell

The implementation layer is /lib/libisys.so.1.0, the system-services library backing the diagnostics
namespace. Its ping implementation constructs an output-stream command whose template carries the
count and timeout arguments as values and the host argument verbatim; the string assignments visible
in the binary are the ping and traceroute template pieces, both IP-version variants, the 2>&1 merge
suffix that guarantees command output is capturable, and the shell path. The command therefore
round-trips through /bin/sh by construction, not by accident: capturing the merged diagnostic output
for return through the RPC response is part of the design, and the mechanism chosen for it is a
shell.

## 5. Sink Identification

The sink chain, recovered from /lib/libisys.so.1.0 at image addresses:

- isys::net::diag::ping at 0x5a988 assembles the command string through a std::ostringstream using
  the template ping -c <count> -W <timeout> <HOST> 2>&1 (with the IPv6 variant selected by the
  validator's IPv6 success return);
- ping hands the assembled string to runShellCommandAndGetResults() at 0x36094, which logs the
  command ("Running shell command '%s'", at 0x5c91b) and opens the process;
- the process open is pp::BackgroundCommand::open(bgCmd, "/bin/sh", argv) at 0x36170 - the recovered
  argv carries the command with the -c convention, and the "/bin/sh" string sits at 0x5c967;
- the traceroute sibling isys::net::diag::traceRoute at 0x5ab64 calls the shared validator at
  0x5abd0 with the same inverted comparison, assembles
  traceroute -w <timeout> -m 30 <HOST> 2>&1 (and the IPv6 variant) and reaches the same sink.

The string-table evidence corroborates the code path: "ping" at 0x5f2d5, "ping6" at 0x5f2ce,
"traceroute" at 0x5f2fb, "traceroute6" at 0x5f2ed, "2>&1" at 0x5f2e7, and the diagnostics source file
name "DiagnosticsImpl.cpp" at 0x5c953 - the implementation is where the template lives, and the
template is a shell invocation.

## 6. Source Identification

The source is the host parameter of the two net.Diagnostics RPC methods and the hostname command
line argument of the corresponding CLI commands. In the RPC shape:

```
{
  "jsonrpc": "2.0",
  "method": "net.Diagnostics.ping",
  "params": {
    "host": "<attacker string>",
    "count": 1,
    "timeout": 1
  },
  "id": 2
}
```

The attacker string travels as one opaque parameter from the RPC deserializer (or the CLI argument
parser) into the validator, and - if rejected, which is the finding's success path - out the other
side into the command template verbatim. No other request data is consulted by the vulnerable
handlers: count and timeout are consumed as numeric values, and the dispatch layer's other fields do
not reach the command string.

## 7. Data Flow

The end-to-end flow of an exploitation string:

```
authenticated session
  |
  | net.Diagnostics.ping host = "1.1.1.1;id>/tmp/marker;#"
  v
IDL-RPC dispatch -> DiagnosticsImpl::ping(host, count, timeout)
  |
  v
validateAndResolveHostName(host)
  |   ';' = ASCII 0x3b > ':'  -> character loop rejects -> return 3
  |   variants: '$' 0x24 / '(' 0x28 survive the loop,
  |             then fail name resolution      -> return 3
  v
caller check (unsigned strictly-greater branch)
  |   return 3 is not > 3  -> fall through  <-- the inverted verdict
  v
assemble "ping -c 1 -W 1 1.1.1.1;id>/tmp/marker;# 2>&1"
  |
  v
runShellCommandAndGetResults -> /bin/sh -c <template>
  |
  v
shell executes: ping of 1.1.1.1, then the injected id command
  |             merged stdout+stderr captured by "2>&1"
  v
command output returned through the diagnostics response to the session
```

The 2>&1 suffix is worth naming in the flow because it is an amplifier an attacker inherits for
free: whatever the injected command prints on either stream is captured by the same mechanism that
returns ping's output, so the response channel doubles as the command-output channel, no
out-of-band exfiltration needed.

The rejection coverage of the character loop, for accuracy: the loop reads each byte, accepts
alphanumerics, returns three on the percent sign, returns three on any byte whose value exceeds the
ASCII colon (which covers semicolon, vertical bar, backtick, greater-than, and everything above),
and lets everything else through to the resolver check. The table of practical injection shapes:
the semicolon is caught by the loop before the resolver sees it; dollar, parenthesis, newline, space,
ampersand, exclamation and hash are individually below the loop's threshold, fail the resolver, and
take the same return-three exit. All of them - caught or unresolved - flow into the command template.
The injected leading literal address keeps the surrounding ping invocation valid so the assembled
line parses cleanly into three shell statements, and the trailing hash comments out the template's
2>&1 remainder.

## 8. Exploit Construction

The construction is deliberately minimal: one authenticated request containing a rejected hostname
whose rejected form is a three-statement shell line.

Payload grammar (semicolon family): host = 1.1.1.1;uid>/tmp/ping_marker_$$;# - the leading literal
target keeps the ping segment syntactically complete, the middle segment writes a single marker
command's output to a transient file, and the trailing hash isolates the injected statement from the
template's merge suffix. The response's own ping segment may succeed or fail; the marker is the
success oracle because it exists only if a second process command ran.

Alternative shapes that ride rejection the same way (all reproduced at sink level, section 9):

- subshell family: host = $(id>/tmp/sub_marker) - survives the character loop dollar-first, fails
  resolution, returns three, executes its substitution inside the command line;
- newline family: host = 1.1.1.1 followed by a newline and a marker command - splits the shell line
  into statements without any above-colon byte in the first line;
- traceroute variant: identical grammar, opposite handler - the traceroute template reaches the same
  sink, arming the second entry point.

Response consumption: the marker can simply be read back with a second diagnostics call whose
injected statements copy the marker into the management web tree, after which one GET fetches it;
alternatively, printed material rides the merged-output capture back inside the diagnostics response
itself. Both consumption routes were considered; the second is preferred operationally because it
keeps the whole exchange inside the authenticated channel.

Script form: the exploit script in the exploit directory implements the request against an explicit
target with explicit credentials or a pre-established session token, a configurable command, and
explicit timeouts; it attempts the two candidate session-establishment routes observed in this
framework generation's front ends and degrades to a supplied token, and it embeds no addresses,
credentials or state of our verification environment.

## 9. Dynamic Verification

### What was measured, and where

The static chain was verified at instruction level from the firmware image: the validator's loop, its
convergence on the rejection constant and the two consumers' compare-and-branch sequences were
recovered and read as cited in sections 2 through 7, and the two import facts (the daemon's absent
import of the strict name validator; the diagnostics library's absent dependency on it) were taken
from the binaries' own tables.

The dynamic layer is a command-level replication of the recovered sink semantics on an isolated
research host - not a full-system emulation, and not a live management interface:

```
shell executes the recovered template with each payload shape:
  "ping -c 1 -W 1 1.1.1.1;id>/tmp/marker;# 2>&1"     -> marker written
  "ping -c 1 -W 1 $(id>/tmp/marker) 2>&1"           -> marker written
  "traceroute -w 1 -m 30 1.1.1.1;id>/tmp/marker;# 2>&1"
                                                    -> marker written
  control: "ping -c 1 -W 1 8.8.8.8 2>&1"            -> no marker
  control: listing of the marker path                -> absent
```

All three injection shapes produced the marker command's output; the metacharacter-free control
produced nothing and the marker file was confirmed absent after it. In that environment the invoking
shell ran under the research host's privileged account, so the marker read that account back. That
measurement demonstrates that a rejected host string passing through the consumer arrives at a real
shell that a real injected command can drive; it is a property of the replication environment and is
reported as such.

### What was not measured, and what that means for the claims

Full end-to-end exploitation through the management interface - a live unit's HTTPS listener serving
the RPC dispatch, the pp::aaa session, and the isys service in its real process - was not performed.
Full-system emulation was not undertaken because the management daemon's startup chain depends on
the configuration daemon and the flash storage layer, which image-only extraction does not
reproduce; no emulatable system disk was available from the firmware, and no physical unit was
available to this work. Two consequences are drawn honestly:

- appliance-side execution identity (the account the web daemon runs as on a deployed unit) was not
  observed, and no superuser claim is made about it anywhere in this advisory;
- the privilege the executed command carries on a unit is bounded by that unobserved daemon
  identity, so the published impact statements are written against "the web service's account,
  whichever it is", and the conditional readings in section 12 exist to bound the score the same
  way.
What is carried from the replication to the finding is the sink semantics: the rejection-returning
path, evaluated through the recovered consumer logic, terminates in a genuine shell interpretation of
the template with the raw host embedded.

## 10. Reachability and Security Impact

### Reachability

Management of a rack PDU is a network service at a datacenter's softest point: the unit is
deliberately reachable for operations automation and monitoring collection, sits in a position of
physical leverage over an entire rack, and its web tier (on the standard management port) exposes the
diagnostics namespace to every authenticated principal. Because the CLI artifact places the two
commands in the all-authenticated class, the finding's effective audience is not merely the
administrator: every monitoring account, every operations automation role, every integration
credential granted "just to poll" is sufficient.

### Impact claimed

- One request converts a diagnostic-privileged session into command execution, with command output
  returned through the same response channel (the merge suffix makes the channel carry both
  streams).
- The web-service context's read reach includes the product's configuration and state stores, and
  an attacker holding it can enumerate further targets at leisure - each enumeration step being yet
  another legal diagnostics call.
- Availability of the fed rack follows from the service context: the injected command executes in
  the daemon that hosts the outlet control surface, so powering outlets - hard-stopping every machine
  behind them - is an inference directly from the product's own function; it is labelled as an
  inference, not a measurement, because only the sink level was measured.
- Re-entry is unlimited: both namespaced methods accept arbitrary repetition with new host strings,
  so staging and cleanup cost one request each, and no resident payload is required.

### Impact not claimed

- Superuser execution on a unit (identity unmeasured, section 9);
- persistence within the product;
- any crossing out of the unit's management context (network pivot);
- abuse of the factory default credential as part of this finding's score (adjacent weakness,
  disclosed separately, and present as a conditional reading only).

## 11. Fix Recommendations

1. Reimplement both diagnostics through non-shell mechanisms: a ping library, raw sockets, or an
   argv-array process spawn with the host passed as a single argument to the binary - no shell
   anywhere between the RPC parameter and the socket.
2. Correct the verdict consumption first, as the smallest change with the largest immediate effect:
   accept only the documented success returns and reject everything else - in particular the
   rejection constant itself - before any command text exists to assemble.
3. Centralize hostname admission for both entry channels on a literal-or-strict-name allow-list that
   runs before dispatch to any implementation, and make the strict fully-qualified-name validator
   already present in the image part of that admission.
4. Audit every other consumer of the shared validation function for the same strictly-greater
   consumption of the rejection constant; the constant is shared and the comparison shape is
   copyable.
5. Remove the factory default credential from the image and force a first-login change (or ship
   per-unit random values), closing the disclosed adjacent weakness and the conditional
   unauthenticated chain it creates.
6. Add injection regression suites for both channels covering the full character-class table
   exercised here - above-colon metacharacters, low-value metacharacters that fail resolution,
   newlines, percent encoding, whitespace and mixed forms - asserting no process spawn and
   template-only responses.
7. Make the shell-template log line an alertable event: the product already logs the assembled
   command verbatim, so a policy rule "diagnostics shell line whose host segment is not a literal
   or strict name" converts the product's own telemetry into detection.
8. For operators until firmware is fixed: change the factory default immediately; restrict the
   management interface to the operations network; prefer account classes whose monitoring role does
   not need diagnostics; review shell-command logs for the two templates.

## 12. CWE and CVSS

### CWE classification

CWE-78 (Improper Neutralization of Special Elements used in an OS Command, OS command injection) is
primary: a shell interprets the attacker's parameter. CWE-20 (Improper Input Validation) is co-equal
here in a precise sense: the finding is not the absence of validation - the validator exists,
runs, and reaches correct verdicts, including for the semicolon - but the discarding of the verdict
by its consumer, which is the validation failure that matters. The adjacent default-credential
weakness is of the CWE-798 class (hard-coded / shipped default credential) and is explicitly not
folded into this advisory's scoring.

### CVSS with the arithmetic shown

Published vector, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High:

- ISS = 1 - (1 - 0.56) x (1 - 0.56) x (1 - 0.56) = 1 - 0.44 x 0.44 x 0.44 = 0.914816
- Impact (scope unchanged) = 6.42 x 0.914816 = 5.86911872, carried as 5.869119
- Exploitability = 8.22 x 0.85 (AV:N) x 0.77 (AC:L) x 0.62 (PR:L) x 0.85 (UI:N) = 2.835255
- Base = 5.869119 + 2.835255 = 8.704374, roundup to the tenth = 8.8

The 8.8 recorded in the source notes against the same vector was re-derived and stands; the
project's known recorded-error patterns (a high-privilege vector recorded at 8.8, or a
no-authentication scope-changed vector recorded at 9.8) were explicitly checked against and do not
occur here.

Rejected reading: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical (Impact 5.869119 +
Exploitability 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043, sum 9.756162 rounded to 9.8). Rejected
as the published score: the methods sit behind per-method authentication and no bypass of it was
measured, so the finding does not itself confer an unauthenticated primitive.

Conditional reading A (deployment with the factory default account unchanged): the same vector
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical applies to the chain of the adjacent
default-credential weakness plus this injection, because a network attacker who uses the
documentation-grade factory value holds an authenticated session by the same mechanism a legitimate
operator does. Conditional because removing the shipped default removes it; never the headline; and
not part of the finding itself.

Conditional reading B (deployment whose only accounts are administrative): the shipped CLI ACL
grants diagnostics to all authenticated users, but a closed shop can exist where no such account is
provisioned. For those deployments `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 High
(Exploitability 8.22 x 0.85 x 0.77 x 0.27 x 0.85 = 1.234708, plus 5.869119, total 7.103826 rounded
to 7.2).
