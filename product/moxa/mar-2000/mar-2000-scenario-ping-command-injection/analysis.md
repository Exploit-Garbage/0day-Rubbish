# Moxa MAR-2000 — Scenario Ping Condition Injection: an Unvalidated Monitoring Field Reaches a Shell-Interpreted, Self-Scheduled Ping Thread

## 1. Overview

### Overview — the finding

Moxa, an industrial networking vendor in Taiwan, ships the MAR-2000 series industrial
4G/LTE cellular router with a scenario facility: an administrator names monitoring
conditions, saves them through the management API, and the device evaluates them on its
own schedule - a connectivity check being the canonical example, expressed as a condition
of type `ping`. This advisory documents the finding in that facility: the thread that
implements the ping condition assembles its command line from the condition's saved
parameter values, executes it through a shell, and neither the write path that stores
those values nor the thread that consumes them ever inspects what they hold.

The Scenario model at `/home/model/scenario/scenario.py` evaluates saved conditions
periodically. A saved ping condition carries a `parameter` object with `ip` (required),
`interface` (defaulting to `eth0`) and `times` values. When the watchdog reaches a
ping-type condition it starts a `PingThread`, whose `run()` method builds the command as
`"ping %s -c 1 -w 5 -I %s "` - the stored `ip` first, a `-c 1` single-count, a `-w 5`
answer window, the `interface` last - and passes it to
`subprocess.Popen(..., shell=True, stdout=PIPE, stderr=PIPE)`. The values got there
through `PUT /api/v1/scenario`, where the model's put handler validates only that the
submitted `data` object exists and is non-empty; no parameter value is examined
at any layer of the stack - not by the Express middleware, not by express-sanji's
translation, not on the broker leg, not at storage, and not when the thread reads the
condition back. An administrator who saves a condition with `parameter.ip` equal to
`$(<command>)` has therefore written a command that the product will execute by itself:
the shell expands the subshell during command expansion - before the `ping` binary is
even started - and the injected statement's output is gathered by the product's own
pipes.

Two properties set this finding apart from the product's other two documented injections,
and they are worth naming early because they are the substance of the risk. The delivery
is self-scheduled: no activation request, no tunnel-apply occasion and no second attacker
request is needed; the watchdog runs the condition because running conditions is its job.
And the payload recurs: the saved condition is re-evaluated on the product's schedule, so
a stored payload executes again at every cycle until the condition is deleted, which makes
this the closest thing to a scheduled-execution primitive the management plane offers.

The finding also carries an unusual payload-engineering lesson, established by the
research record and reported honestly: the naive semicolon form does not fit this
template. Because the template puts the stored `ip` before the `-c 1 -w 5 -I` flags, a
value of `1.1.1.1; <command>; #` makes the shell run `ping 1.1.1.1` without any count
limit, and that unbounded ping blocks the evaluating thread until it is torn down - in the
replication record, the marker never appeared and the thread had to be terminated. The
two forms that work are a command substitution (the subshell executes during expansion,
before the `ping` binary starts) and a newline separator (the ping keeps its flags and the
injected text runs as a second command line). Section 8 develops this; it is the reason
the shipped proof of concept uses the substitution form.

### Overview — the product and its runtime stack

The artefact characterised is firmware `FWR_MAR2000_V1.0_Build_15010909` for the
MAR-2000 series industrial 4G/LTE cellular router, which extracts to an ARM Debian 6.0.8
root filesystem running the MIRF (Mobile Intelligent Routing Framework) stack. The
management plane, as established from the firmware's own application files, is an
Express 4.0 application listening on port 80 with the binding covering every interface;
the express-sanji middleware translates each REST resource into a message on a local MQTT
broker at localhost:1883; and Python 2.6 model daemons under `/home/model/` persist the
configuration and perform what it describes.

Authentication lives entirely at the HTTP layer: the `validateUser` middleware requires a
server-side session for non-GET methods, and login is `POST /api/login` compared against
bcrypt-hashed entries in the SQLite user table. Two adjacent properties are noted for
context and kept out of this chain: the broker accepts unauthenticated publishes, and
every `GET` across `/api/v1/*` is answered without a session. Neither is needed for this
finding.

### Overview — the evidence base and its boundary

As with the sibling advisories, two evidence classes carry this one, labelled wherever
used. The first is the firmware's application source: the scenario model file, its REST
resource, the put handler's validation scope, the condition storage shape and the
PingThread construction quoted in section 5 - structural evidence about shipped software,
complete for the claims about what the product does with the field. The second is
sink-level replication: the exact `run()` construction - the `"ping %s -c 1 -w 5 -I %s "`
template with the value in the leading position, launched through `shell=True` with both
pipes captured - was re-implemented and executed on an isolated cloud Linux sandbox under
a subshell payload, a newline payload, the naive semicolon payload and a benign control;
section 9 quotes all four results. The replications establish the shell behaviour of the
construction, which payload forms fit it and which do not; they do not drive a live
device's watchdog, do not measure its evaluation interval end to end, and do not measure
the on-device process identity - the marker's `uid=0(root)` is the sandbox harness's own
identity, and this advisory claims no device-side privilege.

### Overview — independence: existing records, and how they were searched

Before drafting, the public record was searched over the vulnerability database's keyword
interface along separate axes - the vendor name alone; the vendor name combined with the
product name; the product name alone; and the vendor name combined with the handler
terms naming this finding's entry route (`executer`, `ipsec`, `scenario`). The search we
were able to complete returned two hundred and sixty-eight records under the vendor axis,
describing command-injection and authorisation findings concentrated in the vendor's
other product families; one recent record describes an authorisation weakness in the
vendor's API on other product families, with a different root cause from this finding.
The product axis and the vendor-plus-product axis each returned no record, and the
handler-axis searches returned no record naming this product, this model, or this defect
shape - an unvalidated monitoring-condition parameter evaluated by a scheduled
shell-interpreted ping. No public record was found, in the searches we completed, that
names the MAR-2000 series, its scenario model, or this root cause. The claim is stated
with its boundary: the searches were keyword-based over record description text, and this
advisory claims originality for the finding rather than asserting a universal absence.

This finding is one of three documented for this product and released as a set. It is
independent of the other two on every counting axis: a different model file
(`scenario.py`), a different REST resource (`/api/v1/scenario`), a different configuration
field (the ping condition's `parameter.ip` and `parameter.interface`), a different sink
family (a long-running background thread launched by periodic evaluation rather than a
request-triggered handler), and a different execution occasion (the product's own
schedule), sharing with them only the entry architecture.

## 2. Vulnerability Summary

### Vulnerability Summary — table

| Item | Value established by this research |
|---|---|
| Vendor | Moxa, industrial networking vendor, Taiwan |
| Product | MAR-2000 series industrial 4G/LTE cellular router |
| Firmware | `FWR_MAR2000_V1.0_Build_15010909` |
| Platform | ARM Debian 6.0.8 with the MIRF stack |
| Entry | `PUT /api/v1/scenario` - a `data` object carrying a `condition` array |
| Validation on entry | the put handler checks that `data` exists and is non-empty; no parameter value inspection |
| Sink | `PingThread.run()`'s `subprocess.Popen("ping %s -c 1 -w 5 -I %s ", shell=True, ...)` |
| Delivery | the model's periodic scenario evaluation; no attacker request participates in delivery |
| Storage | the scenario's condition store; payload persists and re-executes per cycle |
| Authentication | administrator session required; factory default pair exists in the shipped user table |
| Verified by | firmware source analysis plus sink-level replication across three payload forms and a control |
| Primary CWE | CWE-78 |
| Published score | 7.2 High - `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary — mechanics in four facts

**One** - the sink exists to serve its owner's monitoring intent, and it serves the
attacker's stored values with the same fidelity. The thread does not know where its
`ip` came from; it builds the command from whatever the condition store gives it, which
is whatever was written through the unvalidated put handler.

**Two** - the write handler's validation is a presence check. The single gate between
the HTTP body and the stored condition is that `data` exists and is non-empty; the
shape of a `parameter` object, let alone the semantics of `ip`, is never examined.

**Three** - delivery belongs to the product. The watchdog evaluates saved scenarios
because that is what the feature is; the attacker's request stores the payload, and the
product schedules its own execution and re-execution. There is deliberately no step
here that requires the attacker to keep a connection, win a race or revisit the device.

**Four** - the template's operand order decides which payloads work. The stored value
precedes `-c 1` and `-w 5`, so a `;` steals the flags from the ping and turns the thread
into a blocked thread; a `$(...)` expands before ping starts; a newline leaves the first
line to the product and gives the attacker the rest. The behaviour was measured, not
intuited, and it is reported in full rather than as a list of successes.

### Vulnerability Summary — preconditions

1. an administrator session on the management application (the credential prerequisite;
   the shipped firmware's default pair collapses it in deployments that never changed
   it - scored separately, never folded in);
2. a payload in the `ip` (or `interface`) field that matches the template's shape - the
   substitution and newline forms qualify, and section 8 explains why;
3. the watchdog's next evaluation of the saved condition - a product-owned schedule,
   not a timing the attacker must beat.

## 3. Authentication Boundary

### Authentication Boundary — what the gate enforces

The `validateUser` middleware requires a server-side session for every non-GET method,
and `PUT /api/v1/scenario` is a mutating request, so the session is required for the
write that stores the payload. Login is `POST /api/login` with a bcrypt-compared pair
from the SQLite user table. Beyond the session check the request enjoys the full reach
of the scenario API: no authorisation layer follows the middleware, no identity rides
the broker leg, and the model itself implements no permission judgement. The product's
management application has one documented role - the device administrator - and that
role is the entire security boundary for this write, exactly as for the product's other
mutating resources.

### Authentication Boundary — the default credential and how it is handled in scoring

The research record documents that the shipped firmware's user table carries a factory
default administrator pair (bcrypt-hashed at rest). This advisory handles it the way
this repository's other industrial-router advisories do: the published vector measures
the vulnerability with the credential prerequisite in place (`PR:H` - the product's
single top role, and the CVSS guide's canonical example of High), and a separate,
labelled conditional reading measures the deployment state where the pair was never
changed. The two figures describe two populations; neither borrows the other's
severity, and the advisory's operational advice follows from the conditional rather
than from the headline.

### Authentication Boundary — adjacent properties not claimed

Three nearby authentication-related observations are not part of this finding, as for
the siblings: the unauthenticated readability of `GET /api/v1/*` (a read-exposure issue
in its own right, and notably one that lets an intruder enumerate saved scenarios
without a session); the broker's absence of authentication (relevant only given another
on-device foothold); and the server-side session store (which is why the hardcoded
cookie-signing secret does not assist this chain). None is scored here.

## 4. Attack Surface

### Attack Surface — listeners and routes

| Surface | Default | Authentication | Role in this chain |
|---|---|---|---|
| Express management application | port 80, all interfaces | session for non-GET methods | entry for the write |
| Scenario resource (`/api/v1/scenario`) | REST | administrator session | payload delivery into the condition store |
| MQTT broker | localhost:1883 | none | internal transport, no gate of its own |
| Scenario model daemon | `/home/model/scenario/scenario.py` | none | evaluates conditions; starts the sink thread |

The web application binds all interfaces on port 80 in the shipped firmware. Whether any
deployment exposes the listener beyond its management network is an operator decision
not field-audited here; the published vector scores the network position of the listener
without assuming WAN exposure, and the conditional reading changes only the privilege
prerequisite.

### Attack Surface — how the surface was read

The surface was mapped from the firmware's application files, as for the siblings: the
Express route registration and middleware order, the express-sanji topic mapping, the
model's put handler, and the thread implementation including its command template and
launch flags. Every quoted artefact - the resource path, the model file path, the
condition and parameter key names, the template text - comes from that reading of
shipped software.

### Attack Surface — what the scenario facility is for

The feature's purpose is exactly what makes this sink load-bearing: a scenario is how an
operator of a communication-infrastructure device automates the behaviour of other
features on a schedule - failover on connectivity loss being the canonical use. The
product intends condition parameters to be data that its own monitoring reacts to, not
shell syntax; the defect is that nothing in the write or evaluation path draws that
line, and the thread's thread-per-condition shape means the injected command lives in
the process that owns the response to the very failure it just caused.

## 5. Sink Identification

### Sink Identification — the construction, quoted from the model

Periodic evaluation of a saved ping condition starts a background thread, whose run
method assembles and executes the command:

```python
class PingThread(threading.Thread):
    def __init__(self, work_info, scenario_id):
        self.ip = work_info["parameter"]["ip"]
        self.interface = work_info["parameter"].get("interface", "eth0")
        self.times = work_info["parameter"].get("times", 3)
        threading.Thread.__init__(self)

    def run(self):
        ip = self.ip
        interface = self.interface
        cmd = "ping %s -c 1 -w 5 -I %s " % (ip, interface)
        process = subprocess.Popen(cmd, shell=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```

Three observations make this a command-injection sink rather than a monitoring feature
that happens to start a binary. The interpolation is textual into a single string handed
to a shell - `shell=True` - where the stored bytes are parsed as command syntax, so a
value such as `127.0.0.1` is one case and a value such as `$(...)` is another. Both
`ip` and `interface` come from the same unvalidated `parameter` object and both sit in
operand positions of the same template, giving two stored fields of one class inside
one condition. And the sink is deliberately detached from the request path: the thread
reads the condition store at evaluation time, not at write time, which is exactly what
gives the stored payload its recurring delivery.

### Sink Identification — where the operand order matters

The template is `"ping %s -c 1 -w 5 -I %s "`. The stored value therefore sits at the
head of the command line, before the flags and before the interface operand. That
ordering has two consequences an exploiter must respect and a reader should
understand. A `;` inside the stored value terminates the `ping` invocation before the
flags are attached, leaving an unbounded ping in the foreground of the thread's shell;
the replication record shows that shape failing to produce the marker inside the tested
time budget, with the thread torn down while the ping still ran. A `$()` or a newline,
by contrast, both preserve or bypass the surrounding invocation: substitution is
expanded by the shell before `ping` execs, and a newline gives the ping its own line
with the flags intact. The consequence for the finding's shape is stated plainly: the
sink is injectable with either verified form, and the naive form that works against the
product's sibling sinks misbehaves against this one.

### Sink Identification — sibling candidates in this model, and their status

The ping condition is the detonated path; a scenario framework built on periodic
evaluation invites the question what else the evaluation reactions reach. Within the
artefacts examined, the ping thread is the documented sink for this model and no other
reaction handler was established by this research record as a distinct sink, so none is
claimed. The scenario store itself is configuration state; the ability to write
arbitrary condition data is only the delivery vehicle for this finding and not scored
independently.

## 6. Source Identification

### Source Identification — the write path and the absence of validation, quoted from the model

The condition data arrives through the scenario resource's put handler, whose validation
scope is the load-bearing fact:

```python
# put(): validates only that "data" exists and is non-empty - then stores the
# condition array as given, including every parameter object's values
```

That is the entire gate. The handler does not enumerate expected condition types, does
not check the `parameter` object's keys, and does not inspect `ip` or `interface` - so
the tainted bytes travel: HTTP body of an authenticated `PUT /api/v1/scenario`, through
express-sanji's translation, through the broker, into the scenario store, and from
there into the thread's constructor the next time the watchdog evaluates the condition.

### Source Identification — the taint summary

- tainted parameter: a saved ping condition's `parameter.ip` (and `parameter.interface`);
- transport: the authenticated REST write; message translation onto the broker; storage
  in the scenario store;
- sink reach: read by `PingThread.__init__` at evaluation, held on the thread object,
  interpolated by `run()` into the ping template, shell-executed.

Sanitisation on this path is none, in any layer. The single check on the write side is
the handler's existence-and-non-emptiness test, and the read side - the thread - treats
the stored object as trusted state, which it is not, because the product's API is not
the only writer's model of validity it should trust. The stored condition also
persists, which turns the absence of validation into a recurring absence.

## 7. Data Flow

### Data Flow — end to end

```
[1] attacker logs in
    POST /api/login  {username, password}
    --> server-side session; validateUser admits mutations

[2] attacker saves a scenario with a poisoned ping condition
    PUT /api/v1/scenario
        {"data": {"condition": [{
            "name": "connectivity_check",
            "type": "ping",
            "parameter": {
                "ip": "$(id > <marker>)",
                "interface": "eth0",
                "times": 3
            }}]}}
    --> put handler: data exists, non-empty - stored verbatim

[3] scenario watchdog evaluates saved conditions on its schedule
    condition type "ping" --> PingThread started with the stored parameters

[4] shell semantics in the thread
    cmd = "ping $(id > <marker>) -c 1 -w 5 -I eth0 "
    subprocess.Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    --> the shell expands $( ...) during command expansion
        - the injected command runs, its output is not even needed by the
          attacker, the marker carries the proof
        - ping then execs with an empty host and exits quickly
    --> thread returns to the pool; the condition re-evaluates next cycle
```

### Data Flow — properties worth naming

The chain has exactly one attacker request. The attestation of delivery - that the
command actually ran - is produced by the payload's own side effect, because the
template's pipes carry the ping output back to the product, not to the attacker. The
delivery is recurring and product-owned: every evaluation cycle re-runs the thread,
which re-runs the shell, which re-runs the payload; there is no cache, guard or one-shot
flag anywhere in the path. The negative control is clean, as section 9 shows: a benign
`ip` value produces a normal one-shot ping and nothing else, which pins the causality
on the stored bytes. And because the payload's bytes live in the condition store, the
attacker's position survives reboots and does not depend on any process staying alive.

## 8. Exploit Construction

### Exploit Construction — payload shape, and why the obvious one is wrong here

The shipped proof of concept stores, in the ping condition's `ip` field:

```
$(<command>)
```

Command substitution is the cleanest form for this template, and the reasons are
mechanical rather than stylistic. The shell performs `$(...)` expansion while
assembling the command line, before `ping` is executed; the expansion's result is
discarded into the ping operand, so nothing about the product's invocation is disturbed;
the command's own output is not needed in the attacker's channel at all, so the pipes
that the thread attaches to ping do not need to be answered for. A newline form -
`127.0.0.1` followed by a newline followed by the command - also verifies: the first
line is a perfectly ordinary ping with its flags attached, and the second line is the
attacker's. The naive semicolon form - `1.1.1.1; <command>; #` - is the one that
fails here: it splits the line before the `-c 1` flag, ping runs unbounded in the
foreground, the evaluating thread waits on it, and the replication record's marker never
appeared before the thread was torn down. The lesson generalises to every finding in
this family drawn against a template that places stored data in front of flags:
construct against the template's recovery rules, not against a habit.

### Exploit Construction — the delivered PoC

`exploit/moxa_mar_2000_scenario_ping_ip_injection.py` is a standard-library-only Python 3
client that drives the entry path: it logs in, reads the current scenario configuration,
saves a ping condition whose `parameter.ip` carries the substitution-form payload, and
reports what the condition will do on the next evaluation. It takes target, credential,
command and timeout arguments; its default target is loopback; it verifies each response
and exits non-zero with an explicit message on failure. It deliberately does not attempt
to compute or drive the watchdog's interval: the product owns the schedule, and the
research record establishes the sink's behaviour by replication rather than by timing a
live scheduler. No persistence, reverse shell or destructive step is implemented, and the
default command writes one marker file.

### Exploit Construction — engineering notes for anyone reproducing this

Two practical points. First, read the scenario configuration back after the write: the
resource serves the saved data, so the persistence of the payload is observable without
waiting any schedule out, and a mis-typed condition-object path that the handler
tolerated would otherwise be indistinguishable from a slow watchdog. Second, when
testing a device, prefer the substitution form, not out of taste but because the record
shows the semicolon form will block your evaluation thread and can wedge the model's
scenario machinery until it times out or is restarted - a laboratory annoyance for the
tester, still a real availability consideration for section 10.

## 9. Dynamic Verification

### Dynamic Verification — environment and method

The `PingThread.run()` construction was replicated verbatim on an isolated cloud Linux
sandbox (x86-64, native shell): the same template `"ping %s -c 1 -w 5 -I %s "`, the same
`shell=True` launch with both pipes captured, executed under three payload forms and a
benign control. This is sink-level replication, labelled as such: it establishes the
construction's shell behaviour across the payload family; it does not drive a live
device's HTTP tier or its watchdog, and the identity recorded in the marker is the
sandbox's own.

### Dynamic Verification — observed results

The substitution form:

```
cmd = "ping $(id > <marker>) -c 1 -w 2 -I lo "
subprocess.Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
--> marker file created, contents: uid=0(root) gid=0(root) groups=0(root)
```

The newline form, with the injected text as a second command line, produced the same
marker content. The semicolon form - the one that works against several of the product's
sibling sinks - produced no marker in the tested window: the stored value split the line
in front of the `-c 1` flag, the ping ran unbounded, and the thread had to be terminated
while the ping was still alive. The control, with the benign address `127.0.0.1`, ran a
normal bounded ping and produced no marker and no side effect - the false-positive
clearance the record requires.

### Dynamic Verification — what the results establish and what they do not

The replications establish: that the thread's construction hands the stored value to a
shell and that the substitution and newline forms both reach execution (markers
written); that the naive semicolon form is unsuited to this template and behaves as an
availability nuisance rather than an execution (no marker within the tested window);
and that the construction with benign input behaves as the product intends it (no
marker, no side effect). They do not establish: the on-device process identity - the
marker's `uid=0(root)` is the replication sandbox's identity, and this advisory never
claims device-side root; the watchdog's real evaluation interval on a device (the
condition's times default is a product input, and the schedule is a product property
established by the model's structure, not timed live); or any behaviour of other
MAR-2000 firmware builds. Each unsupported boundary is stated rather than smoothed
over, and the advisory's title and score rest only on what is established.

## 10. Reachability and Security Impact

### Reachability — position and population

Any client that can reach the management listener and hold an administrator credential
can save this payload; the listener binds all interfaces on port 80 in the shipped
firmware, and the write needs no special protocol position. The population for which the
credential prerequisite collapses - deployments that never changed the factory default
pair - is the population conditional reading A describes, and the two figures are kept
separate because they describe different deployment states.

### Reachability — impact ceiling

The executed command runs as the identity of the Scenario model daemon, and impact is
stated with that ceiling: every file the process can act on, every configuration write
the product performs, the ability to manipulate the device's monitoring-as-automation
features, and - distinctively here - a recurring execution primitive on the product's own
schedule, with the attacker's bytes re-delivered at every evaluation cycle until the
condition is deleted. The on-device identity was not measured; nothing in this record
establishes privilege escalation beyond the model process, and none is claimed. One
availability note belongs to the finding's own mechanics rather than to post-exploitation
narrative: a malformed-in-the-wrong-way payload such as the semicolon form can wedge the
evaluating thread against an unbounded ping, so the same unvalidated field is also a
denial-of-service lever against the monitoring machinery itself.

### Reachability — detection notes

The configuration write is indistinguishable in shape from an administrator's ordinary
scenario definition, and the executing process is the product's own monitoring thread
performing nominally its job - the class is structurally quiet, and the recurring
delivery makes no noise of its own. The readable signals are content-level: a saved
ping condition whose `ip` or `interface` contains `$(`, `;`, `|`, a backtick or a
newline; ping processes with no `-c` count attached; and unexpected child processes
under the model daemon. All three are auditable today without vendor changes, and the
first is a one-line sweep over a configuration that the product itself will happily
read back to whoever asks.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side

1. Run the connectivity check without a shell: build the ping invocation as an argument
   vector - an `execv`-family launch or an equivalent library call - which removes the
   metacharacter question from the thread entirely and, as a side effect, eliminates the
   unbounded-ping failure mode of the semicolon form.
2. Validate condition parameters at the store boundary: IP address form for `ip`,
   interface selector form for `interface`, bounded numeric for `times`, enforced in the
   model's put handler so that no writer the backend serves can store a heterogeneous
   value for the thread to consume.
3. Give the evaluation machinery a failure budget: limit the thread's lifetime
   (`-w` exists precisely for this), reap threads that outlive it, and log evaluations
   that produce unexpected process trees - the same monitoring that is the product's
   own purpose should watch its own reaction handlers.
4. Add a product regression test that saves a ping condition with a substitution-form
   `ip`, waits one evaluation cycle, and asserts that the parameter was rejected at
   write time or executed with no shell interpretation at read time.
5. Treat the recurring property as a design consideration: any value a scheduled
   reaction will eventually consume must be validated at store time, because the
   schedule converts a stored input into an automatically repeated one.

### Fix Recommendations — operator-side, until a patch exists

1. Change the factory default administrator credential at commissioning - this alone
   moves a deployment out of the conditional reading's population.
2. Keep the management listener off WAN-facing addresses and behind management-network
   controls.
3. Audit saved scenarios, not just configuration: sweep ping conditions for `ip` and
   `interface` values containing `$(`, `;`, `|`, backticks or newlines - the product's
   own read-back API makes this a one-request audit.
4. Remove or disable the scenario feature on deployments that do not use scheduled
   monitoring, so the watchdog has nothing to evaluate.

## 12. CWE and CVSS

### CWE and CVSS — classification

| Classification | Assignment | Justification |
|---|---|---|
| Primary | CWE-78 Improper Neutralization of Special Elements used in an OS Command | the saved ping condition's `parameter.ip` reaches a `shell=True` command template verbatim; the substitution and newline forms execute as shell statements, verified by replication |
| Contributing | CWE-20 Improper Input Validation | the put handler validates a presence property of the data object only; no parameter value is ever inspected, at write time or at read time |
| Reported separately, never scored in | CWE-798 Use of Hard-Coded Credentials | the shipped user table carries a factory default administrator pair; it is the condition of the conditional reading, not a metric of the chain |

### CWE and CVSS — published vector

**`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 High.** Metric by metric:

- **Attack Vector Network** - the entry listener binds all interfaces on port 80 in the
  shipped firmware; the attack is ordinary HTTP against it. No WAN exposure is assumed.
- **Attack Complexity Low** - a deterministic write, full control of the injected bytes
  and no race; the delivery moment is a schedule the product runs by itself, and the
  working payload forms are simple and verified.
- **Privileges Required High** - the chain requires the device administrator session;
  the product has one documented role and it is this one, which the CVSS guide calls High.
- **User Interaction None** - the attacker saves the condition; the product does the rest.
- **Scope Unchanged** - the model daemon belongs to the same single-purpose appliance;
  running scheduled monitoring through it is the product's design.
- **C/I/A all High** - command execution as the model process yields full compromise of
  the appliance's function and configuration, and the recurring delivery plus the
  unbounded-ping nuisance give availability impact at will.

Arithmetic:

```
ISS          = 1 - (0.44 * 0.44 * 0.44) = 0.914816
Impact (S:U) = 6.42 * 0.914816          = 5.873119
Exploitability = 8.22 * 0.85 * 0.77 * 0.27 * 0.85 = 1.234708
Base (S:U)   = min(5.873119 + 1.234708, 10) = 7.107826
Roundup      = 7.2
```

### CWE and CVSS — conditional and rejected readings

- Conditional A - factory default credentials unchanged: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  = **9.8** Critical. Exploitability 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043; base
  9.760161, rounded up to 9.8. Labelled conditional on a deployment state; it is not the
  headline score.
- Rejected B - management account treated as Low: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  = **8.8** High (Exploitability 2.835255, base 8.708373). This is the figure the source
  research record carried; it is not adopted, because no artefact evidences a
  lower-privileged product role that can reach the field, and it appears here only as the
  rejected variant's arithmetic.
- Rejected C - Scope Changed: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = **9.1**
  (ISS 0.914816, Impact 6.128026, Exploitability 2.286496, 1.08 x 8.414522 = 9.087684).
  Not published: the executing process belongs to the same appliance authority.
- Recorded score note - the source record behind this advisory carried 8.8 for all three
  same-product findings; none is inherited here, and every number in this section is
  computed from the vector next to it.

### CWE and CVSS — summary of readings

| Reading | Vector | Score | Status |
|---|---|---|---|
| Published | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 7.2 High | the vulnerability itself, credential prerequisite intact |
| Conditional A | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 Critical | deployments that never changed the factory default pair |
| Rejected B | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 High | source-recorded figure; no evidence for a lower product role |
| Rejected C | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 High | scope-changed reading considered and rejected |

One sentence for the vendor's engineers: the scenario facility of the MAR-2000 series
firmware `FWR_MAR2000_V1.0_Build_15010909` hands a stored, unvalidated ping-condition
`ip` field to a `shell=True` thread on the product's own schedule, so an authenticated
administrator saves `$(command)` once and the device executes it at every evaluation
cycle - and the same template misused with a semicolon turns the monitoring thread into
an unbounded ping waiting to be torn down. Rated 7.2 High with the credential
prerequisite intact, and 9.8 for the deployment state that never changed the factory
default pair.
