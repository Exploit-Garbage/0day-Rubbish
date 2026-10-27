# Moxa MAR-2000 — Executer Program-Activation Command Injection: the Program Table argument Field Reaches a Shell-Interpreted Program Launch

## 1. Overview

### Overview — the finding

Moxa, an industrial networking vendor in Taiwan, ships the MAR-2000 series industrial
4G/LTE cellular router with a management backend whose defining property is that every
configuration value eventually becomes an operating-system operation. The web management
application is a Node.js Express 4.0 process listening on port 80 with the address binding
covering every interface; the express-sanji middleware translates each REST call into a
message on a local MQTT broker; and the message is consumed by a Python 2.6 model script
inside the Mobile Intelligent Routing Framework (MIRF) stack, which is the component that
actually does the work. This advisory documents one of three findings in that backend, each
of which turns a stored configuration field into a shell-interpreted command.

The Executer model (`/home/model/system/executer/executer.py`) is the product's mechanism
for running operator-authored programs on the device. It stores one row per program in an
SQLite table whose columns include `fileName` and `argument`, and when a row is activated
the model builds a single shell string — the executable path, a space, the stored
`argument` — and passes it to `subprocess.Popen` with `shell=True`, which is precisely the
`/bin/sh -c` hand-off that makes the `argument` bytes shell syntax. Nothing between the HTTP
request and the operating system validates those bytes. The row's columns are committed by a
generic writer that takes every key of the request's data object and writes it into the row
with a plain SQL `UPDATE`, and the model re-reads the same columns at activation time
without inspection. The result is that one authenticated `PUT` waiting in a table row — not
a parsing edge case, not a memory bug — becomes arbitrary command execution the moment any
row carrying it is activated.

The execution is gated by a single product-intended precondition: the model only executes a
program whose file exists under the user-program directory (`os.path.exists`). That gate
does not restrict the attacker, because the product's own upload route — `POST` to the same
program resource, handled by multer — accepts a file upload into that directory, with no
allowed-type list and no file filter, applying only a filename normalisation. The same model
also contains a second, structurally identical sink in its deletion path, which builds
`rm -rf <user-program dir>/<fileName>` and executes it with `subprocess.call(shell=True)`
whenever a row is deleted, guarded only by a comparison `filename != "/"` that blocks exactly
one value and nothing else.

### Overview — the product and its runtime stack

The artefact characterised is firmware `FWR_MAR2000_V1.0_Build_15010909` for the MAR-2000
series industrial 4G/LTE cellular router. The firmware extracts to an ARM Debian 6.0.8 root
filesystem running the MIRF stack. The management plane, as established from the firmware's
own application files, is:

```
client --> Express 4.0 (port 80, all interfaces)
              |  validateUser middleware: session.user required for non-GET
              |  express-sanji: REST resource --> MQTT topic message
              v
          MQTT broker (localhost:1883, no broker authentication)
              v
          Python 2.6 model daemons (/home/model/...)
              |  SQLite configuration storage, JSON config files
              v
          subprocess.Popen(..., shell=True) / subprocess.call(..., shell=True)
```

Authentication is enforced entirely at the HTTP layer. The `validateUser` middleware blocks
non-GET requests that do not carry an authenticated user in the server-side session; login
is `POST /api/login`, which compares the submitted pair against a bcrypt-hashed entry in the
SQLite user table. Two further properties of this plane matter for context: the broker
carries no authentication of its own (any process able to publish to it can address the
models directly — a design property we observed and report as context, not as part of this
chain), and every `GET` request across `/api/v1/*` is answered without a session, exposing
stored configuration to unauthenticated readers. Neither property is needed for this
advisory's chain, and neither is folded into its score.

### Overview — the evidence base and its boundary

Every claim in this advisory is anchored to one of two evidence classes, and they are
labelled wherever they appear.

The first class is the firmware's own application source: the model file, its REST resource
wiring, the row-writer's SQL shape and the sink construction quoted in section 5 and section 6
are read from the extracted firmware content of `FWR_MAR2000_V1.0_Build_15010909`. This class
establishes the entry path, the storage semantics and the exact code that executes — it is
structural evidence about shipped software, and it is complete for the claims made about
what the product does with the field.

The second class is sink-level replication: the exact command construction —
`str(execute_file) + " " + str(argument)` followed by a `shell=True` launch — was
re-implemented verbatim and executed with a native shell on an isolated cloud Linux sandbox,
carrying a benign payload, an injection payload and a control, with results quoted in
section 9. This class establishes the behaviour of the construction once the stored bytes
reach it: that the shell splits the command as predicted, that the injected statement
executes, and that the same construction with a benign argument does nothing of the sort.
What this evidence does not measure is the identity of the model process on the device
itself; the replication harness ran as root, so the marker recorded `uid=0(root)` — that
number is a property of the sandbox and of no one else, and this advisory does not claim
root on the device. End-to-end detonation against powered-on MAR-2000 hardware is outside
this research record, and the claims of this advisory are scoped to match: the entry path
and the sink are established as structure, and the shell semantics of the sink are
established by replication.

### Overview — independence: existing records, and how they were searched

Before drafting, the public record was searched over the vulnerability database's keyword
interface along separate axes — the vendor name alone; the vendor name combined with the
product name; the product name alone; and the vendor name combined with the handler terms
that name this finding's entry route (`executer`, `ipsec`, `scenario`). The search we were
able to complete returned two hundred and sixty-eight records under the vendor axis, describing
command injection and authorisation findings concentrated in the vendor's other product
families — a history that shows the vendor's cellular router lines have carried
shell-command construction weaknesses in other code bases. The product axis and the
vendor-plus-product axis each returned no record at all, and none of the handler-axis
searches returned a record naming this product or this model. No public record was found,
in the searches we completed, that names the MAR-2000 series, the Executer model, or this
root cause — a stored program-argument field concatenated into a shell-interpreted program
launch. We state the boundary of that claim as we verified it: the searches were
keyword-based over record description text, so absence from those searches is how we
characterise a record we did not find, and this advisory claims originality for its finding
rather than asserting a universal "first".

This finding is one of three documented for this product, all released together as a set.
It is independent of the other two on every axis that matters for counting distinct
vulnerabilities: a different model file (`executer.py`), a different REST resource family
(`/api/v1/system/executer/*`), a different configuration field (the program table's
`argument` and `fileName` columns), and a different sink pattern (a stored program-row
execution gated by a file-existence check), sharing with them only the entry architecture
that all three traverse.

## 2. Vulnerability Summary

### Vulnerability Summary — table

| Item | Value established by this research |
|---|---|
| Vendor | Moxa, industrial networking vendor, Taiwan |
| Product | MAR-2000 series industrial 4G/LTE cellular router |
| Firmware | `FWR_MAR2000_V1.0_Build_15010909` |
| Platform | ARM Debian 6.0.8 with the MIRF stack |
| Management stack | Express 4.0 on port 80, express-sanji, MQTT broker on localhost:1883, Python 2.6 models |
| Entry | `PUT /api/v1/system/executer/program/<id>` — `data` object keys written verbatim into the row |
| Activation | `PUT /api/v1/system/executer/activatedProgram` with `programId` and `runBit` 1 |
| Upload enabler | `POST /api/v1/system/executer/program` multipart upload, no file type restriction |
| Sink | `subprocess.Popen(full_command, shell=True, preexec_fn=os.setsid)` in `executer.py` |
| Secondary sink | `subprocess.call("rm -rf %s" % execute_file, shell=True)` in `delete_row()` |
| Storage | SQLite program table; the injected value persists across reboots |
| Authentication | administrator session required (`validateUser`); factory default pair exists in the shipped user table |
| Verified by | firmware source analysis plus sink-level replication with payload and control |
| Primary CWE | CWE-78 |
| Published score | 7.2 High — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary — mechanics in four facts

**One** — the row writer is generic. The model handles every column identically: it reads
the keys of `input_json["data"]` and writes them into the row. There is no per-column
semantics anywhere on the write path, so a field that is about to become part of a shell
command is stored with exactly the care given to a display string.

**Two** — the sink is a stored interpreter. The command executed at activation time is
assembled from the freshly-read row, not from the request: the executable path and the
`argument` column are concatenated and handed to the shell. The attack therefore has two
independently observable phases joined by a table row — a write that can be scrutinised,
and a launch that happens whenever activation reads the poisoned columns.

**Three** — the file-existence gate is a liveness check, not a security check. The product
wants to run operator programs, so it requires the file to exist; it does not restrict what
may coexist in the argument string, and its own upload route is what an attacker uses to
authorise the launch.

**Four** — the deletion path repeats the whole pattern with a destructor verb.
`rm -rf <dir>/<fileName>` built with `shell=True` from an unvalidated column, with a guard
that compares the raw value to a single slash. Any metacharacter-bearing `fileName` is the
same finding wearing a different verb.

### Vulnerability Summary — preconditions

1. an administrator session on the management application (the credential prerequisite; the
   shipped firmware's default pair makes this collapse in deployments that never changed
   it — scored separately, never folded in);
2. a file under the user-program directory for the primary sink (provided by the product's
   own upload route; the deletion sink needs no file);
3. activation of the poisoned row (a second authenticated request, or any event that
   activates the same row's program later).

## 3. Authentication Boundary

### Authentication Boundary — what the gate enforces

The `validateUser` middleware is the only authentication check on the REST surface: it
requires a server-side session (`session.user`) for every non-GET method. Login is
`POST /api/login` with a username and password compared against the bcrypt-hashed entries
of the SQLite user table. Once the session exists, the full mutating surface of this chain
— the program upload, the row update, the activation request, the row deletion — is open to
it. There is no second authorisation layer inside the backend: express-sanji performs no
permission translation, the MQTT side carries no identity at all, and the model trusts the
message that reaches it. In other words, the management application's single administrator
role is the whole security boundary; the model layer re-implements none of it.

### Authentication Boundary — the default credential and how it is handled in scoring

The research record documents that the shipped firmware's user table carries a factory
default administrator pair (bcrypt-hashed at rest). For scoring hygiene this advisory
treats that pair exactly as the repository's other industrial-router advisories do: the
published vector measures the vulnerability with the credential prerequisite in place
(`PR:H` — the device administrator is the product's top role and the CVSS guide's canonical
example of High), and a separate, labelled conditional reading carries the deployment state
in which the pair was never changed. Neither number claims the other's population. An
operator reading this advisory should treat the conditional as the reason change-on-first-
login is enforced, not as the headline.

### Authentication Boundary — adjacent properties not claimed

Three nearby authentication-related observations are deliberately not part of this finding:
the unauthenticated readability of `GET` requests across `/api/v1/*` (an exposure issue in
its own right); the absence of broker authentication between the web tier and the models
(a design property that widens the in-device attack surface but requires on-device presence
or another injection to matter); and the hardcoded cookie-signing secret, which does not
assist this chain because the session store is server-side. None is scored here.

## 4. Attack Surface

### Attack Surface — listeners and routes

| Surface | Default | Authentication | Role in this chain |
|---|---|---|---|
| Express management application | port 80, all interfaces | session for non-GET methods | entry for every step |
| Executer program resource (`/api/v1/system/executer/program`) | REST family | administrator session | upload enabler plus row write |
| Executer activation (`/api/v1/system/executer/activatedProgram`) | REST | administrator session | sink trigger |
| MQTT broker | localhost:1883 | none | internal transport, no gate of its own |
| Executer model daemon | `/home/model/system/executer/executer.py` | none | sink |

The web application binds all interfaces on port 80 in the shipped firmware. Whether a
given deployment exposes that listener beyond its immediate management network is an
operator decision the research did not field-audit; the published vector scores the
network position of the listener without assuming WAN exposure, and the conditional reading
likewise does not assume it — it changes only the privilege prerequisite.

### Attack Surface — how the surface was read

The surface was mapped from the firmware's application files themselves: the Express route
registration and middleware order for the HTTP tier, the express-sanji topic mapping for the
transport, and the model's handler methods for the backend behaviour. The mapping is
therefore of shipped software, not of a live probe, and every quoted artefact — the
middleware name, the resource paths, the model file path, the column names — comes from that
reading.

### Attack Surface — the upload route as the enabling surface

The product intends `POST /api/v1/system/executer/program` to deliver operator programs.
Its multer configuration applies filename sanitisation only: there is no allowed-mime list
and no file filter, so the route stores what it is given under the user-program directory.
For this chain that is not itself the vulnerability — the vulnerability is what the Executer
model does with the stored row — but it is the surface that converts the model's
file-existence gate from an obstacle into a formality.

## 5. Sink Identification

### Sink Identification — the primary sink, quoted from the model

The activation path of the Executer model reads a program row and executes the program it
names, with the row's `argument` column appended to the command line:

```python
argument = program_table["argument"]
file = program_table["fileName"]
if run_bit == 1:
    execute_file = os.path.join(self.model_profile["user_program_dir"], file)
    if os.path.exists(execute_file):
        os.chmod(execute_file, 755)
        full_command = str(execute_file) + " " + str(argument)
        self.user_program = subprocess.Popen(full_command, shell=True,
                                             preexec_fn=os.setsid)
```

Three observations make this a command-injection sink rather than a program-launch feature
with an argument string. The concatenation is textual: one string handed to a shell, not an
argument vector handed to `execv`. The `shell=True` flag is the shell hand-off: the bytes
of `argument` are parsed as shell syntax, where `;`, `&`, `|`, backticks and `$(...)`
have their ordinary meaning. And the value's provenance is a database column set by an HTTP
request — the model cannot distinguish an operator's intended argument list from an
attacker's.

### Sink Identification — the secondary sink, quoted from the deletion path

The deletion path of the same model builds a filesystem destructor out of the same-table
column, with a guard that blocks exactly one value:

```python
filename = row["fileName"]
execute_file = os.path.join(self.model_profile["user_program_dir"], filename)
if filename != "/":
    cmd = "rm -rf %s" % execute_file
    subprocess.call(cmd, shell=True)
```

The `!= "/"` test answers the question "is the path exactly the root directory in the
trivial textual sense" and nothing else. A `fileName` of `name; <command>; #` traverses the
concatenation identically to the primary sink; the destruction verb in front changes the
garbage command, not the behaviour of the injected segment. This sink requires no upload and
no activation, only the row-deletion request, and is reported as part of this advisory
rather than as a fourth one because it is the same model, the same table, the same
concatenation-to-shell pattern and the same resource family.

### Sink Identification — how the sink was confirmed to be a sink

Sink identification for a configuration-backend finding is a data-flow question: the
construction was confirmed as a sink by tracing its inputs (section 6) and then by
replicating the construction exactly — same concatenation shape, same `shell=True` launch
flags, same payload family, a benign control — on the isolated cloud sandbox described in
section 9. The replication's value is that it removes the interpretation step: whatever the
model's author intended `argument` to hold, the construction demonstrably hands those bytes
to a shell.

## 6. Source Identification

### Source Identification — the write path, quoted from the model

The `PUT` handler for a program row is the model's generic row writer, which commits every
key of the request's data object into the row without inspecting any value:

```python
column_list = [x for x in self.mqttc.json_obj.input_json["data"].keys()]
value_list = []
for item in column_list:
    value_list.append(self.mqttc.json_obj.input_json["data"][item])
sql_command = "UPDATE %s SET %s WHERE id=%s" % (table_name, pair_string, id)
```

The `argument` value therefore has the following provenance chain: the JSON body of an
authenticated `PUT /api/v1/system/executer/program/<id>`, through express-sanji's message
translation, through the broker, into a generic SQL update, into the row — with null
value-level attention at any hop. The write path even commits whatever column keys the
request carries, which makes the row's content a faithful copy of attacker-supplied keys
and values.

### Source Identification — the taint summary

- tainted parameter: the `argument` (and `fileName`) values in the `data` object of the
  authenticated PUT body;
- transport: HTTPS-free plain HTTP by default, express route to broker message, model handler;
- storage: SQLite program table, persisting across reboots;
- sink reach: read at activation time (`select` of the row) or deletion time, concatenated,
  shell-executed.

Sanitisation on this path is exactly none. The only text transformations anywhere near the
chain are the multer filename normalisation (which constrains the uploaded file's stored
basename, not the argument string) and the model's own `str()` casts at the sink — which
are type coercion, not filtering.

## 7. Data Flow

### Data Flow — end to end

```
[1] attacker logs in
    POST /api/login  {username, password}
    --> server-side session; validateUser now admits mutations

[2] attacker uploads a benign program (satisfies the existence gate)
    POST /api/v1/system/executer/program   multipart
    --> file stored under the user-program directory

[3] attacker writes the payload into the row
    PUT /api/v1/system/executer/program/<id>
        {"data": {"fileName": "<uploaded basename>",
                  "argument": "; <command>; #"}}
    --> generic row writer commits both columns verbatim (SQLite)

[4] attacker activates the row
    PUT /api/v1/system/executer/activatedProgram
        {"data": {"programId": <id>, "runBit": 1}}
    --> model reads the row, executes:
        subprocess.Popen("<dir>/<file> ; <command>; #", shell=True)

[5] shell semantics
    "<dir>/<file>" runs as the program (harmless, no arguments)
    ";" terminates it — the injected <command> runs in a shell
    "#" comments the remainder of the line
```

### Data Flow — properties worth naming

The chain is two-request after login (write, then activation), and the write and the
execution are separated by storage: the poison sits in a table row until activation reads
it, which means the attacker's requests do not have to be adjacent in time, and any later
re-activation of the same row re-executes the payload. The stored-through-SQLite property
makes the payload reboot-durable, which is a persistence statement about configuration, not
about any installed start-up mechanism — the command may of course install one, but that is
post-exploitation behaviour this advisory does not exercise. The negative control property
is equally mechanical: a benign `argument` produces the benign program launch and nothing
else, which is what section 9 demonstrates.

## 8. Exploit Construction

### Exploit Construction — payload shape

The payload placed in the `argument` column is:

```
; <command>; #
```

The first command segment is the stored `fileName`'s executable — the benign uploaded
program — which the shell runs first with no arguments; the `;` ends it and begins the
attacker's segment; a trailing `#` comments out whatever the line carries after the payload,
which is nothing here because the argument is the line's tail. Any command that produces
observable output works for verification; the research record used a redirection to a marker
path under the sandbox filesystem (`id > <marker path>`), and the shipped PoC defaults to
the same shape with a device-local marker path. Because the payload need not guess any
quoting context, it also need not be minimal; but the smaller it is, the less likely any
future input front-end is to reject it — and nothing in the current firmware looks at it.

### Exploit Construction — the delivered PoC

`exploit/moxa_mar_2000_executer_program_argument_injection.py` is a standard-library-only
Python 3 client that drives the chain: it logs in, uploads a benign two-line shell script
through the multipart route, writes the argument payload into a chosen row, activates the
row, and reports. It takes the target, credential, row id, marker command and timeouts as
arguments; its default target is loopback; it verifies the write and the activation server
responses and exits non-zero with an explicit message at each potential failure point. It
implementes no persistence, no reverse shell and no destructive action, and its default
command writes a single marker file so the outcome is observable without any second
channel.

### Exploit Construction — engineering notes for anyone reproducing this

Two practical points. First, the stored `fileName` value and the uploaded file's basename
must agree, because the model joins the row's `fileName` with the program directory; the
PoC uploads first and then writes both columns together for that reason. Second, the
activation request is what executes the row — the write alone does nothing until activation
(or until any later activation of the same row), so a verification harness that stops after
the PUT has proven storage, not execution; the PoC performs and checks both steps
separately for exactly that reason.

## 9. Dynamic Verification

### Dynamic Verification — environment and method

The sink construction was replicated verbatim on an isolated cloud Linux sandbox (x86-64,
native shell): the model's concatenation — `str(execute_file) + " " + str(argument)` with
`preexec_fn=os.setsid` — was executed with `shell=True`, carrying a benign upload stand-in
program, an injection payload and a benign argument control. This is a sink-level
replication, and it is labelled as such: it proves what the construction does with the
bytes that reach it. It does not drive a live device end to end, and the identity printed
in the marker is the sandbox's own identity.

### Dynamic Verification — observed results

With the injection payload:

```
full_command = "<user_program_dir>/test" + " " + "; id > <marker>; #"
subprocess.Popen(full_command, shell=True, preexec_fn=os.setsid)
--> marker file created, contents: uid=0(root) gid=0(root) groups=0(root)
```

The control, with the same construction and a benign `argument` value
("a plain program argument string"), produced no marker and no side effect — the benign
program printed its argument line and exited, which is the product's intended behaviour.
The deletion-path construction was replicated with the same method:
`"rm -rf %s" % ("<dir>/" + "test; id > <marker>; #")` executed with `shell=True` also
produced a marker, confirming the secondary sink with the same payload family.

### Dynamic Verification — what the results establish and what they do not

The three replications establish: that the concatenated command line is executed by a shell
(payload executes, marker written); that the execution is caused by the injection bytes and
not by the construction (control produces nothing); and that both sinks of this model
behave identically. They do not establish: the identity of the model process on the device
(the marker's `uid=0(root)` is the replication sandbox's identity, since the sandbox
harness ran privileged — this advisory never claims device-side root); the end-to-end HTTP
behaviour of the live web application (established structurally from the firmware's
application source instead); or any behaviour of other MAR-2000 firmware builds. Each
unsupported boundary is stated rather than papered over, and the title and score of this
advisory rest only on what is established.

## 10. Reachability and Security Impact

### Reachability — position and population

Any client that can reach the management listener and hold an administrator credential can
run this chain; the listener binds all interfaces on port 80 in the shipped firmware, and
the chain needs no special protocol position, no race and no parsing edge case. The
population for which that prerequisite collapses — deployments that never changed the
factory default pair — is exactly the population conditional reading A describes, and the
two numbers are kept separate for the same reason: they describe different deployment
states, and the truth of one is not evidence for the other.

### Reachability — impact ceiling

The executed command runs as the identity of the Executer model daemon. What that identity
is on the device was not measured, and impact is stated with that ceiling: the attacker
gains every file the process can act on, every configuration write the product performs,
and full control of the appliance's function — forwarding, cellular, VPN, the up/down state
of a device deployed as communication infrastructure. Nothing in this advisory's chain
or record establishes privilege escalation beyond that process identity, and none is
claimed. Because the payload is a stored configuration row, its execution repeats with
every activation of the row and survives reboots, so the attacker's control does not depend
on any process staying up.

### Reachability — detection notes

The two requests that matter (row write, activation) are indistinguishable in shape from
ordinary administrator activity in the product's own API, which is where this class of
finding is structurally quiet. The readable signals are at the content level: program rows
whose `argument` contains shell metacharacters, unexpected files in the user-program
directory, and unexpected child processes spawned by the model daemon. A site can audit
for all three today without vendor changes.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side

1. Execute activated programs without a shell — build an argument vector and use an
   `execv`-family launch, which removes the metacharacter question entirely rather than
   answering it with a blocklist.
2. Validate the `argument` value at the row-write boundary: if the product's intended
   semantics are a program argument list, enforce that shape (printable, no shell control
   characters, bounded length) in the model, not only in a web front-end.
3. Constrain `fileName` to the set of files the upload route actually stored and associate
   rows to files by an opaque server-side handle so the column cannot carry path shapes.
4. Rebuild the deletion path with an argument vector: `rm -rf` over a shell string built
   from an unvalidated column is the same vulnerability with a destruction verb; the
   existing `!= "/"` guard protects one value and should not be called a control.
5. Restrict the multipart upload with an explicit executable-basename allowlist, and add a
   product regression test that writes a metacharacter-bearing `argument`, activates the
   row, and asserts that the row is rejected at write time or executed without any shell
   interpretation.

### Fix Recommendations — operator-side, until a patch exists

1. Change the factory default administrator credential at commissioning — this alone moves
   a deployment out of conditional reading A's population.
2. Keep the management listener off WAN-facing addresses and behind management-network
   controls.
3. Audit the program table and the user-program directory on a schedule: look for argument
   values containing `;`, `|`, `$(`, backticks or newlines, and for files nobody deployed.
4. Prefer disabling the Executer feature on deployments that do not use operator programs.

## 12. CWE and CVSS

### CWE and CVSS — classification

| Classification | Assignment | Justification |
|---|---|---|
| Primary | CWE-78 Improper Neutralization of Special Elements used in an OS Command | the stored `argument` (and `fileName`) values reach a `shell=True` launch verbatim; the injection bytes execute as shell statements |
| Contributing | CWE-20 Improper Input Validation | the generic row writer validates nothing about the values it commits, and the model re-reads them without inspection |
| Reported separately, never scored in | CWE-798 Use of Hard-Coded Credentials | the shipped user table carries a factory default administrator pair; it is the condition of the conditional reading, not a metric of the chain |

### CWE and CVSS — published vector

**`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 High.** Metric by metric:

- **Attack Vector Network** — the entry listener binds all interfaces on port 80 in the
  shipped firmware; the attack is ordinary HTTP against it. No WAN exposure is assumed.
- **Attack Complexity Low** — deterministic requests, no race, full control of the
  injected bytes; the file-existence gate is satisfied by the product's own upload route.
- **Privileges Required High** — the chain requires the device administrator session; the
  product has one documented role and it is this one, which the CVSS guide calls High.
- **User Interaction None** — the attacker performs every step.
- **Scope Unchanged** — the model daemon is part of the same single-purpose appliance
  authority; commanding the appliance's own operating system through its management plane
  is the product's design, not a crossing into a different authority.
- **C/I/A all High** — command execution as the model process yields full compromise of
  the appliance's function, configuration and reachable data, and on-demand interruption.

Arithmetic:

```
ISS          = 1 - (0.44 * 0.44 * 0.44) = 0.914816
Impact (S:U) = 6.42 * 0.914816          = 5.873119
Exploitability = 8.22 * 0.85 * 0.77 * 0.27 * 0.85 = 1.234708
Base (S:U)   = min(5.873119 + 1.234708, 10) = 7.107826
Roundup      = 7.2
```

### CWE and CVSS — conditional and rejected readings

- Conditional A — factory default credentials unchanged: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  = **9.8** Critical. Exploitability 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043; base
  9.760161, rounded up to 9.8. Labelled conditional on a deployment state; it is not the
  headline score.
- Rejected B — management account treated as Low: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  = **8.8** High (Exploitability 2.835255, base 8.708373). This is the figure the source
  research record carried; it is not adopted, because no artefact evidences a
  lower-privileged product role that can reach the field, and it appears here only as the
  rejected variant's arithmetic.
- Rejected C — Scope Changed: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = **9.1**
  (ISS 0.914816, Impact 6.128026, Exploitability 2.286496, 1.08 x 8.414522 = 9.087684).
  Not published: the executing process belongs to the same appliance authority.
- Recorded score note — the source record behind this advisory carried 8.8 for all three
  same-product findings; none of those figures is inherited here, and every number in this
  section is computed from the vector next to it.

### CWE and CVSS — summary of readings

| Reading | Vector | Score | Status |
|---|---|---|---|
| Published | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 7.2 High | the vulnerability itself, credential prerequisite intact |
| Conditional A | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 Critical | deployments that never changed the factory default pair |
| Rejected B | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 High | source-recorded figure; no evidence for a lower product role |
| Rejected C | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 High | scope-changed reading considered and rejected |

One sentence for the vendor's engineers: the Executer model of the MAR-2000 series firmware
`FWR_MAR2000_V1.0_Build_15010909` concatenates a stored, unvalidated `argument` column into
a `shell=True` program launch, so an authenticated administrator stores `; command; #` once
and executes it on every activation of the row — and the same pattern sits in the deletion
path with an unvalidated `fileName` inside `rm -rf`. Rated 7.2 High with the credential
prerequisite intact, and 9.8 for the deployment state that never changed the factory
default pair.
