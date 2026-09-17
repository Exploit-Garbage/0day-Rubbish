# Opengear NGCS Firmware 25.11.8 — PDU `name` Command Injection (Authenticated Administrator to Root RCE)

## Summary

Opengear NGCS firmware 25.11.8 exposes a management REST API (`og-rest-api`, served as `nginx` → `wsapi-fcgi` on port 9001 → Lua, shipping 128 source `.lua` files with 371 routes) on appliances the research record categorizes as CII / OT console managers (cellular console gateways) — the out-of-band management tier that holds the serial console path to other equipment. An authenticated **administrator** who creates a PDU via `POST /api/v2/pdus` controls the JSON field `pdu.name`. That value passes `validateJSON` (`PDUs.lua:319`), which checks only that it is a non-empty string — there is **no character filtering** — and is then stored raw (`addPduSettings`, `PDUs.lua:1011`), persisted (`config:commit()`), read back raw (`pduElem:getString("name")`, `PDUs.lua:64`), and concatenated into a shell command template in `getOutletCount`:

```lua
cmd = '/usr/bin/ogpower -n "' .. name .. '" system_info'
PDUs.execute(cmd)      -- io.popen(command .. ' 2>&1')  =>  /bin/sh -c
```

Because `name` sits inside literal double quotes with no escaping, a `"` in the name closes the wrapper. Submitting `name = x";id>/tmp/m_opg;#` with **`outlets` omitted** (which forces the auto-discovery branch that reaches the sink, past the `ls "/etc/ogpower/pdu/<method>"` gate) makes the device build and execute:

```
/usr/bin/ogpower -n "x";id>/tmp/m_opg;#" system_info 2>&1
```

`/bin/sh -c` runs `ogpower` with argument `x`, then treats the injected `id>/tmp/m_opg` as a separate command, with `#` commenting out the template tail. The worker unit `wsapi-fcgi@.service` has **no `User=` directive**, so systemd runs it as root and the injected command executes as **uid=0**. The code base already contains a shell-quoting helper (`common.shlex_quote`, `common.lua:590`) that other modules use but this sink does not — an omission, not a design choice. `/usr/bin/ogpower` itself is a Python wrapper using a `subprocess` argument list with no shell, so it neither re-parses nor neutralizes the injection.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **CWE**: CWE-78 (OS Command Injection), CWE-20 (Improper Input Validation)
- **Target class**: B — authenticated administrator to root RCE. Unauthenticated (Target A) was assessed across all 371 routes and judged **not reachable**: every route is guarded by an `auth_fn`, and the only pre-auth functionality is session/login with no shell sink.

## Affected Products

- **Vendor**: Opengear (Digi), US
- **Product**: Opengear NGCS firmware — console manager / cellular console gateway appliances
- **Firmware version**: **25.11.8**
- **Series enumerated by the research record** (this is a **cross-family merged entry**; the record states the vulnerable file `commands/PDUs.lua` is byte-for-byte identical across families at md5 `d9e0530285f04915c6bf18dde5287e65`, spanning ARM32 / aarch64 / x86-64, and is therefore one code defect rather than five separate ones):

| Product series | Platform / architecture |
|---|---|
| CM80xx (CM8000) | `ogquoll` / aarch64 |
| CM81xx (CM8100) | `ogarmada` / ARM32 |
| OM12xx (OM1200) | `ogpuma` / x86-64 |
| OM13xx (OM1300) | `ogquoll` / aarch64 |
| OM22xx (OM2200) | `ogpuma` / x86-64 |

- **Scope limits**: the five series above are exactly what our record enumerates. It documents extraction provenance only for the **CM8100** image, so beyond those series and that tested build the affected set is **not enumerated in our research record** and no larger model list is claimed. Firmware versions other than 25.11.8 were **not tested**. Exploitation requires an administrator account; **no default-credential vector is relied upon** (that is tracked as a separate disclosure). A separate, independent Opengear 0-day in `CellFwUpgrade.lua` (carrier code injection, different file / sink / parameter) is **not** covered here.

## Impact

- **Execution identity**: **uid=0 (root)** — `wsapi-fcgi@.service` carries no `User=` directive.
- **Control of the last-resort management path**: root on a console manager means control of **every attached device's serial console**. The appliance is the recovery channel for the whole estate, and that path is **out of band of normal monitoring** — production-side sensors, agents and logging do not sit on the OOB segment.
- **Durable persistence**: the malicious PDU entry is legitimate provisioning data that gets **committed to configuration** (`config:commit()`), so it survives reboots.
- **CII / OT adjacency**: deployments reach substations, plant floors and similar environments where the serial path is the control path.
- **Stealth and low barrier**: the delivering traffic is ordinary authenticated management-API activity (login, then create a PDU); the barrier is one administrator credential, with no race, memory corruption or special configuration.
- **Verification**: three-arm controlled dynamic verification **PASSED** via faithful `luajit` replication of the sink (full-device emulation not performed). VULN arm wrote a 39-byte `root root` marker containing `uid=0(root) gid=0(root) groups=0(root)`; CONTROL (`normalname`) and BENIGN (`benign`) arms wrote no marker. Independent adversarial review returned CONFIRMED 0.96 / NOT REFUTED 0.95 across seven falsification angles.

## Mitigation

1. Quote `name` at the sink using the existing `common.shlex_quote` (`common.lua:590`), as `PortAutoDiscover` and `AutoResponseStatus` already do.
2. Stop building shell strings in `PDUs.execute` (`io.popen(command .. ' 2>&1')`); spawn with an argv list so metacharacters have no interpreter.
3. Add a character policy to `validateJSON` rejecting shell metacharacters and quotes in `name`.
4. Audit every remaining `io.popen` / `os.execute` call site in `og-rest-api` for the same omission.
5. Set an explicit least-privilege `User=` on `wsapi-fcgi@.service` — the root default is what turns injection into full appliance compromise.
6. Operators, pending a vendor fix: keep the management API off untrusted segments and behind a jump host/VPN; audit stored PDU `name` values for `"`, `;`, `` ` ``, `$(`, `#`, `|`, `&`, `<`, `>`; enforce strong rotated admin credentials and remove shipped defaults; monitor `POST /api/v2/pdus` for unexpected creations.
