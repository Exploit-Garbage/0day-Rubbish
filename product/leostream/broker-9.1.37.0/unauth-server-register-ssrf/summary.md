# Leostream Connection Broker — Unauthenticated Server.Register Rogue-Agent Registration + SSRF

## Summary

Leostream Connection Broker 9.1.37.0 exposes the Frontier::RPC2 XML-RPC endpoint `/rpc.pl`. The `Server.Register` method is dispatched **without** the `api_setup_session` authentication wrapper used by other methods, and its token parameter (`TOKEN61B240DC3E5B`) is **optional** — when the request does not carry a token, the entire token-validation block is skipped.

An unauthenticated attacker can therefore:

1. Register a **rogue VM/agent record** in the broker database (agent_uuid, ip, hostname, MAC fully attacker-controlled);
2. Trigger **server-side request forgery (SSRF)**: the broker's `check_status` background job connects outbound to `https://<attacker-ip>:<attacker-port>/RPC2` (function `Agent.Connect`) — verified by capturing a TLS ClientHello at an attacker-controlled listener.

This is not RCE (the `Server.Register` handler's direct SSRF block is unreachable because `$desktop_ip` is taken from REMOTE_ADDR), but it proves the token check is optional and enables rogue-machine injection plus outbound TLS requests to attacker-chosen targets. Default installation, no configuration dependency.

## CVSS Score

- **Score**: 7.0 (high) — unauthenticated rogue-record injection + SSRF
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (approximate)

## Affected Products

- **Product**: Leostream Connection Broker
- **Versions**: 9.1.37.0 verified; earlier 9.x releases with the same `Server.Register` dispatch are likely affected
- **Vendor**: Leostream Corporation
- **Endpoint**: `POST /rpc.pl` (Frontier::RPC2 XML-RPC)

## Impact

- **Integrity**: rogue VM/agent records injected into the broker database without authentication
- **Confidentiality (limited)**: outbound TLS requests to attacker-chosen IP:port enable internal-service probing via the broker
- **Availability**: low — rogue records can interfere with VDI session brokering

## Mitigation

1. Make `TOKEN61B240DC3E5B` validation mandatory (remove the `if exists` condition) or wrap `Server.Register` with `api_setup_session`
2. Strictly validate `MAC_LIST`/`IP_LIST` input types and formats
3. Filter RFC1918/loopback/link-local addresses in `check_status` outbound connections (SSRF defense)
4. Route unauthenticated registrations through an approval queue instead of directly creating VM records
