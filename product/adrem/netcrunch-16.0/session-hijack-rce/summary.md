# AdRem NetCrunch Cross-Session Hijack RCE

## Summary

An unauthenticated remote code execution vulnerability in AdRem NetCrunch v16.0.0.8397 RC. The Node.js web layer (WebAppServer.exe, port 9443) RPC session-reuse mechanism lacks a caller-ownership check: `getSession()` parses the `sid@gid` in the `x-sid` header without verifying that the session was created by the current requester, and `rpcRequest()` -> `getApp(url, gid, sid, autoCreate=false)` looks up an existing authenticated ApiSession by gid+sid and reuses its token. An unauthenticated attacker A who obtains a victim B's `sid@gid` can impersonate B and invoke any authenticated RPC method. Combined with the startup-script command-execution sink (`INcStartupScript.SetScriptOptions` to persist a malicious command + `INetCrunchServer.RestartNCServer` to trigger execution on service restart), this forms a complete unauthenticated -> SYSTEM RCE chain. NCServerSvc runs as LocalSystem, so the command executes with SYSTEM privileges.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: AdRem NetCrunch (Windows-native network monitoring system)
- **Versions**: 16.0.0.8397 RC and versions using the same Node.js session-reuse path
- **Vendor**: AdRem Software

## Impact

- **Confidentiality**: Full SYSTEM-level read of the NetCrunch server host
- **Integrity**: Arbitrary SYSTEM command execution; ability to alter monitoring configuration and persisted data
- **Availability**: Full control of the NetCrunch server; can stop/disable the monitoring service

## Exploitation Model

This is a Target A (network service) vulnerability. The Node.js web layer listens on port 9443 by default. The `sid@gid` is predictable (gid is a timestamp offset predictable to ~1s; sid is a 30M space with a 449/200 oracle that allows brute force), or obtainable via leakage (logs, error pages, Referer, SSRF responses). Exploitation requires an existing authenticated victim session (admin or normal user) and attacker access to port 9443. Default install is vulnerable with no special configuration.

## Mitigation

1. Fix the core F1 flaw: `getSession()`/`rpcRequest()` must verify that the `x-sid` session belongs to the current caller (bind the session to client IP / TLS session / cookie, or sign the `sid@gid`)
2. Use a CSPRNG for sid: replace `Math.random()` with `crypto.randomInt(1, 2**31)`, expanding the space to 2^31+
3. Add a random suffix to gid: timestamp + CSPRNG random, removing predictability
4. Add an authorization check to `INcStartupScript.SetScriptOptions`: only admins may set the startup script, plus a command allowlist
5. Unify the 449 response: return an indistinguishable response for invalid `sid@gid` and for a missing valid session (mitigates the oracle)
6. Make the session registry url-scoped: `getApp` lookup should verify url match (mitigates cross-URL hijacking)

## Timeline

- **Discovered**: 2026-07-18
- **Public Disclosure**: 2026-07-18

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).