# NoMachine Terminal Server — Pre-Authentication Stack Overflow with Return-Address (RIP) Control

## Summary

NoMachine Terminal Server 10.0.57 contains a second, independent pre-authentication vulnerability in the same `nxwebrunner` CGI parser: an unbounded `sprintf` in `RequestCollector::parsePOST` overflows a 1032-byte stack buffer and overwrites saved registers plus the return address. Because the binary has **no stack canary and no PIE**, an unauthenticated attacker who controls both the `name` and `value` multipart fields can fully control the return address (`RIP`) — demonstrated by core dumps where the faulting return address mirrors the attacker's fill bytes.

Unlike the sibling heap corruption (VULN-001), this is a classic stack overflow with deterministic return-address control. Stable RCE is not currently reachable (the `sprintf("%s=%s&")` format cannot write a canonical pointer, the process has no information-leak primitive to break ASLR, and the binary imports no command-execution sink), but the pre-auth RIP control is a strong primitive and a deterministic crash on a default installation.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: NoMachine Terminal Server
- **Versions**: 10.0.57 verified; other v10 releases sharing the same `nxwebrunner` CGI parser are likely affected
- **Vendor**: NoMachine S.r.l.
- **Prerequisite**: default installation; binary is non-PIE with stack canaries disabled

## Impact

- **Confidentiality**: return-address control is a code-flow hijack primitive in a non-PIE, no-canary process; if a code-reuse chain becomes viable it enables arbitrary code execution as the `nxhtd` user
- **Integrity**: full control of the saved return address of the parser frame
- **Availability**: deterministic crash (SIGSEGV) of the CGI handler on every loop-exit payload

## Mitigation

1. Bound the `sprintf("%s=%s&", name, value)` output (use `snprintf` with the stack buffer size)
2. Enable stack canaries and PIE in the `nxwebrunner` build
3. Validate every field length against the actual parser buffers and body size
