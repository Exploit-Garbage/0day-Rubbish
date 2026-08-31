# NoMachine Terminal Server — Pre-Authentication Heap Memory Corruption in parsePOST

## Summary

NoMachine Terminal Server 10.0.57 exposes a pre-authentication heap memory corruption vulnerability in the `nxwebrunner` CGI handler (`/usr/NX/bin/nxwebrunner.bin`). Any unauthenticated attacker can send a single crafted `multipart/form-data` POST to the HTTPS web entry point (port 4443) and trigger a deterministic heap corruption that aborts the CGI process (CWE-787 out-of-bounds write → CWE-416 double-free), with RCE-capable exploitation potential.

The root cause is an unbounded quote-scan loop in `RequestCollector::parsePOST` that reads past the end of the request body, followed by an unbounded name-copy loop that overflows a 1024-byte heap buffer and corrupts the metadata of an adjacent heap chunk. The corrupted chunk is freed during cleanup, causing glibc to abort with `double free or corruption (out)`.

No authentication, cookie, session, or token is required. The trigger is a multipart body whose `Content-Disposition` part contains a `filename="..."` attribute — the presence of the `filename` substring alone passes the gate; the filename length is irrelevant (even an empty filename triggers the corruption).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: NoMachine Terminal Server
- **Versions**: 10.0.57 verified; other v10 releases sharing the same `nxwebrunner` CGI parser are likely affected
- **Vendor**: NoMachine S.r.l.
- **Prerequisite**: default installation, no configuration required

## Impact

- **Confidentiality**: Heap metadata corruption can be groomed into arbitrary write primitives (tcache/fastbin poisoning) for information disclosure or code execution in the CGI process
- **Integrity**: RCE-capable corruption of heap state in the `nxwebrunner` process running as the `nxhtd` user
- **Availability**: Deterministic crash (SIGABRT) of the CGI handler on ~90% of trigger attempts

## Mitigation

1. Add body-length and buffer-size bounds checks to the quote-scan and name-copy loops in `parsePOST`
2. Do not rely on the `strstr(body, "filename")` gate as the only defense; validate all copy lengths
3. Replace `sprintf` with bounded writes throughout the parser
