# NoMachine Terminal Server 10.0.57 — Pre-Authentication Stack Overflow with Return-Address Control

## 1. Overview

NoMachine Terminal Server 10.0.57's `nxwebrunner` CGI (`/usr/NX/bin/nxwebrunner.bin`, ELF64 x86-64 stripped, md5 `19c610cb9667c834435223fe4a4b6515`) contains an independent pre-authentication stack overflow in `RequestCollector::parsePOST` (`0x40d990`). The parser copies attacker-controlled multipart `name` and `value` fields into 1024-byte heap buffers (no heap overflow), then executes `sprintf(stack_buf, "%s=%s&", name, value)` into a 1032-byte stack buffer. When `name + value + 2 > 1032`, the write overflows the stack buffer, overwrites saved registers (`rbx/rbp/r12-r15` at offsets 1032–1079), and the return address at offset 1080. Because the binary is non-PIE with stack canaries disabled, the attacker fully controls `RIP` — proven by core dumps where the faulting return address mirrors the attacker's fill byte (`0x4242...` for fill `B`, `0x4343...` for fill `C`).

Stable RCE is currently unreachable: the `sprintf` format cannot write a canonical (NUL-terminated) pointer, the fork-per-request CGI model provides no information-leak primitive against full ASLR, and `nxwebrunner` imports no `system`/`popen`/`execve`. The vulnerability nevertheless delivers deterministic pre-auth crash and return-address control, and is strictly stronger than the sibling heap corruption (VULN-001).

## 2. Vulnerability Summary

- **Type**: Pre-authentication stack buffer overflow (CWE-787 out-of-bounds write / CWE-121) with return-address control
- **Root cause**: `sprintf(rsp+0x60, "%s=%s&", name, value)` at `0x40dc63` writes `name + "=" + value + "&"` into a 1032-byte stack buffer without a size check; `name` and `value` are each < 1024 bytes (no heap overflow), but their concatenation exceeds 1032, overwriting saved registers and the return address
- **Trigger condition**: `name + value + 2 > 1032`, with both fields < 1024, and the request body ending exactly at the `value` newline (loop-exit trick) so the parser returns through the corrupted return address
- **Binary defenses**: no stack canary (direct return-address overwrite), no PIE (fixed base 0x400000), writable GOT; NX enabled
- **Result**: pre-auth RIP control with deterministic crash. CVSS 9.8.

## 3. Authentication Boundary

Identical to VULN-001: `main` calls `fetch` unconditionally; `fetch` gates `parsePOST` only on `strstr(body, "filename")` (`0x40e10b`); the cookie/action dispatch runs after `fetch` returns. No credentials, cookie, session, or token are required. The request is routed to the CGI by `ScriptAliasMatch "(?i)^/?"` on the HTTPS listener (port 4443).

## 4. Attack Surface

- **Entry**: `POST /` with a multipart body containing `Content-Disposition: form-data; name="<600 bytes>"; filename="<600 bytes>"` and no closing boundary
- **Pre-auth**: yes, identical reachability to VULN-001
- **Process model**: `nxhtd` forks and execs `nxwebrunner.bin` per request; a crash affects only the CGI child
- **Binary protections**: no canary, no PIE, NX on, RELRO off — the overflow can reach the return address directly with fixed gadget addresses

## 5. Sink Identification

`parsePOST` stack layout (frame base at `rsp+0x10`):

```
rsp+0x10  : buffer#1 pointer (name, 1024B heap chunk)
rsp+0x18  : buffer#2 pointer (value, 1024B heap chunk)
rsp+0x60  : sprintf stack buffer (1032 bytes to saved regs)
rsp+0x468 : saved rbx   (offset 1032)
rsp+0x470 : saved rbp   (offset 1040)
rsp+0x478 : saved r12   (offset 1048)
rsp+0x480 : saved r13   (offset 1056)
rsp+0x488 : saved r14   (offset 1064)
rsp+0x490 : saved r15   (offset 1072)
rsp+0x498 : return address (offset 1080)
```

The sink instruction sequence:

```asm
0x40da50  quote scan for '"'          ; unbounded scan (shared with VULN-001)
0x40da90  name copy → buffer#1        ; copies until '"', no 0x400 check
0x40dae8  value copy → buffer#2       ; copies until '\n', no 0x400 check
0x40dc35  add rbx, 2                  ; advance past value newline
0x40dc63  sprintf(rsp+0x60, "%s=%s&", buffer#1, buffer#2)   ; ★ stack overflow sink
0x40dc7f  Buffer::appendData
0x40dc84  cmp rbx, rbp; jl 0x40da54   ; loop while rbx < body_size
0x40db9f  [cleanup] ... ret @0x40dc27
```

Return-address offset: `1080 = name(600) + "="(1) + value_offset` → `value_offset = 479`; the 8 bytes `value[479..486]` land exactly on the saved return address.

## 6. Source Identification & Controllability

The source is the multipart body: `name` and `value` are both attacker-controlled and bounded only by the 1024-byte heap buffers. The loop-exit condition is attacker-controlled too — the body must end exactly at the value's `\n` (no closing boundary, no trailing bytes) so the loop counter `rbx` exceeds `rbp` (body size) and the function reaches `ret` with the corrupted return address instead of looping into a heap crash.

Payload shape: `name = 600 × 'A'`, `value = 'lename="' + 600 × fill + '"\r'` (610 bytes), body ends at the value newline. `value[479..486] = fill × 8` fully controls the return address.

## 7. Data Flow

1. Attacker sends `POST /` with the loop-exit multipart payload (no closing boundary).
2. `fetch` passes the `filename` gate and calls `parsePOST`.
3. `parsePOST` copies `name` (600 bytes) and `value` (610 bytes) into heap buffers.
4. `sprintf` writes 1212 bytes (`600+1+610+1`) into the 1032-byte stack buffer.
5. Saved registers at offsets 1032–1079 are overwritten; the return address at 1080 becomes `fill × 8`.
6. Because the body ended at the value newline, the loop exits, cleanup runs, and `ret` pops the attacker-controlled address → SIGSEGV at the controlled address.

## 8. Exploit Construction

```http
POST / HTTP/1.1
Host: <target>:4443
Content-Type: multipart/form-data; boundary=----b
Content-Length: <len>
Connection: close

----b
Content-Disposition: form-data; name="AAA...(600)..."; filename="BBB...(600)..."
```

Notes:
- No closing boundary and no trailing bytes — the value's `\n` is the last byte of the body.
- `name = 600 × 0x41`; `value = 'lename="' + 600 × 0x42 + '"\r'`.
- Changing the fill byte changes the faulting return address (B → `0x4242424242424242`, C → `0x4343434343434343`), proving RIP control.

## 9. Dynamic Verification

Three-way contrast over the real HTTPS path:

| Group | name | filename | body tail | Expected | Observed |
|---|---|---|---|---|---|
| CONTROL | 10 B `shortfield` | `t.txt` | ends at `\n` | 200 OK | 200 OK |
| VULN-B | 600 A | 600 B | ends at `\n` | 500 (crash @ 0x42..) | 500 |
| VULN-C | 600 A | 600 C | ends at `\n` | 500 (crash @ 0x43..) | 500 |
| NEGATIVE | 600 A | 600 B | with closing boundary | heap SIGABRT (loop continues) | 500 |

Core dumps (gdb):

```
Core 1 (fill B):  rip = 0x40dc27 ; [rsp] = 0x4242424242424242
Core 2 (fill C):  rip = 0x40dc27 ; [rsp] = 0x4343434343434343
```

The crash is at the `ret` instruction (`0x40dc27`) in both cores, and the popped return address tracks the fill byte — decisive proof of return-address control. The CONTROL request returns 200 OK, confirming the loop-exit path is benign without the overflow.

## 10. Reachability & Impact

- **Reachability**: fully pre-auth over HTTPS 4443; the payload needs only two attacker-controlled fields and a precise body terminator; no canary, no PIE.
- **Impact**: deterministic return-address control in the `nxwebrunner` CGI. In the worst case this is a code-flow hijack primitive in a non-PIE process with fixed gadget addresses; even without a viable ROP chain, any unauthenticated attacker can deterministically crash the handler.
- **Stable RCE barrier**: (a) `sprintf` always appends `&\0`, so a NUL-containing canonical pointer shortens the write before the return address, while a NUL-free overflow produces a non-canonical address (`#GP`); (b) fork-per-request + full ASLR leaves no information-leak primitive; (c) the imports include no `system`/`popen`/`execve`, and `ProcessCreate` has no callers; (d) saved registers (potential ROP args) are non-canonical whenever the overflow reaches the return address.

## 11. Fix Recommendations

1. Replace `sprintf(rsp+0x60, "%s=%s&", ...)` with `snprintf` bounded to the 1032-byte buffer, or skip the string re-encoding entirely
2. Enable stack canaries and PIE in the `nxwebrunner` build (both are currently disabled)
3. Add length validation to the name/value copy loops and the quote-scan loop (also fixes VULN-001)
4. Fuzz the multipart parser and run the CGI under a sandbox as defense in depth

## 12. CWE & CVSS

- **CWE-787**: Out-of-bounds Write — stack buffer overflow via unbounded `sprintf`
- **CWE-121**: Stack-based Buffer Overflow (consequence)
- **CVSS**: 9.8 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
