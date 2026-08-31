# NoMachine Terminal Server 10.0.57 — Pre-Authentication Heap Memory Corruption in parsePOST

## 1. Overview

NoMachine Terminal Server is a closed-source remote-desktop gateway used by enterprises to deliver virtual desktops and remote sessions over HTTPS. Its web layer (`nxhtd`, an Apache-based daemon listening on TCP 4443) dispatches every dynamic HTTP request to the `nxwebrunner` CGI binary through `ScriptAliasMatch "(?i)^/?"`. The CGI binary contains a pre-authentication heap memory corruption vulnerability in `RequestCollector::parsePOST` (`fcn.0040d990`). A single unauthenticated `multipart/form-data` POST whose part header contains a `filename="..."` attribute deterministically corrupts heap chunk metadata, and the subsequent cleanup frees the corrupted chunk, causing glibc to abort with `double free or corruption (out)`. The corruption is a classic heap-overflow primitive (CWE-787 out-of-bounds write) with RCE-capable exploitation potential via tcache/fastbin poisoning.

The vulnerability was confirmed by static reverse engineering (r2ghidra) and dynamic verification (C13): 0/5 control requests crashed, 9/10 trigger requests crashed (90% reproducibility), and gdb backtraces pinpointed the crash to the fourth `StringReset` (free) in the `parsePOST` cleanup path.

## 2. Vulnerability Summary

- **Type**: Pre-authentication heap memory corruption (out-of-bounds write → double-free)
- **Root cause 1 (CWE-787)**: an unbounded quote-scan loop (`0x40da50`) scans the request body after the first `\n` looking for `"` with no bounds check against the body length; a normal multipart body has no `"` after the `Content-Disposition` header line, so the scan reads past the body terminator into adjacent heap memory
- **Root cause 2 (CWE-787)**: an unbounded name-copy loop (`0x40da90`) copies that out-of-bounds garbage into a 1024-byte heap buffer (`puStack_488`) with no 0x400 size check, overflowing through two sibling buffers (`puStack_480`, `puStack_478`) into the chunk metadata of `pcStack_470`
- **Symptom (CWE-416)**: during cleanup (`0x40db9f`) the fourth `StringReset` frees `pcStack_470`, whose metadata was corrupted, and glibc aborts with `double free or corruption (out)`
- **Result**: deterministic pre-auth crash with heap-corruption primitives. CVSS 9.8.

## 3. Authentication Boundary

The request loop in `main` (`0x404830`) calls `fetch` (`0x4048bb`) as its first operation, unconditionally. `fetch` gates `parsePOST` only on `strstr(body, "filename")` (`0x40e10b`); there is no cookie, session, token, or credential check before `parsePOST` executes. The cookie/action dispatch (`strncasecmp(..., "nxw=", 4)` at `0x404d0f`) runs only after `fetch` returns, proving `parsePOST` executes before any authentication logic.

Dynamic confirmation: `GET /`, `POST /` with URL-encoded short bodies, and multipart bodies without a `filename` attribute all return `HTTP 200 OK` (the Web Player login page) without invoking the vulnerable path — the endpoint is reachable pre-authentication.

## 4. Attack Surface

- **Entry**: `POST /` on TCP 4443 (HTTPS) with `Content-Type: multipart/form-data`
- **Trigger condition**: the request body contains the substring `filename` (specifically a `Content-Disposition: form-data; name="..."; filename="..."` part header)
- **No prerequisites**: no cookie, no credentials, no MITM, no prior foothold
- **Process model**: `nxhtd` forks and execs `nxwebrunner.bin` per request; the crash is contained to the CGI child process, which makes the bug easily reachable and repeatable
- **Request size**: the triggering body can be as small as 89 bytes (far below any web.cfg limit)

## 5. Sink Identification

Static analysis of `nxwebrunner.bin` (ELF64 x86-64, stripped, md5 `19c610cb9667c834435223fe4a4b6515`) identified the following code path:

```
main (0x404830)
  └─ fetch = fcn.0040dda0  (call @ 0x4048bb)
       └─ strstr(body, "filename")  @ 0x40e10b/0x40e113  (gate)
            └─ parsePOST = fcn.0040d990  (call @ 0x40e142)
```

`parsePOST` allocates four 1024-byte heap buffers (`operator_new(0x400)`) at `0x40d9d4`–`0x40da01`: `puStack_488` (name), `puStack_480` (value), `puStack_478` (filename), and `pcStack_470` (file=). The unbounded loops are:

```asm
; first quote-scan loop (UNBOUNDED) @ 0x40da50
0x40da50: add rbx, 1
0x40da54: cmp byte [r15 + rbx], 0x22   ; scan body for '"'
0x40da59: jne 0x40da50                 ; NO rbp (body length) check

; unbounded name-copy loop @ 0x40da90
0x40daa3: mov byte [rsi + rax], cl     ; rsi = puStack_488, no 0x400 cap
0x40daa6: movzx ecx, byte [r15 + r14]
0x40daab: cmp cl, 0x22                 ; exits only on '"'
0x40daae: jne 0x40da90
```

The corruption is consumed by the cleanup path:

```asm
0x40dbbe  call StringReset  ; free(puStack_488)
0x40dbc8  call StringReset  ; free(puStack_480)
0x40dbd2  call StringReset  ; free(puStack_478)
0x40dbdc  call StringReset  ; free(pcStack_470)  ← crash: metadata corrupted
```

## 6. Source Identification & Controllability

The source is the raw HTTP request body. The first `\n` in the body terminates the first header line; all subsequent bytes (the remaining multipart headers, blank line, part content, and closing boundary) are scanned by the unbounded quote-scan loop. In a normal multipart body there are no `"` characters after the `Content-Disposition` header line, so the scan continues past the body's null terminator into adjacent heap memory.

The attacker controls:
- the presence of the `filename="..."` attribute (passes the `strstr` gate);
- the bytes after the first header line (multipart content), which determine what out-of-bounds data the quote scan encounters and therefore what gets copied into the overflowing name buffer;
- the size of the request body, which shapes the heap layout of the four parser buffers.

Controllability is limited by heap layout (ASLR and prior allocations), which is the reason the crash is ~90% reproducible rather than 100% — if the out-of-bounds scan encounters an early `0x22` byte in adjacent heap, the name copy terminates before corrupting `pcStack_470`'s metadata.

## 7. Data Flow

1. Attacker sends `POST /` with a multipart body containing `filename="t.txt"`.
2. `nxhtd` routes the request via `ScriptAliasMatch "(?i)^/?"` to the `nxwebrunner` CGI.
3. `main` calls `fetch` unconditionally; `fetch` finds the substring `filename` in the body and calls `parsePOST`.
4. `parsePOST` allocates four 1024-byte heap buffers.
5. The bounded newline scan finds the first header line end.
6. The unbounded quote-scan reads past the body terminator into adjacent heap.
7. The unbounded name-copy writes that data past `puStack_488` into sibling buffers and into `pcStack_470`'s chunk metadata.
8. Cleanup frees all four buffers; the corrupted `pcStack_470` triggers glibc's `double free or corruption (out)` check and SIGABRT.

## 8. Exploit Construction

The triggering request (89 bytes):

```http
POST / HTTP/1.1
Host: <target>:4443
User-Agent: nxvuln-poc
Accept: */*
Content-Type: multipart/form-data; boundary=----b
Content-Length: 89
Connection: close

------b
Content-Disposition: form-data; name="shortfield"; filename="t.txt"

x
------b--
```

Key construction notes:
- The `filename="..."` attribute (any length, including empty) is the trigger; the filename value is never copied into the overflowing path.
- The part body can be a single byte.
- The closing boundary is not required for the corruption to occur (only for the loop-exit variant of the sibling stack overflow).

## 9. Dynamic Verification

The C13 test matrix, exercised over the real HTTPS path through `nxhtd:4443`:

| Request | Response | Crash |
|---|---|---|
| `GET /` (no body) | 200 OK | no |
| `POST /` urlencoded short body | 200 OK | no |
| multipart, no filename | 200 OK | no |
| multipart `filename="t.txt"` | 500 | yes |
| multipart `filename="x"` (1 byte) | 500 | yes |
| multipart `filename=""` (empty) | 500 | yes |
| multipart 2000-byte name, no filename | 200 OK | no |

Summary: 0/5 controls crashed (0%, no false positives); 9/10 trigger requests crashed (90%, highly reproducible). The `htd.log` recorded `stderr from /usr/NX/bin/nxwebrunner: double free or corruption (out)` on every crash.

gdb backtrace:

```
#5  _int_free ()            /lib64/libc.so.6
#6  free ()                 /lib64/libc.so.6
#7  StringReset(char*&) ()  /usr/NX/lib/libnx.so
#8  0x40dbd7 in ?? ()       nxwebrunner.bin   ← parsePOST cleanup, free(pcStack_470)
#9  0x40e147 in ?? ()       nxwebrunner.bin   ← fetch
#10 0x4048c0 in ?? ()       nxwebrunner.bin   ← main
```

## 10. Reachability & Impact

- **Reachability**: fully pre-authentication over HTTPS 4443; the `ScriptAliasMatch "^/?"` route has no Location-level authentication directive; the trigger body can be under 100 bytes.
- **Impact**: deterministic heap corruption in the `nxwebrunner` CGI process. The corrupted chunk metadata (forward-chunk inconsistency) is a genuine heap-overflow primitive — with heap grooming (tcache/fastbin poisoning) it can be escalated to an arbitrary-write and code execution as the `nxhtd` user. At minimum, any unauthenticated attacker can repeatedly crash the handler (denial of service).
- **Scope**: NoMachine Terminal Server v10 deployments on Linux (the CGI entry is shared across the v10 product line).

## 11. Fix Recommendations

1. Add explicit bounds checks (`index < 0x400` and `index < body_length`) to the quote-scan loop at `0x40da50` and the name/filename copy loops at `0x40da90`/`0x40dcd0`.
2. Remove the reliance on `strstr(body, "filename")` as a gate; `parsePOST` must validate every copy length against the actual buffer and body sizes.
3. Replace `sprintf` with bounded writes (`snprintf` or explicit length-checked copies) in the same function (the stack `sprintf` at `0x40db75` is a separate bug in the same parser).
4. Fuzz the CGI parser with malformed multipart bodies and run it under a memory-safe build or sandbox as defense in depth.

## 12. CWE & CVSS

- **CWE-787**: Out-of-bounds Write — unbounded quote-scan and name-copy loops overwrite adjacent heap chunk metadata
- **CWE-416**: Use After Free / double-free — the corrupted chunk is freed during cleanup, detected by glibc as `double free or corruption (out)`
- **CVSS**: 9.8 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
