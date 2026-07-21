# DataSunrise Suite Email Verification Code Brute Force RCE - Technical Analysis

## Overview

DataSunrise Suite 11.2.17.12820 ships a self-developed C/C++ service, `AppBackendService`, listening on port 11000 (HTTPS), exposing a JSON-RPC interface at `/web_iface` with 529 RPC functions. The forgotten-password flow combines four independent defects into an unauthenticated RCE primitive: (1) `requestEmailCode` stores a 6-digit code in memory before the SMTP send is attempted, so SMTP failure does not prevent the code from existing; (2) `EmailCode::verify` stores a 60-second TTL timestamp but never reads it; (3) `checkEmailCode` has no rate limiting or lockout; (4) `resetForgottenPassword` validates an in-memory `isVerified` flag rather than the database `emailConfirmationStatus` field. Brute forcing the 10^6 code space (~30 minutes at ~450 req/s with 32 workers) sets the in-memory flag, resets the admin password, and unlocks `runShellAction` for arbitrary command execution as the `datasunrise` account.

## Architecture

```
L1 external access: 11000 (HTTPS)
L2 boundary: TLS (built into AppBackendService)
L3 gateway: WebHandlerBackend - 5-route dispatch (/web_iface, /backend_internal_iface, /backend_tfa_iface, /download, /api)
L4 auth: kAllowedBeforeConnect allowlist (9 functions + getSecureKey/getCookie) + session_id check
L5 business: RpcParser/RpcHandler - 529 RPC funcs
L6 storage: SQLite (config/users) + in-memory session table + in-memory EmailCode table
```

**JSON-RPC format**: `{"func":"<name>","data":<obj>,"queryID":1,"session_id":<-1|id>,"serverID":<id>}`

## Authentication Boundary

The `kAllowedBeforeConnect` allowlist (`@0x12f5480`) admits 9 functions plus `getSecureKey`/`getCookie` without a valid session:

| # | Function | Purpose |
|---|----------|---------|
| 1 | initConnect | session init, returns secureKey/session_id/publicKey |
| 2 | connect | auth (login+hash+passwd) |
| 3 | connectSso | SSO auth |
| 4 | resetPassword | password reset (forgotten=true reachable unauthenticated) |
| 5 | requestEmailCode | request email verification code |
| 6 | checkEmailCode | verify email verification code |
| 7 | requestVerificationCode | request verification code |
| 8 | verifyCode | verify code |
| 9 | initConnectExternal | external auth init |

Of the 529 functions, 11 are reachable unauthenticated; the remaining 518 (including `runShellAction`) require authentication and return `err=5 "The client session ID is not valid"`.

## Stage 1: Code Generation Decoupled from Email Send

`RpcHandler::requestEmailCode @ 0x842830` branches on `reason`: `reason=1` (emailConfirmation) enters unconditionally; `reason=2` (forgottenPassword) requires the admin mailbox to be verified (`iStack_cc==1`).

`EmailCode::set @ 0xb50960` is called **before** `sendSecurityEmail`, storing the code in memory (login@0x38, type@0x30, code@0x58, timestamp@0x28, isVerified@0x20). Even if SMTP send fails (no SMTP configured), the code already exists in memory:

```
POST /web_iface {"func":"requestEmailCode","data":{"login":"admin","reason":2},"session_id":-1}
-> {"res":true,"error":0}   # code generated and stored in memory
```

## Stage 2: Missing TTL Enforcement

`EmailCode::verify @ 0xb4f9e0` stores a `0x3c` (60-second) timestamp in `EmailCode::set`, but the `verify` function only checks:

1. type match (`*(arg1+0x30) != arg2`)
2. length (`*(arg1+8)`)
3. `memcmp` comparison

It **never reads the timestamp** — no TTL check. Dynamic proof: a code was still matched by `checkEmailCode` **1832 seconds (~30 minutes)** after `requestEmailCode` was called. A real 60-second TTL would make a 30-minute brute force impossible.

## Stage 3: No Rate Limiting

`RpcHandler::checkEmailCode @ 0x7fa1e0` returns `res:false, error:0` for a wrong code — no error, no ban, no throttle. Brute force measurement with 32 concurrent workers over 000000-999999:

```
hit code: 828541
elapsed: 1832 seconds (~30 minutes)
rate: ~450 req/s
rate limit: none
lockout: none
```

`checkEmailCode(828541)` returns `res:true` -> in-memory `isVerified=1` is set, the code is cleared.

## Stage 4: In-Memory Flag Bypasses Database State

`RpcHandler::resetForgottenPassword @ 0x837bb0` calls `EmailCode::isVerified(login, type=2)` to check the **in-memory `isVerified` flag** (set by `checkEmailCode` success as `puVar3[4]=1`), **not** the database `emailConfirmationStatus` field. Brute-forcing the code sets the in-memory flag, bypassing the database email-verification state.

```
POST /web_iface {"func":"resetPassword","data":{"login":"admin","forgotten":true,"new_hash":"sha512<sha512(new_password)>"},"session_id":<sid>}
-> {"result":true,"error":0}   # admin password reset
```

Verification: old password login -> `res:false`; new password login -> `res:true, roleType:1`.

## Stage 5: runShellAction RCE

```
POST /web_iface {"func":"runShellAction","data":{"command":"touch /tmp/DS_UNAUTH_RCE_CONFIRMED","disableOutput":false,"runOnAllServers":false},"session_id":<sid>,"serverID":1}
-> {"taskIDs":[14],"error":0}
```

`RpcParser::runShellAction @ 0x93c290` -> `RpcHandler::runShellAction @ 0x818ca0` -> `SystemShellActionTask::startManually` -> **execvp(argv)** (not `/bin/sh -c`). The auth gate `AccessChecker::mustHasAccess(userId, 0x4d=SystemShellActionTask, 6=exec)` requires admin (`roleType=1`). The marker file is created by the `datasunrise:datasunrise` user.

## Exploitation Prerequisites (Honest Disclosure)

This is **not** a default-configuration unauthenticated RCE. A pristine install has no admin mailbox, and `requestEmailCode reason=2` returns `error:10 "User has no email set"`, blocking the chain at the first step. The prerequisite is `admin` mailbox configured and verified (`emailConfirmationStatus=1`), which is non-default but common in production (administrators configure an admin mailbox to receive alerts). SMTP configuration is not required — the code is stored in memory before the email send is attempted.

| Scenario | Exploitable |
|----------|-------------|
| admin mailbox configured + verified, SMTP configured | Yes - remote RCE |
| admin mailbox configured + verified, SMTP unconfigured/unreachable | Yes - remote RCE |
| pristine default install (no admin mailbox) | No - blocked at requestEmailCode |
| admin mailbox set but unverified | No - "User email is not verified" |

## Complete Attack Sequence

1. **Reach the unauthenticated surface**: identify port 11000 and call `initConnect` to obtain a `session_id`
2. **Generate a code**: call `requestEmailCode(login=admin, reason=2)` (requires admin mailbox verified) — the code is stored in memory regardless of SMTP success
3. **Brute force the code**: 32 concurrent workers enumerate 000000-999999 against `checkEmailCode` (~30 minutes, no rate limit) — a hit sets the in-memory `isVerified` flag
4. **Reset the admin password**: call `resetPassword(forgotten=true)` with a new sha512 hash — validates the in-memory flag, not the database state
5. **Authenticate as admin**: call `connect` with the new password — obtain `roleType=1`
6. **Execute OS command**: call `runShellAction(command, serverID=1)` — `execvp` runs the command as the `datasunrise` user