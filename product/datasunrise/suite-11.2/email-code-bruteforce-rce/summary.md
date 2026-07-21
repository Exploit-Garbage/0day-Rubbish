# DataSunrise Suite Email Verification Code Brute Force RCE

## Summary

A critical remote code execution vulnerability in DataSunrise Suite allows attackers to take over the `admin` account and execute arbitrary operating system commands through brute force of a 6-digit email verification code, combined with a missing TTL enforcement, no rate limiting, and an in-memory flag check that bypasses the database email-verification state.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: DataSunrise Suite
- **Versions**: 11.2.17.12820 and versions using the same forgotten-password flow
- **Vendor**: DataSunrise

## Impact

- **Confidentiality**: Full administrative takeover of the database security platform; access to all audited/masked data and configuration
- **Integrity**: Arbitrary operating system command execution as the `datasunrise` account; ability to alter audit and firewall policy
- **Availability**: Full control of the AppBackendService process and host command execution

## Exploitation Prerequisites

This is **not** a default-configuration unauthenticated RCE. It requires the `admin` mailbox to be configured and verified (`emailConfirmationStatus=1`), which is a non-default state. A pristine install has no admin mailbox and the chain is blocked at the first step. The prerequisite is commonly satisfied in production where administrators configure an admin mailbox to receive alerts. SMTP configuration is not required — the verification code is stored in memory before the email send is attempted, so SMTP send failure does not affect the brute force.

## Mitigation

1. Enforce the 60-second TTL on `EmailCode::verify`; the timestamp is stored but never read
2. Add rate limiting and lockout to `checkEmailCode`; the current implementation returns `res:false, error:0` with no ban or throttle
3. Make `resetForgottenPassword` validate the database `emailConfirmationStatus` field rather than the in-memory `isVerified` flag set by `checkEmailCode`
4. Decouple verification-code generation from the email-send step so that a failed SMTP send does not leave a valid code in memory

## Timeline

- **Discovered**: 2026-07-13
- **Public Disclosure**: 2026-07-13

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).