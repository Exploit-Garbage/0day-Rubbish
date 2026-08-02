# CatDV Server Factory-Default Empty Admin Password

## Summary

CatDV Server 10.7.8 ships with a factory-default database seed (`create_catdv.sql:294`) that creates the `admin` user with `password=0` and `passwordHash=NULL`. The password verification routine `Encryption.a(password, passwordHash, storedPassword)` skips the PBKDF2 path when `passwordHash` is `null` and falls back to a legacy `simpleMD5Hash` path, where `simpleMD5Hash("")` returns `0` and `0 == 0` evaluates to true. The result is that anyone who can reach the CatDV web login endpoint can authenticate as the built-in administrator using `admin` with an empty password, as long as the factory-default password has not been changed. This grants full administrator control of the media asset management server (catalog data, server configuration, and all admin-gated REST/RMI handlers) and is the credential prerequisite for the authenticated root RCE chain.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: CatDV Server
- **Versions**: 10.7.8 and versions using the same `create_catdv.sql` admin seed and `Encryption.a` legacy `simpleMD5Hash` fallback
- **Vendor**: Square Box Systems (UK; MAM business acquired by Quantum)

## Impact

- **Confidentiality**: Full administrator access to the media asset management server and all media/catalog metadata it holds; the admin session can read any catalog, setting, or user data
- **Integrity**: Administrator can alter catalog data, server configuration, user accounts, and any admin-gated setting; this is the credential prerequisite for injecting attacker-controlled server-config properties
- **Availability**: Administrator can stop the service, delete catalogs, and reconfigure or break the server state

## Exploitation Prerequisites

This is a default-credentials issue. The single precondition is that the deployment has not changed the factory-default `admin` password (the `create_catdv.sql:294` seed of `password=0, passwordHash=NULL`). The attacker supplies no prior credential: the username is the well-known built-in `admin` and the password is empty. The CatDV web port (8181 by default) must be reachable from the attacker's network position; in typical deployments it is reached via the server host. On deployments where the admin password has been changed, this specific credential issue is not exploitable, but the underlying `Encryption.a` legacy fallback and the `simpleMD5Hash("")=0` behavior remain as a latent weakness.

## Mitigation

1. The factory default must not seed an empty-password `admin` account; `create_catdv.sql` should require a strong, non-empty password hash for the seeded admin user.
2. First startup should detect `admin` with `passwordHash=NULL` and force a password-change wizard before any login is permitted.
3. `Encryption.a` must not fall back to the legacy `simpleMD5Hash` path when `passwordHash` is null; PBKDF2/Argon2 should be mandatory for all accounts.
4. `simpleMD5Hash` must not return a fixed value for an empty string; empty-password login attempts must be rejected outright.
5. The login endpoint should reject empty passwords before invoking the password verification routine.

## Timeline

- **Discovered**: 2026-07-27
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
