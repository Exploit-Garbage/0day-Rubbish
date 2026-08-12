# Kerio Connect Server.startEncryption Command Injection Authenticated RCE

## Summary

Kerio Connect 10.0.9 Patch 2 (build 10320) WebAdmin JSON-RPC method `Server.startEncryption({password})` concatenates the attacker-controlled `password` parameter into a shell string (`echo -n "<password>" | cryptsetup ... luksFormat <device>`) with no shell metacharacter escaping, and passes it to `system()` (libc). A FullAdmin user injects a double-quote breakout; the injected command executes in the mailserver process context, which runs as `root` inside the container. Dynamically verified with unique sentinels (`uid=0(root)`).

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Kerio Connect
- **Versions**: 10.0.9 Patch 2 (build 10320)
- **Vendor**: GFI Software

## Impact

- **Confidentiality**: Full control of the mailserver host as root
- **Integrity**: Arbitrary command execution as root
- **Availability**: Full control of mail services and mail storage

## Exploitation Prerequisites

A FullAdmin WebAdmin account (the administrator account set during the install wizard), network reachability to the HTTPS WebAdmin port (4040), and a server in the decrypted state (or an attacker who decrypts it first via `Server.stopEncryption`). WebAdmin does not require a license.

## Mitigation

1. Replace the `system()` shell invocation with `execvp`/`posix_spawn` and pass the password via stdin (cryptsetup supports stdin passwords)
2. If a shell is required, strictly escape shell metacharacters or enforce an allowlist
3. Run the mailserver under a dedicated low-privilege account instead of root

## Timeline

- **Discovered**: 2026-08-10
- **Public Disclosure**: 2026-08-12 (batch #4)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble.
