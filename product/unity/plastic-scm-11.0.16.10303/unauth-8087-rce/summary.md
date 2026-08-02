# Plastic SCM (Unity VCS) Unauthenticated 8087 Name-Only ACL RCE

## Summary

A critical unauthenticated remote code execution vulnerability in the on-premises build of Plastic SCM (Unity Version Control, `plasticd`) allows any network attacker who can reach the default-bound 8087 RAW TCP protocol port to execute arbitrary operating system commands as the `plasticd` service account. The chain combines the default `NameWorkingMode` authentication mode, which validates only that a client-declared username maps to a local OS account and never checks a password (`LocalGroupSEIDProvider.CheckPassword` is an empty no-op), with a default `EVERYBODY` ACL that grants `ALL_PERMISSIONS` (including `mktrigger`) to any name-only-authenticated user. An attacker declares an administrative username (leakable unauthenticated via `GetRepositoryServerInfo`), creates a server-side trigger whose `Path` is fully attacker-controlled, and triggers it with a repository operation; `TriggerProcess.ExecuteTrigger` feeds the `Path` straight into `Process.Start` with no sandbox, path allowlist, or signature check.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Plastic SCM (Unity Version Control On-Prem / UVCS)
- **Versions**: 11.0.16.10303 and releases sharing the default `NameWorkingMode` + 8087 `plasticd` protocol surface
- **Vendor**: Unity Technologies (acquired Codice Software, the original Plastic SCM author, in 2020)

## Impact

- **Confidentiality**: Full compromise of the version-control server and all repositories; the `plasticd` service account can read source code, repository metadata, and any data accessible to that account
- **Integrity**: Arbitrary operating system command execution as the `plasticd` service account (Linux: `plasticscm` uid=217; Windows: local Administrator / service account); attacker can create triggers, alter repositories, and persist access
- **Availability**: Full control of the `plasticd` process and host command execution; the server can be disabled or reconfigured at will

## Exploitation Prerequisites

This is a **default-configuration** unauthenticated RCE. The chain is exploitable when all of the following hold, each of which is the shipping default:

1. Network reachability to the `plasticd` 8087 port (default bind `0.0.0.0`, `RejectRemoteRequests` default `false` — accepts remote connections)
2. Server `WorkingMode` is `NameWorkingMode` (the default; validates username only, no password)
3. The attacker knows one local OS username on the server. The repository-server owner (administrative) username is leaked unauthenticated by `GetRepositoryServerInfo` (method 1012); common service-account names (`root` / `Administrator` / `plasticscm`) are also viable. The username must correspond to a real local OS account, but the password is never checked.
4. The attacker machine has the official `cm` CLI (Unity VCS client, free download) installed; the PoC drives it via subprocess.

## Mitigation

1. Require a shared secret / password to establish a SEID under `NameWorkingMode`, or restrict trigger creation (and other sensitive operations) to a separately authenticated administrative channel; do not treat "client declares a name" as equivalent to "client is that user"
2. Default to `RejectRemoteRequests=true` and raise a loud warning when `NameWorkingMode` is combined with a non-loopback bind
3. `IsAdministrator` must not be satisfied by a client-declared username alone (without credentials)
4. Validate trigger `Path` against a path allowlist / signature check / sandboxed execution; do not feed attacker-controlled strings straight into `Process.Start`
5. User-side mitigation: bind 8087 to loopback or firewall-restrict source IPs; switch to `UPWorkingMode` / `LDAPWorkingMode` / `TokenBasedAuthentication`; set `RejectRemoteRequests=true`; run the `plasticd` service account as a low-privilege user (not `root` / `Administrator`)

## Timeline

- **Discovered**: 2026-08-02
- **Public Disclosure**: 2026-08-10

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
