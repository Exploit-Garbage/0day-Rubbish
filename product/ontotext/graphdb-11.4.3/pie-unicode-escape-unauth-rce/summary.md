# Ontotext GraphDB .pie Ruleset Namespace Prefix Injection Unauthenticated Root RCE

## Summary

A critical unauthenticated remote code execution vulnerability in Ontotext GraphDB 11.4.3 Free edition arises because the default configuration sets `security=false`, bypassing the entire Spring Security filter chain, so `/rest/repositories/ruleset/upload` and `/repositories/*` are anonymously reachable. After uploading a .pie ruleset, `RuleCompilerBase.compilePrefices` (line 297) inlines the namespace prefix verbatim into the runtime-compiled Java source (`namespaces.put("<prefix>", "<uri>")`) with only `.trim()` and no validation. An attacker injects Java code in the prefix; javac compiles and loads it; creating a `graphdb:Sail` repository triggers `infer.initialize()` which runs the injected `Runtime.exec` as the GraphDB process user (root). No authentication and no license are required. This is a bypass variant of the GDB-14528 fix (11.4.1), which only added ParsedIRI validation on the axiom entity, not the namespace prefix. Dynamically verified.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Ontotext GraphDB
- **Versions**: 11.4.3 (and earlier versions vulnerable to the same namespace-prefix injection, i.e. before the prefix validation exists)
- **Vendor**: Ontotext / Graphwise

## Impact

- **Confidentiality**: Full read of the host filesystem and configuration as root
- **Integrity**: Arbitrary OS command execution as root (GraphDB process user)
- **Availability**: Full control of the GraphDB host; ability to persist

## Exploitation Prerequisites

Default configuration (`security=false`); network reachability to the GraphDB HTTP listener (workbench, default 7200). The .pie upload, repository creation, and init trigger are all anonymous. The chain requires no credentials, no license, and no operator action. Dynamically verified with `uid=0(root)`.

## Mitigation

1. Set `security=true` by default (or in every deployment) so the Spring Security filter chain is active
2. Validate/sanitize the namespace prefix in `RuleCompilerBase.compilePrefices` (not only `.trim()`)
3. Restrict ruleset upload and repository creation to authenticated administrators
4. Do not compile user-supplied rules with the system `javac` in the server process; sandbox or remove the runtime compiler
5. Do not run GraphDB as root; run under a dedicated low-privilege user

## Timeline

- **Discovered**: 2026-08-08
- **Public Disclosure**: 2026-08-09 (batch #3)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
