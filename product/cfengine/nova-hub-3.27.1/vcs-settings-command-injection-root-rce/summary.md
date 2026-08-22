# CFEngine Enterprise Nova Hub — VCS Settings Command Injection → Root RCE

## Summary

An authenticated remote code execution vulnerability in CFEngine Enterprise Nova Hub 3.27.1. An admin sends `POST /api/vcs/settings` with a crafted `gitServer` value; `VcsApi::generateScriptFromTemplates` writes it into `params.sh` quoting only `"` without escaping `$`, backticks, or `()` (CWE-78/CWE-88). The shell script is later `source`d by `masterfiles-stage.sh:142` in a cf-agent `commands` promise running as **root**, so the injected `$(...)` executes arbitrary commands as uid=0.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: CFEngine Enterprise Nova Hub
- **Versions**: 3.27.1 (other versions with the same `generateScriptFromTemplates` quoting are likely affected)
- **Vendor**: Northern.tech AS

## Impact

- **Confidentiality**: Full compromise of the configuration-management hub as root
- **Integrity**: Arbitrary command execution via shell command substitution
- **Availability**: Full control of managed infrastructure policy distribution

## Mitigation

1. Use `escapeshellarg`/`escapeshellcmd` on `gitServer` (and all template parameters)
2. Escape `$`, backticks, `(`/`)`, `{`/`}` in the template replacement map
3. Avoid `source`ing user-influenced shell variables; write params as config data instead of executable script
