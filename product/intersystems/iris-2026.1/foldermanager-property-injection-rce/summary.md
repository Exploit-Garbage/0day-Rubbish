# InterSystems IRIS FolderManager Property Injection RCE

## Summary

A critical unauthenticated remote code execution vulnerability in InterSystems IRIS allows attackers to execute arbitrary operating system commands as the `irisowner` account through property injection into the `%DeepSee.UI.FolderManager` Zen page combined with compile-time code execution via `$system.OBJ.Load`.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: InterSystems IRIS
- **Versions**: 2026.1.0.234.1 (Community Edition) and versions using the same FolderManager / broker surface
- **Vendor**: InterSystems

## Impact

- **Confidentiality**: Complete system compromise; the `irisowner` account can read the entire IRIS installation tree and any data accessible to the IRIS process
- **Integrity**: Arbitrary operating system command execution; ability to write the entire IRIS installation tree (`/usr/irissys/csp/sys/`, `/csp/user/`, `/mgr/`, `/bin/`, `/lib/`)
- **Availability**: Full control of the IRIS process and host command execution

## Mitigation

1. Validate the source of the `directory` and `selectedFiles` properties in `ImportItems`; derive them from server-side session state rather than trusting client-submitted property values
2. Disable the `OBJ.Load` compile (`c`) flag for low-privilege accounts such as `CSPSystem`; compile-time execution of an `objectgenerator` body is equivalent to code execution
3. Do not hardcode the `CSPSystem` default password as `SYS`; force a randomly generated password at install time and require a change on first login
4. Restrict the `ReceiveFragment` write path to directories that cannot be loaded by `OBJ.Load`; the current write target overlaps with the `OBJ.Load` load path, forming a write→load→compile→exec chain

## Timeline

- **Discovered**: 2026-07-16
- **Public Disclosure**: 2026-07-16

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).