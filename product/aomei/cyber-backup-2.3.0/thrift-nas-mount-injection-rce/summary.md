# AOMEI Cyber Backup Unauthenticated Thrift NAS Mount Injection RCE

## Summary

A critical unauthenticated remote code execution vulnerability in AOMEI Cyber Backup allows attackers who can reach the internal Thrift ports to execute arbitrary operating system commands as root. The internal Thrift services on ports 9074 (RpcDaoForAUBService) and 9078 (RpcVMBackupNode) expose no authentication gate, bypassing the 9072 Gateway JWT entirely. An attacker persists an injected NAS credential through `AddBackupStorageNAS` (9074) and then triggers `DeleteBackupStorage` (9078), whose async lambda builds a CIFS `mount` command with `system()` using unescaped, single-quote-wrapped username/password fields. A single-quote escape in the username field injects an arbitrary shell command that runs as root inside the container.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: AOMEI Cyber Backup
- **Versions**: 2.3.0 and versions using the same Thrift NAS mount flow
- **Vendor**: AOMEI

## Impact

- **Confidentiality**: Full root read of the backup infrastructure container, including backup metadata, stored credentials, and configuration
- **Integrity**: Arbitrary operating system command execution as root (uid=0); ability to alter backup storage records and tamper with backup data
- **Availability**: Full control of the VmBackupNode process and the host container; ability to disrupt or destroy backup operations

## Exploitation Prerequisites

This is a remote unauthenticated RCE, but it is **not** a default-Internet-exposed primitive. It requires network reachability to the internal Thrift ports 9074 and 9078, which bind to the container's internal network (e.g. `<target-host>`). Reachability is satisfied when an attacker is on the same Docker bridge network, in another container on the same host, or when the ports are mapped to the host or otherwise exposed. No credentials, no MITM, and no user interaction are required. The container runs as root by default with no capability drop and no seccomp restriction on `system()`.

## Mitigation

1. Enforce authentication on the 9074/9077/9078 Thrift ports (reuse the Gateway JWT or require mTLS); reject unauthenticated direct Thrift calls
2. Bind the internal Thrift ports to 127.0.0.1 or a dedicated internal Docker network so they are never reachable outside the container fabric
3. Replace `system()` + shell string concatenation in `CNasHelper` with `execve` array-argument execution, or apply a strict allowlist character filter on username/password fields and escape single quotes
4. Drop container privileges to a non-root user and trim capabilities; do not run the VmBackupNode process as uid=0
5. Add input validation in `AddBackupStorageNAS` for `uriPath` / `authName` / `authPass` that rejects shell metacharacters (`'`, `;`, `|`, `&`, `$`, backtick)

## Timeline

- **Discovered**: 2026-07-31
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
