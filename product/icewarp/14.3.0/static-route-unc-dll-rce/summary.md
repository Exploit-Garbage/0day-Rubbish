# IceWarp Server Static Route External Filter UNC DLL Remote Code Execution

## Summary

A high-severity remote code execution vulnerability in IceWarp Server 14.3.0 allows a server administrator to configure a static route external filter pointing to an attacker-controlled UNC path. The SMTP delivery engine loads the referenced DLL via `LoadLibraryA()` without any path validation (no `PathIsUNC`, no canonicalization), so the DLL is fetched over SMB and executed in the `smtp.exe` process, which runs as `NT AUTHORITY\SYSTEM`. Triggering requires no SMTP authentication, turning an authenticated configuration write into remote SYSTEM code execution.

## CVSS Score

- **Score**: 9.0 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: IceWarp Server
- **Versions**: 14.3.0
- **Vendor**: IceWarp

## Impact

- **Confidentiality**: Full system compromise; `NT AUTHORITY\SYSTEM`
- **Integrity**: Arbitrary code execution in the mail server process
- **Availability**: Full control of the mail server host and mail data

## Mitigation

1. Validate that external filter paths are local paths and reject UNC paths in the server administrator API
2. Run the SMTP service under a least-privilege account instead of SYSTEM
3. Restrict SMB outbound access from mail servers (block outbound 445) to prevent remote DLL loading
4. Audit static route external filter settings for unexpected UNC paths

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
