# GigaSpaces XAP Unauthenticated Path Traversal to Root RCE

## Summary

A critical unauthenticated remote code execution vulnerability in GigaSpaces InsightEdge Enterprise 16.1.1 (XAP In-Memory Data Grid) allows remote attackers to write a JSP webshell to the web application root of the Web Management Console through a path traversal flaw in the `FileUploadServlet`. With security disabled by default (CWE-306), the entire chain is unauthenticated, and the webui process runs as `root`, resulting in arbitrary command execution as `root`.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: GigaSpaces InsightEdge Enterprise (XAP IMDG), Web Management Console
- **Versions**: 16.1.1
- **Vendor**: GigaSpaces

## Impact

- **Confidentiality**: Full system compromise; arbitrary command execution as `root`
- **Integrity**: Arbitrary file write via path traversal, including JSP webshell deployment
- **Availability**: Full control of the management host and data grid

## Mitigation

1. Enable security (`security enabled:true`) and enforce authentication on all Web Management Console endpoints
2. Sanitize and canonicalize upload paths; reject any path escaping the intended upload directory
3. Run the Web Management Console as an unprivileged account instead of `root`
4. Restrict the management port (8099) to trusted networks

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
