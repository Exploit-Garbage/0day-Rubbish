# Voicent Call Center SaveFileServlet Unauthenticated Root RCE

## Summary

A critical unauthenticated remote code execution vulnerability in Voicent Call Center Suite 10.10.1 allows remote attackers to write a JSP webshell to the web application root through the `SaveFileServlet`. The servlet's `forwardpage` parameter short-circuits authentication at the code level (config-independent), and the `target` parameter controls the write location without adequate restriction. The shipped `web.xml` has no security constraints and the default installation has an empty server password, so the entire chain is unauthenticated and results in arbitrary command execution as `root`.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Voicent Call Center Suite
- **Versions**: 10.10.1
- **Vendor**: Voicent

## Impact

- **Confidentiality**: Full system compromise; arbitrary command execution as `root`
- **Integrity**: Arbitrary file write to the webroot (JSP webshell deployment)
- **Availability**: Full control of the call center server, recordings, and customer data

## Mitigation

1. Enforce authentication at the container level with security-constraints / filters
2. Remove the `forwardpage` authentication short-circuit in `SaveFileServlet`
3. Restrict upload targets to a non-webroot directory with an extension allowlist
4. Force a non-empty server password at install time

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
