# Xeams SQLRunner.jsp Unauthenticated Derby Hardcoded Cred JSP Webshell RCE

## Summary

A critical unauthenticated remote code execution vulnerability in Xeams mail server allows an attacker to execute arbitrary commands as the Xeams process user (root in the default lab deployment) by directly accessing the built-in `SQLRunner.jsp` administrative page. The Xeams web application ships with no `security-constraint` in `web.xml`, its `SynaFilter` only maps `/FrontController/*` (not `*.jsp`), and the `NewPageHeader.jsp` include does not enforce authentication. Directly requesting `SQLRunner.jsp` therefore bypasses the `FrontController` dispatch, the `SynaFilter`, and the `Ja.java` operation-level authorization checks. The `operation=1` branch of `SQLRunner.jsp` performs no authentication check and connects to the embedded Derby database using attacker-supplied credentials; Xeams hardcodes the Derby database-owner credentials `system/manager` in `db/Ea.java`, so an attacker reuses them to establish a JDBC session. With the connection stored in the HTTP session, `operation=2` issues an arbitrary SQL statement; calling the Derby procedure `SYSCS_UTIL.SYSCS_EXPORT_QUERY` writes an attacker-controlled JSP webshell into the Tomcat `webapps/ROOT` docBase. A subsequent GET request triggers Jasper on-demand compilation and execution, yielding arbitrary command execution. The chain requires only HTTP access to the Xeams web port (default 5272/TCP), no valid login, no CSRF token, and no prior session.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Xeams
- **Versions**: 10.3 build 6449 and versions sharing the `SQLRunner.jsp` unauthenticated `operation=1` branch, the hardcoded `system/manager` Derby credentials in `db/Ea.java`, and the Jasper-served `webapps/ROOT` docBase
- **Vendor**: Synametrics Technologies

## Impact

- **Confidentiality**: Full read of the Xeams mail repository and the host filesystem at the Xeams process privilege; the RCE was verified to read arbitrary host files
- **Integrity**: Arbitrary command execution on the mail server host; ability to alter mail, configuration, and the embedded Derby database
- **Availability**: Full control of the Xeams process and host; ability to stop the service or destroy data

## Exploitation Prerequisites

This is an **unauthenticated RCE** against the Xeams web administration port. The `SQLRunner.jsp` `operation=1` branch performs no authentication check, and direct `*.jsp` access bypasses the `FrontController`/`SynaFilter`/`Ja.java` authorization pipeline because `web.xml` declares no `security-constraint` for JSPs and `SynaFilter` is mapped only to `/FrontController/*`. The Derby database listens on `127.0.0.1:7865` and is not directly reachable from the network, but `SQLRunner.jsp operation=1` connects to it from inside the Xeams JVM on the attacker's behalf, so no direct Derby access is required. The only deployment condition is that the Xeams web port (default 5272/TCP) is reachable from the attacker; in the lab this port was firewalled to localhost and the chain was verified over loopback, but any deployment that exposes 5272 to the attacker is exploitable. When Xeams runs as root (the lab deployment posture), the resulting command execution is root.

## Mitigation

1. Add a `security-constraint` in `web.xml` covering `SQLRunner.jsp` and all administrative JSPs, or enforce an authentication redirect in `NewPageHeader.jsp` so direct `*.jsp` access is rejected without a valid session
2. Extend `SynaFilter` to cover `*.jsp` so all JSP access is forced through the authentication filter, not only `/FrontController/*`
3. Remove `SQLRunner.jsp` from production builds, or restrict it to local access plus strong authentication; it is a database administration tool and should not ship in a production mail server
4. Remove the hardcoded `system/manager` Derby credentials from `db/Ea.java`; generate random credentials at install time and store them in the configuration
5. Revoke `SYSCS_UTIL` procedure execution privileges from the application Derby user so `SYSCS_EXPORT_QUERY` cannot write arbitrary files even if SQL execution is reached
6. Do not run Xeams as root; privilege reduction limits the impact of any successful RCE

## Timeline

- **Discovered**: 2026-07-31
- **Public Disclosure**: August 10, 2026

## Credits

Discovered by 0day Rubbish Research Team using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
