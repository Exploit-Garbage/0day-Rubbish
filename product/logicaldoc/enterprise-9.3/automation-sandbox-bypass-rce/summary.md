# LogicalDOC Enterprise — Automation Scripting Sandbox-Bypass RCE

## Summary

An authenticated remote code execution vulnerability in LogicalDOC Enterprise Edition 9.3. The Automation Scripting feature evaluates admin-authored scripts with Apache Velocity. The CVE-2024-54448 fix only added a `forbidRuntimeUsage` string/pattern blacklist for `java.lang.Runtime`; it is insufficient in 9.3, leaving reflection available through the default UberspectImpl, so a crafted Automation script bypasses the sandbox and achieves arbitrary Java code execution in the Tomcat process context (CWE-94). Authentication uses the seeded default `admin/admin` credential.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: LogicalDOC Enterprise Edition (Automation Scripting)
- **Versions**: 9.3 (the incomplete CVE-2024-54448 fix suggests earlier 9.x versions are likely affected)
- **Vendor**: LogicalDOC Srl

## Impact

- **Confidentiality**: Full access to the document-management repository
- **Integrity**: Arbitrary Java code execution in the Tomcat context
- **Availability**: Full control of the DMS host

## Mitigation

1. Replace the blacklist with a hardened Velocity sandbox (whitelist classes/methods; restrict reflection)
2. Deny Automation Scripting to non-admin users
3. Force password change for the default `admin` account
4. Run Tomcat with least privilege
