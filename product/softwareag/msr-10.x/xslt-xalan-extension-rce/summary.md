# Software AG webMethods MSR — XSLT Xalan Java-Extension RCE (Default Credentials)

## Summary

An unauthenticated-adjacent remote code execution vulnerability in Software AG webMethods Microservices Runtime (MSR) 10.x. The Integration Server service `pub.xslt.Transformations:transformSerialXML` uses the Xalan `TransformerFactoryImpl` without enabling `FEATURE_SECURE_PROCESSING`, leaving Xalan Java extension functions enabled by default. An attacker with the factory default credentials (`Administrator:manage`, CWE-798) sets `stylesheetSystemId` to an attacker-controlled HTTP URL; the server fetches the malicious XSL stylesheet (SSRF, CWE-918) and the Xalan extension functions execute `java.lang.Runtime.exec` as the `sagadmin` service user, achieving arbitrary OS command execution.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: webMethods Microservices Runtime (MSR) / Integration Server
- **Versions**: 10.x (verified on a JDK 11.0.19 / Alpine deployment; other versions with the same XSLT module are likely affected)
- **Vendor**: Software AG

## Impact

- **Confidentiality**: Full access to Integration Server data as `sagadmin`
- **Integrity**: Arbitrary OS command execution in the Integration Server process context
- **Availability**: Full control of the integration runtime

## Mitigation

1. Enable `FEATURE_SECURE_PROCESSING` (or disable Xalan Java extension functions) on the XSLT transformer factory
2. Enforce password change for the default `Administrator` account at install time
3. Restrict access to `transformSerialXML` via ACLs to trusted users
4. Block outbound fetches from the Integration Server to untrusted HTTP(S) destinations
