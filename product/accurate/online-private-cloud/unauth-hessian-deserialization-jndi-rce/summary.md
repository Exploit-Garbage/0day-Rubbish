# Accurate Online Private Cloud — Unauthenticated Hessian Deserialization JNDI RCE

## Summary

Accurate Online Private Cloud (CPSSoft, Indonesia — the private-cloud / on-premises edition of the Accurate Online accounting/ERP SaaS) embeds Excelsior JET-compiled Tomcat 9.0.31, Spring 4.3.8, and Caucho Hessian 4.0.38 behind a SAML SSO gate (spring-security-saml2-core 1.0.2). The SAML authentication on the `/accurate` business context is strong — every signature-forgery variant tested was rejected. However, three Hessian RPC endpoints registered via Spring `HessianServiceExporter` (`/accurate/remote`, `/accurate/svc/data-exchange`, `/accurate/svc/accurate-maintenance`) escape the SAML filter chain and are reachable unauthenticated.

`POST /accurate/remote` invoking `INucleusAppService.startAwsS3Emigrate` deserializes the attacker-supplied argument through the declared `java.util.Map` parameter type: `MapDeserializer.readMap` → `HashMap.put` → `AbstractPointcutAdvisor.equals` → `AbstractBeanFactoryPointcutAdvisor.getAdvice` → `SimpleJndiBeanFactory.getBean` → `InitialContext.lookup` of an attacker LDAP URI. The bundled JVM is Excelsior JET 1.8.0_144 (pre-8u191, `trustURLCodebase=true`), so the JNDI reference performs unrestricted remote class loading; the loaded class executes an arbitrary command as the Tomcat process — which runs as Administrator. Verified end-to-end on a default installation: `whoami` → `<host>\administrator`, and a multi-step marker command executed fully (`RCE_CONFIRMED_20260731`, exit 0). At research time the product line had zero NVD CVEs.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Accurate Online Private Cloud (on-premises / private-cloud edition of Accurate Online)
- **Versions**: the build distributed as the 287MB `aolprivate.exe` InstallAnywhere installer (verified), which bundles Excelsior JET 1.8.0_144 / Tomcat 9.0.31 / Spring 4.3.8 / Caucho Hessian 4.0.38; other editions with the same Hessian exporter + SAML filter layout are likely affected
- **Vendor**: CPSSoft (Jakarta, Indonesia)
- **Port**: 8765/tcp (Tomcat HTTP)
- **Prerequisites**: none — default configuration, no credentials, no user interaction

## Impact

- **Confidentiality**: full compromise of the accounting/ERP data the platform hosts, plus the underlying Windows server
- **Integrity**: arbitrary command execution as Administrator — tampered financial records, persistence, ransomware deployment
- **Availability**: complete control of the ERP service and host; destructive commands, service shutdown
- **Privilege**: Administrator (Tomcat process started via scheduled task `catalina.bat run`)

## Mitigation

1. Upgrade the bundled JVM to 8u191+ or a current JDK 11/17 — cuts JNDI remote class loading (vendor rebuild required; the runtime is Excelsior JET AOT-compiled)
2. Require authentication on the Hessian endpoints — fold them into the SAML filter chain or a dedicated auth filter (`/accurate/remote` and both `/accurate/svc/*` siblings)
3. Restrict Hessian deserialization to an allowlist via the `SerializerFactory` deserializer configuration; block `AbstractBeanFactoryPointcutAdvisor` / `SimpleJndiBeanFactory`
4. Remove or restrict JNDI (`SimpleJndiBeanFactory`) in the Spring configuration; upgrade the EOL Spring 4.3.8 / Hessian 4.0.38 stack
5. Defense in depth: run Tomcat as a least-privilege service account (not Administrator), bind 8765/tcp away from `0.0.0.0`, isolate the RPC endpoints from the SAML-protected application context
