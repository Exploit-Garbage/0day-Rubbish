# Lightstreamer Server 7.4.8 (build 3506 ENTERPRISE) — Shipped Placeholder JMX/RMI Credentials plus MLet Remote Class Loading Yield root RCE

Advisory: https://0day-rubbish.com/blog/lightstreamer-default-creds-jmx-rmi-mlet-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

Lightstreamer Server 7.4.8 ships a `conf/lightstreamer_conf.xml` whose `<jmx><rmi_connector>` block publishes a cleartext RMI management connector on TCP 8888, bound to every interface, and authenticates it with one credential pair hard-coded in the distribution archive itself: `user_changeme` / `password_changeme`. Comparing the tarball against the deployed file showed them byte-identical, so the pair is not randomized at install time; the research record documents no first-login rotation gate, and the tested instance still accepted the pair. Because the connector hands out a full `MBeanServerConnection` including `createMBean`, an attacker presenting that pair registers `javax.management.loading.MLet` and calls `getMBeansFromURL` against an origin they control. The broker downloads the MLet document and JAR over HTTP and instantiates the declared MBean, whose constructor runs `Runtime.exec`. Verified across four runs — three against the `jmxrmi` platform MBean server and one against the `lsjmx` application MBean server — with out-of-band HTTP logs proving a uniquely named JAR was really fetched, `runCmd` returning `uid=0(root)` and a proof file owned by root. Empty and wrong credentials were both rejected with `SecurityException`, isolating the defect to the credential's provenance rather than a bypassable check. No native-library dependency, no man-in-the-middle position and no user interaction.

## CVSS

CVSS 3.1 base scores. The finding is dual-scored because remote reach depends on the shipped placeholder credential being left unchanged.

- 9.8 Critical — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (shipped placeholder left unchanged)
- 7.2 High — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (operator rotated it; `createMBean` and MLet still exposed)

## Affected

Lightstreamer Server 7.4.8 build 3506 ENTERPRISE with JMS Extender 2.1.0 on JDK 17, unpacked from the distribution archive and started as root; vendor Lightstreamer S.r.l. (Milan, Italy). Other versions were not tested. No public CVE history for this product in the research record.

## Impact

Arbitrary command execution as the broker's user — root in the tested deployment: configuration, keystores and streamed data disclosure; adapter and stream tampering; service and host outage; a foothold inside the trust zone of every consuming system. The payload MBean stays registered for the JVM lifetime as a persistent command channel.

## Mitigation

Rotate the placeholder credential and audit deployments for the literal strings; bind the connector to loopback or block TCP 8888; enable TLS; refuse `MLet` registration and untrusted codebases; stop exposing `createMBean` by default; drop the root execution context.
