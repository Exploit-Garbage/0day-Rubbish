# Cisco CUCM Remote Code Execution Chain

## Summary

A critical remote code execution vulnerability chain in Cisco Unified Communications Manager (CUCM) allows unauthenticated attackers to achieve root-level command execution through a combination of SQL injection, XXE, and Apache Axis deployment vulnerabilities.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Cisco Unified Communications Manager
- **Versions**: 14.0 and earlier versions
- **Vendor**: Cisco Systems

## Impact

- **Confidentiality**: Complete system compromise including credential database access
- **Integrity**: Full system control with root privileges
- **Availability**: Potential service disruption through arbitrary command execution

## Mitigation

1. Update to latest CUCM version with security patches
2. Restrict network access to CUCM administrative interfaces
3. Implement web application firewall rules for SOAP endpoints
4. Monitor for suspicious DNS queries to external domains
5. Disable unnecessary XML parsing features

## Timeline

- **Discovered**: 2026-07-01
- **Public Disclosure**: 2026-07-01

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research.
