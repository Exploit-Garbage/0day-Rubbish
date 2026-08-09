# Confluent Platform ksqlDB Unauthenticated CREATE SINK CONNECTOR to Root RCE

## Summary

A critical unauthenticated remote code execution vulnerability in Confluent Platform 7.9.1-ce arises because ksqlDB (`POST /ksql` on port 8089), the Kafka broker (9092 PLAINTEXT, no SASL), and Kafka Connect (8083) all run with no authentication in the default configuration. An attacker submits a `CREATE SINK CONNECTOR` statement to ksqlDB using `org.apache.kafka.connect.file.FileStreamSinkConnector` with an attacker-controlled `file` path (CWE-73) and `StringConverter`, then produces arbitrary bytes to the subscribed Kafka topic (CWE-306). The connector appends each message to the target file; writing a cron line to `/etc/cron.d/` yields arbitrary command execution as root when crond runs (CWE-78). Dynamic verification produced `uid=0(root)`.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Confluent Platform
- **Versions**: 7.9.1-ce (bundled Kafka 3.9.1) and other versions with default unauthenticated ksqlDB/broker/Connect configuration
- **Vendor**: Confluent, Inc.

## Impact

- **Confidentiality**: Full read of the host filesystem and configuration as root
- **Integrity**: Arbitrary OS command execution as root (via cron)
- **Availability**: Full control of the host; ability to persist or destroy

## Exploitation Prerequisites

Default configuration with no authentication on ksqlDB (8089), Kafka broker (9092 PLAINTEXT), and Connect (8083); network reachability to those ports; crond running (Linux default); ksqlDB/Connect processes running as root (common in default deployments). Confluent's own production template `ksql-production-server.properties` ships `listeners=http://0.0.0.0:8088` with no authentication, so this is the product's default posture, not a researcher-induced misconfiguration. The chain was dynamically verified with `uid=0(root)`.

## Mitigation

1. Enable ksqlDB authentication (`ksql.authentication` with Confluent RBAC / Basic / LDAP)
2. Enable SASL on the Kafka broker; disable unauthenticated PLAINTEXT listeners
3. Restrict Connect connector-class allowlist; disable `FileStreamSinkConnector` or sandbox file-write paths
4. Require admin privileges for ksqlDB `CREATE SOURCE/SINK CONNECTOR` statements
5. Add a path allowlist to `FileStreamSinkConnector`'s `file` parameter; forbid writes to system directories

## Timeline

- **Discovered**: 2026-08-09
- **Public Disclosure**: 2026-08-09 (batch #3)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
