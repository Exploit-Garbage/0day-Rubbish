# TigerGraph Community Edition 4.2.4 — Default Hard-Coded Credentials + GSQL Arbitrary File Write + Unauthenticated REST++ Trigger → SSH RCE as `tigergraph`

## Summary

TigerGraph Community Edition 4.2.4, shipped as the Docker image `tigergraph/community:latest`, exposes a full remote code-execution chain in its default configuration. The product accepts the hard-coded administration credentials `tigergraph`/`tigergraph` and never forces them to be changed — the login response merely carries an advisory `"securityRecommendations":["Change default tigergraph user's password"]` alongside `isSuperUser:true` (CWE-798). Those credentials unlock `POST /api/gsql-server/gsql/v1/statements`, which the GUI nginx reverse-proxies to the internal GSQL HTTP service on 8123 (`server 127.0.0.1:8123`), letting an attacker compile and install an arbitrary GSQL query. A query declared as `CREATE QUERY qwrite_c(FILE f, STRING c) { PRINT c TO_CSV f; }` turns the `FILE` parameter into an unrestricted write primitive: no path validation, no base-directory confinement, no extension allowlist (CWE-73), content written verbatim plus one trailing newline, executed as the `tigergraph` user.

Invoking that installed query needs no authentication at all, because REST++ ships with `RESTPP.Factory.EnableAuth = False` in `tg.cfg` (CWE-306). A bare `GET /query/<graph>/<query>?f=<path>&c=<content>` on port 9000 — headers confirmed by `curl -v` to be `Host`, `User-Agent` and `Accept` only — therefore writes attacker-chosen bytes to an attacker-chosen path. Aimed at `/home/tigergraph/.ssh/authorized_keys` (CWE-22), the write plants an attacker public key in a file owned by the very account whose shell the product starts `sshd` for (`entrypoint.sh` runs `sudo /usr/sbin/sshd -h /home/tigergraph/.ssh/sshd_rsa`, with OpenSSH defaults `PubkeyAuthentication=yes`). An `ssh -i <key> tigergraph@<target>` then yields arbitrary command execution. The landing identity is the **`tigergraph` operating-system user, uid 1001 — not root**: verified output `uid=1001(tigergraph) gid=1001(tigergraph) groups=1001(tigergraph)`, with an independent `RCE_SUCCESS` marker read back from inside the container, and a two-reviewer adversarial pass (falsification plus independent re-analysis) both returning NOT_REFUTED. One encoding subtlety is load-bearing: spaces in the public key must be sent as `%20`, not `+`, because REST++ does not decode `+` as a space.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **CWE**: CWE-798 (hard-coded credentials), CWE-73 (external control of file name or path), CWE-306 (missing authentication for critical function), CWE-22 (path traversal to `authorized_keys`)
- **PR:N rationale**: the only credential in the chain is a hard-coded default that the product never forces the operator to rotate, which makes it a publicly known constant rather than a privilege; the file-write trigger itself is genuinely unauthenticated on every deployment. Same treatment as this project's StreamSets DataCollector advisory (batch #9, `admin`/`admin`, also 9.8 PR:N).
- **Rotated-default case**: where an operator has changed the shipped `tigergraph` password, the prerequisite becomes a valid account rather than a publicly known constant. That configuration is scored **8.8 High** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. The chain is identical; only the privilege metric differs. Nothing else in this advisory depends on which of the two applies.

## Affected Products

- **Product**: TigerGraph Community Edition
- **Version**: 4.2.4, verified on `tigergraph/community:latest`
- **Vendor**: TigerGraph (USA), closed-source commercial graph database
- **Prerequisites**: default configuration. A file-output query must be present in the catalog — not pre-installed, but installable by the attacker with a single HTTP call using the shipped credentials. Any file-output query installed by any legitimate user satisfies the same precondition, after which the write trigger is purely unauthenticated
- **Exposure**: GUI 14240 and REST++ 9000 exposed; SSH 22 exposed on bare-metal/VM deployments (`sshd` started by default via the `SSH` section of `tg.cfg`), reachable only inside the container network on the Docker deployment used in the lab
- **CVE status**: no public CVE for 4.2.4 at the time of research; the research record notes ten prior TigerGraph NVD CVEs, all in the 3.x line (2022–2023)

## Impact

- **Execution identity**: the `tigergraph` OS user, **uid 1001 — not root**. It owns and runs the database engine, all graph data, the catalog and the configuration tree under `/home/tigergraph/tigergraph/`, so the product is totally compromised while the operating system is not (root-owned targets such as `/etc/cron.d/` are unreachable from this identity, as observed)
- **Confidentiality**: high — arbitrary read of graph data, GSQL catalog, query definitions, product configuration and service-account credentials, with an interactive shell for unconstrained exfiltration
- **Integrity**: high — the write primitive is generic, not specific to `authorized_keys`; any path writable by uid 1001 can be created or truncated with attacker-chosen content
- **Availability**: high — the engine, catalog and container services can be stopped, corrupted or rendered unbootable by writing files the service account owns
- **Persistence**: the planted key is durable, survives restarts and leaves no product audit record, since the write is an ordinary query invocation
- **Lateral movement**: a shell inside the database tier reaches every system connected to the graph database and the internal network the appliance sits on; such hosts typically hold connection credentials toward upstream and downstream systems
- **Secondary unauthenticated primitive**: on deployments already carrying file-output queries, the anonymous arbitrary file write stands on its own (CWE-306 + CWE-73)

## Mitigation

1. Force a password change on the shipped `tigergraph` account at first login instead of emitting a dismissible `securityRecommendations` string (CWE-798)
2. Ship `RESTPP.Factory.EnableAuth = True` and require a token to invoke installed queries, rather than exposing every installed query to anonymous invocation (CWE-306)
3. Confine `FILE` parameters in `PRINT ... TO_CSV` to a configured base directory (e.g. `/home/tigergraph/tigergraph/output/`), reject escaping absolute paths, and explicitly deny sensitive targets such as anything under `.ssh/` (CWE-73, CWE-22)
4. Require elevated privilege (or a static install-time path check) to install a query that declares a `FILE` parameter
5. Stop starting `sshd` by default on a database appliance, or restrict it to administratively provisioned keys
6. Operators, today: change the `tigergraph` password immediately and treat any deployment still answering `tigergraph`/`tigergraph` as compromised-by-default; set `RESTPP.Factory.EnableAuth = True`; audit the catalog for queries with `FILE` parameters; file-integrity monitor `/home/tigergraph/.ssh/authorized_keys`; never expose GUI 14240, REST++ 9000 or SSH 22 to untrusted networks
