# Jitterbit Agent Unauthenticated SOAP JdbcEngine COPY TO PROGRAM RCE

## Summary

An unauthenticated remote code execution vulnerability in the Jitterbit Harmony private-deployment integration agent (public Docker image `jitterbit/agent:12.8.1.6`). The agent's SOAP management plane (Apache proxy port 46908; Tomcat Axis direct port 46912) enforces no authentication by default: both `web.xml` files declare zero `security-constraint` elements and the Apache `<Location /axis>` block has no `AuthType`/`Require`, so all 12 SOAP services are anonymously reachable (CWE-306). The `JdbcEngine.dbExecute` SOAP method accepts a fully attacker-controlled `WsDbLookupParams` — connection parameters (`Server/Port/Database/User/Password/DriverName`) and arbitrary SQL text — while a fake all-zero `SourceGuid` passes the GUID non-emptiness check without any existence validation, so the engine builds the database connection purely from the request. The image additionally bakes the local PostgreSQL superuser password (`jitterbit` / `#)~MxgD*m2Q!vhvhXD1`) into the public image at build time (CWE-798), shared by every deployment pulled from Docker Hub. Instructing the agent to connect to its own embedded PostgreSQL (127.0.0.1:46914, TranDb) as that superuser and run `COPY (SELECT 1) TO PROGRAM '<cmd>'` executes an arbitrary OS command in the container as the PostgreSQL service identity `jitterbit` (uid=999) (CWE-78); further `COPY FROM PROGRAM` and `SELECT` calls read the command output back through the SOAP response. Dynamically verified end-to-end on both network paths.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Jitterbit Agent (Jitterbit Harmony private-deployment integration agent)
- **Versions**: 12.8.1.6 (Docker `jitterbit/agent:12.8.1.6`) verified; other releases with the same unauthenticated Axis SOAP `JdbcEngine` plus baked-in PostgreSQL credential are likely affected
- **Vendor**: Jitterbit (USA)
- **Prerequisites**: network reachability to the agent SOAP port (publishing `-p 46908:46908` is the expected deployment pattern; the image declares 46908 in `ExposedPorts`). No credentials, no user interaction, no pre-existing database entities; plain HTTP, no TLS required.

## Impact

- **Confidentiality**: arbitrary command execution as `jitterbit` (uid=999) in the agent container — superuser read access to the embedded PostgreSQL and the agent's local filesystem; SOAP-based output readback makes exfiltration fully remote
- **Integrity**: total control of the integration agent (database contents, configuration, integration runtime) — the component that executes the customer's integration projects
- **Availability**: the agent and its PostgreSQL can be terminated or corrupted at will, halting all integrations the host serves

## Mitigation

1. Enforce authentication on the SOAP plane: add `security-constraint` + authentication filter to the Axis `web.xml`; add `AuthType` + `Require valid-user` to Apache `<Location /axis>`
2. Stop accepting request-supplied `ConnectionParams` in `dbExecute` — resolve connections only from server-side registered Source/Target configurations (by GUID lookup)
3. Remove the hardcoded PostgreSQL superuser password from the image — generate per-deployment secrets at first container start
4. Run the embedded PostgreSQL under a non-superuser application role; gate `COPY TO PROGRAM` via `pg_execute_server_program`
5. Do not expose port 46908 publicly; restrict the SOAP plane to the management network

## Timeline

- **Discovered & verified**: 2026-08-09
- **Public disclosure**: pending (planned 2026-09-08, batch #10)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
