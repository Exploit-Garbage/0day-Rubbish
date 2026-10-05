# RCDevs WebADM 2.4.14 - OS Command Injection in the Log Viewer `sid` Parameter (CWE-78)

Advisory: https://0day-rubbish.com/blog/rcdevs-webadm-logfile-viewer-sid-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

RCDevs WebADM is the closed-source IAM/MFA management platform from RCDevs Security SA (Luxembourg) that fronts the vendor's OpenOTP, SpanKey and TiQR authentication products. In version 2.4.14 (Freeware Edition), the administrator log viewer `admin/logfile_viewer.php` interpolates the `sid` GET parameter, with no escaping of any kind, into the shell command `grep -E '<sid>' <logfile> | tail -n 10000` that it hands to PHP's `popen()`. A single apostrophe closes the quoted grep pattern and everything after it is parsed by `/bin/sh`, so an authenticated administrator executes arbitrary commands as the `webadm` service account (uid=999) - the identity the `webadm-httpd` workers run under, with no privilege drop configured. The endpoint does not echo command output, so confirmation is out-of-band: the injected command appends a run-unique marker plus the output of `id`, `whoami` and `hostname` to `/opt/webadm/logs/webadm.log`, and the same endpoint reads that file back when asked for a different log selector. A negative control - the identical request with no session cookie - produced no marker, which is what makes this finding post-authentication rather than unauthenticated. The application ships as a Blowfish-encrypted opcache `file_cache` corpus that only the custom `webadm-runphp` interpreter (PHP 8.2.30, ZTS) decodes at load time, so the sink had to be recovered by reversing that decoder and reconstructing the logic from the decrypted string literals; 315 files were recovered and the reconstructed construction was then confirmed by observed behaviour.

- Component: `admin/logfile_viewer.php` on the admin console vhost, reached at `GET /admin/<random session prefix>/logfile_viewer.php?log=sessiond&sid=<injection>`
- Sink and source: `popen()` on a shell command built by string concatenation; source is `$_GET['sid']`, percent-decoded once and never validated
- Sanitization: none - no `escapeshellarg`, no `escapeshellcmd`, no quote stripping, no charset allow-list, no length cap on the recorded path

## CVSS Score

- **Score**: 7.2 High (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H) - administrator session required, execution as uid 999
- **Recorded-score correction**: the research record carried a base score of 8.8 against that same `PR:H` vector, which cannot compute to 8.8 (the raw value is 7.107826, taken to 7.2 by the CVSS ceiling-to-tenth `Roundup`)
- **Why 8.8 was rejected**: 8.8 is the base score of the `PR:L` variant, i.e. it asserts a below-administrator authenticated principal reaches the sink. Documenting such a principal was not achieved: the session is issued by an LDAP bind as the administrator DN and the no-cookie control never reached `popen()`. If a lower-privileged console role can open the log viewer in a supported configuration, `PR:L` and 8.8 become correct and this advisory will be amended
- **Scope**: Unchanged. Changed scope would compute to 9.1, and it is rejected because the injected command runs as the same identity, on the same host, with the same backend access the vulnerable application already holds
- **CWE**: CWE-78 primary; CWE-20 and CWE-116 contributing; CWE-732/CWE-276 and CWE-250 are added by this advisory for the writable-by-the-viewer log and the absent privilege separation - the underlying facts are documented in the research record, the CWE labels themselves are our classification, and the record carries CWE-78 only
- **No `PR:N` reading is published**: license registration was required to bring the console up, the research record documents no vendor-shipped default administrator credential and this research did not establish whether one exists, so no unauthenticated reading is claimed on evidence the record does not carry

## Affected Products

- RCDevs WebADM 2.4.14, Freeware Edition, from RCDevs Security SA (Luxembourg)
- Affected component: the administrator console log viewer `admin/logfile_viewer.php`, `sid` parameter
- Runtime: Apache `webadm-httpd` plus the custom `webadm-runphp` PHP 8.2.30 (ZTS) interpreter over a Blowfish-encrypted opcache `file_cache`
- Only this version and edition were tested; no other version, licensed edition or component is claimed
- Verification method and its boundary: analysis of the decoded application corpus plus live exploitation of a Docker container (`webadm-dev`). The container's published ports were mapped to loopback and every request was issued from the container host, so remote reachability is argued from the product's own binding configuration for a network-facing admin console, not observed from a separate host
- Not root: the injected command runs as uid 999; no privilege escalation was attempted and container root is a separate identity

## Impact

- Arbitrary OS command execution as the `webadm` application account on the host that runs the identity platform
- Read and rewrite of platform configuration under `/opt/webadm`, including the httpd and PHP configuration that defines routing, authentication domains and backend connectivity - a restart-surviving persistence path that never touches the operating system
- Access to the directory backend on the local LDAP listener (port 389) and to the application database on MariaDB (port 3306) with the credentials the application itself carries; for an MFA platform that includes user records, OTP state and second-factor enrolments, so integrity of authentication itself is affected
- Interaction with the certificate signing daemon on port 5000 from inside the trust boundary, where network-level protections placed on `webadm-rsignd` no longer apply
- Write access to product logs, which supports both anti-forensics and the observation channel this exploit uses; availability of the console and of the authentication path it fronts can be disrupted, locking out users of every relying application
- Detection caveat: every `/admin/*.php` request returns HTTP 200 with the WebADM doctype even without a session cookie, because the framework renders the HTML shell before the page logic runs the session check. Status code, response length and doctype are therefore unusable as authorization signals; detect on shell metacharacters in `sid`, above all the apostrophe, and on unstructured lines appearing in `/opt/webadm/logs/webadm.log`

## Mitigation

1. Neutralize at the sink: `escapeshellarg()` on `$sid` before concatenation. `escapeshellcmd()` is not an acceptable substitute - it does not move a value out of the quoting context it was placed in
2. Remove the shell: `proc_open()` with an argument vector, or read and filter the file in PHP with a bounded tail counter. This also fixes the second interpolation site, the file operand derived from the `log` selector
3. Validate the shape: `sid` is a session identifier filter, and the product's own `random_id()` output is alphanumeric - enforce that at the boundary and return 400 on mismatch
4. Resolve the `log` selector through a fixed server-side enumeration of known logs; never build a path from request input
5. Separate privileges: set an explicit minimal `User=`/`Group=` for the httpd workers instead of relying on the ambient uid 999, and remove the service account's ability to append to any log the viewer displays back
6. Constrain the runtime: the recorded `php.ini` sets no `disable_functions`, so disable process-spawning functions broadly and re-enable narrowly per verified need
7. Add a regression test that fails on a metacharacter: request the viewer with an apostrophe in `sid`, assert 400 and assert no shell child was spawned
8. Operator measures until a patch exists: bind the admin vhost to a management interface, VPN or mutually authenticated proxy; treat console administrator credentials as tier-zero secrets protected by a second factor; alert on the indicators above; and if exploitation is suspected, rotate the administrator, LDAP and database credentials and audit second-factor enrolments for the interval in question
