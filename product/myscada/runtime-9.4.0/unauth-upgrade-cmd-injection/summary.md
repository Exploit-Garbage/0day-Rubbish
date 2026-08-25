# mySCADA PRO Runtime — Unauthenticated `upgrade` Branch Command Injection → Root RCE

## Summary

mySCADA PRO Runtime 9.4.0 (build 2026051210_master) contains an unauthenticated OS command injection in the `upgrade` branch of the `myscadagate` FastCGI service, reachable through the nginx route `/s.fcgi` which is missing the `auth_request` gate applied to every other route.

The vulnerable code executes `system("chmod 777 " + <attacker-controlled string>)`. The attacker controls the string via the `QUERY_STRING` parameter (`upgrade=<payload>`). The only filter, `checkFileName()`, blocks `\`, `/`, and `..` but permits shell metacharacters such as `;`, `>`, `|`, `&`, and spaces. A payload such as `;id>tmp_marker` passes the filter, and the `rename()` precondition is satisfied by pointing the `X-File` header at a directory that already exists on the default installation (`/opt/myscada/fw/test`).

Result: an unauthenticated remote attacker executes arbitrary OS commands as **root** (the container runs `USER root`). Verified end-to-end with markers (`uid=0(root)`), multiple commands, and persistence (`/tmp_rce`). CVSS 9.4.

## CVSS Score

- **Score**: 9.4 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: mySCADA PRO Runtime (SCADA/ICS runtime)
- **Versions**: 9.4.0 (build 2026051210_master) verified; earlier releases with the same `upgrade` branch in `myscadagate` are likely affected
- **Vendor**: mySCADA (MBS s.r.o.)
- **Deployment**: OCI container (`msxrun`, Ubuntu 24.04, `USER root`), nginx front end on ports 80/443

## Impact

- **Confidentiality**: Full access to SCADA process data and host filesystem as root
- **Integrity**: Arbitrary command execution and file modification on the runtime host/container
- **Availability**: Full control of the SCADA runtime; ability to disrupt or manipulate industrial monitoring

## Mitigation

1. Whitelist `checkFileName` to `[A-Za-z0-9_.-]` and reject all shell metacharacters
2. Replace `system("chmod 777 %s")` with a direct `chmod(path, 0777)` syscall (no shell parsing)
3. Add `auth_request /auth` to the `/s.fcgi` nginx route (consistent with `/gensec` and `/data/N`)
4. Run `myscadagate` as a non-root user
5. Audit all `system` sinks in `fcgi_run__` (the 9.2.1 patch covered only the version/email branches)
