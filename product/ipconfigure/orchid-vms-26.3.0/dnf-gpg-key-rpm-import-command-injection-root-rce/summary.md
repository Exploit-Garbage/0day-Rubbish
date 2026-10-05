# IPConfigure Orchid VMS — Authenticated Command Injection in the DNF Repository GPG-Key Import Path (root RCE)

Advisory: https://0day-rubbish.com/blog/ipconfigure-orchid-vms-dnf-gpg-key-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## Summary

IPConfigure Orchid VMS (installed as "Orchid Recorder") is a closed-source C++ video management system for physical-security deployments. The server property `package.dnf.repo.gpg_key` — the URL or path of the GPG key that signs the vendor's RPM repository — is written through the authenticated management REST API (`PUT` / `POST /service/server/properties`, documented as requiring the `config` permission) and persisted to `/etc/opt/orchid_server.properties` with no character validation of any kind.

On service start or restart, the background `Package_Minder_Thread` reads that property and, inside `ipc::orchid::DNF_Package_Config::import_repo_gpg_key_()` at offset `0x654d0` in `/opt/orchid/lib/libpackage_minder.so`, formats it into the unquoted command template `rpm --import {}` (string at `0x758d5`, substituted by `fmt::v9::vformat`) and hands the result to `popen()`, i.e. to `/bin/sh -c`. Because the placeholder is unquoted and nothing on the path escapes or filters the value, every shell metacharacter in the property — `;`, `|`, `&`, backticks, `$()`, redirections — is interpreted as command syntax. The shipped systemd unit `orchid.service` carries no `User=` directive, so `orchid_server` runs as uid 0 and the injected command runs as root.

Verified end to end against a real installation of the vendor package in a Linux container — and not as a stock install: the container's Debian-family base was made to present as RHEL-family by rewriting `/etc/os-release`, creating `/etc/yum.repos.d/` and hand-writing the DNF repository template, because that preparation is what makes the product take the vulnerable DNF code path (the analysis sets the preparation out in full in section 9). The installed artifact was the Debian bundle for `ipc-orchid` at control `Version: 26.3.0`, 129 MB as downloaded, whose SHA-256 the research record preserves only as the prefix `1fe6ee62...` and whose integrity was established at download time by an `xz` test of the archive's data member; a separately downloaded `26.3.2` bundle was discarded as transfer-corrupted and is not the artifact behind any figure here. The chain was driven purely through the documented HTTP API with HTTP Basic credentials. Three independent marker artifacts were produced, all root-owned: `uid=0(root) gid=0(root) groups=0(root)`, `CLEAN_API_RCE_PROOF:0:root` and `ORCHID_RCE_PROOF:0:root`. The proof that these are real shell evaluations, not literal writes, is that `$(id -u)` resolved to `0`, `$(whoami)` resolved to `root`, and `$(hostname)` / `$(date +%s)` were evaluated on the target. Markers regenerate on every service restart until the property is corrected.

This is a post-authentication finding. The unauthenticated surface was exhausted first: of the 58 paths in the shipped OpenAPI specification, 56 declare `security: *AUTH_TYPES`; the five unauthenticated API endpoints (`/ping`, `/service/about`, `/service/version`, `/service/time`, `/service/time-extended`) are parameterless read-only GETs with no path to a sink; 86 authenticated operations returned 401 under both no-credential and wrong-credential probes; nine path-traversal encodings were rejected by POCO's URI filter before normalization; and more than twenty authentication-bypass techniques failed. Debian/Ubuntu installations are not affected by this sink: platform detection routes them to the APT branch, whose key installation writes a bundled keyfile instead of building a shell command.

## CVSS Score

- **Score**: 7.2 High (CVSS version 3.1)
- **Vector**: AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2
- `PR:H` because `PUT`/`POST /service/server/properties` require the `config` permission, which the vendor's own shipped role table grants in the base scope of exactly one role, Administrator (Manager, Viewer and Live Viewer do not hold it)
- **Conditional — 9.8 Critical**, vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8, for installations that still accept the credential declared by the vendor's own installer (`ipc-orchid/admin_password`, debconf `Default: pass`, written by `preinst` into the properties file); on such a deployment no privilege has to be obtained at all
- The intermediate reading 8.8 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) is documented in the full analysis and deliberately not adopted: PR:L describes basic-user capabilities, which contradicts the Administrator-only `config` scope

## Affected Products

- IPConfigure Orchid VMS / Orchid Recorder 26.3.0 (the version the running service reports and the version in the package control metadata)
- Verified by execution on the Debian bundle carrying control `Version: 26.3.0` (`Package: ipc-orchid`, `Architecture: amd64`, 129 MB as downloaded); the research record preserves its SHA-256 only as the prefix `1fe6ee62...`, and a separately downloaded `26.3.2` bundle was discarded as transfer-corrupted, so no figure in this advisory comes from it
- Affected platform: RHEL-family deployments, where platform detection selects the DNF package path; Debian/Ubuntu deployments take the APT path and this sink is not reachable
- Precondition: a session holding the `config` permission (Administrator role), plus network reachability to the management API; the installer-default administrator password makes that precondition free on unrotated installations
- Not claimed: versions earlier than 26.3.0 (introduction point of the unquoted template not established), Windows builds, and exploitation on a native RHEL host (the DNF branch was entered on a Debian-family lab container by preparing `/etc/os-release` and the DNF template directory)

## Impact

- Arbitrary command execution as uid 0 on the video management server, obtained through a single authenticated HTTP request plus the restart that request causes by itself — the sink fires during `Package_Minder_Thread` initialization and repeats on every subsequent boot, upgrade restart or crash restart
- Full read and rewrite of the recorded video archive and of the SQLite database whose path the shipped default configuration names as `/var/lib/orchid_server/orchid.sqlite`; that such a store would be expected to hold camera credentials and user records is an expectation about a video management server rather than something this research verified — either way the consequence is manipulation of physical-security evidence rather than only data theft
- Persistence through the systemd unit path or any of the `liborchid_*.so` libraries loaded at start (the research record counts 70+ of them in the full extraction; the partial tree retained for this write-up holds 57), plus lateral reach from a host that by design spans camera VLANs and physical-security networks; no privilege separation exists between the authenticated web role and the operating system, and the product's audit trail records the property change but not what the restarted process then executed

## Mitigation

1. Replace the `popen()` call in `DNF_Package_Config::import_repo_gpg_key_()` with argument-array execution (`posix_spawn`/`execvp`, `argv = {"rpm", "--import", gpg_key, NULL}`), removing the shell from the path entirely
2. If a shell call must be retained, quote at the construction site (`rpm --import '<escaped>'`, escaping `'` as `'\''`), as the product already does for its `timedatectl set-timezone '{}'` template
3. Validate `package.dnf.repo.gpg_key` at the write boundary as a strict URL or file path, rejecting `;`, `|`, `&`, backtick, `$(`, `<`, `>`, newline and carriage return; apply the same rule to `package.dnf.repo.url`, `.name` and `.channel`
4. Reuse the 21-character metacharacter blocklist the product already applies in `System_Module::process_tz_request_()` (blocklist at `0x47f340`), and fail the request instead of silently deleting characters
5. Consider placing the `package.*` properties on the locked list so they cannot be modified through the API, and do not treat the five-minute confirmation window as a control — the restart that executes the payload happens before it opens
6. Run the service unprivileged (`User=`/`Group=` in `orchid.service`, dropping privileges before spawning package-management children), and operationally: rotate the installer-default administrator password, restrict management-port reachability, and alert on children of `orchid_server` that are not `rpm`/`dnf`/`apt`/`gpg`

---

*Research and write-up by the 0day Rubbish Research Team. Full technical analysis, disassembly offsets, verification transcripts and a working proof of concept are published alongside this summary.*
