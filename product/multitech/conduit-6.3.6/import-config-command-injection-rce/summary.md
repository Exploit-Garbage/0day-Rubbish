# MultiTech Conduit AEP — Authenticated Command Injection in `import_config` → Root RCE

Advisory: https://0day-rubbish.com/blog/multitech-conduit-import-config-command-injection
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com
## Summary

The MultiTech Conduit IoT gateway (mLinux, ARM 32-bit) serves its management API from lighttpd on TCP 8080, proxied to the proprietary FastCGI daemon `/usr/bin/rcell_api`. The admin-only command `upload_config` accepts a configuration archive as `multipart/form-data`; the `import_config` handler wraps the **client-supplied filename** in single quotes to build `import_config '<filename>'` and runs it through `MTS::System::cmd`, which disassembly confirms is `popen(cmd, "r")` — that is, `/bin/sh -c`.

The multipart parser strips only surrounding double quotes and reduces the value to a basename; **single quotes are never escaped**. An administrator uploading a file named `x'; <CMD> ;#` breaks out of the quoting and injects arbitrary shell syntax, executing as uid 0 because the daemon is root. Verified end to end by emulation: the root filesystem extracted from the firmware image was run under `qemu-arm-static` inside a chroot, with no physical Conduit device used at any point. Under that emulation the upload returned `{"code":200,"status":"success","type":"upload"}` and produced a root-owned marker containing `uid=0(root) gid=0(root) groups=0(root)`, while a benign filename returned HTTP 400 and created nothing. The injection is blind at the protocol level. No factory default credentials exist; the administrator account is provisioned by the deployer at commissioning.

## CVSS Score

- **Score**: 7.2 High (CVSS version 3.1)
- **Vector**: AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2
- `PR:H` because `command/upload_config` is granted only in the admin permission profile

## Affected Products

- MultiTech Conduit AEP, models `mtcdt` / `mtcdtip` / `mtcdtiphp`
- **Verified**: AEP 6.3.6 (mLinux 5.4.199), exploited against the running daemon
- **Also evidenced**: AEP 6.3.0 by patch diff, handler unchanged
- **Claimed range**: 6.3.0 – 6.3.6 from that endpoint comparison; intermediates not individually executed
- **Prerequisite**: administrator credentials provisioned at commissioning

## Impact

Root command execution on a gateway bridging field devices with IP infrastructure: full filesystem read, configuration rewrite, persistence, pivot.

## Mitigation

1. Execute `import_config` via a parameter array (`execv`) rather than `popen`/`/bin/sh -c`
2. Escape single quotes as `'\''`, or reject filenames containing shell metacharacters
3. Enforce a filename allowlist at both the parser and the command-construction site
4. Generate the storage filename server side rather than reusing the client-supplied name
5. Apply the same fix to `custom-app-upload-callback`; drop root privileges for the daemon
