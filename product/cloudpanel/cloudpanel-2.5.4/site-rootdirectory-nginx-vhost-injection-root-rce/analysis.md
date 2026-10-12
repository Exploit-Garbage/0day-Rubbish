# CloudPanel 2.5.4-3 — Site-Settings Root Directory Field Injects nginx Virtual-Host Directives (host uid=0 remote code execution)

## 1. Overview

### Overview of the finding

CloudPanel Community Edition 2.5.4-3+clp-bookworm lets a panel account holding only the lowest application role, `ROLE_USER`, write arbitrary text into the nginx virtual-host configuration file of a site it owns. The mechanism is not shell injection and not a file-write primitive invented by the attacker. It is much blunter than that: the "Root Directory" text field on the site settings page has no character-level validation whatsoever, its value is stored verbatim, and one line of the virtual-host renderer interpolates it into a `root` directive with a `sprintf` call. A value containing real newline characters therefore terminates that `root` directive and begins new directives chosen by the attacker, at server context, ahead of every `location` block the template would otherwise emit.

That single fact is the whole finding, because of where the text lands and who parses it. The file written is `/etc/nginx/sites-enabled/<domain>.conf`. The nginx that reads it is the vendor-built `nginx-common 1.30.4-1+clp-bookworm` package rather than the distribution nginx, and the first line of its `/etc/nginx/nginx.conf` is literally `user root;`, with line 119 reading `include /etc/nginx/sites-enabled/*.conf;`. Two injected `location` blocks therefore buy an anonymous WebDAV `PUT` write primitive whose writes are performed by a root worker, and an anonymous FastCGI dispatch onto `/run/clp-fm-php-fpm.sock` - the socket of the vendor's File Manager php-fpm pool, which the same vendor package ships with `user = root`. Anonymous write plus anonymous execution of the written body equals arbitrary OS command execution as `uid=0` on the host.

The full chain is three HTTP requests after the initial authenticated page load: an authenticated `POST` of a form, an anonymous `PUT`, an anonymous `GET`. The product itself performs the fourth step, which is the reload of nginx. Nothing in the chain requires an administrator, requires a local shell, requires a non-default setting, or requires the attacker to touch the database.

### Overview of the product and its runtime stack

CloudPanel is a server-management panel for virtual private servers and dedicated hosts, from cloudpanel.io in Germany. It provisions and supervises nginx, php-fpm, MariaDB and hosted web sites through a web application, and is aimed at hosting operators who resell or sub-host sites for customers.

It is closed-source freeware, and that is established from the artifact rather than inferred. The package's `composer.json` line 3 reads literally `"license": "proprietary"` (file md5 `568641dea8f40aacb6a4b24a067b825a`). The Debian package ships `/usr/share/doc/cloudpanel/` containing only `changelog.Debian.gz` with no copyright file, and the application source tree carries no copyright headers. The distribution archive examined for this work is 69,183,476 bytes with md5 `24c36a4739ce065c5c188c89def06f29`.

The runtime stack, and the parts of it that matter here:

| Layer | Detail | Why it matters |
|---|---|---|
| Operating system | Debian bookworm, x86_64 | The vendor publishes its own apt repository for this distribution and its own nginx build for it |
| Web framework | Symfony 6.0, PHP 8.1 | Authorisation is expressed in `config/packages/security.yaml`, whose access-control list is the authentication boundary analysed in section 3 |
| Panel application | `src/` main tree, 489 PHP files | Obfuscated: plaintext PHP but every character escaped as octal or hexadecimal and control flow flattened with `goto`. Line numbers in these files are meaningless; only `goto` labels are stable identifiers |
| Site-facing web server | vendor package `nginx-common 1.30.4-1+clp-bookworm`, `nginx -v` reports `nginx/1.30.4` | This is the process that parses the injected file, and it runs workers as root |
| Panel web server | a second nginx, configuration `/home/clp/services/nginx/nginx.conf`, port 8443 | This process runs workers as the panel account and never includes the site directory; the injection is inert against it |
| PHP pools | `php-fpm.conf` for the panel pool at `/run/clp-php-fpm.sock` (`user = clp`), and a File Manager pool at `/run/clp-fm-php-fpm.sock` (`user = root`) | The File Manager pool is the execution amplifier |
| Databases | MariaDB for hosted sites; the panel's own state in SQLite | `DATABASE_URL="sqlite:////home/clp/htdocs/app/data/db.sq3"`, which is why database-side privilege and filesystem privilege are different things here |

The obfuscation has a practical consequence for how the rest of this document cites code. Where a source file is obfuscated, the citation is a `goto` label such as `b9892`, `Dc4ef`, `f807c`, `Aca8b` or `e35ff`, never a line number. Where a file is plaintext - and the configuration, YAML, JavaScript and phpMyAdmin layers are all plaintext - the citation is a conventional `file:line` reference. The decoded corpus we worked from contains 648 files drawn from 31,907 files in the package payload, so roughly two percent of the payload was decoded; every negative conclusion of the form "zero hits across the tree" that appears below is bounded by that coverage, and the two exceptions that are not so bounded are stated where they are used.

### Overview of the testbed and of what that implies

Reproduction ran inside a single-container Linux testbed built from the vendor `.deb` for this exact build, plus the vendor's own nginx package from the vendor's own apt repository, and with MariaDB and sudo present. Published ports were bound to loopback on the host side and were closed at the end of each round.

Three properties of that testbed must be stated plainly, because each one is the kind of thing that turns a real finding into an artifact of the laboratory.

First, layering of responsibilities. A container has no init system as PID 1, so the first startup of MariaDB, of both nginx instances and of php-fpm was a harness action performed by us. The chain hops themselves were not: the form save, the reload that follows it, the anonymous `PUT` and the anonymous `GET` are all performed by product code over vendor-native wiring. The reload is measurable, and in five independent rounds every recorded reload invocation carried `SUDO_USER=clp` with a count of zero harness-originated reloads.

Second, the one file we replaced on disk. Real `systemctl` cannot operate in a container without PID 1: on an unmodified throwaway container, running the product's own command produces `System has not been booted with systemd as init system (PID 1). Can't operate.`, `Failed to connect to bus: Host is down` and a return code of 1. We therefore replaced `/bin/systemctl` with a 35-line POSIX shell shim. That file belongs to the `systemd` package, not to CloudPanel: it was `-rwxr-xr-x 1 root root 1353368 /bin/systemctl`, md5 `40621176f9df719abc43a35a08983631`, `systemd 252 (252.39-1~deb12u2)`, and `dpkg -S /bin/systemctl` reports `systemd: /bin/systemctl`. The shim does not hardcode a reload command; it reads `ExecReload` out of the vendor unit file at run time:

```
CMD=$(grep "^ExecReload=" /lib/systemd/system/nginx.service | head -1 | sed -e "s/^ExecReload=//" -e "s/^-//")
```

and then runs it through the shell. The line in question contains single quotes only, so shell parsing and systemd parsing produce the same argument vector; `Type=forking` and `KillMode` affect stop and restart but not reload, which is signal-only. Two shim variants were used across the two reproduction sets, md5 `17896bd086f8f37e9555683ce51b6aa9` at 1,393 bytes and md5 `2f629aca4bf132db228fa28672780b6e` at 1,504 bytes; both passed `sh -n` before use, and the second one's 17,262-byte log has md5 `2a06e517db0697e0b71c564102b50b7e`.

Third, product integrity at close. `dpkg -V cloudpanel` reported a single difference, `??5??????   /home/clp/logs/php/error.log`, which is a runtime log. `dpkg -V nginx-common` was empty with return code 0. `dpkg -V systemd` reported only `??5??????   /bin/systemctl`, our shim. Both nginx configuration files had identical digests at open and at close. No product file was modified to make this chain work.

What that set of facts implies: the harness supplied an environment the vendor's own installer would have supplied on a real host, and nothing else. There is no product wall to remove. Conversely, the harness is visible in one place and only one - the process that turns the product's `sudo /bin/systemctl reload nginx` into a signal - which is why that substitution is documented at this length rather than quietly absorbed.

### Overview of affected scope

Affected is the site-settings virtual-host path of CloudPanel Community Edition build 2.5.4-3+clp-bookworm: the form `site_domain_settings`, its `rootDirectory` field, the entity setter that stores it, the updater that renders it and the writer that installs it, together with the two packaged components that make the injected text dangerous. Only that build was tested. Nothing is claimed about other builds, and nothing is claimed in the negative direction either: we did not compare against earlier versions, so we cannot say when the condition was introduced.

Reachability in scope terms: any deployment where a panel account with `ROLE_USER` owns at least one site. That is the product's normal operating state for a hosting tenant, because site creation is an administrator action and the tenant account is then granted the site.

### Overview of independence

This is not a re-published public issue. A keyword search of the national vulnerability database for this product returned nine results, and none of them mentions `rootDirectory`, nginx virtual-host generation, CWE-93, `dav_methods`, or a zero-validation site-form field. The vendor's own changelog across the version range likewise contains no entry for this root cause. A fingerprint check against our own previously published research corpus found no earlier work on this sink; the single textual candidate that surfaced was reviewed and rejected as a false positive.

We state one limitation on that independence claim rather than presenting it as verified twice over: the confirming review pass did not re-run the database query, so the nine-result figure and the changelog coverage rest on the primary search, not on two independent searches.

The closest prior public issues for this product are in different components, reached from different endpoints, through different sinks and for different root causes. Two earlier File Manager issues concerned archive path handling - one a path-traversal condition that the vendor's own changelog describes as a critical privilege escalation from a user to root, and one a zip symlink condition handled by an archive backend; a third concerned `chmod` in the File Manager; a fourth concerned File Manager cookie authentication and is fixed. A fifth, the `redirectToReferer` open redirect, is still live in this build, because the vendor changed one call site while leaving the shared sink helper unmodified; the helper body in `src/Controller/Controller.php` (2,725 bytes, md5 `0b78e72eb8649fd47063d5cdd3f26405`, two physical lines after flattening, so citations use label `E95e7`) still returns `new RedirectResponse($referer)` between two statements with nothing in between, and one public-access route, `^/locale/change$`, still calls it. A sixth, static self-signed certificates, is a key-management issue. A seventh, privilege escalation through the `clpctlWrapper` helper, is acknowledged by the vendor in its own changelog for an earlier version and is a local primitive.

None of those shares the endpoint `POST /site/{domainName}/settings`, the sink `RootDirectory.php` label `b9892`, or the root cause of a value interpolated into configuration text without validation.

One further honesty note on novelty, and it cuts against us. The amplifier - a service pool running as root, addressable over a group-permissive Unix socket - belongs to a class the vendor has already acknowledged in its changelog, and an external researcher published on that socket class with the vendor indicating a fix was planned for a later major version. We therefore claim novelty only at the root-cause layer, the virtual-host renderer, and explicitly do not claim a novel privilege-escalation mechanism.

## 2. Vulnerability Summary

### Vulnerability Summary table

| Field | Value |
|---|---|
| Product | CloudPanel Community Edition, from cloudpanel.io (Germany) |
| Build | 2.5.4-3+clp-bookworm (package 69,183,476 bytes, md5 `24c36a4739ce065c5c188c89def06f29`) |
| Source availability | Closed source; `composer.json:3` reads `"license": "proprietary"`, md5 `568641dea8f40aacb6a4b24a067b825a` |
| Vulnerable component | Site settings form and the nginx virtual-host renderer |
| Endpoint | `POST /site/{domainName}/settings`, Symfony route `clp_site_settings`, handler `SitesController::domainSettings` |
| Tainted field | `site_domain_settings[rootDirectory]` |
| Sink | `src/Site/Nginx/Vhost/Processor/RootDirectory.php`, label `b9892`, substituting into the `{{root}}` template placeholder |
| Writer | `src/System/Command/Vhost/WriteFileCommand.php`, label `Dc4ef`, `echo %s \| /usr/bin/sudo /usr/bin/tee %s` |
| Installed artifact | `/etc/nginx/sites-enabled/<domain>.conf`, loaded by `/etc/nginx/nginx.conf:119` |
| Weakness class | CWE-93, injection of control characters into a configuration file later parsed as directives |
| Explicitly not | CWE-78. Both writer substitutions are `escapeshellarg`'d |
| Start identity | Panel `ROLE_USER` over remote HTTP, owning at least one site |
| Follow-on identity | Anonymous, twice: the `PUT` and the `GET` |
| Achieved identity | Host `uid=0`, observed as `uid=0(root) gid=1000(clp) groups=1000(clp),0(root)` |
| Amplifier | `/home/clp/services/php-fpm/fpm/pool.d/file-manager.conf` with `user = root`, socket `srw-rw---- 1 root clp /run/clp-fm-php-fpm.sock`, and `user root;` at `/etc/nginx/nginx.conf:1` |
| Factory credential involved | None. The product ships with zero panel users |
| Published CVSS | 8.8 High, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Rounds observed end to end | Five, in two complementary reproduction sets with vendor-native wiring |

### Vulnerability Summary mechanics

The renderer's entire handling of the value is three statements, quoted verbatim from the decoded corpus of `src/Site/Nginx/Vhost/Processor/RootDirectory.php`:

```php
protected string $placeholder = "{{root}}";
Aca8b: $rootDirectory = $this->site->getRootDirectory();
b9892: $placeholderValue = rtrim(sprintf("root /home/%s/htdocs/%s;", $siteUser, $rootDirectory), "/");
e35ff: $content = $this->replace($placeholderValue, $content);
```

`$siteUser` comes from `$this->site->getUser()`, the site's system account name, so the emitted prefix is fixed at `/home/<siteUser>/htdocs/` and the attacker cannot choose it directly. Two escape routes exist from that prefix. Path traversal with `../` is syntactically legal because the value has no path validation, and newline injection ends the directive outright. Newline injection is the one that matters, because ending the directive is what lets the attacker start new ones.

The `rtrim` in that line is dead code, and its deadness is the clearest single piece of evidence that this was not a considered decision. `rtrim($s, "/")` removes trailing slashes. The format string ends with a semicolon, so the result of the `sprintf` can never end with a slash, so the call can never strip a character. It looks like sanitization and cannot function as sanitization under any input.

What then happens to the resulting text is entirely benign from the shell's point of view and entirely destructive from the configuration parser's point of view:

```php
Dc4ef: echo %s | /usr/bin/sudo /usr/bin/tee %s
```

Both substitutions are wrapped in `escapeshellarg`, so there is no command injection and no shell metacharacter reaches a command line. `sudo` and `tee` are the mechanism by which the panel process, running as the unprivileged account `clp`, writes a root-owned file into a root-owned directory. That is a normal and reasonable design for a panel that manages system configuration. The defect is that the bytes handed to `tee` are configuration syntax assembled from unvalidated user input, and nginx will parse them.

The reload that follows is issued by the product, not by the attacker. `src/Site/Updater.php` contains:

```php
public function domainSettings() : void { $this->updateNginxVhost(); $this->reloadNginxService(); }
```

and `reloadNginxService()` calls `$this->reloadService("nginx")`. The literal service name `"nginx"` appears four times in that file, and the command builder is `src/System/Command/ServiceReloadCommand.php`:

```php
sprintf("/usr/bin/sudo /bin/systemctl reload %s &", escapeshellarg($serviceName))
public function isSuccessful() : bool { return true; }
```

Two things follow. The service reloaded is the vendor unit named `nginx`, whose `ExecStart` carries no `-c`, so it reads the compiled-in default configuration path `/etc/nginx/nginx.conf` - precisely the file whose line 119 includes the site directory and whose line 1 says `user root;`. And the reload is backgrounded and its success is hardcoded, so the panel can never learn that a reload failed.

### Vulnerability Summary preconditions

The chain requires four conditions, and it is worth being exact about which of them are attacker-controllable.

The attacker must hold a panel account with `ROLE_USER` and must know its credentials. Not attacker-controllable in general; this is what makes the finding post-authentication and puts it at `PR:L` rather than `PR:N`.

That account must own at least one site. Site creation is an administrator action and two separate gates prevent a `ROLE_USER` from self-serving one: `SitesController::getSite()` returns null for any `{domainName}` the account does not own, and `NewSiteController::hasPermissions()`, which evaluates `if (!(ROLE_USER != getRole())) return false;`, appears eight times covering all seven site-creation entry points. So a `ROLE_USER` cannot grant itself a site. In a hosting deployment this precondition is satisfied by design the moment an operator onboards a customer, which is the product's reason to exist.

The payload must be syntactically valid nginx. This one is attacker-controllable but it is a real constraint, and it is enforced by nginx rather than by the product. The product performs no `nginx -t` on this code path and keeps no backup, so an invalid payload is written to disk and then simply fails to reload: the injection persists, has no effect, and guarantees that the next nginx restart fails. That is a persistent denial-of-service condition which we report separately and deliberately do not score into the code-execution vector.

The payload must arrange for php-fpm to receive an attacker-controlled `SCRIPT_FILENAME`. In practice this means including the product's own `/etc/nginx/fastcgi_params`, which carries `fastcgi_param SCRIPT_FILENAME $request_filename;` at line 6, or setting `SCRIPT_FILENAME` to an absolute path explicitly. Both work. We measured this as a hard requirement, and the reason it is hard is not established - see section 8.

## 3. Authentication Boundary

### Authentication Boundary — how sessions are issued

Sessions are ordinary Symfony sessions issued by the `main` firewall through `App\Security\LoginFormAuthenticator`. A `POST /login` carrying the fields `userName`, `password` and `_csrf_token` - those exact names, not `_username` - returns `302` with `location: /` on success and sets the session cookie `cloudpanel` alongside a `locale` cookie. Measured on a live instance, a successful login returned `302` with a 250-byte body and a subsequent `GET /` returned `200` with a 12,626-byte body containing the account name and a logout affordance.

Failure is a redirect, not a challenge. A wrong password returns `302` with a 270-byte body and `location: /login`, and every subsequent authenticated request also returns `302` with 270 bytes pointing back at `/login`. A nonexistent account returns a response that is byte-identical to the wrong-password response, so there is no user-enumeration oracle. The panel login surface never emits `401`; the only `401` anywhere in the product is in the non-Symfony file `public/phpmyadmin/login.php:29`, as a HTTP-Basic fallback. A size wobble on `GET /login` of 4422, 4404 and 4399 bytes across three fetches is fully explained by the length of `_csrf_token` in each page, which was 127, 109 and 104 characters, and is therefore not an oracle either.

There are two other authenticators. `App\Security\AutoLoginAuthenticator` serves `^/autologin` and reads a token whose value is a filename: `sprintf("%s/var/.token_%s", $this->kernel->getProjectDir(), $token)`, with the file content as the credential, keys `userName` and `expiration`, an `@unlink` in a `finally` block, and no `HMAC(APP_SECRET)` construction. No writer for `var/.token_*` exists anywhere in the package - two independently decoded corpora searched for it, one of 1373 files and one built through the parser tokenizer with 498 files parsed, zero failures, 450521 tokens, 11580 string literals, and four positive controls. The surface exists and is not self-serviceable. `App\Security\ApiTokenAuthenticator` serves `^/api` and is analysed in full in section 10 because it is the only anonymous identity-swap primitive in the product.

### Authentication Boundary — what the gate actually checks

Authorisation is a nine-rule access-control list in `config/packages/security.yaml`. That file was read from the package payload rather than transcribed from an earlier note: md5 `3a9319979994ba388bf8871fb6646fd3`, 1,447 bytes, 37 lines. The relevant rules, verbatim:

```yaml
access_control:
    - { path: ^/admin/user/creation, roles: PUBLIC_ACCESS }
    - { path: ^/autologin, roles: PUBLIC_ACCESS }
    - { path: ^/admin, roles: [ ROLE_ADMIN ] }
    - { path: ^/login$, roles: PUBLIC_ACCESS }
    - { path: ^/login/mfa$, roles: PUBLIC_ACCESS }
    - { path: ^/locale/change$, roles: PUBLIC_ACCESS }
    - { path: ^/pma$, roles: PUBLIC_ACCESS }
    - { path: ^/pma/logout$, roles: PUBLIC_ACCESS }
    - { path: ^/, role: IS_AUTHENTICATED_FULLY }
```

Seven of the nine rules are public. One rule requires `ROLE_ADMIN` and it is anchored at `^/admin`. The last rule is the catch-all and it requires full authentication for everything else. A comment two lines above the block states that only the first matching rule is used, which makes the ordering significant and tells us the ordering is deliberate: `^/admin/user/creation` is listed before `^/admin` precisely so that the installation wizard stays anonymous.

The site settings page is `POST /site/{domainName}/settings`. It is not under `^/admin`. It therefore falls to the catch-all and requires only a fully authenticated session. Any panel account, of any role, passes that gate; ownership of the site is enforced later, inside the controller.

One detail deserves emphasis because it is easy to get wrong and it determines whether the catch-all is real. The last rule uses the singular key `role:` rather than `roles:`. That singular key is valid, not a typo that silently disables the rule: `MainConfiguration.php:155` calls `->fixXmlConfig('role')` and `SecurityExtension.php:207` reads `$attributes = $access['roles'];`, so the normalisation folds the singular form into the plural one. The dynamic proof that the catch-all is live is that an anonymous request for a deliberately nonexistent path returns `302` to `/login` rather than `404`, which means the access-control check fires before route resolution. Fourteen sampled protected paths all returned `302`. Twelve URI-mismatch variants - trailing slash, doubled slash, encoded slash, matrix-semicolon path parameter, dot segments, percent-encoded letters, a null byte, upper-case folding and an added query string - were fired at one protected route, `/admin/users`, and none of the twelve was admitted; the only non-`302` result was `400` with 150 bytes, which is nginx rejecting the null byte.

### Authentication Boundary — the principal required by the sink

The least privileged principal demonstrated to reach the sink holds `ROLE_USER` and nothing more.

The evidence for that is layered rather than resting on a single reading. `security.yaml` declares two roles, `ROLE_ADMIN` and `ROLE_USER`, and contains no `role_hierarchy` key at all, so `ROLE_USER` inherits nothing. In `src/Entity/User.php` the field declaration at line 132 is `private $role = self::ROLE_USER;` and the array at line 152 is `private $roles = [];`, with the three role constants declared at lines 26 to 28, so the roles collection returned for a low-privilege account is `['ROLE_USER']`. A textual survey of role idioms across the tree found six files using them, and all fourteen administrative controllers under `Admin/` have zero occurrences, meaning authorisation for the administrative surface lives entirely in the access-control list rather than in per-controller checks. In the handler that owns this sink, `grep -oE 'ROLE_[A-Z_]+' src/Controller/Frontend/SitesController.php` returns exactly one hit: `ROLE_USER`.

And it was performed with that principal. Across the two reproduction sets, four distinct `ROLE_USER` identities executed five injection rounds - in one set a single identity ran two consecutive rounds against the same site, in the other each of three identities had its own site - and each round was measured at the HTTP layer: the login returned `302` with `location: /`; the settings page returned `200` with sizes of 21777 and 21831 and 21843 bytes in different rounds; the save returned `302` redirecting back to the same settings path. In every case the injection took effect and the marker came back with `uid=0`.

The accounts used were created through the product's own administrative user-creation form `POST /admin/user/new` with a CSRF token, fields `admin_user[userName]`, `admin_user[plainPassword]`, `admin_user[role]` set to `ROLE_USER`, `admin_user[status]`, `admin_user[timezone]` and `admin_user[sites]`. That is administrator provisioning, which is the product's intended workflow, and it is not part of the attack chain.

### Authentication Boundary — the credential posture of a fresh installation

This finding is not a default-credential finding, and the distinction is load-bearing rather than cosmetic.

CloudPanel ships in a zero-user state. There is no factory panel password, no built-in `admin` account with a published secret and no fallback credential anywhere. The only path to the first administrator is the installation wizard at `^/admin/user/creation`, which is public in the access-control list, is ordered ahead of the `^/admin` rule so that ordering works in its favour, and is gated by `if (!count($users))`, the two flattened labels being `Fcf30` and `F5828`. The installer itself is a shell-side affair: the four Debian maintainer scripts expose no HTTP endpoints and the installer removes its staging tree when it finishes, and there is no persistent `installed` flag either - thirty database tables were enumerated on a live instance and the configuration table holds only cloud and masquerade-address keys, so the gate is the user-table count and nothing else.

That gate was attacked and closed with two independent measurements. Once a user exists, an anonymous `GET` of `/admin/user/creation` returns `302` to `/login` and an anonymous `POST` likewise, in both cases without ever yielding a CSRF token; an administrator identity chosen by the attacker was not persisted, the user table afterwards still held the single pre-existing row, and a login attempt with the chosen credentials failed. On a truly zero-user installation the wizard page does return `200` with 25,702 bytes, which is anonymous reachability of a credential-creation surface - but exploiting it requires the host to be in a state that exists only between package installation and first use, and we do not count an installation wizard as a vulnerability.

The account used for verification in this work was seeded by us, on an earlier provisioning pass, through the product's own wizard and then through the product's own user form. It is not a factory default and it does not exist in a shipped artifact. The password is a command-line argument to the reference exploit and appears nowhere in published material.

### Authentication Boundary — what is deliberately not claimed

We do not claim that the chain is unauthenticated. Every one of the five rounds began with a valid `ROLE_USER` session.

We do not claim that the chain is a privilege-escalation issue in the conventional sense. It is not a low-privilege OS account reaching root: the start principal is an application role stored in a database, and the end principal is an OS account in `/etc/passwd`. Those are two different subjects. What the chain does is take a configuration-write surface belonging to an application role and turn it into host-root execution through vendor-owned service identities. The honest formulation of the gain is that the site system account (observed as uid 1003), the panel account `clp` (uid 1000) and the `ROLE_USER` application role are none of them `uid=0`, and the chain crosses from the first of those that a real attacker can obtain into `uid=0`, remotely, with no local shell.

We do not claim that `ROLE_USER` is inert. An earlier reading in this research - that a `ROLE_USER` has no SSH access, no sudo and no shell - was disproved and withdrawn. `CreateUserCommand.php:2` reads `useradd -p %s -%s %s %s -s %s -d %s %s %s`, where the shell is a parameter, and `SiteSshUserType.php`, `SiteSshUserEditType.php` and `SshUserManager.php` are all present, so a `ROLE_USER` can create a site SSH user with a shell and log in as uid 1003. `/etc/sudoers.d/cloudpanel` line 3 reads `ALL ALL=(ALL) NOPASSWD: /usr/bin/clpctlWrapper`, which gives any local user the clpctl command set for free, and line 2 reads `clp ALL=(ALL) NOPASSWD: ALL`, so the `clp` account genuinely can become root locally without a password. That local route already existed; it needs a local shell. The point of the correction is that the gain from this finding must be argued on remote reachability rather than on the weakness of the starting role, which is not weak.

We do not claim that the web form is the only path into the same sink. The same sudoers line exposes `SiteAddStaticCommand` and `SiteAddPhpCommand`, which write to the identical virtual-host sink, to any local user, running as `clp`. Whether a local `clpctl site:add` can inject the same field was not tested.

We do not claim coverage of the whole route space. Twenty-two of 119 Symfony routes were exercised anonymously, about eighteen percent. The catch-all evidence is structural and it is strong for the question it answers - that an anonymous request to any path is redirected - but it says nothing about whether a second-layer check inside an individual route body fails open, and those bodies were not individually tested.

## 4. Attack Surface

### Attack Surface — listeners, routes and their protection

The product presents two separate HTTP surfaces served by two separate nginx processes, and mixing them up makes the whole chain unintelligible. This table is the single most important structural fact in the analysis.

| | Site-facing nginx, the one that gets injected | Panel nginx, the one that does not |
|---|---|---|
| Configuration path | `/etc/nginx/nginx.conf` | `/home/clp/services/nginx/nginx.conf` |
| Owning package | vendor `nginx-common 1.30.4-1+clp-bookworm` | CloudPanel package payload |
| Line 1, verbatim | `user root;` | `user clp;` |
| Digest and size | md5 `6727bffeb96cb3e03b85d00eac39c47c`, 3,077 bytes | md5 `1feb5d8bda1f1b2e6f3a8b0a1264d1dc` |
| Include directive | line 119, `include /etc/nginx/sites-enabled/*.conf;` | line 76, `include /home/clp/services/nginx/sites-enabled/*.conf;`, and that directory holds one file, `cloudpanel.conf`, 3,065 bytes, md5 `07570ef1c48198691ac8c8edeb3bef1f` |
| Pid file | `/run/nginx.pid` | line 3, `pid /run/clp-nginx.pid;` |
| Unit and its `ExecStart` | `nginx.service`, `/lib/systemd/system/nginx.service:22` reads `ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'` with no `-c` | `clp-nginx.service`, lines 21 to 23 all carry `-c /home/clp/services/nginx/nginx.conf`; installed by the package `postinst` at line 341 |
| Observed workers | 32 workers, uid 0, root | 32 workers, uid 1000, clp |
| Listener | 443, plus 80 and 8080 inside the virtual-host template | 8443 |
| Target of the product's reload | yes - the literal service name `"nginx"` | no |

The port on which the panel listens, 8443, is also where the login form, the site settings form, the File Manager front controller and the phpMyAdmin integration live. The port that serves hosted sites, 443, is where the injected directives execute. The attacker's authenticated request goes to the first and the attacker's anonymous requests go to the second.

The listener inventory is not just the two HTTP surfaces. MariaDB listens on every interface, `0.0.0.0:3306` and `[::]:3306`, with `@@bind_address` reading NULL and `@@secure_file_priv` reading NULL, though there is no `root@%` account so the exposure is a disclosure item rather than an authentication bypass. The default state of that binding was proven by digest comparison: the drop-in `100-cloudpanel.cnf` has md5 `f99104babf8b905c7acff5cdba9c1c3c` and matches the packaged file, and its directory contains only that one file, which establishes that the maintainer script's clearing of the directory really ran and that the distribution default of `bind-address=127.0.0.1` in `50-server.cnf` was deleted.

### Attack Surface — how the surface was mapped

Three independent means, cross-checked against each other, and the numbers below are the ones that survived a re-run.

The product's own router introspection. `php bin/console debug:router --no-interaction` was executed on a live instance of this build from inside the container, with the application root `/home/clp/htdocs/app/files`, and returned a zero exit code and 15,745 bytes. That output is 124 lines: three table border lines, one header line, 119 route rows and one blank line. So the Symfony route space is 119 routes. An earlier figure of 129 lines was carried through several notes and is not reproducible - even counting the two PHP extension warnings that were present, `redis.so` and `memcached.so`, the total is 126 - and it is discarded here. The arithmetic closes independently: `grep -o 'path:' config/routes.yaml | wc -l` returns 121, three of those are commented out at lines 2, 6 and 10, giving 118, and `config/routes/endroid_qr_code.yaml` imports exactly one more, `qr_code_generate` at `/qr-code/{builder}/{data}`, giving 119. `config/routes.yaml` itself is plaintext and unobfuscated, 483 lines, md5 `53d7b7c5769613976783fcac98a7d232`, and a grep for `path:` returned 121 hits, which serves as the positive control proving that the file was searched rather than mis-parsed.

The filesystem route. `public/` contains 2,349 PHP files, of which 2,345 live under `public/phpmyadmin/`. Excluding phpMyAdmin, the File Manager tree and vendor code leaves exactly one front controller, `public/index.php`.

The access-control route. The nine rules quoted in section 3, each of which was either exercised dynamically or read statically and labelled accordingly.

And a fourth finding that qualifies all three: the Symfony route space is not the whole HTTP surface. In the panel configuration `cloudpanel.conf` - specifically `cloudpanel.conf:24-26` and `cloudpanel.conf:33-37` - the two blocks read:

```
location /file-manager/ {
  try_files $uri $uri/ /file-manager/index.php?$args;
  location ~ \.php$ {
    include fastcgi_params;
    fastcgi_intercept_errors on;
```

and lines 24 to 29 read:

```
if ($request_uri ~ ^/phpmyadmin) {
  set $basicAuth "off";
}

auth_basic $basicAuth;
auth_basic_user_file /home/clp/services/nginx/basic-auth/credentials;
```

So `/file-manager/**` is served by nginx directly through `try_files` and never reaches the Symfony front controller, and `/phpmyadmin/**` is served the same way through a `rewrite` at line 31 plus its own PHP location block, and the panel's own HTTP Basic authentication is explicitly switched off for it by the `set $basicAuth "off"` assignment. Neither prefix is governed by the access-control list, including the catch-all at line 37. The dynamic disproof is clean: an anonymous `GET /phpmyadmin/login.php` executes the script and reflects the `Host` header into a `Location` response header, whereas every one of the fourteen sampled Symfony paths returned `302` to `/login`. If that path had passed through the framework it would have redirected.

Both non-Symfony PHP surfaces are worth pinning down, because neither is covered by anything the framework enforces. `public/phpmyadmin/login.php` is plaintext, 86 lines, md5 `733ad4edb3239f67439282d7a5a61294`; its lines 46 to 49 read `$serverHost = $_SERVER['HTTP_HOST'] ?? '';` at `public/phpmyadmin/login.php:46`, then `$redirectUrl = sprintf('%s://%s/pma', ..., $serverHost);` at `:48`, then `header(sprintf('Location: %s', $redirectUrl));` at `login.php:49`, with no validation of the host value - an anonymous `GET /phpmyadmin/login.php` carrying a forged `Host` reflects that host into the response, and the control request without the forged header reflects the real one. Separately, the vendor changed phpMyAdmin's own authentication type from the upstream cookie mode to signon at `config.inc.php:37-44`, commenting out the two upstream lines, so there is no anonymous credential form at all; the only entry is a vendor-written HTTP Basic bridge. The File Manager backend's own action endpoints live under `/file-manager/backend/compress` and its siblings, and are governed by the session key and `checkPath()` gate described above rather than by `access_control`.

The File Manager backend is still gated, and it is gated fail-closed. It requires a session key `clp-file-manager` whose only writer in the whole tree is `SitesController.php` at labels `Ec659` through `ee99f`, and every one of its fourteen action endpoints passes `backend.php:2` label `B5229` into `checkPath()`, which does `realpath`, `str_starts_with($file, rtrim($homeDirectory,'/'))` and `exit` on failure, appearing nineteen times in that file with eleven read-write actions all hitting it; the filename check `isFilenameValid()` uses the pattern `/^(?!.*\.\.)…$/`. On the anonymous side, the double gate reads `d9914 is_null($user)` then `d12b4: exit`, and `eef25` then `b7186: exit`, and `$homeDirectory` has exactly one assignment in the file, `$sprintf("/home/%s/",$user)`, verified exhaustively rather than by sampling, so a null-directory fail-open is not reachable. Three dynamic states confirmed it: no cookie returns 0 bytes, an anonymous real session returns 0 bytes, and a seeded session returns 311 bytes of real JSON, against a positive scale of 81,087 bytes.

### Attack Surface — components that narrow the surface

Several surfaces that look promising are closed, and naming them matters as much as naming the open one.

The developer firewall is off. `security.yaml` lines 9 to 11 declare `pattern: ^/(_(profiler|wdt)|css|images|js)/` with `security: false`, which removes those four prefixes from the security subsystem entirely. It is unreachable in practice because the environment is production: all three copies of `.env` on the instance are identical and read `APP_ENV=prod` and `APP_DEBUG=false`, and the packaged template value equals the runtime value because the maintainer script installs it at line 86. The profiler and web-debug-toolbar routes are not registered and an anonymous `GET /_profiler/latest` returns `302`. Worth noting, though, that the same rule also disables security for `^/js/`, `^/css/` and `^/images/`, and whether any functional route lives under those prefixes was not enumerated.

The API surface does not exist. There are zero routes beginning with `/api`, so the `api` firewall guards an empty path space. Section 10 covers this in full because it is also the identity-swap question.

There is no password-reset surface at all. `config/routes.yaml` returns zero hits for `reset`, `forgot`, `password` and `recover`, against a positive control of 121 `path:` hits, so the file is plaintext and greppable and the zero is meaningful. The only reset capability is the local console command `user:reset:password`, and the runtime registration surface does not include that namespace: invoking `clpctl` with no arguments enumerates exactly `db:export`, `db:import`, `system:permissions:reset` and `varnish-cache:purge`. A related correction is worth recording because it prevents a later reader from wasting effort - a vendor changelog line describing a "Generate Password Link" refers to the client-side JavaScript password generator analysed in section 10, not to a reset-link surface. There is no token-shaped or URL-shaped reset link anywhere in the decoded corpus.

The installation wizard is anonymous but dead after first use, as established in section 3.

### Attack Surface — the injected configuration in its loading context

`nginx -T -c /etc/nginx/nginx.conf` enumerates what the site-facing process actually loads, and the list is the proof that the injected file is inside the loaded set rather than in some ignored directory:

```
# configuration file /etc/nginx/nginx.conf:
# configuration file /etc/nginx/sites-enabled/victim.example.com.conf:
# configuration file /etc/nginx/sites-enabled/default.conf:
# configuration file /etc/nginx/fastcgi_params:
# configuration file /etc/nginx/global_settings:
# configuration file /etc/nginx/blocked_ips:
# configuration file /etc/nginx/mime.types:
# configuration file /etc/nginx/modules-enabled/<18 module files>:
```

One directory entry deserves a mention because it looks like a symlink-based dependency and is not. `/etc/nginx/sites-enabled/default` is a symlink to `/etc/nginx/sites-available/default`, and it is triply shown to be irrelevant to the chain: `dpkg -S /etc/nginx/sites-enabled/default.conf` attributes the real file to the vendor nginx package, its modification time predates the rounds by many hours, and because the include only consumes `*.conf`, a symlink with no extension is never loaded at all - `nginx -T | grep '^# configuration file' | grep -c 'sites-enabled/default:'` returns zero. In the authoritative round, counting `l` entries in `/etc/nginx/sites-enabled/` gave exactly one, that inherited symlink, and counting them in `/home/clp/services/nginx/sites-enabled/` gave zero. No symlink is part of the chain.

## 5. Sink Identification

### Sink Identification — how the sink was found

The sink was found by walking the write path of the virtual-host file backwards from a constant, not by fuzzing the form. The constant is in `src/Site/Creator.php`:

```php
NGINX_VHOST_DIRECTORY = "/etc/nginx/sites-enabled/"
```

that literal appearing three times across the decoded corpus, sitting alongside two siblings in the same family, `NGINX_SSL_CERTIFICATES_DIRECTORY = "/etc/nginx/ssl-certificates/"` appearing five times and `NGINX_BASIC_AUTH_DIRECTORY = "/etc/nginx/basic-auth/"` appearing three times. From that constant backwards to the command that writes to it, and then to the processor classes that build the text, gives the sink directly.

The processor family is the interesting part. Virtual-host text is not assembled by string concatenation in a controller; it is assembled by a set of processor classes, each owning one template placeholder, each overriding a `$placeholder` property and a method that computes the replacement value. `RootDirectory` owns `{{root}}`. `Settings` owns `{{settings}}`. `PhpSettings` owns `{{php_settings}}`. Finding one therefore identifies the family, which is why the sibling question is answered in its own subsection below rather than left implicit.

### Sink Identification — the vulnerable construction

Three statements, already quoted in section 2, are the whole sink:

```php
protected string $placeholder = "{{root}}";
Aca8b: $rootDirectory = $this->site->getRootDirectory();
b9892: $placeholderValue = rtrim(sprintf("root /home/%s/htdocs/%s;", $siteUser, $rootDirectory), "/");
e35ff: $content = $this->replace($placeholderValue, $content);
```

Between `Aca8b`, where the value enters, and `b9892`, where it is composed into a directive, there is no call of any kind. No `basename`, no `realpath`, no `preg_match`, no allowlist, no blacklist, no length check, no character check. The value that was read from the database is the value that is concatenated. The only function in the line is `rtrim`, and it operates on the composed string rather than on the input, and it targets a character that the composed string provably never ends with.

`$siteUser` is the site's system account, taken from `$this->site->getUser()`. The consequence for exploitation is that the attacker does not control the `root` directive's value directly; the attacker controls its tail. A trailing newline in the tail ends the directive. That is sufficient, and it is also why the first line of every working payload is a bare semicolon: it terminates the already-started `root` directive cleanly before the attacker's own blocks begin.

### Sink Identification — the writer, and why this is not command injection

`src/System/Command/Vhost/WriteFileCommand.php` at label `Dc4ef`:

```php
echo %s | /usr/bin/sudo /usr/bin/tee %s
```

Both substitutions pass through `escapeshellarg`. The newlines inside the value are therefore inside a single-quoted shell argument, `tee` receives them as data, and the data written is exactly the composed configuration text. There is no shell injection here, and it would be wrong to classify this as CWE-78. The escalation to code execution happens later and somewhere else: nginx parses the file as configuration, and the attacker's `location` blocks are honoured as configuration. That is CWE-93, injection of control characters into a value that is later interpreted by a different parser.

The same reasoning applies to the wider command family, and it is worth a number. Under `src/System/Command/` there are 49 command builders, 44 of which contain `escapeshellarg`, and five command sinks reach execution. `WriteFileCommand` itself has fourteen callers, and all fourteen were walked to determine their routing home; the count reachable from an unauthenticated request was zero. So `escapeshellarg` discipline across this family is genuinely good, and that discipline is exactly what makes the configuration-text layer the only place a defect of this kind can survive. Escaping a shell argument does nothing for a parser that is not a shell.

Of the five builders without escaping, three take only constant arguments, one takes a temporary filename, and one builds a `find` invocation that is reachable only from the console with an argument derived from a value already constrained by the `AppAssert\DomainName` validator.

### Sink Identification — the template that receives the substitution

The template text is not in the package. It is a row in the SQLite `vhost_template.template` column, populated at install time by a git clone. The maintainer script at line 97 runs:

```
su -s /bin/bash -c "/usr/bin/clpctl vhost-templates:import &> /dev/null" clp
```

and `src/Command/VhostTemplatesImportCommand.php` contains, verbatim:

```php
$gitCloneCommand = sprintf("/usr/bin/git clone %s %s", $_ENV["APP_VHOST_GIT_REPOSITORY"], $tmpVhostTemplatesDirectory);
```

with `Process::fromShellCommandline($gitCloneCommand)` running it, the directory built as `sprintf("%s/v%s/", rtrim($tmpVhostTemplatesDirectory,"/"), $_ENV["APP_VHOST_DIRECTORY"])`, and every import first calling a delete-by-type and then re-inserting. The two environment values in `.env` are `APP_VHOST_GIT_REPOSITORY='https://github.com/cloudpanel-io/vhost-templates.git'` at line 5 and `APP_VHOST_DIRECTORY='2-http3'` at line 6.

A package-wide search for the literal `{{root}}` hits exactly one file, `RootDirectory.php`. The three plaintext templates that are shipped, `custom-domain`, `redirect` and `redirect-http3` under `resources/nginx/vhost_template/`, are all redirect helpers and none of them contains `{{root}}`. The `redirect` template in full is:

```
server {
  listen 80;
  listen [::]:80;
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  {{ssl_certificate_key}}
  {{ssl_certificate}}
  {{redirect_server_name}}
  return 301 https://{{redirect_domain}}$request_uri;
}
```

The hosting template that matters, the Generic one, has this structure, reconstructed from a fetch of the same repository the installer clones and given by structural facts rather than by absolute line numbers because the master branch drifts. It contains two server blocks, one listening on 80 and 443 and one on 8080. `{{root}}` appears twice, once in each server block, and in both cases at server context, before any `location` block. `{{settings}}` appears in the first server block. The second server block has the only PHP location in the template, with `include fastcgi_params;` and `fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;` and `fastcgi_pass 127.0.0.1:{{php_fpm_port}};`, plus `fastcgi_param PHP_VALUE "{{php_settings}}";`. The only deny rule in the whole template is `location ~ /\.(ht|svn|git) { deny all; }`.

Three structural consequences drive the payload design. Injected content lands at server context ahead of the template's own `location` blocks, so an injected prefix match cannot be shadowed by them. Regex locations are matched in order of appearance but prefix matches are matched by specificity, and the payloads below all use `^~`, which is a prefix match that suppresses regex evaluation once matched - hence it outranks the template's own regex locations. And the two occurrences of `{{root}}` mean the payload is inserted twice into the file, once per server block, which is consistent with the observed size growth.

The one validation the product applies to virtual-host text is structural, and it applies to the template rather than to the rendered output. `src/Command/VhostTemplateAddCommand.php` declares `private array $requiredPlaceholders = ["server_name", "root"];` and `validateVhostTemplate()` throws `Placeholder "%s" is required and missing.` The vendor therefore knows that virtual-host text is a structure requiring validation - it validates that the placeholders exist, and validates nothing about the values substituted into them.

### Sink Identification — execution identity of the child process

Two vendor-packaged decisions make the child process run as root. Neither is attacker-supplied and neither is a non-default setting.

The nginx worker identity. `/etc/nginx/nginx.conf` line 1 is `user root;`, in the vendor's own build of nginx, and 32 workers were observed with uid 0. This claim is pinned by three independent measurements, and the fourth measurement that might be expected is discarded on purpose:

1. The package was downloaded directly from the vendor repository and unpacked: `dpkg-deb --fsys-tarfile | tar -xO ./etc/nginx/nginx.conf` yielded line 1 verbatim as `user root;`, md5 `6727bffeb96cb3e03b85d00eac39c47c`, 3,077 bytes, with the include at line 119. The repository metadata is `pool/nginx/n/nginx/nginx-common_1.30.4-1+clp-bookworm_all.deb`, 14,106,602 bytes, digest `210fd2c7d65d7cf04b22fa29c52cc578`, listed in the index at `dists/bookworm/nginx/binary-amd64/Packages`, 42,288 bytes covering 45 packages.
2. The same vendor package was independently unpacked again during reproduction, with `dpkg-deb -x`, and its first three lines were read as `user root;`, `worker_processes auto;` and `pid /run/nginx.pid;`. The unpacked digest equalled the installed digest.
3. Structural corroboration: the installed file's modification timestamp equals the package build time and predates the rounds by months; the distribution's stock nginx has `user www-data;` as its first line, so no line deletion could transform one into the other; and the vendor unit's `ExecStart` carries no `-c`, so this is provably the file the running process reads.

The measurement that was discarded: `dpkg -V nginx-common` returns empty with code 0, which looks like a fourth proof and is not one. Debian packaging convention keeps configuration files out of the `md5sums` control file, and `grep etc/nginx/nginx.conf /var/lib/dpkg/info/nginx-common.md5sums` returns nothing, so there is no recorded value for the verification to compare against. An empty result carries no information either way and is not used as evidence.

One further hypothesis was tested and disproved rather than assumed: that our own harness had produced `user root;` by deleting the stock `user` line. The harness script that installs the vendor nginx is 940 bytes and contains zero occurrences of `sed` or of `user`; a recursive grep for `sed -i` variants across the harness tree returned nothing. And a genuinely stock instance, on which the vendor package had not been installed, showed Debian nginx 1.22.1 with a 1,446-byte configuration whose first line is `user www-data;` and whose include sits at line 60 - proving that the two states are distinguishable and that installing the vendor package is what changes the path from one to the other.

The PHP execution identity. The File Manager pool file is a packaged file, `dpkg -S` attributing it to `cloudpanel:`, physically 17 lines with `wc -l` reporting 16, md5 `83e79f2f3de4afad76c0b0a4666dcb89`, and the payload copy, the unpacked-data copy and the runtime copy are byte-identical:

```
[clp-file-manager]
listen = /run/clp-fm-php-fpm.sock
user = root
group = clp
listen.owner = root
listen.group = clp
listen.mode = 0660
pm = ondemand
```

Line 2 is the socket, line 3 is `user = root`, line 4 is `group = clp`, line 5 `listen.owner = root`, line 6 `listen.group = clp`, line 7 `listen.mode = 0660`. Nowhere in the seventeen lines is there a `php_admin_value`, an `open_basedir`, a `disable_functions` or a `security.limit_extensions` directive, and a grep for `security.limit_extensions` across all three trees returns zero hits, so php-fpm's compiled-in default of `.php` applies. The socket itself was observed as `srw-rw---- 1 root clp /run/clp-fm-php-fpm.sock`.

The panel's own pool is different and, notably, is not the amplifier: `listen = /run/clp-php-fpm.sock`, `user = clp`, `group = clp`, `listen.owner = clp`, `listen.group = clp`, `listen.mode = 0660`.

That the `group = clp` directive is real and load-bearing, not decoration, is confirmed by the shape of the identity string that came back over HTTP in every round: `uid=0(root) gid=1000(clp) groups=1000(clp),0(root)`. A pool declaring only `user = root` would have produced `gid=0(root) groups=0(root)`. Section 9 develops why that asymmetry matters more than it looks.

### Sink Identification — sibling sinks, and whether they are proven

Three siblings of `RootDirectory` were examined, and their status differs.

`Settings.php` feeding `{{settings}}` is a genuine second injection point of the same shape and it is not proven. `getPageSpeedSettings()` concatenates lines verbatim:

```php
foreach ($pageSpeedSettingsExploded as $setting) { $setting = trim($setting); if (!(false === empty($setting))) { $pageSpeedSettingsContent .= sprintf("  %s", $setting) . PHP_EOL; } }
```

The only operation is `trim`, and the placeholder sits at server context in the template. Its authorisation gate is presumed to be the same `ROLE_USER` gate because the settings page hosts a `site_page_speed_settings` form alongside `site_domain_settings`, but that presumption was not verified, and no dynamic round was run against it. We report it as an unproven second instance of the same root cause, which is why the fix recommendation asks for one shared normalization across all processors rather than a patch to this one field.

`PhpSettings.php` feeding `{{php_settings}}`, at label `b251a` reading `$placeholderValue .= PHP_EOL . $additionalConfigurations;`, is not an nginx-directive injection. The value lands inside `fastcgi_param PHP_VALUE "{{php_settings}}";`, which is a quoted PHP ini surface, and the upstream field has a four-step normalization including the rewrite of double quotes to single quotes at flattened label `ada86`. It is discussed in section 6 as the contrast case.

The `CreateSymlinkCommand` builder is not a sibling at all, and this matters because a symlink-based explanation of the chain would be a harness artifact rather than a product defect. `grep -rl 'CreateSymlinkCommand' src/` returns exactly two files: its own definition and `src/Site/Updater.php` as its sole consumer, whose use is symlinking SSH site-user directories. `Creator.php`, `Creator/StaticSite.php` and the rest of `Updater/*.php` have zero hits. No symlink participates in loading the injected virtual host, and the two reproduction sets were both wired with zero symlinks.

## 6. Source Identification

### Source Identification — the tainted input and its transport

The tainted input is a single URL-encoded form field on a single endpoint:

```
POST /site/victim.example.com/settings HTTP/1.1
Host: <panel-host>:8443
Cookie: cloudpanel=<session>; locale=<locale>
Content-Type: application/x-www-form-urlencoded

site_domain_settings[rootDirectory]=<PAYLOAD>&site_domain_settings[_token]=<token>
```

The route is registered as `clp_site_settings` and accepts any method, which the product's own router listing shows as `clp_site_settings ANY /site/{domainName}/settings`. The page that hosts the form carries four separate forms - `site_delete`, `site_domain_settings`, `site_page_speed_settings` and `site_user_settings` - so the exploit scrapes the live page for the named form rather than assuming field ordering. The field as rendered, verbatim from a live page:

```html
<input type="text" id="site_domain_settings_rootDirectory" name="site_domain_settings[rootDirectory]" required="required" class="form-control form-control-lg" value="victim.example.com" />
```

Two properties of that rendering are worth naming. It is a plain single-line text input, so no browser will ever put a newline in it voluntarily, and the field's own label in the product's form class is "Root Directory". The `required="required"` attribute is an HTML-level hint that produces no server-side character restriction whatever. And the default value the product puts in the box is the domain name itself, which is why every payload in this work appends to the existing value rather than replacing it: `before.rstrip("/") + payload`, preserving a plausible prefix and keeping the site nominally functional.

The transport is the only runtime carrier. The form declaration in `src/Form/SiteDomainSettingsType.php`, which is plaintext and two lines wide, is:

```php
$builder->add("domainName", TextType::class, ["required" => false, ..., "disabled" => true, "label" => "Domain Name"]);
$builder->add("rootDirectory", TextType::class, ["required" => true, "attr" => [...], "label" => "Root Directory", "constraints" => [new Assert\NotNull()]]);
```

The console channel could in principle reach the same sink through `SiteAddStaticCommand` or `SiteAddPhpCommand`, which the sudoers drop-in exposes to any local user, but that was not tested and is recorded as an open question. The wording used throughout this document is therefore the narrow and defensible one: for a remote attacker, the only runtime carrier of a newline-bearing `rootDirectory` value is the authenticated web form. It is not correct to say the web form is the only path.

### Source Identification — sanitization that exists, and what it is for

Sanitization does exist in this product, in the neighbourhood of this field, for other fields. Four instances, all of which strengthen rather than weaken the finding, because together they show that the absence here is an omission rather than a design statement.

First, the same form family validates its domain field with a dedicated constraint class. Six site-creation forms each carry `new AppAssert\DomainName()` in their constraint array, for example in `SiteNewPhpType.php` at flattened label `A1915`, and `DomainNameValidator.php:13` defines a pattern whose character class excludes both `/` and `\`. So this vendor writes character-level validators for site fields when it wants one.

Second, the console channel clamps the identical value. The command-line site-creation path applies `ltrim(rtrim($x,"/"),"/")` to the root directory before use. The vendor therefore knows this specific field needs normalisation, and applied it on exactly one of the two channels.

Third, a neighbouring free-text field on the same settings page has a four-step normalization registered as a pre-submit listener. In `Form/SitePhpSettingsType.php`, for the field `additionalConfiguration`, the flattened sequence is: label `D7204` `$additionalConfiguration = trim($data["additionalConfiguration"]);`, label `df5b8` `explode(PHP_EOL, ...)`, label `ac761` `$value = trim($value);`, label `ada86` `$value = str_replace(["\""], ["'"], $value);`, then labels `b489b` and `C8ee3` appending a `;` if the line does not already end with one, and label `Aec53` `implode(PHP_EOL, ...)`. It is a line-oriented sanitizer built precisely to neutralize the characters that matter to a directive parser, including the double quote that would escape a quoted-string context.

Fourth, the virtual-host template layer has structural validation, described in section 5: `requiredPlaceholders` and the "required and missing" exception.

The `additionalConfiguration` case is instructive about why the fourth instance is not itself a vulnerability. That value is substituted into `fastcgi_param PHP_VALUE "{{php_settings}}";`, inside double quotes. Rewriting `"` to `'` closes the only escape from that context, and the surface being configured is the PHP ini, not nginx directives, so a newline there cannot start an nginx block. It is the same class of construction as `{{root}}`, defended, and `rootDirectory` passes through none of that defense. We deliberately do not report `additionalConfiguration` as an injection point; its value to this analysis is as a contrast case showing what the vendor does when it thinks about the problem.

### Source Identification — validation that is absent

For `rootDirectory` on the web channel, the complete list of validation is one constraint: `Assert\NotNull`.

There is no validator class for it. A search of the product-wide corpus for a root-directory constraint class returns nothing, from two independent decoding channels, so this is not an artifact of one failed deobfuscation. The entity setter at `src/Entity/Site.php:404-406` performs no sanitization. `src/Site/Updater.php` at flattened label `f807c` prepends a path prefix and does not re-validate afterwards. And the composer line in `RootDirectory.php` that would have been the last chance is dead code, as established in section 2.

The absence was not merely read statically, it was measured. In one round the stored column length was 314 characters after submission, with the value persisted verbatim including its newlines and its directive text. In the authoritative round the column length went from 16 to 229 after the first injection. In neither case was anything rejected, altered or truncated.

There is one measurement in this area that we publish as uninformative rather than as support, because the honesty matters more than the extra data point. In the authoritative round, both injections used payloads of the same length, so the stored length went 16 then 229 then 229, and the rendered file size was 1198 bytes both times. That measurement therefore has no discriminating power between the two rounds and cannot serve as pairing evidence. Where the two rounds did use differently sized payloads - which happened in a first stage of the same testbed - the same measurements were informative: the file went 985 then 1332 then 1273 bytes and the stored column went 16 then 363 then 304, with the rendered file's digest read back from inside the executing payload agreeing with an independent host-side digest of the same file, closing the pairing at the point of execution. The two sets of numbers are never mixed.

### Source Identification — the value's journey, end to end

The complete path from HTTP body to nginx directive, as a single chain of named artifacts:

```
POST /site/{domainName}/settings
  field  site_domain_settings[rootDirectory]        constraint: Assert\NotNull only
  form   src/Form/SiteDomainSettingsType.php        TextType, label "Root Directory"
  entity src/Entity/Site.php:404-406                setter, no sanitization
  store  SQLite column root_directory               measured verbatim, length 314 in one round
  render src/Site/Updater.php label f807c           prefixes, does not re-validate
  sink   RootDirectory.php labels Aca8b, b9892, e35ff
         rtrim(sprintf("root /home/%s/htdocs/%s;", $siteUser, $rootDirectory), "/")
         substituted for {{root}} at server context, twice, ahead of every location block
  write  src/System/Command/Vhost/WriteFileCommand.php label Dc4ef
         echo %s | /usr/bin/sudo /usr/bin/tee %s     both %s escapeshellarg'd
  target /etc/nginx/sites-enabled/<domain>.conf      root-owned, 0644
  reload src/Site/Updater.php  reloadService("nginx")
         src/System/Command/ServiceReloadCommand.php  sudo /bin/systemctl reload nginx &
                                                      isSuccessful() returns true always
  load   /lib/systemd/system/nginx.service:22        ExecStart has no -c
         /etc/nginx/nginx.conf:1                     user root;
         /etc/nginx/nginx.conf:119                   include /etc/nginx/sites-enabled/*.conf;
```

## 7. Data Flow

### Data Flow — end-to-end chain

Ten hops, with the actor for each one named. The distinction between product action and attacker action is the part that makes this a product vulnerability rather than a misconfiguration discovered in a laboratory.

| Hop | Actor | Action | Observed |
|---|---|---|---|
| 1 | Administrator, via product forms | Creates a site. `POST /site/new/static` with `site_new_static[domainName]`, `[siteUser]`, `[siteUserPassword]` and `[_token]` | `302` to `/`; product writes the virtual host at 985 bytes with digest `c4834dde2f92b3e79949f883ead3e9b8`; product creates the system account, observed as a passwd line with uid 1003 and gid 1004 and a home under `/home/`; product issues a reload of its own at the same moment |
| 2 | Administrator, via product form | Creates a `ROLE_USER` and assigns it the site. `POST /admin/user/new` | `302` to the user list |
| 3 | Attacker | Authenticates as that `ROLE_USER` | `POST /login` returns `302` with `location: /`; session cookies `cloudpanel` and `locale` issued |
| 4 | Attacker | Opens the settings page to obtain the form and its CSRF token | `GET /site/victim.example.com/settings` returns `200` with 21777 bytes; the named form `site_domain_settings` is scraped from the HTML |
| 5 | Attacker | Submits the payload as the `rootDirectory` value, real newlines inside a single form field | `302` redirecting back to the same settings path; no error text, no rejection. This is the only attacker input in the chain |
| 6 | Product | Writes the rendered virtual host | File grows 985 to 1198 bytes; digest changes to `d6230283fa6189fa76cf995673bc3116`; `grep -n` shows the two injected blocks at lines 14 and 15 and the comment at line 16 |
| 7 | Product | Reloads nginx on its own initiative | Reload entry recorded with `ARGV=reload nginx`, `SUDO_USER=clp`, `SUDO_UID=1000`, and the unit's `ExecReload` string read back at that moment |
| 8 | Product's nginx | Parses the poisoned configuration and rotates its workers | Worker pids move through three successive sets; the round's nonce hit count in `nginx -T` goes from 0 to 1; the previous round's nonce goes back to 0; `nginx: configuration file /etc/nginx/nginx.conf test is successful` |
| 9 | Attacker, anonymous | Uploads the marker script through the injected WebDAV block | `PUT` returns `201`; the file lands as `-rw------- 1 root root` with its full size, in a directory the product's nginx created on the attacker's behalf |
| 10 | Attacker, anonymous | Requests the marker through the injected FastCGI block | `GET` returns `200` with the marker body; identity reads `uid=0(root)` |

### Data Flow — why the injected configuration is actually loaded

This is the hop that a reviewer should attack hardest, because it is the one where a laboratory could accidentally supply what a real host would not. It rests on four positive statements, each quoted from an artifact rather than inferred:

```
1  src/Site/Creator.php                NGINX_VHOST_DIRECTORY = "/etc/nginx/sites-enabled/"
                                       (the same literal appears 3 times in the decoded corpus)
2  src/Site/Updater.php                reloadService("nginx") and setServiceName("nginx")
                                       (the literal "nginx" appears 4 times)
3  /lib/systemd/system/nginx.service:21 ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
   /lib/systemd/system/nginx.service:22 ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
                                       no -c anywhere, so the compiled-in default path is read
4  /etc/nginx/nginx.conf:119           include /etc/nginx/sites-enabled/*.conf;
```

Four statements, no assumption in between. The directory the product writes to is exactly the directory line 119 includes; the service the product reloads is exactly the unit whose `ExecStart` reads that configuration file without an override; and that configuration file is exactly the vendor one whose first line is `user root;`.

It is also worth recording what the fourth statement is not. `include` consumes `*.conf` only, so a file in that directory without the extension is inert, and the loaded set enumerated by `nginx -T` was checked against that expectation.

### Data Flow — properties of the chain worth naming

The write and the execution are decoupled, and the decoupling is asymmetric. The injected `location` that accepts `PUT` and the injected `location` that runs PHP are two separate blocks; the first writes with `dav_methods PUT` and `create_full_put_path on`, and the second dispatches. That means an attacker can write files whose names they choose, into a directory of their choosing, with permissions determined by the worker identity, and independently arrange for one of those files to be executed by a pool they do not otherwise control.

The writer identity and the executor identity can differ, and in one round they were directly observed to. When the site-facing nginx runs workers as `clp` rather than root, the uploaded file lands as `-rw------- 1 clp clp` while the executed PHP still reports `uid=0(root)`, because execution identity comes from the pool file, not from nginx. That is the most direct possible demonstration that the privilege boundary being crossed belongs to the php-fpm pool configuration. In the vendor-native wiring the worker is already root, so the file lands as `root root`, and then the two identities coincide - which is why the finding is argued on both bases rather than one: the write primitive does not depend on worker privilege at all, since `/tmp` is a world-writable sticky directory, while the execution privilege comes from the pool.

The chain survives a reduction of nginx worker privilege. That is an inconvenient fact for a mitigation story and it is stated plainly: even with `user clp;`, the write primitive works, the upload succeeds, and the marker returns `uid=0`. What removing `user root;` buys is the removal of "a compromised configuration can write anywhere root can write", which is worth having but is not the fix.

The product cannot report failure at any point in the chain. The save handler returns a redirect with success semantics whether or not the value was sane, because the value is always sane to the layer that accepts it. The reload command returns success unconditionally. And even the vendor-documented promise that syntax is checked and changes are reverted does not cover this path: the product contains two writers, `updateNginxVhost()` used eleven times and `updateNginxVhostWithRollback()` used four times, and `domainSettings()` calls the bare one. The rollback variant genuinely contains a configuration-test command, a copy command, a `.conf.bak` artifact and an invalid-configuration exception - and it is wired only into the reverse-proxy handler. So the promise is true of another code path and false of this one.

The attacker therefore has no error channel and must probe the observable state. This is a design property of the exploit rather than a guess about the product: after saving, the attacker learns whether the injection worked by attempting the `PUT` and the `GET`. That works, it converges in one additional request, and it is why the attack complexity assessment is Low rather than High - the retry loop is short, deterministic and silent.

## 8. Exploit Construction

### Exploit Construction — step sequence

1. Authenticate over the panel listener on 8443 by scraping the live login page for its field names and its CSRF token, then submitting them. Field names are discovered at runtime rather than hardcoded, because hardcoding a name that was never verified is how an exploit silently breaks across builds. In practice the scrape yields `_csrf_token`, `password` and `userName`.
2. Request `/site/<domain>/settings` with the session cookie, scrape the named form `site_domain_settings`, take its action, its CSRF token and the current value of `rootDirectory`.
3. Build the payload with a fresh random nonce and append it to the current value after stripping any trailing slash.
4. Submit the form. Expect `302` and treat the status as information-free, because the product's reload cannot fail observably.
5. Confirm on accessible evidence where possible: the virtual-host digest changed, the per-nonce hit count in `nginx -T` went from 0 to 1, worker pids rotated.
6. Anonymously, on the site listener at 443 with the site domain as both SNI and `Host`, `PUT` the marker script to `/<put-prefix>/<exec-prefix>/<nonce>.x.php`.
7. Anonymously `GET /<exec-prefix>/<nonce>.x.php` and read the marker body.
8. Judge the four requirements in section 9. Never judge on a status code.

The two anonymous requests target the site listener and carry the site domain in `Host`, matching the injected server block's `server_name`. This is a deliberate choice with a consequence recorded in section 9: it means the experiment never isolated whether a mismatched `Host` also reaches the injected block, and the injected virtual host may well have been the default server on 443.

The injected text, verbatim, four lines including the leading semicolon:

```
;
location ^~ /EXPput/ { alias /tmp/; dav_methods PUT; create_full_put_path on; }
location ^~ /EXPa/ { root /tmp; include /etc/nginx/fastcgi_params; fastcgi_pass unix:/run/clp-fm-php-fpm.sock; }
<comment-char> nonce<24-hex-nonce>
```

The rendered file, as observed with `grep -n` after the product wrote it:

```
14:location ^~ /EXPput/ { alias /tmp/; dav_methods PUT; create_full_put_path on; }
15:location ^~ /EXPa/ { root /tmp; include /etc/nginx/fastcgi_params; fastcgi_pass unix:/run/clp-fm-php-fpm.sock; }
16:<comment-char> nonce<24-hex-nonce>;
```

Note the trailing semicolon on line 16 that is not in the payload. That is the `sprintf` in `b9892` appending its format-string terminator after the attacker's value, and the payload's last line exists precisely to swallow it.

### Exploit Construction — payload engineering constraints

Nine constraints were learned the hard way, and each one is a real constraint rather than a stylistic preference.

1. The payload must be syntactically valid nginx. There is no `nginx -t` and no rollback on this path, so validity is not enforced by the product - it is enforced by nginx refusing to reload. Measured with an intentionally illegal payload: the save returned `302` with no rejection and no error message; the file on disk held an unclosed `location` at line 10 and a `root` directive missing its semicolon at line 9; an independent `nginx -t` produced `[emerg] directive "root" is not terminated by ";"` at that line plus `configuration file ... test is failed`; no `.bak` file existed anywhere in the directory; and the worker pid set was unchanged before and after, proving the reload was refused and the previous configuration stayed live. The injection persisted and had no effect, and the next nginx restart would fail. That is the persistent denial-of-service condition, reported separately.

2. The trailing semicolon that `sprintf` appends must be neutralised. The first payload line must be a bare `;` to terminate the poisoned `root` directive, and the last line must begin with a comment character so the appended `;` lands inside a comment. Getting the position of that comment wrong produces `directive "root" is not terminated by ";"` and costs a full replay cycle. It cost one during this work.

3. The payload must give php-fpm an attacker-controlled `SCRIPT_FILENAME`, in practice by including `/etc/nginx/fastcgi_params`. This was measured as an A/B on the same container. With the include, the marker `GET` returned `200` with 1167 bytes and the identity line showed `uid=0`. Without it, the marker `GET` returned `200` with an empty body, no marker text, and - the part that is strange - zero entries in the site error log, not even an upstream error. The product's own `fastcgi_params` line 6 reads `fastcgi_param SCRIPT_FILENAME $request_filename;`. The mechanism producing the silent zero-byte response was investigated and two candidate explanations were constructed, and both contradicted the logs. We publish the phenomenon and the requirement, and we do not publish a mechanism. The usable phrasing is: the payload must include the product's `fastcgi_params` file, or otherwise arrange for php-fpm to receive an attacker-controlled `SCRIPT_FILENAME`.

4. Both arrangements of `SCRIPT_FILENAME` satisfy the requirement. One is `root /tmp;` together with the include, which relies on `$request_filename` and `$document_root`. The other is an explicit absolute path, `fastcgi_param SCRIPT_FILENAME /some/absolute/path.php;`, which is strictly stronger because it does not depend on the document root and therefore does not depend on a writable one. The reference implementation uses the first form because it is what round-trips with the `alias` write block; the second is the shape to reach for if the write target must move.

5. The write target must be a directory the worker can create in. `/tmp` is `drwxrwxrwt`, and `df -T /tmp` reported an overlay filesystem rather than tmpfs, which matters because a tmpfs would be cleared on restart and because overlay confirms the write is durable on the container's disk. `create_full_put_path on;` makes nginx create intermediate directories itself; the resulting directory was `drwx------ 2 root root 4096`, mode 0700 and root-owned, i.e. created by the worker.

6. The upload body must actually reach the target. One round produced `PUT` status `201` with an uploaded size of 0 bytes and a marker `GET` of `200` with an empty body, because the file being uploaded was referenced by a host path that did not exist inside the container. Status `201` with a zero-length body is a success code for a failed exploit.

7. `/home/<sshuser>` must exist before a `PUT` into that home tree, otherwise the DAV layer returns `409`. Payloads writing under `/tmp` sidestep this entirely.

8. The site-facing nginx must be the vendor's build with its modules and support files present. Without `/etc/nginx/global_settings`, the module symlinks and the configuration fragments the vendor package provides, `nginx -t` fails immediately. Four separate failures of this kind were observed when a distribution nginx was present instead of the vendor one: an unsupported `quic` parameter, `unknown directive "http2"`, an `http3` directive, and `unknown log format "main"`. Adding the vendor build, whose `nginx -v` reports `nginx/1.30.4` and whose configure arguments include `--with-http_dav_module` and `--with-http_v3_module`, made all four disappear. Note the specific fact that makes the write primitive available at all: DAV is compiled in as a static module, so `dav_methods` works with no `load_module` needed. The optional-module list is present in the vendor tree but that configuration file references only two includes and no `load_module` lines, and the extended DAV module is not loaded, so WebDAV locking and property methods are unavailable - which does not affect `PUT`.

    There is no Lua, no embedded Perl loaded, and no njs in this build, so payload design cannot rely on a scripting module. Perl is built as a dynamic module and is never loaded. Everything below is constructed from core directives.

9. Injection is independent of site type. An earlier reading held that only static sites were injectable, and it is wrong. The `{{root}}` substitution sits on the common path in `Template::init()`; `StaticTemplate.php` is literally `class StaticTemplate extends Template { }`, an empty subclass, and the first statement of `PhpTemplate::init()` at label `E6da0` is `parent::init();`. The same processors, including `RootDirectory`, run for PHP sites. The reference exploit uses a static site because that is the minimal injectable template choice, and because PHP site creation failed in our harness with `Call to a member function getPort() on null`, which is a missing-fixture problem in the laboratory rather than product immunity. Where the injected text lands in the PHP template was not established, since the PHP template body is not in the package at all - it lives only in the upstream template repository. We also do not publish a count of templates, because the total was never independently verified.

### Exploit Construction — what the exploit deliberately does not do

The marker script is a forensic read-only probe. Its default command is `id`. It contains no hardcoded uid, no expected value to echo, and no assertion that could pass by accident: every privileged fact it reports is fetched at execution time with `shell_exec()`, `posix_getuid()` and `posix_geteuid()`, and several values are read back out of product files at run time. It writes one file under `/tmp` and reads a set of files. It does not modify the system, does not add users, does not change the sudoers drop-in, does not install persistence and does not touch other tenants' directories.

The nonce is generated per round from the operating system's random source and is never reused. It appears in three places at once - the uploaded filename, the comment line inside the rendered configuration and the `file_nonce=` field in the response body - so that a body from an earlier round cannot be mistaken for the current one.

The exploit does not use the site-facing listener for anything authenticated, and does not use the panel listener for anything anonymous. The two listeners stay in their lanes, which is also how a defender should read the traffic.

The exploit does not rely on the panel returning an error, a status code or a log line to decide whether it worked, because the product's reload cannot fail observably. It decides from the response body and from on-target state.

Cleanup is described rather than automated, because automation would need a second write to the same field and would risk leaving a second poisoned configuration behind. The instruction is: restore `rootDirectory` to a plain directory name through the same form so the product rewrites the file, let the product issue the reload, and delete the directory the WebDAV block created.

The reference implementation exposes every environment-specific value as a command-line argument - scheme, panel host, panel port, login path, credentials, site domain, site address, site port, command, both location prefixes, pool socket path, fastcgi parameter file, rounds and timeout - and defaults the panel host to loopback. Credentials, the site domain and the panel host must be supplied; the tool refuses to run without them, so it cannot fire at anything by accident. A `--control` mode runs the identical authenticated flow and submits the existing directory name verbatim, with no newlines and no directives, then performs the same two anonymous requests and expects nginx's ordinary `404` and no marker text.

## 9. Dynamic Verification

### Dynamic Verification — environment

Two reproduction sets are published, and their numbers are never mixed. Set A is the chain-authoritative one, because it is the only set in which the product's own reload, the vendor wiring, the anonymous write and the anonymous execution all happened inside a single container in a single continuous run. Set B is the one in which the delivered reference script was actually executed, three separate end-to-end rounds.

Set A. One container, vendor-native wiring, zero symlinks. Inside it: MariaDB, then the panel's `php-fpm8.1 -R -F` with the panel's own `php-fpm.conf` and `php.ini`, then the panel nginx started as `-c /home/clp/services/nginx/nginx.conf` serving 8443, then the site-facing nginx started as `-c /etc/nginx/nginx.conf` serving 443 - which is exactly what the vendor unit does, because its `ExecStart` has no `-c`. Host-side ports were published on loopback only. The vendor build reported `nginx/1.30.4`; the site configuration had digest `6727bffeb96cb3e03b85d00eac39c47c` at 3,077 bytes with `head -1` reading `user root;` and line 119 holding the include; the panel configuration had digest `1feb5d8bda1f1b2e6f3a8b0a1264d1dc` with `head -1` reading `user clp;`. Baseline before anything was sent: the round's tag had zero hits in `nginx -T`, the shim log had zero entries, the panel login page returned `200` with 4403 bytes, and `df -T /tmp | tail -1` reported `overlay overlay 2113445792 289151364 1738184524 15% /`.

Set B. One container, vendor-native wiring, three rounds each against a brand-new site, a brand-new virtual host and a brand-new `ROLE_USER`, deliberately so that no round could contaminate another. Same digests for both configuration files at open and at close, independently re-measured. `nginx version: nginx/1.30.4`. Integrity at close: `dpkg -V cloudpanel` differing only on a runtime log, `dpkg -V nginx-common` empty, `dpkg -V systemd` differing only on our shim. Package anchor unchanged at open and close, 69,183,476 bytes with digest `24c36a4739ce065c5c188c89def06f29`.

A third complementary round exists in this work, wired by a harness symlink and with the reload performed by sending a signal to the master process, and it is the round that produced the clearest writer-versus-executor asymmetry (`-rw------- 1 clp clp` on disk with `uid=0` in execution). Its numbers are quoted above only for that specific structural point and are excluded from every set-A and set-B figure, because its wiring was ours rather than the vendor's and one of its host-side disproof searches looked in the wrong directory.

Container memory sizing is explicitly not established. One round recorded an out-of-memory exit under a 2 GB cap and so the next used 6 GB; a later round ran entirely under a 2 GB cap with peak usage of 233.1 MiB and the killed-by-OOM flag false the whole time. Neither observation is published as a general fact, and any sizing advice is engineering preference rather than a product or environment property.

### Dynamic Verification — the triggering request

Set A, round 1. The identity ladder is provisioned first with the product's own forms: an administrator session creates a static site via `POST /site/new/static`, then creates the low-privilege account via `POST /admin/user/new` with `admin_user[userName]`, `admin_user[plainPassword]`, `admin_user[role]=ROLE_USER`, `admin_user[status]=1`, `admin_user[timezone]=317`, `admin_user[sites]=victim.example.com` and a CSRF token. Then the attack proper:

```
POST /login                                     as <low-user>              => 302 location=/
GET  /site/victim.example.com/settings          as <low-user>              => 200 size=21777
POST /site/victim.example.com/settings          as <low-user>              => 302, back to settings
```

The submitted field, verbatim shape, with a 230-character payload containing real newlines. The value that went into the body was:

```
site_domain_settings[rootDirectory]=<current-value>;<newline>location ^~ /EXPput/ { alias /tmp/; dav_methods PUT; create_full_put_path on; }<newline>location ^~ /EXPa/ { root /tmp; include /etc/nginx/fastcgi_params; fastcgi_pass unix:/run/clp-fm-php-fpm.sock; }<newline><comment-char> nonce<24-hex>&site_domain_settings[_token]=<token>
```

The response was `302` redirecting back to the same settings path, with no error text of any kind. On disk the file grew from 985 bytes to 1198 bytes and its digest moved from `c4834dde2f92b3e79949f883ead3e9b8` to `d6230283fa6189fa76cf995673bc3116`.

Round 2 in the same container, same session, fresh nonce and fresh CSRF token, produced a file of the same size, 1198 bytes, with digest `86cee979f27ccb32a346a1f7f50cd142`.

Set B's three rounds produced identical structure with different sizes: the virtual host went from 985 bytes to 1211 bytes in each round, with digests `b8de3553373232cea020de23b19bdcbd`, `04eba5784b37b1040b8f4d431c31ef9f` and `90df9b8181851dbc1c251ec327817da4` respectively, from pre-injection digests `05390cb88e4fd0d9059660015dbfe2f5`, `639df6958ea5f04ce6b572b30d00f343` and `076218b9f9aae0100d990e657906d4e0`, and uploaded marker sizes of 1824, 1860 and 1814 bytes. The login scrape worked on the live page in all three, emitting `POST /login fields=['_csrf_token', 'password', 'userName']`, `login => http 302 size=261 location=/`, cookies `['cloudpanel', 'locale']`, settings page sizes of 21831 and 21843 bytes and save responses of `302` with 382 bytes.

### Dynamic Verification — observed output

The marker body returned by the anonymous `GET` in set A round 1, at HTTP `200` with 1087 bytes. Four categories of value are elided below and the elision is stated rather than hidden: the literal marker tag string, the container hostname value, the file timestamps, and the boot identifier and application-secret values. Every other token is verbatim.

```
MARKER file_nonce=a77cc4feecb1e7e45d4bba11.x.php
shell_id=[uid=0(root) gid=1000(clp) groups=1000(clp),0(root)]
posix_uid=0 euid=0
whoami=root
hostname=<container-id, elided>
boot_id=<elided>
app_secret_from_product_file=<factory constant read from /home/clp/htdocs/app/files/.env, elided>
fm_pool_user_line=3:user = root
SELF_LS=-rw------- 1 root root 1739 <timestamp elided> /tmp/EXPa/a77cc4feecb1e7e45d4bba11.x.php
PARENT_LS=drwx------ 2 root root 4096 <timestamp elided> /tmp/EXPa
SCRIPT_FILENAME=/tmp/EXPa/a77cc4feecb1e7e45d4bba11.x.php realpath=/tmp/EXPa/a77cc4feecb1e7e45d4bba11.x.php
etc_nginx_conf_head1=user root;
clp_nginx_conf_head1=user clp;
vhost_md5=
df_tmp=overlay        overlay 2113445792 289152432 1738183456  15% /
sudoers_clp=Defaults !mail_badpass
clp ALL=(ALL) NOPASSWD: ALL
ALL ALL=(ALL) NOPASSWD: /usr/bin/clpctlWrapper
uname=Linux <container-id, elided> 6.6.102-7.alnx4.x86_64 (kernel build stamp elided) x86_64 GNU/Linux
```

Two lines in that body need explanation, because both look like failures and neither is. The `vhost_md5=` line is empty because that field was read from a file whose path had been baked from an earlier round's domain name, so the read found nothing; the digest evidence is carried instead by the value captured at reload time, described next, which is strictly stronger because it is contemporaneous with the reload. And the round-2 body was identical in every field except the nonce, the file paths and the parent-directory timestamps, at the same 1087 bytes.

Set B's bodies are the same shape at different sizes - the marker `GET` returned `200` with 1632, 1184 and 1068 bytes in its three rounds - plus one honest cosmetic defect in the delivered reader: it does not de-frame `Transfer-Encoding: chunked` responses, so the printed body carries a leading hexadecimal chunk length and a trailing `0`, and the reported sizes include framing overhead. The four requirements are all textual greps, so the framing does not affect any judgement, and the sizes printed there are not comparable with the 1824, 1860 and 1814 byte upload figures, which are upstream body lengths.

Set B also contains an unplanned and unusually instructive round. Before a syntax error in the generated marker script was fixed, one round completed the injection side in full - the product wrote the virtual host and reloaded it, the anonymous `PUT` landed and the file was root-owned on disk - while the execution side returned `http 500` with a body of five bytes containing the single character `0`. The explanation is fully established: the response was chunked, the PHP parse error meant zero bytes were emitted, so the body was the terminating chunk frame `0` followed by CRLF CRLF, five bytes in total, and the reader printed those five bytes as if they were content. The lint evidence is verbatim: for the unfixed variant, `PHP Parse error:  syntax error, unexpected token ";"` at line 22 of the generated file with a lint return code of 255; for the fixed variant, `No syntax errors detected` with a lint return code of 0; and the two generated bodies differed by exactly one byte, 1824 versus 1823.

### Dynamic Verification — proof that the reload came from the product

The reload is the one hop where a laboratory could substitute for the product, so it is instrumented rather than assumed. The shim replaced `/bin/systemctl` on the container and logged every invocation, capturing the argument vector, the effective identity, the parent pid, sudo environment variables, two levels of ancestor process, the unit file path, the unit's `ExecReload` line read at that moment, the reload return code, the post-reload worker set, the post-reload nonce presence in `nginx -T`, and the post-reload digest of every virtual-host file. One entry verbatim:

```
ARGV=reload nginx  ARGV0=/bin/systemctl
uid=0(root) gid=0(root) groups=0(root)
PPID=1554 SUDO_USER=clp SUDO_UID=1000
ANC1=   1554       1     0 root     /usr/bin/sudo /bin/systemctl reload nginx
ANC2=      1       0     0 root     sleep infinity
UNIT_FILE=/lib/systemd/system/nginx.service
UNIT_EXECRELOAD_VERBATIM=ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
RUNNING_CMD_FROM_UNIT=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
RELOAD_RC=0
POST_workers_uid0=1584,1585,1587,...,1645,
POST_T_nonce_present=<four nonces, one per round>
POST_vhost_md5=... 90df9b8181851dbc1c251ec327817da4  /etc/nginx/sites-enabled/<site-domain>.conf
```

Aggregate counts in set B, from the 17,262-byte log with digest `2a06e517db0697e0b71c564102b50b7e`: 8 total entries, 8 entries with `SUDO_USER=clp`, 0 entries with an empty `SUDO_USER` - which is the count that would be non-zero for a harness-issued reload - and 8 argument-vector lines all reading `ARGV=reload nginx`. In set A the corresponding counts were 3 total and 3 with `SUDO_USER=clp`. Both are one hundred percent product-originated.

The reload's effect is proven on observable state and never on a return code, because `ServiceReloadCommand::isSuccessful()` returns `true` unconditionally and the `RELOAD_RC` in the log is the shim's own exit code for the line it ran, not the product's opinion. Set A: worker pids moved from 405, 406, 408 through 466, to 605, 606, 608 through 666 after round 1, then to 821, 822, 824 through 879 after round 2; the current round's nonce went from 0 to 1 hits in `nginx -T` while the previous round's nonce went from 1 back to 0; and `nginx: configuration file /etc/nginx/nginx.conf test is successful`, with `ls: cannot access '/etc/nginx/sites-enabled/*.bak': No such file or directory`. An independent third-party corroboration exists for set A's worker rotation: the site's own error log attributed round 1's request to worker `605#605` and round 2's to `821#821`, which nginx wrote, not us. Set B: worker sets rotated 858 through 919, then 1029 through 1090, then 1218 through 1279, then 1419 through 1480, then 1584 through 1645, each measured both by the shim at reload time and re-measured from the host afterwards with identical values. Set B could not obtain the corresponding error-log worker numbers - the file was empty in both relevant site directories because every request in those rounds succeeded - so that corroboration is present for set A and absent for set B, which is recorded rather than papered over.

Two honest limits on this instrumentation. The ancestor chain terminates at the `sudo` process: the product's own wrapping command is `su -s /bin/bash -c "/usr/bin/sudo /bin/systemctl reload nginx" clp`, the intermediate shell exits first, and `sudo` is reparented to PID 1, so the log's second ancestor line reads the container's keep-alive process. The `php-fpm: pool www-portal` link was never captured directly. Attribution of the reload to the panel pool therefore rests on three things composed together: `SUDO_USER=clp` and `SUDO_UID=1000` being exactly the panel pool's identity, the reload timestamp matching the save request's timestamp to the second in round 2, and the archived product source line for `ServiceReloadCommand`. That is a strong composite and it is not a single measurement. Second, the shim covers a file belonging to the `systemd` package, not a CloudPanel file, so it is a harness artifact and is disclosed as such with its original digest and size.

### Dynamic Verification — the four marker requirements

Judging on a status code is what produces false positives in this kind of work, so four requirements were defined in advance and all four were checked every round, in both sets, with every round passing all four.

Requirement one: the live `id` output in the response body contains `uid=0(root)`. Corroborated in the same body by `posix_uid=0 euid=0` from `posix_getuid()` and `posix_geteuid()`, by `whoami=root`, and by the requested command's own output line which reads the same identity back. No uid is hardcoded anywhere in the uploaded script, so this cannot pass by echoing.

Requirement two: device self-attestation values appearing in the body are absent from our own payload and our own script. The witness values in the body are the container hostname, the boot identifier, the application secret read at runtime out of the product's `.env`, the File Manager pool's `user` line read at runtime out of the pool file, and the three sudoers lines read at runtime out of `/etc/sudoers.d/cloudpanel`. Host-side greps over the payload files and the exploit script returned zero hits for every witness value and for every nonce, and the zero is not an empty-bucket artifact: the same grep pattern run over the directory holding the captured evidence files did hit, which is the positive control proving the search works.

One witness must be downgraded honestly. The boot identifier is identical across containers sharing a host kernel and the application secret is a factory constant baked into the image, so neither is device-unique and each serves only as weak disproof that it appears in the payload. The genuinely device-unique witness is the container hostname value, which differed between set A and set B and did not appear in any payload or script; the `uname` line independently embeds the same value, cross-confirming it.

Requirement three: a fresh nonce per round, and a pairing between that nonce and the rendered configuration. The nonce appears simultaneously in the uploaded filename, in the comment line inside the written virtual host, and in the `file_nonce=` field of the response body. The pairing value is written by the shim at reload time - the post-reload digest of that specific virtual-host file - together with a per-nonce hit count in `nginx -T` that goes from 0 to 1 for the current round and back from 1 to 0 for the previous one. Set A pairs `a77cc4feecb1e7e45d4bba11` with `d6230283fa6189fa76cf995673bc3116` and `4baa4866cfaa7d988577b149` with `86cee979f27ccb32a346a1f7f50cd142`. Set B pairs `77b3819f6334c483ce2e4743` with `b8de3553373232cea020de23b19bdcbd`, `d808928abf540c7213b4fb11` with `04eba5784b37b1040b8f4d431c31ef9f`, and `fe831138c444bc3dc610cc5f` with `90df9b8181851dbc1c251ec327817da4`. The earlier first-stage pairs, where payload lengths differed and so did the sizes, are `b9c490a492edf16c3b9b2461` with `5a5c93b9392bd63f77494b5da0d8e20d` and `b22b59c6b67b099982f9e842` with `240ac50756ae31862ff6c750b22b7c2c`, and for those the digest was additionally read back from inside the executing payload and matched a host-side digest of the same file, closing the pairing at the point of execution. One anti-pairing note: the set-B round that preceded the syntax fix carried nonce `9fc6c2c5a4f968c438a2bbd6`, its own file at 1823 bytes, and no marker.

Requirement four: the evidence is response-body content and size, never the status code. Every successful round produced HTTP `302` for the save, `201` for the `PUT` and `200` for the `GET`, and those codes also occurred in failed rounds. The set-A round with a zero-byte upload returned `201` then `200` with an empty body. The set-B round with the PHP syntax error returned `201` then `500`. The criterion is the presence of the marker tag, the `SELF_LS` ownership line and the identity text.

And one additional check that is not part of the four but was always taken: the filesystem holding the uploaded marker is not tmpfs. `df_tmp=overlay`, read back from inside the executing script, so the write is durable rather than a memory artifact that would vanish.

Finally, both legs of the privilege claim were taken independently. Leg one is the HTTP read-back of `uid=0(root)`. Leg two is the on-disk ownership of the file the product's own nginx wrote on the attacker's behalf, `-rw------- 1 root root` with the full byte count, produced by an `ls -la` executed inside the payload and returned over HTTP.

The reason both legs are needed, and the reason the identity string's exact shape matters, is a shape-asymmetry argument that excludes a container-layer origin. Three measurements were taken side by side inside the same container:

```
docker exec id            ->  uid=0(root) gid=0(root) groups=0(root)
docker exec sudo -n id    ->  uid=0(root) gid=0(root) groups=0(root)
HTTP marker shell_id      ->  uid=0(root) gid=1000(clp) groups=1000(clp),0(root)
```

The container layer cannot print the third shape. `gid=1000(clp) groups=1000(clp),0(root)` is exactly what a process started by a php-fpm pool declaring `user = root` and `group = clp` looks like, and the packaged pool file declares precisely that pair. So the string that came back over HTTP can only have been produced by the product's own execution path, not by anything we ran from outside. Labelled honestly: this is a morphological inference drawn from verbatim strings in two independent rounds plus a packaged pool file whose bytes are on record, and the reviewing pass did not itself start a File Manager pool to observe the shape directly.

### Dynamic Verification — the negative control and why it matters

Seven controls were run, across both sets. Six did what a control should. One is invalid and is reported as invalid.

The control that matters most is the delivered script's `--control` mode, which repeats the entire authenticated flow - login, settings fetch, form submission - with the `rootDirectory` value submitted exactly as it was read, carrying no newlines and no directives, and then performs the same two anonymous requests against the same URL prefixes. Expected result: the save succeeds and changes nothing, the `PUT` returns nginx's ordinary `404`, and no marker text exists. This isolates the injected newlines as the sole cause of the write primitive, which is the whole causal claim.

The remaining controls, all of which produced no marker and no identity string, with `uid=0 hits: 0` and `marker tag hits: 0` in each:

- No injection at all, against a site the product had already created, hitting the execution path. Pre-measured state: zero nonce hits in `nginx -T`, virtual host at 985 bytes. Result: `404` with 146 bytes and nginx's standard `404 Not Found` page. This proves the execution path exists only because of the injection.
- Wrong path against an injected site, with a real nonce from a previous successful round but the execution prefix altered. Result: `404` with 146 bytes.
- Correct path, no upload, against an injected site with a fresh never-uploaded nonce. Result: `404` with 16 bytes and a body reading exactly `File not found.`, with the site error log carrying `FastCGI sent in stderr: "Primary script unknown"` against the request line and server name, attributed to workers `605#605` and `821#821` in the two rounds. This is the control that proves injection-on-disk is not execution, and that the `PUT` is a necessary hop rather than a convenience.
- The execution path requested against the panel listener on 8443, carrying a real nonce. Result: `404` with 146 bytes, the panel's own 404 page, no marker, no identity string. The panel nginx includes only its own site directory, which holds a single file. This is the empirical form of the structural claim that the injection is inert against the `user clp;` configuration. Its shape differs from what one might expect - not a framework redirect - because the request path ends in `.php` and the panel's FastCGI handling resolves it before Symfony ever sees it; a non-`.php` path on the same listener does produce a `302` to the login page. Direction is the same, shape differs, and the difference is recorded.
- Cross-virtual-host request: another site's domain in the `Host` header asking for our injected path. Result: `404` with 146 bytes. The injected `location` blocks affect only their own server block. This is not a proof that arbitrary hosts are unreachable - see the invalid control below.
- A non-executable extension in the same directory, `/marker.txt`, in the harness-wired round: `403` with 146 bytes, so execution is confined by the location pattern rather than granted to the whole directory. In the same round, an anonymous request to `/dashboard` returned `302` to the login page, so the injection did not contaminate the panel's authenticated surface either.

The invalid control, reported as invalid: a host-substitution variant in the earliest harness-wired round returned `200` with 422 bytes and emitted the marker. In that harness the injected virtual host was the only server block on 443, hence the default server, so any `Host` value reached it. The control could not distinguish "host matching does not matter" from "there was nothing else to serve", and it is void. Combined with the fact that both later sets used a resolver mapping that made `Host` match `server_name`, the only defensible statement is that reachability depends on the `server_name` and default-server configuration, and that reachability by arbitrary `Host` was never proven. The cross-virtual-host control above gives directional support for block-locality but does not isolate the default-server effect.

### Dynamic Verification — boundaries of what was verified

What is proven: a low-privilege remote panel account, using only the product's own forms and the product's own reload, can place attacker-chosen directives into a root-owned nginx configuration that the vendor's nginx then loads, and the resulting anonymous write and execution reach `uid=0` on the host, inside a container built from vendor artifacts with no product file modified.

What is argued rather than measured: the attribution of the reload to the panel pool, which composes sudo environment variables, a same-second timestamp and an archived source line, but never captured the pool process in the ancestor chain. The exclusion of a container-layer origin for the identity string, which is a shape argument from two verbatim strings plus a packaged pool file. And the claim that a second tenant on the same host would be affected, which is a capability inference from what root can do rather than a measurement.

What is not established, and is not papered over:

- Whether the injection is reachable by an arbitrary `Host` value, or only where the request matches the injected block's `server_name`. All three attempts to isolate this failed, for different reasons each, one of which is the invalid control above.
- Whether an illegal payload is rolled back under vendor-native wiring. It was measured not to be rolled back under harness wiring, and both native-wiring sets used only legal payloads. Indirect evidence points the same way - no `.bak` file existed in either set, the bare writer is what `domainSettings()` calls, and the rollback writer exists four times for a different handler - but the direct test was never run natively.
- Where injected text lands in the PHP-site template, since the PHP template body is not present in the package and lives only in the upstream template repository. Injection independence from site type is established statically through the empty subclass and the `parent::init()` first statement; the rendering target for PHP sites is not.
- Whether the second injection sink, `addPageSpeed()` feeding `{{settings}}`, is exploitable. Static analysis says it has the same shape and the same authorisation exposure; no dynamic round was run and no control was constructed.
- Whether a local `clpctl site:add` invocation, which the sudoers drop-in grants to any local user, can inject the same sink. If it can, the web form is one path among several; if it cannot, the web form is the remote path. Neither was tested.
- The mechanism behind the silent zero-byte response when `fastcgi_params` is not included. The phenomenon is measured twice; two proposed mechanisms were both contradicted by the logs.
- Whether repeated injection against the same site is workable. Set A ran two rounds against one site, so it is answered yes for that shape; set B ran three rounds against three different sites by design, and its author did not test appending to an already-poisoned value. The reference implementation appends to the existing value, so a second injection against the same site produces duplicate `location` blocks; that was not measured and is not claimed in either direction.
- The exit code of one set-B round was not captured, because that invocation's output was truncated. The other two were measured as zero. Given the implementation's return statement, zero is derivable for the third, but derived is not measured and it is labelled as such.

## 10. Reachability and Security Impact

### Reachability and impact — network position

Fully remote. Two listeners are involved and both are network-facing in a normal deployment: the panel on 8443 and hosted sites on 443. The attacker needs credentials for one panel account of the lowest role and ownership of one site, and then needs no further authentication for anything. Steps after the save are anonymous, so credential rotation or session revocation mid-attack does not stop the second half once the first half has landed - the injected directives are on disk and loaded.

Network position affects nothing about exploitability but affects everything about blast radius, because a hosting panel is by nature the trust anchor for every site on the box. The site-facing listener is the one customers' visitors reach. An attacker who controls that listener's configuration controls what every visitor to that virtual host receives, and - subject to the `server_name` and default-server question above - potentially what visitors to other virtual hosts on the same address receive.

### Reachability and impact — what the achieved identity controls

`uid=0` on the host. Concretely, the observed identity read back these five things and could have read or written anything else:

- The product's application secret, read at runtime out of `/home/clp/htdocs/app/files/.env`, which in this build is a static factory constant identical across installations. Its exploitability was checked in three directions and all three are negative - Symfony's CSRF token is session-stored and not an HMAC of that secret; the product has no remember-me surface at all, established by zero hits in plaintext with a nine-line positive control from the same file; and the auto-login token is filename-addressed with content as credential, not an HMAC - so the secret is a disclosure item and not a key.
- The File Manager pool file, confirming at runtime that line 3 reads `user = root`, which is the amplifier being observed from inside rather than read from a package listing.
- Both nginx configuration files' first lines, confirming at runtime that the site-facing one reads `user root;` and the panel one reads `user clp;`.
- The sudoers drop-in, reading back all three lines including `clp ALL=(ALL) NOPASSWD: ALL`, which means any process that can already run as `clp` can become root locally without a password. Note this is a consequence of the vendor's own configuration, not a second vulnerability, and it also means the achieved root is not the ceiling of what a local `clp` can do - it is the ceiling of what this chain achieves remotely.
- The filesystem type of the write target, confirming the marker landed on durable storage rather than tmpfs.

Beyond what the marker chose to read, host root on a hosting server means: every tenant's document root, every site system account's home directory and SSH keys, the panel's SQLite database holding password hashes and API tokens, session files under `var/sessions/`, TLS private keys under `services/nginx/ssl-certificates/`, MariaDB's data directory, all systemd units, all cron entries under `/etc/cron.d/`, the sudoers tree, and the ability to load a kernel module. It also means the attacker can rewrite any virtual host on the box, which is the practical route to persistent access and to attacking the hosted sites' visitors.

Availability is total, and there is a second, non-execution availability consequence that comes with the injection surface for free: a syntactically invalid `rootDirectory` leaves a broken configuration on disk with no rollback, and the next nginx restart or host reboot then fails to bring up the site listener. Because the product's reload success check is hardcoded, nothing in the panel reports the problem. This is reported as a separate disclosure item and is deliberately not folded into this advisory's score.

### Reachability and impact — the unauthenticated question, answered in full

The most promising anonymous route to this sink was the `X-Forwarded-For` header reaching `App\Security\ApiTokenAuthenticator`, and it deserves a complete answer because it nearly works and then fails for a reason that is easy to state wrongly in either direction.

The authenticator is at `src/Security/ApiTokenAuthenticator.php` and, deobfuscated, contains:

```php
private static array $whitelistedIps = ["172.17.0.1","127.0.0.1"];
b1968: $clientIP = $request->getClientIp();
e01c5: if (true === in_array($clientIP, self::$whitelistedIps))
ac7bb: $passport = new SelfValidatingPassport(new UserBadge("api", ...));
f3aff: return $passport;
```

The `supports()` gate requires an `Authorization` header that exists and begins with `Bearer `, and does not inspect its value. The whitelist comparison happens before any token lookup, so on a match the authenticator issues a self-validating passport for the user identifier `"api"` while never reading the `Authorization` value and never querying the token repository. So this is not a token-forgery problem. It is an IP-trust problem.

And the transport for it is present in the product's own configuration. The panel nginx declares, at `http` context starting line 10 with seven directives at lines 16 through 23:

```
real_ip_recursive on;
set_real_ip_from 127.0.0.1;
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;
set_real_ip_from 0.0.0.0/0;
real_ip_header X-Forwarded-For;
```

The `0.0.0.0/0` entry makes every source trusted, and `real_ip_header X-Forwarded-For;` makes the client-supplied header the address that `$remote_addr` reports. Both fastcgi parameter files then hand it to PHP: `fastcgi.conf:19` and `fastcgi_params:16` each carry `fastcgi_param REMOTE_ADDR $remote_addr;`. Symfony performs no second filtering, because no trusted-proxy configuration exists: a search for `trusted_proxies`, `TRUSTED_PROXIES`, `setTrustedProxies`, `REMOTE_ADDR`, `X_FORWARDED_FOR` and `HTTP_X_FORWARDED` across the 489 `src` files, the whole `config` tree, `public/index.php` and all five files under `bin` returned zero hits, and `config/packages/framework.yaml` contains only a secret referencing the environment variable at line 3, `http_method_override: false` at line 6 and a `php_errors:` block at line 25. So `Request.php:758-766`, which returns the `REMOTE_ADDR` server value when `isFromTrustedProxy()` is false, and `:785-790`, which takes the first element of that array, both fall straight through.

One recursion subtlety: with `real_ip_recursive on` and every candidate falling inside `0.0.0.0/0`, there is no untrusted address at which to stop, so a single-entry header such as `X-Forwarded-For: 127.0.0.1` yields `$remote_addr` equal to that entry regardless of the recursive setting. The payload is unambiguous.

Note also which whitelist entry this matches. It is the second one, `127.0.0.1`, not the Docker bridge gateway `172.17.0.1`. That distinction is what decouples the finding from any container artifact: `127.0.0.1` is a value the vendor wrote into its own source, present identically on bare metal, and reachable by any remote client that can set a header. Both configurations required to make the swap work are installed by the vendor's own package - the nginx configuration carrying `set_real_ip_from 0.0.0.0/0`, and the panel unit carrying `-c` pointing at that configuration, installed by the maintainer script at line 341 - so no researcher-supplied key, environment variable or container network participates. A four-shot control was run against one endpoint: nothing at all, `Authorization: Bearer` alone, `Bearer` plus `X-Forwarded-For: 127.0.0.1`, and `Bearer` plus a non-allowlisted address as the negative leg. All four response bodies were byte-identical, `302` with 270 bytes, and the same was true on `/dashboard`.

That identity swap is real and it does not help. Four independent reasons, each sufficient:

1. The identity is scoped to an empty path space. The `api` firewall's pattern is `^/api`, at `security.yaml` lines 12 to 15, and there are zero routes under `/api`: `config/routes.yaml` lines 5 to 12 are entirely commented out, a search for route attributes and annotations across `src` found zero files, and the product's own router listing shows no path beginning with `/api`, even though `src/Controller/ApiController.php` exists and the firewall is declared. The sink in this advisory is `POST /site/{domainName}/settings`, which is under the `main` firewall, and the `api` identity cannot reach it.
2. The roles granted are `ROLE_USER`. With no `role_hierarchy` in the configuration, that identity inherits nothing and `^/admin` stays closed.
3. The ownership gates stop it even within its own reach. `SitesController::getSite()` returns null for any `{domainName}` an account that owns no sites requests, and `NewSiteController::hasPermissions()` returns false for `ROLE_USER` at all seven site-creation entry points, so this identity can neither target an existing site nor create one. Of the seven functionally reachable routes for a siteless identity - the dashboard, settings, security, enable-MFA, disable-MFA, announcement-read and locale-change paths - the count of execution sinks and root-write sinks is zero. That zero has a positive control: the same detection pattern finds four hits in `DashboardController.php`, all of which are constant argument vectors such as reading memory information through sudo, with the only request-derived input being a time-range value clamped by an `in_array` allowlist, and finds zero hits in `Frontend/UserController.php` at 10,058 characters and in `AppController.php` at 4,934 characters.
4. The dynamic observation genuinely does not decide it, and this is stated as a limitation rather than hidden. A request to `/api/users` returns the same `302` with a 270-byte body as a request to a deliberately nonexistent path, so the response cannot distinguish "identity not granted" from "no route exists at this path". The route-space non-existence is what decides the question, statically and arithmetically, and the dynamic leg is corroborative only.

The correct summary of the anonymous route is therefore: the identity swap succeeds on a default installation and yields an identity with zero additional capability. That is a real weakness - a request header controls an authentication decision - and it is reported as a disclosure item, but it is not an authentication bypass into this sink and it does not raise this advisory's privilege requirement.

### Reachability and impact — deployment shapes that would change the unauthenticated analysis

Stated in both directions, because the argument above depends on the vendor's real-IP configuration and a hardened deployment changes it.

Shapes that remove the transport. If an operator deletes or narrows `set_real_ip_from 0.0.0.0/0;` in `/home/clp/services/nginx/nginx.conf`, or removes `real_ip_header X-Forwarded-For;`, then `$remote_addr` reflects the TCP peer and a remote attacker can no longer present themselves as `127.0.0.1`. Reaching the whitelist then requires an actual on-box loopback position, meaning the bridge gateway case for the first allowlist entry `172.17.0.1` in a containerised deployment, or any local process for `127.0.0.1`.

Shapes that alter the semantics in a way we did not test. If another proxy or load balancer sits in front of the panel and overwrites or appends to `X-Forwarded-For`, the value nginx selects changes; with `real_ip_recursive on` and a mixed trusted-range configuration the selected entry can be an address the outer proxy chose rather than the attacker. In a default installation there is no such layer, since the maintainer script installs the unit directly. We did not test a fronted deployment, so we make no claim about it in either direction. Note that the vendor's changelog for an earlier version mentions fixing server-IP disclosure when a content-delivery network is used, which indicates the real-IP trust model exists deliberately for that scenario and that the vendor has already revisited it.

What does not change. Reasons two and three above - roles are `ROLE_USER`, the `/api` space is empty, and the ownership gates hold - are properties of the application and its routing table, not of the network path. Hardening real-IP handling therefore does not fix a remote code execution issue; it removes an identity-swap primitive that was already capability-free. And nothing about the finding published in this document depends on any of it: the chain starts from a legitimate panel session, never sends `X-Forwarded-For`, and reaches the sink through the `main` firewall.

### Reachability and impact — what is not reachable from this identity

For completeness, and because a reader assessing exposure will ask: from a `ROLE_USER` without a site, essentially nothing. The seven reachable routes contain no execution sink and no root-write sink. `ROLE_USER` cannot self-assign a site, cannot reach `^/admin`, cannot reach the File Manager backend without the `clp-file-manager` session key that only the sites controller writes, and cannot reset any account's credentials because the product has no password-reset surface at all.

Two structural facts about state that close off an otherwise attractive escalation, and both were proven rather than assumed. The panel's own state is not in MariaDB: `.env` reads `DATABASE_URL="sqlite:////home/clp/htdocs/app/data/db.sq3"`, the directory is `drwxrwx--- clp clp` and the file is `-rwxrwx--- clp clp`, while the MariaDB daemon runs as uid 101, gid 103 with only the `mysql` group. So being root inside the database is not being root on the filesystem, and no chain of the form "reach the database, edit the users table, become administrator, then use this finding" exists on a default deployment. Equally, that is not a permanent statement: the permissions on the landing directories are a deployment variable, and an operator who makes a site webroot world-writable changes the picture. We tested the default shape and found the barrier; we did not enumerate operator variations.

The File Manager's own fourteen action endpoints stay inside the site home through `checkPath()`, verified exhaustively rather than by sampling, and a site system account could not read the panel's own variable directory, returning permission denied. Those are the constraints that make this injection necessary rather than convenient: the root File Manager socket is referenced by exactly two files in all vendor material - its own pool declaration and the panel virtual-host's `/file-manager/` block - the latter inherits a document root of `/home/clp/htdocs/app/files/public` which is `root:root` mode 0755 and not writable, and it carries `try_files $uri =404;` at line 40. Without injecting configuration, there is no route to root execution through that socket.

A related hypothesis about the local console channel was tested and failed, and the failure is recorded with its own weakness. It was proposed that the `clpctlWrapper` helper's quoting, which uses `printf '%q'` together with an escaping function, could be made to resurrect a semicolon and reach the same sink without injection. The test ran in a fresh container with the product's own files copied in and verified by digest in both directions, and the expected artifacts never appeared, so the hypothesis was abandoned. The honest caveat: all three attempts piped their output through a head filter which was consumed entirely by PHP startup warnings, so not one argument vector from the wrapper was captured, and the experiment carries only effect-level negative evidence. It does not prove that an injection-free local route is impossible.

### Reachability and impact — detection notes

The signals worth alerting on, in rough order of specificity:

- A `root_directory` column value in the panel database containing a newline, a semicolon, or the substrings `location`, `dav_methods`, `fastcgi_pass` or `alias`. This is the earliest and cheapest detector and requires no host access.
- Any growth in the size of `/etc/nginx/sites-enabled/*.conf` that is not explained by a legitimate configuration change, and any occurrence of `dav_methods` at any line of any file in that directory - the shipped templates do not emit it.
- `PUT`, `MKCOL` or `PROPFIND` verbs in the site-facing nginx access log for a hosting tenant. Ordinary site traffic does not contain WebDAV verbs.
- New files under `/tmp` with mode `0600`, owner root, and a `.php` extension, in directories of mode `0700` created by nginx via `create_full_put_path`.
- Rotated nginx worker pid sets on the site-facing process without a matching administrative action, and reload invocations of the `nginx` unit with `SUDO_USER=clp` that follow a site-settings save within the same second.
- `directive "root" is not terminated by ";"` or any `[emerg]` at nginx startup, which both indicate a poisoned configuration already on disk and a startup that will fail.

The detection caveats are as important as the signals. The product produces no log line for the injection itself, because the save handler returns a redirect with success semantics and the reload reports success unconditionally. There is no audit trail in the panel UI. And an attacker who uses a marker file rather than a persistent web shell leaves a `0600` root-owned file that ordinary site-level monitoring has no reason to look at.

## 11. Fix Recommendations

### Fix Recommendations — vendor-side, ordered by root cause

1. Add a character-level validator to the `rootDirectory` field, matching what the same form family already does for `$domainName` with `AppAssert\DomainName`. An allowlist of `[A-Za-z0-9._-]` is sufficient for a directory name. At an absolute minimum reject newline, carriage return, brace, semicolon, the comment character, quote characters, whitespace and any leading traversal sequence. Apply it as a constraint on the form field so that it runs before the entity setter, and apply the same constraint to the entity setter so that a value arriving from the console channel is covered too.
2. Reuse the clamping the console channel already performs. `ltrim(rtrim($x,"/"),"/")` exists on that path and not on the web path; that asymmetry is the double standard at the heart of this finding and closing it is a two-line change.
3. Delete or repair the dead sanitization in the renderer. `rtrim(sprintf("root /home/%s/htdocs/%s;", $siteUser, $rootDirectory), "/")` cannot strip anything, because its argument always ends with a semicolon. Whatever the intent was, it needs to operate on `$rootDirectory` before composition, not on the composed string afterwards.
4. Treat every virtual-host placeholder as a structured-configuration sink and put one shared normalization in front of all processors. `{{root}}`, the `{{settings}}` placeholder written by `addPageSpeed()` which currently applies only `trim`, and `{{php_settings}}` should all pass through the same line-oriented allowlist logic that `additionalConfiguration` already uses - trim per line, drop empties, reject or neutralise directive terminators and block openers, and re-join. The current state is that one free-text field on the page has four normalization steps and the field that reaches an nginx directive context has none.
5. Validate the rendered artifact, not just the template. `validateVhostTemplate()` today checks that `server_name` and `root` placeholders are present, which says nothing about the values substituted into them. Run `nginx -t` against the rendered content in a temporary path and install only on success.
6. Route every write through the rollback writer. The product already contains `updateNginxVhostWithRollback()`, with a configuration-test command, a copy command, a `.conf.bak` artifact and an invalid-configuration exception; it is used four times and serves the reverse-proxy handler. `Updater::domainSettings()` currently calls the bare `updateNginxVhost()`, which is used eleven times and has none of that. The documented behaviour that syntax is checked and changes reverted should be true of this path, because customers reasonably believe it is.
7. Make reload failure observable and non-silent. `ServiceReloadCommand::isSuccessful()` returning `true` unconditionally means the product can never know a reload failed, and backgrounding it with `&` means it cannot find out later either. Report the real result, surface it to the user who performed the save, and log it.
8. Separate privilege in the File Manager pool. Do not run `/home/clp/services/php-fpm/fpm/pool.d/file-manager.conf` with `user = root`; drop it to the panel account or a dedicated unprivileged user. Set `security.limit_extensions` explicitly rather than relying on the php-fpm compiled-in default. Restrict `srw-rw---- root clp /run/clp-fm-php-fpm.sock` so a site-facing worker cannot address it. The vendor has already acknowledged this class of issue in its changelog, which is precisely why the fix belongs here rather than in the next release.
9. Lower the site-facing worker identity. `/etc/nginx/nginx.conf` line 1 reads `user root;` in the vendor's own build. Moving to an unprivileged worker user does not fix the injection - measured, the write primitive and the root execution both still work when workers run as `clp` - but it removes the property that a compromised configuration can write to any path root can write to, which is a distinct and worthwhile reduction.
10. Audit the whole command-builder family for the same category error. Of 49 builders under `src/System/Command/`, 44 use `escapeshellarg`, which is good discipline for command lines and completely irrelevant for configuration text. Every builder whose output is parsed by something other than a shell needs value-level validation instead of argument escaping.
11. Ship the virtual-host templates in the package. `postinst.sh:97` runs an import that performs `git clone` of an external repository and stores the resulting text in a database column that is later interpolated with user data. Bundling the templates removes a supply-chain dependency and an integrity question, independent of this finding.
12. Replace the client-side password generator's randomness source. `public/assets/js/common.js` lines 18 to 29 use `Math.random()`; that file contains two uses of `Math.random` and zero of `crypto.getRandomValues`. It is called from 17 templates covering site users, SSH users, FTP users, database users, panel users and Basic-Auth credentials. Use a cryptographic generator, either `crypto.getRandomValues` in the browser or server-side generation. The corresponding server-side construction `md5(uniqid(rand(), true))` at `public/phpmyadmin/login.php:40` and `:42`, which produces the single-signon token and its HMAC secret, should change for the same reason.
13. Add regression tests: a fixture that saves a `rootDirectory` containing a newline, a semicolon, a brace pair and a comment character and asserts rejection; a test that renders a virtual host from a hostile value and asserts the configuration test fails before installation; a test asserting no packaged pool file declares `user = root`; and a test asserting the `rootDirectory` constraint list is not a bare not-null check.

### Fix Recommendations — operator-side, until a patch exists

1. Treat every panel account that owns a site as holding host root, because that is what this finding proves. Restrict who can hold such an account, apply the same vetting you would apply to shell access on the host, and do not issue site-owning panel accounts to parties you would not trust with the machine.
2. Put the panel listener behind an access control you own - VPN, single sign-on, or a source-address allowlist at the network layer. Port 8443 should not be reachable from untrusted networks.
3. Reconfigure the File Manager pool away from root: edit `/home/clp/services/php-fpm/fpm/pool.d/file-manager.conf` to use a non-root `user`, restart the pool, and verify the File Manager still functions. This removes the escalation from configuration injection to host root. The write primitive remains, so this is mitigation and not a fix.
4. Diff `/etc/nginx/sites-enabled/*.conf` against a known-good baseline after every site-settings save, and alert on any newly appearing `location`, `dav_methods`, `alias`, `root` or `fastcgi_pass` directive.
5. Alert on `PUT`, `MKCOL` and `PROPFIND` verbs in the site-facing access log. A hosting tenant's visitor traffic should never contain them.
6. Alert on `directive "root" is not terminated by ";"` and on `[emerg]` at nginx startup. Either means a broken configuration is on disk and the next restart will fail to bring up hosted sites.
7. Do not trust panel-reported success as evidence that the nginx configuration is valid, because the product's reload success check is hardcoded to true. Validate independently with `nginx -t` as part of any configuration-change procedure.
8. Keep a backup of `/etc/nginx/sites-enabled/`. The product creates no `.bak` on this path, so an operator needs their own copy to recover from a poisoned configuration before a restart.
9. Rotate every credential that was produced by the panel's "Generate Password" button, since those come from `Math.random()`, and generate replacements with a cryptographic source.
10. Consider whether MariaDB needs to listen on every interface. It does in this build, with `@@bind_address` NULL and `@@secure_file_priv` NULL, and although no `root@%` account exists, the exposure is unnecessary on a single-host panel deployment and a firewall rule at the host is cheap.

## 12. CWE and CVSS

### CWE and CVSS — classification

The primary classification is CWE-93, improper neutralization of CRLF sequences - here, control characters injected into a value that is later parsed as nginx directives. The precise shape is a configuration-injection variant: the payload is not interpreted by the parser that received it as data, but by a second parser, the nginx configuration reader, that treats it as syntax.

Contributing classifications, in the order they matter to the outcome:

- CWE-20, improper input validation. The field's declared constraint set is a single not-null check; there is no character, length or path validation on a value destined for a configuration file.
- CWE-74, improper neutralization of special elements in output used by a downstream component, which is the parent family and the accurate description of the layer the vendor missed.
- CWE-269 and CWE-250, improper privilege management and execution with unnecessary privileges. These describe the amplifier rather than the injection: the vendor runs a php-fpm pool as root and its site-facing nginx workers as root. Neither is required for CWE-93 to be a defect, and both are what turn it into host-root execution.
- CWE-338, use of a cryptographically weak pseudorandom number generator. This is a separate finding in the same product, reported in section 11 item 12 and in the summary, and it is not part of this vector.

Two classifications are explicitly rejected:

- Not CWE-78, OS command injection. `WriteFileCommand.php` at label `Dc4ef` is `echo %s | /usr/bin/sudo /usr/bin/tee %s` with both substitutions passed through `escapeshellarg`. No shell metacharacter reaches a command line, and the newline in the value is data as far as the shell is concerned. The defect is entirely in configuration-text composition.
- Not an unauthenticated chain, and not a local privilege-escalation chain in the usual sense. It is a post-authentication configuration injection whose start principal is an application role and whose end principal is an operating-system account obtained through vendor-owned service identities.

### CWE and CVSS — vector derivation

The published vector is:

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

Derived from first principles under the CVSS 3.1 base metric weights.

Impact sub-score. Confidentiality, integrity and availability are all High, so each impact weight is 0.56. ISS is `1 - ((1 - 0.56) * (1 - 0.56) * (1 - 0.56))`, that is `1 - 0.44^3`, that is `1 - 0.085184`, giving 0.914816. With Scope Unchanged the impact term is `6.42 * ISS` = `6.42 * 0.914816` = 5.873119.

Exploitability sub-score. `8.22 * AV * AC * PR * UI`, with Attack Vector Network at 0.85, Attack Complexity Low at 0.77, Privileges Required Low at 0.62 under Scope Unchanged, and User Interaction None at 0.85. That is `8.22 * 0.85 * 0.77 * 0.62 * 0.85` = 2.835255.

Base score. Scope Unchanged, so base is the lesser of impact plus exploitability and ten: `5.873119 + 2.835255` = 8.708374. CVSS rounds up to the nearest tenth, so the published value is 8.8, severity High.

The per-metric justifications:

- **AV:N** - every hop is HTTP over the network: one authenticated form post on the panel listener and two anonymous requests on the site listener. No local access, no adjacent-network position, no physical proximity.
- **AC:L** - no race condition, no memory-corruption reliability question, no heap grooming, no dependency on a non-default setting and no dependency on operator configuration. Five independent rounds across two reproduction sets each produced the marker, and the injection landed on the first submission in every one. The payload has two engineering constraints - syntactic validity and inclusion of the product's fastcgi parameter file - both of which the reference implementation produces deterministically rather than by trial. Because the product cannot report failure, the attacker confirms success by attempting the two anonymous requests, which is a short retry loop rather than a hard attack condition; nothing about it makes success improbable.
- **PR:L** - the least privileged principal proven to reach the sink holds `ROLE_USER`, the lowest panel role, and four such identities performed five injection rounds. This is the metric to argue hardest on both sides, so both directions are given. It is not `PR:N`, because no anonymous path reaches this sink: the catch-all access-control rule requires full authentication, the twelve URI-mismatch variants against a protected route produced zero admissions, the anonymous identity-swap primitive yields an identity with zero additional capability confined to a route space that does not exist, and there is no factory credential to use since the product ships with zero users. It is not `PR:H`, because `ROLE_ADMIN` was never required - the settings page is not under `^/admin`, the handler declares only `ROLE_USER`, and the injection was performed with `ROLE_USER` sessions and observed to take effect. Had only an administrator been demonstrated, the correct metric would be High and the same impact weights would produce 7.2, so getting this metric wrong would move the score by 1.6 points.
- **UI:N** - no step requires another user's action. The site and the account are provisioned by an administrator in the normal course of onboarding a customer, before the attack begins, which is a precondition and not an interaction with the attack.
- **S:U** - see the Scope decision.
- **C:H** - host root reads everything on the machine, including the panel database with password hashes and API tokens, session files, TLS private keys, every tenant's document root, every site account's SSH keys and the application environment file.
- **I:H** - host root writes everything, including systemd units, cron entries under `/etc/cron.d/`, the sudoers tree, any virtual host on the box, and the panel's own code.
- **A:H** - host root can stop any service, unmount or encrypt any filesystem, and the injection surface carries an independent path to persistent unavailability through an invalid configuration that breaks the next nginx restart.

### CWE and CVSS — the Scope decision

The published vector says Unchanged. A Changed reading is genuinely tempting here and it is worth stating the temptation accurately before rejecting it.

The temptation: the vulnerable component is the panel application, whose authorisation boundary is the set of roles in `security.yaml`, and the achieved impact lands on the host operating system and, in a multi-tenant deployment, on every other tenant's site - components that are outside the panel's own authorisation boundary and are impacted in their own right. An action authorised as "a tenant edits a setting on their own site" produces an outcome that no authorisation model in the product anticipates, affecting systems the vulnerable component does not manage. That is the textbook argument for Changed, and it is not a strained one.

Why we publish Unchanged, for three reasons in increasing order of weight:

First, the privilege ceiling is entirely the vendor's own configuration. `user root;` at line 1 of the vendor nginx configuration, `user = root` at line 3 of the vendor File Manager pool file, and `clp ALL=(ALL) NOPASSWD: ALL` in the vendor's sudoers drop-in are all product-shipped decisions. Every step of the escalation is performed by a component the product itself installed, configured and invoked, and the product is the authority at each step. No second product's own exposed interface is being reached through the first product's flaw; what is being reached is the host, through identities the product itself established. Under the Scope metric's own logic, an impact that stays within the authority the vulnerable component's vendor established is Scope Unchanged.

Second, the cross-tenant consequence is a capability inference and not a measurement. We did not run the verification on a host with a second tenant installed, and we did not measure any impact on another tenant's site. Publishing Scope Changed on the strength of an untested cross-tenant claim is precisely the class of overreach that produces public corrections, and the operational benefit of the higher number is nil.

Third, the conservative value already communicates the finding. 8.8 High conveys "remote authenticated host-root code execution" to every triage process that consumes it. Nothing decision-relevant is lost by declining the upgrade.

The Changed-scope form of the same facts, recorded as a rejected reading and carrying no score in this document, is:

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
```

We do not publish it, we do not submit it as the headline, and we do not attach a number to it. If a triage process or an identifier-assigning authority prefers the Changed reading on the grounds that a tenant-scope authorisation boundary is crossed to affect the host and other tenants, the argument above is the complete case for it and the only missing evidence is a two-tenant measurement.

### CWE and CVSS — what is deliberately not published

- No conditional higher score. We found no deployment state that makes this chain unauthenticated, so there is no conditional reading to publish. Publishing a hypothetical `PR:N` score conditioned on an unproven bypass would be inventing severity.
- No score for the persistent denial-of-service condition. An invalid payload leaves a broken configuration on disk with no rollback, so the next nginx restart or host reboot fails to bring up hosted sites, and the product reports success regardless. That is a real and separately reportable availability consequence of the same missing validation, and scoring it into the code-execution vector would be double-counting the same root cause. It is reported as its own disclosure item.
- No score contribution from CWE-338. The weak-randomness weakness in the password generator is a hardening finding with predictability not empirically demonstrated - no experiment reconstructed engine state and no output was predicted. It stays out of the vector entirely.
- No score contribution from the `X-Forwarded-For` identity swap. It is disclosed as a weakness in the authentication decision path, and its net capability was measured as zero.
- No score for the anonymous file-read condition in the File Manager's archive-compression action at `POST /file-manager/backend/compress`, which was found alongside this work and statically determined to be exploitable as a cross-tenant read, with the download leg being the `direct` action. It was never dynamically verified, its relationship to an earlier published archive issue could not be resolved because the vendor's repository retains only the current version so no patch comparison was possible, and reading a file is not code execution. It is disclosed with its novelty explicitly unretired.
- No claim about an anonymous route to MariaDB administrator, which was also found and is also disclosure-only. It reaches database administrator over two anonymous HTTP requests, entirely through vendor-modified files, with the single-signon authentication type having been changed from the upstream cookie mode. It stops at the database because the daemon runs as uid 101, gid 103 with only the `mysql` group while the panel's own state is a SQLite file whose directory is `drwxrwx--- clp clp`, so database-root is not filesystem-root. Equally it is not claimed to be permanently impossible: landing permissions are a deployment variable.
- No claim about earlier or later builds. Only 2.5.4-3+clp-bookworm was tested. We did not compare against a previous version, so we cannot say when the field lost its validation, and we say nothing in the negative direction either.
- No coverage claim of exhaustiveness. Twenty-two of 119 Symfony routes were exercised anonymously, twelve URI variants against one protected route, fourteen catch-all paths sampled, and the decoded corpus is 648 of 31,907 payload files. Statements of the form "no second injection point exists" are not made anywhere in this document.

### CWE and CVSS — summary

| Item | Value |
|---|---|
| Primary weakness | CWE-93, control characters injected into a value later parsed as nginx directives |
| Contributing | CWE-20, CWE-74, CWE-269 and CWE-250 for the root-running service identities |
| Separate finding | CWE-338, weak randomness in the client-side password generator |
| Explicitly not | CWE-78; both writer substitutions are escaped for the shell |
| Published vector | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Published score | 8.8, High |
| ISS | 0.914816 |
| Impact, Scope Unchanged | 5.873119 |
| Exploitability | 2.835255 |
| Sum before rounding | 8.708374 |
| Rounding | up to the nearest tenth |
| Scope | Unchanged. Changed is argued above and rejected, with no score attached |
| Privileges Required basis | Four distinct `ROLE_USER` identities performed five injection rounds; no `ROLE_ADMIN` was needed and no anonymous path exists |
| Conditional readings | None published |
| Recorded-score correction | None needed; the derived value equals the published value |

---

*Research by the 0day Rubbish Research Team. Advisory: https://0day-rubbish.com/blog/cloudpanel-site-rootdirectory-nginx-vhost-injection-root-rce — Repository and full PoC: https://github.com/Exploit-Garbage/0day-Rubbish — Contact: disclosure@0day-rubbish.com*
