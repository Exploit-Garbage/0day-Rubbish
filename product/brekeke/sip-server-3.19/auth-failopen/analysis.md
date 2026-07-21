# Brekeke SIP Server Authentication Fail-Open Primitive - Technical Analysis

## Overview

Brekeke SIP Server v3.19.1.8p1 ships a self-developed authentication framework (`ScopeBean.checkScope()` in `ondoutil.jar`) that **fails open** for any bean that has not declared a scope via `setCheckScope()`. Combined with a `GateServlet` dispatcher where the `bean` request parameter is fully attacker-controlled, twenty-three beans with undeclared scopes become reachable without any authentication. This is the root-cause primitive that two downstream unauthenticated RCE chains build on — the Zip Slip webshell path and the Nashorn JS engine path.

## Product Background

| Item | Value |
|------|-------|
| Product | Brekeke SIP Server (SIP Proxy / SIP Registrar) |
| Vendor | Brekeke Software, Inc. (US California / Japan Okinawa R&D) |
| Version | v3.19.1.8p1 (Evaluation Edition, built 2026-06-24) |
| Architecture | Java Servlet (sip.war 20.5 MB) on Tomcat 9.0.87 + Java 17 |
| Self-developed components | ondosip.jar (SIP stack) / ondooss.jar (business + Command bean) / ondoutil.jar (GateServlet/Bean/auth framework) |

## Authentication Boundary

### GateServlet dispatcher

All seven servlets (`/sip/gate`, `/sip/*` mappings) route to `GateServlet`. The `bean` request parameter selects which business bean handles the request:

```java
// com.brekeke...GateServlet (ondoutil.jar)
String beanName = request.getParameter("bean");          // <- attacker-controlled
Object bean = createBean("com.brekeke." + beanName);     // <- reflective instantiation
// bean.checkAuth() then bean.exec()
```

The `bean` parameter is the relative class name under `com.brekeke.`. An attacker who knows (or brute-forces) a bean class name can route any request to it. There is no allowlist.

### Bean.checkAuth() is not a real gate

`Bean.checkAuth()` defaults to returning `true` — it is not a real authentication check. It only blocks GET requests when `bGetAllowed=false` (default `bGetAllowed=true`). The real scope gate is `ScopeBean.checkScope()`, invoked when a bean calls `setCheckScope(...)` to declare the scopes allowed to access it.

### isAdmin() is ineffective

`isAdmin()` returns `true` when the caller is not logged in (`getProcessDomain() == null`). This inverted logic means the "admin" branch is taken for anonymous callers, defeating any code that branches on `isAdmin()` to restrict behavior.

## Root Cause: ScopeBean.checkScope() Fail-Open

`ScopeBean.checkScope()` (`ondoutil.jar`) lets through any bean that has not declared a scope:

```java
protected boolean checkScope() {
    if (this.setHasScope.size() == 0) return true;   // <- fail-open: no scope declared -> pass
    // ... otherwise enforce declared scopes ...
}
```

A bean only enters the enforcing branch if it has previously called `setCheckScope(...)` to register the scopes that may access it. Beans that never call `setCheckScope` have an empty `setHasScope` and are admitted unconditionally.

### Inheritance chain

```
Bean (com.brekeke.web.Bean)                    <- checkAuth defaults true
  ^
ScopeBean (com.brekeke.web.ScopeBean)          <- checkAuth = super.checkAuth() && checkScope()
  ^
WindowScopeBean                                <- does not override checkAuth/checkScope
  ^
SipAdminBase (com.brekeke.sipadmin)            <- does not override checkAuth/checkScope
  ^
business beans (ProvisioningTest / ProvisioningModelImport / ...)
```

`SipAdminBase` and `WindowScopeBean` do not override `checkAuth()` / `checkScope()`, so authentication is entirely determined by `ScopeBean.checkScope()`.

### Bean population

Of the 95 beans that inherit `ScopeBean`:

- 78 beans call `setCheckScope` (protected — authentication enforced)
- 23 beans never call `setCheckScope` (unauthenticated reachable)

### The 23 unauthenticated beans

| Bean | Notes |
|------|-------|
| Command | command execution surface |
| CloudManager | cloud configuration |
| Gw | gateway management |
| ConfigCertificate | certificate configuration |
| HaAction | high-availability actions |
| HsqldbRecovery | database recovery |
| Login | login flow |
| LogSelect | log selection |
| Provisioning | provisioning base |
| ProvisioningLog | provisioning logs |
| ProvisioningModelManager | model management |
| ProvisioningScriptUtil | provisioning scripts |
| ProvisioningSettings | provisioning settings |
| ProvisioningTagManager | provisioning tags |
| RedundancyBase | redundancy control |
| SettingsBase | settings base |
| SipFrame | SIP frame |
| StiAsKeyEdit | STI AS key edit |
| StiAsSettings | STI AS settings |
| Test | test bean |
| LicenseBean | license management |
| ProvisioningTest | JS evaluation sink (RCE chain) |
| ProvisioningModelImport | zip upload sink (RCE chain) |

The last two — `ProvisioningTest` and `ProvisioningModelImport` — are the sinks that the two downstream RCE chains target.

## Dynamic Verification: Unauthenticated-Reachability Oracle

The `bean` parameter produces a distinguishable HTTP status code that acts as an oracle for whether a bean is unauthenticated-reachable:

```bash
# Unauthenticated-reachable bean (undeclared scope) -> 200
curl -s -o /dev/null -w "%{http_code}" \
  "http://127.0.0.1:8080/sip/gate?bean=sipadmin.web.Test"
# -> 200

# Protected bean (declared scope) -> 403
curl -s -o /dev/null -w "%{http_code}" \
  "http://127.0.0.1:8080/sip/gate?bean=sipadmin.web.DomainEdit"
# -> 403
```

The 200/403 split confirms the fail-open behavior empirically: beans with undeclared scopes return 200 to an anonymous caller, while beans that declared a scope return 403.

### Confirming the two RCE sinks are unauthenticated

```bash
curl -s -o /dev/null -w "%{http_code}" \
  "http://127.0.0.1:8080/sip/gate?bean=sipadmin.web.ProvisioningModelImport"
# -> 200  (Zip Slip webshell sink, unauthenticated)

curl -s -o /dev/null -w "%{http_code}" \
  "http://127.0.0.1:8080/sip/gate?bean=sipadmin.web.ProvisioningTest"
# -> 200  (Nashorn JS RCE sink, unauthenticated)
```

Both sinks are reachable without credentials.

## Downstream Chains

This primitive is the foundation for two independent unauthenticated RCE chains, each documented in its own article:

| Chain | Sink bean | Mechanism |
|-------|-----------|-----------|
| Zip Slip webshell RCE | ProvisioningModelImport | malicious zip entry traverses to webroot, writes JSP webshell |
| Nashorn JS RCE | ProvisioningTest | user-controlled JS passed to ScriptEngine.eval() |

Both chains require zero credentials and work in the factory default configuration.

## Core Code Index

| File | Key code | Role |
|------|----------|------|
| `ondoutil/.../ScopeBean.java:88` | `if (setHasScope.size()==0) return true;` | fail-open root cause |
| `ondoutil/.../ScopeBean.java:120` | `checkAuth() = super.checkAuth() && checkScope()` | real auth gate |
| `ondoutil/.../Bean.java` | `checkAuth()` defaults to true | not a real gate |
| `ondooss/.../SipAdminBase.java:774` | `isAdmin() = (getProcessDomain()==null)` | returns true when not logged in, ineffective gate |
| `GateServlet` dispatch | `bean` param -> `createBean("com.brekeke."+beanName)` | attacker-controlled class loading |