# Joget Workflow Enterprise JasperReports jrxml Expression Injection RCE - Technical Analysis

## 1. Overview

Joget Workflow Enterprise 9.1.0.1 is a closed-source low-code application platform used for business process management and workflow automation, often integrated with ERP and approval systems. The enterprise plugin `JasperReportsMenu` (`jw-enterprise-plugins-9.1.0.1.jar`) compiles and fills a user-supplied JasperReports `jrxml` document. Its `webService` endpoint is reachable by anonymous users (`ROLE_ANONYMOUS`) and performs no permission checks. Because JasperReports 6.20.6 has no expression allowlist by default (`ReportClassFilter.filterEnabled=false`), a `textFieldExpression` can invoke arbitrary Java — including `Runtime.getRuntime().exec(...)` — yielding unauthenticated root RCE on the application server.

## 2. Vulnerability Summary

- **Root cause**: anonymous-reachable plugin service endpoint + no permission checks + unvalidated jrxml expression evaluation
- **CWE**: CWE-94 (code injection / expression injection), CWE-306 (missing authentication on the plugin service endpoint)
- **CVSS 3.1**: 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Impact**: unauthenticated root RCE; full control of the Joget application server

## 3. Authentication Boundary

Spring Security configuration (`WEB-INF/applicationContext.xml`):

```xml
<security:http pattern="/**">
  <security:anonymous username="roleAnonymous"/>
  ...
  <security:intercept-url pattern="/web/json/app/**/plugin/**/service" access="ROLE_ANONYMOUS"/>
  <!-- comment: permissions controlled by plugin -->
</security:http>
```

The route `/web/json/app/**/plugin/**/service` is explicitly allowed for anonymous users. CSRFGuard marks `/web/json/*` as unprotected, and `JsonResponseFilter` only performs a Referer domain whitelist check (CSRF domain validation, not authentication) — a `Referer: http://<host>/jw/web/` header passes.

## 4. Attack Surface

| Item | Value |
|---|---|
| Port | 8180 (Tomcat 11.0.22) |
| Entry point | `POST /web/json/app/<appId>/<appVersion>/plugin/<pluginName>/service` |
| Auth | anonymous (`ROLE_ANONYMOUS`) |
| Process user | root (default) |

The vulnerable route is the generic plugin-service dispatcher (`PluginJsonController.service`), which forwards to any installed plugin implementing `PluginWebSupport`. The `JasperReportsMenu` enterprise plugin is one such plugin; the route is anonymous by default, so any Joget deployment with the enterprise plugin installed and at least one app definition is exposed. The dispatcher resolves the app with `getAppDefinition` (no publish requirement), obtains the plugin by name, and calls `webService` with no permission check on the handler.

## 5. Sink Identification

`org.joget.plugin.enterprise.JasperReportsMenu.getReport` (JasperReportsMenu.java:577-626):

```java
static final JasperPrint getReport(JasperReportsMenu ajc$this, UserviewMenu menu, JoinPoint joinPoint) {
    String jrxml = menu.getPropertyString("jrxml");          // line 580 - attacker-controlled
    if (jrxml.isEmpty()) return null;
    ...
    ByteArrayInputStream input = new ByteArrayInputStream(jrxml.getBytes("UTF-8"));
    JasperReport report = JasperCompileManager.compileReport(input);  // line 588 - compile
    ...
    print = JasperFillManager.fillReport(report, hm, conn);           // line 626 - fill, evaluates expressions
}
```

JasperReports 6.20.6 has no expression allowlist by default; `textFieldExpression` can call any Java, including `Runtime.getRuntime().exec(...)`.

## 6. Source Identification

`JasperReportsMenu.webService` (JasperReportsMenu.java:475-502) reads the `json` HTTP parameter:

```java
String json = request.getParameter("json");   // line 491 - SOURCE
selectedMenu = json != null && !json.trim().isEmpty()
    ? ajc$this.findUserviewMenuFromPreview(json, menuId, contextPath, parameterMap, key)  // line 497
    : ajc$this.findUserviewMenuFromDef(...);
if (selectedMenu != null) {
    ajc$this.generateReport(selectedMenu, type, output, request, response);  // line 502
}
```

The `json` parameter carries a userview definition whose `properties.jrxml` becomes the menu property.

The userview JSON structure is fully attacker-controlled. Setting `setting.properties.tempDisablePermissionChecking` to `"true"` makes `UserviewService.createUserview` set `userviewPermission = true` (line 243-244), bypassing the userview permission rules; the same flag sets `hasPermis = true` (line 268-269), bypassing category-level permissions. The menu object is instantiated by `className`, and `menu.setProperties` (line 310) assigns the attacker's `jrxml` string to the menu property. No signature, size, or content validation is applied to the `jrxml` before it reaches the report compiler.

## 7. Data Flow

```
Attacker -> POST /web/json/app/<appId>/<appVersion>/plugin/<pluginName>/service?json=<userview>
  -> PluginJsonController.service (line 167-181)
     -> appService.getAppDefinition(appId, appVersion)   // any existing app works, no publish needed
     -> pluginManager.getPlugin(pluginName) instanceof PluginWebSupport
     -> pluginWeb.webService(request, response)          // line 176 - no permission check
  -> UserviewService.createUserview (line 175-346)
     -> setting.properties.tempDisablePermissionChecking=true -> userviewPermission=true
     -> menu.setProperties(...jrxml from JSON...)        // line 310
  -> findUserviewMenuFromPreview -> menu with attacker jrxml
  -> generateReport -> getReport
     -> JasperCompileManager.compileReport(jrxml)
     -> JasperFillManager.fillReport(...)                // evaluates textFieldExpression
        -> Runtime.getRuntime().exec(...)                // RCE as root
```

Route B uses `getAppDefinition` (not `getPublishedAppDefinition`), so any existing app (e.g. the default `crm/1`) suffices; no publishing is required. Setting `tempDisablePermissionChecking=true` bypasses all three permission layers (userview / category / menu).

## 8. Exploit Construction

1. Submit a userview JSON in the `json` form parameter with:
   - `className: org.joget.apps.userview.model.Userview`
   - `setting.properties.tempDisablePermissionChecking: "true"` (bypasses permission checks)
   - a menu whose `properties.jrxml` is a JasperReports document with a `textFieldExpression` that calls `Runtime.getRuntime().exec("<cmd>")` and writes output to a readable location
2. The service endpoint compiles and fills the report; the expression executes as the Joget process user (default root).
3. Read the command output file on the target to confirm RCE.

The `jrxml` template uses a `textFieldExpression` that invokes Java at report-fill time. A minimal malicious template declares a text field whose expression calls `Runtime.getRuntime().exec()` with a command that redirects output to a readable file. Because JasperReports imports `java.lang.*` by default and `ReportClassFilter.filterEnabled` defaults to false, no class/expression allowlist blocks the call. The request also needs a `Referer: http://<host>/jw/web/` header to pass the CSRF-domain check performed by `JsonResponseFilter`.

## 9. Dynamic Verification

Verified dynamically against Joget Workflow Enterprise 9.1.0.1 running as root:

```
POST /web/json/app/crm/1/plugin/<pluginName>/service?action=report&json=<userview with jrxml>
  -> report compiled and filled; expression evaluated; command executed
Target-side: cat /tmp/joget-rce-id.txt -> uid=0(root)
```

The verification used the default bundled app and a `jrxml` template whose `textFieldExpression` executed `id` and wrote the output to `/tmp/joget-rce-id.txt`; the file was then read on the target, confirming root execution. The request included the expected `Referer` header to pass the CSRF-domain check. The same template pattern with a command that appends an SSH key or writes a cron job provides persistence.

## 10. Reachability & Impact

- **Default configuration**: reachable — the `/web/json/app/**/plugin/**/service` route is anonymous by default; any existing app suffices.
- **No authentication**: no permission checks in the plugin dispatch handler.
- **Impact**: unauthenticated root RCE on the application server; full control of the low-code platform and all hosted applications/data.

Joget Workflow Enterprise is a low-code BPM platform used to build business applications; a compromise gives full access to workflow definitions, business data, and any integrations the platform can reach. The anonymous route is part of the shipped Spring Security configuration (`ROLE_ANONYMOUS`), so no misconfiguration is required. Any existing app (including the bundled default) is sufficient because Route B resolves apps with `getAppDefinition` rather than requiring a published definition.

## 11. Fix Recommendations

1. Remove `ROLE_ANONYMOUS` from the plugin service route and enforce per-plugin permission checks in the dispatch handler.
2. Enable JasperReports `ReportClassFilter` or a strict expression allowlist to block `Runtime`/`ProcessBuilder` and other dangerous classes.
3. Validate `jrxml` input as a template rather than evaluating arbitrary expressions.
4. Run Joget under an unprivileged account instead of root.

## 12. CWE / CVSS

- **CWE-94** — code injection via expression evaluation
- **CWE-306** — missing authentication on the plugin service endpoint
- **CVSS 3.1**: **9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

The score reflects the unauthenticated, default-configuration reachability and the root execution context of the Joget server. Enabling JasperReports expression filtering or removing the anonymous route would each independently break the chain.
