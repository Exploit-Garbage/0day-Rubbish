# ObjectDB JDOQL Filter Injection to Root RCE — Technical Analysis

## Overview

ObjectDB 2.9.5 server mode listens on port 6136 using a proprietary binary protocol. Factory default credentials `admin/admin` (CWE-798) grant full privileges with no forced change; the IP check accepts any source IP when the user has no `ip` attribute. JDOQL query filter evaluation allows arbitrary static-method reflective invocation (CWE-94): `QNF.q()` loads any class (no class-name allowlist), and `MCN.l()` invokes any method via `Method.invoke` with `setAccessible(true)`, reaching `java.lang.Runtime.getRuntime().exec(cmd)` in the server-side Java process, which runs as root. Dynamically verified with `uid=0(root)`.

- **Authentication required**: default credentials `admin/admin` (CWE-798, effectively no-auth; IP check accepts any source IP)
- **Preconditions**: Default config; network reachability to port 6136
- **Affected versions**: 2.9.5 (server mode); 0-CVE (blue ocean) before this finding
- **Privilege**: root (ObjectDB server process, dynamically verified `uid=0(root)`)

## Architecture

```
L1 external access: ObjectDB server port 6136 (proprietary binary protocol)
L2 protocol layers: handshake (SMR.w: 4-byte magic + 1-byte cmd) + SHN frame layer
L3 auth boundary: HND.x(2) login is the only pre-auth gate; default admin/admin; USR.b IP check returns true when ip attribute is null
L4 source: JDOQL filter string (Query.setFilter) serialized over the network (EBW)
L5 eval: server-side SHN.x cmd 10 -> F() -> TYD query evaluation
L6 sink: QNF.q() loads class -> MCN.l() Method.invoke (setAccessible(true)) -> Runtime.exec
L7 exec: root process runs arbitrary command
```

## Authentication Boundary

- **HND.x(2) login**: the only pre-auth gate. Client sends username+password, server validates.
- **USR.b(byte[]) IP check**: when `this.b == null` (user has no `ip` attribute), returns `true` -> admin user accepts any source IP.
- **Default credentials**: `admin/admin` (CWE-798), factory default, full privileges, no forced change.

## Stage 1: Sink Identification

`MCN.l()` (CFR decompiled from `src/com/objectdb/o/MCN.java` of the ObjectDB source tree) invokes an arbitrary method reflectively:

```java
public final class MCN extends ... {
    // line 83
    this.r.setAccessible(true);
    // line 127
    public Object l() {
        return this.r.invoke(this.aj(), objectArray);  // arbitrary method reflective invoke
    }
}
```

`setAccessible(true)` bypasses Java access control. This is the final sink of JDOQL filter evaluation.

## Stage 2: Source Identification

`JdoQuery.setFilter()` stores the filter string, which is client-supplied:

```java
// JdoQuery.setFilter() line 231
public void setFilter(String filter) {
    getJdoData().c = filter;
}
```

The filter is serialized and transported to the server via EBW (ObjectDB internal serialization):

```java
// JdoQuery.writeObject() line 429-435
writeInt(byArray.length);
write(byArray);
```

## Stage 3: Data Flow (Source -> Sink)

```
Client Query.setFilter("java.lang.Runtime.getRuntime().exec(cmd) != null")
  -> EBW serialization -> network transport
  -> server SHN.x() cmd 10 -> F() -> TYD query evaluation
  -> QNF.q() parses static method call
  -> QMR.c() allowlist check (only Math/JDOHelper/String)
  -> Runtime does not match -> new MCN(...)
  -> MCN.l() this.r.invoke(this.aj(), objectArray) [setAccessible(true)]
  -> java.lang.Runtime.getRuntime().exec(cmd)
  -> server root process executes arbitrary command
```

`QNF.q()` loads any class (key):

```java
// src/com/objectdb/o/QNF.java (CFR decompiled)
// line 453-469
public Object q(...) {
    String string = ...;  // attacker-controlled class name
    Class clazz = "JDOHelper".equals(string) ? JDOHelper.class : this.h.b(string, null);
    // this.h.b(string, null) -> TRS.b -> TYM.N -> loadClass
    // no class-name allowlist! any class can be loaded (including java.lang.Runtime)
}
```

## Stage 4: Injection / Exploit Construction

Malicious JDOQL filter:

```
java.lang.Runtime.getRuntime().exec("<cmd>") != null
```

The filter is set via `Query.setFilter()` on the client, using `javax.jdo` APIs (JDOHelper -> PersistenceManager -> newQuery(Item.class) -> setFilter). The PoC script generates a Java program that compiles and runs against the ObjectDB jar, connecting over the proprietary protocol.

## Dynamic Verification

- Probe: unauthenticated admin cmd 16 (info disclosure) confirms service reachability and CWE-306.
- The Java PoC connects with `admin/admin`, persists a candidate `Item`, then executes the malicious JDOQL filter.
- Server-side `Runtime.exec` runs as root; marker file confirms `uid=0(root)`.

## Mitigation

1. Force a password change on first login; disallow the factory default `admin/admin`
2. Add a class-name allowlist to `QNF.q()` (currently only `Math`/`JDOHelper`/`String` are checked by `QMR.c()`, but arbitrary classes are loadable via `loadClass`)
3. Remove `setAccessible(true)` in `MCN.l()` so Java access control cannot be bypassed
4. Run the server under a dedicated low-privilege user, not root
5. Restrict network exposure of the ObjectDB server port

## CWEs

- CWE-94 (Improper Control of Generation of Code) - arbitrary static method reflection in JDOQL filter evaluation
- CWE-798 (Use of Hard-coded Credentials) - factory default admin/admin, no forced change
- CWE-250 (Execution with Unnecessary Privileges) - server runs as root
- CWE-284 (Improper Access Control) - IP check accepts any source IP for admin
