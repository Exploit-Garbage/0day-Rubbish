# MAPS SCADA WSDataProvider.Login Unauthenticated BinaryFormatter Deserialization RCE

## Summary

A critical unauthenticated remote code execution vulnerability in MAPS SCADA 4.0.5.5 (Adroit Technologies / Mitsubishi Adroit Process Suite) arises because the IIS WebService (default port 8878) exposes `WSDataProvider.asmx`, whose `Login` / `LogOff` / `VerifyLoginStatus` WebMethods deserialize the caller-supplied byte array before any authentication:

```csharp
object obj = Serializer.BinaryDeserialization(Zipper.Unzip(zippedUserDetails));  // line 135
```

`Serializer.BinaryDeserialization` internally calls `new BinaryFormatter().Deserialize(stream)` with no `SerializationBinder` and no `TypeFilterLevel` (line 263). An attacker sends a single unauthenticated HTTP SOAP POST carrying a GZip-compressed BinaryFormatter gadget (TypeConfuseDelegate -> Process.Start), achieving arbitrary command execution as the IIS app pool identity — `NT AUTHORITY\SYSTEM` in the default deployment. Dynamically verified (marker file Owner=SYSTEM).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: MAPS SCADA (Mitsubishi Adroit Process Suite)
- **Versions**: 4.0.5.5 (2026 latest)
- **Vendor**: Adroit Technologies (Johannesburg, South Africa)

## Impact

- **Confidentiality**: Full read of the host filesystem and configuration as NT AUTHORITY\SYSTEM
- **Integrity**: Arbitrary OS command execution as SYSTEM
- **Availability**: Full control of the SCADA host; ability to persist

## Exploitation Prerequisites

Default deployment: IIS WebService on port 8878 with no authentication module/filter; the `Login` WebMethod only has `[WebMethod(true)]` (enables Session). Network reachability to port 8878. The Agent Server (VIPServer) runs by default. Dynamically verified (marker file Owner=SYSTEM).

## Mitigation

1. Add a `SerializationBinder` allowlist and set `TypeFilterLevel` to `Low` in `Serializer.BinaryDeserialization`
2. Replace `BinaryFormatter` with a secure serializer (it is deprecated and inherently unsafe for untrusted input)
3. Require authentication on the WebService endpoints before any deserialization
4. Run the IIS app pool under a low-privilege identity instead of LocalSystem
5. Restrict network exposure of the WebService port to trusted SCADA networks

## Timeline

- **Discovered**: 2026-07-25
- **Public Disclosure**: 2026-08-09 (batch #3)

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
