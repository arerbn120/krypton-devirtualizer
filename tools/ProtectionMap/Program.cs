using System.Globalization;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

if (args.Length < 1)
{
    Console.WriteLine("usage: ProtectionMap <assembly-path> [out-report]");
    return;
}

var assemblyPath = Path.GetFullPath(args[0]);
if (!File.Exists(assemblyPath))
{
    Console.WriteLine($"file not found: {assemblyPath}");
    return;
}

var module = ModuleDefinition.FromFile(assemblyPath);
var lines = new List<string>();
void Line(string text = "") => lines.Add(text);

var allMethods = module.GetAllTypes()
    .SelectMany(t => t.Methods)
    .ToList();
var ilMethods = allMethods
    .Where(m => m.CilMethodBody != null)
    .ToList();

Line("# Protection Map");
Line();
Line($"Input: {assemblyPath}");
Line($"Types: {module.GetAllTypes().Count()}");
Line($"Methods: {allMethods.Count}");
Line($"IL methods: {ilMethods.Count}");
Line();

var markers = new[]
{
    new Marker("Anti Debug", new[]
    {
        "System.Diagnostics.Debugger",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
        "get_IsAttached",
        "get_IsLogging",
        "Debugger::Log"
    }),
    new Marker("Anti Injection / Native Runtime", new[]
    {
        "VirtualProtect",
        "VirtualAlloc",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "GetProcAddress",
        "GetModuleHandle",
        "LoadLibrary",
        "OpenProcess",
        "CloseHandle",
        "Marshal::Read",
        "Marshal::Write",
        "Marshal::Copy",
        "Marshal::GetDelegateForFunctionPointer"
    }),
    new Marker("Watchdog / Threading", new[]
    {
        "System.Threading.Thread",
        "ThreadStart",
        "ParameterizedThreadStart",
        "Task::Run",
        "Timer",
        "Sleep",
        "Abort",
        "Start"
    }),
    new Marker("Integrity / Tamper", new[]
    {
        "GetManifestResourceStream",
        "ComputeHash",
        "SHA",
        "MD5",
        "CRC",
        "FileStream",
        "File::Read",
        "Assembly::GetExecutingAssembly",
        "Module::Resolve",
        "MetadataToken",
        "PEKind"
    }),
    new Marker("Resource / String Crypto", new[]
    {
        "GetManifestResourceStream",
        "ResourceManager",
        "DeflateStream",
        "GZipStream",
        "CryptoStream",
        "Aes",
        "Rijndael",
        "DES",
        "FromBase64String",
        "TransformFinalBlock",
        "Rfc2898DeriveBytes",
        "Encoding::GetString"
    }),
    new Marker("Hide Calls / Delegates", new[]
    {
        "Delegate",
        "MulticastDelegate",
        "Invoke",
        "DynamicInvoke",
        "Ldftn",
        "Ldvirtftn",
        "RuntimeMethodHandle",
        "RuntimeTypeHandle",
        "RuntimeFieldHandle"
    }),
    new Marker("Process Kill / Exit", new[]
    {
        "Environment::Exit",
        "Environment::FailFast",
        "Process::Kill",
        "Application::Exit"
    })
};

Line("## P/Invoke Imports");
var pinvokes = allMethods
    .Where(m => m.ImplementationMap != null)
    .OrderBy(m => Token(m))
    .ToList();
if (pinvokes.Count == 0)
{
    Line("- <none>");
}
else
{
    foreach (var method in pinvokes)
    {
        var map = method.ImplementationMap;
        Line($"- {Tok(method)} {method.FullName} => {map?.Scope?.Name}!{map?.Name}");
    }
}
Line();

Line("## Runtime-Looking Types");
foreach (var type in module.GetAllTypes()
             .Where(t => LooksRuntimeLike(t))
             .OrderBy(t => t.MetadataToken.ToUInt32()))
{
    var cctor = type.Methods.FirstOrDefault(m => m.IsStatic && string.Equals(m.Name, ".cctor", StringComparison.Ordinal));
    var methodCount = type.Methods.Count;
    var fieldCount = type.Fields.Count;
    var maxBody = type.Methods
        .Where(m => m.CilMethodBody != null)
        .Select(m => m.CilMethodBody!.Instructions.Count)
        .DefaultIfEmpty(0)
        .Max();
    Line($"- type 0x{type.MetadataToken.ToUInt32():X8} {type.FullName} methods={methodCount} fields={fieldCount} maxBody={maxBody} cctor={(cctor == null ? "no" : Tok(cctor))}");
}
Line();

Line("## Protection Markers");
foreach (var marker in markers)
{
    var hits = FindMarkerHits(ilMethods, marker.Patterns)
        .OrderBy(h => h.MethodToken)
        .ThenBy(h => h.InstructionIndex)
        .ToList();

    Line($"### {marker.Name}");
    if (hits.Count == 0)
    {
        Line("- <none>");
        Line();
        continue;
    }

    foreach (var group in hits.GroupBy(h => h.MethodFullName).Take(40))
    {
        var first = group.First();
        Line($"- {first.MethodTokenText} {first.MethodFullName}");
        foreach (var hit in group.Take(8))
            Line($"  - [{hit.InstructionIndex}] {hit.OpCode} {hit.OperandText}");
    }

    if (hits.Select(h => h.MethodFullName).Distinct().Count() > 40)
        Line("- ... truncated ...");
    Line();
}

Line("## Static Constructors Calling Runtime Stubs");
var runtimeStubCalls = ilMethods
    .Where(m => m.IsStatic && string.Equals(m.Name, ".cctor", StringComparison.Ordinal))
    .Select(m => new
    {
        Method = m,
        Calls = GetCallOperands(m)
            .Where(c => IsObfuscatedUserMethod(c) || ContainsAny(c.FullName ?? string.Empty, new[] {"RuntimeHelpers", "Module::Resolve"}))
            .Take(12)
            .ToList()
    })
    .Where(x => x.Calls.Count > 0)
    .OrderBy(x => Token(x.Method))
    .ToList();
if (runtimeStubCalls.Count == 0)
{
    Line("- <none>");
}
else
{
    foreach (var item in runtimeStubCalls.Take(80))
    {
        Line($"- {Tok(item.Method)} {item.Method.FullName}");
        foreach (var call in item.Calls)
            Line($"  - {call.FullName}");
    }
}
Line();

Line("## Resource Hints");
foreach (var method in ilMethods.Where(m => ContainsStringOrCall(m, "GetManifestResourceStream") || ContainsStringOrCall(m, "ResourceManager")))
{
    Line($"- {Tok(method)} {method.FullName}");
    foreach (var ins in method.CilMethodBody!.Instructions.Where(i => i.OpCode.Code == CilCode.Ldstr).Take(12))
        Line($"  - ldstr {ins.Operand}");
}
Line();

Line("## Biggest IL Bodies");
foreach (var method in ilMethods
             .OrderByDescending(m => m.CilMethodBody!.Instructions.Count)
             .Take(25))
{
    var body = method.CilMethodBody!;
    Line($"- {Tok(method)} instr={body.Instructions.Count} locals={body.LocalVariables.Count} eh={body.ExceptionHandlers.Count} {method.FullName}");
}

var output = string.Join(Environment.NewLine, lines);
if (args.Length >= 2)
{
    var reportPath = Path.GetFullPath(args[1]);
    File.WriteAllText(reportPath, output);
    Console.WriteLine($"wrote {reportPath}");
}
else
{
    Console.WriteLine(output);
}

static IEnumerable<MarkerHit> FindMarkerHits(IEnumerable<MethodDefinition> methods, IEnumerable<string> patterns)
{
    foreach (var method in methods)
    {
        var body = method.CilMethodBody;
        if (body == null)
            continue;

        for (var i = 0; i < body.Instructions.Count; i++)
        {
            var instruction = body.Instructions[i];
            var operandText = OperandText(instruction);
            if (string.IsNullOrEmpty(operandText))
                continue;

            if (!ContainsAny(operandText, patterns))
                continue;

            yield return new MarkerHit(
                Token(method),
                Tok(method),
                method.FullName,
                i,
                instruction.OpCode.Code.ToString(),
                operandText);
        }
    }
}

static IEnumerable<IMethodDescriptor> GetCallOperands(MethodDefinition method)
{
    var body = method.CilMethodBody;
    if (body == null)
        yield break;

    foreach (var instruction in body.Instructions)
    {
        if (instruction.OpCode.Code != CilCode.Call &&
            instruction.OpCode.Code != CilCode.Callvirt &&
            instruction.OpCode.Code != CilCode.Newobj &&
            instruction.OpCode.Code != CilCode.Ldftn &&
            instruction.OpCode.Code != CilCode.Ldvirtftn)
        {
            continue;
        }

        if (instruction.Operand is IMethodDescriptor descriptor)
            yield return descriptor;
    }
}

static bool ContainsStringOrCall(MethodDefinition method, string text)
{
    var body = method.CilMethodBody;
    if (body == null)
        return false;

    foreach (var instruction in body.Instructions)
    {
        if (OperandText(instruction).IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0)
            return true;
    }

    return false;
}

static string OperandText(CilInstruction instruction)
{
    if (instruction.Operand == null)
        return string.Empty;

    var text = instruction.Operand.ToString() ?? string.Empty;
    if (instruction.Operand is IMethodDescriptor descriptor)
    {
        try
        {
            var resolved = descriptor.Resolve();
            if (resolved != null)
                text += $" [resolved={Tok(resolved)}]";
        }
        catch
        {
            // Best effort for malformed protector metadata.
        }
    }

    return text;
}

static bool LooksRuntimeLike(TypeDefinition type)
{
    var fullName = type.FullName ?? string.Empty;
    if (fullName.Contains("<Module>", StringComparison.Ordinal) ||
        fullName.Contains("{", StringComparison.Ordinal) ||
        fullName.Any(c => c < 0x20 || c > 0x7E))
    {
        return true;
    }

    var maxBody = type.Methods
        .Where(m => m.CilMethodBody != null)
        .Select(m => m.CilMethodBody!.Instructions.Count)
        .DefaultIfEmpty(0)
        .Max();

    return type.Methods.Count >= 20 || type.Fields.Count >= 20 || maxBody >= 200;
}

static bool IsObfuscatedUserMethod(IMethodDescriptor descriptor)
{
    var fullName = descriptor.FullName ?? string.Empty;
    if (fullName.StartsWith("System.", StringComparison.Ordinal) ||
        fullName.StartsWith("Microsoft.", StringComparison.Ordinal))
    {
        return false;
    }

    return fullName.Any(c => c < 0x20 || c > 0x7E) ||
           fullName.Contains("<Module>", StringComparison.Ordinal) ||
           fullName.Contains("{", StringComparison.Ordinal);
}

static bool ContainsAny(string text, IEnumerable<string> patterns)
{
    foreach (var pattern in patterns)
    {
        if (text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
            return true;
    }

    return false;
}

static uint Token(MethodDefinition method)
{
    var raw = method.MetadataToken.ToUInt32();
    if (raw != 0)
        return raw;
    return 0x06000000u | method.MetadataToken.Rid;
}

static string Tok(MethodDefinition method) => $"0x{Token(method).ToString("X8", CultureInfo.InvariantCulture)}";

sealed record Marker(string Name, string[] Patterns);

sealed record MarkerHit(
    uint MethodToken,
    string MethodTokenText,
    string MethodFullName,
    int InstructionIndex,
    string OpCode,
    string OperandText);
