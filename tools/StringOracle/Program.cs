using System.Reflection;
using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;

if (args.Length < 1)
{
    PrintUsage();
    return;
}

var inputPath = Path.GetFullPath(args[0]);
if (!File.Exists(inputPath))
{
    Console.WriteLine($"file not found: {inputPath}");
    return;
}

string? decoderTypeOverride = null;
string? decoderMethodOverride = null;
string? callerFilter = null;
var includeFailures = false;
var uniqueOnly = true;
var maxResults = 0;

for (var i = 1; i < args.Length; i++)
{
    var arg = args[i];
    if (string.Equals(arg, "--decoder-type", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        decoderTypeOverride = args[++i];
        continue;
    }

    if (string.Equals(arg, "--decoder-method", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        decoderMethodOverride = args[++i];
        continue;
    }

    if (string.Equals(arg, "--caller", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        callerFilter = args[++i];
        continue;
    }

    if (string.Equals(arg, "--include-failures", StringComparison.OrdinalIgnoreCase))
    {
        includeFailures = true;
        continue;
    }

    if (string.Equals(arg, "--all", StringComparison.OrdinalIgnoreCase))
    {
        uniqueOnly = false;
        continue;
    }

    if (string.Equals(arg, "--max", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        if (!int.TryParse(args[++i], out maxResults) || maxResults < 0)
            maxResults = 0;
        continue;
    }
}

var module = ModuleDefinition.FromFile(inputPath);
var asm = Assembly.LoadFrom(inputPath);
var runtime = new RuntimeContext(asm);

runtime.RunModuleConstructors();

var decoderMethod = FindDecoderMethod(module, decoderTypeOverride, decoderMethodOverride);
if (decoderMethod == null)
{
    Console.WriteLine("decoder method not found.");
    Console.WriteLine("Tip: pass --decoder-type and --decoder-method.");
    return;
}

var reflectionDecoder = runtime.ResolveDecoderMethod(decoderMethod);
if (reflectionDecoder == null)
{
    Console.WriteLine("could not resolve reflection decoder method.");
    return;
}

runtime.TryRelaxDecoderGuard(reflectionDecoder.DeclaringType);
runtime.RunClassConstructor(reflectionDecoder.DeclaringType);

Console.WriteLine($"assembly: {inputPath}");
Console.WriteLine($"decoder: {decoderMethod.FullName}");
Console.WriteLine();

var matches = ScanDecoderCallsites(module, decoderMethod, callerFilter);
if (matches.Count == 0)
{
    Console.WriteLine("no decoder callsites found.");
    return;
}

var results = new List<RecoveredString>();
foreach (var match in matches)
{
    if (!TryEvaluateIntExpression(match.Caller.CilMethodBody!.Instructions, match.CallIndex - 1, runtime, out var index))
    {
        if (includeFailures)
        {
            results.Add(new RecoveredString(
                match.Caller,
                match.CallIndex,
                null,
                null,
                "failed to evaluate index expression"));
        }

        continue;
    }

    if (runtime.TryInvokeDecoder(reflectionDecoder, index, out var text, out var error))
    {
        results.Add(new RecoveredString(match.Caller, match.CallIndex, index, text, null));
    }
    else if (includeFailures)
    {
        results.Add(new RecoveredString(match.Caller, match.CallIndex, index, null, error));
    }
}

if (results.Count == 0)
{
    Console.WriteLine("no recovered strings.");
    return;
}

IEnumerable<RecoveredString> output = results;
if (uniqueOnly)
{
    output = results
        .Where(r => r.Text != null)
        .GroupBy(r => $"{r.Index}:{r.Text}", StringComparer.Ordinal)
        .Select(g => g.First());
}

if (maxResults > 0)
    output = output.Take(maxResults);

var emitted = 0;
foreach (var row in output.OrderBy(r => r.Caller.FullName, StringComparer.Ordinal).ThenBy(r => r.CallIndex))
{
    emitted++;
    var token = GetMethodToken(row.Caller);
    var location = $"0x{token:X8}@{row.CallIndex}";
    if (row.Text != null)
    {
        Console.WriteLine($"{location} idx={row.Index} text=\"{Escape(row.Text)}\"");
    }
    else
    {
        Console.WriteLine($"{location} idx={row.Index?.ToString() ?? "?"} error={row.Error}");
    }
}

Console.WriteLine();
Console.WriteLine($"callsites scanned: {matches.Count}");
Console.WriteLine($"rows emitted: {emitted}");
Console.WriteLine($"successes: {results.Count(r => r.Text != null)}");
Console.WriteLine($"failures: {results.Count(r => r.Text == null)}");
if (uniqueOnly)
    Console.WriteLine("mode: unique");
else
    Console.WriteLine("mode: all");

return;

static void PrintUsage()
{
    Console.WriteLine("usage: StringOracle <assembly-path> [options]");
    Console.WriteLine("options:");
    Console.WriteLine("  --decoder-type <full-name>      Explicit decoder declaring type");
    Console.WriteLine("  --decoder-method <name>         Explicit decoder method name");
    Console.WriteLine("  --caller <substring>            Scan only callers that contain substring");
    Console.WriteLine("  --all                           Print all matches (default is unique by idx+text)");
    Console.WriteLine("  --include-failures              Also print failures");
    Console.WriteLine("  --max <N>                       Limit output rows");
}

static MethodDefinition? FindDecoderMethod(
    ModuleDefinition module,
    string? decoderTypeOverride,
    string? decoderMethodOverride)
{
    var allMethods = module.GetAllTypes()
        .SelectMany(t => t.Methods)
        .Where(m => m.IsStatic && m.IsIL && m.CilMethodBody != null)
        .ToList();

    if (!string.IsNullOrWhiteSpace(decoderTypeOverride) && !string.IsNullOrWhiteSpace(decoderMethodOverride))
    {
        var forced = allMethods.FirstOrDefault(m =>
            string.Equals(NormalizeTypeName(m.DeclaringType?.FullName), NormalizeTypeName(decoderTypeOverride), StringComparison.Ordinal) &&
            string.Equals(m.Name, decoderMethodOverride, StringComparison.Ordinal));
        if (forced != null)
            return forced;
    }

    var candidates = allMethods
        .Where(IsLikelyDecoderSignature)
        .Where(ContainsResourceAndUnicodeDecoderPattern)
        .ToList();
    if (candidates.Count == 0)
        return null;

    if (!string.IsNullOrWhiteSpace(decoderMethodOverride))
    {
        var byName = candidates.FirstOrDefault(m =>
            string.Equals(m.Name, decoderMethodOverride, StringComparison.Ordinal));
        if (byName != null)
            return byName;
    }

    return candidates
        .OrderByDescending(m => CountInstructions(m.CilMethodBody!))
        .FirstOrDefault();
}

static bool IsLikelyDecoderSignature(MethodDefinition method)
{
    var sig = method.Signature;
    if (sig == null || !method.IsStatic)
        return false;
    if (!string.Equals(sig.ReturnType?.FullName, "System.String", StringComparison.Ordinal))
        return false;
    if (sig.ParameterTypes.Count != 1)
        return false;
    return string.Equals(sig.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal);
}

static bool ContainsResourceAndUnicodeDecoderPattern(MethodDefinition method)
{
    if (method.CilMethodBody == null)
        return false;

    var hasManifestResource = false;
    var hasUnicodeGetString = false;

    foreach (var instruction in method.CilMethodBody.Instructions)
    {
        var operandText = instruction.Operand?.ToString() ?? string.Empty;
        if (operandText.IndexOf("GetManifestResourceStream", StringComparison.OrdinalIgnoreCase) >= 0)
            hasManifestResource = true;
        if (operandText.IndexOf("System.Text.Encoding", StringComparison.OrdinalIgnoreCase) >= 0 &&
            operandText.IndexOf("GetString", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            hasUnicodeGetString = true;
        }
    }

    return hasManifestResource && hasUnicodeGetString;
}

static int CountInstructions(CilMethodBody body) => body.Instructions.Count;

static List<CallsiteMatch> ScanDecoderCallsites(
    ModuleDefinition module,
    MethodDefinition decoderMethod,
    string? callerFilter)
{
    var matches = new List<CallsiteMatch>();
    foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
    {
        if (!method.IsIL || method.CilMethodBody == null)
            continue;
        if (!string.IsNullOrWhiteSpace(callerFilter) &&
            method.FullName.IndexOf(callerFilter, StringComparison.OrdinalIgnoreCase) < 0)
        {
            continue;
        }

        var instructions = method.CilMethodBody.Instructions;
        for (var i = 0; i < instructions.Count; i++)
        {
            var instruction = instructions[i];
            if (instruction.OpCode.Code != CilCode.Call && instruction.OpCode.Code != CilCode.Callvirt)
                continue;
            if (instruction.Operand is not IMethodDescriptor descriptor)
                continue;
            if (!MatchesDecoder(descriptor, decoderMethod))
                continue;

            matches.Add(new CallsiteMatch(method, i));
        }
    }

    return matches;
}

static bool MatchesDecoder(IMethodDescriptor descriptor, MethodDefinition decoderMethod)
{
    try
    {
        var resolved = descriptor.Resolve();
        if (resolved != null &&
            resolved.MetadataToken.ToUInt32() == decoderMethod.MetadataToken.ToUInt32() &&
            string.Equals(
                NormalizeTypeName(resolved.DeclaringType?.FullName),
                NormalizeTypeName(decoderMethod.DeclaringType?.FullName),
                StringComparison.Ordinal))
        {
            return true;
        }
    }
    catch
    {
        // Continue with name-based fallback.
    }

    var declaring = NormalizeTypeName(descriptor.DeclaringType?.FullName);
    var targetDeclaring = NormalizeTypeName(decoderMethod.DeclaringType?.FullName);
    return string.Equals(descriptor.Name, decoderMethod.Name, StringComparison.Ordinal) &&
           string.Equals(declaring, targetDeclaring, StringComparison.Ordinal);
}

static bool TryEvaluateIntExpression(
    IList<CilInstruction> instructions,
    int index,
    RuntimeContext runtime,
    out int value)
{
    value = 0;
    var position = index;
    return TryPopInt(instructions, ref position, runtime, out value);
}

static bool TryPopInt(
    IList<CilInstruction> instructions,
    ref int position,
    RuntimeContext runtime,
    out int value)
{
    value = 0;
    if (position < 0 || position >= instructions.Count)
        return false;

    var instruction = instructions[position];
    switch (instruction.OpCode.Code)
    {
        case CilCode.Ldc_I4_M1:
            value = -1;
            position--;
            return true;
        case CilCode.Ldc_I4_0:
            value = 0;
            position--;
            return true;
        case CilCode.Ldc_I4_1:
            value = 1;
            position--;
            return true;
        case CilCode.Ldc_I4_2:
            value = 2;
            position--;
            return true;
        case CilCode.Ldc_I4_3:
            value = 3;
            position--;
            return true;
        case CilCode.Ldc_I4_4:
            value = 4;
            position--;
            return true;
        case CilCode.Ldc_I4_5:
            value = 5;
            position--;
            return true;
        case CilCode.Ldc_I4_6:
            value = 6;
            position--;
            return true;
        case CilCode.Ldc_I4_7:
            value = 7;
            position--;
            return true;
        case CilCode.Ldc_I4_8:
            value = 8;
            position--;
            return true;
        case CilCode.Ldc_I4_S:
            value = Convert.ToSByte(instruction.Operand);
            position--;
            return true;
        case CilCode.Ldc_I4:
            value = Convert.ToInt32(instruction.Operand);
            position--;
            return true;
        case CilCode.Xor:
        {
            position--;
            if (!TryPopInt(instructions, ref position, runtime, out var right))
                return false;
            if (!TryPopInt(instructions, ref position, runtime, out var left))
                return false;
            value = left ^ right;
            return true;
        }
        case CilCode.Add:
        {
            position--;
            if (!TryPopInt(instructions, ref position, runtime, out var right))
                return false;
            if (!TryPopInt(instructions, ref position, runtime, out var left))
                return false;
            value = unchecked(left + right);
            return true;
        }
        case CilCode.Sub:
        {
            position--;
            if (!TryPopInt(instructions, ref position, runtime, out var right))
                return false;
            if (!TryPopInt(instructions, ref position, runtime, out var left))
                return false;
            value = unchecked(left - right);
            return true;
        }
        case CilCode.Shl:
        {
            position--;
            if (!TryPopInt(instructions, ref position, runtime, out var right))
                return false;
            if (!TryPopInt(instructions, ref position, runtime, out var left))
                return false;
            value = left << (right & 31);
            return true;
        }
        case CilCode.Shr:
        {
            position--;
            if (!TryPopInt(instructions, ref position, runtime, out var right))
                return false;
            if (!TryPopInt(instructions, ref position, runtime, out var left))
                return false;
            value = left >> (right & 31);
            return true;
        }
        case CilCode.Not:
        {
            position--;
            if (!TryPopInt(instructions, ref position, runtime, out var inner))
                return false;
            value = ~inner;
            return true;
        }
        case CilCode.Neg:
        {
            position--;
            if (!TryPopInt(instructions, ref position, runtime, out var inner))
                return false;
            value = -inner;
            return true;
        }
        case CilCode.Ldsfld:
        {
            if (instruction.Operand is not IFieldDescriptor staticField)
                return false;
            if (!runtime.TryReadStaticIntField(staticField, out value))
                return false;
            position--;
            return true;
        }
        case CilCode.Ldfld:
        {
            if (instruction.Operand is not IFieldDescriptor instanceField)
                return false;
            if (position - 1 < 0)
                return false;
            var prev = instructions[position - 1];
            if (prev.OpCode.Code != CilCode.Ldsfld || prev.Operand is not IFieldDescriptor ownerField)
                return false;
            if (!runtime.TryReadInstanceIntField(ownerField, instanceField, out value))
                return false;
            position -= 2;
            return true;
        }
        default:
            return false;
    }
}

static string NormalizeTypeName(string? fullName)
{
    if (string.IsNullOrWhiteSpace(fullName))
        return string.Empty;
    return fullName.Replace('/', '+').Trim();
}

static string Escape(string value) =>
    value.Replace("\r", "\\r", StringComparison.Ordinal)
        .Replace("\n", "\\n", StringComparison.Ordinal)
        .Replace("\t", "\\t", StringComparison.Ordinal)
        .Replace("\"", "\\\"", StringComparison.Ordinal);

static uint GetMethodToken(MethodDefinition method)
{
    var raw = method.MetadataToken.ToUInt32();
    if (raw != 0)
        return raw;
    return 0x06000000u | method.MetadataToken.Rid;
}

file sealed record CallsiteMatch(MethodDefinition Caller, int CallIndex);

file sealed record RecoveredString(
    MethodDefinition Caller,
    int CallIndex,
    int? Index,
    string? Text,
    string? Error);

file sealed class RuntimeContext
{
    private readonly Assembly _assembly;
    private readonly Dictionary<string, Type> _typesByName;

    public RuntimeContext(Assembly assembly)
    {
        _assembly = assembly;
        _typesByName = GetAllTypesSafe(_assembly)
            .GroupBy(t => NormalizeTypeName(t.FullName), StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
    }

    public void RunModuleConstructors()
    {
        foreach (var module in _assembly.Modules)
        {
            try
            {
                RuntimeHelpers.RunModuleConstructor(module.ModuleHandle);
            }
            catch
            {
                // Best effort only.
            }
        }
    }

    public void RunClassConstructor(Type? type)
    {
        if (type == null)
            return;
        try
        {
            RuntimeHelpers.RunClassConstructor(type.TypeHandle);
        }
        catch
        {
            // Best effort only.
        }
    }

    public MethodInfo? ResolveDecoderMethod(MethodDefinition decoderMethod)
    {
        var typeName = NormalizeTypeName(decoderMethod.DeclaringType?.FullName);
        if (!_typesByName.TryGetValue(typeName, out var reflectionType))
            return null;

        return reflectionType
            .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            .FirstOrDefault(m =>
                string.Equals(m.Name, decoderMethod.Name, StringComparison.Ordinal) &&
                m.ReturnType == typeof(string) &&
                m.GetParameters().Length == 1 &&
                m.GetParameters()[0].ParameterType == typeof(int));
    }

    public void TryRelaxDecoderGuard(Type? decoderType)
    {
        if (decoderType == null)
            return;

        var flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;
        foreach (var field in decoderType.GetFields(flags))
        {
            if (field.FieldType != typeof(int))
                continue;
            if (field.IsInitOnly || field.IsLiteral)
                continue;
            if (field.Name.IndexOf("xTJ", StringComparison.OrdinalIgnoreCase) < 0)
                continue;
            try
            {
                field.SetValue(null, 75);
            }
            catch
            {
                // Best effort only.
            }
        }
    }

    public bool TryInvokeDecoder(MethodInfo decoderMethod, int index, out string? text, out string? error)
    {
        text = null;
        error = null;
        try
        {
            text = decoderMethod.Invoke(null, new object[] { index }) as string;
            return text != null;
        }
        catch (TargetInvocationException tie)
        {
            error = tie.InnerException?.Message ?? tie.Message;
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public bool TryReadStaticIntField(IFieldDescriptor fieldDescriptor, out int value)
    {
        value = 0;
        if (fieldDescriptor == null)
            return false;

        if (!TryResolveReflectionField(fieldDescriptor, out var reflectionField))
            return false;
        if (reflectionField.FieldType != typeof(int) || !reflectionField.IsStatic)
            return false;
        try
        {
            value = (int) reflectionField.GetValue(null)!;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public bool TryReadInstanceIntField(
        IFieldDescriptor ownerStaticFieldDescriptor,
        IFieldDescriptor instanceFieldDescriptor,
        out int value)
    {
        value = 0;
        if (!TryResolveReflectionField(ownerStaticFieldDescriptor, out var ownerField))
            return false;
        if (!ownerField.IsStatic)
            return false;

        object? ownerInstance;
        try
        {
            ownerInstance = ownerField.GetValue(null);
        }
        catch
        {
            return false;
        }

        if (ownerInstance == null)
            return false;

        if (!TryResolveReflectionField(instanceFieldDescriptor, out var instanceField))
            return false;
        if (instanceField.FieldType != typeof(int))
            return false;

        try
        {
            value = (int) instanceField.GetValue(ownerInstance)!;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool TryResolveReflectionField(IFieldDescriptor descriptor, out FieldInfo field)
    {
        field = null!;
        if (descriptor == null)
            return false;

        var declaringName = NormalizeTypeName(descriptor.DeclaringType?.FullName);
        if (!_typesByName.TryGetValue(declaringName, out var declaringType))
            return false;

        var flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance;
        field = declaringType.GetField(descriptor.Name, flags)!;
        return field != null;
    }

    private static IReadOnlyList<Type> GetAllTypesSafe(Assembly assembly)
    {
        try
        {
            return assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            return ex.Types.Where(t => t != null).Cast<Type>().ToArray();
        }
    }
}
