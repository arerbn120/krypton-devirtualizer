using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.Parser;
using Krypton.Core.PatternMatching;
using Krypton.Pipeline.Stages;

if (args.Length < 2)
{
    Console.WriteLine("usage: PatternProbe <assembly> <vm-byte-hex> [vm-byte-hex ...]");
    return;
}

var inputPath = args[0];
var requested = args
    .Skip(1)
    .Select(arg => int.Parse(arg.Replace("0x", string.Empty, StringComparison.OrdinalIgnoreCase), NumberStyles.HexNumber, CultureInfo.InvariantCulture))
    .Distinct()
    .ToList();

var ctx = BuildContext(inputPath);
if (ctx.OpcodeHandlerMethod?.CilMethodBody?.Instructions == null || ctx.OpcodeHandlerIndices == null)
{
    Console.WriteLine("handler method not found");
    return;
}

var opcodeHandlerMethod = ctx.OpcodeHandlerMethod;
var instructions = opcodeHandlerMethod.CilMethodBody.Instructions.ToList();
var patterns = typeof(PatternMatcher).Assembly.GetTypes()
    .Where(t => typeof(IPattern).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract)
    .Select(t => (IPattern) Activator.CreateInstance(t)!)
    .OrderByDescending(p => p.Pattern.Count)
    .ToList();

Console.WriteLine($"dispatcher: {opcodeHandlerMethod.FullName}");
Console.WriteLine($"handlers: {ctx.OpcodeHandlerIndices.Count}");
Console.WriteLine();

foreach (var vm in requested)
{
    if (!ctx.OpcodeHandlerIndices.TryGetValue(vm, out var index))
    {
        Console.WriteLine($"vm 0x{vm:X2}: handler not found");
        Console.WriteLine();
        continue;
    }

    Console.WriteLine($"==== vm 0x{vm:X2} @ {index} ====");
    var any = false;
    foreach (var pat in patterns)
    {
        if (!Matches(pat.Pattern, instructions, index))
            continue;
        any = true;
        var ok = pat.Verify(opcodeHandlerMethod, index);
        Console.WriteLine($"{pat.GetType().Name} => {pat.Translates} | verify={ok}");
    }

    if (!any)
        Console.WriteLine("<no pattern match>");

    if (ctx.OpcodeConfidence != null && ctx.OpcodeConfidence.TryGetValue(vm, out var confidence))
        Console.WriteLine($"selected: {confidence.OpCode} conf={confidence.Confidence:F2} source={confidence.Source}");
    else
        Console.WriteLine("selected: <unknown>");

    Console.WriteLine();
}

static bool Matches(IList<CilOpCode> pattern, List<CilInstruction> instructions, int index)
{
    if (index + pattern.Count > instructions.Count)
        return false;

    for (var i = 0; i < pattern.Count; i++)
    {
        if (pattern[i] == CilOpCodes.Nop)
            continue;
        if (instructions[index + i].OpCode != pattern[i])
            return false;
    }

    return true;
}

static DevirtualizationCtx BuildContext(string inputPath)
{
    var logger = new ToolLogger();
    var options = new DevirtualizationOptions(inputPath, logger)
    {
        StrictDiagnostics = true
    };
    var ctx = new DevirtualizationCtx(options);
    ctx.ResourceReader = new ResourceParser();

    var resourceParsing = new ResourceParsing();
    var opcodeMapping = new OpcodeMapping();

    resourceParsing.Run(ctx);
    opcodeMapping.Run(ctx);
    return ctx;
}

file sealed class ToolLogger : ILogger
{
    public void Info(string text)
    {
    }

    public void InfoStr(string message, string message2)
    {
    }

    public void Warning(string text)
    {
    }

    public void Error(string text)
    {
        Console.Error.WriteLine(text);
    }

    public void Success(string text)
    {
    }
}
