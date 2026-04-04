using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.Parser;
using Krypton.Pipeline.Stages;

if (args.Length < 2)
{
    Console.WriteLine("usage: HandlerDump <assembly> <vm-byte-hex> [vm-byte-hex ...] [--lines N]");
    return;
}

var inputPath = args[0];
var maxLines = 120;
var requested = new List<int>();

for (var i = 1; i < args.Length; i++)
{
    if (string.Equals(args[i], "--lines", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        if (!int.TryParse(args[++i], NumberStyles.Integer, CultureInfo.InvariantCulture, out maxLines) || maxLines <= 0)
            maxLines = 120;
        continue;
    }

    var raw = args[i].Replace("0x", string.Empty, StringComparison.OrdinalIgnoreCase);
    requested.Add(int.Parse(raw, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
}

if (requested.Count == 0)
{
    Console.WriteLine("no vm bytes requested");
    return;
}

var ctx = BuildContext(inputPath);
if (ctx.OpcodeHandlerMethod?.CilMethodBody?.Instructions == null || ctx.OpcodeHandlerIndices == null)
{
    Console.WriteLine("handler method not found");
    return;
}

var body = ctx.OpcodeHandlerMethod.CilMethodBody;
var instructions = body.Instructions;
var handlerStarts = new HashSet<int>(ctx.OpcodeHandlerIndices.Values);

Console.WriteLine($"dispatcher: {ctx.OpcodeHandlerMethod.FullName}");
Console.WriteLine($"handlers: {ctx.OpcodeHandlerIndices.Count}");
Console.WriteLine();

foreach (var vm in requested.Distinct())
{
    if (!ctx.OpcodeHandlerIndices.TryGetValue(vm, out var start))
    {
        Console.WriteLine($"vm 0x{vm:X2}: handler not found");
        Console.WriteLine();
        continue;
    }

    var nextHandlerStart = ctx.OpcodeHandlerIndices.Values
        .Where(index => index > start)
        .DefaultIfEmpty(instructions.Count)
        .Min();

    Console.WriteLine($"==== vm 0x{vm:X2} start={start} next={nextHandlerStart} ====");

    var emitted = 0;
    for (var i = start; i < instructions.Count && emitted < maxLines; i++, emitted++)
    {
        if (i > start && handlerStarts.Contains(i))
        {
            Console.WriteLine($"[stop] reached next handler start at [{i}]");
            break;
        }

        var instruction = instructions[i];
        var operand = instruction.Operand == null ? string.Empty : " " + instruction.Operand;
        Console.WriteLine($"[{i}] {instruction.OpCode.Code}{operand}");

        if (instruction.OpCode == CilOpCodes.Ret)
            break;
    }

    Console.WriteLine();
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
