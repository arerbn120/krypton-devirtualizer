using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Services
{
    internal static class DevirtualizationReportService
    {
        public static string WriteReport(
            DevirtualizationCtx ctx,
            Func<VMInstruction, string> instructionFormatter,
            Func<int, IEnumerable<string>> unknownHandlerSnippetProvider)
        {
            if (ctx?.VirtualizedMethods == null || ctx.VirtualizedMethods.Count == 0)
                return null;

            var reportPath = Path.Combine(
                Path.GetDirectoryName(ctx.Options.OutPath)!,
                Path.GetFileNameWithoutExtension(ctx.Options.OutPath) + "-report.txt");

            var sb = new StringBuilder();
            sb.AppendLine("Krypton Disassembly Report");
            sb.AppendLine("=========================");
            sb.AppendLine($"Input: {ctx.Options.FilePath}");
            sb.AppendLine($"Methods: {ctx.VirtualizedMethods.Count}");
            sb.AppendLine();

            foreach (var method in ctx.VirtualizedMethods)
            {
                var resolvedName = method.Parent?.FullName ?? "<unresolved method>";
                var total = method.MethodBody.Instructions.Count;
                var mapped = method.MethodBody.Instructions.Count(i => i.IsResolved);
                var unknownGroups = method.MethodBody.Instructions
                    .Where(i => !i.IsResolved)
                    .GroupBy(i => i.VmByte)
                    .OrderByDescending(g => g.Count())
                    .ThenBy(g => g.Key)
                    .Select(g => $"0x{g.Key:X2}:{g.Count()}");

                sb.AppendLine($"MethodKey: {method.MethodKey}");
                sb.AppendLine($"Parent: {resolvedName}");
                sb.AppendLine($"Locals: {method.MethodBody.Locals.Count} | EH: {method.MethodBody.ExceptionHandlers.Count}");
                if (method.MethodBody.ExceptionHandlers.Count > 0)
                {
                    for (var i = 0; i < method.MethodBody.ExceptionHandlers.Count; i++)
                    {
                        var eh = method.MethodBody.ExceptionHandlers[i];
                        var extra = eh.EHType switch
                        {
                            VMExceptionHandlerType.Catch => $" catch:{eh.CatchType}",
                            VMExceptionHandlerType.Filter => $" filter:{eh.Filter}",
                            _ => string.Empty
                        };
                        sb.AppendLine(
                            $"  EH[{i}] try:[{eh.TryStart},{eh.TryEnd}] handler:[{eh.HandlerStart},{eh.HandlerEnd}] type:{eh.EHType}{extra}");
                    }
                }
                sb.AppendLine($"Instructions: {total} | Mapped: {mapped} | Unknown: {total - mapped}");
                sb.AppendLine($"Unknown VM bytes: {(total == mapped ? "<none>" : string.Join(", ", unknownGroups))}");
                sb.AppendLine("Used VM bytes (byte -> opcode, operand-type):");
                foreach (var vmByte in method.MethodBody.Instructions.Select(i => i.VmByte).Distinct().OrderBy(i => i))
                {
                    var opcode = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    ctx.TryGetOperandType(vmByte, out var operandType);
                    if (ctx.OpcodeConfidence != null && ctx.OpcodeConfidence.TryGetValue(vmByte, out var confidence))
                    {
                        sb.AppendLine(
                            $"  0x{vmByte:X2} -> {opcode}, operand:{operandType}, conf:{confidence.Confidence:F2}, source:{confidence.Source}");
                    }
                    else
                    {
                        sb.AppendLine($"  0x{vmByte:X2} -> {opcode}, operand:{operandType}");
                    }
                }
                sb.AppendLine("Unknown handler snippets:");
                foreach (var vmByte in method.MethodBody.Instructions
                             .Where(i => !i.IsResolved)
                             .Select(i => i.VmByte)
                             .Distinct()
                             .OrderBy(i => i))
                {
                    sb.AppendLine($"  vm 0x{vmByte:X2}:");
                    foreach (var line in unknownHandlerSnippetProvider(vmByte))
                        sb.AppendLine($"    {line}");
                }
                sb.AppendLine("Instructions:");
                foreach (var instruction in method.MethodBody.Instructions)
                    sb.AppendLine($"  {instructionFormatter(instruction)}");
                sb.AppendLine();
            }

            File.WriteAllText(reportPath, sb.ToString());
            return reportPath;
        }
    }
}
