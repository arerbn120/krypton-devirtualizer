using System;
using System.Collections.Generic;
using System.Linq;
using Krypton.Core;
using Krypton.Core.Architecture;
using Krypton.Core.Disassembly;

namespace Krypton.Pipeline.Stages
{
    public class MethodDisassembling : IStage
    {
        public string Name => nameof(MethodDisassembling);

        public void Run(DevirtualizationCtx Ctx)
        {
            Ctx.VirtualizedMethods = new List<VMMethod>();
            var decoder = Ctx.InstructionDecoder ?? new VmInstructionDecoder();
            var methodLayouts = Ctx.GetMethodLayouts();
            for (var i = 0; i < methodLayouts.Count; i++)
            {
                var method = decoder.DisassembleMethod(Ctx, methodLayouts[i].MethodKey);
                Ctx.VirtualizedMethods.Add(method);

                var instructions = method.MethodBody.Instructions;
                var total = instructions.Count;
                var mapped = instructions.Count(q => q.IsResolved);
                var unknown = total - mapped;
                var parent = method.Parent?.FullName ?? "<unresolved method>";
                Ctx.Options.Logger.Info(
                    $"Method {i + 1}/{methodLayouts.Count}: {parent} | total={total}, mapped={mapped}, unknown={unknown}");

                if (unknown > 0)
                {
                    var topUnknownBytes = instructions
                        .Where(q => !q.IsResolved)
                        .GroupBy(q => q.VmByte)
                        .OrderByDescending(q => q.Count())
                        .Take(12)
                        .Select(q => $"0x{q.Key:X2}={q.Count()}")
                        .ToArray();
                    Ctx.Options.Logger.Warning(
                        $"Unknown VM byte kinds in {parent}: {string.Join(", ", topUnknownBytes)}");
                }

                if (IsEnvironmentEnabled("KRYPTON_LOG_VM_BYTE_HISTOGRAM"))
                {
                    var histogram = instructions
                        .GroupBy(q => q.VmByte)
                        .OrderByDescending(q => q.Count())
                        .Take(16)
                        .Select(q => $"0x{q.Key:X2}={q.Count()}")
                        .ToArray();
                    Ctx.Options.Logger.Info(
                        $"VM byte histogram for {parent}: {string.Join(", ", histogram)}");
                }
            }
        }

        private bool IsEnvironmentEnabled(string variableName)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
                return false;
            return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);
        }
    }
}
