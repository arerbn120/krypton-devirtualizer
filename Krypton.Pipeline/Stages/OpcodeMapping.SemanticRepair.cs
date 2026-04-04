using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.Architecture;
using Krypton.Core.PatternMatching;
using Krypton.Core.Signatures;

namespace Krypton.Pipeline.Stages
{
    public partial class OpcodeMapping
    {
        private void RetuneRareHighRiskArithmeticMappings(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var frequency = new Dictionary<int, int>();
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (!frequency.TryGetValue(sample.VmByte, out var count))
                        count = 0;
                    frequency[sample.VmByte] = count + 1;
                }
            }

            var unaryCandidates = new[]
            {
                VMOpCode.Not,
                VMOpCode.Neg,
                VMOpCode.Conv_I4,
                VMOpCode.Conv_I8,
                VMOpCode.Conv_U1
            };

            var retuned = 0;
            var maxVmByte = Math.Min(_addressableOpcodeCount, ctx.Parser.Operands.Length);
            for (var vmByte = 0; vmByte < maxVmByte; vmByte++)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (!frequency.TryGetValue(vmByte, out var freq) || freq <= 0 || freq > 4)
                    continue;
                if (ctx.Parser.Operands[vmByte] != 0)
                    continue;

                var mapped = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (!IsBinaryArithmeticOpcode(mapped))
                    continue;

                if (!ctx.OpcodeConfidence.TryGetValue(vmByte, out var info))
                    continue;
                if ((info.Source ?? string.Empty).IndexOf("handler-pattern", StringComparison.OrdinalIgnoreCase) < 0)
                    continue;

                var baselineGlobal = ScoreStackPenalty(ctx, streams, vmByte, mapped);
                var (baselineWindow, _) = ScoreWindowPenalty(ctx, streams, vmByte, mapped, windowRadius: 8);

                var best = mapped;
                var bestGlobal = baselineGlobal;
                var bestWindow = baselineWindow;

                foreach (var candidate in unaryCandidates)
                {
                    if (!IsOperandTypeCompatible(candidate, 0))
                        continue;
                    if (!AreCandidateOperandsValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                        continue;

                    var global = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                    var (window, _) = ScoreWindowPenalty(ctx, streams, vmByte, candidate, windowRadius: 8);

                    var better = global + 6 < bestGlobal ||
                                 (global == bestGlobal && window + 3 < bestWindow);
                    if (!better)
                        continue;

                    best = candidate;
                    bestGlobal = global;
                    bestWindow = window;
                }

                if (best == mapped)
                    continue;

                ApplyMapping(ctx, vmByte, best, 0.66, "rare-stack-retune");
                retuned++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {best} (rare stack retune; freq={freq}, global {baselineGlobal}->{bestGlobal}, window {baselineWindow}->{bestWindow})");
                }
            }

            if (retuned > 0)
                ctx.Options.Logger.Info($"Rare stack retune adjusted {retuned} opcode mapping(s).");
        }

        private bool IsBinaryArithmeticOpcode(VMOpCode opCode)
        {
            return opCode == VMOpCode.Add ||
                   opCode == VMOpCode.Sub ||
                   opCode == VMOpCode.Xor ||
                   opCode == VMOpCode.Shl ||
                   opCode == VMOpCode.Shr;
        }

        private void RetuneSuspiciousUnaryMappingsByBinaryContext(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var frequency = new Dictionary<int, int>();
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (!frequency.TryGetValue(sample.VmByte, out var count))
                        count = 0;
                    frequency[sample.VmByte] = count + 1;
                }
            }

            var binaryCandidates = new[] { VMOpCode.Add, VMOpCode.Sub, VMOpCode.Xor, VMOpCode.Shl, VMOpCode.Shr };
            var suspiciousUnary = new HashSet<VMOpCode>
            {
                VMOpCode.Dup,
                VMOpCode.Pop,
                VMOpCode.Nop,
                VMOpCode.Conv_I4,
                VMOpCode.Conv_I8,
                VMOpCode.Conv_U1,
                VMOpCode.Not,
                VMOpCode.Neg
            };

            var retuned = 0;
            var maxVmByte = Math.Min(_addressableOpcodeCount, ctx.Parser.Operands.Length);
            for (var vmByte = 0; vmByte < maxVmByte; vmByte++)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (!frequency.TryGetValue(vmByte, out var freq) || freq <= 0)
                    continue;
                if (ctx.Parser.Operands[vmByte] != 0)
                    continue;

                var mapped = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (!suspiciousUnary.Contains(mapped))
                    continue;
                if (!IsLikelyBinaryOperationContext(ctx.PatternMatcher, streams, vmByte))
                    continue;

                var baselineGlobal = ScoreStackPenalty(ctx, streams, vmByte, mapped);
                var (baselineWindow, _) = ScoreWindowPenalty(ctx, streams, vmByte, mapped, windowRadius: 8);
                if (baselineGlobal < Math.Max(16, freq * 3))
                    continue;

                var best = mapped;
                var bestGlobal = baselineGlobal;
                var bestWindow = baselineWindow;

                foreach (var candidate in binaryCandidates)
                {
                    if (!IsOperandTypeCompatible(candidate, 0))
                        continue;
                    if (!AreCandidateOperandsValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                        continue;

                    var global = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                    var (window, _) = ScoreWindowPenalty(ctx, streams, vmByte, candidate, windowRadius: 8);
                    var better = global + 8 < bestGlobal ||
                                 (global + 3 <= bestGlobal && window + 6 < bestWindow);
                    if (!better)
                        continue;

                    best = candidate;
                    bestGlobal = global;
                    bestWindow = window;
                }

                if (best == mapped)
                    continue;

                ApplyMapping(ctx, vmByte, best, 0.72, "binary-context-retune");
                retuned++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {best} (binary context retune; freq={freq}, global {baselineGlobal}->{bestGlobal}, window {baselineWindow}->{bestWindow})");
                }
            }

            if (retuned > 0)
                ctx.Options.Logger.Info($"Binary-context retune adjusted {retuned} opcode mapping(s).");
        }
    }
}
