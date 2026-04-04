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
        private void InferDominantUnknownIndexLikeOpcodes(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var stats = CollectUnknownByteContextStats(ctx);
            if (stats.Count == 0)
                return;

            var inferred = 0;
            foreach (var entry in stats
                         .Where(p => p.Value.Total >= _heuristicsProfile.DominantMinimumFrequency)
                         .OrderByDescending(p => p.Value.Total)
                         .Take(_heuristicsProfile.DominantTopLimit))
            {
                var vmByte = entry.Key;
                var stat = entry.Value;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length || ctx.Parser.Operands[vmByte] != 1)
                    continue;

                var candidate = InferIndexLikeOpcodeFromStat(stat);
                if (candidate == VMOpCode.Nop)
                    continue;

                if (!IsOperandTypeCompatible(candidate, ctx.Parser.Operands[vmByte]))
                    continue;
                if (!IsCandidateValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                    continue;

                ApplyMapping(ctx, vmByte, candidate, 0.68, "dominant-index-like");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {candidate} (dominant-byte inference; freq={stat.Total})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Dominant-byte inference mapped {inferred} additional VM opcodes.");
        }

        private void InferUnknownByStackConsistency(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var unknownFrequency = new Dictionary<int, int>();
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte))
                        continue;
                    if (!unknownFrequency.TryGetValue(sample.VmByte, out var count))
                        count = 0;
                    unknownFrequency[sample.VmByte] = count + 1;
                }
            }

            var inferred = 0;
            foreach (var candidateByte in unknownFrequency.OrderByDescending(q => q.Value).Select(q => q.Key))
            {
                if (!unknownFrequency.TryGetValue(candidateByte, out var frequency) || frequency < 3)
                    continue;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(candidateByte))
                    continue;
                if (candidateByte < 0 || candidateByte >= ctx.Parser.Operands.Length)
                    continue;

                var operandType = ctx.Parser.Operands[candidateByte];
                var candidates = BuildCandidatesForUnknownByte(streams, candidateByte, operandType);
                if (candidates.Count == 0)
                    continue;

                var baselinePenalty = ScoreStackPenalty(ctx, streams, candidateByte, null);
                var scored = new List<(VMOpCode opCode, int penalty)>();

                foreach (var candidate in candidates)
                {
                    if (!IsCandidateValidAcrossOccurrences(ctx, streams, candidateByte, candidate))
                        continue;
                    var penalty = ScoreStackPenalty(ctx, streams, candidateByte, candidate);
                    scored.Add((candidate, penalty));
                }

                if (scored.Count == 0)
                    continue;
                scored = scored
                    .OrderBy(s => s.penalty)
                    .ThenBy(s => (int) s.opCode)
                    .ToList();

                var best = scored[0];
                var secondPenalty = scored.Count > 1 ? scored[1].penalty : int.MaxValue;
                var margin = secondPenalty == int.MaxValue ? int.MaxValue : secondPenalty - best.penalty;
                if (margin < 1)
                    continue;

                var bestPenalty = best.penalty;
                var bestOpcode = best.opCode;
                if (bestPenalty >= baselinePenalty - 8)
                    continue;
                if (frequency > 12)
                {
                    var gain = baselinePenalty - bestPenalty;
                    var minimumGain = Math.Max(16, frequency / 4);
                    if (gain < minimumGain)
                        continue;
                }
                if (frequency > 32 && margin < 2)
                    continue;

                var resolvedOpcode = bestOpcode;
                if (resolvedOpcode == VMOpCode.Nop)
                {
                    ApplyMapping(ctx, candidateByte, VMOpCode.Nop, 0.65, "stack-consistency");
                }
                else
                {
                    if (!IsOperandTypeCompatible(resolvedOpcode, operandType))
                        continue;
                    var gain = baselinePenalty - bestPenalty;
                    var confidence = 0.55 + (double) gain / 30.0;
                    ApplyMapping(ctx, candidateByte, resolvedOpcode, confidence, "stack-consistency");
                }

                inferred++;
                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    var gain = baselinePenalty - bestPenalty;
                    ctx.Options.Logger.Info(
                        $"vm 0x{candidateByte:X2} -> {resolvedOpcode} (stack-consistency inference; gain={gain}, margin={(margin == int.MaxValue ? -1 : margin)})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Stack-consistency inference mapped {inferred} additional VM opcodes.");
        }

        private void InferRareUnknownByWindowedStackConsistency(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var unknownFrequency = new Dictionary<int, int>();
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte))
                        continue;
                    if (!unknownFrequency.TryGetValue(sample.VmByte, out var count))
                        count = 0;
                    unknownFrequency[sample.VmByte] = count + 1;
                }
            }

            var inferred = 0;
            foreach (var candidateByte in unknownFrequency.OrderByDescending(q => q.Value).Select(q => q.Key))
            {
                if (!unknownFrequency.TryGetValue(candidateByte, out var frequency))
                    continue;
                if (frequency <= 0 || frequency > 4)
                    continue;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(candidateByte))
                    continue;
                if (candidateByte < 0 || candidateByte >= ctx.Parser.Operands.Length)
                    continue;

                var candidates = BuildCandidatesForUnknownByte(streams, candidateByte, ctx.Parser.Operands[candidateByte]);
                if (candidates.Count == 0)
                    continue;

                var scored = new List<(VMOpCode opCode, int penalty, int covered)>();
                foreach (var candidate in candidates)
                {
                    if (!IsCandidateValidAcrossOccurrences(ctx, streams, candidateByte, candidate))
                        continue;
                    var (penalty, covered) = ScoreWindowPenalty(ctx, streams, candidateByte, candidate, windowRadius: 7);
                    if (covered == 0)
                        continue;
                    scored.Add((candidate, penalty, covered));
                }

                if (scored.Count < 2)
                    continue;

                scored = scored
                    .OrderBy(s => s.penalty)
                    .ThenByDescending(s => s.covered)
                    .ToList();

                var best = scored[0];
                var second = scored[1];
                var margin = second.penalty - best.penalty;
                var branchOnly = scored.All(s => IsBranchOpcode(s.opCode));
                var requiredMargin = branchOnly ? 2 : 3;
                if (best.covered < frequency)
                    continue;
                if (margin < requiredMargin)
                    continue;

                if (best.opCode == VMOpCode.Nop)
                    ApplyMapping(ctx, candidateByte, VMOpCode.Nop, 0.62, "windowed-stack");
                else
                    ApplyMapping(ctx, candidateByte, best.opCode, 0.62 + Math.Min(0.25, margin / 20.0), "windowed-stack");

                inferred++;
                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{candidateByte:X2} -> {best.opCode} (windowed-stack inference; penalty {best.penalty}, margin {margin})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Windowed-stack inference mapped {inferred} additional VM opcodes.");
        }

        private void InferRareUnknownByConsensus(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var unknownFrequency = new Dictionary<int, int>();
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte))
                        continue;
                    if (!unknownFrequency.TryGetValue(sample.VmByte, out var count))
                        count = 0;
                    unknownFrequency[sample.VmByte] = count + 1;
                }
            }

            var inferred = 0;
            foreach (var candidateByte in unknownFrequency.OrderByDescending(q => q.Value).Select(q => q.Key))
            {
                if (!unknownFrequency.TryGetValue(candidateByte, out var frequency))
                    continue;
                if (frequency <= 0 || frequency > 4)
                    continue;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(candidateByte))
                    continue;
                if (candidateByte < 0 || candidateByte >= ctx.Parser.Operands.Length)
                    continue;

                var operandType = ctx.Parser.Operands[candidateByte];
                var candidates = BuildCandidatesForUnknownByte(streams, candidateByte, operandType);
                if (candidates.Count < 2)
                    continue;

                var globalScores = new List<(VMOpCode opCode, int penalty)>();
                var windowScores = new List<(VMOpCode opCode, int penalty, int covered)>();

                foreach (var candidate in candidates)
                {
                    if (!IsOperandTypeCompatible(candidate, operandType))
                        continue;
                    if (!IsCandidateValidAcrossOccurrences(ctx, streams, candidateByte, candidate))
                        continue;
                    var globalPenalty = ScoreStackPenalty(ctx, streams, candidateByte, candidate);
                    globalScores.Add((candidate, globalPenalty));

                    var (windowPenalty, covered) = ScoreWindowPenalty(ctx, streams, candidateByte, candidate, windowRadius: 8);
                    if (covered > 0)
                        windowScores.Add((candidate, windowPenalty, covered));
                }

                if (globalScores.Count < 2 || windowScores.Count < 2)
                    continue;

                var bestGlobal = globalScores.OrderBy(s => s.penalty).ToList();
                var bestWindow = windowScores.OrderBy(s => s.penalty).ThenByDescending(s => s.covered).ToList();

                var globalBest = bestGlobal[0];
                var globalSecond = bestGlobal[1];
                var windowBest = bestWindow[0];
                var windowSecond = bestWindow[1];

                var globalMargin = globalSecond.penalty - globalBest.penalty;
                var windowMargin = windowSecond.penalty - windowBest.penalty;

                if (globalBest.opCode != windowBest.opCode)
                    continue;
                if (globalMargin < 8 || windowMargin < 4)
                    continue;

                if (globalBest.opCode == VMOpCode.Nop)
                    ApplyMapping(ctx, candidateByte, VMOpCode.Nop, 0.70, "rare-consensus");
                else
                    ApplyMapping(
                        ctx,
                        candidateByte,
                        globalBest.opCode,
                        0.72 + Math.Min(0.20, (globalMargin + windowMargin) / 100.0),
                        "rare-consensus");

                inferred++;
                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{candidateByte:X2} -> {globalBest.opCode} (rare-consensus; global={globalBest.penalty}/{globalMargin}, window={windowBest.penalty}/{windowMargin})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Rare-consensus inference mapped {inferred} additional VM opcodes.");
        }

        private void InferSmallUnknownSetByJointStackSearch(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var unknownFrequency = new Dictionary<int, int>();
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte))
                        continue;
                    if (!unknownFrequency.TryGetValue(sample.VmByte, out var count))
                        count = 0;
                    unknownFrequency[sample.VmByte] = count + 1;
                }
            }

            // Keep this fallback intentionally narrow: tiny unknown sets only.
            var unknownBytes = unknownFrequency
                .Where(p => p.Value > 0 && p.Value <= 4)
                .OrderByDescending(p => p.Value)
                .Select(p => p.Key)
                .Take(6)
                .ToList();
            if (unknownBytes.Count == 0)
                return;

            var candidateMap = new Dictionary<int, List<VMOpCode>>();
            var totalCombinations = 1L;
            foreach (var vmByte in unknownBytes)
            {
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                    continue;

                var operandType = ctx.Parser.Operands[vmByte];
                var candidates = BuildCandidatesForUnknownByte(streams, vmByte, operandType);
                if (candidates.Count == 0)
                    continue;

                var trimmed = candidates
                    .Distinct()
                    .Where(candidate => IsOperandTypeCompatible(candidate, operandType))
                    .Where(candidate => IsCandidateValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                    .Select(candidate =>
                    {
                        var globalPenalty = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                        var (windowPenalty, covered) = ScoreWindowPenalty(ctx, streams, vmByte, candidate, windowRadius: 8);
                        var branchBonus = IsBranchOpcode(candidate) ? 1 : 0;
                        return (candidate, globalPenalty, windowPenalty, covered, branchBonus);
                    })
                    .OrderBy(s => s.globalPenalty)
                    .ThenBy(s => s.windowPenalty)
                    .ThenByDescending(s => s.covered)
                    .ThenByDescending(s => s.branchBonus)
                    .Take(4)
                    .Select(s => s.candidate)
                    .ToList();
                if (trimmed.Count < 2)
                    continue;

                candidateMap[vmByte] = trimmed;
                totalCombinations *= trimmed.Count;
                if (totalCombinations > _heuristicsProfile.JointSearchCombinationLimit)
                    return;
            }

            if (candidateMap.Count < 2)
                return;

            var keys = candidateMap.Keys.ToList();
            var baselinePenalty = ScoreStackPenaltyWithSubstitutions(ctx, streams, null);
            var bestPenalty = int.MaxValue;
            var secondBestPenalty = int.MaxValue;
            var bestAssignment = new Dictionary<int, VMOpCode>();
            var scratch = new Dictionary<int, VMOpCode>();

            void Explore(int depth)
            {
                if (depth >= keys.Count)
                {
                    var penalty = ScoreStackPenaltyWithSubstitutions(ctx, streams, scratch);
                    if (penalty < bestPenalty)
                    {
                        secondBestPenalty = bestPenalty;
                        bestPenalty = penalty;
                        bestAssignment = new Dictionary<int, VMOpCode>(scratch);
                    }
                    else if (penalty < secondBestPenalty)
                    {
                        secondBestPenalty = penalty;
                    }

                    return;
                }

                var vmByte = keys[depth];
                if (!candidateMap.TryGetValue(vmByte, out var options) || options.Count == 0)
                {
                    Explore(depth + 1);
                    return;
                }

                foreach (var option in options)
                {
                    scratch[vmByte] = option;
                    Explore(depth + 1);
                }

                scratch.Remove(vmByte);
            }

            Explore(0);

            if (bestAssignment.Count == 0 || bestPenalty == int.MaxValue)
                return;

            var improvement = baselinePenalty - bestPenalty;
            var margin = secondBestPenalty == int.MaxValue ? int.MaxValue : secondBestPenalty - bestPenalty;
            if (improvement < Math.Max(2, bestAssignment.Count))
                return;
            if (margin < Math.Max(1, bestAssignment.Count / 2))
                return;

            var mapped = 0;
            foreach (var kv in bestAssignment)
            {
                if (ctx.PatternMatcher.IsOpCodeValueKnown(kv.Key))
                    continue;
                if (kv.Value == VMOpCode.Nop)
                    ApplyMapping(ctx, kv.Key, VMOpCode.Nop, 0.70, "joint-stack");
                else
                    ApplyMapping(ctx, kv.Key, kv.Value, 0.74, "joint-stack");
                mapped++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{kv.Key:X2} -> {kv.Value} (joint-stack search)");
                }
            }

            if (mapped > 0)
            {
                ctx.Options.Logger.Info(
                    $"Joint-stack search mapped {mapped} VM opcode(s) (improvement {improvement}, margin {margin}).");
            }
        }

        private int ScoreStackPenaltyWithSubstitutions(
            DevirtualizationCtx ctx,
            IReadOnlyList<VmMethodStreamSample> streams,
            IDictionary<int, VMOpCode> substitutions)
        {
            var penalty = 0;
            foreach (var stream in streams)
            {
                var stack = 0;
                foreach (var sample in stream.Instructions)
                {
                    VMOpCode opCode;
                    var isResolved = ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte);
                    if (substitutions != null && substitutions.TryGetValue(sample.VmByte, out var substituted))
                    {
                        opCode = substituted;
                        isResolved = true;
                    }
                    else if (isResolved)
                    {
                        opCode = ctx.PatternMatcher.GetOpCodeValue(sample.VmByte);
                    }
                    else
                    {
                        continue;
                    }

                    if (!TryGetStackEffect(opCode, sample.Operand, ctx.Module, stream.ExpectedReturnStack, out var pop, out var push))
                        continue;

                    if (stack < pop)
                    {
                        penalty += (pop - stack) * 5;
                        stack = 0;
                    }
                    else
                    {
                        stack -= pop;
                    }

                    stack += push;
                    if (stack > _heuristicsProfile.StackPenaltyCapGlobal)
                    {
                        penalty += stack - _heuristicsProfile.StackPenaltyCapGlobal;
                        stack = _heuristicsProfile.StackPenaltyCapGlobal;
                    }
                }

                penalty += Math.Abs(stack - stream.ExpectedReturnStack);
            }

            return penalty;
        }

        private void InferLastResortRareUnknowns(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var aggressiveLastResort = string.Equals(
                Environment.GetEnvironmentVariable("KRYPTON_ENABLE_AGGRESSIVE_LAST_RESORT"),
                "1",
                StringComparison.Ordinal);
            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var unknownFrequency = new Dictionary<int, int>();
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte))
                        continue;
                    if (!unknownFrequency.TryGetValue(sample.VmByte, out var count))
                        count = 0;
                    unknownFrequency[sample.VmByte] = count + 1;
                }
            }

            var inferred = 0;
            foreach (var vmByte in unknownFrequency.OrderByDescending(q => q.Value).Select(q => q.Key))
            {
                if (!unknownFrequency.TryGetValue(vmByte, out var frequency))
                    continue;
                if (frequency <= 0 || frequency > 2)
                    continue;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                    continue;

                var operandType = ctx.Parser.Operands[vmByte];
                var ranked = BuildCandidatesForUnknownByte(streams, vmByte, operandType)
                    .Distinct()
                    .Where(candidate => IsOperandTypeCompatible(candidate, operandType))
                    .Where(candidate => IsCandidateValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                    .Select(candidate =>
                    {
                        var globalPenalty = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                        var (windowPenalty, covered) = ScoreWindowPenalty(ctx, streams, vmByte, candidate, windowRadius: 8);
                        return (candidate, globalPenalty, windowPenalty, covered);
                    })
                    .OrderBy(s => s.globalPenalty)
                    .ThenBy(s => s.windowPenalty)
                    .ThenByDescending(s => s.covered)
                    .Take(6)
                    .ToList();
                if (ranked.Count == 0)
                    continue;

                var best = ranked[0];
                var second = ranked.Count > 1 ? ranked[1] : (best.candidate, best.globalPenalty, best.windowPenalty, best.covered);
                var globalMargin = second.globalPenalty - best.globalPenalty;
                var windowMargin = second.windowPenalty - best.windowPenalty;

                VMOpCode chosen = VMOpCode.Nop;
                var decided = false;

                if (operandType == 1)
                {
                    if (IsLikelyLocalIndexByte(streams, vmByte))
                    {
                        var localCandidate = ranked.FirstOrDefault(s => s.candidate == VMOpCode.Ldloc);
                        if (localCandidate.candidate == VMOpCode.Ldloc &&
                            localCandidate.globalPenalty <= best.globalPenalty + 1 &&
                            localCandidate.windowPenalty <= best.windowPenalty + 1)
                        {
                            chosen = VMOpCode.Ldloc;
                            decided = true;
                        }

                        if (!decided)
                        {
                            var storeLocalCandidate = ranked.FirstOrDefault(s => s.candidate == VMOpCode.Stloc);
                            if (storeLocalCandidate.candidate == VMOpCode.Stloc &&
                                storeLocalCandidate.globalPenalty <= best.globalPenalty + 1 &&
                                storeLocalCandidate.windowPenalty <= best.windowPenalty + 1)
                            {
                                chosen = VMOpCode.Stloc;
                                decided = true;
                            }
                        }
                    }

                    if (!decided && frequency == 1 && best.candidate == VMOpCode.BrLessThan)
                    {
                        // For singleton branch bytes, prefer unary-branch candidates when
                        // local window scoring is clearly better than BrLessThan (pop=2).
                        var unaryBranch = ranked
                            .Where(s => s.candidate == VMOpCode.BrTrue || s.candidate == VMOpCode.BrFalse || s.candidate == VMOpCode.Br)
                            .OrderBy(s => s.windowPenalty)
                            .ThenBy(s => s.globalPenalty)
                            .FirstOrDefault();
                        if (unaryBranch.candidate != VMOpCode.Nop &&
                            unaryBranch.windowPenalty + 1 <= best.windowPenalty)
                        {
                            chosen = unaryBranch.candidate;
                            decided = true;
                        }
                    }

                    if (!decided && IsBranchOpcode(best.candidate) && globalMargin >= 1 && windowMargin >= 1)
                    {
                        chosen = best.candidate;
                        decided = true;
                    }

                    // Singleton operand-1 unknowns tend to be opaque branch glue where
                    // only one structurally valid branch candidate survives validation.
                    if (!decided && frequency == 1 && IsBranchOpcode(best.candidate))
                    {
                        if (ranked.Count == 1 || globalMargin >= 1)
                        {
                            chosen = best.candidate;
                            decided = true;
                        }
                    }

                    if (!aggressiveLastResort &&
                        decided &&
                        IsBranchOpcode(chosen) &&
                        frequency > 1 &&
                        (globalMargin < 2 || windowMargin < 2))
                        decided = false;

                    if (decided && frequency == 1 && chosen == VMOpCode.BrLessThan)
                    {
                        var unaryBranch = ranked
                            .Where(s => s.candidate == VMOpCode.BrTrue || s.candidate == VMOpCode.BrFalse)
                            .OrderBy(s => s.globalPenalty)
                            .ThenBy(s => s.windowPenalty)
                            .FirstOrDefault();
                        if (unaryBranch.candidate != VMOpCode.Nop &&
                            unaryBranch.globalPenalty <= best.globalPenalty + 1 &&
                            unaryBranch.windowPenalty <= best.windowPenalty + 2)
                        {
                            chosen = unaryBranch.candidate;
                        }
                    }

                    if (decided && frequency == 1 && IsBranchOpcode(chosen) && chosen != VMOpCode.Br)
                    {
                        var directBranch = ranked.FirstOrDefault(s => s.candidate == VMOpCode.Br);
                        if (directBranch.candidate == VMOpCode.Br &&
                            directBranch.globalPenalty <= best.globalPenalty + 2 &&
                            directBranch.windowPenalty <= best.windowPenalty + 3)
                        {
                            chosen = VMOpCode.Br;
                        }
                    }

                    if (!decided && frequency == 1 && !IsStrongBranchTargetByte(streams, vmByte))
                    {
                        var tiedBest = ranked
                            .Where(s => s.globalPenalty == best.globalPenalty && s.windowPenalty == best.windowPenalty)
                            .Select(s => s.candidate)
                            .Distinct()
                            .ToList();

                        if (tiedBest.Contains(VMOpCode.Stloc))
                        {
                            chosen = VMOpCode.Stloc;
                            decided = true;
                        }
                        else if (tiedBest.Contains(VMOpCode.Ldloc))
                        {
                            chosen = VMOpCode.Ldloc;
                            decided = true;
                        }
                        else if (tiedBest.Contains(VMOpCode.Ldarg))
                        {
                            chosen = VMOpCode.Ldarg;
                            decided = true;
                        }
                        else if (tiedBest.Contains(VMOpCode.Ldc_I4))
                        {
                            chosen = VMOpCode.Ldc_I4;
                            decided = true;
                        }
                    }
                }
                else if (operandType == 0)
                {
                    if (globalMargin >= 4)
                    {
                        chosen = best.candidate;
                        decided = true;
                    }

                    if (!aggressiveLastResort && !decided && globalMargin >= 2 && windowMargin >= 2)
                    {
                        chosen = best.candidate;
                        decided = true;
                    }

                    if (aggressiveLastResort && !decided)
                    {
                        var tied = ranked
                            .Where(s => s.globalPenalty == best.globalPenalty && s.windowPenalty == best.windowPenalty)
                            .Select(s => s.candidate)
                            .Where(IsBinaryStackOpcode)
                            .Distinct()
                            .ToList();
                        if (tied.Count > 0)
                        {
                            chosen = PickMostFrequentResolvedOpcode(ctx.PatternMatcher, streams, tied);
                            if (chosen != VMOpCode.Nop)
                                decided = true;
                        }
                    }
                }

                if (!decided)
                    continue;

                if (chosen == VMOpCode.Nop)
                    ApplyMapping(ctx, vmByte, VMOpCode.Nop, 0.55, "last-resort");
                else
                    ApplyMapping(ctx, vmByte, chosen, 0.58, "last-resort");

                inferred++;
                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {chosen} (last-resort rare inference; g/w margin={globalMargin}/{windowMargin})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Last-resort rare inference mapped {inferred} additional VM opcodes.");
        }

        private bool IsLikelyLocalIndexByte(IReadOnlyList<VmMethodStreamSample> streams, int vmByte)
        {
            var seen = 0;
            var localLike = 0;

            foreach (var stream in streams)
            {
                for (var i = 0; i < stream.Instructions.Count; i++)
                {
                    var sample = stream.Instructions[i];
                    if (sample.VmByte != vmByte)
                        continue;
                    if (!(sample.Operand is int index))
                        return false;

                    seen++;
                    if (index >= 0 && index < stream.LocalCount)
                        localLike++;
                }
            }

            return seen > 0 && localLike * 2 >= seen;
        }

        private bool IsLikelyBinaryOperationContext(
            PatternMatcher matcher,
            IReadOnlyList<VmMethodStreamSample> streams,
            int vmByte)
        {
            var seen = 0;
            var binaryLike = 0;

            foreach (var stream in streams)
            {
                for (var i = 0; i < stream.Instructions.Count; i++)
                {
                    var sample = stream.Instructions[i];
                    if (sample.VmByte != vmByte)
                        continue;

                    seen++;
                    var prev1 = FindNeighborKnownOpcodeInStream(matcher, stream.Instructions, i - 1, -1);
                    var prev2 = FindNeighborKnownOpcodeInStream(matcher, stream.Instructions, i - 2, -1);

                    if (IsLikelyPushOpcode(prev1) &&
                        IsLikelyPushOpcode(prev2))
                    {
                        binaryLike++;
                    }
                }
            }

            return seen > 0 && binaryLike * 2 >= seen;
        }

        private bool IsLikelyPushOpcode(VMOpCode opcode)
        {
            switch (opcode)
            {
                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldfld:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldelema:
                case VMOpCode.Ldobj:
                case VMOpCode.Dup:
                case VMOpCode.Newarr:
                case VMOpCode.Newobj:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                    return true;
                default:
                    return false;
            }
        }

        private bool IsBinaryStackOpcode(VMOpCode opcode)
        {
            return opcode == VMOpCode.Add ||
                   opcode == VMOpCode.Sub ||
                   opcode == VMOpCode.Xor ||
                   opcode == VMOpCode.Shl ||
                   opcode == VMOpCode.Shr;
        }

        private VMOpCode PickMostFrequentResolvedOpcode(
            PatternMatcher matcher,
            IReadOnlyList<VmMethodStreamSample> streams,
            IReadOnlyCollection<VMOpCode> candidates)
        {
            if (candidates == null || candidates.Count == 0)
                return VMOpCode.Nop;

            var counts = new Dictionary<VMOpCode, int>();
            foreach (var candidate in candidates)
                counts[candidate] = 0;

            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (!matcher.IsOpCodeValueKnown(sample.VmByte))
                        continue;
                    var opcode = matcher.GetOpCodeValue(sample.VmByte);
                    if (!counts.TryGetValue(opcode, out var count))
                        continue;
                    counts[opcode] = count + 1;
                }
            }

            return counts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => (int) kv.Key)
                .Select(kv => kv.Key)
                .FirstOrDefault();
        }

        private (int penalty, int covered) ScoreWindowPenalty(
            DevirtualizationCtx ctx,
            IReadOnlyList<VmMethodStreamSample> streams,
            int targetVmByte,
            VMOpCode candidate,
            int windowRadius)
        {
            var totalPenalty = 0;
            var covered = 0;

            foreach (var stream in streams)
            {
                for (var i = 0; i < stream.Instructions.Count; i++)
                {
                    if (stream.Instructions[i].VmByte != targetVmByte)
                        continue;

                    covered++;
                    var start = Math.Max(0, i - windowRadius);
                    var end = Math.Min(stream.Instructions.Count - 1, i + windowRadius);
                    var stack = 0;

                    for (var j = start; j <= end; j++)
                    {
                        var sample = stream.Instructions[j];
                        VMOpCode opCode;
                        var resolved = ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte);
                        if (sample.VmByte == targetVmByte)
                        {
                            opCode = candidate;
                            resolved = true;
                        }
                        else if (resolved)
                        {
                            opCode = ctx.PatternMatcher.GetOpCodeValue(sample.VmByte);
                        }
                        else
                        {
                            continue;
                        }

                        if (!TryGetStackEffect(opCode, sample.Operand, ctx.Module, stream.ExpectedReturnStack, out var pop, out var push))
                            continue;

                        if (stack < pop)
                        {
                            totalPenalty += (pop - stack) * 4;
                            stack = 0;
                        }
                        else
                        {
                            stack -= pop;
                        }

                        stack += push;
                        if (stack > _heuristicsProfile.StackPenaltyCapWindow)
                        {
                            totalPenalty += stack - _heuristicsProfile.StackPenaltyCapWindow;
                            stack = _heuristicsProfile.StackPenaltyCapWindow;
                        }
                    }

                    totalPenalty += Math.Abs(stack);
                }
            }

            return (totalPenalty, covered);
        }

        private List<VMOpCode> GetStackConsistencyCandidates(byte operandType)
        {
            switch (operandType)
            {
                case 0:
                    return new List<VMOpCode>
                    {
                        VMOpCode.Nop,
                        VMOpCode.Pop,
                        VMOpCode.Dup,
                        VMOpCode.Conv_I4,
                        VMOpCode.Conv_I8,
                        VMOpCode.Conv_U1,
                        VMOpCode.Not,
                        VMOpCode.Neg,
                        VMOpCode.Add,
                        VMOpCode.Sub,
                        VMOpCode.Xor,
                        VMOpCode.Shl,
                        VMOpCode.Shr
                    };
                case 1:
                {
                    var result = new List<VMOpCode>
                    {
                        VMOpCode.Ldloc,
                        VMOpCode.Ldarg,
                        VMOpCode.Ldc_I4,
                        VMOpCode.Stloc,
                        VMOpCode.Br,
                        VMOpCode.BrTrue,
                        VMOpCode.BrFalse,
                        VMOpCode.BrLessThan,
                        VMOpCode.Ldfld,
                        VMOpCode.Ldsfld,
                        VMOpCode.Stfld,
                        VMOpCode.Stsfld,
                        VMOpCode.Call,
                        VMOpCode.Callvirt,
                        VMOpCode.Newobj,
                        VMOpCode.Newarr,
                        VMOpCode.Unbox_Any,
                        VMOpCode.Ldelem_Ref,
                        VMOpCode.Ldelem_U1,
                        VMOpCode.Stelem_Ref,
                        VMOpCode.Stelem_I1,
                        VMOpCode.Ldobj,
                        VMOpCode.Stobj,
                        VMOpCode.Ldelema
                    };
                    if (_heuristicsProfile.AllowOperandType1PopInference)
                        result.Add(VMOpCode.Pop);
                    return result;
                }
                case 5:
                    return new List<VMOpCode> { VMOpCode.Switch };
                default:
                    return new List<VMOpCode>();
            }
        }

        private List<VMOpCode> GetRareConsensusCandidates(byte operandType)
        {
            switch (operandType)
            {
                case 0:
                    return new List<VMOpCode>
                    {
                        VMOpCode.Nop,
                        VMOpCode.Pop,
                        VMOpCode.Dup,
                        VMOpCode.Conv_I4,
                        VMOpCode.Conv_I8,
                        VMOpCode.Conv_U1,
                        VMOpCode.Not,
                        VMOpCode.Neg,
                        VMOpCode.Add,
                        VMOpCode.Sub,
                        VMOpCode.Xor,
                        VMOpCode.Shl,
                        VMOpCode.Shr
                    };
                case 1:
                {
                    var result = new List<VMOpCode>
                    {
                        VMOpCode.Ldloc,
                        VMOpCode.Ldarg,
                        VMOpCode.Ldc_I4,
                        VMOpCode.Stloc,
                        VMOpCode.Br,
                        VMOpCode.BrTrue,
                        VMOpCode.BrFalse,
                        VMOpCode.BrLessThan,
                        VMOpCode.Ldfld,
                        VMOpCode.Ldsfld,
                        VMOpCode.Stfld,
                        VMOpCode.Stsfld,
                        VMOpCode.Call,
                        VMOpCode.Callvirt,
                        VMOpCode.Newobj,
                        VMOpCode.Newarr,
                        VMOpCode.Unbox_Any,
                        VMOpCode.Ldelem_Ref,
                        VMOpCode.Ldelem_U1,
                        VMOpCode.Stelem_Ref,
                        VMOpCode.Stelem_I1,
                        VMOpCode.Ldobj,
                        VMOpCode.Stobj,
                        VMOpCode.Ldelema
                    };
                    if (_heuristicsProfile.AllowOperandType1PopInference)
                        result.Add(VMOpCode.Pop);
                    return result;
                }
                case 5:
                    return new List<VMOpCode> { VMOpCode.Switch };
                default:
                    return new List<VMOpCode>();
            }
        }

        private List<VMOpCode> BuildCandidatesForUnknownByte(
            IReadOnlyList<VmMethodStreamSample> streams,
            int vmByte,
            byte operandType)
        {
            var candidates = GetRareConsensusCandidates(operandType);
            if (candidates.Count == 0)
                candidates = GetStackConsistencyCandidates(operandType);
            if (candidates.Count == 0)
                return candidates;

            // Strong branch-shape bytes (target-like operands, never local/arg-like)
            // are better resolved against branch candidates only.
            if (operandType == 1 && IsStrongBranchTargetByte(streams, vmByte))
                return new List<VMOpCode> { VMOpCode.Br, VMOpCode.BrTrue, VMOpCode.BrFalse, VMOpCode.BrLessThan };

            return candidates;
        }

        private bool IsStrongBranchTargetByte(IReadOnlyList<VmMethodStreamSample> streams, int vmByte)
        {
            var seen = 0;
            var branchLike = 0;
            foreach (var stream in streams)
            {
                for (var i = 0; i < stream.Instructions.Count; i++)
                {
                    var sample = stream.Instructions[i];
                    if (sample.VmByte != vmByte)
                        continue;
                    if (!(sample.Operand is int target))
                        return false;
                    if (target < 0 || target >= stream.Instructions.Count)
                        return false;

                    seen++;
                    if (target >= stream.LocalCount && target >= stream.ArgCount)
                        branchLike++;
                }
            }

            return seen > 0 && (branchLike * 2 >= seen);
        }

        private bool IsBranchOpcode(VMOpCode opCode)
        {
            return opCode == VMOpCode.Br ||
                   opCode == VMOpCode.BrTrue ||
                   opCode == VMOpCode.BrFalse ||
                   opCode == VMOpCode.BrLessThan;
        }

        private int CountVmByteOccurrences(IReadOnlyList<VmMethodStreamSample> streams, int vmByte)
        {
            var count = 0;
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (sample.VmByte == vmByte)
                        count++;
                }
            }

            return count;
        }

        private int ScoreStackPenalty(
            DevirtualizationCtx ctx,
            IReadOnlyList<VmMethodStreamSample> streams,
            int targetVmByte,
            VMOpCode? substituteOpcode)
        {
            var penalty = 0;
            foreach (var stream in streams)
            {
                var stack = 0;
                foreach (var sample in stream.Instructions)
                {
                    VMOpCode opCode;
                    var isResolved = ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte);
                    if (sample.VmByte == targetVmByte && substituteOpcode.HasValue)
                    {
                        opCode = substituteOpcode.Value;
                        isResolved = true;
                    }
                    else if (isResolved)
                    {
                        opCode = ctx.PatternMatcher.GetOpCodeValue(sample.VmByte);
                    }
                    else
                    {
                        continue;
                    }

                    if (!TryGetStackEffect(opCode, sample.Operand, ctx.Module, stream.ExpectedReturnStack, out var pop, out var push))
                        continue;

                    if (stack < pop)
                    {
                        penalty += (pop - stack) * 6;
                        stack = 0;
                    }
                    else
                    {
                        stack -= pop;
                    }

                    stack += push;
                    if (stack > _heuristicsProfile.StackPenaltyCapGlobal)
                    {
                        penalty += stack - _heuristicsProfile.StackPenaltyCapGlobal;
                        stack = _heuristicsProfile.StackPenaltyCapGlobal;
                    }
                }

                penalty += Math.Abs(stack - stream.ExpectedReturnStack);
            }

            return penalty;
        }

        private bool TryGetStackEffect(
            VMOpCode opCode,
            object operand,
            ModuleDefinition module,
            int expectedReturnStack,
            out int pop,
            out int push)
        {
            pop = 0;
            push = 0;

            switch (opCode)
            {
                case VMOpCode.Nop:
                    return true;
                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldsfld:
                case VMOpCode.Newobj:
                    push = 1;
                    return true;
                case VMOpCode.Ldfld:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldobj:
                case VMOpCode.Unbox_Any:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldelema:
                    pop = 2;
                    push = 1;
                    return true;
                case VMOpCode.Newarr:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.Stloc:
                case VMOpCode.Pop:
                    pop = 1;
                    return true;
                case VMOpCode.Dup:
                    pop = 1;
                    push = 2;
                    return true;
                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                    pop = 2;
                    push = 1;
                    return true;
                case VMOpCode.Neg:
                case VMOpCode.Not:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.Br:
                    return true;
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                    pop = 1;
                    return true;
                case VMOpCode.BrLessThan:
                    pop = 2;
                    return true;
                case VMOpCode.Switch:
                    pop = 1;
                    return true;
                case VMOpCode.Stsfld:
                    pop = 1;
                    return true;
                case VMOpCode.Stfld:
                    pop = 2;
                    return true;
                case VMOpCode.Stobj:
                    pop = 2;
                    return true;
                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                    pop = 3;
                    return true;
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                {
                    if (!(operand is int token))
                        return false;
                    IMethodDescriptor descriptor;
                    try
                    {
                        descriptor = module.LookupMember(token) as IMethodDescriptor;
                    }
                    catch
                    {
                        return false;
                    }

                    var sig = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                    if (sig == null)
                        return false;
                    pop = sig.ParameterTypes.Count + ((opCode == VMOpCode.Callvirt || sig.HasThis) ? 1 : 0);
                    push = string.Equals(sig.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) ? 0 : 1;
                    return true;
                }
                case VMOpCode.Ret:
                    pop = expectedReturnStack;
                    return true;
                default:
                    return false;
            }
        }

        private void InferRareOperand1BranchesByTargetAndNeighbors(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var branchOpCodes = new[] { VMOpCode.Br, VMOpCode.BrTrue, VMOpCode.BrFalse, VMOpCode.BrLessThan };
            var exactVotes = new Dictionary<BranchContextKey, Dictionary<VMOpCode, int>>();
            var sourceVotes = new Dictionary<SourceNeighborKey, Dictionary<VMOpCode, int>>();
            var targetVotes = new Dictionary<TargetNeighborKey, Dictionary<VMOpCode, int>>();
            var deltaVotes = new Dictionary<BranchDeltaBucket, Dictionary<VMOpCode, int>>();
            var unknownFrequency = new Dictionary<int, int>();

            foreach (var stream in streams)
            {
                for (var i = 0; i < stream.Instructions.Count; i++)
                {
                    var sample = stream.Instructions[i];
                    if (sample.VmByte < 0 || sample.VmByte >= ctx.Parser.Operands.Length)
                        continue;

                    if (!ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte))
                    {
                        if (ctx.Parser.Operands[sample.VmByte] == 1)
                        {
                            if (!unknownFrequency.TryGetValue(sample.VmByte, out var count))
                                count = 0;
                            unknownFrequency[sample.VmByte] = count + 1;
                        }

                        continue;
                    }

                    var opcode = ctx.PatternMatcher.GetOpCodeValue(sample.VmByte);
                    if (!branchOpCodes.Contains(opcode))
                        continue;
                    if (!(sample.Operand is int target))
                        continue;
                    if (target < 0 || target >= stream.Instructions.Count)
                        continue;

                    var sourcePrev = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, i - 1, -1);
                    var sourceNext = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, i + 1, +1);
                    var targetPrev = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, target - 1, -1);
                    var targetNext = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, target + 1, +1);
                    var deltaBucket = GetBranchDeltaBucket(target - i);

                    AddVote(exactVotes, new BranchContextKey(sourcePrev, sourceNext, targetPrev, targetNext, deltaBucket), opcode);
                    AddVote(sourceVotes, new SourceNeighborKey(sourcePrev, sourceNext), opcode);
                    AddVote(targetVotes, new TargetNeighborKey(targetPrev, targetNext), opcode);
                    AddVote(deltaVotes, deltaBucket, opcode);
                }
            }

            if (exactVotes.Count == 0 || unknownFrequency.Count == 0)
                return;

            var inferred = 0;
            foreach (var vmByte in unknownFrequency.OrderByDescending(q => q.Value).Select(q => q.Key))
            {
                if (!unknownFrequency.TryGetValue(vmByte, out var freq))
                    continue;
                if (freq <= 0 || freq > 256)
                    continue;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length || ctx.Parser.Operands[vmByte] != 1)
                    continue;

                var candidateScores = new Dictionary<VMOpCode, int>();
                var covered = 0;

                foreach (var stream in streams)
                {
                    for (var i = 0; i < stream.Instructions.Count; i++)
                    {
                        var sample = stream.Instructions[i];
                        if (sample.VmByte != vmByte || !(sample.Operand is int target))
                            continue;
                        if (target < 0 || target >= stream.Instructions.Count)
                            continue;

                        covered++;
                        var sourcePrev = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, i - 1, -1);
                        var sourceNext = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, i + 1, +1);
                        var targetPrev = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, target - 1, -1);
                        var targetNext = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, target + 1, +1);
                        var deltaBucket = GetBranchDeltaBucket(target - i);

                        var exactKey = new BranchContextKey(sourcePrev, sourceNext, targetPrev, targetNext, deltaBucket);
                        if (exactVotes.TryGetValue(exactKey, out var ev))
                        {
                            foreach (var vote in ev)
                                AddWeightedScore(candidateScores, vote.Key, vote.Value * 5);
                        }

                        var sourceKey = new SourceNeighborKey(sourcePrev, sourceNext);
                        if (sourceVotes.TryGetValue(sourceKey, out var sv))
                        {
                            foreach (var vote in sv)
                                AddWeightedScore(candidateScores, vote.Key, vote.Value * 2);
                        }

                        var targetKey = new TargetNeighborKey(targetPrev, targetNext);
                        if (targetVotes.TryGetValue(targetKey, out var tv))
                        {
                            foreach (var vote in tv)
                                AddWeightedScore(candidateScores, vote.Key, vote.Value * 2);
                        }

                        if (deltaVotes.TryGetValue(deltaBucket, out var dv))
                        {
                            foreach (var vote in dv)
                                AddWeightedScore(candidateScores, vote.Key, vote.Value);
                        }
                    }
                }

                if (covered < freq || candidateScores.Count < 2)
                    continue;

                var ordered = candidateScores.OrderByDescending(q => q.Value).ToList();
                var best = ordered[0];
                var second = ordered[1];
                var margin = best.Value - second.Value;
                var confidence = best.Value / (double) ordered.Sum(q => q.Value);

                if (!branchOpCodes.Contains(best.Key))
                    continue;
                if (!IsOperandTypeCompatible(best.Key, ctx.Parser.Operands[vmByte]))
                    continue;

                // Cross-check branch votes with stack-based scoring to avoid
                // picking context winners that break local/global stack shape.
                var branchStackScores = new List<(VMOpCode opCode, int global, int window, int windowCovered)>();
                foreach (var candidate in branchOpCodes)
                {
                    if (!IsOperandTypeCompatible(candidate, ctx.Parser.Operands[vmByte]))
                        continue;
                    if (!IsCandidateValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                        continue;

                    var globalPenalty = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                    var (windowPenalty, windowCovered) = ScoreWindowPenalty(ctx, streams, vmByte, candidate, windowRadius: 8);
                    if (windowCovered < freq)
                        continue;

                    branchStackScores.Add((candidate, globalPenalty, windowPenalty, windowCovered));
                }

                if (branchStackScores.Count < 2)
                    continue;

                var byGlobal = branchStackScores.OrderBy(s => s.global).ToList();
                var byWindow = branchStackScores.OrderBy(s => s.window).ToList();
                var bestGlobal = byGlobal[0];
                var secondGlobal = byGlobal[1];
                var bestWindow = byWindow[0];
                var secondWindow = byWindow[1];
                var globalMargin = secondGlobal.global - bestGlobal.global;
                var windowMargin = secondWindow.window - bestWindow.window;

                if (best.Key != bestGlobal.opCode || best.Key != bestWindow.opCode)
                    continue;
                if (globalMargin < 1 || windowMargin < 1)
                    continue;
                if (best.Value < _heuristicsProfile.BranchVoteMinimum ||
                    margin < _heuristicsProfile.BranchMarginMinimum ||
                    confidence < _heuristicsProfile.BranchConfidenceMinimum)
                    continue;

                ApplyMapping(ctx, vmByte, best.Key, confidence, "branch-neighbor");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {best.Key} (branch-context inference; score={best.Value}, margin={margin}, conf={confidence:F2}, stack g/w margin={globalMargin}/{windowMargin})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Branch-context inference mapped {inferred} additional VM opcodes.");
        }

        private void InferReactorVersionAwareDispatcherBranches(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var unknownFrequency = new Dictionary<int, int>();
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (sample.VmByte < 0 || sample.VmByte >= ctx.Parser.Operands.Length)
                        continue;
                    if (ctx.Parser.Operands[sample.VmByte] != 1)
                        continue;
                    if (ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte))
                        continue;

                    if (!unknownFrequency.TryGetValue(sample.VmByte, out var count))
                        count = 0;
                    unknownFrequency[sample.VmByte] = count + 1;
                }
            }

            if (unknownFrequency.Count == 0)
                return;

            var mapped = 0;
            foreach (var vmByte in unknownFrequency.OrderByDescending(q => q.Value).Select(q => q.Key))
            {
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;

                if (!TryCollectDispatcherLoopBranchStats(ctx, streams, vmByte, out var stats))
                    continue;

                var isGuardedConditional = stats.GuardedConditionalRate >= 0.30 && stats.NonLoopTargetCount > 0;
                var candidate = isGuardedConditional ? VMOpCode.BrFalse : VMOpCode.Br;
                if (!AreCandidateOperandsValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                    continue;

                var confidence = 0.62 +
                                 Math.Min(0.18, stats.DominantTargetRate * 0.18) +
                                 Math.Min(0.12, stats.LoopTargetRate * 0.12) +
                                 (isGuardedConditional ? 0.04 : 0.0);
                confidence = Math.Max(0.50, Math.Min(0.90, confidence));

                ApplyMapping(ctx, vmByte, candidate, confidence, "reactor-dispatcher-aware");
                mapped++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {candidate} (reactor dispatcher inference; occ={stats.Occurrences}, dominant={stats.DominantTarget}:{stats.DominantTargetRate:F2}, loop={stats.LoopTargetRate:F2}, guarded={stats.GuardedConditionalRate:F2})");
                }
            }

            if (mapped > 0)
            {
                ctx.Options.Logger.Info(
                    $"Reactor dispatcher inference mapped {mapped} additional VM opcode(s).");
            }
        }

        private bool TryCollectDispatcherLoopBranchStats(
            DevirtualizationCtx ctx,
            IReadOnlyList<VmMethodStreamSample> streams,
            int vmByte,
            out DispatcherLoopBranchStats stats)
        {
            stats = null;
            if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length || ctx.Parser.Operands[vmByte] != 1)
                return false;

            var targetCounts = new Dictionary<int, int>();
            var candidate = new DispatcherLoopBranchStats();

            foreach (var stream in streams)
            {
                for (var i = 0; i < stream.Instructions.Count; i++)
                {
                    var sample = stream.Instructions[i];
                    if (sample.VmByte != vmByte)
                        continue;
                    if (!(sample.Operand is int target))
                        return false;
                    if (target < 0 || target >= stream.Instructions.Count)
                        return false;

                    candidate.Occurrences++;
                    if (!targetCounts.TryGetValue(target, out var count))
                        count = 0;
                    targetCounts[target] = count + 1;

                    if (LooksLikeDispatcherLoopTarget(stream, target))
                        candidate.LoopTargetCount++;
                    else
                        candidate.NonLoopTargetCount++;

                    if (target >= Math.Max(stream.LocalCount, stream.ArgCount) + 16)
                        candidate.OutlierTargetCount++;

                    var prevKnown = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, i - 1, -1);
                    var nextKnown = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, i + 1, +1);
                    if (IsCallLikeOpcode(prevKnown) && nextKnown == VMOpCode.Pop)
                        candidate.GuardedConditionalCount++;
                }
            }

            if (candidate.Occurrences < 16 || targetCounts.Count == 0)
                return false;

            var dominant = targetCounts.OrderByDescending(q => q.Value).First();
            candidate.DominantTarget = dominant.Key;
            candidate.DominantTargetCount = dominant.Value;

            if (candidate.DominantTarget > 8)
                return false;
            if (targetCounts.Count > 8)
                return false;
            if (candidate.OutlierTargetCount == 0)
                return false;
            if (candidate.DominantTargetRate < 0.70)
                return false;
            if (candidate.LoopTargetRate < 0.75)
                return false;

            stats = candidate;
            return true;
        }

        private bool LooksLikeDispatcherLoopTarget(VmMethodStreamSample stream, int target)
        {
            if (stream?.Instructions == null || target < 0 || target >= stream.Instructions.Count)
                return false;

            for (var i = target; i < stream.Instructions.Count && i <= target + 2; i++)
            {
                if (stream.Instructions[i].Operand is int[] targets && targets.Length > 0)
                    return true;
            }

            return false;
        }

        private bool IsCallLikeOpcode(VMOpCode opCode)
        {
            return opCode == VMOpCode.Call || opCode == VMOpCode.Callvirt;
        }

        private static void AddVote<TKey>(
            IDictionary<TKey, Dictionary<VMOpCode, int>> table,
            TKey key,
            VMOpCode opCode)
        {
            if (!table.TryGetValue(key, out var votes))
            {
                votes = new Dictionary<VMOpCode, int>();
                table[key] = votes;
            }

            if (!votes.TryGetValue(opCode, out var count))
                count = 0;
            votes[opCode] = count + 1;
        }

        private static void AddWeightedScore(IDictionary<VMOpCode, int> scores, VMOpCode opCode, int add)
        {
            if (add <= 0)
                return;
            if (!scores.TryGetValue(opCode, out var value))
                value = 0;
            scores[opCode] = value + add;
        }

        private VMOpCode FindNeighborKnownOpcodeInStream(
            PatternMatcher matcher,
            IReadOnlyList<VmInstructionSample> entries,
            int start,
            int direction)
        {
            for (var i = start; i >= 0 && i < entries.Count; i += direction)
            {
                var vm = entries[i].VmByte;
                if (!matcher.IsOpCodeValueKnown(vm))
                    continue;

                var opcode = matcher.GetOpCodeValue(vm);
                if (opcode != VMOpCode.Nop)
                    return opcode;
            }

            return VMOpCode.Nop;
        }

        private BranchDeltaBucket GetBranchDeltaBucket(int delta)
        {
            if (delta < -_heuristicsProfile.BranchDeltaBucketBoundary)
                return BranchDeltaBucket.BackwardFar;
            if (delta < -8)
                return BranchDeltaBucket.BackwardMedium;
            if (delta < 0)
                return BranchDeltaBucket.BackwardNear;
            if (delta == 0)
                return BranchDeltaBucket.Self;
            if (delta <= 8)
                return BranchDeltaBucket.ForwardNear;
            if (delta <= _heuristicsProfile.BranchDeltaBucketBoundary)
                return BranchDeltaBucket.ForwardMedium;
            return BranchDeltaBucket.ForwardFar;
        }

        private Dictionary<int, UnknownByteContextStat> CollectUnknownByteContextStats(DevirtualizationCtx ctx)
        {
            var parser = ctx.Parser;
            var stream = parser.Reader.BaseStream;
            var originalPosition = stream.Position;
            var result = new Dictionary<int, UnknownByteContextStat>();

            try
            {
                foreach (var methodKey in parser.MethodKeys)
                {
                    stream.Position = methodKey;
                    var parentToken = parser.ReadEncryptedByte();
                    var locals = parser.ReadEncryptedByte();
                    var exceptionHandlers = parser.ReadEncryptedByte();
                    var instructionCount = parser.ReadEncryptedByte();

                    for (var i = 0; i < locals; i++)
                        parser.ReadEncryptedByte();
                    for (var i = 0; i < exceptionHandlers; i++)
                        new VMExceptionHandler().Read(ctx.Module, parser);

                    var argCount = ResolveArgCount(ctx.Module, parentToken);
                    var entries = new List<(int vmByte, int operand)>(instructionCount);
                    for (var i = 0; i < instructionCount; i++)
                    {
                        var vmByte = parser.Reader.ReadByte();
                        var operand = int.MinValue;
                        if (vmByte >= 0 && vmByte < parser.Operands.Length)
                        {
                            if (parser.Operands[vmByte] == 1)
                                operand = parser.ReadEncryptedByte();
                            else
                                SkipOperand(parser, parser.Operands[vmByte]);
                        }

                        entries.Add((vmByte, operand));
                    }

                    for (var i = 0; i < entries.Count; i++)
                    {
                        var vmByte = entries[i].vmByte;
                        if (vmByte < 0 || vmByte >= parser.Operands.Length || parser.Operands[vmByte] != 1)
                            continue;
                        if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                            continue;

                        var stat = GetOrCreateUnknownByteStat(result, vmByte);
                        stat.Total++;

                        var operand = entries[i].operand;
                        if (operand >= 0 && operand < locals)
                            stat.LocalLike++;
                        if (operand >= 0 && operand < argCount)
                            stat.ArgLike++;
                        if (operand >= -1 && operand <= 16)
                            stat.SmallConstLike++;
                        if (operand >= 0 && operand < entries.Count)
                            stat.BranchLike++;

                        var prevKnown = FindNearestKnownOpcode(ctx.PatternMatcher, entries, i, -1);
                        var nextKnown = FindNearestKnownOpcode(ctx.PatternMatcher, entries, i, +1);
                        if (prevKnown != VMOpCode.Nop && ProducesValue(prevKnown))
                            stat.PrevProducesValue++;
                        if (nextKnown != VMOpCode.Nop && ConsumesValue(nextKnown))
                            stat.NextConsumesValue++;
                    }
                }
            }
            catch
            {
                return new Dictionary<int, UnknownByteContextStat>();
            }
            finally
            {
                stream.Position = originalPosition;
            }

            return result;
        }

        private UnknownByteContextStat GetOrCreateUnknownByteStat(
            IDictionary<int, UnknownByteContextStat> stats,
            int vmByte)
        {
            if (stats.TryGetValue(vmByte, out var existing))
                return existing;
            var created = new UnknownByteContextStat();
            stats[vmByte] = created;
            return created;
        }

        private VMOpCode FindNearestKnownOpcode(
            PatternMatcher matcher,
            IReadOnlyList<(int vmByte, int operand)> entries,
            int start,
            int direction)
        {
            for (var i = start + direction; i >= 0 && i < entries.Count; i += direction)
            {
                var known = matcher.GetOpCodeValue(entries[i].vmByte);
                if (known != VMOpCode.Nop)
                    return known;
            }

            return VMOpCode.Nop;
        }

        private VMOpCode InferIndexLikeOpcodeFromStat(UnknownByteContextStat stat)
        {
            if (stat == null || stat.Total <= 0)
                return VMOpCode.Nop;

            var localRate = (double) stat.LocalLike / stat.Total;
            var argRate = (double) stat.ArgLike / stat.Total;
            var smallConstRate = (double) stat.SmallConstLike / stat.Total;
            var branchRate = (double) stat.BranchLike / stat.Total;
            var prevProducesRate = (double) stat.PrevProducesValue / stat.Total;
            var nextConsumesRate = (double) stat.NextConsumesValue / stat.Total;

            var scoreLdloc = localRate * 3.0 + nextConsumesRate * 2.0 + prevProducesRate * 0.4;
            var scoreLdarg = argRate * 2.6 + nextConsumesRate * 1.8;
            var scoreStloc = localRate * 2.8 + prevProducesRate * 2.0 - nextConsumesRate * 0.8;
            var scoreLdc = smallConstRate * 2.4 + nextConsumesRate * 0.8;
            var scoreBr = branchRate * 2.0;

            var best = scoreLdloc;
            var opcode = VMOpCode.Ldloc;

            if (scoreLdarg > best)
            {
                best = scoreLdarg;
                opcode = VMOpCode.Ldarg;
            }
            if (scoreStloc > best)
            {
                best = scoreStloc;
                opcode = VMOpCode.Stloc;
            }
            if (scoreLdc > best)
            {
                best = scoreLdc;
                opcode = VMOpCode.Ldc_I4;
            }
            if (scoreBr > best)
            {
                best = scoreBr;
                opcode = VMOpCode.Br;
            }

            return best >= _heuristicsProfile.IndexLikeScoreMinimum ? opcode : VMOpCode.Nop;
        }

        private bool ProducesValue(VMOpCode opCode)
        {
            switch (opCode)
            {
                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldfld:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldelema:
                case VMOpCode.Ldobj:
                case VMOpCode.Dup:
                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Neg:
                case VMOpCode.Not:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                case VMOpCode.Newarr:
                case VMOpCode.Newobj:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                    return true;
                default:
                    return false;
            }
        }

        private bool ConsumesValue(VMOpCode opCode)
        {
            switch (opCode)
            {
                case VMOpCode.Pop:
                case VMOpCode.Stloc:
                case VMOpCode.Ldfld:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldobj:
                case VMOpCode.Ldelema:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Stfld:
                case VMOpCode.Stsfld:
                case VMOpCode.Stobj:
                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Ret:
                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                    return true;
                default:
                    return false;
            }
        }

        private sealed class UnknownByteContextStat
        {
            public int Total { get; set; }
            public int LocalLike { get; set; }
            public int ArgLike { get; set; }
            public int SmallConstLike { get; set; }
            public int BranchLike { get; set; }
            public int PrevProducesValue { get; set; }
            public int NextConsumesValue { get; set; }
        }

        private sealed class DispatcherLoopBranchStats
        {
            public int Occurrences { get; set; }
            public int DominantTarget { get; set; }
            public int DominantTargetCount { get; set; }
            public int LoopTargetCount { get; set; }
            public int NonLoopTargetCount { get; set; }
            public int OutlierTargetCount { get; set; }
            public int GuardedConditionalCount { get; set; }

            public double DominantTargetRate =>
                Occurrences <= 0 ? 0.0 : DominantTargetCount / (double) Occurrences;

            public double LoopTargetRate =>
                Occurrences <= 0 ? 0.0 : LoopTargetCount / (double) Occurrences;

            public double GuardedConditionalRate =>
                Occurrences <= 0 ? 0.0 : GuardedConditionalCount / (double) Occurrences;
        }

        private readonly struct NeighborContextKey : IEquatable<NeighborContextKey>
        {
            public NeighborContextKey(VMOpCode prev, VMOpCode next, byte operandType)
            {
                Prev = prev;
                Next = next;
                OperandType = operandType;
            }

            public VMOpCode Prev { get; }
            public VMOpCode Next { get; }
            public byte OperandType { get; }

            public bool Equals(NeighborContextKey other)
            {
                return Prev == other.Prev &&
                       Next == other.Next &&
                       OperandType == other.OperandType;
            }

            public override bool Equals(object obj)
            {
                return obj is NeighborContextKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                unchecked
                {
                    var hash = (int) Prev;
                    hash = (hash * 397) ^ (int) Next;
                    hash = (hash * 397) ^ OperandType;
                    return hash;
                }
            }
        }

        private enum BranchDeltaBucket
        {
            BackwardFar,
            BackwardMedium,
            BackwardNear,
            Self,
            ForwardNear,
            ForwardMedium,
            ForwardFar
        }

        private readonly struct SourceNeighborKey : IEquatable<SourceNeighborKey>
        {
            public SourceNeighborKey(VMOpCode prev, VMOpCode next)
            {
                Prev = prev;
                Next = next;
            }

            public VMOpCode Prev { get; }
            public VMOpCode Next { get; }

            public bool Equals(SourceNeighborKey other)
            {
                return Prev == other.Prev && Next == other.Next;
            }

            public override bool Equals(object obj)
            {
                return obj is SourceNeighborKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                unchecked
                {
                    return ((int) Prev * 397) ^ (int) Next;
                }
            }
        }

        private readonly struct TargetNeighborKey : IEquatable<TargetNeighborKey>
        {
            public TargetNeighborKey(VMOpCode prev, VMOpCode next)
            {
                Prev = prev;
                Next = next;
            }

            public VMOpCode Prev { get; }
            public VMOpCode Next { get; }

            public bool Equals(TargetNeighborKey other)
            {
                return Prev == other.Prev && Next == other.Next;
            }

            public override bool Equals(object obj)
            {
                return obj is TargetNeighborKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                unchecked
                {
                    return ((int) Prev * 397) ^ (int) Next;
                }
            }
        }

        private readonly struct BranchContextKey : IEquatable<BranchContextKey>
        {
            public BranchContextKey(
                VMOpCode sourcePrev,
                VMOpCode sourceNext,
                VMOpCode targetPrev,
                VMOpCode targetNext,
                BranchDeltaBucket deltaBucket)
            {
                SourcePrev = sourcePrev;
                SourceNext = sourceNext;
                TargetPrev = targetPrev;
                TargetNext = targetNext;
                DeltaBucket = deltaBucket;
            }

            public VMOpCode SourcePrev { get; }
            public VMOpCode SourceNext { get; }
            public VMOpCode TargetPrev { get; }
            public VMOpCode TargetNext { get; }
            public BranchDeltaBucket DeltaBucket { get; }

            public bool Equals(BranchContextKey other)
            {
                return SourcePrev == other.SourcePrev &&
                       SourceNext == other.SourceNext &&
                       TargetPrev == other.TargetPrev &&
                       TargetNext == other.TargetNext &&
                       DeltaBucket == other.DeltaBucket;
            }

            public override bool Equals(object obj)
            {
                return obj is BranchContextKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                unchecked
                {
                    var hash = (int) SourcePrev;
                    hash = (hash * 397) ^ (int) SourceNext;
                    hash = (hash * 397) ^ (int) TargetPrev;
                    hash = (hash * 397) ^ (int) TargetNext;
                    hash = (hash * 397) ^ (int) DeltaBucket;
                    return hash;
                }
            }
        }
    }
}
