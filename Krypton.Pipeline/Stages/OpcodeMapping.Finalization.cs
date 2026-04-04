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
        private void InferSingletonOperand0TieAsNoOp(DevirtualizationCtx ctx)
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
            foreach (var pair in unknownFrequency.Where(p => p.Value == 1))
            {
                var vmByte = pair.Key;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                    continue;
                if (ctx.Parser.Operands[vmByte] != 0)
                    continue;

                var scored = BuildCandidatesForUnknownByte(streams, vmByte, operandType: 0)
                    .Distinct()
                    .Where(candidate => IsOperandTypeCompatible(candidate, 0))
                    .Where(candidate => IsCandidateValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                    .Select(candidate => (candidate, penalty: ScoreStackPenalty(ctx, streams, vmByte, candidate)))
                    .OrderBy(s => s.penalty)
                    .ToList();
                if (scored.Count == 0)
                    continue;

                var bestPenalty = scored[0].penalty;
                var tiedBest = scored
                    .Where(s => s.penalty == bestPenalty)
                    .Select(s => s.candidate)
                    .Distinct()
                    .ToList();
                if (tiedBest.Count < 3)
                    continue;

                ApplyMapping(ctx, vmByte, VMOpCode.Nop, 0.42, "singleton-tie-noop");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    var tied = string.Join(", ", tiedBest.Select(o => o.ToString()));
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> Nop (singleton tie fallback; tied={tied})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Singleton tie fallback marked {inferred} additional VM opcode(s) as Nop.");
        }

        private void ApplyEnvironmentOpcodeOverrides(DevirtualizationCtx ctx)
        {
            var raw = Environment.GetEnvironmentVariable("KRYPTON_FORCE_VM_MAP");
            if (string.IsNullOrWhiteSpace(raw) || ctx?.PatternMatcher == null || ctx.Parser?.Operands == null)
                return;

            var entries = raw.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries);
            var applied = 0;
            foreach (var entry in entries)
            {
                var parts = entry.Split(new[] { '=', ':' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 2)
                    continue;

                var byteToken = parts[0].Trim();
                if (byteToken.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    byteToken = byteToken.Substring(2);

                if (!int.TryParse(byteToken, System.Globalization.NumberStyles.HexNumber, null, out var vmByte) &&
                    !int.TryParse(byteToken, out vmByte))
                {
                    continue;
                }

                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                    continue;

                if (!Enum.TryParse<VMOpCode>(parts[1].Trim(), true, out var opcode))
                    continue;
                if (!IsOperandTypeCompatible(opcode, ctx.Parser.Operands[vmByte]))
                    continue;

                ApplyMapping(ctx, vmByte, opcode, 1.0, "env-override");
                applied++;
                ctx.Options.Logger.Warning($"Environment override: vm 0x{vmByte:X2} -> {opcode}.");
            }

            if (applied > 0)
                ctx.Options.Logger.Warning($"Applied {applied} environment opcode override(s).");
        }

        private void InferTailTerminatorRetMappings(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var tailCount = new Dictionary<int, int>();
            var totalCount = new Dictionary<int, int>();

            foreach (var stream in streams)
            {
                if (stream?.Instructions == null || stream.Instructions.Count == 0)
                    continue;

                foreach (var sample in stream.Instructions)
                {
                    if (!totalCount.TryGetValue(sample.VmByte, out var seen))
                        seen = 0;
                    totalCount[sample.VmByte] = seen + 1;
                }

                var tail = stream.Instructions[stream.Instructions.Count - 1];
                if (tail.VmByte < 0 || tail.VmByte >= ctx.Parser.Operands.Length)
                    continue;
                if (ctx.Parser.Operands[tail.VmByte] != 0)
                    continue;

                if (!tailCount.TryGetValue(tail.VmByte, out var count))
                    count = 0;
                tailCount[tail.VmByte] = count + 1;
            }

            var inferred = 0;
            foreach (var pair in tailCount.OrderByDescending(p => p.Value))
            {
                var vmByte = pair.Key;
                var tailHits = pair.Value;
                if (tailHits < 2)
                    continue;
                if (!totalCount.TryGetValue(vmByte, out var totalHits) || totalHits <= 0)
                    continue;
                if (tailHits * 2 < totalHits)
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                    continue;
                if (ctx.Parser.Operands[vmByte] != 0)
                    continue;

                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                {
                    var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    if (current == VMOpCode.Ret || current == VMOpCode.Leave || current == VMOpCode.EndFinally)
                        continue;
                    if (!IsLikelyTailRetMistake(current))
                        continue;
                }

                ApplyMapping(ctx, vmByte, VMOpCode.Ret, 0.74, "tail-terminator");
                inferred++;
                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"), "1", StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> Ret (tail-terminator inference; tail {tailHits}/{totalHits})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Tail-terminator inference mapped {inferred} VM opcode(s) to Ret.");
        }

        private void ResolveRemainingUnknownOpcodesAggressively(DevirtualizationCtx ctx)
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

            if (unknownFrequency.Count == 0)
                return;

            var contextVotes = new Dictionary<NeighborContextKey, Dictionary<VMOpCode, int>>();
            var unknownSamples = new Dictionary<int, List<NeighborContextKey>>();
            ScanVmNeighborContexts(ctx, contextVotes, unknownSamples);

            var inferred = 0;
            foreach (var pair in unknownFrequency.OrderByDescending(p => p.Value))
            {
                var vmByte = pair.Key;
                var frequency = pair.Value;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                    continue;

                var operandType = ctx.Parser.Operands[vmByte];
                var candidateSet = BuildCandidatesForUnknownByte(streams, vmByte, operandType);
                if (candidateSet == null || candidateSet.Count == 0)
                    candidateSet = GetStackConsistencyCandidates(operandType);
                if (candidateSet == null || candidateSet.Count == 0)
                    continue;

                var scored = new List<(VMOpCode opCode, bool strictValid, bool relaxedValid, int contextScore, int heuristicScore, int globalPenalty, int windowPenalty, int covered)>();
                foreach (var candidate in candidateSet.Distinct())
                {
                    if (!IsOperandTypeCompatible(candidate, operandType))
                        continue;

                    var strictValid = IsCandidateValidAcrossOccurrences(ctx, streams, vmByte, candidate);
                    var relaxedValid = strictValid || AreCandidateOperandsValidAcrossOccurrences(ctx, streams, vmByte, candidate);
                    if (!relaxedValid)
                        continue;

                    var globalPenalty = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                    var (windowPenalty, covered) = ScoreWindowPenalty(ctx, streams, vmByte, candidate, windowRadius: 8);
                    var contextScore = GetContextVoteScoreForCandidate(vmByte, candidate, contextVotes, unknownSamples);
                    var heuristicScore = GetResolverHeuristicScore(ctx, streams, vmByte, candidate, operandType);
                    scored.Add((candidate, strictValid, relaxedValid, contextScore, heuristicScore, globalPenalty, windowPenalty, covered));
                }

                if (scored.Count == 0)
                {
                    foreach (var candidate in candidateSet.Distinct())
                    {
                        if (!IsOperandTypeCompatible(candidate, operandType))
                            continue;

                        var globalPenalty = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                        var (windowPenalty, covered) = ScoreWindowPenalty(ctx, streams, vmByte, candidate, windowRadius: 8);
                        var contextScore = GetContextVoteScoreForCandidate(vmByte, candidate, contextVotes, unknownSamples);
                        var heuristicScore = GetResolverHeuristicScore(ctx, streams, vmByte, candidate, operandType);
                        scored.Add((candidate, strictValid: false, relaxedValid: false, contextScore, heuristicScore, globalPenalty, windowPenalty, covered));
                    }
                }

                if (scored.Count == 0)
                    continue;

                scored = scored
                    .OrderByDescending(s => s.strictValid)
                    .ThenByDescending(s => s.relaxedValid)
                    .ThenByDescending(s => s.contextScore)
                    .ThenByDescending(s => s.heuristicScore)
                    .ThenBy(s => s.globalPenalty)
                    .ThenBy(s => s.windowPenalty)
                    .ThenByDescending(s => s.covered)
                    .ThenBy(s => (int) s.opCode)
                    .ToList();

                var best = scored[0];
                (VMOpCode opCode, bool strictValid, bool relaxedValid, int contextScore, int heuristicScore, int globalPenalty, int windowPenalty, int covered)? second =
                    scored.Count > 1 ? scored[1] : ((VMOpCode, bool, bool, int, int, int, int, int)?) null;

                var confidence = ComputeAggressiveResolverConfidence(frequency, best, second);
                ApplyMapping(ctx, vmByte, best.opCode, confidence, "aggressive-unknown-resolver");
                inferred++;

                var top = string.Join(
                    ", ",
                    scored.Take(5).Select(s =>
                        $"{s.opCode} g={s.globalPenalty} w={s.windowPenalty} ctx={s.contextScore} h={s.heuristicScore} strict={(s.strictValid ? 1 : 0)}"));
                ctx.Options.Logger.Info(
                    $"Resolved unknown vm 0x{vmByte:X2} (freq={frequency}, operand={operandType}) -> {best.opCode} | top: {top}");
            }

            if (inferred > 0)
            {
                var remaining = unknownFrequency.Keys.Count(vm => !ctx.PatternMatcher.IsOpCodeValueKnown(vm));
                ctx.Options.Logger.Info(
                    $"Aggressive unknown-byte resolver mapped {inferred} VM opcode(s); remaining unknown byte kinds: {remaining}.");
            }
        }

        private int GetContextVoteScoreForCandidate(
            int vmByte,
            VMOpCode candidate,
            IReadOnlyDictionary<NeighborContextKey, Dictionary<VMOpCode, int>> contextVotes,
            IReadOnlyDictionary<int, List<NeighborContextKey>> unknownSamples)
        {
            if (!unknownSamples.TryGetValue(vmByte, out var samples) || samples == null || samples.Count == 0)
                return 0;

            var score = 0;
            foreach (var key in samples)
            {
                if (!contextVotes.TryGetValue(key, out var votes))
                    continue;
                if (!votes.TryGetValue(candidate, out var voteCount))
                    continue;
                score += voteCount;
            }

            return score;
        }

        private int GetResolverHeuristicScore(
            DevirtualizationCtx ctx,
            IReadOnlyList<VmMethodStreamSample> streams,
            int vmByte,
            VMOpCode candidate,
            byte operandType)
        {
            var score = 0;

            if (operandType == 5 && candidate == VMOpCode.Switch)
            {
                score += IsLikelySwitchByte(streams, vmByte) ? 6 : 2;
            }

            if ((candidate == VMOpCode.Ldloc || candidate == VMOpCode.Stloc) &&
                IsLikelyLocalIndexByte(streams, vmByte))
            {
                score += 5;
            }

            if (candidate == VMOpCode.Ldarg && !IsLikelyLocalIndexByte(streams, vmByte))
                score += 2;

            if (IsBinaryStackOpcode(candidate) &&
                IsLikelyBinaryOperationContext(ctx.PatternMatcher, streams, vmByte))
            {
                score += 4;
            }

            if (IsBranchOpcode(candidate))
            {
                if (IsStrongBranchTargetByte(streams, vmByte))
                    score += 5;
                else if (candidate == VMOpCode.BrTrue || candidate == VMOpCode.BrFalse)
                    score += 2;
                else
                    score += 1;
            }

            if (candidate == VMOpCode.Nop && operandType == 0)
                score -= 1;

            return score;
        }

        private double ComputeAggressiveResolverConfidence(
            int frequency,
            (VMOpCode opCode, bool strictValid, bool relaxedValid, int contextScore, int heuristicScore, int globalPenalty, int windowPenalty, int covered) best,
            (VMOpCode opCode, bool strictValid, bool relaxedValid, int contextScore, int heuristicScore, int globalPenalty, int windowPenalty, int covered)? second)
        {
            var confidence = best.strictValid ? 0.76 : best.relaxedValid ? 0.66 : 0.56;
            confidence += Math.Min(0.10, Math.Log10(Math.Max(1, frequency) + 1.0) * 0.06);

            if (second.HasValue)
            {
                var next = second.Value;
                var globalGap = next.globalPenalty - best.globalPenalty;
                var windowGap = next.windowPenalty - best.windowPenalty;
                var contextGap = best.contextScore - next.contextScore;
                var heuristicGap = best.heuristicScore - next.heuristicScore;

                if (globalGap > 0)
                    confidence += Math.Min(0.08, globalGap / 240.0);
                if (windowGap > 0)
                    confidence += Math.Min(0.06, windowGap / 220.0);
                if (contextGap > 0)
                    confidence += Math.Min(0.05, contextGap * 0.01);
                if (heuristicGap > 0)
                    confidence += Math.Min(0.04, heuristicGap * 0.02);
            }
            else
            {
                confidence += 0.08;
            }

            if (best.covered <= 1)
                confidence -= 0.08;

            return Math.Max(0.42, Math.Min(0.96, confidence));
        }

        private bool IsLikelyTailRetMistake(VMOpCode opCode)
        {
            switch (opCode)
            {
                case VMOpCode.Nop:
                case VMOpCode.Pop:
                case VMOpCode.Dup:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                case VMOpCode.Not:
                case VMOpCode.Neg:
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

        private void LogRemainingUnknownCandidates(DevirtualizationCtx ctx)
        {
            if (!string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_UNKNOWN_CANDIDATES"), "1", StringComparison.Ordinal))
                return;
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

            if (unknownFrequency.Count == 0)
                return;

            foreach (var vmByte in unknownFrequency.OrderByDescending(q => q.Value).Select(q => q.Key))
            {
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                    continue;
                var operandType = ctx.Parser.Operands[vmByte];
                var candidates = BuildCandidatesForUnknownByte(streams, vmByte, operandType);
                if (candidates.Count == 0)
                    continue;

                var ranked = new List<(VMOpCode op, int global, int window, int covered)>();
                foreach (var candidate in candidates.Distinct())
                {
                    if (!IsOperandTypeCompatible(candidate, operandType))
                        continue;
                    var global = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                    var (window, covered) = ScoreWindowPenalty(ctx, streams, vmByte, candidate, windowRadius: 8);
                    ranked.Add((candidate, global, window, covered));
                }

                if (ranked.Count == 0)
                    continue;

                ranked = ranked
                    .OrderBy(r => r.global)
                    .ThenBy(r => r.window)
                    .ThenByDescending(r => r.covered)
                    .Take(5)
                    .ToList();

                var candidateLog = string.Join(", ", ranked.Select(r =>
                    $"{r.op} g={r.global} w={r.window} c={r.covered}"));
                ctx.Options.Logger.Info(
                    $"unknown vm 0x{vmByte:X2} freq={unknownFrequency[vmByte]} operand={operandType} candidates: {candidateLog}");
            }
        }

        private void LogOpcodeConfidenceSummary(DevirtualizationCtx ctx)
        {
            if (!string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_CONFIDENCE"), "1", StringComparison.Ordinal))
                return;
            if (ctx?.OpcodeConfidence == null || ctx.OpcodeConfidence.Count == 0)
                return;

            foreach (var pair in ctx.OpcodeConfidence.OrderBy(p => p.Key))
            {
                var vmByte = pair.Key;
                var info = pair.Value;
                ctx.Options.Logger.Info(
                    $"vm 0x{vmByte:X2} => {info.OpCode} (confidence={info.Confidence:F2}, source={info.Source})");
            }
        }

        // ConstraintMapper (control-flow focused):
        // If a vm-byte is mapped to branch/switch but frequently violates
        // operand target constraints, remap to the best compatible non-branch
        // candidate to avoid impossible branch targets at recompilation time.
    }
}
