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
        private void ApplyControlFlowConstraints(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Operands == null || ctx.Module == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var remapped = 0;
            var maxByte = Math.Min(_addressableOpcodeCount, ctx.Parser.Operands.Length);
            for (var vmByte = 0; vmByte < maxByte; vmByte++)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;

                var mapped = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (!IsBranchOpcode(mapped) && mapped != VMOpCode.Switch)
                    continue;

                var occurrences = 0;
                var invalidForCurrent = 0;
                foreach (var stream in streams)
                {
                    foreach (var sample in stream.Instructions)
                    {
                        if (sample.VmByte != vmByte)
                            continue;
                        occurrences++;
                        if (!IsCandidateOperandValid(ctx.Module, stream, mapped, sample.Operand))
                            invalidForCurrent++;
                    }
                }

                if (occurrences <= 0 || invalidForCurrent <= 0)
                    continue;

                var operandType = ctx.Parser.Operands[vmByte];
                var candidates = BuildCandidatesForUnknownByte(streams, vmByte, operandType)
                    .Distinct()
                    .Where(c => !IsBranchOpcode(c) && c != VMOpCode.Switch)
                    .Where(c => IsOperandTypeCompatible(c, operandType))
                    .ToList();
                if (candidates.Count == 0)
                    continue;

                var best = mapped;
                var bestInvalid = invalidForCurrent;
                foreach (var candidate in candidates)
                {
                    var invalid = 0;
                    foreach (var stream in streams)
                    {
                        foreach (var sample in stream.Instructions)
                        {
                            if (sample.VmByte != vmByte)
                                continue;
                            if (!IsCandidateOperandValid(ctx.Module, stream, candidate, sample.Operand))
                                invalid++;
                        }
                    }

                    if (invalid < bestInvalid)
                    {
                        bestInvalid = invalid;
                        best = candidate;
                    }
                }

                if (best == mapped || bestInvalid >= invalidForCurrent)
                    continue;

                ApplyMapping(
                    ctx,
                    vmByte,
                    best,
                    0.76,
                    "constraint-mapper");
                remapped++;

                ctx.Options.Logger.Warning(
                    $"ConstraintMapper remapped vm 0x{vmByte:X2} {mapped} -> {best} " +
                    $"(invalid-target occurrences {invalidForCurrent}->{bestInvalid}).");
            }

            if (remapped > 0)
                ctx.Options.Logger.Warning($"ConstraintMapper adjusted {remapped} control-flow vm-byte mapping(s).");
        }

        private void PruneLowConfidencePopMappings(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Operands == null || ctx.OpcodeConfidence == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var maxByte = Math.Min(_addressableOpcodeCount, ctx.Parser.Operands.Length);
            var removed = 0;
            for (var vmByte = 0; vmByte < maxByte; vmByte++)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (ctx.PatternMatcher.GetOpCodeValue(vmByte) != VMOpCode.Pop)
                    continue;
                if (!ctx.OpcodeConfidence.TryGetValue(vmByte, out var info))
                    continue;
                if (info.Confidence >= _heuristicsProfile.PopInferenceMinConfidence)
                    continue;
                if (string.IsNullOrWhiteSpace(info.Source) ||
                    info.Source.IndexOf("inference", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    continue;
                }

                var frequency = CountVmByteOccurrences(streams, vmByte);
                if (frequency < _heuristicsProfile.PopInferenceMinFrequency)
                    continue;

                var popPenalty = ScoreStackPenalty(ctx, streams, vmByte, VMOpCode.Pop);
                var operandType = ctx.Parser.Operands[vmByte];
                var bestAlternativePenalty = int.MaxValue;

                foreach (var candidate in BuildCandidatesForUnknownByte(streams, vmByte, operandType).Distinct())
                {
                    if (candidate == VMOpCode.Pop || candidate == VMOpCode.Nop)
                        continue;
                    if (!IsOperandTypeCompatible(candidate, operandType))
                        continue;
                    if (!IsCandidateValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                        continue;

                    var candidatePenalty = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                    if (candidatePenalty < bestAlternativePenalty)
                        bestAlternativePenalty = candidatePenalty;
                }

                if (bestAlternativePenalty == int.MaxValue)
                    continue;

                var gain = popPenalty - bestAlternativePenalty;
                if (gain < _heuristicsProfile.PopInferenceRequiredPenaltyGain)
                    continue;

                ctx.PatternMatcher.UnsetOpCodeValue(vmByte);
                ctx.OpcodeConfidence.Remove(vmByte);
                removed++;

                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"), "1", StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"pruned vm 0x{vmByte:X2} Pop mapping (confidence={info.Confidence:F2}, source={info.Source}, gain={gain})");
                }
            }

            if (removed > 0)
                ctx.Options.Logger.Warning($"Pruned {removed} low-confidence Pop mapping(s) to prevent invalid IL.");
        }

        private void PruneSuspiciousPopMappings(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.OpcodeConfidence == null)
                return;
            if (ctx.OpcodeHandlerMethod?.CilMethodBody?.Instructions == null || ctx.OpcodeHandlerIndices == null)
                return;

            var instructions = ctx.OpcodeHandlerMethod.CilMethodBody.Instructions;
            var removed = 0;

            foreach (var vmByte in ctx.OpcodeConfidence.Keys.ToList())
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (ctx.PatternMatcher.GetOpCodeValue(vmByte) != VMOpCode.Pop)
                    continue;
                if (!ctx.OpcodeHandlerIndices.TryGetValue(vmByte, out var start))
                    continue;
                if (!ctx.OpcodeConfidence.TryGetValue(vmByte, out var info))
                    continue;

                var source = info.Source ?? string.Empty;
                if (source.IndexOf("override", StringComparison.OrdinalIgnoreCase) >= 0)
                    continue;
                if (source.IndexOf("guarded-pop", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    LooksLikeGuardedPopHandler(ctx, instructions, start))
                {
                    continue;
                }
                if (!LooksLikeSuspiciousPopHandler(ctx, instructions, start))
                    continue;

                ctx.PatternMatcher.UnsetOpCodeValue(vmByte);
                ctx.OpcodeConfidence.Remove(vmByte);
                removed++;

                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"), "1", StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"pruned vm 0x{vmByte:X2} Pop mapping (complex/non-pop handler, source={info.Source})");
                }
            }

            if (removed > 0)
                ctx.Options.Logger.Warning($"Pruned {removed} suspicious Pop mapping(s) after handler inspection.");
        }

        private void RetuneLikelyIndexBytesMappedAsLdcI4(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Operands == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var maxByte = Math.Min(_addressableOpcodeCount, ctx.Parser.Operands.Length);
            var retuned = 0;
            for (var vmByte = 0; vmByte < maxByte; vmByte++)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (ctx.PatternMatcher.GetOpCodeValue(vmByte) != VMOpCode.Ldc_I4)
                    continue;
                if (ctx.Parser.Operands[vmByte] != 1)
                    continue;

                var localLike = IsLikelyLocalIndexByte(streams, vmByte);
                var argLike = IsLikelyArgumentIndexByte(streams, vmByte);
                if (!localLike && !argLike)
                    continue;

                var candidates = new List<VMOpCode>();
                if (localLike)
                {
                    candidates.Add(VMOpCode.Ldloc);
                    candidates.Add(VMOpCode.Stloc);
                }

                if (argLike)
                    candidates.Add(VMOpCode.Ldarg);

                var baselineGlobal = ScoreStackPenalty(ctx, streams, vmByte, VMOpCode.Ldc_I4);
                var (baselineWindow, _) = ScoreWindowPenalty(ctx, streams, vmByte, VMOpCode.Ldc_I4, windowRadius: 8);

                var best = (opCode: VMOpCode.Nop, global: int.MaxValue, window: int.MaxValue);
                foreach (var candidate in candidates.Distinct())
                {
                    if (!IsOperandTypeCompatible(candidate, 1))
                        continue;
                    if (!IsCandidateValidAcrossOccurrences(ctx, streams, vmByte, candidate))
                        continue;

                    var global = ScoreStackPenalty(ctx, streams, vmByte, candidate);
                    var (window, covered) = ScoreWindowPenalty(ctx, streams, vmByte, candidate, windowRadius: 8);
                    if (covered == 0)
                        continue;

                    if (global < best.global || (global == best.global && window < best.window))
                        best = (candidate, global, window);
                }

                if (best.opCode == VMOpCode.Nop)
                    continue;

                var globalGain = baselineGlobal - best.global;
                var windowGain = baselineWindow - best.window;
                if (globalGain < 12 && windowGain < 12)
                    continue;

                ApplyMapping(
                    ctx,
                    vmByte,
                    best.opCode,
                    0.86,
                    "index-like-ldc-retune");
                retuned++;

                ctx.Options.Logger.Warning(
                    $"Index-like retune remapped vm 0x{vmByte:X2} Ldc_I4 -> {best.opCode} " +
                    $"(global {baselineGlobal}->{best.global}, window {baselineWindow}->{best.window}).");
            }

            if (retuned > 0)
                ctx.Options.Logger.Warning($"Index-like retune adjusted {retuned} Ldc_I4 mapping(s).");
        }

        private void RetuneFinallyGuardPatternMappings(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null)
                return;

            var parser = ctx.Parser;
            var stream = parser.Reader.BaseStream;
            var originalPosition = stream.Position;

            var ldlocVotes = new Dictionary<int, int>();
            var brFalseVotes = new Dictionary<int, int>();
            var endFinallyVotes = new Dictionary<int, int>();

            try
            {
                foreach (var methodKey in parser.MethodKeys)
                {
                    stream.Position = methodKey;
                    parser.ReadEncryptedByte(); // parent token
                    var locals = parser.ReadEncryptedByte();
                    var exceptionHandlers = parser.ReadEncryptedByte();
                    var instructionCount = parser.ReadEncryptedByte();

                    for (var i = 0; i < locals; i++)
                        parser.ReadEncryptedByte();

                    var handlers = new List<VMExceptionHandler>(exceptionHandlers);
                    for (var i = 0; i < exceptionHandlers; i++)
                        handlers.Add(new VMExceptionHandler().Read(ctx.Module, parser));

                    var entries = new List<(int VmByte, object Operand)>(instructionCount);
                    for (var i = 0; i < instructionCount; i++)
                    {
                        var vmByte = parser.Reader.ReadByte();
                        object operand = null;
                        if (vmByte >= 0 && vmByte < parser.Operands.Length)
                            operand = ReadOperandSample(parser, parser.Operands[vmByte]);
                        entries.Add((vmByte, operand));
                    }

                    foreach (var eh in handlers)
                    {
                        if (eh == null || (eh.EHType != VMExceptionHandlerType.Finally && eh.EHType != VMExceptionHandlerType.Fault))
                            continue;

                        var hs = eh.HandlerStart;
                        var he = eh.HandlerEnd;
                        if (hs < 0 || he <= hs || he > entries.Count)
                            continue;

                        var endVmByte = entries[he - 1].VmByte;
                        if (endVmByte >= 0 &&
                            endVmByte < parser.Operands.Length &&
                            parser.Operands[endVmByte] == 0)
                        {
                            if (!endFinallyVotes.TryGetValue(endVmByte, out var endCount))
                                endCount = 0;
                            endFinallyVotes[endVmByte] = endCount + 1;
                        }

                        for (var j = hs + 1; j + 2 < he; j++)
                        {
                            var prev = entries[j - 1];
                            var branch = entries[j];
                            var next = entries[j + 1];
                            var call = entries[j + 2];

                            if (prev.VmByte != next.VmByte)
                                continue;
                            if (!(prev.Operand is int localA) || !(next.Operand is int localB) || localA != localB)
                                continue;
                            if (localA < 0 || localA >= locals)
                                continue;
                            if (!(branch.Operand is int target) || target != he - 1)
                                continue;
                            if (!IsDisposeMethodToken(ctx.Module, call.Operand))
                                continue;

                            if (!ldlocVotes.TryGetValue(prev.VmByte, out var ldCount))
                                ldCount = 0;
                            ldlocVotes[prev.VmByte] = ldCount + 1;

                            if (!brFalseVotes.TryGetValue(branch.VmByte, out var brCount))
                                brCount = 0;
                            brFalseVotes[branch.VmByte] = brCount + 1;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                HandleBestEffortFailure(ctx, "finally-guard retune", ex);
                return;
            }
            finally
            {
                stream.Position = originalPosition;
            }

            ApplyDominantVoteMapping(ctx, ldlocVotes, VMOpCode.Ldloc, "finally-guard-pattern", minimumVotes: 2);
            ApplyDominantVoteMapping(ctx, brFalseVotes, VMOpCode.BrFalse, "finally-guard-pattern", minimumVotes: 2);
            ApplyDominantVoteMapping(ctx, endFinallyVotes, VMOpCode.EndFinally, "finally-guard-pattern", minimumVotes: 2);
        }

        private void ApplyDominantVoteMapping(
            DevirtualizationCtx ctx,
            IReadOnlyDictionary<int, int> votes,
            VMOpCode target,
            string source,
            int minimumVotes)
        {
            if (ctx?.Parser?.Operands == null || votes == null || votes.Count == 0)
                return;

            var best = votes.OrderByDescending(v => v.Value).First();
            var total = votes.Values.Sum();
            if (best.Value < minimumVotes)
                return;
            if (total > 0 && best.Value * 2 < total)
                return;

            var vmByte = best.Key;
            if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                return;
            if (!IsOperandTypeCompatible(target, ctx.Parser.Operands[vmByte]))
                return;

            ApplyMapping(ctx, vmByte, target, 0.90, source);
            ctx.Options.Logger.Warning(
                $"Finally-guard retune mapped vm 0x{vmByte:X2} -> {target} (votes {best.Value}/{total}).");
        }

        private bool IsDisposeMethodToken(ModuleDefinition module, object operand)
        {
            if (!(operand is int token))
                return false;

            try
            {
                if (!(module.LookupMember(token) is IMethodDescriptor descriptor))
                    return false;
                var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
                if (signature == null)
                    return false;
                if (!string.Equals(descriptor.Name ?? descriptor.Resolve()?.Name, "Dispose", StringComparison.Ordinal))
                    return false;
                if (signature.ParameterTypes.Count != 0)
                    return false;
                return string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        private void PruneOperandIncompatibleMappings(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Operands == null)
                return;

            var maxByte = Math.Min(_addressableOpcodeCount, ctx.Parser.Operands.Length);
            var metadataLikeOperandBytes = BuildMetadataLikeOperandByteSet(ctx);
            var removed = 0;
            for (var vmByte = 0; vmByte < maxByte; vmByte++)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;

                var operandType = ctx.Parser.Operands[vmByte];
                var mapped = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (IsOperandTypeCompatible(mapped, operandType))
                    continue;

                var source = "unknown";
                if (ctx.OpcodeConfidence != null && ctx.OpcodeConfidence.TryGetValue(vmByte, out var info))
                {
                    source = info.Source ?? source;
                    if (ShouldDeferOperandIncompatibilityPrune(
                            ctx,
                            vmByte,
                            mapped,
                            operandType,
                            source,
                            metadataLikeOperandBytes))
                    {
                        ctx.Options.Logger.Info(
                            $"Deferred prune for vm 0x{vmByte:X2} -> {mapped} (operand {operandType}, source={source}) in dense dispatcher profile.");
                        continue;
                    }
                    ctx.OpcodeConfidence.Remove(vmByte);
                }
                else if (ShouldDeferOperandIncompatibilityPrune(
                             ctx,
                             vmByte,
                             mapped,
                             operandType,
                             source,
                             metadataLikeOperandBytes))
                {
                    ctx.Options.Logger.Info(
                        $"Deferred prune for vm 0x{vmByte:X2} -> {mapped} (operand {operandType}, source={source}) in dense dispatcher profile.");
                    continue;
                }

                ctx.PatternMatcher.UnsetOpCodeValue(vmByte);
                removed++;
                ctx.Options.Logger.Warning(
                    $"Pruned vm 0x{vmByte:X2} -> {mapped} because operand type {operandType} is incompatible (source={source}).");
            }

            if (removed > 0)
            {
                ctx.Options.Logger.Warning(
                    $"Pruned {removed} operand-incompatible vm-byte mapping(s) before disassembly.");
            }
        }

        private void PruneSemanticallyInvalidIndexLikeMappings(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Operands == null || ctx.Module == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var maxByte = Math.Min(_addressableOpcodeCount, ctx.Parser.Operands.Length);
            var removed = 0;
            for (var vmByte = 0; vmByte < maxByte; vmByte++)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;

                var mapped = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (!RequiresSemanticOperandPrune(mapped))
                    continue;

                var occurrences = 0;
                var invalid = 0;
                foreach (var stream in streams)
                {
                    foreach (var sample in stream.Instructions)
                    {
                        if (sample.VmByte != vmByte)
                            continue;

                        occurrences++;
                        if (!IsCandidateOperandValid(ctx.Module, stream, mapped, sample.Operand))
                            invalid++;
                    }
                }

                if (occurrences <= 0 || invalid <= 0)
                    continue;

                var source = "unknown";
                if (ctx.OpcodeConfidence != null && ctx.OpcodeConfidence.TryGetValue(vmByte, out var info))
                {
                    source = info.Source ?? source;
                    if (source.IndexOf("override", StringComparison.OrdinalIgnoreCase) >= 0)
                        continue;
                    ctx.OpcodeConfidence.Remove(vmByte);
                }

                ctx.PatternMatcher.UnsetOpCodeValue(vmByte);
                removed++;
                ctx.Options.Logger.Warning(
                    $"Pruned vm 0x{vmByte:X2} -> {mapped} because semantic operand validation failed ({invalid}/{occurrences} invalid, source={source}).");
            }

            if (removed > 0)
            {
                ctx.Options.Logger.Warning(
                    $"Pruned {removed} semantically invalid index/control-flow vm-byte mapping(s).");
            }
        }

        private bool RequiresSemanticOperandPrune(VMOpCode mapped)
        {
            switch (mapped)
            {
                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Stloc:
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                case VMOpCode.Switch:
                case VMOpCode.Newarr:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Ldobj:
                case VMOpCode.Stobj:
                case VMOpCode.Ldelema:
                    return true;
                default:
                    return false;
            }
        }

        private bool ShouldDeferOperandIncompatibilityPrune(
            DevirtualizationCtx ctx,
            int vmByte,
            VMOpCode mapped,
            byte operandType,
            string source,
            ISet<int> metadataLikeOperandBytes)
        {
            if (operandType != 1)
                return false;
            // Never defer incompatible arithmetic/shift mappings on operand-1 bytes.
            // These tend to be branch/local opcodes in dense Reactor dispatchers.
            if (mapped == VMOpCode.Add ||
                mapped == VMOpCode.Sub ||
                mapped == VMOpCode.Xor ||
                mapped == VMOpCode.Shl ||
                mapped == VMOpCode.Shr)
            {
                return false;
            }

            if (mapped != VMOpCode.Conv_I4 &&
                mapped != VMOpCode.Conv_I8 &&
                mapped != VMOpCode.Conv_U1)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(source))
                return false;
            if (source.IndexOf("handler-pattern", StringComparison.OrdinalIgnoreCase) < 0 &&
                source.IndexOf("handler-similarity", StringComparison.OrdinalIgnoreCase) < 0)
            {
                return false;
            }
            if (metadataLikeOperandBytes != null && metadataLikeOperandBytes.Contains(vmByte))
                return false;

            // Very dense flattened dispatchers can carry operand descriptors
            // that do not align with handler-body classification. In this case
            // keep handler-derived mappings and let semantic validation decide.
            var handlerCount = ctx?.OpcodeHandlerIndices?.Count ?? 0;
            return handlerCount >= 224;
        }

        private HashSet<int> BuildMetadataLikeOperandByteSet(DevirtualizationCtx ctx)
        {
            var result = new HashSet<int>();
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null)
                return result;

            var parser = ctx.Parser;
            var stream = parser.Reader.BaseStream;
            var originalPosition = stream.Position;
            try
            {
                foreach (var methodKey in parser.MethodKeys)
                {
                    stream.Position = methodKey;
                    parser.ReadEncryptedByte(); // parent token
                    var locals = parser.ReadEncryptedByte();
                    var exceptionHandlers = parser.ReadEncryptedByte();
                    var instructionCount = parser.ReadEncryptedByte();

                    for (var i = 0; i < locals; i++)
                        parser.ReadEncryptedByte();
                    for (var i = 0; i < exceptionHandlers; i++)
                        new VMExceptionHandler().Read(ctx.Module, parser);

                    for (var i = 0; i < instructionCount; i++)
                    {
                        var vmByte = parser.Reader.ReadByte();
                        if (vmByte < 0 || vmByte >= parser.Operands.Length)
                            continue;

                        var operandType = parser.Operands[vmByte];
                        if (operandType == 1)
                        {
                            var operand = parser.ReadEncryptedByte();
                            if (operand > 0 && (((uint) operand) & 0xFF000000u) != 0)
                                result.Add(vmByte);
                        }
                        else
                        {
                            SkipOperand(parser, operandType);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                HandleBestEffortFailure(ctx, "metadata-like operand scan", ex);
            }
            finally
            {
                stream.Position = originalPosition;
            }

            return result;
        }

        private bool LooksLikeSuspiciousPopHandler(
            DevirtualizationCtx ctx,
            IList<CilInstruction> instructions,
            int startIndex)
        {
            var endExclusive = GetHandlerEndExclusive(ctx, instructions, startIndex);
            if (endExclusive <= startIndex)
                return false;

            var hasPop = false;
            var callCount = 0;
            for (var i = startIndex; i < endExclusive; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Pop)
                    hasPop = true;
                if (IsCallInstruction(instructions[i]))
                    callCount++;
                if (IsStlocInstruction(instructions[i]) ||
                    IsConditionalBranchInstruction(op) ||
                    op == CilOpCodes.Unbox_Any ||
                    op == CilOpCodes.Newobj ||
                    op == CilOpCodes.Ldtoken ||
                    op == CilOpCodes.Castclass ||
                    op == CilOpCodes.Isinst ||
                    op == CilOpCodes.Ldelem_Ref ||
                    op == CilOpCodes.Ldflda ||
                    op == CilOpCodes.Switch)
                {
                    return true;
                }
            }

            if (!hasPop)
                return true;

            return callCount > 3;
        }
    }
}
