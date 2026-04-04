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
        private int GetObservedMaxVmByte(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null)
                return -1;

            var parser = ctx.Parser;
            var stream = parser.Reader.BaseStream;
            var originalPosition = stream.Position;
            var maxVmByte = -1;

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
                        if (vmByte > maxVmByte)
                            maxVmByte = vmByte;

                        if (vmByte >= 0 && vmByte < parser.Operands.Length)
                            SkipOperand(parser, parser.Operands[vmByte]);
                    }
                }
            }
            catch (Exception ex)
            {
                HandleBestEffortFailure(ctx, "observed VM max-byte scan", ex);
                return -1;
            }
            finally
            {
                stream.Position = originalPosition;
            }

            return maxVmByte;
        }

        private Dictionary<int, int> GetObservedVmByteHistogram(DevirtualizationCtx ctx)
        {
            var histogram = new Dictionary<int, int>();
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null)
                return histogram;

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
                        if (!histogram.TryGetValue(vmByte, out var count))
                            count = 0;
                        histogram[vmByte] = count + 1;

                        if (vmByte >= 0 && vmByte < parser.Operands.Length)
                            SkipOperand(parser, parser.Operands[vmByte]);
                    }
                }
            }
            catch (Exception ex)
            {
                HandleBestEffortFailure(ctx, "observed VM-byte histogram scan", ex);
                return new Dictionary<int, int>();
            }
            finally
            {
                stream.Position = originalPosition;
            }

            return histogram;
        }

        private void InferUnmappedOpcodesFromOperandSemantics(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null)
                return;

            var observations = CollectOperandObservations(ctx);
            if (observations.Count == 0)
                return;

            var inferred = 0;
            foreach (var pair in observations)
            {
                var vmByte = pair.Key;
                var stats = pair.Value;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length || ctx.Parser.Operands[vmByte] != 1)
                    continue;

                var inferredOpcode = InferOpcodeFromObservation(stats);
                if (inferredOpcode == VMOpCode.Nop)
                    continue;

                ApplyMapping(ctx, vmByte, inferredOpcode, 0.70, "operand-semantics");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {inferredOpcode} (semantic fallback; samples={stats.SampleCount})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Semantic fallback mapped {inferred} additional VM opcodes.");
        }

        // Automatic, profile-free mapping for operand encodings that are
        // structurally unique in this VM format.

        private void InferStructurallyUniqueOperandOpcodes(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var stream = ctx.Parser.Reader.BaseStream;
            var originalPosition = stream.Position;
            var seenSwitchLikeBytes = new HashSet<int>();

            try
            {
                foreach (var methodKey in ctx.Parser.MethodKeys)
                {
                    stream.Position = methodKey;
                    ctx.Parser.ReadEncryptedByte(); // parent token
                    var locals = ctx.Parser.ReadEncryptedByte();
                    var exceptionHandlers = ctx.Parser.ReadEncryptedByte();
                    var instructionCount = ctx.Parser.ReadEncryptedByte();

                    for (var i = 0; i < locals; i++)
                        ctx.Parser.ReadEncryptedByte();
                    for (var i = 0; i < exceptionHandlers; i++)
                        new VMExceptionHandler().Read(ctx.Module, ctx.Parser);

                    for (var i = 0; i < instructionCount; i++)
                    {
                        var vmByte = ctx.Parser.Reader.ReadByte();
                        if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                            continue;
                        var operandType = ctx.Parser.Operands[vmByte];
                        if (operandType == 5)
                            seenSwitchLikeBytes.Add(vmByte);

                        SkipOperand(ctx.Parser, operandType);
                    }
                }
            }
            catch (Exception ex)
            {
                HandleBestEffortFailure(ctx, "structural operand inference", ex);
                return;
            }
            finally
            {
                stream.Position = originalPosition;
            }

            var mapped = 0;
            foreach (var vmByte in seenSwitchLikeBytes)
            {
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;

                ApplyMapping(ctx, vmByte, VMOpCode.Switch, 0.98, "structural-operand");
                mapped++;
            }

            if (mapped > 0)
                ctx.Options.Logger.Info($"Structural operand inference mapped {mapped} additional VM opcodes.");
        }

        private void InferUnmappedOpcodesByHandlerSimilarity(
            DevirtualizationCtx ctx,
            SelectionResult selection,
            IList<ICilLabel> values)
        {
            if (ctx?.PatternMatcher == null || selection?.Method?.CilMethodBody == null || values == null)
                return;

            var maxByte = Math.Min(values.Count, _addressableOpcodeCount);
            var mappedSignatures = new List<(int vmByte, VMOpCode opCode, HashSet<int> grams)>();
            var unknownEntries = new List<(int vmByte, HashSet<int> grams)>();

            for (var vmByte = 0; vmByte < maxByte; vmByte++)
            {
                if (!(values[vmByte] is CilInstructionLabel instructionLabel) || instructionLabel.Instruction == null)
                    continue;
                if (!selection.AnalysisContext.InstructionIndexByInstruction.TryGetValue(
                        instructionLabel.Instruction,
                        out var index))
                {
                    continue;
                }

                var grams = BuildHandlerSignatureGrams(
                    selection.Method,
                    index,
                    maxOps: _heuristicsProfile.SignatureGramMaxOps);
                if (grams.Count == 0)
                    continue;

                var opCode = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                {
                    unknownEntries.Add((vmByte, grams));
                }
                else
                {
                    mappedSignatures.Add((vmByte, opCode, grams));
                }
            }

            if (mappedSignatures.Count == 0 || unknownEntries.Count == 0)
                return;

            var inferred = 0;
            foreach (var unknown in unknownEntries)
            {
                var bestScore = 0.0;
                var bestOpcode = VMOpCode.Nop;
                var bestSourceByte = -1;

                foreach (var mapped in mappedSignatures)
                {
                    if (ctx.Parser?.Operands != null &&
                        unknown.vmByte >= 0 &&
                        unknown.vmByte < ctx.Parser.Operands.Length &&
                        mapped.vmByte >= 0 &&
                        mapped.vmByte < ctx.Parser.Operands.Length &&
                        ctx.Parser.Operands[unknown.vmByte] != ctx.Parser.Operands[mapped.vmByte])
                    {
                        continue;
                    }

                    var score = DiceCoefficient(unknown.grams, mapped.grams);
                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestOpcode = mapped.opCode;
                        bestSourceByte = mapped.vmByte;
                    }
                }

                if (bestOpcode == VMOpCode.Nop || bestScore < _heuristicsProfile.SimilarityDiceThreshold)
                    continue;
                if (!IsSimilaritySafeOpcode(bestOpcode))
                    continue;
                if (ctx.Parser?.Operands != null &&
                    unknown.vmByte >= 0 &&
                    unknown.vmByte < ctx.Parser.Operands.Length &&
                    !IsOperandTypeCompatible(bestOpcode, ctx.Parser.Operands[unknown.vmByte]))
                {
                    continue;
                }

                ApplyMapping(ctx, unknown.vmByte, bestOpcode, bestScore, "handler-similarity");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{unknown.vmByte:X2} -> {bestOpcode} (handler-similarity {bestScore:F2}, ref 0x{bestSourceByte:X2})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Handler-similarity fallback mapped {inferred} additional VM opcodes.");
        }

        private void InferUnknownByIntrinsicTypeTokenHandlers(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;
            if (ctx.OpcodeHandlerMethod?.CilMethodBody?.Instructions == null || ctx.OpcodeHandlerIndices == null)
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
            foreach (var vmByte in unknownFrequency.OrderByDescending(q => q.Value).Select(q => q.Key))
            {
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                    continue;
                if (ctx.Parser.Operands[vmByte] != 1)
                    continue;
                if (!AreAllOccurrencesTypeTokens(ctx.Module, streams, vmByte))
                    continue;

                var intrinsic = InferIntrinsicTypeTokenOpcodeFromHandler(ctx, vmByte);
                if (intrinsic == VMOpCode.Nop)
                    continue;
                if (!IsOperandTypeCompatible(intrinsic, ctx.Parser.Operands[vmByte]))
                    continue;
                if (!AreCandidateOperandsValidAcrossOccurrences(ctx, streams, vmByte, intrinsic))
                    continue;

                ApplyMapping(ctx, vmByte, intrinsic, 0.90, "intrinsic-token-handler");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {intrinsic} (intrinsic type-token handler inference)");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Intrinsic type-token inference mapped {inferred} additional VM opcodes.");
        }

        private bool AreAllOccurrencesTypeTokens(
            ModuleDefinition module,
            IReadOnlyList<VmMethodStreamSample> streams,
            int vmByte)
        {
            var seen = 0;
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (sample.VmByte != vmByte)
                        continue;
                    if (!(sample.Operand is int token))
                        return false;

                    seen++;
                    try
                    {
                        if (!(module.LookupMember(token) is ITypeDefOrRef))
                            return false;
                    }
                    catch
                    {
                        return false;
                    }
                }
            }

            return seen > 0;
        }

        private VMOpCode InferIntrinsicTypeTokenOpcodeFromHandler(DevirtualizationCtx ctx, int vmByte)
        {
            if (!ctx.OpcodeHandlerIndices.TryGetValue(vmByte, out var start))
                return VMOpCode.Nop;

            var instructions = ctx.OpcodeHandlerMethod.CilMethodBody.Instructions;
            if (start < 0 || start >= instructions.Count)
                return VMOpCode.Nop;

            var nextStart = ctx.OpcodeHandlerIndices.Values
                .Where(v => v > start)
                .DefaultIfEmpty(instructions.Count)
                .Min();
            var endExclusive = Math.Min(instructions.Count, Math.Max(start + 1, nextStart));
            var retIndex = -1;
            for (var i = start; i < endExclusive; i++)
            {
                if (instructions[i].OpCode == CilOpCodes.Ret)
                {
                    retIndex = i;
                    break;
                }
            }

            if (retIndex >= 0)
                endExclusive = retIndex + 1;

            var hasNewarr = false;
            var hasUnboxAny = false;
            var hasLdelema = false;
            var hasLdobj = false;
            var hasStobj = false;

            for (var i = start; i < endExclusive; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Newarr)
                    hasNewarr = true;
                else if (op == CilOpCodes.Unbox_Any)
                    hasUnboxAny = true;
                else if (op == CilOpCodes.Ldelema)
                    hasLdelema = true;
                else if (op == CilOpCodes.Ldobj)
                    hasLdobj = true;
                else if (op == CilOpCodes.Stobj)
                    hasStobj = true;
            }

            var hits = 0;
            if (hasNewarr) hits++;
            if (hasUnboxAny) hits++;
            if (hasLdelema) hits++;
            if (hasLdobj) hits++;
            if (hasStobj) hits++;
            if (hits != 1)
                return VMOpCode.Nop;

            if (hasNewarr) return VMOpCode.Newarr;
            if (hasUnboxAny) return VMOpCode.Unbox_Any;
            if (hasLdelema) return VMOpCode.Ldelema;
            if (hasLdobj) return VMOpCode.Ldobj;
            if (hasStobj) return VMOpCode.Stobj;
            return VMOpCode.Nop;
        }

        private bool IsSimilaritySafeOpcode(VMOpCode opCode)
        {
            switch (opCode)
            {
                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Stloc:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldstr:
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                case VMOpCode.Newobj:
                case VMOpCode.Newarr:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldfld:
                case VMOpCode.Stsfld:
                case VMOpCode.Stfld:
                case VMOpCode.Ldelema:
                case VMOpCode.Ldobj:
                case VMOpCode.Stobj:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                case VMOpCode.Pop:
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
                case VMOpCode.Ldnull:
                case VMOpCode.Ret:
                    return true;
                default:
                    return false;
            }
        }

        private void InferUnknownByCompactDupHandlers(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Operands == null)
                return;
            if (ctx.OpcodeHandlerMethod?.CilMethodBody?.Instructions == null || ctx.OpcodeHandlerIndices == null)
                return;

            var instructions = ctx.OpcodeHandlerMethod.CilMethodBody.Instructions;
            var inferred = 0;

            foreach (var pair in ctx.OpcodeHandlerIndices.OrderBy(p => p.Key))
            {
                var vmByte = pair.Key;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length || ctx.Parser.Operands[vmByte] != 0)
                    continue;
                if (!LooksLikeCompactDupHandler(ctx, instructions, pair.Value))
                    continue;

                ApplyMapping(ctx, vmByte, VMOpCode.Dup, 0.88, "compact-dup-handler");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info($"vm 0x{vmByte:X2} -> Dup (compact handler inference)");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Compact Dup handler inference mapped {inferred} additional VM opcodes.");
        }

        private void InferUnknownByGuardedPopHandlers(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Operands == null)
                return;
            if (ctx.OpcodeHandlerMethod?.CilMethodBody?.Instructions == null || ctx.OpcodeHandlerIndices == null)
                return;

            var instructions = ctx.OpcodeHandlerMethod.CilMethodBody.Instructions;
            var inferred = 0;

            foreach (var pair in ctx.OpcodeHandlerIndices.OrderBy(p => p.Key))
            {
                var vmByte = pair.Key;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length || ctx.Parser.Operands[vmByte] != 0)
                    continue;
                if (!LooksLikeGuardedPopHandler(ctx, instructions, pair.Value))
                    continue;

                ApplyMapping(ctx, vmByte, VMOpCode.Pop, 0.74, "guarded-pop-inference");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info($"vm 0x{vmByte:X2} -> Pop (guarded handler inference)");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Guarded Pop inference mapped {inferred} additional VM opcodes.");
        }

        private void InferUnknownByPointerProjectionUnaryHandlers(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Operands == null)
                return;
            if (ctx.OpcodeHandlerMethod?.CilMethodBody?.Instructions == null || ctx.OpcodeHandlerIndices == null)
                return;

            var instructions = ctx.OpcodeHandlerMethod.CilMethodBody.Instructions;
            var inferred = 0;

            foreach (var pair in ctx.OpcodeHandlerIndices.OrderBy(p => p.Key))
            {
                var vmByte = pair.Key;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length || ctx.Parser.Operands[vmByte] != 0)
                    continue;
                if (!LooksLikePointerProjectionUnaryHandler(ctx, instructions, pair.Value))
                    continue;

                ApplyMapping(ctx, vmByte, VMOpCode.Conv_I8, 0.66, "pointer-unary-inference");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info($"vm 0x{vmByte:X2} -> Conv_I8 (pointer-projection unary inference)");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Pointer-projection unary inference mapped {inferred} additional VM opcodes.");
        }

        private void InferUnknownByStelemI1Handlers(DevirtualizationCtx ctx)
        {
            if (ctx?.PatternMatcher == null || ctx.Parser?.Operands == null)
                return;
            if (ctx.OpcodeHandlerMethod?.CilMethodBody?.Instructions == null || ctx.OpcodeHandlerIndices == null)
                return;

            var instructions = ctx.OpcodeHandlerMethod.CilMethodBody.Instructions;
            var inferred = 0;

            foreach (var pair in ctx.OpcodeHandlerIndices.OrderBy(p => p.Key))
            {
                var vmByte = pair.Key;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length || ctx.Parser.Operands[vmByte] != 1)
                    continue;
                if (!LooksLikeStelemI1Handler(ctx, instructions, pair.Value))
                    continue;

                ApplyMapping(ctx, vmByte, VMOpCode.Stelem_I1, 0.90, "stelem-i1-handler");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info($"vm 0x{vmByte:X2} -> Stelem_I1 (handler inference)");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Stelem.I1 handler inference mapped {inferred} additional VM opcodes.");
        }

        private void InferUnknownDupBeforeStructuredStelemRef(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var streams = CollectVmMethodStreams(ctx);
            if (streams.Count == 0)
                return;

            var frequency = new Dictionary<int, int>();
            var support = new Dictionary<int, int>();

            foreach (var stream in streams)
            {
                var instructions = stream.Instructions;
                for (var i = 0; i < instructions.Count; i++)
                {
                    var sample = instructions[i];
                    if (sample.VmByte < 0 || sample.VmByte >= ctx.Parser.Operands.Length)
                        continue;
                    if (ctx.PatternMatcher.IsOpCodeValueKnown(sample.VmByte))
                        continue;
                    if (ctx.Parser.Operands[sample.VmByte] != 0)
                        continue;

                    if (!frequency.TryGetValue(sample.VmByte, out var count))
                        count = 0;
                    frequency[sample.VmByte] = count + 1;

                    if (!MatchesStructuredStelemRefTail(ctx.PatternMatcher, instructions, i + 1))
                        continue;

                    if (!support.TryGetValue(sample.VmByte, out var matched))
                        matched = 0;
                    support[sample.VmByte] = matched + 1;
                }
            }

            var mapped = 0;
            foreach (var pair in support.OrderByDescending(q => q.Value))
            {
                var vmByte = pair.Key;
                var matched = pair.Value;
                if (!frequency.TryGetValue(vmByte, out var total) || total <= 0)
                    continue;
                if (matched < 8)
                    continue;

                var ratio = (double) matched / total;
                if (ratio < 0.60)
                    continue;

                ApplyMapping(ctx, vmByte, VMOpCode.Dup, Math.Min(0.92, 0.55 + ratio * 0.35), "structured-stelemref");
                mapped++;

                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"), "1", StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> Dup (structured-stelemref {matched}/{total}, ratio={ratio:F2})");
                }
            }

            if (mapped > 0)
            {
                ctx.Options.Logger.Info(
                    $"Structured Stelem.Ref inference mapped {mapped} additional VM opcode(s).");
            }
        }

        private bool MatchesStructuredStelemRefTail(
            PatternMatcher matcher,
            IReadOnlyList<VmInstructionSample> instructions,
            int startIndex)
        {
            if (matcher == null || instructions == null || startIndex < 0 || startIndex >= instructions.Count)
                return false;

            var upcoming = new List<VMOpCode>(5);
            for (var i = startIndex; i < instructions.Count && upcoming.Count < 5; i++)
            {
                var vmByte = instructions[i].VmByte;
                if (!matcher.IsOpCodeValueKnown(vmByte))
                    return false;

                upcoming.Add(matcher.GetOpCodeValue(vmByte));
            }

            return upcoming.Count >= 5 &&
                   upcoming[0] == VMOpCode.Ldarg &&
                   upcoming[1] == VMOpCode.Stloc &&
                   upcoming[2] == VMOpCode.Ldc_I4 &&
                   upcoming[3] == VMOpCode.Ldc_I4 &&
                   upcoming[4] == VMOpCode.Stelem_Ref;
        }

        private List<VmMethodStreamSample> CollectVmMethodStreams(DevirtualizationCtx ctx)
        {
            var streams = new List<VmMethodStreamSample>();
            var parser = ctx.Parser;
            var stream = parser.Reader.BaseStream;
            var originalPosition = stream.Position;

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

                    var expectedReturn = ResolveExpectedReturnStack(ctx.Module, parentToken);
                    var argCount = ResolveArgCount(ctx.Module, parentToken);
                    var instructions = new List<VmInstructionSample>(instructionCount);
                    for (var i = 0; i < instructionCount; i++)
                    {
                        var vmByte = parser.Reader.ReadByte();
                        object operand = null;
                        if (vmByte >= 0 && vmByte < parser.Operands.Length)
                        {
                            var operandType = parser.Operands[vmByte];
                            operand = ReadOperandSample(parser, operandType);
                        }

                        instructions.Add(new VmInstructionSample(vmByte, operand));
                    }

                    streams.Add(new VmMethodStreamSample(instructions, expectedReturn, locals, argCount));
                }
            }
            catch
            {
                return new List<VmMethodStreamSample>();
            }
            finally
            {
                stream.Position = originalPosition;
            }

            return streams;
        }

        private object ReadOperandSample(Core.Parser.ResourceParser parser, byte operandType)
        {
            switch (operandType)
            {
                case 1:
                    return parser.ReadEncryptedByte();
                case 2:
                    return parser.Reader.ReadInt64();
                case 3:
                    return parser.Reader.ReadSingle();
                case 4:
                    return parser.Reader.ReadDouble();
                case 5:
                {
                    var count = parser.ReadEncryptedByte();
                    var targets = new int[count];
                    for (var i = 0; i < count; i++)
                        targets[i] = parser.ReadEncryptedByte();
                    return targets;
                }
                default:
                    return null;
            }
        }

        private int ResolveExpectedReturnStack(ModuleDefinition module, int parentToken)
        {
            try
            {
                if (!(module.LookupMember(parentToken) is IMethodDescriptor descriptor))
                    return 0;

                var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
                if (signature == null)
                    return 0;

                return string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) ? 0 : 1;
            }
            catch
            {
                return 0;
            }
        }

        private bool IsCandidateValidAcrossOccurrences(
            DevirtualizationCtx ctx,
            IReadOnlyList<VmMethodStreamSample> streams,
            int targetVmByte,
            VMOpCode candidate)
        {
            var strongBranchShape = IsBranchOpcode(candidate) && IsStrongBranchTargetByte(streams, targetVmByte);
            if (candidate == VMOpCode.Switch && !IsLikelySwitchByte(streams, targetVmByte))
                return false;

            var matched = 0;
            var flowChecks = 0;
            var flowMismatches = 0;
            var requiresValueFlow = ConsumesValue(candidate) && ProducesValue(candidate);

            foreach (var stream in streams)
            {
                for (var i = 0; i < stream.Instructions.Count; i++)
                {
                    var sample = stream.Instructions[i];
                    if (sample.VmByte != targetVmByte)
                        continue;

                    matched++;
                    if (!IsCandidateOperandValid(ctx.Module, stream, candidate, sample.Operand))
                        return false;

                    // Local flow guard for transform-like opcodes (pop+push):
                    // avoid assigning them when surrounding known context contradicts value flow.
                    if (!requiresValueFlow)
                        continue;

                    var prevKnown = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, i - 1, -1);
                    if (prevKnown != VMOpCode.Nop)
                    {
                        flowChecks++;
                        if (!ProducesValue(prevKnown))
                            flowMismatches++;
                    }

                    var nextKnown = FindNeighborKnownOpcodeInStream(ctx.PatternMatcher, stream.Instructions, i + 1, +1);
                    if (nextKnown != VMOpCode.Nop)
                    {
                        flowChecks++;
                        if (!ConsumesValue(nextKnown))
                            flowMismatches++;
                    }
                }
            }

            if (flowChecks > 0 && flowMismatches * 4 > flowChecks)
                return false;

            // Some protected handlers use rare singleton/dual branch bytes that
            // are valid targets but do not pass strict "strong branch" shape.
            // Keep strictness for common bytes and allow only truly rare cases.
            if (IsBranchOpcode(candidate) && !strongBranchShape && matched > 2)
                return false;

            return matched > 0;
        }

        private bool IsLikelySwitchByte(IReadOnlyList<VmMethodStreamSample> streams, int vmByte)
        {
            var seen = 0;
            var switchLike = 0;
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (sample.VmByte != vmByte)
                        continue;

                    seen++;
                    if (sample.Operand is int[] targets &&
                        targets.Length > 1 &&
                        targets.All(t => t >= 0 && t < stream.Instructions.Count))
                    {
                        switchLike++;
                    }
                }
            }

            return seen > 0 && switchLike * 10 >= seen * 9;
        }

        private bool AreCandidateOperandsValidAcrossOccurrences(
            DevirtualizationCtx ctx,
            IReadOnlyList<VmMethodStreamSample> streams,
            int targetVmByte,
            VMOpCode candidate)
        {
            var matched = 0;
            foreach (var stream in streams)
            {
                foreach (var sample in stream.Instructions)
                {
                    if (sample.VmByte != targetVmByte)
                        continue;

                    matched++;
                    if (!IsCandidateOperandValid(ctx.Module, stream, candidate, sample.Operand))
                        return false;
                }
            }

            return matched > 0;
        }

        private bool IsCandidateOperandValid(
            ModuleDefinition module,
            VmMethodStreamSample stream,
            VMOpCode candidate,
            object operand)
        {
            switch (candidate)
            {
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                    return operand is int branchTarget &&
                           branchTarget >= 0 &&
                           branchTarget < stream.Instructions.Count;

                case VMOpCode.Switch:
                {
                    if (!(operand is int[] targets) || targets.Length == 0)
                        return false;
                    return targets.All(t => t >= 0 && t < stream.Instructions.Count);
                }

                case VMOpCode.Ldloc:
                case VMOpCode.Stloc:
                    return operand is int localIndex &&
                           localIndex >= 0 &&
                           localIndex < stream.LocalCount;

                case VMOpCode.Ldarg:
                    return operand is int argIndex &&
                           argIndex >= 0 &&
                           argIndex < stream.ArgCount;

                case VMOpCode.Ldc_I4:
                {
                    if (!(operand is int value))
                        return false;

                    // If value resolves to metadata, it is most likely a token-based opcode,
                    // not a plain integer constant.
                    try
                    {
                        if ((uint) value >= 0x01000000u && module.LookupMember(value) != null)
                            return false;
                    }
                    catch
                    {
                        // Ignore resolution errors and keep it as a valid constant candidate.
                    }

                    return true;
                }

                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                case VMOpCode.Newobj:
                {
                    if (!(operand is int methodToken))
                        return false;

                    IMethodDescriptor descriptor;
                    try
                    {
                        descriptor = module.LookupMember(methodToken) as IMethodDescriptor;
                    }
                    catch
                    {
                        return false;
                    }

                    if (descriptor == null)
                        return false;

                    if (candidate != VMOpCode.Newobj)
                        return true;

                    var name = descriptor.Name ?? descriptor.Resolve()?.Name;
                    return string.Equals(name, ".ctor", StringComparison.Ordinal);
                }

                case VMOpCode.Ldsfld:
                case VMOpCode.Stsfld:
                case VMOpCode.Ldfld:
                case VMOpCode.Stfld:
                {
                    if (!(operand is int fieldToken))
                        return false;
                    try
                    {
                        return module.LookupMember(fieldToken) is IFieldDescriptor;
                    }
                    catch
                    {
                        return false;
                    }
                }

                case VMOpCode.Newarr:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Ldobj:
                case VMOpCode.Stobj:
                case VMOpCode.Ldelema:
                {
                    if (!(operand is int typeToken))
                        return false;
                    try
                    {
                        return module.LookupMember(typeToken) is ITypeDefOrRef;
                    }
                    catch
                    {
                        return false;
                    }
                }

                default:
                    return true;
            }
        }

        private void InferUnknownByNeighborContext(DevirtualizationCtx ctx)
        {
            if (ctx?.Parser?.Reader == null || ctx.Parser.MethodKeys == null || ctx.Parser.Operands == null || ctx.PatternMatcher == null)
                return;

            var contextVotes = new Dictionary<NeighborContextKey, Dictionary<VMOpCode, int>>();
            var unknownSamples = new Dictionary<int, List<NeighborContextKey>>();

            ScanVmNeighborContexts(ctx, contextVotes, unknownSamples);

            var inferred = 0;
            foreach (var pair in unknownSamples)
            {
                var vmByte = pair.Key;
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (vmByte < 0 || vmByte >= ctx.Parser.Operands.Length)
                    continue;

                var candidateScores = new Dictionary<VMOpCode, int>();
                foreach (var key in pair.Value)
                {
                    if (!contextVotes.TryGetValue(key, out var votes))
                        continue;
                    foreach (var vote in votes)
                    {
                        if (!IsContextSafeOpcode(vote.Key))
                            continue;
                        if (!candidateScores.TryGetValue(vote.Key, out var score))
                            score = 0;
                        candidateScores[vote.Key] = score + vote.Value;
                    }
                }

                if (candidateScores.Count == 0)
                    continue;

                var ordered = candidateScores.OrderByDescending(q => q.Value).ToList();
                var best = ordered[0];
                var totalVotes = ordered.Sum(q => q.Value);
                var confidence = totalVotes == 0 ? 0.0 : (double) best.Value / totalVotes;

                if (best.Value < _heuristicsProfile.NeighborVoteMinimum ||
                    confidence < _heuristicsProfile.NeighborConfidenceMinimum)
                    continue;
                if (!IsOperandTypeCompatible(best.Key, ctx.Parser.Operands[vmByte]))
                    continue;

                ApplyMapping(ctx, vmByte, best.Key, confidence, "neighbor-context");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {best.Key} (neighbor-context inference; votes={best.Value}, conf={confidence:F2})");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Neighbor-context inference mapped {inferred} additional VM opcodes.");
        }

        private void ScanVmNeighborContexts(
            DevirtualizationCtx ctx,
            IDictionary<NeighborContextKey, Dictionary<VMOpCode, int>> contextVotes,
            IDictionary<int, List<NeighborContextKey>> unknownSamples)
        {
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

                    var entries = new List<int>(instructionCount);
                    for (var i = 0; i < instructionCount; i++)
                    {
                        var vmByte = parser.Reader.ReadByte();
                        entries.Add(vmByte);
                        if (vmByte >= 0 && vmByte < parser.Operands.Length)
                            SkipOperand(parser, parser.Operands[vmByte]);
                    }

                    for (var i = 0; i < entries.Count; i++)
                    {
                        var vmByte = entries[i];
                        if (vmByte < 0 || vmByte >= parser.Operands.Length)
                            continue;

                        var prev = FindNeighborKnownOpcode(ctx.PatternMatcher, entries, i - 1, -1);
                        var next = FindNeighborKnownOpcode(ctx.PatternMatcher, entries, i + 1, +1);
                        if (prev == VMOpCode.Nop || next == VMOpCode.Nop)
                            continue;

                        var key = new NeighborContextKey(prev, next, parser.Operands[vmByte]);
                        if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                        {
                            var opcode = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                            if (opcode == VMOpCode.Nop)
                                continue;

                            if (!contextVotes.TryGetValue(key, out var opVotes))
                            {
                                opVotes = new Dictionary<VMOpCode, int>();
                                contextVotes[key] = opVotes;
                            }

                            if (!opVotes.TryGetValue(opcode, out var count))
                                count = 0;
                            opVotes[opcode] = count + 1;
                        }
                        else
                        {
                            if (!unknownSamples.TryGetValue(vmByte, out var list))
                            {
                                list = new List<NeighborContextKey>();
                                unknownSamples[vmByte] = list;
                            }

                            list.Add(key);
                        }
                    }
                }
            }
            catch
            {
                // Best effort only.
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        private VMOpCode FindNeighborKnownOpcode(
            PatternMatcher matcher,
            IReadOnlyList<int> entries,
            int start,
            int direction)
        {
            for (var i = start; i >= 0 && i < entries.Count; i += direction)
            {
                var vm = entries[i];
                if (!matcher.IsOpCodeValueKnown(vm))
                    continue;

                var opcode = matcher.GetOpCodeValue(vm);
                if (opcode != VMOpCode.Nop)
                    return opcode;
            }

            return VMOpCode.Nop;
        }

        private bool IsContextSafeOpcode(VMOpCode opCode)
        {
            switch (opCode)
            {
                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Stloc:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Pop:
                case VMOpCode.Dup:
                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                case VMOpCode.Not:
                case VMOpCode.Neg:
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                    return true;
                default:
                    return false;
            }
        }

        private int ResolveArgCount(ModuleDefinition module, int methodToken)
        {
            try
            {
                if (!(module.LookupMember(methodToken) is IMethodDescriptor descriptor))
                    return 0;

                var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
                if (signature == null)
                    return 0;

                var count = signature.ParameterTypes.Count;
                if (signature.HasThis)
                    count++;
                return count;
            }
            catch
            {
                return 0;
            }
        }

        private sealed class VmInstructionSample
        {
            public VmInstructionSample(int vmByte, object operand)
            {
                VmByte = vmByte;
                Operand = operand;
            }

            public int VmByte { get; }
            public object Operand { get; }
        }

        private sealed class VmMethodStreamSample
        {
            public VmMethodStreamSample(
                IReadOnlyList<VmInstructionSample> instructions,
                int expectedReturnStack,
                int localCount,
                int argCount)
            {
                Instructions = instructions;
                ExpectedReturnStack = expectedReturnStack;
                LocalCount = localCount;
                ArgCount = argCount;
            }

            public IReadOnlyList<VmInstructionSample> Instructions { get; }
            public int ExpectedReturnStack { get; }
            public int LocalCount { get; }
            public int ArgCount { get; }
        }

        private void InferStubNoOpHandlers(
            DevirtualizationCtx ctx,
            SelectionResult selection,
            IList<ICilLabel> values,
            IDictionary<int, int> observedVmByteHistogram)
        {
            if (ctx?.PatternMatcher == null || selection?.Method?.CilMethodBody == null || values == null)
                return;

            var inferred = 0;
            var maxByte = Math.Min(values.Count, _addressableOpcodeCount);
            for (var vmByte = 0; vmByte < maxByte; vmByte++)
            {
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (ctx.Parser?.Operands == null || vmByte < 0 || vmByte >= ctx.Parser.Operands.Length || ctx.Parser.Operands[vmByte] != 1)
                    continue;
                if (observedVmByteHistogram != null &&
                    observedVmByteHistogram.TryGetValue(vmByte, out var frequency) &&
                    frequency > 2)
                {
                    continue;
                }

                if (!(values[vmByte] is CilInstructionLabel instructionLabel) || instructionLabel.Instruction == null)
                    continue;
                if (!selection.AnalysisContext.InstructionIndexByInstruction.TryGetValue(instructionLabel.Instruction, out var index))
                    continue;

                if (!IsLikelyNoOpStub(selection.Method, index))
                    continue;

                ApplyMapping(ctx, vmByte, VMOpCode.Nop, 0.60, "stub-noop");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info($"vm 0x{vmByte:X2} -> Nop (stub-noop inference)");
                }
            }

            if (inferred > 0)
                ctx.Options.Logger.Info($"Stub-noop inference marked {inferred} VM opcodes as resolved no-ops.");
        }

        private bool IsLikelyNoOpStub(MethodDefinition method, int startIndex)
        {
            var instructions = method.CilMethodBody.Instructions;
            if (startIndex < 0 || startIndex >= instructions.Count)
                return false;

            var end = Math.Min(instructions.Count, startIndex + 12);
            var sawRet = false;
            for (var i = startIndex; i < end; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Ret)
                {
                    sawRet = true;
                    break;
                }

                // Extremely conservative: accept only short prologue/control scaffolding.
                if (op != CilOpCodes.Ldarg_0 &&
                    op != CilOpCodes.Ldfld &&
                    op != CilOpCodes.Unbox_Any &&
                    op != CilOpCodes.Stloc &&
                    op != CilOpCodes.Stloc_S &&
                    op != CilOpCodes.Stloc_0 &&
                    op != CilOpCodes.Stloc_1 &&
                    op != CilOpCodes.Stloc_2 &&
                    op != CilOpCodes.Stloc_3 &&
                    op != CilOpCodes.Ldc_I4 &&
                    op != CilOpCodes.Ldc_I4_S &&
                    op != CilOpCodes.Ldc_I4_0 &&
                    op != CilOpCodes.Ldc_I4_1 &&
                    op != CilOpCodes.Ldc_I4_2 &&
                    op != CilOpCodes.Ldc_I4_3 &&
                    op != CilOpCodes.Ldc_I4_4 &&
                    op != CilOpCodes.Ldc_I4_5 &&
                    op != CilOpCodes.Ldc_I4_6 &&
                    op != CilOpCodes.Ldc_I4_7 &&
                    op != CilOpCodes.Ldc_I4_8 &&
                    op != CilOpCodes.Br &&
                    op != CilOpCodes.Br_S &&
                    op != CilOpCodes.Nop)
                {
                    return false;
                }
            }

            return sawRet;
        }

        private bool LooksLikeCompactDupHandler(
            DevirtualizationCtx ctx,
            IList<CilInstruction> instructions,
            int startIndex)
        {
            var endExclusive = GetHandlerEndExclusive(ctx, instructions, startIndex);
            if (endExclusive <= startIndex || endExclusive - startIndex > 10)
                return false;
            if (startIndex + 7 >= endExclusive)
                return false;
            if (instructions[endExclusive - 1].OpCode != CilOpCodes.Ret)
                return false;
            if (instructions[startIndex].OpCode != CilOpCodes.Ldarg_0 ||
                instructions[startIndex + 1].OpCode != CilOpCodes.Ldfld ||
                instructions[startIndex + 2].OpCode != CilOpCodes.Ldsfld ||
                !IsCallInstruction(instructions[startIndex + 3]) ||
                !IsCallInstruction(instructions[startIndex + 4]) ||
                !IsStlocInstruction(instructions[startIndex + 5]) ||
                !IsIntLoadInstruction(instructions[startIndex + 6]) ||
                !IsUnconditionalBranchInstruction(instructions[startIndex + 7].OpCode))
            {
                return false;
            }

            if (!(instructions[startIndex + 3].Operand is IMethodDescriptor firstDescriptor) ||
                !(instructions[startIndex + 4].Operand is IMethodDescriptor secondDescriptor))
            {
                return false;
            }

            var firstSig = firstDescriptor.Signature ?? firstDescriptor.Resolve()?.Signature;
            var secondSig = secondDescriptor.Signature ?? secondDescriptor.Resolve()?.Signature;
            if (firstSig == null || secondSig == null)
            {
                return false;
            }

            if (string.Equals(firstSig.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) ||
                string.Equals(secondSig.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
            {
                return false;
            }

            for (var i = startIndex; i < endExclusive; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Pop ||
                    op == CilOpCodes.Unbox_Any ||
                    op == CilOpCodes.Newobj ||
                    op == CilOpCodes.Ldtoken ||
                    op == CilOpCodes.Castclass ||
                    op == CilOpCodes.Isinst ||
                    op == CilOpCodes.Ldelem_Ref ||
                    op == CilOpCodes.Ldflda ||
                    IsConditionalBranchInstruction(op))
                {
                    return false;
                }
            }

            return true;
        }

        private bool LooksLikeGuardedPopHandler(
            DevirtualizationCtx ctx,
            IList<CilInstruction> instructions,
            int startIndex)
        {
            var endExclusive = GetHandlerEndExclusive(ctx, instructions, startIndex);
            if (endExclusive <= startIndex || endExclusive - startIndex > 18)
                return false;
            if (instructions[endExclusive - 1].OpCode != CilOpCodes.Ret)
                return false;
            if (startIndex + 11 >= endExclusive)
                return false;
            if (instructions[startIndex].OpCode != CilOpCodes.Ldarg_0 ||
                instructions[startIndex + 1].OpCode != CilOpCodes.Ldfld ||
                instructions[startIndex + 2].OpCode != CilOpCodes.Ldsfld ||
                !IsCallInstruction(instructions[startIndex + 3]) ||
                !IsCallInstruction(instructions[startIndex + 4]) ||
                !IsStlocInstruction(instructions[startIndex + 5]) ||
                !IsIntLoadInstruction(instructions[startIndex + 6]) ||
                !IsCallInstruction(instructions[startIndex + 7]) ||
                !IsConditionalBranchInstruction(instructions[startIndex + 8].OpCode) ||
                instructions[startIndex + 9].OpCode != CilOpCodes.Pop ||
                !IsIntLoadInstruction(instructions[startIndex + 10]) ||
                !IsUnconditionalBranchInstruction(instructions[startIndex + 11].OpCode))
            {
                return false;
            }

            var popCount = 0;
            var conditionalBranchCount = 0;
            var stlocCount = 0;
            var nonVoidCallCount = 0;

            for (var i = startIndex; i < endExclusive; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Pop)
                    popCount++;
                if (IsConditionalBranchInstruction(op))
                    conditionalBranchCount++;
                if (IsStlocInstruction(instructions[i]))
                    stlocCount++;
                if (IsCallInstruction(instructions[i]))
                {
                    if (!HasReturnType(instructions[i], "System.Void"))
                        nonVoidCallCount++;
                }

                if (op == CilOpCodes.Unbox_Any ||
                    op == CilOpCodes.Newobj ||
                    op == CilOpCodes.Ldtoken ||
                    op == CilOpCodes.Castclass ||
                    op == CilOpCodes.Isinst ||
                    op == CilOpCodes.Ldelem_Ref ||
                    op == CilOpCodes.Ldflda ||
                    op == CilOpCodes.Switch)
                {
                    return false;
                }
            }

            return popCount == 1 &&
                   conditionalBranchCount >= 1 &&
                   stlocCount == 1 &&
                   nonVoidCallCount >= 2 &&
                   instructions[startIndex].OpCode == CilOpCodes.Ldarg_0 &&
                   instructions[startIndex + 1].OpCode == CilOpCodes.Ldfld;
        }

        private bool LooksLikePointerProjectionUnaryHandler(
            DevirtualizationCtx ctx,
            IList<CilInstruction> instructions,
            int startIndex)
        {
            var endExclusive = GetHandlerEndExclusive(ctx, instructions, startIndex);
            if (endExclusive <= startIndex || endExclusive - startIndex > 40)
                return false;
            if (instructions[endExclusive - 1].OpCode != CilOpCodes.Ret)
                return false;
            if (startIndex + 7 >= endExclusive)
                return false;
            if (instructions[startIndex].OpCode != CilOpCodes.Ldarg_0 ||
                instructions[startIndex + 1].OpCode != CilOpCodes.Ldfld ||
                instructions[startIndex + 2].OpCode != CilOpCodes.Ldsfld ||
                !IsCallInstruction(instructions[startIndex + 3]) ||
                !IsCallInstruction(instructions[startIndex + 4]) ||
                !IsStlocInstruction(instructions[startIndex + 5]) ||
                !IsIntLoadInstruction(instructions[startIndex + 6]) ||
                !IsUnconditionalBranchInstruction(instructions[startIndex + 7].OpCode))
            {
                return false;
            }

            var callCount = 0;
            var pointerCallCount = 0;
            var castclassCount = 0;
            var stlocCount = 0;
            var castclassIndex = -1;

            for (var i = startIndex; i < endExclusive; i++)
            {
                var instruction = instructions[i];
                var op = instruction.OpCode;
                if (IsCallInstruction(instruction))
                {
                    callCount++;
                    if (HasReturnType(instruction, "System.IntPtr"))
                        pointerCallCount++;
                }

                if (op == CilOpCodes.Castclass)
                {
                    castclassCount++;
                    if (castclassIndex < 0)
                        castclassIndex = i;
                }
                if (IsStlocInstruction(instruction))
                    stlocCount++;
                if (op == CilOpCodes.Unbox_Any ||
                    op == CilOpCodes.Newobj ||
                    op == CilOpCodes.Ldelem_Ref ||
                    op == CilOpCodes.Ldflda ||
                    op == CilOpCodes.Switch)
                {
                    return false;
                }
            }

            if (castclassIndex < 0)
                return false;

            var sawPointerProjection = false;
            for (var i = castclassIndex + 1; i + 2 < endExclusive; i++)
            {
                if (instructions[i].OpCode != CilOpCodes.Ldsfld)
                    continue;
                if (!IsCallInstruction(instructions[i + 1]))
                    continue;
                if (!HasReturnType(instructions[i + 1], "System.IntPtr"))
                    continue;
                if (!IsStlocInstruction(instructions[i + 2]))
                    continue;
                sawPointerProjection = true;
                break;
            }

            return pointerCallCount == 1 &&
                   castclassCount >= 1 &&
                   stlocCount >= 2 &&
                   callCount <= 6 &&
                   sawPointerProjection;
        }

        private bool LooksLikeStelemI1Handler(
            DevirtualizationCtx ctx,
            IList<CilInstruction> instructions,
            int startIndex)
        {
            var endExclusive = GetHandlerEndExclusive(ctx, instructions, startIndex);
            if (endExclusive <= startIndex)
                return false;

            var hasStelemI1 = false;
            var hasStelemRef = false;
            var stackLoaderCount = 0;

            for (var i = startIndex; i < endExclusive; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Stelem_I1)
                    hasStelemI1 = true;
                else if (op == CilOpCodes.Stelem_Ref)
                    hasStelemRef = true;

                if (op == CilOpCodes.Ldloc ||
                    op == CilOpCodes.Ldloc_S ||
                    op == CilOpCodes.Ldloc_0 ||
                    op == CilOpCodes.Ldloc_1 ||
                    op == CilOpCodes.Ldloc_2 ||
                    op == CilOpCodes.Ldloc_3 ||
                    op == CilOpCodes.Ldarg ||
                    op == CilOpCodes.Ldarg_0 ||
                    op == CilOpCodes.Ldarg_1 ||
                    op == CilOpCodes.Ldarg_2 ||
                    op == CilOpCodes.Ldarg_3)
                {
                    stackLoaderCount++;
                }
            }

            if (hasStelemRef || !hasStelemI1)
                return false;

            // Store-element handlers are expected to stage at least array/index/value.
            return stackLoaderCount >= 2;
        }

        private int GetHandlerEndExclusive(
            DevirtualizationCtx ctx,
            IList<CilInstruction> instructions,
            int startIndex)
        {
            if (instructions == null || startIndex < 0 || startIndex >= instructions.Count)
                return startIndex;

            var nextStart = ctx.OpcodeHandlerIndices.Values
                .Where(v => v > startIndex)
                .DefaultIfEmpty(instructions.Count)
                .Min();
            var endExclusive = Math.Min(instructions.Count, Math.Max(startIndex + 1, nextStart));
            for (var i = startIndex; i < endExclusive; i++)
            {
                if (instructions[i].OpCode == CilOpCodes.Ret)
                    return i + 1;
            }

            return endExclusive;
        }

        private bool IsCallInstruction(CilInstruction instruction)
        {
            if (instruction == null)
                return false;
            return instruction.OpCode == CilOpCodes.Call || instruction.OpCode == CilOpCodes.Callvirt;
        }

        private bool HasReturnType(CilInstruction instruction, string returnTypeFullName)
        {
            if (!IsCallInstruction(instruction))
                return false;
            if (!(instruction.Operand is IMethodDescriptor descriptor))
                return false;

            var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
            if (signature == null)
                return false;

            var fullName = signature.ReturnType?.FullName;
            var name = signature.ReturnType?.Name?.ToString();
            return string.Equals(fullName, returnTypeFullName, StringComparison.Ordinal) ||
                   string.Equals(name, returnTypeFullName, StringComparison.Ordinal) ||
                   string.Equals(name, returnTypeFullName.Replace("System.", string.Empty, StringComparison.Ordinal), StringComparison.Ordinal);
        }

        private bool IsStlocInstruction(CilInstruction instruction)
        {
            if (instruction == null)
                return false;

            var op = instruction.OpCode;
            return op == CilOpCodes.Stloc ||
                   op == CilOpCodes.Stloc_S ||
                   op == CilOpCodes.Stloc_0 ||
                   op == CilOpCodes.Stloc_1 ||
                   op == CilOpCodes.Stloc_2 ||
                   op == CilOpCodes.Stloc_3;
        }

        private bool IsConditionalBranchInstruction(CilOpCode op)
        {
            return op == CilOpCodes.Brtrue ||
                   op == CilOpCodes.Brtrue_S ||
                   op == CilOpCodes.Brfalse ||
                   op == CilOpCodes.Brfalse_S ||
                   op == CilOpCodes.Blt ||
                   op == CilOpCodes.Blt_S ||
                   op == CilOpCodes.Blt_Un ||
                   op == CilOpCodes.Blt_Un_S ||
                   op == CilOpCodes.Switch;
        }

        private bool IsUnconditionalBranchInstruction(CilOpCode op)
        {
            return op == CilOpCodes.Br || op == CilOpCodes.Br_S;
        }

        private bool IsIntLoadInstruction(CilInstruction instruction)
        {
            if (instruction == null)
                return false;

            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldc_I4:
                case CilCode.Ldc_I4_S:
                case CilCode.Ldc_I4_0:
                case CilCode.Ldc_I4_1:
                case CilCode.Ldc_I4_2:
                case CilCode.Ldc_I4_3:
                case CilCode.Ldc_I4_4:
                case CilCode.Ldc_I4_5:
                case CilCode.Ldc_I4_6:
                case CilCode.Ldc_I4_7:
                case CilCode.Ldc_I4_8:
                    return true;
                default:
                    return false;
            }
        }

        private HashSet<int> BuildHandlerSignatureGrams(MethodDefinition method, int startIndex, int maxOps)
        {
            var result = new HashSet<int>();
            var instructions = method.CilMethodBody.Instructions;
            if (startIndex < 0 || startIndex >= instructions.Count || maxOps < 2)
                return result;

            var sequence = new List<int>(maxOps);
            var end = Math.Min(instructions.Count, startIndex + maxOps);
            for (var i = startIndex; i < end; i++)
            {
                sequence.Add((int) instructions[i].OpCode.Code);
                if (instructions[i].OpCode == CilOpCodes.Ret)
                    break;
            }

            for (var i = 0; i + 1 < sequence.Count; i++)
            {
                var gram = (sequence[i] * 1000003) ^ sequence[i + 1];
                result.Add(gram);
            }

            return result;
        }

        private double DiceCoefficient(HashSet<int> left, HashSet<int> right)
        {
            if (left == null || right == null || left.Count == 0 || right.Count == 0)
                return 0.0;

            var intersection = 0;
            var small = left.Count <= right.Count ? left : right;
            var large = ReferenceEquals(small, left) ? right : left;
            foreach (var value in small)
            {
                if (large.Contains(value))
                    intersection++;
            }

            return (2.0 * intersection) / (left.Count + right.Count);
        }

        private Dictionary<int, OperandObservation> CollectOperandObservations(DevirtualizationCtx ctx)
        {
            var parser = ctx.Parser;
            var stream = parser.Reader.BaseStream;
            var originalPosition = stream.Position;
            var observations = new Dictionary<int, OperandObservation>();

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
                            var observation = GetOrCreateObservation(observations, vmByte);
                            observation.Add(operand, ctx.Module);
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
                HandleBestEffortFailure(ctx, "operand observation collection", ex);
                return new Dictionary<int, OperandObservation>();
            }
            finally
            {
                stream.Position = originalPosition;
            }

            return observations;
        }

        private OperandObservation GetOrCreateObservation(
            IDictionary<int, OperandObservation> observations,
            int vmByte)
        {
            if (observations.TryGetValue(vmByte, out var existing))
                return existing;

            var created = new OperandObservation(_heuristicsProfile.OperandObservationMaxSamples);
            observations[vmByte] = created;
            return created;
        }

        private VMOpCode InferOpcodeFromObservation(OperandObservation observation)
        {
            if (observation == null || observation.SampleCount <= 0)
                return VMOpCode.Nop;

            // Low-sample, high-purity token observations are still valuable
            // for uncommon handlers (for example ctor-heavy Newobj bytes).
            if (observation.SampleCount >= 2)
            {
                if (observation.MethodTokenCount == observation.SampleCount)
                {
                    if (observation.CtorMethodCount == observation.SampleCount)
                        return VMOpCode.Newobj;
                    return VMOpCode.Call;
                }

                if (observation.FieldTokenCount == observation.SampleCount)
                {
                    return observation.InstanceFieldCount > observation.StaticFieldCount
                        ? VMOpCode.Ldfld
                        : VMOpCode.Ldsfld;
                }

                if (observation.UserStringTokenCount == observation.SampleCount)
                    return VMOpCode.Ldstr;
            }

            // Rare, strongly-typed token bytes are often Newarr in Reactor VMs.
            if (observation.SampleCount >= 3 &&
                observation.SampleCount <= 6 &&
                observation.TypeTokenCount == observation.SampleCount)
            {
                return VMOpCode.Newarr;
            }

            if (observation.SampleCount < 3)
                return VMOpCode.Nop;

            if (observation.MethodTokenCount >= 3 &&
                observation.MethodTokenCount * 10 >= observation.SampleCount * 8)
            {
                if (observation.CtorMethodCount * 10 >= observation.MethodTokenCount * 7)
                    return VMOpCode.Newobj;

                return VMOpCode.Call;
            }

            if (observation.FieldTokenCount >= 3 &&
                observation.FieldTokenCount * 10 >= observation.SampleCount * 8)
            {
                if (observation.InstanceFieldCount > observation.StaticFieldCount)
                    return VMOpCode.Ldfld;
                return VMOpCode.Ldsfld;
            }

            if (observation.UserStringTokenCount >= 3 &&
                observation.UserStringTokenCount * 10 >= observation.SampleCount * 8)
            {
                return VMOpCode.Ldstr;
            }

            return VMOpCode.Nop;
        }

        private sealed class OperandObservation
        {
            private readonly int _maxSamples;

            public OperandObservation(int maxSamples)
            {
                _maxSamples = maxSamples > 0 ? maxSamples : 96;
            }

            public int SampleCount { get; private set; }
            public int MethodTokenCount { get; private set; }
            public int CtorMethodCount { get; private set; }
            public int FieldTokenCount { get; private set; }
            public int StaticFieldCount { get; private set; }
            public int InstanceFieldCount { get; private set; }
            public int UserStringTokenCount { get; private set; }
            public int TypeTokenCount { get; private set; }

            public void Add(int operand, ModuleDefinition module)
            {
                if (SampleCount >= _maxSamples)
                    return;
                SampleCount++;

                var table = (uint) operand & 0xFF000000u;
                if (table == 0x70000000u)
                {
                    UserStringTokenCount++;
                    return;
                }

                try
                {
                    var member = module.LookupMember(operand);
                    if (member is IMethodDescriptor method)
                    {
                        MethodTokenCount++;
                        if (LooksLikeConstructor(method))
                            CtorMethodCount++;
                    }
                    else if (member is IFieldDescriptor field)
                    {
                        FieldTokenCount++;
                        var resolved = field.Resolve();
                        if (resolved != null && resolved.IsStatic)
                            StaticFieldCount++;
                        else
                            InstanceFieldCount++;
                    }
                    else if (member is ITypeDefOrRef)
                    {
                        TypeTokenCount++;
                    }
                }
                catch
                {
                    // Ignore malformed or non-resolvable operands.
                }
            }

            private bool LooksLikeConstructor(IMethodDescriptor method)
            {
                var name = method.Name ?? method.Resolve()?.Name;
                return string.Equals(name, ".ctor", StringComparison.Ordinal) ||
                       string.Equals(name, ".cctor", StringComparison.Ordinal);
            }
        }

        private void SkipOperand(Core.Parser.ResourceParser parser, byte operandType)
        {
            switch (operandType)
            {
                case 1:
                    parser.ReadEncryptedByte();
                    break;
                case 2:
                    parser.Reader.ReadInt64();
                    break;
                case 3:
                    parser.Reader.ReadSingle();
                    break;
                case 4:
                    parser.Reader.ReadDouble();
                    break;
                case 5:
                {
                    var count = parser.ReadEncryptedByte();
                    for (var i = 0; i < count; i++)
                        parser.ReadEncryptedByte();
                    break;
                }
            }
        }
    }
}
