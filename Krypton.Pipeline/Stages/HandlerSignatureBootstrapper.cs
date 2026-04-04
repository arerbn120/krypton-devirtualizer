using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.Architecture;
using Krypton.Core.Signatures;

namespace Krypton.Pipeline.Stages
{
    internal sealed class HandlerSignatureBootstrapper
    {
        public void ApplySignatureCatalogBootstrap(
            DevirtualizationCtx ctx,
            MethodDefinition method,
            IDictionary<CilInstruction, int> instructionIndexByInstruction,
            IList<ICilLabel> values,
            int addressableOpcodeCount,
            OpcodeMappingHeuristicsProfile heuristicsProfile,
            Func<MethodDefinition, int, int, HashSet<int>> buildHandlerSignatureGrams,
            Func<HashSet<int>, HashSet<int>, double> diceCoefficient,
            Func<VMOpCode, bool> isSimilaritySafeOpcode,
            Func<VMOpCode, byte, bool> isOperandTypeCompatible,
            Action<int, VMOpCode, double, string> applyMapping,
            Action<string, Exception> onBestEffortFailure)
        {
            if (ctx?.PatternMatcher == null || method?.CilMethodBody == null || values == null)
                return;

            var inputPath = ResolveSignatureInputPath(ctx);
            if (string.IsNullOrWhiteSpace(inputPath))
                return;

            HandlerSignatureCatalog catalog;
            try
            {
                catalog = HandlerSignatureCatalogSerializer.Load(inputPath);
            }
            catch (Exception ex)
            {
                onBestEffortFailure?.Invoke("signature catalog bootstrap load", ex);
                return;
            }

            var threshold = heuristicsProfile.SimilarityDiceThreshold;
            var thresholdEnv = Environment.GetEnvironmentVariable("KRYPTON_SIGNATURE_SIMILARITY");
            if (!string.IsNullOrWhiteSpace(thresholdEnv) &&
                double.TryParse(thresholdEnv, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var parsedThreshold))
            {
                threshold = parsedThreshold;
            }
            if (threshold <= 0.0 || threshold > 1.0)
                threshold = heuristicsProfile.SimilarityDiceThreshold;
            var minSharedGrams = 4;
            var minSharedEnv = Environment.GetEnvironmentVariable("KRYPTON_SIGNATURE_MIN_SHARED_GRAMS");
            if (!string.IsNullOrWhiteSpace(minSharedEnv) &&
                int.TryParse(minSharedEnv, out var parsedMinShared))
            {
                minSharedGrams = parsedMinShared;
            }
            if (minSharedGrams < 1)
                minSharedGrams = 1;

            var indexedRecords = new List<(VMOpCode opCode, byte operandType, HashSet<int> grams, int vmByte)>();
            foreach (var record in catalog.Records.Where(r => r != null && r.SignatureGrams != null && r.SignatureGrams.Count > 0))
            {
                if (!Enum.TryParse<VMOpCode>(record.OpCode, ignoreCase: true, out var mappedOpCode))
                    continue;
                if (mappedOpCode == VMOpCode.Nop || !isSimilaritySafeOpcode(mappedOpCode))
                    continue;

                indexedRecords.Add((mappedOpCode, record.OperandType, new HashSet<int>(record.SignatureGrams), record.VmByte));
            }

            if (indexedRecords.Count == 0)
                return;

            var maxVmByte = Math.Min(values.Count, addressableOpcodeCount);
            var inferred = 0;
            for (var vmByte = 0; vmByte < maxVmByte; vmByte++)
            {
                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (!(values[vmByte] is CilInstructionLabel label) || label.Instruction == null)
                    continue;
                if (instructionIndexByInstruction == null || !instructionIndexByInstruction.TryGetValue(label.Instruction, out var startIndex))
                    continue;

                var currentGrams = buildHandlerSignatureGrams(method, startIndex, heuristicsProfile.SignatureGramMaxOps);
                if (currentGrams.Count == 0)
                    continue;

                var hasOperandType = ctx.TryGetOperandType(vmByte, out var operandType);
                var bestScore = 0.0;
                var bestOpcode = VMOpCode.Nop;
                var bestReferenceVmByte = -1;
                var bestSharedGrams = 0;

                foreach (var record in indexedRecords)
                {
                    if (hasOperandType && record.operandType != operandType)
                        continue;
                    if (hasOperandType && !isOperandTypeCompatible(record.opCode, operandType))
                        continue;

                    var shared = CountSharedGrams(currentGrams, record.grams);
                    if (shared < minSharedGrams)
                        continue;

                    var score = diceCoefficient(currentGrams, record.grams);
                    if (score < bestScore)
                        continue;
                    if (Math.Abs(score - bestScore) < 1e-9 && shared < bestSharedGrams)
                        continue;

                    bestScore = score;
                    bestSharedGrams = shared;
                    bestOpcode = record.opCode;
                    bestReferenceVmByte = record.vmByte;
                }

                if (bestOpcode == VMOpCode.Nop || bestScore < threshold)
                    continue;
                if (hasOperandType && !isOperandTypeCompatible(bestOpcode, operandType))
                    continue;

                applyMapping(vmByte, bestOpcode, bestScore, "signature-bootstrap");
                inferred++;

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                {
                    ctx.Options.Logger.Info(
                        $"vm 0x{vmByte:X2} -> {bestOpcode} (signature-bootstrap {bestScore:F2}, ref 0x{bestReferenceVmByte:X2})");
                }
            }

            if (inferred > 0)
            {
                ctx.Options.Logger.Info(
                    $"Signature bootstrap mapped {inferred} additional VM opcodes from '{Path.GetFileName(inputPath)}'.");
            }
        }

        public void ExportHandlerSignatureCatalog(
            DevirtualizationCtx ctx,
            MethodDefinition method,
            IDictionary<CilInstruction, int> instructionIndexByInstruction,
            IList<ICilLabel> values,
            int addressableOpcodeCount,
            OpcodeMappingHeuristicsProfile heuristicsProfile,
            Func<MethodDefinition, int, int, HashSet<int>> buildHandlerSignatureGrams,
            Action<string, Exception> onBestEffortFailure)
        {
            if (ctx?.PatternMatcher == null || method?.CilMethodBody == null || values == null)
                return;

            var outputPath = ResolveSignatureOutputPath(ctx);
            if (string.IsNullOrWhiteSpace(outputPath))
                return;

            var maxVmByte = Math.Min(values.Count, addressableOpcodeCount);
            var records = new List<HandlerSignatureRecord>();
            for (var vmByte = 0; vmByte < maxVmByte; vmByte++)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (!(values[vmByte] is CilInstructionLabel label) || label.Instruction == null)
                    continue;
                if (instructionIndexByInstruction == null || !instructionIndexByInstruction.TryGetValue(label.Instruction, out var startIndex))
                    continue;

                var mapped = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (mapped == VMOpCode.Nop)
                    continue;

                var grams = buildHandlerSignatureGrams(method, startIndex, heuristicsProfile.SignatureGramMaxOps);
                if (grams.Count == 0)
                    continue;

                var confidence = 0.0;
                var source = "unknown";
                if (ctx.OpcodeConfidence != null && ctx.OpcodeConfidence.TryGetValue(vmByte, out var entry))
                {
                    confidence = entry.Confidence;
                    source = entry.Source ?? source;
                }

                ctx.TryGetOperandType(vmByte, out var operandType);
                records.Add(new HandlerSignatureRecord
                {
                    VmByte = vmByte,
                    OpCode = mapped.ToString(),
                    OperandType = operandType,
                    Confidence = confidence,
                    Source = source,
                    SignatureGrams = grams.OrderBy(g => g).ToList()
                });
            }

            if (records.Count == 0)
                return;

            var catalog = new HandlerSignatureCatalog
            {
                Version = "1",
                SourceAssembly = ctx.Module?.Name ?? string.Empty,
                DispatcherMethod = method.FullName ?? string.Empty,
                SignatureGramMaxOps = heuristicsProfile.SignatureGramMaxOps,
                HandlerCount = maxVmByte,
                Records = records,
                CreatedUtc = DateTime.UtcNow
            };

            try
            {
                HandlerSignatureCatalogSerializer.Save(catalog, outputPath);
                ctx.Options.Logger.Info(
                    $"Exported {records.Count} handler signatures to '{outputPath}'.");
            }
            catch (Exception ex)
            {
                onBestEffortFailure?.Invoke("signature catalog export", ex);
            }
        }

        private static string ResolveSignatureInputPath(DevirtualizationCtx ctx)
        {
            var configured = Environment.GetEnvironmentVariable("KRYPTON_SIGNATURE_INPUT");
            if (string.IsNullOrWhiteSpace(configured))
                return null;
            return Path.GetFullPath(configured);
        }

        private static string ResolveSignatureOutputPath(DevirtualizationCtx ctx)
        {
            var configured = Environment.GetEnvironmentVariable("KRYPTON_SIGNATURE_OUTPUT");
            if (string.IsNullOrWhiteSpace(configured))
                return null;
            return Path.GetFullPath(configured);
        }

        private static int CountSharedGrams(HashSet<int> left, HashSet<int> right)
        {
            if (left == null || right == null || left.Count == 0 || right.Count == 0)
                return 0;

            var intersection = 0;
            var small = left.Count <= right.Count ? left : right;
            var large = ReferenceEquals(small, left) ? right : left;
            foreach (var value in small)
            {
                if (large.Contains(value))
                    intersection++;
            }

            return intersection;
        }
    }
}
