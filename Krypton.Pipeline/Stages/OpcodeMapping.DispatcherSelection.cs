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
        public DispatcherSelection LocateDispatcher(
            DevirtualizationCtx ctx,
            byte[] operandTypes,
            int observedMaxVmByte,
            IDictionary<int, int> observedVmByteHistogram)
        {
            var selection = FindOpCodeMethod(ctx.Module, operandTypes, observedMaxVmByte, observedVmByteHistogram);
            if (selection == null)
                return null;

            return new DispatcherSelection(selection.Method, selection.SwitchInstruction, selection.AnalysisContext);
        }

        private SelectionResult FindOpCodeMethod(
            ModuleDefinition Module,
            byte[] operandTypes,
            int observedMaxVmByte,
            IDictionary<int, int> observedVmByteHistogram)
        {
            var candidates = new List<CandidateDescriptor>();
            var methodContexts = new Dictionary<MethodDefinition, MethodAnalysisContext>();

            var maxHandlerCount = 0;
            foreach (var type in Module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.IsIL || method.CilMethodBody?.Instructions == null)
                        continue;

                    foreach (var candidateSwitch in method.CilMethodBody.Instructions.Where(i => i.OpCode == CilOpCodes.Switch))
                    {
                        var handlerCount = GetSwitchTargetCount(candidateSwitch);
                        if (handlerCount > maxHandlerCount)
                            maxHandlerCount = handlerCount;
                    }
                }
            }

            var minimumDispatcherHandlers = Math.Max(
                _dispatcherProfile.MinDispatcherHandlersAbsolute,
                maxHandlerCount / Math.Max(1, _dispatcherProfile.MinDispatcherHandlersDivisor));
            var minimumObservedHandlers = observedMaxVmByte >= 0 ? observedMaxVmByte + 1 : 0;

            var bestQualityScore = int.MinValue;
            var bestObservedMappingScore = int.MinValue;
            var bestUniqueOpcodes = -1;
            var bestMappedCount = -1;
            var bestHandlerCount = -1;
            var bestInstructionCount = -1;

            foreach (var type in Module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.IsIL || method.CilMethodBody?.Instructions == null)
                        continue;

                    var switches = method.CilMethodBody.Instructions
                        .Where(i => i.OpCode == CilOpCodes.Switch)
                        .ToList();
                    if (switches.Count == 0)
                        continue;

                    foreach (var candidateSwitch in switches)
                    {
                        if (!(candidateSwitch.Operand is IList<ICilLabel> labels) || labels.Count == 0)
                            continue;

                        var context = GetOrCreateMethodContext(methodContexts, method);
                        var evaluation = EvaluateSwitchCandidate(
                            context,
                            method,
                            labels,
                            sampleBudget: _dispatcherProfile.InitialSampleBudget,
                            operandTypes: operandTypes,
                            minimumObservedHandlers: minimumObservedHandlers,
                            observedVmByteHistogram: observedVmByteHistogram);
                        if (evaluation.HandlerCount <= 0)
                            continue;

                        candidates.Add(new CandidateDescriptor(
                            method,
                            candidateSwitch,
                            evaluation,
                            method.CilMethodBody.Instructions.Count,
                            context));
                    }
                }
            }

            var selectionPool = candidates
                .Where(c => c.Evaluation.HandlerCount >= minimumDispatcherHandlers &&
                            (minimumObservedHandlers <= 0 || c.Evaluation.HandlerCount >= minimumObservedHandlers))
                .ToList();
            if (selectionPool.Count == 0)
                selectionPool = candidates;

            var fullEvaluationCount = Math.Max(
                _dispatcherProfile.FullEvaluationMinCandidates,
                Math.Min(
                    _dispatcherProfile.FullEvaluationMaxCandidates,
                    (int) Math.Ceiling(Math.Sqrt(selectionPool.Count) * _dispatcherProfile.FullEvaluationScale)));
            foreach (var candidate in selectionPool
                         .OrderByDescending(c => c.Evaluation.QualityScore)
                         .ThenByDescending(c => c.Evaluation.HandlerCount)
                         .Take(fullEvaluationCount))
            {
                if (candidate.SwitchInstruction.Operand is IList<ICilLabel> labels)
                {
                    candidate.Evaluation = EvaluateSwitchCandidate(
                        candidate.AnalysisContext,
                        candidate.Method,
                        labels,
                        sampleBudget: 0,
                        operandTypes: operandTypes,
                        minimumObservedHandlers: minimumObservedHandlers,
                        observedVmByteHistogram: observedVmByteHistogram);
                }
            }

            SelectionResult bestSelection = null;
            foreach (var candidate in selectionPool)
            {
                var evaluation = candidate.Evaluation;
                var instructionCount = candidate.InstructionCount;
                if (evaluation.ObservedMappingScore > bestObservedMappingScore ||
                    (evaluation.ObservedMappingScore == bestObservedMappingScore &&
                     evaluation.QualityScore > bestQualityScore) ||
                    (evaluation.ObservedMappingScore == bestObservedMappingScore &&
                     evaluation.QualityScore == bestQualityScore &&
                     evaluation.UniqueOpcodes > bestUniqueOpcodes) ||
                    (evaluation.ObservedMappingScore == bestObservedMappingScore &&
                     evaluation.QualityScore == bestQualityScore &&
                     evaluation.UniqueOpcodes == bestUniqueOpcodes &&
                     evaluation.MappedCount > bestMappedCount) ||
                    (evaluation.ObservedMappingScore == bestObservedMappingScore &&
                     evaluation.QualityScore == bestQualityScore &&
                     evaluation.UniqueOpcodes == bestUniqueOpcodes &&
                     evaluation.MappedCount == bestMappedCount && evaluation.HandlerCount > bestHandlerCount) ||
                    (evaluation.ObservedMappingScore == bestObservedMappingScore &&
                     evaluation.QualityScore == bestQualityScore &&
                     evaluation.UniqueOpcodes == bestUniqueOpcodes &&
                     evaluation.MappedCount == bestMappedCount && evaluation.HandlerCount == bestHandlerCount &&
                     instructionCount > bestInstructionCount))
                {
                    bestObservedMappingScore = evaluation.ObservedMappingScore;
                    bestQualityScore = evaluation.QualityScore;
                    bestUniqueOpcodes = evaluation.UniqueOpcodes;
                    bestMappedCount = evaluation.MappedCount;
                    bestHandlerCount = evaluation.HandlerCount;
                    bestInstructionCount = instructionCount;
                    bestSelection = new SelectionResult(
                        candidate.Method,
                        candidate.SwitchInstruction,
                        candidate.AnalysisContext);
                }
            }

            if (string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_LOG_DISPATCHER_CANDIDATES"),
                    "1",
                    StringComparison.Ordinal))
            {
                foreach (var candidate in selectionPool
                             .OrderByDescending(c => c.Evaluation.ObservedMappingScore)
                             .ThenByDescending(c => c.Evaluation.QualityScore)
                             .Take(_dispatcherProfile.CandidateLogLimit))
                {
                    var switchTargets = GetSwitchTargetCount(candidate.SwitchInstruction);
                    Console.WriteLine(
                        $"[dispatcher-candidate] method={candidate.Method.FullName} switch={switchTargets} " +
                        $"obs={candidate.Evaluation.ObservedMappingScore} quality={candidate.Evaluation.QualityScore} " +
                        $"mapped={candidate.Evaluation.MappedCount} unique={candidate.Evaluation.UniqueOpcodes}");
                }
            }

            return bestSelection;
        }

        private MethodAnalysisContext GetOrCreateMethodContext(
            IDictionary<MethodDefinition, MethodAnalysisContext> contexts,
            MethodDefinition method)
        {
            if (contexts.TryGetValue(method, out var existing))
                return existing;

            var created = new MethodAnalysisContext(method);
            contexts[method] = created;
            return created;
        }

        private VMOpCode GetMappedOpcode(
            MethodAnalysisContext context,
            MethodDefinition method,
            int index,
            bool allowFallback)
        {
            var cache = allowFallback ? context.HandlerOpcodeCache : context.StrictHandlerOpcodeCache;
            if (cache.TryGetValue(index, out var cached))
                return cached;

            var resolved = context.Matcher.FindOpCode(method, index, allowFallback);
            cache[index] = resolved;
            return resolved;
        }

        private sealed class SelectionResult
        {
            public SelectionResult(
                MethodDefinition method,
                CilInstruction switchInstruction,
                MethodAnalysisContext analysisContext)
            {
                Method = method;
                SwitchInstruction = switchInstruction;
                AnalysisContext = analysisContext;
            }

            public MethodDefinition Method { get; }
            public CilInstruction SwitchInstruction { get; }
            public MethodAnalysisContext AnalysisContext { get; }
        }

        private sealed class MethodAnalysisContext
        {
            public MethodAnalysisContext(MethodDefinition method)
            {
                Matcher = new PatternMatcher();
                HandlerOpcodeCache = new Dictionary<int, VMOpCode>();
                StrictHandlerOpcodeCache = new Dictionary<int, VMOpCode>();
                InstructionIndexByInstruction = new Dictionary<CilInstruction, int>();

                var instructions = method.CilMethodBody.Instructions;
                for (var i = 0; i < instructions.Count; i++)
                {
                    if (!InstructionIndexByInstruction.ContainsKey(instructions[i]))
                        InstructionIndexByInstruction[instructions[i]] = i;
                }
            }

            public PatternMatcher Matcher { get; }
            public Dictionary<int, VMOpCode> HandlerOpcodeCache { get; }
            public Dictionary<int, VMOpCode> StrictHandlerOpcodeCache { get; }
            public Dictionary<CilInstruction, int> InstructionIndexByInstruction { get; }
        }

        private sealed class CandidateDescriptor
        {
            public CandidateDescriptor(
                MethodDefinition method,
                CilInstruction switchInstruction,
                CandidateEvaluation evaluation,
                int instructionCount,
                MethodAnalysisContext analysisContext)
            {
                Method = method;
                SwitchInstruction = switchInstruction;
                Evaluation = evaluation;
                InstructionCount = instructionCount;
                AnalysisContext = analysisContext;
            }

            public MethodDefinition Method { get; }
            public CilInstruction SwitchInstruction { get; }
            public CandidateEvaluation Evaluation { get; set; }
            public int InstructionCount { get; }
            public MethodAnalysisContext AnalysisContext { get; }
        }

        private CandidateEvaluation EvaluateSwitchCandidate(
            MethodAnalysisContext context,
            MethodDefinition method,
            IList<ICilLabel> labels,
            int sampleBudget,
            byte[] operandTypes,
            int minimumObservedHandlers,
            IDictionary<int, int> observedVmByteHistogram)
        {
            var opcodeFrequency = new Dictionary<VMOpCode, int>();
            var mappedCount = 0;
            var maxSingleOpcodeCount = 0;
            var sampledHandlers = 0;
            var operandCompatibleCount = 0;
            var operandIncompatibleCount = 0;

            var addressableCount = Math.Min(labels.Count, _addressableOpcodeCount);
            if (addressableCount <= 0)
                return new CandidateEvaluation(int.MinValue, 0, 0, 0, 0);

            var fullScan = sampleBudget <= 0 || sampleBudget >= addressableCount;
            var stride = fullScan ? 1 : Math.Max(1, addressableCount / sampleBudget);
            var limit = fullScan ? addressableCount : sampleBudget;

            for (var labelIndex = 0; labelIndex < addressableCount && sampledHandlers < limit; labelIndex += stride)
            {
                var label = labels[labelIndex];
                if (!(label is CilInstructionLabel instructionLabel) || instructionLabel.Instruction == null)
                    continue;

                if (!context.InstructionIndexByInstruction.TryGetValue(instructionLabel.Instruction, out var index))
                    continue;

                sampledHandlers++;
                var mapped = GetMappedOpcode(context, method, index, allowFallback: false);
                if (mapped == VMOpCode.Nop)
                    continue;

                mappedCount++;
                if (labelIndex >= 0 && operandTypes != null && labelIndex < operandTypes.Length)
                {
                    if (IsOperandTypeCompatible(mapped, operandTypes[labelIndex]))
                        operandCompatibleCount++;
                    else
                        operandIncompatibleCount++;
                }

                if (!opcodeFrequency.TryGetValue(mapped, out var count))
                    count = 0;
                count++;
                opcodeFrequency[mapped] = count;
                if (count > maxSingleOpcodeCount)
                    maxSingleOpcodeCount = count;
            }

            var uniqueOpcodes = opcodeFrequency.Count;
            var handlerCount = addressableCount;
            if (handlerCount <= 0 || sampledHandlers <= 0)
                return new CandidateEvaluation(int.MinValue, 0, 0, 0, 0);

            var coveragePermille = (mappedCount * 1000) / sampledHandlers;
            var diversityPermille = (uniqueOpcodes * 1000) / sampledHandlers;
            var dominancePermille = mappedCount == 0 ? 1000 : (maxSingleOpcodeCount * 1000) / mappedCount;
            var compatibilityPermille = mappedCount == 0 ? 0 : (operandCompatibleCount * 1000) / mappedCount;
            var incompatibilityPermille = mappedCount == 0 ? 0 : (operandIncompatibleCount * 1000) / mappedCount;
            var observedMappingScore = EvaluateObservedMappingScore(
                context,
                method,
                labels,
                operandTypes,
                observedVmByteHistogram);

            // Prefer structurally rich dispatchers:
            // high coverage, high opcode diversity, low single-opcode dominance.
            var qualityScore =
                uniqueOpcodes * 10000 +
                coveragePermille * 120 +
                diversityPermille * 80 -
                dominancePermille * 100 +
                compatibilityPermille * 70 -
                incompatibilityPermille * 180 +
                Math.Min(handlerCount, 512);

            if (minimumObservedHandlers > 0 && handlerCount < minimumObservedHandlers)
                qualityScore -= 2_000_000;

            return new CandidateEvaluation(
                qualityScore,
                mappedCount,
                uniqueOpcodes,
                handlerCount,
                observedMappingScore);
        }

        private sealed class CandidateEvaluation
        {
            public CandidateEvaluation(
                int qualityScore,
                int mappedCount,
                int uniqueOpcodes,
                int handlerCount,
                int observedMappingScore)
            {
                QualityScore = qualityScore;
                MappedCount = mappedCount;
                UniqueOpcodes = uniqueOpcodes;
                HandlerCount = handlerCount;
                ObservedMappingScore = observedMappingScore;
            }

            public int QualityScore { get; }
            public int MappedCount { get; }
            public int UniqueOpcodes { get; }
            public int HandlerCount { get; }
            public int ObservedMappingScore { get; }
        }

        private int EvaluateObservedMappingScore(
            MethodAnalysisContext context,
            MethodDefinition method,
            IList<ICilLabel> labels,
            byte[] operandTypes,
            IDictionary<int, int> observedVmByteHistogram)
        {
            if (observedVmByteHistogram == null || observedVmByteHistogram.Count == 0)
                return 0;

            var score = 0;
            var addressableCount = Math.Min(labels.Count, _addressableOpcodeCount);
            foreach (var entry in observedVmByteHistogram)
            {
                var vmByte = entry.Key;
                var frequency = entry.Value;
                if (vmByte < 0 || vmByte >= addressableCount)
                    continue;
                if (!(labels[vmByte] is CilInstructionLabel instructionLabel) || instructionLabel.Instruction == null)
                    continue;
                if (!context.InstructionIndexByInstruction.TryGetValue(instructionLabel.Instruction, out var index))
                    continue;

                var mapped = GetMappedOpcode(context, method, index, allowFallback: false);
                if (mapped == VMOpCode.Nop)
                    continue;

                score += Math.Max(1, frequency);
                if (operandTypes != null && vmByte >= 0 && vmByte < operandTypes.Length)
                {
                    if (IsOperandTypeCompatible(mapped, operandTypes[vmByte]))
                        score += Math.Max(1, frequency / 2);
                    else
                        score -= Math.Max(1, frequency / 2);
                }
            }

            return score;
        }

        private int GetSwitchTargetCount(CilInstruction switchInstruction)
        {
            if (switchInstruction?.Operand is IList<ICilLabel> labels)
                return labels.Count;
            if (switchInstruction?.Operand is IEnumerable<ICilLabel> enumerable)
                return enumerable.Count();
            return -1;
        }

        private bool IsOperandTypeCompatible(VMOpCode opCode, byte operandType)
        {
            switch (opCode)
            {
                case VMOpCode.Nop:
                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Pop:
                case VMOpCode.Dup:
                case VMOpCode.Ret:
                case VMOpCode.EndFinally:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                case VMOpCode.Not:
                case VMOpCode.Neg:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                    return operandType == 0;

                case VMOpCode.Leave:
                    return operandType == 0 || operandType == 1;

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
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldfld:
                case VMOpCode.Stsfld:
                case VMOpCode.Stfld:
                case VMOpCode.Ldelema:
                case VMOpCode.Ldobj:
                case VMOpCode.Stobj:
                case VMOpCode.Ldtoken:
                    return operandType == 1;

                case VMOpCode.Switch:
                    return operandType == 5;

                default:
                    return true;
            }
        }
    }
}
