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
    public partial class OpcodeMapping : IStage, IOpcodeMapper, IDispatcherLocator
    {
        private DispatcherStrategyProfile _dispatcherProfile = new DispatcherStrategyProfile();

        private OpcodeMappingHeuristicsProfile _heuristicsProfile = new OpcodeMappingHeuristicsProfile();

        private int _addressableOpcodeCount = byte.MaxValue + 1;

        private SelectionResult _currentSelection;

        private IList<ICilLabel> _currentSwitchLabels = Array.Empty<ICilLabel>();

        private readonly HandlerSignatureBootstrapper _handlerSignatureBootstrapper = new HandlerSignatureBootstrapper();

        public string Name => nameof(OpcodeMapping);

        public void Run(DevirtualizationCtx Ctx)
        {
            var mapper = Ctx.OpcodeMapper ?? this;
            if (!ReferenceEquals(mapper, this))
            {
                mapper.MapOpcodes(Ctx);
                return;
            }

            MapOpcodes(Ctx);
        }

        public void MapOpcodes(DevirtualizationCtx Ctx)
        {
            Ctx.OpcodeConfidence = new Dictionary<int, OpcodeMappingConfidence>();
            var observedVmByteHistogram = GetObservedVmByteHistogram(Ctx);
            _dispatcherProfile = new DispatcherStrategyProfile();
            _heuristicsProfile = new OpcodeMappingHeuristicsProfile();
            _addressableOpcodeCount = GetAddressableOpcodeCount();
            PatternPriorityRegistry.Configure(null);
            var observedMaxVmByte = observedVmByteHistogram.Count == 0 ? -1 : observedVmByteHistogram.Keys.Max();
            var operandTypes = Ctx.GetOperandTypes();
            var selection = (Ctx.DispatcherLocator ?? this).LocateDispatcher(
                Ctx,
                operandTypes,
                observedMaxVmByte,
                observedVmByteHistogram);
            if (selection?.Method == null || selection.SwitchInstruction == null)
                throw new DevirtualizationException("Could not locate Opcode Handler method.");
            if (!(selection.NativeContext is MethodAnalysisContext analysisContext))
                throw new DevirtualizationException("Dispatcher locator returned invalid analysis context.");

            Ctx.PatternMatcher = analysisContext.Matcher;
            var opcodeHandlerMethod = selection.Method;
            var switchOpCode = selection.SwitchInstruction;
            var internalSelection = new SelectionResult(opcodeHandlerMethod, switchOpCode, analysisContext);
            Ctx.OpcodeHandlerMethod = opcodeHandlerMethod;
            Ctx.Options.Logger.Success($"Found method {opcodeHandlerMethod.Name} that contains Opcode Handlers!");

            if (!(switchOpCode.Operand is IList<ICilLabel> values))
                throw new DevirtualizationException("Opcode handler switch has an unexpected operand type.");
            Ctx.OpcodeHandlerIndices = new Dictionary<int, int>();

            var addressableHandlerCount = Math.Min(values.Count, _addressableOpcodeCount);
            for (var i = 0; i < addressableHandlerCount; i++)
            {
                if (!(values[i] is CilInstructionLabel instructionLabel) || instructionLabel.Instruction == null)
                    continue;
                if (!analysisContext.InstructionIndexByInstruction.TryGetValue(
                        instructionLabel.Instruction,
                        out var index))
                {
                    continue;
                }
                Ctx.OpcodeHandlerIndices[i] = index;
                var opCode = GetMappedOpcode(
                    analysisContext,
                    opcodeHandlerMethod,
                    index,
                    allowFallback: _dispatcherProfile.UseHandlerFallbackInference);
                if (opCode != VMOpCode.Nop)
                    ApplyMapping(Ctx, i, opCode, 0.95, "handler-pattern");

                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                    Ctx.Options.Logger.Info($"vm 0x{i:X2} -> {opCode} (handler index {index})");
            }

            if (values.Count > addressableHandlerCount)
            {
                Ctx.Options.Logger.Info(
                    $"Switch handlers: {values.Count} (addressable VM-byte range: {addressableHandlerCount}) | mapped VM opcodes: {Ctx.PatternMatcher.GetMappedCount()}");
            }
            else
            {
                Ctx.Options.Logger.Info(
                    $"Switch handlers: {values.Count} | mapped VM opcodes: {Ctx.PatternMatcher.GetMappedCount()}");
            }

            _currentSelection = internalSelection;
            _currentSwitchLabels = values;
            try
            {
                ApplySignatureCatalogBootstrap(Ctx, internalSelection, values);
                RunOpcodeMappingSteps(Ctx);
                ExportHandlerSignatureCatalog(Ctx, internalSelection, values);
            }
            finally
            {
                _currentSelection = null;
                _currentSwitchLabels = Array.Empty<ICilLabel>();
            }

            if (string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_ENABLE_STUB_NOOP"),
                    "1",
                    StringComparison.Ordinal))
            {
                InferStubNoOpHandlers(Ctx, internalSelection, values, observedVmByteHistogram);
            }
        }

        private void ExecuteDiscoveryPhase(
            DevirtualizationCtx ctx,
            SelectionResult internalSelection,
            IList<ICilLabel> switchLabels)
        {
            InferStructurallyUniqueOperandOpcodes(ctx);
            InferUnmappedOpcodesFromOperandSemantics(ctx);
            InferUnknownByIntrinsicTypeTokenHandlers(ctx);
            InferUnknownByCompactDupHandlers(ctx);
            InferUnknownByGuardedPopHandlers(ctx);
            InferUnknownByPointerProjectionUnaryHandlers(ctx);
            InferUnknownByStelemI1Handlers(ctx);
            InferUnmappedOpcodesByHandlerSimilarity(ctx, internalSelection, switchLabels);
            InferUnknownByNeighborContext(ctx);
            InferUnknownDupBeforeStructuredStelemRef(ctx);
        }

        private void ExecuteScoringPhase(DevirtualizationCtx ctx)
        {
            InferDominantUnknownIndexLikeOpcodes(ctx);
            InferUnknownByStackConsistency(ctx);
            InferRareUnknownByWindowedStackConsistency(ctx);
            InferRareUnknownByConsensus(ctx);
            InferRareOperand1BranchesByTargetAndNeighbors(ctx);
            InferReactorVersionAwareDispatcherBranches(ctx);
            InferSmallUnknownSetByJointStackSearch(ctx);
            InferLastResortRareUnknowns(ctx);
        }

        private void ExecutePruningPhase(DevirtualizationCtx ctx)
        {
            ApplyControlFlowConstraints(ctx);
            PruneOperandIncompatibleMappings(ctx);
            PruneSemanticallyInvalidIndexLikeMappings(ctx);
            PruneLowConfidencePopMappings(ctx);
            PruneSuspiciousPopMappings(ctx);
        }

        private void ExecuteSemanticRepairPhase(DevirtualizationCtx ctx)
        {
            // Handler-pattern mappings are optimistic by design; after pruning,
            // run selected inference passes once more to recover compatible mappings.
            InferUnmappedOpcodesFromOperandSemantics(ctx);
            InferUnknownByStackConsistency(ctx);
            InferRareOperand1BranchesByTargetAndNeighbors(ctx);
            InferReactorVersionAwareDispatcherBranches(ctx);
            InferLastResortRareUnknowns(ctx);
            RetuneRareHighRiskArithmeticMappings(ctx);
            RetuneSuspiciousUnaryMappingsByBinaryContext(ctx);
        }

        private void ExecuteFinalizationPhase(DevirtualizationCtx ctx)
        {
            InferTailTerminatorRetMappings(ctx);
            ApplyEnvironmentOpcodeOverrides(ctx);
            InferSingletonOperand0TieAsNoOp(ctx);
            ResolveRemainingUnknownOpcodesAggressively(ctx);
            PruneOperandIncompatibleMappings(ctx);
            PruneSemanticallyInvalidIndexLikeMappings(ctx);
            LogRemainingUnknownCandidates(ctx);
            LogOpcodeConfidenceSummary(ctx);
        }

        internal void RunDiscoveryStep(DevirtualizationCtx ctx)
        {
            ExecuteDiscoveryPhase(ctx, _currentSelection, _currentSwitchLabels);
        }

        internal void RunScoringStep(DevirtualizationCtx ctx)
        {
            ExecuteScoringPhase(ctx);
        }

        internal void RunPruningStep(DevirtualizationCtx ctx)
        {
            ExecutePruningPhase(ctx);
        }

        internal void RunSemanticRepairStep(DevirtualizationCtx ctx)
        {
            ExecuteSemanticRepairPhase(ctx);
        }

        internal void RunFinalizationStep(DevirtualizationCtx ctx)
        {
            ExecuteFinalizationPhase(ctx);
        }

        private void RunOpcodeMappingSteps(DevirtualizationCtx ctx)
        {
            var steps = OpcodeMappingStepRegistry.GetOrderedSteps();
            if (steps == null || steps.Count == 0)
            {
                RunDiscoveryStep(ctx);
                RunScoringStep(ctx);
                RunPruningStep(ctx);
                RunSemanticRepairStep(ctx);
                RunFinalizationStep(ctx);
                return;
            }

            ctx?.Options?.Logger?.Info(
                $"Opcode mapping pipeline: {string.Join(" -> ", steps.Select(s => s.Name))}");

            var context = new OpcodeMappingStepContext(ctx, this);
            foreach (var step in steps)
            {
                if (step == null)
                    continue;

                try
                {
                    step.Execute(context);
                }
                catch (Exception ex)
                {
                    HandleBestEffortFailure(ctx, $"opcode mapping step '{step.Name}'", ex);
                }
            }
        }

        private void ApplySignatureCatalogBootstrap(
            DevirtualizationCtx ctx,
            SelectionResult selection,
            IList<ICilLabel> values)
        {
            _handlerSignatureBootstrapper.ApplySignatureCatalogBootstrap(
                ctx,
                selection?.Method,
                selection?.AnalysisContext?.InstructionIndexByInstruction,
                values,
                _addressableOpcodeCount,
                _heuristicsProfile,
                BuildHandlerSignatureGrams,
                DiceCoefficient,
                IsSimilaritySafeOpcode,
                IsOperandTypeCompatible,
                (vmByte, opCode, confidence, source) => ApplyMapping(ctx, vmByte, opCode, confidence, source),
                (phase, ex) => HandleBestEffortFailure(ctx, phase, ex));
        }

        private void ExportHandlerSignatureCatalog(
            DevirtualizationCtx ctx,
            SelectionResult selection,
            IList<ICilLabel> values)
        {
            _handlerSignatureBootstrapper.ExportHandlerSignatureCatalog(
                ctx,
                selection?.Method,
                selection?.AnalysisContext?.InstructionIndexByInstruction,
                values,
                _addressableOpcodeCount,
                _heuristicsProfile,
                BuildHandlerSignatureGrams,
                (phase, ex) => HandleBestEffortFailure(ctx, phase, ex));
        }

        private int GetAddressableOpcodeCount()
        {
            return byte.MaxValue + 1;
        }

        private bool IsStrictDiagnostics(DevirtualizationCtx ctx)
        {
            return ctx?.Options?.StrictDiagnostics == true;
        }

        private void HandleBestEffortFailure(DevirtualizationCtx ctx, string phase, Exception ex)
        {
            if (IsStrictDiagnostics(ctx))
                throw new DevirtualizationException($"Best-effort stage failed during {phase}.", ex);

            ctx?.Options?.Logger?.Warning(
                $"Best-effort stage '{phase}' failed: {ex.Message}. Continuing with partial heuristics.");
        }

        private void ApplyMapping(
            DevirtualizationCtx ctx,
            int vmByte,
            VMOpCode opCode,
            double confidence,
            string source)
        {
            if (ctx?.PatternMatcher == null)
                return;

            if (opCode == VMOpCode.Nop)
                ctx.PatternMatcher.MarkKnownNoOpValue(vmByte);
            else
                ctx.PatternMatcher.SetOpCodeValue(opCode, vmByte);

            RecordConfidence(ctx, vmByte, opCode, confidence, source);
        }

        private void RecordConfidence(
            DevirtualizationCtx ctx,
            int vmByte,
            VMOpCode opCode,
            double confidence,
            string source)
        {
            if (ctx?.OpcodeConfidence == null)
                return;
            confidence = Math.Max(0.0, Math.Min(1.0, confidence));

            if (!ctx.OpcodeConfidence.TryGetValue(vmByte, out var existing))
            {
                ctx.OpcodeConfidence[vmByte] = new OpcodeMappingConfidence(opCode, confidence, source ?? "unknown");
                return;
            }

            if (existing.OpCode == opCode)
            {
                if (confidence >= existing.Confidence)
                    ctx.OpcodeConfidence[vmByte] = new OpcodeMappingConfidence(opCode, confidence, source ?? existing.Source);
                return;
            }

            ctx.OpcodeConfidence[vmByte] = new OpcodeMappingConfidence(opCode, confidence, source ?? existing.Source);
        }
    }
}
