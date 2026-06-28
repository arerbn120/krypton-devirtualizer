using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    internal static class VerifiableIlSanitizer
    {
        public static VerifiableIlSanitizerResult TryRepair(
            DevirtualizationCtx ctx,
            VMMethod vmMethod,
            RecompiledMethodArtifact artifact)
        {
            var result = new VerifiableIlSanitizerResult();
            if (!IsEnvironmentEnabled("KRYPTON_VERIFIABLE_IL_MODE"))
                return result;
            if (vmMethod?.Parent == null || artifact?.Body == null)
                return result;

            var currentArtifact = artifact;
            var initialAnalysis = Analyze(ctx, vmMethod, currentArtifact);
            result.InitialCilIssues = initialAnalysis.cilIssues;
            result.InitialDnlibIssues = initialAnalysis.dnlibIssues;
            result.FinalCilAnalysis = initialAnalysis.cilAnalysis;
            result.FinalDnlibAnalysis = initialAnalysis.dnlibAnalysis;
            result.FinalCilIssues = initialAnalysis.cilIssues;
            result.FinalDnlibIssues = initialAnalysis.dnlibIssues;
            result.FinalArtifact = currentArtifact;

            if (initialAnalysis.score <= 0)
                return result;

            var maxIterations = ReadPositiveIntFromEnvironment("KRYPTON_VERIFIABLE_MAX_ITERATIONS", 6);
            var currentScore = initialAnalysis.score;

            for (var iter = 0; iter < maxIterations; iter++)
            {
                var candidateBody = CloneBody(vmMethod.Parent, currentArtifact.Body);
                if (candidateBody == null)
                    break;

                var changed = ApplyEhAwareNormalization(candidateBody);
                if (changed <= 0)
                    break;

                var candidateArtifact = new RecompiledMethodArtifact(
                    candidateBody,
                    currentArtifact.InstructionOrigins);
                var candidateAnalysis = Analyze(ctx, vmMethod, candidateArtifact);
                if (candidateAnalysis.score >= currentScore)
                    break;

                currentArtifact = candidateArtifact;
                currentScore = candidateAnalysis.score;
                result.IterationsApplied++;
                result.ChangesApplied += changed;
                result.FinalArtifact = currentArtifact;
                result.FinalCilIssues = candidateAnalysis.cilIssues;
                result.FinalDnlibIssues = candidateAnalysis.dnlibIssues;
                result.FinalCilAnalysis = candidateAnalysis.cilAnalysis;
                result.FinalDnlibAnalysis = candidateAnalysis.dnlibAnalysis;

                if (currentScore <= 0)
                    break;
            }

            result.Improved = result.FinalCilIssues < result.InitialCilIssues ||
                              result.FinalDnlibIssues < result.InitialDnlibIssues;
            return result;
        }

        private static (int score, int cilIssues, int dnlibIssues, CilBodyAnalysisResult cilAnalysis, DnlibStyleMaxStackAnalysisResult dnlibAnalysis) Analyze(
            DevirtualizationCtx ctx,
            VMMethod vmMethod,
            RecompiledMethodArtifact artifact)
        {
            var dnlibWeight = ReadPositiveIntFromEnvironment("KRYPTON_VERIFIABLE_DNLIB_WEIGHT", 1);
            var cilAnalysis = CilBodyStackAnalyzer.Analyze(ctx, vmMethod, artifact);
            var dnlibAnalysis = DnlibStyleMaxStackAnalyzer.Analyze(ctx, vmMethod, artifact);
            var score = cilAnalysis.TotalIssues + (dnlibAnalysis.TotalIssues * dnlibWeight);
            return (score, cilAnalysis.TotalIssues, dnlibAnalysis.TotalIssues, cilAnalysis, dnlibAnalysis);
        }

        private static int ApplyEhAwareNormalization(CilMethodBody body)
        {
            if (body?.Instructions == null || body.Instructions.Count == 0)
                return 0;

            var changed = 0;
            changed += ThreadBranchTargets(body);
            changed += SimplifyConstantConditionalBranches(body);
            changed += SimplifyConstantSwitchDispatch(body);
            changed += NopUnreachableInstructions(body);
            changed += NopTrivialStackNoise(body);
            return changed;
        }

        private static int ThreadBranchTargets(CilMethodBody body)
        {
            var changed = 0;
            var instructions = body.Instructions;
            for (var i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                if (TryGetSingleTarget(instruction, out var singleTarget))
                {
                    var rewritten = FollowUnconditionalBranchChain(singleTarget);
                    if (rewritten != null && !ReferenceEquals(rewritten, singleTarget))
                    {
                        SetSingleTarget(instruction, rewritten);
                        changed++;
                    }
                }
                else if (TryGetSwitchTargets(instruction, out var switchTargets))
                {
                    var rewiredAny = false;
                    for (var t = 0; t < switchTargets.Count; t++)
                    {
                        var rewritten = FollowUnconditionalBranchChain(switchTargets[t]);
                        if (rewritten != null && !ReferenceEquals(rewritten, switchTargets[t]))
                        {
                            switchTargets[t] = rewritten;
                            rewiredAny = true;
                        }
                    }

                    if (rewiredAny)
                    {
                        SetSwitchTargets(instruction, switchTargets);
                        changed++;
                    }
                }
            }

            return changed;
        }

        private static int SimplifyConstantConditionalBranches(CilMethodBody body)
        {
            var changed = 0;
            var instructions = body.Instructions;
            for (var i = 1; i < instructions.Count; i++)
            {
                var branch = instructions[i];
                if (!TryGetSingleTarget(branch, out var target))
                    continue;
                if (!IsConditionalBranch(branch.OpCode.Code, out var isBrTrue))
                    continue;
                if (!TryGetConstantInt32(instructions[i - 1], out var value))
                    continue;

                var taken = isBrTrue ? value != 0 : value == 0;
                NopInstruction(instructions[i - 1], ref changed);
                if (taken)
                {
                    branch.OpCode = CilOpCodes.Br;
                    SetSingleTarget(branch, target);
                    changed++;
                }
                else
                {
                    NopInstruction(branch, ref changed);
                }
            }

            return changed;
        }

        private static int SimplifyConstantSwitchDispatch(CilMethodBody body)
        {
            var changed = 0;
            var instructions = body.Instructions;
            for (var i = 1; i < instructions.Count; i++)
            {
                var switchInstruction = instructions[i];
                if (switchInstruction.OpCode.Code != CilCode.Switch)
                    continue;
                if (!TryGetConstantInt32(instructions[i - 1], out var selector))
                    continue;
                if (!TryGetSwitchTargets(switchInstruction, out var targets) || targets.Count == 0)
                    continue;

                var next = i + 1 < instructions.Count ? instructions[i + 1] : null;
                CilInstruction target = null;
                if (selector >= 0 && selector < targets.Count)
                    target = targets[selector];

                NopInstruction(instructions[i - 1], ref changed);
                if (target == null || ReferenceEquals(target, next))
                {
                    NopInstruction(switchInstruction, ref changed);
                }
                else
                {
                    switchInstruction.OpCode = CilOpCodes.Br;
                    SetSingleTarget(switchInstruction, target);
                    changed++;
                }
            }

            return changed;
        }

        private static int NopUnreachableInstructions(CilMethodBody body)
        {
            var reachable = ComputeReachable(body);
            var protectedBoundaries = CollectProtectedBoundaries(body);
            var changed = 0;

            foreach (var instruction in body.Instructions)
            {
                if (reachable.Contains(instruction))
                    continue;
                if (protectedBoundaries.Contains(instruction))
                    continue;
                NopInstruction(instruction, ref changed);
            }

            return changed;
        }

        private static int NopTrivialStackNoise(CilMethodBody body)
        {
            var changed = 0;
            var instructions = body.Instructions;
            for (var i = 0; i < instructions.Count - 1; i++)
            {
                var current = instructions[i];
                var next = instructions[i + 1];
                if (current.OpCode.Code == CilCode.Dup && next.OpCode.Code == CilCode.Pop)
                {
                    NopInstruction(current, ref changed);
                    NopInstruction(next, ref changed);
                    i++;
                    continue;
                }

                if (IsConstPush(current.OpCode.Code) && next.OpCode.Code == CilCode.Pop)
                {
                    NopInstruction(current, ref changed);
                    NopInstruction(next, ref changed);
                    i++;
                }
            }

            return changed;
        }

        private static HashSet<CilInstruction> ComputeReachable(CilMethodBody body)
        {
            var reachable = new HashSet<CilInstruction>(ReferenceEqualityComparer.Instance);
            var instructions = body.Instructions;
            if (instructions.Count == 0)
                return reachable;

            var work = new Stack<CilInstruction>();
            void Enqueue(CilInstruction instruction)
            {
                if (instruction == null)
                    return;
                if (reachable.Add(instruction))
                    work.Push(instruction);
            }

            Enqueue(instructions[0]);
            foreach (var eh in body.ExceptionHandlers)
            {
                Enqueue(ResolveLabelInstruction(eh.TryStart));
                Enqueue(ResolveLabelInstruction(eh.HandlerStart));
                Enqueue(ResolveLabelInstruction(eh.FilterStart));
            }

            while (work.Count > 0)
            {
                var current = work.Pop();
                var index = instructions.IndexOf(current);
                if (index < 0)
                    continue;

                if (TryGetSingleTarget(current, out var singleTarget))
                    Enqueue(singleTarget);
                else if (TryGetSwitchTargets(current, out var targets))
                {
                    foreach (var target in targets)
                        Enqueue(target);
                }

                if (IsTerminal(current.OpCode.Code))
                    continue;
                if (IsUnconditionalBranch(current.OpCode.Code))
                    continue;

                var nextIndex = index + 1;
                if (nextIndex >= 0 && nextIndex < instructions.Count)
                    Enqueue(instructions[nextIndex]);
            }

            return reachable;
        }

        private static HashSet<CilInstruction> CollectProtectedBoundaries(CilMethodBody body)
        {
            var boundaries = new HashSet<CilInstruction>(ReferenceEqualityComparer.Instance);
            foreach (var instruction in body.Instructions)
            {
                if (TryGetSingleTarget(instruction, out var target))
                    boundaries.Add(target);
                else if (TryGetSwitchTargets(instruction, out var targets))
                {
                    foreach (var switchTarget in targets)
                        boundaries.Add(switchTarget);
                }
            }

            foreach (var eh in body.ExceptionHandlers)
            {
                AddBoundary(boundaries, ResolveLabelInstruction(eh.TryStart));
                AddBoundary(boundaries, ResolveLabelInstruction(eh.TryEnd));
                AddBoundary(boundaries, ResolveLabelInstruction(eh.HandlerStart));
                AddBoundary(boundaries, ResolveLabelInstruction(eh.HandlerEnd));
                AddBoundary(boundaries, ResolveLabelInstruction(eh.FilterStart));
            }

            return boundaries;
        }

        private static void AddBoundary(HashSet<CilInstruction> boundaries, CilInstruction instruction)
        {
            if (instruction != null)
                boundaries.Add(instruction);
        }

        private static CilInstruction FollowUnconditionalBranchChain(CilInstruction start)
        {
            if (start == null)
                return null;

            var current = start;
            var visited = new HashSet<CilInstruction>(ReferenceEqualityComparer.Instance);
            while (current != null && visited.Add(current))
            {
                if (!IsUnconditionalBranch(current.OpCode.Code))
                    break;
                if (!TryGetSingleTarget(current, out var target))
                    break;
                if (ReferenceEquals(target, current))
                    break;
                current = target;
            }

            return current;
        }

        private static bool TryGetSingleTarget(CilInstruction instruction, out CilInstruction target)
        {
            target = null;
            if (instruction == null)
                return false;
            switch (instruction.Operand)
            {
                case CilInstructionLabel label:
                    target = label.Instruction;
                    return target != null;
                case CilInstruction instructionTarget:
                    target = instructionTarget;
                    return true;
                default:
                    return false;
            }
        }

        private static bool TryGetSwitchTargets(CilInstruction instruction, out List<CilInstruction> targets)
        {
            targets = null;
            if (instruction == null || instruction.OpCode.Code != CilCode.Switch)
                return false;

            if (instruction.Operand is IList<ICilLabel> labels)
            {
                var list = new List<CilInstruction>(labels.Count);
                foreach (var label in labels)
                {
                    var target = ResolveLabelInstruction(label);
                    if (target == null)
                        return false;
                    list.Add(target);
                }
                targets = list;
                return true;
            }

            if (instruction.Operand is IList<CilInstruction> instructionTargets)
            {
                targets = instructionTargets.ToList();
                return targets.All(t => t != null);
            }

            return false;
        }

        private static void SetSingleTarget(CilInstruction instruction, CilInstruction target)
        {
            instruction.Operand = target == null ? null : new CilInstructionLabel(target);
        }

        private static void SetSwitchTargets(CilInstruction instruction, IReadOnlyList<CilInstruction> targets)
        {
            var labels = new List<ICilLabel>(targets.Count);
            for (var i = 0; i < targets.Count; i++)
                labels.Add(new CilInstructionLabel(targets[i]));
            instruction.Operand = labels;
        }

        private static bool TryGetConstantInt32(CilInstruction instruction, out int value)
        {
            value = 0;
            if (instruction == null)
                return false;

            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldc_I4_M1:
                    value = -1;
                    return true;
                case CilCode.Ldc_I4_0:
                    value = 0;
                    return true;
                case CilCode.Ldc_I4_1:
                    value = 1;
                    return true;
                case CilCode.Ldc_I4_2:
                    value = 2;
                    return true;
                case CilCode.Ldc_I4_3:
                    value = 3;
                    return true;
                case CilCode.Ldc_I4_4:
                    value = 4;
                    return true;
                case CilCode.Ldc_I4_5:
                    value = 5;
                    return true;
                case CilCode.Ldc_I4_6:
                    value = 6;
                    return true;
                case CilCode.Ldc_I4_7:
                    value = 7;
                    return true;
                case CilCode.Ldc_I4_8:
                    value = 8;
                    return true;
                case CilCode.Ldc_I4:
                    if (instruction.Operand is int i32)
                    {
                        value = i32;
                        return true;
                    }
                    if (instruction.Operand is uint u32)
                    {
                        value = unchecked((int) u32);
                        return true;
                    }
                    return false;
                case CilCode.Ldc_I4_S:
                    if (instruction.Operand is sbyte i8)
                    {
                        value = i8;
                        return true;
                    }
                    if (instruction.Operand is byte u8)
                    {
                        value = u8;
                        return true;
                    }
                    return false;
                default:
                    return false;
            }
        }

        private static bool IsConditionalBranch(CilCode code, out bool isBrTrue)
        {
            isBrTrue = false;
            switch (code)
            {
                case CilCode.Brtrue:
                case CilCode.Brtrue_S:
                    isBrTrue = true;
                    return true;
                case CilCode.Brfalse:
                case CilCode.Brfalse_S:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsConstPush(CilCode code)
        {
            switch (code)
            {
                case CilCode.Ldc_I4:
                case CilCode.Ldc_I4_M1:
                case CilCode.Ldc_I4_0:
                case CilCode.Ldc_I4_1:
                case CilCode.Ldc_I4_2:
                case CilCode.Ldc_I4_3:
                case CilCode.Ldc_I4_4:
                case CilCode.Ldc_I4_5:
                case CilCode.Ldc_I4_6:
                case CilCode.Ldc_I4_7:
                case CilCode.Ldc_I4_8:
                case CilCode.Ldc_I4_S:
                case CilCode.Ldc_I8:
                case CilCode.Ldc_R4:
                case CilCode.Ldc_R8:
                case CilCode.Ldstr:
                case CilCode.Ldnull:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsTerminal(CilCode code)
        {
            switch (code)
            {
                case CilCode.Ret:
                case CilCode.Throw:
                case CilCode.Rethrow:
                case CilCode.Endfinally:
                case CilCode.Endfilter:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsUnconditionalBranch(CilCode code)
        {
            switch (code)
            {
                case CilCode.Br:
                case CilCode.Br_S:
                case CilCode.Leave:
                case CilCode.Leave_S:
                    return true;
                default:
                    return false;
            }
        }

        private static void NopInstruction(CilInstruction instruction, ref int changed)
        {
            if (instruction == null)
                return;
            if (instruction.OpCode == CilOpCodes.Nop && instruction.Operand == null)
                return;

            instruction.OpCode = CilOpCodes.Nop;
            instruction.Operand = null;
            changed++;
        }

        private static CilMethodBody CloneBody(MethodDefinition owner, CilMethodBody source)
        {
            if (owner == null || source == null)
                return null;

            var clone = new CilMethodBody(owner)
            {
                InitializeLocals = source.InitializeLocals,
                MaxStack = source.MaxStack,
                ComputeMaxStackOnBuild = source.ComputeMaxStackOnBuild,
                VerifyLabelsOnBuild = source.VerifyLabelsOnBuild,
                BuildFlags = source.BuildFlags
            };

            for (var i = 0; i < source.LocalVariables.Count; i++)
            {
                var local = source.LocalVariables[i];
                clone.LocalVariables.Add(new CilLocalVariable(local.VariableType));
            }

            var map = new Dictionary<CilInstruction, CilInstruction>(ReferenceEqualityComparer.Instance);
            for (var i = 0; i < source.Instructions.Count; i++)
            {
                var instruction = source.Instructions[i];
                var clonedInstruction = new CilInstruction(instruction.OpCode);
                clone.Instructions.Add(clonedInstruction);
                map[instruction] = clonedInstruction;
            }

            for (var i = 0; i < source.Instructions.Count; i++)
            {
                var instruction = source.Instructions[i];
                clone.Instructions[i].Operand = CloneOperand(instruction.Operand, map);
            }

            foreach (var handler in source.ExceptionHandlers)
            {
                var clonedHandler = new CilExceptionHandler
                {
                    HandlerType = handler.HandlerType,
                    ExceptionType = handler.ExceptionType,
                    TryStart = CloneLabel(handler.TryStart, map),
                    TryEnd = CloneLabel(handler.TryEnd, map),
                    HandlerStart = CloneLabel(handler.HandlerStart, map),
                    HandlerEnd = CloneLabel(handler.HandlerEnd, map),
                    FilterStart = CloneLabel(handler.FilterStart, map)
                };

                clone.ExceptionHandlers.Add(clonedHandler);
            }

            return clone;
        }

        private static object CloneOperand(object operand, IReadOnlyDictionary<CilInstruction, CilInstruction> map)
        {
            switch (operand)
            {
                case null:
                    return null;
                case CilInstructionLabel label:
                    return label.Instruction != null && map.TryGetValue(label.Instruction, out var mappedLabel)
                        ? new CilInstructionLabel(mappedLabel)
                        : null;
                case ICilLabel anyLabel:
                    var instruction = ResolveLabelInstruction(anyLabel);
                    return instruction != null && map.TryGetValue(instruction, out var mappedAnyLabel)
                        ? new CilInstructionLabel(mappedAnyLabel)
                        : null;
                case IList<ICilLabel> labels:
                {
                    var cloned = new List<ICilLabel>(labels.Count);
                    for (var i = 0; i < labels.Count; i++)
                    {
                        var target = ResolveLabelInstruction(labels[i]);
                        if (target == null || !map.TryGetValue(target, out var mappedTarget))
                            continue;
                        cloned.Add(new CilInstructionLabel(mappedTarget));
                    }
                    return cloned;
                }
                case IList<CilInstruction> instructions:
                {
                    var cloned = new List<CilInstruction>(instructions.Count);
                    for (var i = 0; i < instructions.Count; i++)
                    {
                        if (instructions[i] != null && map.TryGetValue(instructions[i], out var mappedTarget))
                            cloned.Add(mappedTarget);
                    }
                    return cloned;
                }
                case CilInstruction instructionOperand:
                    return map.TryGetValue(instructionOperand, out var mappedInstruction) ? mappedInstruction : null;
                default:
                    return operand;
            }
        }

        private static ICilLabel CloneLabel(ICilLabel label, IReadOnlyDictionary<CilInstruction, CilInstruction> map)
        {
            var instruction = ResolveLabelInstruction(label);
            if (instruction == null)
                return null;
            if (!map.TryGetValue(instruction, out var mapped))
                return null;
            return new CilInstructionLabel(mapped);
        }

        private static CilInstruction ResolveLabelInstruction(ICilLabel label)
        {
            return (label as CilInstructionLabel)?.Instruction;
        }

        private static bool IsEnvironmentEnabled(string variableName)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
                return false;
            return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);
        }

        private static int ReadPositiveIntFromEnvironment(string variableName, int fallback)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
                return fallback;
            if (!int.TryParse(raw, out var parsed))
                return fallback;
            if (parsed <= 0)
                return fallback;
            return parsed;
        }

        private sealed class ReferenceEqualityComparer : IEqualityComparer<CilInstruction>
        {
            public static readonly ReferenceEqualityComparer Instance = new ReferenceEqualityComparer();

            public bool Equals(CilInstruction x, CilInstruction y)
            {
                return ReferenceEquals(x, y);
            }

            public int GetHashCode(CilInstruction obj)
            {
                return obj == null ? 0 : System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj);
            }
        }
    }

    internal sealed class VerifiableIlSanitizerResult
    {
        public bool Improved { get; set; }
        public int InitialCilIssues { get; set; }
        public int InitialDnlibIssues { get; set; }
        public int FinalCilIssues { get; set; }
        public int FinalDnlibIssues { get; set; }
        public int IterationsApplied { get; set; }
        public int ChangesApplied { get; set; }
        public RecompiledMethodArtifact FinalArtifact { get; set; }
        public CilBodyAnalysisResult FinalCilAnalysis { get; set; }
        public DnlibStyleMaxStackAnalysisResult FinalDnlibAnalysis { get; set; }
    }
}
