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
    internal static class CilBodyStackAnalyzer
    {
        private const int MaxStatesPerInstruction = 24;
        private const int MaxTrackedStackDepth = 128;

        public static CilBodyAnalysisResult Analyze(
            DevirtualizationCtx ctx,
            VMMethod vmMethod,
            RecompiledMethodArtifact artifact)
        {
            if (artifact?.Body?.Instructions == null || artifact.Body.Instructions.Count == 0)
                return new CilBodyAnalysisResult();

            var body = artifact.Body;
            var instructions = body.Instructions;
            var instructionIndexByInstruction = new Dictionary<CilInstruction, int>(instructions.Count);
            for (var i = 0; i < instructions.Count; i++)
                instructionIndexByInstruction[instructions[i]] = i;

            var result = new CilBodyAnalysisResult();
            var seenDepths = new HashSet<int>[instructions.Count];
            for (var i = 0; i < seenDepths.Length; i++)
                seenDepths[i] = new HashSet<int>();

            var queue = new Queue<(int index, int depth)>();
            queue.Enqueue((0, 0));

            while (queue.Count > 0)
            {
                var (index, depth) = queue.Dequeue();
                if (index < 0 || index >= instructions.Count)
                    continue;

                var seen = seenDepths[index];
                if (seen.Contains(depth))
                    continue;
                if (seen.Count >= MaxStatesPerInstruction)
                    continue;
                seen.Add(depth);

                var instruction = instructions[index];
                if (!TryGetStackEffect(vmMethod, instruction, out var pop, out var push))
                    continue;

                var effectiveDepth = depth;
                if (effectiveDepth < pop)
                {
                    RegisterIssue(result, artifact.InstructionOrigins, index, $"stack underflow at il-index {index}: depth={effectiveDepth}, pop={pop}, op={instruction.OpCode.Code}");
                    effectiveDepth = pop;
                }

                var nextDepth = effectiveDepth - pop + push;
                if (nextDepth < 0)
                {
                    RegisterIssue(result, artifact.InstructionOrigins, index, $"negative stack depth at il-index {index}: {nextDepth}");
                    nextDepth = 0;
                }
                if (nextDepth > MaxTrackedStackDepth)
                {
                    RegisterIssue(result, artifact.InstructionOrigins, index, $"stack depth exceeded tracking limit at il-index {index}: {nextDepth}");
                    nextDepth = MaxTrackedStackDepth;
                }

                if (nextDepth > result.MaxObservedDepth)
                    result.MaxObservedDepth = nextDepth;

                var code = instruction.OpCode.Code;
                switch (code)
                {
                    case CilCode.Br:
                    {
                        if (!TryGetTargetIndex(instruction.Operand, instructionIndexByInstruction, out var target))
                        {
                            RegisterIssue(result, artifact.InstructionOrigins, index, $"invalid branch target at il-index {index}");
                            break;
                        }

                        QueueSuccessor(queue, seenDepths, artifact, result, index, target, nextDepth);
                        break;
                    }
                    case CilCode.Leave:
                    {
                        if (!TryGetTargetIndex(instruction.Operand, instructionIndexByInstruction, out var target))
                        {
                            RegisterIssue(result, artifact.InstructionOrigins, index, $"invalid leave target at il-index {index}");
                            break;
                        }

                        QueueSuccessor(queue, seenDepths, artifact, result, index, target, 0);
                        break;
                    }
                    case CilCode.Brtrue:
                    case CilCode.Brfalse:
                    case CilCode.Blt_Un:
                    case CilCode.Bge_Un:
                    {
                        if (!TryGetTargetIndex(instruction.Operand, instructionIndexByInstruction, out var target))
                        {
                            RegisterIssue(result, artifact.InstructionOrigins, index, $"invalid conditional target at il-index {index}");
                            break;
                        }

                        QueueSuccessor(queue, seenDepths, artifact, result, index, target, nextDepth);
                        EnqueueFallThrough(queue, seenDepths, artifact, result, index, nextDepth, instructions.Count);
                        break;
                    }
                    case CilCode.Switch:
                    {
                        if (!(instruction.Operand is IList<ICilLabel> labels) || labels.Count == 0)
                        {
                            RegisterIssue(result, artifact.InstructionOrigins, index, $"invalid switch labels at il-index {index}");
                            break;
                        }

                        foreach (var label in labels)
                        {
                            if (!TryGetTargetIndex(label, instructionIndexByInstruction, out var target))
                            {
                                RegisterIssue(result, artifact.InstructionOrigins, index, $"invalid switch target at il-index {index}");
                                continue;
                            }

                            QueueSuccessor(queue, seenDepths, artifact, result, index, target, nextDepth);
                        }

                        EnqueueFallThrough(queue, seenDepths, artifact, result, index, nextDepth, instructions.Count);
                        break;
                    }
                    case CilCode.Ret:
                    case CilCode.Endfinally:
                        break;
                    default:
                        EnqueueFallThrough(queue, seenDepths, artifact, result, index, nextDepth, instructions.Count);
                        break;
                }
            }

            if (string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_LOG_CIL_STACK"),
                    "1",
                    StringComparison.Ordinal) &&
                result.TotalIssues > 0)
            {
                var methodName = vmMethod?.Parent?.FullName ?? "<unknown>";
                ctx?.Options?.Logger?.Warning(
                    $"CIL stack analysis found {result.TotalIssues} issue(s) in {methodName}. Top vm bytes: {string.Join(", ", result.IssuesByVmByte.OrderByDescending(q => q.Value).Take(6).Select(q => $"0x{q.Key:X2}={q.Value}"))}");
                if (result.Messages.Count > 0)
                {
                    ctx?.Options?.Logger?.Info(
                        $"CIL stack samples for {methodName}: {string.Join(" | ", result.Messages.Take(6))}");
                }
            }

            return result;
        }

        private static void EnqueueFallThrough(
            Queue<(int index, int depth)> queue,
            IReadOnlyList<HashSet<int>> seenDepths,
            RecompiledMethodArtifact artifact,
            CilBodyAnalysisResult result,
            int sourceIndex,
            int depth,
            int count)
        {
            var next = sourceIndex + 1;
            if (next >= 0 && next < count)
                QueueSuccessor(queue, seenDepths, artifact, result, sourceIndex, next, depth);
        }

        private static void QueueSuccessor(
            Queue<(int index, int depth)> queue,
            IReadOnlyList<HashSet<int>> seenDepths,
            RecompiledMethodArtifact artifact,
            CilBodyAnalysisResult result,
            int sourceIndex,
            int targetIndex,
            int depth)
        {
            if (targetIndex < 0 || targetIndex >= seenDepths.Count)
                return;

            var seen = seenDepths[targetIndex];
            if (seen.Count >= MaxStatesPerInstruction)
            {
                RegisterIssue(result, artifact.InstructionOrigins, sourceIndex, $"state explosion on edge {sourceIndex}->{targetIndex}: exceeded {MaxStatesPerInstruction} incoming depths");
                return;
            }

            if (seen.Count > 0 && !seen.Contains(depth))
            {
                RegisterIssue(
                    result,
                    artifact.InstructionOrigins,
                    sourceIndex,
                    $"stack-depth merge mismatch on edge {sourceIndex}->{targetIndex}: {string.Join("/", seen.OrderBy(q => q))} vs {depth}");
                if (targetIndex >= 0)
                    result.IssueInstructionIndices.Add(targetIndex);
            }

            queue.Enqueue((targetIndex, depth));
        }

        private static bool TryGetTargetIndex(
            object operand,
            IReadOnlyDictionary<CilInstruction, int> instructionIndexByInstruction,
            out int targetIndex)
        {
            targetIndex = -1;
            if (!(operand is CilInstructionLabel label) || label.Instruction == null)
                return false;
            return instructionIndexByInstruction.TryGetValue(label.Instruction, out targetIndex);
        }

        private static void RegisterIssue(
            CilBodyAnalysisResult result,
            IReadOnlyList<VMInstruction> instructionOrigins,
            int instructionIndex,
            string message)
        {
            result.TotalIssues++;
            if (instructionIndex >= 0)
                result.IssueInstructionIndices.Add(instructionIndex);
            if (instructionOrigins != null &&
                instructionIndex >= 0 &&
                instructionIndex < instructionOrigins.Count &&
                instructionOrigins[instructionIndex] != null)
            {
                var vmByte = instructionOrigins[instructionIndex].VmByte;
                if (!result.IssuesByVmByte.TryGetValue(vmByte, out var count))
                    count = 0;
                result.IssuesByVmByte[vmByte] = count + 1;
            }

            if (result.Messages.Count < 32)
                result.Messages.Add(message);
        }

        private static bool TryGetStackEffect(VMMethod vmMethod, CilInstruction instruction, out int pop, out int push)
        {
            pop = 0;
            push = 0;

            switch (instruction.OpCode.Code)
            {
                case CilCode.Nop:
                    return true;

                case CilCode.Ldarg:
                case CilCode.Ldarg_0:
                case CilCode.Ldarg_1:
                case CilCode.Ldarg_2:
                case CilCode.Ldarg_3:
                case CilCode.Ldloc:
                case CilCode.Ldloc_0:
                case CilCode.Ldloc_1:
                case CilCode.Ldloc_2:
                case CilCode.Ldloc_3:
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
                case CilCode.Ldc_I8:
                case CilCode.Ldc_R4:
                case CilCode.Ldc_R8:
                case CilCode.Ldstr:
                case CilCode.Ldnull:
                case CilCode.Ldsfld:
                    push = 1;
                    return true;

                case CilCode.Stloc:
                case CilCode.Stloc_0:
                case CilCode.Stloc_1:
                case CilCode.Stloc_2:
                case CilCode.Stloc_3:
                case CilCode.Pop:
                case CilCode.Stsfld:
                    pop = 1;
                    return true;

                case CilCode.Dup:
                    pop = 1;
                    push = 2;
                    return true;

                case CilCode.Br:
                case CilCode.Leave:
                case CilCode.Endfinally:
                    return true;

                case CilCode.Brtrue:
                case CilCode.Brfalse:
                case CilCode.Switch:
                    pop = 1;
                    return true;

                case CilCode.Blt_Un:
                case CilCode.Bge_Un:
                    pop = 2;
                    return true;

                case CilCode.Add:
                case CilCode.Sub:
                case CilCode.Xor:
                case CilCode.Shl:
                case CilCode.Shr:
                    pop = 2;
                    push = 1;
                    return true;

                case CilCode.Neg:
                case CilCode.Not:
                case CilCode.Conv_I4:
                case CilCode.Conv_I8:
                case CilCode.Conv_U1:
                case CilCode.Ldlen:
                case CilCode.Unbox_Any:
                case CilCode.Ldind_I1:
                case CilCode.Ldind_U1:
                case CilCode.Ldind_I2:
                case CilCode.Ldind_U2:
                case CilCode.Ldind_I4:
                case CilCode.Ldind_U4:
                case CilCode.Ldind_I8:
                case CilCode.Ldind_R4:
                case CilCode.Ldind_R8:
                case CilCode.Ldind_I:
                case CilCode.Ldobj:
                    pop = 1;
                    push = 1;
                    return true;

                case CilCode.Newarr:
                    pop = 1;
                    push = 1;
                    return true;

                case CilCode.Ldelema:
                case CilCode.Ldelem_Ref:
                case CilCode.Ldelem_U1:
                    pop = 2;
                    push = 1;
                    return true;

                case CilCode.Stind_I1:
                case CilCode.Stind_I2:
                case CilCode.Stind_I4:
                case CilCode.Stind_I8:
                case CilCode.Stind_R4:
                case CilCode.Stind_R8:
                case CilCode.Stind_I:
                case CilCode.Stobj:
                    pop = 2;
                    return true;

                case CilCode.Stelem_Ref:
                case CilCode.Stelem_I1:
                    pop = 3;
                    return true;

                case CilCode.Ldfld:
                    pop = 1;
                    push = 1;
                    return true;

                case CilCode.Stfld:
                    pop = 2;
                    return true;

                case CilCode.Call:
                case CilCode.Callvirt:
                {
                    var descriptor = instruction.Operand as IMethodDescriptor;
                    var sig = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                    if (sig == null)
                        return false;

                    pop = sig.ParameterTypes.Count + ((instruction.OpCode.Code == CilCode.Callvirt || sig.HasThis) ? 1 : 0);
                    push = string.Equals(sig.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) ? 0 : 1;
                    return true;
                }

                case CilCode.Newobj:
                {
                    var descriptor = instruction.Operand as IMethodDescriptor;
                    var sig = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                    if (sig == null)
                        return false;

                    pop = sig.ParameterTypes.Count;
                    push = 1;
                    return true;
                }

                case CilCode.Ret:
                    pop = string.Equals(vmMethod?.Parent?.Signature?.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) ? 0 : 1;
                    return true;

                default:
                    return false;
            }
        }
    }

    internal sealed class CilBodyAnalysisResult
    {
        public int TotalIssues { get; set; }
        public int MaxObservedDepth { get; set; }
        public Dictionary<int, int> IssuesByVmByte { get; } = new Dictionary<int, int>();
        public List<string> Messages { get; } = new List<string>();
        public HashSet<int> IssueInstructionIndices { get; } = new HashSet<int>();
    }
}
