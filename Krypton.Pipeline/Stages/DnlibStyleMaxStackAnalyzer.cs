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
    internal static class DnlibStyleMaxStackAnalyzer
    {
        public static DnlibStyleMaxStackAnalysisResult Analyze(
            DevirtualizationCtx ctx,
            VMMethod vmMethod,
            RecompiledMethodArtifact artifact)
        {
            var result = new DnlibStyleMaxStackAnalysisResult();
            if (artifact?.Body?.Instructions == null || artifact.Body.Instructions.Count == 0)
                return result;

            var body = artifact.Body;
            var instructions = body.Instructions;
            var instructionIndexByInstruction = new Dictionary<CilInstruction, int>(
                instructions.Count,
                ReferenceEqualityComparer.Instance);
            for (var i = 0; i < instructions.Count; i++)
                instructionIndexByInstruction[instructions[i]] = i;

            var stackHeights = new Dictionary<CilInstruction, DnlibStyleStackEntry>(
                instructions.Count,
                ReferenceEqualityComparer.Instance);
            SeedExceptionHandlers(body, stackHeights, instructionIndexByInstruction, artifact, result);

            var stack = 0;
            var reloadRecordedStack = false;
            for (var i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                if (instruction == null)
                    continue;

                if (reloadRecordedStack)
                {
                    if (stackHeights.TryGetValue(instruction, out var recorded))
                        stack = recorded.Depth;
                    else
                        stack = 0;
                    reloadRecordedStack = false;
                }

                stack = WriteStack(
                    instruction,
                    stack,
                    sourceIndex: i,
                    reason: reloadRecordedStack ? "resume" : "fallthrough",
                    stackHeights,
                    instructionIndexByInstruction,
                    artifact,
                    result);

                if (!TryGetStackUsage(vmMethod, instruction, out var popCount, out var pushCount, out var resetStack))
                {
                    RegisterIssue(
                        result,
                        artifact.InstructionOrigins,
                        i,
                        $"dnlib-style analysis could not determine stack usage at il-index {i}: {instruction.OpCode.Code}");
                    continue;
                }

                if (resetStack)
                {
                    stack = 0;
                }
                else
                {
                    stack -= popCount;
                    if (stack < 0)
                    {
                        RegisterIssue(
                            result,
                            artifact.InstructionOrigins,
                            i,
                            $"dnlib-style underflow at il-index {i}: depth={stack + popCount}, pop={popCount}, op={instruction.OpCode.Code}");
                        stack = 0;
                    }

                    stack += pushCount;
                }

                if (stack < 0)
                {
                    RegisterIssue(
                        result,
                        artifact.InstructionOrigins,
                        i,
                        $"dnlib-style negative stack after il-index {i}: {stack}");
                    stack = 0;
                }

                switch (instruction.OpCode.Code)
                {
                    case CilCode.Br:
                    case CilCode.Leave:
                        WriteTargetStack(
                            instruction.Operand,
                            stack,
                            i,
                            "branch",
                            stackHeights,
                            instructionIndexByInstruction,
                            artifact,
                            result);
                        reloadRecordedStack = true;
                        break;

                    case CilCode.Brtrue:
                    case CilCode.Brfalse:
                    case CilCode.Blt_Un:
                    case CilCode.Bge_Un:
                        WriteTargetStack(
                            instruction.Operand,
                            stack,
                            i,
                            "cond-branch",
                            stackHeights,
                            instructionIndexByInstruction,
                            artifact,
                            result);
                        break;

                    case CilCode.Switch:
                        if (instruction.Operand is IList<ICilLabel> labels)
                        {
                            foreach (var label in labels)
                            {
                                WriteTargetStack(
                                    label,
                                    stack,
                                    i,
                                    "switch",
                                    stackHeights,
                                    instructionIndexByInstruction,
                                    artifact,
                                    result);
                            }
                        }
                        else
                        {
                            RegisterIssue(
                                result,
                                artifact.InstructionOrigins,
                                i,
                                $"dnlib-style invalid switch labels at il-index {i}");
                        }
                        break;

                    case CilCode.Ret:
                    case CilCode.Throw:
                    case CilCode.Rethrow:
                    case CilCode.Endfinally:
                    case CilCode.Endfilter:
                        reloadRecordedStack = true;
                        break;
                }
            }

            if (string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_LOG_DNLIB_STACK"),
                    "1",
                    StringComparison.Ordinal) &&
                result.TotalIssues > 0)
            {
                var methodName = vmMethod?.Parent?.FullName ?? "<unknown>";
                ctx?.Options?.Logger?.Warning(
                    $"dnlib-style max-stack analysis found {result.TotalIssues} issue(s) in {methodName}.");
                if (result.Messages.Count > 0)
                {
                    ctx?.Options?.Logger?.Info(
                        $"dnlib-style samples for {methodName}: {string.Join(" | ", result.Messages.Take(6))}");
                }
            }

            return result;
        }

        private static void SeedExceptionHandlers(
            CilMethodBody body,
            IDictionary<CilInstruction, DnlibStyleStackEntry> stackHeights,
            IReadOnlyDictionary<CilInstruction, int> instructionIndexByInstruction,
            RecompiledMethodArtifact artifact,
            DnlibStyleMaxStackAnalysisResult result)
        {
            foreach (var handler in body.ExceptionHandlers)
            {
                if (handler == null)
                    continue;

                WriteSeed(
                    ResolveLabelInstruction(handler.TryStart),
                    0,
                    "eh-try",
                    stackHeights,
                    instructionIndexByInstruction,
                    artifact,
                    result);

                if (handler.FilterStart != null)
                    WriteSeed(
                        ResolveLabelInstruction(handler.FilterStart),
                        1,
                        "eh-filter",
                        stackHeights,
                        instructionIndexByInstruction,
                        artifact,
                        result);

                if (handler.HandlerStart == null)
                    continue;

                var handlerDepth = handler.HandlerType == CilExceptionHandlerType.Exception ||
                                   handler.HandlerType == CilExceptionHandlerType.Filter
                    ? 1
                    : 0;
                WriteSeed(
                    ResolveLabelInstruction(handler.HandlerStart),
                    handlerDepth,
                    "eh-handler",
                    stackHeights,
                    instructionIndexByInstruction,
                    artifact,
                    result);
            }
        }

        private static void WriteSeed(
            CilInstruction target,
            int stack,
            string reason,
            IDictionary<CilInstruction, DnlibStyleStackEntry> stackHeights,
            IReadOnlyDictionary<CilInstruction, int> instructionIndexByInstruction,
            RecompiledMethodArtifact artifact,
            DnlibStyleMaxStackAnalysisResult result)
        {
            WriteStack(
                target,
                stack,
                sourceIndex: -1,
                reason,
                stackHeights,
                instructionIndexByInstruction,
                artifact,
                result);
        }

        private static CilInstruction ResolveLabelInstruction(ICilLabel label)
        {
            return (label as CilInstructionLabel)?.Instruction;
        }

        private static void WriteTargetStack(
            object operand,
            int stack,
            int sourceIndex,
            string reason,
            IDictionary<CilInstruction, DnlibStyleStackEntry> stackHeights,
            IReadOnlyDictionary<CilInstruction, int> instructionIndexByInstruction,
            RecompiledMethodArtifact artifact,
            DnlibStyleMaxStackAnalysisResult result)
        {
            if (!(operand is CilInstructionLabel label))
            {
                RegisterIssue(
                    result,
                    artifact.InstructionOrigins,
                    sourceIndex,
                    $"dnlib-style missing branch target from il-index {sourceIndex} ({reason})");
                return;
            }

            WriteStack(
                label.Instruction,
                stack,
                sourceIndex,
                reason,
                stackHeights,
                instructionIndexByInstruction,
                artifact,
                result);
        }

        private static int WriteStack(
            CilInstruction target,
            int stack,
            int sourceIndex,
            string reason,
            IDictionary<CilInstruction, DnlibStyleStackEntry> stackHeights,
            IReadOnlyDictionary<CilInstruction, int> instructionIndexByInstruction,
            RecompiledMethodArtifact artifact,
            DnlibStyleMaxStackAnalysisResult result)
        {
            if (target == null)
            {
                RegisterIssue(
                    result,
                    artifact.InstructionOrigins,
                    sourceIndex,
                    $"dnlib-style null target from {FormatSource(sourceIndex, reason)}");
                return stack;
            }

            if (stackHeights.TryGetValue(target, out var existing))
            {
                if (existing.Depth != stack)
                {
                    instructionIndexByInstruction.TryGetValue(target, out var targetIndex);
                    RegisterIssue(
                        result,
                        artifact.InstructionOrigins,
                        sourceIndex,
                        $"dnlib-style stack mismatch at il-index {targetIndex}: existing={existing.Depth} from {FormatSource(existing.SourceIndex, existing.Reason)}, incoming={stack} from {FormatSource(sourceIndex, reason)}");
                }

                return existing.Depth;
            }

            stackHeights[target] = new DnlibStyleStackEntry(stack, sourceIndex, reason);
            if (stack > result.MaxObservedDepth)
                result.MaxObservedDepth = stack;
            return stack;
        }

        private static string FormatSource(int sourceIndex, string reason)
        {
            if (sourceIndex >= 0)
                return $"il-index {sourceIndex} ({reason})";
            return reason ?? "entry";
        }

        private static void RegisterIssue(
            DnlibStyleMaxStackAnalysisResult result,
            IReadOnlyList<VMInstruction> instructionOrigins,
            int sourceIndex,
            string message)
        {
            result.TotalIssues++;

            if (instructionOrigins != null &&
                sourceIndex >= 0 &&
                sourceIndex < instructionOrigins.Count &&
                instructionOrigins[sourceIndex] != null)
            {
                var origin = instructionOrigins[sourceIndex];
                var vmByte = origin.VmByte;
                if (!result.IssuesByVmByte.TryGetValue(vmByte, out var count))
                    count = 0;
                result.IssuesByVmByte[vmByte] = count + 1;

                message = $"{message} [vm 0x{vmByte:X2} {origin.OpCode}]";
            }

            if (result.Messages.Count < 32)
                result.Messages.Add(message);
        }

        private static bool TryGetStackUsage(
            VMMethod vmMethod,
            CilInstruction instruction,
            out int pop,
            out int push,
            out bool resetStack)
        {
            pop = 0;
            push = 0;
            resetStack = false;

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
                case CilCode.Starg:
                case CilCode.Pop:
                case CilCode.Stsfld:
                    pop = 1;
                    return true;

                case CilCode.Dup:
                    pop = 1;
                    push = 2;
                    return true;

                case CilCode.Br:
                    return true;

                case CilCode.Leave:
                    resetStack = true;
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
                    var signature = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                    if (signature == null)
                        return false;

                    pop = signature.ParameterTypes.Count +
                          ((instruction.OpCode.Code == CilCode.Callvirt || signature.HasThis) ? 1 : 0);
                    push = string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal)
                        ? 0
                        : 1;
                    return true;
                }

                case CilCode.Newobj:
                {
                    var descriptor = instruction.Operand as IMethodDescriptor;
                    var signature = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                    if (signature == null)
                        return false;

                    pop = signature.ParameterTypes.Count;
                    push = 1;
                    return true;
                }

                case CilCode.Ret:
                    pop = string.Equals(vmMethod?.Parent?.Signature?.ReturnType?.FullName, "System.Void", StringComparison.Ordinal)
                        ? 0
                        : 1;
                    return true;

                case CilCode.Throw:
                    pop = 1;
                    return true;

                case CilCode.Rethrow:
                case CilCode.Endfinally:
                    return true;

                case CilCode.Endfilter:
                    pop = 1;
                    return true;

                default:
                    return false;
            }
        }
    }

    internal sealed class DnlibStyleMaxStackAnalysisResult
    {
        public int TotalIssues { get; set; }
        public int MaxObservedDepth { get; set; }
        public Dictionary<int, int> IssuesByVmByte { get; } = new Dictionary<int, int>();
        public List<string> Messages { get; } = new List<string>();
    }

    internal sealed class DnlibStyleStackEntry
    {
        public DnlibStyleStackEntry(int depth, int sourceIndex, string reason)
        {
            Depth = depth;
            SourceIndex = sourceIndex;
            Reason = reason ?? string.Empty;
        }

        public int Depth { get; }
        public int SourceIndex { get; }
        public string Reason { get; }
    }
}
