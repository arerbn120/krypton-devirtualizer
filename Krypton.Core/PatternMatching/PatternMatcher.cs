using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core.Architecture;
using Krypton.Core.PatternMatching.Patterns;

namespace Krypton.Core.PatternMatching
{
    public class PatternMatcher
    {
        private const int FallbackWindow = 256;
        private readonly HashSet<int> _knownValues = new HashSet<int>();
        private readonly Dictionary<MethodDefinition, IFieldDescriptor> _stlocArrayFieldCache =
            new Dictionary<MethodDefinition, IFieldDescriptor>();
        private readonly HashSet<MethodDefinition> _stlocArrayFieldCacheResolved =
            new HashSet<MethodDefinition>();

        public PatternMatcher()
        {
            OpCodes = new Dictionary<int, VMOpCode>();
            Patterns = new List<IPattern>();
            var patternTypes = typeof(PatternMatcher).Assembly.GetTypes()
                .Where(type => typeof(IPattern).IsAssignableFrom(type) && !type.IsInterface && !type.IsAbstract)
                .OrderBy(type => type.FullName, StringComparer.Ordinal)
                .ToList();

            foreach (var type in patternTypes)
            {
                if (Activator.CreateInstance(type) is IPattern instance)
                    Patterns.Add(instance);
            }

            // Deterministic ordering:
            // 1) explicit priority,
            // 2) stricter signatures,
            // 3) full type name as stable tie-break.
            Patterns = Patterns
                .OrderByDescending(GetPatternPriority)
                .ThenByDescending(p => p.Pattern.Count)
                .ThenBy(p => p.GetType().FullName, StringComparer.Ordinal)
                .ToList();
        }

        private Dictionary<int, VMOpCode> OpCodes { get; }
        private List<IPattern> Patterns { get; }

        public void SetOpCodeValue(VMOpCode opCode, int value)
        {
            _knownValues.Add(value);
            if (opCode == VMOpCode.Nop)
            {
                OpCodes.Remove(value);
                return;
            }

            OpCodes[value] = opCode;
        }

        public void MarkKnownNoOpValue(int value)
        {
            _knownValues.Add(value);
            OpCodes.Remove(value);
        }

        public bool IsOpCodeValueKnown(int value)
        {
            return _knownValues.Contains(value);
        }

        public void UnsetOpCodeValue(int value)
        {
            _knownValues.Remove(value);
            OpCodes.Remove(value);
        }

        public VMOpCode GetOpCodeValue(int value)
        {
            if (OpCodes.TryGetValue(value, out var opc)) return opc;
            return VMOpCode.Nop;
        }

        public VMOpCode FindOpCode(MethodDefinition Method, int index)
        {
            return FindOpCode(Method, index, true);
        }

        public VMOpCode FindOpCode(MethodDefinition Method, int index, bool allowFallback)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            foreach (var pat in Patterns)
                if (MatchesPattern(pat, instructions, index) && pat.Verify(Method, index))
                {
                    return pat.Translates;
                }

            if (!allowFallback)
                return VMOpCode.Nop;

            var inferred = InferFromHandler(Method, instructions, index);
            if (inferred != VMOpCode.Nop)
                return inferred;

            return VMOpCode.Nop;
        }

        public int GetMappedCount()
        {
            return _knownValues.Count;
        }

        private bool MatchesPattern(IPattern pattern, List<CilInstruction> instructions, int index)
        {
            var pat = pattern.Pattern;
            if (index + pat.Count > instructions.Count)
                return false;
            for (var i = 0; i < pat.Count; i++)
            {
                if (pat[i] == CilOpCodes.Nop)
                    continue;
                if (instructions[i + index].OpCode != pat[i])
                    return false;
            }

            return true;
        }

        private int GetPatternPriority(IPattern pattern)
        {
            if (pattern == null)
                return 0;

            if (PatternPriorityRegistry.TryGetPriority(pattern.GetType().FullName, out var configuredPriority))
                return configuredPriority;

            var attribute = pattern.GetType()
                .GetCustomAttributes(typeof(PatternPriorityAttribute), inherit: false)
                .OfType<PatternPriorityAttribute>()
                .FirstOrDefault();
            return attribute?.Priority ?? 0;
        }

        private VMOpCode InferFromHandler(MethodDefinition method, List<CilInstruction> instructions, int index)
        {
            if (instructions == null || index < 0 || index >= instructions.Count)
                return VMOpCode.Nop;

            var end = FindHandlerEnd(instructions, index, FallbackWindow);
            if (end <= index)
                return VMOpCode.Nop;

            var callFlag = TryInferCallFlag(instructions, index, end);
            if (callFlag != VMOpCode.Nop)
                return callFlag;

            if (LooksLikePackedInt32Load(instructions, index, end))
                return VMOpCode.Ldc_I4;

            if (LooksLikeLdstr(instructions, index, end))
                return VMOpCode.Ldstr;

            if (LooksLikeLdfld(instructions, index, end))
                return VMOpCode.Ldfld;

            if (LooksLikeLdlen(instructions, index, end))
                return VMOpCode.Ldlen;

            if (LooksLikeBrFalse(instructions, index, end))
                return VMOpCode.BrFalse;

            if (LooksLikeBrLessThan(instructions, index, end))
                return VMOpCode.BrLessThan;

            if (LooksLikeLdcI4(instructions, index, end))
                return VMOpCode.Ldc_I4;

            if (LooksLikeDup(instructions, index, end))
                return VMOpCode.Dup;

            if (LooksLikePop(instructions, index, end))
                return VMOpCode.Pop;

            var ldlocViaCtor = TryInferLdlocViaCtor(instructions, index, end);
            if (ldlocViaCtor != VMOpCode.Nop)
                return ldlocViaCtor;

            if (LooksLikeStloc(instructions, index, end))
                return VMOpCode.Stloc;

            if (LooksLikeArrayLoadPush(instructions, index, end))
            {
                var sourceField = GetPrimaryArrayField(instructions, index, end);
                if (TryGetStlocArrayField(method, instructions, out var stlocArrayField) &&
                    FieldsMatch(sourceField, stlocArrayField))
                {
                    return VMOpCode.Ldloc;
                }

                return VMOpCode.Ldarg;
            }

            if (LooksLikeStelemRef(instructions, index, end))
                return VMOpCode.Stelem_Ref;

            if (LooksLikeLdelemRef(instructions, index, end))
                return VMOpCode.Ldelem_Ref;

            var unary = TryInferUnaryOperation(method, instructions, index, end);
            if (unary != VMOpCode.Nop)
                return unary;

            var binary = TryInferBinaryOperation(method, instructions, index, end);
            if (binary != VMOpCode.Nop)
                return binary;

            return VMOpCode.Nop;
        }

        private VMOpCode TryInferCallFlag(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (index + 3 > end || instructions[index].OpCode != CilOpCodes.Ldarg_0)
                return VMOpCode.Nop;

            var flagInstr = instructions[index + 1];
            if (!PatternHelpers.IsIntConstant(flagInstr, 0) && !PatternHelpers.IsIntConstant(flagInstr, 1))
                return VMOpCode.Nop;

            var callIndex = index + 2;
            if (instructions[callIndex].OpCode == CilOpCodes.Ldsfld)
                callIndex++;

            if (callIndex > end || !IsBoolSetterCall(instructions[callIndex]))
                return VMOpCode.Nop;

            if (callIndex + 1 <= end && instructions[callIndex + 1].OpCode == CilOpCodes.Ret)
                return PatternHelpers.IsIntConstant(flagInstr, 1) ? VMOpCode.Call : VMOpCode.Callvirt;

            return VMOpCode.Nop;
        }

        private bool IsBoolSetterCall(CilInstruction instruction)
        {
            if (instruction == null)
                return false;
            if (instruction.OpCode != CilOpCodes.Call && instruction.OpCode != CilOpCodes.Callvirt)
                return false;
            if (!(instruction.Operand is IMethodDescriptor descriptor))
                return false;

            var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
            if (signature == null)
                return false;
            if (!string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
                return false;
            if (signature.ParameterTypes.Count < 2)
                return false;
            return string.Equals(signature.ParameterTypes[1].FullName, "System.Boolean", StringComparison.Ordinal);
        }

        private bool LooksLikeLdstr(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            return PatternHelpers.ContainsMethodCallWithSignatureOnType(
                instructions,
                index,
                end - index + 1,
                "System.Reflection.Module",
                "System.String",
                "System.Int32");
        }

        private bool LooksLikeLdfld(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (!PatternHelpers.ContainsMethodCallWithSignatureOnType(
                    instructions,
                    index,
                    end - index + 1,
                    "System.Reflection.Module",
                    "System.Reflection.FieldInfo",
                    "System.Int32"))
            {
                return false;
            }

            return PatternHelpers.ContainsMethodCallWithSignatureOnType(
                instructions,
                index,
                end - index + 1,
                "System.Reflection.FieldInfo",
                "System.Object",
                "System.Object");
        }

        private bool LooksLikeLdlen(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            var hasIntLengthGetter = false;
            for (var i = index; i <= end; i++)
            {
                if (!PatternHelpers.CalleeLooksLikeIntLengthGetter(instructions[i]))
                    continue;
                hasIntLengthGetter = true;
                break;
            }
            if (!hasIntLengthGetter)
                return false;

            for (var i = index; i <= end; i++)
            {
                if (instructions[i].OpCode != CilOpCodes.Newobj ||
                    !(instructions[i].Operand is IMethodDescriptor descriptor))
                {
                    continue;
                }

                var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
                if (signature == null || signature.ParameterTypes.Count < 1)
                    continue;
                if (string.Equals(signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal))
                    return true;
            }

            return false;
        }

        private bool LooksLikeBrFalse(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            return PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Ceq) &&
                   PatternHelpers.EndsWithStateDecrementAndReturn(instructions, index, end - index + 1);
        }

        private bool LooksLikeBrLessThan(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (!PatternHelpers.EndsWithStateDecrementAndReturn(instructions, index, end - index + 1))
                return false;

            var stlocCount = 0;
            for (var i = index; i <= end; i++)
            {
                if (instructions[i].OpCode == CilOpCodes.Stloc || instructions[i].OpCode == CilOpCodes.Stloc_S ||
                    instructions[i].OpCode == CilOpCodes.Stloc_0 || instructions[i].OpCode == CilOpCodes.Stloc_1 ||
                    instructions[i].OpCode == CilOpCodes.Stloc_2 || instructions[i].OpCode == CilOpCodes.Stloc_3)
                {
                    stlocCount++;
                }
            }

            return stlocCount >= 2 &&
                   PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Brfalse);
        }

        private bool LooksLikePop(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (instructions[end].OpCode != CilOpCodes.Ret)
                return false;

            if (!PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Pop))
                return false;

            // Opaque-predicate-heavy Reactor handlers often contain incidental Pop instructions.
            // Keep fallback Pop inference intentionally narrow and let more specific loaders win.
            if (PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Unbox_Any) ||
                PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Newobj) ||
                PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Ldtoken) ||
                PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Castclass) ||
                PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Isinst) ||
                PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Ldelem_Ref) ||
                PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Ldflda))
            {
                return false;
            }

            for (var i = index; i <= end; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Br ||
                    op == CilOpCodes.Br_S ||
                    op == CilOpCodes.Brtrue ||
                    op == CilOpCodes.Brtrue_S ||
                    op == CilOpCodes.Brfalse ||
                    op == CilOpCodes.Brfalse_S ||
                    op == CilOpCodes.Blt ||
                    op == CilOpCodes.Blt_S ||
                    op == CilOpCodes.Blt_Un ||
                    op == CilOpCodes.Blt_Un_S ||
                    op == CilOpCodes.Switch)
                {
                    return false;
                }
            }

            return true;
        }

        private bool LooksLikeDup(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (end - index < 6)
                return false;
            if (instructions[index].OpCode != CilOpCodes.Ldarg_0 || instructions[index + 1].OpCode != CilOpCodes.Ldfld)
                return false;
            if (instructions[index + 2].OpCode != CilOpCodes.Ldarg_0 || instructions[index + 3].OpCode != CilOpCodes.Ldfld)
                return false;

            var calls = GetCallsInRange(instructions, index, end).ToList();
            if (calls.Count < 2)
                return false;

            var first = calls[0];
            var second = calls[1];
            var firstDescriptor = first.Operand as IMethodDescriptor;
            var secondDescriptor = second.Operand as IMethodDescriptor;
            var firstSig = firstDescriptor?.Signature ?? firstDescriptor?.Resolve()?.Signature;
            var secondSig = secondDescriptor?.Signature ?? secondDescriptor?.Resolve()?.Signature;
            if (firstSig == null || secondSig == null)
                return false;

            return !string.Equals(firstSig.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) &&
                   string.Equals(secondSig.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) &&
                   secondSig.ParameterTypes.Count >= 2;
        }

        private bool LooksLikeLdcI4(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (!ContainsUnboxAnyInt32(instructions, index, end))
                return false;

            for (var i = index; i <= end; i++)
            {
                if (instructions[i].OpCode != CilOpCodes.Newobj ||
                    !(instructions[i].Operand is IMethodDescriptor descriptor))
                {
                    continue;
                }

                var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
                if (signature == null || signature.ParameterTypes.Count != 1)
                    continue;
                if (!string.Equals(signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal))
                    continue;

                return true;
            }

            return false;
        }

        private bool LooksLikePackedInt32Load(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            var ldelemU1Count = 0;
            var shlCount = 0;
            var hasOr = false;
            var callCount = 0;

            for (var i = index; i <= end; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Ldelem_U1)
                    ldelemU1Count++;
                else if (op == CilOpCodes.Shl)
                    shlCount++;
                else if (op == CilOpCodes.Or)
                    hasOr = true;
                else if (op == CilOpCodes.Call || op == CilOpCodes.Callvirt)
                    callCount++;
            }

            // Generic Reactor-style operand reconstruction:
            // combine multiple bytes with shifts/or without reflection/runtime calls.
            return ldelemU1Count >= 2 && shlCount >= 1 && hasOr && callCount == 0;
        }

        private bool LooksLikeStloc(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (index + 3 > end)
                return false;
            if (instructions[index].OpCode != CilOpCodes.Ldarg_0 || instructions[index + 1].OpCode != CilOpCodes.Ldfld)
                return false;
            if (instructions[index + 2].OpCode != CilOpCodes.Unbox_Any)
                return false;

            var stloc = instructions[index + 3].OpCode;
            if (stloc != CilOpCodes.Stloc &&
                stloc != CilOpCodes.Stloc_S &&
                stloc != CilOpCodes.Stloc_0 &&
                stloc != CilOpCodes.Stloc_1 &&
                stloc != CilOpCodes.Stloc_2 &&
                stloc != CilOpCodes.Stloc_3)
            {
                return false;
            }

            return PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Stelem_Ref);
        }

        private bool LooksLikeStelemRef(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (PatternHelpers.ContainsMethodCallOnType(instructions, index, end - index + 1, "SetValue", "System.Array"))
                return true;
            return PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Stelem_Ref);
        }

        private bool LooksLikeLdelemRef(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            return PatternHelpers.ContainsMethodCallOnType(instructions, index, end - index + 1, "GetValue", "System.Array");
        }

        private bool LooksLikeArrayLoadPush(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            return PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Ldelem_Ref) &&
                   ContainsUnboxAnyInt32(instructions, index, end) &&
                   instructions[end].OpCode == CilOpCodes.Ret;
        }

        private VMOpCode TryInferLdlocViaCtor(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            for (var i = index; i <= end; i++)
            {
                if (instructions[i].OpCode != CilOpCodes.Newobj ||
                    !(instructions[i].Operand is IMethodDescriptor descriptor))
                {
                    continue;
                }

                var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
                if (signature == null || signature.ParameterTypes.Count != 2)
                    continue;

                if (!string.Equals(signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal))
                    continue;

                if (PatternHelpers.ContainsOpCode(instructions, index, end - index + 1, CilOpCodes.Unbox_Any) &&
                    instructions[end].OpCode == CilOpCodes.Ret)
                {
                    return VMOpCode.Ldloc;
                }
            }

            return VMOpCode.Nop;
        }

        private VMOpCode TryInferUnaryOperation(
            MethodDefinition method,
            IReadOnlyList<CilInstruction> instructions,
            int index,
            int end)
        {
            var detected = new HashSet<VMOpCode>();
            foreach (var candidate in GetNonVoidCalls(instructions, index, end).Reverse())
            {
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Conv_I4, 10))
                    detected.Add(VMOpCode.Conv_I4);
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Conv_I8, 10))
                    detected.Add(VMOpCode.Conv_I8);
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Conv_U1, 10))
                    detected.Add(VMOpCode.Conv_U1);
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Not, 10))
                    detected.Add(VMOpCode.Not);
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Neg, 10))
                    detected.Add(VMOpCode.Neg);
            }

            if (detected.Count == 1)
                return detected.First();

            return VMOpCode.Nop;
        }

        private VMOpCode TryInferBinaryOperation(
            MethodDefinition method,
            IReadOnlyList<CilInstruction> instructions,
            int index,
            int end)
        {
            var detected = new HashSet<VMOpCode>();
            foreach (var candidate in GetNonVoidCalls(instructions, index, end).Reverse())
            {
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Add, 10))
                    detected.Add(VMOpCode.Add);
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Sub, 10))
                    detected.Add(VMOpCode.Sub);
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Xor, 10))
                    detected.Add(VMOpCode.Xor);
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Shl, 10))
                    detected.Add(VMOpCode.Shl);
                if (PatternHelpers.CalleeContainsOpCode(method, candidate, CilCode.Shr, 10))
                    detected.Add(VMOpCode.Shr);
            }

            if (detected.Count == 1)
                return detected.First();

            return VMOpCode.Nop;
        }

        private IList<CilInstruction> GetNonVoidCalls(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            var calls = new List<CilInstruction>();
            for (var i = end; i >= index; i--)
            {
                var instruction = instructions[i];
                if (instruction.OpCode != CilOpCodes.Call && instruction.OpCode != CilOpCodes.Callvirt)
                    continue;

                if (!(instruction.Operand is IMethodDescriptor descriptor))
                    continue;

                var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
                if (signature == null)
                    continue;

                if (!string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
                    calls.Add(instruction);
            }

            return calls;
        }

        private bool LooksLikeBinaryWrapper(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (PatternHelpers.EndsWithStateDecrementAndReturn(instructions, index, end - index + 1))
                return false;

            var brfalseCount = 0;
            var callCount = 0;
            for (var i = index; i <= end; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Brfalse)
                    brfalseCount++;
                if (op == CilOpCodes.Call || op == CilOpCodes.Callvirt)
                    callCount++;
            }

            return brfalseCount >= 2 && callCount >= 4;
        }

        private bool LooksLikeUnaryWrapper(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            if (PatternHelpers.EndsWithStateDecrementAndReturn(instructions, index, end - index + 1))
                return false;

            var brfalseCount = 0;
            var callvirtCount = 0;
            for (var i = index; i <= end; i++)
            {
                var op = instructions[i].OpCode;
                if (op == CilOpCodes.Brfalse)
                    brfalseCount++;
                if (op == CilOpCodes.Callvirt)
                    callvirtCount++;
            }

            return brfalseCount >= 1 && callvirtCount >= 1;
        }

        private IEnumerable<CilInstruction> GetCallsInRange(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            for (var i = index; i <= end; i++)
            {
                var opCode = instructions[i].OpCode;
                if (opCode == CilOpCodes.Call || opCode == CilOpCodes.Callvirt)
                    yield return instructions[i];
            }
        }

        private bool ContainsUnboxAnyInt32(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            for (var i = index; i <= end; i++)
            {
                if (instructions[i].OpCode != CilOpCodes.Unbox_Any)
                    continue;
                if (!(instructions[i].Operand is ITypeDescriptor descriptor))
                    continue;
                if (string.Equals(descriptor.FullName, "System.Int32", StringComparison.Ordinal))
                    return true;
            }

            return false;
        }

        private int FindHandlerEnd(IReadOnlyList<CilInstruction> instructions, int start, int maxDistance)
        {
            var end = Math.Min(instructions.Count, start + Math.Max(maxDistance, 1));
            for (var i = start; i < end; i++)
            {
                if (instructions[i].OpCode == CilOpCodes.Ret)
                    return i;
            }

            return end - 1;
        }

        private bool TryGetStlocArrayField(
            MethodDefinition method,
            IReadOnlyList<CilInstruction> instructions,
            out IFieldDescriptor field)
        {
            if (_stlocArrayFieldCacheResolved.Contains(method))
            {
                field = _stlocArrayFieldCache.TryGetValue(method, out var cached) ? cached : null;
                return field != null;
            }

            field = null;
            for (var i = 0; i < instructions.Count - 4; i++)
            {
                if (instructions[i].OpCode != CilOpCodes.Ldarg_0 ||
                    instructions[i + 1].OpCode != CilOpCodes.Ldfld ||
                    instructions[i + 2].OpCode != CilOpCodes.Unbox_Any)
                {
                    continue;
                }

                var stloc = instructions[i + 3].OpCode;
                if (stloc != CilOpCodes.Stloc &&
                    stloc != CilOpCodes.Stloc_S &&
                    stloc != CilOpCodes.Stloc_0 &&
                    stloc != CilOpCodes.Stloc_1 &&
                    stloc != CilOpCodes.Stloc_2 &&
                    stloc != CilOpCodes.Stloc_3)
                {
                    continue;
                }

                var end = FindHandlerEnd(instructions, i, 128);
                if (!PatternHelpers.ContainsOpCode(instructions, i, end - i + 1, CilOpCodes.Stelem_Ref))
                    continue;

                field = GetPrimaryArrayField(instructions, i, end);
                if (field != null)
                    break;
            }

            _stlocArrayFieldCacheResolved.Add(method);
            _stlocArrayFieldCache[method] = field;
            return field != null;
        }

        private IFieldDescriptor GetPrimaryArrayField(IReadOnlyList<CilInstruction> instructions, int index, int end)
        {
            for (var i = index; i <= end; i++)
            {
                if (instructions[i].OpCode != CilOpCodes.Ldfld)
                    continue;
                if (!(instructions[i].Operand is IFieldDescriptor field))
                    continue;

                var signature = field.Signature ?? field.Resolve()?.Signature;
                var fieldTypeName = signature?.FieldType?.FullName ?? string.Empty;
                if (fieldTypeName.EndsWith("[]", StringComparison.Ordinal))
                    return field;
            }

            return null;
        }

        private bool FieldsMatch(IFieldDescriptor left, IFieldDescriptor right)
        {
            if (left == null || right == null)
                return false;
            if (ReferenceEquals(left, right))
                return true;

            var leftResolved = left.Resolve();
            var rightResolved = right.Resolve();
            if (leftResolved != null && rightResolved != null)
                return string.Equals(leftResolved.FullName, rightResolved.FullName, StringComparison.Ordinal);

            return string.Equals(left.FullName, right.FullName, StringComparison.Ordinal);
        }
    }
}
