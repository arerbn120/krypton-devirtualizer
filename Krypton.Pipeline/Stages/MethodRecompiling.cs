using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    public class MethodRecompiling : IStage, ICilLowerer
    {
        private readonly Dictionary<int, string> _userStringCache = new Dictionary<int, string>();
        private readonly HashSet<string> _loggedCallFallbacks = new HashSet<string>();
        private string _userStringCachePath;

        public string Name => nameof(MethodRecompiling);

        public void Run(DevirtualizationCtx Ctx)
        {
            _loggedCallFallbacks.Clear();
            if (!string.Equals(_userStringCachePath, Ctx.Options.FilePath, StringComparison.OrdinalIgnoreCase))
            {
                _userStringCache.Clear();
                _userStringCachePath = Ctx.Options.FilePath;
            }

            var lowerer = Ctx.CilLowerer ?? this;
            foreach (var method in Ctx.VirtualizedMethods)
            {
                var unknownCount = method.MethodBody.Instructions.Count(q => !q.IsResolved);
                if (unknownCount > 0)
                {
                    var methodName = method.Parent?.FullName ?? "<unresolved method>";
                    Ctx.Options.Logger.Warning(
                        $"Skipping recompilation for {methodName} because {unknownCount} VM instructions are still unknown.");
                    method.RecompiledBody = null;
                    continue;
                }

                try
                {
                    RecompiledMethodArtifact artifact;
                    if (ReferenceEquals(lowerer, this))
                    {
                        artifact = RecompileDetailed(Ctx, method);
                    }
                    else
                    {
                        artifact = new RecompiledMethodArtifact(
                            lowerer.Recompile(Ctx, method),
                            method.MethodBody.Instructions.ToList());
                    }

                    LogDnlibStyleMaxStackAnalysis(Ctx, method, artifact);
                    method.RecompiledBody = artifact.Body;
                    Ctx.Options.Logger.Info($"Recompiled method body for {method.Parent.FullName}");
                }
                catch (Exception ex)
                {
                    method.RecompiledBody = null;
                    Ctx.Options.Logger.Warning(
                        $"Recompilation failed for {method.Parent.FullName}: {ex.Message}");
                    TryDumpRecompileFailure(Ctx, method, ex);
                    if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_EXCEPTIONS"), "1", StringComparison.Ordinal))
                        Ctx.Options.Logger.Warning(ex.ToString());
                }
            }
        }

        public CilMethodBody Recompile(DevirtualizationCtx ctx, VMMethod vmMethod)
        {
            return RecompileDetailed(ctx, vmMethod).Body;
        }

        internal RecompiledMethodArtifact RecompileDetailed(DevirtualizationCtx ctx, VMMethod vmMethod)
        {
            if (vmMethod.Parent == null)
                throw new DevirtualizationException("VM method has no parent method.");

            var relaxStackValidation = string.Equals(
                Environment.GetEnvironmentVariable("KRYPTON_RELAX_STACK_VALIDATION"),
                "1",
                StringComparison.Ordinal);
            var body = new CilMethodBody(vmMethod.Parent)
            {
                InitializeLocals = true,
                ComputeMaxStackOnBuild = !relaxStackValidation,
                MaxStack = relaxStackValidation ? 64 : 8
            };
            if (relaxStackValidation)
            {
                body.VerifyLabelsOnBuild = false;
                body.BuildFlags &= ~(CilMethodBodyBuildFlags.ComputeMaxStack |
                                     CilMethodBodyBuildFlags.VerifyLabels |
                                     CilMethodBodyBuildFlags.FullValidation);
            }

            var localTypes = InferLocalTypes(ctx, vmMethod);
            if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_LOCAL_TYPES"), "1", StringComparison.Ordinal))
            {
                var summary = string.Join(", ", localTypes.Select(t => t?.FullName ?? "<null>"));
                ctx.Options.Logger.Info($"Local type inference: {summary}");
            }
            var locals = new List<CilLocalVariable>(localTypes.Count);
            foreach (var localType in localTypes)
            {
                var local = new CilLocalVariable(localType);
                body.LocalVariables.Add(local);
                locals.Add(local);
            }

            var fixups = new List<(CilInstruction instruction, int targetOffset, int sourceOffset, VMInstruction sourceInstruction)>();
            var switchFixups = new List<(CilInstruction instruction, int[] targets)>();
            var translatedInstructionMap = new List<CilInstruction>(vmMethod.MethodBody.Instructions.Count);
            var translatedInstructionOrigins = new List<VMInstruction>(vmMethod.MethodBody.Instructions.Count);
            foreach (var vmInstruction in vmMethod.MethodBody.Instructions)
            {
                try
                {
                    var translated = TranslateInstruction(ctx, vmMethod, vmInstruction, locals, fixups, switchFixups);
                    body.Instructions.Add(translated);
                    translatedInstructionMap.Add(translated);
                    translatedInstructionOrigins.Add(vmInstruction);
                }
                catch (Exception ex)
                {
                    throw new DevirtualizationException(
                        $"Failed to translate VM instruction offset {vmInstruction.Offset} (vm:0x{vmInstruction.VmByte:X2}, op:{vmInstruction.OpCode}, operand:{vmInstruction.Operand ?? "<null>"}): {ex.Message}");
                }
            }

            foreach (var fixup in fixups)
            {
                if (!TryNormalizeInstructionOffset(fixup.targetOffset, translatedInstructionMap.Count, out var normalizedTarget))
                    throw new DevirtualizationException($"Invalid branch target offset {fixup.targetOffset}.");

                var targetInstruction = translatedInstructionMap[normalizedTarget];
                ApplyBranchFixup(
                    vmMethod,
                    body,
                    fixup.instruction,
                    fixup.sourceOffset,
                    normalizedTarget,
                    targetInstruction,
                    translatedInstructionOrigins,
                    fixup.sourceInstruction);
            }

            foreach (var switchFixup in switchFixups)
            {
                var labels = new List<ICilLabel>(switchFixup.targets.Length);
                for (var i = 0; i < switchFixup.targets.Length; i++)
                {
                    var targetOffset = switchFixup.targets[i];
                    if (!TryNormalizeInstructionOffset(targetOffset, translatedInstructionMap.Count, out var normalizedTarget))
                        throw new DevirtualizationException($"Invalid switch target offset {targetOffset}.");

                    labels.Add(new CilInstructionLabel(translatedInstructionMap[normalizedTarget]));
                }

                switchFixup.instruction.Operand = labels;
            }

            NormalizeDispatcherBranches(body);
            LiftDispatcherBranches(body, translatedInstructionOrigins);
            SpecializeDispatcherBlocksByEntryStackDepth(body, translatedInstructionOrigins, vmMethod);
            SanitizeUnreachableInvalidInstructions(body);
            ApplyExceptionHandlers(vmMethod, body, translatedInstructionMap);
            return new RecompiledMethodArtifact(body, translatedInstructionOrigins);
        }

        private bool TryNormalizeInstructionOffset(int rawOffset, int instructionCount, out int normalizedOffset)
        {
            normalizedOffset = rawOffset;
            if (rawOffset >= 0 && rawOffset < instructionCount)
                return true;

            // Some wrong mappings leak metadata-like tokens as branch operands.
            // Attempt a conservative normalization before rejecting.
            var low24 = rawOffset & 0x00FFFFFF;
            if (low24 >= 0 && low24 < instructionCount)
            {
                normalizedOffset = low24;
                return true;
            }

            var low16 = rawOffset & 0x0000FFFF;
            if (low16 >= 0 && low16 < instructionCount)
            {
                normalizedOffset = low16;
                return true;
            }

            return false;
        }

        private List<TypeSignature> InferLocalTypes(DevirtualizationCtx ctx, VMMethod vmMethod)
        {
            var maxLocalIndex = -1;
            foreach (var instruction in vmMethod.MethodBody.Instructions)
            {
                if ((instruction.OpCode == VMOpCode.Stloc || instruction.OpCode == VMOpCode.Ldloc) &&
                    instruction.Operand is int index &&
                    index > maxLocalIndex)
                    maxLocalIndex = index;
            }

            var localCount = Math.Max(vmMethod.MethodBody.Locals.Count, maxLocalIndex + 1);
            var types = new List<TypeSignature>(localCount);
            for (var i = 0; i < localCount; i++)
            {
                if (i < vmMethod.MethodBody.Locals.Count)
                    types.Add(ToTypeSignature(ctx, vmMethod.MethodBody.Locals[i]));
                else
                    types.Add(ctx.Module.CorLibTypeFactory.Object);
            }

            for (var i = 0; i < vmMethod.MethodBody.Instructions.Count; i++)
            {
                var instruction = vmMethod.MethodBody.Instructions[i];
                if (instruction.OpCode != VMOpCode.Stloc || !(instruction.Operand is int localIndex))
                    continue;

                if (localIndex < 0 || localIndex >= types.Count || i == 0)
                    continue;

                var producer = FindLikelyProducerInstruction(vmMethod.MethodBody.Instructions, i);
                if (producer == null)
                    continue;

                var inferred = InferFromProducer(ctx, producer);
                if (ShouldPreferInferredLocalType(
                        ctx,
                        types[localIndex],
                        inferred))
                {
                    types[localIndex] = inferred;
                }
            }

            return types;
        }

        private bool ShouldPreferInferredLocalType(
            DevirtualizationCtx ctx,
            TypeSignature current,
            TypeSignature inferred)
        {
            if (inferred == null)
                return false;
            if (current == null)
                return true;
            if (string.Equals(current.FullName, inferred.FullName, StringComparison.Ordinal))
                return false;

            var corLib = ctx?.Module?.CorLibTypeFactory;
            if (corLib != null &&
                string.Equals(current.FullName, corLib.Object.FullName, StringComparison.Ordinal))
            {
                return true;
            }

            if (LooksLikePlaceholderValueType(current) &&
                !LooksLikePlaceholderValueType(inferred))
            {
                return true;
            }

            return false;
        }

        private bool LooksLikePlaceholderValueType(TypeSignature type)
        {
            if (type == null)
                return true;

            switch (type.FullName)
            {
                case "System.Boolean":
                case "System.SByte":
                case "System.Byte":
                case "System.Int16":
                case "System.UInt16":
                case "System.Int32":
                case "System.UInt32":
                case "System.Int64":
                case "System.UInt64":
                case "System.IntPtr":
                case "System.UIntPtr":
                    return true;
                default:
                    return false;
            }
        }

        private VMInstruction FindLikelyProducerInstruction(IList<VMInstruction> instructions, int consumerIndex)
        {
            if (instructions == null || consumerIndex <= 0 || consumerIndex > instructions.Count)
                return null;

            var targetDepth = 1;
            var stop = Math.Max(0, consumerIndex - 64);
            for (var i = consumerIndex - 1; i >= stop; i--)
            {
                var candidate = instructions[i];
                if (candidate.OpCode == VMOpCode.Call ||
                    candidate.OpCode == VMOpCode.Callvirt ||
                    candidate.OpCode == VMOpCode.Newobj ||
                    candidate.OpCode == VMOpCode.Newarr)
                {
                    return candidate;
                }

                if (!TryGetApproximateStackEffect(candidate.OpCode, out var pop, out var push))
                    continue;

                targetDepth += pop - push;
                if (targetDepth <= 0)
                    return candidate;

                if (candidate.OpCode == VMOpCode.Br ||
                    candidate.OpCode == VMOpCode.BrTrue ||
                    candidate.OpCode == VMOpCode.BrFalse ||
                    candidate.OpCode == VMOpCode.BrLessThan ||
                    candidate.OpCode == VMOpCode.Switch ||
                    candidate.OpCode == VMOpCode.Ret)
                {
                    break;
                }
            }

            return instructions[consumerIndex - 1];
        }

        private bool TryGetApproximateStackEffect(VMOpCode opCode, out int pop, out int push)
        {
            pop = 0;
            push = 0;
            switch (opCode)
            {
                case VMOpCode.Nop:
                    return true;
                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldsfld:
                case VMOpCode.Newobj:
                    push = 1;
                    return true;
                case VMOpCode.Ldfld:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldobj:
                case VMOpCode.Unbox_Any:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldelema:
                    pop = 2;
                    push = 1;
                    return true;
                case VMOpCode.Newarr:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.Stloc:
                case VMOpCode.Pop:
                    pop = 1;
                    return true;
                case VMOpCode.Dup:
                    pop = 1;
                    push = 2;
                    return true;
                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                    pop = 2;
                    push = 1;
                    return true;
                case VMOpCode.Neg:
                case VMOpCode.Not:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                    pop = 1;
                    return true;
                case VMOpCode.BrLessThan:
                    pop = 2;
                    return true;
                case VMOpCode.Switch:
                    pop = 1;
                    return true;
                case VMOpCode.Stsfld:
                    pop = 1;
                    return true;
                case VMOpCode.Stfld:
                case VMOpCode.Stobj:
                    pop = 2;
                    return true;
                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                    pop = 3;
                    return true;
                default:
                    return false;
            }
        }

        private TypeSignature ToTypeSignature(DevirtualizationCtx ctx, ITypeDescriptor descriptor)
        {
            if (descriptor == null)
                return ctx.Module.CorLibTypeFactory.Object;

            if (descriptor is TypeSignature signature)
                return signature;

            if (descriptor is ITypeDefOrRef typeDefOrRef)
                return new TypeDefOrRefSignature(typeDefOrRef);

            return ctx.Module.CorLibTypeFactory.Object;
        }

        private TypeSignature InferFromProducer(DevirtualizationCtx ctx, VMInstruction producer)
        {
            switch (producer.OpCode)
            {
                case VMOpCode.Ldc_I4:
                case VMOpCode.Conv_I4:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Add:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Sub:
                case VMOpCode.Neg:
                case VMOpCode.Conv_U1:
                case VMOpCode.Not:
                    return ctx.Module.CorLibTypeFactory.Int32;
                case VMOpCode.Conv_I8:
                    return ctx.Module.CorLibTypeFactory.Int64;
                case VMOpCode.Ldnull:
                    return ctx.Module.CorLibTypeFactory.Object;
                case VMOpCode.Ldstr:
                    return ctx.Module.CorLibTypeFactory.String;
                case VMOpCode.Newarr:
                {
                    var elementType = ResolveTypeFromToken(ctx, producer.Operand);
                    return elementType == null
                        ? null
                        : new SzArrayTypeSignature(new TypeDefOrRefSignature(elementType));
                }
                case VMOpCode.Unbox_Any:
                {
                    var targetType = ResolveTypeFromToken(ctx, producer.Operand);
                    return targetType == null ? null : new TypeDefOrRefSignature(targetType);
                }
                case VMOpCode.Newobj:
                {
                    var descriptor = ResolveMethodDescriptor(ctx, producer.Operand) as IMethodDefOrRef;
                    if (descriptor?.DeclaringType == null)
                        return null;
                    return new TypeDefOrRefSignature(descriptor.DeclaringType);
                }
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                {
                    if (producer.Operand is int producerToken &&
                        !IsMethodMetadataToken(producerToken))
                    {
                        // Wrong call-mapping occasionally leaks raw metadata tokens.
                        // Treat these as integer constants so local type inference stays resilient.
                        return ctx.Module.CorLibTypeFactory.Int32;
                    }

                    var descriptor = ResolveMethodDescriptor(ctx, producer.Operand);
                    return ResolveCallReturnType(descriptor);
                }
                case VMOpCode.Ldsfld:
                {
                    var field = ResolveFieldDescriptor(ctx, producer.Operand);
                    return field.Signature?.FieldType ?? field.Resolve()?.Signature?.FieldType;
                }
                case VMOpCode.Ldfld:
                {
                    var field = ResolveFieldDescriptor(ctx, producer.Operand);
                    return field.Signature?.FieldType ?? field.Resolve()?.Signature?.FieldType;
                }
                default:
                    return null;
            }
        }

        private TypeSignature ResolveCallReturnType(IMethodDescriptor descriptor)
        {
            if (descriptor == null)
                return null;

            if (descriptor is AsmResolver.DotNet.MethodSpecification methodSpec)
            {
                var baseReturnType = methodSpec.Method?.Signature?.ReturnType;
                return SubstituteMethodGenericArguments(baseReturnType, methodSpec.Signature?.TypeArguments);
            }

            return descriptor.Signature?.ReturnType;
        }

        private TypeSignature SubstituteMethodGenericArguments(
            TypeSignature signature,
            IList<TypeSignature> methodTypeArguments)
        {
            if (signature == null)
                return null;

            if (signature is GenericParameterSignature genericParameter &&
                genericParameter.ParameterType == GenericParameterType.Method &&
                methodTypeArguments != null &&
                genericParameter.Index >= 0 &&
                genericParameter.Index < methodTypeArguments.Count)
                return methodTypeArguments[genericParameter.Index];

            if (signature is SzArrayTypeSignature szArray)
            {
                var baseType = SubstituteMethodGenericArguments(szArray.BaseType, methodTypeArguments);
                if (baseType == null || ReferenceEquals(baseType, szArray.BaseType))
                    return signature;
                return new SzArrayTypeSignature(baseType);
            }

            if (signature is GenericInstanceTypeSignature genericInstance)
            {
                var changed = false;
                var substituted = new TypeSignature[genericInstance.TypeArguments.Count];
                for (var i = 0; i < genericInstance.TypeArguments.Count; i++)
                {
                    var current = genericInstance.TypeArguments[i];
                    substituted[i] = SubstituteMethodGenericArguments(current, methodTypeArguments);
                    if (!ReferenceEquals(substituted[i], current))
                        changed = true;
                }

                if (!changed)
                    return signature;

                return new GenericInstanceTypeSignature(genericInstance.GenericType, genericInstance.IsValueType, substituted);
            }

            return signature;
        }

        private CilInstruction TranslateInstruction(
            DevirtualizationCtx ctx,
            VMMethod vmMethod,
            VMInstruction instruction,
            IList<CilLocalVariable> locals,
            ICollection<(CilInstruction instruction, int targetOffset, int sourceOffset, VMInstruction sourceInstruction)> fixups,
            ICollection<(CilInstruction instruction, int[] targets)> switchFixups)
        {
            switch (instruction.OpCode)
            {
                case VMOpCode.Nop:
                    return new CilInstruction(CilOpCodes.Nop);
                case VMOpCode.Ldarg:
                    return BuildLdargInstruction(vmMethod, locals, instruction.Operand);
                case VMOpCode.Ldloc:
                    return BuildLdlocInstruction(locals, instruction.Operand);
                case VMOpCode.Stloc:
                    return BuildStlocInstruction(locals, instruction.Operand);
                case VMOpCode.Ldsfld:
                    return new CilInstruction(CilOpCodes.Ldsfld, ResolveFieldDescriptor(ctx, instruction.Operand));
                case VMOpCode.Ldfld:
                    return new CilInstruction(CilOpCodes.Ldfld, ResolveFieldDescriptor(ctx, instruction.Operand));
                case VMOpCode.Stsfld:
                    return new CilInstruction(CilOpCodes.Stsfld, ResolveFieldDescriptor(ctx, instruction.Operand));
                case VMOpCode.Stfld:
                    return new CilInstruction(CilOpCodes.Stfld, ResolveFieldDescriptor(ctx, instruction.Operand));
                case VMOpCode.Ldc_I4:
                    return new CilInstruction(CilOpCodes.Ldc_I4, Convert.ToInt32(instruction.Operand));
                case VMOpCode.Ldelem_Ref:
                    return new CilInstruction(CilOpCodes.Ldelem_Ref);
                case VMOpCode.Ldelem_U1:
                    return new CilInstruction(CilOpCodes.Ldelem_U1);
                case VMOpCode.Stelem_Ref:
                    return new CilInstruction(CilOpCodes.Stelem_Ref);
                case VMOpCode.Stelem_I1:
                    return new CilInstruction(CilOpCodes.Stelem_I1);
                case VMOpCode.Ldstr:
                    return new CilInstruction(CilOpCodes.Ldstr, ResolveUserString(ctx, Convert.ToInt32(instruction.Operand)));
                case VMOpCode.Call:
                    if (TryBuildCallInstructionOrFallback(ctx, vmMethod, instruction, false, out var callInstruction))
                        return callInstruction;

                    throw new DevirtualizationException("Could not translate VM Call instruction.");
                case VMOpCode.Callvirt:
                    if (TryBuildCallInstructionOrFallback(ctx, vmMethod, instruction, true, out var virtualCallInstruction))
                        return virtualCallInstruction;

                    throw new DevirtualizationException("Could not translate VM Callvirt instruction.");
                case VMOpCode.Newobj:
                    return new CilInstruction(CilOpCodes.Newobj, ResolveMethodDescriptor(ctx, instruction.Operand));
                case VMOpCode.Newarr:
                    return new CilInstruction(CilOpCodes.Newarr, ResolveTypeFromToken(ctx, instruction.Operand));
                case VMOpCode.Unbox_Any:
                    return new CilInstruction(CilOpCodes.Unbox_Any, ResolveTypeFromToken(ctx, instruction.Operand));
                case VMOpCode.Br:
                    return BuildUnconditionalBranch(instruction, fixups);
                case VMOpCode.BrTrue:
                {
                    var branch = new CilInstruction(CilOpCodes.Brtrue);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrLessThan:
                {
                    var branch = new CilInstruction(CilOpCodes.Blt_Un);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrFalse:
                {
                    var branch = new CilInstruction(CilOpCodes.Brfalse);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.Pop:
                    return new CilInstruction(CilOpCodes.Pop);
                case VMOpCode.Dup:
                    return new CilInstruction(CilOpCodes.Dup);
                case VMOpCode.Ldlen:
                    return new CilInstruction(CilOpCodes.Ldlen);
                case VMOpCode.Ldelema:
                    return new CilInstruction(CilOpCodes.Ldelema, ResolveTypeFromToken(ctx, instruction.Operand));
                case VMOpCode.Ldobj:
                    return BuildLdobjInstruction(ctx, instruction.Operand);
                case VMOpCode.Stobj:
                    return BuildStobjInstruction(ctx, instruction.Operand);
                case VMOpCode.Conv_I4:
                    return new CilInstruction(CilOpCodes.Conv_I4);
                case VMOpCode.Conv_I8:
                    return new CilInstruction(CilOpCodes.Conv_I8);
                case VMOpCode.Conv_U1:
                    return new CilInstruction(CilOpCodes.Conv_U1);
                case VMOpCode.Not:
                    return new CilInstruction(CilOpCodes.Not);
                case VMOpCode.Add:
                    return new CilInstruction(CilOpCodes.Add);
                case VMOpCode.Xor:
                    return new CilInstruction(CilOpCodes.Xor);
                case VMOpCode.Shl:
                    return new CilInstruction(CilOpCodes.Shl);
                case VMOpCode.Shr:
                    return new CilInstruction(CilOpCodes.Shr);
                case VMOpCode.Sub:
                    return new CilInstruction(CilOpCodes.Sub);
                case VMOpCode.Neg:
                    return new CilInstruction(CilOpCodes.Neg);
                case VMOpCode.Ldnull:
                    return new CilInstruction(CilOpCodes.Ldnull);
                case VMOpCode.Ldtoken:
                    return BuildLdtokenInstruction(ctx, instruction.Operand);
                case VMOpCode.Switch:
                {
                    if (!(instruction.Operand is int[] targets))
                        throw new DevirtualizationException("Expected Int32[] switch operand.");

                    var branch = new CilInstruction(CilOpCodes.Switch);
                    switchFixups.Add((branch, targets));
                    return branch;
                }
                case VMOpCode.EndFinally:
                    return new CilInstruction(CilOpCodes.Endfinally);
                case VMOpCode.Leave:
                {
                    if (!(instruction.Operand is int))
                    {
                        if (IsStrictDiagnostics(ctx))
                        {
                            throw new DevirtualizationException(
                                "VM Leave opcode requires a target offset operand in strict diagnostics mode.");
                        }

                        ctx.Options.Logger.Warning(
                            $"VM Leave at offset {instruction.Offset} has no target operand; interpreting as Endfinally.");
                        return new CilInstruction(CilOpCodes.Endfinally);
                    }

                    var branch = new CilInstruction(CilOpCodes.Leave);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.Ret:
                    return new CilInstruction(CilOpCodes.Ret);
                default:
                    throw new DevirtualizationException($"Cannot recompile unsupported VM opcode: {instruction.OpCode}");
            }
        }

        private CilInstruction BuildUnconditionalBranch(
            VMInstruction instruction,
            ICollection<(CilInstruction instruction, int targetOffset, int sourceOffset, VMInstruction sourceInstruction)> fixups)
        {
            var targetOffset = Convert.ToInt32(instruction.Operand);
            var branch = new CilInstruction(CilOpCodes.Br);
            fixups.Add((branch, targetOffset, instruction.Offset, instruction));
            return branch;
        }

        private void ApplyBranchFixup(
            VMMethod vmMethod,
            CilMethodBody body,
            CilInstruction branchInstruction,
            int sourceOffset,
            int targetOffset,
            CilInstruction targetInstruction,
            IList<VMInstruction> instructionOrigins,
            VMInstruction sourceInstruction)
        {
            if (branchInstruction == null)
                throw new ArgumentNullException(nameof(branchInstruction));

            var requiresLeave = ShouldUseLeave(vmMethod, sourceOffset, targetOffset);
            if (!requiresLeave)
            {
                branchInstruction.Operand = new CilInstructionLabel(targetInstruction);
                return;
            }

            if (branchInstruction.OpCode == CilOpCodes.Br)
            {
                branchInstruction.OpCode = CilOpCodes.Leave;
                branchInstruction.Operand = new CilInstructionLabel(targetInstruction);
                return;
            }

            if (branchInstruction.OpCode == CilOpCodes.Leave)
            {
                branchInstruction.Operand = new CilInstructionLabel(targetInstruction);
                return;
            }

            var inverse = GetInverseBranchOpCode(branchInstruction.OpCode);
            if (inverse == null)
                throw new DevirtualizationException(
                    $"Cannot lower EH-safe conditional branch opcode {branchInstruction.OpCode} at offset {sourceOffset}.");

            var leaveInstruction = new CilInstruction(CilOpCodes.Leave, new CilInstructionLabel(targetInstruction));
            var skipLeaveInstruction = new CilInstruction(CilOpCodes.Nop);
            branchInstruction.OpCode = inverse.Value;
            branchInstruction.Operand = new CilInstructionLabel(skipLeaveInstruction);

            var branchIndex = body.Instructions.IndexOf(branchInstruction);
            if (branchIndex < 0)
                throw new DevirtualizationException("Could not locate branch instruction during EH fixup.");

            body.Instructions.Insert(branchIndex + 1, leaveInstruction);
            body.Instructions.Insert(branchIndex + 2, skipLeaveInstruction);
            if (instructionOrigins != null)
            {
                instructionOrigins.Insert(branchIndex + 1, sourceInstruction);
                instructionOrigins.Insert(branchIndex + 2, sourceInstruction);
            }
        }

        private void NormalizeDispatcherBranches(CilMethodBody body)
        {
            if (body?.Instructions == null || body.Instructions.Count < 3)
                return;
            for (var i = 0; i < body.Instructions.Count; i++)
            {
                var instruction = body.Instructions[i];
                if (instruction.OpCode != CilOpCodes.Br || !(instruction.Operand is CilInstructionLabel label))
                    continue;

                if (!TryResolveDispatcherBranchTarget(
                        body,
                        label.Instruction,
                        out var switchInstruction,
                        out var switchTargets,
                        out var selectorInstruction,
                        out var targetsSelector))
                {
                    continue;
                }

                if (!targetsSelector)
                {
                    if (TryGetDispatcherStateFromStack(body, i - 1, out var state) &&
                        TryGetSwitchTarget(switchTargets, state, out var target))
                    {
                        instruction.Operand = new CilInstructionLabel(target);
                        NopInstruction(body.Instructions[GetPreviousMeaningfulInstructionIndex(body, i - 1)]);
                    }

                    continue;
                }

                if (!TryGetStoredDispatcherState(body, i - 1, selectorInstruction, out var stateFromStore))
                    continue;
                if (!TryGetSwitchTarget(switchTargets, stateFromStore, out var storedTarget))
                    continue;
                instruction.Operand = new CilInstructionLabel(storedTarget);
            }
        }

        private bool TryResolveDispatcherBranchTarget(
            CilMethodBody body,
            CilInstruction branchTarget,
            out CilInstruction switchInstruction,
            out IList<ICilLabel> switchTargets,
            out CilInstruction selectorInstruction,
            out bool targetsSelector)
        {
            switchInstruction = null;
            switchTargets = null;
            selectorInstruction = null;
            targetsSelector = false;
            if (body?.Instructions == null || branchTarget == null)
                return false;

            if (branchTarget.OpCode == CilOpCodes.Switch &&
                branchTarget.Operand is IList<ICilLabel> directTargets &&
                directTargets.Count >= 16)
            {
                var switchIndex = FindInstructionIndexByReference(body.Instructions, branchTarget);
                if (switchIndex < 1)
                    return false;

                var previousIndex = GetPreviousMeaningfulInstructionIndex(body, switchIndex - 1);
                if (previousIndex < 0)
                    return false;

                var previous = body.Instructions[previousIndex];
                if (!IsDispatcherSelectorLoad(previous))
                    return false;

                switchInstruction = branchTarget;
                switchTargets = directTargets;
                selectorInstruction = previous;
                return true;
            }

            if (!IsDispatcherSelectorLoad(branchTarget))
                return false;

            var targetIndex = FindInstructionIndexByReference(body.Instructions, branchTarget);
            if (targetIndex < 0)
                return false;

            var nextIndex = GetNextMeaningfulInstructionIndex(body, targetIndex + 1);
            if (nextIndex < 0)
                return false;

            var nextInstruction = body.Instructions[nextIndex];
            if (nextInstruction.OpCode != CilOpCodes.Switch ||
                !(nextInstruction.Operand is IList<ICilLabel> indirectTargets) ||
                indirectTargets.Count < 16)
            {
                return false;
            }

            switchInstruction = nextInstruction;
            switchTargets = indirectTargets;
            selectorInstruction = branchTarget;
            targetsSelector = true;
            return true;
        }

        private bool TryFindDispatcherSwitch(
            CilMethodBody body,
            out int switchIndex,
            out CilInstruction switchInstruction,
            out CilInstruction selectorInstruction)
        {
            switchIndex = -1;
            switchInstruction = null;
            selectorInstruction = null;

            for (var i = 1; i < body.Instructions.Count; i++)
            {
                var candidate = body.Instructions[i];
                if (candidate.OpCode != CilOpCodes.Switch ||
                    !(candidate.Operand is IList<ICilLabel> labels) ||
                    labels.Count < 16)
                    continue;

                var previousIndex = GetPreviousMeaningfulInstructionIndex(body, i - 1);
                if (previousIndex < 0)
                    continue;

                var previous = body.Instructions[previousIndex];
                if (!IsDispatcherSelectorLoad(previous))
                    continue;

                switchIndex = i;
                switchInstruction = candidate;
                selectorInstruction = previous;
                return true;
            }

            return false;
        }

        private int GetPreviousMeaningfulInstructionIndex(CilMethodBody body, int startIndex)
        {
            for (var i = startIndex; i >= 0; i--)
            {
                if (body.Instructions[i].OpCode != CilOpCodes.Nop)
                    return i;
            }

            return -1;
        }

        private int GetNextMeaningfulInstructionIndex(CilMethodBody body, int startIndex)
        {
            for (var i = startIndex; i < body.Instructions.Count; i++)
            {
                if (body.Instructions[i].OpCode != CilOpCodes.Nop)
                    return i;
            }

            return -1;
        }

        private bool TryGetDispatcherStateFromStack(CilMethodBody body, int startIndex, out int state)
        {
            state = 0;
            var valueIndex = GetPreviousMeaningfulInstructionIndex(body, startIndex);
            if (valueIndex < 0)
                return false;

            return TryGetInt32Constant(body.Instructions[valueIndex], out state);
        }

        private bool TryGetStoredDispatcherState(
            CilMethodBody body,
            int startIndex,
            CilInstruction selectorInstruction,
            out int state)
        {
            state = 0;
            var storeIndex = GetPreviousMeaningfulInstructionIndex(body, startIndex);
            if (storeIndex < 1)
                return false;

            var storeInstruction = body.Instructions[storeIndex];
            if (!IsMatchingDispatcherStore(selectorInstruction, storeInstruction))
                return false;

            var valueIndex = GetPreviousMeaningfulInstructionIndex(body, storeIndex - 1);
            if (valueIndex < 0)
                return false;

            return TryGetInt32Constant(body.Instructions[valueIndex], out state);
        }

        private bool IsDispatcherSelectorLoad(CilInstruction instruction)
        {
            if (instruction == null)
                return false;

            return instruction.OpCode == CilOpCodes.Ldloc ||
                   instruction.OpCode == CilOpCodes.Ldloc_0 ||
                   instruction.OpCode == CilOpCodes.Ldloc_1 ||
                   instruction.OpCode == CilOpCodes.Ldloc_2 ||
                   instruction.OpCode == CilOpCodes.Ldloc_3 ||
                   instruction.OpCode == CilOpCodes.Ldarg ||
                   instruction.OpCode == CilOpCodes.Ldarg_0 ||
                   instruction.OpCode == CilOpCodes.Ldarg_1 ||
                   instruction.OpCode == CilOpCodes.Ldarg_2 ||
                   instruction.OpCode == CilOpCodes.Ldarg_3;
        }

        private bool IsMatchingDispatcherStore(CilInstruction selectorInstruction, CilInstruction storeInstruction)
        {
            if (selectorInstruction == null || storeInstruction == null)
                return false;

            if (selectorInstruction.OpCode == CilOpCodes.Ldloc ||
                selectorInstruction.OpCode == CilOpCodes.Ldloc_0 ||
                selectorInstruction.OpCode == CilOpCodes.Ldloc_1 ||
                selectorInstruction.OpCode == CilOpCodes.Ldloc_2 ||
                selectorInstruction.OpCode == CilOpCodes.Ldloc_3)
            {
                if (!(storeInstruction.OpCode == CilOpCodes.Stloc ||
                      storeInstruction.OpCode == CilOpCodes.Stloc_0 ||
                      storeInstruction.OpCode == CilOpCodes.Stloc_1 ||
                      storeInstruction.OpCode == CilOpCodes.Stloc_2 ||
                      storeInstruction.OpCode == CilOpCodes.Stloc_3))
                    return false;

                return GetVariableIndex(selectorInstruction) == GetVariableIndex(storeInstruction);
            }

            if (selectorInstruction.OpCode == CilOpCodes.Ldarg ||
                selectorInstruction.OpCode == CilOpCodes.Ldarg_0 ||
                selectorInstruction.OpCode == CilOpCodes.Ldarg_1 ||
                selectorInstruction.OpCode == CilOpCodes.Ldarg_2 ||
                selectorInstruction.OpCode == CilOpCodes.Ldarg_3)
            {
                if (storeInstruction.OpCode != CilOpCodes.Starg)
                    return false;

                return GetVariableIndex(selectorInstruction) == GetVariableIndex(storeInstruction);
            }

            return false;
        }

        private int GetVariableIndex(CilInstruction instruction)
        {
            if (instruction == null)
                return -1;

            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldloc_0:
                case CilCode.Stloc_0:
                    return 0;
                case CilCode.Ldloc_1:
                case CilCode.Stloc_1:
                    return 1;
                case CilCode.Ldloc_2:
                case CilCode.Stloc_2:
                    return 2;
                case CilCode.Ldloc_3:
                case CilCode.Stloc_3:
                    return 3;
                case CilCode.Ldarg_0:
                    return 0;
                case CilCode.Ldarg_1:
                    return 1;
                case CilCode.Ldarg_2:
                    return 2;
                case CilCode.Ldarg_3:
                    return 3;
                case CilCode.Ldloc:
                case CilCode.Stloc:
                    return bodyIndexFromOperand(instruction.Operand);
                case CilCode.Ldarg:
                case CilCode.Starg:
                    return bodyIndexFromOperand(instruction.Operand);
                default:
                    return -1;
            }
        }

        private int bodyIndexFromOperand(object operand)
        {
            if (operand is CilLocalVariable local)
                return local.Index;
            if (operand is AsmResolver.DotNet.Collections.Parameter parameter)
                return parameter.Sequence;
            if (operand is int index)
                return index;
            return -1;
        }

        private bool TryGetSwitchTarget(IList<ICilLabel> switchTargets, int state, out CilInstruction target)
        {
            target = null;
            if (state < 0 || state >= switchTargets.Count)
                return false;
            if (!(switchTargets[state] is CilInstructionLabel label) || label.Instruction == null)
                return false;

            target = label.Instruction;
            return true;
        }

        private bool TryGetInt32Constant(CilInstruction instruction, out int value)
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
                    value = Convert.ToInt32(instruction.Operand);
                    return true;
                default:
                    return false;
            }
        }

        private void NopInstruction(CilInstruction instruction)
        {
            if (instruction == null)
                return;

            instruction.OpCode = CilOpCodes.Nop;
            instruction.Operand = null;
        }

        private void LiftDispatcherBranches(CilMethodBody body, IList<VMInstruction> instructionOrigins)
        {
            if (body?.Instructions == null || body.Instructions.Count < 3)
                return;

            if (!TryResolveDispatcherDescriptor(body, out var dispatcher))
                return;

            var rewrites = new Dictionary<CilInstruction, DispatcherRewritePlan>(
                AnalyzeDispatcherBranchRewrites(body, dispatcher),
                ReferenceEqualityComparer.Instance);
            AugmentConditionalSwitchFallbackRewrites(body, dispatcher, rewrites);
            ApplyDispatcherBranchRewrites(body, instructionOrigins, rewrites);
            RewriteRemainingSimpleConditionalDispatcherBranches(body, instructionOrigins, dispatcher);
            NormalizeDispatcherBranches(body);
        }

        private bool TryResolveDispatcherDescriptor(CilMethodBody body, out DispatcherDescriptor dispatcher)
        {
            dispatcher = null;
            if (!TryFindDispatcherSwitch(body, out _, out var switchInstruction, out var selectorInstruction))
                return false;
            if (!(switchInstruction.Operand is IList<ICilLabel> switchTargets) || switchTargets.Count == 0)
                return false;

            var selectorVariableIndex = GetVariableIndex(selectorInstruction);
            if (selectorVariableIndex < 0)
                return false;

            dispatcher = new DispatcherDescriptor(
                switchInstruction,
                selectorInstruction,
                switchTargets,
                selectorVariableIndex);
            return true;
        }

        private IReadOnlyDictionary<CilInstruction, DispatcherRewritePlan> AnalyzeDispatcherBranchRewrites(
            CilMethodBody body,
            DispatcherDescriptor dispatcher)
        {
            var instructions = body.Instructions;
            var instructionIndexByInstruction = new Dictionary<CilInstruction, int>(
                instructions.Count,
                ReferenceEqualityComparer.Instance);
            for (var i = 0; i < instructions.Count; i++)
                instructionIndexByInstruction[instructions[i]] = i;

            var seenStates = new Dictionary<int, HashSet<string>>();
            var pending = new Queue<DispatcherAnalysisState>();
            var rewrites = new Dictionary<CilInstruction, DispatcherRewritePlan>(
                ReferenceEqualityComparer.Instance);
            pending.Enqueue(new DispatcherAnalysisState(
                0,
                DispatcherAbstractValue.Unknown,
                Array.Empty<DispatcherAbstractValue>()));

            while (pending.Count > 0)
            {
                var state = pending.Dequeue();
                if (state.InstructionIndex < 0 || state.InstructionIndex >= instructions.Count)
                    continue;
                if (!RegisterDispatcherAnalysisState(seenStates, state))
                    continue;

                var instruction = instructions[state.InstructionIndex];
                if (ReferenceEquals(instruction, dispatcher.SwitchInstruction))
                {
                    if (TryResolveDispatcherTargetFromStack(state.Stack, dispatcher, out var targetInstruction, out var remainingStack) &&
                        instructionIndexByInstruction.TryGetValue(targetInstruction, out var targetIndex))
                    {
                        pending.Enqueue(new DispatcherAnalysisState(targetIndex, state.SelectorValue, remainingStack));
                    }

                    continue;
                }

                if (instruction.OpCode == CilOpCodes.Br &&
                    instruction.Operand is CilInstructionLabel unconditionalLabel)
                {
                    if (TryBuildDispatcherRewriteOutcome(
                            dispatcher,
                            unconditionalLabel.Instruction,
                            state.Stack,
                            state.SelectorValue,
                            out var outcome) &&
                        instructionIndexByInstruction.TryGetValue(outcome.TargetInstruction, out var targetIndex))
                    {
                        RegisterDispatcherRewrite(rewrites, instruction, outcome);
                        pending.Enqueue(new DispatcherAnalysisState(targetIndex, state.SelectorValue, outcome.ResultingStack));
                        continue;
                    }

                    if (unconditionalLabel.Instruction != null &&
                        instructionIndexByInstruction.TryGetValue(unconditionalLabel.Instruction, out var branchTarget))
                    {
                        pending.Enqueue(new DispatcherAnalysisState(branchTarget, state.SelectorValue, state.Stack));
                    }

                    continue;
                }

                if (IsConditionalDispatcherBranchOpCode(instruction.OpCode) &&
                    instruction.Operand is CilInstructionLabel conditionalLabel &&
                    TryPopConditionalBranchOperands(state.Stack, instruction.OpCode, out var stackAfterCondition))
                {
                    if (TryBuildDispatcherRewriteOutcome(
                            dispatcher,
                            conditionalLabel.Instruction,
                            stackAfterCondition,
                            state.SelectorValue,
                            out var outcome) &&
                        instructionIndexByInstruction.TryGetValue(outcome.TargetInstruction, out var targetIndex))
                    {
                        RegisterDispatcherRewrite(rewrites, instruction, outcome);
                        pending.Enqueue(new DispatcherAnalysisState(targetIndex, state.SelectorValue, outcome.ResultingStack));
                    }
                    else if (conditionalLabel.Instruction != null &&
                             instructionIndexByInstruction.TryGetValue(conditionalLabel.Instruction, out var conditionalTarget))
                    {
                        pending.Enqueue(new DispatcherAnalysisState(conditionalTarget, state.SelectorValue, stackAfterCondition));
                    }

                    var nextIndex = state.InstructionIndex + 1;
                    if (nextIndex < instructions.Count)
                        pending.Enqueue(new DispatcherAnalysisState(nextIndex, state.SelectorValue, stackAfterCondition));
                    continue;
                }

                if (!TryApplyAbstractInstructionEffect(
                        instruction,
                        dispatcher,
                        state.Stack,
                        state.SelectorValue,
                        out var nextStack,
                        out var nextSelector))
                {
                    continue;
                }

                var fallthroughIndex = state.InstructionIndex + 1;
                if (fallthroughIndex < instructions.Count &&
                    instruction.OpCode.Code != CilCode.Ret &&
                    instruction.OpCode.Code != CilCode.Endfinally)
                {
                    pending.Enqueue(new DispatcherAnalysisState(fallthroughIndex, nextSelector, nextStack));
                }
            }

            var filtered = new Dictionary<CilInstruction, DispatcherRewritePlan>(
                ReferenceEqualityComparer.Instance);
            foreach (var pair in rewrites)
            {
                if (!pair.Value.IsConflicted)
                    filtered[pair.Key] = pair.Value;
            }

            return filtered;
        }

        private bool RegisterDispatcherAnalysisState(
            IDictionary<int, HashSet<string>> seenStates,
            DispatcherAnalysisState state)
        {
            if (!seenStates.TryGetValue(state.InstructionIndex, out var seen))
            {
                seen = new HashSet<string>(StringComparer.Ordinal);
                seenStates[state.InstructionIndex] = seen;
            }

            if (seen.Count >= 48)
                return false;

            return seen.Add(state.GetKey());
        }

        private void RegisterDispatcherRewrite(
            IDictionary<CilInstruction, DispatcherRewritePlan> rewrites,
            CilInstruction instruction,
            DispatcherRewriteOutcome outcome)
        {
            if (instruction == null || outcome?.TargetInstruction == null)
                return;

            if (!rewrites.TryGetValue(instruction, out var existing))
            {
                rewrites[instruction] = new DispatcherRewritePlan(
                    outcome.TargetInstruction,
                    outcome.RequiresTakenSelectorPop);
                return;
            }

            if (!ReferenceEquals(existing.TargetInstruction, outcome.TargetInstruction) ||
                existing.RequiresTakenSelectorPop != outcome.RequiresTakenSelectorPop)
            {
                existing.IsConflicted = true;
            }
        }

        private void ApplyDispatcherBranchRewrites(
            CilMethodBody body,
            IList<VMInstruction> instructionOrigins,
            IReadOnlyDictionary<CilInstruction, DispatcherRewritePlan> rewrites)
        {
            if (body?.Instructions == null || rewrites == null || rewrites.Count == 0)
                return;

            var ordered = rewrites
                .Select(pair => new
                {
                    Instruction = pair.Key,
                    Plan = pair.Value,
                    Index = FindInstructionIndexByReference(body.Instructions, pair.Key)
                })
                .Where(pair => pair.Index >= 0)
                .OrderByDescending(pair => pair.Index)
                .ToList();

            foreach (var item in ordered)
            {
                var instruction = item.Instruction;
                var plan = item.Plan;
                var branchIndex = FindInstructionIndexByReference(body.Instructions, instruction);
                if (branchIndex < 0)
                    continue;

                if (instruction.OpCode == CilOpCodes.Br)
                {
                    if (!plan.RequiresTakenSelectorPop)
                    {
                        instruction.Operand = new CilInstructionLabel(plan.TargetInstruction);
                        continue;
                    }

                    var directBranch = new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(plan.TargetInstruction));
                    instruction.OpCode = CilOpCodes.Pop;
                    instruction.Operand = null;
                    body.Instructions.Insert(branchIndex + 1, directBranch);
                    if (instructionOrigins != null)
                        instructionOrigins.Insert(branchIndex + 1, instructionOrigins[Math.Max(0, branchIndex)]);
                    continue;
                }

                if (!IsConditionalDispatcherBranchOpCode(instruction.OpCode))
                    continue;

                if (!plan.RequiresTakenSelectorPop)
                {
                    instruction.Operand = new CilInstructionLabel(plan.TargetInstruction);
                    continue;
                }

                var inverse = GetInverseBranchOpCode(instruction.OpCode);
                if (inverse == null)
                    continue;

                var popSelectorInstruction = new CilInstruction(CilOpCodes.Pop);
                var directBranchInstruction = new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(plan.TargetInstruction));
                var skipTakenInstruction = new CilInstruction(CilOpCodes.Nop);
                instruction.OpCode = inverse.Value;
                instruction.Operand = new CilInstructionLabel(skipTakenInstruction);

                body.Instructions.Insert(branchIndex + 1, popSelectorInstruction);
                body.Instructions.Insert(branchIndex + 2, directBranchInstruction);
                body.Instructions.Insert(branchIndex + 3, skipTakenInstruction);
                if (instructionOrigins != null)
                {
                    var origin = instructionOrigins[Math.Max(0, branchIndex)];
                    instructionOrigins.Insert(branchIndex + 1, origin);
                    instructionOrigins.Insert(branchIndex + 2, origin);
                    instructionOrigins.Insert(branchIndex + 3, origin);
                }
            }
        }

        private void AugmentConditionalSwitchFallbackRewrites(
            CilMethodBody body,
            DispatcherDescriptor dispatcher,
            IDictionary<CilInstruction, DispatcherRewritePlan> rewrites)
        {
            if (body?.Instructions == null || dispatcher == null || rewrites == null)
                return;

            for (var i = 0; i < body.Instructions.Count; i++)
            {
                var instruction = body.Instructions[i];
                if (!IsConditionalDispatcherBranchOpCode(instruction.OpCode))
                    continue;
                if (rewrites.ContainsKey(instruction))
                    continue;
                if (!(instruction.Operand is CilInstructionLabel label) ||
                    !ReferenceEquals(label.Instruction, dispatcher.SwitchInstruction))
                    continue;

                var callIndex = GetPreviousMeaningfulInstructionIndex(body, i - 1);
                if (callIndex <= 0)
                    continue;

                var callInstruction = body.Instructions[callIndex];
                if (callInstruction.OpCode != CilOpCodes.Call &&
                    callInstruction.OpCode != CilOpCodes.Callvirt)
                {
                    continue;
                }

                if (!TryGetAbstractStackUsage(callInstruction, out var popCount, out var pushCount) ||
                    popCount != 0 ||
                    pushCount != 1)
                {
                    continue;
                }

                var selectorIndex = GetPreviousMeaningfulInstructionIndex(body, callIndex - 1);
                if (selectorIndex < 0)
                    continue;
                if (!TryGetInt32Constant(body.Instructions[selectorIndex], out var state))
                    continue;
                if (!TryGetSwitchTarget(dispatcher.SwitchTargets, state, out var targetInstruction))
                    continue;

                rewrites[instruction] = new DispatcherRewritePlan(
                    targetInstruction,
                    requiresTakenSelectorPop: true);
            }
        }

        private void RewriteRemainingSimpleConditionalDispatcherBranches(
            CilMethodBody body,
            IList<VMInstruction> instructionOrigins,
            DispatcherDescriptor dispatcher)
        {
            if (body?.Instructions == null || dispatcher == null)
                return;

            for (var i = body.Instructions.Count - 1; i >= 0; i--)
            {
                var instruction = body.Instructions[i];
                if (instruction.OpCode != CilOpCodes.Brtrue &&
                    instruction.OpCode != CilOpCodes.Brfalse)
                {
                    continue;
                }

                if (!(instruction.Operand is CilInstructionLabel label) ||
                    !ReferenceEquals(label.Instruction, dispatcher.SwitchInstruction))
                {
                    continue;
                }

                var callIndex = GetPreviousMeaningfulInstructionIndex(body, i - 1);
                if (callIndex <= 0)
                    continue;

                var callInstruction = body.Instructions[callIndex];
                if (callInstruction.OpCode != CilOpCodes.Call &&
                    callInstruction.OpCode != CilOpCodes.Callvirt)
                {
                    continue;
                }

                if (!TryGetAbstractStackUsage(callInstruction, out var popCount, out var pushCount) ||
                    popCount != 0 ||
                    pushCount != 1)
                {
                    continue;
                }

                var selectorIndex = GetPreviousMeaningfulInstructionIndex(body, callIndex - 1);
                if (selectorIndex < 0)
                    continue;
                if (!TryGetInt32Constant(body.Instructions[selectorIndex], out var state))
                    continue;
                if (!TryGetSwitchTarget(dispatcher.SwitchTargets, state, out var targetInstruction))
                    continue;

                var inverse = GetInverseBranchOpCode(instruction.OpCode);
                if (inverse == null)
                    continue;

                var popSelectorInstruction = new CilInstruction(CilOpCodes.Pop);
                var directBranchInstruction = new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(targetInstruction));
                var skipTakenInstruction = new CilInstruction(CilOpCodes.Nop);
                instruction.OpCode = inverse.Value;
                instruction.Operand = new CilInstructionLabel(skipTakenInstruction);

                body.Instructions.Insert(i + 1, popSelectorInstruction);
                body.Instructions.Insert(i + 2, directBranchInstruction);
                body.Instructions.Insert(i + 3, skipTakenInstruction);
                if (instructionOrigins != null)
                {
                    var origin = instructionOrigins[Math.Max(0, i)];
                    instructionOrigins.Insert(i + 1, origin);
                    instructionOrigins.Insert(i + 2, origin);
                    instructionOrigins.Insert(i + 3, origin);
                }
            }
        }

        private bool TryBuildDispatcherRewriteOutcome(
            DispatcherDescriptor dispatcher,
            CilInstruction branchTarget,
            IReadOnlyList<DispatcherAbstractValue> stack,
            DispatcherAbstractValue selectorValue,
            out DispatcherRewriteOutcome outcome)
        {
            outcome = null;
            if (dispatcher == null || branchTarget == null)
                return false;

            if (ReferenceEquals(branchTarget, dispatcher.SwitchInstruction))
            {
                if (!TryResolveDispatcherTargetFromStack(stack, dispatcher, out var targetInstruction, out var remainingStack))
                    return false;

                outcome = new DispatcherRewriteOutcome(targetInstruction, remainingStack, requiresTakenSelectorPop: true);
                return true;
            }

            if (!ReferenceEquals(branchTarget, dispatcher.SelectorInstruction))
                return false;
            if (!selectorValue.IsKnownInt)
                return false;
            if (!TryGetSwitchTarget(dispatcher.SwitchTargets, selectorValue.ConstantValue, out var selectorTarget))
                return false;

            outcome = new DispatcherRewriteOutcome(selectorTarget, stack.ToArray(), requiresTakenSelectorPop: false);
            return true;
        }

        private bool TryResolveDispatcherTargetFromStack(
            IReadOnlyList<DispatcherAbstractValue> stack,
            DispatcherDescriptor dispatcher,
            out CilInstruction targetInstruction,
            out DispatcherAbstractValue[] remainingStack)
        {
            targetInstruction = null;
            remainingStack = null;
            if (stack == null || stack.Count == 0)
                return false;

            var selector = stack[stack.Count - 1];
            if (!selector.IsKnownInt)
                return false;
            if (!TryGetSwitchTarget(dispatcher.SwitchTargets, selector.ConstantValue, out targetInstruction))
                return false;

            remainingStack = stack
                .Take(stack.Count - 1)
                .ToArray();
            return true;
        }

        private bool TryPopConditionalBranchOperands(
            IReadOnlyList<DispatcherAbstractValue> stack,
            CilOpCode opCode,
            out DispatcherAbstractValue[] remainingStack)
        {
            remainingStack = null;
            var popCount = opCode == CilOpCodes.Blt_Un || opCode == CilOpCodes.Bge_Un
                ? 2
                : 1;

            if (stack == null || stack.Count < popCount)
                return false;

            remainingStack = stack
                .Take(stack.Count - popCount)
                .ToArray();
            return true;
        }

        private bool TryApplyAbstractInstructionEffect(
            CilInstruction instruction,
            DispatcherDescriptor dispatcher,
            IReadOnlyList<DispatcherAbstractValue> stack,
            DispatcherAbstractValue selectorValue,
            out DispatcherAbstractValue[] nextStack,
            out DispatcherAbstractValue nextSelector)
        {
            nextSelector = selectorValue;
            nextStack = stack?.ToArray() ?? Array.Empty<DispatcherAbstractValue>();
            if (instruction == null)
                return false;
            if (instruction.OpCode == CilOpCodes.Br ||
                instruction.OpCode == CilOpCodes.Brtrue ||
                instruction.OpCode == CilOpCodes.Brfalse ||
                instruction.OpCode == CilOpCodes.Blt_Un ||
                instruction.OpCode == CilOpCodes.Bge_Un ||
                instruction.OpCode == CilOpCodes.Switch)
            {
                return true;
            }

            if (TryGetInt32Constant(instruction, out var constantValue))
            {
                nextStack = AppendDispatcherValue(nextStack, DispatcherAbstractValue.FromConstant(constantValue));
                return true;
            }

            if (IsDispatcherSelectorLoadInstruction(instruction, dispatcher))
            {
                nextStack = AppendDispatcherValue(nextStack, selectorValue);
                return true;
            }

            if (IsDispatcherSelectorStoreInstruction(instruction, dispatcher))
            {
                if (!TryPopDispatcherValue(nextStack, out nextStack, out var storedValue))
                    return false;
                nextSelector = storedValue;
                return true;
            }

            switch (instruction.OpCode.Code)
            {
                case CilCode.Nop:
                    return true;

                case CilCode.Pop:
                    return TryPopDispatcherValue(nextStack, out nextStack, out _);

                case CilCode.Dup:
                    if (nextStack.Length == 0)
                        return false;
                    nextStack = AppendDispatcherValue(nextStack, nextStack[nextStack.Length - 1]);
                    return true;

                case CilCode.Add:
                case CilCode.Sub:
                case CilCode.Xor:
                case CilCode.Shl:
                case CilCode.Shr:
                    return TryApplyBinaryDispatcherOperation(instruction.OpCode.Code, nextStack, out nextStack);

                case CilCode.Neg:
                case CilCode.Not:
                case CilCode.Conv_I4:
                case CilCode.Conv_I8:
                case CilCode.Conv_U1:
                    return TryApplyUnaryDispatcherOperation(instruction.OpCode.Code, nextStack, out nextStack);
            }

            if (!TryGetAbstractStackUsage(instruction, out var popCount, out var pushCount))
                return false;
            if (nextStack.Length < popCount)
                return false;

            nextStack = nextStack
                .Take(nextStack.Length - popCount)
                .ToArray();
            for (var i = 0; i < pushCount; i++)
                nextStack = AppendDispatcherValue(nextStack, DispatcherAbstractValue.Unknown);
            return true;
        }

        private bool TryApplyBinaryDispatcherOperation(
            CilCode opCode,
            IReadOnlyList<DispatcherAbstractValue> stack,
            out DispatcherAbstractValue[] nextStack)
        {
            nextStack = null;
            if (stack == null || stack.Count < 2)
                return false;

            var right = stack[stack.Count - 1];
            var left = stack[stack.Count - 2];
            var prefix = stack
                .Take(stack.Count - 2)
                .ToArray();

            if (left.IsKnownInt && right.IsKnownInt)
            {
                var result = opCode switch
                {
                    CilCode.Add => left.ConstantValue + right.ConstantValue,
                    CilCode.Sub => left.ConstantValue - right.ConstantValue,
                    CilCode.Xor => left.ConstantValue ^ right.ConstantValue,
                    CilCode.Shl => left.ConstantValue << right.ConstantValue,
                    CilCode.Shr => left.ConstantValue >> right.ConstantValue,
                    _ => 0
                };
                nextStack = AppendDispatcherValue(prefix, DispatcherAbstractValue.FromConstant(result));
                return true;
            }

            nextStack = AppendDispatcherValue(prefix, DispatcherAbstractValue.Unknown);
            return true;
        }

        private bool TryApplyUnaryDispatcherOperation(
            CilCode opCode,
            IReadOnlyList<DispatcherAbstractValue> stack,
            out DispatcherAbstractValue[] nextStack)
        {
            nextStack = null;
            if (stack == null || stack.Count == 0)
                return false;

            var value = stack[stack.Count - 1];
            var prefix = stack
                .Take(stack.Count - 1)
                .ToArray();

            if (value.IsKnownInt)
            {
                var result = opCode switch
                {
                    CilCode.Neg => -value.ConstantValue,
                    CilCode.Not => ~value.ConstantValue,
                    CilCode.Conv_U1 => value.ConstantValue & 0xFF,
                    _ => value.ConstantValue
                };
                nextStack = AppendDispatcherValue(prefix, DispatcherAbstractValue.FromConstant(result));
                return true;
            }

            nextStack = AppendDispatcherValue(prefix, DispatcherAbstractValue.Unknown);
            return true;
        }

        private bool TryGetAbstractStackUsage(CilInstruction instruction, out int pop, out int push)
        {
            pop = 0;
            push = 0;
            if (instruction == null)
                return false;

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
                    return true;

                default:
                    return false;
            }
        }

        private bool IsConditionalDispatcherBranchOpCode(CilOpCode opCode)
        {
            return opCode == CilOpCodes.Brtrue ||
                   opCode == CilOpCodes.Brfalse ||
                   opCode == CilOpCodes.Blt_Un ||
                   opCode == CilOpCodes.Bge_Un;
        }

        private bool IsDispatcherSelectorLoadInstruction(CilInstruction instruction, DispatcherDescriptor dispatcher)
        {
            if (instruction == null || dispatcher == null)
                return false;

            return IsDispatcherSelectorLoad(instruction) &&
                   GetVariableIndex(instruction) == dispatcher.SelectorVariableIndex;
        }

        private bool IsDispatcherSelectorStoreInstruction(CilInstruction instruction, DispatcherDescriptor dispatcher)
        {
            if (instruction == null || dispatcher == null)
                return false;

            if (instruction.OpCode == CilOpCodes.Stloc ||
                instruction.OpCode == CilOpCodes.Stloc_0 ||
                instruction.OpCode == CilOpCodes.Stloc_1 ||
                instruction.OpCode == CilOpCodes.Stloc_2 ||
                instruction.OpCode == CilOpCodes.Stloc_3 ||
                instruction.OpCode == CilOpCodes.Starg)
            {
                return GetVariableIndex(instruction) == dispatcher.SelectorVariableIndex;
            }

            return false;
        }

        private DispatcherAbstractValue[] AppendDispatcherValue(
            IReadOnlyList<DispatcherAbstractValue> stack,
            DispatcherAbstractValue value)
        {
            var result = new DispatcherAbstractValue[(stack?.Count ?? 0) + 1];
            if (stack != null)
            {
                for (var i = 0; i < stack.Count; i++)
                    result[i] = stack[i];
            }

            result[result.Length - 1] = value;
            return result;
        }

        private bool TryPopDispatcherValue(
            IReadOnlyList<DispatcherAbstractValue> stack,
            out DispatcherAbstractValue[] remainingStack,
            out DispatcherAbstractValue value)
        {
            remainingStack = null;
            value = DispatcherAbstractValue.Unknown;
            if (stack == null || stack.Count == 0)
                return false;

            value = stack[stack.Count - 1];
            remainingStack = stack
                .Take(stack.Count - 1)
                .ToArray();
            return true;
        }

        private void SanitizeUnreachableInvalidInstructions(CilMethodBody body)
        {
            if (body?.Instructions == null || body.Instructions.Count == 0)
                return;

            var reachable = GetReachableInstructionIndices(body);
            for (var i = 0; i < body.Instructions.Count; i++)
            {
                if (reachable.Contains(i))
                    continue;

                var instruction = body.Instructions[i];
                if (RequiresOperand(instruction.OpCode) && instruction.Operand == null)
                    NopInstruction(instruction);
            }
        }

        private void SpecializeDispatcherBlocksByEntryStackDepth(
            CilMethodBody body,
            IList<VMInstruction> instructionOrigins,
            VMMethod vmMethod)
        {
            var logSpecialization = string.Equals(
                Environment.GetEnvironmentVariable("KRYPTON_LOG_DNLIB_STACK"),
                "1",
                StringComparison.Ordinal);
            if (body?.Instructions == null || body.Instructions.Count == 0)
            {
                if (logSpecialization)
                    Console.WriteLine("[-] stack-specialization: skipped because body is empty.");
                return;
            }
            if (body.ExceptionHandlers.Count > 0)
            {
                if (logSpecialization)
                    Console.WriteLine("[-] stack-specialization: skipped because method has exception handlers.");
                return;
            }
            if (!TryResolveDispatcherDescriptor(body, out _))
            {
                if (logSpecialization)
                    Console.WriteLine("[-] stack-specialization: skipped because dispatcher descriptor was not found.");
                return;
            }
            if (!(instructionOrigins is List<VMInstruction> originsList))
            {
                if (logSpecialization)
                    Console.WriteLine($"[-] stack-specialization: skipped because origins list type is {instructionOrigins?.GetType().FullName ?? "<null>"}.");
                return;
            }

            var analysis = DnlibStyleMaxStackAnalyzer.Analyze(null, vmMethod, new RecompiledMethodArtifact(body, originsList));
            if (analysis.TotalIssues <= 0)
            {
                if (logSpecialization)
                    Console.WriteLine("[*] stack-specialization: skipped because dnlib-style analysis is already clean.");
                return;
            }

            if (!TrySpecializeBlocksByEntryStackDepth(body, originsList, vmMethod))
                return;
        }

        private bool TrySpecializeBlocksByEntryStackDepth(
            CilMethodBody body,
            List<VMInstruction> instructionOrigins,
            VMMethod vmMethod)
        {
            var logSpecialization = string.Equals(
                Environment.GetEnvironmentVariable("KRYPTON_LOG_DNLIB_STACK"),
                "1",
                StringComparison.Ordinal);
            bool Fail(string reason)
            {
                if (logSpecialization)
                    Console.WriteLine($"[-] stack-specialization: {reason}");
                return false;
            }

            var blocks = BuildStackDepthBlocks(body);
            if (blocks.Count == 0)
                return Fail("no basic blocks were built.");

            var variants = new Dictionary<(int blockIndex, int entryDepth), StackDepthVariant>();
            var pending = new Queue<(int blockIndex, int entryDepth)>();
            var emissionOrder = new List<StackDepthVariant>();
            pending.Enqueue((0, 0));

            while (pending.Count > 0)
            {
                var key = pending.Dequeue();
                if (variants.ContainsKey(key))
                    continue;
                if (variants.Count >= 4096)
                    return Fail("variant limit exceeded.");
                if (key.entryDepth < 0 || key.entryDepth > 512)
                    return Fail($"unsupported entry depth {key.entryDepth} for block {key.blockIndex}.");

                var block = blocks[key.blockIndex];
                if (!TryComputeBlockExitDepth(body, block, vmMethod, key.entryDepth, out var exitDepth))
                {
                    return Fail(
                        $"failed to simulate block {block.Index} [{block.StartIndex},{block.EndIndex}] with entry depth {key.entryDepth}; start={body.Instructions[block.StartIndex].OpCode.Code}, end={body.Instructions[block.EndIndex].OpCode.Code}.");
                }

                var variant = new StackDepthVariant(block.Index, key.entryDepth)
                {
                    ExitDepth = exitDepth
                };
                variants[key] = variant;
                emissionOrder.Add(variant);

                foreach (var successorBlock in block.BranchSuccessors)
                {
                    var successorKey = (successorBlock, exitDepth);
                    variant.BranchSuccessors.Add(successorKey);
                    if (!variants.ContainsKey(successorKey))
                        pending.Enqueue(successorKey);
                }

                if (block.FallthroughSuccessor.HasValue)
                {
                    var fallthroughKey = (block.FallthroughSuccessor.Value, exitDepth);
                    variant.FallthroughSuccessor = fallthroughKey;
                    if (!variants.ContainsKey(fallthroughKey))
                        pending.Enqueue(fallthroughKey);
                }
            }

            if (emissionOrder.Count == 0)
                return Fail("no block variants were discovered.");

            var emittedInstructions = new List<CilInstruction>();
            var emittedOrigins = new List<VMInstruction>();
            foreach (var variant in emissionOrder)
            {
                var block = blocks[variant.BlockIndex];
                variant.StartInstruction = null;
                for (var i = block.StartIndex; i <= block.EndIndex; i++)
                {
                    var clone = CloneInstruction(body.Instructions[i]);
                    if (variant.StartInstruction == null)
                        variant.StartInstruction = clone;
                    variant.ClonedInstructions.Add(clone);
                    emittedInstructions.Add(clone);
                    emittedOrigins.Add(i < instructionOrigins.Count ? instructionOrigins[i] : null);
                }

                if (block.FlowKind == StackDepthBlockFlowKind.FallThroughOnly ||
                    block.FlowKind == StackDepthBlockFlowKind.ConditionalBranch ||
                    block.FlowKind == StackDepthBlockFlowKind.Switch)
                {
                    var fallthroughBranch = new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(body.Instructions[block.StartIndex]));
                    variant.FallthroughBranchInstruction = fallthroughBranch;
                    emittedInstructions.Add(fallthroughBranch);
                    emittedOrigins.Add(block.EndIndex < instructionOrigins.Count ? instructionOrigins[block.EndIndex] : null);
                }
            }

            foreach (var variant in emissionOrder)
            {
                if (variant.StartInstruction == null)
                    return Fail($"variant {variant.BlockIndex}@{variant.EntryDepth} has no start instruction.");

                var block = blocks[variant.BlockIndex];
                var terminator = variant.ClonedInstructions[variant.ClonedInstructions.Count - 1];
                switch (block.FlowKind)
                {
                    case StackDepthBlockFlowKind.UnconditionalBranch:
                    {
                        if (variant.BranchSuccessors.Count != 1 ||
                            !variants.TryGetValue(variant.BranchSuccessors[0], out var successor) ||
                            successor.StartInstruction == null)
                        {
                            return Fail($"failed to resolve unconditional successor for {variant.BlockIndex}@{variant.EntryDepth}.");
                        }

                        terminator.Operand = new CilInstructionLabel(successor.StartInstruction);
                        break;
                    }
                    case StackDepthBlockFlowKind.ConditionalBranch:
                    {
                        if (variant.BranchSuccessors.Count != 1 ||
                            !variants.TryGetValue(variant.BranchSuccessors[0], out var branchSuccessor) ||
                            branchSuccessor.StartInstruction == null ||
                            !variant.FallthroughSuccessor.HasValue ||
                            !variants.TryGetValue(variant.FallthroughSuccessor.Value, out var fallthroughSuccessor) ||
                            fallthroughSuccessor.StartInstruction == null ||
                            variant.FallthroughBranchInstruction == null)
                        {
                            return Fail($"failed to resolve conditional successors for {variant.BlockIndex}@{variant.EntryDepth}.");
                        }

                        terminator.Operand = new CilInstructionLabel(branchSuccessor.StartInstruction);
                        variant.FallthroughBranchInstruction.Operand =
                            new CilInstructionLabel(fallthroughSuccessor.StartInstruction);
                        break;
                    }
                    case StackDepthBlockFlowKind.Switch:
                    {
                        var labels = new List<ICilLabel>(variant.BranchSuccessors.Count);
                        foreach (var successorKey in variant.BranchSuccessors)
                        {
                            if (!variants.TryGetValue(successorKey, out var switchSuccessor) ||
                                switchSuccessor.StartInstruction == null)
                            {
                                return Fail($"failed to resolve switch successor for {variant.BlockIndex}@{variant.EntryDepth}.");
                            }

                            labels.Add(new CilInstructionLabel(switchSuccessor.StartInstruction));
                        }

                        terminator.Operand = labels;
                        if (!variant.FallthroughSuccessor.HasValue ||
                            !variants.TryGetValue(variant.FallthroughSuccessor.Value, out var switchFallthrough) ||
                            switchFallthrough.StartInstruction == null ||
                            variant.FallthroughBranchInstruction == null)
                        {
                            return Fail($"failed to resolve switch fallthrough for {variant.BlockIndex}@{variant.EntryDepth}.");
                        }

                        variant.FallthroughBranchInstruction.Operand =
                            new CilInstructionLabel(switchFallthrough.StartInstruction);
                        break;
                    }
                    case StackDepthBlockFlowKind.FallThroughOnly:
                    {
                        if (!variant.FallthroughSuccessor.HasValue ||
                            !variants.TryGetValue(variant.FallthroughSuccessor.Value, out var nextSuccessor) ||
                            nextSuccessor.StartInstruction == null ||
                            variant.FallthroughBranchInstruction == null)
                        {
                            return Fail($"failed to resolve fallthrough successor for {variant.BlockIndex}@{variant.EntryDepth}.");
                        }

                        variant.FallthroughBranchInstruction.Operand =
                            new CilInstructionLabel(nextSuccessor.StartInstruction);
                        break;
                    }
                }
            }

            body.Instructions.Clear();
            foreach (var instruction in emittedInstructions)
                body.Instructions.Add(instruction);

            instructionOrigins.Clear();
            foreach (var origin in emittedOrigins)
                instructionOrigins.Add(origin);

            if (logSpecialization)
                Console.WriteLine($"[*] stack-specialization: rebuilt {emissionOrder.Count} variants into {emittedInstructions.Count} instructions.");

            return true;
        }

        private List<StackDepthBlock> BuildStackDepthBlocks(CilMethodBody body)
        {
            var leaders = new HashSet<int> { 0 };
            var instructionIndexByInstruction = new Dictionary<CilInstruction, int>(
                body.Instructions.Count,
                ReferenceEqualityComparer.Instance);
            for (var i = 0; i < body.Instructions.Count; i++)
                instructionIndexByInstruction[body.Instructions[i]] = i;

            for (var i = 0; i < body.Instructions.Count; i++)
            {
                var instruction = body.Instructions[i];
                switch (instruction.OpCode.Code)
                {
                    case CilCode.Br:
                    case CilCode.Leave:
                        AddLeader(leaders, instruction.Operand, instructionIndexByInstruction);
                        break;

                    case CilCode.Brtrue:
                    case CilCode.Brfalse:
                    case CilCode.Blt_Un:
                    case CilCode.Bge_Un:
                        AddLeader(leaders, instruction.Operand, instructionIndexByInstruction);
                        if (i + 1 < body.Instructions.Count)
                            leaders.Add(i + 1);
                        break;

                    case CilCode.Switch:
                        if (instruction.Operand is IList<ICilLabel> labels)
                        {
                            foreach (var label in labels)
                                AddLeader(leaders, label, instructionIndexByInstruction);
                        }
                        if (i + 1 < body.Instructions.Count)
                            leaders.Add(i + 1);
                        break;
                }
            }

            var orderedLeaders = leaders.OrderBy(index => index).ToList();
            var blockIndexByStart = new Dictionary<int, int>(orderedLeaders.Count);
            var blocks = new List<StackDepthBlock>(orderedLeaders.Count);
            for (var i = 0; i < orderedLeaders.Count; i++)
            {
                var start = orderedLeaders[i];
                var end = i + 1 < orderedLeaders.Count
                    ? orderedLeaders[i + 1] - 1
                    : body.Instructions.Count - 1;
                var block = new StackDepthBlock(i, start, end);
                blockIndexByStart[start] = i;
                blocks.Add(block);
            }

            foreach (var block in blocks)
            {
                var terminator = body.Instructions[block.EndIndex];
                switch (terminator.OpCode.Code)
                {
                    case CilCode.Br:
                    case CilCode.Leave:
                        if (TryGetTargetBlock(terminator.Operand, instructionIndexByInstruction, blockIndexByStart, out var branchTarget))
                        {
                            block.FlowKind = StackDepthBlockFlowKind.UnconditionalBranch;
                            block.BranchSuccessors.Add(branchTarget);
                        }
                        break;

                    case CilCode.Brtrue:
                    case CilCode.Brfalse:
                    case CilCode.Blt_Un:
                    case CilCode.Bge_Un:
                        if (TryGetTargetBlock(terminator.Operand, instructionIndexByInstruction, blockIndexByStart, out var conditionalTarget))
                            block.BranchSuccessors.Add(conditionalTarget);
                        if (block.EndIndex + 1 < body.Instructions.Count &&
                            blockIndexByStart.TryGetValue(block.EndIndex + 1, out var conditionalNext))
                        {
                            block.FlowKind = StackDepthBlockFlowKind.ConditionalBranch;
                            block.FallthroughSuccessor = conditionalNext;
                        }
                        break;

                    case CilCode.Switch:
                        block.FlowKind = StackDepthBlockFlowKind.Switch;
                        if (terminator.Operand is IList<ICilLabel> switchTargets)
                        {
                            foreach (var label in switchTargets)
                            {
                                if (TryGetTargetBlock(label, instructionIndexByInstruction, blockIndexByStart, out var switchTarget))
                                    block.BranchSuccessors.Add(switchTarget);
                            }
                        }
                        if (block.EndIndex + 1 < body.Instructions.Count &&
                            blockIndexByStart.TryGetValue(block.EndIndex + 1, out var switchNext))
                        {
                            block.FallthroughSuccessor = switchNext;
                        }
                        break;

                    case CilCode.Ret:
                    case CilCode.Throw:
                    case CilCode.Rethrow:
                    case CilCode.Endfinally:
                    case CilCode.Endfilter:
                        block.FlowKind = StackDepthBlockFlowKind.Terminal;
                        break;

                    default:
                        if (block.EndIndex + 1 < body.Instructions.Count &&
                            blockIndexByStart.TryGetValue(block.EndIndex + 1, out var nextBlock))
                        {
                            block.FlowKind = StackDepthBlockFlowKind.FallThroughOnly;
                            block.FallthroughSuccessor = nextBlock;
                        }
                        else
                        {
                            block.FlowKind = StackDepthBlockFlowKind.Terminal;
                        }
                        break;
                }
            }

            return blocks;
        }

        private bool TryComputeBlockExitDepth(
            CilMethodBody body,
            StackDepthBlock block,
            VMMethod vmMethod,
            int entryDepth,
            out int exitDepth)
        {
            exitDepth = entryDepth;
            for (var i = block.StartIndex; i <= block.EndIndex; i++)
            {
                if (!TryGetEntryDepthSpecializationStackUsage(body.Instructions[i], vmMethod, out var popCount, out var pushCount, out var resetStack))
                    return false;

                if (resetStack)
                {
                    exitDepth = 0;
                    continue;
                }

                exitDepth -= popCount;
                if (exitDepth < 0)
                    return false;
                exitDepth += pushCount;
                if (exitDepth > 512)
                    return false;
            }

            return true;
        }

        private bool TryGetEntryDepthSpecializationStackUsage(
            CilInstruction instruction,
            VMMethod vmMethod,
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

        private void AddLeader(
            ISet<int> leaders,
            object operand,
            IReadOnlyDictionary<CilInstruction, int> instructionIndexByInstruction)
        {
            if (!(operand is CilInstructionLabel label) || label.Instruction == null)
                return;
            if (!instructionIndexByInstruction.TryGetValue(label.Instruction, out var targetIndex))
                return;
            leaders.Add(targetIndex);
        }

        private bool TryGetTargetBlock(
            object operand,
            IReadOnlyDictionary<CilInstruction, int> instructionIndexByInstruction,
            IReadOnlyDictionary<int, int> blockIndexByStart,
            out int targetBlock)
        {
            targetBlock = -1;
            if (!(operand is CilInstructionLabel label) || label.Instruction == null)
                return false;
            if (!instructionIndexByInstruction.TryGetValue(label.Instruction, out var targetInstruction))
                return false;
            return blockIndexByStart.TryGetValue(targetInstruction, out targetBlock);
        }

        private CilInstruction CloneInstruction(CilInstruction instruction)
        {
            return instruction.Operand == null
                ? new CilInstruction(instruction.OpCode)
                : new CilInstruction(instruction.OpCode, instruction.Operand);
        }

        private HashSet<int> GetReachableInstructionIndices(CilMethodBody body)
        {
            var reachable = new HashSet<int>();
            var worklist = new Stack<int>();
            var instructionIndexByInstruction = new Dictionary<CilInstruction, int>(
                body.Instructions.Count,
                ReferenceEqualityComparer.Instance);
            for (var i = 0; i < body.Instructions.Count; i++)
                instructionIndexByInstruction[body.Instructions[i]] = i;

            worklist.Push(0);
            while (worklist.Count > 0)
            {
                var index = worklist.Pop();
                if (index < 0 || index >= body.Instructions.Count || !reachable.Add(index))
                    continue;

                var instruction = body.Instructions[index];
                switch (instruction.OpCode.Code)
                {
                    case CilCode.Br:
                    case CilCode.Leave:
                        PushTargetInstruction(worklist, instruction.Operand, instructionIndexByInstruction);
                        break;

                    case CilCode.Brtrue:
                    case CilCode.Brfalse:
                    case CilCode.Blt_Un:
                    case CilCode.Bge_Un:
                        PushTargetInstruction(worklist, instruction.Operand, instructionIndexByInstruction);
                        worklist.Push(index + 1);
                        break;

                    case CilCode.Switch:
                        if (instruction.Operand is IList<ICilLabel> labels)
                        {
                            foreach (var label in labels)
                                PushTargetInstruction(worklist, label, instructionIndexByInstruction);
                        }

                        worklist.Push(index + 1);
                        break;

                    case CilCode.Ret:
                    case CilCode.Endfinally:
                        break;

                    default:
                        worklist.Push(index + 1);
                        break;
                }
            }

            return reachable;
        }

        private void PushTargetInstruction(
            Stack<int> worklist,
            object operand,
            IReadOnlyDictionary<CilInstruction, int> instructionIndexByInstruction)
        {
            if (!(operand is CilInstructionLabel label) || label.Instruction == null)
                return;
            if (!instructionIndexByInstruction.TryGetValue(label.Instruction, out var targetIndex))
                return;

            worklist.Push(targetIndex);
        }

        private int FindInstructionIndexByReference(IList<CilInstruction> instructions, CilInstruction target)
        {
            if (instructions == null || target == null)
                return -1;

            for (var i = 0; i < instructions.Count; i++)
            {
                if (ReferenceEquals(instructions[i], target))
                    return i;
            }

            return -1;
        }

        private bool RequiresOperand(CilOpCode opCode)
        {
            return opCode.Code != CilCode.Nop &&
                   opCode.OperandType != CilOperandType.InlineNone;
        }

        private CilOpCode? GetInverseBranchOpCode(CilOpCode opCode)
        {
            if (opCode == CilOpCodes.Brtrue)
                return CilOpCodes.Brfalse;
            if (opCode == CilOpCodes.Brfalse)
                return CilOpCodes.Brtrue;
            if (opCode == CilOpCodes.Blt_Un)
                return CilOpCodes.Bge_Un;
            return null;
        }

        private bool ShouldUseLeave(VMMethod vmMethod, int sourceOffset, int targetOffset)
        {
            foreach (var eh in vmMethod.MethodBody.ExceptionHandlers)
            {
                var sourceInTry = IsInsideRange(sourceOffset, eh.TryStart, eh.TryEnd);
                if (sourceInTry && !IsInsideRange(targetOffset, eh.TryStart, eh.TryEnd))
                    return true;

                var sourceInHandler = IsInsideRange(sourceOffset, eh.HandlerStart, eh.HandlerEnd);
                if (sourceInHandler && !IsInsideRange(targetOffset, eh.HandlerStart, eh.HandlerEnd))
                    return true;
            }

            return false;
        }

        private bool IsInsideRange(int offset, int start, int endInclusive)
        {
            return offset >= start && offset <= endInclusive;
        }

        private void ApplyExceptionHandlers(
            VMMethod vmMethod,
            CilMethodBody body,
            IList<CilInstruction> translatedInstructionMap)
        {
            foreach (var vmEh in vmMethod.MethodBody.ExceptionHandlers)
            {
                var cilEh = new CilExceptionHandler
                {
                    HandlerType = MapExceptionHandlerType(vmEh.EHType),
                    TryStart = GetInstructionAt(translatedInstructionMap, vmEh.TryStart, "try start"),
                    TryEnd = GetInstructionBoundary(translatedInstructionMap, vmEh.TryEnd + 1),
                    HandlerStart = GetInstructionAt(translatedInstructionMap, vmEh.HandlerStart, "handler start"),
                    HandlerEnd = GetInstructionBoundary(translatedInstructionMap, vmEh.HandlerEnd + 1)
                };

                switch (vmEh.EHType)
                {
                    case VMExceptionHandlerType.Catch:
                        cilEh.ExceptionType = ResolveExceptionType(vmEh.CatchType);
                        break;
                    case VMExceptionHandlerType.Filter:
                        cilEh.FilterStart = GetInstructionAt(translatedInstructionMap, vmEh.Filter, "filter start");
                        break;
                }

                body.ExceptionHandlers.Add(cilEh);
            }
        }

        private CilExceptionHandlerType MapExceptionHandlerType(VMExceptionHandlerType type)
        {
            return type switch
            {
                VMExceptionHandlerType.Catch => CilExceptionHandlerType.Exception,
                VMExceptionHandlerType.Filter => CilExceptionHandlerType.Filter,
                VMExceptionHandlerType.Finally => CilExceptionHandlerType.Finally,
                VMExceptionHandlerType.Fault => CilExceptionHandlerType.Fault,
                _ => throw new DevirtualizationException($"Unsupported exception handler type: {type}.")
            };
        }

        private ITypeDefOrRef ResolveExceptionType(ITypeDescriptor descriptor)
        {
            if (descriptor is ITypeDefOrRef typeDefOrRef)
                return typeDefOrRef;
            if (descriptor is TypeDefOrRefSignature typeDefOrRefSignature)
                return typeDefOrRefSignature.Type;

            throw new DevirtualizationException("Unsupported catch type descriptor.");
        }

        private ICilLabel GetInstructionAt(IList<CilInstruction> translatedInstructionMap, int index, string markerName)
        {
            if (index < 0 || index >= translatedInstructionMap.Count)
                throw new DevirtualizationException($"Invalid {markerName} index {index}.");

            return new CilInstructionLabel(translatedInstructionMap[index]);
        }

        private ICilLabel GetInstructionBoundary(IList<CilInstruction> translatedInstructionMap, int index)
        {
            if (index < 0 || index > translatedInstructionMap.Count)
                throw new DevirtualizationException($"Invalid exception boundary index {index}.");

            return index == translatedInstructionMap.Count
                ? null
                : new CilInstructionLabel(translatedInstructionMap[index]);
        }

        private CilInstruction BuildLdargInstruction(
            VMMethod vmMethod,
            IList<CilLocalVariable> locals,
            object operand)
        {
            var vmIndex = Convert.ToInt32(operand);
            var argumentSlotCount = GetArgumentSlotCount(vmMethod?.Parent);
            if (vmIndex >= argumentSlotCount)
            {
                if (vmIndex < 0 || vmIndex >= locals.Count)
                    throw new DevirtualizationException($"Invalid ldarg/ldloc index {vmIndex}.");

                return BuildLdlocInstruction(locals, vmIndex);
            }

            var index = vmIndex;
            switch (index)
            {
                case 0:
                    return new CilInstruction(CilOpCodes.Ldarg_0);
                case 1:
                    return new CilInstruction(CilOpCodes.Ldarg_1);
                case 2:
                    return new CilInstruction(CilOpCodes.Ldarg_2);
                case 3:
                    return new CilInstruction(CilOpCodes.Ldarg_3);
                default:
                    return new CilInstruction(CilOpCodes.Ldarg, index);
            }
        }

        private int GetArgumentSlotCount(AsmResolver.DotNet.MethodDefinition method)
        {
            if (method?.Signature == null)
                return 0;

            var count = method.Signature.ParameterTypes.Count;
            if (!method.IsStatic)
                count++;
            return count;
        }

        private CilInstruction BuildLdlocInstruction(IList<CilLocalVariable> locals, object operand)
        {
            var index = Convert.ToInt32(operand);
            if (index < 0 || index >= locals.Count)
                throw new DevirtualizationException($"Invalid ldloc index {index}.");

            switch (index)
            {
                case 0:
                    return new CilInstruction(CilOpCodes.Ldloc_0);
                case 1:
                    return new CilInstruction(CilOpCodes.Ldloc_1);
                case 2:
                    return new CilInstruction(CilOpCodes.Ldloc_2);
                case 3:
                    return new CilInstruction(CilOpCodes.Ldloc_3);
                default:
                    return new CilInstruction(CilOpCodes.Ldloc, locals[index]);
            }
        }

        private CilInstruction BuildStlocInstruction(IList<CilLocalVariable> locals, object operand)
        {
            var index = Convert.ToInt32(operand);
            if (index < 0 || index >= locals.Count)
                throw new DevirtualizationException($"Invalid stloc index {index}.");

            switch (index)
            {
                case 0:
                    return new CilInstruction(CilOpCodes.Stloc_0);
                case 1:
                    return new CilInstruction(CilOpCodes.Stloc_1);
                case 2:
                    return new CilInstruction(CilOpCodes.Stloc_2);
                case 3:
                    return new CilInstruction(CilOpCodes.Stloc_3);
                default:
                    return new CilInstruction(CilOpCodes.Stloc, locals[index]);
            }
        }

        private CilInstruction BuildCallInstruction(DevirtualizationCtx ctx, object operand, bool forceVirtualCall)
        {
            var descriptor = ResolveMethodDescriptor(ctx, operand);
            if (forceVirtualCall)
                return new CilInstruction(CilOpCodes.Callvirt, descriptor);

            var hasThis = descriptor.Signature?.HasThis == true;
            if (!hasThis && descriptor is AsmResolver.DotNet.MethodSpecification spec)
                hasThis = spec.Method?.Signature?.HasThis == true;

            var opcode = CilOpCodes.Call;
            if (hasThis)
            {
                var resolved = descriptor.Resolve();
                if (resolved == null ||
                    resolved.IsVirtual ||
                    resolved.DeclaringType?.IsInterface == true)
                {
                    opcode = CilOpCodes.Callvirt;
                }
            }

            return new CilInstruction(opcode, descriptor);
        }

        private bool TryBuildCallInstructionOrFallback(
            DevirtualizationCtx ctx,
            VMMethod vmMethod,
            VMInstruction instruction,
            bool forceVirtualCall,
            out CilInstruction translated)
        {
            translated = null;
            try
            {
                translated = BuildCallInstruction(ctx, instruction.Operand, forceVirtualCall);
                return true;
            }
            catch (DevirtualizationException ex) when (TryLowerInvalidCallOperandAsConstant(ctx, vmMethod, instruction, ex, out var fallback))
            {
                translated = fallback;
                return true;
            }
        }

        private bool TryLowerInvalidCallOperandAsConstant(
            DevirtualizationCtx ctx,
            VMMethod vmMethod,
            VMInstruction instruction,
            Exception cause,
            out CilInstruction fallback)
        {
            fallback = null;
            if (!(instruction?.Operand is int token))
                return false;

            if (IsMethodMetadataToken(token) && !IsUnresolvableMetadataTokenException(cause))
                return false;

            fallback = new CilInstruction(CilOpCodes.Ldc_I4, token);
            var parentName = vmMethod?.Parent?.FullName ?? "<unknown>";
            var fallbackKey = $"{parentName}|{instruction.Offset}|{instruction.VmByte:X2}|{token:X8}|{instruction.OpCode}";
            if (_loggedCallFallbacks.Add(fallbackKey))
            {
                ctx.Options.Logger.Warning(
                    $"Call-mapping fallback: lowered vm 0x{instruction.VmByte:X2} ({instruction.OpCode}) " +
                    $"at {parentName} offset {instruction.Offset} from invalid token 0x{token:X8} ({GetMetadataTokenKind(token)}). " +
                    $"Original error: {cause.Message}");
            }
            return true;
        }

        private bool IsUnresolvableMetadataTokenException(Exception exception)
        {
            var message = exception?.Message;
            if (string.IsNullOrWhiteSpace(message))
                return false;

            return message.IndexOf("Cannot resolve metadata token", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool IsMethodMetadataToken(int token)
        {
            var table = (token >> 24) & 0xFF;
            return table == 0x06 || // MethodDef
                   table == 0x0A || // MemberRef
                   table == 0x2B;   // MethodSpec
        }

        private string GetMetadataTokenKind(int token)
        {
            var table = (token >> 24) & 0xFF;
            switch (table)
            {
                case 0x00:
                    return "Nil";
                case 0x01:
                    return "TypeRef";
                case 0x02:
                    return "TypeDef";
                case 0x04:
                    return "Field";
                case 0x06:
                    return "MethodDef";
                case 0x08:
                    return "Param";
                case 0x09:
                    return "InterfaceImpl";
                case 0x0A:
                    return "MemberRef";
                case 0x0B:
                    return "Constant";
                case 0x0C:
                    return "CustomAttribute";
                case 0x0D:
                    return "FieldMarshal";
                case 0x0E:
                    return "DeclSecurity";
                case 0x0F:
                    return "ClassLayout";
                case 0x10:
                    return "FieldLayout";
                case 0x11:
                    return "StandAloneSig";
                case 0x12:
                    return "EventMap";
                case 0x14:
                    return "Event";
                case 0x15:
                    return "PropertyMap";
                case 0x17:
                    return "Property";
                case 0x18:
                    return "MethodSemantics";
                case 0x19:
                    return "MethodImpl";
                case 0x1A:
                    return "ModuleRef";
                case 0x1B:
                    return "TypeSpec";
                case 0x1C:
                    return "ImplMap";
                case 0x1D:
                    return "FieldRva";
                case 0x20:
                    return "Assembly";
                case 0x23:
                    return "AssemblyRef";
                case 0x26:
                    return "File";
                case 0x27:
                    return "ExportedType";
                case 0x28:
                    return "ManifestResource";
                case 0x2A:
                    return "GenericParam";
                case 0x2B:
                    return "MethodSpec";
                case 0x2C:
                    return "GenericParamConstraint";
                case 0x70:
                    return "UserString";
                default:
                    return $"Table0x{table:X2}";
            }
        }

        private IMethodDescriptor ResolveMethodDescriptor(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                throw new DevirtualizationException("Expected method token operand.");

            if (TryResolveMethodDescriptor(ctx, token, out var descriptor))
                return descriptor;

            throw new DevirtualizationException($"Token 0x{token:X8} is not a method descriptor.");
        }

        private bool TryResolveMethodDescriptor(
            DevirtualizationCtx ctx,
            int token,
            out IMethodDescriptor descriptor)
        {
            descriptor = null;

            var member = TryLookupMember(ctx, token);
            if (member is IMethodDescriptor directDescriptor)
            {
                descriptor = directDescriptor;
                return true;
            }

            var table = (token >> 24) & 0xFF;
            var rid = token & 0x00FFFFFF;
            if ((table == 0x0A || table == 0x2B) && rid > 0)
            {
                // Some protected samples leak method-like tokens encoded as member-ref rids
                // even though the target entry lives in MethodDef.
                var methodDefToken = unchecked((int) 0x06000000) | rid;
                var fallbackMember = TryLookupMember(ctx, methodDefToken);
                if (fallbackMember is IMethodDescriptor fallbackDescriptor)
                {
                    descriptor = fallbackDescriptor;
                    return true;
                }
            }

            return false;
        }

        private IMetadataMember TryLookupMember(DevirtualizationCtx ctx, int token)
        {
            try
            {
                return ctx.Module.LookupMember(token);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private IFieldDescriptor ResolveFieldDescriptor(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                throw new DevirtualizationException("Expected field token operand.");

            var member = ctx.Module.LookupMember(token);
            if (member is IFieldDescriptor descriptor)
                return descriptor;

            throw new DevirtualizationException($"Token 0x{token:X8} is not a field descriptor.");
        }

        private ITypeDefOrRef ResolveTypeFromToken(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                throw new DevirtualizationException("Expected type token operand.");

            var member = ctx.Module.LookupMember(token);
            if (member is ITypeDefOrRef type)
                return type;
            if (member is TypeSignature typeSignature && typeSignature is TypeDefOrRefSignature typeDefOrRefSignature)
                return typeDefOrRefSignature.Type;

            throw new DevirtualizationException($"Token 0x{token:X8} is not a type reference.");
        }

        private CilInstruction BuildLdtokenInstruction(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                throw new DevirtualizationException("Expected metadata token operand for ldtoken.");

            var member = TryLookupMember(ctx, token);
            if (member is ITypeDefOrRef type)
                return new CilInstruction(CilOpCodes.Ldtoken, type);
            if (member is IFieldDescriptor field)
                return new CilInstruction(CilOpCodes.Ldtoken, field);
            if (member is IMethodDescriptor method)
                return new CilInstruction(CilOpCodes.Ldtoken, method);

            throw new DevirtualizationException($"Token 0x{token:X8} cannot be resolved as type/field/method for ldtoken.");
        }

        private CilInstruction BuildLdobjInstruction(DevirtualizationCtx ctx, object operand)
        {
            var type = ResolveTypeFromToken(ctx, operand);
            switch (type.FullName)
            {
                case "System.SByte":
                    return new CilInstruction(CilOpCodes.Ldind_I1);
                case "System.Byte":
                case "System.Boolean":
                    return new CilInstruction(CilOpCodes.Ldind_U1);
                case "System.Int16":
                    return new CilInstruction(CilOpCodes.Ldind_I2);
                case "System.UInt16":
                case "System.Char":
                    return new CilInstruction(CilOpCodes.Ldind_U2);
                case "System.Int32":
                    return new CilInstruction(CilOpCodes.Ldind_I4);
                case "System.UInt32":
                    return new CilInstruction(CilOpCodes.Ldind_U4);
                case "System.Int64":
                case "System.UInt64":
                    return new CilInstruction(CilOpCodes.Ldind_I8);
                case "System.Single":
                    return new CilInstruction(CilOpCodes.Ldind_R4);
                case "System.Double":
                    return new CilInstruction(CilOpCodes.Ldind_R8);
                case "System.IntPtr":
                case "System.UIntPtr":
                    return new CilInstruction(CilOpCodes.Ldind_I);
                default:
                    return new CilInstruction(CilOpCodes.Ldobj, type);
            }
        }

        private CilInstruction BuildStobjInstruction(DevirtualizationCtx ctx, object operand)
        {
            var type = ResolveTypeFromToken(ctx, operand);
            switch (type.FullName)
            {
                case "System.SByte":
                case "System.Byte":
                case "System.Boolean":
                    return new CilInstruction(CilOpCodes.Stind_I1);
                case "System.Int16":
                case "System.UInt16":
                case "System.Char":
                    return new CilInstruction(CilOpCodes.Stind_I2);
                case "System.Int32":
                case "System.UInt32":
                    return new CilInstruction(CilOpCodes.Stind_I4);
                case "System.Int64":
                case "System.UInt64":
                    return new CilInstruction(CilOpCodes.Stind_I8);
                case "System.Single":
                    return new CilInstruction(CilOpCodes.Stind_R4);
                case "System.Double":
                    return new CilInstruction(CilOpCodes.Stind_R8);
                case "System.IntPtr":
                case "System.UIntPtr":
                    return new CilInstruction(CilOpCodes.Stind_I);
                default:
                    return new CilInstruction(CilOpCodes.Stobj, type);
            }
        }

        private sealed class DispatcherDescriptor
        {
            public DispatcherDescriptor(
                CilInstruction switchInstruction,
                CilInstruction selectorInstruction,
                IList<ICilLabel> switchTargets,
                int selectorVariableIndex)
            {
                SwitchInstruction = switchInstruction;
                SelectorInstruction = selectorInstruction;
                SwitchTargets = switchTargets;
                SelectorVariableIndex = selectorVariableIndex;
            }

            public CilInstruction SwitchInstruction { get; }
            public CilInstruction SelectorInstruction { get; }
            public IList<ICilLabel> SwitchTargets { get; }
            public int SelectorVariableIndex { get; }
        }

        private sealed class DispatcherRewritePlan
        {
            public DispatcherRewritePlan(CilInstruction targetInstruction, bool requiresTakenSelectorPop)
            {
                TargetInstruction = targetInstruction;
                RequiresTakenSelectorPop = requiresTakenSelectorPop;
            }

            public CilInstruction TargetInstruction { get; }
            public bool RequiresTakenSelectorPop { get; }
            public bool IsConflicted { get; set; }
        }

        private sealed class DispatcherRewriteOutcome
        {
            public DispatcherRewriteOutcome(
                CilInstruction targetInstruction,
                DispatcherAbstractValue[] resultingStack,
                bool requiresTakenSelectorPop)
            {
                TargetInstruction = targetInstruction;
                ResultingStack = resultingStack ?? Array.Empty<DispatcherAbstractValue>();
                RequiresTakenSelectorPop = requiresTakenSelectorPop;
            }

            public CilInstruction TargetInstruction { get; }
            public DispatcherAbstractValue[] ResultingStack { get; }
            public bool RequiresTakenSelectorPop { get; }
        }

        private sealed class DispatcherAnalysisState
        {
            public DispatcherAnalysisState(
                int instructionIndex,
                DispatcherAbstractValue selectorValue,
                DispatcherAbstractValue[] stack)
            {
                InstructionIndex = instructionIndex;
                SelectorValue = selectorValue;
                Stack = stack ?? Array.Empty<DispatcherAbstractValue>();
            }

            public int InstructionIndex { get; }
            public DispatcherAbstractValue SelectorValue { get; }
            public DispatcherAbstractValue[] Stack { get; }

            public string GetKey()
            {
                var stackKey = Stack.Length == 0
                    ? string.Empty
                    : string.Join(",", Stack.Select(value => value.ToKey()));
                return $"{SelectorValue.ToKey()}|{stackKey}";
            }
        }

        private readonly struct DispatcherAbstractValue
        {
            private DispatcherAbstractValue(bool isKnownInt, int constantValue)
            {
                IsKnownInt = isKnownInt;
                ConstantValue = constantValue;
            }

            public static DispatcherAbstractValue Unknown => new DispatcherAbstractValue(false, 0);

            public static DispatcherAbstractValue FromConstant(int value) => new DispatcherAbstractValue(true, value);

            public bool IsKnownInt { get; }
            public int ConstantValue { get; }

            public string ToKey() => IsKnownInt ? $"c{ConstantValue}" : "?";
        }

        private string ResolveUserString(DevirtualizationCtx ctx, int offset)
        {
            if (_userStringCache.TryGetValue(offset, out var cached))
                return cached;

            try
            {
                using var fs = File.OpenRead(ctx.Options.FilePath);
                using var pe = new PEReader(fs);
                var mr = pe.GetMetadataReader();
                var handle = MetadataTokens.UserStringHandle(offset);
                var resolved = mr.GetUserString(handle);
                _userStringCache[offset] = resolved;
                return resolved;
            }
            catch (Exception ex)
            {
                if (IsStrictDiagnostics(ctx))
                    throw new DevirtualizationException($"Failed to resolve user string at #US offset {offset}.", ex);

                ctx.Options.Logger.Warning(
                    $"Failed to resolve user string at #US offset {offset}. Using empty string fallback. Reason: {ex.Message}");
                _userStringCache[offset] = string.Empty;
                return string.Empty;
            }
        }

        private bool IsStrictDiagnostics(DevirtualizationCtx ctx)
        {
            return ctx.Options.StrictDiagnostics;
        }

        private void TryDumpRecompileFailure(DevirtualizationCtx ctx, VMMethod method, Exception ex)
        {
            var outputDir = Environment.GetEnvironmentVariable("KRYPTON_DUMP_RECOMPILE_FAILURES_DIR");
            if (string.IsNullOrWhiteSpace(outputDir))
                return;
            if (method?.Parent == null)
                return;

            try
            {
                Directory.CreateDirectory(outputDir);
                var safeMethodName = SanitizeFileName(method.Parent.FullName);
                var filePath = Path.Combine(outputDir, safeMethodName + "-recompile-failure.txt");

                var sb = new StringBuilder(64 * 1024);
                sb.AppendLine($"Method: {method.Parent.FullName}");
                sb.AppendLine($"Exception: {ex.GetType().FullName}: {ex.Message}");
                sb.AppendLine($"Generated: {DateTime.UtcNow:O}");
                sb.AppendLine();
                sb.AppendLine("VM instructions:");

                var instructions = method.MethodBody?.Instructions;
                if (instructions != null)
                {
                    for (var i = 0; i < instructions.Count; i++)
                    {
                        var instruction = instructions[i];
                        if (instruction == null)
                        {
                            sb.AppendLine($"[{i:D4}] <null>");
                            continue;
                        }

                        sb.AppendLine(
                            $"[{i:D4}] off={instruction.Offset}, vm=0x{instruction.VmByte:X2}, op={instruction.OpCode}, resolved={instruction.IsResolved}, operand={FormatVmOperand(instruction.Operand)}");
                    }
                }

                File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
                ctx?.Options?.Logger?.Info($"Wrote recompile failure dump: {filePath}");
            }
            catch (Exception dumpEx)
            {
                ctx?.Options?.Logger?.Warning($"Could not write recompile failure dump: {dumpEx.Message}");
            }
        }

        private string FormatVmOperand(object operand)
        {
            if (operand == null)
                return "<null>";
            if (operand is int[] targets)
                return "[" + string.Join(", ", targets.Take(24)) + (targets.Length > 24 ? ", ..." : string.Empty) + "]";
            try
            {
                return operand.ToString() ?? "<null>";
            }
            catch
            {
                return "<operand-to-string-failed>";
            }
        }

        private string SanitizeFileName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "unknown";

            var invalid = Path.GetInvalidFileNameChars();
            var sanitized = new string(value.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
            if (sanitized.Length > 140)
                sanitized = sanitized.Substring(0, 140);
            return string.IsNullOrWhiteSpace(sanitized) ? "unknown" : sanitized;
        }

        private void LogDnlibStyleMaxStackAnalysis(
            DevirtualizationCtx ctx,
            VMMethod vmMethod,
            RecompiledMethodArtifact artifact)
        {
            if (!string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_LOG_DNLIB_STACK"),
                    "1",
                    StringComparison.Ordinal))
            {
                return;
            }

            var methodFilter = Environment.GetEnvironmentVariable("KRYPTON_LOG_DNLIB_STACK_METHOD");
            var methodName = vmMethod?.Parent?.FullName ?? "<unknown>";
            if (!string.IsNullOrWhiteSpace(methodFilter) &&
                methodName.IndexOf(methodFilter, StringComparison.OrdinalIgnoreCase) < 0)
            {
                return;
            }

            var analysis = DnlibStyleMaxStackAnalyzer.Analyze(ctx, vmMethod, artifact);
            if (analysis.TotalIssues <= 0)
            {
                ctx?.Options?.Logger?.Info(
                    $"dnlib-style max-stack analysis passed for {methodName} (max-depth {analysis.MaxObservedDepth}).");
                return;
            }

            ctx?.Options?.Logger?.Warning(
                $"dnlib-style max-stack analysis found {analysis.TotalIssues} issue(s) in {methodName}.");
            if (analysis.IssuesByVmByte.Count > 0)
            {
                ctx?.Options?.Logger?.Info(
                    $"dnlib-style top vm bytes for {methodName}: {string.Join(", ", analysis.IssuesByVmByte.OrderByDescending(q => q.Value).Take(8).Select(q => $"0x{q.Key:X2}={q.Value}"))}");
            }
            if (analysis.Messages.Count > 0)
            {
                ctx?.Options?.Logger?.Info(
                    $"dnlib-style samples for {methodName}: {string.Join(" | ", analysis.Messages.Take(8))}");
            }
        }
    }

    internal sealed class RecompiledMethodArtifact
    {
        public RecompiledMethodArtifact(CilMethodBody body, IReadOnlyList<VMInstruction> instructionOrigins)
        {
            Body = body ?? throw new ArgumentNullException(nameof(body));
            InstructionOrigins = instructionOrigins ?? throw new ArgumentNullException(nameof(instructionOrigins));
        }

        public CilMethodBody Body { get; }
        public IReadOnlyList<VMInstruction> InstructionOrigins { get; }
    }

    internal enum StackDepthBlockFlowKind
    {
        FallThroughOnly,
        UnconditionalBranch,
        ConditionalBranch,
        Switch,
        Terminal
    }

    internal sealed class StackDepthBlock
    {
        public StackDepthBlock(int index, int startIndex, int endIndex)
        {
            Index = index;
            StartIndex = startIndex;
            EndIndex = endIndex;
            BranchSuccessors = new List<int>();
        }

        public int Index { get; }
        public int StartIndex { get; }
        public int EndIndex { get; }
        public StackDepthBlockFlowKind FlowKind { get; set; }
        public List<int> BranchSuccessors { get; }
        public int? FallthroughSuccessor { get; set; }
    }

    internal sealed class StackDepthVariant
    {
        public StackDepthVariant(int blockIndex, int entryDepth)
        {
            BlockIndex = blockIndex;
            EntryDepth = entryDepth;
            BranchSuccessors = new List<(int blockIndex, int entryDepth)>();
            ClonedInstructions = new List<CilInstruction>();
        }

        public int BlockIndex { get; }
        public int EntryDepth { get; }
        public int ExitDepth { get; set; }
        public List<(int blockIndex, int entryDepth)> BranchSuccessors { get; }
        public (int blockIndex, int entryDepth)? FallthroughSuccessor { get; set; }
        public List<CilInstruction> ClonedInstructions { get; }
        public CilInstruction StartInstruction { get; set; }
        public CilInstruction FallthroughBranchInstruction { get; set; }
    }
}
