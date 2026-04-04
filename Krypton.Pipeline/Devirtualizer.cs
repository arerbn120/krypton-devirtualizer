using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Builder;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.Disassembly;
using Krypton.Core.Payload;
using Krypton.Core.Parser;
using Krypton.Pipeline.Services;
using Krypton.Pipeline.Stages;

namespace Krypton.Pipeline
{
    public class Devirtualizer
    {
        private static readonly string[] StrictAntiTamperStringMarkers =
        {
            "is tampered"
        };

        private static readonly string[] StrictAntiDebuggerStringMarkers =
        {
            "Debugger Detected"
        };

        private static readonly string[] AntiManipulationStringMarkers =
        {
            "is tampered",
            "tampered",
            "anti tamper",
            "anti-tamper",
            "integrity",
            "checksum",
            "debugger detected"
        };

        private static readonly string[] DebuggerApiMarkers =
        {
            "System.Diagnostics.Debugger::get_IsAttached",
            "System.Diagnostics.Debugger::IsAttached",
            "System.Diagnostics.Debugger::get_IsLogging",
            "System.Diagnostics.Debugger::IsLogging",
            "System.Diagnostics.Debugger::Log",
            "CheckRemoteDebuggerPresent",
            "IsDebuggerPresent"
        };

        private static readonly string[] TerminationApiMarkers =
        {
            "System.Environment::FailFast",
            "System.Environment::Exit",
            "System.Diagnostics.Process::Kill",
            "System.Windows.Forms.Application::Exit"
        };

        public Devirtualizer(DevirtualizationCtx Ctx)
        {
            this.Ctx = Ctx;
            var opcodeMapping = new OpcodeMapping();
            var semanticValidation = new SemanticValidation();
            var methodRecompiling = new MethodRecompiling();

            Ctx.ResourceReader ??= new ResourceParser();
            Ctx.ResourceReaders ??= new List<IResourceReader> { Ctx.ResourceReader };
            Ctx.PayloadParsers ??= new List<IVmPayloadParser> { new LegacyVmPayloadParser() };
            Ctx.OperandModelExtractors ??= new List<IOperandModelExtractor> { new OperandModelExtractor() };
            Ctx.DispatcherLocator ??= opcodeMapping;
            Ctx.OpcodeMapper ??= opcodeMapping;
            Ctx.InstructionDecoder ??= new VmInstructionDecoder();
            Ctx.VmSemanticValidator ??= semanticValidation;
            var semanticValidationStage = Ctx.VmSemanticValidator as IStage ?? semanticValidation;
            Ctx.CilLowerer ??= methodRecompiling;

            Stages = new List<IStage>
            {
                new ResourceParsing(),
                opcodeMapping,
                new MethodDisassembling(),
                semanticValidationStage,
                methodRecompiling,
                new MethodReplacing()
            };
        }

        public DevirtualizationCtx Ctx { get; set; }
        public List<IStage> Stages { get; set; }

        public void Devirtualize()
        {
            foreach (var stage in Stages)
            {
                Ctx.Options.Logger.Info($"Executing {stage.Name} Stage...");
                stage.Run(Ctx);
                Ctx.Options.Logger.Success($"Executed {stage.Name} Stage!");
            }
        }

        public void Save()
        {
            if (Ctx.VirtualizedMethods == null || Ctx.VirtualizedMethods.Count == 0)
            {
                Ctx.Options.Logger.Warning("No virtualized methods were disassembled, report generation skipped.");
                return;
            }

            var reportPath = DevirtualizationReportService.WriteReport(
                Ctx,
                FormatInstruction,
                GetHandlerSnippet);
            if (!string.IsNullOrWhiteSpace(reportPath))
                Ctx.Options.Logger.Success($"Wrote report at {reportPath}");

            var outputDecision = OutputEligibilityService.Evaluate(Ctx);
            if (outputDecision.MethodsWithUnknownCount > 0)
            {
                Ctx.Options.Logger.Warning(
                    $"Detected unresolved VM opcodes in {outputDecision.MethodsWithUnknownCount} method(s). Writing partial output with only fully recompiled methods replaced.");
            }
            if (!outputDecision.ShouldWriteOutput)
            {
                if (!string.IsNullOrWhiteSpace(outputDecision.SkipReason))
                    Ctx.Options.Logger.Warning(outputDecision.SkipReason);
                if (outputDecision.RemoveStaleOutput)
                    RemoveStaleOutputFile("this run does not satisfy output write conditions");
                return;
            }
            if (outputDecision.AllowStabilizationOnly &&
                !Ctx.VirtualizedMethods.Any(q => q.RecompiledBody != null))
            {
                Ctx.Options.Logger.Warning(
                    "No method was recompiled, but stabilization-only output is enabled. " +
                    "Applying runtime/anti-tamper stabilizers without method-body replacement.");
            }

            if (TryWriteInPlacePatchedAssembly())
            {
                Ctx.Options.Logger.Success($"Wrote File At {Ctx.Options.OutPath}");
                return;
            }

            Ctx.Options.Logger.Warning(
                "In-place method patch failed. Skipping full PE rebuild to avoid producing a broken PE layout. " +
                "Use the unpacked/working base binary as input.");
            RemoveStaleOutputFile("this run could not produce a valid patched output");
        }

        private void RemoveStaleOutputFile(string reason)
        {
            if (!File.Exists(Ctx.Options.OutPath))
                return;

            try
            {
                File.Delete(Ctx.Options.OutPath);
                Ctx.Options.Logger.Warning(
                    $"Removed stale output file at {Ctx.Options.OutPath} because {reason}.");
            }
            catch
            {
                Ctx.Options.Logger.Warning(
                    $"Could not remove stale file at {Ctx.Options.OutPath}; it may not reflect current report.");
            }
        }

        private bool TryWriteInPlacePatchedAssembly()
        {
            var methodsToPatch = Ctx.VirtualizedMethods
                .Where(q => q.Parent != null && q.RecompiledBody != null)
                .ToList();
            var allowStabilizationOnlyOutput = GetFeatureToggle(
                "KRYPTON_ALLOW_STABILIZATION_ONLY_OUTPUT",
                defaultEnabled: false);
            if (methodsToPatch.Count == 0 && !allowStabilizationOnlyOutput)
                return false;
            if (methodsToPatch.Count == 0 && allowStabilizationOnlyOutput)
            {
                Ctx.Options.Logger.Info(
                    "Proceeding without method-body patches because stabilization-only output is enabled.");
            }

            var tempPath = Path.Combine(
                Path.GetDirectoryName(Ctx.Options.OutPath)!,
                Path.GetFileNameWithoutExtension(Ctx.Options.OutPath) + ".tmp-rewrite" + Path.GetExtension(Ctx.Options.OutPath));

            try
            {
                // Keep final output layout identical to the original by patching directly into a copied file.
                File.Copy(Ctx.Options.FilePath, Ctx.Options.OutPath, true);

                var enableHashtableSanitize = GetFeatureToggle(
                    "KRYPTON_ENABLE_HASHTABLE_SANITIZE",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_HASHTABLE_SANITIZE");
                if (enableHashtableSanitize)
                {
                    var patchedHashtableCtors = SanitizeHashtableCapacityConstructors(Ctx.Module);
                    if (patchedHashtableCtors > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Sanitized {patchedHashtableCtors} Hashtable(Int32) constructor call(s) to avoid invalid negative capacities.");
                    }
                }

                var enableWinFormsGuardBypass = GetFeatureToggle(
                    "KRYPTON_ENABLE_WINFORMS_GUARD_BYPASS",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_WINFORMS_GUARD_BYPASS");
                if (enableWinFormsGuardBypass)
                {
                    var bypassedFormGuards = BypassWindowsFormsEntryGuards(Ctx.Module);
                    if (bypassedFormGuards > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Bypassed {bypassedFormGuards} Windows Forms anti-tamper entry guard(s).");
                    }
                }

                var enableStrictAntiManipulationPatch = GetFeatureToggle(
                    "KRYPTON_ENABLE_STRICT_ANTI_MANIPULATION_PATCH",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_STRICT_ANTI_MANIPULATION_PATCH");
                if (enableStrictAntiManipulationPatch)
                {
                    var strictTamperPatched = NeutralizeStrictMarkerGuards(
                        Ctx.Module,
                        StrictAntiTamperStringMarkers,
                        requireDebuggerSignal: false);
                    var strictDebuggerPatched = NeutralizeStrictMarkerGuards(
                        Ctx.Module,
                        StrictAntiDebuggerStringMarkers,
                        requireDebuggerSignal: true);
                    var strictTotalPatched = strictTamperPatched + strictDebuggerPatched;
                    if (strictTotalPatched > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Neutralized {strictTotalPatched} strict marker-based anti-manipulation method(s) " +
                            $"(anti-tamper={strictTamperPatched}, anti-debugger={strictDebuggerPatched}).");
                    }
                }

                var enableStringAntiManipulationPatch = GetFeatureToggle(
                    "KRYPTON_ENABLE_STRING_ANTI_MANIPULATION_PATCH",
                    defaultEnabled: false,
                    disableVariableName: "KRYPTON_DISABLE_STRING_ANTI_MANIPULATION_PATCH");
                if (enableStringAntiManipulationPatch)
                {
                    var patchedAntiManipulationMethods = NeutralizeStringSignatureAntiManipulationMethods(Ctx.Module);
                    if (patchedAntiManipulationMethods > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Neutralized {patchedAntiManipulationMethods} anti-manipulation method(s) using string/API heuristics.");
                    }
                }

                var enableTamperThrowNeutralize = GetFeatureToggle(
                    "KRYPTON_ENABLE_TAMPER_THROW_NEUTRALIZE",
                    defaultEnabled: false,
                    disableVariableName: "KRYPTON_DISABLE_TAMPER_THROW_NEUTRALIZE");
                if (enableTamperThrowNeutralize)
                {
                    var patchedTamperThrowers = NeutralizeTamperedExceptionThrowers(Ctx.Module);
                    if (patchedTamperThrowers > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Neutralized {patchedTamperThrowers} tamper-throw guard method(s).");
                    }
                }

                var enableStartupAntiTamperNeutralize = GetFeatureToggle(
                    "KRYPTON_ENABLE_STARTUP_ANTI_TAMPER_NEUTRALIZE",
                    defaultEnabled: false,
                    disableVariableName: "KRYPTON_DISABLE_STARTUP_ANTI_TAMPER_NEUTRALIZE");
                if (enableStartupAntiTamperNeutralize)
                {
                    var patchedStartupTamperGuards = NeutralizeStartupAntiTamperGuards(Ctx.Module);
                    if (patchedStartupTamperGuards > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Neutralized {patchedStartupTamperGuards} startup anti-tamper guard method(s) reachable from static constructors.");
                    }
                }

                var enableTokenDeobfuscationPatch = GetFeatureToggle(
                    "KRYPTON_ENABLE_TOKEN_DEOBFUSCATION_PATCH",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_TOKEN_DEOBFUSCATION_PATCH");
                if (enableTokenDeobfuscationPatch)
                {
                    var tokenPatches = DeobfuscateTokenResolverCalls(Ctx.Module);
                    if (tokenPatches > 0)
                    {
                        Ctx.Options.Logger.Info(
                            $"Token deobfuscation patch replaced {tokenPatches} ldc.i4+call wrapper sequence(s) with ldtoken.");
                    }
                }

                // Preserve definition table indices/tokens to avoid breaking protectors that do token-based runtime lookups.
                // Do not preserve all tables: some samples contain duplicate member refs that fail full token preservation.
                var metadataBuilderFlags =
                    MetadataBuilderFlags.PreserveTypeDefinitionIndices |
                    MetadataBuilderFlags.PreserveFieldDefinitionIndices |
                    MetadataBuilderFlags.PreserveMethodDefinitionIndices |
                    MetadataBuilderFlags.PreserveParameterDefinitionIndices |
                    MetadataBuilderFlags.PreserveEventDefinitionIndices |
                    MetadataBuilderFlags.PreservePropertyDefinitionIndices |
                    MetadataBuilderFlags.PreserveMemberReferenceIndices |
                    MetadataBuilderFlags.NoStringsStreamOptimization;

                // Build a temporary rewritten image only to extract the new method body bytes.
                var stripMalformedAttributes = string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_STRIP_MALFORMED_ATTRIBUTES"),
                    "1",
                    StringComparison.Ordinal);
                if (stripMalformedAttributes)
                {
                    var removed = StripMalformedCustomAttributes(Ctx.Module);
                    if (removed > 0)
                        Ctx.Options.Logger.Warning($"Removed {removed} malformed custom attributes before temporary donor write.");
                }

                var disableStartupGuard = GetFeatureToggle(
                    "KRYPTON_DISABLE_STARTUP_GUARD",
                    defaultEnabled: false);
                if (disableStartupGuard)
                {
                    var disableAllBootstrapCctors = string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_DISABLE_ALL_BOOTSTRAP_CCTORS"),
                        "1",
                        StringComparison.Ordinal);
                    var disabled = disableAllBootstrapCctors
                        ? DisableBootstrapTypeInitializers(Ctx.Module, Ctx.Module.GetAllTypes())
                        : DisableBootstrapTypeInitializers(Ctx.Module, GetBootstrapCandidateTypes(methodsToPatch));
                    if (disabled > 0)
                        Ctx.Options.Logger.Warning(
                            $"Neutralized {disabled} bootstrap-like static constructor(s) in temporary donor.");
                }

                var neutralizeSharedBootstrap = GetFeatureToggle(
                    "KRYPTON_NEUTRALIZE_SHARED_BOOTSTRAP",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_SHARED_BOOTSTRAP_NEUTRALIZE");
                if (neutralizeSharedBootstrap)
                {
                    var neutralizedWorkers = NeutralizeSharedBootstrapMethods(Ctx.Module);
                    if (neutralizedWorkers > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Neutralized {neutralizedWorkers} shared bootstrap worker method(s) referenced by multiple static constructors.");
                    }
                }
                var enableTypeRefRepair = GetFeatureToggle(
                    "KRYPTON_ENABLE_TYPEREF_REPAIR",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_TYPEREF_REPAIR");
                var repairedTypeRefs = 0;
                if (enableTypeRefRepair)
                {
                    repairedTypeRefs = RepairInvalidTypeReferences(Ctx.Module, Ctx.Options.FilePath);
                    if (repairedTypeRefs > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Repaired {repairedTypeRefs} invalid type reference scope(s) before donor write.");
                    }
                }

                var enableDeadInstructionSanitize = GetFeatureToggle(
                    "KRYPTON_ENABLE_DEAD_INSTRUCTION_SANITIZE",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_DEAD_INSTRUCTION_SANITIZE");
                var sanitizedDeadInstructions = 0;
                if (enableDeadInstructionSanitize)
                {
                    sanitizedDeadInstructions = SanitizeUnreachableInvalidInstructions(Ctx.Module);
                    if (sanitizedDeadInstructions > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Sanitized {sanitizedDeadInstructions} unreachable invalid instruction(s) before donor write.");
                    }
                }
                NormalizeAssemblyIdentity(Ctx.Module);
                WriteTemporaryDonorImage(tempPath, metadataBuilderFlags, stripMalformedAttributes, methodsToPatch);

                var useRewriteOutput = !string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_USE_INPLACE_PATCH"),
                    "1",
                    StringComparison.Ordinal);
                if (useRewriteOutput)
                {
                    File.Copy(tempPath, Ctx.Options.OutPath, true);
                    ClearInvalidStrongNameFlag(Ctx.Options.OutPath);
                    Ctx.Options.Logger.Info("Using rewritten assembly output (manual in-place patch disabled by default).");
                    return true;
                }

                var targetBytes = File.ReadAllBytes(Ctx.Options.OutPath);
                var donorBytes = File.ReadAllBytes(tempPath);

                var targetLayout = ReadPeLayout(targetBytes);
                var donorLayout = ReadPeLayout(donorBytes);

                var targetMethodRvas = GetMethodBodyRvas(Ctx.Options.OutPath);
                var donorMethodRvas = GetMethodBodyRvas(tempPath);
                var donorMethodTokensByFullName = GetMethodTokensByFullName(tempPath);
                var capacities = BuildMethodBodyCapacities(targetMethodRvas, targetLayout);

                var patched = 0;
                foreach (var vmMethod in methodsToPatch)
                {
                    var token = vmMethod.Parent!.MetadataToken.ToUInt32();
                    if (!targetMethodRvas.TryGetValue(token, out var targetRva))
                        throw new DevirtualizationException($"Could not resolve method token 0x{token:X8} for in-place patch.");

                    var methodFullName = vmMethod.Parent.FullName;
                    if (!donorMethodTokensByFullName.TryGetValue(methodFullName, out var donorToken))
                        donorToken = token;

                    if (!donorMethodRvas.TryGetValue(donorToken, out var donorRva))
                        throw new DevirtualizationException(
                            $"Could not resolve donor method RVA for {methodFullName} (token 0x{donorToken:X8}).");

                    if (donorToken != token)
                    {
                        Ctx.Options.Logger.Info(
                            $"Resolved donor token remap for {methodFullName}: 0x{token:X8} -> 0x{donorToken:X8}.");
                    }

                    if (targetRva == 0 || donorRva == 0)
                    {
                        throw new DevirtualizationException(
                            $"Method token 0x{token:X8} / donor token 0x{donorToken:X8} has no method body RVA.");
                    }

                    var targetOffset = RvaToFileOffset(targetLayout, targetRva);
                    var donorOffset = RvaToFileOffset(donorLayout, donorRva);
                    var oldBodySize = GetMethodBodySize(targetBytes, targetOffset);
                    var newBodySize = GetMethodBodySize(donorBytes, donorOffset);

                    if (!capacities.TryGetValue(token, out var capacity))
                        throw new DevirtualizationException($"Could not determine in-place capacity for method token 0x{token:X8}.");

                    if (newBodySize <= capacity)
                    {
                        Buffer.BlockCopy(donorBytes, donorOffset, targetBytes, targetOffset, newBodySize);
                        if (newBodySize < oldBodySize)
                            Array.Clear(targetBytes, targetOffset + newBodySize, oldBodySize - newBodySize);
                    }
                    else
                    {
                        var relocatedBody = new byte[newBodySize];
                        Buffer.BlockCopy(donorBytes, donorOffset, relocatedBody, 0, newBodySize);
                        var newRva = AppendMethodBodyToPreferredSection(
                            ref targetBytes,
                            targetLayout,
                            relocatedBody,
                            targetRva);
                        PatchMethodDefinitionRva(targetBytes, targetLayout, token, newRva);
                        targetMethodRvas[token] = newRva;
                        Ctx.Options.Logger.Warning(
                            $"Relocated method token 0x{token:X8} to RVA 0x{newRva:X8} because body size {newBodySize} exceeded original capacity {capacity}.");
                    }

                    patched++;
                }

                File.WriteAllBytes(Ctx.Options.OutPath, targetBytes);
                ClearInvalidStrongNameFlag(Ctx.Options.OutPath);
                Ctx.Options.Logger.Info($"Patched {patched} method body(s) in-place.");
                return patched > 0;
            }
            catch (Exception ex)
            {
                Ctx.Options.Logger.Warning($"In-place patch failed: {ex.Message}");
                return false;
            }
            finally
            {
                if (File.Exists(tempPath))
                {
                    try
                    {
                        File.Delete(tempPath);
                    }
                    catch
                    {
                        // Best effort cleanup.
                    }
                }
            }
        }

        private void WriteTemporaryDonorImage(
            string tempPath,
            MetadataBuilderFlags metadataBuilderFlags,
            bool stripMalformedAttributes,
            IReadOnlyCollection<Core.Architecture.VMMethod> methodsToPatch)
        {
            void WriteDonor()
            {
                Ctx.Module.Write(
                    tempPath,
                    new ManagedPEImageBuilder(new DotNetDirectoryFactory(metadataBuilderFlags)));
            }

            Exception initialWriteError = null;
            try
            {
                WriteDonor();
                return;
            }
            catch (Exception ex)
            {
                initialWriteError = ex;
            }

            if (TryRelaxStackValidationOnWriteFailure(initialWriteError, methodsToPatch))
            {
                try
                {
                    WriteDonor();
                    return;
                }
                catch (Exception relaxedRetryError)
                {
                    initialWriteError = relaxedRetryError;
                }
            }

            if (stripMalformedAttributes)
                throw initialWriteError;

            Ctx.Options.Logger.Warning(
                $"Temporary donor write failed without attribute stripping ({initialWriteError.Message}). Retrying with malformed-attribute cleanup.");
            var removed = StripMalformedCustomAttributes(Ctx.Module);
            if (removed > 0)
                Ctx.Options.Logger.Warning($"Removed {removed} malformed custom attributes before retry donor write.");
            try
            {
                WriteDonor();
            }
            catch (Exception retryEx)
            {
                Ctx.Options.Logger.Warning(
                    $"Retry donor write after malformed-attribute cleanup failed ({retryEx.Message}). Retrying with full custom-attribute strip.");
                var cleared = ClearAllCustomAttributes(Ctx.Module);
                if (cleared > 0)
                    Ctx.Options.Logger.Warning($"Removed {cleared} custom attributes before final donor write retry.");
                WriteDonor();
            }
        }

        private bool TryRelaxStackValidationOnWriteFailure(
            Exception writeError,
            IReadOnlyCollection<Core.Architecture.VMMethod> methodsToPatch)
        {
            if (!IsStackImbalanceWriteFailure(writeError))
                return false;

            var relaxed = 0;
            foreach (var vmMethod in methodsToPatch)
            {
                var body = vmMethod?.Parent?.CilMethodBody;
                if (body == null)
                    continue;

                var changed = false;
                if (body.ComputeMaxStackOnBuild)
                {
                    body.ComputeMaxStackOnBuild = false;
                    changed = true;
                }

                if (body.VerifyLabelsOnBuild)
                {
                    body.VerifyLabelsOnBuild = false;
                    changed = true;
                }

                var relaxedFlags = body.BuildFlags &
                                   ~(CilMethodBodyBuildFlags.ComputeMaxStack |
                                     CilMethodBodyBuildFlags.VerifyLabels |
                                     CilMethodBodyBuildFlags.FullValidation);
                if (relaxedFlags != body.BuildFlags)
                {
                    body.BuildFlags = relaxedFlags;
                    changed = true;
                }

                if (body.MaxStack < 64)
                {
                    body.MaxStack = 64;
                    changed = true;
                }

                if (changed)
                    relaxed++;
            }

            if (relaxed <= 0)
                return false;

            Ctx.Options.Logger.Warning(
                $"Detected stack validation failure while writing donor image. Relaxed max-stack computation for {relaxed} method(s) and retrying.");
            return true;
        }

        private bool IsStackImbalanceWriteFailure(Exception error)
        {
            if (error == null)
                return false;

            return error.ToString().IndexOf("Stack imbalance was detected", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private int SanitizeUnreachableInvalidInstructions(AsmResolver.DotNet.ModuleDefinition module)
        {
            if (module == null)
                return 0;

            var sanitized = 0;
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    var body = method?.CilMethodBody;
                    if (body?.Instructions == null || body.Instructions.Count == 0)
                        continue;

                    var reachable = GetReachableInstructionIndices(body);
                    for (var i = 0; i < body.Instructions.Count; i++)
                    {
                        if (reachable.Contains(i))
                            continue;

                        var instruction = body.Instructions[i];
                        if (!RequiresOperand(instruction.OpCode) || instruction.Operand != null)
                            continue;

                        instruction.OpCode = CilOpCodes.Nop;
                        instruction.Operand = null;
                        sanitized++;
                    }
                }
            }

            return sanitized;
        }

        private HashSet<int> GetReachableInstructionIndices(CilMethodBody body)
        {
            var reachable = new HashSet<int>();
            var worklist = new Stack<int>();
            var instructionIndexByInstruction = new Dictionary<CilInstruction, int>(body.Instructions.Count);
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
                        PushReachableTarget(worklist, instruction.Operand, instructionIndexByInstruction);
                        break;

                    case CilCode.Brtrue:
                    case CilCode.Brfalse:
                    case CilCode.Blt_Un:
                    case CilCode.Bge_Un:
                        PushReachableTarget(worklist, instruction.Operand, instructionIndexByInstruction);
                        worklist.Push(index + 1);
                        break;

                    case CilCode.Switch:
                        if (instruction.Operand is IList<ICilLabel> labels)
                        {
                            foreach (var label in labels)
                                PushReachableTarget(worklist, label, instructionIndexByInstruction);
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

        private void PushReachableTarget(
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

        private bool RequiresOperand(CilOpCode opCode)
        {
            return opCode.Code != CilCode.Nop &&
                   opCode.OperandType != CilOperandType.InlineNone;
        }

        private Dictionary<uint, int> BuildMethodBodyCapacities(
            Dictionary<uint, uint> methodRvas,
            PeLayout layout)
        {
            var methods = methodRvas
                .Where(kv => kv.Value > 0)
                .OrderBy(kv => kv.Value)
                .ToList();

            var result = new Dictionary<uint, int>();
            for (var i = 0; i < methods.Count; i++)
            {
                var methodToken = methods[i].Key;
                var methodRva = methods[i].Value;
                var section = GetSectionForRva(layout, methodRva);
                if (section == null)
                    continue;

                uint? nextRva = null;
                for (var j = i + 1; j < methods.Count; j++)
                {
                    if (methods[j].Value > methodRva)
                    {
                        nextRva = methods[j].Value;
                        break;
                    }
                }

                var sectionSpan = Math.Max(section.VirtualSize, section.RawSize);
                var sectionEndRva = section.VirtualAddress + sectionSpan;
                var capacity = (int) ((nextRva ?? sectionEndRva) - methodRva);
                if (capacity <= 0)
                    continue;

                result[methodToken] = capacity;
            }

            return result;
        }

        private Dictionary<uint, uint> GetMethodBodyRvas(string filePath)
        {
            using var stream = File.OpenRead(filePath);
            using var peReader = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
            var metadata = peReader.GetMetadataReader();

            var result = new Dictionary<uint, uint>();
            foreach (var handle in metadata.MethodDefinitions)
            {
                var token = (uint) MetadataTokens.GetToken(handle);
                var row = metadata.GetMethodDefinition(handle);
                result[token] = unchecked((uint) row.RelativeVirtualAddress);
            }

            return result;
        }

        private Dictionary<string, uint> GetMethodTokensByFullName(string filePath)
        {
            var module = AsmResolver.DotNet.ModuleDefinition.FromFile(filePath);
            var result = new Dictionary<string, uint>(StringComparer.Ordinal);
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    var key = method.FullName;
                    if (!result.ContainsKey(key))
                        result[key] = method.MetadataToken.ToUInt32();
                }
            }

            return result;
        }

        private int RvaToFileOffset(PeLayout layout, uint rva)
        {
            var section = GetSectionForRva(layout, rva);
            if (section == null)
                throw new DevirtualizationException($"Could not map RVA 0x{rva:X8} to file offset.");

            return checked((int) (section.RawPointer + (rva - section.VirtualAddress)));
        }

        private PeSection GetSectionForRva(PeLayout layout, uint rva)
        {
            foreach (var section in layout.Sections)
            {
                var sectionSpan = Math.Max(section.VirtualSize, section.RawSize);
                var end = section.VirtualAddress + sectionSpan;
                if (rva >= section.VirtualAddress && rva < end)
                    return section;
            }

            return null;
        }

        private int GetMethodBodySize(byte[] image, int offset)
        {
            if (offset < 0 || offset >= image.Length)
                throw new DevirtualizationException($"Method body offset 0x{offset:X8} is outside image bounds.");

            var first = image[offset];
            var format = first & 0x3;
            switch (format)
            {
                case 0x2: // tiny
                    return 1 + (first >> 2);
                case 0x3: // fat
                {
                    var flags = BitConverter.ToUInt16(image, offset);
                    var headerDwords = (flags >> 12) & 0xF;
                    var headerSize = headerDwords * 4;
                    if (headerSize <= 0)
                        throw new DevirtualizationException("Invalid fat method header size.");

                    var codeSize = BitConverter.ToInt32(image, offset + 4);
                    var total = headerSize + codeSize;
                    if ((flags & 0x8) == 0)
                        return total;

                    var sectionOffset = offset + Align4(total);
                    var hasMoreSections = true;
                    while (hasMoreSections)
                    {
                        if (sectionOffset + 4 > image.Length)
                            throw new DevirtualizationException("Method data section exceeds image bounds.");

                        var kind = image[sectionOffset];
                        hasMoreSections = (kind & 0x80) != 0;
                        var fatSection = (kind & 0x40) != 0;

                        int dataSize;
                        if (fatSection)
                        {
                            dataSize = image[sectionOffset + 1]
                                       | (image[sectionOffset + 2] << 8)
                                       | (image[sectionOffset + 3] << 16);
                        }
                        else
                        {
                            dataSize = image[sectionOffset + 1];
                        }

                        if (dataSize <= 0)
                            throw new DevirtualizationException("Invalid method data section size.");

                        sectionOffset += Align4(dataSize);
                    }

                    return sectionOffset - offset;
                }
                default:
                    throw new DevirtualizationException($"Unsupported method body format 0x{format:X}.");
            }
        }

        private int Align4(int value) => (value + 3) & ~3;

        private uint Align(uint value, uint alignment)
        {
            if (alignment == 0)
                return value;
            var mask = alignment - 1;
            return (value + mask) & ~mask;
        }

        private uint AppendMethodBodyToPreferredSection(
            ref byte[] image,
            PeLayout layout,
            byte[] bodyBytes,
            uint preferredRva)
        {
            var section = GetSectionForRva(layout, preferredRva);
            var textSection = layout.Sections.FirstOrDefault(s =>
                s.Name.Equals(".text", StringComparison.OrdinalIgnoreCase) ||
                s.Name.StartsWith(".text", StringComparison.OrdinalIgnoreCase));
            if (textSection != null &&
                (section == null || !section.Name.StartsWith(".text", StringComparison.OrdinalIgnoreCase)))
            {
                if (section != null)
                {
                    Ctx.Options.Logger.Warning(
                        $"Relocation target section switched from '{section.Name}' to '{textSection.Name}' for dnSpy-friendly method body placement.");
                }

                section = textSection;
            }

            section ??= GetOrCreatePatchCodeSection(ref image, layout);
            if (section == null)
                throw new DevirtualizationException("Could not locate or create a patch code section.");

            // Keep RVA/file mapping consistent even when VirtualSize != RawSize.
            var sectionSpan = Math.Max(section.VirtualSize, section.RawSize);
            var bodyStart = Align(sectionSpan, 4);
            var newRva = section.VirtualAddress + bodyStart;
            var newRawOffset = section.RawPointer + bodyStart;

            var requiredVirtualSize = bodyStart + (uint) bodyBytes.Length;
            var requiredRawSize = Align(requiredVirtualSize, layout.FileAlignment);
            EnsureSectionRawCapacity(ref image, layout, section, requiredRawSize);

            var requiredLength = checked((int) (section.RawPointer + requiredRawSize));
            if (requiredLength > image.Length)
                Array.Resize(ref image, requiredLength);

            Buffer.BlockCopy(bodyBytes, 0, image, checked((int) newRawOffset), bodyBytes.Length);

            section.VirtualSize = Math.Max(section.VirtualSize, requiredVirtualSize);
            section.RawSize = Math.Max(section.RawSize, requiredRawSize);
            WriteUInt32(image, section.HeaderOffset + 8, section.VirtualSize);
            WriteUInt32(image, section.HeaderOffset + 16, section.RawSize);

            var sizeOfImage = layout.Sections
                .Select(s => s.VirtualAddress + Align(Math.Max(s.VirtualSize, s.RawSize), layout.SectionAlignment))
                .Max();
            WriteUInt32(image, layout.SizeOfImageOffset, sizeOfImage);

            return newRva;
        }

        private void EnsureSectionRawCapacity(
            ref byte[] image,
            PeLayout layout,
            PeSection section,
            uint requiredRawSize)
        {
            if (requiredRawSize <= section.RawSize)
                return;

            var growth = requiredRawSize - section.RawSize;
            if (growth == 0)
                return;

            var ordered = layout.Sections
                .OrderBy(s => s.RawPointer)
                .ToList();
            var sectionIndex = ordered.IndexOf(section);
            if (sectionIndex < 0)
                throw new DevirtualizationException("Target section is missing from PE layout.");

            var insertAt = section.RawPointer + section.RawSize;
            if (sectionIndex < ordered.Count - 1)
            {
                var oldLength = image.Length;
                var newLength = checked(oldLength + (int) growth);
                Array.Resize(ref image, newLength);

                Buffer.BlockCopy(
                    image,
                    checked((int) insertAt),
                    image,
                    checked((int) (insertAt + growth)),
                    checked(oldLength - (int) insertAt));
                Array.Clear(image, checked((int) insertAt), checked((int) growth));

                for (var i = sectionIndex + 1; i < ordered.Count; i++)
                {
                    var moved = ordered[i];
                    moved.RawPointer += growth;
                    WriteUInt32(image, moved.HeaderOffset + 20, moved.RawPointer);
                }

                Ctx.Options.Logger.Warning(
                    $"Expanded section '{section.Name}' raw data by 0x{growth:X} and shifted following sections to keep method body inside .text.");
            }
            else
            {
                var requiredLength = checked((int) (insertAt + growth));
                if (requiredLength > image.Length)
                    Array.Resize(ref image, requiredLength);
            }
        }

        private PeSection GetOrCreatePatchCodeSection(ref byte[] image, PeLayout layout)
        {
            var existing = layout.Sections.FirstOrDefault(s => s.Name == ".text#2");
            if (existing != null)
                return existing;

            var newHeaderOffset = layout.SectionTableOffset + layout.Sections.Count * 40;
            var firstRawPointer = layout.Sections.Min(s => s.RawPointer);
            if (newHeaderOffset + 40 > firstRawPointer)
            {
                var fallback = layout.Sections
                    .OrderBy(s => s.RawPointer + s.RawSize)
                    .LastOrDefault();
                if (fallback == null)
                    throw new DevirtualizationException("Not enough room in PE headers to add a new section.");

                Ctx.Options.Logger.Warning(
                    $"Not enough room in PE headers for .text#2; reusing existing section '{fallback.Name}' for relocated method body.");
                return fallback;
            }

            var newVirtualAddress = layout.Sections
                .Select(s => s.VirtualAddress + Align(Math.Max(s.VirtualSize, s.RawSize), layout.SectionAlignment))
                .Max();
            newVirtualAddress = Align(newVirtualAddress, layout.SectionAlignment);

            var newRawPointer = layout.Sections
                .Select(s => s.RawPointer + s.RawSize)
                .Max();
            newRawPointer = Align(newRawPointer, layout.FileAlignment);

            // Name (8 bytes)
            var nameBytes = new byte[8];
            var encoded = Encoding.ASCII.GetBytes(".text#2");
            Buffer.BlockCopy(encoded, 0, nameBytes, 0, encoded.Length);
            Buffer.BlockCopy(nameBytes, 0, image, newHeaderOffset, 8);

            WriteUInt32(image, newHeaderOffset + 8, 0); // VirtualSize
            WriteUInt32(image, newHeaderOffset + 12, newVirtualAddress);
            WriteUInt32(image, newHeaderOffset + 16, 0); // SizeOfRawData
            WriteUInt32(image, newHeaderOffset + 20, newRawPointer);
            WriteUInt32(image, newHeaderOffset + 24, 0);
            WriteUInt32(image, newHeaderOffset + 28, 0);
            WriteUInt16(image, newHeaderOffset + 32, 0);
            WriteUInt16(image, newHeaderOffset + 34, 0);
            WriteUInt32(image, newHeaderOffset + 36, 0x60000020); // code | execute | read

            layout.SectionCount++;
            WriteUInt16(image, layout.NumberOfSectionsOffset, (ushort) layout.SectionCount);

            var section = new PeSection(".text#2", newHeaderOffset, newVirtualAddress, 0, newRawPointer, 0);
            layout.Sections.Add(section);
            return section;
        }

        private void PatchMethodDefinitionRva(byte[] image, PeLayout layout, uint methodToken, uint newRva)
        {
            var info = GetMethodDefTableInfo(image, layout);
            var rid = methodToken & 0x00FFFFFF;
            if (rid == 0)
                throw new DevirtualizationException($"Invalid method token 0x{methodToken:X8}.");

            var rowIndex = checked((int) (rid - 1));
            var rowOffset = info.MethodTableOffset + rowIndex * info.MethodRowSize;
            if (rowOffset < 0 || rowOffset + 4 > image.Length)
                throw new DevirtualizationException($"MethodDef row offset out of bounds for token 0x{methodToken:X8}.");

            WriteUInt32(image, rowOffset, newRva);
        }

        private MethodDefTableInfo GetMethodDefTableInfo(byte[] image, PeLayout layout)
        {
            var metadataRva = ReadUInt32(image, layout.ClrHeaderFileOffset + 8);
            if (metadataRva == 0)
                throw new DevirtualizationException("CLR metadata RVA is zero.");

            var metadataOffset = RvaToFileOffset(layout, metadataRva);
            if (ReadUInt32(image, metadataOffset) != 0x424A5342) // BSJB
                throw new DevirtualizationException("Invalid CLR metadata signature.");

            var position = metadataOffset + 4; // signature
            position += 2; // major
            position += 2; // minor
            position += 4; // reserved
            var versionLength = ReadUInt32(image, position);
            position += 4;
            position += checked((int) versionLength);
            position = Align4(position);

            position += 2; // flags
            var streamCount = ReadUInt16(image, position);
            position += 2;

            int tablesStreamOffset = -1;
            for (var i = 0; i < streamCount; i++)
            {
                var streamOffset = ReadUInt32(image, position);
                position += 4;
                _ = ReadUInt32(image, position); // size
                position += 4;

                var nameStart = position;
                while (position < image.Length && image[position] != 0)
                    position++;
                var name = Encoding.ASCII.GetString(image, nameStart, position - nameStart);
                position++; // null terminator
                while (((position - nameStart) & 3) != 0)
                    position++;

                if (name == "#~" || name == "#-")
                    tablesStreamOffset = metadataOffset + checked((int) streamOffset);
            }

            if (tablesStreamOffset < 0)
                throw new DevirtualizationException("Could not locate metadata tables stream.");

            return ParseMethodDefTableInfo(image, tablesStreamOffset);
        }

        private MethodDefTableInfo ParseMethodDefTableInfo(byte[] image, int tablesOffset)
        {
            var position = tablesOffset;
            position += 4; // reserved
            position += 1; // major
            position += 1; // minor
            var heapSizes = image[position];
            position += 1;
            position += 1; // reserved
            var validMask = ReadUInt64(image, position);
            position += 8;
            position += 8; // sorted mask

            var rowCounts = new uint[64];
            for (var table = 0; table < 64; table++)
            {
                if (((validMask >> table) & 1UL) == 0)
                    continue;
                rowCounts[table] = ReadUInt32(image, position);
                position += 4;
            }

            var rowsOffset = position;
            var current = rowsOffset;
            for (var table = 0; table < 64; table++)
            {
                if (((validMask >> table) & 1UL) == 0)
                    continue;

                var rowSize = GetMetadataTableRowSize(table, rowCounts, heapSizes);
                if (table == 6) // MethodDef
                    return new MethodDefTableInfo(current, rowSize);

                current += checked((int) (rowCounts[table] * (uint) rowSize));
            }

            throw new DevirtualizationException("MethodDef table is missing from metadata.");
        }

        private MetadataTableInfo GetAssemblyTableInfo(byte[] image, PeLayout layout)
        {
            var metadataRva = ReadUInt32(image, layout.ClrHeaderFileOffset + 8);
            if (metadataRva == 0)
                throw new DevirtualizationException("CLR metadata RVA is zero.");

            var metadataOffset = RvaToFileOffset(layout, metadataRva);
            if (ReadUInt32(image, metadataOffset) != 0x424A5342) // BSJB
                throw new DevirtualizationException("Invalid CLR metadata signature.");

            var position = metadataOffset + 4; // signature
            position += 2; // major
            position += 2; // minor
            position += 4; // reserved
            var versionLength = ReadUInt32(image, position);
            position += 4;
            position += checked((int) versionLength);
            position = Align4(position);

            position += 2; // flags
            var streamCount = ReadUInt16(image, position);
            position += 2;

            var tablesStreamOffset = -1;
            for (var i = 0; i < streamCount; i++)
            {
                var streamOffset = ReadUInt32(image, position);
                position += 4;
                _ = ReadUInt32(image, position); // size
                position += 4;

                var nameStart = position;
                while (position < image.Length && image[position] != 0)
                    position++;
                var name = Encoding.ASCII.GetString(image, nameStart, position - nameStart);
                position++; // null terminator
                while (((position - nameStart) & 3) != 0)
                    position++;

                if (name == "#~" || name == "#-")
                    tablesStreamOffset = metadataOffset + checked((int) streamOffset);
            }

            if (tablesStreamOffset < 0)
                throw new DevirtualizationException("Could not locate metadata tables stream.");

            position = tablesStreamOffset;
            position += 4; // reserved
            position += 1; // major
            position += 1; // minor
            var heapSizes = image[position];
            position += 1;
            position += 1; // reserved
            var validMask = ReadUInt64(image, position);
            position += 8;
            position += 8; // sorted mask

            var rowCounts = new uint[64];
            for (var table = 0; table < 64; table++)
            {
                if (((validMask >> table) & 1UL) == 0)
                    continue;
                rowCounts[table] = ReadUInt32(image, position);
                position += 4;
            }

            var rowsOffset = position;
            var current = rowsOffset;
            for (var table = 0; table < 64; table++)
            {
                if (((validMask >> table) & 1UL) == 0)
                    continue;

                var rowSize = GetMetadataTableRowSize(table, rowCounts, heapSizes);
                if (table == 32) // Assembly
                {
                    return new MetadataTableInfo(
                        current,
                        rowSize,
                        rowCounts[table],
                        (heapSizes & 0x04) != 0 ? 4 : 2);
                }

                current += checked((int) (rowCounts[table] * (uint) rowSize));
            }

            throw new DevirtualizationException("Assembly table is missing from metadata.");
        }

        private int GetMetadataTableRowSize(int table, uint[] rowCounts, byte heapSizes)
        {
            var stringIndexSize = (heapSizes & 0x01) != 0 ? 4 : 2;
            var guidIndexSize = (heapSizes & 0x02) != 0 ? 4 : 2;
            var blobIndexSize = (heapSizes & 0x04) != 0 ? 4 : 2;

            int SimpleIndexSize(int targetTable) => rowCounts[targetTable] < 0x10000 ? 2 : 4;
            int CodedIndexSize(int tagBits, params int[] targetTables)
            {
                var maxRows = 0u;
                foreach (var t in targetTables)
                    maxRows = Math.Max(maxRows, rowCounts[t]);
                return maxRows < (1u << (16 - tagBits)) ? 2 : 4;
            }

            switch (table)
            {
                case 0: // Module
                    return 2 + stringIndexSize + guidIndexSize + guidIndexSize + guidIndexSize;
                case 1: // TypeRef
                    return CodedIndexSize(2, 0, 1, 26, 35) + stringIndexSize + stringIndexSize;
                case 2: // TypeDef
                    return 4 + stringIndexSize + stringIndexSize + CodedIndexSize(2, 1, 2, 27) +
                           SimpleIndexSize(4) + SimpleIndexSize(6);
                case 3: // FieldPtr
                    return SimpleIndexSize(4);
                case 4: // Field
                    return 2 + stringIndexSize + blobIndexSize;
                case 5: // MethodPtr
                    return SimpleIndexSize(6);
                case 6: // MethodDef
                    return 4 + 2 + 2 + stringIndexSize + blobIndexSize + SimpleIndexSize(8);
                case 7: // ParamPtr
                    return SimpleIndexSize(8);
                case 8: // Param
                    return 2 + 2 + stringIndexSize;
                case 9: // InterfaceImpl
                    return SimpleIndexSize(2) + CodedIndexSize(2, 1, 2, 27);
                case 10: // MemberRef
                    return CodedIndexSize(3, 2, 1, 26, 6, 27) + stringIndexSize + blobIndexSize;
                case 11: // Constant
                    return 2 + CodedIndexSize(2, 4, 8, 23) + blobIndexSize;
                case 12: // CustomAttribute
                    return CodedIndexSize(5, 6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43) +
                           CodedIndexSize(3, 6, 10) + blobIndexSize;
                case 13: // FieldMarshal
                    return CodedIndexSize(1, 4, 8) + blobIndexSize;
                case 14: // DeclSecurity
                    return 2 + CodedIndexSize(2, 2, 6, 32) + blobIndexSize;
                case 15: // ClassLayout
                    return 2 + 4 + SimpleIndexSize(2);
                case 16: // FieldLayout
                    return 4 + SimpleIndexSize(4);
                case 17: // StandAloneSig
                    return blobIndexSize;
                case 18: // EventMap
                    return SimpleIndexSize(2) + SimpleIndexSize(20);
                case 19: // EventPtr
                    return SimpleIndexSize(20);
                case 20: // Event
                    return 2 + stringIndexSize + CodedIndexSize(2, 1, 2, 27);
                case 21: // PropertyMap
                    return SimpleIndexSize(2) + SimpleIndexSize(23);
                case 22: // PropertyPtr
                    return SimpleIndexSize(23);
                case 23: // Property
                    return 2 + stringIndexSize + blobIndexSize;
                case 24: // MethodSemantics
                    return 2 + SimpleIndexSize(6) + CodedIndexSize(1, 20, 23);
                case 25: // MethodImpl
                    return SimpleIndexSize(2) + CodedIndexSize(1, 6, 10) + CodedIndexSize(1, 6, 10);
                case 26: // ModuleRef
                    return stringIndexSize;
                case 27: // TypeSpec
                    return blobIndexSize;
                case 28: // ImplMap
                    return 2 + CodedIndexSize(1, 4, 6) + stringIndexSize + SimpleIndexSize(26);
                case 29: // FieldRva
                    return 4 + SimpleIndexSize(4);
                case 30: // ENCLog
                    return 8;
                case 31: // ENCMap
                    return 4;
                case 32: // Assembly
                    return 4 + 2 + 2 + 2 + 2 + 4 + blobIndexSize + stringIndexSize + stringIndexSize;
                case 33: // AssemblyProcessor
                    return 4;
                case 34: // AssemblyOS
                    return 12;
                case 35: // AssemblyRef
                    return 2 + 2 + 2 + 2 + 4 + blobIndexSize + stringIndexSize + stringIndexSize + blobIndexSize;
                case 36: // AssemblyRefProcessor
                    return 4 + SimpleIndexSize(35);
                case 37: // AssemblyRefOS
                    return 12 + SimpleIndexSize(35);
                case 38: // File
                    return 4 + stringIndexSize + blobIndexSize;
                case 39: // ExportedType
                    return 4 + 4 + stringIndexSize + stringIndexSize + CodedIndexSize(2, 38, 35, 39);
                case 40: // ManifestResource
                    return 4 + 4 + stringIndexSize + CodedIndexSize(2, 38, 35, 39);
                case 41: // NestedClass
                    return SimpleIndexSize(2) + SimpleIndexSize(2);
                case 42: // GenericParam
                    return 2 + 2 + CodedIndexSize(1, 2, 6) + stringIndexSize;
                case 43: // MethodSpec
                    return CodedIndexSize(1, 6, 10) + blobIndexSize;
                case 44: // GenericParamConstraint
                    return SimpleIndexSize(42) + CodedIndexSize(2, 1, 2, 27);
                default:
                    throw new DevirtualizationException(
                        $"Unsupported metadata table {table} while locating MethodDef table.");
            }
        }

        private uint ReadUInt32(byte[] data, int offset) => BitConverter.ToUInt32(data, offset);
        private ushort ReadUInt16(byte[] data, int offset) => BitConverter.ToUInt16(data, offset);
        private ulong ReadUInt64(byte[] data, int offset) => BitConverter.ToUInt64(data, offset);

        private void WriteUInt32(byte[] data, int offset, uint value)
        {
            var bytes = BitConverter.GetBytes(value);
            Buffer.BlockCopy(bytes, 0, data, offset, 4);
        }

        private void WriteUInt16(byte[] data, int offset, ushort value)
        {
            var bytes = BitConverter.GetBytes(value);
            Buffer.BlockCopy(bytes, 0, data, offset, 2);
        }

        private PeLayout ReadPeLayout(byte[] image)
        {
            using var ms = new MemoryStream(image, false);
            using var br = new BinaryReader(ms, Encoding.UTF8, true);

            if (br.ReadUInt16() != 0x5A4D)
                throw new DevirtualizationException("Invalid DOS header.");

            ms.Position = 0x3C;
            var peOffset = br.ReadInt32();
            ms.Position = peOffset;
            if (br.ReadUInt32() != 0x00004550)
                throw new DevirtualizationException("Invalid PE signature.");

            _ = br.ReadUInt16(); // machine
            var numberOfSectionsOffset = checked((int) ms.Position);
            var numberOfSections = br.ReadUInt16();
            ms.Position += 12;
            var optionalHeaderSize = br.ReadUInt16();
            ms.Position += 2;

            var optionalHeaderStart = ms.Position;
            var magic = br.ReadUInt16();
            var isPe32Plus = magic == 0x20B;
            ms.Position = optionalHeaderStart + 32;
            var sectionAlignment = br.ReadUInt32();
            var fileAlignment = br.ReadUInt32();
            ms.Position = optionalHeaderStart + 56;
            _ = br.ReadUInt32(); // size of image
            var sizeOfImageOffset = checked((int) (optionalHeaderStart + 56));

            var dataDirectoryStart = optionalHeaderStart + (isPe32Plus ? 112 : 96);
            var clrDirectoryOffset = dataDirectoryStart + 14 * 8;
            ms.Position = clrDirectoryOffset;
            var clrRva = br.ReadUInt32();
            var clrHeaderFileOffset = clrRva == 0 ? 0 : RvaToOffsetForLayoutRead(ms, br, optionalHeaderStart, optionalHeaderSize, numberOfSections, clrRva);

            ms.Position = optionalHeaderStart + optionalHeaderSize;
            var sectionTableOffset = checked((int) ms.Position);

            var sections = new List<PeSection>(numberOfSections);
            for (var i = 0; i < numberOfSections; i++)
            {
                var sectionHeaderOffset = checked((int) ms.Position);
                var name = Encoding.ASCII.GetString(br.ReadBytes(8)).Trim('\0'); // name
                var virtualSize = br.ReadUInt32();
                var virtualAddress = br.ReadUInt32();
                var rawSize = br.ReadUInt32();
                var rawPointer = br.ReadUInt32();
                ms.Position += 16;

                sections.Add(new PeSection(name, sectionHeaderOffset, virtualAddress, virtualSize, rawPointer, rawSize));
            }

            return new PeLayout(
                sections,
                fileAlignment,
                sectionAlignment,
                sizeOfImageOffset,
                checked((int) clrHeaderFileOffset),
                sectionTableOffset,
                numberOfSectionsOffset);
        }

        private uint RvaToOffsetForLayoutRead(
            MemoryStream ms,
            BinaryReader br,
            long optionalHeaderStart,
            ushort optionalHeaderSize,
            ushort numberOfSections,
            uint rva)
        {
            var sectionTableStart = optionalHeaderStart + optionalHeaderSize;
            for (var i = 0; i < numberOfSections; i++)
            {
                ms.Position = sectionTableStart + i * 40;
                _ = br.ReadBytes(8);
                var virtualSize = br.ReadUInt32();
                var virtualAddress = br.ReadUInt32();
                var rawSize = br.ReadUInt32();
                var rawPointer = br.ReadUInt32();
                ms.Position += 16;

                var sectionSpan = Math.Max(virtualSize, rawSize);
                if (rva >= virtualAddress && rva < virtualAddress + sectionSpan)
                    return rawPointer + (rva - virtualAddress);
            }

            throw new DevirtualizationException($"Could not map RVA 0x{rva:X8} while reading PE layout.");
        }

        private sealed class PeLayout
        {
            public PeLayout(
                List<PeSection> sections,
                uint fileAlignment,
                uint sectionAlignment,
                int sizeOfImageOffset,
                int clrHeaderFileOffset,
                int sectionTableOffset,
                int numberOfSectionsOffset)
            {
                Sections = sections;
                FileAlignment = fileAlignment;
                SectionAlignment = sectionAlignment;
                SizeOfImageOffset = sizeOfImageOffset;
                ClrHeaderFileOffset = clrHeaderFileOffset;
                SectionTableOffset = sectionTableOffset;
                NumberOfSectionsOffset = numberOfSectionsOffset;
                SectionCount = sections.Count;
            }

            public List<PeSection> Sections { get; }
            public uint FileAlignment { get; }
            public uint SectionAlignment { get; }
            public int SizeOfImageOffset { get; }
            public int ClrHeaderFileOffset { get; }
            public int SectionTableOffset { get; }
            public int NumberOfSectionsOffset { get; }
            public int SectionCount { get; set; }
        }

        private sealed class PeSection
        {
            public PeSection(string name, int headerOffset, uint virtualAddress, uint virtualSize, uint rawPointer, uint rawSize)
            {
                Name = name;
                HeaderOffset = headerOffset;
                VirtualAddress = virtualAddress;
                VirtualSize = virtualSize;
                RawPointer = rawPointer;
                RawSize = rawSize;
            }

            public string Name { get; }
            public int HeaderOffset { get; }
            public uint VirtualAddress { get; }
            public uint VirtualSize { get; set; }
            public uint RawPointer { get; set; }
            public uint RawSize { get; set; }
        }

        private sealed class MethodDefTableInfo
        {
            public MethodDefTableInfo(int methodTableOffset, int methodRowSize)
            {
                MethodTableOffset = methodTableOffset;
                MethodRowSize = methodRowSize;
            }

            public int MethodTableOffset { get; }
            public int MethodRowSize { get; }
        }

        private sealed class MetadataTableInfo
        {
            public MetadataTableInfo(int tableOffset, int rowSize, uint rowCount, int blobIndexSize)
            {
                TableOffset = tableOffset;
                RowSize = rowSize;
                RowCount = rowCount;
                BlobIndexSize = blobIndexSize;
            }

            public int TableOffset { get; }
            public int RowSize { get; }
            public uint RowCount { get; }
            public int BlobIndexSize { get; }
        }

        private void NormalizeAssemblyIdentity(AsmResolver.DotNet.ModuleDefinition module)
        {
            module.IsStrongNameSigned = false;
            if (module.Assembly != null)
            {
                module.Assembly.PublicKey = null;
                module.Assembly.HasPublicKey = false;
            }
        }

        private int RepairInvalidTypeReferences(AsmResolver.DotNet.ModuleDefinition module, string sourcePath)
        {
            try
            {
                using var stream = File.OpenRead(sourcePath);
                using var pe = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
                var metadata = pe.GetMetadataReader();

                AsmResolver.DotNet.IResolutionScope fallbackScope = module;

                var repaired = 0;
                for (var rid = 1; rid <= metadata.TypeReferences.Count; rid++)
                {
                    var token = unchecked((int) (0x01000000u | (uint) rid));
                    AsmResolver.DotNet.ITypeDefOrRef member;
                    try
                    {
                        member = module.LookupMember(token) as AsmResolver.DotNet.ITypeDefOrRef;
                    }
                    catch
                    {
                        continue;
                    }

                    if (!(member is AsmResolver.DotNet.TypeReference typeRef))
                        continue;

                    var needsRepair = false;
                    try
                    {
                        _ = typeRef.Scope;
                    }
                    catch
                    {
                        needsRepair = true;
                    }

                    if (!needsRepair && typeRef.Scope != null)
                        continue;

                    try
                    {
                        var currentName = typeRef.Name?.ToString();
                        if (string.IsNullOrEmpty(currentName))
                            typeRef.Name = "Object";
                        if (ReferenceEquals(typeRef.Namespace, null))
                            typeRef.Namespace = string.Empty;
                        typeRef.Scope = fallbackScope;
                        repaired++;
                    }
                    catch
                    {
                        // Best effort repair only.
                    }
                }

                return repaired;
            }
            catch
            {
                return 0;
            }
        }

        private int SanitizeHashtableCapacityConstructors(AsmResolver.DotNet.ModuleDefinition module)
        {
            var patched = 0;
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    var body = method.CilMethodBody;
                    if (body == null)
                        continue;

                    for (var i = 0; i < body.Instructions.Count; i++)
                    {
                        var instruction = body.Instructions[i];
                        if (instruction.OpCode.Code != CilCode.Newobj ||
                            !(instruction.Operand is IMethodDescriptor descriptor))
                            continue;

                        if (!IsHashtableIntCapacityCtor(descriptor))
                            continue;

                        if (HasHashtableCapacityClamp(body, i))
                            continue;

                        var keepOriginalCapacity = new CilInstruction(CilOpCodes.Nop);
                        body.Instructions.Insert(i, new CilInstruction(CilOpCodes.Dup));
                        body.Instructions.Insert(i + 1, new CilInstruction(CilOpCodes.Ldc_I4_0));
                        body.Instructions.Insert(
                            i + 2,
                            new CilInstruction(CilOpCodes.Bge, new CilInstructionLabel(keepOriginalCapacity)));
                        body.Instructions.Insert(i + 3, new CilInstruction(CilOpCodes.Pop));
                        body.Instructions.Insert(i + 4, new CilInstruction(CilOpCodes.Ldc_I4_0));
                        body.Instructions.Insert(i + 5, keepOriginalCapacity);

                        i += 6;
                        patched++;
                    }
                }
            }

            return patched;
        }

        private bool HasHashtableCapacityClamp(CilMethodBody body, int newobjIndex)
        {
            if (newobjIndex < 6)
                return false;

            var first = body.Instructions[newobjIndex - 6];
            var second = body.Instructions[newobjIndex - 5];
            var third = body.Instructions[newobjIndex - 4];
            var fourth = body.Instructions[newobjIndex - 3];
            var fifth = body.Instructions[newobjIndex - 2];
            var target = body.Instructions[newobjIndex - 1];

            if (first.OpCode.Code != CilCode.Dup)
                return false;
            if (!IsLdcI4Zero(second))
                return false;
            if (third.OpCode.Code != CilCode.Bge && third.OpCode.Code != CilCode.Bge_S)
                return false;
            if (fourth.OpCode.Code != CilCode.Pop)
                return false;
            if (!IsLdcI4Zero(fifth))
                return false;
            if (!(third.Operand is CilInstructionLabel label))
                return false;

            return ReferenceEquals(label.Instruction, target);
        }

        private bool IsHashtableIntCapacityCtor(IMethodDescriptor descriptor)
        {
            if (descriptor == null)
                return false;

            AsmResolver.DotNet.MethodDefinition resolved = null;
            try
            {
                resolved = descriptor.Resolve();
            }
            catch
            {
                // Resolution may fail for malformed metadata. Fall back to signature checks only.
            }

            var declaringTypeFullName = descriptor.DeclaringType?.FullName ?? resolved?.DeclaringType?.FullName;
            if (!string.Equals(declaringTypeFullName, "System.Collections.Hashtable", StringComparison.Ordinal))
                return false;

            var signature = descriptor.Signature ?? resolved?.Signature;
            return signature?.ParameterTypes.Count == 1 &&
                   string.Equals(signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal);
        }

        private bool IsLdcI4Zero(CilInstruction instruction)
        {
            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldc_I4_0:
                    return true;
                case CilCode.Ldc_I4:
                    return instruction.Operand is int fullInt && fullInt == 0;
                case CilCode.Ldc_I4_S:
                    return instruction.Operand is sbyte shortInt && shortInt == 0;
                default:
                    return false;
            }
        }

        private bool GetFeatureToggle(string enableVariableName, bool defaultEnabled, string disableVariableName = null)
        {
            if (!string.IsNullOrWhiteSpace(disableVariableName) &&
                TryGetEnvironmentToggle(disableVariableName, out var isDisabled) &&
                isDisabled)
            {
                return false;
            }

            if (TryGetEnvironmentToggle(enableVariableName, out var isEnabled))
                return isEnabled;

            return defaultEnabled;
        }

        private bool TryGetEnvironmentToggle(string variableName, out bool value)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
            {
                value = false;
                return false;
            }

            raw = raw.Trim();
            if (string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase))
            {
                value = true;
                return true;
            }

            if (string.Equals(raw, "0", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(raw, "false", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(raw, "no", StringComparison.OrdinalIgnoreCase))
            {
                value = false;
                return true;
            }

            value = false;
            return false;
        }

        private int BypassWindowsFormsEntryGuards(AsmResolver.DotNet.ModuleDefinition module)
        {
            var patched = 0;
            foreach (var type in module.GetAllTypes())
            {
                if (!IsWindowsFormsFormType(type))
                    continue;

                foreach (var method in type.Methods)
                {
                    if (method.CilMethodBody == null)
                        continue;
                    if (!TryPatchLeadingBooleanGuard(method.CilMethodBody))
                        continue;

                    patched++;
                }
            }

            return patched;
        }

        private bool IsWindowsFormsFormType(AsmResolver.DotNet.TypeDefinition type)
        {
            var depth = 0;
            var current = type;
            while (current != null && depth++ < 16)
            {
                var baseType = current.BaseType;
                if (baseType == null)
                    return false;
                if (string.Equals(baseType.FullName, "System.Windows.Forms.Form", StringComparison.Ordinal))
                    return true;

                current = baseType.Resolve();
            }

            return false;
        }

        private bool TryPatchLeadingBooleanGuard(CilMethodBody body)
        {
            if (body.Instructions.Count < 3)
                return false;

            var first = body.Instructions[0];
            var second = body.Instructions[1];
            var third = body.Instructions[2];
            if (!IsLdcI4(first))
                return false;
            if (!IsInt32ToBooleanCall(second))
                return false;
            if (third.OpCode.Code != CilCode.Brfalse && third.OpCode.Code != CilCode.Brfalse_S)
                return false;
            if (!(third.Operand is CilInstructionLabel target) || target.Instruction == null ||
                target.Instruction.OpCode.Code != CilCode.Ret)
                return false;

            body.Instructions[0] = new CilInstruction(CilOpCodes.Nop);
            body.Instructions[1] = new CilInstruction(CilOpCodes.Ldc_I4_1);
            return true;
        }

        private bool IsLdcI4(CilInstruction instruction)
        {
            switch (instruction.OpCode.Code)
            {
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
                case CilCode.Ldc_I4:
                    return true;
                default:
                    return false;
            }
        }

        private bool IsInt32ToBooleanCall(CilInstruction instruction)
        {
            if (instruction.OpCode.Code != CilCode.Call && instruction.OpCode.Code != CilCode.Callvirt)
                return false;
            if (!(instruction.Operand is IMethodDescriptor descriptor))
                return false;

            var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
            return signature != null &&
                   string.Equals(signature.ReturnType?.FullName, "System.Boolean", StringComparison.Ordinal) &&
                   signature.ParameterTypes.Count == 1 &&
                   string.Equals(signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal);
        }

        private int NeutralizeStrictMarkerGuards(
            AsmResolver.DotNet.ModuleDefinition module,
            IReadOnlyCollection<string> markerStrings,
            bool requireDebuggerSignal)
        {
            if (module == null || markerStrings == null || markerStrings.Count == 0)
                return 0;

            var patched = 0;
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!LooksLikeStrictMarkerGuard(method, markerStrings, requireDebuggerSignal))
                        continue;
                    if (!TryReplaceWithRetOnlyStub(method))
                        continue;

                    patched++;
                }
            }

            return patched;
        }

        private bool LooksLikeStrictMarkerGuard(
            AsmResolver.DotNet.MethodDefinition method,
            IReadOnlyCollection<string> markerStrings,
            bool requireDebuggerSignal)
        {
            if (method?.CilMethodBody == null || !method.IsStatic)
                return false;
            if (string.Equals(method.Name, ".cctor", StringComparison.Ordinal))
                return false;

            var signature = method.Signature;
            if (signature == null)
                return false;
            if (!string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
                return false;
            if (signature.ParameterTypes.Count != 0)
                return false;

            var body = method.CilMethodBody;
            if (body.Instructions.Count == 0 || body.Instructions.Count > 4096)
                return false;

            var hasMarker = false;
            var hasDebuggerApi = false;
            var hasTerminationApi = false;
            var hasThrow = false;

            foreach (var instruction in body.Instructions)
            {
                if (!hasMarker &&
                    instruction.OpCode.Code == CilCode.Ldstr &&
                    instruction.Operand != null &&
                    ContainsAnyToken(SafeStringify(instruction.Operand), markerStrings))
                {
                    hasMarker = true;
                }

                if (instruction.OpCode.Code == CilCode.Call || instruction.OpCode.Code == CilCode.Callvirt)
                {
                    var methodIdentity = GetMethodIdentity(instruction.Operand as IMethodDescriptor);
                    if (!hasDebuggerApi && ContainsAnyToken(methodIdentity, DebuggerApiMarkers))
                        hasDebuggerApi = true;
                    if (!hasTerminationApi && ContainsAnyToken(methodIdentity, TerminationApiMarkers))
                        hasTerminationApi = true;
                }

                if (!hasThrow &&
                    (instruction.OpCode.Code == CilCode.Throw || instruction.OpCode.Code == CilCode.Rethrow))
                {
                    hasThrow = true;
                }

                if (hasMarker &&
                    (hasDebuggerApi || hasTerminationApi || hasThrow) &&
                    (!requireDebuggerSignal || hasDebuggerApi))
                {
                    return true;
                }
            }

            return false;
        }

        private bool TryReplaceWithRetOnlyStub(AsmResolver.DotNet.MethodDefinition method)
        {
            var signature = method?.Signature;
            if (signature == null)
                return false;
            if (!string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
                return false;
            if (signature.ParameterTypes.Count != 0)
                return false;

            var replacement = new CilMethodBody(method)
            {
                InitializeLocals = false,
                ComputeMaxStackOnBuild = true,
                MaxStack = 1
            };
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
            method.CilMethodBody = replacement;
            return true;
        }

        private int DeobfuscateTokenResolverCalls(AsmResolver.DotNet.ModuleDefinition module)
        {
            if (module == null)
                return 0;

            var resolverMethods = FindTokenResolverMethods(module);
            if (resolverMethods == null)
                return 0;

            var patched = 0;
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    var body = method.CilMethodBody;
                    if (body == null || body.Instructions.Count < 2)
                        continue;

                    for (var i = 0; i < body.Instructions.Count - 1; i++)
                    {
                        if (!TryGetLdcI4Value(body.Instructions[i], out var token))
                            continue;

                        var call = body.Instructions[i + 1];
                        if (call.OpCode.Code != CilCode.Call && call.OpCode.Code != CilCode.Callvirt)
                            continue;
                        if (!(call.Operand is IMethodDescriptor calledDescriptor))
                            continue;

                        AsmResolver.DotNet.MethodDefinition calledMethod;
                        try
                        {
                            calledMethod = calledDescriptor.Resolve();
                        }
                        catch
                        {
                            continue;
                        }

                        if (calledMethod == null)
                            continue;

                        var expectsTypeToken = false;
                        if (ReferenceEquals(calledMethod, resolverMethods.TypeResolver))
                        {
                            expectsTypeToken = true;
                        }
                        else if (!ReferenceEquals(calledMethod, resolverMethods.FieldResolver))
                        {
                            continue;
                        }

                        if (!TryResolveLdtokenOperand(module, token, expectsTypeToken, out var ldtokenOperand))
                            continue;

                        body.Instructions[i].OpCode = CilOpCodes.Nop;
                        body.Instructions[i].Operand = null;
                        body.Instructions[i + 1].OpCode = CilOpCodes.Ldtoken;
                        body.Instructions[i + 1].Operand = ldtokenOperand;
                        patched++;
                        i++;
                    }
                }
            }

            return patched;
        }

        private TokenResolverMethods FindTokenResolverMethods(AsmResolver.DotNet.ModuleDefinition module)
        {
            foreach (var type in module.GetAllTypes())
            {
                var hasModuleHandleField = type.Fields.Any(field =>
                {
                    var fieldTypeName = field.Signature?.FieldType?.FullName;
                    return string.Equals(fieldTypeName, "System.ModuleHandle", StringComparison.Ordinal);
                });
                if (!hasModuleHandleField)
                    continue;

                AsmResolver.DotNet.MethodDefinition typeResolver = null;
                AsmResolver.DotNet.MethodDefinition fieldResolver = null;

                foreach (var method in type.Methods)
                {
                    var signature = method.Signature;
                    if (signature == null || signature.ParameterTypes.Count != 1)
                        continue;
                    if (!string.Equals(signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal))
                        continue;

                    var returnTypeName = signature.ReturnType?.FullName;
                    if (string.Equals(returnTypeName, "System.RuntimeTypeHandle", StringComparison.Ordinal))
                        typeResolver = method;
                    else if (string.Equals(returnTypeName, "System.RuntimeFieldHandle", StringComparison.Ordinal))
                        fieldResolver = method;
                }

                if (typeResolver != null && fieldResolver != null)
                    return new TokenResolverMethods(typeResolver, fieldResolver);
            }

            return null;
        }

        private bool TryGetLdcI4Value(CilInstruction instruction, out int value)
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
                case CilCode.Ldc_I4_S:
                    if (instruction.Operand is sbyte signedByte)
                    {
                        value = signedByte;
                        return true;
                    }

                    if (instruction.Operand is byte unsignedByte)
                    {
                        value = (sbyte) unsignedByte;
                        return true;
                    }

                    if (instruction.Operand is int intValueS)
                    {
                        value = intValueS;
                        return true;
                    }

                    return false;
                case CilCode.Ldc_I4:
                    if (instruction.Operand is int intValue)
                    {
                        value = intValue;
                        return true;
                    }

                    if (instruction.Operand is uint uintValue)
                    {
                        value = unchecked((int) uintValue);
                        return true;
                    }

                    return false;
                default:
                    return false;
            }
        }

        private bool TryResolveLdtokenOperand(
            AsmResolver.DotNet.ModuleDefinition module,
            int token,
            bool expectTypeToken,
            out object operand)
        {
            operand = null;
            if (module == null || token <= 0)
                return false;

            object member;
            try
            {
                member = module.LookupMember(token);
            }
            catch
            {
                return false;
            }

            if (member == null)
                return false;

            if (expectTypeToken)
            {
                if (member is AsmResolver.DotNet.ITypeDefOrRef typeDefOrRef)
                {
                    operand = typeDefOrRef;
                    return true;
                }

                if (member is AsmResolver.DotNet.ITypeDescriptor typeDescriptor)
                {
                    operand = typeDescriptor;
                    return true;
                }

                return false;
            }

            if (member is IFieldDescriptor fieldDescriptor)
            {
                operand = fieldDescriptor;
                return true;
            }

            return false;
        }

        private sealed class TokenResolverMethods
        {
            public TokenResolverMethods(
                AsmResolver.DotNet.MethodDefinition typeResolver,
                AsmResolver.DotNet.MethodDefinition fieldResolver)
            {
                TypeResolver = typeResolver;
                FieldResolver = fieldResolver;
            }

            public AsmResolver.DotNet.MethodDefinition TypeResolver { get; }
            public AsmResolver.DotNet.MethodDefinition FieldResolver { get; }
        }

        private int NeutralizeStringSignatureAntiManipulationMethods(AsmResolver.DotNet.ModuleDefinition module)
        {
            var patched = 0;
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!LooksLikeAntiManipulationMethod(method))
                        continue;
                    if (!TryReplaceWithSafeReturnStub(method))
                        continue;

                    patched++;
                }
            }

            return patched;
        }

        private bool LooksLikeAntiManipulationMethod(AsmResolver.DotNet.MethodDefinition method)
        {
            if (method?.CilMethodBody == null || !method.IsStatic)
                return false;
            if (string.Equals(method.Name, ".cctor", StringComparison.Ordinal))
                return false;

            var signature = method.Signature;
            var returnTypeName = signature?.ReturnType?.FullName;
            if (string.IsNullOrEmpty(returnTypeName))
                return false;
            if (returnTypeName.EndsWith("&", StringComparison.Ordinal))
                return false;

            var body = method.CilMethodBody;
            if (body.Instructions.Count == 0)
                return false;
            if (body.Instructions.Count > 1024)
                return false;

            var hasMarkerString = false;
            var hasDebuggerApi = false;
            var hasTerminationApi = false;
            foreach (var instruction in body.Instructions)
            {
                if (instruction.OpCode.Code == CilCode.Ldstr &&
                    instruction.Operand != null &&
                    ContainsAnyToken(SafeStringify(instruction.Operand), AntiManipulationStringMarkers))
                {
                    hasMarkerString = true;
                }

                if (instruction.OpCode.Code == CilCode.Call || instruction.OpCode.Code == CilCode.Callvirt)
                {
                    var methodIdentity = GetMethodIdentity(instruction.Operand as IMethodDescriptor);
                    if (!hasDebuggerApi && ContainsAnyToken(methodIdentity, DebuggerApiMarkers))
                        hasDebuggerApi = true;
                    if (!hasTerminationApi && ContainsAnyToken(methodIdentity, TerminationApiMarkers))
                        hasTerminationApi = true;
                }

                if (hasMarkerString || (hasDebuggerApi && hasTerminationApi))
                    break;
            }

            if (hasMarkerString)
                return true;

            if (!hasDebuggerApi || !hasTerminationApi)
                return false;

            return string.Equals(returnTypeName, "System.Void", StringComparison.Ordinal) ||
                   string.Equals(returnTypeName, "System.Boolean", StringComparison.Ordinal) ||
                   string.Equals(returnTypeName, "System.Int32", StringComparison.Ordinal);
        }

        private bool TryReplaceWithSafeReturnStub(AsmResolver.DotNet.MethodDefinition method)
        {
            var signature = method?.Signature;
            if (signature == null)
                return false;

            var returnType = signature.ReturnType;
            if (returnType?.FullName != null && returnType.FullName.EndsWith("&", StringComparison.Ordinal))
                return false;

            var replacement = new CilMethodBody(method)
            {
                InitializeLocals = true,
                ComputeMaxStackOnBuild = true,
                MaxStack = 1
            };

            if (!string.Equals(returnType?.FullName, "System.Void", StringComparison.Ordinal))
            {
                replacement.LocalVariables.Add(new CilLocalVariable(returnType));
                replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc_0));
            }

            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
            method.CilMethodBody = replacement;
            return true;
        }

        private int NeutralizeTamperedExceptionThrowers(AsmResolver.DotNet.ModuleDefinition module)
        {
            if (module == null)
                return 0;

            var patched = 0;
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!LooksLikeTamperedExceptionThrower(method))
                        continue;
                    if (!TryReplaceWithSafeReturnStub(method))
                        continue;
                    patched++;
                }
            }

            return patched;
        }

        private bool LooksLikeTamperedExceptionThrower(AsmResolver.DotNet.MethodDefinition method)
        {
            var body = method?.CilMethodBody;
            if (body == null)
                return false;
            if (body.Instructions.Count == 0 || body.Instructions.Count > 8192)
                return false;

            var hasTamperMarker = false;
            var hasThrow = false;
            var hasExceptionCtor = false;

            foreach (var instruction in body.Instructions)
            {
                if (!hasTamperMarker &&
                    instruction.OpCode.Code == CilCode.Ldstr &&
                    instruction.Operand != null &&
                    ContainsAnyToken(SafeStringify(instruction.Operand), AntiManipulationStringMarkers))
                {
                    hasTamperMarker = true;
                }

                if (!hasThrow &&
                    (instruction.OpCode.Code == CilCode.Throw || instruction.OpCode.Code == CilCode.Rethrow))
                {
                    hasThrow = true;
                }

                if (!hasExceptionCtor &&
                    instruction.OpCode.Code == CilCode.Newobj &&
                    instruction.Operand is IMethodDescriptor ctor &&
                    IsExceptionConstructor(ctor))
                {
                    hasExceptionCtor = true;
                }

                if (hasTamperMarker && hasThrow && hasExceptionCtor)
                    return true;
            }

            return false;
        }

        private bool IsExceptionConstructor(IMethodDescriptor descriptor)
        {
            if (descriptor == null)
                return false;

            var identity = GetMethodIdentity(descriptor);
            if (identity.IndexOf("Exception::.ctor", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;

            var declaringTypeName = SafeStringify(descriptor.DeclaringType?.FullName);
            if (declaringTypeName.EndsWith("Exception", StringComparison.OrdinalIgnoreCase))
                return true;

            try
            {
                var resolved = descriptor.Resolve();
                var resolvedDeclaringTypeName = SafeStringify(resolved?.DeclaringType?.FullName);
                return resolvedDeclaringTypeName.EndsWith("Exception", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private int NeutralizeStartupAntiTamperGuards(AsmResolver.DotNet.ModuleDefinition module)
        {
            if (module == null)
                return 0;

            var roots = module
                .GetAllTypes()
                .SelectMany(t => t.Methods)
                .Where(m => m != null &&
                            m.IsStatic &&
                            string.Equals(m.Name, ".cctor", StringComparison.Ordinal) &&
                            m.CilMethodBody != null)
                .ToList();
            if (roots.Count == 0)
                return 0;

            var reachable = CollectMethodsReachableFromConstructors(roots, maxDepth: 3);
            var patched = 0;

            foreach (var method in reachable)
            {
                if (method == null || method.CilMethodBody == null)
                    continue;
                if (!LooksLikeStartupAntiTamperGuard(method))
                    continue;
                if (!TryReplaceWithSafeReturnStub(method))
                    continue;

                patched++;
            }

            return patched;
        }

        private HashSet<AsmResolver.DotNet.MethodDefinition> CollectMethodsReachableFromConstructors(
            IReadOnlyCollection<AsmResolver.DotNet.MethodDefinition> roots,
            int maxDepth)
        {
            var reachable = new HashSet<AsmResolver.DotNet.MethodDefinition>();
            var queue = new Queue<(AsmResolver.DotNet.MethodDefinition method, int depth)>();

            foreach (var root in roots)
                queue.Enqueue((root, 0));

            while (queue.Count > 0)
            {
                var (method, depth) = queue.Dequeue();
                if (method?.CilMethodBody == null)
                    continue;
                if (depth >= maxDepth)
                    continue;

                foreach (var instruction in method.CilMethodBody.Instructions)
                {
                    if (instruction.OpCode.Code != CilCode.Call && instruction.OpCode.Code != CilCode.Callvirt)
                        continue;
                    if (!(instruction.Operand is IMethodDescriptor calleeDescriptor))
                        continue;

                    AsmResolver.DotNet.MethodDefinition callee;
                    try
                    {
                        callee = calleeDescriptor.Resolve();
                    }
                    catch
                    {
                        continue;
                    }

                    if (callee?.CilMethodBody == null)
                        continue;
                    if (!reachable.Add(callee))
                        continue;

                    queue.Enqueue((callee, depth + 1));
                }
            }

            return reachable;
        }

        private bool LooksLikeStartupAntiTamperGuard(AsmResolver.DotNet.MethodDefinition method)
        {
            if (method?.CilMethodBody == null || !method.IsStatic)
                return false;
            if (string.Equals(method.Name, ".cctor", StringComparison.Ordinal))
                return false;

            var signature = method.Signature;
            var returnTypeName = signature?.ReturnType?.FullName;
            if (string.IsNullOrEmpty(returnTypeName))
                return false;
            if (returnTypeName.EndsWith("&", StringComparison.Ordinal))
                return false;
            if (method.CilMethodBody.Instructions.Count == 0 || method.CilMethodBody.Instructions.Count > 32768)
                return false;

            var hasThrow = false;
            var hasExceptionCtor = false;
            var hasMarkerString = false;
            var hasDebuggerApi = false;
            var hasTerminationApi = false;
            var hasSecurityApi = false;

            foreach (var instruction in method.CilMethodBody.Instructions)
            {
                if (!hasThrow &&
                    (instruction.OpCode.Code == CilCode.Throw || instruction.OpCode.Code == CilCode.Rethrow))
                {
                    hasThrow = true;
                }

                if (!hasMarkerString &&
                    instruction.OpCode.Code == CilCode.Ldstr &&
                    instruction.Operand != null &&
                    ContainsAnyToken(SafeStringify(instruction.Operand), AntiManipulationStringMarkers))
                {
                    hasMarkerString = true;
                }

                if (instruction.OpCode.Code == CilCode.Newobj &&
                    instruction.Operand is IMethodDescriptor ctorDescriptor &&
                    IsExceptionConstructor(ctorDescriptor))
                {
                    hasExceptionCtor = true;
                }

                if (instruction.OpCode.Code == CilCode.Call || instruction.OpCode.Code == CilCode.Callvirt)
                {
                    var methodIdentity = GetMethodIdentity(instruction.Operand as IMethodDescriptor);
                    if (!hasDebuggerApi && ContainsAnyToken(methodIdentity, DebuggerApiMarkers))
                        hasDebuggerApi = true;
                    if (!hasTerminationApi && ContainsAnyToken(methodIdentity, TerminationApiMarkers))
                        hasTerminationApi = true;
                    if (!hasSecurityApi && LooksLikeSecurityIntegrityApi(methodIdentity))
                        hasSecurityApi = true;
                }

                if (hasThrow && hasExceptionCtor &&
                    (hasMarkerString || hasDebuggerApi || hasTerminationApi || hasSecurityApi))
                {
                    return true;
                }
            }

            return false;
        }

        private bool LooksLikeSecurityIntegrityApi(string methodIdentity)
        {
            if (string.IsNullOrEmpty(methodIdentity))
                return false;

            return methodIdentity.IndexOf("System.Security", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   methodIdentity.IndexOf("RSACryptoServiceProvider", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   methodIdentity.IndexOf("SHA1", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   methodIdentity.IndexOf("Crypto", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   methodIdentity.IndexOf("GetManifestResource", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   methodIdentity.IndexOf("System.Reflection.Assembly", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   methodIdentity.IndexOf("StrongName", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   methodIdentity.IndexOf("File::Exists", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool ContainsAnyToken(string value, IEnumerable<string> tokens)
        {
            if (string.IsNullOrEmpty(value))
                return false;

            foreach (var token in tokens)
            {
                if (string.IsNullOrWhiteSpace(token))
                    continue;
                if (value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        private string GetMethodIdentity(IMethodDescriptor descriptor)
        {
            if (descriptor == null)
                return string.Empty;

            AsmResolver.DotNet.MethodDefinition resolved = null;
            try
            {
                resolved = descriptor.Resolve();
            }
            catch
            {
                // Malformed metadata can fail resolution; fallback below still provides useful identity.
            }

            var declaringTypeName = SafeStringify(descriptor.DeclaringType?.FullName);
            if (string.IsNullOrEmpty(declaringTypeName))
                declaringTypeName = SafeStringify(resolved?.DeclaringType?.FullName);

            var methodName = SafeStringify(descriptor.Name);
            if (string.IsNullOrEmpty(methodName))
                methodName = SafeStringify(resolved?.Name);

            return declaringTypeName + "::" + methodName;
        }

        private string SafeStringify(object value)
        {
            if (value == null)
                return string.Empty;

            try
            {
                return value.ToString() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private IEnumerable<AsmResolver.DotNet.TypeDefinition> GetBootstrapCandidateTypes(
            IEnumerable<Core.Architecture.VMMethod> methodsToPatch)
        {
            var candidates = new HashSet<AsmResolver.DotNet.TypeDefinition>();

            var entryType = Ctx.Module.ManagedEntryPointMethod?.DeclaringType;
            if (entryType != null)
                candidates.Add(entryType);

            var entryPoint = Ctx.Module.ManagedEntryPointMethod;
            if (entryPoint?.CilMethodBody != null)
            {
                foreach (var instruction in entryPoint.CilMethodBody.Instructions)
                {
                    if (instruction.OpCode.Code != CilCode.Call && instruction.OpCode.Code != CilCode.Callvirt)
                        continue;
                    if (!(instruction.Operand is IMethodDescriptor callee))
                        continue;

                    var calleeType = callee.Resolve()?.DeclaringType;
                    if (calleeType != null)
                        candidates.Add(calleeType);
                }
            }

            var moduleType = Ctx.Module.GetAllTypes().FirstOrDefault(t =>
                string.Equals(t.Name, "<Module>", StringComparison.Ordinal));
            if (moduleType != null)
                candidates.Add(moduleType);

            foreach (var vmMethod in methodsToPatch)
            {
                var declaringType = vmMethod.Parent?.DeclaringType;
                if (declaringType != null)
                    candidates.Add(declaringType);
            }

            return candidates;
        }

        private int NeutralizeSharedBootstrapMethods(AsmResolver.DotNet.ModuleDefinition module)
        {
            var callCounts = new Dictionary<AsmResolver.DotNet.MethodDefinition, int>();

            foreach (var type in module.GetAllTypes())
            {
                var cctor = type.Methods.FirstOrDefault(m =>
                    m.Name == ".cctor" && m.IsStatic && m.CilMethodBody != null);
                if (cctor?.CilMethodBody == null)
                    continue;

                var instructions = cctor.CilMethodBody.Instructions;
                if (instructions.Count < 1 || instructions.Count > 8)
                    continue;

                var firstCall = instructions.FirstOrDefault(i =>
                    i.OpCode.Code == CilCode.Call || i.OpCode.Code == CilCode.Callvirt);
                var callee = firstCall?.Operand as IMethodDescriptor;
                if (callee == null)
                    continue;

                AsmResolver.DotNet.MethodDefinition calleeDef;
                try
                {
                    calleeDef = callee.Resolve();
                }
                catch
                {
                    continue;
                }

                if (calleeDef?.CilMethodBody == null)
                    continue;
                if (!string.Equals(calleeDef.Signature?.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
                    continue;
                if (calleeDef.Signature.ParameterTypes.Count != 0)
                    continue;
                if (!LooksLikeSharedBootstrapWorker(calleeDef))
                    continue;

                if (!callCounts.TryGetValue(calleeDef, out var count))
                    count = 0;
                callCounts[calleeDef] = count + 1;
            }

            var patched = 0;
            foreach (var kv in callCounts.Where(kv => kv.Value >= 3))
            {
                var method = kv.Key;
                if (method.CilMethodBody == null)
                    continue;

                var replacement = new CilMethodBody(method)
                {
                    InitializeLocals = false,
                    ComputeMaxStackOnBuild = true,
                    MaxStack = 1
                };
                replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
                method.CilMethodBody = replacement;
                patched++;
            }

            return patched;
        }

        private bool LooksLikeSharedBootstrapWorker(AsmResolver.DotNet.MethodDefinition method)
        {
            var body = method.CilMethodBody;
            if (body == null)
                return false;

            var largeAndObfuscated =
                body.Instructions.Count >= 500 ||
                body.LocalVariables.Count >= 64 ||
                body.ExceptionHandlers.Count >= 8;
            if (!largeAndObfuscated)
                return false;

            return ContainsHashtableCapacityCtor(body);
        }

        private bool ContainsHashtableCapacityCtor(CilMethodBody body)
        {
            foreach (var instruction in body.Instructions)
            {
                if (instruction.OpCode.Code != CilCode.Newobj ||
                    !(instruction.Operand is IMethodDescriptor descriptor))
                    continue;

                if (IsHashtableIntCapacityCtor(descriptor))
                    return true;
            }

            return false;
        }

        private int DisableBootstrapTypeInitializers(
            AsmResolver.DotNet.ModuleDefinition module,
            IEnumerable<AsmResolver.DotNet.TypeDefinition> candidateTypes)
        {
            var patched = 0;
            foreach (var type in candidateTypes)
            {
                var cctor = type.Methods.FirstOrDefault(m =>
                    m.Name == ".cctor" && m.IsStatic && m.CilMethodBody != null);
                if (cctor?.CilMethodBody == null)
                    continue;
                if (!LooksLikeBootstrapTypeInitializer(cctor))
                    continue;

                var replacement = new CilMethodBody(cctor)
                {
                    InitializeLocals = false,
                    ComputeMaxStackOnBuild = true,
                    MaxStack = 1
                };
                replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
                cctor.CilMethodBody = replacement;
                patched++;
            }

            return patched;
        }

        private bool LooksLikeBootstrapTypeInitializer(AsmResolver.DotNet.MethodDefinition cctor)
        {
            var instructions = cctor.CilMethodBody.Instructions;
            if (instructions.Count < 1 || instructions.Count > 3)
                return false;

            var first = instructions[0];
            if (first.OpCode.Code != CilCode.Call && first.OpCode.Code != CilCode.Callvirt)
                return false;

            if (!(first.Operand is IMethodDescriptor callee))
                return false;

            var calleeDef = callee.Resolve();
            var calleeBody = calleeDef?.CilMethodBody;
            if (calleeBody == null)
                return false;

            // Generic heuristic for protector bootstrap stubs:
            // tiny .cctor -> one call -> huge obfuscated bootstrap method.
            return calleeBody.Instructions.Count >= 500 ||
                   calleeBody.LocalVariables.Count >= 64 ||
                   calleeBody.ExceptionHandlers.Count >= 8;
        }

        private int StripMalformedCustomAttributes(AsmResolver.DotNet.ModuleDefinition module)
        {
            var removed = 0;

            removed += RemoveMalformedAttributes(module);

            if (module.Assembly != null)
                removed += RemoveMalformedAttributes(module.Assembly);

            foreach (var type in module.GetAllTypes())
            {
                removed += RemoveMalformedAttributes(type);

                foreach (var genericParameter in type.GenericParameters)
                    removed += RemoveMalformedAttributes(genericParameter);

                foreach (var field in type.Fields)
                {
                    removed += RemoveMalformedAttributes(field);
                }

                foreach (var method in type.Methods)
                {
                    removed += RemoveMalformedAttributes(method);

                    foreach (var parameter in method.ParameterDefinitions)
                        removed += RemoveMalformedAttributes(parameter);

                    foreach (var genericParameter in method.GenericParameters)
                        removed += RemoveMalformedAttributes(genericParameter);
                }

                foreach (var property in type.Properties)
                {
                    removed += RemoveMalformedAttributes(property);
                }

                foreach (var evt in type.Events)
                {
                    removed += RemoveMalformedAttributes(evt);
                }
            }

            return removed;
        }

        private int ClearAllCustomAttributes(AsmResolver.DotNet.ModuleDefinition module)
        {
            var removed = 0;

            removed += ClearAttributes(module);

            if (module.Assembly != null)
                removed += ClearAttributes(module.Assembly);

            foreach (var type in module.GetAllTypes())
            {
                removed += ClearAttributes(type);

                foreach (var genericParameter in type.GenericParameters)
                    removed += ClearAttributes(genericParameter);

                foreach (var field in type.Fields)
                {
                    removed += ClearAttributes(field);
                }

                foreach (var method in type.Methods)
                {
                    removed += ClearAttributes(method);

                    foreach (var parameter in method.ParameterDefinitions)
                        removed += ClearAttributes(parameter);

                    foreach (var genericParameter in method.GenericParameters)
                        removed += ClearAttributes(genericParameter);
                }

                foreach (var property in type.Properties)
                {
                    removed += ClearAttributes(property);
                }

                foreach (var evt in type.Events)
                {
                    removed += ClearAttributes(evt);
                }
            }

            return removed;
        }

        private int RemoveMalformedAttributes(AsmResolver.DotNet.IHasCustomAttribute provider)
        {
            if (provider == null || provider.CustomAttributes == null || provider.CustomAttributes.Count == 0)
                return 0;

            // AsmResolver crashes on some malformed custom attribute blobs in this challenge family.
            // Keep this aggressive for method/field/parameter scopes where obfuscators inject unstable data.
            if (provider is AsmResolver.DotNet.FieldDefinition ||
                provider is AsmResolver.DotNet.MethodDefinition ||
                provider is ParameterDefinition)
            {
                var all = provider.CustomAttributes.Count;
                provider.CustomAttributes.Clear();
                return all;
            }

            var removed = 0;
            for (var i = provider.CustomAttributes.Count - 1; i >= 0; i--)
            {
                if (!ShouldRemoveCustomAttribute(provider.CustomAttributes[i]))
                    continue;

                provider.CustomAttributes.RemoveAt(i);
                removed++;
            }

            return removed;
        }

        private bool ShouldRemoveCustomAttribute(AsmResolver.DotNet.CustomAttribute attribute)
        {
            try
            {
                return IsMalformedCustomAttribute(attribute);
            }
            catch
            {
                return true;
            }
        }

        private int ClearAttributes(AsmResolver.DotNet.IHasCustomAttribute provider)
        {
            if (provider == null || provider.CustomAttributes == null || provider.CustomAttributes.Count == 0)
                return 0;

            var count = provider.CustomAttributes.Count;
            provider.CustomAttributes.Clear();
            return count;
        }

        private bool IsMalformedCustomAttribute(AsmResolver.DotNet.CustomAttribute attribute)
        {
            if (attribute == null || attribute.Constructor == null || attribute.Signature == null)
                return true;

            foreach (var fixedArg in attribute.Signature.FixedArguments)
            {
                if (fixedArg == null || fixedArg.ArgumentType == null)
                    return true;
            }

            foreach (var namedArg in attribute.Signature.NamedArguments)
            {
                if (namedArg == null || namedArg.ArgumentType == null || namedArg.Argument == null ||
                    namedArg.Argument.ArgumentType == null)
                    return true;
            }

            return false;
        }

        private void ClearInvalidStrongNameFlag(string path)
        {
            byte[] image;
            try
            {
                image = File.ReadAllBytes(path);
            }
            catch
            {
                return;
            }

            try
            {
                var layout = ReadPeLayout(image);
                if (layout.ClrHeaderFileOffset <= 0 || layout.ClrHeaderFileOffset + 40 > image.Length)
                    return;

                // Clear COMIMAGE_FLAGS_STRONGNAMESIGNED in IMAGE_COR20_HEADER::Flags.
                var corFlagsOffset = layout.ClrHeaderFileOffset + 16;
                var corFlags = ReadUInt32(image, corFlagsOffset);
                WriteUInt32(image, corFlagsOffset, corFlags & ~0x8U);

                // Clear IMAGE_COR20_HEADER::StrongNameSignature directory RVA/Size.
                var strongNameDirectoryOffset = layout.ClrHeaderFileOffset + 32;
                WriteUInt32(image, strongNameDirectoryOffset, 0);
                WriteUInt32(image, strongNameDirectoryOffset + 4, 0);

                // Clear Assembly table HasPublicKey bit and zero PublicKey blob index.
                var assemblyTable = GetAssemblyTableInfo(image, layout);
                if (assemblyTable.RowCount > 0)
                {
                    var rowOffset = assemblyTable.TableOffset;
                    var assemblyFlagsOffset = rowOffset + 12;
                    var assemblyFlags = ReadUInt32(image, assemblyFlagsOffset);
                    WriteUInt32(image, assemblyFlagsOffset, assemblyFlags & ~0x1U);

                    var publicKeyIndexOffset = rowOffset + 16;
                    if (assemblyTable.BlobIndexSize == 2)
                        WriteUInt16(image, publicKeyIndexOffset, 0);
                    else
                        WriteUInt32(image, publicKeyIndexOffset, 0);
                }

                File.WriteAllBytes(path, image);
            }
            catch
            {
                // Best-effort cleanup only.
            }
        }

        private string FormatInstruction(Core.Architecture.VMInstruction instruction)
        {
            var line = instruction.ToString();
            if (instruction.Operand is int[] intArray)
            {
                var preview = string.Join(", ", intArray.Take(24));
                if (intArray.Length > 24)
                    preview += ", ...";
                return line + $" // targets[{intArray.Length}]: {preview}";
            }

            if (!(instruction.Operand is int))
                return line;

            var token = (int) instruction.Operand;
            if (token <= 0)
                return line;

            try
            {
                var member = Ctx.Module.LookupMember(token);
                if (member != null)
                    line += $" // {member}";
            }
            catch
            {
                // Non-metadata operands (or transformed tokens) are expected for many VM instructions.
            }

            return line;
        }

        private IEnumerable<string> GetHandlerSnippet(int vmByte)
        {
            if (Ctx.OpcodeHandlerMethod == null || Ctx.OpcodeHandlerIndices == null)
                return new[] {"<handler map unavailable>"};

            if (!Ctx.OpcodeHandlerIndices.TryGetValue(vmByte, out var index))
                return new[] {"<handler not found>"};

            var instructions = Ctx.OpcodeHandlerMethod.CilMethodBody.Instructions;
            var lines = new List<string>();
            for (var i = index; i < instructions.Count && lines.Count < 22; i++)
            {
                var instruction = instructions[i];
                var operand = instruction.Operand == null ? string.Empty : " " + instruction.Operand;
                lines.Add($"[{i}] {instruction.OpCode}{operand}");
                if (instruction.OpCode == AsmResolver.PE.DotNet.Cil.CilOpCodes.Ret)
                    break;
            }

            return lines;
        }
    }
}
