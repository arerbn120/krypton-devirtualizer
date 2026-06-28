using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using AsmResolver.IO;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Builder;
using AsmResolver.DotNet.Signatures;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables.Rows;
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
                new MethodReplacing(),
                new HiddenCallRecovery(),   // recover NET Reactor "Hide Method Calls" stubs
                new PostDeobfuscation(),
                new StringDecryption(),
                new ResourceDecryption()
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
            var enableNecrobitBodyRestore = GetFeatureToggle(
                "KRYPTON_ENABLE_NECROBIT_BODY_RESTORE",
                defaultEnabled: true,
                disableVariableName: "KRYPTON_DISABLE_NECROBIT_BODY_RESTORE");
            var restoredNecrobitBodies = enableNecrobitBodyRestore
                ? RestoreNecrobitMethodBodies(Ctx.Module)
                : 0;
            if (restoredNecrobitBodies > 0)
            {
                Ctx.Options.Logger.Warning(
                    $"Restored {restoredNecrobitBodies} NecroBit runtime method body/bodies from Hashtable dump.");
            }

            if (methodsToPatch.Count == 0 && !allowStabilizationOnlyOutput && restoredNecrobitBodies == 0)
                return false;
            if (methodsToPatch.Count == 0 && allowStabilizationOnlyOutput)
            {
                Ctx.Options.Logger.Info(
                    "Proceeding without method-body patches because stabilization-only output is enabled.");
            }
            else if (methodsToPatch.Count == 0 && restoredNecrobitBodies > 0)
            {
                Ctx.Options.Logger.Info(
                    "Proceeding with NecroBit-restored method bodies even though no VM recompilation patches were queued.");
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

                var enableAesFinalBlockRepair = GetFeatureToggle(
                    "KRYPTON_ENABLE_AES_FINAL_BLOCK_REPAIR",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_AES_FINAL_BLOCK_REPAIR");
                if (enableAesFinalBlockRepair)
                {
                    var repairedAesFinalBlocks = RepairAesTransformFinalBlockLengthPatterns(Ctx.Module);
                    if (repairedAesFinalBlocks > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Repaired {repairedAesFinalBlocks} AES TransformFinalBlock length expression(s).");
                    }
                }

                var enableStaticDataCctorRepair = GetFeatureToggle(
                    "KRYPTON_ENABLE_STATIC_DATA_CCTOR_REPAIR",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_STATIC_DATA_CCTOR_REPAIR");
                if (enableStaticDataCctorRepair)
                {
                    var repairedStaticDataCctors = RepairStaticDataInitializers(Ctx.Module);
                    if (repairedStaticDataCctors > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Repaired {repairedStaticDataCctors} static data initializer(s).");
                    }
                }

                var enableWinFormsFormRepair = GetFeatureToggle(
                    "KRYPTON_ENABLE_WINFORMS_FORM_REPAIR",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_WINFORMS_FORM_REPAIR");
                if (enableWinFormsFormRepair)
                {
                    var repairedWinFormsForms = RepairWindowsFormsFormConstructors(Ctx.Module);
                    if (repairedWinFormsForms > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Rebuilt {repairedWinFormsForms} WinForms form constructor(s).");
                    }
                }

                var enableWinFormsDisposeRepair = GetFeatureToggle(
                    "KRYPTON_ENABLE_WINFORMS_DISPOSE_REPAIR",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_WINFORMS_DISPOSE_REPAIR");
                if (enableWinFormsDisposeRepair)
                {
                    var repairedWinFormsDisposeMethods = RepairWindowsFormsDisposeMethods(Ctx.Module);
                    if (repairedWinFormsDisposeMethods > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Rebuilt {repairedWinFormsDisposeMethods} WinForms Dispose(bool) method(s).");
                    }
                }

                var enableWinFormsEntryPointRepair = GetFeatureToggle(
                    "KRYPTON_ENABLE_WINFORMS_ENTRYPOINT_REPAIR",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_WINFORMS_ENTRYPOINT_REPAIR");
                if (enableWinFormsEntryPointRepair)
                {
                    var repairedWinFormsEntryPoints = RepairWindowsFormsDelegateEntryPoint(Ctx.Module);
                    if (repairedWinFormsEntryPoints > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Rebuilt {repairedWinFormsEntryPoints} WinForms delegate-based entry point(s).");
                    }
                }

                var enableAntiIldasmStrip = GetFeatureToggle(
                    "KRYPTON_ENABLE_ANTI_ILDASM_STRIP",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_ANTI_ILDASM_STRIP");
                if (enableAntiIldasmStrip)
                {
                    var strippedAntiIldasmAttributes = StripAntiIldasmAttributes(Ctx.Module);
                    if (strippedAntiIldasmAttributes > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Stripped {strippedAntiIldasmAttributes} Anti-ILDASM attribute(s).");
                    }
                }

                var enableReactorRuntimeCleanup = GetFeatureToggle(
                    "KRYPTON_ENABLE_REACTOR_RUNTIME_CLEANUP",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_REACTOR_RUNTIME_CLEANUP");
                if (enableReactorRuntimeCleanup)
                {
                    var cleanup = CleanUnusedReactorRuntime(Ctx.Module);
                    if (cleanup.TotalChanges > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            "Cleaned unused NET Reactor runtime: " +
                            $"{cleanup.StubbedMethods} method body/bodies stubbed, " +
                            $"{cleanup.DisabledPInvokes} P/Invoke import(s) disabled, " +
                            $"{cleanup.RuntimeTypes} runtime-looking type(s) analyzed, " +
                            $"{cleanup.ReachableMethods} reachable method(s) preserved.");
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
                    defaultEnabled: true);
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

        private int RepairWindowsFormsDelegateEntryPoint(AsmResolver.DotNet.ModuleDefinition module)
        {
            var entry = module?.ManagedEntryPoint as AsmResolver.DotNet.MethodDefinition;
            if (entry?.CilMethodBody == null)
                return 0;

            if (!TryFindConstructedWindowsFormsCtor(module, entry.CilMethodBody, out var formCtor))
                return 0;

            if (!UsesDelegateInvokeWrappers(entry.CilMethodBody))
                return 0;

            if (!TryBuildWindowsFormsApplicationReferences(
                    module,
                    formCtor,
                    out var enableStyles,
                    out var setCompatibleTextRenderingDefault,
                    out var run))
            {
                return 0;
            }

            var replacement = new CilMethodBody(entry)
            {
                InitializeLocals = false,
                ComputeMaxStackOnBuild = true
            };
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Call, enableStyles));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Call, setCompatibleTextRenderingDefault));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Newobj, formCtor));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Call, run));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ret));

            entry.CilMethodBody = replacement;
            return 1;
        }

        private bool TryFindConstructedWindowsFormsCtor(
            AsmResolver.DotNet.ModuleDefinition module,
            CilMethodBody body,
            out IMethodDescriptor formCtor)
        {
            formCtor = null;
            if (body?.Instructions == null)
                return false;

            foreach (var instruction in body.Instructions)
            {
                if (instruction.OpCode.Code != CilCode.Newobj)
                    continue;

                var ctor = instruction.Operand as IMethodDescriptor;
                if (ctor == null || ctor.Signature == null || ctor.Signature.ParameterTypes.Count != 0)
                    continue;

                if (IsWindowsFormsFormConstructor(ctor))
                {
                    formCtor = ctor;
                    return true;
                }
            }

            formCtor = FindFirstWindowsFormsFormCtor(module);
            return formCtor != null;
        }

        private bool IsWindowsFormsFormConstructor(IMethodDescriptor ctor)
        {
            if (ctor?.DeclaringType == null)
                return false;

            try
            {
                var declaringType = ctor.DeclaringType.Resolve();
                return string.Equals(
                    declaringType?.BaseType?.FullName,
                    "System.Windows.Forms.Form",
                    StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        private IMethodDescriptor FindFirstWindowsFormsFormCtor(AsmResolver.DotNet.ModuleDefinition module)
        {
            if (module == null)
                return null;

            foreach (var type in module.GetAllTypes())
            {
                if (!string.Equals(type.BaseType?.FullName, "System.Windows.Forms.Form", StringComparison.Ordinal))
                    continue;

                foreach (var method in type.Methods)
                {
                    if (!method.IsConstructor || method.IsStatic || method.Signature == null)
                        continue;
                    if (method.Signature.ParameterTypes.Count == 0)
                        return method;
                }
            }

            return null;
        }

        private bool UsesDelegateInvokeWrappers(CilMethodBody body)
        {
            if (body?.Instructions == null)
                return false;

            foreach (var instruction in body.Instructions)
            {
                if (instruction.OpCode.Code != CilCode.Call && instruction.OpCode.Code != CilCode.Callvirt)
                    continue;

                var descriptor = instruction.Operand as IMethodDescriptor;
                if (descriptor == null)
                    continue;

                AsmResolver.DotNet.MethodDefinition resolved;
                try
                {
                    resolved = descriptor.Resolve();
                }
                catch
                {
                    continue;
                }

                if (IsDelegateInvokeWrapper(resolved))
                    return true;
            }

            return false;
        }

        private bool IsDelegateInvokeWrapper(AsmResolver.DotNet.MethodDefinition method)
        {
            var body = method?.CilMethodBody;
            if (body == null || body.Instructions.Count > 12)
                return false;

            foreach (var instruction in body.Instructions)
            {
                if (instruction.OpCode.Code != CilCode.Callvirt && instruction.OpCode.Code != CilCode.Call)
                    continue;

                var descriptor = instruction.Operand as IMethodDescriptor;
                if (descriptor == null)
                    continue;

                if (string.Equals(descriptor.Name, "Invoke", StringComparison.Ordinal))
                    return true;
            }

            return false;
        }

        private bool TryBuildWindowsFormsApplicationReferences(
            AsmResolver.DotNet.ModuleDefinition module,
            IMethodDescriptor formCtor,
            out IMethodDescriptor enableStyles,
            out IMethodDescriptor setCompatibleTextRenderingDefault,
            out IMethodDescriptor run)
        {
            enableStyles = null;
            setCompatibleTextRenderingDefault = null;
            run = null;

            var formType = FindWindowsFormsFormTypeReference(module, formCtor);
            var formTypeReference = formType as AsmResolver.DotNet.TypeReference;
            if (module == null || formType == null || formTypeReference?.Scope == null)
                return false;

            var applicationType = new AsmResolver.DotNet.TypeReference(
                module,
                formTypeReference.Scope,
                "System.Windows.Forms",
                "Application");

            var corLib = module.CorLibTypeFactory;
            enableStyles = new AsmResolver.DotNet.MemberReference(
                applicationType,
                "EnableVisualStyles",
                MethodSignature.CreateStatic(corLib.Void));
            setCompatibleTextRenderingDefault = new AsmResolver.DotNet.MemberReference(
                applicationType,
                "SetCompatibleTextRenderingDefault",
                MethodSignature.CreateStatic(corLib.Void, corLib.Boolean));
            run = new AsmResolver.DotNet.MemberReference(
                applicationType,
                "Run",
                MethodSignature.CreateStatic(corLib.Void, new TypeDefOrRefSignature(formType)));

            return true;
        }

        private ITypeDefOrRef FindWindowsFormsFormTypeReference(
            AsmResolver.DotNet.ModuleDefinition module,
            IMethodDescriptor formCtor)
        {
            try
            {
                var declaringType = formCtor?.DeclaringType?.Resolve();
                if (string.Equals(declaringType?.BaseType?.FullName, "System.Windows.Forms.Form", StringComparison.Ordinal))
                    return declaringType.BaseType;
            }
            catch
            {
                // Fallback to scanning all type definitions below.
            }

            if (module == null)
                return null;

            foreach (var type in module.GetAllTypes())
            {
                if (string.Equals(type.BaseType?.FullName, "System.Windows.Forms.Form", StringComparison.Ordinal))
                    return type.BaseType;
            }

            return null;
        }

        private int RepairWindowsFormsFormConstructors(AsmResolver.DotNet.ModuleDefinition module)
        {
            if (module == null)
                return 0;

            var formSnapshots = LoadWinFormsSnapshots();
            var repaired = 0;
            foreach (var type in module.GetAllTypes())
            {
                if (!string.Equals(type.BaseType?.FullName, "System.Windows.Forms.Form", StringComparison.Ordinal))
                    continue;

                var ctor = type.Methods.FirstOrDefault(m =>
                    m.IsConstructor &&
                    !m.IsStatic &&
                    m.Signature != null &&
                    m.Signature.ParameterTypes.Count == 0 &&
                    m.CilMethodBody != null);
                if (ctor == null || !LooksLikeEmptyMethodBody(ctor.CilMethodBody))
                    continue;

                if (!TryBuildWindowsFormsControlReferences(module, type.BaseType, out var refs))
                    continue;

                if (TryGetWinFormsSnapshot(formSnapshots, type, out var snapshot) &&
                    IsUsableWinFormsSnapshot(snapshot) &&
                    TryRewriteWindowsFormsConstructorFromSnapshot(ctor, type, snapshot, refs))
                {
                    repaired++;
                    continue;
                }

                // Generic path: if there is an InitializeComponent-like method that was
                // already patched by HiddenCallRecovery, just emit base..ctor + call it.
                var initComp = FindInitializeComponentMethod(type);
                if (initComp != null)
                {
                    RewriteConstructorWithInitializeComponent(ctor, initComp, refs);
                    repaired++;
                    continue;
                }

                // Fallback: no InitializeComponent found — attempt structural reconstruction
                // using type-inspection (requires a TextBox field and a click handler).
                // Optional last-resort heuristic. This is not original designer recovery:
                // it fabricates a minimal UI from type shape, so keep it opt-in.
                if (!IsWinFormsHeuristicFallbackEnabled())
                {
                    Ctx?.Options?.Logger?.Warning(
                        $"WinForms UI for {type.FullName} was not recovered from runtime snapshot or InitializeComponent payload. " +
                        "Set KRYPTON_WINFORMS_HEURISTIC_FALLBACK=1 to emit the old synthetic fallback.");
                    continue;
                }

                var textBoxField = FindInstanceFieldOfType(type, "System.Windows.Forms.TextBox");
                var clickHandler = FindWindowsFormsClickHandler(type);
                if (textBoxField == null || clickHandler == null)
                    continue;

                RewriteWindowsFormsConstructor(ctor, textBoxField, clickHandler, refs);
                repaired++;
            }

            return repaired;
        }

        private int RepairWindowsFormsDisposeMethods(AsmResolver.DotNet.ModuleDefinition module)
        {
            if (module == null)
                return 0;

            var repaired = 0;
            foreach (var type in module.GetAllTypes())
            {
                if (!IsWindowsFormsFormType(type))
                    continue;

                var dispose = FindWindowsFormsDisposeBoolMethod(type);
                if (dispose?.CilMethodBody == null)
                    continue;
                if (!ShouldRewriteWindowsFormsDispose(dispose))
                    continue;

                if (!TryBuildWindowsFormsControlReferences(module, type.BaseType, out var refs))
                    continue;
                if (refs.FormDisposeBool == null || refs.DisposableDispose == null)
                    continue;

                var componentsField = FindWindowsFormsComponentsField(type);
                RewriteWindowsFormsDisposeMethod(dispose, componentsField, refs);
                repaired++;
            }

            return repaired;
        }

        private static AsmResolver.DotNet.MethodDefinition FindWindowsFormsDisposeBoolMethod(
            AsmResolver.DotNet.TypeDefinition type)
        {
            if (type == null)
                return null;

            foreach (var method in type.Methods)
            {
                if (method.IsStatic || method.Signature == null)
                    continue;
                if (!string.Equals(method.Name, "Dispose", StringComparison.Ordinal))
                    continue;
                if (!string.Equals(method.Signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
                    continue;
                if (method.Signature.ParameterTypes.Count != 1)
                    continue;
                if (!string.Equals(method.Signature.ParameterTypes[0].FullName, "System.Boolean", StringComparison.Ordinal))
                    continue;

                return method;
            }

            return null;
        }

        private bool ShouldRewriteWindowsFormsDispose(AsmResolver.DotNet.MethodDefinition method)
        {
            var body = method?.CilMethodBody;
            if (body == null)
                return false;

            if (LooksLikeEmptyMethodBody(body))
                return true;

            // A valid WinForms Dispose(bool) override must eventually delegate to
            // Form.Dispose(bool). If it is a tiny protected stub that does not, the
            // close path can be left half-alive after devirtualization.
            return body.Instructions.Count <= 8 && !CallsWindowsFormsBaseDispose(body);
        }

        private static bool CallsWindowsFormsBaseDispose(CilMethodBody body)
        {
            foreach (var instruction in body.Instructions)
            {
                if (instruction.OpCode.Code != CilCode.Call &&
                    instruction.OpCode.Code != CilCode.Callvirt)
                {
                    continue;
                }

                if (!(instruction.Operand is IMethodDescriptor descriptor))
                    continue;
                if (!string.Equals(descriptor.Name, "Dispose", StringComparison.Ordinal))
                    continue;

                var signature = descriptor.Signature;
                if (signature == null || signature.ParameterTypes.Count != 1)
                    continue;
                if (!string.Equals(signature.ParameterTypes[0].FullName, "System.Boolean", StringComparison.Ordinal))
                    continue;
                if (string.Equals(
                        descriptor.DeclaringType?.FullName,
                        "System.Windows.Forms.Form",
                        StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        private static AsmResolver.DotNet.FieldDefinition FindWindowsFormsComponentsField(
            AsmResolver.DotNet.TypeDefinition type)
        {
            if (type == null)
                return null;

            return type.Fields.FirstOrDefault(field =>
                !field.IsStatic &&
                string.Equals(
                    field.Signature?.FieldType?.FullName,
                    "System.ComponentModel.IContainer",
                    StringComparison.Ordinal));
        }

        private static void RewriteWindowsFormsDisposeMethod(
            AsmResolver.DotNet.MethodDefinition dispose,
            AsmResolver.DotNet.FieldDefinition componentsField,
            WindowsFormsControlReferences refs)
        {
            var body = new CilMethodBody(dispose)
            {
                InitializeLocals = false,
                ComputeMaxStackOnBuild = true
            };

            var il = body.Instructions;
            var callBase = new CilInstruction(CilOpCodes.Ldarg_0);

            if (componentsField != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_1));
                il.Add(new CilInstruction(CilOpCodes.Brfalse, new CilInstructionLabel(callBase)));
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldfld, componentsField));
                il.Add(new CilInstruction(CilOpCodes.Brfalse, new CilInstructionLabel(callBase)));
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldfld, componentsField));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.DisposableDispose));
            }

            il.Add(callBase);
            il.Add(new CilInstruction(CilOpCodes.Ldarg_1));
            il.Add(new CilInstruction(CilOpCodes.Call, refs.FormDisposeBool));
            il.Add(new CilInstruction(CilOpCodes.Ret));

            dispose.CilMethodBody = body;
        }

        private static bool IsWinFormsHeuristicFallbackEnabled()
        {
            var value = Environment.GetEnvironmentVariable("KRYPTON_WINFORMS_HEURISTIC_FALLBACK");
            if (string.IsNullOrWhiteSpace(value))
                return false;

            value = value.Trim();
            return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "on", StringComparison.OrdinalIgnoreCase);
        }

        private List<WinFormsSnapshot> LoadWinFormsSnapshots()
        {
            var results = new List<WinFormsSnapshot>();
            var originalPath = Ctx?.Options?.FilePath;
            if (string.IsNullOrWhiteSpace(originalPath))
                return results;

            var dumpPath = Path.ChangeExtension(originalPath, null) + "-dynamic-dump.json";
            if (!File.Exists(dumpPath))
                return results;

            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(dumpPath));
                if (!doc.RootElement.TryGetProperty("Forms", out var forms) ||
                    forms.ValueKind != JsonValueKind.Array)
                {
                    return results;
                }

                foreach (var form in forms.EnumerateArray())
                {
                    var snapshot = new WinFormsSnapshot
                    {
                        TypeName = ReadString(form, "TypeName"),
                        TypeToken = ReadString(form, "TypeToken"),
                        Text = ReadString(form, "Text"),
                        ClientWidth = ReadNullableInt(form, "ClientWidth"),
                        ClientHeight = ReadNullableInt(form, "ClientHeight"),
                        FormBorderStyle = ReadNullableInt(form, "FormBorderStyle"),
                        StartPosition = ReadNullableInt(form, "StartPosition"),
                        MaximizeBox = ReadNullableBool(form, "MaximizeBox"),
                        MinimizeBox = ReadNullableBool(form, "MinimizeBox"),
                        AutoScaleMode = ReadNullableInt(form, "AutoScaleMode"),
                        AutoScaleWidth = ReadNullableFloat(form, "AutoScaleWidth"),
                        AutoScaleHeight = ReadNullableFloat(form, "AutoScaleHeight"),
                    };

                    if (form.TryGetProperty("Controls", out var controls) &&
                        controls.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var control in controls.EnumerateArray())
                            snapshot.Controls.Add(ReadControlSnapshot(control));
                    }

                    results.Add(snapshot);
                }
            }
            catch (Exception ex)
            {
                Ctx?.Options?.Logger?.Warning(
                    $"Failed to read WinForms snapshots from dynamic dump: {ex.Message}");
            }

            results.AddRange(LoadWinFormsPayloadSnapshots());
            return results;
        }

        private List<WinFormsSnapshot> LoadWinFormsPayloadSnapshots()
        {
            var results = new List<WinFormsSnapshot>();
            var originalPath = Ctx?.Options?.FilePath;
            var module = Ctx?.Module;
            if (module == null || string.IsNullOrWhiteSpace(originalPath) || !File.Exists(originalPath))
                return results;

            var tracePath = Path.ChangeExtension(originalPath, null) + "-payload-trace.json";
            if (!File.Exists(tracePath) && !InvokeRunner(
                    "--payload-trace",
                    originalPath,
                    tracePath,
                    "WinFormsPayload"))
            {
                return results;
            }

            var hcrMap = LoadHiddenCallMap();
            if (hcrMap.Count == 0)
                return results;

            var buffers = ReadPayloadTraceBuffers(tracePath).ToList();
            if (buffers.Count == 0)
                return results;

            foreach (var type in module.GetAllTypes())
            {
                if (!string.Equals(type.BaseType?.FullName, "System.Windows.Forms.Form", StringComparison.Ordinal))
                    continue;

                var controlFields = type.Fields
                    .Where(IsWinFormsControlField)
                    .ToList();
                if (controlFields.Count == 0)
                    continue;

                var best = SelectBestPayloadBuffer(buffers, controlFields);
                if (best == null)
                    continue;

                var instructions = ParseRawIl(best.Data);
                if (instructions.Count == 0)
                    continue;

                var decoderToken = FindStringDecoderToken(module, instructions);
                var fieldValues = ResolveRuntimeFieldValues(originalPath, instructions, decoderToken);
                var decodedStrings = DecodeRuntimeStrings(originalPath, decoderToken, instructions, fieldValues);
                if (TryBuildWinFormsSnapshotFromPayload(
                        module,
                        type,
                        controlFields,
                        instructions,
                        hcrMap,
                        fieldValues,
                        decodedStrings,
                        out var snapshot))
                {
                    results.Add(snapshot);
                    Ctx?.Options?.Logger?.Info(
                        $"Recovered WinForms payload snapshot for {type.FullName} from {best.Name}.");
                }
            }

            return results;
        }

        private Dictionary<uint, HiddenCallEntry> LoadHiddenCallMap()
        {
            var result = new Dictionary<uint, HiddenCallEntry>();
            var originalPath = Ctx?.Options?.FilePath;
            if (string.IsNullOrWhiteSpace(originalPath))
                return result;

            var dumpPath = Path.ChangeExtension(originalPath, null) + "-dynamic-dump.json";
            if (!File.Exists(dumpPath))
                return result;

            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(dumpPath));
                if (!doc.RootElement.TryGetProperty("Methods", out var methods) ||
                    methods.ValueKind != JsonValueKind.Array)
                {
                    return result;
                }

                foreach (var entry in methods.EnumerateArray())
                {
                    var fieldToken = ExtractMetadataToken(ReadString(entry, "SourceField"));
                    if (fieldToken == 0 ||
                        !entry.TryGetProperty("Instructions", out var ins) ||
                        ins.ValueKind != JsonValueKind.Array)
                    {
                        continue;
                    }

                    foreach (var instruction in ins.EnumerateArray())
                    {
                        if (!string.Equals(ReadString(instruction, "OperandKind"), "method", StringComparison.Ordinal))
                            continue;
                        if (string.Equals(ReadString(instruction, "MemberName"), "Invoke", StringComparison.Ordinal))
                            continue;

                        result[fieldToken] = new HiddenCallEntry
                        {
                            DeclaringType = ReadString(instruction, "DeclType"),
                            MethodName = ReadString(instruction, "MemberName"),
                            MemberSig = ReadString(instruction, "MemberSig")
                        };
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                Ctx?.Options?.Logger?.Warning($"Failed to read hidden-call map for WinForms payload recovery: {ex.Message}");
            }

            return result;
        }

        private static uint ExtractMetadataToken(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return 0;

            var tokenText = text.Trim();
            var pipe = tokenText.LastIndexOf('|');
            if (pipe >= 0)
                tokenText = tokenText.Substring(pipe + 1);

            if (tokenText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                tokenText = tokenText.Substring(2);

            return uint.TryParse(
                tokenText,
                System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture,
                out var token)
                ? token
                : 0;
        }

        private IEnumerable<PayloadBuffer> ReadPayloadTraceBuffers(string tracePath)
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(tracePath));
            if (!doc.RootElement.TryGetProperty("Buffers", out var buffers) ||
                buffers.ValueKind != JsonValueKind.Array)
            {
                yield break;
            }

            foreach (var buffer in buffers.EnumerateArray())
            {
                var base64 = ReadString(buffer, "Base64");
                if (string.IsNullOrWhiteSpace(base64))
                    continue;

                byte[] data;
                try
                {
                    data = Convert.FromBase64String(base64);
                }
                catch
                {
                    continue;
                }

                buffer.TryGetProperty("Index", out var indexProp);
                var index = indexProp.TryGetInt32(out var parsedIndex) ? parsedIndex : -1;
                var source = ReadString(buffer, "Source") ?? "trace";
                yield return new PayloadBuffer
                {
                    Name = $"trace #{index} {source}",
                    Data = data
                };
            }
        }

        private static PayloadBuffer SelectBestPayloadBuffer(
            List<PayloadBuffer> buffers,
            List<AsmResolver.DotNet.FieldDefinition> controlFields)
        {
            var fieldTokens = controlFields
                .Select(f => f.MetadataToken.ToUInt32())
                .Where(t => t != 0)
                .ToList();

            return buffers
                .Select(b => new
                {
                    Buffer = b,
                    Hits = fieldTokens.Sum(t => CountTokenHits(b.Data, t)),
                    DistinctHits = fieldTokens.Count(t => CountTokenHits(b.Data, t) > 0)
                })
                .Where(x => x.DistinctHits >= Math.Min(2, fieldTokens.Count))
                .OrderByDescending(x => x.Hits)
                .ThenByDescending(x => x.Buffer.Data.Length)
                .Select(x => x.Buffer)
                .FirstOrDefault();
        }

        private static int CountTokenHits(byte[] data, uint token)
        {
            var needle = BitConverter.GetBytes(token);
            var count = 0;
            for (var i = 0; i <= data.Length - 4; i++)
            {
                if (data[i] == needle[0] &&
                    data[i + 1] == needle[1] &&
                    data[i + 2] == needle[2] &&
                    data[i + 3] == needle[3])
                {
                    count++;
                }
            }
            return count;
        }

        private static bool IsWinFormsControlField(AsmResolver.DotNet.FieldDefinition field)
        {
            if (field == null || field.IsStatic)
                return false;

            var typeName = field.Signature?.FieldType?.FullName;
            return string.Equals(typeName, "System.Windows.Forms.TextBox", StringComparison.Ordinal) ||
                   string.Equals(typeName, "System.Windows.Forms.Button", StringComparison.Ordinal) ||
                   string.Equals(typeName, "System.Windows.Forms.CheckBox", StringComparison.Ordinal) ||
                   string.Equals(typeName, "System.Windows.Forms.RadioButton", StringComparison.Ordinal) ||
                   string.Equals(typeName, "System.Windows.Forms.Label", StringComparison.Ordinal);
        }

        private static List<RawIlInstruction> ParseRawIl(byte[] data)
        {
            var result = new List<RawIlInstruction>();
            var p = 0;
            while (p < data.Length)
            {
                var offset = p;
                var first = data[p++];
                var op = first == 0xFE && p < data.Length
                    ? 0xFE00 | data[p++]
                    : first;

                var instruction = new RawIlInstruction { Offset = offset, Op = op };
                switch (op)
                {
                    case 0x15: instruction.Int32 = -1; break;
                    case 0x16: instruction.Int32 = 0; break;
                    case 0x17: instruction.Int32 = 1; break;
                    case 0x18: instruction.Int32 = 2; break;
                    case 0x19: instruction.Int32 = 3; break;
                    case 0x1A: instruction.Int32 = 4; break;
                    case 0x1B: instruction.Int32 = 5; break;
                    case 0x1C: instruction.Int32 = 6; break;
                    case 0x1D: instruction.Int32 = 7; break;
                    case 0x1E: instruction.Int32 = 8; break;
                    case 0x1F:
                        if (p + 1 > data.Length) return result;
                        instruction.Int32 = unchecked((sbyte)data[p++]);
                        break;
                    case 0x20:
                        if (p + 4 > data.Length) return result;
                        instruction.Int32 = BitConverter.ToInt32(data, p);
                        p += 4;
                        break;
                    case 0x22:
                        if (p + 4 > data.Length) return result;
                        instruction.Single = BitConverter.ToSingle(data, p);
                        p += 4;
                        break;
                    case 0x23:
                        if (p + 8 > data.Length) return result;
                        p += 8;
                        break;
                    case 0x2B:
                    case 0x0E:
                    case 0x10:
                    case 0x11:
                    case 0x13:
                        if (p + 1 > data.Length) return result;
                        p++;
                        break;
                    case 0x38:
                    case 0x39:
                    case 0x3A:
                    case 0x3B:
                    case 0x3C:
                    case 0x3D:
                    case 0x3E:
                    case 0x3F:
                    case 0x40:
                    case 0x41:
                    case 0x42:
                    case 0x43:
                    case 0x44:
                        if (p + 4 > data.Length) return result;
                        p += 4;
                        break;
                    case 0x45:
                        if (p + 4 > data.Length) return result;
                        var count = BitConverter.ToInt32(data, p);
                        p += 4;
                        if (count < 0 || count > 4096 || p + count * 4 > data.Length) return result;
                        p += count * 4;
                        break;
                    case 0x28:
                    case 0x6F:
                    case 0x70:
                    case 0x71:
                    case 0x72:
                    case 0x73:
                    case 0x74:
                    case 0x75:
                    case 0x7B:
                    case 0x7C:
                    case 0x7D:
                    case 0x7E:
                    case 0xFE06:
                        if (p + 4 > data.Length) return result;
                        instruction.Token = BitConverter.ToUInt32(data, p);
                        p += 4;
                        break;
                    case 0xFE09:
                    case 0xFE0B:
                    case 0xFE0C:
                    case 0xFE0E:
                        if (p + 2 > data.Length) return result;
                        p += 2;
                        break;
                }

                result.Add(instruction);
            }

            return result;
        }

        private static uint FindStringDecoderToken(
            AsmResolver.DotNet.ModuleDefinition module,
            List<RawIlInstruction> instructions)
        {
            foreach (var instruction in instructions)
            {
                if (instruction.Op != 0x28 && instruction.Op != 0x6F)
                    continue;
                if (instruction.Token == 0)
                    continue;

                var method = TryFindMethodByToken(module, instruction.Token);
                if (method?.Signature == null)
                    continue;
                if (method.Signature.ParameterTypes.Count == 1 &&
                    string.Equals(method.Signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal) &&
                    string.Equals(method.Signature.ReturnType?.FullName, "System.String", StringComparison.Ordinal))
                {
                    return instruction.Token;
                }
            }

            return 0x0600005C;
        }

        private Dictionary<uint, int> ResolveRuntimeFieldValues(
            string originalPath,
            List<RawIlInstruction> instructions,
            uint decoderToken)
        {
            var needed = new HashSet<uint>();
            for (var i = 0; i < instructions.Count; i++)
            {
                if ((instructions[i].Op != 0x28 && instructions[i].Op != 0x6F) ||
                    instructions[i].Token != decoderToken)
                {
                    continue;
                }

                var position = i - 1;
                TryEvaluateRawInt(instructions, ref position, new Dictionary<uint, int>(), out _, needed);
            }

            if (needed.Count == 0)
                return new Dictionary<uint, int>();

            var outPath = Path.ChangeExtension(originalPath, null) + "-payload-fields.json";
            if (!InvokeRunner(
                    "--dump-fields",
                    originalPath,
                    outPath,
                    "WinFormsPayload",
                    needed.Select(t => "0x" + t.ToString("X8")).ToArray()))
            {
                return new Dictionary<uint, int>();
            }

            return ReadRuntimeFieldValues(outPath);
        }

        private Dictionary<int, string> DecodeRuntimeStrings(
            string originalPath,
            uint decoderToken,
            List<RawIlInstruction> instructions,
            Dictionary<uint, int> fieldValues)
        {
            var indices = new List<int>();
            for (var i = 0; i < instructions.Count; i++)
            {
                if ((instructions[i].Op != 0x28 && instructions[i].Op != 0x6F) ||
                    instructions[i].Token != decoderToken)
                {
                    continue;
                }

                var position = i - 1;
                if (TryEvaluateRawInt(instructions, ref position, fieldValues, out var index, null))
                    indices.Add(index);
            }

            indices = indices.Distinct().ToList();
            if (indices.Count == 0)
                return new Dictionary<int, string>();

            var outPath = Path.ChangeExtension(originalPath, null) + "-payload-strings.json";
            var extra = new List<string> { "0x" + decoderToken.ToString("X8") };
            extra.AddRange(indices.Select(i => i.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            if (!InvokeRunner(
                    "--eval-strings",
                    originalPath,
                    outPath,
                    "WinFormsPayload",
                    extra.ToArray()))
            {
                return new Dictionary<int, string>();
            }

            return ReadRuntimeStrings(outPath);
        }

        private static Dictionary<uint, int> ReadRuntimeFieldValues(string path)
        {
            var result = new Dictionary<uint, int>();
            if (!File.Exists(path))
                return result;

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (!doc.RootElement.TryGetProperty("Fields", out var fields) ||
                fields.ValueKind != JsonValueKind.Array)
            {
                return result;
            }

            foreach (var field in fields.EnumerateArray())
            {
                var token = ExtractMetadataToken(ReadString(field, "Token"));
                var valueText = ReadString(field, "Value");
                if (token == 0 || !int.TryParse(valueText, out var value))
                    continue;

                result[token] = value;
            }

            return result;
        }

        private static Dictionary<int, string> ReadRuntimeStrings(string path)
        {
            var result = new Dictionary<int, string>();
            if (!File.Exists(path))
                return result;

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (!doc.RootElement.TryGetProperty("Strings", out var strings) ||
                strings.ValueKind != JsonValueKind.Array)
            {
                return result;
            }

            foreach (var row in strings.EnumerateArray())
            {
                if (!row.TryGetProperty("Index", out var indexProp) ||
                    !indexProp.TryGetInt32(out var index))
                {
                    continue;
                }

                var text = ReadString(row, "Text");
                if (text != null)
                    result[index] = text;
            }

            return result;
        }

        private bool TryBuildWinFormsSnapshotFromPayload(
            AsmResolver.DotNet.ModuleDefinition module,
            AsmResolver.DotNet.TypeDefinition formType,
            List<AsmResolver.DotNet.FieldDefinition> controlFields,
            List<RawIlInstruction> instructions,
            Dictionary<uint, HiddenCallEntry> hcrMap,
            Dictionary<uint, int> fieldValues,
            Dictionary<int, string> decodedStrings,
            out WinFormsSnapshot snapshot)
        {
            var payloadSnapshot = new WinFormsSnapshot
            {
                TypeName = formType.FullName,
                TypeToken = "0x" + formType.MetadataToken.ToUInt32().ToString("X8")
            };
            snapshot = null;

            var controlsByToken = new Dictionary<uint, WinFormsControlSnapshot>();
            foreach (var field in controlFields)
            {
                var token = field.MetadataToken.ToUInt32();
                controlsByToken[token] = new WinFormsControlSnapshot
                {
                    TypeName = field.Signature?.FieldType?.FullName,
                    FieldName = field.Name,
                    FieldToken = "0x" + token.ToString("X8")
                };
            }

            var orderedControlTokens = new List<uint>();
            void TouchControl(uint token)
            {
                if (token == 0 || !controlsByToken.ContainsKey(token))
                    return;
                if (!orderedControlTokens.Contains(token))
                    orderedControlTokens.Add(token);
            }

            var decoderToken = FindStringDecoderToken(module, instructions);
            var stringByCallIndex = new Dictionary<int, string>();
            for (var i = 0; i < instructions.Count; i++)
            {
                if ((instructions[i].Op != 0x28 && instructions[i].Op != 0x6F) ||
                    instructions[i].Token != decoderToken)
                {
                    continue;
                }

                var position = i - 1;
                if (TryEvaluateRawInt(instructions, ref position, fieldValues, out var index, null) &&
                    decodedStrings.TryGetValue(index, out var text))
                {
                    stringByCallIndex[i] = text;
                }
            }

            for (var i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                if (instruction.Op == 0x7D && instruction.Token != 0)
                    TouchControl(instruction.Token);

                if ((instruction.Op != 0x28 && instruction.Op != 0x6F) || i < 1)
                    continue;

                var hcrLoad = instructions[i - 1];
                if (hcrLoad.Op != 0x7E || hcrLoad.Token == 0 ||
                    !hcrMap.TryGetValue(hcrLoad.Token, out var hcr) ||
                    string.IsNullOrEmpty(hcr.MethodName))
                {
                    continue;
                }

                switch (hcr.MethodName)
                {
                    case "set_Location":
                        ApplyPointOrSizeSetter(instructions, i, controlsByToken, TouchControl, isLocation: true);
                        break;
                    case "set_Size":
                        ApplyPointOrSizeSetter(instructions, i, controlsByToken, TouchControl, isLocation: false);
                        break;
                    case "set_TabIndex":
                        ApplyControlIntSetter(instructions, i, controlsByToken, TouchControl, (c, v) => c.TabIndex = v);
                        break;
                    case "set_UseVisualStyleBackColor":
                        ApplyControlIntSetter(instructions, i, controlsByToken, TouchControl, (c, v) => c.UseVisualStyleBackColor = v != 0);
                        break;
                    case "set_Name":
                    case "set_Text":
                        ApplyStringSetter(
                            instructions,
                            i,
                            stringByCallIndex,
                            fieldValues,
                            controlsByToken,
                            TouchControl,
                            payloadSnapshot,
                            hcr.MethodName);
                        break;
                    case "set_ClientSize":
                        ApplyFormSizeSetter(instructions, i, payloadSnapshot);
                        break;
                    case "set_AutoScaleDimensions":
                        ApplyFormScaleSetter(instructions, i, payloadSnapshot);
                        break;
                    case "set_AutoScaleMode":
                        ApplyFormIntSetter(instructions, i, v => payloadSnapshot.AutoScaleMode = v);
                        break;
                    case "set_FormBorderStyle":
                        ApplyFormIntSetter(instructions, i, v => payloadSnapshot.FormBorderStyle = v);
                        break;
                    case "set_StartPosition":
                        ApplyFormIntSetter(instructions, i, v => payloadSnapshot.StartPosition = v);
                        break;
                    case "set_MaximizeBox":
                        ApplyFormIntSetter(instructions, i, v => payloadSnapshot.MaximizeBox = v != 0);
                        break;
                    case "set_MinimizeBox":
                        ApplyFormIntSetter(instructions, i, v => payloadSnapshot.MinimizeBox = v != 0);
                        break;
                }
            }

            foreach (var token in orderedControlTokens)
            {
                if (controlsByToken.TryGetValue(token, out var control))
                    payloadSnapshot.Controls.Add(control);
            }

            if (payloadSnapshot.Controls.Count == 0 && !IsUsableWinFormsSnapshot(payloadSnapshot))
                return false;

            snapshot = payloadSnapshot;
            return true;
        }

        private static void ApplyPointOrSizeSetter(
            List<RawIlInstruction> instructions,
            int callIndex,
            Dictionary<uint, WinFormsControlSnapshot> controlsByToken,
            Action<uint> touchControl,
            bool isLocation)
        {
            if (callIndex < 5)
                return;
            var receiver = instructions[callIndex - 5];
            if (receiver.Op != 0x7B || receiver.Token == 0 ||
                !controlsByToken.TryGetValue(receiver.Token, out var control) ||
                !TryGetRawInt(instructions[callIndex - 4], out var first) ||
                !TryGetRawInt(instructions[callIndex - 3], out var second))
            {
                return;
            }

            if (isLocation)
            {
                control.Left = first;
                control.Top = second;
            }
            else
            {
                control.Width = first;
                control.Height = second;
            }
            touchControl(receiver.Token);
        }

        private static void ApplyControlIntSetter(
            List<RawIlInstruction> instructions,
            int callIndex,
            Dictionary<uint, WinFormsControlSnapshot> controlsByToken,
            Action<uint> touchControl,
            Action<WinFormsControlSnapshot, int> assign)
        {
            if (callIndex < 3)
                return;
            var receiver = instructions[callIndex - 3];
            if (receiver.Op != 0x7B || receiver.Token == 0 ||
                !controlsByToken.TryGetValue(receiver.Token, out var control) ||
                !TryGetRawInt(instructions[callIndex - 2], out var value))
            {
                return;
            }

            assign(control, value);
            touchControl(receiver.Token);
        }

        private static void ApplyStringSetter(
            List<RawIlInstruction> instructions,
            int callIndex,
            Dictionary<int, string> stringByCallIndex,
            Dictionary<uint, int> fieldValues,
            Dictionary<uint, WinFormsControlSnapshot> controlsByToken,
            Action<uint> touchControl,
            WinFormsSnapshot snapshot,
            string setterName)
        {
            if (callIndex < 2)
                return;

            var decoderCallIndex = callIndex - 2;
            if (!stringByCallIndex.TryGetValue(decoderCallIndex, out var value))
                return;

            var position = decoderCallIndex - 1;
            if (!TryEvaluateRawInt(instructions, ref position, fieldValues, out _, null))
                return;

            var receiverIndex = position;
            if (receiverIndex < 0)
                return;

            var receiver = instructions[receiverIndex];
            if (receiver.Op == 0x02)
            {
                if (setterName == "set_Text")
                    snapshot.Text = value;
                return;
            }

            if (receiver.Op == 0x7B && receiver.Token != 0 &&
                controlsByToken.TryGetValue(receiver.Token, out var control))
            {
                if (setterName == "set_Name")
                    control.Name = value;
                else if (setterName == "set_Text")
                    control.Text = value;
                touchControl(receiver.Token);
            }
        }

        private static void ApplyFormSizeSetter(
            List<RawIlInstruction> instructions,
            int callIndex,
            WinFormsSnapshot snapshot)
        {
            if (callIndex < 4 ||
                !TryGetRawInt(instructions[callIndex - 4], out var width) ||
                !TryGetRawInt(instructions[callIndex - 3], out var height))
            {
                return;
            }

            snapshot.ClientWidth = width;
            snapshot.ClientHeight = height;
        }

        private static void ApplyFormScaleSetter(
            List<RawIlInstruction> instructions,
            int callIndex,
            WinFormsSnapshot snapshot)
        {
            if (callIndex < 4 ||
                !instructions[callIndex - 4].Single.HasValue ||
                !instructions[callIndex - 3].Single.HasValue)
            {
                return;
            }

            snapshot.AutoScaleWidth = instructions[callIndex - 4].Single.Value;
            snapshot.AutoScaleHeight = instructions[callIndex - 3].Single.Value;
        }

        private static void ApplyFormIntSetter(
            List<RawIlInstruction> instructions,
            int callIndex,
            Action<int> assign)
        {
            if (callIndex < 2 || !TryGetRawInt(instructions[callIndex - 2], out var value))
                return;

            assign(value);
        }

        private static bool TryEvaluateRawInt(
            List<RawIlInstruction> instructions,
            ref int position,
            Dictionary<uint, int> fieldValues,
            out int value,
            ISet<uint> missingFieldTokens)
        {
            value = 0;
            if (position < 0 || position >= instructions.Count)
                return false;

            var instruction = instructions[position];
            if (TryGetRawInt(instruction, out value))
            {
                position--;
                return true;
            }

            switch (instruction.Op)
            {
                case 0x58:
                    return TryEvaluateBinary(instructions, ref position, fieldValues, out value, missingFieldTokens, (a, b) => unchecked(a + b));
                case 0x61:
                    return TryEvaluateBinary(instructions, ref position, fieldValues, out value, missingFieldTokens, (a, b) => a ^ b);
                case 0x62:
                    return TryEvaluateBinary(instructions, ref position, fieldValues, out value, missingFieldTokens, (a, b) => a << (b & 31));
                case 0x66:
                    position--;
                    if (!TryEvaluateRawInt(instructions, ref position, fieldValues, out var inner, missingFieldTokens))
                        return false;
                    value = ~inner;
                    return true;
                case 0x7B:
                    if (instruction.Token == 0)
                        return false;
                    if (!fieldValues.TryGetValue(instruction.Token, out value))
                    {
                        if (missingFieldTokens != null)
                        {
                            missingFieldTokens.Add(instruction.Token);
                            value = 0;
                            position -= 2;
                            return true;
                        }
                        return false;
                    }
                    position -= 2;
                    return true;
                default:
                    return false;
            }
        }

        private static bool TryEvaluateBinary(
            List<RawIlInstruction> instructions,
            ref int position,
            Dictionary<uint, int> fieldValues,
            out int value,
            ISet<uint> missingFieldTokens,
            Func<int, int, int> op)
        {
            value = 0;
            position--;
            if (!TryEvaluateRawInt(instructions, ref position, fieldValues, out var right, missingFieldTokens))
                return false;
            if (!TryEvaluateRawInt(instructions, ref position, fieldValues, out var left, missingFieldTokens))
                return false;
            value = op(left, right);
            return true;
        }

        private static bool TryGetRawInt(RawIlInstruction instruction, out int value)
        {
            value = 0;
            if (!instruction.Int32.HasValue)
                return false;

            value = instruction.Int32.Value;
            return true;
        }

        private bool InvokeRunner(
            string mode,
            string targetPath,
            string outputPath,
            string logPrefix,
            string[] extraArgs = null)
        {
            var runnerPath = FindRunnerExecutable();
            if (runnerPath == null)
            {
                Ctx?.Options?.Logger?.Warning($"[{logPrefix}] Krypton.Runner.exe not found.");
                return false;
            }

            try
            {
                var args = new List<string>
                {
                    mode,
                    targetPath,
                    outputPath
                };
                if (extraArgs != null)
                    args.AddRange(extraArgs);

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = runnerPath,
                    Arguments = string.Join(" ", args.Select(QuoteArgument)),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };

                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc == null)
                    return false;

                var stdout = proc.StandardOutput.ReadToEnd();
                var stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit(60_000);

                foreach (var line in stdout.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line))
                        Ctx?.Options?.Logger?.Info($"  [{logPrefix}] {line.TrimEnd()}");
                foreach (var line in stderr.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line))
                        Ctx?.Options?.Logger?.Warning($"  [{logPrefix}/err] {line.TrimEnd()}");

                return proc.ExitCode == 0 && File.Exists(outputPath);
            }
            catch (Exception ex)
            {
                Ctx?.Options?.Logger?.Warning($"[{logPrefix}] Runner invocation failed: {ex.Message}");
                return false;
            }
        }

        private int RestoreNecrobitMethodBodies(AsmResolver.DotNet.ModuleDefinition module)
        {
            var originalPath = Ctx?.Options?.FilePath;
            if (module == null || string.IsNullOrWhiteSpace(originalPath) || !File.Exists(originalPath))
                return 0;

            var dumpPath = Path.ChangeExtension(originalPath, null) + "-necrobit-dump.json";
            if (!File.Exists(dumpPath) && !InvokeRunner(
                    "--necrobit-dump",
                    originalPath,
                    dumpPath,
                    "NecroBit"))
            {
                return 0;
            }

            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(dumpPath));
                if (!doc.RootElement.TryGetProperty("Methods", out var methods) ||
                    methods.ValueKind != JsonValueKind.Array)
                {
                    return 0;
                }

                var restored = 0;
                foreach (var entry in methods.EnumerateArray())
                {
                    var tokenText = ReadString(entry, "Token");
                    if (!TryParseMetadataToken(tokenText, out var token))
                        continue;

                    var method = TryFindMethodByToken(module, token);
                    if (method == null)
                        continue;

                    var base64 = ReadString(entry, "Base64");
                    if (string.IsNullOrWhiteSpace(base64))
                        continue;

                    byte[] rawBody;
                    try
                    {
                        rawBody = Convert.FromBase64String(base64);
                    }
                    catch
                    {
                        continue;
                    }

                    if (rawBody.Length == 0)
                        continue;

                    if (TryReplaceMethodInstructionsFromRawCil(module, method, rawBody))
                        restored++;
                }

                return restored;
            }
            catch (Exception ex)
            {
                Ctx?.Options?.Logger?.Warning($"Failed to apply NecroBit method body dump: {ex.Message}");
                return 0;
            }
        }

        private bool TryReplaceMethodInstructionsFromRawCil(
            AsmResolver.DotNet.ModuleDefinition module,
            AsmResolver.DotNet.MethodDefinition method,
            byte[] rawBody)
        {
            try
            {
                var body = method.CilMethodBody ?? new CilMethodBody(method);
                var reader = new BinaryStreamReader(rawBody);
                var resolver = new PhysicalCilOperandResolver(module, body);
                var disassembler = new CilDisassembler(in reader, resolver)
                {
                    ResolveBranchTargets = true
                };
                var instructions = disassembler.ReadInstructions();
                if (instructions == null || instructions.Count == 0)
                    return false;

                body.Instructions.Clear();
                body.Instructions.AddRange(instructions);
                body.ComputeMaxStackOnBuild = true;
                body.VerifyLabelsOnBuild = false;
                body.BuildFlags &= ~(CilMethodBodyBuildFlags.VerifyLabels |
                                     CilMethodBodyBuildFlags.FullValidation);
                method.CilMethodBody = body;
                return true;
            }
            catch (Exception ex)
            {
                Ctx?.Options?.Logger?.Warning(
                    $"Failed to restore NecroBit body for {method?.FullName ?? "<method>"}: {ex.Message}");
                return false;
            }
        }

        private static string FindRunnerExecutable()
        {
            var baseDir = AppContext.BaseDirectory;
            var up4 = Path.Combine(baseDir, "..", "..", "..", "..");
            var candidates = new[]
            {
                Path.Combine(baseDir, "Krypton.Runner.exe"),
                Path.Combine(up4, "Krypton.Runner", "bin", "Release", "net48", "Krypton.Runner.exe"),
                Path.Combine(up4, "Krypton.Runner", "bin", "Debug", "net48", "Krypton.Runner.exe"),
            };

            return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
        }

        private static string QuoteArgument(string value)
        {
            if (value == null)
                return "\"\"";
            return "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
        }

        private static AsmResolver.DotNet.MethodDefinition TryFindMethodByToken(
            AsmResolver.DotNet.ModuleDefinition module,
            uint token)
        {
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (method.MetadataToken.ToUInt32() == token)
                        return method;
                }
            }
            return null;
        }

        private static WinFormsControlSnapshot ReadControlSnapshot(JsonElement element)
        {
            var control = new WinFormsControlSnapshot
            {
                TypeName = ReadString(element, "TypeName"),
                FieldName = ReadString(element, "FieldName"),
                FieldToken = ReadString(element, "FieldToken"),
                Name = ReadString(element, "Name"),
                Text = ReadString(element, "Text"),
                Left = ReadInt(element, "Left"),
                Top = ReadInt(element, "Top"),
                Width = ReadInt(element, "Width"),
                Height = ReadInt(element, "Height"),
                TabIndex = ReadInt(element, "TabIndex"),
                Anchor = ReadInt(element, "Anchor"),
                PasswordChar = ReadInt(element, "PasswordChar"),
                UseVisualStyleBackColor = ReadNullableBool(element, "UseVisualStyleBackColor"),
            };

            if (element.TryGetProperty("Controls", out var children) &&
                children.ValueKind == JsonValueKind.Array)
            {
                foreach (var child in children.EnumerateArray())
                    control.Controls.Add(ReadControlSnapshot(child));
            }

            return control;
        }

        private static bool TryGetWinFormsSnapshot(
            List<WinFormsSnapshot> snapshots,
            AsmResolver.DotNet.TypeDefinition type,
            out WinFormsSnapshot snapshot)
        {
            snapshot = null;
            if (snapshots == null || snapshots.Count == 0 || type == null)
                return false;

            var typeToken = type.MetadataToken.ToUInt32();
            var tokenMatches = snapshots
                .Where(s => TryParseMetadataToken(s.TypeToken, out var token) && token == typeToken)
                .ToList();
            snapshot = tokenMatches.FirstOrDefault(IsUsableWinFormsSnapshot) ?? tokenMatches.FirstOrDefault();
            if (snapshot != null)
                return true;

            var nameMatches = snapshots
                .Where(s => string.Equals(s.TypeName, type.FullName, StringComparison.Ordinal))
                .ToList();
            snapshot = nameMatches.FirstOrDefault(IsUsableWinFormsSnapshot) ?? nameMatches.FirstOrDefault();
            return snapshot != null;
        }

        private static bool IsUsableWinFormsSnapshot(WinFormsSnapshot snapshot)
        {
            if (snapshot == null)
                return false;
            if (snapshot.Controls != null && snapshot.Controls.Count > 0)
                return true;
            if (!string.IsNullOrEmpty(snapshot.Text))
                return true;
            return (snapshot.ClientWidth ?? 0) > 0 || (snapshot.ClientHeight ?? 0) > 0;
        }

        private static string ReadString(JsonElement element, string name)
        {
            return element.TryGetProperty(name, out var prop) &&
                   prop.ValueKind == JsonValueKind.String
                ? prop.GetString()
                : null;
        }

        private static int ReadInt(JsonElement element, string name)
        {
            return ReadNullableInt(element, name) ?? 0;
        }

        private static int? ReadNullableInt(JsonElement element, string name)
        {
            if (!element.TryGetProperty(name, out var prop) ||
                prop.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            return prop.TryGetInt32(out var value) ? value : (int?)null;
        }

        private static bool? ReadNullableBool(JsonElement element, string name)
        {
            if (!element.TryGetProperty(name, out var prop) ||
                prop.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            if (prop.ValueKind == JsonValueKind.True) return true;
            if (prop.ValueKind == JsonValueKind.False) return false;
            return null;
        }

        private static float? ReadNullableFloat(JsonElement element, string name)
        {
            if (!element.TryGetProperty(name, out var prop) ||
                prop.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            return prop.TryGetSingle(out var value) ? value : (float?)null;
        }

        private static bool TryParseMetadataToken(string tokenText, out uint token)
        {
            token = 0;
            if (string.IsNullOrWhiteSpace(tokenText))
                return false;

            var text = tokenText.Trim();
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                text = text.Substring(2);

            return uint.TryParse(
                text,
                System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture,
                out token);
        }

        /// <summary>
        /// Finds a private parameterless void method in <paramref name="formType"/> that
        /// looks like InitializeComponent: it is not a constructor and its body contains
        /// at least one call to SuspendLayout, ResumeLayout, PerformLayout, set_ClientSize,
        /// or another WinForms control-setup method that HCR would have recovered.
        /// </summary>
        private static AsmResolver.DotNet.MethodDefinition FindInitializeComponentMethod(
            AsmResolver.DotNet.TypeDefinition formType)
        {
            foreach (var method in formType.Methods)
            {
                if (method.IsConstructor || method.IsStatic) continue;
                if (method.Signature == null) continue;
                if (!string.Equals(method.Signature.ReturnType?.FullName,
                        "System.Void", StringComparison.Ordinal)) continue;
                if (method.Signature.ParameterTypes.Count != 0) continue;
                if (method.CilMethodBody == null) continue;

                if (HasWinFormsLayoutCalls(method.CilMethodBody))
                    return method;
            }
            return null;
        }

        private static bool HasWinFormsLayoutCalls(CilMethodBody body)
        {
            // Look for the characteristic SuspendLayout / ResumeLayout / set_ClientSize calls
            // that HiddenCallRecovery restores to direct callvirt/call instructions.
            int hits = 0;
            foreach (var instr in body.Instructions)
            {
                if (instr.OpCode.Code != CilCode.Callvirt &&
                    instr.OpCode.Code != CilCode.Call) continue;

                var name = (instr.Operand as IMethodDescriptor)?.Name?.ToString() ?? string.Empty;
                switch (name)
                {
                    case "SuspendLayout":
                    case "ResumeLayout":
                    case "PerformLayout":
                    case "set_ClientSize":
                    case "set_FormBorderStyle":
                    case "set_StartPosition":
                    case "set_AutoScaleMode":
                        hits++;
                        if (hits >= 2) return true;
                        break;
                }
            }
            return false;
        }

        /// <summary>
        /// Rewrites the form constructor to:
        ///   base..ctor();
        ///   this.InitializeComponent();
        ///
        /// This is the generic path used when HiddenCallRecovery has already restored
        /// the real method calls inside InitializeComponent. No values are hardcoded.
        /// </summary>
        private static void RewriteConstructorWithInitializeComponent(
            AsmResolver.DotNet.MethodDefinition ctor,
            AsmResolver.DotNet.MethodDefinition initComp,
            WindowsFormsControlReferences refs)
        {
            var body = new CilMethodBody(ctor)
            {
                InitializeLocals       = false,
                ComputeMaxStackOnBuild = true
            };
            var il = body.Instructions;

            // call base.Form()
            il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            il.Add(new CilInstruction(CilOpCodes.Call, refs.FormCtor));

            // call this.InitializeComponent()
            il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            il.Add(new CilInstruction(CilOpCodes.Call, initComp));

            il.Add(new CilInstruction(CilOpCodes.Ret));

            ctor.CilMethodBody = body;

            MaybeInjectSyntheticWndProcCloseOverride(ctor.DeclaringType, refs);
        }

        private bool LooksLikeEmptyMethodBody(CilMethodBody body)
        {
            if (body == null || body.Instructions.Count == 0 || body.Instructions.Count > 6)
                return false;

            foreach (var instruction in body.Instructions)
            {
                if (instruction.OpCode.Code != CilCode.Nop && instruction.OpCode.Code != CilCode.Ret)
                    return false;
            }

            return body.Instructions.Any(i => i.OpCode.Code == CilCode.Ret);
        }

        private AsmResolver.DotNet.FieldDefinition FindInstanceFieldOfType(
            AsmResolver.DotNet.TypeDefinition type,
            string fieldTypeFullName)
        {
            if (type == null)
                return null;

            foreach (var field in type.Fields)
            {
                if (field.IsStatic || field.Signature == null)
                    continue;

                if (string.Equals(
                        field.Signature.FieldType?.FullName,
                        fieldTypeFullName,
                        StringComparison.Ordinal))
                {
                    return field;
                }
            }

            return null;
        }

        private AsmResolver.DotNet.MethodDefinition FindWindowsFormsClickHandler(AsmResolver.DotNet.TypeDefinition type)
        {
            if (type == null)
                return null;

            foreach (var method in type.Methods)
            {
                if (method.IsStatic || method.IsConstructor || method.Signature == null || method.CilMethodBody == null)
                    continue;

                var signature = method.Signature;
                if (!string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) ||
                    signature.ParameterTypes.Count != 2 ||
                    !string.Equals(signature.ParameterTypes[0].FullName, "System.Object", StringComparison.Ordinal) ||
                    !string.Equals(signature.ParameterTypes[1].FullName, "System.EventArgs", StringComparison.Ordinal))
                {
                    continue;
                }

                foreach (var instruction in method.CilMethodBody.Instructions)
                {
                    var descriptor = instruction.Operand as IMethodDescriptor;
                    if (descriptor == null)
                        continue;

                    var fullName = descriptor.FullName ?? string.Empty;
                    if (fullName.IndexOf("System.Windows.Forms.MessageBox::Show", StringComparison.Ordinal) >= 0)
                        return method;
                }
            }

            return null;
        }

        private bool TryBuildWindowsFormsControlReferences(
            AsmResolver.DotNet.ModuleDefinition module,
            ITypeDefOrRef formBaseType,
            out WindowsFormsControlReferences refs)
        {
            refs = null;
            var formTypeReference = formBaseType as AsmResolver.DotNet.TypeReference;
            if (module == null || formTypeReference?.Scope == null)
                return false;

            var corLib = module.CorLibTypeFactory;
            var scope = formTypeReference.Scope;
            var formType = formTypeReference;
            var controlType = new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "Control");
            var containerControlType = new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "ContainerControl");
            var controlCollectionType = new AsmResolver.DotNet.TypeReference(module, controlType, string.Empty, "ControlCollection");
            var textBoxType = new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "TextBox");
            var buttonType = new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "Button");
            var sizeType = new AsmResolver.DotNet.TypeReference(module, GetReferenceScopeForTypeName(module, "System.Drawing.Size"), "System.Drawing", "Size");
            var sizeFType = new AsmResolver.DotNet.TypeReference(module, GetReferenceScopeForTypeName(module, "System.Drawing.SizeF"), "System.Drawing", "SizeF");
            var autoScaleModeType = new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "AutoScaleMode");
            var formBorderStyleType = new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "FormBorderStyle");
            var formStartPositionType = new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "FormStartPosition");
            var eventHandlerType = new AsmResolver.DotNet.TypeReference(
                module,
                corLib.CorLibScope,
                "System",
                "EventHandler");
            var disposableType = new AsmResolver.DotNet.TypeReference(
                module,
                corLib.CorLibScope,
                "System",
                "IDisposable");

            var controlSignature = new TypeDefOrRefSignature(controlType);
            refs = new WindowsFormsControlReferences
            {
                ButtonType = buttonType,
                FormCtor = new AsmResolver.DotNet.MemberReference(
                    formType,
                    ".ctor",
                    MethodSignature.CreateInstance(corLib.Void)),
                TextBoxCtor = new AsmResolver.DotNet.MemberReference(
                    textBoxType,
                    ".ctor",
                    MethodSignature.CreateInstance(corLib.Void)),
                ButtonCtor = new AsmResolver.DotNet.MemberReference(
                    buttonType,
                    ".ctor",
                    MethodSignature.CreateInstance(corLib.Void)),
                SizeCtor = new AsmResolver.DotNet.MemberReference(
                    sizeType,
                    ".ctor",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Int32, corLib.Int32)),
                SizeFCtor = new AsmResolver.DotNet.MemberReference(
                    sizeFType,
                    ".ctor",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Single, corLib.Single)),
                EventHandlerCtor = new AsmResolver.DotNet.MemberReference(
                    eventHandlerType,
                    ".ctor",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Object, corLib.IntPtr)),
                ControlSetText = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "set_Text",
                    MethodSignature.CreateInstance(corLib.Void, corLib.String)),
                ControlSetName = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "set_Name",
                    MethodSignature.CreateInstance(corLib.Void, corLib.String)),
                ControlSetLeft = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "set_Left",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Int32)),
                ControlSetTop = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "set_Top",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Int32)),
                ControlSetWidth = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "set_Width",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Int32)),
                ControlSetHeight = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "set_Height",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Int32)),
                ControlSetTabIndex = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "set_TabIndex",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Int32)),
                ControlSetAnchor = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "set_Anchor",
                    MethodSignature.CreateInstance(corLib.Void, new TypeDefOrRefSignature(
                        new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "AnchorStyles"),
                        isValueType: true))),
                ControlGetControls = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "get_Controls",
                    MethodSignature.CreateInstance(new TypeDefOrRefSignature(controlCollectionType))),
                ControlAddClick = new AsmResolver.DotNet.MemberReference(
                    controlType,
                    "add_Click",
                    MethodSignature.CreateInstance(corLib.Void, new TypeDefOrRefSignature(eventHandlerType))),
                ControlCollectionAdd = new AsmResolver.DotNet.MemberReference(
                    controlCollectionType,
                    "Add",
                    MethodSignature.CreateInstance(corLib.Void, controlSignature)),
                TextBoxSetPasswordChar = new AsmResolver.DotNet.MemberReference(
                    textBoxType,
                    "set_PasswordChar",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Char)),
                ButtonBaseSetUseVisualStyleBackColor = new AsmResolver.DotNet.MemberReference(
                    new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "ButtonBase"),
                    "set_UseVisualStyleBackColor",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Boolean)),
                FormSetClientSize = new AsmResolver.DotNet.MemberReference(
                    formType,
                    "set_ClientSize",
                    MethodSignature.CreateInstance(corLib.Void, new TypeDefOrRefSignature(sizeType, isValueType: true))),
                ContainerSetAutoScaleDimensions = new AsmResolver.DotNet.MemberReference(
                    containerControlType,
                    "set_AutoScaleDimensions",
                    MethodSignature.CreateInstance(corLib.Void, new TypeDefOrRefSignature(sizeFType, isValueType: true))),
                ContainerSetAutoScaleMode = new AsmResolver.DotNet.MemberReference(
                    containerControlType,
                    "set_AutoScaleMode",
                    MethodSignature.CreateInstance(corLib.Void, new TypeDefOrRefSignature(autoScaleModeType, isValueType: true))),
                FormSetFormBorderStyle = new AsmResolver.DotNet.MemberReference(
                    formType,
                    "set_FormBorderStyle",
                    MethodSignature.CreateInstance(corLib.Void, new TypeDefOrRefSignature(formBorderStyleType, isValueType: true))),
                FormSetStartPosition = new AsmResolver.DotNet.MemberReference(
                    formType,
                    "set_StartPosition",
                    MethodSignature.CreateInstance(corLib.Void, new TypeDefOrRefSignature(formStartPositionType, isValueType: true))),
                FormSetMaximizeBox = new AsmResolver.DotNet.MemberReference(
                    formType,
                    "set_MaximizeBox",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Boolean)),
                FormSetMinimizeBox = new AsmResolver.DotNet.MemberReference(
                    formType,
                    "set_MinimizeBox",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Boolean)),
                FormDisposeBool = new AsmResolver.DotNet.MemberReference(
                    formType,
                    "Dispose",
                    MethodSignature.CreateInstance(corLib.Void, corLib.Boolean)),
                DisposableDispose = new AsmResolver.DotNet.MemberReference(
                    disposableType,
                    "Dispose",
                    MethodSignature.CreateInstance(corLib.Void)),
                Module = module,
                FormBaseType = formBaseType
            };

            // Build WndProc override references (needed to inject explicit WM_CLOSE handler).
            var messageType = new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "Message");
            var messageByRef = new ByReferenceTypeSignature(new TypeDefOrRefSignature(messageType, isValueType: true));
            var applicationType = new AsmResolver.DotNet.TypeReference(module, scope, "System.Windows.Forms", "Application");

            refs.MessageByRefType = messageByRef;
            refs.ApplicationExit = new AsmResolver.DotNet.MemberReference(
                applicationType, "Exit", MethodSignature.CreateStatic(corLib.Void));
            refs.FormWndProc = new AsmResolver.DotNet.MemberReference(
                formType, "WndProc", MethodSignature.CreateInstance(corLib.Void, messageByRef));
            refs.MessageGetMsg = new AsmResolver.DotNet.MemberReference(
                messageType, "get_Msg", MethodSignature.CreateInstance(corLib.Int32));

            return true;
        }

        private bool TryRewriteWindowsFormsConstructorFromSnapshot(
            AsmResolver.DotNet.MethodDefinition ctor,
            AsmResolver.DotNet.TypeDefinition formType,
            WinFormsSnapshot snapshot,
            WindowsFormsControlReferences refs)
        {
            if (ctor == null || formType == null || snapshot == null || refs?.Module == null)
                return false;

            var body = new CilMethodBody(ctor)
            {
                InitializeLocals = true,
                ComputeMaxStackOnBuild = true
            };

            var assignedFields = new HashSet<AsmResolver.DotNet.FieldDefinition>();
            var clickHandler = FindWindowsFormsClickHandler(formType);

            var il = body.Instructions;
            il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            il.Add(new CilInstruction(CilOpCodes.Call, refs.FormCtor));

            ApplyFormSnapshotProperties(il, snapshot, refs);

            foreach (var control in snapshot.Controls)
            {
                var slot = EmitCreateSnapshotControl(
                    formType,
                    body,
                    control,
                    refs,
                    assignedFields,
                    clickHandler);
                if (slot == null)
                    return false;

                EmitAddControlToForm(il, slot, refs);
            }

            il.Add(new CilInstruction(CilOpCodes.Ret));
            ctor.CilMethodBody = body;

            MaybeInjectSyntheticWndProcCloseOverride(ctor.DeclaringType, refs);
            return true;
        }

        private static void ApplyFormSnapshotProperties(
            CilInstructionCollection il,
            WinFormsSnapshot snapshot,
            WindowsFormsControlReferences refs)
        {
            if (snapshot.AutoScaleWidth.HasValue && snapshot.AutoScaleHeight.HasValue &&
                refs.ContainerSetAutoScaleDimensions != null && refs.SizeFCtor != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldc_R4, snapshot.AutoScaleWidth.Value));
                il.Add(new CilInstruction(CilOpCodes.Ldc_R4, snapshot.AutoScaleHeight.Value));
                il.Add(new CilInstruction(CilOpCodes.Newobj, refs.SizeFCtor));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ContainerSetAutoScaleDimensions));
            }

            if (snapshot.AutoScaleMode.HasValue && refs.ContainerSetAutoScaleMode != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldc_I4, snapshot.AutoScaleMode.Value));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ContainerSetAutoScaleMode));
            }

            if ((snapshot.ClientWidth ?? 0) > 0 && (snapshot.ClientHeight ?? 0) > 0 &&
                refs.FormSetClientSize != null && refs.SizeCtor != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldc_I4, snapshot.ClientWidth.Value));
                il.Add(new CilInstruction(CilOpCodes.Ldc_I4, snapshot.ClientHeight.Value));
                il.Add(new CilInstruction(CilOpCodes.Newobj, refs.SizeCtor));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.FormSetClientSize));
            }

            if (snapshot.FormBorderStyle.HasValue && refs.FormSetFormBorderStyle != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldc_I4, snapshot.FormBorderStyle.Value));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.FormSetFormBorderStyle));
            }

            if (snapshot.MaximizeBox.HasValue && refs.FormSetMaximizeBox != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(snapshot.MaximizeBox.Value ? CilOpCodes.Ldc_I4_1 : CilOpCodes.Ldc_I4_0));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.FormSetMaximizeBox));
            }

            if (snapshot.MinimizeBox.HasValue && refs.FormSetMinimizeBox != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(snapshot.MinimizeBox.Value ? CilOpCodes.Ldc_I4_1 : CilOpCodes.Ldc_I4_0));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.FormSetMinimizeBox));
            }

            if (snapshot.StartPosition.HasValue && refs.FormSetStartPosition != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldc_I4, snapshot.StartPosition.Value));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.FormSetStartPosition));
            }

            if (!string.IsNullOrEmpty(snapshot.Text))
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldstr, snapshot.Text));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetText));
            }

            if ((snapshot.ClientWidth ?? 0) > 0 && refs.FormSetClientSize == null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldc_I4, snapshot.ClientWidth.Value));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetWidth));
            }

            if ((snapshot.ClientHeight ?? 0) > 0 && refs.FormSetClientSize == null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldc_I4, snapshot.ClientHeight.Value));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetHeight));
            }
        }

        private ControlSlot EmitCreateSnapshotControl(
            AsmResolver.DotNet.TypeDefinition formType,
            CilMethodBody body,
            WinFormsControlSnapshot control,
            WindowsFormsControlReferences refs,
            HashSet<AsmResolver.DotNet.FieldDefinition> assignedFields,
            AsmResolver.DotNet.MethodDefinition clickHandler)
        {
            if (control == null || string.IsNullOrWhiteSpace(control.TypeName))
                return null;

            var controlType = ResolveSnapshotControlType(refs, control.TypeName);
            if (controlType == null)
                return null;

            var ctor = new AsmResolver.DotNet.MemberReference(
                controlType,
                ".ctor",
                MethodSignature.CreateInstance(refs.Module.CorLibTypeFactory.Void));

            var field = ResolveSnapshotControlField(formType, control, assignedFields);
            var slot = new ControlSlot { Field = field, Type = controlType };
            var il = body.Instructions;

            if (field != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Newobj, ctor));
                il.Add(new CilInstruction(CilOpCodes.Stfld, field));
                assignedFields.Add(field);
            }
            else
            {
                var local = new CilLocalVariable(new TypeDefOrRefSignature(controlType));
                body.LocalVariables.Add(local);
                slot.Local = local;
                il.Add(new CilInstruction(CilOpCodes.Newobj, ctor));
                il.Add(new CilInstruction(CilOpCodes.Stloc, local));
            }

            ApplyControlSnapshotProperties(il, slot, control, refs);

            if (clickHandler != null && IsButtonLikeControl(control.TypeName))
            {
                EmitLoadControl(il, slot);
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldftn, clickHandler));
                il.Add(new CilInstruction(CilOpCodes.Newobj, refs.EventHandlerCtor));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlAddClick));
            }

            foreach (var child in control.Controls)
            {
                var childSlot = EmitCreateSnapshotControl(
                    formType,
                    body,
                    child,
                    refs,
                    assignedFields,
                    clickHandler);
                if (childSlot == null)
                    return null;

                EmitAddControlToParent(il, slot, childSlot, refs);
            }

            return slot;
        }

        private static void ApplyControlSnapshotProperties(
            CilInstructionCollection il,
            ControlSlot slot,
            WinFormsControlSnapshot control,
            WindowsFormsControlReferences refs)
        {
            if (!string.IsNullOrEmpty(control.Name))
                EmitStringSetter(il, slot, control.Name, refs.ControlSetName);

            if (!string.IsNullOrEmpty(control.Text))
                EmitStringSetter(il, slot, control.Text, refs.ControlSetText);

            EmitIntSetter(il, slot, control.Left, refs.ControlSetLeft);
            EmitIntSetter(il, slot, control.Top, refs.ControlSetTop);
            if (control.Width > 0)
                EmitIntSetter(il, slot, control.Width, refs.ControlSetWidth);
            if (control.Height > 0)
                EmitIntSetter(il, slot, control.Height, refs.ControlSetHeight);
            EmitIntSetter(il, slot, control.TabIndex, refs.ControlSetTabIndex);

            if (control.Anchor != 0)
                EmitIntSetter(il, slot, control.Anchor, refs.ControlSetAnchor);

            if (control.PasswordChar != 0 &&
                string.Equals(control.TypeName, "System.Windows.Forms.TextBox", StringComparison.Ordinal))
            {
                EmitLoadControl(il, slot);
                il.Add(new CilInstruction(CilOpCodes.Ldc_I4, control.PasswordChar));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.TextBoxSetPasswordChar));
            }

            if (control.UseVisualStyleBackColor.HasValue && IsButtonLikeControl(control.TypeName))
            {
                EmitLoadControl(il, slot);
                il.Add(new CilInstruction(
                    control.UseVisualStyleBackColor.Value ? CilOpCodes.Ldc_I4_1 : CilOpCodes.Ldc_I4_0));
                il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ButtonBaseSetUseVisualStyleBackColor));
            }
        }

        private static void EmitStringSetter(
            CilInstructionCollection il,
            ControlSlot slot,
            string value,
            IMethodDescriptor setter)
        {
            EmitLoadControl(il, slot);
            il.Add(new CilInstruction(CilOpCodes.Ldstr, value));
            il.Add(new CilInstruction(CilOpCodes.Callvirt, setter));
        }

        private static void EmitIntSetter(
            CilInstructionCollection il,
            ControlSlot slot,
            int value,
            IMethodDescriptor setter)
        {
            EmitLoadControl(il, slot);
            il.Add(new CilInstruction(CilOpCodes.Ldc_I4, value));
            il.Add(new CilInstruction(CilOpCodes.Callvirt, setter));
        }

        private static void EmitAddControlToForm(
            CilInstructionCollection il,
            ControlSlot child,
            WindowsFormsControlReferences refs)
        {
            il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlGetControls));
            EmitLoadControl(il, child);
            il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlCollectionAdd));
        }

        private static void EmitAddControlToParent(
            CilInstructionCollection il,
            ControlSlot parent,
            ControlSlot child,
            WindowsFormsControlReferences refs)
        {
            EmitLoadControl(il, parent);
            il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlGetControls));
            EmitLoadControl(il, child);
            il.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlCollectionAdd));
        }

        private static void EmitLoadControl(CilInstructionCollection il, ControlSlot slot)
        {
            if (slot.Field != null)
            {
                il.Add(new CilInstruction(CilOpCodes.Ldarg_0));
                il.Add(new CilInstruction(CilOpCodes.Ldfld, slot.Field));
                return;
            }

            il.Add(new CilInstruction(CilOpCodes.Ldloc, slot.Local));
        }

        private static ITypeDefOrRef ResolveSnapshotControlType(
            WindowsFormsControlReferences refs,
            string fullName)
        {
            var module = refs.Module;
            var existing = module.GetAllTypes()
                .FirstOrDefault(t => string.Equals(t.FullName, fullName, StringComparison.Ordinal));
            if (existing != null)
                return existing;

            var scope = GetReferenceScopeForType(refs, fullName);
            var ns = GetTypeNamespace(fullName);
            var name = GetTypeNameOnly(fullName);
            return new AsmResolver.DotNet.TypeReference(module, scope, ns, name);
        }

        private static IResolutionScope GetReferenceScopeForType(
            WindowsFormsControlReferences refs,
            string fullName)
        {
            if (fullName.StartsWith("System.Windows.Forms.", StringComparison.Ordinal))
                return (refs.FormBaseType as AsmResolver.DotNet.TypeReference)?.Scope
                    ?? refs.Module.CorLibTypeFactory.CorLibScope;

            if (fullName.StartsWith("System.Drawing.", StringComparison.Ordinal))
            {
                var existing = refs.Module.AssemblyReferences
                    .FirstOrDefault(r => string.Equals(r.Name, "System.Drawing", StringComparison.OrdinalIgnoreCase));
                if (existing != null)
                    return existing;

                var created = new AsmResolver.DotNet.AssemblyReference(
                    "System.Drawing",
                    new Version(4, 0, 0, 0));
                refs.Module.AssemblyReferences.Add(created);
                return created;
            }

            return refs.Module.CorLibTypeFactory.CorLibScope;
        }

        private static IResolutionScope GetReferenceScopeForTypeName(
            AsmResolver.DotNet.ModuleDefinition module,
            string fullName)
        {
            if (fullName.StartsWith("System.Drawing.", StringComparison.Ordinal))
            {
                var existing = module.AssemblyReferences
                    .FirstOrDefault(r => string.Equals(r.Name, "System.Drawing", StringComparison.OrdinalIgnoreCase));
                if (existing != null)
                    return existing;

                var created = new AsmResolver.DotNet.AssemblyReference(
                    "System.Drawing",
                    new Version(4, 0, 0, 0));
                module.AssemblyReferences.Add(created);
                return created;
            }

            return module.CorLibTypeFactory.CorLibScope;
        }

        private static string GetTypeNamespace(string fullName)
        {
            var index = fullName.LastIndexOf('.');
            return index < 0 ? string.Empty : fullName.Substring(0, index);
        }

        private static string GetTypeNameOnly(string fullName)
        {
            var index = fullName.LastIndexOf('.');
            return index < 0 ? fullName : fullName.Substring(index + 1);
        }

        private static AsmResolver.DotNet.FieldDefinition ResolveSnapshotControlField(
            AsmResolver.DotNet.TypeDefinition formType,
            WinFormsControlSnapshot control,
            HashSet<AsmResolver.DotNet.FieldDefinition> assignedFields)
        {
            if (TryParseMetadataToken(control.FieldToken, out var fieldToken))
            {
                var byToken = formType.Fields.FirstOrDefault(f =>
                    f.MetadataToken.ToUInt32() == fieldToken &&
                    !assignedFields.Contains(f));
                if (byToken != null)
                    return byToken;
            }

            if (!string.IsNullOrEmpty(control.FieldName))
            {
                var byName = formType.Fields.FirstOrDefault(f =>
                    string.Equals(f.Name, control.FieldName, StringComparison.Ordinal) &&
                    !assignedFields.Contains(f));
                if (byName != null)
                    return byName;
            }

            return formType.Fields.FirstOrDefault(f =>
                !f.IsStatic &&
                f.Signature?.FieldType != null &&
                string.Equals(f.Signature.FieldType.FullName, control.TypeName, StringComparison.Ordinal) &&
                !assignedFields.Contains(f));
        }

        private static bool IsButtonLikeControl(string typeName)
        {
            return string.Equals(typeName, "System.Windows.Forms.Button", StringComparison.Ordinal) ||
                   string.Equals(typeName, "System.Windows.Forms.ButtonBase", StringComparison.Ordinal) ||
                   string.Equals(typeName, "System.Windows.Forms.CheckBox", StringComparison.Ordinal) ||
                   string.Equals(typeName, "System.Windows.Forms.RadioButton", StringComparison.Ordinal);
        }

        private void RewriteWindowsFormsConstructor(
            AsmResolver.DotNet.MethodDefinition ctor,
            AsmResolver.DotNet.FieldDefinition textBoxField,
            AsmResolver.DotNet.MethodDefinition clickHandler,
            WindowsFormsControlReferences refs)
        {
            var body = new CilMethodBody(ctor)
            {
                InitializeLocals = true,
                ComputeMaxStackOnBuild = true
            };
            var buttonLocal = new CilLocalVariable(new TypeDefOrRefSignature(refs.ButtonType));
            body.LocalVariables.Add(buttonLocal);
            var instructions = body.Instructions;

            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Call, refs.FormCtor));
            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Ldstr, "NET Reactor Unpack Me"));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetText));
            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 360));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetWidth));
            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 150));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetHeight));

            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Newobj, refs.TextBoxCtor));
            instructions.Add(new CilInstruction(CilOpCodes.Stfld, textBoxField));
            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Ldfld, textBoxField));
            instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 20));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetLeft));
            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Ldfld, textBoxField));
            instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 20));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetTop));
            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Ldfld, textBoxField));
            instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 210));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetWidth));

            instructions.Add(new CilInstruction(CilOpCodes.Newobj, refs.ButtonCtor));
            instructions.Add(new CilInstruction(CilOpCodes.Stloc, buttonLocal));
            instructions.Add(new CilInstruction(CilOpCodes.Ldloc, buttonLocal));
            instructions.Add(new CilInstruction(CilOpCodes.Ldstr, "Check"));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetText));
            instructions.Add(new CilInstruction(CilOpCodes.Ldloc, buttonLocal));
            instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 240));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetLeft));
            instructions.Add(new CilInstruction(CilOpCodes.Ldloc, buttonLocal));
            instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 18));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetTop));
            instructions.Add(new CilInstruction(CilOpCodes.Ldloc, buttonLocal));
            instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 80));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetWidth));
            instructions.Add(new CilInstruction(CilOpCodes.Ldloc, buttonLocal));
            instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 26));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlSetHeight));
            instructions.Add(new CilInstruction(CilOpCodes.Ldloc, buttonLocal));
            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Ldftn, clickHandler));
            instructions.Add(new CilInstruction(CilOpCodes.Newobj, refs.EventHandlerCtor));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlAddClick));

            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlGetControls));
            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Ldfld, textBoxField));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlCollectionAdd));
            instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlGetControls));
            instructions.Add(new CilInstruction(CilOpCodes.Ldloc, buttonLocal));
            instructions.Add(new CilInstruction(CilOpCodes.Callvirt, refs.ControlCollectionAdd));
            instructions.Add(new CilInstruction(CilOpCodes.Ret));

            ctor.CilMethodBody = body;

            MaybeInjectSyntheticWndProcCloseOverride(ctor.DeclaringType, refs);
        }

        private static void MaybeInjectSyntheticWndProcCloseOverride(
            AsmResolver.DotNet.TypeDefinition type,
            WindowsFormsControlReferences refs)
        {
            // Normal WinForms exits when the main form passed to Application.Run closes.
            // Keep this synthetic WM_CLOSE shim opt-in so recovered output does not
            // invent close behavior that was not present in the original payload.
            if (!IsSyntheticWinFormsCloseOverrideEnabled())
                return;

            InjectWndProcCloseOverride(type, refs);
        }

        private static bool IsSyntheticWinFormsCloseOverrideEnabled()
        {
            var value = Environment.GetEnvironmentVariable("KRYPTON_WINFORMS_CLOSE_OVERRIDE") ??
                        Environment.GetEnvironmentVariable("KRYPTON_ENABLE_WINFORMS_CLOSE_OVERRIDE");
            if (string.IsNullOrWhiteSpace(value))
                return false;

            value = value.Trim();
            return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "on", StringComparison.OrdinalIgnoreCase);
        }

        private static void InjectWndProcCloseOverride(
            AsmResolver.DotNet.TypeDefinition type,
            WindowsFormsControlReferences refs)
        {
            if (refs.MessageByRefType == null || refs.ApplicationExit == null ||
                refs.FormWndProc == null || refs.MessageGetMsg == null)
                return;

            // Skip if the type already has a WndProc override (e.g. was not a stub).
            if (type.Methods.Any(m =>
                    !m.IsStatic &&
                    string.Equals(m.Name, "WndProc", StringComparison.Ordinal)))
                return;

            var methodSig = MethodSignature.CreateInstance(
                refs.Module.CorLibTypeFactory.Void,
                refs.MessageByRefType);

            var wndProc = new AsmResolver.DotNet.MethodDefinition(
                "WndProc",
                MethodAttributes.Family |
                MethodAttributes.Virtual |
                MethodAttributes.HideBySig,
                methodSig);

            var body = new CilMethodBody(wndProc) { ComputeMaxStackOnBuild = true };
            var callBaseLabel = new CilInstruction(CilOpCodes.Ldarg_0);

            var il = body.Instructions;
            // if (m.Msg == WM_CLOSE) { Application.Exit(); return; }
            il.Add(new CilInstruction(CilOpCodes.Ldarg_1));
            il.Add(new CilInstruction(CilOpCodes.Call, refs.MessageGetMsg));
            il.Add(new CilInstruction(CilOpCodes.Ldc_I4, 0x0010)); // WM_CLOSE
            il.Add(new CilInstruction(CilOpCodes.Bne_Un, new CilInstructionLabel(callBaseLabel)));
            il.Add(new CilInstruction(CilOpCodes.Call, refs.ApplicationExit));
            il.Add(new CilInstruction(CilOpCodes.Ret));
            // base.WndProc(ref m)
            il.Add(callBaseLabel);
            il.Add(new CilInstruction(CilOpCodes.Ldarg_1));
            il.Add(new CilInstruction(CilOpCodes.Call, refs.FormWndProc));
            il.Add(new CilInstruction(CilOpCodes.Ret));

            wndProc.CilMethodBody = body;
            type.Methods.Add(wndProc);
        }

        private sealed class WindowsFormsControlReferences
        {
            public ITypeDefOrRef ButtonType { get; set; }
            public IMethodDescriptor FormCtor { get; set; }
            public IMethodDescriptor TextBoxCtor { get; set; }
            public IMethodDescriptor ButtonCtor { get; set; }
            public IMethodDescriptor SizeCtor { get; set; }
            public IMethodDescriptor SizeFCtor { get; set; }
            public IMethodDescriptor EventHandlerCtor { get; set; }
            public IMethodDescriptor ControlSetText { get; set; }
            public IMethodDescriptor ControlSetName { get; set; }
            public IMethodDescriptor ControlSetLeft { get; set; }
            public IMethodDescriptor ControlSetTop { get; set; }
            public IMethodDescriptor ControlSetWidth { get; set; }
            public IMethodDescriptor ControlSetHeight { get; set; }
            public IMethodDescriptor ControlSetTabIndex { get; set; }
            public IMethodDescriptor ControlSetAnchor { get; set; }
            public IMethodDescriptor ControlGetControls { get; set; }
            public IMethodDescriptor ControlAddClick { get; set; }
            public IMethodDescriptor ControlCollectionAdd { get; set; }
            public IMethodDescriptor TextBoxSetPasswordChar { get; set; }
            public IMethodDescriptor ButtonBaseSetUseVisualStyleBackColor { get; set; }
            public IMethodDescriptor FormSetClientSize { get; set; }
            public IMethodDescriptor ContainerSetAutoScaleDimensions { get; set; }
            public IMethodDescriptor ContainerSetAutoScaleMode { get; set; }
            public IMethodDescriptor FormSetFormBorderStyle { get; set; }
            public IMethodDescriptor FormSetStartPosition { get; set; }
            public IMethodDescriptor FormSetMaximizeBox { get; set; }
            public IMethodDescriptor FormSetMinimizeBox { get; set; }
            public IMethodDescriptor FormDisposeBool { get; set; }
            public IMethodDescriptor DisposableDispose { get; set; }
            // WndProc override support
            public AsmResolver.DotNet.ModuleDefinition Module { get; set; }
            public ITypeDefOrRef FormBaseType { get; set; }
            public IMethodDescriptor ApplicationExit { get; set; }
            public IMethodDescriptor FormWndProc { get; set; }
            public IMethodDescriptor MessageGetMsg { get; set; }
            public TypeSignature MessageByRefType { get; set; }
        }

        private sealed class WinFormsSnapshot
        {
            public string TypeName { get; set; }
            public string TypeToken { get; set; }
            public string Text { get; set; }
            public int? ClientWidth { get; set; }
            public int? ClientHeight { get; set; }
            public int? FormBorderStyle { get; set; }
            public int? StartPosition { get; set; }
            public bool? MaximizeBox { get; set; }
            public bool? MinimizeBox { get; set; }
            public int? AutoScaleMode { get; set; }
            public float? AutoScaleWidth { get; set; }
            public float? AutoScaleHeight { get; set; }
            public List<WinFormsControlSnapshot> Controls { get; } = new List<WinFormsControlSnapshot>();
        }

        private sealed class WinFormsControlSnapshot
        {
            public string TypeName { get; set; }
            public string FieldName { get; set; }
            public string FieldToken { get; set; }
            public string Name { get; set; }
            public string Text { get; set; }
            public int Left { get; set; }
            public int Top { get; set; }
            public int Width { get; set; }
            public int Height { get; set; }
            public int TabIndex { get; set; }
            public int Anchor { get; set; }
            public int PasswordChar { get; set; }
            public bool? UseVisualStyleBackColor { get; set; }
            public List<WinFormsControlSnapshot> Controls { get; } = new List<WinFormsControlSnapshot>();
        }

        private sealed class ControlSlot
        {
            public AsmResolver.DotNet.FieldDefinition Field { get; set; }
            public CilLocalVariable Local { get; set; }
            public ITypeDefOrRef Type { get; set; }
        }

        private sealed class PayloadBuffer
        {
            public string Name { get; set; }
            public byte[] Data { get; set; }
        }

        private sealed class HiddenCallEntry
        {
            public string DeclaringType { get; set; }
            public string MethodName { get; set; }
            public string MemberSig { get; set; }
        }

        private sealed class RawIlInstruction
        {
            public int Offset { get; set; }
            public int Op { get; set; }
            public uint Token { get; set; }
            public int? Int32 { get; set; }
            public float? Single { get; set; }
        }

        private int RepairStaticDataInitializers(AsmResolver.DotNet.ModuleDefinition module)
        {
            var repaired = 0;
            foreach (var type in module.GetAllTypes())
            {
                var cctor = type.Methods.FirstOrDefault(m =>
                    m.IsStatic &&
                    string.Equals(m.Name, ".cctor", StringComparison.Ordinal) &&
                    m.CilMethodBody != null);
                if (cctor?.CilMethodBody == null)
                    continue;

                if (TryRepairStaticDataInitializer(module, cctor))
                    repaired++;
            }

            return repaired;
        }

        private bool TryRepairStaticDataInitializer(
            AsmResolver.DotNet.ModuleDefinition module,
            AsmResolver.DotNet.MethodDefinition cctor)
        {
            var body = cctor.CilMethodBody;
            var instructions = body.Instructions;
            if (instructions.Count < 12)
                return false;

            IMethodDescriptor initArray = null;
            IFieldDescriptor initWrapperField = null;
            IFieldDescriptor tokenField = null;
            AsmResolver.DotNet.FieldDefinition targetField = null;
            var arrayLength = -1;

            for (var i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode.Code != CilCode.Call && instruction.OpCode.Code != CilCode.Callvirt) ||
                    !(instruction.Operand is IMethodDescriptor method))
                {
                    continue;
                }

                if (!IsInitializeArrayCall(method) && !IsInitializeArrayWrapper(method))
                    continue;

                initArray = method;
                for (var j = i - 1; j >= 0; j--)
                {
                    var previous = instructions[j];
                    if (tokenField == null &&
                        previous.OpCode.Code == CilCode.Ldtoken &&
                        previous.Operand is IFieldDescriptor fieldDescriptor)
                    {
                        tokenField = fieldDescriptor;
                    }

                    if (initWrapperField == null &&
                        previous.OpCode.Code == CilCode.Ldsfld &&
                        previous.Operand is IFieldDescriptor wrapperField)
                    {
                        initWrapperField = wrapperField;
                    }

                    if (arrayLength < 0 && TryGetLdcI4Value(previous, out var length))
                        arrayLength = length;

                    if (tokenField != null && arrayLength >= 0)
                        break;
                }

                for (var j = i + 1; j < instructions.Count; j++)
                {
                    var next = instructions[j];
                    if (next.OpCode.Code == CilCode.Stsfld && next.Operand is AsmResolver.DotNet.FieldDefinition field)
                    {
                        targetField = field;
                        break;
                    }
                }

                break;
            }

            if (arrayLength < 0 && tokenField != null)
                arrayLength = TryGetArrayLengthFromFieldToken(tokenField);

            if (initArray == null ||
                tokenField == null ||
                targetField == null ||
                arrayLength <= 0 ||
                !IsByteArrayField(targetField))
            {
                return false;
            }

            var replacementInitArray = IsInitializeArrayCall(initArray)
                ? initArray
                : FindRuntimeHelpersInitializeArrayReference(module);
            if (replacementInitArray == null)
                return false;

            var corlib = module.CorLibTypeFactory;
            var arrayType = new SzArrayTypeSignature(corlib.Byte);
            var replacement = new CilMethodBody(cctor)
            {
                InitializeLocals = true,
                ComputeMaxStackOnBuild = true
            };
            var local = new CilLocalVariable(arrayType);
            replacement.LocalVariables.Add(local);

            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, arrayLength));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Newarr, corlib.Byte.Type));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Stloc, local));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, local));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ldtoken, tokenField));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Call, replacementInitArray));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, local));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Stsfld, targetField));
            replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ret));

            cctor.CilMethodBody = replacement;
            return true;
        }

        private bool IsInitializeArrayCall(IMethodDescriptor method)
        {
            if (method == null)
                return false;

            AsmResolver.DotNet.MethodDefinition resolved = null;
            try
            {
                resolved = method.Resolve();
            }
            catch
            {
                // Protected metadata may be partially malformed; keep signature/name fallback.
            }

            var name = method.Name ?? resolved?.Name;
            var declaringTypeFullName = method.DeclaringType?.FullName ?? resolved?.DeclaringType?.FullName;
            return string.Equals(name, "InitializeArray", StringComparison.Ordinal) &&
                   string.Equals(
                       declaringTypeFullName,
                       "System.Runtime.CompilerServices.RuntimeHelpers",
                       StringComparison.Ordinal);
        }

        private IMethodDescriptor FindRuntimeHelpersInitializeArrayReference(AsmResolver.DotNet.ModuleDefinition module)
        {
            if (module == null)
                return null;

            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    var body = method.CilMethodBody;
                    if (body == null)
                        continue;

                    foreach (var instruction in body.Instructions)
                    {
                        if (instruction.OpCode.Code != CilCode.Call &&
                            instruction.OpCode.Code != CilCode.Callvirt)
                        {
                            continue;
                        }

                        var descriptor = instruction.Operand as IMethodDescriptor;
                        if (descriptor != null && IsInitializeArrayCall(descriptor))
                            return descriptor;
                    }
                }
            }

            return null;
        }

        private bool IsInitializeArrayWrapper(IMethodDescriptor method)
        {
            if (method?.Signature == null || method.Signature.ParameterTypes.Count < 2)
                return false;

            return string.Equals(
                method.Signature.ParameterTypes[1]?.FullName,
                "System.RuntimeFieldHandle",
                StringComparison.Ordinal);
        }

        private bool RequiresInitializeArrayWrapperField(
            IMethodDescriptor method,
            IFieldDescriptor wrapperField)
        {
            if (method?.Signature == null)
                return false;

            return method.Signature.ParameterTypes.Count >= 3 && wrapperField != null;
        }

        private bool IsByteArrayField(AsmResolver.DotNet.FieldDefinition field)
        {
            var fieldTypeName = field?.Signature?.FieldType?.FullName;
            return string.Equals(fieldTypeName, "System.Byte[]", StringComparison.Ordinal) ||
                   string.Equals(fieldTypeName, "System.Byte[*]", StringComparison.Ordinal);
        }

        private int TryGetArrayLengthFromFieldToken(IFieldDescriptor tokenField)
        {
            try
            {
                var declaringType = tokenField?.DeclaringType?.Resolve();
                if (declaringType?.ClassLayout?.ClassSize > 0)
                    return (int) declaringType.ClassLayout.ClassSize;
            }
            catch
            {
                // Best effort only.
            }

            return -1;
        }

        private int RepairAesTransformFinalBlockLengthPatterns(AsmResolver.DotNet.ModuleDefinition module)
        {
            var repaired = 0;
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    var body = method.CilMethodBody;
                    if (body == null)
                        continue;

                    var instructions = body.Instructions;
                    for (var i = 7; i < instructions.Count; i++)
                    {
                        var call = instructions[i];
                        if ((call.OpCode.Code != CilCode.Callvirt && call.OpCode.Code != CilCode.Call) ||
                            !(call.Operand is IMethodDescriptor descriptor) ||
                            !IsCryptoTransformFinalBlock(descriptor))
                        {
                            continue;
                        }

                        var firstBufferLoad = instructions[i - 7];
                        var offset = instructions[i - 6];
                        var secondBufferLoad = instructions[i - 5];
                        var ldlen = instructions[i - 4];
                        var conv = instructions[i - 3];
                        var lengthAdjustment = instructions[i - 2];
                        var arithmetic = instructions[i - 1];

                        if (!AreSameStackValueLoad(firstBufferLoad, secondBufferLoad))
                            continue;
                        if (!TryGetLdcI4Value(offset, out var offsetValue) || offsetValue != 16)
                            continue;
                        if (ldlen.OpCode.Code != CilCode.Ldlen)
                            continue;
                        if (conv.OpCode.Code != CilCode.Conv_I4)
                            continue;
                        if (!TryGetLdcI4Value(lengthAdjustment, out var lengthAdjustmentValue) ||
                            lengthAdjustmentValue != 16)
                        {
                            continue;
                        }

                        if (arithmetic.OpCode.Code != CilCode.Add)
                            continue;

                        arithmetic.OpCode = CilOpCodes.Sub;
                        arithmetic.Operand = null;
                        repaired++;
                    }
                }
            }

            return repaired;
        }

        private bool IsCryptoTransformFinalBlock(IMethodDescriptor descriptor)
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
                // Metadata in protected assemblies is often partially malformed; signature fallback below is enough.
            }

            if (!string.Equals(descriptor.Name ?? resolved?.Name, "TransformFinalBlock", StringComparison.Ordinal))
                return false;

            var declaringTypeFullName = descriptor.DeclaringType?.FullName ?? resolved?.DeclaringType?.FullName;
            if (!string.Equals(
                    declaringTypeFullName,
                    "System.Security.Cryptography.ICryptoTransform",
                    StringComparison.Ordinal))
            {
                return false;
            }

            var signature = descriptor.Signature ?? resolved?.Signature;
            if (signature == null || signature.ParameterTypes.Count != 3)
                return false;

            return string.Equals(signature.ReturnType?.FullName, "System.Byte[]", StringComparison.Ordinal) &&
                   string.Equals(signature.ParameterTypes[0].FullName, "System.Byte[]", StringComparison.Ordinal) &&
                   string.Equals(signature.ParameterTypes[1].FullName, "System.Int32", StringComparison.Ordinal) &&
                   string.Equals(signature.ParameterTypes[2].FullName, "System.Int32", StringComparison.Ordinal);
        }

        private bool AreSameStackValueLoad(CilInstruction first, CilInstruction second)
        {
            if (!TryGetStackValueLoadIdentity(first, out var firstKind, out var firstValue))
                return false;
            if (!TryGetStackValueLoadIdentity(second, out var secondKind, out var secondValue))
                return false;
            if (!string.Equals(firstKind, secondKind, StringComparison.Ordinal))
                return false;

            return ReferenceEquals(firstValue, secondValue) || Equals(firstValue, secondValue);
        }

        private bool TryGetStackValueLoadIdentity(CilInstruction instruction, out string kind, out object value)
        {
            kind = null;
            value = null;
            if (instruction == null)
                return false;

            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldarg_0:
                    kind = "arg";
                    value = 0;
                    return true;
                case CilCode.Ldarg_1:
                    kind = "arg";
                    value = 1;
                    return true;
                case CilCode.Ldarg_2:
                    kind = "arg";
                    value = 2;
                    return true;
                case CilCode.Ldarg_3:
                    kind = "arg";
                    value = 3;
                    return true;
                case CilCode.Ldarg:
                case CilCode.Ldarg_S:
                    if (instruction.Operand == null)
                        return false;
                    kind = "arg";
                    value = instruction.Operand;
                    return true;
                case CilCode.Ldloc_0:
                    kind = "loc";
                    value = 0;
                    return true;
                case CilCode.Ldloc_1:
                    kind = "loc";
                    value = 1;
                    return true;
                case CilCode.Ldloc_2:
                    kind = "loc";
                    value = 2;
                    return true;
                case CilCode.Ldloc_3:
                    kind = "loc";
                    value = 3;
                    return true;
                case CilCode.Ldloc:
                case CilCode.Ldloc_S:
                    if (instruction.Operand == null)
                        return false;
                    kind = "loc";
                    value = instruction.Operand;
                    return true;
                default:
                    return false;
            }
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
            if (instructions.Count < 1 || instructions.Count > 64)
                return false;

            foreach (var instruction in instructions)
            {
                if (instruction.OpCode.Code != CilCode.Call && instruction.OpCode.Code != CilCode.Callvirt)
                    continue;

                if (!(instruction.Operand is IMethodDescriptor callee))
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

                var calleeBody = calleeDef?.CilMethodBody;
                if (calleeBody == null)
                    continue;

                // Generic heuristic for protector bootstrap stubs:
                // a bounded .cctor dispatches into a huge obfuscated runtime worker.
                if (calleeBody.Instructions.Count >= 500 ||
                    calleeBody.LocalVariables.Count >= 64 ||
                    calleeBody.ExceptionHandlers.Count >= 8)
                {
                    return true;
                }
            }

            return false;
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

        private sealed class ReactorRuntimeCleanupResult
        {
            public int RuntimeTypes { get; set; }
            public int ReachableMethods { get; set; }
            public int StubbedMethods { get; set; }
            public int DisabledPInvokes { get; set; }
            public int TotalChanges => StubbedMethods + DisabledPInvokes;
        }

        private ReactorRuntimeCleanupResult CleanUnusedReactorRuntime(AsmResolver.DotNet.ModuleDefinition module)
        {
            var result = new ReactorRuntimeCleanupResult();
            if (module == null)
                return result;

            var allTypes = module.GetAllTypes().ToList();
            var allMethods = allTypes
                .SelectMany(t => t.Methods)
                .Where(m => m != null)
                .ToHashSet();

            var runtimeTypes = IdentifyReactorRuntimeTypes(allTypes);
            result.RuntimeTypes = runtimeTypes.Count;
            if (runtimeTypes.Count == 0)
                return result;

            var reachable = BuildReachableMethodSet(module, allTypes, allMethods, runtimeTypes);
            result.ReachableMethods = reachable.Count;

            foreach (var type in runtimeTypes.OrderBy(t => t.MetadataToken.ToUInt32()))
            {
                foreach (var method in type.Methods.OrderBy(m => m.MetadataToken.ToUInt32()).ToList())
                {
                    if (method == null)
                        continue;
                    if (reachable.Contains(method))
                        continue;
                    if (method.Signature == null)
                        continue;

                    if (method.ImplementationMap != null)
                    {
                        if (TryDisablePInvokeImport(method))
                        {
                            result.DisabledPInvokes++;
                            result.StubbedMethods++;
                        }
                        continue;
                    }

                    if (method.CilMethodBody == null)
                        continue;

                    // Keep instance constructors verifier-friendly. Runtime .cctors are safe to neutralize.
                    if (method.IsConstructor && !method.IsStatic)
                        continue;

                    if (!TryReplaceWithSafeReturnStub(method))
                        continue;

                    result.StubbedMethods++;
                }
            }

            return result;
        }

        private HashSet<AsmResolver.DotNet.TypeDefinition> IdentifyReactorRuntimeTypes(
            IReadOnlyList<AsmResolver.DotNet.TypeDefinition> allTypes)
        {
            var runtimeTypes = new HashSet<AsmResolver.DotNet.TypeDefinition>();

            foreach (var type in allTypes)
            {
                if (IsReactorRuntimeTypeSeed(type))
                    runtimeTypes.Add(type);
            }

            var changed = true;
            while (changed)
            {
                changed = false;
                foreach (var type in allTypes)
                {
                    if (type == null || runtimeTypes.Contains(type))
                        continue;
                    if (IsPrivateImplementationDetailsType(type))
                        continue;
                    if (!IsLikelyReactorCompanionType(type))
                        continue;
                    if (!CallsAnyRuntimeType(type, runtimeTypes))
                        continue;

                    runtimeTypes.Add(type);
                    changed = true;
                }
            }

            return runtimeTypes;
        }

        private bool IsReactorRuntimeTypeSeed(AsmResolver.DotNet.TypeDefinition type)
        {
            if (type == null)
                return false;
            if (IsPrivateImplementationDetailsType(type))
                return false;

            var fullName = SafeStringify(type.FullName);
            if (string.IsNullOrWhiteSpace(fullName))
                return false;

            if (type.IsModuleType)
                return HasRuntimeLikeStaticConstructor(type) || type.Methods.Count > 0;

            if (fullName.IndexOf("<Module>{", StringComparison.Ordinal) >= 0)
                return true;

            if (ContainsNonAsciiOrControl(fullName))
                return true;

            var maxBody = type.Methods
                .Where(m => m?.CilMethodBody != null)
                .Select(m => m.CilMethodBody.Instructions.Count)
                .DefaultIfEmpty(0)
                .Max();

            return type.Methods.Count >= 40 ||
                   type.Fields.Count >= 30 ||
                   maxBody >= 300;
        }

        private bool IsLikelyReactorCompanionType(AsmResolver.DotNet.TypeDefinition type)
        {
            if (type == null)
                return false;
            if (IsPrivateImplementationDetailsType(type))
                return false;

            var name = SafeStringify(type.Name);
            var ns = SafeStringify(type.Namespace);
            var fullName = SafeStringify(type.FullName);

            if (ContainsNonAsciiOrControl(fullName))
                return true;
            if (fullName.IndexOf("<Module>{", StringComparison.Ordinal) >= 0)
                return true;

            if (string.IsNullOrEmpty(ns) &&
                name.StartsWith("Type_", StringComparison.Ordinal) &&
                type.Methods.Count <= 8)
            {
                return true;
            }

            var baseName = SafeStringify(type.BaseType?.FullName);
            if (string.Equals(baseName, "System.MulticastDelegate", StringComparison.Ordinal) ||
                string.Equals(baseName, "System.Delegate", StringComparison.Ordinal))
            {
                return true;
            }

            return HasRuntimeLikeStaticConstructor(type);
        }

        private bool CallsAnyRuntimeType(
            AsmResolver.DotNet.TypeDefinition type,
            ISet<AsmResolver.DotNet.TypeDefinition> runtimeTypes)
        {
            foreach (var method in type.Methods)
            {
                var body = method?.CilMethodBody;
                if (body == null)
                    continue;

                foreach (var instruction in body.Instructions)
                {
                    if (!IsMethodReferenceInstruction(instruction))
                        continue;
                    if (!(instruction.Operand is IMethodDescriptor descriptor))
                        continue;

                    AsmResolver.DotNet.MethodDefinition resolved;
                    try
                    {
                        resolved = descriptor.Resolve();
                    }
                    catch
                    {
                        continue;
                    }

                    if (resolved?.DeclaringType != null && runtimeTypes.Contains(resolved.DeclaringType))
                        return true;
                }
            }

            return false;
        }

        private bool HasRuntimeLikeStaticConstructor(AsmResolver.DotNet.TypeDefinition type)
        {
            var cctor = type?.Methods?.FirstOrDefault(m =>
                m != null &&
                m.IsStatic &&
                string.Equals(m.Name, ".cctor", StringComparison.Ordinal) &&
                m.CilMethodBody != null);
            if (cctor?.CilMethodBody == null)
                return false;

            foreach (var instruction in cctor.CilMethodBody.Instructions)
            {
                if (!IsMethodReferenceInstruction(instruction))
                    continue;

                var identity = GetMethodIdentity(instruction.Operand as IMethodDescriptor);
                if (identity.IndexOf("RuntimeHelpers", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    identity.IndexOf("Module::Resolve", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    identity.IndexOf("CreateDelegate", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    identity.IndexOf("DynamicMethod", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    identity.IndexOf("GetManifestResourceStream", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private HashSet<AsmResolver.DotNet.MethodDefinition> BuildReachableMethodSet(
            AsmResolver.DotNet.ModuleDefinition module,
            IReadOnlyList<AsmResolver.DotNet.TypeDefinition> allTypes,
            ISet<AsmResolver.DotNet.MethodDefinition> allMethods,
            ISet<AsmResolver.DotNet.TypeDefinition> runtimeTypes)
        {
            var reachable = new HashSet<AsmResolver.DotNet.MethodDefinition>();
            var queue = new Queue<AsmResolver.DotNet.MethodDefinition>();

            void AddMethod(AsmResolver.DotNet.MethodDefinition method)
            {
                if (method == null || !allMethods.Contains(method))
                    return;
                if (!reachable.Add(method))
                    return;

                queue.Enqueue(method);

                if (method.DeclaringType != null && !runtimeTypes.Contains(method.DeclaringType))
                {
                    var cctor = GetStaticConstructor(method.DeclaringType);
                    if (cctor != null && !ReferenceEquals(cctor, method))
                        AddMethod(cctor);
                }
            }

            AddMethod(module.ManagedEntryPoint as AsmResolver.DotNet.MethodDefinition);
            AddMethod(module.ManagedEntryPointMethod);

            foreach (var vmMethod in Ctx.VirtualizedMethods ?? Array.Empty<Core.Architecture.VMMethod>())
            {
                if (vmMethod?.Parent != null &&
                    vmMethod.RecompiledBody != null &&
                    !runtimeTypes.Contains(vmMethod.Parent.DeclaringType))
                {
                    AddMethod(vmMethod.Parent);
                }
            }

            var rootAllApplicationTypes = GetFeatureToggle(
                "KRYPTON_REACTOR_CLEAN_ROOT_ALL_APP_TYPES",
                defaultEnabled: false,
                disableVariableName: "KRYPTON_DISABLE_REACTOR_CLEAN_ROOT_ALL_APP_TYPES");
            if (rootAllApplicationTypes)
            {
                foreach (var type in allTypes)
                {
                    if (!IsApplicationPreservationRootType(type, runtimeTypes))
                        continue;

                    foreach (var method in type.Methods)
                        AddMethod(method);
                }
            }

            while (queue.Count > 0)
            {
                var method = queue.Dequeue();
                var body = method.CilMethodBody;
                if (body == null)
                    continue;

                foreach (var instruction in body.Instructions)
                {
                    if (IsMethodReferenceInstruction(instruction) &&
                        instruction.Operand is IMethodDescriptor descriptor &&
                        TryResolveModuleMethod(descriptor, allMethods, out var callee))
                    {
                        AddMethod(callee);
                    }

                    if (IsStaticFieldReferenceInstruction(instruction) &&
                        TryResolveModuleField(instruction.Operand, out var field))
                    {
                        AddMethod(GetStaticConstructor(field.DeclaringType));
                    }
                }
            }

            return reachable;
        }

        private bool IsApplicationPreservationRootType(
            AsmResolver.DotNet.TypeDefinition type,
            ISet<AsmResolver.DotNet.TypeDefinition> runtimeTypes)
        {
            if (type == null)
                return false;
            if (runtimeTypes.Contains(type))
                return false;
            if (type.IsModuleType)
                return false;
            if (IsPrivateImplementationDetailsType(type))
                return false;

            return true;
        }

        private AsmResolver.DotNet.MethodDefinition GetStaticConstructor(
            AsmResolver.DotNet.TypeDefinition type)
        {
            return type?.Methods?.FirstOrDefault(m =>
                m != null &&
                m.IsStatic &&
                string.Equals(m.Name, ".cctor", StringComparison.Ordinal));
        }

        private bool TryResolveModuleMethod(
            IMethodDescriptor descriptor,
            ISet<AsmResolver.DotNet.MethodDefinition> allMethods,
            out AsmResolver.DotNet.MethodDefinition method)
        {
            method = null;
            if (descriptor == null)
                return false;

            if (descriptor is AsmResolver.DotNet.MethodDefinition direct && allMethods.Contains(direct))
            {
                method = direct;
                return true;
            }

            try
            {
                var resolved = descriptor.Resolve();
                if (resolved != null && allMethods.Contains(resolved))
                {
                    method = resolved;
                    return true;
                }
            }
            catch
            {
                // Best effort for malformed protector metadata.
            }

            return false;
        }

        private bool TryResolveModuleField(object operand, out AsmResolver.DotNet.FieldDefinition field)
        {
            field = null;

            if (operand is AsmResolver.DotNet.FieldDefinition direct)
            {
                field = direct;
                return true;
            }

            if (!(operand is IFieldDescriptor descriptor))
                return false;

            try
            {
                field = descriptor.Resolve();
                return field != null;
            }
            catch
            {
                return false;
            }
        }

        private bool IsMethodReferenceInstruction(CilInstruction instruction)
        {
            if (instruction == null)
                return false;

            return instruction.OpCode.Code == CilCode.Call ||
                   instruction.OpCode.Code == CilCode.Callvirt ||
                   instruction.OpCode.Code == CilCode.Newobj ||
                   instruction.OpCode.Code == CilCode.Ldftn ||
                   instruction.OpCode.Code == CilCode.Ldvirtftn;
        }

        private bool IsStaticFieldReferenceInstruction(CilInstruction instruction)
        {
            if (instruction == null)
                return false;

            return instruction.OpCode.Code == CilCode.Ldsfld ||
                   instruction.OpCode.Code == CilCode.Ldsflda ||
                   instruction.OpCode.Code == CilCode.Stsfld;
        }

        private bool TryDisablePInvokeImport(AsmResolver.DotNet.MethodDefinition method)
        {
            if (method?.ImplementationMap == null)
                return false;

            try
            {
                method.ImplementationMap = null;
                method.Attributes &= ~MethodAttributes.PInvokeImpl;
            }
            catch
            {
                return false;
            }

            return TryReplaceWithSafeReturnStub(method);
        }

        private int StripAntiIldasmAttributes(AsmResolver.DotNet.ModuleDefinition module)
        {
            if (module == null)
                return 0;

            var removed = 0;
            removed += RemoveAntiIldasmAttributes(module);

            if (module.Assembly != null)
                removed += RemoveAntiIldasmAttributes(module.Assembly);

            foreach (var type in module.GetAllTypes())
            {
                removed += RemoveAntiIldasmAttributes(type);

                foreach (var genericParameter in type.GenericParameters)
                    removed += RemoveAntiIldasmAttributes(genericParameter);

                foreach (var field in type.Fields)
                    removed += RemoveAntiIldasmAttributes(field);

                foreach (var method in type.Methods)
                {
                    removed += RemoveAntiIldasmAttributes(method);

                    foreach (var parameter in method.ParameterDefinitions)
                        removed += RemoveAntiIldasmAttributes(parameter);

                    foreach (var genericParameter in method.GenericParameters)
                        removed += RemoveAntiIldasmAttributes(genericParameter);
                }

                foreach (var property in type.Properties)
                    removed += RemoveAntiIldasmAttributes(property);

                foreach (var evt in type.Events)
                    removed += RemoveAntiIldasmAttributes(evt);
            }

            return removed;
        }

        private int RemoveAntiIldasmAttributes(AsmResolver.DotNet.IHasCustomAttribute provider)
        {
            if (provider?.CustomAttributes == null || provider.CustomAttributes.Count == 0)
                return 0;

            var removed = 0;
            for (var i = provider.CustomAttributes.Count - 1; i >= 0; i--)
            {
                var attribute = provider.CustomAttributes[i];
                var identity = SafeStringify(attribute?.Constructor);
                if (attribute?.Constructor is IMethodDescriptor ctor)
                {
                    identity += " " + SafeStringify(ctor.FullName);
                    identity += " " + SafeStringify(ctor.DeclaringType?.FullName);
                }

                if (identity.IndexOf("SuppressIldasm", StringComparison.OrdinalIgnoreCase) < 0)
                    continue;

                provider.CustomAttributes.RemoveAt(i);
                removed++;
            }

            return removed;
        }

        private bool IsPrivateImplementationDetailsType(AsmResolver.DotNet.TypeDefinition type)
        {
            var fullName = SafeStringify(type?.FullName);
            return fullName.StartsWith("<PrivateImplementationDetails>", StringComparison.Ordinal);
        }

        private bool ContainsNonAsciiOrControl(string value)
        {
            if (string.IsNullOrEmpty(value))
                return false;

            foreach (var ch in value)
            {
                if (ch < 0x20 || ch > 0x7E)
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
