using System;
using System.IO;
using System.Linq;
using System.Text;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    public class MethodReplacing : IStage
    {
        public string Name => nameof(MethodReplacing);

        public void Run(DevirtualizationCtx Ctx)
        {
            var replaced = 0;
            var skippedByPolicy = 0;
            var skippedBySemanticGate = 0;
            var skippedByIlSafetyGate = 0;
            var skippedByGlobalDisable = 0;
            var disableAllReplacement = string.Equals(
                Environment.GetEnvironmentVariable("KRYPTON_DISABLE_METHOD_REPLACEMENT"),
                "1",
                StringComparison.Ordinal);
            var replacementPolicy = new ReplacementPolicyProfile();
            var skipModuleMethods = replacementPolicy.SkipModuleMethods;
            if (string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_SKIP_MODULE_METHODS"),
                    "1",
                    StringComparison.Ordinal))
            {
                skipModuleMethods = true;
            }
            else if (string.Equals(
                         Environment.GetEnvironmentVariable("KRYPTON_REPLACE_MODULE_METHODS"),
                         "1",
                         StringComparison.Ordinal))
            {
                skipModuleMethods = false;
            }
            var skipHighPopRatioMethods = replacementPolicy.SkipHighPopRatioMethods;
            var highPopRatioThreshold = replacementPolicy.HighPopRatioThreshold;
            var highPopRatioMinInstructionCount = replacementPolicy.HighPopRatioMinInstructionCount;
            var maxCilIssues = ReadNonNegativeIntFromEnvironment(
                "KRYPTON_MAX_RECOMPILED_CIL_ISSUES",
                512);
            var maxDnlibIssues = ReadNonNegativeIntFromEnvironment(
                "KRYPTON_MAX_RECOMPILED_DNLIB_ISSUES",
                int.MaxValue);
            var semanticValidator = Ctx.VmSemanticValidator as SemanticValidation;
            foreach (var method in Ctx.VirtualizedMethods)
            {
                if (method.Parent == null || method.RecompiledBody == null)
                    continue;
                if (disableAllReplacement)
                {
                    skippedByGlobalDisable++;
                    method.RecompiledBody = null;
                    continue;
                }
                if (skipModuleMethods && IsModuleMethod(method.Parent))
                {
                    skippedByPolicy++;
                    Ctx.Options.Logger.Warning(
                        $"Skipping replacement for module method by replacement policy: {method.Parent.FullName}");
                    method.RecompiledBody = null;
                    continue;
                }
                if (skipHighPopRatioMethods &&
                    IsHighPopRatioMethod(method, highPopRatioThreshold, highPopRatioMinInstructionCount))
                {
                    skippedByPolicy++;
                    Ctx.Options.Logger.Warning(
                        $"Skipping replacement for high-pop-ratio method by replacement policy: {method.Parent.FullName}");
                    method.RecompiledBody = null;
                    continue;
                }

                var artifact = BuildRecompiledArtifact(method);
                var cilIssueCount = 0;
                var dnlibIssueCount = 0;
                CilBodyAnalysisResult cilAnalysis = null;
                DnlibStyleMaxStackAnalysisResult dnlibAnalysis = null;
                var diagnosticsLogged = false;
                if (artifact != null)
                {
                    cilAnalysis = CilBodyStackAnalyzer.Analyze(Ctx, method, artifact);
                    dnlibAnalysis = DnlibStyleMaxStackAnalyzer.Analyze(Ctx, method, artifact);
                    cilIssueCount = cilAnalysis.TotalIssues;
                    dnlibIssueCount = dnlibAnalysis.TotalIssues;
                    if (IsEnvironmentEnabled("KRYPTON_LOG_REPLACEMENT_ISSUES") &&
                        (cilIssueCount > 0 || dnlibIssueCount > 0))
                    {
                        LogReplacementDiagnostics(Ctx, method, cilAnalysis, dnlibAnalysis);
                        diagnosticsLogged = true;
                        if (IsEnvironmentEnabled("KRYPTON_DUMP_REPLACEMENT_ANALYSIS"))
                        {
                            TryDumpReplacementSkip(
                                Ctx,
                                method,
                                artifact,
                                cilAnalysis,
                                dnlibAnalysis,
                                "analysis-issues");
                        }
                    }
                }

                if (cilIssueCount > maxCilIssues || dnlibIssueCount > maxDnlibIssues)
                {
                    skippedByIlSafetyGate++;
                    Ctx.Options.Logger.Warning(
                        $"Skipping replacement for {method.Parent.FullName} because IL safety gate failed (cil issues={cilIssueCount}, dnlib issues={dnlibIssueCount}, limits={maxCilIssues}/{maxDnlibIssues}).");
                    if (!diagnosticsLogged)
                        LogReplacementDiagnostics(Ctx, method, cilAnalysis, dnlibAnalysis);
                    TryDumpReplacementSkip(
                        Ctx,
                        method,
                        artifact,
                        cilAnalysis,
                        dnlibAnalysis,
                        "il-safety-gate");
                    method.RecompiledBody = null;
                    continue;
                }

                if (semanticValidator != null && semanticValidator.HasReachableEntryUnderflow(Ctx, method))
                {
                    skippedBySemanticGate++;
                    Ctx.Options.Logger.Warning(
                        $"Skipping replacement for {method.Parent.FullName} because semantic validation detected reachable stack underflow from method entry.");
                    TryDumpReplacementSkip(
                        Ctx,
                        method,
                        artifact,
                        cilAnalysis,
                        dnlibAnalysis,
                        "semantic-entry-underflow");
                    method.RecompiledBody = null;
                    continue;
                }

                method.Parent.CilMethodBody = method.RecompiledBody;
                Ctx.Options.Logger.Info($"Replaced method body: {method.Parent.FullName}");
                replaced++;
            }

            Ctx.Options.Logger.Info($"Method bodies replaced: {replaced}");
            Ctx.ReplacedMethodCount = replaced;
            if (skippedByPolicy > 0)
                Ctx.Options.Logger.Info($"Method bodies skipped by replacement policy: {skippedByPolicy}");
            if (skippedBySemanticGate > 0)
                Ctx.Options.Logger.Info($"Method bodies skipped by semantic safety gate: {skippedBySemanticGate}");
            if (skippedByIlSafetyGate > 0)
                Ctx.Options.Logger.Info($"Method bodies skipped by IL safety gate: {skippedByIlSafetyGate}");
            if (skippedByGlobalDisable > 0)
                Ctx.Options.Logger.Info($"Method bodies skipped by global replacement disable: {skippedByGlobalDisable}");
        }

        private RecompiledMethodArtifact BuildRecompiledArtifact(VMMethod method)
        {
            if (method?.RecompiledBody == null || method?.MethodBody?.Instructions == null)
                return null;

            return new RecompiledMethodArtifact(
                method.RecompiledBody,
                method.MethodBody.Instructions.ToList());
        }

        private int ReadNonNegativeIntFromEnvironment(string variableName, int fallback)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
                return fallback;
            if (!int.TryParse(raw, out var parsed))
                return fallback;
            if (parsed < 0)
                return fallback;
            return parsed;
        }

        private bool IsModuleMethod(AsmResolver.DotNet.MethodDefinition method)
        {
            var declaringType = method?.DeclaringType;
            if (declaringType == null)
                return false;

            var typeName = declaringType.Name?.ToString();
            return (!string.IsNullOrEmpty(typeName) &&
                    typeName.StartsWith("<Module>", System.StringComparison.Ordinal)) ||
                   declaringType.IsModuleType;
        }

        private bool IsHighPopRatioMethod(
            VMMethod method,
            double threshold,
            int minInstructionCount)
        {
            if (method?.MethodBody?.Instructions == null)
                return false;

            var instructions = method.MethodBody.Instructions;
            if (instructions.Count < minInstructionCount || instructions.Count == 0)
                return false;

            var popCount = 0;
            foreach (var instruction in instructions)
            {
                if (instruction.OpCode == VMOpCode.Pop)
                    popCount++;
            }

            var ratio = (double) popCount / instructions.Count;
            return ratio >= threshold;
        }

        private void LogReplacementDiagnostics(
            DevirtualizationCtx ctx,
            VMMethod method,
            CilBodyAnalysisResult cilAnalysis,
            DnlibStyleMaxStackAnalysisResult dnlibAnalysis)
        {
            if (!IsEnvironmentEnabled("KRYPTON_LOG_REPLACEMENT_ISSUES"))
                return;
            if (ctx?.Options?.Logger == null || method?.Parent == null)
                return;

            var methodName = method.Parent.FullName;
            if (cilAnalysis != null && cilAnalysis.IssuesByVmByte.Count > 0)
            {
                var top = string.Join(
                    ", ",
                    cilAnalysis.IssuesByVmByte
                        .OrderByDescending(q => q.Value)
                        .Take(8)
                        .Select(q => $"0x{q.Key:X2}={q.Value}"));
                ctx.Options.Logger.Info(
                    $"Replacement diagnostics (CIL) for {methodName}: top vm bytes {top}");
            }

            if (dnlibAnalysis != null && dnlibAnalysis.IssuesByVmByte.Count > 0)
            {
                var top = string.Join(
                    ", ",
                    dnlibAnalysis.IssuesByVmByte
                        .OrderByDescending(q => q.Value)
                        .Take(8)
                        .Select(q => $"0x{q.Key:X2}={q.Value}"));
                ctx.Options.Logger.Info(
                    $"Replacement diagnostics (dnlib) for {methodName}: top vm bytes {top}");
            }

            if (dnlibAnalysis?.Messages != null && dnlibAnalysis.Messages.Count > 0)
            {
                ctx.Options.Logger.Info(
                    $"Replacement diagnostics samples for {methodName}: {string.Join(" | ", dnlibAnalysis.Messages.Take(6))}");
            }
        }

        private void TryDumpReplacementSkip(
            DevirtualizationCtx ctx,
            VMMethod method,
            RecompiledMethodArtifact artifact,
            CilBodyAnalysisResult cilAnalysis,
            DnlibStyleMaxStackAnalysisResult dnlibAnalysis,
            string reason)
        {
            var outputDir = Environment.GetEnvironmentVariable("KRYPTON_DUMP_REPLACEMENT_SKIPS_DIR");
            if (string.IsNullOrWhiteSpace(outputDir))
                return;
            if (method?.Parent == null)
                return;

            try
            {
                Directory.CreateDirectory(outputDir);
                var safeMethodName = SanitizeFileName(method.Parent.FullName);
                var safeReason = SanitizeFileName(reason);
                var filePath = Path.Combine(
                    outputDir,
                    $"{safeMethodName}-{safeReason}.txt");

                var sb = new StringBuilder(64 * 1024);
                sb.AppendLine($"Method: {method.Parent.FullName}");
                sb.AppendLine($"Reason: {reason}");
                sb.AppendLine($"Generated: {DateTime.UtcNow:O}");
                sb.AppendLine();

                if (cilAnalysis != null)
                {
                    sb.AppendLine($"CIL issues: {cilAnalysis.TotalIssues}");
                    if (cilAnalysis.IssuesByVmByte.Count > 0)
                    {
                        sb.AppendLine(
                            "CIL top vm bytes: " +
                            string.Join(
                                ", ",
                                cilAnalysis.IssuesByVmByte
                                    .OrderByDescending(q => q.Value)
                                    .Take(12)
                                    .Select(q => $"0x{q.Key:X2}={q.Value}")));
                    }
                }

                if (dnlibAnalysis != null)
                {
                    sb.AppendLine($"dnlib issues: {dnlibAnalysis.TotalIssues}");
                    if (dnlibAnalysis.IssuesByVmByte.Count > 0)
                    {
                        sb.AppendLine(
                            "dnlib top vm bytes: " +
                            string.Join(
                                ", ",
                                dnlibAnalysis.IssuesByVmByte
                                    .OrderByDescending(q => q.Value)
                                    .Take(12)
                                    .Select(q => $"0x{q.Key:X2}={q.Value}")));
                    }

                    if (dnlibAnalysis.Messages.Count > 0)
                    {
                        sb.AppendLine("dnlib samples:");
                        foreach (var sample in dnlibAnalysis.Messages.Take(20))
                            sb.AppendLine("- " + sample);
                    }
                }

                var bodyInstructions = artifact?.Body?.Instructions;
                var origins = artifact?.InstructionOrigins;
                if (bodyInstructions != null)
                {
                    sb.AppendLine();
                    sb.AppendLine("Recompiled IL:");
                    for (var i = 0; i < bodyInstructions.Count; i++)
                    {
                        var il = bodyInstructions[i];
                        var origin = origins != null && i < origins.Count ? origins[i] : null;
                        var originPart = origin == null
                            ? "<none>"
                            : $"off={origin.Offset}, vm=0x{origin.VmByte:X2}, op={origin.OpCode}, operand={FormatOriginOperand(origin.Operand)}";
                        sb.AppendLine(
                            $"[{i:D4}] {il.OpCode.Code} {FormatIlOperand(il.Operand)} | origin: {originPart}");
                    }
                }

                File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
                ctx?.Options?.Logger?.Info($"Wrote replacement skip dump: {filePath}");
            }
            catch (Exception ex)
            {
                ctx?.Options?.Logger?.Warning($"Could not write replacement skip dump: {ex.Message}");
            }
        }

        private bool IsEnvironmentEnabled(string variableName)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
                return false;
            return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);
        }

        private string FormatIlOperand(object operand)
        {
            if (operand == null)
                return string.Empty;

            if (operand is AsmResolver.PE.DotNet.Cil.CilInstructionLabel label)
                return label.Instruction == null ? "<null-label>" : $"-> {label.Instruction.OpCode.Code}";

            if (operand is System.Collections.Generic.IEnumerable<AsmResolver.PE.DotNet.Cil.CilInstructionLabel> labels)
                return "[" + string.Join(", ", labels.Select(q => q?.Instruction?.OpCode.Code.ToString() ?? "<null>")) + "]";

            try
            {
                return operand.ToString() ?? string.Empty;
            }
            catch
            {
                return "<operand-to-string-failed>";
            }
        }

        private string FormatOriginOperand(object operand)
        {
            if (operand == null)
                return "<null>";
            if (operand is int[] targets)
                return "[" + string.Join(", ", targets.Take(24)) + (targets.Length > 24 ? ", ..." : string.Empty) + "]";
            return operand.ToString() ?? "<null>";
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
    }
}
