using System;
using System.Linq;
using Krypton.Core;

namespace Krypton.Pipeline.Services
{
    internal static class OutputEligibilityService
    {
        internal sealed class OutputDecision
        {
            public bool ShouldWriteOutput { get; set; }
            public bool RemoveStaleOutput { get; set; }
            public string SkipReason { get; set; }
            public int MethodsWithUnknownCount { get; set; }
            public bool AllowStabilizationOnly { get; set; }
        }

        public static OutputDecision Evaluate(DevirtualizationCtx ctx)
        {
            var decision = new OutputDecision();
            if (ctx == null)
                return decision;

            decision.AllowStabilizationOnly = string.Equals(
                Environment.GetEnvironmentVariable("KRYPTON_ALLOW_STABILIZATION_ONLY_OUTPUT"),
                "1",
                StringComparison.Ordinal);

            if (ctx.ReplacedMethodCount <= 0)
            {
                if (!decision.AllowStabilizationOnly)
                {
                    decision.ShouldWriteOutput = false;
                    decision.RemoveStaleOutput = true;
                    decision.SkipReason =
                        "No methods were replaced. Skipping output write to avoid producing a misleading copy of the original input.";
                    return decision;
                }
            }

            var methodsWithUnknown = ctx.VirtualizedMethods
                .Where(q => q.MethodBody.Instructions.Any(i => !i.IsResolved))
                .ToList();
            decision.MethodsWithUnknownCount = methodsWithUnknown.Count;
            var allowPartialOutput = string.Equals(
                Environment.GetEnvironmentVariable("KRYPTON_ALLOW_PARTIAL_OUTPUT"),
                "1",
                StringComparison.Ordinal);
            if (methodsWithUnknown.Count > 0 && !allowPartialOutput)
            {
                decision.ShouldWriteOutput = false;
                decision.RemoveStaleOutput = true;
                decision.SkipReason =
                    "Strict mode is enabled (default): output write is skipped because unresolved VM opcodes remain. " +
                    "Set KRYPTON_ALLOW_PARTIAL_OUTPUT=1 to allow partial writes.";
                return decision;
            }

            var hasRecompiledBodies = ctx.VirtualizedMethods.Any(q => q.RecompiledBody != null);
            if (!hasRecompiledBodies && !decision.AllowStabilizationOnly)
            {
                decision.ShouldWriteOutput = false;
                decision.RemoveStaleOutput = true;
                decision.SkipReason = "No method was fully recompiled and replaced. Skipping assembly write.";
                return decision;
            }

            decision.ShouldWriteOutput = true;
            return decision;
        }
    }
}
