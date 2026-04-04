using System;
using System.Collections.Generic;
using System.Linq;
namespace Krypton.Pipeline.Stages
{
    internal static class OpcodeMappingStepRegistry
    {
        private static readonly IReadOnlyList<IOpcodeMappingStep> RegisteredSteps;

        static OpcodeMappingStepRegistry()
        {
            var steps = new List<IOpcodeMappingStep>();
            var stepTypes = typeof(OpcodeMappingStepRegistry).Assembly.GetTypes()
                .Where(t => typeof(IOpcodeMappingStep).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract)
                .OrderBy(t => t.FullName, StringComparer.Ordinal)
                .ToList();

            foreach (var stepType in stepTypes)
            {
                if (Activator.CreateInstance(stepType) is IOpcodeMappingStep step)
                    steps.Add(step);
            }

            RegisteredSteps = steps;
        }

        public static IReadOnlyList<IOpcodeMappingStep> GetOrderedSteps()
        {
            return RegisteredSteps
                .OrderByDescending(step => step.DefaultPriority)
                .ThenBy(step => step.Name, StringComparer.Ordinal)
                .ToList();
        }
    }
}
