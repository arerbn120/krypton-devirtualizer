using System;
using System.Collections.Generic;
using System.Linq;

namespace Krypton.Core.PatternMatching
{
    public static class PatternPriorityRegistry
    {
        private static readonly object Sync = new object();
        private static Dictionary<string, int> _priorityByPatternType = new Dictionary<string, int>(StringComparer.Ordinal);

        public static void Configure(IEnumerable<PatternPriorityOverrideEntry> overrides)
        {
            var map = new Dictionary<string, int>(StringComparer.Ordinal);
            if (overrides != null)
            {
                foreach (var entry in overrides.Where(e => e != null))
                {
                    if (string.IsNullOrWhiteSpace(entry.PatternType))
                        continue;

                    map[entry.PatternType.Trim()] = entry.Priority;
                }
            }

            lock (Sync)
                _priorityByPatternType = map;
        }

        public static bool TryGetPriority(string patternType, out int priority)
        {
            lock (Sync)
            {
                if (!string.IsNullOrWhiteSpace(patternType) &&
                    _priorityByPatternType.TryGetValue(patternType, out priority))
                {
                    return true;
                }
            }

            priority = 0;
            return false;
        }
    }
}
