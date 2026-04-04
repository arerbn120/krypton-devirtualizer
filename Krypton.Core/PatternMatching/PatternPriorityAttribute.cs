using System;

namespace Krypton.Core.PatternMatching
{
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class PatternPriorityAttribute : Attribute
    {
        public PatternPriorityAttribute(int priority)
        {
            Priority = priority;
        }

        public int Priority { get; }
    }
}
