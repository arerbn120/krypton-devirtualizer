using System;
using System.Collections.Generic;

namespace Krypton.Core.Payload
{
    public sealed class VmStringLayout
    {
        public VmStringLayout(string[] values, int[] offsets, int[] sizes)
        {
            Values = values ?? Array.Empty<string>();
            Offsets = offsets ?? Array.Empty<int>();
            Sizes = sizes ?? Array.Empty<int>();
        }

        public IReadOnlyList<string> Values { get; }
        public IReadOnlyList<int> Offsets { get; }
        public IReadOnlyList<int> Sizes { get; }
        public int Count => Values.Count;
    }
}
