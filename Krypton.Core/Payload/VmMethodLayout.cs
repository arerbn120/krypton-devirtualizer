using System;

namespace Krypton.Core.Payload
{
    public sealed class VmMethodLayout
    {
        public VmMethodLayout(int methodIndex, int methodKey, int size)
        {
            MethodIndex = methodIndex;
            MethodKey = methodKey;
            Size = size;
            StartOffset = methodKey;
            EndOffset = methodKey + Math.Max(0, size);
        }

        public int MethodIndex { get; }
        public int MethodKey { get; }
        public int Size { get; }
        public int StartOffset { get; }
        public int EndOffset { get; }
    }
}
