using System;

namespace Krypton.Core.Payload
{
    public sealed class VmPayloadBlob
    {
        public VmPayloadBlob(string resourceName, byte[] data)
        {
            ResourceName = resourceName ?? string.Empty;
            Data = data ?? Array.Empty<byte>();
        }

        public string ResourceName { get; }
        public byte[] Data { get; }
        public int Length => Data.Length;
    }
}
