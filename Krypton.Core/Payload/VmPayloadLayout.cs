using System;
using System.Collections.Generic;

namespace Krypton.Core.Payload
{
    public sealed class VmPayloadLayout
    {
        public VmPayloadLayout(
            VmPayloadBlob payloadBlob,
            byte[] operands,
            bool[] definedOperands,
            VmStringLayout strings,
            VmMethodLayout[] methods)
        {
            PayloadBlob = payloadBlob ?? new VmPayloadBlob(string.Empty, Array.Empty<byte>());
            Operands = operands ?? Array.Empty<byte>();
            DefinedOperands = definedOperands ?? Array.Empty<bool>();
            Strings = strings ?? new VmStringLayout(Array.Empty<string>(), Array.Empty<int>(), Array.Empty<int>());
            Methods = methods ?? Array.Empty<VmMethodLayout>();
        }

        public VmPayloadBlob PayloadBlob { get; }
        public byte[] Operands { get; }
        public bool[] DefinedOperands { get; }
        public VmStringLayout Strings { get; }
        public IReadOnlyList<VmMethodLayout> Methods { get; }
        public string ResourceName => PayloadBlob.ResourceName;
        public int MethodCount => Methods.Count;
    }
}
