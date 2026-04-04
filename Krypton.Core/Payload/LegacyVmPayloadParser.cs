using System;
using Krypton.Core.Parser;

namespace Krypton.Core.Payload
{
    public sealed class LegacyVmPayloadParser : IVmPayloadParser
    {
        public VmPayloadLayout Parse(VmPayloadBlob payloadBlob, ResourceParser legacyParser)
        {
            if (legacyParser == null)
                throw new ArgumentNullException(nameof(legacyParser));

            payloadBlob ??= new VmPayloadBlob(legacyParser.ResourceName, legacyParser.RawData);

            var methodKeys = legacyParser.MethodKeys ?? Array.Empty<int>();
            var methodSizes = legacyParser.MethodSizes ?? Array.Empty<int>();
            var methods = new VmMethodLayout[methodKeys.Length];
            for (var i = 0; i < methodKeys.Length; i++)
            {
                var size = i < methodSizes.Length ? methodSizes[i] : 0;
                methods[i] = new VmMethodLayout(i, methodKeys[i], size);
            }

            var strings = new VmStringLayout(
                legacyParser.Strings ?? Array.Empty<string>(),
                legacyParser.StringOffsets ?? Array.Empty<int>(),
                legacyParser.StringSizes ?? Array.Empty<int>());

            return new VmPayloadLayout(
                payloadBlob,
                legacyParser.Operands ?? Array.Empty<byte>(),
                legacyParser.DefinedOperands ?? Array.Empty<bool>(),
                strings,
                methods);
        }
    }
}
