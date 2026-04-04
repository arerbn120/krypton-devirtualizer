using System;
using Krypton.Core.Parser;

namespace Krypton.Core.Payload
{
    public sealed class VmResourceData
    {
        public VmResourceData(
            string resourceName,
            ResourceParser legacyParser,
            VmPayloadBlob payloadBlob,
            VmPayloadLayout payloadLayout,
            OperandModel operandModel,
            ResourceFormatProfile appliedProfile)
        {
            ResourceName = resourceName ?? string.Empty;
            LegacyParser = legacyParser ?? throw new ArgumentNullException(nameof(legacyParser));
            PayloadBlob = payloadBlob ?? new VmPayloadBlob(ResourceName, Array.Empty<byte>());
            PayloadLayout = payloadLayout ?? new VmPayloadLayout(
                PayloadBlob,
                Array.Empty<byte>(),
                Array.Empty<bool>(),
                new VmStringLayout(Array.Empty<string>(), Array.Empty<int>(), Array.Empty<int>()),
                Array.Empty<VmMethodLayout>());
            OperandModel = operandModel ?? new OperandModel(Array.Empty<OperandDescriptor>());
            AppliedProfile = appliedProfile ?? new ResourceFormatProfile();
        }

        public string ResourceName { get; }
        public ResourceParser LegacyParser { get; }
        public VmPayloadBlob PayloadBlob { get; }
        public VmPayloadLayout PayloadLayout { get; }
        public OperandModel OperandModel { get; }
        public ResourceFormatProfile AppliedProfile { get; }
    }
}
