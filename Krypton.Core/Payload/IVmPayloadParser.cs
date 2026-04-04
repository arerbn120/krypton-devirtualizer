using Krypton.Core.Parser;

namespace Krypton.Core.Payload
{
    public interface IVmPayloadParser
    {
        VmPayloadLayout Parse(VmPayloadBlob payloadBlob, ResourceParser legacyParser);
    }
}
