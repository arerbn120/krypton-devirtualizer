namespace Krypton.Core.Payload
{
    public interface IOperandModelExtractor
    {
        OperandModel Extract(VmPayloadLayout payloadLayout);
    }
}
