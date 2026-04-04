using Krypton.Core.Architecture;

namespace Krypton.Core
{
    public sealed class OpcodeMappingConfidence
    {
        public OpcodeMappingConfidence(VMOpCode opCode, double confidence, string source)
        {
            OpCode = opCode;
            Confidence = confidence;
            Source = source;
        }

        public VMOpCode OpCode { get; }
        public double Confidence { get; }
        public string Source { get; }
    }
}
