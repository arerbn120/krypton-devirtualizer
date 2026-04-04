using System;

namespace Krypton.Core.Payload
{
    public sealed class OperandModelExtractor : IOperandModelExtractor
    {
        public OperandModel Extract(VmPayloadLayout payloadLayout)
        {
            if (payloadLayout == null)
                throw new ArgumentNullException(nameof(payloadLayout));

            var descriptors = new OperandDescriptor[payloadLayout.Operands.Length];
            for (var i = 0; i < descriptors.Length; i++)
            {
                var operandType = payloadLayout.Operands[i];
                var isDefined = i < payloadLayout.DefinedOperands.Length && payloadLayout.DefinedOperands[i];
                descriptors[i] = new OperandDescriptor(i, operandType, isDefined);
            }

            return new OperandModel(descriptors);
        }
    }
}
