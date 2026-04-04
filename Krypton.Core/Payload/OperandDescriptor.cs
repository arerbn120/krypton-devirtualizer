namespace Krypton.Core.Payload
{
    public sealed class OperandDescriptor
    {
        public OperandDescriptor(int vmByte, byte operandType, bool isDefined)
        {
            VmByte = vmByte;
            OperandType = operandType;
            IsDefined = isDefined;
        }

        public int VmByte { get; }
        public byte OperandType { get; }
        public bool IsDefined { get; }
        public bool HasInlineOperand => OperandType != 0;
        public bool IsVariableSized => OperandType == 5;
        public bool IsBranchTargetLike => OperandType == 1 || OperandType == 5;
        public bool IsMetadataTokenLike => OperandType == 1;
    }
}
