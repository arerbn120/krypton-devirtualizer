using Krypton.Core.Architecture;

namespace Krypton.Core.Disassembly
{
    public sealed class VmInstructionDecoder : IInstructionDecoder
    {
        public VMMethod DisassembleMethod(DevirtualizationCtx ctx, int methodKey)
        {
            return new VMDisassembler(ctx).DisassembleMethod(methodKey);
        }
    }
}
