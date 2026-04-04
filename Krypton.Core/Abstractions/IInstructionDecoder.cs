using Krypton.Core.Architecture;

namespace Krypton.Core
{
    public interface IInstructionDecoder
    {
        VMMethod DisassembleMethod(DevirtualizationCtx ctx, int methodKey);
    }
}
