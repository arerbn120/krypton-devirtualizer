using AsmResolver.DotNet.Code.Cil;
using Krypton.Core.Architecture;

namespace Krypton.Core
{
    public interface ICilLowerer
    {
        CilMethodBody Recompile(DevirtualizationCtx ctx, VMMethod vmMethod);
    }
}
