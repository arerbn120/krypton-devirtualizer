using System.Collections.Generic;

namespace Krypton.Core
{
    public interface IDispatcherLocator
    {
        DispatcherSelection LocateDispatcher(
            DevirtualizationCtx ctx,
            byte[] operandTypes,
            int observedMaxVmByte,
            IDictionary<int, int> observedVmByteHistogram);
    }
}
