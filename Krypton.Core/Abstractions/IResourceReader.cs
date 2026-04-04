using Krypton.Core.Payload;

namespace Krypton.Core
{
    public interface IResourceReader
    {
        VmResourceData Parse(DevirtualizationCtx ctx);
    }
}
