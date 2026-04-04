using Krypton.Core;

namespace Krypton.Pipeline.Stages
{
    public sealed class OpcodeMappingStepContext
    {
        public OpcodeMappingStepContext(DevirtualizationCtx ctx, OpcodeMapping mapper)
        {
            Ctx = ctx;
            Mapper = mapper;
        }

        public DevirtualizationCtx Ctx { get; }
        public OpcodeMapping Mapper { get; }
    }
}
