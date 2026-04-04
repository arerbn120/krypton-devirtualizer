namespace Krypton.Pipeline.Stages
{
    internal sealed class OpcodeMappingDiscoveryStep : IOpcodeMappingStep
    {
        public string Name => "discovery";
        public int DefaultPriority => 500;

        public void Execute(OpcodeMappingStepContext context)
        {
            context?.Mapper?.RunDiscoveryStep(context.Ctx);
        }
    }
}
