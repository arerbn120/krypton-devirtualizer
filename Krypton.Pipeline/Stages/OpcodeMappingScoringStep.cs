namespace Krypton.Pipeline.Stages
{
    internal sealed class OpcodeMappingScoringStep : IOpcodeMappingStep
    {
        public string Name => "scoring";
        public int DefaultPriority => 400;

        public void Execute(OpcodeMappingStepContext context)
        {
            context?.Mapper?.RunScoringStep(context.Ctx);
        }
    }
}
