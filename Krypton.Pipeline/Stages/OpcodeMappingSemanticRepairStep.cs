namespace Krypton.Pipeline.Stages
{
    internal sealed class OpcodeMappingSemanticRepairStep : IOpcodeMappingStep
    {
        public string Name => "semantic-repair";
        public int DefaultPriority => 200;

        public void Execute(OpcodeMappingStepContext context)
        {
            context?.Mapper?.RunSemanticRepairStep(context.Ctx);
        }
    }
}
