namespace Krypton.Pipeline.Stages
{
    internal sealed class OpcodeMappingFinalizationStep : IOpcodeMappingStep
    {
        public string Name => "finalization";
        public int DefaultPriority => 100;

        public void Execute(OpcodeMappingStepContext context)
        {
            context?.Mapper?.RunFinalizationStep(context.Ctx);
        }
    }
}
