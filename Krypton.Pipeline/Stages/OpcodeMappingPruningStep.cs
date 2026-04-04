namespace Krypton.Pipeline.Stages
{
    internal sealed class OpcodeMappingPruningStep : IOpcodeMappingStep
    {
        public string Name => "pruning";
        public int DefaultPriority => 300;

        public void Execute(OpcodeMappingStepContext context)
        {
            context?.Mapper?.RunPruningStep(context.Ctx);
        }
    }
}
