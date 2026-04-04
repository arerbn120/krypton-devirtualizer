namespace Krypton.Pipeline.Stages
{
    public interface IOpcodeMappingStep
    {
        string Name { get; }
        int DefaultPriority { get; }
        void Execute(OpcodeMappingStepContext context);
    }
}
