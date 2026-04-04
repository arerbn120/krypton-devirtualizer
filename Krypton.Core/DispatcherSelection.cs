using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;

namespace Krypton.Core
{
    public sealed class DispatcherSelection
    {
        public DispatcherSelection(MethodDefinition method, CilInstruction switchInstruction, object nativeContext)
        {
            Method = method;
            SwitchInstruction = switchInstruction;
            NativeContext = nativeContext;
        }

        public MethodDefinition Method { get; }
        public CilInstruction SwitchInstruction { get; }
        public object NativeContext { get; }
    }
}
