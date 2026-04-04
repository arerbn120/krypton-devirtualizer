using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using Krypton.Core.Architecture;
using Krypton.Core.Parser;
using Krypton.Core.Payload;
using Krypton.Core.PatternMatching;

namespace Krypton.Core
{
    public class DevirtualizationCtx
    {
        public DevirtualizationCtx(DevirtualizationOptions Options)
        {
            this.Options = Options;
            Module = ModuleDefinition.FromFile(Options.FilePath);
        }

        public DevirtualizationOptions Options { get; set; }
        public ModuleDefinition Module { get; set; }
        public VmResourceData ResourceData { get; set; }
        public ResourceParser Parser { get; set; }
        public VmPayloadBlob PayloadBlob { get; set; }
        public VmPayloadLayout PayloadLayout { get; set; }
        public OperandModel OperandModel { get; set; }
        public PatternMatcher PatternMatcher { get; set; }
        public IList<VMMethod> VirtualizedMethods { get; set; }
        public MethodDefinition OpcodeHandlerMethod { get; set; }
        public IDictionary<int, int> OpcodeHandlerIndices { get; set; }
        public IDictionary<int, OpcodeMappingConfidence> OpcodeConfidence { get; set; }
        public int ReplacedMethodCount { get; set; }
        public IResourceReader ResourceReader { get; set; }
        public IList<IResourceReader> ResourceReaders { get; set; }
        public IDispatcherLocator DispatcherLocator { get; set; }
        public IOpcodeMapper OpcodeMapper { get; set; }
        public IInstructionDecoder InstructionDecoder { get; set; }
        public IVmSemanticValidator VmSemanticValidator { get; set; }
        public ICilLowerer CilLowerer { get; set; }
        public IList<IVmPayloadParser> PayloadParsers { get; set; }
        public IList<IOperandModelExtractor> OperandModelExtractors { get; set; }

        public byte[] GetOperandTypes()
        {
            if (PayloadLayout?.Operands != null && PayloadLayout.Operands.Length > 0)
                return PayloadLayout.Operands;
            if (Parser?.Operands != null)
                return Parser.Operands;
            return Array.Empty<byte>();
        }

        public bool TryGetOperandType(int vmByte, out byte operandType)
        {
            if (OperandModel != null && OperandModel.TryGetDescriptor(vmByte, out var descriptor))
            {
                operandType = descriptor.OperandType;
                return true;
            }

            var operands = GetOperandTypes();
            if (vmByte >= 0 && vmByte < operands.Length)
            {
                operandType = operands[vmByte];
                return true;
            }

            operandType = 0;
            return false;
        }

        public IReadOnlyList<VmMethodLayout> GetMethodLayouts()
        {
            if (PayloadLayout?.Methods != null && PayloadLayout.Methods.Count > 0)
                return PayloadLayout.Methods;

            if (Parser?.MethodKeys == null || Parser.MethodKeys.Length == 0)
                return Array.Empty<VmMethodLayout>();

            var methodSizes = Parser.MethodSizes ?? Array.Empty<int>();
            return Parser.MethodKeys
                .Select((methodKey, index) =>
                    new VmMethodLayout(index, methodKey, index < methodSizes.Length ? methodSizes[index] : 0))
                .ToArray();
        }
    }
}
