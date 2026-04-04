using System;
using System.Collections.Generic;

namespace Krypton.Core.Signatures
{
    public sealed class HandlerSignatureCatalog
    {
        public string Version { get; set; } = "1";
        public string SourceAssembly { get; set; } = string.Empty;
        public string DispatcherMethod { get; set; } = string.Empty;
        public int SignatureGramMaxOps { get; set; }
        public int HandlerCount { get; set; }
        public List<HandlerSignatureRecord> Records { get; set; } = new List<HandlerSignatureRecord>();
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    }

    public sealed class HandlerSignatureRecord
    {
        public int VmByte { get; set; }
        public string OpCode { get; set; } = string.Empty;
        public byte OperandType { get; set; }
        public double Confidence { get; set; }
        public string Source { get; set; } = string.Empty;
        public List<int> SignatureGrams { get; set; } = new List<int>();
    }
}
