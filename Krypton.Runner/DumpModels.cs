using System.Collections.Generic;

namespace Krypton.Runner
{
    /// <summary>
    /// Root object written to dump.json after dynamic analysis of a protected assembly.
    /// </summary>
    public sealed class DynamicDump
    {
        public string AssemblyPath { get; set; }
        public string CapturedAt { get; set; }
        public string RuntimeVersion { get; set; }
        public List<DynamicMethodEntry> Methods { get; set; } = new List<DynamicMethodEntry>();

        /// <summary>
        /// Ground-truth property snapshots of all Form types captured by instantiating
        /// them at runtime. Used to reconstruct InitializeComponent with exact values.
        /// </summary>
        public List<FormEntry> Forms { get; set; } = new List<FormEntry>();
    }

    /// <summary>
    /// One recovered DynamicMethod — maps to a stub method in the original assembly.
    /// </summary>
    public sealed class DynamicMethodEntry
    {
        /// <summary>
        /// "Namespace.TypeName::FieldName" — the static field that held the delegate pointing
        /// to this DynamicMethod. Used as primary matching key.
        /// </summary>
        public string SourceField { get; set; }

        /// <summary>
        /// Index inside the delegate array (-1 if the field was a scalar delegate, not array).
        /// </summary>
        public int SourceIndex { get; set; }

        // Method signature — used as fallback matching key when field info is ambiguous.
        public string ReturnType { get; set; }
        public List<string> ParameterTypes { get; set; } = new List<string>();

        // Body
        public int MaxStack { get; set; }
        public bool InitLocals { get; set; }
        public List<LocalEntry> Locals { get; set; } = new List<LocalEntry>();
        public List<InstructionEntry> Instructions { get; set; } = new List<InstructionEntry>();
        public List<ExHandlerEntry> ExceptionHandlers { get; set; } = new List<ExHandlerEntry>();
    }

    public sealed class LocalEntry
    {
        public string Type { get; set; }   // full CLR type name
        public bool IsPinned { get; set; }
    }

    public sealed class InstructionEntry
    {
        public int Offset { get; set; }
        public string Opcode { get; set; }

        /// <summary>
        /// Discriminator: null | "i32" | "i64" | "r32" | "r64" | "string" |
        /// "method" | "field" | "type" | "sig" | "branch" | "switch"
        /// </summary>
        public string OperandKind { get; set; }

        // primitive operands
        public long? IntValue { get; set; }
        public double? FloatValue { get; set; }
        public string StringValue { get; set; }

        // member-reference operands (method / field / type)
        public string DeclType { get; set; }    // declaring type full name
        public string MemberName { get; set; }
        public string MemberSig { get; set; }   // human-readable sig, e.g. "instance void (System.String)"

        // for call/callvirt/newobj: are any params by-ref?
        public List<ParamEntry> Params { get; set; }

        // branch / switch
        public int? BranchTarget { get; set; }
        public List<int> SwitchTargets { get; set; }
    }

    public sealed class ParamEntry
    {
        public string Type { get; set; }
        public bool IsByRef { get; set; }
    }

    public sealed class ExHandlerEntry
    {
        public string HandlerType { get; set; }   // Catch | Finally | Fault | Filter
        public string CatchType { get; set; }      // only for Catch
        public int TryStart { get; set; }
        public int TryEnd { get; set; }
        public int HandlerStart { get; set; }
        public int HandlerEnd { get; set; }
        public int FilterStart { get; set; }       // only for Filter (-1 otherwise)
    }
}
