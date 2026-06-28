using System;
using System.Collections.Generic;
using System.Reflection;
using System.Reflection.Emit;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Krypton.Runner
{
    /// <summary>
    /// Converts a dnlib MethodDef (produced by DynamicMethodBodyReader) into
    /// a serialization-friendly DynamicMethodEntry.
    /// </summary>
    internal static class DynamicMethodSerializer
    {
        public static DynamicMethodEntry Serialize(
            DynamicMethod runtimeMethod,
            MethodDef dnlibMethod,
            string sourceField,
            int sourceIndex)
        {
            var entry = new DynamicMethodEntry
            {
                SourceField  = sourceField,
                SourceIndex  = sourceIndex,
                ReturnType   = GetTypeName(runtimeMethod.ReturnType),
                MaxStack     = dnlibMethod.Body?.MaxStack ?? 8,
                InitLocals   = dnlibMethod.Body?.InitLocals ?? true,
            };

            // Parameter types (not counting 'this' which dnlib may strip)
            foreach (var p in runtimeMethod.GetParameters())
                entry.ParameterTypes.Add(GetTypeName(p.ParameterType));

            if (dnlibMethod.Body == null)
                return entry;

            // Locals
            foreach (var loc in dnlibMethod.Body.Variables)
                entry.Locals.Add(new LocalEntry
                {
                    Type     = loc.Type?.FullName ?? "System.Object",
                    IsPinned = loc.Type is PinnedSig,
                });

            // Instructions
            foreach (var instr in dnlibMethod.Body.Instructions)
                entry.Instructions.Add(SerializeInstruction(instr));

            // Exception handlers
            foreach (var eh in dnlibMethod.Body.ExceptionHandlers)
                entry.ExceptionHandlers.Add(SerializeEH(eh));

            return entry;
        }

        // ──────────────────────────────────────────────────────────────
        // Instruction serialization
        // ──────────────────────────────────────────────────────────────

        private static InstructionEntry SerializeInstruction(Instruction instr)
        {
            var e = new InstructionEntry
            {
                Offset = (int)instr.Offset,
                Opcode = instr.OpCode.Name,
            };

            var operand = instr.Operand;
            if (operand == null)
                return e;

            switch (operand)
            {
                case sbyte sb:
                    e.OperandKind = "i32";
                    e.IntValue    = sb;
                    break;
                case byte b:
                    e.OperandKind = "i32";
                    e.IntValue    = b;
                    break;
                case int i:
                    e.OperandKind = "i32";
                    e.IntValue    = i;
                    break;
                case long l:
                    e.OperandKind = "i64";
                    e.IntValue    = l;
                    break;
                case float f:
                    e.OperandKind = "r32";
                    e.FloatValue  = f;
                    break;
                case double d:
                    e.OperandKind = "r64";
                    e.FloatValue  = d;
                    break;
                case string s:
                    e.OperandKind  = "string";
                    e.StringValue  = s;
                    break;

                case IMethod m:
                    SerializeMethod(e, m);
                    break;

                case IField f:
                    e.OperandKind  = "field";
                    e.DeclType     = f.DeclaringType?.FullName;
                    e.MemberName   = f.Name;
                    e.MemberSig    = f.FieldSig?.Type?.FullName;
                    break;

                case ITypeDefOrRef t:
                    e.OperandKind  = "type";
                    e.DeclType     = t.FullName;
                    break;

                case Instruction target:
                    e.OperandKind  = "branch";
                    e.BranchTarget = (int)target.Offset;
                    break;

                case Instruction[] targets:
                    e.OperandKind  = "switch";
                    e.SwitchTargets = new List<int>();
                    foreach (var t in targets)
                        e.SwitchTargets.Add((int)t.Offset);
                    break;
            }

            return e;
        }

        private static void SerializeMethod(InstructionEntry e, IMethod m)
        {
            e.OperandKind = "method";
            e.DeclType    = m.DeclaringType?.FullName;
            e.MemberName  = m.Name;

            var ms = m.MethodSig;
            if (ms == null) return;

            // Build a human-readable sig: "instance RetType (Param1, Param2)"
            var sb = new System.Text.StringBuilder();
            if (ms.HasThis) sb.Append("instance ");
            sb.Append(ms.RetType?.FullName ?? "void");
            sb.Append(" (");
            bool first = true;
            var parms = new List<ParamEntry>();
            foreach (var pt in ms.Params)
            {
                if (!first) sb.Append(", ");
                first = false;
                var isByRef = pt is ByRefSig;
                var typeName = (isByRef ? ((ByRefSig)pt).Next?.FullName : pt?.FullName) ?? "?";
                sb.Append(isByRef ? typeName + "&" : typeName);
                parms.Add(new ParamEntry { Type = typeName, IsByRef = isByRef });
            }
            sb.Append(")");
            e.MemberSig = sb.ToString();
            e.Params = parms;
        }

        private static ExHandlerEntry SerializeEH(dnlib.DotNet.Emit.ExceptionHandler eh)
        {
            return new ExHandlerEntry
            {
                HandlerType  = eh.HandlerType.ToString(),
                CatchType    = eh.CatchType?.FullName,
                TryStart     = eh.TryStart == null ? 0 : (int)eh.TryStart.Offset,
                TryEnd       = eh.TryEnd   == null ? 0 : (int)eh.TryEnd.Offset,
                HandlerStart = eh.HandlerStart == null ? 0 : (int)eh.HandlerStart.Offset,
                HandlerEnd   = eh.HandlerEnd   == null ? 0 : (int)eh.HandlerEnd.Offset,
                FilterStart  = eh.FilterStart  == null ? -1 : (int)eh.FilterStart.Offset,
            };
        }

        // ──────────────────────────────────────────────────────────────
        // Helper
        // ──────────────────────────────────────────────────────────────

        internal static string GetTypeName(Type t)
        {
            if (t == null) return "System.Void";
            if (t.IsByRef) return GetTypeName(t.GetElementType()) + "&";
            if (t.IsPointer) return GetTypeName(t.GetElementType()) + "*";
            if (t.IsArray) return GetTypeName(t.GetElementType()) + "[]";
            return t.FullName ?? t.Name;
        }
    }
}
