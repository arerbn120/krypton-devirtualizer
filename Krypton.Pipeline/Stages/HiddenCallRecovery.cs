using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;

namespace Krypton.Pipeline.Stages
{
    /// <summary>
    /// Recovers NET Reactor "Hide Method Calls" stubs by:
    ///
    ///   1. Invoking Krypton.Runner.exe on the ORIGINAL protected assembly to
    ///      capture the DynamicMethod delegate table at runtime.
    ///
    ///   2. Parsing the dump to build a map:  field_metadata_token → real_callee
    ///      (e.g. 0x0400017E → Control::set_Text(string))
    ///
    ///   3. Scanning every devirtualized method body for the NET Reactor stub pattern:
    ///          ldsfld   <hidden_field>          ; load delegate from anonymous field
    ///          callvirt Delegate::Invoke / ...  ; call it
    ///      and replacing the pair with a direct callvirt to the real method.
    ///
    /// The stage is optional: if Krypton.Runner is not found or the dump fails,
    /// devirtualization proceeds without hidden-call recovery (existing behavior).
    /// </summary>
    public sealed class HiddenCallRecovery : IStage
    {
        public string Name => "HiddenCallRecovery";

        public void Run(DevirtualizationCtx ctx)
        {
            // Kill-switch: set KRYPTON_HCR_ENABLE=0 to disable.
            var envSwitch = Environment.GetEnvironmentVariable("KRYPTON_HCR_ENABLE");
            if (!string.IsNullOrWhiteSpace(envSwitch) &&
                string.Equals(envSwitch, "0", StringComparison.Ordinal))
            {
                ctx.Options.Logger.Info("[HCR] Disabled via KRYPTON_HCR_ENABLE=0, skipping.");
                return;
            }

            string originalPath = ctx.Options.FilePath;
            if (string.IsNullOrWhiteSpace(originalPath) || !File.Exists(originalPath))
            {
                ctx.Options.Logger.Warning("[HCR] Original assembly path not set — skipping.");
                return;
            }

            // ── 1. Find Krypton.Runner.exe ──────────────────────────────────────
            string runnerPath = FindRunner();
            if (runnerPath == null)
            {
                ctx.Options.Logger.Warning("[HCR] Krypton.Runner.exe not found — skipping hidden-call recovery.");
                return;
            }

            // ── 2. Run Krypton.Runner to produce a dump ─────────────────────────
            string dumpPath = Path.ChangeExtension(originalPath, null) + "-dynamic-dump.json";
            ctx.Options.Logger.Info($"[HCR] Running Krypton.Runner on: {originalPath}");

            bool dumpOk = InvokeRunner(runnerPath, originalPath, dumpPath, ctx);
            if (!dumpOk || !File.Exists(dumpPath))
            {
                ctx.Options.Logger.Warning("[HCR] Runner did not produce a dump — skipping.");
                return;
            }

            // ── 3. Parse dump and build token → callee map ───────────────────────
            var calleeMap = BuildCalleeMap(dumpPath, ctx);
            if (calleeMap == null || calleeMap.Count == 0)
            {
                ctx.Options.Logger.Warning("[HCR] Dump produced no usable entries — skipping.");
                return;
            }
            ctx.Options.Logger.Info($"[HCR] Built callee map with {calleeMap.Count} entries.");

            // ── 4. Patch methods in the module ───────────────────────────────────
            if (ctx.Module == null)
            {
                ctx.Options.Logger.Warning("[HCR] Module not available — skipping.");
                return;
            }

            int patchedCalls   = 0;
            int patchedMethods = 0;

            foreach (var type in ctx.Module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (method.CilMethodBody == null) continue;
                    int patched = PatchMethod(method, calleeMap, ctx.Module);
                    if (patched > 0)
                    {
                        patchedCalls += patched;
                        patchedMethods++;
                    }
                }
            }

            ctx.Options.Logger.Success(
                $"[HCR] Recovered {patchedCalls} hidden call(s) in {patchedMethods} method(s).");
        }

        // ──────────────────────────────────────────────────────────────────────────
        // Runner invocation
        // ──────────────────────────────────────────────────────────────────────────

        private static string FindRunner()
        {
            // Deployment: Runner.exe sits next to Krypton.exe
            // Development: Krypton is at <root>/Krypton/bin/<cfg>/net8.0/
            //              Runner  is at <root>/Krypton.Runner/bin/<cfg>/net48/
            //              so we walk up 3 levels to reach <root>.
            string baseDir = AppContext.BaseDirectory;
            // Development layout: <root>/Krypton/bin/<cfg>/net8.0/ → 4 levels up to <root>
            string up4 = Path.Combine(baseDir, "..", "..", "..", "..");
            var candidates = new[]
            {
                Path.Combine(baseDir, "Krypton.Runner.exe"),
                Path.Combine(up4, "Krypton.Runner", "bin", "Release", "net48", "Krypton.Runner.exe"),
                Path.Combine(up4, "Krypton.Runner", "bin", "Debug",   "net48", "Krypton.Runner.exe"),
            };
            return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
        }

        private static bool InvokeRunner(
            string runnerPath,
            string targetPath,
            string dumpPath,
            DevirtualizationCtx ctx)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName               = runnerPath,
                    Arguments              = $"\"{targetPath}\" \"{dumpPath}\"",
                    UseShellExecute        = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                };

                using var proc = Process.Start(psi);
                if (proc == null) return false;

                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit(60_000); // 60 second timeout

                foreach (var line in stdout.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line))
                        ctx.Options.Logger.Info("  [Runner] " + line.TrimEnd());

                foreach (var line in stderr.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line))
                        ctx.Options.Logger.Warning("  [Runner/err] " + line.TrimEnd());

                return proc.ExitCode == 0;
            }
            catch (Exception ex)
            {
                ctx.Options.Logger.Warning($"[HCR] Failed to start Runner: {ex.Message}");
                return false;
            }
        }

        // ──────────────────────────────────────────────────────────────────────────
        // Dump parsing → token map
        // ──────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Returns a map from field metadata token (e.g. 0x0400017E) to a resolved
        /// callee descriptor (declaring type full name, method name, signature).
        /// </summary>
        private static Dictionary<int, CalleeDescriptor> BuildCalleeMap(
            string dumpPath,
            DevirtualizationCtx ctx)
        {
            try
            {
                string json = File.ReadAllText(dumpPath);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (!root.TryGetProperty("Methods", out var methods)) return null;

                var map = new Dictionary<int, CalleeDescriptor>();

                foreach (var entry in methods.EnumerateArray())
                {
                    // SourceField format: "::|0x04xxxxxx" or "TypeName::FieldName|0x04xxxxxx"
                    if (!entry.TryGetProperty("SourceField", out var sfProp)) continue;
                    string sourceField = sfProp.GetString() ?? string.Empty;

                    int fieldToken = ExtractToken(sourceField);
                    if (fieldToken == 0) continue;

                    // Find the single real call instruction — skip ldarg.*, tail., ret
                    if (!entry.TryGetProperty("Instructions", out var instrs)) continue;

                    CalleeDescriptor callee = ExtractCallee(instrs);
                    if (callee == null) continue;

                    map[fieldToken] = callee;
                }

                return map;
            }
            catch (Exception ex)
            {
                ctx.Options.Logger.Warning($"[HCR] Failed to parse dump: {ex.Message}");
                return null;
            }
        }

        private static int ExtractToken(string sourceField)
        {
            // Expect something like "::|0x04000165" or "Type::Field|0x04000165"
            int pipeIdx = sourceField.LastIndexOf('|');
            string tokenStr = pipeIdx >= 0
                ? sourceField.Substring(pipeIdx + 1)
                : sourceField;

            if (tokenStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                tokenStr = tokenStr.Substring(2);

            return int.TryParse(tokenStr, System.Globalization.NumberStyles.HexNumber,
                null, out int tok) ? tok : 0;
        }

        private static CalleeDescriptor ExtractCallee(JsonElement instrs)
        {
            // Pattern in each DynamicMethod thunk:
            //   ldarg.0, [ldarg.1, ...], [tail.], call/callvirt RealMethod, ret
            // We want the one instruction that references a real method.
            foreach (var instr in instrs.EnumerateArray())
            {
                if (!instr.TryGetProperty("OperandKind", out var opKind)) continue;
                if (!string.Equals(opKind.GetString(), "method", StringComparison.Ordinal))
                    continue;

                instr.TryGetProperty("Opcode",     out var opcodeProp);
                instr.TryGetProperty("DeclType",   out var declTypeProp);
                instr.TryGetProperty("MemberName", out var memberNameProp);
                instr.TryGetProperty("MemberSig",  out var memberSigProp);

                string opcode     = opcodeProp.GetString()     ?? string.Empty;
                string declType   = declTypeProp.GetString()   ?? string.Empty;
                string memberName = memberNameProp.GetString()  ?? string.Empty;
                string memberSig  = memberSigProp.GetString()  ?? string.Empty;

                // Skip delegate Invoke itself (we're looking for the real call inside the thunk)
                if (string.Equals(memberName, "Invoke", StringComparison.Ordinal))
                    continue;

                // Parse parameters from MemberSig for proper arity
                var paramTypes = ParseParamTypes(memberSig, instr);

                return new CalleeDescriptor
                {
                    Opcode        = opcode,
                    DeclaringType = declType,
                    MethodName    = memberName,
                    MemberSig     = memberSig,
                    ParamTypes    = paramTypes,
                    IsInstance    = memberSig.StartsWith("instance", StringComparison.Ordinal),
                };
            }
            return null;
        }

        private static List<string> ParseParamTypes(string sig, JsonElement instr)
        {
            var result = new List<string>();

            // Try reading from "Params" array if present
            if (instr.TryGetProperty("Params", out var paramsArr))
            {
                foreach (var p in paramsArr.EnumerateArray())
                {
                    p.TryGetProperty("Type", out var typeProp);
                    p.TryGetProperty("IsByRef", out var byRefProp);
                    string t = typeProp.GetString() ?? "System.Object";
                    bool r   = byRefProp.ValueKind == JsonValueKind.True;
                    result.Add(r ? t + "&" : t);
                }
            }
            return result;
        }

        // ──────────────────────────────────────────────────────────────────────────
        // IL patching
        // ──────────────────────────────────────────────────────────────────────────

        private static int PatchMethod(
            MethodDefinition method,
            Dictionary<int, CalleeDescriptor> calleeMap,
            ModuleDefinition module)
        {
            var body = method.CilMethodBody;
            var il   = body.Instructions;
            int count = 0;

            for (int i = 0; i < il.Count - 1; i++)
            {
                if (il[i].OpCode != CilOpCodes.Ldsfld) continue;

                var fieldRef = il[i].Operand as IFieldDescriptor;
                if (fieldRef == null) continue;

                int fieldToken = fieldRef.MetadataToken.ToInt32();
                if (!calleeMap.TryGetValue(fieldToken, out var callee)) continue;

                // Find the delegate dispatch call: named "Invoke" or with obfuscated name
                // (NET Reactor renames Invoke to control chars that have no identifier chars).
                int callIdx = FindDelegateCall(il, i + 1, out _);
                if (callIdx < 0) continue;

                var replacement = BuildCallInstruction(callee, module);
                if (replacement == null) continue;

                // Correct patching:
                //   BEFORE: ldsfld <delegate>, [arg-loading...], callvirt Invoke
                //   AFTER:  [arg-loading...],  callvirt/call  RealMethod
                //
                // Step 1 — replace the Invoke with the real call (index still valid)
                il[callIdx] = replacement;

                // Step 2 — remove the ldsfld; everything between shifts down by 1,
                //           but that's fine since we already replaced what matters.
                il.RemoveAt(i);

                // i now points to the first arg-loading instruction (was i+1).
                // Decrement so the outer loop re-evaluates position i next iteration.
                i--;
                count++;
            }

            if (count > 0)
                body.Instructions.OptimizeMacros();

            return count;
        }

        /// <summary>
        /// Finds the delegate Invoke call after <paramref name="start"/>.
        /// Returns the first call/callvirt whose method name is "Invoke" (standard)
        /// or empty-string (NET Reactor renames Invoke to "").
        /// Other call instructions are NOT used as fallback — they are not delegate dispatches.
        /// <paramref name="diagName"/> receives the matched name for logging.
        /// Returns -1 if no qualifying call found within 20 slots or at a control-flow boundary.
        /// </summary>
        private static int FindDelegateCall(
            CilInstructionCollection il,
            int start,
            out string diagName)
        {
            diagName = null;
            int limit = Math.Min(start + 20, il.Count);

            for (int i = start; i < limit; i++)
            {
                var instr = il[i];
                var op    = instr.OpCode;

                if (op == CilOpCodes.Callvirt || op == CilOpCodes.Call)
                {
                    string name = (instr.Operand is IMethodDescriptor md)
                        ? md.Name?.ToString() ?? string.Empty
                        : string.Empty;

                    // Accept "Invoke" (standard) or any name with no visible
                    // identifier characters — NET Reactor renames Invoke to control chars.
                    bool isObfuscatedInvoke = !name.Any(c => char.IsLetterOrDigit(c) || c == '_');
                    if (string.Equals(name, "Invoke", StringComparison.Ordinal) || isObfuscatedInvoke)
                    {
                        diagName = name.Length == 0 ? "<empty>" : isObfuscatedInvoke ? "<ctrlchars>" : "Invoke";
                        return i;
                    }
                }

                // Stop at unconditional control flow.
                if (op == CilOpCodes.Ret    || op == CilOpCodes.Throw  ||
                    op == CilOpCodes.Br     || op == CilOpCodes.Br_S   ||
                    op == CilOpCodes.Switch)
                    break;
            }

            return -1;
        }


        /// <summary>
        /// Builds the replacement CIL instruction that directly calls the real method.
        /// </summary>
        private static CilInstruction BuildCallInstruction(
            CalleeDescriptor callee,
            ModuleDefinition module)
        {
            try
            {
                var scope     = FindOrAddAssemblyRef(callee.DeclaringType, module);
                var ns        = GetNamespace(callee.DeclaringType);
                var typeName  = GetTypeName(callee.DeclaringType);

                ITypeDefOrRef typeRef = new TypeReference(module, scope, ns, typeName);

                // Handle nested types (e.g. "System.Windows.Forms.Control/ControlCollection")
                // In AsmResolver 5.x, TypeReference implements IResolutionScope, so nested type
                // references are built by passing the outer TypeReference as the scope.
                if (callee.DeclaringType.Contains("/"))
                {
                    var parts = callee.DeclaringType.Split('/');
                    var outerScope = FindOrAddAssemblyRef(parts[0], module);
                    var current = new TypeReference(module, outerScope, GetNamespace(parts[0]), GetTypeName(parts[0]));
                    for (int p = 1; p < parts.Length; p++)
                        current = new TypeReference(module, current, string.Empty, parts[p]);
                    typeRef = current;
                }

                var methodSig = BuildMethodSignature(callee, module);
                if (methodSig == null) return null;

                var memberRef = new MemberReference(typeRef, callee.MethodName, methodSig);

                var opcode = (string.Equals(callee.Opcode, "call",    StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(callee.Opcode, "call.",    StringComparison.OrdinalIgnoreCase))
                    ? CilOpCodes.Call
                    : CilOpCodes.Callvirt;

                // Constructors always use newobj (but they appear as "call" in thunks that
                // forward to them)
                if (string.Equals(callee.MethodName, ".ctor", StringComparison.Ordinal))
                    opcode = CilOpCodes.Newobj;

                return new CilInstruction(opcode, memberRef);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HCR] BuildCallInstruction failed for {callee.DeclaringType}::{callee.MethodName}: {ex.Message}");
                return null;
            }
        }

        // ──────────────────────────────────────────────────────────────────────────
        // Helpers for type/sig construction
        // ──────────────────────────────────────────────────────────────────────────

        private static MethodSignature BuildMethodSignature(
            CalleeDescriptor callee,
            ModuleDefinition module)
        {
            var corLib = module.CorLibTypeFactory;
            var returnSig  = ParseTypeSig(ExtractReturnType(callee.MemberSig), module, corLib);
            var paramSigs  = callee.ParamTypes
                .Select(p => ParseTypeSig(p, module, corLib))
                .Where(s => s != null)
                .ToArray();

            if (callee.IsInstance)
                return MethodSignature.CreateInstance(returnSig, paramSigs);
            else
                return MethodSignature.CreateStatic(returnSig, paramSigs);
        }

        private static TypeSignature ParseTypeSig(
            string fullName,
            ModuleDefinition module,
            CorLibTypeFactory corLib)
        {
            if (string.IsNullOrWhiteSpace(fullName)) return corLib.Object;

            bool isByRef = fullName.EndsWith("&");
            if (isByRef) fullName = fullName.Substring(0, fullName.Length - 1).TrimEnd();

            // Strip array suffix and build SzArrayTypeSignature recursively.
            if (fullName.EndsWith("[]"))
            {
                var elem = ParseTypeSig(fullName.Substring(0, fullName.Length - 2), module, corLib);
                TypeSignature arr = elem != null ? new SzArrayTypeSignature(elem) : (TypeSignature)corLib.Object;
                return isByRef ? new ByReferenceTypeSignature(arr) : arr;
            }

            TypeSignature inner = fullName switch
            {
                "System.Void"    => corLib.Void,
                "System.Boolean" => corLib.Boolean,
                "System.Byte"    => corLib.Byte,
                "System.Int16"   => corLib.Int16,
                "System.Int32"   => corLib.Int32,
                "System.Int64"   => corLib.Int64,
                "System.Single"  => corLib.Single,
                "System.Double"  => corLib.Double,
                "System.Char"    => corLib.Char,
                "System.String"  => corLib.String,
                "System.Object"  => corLib.Object,
                "System.IntPtr"  => corLib.IntPtr,
                _ => BuildCustomTypeSig(fullName, module),
            };

            return isByRef && inner != null
                ? new ByReferenceTypeSignature(inner)
                : inner;
        }

        private static TypeSignature BuildCustomTypeSig(string fullName, ModuleDefinition module)
        {
            if (string.IsNullOrWhiteSpace(fullName)) return null;

            // Try to find an existing TypeReference in the module
            var existingRef = module.GetImportedTypeReferences()
                .FirstOrDefault(r => string.Equals(
                    r.FullName, fullName, StringComparison.Ordinal));

            if (existingRef != null)
                return new TypeDefOrRefSignature(existingRef);

            // Build a new TypeReference
            var scope  = FindOrAddAssemblyRef(fullName, module);
            var ns     = GetNamespace(fullName);
            var name   = GetTypeName(fullName);
            bool isValueType = IsKnownValueType(fullName);

            var typeRef = new TypeReference(module, scope, ns, name);
            return new TypeDefOrRefSignature(typeRef, isValueType);
        }

        private static IResolutionScope FindOrAddAssemblyRef(string typeName, ModuleDefinition module)
        {
            // Heuristic: map known namespaces to assembly names
            if (typeName.StartsWith("System.Windows.Forms") || typeName.Contains("/"))
                return GetOrAddRef(module, "System.Windows.Forms");
            if (typeName.StartsWith("System.Drawing"))
                return GetOrAddRef(module, "System.Drawing");
            if (typeName.StartsWith("System."))
                return module.CorLibTypeFactory.CorLibScope;
            return module.CorLibTypeFactory.CorLibScope;
        }

        private static AssemblyReference GetOrAddRef(ModuleDefinition module, string name)
        {
            var existing = module.AssemblyReferences
                .FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
            if (existing != null) return existing;

            var newRef = new AssemblyReference(name, new Version(4, 0, 0, 0));
            module.AssemblyReferences.Add(newRef);
            return newRef;
        }

        private static string GetNamespace(string fullName)
        {
            // Handle nested types: "System.Windows.Forms.Control/ControlCollection" → "System.Windows.Forms"
            string flat = fullName.Contains('/') ? fullName.Split('/')[0] : fullName;
            int dot = flat.LastIndexOf('.');
            return dot < 0 ? string.Empty : flat.Substring(0, dot);
        }

        private static string GetTypeName(string fullName)
        {
            string flat = fullName.Contains('/') ? fullName.Split('/')[0] : fullName;
            int dot = flat.LastIndexOf('.');
            return dot < 0 ? flat : flat.Substring(dot + 1);
        }

        private static string ExtractReturnType(string sig)
        {
            // sig: "instance void (System.String)"  or "void ()"
            // We want the word after "instance" (if present) up to the first "("
            if (string.IsNullOrWhiteSpace(sig)) return "System.Void";
            sig = sig.TrimStart();
            if (sig.StartsWith("instance ")) sig = sig.Substring(9);
            int paren = sig.IndexOf('(');
            return paren < 0 ? sig.Trim() : sig.Substring(0, paren).Trim();
        }

        private static bool IsKnownValueType(string fullName) =>
            fullName == "System.Drawing.Size"  ||
            fullName == "System.Drawing.SizeF" ||
            fullName == "System.Drawing.Point" ||
            fullName == "System.Drawing.Rectangle" ||
            fullName == "System.Windows.Forms.FormBorderStyle" ||
            fullName == "System.Windows.Forms.FormStartPosition" ||
            fullName == "System.Windows.Forms.AutoScaleMode" ||
            fullName == "System.Windows.Forms.AnchorStyles";
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Data model
    // ──────────────────────────────────────────────────────────────────────────

    internal sealed class CalleeDescriptor
    {
        public string       Opcode        { get; set; }
        public string       DeclaringType { get; set; }
        public string       MethodName    { get; set; }
        public string       MemberSig     { get; set; }
        public List<string> ParamTypes    { get; set; } = new List<string>();
        public bool         IsInstance    { get; set; }
    }
}
