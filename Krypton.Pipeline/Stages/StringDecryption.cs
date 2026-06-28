using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;

namespace Krypton.Pipeline.Stages
{
    /// <summary>
    /// Detects NET Reactor string-encryption call sites and inlines decrypted string literals.
    ///
    /// NET Reactor's string encoder stores each string as:
    ///   [offset+0 .. +3] = byte length (int32-LE)
    ///   [offset+4 .. +4+len) = UTF-16LE bytes
    ///
    /// Callers receive the offset baked as a constant: ldc.i4 N; call StringDecoder(int32) → string
    ///
    /// This stage works for the common variant where the resource blob is not RSA-encrypted at rest.
    /// When the blob is protected by a 2000+ instruction RSA initialiser (NecroBit tier), the blob
    /// reads as high-entropy bytes and static decryption is not feasible — the stage reports this
    /// and skips patching.
    ///
    /// Enable via: KRYPTON_STRING_DECRYPT=1
    /// </summary>
    public sealed class StringDecryption : IStage
    {
        public string Name => nameof(StringDecryption);

        public void Run(DevirtualizationCtx ctx)
        {
            if (!IsEnabled())
                return;

            var module = ctx.Module;
            if (module == null)
                return;

            var decoders = FindStringDecoderMethods(module);
            if (decoders.Count == 0)
            {
                ctx.Options.Logger.Info("StringDecryption: no NET Reactor string decoder found.");
                return;
            }

            ctx.Options.Logger.Info($"StringDecryption: found {decoders.Count} decoder candidate(s).");

            var totalPatched = 0;
            foreach (var (decoder, resourceName) in decoders)
            {
                var blob = LoadEmbeddedResource(module, resourceName);
                if (blob == null)
                {
                    ctx.Options.Logger.Info($"StringDecryption: resource '{resourceName}' not found in manifest.");
                    continue;
                }

                // Collect all offsets referenced at call sites before touching anything.
                var callSites = CollectCallSites(module, decoder);
                if (callSites.Count == 0)
                {
                    ctx.Options.Logger.Info($"StringDecryption: no call sites found for {decoder.MetadataToken}.");
                    continue;
                }

                ctx.Options.Logger.Info($"StringDecryption: {callSites.Count} call site(s) referencing {decoder.MetadataToken}.");

                // Try to decode strings from the blob at the observed offsets.
                var strings = TryDecodeStrings(blob, callSites.Keys);
                if (strings == null)
                {
                    ctx.Options.Logger.Info(
                        $"StringDecryption: resource '{resourceName}' appears RSA/AES-encrypted at rest. " +
                        "Static decryption is not supported for this NecroBit-tier variant.");
                    continue;
                }

                ctx.Options.Logger.Info($"StringDecryption: decoded {strings.Count}/{callSites.Count} string(s) from '{resourceName}'.");

                // Patch: replace (ldc.i4 N; call decoder) with (ldstr "value"; nop).
                var patched = ApplyPatches(callSites, strings);
                totalPatched += patched;
                ctx.Options.Logger.Info($"StringDecryption: patched {patched} call site(s).");
            }

            if (totalPatched > 0)
                ctx.Options.Logger.Info($"StringDecryption: total {totalPatched} string(s) inlined.");
        }

        // ── Detection ──────────────────────────────────────────────────────────────

        private static List<(MethodDefinition Decoder, string ResourceName)> FindStringDecoderMethods(
            ModuleDefinition module)
        {
            var found = new List<(MethodDefinition, string)>();
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (TryMatchStringDecoder(method, out var resourceName))
                        found.Add((method, resourceName));
                }
            }
            return found;
        }

        /// <summary>
        /// A NET Reactor string decoder is:
        ///   - static
        ///   - returns System.String
        ///   - takes exactly one System.Int32 parameter
        ///   - body contains GetManifestResourceStream (with an ldstr for the resource name nearby)
        ///   - body contains Encoding.GetString or Unicode.GetString
        /// </summary>
        private static bool TryMatchStringDecoder(MethodDefinition method, out string resourceName)
        {
            resourceName = null;

            if (!method.IsStatic)
                return false;
            if (method.Signature?.ReturnType?.FullName != "System.String")
                return false;
            if (method.Signature.ParameterTypes.Count != 1)
                return false;
            if (method.Signature.ParameterTypes[0].FullName != "System.Int32")
                return false;
            if (!method.HasMethodBody || method.CilMethodBody == null)
                return false;

            var instr = method.CilMethodBody.Instructions;

            var hasGetManifestResourceStream = false;
            var hasGetString = false;
            string lastLdstr = null;

            foreach (var ins in instr)
            {
                if (ins.OpCode == CilOpCodes.Ldstr)
                {
                    lastLdstr = ins.Operand as string;
                    continue;
                }

                if (ins.OpCode != CilOpCodes.Call && ins.OpCode != CilOpCodes.Callvirt)
                    continue;

                var fullName = (ins.Operand as IMethodDescriptor)?.FullName ?? string.Empty;

                if (fullName.Contains("GetManifestResourceStream", StringComparison.Ordinal))
                {
                    hasGetManifestResourceStream = true;
                    if (!string.IsNullOrEmpty(lastLdstr))
                        resourceName = lastLdstr;
                }
                else if (fullName.Contains("GetString", StringComparison.Ordinal) &&
                         fullName.Contains("Encoding", StringComparison.Ordinal))
                {
                    hasGetString = true;
                }
            }

            return hasGetManifestResourceStream && hasGetString && !string.IsNullOrEmpty(resourceName);
        }

        // ── Resource loading ───────────────────────────────────────────────────────

        private static byte[] LoadEmbeddedResource(ModuleDefinition module, string name)
        {
            foreach (var res in module.Resources)
            {
                if (res.Name != name)
                    continue;
                if (res is ManifestResource mr && mr.IsEmbedded)
                    return mr.GetData();
            }
            return null;
        }

        // ── Call-site collection ───────────────────────────────────────────────────

        /// <summary>
        /// Finds all (ldc.i4 N; call decoder) sites across the module.
        /// Returns a map from offset N → list of instruction pairs to patch.
        /// </summary>
        private static Dictionary<int, List<(CilInstruction Push, CilInstruction Call)>> CollectCallSites(
            ModuleDefinition module,
            MethodDefinition decoder)
        {
            var result = new Dictionary<int, List<(CilInstruction, CilInstruction)>>();

            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasMethodBody || method.CilMethodBody == null)
                        continue;

                    var instr = method.CilMethodBody.Instructions;
                    for (int i = 0; i < instr.Count - 1; i++)
                    {
                        if (!TryGetInt32Push(instr[i], out var offset))
                            continue;

                        var callIns = instr[i + 1];
                        if (callIns.OpCode != CilOpCodes.Call && callIns.OpCode != CilOpCodes.Callvirt)
                            continue;

                        if (!IsCallTo(callIns, decoder))
                            continue;

                        if (!result.TryGetValue(offset, out var sites))
                            result[offset] = sites = new List<(CilInstruction, CilInstruction)>();

                        sites.Add((instr[i], callIns));
                    }
                }
            }

            return result;
        }

        private static bool IsCallTo(CilInstruction ins, MethodDefinition target)
        {
            if (ins.Operand is IMethodDescriptor desc)
            {
                var resolved = desc.Resolve() as MethodDefinition;
                if (resolved != null)
                    return ReferenceEquals(resolved, target);

                // fallback: compare by metadata token
                return desc.Name == target.Name &&
                       desc.DeclaringType?.FullName == target.DeclaringType?.FullName;
            }
            return false;
        }

        // ── String decoding ────────────────────────────────────────────────────────

        /// <summary>
        /// For each offset, reads the NET Reactor string format:
        ///   blob[offset..+4] = int32 byte-length
        ///   blob[offset+4..+len] = UTF-16LE chars
        ///
        /// Returns null when the resource is encrypted (less than half the offsets
        /// produce a plausible ASCII/Unicode string).
        /// </summary>
        private static Dictionary<int, string> TryDecodeStrings(
            byte[] blob,
            IEnumerable<int> offsets)
        {
            var result = new Dictionary<int, string>();
            var success = 0;
            var failure = 0;

            foreach (var offset in offsets)
            {
                if (TryReadString(blob, offset, out var s))
                {
                    result[offset] = s;
                    success++;
                }
                else
                {
                    failure++;
                }
            }

            if (success == 0)
                return null;

            // If more than half failed → likely encrypted.
            if (failure > success)
                return null;

            return result;
        }

        private static bool TryReadString(byte[] blob, int offset, out string value)
        {
            value = null;

            if (offset < 0 || offset + 4 > blob.Length)
                return false;

            var byteLen = BitConverter.ToInt32(blob, offset);
            if (byteLen <= 0 || byteLen > 0x20000)
                return false;
            if (offset + 4 + byteLen > blob.Length)
                return false;
            if ((byteLen & 1) != 0)
                return false;  // UTF-16LE must be even number of bytes

            try
            {
                var candidate = Encoding.Unicode.GetString(blob, offset + 4, byteLen);
                if (!IsPlausibleString(candidate))
                    return false;
                value = candidate;
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// A "plausible" string is one where ≥80% of chars are printable ASCII or common Unicode.
        /// This filters out random binary data that might accidentally parse as valid UTF-16.
        /// </summary>
        private static bool IsPlausibleString(string s)
        {
            if (s.Length == 0)
                return true;

            var printable = 0;
            foreach (var c in s)
            {
                if (c >= 0x20 && c < 0x7F)        // printable ASCII
                    printable++;
                else if (c == '\t' || c == '\r' || c == '\n')
                    printable++;
                else if (c > 0x7F && !char.IsControl(c) && char.IsLetterOrDigit(c))
                    printable++;
            }

            return (double)printable / s.Length >= 0.80;
        }

        // ── Patching ───────────────────────────────────────────────────────────────

        private static int ApplyPatches(
            Dictionary<int, List<(CilInstruction Push, CilInstruction Call)>> callSites,
            Dictionary<int, string> strings)
        {
            var count = 0;
            foreach (var (offset, sites) in callSites)
            {
                if (!strings.TryGetValue(offset, out var value))
                    continue;

                foreach (var (push, call) in sites)
                {
                    push.OpCode = CilOpCodes.Ldstr;
                    push.Operand = value;
                    call.OpCode = CilOpCodes.Nop;
                    call.Operand = null;
                    count++;
                }
            }
            return count;
        }

        // ── Helpers ────────────────────────────────────────────────────────────────

        private static bool TryGetInt32Push(CilInstruction ins, out int value)
        {
            value = 0;
            var code = ins.OpCode.Code;
            switch (code)
            {
                case CilCode.Ldc_I4:
                    value = (int)ins.Operand;
                    return true;
                case CilCode.Ldc_I4_S:
                    value = (sbyte)ins.Operand;
                    return true;
                case CilCode.Ldc_I4_0:  value = 0;  return true;
                case CilCode.Ldc_I4_1:  value = 1;  return true;
                case CilCode.Ldc_I4_2:  value = 2;  return true;
                case CilCode.Ldc_I4_3:  value = 3;  return true;
                case CilCode.Ldc_I4_4:  value = 4;  return true;
                case CilCode.Ldc_I4_5:  value = 5;  return true;
                case CilCode.Ldc_I4_6:  value = 6;  return true;
                case CilCode.Ldc_I4_7:  value = 7;  return true;
                case CilCode.Ldc_I4_8:  value = 8;  return true;
                case CilCode.Ldc_I4_M1: value = -1; return true;
                default: return false;
            }
        }

        private static bool IsEnabled()
        {
            var v = Environment.GetEnvironmentVariable("KRYPTON_STRING_DECRYPT");
            return v == "1" || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase);
        }
    }
}
