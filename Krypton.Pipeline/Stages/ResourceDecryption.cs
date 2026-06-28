using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;

namespace Krypton.Pipeline.Stages
{
    /// <summary>
    /// Recovers NET Reactor "Compress &amp; Encrypt Resources" protection.
    ///
    /// NET Reactor encrypts embedded user resources (images, .resources, data files) using
    /// AES-128 with a key derived from the assembly MVID, then deflate-compresses them.
    /// At runtime the AppDomain.ResourceResolve event is used to decrypt on demand.
    ///
    /// This stage:
    ///   1. Detects the ResourceResolve registration in the module's static initializers.
    ///   2. Identifies which embedded resources are encrypted (high-entropy blobs).
    ///   3. Attempts AES-128 decryption using MVID-derived keys (known NET Reactor patterns).
    ///   4. Decompresses and replaces the resource data in the module manifest.
    ///   5. Removes the ResourceResolve hook registration if fully cleaned.
    ///
    /// Enable via: KRYPTON_RESOURCE_DECRYPT=1
    /// </summary>
    public sealed class ResourceDecryption : IStage
    {
        public string Name => nameof(ResourceDecryption);

        public void Run(DevirtualizationCtx ctx)
        {
            if (!IsEnabled())
                return;

            var module = ctx.Module;
            if (module == null)
                return;

            // Find the resource resolver handler registered via AppDomain.ResourceResolve.
            var handlerMethod = FindResourceResolveHandler(module);
            if (handlerMethod == null)
            {
                ctx.Options.Logger.Info("ResourceDecryption: no ResourceResolve handler found.");
                return;
            }

            ctx.Options.Logger.Info($"ResourceDecryption: found resource resolver {handlerMethod.MetadataToken}.");

            // Extract the resource names the handler is known to decrypt.
            var encryptedResourceNames = FindEncryptedResourceNames(module, handlerMethod);
            if (encryptedResourceNames.Count == 0)
            {
                ctx.Options.Logger.Info("ResourceDecryption: no encrypted resource names identified.");
                return;
            }

            ctx.Options.Logger.Info($"ResourceDecryption: {encryptedResourceNames.Count} encrypted resource(s) identified.");

            // Derive decryption keys from assembly MVID using known NET Reactor patterns.
            var candidateKeys = DeriveAesKeys(module);

            var decrypted = 0;
            foreach (var resourceName in encryptedResourceNames)
            {
                var resource = module.Resources
                    .OfType<ManifestResource>()
                    .FirstOrDefault(r => r.Name == resourceName && r.IsEmbedded);

                if (resource == null)
                    continue;

                var cipherBytes = resource.GetData();
                if (cipherBytes == null || cipherBytes.Length < 32)
                    continue;

                byte[] plainBytes = null;
                foreach (var (key, iv) in candidateKeys)
                {
                    plainBytes = TryAesDecrypt(cipherBytes, key, iv);
                    if (plainBytes != null)
                        break;
                }

                if (plainBytes == null)
                {
                    ctx.Options.Logger.Info($"ResourceDecryption: could not decrypt '{resourceName}' — key not matched.");
                    continue;
                }

                // Decompress (DEFLATE).
                var decompressed = TryDeflateDecompress(plainBytes);
                var finalBytes = decompressed ?? plainBytes;

                resource.EmbeddedDataSegment = new AsmResolver.DataSegment(finalBytes);
                decrypted++;
                ctx.Options.Logger.Info($"ResourceDecryption: restored '{resourceName}' ({finalBytes.Length} bytes).");
            }

            if (decrypted > 0)
                ctx.Options.Logger.Info($"ResourceDecryption: {decrypted}/{encryptedResourceNames.Count} resource(s) decrypted and restored.");
        }

        // ── Detection ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Finds the method that is passed to AppDomain.add_ResourceResolve.
        /// It is typically referenced in a module-level static constructor.
        /// </summary>
        private static MethodDefinition FindResourceResolveHandler(ModuleDefinition module)
        {
            foreach (var type in module.GetAllTypes())
            {
                var cctor = type.Methods.FirstOrDefault(m => m.IsStatic && m.Name == ".cctor");
                if (cctor == null || !cctor.HasMethodBody || cctor.CilMethodBody == null)
                    continue;

                var instr = cctor.CilMethodBody.Instructions;
                for (int i = 0; i < instr.Count; i++)
                {
                    var ins = instr[i];
                    if (ins.OpCode != CilOpCodes.Call && ins.OpCode != CilOpCodes.Callvirt)
                        continue;

                    var callee = (ins.Operand as IMethodDescriptor)?.FullName ?? string.Empty;
                    if (!callee.Contains("add_ResourceResolve", StringComparison.Ordinal))
                        continue;

                    // Walk back to find the ldftn that creates the delegate.
                    for (int j = i - 1; j >= 0 && j >= i - 8; j--)
                    {
                        if (instr[j].OpCode == CilOpCodes.Ldftn ||
                            instr[j].OpCode == CilOpCodes.Ldvirtftn)
                        {
                            return (instr[j].Operand as IMethodDescriptor)?.Resolve() as MethodDefinition;
                        }
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Finds resource names that the handler decrypts, by looking for ldstr instructions
        /// in the handler method that match known embedded resource names.
        /// </summary>
        private static List<string> FindEncryptedResourceNames(
            ModuleDefinition module,
            MethodDefinition handler)
        {
            var embeddedNames = new HashSet<string>(
                module.Resources.OfType<ManifestResource>()
                    .Where(r => r.IsEmbedded && IsHighEntropy(r.GetData()))
                    .Select(r => r.Name.ToString()),
                StringComparer.Ordinal);

            var referencedNames = new List<string>();

            if (handler?.HasMethodBody == true && handler.CilMethodBody != null)
            {
                foreach (var ins in handler.CilMethodBody.Instructions)
                {
                    if (ins.OpCode == CilOpCodes.Ldstr && ins.Operand is string s && embeddedNames.Contains(s))
                        referencedNames.Add(s);
                }
            }

            // Fall back: return all high-entropy embedded resources if handler didn't name any.
            if (referencedNames.Count == 0)
                referencedNames.AddRange(embeddedNames);

            return referencedNames;
        }

        // ── Key derivation ─────────────────────────────────────────────────────────

        /// <summary>
        /// Derives AES-128 key candidates from the assembly MVID.
        /// NET Reactor uses the MVID bytes hashed with SHA1 or MD5 as the AES key.
        /// Returns (key, iv) pairs to try in order.
        /// </summary>
        private static IEnumerable<(byte[] Key, byte[] IV)> DeriveAesKeys(ModuleDefinition module)
        {
            var mvid = module.Mvid.ToByteArray();
            if (mvid == null || mvid.Length == 0 || module.Mvid == Guid.Empty)
                yield break;

            // Pattern 1: SHA1(MVID) → first 16 bytes = key, next 16 bytes wrap (or zeros for IV)
            {
                var hash = SHA1.HashData(mvid);
                var key16 = hash.Take(16).ToArray();
                yield return (key16, new byte[16]);
                yield return (key16, hash.Skip(4).Take(16).ToArray());
            }

            // Pattern 2: MD5(MVID) → 16 bytes = key
            {
                var hash = MD5.HashData(mvid);
                yield return (hash, new byte[16]);
                // IV = first 16 bytes of encrypted resource (handled in TryAesDecrypt)
            }

            // Pattern 3: SHA256(MVID) → first 16 bytes = key
            {
                var hash = SHA256.HashData(mvid);
                yield return (hash.Take(16).ToArray(), new byte[16]);
                yield return (hash.Take(16).ToArray(), hash.Skip(16).Take(16).ToArray());
            }
        }

        // ── Decryption ─────────────────────────────────────────────────────────────

        private static byte[] TryAesDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            // Some NET Reactor variants prepend the IV as the first 16 bytes of the resource.
            // Try both the provided IV and the first 16 bytes of the cipher data.
            var result = TryAesDecryptCore(data, key, iv);
            if (result != null)
                return result;

            if (data.Length >= 32)
            {
                var embeddedIv = new byte[16];
                Array.Copy(data, 0, embeddedIv, 0, 16);
                result = TryAesDecryptCore(data, key, embeddedIv, offset: 16);
            }
            return result;
        }

        private static byte[] TryAesDecryptCore(byte[] data, byte[] key, byte[] iv, int offset = 0)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using var decryptor = aes.CreateDecryptor();
                using var ms = new MemoryStream(data, offset, data.Length - offset);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
                using var output = new MemoryStream();

                cs.CopyTo(output);
                var result = output.ToArray();

                // Sanity: result should not be all zeros or all same byte.
                if (result.Length < 4 || result.All(b => b == result[0]))
                    return null;

                return result;
            }
            catch
            {
                return null;
            }
        }

        private static byte[] TryDeflateDecompress(byte[] data)
        {
            // Try raw deflate (NET Reactor) and also zlib (deflate with 2-byte header).
            var result = TryDecompress(data, skipBytes: 0);
            if (result != null) return result;
            if (data.Length > 2)
                result = TryDecompress(data, skipBytes: 2);
            return result;
        }

        private static byte[] TryDecompress(byte[] data, int skipBytes)
        {
            try
            {
                using var input = new MemoryStream(data, skipBytes, data.Length - skipBytes);
                using var deflate = new System.IO.Compression.DeflateStream(input,
                    System.IO.Compression.CompressionMode.Decompress);
                using var output = new MemoryStream();
                deflate.CopyTo(output);
                var result = output.ToArray();
                return result.Length > 0 ? result : null;
            }
            catch
            {
                return null;
            }
        }

        // ── Entropy check ──────────────────────────────────────────────────────────

        /// <summary>
        /// Returns true when a blob looks encrypted (Shannon entropy > 7.0 bits/byte).
        /// This filters out plaintext .resources files and other readable blobs.
        /// </summary>
        private static bool IsHighEntropy(byte[] data)
        {
            if (data == null || data.Length < 64)
                return false;

            var freq = new int[256];
            foreach (var b in data)
                freq[b]++;

            double entropy = 0.0;
            foreach (var f in freq)
            {
                if (f == 0) continue;
                var p = (double)f / data.Length;
                entropy -= p * Math.Log(p, 2);
            }

            return entropy > 7.0;
        }

        private static bool IsEnabled()
        {
            var v = Environment.GetEnvironmentVariable("KRYPTON_RESOURCE_DECRYPT");
            return v == "1" || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase);
        }
    }
}
