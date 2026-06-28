using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HarmonyLib;
using Newtonsoft.Json;

namespace Krypton.Runner
{
    internal static class PayloadTraceRunner
    {
        private static Harmony _harmony;
        private static readonly object Sync = new object();
        private static readonly Dictionary<string, PayloadBufferEntry> Seen =
            new Dictionary<string, PayloadBufferEntry>(StringComparer.OrdinalIgnoreCase);
        private static readonly List<PayloadBufferEntry> Buffers =
            new List<PayloadBufferEntry>();

        private static int _nextIndex;
        private static int _minLength = 64;
        private static int _maxBuffers = 256;

        public static int Run(string targetPath, string outputPath)
        {
            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine("[PayloadTrace] File not found: " + targetPath);
                return 1;
            }

            try
            {
                ReadOptions();
                InstallPatches();
                ExitGuard.Install();
                ExitGuard.Behavior = ExitGuardBehavior.Suppress;

                var assembly = LoadTarget(targetPath);
                Console.WriteLine("[PayloadTrace] Loaded: " + assembly.FullName);

                TriggerInitialization(assembly);
                CaptureStaticByteArrays(assembly);

                var dump = new PayloadTraceDump
                {
                    AssemblyPath = Path.GetFullPath(targetPath),
                    CapturedAt = DateTime.UtcNow.ToString("o"),
                    RuntimeVersion = Environment.Version.ToString(),
                    Buffers = Buffers
                        .OrderByDescending(b => b.Length)
                        .ThenBy(b => b.Index)
                        .ToList()
                };

                File.WriteAllText(
                    outputPath,
                    JsonConvert.SerializeObject(dump, Formatting.Indented),
                    System.Text.Encoding.UTF8);

                Console.WriteLine("[PayloadTrace] Wrote: " + outputPath);
                Console.WriteLine("[PayloadTrace] Buffers captured: " + dump.Buffers.Count);
                foreach (var buffer in dump.Buffers.Take(20))
                {
                    Console.WriteLine(
                        "[PayloadTrace]   #" + buffer.Index +
                        " len=" + buffer.Length +
                        " sha256=" + buffer.Sha256.Substring(0, 12) +
                        " source=" + buffer.Source);
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[PayloadTrace] Fatal error: " + ex);
                return 2;
            }
            finally
            {
                if (_harmony != null)
                    _harmony.UnpatchAll("krypton.runner.payloadtrace");
            }
        }

        private static void ReadOptions()
        {
            int value;
            if (int.TryParse(Environment.GetEnvironmentVariable("KRYPTON_PAYLOAD_TRACE_MIN"), out value) &&
                value >= 0)
            {
                _minLength = value;
            }

            if (int.TryParse(Environment.GetEnvironmentVariable("KRYPTON_PAYLOAD_TRACE_MAX"), out value) &&
                value > 0)
            {
                _maxBuffers = value;
            }
        }

        private static Assembly LoadTarget(string targetPath)
        {
            var baseDir = Path.GetDirectoryName(Path.GetFullPath(targetPath));
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                var simpleName = new AssemblyName(e.Name).Name;
                var candidate = Path.Combine(baseDir, simpleName + ".dll");
                if (File.Exists(candidate))
                    return Assembly.LoadFrom(candidate);
                candidate = Path.Combine(baseDir, simpleName + ".exe");
                if (File.Exists(candidate))
                    return Assembly.LoadFrom(candidate);
                return null;
            };

            var rawBytes = File.ReadAllBytes(targetPath);
            try
            {
                return Assembly.Load(rawBytes);
            }
            catch (BadImageFormatException)
            {
                return Assembly.LoadFrom(targetPath);
            }
        }

        private static void TriggerInitialization(Assembly assembly)
        {
            Console.WriteLine("[PayloadTrace] Triggering assembly initialization...");

            Type[] types;
            try
            {
                types = assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException ex)
            {
                types = ex.Types;
            }

            foreach (var type in types)
            {
                if (type == null || type.ContainsGenericParameters)
                    continue;

                try
                {
                    RuntimeHelpers.RunClassConstructor(type.TypeHandle);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(
                        "[PayloadTrace]   .cctor ignored " + SafeTypeName(type) +
                        ": " + ex.GetType().Name);
                }
            }

            Console.WriteLine("[PayloadTrace] Initialization complete.");
        }

        private static void CaptureStaticByteArrays(Assembly assembly)
        {
            Type[] types;
            try
            {
                types = assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException ex)
            {
                types = ex.Types;
            }

            foreach (var type in types)
            {
                if (type == null || type.ContainsGenericParameters)
                    continue;

                FieldInfo[] fields;
                try
                {
                    fields = type.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                }
                catch
                {
                    continue;
                }

                foreach (var field in fields)
                {
                    try
                    {
                        if (field.FieldType == typeof(byte[]))
                        {
                            var value = field.GetValue(null) as byte[];
                            Capture("static " + SafeTypeName(type) + "::" + field.Name + "|" + SafeToken(field), value);
                        }
                        else if (field.FieldType.IsArray &&
                                 field.FieldType.GetElementType() == typeof(byte[]))
                        {
                            var array = field.GetValue(null) as Array;
                            if (array == null)
                                continue;
                            for (var i = 0; i < array.Length; i++)
                                Capture("static " + SafeTypeName(type) + "::" + field.Name + "[" + i + "]|" + SafeToken(field),
                                    array.GetValue(i) as byte[]);
                        }
                    }
                    catch
                    {
                    }
                }
            }
        }

        private static void InstallPatches()
        {
            _harmony = new Harmony("krypton.runner.payloadtrace");

            PatchPostfix(
                typeof(MemoryStream).GetMethod("ToArray", BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null),
                nameof(MemoryStreamToArrayPostfix));
            PatchPostfix(
                typeof(BinaryReader).GetMethod("ReadBytes", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(int) }, null),
                nameof(BinaryReaderReadBytesPostfix));
            PatchPrefix(
                typeof(CryptoStream).GetMethod("Write", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(byte[]), typeof(int), typeof(int) }, null),
                nameof(CryptoStreamWritePrefix));
            PatchPrefix(
                typeof(SymmetricAlgorithm).GetMethod("CreateDecryptor", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(byte[]), typeof(byte[]) }, null),
                nameof(CreateDecryptorPrefix));
            PatchPrefix(
                typeof(RijndaelManaged).GetMethod("CreateDecryptor", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(byte[]), typeof(byte[]) }, null),
                nameof(CreateDecryptorPrefix));

            var aesCsp = typeof(AesCryptoServiceProvider);
            PatchPrefix(
                aesCsp.GetMethod("CreateDecryptor", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(byte[]), typeof(byte[]) }, null),
                nameof(CreateDecryptorPrefix));
        }

        private static void PatchPrefix(MethodInfo target, string patchName)
        {
            if (target == null)
                return;

            try
            {
                _harmony.Patch(
                    target,
                    prefix: new HarmonyMethod(typeof(PayloadTraceRunner).GetMethod(
                        patchName,
                        BindingFlags.Public | BindingFlags.Static)));
                Console.WriteLine("[PayloadTrace] patched prefix: " + target.DeclaringType.FullName + "::" + target.Name);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[PayloadTrace] patch skipped " + target.Name + ": " + ex.Message);
            }
        }

        private static void PatchPostfix(MethodInfo target, string patchName)
        {
            if (target == null)
                return;

            try
            {
                _harmony.Patch(
                    target,
                    postfix: new HarmonyMethod(typeof(PayloadTraceRunner).GetMethod(
                        patchName,
                        BindingFlags.Public | BindingFlags.Static)));
                Console.WriteLine("[PayloadTrace] patched postfix: " + target.DeclaringType.FullName + "::" + target.Name);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[PayloadTrace] patch skipped " + target.Name + ": " + ex.Message);
            }
        }

        public static void MemoryStreamToArrayPostfix(MemoryStream __instance, byte[] __result)
        {
            Capture("MemoryStream.ToArray", __result);
        }

        public static void BinaryReaderReadBytesPostfix(int __0, byte[] __result)
        {
            Capture("BinaryReader.ReadBytes(" + __0 + ")", __result);
        }

        public static void CryptoStreamWritePrefix(byte[] __0, int __1, int __2)
        {
            var buffer = __0;
            var offset = __1;
            var count = __2;
            if (buffer == null || count <= 0)
                return;

            if (offset == 0 && count == buffer.Length)
            {
                Capture("CryptoStream.Write input", buffer);
                return;
            }

            if (offset < 0 || count < 0 || offset + count > buffer.Length)
                return;

            var copy = new byte[count];
            Buffer.BlockCopy(buffer, offset, copy, 0, count);
            Capture("CryptoStream.Write input slice", copy);
        }

        public static void CreateDecryptorPrefix(byte[] __0, byte[] __1)
        {
            Capture("CreateDecryptor key", __0);
            Capture("CreateDecryptor iv", __1);
        }

        private static void Capture(string source, byte[] data)
        {
            if (data == null || data.Length < _minLength)
                return;

            lock (Sync)
            {
                if (Buffers.Count >= _maxBuffers)
                    return;

                string sha = Sha256(data);
                if (Seen.ContainsKey(sha))
                    return;

                var entry = new PayloadBufferEntry
                {
                    Index = _nextIndex++,
                    Source = source ?? string.Empty,
                    Length = data.Length,
                    Sha256 = sha,
                    Entropy = Entropy(data),
                    Head = Hex(data, Math.Min(data.Length, 32)),
                    Base64 = Convert.ToBase64String(data)
                };

                Seen.Add(sha, entry);
                Buffers.Add(entry);
            }
        }

        private static string Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
            }
        }

        private static double Entropy(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0;

            var counts = new int[256];
            for (var i = 0; i < data.Length; i++)
                counts[data[i]]++;

            var entropy = 0.0;
            for (var i = 0; i < counts.Length; i++)
            {
                var count = counts[i];
                if (count == 0)
                    continue;

                var p = (double)count / data.Length;
                entropy -= p * (Math.Log(p) / Math.Log(2.0));
            }

            return entropy;
        }

        private static string Hex(byte[] data, int count)
        {
            if (data == null || data.Length == 0)
                return string.Empty;

            var items = new string[count];
            for (var i = 0; i < count; i++)
                items[i] = data[i].ToString("X2");
            return string.Join(" ", items);
        }

        private static string SafeTypeName(Type type)
        {
            try
            {
                return type.FullName ?? type.Name;
            }
            catch
            {
                return "<type>";
            }
        }

        private static string SafeToken(MemberInfo member)
        {
            try
            {
                return "0x" + member.MetadataToken.ToString("X8");
            }
            catch
            {
                return "0x00000000";
            }
        }
    }

    public sealed class PayloadTraceDump
    {
        public string AssemblyPath { get; set; }
        public string CapturedAt { get; set; }
        public string RuntimeVersion { get; set; }
        public List<PayloadBufferEntry> Buffers { get; set; }
    }

    public sealed class PayloadBufferEntry
    {
        public int Index { get; set; }
        public string Source { get; set; }
        public int Length { get; set; }
        public string Sha256 { get; set; }
        public double Entropy { get; set; }
        public string Head { get; set; }
        public string Base64 { get; set; }
    }
}
