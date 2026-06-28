using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using dnlib.DotNet;
using Newtonsoft.Json;

namespace Krypton.Runner
{
    internal static class NecrobitDumpRunner
    {
        public static int Run(string targetPath, string outputPath)
        {
            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine("[NecroBit] File not found: " + targetPath);
                return 1;
            }

            try
            {
                ExitGuard.Install();
                ExitGuard.Behavior = ExitGuardBehavior.Suppress;

                var assembly = LoadAndInitialize(targetPath);
                var hInstance = GetModuleBase(assembly);
                var methodsByRva = BuildMethodsByRva(targetPath);
                var rows = DumpHashtableBodies(assembly, hInstance, methodsByRva);

                var result = new NecrobitDumpResult
                {
                    Assembly = Path.GetFullPath(targetPath),
                    CapturedAt = DateTime.UtcNow.ToString("o"),
                    RuntimeVersion = Environment.Version.ToString(),
                    HInstance = "0x" + hInstance.ToString("X", CultureInfo.InvariantCulture),
                    Methods = rows
                        .OrderBy(r => r.Token)
                        .ToList()
                };

                File.WriteAllText(
                    outputPath,
                    JsonConvert.SerializeObject(result, Formatting.Indented),
                    System.Text.Encoding.UTF8);

                Console.WriteLine("[NecroBit] Wrote " + result.Methods.Count + " method body row(s) to " + outputPath);
                foreach (var row in result.Methods.Take(20))
                {
                    Console.WriteLine(
                        "[NecroBit]   " + row.Token +
                        " rva=" + row.Rva +
                        " len=" + row.Length +
                        " source=" + row.SourceField);
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[NecroBit] Dump failed: " + ex);
                return 2;
            }
        }

        private static Assembly LoadAndInitialize(string targetPath)
        {
            var fullPath = Path.GetFullPath(targetPath);
            var baseDir = Path.GetDirectoryName(fullPath);
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                var name = new AssemblyName(e.Name).Name;
                var dll = Path.Combine(baseDir ?? string.Empty, name + ".dll");
                if (File.Exists(dll))
                    return Assembly.LoadFrom(dll);
                var exe = Path.Combine(baseDir ?? string.Empty, name + ".exe");
                return File.Exists(exe) ? Assembly.LoadFrom(exe) : null;
            };

            var assembly = Assembly.LoadFrom(fullPath);

            foreach (var module in assembly.Modules)
            {
                try { RuntimeHelpers.RunModuleConstructor(module.ModuleHandle); }
                catch { }
            }

            foreach (var type in GetAllTypesSafe(assembly))
            {
                if (type == null || type.ContainsGenericParameters)
                    continue;

                try { RuntimeHelpers.RunClassConstructor(type.TypeHandle); }
                catch { }
            }

            return assembly;
        }

        private static long GetModuleBase(Assembly assembly)
        {
            try
            {
                return Marshal.GetHINSTANCE(assembly.ManifestModule).ToInt64();
            }
            catch
            {
                return 0;
            }
        }

        private static Dictionary<uint, NecrobitMethodInfo> BuildMethodsByRva(string targetPath)
        {
            var result = new Dictionary<uint, NecrobitMethodInfo>();
            using (var module = ModuleDefMD.Load(targetPath, (ModuleContext)null))
            {
                foreach (var type in module.GetTypes())
                {
                    foreach (var method in type.Methods)
                    {
                        var rva = (uint)method.RVA;
                        if (rva == 0 || result.ContainsKey(rva))
                            continue;

                        result.Add(rva, new NecrobitMethodInfo
                        {
                            Token = method.MDToken.ToUInt32(),
                            FullName = method.FullName,
                            Rva = rva
                        });
                    }
                }
            }

            return result;
        }

        private static List<NecrobitMethodBodyEntry> DumpHashtableBodies(
            Assembly assembly,
            long hInstance,
            Dictionary<uint, NecrobitMethodInfo> methodsByRva)
        {
            var result = new List<NecrobitMethodBodyEntry>();
            var seenTokens = new HashSet<uint>();

            foreach (var type in GetAllTypesSafe(assembly))
            {
                if (type == null)
                    continue;

                foreach (var field in GetStaticFieldsSafe(type))
                {
                    IDictionary table;
                    try
                    {
                        if (!typeof(IDictionary).IsAssignableFrom(field.FieldType))
                            continue;

                        table = field.GetValue(null) as IDictionary;
                    }
                    catch
                    {
                        continue;
                    }

                    if (table == null || table.Count == 0)
                        continue;

                    foreach (DictionaryEntry entry in table)
                    {
                        if (!TryConvertKey(entry.Key, out var key))
                            continue;

                        var body = ExtractByteArray(entry.Value);
                        if (body == null || body.Length == 0 || body.Length > 1024 * 1024)
                            continue;

                        foreach (var rva in GetRvaCandidates(key, hInstance))
                        {
                            if (!methodsByRva.TryGetValue(rva, out var method) ||
                                !seenTokens.Add(method.Token))
                            {
                                continue;
                            }

                            result.Add(new NecrobitMethodBodyEntry
                            {
                                Token = TokenText(method.Token),
                                Method = method.FullName,
                                Rva = "0x" + method.Rva.ToString("X8", CultureInfo.InvariantCulture),
                                EntryKey = "0x" + key.ToString("X", CultureInfo.InvariantCulture),
                                SourceField = SafeTypeName(type) + "::" + field.Name + "|" + SafeToken(field),
                                Length = body.Length,
                                Sha256 = Sha256(body),
                                Base64 = Convert.ToBase64String(body)
                            });
                            break;
                        }
                    }
                }
            }

            return result;
        }

        private static IEnumerable<uint> GetRvaCandidates(long key, long hInstance)
        {
            var candidates = new[]
            {
                key - hInstance - 1,
                key - hInstance,
                key - 1,
                key
            };

            var seen = new HashSet<uint>();
            foreach (var candidate in candidates)
            {
                if (candidate <= 0 || candidate > uint.MaxValue)
                    continue;

                var rva = (uint)candidate;
                if (seen.Add(rva))
                    yield return rva;
            }
        }

        private static byte[] ExtractByteArray(object value)
        {
            if (value == null)
                return null;

            var direct = value as byte[];
            if (direct != null)
                return direct;

            var type = value.GetType();
            foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
            {
                if (field.FieldType != typeof(byte[]))
                    continue;

                try
                {
                    return field.GetValue(value) as byte[];
                }
                catch
                {
                    return null;
                }
            }

            return null;
        }

        private static bool TryConvertKey(object key, out long value)
        {
            value = 0;
            if (key == null)
                return false;

            try
            {
                if (key is IntPtr ptr)
                {
                    value = ptr.ToInt64();
                    return true;
                }

                if (key is UIntPtr uptr)
                {
                    var raw = uptr.ToUInt64();
                    if (raw > long.MaxValue)
                        return false;
                    value = (long)raw;
                    return true;
                }

                if (key is ulong ulongValue)
                {
                    if (ulongValue > long.MaxValue)
                        return false;
                    value = (long)ulongValue;
                    return true;
                }

                if (key is IConvertible)
                {
                    value = Convert.ToInt64(key, CultureInfo.InvariantCulture);
                    return true;
                }
            }
            catch
            {
            }

            return false;
        }

        private static Type[] GetAllTypesSafe(Assembly assembly)
        {
            try
            {
                return assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException ex)
            {
                return ex.Types.Where(t => t != null).ToArray();
            }
        }

        private static FieldInfo[] GetStaticFieldsSafe(Type type)
        {
            try
            {
                return type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
            }
            catch
            {
                return new FieldInfo[0];
            }
        }

        private static string Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
            }
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
                return TokenText((uint)member.MetadataToken);
            }
            catch
            {
                return "0x00000000";
            }
        }

        private static string TokenText(uint token)
        {
            return "0x" + token.ToString("X8", CultureInfo.InvariantCulture);
        }
    }

    internal sealed class NecrobitDumpResult
    {
        public string Assembly { get; set; }
        public string CapturedAt { get; set; }
        public string RuntimeVersion { get; set; }
        public string HInstance { get; set; }
        public List<NecrobitMethodBodyEntry> Methods { get; set; }
    }

    internal sealed class NecrobitMethodBodyEntry
    {
        public string Token { get; set; }
        public string Method { get; set; }
        public string Rva { get; set; }
        public string EntryKey { get; set; }
        public string SourceField { get; set; }
        public int Length { get; set; }
        public string Sha256 { get; set; }
        public string Base64 { get; set; }
    }

    internal sealed class NecrobitMethodInfo
    {
        public uint Token { get; set; }
        public string FullName { get; set; }
        public uint Rva { get; set; }
    }
}
