using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;

namespace Krypton.Runner
{
    internal static class RuntimeValueRunner
    {
        public static int DumpFields(string[] args)
        {
            var targetPath = args[1];
            var outputPath = args[2];
            var requestedTokens = args
                .Skip(3)
                .Select(ParseToken)
                .Where(t => t != 0)
                .Distinct()
                .ToList();

            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine("[RuntimeValue] File not found: " + targetPath);
                return 1;
            }

            try
            {
                var assembly = LoadAndInitialize(targetPath);
                var rows = requestedTokens.Count == 0
                    ? DumpAllInterestingIntFields(assembly)
                    : requestedTokens.Select(t => DumpField(assembly, t)).ToList();

                File.WriteAllText(
                    outputPath,
                    JsonConvert.SerializeObject(new FieldDumpResult
                    {
                        Assembly = targetPath,
                        Fields = rows
                    }, Formatting.Indented));

                Console.WriteLine("[RuntimeValue] Wrote " + rows.Count + " field value(s) to " + outputPath);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[RuntimeValue] Field dump failed: " + ex);
                return 2;
            }
        }

        public static int EvaluateStrings(string[] args)
        {
            var targetPath = args[1];
            var outputPath = args[2];
            var cursor = 3;
            var decoderToken = 0x0600005C;

            if (cursor < args.Length && IsMethodToken(args[cursor]))
            {
                decoderToken = ParseToken(args[cursor]);
                cursor++;
            }

            var indices = args
                .Skip(cursor)
                .Select(ParseInt)
                .ToList();

            if (indices.Count == 0)
            {
                Console.Error.WriteLine("[RuntimeValue] No string indices were provided.");
                return 1;
            }

            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine("[RuntimeValue] File not found: " + targetPath);
                return 1;
            }

            try
            {
                var assembly = LoadAndInitialize(targetPath);
                var decoder = ResolveMethod(assembly, decoderToken) as MethodInfo;
                if (decoder == null)
                {
                    Console.Error.WriteLine("[RuntimeValue] Decoder method not found: 0x" + decoderToken.ToString("X8"));
                    return 2;
                }

                RelaxDecoderGuard(decoder.DeclaringType);
                RunClassConstructor(decoder.DeclaringType);
                RelaxDecoderGuard(decoder.DeclaringType);

                var rows = new List<StringEvalRow>();
                foreach (var index in indices)
                {
                    var row = new StringEvalRow { Index = index };
                    try
                    {
                        row.Text = decoder.Invoke(null, new object[] { index }) as string;
                    }
                    catch (TargetInvocationException ex)
                    {
                        row.Error = ex.InnerException == null
                            ? ex.Message
                            : ex.InnerException.GetType().Name + ": " + ex.InnerException.Message;
                    }
                    catch (Exception ex)
                    {
                        row.Error = ex.GetType().Name + ": " + ex.Message;
                    }

                    rows.Add(row);
                }

                File.WriteAllText(
                    outputPath,
                    JsonConvert.SerializeObject(new StringEvalResult
                    {
                        Assembly = targetPath,
                        DecoderToken = "0x" + decoderToken.ToString("X8"),
                        Strings = rows
                    }, Formatting.Indented));

                Console.WriteLine("[RuntimeValue] Wrote " + rows.Count + " decoded string row(s) to " + outputPath);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[RuntimeValue] String evaluation failed: " + ex);
                return 2;
            }
        }

        private static Assembly LoadAndInitialize(string targetPath)
        {
            ExitGuard.Install();
            ExitGuard.Behavior = ExitGuardBehavior.Suppress;

            var fullPath = Path.GetFullPath(targetPath);
            var baseDir = Path.GetDirectoryName(fullPath);
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                var name = new AssemblyName(e.Name).Name;
                var candidate = Path.Combine(baseDir ?? string.Empty, name + ".dll");
                return File.Exists(candidate) ? Assembly.LoadFrom(candidate) : null;
            };

            var assembly = Assembly.LoadFrom(fullPath);

            foreach (var module in assembly.Modules)
            {
                try { RuntimeHelpers.RunModuleConstructor(module.ModuleHandle); }
                catch { /* Protected initializers are best effort only. */ }
            }

            Type[] types;
            try { types = assembly.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { types = ex.Types; }

            foreach (var type in types)
            {
                if (type == null || type.ContainsGenericParameters)
                    continue;
                RunClassConstructor(type);
            }

            return assembly;
        }

        private static void RunClassConstructor(Type type)
        {
            try { RuntimeHelpers.RunClassConstructor(type.TypeHandle); }
            catch { /* Best effort only. */ }
        }

        private static List<FieldDumpRow> DumpAllInterestingIntFields(Assembly assembly)
        {
            var rows = new List<FieldDumpRow>();
            var flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance;

            foreach (var type in GetAllTypesSafe(assembly))
            {
                if (type == null)
                    continue;

                var interestingType =
                    string.Equals(type.Name, "<Module>", StringComparison.Ordinal) ||
                    (type.FullName ?? string.Empty).IndexOf("{", StringComparison.Ordinal) >= 0;
                if (!interestingType)
                    continue;

                foreach (var field in type.GetFields(flags)
                    .Where(f => f.FieldType == typeof(int) || f.FieldType == typeof(bool)))
                {
                    rows.Add(DumpField(field));
                }
            }

            return rows;
        }

        private static FieldDumpRow DumpField(Assembly assembly, int token)
        {
            try
            {
                var field = ResolveField(assembly, token);
                if (field == null)
                {
                    return new FieldDumpRow
                    {
                        Token = TokenText(token),
                        Error = "field not found"
                    };
                }

                return DumpField(field);
            }
            catch (Exception ex)
            {
                return new FieldDumpRow
                {
                    Token = TokenText(token),
                    Error = ex.GetType().Name + ": " + ex.Message
                };
            }
        }

        private static FieldDumpRow DumpField(FieldInfo field)
        {
            var row = new FieldDumpRow
            {
                Token = TokenText(field.MetadataToken),
                DeclaringType = field.DeclaringType == null ? null : field.DeclaringType.FullName,
                Name = field.Name,
                FieldType = field.FieldType.FullName,
                IsStatic = field.IsStatic
            };

            try
            {
                object owner = null;
                if (!field.IsStatic)
                {
                    owner = TryGetSingletonInstance(field.DeclaringType);
                    if (owner == null)
                    {
                        row.Error = "instance owner not found";
                        return row;
                    }
                }

                var value = field.GetValue(owner);
                row.Value = value == null ? null : Convert.ToString(value, CultureInfo.InvariantCulture);
            }
            catch (Exception ex)
            {
                row.Error = ex.GetType().Name + ": " + ex.Message;
            }

            return row;
        }

        private static object TryGetSingletonInstance(Type type)
        {
            if (type == null)
                return null;

            var flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;
            foreach (var field in type.GetFields(flags))
            {
                if (field.FieldType != type)
                    continue;

                try
                {
                    var value = field.GetValue(null);
                    if (value != null)
                        return value;
                }
                catch
                {
                    // Try the next candidate.
                }
            }

            return null;
        }

        private static void RelaxDecoderGuard(Type decoderType)
        {
            if (decoderType == null)
                return;

            var flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;
            foreach (var field in decoderType.GetFields(flags))
            {
                if (field.IsInitOnly || field.IsLiteral || field.FieldType != typeof(int))
                    continue;

                try
                {
                    var current = (int) field.GetValue(null);
                    if (current < 75)
                        field.SetValue(null, 75);
                }
                catch
                {
                    // Best effort only.
                }
            }
        }

        private static FieldInfo ResolveField(Assembly assembly, int token)
        {
            foreach (var module in assembly.Modules)
            {
                try
                {
                    return module.ResolveField(token);
                }
                catch
                {
                    // Try next module.
                }
            }

            return null;
        }

        private static MethodBase ResolveMethod(Assembly assembly, int token)
        {
            foreach (var module in assembly.Modules)
            {
                try
                {
                    return module.ResolveMethod(token);
                }
                catch
                {
                    // Try next module.
                }
            }

            return null;
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

        private static bool IsMethodToken(string value)
        {
            var token = ParseToken(value);
            return (token & unchecked((int)0xFF000000)) == 0x06000000;
        }

        private static int ParseToken(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0;

            var text = value.Trim();
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                text = text.Substring(2);

            int parsed;
            return int.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed)
                ? parsed
                : 0;
        }

        private static int ParseInt(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0;

            var text = value.Trim();
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return ParseToken(text);

            int parsed;
            return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed)
                ? parsed
                : 0;
        }

        private static string TokenText(int token)
        {
            return "0x" + token.ToString("X8", CultureInfo.InvariantCulture);
        }
    }

    internal sealed class FieldDumpResult
    {
        public string Assembly { get; set; }
        public List<FieldDumpRow> Fields { get; set; }
    }

    internal sealed class FieldDumpRow
    {
        public string Token { get; set; }
        public string DeclaringType { get; set; }
        public string Name { get; set; }
        public string FieldType { get; set; }
        public bool IsStatic { get; set; }
        public string Value { get; set; }
        public string Error { get; set; }
    }

    internal sealed class StringEvalResult
    {
        public string Assembly { get; set; }
        public string DecoderToken { get; set; }
        public List<StringEvalRow> Strings { get; set; }
    }

    internal sealed class StringEvalRow
    {
        public int Index { get; set; }
        public string Text { get; set; }
        public string Error { get; set; }
    }
}
