using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;

namespace Krypton.Runner
{
    /// <summary>
    /// Diagnostic-only pass: prints every static field in the protected assembly
    /// so we can see exactly where NET Reactor stores its delegates/DynamicMethods.
    /// Run with --diag flag.
    /// </summary>
    internal static class DiagnosticRunner
    {
        public static void Run(string assemblyPath)
        {
            Console.WriteLine($"[Diag] Loading: {assemblyPath}");

            var baseDir = Path.GetDirectoryName(assemblyPath);
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                var name = new AssemblyName(e.Name).Name;
                var p = Path.Combine(baseDir, name + ".dll");
                return File.Exists(p) ? Assembly.LoadFrom(p) : null;
            };

            // Use LoadFrom so Assembly.Location is populated (important for NET Reactor
            // bootstrap that reads the file via its own location)
            Assembly asm;
            try { asm = Assembly.LoadFrom(assemblyPath); }
            catch (Exception ex)
            {
                Console.WriteLine($"[Diag] Load failed: {ex.Message}");
                return;
            }

            Console.WriteLine($"[Diag] Assembly: {asm.FullName}");
            Console.WriteLine($"[Diag] Location: {asm.Location}");
            Console.WriteLine();

            Type[] types;
            try { types = asm.GetTypes(); }
            catch (ReflectionTypeLoadException e) { types = e.Types; }

            // Trigger .cctors
            Console.WriteLine("[Diag] Triggering .cctors...");
            foreach (var t in types)
            {
                if (t == null || t.ContainsGenericParameters) continue;
                try { System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
                catch (Exception ex) { Console.WriteLine($"[Diag]   .cctor fail: {t.FullName} → {ex.InnerException?.GetType().Name ?? ex.GetType().Name}: {ex.InnerException?.Message ?? ex.Message}"); }
            }
            Console.WriteLine();

            // Dump all static fields
            Console.WriteLine("[Diag] Static fields inventory:");
            Console.WriteLine("─────────────────────────────────────────────────────────────────");

            foreach (var t in types)
            {
                if (t == null) continue;
                var closedType = t.ContainsGenericParameters ? null : t;

                var fields = t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                if (fields.Length == 0) continue;

                Console.WriteLine($"\n  [{t.FullName}]");

                foreach (var f in fields)
                {
                    string typeName = f.FieldType.Name;
                    if (closedType == null)
                    {
                        Console.WriteLine($"    {f.Name} : {typeName}  (open generic — skip read)");
                        continue;
                    }

                    object val;
                    try { val = f.GetValue(null); }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"    {f.Name} : {typeName}  ERROR={ex.GetType().Name}");
                        continue;
                    }

                    if (val == null)
                    {
                        Console.WriteLine($"    {f.Name} : {typeName}  = null");
                        continue;
                    }

                    var actualType = val.GetType();

                    if (val is Delegate d)
                    {
                        PrintDelegate(f.Name, typeName, d, 0);
                    }
                    else if (actualType.IsArray)
                    {
                        var arr = (Array)val;
                        Console.WriteLine($"    {f.Name} : {typeName}  = {actualType.GetElementType()?.Name}[{arr.Length}]");
                        for (int i = 0; i < Math.Min(arr.Length, 10); i++)
                        {
                            var elem = arr.GetValue(i);
                            if (elem is Delegate ed)
                                PrintDelegate($"      [{i}]", typeName, ed, 4);
                            else
                                Console.WriteLine($"      [{i}] = {elem?.GetType()?.Name ?? "null"}");
                        }
                        if (arr.Length > 10) Console.WriteLine($"      ... +{arr.Length - 10} more");
                    }
                    else if (val is IDictionary dict)
                    {
                        Console.WriteLine($"    {f.Name} : {typeName}  = Dictionary, {dict.Count} entries");
                        int shown = 0;
                        foreach (DictionaryEntry kv in dict)
                        {
                            if (shown++ > 5) { Console.WriteLine("      ..."); break; }
                            if (kv.Value is Delegate dd)
                                PrintDelegate($"      [{kv.Key}]", typeName, dd, 4);
                            else
                                Console.WriteLine($"      [{kv.Key}] = {kv.Value?.GetType()?.Name ?? "null"}");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"    {f.Name} : {typeName}  = {actualType.Name}: {TryToString(val)}");
                    }
                }
            }

            Console.WriteLine();
            Console.WriteLine("[Diag] Done.");
        }

        private static void PrintDelegate(string label, string fieldType, Delegate d, int indent)
        {
            var pad = new string(' ', indent);
            var m   = d.Method;
            bool isDynamic = m is DynamicMethod;
            Console.WriteLine($"{pad}  {label} : {fieldType}  → Delegate → {(isDynamic ? "DynamicMethod" : m?.GetType()?.Name)}  Method={m?.Name}  DeclaringType={m?.DeclaringType?.Name ?? "<null>"}");
            if (!isDynamic && d.GetInvocationList().Length > 1)
            {
                foreach (var sub in d.GetInvocationList())
                    PrintDelegate($"  {label}[inv]", fieldType, sub, indent + 2);
            }
        }

        private static string TryToString(object o)
        {
            try { return o.ToString().Replace('\n', ' ').Replace('\r', ' ').Substring(0, Math.Min(80, o.ToString().Length)); }
            catch { return "?"; }
        }
    }
}
