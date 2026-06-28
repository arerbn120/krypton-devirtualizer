using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Newtonsoft.Json;

namespace Krypton.Runner
{
    /// <summary>
    /// Krypton.Runner — dynamic analysis helper (net48).
    ///
    /// Usage:  Krypton.Runner.exe  &lt;protected-exe&gt;  &lt;output-dump.json&gt;
    ///
    /// Loads the NET Reactor protected assembly inside a real .NET Framework 4.x
    /// process, lets the bootstrap run so all DynamicMethods are created, captures
    /// their IL via dnlib's DynamicMethodBodyReader, and writes the resolved IL to
    /// a JSON dump consumed by Krypton's HiddenCallRecovery stage.
    ///
    /// Exit codes:
    ///   0 — success
    ///   1 — bad arguments
    ///   2 — load / capture failure
    /// </summary>
    internal static class Program
    {
        private static int Main(string[] args)
        {
            Console.WriteLine("Krypton.Runner  [dynamic DynamicMethod capture for NET Reactor]");
            Console.WriteLine();

            if (args.Length >= 2 && args[0] == "--diag")
            {
                DiagnosticRunner.Run(args[1]);
                return 0;
            }

            // --snapshot <exe> <forms.json>  — runs ONLY form snapshot (called as child process)
            if (args.Length >= 3 && args[0] == "--snapshot")
            {
                return RunFormSnapshot(args[1], args[2]);
            }

            // --payload-trace <exe> <payload-trace.json>  - captures runtime byte buffers
            // produced by NET Reactor resource/method-body decryptors.
            if (args.Length >= 3 && args[0] == "--payload-trace")
            {
                return PayloadTraceRunner.Run(args[1], args[2]);
            }

            // --necrobit-dump <exe> <necrobit-dump.json>  - extracts NecroBit runtime
            // Hashtable method bodies and maps them back to metadata method tokens.
            if (args.Length >= 3 && args[0] == "--necrobit-dump")
            {
                return NecrobitDumpRunner.Run(args[1], args[2]);
            }

            // --dump-fields <exe> <fields.json> [metadata-token...]
            if (args.Length >= 3 && args[0] == "--dump-fields")
            {
                return RuntimeValueRunner.DumpFields(args);
            }

            // --eval-strings <exe> <strings.json> [decoder-token] <index...>
            if (args.Length >= 4 && args[0] == "--eval-strings")
            {
                return RuntimeValueRunner.EvaluateStrings(args);
            }

            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: Krypton.Runner.exe <protected-exe> <output-dump.json>");
                Console.Error.WriteLine("       Krypton.Runner.exe --diag <protected-exe>");
                Console.Error.WriteLine("       Krypton.Runner.exe --payload-trace <protected-exe> <payload-trace.json>");
                Console.Error.WriteLine("       Krypton.Runner.exe --necrobit-dump <protected-exe> <necrobit-dump.json>");
                Console.Error.WriteLine("       Krypton.Runner.exe --dump-fields <protected-exe> <fields.json> [metadata-token...]");
                Console.Error.WriteLine("       Krypton.Runner.exe --eval-strings <protected-exe> <strings.json> [decoder-token] <index...>");
                return 1;
            }

            string targetPath = args[0];
            string outputPath = args[1];

            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine($"[Runner] File not found: {targetPath}");
                return 1;
            }

            try
            {
                var runner = new AssemblyRunner(targetPath);
                var dump   = runner.Run();

                // Write DynamicMethod dump immediately — before attempting form snapshot
                // (form snapshot runs in a child process and may call Environment.Exit).
                string json = JsonConvert.SerializeObject(dump, Formatting.Indented);
                File.WriteAllText(outputPath, json, System.Text.Encoding.UTF8);

                Console.WriteLine();
                Console.WriteLine($"[Runner] Dump written to: {outputPath}");
                Console.WriteLine($"[Runner] Methods captured: {dump.Methods.Count}");

                // Attempt form snapshot in a child process so that NET Reactor's
                // Environment.Exit() calls don't kill us.
                string formsPath = outputPath + ".forms.json";
                Console.WriteLine("[Runner] Attempting form snapshot via child process...");
                bool snapshotOk = RunChildSnapshot(targetPath, formsPath);

                if (snapshotOk && File.Exists(formsPath))
                {
                    // Merge forms into main dump
                    string formsJson = File.ReadAllText(formsPath);
                    var forms = JsonConvert.DeserializeObject<List<FormEntry>>(formsJson);
                    if (forms != null && forms.Count > 0)
                    {
                        dump.Forms = forms;
                        // Re-write dump with forms included
                        File.WriteAllText(outputPath,
                            JsonConvert.SerializeObject(dump, Formatting.Indented),
                            System.Text.Encoding.UTF8);
                        Console.WriteLine($"[Runner] Form snapshots merged: {forms.Count}");
                    }
                    File.Delete(formsPath);
                }
                else
                {
                    Console.WriteLine("[Runner] Form snapshot unavailable (protected form may call Environment.Exit).");
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Runner] Fatal error: {ex}");
                return 2;
            }
        }

        private static bool RunChildSnapshot(string targetPath, string formsPath)
        {
            try
            {
                string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = exePath,
                    Arguments       = $"--snapshot \"{targetPath}\" \"{formsPath}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                };
                using (var p = System.Diagnostics.Process.Start(psi))
                {
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    p.WaitForExit(15000); // 15 second timeout

                    if (!string.IsNullOrWhiteSpace(stdout))
                        foreach (var line in stdout.Split('\n'))
                            if (!string.IsNullOrWhiteSpace(line))
                                Console.WriteLine("[ChildRunner] " + line.TrimEnd());

                    if (!string.IsNullOrWhiteSpace(stderr))
                        foreach (var line in stderr.Split('\n'))
                            if (!string.IsNullOrWhiteSpace(line))
                                Console.Error.WriteLine("[ChildRunner/err] " + line.TrimEnd());

                    return p.ExitCode == 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Runner] Child snapshot process error: {ex.Message}");
                return false;
            }
        }

        private static int RunFormSnapshot(string targetPath, string outputPath)
        {
            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine($"[Snapshot] File not found: {targetPath}");
                return 1;
            }

            try
            {
                // Install Harmony patches BEFORE loading the assembly — NET Reactor may
                // call Environment.Exit at any point from here on (cctors, ctor, etc.).
                ExitGuard.Install();
                ExitGuard.Behavior = ExitGuardBehavior.Suppress;

                var baseDir = Path.GetDirectoryName(targetPath);
                AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
                {
                    var name = new AssemblyName(e.Name).Name;
                    var p    = Path.Combine(baseDir, name + ".dll");
                    return File.Exists(p) ? System.Reflection.Assembly.LoadFrom(p) : null;
                };

                var assembly = System.Reflection.Assembly.LoadFrom(targetPath);

                // Trigger .cctors so bootstrap runs and installs all hooks
                Type[] types;
                try { types = assembly.GetTypes(); }
                catch (ReflectionTypeLoadException ex) { types = ex.Types; }

                foreach (var t in types)
                {
                    if (t == null || t.ContainsGenericParameters) continue;
                    try { System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
                    catch { /* expected */ }
                }

                // Capture form snapshots (may call Environment.Exit — that's OK here)
                var forms = new List<FormEntry>();
                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_RUNNER_SNAPSHOT_ENTRYPOINT"),
                        "1",
                        StringComparison.Ordinal))
                {
                    forms = FormSnapshot.CaptureFromEntryPoint(assembly);
                }

                if (forms.Count == 0 || forms.TrueForAll(IsEmptyFormSnapshot))
                    forms = FormSnapshot.CaptureAll(assembly);
                string json = JsonConvert.SerializeObject(forms, Formatting.Indented);
                File.WriteAllText(outputPath, json, System.Text.Encoding.UTF8);
                Console.WriteLine($"[Snapshot] Wrote {forms.Count} form(s) to {outputPath}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Snapshot] Error: {ex}");
                return 2;
            }
        }

        private static bool IsEmptyFormSnapshot(FormEntry form)
        {
            if (form == null) return true;
            if (form.Controls != null && form.Controls.Count > 0) return false;
            if (!string.IsNullOrEmpty(form.Text)) return false;
            if ((form.ClientWidth ?? 0) > 0 || (form.ClientHeight ?? 0) > 0) return false;
            return true;
        }
    }
}
