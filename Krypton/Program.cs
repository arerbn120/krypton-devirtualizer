using System;
using System.Linq;
using Krypton.Core;
using Krypton.Pipeline;
using Console = Colorful.Console;

namespace Krypton
{
    internal class Program
    {
        public static Version CurrentVersion = new Version("1.0.0");

        private static void Main(string[] args)
        {
            var logger = new ConsoleLogger();
            Console.Title = $"Krypton - {CurrentVersion}";
            Environment.ExitCode = 0;

            var pauseOnExit =
                !args.Any(q => string.Equals(q, "--no-pause", StringComparison.OrdinalIgnoreCase)) &&
                !string.Equals(Environment.GetEnvironmentVariable("KRYPTON_NO_PAUSE"), "1", StringComparison.Ordinal);

            try
            {
                var strictDiagnostics = false;
                string inputPath = null;

                for (var i = 0; i < args.Length; i++)
                {
                    var arg = args[i];
                    if (string.Equals(arg, "--strict-diagnostics", StringComparison.OrdinalIgnoreCase))
                    {
                        strictDiagnostics = true;
                        continue;
                    }

                    if (!arg.StartsWith("--", StringComparison.Ordinal) && string.IsNullOrWhiteSpace(inputPath))
                    {
                        inputPath = arg;
                    }
                }

                if (string.IsNullOrWhiteSpace(inputPath))
                {
                    logger.Error(
                        "Usage: Krypton.exe <input-assembly> [--strict-diagnostics] [--no-pause]");
                    Environment.ExitCode = 1;
                    return;
                }

                var opts = new DevirtualizationOptions(inputPath, logger)
                {
                    StrictDiagnostics = strictDiagnostics
                };
                var ctx = new DevirtualizationCtx(opts);

                var devirtualizer = new Devirtualizer(ctx);
                devirtualizer.Devirtualize();
                devirtualizer.Save();
            }
            catch (Exception ex)
            {
                logger.Error($"Krypton failed: {ex.Message}");
                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_EXCEPTIONS"), "1", StringComparison.Ordinal))
                    logger.Error(ex.ToString());
                Environment.ExitCode = 1;
            }
            finally
            {
                if (pauseOnExit)
                {
                    Console.WriteLine();
                    Console.WriteLine("Press any key to close...");
                    Console.ReadKey(intercept: true);
                }
            }
        }

    }
}
