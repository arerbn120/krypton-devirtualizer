using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using Krypton.Core;
using Krypton.Pipeline;
using Xunit;

namespace Krypton.Tests
{
    public class SampleRegressionTests
    {
        [Fact]
        [Trait("Category", "Regression")]
        public void Devirtualize_KnownSamples_WhenAvailable()
        {
            var samplePaths = DiscoverSamplePaths();
            if (samplePaths.Count == 0)
                return;

            foreach (var samplePath in samplePaths)
            {
                var options = new DevirtualizationOptions(samplePath, new TestLogger())
                {
                    StrictDiagnostics = false
                };
                var ctx = new DevirtualizationCtx(options);
                var devirtualizer = new Devirtualizer(ctx);

                devirtualizer.Devirtualize();

                Assert.NotNull(ctx.VirtualizedMethods);
                Assert.True(ctx.VirtualizedMethods.Count > 0, $"No VM methods found for sample: {samplePath}");
            }
        }

        private List<string> DiscoverSamplePaths()
        {
            var knownSamples = new[]
            {
                "Crackme.exe",
                "awesome_msil.exe",
                "Offline_sales_bills_msil.exe",
                "WindowsFormsApplication41.exe"
            };

            var baseDir = AppContext.BaseDirectory;
            var repoRoot = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", ".."));
            var workspaceRoot = Path.GetFullPath(Path.Combine(repoRoot, ".."));

            var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                repoRoot,
                workspaceRoot
            };

            var results = new List<string>();
            foreach (var root in candidates)
            {
                foreach (var sampleName in knownSamples)
                {
                    var path = Path.Combine(root, sampleName);
                    if (!File.Exists(path))
                        continue;
                    if (!IsManagedAssembly(path))
                        continue;
                    if (!results.Contains(path, StringComparer.OrdinalIgnoreCase))
                        results.Add(path);
                }
            }

            return results;
        }

        private bool IsManagedAssembly(string path)
        {
            try
            {
                using var stream = File.OpenRead(path);
                using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
                return peReader.HasMetadata;
            }
            catch
            {
                return false;
            }
        }

        private sealed class TestLogger : ILogger
        {
            public void Success(string message)
            {
            }

            public void Warning(string message)
            {
            }

            public void Error(string message)
            {
            }

            public void Info(string message)
            {
            }

            public void InfoStr(string message, string message2)
            {
            }
        }
    }
}
