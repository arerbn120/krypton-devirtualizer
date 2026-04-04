using System;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;
using Xunit;

namespace Krypton.Tests
{
    public class AssemblyLoadSmokeTests
    {
        [Fact]
        public void CanLoadManagedAssemblyBytes()
        {
            var assemblyPath = typeof(AssemblyLoadSmokeTests).Assembly.Location;
            var bytes = File.ReadAllBytes(assemblyPath);

            using var ms = new MemoryStream(bytes);
            var alc = new AssemblyLoadContext("krypton-smoke", isCollectible: true);
            try
            {
                var assembly = alc.LoadFromStream(ms);
                Assert.NotNull(assembly);
                Assert.False(string.IsNullOrWhiteSpace(assembly.FullName));
            }
            finally
            {
                alc.Unload();
            }
        }
    }
}
