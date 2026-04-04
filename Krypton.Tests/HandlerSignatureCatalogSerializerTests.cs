using System;
using System.IO;
using Krypton.Core.Signatures;
using Xunit;

namespace Krypton.Tests
{
    public class HandlerSignatureCatalogSerializerTests
    {
        [Fact]
        public void Roundtrip_PreservesCatalogData()
        {
            var tempPath = Path.Combine(Path.GetTempPath(), $"krypton-signatures-{Guid.NewGuid():N}.json");
            var now = new DateTime(2026, 4, 2, 10, 11, 12, DateTimeKind.Utc);
            var original = new HandlerSignatureCatalog
            {
                Version = "1",
                SourceAssembly = "sample.exe",
                DispatcherMethod = "VM.Dispatch",
                SignatureGramMaxOps = 96,
                HandlerCount = 3,
                CreatedUtc = now
            };
            original.Records.Add(new HandlerSignatureRecord
            {
                VmByte = 1,
                OpCode = "Ldstr",
                OperandType = 1,
                Confidence = 0.95,
                Source = "handler-pattern",
                SignatureGrams = { 11, 22, 33 }
            });

            try
            {
                HandlerSignatureCatalogSerializer.Save(original, tempPath);
                var loaded = HandlerSignatureCatalogSerializer.Load(tempPath);

                Assert.NotNull(loaded);
                Assert.Equal("sample.exe", loaded.SourceAssembly);
                Assert.Equal("VM.Dispatch", loaded.DispatcherMethod);
                Assert.Equal(96, loaded.SignatureGramMaxOps);
                Assert.Equal(3, loaded.HandlerCount);
                Assert.Equal(now, loaded.CreatedUtc);
                Assert.Single(loaded.Records);
                Assert.Equal(1, loaded.Records[0].VmByte);
                Assert.Equal("Ldstr", loaded.Records[0].OpCode);
                Assert.Equal((byte) 1, loaded.Records[0].OperandType);
                Assert.Equal(0.95, loaded.Records[0].Confidence);
                Assert.Equal("handler-pattern", loaded.Records[0].Source);
                Assert.Equal(new[] { 11, 22, 33 }, loaded.Records[0].SignatureGrams);
            }
            finally
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
        }
    }
}
