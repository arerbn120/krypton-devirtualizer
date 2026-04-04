using System;
using System.IO;
using System.Text.Json;

namespace Krypton.Core.Signatures
{
    public static class HandlerSignatureCatalogSerializer
    {
        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        public static HandlerSignatureCatalog Load(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("Signature catalog path cannot be empty.", nameof(path));

            var fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
                throw new FileNotFoundException("Signature catalog file not found.", fullPath);

            var json = File.ReadAllText(fullPath);
            var catalog = JsonSerializer.Deserialize<HandlerSignatureCatalog>(json, JsonOptions);
            if (catalog == null)
                throw new DevirtualizationException("Signature catalog JSON produced a null result.");
            catalog.Records ??= new System.Collections.Generic.List<HandlerSignatureRecord>();
            return catalog;
        }

        public static void Save(HandlerSignatureCatalog catalog, string path)
        {
            if (catalog == null)
                throw new ArgumentNullException(nameof(catalog));
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("Signature catalog path cannot be empty.", nameof(path));

            var fullPath = Path.GetFullPath(path);
            var directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            var json = JsonSerializer.Serialize(catalog, JsonOptions);
            File.WriteAllText(fullPath, json);
        }
    }
}
