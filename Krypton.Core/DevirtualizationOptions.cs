using System;
using System.IO;

namespace Krypton.Core
{
    public class DevirtualizationOptions
    {
        public DevirtualizationOptions(string path, ILogger logger)
        {
            if (logger == null)
                throw new ArgumentNullException(nameof(logger));
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("Input assembly path cannot be empty.", nameof(path));

            var fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
                throw new FileNotFoundException("Input assembly file was not found.", fullPath);

            FilePath = fullPath;
            Logger = logger;
            OutPath = Path.Combine(
                Path.GetDirectoryName(fullPath)!,
                Path.GetFileNameWithoutExtension(fullPath) + "-Devirtualized" + Path.GetExtension(fullPath));
        }

        public string FilePath { get; set; }
        public ILogger Logger { get; set; }
        public string OutPath { get; set; }
        public bool StrictDiagnostics { get; set; }
    }
}
