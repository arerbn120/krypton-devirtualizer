using System;
using System.IO;
using System.Linq;
using System.Text;
using Krypton.Core.Payload;

namespace Krypton.Core.Parser
{
    public class ResourceParser : IResourceReader
    {
        public string ResourceName { get; set; }
        public byte[] RawData { get; set; }
        public int[] MethodKeys { get; set; }
        public int[] MethodSizes { get; set; }
        public byte[] Operands { get; set; }
        public bool[] DefinedOperands { get; set; }
        public string[] Strings { get; set; }
        public int[] StringOffsets { get; set; }
        public int[] StringSizes { get; set; }
        public BinaryReader Reader { get; set; }
        private string IntegerEncoding { get; set; } = "encrypted-leb128";

        public VmResourceData Parse(DevirtualizationCtx Ctx)
        {
            var strictDiagnostics = Ctx.Options.StrictDiagnostics;
            var resourceSettings = new ResourceFormatProfile();
            var parsedEncoding = NormalizeIntegerEncoding(resourceSettings.IntegerEncoding);
            if (!IsSupportedIntegerEncoding(parsedEncoding))
            {
                var message =
                    $"Unsupported resource integer encoding '{resourceSettings.IntegerEncoding}'. " +
                    "Supported values: encrypted-leb128, leb128, sleb128, int32-le.";
                if (strictDiagnostics)
                    throw new DevirtualizationException(message);

                Ctx.Options.Logger.Warning(message + " Falling back to encrypted-leb128.");
                parsedEncoding = "encrypted-leb128";
            }

            foreach (var resource in Ctx.Module.Resources)
            {
                byte[] data;
                try
                {
                    data = resource.GetData();
                }
                catch (Exception ex)
                {
                    if (strictDiagnostics)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Resource read failed for '{resource.Name}': {ex.Message}");
                    }
                    continue;
                }

                if (!TryParseLayout(
                        data,
                        resourceSettings,
                        parsedEncoding,
                        strictDiagnostics,
                        Ctx.Options.Logger,
                        resource.Name,
                        out var operands,
                        out var definedOperands,
                        out var strings,
                        out var stringOffsets,
                        out var stringSizes,
                        out var methodKeys))
                {
                    continue;
                }

                Reader = new BinaryReader(new MemoryStream(data));
                IntegerEncoding = parsedEncoding;
                ResourceName = resource.Name;
                RawData = data;
                Operands = operands;
                DefinedOperands = definedOperands;
                Strings = strings;
                StringOffsets = stringOffsets;
                StringSizes = stringSizes;
                MethodKeys = methodKeys;
                MethodSizes = lastParsedMethodSizes ?? Array.Empty<int>();
                Ctx.Options.Logger.Success(
                    $"Located Resource With Name {resource.Name} And Byte Data Length {data.Length}");

                var payloadBlob = new VmPayloadBlob(resource.Name, data);
                var payloadLayout = new LegacyVmPayloadParser().Parse(payloadBlob, this);
                var operandModel = new OperandModelExtractor().Extract(payloadLayout);
                return new VmResourceData(
                    resource.Name,
                    this,
                    payloadBlob,
                    payloadLayout,
                    operandModel,
                    resourceSettings);
            }

            throw new DevirtualizationException("Could not locate VM resource payload.");
        }

        private bool TryParseLayout(
            byte[] data,
            ResourceFormatProfile profile,
            string parsedEncoding,
            bool strictDiagnostics,
            ILogger logger,
            string resourceName,
            out byte[] operands,
            out bool[] definedOperands,
            out string[] strings,
            out int[] stringOffsets,
            out int[] stringSizes,
            out int[] methodKeys)
        {
            operands = null;
            definedOperands = null;
            strings = null;
            stringOffsets = null;
            stringSizes = null;
            methodKeys = null;
            lastParsedMethodSizes = null;

            if (data == null || data.Length == 0)
                return false;

            try
            {
                using var stream = new MemoryStream(data, false);
                using var reader = new BinaryReader(stream);

                var headerOffset = GetHeaderOffset(data, profile?.HeaderMagic);
                if (headerOffset < 0)
                    return false;
                reader.BaseStream.Position = headerOffset;

                IntegerEncoding = NormalizeIntegerEncoding(parsedEncoding);
                var maxOperandEntries = profile?.MaxOperandEntries > 0 ? profile.MaxOperandEntries : 256;
                maxOperandEntries = Math.Max(256, maxOperandEntries);
                var parsedOperands = new byte[maxOperandEntries];
                var parsedDefinedOperands = new bool[maxOperandEntries];
                if (!TryReadEncodedInt(reader, out var operandCount))
                    return false;
                if (operandCount < 0 || operandCount > maxOperandEntries)
                    return false;

                for (var i = 0; i < operandCount; i++)
                {
                    if (reader.BaseStream.Position + 2 > reader.BaseStream.Length)
                        return false;

                    var index = reader.ReadByte();
                    if (index < 0 || index >= parsedOperands.Length)
                        return false;
                    parsedOperands[index] = reader.ReadByte();
                    parsedDefinedOperands[index] = true;
                }

                if (!TryReadEncodedInt(reader, out var stringCount))
                    return false;
                if (stringCount < 0 || stringCount > (profile?.MaxStringCount > 0 ? profile.MaxStringCount : 0x4000))
                    return false;

                var parsedStrings = new string[stringCount];
                var parsedStringOffsets = new int[stringCount];
                var parsedStringSizes = new int[stringCount];
                for (var i = 0; i < stringCount; i++)
                {
                    if (!TryReadEncodedInt(reader, out var size))
                        return false;
                    if (size < 0 || reader.BaseStream.Position + size > reader.BaseStream.Length)
                        return false;

                    parsedStringOffsets[i] = (int) reader.BaseStream.Position;
                    parsedStringSizes[i] = size;
                    parsedStrings[i] = Encoding.Unicode.GetString(reader.ReadBytes(size));
                }

                if (!TryReadEncodedInt(reader, out var methodCount))
                    return false;
                if (methodCount <= 0 || methodCount > (profile?.MaxMethodCount > 0 ? profile.MaxMethodCount : 0x8000))
                    return false;

                var methodSizes = new int[methodCount];
                for (var i = 0; i < methodCount; i++)
                {
                    if (!TryReadEncodedInt(reader, out var size))
                        return false;
                    if (size <= 0)
                        return false;
                    methodSizes[i] = size;
                }

                var methodPosition = reader.BaseStream.Position;
                var parsedMethodKeys = new int[methodCount];
                for (var i = 0; i < methodCount; i++)
                {
                    if (methodPosition > int.MaxValue)
                        return false;
                    parsedMethodKeys[i] = (int) methodPosition;
                    methodPosition += methodSizes[i];
                    if (methodPosition > data.Length)
                        return false;
                }

                operands = parsedOperands;
                definedOperands = parsedDefinedOperands;
                strings = parsedStrings;
                stringOffsets = parsedStringOffsets;
                stringSizes = parsedStringSizes;
                methodKeys = parsedMethodKeys;
                lastParsedMethodSizes = methodSizes;
                return true;
            }
            catch (Exception ex)
            {
                if (strictDiagnostics)
                {
                    logger.Warning($"Resource layout parse failed for '{resourceName}': {ex.Message}");
                }
                return false;
            }
        }

        public int ReadEncryptedByte()
        {
            if (Reader == null)
                throw new InvalidOperationException("Resource parser stream was not initialized.");
            return ReadEncodedInt(Reader);
        }

        private int[] lastParsedMethodSizes;

        private bool TryReadEncodedInt(BinaryReader reader, out int value)
        {
            value = 0;
            if (reader == null || reader.BaseStream.Position >= reader.BaseStream.Length)
                return false;

            try
            {
                value = ReadEncodedInt(reader);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private int ReadEncodedInt(BinaryReader reader)
        {
            var encoding = NormalizeIntegerEncoding(IntegerEncoding);
            return encoding switch
            {
                "encrypted-leb128" => ReadEncryptedLeb128(reader),
                "leb128" => ReadUnsignedLeb128(reader),
                "unsigned-leb128" => ReadUnsignedLeb128(reader),
                "7bit" => ReadUnsignedLeb128(reader),
                "sleb128" => ReadSignedLeb128(reader),
                "signed-leb128" => ReadSignedLeb128(reader),
                "int32-le" => ReadInt32LittleEndian(reader),
                "int32" => ReadInt32LittleEndian(reader),
                _ => ReadEncryptedLeb128(reader)
            };
        }

        private int ReadEncryptedLeb128(BinaryReader reader)
        {
            var flag = false;
            var num = 0U;
            var num2 = reader.ReadByte();
            num |= num2 & 63U;
            if ((num2 & 64U) != 0U) flag = true;
            if (num2 < 128U)
            {
                if (flag)
                    return ~(int)num;
                return (int)num;
            }

            var num3 = 0;
            for (;;)
            {
                var num4 = (uint)reader.ReadByte();
                num |= (num4 & 127U) << (7 * num3 + 6);
                if (num4 < 128U) break;
                num3++;
            }

            if (flag) return ~(int)num;
            return (int)num;
        }

        private int ReadUnsignedLeb128(BinaryReader reader)
        {
            var value = 0U;
            var shift = 0;
            while (true)
            {
                if (shift > 28)
                    throw new DevirtualizationException("Invalid LEB128 integer encoding.");

                var next = reader.ReadByte();
                value |= (uint) (next & 0x7F) << shift;
                if ((next & 0x80) == 0)
                    break;
                shift += 7;
            }

            return unchecked((int) value);
        }

        private int ReadSignedLeb128(BinaryReader reader)
        {
            var result = 0;
            var shift = 0;
            byte next;
            do
            {
                if (shift > 28)
                    throw new DevirtualizationException("Invalid signed LEB128 integer encoding.");
                next = reader.ReadByte();
                result |= (next & 0x7F) << shift;
                shift += 7;
            } while ((next & 0x80) != 0);

            if ((shift < 32) && (next & 0x40) != 0)
                result |= -1 << shift;

            return result;
        }

        private int ReadInt32LittleEndian(BinaryReader reader)
        {
            if (reader.BaseStream.Position + 4 > reader.BaseStream.Length)
                throw new EndOfStreamException("Unexpected end of stream while reading Int32.");
            return reader.ReadInt32();
        }

        private int GetHeaderOffset(byte[] data, string headerMagic)
        {
            var magicBytes = ParseHeaderMagicBytes(headerMagic);
            if (magicBytes.Length == 0)
                return 0;
            if (data == null || data.Length < magicBytes.Length)
                return -1;

            for (var i = 0; i < magicBytes.Length; i++)
            {
                if (data[i] != magicBytes[i])
                    return -1;
            }

            return magicBytes.Length;
        }

        private byte[] ParseHeaderMagicBytes(string headerMagic)
        {
            if (string.IsNullOrWhiteSpace(headerMagic))
                return Array.Empty<byte>();

            var trimmed = headerMagic.Trim();
            if (trimmed.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
                return ParseHexBytes(trimmed.Substring(4));
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return ParseHexBytes(trimmed.Substring(2));

            return Encoding.ASCII.GetBytes(trimmed);
        }

        private byte[] ParseHexBytes(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return Array.Empty<byte>();

            var cleaned = new string(text.Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '_').ToArray());
            if (cleaned.Length == 0)
                return Array.Empty<byte>();
            if ((cleaned.Length & 1) != 0)
                throw new DevirtualizationException("HeaderMagic hex encoding must contain an even number of digits.");

            var bytes = new byte[cleaned.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                var pair = cleaned.Substring(i * 2, 2);
                bytes[i] = Convert.ToByte(pair, 16);
            }

            return bytes;
        }

        private string NormalizeIntegerEncoding(string encoding)
        {
            return string.IsNullOrWhiteSpace(encoding)
                ? "encrypted-leb128"
                : encoding.Trim().ToLowerInvariant();
        }

        private bool IsSupportedIntegerEncoding(string encoding)
        {
            switch (NormalizeIntegerEncoding(encoding))
            {
                case "encrypted-leb128":
                case "leb128":
                case "unsigned-leb128":
                case "7bit":
                case "sleb128":
                case "signed-leb128":
                case "int32-le":
                case "int32":
                    return true;
                default:
                    return false;
            }
        }
    }
}
