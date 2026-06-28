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
            var encodingProbeOrder = BuildEncodingProbeOrder(parsedEncoding);

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

                if (strictDiagnostics)
                {
                    Ctx.Options.Logger.Info(
                        $"Resource candidate '{resource.Name}' size={data?.Length ?? 0} head={FormatHexPreview(data, 16)}");
                }

                foreach (var payloadCandidate in BuildPayloadCandidates(data))
                {
                    foreach (var slicedCandidate in BuildOffsetCandidates(payloadCandidate))
                    {
                        foreach (var encoding in encodingProbeOrder)
                        {
                            if (!TryParseLayout(
                                    slicedCandidate.Data,
                                    resourceSettings,
                                    encoding,
                                    strictDiagnostics,
                                    Ctx.Options.Logger,
                                    resource.Name,
                                    out var operands,
                                    out var definedOperands,
                                    out var strings,
                                    out var stringOffsets,
                                    out var stringSizes,
                                    out var methodKeys,
                                    out var rejectionReason))
                            {
                                if (strictDiagnostics)
                                {
                                    Ctx.Options.Logger.Warning(
                                        $"Resource '{resource.Name}' rejected with transform '{slicedCandidate.Name}' and encoding '{encoding}': {rejectionReason}");
                                }
                                continue;
                            }

                            Reader = new BinaryReader(new MemoryStream(slicedCandidate.Data));
                            IntegerEncoding = encoding;
                            ResourceName = resource.Name;
                            RawData = slicedCandidate.Data;
                            Operands = operands;
                            DefinedOperands = definedOperands;
                            Strings = strings;
                            StringOffsets = stringOffsets;
                            StringSizes = stringSizes;
                            MethodKeys = methodKeys;
                            MethodSizes = lastParsedMethodSizes ?? Array.Empty<int>();
                            Ctx.Options.Logger.Success(
                                $"Located Resource With Name {resource.Name} And Byte Data Length {slicedCandidate.Data.Length} (transform={slicedCandidate.Name}, encoding={encoding})");

                            try
                            {
                                var payloadBlob = new VmPayloadBlob(resource.Name, slicedCandidate.Data);
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
                            catch (Exception ex)
                            {
                                if (strictDiagnostics)
                                {
                                    Ctx.Options.Logger.Warning(
                                        $"Resource '{resource.Name}' layout matched with transform '{slicedCandidate.Name}' and encoding '{encoding}', but payload parse failed: {ex.Message}");
                                }
                            }
                        }
                    }
                }
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
            out int[] methodKeys,
            out string rejectionReason)
        {
            operands = null;
            definedOperands = null;
            strings = null;
            stringOffsets = null;
            stringSizes = null;
            methodKeys = null;
            rejectionReason = null;
            lastParsedMethodSizes = null;
            string localRejectionReason = null;

            bool Reject(string reason)
            {
                localRejectionReason = reason;
                return false;
            }

            if (data == null || data.Length == 0)
                return Reject("data is null or empty");

            try
            {
                using var stream = new MemoryStream(data, false);
                using var reader = new BinaryReader(stream);

                var headerOffset = GetHeaderOffset(data, profile?.HeaderMagic);
                if (headerOffset < 0)
                    return Reject("header magic mismatch");
                reader.BaseStream.Position = headerOffset;

                IntegerEncoding = NormalizeIntegerEncoding(parsedEncoding);
                var maxOperandEntries = profile?.MaxOperandEntries > 0 ? profile.MaxOperandEntries : 256;
                maxOperandEntries = Math.Max(256, maxOperandEntries);
                var parsedOperands = new byte[maxOperandEntries];
                var parsedDefinedOperands = new bool[maxOperandEntries];
                if (!TryReadEncodedInt(reader, out var operandCount))
                    return Reject($"failed to read operandCount at offset {reader.BaseStream.Position}");
                if (operandCount < 0 || operandCount > maxOperandEntries)
                    return Reject(
                        $"operandCount out of range: {operandCount} (max {maxOperandEntries}) at offset {reader.BaseStream.Position}");

                for (var i = 0; i < operandCount; i++)
                {
                    if (reader.BaseStream.Position + 2 > reader.BaseStream.Length)
                        return Reject($"operand table truncated at item {i}");

                    var index = reader.ReadByte();
                    if (index < 0 || index >= parsedOperands.Length)
                        return Reject($"operand index out of range at item {i}: {index}");
                    parsedOperands[index] = reader.ReadByte();
                    parsedDefinedOperands[index] = true;
                }

                if (!TryReadEncodedInt(reader, out var stringCount))
                    return Reject($"failed to read stringCount at offset {reader.BaseStream.Position}");
                if (stringCount < 0 || stringCount > (profile?.MaxStringCount > 0 ? profile.MaxStringCount : 0x4000))
                    return Reject(
                        $"stringCount out of range: {stringCount} (max {(profile?.MaxStringCount > 0 ? profile.MaxStringCount : 0x4000)})");

                var parsedStrings = new string[stringCount];
                var parsedStringOffsets = new int[stringCount];
                var parsedStringSizes = new int[stringCount];
                for (var i = 0; i < stringCount; i++)
                {
                    if (!TryReadEncodedInt(reader, out var size))
                        return Reject($"failed to read string size at index {i} offset {reader.BaseStream.Position}");
                    if (size < 0 || reader.BaseStream.Position + size > reader.BaseStream.Length)
                        return Reject($"string[{i}] size invalid: {size} at offset {reader.BaseStream.Position}");

                    parsedStringOffsets[i] = (int) reader.BaseStream.Position;
                    parsedStringSizes[i] = size;
                    parsedStrings[i] = Encoding.Unicode.GetString(reader.ReadBytes(size));
                }

                if (!TryReadEncodedInt(reader, out var methodCount))
                    return Reject($"failed to read methodCount at offset {reader.BaseStream.Position}");
                if (methodCount <= 0 || methodCount > (profile?.MaxMethodCount > 0 ? profile.MaxMethodCount : 0x8000))
                    return Reject(
                        $"methodCount out of range: {methodCount} (max {(profile?.MaxMethodCount > 0 ? profile.MaxMethodCount : 0x8000)})");

                var methodSizes = new int[methodCount];
                for (var i = 0; i < methodCount; i++)
                {
                    if (!TryReadEncodedInt(reader, out var size))
                        return Reject($"failed to read method size at index {i} offset {reader.BaseStream.Position}");
                    if (size <= 0)
                        return Reject($"method[{i}] size invalid: {size}");
                    methodSizes[i] = size;
                }

                var methodPosition = reader.BaseStream.Position;
                var parsedMethodKeys = new int[methodCount];
                for (var i = 0; i < methodCount; i++)
                {
                    if (methodPosition > int.MaxValue)
                        return Reject($"method position overflow at index {i}: {methodPosition}");
                    parsedMethodKeys[i] = (int) methodPosition;
                    methodPosition += methodSizes[i];
                    if (methodPosition > data.Length)
                        return Reject(
                            $"method payload overflow at index {i}: end={methodPosition}, dataLength={data.Length}");
                }

                operands = parsedOperands;
                definedOperands = parsedDefinedOperands;
                strings = parsedStrings;
                stringOffsets = parsedStringOffsets;
                stringSizes = parsedStringSizes;
                methodKeys = parsedMethodKeys;
                lastParsedMethodSizes = methodSizes;
                rejectionReason = "ok";
                return true;
            }
            catch (Exception ex)
            {
                rejectionReason = $"exception: {ex.GetType().Name}: {ex.Message}";
                if (strictDiagnostics)
                {
                    logger.Warning($"Resource layout parse failed for '{resourceName}': {ex.Message}");
                }
                return false;
            }
            finally
            {
                if (string.IsNullOrEmpty(rejectionReason) && !string.IsNullOrEmpty(localRejectionReason))
                    rejectionReason = localRejectionReason;
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

        private string[] BuildEncodingProbeOrder(string primaryEncoding)
        {
            var normalizedPrimary = NormalizeIntegerEncoding(primaryEncoding);
            var all = new[]
            {
                "encrypted-leb128",
                "leb128",
                "sleb128",
                "int32-le"
            };

            return new[] { normalizedPrimary }
                .Concat(all)
                .Select(NormalizeIntegerEncoding)
                .Distinct()
                .Where(IsSupportedIntegerEncoding)
                .ToArray();
        }

        private PayloadCandidate[] BuildPayloadCandidates(byte[] originalData)
        {
            if (originalData == null)
                return Array.Empty<PayloadCandidate>();

            var list = new System.Collections.Generic.List<PayloadCandidate>
            {
                new PayloadCandidate("raw", originalData)
            };

            const ulong qwordXorKey = 0x000000003018CBC7UL;
            if (originalData.Length >= 8)
            {
                for (var alignment = 0; alignment < 8; alignment++)
                {
                    var transformed = new byte[originalData.Length];
                    Array.Copy(originalData, transformed, originalData.Length);
                    for (var i = alignment; i + 7 < transformed.Length; i += 8)
                    {
                        var value = BitConverter.ToUInt64(transformed, i) ^ qwordXorKey;
                        var bytes = BitConverter.GetBytes(value);
                        Buffer.BlockCopy(bytes, 0, transformed, i, 8);
                    }

                    var transformName = alignment == 0
                        ? "xor-qword-0x3018CBC7"
                        : $"xor-qword-0x3018CBC7@+{alignment}";
                    list.Add(new PayloadCandidate(transformName, transformed));
                }
            }

            const uint dwordXorKey = 0x3018CBC7U;
            if (originalData.Length >= 4)
            {
                for (var alignment = 0; alignment < 4; alignment++)
                {
                    var transformed = new byte[originalData.Length];
                    Array.Copy(originalData, transformed, originalData.Length);
                    for (var i = alignment; i + 3 < transformed.Length; i += 4)
                    {
                        var value = BitConverter.ToUInt32(transformed, i) ^ dwordXorKey;
                        var bytes = BitConverter.GetBytes(value);
                        Buffer.BlockCopy(bytes, 0, transformed, i, 4);
                    }

                    var transformName = alignment == 0
                        ? "xor-dword-0x3018CBC7"
                        : $"xor-dword-0x3018CBC7@+{alignment}";
                    list.Add(new PayloadCandidate(transformName, transformed));
                }
            }

            return list
                .GroupBy(c => c.Name, StringComparer.Ordinal)
                .Select(g => g.First())
                .ToArray();
        }

        private PayloadCandidate[] BuildOffsetCandidates(PayloadCandidate payloadCandidate)
        {
            if (payloadCandidate.Data == null || payloadCandidate.Data.Length == 0)
                return Array.Empty<PayloadCandidate>();

            var maxScanOffset = GetIntEnvironmentVariable("KRYPTON_RESOURCE_SCAN_MAX_OFFSET", 64);
            if (maxScanOffset <= 0)
                return new[] { payloadCandidate };

            var maxOffset = Math.Min(maxScanOffset, payloadCandidate.Data.Length - 1);
            if (maxOffset <= 0)
                return new[] { payloadCandidate };

            var list = new System.Collections.Generic.List<PayloadCandidate>(maxOffset + 1)
            {
                payloadCandidate
            };

            for (var offset = 1; offset <= maxOffset; offset++)
            {
                var remaining = payloadCandidate.Data.Length - offset;
                if (remaining < 32)
                    break;

                var sliced = new byte[remaining];
                Buffer.BlockCopy(payloadCandidate.Data, offset, sliced, 0, remaining);
                list.Add(new PayloadCandidate($"{payloadCandidate.Name}@off+0x{offset:X2}", sliced));
            }

            return list.ToArray();
        }

        private int GetIntEnvironmentVariable(string variableName, int defaultValue)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
                return defaultValue;
            return int.TryParse(raw, out var parsed) ? parsed : defaultValue;
        }

        private readonly struct PayloadCandidate
        {
            public PayloadCandidate(string name, byte[] data)
            {
                Name = name;
                Data = data;
            }

            public string Name { get; }
            public byte[] Data { get; }
        }

        private string FormatHexPreview(byte[] data, int maxBytes)
        {
            if (data == null || data.Length == 0 || maxBytes <= 0)
                return "<empty>";

            var count = Math.Min(maxBytes, data.Length);
            var chars = new char[count * 3 - 1];
            var cursor = 0;
            for (var i = 0; i < count; i++)
            {
                var b = data[i];
                var high = b >> 4;
                var low = b & 0xF;
                chars[cursor++] = (char) (high < 10 ? '0' + high : 'A' + (high - 10));
                chars[cursor++] = (char) (low < 10 ? '0' + low : 'A' + (low - 10));
                if (i != count - 1)
                    chars[cursor++] = ' ';
            }

            var suffix = data.Length > count ? " ..." : string.Empty;
            return new string(chars) + suffix;
        }
    }
}
