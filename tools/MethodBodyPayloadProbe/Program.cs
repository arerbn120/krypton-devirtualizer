using System.Globalization;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;

if (args.Length < 1)
{
    Console.WriteLine("usage: MethodBodyPayloadProbe <assembly> [payload-trace.json] [metadata-token...]");
    Console.WriteLine("example: MethodBodyPayloadProbe sample.exe sample-payload-trace.json 0x0600001F 0x04000009");
    return;
}

var assemblyPath = Path.GetFullPath(args[0]);
if (!File.Exists(assemblyPath))
{
    Console.WriteLine($"file not found: {assemblyPath}");
    return;
}

var tracePath = args.Length >= 2 && File.Exists(args[1])
    ? Path.GetFullPath(args[1])
    : null;

var explicitTokens = args
    .Skip(tracePath == null ? 1 : 2)
    .Select(TryParseToken)
    .Where(t => t != 0)
    .Distinct()
    .ToList();

var module = ModuleDefinition.FromFile(assemblyPath);
var watchedTokens = explicitTokens.Count > 0
    ? explicitTokens
    : BuildDefaultWatchedTokens(module);
var hcrMap = BuildHiddenCallMap(assemblyPath, tracePath);

Console.WriteLine("# Method Body Payload Probe");
Console.WriteLine($"Assembly: {assemblyPath}");
Console.WriteLine($"Trace: {(tracePath ?? "<none>")}");
Console.WriteLine($"Watched tokens: {string.Join(", ", watchedTokens.Select(t => "0x" + t.ToString("X8", CultureInfo.InvariantCulture)))}");
Console.WriteLine();

PrintWatchedMembers(module, watchedTokens);
Console.WriteLine();

var buffers = new List<NamedBuffer>();
foreach (var resource in module.Resources.OfType<ManifestResource>().Where(r => r.IsEmbedded))
{
    try
    {
        buffers.Add(new NamedBuffer(
            "resource " + Display(resource.Name ?? string.Empty),
            resource.GetData() ?? Array.Empty<byte>()));
    }
    catch (Exception ex)
    {
        Console.WriteLine($"resource read failed: {Display(resource.Name ?? string.Empty)}: {ex.Message}");
    }
}

if (tracePath != null)
    buffers.AddRange(ReadTraceBuffers(tracePath));

var opcodeMap = BuildOpcodeMap();

foreach (var buffer in buffers
             .Where(b => b.Data.Length > 0)
             .OrderByDescending(b => b.Data.Length)
             .ThenBy(b => b.Name, StringComparer.Ordinal))
{
    AnalyzeBuffer(buffer, watchedTokens, opcodeMap, module, hcrMap);
}

static List<uint> BuildDefaultWatchedTokens(ModuleDefinition module)
{
    var result = new List<uint>();

    var formTypes = module.GetAllTypes()
        .Where(t => t.BaseType?.FullName == "System.Windows.Forms.Form" ||
                    t.FullName.Contains("Form", StringComparison.OrdinalIgnoreCase))
        .ToList();

    foreach (var type in formTypes)
    {
        foreach (var method in type.Methods)
        {
            var token = Token(method);
            if (token != 0)
                result.Add(token);
        }

        foreach (var field in type.Fields)
        {
            var token = Token(field);
            if (token != 0)
                result.Add(token);
        }
    }

    if (result.Count == 0)
    {
        result.AddRange(new uint[]
        {
            0x0600001F, 0x06000020, 0x06000021, 0x06000022, 0x06000023,
            0x06000024, 0x06000025, 0x06000026, 0x06000027, 0x06000028,
            0x04000007, 0x04000008, 0x04000009, 0x0400000A, 0x0400000B
        });
    }

    return result.Distinct().OrderBy(t => t).ToList();
}

static void PrintWatchedMembers(ModuleDefinition module, IReadOnlyList<uint> watchedTokens)
{
    Console.WriteLine("## Watched Members");
    foreach (var token in watchedTokens)
    {
        var member = TryLookupMember(module, token);
        Console.WriteLine(member == null
            ? $"- 0x{token:X8}: <not found>"
            : $"- 0x{token:X8}: {member}");
    }
}

static object? TryLookupMember(ModuleDefinition module, uint token)
{
    foreach (var type in module.GetAllTypes())
    {
        if (Token(type) == token)
            return type.FullName;

        foreach (var method in type.Methods)
            if (Token(method) == token)
                return method.FullName;

        foreach (var field in type.Fields)
            if (Token(field) == token)
                return field.FullName;
    }

    return null;
}

static IEnumerable<NamedBuffer> ReadTraceBuffers(string tracePath)
{
    using var doc = JsonDocument.Parse(File.ReadAllText(tracePath));
    if (!doc.RootElement.TryGetProperty("Buffers", out var buffers) ||
        buffers.ValueKind != JsonValueKind.Array)
    {
        yield break;
    }

    foreach (var buffer in buffers.EnumerateArray())
    {
        var source = ReadString(buffer, "Source") ?? "<trace>";
        var index = ReadInt(buffer, "Index") ?? -1;
        var base64 = ReadString(buffer, "Base64");
        if (string.IsNullOrWhiteSpace(base64))
            continue;

        byte[] data;
        try
        {
            data = Convert.FromBase64String(base64);
        }
        catch
        {
            continue;
        }

        yield return new NamedBuffer($"trace #{index} {source}", data);
    }
}

static Dictionary<uint, string> BuildHiddenCallMap(string assemblyPath, string? tracePath)
{
    var result = new Dictionary<uint, string>();
    var candidates = new List<string>();

    var assemblyBase = Path.ChangeExtension(assemblyPath, null);
    if (!string.IsNullOrWhiteSpace(assemblyBase))
        candidates.Add(assemblyBase + "-dynamic-dump.json");

    if (!string.IsNullOrWhiteSpace(tracePath))
    {
        var traceDir = Path.GetDirectoryName(tracePath) ?? string.Empty;
        var traceName = Path.GetFileName(tracePath);
        if (traceName.EndsWith("-payload-trace.json", StringComparison.OrdinalIgnoreCase))
        {
            var stem = traceName[..^"-payload-trace.json".Length];
            candidates.Add(Path.Combine(traceDir, stem + "-dynamic-dump.json"));
        }
    }

    foreach (var path in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
    {
        if (!File.Exists(path))
            continue;

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (!doc.RootElement.TryGetProperty("Methods", out var methods) ||
                methods.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var entry in methods.EnumerateArray())
            {
                var sourceField = ReadString(entry, "SourceField");
                var fieldToken = ExtractToken(sourceField);
                if (fieldToken == 0 ||
                    !entry.TryGetProperty("Instructions", out var instructions) ||
                    instructions.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var instruction in instructions.EnumerateArray())
                {
                    if (!string.Equals(ReadString(instruction, "OperandKind"), "method", StringComparison.Ordinal) ||
                        string.Equals(ReadString(instruction, "MemberName"), "Invoke", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    var opcode = ReadString(instruction, "Opcode") ?? "call";
                    var declType = ReadString(instruction, "DeclType") ?? "<type>";
                    var memberName = ReadString(instruction, "MemberName") ?? "<member>";
                    var memberSig = ReadString(instruction, "MemberSig") ?? string.Empty;
                    result[fieldToken] = $"{opcode} {declType}::{memberName} {memberSig}".TrimEnd();
                    break;
                }
            }

            if (result.Count > 0)
                return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"hidden-call map read failed: {path}: {ex.Message}");
        }
    }

    return result;
}

static uint ExtractToken(string? sourceField)
{
    if (string.IsNullOrWhiteSpace(sourceField))
        return 0;

    var text = sourceField;
    var pipe = text.LastIndexOf('|');
    if (pipe >= 0)
        text = text[(pipe + 1)..];

    return TryParseToken(text);
}

static void AnalyzeBuffer(
    NamedBuffer buffer,
    IReadOnlyList<uint> watchedTokens,
    Dictionary<int, OpCode> opcodeMap,
    ModuleDefinition module,
    IReadOnlyDictionary<uint, string> hcrMap)
{
    var tokenHits = FindTokenHits(buffer.Data, watchedTokens).ToList();
    var bodyCandidates = ScanMethodBodies(buffer.Data, watchedTokens, opcodeMap)
        .OrderByDescending(c => c.Score)
        .ThenBy(c => c.Offset)
        .ToList();

    var interestingBodies = bodyCandidates
        .Where(c => c.Score >= 8 || c.TokenHits.Count > 0)
        .Take(12)
        .ToList();

    var containsWinFormsText =
        ContainsAsciiOrUnicode(buffer.Data, "System.Windows.Forms") ||
        ContainsAsciiOrUnicode(buffer.Data, "SuspendLayout") ||
        ContainsAsciiOrUnicode(buffer.Data, "set_ClientSize") ||
        ContainsAsciiOrUnicode(buffer.Data, "Controls.Add");

    if (tokenHits.Count == 0 && interestingBodies.Count == 0 && !containsWinFormsText &&
        !IsShowAllEnabled())
    {
        return;
    }

    Console.WriteLine("## Buffer");
    Console.WriteLine($"- name: {buffer.Name}");
    Console.WriteLine($"  length: {buffer.Data.Length}");
    Console.WriteLine($"  sha256: {Sha256(buffer.Data)}");
    Console.WriteLine($"  entropy: {Entropy(buffer.Data):F2}");
    Console.WriteLine($"  head: {Hex(buffer.Data, 24)}");
    Console.WriteLine($"  watched-token hits: {tokenHits.Count}");
    if (tokenHits.Count > 0)
    {
        foreach (var hit in tokenHits.Take(20))
            Console.WriteLine($"    - offset=0x{hit.Offset:X} token=0x{hit.Token:X8}");
        if (tokenHits.Count > 20)
            Console.WriteLine($"    - ... {tokenHits.Count - 20} more");
    }

    Console.WriteLine($"  method-body candidates: {bodyCandidates.Count} total, {interestingBodies.Count} interesting");
    Console.WriteLine($"  winforms text marker: {(containsWinFormsText ? "yes" : "no")}");

    if (tokenHits.Count > 0 &&
        TryValidateIl(buffer.Data, 0, buffer.Data.Length, opcodeMap, out var rawStats))
    {
        var rawCandidate = new BodyCandidate
        {
            Offset = 0,
            Kind = "raw-il",
            HeaderSize = 0,
            CodeSize = buffer.Data.Length,
            MaxStack = 0,
            Score = ScoreCandidate(buffer.Data.Length, tokenHits.Select(h => h.Token).Distinct().ToList(), rawStats),
            TokenHits = tokenHits.Select(h => h.Token).Distinct().ToList(),
            Stats = rawStats
        };
        Console.WriteLine(
            $"  raw-il: yes instr={rawStats.InstructionCount} metadata={rawStats.MetadataOperandCount} " +
            $"score={rawCandidate.Score}");
        Console.WriteLine($"    preview: {DisassemblePreview(buffer.Data, rawCandidate, opcodeMap, 80)}");

        if (ShouldDumpBuffer(buffer))
        {
            var lines = DisassembleLines(buffer.Data, rawCandidate, opcodeMap, module, hcrMap).ToList();
            var outPath = Environment.GetEnvironmentVariable("MBPP_DUMP_OUT");
            if (!string.IsNullOrWhiteSpace(outPath))
            {
                File.WriteAllLines(outPath, lines);
                Console.WriteLine($"    full-disasm: {outPath}");
            }
            else
            {
                Console.WriteLine("    full-disasm:");
                foreach (var line in lines)
                    Console.WriteLine("      " + line);
            }
        }
    }

    foreach (var candidate in interestingBodies)
    {
        Console.WriteLine(
            $"    - off=0x{candidate.Offset:X} {candidate.Kind} code={candidate.CodeSize} " +
            $"maxstack={candidate.MaxStack} score={candidate.Score} " +
            $"tokens=[{string.Join(", ", candidate.TokenHits.Select(t => "0x" + t.ToString("X8", CultureInfo.InvariantCulture)))}]");
        Console.WriteLine($"      il: {DisassemblePreview(buffer.Data, candidate, opcodeMap, 16)}");
    }
}

static bool ShouldDumpBuffer(NamedBuffer buffer)
{
    var index = Environment.GetEnvironmentVariable("MBPP_DUMP_INDEX");
    if (!string.IsNullOrWhiteSpace(index) &&
        TryGetTraceIndex(buffer.Name, out var traceIndex) &&
        int.TryParse(index, NumberStyles.Integer, CultureInfo.InvariantCulture, out var requestedIndex) &&
        traceIndex == requestedIndex)
    {
        return true;
    }

    var sha = Environment.GetEnvironmentVariable("MBPP_DUMP_SHA256");
    return !string.IsNullOrWhiteSpace(sha) &&
           string.Equals(Sha256(buffer.Data), sha.Trim(), StringComparison.OrdinalIgnoreCase);
}

static bool TryGetTraceIndex(string name, out int index)
{
    index = -1;
    const string marker = "trace #";
    var start = name.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
    if (start < 0)
        return false;

    start += marker.Length;
    var end = start;
    while (end < name.Length && char.IsDigit(name[end]))
        end++;

    return end > start &&
           int.TryParse(name[start..end], NumberStyles.Integer, CultureInfo.InvariantCulture, out index);
}

static bool IsShowAllEnabled()
{
    var value = Environment.GetEnvironmentVariable("MBPP_SHOW_ALL");
    return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase);
}

static IEnumerable<TokenHit> FindTokenHits(byte[] data, IReadOnlyList<uint> tokens)
{
    foreach (var token in tokens)
    {
        var needle = BitConverter.GetBytes(token);
        for (var i = 0; i <= data.Length - 4; i++)
        {
            if (data[i] == needle[0] &&
                data[i + 1] == needle[1] &&
                data[i + 2] == needle[2] &&
                data[i + 3] == needle[3])
            {
                yield return new TokenHit(i, token);
            }
        }
    }
}

static IEnumerable<BodyCandidate> ScanMethodBodies(
    byte[] data,
    IReadOnlyList<uint> watchedTokens,
    Dictionary<int, OpCode> opcodeMap)
{
    for (var offset = 0; offset < data.Length; offset++)
    {
        var header = data[offset];
        if ((header & 0x3) == 0x2)
        {
            var codeSize = header >> 2;
            if (codeSize > 0 &&
                offset + 1 + codeSize <= data.Length &&
                TryValidateIl(data, offset + 1, codeSize, opcodeMap, out var stats))
            {
                var hits = FindTokensInRange(data, Math.Max(0, offset - 64), Math.Min(data.Length, offset + 1 + codeSize + 64), watchedTokens);
                yield return new BodyCandidate
                {
                    Offset = offset,
                    Kind = "tiny",
                    HeaderSize = 1,
                    CodeSize = codeSize,
                    MaxStack = 8,
                    Score = ScoreCandidate(codeSize, hits, stats),
                    TokenHits = hits,
                    Stats = stats
                };
            }
        }

        if (offset + 12 <= data.Length)
        {
            var flags = BitConverter.ToUInt16(data, offset);
            if ((flags & 0x3) != 0x3)
                continue;

            var headerSize = (flags >> 12) * 4;
            if (headerSize < 12 || offset + headerSize > data.Length)
                continue;

            var codeSize = BitConverter.ToInt32(data, offset + 4);
            if (codeSize <= 0 || codeSize > 0x20000 || offset + headerSize + codeSize > data.Length)
                continue;

            if (!TryValidateIl(data, offset + headerSize, codeSize, opcodeMap, out var stats))
                continue;

            var hits = FindTokensInRange(data, Math.Max(0, offset - 64), Math.Min(data.Length, offset + headerSize + codeSize + 64), watchedTokens);
            yield return new BodyCandidate
            {
                Offset = offset,
                Kind = "fat",
                HeaderSize = headerSize,
                CodeSize = codeSize,
                MaxStack = BitConverter.ToUInt16(data, offset + 2),
                LocalVarSigTok = BitConverter.ToUInt32(data, offset + 8),
                MoreSections = (flags & 0x8) != 0,
                Score = ScoreCandidate(codeSize, hits, stats),
                TokenHits = hits,
                Stats = stats
            };
        }
    }
}

static int ScoreCandidate(int codeSize, List<uint> tokenHits, IlStats stats)
{
    var score = 0;
    if (tokenHits.Count > 0)
        score += 5 + Math.Min(5, tokenHits.Count);
    if (stats.EndsWithRetOrThrow)
        score += 2;
    if (stats.MetadataOperandCount > 0)
        score += 2;
    if (stats.CallLikeCount > 0)
        score += 1;
    if (stats.FieldLikeCount > 0)
        score += 1;
    if (codeSize >= 8)
        score += 1;
    return score;
}

static List<uint> FindTokensInRange(byte[] data, int start, int end, IReadOnlyList<uint> watchedTokens)
{
    var hits = new List<uint>();
    start = Math.Max(0, start);
    end = Math.Min(data.Length, end);
    if (end - start < 4)
        return hits;

    foreach (var token in watchedTokens)
    {
        var needle = BitConverter.GetBytes(token);
        for (var i = start; i <= end - 4; i++)
        {
            if (data[i] != needle[0] ||
                data[i + 1] != needle[1] ||
                data[i + 2] != needle[2] ||
                data[i + 3] != needle[3])
            {
                continue;
            }

            hits.Add(token);
            break;
        }
    }

    return hits;
}

static bool TryValidateIl(
    byte[] data,
    int codeStart,
    int codeSize,
    Dictionary<int, OpCode> opcodeMap,
    out IlStats stats)
{
    stats = new IlStats();
    var p = codeStart;
    var end = codeStart + codeSize;

    while (p < end)
    {
        var opcodeOffset = p;
        int key;
        var first = data[p++];
        if (first == 0xFE)
        {
            if (p >= end)
                return false;
            key = 0xFE00 | data[p++];
        }
        else
        {
            key = first;
        }

        if (!opcodeMap.TryGetValue(key, out var opcode))
            return false;

        stats.InstructionCount++;
        if (opcode == OpCodes.Ret || opcode == OpCodes.Throw)
            stats.EndsWithRetOrThrow = p == end;
        else if (p == end)
            stats.EndsWithRetOrThrow = false;

        switch (opcode.OperandType)
        {
            case OperandType.InlineNone:
                break;

            case OperandType.ShortInlineBrTarget:
            case OperandType.ShortInlineI:
            case OperandType.ShortInlineVar:
                if (p + 1 > end) return false;
                p += 1;
                break;

            case OperandType.InlineVar:
                if (p + 2 > end) return false;
                p += 2;
                break;

            case OperandType.InlineBrTarget:
            case OperandType.InlineI:
            case OperandType.ShortInlineR:
                if (p + 4 > end) return false;
                p += 4;
                break;

            case OperandType.InlineField:
            case OperandType.InlineMethod:
            case OperandType.InlineSig:
            case OperandType.InlineString:
            case OperandType.InlineTok:
            case OperandType.InlineType:
                if (p + 4 > end) return false;
                stats.MetadataOperandCount++;
                if (opcode.OperandType == OperandType.InlineMethod)
                    stats.CallLikeCount++;
                if (opcode.OperandType == OperandType.InlineField)
                    stats.FieldLikeCount++;
                p += 4;
                break;

            case OperandType.InlineI8:
            case OperandType.InlineR:
                if (p + 8 > end) return false;
                p += 8;
                break;

            case OperandType.InlineSwitch:
                if (p + 4 > end) return false;
                var count = BitConverter.ToInt32(data, p);
                p += 4;
                if (count < 0 || count > 4096 || p + (count * 4) > end)
                    return false;
                p += count * 4;
                break;

            default:
                return false;
        }

        if (p <= opcodeOffset)
            return false;
    }

    return p == end && stats.InstructionCount > 0;
}

static string DisassemblePreview(
    byte[] data,
    BodyCandidate candidate,
    Dictionary<int, OpCode> opcodeMap,
    int maxInstructions)
{
    var p = candidate.Offset + candidate.HeaderSize;
    var end = p + candidate.CodeSize;
    var parts = new List<string>();

    while (p < end && parts.Count < maxInstructions)
    {
        int key;
        var opStart = p;
        var first = data[p++];
        if (first == 0xFE)
        {
            if (p >= end)
                break;
            key = 0xFE00 | data[p++];
        }
        else
        {
            key = first;
        }

        if (!opcodeMap.TryGetValue(key, out var opcode))
            break;

        var operandText = ReadOperandPreview(data, ref p, end, opcode.OperandType);
        parts.Add("IL_" + (opStart - (candidate.Offset + candidate.HeaderSize)).ToString("X4", CultureInfo.InvariantCulture) +
                  ":" + opcode.Name + operandText);
    }

    if (p < end)
        parts.Add("...");
    return string.Join(" ; ", parts);
}

static IEnumerable<string> DisassembleLines(
    byte[] data,
    BodyCandidate candidate,
    Dictionary<int, OpCode> opcodeMap,
    ModuleDefinition module,
    IReadOnlyDictionary<uint, string> hcrMap)
{
    var p = candidate.Offset + candidate.HeaderSize;
    var codeStart = p;
    var end = p + candidate.CodeSize;

    while (p < end)
    {
        int key;
        var opStart = p;
        var first = data[p++];
        if (first == 0xFE)
        {
            if (p >= end)
            {
                yield return FormatInvalid(opStart, codeStart, first);
                yield break;
            }

            key = 0xFE00 | data[p++];
        }
        else
        {
            key = first;
        }

        if (!opcodeMap.TryGetValue(key, out var opcode))
        {
            yield return FormatInvalid(opStart, codeStart, first);
            yield break;
        }

        var operandText = ReadOperandDetailed(data, ref p, end, codeStart, opcode.OperandType, module, hcrMap);
        yield return "IL_" + (opStart - codeStart).ToString("X4", CultureInfo.InvariantCulture) +
                     ": " + opcode.Name + operandText;
    }
}

static string FormatInvalid(int opStart, int codeStart, byte first) =>
    "IL_" + (opStart - codeStart).ToString("X4", CultureInfo.InvariantCulture) +
    ": <invalid 0x" + first.ToString("X2", CultureInfo.InvariantCulture) + ">";

static string ReadOperandDetailed(
    byte[] data,
    ref int p,
    int end,
    int codeStart,
    OperandType type,
    ModuleDefinition module,
    IReadOnlyDictionary<uint, string> hcrMap)
{
    switch (type)
    {
        case OperandType.InlineNone:
            return string.Empty;

        case OperandType.ShortInlineBrTarget:
            if (p + 1 > end) return " ?";
            var rel8 = unchecked((sbyte)data[p++]);
            return " IL_" + ((p - codeStart) + rel8).ToString("X4", CultureInfo.InvariantCulture);

        case OperandType.ShortInlineI:
            if (p + 1 > end) return " ?";
            return " " + unchecked((sbyte)data[p++]).ToString(CultureInfo.InvariantCulture);

        case OperandType.ShortInlineVar:
            if (p + 1 > end) return " ?";
            return " " + data[p++].ToString(CultureInfo.InvariantCulture);

        case OperandType.InlineVar:
            if (p + 2 > end) return " ?";
            var u16 = BitConverter.ToUInt16(data, p);
            p += 2;
            return " " + u16.ToString(CultureInfo.InvariantCulture);

        case OperandType.InlineBrTarget:
            if (p + 4 > end) return " ?";
            var rel32 = BitConverter.ToInt32(data, p);
            p += 4;
            return " IL_" + ((p - codeStart) + rel32).ToString("X4", CultureInfo.InvariantCulture);

        case OperandType.InlineI:
            if (p + 4 > end) return " ?";
            var i32 = BitConverter.ToInt32(data, p);
            p += 4;
            return " " + i32.ToString(CultureInfo.InvariantCulture);

        case OperandType.ShortInlineR:
            if (p + 4 > end) return " ?";
            var f32 = BitConverter.ToSingle(data, p);
            p += 4;
            return " " + f32.ToString(CultureInfo.InvariantCulture);

        case OperandType.InlineField:
        case OperandType.InlineMethod:
        case OperandType.InlineSig:
        case OperandType.InlineString:
        case OperandType.InlineTok:
        case OperandType.InlineType:
            if (p + 4 > end) return " ?";
            var token = BitConverter.ToUInt32(data, p);
            p += 4;
            return " 0x" + token.ToString("X8", CultureInfo.InvariantCulture) +
                   ResolveOperand(token, module, hcrMap);

        case OperandType.InlineI8:
            if (p + 8 > end) return " ?";
            var i64 = BitConverter.ToInt64(data, p);
            p += 8;
            return " " + i64.ToString(CultureInfo.InvariantCulture);

        case OperandType.InlineR:
            if (p + 8 > end) return " ?";
            var f64 = BitConverter.ToDouble(data, p);
            p += 8;
            return " " + f64.ToString(CultureInfo.InvariantCulture);

        case OperandType.InlineSwitch:
            if (p + 4 > end) return " ?";
            var count = BitConverter.ToInt32(data, p);
            p += 4;
            if (count < 0 || count > 4096 || p + (count * 4) > end)
                return " ?";

            var baseOffset = (p - codeStart) + (count * 4);
            var targets = new List<string>(count);
            for (var i = 0; i < count; i++)
            {
                var rel = BitConverter.ToInt32(data, p);
                p += 4;
                targets.Add("IL_" + (baseOffset + rel).ToString("X4", CultureInfo.InvariantCulture));
            }

            return " (" + string.Join(", ", targets) + ")";

        default:
            return " ?";
    }
}

static string ResolveOperand(
    uint token,
    ModuleDefinition module,
    IReadOnlyDictionary<uint, string> hcrMap)
{
    var parts = new List<string>();
    if (hcrMap.TryGetValue(token, out var hcr))
        parts.Add("HCR " + hcr);

    var member = TryLookupMember(module, token);
    if (member != null)
        parts.Add(member.ToString() ?? string.Empty);

    return parts.Count == 0
        ? string.Empty
        : " ; " + string.Join(" | ", parts.Where(p => !string.IsNullOrWhiteSpace(p)));
}

static string ReadOperandPreview(byte[] data, ref int p, int end, OperandType type)
{
    switch (type)
    {
        case OperandType.InlineNone:
            return string.Empty;
        case OperandType.ShortInlineBrTarget:
        case OperandType.ShortInlineI:
        case OperandType.ShortInlineVar:
            if (p + 1 > end) return " ?";
            return " " + data[p++].ToString("X2", CultureInfo.InvariantCulture);
        case OperandType.InlineVar:
            if (p + 2 > end) return " ?";
            var u16 = BitConverter.ToUInt16(data, p);
            p += 2;
            return " " + u16.ToString(CultureInfo.InvariantCulture);
        case OperandType.InlineBrTarget:
        case OperandType.InlineI:
        case OperandType.ShortInlineR:
        case OperandType.InlineField:
        case OperandType.InlineMethod:
        case OperandType.InlineSig:
        case OperandType.InlineString:
        case OperandType.InlineTok:
        case OperandType.InlineType:
            if (p + 4 > end) return " ?";
            var u32 = BitConverter.ToUInt32(data, p);
            p += 4;
            return " 0x" + u32.ToString("X8", CultureInfo.InvariantCulture);
        case OperandType.InlineI8:
        case OperandType.InlineR:
            if (p + 8 > end) return " ?";
            var u64 = BitConverter.ToUInt64(data, p);
            p += 8;
            return " 0x" + u64.ToString("X16", CultureInfo.InvariantCulture);
        case OperandType.InlineSwitch:
            if (p + 4 > end) return " ?";
            var count = BitConverter.ToInt32(data, p);
            p += 4;
            var bytes = Math.Max(0, count) * 4;
            if (count < 0 || p + bytes > end) return " ?";
            p += bytes;
            return " switch[" + count.ToString(CultureInfo.InvariantCulture) + "]";
        default:
            return " ?";
    }
}

static Dictionary<int, OpCode> BuildOpcodeMap()
{
    var result = new Dictionary<int, OpCode>();
    foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
    {
        if (field.GetValue(null) is not OpCode opcode)
            continue;

        var key = opcode.Value & 0xFFFF;
        result[key] = opcode;
    }

    return result;
}

static uint TryParseToken(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
        return 0;

    var text = value.Trim();
    if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        text = text[2..];

    return uint.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsed)
        ? parsed
        : 0;
}

static string? ReadString(JsonElement element, string name)
{
    return element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
        ? property.GetString()
        : null;
}

static int? ReadInt(JsonElement element, string name)
{
    return element.TryGetProperty(name, out var property) && property.TryGetInt32(out var value)
        ? value
        : null;
}

static uint Token(IMetadataMember member) => member.MetadataToken.ToUInt32();

static bool ContainsAsciiOrUnicode(byte[] data, string text)
{
    return IndexOf(data, Encoding.ASCII.GetBytes(text)) >= 0 ||
           IndexOf(data, Encoding.Unicode.GetBytes(text)) >= 0;
}

static int IndexOf(byte[] haystack, byte[] needle)
{
    if (needle.Length == 0 || haystack.Length < needle.Length)
        return -1;

    for (var i = 0; i <= haystack.Length - needle.Length; i++)
    {
        var ok = true;
        for (var j = 0; j < needle.Length; j++)
        {
            if (haystack[i + j] == needle[j])
                continue;

            ok = false;
            break;
        }

        if (ok)
            return i;
    }

    return -1;
}

static string Sha256(byte[] data)
{
    using var sha = SHA256.Create();
    return Convert.ToHexString(sha.ComputeHash(data)).ToLowerInvariant();
}

static double Entropy(byte[] data)
{
    if (data.Length == 0)
        return 0;

    Span<int> counts = stackalloc int[256];
    foreach (var b in data)
        counts[b]++;

    var entropy = 0.0;
    foreach (var count in counts)
    {
        if (count == 0)
            continue;

        var p = (double)count / data.Length;
        entropy -= p * Math.Log2(p);
    }

    return entropy;
}

static string Hex(byte[] data, int max)
{
    if (data.Length == 0)
        return "<empty>";

    var count = Math.Min(data.Length, max);
    var text = string.Join(" ", data.Take(count).Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    return data.Length > count ? text + " ..." : text;
}

static string Display(string text)
{
    if (string.IsNullOrEmpty(text))
        return "<empty>";

    var builder = new StringBuilder(text.Length);
    foreach (var ch in text)
    {
        if (char.IsControl(ch))
        {
            builder.Append("\\u");
            builder.Append(((int)ch).ToString("X4", CultureInfo.InvariantCulture));
        }
        else
        {
            builder.Append(ch);
        }
    }

    return builder.ToString();
}

sealed record NamedBuffer(string Name, byte[] Data);
sealed record TokenHit(int Offset, uint Token);

sealed class BodyCandidate
{
    public int Offset { get; set; }
    public string Kind { get; set; } = string.Empty;
    public int HeaderSize { get; set; }
    public int CodeSize { get; set; }
    public int MaxStack { get; set; }
    public uint LocalVarSigTok { get; set; }
    public bool MoreSections { get; set; }
    public int Score { get; set; }
    public List<uint> TokenHits { get; set; } = new();
    public IlStats Stats { get; set; } = new();
}

sealed class IlStats
{
    public int InstructionCount { get; set; }
    public int MetadataOperandCount { get; set; }
    public int CallLikeCount { get; set; }
    public int FieldLikeCount { get; set; }
    public bool EndsWithRetOrThrow { get; set; }
}
