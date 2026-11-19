using System.Buffers;
using System.Buffers.Text;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class Program
{
    private const byte GuardByte = 0xA5;
    private const byte DestinationFillByte = 0xCC;
    private const int GuardLength = 64;
    private static readonly int[] DestinationOffsets = [0, 1, 31];

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("Usage: R78 <mode-name> <output.json>");
            return 2;
        }

        string mode = args[0];
        string outputPath = args[1];
        WarmUp();

        List<InputVector> inputs = BuildInputs();
        var records = new List<CaseResult>(capacity: inputs.Count * 160);

        foreach (InputVector input in inputs)
        {
            RunSpanCases(input, ApiKind.Utf8, records);
            RunSpanCases(input, ApiKind.Chars, records);
            RunInPlaceCase(input, records);
        }

        int guardFailures = records.Count(r => !r.PrefixGuardOk || !r.SuffixGuardOk);
        int tailFailures = records.Count(r => !r.TailPreserved);
        int invariantFailures = records.Count(r => r.InvariantFailure is not null);
        int publicKnownSignals = records.Count(r =>
            r.PublicKnownRoot &&
            (!r.PrefixGuardOk || !r.SuffixGuardOk || !r.TailPreserved || r.InvariantFailure is not null));
        int freshSignals = records.Count(r =>
            !r.PublicKnownRoot &&
            (!r.PrefixGuardOk || !r.SuffixGuardOk || !r.TailPreserved || r.InvariantFailure is not null));

        var output = new HarnessOutput
        {
            Schema = "r78-base64url-simd-differential/v1",
            Mode = mode,
            Runtime = Environment.Version.ToString(),
            Framework = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            Os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            Architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            Hardware = new HardwareState
            {
                Avx2 = Avx2.IsSupported,
                Ssse3 = Ssse3.IsSupported,
                Sse2 = Sse2.IsSupported,
                AdvSimd = AdvSimd.IsSupported,
                AdvSimdArm64 = AdvSimd.Arm64.IsSupported,
            },
            Inputs = inputs.Select(input => new InputDescription
            {
                Id = input.Id,
                Category = input.Category,
                Utf8Base64 = Convert.ToBase64String(input.Utf8),
                Chars = input.Chars,
                CrossApiComparable = input.CrossApiComparable,
                ExpectedBase64 = input.ExpectedBytes is null
                    ? null
                    : Convert.ToBase64String(input.ExpectedBytes),
            }).ToList(),
            Records = records,
            Summary = new HarnessSummary
            {
                InputCount = inputs.Count,
                RecordCount = records.Count,
                GuardFailures = guardFailures,
                TailFailures = tailFailures,
                InvariantFailures = invariantFailures,
                PublicKnownSignals = publicKnownSignals,
                FreshSignals = freshSignals,
            },
        };

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        await using FileStream stream = File.Create(outputPath);
        await JsonSerializer.SerializeAsync(stream, output, new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });
        await stream.WriteAsync("\n"u8.ToArray());

        Console.WriteLine(
            $"R78 mode={mode} inputs={inputs.Count} records={records.Count} " +
            $"guard={guardFailures} tail={tailFailures} invariants={invariantFailures} " +
            $"publicKnown={publicKnownSignals} fresh={freshSignals} " +
            $"avx2={Avx2.IsSupported} ssse3={Ssse3.IsSupported} advsimd={AdvSimd.IsSupported}");

        // A mode-local signal is review material, not a vulnerability verdict. The
        // workflow comparator decides whether it is public-known or fresh and whether
        // hardware and scalar executions diverge.
        return 0;
    }

    private static void WarmUp()
    {
        byte[] utf8 = Enumerable.Repeat((byte)'A', 256).ToArray();
        char[] chars = new string('A', 256).ToCharArray();
        byte[] destination = new byte[256];

        for (int index = 0; index < 2_000; index++)
        {
            _ = Base64Url.DecodeFromUtf8(utf8, destination, out _, out _);
            _ = Base64Url.DecodeFromChars(chars, destination, out _, out _);
        }
    }

    private static List<InputVector> BuildInputs()
    {
        var inputs = new List<InputVector>();
        var dedupe = new HashSet<string>(StringComparer.Ordinal);

        void Add(string category, byte[] utf8, string chars, bool comparable)
        {
            string key = Convert.ToBase64String(utf8) + "\u0000" + chars;
            if (!dedupe.Add(key))
            {
                return;
            }

            byte[]? expected = TryDecodeReference(chars);
            inputs.Add(new InputVector
            {
                Id = $"I{inputs.Count:D4}",
                Category = category,
                Utf8 = utf8,
                Chars = chars,
                CrossApiComparable = comparable,
                ExpectedBytes = expected,
            });
        }

        void AddAscii(string category, string text)
            => Add(category, Encoding.ASCII.GetBytes(text), text, comparable: true);

        // Exhaustive source-length boundaries for a uniform alphabet. This includes
        // the public AVX2 control shape at length 45 and many neighboring lengths.
        for (int length = 0; length <= 192; length++)
        {
            AddAscii("uniform-A", new string('A', length));
        }

        foreach (int length in new[] { 223, 224, 225, 255, 256, 257, 299, 300, 301, 319, 320, 321 })
        {
            AddAscii("uniform-A-boundary", new string('A', length));
        }

        // Deterministic valid Base64Url encodings with diverse output bytes.
        int[] rawLengths =
        [
            .. Enumerable.Range(0, 41),
            47, 48, 49, 63, 64, 65, 79, 80, 81,
            95, 96, 97, 127, 128, 129, 159, 160, 161,
            191, 192, 193, 255, 256, 257,
        ];
        var random = new Random(unchecked((int)0x78C0FFEE));
        var validSamples = new Dictionary<int, string>();
        foreach (int rawLength in rawLengths.Distinct())
        {
            byte[] raw = new byte[rawLength];
            random.NextBytes(raw);
            string padded = Convert.ToBase64String(raw)
                .Replace('+', '-')
                .Replace('/', '_');
            string unpadded = padded.TrimEnd('=');
            validSamples[rawLength] = unpadded;
            AddAscii("valid-unpadded", unpadded);
            AddAscii("valid-padded", padded);
        }

        // Whitespace is explicitly ignored by Base64Url. Exercise vector boundaries
        // with leading, trailing, and interspersed whitespace.
        foreach (int rawLength in new[] { 11, 12, 13, 23, 24, 25, 31, 32, 33, 47, 48, 49, 63, 64, 65, 95, 96, 97 })
        {
            string sample = validSamples[rawLength];
            AddAscii("whitespace-leading", " \t\r\n" + sample);
            AddAscii("whitespace-trailing", sample + " \t\r\n     ");
            AddAscii("whitespace-interspersed", InsertWhitespace(sample));
        }

        // Invalid characters and padding around vector boundaries. Keep UTF-8 and
        // character inputs identical for cross-API comparison.
        foreach (int sourceLength in new[] { 15, 16, 17, 31, 32, 33, 45, 47, 48, 49, 63, 64, 65, 95, 96, 97, 127, 128, 129 })
        {
            string baseline = new string('A', sourceLength);
            foreach (int position in CandidateMutationPositions(sourceLength))
            {
                AddAscii("invalid-bang", ReplaceAt(baseline, position, '!'));
                AddAscii("invalid-padding", ReplaceAt(baseline, position, '='));
            }
            AddAscii("invalid-extra-padding", baseline + "===");
        }

        // Non-ASCII byte and character paths are intentionally separate and are not
        // compared against one another.
        foreach (int sourceLength in new[] { 16, 32, 48, 64, 96, 128 })
        {
            byte[] highByte = Enumerable.Repeat((byte)'A', sourceLength).ToArray();
            highByte[sourceLength / 2] = 0xFF;
            Add("invalid-high-byte", highByte, new string('A', sourceLength - 1) + "!", comparable: false);

            char[] highChar = new string('A', sourceLength).ToCharArray();
            highChar[sourceLength / 2] = '\u0100';
            Add("invalid-high-char", Encoding.ASCII.GetBytes(new string('A', sourceLength - 1) + "!"), new string(highChar), comparable: false);
        }

        return inputs;
    }

    private static string InsertWhitespace(string value)
    {
        var builder = new StringBuilder(value.Length + value.Length / 4 + 8);
        for (int index = 0; index < value.Length; index++)
        {
            builder.Append(value[index]);
            if ((index & 7) == 7)
            {
                builder.Append(index % 16 == 7 ? ' ' : '\t');
            }
        }
        return builder.ToString();
    }

    private static IEnumerable<int> CandidateMutationPositions(int length)
    {
        foreach (int candidate in new[] { 0, 1, 15, 16, 31, 32, length / 2, length - 2, length - 1 })
        {
            if ((uint)candidate < (uint)length)
            {
                yield return candidate;
            }
        }
    }

    private static string ReplaceAt(string source, int index, char replacement)
    {
        char[] chars = source.ToCharArray();
        chars[index] = replacement;
        return new string(chars);
    }

    private static byte[]? TryDecodeReference(string source)
    {
        try
        {
            string compact = new(source.Where(character => !char.IsWhiteSpace(character)).ToArray());
            compact = compact.Replace('-', '+').Replace('_', '/');
            int remainder = compact.Length & 3;
            if (remainder == 1)
            {
                return null;
            }
            if (remainder != 0)
            {
                compact = compact.PadRight(compact.Length + (4 - remainder), '=');
            }
            return Convert.FromBase64String(compact);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static void RunSpanCases(
        InputVector input,
        ApiKind api,
        List<CaseResult> records)
    {
        int sourceLength = api == ApiKind.Utf8 ? input.Utf8.Length : input.Chars.Length;
        int maximumDecodedLength = Base64Url.GetMaxDecodedLength(sourceLength);
        var destinationLengths = new HashSet<int>
        {
            0,
            1,
            Math.Max(0, maximumDecodedLength - 4),
            Math.Max(0, maximumDecodedLength - 3),
            Math.Max(0, maximumDecodedLength - 2),
            Math.Max(0, maximumDecodedLength - 1),
            maximumDecodedLength,
            maximumDecodedLength + 1,
        };

        if (input.ExpectedBytes is { } expected)
        {
            destinationLengths.Add(Math.Max(0, expected.Length - 2));
            destinationLengths.Add(Math.Max(0, expected.Length - 1));
            destinationLengths.Add(expected.Length);
            destinationLengths.Add(expected.Length + 1);
        }

        foreach (bool finalBlock in new[] { false, true })
        {
            foreach (int destinationLength in destinationLengths.Order())
            {
                foreach (int offset in DestinationOffsets)
                {
                    records.Add(RunSpanCase(
                        input,
                        api,
                        finalBlock,
                        destinationLength,
                        offset,
                        maximumDecodedLength));
                }
            }
        }
    }

    private static CaseResult RunSpanCase(
        InputVector input,
        ApiKind api,
        bool finalBlock,
        int destinationLength,
        int offset,
        int maximumDecodedLength)
    {
        int start = GuardLength + offset;
        byte[] storage = Enumerable.Repeat(
            GuardByte,
            start + destinationLength + GuardLength).ToArray();
        Span<byte> destination = storage.AsSpan(start, destinationLength);
        destination.Fill(DestinationFillByte);

        OperationStatus status = default;
        int consumed = -1;
        int written = -1;
        string? exceptionType = null;
        string? exceptionMessage = null;

        try
        {
            status = api == ApiKind.Utf8
                ? Base64Url.DecodeFromUtf8(
                    input.Utf8,
                    destination,
                    out consumed,
                    out written,
                    finalBlock)
                : Base64Url.DecodeFromChars(
                    input.Chars,
                    destination,
                    out consumed,
                    out written,
                    finalBlock);
        }
        catch (Exception exception)
        {
            exceptionType = exception.GetType().FullName;
            exceptionMessage = exception.Message;
        }

        bool prefixGuardOk = AllEqual(storage.AsSpan(0, start), GuardByte);
        bool suffixGuardOk = AllEqual(
            storage.AsSpan(start + destinationLength),
            GuardByte);
        bool boundsValid =
            consumed >= 0 && consumed <= (api == ApiKind.Utf8 ? input.Utf8.Length : input.Chars.Length) &&
            written >= 0 && written <= destinationLength;
        int safeWritten = written >= 0 && written <= destinationLength ? written : 0;
        bool tailPreserved = boundsValid &&
            AllEqual(destination[safeWritten..], DestinationFillByte);

        var failures = new List<string>();
        if (!prefixGuardOk) failures.Add("prefix-guard-overwrite");
        if (!suffixGuardOk) failures.Add("suffix-guard-overwrite");
        if (!boundsValid && exceptionType is null) failures.Add("consumed-or-written-out-of-range");
        if (!tailPreserved && exceptionType is null) failures.Add("write-beyond-bytesWritten");

        if (input.ExpectedBytes is { } expected && finalBlock && exceptionType is null)
        {
            int comparisonLength = Math.Min(safeWritten, expected.Length);
            if (!destination[..comparisonLength].SequenceEqual(expected.AsSpan(0, comparisonLength)))
            {
                failures.Add("decoded-prefix-mismatch-reference");
            }

            if (destinationLength >= expected.Length)
            {
                if (status != OperationStatus.Done)
                {
                    failures.Add("valid-input-not-done-with-sufficient-destination");
                }
                if (safeWritten != expected.Length)
                {
                    failures.Add("valid-input-written-length-mismatch");
                }
                if (safeWritten == expected.Length &&
                    !destination[..safeWritten].SequenceEqual(expected))
                {
                    failures.Add("valid-input-output-mismatch");
                }
            }
            else if (status == OperationStatus.InvalidData)
            {
                failures.Add("valid-input-reported-invalid-data");
            }
        }

        int sourceLength = api == ApiKind.Utf8 ? input.Utf8.Length : input.Chars.Length;
        bool publicKnownRoot = finalBlock &&
            destinationLength == maximumDecodedLength - 2 &&
            (sourceLength & 3) is 1 or 2;

        return new CaseResult
        {
            CaseId = $"{input.Id}|{api}|F{(finalBlock ? 1 : 0)}|D{destinationLength}|O{offset}",
            InputId = input.Id,
            Api = api.ToString(),
            SourceLength = sourceLength,
            FinalBlock = finalBlock,
            DestinationLength = destinationLength,
            Offset = offset,
            PublicKnownRoot = publicKnownRoot,
            Status = exceptionType is null ? status.ToString() : null,
            Consumed = consumed,
            Written = written,
            OutputHash = Hash(destination[..safeWritten]),
            OutputPrefixHex = Convert.ToHexString(destination[..Math.Min(safeWritten, 16)]),
            FullDestinationHash = Hash(destination),
            PrefixGuardOk = prefixGuardOk,
            SuffixGuardOk = suffixGuardOk,
            TailPreserved = tailPreserved,
            ExceptionType = exceptionType,
            ExceptionMessage = exceptionMessage,
            InvariantFailure = failures.Count == 0
                ? null
                : string.Join(';', failures.Distinct(StringComparer.Ordinal)),
        };
    }

    private static void RunInPlaceCase(InputVector input, List<CaseResult> records)
    {
        int start = GuardLength + 1;
        byte[] storage = Enumerable.Repeat(
            GuardByte,
            start + input.Utf8.Length + GuardLength).ToArray();
        input.Utf8.CopyTo(storage.AsSpan(start, input.Utf8.Length));
        Span<byte> buffer = storage.AsSpan(start, input.Utf8.Length);

        int written = -1;
        string? exceptionType = null;
        string? exceptionMessage = null;
        try
        {
            written = Base64Url.DecodeFromUtf8InPlace(buffer);
        }
        catch (Exception exception)
        {
            exceptionType = exception.GetType().FullName;
            exceptionMessage = exception.Message;
        }

        bool prefixGuardOk = AllEqual(storage.AsSpan(0, start), GuardByte);
        bool suffixGuardOk = AllEqual(
            storage.AsSpan(start + input.Utf8.Length), GuardByte);
        bool boundsValid = written >= 0 && written <= input.Utf8.Length;
        int safeWritten = boundsValid ? written : 0;
        var failures = new List<string>();
        if (!prefixGuardOk) failures.Add("prefix-guard-overwrite");
        if (!suffixGuardOk) failures.Add("suffix-guard-overwrite");
        if (!boundsValid && exceptionType is null) failures.Add("written-out-of-range");

        if (input.ExpectedBytes is { } expected && exceptionType is null)
        {
            if (safeWritten != expected.Length)
            {
                failures.Add("in-place-written-length-mismatch");
            }
            else if (!buffer[..safeWritten].SequenceEqual(expected))
            {
                failures.Add("in-place-output-mismatch");
            }
        }

        records.Add(new CaseResult
        {
            CaseId = $"{input.Id}|InPlace",
            InputId = input.Id,
            Api = "InPlace",
            SourceLength = input.Utf8.Length,
            FinalBlock = true,
            DestinationLength = input.Utf8.Length,
            Offset = 1,
            PublicKnownRoot = false,
            Status = exceptionType is null ? "Done" : null,
            Consumed = exceptionType is null ? input.Utf8.Length : -1,
            Written = written,
            OutputHash = Hash(buffer[..safeWritten]),
            OutputPrefixHex = Convert.ToHexString(buffer[..Math.Min(safeWritten, 16)]),
            FullDestinationHash = Hash(buffer),
            PrefixGuardOk = prefixGuardOk,
            SuffixGuardOk = suffixGuardOk,
            // The in-place API does not promise to preserve bytes after the decoded output.
            TailPreserved = true,
            ExceptionType = exceptionType,
            ExceptionMessage = exceptionMessage,
            InvariantFailure = failures.Count == 0
                ? null
                : string.Join(';', failures.Distinct(StringComparer.Ordinal)),
        });
    }

    private static bool AllEqual(ReadOnlySpan<byte> bytes, byte expected)
    {
        foreach (byte value in bytes)
        {
            if (value != expected)
            {
                return false;
            }
        }
        return true;
    }

    private static string Hash(ReadOnlySpan<byte> bytes)
    {
        ulong hash = 14695981039346656037UL;
        foreach (byte value in bytes)
        {
            hash ^= value;
            hash *= 1099511628211UL;
        }
        return hash.ToString("X16");
    }

    private enum ApiKind
    {
        Utf8,
        Chars,
    }
}

internal sealed class InputVector
{
    public string Id { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public byte[] Utf8 { get; set; } = [];
    public string Chars { get; set; } = string.Empty;
    public bool CrossApiComparable { get; set; }
    public byte[]? ExpectedBytes { get; set; }
}

internal sealed class HarnessOutput
{
    public string Schema { get; set; } = string.Empty;
    public string Mode { get; set; } = string.Empty;
    public string Runtime { get; set; } = string.Empty;
    public string Framework { get; set; } = string.Empty;
    public string Os { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public HardwareState Hardware { get; set; } = new();
    public List<InputDescription> Inputs { get; set; } = new();
    public List<CaseResult> Records { get; set; } = new();
    public HarnessSummary Summary { get; set; } = new();
}

internal sealed class HardwareState
{
    public bool Avx2 { get; set; }
    public bool Ssse3 { get; set; }
    public bool Sse2 { get; set; }
    public bool AdvSimd { get; set; }
    public bool AdvSimdArm64 { get; set; }
}

internal sealed class InputDescription
{
    public string Id { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Utf8Base64 { get; set; } = string.Empty;
    public string Chars { get; set; } = string.Empty;
    public bool CrossApiComparable { get; set; }
    public string? ExpectedBase64 { get; set; }
}

internal sealed class HarnessSummary
{
    public int InputCount { get; set; }
    public int RecordCount { get; set; }
    public int GuardFailures { get; set; }
    public int TailFailures { get; set; }
    public int InvariantFailures { get; set; }
    public int PublicKnownSignals { get; set; }
    public int FreshSignals { get; set; }
}

internal sealed class CaseResult
{
    public string CaseId { get; set; } = string.Empty;
    public string InputId { get; set; } = string.Empty;
    public string Api { get; set; } = string.Empty;
    public int SourceLength { get; set; }
    public bool FinalBlock { get; set; }
    public int DestinationLength { get; set; }
    public int Offset { get; set; }
    public bool PublicKnownRoot { get; set; }
    public string? Status { get; set; }
    public int Consumed { get; set; }
    public int Written { get; set; }
    public string OutputHash { get; set; } = string.Empty;
    public string OutputPrefixHex { get; set; } = string.Empty;
    public string FullDestinationHash { get; set; } = string.Empty;
    public bool PrefixGuardOk { get; set; }
    public bool SuffixGuardOk { get; set; }
    public bool TailPreserved { get; set; }
    public string? ExceptionType { get; set; }
    public string? ExceptionMessage { get; set; }
    public string? InvariantFailure { get; set; }
}
