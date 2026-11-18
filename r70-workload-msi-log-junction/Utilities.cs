internal static partial class Program
{
    private static int GetCurrentIntegrityRid()
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TokenQuery, out SafeAccessTokenHandle token))
        {
            int openError = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"OpenProcessToken(TokenQuery) failed: {openError}");
        }

        using (token)
        {
            _ = GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out int required);
            IntPtr buffer = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, required, out _))
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new InvalidOperationException($"GetTokenInformation failed: {error}");
                }

                TOKEN_MANDATORY_LABEL label = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(buffer);
                IntPtr countPtr = GetSidSubAuthorityCount(label.Label.Sid);
                byte count = Marshal.ReadByte(countPtr);
                IntPtr ridPtr = GetSidSubAuthority(label.Label.Sid, (uint)(count - 1));
                return Marshal.ReadInt32(ridPtr);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static string Sha256File(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    private static string BuildWindowsCommandLine(IReadOnlyList<string> arguments) =>
        string.Join(" ", arguments.Select(QuoteWindowsArgument));

    private static string QuoteWindowsArgument(string value)
    {
        if (value.Length > 0 && !value.Any(ch => char.IsWhiteSpace(ch) || ch == '"'))
        {
            return value;
        }

        var builder = new StringBuilder();
        builder.Append('"');
        int backslashes = 0;
        foreach (char ch in value)
        {
            if (ch == '\\')
            {
                backslashes++;
                continue;
            }

            if (ch == '"')
            {
                builder.Append('\\', backslashes * 2 + 1);
                builder.Append('"');
                backslashes = 0;
                continue;
            }

            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(ch);
        }

        builder.Append('\\', backslashes * 2);
        builder.Append('"');
        return builder.ToString();
    }

    private static string QuoteCmd(string value) => "\"" + value.Replace("\"", "\"\"") + "\"";

    private static bool GetBool(IReadOnlyDictionary<string, object?> dictionary, string key)
    {
        if (!dictionary.TryGetValue(key, out object? value))
        {
            return false;
        }

        return value switch
        {
            bool b => b,
            JsonElement e when e.ValueKind is JsonValueKind.True or JsonValueKind.False => e.GetBoolean(),
            _ => false,
        };
    }

    private static Dictionary<string, object?> JsonToDictionary(JsonElement element)
    {
        var result = new Dictionary<string, object?>();
        foreach (JsonProperty property in element.EnumerateObject())
        {
            result[property.Name] = JsonToObject(property.Value);
        }
        return result;
    }

    private static object? JsonToObject(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => JsonToDictionary(element),
        JsonValueKind.Array => element.EnumerateArray().Select(JsonToObject).ToList(),
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number when element.TryGetInt64(out long l) => l,
        JsonValueKind.Number => element.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        _ => element.GetRawText(),
    };

    private static async Task WriteCommandOutputAsync(string fileName, string arguments, string outputPath)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using Process process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");
        string stdout = await process.StandardOutput.ReadToEndAsync();
        string stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        await File.WriteAllTextAsync(outputPath, $"exit={process.ExitCode}{Environment.NewLine}{stdout}{Environment.NewLine}{stderr}");
    }
}
