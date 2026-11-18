internal static partial class Program
{
    private static async Task<string> SendRepairAsync(NamedPipeClientStream dispatch, string logFile)
    {
        return await SendRequestAsync(dispatch, new Dictionary<string, object?>
        {
            ["RequestType"] = 302,
            ["LogFile"] = logFile,
            ["ProductCode"] = "{00000000-0000-0000-0000-000000000000}",
        });
    }

    private static async Task<string> SendRequestAsync(NamedPipeClientStream dispatch, Dictionary<string, object?> request)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(request);
        byte[] length = BitConverter.GetBytes(payload.Length);
        await dispatch.WriteAsync(length);
        await dispatch.WriteAsync(payload);
        await dispatch.FlushAsync();
        dispatch.WaitForPipeDrain();
        byte[] response = await ReadFramedMessageAsync(dispatch, CancellationToken.None);
        return Encoding.UTF8.GetString(response);
    }

    private static async Task DrainLogPipeAsync(NamedPipeClientStream pipe, List<string> messages, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
        {
            try
            {
                byte[] message = await ReadFramedMessageAsync(pipe, cancellationToken);
                lock (messages)
                {
                    messages.Add(Encoding.UTF8.GetString(message));
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (IOException)
            {
                return;
            }
        }
    }

    private static async Task<byte[]> ReadFramedMessageAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] lengthBuffer = new byte[4];
        await ReadExactlyAsync(stream, lengthBuffer, cancellationToken);
        int length = BitConverter.ToInt32(lengthBuffer, 0);
        if (length < 0 || length > 2044)
        {
            throw new InvalidDataException($"Invalid framed message length: {length}");
        }

        byte[] payload = new byte[length];
        await ReadExactlyAsync(stream, payload, cancellationToken);
        return payload;
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
        }
    }

    private static string CreatePipeName(int processId, params string[] values)
    {
        string processPath = (Environment.ProcessPath
            ?? throw new InvalidOperationException("Environment.ProcessPath unavailable."))
            .ToLowerInvariant();
        string? mac = NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.NetworkInterfaceType != NetworkInterfaceType.Loopback && nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .Select(nic => nic.GetPhysicalAddress().GetAddressBytes())
            .Where(bytes => bytes.Length == 6 && bytes.Any(b => b != 0))
            .Select(bytes => string.Join("-", bytes.Select(b => b.ToString("X2"))))
            .FirstOrDefault();
        string macHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(mac ?? string.Empty)));
        string name = $"{processId};{processPath};{macHash};{string.Join(";", values)}";
        return CreateUuid(name).ToString("B");
    }

    private static Guid CreateUuid(string name)
    {
        Guid namespaceId = new("28F1468D-672B-489A-8E0C-7C5B3030630C");
        byte[] nameBytes = Encoding.UTF8.GetBytes(name ?? string.Empty);
        byte[] namespaceBytes = namespaceId.ToByteArray();
        Swap(namespaceBytes, 0, 3);
        Swap(namespaceBytes, 1, 2);
        Swap(namespaceBytes, 5, 6);
        Swap(namespaceBytes, 7, 8);
        byte[] input = [.. namespaceBytes, .. nameBytes];
        byte[] hash = XxHash128.Hash(input);
        byte[] result = hash[..16];
        result[6] = (byte)(0x80 | (result[6] & 0x0F));
        result[8] = (byte)(0x40 | (result[8] & 0x3F));
        Swap(result, 0, 3);
        Swap(result, 1, 2);
        Swap(result, 5, 6);
        Swap(result, 7, 8);
        return new Guid(result);
    }

    private static void Swap(byte[] bytes, int x, int y) => (bytes[x], bytes[y]) = (bytes[y], bytes[x]);
}
