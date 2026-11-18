global using static R65ProbeHash;

using System.Security.Cryptography;

internal static class R65ProbeHash
{
    internal static string Sha256Hex(ReadOnlySpan<byte> value)
        => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
}
