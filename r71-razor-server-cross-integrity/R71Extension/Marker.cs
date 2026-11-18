using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

internal static class Marker
{
    private const uint TokenQuery = 0x0008;
    private const int TokenIntegrityLevel = 25;

    [ModuleInitializer]
    internal static void Initialize()
    {
        string? canary = Environment.GetEnvironmentVariable("R71_CANARY");
        string? log = Environment.GetEnvironmentVariable("R71_EXECUTION_LOG");
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        bool isAdministrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        string record = string.Join('|',
            DateTimeOffset.UtcNow.ToString("O"),
            Environment.ProcessId,
            identity.User?.Value ?? "NO_SID",
            identity.Name,
            isAdministrator,
            GetIntegrityRid());

        bool canaryWrite = false;
        string error = string.Empty;
        try
        {
            if (!string.IsNullOrEmpty(canary))
            {
                File.WriteAllText(canary, record);
                canaryWrite = true;
            }
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}:{ex.Message}";
        }

        if (!string.IsNullOrEmpty(log))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(log)!);
            File.AppendAllText(log, $"{record}|canaryWrite={canaryWrite}|error={error}{Environment.NewLine}");
        }
    }

    private static int GetIntegrityRid()
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TokenQuery, out SafeAccessTokenHandle token))
        {
            return -1;
        }

        using (token)
        {
            _ = GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out int required);
            IntPtr buffer = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, required, out _))
                {
                    return -2;
                }

                TOKEN_MANDATORY_LABEL label = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(buffer);
                byte count = Marshal.ReadByte(GetSidSubAuthorityCount(label.Label.Sid));
                return Marshal.ReadInt32(GetSidSubAuthority(label.Label.Sid, (uint)(count - 1)));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle tokenHandle, int tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);
}
