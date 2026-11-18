internal static partial class Program
{
    private static Process StartRestrictedProcess(
        string dotnetPath,
        string assemblyPath,
        IReadOnlyList<string> arguments)
    {
        using SafeAccessTokenHandle currentToken = OpenCurrentProcessTokenForDuplication();
        using SafeAccessTokenHandle restrictedToken = CreateMediumRestrictedToken(currentToken);

        string commandLine = BuildWindowsCommandLine([dotnetPath, assemblyPath, .. arguments]);
        var startupInfo = new STARTUPINFO
        {
            cb = Marshal.SizeOf<STARTUPINFO>(),
        };

        bool created = CreateProcessWithTokenW(
            restrictedToken,
            0,
            dotnetPath,
            new StringBuilder(commandLine),
            CreateNoWindow | CreateUnicodeEnvironment,
            IntPtr.Zero,
            Path.GetDirectoryName(assemblyPath),
            ref startupInfo,
            out PROCESS_INFORMATION processInfo);

        if (!created)
        {
            int error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"CreateProcessWithTokenW failed: {error} {new System.ComponentModel.Win32Exception(error).Message}");
        }

        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return Process.GetProcessById(processInfo.dwProcessId);
    }

    private static SafeAccessTokenHandle OpenCurrentProcessTokenForDuplication()
    {
        if (!OpenProcessToken(
            Process.GetCurrentProcess().Handle,
            TokenAssignPrimary | TokenDuplicate | TokenQuery | TokenAdjustDefault | TokenAdjustSessionId,
            out SafeAccessTokenHandle token))
        {
            int error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"OpenProcessToken failed: {error}");
        }

        return token;
    }

    private static SafeAccessTokenHandle CreateMediumRestrictedToken(SafeAccessTokenHandle currentToken)
    {
        SecurityIdentifier adminSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        IntPtr adminSidMemory = AllocSid(adminSid);
        IntPtr attributesMemory = Marshal.AllocHGlobal(Marshal.SizeOf<SID_AND_ATTRIBUTES>());
        try
        {
            Marshal.StructureToPtr(new SID_AND_ATTRIBUTES
            {
                Sid = adminSidMemory,
                Attributes = SeGroupUseForDenyOnly,
            }, attributesMemory, false);

            if (!CreateRestrictedToken(
                currentToken,
                DisableMaxPrivilege,
                1,
                attributesMemory,
                0,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                out SafeAccessTokenHandle restricted))
            {
                int error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"CreateRestrictedToken failed: {error}");
            }

            try
            {
                SetIntegrityLevel(restricted, new SecurityIdentifier("S-1-16-8192"));
                return restricted;
            }
            catch
            {
                restricted.Dispose();
                throw;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(attributesMemory);
            Marshal.FreeHGlobal(adminSidMemory);
        }
    }

    private static void SetIntegrityLevel(SafeAccessTokenHandle token, SecurityIdentifier integritySid)
    {
        IntPtr sidMemory = AllocSid(integritySid);
        IntPtr labelMemory = Marshal.AllocHGlobal(Marshal.SizeOf<TOKEN_MANDATORY_LABEL>());
        try
        {
            Marshal.StructureToPtr(new TOKEN_MANDATORY_LABEL
            {
                Label = new SID_AND_ATTRIBUTES
                {
                    Sid = sidMemory,
                    Attributes = SeGroupIntegrity,
                }
            }, labelMemory, false);

            int length = Marshal.SizeOf<TOKEN_MANDATORY_LABEL>() + integritySid.BinaryLength;
            if (!SetTokenInformation(token, TokenIntegrityLevel, labelMemory, length))
            {
                int error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"SetTokenInformation(TokenIntegrityLevel) failed: {error}");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(labelMemory);
            Marshal.FreeHGlobal(sidMemory);
        }
    }

    private static IntPtr AllocSid(SecurityIdentifier sid)
    {
        byte[] bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        IntPtr memory = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, memory, bytes.Length);
        return memory;
    }

    private static void CreateAdminOwnedDirectory(string path)
    {
        Directory.CreateDirectory(path);
        SecurityIdentifier admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier users = new(WellKnownSidType.BuiltinUsersSid, null);

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(admins);
        security.SetGroup(admins);
        InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }
}
