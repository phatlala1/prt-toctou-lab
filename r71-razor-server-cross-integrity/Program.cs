using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

internal static class Program
{
    private const uint DisableMaxPrivilege = 0x1;
    private const uint SeGroupUseForDenyOnly = 0x10;
    private const uint SeGroupIntegrity = 0x20;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustSessionId = 0x0100;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const int TokenIntegrityLevel = 25;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("R71 requires Windows.");
            return 2;
        }

        try
        {
            return args[0] switch
            {
                "orchestrate" => await OrchestrateAsync(args),
                "client" => await ClientAsync(args),
                _ => throw new ArgumentException("Expected orchestrate or client mode."),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static async Task<int> OrchestrateAsync(string[] args)
    {
        if (args.Length != 7)
        {
            throw new ArgumentException("orchestrate evidence dotnet rzc tasks extension invokeProject");
        }

        string evidenceRoot = Path.GetFullPath(args[1]);
        string dotnetPath = Path.GetFullPath(args[2]);
        string rzcPath = Path.GetFullPath(args[3]);
        string tasksPath = Path.GetFullPath(args[4]);
        string extensionPath = Path.GetFullPath(args[5]);
        string invokeProject = Path.GetFullPath(args[6]);
        Directory.CreateDirectory(evidenceRoot);

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        bool orchestratorAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        int orchestratorIntegrity = GetProcessIntegrity(Process.GetCurrentProcess());
        if (!orchestratorAdmin || orchestratorIntegrity < 12288)
        {
            throw new InvalidOperationException($"Orchestrator is not high integrity: admin={orchestratorAdmin}, IL={orchestratorIntegrity}");
        }

        var trials = new List<Dictionary<string, object?>>();
        for (int trial = 1; trial <= 3; trial++)
        {
            trials.Add(await RunTrialAsync(trial, evidenceRoot, dotnetPath, rzcPath, tasksPath, extensionPath, invokeProject));
        }

        bool positive = trials.All(t => Bool(t, "runtimePositive"));
        bool controls = trials.All(t => Bool(t, "controlsPassed"));
        bool identities = trials.All(t => Bool(t, "identityBoundaryConfirmed"));
        var result = new Dictionary<string, object?>
        {
            ["schema"] = "r71-razor-server-cross-integrity/v1",
            ["testedAtUtc"] = DateTimeOffset.UtcNow,
            ["orchestratorSid"] = identity.User?.Value,
            ["orchestratorName"] = identity.Name,
            ["orchestratorIsAdministrator"] = orchestratorAdmin,
            ["orchestratorIntegrityRid"] = orchestratorIntegrity,
            ["dotnetPath"] = dotnetPath,
            ["rzcPath"] = rzcPath,
            ["tasksPath"] = tasksPath,
            ["extensionPath"] = extensionPath,
            ["trials"] = trials,
            ["verdict"] = new Dictionary<string, object?>
            {
                ["allThreeRuntimePositive"] = positive,
                ["allControlsPassed"] = controls,
                ["identityBoundaryConfirmed"] = identities,
                ["status"] = positive && controls && identities
                    ? "RUNTIME_POSITIVE_REVIEW_REQUIRED"
                    : "RUNTIME_NEGATIVE_OR_INVALID",
            },
        };

        string resultPath = Path.Combine(evidenceRoot, "result.json");
        await File.WriteAllTextAsync(resultPath, JsonSerializer.Serialize(result, JsonOptions) + Environment.NewLine);
        Console.WriteLine(JsonSerializer.Serialize(result["verdict"], JsonOptions));
        return positive && controls && identities ? 0 : 3;
    }

    private static async Task<Dictionary<string, object?>> RunTrialAsync(
        int trial,
        string evidenceRoot,
        string dotnetPath,
        string rzcPath,
        string tasksPath,
        string extensionPath,
        string invokeProject)
    {
        string id = $"trial-{trial}-{Guid.NewGuid():N}";
        string trialDir = Path.Combine(evidenceRoot, id);
        string workDir = Path.Combine(trialDir, "client-work");
        Directory.CreateDirectory(workDir);
        await File.WriteAllTextAsync(Path.Combine(workDir, "Index.cshtml"), "@page\nR71");

        string targetDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), $"r71-target-{Guid.NewGuid():N}");
        CreateAdminOnlyDirectory(targetDir);
        string canary = Path.Combine(targetDir, "protected-canary.txt");
        string original = $"R71_ORIGINAL_{Guid.NewGuid():N}";
        await File.WriteAllTextAsync(canary, original);
        string originalHash = Hash(canary);

        string pipe = $"r71-{Guid.NewGuid():N}";
        string serverLog = Path.Combine(trialDir, "razor-server.log");
        string highExecutionLog = Path.Combine(trialDir, "high-extension.log");
        string clientResult = Path.Combine(trialDir, "client-result.json");
        string clientDll = typeof(Program).Assembly.Location;

        var serverStart = new ProcessStartInfo(dotnetPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(rzcPath)!,
        };
        serverStart.ArgumentList.Add(rzcPath);
        serverStart.ArgumentList.Add("server");
        serverStart.ArgumentList.Add("-p");
        serverStart.ArgumentList.Add(pipe);
        serverStart.ArgumentList.Add("-k");
        serverStart.ArgumentList.Add("300");
        serverStart.Environment["R71_CANARY"] = canary;
        serverStart.Environment["R71_EXECUTION_LOG"] = highExecutionLog;
        serverStart.Environment["RAZORBUILDSERVER_LOG"] = serverLog;
        serverStart.Environment["DOTNET_HOST_PATH"] = dotnetPath;
        serverStart.Environment["DOTNET_BUILD_PIDFILE_DIRECTORY"] = trialDir;

        using Process server = Process.Start(serverStart) ?? throw new InvalidOperationException("Failed to start stock rzc server.");
        Task<string> serverOutTask = server.StandardOutput.ReadToEndAsync();
        Task<string> serverErrTask = server.StandardError.ReadToEndAsync();
        if (!WaitNamedPipe($@"\\.\pipe\{pipe}", 30_000))
        {
            throw new TimeoutException("Stock rzc server pipe did not become ready.");
        }

        int serverIntegrity = GetProcessIntegrity(server);
        string serverSid = GetProcessSid(server);

        Process client = StartRestrictedProcess(dotnetPath, clientDll,
        [
            "client", canary, clientResult, dotnetPath, rzcPath, tasksPath,
            extensionPath, invokeProject, pipe, workDir,
        ]);

        using var clientTimeout = new CancellationTokenSource(TimeSpan.FromMinutes(4));
        await client.WaitForExitAsync(clientTimeout.Token);
        int clientExit = client.ExitCode;

        if (!server.HasExited)
        {
            server.Kill(entireProcessTree: true);
        }
        await server.WaitForExitAsync();
        string serverStdout = await serverOutTask;
        string serverStderr = await serverErrTask;
        await File.WriteAllTextAsync(Path.Combine(trialDir, "server.stdout.txt"), serverStdout);
        await File.WriteAllTextAsync(Path.Combine(trialDir, "server.stderr.txt"), serverStderr);

        Dictionary<string, object?>? clientData = null;
        if (File.Exists(clientResult))
        {
            using JsonDocument document = JsonDocument.Parse(await File.ReadAllTextAsync(clientResult));
            clientData = ToDictionary(document.RootElement);
        }

        string finalHash = Hash(canary);
        string finalText = await File.ReadAllTextAsync(canary);
        string[] fields = finalText.Split('|');
        bool serverPidInCanary = fields.Length >= 6 && int.TryParse(fields[1], out int markerPid) && markerPid == server.Id;
        bool highIntegrityInCanary = fields.Length >= 6 && int.TryParse(fields[5], out int markerIl) && markerIl >= 12288;
        bool highLogRecorded = File.Exists(highExecutionLog) && (await File.ReadAllTextAsync(highExecutionLog)).Contains($"|{server.Id}|");

        bool controlsPassed = clientData is not null
            && Bool(clientData, "directWriteDenied")
            && Bool(clientData, "inProcessExecutedMedium")
            && Bool(clientData, "inProcessCanaryUnchanged")
            && Bool(clientData, "noExtensionServerCanaryUnchanged");
        bool identityBoundary = clientData is not null
            && Bool(clientData, "restrictedClientConfirmed")
            && serverIntegrity >= 12288
            && string.Equals(serverSid, clientData.GetValueOrDefault("clientSid")?.ToString(), StringComparison.OrdinalIgnoreCase);
        bool runtimePositive = finalHash != originalHash && serverPidInCanary && highIntegrityInCanary && highLogRecorded;

        var summary = new Dictionary<string, object?>
        {
            ["trial"] = trial,
            ["id"] = id,
            ["pipeName"] = pipe,
            ["serverPid"] = server.Id,
            ["serverSid"] = serverSid,
            ["serverIntegrityRid"] = serverIntegrity,
            ["clientExitCode"] = clientExit,
            ["originalCanarySha256"] = originalHash,
            ["finalCanarySha256"] = finalHash,
            ["finalCanaryText"] = finalText,
            ["serverPidInCanary"] = serverPidInCanary,
            ["highIntegrityInCanary"] = highIntegrityInCanary,
            ["highExecutionLogRecorded"] = highLogRecorded,
            ["client"] = clientData,
            ["controlsPassed"] = controlsPassed,
            ["identityBoundaryConfirmed"] = identityBoundary,
            ["runtimePositive"] = runtimePositive,
        };
        await File.WriteAllTextAsync(Path.Combine(trialDir, "trial-summary.json"), JsonSerializer.Serialize(summary, JsonOptions) + Environment.NewLine);
        return summary;
    }

    private static async Task<int> ClientAsync(string[] args)
    {
        if (args.Length != 10)
        {
            throw new ArgumentException("client canary result dotnet rzc tasks extension invoke pipe workdir");
        }

        string canary = Path.GetFullPath(args[1]);
        string resultFile = Path.GetFullPath(args[2]);
        string dotnetPath = Path.GetFullPath(args[3]);
        string rzcPath = Path.GetFullPath(args[4]);
        string tasksPath = Path.GetFullPath(args[5]);
        string extensionPath = Path.GetFullPath(args[6]);
        string invokeProject = Path.GetFullPath(args[7]);
        string pipe = args[8];
        string workDir = Path.GetFullPath(args[9]);
        Directory.CreateDirectory(workDir);

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        bool admin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        int integrity = GetProcessIntegrity(Process.GetCurrentProcess());
        string before = Hash(canary);

        bool directDenied = false;
        string directError = string.Empty;
        try
        {
            await File.WriteAllTextAsync(canary, "MEDIUM_DIRECT_WRITE");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            directDenied = true;
            directError = $"{ex.GetType().Name}:{ex.Message}";
        }

        string mediumLog = Path.Combine(workDir, "medium-extension.log");
        CommandResult inProcess = await RunTaskAsync(false, true, "unused", "inproc", mediumLog);
        string afterInProcess = Hash(canary);
        string mediumText = File.Exists(mediumLog) ? await File.ReadAllTextAsync(mediumLog) : string.Empty;
        bool mediumExecuted = mediumText.Contains($"|{Environment.ProcessId}|") || mediumText.Contains("|8192|");

        CommandResult noExtension = await RunTaskAsync(true, false, pipe, "server-no-extension", Path.Combine(workDir, "client-no-extension.log"));
        string afterNoExtension = Hash(canary);

        CommandResult attack = await RunTaskAsync(true, true, pipe, "server-extension", Path.Combine(workDir, "client-attack.log"));
        string afterAttack = Hash(canary);

        bool restricted = !admin && integrity <= 8192 && directDenied;
        var result = new Dictionary<string, object?>
        {
            ["clientPid"] = Environment.ProcessId,
            ["clientSid"] = identity.User?.Value,
            ["clientName"] = identity.Name,
            ["clientIsAdministrator"] = admin,
            ["clientIntegrityRid"] = integrity,
            ["restrictedClientConfirmed"] = restricted,
            ["directWriteDenied"] = directDenied,
            ["directWriteError"] = directError,
            ["inProcessExitCode"] = inProcess.ExitCode,
            ["inProcessStdout"] = inProcess.Stdout,
            ["inProcessStderr"] = inProcess.Stderr,
            ["inProcessExecutionLog"] = mediumText,
            ["inProcessExecutedMedium"] = mediumExecuted,
            ["inProcessCanaryUnchanged"] = before == afterInProcess,
            ["noExtensionServerExitCode"] = noExtension.ExitCode,
            ["noExtensionServerStdout"] = noExtension.Stdout,
            ["noExtensionServerStderr"] = noExtension.Stderr,
            ["noExtensionServerCanaryUnchanged"] = afterInProcess == afterNoExtension,
            ["attackExitCode"] = attack.ExitCode,
            ["attackStdout"] = attack.Stdout,
            ["attackStderr"] = attack.Stderr,
            ["attackChangedCanary"] = afterAttack != afterNoExtension,
        };
        Directory.CreateDirectory(Path.GetDirectoryName(resultFile)!);
        await File.WriteAllTextAsync(resultFile, JsonSerializer.Serialize(result, JsonOptions) + Environment.NewLine);
        return restricted ? 0 : 4;

        async Task<CommandResult> RunTaskAsync(bool useServer, bool includeExtension, string pipeName, string label, string executionLog)
        {
            string runDir = Path.Combine(workDir, label);
            Directory.CreateDirectory(runDir);
            string source = Path.Combine(runDir, "Index.cshtml");
            await File.WriteAllTextAsync(source, "@page\nR71");

            var psi = new ProcessStartInfo(dotnetPath)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = runDir,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(invokeProject);
            psi.ArgumentList.Add("/t:Run");
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:diag");
            AddProperty("RazorTasksAssembly", tasksPath);
            AddProperty("RzcPath", rzcPath);
            AddProperty("DotnetPath", dotnetPath);
            AddProperty("ExtensionPath", extensionPath);
            AddProperty("SourcePath", source);
            AddProperty("WorkDirectory", runDir);
            AddProperty("TagHelperManifest", Path.Combine(runDir, "taghelpers.json"));
            AddProperty("UseServer", useServer.ToString().ToLowerInvariant());
            AddProperty("ForceServer", useServer.ToString().ToLowerInvariant());
            AddProperty("PipeName", pipeName);
            AddProperty("IncludeExtension", includeExtension.ToString().ToLowerInvariant());
            psi.Environment["DOTNET_HOST_PATH"] = dotnetPath;
            psi.Environment["R71_CANARY"] = canary;
            psi.Environment["R71_EXECUTION_LOG"] = executionLog;
            psi.Environment["DOTNET_NOLOGO"] = "1";
            using Process process = Process.Start(psi) ?? throw new InvalidOperationException("Failed to launch official Razor MSBuild task.");
            string stdout = await process.StandardOutput.ReadToEndAsync();
            string stderr = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            await File.WriteAllTextAsync(Path.Combine(runDir, "stdout.txt"), stdout);
            await File.WriteAllTextAsync(Path.Combine(runDir, "stderr.txt"), stderr);
            return new CommandResult(process.ExitCode, stdout, stderr);

            void AddProperty(string name, string value) => psi.ArgumentList.Add($"/p:{name}={value}");
        }
    }

    private static Process StartRestrictedProcess(string dotnetPath, string assemblyPath, IReadOnlyList<string> args)
    {
        using SafeAccessTokenHandle current = OpenCurrentToken();
        using SafeAccessTokenHandle restricted = CreateMediumRestrictedToken(current);
        string commandLine = BuildCommandLine([dotnetPath, assemblyPath, .. args]);
        var startup = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
        if (!CreateProcessWithTokenW(restricted, 0, dotnetPath, new StringBuilder(commandLine), CreateNoWindow | CreateUnicodeEnvironment, IntPtr.Zero, Path.GetDirectoryName(assemblyPath), ref startup, out PROCESS_INFORMATION info))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        return Process.GetProcessById(info.dwProcessId);
    }

    private static SafeAccessTokenHandle OpenCurrentToken()
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TokenAssignPrimary | TokenDuplicate | TokenQuery | TokenAdjustDefault | TokenAdjustSessionId, out SafeAccessTokenHandle token))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        return token;
    }

    private static SafeAccessTokenHandle CreateMediumRestrictedToken(SafeAccessTokenHandle current)
    {
        SecurityIdentifier admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        IntPtr sid = AllocSid(admins);
        IntPtr disabled = Marshal.AllocHGlobal(Marshal.SizeOf<SID_AND_ATTRIBUTES>());
        try
        {
            Marshal.StructureToPtr(new SID_AND_ATTRIBUTES { Sid = sid, Attributes = SeGroupUseForDenyOnly }, disabled, false);
            if (!CreateRestrictedToken(current, DisableMaxPrivilege, 1, disabled, 0, IntPtr.Zero, 0, IntPtr.Zero, out SafeAccessTokenHandle restricted))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            SetIntegrity(restricted, new SecurityIdentifier("S-1-16-8192"));
            return restricted;
        }
        finally
        {
            Marshal.FreeHGlobal(disabled);
            Marshal.FreeHGlobal(sid);
        }
    }

    private static void SetIntegrity(SafeAccessTokenHandle token, SecurityIdentifier integritySid)
    {
        IntPtr sid = AllocSid(integritySid);
        IntPtr label = Marshal.AllocHGlobal(Marshal.SizeOf<TOKEN_MANDATORY_LABEL>());
        try
        {
            Marshal.StructureToPtr(new TOKEN_MANDATORY_LABEL { Label = new SID_AND_ATTRIBUTES { Sid = sid, Attributes = SeGroupIntegrity } }, label, false);
            if (!SetTokenInformation(token, TokenIntegrityLevel, label, Marshal.SizeOf<TOKEN_MANDATORY_LABEL>() + integritySid.BinaryLength))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(label);
            Marshal.FreeHGlobal(sid);
        }
    }

    private static int GetProcessIntegrity(Process process)
    {
        if (!OpenProcessToken(process.Handle, TokenQuery, out SafeAccessTokenHandle token))
        {
            return -1;
        }
        using (token)
        {
            _ = GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out int required);
            IntPtr buffer = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, required, out _)) return -2;
                TOKEN_MANDATORY_LABEL label = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(buffer);
                byte count = Marshal.ReadByte(GetSidSubAuthorityCount(label.Label.Sid));
                return Marshal.ReadInt32(GetSidSubAuthority(label.Label.Sid, (uint)(count - 1)));
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    private static string GetProcessSid(Process process)
    {
        if (!OpenProcessToken(process.Handle, TokenQuery, out SafeAccessTokenHandle token)) return "TOKEN_ERROR";
        using (token)
        using (WindowsIdentity identity = new(token.DangerousGetHandle()))
        {
            return identity.User?.Value ?? "NO_SID";
        }
    }

    private static void CreateAdminOnlyDirectory(string path)
    {
        Directory.CreateDirectory(path);
        SecurityIdentifier admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier users = new(WellKnownSidType.BuiltinUsersSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(admins);
        InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static IntPtr AllocSid(SecurityIdentifier sid)
    {
        byte[] bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        IntPtr memory = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, memory, bytes.Length);
        return memory;
    }

    private static string Hash(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
    private static bool Bool(IReadOnlyDictionary<string, object?> data, string key) => data.TryGetValue(key, out object? value) && value is bool b && b;

    private static string BuildCommandLine(IReadOnlyList<string> values) => string.Join(" ", values.Select(Quote));
    private static string Quote(string value) => "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    private static Dictionary<string, object?> ToDictionary(JsonElement element)
    {
        var result = new Dictionary<string, object?>();
        foreach (JsonProperty property in element.EnumerateObject()) result[property.Name] = ToObject(property.Value);
        return result;
    }

    private static object? ToObject(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => ToDictionary(element),
        JsonValueKind.Array => element.EnumerateArray().Select(ToObject).ToList(),
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number when element.TryGetInt64(out long value) => value,
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        _ => element.GetRawText(),
    };

    private readonly record struct CommandResult(int ExitCode, string Stdout, string Stderr);

    [StructLayout(LayoutKind.Sequential)] private struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct STARTUPINFO { public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CreateRestrictedToken(SafeAccessTokenHandle existingTokenHandle, uint flags, int disableSidCount, IntPtr sidsToDisable, int deletePrivilegeCount, IntPtr privilegesToDelete, int restrictedSidCount, IntPtr sidsToRestrict, out SafeAccessTokenHandle newTokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetTokenInformation(SafeAccessTokenHandle tokenHandle, int tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(SafeAccessTokenHandle tokenHandle, int tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength, out int returnLength);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CreateProcessWithTokenW(SafeAccessTokenHandle token, uint logonFlags, string? applicationName, StringBuilder commandLine, uint creationFlags, IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);
    [DllImport("advapi32.dll")] private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool WaitNamedPipe(string name, int timeout);
}
