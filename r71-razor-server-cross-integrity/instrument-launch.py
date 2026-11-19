#!/usr/bin/env python3
from pathlib import Path

program = Path("r71-razor-server-cross-integrity/Program.cs")
source = program.read_text(encoding="utf-8")


def replace_once(old: str, new: str, name: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{name} block count was {count}, expected exactly one")
    source = source.replace(old, new, 1)

replace_once(
    '''    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
''',
    '''    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint LogonWithProfile = 0x00000001;
''',
    "launch constants")

old_launch = '''    private static Process StartRestrictedProcess(string dotnetPath, string assemblyPath, IReadOnlyList<string> args)
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
'''
new_launch = '''    private static Process StartRestrictedProcess(string dotnetPath, string assemblyPath, IReadOnlyList<string> args)
    {
        using SafeAccessTokenHandle current = OpenCurrentToken();
        using SafeAccessTokenHandle restricted = CreateMediumRestrictedToken(current);
        string commandLine = BuildCommandLine([dotnetPath, assemblyPath, .. args]);
        var startup = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };

        if (!CreateEnvironmentBlock(out IntPtr environment, restricted, false))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateEnvironmentBlock failed");
        }

        try
        {
            if (!CreateProcessWithTokenW(
                restricted,
                LogonWithProfile,
                dotnetPath,
                new StringBuilder(commandLine),
                CreateNoWindow | CreateUnicodeEnvironment,
                environment,
                Path.GetDirectoryName(assemblyPath),
                ref startup,
                out PROCESS_INFORMATION info))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                Process process = Process.GetProcessById(info.dwProcessId);
                process.EnableRaisingEvents = true;
                return process;
            }
            finally
            {
                CloseHandle(info.hThread);
                CloseHandle(info.hProcess);
            }
        }
        finally
        {
            DestroyEnvironmentBlock(environment);
        }
    }
'''
replace_once(old_launch, new_launch, "restricted launch")

old_after_launch = '''        Process client = StartRestrictedProcess(dotnetPath, clientDll,
        [
            "client", canary, clientResult, dotnetPath, rzcPath, tasksPath,
            extensionPath, invokeProject, pipe, workDir,
        ]);

        bool clientTimedOut = false;
'''
new_after_launch = '''        Process client = StartRestrictedProcess(dotnetPath, clientDll,
        [
            "client", canary, clientResult, dotnetPath, rzcPath, tasksPath,
            extensionPath, invokeProject, pipe, workDir,
        ]);

        var bootstrap = new Dictionary<string, object?>
        {
            ["pid"] = client.Id,
            ["capturedAtUtc"] = DateTimeOffset.UtcNow,
        };
        try
        {
            bootstrap["processName"] = client.ProcessName;
            bootstrap["hasExitedAtLaunch"] = client.HasExited;
            bootstrap["integrityRid"] = GetProcessIntegrity(client);
            bootstrap["sid"] = GetProcessSid(client);
            bootstrap["threadCount"] = client.Threads.Count;
            bootstrap["mainModule"] = client.MainModule?.FileName;
        }
        catch (Exception ex)
        {
            bootstrap["snapshotError"] = ex.ToString();
        }
        await Task.Delay(TimeSpan.FromSeconds(3));
        try
        {
            bootstrap["hasExitedAfterThreeSeconds"] = client.HasExited;
            bootstrap["clientProgressAfterThreeSeconds"] = File.Exists(clientProgress);
            bootstrap["totalProcessorMillisecondsAfterThreeSeconds"] = client.TotalProcessorTime.TotalMilliseconds;
            bootstrap["threadCountAfterThreeSeconds"] = client.Threads.Count;
        }
        catch (Exception ex)
        {
            bootstrap["delayedSnapshotError"] = ex.ToString();
        }
        await File.WriteAllTextAsync(
            Path.Combine(trialDir, "client-bootstrap-snapshot.json"),
            JsonSerializer.Serialize(bootstrap, JsonOptions) + Environment.NewLine);

        bool clientTimedOut = false;
'''
replace_once(old_after_launch, new_after_launch, "bootstrap snapshot")

replace_once(
    '''        for (int trial = 1; trial <= 3; trial++)
''',
    '''        for (int trial = 1; trial <= 1; trial++)
''',
    "diagnostic trial count")

replace_once(
    '''        bool positive = trials.All(t => Bool(t, "runtimePositive"));
        bool controls = trials.All(t => Bool(t, "controlsPassed"));
        bool identities = trials.All(t => Bool(t, "identityBoundaryConfirmed"));
''',
    '''        bool positive = trials.Count == 3 && trials.All(t => Bool(t, "runtimePositive"));
        bool controls = trials.Count == 3 && trials.All(t => Bool(t, "controlsPassed"));
        bool identities = trials.Count == 3 && trials.All(t => Bool(t, "identityBoundaryConfirmed"));
''',
    "diagnostic verdict gate")

replace_once(
    '''        using var clientTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(230));
''',
    '''        using var clientTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
''',
    "diagnostic client timeout")

replace_once(
    '''    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CreateProcessWithTokenW(SafeAccessTokenHandle token, uint logonFlags, string? applicationName, StringBuilder commandLine, uint creationFlags, IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);
''',
    '''    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CreateProcessWithTokenW(SafeAccessTokenHandle token, uint logonFlags, string? applicationName, StringBuilder commandLine, uint creationFlags, IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool CreateEnvironmentBlock(out IntPtr environment, SafeAccessTokenHandle token, bool inherit);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool DestroyEnvironmentBlock(IntPtr environment);
''',
    "environment block imports")

program.write_text(source, encoding="utf-8")
print("R71_RESTRICTED_BOOTSTRAP_DIAGNOSTIC_APPLIED")
