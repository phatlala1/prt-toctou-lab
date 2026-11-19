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
    '''        string clientProgress = Path.Combine(trialDir, "client-progress.json");
        string clientDll = typeof(Program).Assembly.Location;
''',
    '''        string clientProgress = Path.Combine(trialDir, "client-progress.json");
        string clientExe = Path.ChangeExtension(typeof(Program).Assembly.Location, ".exe");
        if (!File.Exists(clientExe))
        {
            throw new FileNotFoundException("R71 apphost was not produced.", clientExe);
        }
''',
    "client apphost declaration")

replace_once(
    '''        Process client = StartRestrictedProcess(dotnetPath, clientDll,
        [
            "client", canary, clientResult, dotnetPath, rzcPath, tasksPath,
            extensionPath, invokeProject, pipe, workDir,
        ]);
''',
    '''        Process client = StartRestrictedProcess(clientExe,
        [
            "client", canary, clientResult, dotnetPath, rzcPath, tasksPath,
            extensionPath, invokeProject, pipe, workDir,
        ]);
''',
    "restricted apphost call")

replace_once(
    '''    private static Process StartRestrictedProcess(string dotnetPath, string assemblyPath, IReadOnlyList<string> args)
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
''',
    '''    private static Process StartRestrictedProcess(string executablePath, IReadOnlyList<string> args)
    {
        using SafeAccessTokenHandle current = OpenCurrentToken();
        using SafeAccessTokenHandle restricted = CreateMediumRestrictedToken(current);
        string commandLine = BuildCommandLine([executablePath, .. args]);
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
                executablePath,
                new StringBuilder(commandLine),
                CreateNoWindow | CreateUnicodeEnvironment,
                environment,
                Path.GetDirectoryName(executablePath),
                ref startup,
                out PROCESS_INFORMATION info))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
''',
    "restricted process apphost implementation")

program.write_text(source, encoding="utf-8")
print("R71_RESTRICTED_APPHOST_APPLIED")
