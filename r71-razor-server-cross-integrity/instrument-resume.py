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
    private const uint LogonWithProfile = 0x00000001;
''',
    '''    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateSuspended = 0x00000004;
    private const uint LogonWithProfile = 0x00000001;
    private static uint LastResumeThreadPreviousCount = uint.MaxValue;
''',
    "resume constants")

replace_once(
    '''                CreateNoWindow | CreateUnicodeEnvironment,
                environment,
''',
    '''                CreateNoWindow | CreateUnicodeEnvironment | CreateSuspended,
                environment,
''',
    "create suspended flag")

replace_once(
    '''            try
            {
                Process process = Process.GetProcessById(info.dwProcessId);
                process.EnableRaisingEvents = true;
                return process;
            }
            finally
''',
    '''            try
            {
                LastResumeThreadPreviousCount = ResumeThread(info.hThread);
                if (LastResumeThreadPreviousCount == uint.MaxValue)
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
                }
                Process process = Process.GetProcessById(info.dwProcessId);
                process.EnableRaisingEvents = true;
                return process;
            }
            finally
''',
    "resume primary thread")

replace_once(
    '''            ["capturedAtUtc"] = DateTimeOffset.UtcNow,
        };
''',
    '''            ["capturedAtUtc"] = DateTimeOffset.UtcNow,
            ["resumeThreadPreviousCount"] = LastResumeThreadPreviousCount,
        };
''',
    "resume snapshot")

replace_once(
    '''    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
''',
    '''    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr threadHandle);
''',
    "resume import")

program.write_text(source, encoding="utf-8")
print("R71_EXPLICIT_THREAD_RESUME_APPLIED")
