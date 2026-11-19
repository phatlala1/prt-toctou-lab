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
    '''    private const uint DisableMaxPrivilege = 0x1;
    private const uint SeGroupUseForDenyOnly = 0x10;
''',
    '''    private const uint DisableMaxPrivilege = 0x1;
    private const uint LuaToken = 0x4;
    private const uint SeGroupUseForDenyOnly = 0x10;
''',
    "LUA token constant")

old_function = '''    private static SafeAccessTokenHandle CreateMediumRestrictedToken(SafeAccessTokenHandle current)
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
'''
new_function = '''    private static SafeAccessTokenHandle CreateMediumRestrictedToken(SafeAccessTokenHandle current)
    {
        if (!CreateRestrictedToken(
            current,
            DisableMaxPrivilege | LuaToken,
            0,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            out SafeAccessTokenHandle restricted))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateRestrictedToken(LUA_TOKEN) failed");
        }
        SetIntegrity(restricted, new SecurityIdentifier("S-1-16-8192"));
        return restricted;
    }
'''
replace_once(old_function, new_function, "medium token implementation")

program.write_text(source, encoding="utf-8")
print("R71_LUA_FILTERED_TOKEN_APPLIED")
