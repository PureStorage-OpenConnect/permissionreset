using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace PermissionReset.Smb;

// Win32Security reads raw security descriptors by handle. The handle is opened with backup intent
// and without following reparse points, so the read sees the object itself, under
// SeBackupPrivilege, as Set-SaclOnly does (tools/set-saclonly/SaclOnly.cs).
[SupportedOSPlatform("windows")]
static partial class Win32Security
{
    const uint OWNER = 1, GROUP = 2, DACL = 4, SACL = 8;
    const uint READ_CONTROL = 0x00020000, ACCESS_SYSTEM_SECURITY = 0x01000000;
    const uint SHARE_ALL = 7, OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const int ERROR_INSUFFICIENT_BUFFER = 122;

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial IntPtr CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr h);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetKernelObjectSecurity(IntPtr h, uint info, byte[]? sd, uint len, out uint needed);

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint Low; public int High; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [LibraryImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValue(string? system, string name, out LUID luid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AdjustTokenPrivileges(IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, ref TOKEN_PRIVILEGES state, uint len, IntPtr prev, IntPtr retLen);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetCurrentProcess();

    // EnablePrivilege enables a privilege the token already holds. AdjustTokenPrivileges reports
    // success even when the token lacks it, so ERROR_NOT_ALL_ASSIGNED (1300) is checked too.
    public static void EnablePrivilege(string name)
    {
        const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8, SE_PRIVILEGE_ENABLED = 2;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token))
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"open process token for {name}");
        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"look up {name}");
            var tp = new TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"enable {name}");
            int err = Marshal.GetLastPInvokeError();
            if (err == 1300) throw new Win32Exception(err, $"this account does not hold {name}; run elevated as an account that does");
        }
        finally { CloseHandle(token); }
    }

    // ReadDescriptor returns the object's self-relative descriptor: owner, group, DACL and, when
    // withSacl, the SACL (which needs SeSecurityPrivilege enabled).
    public static byte[] ReadDescriptor(string path, bool withSacl)
    {
        uint access = READ_CONTROL | (withSacl ? ACCESS_SYSTEM_SECURITY : 0);
        uint info = OWNER | GROUP | DACL | (withSacl ? SACL : 0);
        IntPtr h = CreateFile(LongPath(path), access, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastPInvokeError(), "open");
        try
        {
            GetKernelObjectSecurity(h, info, null, 0, out uint needed);
            int err = Marshal.GetLastPInvokeError();
            if (err != ERROR_INSUFFICIENT_BUFFER) throw new Win32Exception(err, "size descriptor");
            var sd = new byte[needed];
            if (!GetKernelObjectSecurity(h, info, sd, needed, out _))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "read descriptor");
            return sd;
        }
        finally { CloseHandle(h); }
    }

    // LongPath adds the \\?\ prefix so paths past MAX_PATH open; UNC paths become \\?\UNC\.
    public static string LongPath(string p)
    {
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) return p;
        var full = Path.GetFullPath(p);
        return full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;
    }
}
