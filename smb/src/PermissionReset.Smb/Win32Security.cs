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
    const uint READ_CONTROL = 0x00020000, ACCESS_SYSTEM_SECURITY = 0x01000000, FILE_READ_ATTRIBUTES = 0x0080;
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
    public static void EnablePrivilege(string name) => AdjustPrivilege(name, enable: true);

    // IsElevated is run.json's "elevated" (run control plan 4.1): the process token holds the
    // Administrators role.
    public static bool IsElevated()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    delegate bool ConsoleCtrlHandler(uint controlType);

    static ConsoleCtrlHandler? closeHandler;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleCtrlHandler(ConsoleCtrlHandler handler, [MarshalAs(UnmanagedType.Bool)] bool add);

    // RegisterCloseHandler is the console-close stop source of the run control plan (5.1): on
    // CTRL_CLOSE_EVENT Windows gives the process about 5 seconds, so the handler asks for the
    // clean stop, waits deadline for Main's flush-and-exit-3 sequence, and then forces the exit.
    // The handler stays for the process's life; the delegate is kept reachable.
    public static void RegisterCloseHandler(Action cancel, TimeSpan deadline)
    {
        const uint CTRL_CLOSE_EVENT = 2;
        ConsoleCtrlHandler handler = type =>
        {
            if (type != CTRL_CLOSE_EVENT) return false;
            cancel();
            Thread.Sleep(deadline);
            Environment.Exit(3);
            return true;
        };
        // Rooted in a static field: the OS holds only a raw function pointer, so a delegate the GC
        // collected would crash the process when the close event arrives.
        closeHandler = handler;
        SetConsoleCtrlHandler(handler, true);
    }

    // DisablePrivilege turns a privilege off for this process (design 4: SeRestorePrivilege stays
    // off unless the plan sets owner or group). A token that does not hold it is already there.
    public static void DisablePrivilege(string name)
    {
        try { AdjustPrivilege(name, enable: false); }
        catch (Win32Exception e) when (e.NativeErrorCode == 1300) { }
    }

    static void AdjustPrivilege(string name, bool enable)
    {
        const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8;
        uint SE_PRIVILEGE_ENABLED = enable ? 2u : 0u;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token))
            throw LastError($"open process token for {name}");
        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
                throw LastError($"look up {name}");
            var tp = new TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                throw LastError($"enable {name}");
            int err = Marshal.GetLastPInvokeError();
            if (err == 1300) throw new Win32Exception(err, $"this account does not hold {name}; run elevated as an account that does");
        }
        finally { CloseHandle(token); }
    }

    // DescriptorRead is one open's result: the self-relative descriptor and the FILE_ATTRIBUTE_*
    // bits of the object the handle actually opened. The attributes come from the same handle, so
    // a caller can tell that an object listed as a file has since become a directory or a reparse
    // point (smb/DESIGN-write-path.md, 5.3).
    public readonly record struct DescriptorRead(byte[] Descriptor, uint Attributes);

    // FILE_ATTRIBUTE_TAG_INFO, GetFileInformationByHandleEx class: FileAttributes, ReparseTag.
    const int FileAttributeTagInfo = 9;

    [StructLayout(LayoutKind.Sequential)]
    struct AttributeTag { public uint FileAttributes; public uint ReparseTag; }

    // ReadDescriptor returns the object's self-relative descriptor: owner, group, DACL and, when
    // withSacl, the SACL (which needs SeSecurityPrivilege enabled), plus the opened attributes.
    public static DescriptorRead ReadDescriptor(string path, bool withSacl)
    {
        // FILE_READ_ATTRIBUTES is for the FileAttributeTagInfo query below; READ_CONTROL alone does
        // not grant it. Both are read-only rights.
        uint access = READ_CONTROL | FILE_READ_ATTRIBUTES | (withSacl ? ACCESS_SYSTEM_SECURITY : 0);
        uint info = OWNER | GROUP | DACL | (withSacl ? SACL : 0);
        IntPtr h = CreateFile(LongPath(path), access, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw LastError("open");
        try
        {
            if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, out AttributeTag tag, (uint)Marshal.SizeOf<AttributeTag>()))
                throw LastError("query attributes");
            GetKernelObjectSecurity(h, info, null, 0, out uint needed);
            int err = Marshal.GetLastPInvokeError();
            if (err != ERROR_INSUFFICIENT_BUFFER) throw Error(err, "size descriptor");
            var sd = new byte[needed];
            if (!GetKernelObjectSecurity(h, info, sd, needed, out _))
                throw LastError("read descriptor");
            return new DescriptorRead(sd, tag.FileAttributes);
        }
        finally { CloseHandle(h); }
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetKernelObjectSecurity(IntPtr h, uint info, byte[] sd);

    const uint WRITE_DAC = 0x00040000, WRITE_OWNER = 0x00080000;

    // WriteDescriptor sets the parts info names, through a handle opened with backup intent and
    // without following a reparse point, asking only for the access those parts need: WRITE_DAC for
    // the DACL, WRITE_OWNER for owner or group, ACCESS_SYSTEM_SECURITY for the SACL. It is one
    // SetKernelObjectSecurity, the handle-based form of the SetFileSecurityW call the Q-INH/Q-EXP/
    // Q-PROT runs used; unlike SetSecurityInfo it does no client-side inheritance work.
    public static void WriteDescriptor(string path, uint info, byte[] sd)
    {
        uint access = READ_CONTROL;
        if ((info & DACL) != 0) access |= WRITE_DAC;
        if ((info & (OWNER | GROUP)) != 0) access |= WRITE_OWNER;
        if ((info & SACL) != 0) access |= ACCESS_SYSTEM_SECURITY;
        IntPtr h = CreateFile(LongPath(path), access, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw LastError("open for write");
        try
        {
            if (!SetKernelObjectSecurity(h, info, sd)) throw LastError("set security");
        }
        finally { CloseHandle(h); }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateDirectoryW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateDirectoryW(string path, IntPtr sa);

    [LibraryImport("kernel32.dll", EntryPoint = "RemoveDirectoryW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool RemoveDirectoryW(string path);

    [LibraryImport("kernel32.dll", EntryPoint = "DeleteFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeleteFileW(string path);

    // The probe's calls. The parent must exist: nothing here creates intermediate directories, so
    // a mistyped --probe-dir fails rather than landing a new directory in live data.
    public static void CreateDirectory(string path)
    {
        if (!CreateDirectoryW(LongPath(path), IntPtr.Zero)) throw LastError("create directory");
    }

    public static void CreateNewFile(string path)
    {
        const uint GENERIC_WRITE = 0x40000000, CREATE_NEW = 1, FILE_ATTRIBUTE_NORMAL = 0x80;
        IntPtr h = CreateFile(LongPath(path), GENERIC_WRITE, SHARE_ALL, IntPtr.Zero, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw LastError("create file");
        CloseHandle(h);
    }

    // Delete removes a file or an empty directory. A missing one is FileNotFoundException.
    public static void Delete(string path, bool isDir)
    {
        if (isDir ? RemoveDirectoryW(LongPath(path)) : DeleteFileW(LongPath(path))) return;
        int err = Marshal.GetLastPInvokeError();
        if (err is 2 or 3) throw new FileNotFoundException($"delete: {new Win32Exception(err).Message}", path);
        throw Error(err, "delete");
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandleEx(IntPtr h, int cls, byte[] buf, uint len);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandleEx(IntPtr h, int cls, out AttributeTag info, uint len);

    public const uint AttrDirectory = 0x10, AttrReparsePoint = 0x400;

    // ListDir enumerates one directory through a handle opened with backup intent, so the listing
    // gets the same access the descriptor reads do, as Set-SaclOnly's ListDir does. "." and ".."
    // are left out. Each entry is its name and FILE_ATTRIBUTE_* bits.
    public static List<(string Name, uint Attributes)> ListDir(string path)
    {
        const uint FILE_LIST_DIRECTORY = 0x1, SYNCHRONIZE = 0x00100000;
        const int FileFullDirectoryInfo = 14, ERROR_NO_MORE_FILES = 18;
        IntPtr h = CreateFile(LongPath(path), FILE_LIST_DIRECTORY | SYNCHRONIZE, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw LastError("open directory");
        var list = new List<(string, uint)>();
        try
        {
            var buf = new byte[64 * 1024];
            while (true)
            {
                if (!GetFileInformationByHandleEx(h, FileFullDirectoryInfo, buf, (uint)buf.Length))
                {
                    int err = Marshal.GetLastPInvokeError();
                    if (err == ERROR_NO_MORE_FILES) break;
                    throw Error(err, "list");
                }
                DirInfo.Parse(buf, buf.Length, list);
            }
        }
        finally { CloseHandle(h); }
        return list;
    }

    // Error names the step that failed and keeps the system's text for the code, which
    // Win32Exception(code, message) would otherwise replace: "open: Access is denied." The code
    // itself stays in NativeErrorCode.
    internal static Win32Exception Error(int code, string step) => new(code, $"{step}: {new Win32Exception(code).Message}");

    static Win32Exception LastError(string step) => Error(Marshal.GetLastPInvokeError(), step);

    // LongPath adds the \\?\ prefix so paths past MAX_PATH open; UNC paths become \\?\UNC\.
    public static string LongPath(string p)
    {
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) return p;
        var full = Path.GetFullPath(p);
        return full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;
    }
}

// DirInfo parses one GetFileInformationByHandleEx(FileFullDirectoryInfo) buffer. It is portable
// (no Win32) so the bounds checks are tested on Linux. The offsets and lengths come from the
// server, so each is checked before it is used: a malformed entry throws InvalidDataException
// naming the step, never an out-of-range read or an endless loop.
static class DirInfo
{
    // FILE_FULL_DIR_INFO: NextEntryOffset @0, FileAttributes @56, FileNameLength (bytes) @60,
    // FileName @68.
    public const int HeaderSize = 68;
    const int AttributesAt = 56, NameLengthAt = 60;

    // Parse appends each entry in buf[0..valid) to list, leaving out "." and "..". The entries are
    // a chain from offset 0: each NextEntryOffset must move past its own header and name, and not so
    // far that the next header would not fit in the buffer; 0 ends the chain.
    public static void Parse(byte[] buf, int valid, List<(string Name, uint Attributes)> list)
    {
        if (valid < 0 || valid > buf.Length)
            throw new InvalidDataException($"list: buffer length {valid} is outside 0..{buf.Length}");
        int off = 0;
        while (true)
        {
            if (valid - off < HeaderSize)
                throw Malformed(off, $"its header needs {HeaderSize} bytes, {valid - off} remain");
            int next = BitConverter.ToInt32(buf, off);
            uint attrs = BitConverter.ToUInt32(buf, off + AttributesAt);
            int nameLen = BitConverter.ToInt32(buf, off + NameLengthAt);
            if (nameLen < 0 || nameLen % 2 != 0)
                throw Malformed(off, $"name length {nameLen} is not a non-negative even byte count");
            if (nameLen > valid - off - HeaderSize)
                throw Malformed(off, $"name length {nameLen} runs past the {valid}-byte buffer");
            if (next != 0 && (next < HeaderSize + nameLen || next > valid - off - HeaderSize))
                throw Malformed(off, $"next entry offset {next} does not move past this entry to a whole header inside the {valid}-byte buffer");
            string name = System.Text.Encoding.Unicode.GetString(buf, off + HeaderSize, nameLen);
            if (name is not ("." or "..")) list.Add((name, attrs));
            if (next == 0) return;
            off += next;
        }
    }

    static InvalidDataException Malformed(int off, string why) => new($"list: malformed directory entry at offset {off}: {why}");
}
