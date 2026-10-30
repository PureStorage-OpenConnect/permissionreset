// SaclOnly engine for Set-SaclOnly.ps1. Loaded with Add-Type, so it stays C# 5
// (Windows PowerShell 5.1 compiles it with the .NET Framework compiler).
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Threading;

// GoGlob is Go's path.Match: the same grammar permissionreset' spec matching uses (filepath.Match on Linux,
// where '/' is the only separator and '\' escapes). It is case-sensitive, as the NFS run is.
// A malformed pattern matches nothing; build-spec has already refused one at spec load.
public static class GoGlob {
    class BadPattern : Exception { }

    public static bool Match(string pattern, string name) {
        try { return MatchOrThrow(pattern, name); }
        catch (BadPattern) { return false; }
    }

    static bool MatchOrThrow(string pattern, string name) {
        while (pattern.Length > 0) {
            bool star; string chunk;
            ScanChunk(ref pattern, out star, out chunk);
            if (star && chunk.Length == 0) return name.IndexOf('/') < 0;
            string t; bool ok = MatchChunk(chunk, name, out t);
            if (ok && (t.Length == 0 || pattern.Length > 0)) { name = t; continue; }
            if (star) {
                bool advanced = false;
                for (int i = 0; i < name.Length && name[i] != '/'; i++) {
                    if (MatchChunk(chunk, name.Substring(i + 1), out t)) {
                        if (pattern.Length == 0 && t.Length > 0) continue;
                        name = t; advanced = true; break;
                    }
                }
                if (advanced) continue;
            }
            return false;
        }
        return name.Length == 0;
    }

    static void ScanChunk(ref string pattern, out bool star, out string chunk) {
        star = false;
        while (pattern.Length > 0 && pattern[0] == '*') { pattern = pattern.Substring(1); star = true; }
        bool inrange = false;
        int i;
        for (i = 0; i < pattern.Length; i++) {
            char c = pattern[i];
            if (c == '\\') { if (i + 1 < pattern.Length) i++; }
            else if (c == '[') inrange = true;
            else if (c == ']') inrange = false;
            else if (c == '*' && !inrange) break;
        }
        chunk = pattern.Substring(0, i);
        pattern = pattern.Substring(i);
    }

    // One code point (a surrogate pair counts as one, as a Go rune does).
    static int Rune(string s, int at, out int width) {
        if (char.IsHighSurrogate(s[at]) && at + 1 < s.Length && char.IsLowSurrogate(s[at + 1])) {
            width = 2; return char.ConvertToUtf32(s[at], s[at + 1]);
        }
        width = 1; return s[at];
    }

    static bool MatchChunk(string chunk, string s, out string rest) {
        bool failed = false;
        int ci = 0, si = 0;
        while (ci < chunk.Length) {
            if (!failed && si >= s.Length) failed = true;
            char c = chunk[ci];
            if (c == '[') {
                int r = 0, w;
                if (!failed) { r = Rune(s, si, out w); si += w; }
                ci++;
                bool negated = false;
                if (ci < chunk.Length && chunk[ci] == '^') { negated = true; ci++; }
                bool match = false; int nrange = 0;
                while (true) {
                    if (ci < chunk.Length && chunk[ci] == ']' && nrange > 0) { ci++; break; }
                    int lo = GetEsc(chunk, ref ci), hi = lo;
                    if (chunk[ci] == '-') { ci++; hi = GetEsc(chunk, ref ci); }
                    if (lo <= r && r <= hi) match = true;
                    nrange++;
                }
                if (match == negated) failed = true;
            } else if (c == '?') {
                if (!failed) {
                    if (s[si] == '/') failed = true;
                    int w; Rune(s, si, out w); si += w;
                }
                ci++;
            } else {
                if (c == '\\') { ci++; if (ci >= chunk.Length) throw new BadPattern(); }
                if (!failed) { if (chunk[ci] != s[si]) failed = true; si++; }
                ci++;
            }
        }
        rest = failed ? "" : s.Substring(si);
        return !failed;
    }

    static int GetEsc(string chunk, ref int ci) {
        if (ci >= chunk.Length || chunk[ci] == '-' || chunk[ci] == ']') throw new BadPattern();
        if (chunk[ci] == '\\') { ci++; if (ci >= chunk.Length) throw new BadPattern(); }
        int w; int r = Rune(chunk, ci, out w);
        ci += w;
        if (ci >= chunk.Length) throw new BadPattern();
        return r;
    }
}

// SaclRules is permissionreset' rule selection: Spec.MatchRule (first rule whose type and base-name
// pattern match, else the default) and Excluder.Match (a pattern without '/' against the base
// name, one with '/' against the path relative to the root; the root is never excluded).
public class SaclRules {
    public const int AnyType = 0, FileType = 1, DirType = 2;
    public const int Excluded = -2, Default = -1;

    readonly List<int> types = new List<int>();
    readonly List<string> patterns = new List<string>();
    readonly List<string> baseGlobs = new List<string>();
    readonly List<string> pathGlobs = new List<string>();

    public void AddRule(int type, string pattern) { types.Add(type); patterns.Add(pattern ?? ""); }
    public void AddExcludeBase(string glob) { baseGlobs.Add(glob); }
    public void AddExcludePath(string glob) { pathGlobs.Add(glob); }
    public int Count { get { return types.Count; } }

    // rel is the path below the root with '/' separators, "" for the root itself.
    public bool IsExcluded(string rel) {
        if (string.IsNullOrEmpty(rel)) return false;
        string b = BaseOf(rel);
        foreach (var g in baseGlobs) if (GoGlob.Match(g, b)) return true;
        foreach (var g in pathGlobs) if (GoGlob.Match(g, rel)) return true;
        return false;
    }

    // The index of the first matching rule, or Default.
    public int MatchRule(string baseName, bool isDir) {
        for (int i = 0; i < types.Count; i++) {
            if (types[i] == DirType && !isDir) continue;
            if (types[i] == FileType && isDir) continue;
            if (patterns[i].Length > 0 && !GoGlob.Match(patterns[i], baseName)) continue;
            return i;
        }
        return Default;
    }

    // Excluded, or the rule index (Default when none matched).
    public int Classify(string rel, string baseName, bool isDir) {
        if (IsExcluded(rel)) return Excluded;
        return MatchRule(baseName, isDir);
    }

    public static string BaseOf(string rel) {
        int i = rel.LastIndexOf('/');
        return i < 0 ? rel : rel.Substring(i + 1);
    }
}

// One action: the SACL to write on directories and on files that select it, or leave them.
public class SaclAction {
    public string Label;
    public bool Leave;                    // the rule writes no SACL: objects it selects are not touched
    public string DirSddl, FileSddl;      // "S:AI(...)": the SACL part of a security descriptor
    internal string DirKey, FileKey;
    internal byte[] DirSD, FileSD;
}

public class SaclRun {
    // Unprotected counts accepted D:P-only changes; NotStarted, objects read after a stop or cancel
    // and so never written. SetStopped counts objects whose SACL was written but whose write also
    // changed something the policy refuses: each is an error and stops the run, but its SACL is set,
    // so Applied + SetStopped is every SACL this run wrote.
    public long Seen, Applied, Would, Skipped, Errors, Reparse, Unprotected, Excluded, Left, NotStarted, SetStopped;
    public string Stopped;   // non-null: the preflight failed or a DACL changed, the run was stopped
    public string Preflight; // what the root preflight proved
}

public static class SaclOnly {
    const uint OWNER = 1, GROUP = 2, DACL = 4, SACL = 8;
    const uint READ_CONTROL = 0x00020000, ACCESS_SYSTEM_SECURITY = 0x01000000;
    const uint FILE_LIST_DIRECTORY = 0x1, SYNCHRONIZE = 0x00100000;
    const uint SHARE_ALL = 7, OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const int FileFullDirectoryInfo = 14, ERROR_NO_MORE_FILES = 18, ERROR_INSUFFICIENT_BUFFER = 122;
    const uint ATTR_DIRECTORY = 0x10, ATTR_REPARSE = 0x400;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetKernelObjectSecurity(IntPtr h, uint info, byte[] sd, uint len, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetKernelObjectSecurity(IntPtr h, uint info, byte[] sd);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(IntPtr h, int cls, byte[] buf, uint len);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(IntPtr h, out BY_HANDLE_FILE_INFORMATION info);
    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION {
        public uint Attributes; public long Created, Accessed, Written;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attr; }
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LookupPrivilegeValueW(string system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, uint len, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    static readonly IntPtr INVALID = new IntPtr(-1);

    // \\?\UNC\ form, so a deep tree is not cut off at MAX_PATH.
    public static string Long(string p) {
        if (p.StartsWith(@"\\?\")) return p;
        if (p.StartsWith(@"\\")) return @"\\?\UNC\" + p.Substring(2);
        return @"\\?\" + p;
    }
    static string Short(string p) {
        if (p.StartsWith(@"\\?\UNC\")) return @"\\" + p.Substring(8);
        if (p.StartsWith(@"\\?\")) return p.Substring(4);
        return p;
    }

    // EnablePrivilege turns on a privilege the token holds, and throws when it does not hold it.
    public static void EnablePrivilege(string name) { SetPrivilege(name, true); }
    // DisablePrivilege turns a privilege off. A child process starts with its parent's enabled
    // privileges, so -NoBackup cannot rely on SeBackupPrivilege being off already.
    public static void DisablePrivilege(string name) { SetPrivilege(name, false); }
    static void SetPrivilege(string name, bool enable) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28 /* ADJUST_PRIVILEGES|QUERY */, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            var tp = new TOKEN_PRIVILEGES();
            tp.Count = 1; tp.Attr = enable ? 2u : 0u; /* SE_PRIVILEGE_ENABLED */
            if (!LookupPrivilegeValueW(null, name, out tp.Luid))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            if (err == 1300 && !enable) return;   // not held is as good as disabled
            if (err != 0) // 1300 = ERROR_NOT_ALL_ASSIGNED: the token does not hold it
                throw new Win32Exception(err, name + " is not held; run elevated as an administrator");
        } finally { CloseHandle(token); }
    }

    // Fail keeps the system's text for err ("Access is denied.", "A required privilege is not held
    // by the client."): a Win32Exception given a message of its own drops it.
    static Win32Exception Fail(int err, string what) {
        return new Win32Exception(err, what + ": " + new Win32Exception(err).Message);
    }

    // Every open asks for backup intent (FILE_FLAG_BACKUP_SEMANTICS). With SeBackupPrivilege
    // enabled, that grants READ_CONTROL and FILE_LIST_DIRECTORY whatever the DACL says, so a
    // directory that denies Administrators is still read and listed. Without the privilege the
    // flag only allows opening a directory, and the DACL decides. The SACL itself needs
    // ACCESS_SYSTEM_SECURITY, which SeSecurityPrivilege grants for both reading and writing it:
    // no write to the DACL, owner or data is ever requested, so SeRestorePrivilege is not used.
    // FILE_FLAG_OPEN_REPARSE_POINT: a reparse point is opened as itself, never followed.
    static IntPtr Open(string path, uint access) {
        IntPtr h = CreateFileW(path, access, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == INVALID) throw Fail(Marshal.GetLastWin32Error(), "open " + Short(path));
        return h;
    }

    static RawSecurityDescriptor Get(IntPtr h, string path) {
        uint needed;
        var buf = new byte[512];
        for (int tries = 0; tries < 4; tries++) {
            if (GetKernelObjectSecurity(h, OWNER | GROUP | DACL | SACL, buf, (uint)buf.Length, out needed))
                return new RawSecurityDescriptor(buf, 0);
            int err = Marshal.GetLastWin32Error();
            if (err != ERROR_INSUFFICIENT_BUFFER || needed == 0)
                throw Fail(err, "read security of " + Short(path));
            buf = new byte[needed];
        }
        throw Fail(ERROR_INSUFFICIENT_BUFFER, "read security of " + Short(path));
    }
    // SetSacl writes want's audit ACEs with the object's own SACL control flags: protected (S:P)
    // and auto-inherited (S:AI) are copied from cur, so only the ACEs change. The protection is
    // also passed as PROTECTED_/UNPROTECTED_SACL_SECURITY_INFORMATION, which is what the system
    // (and the array, over SMB) reads it from.
    const ControlFlags SaclControl = ControlFlags.SystemAclProtected | ControlFlags.SystemAclAutoInherited;
    const uint PROTECTED_SACL = 0x40000000, UNPROTECTED_SACL = 0x10000000;
    static void SetSacl(IntPtr h, string path, byte[] want, RawSecurityDescriptor cur) {
        var sd = new RawSecurityDescriptor(want, 0);
        sd.SetFlags((sd.ControlFlags & ~SaclControl) | (cur.ControlFlags & SaclControl));
        var buf = new byte[sd.BinaryLength];
        sd.GetBinaryForm(buf, 0);
        bool p = (cur.ControlFlags & ControlFlags.SystemAclProtected) != 0;
        if (!SetKernelObjectSecurity(h, SACL | (p ? PROTECTED_SACL : UNPROTECTED_SACL), buf))
            throw Fail(Marshal.GetLastWin32Error(), "write SACL of " + Short(path));
    }

    // One open; owner, group, DACL and SACL in one read.
    public static RawSecurityDescriptor GetAll(string path) {
        string p = Long(path);
        IntPtr h = Open(p, READ_CONTROL | ACCESS_SYSTEM_SECURITY);
        try { return Get(h, p); } finally { CloseHandle(h); }
    }
    public static bool IsDirectory(string path) {
        IntPtr h = Open(Long(path), 0);
        try {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) throw Fail(Marshal.GetLastWin32Error(), "stat " + path);
            return (info.Attributes & ATTR_DIRECTORY) != 0;
        } finally { CloseHandle(h); }
    }

    static string OGD(RawSecurityDescriptor sd) {
        return sd.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
    }

    // What a SACL write changed besides the audit ACEs, worst first. FlashBlade clears D:P on an SMB
    // SACL write to an object whose ACL was last written over NFS; that alone is DaclUnprotected.
    public const string Unchanged = "", DaclUnprotected = "dacl-unprotected", OwnerChanged = "owner-changed",
        GroupChanged = "group-changed", DaclChanged = "dacl-changed", SaclProtectionChanged = "sacl-protection-changed";
    public static string Diff(RawSecurityDescriptor before, RawSecurityDescriptor after) {
        if (before.GetSddlForm(AccessControlSections.Owner) != after.GetSddlForm(AccessControlSections.Owner)) return OwnerChanged;
        if (before.GetSddlForm(AccessControlSections.Group) != after.GetSddlForm(AccessControlSections.Group)) return GroupChanged;
        const ControlFlags P = ControlFlags.DiscretionaryAclProtected;
        // The ACEs (type, flags, mask, SID, order) and every DACL control flag but P.
        var b = new byte[after.BinaryLength];
        after.GetBinaryForm(b, 0);
        var restored = new RawSecurityDescriptor(b, 0);
        restored.SetFlags((restored.ControlFlags & ~P) | (before.ControlFlags & P));
        if (OGD(restored) != OGD(before)) return DaclChanged;
        if (((before.ControlFlags ^ after.ControlFlags) & P) != 0)
            return (before.ControlFlags & P) != 0 ? DaclUnprotected : DaclChanged;   // gaining P is not the known drift
        // Only S:P: FlashBlade stores an S:AI write as S:, which changes nothing that is audited.
        if (((before.ControlFlags ^ after.ControlFlags) & ControlFlags.SystemAclProtected) != 0) return SaclProtectionChanged;
        return Unchanged;
    }
    public static string Diff(string beforeSddl, string afterSddl) {
        return Diff(new RawSecurityDescriptor(beforeSddl), new RawSecurityDescriptor(afterSddl));
    }

    // Policy: strict (the default) stops the run on any change Diff reports. Accepted lets exactly the
    // changes named in Accept through, each counted and logged; nothing else is ever accepted.
    public static readonly string[] Acceptable = { DaclUnprotected };
    public static bool Accepts(string[] accept, string change) {
        if (change == Unchanged) return true;
        if (Array.IndexOf(Acceptable, change) < 0 || accept == null) return false;
        return Array.IndexOf(accept, change) >= 0;
    }
    public static string Policy(string[] accept) {
        return accept == null || accept.Length == 0 ? "strict" : "accept " + string.Join(",", accept);
    }

    // KnownIncompatible is why a strict run cannot succeed on this array before anything is written,
    // or null. FlashBlade clears D:P on the SACL write, so a protected root would be the first
    // violation, and post-write detection cannot undo it.
    public static string KnownIncompatible(string array, string[] accept, RawSecurityDescriptor root) {
        if (Accepts(accept, DaclUnprotected)) return null;
        if (array != "FlashBlade") return null;
        if ((root.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0) return null;
        return "strict policy on FlashBlade with a protected root DACL (D:P): FlashBlade clears D:P on an SMB SACL " +
            "write to an object whose ACL was last written over NFS, and a strict run must not cause that. Pass " +
            "-Accept dacl-unprotected with -Log to accept and list every occurrence.";
    }
    public static string GetOGD(string path) { return OGD(GetAll(path)); }
    public static string GetSacl(string path) { return GetAll(path).GetSddlForm(AccessControlSections.Audit); }

    // The SACL's ACEs in order, as hex of each ACE's binary form (type, flags, mask, SID).
    // The SACL's control flags (AI, AR, P) are left out: FlashBlade stores S:AI(...) as S:(...),
    // and that does not change what is audited.
    static string SaclKey(RawSecurityDescriptor sd) {
        RawAcl acl = sd.SystemAcl;
        if (acl == null) return "";
        var sb = new StringBuilder();
        foreach (GenericAce a in acl) {
            var b = new byte[a.BinaryLength];
            a.GetBinaryForm(b, 0);
            sb.Append(BitConverter.ToString(b)).Append('|');
        }
        return sb.ToString();
    }
    static string SaclSddl(RawSecurityDescriptor sd) { return sd.GetSddlForm(AccessControlSections.Audit); }
    public static string Normalize(string saclSddl) {
        return new RawSecurityDescriptor(saclSddl).GetSddlForm(AccessControlSections.Audit);
    }
    static byte[] Binary(string sddl) {
        var sd = new RawSecurityDescriptor(sddl);
        var buf = new byte[sd.BinaryLength];
        sd.GetBinaryForm(buf, 0);
        return buf;
    }

    // ListDir enumerates one directory through a handle opened with backup intent, so the
    // listing gets the same access the security reads do. "." and ".." are left out.
    public struct Entry { public string Name; public uint Attributes; }
    public static List<Entry> ListDir(string dir) {
        string p = Long(dir);
        var list = new List<Entry>();
        IntPtr h = Open(p, FILE_LIST_DIRECTORY | SYNCHRONIZE);
        try {
            var buf = new byte[64 * 1024];
            while (true) {
                if (!GetFileInformationByHandleEx(h, FileFullDirectoryInfo, buf, (uint)buf.Length)) {
                    int err = Marshal.GetLastWin32Error();
                    if (err == ERROR_NO_MORE_FILES) break;
                    throw Fail(err, "list " + Short(p));
                }
                int off = 0;
                while (true) {
                    // FILE_FULL_DIR_INFO: NextEntryOffset @0, FileAttributes @56,
                    // FileNameLength (bytes) @60, FileName @68.
                    int next = BitConverter.ToInt32(buf, off);
                    uint attrs = BitConverter.ToUInt32(buf, off + 56);
                    int nameLen = BitConverter.ToInt32(buf, off + 60);
                    string name = Encoding.Unicode.GetString(buf, off + 68, nameLen);
                    if (name != "." && name != "..") {
                        var e = new Entry(); e.Name = name; e.Attributes = attrs;
                        list.Add(e);
                    }
                    if (next == 0) break;
                    off += next;
                }
            }
        } finally { CloseHandle(h); }
        return list;
    }

    // Shared state for one Run.
    static SaclRun R;
    static ConcurrentQueue<string> Q;
    static int Pending;          // directories queued or being worked on
    static volatile bool Stop;
    static StreamWriter LogW;
    static readonly object LogLock = new object();
    static SaclRules Rules;
    static SaclAction[] Actions;   // Actions[i] for rule i; Actions[Rules.Count] is the default
    static string RootLong;
    static bool DoApply, DoReadback;
    static string[] AcceptList;    // changes the operator accepted (-Accept); empty is strict
    static string ArrayKind;       // FlashArray, FlashBlade or Unknown (-Array)

    public static SaclRun Current { get { return R; } }

    // AfterSetForTest, when set, runs on each object right after its SACL write and before the
    // read-back. Only the tests set it, to make a write change what NTFS never changes on its own.
    public static Action<string> AfterSetForTest;

    static void Log(string path, string action, string detail) {
        if (LogW == null) return;
        string line = string.Format("\"{0}\",{1},\"{2}\"", Short(path).Replace("\"", "\"\""), action, (detail ?? "").Replace("\"", "\"\""));
        lock (LogLock) { LogW.WriteLine(line); }
    }

    // Rel is a path below the root in spec form: '/' separators, "" for the root.
    static string Rel(string longPath) {
        if (longPath.Length <= RootLong.Length) return "";
        return longPath.Substring(RootLong.Length).TrimStart('\\').Replace('\\', '/');
    }
    static string BaseName(string longPath) {
        string t = longPath.TrimEnd('\\');
        int i = t.LastIndexOf('\\');
        return i < 0 ? t : t.Substring(i + 1);
    }
    static SaclAction ActionFor(string longPath, bool isDir) {
        int i = Rules.MatchRule(BaseName(longPath), isDir);
        return Actions[i == SaclRules.Default ? Rules.Count : i];
    }

    // One handles one object. It returns null, or why the object failed or stopped the run.
    static string One(string path, bool isDir, bool readback) {
        Interlocked.Increment(ref R.Seen);
        SaclAction act = ActionFor(path, isDir);
        if (act.Leave) { Interlocked.Increment(ref R.Left); return null; }
        IntPtr h = IntPtr.Zero;
        try {
            string wantKey = isDir ? act.DirKey : act.FileKey;
            h = Open(path, READ_CONTROL | ACCESS_SYSTEM_SECURITY);
            var cur = Get(h, path);
            if (SaclKey(cur) == wantKey) { Interlocked.Increment(ref R.Skipped); return null; }
            if (!DoApply) {
                Interlocked.Increment(ref R.Would);
                Log(path, "would-set", act.Label + " " + (isDir ? act.DirSddl : act.FileSddl));
                return null;
            }

            // A stop or cancel schedules no further write; one already past this point finishes and is checked.
            if (Stop) { Interlocked.Increment(ref R.NotStarted); return null; }
            SetSacl(h, path, isDir ? act.DirSD : act.FileSD, cur);
            var hook = AfterSetForTest;
            if (hook != null) hook(path);
            var now = Get(h, path);                              // the control check and the SACL read-back
            string change = Diff(cur, now);
            string detail = "before=" + cur.GetSddlForm(AccessControlSections.All) + " after=" + now.GetSddlForm(AccessControlSections.All);
            if (change == DaclUnprotected && Accepts(AcceptList, change)) {
                Interlocked.Increment(ref R.Unprotected);
                Log(path, "dacl-unprotected", "accepted " + detail);
            } else if (change != Unchanged) {
                // Not success: the write is done and cannot be undone here, so stop the rest.
                Interlocked.Increment(ref R.Errors);
                Interlocked.Increment(ref R.SetStopped);
                Log(path, change, Policy(AcceptList) + " " + detail);
                lock (LogLock) {
                    if (R.Stopped == null)
                        R.Stopped = string.Format("{0} on {1} across the SACL write ({2} policy); no further writes were started.\n  {3}",
                            change, Short(path), Policy(AcceptList), detail);
                }
                Stop = true;
                return R.Stopped;
            }
            if (readback && SaclKey(now) != wantKey) {
                Interlocked.Increment(ref R.Errors);
                Log(path, "sacl-not-retained", SaclSddl(now));
                return "the array accepted the SACL write but did not keep it: read back " + SaclSddl(now);
            }
            Interlocked.Increment(ref R.Applied);
            return null;
        } catch (Exception e) {
            Interlocked.Increment(ref R.Errors);
            Log(path, "error", e.Message);
            return e.Message;
        } finally {
            if (h != IntPtr.Zero) CloseHandle(h);
        }
    }

    // RootPreflight handles the root on its own, before any worker starts: it is read and, under
    // apply, set and read back, whatever -NoReadback says. A root that cannot be read or set, or
    // whose SACL the array does not keep, means this identity lacks the privilege on the array (on
    // FlashArray, the audit bypass), and every other object would fail the same way. The run then
    // stops with nothing else touched. A root that already has its SACL proves the read and that
    // an earlier write was kept, but not that this identity can write; the walk's per-object
    // read-back still catches that.
    static bool RootPreflight() {
        SaclAction act = ActionFor(RootLong, true);
        if (DoApply && !act.Leave) {
            string incompat;
            try { incompat = KnownIncompatible(ArrayKind, AcceptList, GetAll(RootLong)); }
            catch (Exception) { incompat = null; }  // unreadable root: One() below reports it with the privilege guidance
            if (incompat != null) {
                R.Stopped = "preflight: " + incompat + "\n  No object was written.";
                return false;
            }
        }
        long skipped = R.Skipped;
        string why = One(RootLong, true, true);
        if (why != null) {
            if (R.Stopped == null)
                R.Stopped = string.Format("preflight: {0}\n  To read and set SACLs the running identity needs SeSecurityPrivilege " +
                    "on the array (on FlashArray, the audit bypass; Domain Admins alone is not enough) and, without backup " +
                    "intent (-NoBackup), read access to the root. No other object was touched.", why);
            return false;
        }
        if (act.Leave) R.Preflight = "not probed: the root's rule has no sacl: key";
        else if (R.Skipped != skipped) R.Preflight = "root read; it already has its SACL, so the write was not probed";
        else if (!DoApply) R.Preflight = "root read (dry run: the write is probed under -Apply)";
        else R.Preflight = "root set and read back";
        if (ArrayKind != "FlashArray" && ArrayKind != "FlashBlade")
            R.Preflight += "; array not named (-Array), so whether it keeps D:P across a SACL write is unknown: " +
                (Accepts(AcceptList, DaclUnprotected) ? "accepted changes are listed in -Log" : "the first object it changes stops the run");
        return true;
    }

    static void Worker() {
        while (!Stop) {
            string dir;
            if (!Q.TryDequeue(out dir)) {
                if (Volatile.Read(ref Pending) == 0) return;
                Thread.Sleep(1);
                continue;
            }
            try {
                if (dir != RootLong) One(dir, true, DoReadback);   // the preflight did the root
                Children(dir);
            } finally {
                Interlocked.Decrement(ref Pending);
            }
        }
    }

    static void Children(string dir) {
        List<Entry> entries;
        try {
            entries = ListDir(dir);
        } catch (Exception e) {
            Interlocked.Increment(ref R.Errors);
            Log(dir, "enumerate-error", e.Message);
            return;
        }
        foreach (var e in entries) {
            if (Stop) return;
            string p = dir.TrimEnd('\\') + "\\" + e.Name;
            // Excludes come first, as in the NFS walk: an excluded directory is pruned whole.
            if (Rules.IsExcluded(Rel(p))) {
                Interlocked.Increment(ref R.Excluded);
                Log(p, "excluded", "");
                continue;
            }
            if ((e.Attributes & ATTR_REPARSE) != 0) {
                Interlocked.Increment(ref R.Seen);
                Interlocked.Increment(ref R.Reparse);
                Log(p, "reparse-skipped", "");
                continue;
            }
            if ((e.Attributes & ATTR_DIRECTORY) != 0) {
                Interlocked.Increment(ref Pending);
                Q.Enqueue(p);
            } else {
                One(p, false, DoReadback);
            }
        }
    }

    // Prepare encodes each action's SACL once. Called by Start, and by tests.
    public static void Prepare(SaclAction a) {
        if (a.Leave) return;
        a.DirSddl = Normalize(a.DirSddl); a.FileSddl = Normalize(a.FileSddl);
        a.DirKey = SaclKey(new RawSecurityDescriptor(a.DirSddl)); a.FileKey = SaclKey(new RawSecurityDescriptor(a.FileSddl));
        a.DirSD = Binary(a.DirSddl); a.FileSD = Binary(a.FileSddl);
    }

    // Start runs the root preflight, then the walk on background threads, and returns once the
    // walk has started; poll Current and call Wait. A failed preflight sets Current.Stopped and
    // starts no walk. The root must be a directory. actions has one entry per rule, then the default.
    static Thread[] Threads;
    public static void Start(string root, SaclRules rules, SaclAction[] actions, bool apply, bool readback, int threads, string logPath,
            string[] accept, string array) {
        if (actions.Length != rules.Count + 1) throw new ArgumentException("need one action per rule plus the default");
        accept = accept ?? new string[0];
        foreach (var a in accept)
            if (Array.IndexOf(Acceptable, a) < 0) throw new ArgumentException("cannot accept '" + a + "'");
        if (apply && accept.Length > 0 && string.IsNullOrEmpty(logPath))
            throw new ArgumentException("-Accept needs -Log, so every accepted change is listed");
        AcceptList = accept; ArrayKind = array ?? "Unknown";
        foreach (var a in actions) Prepare(a);
        R = new SaclRun();
        Q = new ConcurrentQueue<string>();
        Stop = false;
        Rules = rules; Actions = actions;
        RootLong = Long(root);
        if (!RootLong.EndsWith(":\\")) RootLong = RootLong.TrimEnd('\\');   // \\?\C: is the volume, not its root
        DoApply = apply; DoReadback = readback;
        LogW = null;
        if (!string.IsNullOrEmpty(logPath)) { LogW = new StreamWriter(logPath, false); LogW.WriteLine("path,action,detail"); }
        if (!RootPreflight()) { Threads = new Thread[0]; return; }
        Pending = 1;
        Q.Enqueue(RootLong);
        Threads = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            Threads[i] = new Thread(Worker);
            Threads[i].IsBackground = true;
            Threads[i].Start();
        }
    }
    public static bool Wait(int ms) {
        var end = DateTime.UtcNow.AddMilliseconds(ms);
        foreach (var t in Threads) {
            int left = (int)Math.Max(0, (end - DateTime.UtcNow).TotalMilliseconds);
            if (!t.Join(left)) return false;
        }
        if (LogW != null) { LogW.Close(); LogW = null; }
        return true;
    }
    public static void Cancel() { Stop = true; }

    // Baseline: what Explorer's Properties > Security > Advanced > Auditing does with
    // "Replace all child object auditing entries with inheritable auditing entries from
    // this object". One call, single-threaded, run by Windows itself: it sets root's SACL
    // and resets every descendant's SACL to the inherited copy (TREE_SEC_INFO_RESET).
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern uint TreeSetNamedSecurityInfoW(string name, int objType, uint info, IntPtr owner, IntPtr group,
        IntPtr dacl, IntPtr sacl, uint action, IntPtr progress, int invoke, IntPtr args);
    public static void TreeSetSacl(string root, string saclSddl) {
        RawAcl acl = new RawSecurityDescriptor(saclSddl).SystemAcl;
        byte[] buf = new byte[acl.BinaryLength];
        acl.GetBinaryForm(buf, 0);
        IntPtr p = Marshal.AllocHGlobal(buf.Length);
        try {
            Marshal.Copy(buf, 0, p, buf.Length);
            // 1 = SE_FILE_OBJECT, 2 = TREE_SEC_INFO_RESET, 1 = ProgressInvokeNever
            uint rc = TreeSetNamedSecurityInfoW(root, 1, SACL, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, p, 2, IntPtr.Zero, 1, IntPtr.Zero);
            if (rc != 0) throw Fail((int)rc, "TreeSetNamedSecurityInfo " + root);
        } finally { Marshal.FreeHGlobal(p); }
    }
}
