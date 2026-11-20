using System.Runtime.Versioning;
using System.Security.Principal;
using PermissionReset.Smb.Core;

namespace PermissionReset.Smb;

// Win32Tree is the walk's view of a tree on Windows: backup-intent listing, descriptor reads and
// writes, never following a reparse point, and the probe's create and delete calls.
[SupportedOSPlatform("windows")]
sealed class Win32Tree(string root) : IWritableTree
{
    string Full(string rel) => rel.Length == 0 ? root : Path.Combine(root, rel.Replace('/', '\\'));

    public IReadOnlyList<TreeEntry> List(string rel) =>
        Win32Security.ListDir(Full(rel)).Select(e => new TreeEntry(e.Name,
            (e.Attributes & Win32Security.AttrDirectory) != 0,
            (e.Attributes & Win32Security.AttrReparsePoint) != 0)).ToList();

    // Read carries the opened handle's attributes with the descriptor, so the checker can skip an
    // object whose type changed between the listing and this open (smb/DESIGN-write-path.md, 5.3).
    public TreeObject Read(string rel, bool withSacl)
    {
        var r = Win32Security.ReadDescriptor(Full(rel), withSacl);
        return new TreeObject(r.Descriptor,
            (r.Attributes & Win32Security.AttrDirectory) != 0,
            (r.Attributes & Win32Security.AttrReparsePoint) != 0);
    }

    public void Write(string rel, uint securityInformation, byte[] descriptor) =>
        Win32Security.WriteDescriptor(Full(rel), securityInformation, descriptor);

    public void CreateDirectory(string rel) => Win32Security.CreateDirectory(Full(rel));
    public void CreateFile(string rel) => Win32Security.CreateNewFile(Full(rel));
    public void Delete(string rel, bool isDir) => Win32Security.Delete(Full(rel), isDir);

    // Resolve looks a name (name@domain or DOMAIN\name) up on this host, as Set-SaclOnly does. Any
    // Translate failure — an unmapped name or a domain/trust error — is an unresolved principal:
    // the caller refuses the run and names it.
    public static string? Resolve(string name)
    {
        try { return new NTAccount(name).Translate(typeof(SecurityIdentifier)).Value; }
        catch { return null; }
    }
}
