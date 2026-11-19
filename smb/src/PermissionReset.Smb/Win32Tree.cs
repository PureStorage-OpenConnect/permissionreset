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

    public byte[] Read(string rel, bool withSacl) => Win32Security.ReadDescriptor(Full(rel), withSacl);

    public void Write(string rel, uint securityInformation, byte[] descriptor) =>
        Win32Security.WriteDescriptor(Full(rel), securityInformation, descriptor);

    public void CreateDirectory(string rel) => Win32Security.CreateDirectory(Full(rel));
    public void CreateFile(string rel) => Win32Security.CreateNewFile(Full(rel));
    public void Delete(string rel, bool isDir) => Win32Security.Delete(Full(rel), isDir);

    // Resolve looks a name (name@domain or DOMAIN\name) up on this host, as Set-SaclOnly does.
    public static string? Resolve(string name)
    {
        try { return new NTAccount(name).Translate(typeof(SecurityIdentifier)).Value; }
        catch (IdentityNotMappedException) { return null; }
    }
}
