using System.Runtime.Versioning;
using System.Security.Principal;
using PermissionReset.Smb.Core;

namespace PermissionReset.Smb;

// Win32Tree is the Checker's view of a tree on Windows: backup-intent listing and descriptor
// reads (DACL, owner and group; phase 1 does not read the SACL), never following a reparse point.
[SupportedOSPlatform("windows")]
sealed class Win32Tree(string root) : ITree
{
    string Full(string rel) => rel.Length == 0 ? root : Path.Combine(root, rel.Replace('/', '\\'));

    public IReadOnlyList<TreeEntry> List(string rel) =>
        Win32Security.ListDir(Full(rel)).Select(e => new TreeEntry(e.Name,
            (e.Attributes & Win32Security.AttrDirectory) != 0,
            (e.Attributes & Win32Security.AttrReparsePoint) != 0)).ToList();

    // Read carries the opened handle's attributes with the descriptor, so the checker can skip an
    // object whose type changed between the listing and this open (smb/DESIGN-write-path.md, 5.3).
    public TreeObject Read(string rel)
    {
        var r = Win32Security.ReadDescriptor(Full(rel), withSacl: false);
        return new TreeObject(r.Descriptor,
            (r.Attributes & Win32Security.AttrDirectory) != 0,
            (r.Attributes & Win32Security.AttrReparsePoint) != 0);
    }

    // Resolve looks a name (name@domain or DOMAIN\name) up on this host, as Set-SaclOnly does. Any
    // Translate failure — an unmapped name or a domain/trust error — is an unresolved principal:
    // the caller refuses the run and names it.
    public static string? Resolve(string name)
    {
        try { return new NTAccount(name).Translate(typeof(SecurityIdentifier)).Value; }
        catch { return null; }
    }
}
