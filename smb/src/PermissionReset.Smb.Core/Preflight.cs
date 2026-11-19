namespace PermissionReset.Smb.Core;

// ProbeResult says whether the preflight passed, and what it did, in one line each way.
public sealed record ProbeResult(bool Passed, string Detail, string Probe);

// Preflight is the disposable probe that runs before anything in the tree is written
// (smb/DESIGN-write-path.md, section 4, step 2). It makes a directory with one subdirectory and
// one file, writes the root's desired explicit ACEs to the directory as a protected DACL, and a
// placeholder audit ACE as its SACL, then checks:
//   - the directory reads back exactly what was written, owner and group unchanged (G2 on known
//     data);
//   - the SACL was kept: the identity can read and write audit ACEs on this array (on FlashArray,
//     the audit bypass), which every G2 read in the walk needs;
//   - its two children, created before the write, now hold exactly Inheritance.Inherit of those
//     ACEs as their inherited part (G1 on known data, and F3's propagation);
//   - an unprotected write to the subdirectory, one explicit ACE followed by its inherited part,
//     reads back exactly and with D:AI set (G2 on the write most of the walk makes, F5).
// The probe is removed whatever happened; a probe that cannot be removed fails the preflight.
public static class Preflight
{
    public const string Prefix = ".permissionreset-smb-probe-";

    // The placeholder audit ACE: Everyone, success and failure, FILE_READ_DATA. It lives only on the
    // probe, which is removed before the walk.
    public static readonly Ace PlaceholderAudit = new(AceTypes.Audit, AceFlags.SuccessfulAccess | AceFlags.FailedAccess, 0x1, "S-1-1-0");

    // Cleanup's DACL: OWNER RIGHTS full control, inherited by the children, so the identity that
    // created the probe can delete it whatever the root's ACEs grant.
    static readonly Ace OwnerFull = new(AceTypes.Allow, AceFlags.ObjectInherit | AceFlags.ContainerInherit, 0x1f01ff, "S-1-3-4");

    // The explicit part of the unprotected probe write: OWNER RIGHTS read and execute, inheritable.
    // It grants the probe's creator nothing it lacks, and the probe is removed before the walk.
    static readonly Ace UnprotectedExplicit = new(AceTypes.Allow, AceFlags.ObjectInherit | AceFlags.ContainerInherit, 0x1200a9, "S-1-3-4");

    // Run probes under parent ("" is the probe tree's root). rootAces is the root's desired DACL;
    // its ID flags are cleared, since the probe holds them as its own explicit ACEs.
    public static ProbeResult Run(IWritableTree t, string parent, IReadOnlyList<Ace> rootAces, string? name = null)
    {
        name ??= Prefix + Guid.NewGuid().ToString("N")[..12];
        var dir = parent.Length == 0 ? name : parent + "/" + name;
        string sub = dir + "/d", file = dir + "/f";
        var aces = rootAces.Select(a => a with { Flags = (byte)(a.Flags & ~AceFlags.Inherited) }).ToList();
        bool made = false;
        string? result = null;
        try
        {
            t.CreateDirectory(dir);
            made = true;
            t.CreateDirectory(sub);
            t.CreateFile(file);
            result = Check(t, dir, sub, file, aces);
        }
        catch (Exception e) { result = e.Message; }
        finally
        {
            if (made)
            {
                var left = Remove(t, dir, sub, file);
                if (left is not null) result = result is null ? left : $"{result}; and {left}";
            }
        }
        if (result is not null) return new ProbeResult(false, result, dir);
        var note = Inheritance.Inherit(aces, false).Count + Inheritance.Inherit(aces, true).Count == 0
            ? " (the root's DACL passes nothing down, so the children's check was only that nothing was inherited)"
            : "";
        return new ProbeResult(true,
            $"preflight passed: probe {dir} took the root's DACL and an audit ACE, read back exactly, its children inherited what the walk computes{note}, an unprotected explicit+inherited write read back exactly, and the probe was removed",
            dir);
    }

    static string? Check(IWritableTree t, string dir, string sub, string file, List<Ace> aces)
    {
        var before = Descriptor.Decode(t.Read(dir, withSacl: true));
        var protectedDacl = new Desired(Form.Protected, aces, true);
        t.Write(dir, SecurityInformation.Dacl | SecurityInformation.ProtectedDacl,
            DescriptorBuilder.Build((ushort)(Control.DaclProtected | (before.Control & Control.DaclAutoInherited)), null, null, null, aces));
        t.Write(dir, SecurityInformation.Sacl | SecurityInformation.ProtectedSacl,
            DescriptorBuilder.Build((ushort)(Control.SaclProtected | (before.Control & Control.SaclAutoInherited)), null, null, [PlaceholderAudit], null));

        var after = Descriptor.Decode(t.Read(dir, withSacl: true));
        var d = protectedDacl.Matches(after.Dacl, (after.Control & Control.DaclProtected) != 0);
        if (d is not null) return $"the probe's DACL read back differs from what was written: {d}";
        if (after.Owner != before.Owner || after.Group != before.Group) return "the probe's owner or group changed across a DACL-only write";
        var sacl = after.Sacl?.Aces ?? [];
        if (sacl.Count != 1 || Ace.FromView(sacl[0]) != PlaceholderAudit)
            return "the array accepted the probe's audit ACE but did not keep it; the identity lacks SeSecurityPrivilege on the array (on FlashArray, the audit bypass)";

        foreach (var (rel, isDir) in new[] { (sub, true), (file, false) })
        {
            var c = Descriptor.Decode(t.Read(rel, withSacl: false));
            if ((c.Control & Control.DaclProtected) != 0) return $"probe child {rel} is protected; it should inherit";
            var got = (c.Dacl?.Aces ?? []).Select(Ace.FromView).Where(a => a is null || a.Value.Inherited).ToList();
            var wantInh = Inheritance.Inherit(aces, isDir);
            if (got.Count != wantInh.Count || got.Zip(wantInh).Any(p => p.First != p.Second))
                return $"probe child {rel} inherited [{string.Join(", ", got.Select(a => a?.ToString() ?? "unmodelled"))}], " +
                    $"the walk computes [{string.Join(", ", wantInh)}]: the inheritance function disagrees with this array";
        }
        return CheckUnprotected(t, sub, aces);
    }

    // CheckUnprotected is the write most of the walk makes, on known data: an unprotected DACL with
    // an explicit part and an ID part, written to the probe's subdirectory the way Checker.Write
    // writes it (UNPROTECTED_DACL_SECURITY_INFORMATION, D:AI per F5) and read back with G2's own
    // comparison. An array that drops, reorders or re-derives the ID ACEs of such a write, or
    // handles D:AI differently, refuses the preflight before anything in the tree is written.
    static string? CheckUnprotected(IWritableTree t, string sub, List<Ace> aces)
    {
        var want = new Desired(Form.ExplicitPlusInherits, [UnprotectedExplicit, .. Inheritance.Inherit(aces, true)], false);
        var before = Descriptor.Decode(t.Read(sub, withSacl: true));
        t.Write(sub, SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl,
            DescriptorBuilder.Build(Control.DaclAutoInherited, null, null, null, want.Aces));
        var after = Descriptor.Decode(t.Read(sub, withSacl: true));
        var d = Checker.ReadbackDiff(want, before, after, before.Owner, before.Group, daclWritten: true);
        return d is null ? null : $"probe child {sub}, written unprotected with explicit and inherited ACEs: {d}";
    }

    // Remove makes the probe deletable by its owner, then deletes children first. Null when the
    // probe is gone, else what was left behind. The cleanup DACL is read back like every other
    // write (G2 on the probe); if it failed or did not read back, the deletes are still tried, and
    // when they leave something, the report leads with the cleanup write, since that is the likely
    // cause. A probe that is gone passes whatever the cleanup write did.
    static string? Remove(IWritableTree t, string dir, string sub, string file)
    {
        string? cleanup = null;
        try
        {
            t.Write(dir, SecurityInformation.Dacl | SecurityInformation.ProtectedDacl,
                DescriptorBuilder.Build(Control.DaclProtected, null, null, null, [OwnerFull]));
            var back = Descriptor.Decode(t.Read(dir, withSacl: false));
            var d = new Desired(Form.Protected, [OwnerFull], true).Matches(back.Dacl, (back.Control & Control.DaclProtected) != 0);
            if (d is not null) cleanup = $"the cleanup DACL on {dir} read back differently: {d}";
        }
        catch (Exception e) when (e is not OutOfMemoryException) { cleanup = $"the cleanup DACL on {dir} failed: {e.Message}"; }
        var left = new List<string>();
        foreach (var (rel, isDir) in new[] { (file, false), (sub, true), (dir, true) })
        {
            try { t.Delete(rel, isDir); }
            catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException) { }
            catch (Exception e) { left.Add($"{rel} ({e.Message})"); }
        }
        if (left.Count == 0) return null;
        var why = $"the probe could not be removed: {string.Join(", ", left)}";
        return cleanup is null ? why : $"{cleanup}; {why}";
    }
}
