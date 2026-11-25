namespace PermissionReset.Smb.Core;

// ProbeResult says whether the preflight passed, and what it did, in one line each way.
public sealed record ProbeResult(bool Passed, string Detail, string Probe);

// ProbeMode picks how much of a SACL plan's preflight runs (smb/DESIGN-sacl-write.md, section 6):
// Apply runs every step; Check runs steps 1, 2 and 7's cleanup — the audit-bypass proof on the
// probe before any tree read.
public enum ProbeMode { Apply, Check }

// ProbeEvent is one recorded probe operation (section 11, decision 18): a write (its before-image
// when there is one, and the read-back), a check read, or a removal. The base64 fields are the raw
// self-relative descriptor bytes. Kind is "write", "read" or "remove".
public sealed record ProbeEvent(string Kind, string Rel, string? BeforeB64, string? AfterB64, string? Detail)
{
    public static ProbeEvent Of(string kind, string rel, byte[]? before = null, byte[]? after = null, string? detail = null) =>
        new(kind, rel, before is null ? null : Convert.ToBase64String(before),
            after is null ? null : Convert.ToBase64String(after), detail);
}

// SaclProbe is what a plan with a sacl: rule adds to the preflight (design 6). RootSacl supplies
// the root's desired SACL and is invoked only after step 2 has proven the bypass: design 6 keeps
// every tree SACL read after that proof (PS-02; internal/auditproof is the NFS analogue). OnEvent
// receives every probe write, read-back and removal as an evidence event (section 11, decision 18).
public sealed record SaclProbe(Func<List<Ace>> RootSacl, ProbeMode Mode, Action<ProbeEvent>? OnEvent = null);

// Preflight is the disposable probe that runs before anything in the tree is written
// (smb/DESIGN-write-path.md, section 4, step 2) and, with a sacl: rule, before anything in the tree
// has its SACL read (smb/DESIGN-sacl-write.md, section 6). It makes a directory with one
// subdirectory and one file, writes the root's desired explicit ACEs to the directory as a
// protected DACL, and a placeholder audit ACE as its SACL, then checks:
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

    // Step 2's placeholder, made inheritable (SA|FA, OI|CI; design 6, step 2). S-1-1-0 again: the
    // probe is removed before the walk (section 11, decision 17).
    static readonly Ace PlaceholderInheritable = new(AceTypes.Audit,
        AceFlags.SuccessfulAccess | AceFlags.FailedAccess | AceFlags.ObjectInherit | AceFlags.ContainerInherit, 0x1, "S-1-1-0");

    // Step 5's explicit audit ACE, distinct from the placeholders so a left-over from an earlier
    // step is distinguishable from this write.
    static readonly Ace SaclExplicit = new(AceTypes.Audit, AceFlags.SuccessfulAccess | AceFlags.FailedAccess, 0x2, "S-1-1-0");

    // The K9 terminal writes of step 5 (design 6): an SA-only ACE, an FA-only ACE.
    static readonly Ace SaOnly = new(AceTypes.Audit, AceFlags.SuccessfulAccess, 0x4, "S-1-1-0");
    static readonly Ace FaOnly = new(AceTypes.Audit, AceFlags.FailedAccess, 0x8, "S-1-1-0");

    // Cleanup's DACL: OWNER RIGHTS full control, inherited by the children, so the identity that
    // created the probe can delete it whatever the root's ACEs grant.
    static readonly Ace OwnerFull = new(AceTypes.Allow, AceFlags.ObjectInherit | AceFlags.ContainerInherit, 0x1f01ff, "S-1-3-4");

    // The explicit part of the unprotected probe write: OWNER RIGHTS read and execute, inheritable.
    // It grants the probe's creator nothing it lacks, and the probe is removed before the walk.
    static readonly Ace UnprotectedExplicit = new(AceTypes.Allow, AceFlags.ObjectInherit | AceFlags.ContainerInherit, 0x1200a9, "S-1-3-4");

    // Run probes under parent ("" is the probe tree's root). rootAces is the root's desired DACL;
    // its ID flags are cleared, since the probe holds them as its own explicit ACEs.
    public static ProbeResult Run(IWritableTree t, string parent, IReadOnlyList<Ace> rootAces, string? name = null) =>
        Run(t, parent, rootAces, sacl: null, name);

    // Run probes under parent. sacl is null for a plan with no sacl: rule, which runs phase 2's
    // preflight unchanged (design 6: "a plan with no sacl_set rule runs phase 2's preflight
    // unchanged"); a plan with one runs design 6, in sacl's mode.
    public static ProbeResult Run(IWritableTree t, string parent, IReadOnlyList<Ace> rootAces, SaclProbe? sacl, string? name = null)
    {
        name ??= Prefix + Guid.NewGuid().ToString("N")[..12];
        var dir = parent.Length == 0 ? name : parent + "/" + name;
        string sub = dir + "/d", file = dir + "/f";
        var aces = rootAces.Select(a => a with { Flags = (byte)(a.Flags & ~AceFlags.Inherited) }).ToList();
        var sink = sacl?.OnEvent;
        bool made = false;
        string? result = null;
        try
        {
            t.CreateDirectory(dir);
            made = true;
            t.CreateDirectory(sub);
            t.CreateFile(file);
            result = sacl switch
            {
                null => Check(t, dir, sub, file, aces, sink),
                { Mode: ProbeMode.Check } => ProveBypass(t, dir, baseline: null, sink),
                var sp => CheckWithSacl(t, dir, sub, file, aces, sp, sink),
            };
        }
        catch (Exception e) { result = e.Message; }
        finally
        {
            if (made)
            {
                var left = Remove(t, dir, sub, file, sink);
                if (left is not null) result = result is null ? left : $"{result}; and {left}";
            }
        }
        if (result is not null) return new ProbeResult(false, result, dir);
        if (sacl is null) return Phase2Passed(dir, aces);
        return new ProbeResult(true, sacl.Mode == ProbeMode.Check
            ? $"preflight passed: probe {dir} kept a SACL write, so the audit bypass is proven on data that is not the tree's (K5; design 6, steps 1, 2 and 7's cleanup), and the probe was removed"
            : $"preflight passed: probe {dir} kept a SACL write, so the audit bypass is proven, the root's desired audit ACEs flowed to the probe's children exactly as the walk's inheritance computes, the S:AI rule held across protected, unprotected and AI-clear writes (K11; design 4.3), SA-only, FA-only and present-empty SACLs read back exactly (K9), owner, group and DACL stayed unchanged across the SACL steps (K2), the phase 2 DACL steps passed, and the probe was removed",
            dir);
    }

    static ProbeResult Phase2Passed(string dir, List<Ace> aces)
    {
        var note = Inheritance.Inherit(aces, false).Count + Inheritance.Inherit(aces, true).Count == 0
            ? " (the root's DACL passes nothing down, so the children's check was only that nothing was inherited)"
            : "";
        return new ProbeResult(true,
            $"preflight passed: probe {dir} took the root's DACL and an audit ACE, read back exactly, its children inherited what the walk computes{note}, an unprotected explicit+inherited write read back exactly, and the probe was removed",
            dir);
    }

    static string? Check(IWritableTree t, string dir, string sub, string file, List<Ace> aces, Action<ProbeEvent>? sink = null)
    {
        var rawBefore = t.Read(dir, withSacl: true).Descriptor;
        var before = Descriptor.Decode(rawBefore);
        var protectedDacl = new Desired(Form.Protected, aces, true);
        var daclWrite = DescriptorBuilder.Build((ushort)(Control.DaclProtected | (before.Control & Control.DaclAutoInherited)), null, null, null, aces);
        var saclWrite = DescriptorBuilder.Build((ushort)(Control.SaclProtected | (before.Control & Control.SaclAutoInherited)), null, null, [PlaceholderAudit], null);
        t.Write(dir, SecurityInformation.Dacl | SecurityInformation.ProtectedDacl, daclWrite);
        t.Write(dir, SecurityInformation.Sacl | SecurityInformation.ProtectedSacl, saclWrite);

        var rawAfter = t.Read(dir, withSacl: true).Descriptor;
        sink?.Invoke(ProbeEvent.Of("write", dir, rawBefore, rawAfter, "the phase 2 probe writes: the root's desired DACL protected, and the placeholder SACL"));
        var after = Descriptor.Decode(rawAfter);
        var d = protectedDacl.Matches(after.Dacl, (after.Control & Control.DaclProtected) != 0);
        if (d is not null) return $"the probe's DACL read back differs from what was written: {d}";
        if (after.Owner != before.Owner || after.Group != before.Group) return "the probe's owner or group changed across a DACL-only write";
        var sacl = after.Sacl?.Aces ?? [];
        if (sacl.Count != 1 || Ace.FromView(sacl[0]) != PlaceholderAudit)
            return "the array accepted the probe's audit ACE but did not keep it; the identity lacks SeSecurityPrivilege on the array (on FlashArray, the audit bypass)";

        foreach (var (rel, isDir) in new[] { (sub, true), (file, false) })
        {
            var rawChild = t.Read(rel, withSacl: false).Descriptor;
            sink?.Invoke(ProbeEvent.Of("read", rel, null, rawChild, "the phase 2 children's inheritance check"));
            var c = Descriptor.Decode(rawChild);
            if ((c.Control & Control.DaclProtected) != 0) return $"probe child {rel} is protected; it should inherit";
            var got = (c.Dacl?.Aces ?? []).Select(Ace.FromView).Where(a => a is null || a.Value.Inherited).ToList();
            var wantInh = Inheritance.Inherit(aces, isDir);
            if (got.Count != wantInh.Count || got.Zip(wantInh).Any(p => p.First != p.Second))
                return $"probe child {rel} inherited [{string.Join(", ", got.Select(a => a?.ToString() ?? "unmodelled"))}], " +
                    $"the walk computes [{string.Join(", ", wantInh)}]: the inheritance function disagrees with this array";
        }
        return CheckUnprotected(t, sub, aces, sink);
    }

    // CheckUnprotected is the write most of the walk makes, on known data: an unprotected DACL with
    // an explicit part and an ID part, written to the probe's subdirectory the way Checker.Write
    // writes it (UNPROTECTED_DACL_SECURITY_INFORMATION, D:AI per F5) and read back with G2's own
    // comparison. An array that drops, reorders or re-derives the ID ACEs of such a write, or
    // handles D:AI differently, refuses the preflight before anything in the tree is written.
    static string? CheckUnprotected(IWritableTree t, string sub, List<Ace> aces, Action<ProbeEvent>? sink = null)
    {
        var want = new Desired(Form.ExplicitPlusInherits, [UnprotectedExplicit, .. Inheritance.Inherit(aces, true)], false);
        var rawBefore = t.Read(sub, withSacl: true).Descriptor;
        var before = Descriptor.Decode(rawBefore);
        t.Write(sub, SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl,
            DescriptorBuilder.Build(Control.DaclAutoInherited, null, null, null, want.Aces));
        var rawAfter = t.Read(sub, withSacl: true).Descriptor;
        sink?.Invoke(ProbeEvent.Of("write", sub, rawBefore, rawAfter, "the phase 2 unprotected explicit+inherited DACL write"));
        var after = Descriptor.Decode(rawAfter);
        var d = Checker.ReadbackDiff(want, before, after, before.Owner, before.Group, daclWritten: true);
        return d is null ? null : $"probe child {sub}, written unprotected with explicit and inherited ACEs: {d}";
    }

    // Remove makes the probe deletable by its owner, then deletes children first. Null when the
    // probe is gone, else what was left behind. The cleanup DACL is read back like every other
    // write (G2 on the probe); if it failed or did not read back, the deletes are still tried, and
    // when they leave something, the report leads with the cleanup write, since that is the likely
    // cause. A probe that is gone passes whatever the cleanup write did.
    static string? Remove(IWritableTree t, string dir, string sub, string file, Action<ProbeEvent>? sink = null)
    {
        string? cleanup = null;
        try
        {
            t.Write(dir, SecurityInformation.Dacl | SecurityInformation.ProtectedDacl,
                DescriptorBuilder.Build(Control.DaclProtected, null, null, null, [OwnerFull]));
            var rawBack = t.Read(dir, withSacl: false).Descriptor;
            sink?.Invoke(ProbeEvent.Of("write", dir, null, rawBack, "the cleanup DACL, so the probe's owner can delete it"));
            var back = Descriptor.Decode(rawBack);
            var d = new Desired(Form.Protected, [OwnerFull], true).Matches(back.Dacl, (back.Control & Control.DaclProtected) != 0);
            if (d is not null) cleanup = $"the cleanup DACL on {dir} read back differently: {d}";
        }
        catch (Exception e) when (e is not OutOfMemoryException) { cleanup = $"the cleanup DACL on {dir} failed: {e.Message}"; }
        var left = new List<string>();
        foreach (var (rel, isDir) in new[] { (file, false), (sub, true), (dir, true) })
        {
            try { t.Delete(rel, isDir); sink?.Invoke(ProbeEvent.Of("remove", rel, detail: "removed")); }
            catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException) { }
            catch (Exception e)
            {
                sink?.Invoke(ProbeEvent.Of("remove", rel, detail: $"removal failed: {e.Message}"));
                left.Add($"{rel} ({e.Message})");
            }
        }
        if (left.Count == 0) return null;
        var why = $"the probe could not be removed: {string.Join(", ", left)}";
        return cleanup is null ? why : $"{cleanup}; {why}";
    }

    // ---- the SACL steps (smb/DESIGN-sacl-write.md, section 6) --------------------------------

    // CheckWithSacl is design 6's full SACL preflight (apply mode): step 2 proves the bypass on a
    // protected placeholder, step 3 obtains the root's desired SACL only now, step 4 writes it to
    // the probe dir unprotected and checks the children followed (G1 on known data), step 5
    // confirms K11's S:AI rule and K9 on known data, step 7 runs the phase 2 DACL steps. Step 6
    // runs throughout: the probe directory's, subdirectory's and file's owner, group, DACL bytes
    // and DACL control bits are compared with their baselines after steps 4 and 5 (K2: a SACL-only write leaves everything else alone). Error 5
    // on any SACL-bit access is layer 2's "no audit bypass" (design 5, K12).
    static string? CheckWithSacl(IWritableTree t, string dir, string sub, string file, List<Ace> aces, SaclProbe sp, Action<ProbeEvent>? sink)
    {
        // The baselines are read without the SACL: no SACL-bit access happens before the proof.
        // Step 6 covers the whole probe, since step 5 writes the subdirectory and the file.
        var probe = new[] { dir, sub, file };
        var baselines = new Dictionary<string, Descriptor>();
        byte[]? baselineRaw = null;
        foreach (var rel in probe)
        {
            var raw = t.Read(rel, withSacl: false).Descriptor;
            sink?.Invoke(ProbeEvent.Of("read", rel, null, raw, "the step 6 baseline: owner, group and DACL before the SACL steps"));
            baselines[rel] = Descriptor.Decode(raw);
            baselineRaw ??= raw;
        }
        string? Drift()
        {
            foreach (var rel in probe)
                if (OwnerDaclDrift(baselines[rel], Descriptor.Decode(t.Read(rel, withSacl: true).Descriptor)) is { } d)
                    return $"the probe's {d} on {rel} did not stay unchanged across the SACL steps (K2; design 6, step 6)";
            return null;
        }
        try
        {
            var why = ProveBypass(t, dir, baselineRaw, sink);
            if (why is not null) return why;

            // Step 3: only now, after the proof, the root's desired SACL.
            var rootWanted = sp.RootSacl().Select(a => a with { Flags = (byte)(a.Flags & ~AceFlags.Inherited) }).ToList();

            var (why4, passes) = CheckRootPropagation(t, dir, sub, file, rootWanted, sink);
            if (why4 is not null) return why4;
            if (Drift() is { } d1) return d1;

            var why5 = CheckSaclControl(t, sub, file, passes, sink);
            if (why5 is not null) return why5;
            if (Drift() is { } d2) return d2;
        }
        catch (Exception e) when (IsAccessDenied(e)) { return NoBypass(e); }

        // Step 7 (apply only): phase 2's DACL steps. Cleanup is Run's.
        return Check(t, dir, sub, file, aces, sink);
    }

    // ProveBypass is design 6's step 2 (and, on its own, check mode's proof): a protected SACL
    // with the EVERYONE@ placeholder audit ACE (SA|FA, OI|CI), written with SaclModel's control
    // word, and required back raw (K5). A refusal with access denied is layer 2, "no audit
    // bypass"; a placeholder that does not read back is layer 3.
    static string? ProveBypass(IWritableTree t, string dir, byte[]? baseline, Action<ProbeEvent>? sink)
    {
        try
        {
            t.Write(dir, SaclModel.WriteInfo(true),
                DescriptorBuilder.Build(SaclModel.WriteControl(true), null, null, [PlaceholderInheritable], null));
            var raw = t.Read(dir, withSacl: true).Descriptor;
            sink?.Invoke(ProbeEvent.Of("write", dir, baseline, raw, "the step 2 bypass proof: a protected SACL with the EVERYONE@ placeholder audit ACE (SA|FA, OI|CI)"));
            var after = Descriptor.Decode(raw);
            var sacl = after.Sacl?.Aces ?? [];
            if (sacl.Count != 1 || Ace.FromView(sacl[0]) != PlaceholderInheritable || (after.Control & Control.SaclProtected) == 0)
                return "the array accepted the probe's placeholder audit ACE but did not keep it (K5): the bypass is not proven (design 5, layer 3)";
            return null;
        }
        catch (Exception e) when (IsAccessDenied(e)) { return NoBypass(e); }
    }

    // CheckRootPropagation is design 6's steps 3 and 4: the root's desired audit ACEs, written to
    // the probe dir as an unprotected SACL with ID cleared — or an inheritable placeholder when
    // the root passes nothing down, so the children's check is never vacuous — and the subdir's
    // and file's ID audit part required to equal Inheritance.Inherit of what was written. It
    // returns what the probe dir now passes down, for step 5's explicit+inherited write.
    static (string? Why, List<Ace> Passes) CheckRootPropagation(IWritableTree t, string dir, string sub, string file, List<Ace> rootWanted, Action<ProbeEvent>? sink)
    {
        bool passesDown = Inheritance.Inherit(rootWanted, false).Count + Inheritance.Inherit(rootWanted, true).Count > 0;
        List<Ace> written = passesDown ? rootWanted : new List<Ace> { PlaceholderInheritable };
        var detail = passesDown
            ? "step 4: the root's desired audit ACEs on the probe dir, unprotected"
            : "step 4: the root passes nothing down, so the inheritable placeholder keeps this check non-vacuous";
        t.Write(dir, SaclModel.WriteInfo(false), DescriptorBuilder.Build(SaclModel.WriteControl(false), null, null, written, null));
        var rawDir = t.Read(dir, withSacl: true).Descriptor;
        sink?.Invoke(ProbeEvent.Of("write", dir, null, rawDir, detail));
        foreach (var (rel, isDir) in new[] { (sub, true), (file, false) })
        {
            var rawChild = t.Read(rel, withSacl: true).Descriptor;
            sink?.Invoke(ProbeEvent.Of("read", rel, null, rawChild, "step 4: the children's inherited audit part"));
            var c = Descriptor.Decode(rawChild);
            var got = (c.Sacl?.Aces ?? []).Select(Ace.FromView).Where(a => a is null || a.Value.Inherited).ToList();
            var wantInh = Inheritance.Inherit(written, isDir);
            if (got.Count != wantInh.Count || got.Zip(wantInh).Any(p => p.First != p.Second))
                return ($"probe child {rel} inherited audit ACEs [{string.Join(", ", got.Select(a => a?.ToString() ?? "unmodelled"))}], " +
                    $"the walk computes [{string.Join(", ", wantInh)}]: the inheritance function disagrees with this array (design 6, step 4)", []);
        }
        return (null, written.ToList());
    }

    // CheckSaclControl is design 6's step 5, the S:AI rule (4.3, K11) and K9 on known data: an
    // unprotected SACL (one explicit audit ACE, then its inherited part) on the subdir, a
    // protected one on the file, and the subdir once more unprotected with S:AI CLEAR in the
    // control word. All three must store the AI bit K11 says. Then SA-only, FA-only ACEs and a
    // present, empty, protected SACL, each required back exactly (K9).
    static string? CheckSaclControl(IWritableTree t, string sub, string file, List<Ace> passes, Action<ProbeEvent>? sink)
    {
        List<Ace> explicitPlusInherited = [SaclExplicit, .. Inheritance.Inherit(passes, true)];
        var why = PutAndRequire(t, sub, protectedSacl: false, SaclModel.WriteControl(false), explicitPlusInherited,
            sink, "step 5: the unprotected explicit+inherited SACL on the probe subdir");
        if (why is not null) return why;
        why = PutAndRequire(t, file, protectedSacl: true, SaclModel.WriteControl(true), [PlaceholderAudit],
            sink, "step 5: the protected SACL on the probe file");
        if (why is not null) return why;
        // The one combination 4.1 never sends: unprotected with S:AI clear. The probe measures it
        // each run, since K11 says the array still stores S:AI set.
        why = PutAndRequire(t, sub, protectedSacl: false, Control.SaclPresent, explicitPlusInherited,
            sink, "step 5: the unprotected SACL sent with S:AI CLEAR in the control word");
        if (why is not null) return why;
        why = PutAndRequire(t, file, protectedSacl: true, SaclModel.WriteControl(true), [SaOnly], sink, "step 5: the SA-only ACE (K9)");
        if (why is not null) return why;
        why = PutAndRequire(t, file, protectedSacl: true, SaclModel.WriteControl(true), [FaOnly], sink, "step 5: the FA-only ACE (K9)");
        if (why is not null) return why;
        return PutAndRequire(t, file, protectedSacl: true, SaclModel.WriteControl(true), [], sink, "step 5: the present, empty, protected SACL (K9)");
    }

    // PutAndRequire sends one SACL write and requires the read-back, raw: the protection flag, the
    // ACEs exactly as written (K13: success is not proof of what was stored), and the S:AI bit K11
    // says that protection stores. Error 5 escapes to the layer 2 catch in CheckWithSacl.
    static string? PutAndRequire(IWritableTree t, string rel, bool protectedSacl, ushort control, IReadOnlyList<Ace> want, Action<ProbeEvent>? sink, string detail)
    {
        t.Write(rel, SaclModel.WriteInfo(protectedSacl), DescriptorBuilder.Build(control, null, null, [.. want], null));
        var raw = t.Read(rel, withSacl: true).Descriptor;
        sink?.Invoke(ProbeEvent.Of("write", rel, null, raw, detail));
        var got = Descriptor.Decode(raw);
        bool gotProtected = (got.Control & Control.SaclProtected) != 0;
        if (gotProtected != protectedSacl)
            return $"{detail}: the SACL read back {(gotProtected ? "protected" : "unprotected")}, want {(protectedSacl ? "protected" : "unprotected")} (K9)";
        var aces = (got.Sacl?.Aces ?? []).Select(Ace.FromView).ToList();
        if (aces.Count != want.Count)
            return $"{detail}: the SACL read back with {aces.Count} audit ACE(s), want {want.Count} (K9/K13)";
        for (int i = 0; i < want.Count; i++)
        {
            if (aces[i] is null) return $"{detail}: ACE {i} read back a type this code does not model (K13)";
            if (aces[i]!.Value != want[i]) return $"{detail}: ACE {i} read back {aces[i]!.Value}, want {want[i]} (K13)";
        }
        bool gotAI = (got.Control & Control.SaclAutoInherited) != 0;
        if (gotAI != SaclModel.ExpectedAutoInherited(protectedSacl))
            return $"{detail}: SaclAutoInherited is {(gotAI ? "set" : "clear")} after {(protectedSacl ? "a protected" : "an unprotected")} SACL write; " +
                $"this array was measured to store it {(!protectedSacl ? "set" : "clear")} whatever the write sent (K11; design 4.3)";
        return null;
    }

    // OwnerDaclDrift is step 6's comparison: owner, group, DACL bytes and DACL control bits versus
    // the baseline read before the SACL steps (K2).
    static string? OwnerDaclDrift(Descriptor before, Descriptor after)
    {
        if (after.Owner != before.Owner || after.Group != before.Group) return "owner or group";
        if (AclKey(after.Dacl) != AclKey(before.Dacl)) return "DACL bytes";
        const ushort bits = unchecked((ushort)(Control.DaclPresent | Control.DaclAutoInherited | Control.DaclProtected));
        if ((after.Control & bits) != (before.Control & bits))
            return $"DACL control bits ({string.Join("|", Descriptor.DescribeControl((ushort)(before.Control & bits)))} to {string.Join("|", Descriptor.DescribeControl((ushort)(after.Control & bits)))})";
        return null;
    }

    // AclKey is SaclModel's same private rendering, so step 6 compares the probe's DACL bytes by value.
    static string AclKey(AclView? a) =>
        a is null ? "absent" : $"{a.Revision}:" + string.Join("|", a.Aces.Select(x => $"{x.TypeCode},{x.Flags},{x.Mask},{x.Sid},{x.Body}"));

    // NoBypass is layer 2's refusal (design 5): error 5 on a SACL-bit open or write of the probe
    // means "no audit bypass", not a DACL denial, on a probe whose access the identity created.
    static string NoBypass(Exception e) =>
        $"the array refused a SACL access on the probe with access denied: the identity lacks the array's audit bypass (K12; design 5, layer 2): {e.Message}";

    // IsAccessDenied recognizes layer 2's signal: Win32 error 5. Win32Tree throws
    // Win32Exception(5), whose HResult is E_FAIL, not 0x80070005, so the native code is matched.
    // Win32Exception is System.ComponentModel, portable on every platform; Core still makes no
    // Win32 call (smb/CLAUDE.md).
    static bool IsAccessDenied(Exception e) =>
        e is UnauthorizedAccessException || e is System.ComponentModel.Win32Exception { NativeErrorCode: 5 }
        || e.HResult == unchecked((int)0x80070005);
}
