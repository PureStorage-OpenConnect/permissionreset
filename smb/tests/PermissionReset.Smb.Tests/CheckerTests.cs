using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class CheckerTests
{
    const string Users = "S-1-5-21-1-2-3-1001", Admins = "S-1-5-21-1-2-3-1002", Other = "S-1-5-21-1-2-3-1003";
    const byte OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, ID = AceFlags.Inherited;
    const ushort SelfRelative = 0x8000, DaclPresent = 0x0004, DaclProtected = 0x1000;

    // ---- fixture: an in-memory tree ------------------------------------------------------------

    // A null Dacl is an absent DACL (SE_DACL_PRESENT clear: everyone full control), not an empty one.
    // OpenedIsDir/OpenedReparse simulate an object whose type changed between listing and open
    // (smb/DESIGN-write-path.md, 5.3): List reports IsDir/Reparse, Read reports the opened kind.
    internal sealed record Obj(bool IsDir, Ace[]? Dacl, bool Protected, string Owner = Admins, bool Reparse = false,
        bool? OpenedIsDir = null, bool OpenedReparse = false);

    internal sealed class FakeTree(Dictionary<string, Obj> objs) : ITree
    {
        public HashSet<string> ReadFails = [], ListFails = [];

        public IReadOnlyList<TreeEntry> List(string rel)
        {
            if (ListFails.Contains(rel)) throw new IOException("Access is denied.");
            var prefix = rel.Length == 0 ? "" : rel + "/";
            return objs.Where(kv => kv.Key.Length > prefix.Length && kv.Key.StartsWith(prefix, StringComparison.Ordinal) && !kv.Key[prefix.Length..].Contains('/'))
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => new TreeEntry(kv.Key[prefix.Length..], kv.Value.IsDir, kv.Value.Reparse)).ToList();
        }

        public TreeObject Read(string rel)
        {
            if (ReadFails.Contains(rel)) throw new IOException("Access is denied.");
            var o = objs[rel];
            var dacl = o.Dacl is null ? null : DescriptorTests.Acl(o.Dacl.Select(a => DescriptorTests.Ace((byte)a.Type, a.Flags, a.Mask, Sid(a.Sid))).ToArray());
            ushort control = (ushort)(SelfRelative | (dacl is null ? 0 : DaclPresent) | (o.Protected ? DaclProtected : 0));
            var sd = DescriptorTests.Sd(control, Sid(o.Owner), Sid(Admins), null, dacl);
            return new TreeObject(sd, o.OpenedIsDir ?? o.IsDir, o.OpenedReparse);
        }
    }

    static byte[] Sid(string s)
    {
        var p = s.Split('-');
        return DescriptorTests.SidBytes(ulong.Parse(p[2]), p[3..].Select(uint.Parse).ToArray());
    }

    internal static Ace A(byte flags, string sid, uint mask = 0x1200a9) => new(AceTypes.Allow, flags, mask, sid);

    // The spec guide's usual shape: directories get two fd ACEs, files the same principals with none.
    internal static readonly Ace[] DirWant = [A(OI | CI, Users), A(OI | CI, Admins, 0x1f01ff)];
    internal static readonly Ace[] FileWant = [A(0, Users), A(0, Admins, 0x1f01ff)];
    internal static readonly Ace[] DirInherited = [A(ID | OI | CI, Users), A(ID | OI | CI, Admins, 0x1f01ff)];
    internal static readonly Ace[] FileInherited = [A(ID, Users), A(ID, Admins, 0x1f01ff)];

    static PlanAce PA(Ace a, string principal = "") =>
        new("line", 0, 0, a.Type, a.Flags, a.Mask, principal, false, principal.Length > 0 ? "" : a.Sid, "");

    static PlanRule Rule(string label, string type, string pattern, Ace[]? dacl, string owner = "") =>
        new(label, new PlanMatch(type, pattern), false, false, dacl is not null, false, false, owner, "", [], dacl?.Select(a => PA(a)).ToList());

    static Plan MakePlan(params PlanRule[] rules) =>
        new(Plan.SmbSchema, "t.yaml", "nfsv4", new PlanExclude(["skip"], ["skip"], []),
            Rule("default", "", "", FileWant), rules);

    internal static readonly Plan Usual = MakePlan(Rule("rule[0]", "directory", "", DirWant), Rule("rule[1]", "file", "", FileWant));

    static (List<CheckRecord> Records, CheckSummary Summary) Run(Plan plan, FakeTree tree, int workers = 1, string rootName = "root")
    {
        var recs = new List<CheckRecord>();
        var s = new Checker(plan, tree, rootName, _ => null).Run(recs.Add, workers);
        return (recs.OrderBy(r => r.Path, StringComparer.Ordinal).ToList(), s);
    }

    static CheckRecord At(List<CheckRecord> recs, string path) => Assert.Single(recs, r => r.Path == path);

    // ---- the walk ------------------------------------------------------------------------------

    [Fact]
    public void ARightTreeIsAllOk()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),                       // root: parent passes nothing here
            ["a"] = new(true, DirInherited, false),
            ["a/f.txt"] = new(false, FileInherited, false),
            ["g.txt"] = new(false, FileInherited, false),
        });
        var (recs, s) = Run(Usual, tree);
        Assert.All(recs, r => Assert.Equal(Outcome.Ok, r.Outcome));
        Assert.Equal(Form.Inherits, At(recs, "a").Form);
        Assert.Equal(Form.Inherits, At(recs, "a/f.txt").Form);
        Assert.Equal(4, s.Count(Outcome.Ok));
    }

    [Fact]
    public void AnNfsFlattenedTreeNeedsAWriteOnEveryObject()
    {
        // What an NFS reset leaves on FlashArray: every object D:P with explicit ACEs.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirWant, true),
            ["a/f.txt"] = new(false, FileWant, true),
        });
        var (recs, _) = Run(Usual, tree);
        Assert.Equal(Outcome.Ok, At(recs, "").Outcome);
        Assert.Equal(Outcome.Write, At(recs, "a").Outcome);
        Assert.Contains("want unprotected", At(recs, "a").Detail);
        // Its child is protected too, so it does not follow; it needs its own write.
        Assert.Equal(Outcome.Write, At(recs, "a/f.txt").Outcome);
    }

    [Fact]
    public void ChildrenThatOnlyInheritFollowAWrittenParent()
    {
        var old = new[] { A(OI | CI, Other) };
        var tree = new FakeTree(new()
        {
            [""] = new(true, old, true),
            ["a"] = new(true, [A(ID | OI | CI, Other)], false),
            ["a/f.txt"] = new(false, [A(ID, Other)], false),
        });
        var (recs, s) = Run(Usual, tree);
        Assert.Equal(Outcome.Write, At(recs, "").Outcome);
        Assert.Equal(Outcome.Follows, At(recs, "a").Outcome);
        Assert.Equal(Outcome.Follows, At(recs, "a/f.txt").Outcome);
        Assert.Equal(1, s.Count(Outcome.Write));
    }

    [Fact]
    public void AFrozenInheritedCopyIsAWriteAndSaysSo()
    {
        // The parent is right, so nothing above will change, yet the child's ID ACEs differ.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["f.txt"] = new(false, [A(ID, Other)], false),
        });
        var r = At(Run(Usual, tree).Records, "f.txt");
        Assert.Equal(Outcome.Write, r.Outcome);
        Assert.Contains("frozen copy", r.Detail);
    }

    [Fact]
    public void ARuleThatDiffersFromItsParentIsProtected()
    {
        var plan = MakePlan(Rule("rule[0]", "directory", "", DirWant), Rule("rule[1]", "file", "*.db", [A(0, Admins, 0x1f01ff)]),
            Rule("rule[2]", "file", "", FileWant));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["x.db"] = new(false, [A(0, Admins, 0x1f01ff)], true),
        });
        var r = At(Run(plan, tree).Records, "x.db");
        Assert.Equal(Form.Protected, r.Form);
        Assert.Equal(Outcome.Ok, r.Outcome);
    }

    [Fact]
    public void RootInheritsWhatTheArraySaysItInherits()
    {
        // The root's stored ID ACEs equal its rule, so it is Inherits and keeps following its real parent.
        var tree = new FakeTree(new() { [""] = new(true, DirInherited, false) });
        var r = At(Run(Usual, tree).Records, "");
        Assert.Equal(Form.Inherits, r.Form);
        Assert.Equal(Outcome.Ok, r.Outcome);
    }

    [Fact]
    public void KeepRuleChildrenInheritFromTheStoredDacl()
    {
        // A directory with no acl: rule is left alone; its child is classified against it.
        var plan = MakePlan(Rule("rule[0]", "directory", "keep*", null), Rule("rule[1]", "directory", "", DirWant),
            Rule("rule[2]", "file", "", FileWant));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["keepme"] = new(true, [A(OI | CI, Other)], true),
            ["keepme/f.txt"] = new(false, [A(ID, Other)], false),
        });
        var (recs, _) = Run(plan, tree);
        Assert.Equal(Outcome.Keep, At(recs, "keepme").Outcome);
        var f = At(recs, "keepme/f.txt");
        Assert.Equal(Form.Protected, f.Form);      // FileWant isn't what keepme passes down
        Assert.Equal(Outcome.Write, f.Outcome);
    }

    [Fact]
    public void SkipsExcludedAndReparseAndReportsErrors()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["skip"] = new(true, DirWant, true),
            ["skip/x"] = new(false, FileWant, true),
            ["link"] = new(true, DirWant, true, Reparse: true),
            ["bad.txt"] = new(false, FileInherited, false),
            ["locked"] = new(true, DirInherited, false),
            ["locked/f"] = new(false, FileInherited, false),
        });
        tree.ReadFails.Add("bad.txt");
        tree.ListFails.Add("locked");
        var (recs, s) = Run(Usual, tree);
        Assert.Equal(Outcome.Excluded, At(recs, "skip").Outcome);
        Assert.DoesNotContain(recs, r => r.Path == "skip/x");                 // pruned whole
        Assert.Equal(Outcome.Reparse, At(recs, "link").Outcome);
        Assert.Contains("read:", At(recs, "bad.txt").Detail);
        Assert.Contains(recs, r => r.Path == "locked" && r.Outcome == Outcome.Error && r.Detail!.StartsWith("list:"));
        Assert.Equal(1, s.NotProcessed);
    }

    [Fact]
    public void AKeepRuleStillReportsAnOwnerDifference()
    {
        // No acl:, so the DACL is kept, but the rule names an owner: ownership is checked
        // independently of the DACL, and a difference is a write, not a keep.
        var plan = MakePlan(Rule("rule[0]", "directory", "keep*", null, owner: "owner@example.net"),
            Rule("rule[1]", "directory", "", DirWant), Rule("rule[2]", "file", "", FileWant));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["keepme"] = new(true, [A(OI | CI, Other)], true, Owner: Users),
        });
        var recs = new List<CheckRecord>();
        new Checker(plan, tree, "root", n => n == "owner@example.net" ? Admins : null).Run(recs.Add);
        var r = At(recs, "keepme");
        Assert.Equal(Outcome.Write, r.Outcome);
        Assert.Contains("owner is", r.Detail);
    }

    [Fact]
    public void AnExplicitOnlyChildDoesNotFollowAWrittenParent()
    {
        // The root will be written and the child wants explicit ACEs plus the inherited part, but
        // it stores only the explicit one: Q-EXP found an unprotected explicit-only object does
        // not pick up parent changes, so nothing above re-derives it. It needs its own write.
        var plan = MakePlan(Rule("rule[0]", "directory", "", DirWant),
            Rule("rule[1]", "file", "", [A(0, Other), .. FileWant]));
        var tree = new FakeTree(new()
        {
            [""] = new(true, [A(OI | CI, Other)], true),
            ["f.txt"] = new(false, [A(0, Other)], false),
        });
        var (recs, _) = Run(plan, tree);
        Assert.Equal(Outcome.Write, At(recs, "").Outcome);
        var f = At(recs, "f.txt");
        Assert.Equal(Form.ExplicitPlusInherits, f.Form);
        Assert.Equal(Outcome.Write, f.Outcome);
    }

    [Fact]
    public void AFrozenIdCopyDoesNotFollowAWrittenParent()
    {
        // The root will be written, but the child's ID part is a frozen copy of an unrelated ACL:
        // it does not equal what the stored root currently passes down (F2), so the array will not
        // re-derive it when the root changes. It needs its own write.
        var tree = new FakeTree(new()
        {
            [""] = new(true, [A(OI | CI, Other)], true),
            ["f.txt"] = new(false, [A(ID, Users)], false),
        });
        var (recs, _) = Run(Usual, tree);
        Assert.Equal(Outcome.Write, At(recs, "").Outcome);
        var f = At(recs, "f.txt");
        Assert.Equal(Outcome.Write, f.Outcome);
        Assert.Contains("frozen copy", f.Detail);
    }

    [Fact]
    public void AnUnprotectedKeepDirectoryPassesDownOnlyItsStoredDacl()
    {
        // Nothing above writes; the kept directory's children are classified against the DACL it
        // actually stores, not against its explicit ACEs plus a re-derived inherited part.
        var plan = MakePlan(Rule("rule[0]", "directory", "keep*", null), Rule("rule[1]", "directory", "", DirWant),
            Rule("rule[2]", "file", "", [A(0, Other)]));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["keepme"] = new(true, [A(OI | CI, Other)], false),
            ["keepme/f.txt"] = new(false, [A(ID, Other)], false),
        });
        var (recs, _) = Run(plan, tree);
        Assert.Equal(Outcome.Keep, At(recs, "keepme").Outcome);
        var f = At(recs, "keepme/f.txt");
        Assert.Equal(Form.Inherits, f.Form);
        Assert.Equal(Outcome.Ok, f.Outcome);
    }

    [Fact]
    public void ATrackingKeepDirectoryUnderAWrittenAncestorLetsItsRederivedPartDown()
    {
        // The root will be written, and the kept directory's inherited part equals what the stored
        // root currently passes down: it tracks (F2), so after the root's write the array
        // re-derives it from the root's desired DACL, and the tracking child follows.
        var plan = MakePlan(Rule("rule[0]", "directory", "keep*", null), Rule("rule[1]", "directory", "", DirWant),
            Rule("rule[2]", "file", "", FileWant));
        var tree = new FakeTree(new()
        {
            [""] = new(true, [A(OI | CI, Other)], true),
            ["keepme"] = new(true, [A(ID | OI | CI, Other)], false),
            ["keepme/f.txt"] = new(false, [A(ID, Other)], false),
        });
        var (recs, _) = Run(plan, tree);
        Assert.Equal(Outcome.Write, At(recs, "").Outcome);
        Assert.Equal(Outcome.Keep, At(recs, "keepme").Outcome);
        Assert.Equal(Outcome.Follows, At(recs, "keepme/f.txt").Outcome);
    }

    [Fact]
    public void AFileThatBecomesADirectoryBetweenListingAndOpenIsSkippedAndCounted()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["moved"] = new(false, FileInherited, false, OpenedIsDir: true),
            ["moved/inside"] = new(false, FileInherited, false),
        });
        var (recs, s) = Run(Usual, tree);
        var m = At(recs, "moved");
        Assert.Equal(Outcome.Error, m.Outcome);
        Assert.Contains("type changed", m.Detail);
        Assert.Contains("a directory", m.Detail);
        Assert.DoesNotContain(recs, r => r.Path == "moved/inside");     // the new subtree was never walked
        Assert.Equal(1, s.NotProcessed);
    }

    [Fact]
    public void AListentryThatBecomesAReparsePointAtOpenIsSkippedAndCounted()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["gone"] = new(true, DirInherited, false, OpenedReparse: true),
            ["gone/f"] = new(false, FileInherited, false),
        });
        var (recs, s) = Run(Usual, tree);
        var g = At(recs, "gone");
        Assert.Equal(Outcome.Error, g.Outcome);
        Assert.Contains("reparse point", g.Detail);
        Assert.DoesNotContain(recs, r => r.Path == "gone/f");
        Assert.Equal(1, s.NotProcessed);
    }

    [Fact]
    public void ChecksANamedOwner()
    {
        var plan = MakePlan(Rule("rule[0]", "directory", "", DirWant), Rule("rule[1]", "file", "", FileWant, owner: "owner@example.net"));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["f.txt"] = new(false, FileInherited, false, Owner: Users),
        });
        var recs = new List<CheckRecord>();
        new Checker(plan, tree, "root", n => n == "owner@example.net" ? Admins : null).Run(recs.Add);
        var r = At(recs, "f.txt");
        Assert.Equal(Outcome.Write, r.Outcome);
        Assert.Contains("owner is", r.Detail);
        // Its DACL matched; the frozen-copy note explains a DACL difference, so it is not here.
        Assert.DoesNotContain("frozen copy", r.Detail);
    }

    // ---- the root's name (Go MatchRule: filepath.Base of the root; Set-SaclOnly: BaseName) ------

    [Fact]
    public void ARuleNamingTheRootAppliesToTheRoot()
    {
        var plan = MakePlan(Rule("rule[0]", "directory", "dept", DirWant), Rule("rule[1]", "directory", "", [A(OI | CI, Other)]),
            Rule("rule[2]", "file", "", FileWant));
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true) });
        var r = At(Run(plan, tree, rootName: "dept").Records, "");
        Assert.Equal("rule[0]", r.Rule);
        Assert.Equal(Outcome.Ok, r.Outcome);
        // Under another name the same root falls through to rule[1].
        Assert.Equal("rule[1]", At(Run(plan, tree, rootName: "other").Records, "").Rule);
    }

    [Fact]
    public void AFileRuleNamingTheRootDoesNotApplyToIt()
    {
        var plan = MakePlan(Rule("rule[0]", "file", "dept", [A(0, Other)]), Rule("rule[1]", "directory", "", DirWant));
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true) });
        var r = At(Run(plan, tree, rootName: "dept").Records, "");
        Assert.Equal("rule[1]", r.Rule);
        Assert.Equal(Outcome.Ok, r.Outcome);
    }

    [Fact]
    public void TheRootIsNeverExcludedEvenWhenItsNameIs()
    {
        // MakePlan excludes "skip" by base name; the root keeps being checked under that name.
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true), ["f.txt"] = new(false, FileInherited, false) });
        var (recs, _) = Run(Usual, tree, rootName: "skip");
        Assert.Equal(Outcome.Ok, At(recs, "").Outcome);
        Assert.Equal(Outcome.Ok, At(recs, "f.txt").Outcome);
    }

    // ---- incomplete walks ---------------------------------------------------------------------

    [Fact]
    public void ADirectoryWhoseReadFailsMakesTheCheckIncomplete()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["locked"] = new(true, DirInherited, false),
            ["locked/f"] = new(false, FileInherited, false),
            ["bad.txt"] = new(false, FileInherited, false),
        });
        tree.ReadFails.Add("locked");
        tree.ReadFails.Add("bad.txt");
        var (recs, s) = Run(Usual, tree);
        Assert.Contains("read:", At(recs, "locked").Detail);
        Assert.DoesNotContain(recs, r => r.Path == "locked/f");     // its subtree was dropped
        Assert.Equal(1, s.NotProcessed);                            // the file's failure is not a dropped subtree
    }

    [Fact]
    public void AnUnreadableRootMakesTheCheckIncomplete()
    {
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true) });
        tree.ReadFails.Add("");
        var (recs, s) = Run(Usual, tree);
        Assert.Equal(Outcome.Error, Assert.Single(recs).Outcome);
        Assert.Equal(1, s.NotProcessed);
    }

    // ---- an absent DACL (SE_DACL_PRESENT clear) -----------------------------------------------

    [Fact]
    public void AnAbsentDaclNeverFollows()
    {
        // The root is written, so its children would follow if their DACL had the re-derivable
        // shape. An absent DACL has no inherited part to re-derive: it is a write of its own.
        var tree = new FakeTree(new()
        {
            [""] = new(true, [A(OI | CI, Other)], true),
            ["f.txt"] = new(false, null, false),
        });
        var (recs, _) = Run(Usual, tree);
        Assert.Equal(Outcome.Write, At(recs, "").Outcome);
        var f = At(recs, "f.txt");
        Assert.Equal(Outcome.Write, f.Outcome);
        Assert.DoesNotContain("frozen copy", f.Detail);
    }

    [Fact]
    public void AKeepDirectoryWithAnAbsentDaclDropsItsSubtree()
    {
        var plan = MakePlan(Rule("rule[0]", "directory", "keep*", null), Rule("rule[1]", "directory", "", DirWant),
            Rule("rule[2]", "file", "", FileWant));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["keepme"] = new(true, null, false),
            ["keepme/f.txt"] = new(false, FileInherited, false),
        });
        var (recs, s) = Run(plan, tree);
        Assert.Contains(recs, r => r.Path == "keepme" && r.Outcome == Outcome.Keep);
        Assert.Contains(recs, r => r.Path == "keepme" && r.Outcome == Outcome.Error && r.Detail!.Contains("DACL is absent"));
        Assert.DoesNotContain(recs, r => r.Path == "keepme/f.txt");
        Assert.Equal(1, s.NotProcessed);
    }

    // ---- a fault in the walk itself -----------------------------------------------------------

    [Fact]
    public async Task AWorkerFaultStopsTheRunAndIsRaised()
    {
        var objs = new Dictionary<string, Obj> { [""] = new(true, DirWant, true) };
        for (int d = 0; d < 20; d++)
        {
            objs[$"d{d}"] = new(true, DirInherited, false);
            for (int f = 0; f < 10; f++) objs[$"d{d}/f{f}"] = new(false, FileInherited, false);
        }
        int emitted = 0;
        var checker = new Checker(Usual, new FakeTree(objs), "root", _ => null);
        var run = Task.Run(() => checker.Run(r =>
        {
            emitted++;
            if (r.Path == "d3") throw new InvalidOperationException("boom");
        }, workers: 4));
        // A regression that hangs fails here instead of hanging the suite.
        var done = await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(30)));
        Assert.Same(run, done);
        var e = await Assert.ThrowsAsync<CheckFaultException>(() => run);
        Assert.Contains("boom", e.Message);
        Assert.IsType<InvalidOperationException>(e.InnerException);
        Assert.True(emitted < objs.Count, $"the walk went on after the fault ({emitted} of {objs.Count} emitted)");
    }

    [Fact]
    public void AFaultOnTheRootIsRaised()
    {
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true) });
        var e = Assert.Throws<CheckFaultException>(() => new Checker(Usual, tree, "root", _ => null).Run(_ => throw new InvalidOperationException("boom")));
        Assert.Contains("boom", e.Message);
    }

    [Fact]
    public void RefusesUnresolvedPrincipalsAndSchema1()
    {
        var named = new PlanRule("default", new PlanMatch("", ""), false, false, true, false, false, "", "", [],
            [PA(A(0, ""), "nobody-here@example.net")]);
        var plan = new Plan(Plan.SmbSchema, "t", "nfsv4", new PlanExclude([], [], []), named, []);
        var e = Assert.Throws<PlanException>(() => new Checker(plan, new FakeTree([]), "root", _ => null));
        Assert.Contains("nobody-here@example.net", e.Message);
        Assert.Throws<PlanException>(() => new Checker(plan with { Schema = Plan.SaclSchema }, new FakeTree([]), "root", _ => "S-1-1-0"));
    }

    [Fact]
    public void ParallelWalkSeesEveryObjectOnce()
    {
        var objs = new Dictionary<string, Obj> { [""] = new(true, DirWant, true) };
        for (int d = 0; d < 20; d++)
        {
            objs[$"d{d}"] = new(true, DirInherited, false);
            for (int f = 0; f < 10; f++) objs[$"d{d}/f{f}"] = new(false, FileInherited, false);
        }
        var (recs, s) = Run(Usual, new FakeTree(objs), workers: 8);
        Assert.Equal(objs.Count, recs.Count);
        Assert.Equal(objs.Count, recs.Select(r => r.Path).Distinct().Count());
        Assert.Equal(objs.Count, s.Count(Outcome.Ok));
    }
}
