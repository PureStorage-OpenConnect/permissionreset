using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class CheckerTests
{
    const string Users = "S-1-5-21-1-2-3-1001", Admins = "S-1-5-21-1-2-3-1002", Other = "S-1-5-21-1-2-3-1003";
    const byte OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, ID = AceFlags.Inherited;
    const ushort SelfRelative = 0x8000, DaclPresent = 0x0004, DaclProtected = 0x1000;

    // ---- fixture: an in-memory tree ------------------------------------------------------------

    internal sealed record Obj(bool IsDir, Ace[] Dacl, bool Protected, string Owner = Admins, bool Reparse = false);

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

        public byte[] Read(string rel)
        {
            if (ReadFails.Contains(rel)) throw new IOException("Access is denied.");
            var o = objs[rel];
            var dacl = DescriptorTests.Acl(o.Dacl.Select(a => DescriptorTests.Ace((byte)a.Type, a.Flags, a.Mask, Sid(a.Sid))).ToArray());
            ushort control = (ushort)(SelfRelative | DaclPresent | (o.Protected ? DaclProtected : 0));
            return DescriptorTests.Sd(control, Sid(o.Owner), Sid(Admins), null, dacl);
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

    static (List<CheckRecord> Records, CheckSummary Summary) Run(Plan plan, FakeTree tree, int workers = 1)
    {
        var recs = new List<CheckRecord>();
        var s = new Checker(plan, tree, _ => null).Run(recs.Add, workers);
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
    public void ChecksANamedOwner()
    {
        var plan = MakePlan(Rule("rule[0]", "directory", "", DirWant), Rule("rule[1]", "file", "", FileWant, owner: "owner@example.net"));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["f.txt"] = new(false, FileInherited, false, Owner: Users),
        });
        var recs = new List<CheckRecord>();
        new Checker(plan, tree, n => n == "owner@example.net" ? Admins : null).Run(recs.Add);
        var r = At(recs, "f.txt");
        Assert.Equal(Outcome.Write, r.Outcome);
        Assert.Contains("owner is", r.Detail);
    }

    [Fact]
    public void RefusesUnresolvedPrincipalsAndSchema1()
    {
        var named = new PlanRule("default", new PlanMatch("", ""), false, false, true, false, false, "", "", [],
            [PA(A(0, ""), "nobody-here@example.net")]);
        var plan = new Plan(Plan.SmbSchema, "t", "nfsv4", new PlanExclude([], [], []), named, []);
        var e = Assert.Throws<PlanException>(() => new Checker(plan, new FakeTree([]), _ => null));
        Assert.Contains("nobody-here@example.net", e.Message);
        Assert.Throws<PlanException>(() => new Checker(plan with { Schema = Plan.SaclSchema }, new FakeTree([]), _ => "S-1-1-0"));
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
