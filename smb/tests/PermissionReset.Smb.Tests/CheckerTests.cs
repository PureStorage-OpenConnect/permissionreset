using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class CheckerTests
{
    internal const string Users = "S-1-5-21-1-2-3-1001", Admins = "S-1-5-21-1-2-3-1002", Other = "S-1-5-21-1-2-3-1003";
    const byte OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, ID = AceFlags.Inherited;
    const ushort SelfRelative = 0x8000, DaclPresent = 0x0004, DaclProtected = 0x1000;

    // ---- fixture: an in-memory tree ------------------------------------------------------------

    // A null Dacl is an absent DACL (SE_DACL_PRESENT clear: everyone full control), not an empty one.
    // OpenedIsDir/OpenedReparse simulate an object whose type changed between listing and open
    // (smb/DESIGN-write-path.md, 5.3): List reports IsDir/Reparse, Read reports the opened kind.
    // A null Sacl with SaclEverWritten false is a never-ACL-written object (smb/DESIGN-sacl-write.md,
    // K9: it reads S:AI empty); SaclProtected is S:P, set by a protected SACL write or by
    // MarkNfsAclWritten (K3).
    internal sealed record Obj(bool IsDir, Ace[]? Dacl, bool Protected, string Owner = Admins, bool Reparse = false,
        Ace[]? Sacl = null, string Group = Admins, ushort ExtraControl = 0, bool? OpenedIsDir = null, bool OpenedReparse = false,
        bool SaclProtected = false, bool SaclEverWritten = false);

    // FakeTree is an in-memory array. Its writes model what FlashArray was measured to do
    // (smb/DESIGN-write-path.md, section 1; smb/DESIGN-sacl-write.md, section 1): it stores exactly
    // the DACL written (F1), and a DACL write to a directory re-derives every unprotected
    // descendant whose inherited part matched what the directory passed down before (F2, F3); one
    // that didn't match is a frozen copy and keeps its ACEs. The SACL side is the same model
    // (K4): a SACL write stores exactly what was sent (DropSaclAceTypes excepted), an empty one
    // reads back present-empty (K9), the AI bit comes from protection (K11), never-ACL-written
    // objects (S:AI empty) and matching-ID ones follow a parent's SACL change while protected and
    // mismatching-ID ones stay frozen (K10, K16). ArrayInherit is the array's inheritance
    // function: the tool's by default, replaceable to model an array that disagrees.
    internal sealed class FakeTree(Dictionary<string, Obj> objs) : IWritableTree
    {
        public HashSet<string> ReadFails = [], ListFails = [], WriteFails = [], DeleteFails = [], SaclReadFails = [];
        public Action<string>? BeforeSaclRead;                 // runs before each read with the SACL
        public readonly List<string> SaclReads = [];
        public Func<IReadOnlyList<Ace>, bool, List<Ace>> ArrayInherit = Inheritance.Inherit;
        public bool DropSacl;                                  // accept SACL writes, keep nothing
        public readonly HashSet<byte> DropSaclAceTypes = [];   // accept SACL writes, silently drop these ACE types (K13)
        public Action<string>? AfterWrite;                     // runs after each write, to corrupt it
        public readonly List<(string Rel, uint Info)> Writes = [];
        public readonly List<(string Rel, uint Info, byte[] Sd)> SentWrites = [];   // exact bytes, for the phase 2 byte-equality check
        public readonly Dictionary<string, ushort> SentControl = [];  // the control word of each object's last write
        public readonly Dictionary<string, Obj> Objs = objs;

        public IReadOnlyList<TreeEntry> List(string rel)
        {
            if (ListFails.Contains(rel)) throw new IOException("Access is denied.");
            return Children(rel).Select(kv => new TreeEntry(kv.Key[(rel.Length == 0 ? 0 : rel.Length + 1)..], kv.Value.IsDir, kv.Value.Reparse)).ToList();
        }

        List<KeyValuePair<string, Obj>> Children(string rel)
        {
            var prefix = rel.Length == 0 ? "" : rel + "/";
            lock (Objs)
                return Objs.Where(kv => kv.Key.Length > prefix.Length && kv.Key.StartsWith(prefix, StringComparison.Ordinal) && !kv.Key[prefix.Length..].Contains('/'))
                    .OrderBy(kv => kv.Key, StringComparer.Ordinal).ToList();
        }

        public TreeObject Read(string rel, bool withSacl)
        {
            if (ReadFails.Contains(rel)) throw new IOException("Access is denied.");
            if (withSacl)
            {
                lock (SaclReads) SaclReads.Add(rel);
                if (SaclReadFails.Contains(rel)) throw new IOException("A required privilege is not held by the client.");
                BeforeSaclRead?.Invoke(rel);
            }
            Obj o;
            lock (Objs) o = Objs[rel];
            var dacl = o.Dacl is null ? null : DescriptorTests.Acl(o.Dacl.Select(a => DescriptorTests.Ace((byte)a.Type, a.Flags, a.Mask, Sid(a.Sid))).ToArray());
            // K9: FlashArray always stores a present SACL, so a read that asks for it gets one:
            // present-empty for a never-ACL-written object (S:AI empty), the stored ACEs otherwise.
            byte[]? sacl = withSacl
                ? DescriptorTests.Acl((o.Sacl ?? []).Select(a => DescriptorTests.Ace((byte)a.Type, a.Flags, a.Mask, Sid(a.Sid))).ToArray())
                : null;
            ushort saclControl = 0;
            if (sacl is not null)
            {
                saclControl = (ushort)(0x0010 | (o.SaclProtected ? 0x2000 : 0));
                // K11: the array decides the AI bit from protection. It is derived for written
                // SACLs and never-written ones; a fixture SACL put in by hand states it through
                // ExtraControl, as before.
                if (o.SaclEverWritten || o.Sacl is null)
                    saclControl |= o.SaclProtected ? (ushort)0 : (ushort)0x0800;
            }
            ushort control = (ushort)(SelfRelative | (dacl is null ? 0 : DaclPresent) | (o.Protected ? DaclProtected : 0) | saclControl | o.ExtraControl);
            var sd = DescriptorTests.Sd(control, Sid(o.Owner), Sid(o.Group), sacl, dacl);
            return new TreeObject(sd, o.OpenedIsDir ?? o.IsDir, o.OpenedReparse);
        }

        public void Write(string rel, uint info, byte[] sd)
        {
            if (WriteFails.Contains(rel)) throw new IOException("set security: Access is denied.");
            var d = Descriptor.Decode(sd);
            lock (Objs)
            {
                Writes.Add((rel, info));
                SentWrites.Add((rel, info, sd));
                SentControl[rel] = d.Control;
                var o = Objs[rel];
                if ((info & SecurityInformation.Owner) != 0) o = o with { Owner = d.Owner! };
                if ((info & SecurityInformation.Group) != 0) o = o with { Group = d.Group! };
                if ((info & SecurityInformation.Sacl) != 0 && !DropSacl)
                {
                    // The array stores exactly the SACL written (F1's SACL analogue, K4), a
                    // present-empty one reading back present-empty (K9); it can also return
                    // success and drop ACE types it doesn't store (K13), which DropSaclAceTypes
                    // models: only the read-back shows what was stored.
                    var oldSacl = o.Sacl?.ToList() ?? [];
                    var newSacl = d.Sacl!.Aces.Where(a => !DropSaclAceTypes.Contains(a.TypeCode)).Select(a => Ace.FromView(a)!.Value).ToArray();
                    o = o with
                    {
                        Sacl = newSacl,
                        SaclProtected = (info & SecurityInformation.ProtectedSacl) != 0,
                        SaclEverWritten = true,
                    };
                    Objs[rel] = o;
                    // A SACL write to a directory re-derives every unprotected descendant whose
                    // ID part matched what the directory passed down before, S:AI empty ones
                    // included (K10, K16); a frozen or protected one keeps its ACEs.
                    if (o.IsDir) PropagateSacl(rel, oldSacl, newSacl.ToList());
                }
                if ((info & SecurityInformation.Dacl) != 0)
                {
                    var old = o.Dacl?.ToList() ?? [];
                    o = o with
                    {
                        Dacl = d.Dacl!.Aces.Select(a => Ace.FromView(a)!.Value).ToArray(),
                        Protected = (info & SecurityInformation.ProtectedDacl) != 0,
                    };
                    // F5: the array stores D:AI on an unprotected DACL and drops it on a protected
                    // one, whatever the control word sent says.
                    o = o with { ExtraControl = (ushort)((o.ExtraControl & ~Control.DaclAutoInherited) | (o.Protected ? 0 : Control.DaclAutoInherited)) };
                    Objs[rel] = o;
                    if (o.IsDir) Propagate(rel, old, o.Dacl!.ToList());
                }
                Objs[rel] = o;
            }
            AfterWrite?.Invoke(rel);
        }

        void Propagate(string dir, List<Ace> oldAcl, List<Ace> newAcl)
        {
            foreach (var (rel, c) in Children(dir))
            {
                if (c.Protected || c.Reparse || c.Dacl is null) continue;
                var id = c.Dacl.Where(a => a.Inherited).ToList();
                if (!id.SequenceEqual(ArrayInherit(oldAcl, c.IsDir))) continue;   // a frozen copy (F2)
                var updated = c with { Dacl = c.Dacl.Where(a => !a.Inherited).Concat(ArrayInherit(newAcl, c.IsDir)).ToArray() };
                Objs[rel] = updated;
                if (c.IsDir) Propagate(rel, c.Dacl.ToList(), updated.Dacl.ToList());
            }
        }

        // PropagateSacl is Propagate for the SACL (K4, K10, K16). Never-ACL-written children
        // (S:AI empty) and ones whose ID part matched what the directory passed down before
        // follow; an explicit-only SACL does not (no record says so; Q-EXP for the DACL); a
        // protected SACL (S:P, sacl: [] and NFS-ACL-written objects included) does not follow and
        // blocks its children from a later ancestor change until it is itself written; a
        // mismatching ID part stays frozen.
        void PropagateSacl(string dir, List<Ace> oldSacl, List<Ace> newSacl)
        {
            foreach (var (rel, c) in Children(dir))
            {
                if (c.SaclProtected || c.Reparse) continue;
                var aces = c.Sacl?.ToList() ?? [];                       // never written: S:AI empty (K9)
                var id = aces.Where(a => a.Inherited).ToList();
                if (!id.SequenceEqual(ArrayInherit(oldSacl, c.IsDir))) continue;   // a frozen copy (K10)
                // Explicit audit ACEs only: no record says this follows (K10 covers S:AI empty and
                // matching ID parts), and the DACL's explicit-only objects do not (Q-EXP).
                if (aces.Count > 0 && id.Count == 0) continue;
                var newAces = aces.Where(a => !a.Inherited).Concat(ArrayInherit(newSacl, c.IsDir)).ToArray();
                var updated = c;
                // A write that changes nothing the child inherits leaves the child untouched; a
                // followed child still reads S:AI, so a hand-built fixture states the bit here.
                if (!newAces.SequenceEqual(aces))
                    updated = c with { Sacl = newAces, ExtraControl = (ushort)(c.ExtraControl | Control.SaclAutoInherited) };
                Objs[rel] = updated;
                if (c.IsDir) PropagateSacl(rel, aces, (updated.Sacl ?? []).ToList());
            }
        }

        // MarkNfsAclWritten models what an NFS ACL write leaves on FlashArray (K3: S:AI to S:P,
        // D:AI to D:P): the object is S:P, does not follow a later parent SACL change and needs
        // its own conversion (K16).
        public void MarkNfsAclWritten(string rel)
        {
            lock (Objs)
            {
                var o = Objs[rel];
                Objs[rel] = o with
                {
                    Protected = true,
                    SaclProtected = true,
                    SaclEverWritten = true,
                    Sacl = o.Sacl ?? [],
                    ExtraControl = (ushort)(o.ExtraControl & ~(Control.DaclAutoInherited | Control.SaclAutoInherited)),
                };
            }
        }

        public void CreateDirectory(string rel) => Create(rel, true);
        public void CreateFile(string rel) => Create(rel, false);

        void Create(string rel, bool isDir)
        {
            lock (Objs)
            {
                var parent = rel.Contains('/') ? rel[..rel.LastIndexOf('/')] : "";
                if (!Objs.TryGetValue(parent, out var p) || !p.IsDir) throw new IOException("create: The system cannot find the path specified.");
                if (Objs.ContainsKey(rel)) throw new IOException("create: Cannot create a file when that file already exists.");
                // A new object holds its parent's inheritable ACEs as ID, on both ACLs, and is
                // never ACL-written, so it follows later parent changes (K10, K18). A parent that
                // passes nothing down leaves a never-written SACL (null: S:AI empty, K9).
                var sacl = ArrayInherit(p.Sacl ?? [], isDir);
                Objs[rel] = new Obj(isDir, ArrayInherit(p.Dacl ?? [], isDir).ToArray(), false, Owner: Users,
                    Sacl: sacl.Count > 0 ? sacl.ToArray() : null, ExtraControl: Control.SaclAutoInherited);
            }
        }

        public void Delete(string rel, bool isDir)
        {
            if (DeleteFails.Contains(rel)) throw new IOException("delete: Access is denied.");
            lock (Objs)
            {
                if (!Objs.ContainsKey(rel)) throw new FileNotFoundException("delete: not found", rel);
                if (Children(rel).Count > 0) throw new IOException("delete: The directory is not empty.");
                Objs.Remove(rel);
            }
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

    internal static PlanAce PA(Ace a, string principal = "") =>
        new("line", 0, 0, a.Type, a.Flags, a.Mask, principal, false, principal.Length > 0 ? "" : a.Sid, "");

    internal static PlanRule Rule(string label, string type, string pattern, Ace[]? dacl, string owner = "") =>
        new(label, new PlanMatch(type, pattern), false, false, dacl is not null, false, false, owner, "", [], dacl?.Select(a => PA(a)).ToList());

    internal static Plan MakePlan(params PlanRule[] rules) =>
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
    public void ApplyReportsAKeepRuleOwnerDifferenceAsAnErrorAndWritesNothing()
    {
        // Apply writes nothing on a rule without acl:, so an owner difference there is an error
        // the operator sees, never a silent Keep, and no write is sent for it.
        var plan = MakePlan(Rule("rule[0]", "directory", "keep*", null, owner: "owner@example.net"),
            Rule("rule[1]", "directory", "", DirWant), Rule("rule[2]", "file", "", FileWant));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["keepme"] = new(true, [A(OI | CI, Other)], true, Owner: Users),
        });
        var recs = new List<CheckRecord>();
        new Checker(plan, tree, "root", n => n == "owner@example.net" ? Admins : null, new WalkOptions(Apply: true)).Run(recs.Add);
        var r = At(recs, "keepme");
        Assert.Equal(Outcome.Error, r.Outcome);
        Assert.Contains("owner is", r.Detail);
        Assert.DoesNotContain(tree.Writes, w => w.Rel == "keepme");
        Assert.Equal(Users, tree.Objs["keepme"].Owner);
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
    // Nothing thrown inside the walk escapes Run: it stops the run the way a guard does, so the
    // caller still gets a summary (and apply can close its evidence with the reason).

    [Fact]
    public async Task AWorkerFaultStopsTheRunAndIsReported()
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
        var s = await run;
        Assert.Contains("boom", s.Stop);
        Assert.False(s.Complete);
        Assert.True(emitted < objs.Count, $"the walk went on after the fault ({emitted} of {objs.Count} emitted)");
    }

    [Fact]
    public void AFaultOnTheRootIsReported()
    {
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true) });
        var s = new Checker(Usual, tree, "root", _ => null).Run(_ => throw new InvalidOperationException("boom"));
        Assert.Contains("boom", s.Stop);
        Assert.False(s.Complete);
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

    // #78: one lookup per distinct principal, over DACL, ownership and sacl:-only names, the miss
    // cached as well. Principals that appear only in sacl: entries are resolved.
    [Fact]
    public void ResolvesEachDistinctPrincipalOnceAndSaclOnlyOnesToo()
    {
        var named = new PlanRule("default", new PlanMatch("", ""), false, false, true, false, false, "owner@example.net", "", [],
            [PA(A(0, ""), "user@example.net"), PA(A(0, ""), "user@example.net")]);
        var again = new PlanRule("rule[0]", new PlanMatch("file", "*.log"), false, false, true, false, false, "", "", [],
            [PA(A(0, ""), "user@example.net")]);
        var saclOnly = new PlanRule("rule[1]", new PlanMatch("file", "*.db"), true, true, false, false, false, "", "",
            [new PlanAce("line", 0, 0, AceTypes.Audit, AceFlags.SuccessfulAccess, 0x1f01ff, "audit@example.net", false, "", "")]);
        var plan = new Plan(Plan.SmbSchema, "t", "nfsv4", new PlanExclude([], [], []), named, [again, saclOnly]);
        var calls = new Dictionary<string, int>(StringComparer.Ordinal);
        string? Resolve(string name)
        {
            calls[name] = calls.GetValueOrDefault(name) + 1;
            return name switch
            {
                "user@example.net" => Users,
                "audit@example.net" => Admins,
                "owner@example.net" => Other,
                _ => null,
            };
        }

        var missing = new PlanRule("rule[2]", new PlanMatch("file", "*.tmp"), false, false, true, false, false, "", "", [],
            [PA(A(0, ""), "missing@example.net"), PA(A(0, ""), "missing@example.net")]);
        var bad = plan with { Rules = [.. plan.Rules, missing] };
        Assert.Throws<PlanException>(() => new Checker(bad, new FakeTree([]), "root", Resolve));
        Assert.All(calls, kv => Assert.Equal(1, kv.Value));      // the unresolved one is looked up once, too

        calls.Clear();
        var checker = new Checker(plan, new FakeTree([]), "root", Resolve);
        Assert.Equal(3, checker.Principals.Count);
        Assert.Equal(Admins, checker.Principals["audit@example.net"]);   // named only in sacl:
        Assert.All(calls, kv => Assert.Equal(1, kv.Value));
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
