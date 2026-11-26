using PermissionReset.Smb.Core;
using static PermissionReset.Smb.Tests.CheckerTests;

namespace PermissionReset.Smb.Tests;

// Phase 2: the apply walk, its guards (G1, G2), the checkpoint and the preflight probe, against
// FakeTree, which models FlashArray's measured inheritance behavior (F1-F4).
public class ApplyTests
{
    const byte OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, ID = AceFlags.Inherited, NP = AceFlags.NoPropagate;
    static readonly Ace Audit = new(AceTypes.Audit, AceFlags.SuccessfulAccess | OI | CI, 0x10000, Other);

    static (List<CheckRecord> Records, CheckSummary Summary) Apply(Plan plan, FakeTree tree, int workers = 1, ICheckpoint? cp = null, bool rootProtected = false)
    {
        var recs = new List<CheckRecord>();
        var s = new Checker(plan, tree, "root", _ => null, new WalkOptions(Apply: true, RootProtected: rootProtected)).Run(recs.Add, workers, cp);
        return (recs.OrderBy(r => r.Path, StringComparer.Ordinal).ToList(), s);
    }

    static List<CheckRecord> Check(Plan plan, FakeTree tree)
    {
        var recs = new List<CheckRecord>();
        new Checker(plan, tree, "root", _ => null).Run(recs.Add);
        return recs;
    }

    static CheckRecord At(List<CheckRecord> recs, string path) => Assert.Single(recs, r => r.Path == path);

    static FakeTree Flattened() => new(new()
    {
        [""] = new(true, DirWant, true),
        ["a"] = new(true, DirWant, true),
        ["a/f.txt"] = new(false, FileWant, true),
        ["a/b"] = new(true, DirWant, true),
        ["a/b/g.txt"] = new(false, FileWant, true),
        ["h.txt"] = new(false, FileInherited, false),
    });

    // ---- converging -------------------------------------------------------------------------------

    [Fact]
    public void AnAbsentDaclIsWrittenNotTakenForAFrozenCopy()
    {
        // An absent DACL (everyone full control) is never right and never follows, so apply writes
        // it in the desired form rather than stopping on G1; its child then follows.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, null, false),
            ["a/f.txt"] = new(false, FileInherited, false),
        });
        var (recs, s) = Apply(Usual, tree);
        Assert.Null(s.Stop);
        Assert.True(s.Complete);
        Assert.Equal(Outcome.Written, At(recs, "a").Outcome);
        Assert.NotNull(tree.Objs["a"].Dacl);
        Assert.All(Check(Usual, tree), r => Assert.Equal(Outcome.Ok, r.Outcome));
    }

    [Fact]
    public void AnNfsFlattenedTreeBecomesDynamicAndARerunWritesNothing()
    {
        var tree = Flattened();
        var (recs, s) = Apply(Usual, tree);
        Assert.True(s.Complete);
        Assert.Equal(Outcome.Ok, At(recs, "").Outcome);
        Assert.Equal(Outcome.Ok, At(recs, "h.txt").Outcome);
        foreach (var p in new[] { "a", "a/f.txt", "a/b", "a/b/g.txt" })
        {
            var r = At(recs, p);
            Assert.Equal(Outcome.Written, r.Outcome);
            Assert.Equal("dacl", r.Parts);
            Assert.NotNull(r.Before);
            Assert.NotNull(r.After);
        }
        // Q-PROT's answer: unprotected, the inherited part in ID form.
        Assert.False(tree.Objs["a"].Protected);
        Assert.Equal(DirInherited, tree.Objs["a"].Dacl);
        Assert.Equal(FileInherited, tree.Objs["a/b/g.txt"].Dacl);

        Assert.All(Check(Usual, tree), r => Assert.Equal(Outcome.Ok, r.Outcome));
        int writes = tree.Writes.Count;
        Assert.True(Apply(Usual, tree).Summary.Complete);
        Assert.Equal(writes, tree.Writes.Count);
    }

    [Fact]
    public void ChildrenThatFollowAreNotWritten()
    {
        // Only the root is wrong; its dynamic children follow it once it is written (F3).
        var old = new[] { A(OI | CI, Other) };
        var tree = new FakeTree(new()
        {
            [""] = new(true, old, true),
            ["a"] = new(true, [A(ID | OI | CI, Other)], false),
            ["a/f.txt"] = new(false, [A(ID, Other)], false),
        });
        var (recs, s) = Apply(Usual, tree);
        Assert.True(s.Complete);
        Assert.Equal(Outcome.Written, At(recs, "").Outcome);
        Assert.Equal(Outcome.Ok, At(recs, "a").Outcome);
        Assert.Equal(Outcome.Ok, At(recs, "a/f.txt").Outcome);
        Assert.Single(tree.Writes);
    }

    [Fact]
    public void WritesNameOnlyTheirPartsAndStateProtection()
    {
        var plan = MakePlan(Rule("rule[0]", "directory", "", DirWant), Rule("rule[1]", "file", "*.db", [A(0, Admins, 0x1f01ff)]),
            Rule("rule[2]", "file", "", FileWant));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirWant, true),                       // inherits: unprotected write
            ["x.db"] = new(false, FileInherited, false),            // protected write
        });
        Assert.True(Apply(plan, tree).Summary.Complete);
        var w = tree.Writes.ToDictionary(x => x.Rel, x => x.Info);
        Assert.Equal(SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl, w["a"]);
        Assert.Equal(SecurityInformation.Dacl | SecurityInformation.ProtectedDacl, w["x.db"]);
        Assert.True(tree.Objs["x.db"].Protected);
    }

    [Fact]
    public void TheSaclAndAutoInheritBitsAreLeftAlone()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirWant, true, Sacl: [Audit], ExtraControl: Control.DaclAutoInherited | Control.SaclAutoInherited),
        });
        var (recs, s) = Apply(Usual, tree);
        Assert.True(s.Complete);
        Assert.Equal(Outcome.Written, At(recs, "a").Outcome);
        Assert.Equal([Audit], tree.Objs["a"].Sacl);
        Assert.DoesNotContain(tree.Writes, x => (x.Info & SecurityInformation.Sacl) != 0);
    }

    [Fact]
    public void ANamedOwnerIsWrittenOnItsOwn()
    {
        var plan = MakePlan(Rule("rule[0]", "directory", "", DirWant), Rule("rule[1]", "file", "", FileWant, owner: "owner@example.net"));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["f.txt"] = new(false, FileInherited, false, Owner: Users),
        });
        var recs = new List<CheckRecord>();
        var checker = new Checker(plan, tree, "root", n => n == "owner@example.net" ? Admins : null, new WalkOptions(Apply: true));
        Assert.True(checker.SetsOwnerOrGroup);
        Assert.Equal(Admins, checker.Principals["owner@example.net"]);
        Assert.True(checker.Run(recs.Add).Complete);
        Assert.Equal("owner", At(recs, "f.txt").Parts);
        Assert.Equal(SecurityInformation.Owner, Assert.Single(tree.Writes).Info);
        Assert.Equal(Admins, tree.Objs["f.txt"].Owner);
    }

    [Fact]
    public void RootProtectedForcesTheRootsForm()
    {
        var tree = new FakeTree(new() { [""] = new(true, DirInherited, false) });
        Assert.Equal(Outcome.Ok, At(Apply(Usual, tree).Records, "").Outcome);
        var (recs, s) = Apply(Usual, tree, rootProtected: true);
        Assert.True(s.Complete);
        Assert.Equal(Form.Protected, At(recs, "").Form);
        Assert.True(tree.Objs[""].Protected);
        Assert.Equal(DirWant, tree.Objs[""].Dacl);
    }

    // ---- G1 ---------------------------------------------------------------------------------------

    [Fact]
    public void G1StopsWhenTheArrayInheritsDifferently()
    {
        // This array keeps OI on what a file inherits; the tool computes plain ID. The file is
        // Inherits, it followed the root's write, and what it followed to is not what the run
        // computes: writing it would freeze it.
        var plan = MakePlan(Rule("rule[0]", "directory", "", [A(OI | CI, Users)]), Rule("rule[1]", "file", "", [A(0, Users)]));
        Func<IReadOnlyList<Ace>, bool, List<Ace>> array = (p, isDir) =>
            Inheritance.Inherit(p, isDir).Select(a => isDir ? a : a with { Flags = (byte)(a.Flags | OI) }).ToList();
        var tree = new FakeTree(new()
        {
            [""] = new(true, [A(OI | CI, Other)], true),
            ["f.txt"] = new(false, array([A(OI | CI, Other)], false).ToArray(), false),
            ["g.txt"] = new(false, array([A(OI | CI, Other)], false).ToArray(), false),
        }) { ArrayInherit = array };
        var (recs, s) = Apply(plan, tree);
        Assert.False(s.Complete);
        Assert.StartsWith("G1:", s.Stop);
        Assert.StartsWith("G1:", At(recs, "f.txt").Detail);
        Assert.DoesNotContain(recs, r => r.Path == "g.txt");
        Assert.Single(tree.Writes);                                   // the root, before the guard fired
    }

    [Fact]
    public void G1StopsOnAFrozenCopyRatherThanRewriteIt()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["f.txt"] = new(false, [A(ID, Other)], false),
        });
        var (recs, s) = Apply(Usual, tree);
        Assert.StartsWith("G1:", s.Stop);
        Assert.Contains("frozen copy", At(recs, "f.txt").Detail);
        Assert.Empty(tree.Writes);
    }

    // ---- G2 ---------------------------------------------------------------------------------------

    [Fact]
    public void G2StopsWhenTheReadBackDiffers()
    {
        var tree = Flattened();
        tree.AfterWrite = rel => tree.Objs[rel] = tree.Objs[rel] with { Protected = true };   // the array re-protects
        var (recs, s) = Apply(Usual, tree);
        Assert.StartsWith("G2:", s.Stop);
        Assert.Contains("want unprotected", s.Stop);
        var a = At(recs, "a");
        Assert.Equal(Outcome.Error, a.Outcome);
        Assert.NotNull(a.After);
        Assert.Single(tree.Writes);
        Assert.DoesNotContain(recs, r => r.Path.StartsWith("a/"));      // its children are not reached
        Assert.DoesNotContain(recs, r => r.Path == "h.txt");            // nor the rest of the root's listing
        Assert.Equal(2, s.NotProcessed);
    }

    [Fact]
    public void G2StopsWhenTheSaclChangesAcrossADaclWrite()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirWant, true, Sacl: [Audit]),
        });
        tree.AfterWrite = rel => tree.Objs[rel] = tree.Objs[rel] with { Sacl = [] };
        var s = Apply(Usual, tree).Summary;
        Assert.StartsWith("G2:", s.Stop);
        Assert.Contains("SACL changed", s.Stop);
    }

    [Fact]
    public void G2StopsWhenTheArrayDoesNotSetAutoInheritOnAnUnprotectedWrite()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirWant, true, ExtraControl: Control.DaclAutoInherited),
        });
        tree.AfterWrite = rel => tree.Objs[rel] = tree.Objs[rel] with { ExtraControl = 0 };
        var s = Apply(Usual, tree).Summary;
        Assert.StartsWith("G2:", s.Stop);
        Assert.Contains("DaclAutoInherited is clear after an unprotected DACL write", s.Stop);
    }

    [Fact]
    public void AProtectedObjectWithoutAutoInheritBecomesUnprotectedWithIt()
    {
        // The FlashArray qualification case (F5): every protected object there lacks D:AI, and an
        // unprotected write gets D:AI set by the array whatever the control word says.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirWant, true),
            ["a/f.txt"] = new(false, FileWant, true),
        });
        var (recs, s) = Apply(Usual, tree);
        Assert.True(s.Complete, s.Stop);
        Assert.Equal(Outcome.Written, At(recs, "a").Outcome);
        Assert.Equal(Control.DaclAutoInherited, tree.SentControl["a"] & (Control.DaclAutoInherited | Control.DaclProtected));
        Assert.NotEqual(0, tree.Objs["a"].ExtraControl & Control.DaclAutoInherited);
    }

    [Fact]
    public void AProtectedWriteDropsAutoInherit()
    {
        var tree = new FakeTree(new() { [""] = new(true, DirInherited, false, ExtraControl: Control.DaclAutoInherited) });
        var (recs, s) = Apply(Usual, tree, rootProtected: true);
        Assert.True(s.Complete, s.Stop);
        Assert.Equal(Outcome.Written, At(recs, "").Outcome);
        Assert.Equal(Control.DaclProtected, tree.SentControl[""] & (Control.DaclAutoInherited | Control.DaclProtected));
        Assert.Equal(0, tree.Objs[""].ExtraControl & Control.DaclAutoInherited);
    }

    [Fact]
    public void G2StopsWhenAutoInheritSurvivesAProtectedWrite()
    {
        var tree = new FakeTree(new() { [""] = new(true, DirInherited, false, ExtraControl: Control.DaclAutoInherited) });
        tree.AfterWrite = rel => tree.Objs[rel] = tree.Objs[rel] with { ExtraControl = Control.DaclAutoInherited };
        var s = Apply(Usual, tree, rootProtected: true).Summary;
        Assert.StartsWith("G2:", s.Stop);
        Assert.Contains("DaclAutoInherited is set after a protected DACL write", s.Stop);
    }

    [Fact]
    public void G2StopsWhenASaclControlBitChanges()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirWant, true, Sacl: [Audit], ExtraControl: Control.SaclAutoInherited),
        });
        tree.AfterWrite = rel => tree.Objs[rel] = tree.Objs[rel] with { ExtraControl = (ushort)(tree.Objs[rel].ExtraControl & ~Control.SaclAutoInherited) };
        var s = Apply(Usual, tree).Summary;
        Assert.StartsWith("G2:", s.Stop);
        Assert.Contains("control changed", s.Stop);
    }

    [Fact]
    public void AfterAStopNothingElseIsWritten()
    {
        var objs = new Dictionary<string, Obj> { [""] = new(true, DirWant, true) };
        for (int d = 0; d < 30; d++)
        {
            objs[$"d{d:00}"] = new(true, DirWant, true);
            for (int f = 0; f < 5; f++) objs[$"d{d:00}/f{f}"] = new(false, FileWant, true);
        }
        var tree = new FakeTree(objs);
        int n = 0;
        tree.AfterWrite = rel => { if (Interlocked.Increment(ref n) == 3) tree.Objs[rel] = tree.Objs[rel] with { Dacl = [] }; };
        var (recs, s) = Apply(Usual, tree, workers: 4);
        Assert.StartsWith("G2:", s.Stop);
        Assert.False(s.Complete);
        // Writes already past their check finish; with four workers that is at most three more.
        Assert.InRange(tree.Writes.Count, 3, 3 + 3);
        Assert.Equal(tree.Writes.Count, recs.Count(r => r.Outcome == Outcome.Written) + recs.Count(r => r.Detail?.StartsWith("G2:") == true));
    }

    // ---- failures ---------------------------------------------------------------------------------

    [Fact]
    public void AFailedDirectoryWriteLeavesItsChildrenUnprocessed()
    {
        var tree = Flattened();
        tree.WriteFails.Add("a");
        var (recs, s) = Apply(Usual, tree);
        Assert.Null(s.Stop);                                           // an I/O error is not a guard
        Assert.Contains("write dacl:", At(recs, "a").Detail);
        Assert.DoesNotContain(recs, r => r.Path.StartsWith("a/"));
        Assert.Equal(1, s.NotProcessed);
        Assert.False(s.Complete);
    }

    [Fact]
    public void ADescriptorThatCannotBeEncodedFailsTheObjectNotTheRun()
    {
        // Plan does not check SID syntax; the encoder is the first to see a malformed one.
        var bad = new[] { A(0, "S-1-5-21-x") };
        var plan = MakePlan(Rule("rule[0]", "directory", "", DirWant), Rule("rule[1]", "file", "", bad));
        var tree = Flattened();
        var (recs, s) = Apply(plan, tree);
        var f = At(recs, "a/f.txt");
        Assert.Equal(Outcome.Error, f.Outcome);
        Assert.StartsWith("encode dacl:", f.Detail);
        Assert.DoesNotContain(tree.Writes, w => w.Rel == "a/f.txt");
        Assert.Equal(Outcome.Written, At(recs, "a/b").Outcome);         // the rest of the walk goes on
        Assert.Null(s.Stop);
        Assert.False(s.Complete);
    }

    [Fact]
    public void ARecordThatCannotBeWrittenStopsTheRunInsteadOfEscaping()
    {
        var tree = Flattened();
        int n = 0;
        var s = new Checker(Usual, tree, "root", _ => null, new WalkOptions(Apply: true)).Run(r =>
        {
            if (++n == 2) throw new IOException("There is not enough space on the disk.");
        }, workers: 4);
        Assert.Contains("could not record", s.Stop);
        Assert.Contains("not enough space", s.Stop);
        Assert.False(s.Complete);
    }

    [Fact]
    public void OnlyObjectsThatNeedAWriteHaveTheirSaclRead()
    {
        var tree = Flattened();
        tree.SaclReadFails.Add("h.txt");                               // right already: its SACL is never needed
        var (recs, s) = Apply(Usual, tree);
        Assert.True(s.Complete);
        Assert.Equal(Outcome.Ok, At(recs, "h.txt").Outcome);
        // Each written object is read with its SACL twice: the before-image, and G2's read-back.
        Assert.Equal(["a", "a", "a/b", "a/b", "a/b/g.txt", "a/b/g.txt", "a/f.txt", "a/f.txt"], tree.SaclReads.Order(StringComparer.Ordinal));
        Assert.NotNull(At(recs, "a").Before);
    }

    [Fact]
    public void ASaclReadFailureBeforeAWriteFailsThatObjectAndWritesNothing()
    {
        var tree = Flattened();
        tree.SaclReadFails.Add("a/f.txt");
        var (recs, s) = Apply(Usual, tree);
        var f = At(recs, "a/f.txt");
        Assert.Equal(Outcome.Error, f.Outcome);
        Assert.StartsWith("read with SACL before writing:", f.Detail);
        Assert.DoesNotContain(tree.Writes, w => w.Rel == "a/f.txt");
        Assert.Null(s.Stop);
        Assert.False(s.Complete);
    }

    [Fact]
    public void AnObjectThatChangesBetweenTheCompareAndTheWriteIsNotWritten()
    {
        var tree = Flattened();
        tree.BeforeSaclRead = rel =>
        {
            if (rel == "a/f.txt") lock (tree.Objs) tree.Objs[rel] = tree.Objs[rel] with { Dacl = [A(0, Other)] };
        };
        var (recs, s) = Apply(Usual, tree);
        var f = At(recs, "a/f.txt");
        Assert.Equal(Outcome.Error, f.Outcome);
        Assert.Contains("changed between the compare and the write", f.Detail);
        Assert.DoesNotContain(tree.Writes, w => w.Rel == "a/f.txt");
        Assert.Null(s.Stop);
    }

    // ---- checkpoint -------------------------------------------------------------------------------

    sealed class MemCheckpoint(params string[] done) : ICheckpoint
    {
        public readonly HashSet<string> Set = [.. done];
        public readonly Dictionary<string, IReadOnlyList<Ace>> Sacls = new(StringComparer.Ordinal);
        public bool IsDone(string rel) => Set.Contains(rel);
        public void Done(string rel) { lock (Set) Set.Add(rel); }
        public bool TryGetCompareSacl(string rel, out IReadOnlyList<Ace> sacl) => Sacls.TryGetValue(rel, out sacl!);
        public void RecordCompareSacl(string rel, IReadOnlyList<Ace> sacl) { lock (Set) Sacls.TryAdd(rel, sacl); }
    }

    [Fact]
    public void ADirectoryIsCompleteOnlyWhenItsFilesAreRight()
    {
        var tree = Flattened();
        tree.WriteFails.Add("a/f.txt");
        var cp = new MemCheckpoint();
        Apply(Usual, tree, cp: cp);
        Assert.Contains("", cp.Set);
        Assert.Contains("a/b", cp.Set);
        Assert.DoesNotContain("a", cp.Set);
    }

    [Fact]
    public void ResumeSkipsTheFilesOfCompleteDirectories()
    {
        var tree = Flattened();
        tree.Objs["a/f.txt"] = tree.Objs["a/f.txt"] with { Dacl = [] };   // would need a write; the checkpoint says "a" is done
        var (recs, s) = Apply(Usual, tree, cp: new MemCheckpoint("a"));
        Assert.DoesNotContain(recs, r => r.Path == "a/f.txt");
        Assert.Equal(1, s.Resumed);
        Assert.Equal(Outcome.Written, At(recs, "a/b/g.txt").Outcome);     // subdirectories are still walked
    }

    [Fact]
    public void AFileCheckpointRefusesAnotherRunAndDropsATornLine()
    {
        var f = Path.Combine(Path.GetTempPath(), $"smbcp-{Guid.NewGuid():N}");
        try
        {
            Assert.Throws<PlanException>(() => new FileCheckpoint(f, "id", resume: true));
            using (var cp = new FileCheckpoint(f, "id", resume: false))
            {
                Assert.False(File.Exists(f));                            // nothing is written before Start
                Assert.Throws<InvalidOperationException>(() => cp.Done("x"));
                cp.Start();
                cp.Done("a");
                cp.Done("a/b c");
            }
            File.AppendAllText(f, "\"a/tor");
            Assert.Throws<PlanException>(() => new FileCheckpoint(f, "id", resume: false));
            Assert.Throws<PlanException>(() => new FileCheckpoint(f, "other", resume: true));
            using (var again = new FileCheckpoint(f, "id", resume: true))
            {
                Assert.Equal(2, again.Loaded);
                Assert.True(again.IsDone("a/b c"));
                again.Start();
                again.Done("c/d");                                       // must not be glued onto the torn line
            }
            using var third = new FileCheckpoint(f, "id", resume: true);
            Assert.Equal(3, third.Loaded);
            Assert.True(third.IsDone("c/d"));
        }
        finally { File.Delete(f); }
    }

    [Fact]
    public void AFileCheckpointThatAppearsAfterTheCheckIsNotOverwritten()
    {
        var f = Path.Combine(Path.GetTempPath(), $"smbcp-{Guid.NewGuid():N}");
        try
        {
            using var cp = new FileCheckpoint(f, "id", resume: false);
            File.WriteAllText(f, "someone else's\n");
            Assert.Throws<IOException>(cp.Start);
            Assert.Equal("someone else's\n", File.ReadAllText(f));
        }
        finally { File.Delete(f); }
    }

    // ---- checkpoint v2 (smb/DESIGN-sacl-write.md 7.1, decision 13) ------------------------------------

    [Fact]
    public void ANewCheckpointGetsTheV2HeaderAndAV1FileIsRefused()
    {
        var f = Path.Combine(Path.GetTempPath(), $"smbcp-{Guid.NewGuid():N}");
        try
        {
            using (var cp = new FileCheckpoint(f, "id", resume: false))
            {
                cp.Start();
                cp.Done("a");
            }
            Assert.StartsWith("permissionreset-smb checkpoint v2 ", File.ReadLines(f).First());
            using var again = new FileCheckpoint(f, "id", resume: true);
            Assert.Equal(1, again.Loaded);

            var v1 = f + "-v1";
            File.WriteAllText(v1, "permissionreset-smb checkpoint v1 id\n\"a\"\n");
            var e = Assert.Throws<PlanException>(() => new FileCheckpoint(v1, "id", resume: true));
            Assert.Contains("checkpoint v1", e.Message);
            Assert.Contains("never resumes a v1 checkpoint", e.Message);
            Assert.Contains("--resume", e.Message);
            File.Delete(v1);
        }
        finally { File.Delete(f); File.Delete(f + "-v1"); }
    }

    [Fact]
    public void ACheckpointWithAChangedRootSaclProtectedIsRefused()
    {
        var f = Path.Combine(Path.GetTempPath(), $"smbcp-{Guid.NewGuid():N}");
        const string id = "plan=x root=R root-protected=False root-sacl-protected=False principals=h sai-rule=none";
        try
        {
            using (var cp = new FileCheckpoint(f, id, resume: false)) cp.Start();
            var e = Assert.Throws<PlanException>(() => new FileCheckpoint(f, id.Replace("root-sacl-protected=False", "root-sacl-protected=True"), resume: true));
            Assert.Contains("belongs to another run", e.Message);
            Assert.Contains("--root-sacl-protected", e.Message);
            using var original = new FileCheckpoint(f, id, resume: true);   // the right identity still loads
            Assert.Equal(0, original.Loaded);
        }
        finally { File.Delete(f); }
    }

    [Fact]
    public void CompareSaclRecordsRoundTripThroughAResume()
    {
        var f = Path.Combine(Path.GetTempPath(), $"smbcp-{Guid.NewGuid():N}");
        var aces = new List<Ace>
        {
            new(AceTypes.Audit, 0x1b, 1179817, "S-1-1-0"),
            new(AceTypes.Audit, 0x5b, 0x1f01ff, "S-1-5-21-1-2-3-1001"),
        };
        try
        {
            using (var cp = new FileCheckpoint(f, "id", resume: false))
            {
                Assert.Throws<InvalidOperationException>(() => cp.RecordCompareSacl("x", []));
                cp.Start();
                cp.Done("a");
                cp.RecordCompareSacl("", aces);
                cp.RecordCompareSacl("", [new Ace(AceTypes.Allow, 0, 1, Other)]);   // first wins
                cp.RecordCompareSacl("e", []);                                       // S:AI empty
            }
            File.AppendAllText(f, "{\"dir\":\"tor");                              // a torn record line
            using var again = new FileCheckpoint(f, "id", resume: true);
            Assert.Equal(1, again.Loaded);
            Assert.True(again.IsDone("a"));
            Assert.True(again.TryGetCompareSacl("", out var got));
            Assert.Equal(aces, got);                                                       // ACE fields exact
            Assert.True(again.TryGetCompareSacl("e", out var empty));
            Assert.Empty(empty);
            Assert.False(again.TryGetCompareSacl("tor", out _));                         // dropped
            // Done lines and records mix, and a duplicate record is not written again.
            Assert.Contains(File.ReadLines(f), l => l.StartsWith("{\"dir\":"));
            int lines = File.ReadLines(f).Count();
            again.Start();
            again.RecordCompareSacl("", [new Ace(AceTypes.Allow, 0, 1, Other)]);
            Assert.Equal(lines, File.ReadLines(f).Count());
            Assert.True(again.TryGetCompareSacl("", out var kept));
            Assert.Equal(aces, kept);
        }
        finally { File.Delete(f); }
    }

    sealed class FailingCheckpoint : ICheckpoint
    {
        public bool IsDone(string rel) => false;
        public void Done(string rel) => throw new IOException("There is not enough space on the disk.");
        public bool TryGetCompareSacl(string rel, out IReadOnlyList<Ace> sacl) { sacl = []; return false; }
        public void RecordCompareSacl(string rel, IReadOnlyList<Ace> sacl) => throw new IOException("There is not enough space on the disk.");
    }

    [Fact]
    public void ACheckpointThatCannotBeWrittenStopsTheRun()
    {
        var tree = Flattened();
        var (_, s) = Apply(Usual, tree, cp: new FailingCheckpoint());
        Assert.Contains("checkpoint", s.Stop);
        Assert.Contains("not enough space", s.Stop);
        Assert.False(s.Complete);
    }

    // ---- preflight --------------------------------------------------------------------------------

    static FakeTree ProbeTree() => new(new() { [""] = new(true, DirWant, true) });

    static void NoProbeLeft(FakeTree t) => Assert.DoesNotContain(t.Objs.Keys, k => k.Contains(Preflight.Prefix));

    [Fact]
    public void ThePreflightPassesAndRemovesItsProbe()
    {
        var t = ProbeTree();
        var r = Preflight.Run(t, "", DirInherited);
        Assert.True(r.Passed, r.Detail);
        Assert.StartsWith(Preflight.Prefix, r.Probe);
        NoProbeLeft(t);
        Assert.Contains(t.Writes, w => w.Info == (SecurityInformation.Sacl | SecurityInformation.ProtectedSacl));
    }

    [Fact]
    public void ThePreflightProbesAnUnprotectedWriteWithInheritedAces()
    {
        var t = ProbeTree();
        var r = Preflight.Run(t, "", DirWant, name: "p");
        Assert.True(r.Passed, r.Detail);
        Assert.Contains(t.Writes, w => w.Rel == "p/d" && w.Info == (SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl));
        Assert.Equal(Control.DaclAutoInherited, t.SentControl["p/d"] & (Control.DaclAutoInherited | Control.DaclProtected));
        Assert.Contains("unprotected explicit+inherited write read back exactly", r.Detail);
    }

    [Fact]
    public void ThePreflightRefusesAnArrayThatReordersAnUnprotectedWrite()
    {
        var t = ProbeTree();
        t.AfterWrite = rel =>
        {
            if (rel == "p/d") t.Objs[rel] = t.Objs[rel] with { Dacl = [.. t.Objs[rel].Dacl!.Reverse()] };
        };
        var r = Preflight.Run(t, "", DirWant, name: "p");
        Assert.False(r.Passed);
        Assert.StartsWith("probe child p/d, written unprotected with explicit and inherited ACEs: the DACL read back differs", r.Detail);
        NoProbeLeft(t);
    }

    [Fact]
    public void ThePreflightRefusesAnArrayThatLeavesAutoInheritClearOnAnUnprotectedWrite()
    {
        var t = ProbeTree();
        t.AfterWrite = rel =>
        {
            if (rel == "p/d") t.Objs[rel] = t.Objs[rel] with { ExtraControl = 0 };
        };
        var r = Preflight.Run(t, "", DirWant, name: "p");
        Assert.False(r.Passed);
        Assert.Contains("DaclAutoInherited is clear after an unprotected DACL write", r.Detail);
        NoProbeLeft(t);
    }

    [Fact]
    public void ThePreflightRefusesAnArrayThatInheritsDifferently()
    {
        var t = ProbeTree();
        t.ArrayInherit = (p, isDir) => Inheritance.Inherit(p, isDir).Select(a => a with { Mask = a.Mask | 0x2 }).ToList();
        var r = Preflight.Run(t, "", DirWant);
        Assert.False(r.Passed);
        Assert.Contains("inheritance function disagrees", r.Detail);
        NoProbeLeft(t);
    }

    [Fact]
    public void ThePreflightRefusesWhenAuditAcesAreNotKept()
    {
        var t = ProbeTree();
        t.DropSacl = true;
        var r = Preflight.Run(t, "", DirWant);
        Assert.False(r.Passed);
        Assert.Contains("audit", r.Detail);
        NoProbeLeft(t);
    }

    [Fact]
    public void ThePreflightReportsAProbeItCouldNotRemove()
    {
        var t = ProbeTree();
        t.DeleteFails.Add("p/d");
        var r = Preflight.Run(t, "", DirWant, name: "p");
        Assert.False(r.Passed);
        Assert.Contains("could not be removed: p/d", r.Detail);
    }

    // The probe's third write to its directory is the cleanup DACL (after the DACL and SACL writes).
    static FakeTree CleanupCorrupted()
    {
        var t = ProbeTree();
        int n = 0;
        t.AfterWrite = rel =>
        {
            if (rel == "p" && ++n == 3) t.Objs["p"] = t.Objs["p"] with { Dacl = [] };
        };
        return t;
    }

    [Fact]
    public void ThePreflightReadsBackItsCleanupDaclAndLeadsWithItWhenTheProbeStays()
    {
        var t = CleanupCorrupted();
        t.DeleteFails.Add("p");
        var r = Preflight.Run(t, "", DirWant, name: "p");
        Assert.False(r.Passed);
        Assert.StartsWith("the cleanup DACL on p read back differently:", r.Detail);
        Assert.Contains("could not be removed: p", r.Detail);
    }

    [Fact]
    public void ACleanupDaclThatDoesNotReadBackStillPassesWhenTheProbeIsGone()
    {
        var t = CleanupCorrupted();
        var r = Preflight.Run(t, "", DirWant, name: "p");
        Assert.True(r.Passed, r.Detail);
        NoProbeLeft(t);
    }

    [Fact]
    public void ThePreflightRefusesAMissingProbeParent()
    {
        var t = ProbeTree();
        var r = Preflight.Run(t, "nope", DirWant);
        Assert.False(r.Passed);
        Assert.DoesNotContain(t.Objs.Keys, k => k.StartsWith("nope"));
    }
}
