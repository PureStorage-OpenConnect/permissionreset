using PermissionReset.Smb.Core;
using static PermissionReset.Smb.Tests.CheckerTests;

namespace PermissionReset.Smb.Tests;

// saclMode in the walk (smb/DESIGN-sacl-write.md, sections 2.3, 3.2, 4.1, 4.2, 4.4, 4.5 and 4.6):
// the schema 3 compare read covers the SACL, records carry SaclForm and the two part outcomes,
// followers under a newly audited directory are predicted and not written, the pre-run freeze
// against G1-SACL, the two-write order with its pre-write checks, the per-part refusals, and the
// dacl-first write's byte equality with phase 2. All of it through FakeTree's SACL model (K4,
// K9, K10, K11, K16).
public class SaclWalkTests
{
    const byte OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, ID = AceFlags.Inherited,
        SA = AceFlags.SuccessfulAccess, FA = AceFlags.FailedAccess;

    static Ace AU(byte flags, string sid, uint mask = 0x1) => new(AceTypes.Audit, flags, mask, sid);
    static readonly Ace AuditDir = AU(OI | CI | SA | FA, Users);
    static readonly Ace AuditFile = AU(SA | FA, Users);

    static PlanAce AUP(Ace a) => new("line", 0, 0, a.Type, a.Flags, a.Mask, "", false, a.Sid, "");

    // A schema 3 rule: the phase 2 DACL fields plus a SACL list; a sacl: [] rule carries SaclSet
    // with an empty list, a rule without a sacl: key neither (SaclSet false, list empty).
    static PlanRule SaclRule(string label, string type, string pattern, Ace[]? dacl, Ace[] sacl, bool saclSet = true) =>
        new(label, new PlanMatch(type, pattern), saclSet, dacl is null, dacl is not null, false, false, "", "",
            sacl.Select(AUP).ToList(), dacl?.Select(a => PA(a)).ToList());

    static Plan MakeSaclPlan(params PlanRule[] rules) =>
        new(Plan.SmbSaclSchema, "t.yaml", "nfsv4", new PlanExclude(["skip"], ["skip"], []),
            new PlanRule("default", new PlanMatch("", ""), false, false, true, false, false, "", "", [],
                FileWant.Select(a => PA(a)).ToList()), rules);

    // A rule per kind, auditing one fd ACE on directories and the plain ACE on files, with phase
    // 2's DACLs.
    static Plan AuditedPlan() => MakeSaclPlan(
        SaclRule("rule[0]", "directory", "", DirWant, [AuditDir]),
        SaclRule("rule[1]", "file", "", FileWant, [AuditFile]));

    // SMB state of a tree whose ACLs were never written (K9): DACLs right, SACLs S:AI empty.
    static FakeTree NeverAudited() => new(new()
    {
        [""] = new(true, DirWant, true),
        ["a"] = new(true, DirInherited, false),
        ["a/f.txt"] = new(false, FileInherited, false),
    });

    // A root that already passes audit ACEs down (audited before this run), with a never-written
    // child: the pre-run freeze of 3.2 (an NFS ACL write left the parent passing without
    // propagating).
    static FakeTree FreezeTree() => new(new()
    {
        [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
        ["a"] = new(true, DirInherited, false),
        ["a/f.txt"] = new(false, FileInherited, false),
    });

    // x.txt needs both parts: its DACL is explicit-only (a Write) and its SACL is S:P with an
    // audit ACE the rule does not name (a Write in the desired Inherits form).
    static FakeTree TwoPartTree() => new(new()
    {
        [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
        ["x.txt"] = new(false, [A(0, Other)], false, Sacl: [AU(SA | FA, Other)], SaclProtected: true, SaclEverWritten: true),
    });

    static (List<CheckRecord> Records, CheckSummary Summary) Check(Plan plan, FakeTree tree)
    {
        var recs = new List<CheckRecord>();
        var s = new Checker(plan, tree, "root", _ => null).Run(recs.Add);
        return (recs.OrderBy(r => r.Path, StringComparer.Ordinal).ToList(), s);
    }

    static (List<CheckRecord> Records, CheckSummary Summary) Apply(Plan plan, FakeTree tree, WalkOptions? opt = null, ICheckpoint? cp = null)
    {
        var recs = new List<CheckRecord>();
        var s = new Checker(plan, tree, "root", _ => null, opt ?? new WalkOptions(Apply: true)).Run(recs.Add, 1, cp);
        return (recs.OrderBy(r => r.Path, StringComparer.Ordinal).ToList(), s);
    }

    static CheckRecord At(List<CheckRecord> recs, string path) => Assert.Single(recs, r => r.Path == path);

    // ---- schema 2 is untouched -------------------------------------------------------------------

    [Fact]
    public void ASchema2PlanLeavesSaclFieldsAndReadsUntouched()
    {
        var tree = NeverAudited();
        var (recs, s) = Check(Usual, tree);
        Assert.All(recs, r =>
        {
            Assert.Null(r.SaclForm);
            Assert.Null(r.DaclOutcome);
            Assert.Null(r.SaclOutcome);
        });
        Assert.Empty(tree.SaclReads);
        Assert.Equal(0, s.CountSacl(Form.Inherits) + s.CountSacl(Form.ExplicitPlusInherits) + s.CountSacl(Form.Protected));
    }

    // ---- following under a newly audited directory (3.2, K10) --------------------------------------

    [Fact]
    public void CheckPredictsFollowsForANeverWrittenSubtreeUnderANewlyAuditedDirectory()
    {
        var (recs, s) = Check(AuditedPlan(), NeverAudited());
        var root = At(recs, "");
        Assert.Equal(Outcome.Write, root.Outcome);                 // dacl Ok, sacl Write
        Assert.Equal(Form.Protected, root.SaclForm);               // the root's parent passes nothing here
        Assert.Equal(Outcome.Ok, root.DaclOutcome);
        Assert.Equal(Outcome.Write, root.SaclOutcome);
        Assert.Contains("sacl:", root.Detail);
        foreach (var p in new[] { "a", "a/f.txt" })
        {
            var r = At(recs, p);
            Assert.Equal(Outcome.Follows, r.Outcome);              // the array re-derives them (K10)
            Assert.Equal(Form.Inherits, r.SaclForm);
            Assert.Equal(Outcome.Ok, r.DaclOutcome);
            Assert.Equal(Outcome.Follows, r.SaclOutcome);
        }
        Assert.Equal(1, s.CountSacl(Form.Protected));
        Assert.Equal(2, s.CountSacl(Form.Inherits));
        Assert.Equal(1, s.Count(Outcome.Write));               // the root's SACL, nothing else
    }

    [Fact]
    public void ApplyWritesTheParentSaclOnceAndChildrenReadOk()
    {
        var tree = NeverAudited();
        var (recs, s) = Apply(AuditedPlan(), tree);
        Assert.True(s.Complete);
        var root = At(recs, "");
        Assert.Equal(Outcome.Written, root.Outcome);
        Assert.Equal(Outcome.Written, root.SaclOutcome);
        Assert.Equal("sacl", root.Parts);
        Assert.NotNull(root.Before);
        Assert.NotNull(root.After);
        var w = Assert.Single(tree.Writes);
        Assert.Equal("", w.Rel);
        Assert.Equal(SecurityInformation.Sacl | SecurityInformation.ProtectedSacl, w.Info);
        foreach (var p in new[] { "a", "a/f.txt" })
        {
            var r = At(recs, p);
            Assert.Equal(Outcome.Ok, r.Outcome);                   // followed the write, not written
            Assert.Equal(Outcome.Ok, r.SaclOutcome);
        }
        // Exactly what the array was measured to store: the ACE with S:P, S:AI clear (K9, K11).
        var ro = tree.Objs[""];
        Assert.Equal([AuditDir], ro.Sacl);
        Assert.True(ro.SaclProtected);
        Assert.True(ro.SaclEverWritten);
        // A rerun converges.
        var again = Apply(AuditedPlan(), tree);
        Assert.True(again.Summary.Complete);
        Assert.Single(tree.Writes);
    }

    // ---- the pre-run freeze against G1-SACL (3.2, 4.4) ---------------------------------------------

    [Fact]
    public void APreRunFreezeIsWriteInCheckAndWrittenInApplyWithoutG1()
    {
        var (recs, _) = Check(AuditedPlan(), FreezeTree());
        Assert.Equal(Outcome.Ok, At(recs, "").Outcome);            // the root already passes ACEs down
        var a = At(recs, "a");
        Assert.Equal(Outcome.Write, a.Outcome);
        Assert.Equal(Outcome.Write, a.SaclOutcome);
        Assert.Contains("frozen copy from before this run", a.Detail);

        var tree = FreezeTree();
        var (applied, s) = Apply(AuditedPlan(), tree);
        Assert.True(s.Complete);
        var ra = At(applied, "a");
        Assert.Equal(Outcome.Written, ra.Outcome);
        Assert.Equal(Outcome.Written, ra.SaclOutcome);
        Assert.Contains("frozen copy from before this run", ra.Detail);
        var w = Assert.Single(tree.Writes);                        // a's own SACL, the write that makes it dynamic (K10)
        Assert.Equal("a", w.Rel);
        Assert.Equal(SecurityInformation.Sacl | SecurityInformation.UnprotectedSacl, w.Info);
        Assert.Equal(Outcome.Ok, At(applied, "a/f.txt").Outcome);  // it picked the new parent up
    }

    [Fact]
    public void G1SaclStopsApplyWhenAChildShouldHaveFollowedButDidNot()
    {
        // Rig the array: the never-written child does not pick the root's new audit ACEs up. The
        // parent's compare-time SACL passed nothing down, so the child should have followed the
        // run's write (K10): G1-SACL, no override.
        var tree = NeverAudited();
        tree.AfterWrite = rel =>
        {
            if (rel == "") lock (tree.Objs) tree.Objs["a"] = tree.Objs["a"] with { Sacl = null };
        };
        var (recs, s) = Apply(AuditedPlan(), tree);
        Assert.False(s.Complete);
        Assert.StartsWith("G1-SACL:", s.Stop);
        var a = At(recs, "a");
        Assert.Equal(Outcome.Error, a.Outcome);
        Assert.Contains("G1-SACL:", a.Detail);
        Assert.Equal(Outcome.Error, a.SaclOutcome);
        Assert.Single(tree.Writes);                                // the root, before the guard fired
        Assert.DoesNotContain(recs, r => r.Path == "a/f.txt");     // its subtree was not walked
        Assert.Equal(1, s.NotProcessed);
    }

    // ---- kept SACLs (2.3, decision 14) -------------------------------------------------------------

    [Fact]
    public void AFailedSecondWriteRecordsOnlyTheWrittenParts()
    {
        // 4.4: the first write (the SACL, sacl-first) is stored; the record shows the parts that
        // were written, the after image is the read back of what is stored, and the run goes on.
        // x.txt is a file, so done(false) keeps its directory out of the checkpoint.
        var tree = TwoPartTree();
        tree.AfterWrite = rel => tree.WriteFails.Add(rel);
        var (recs, s) = Apply(AuditedPlan(), tree);
        Assert.Null(s.Stop);
        var r = At(recs, "x.txt");
        Assert.Equal(Outcome.Error, r.Outcome);
        Assert.Equal(Outcome.Written, r.SaclOutcome);              // stored, per the read-back
        Assert.Equal(Outcome.Error, r.DaclOutcome);                // refused by the array
        Assert.Equal("sacl", r.Parts);                             // not "sacl,dacl"
        Assert.NotNull(r.After);
        Assert.Single(tree.Writes);
        var cp = new MemCheckpoint();
        var tree2 = TwoPartTree();
        tree2.AfterWrite = rel => tree2.WriteFails.Add(rel);
        var (_, s2) = Apply(AuditedPlan(), tree2, cp: cp);
        Assert.False(s2.Complete);
        Assert.DoesNotContain("", cp.Set);                         // the root's listing held a failed file
    }

    [Fact]
    public void AWriteErrorWithAFailingReadBackIsUnknownAndStopsTheRun()
    {
        // 4.4: a write API error is not proof that nothing changed (K13), so the object is read
        // back; if that read fails too, what is stored is unknown and the run stops.
        var tree = TwoPartTree();
        tree.BeforeSaclRead = rel =>
        {
            // The second SACL read of x.txt is its pre-write read; make the write after it and
            // every read after that fail.
            if (rel == "x.txt" && tree.SaclReads.Count(r => r == "x.txt") == 2)
            {
                tree.WriteFails.Add("x.txt");
                tree.ReadFails.Add("x.txt");
            }
        };
        var (recs, s) = Apply(AuditedPlan(), tree);
        Assert.False(s.Complete);
        Assert.Contains("unknown", s.Stop);
        var r = At(recs, "x.txt");
        Assert.Equal(Outcome.Error, r.Outcome);
        Assert.Contains("unknown", r.Detail);
        Assert.Null(r.Parts);
        Assert.Empty(tree.Writes);
    }

    [Fact]
    public void TheSecondPreWriteCheckCatchesAChangeBetweenTheTwoWrites()
    {
        // 4.2: under sacl-first, the DACL write's pre-write check compares the DACL against the
        // compare-time read; a change between the two writes means nothing more is written, an
        // error, not a guard.
        var tree = TwoPartTree();
        tree.BeforeSaclRead = rel =>
        {
            // The fourth SACL read of x.txt is the second write's pre-write read (compare, first
            // pre-write, first G2 read-back before it): the DACL moved between the two writes.
            if (rel == "x.txt" && tree.SaclReads.Count(r => r == "x.txt") == 4)
                lock (tree.Objs) tree.Objs["x.txt"] = tree.Objs["x.txt"] with { Dacl = [A(0, Admins, 0x1f01ff)] };
        };
        var (recs, s) = Apply(AuditedPlan(), tree);
        Assert.Null(s.Stop);
        var r = At(recs, "x.txt");
        Assert.Equal(Outcome.Error, r.Outcome);
        Assert.Equal(Outcome.Written, r.SaclOutcome);
        Assert.Equal(Outcome.Error, r.DaclOutcome);
        Assert.Contains("changed between the first write and the second", r.Detail);
        Assert.Equal("sacl", r.Parts);
        Assert.Single(tree.Writes);                                // the SACL only
    }

    [Fact]
    public void AProtectedKeptSaclIsKeep()
    {
        var plan = MakeSaclPlan(
            SaclRule("rule[0]", "directory", "", DirWant, [AuditDir]),
            Rule("rule[1]", "file", "", FileWant));                // no sacl: key
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
            ["k.txt"] = new(false, FileInherited, false, Sacl: [AU(SA | FA, Other)], SaclProtected: true, SaclEverWritten: true),
        });
        var r = At(Check(plan, tree).Records, "k.txt");
        Assert.Equal(Outcome.Ok, r.Outcome);                       // the DACL is right, so the record is clean
        Assert.Equal(Outcome.Ok, r.DaclOutcome);
        Assert.Equal(Outcome.Keep, r.SaclOutcome);                 // a rule without sacl: never writes it
        Assert.Null(r.SaclForm);
    }

    [Fact]
    public void AKeptNeverAuditedDirectoryPassesItsParentsNewAuditToItsChildren()
    {
        // 3.2, K10: a kept directory whose SACL is S:AI empty under a root that passes nothing
        // tracks it, so once the root is audited it passes the new ACEs on. Its children are
        // classified against that, not against its empty stored SACL.
        var plan = MakeSaclPlan(
            Rule("rule[k]", "directory", "k", DirWant),               // no sacl: key
            SaclRule("rule[0]", "directory", "", DirWant, [AuditDir]),
            SaclRule("rule[1]", "file", "", FileWant, [AuditFile]));
        FakeTree Tree() => new(new()
        {
            [""] = new(true, DirWant, true),
            ["k"] = new(true, DirInherited, false),
            ["k/f.txt"] = new(false, FileInherited, false),
        });
        var recs = Check(plan, Tree()).Records;
        Assert.Equal(Outcome.Follows, At(recs, "k").SaclOutcome);
        var f = At(recs, "k/f.txt");
        Assert.Equal(Form.Inherits, f.SaclForm);
        Assert.Equal(Outcome.Follows, f.SaclOutcome);
        var tree = Tree();
        var (applied, s) = Apply(plan, tree);
        Assert.Null(s.Stop);
        Assert.Equal(Outcome.Ok, At(applied, "k/f.txt").Outcome);
        Assert.Equal("", Assert.Single(tree.Writes).Rel);           // one root write; the rest followed
    }

    // ---- per-part refusals (4.5, decision 16) -------------------------------------------------------

    [Fact]
    public void AnOpaqueStoredSaclErrorsTheSaclPartWhileTheDaclIsWritten()
    {
        var plan = AuditedPlan();
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
            ["o.txt"] = new(false, [A(0, Other)], false, Sacl: [new Ace(0x11, 0, 0x3, "S-1-16-4096")], SaclProtected: true, SaclEverWritten: true),
        });
        var (recs, s) = Apply(plan, tree);
        Assert.Null(s.Stop);                                       // a refusal, not a guard
        var r = At(recs, "o.txt");
        Assert.Equal(Outcome.Error, r.Outcome);                    // the worse of the two parts
        Assert.Equal(Outcome.Written, r.DaclOutcome);              // the DACL part proceeded
        Assert.Equal(Outcome.Error, r.SaclOutcome);
        Assert.Equal(Form.Inherits, r.SaclForm);
        Assert.Contains("opaque ACE", r.Detail);
        Assert.Contains("dacl:", r.Detail);
        Assert.Contains("; sacl:", r.Detail);                    // both parts' details, combined (4.6)
        var w = Assert.Single(tree.Writes);
        Assert.Equal("o.txt", w.Rel);
        Assert.Equal(SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl, w.Info);
    }

    [Fact]
    public void AKeptDirectoryWithAnOpaqueSaclErrorsItsChildrensSaclParts()
    {
        // 3.2: a kept directory whose stored SACL holds an opaque ACE makes its children's SACL
        // parts Error; their DACL parts are classified and written on their own.
        var plan = MakeSaclPlan(
            SaclRule("rule[0]", "directory", "keep*", DirWant, [], saclSet: false),
            SaclRule("rule[1]", "directory", "", DirWant, [AuditDir]),
            SaclRule("rule[2]", "file", "", FileWant, [AuditFile]));
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
            ["keepme"] = new(true, DirInherited, false, Sacl: [new Ace(0x11, 0, 0x3, "S-1-16-4096")], SaclEverWritten: true),
            ["keepme/f.txt"] = new(false, [A(0, Other)], false),
        });
        var (recs, s) = Apply(plan, tree);
        Assert.Null(s.Stop);
        var dir = At(recs, "keepme");
        Assert.Equal(Outcome.Keep, dir.SaclOutcome);               // the directory itself is kept
        var f = At(recs, "keepme/f.txt");
        Assert.Equal(Outcome.Error, f.Outcome);                    // the SACL part is the worse verdict
        Assert.Equal(Outcome.Written, f.DaclOutcome);              // the DACL part proceeded
        Assert.Equal(Outcome.Error, f.SaclOutcome);
        Assert.Contains("parent's SACL holds an opaque ACE; cannot classify", f.Detail);
        var w = Assert.Single(tree.Writes);
        Assert.Equal("keepme/f.txt", w.Rel);                       // only the DACL went out
        Assert.Equal(SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl, w.Info);
    }

    [Fact]
    public void AnOversizeSaclWritesNothingForThatPart()
    {
        // 4.5's last row: beyond the encoder's 65,535 bytes the SACL write is refused before
        // anything is sent; the DACL part still proceeds.
        var big = Enumerable.Range(0, 2000).Select(i => AU(OI | CI | SA | FA, Users, (uint)(0x1000 + i))).ToArray();
        var plan = MakeSaclPlan(
            SaclRule("rule[0]", "directory", "", DirWant, big),
            SaclRule("rule[1]", "file", "", FileWant, [AuditFile]));
        var tree = new FakeTree(new()
        {
            [""] = new(true, [A(OI | CI, Other)], true),           // DACL differs too
        });
        var (recs, s) = Apply(plan, tree);
        var r = At(recs, "");
        Assert.Equal(Outcome.Error, r.Outcome);
        Assert.Equal(Outcome.Written, r.DaclOutcome);
        Assert.Equal(Outcome.Error, r.SaclOutcome);
        Assert.Contains("encode sacl", r.Detail);
        Assert.Contains("65535", r.Detail);
        Assert.Null(s.Stop);
        var w = Assert.Single(tree.Writes);                        // only the DACL went out
        Assert.Equal("dacl", r.Parts);
        Assert.Equal(SecurityInformation.Dacl | SecurityInformation.ProtectedDacl, w.Info);
    }

    [Fact]
    public void ADirectoryRefusedAtEncodeDropsItsSubtree()
    {
        // 4.5, #92 review Q2: the root's SACL is refused at encode, so the root does not hold
        // what its children would be classified against; its subtree is dropped, as phase 2
        // drops it on any write error. Without the drop f.txt would be written against the
        // root's unwritten desired SACL.
        var big = Enumerable.Range(0, 2000).Select(i => AU(OI | CI | SA | FA, Users, (uint)(0x1000 + i))).ToArray();
        var plan = MakeSaclPlan(
            SaclRule("rule[0]", "directory", "", DirWant, big),
            SaclRule("rule[1]", "file", "", FileWant, [AuditFile]));
        var tree = new FakeTree(new()
        {
            [""] = new(true, [A(OI | CI, Other)], true),
            ["f.txt"] = new(false, [A(0, Other)], false),
        });
        var (recs, s) = Apply(plan, tree);
        Assert.Null(s.Stop);
        var r = At(recs, "");
        Assert.Equal(Outcome.Written, r.DaclOutcome);
        Assert.Equal(Outcome.Error, r.SaclOutcome);
        Assert.DoesNotContain(recs, x => x.Path == "f.txt");
        Assert.Equal("", Assert.Single(tree.Writes).Rel);
        Assert.Equal(1, s.NotProcessed);
    }

    // ---- a sacl:-only directory rule keeps phase 2's DACL refusals (#92 review finding 1) -----------

    static Plan SaclOnlyDirPlan() => MakeSaclPlan(
        SaclRule("rule[k]", "directory", "k", null, [AuditDir]),
        SaclRule("rule[0]", "directory", "", DirWant, [AuditDir]),
        SaclRule("rule[1]", "file", "", FileWant, [AuditFile]));

    [Fact]
    public void AnUnmodeledDaclAceOnASaclOnlyDirectoryIsRefusedBeforeItsSaclIsWritten()
    {
        // k has no acl:, so its children inherit its stored DACL, which holds an ACE type a reset
        // does not model. Its SACL part is a Write (a pre-run freeze under an audited root), but
        // the DACL refusal comes first: nothing is written to k and its subtree is dropped.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
            ["k"] = new(true, [A(OI | CI, Users), new Ace(0x11, 0, 0x3, "S-1-16-4096")], true),
            ["k/f.txt"] = new(false, FileInherited, false),
        });
        var (recs, s) = Apply(SaclOnlyDirPlan(), tree);
        Assert.Null(s.Stop);
        var k = At(recs, "k");
        Assert.Equal(Outcome.Error, k.Outcome);
        Assert.Equal(Outcome.Error, k.DaclOutcome);
        Assert.Equal(Outcome.Error, k.SaclOutcome);
        Assert.Contains("an ACE type a reset does not model", k.Detail);
        Assert.Contains("sacl: not written", k.Detail);
        Assert.DoesNotContain(recs, x => x.Path == "k/f.txt");
        Assert.Empty(tree.Writes);
        Assert.Equal(1, s.NotProcessed);
    }

    [Fact]
    public void AnAbsentDaclOnASaclOnlyDirectoryIsRefusedBeforeItsSaclIsWritten()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
            ["k"] = new(true, null, false),
            ["k/f.txt"] = new(false, FileInherited, false),
        });
        var (recs, s) = Apply(SaclOnlyDirPlan(), tree);
        Assert.Null(s.Stop);
        var k = At(recs, "k");
        Assert.Equal(Outcome.Error, k.SaclOutcome);
        Assert.Contains("its DACL is absent", k.Detail);
        Assert.DoesNotContain(recs, x => x.Path == "k/f.txt");
        Assert.Empty(tree.Writes);
    }

    // ---- the two-write order (4.2) ------------------------------------------------------------------

    [Fact]
    public void SaclFirstAndDaclFirstOrderTheTwoCalls()
    {
        foreach (var (order, first) in new[] { (WriteOrder.SaclFirst, "sacl"), (WriteOrder.DaclFirst, "dacl") })
        {
            var tree = TwoPartTree();
            var (recs, s) = Apply(AuditedPlan(), tree, new WalkOptions(Apply: true, Order: order));
            Assert.True(s.Complete);
            var infos = tree.Writes.Where(w => w.Rel == "x.txt").Select(w => w.Info).ToList();
            Assert.Equal(2, infos.Count);
            Assert.Equal(first == "sacl" ? SecurityInformation.Sacl | SecurityInformation.UnprotectedSacl : SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl, infos[0]);
            Assert.Equal(first == "sacl" ? SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl : SecurityInformation.Sacl | SecurityInformation.UnprotectedSacl, infos[1]);
            Assert.Equal(first == "sacl" ? "sacl,dacl" : "dacl,sacl", At(recs, "x.txt").Parts);
            Assert.Equal(Outcome.Written, At(recs, "x.txt").Outcome);
        }
    }

    [Fact]
    public void DaclFirstSendsPhase2sDaclWriteBytes()
    {
        // 4.2's compatibility rule: under dacl-first the DACL write call and its descriptor bytes
        // are exactly what phase 2 sends for the same object.
        var t2 = TwoPartTree();
        var (_, s2) = Apply(Usual, t2);                            // the same DACL under a schema 2 plan
        Assert.True(s2.Complete);
        var phase2 = Assert.Single(t2.SentWrites, w => w.Rel == "x.txt");
        Assert.Equal(SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl, phase2.Info);

        var t3 = TwoPartTree();
        var (_, s3) = Apply(AuditedPlan(), t3, new WalkOptions(Apply: true, Order: WriteOrder.DaclFirst));
        Assert.True(s3.Complete);
        var daclFirst = Assert.Single(t3.SentWrites.Where(w => w.Rel == "x.txt" && (w.Info & SecurityInformation.Dacl) != 0));
        Assert.Equal(phase2.Info, daclFirst.Info);
        Assert.Equal(phase2.Sd, daclFirst.Sd);
    }

    [Fact]
    public void ThePreWriteCheckCatchesASaclChangeBetweenCompareAndWrite()
    {
        // 4.2: in saclMode the first write's pre-write check covers the SACL rows too. Only the
        // DACL differs here, so the SACL is an untouched part and still a change in it refuses the
        // write.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
            ["x.txt"] = new(false, [A(0, Other)], false, Sacl: [AU(ID | SA | FA, Users)], SaclEverWritten: true),
        });
        tree.BeforeSaclRead = rel =>
        {
            // The second SACL read of x.txt is the pre-write one (the compare's was the first).
            if (rel == "x.txt" && tree.SaclReads.Count(r => r == "x.txt") == 2)
                lock (tree.Objs) tree.Objs["x.txt"] = tree.Objs["x.txt"] with { Sacl = [AU(SA | FA, Other)] };
        };
        var (recs, s) = Apply(AuditedPlan(), tree);
        Assert.Null(s.Stop);                                       // a refusal, not a guard
        var r = At(recs, "x.txt");
        Assert.Equal(Outcome.Error, r.Outcome);
        Assert.Equal(Outcome.Error, r.DaclOutcome);
        Assert.Equal(Outcome.Ok, r.SaclOutcome);                   // the SACL part did not differ
        Assert.Contains("changed between the compare and the write", r.Detail);
        Assert.DoesNotContain(tree.Writes, w => w.Rel == "x.txt");
    }

    // ---- G2 for the SACL write (4.4) -----------------------------------------------------------------

    [Fact]
    public void G2StopsWhenTheSaclReadBackDiffers()
    {
        var tree = FreezeTree();
        tree.AfterWrite = rel =>
        {
            if (rel == "a") lock (tree.Objs) tree.Objs["a"] = tree.Objs["a"] with { Sacl = [.. (tree.Objs["a"].Sacl ?? []), AU(SA | FA, Other, 0x2)] };
        };
        var (recs, s) = Apply(AuditedPlan(), tree);
        Assert.False(s.Complete);
        Assert.StartsWith("G2:", s.Stop);
        Assert.Contains("the SACL read back differs", s.Stop);
        var a = At(recs, "a");
        Assert.Equal(Outcome.Error, a.Outcome);
        Assert.NotNull(a.After);                                   // the read-back is the evidence
        Assert.Single(tree.Writes);
        Assert.DoesNotContain(recs, r => r.Path == "a/f.txt");
    }

    // ---- refusals before any read (2.2) ----------------------------------------------------------------

    [Fact]
    public void APrincipalResolvingToACreatorSidIsRefusedBeforeAnyRead()
    {
        var ace = new PlanAce("line", 0, 0, AceTypes.Audit, (byte)(OI | CI | SA | FA), 0x1, "creator@example.net", false, "", "");
        var rule = new PlanRule("rule[0]", new PlanMatch("directory", ""), true, true, false, false, false, "", "", [ace], null);
        var plan = MakeSaclPlan(rule);
        var tree = NeverAudited();
        var e = Assert.Throws<PlanException>(() => new Checker(plan, tree, "root", n => n == "creator@example.net" ? "S-1-3-0" : null));
        Assert.Contains("creator@example.net", e.Message);
        Assert.Contains("creator SID", e.Message);
        Assert.Empty(tree.SaclReads);
    }

    // ---- sacl: [] (2.3, decision 2) ----------------------------------------------------------------------

    [Fact]
    public void SaclEmptyIsWrittenAsPresentEmptyProtected()
    {
        var plan = MakeSaclPlan(
            SaclRule("rule[0]", "directory", "", DirWant, []),
            SaclRule("rule[1]", "file", "", FileWant, []));
        var (recs, _) = Check(plan, NeverAudited());
        // 2.3: never-audited reads S:AI empty, and neither that nor absent equals present-empty
        // S:P, so every object in scope is written once.
        Assert.All(recs, r =>
        {
            Assert.Equal(Outcome.Write, r.SaclOutcome);
            Assert.Equal(Form.Protected, r.SaclForm);
        });

        var tree = NeverAudited();
        var (applied, s) = Apply(plan, tree);
        Assert.True(s.Complete);
        Assert.All(applied, r => Assert.Equal(Outcome.Written, r.SaclOutcome));
        Assert.All(tree.Writes, w => Assert.Equal(SecurityInformation.Sacl | SecurityInformation.ProtectedSacl, w.Info));
        foreach (var (p, o) in tree.Objs)
        {
            Assert.Equal([], o.Sacl);
            Assert.True(o.SaclProtected, p);
        }
        Assert.All(tree.SentControl.Values, c => Assert.Equal(0, c & (Control.SaclAutoInherited | Control.DaclProtected | Control.DaclAutoInherited)));
    }

    // ---- --root-sacl-protected (3.2, decision 4) -----------------------------------------------------------

    [Fact]
    public void RootSaclProtectedForcesTheRootsSaclForm()
    {
        static FakeTree Tree() => new(new()
        {
            // The root tracks its real parent: without the flag its SACL reads Inherits and is Ok.
            [""] = new(true, DirWant, true, Sacl: [AU(ID | OI | CI | SA | FA, Users)], SaclEverWritten: true),
        });
        var plan = MakeSaclPlan(SaclRule("rule[0]", "directory", "", DirWant, [AuditDir]));
        var r = At(Check(plan, Tree()).Records, "");
        Assert.Equal(Outcome.Ok, r.SaclOutcome);
        Assert.Equal(Form.Inherits, r.SaclForm);

        var tree = Tree();
        var (recs, _) = Apply(plan, tree, new WalkOptions(Apply: true, RootSaclProtected: true));
        var f = At(recs, "");
        Assert.Equal(Form.Protected, f.SaclForm);
        Assert.Equal(Outcome.Written, f.SaclOutcome);
        Assert.True(tree.Objs[""].SaclProtected);
        Assert.Equal([AuditDir], tree.Objs[""].Sacl);
    }

    // ---- the pre-run SACL in memory (7.1, decision 13; #92 review question Q1) -----------------------

    [Fact]
    public void AGrandchildThatShouldHaveFollowedThisRunsWriteStopsOnG1Sacl()
    {
        // P (the root) is written and C follows its write by propagation, so C's fresh read already
        // carries the parent's post-write output. Its grandchild G reads S:AI empty (made to not
        // follow). C's compare-time read is what it passed down before any write — nothing — so G
        // should have followed this run's write and did not: G1-SACL, not a plain Write (#92 review
        // Q1; without the pre-run reconstruction this comes out Write).
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["c"] = new(true, DirInherited, false),
            ["c/g"] = new(true, DirInherited, false),
        });
        tree.AfterWrite = rel =>
        {
            if (rel == "") lock (tree.Objs) tree.Objs["c/g"] = tree.Objs["c/g"] with { Sacl = null };
        };
        var (recs, s) = Apply(AuditedPlan(), tree);
        Assert.False(s.Complete);
        Assert.StartsWith("G1-SACL:", s.Stop);
        Assert.Equal(Outcome.Ok, At(recs, "c").Outcome);           // it followed the write, as the array does (K10)
        var g = At(recs, "c/g");
        Assert.Equal(Outcome.Error, g.Outcome);
        Assert.Contains("G1-SACL:", g.Detail);
        Assert.Equal(Outcome.Error, g.SaclOutcome);
        Assert.Single(tree.Writes);                                // the root, before the guard fired
    }

    // ---- resume in saclMode, checkpoint v2 (7.1, decision 13) ------------------------------------------------

    sealed class MemCheckpoint(params string[] done) : ICheckpoint
    {
        public readonly HashSet<string> Set = [.. done];
        public readonly Dictionary<string, IReadOnlyList<Ace>> Sacls = new(StringComparer.Ordinal);
        public bool IsDone(string rel) => Set.Contains(rel);
        public void Done(string rel) { lock (Set) Set.Add(rel); }
        public bool TryGetCompareSacl(string rel, out IReadOnlyList<Ace> sacl) => Sacls.TryGetValue(rel, out sacl!);
        public void RecordCompareSacl(string rel, IReadOnlyList<Ace> sacl) { lock (Set) Sacls.TryAdd(rel, sacl); }
    }

    // The root after an earlier run wrote its SACL (S:P, ever written), with a never-ACL-written
    // child directory that did not follow (S:AI empty).
    static FakeTree WrittenRoot() => new(new()
    {
        [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
        ["c"] = new(true, DirInherited, false),
    });

    [Fact]
    public void AResumeTellsG1SaclFromTheCheckpointRecord()
    {
        // Run 2 of a run whose P passed nothing down before its write (its record says so). Without
        // the in-memory compare-time read the record is what stops C from reading as a pre-run
        // freeze: C should have followed run 1's write and did not, so the resume stops on G1-SACL.
        var tree = WrittenRoot();
        var cp = new MemCheckpoint();
        cp.Sacls[""] = [];
        var (recs, s) = Apply(AuditedPlan(), tree, cp: cp);
        Assert.False(s.Complete);
        Assert.StartsWith("G1-SACL:", s.Stop);
        var c = At(recs, "c");
        Assert.Equal(Outcome.Error, c.Outcome);
        Assert.Contains("G1-SACL:", c.Detail);
        Assert.Empty(tree.Writes);                               // a guard writes nothing

        // The same tree, a checkpoint with no record for P: the fresh read stands in as the
        // compare-time state (a pre-run freeze: P already passed ACEs down), so C is a plain Write.
        var (again, s2) = Apply(AuditedPlan(), WrittenRoot(), cp: new MemCheckpoint());
        Assert.Null(s2.Stop);
        Assert.Equal(Outcome.Written, At(again, "c").SaclOutcome);
        Assert.Contains("frozen copy from before this run", At(again, "c").Detail);
    }

    [Fact]
    public void AResumeTellsAPreRunFreezeFromTheCheckpointRecord()
    {
        // The record says P passed audit ACEs down before any write of run 1, so C's S:AI empty
        // state predates the run: a plain Write that makes it dynamic (3.2, K10), never a stop.
        var tree = WrittenRoot();
        var cp = new MemCheckpoint();
        cp.Sacls[""] = [AuditDir];
        var (recs, s) = Apply(AuditedPlan(), tree, cp: cp);
        Assert.True(s.Complete);
        var c = At(recs, "c");
        Assert.Equal(Outcome.Written, c.Outcome);
        Assert.Equal(Outcome.Written, c.SaclOutcome);
        Assert.Contains("frozen copy from before this run", c.Detail);
        Assert.Equal(SecurityInformation.Sacl | SecurityInformation.UnprotectedSacl, Assert.Single(tree.Writes).Info);
    }

    [Fact]
    public void SaclModeResumeSkipsTheFilesOfCompleteDirectories()
    {
        // 7.1: done(ok) already requires both part verdicts right, so a done directory's files are
        // right on every part and the resume skips them without reading, as phase 2 does.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
            ["d"] = new(true, DirInherited, false, Sacl: [AU(ID | OI | CI | SA | FA, Users)], SaclEverWritten: true),
            ["d/f.txt"] = new(false, FileInherited, false, Sacl: [AU(ID | OI | SA | FA, Users)], SaclEverWritten: true),
        });
        var (recs, s) = Apply(AuditedPlan(), tree, cp: new MemCheckpoint("d"));
        Assert.True(s.Complete);
        Assert.Equal(1, s.Resumed);
        Assert.DoesNotContain(recs, r => r.Path == "d/f.txt");
        Assert.DoesNotContain(tree.SaclReads, r => r == "d/f.txt");   // skipped without being read
        Assert.Equal(Outcome.Ok, At(recs, "d").Outcome);              // the directory is still visited
    }

    [Fact]
    public void APersistentFileErrorKeepsItsDirectoryIncompleteAndTheResumeRereadsIt()
    {
        // G8 (decision 19, 7.1's PS-11 rule): a file whose read fails keeps its directory out of
        // the checkpoint, so the resume reads the file again — as the Go tool's PS-11 rule does —
        // and nothing is skipped silently.
        FakeTree Tree() => new(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
            ["e"] = new(true, DirInherited, false, Sacl: [AU(ID | OI | CI | SA | FA, Users)], SaclEverWritten: true),
            ["e/bad.txt"] = new(false, FileInherited, false),
        });
        var cp = new MemCheckpoint();
        var tree = Tree();
        tree.SaclReadFails.Add("e/bad.txt");
        var (_, s1) = Apply(AuditedPlan(), tree, cp: cp);
        Assert.False(s1.Complete);
        Assert.DoesNotContain("e", cp.Set);                     // a directory is done only when its own files are right
        Assert.Contains("", cp.Set);                            // the root's own files are all right, so it is done

        var tree2 = Tree();
        tree2.SaclReadFails.Add("e/bad.txt");
        var (recs2, s2) = Apply(AuditedPlan(), tree2, cp: cp);
        Assert.False(s2.Complete);
        Assert.Equal(0, s2.Resumed);
        Assert.Equal(Outcome.Error, At(recs2, "e/bad.txt").Outcome);
        Assert.Equal(1, tree2.SaclReads.Count(r => r == "e/bad.txt")); // re-read, like a fresh run
    }
}
