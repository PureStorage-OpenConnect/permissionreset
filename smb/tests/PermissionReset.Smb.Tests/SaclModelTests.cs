using PermissionReset.Smb.Core;
using static PermissionReset.Smb.Tests.CheckerTests;

namespace PermissionReset.Smb.Tests;

// The SACL model (smb/DESIGN-sacl-write.md, sections 3, 3.1, 4.1, 4.3 and 4.5) against FakeTree's
// array behavior (K9, K10, K11, K13, K16): what a read reports, what a write stores, and what
// follows a parent's SACL change.
public class SaclModelTests
{
    const string Users = "S-1-5-21-1-2-3-1001", Admins = "S-1-5-21-1-2-3-1002", Other = "S-1-5-21-1-2-3-1003";
    const byte OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, ID = AceFlags.Inherited,
        SA = AceFlags.SuccessfulAccess, FA = AceFlags.FailedAccess;

    // The spec guide's audit shape: an fd ACE on the directory, its plain form on the file.
    static readonly Ace AuditFd = new(AceTypes.Audit, OI | CI | SA | FA, 0x1, Users);
    static readonly Ace AuditFdOther = new(AceTypes.Audit, OI | CI | SA | FA, 0x1, Other);
    static readonly Ace AuditDirId = new(AceTypes.Audit, ID | OI | CI | SA | FA, 0x1, Users);
    static readonly Ace AuditFileId = new(AceTypes.Audit, ID | SA | FA, 0x1, Users);

    static Descriptor Read(FakeTree t, string rel) => Descriptor.Decode(t.Read(rel, withSacl: true).Descriptor);

    static void WriteSacl(FakeTree t, string rel, bool prot, IReadOnlyList<Ace> aces, ushort? control = null) =>
        t.Write(rel, SaclModel.WriteInfo(prot), DescriptorBuilder.Build(control ?? SaclModel.WriteControl(prot), null, null, aces, null));

    // ---- K9: FlashArray always stores a present SACL ---------------------------------------------

    [Fact]
    public void ANeverWrittenSaclReadsPresentEmptyWithAutoInherit()
    {
        // K9: the array never reports an absent SACL; an object whose SACL was never written reads
        // S:AI empty. A read that does not ask for the SACL still gets none (the DACL-only
        // compare read is unchanged).
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true), ["f.txt"] = new(false, FileInherited, false) });
        var d = Read(tree, "f.txt");
        Assert.NotNull(d.Sacl);
        Assert.Empty(d.Sacl!.Aces);
        Assert.NotEqual(0, d.Control & Control.SaclPresent);
        Assert.NotEqual(0, d.Control & Control.SaclAutoInherited);
        Assert.Equal(0, d.Control & Control.SaclProtected);
        Assert.Null(Descriptor.Decode(tree.Read("f.txt", withSacl: false).Descriptor).Sacl);
    }

    [Fact]
    public void AnEmptyProtectedWriteReadsBackPresentEmptyProtected()
    {
        // sacl: [] is present, empty and protected (2.3, decision 2), and reads back exactly so
        // (K9), which is what makes it converge.
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true) });
        WriteSacl(tree, "", prot: true, []);
        var d = Read(tree, "");
        Assert.NotNull(d.Sacl);
        Assert.Empty(d.Sacl!.Aces);
        Assert.NotEqual(0, d.Control & Control.SaclProtected);
        Assert.Equal(0, d.Control & Control.SaclAutoInherited);
        var desired = new Desired(Form.Protected, [], true);
        Assert.Null(SaclModel.Matches(desired, d.Sacl, (d.Control & Control.SaclProtected) != 0));
    }

    [Fact]
    public void AnAbsentStoredSaclNeverEqualsPresentEmptyProtected()
    {
        // 3.1: absent is the normal state and means no auditing, but it is not present-empty S:P,
        // so sacl: [] writes a never-audited object once.
        var empty = new Desired(Form.Protected, [], true);
        Assert.Contains("present, empty, protected", SaclModel.Matches(empty, null, storedProtected: false));
        var some = new Desired(Form.Protected, [new Ace(AceTypes.Audit, SA, 0x1, Users)], true);
        Assert.Equal("the stored SACL is absent", SaclModel.Matches(some, null, storedProtected: false));
    }

    // ---- storing and the control bits -------------------------------------------------------------

    [Fact]
    public void TheArrayStoresExactlyTheSaclWritten()
    {
        // F1's SACL analogue (K4): the array stores exactly the SACL written, order and flags, and
        // does not merge in the parent's inheritable audit ACEs.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditFd], ExtraControl: Control.SaclAutoInherited),
            ["f.txt"] = new(false, FileInherited, false),
        });
        var aces = new[] { new Ace(AceTypes.Audit, SA, 0x1, Users), new Ace(AceTypes.Audit, FA, 0x2, Admins) };
        WriteSacl(tree, "f.txt", prot: true, aces);
        Assert.Equal(aces, Read(tree, "f.txt").Sacl!.Aces.Select(a => Ace.FromView(a)!.Value));
    }

    [Fact]
    public void TheProtectionFlagDecidesTheStoredAutoInheritBit()
    {
        // K11, 4.3: a protected SACL is stored with S:AI clear and an unprotected one with S:AI
        // set, whatever AI bit the control word carried.
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true), ["f.txt"] = new(false, FileInherited, false) });
        WriteSacl(tree, "f.txt", prot: true, [new Ace(AceTypes.Audit, SA, 0x1, Users)],
            control: Control.SaclPresent | Control.SaclProtected | Control.SaclAutoInherited);
        var d = Read(tree, "f.txt");
        Assert.NotEqual(0, d.Control & Control.SaclProtected);
        Assert.Equal(0, d.Control & Control.SaclAutoInherited);
        WriteSacl(tree, "f.txt", prot: false, [new Ace(AceTypes.Audit, SA, 0x1, Users)],
            control: Control.SaclPresent);
        d = Read(tree, "f.txt");
        Assert.Equal(0, d.Control & Control.SaclProtected);
        Assert.NotEqual(0, d.Control & Control.SaclAutoInherited);
        Assert.True(SaclModel.ExpectedAutoInherited(saclProtected: false));
        Assert.False(SaclModel.ExpectedAutoInherited(saclProtected: true));
    }

    [Fact]
    public void TheWriteStatesItsProtectionTwice()
    {
        // 4.1: SACL_SECURITY_INFORMATION with exactly one protection flag, and the control word to
        // match, never left to the server.
        Assert.Equal(SecurityInformation.Sacl | SecurityInformation.ProtectedSacl, SaclModel.WriteInfo(saclProtected: true));
        Assert.Equal(SecurityInformation.Sacl | SecurityInformation.UnprotectedSacl, SaclModel.WriteInfo(saclProtected: false));
        Assert.Equal(Control.SaclPresent | Control.SaclProtected, SaclModel.WriteControl(saclProtected: true));
        Assert.Equal(Control.SaclPresent | Control.SaclAutoInherited, SaclModel.WriteControl(saclProtected: false));
    }

    // ---- following a parent's SACL change (K10, K16) ----------------------------------------------

    static FakeTree NeverWrittenTree() => new(new()
    {
        [""] = new(true, DirWant, true),
        ["a"] = new(true, DirInherited, false),
        ["a/b"] = new(true, DirInherited, false),
        ["a/b/g.txt"] = new(false, FileInherited, false),
        ["a/f.txt"] = new(false, FileInherited, false),
    });

    [Fact]
    public void ANeverWrittenSubtreeFollowsItsParentsFirstSaclWrite()
    {
        // K10's never-audited case: one SACL write on the parent, and the whole unwritten subtree
        // picks the ACE up as ID (S:AI), with no write to any child. This is the SACL analogue of
        // F3.
        var tree = NeverWrittenTree();
        WriteSacl(tree, "", prot: false, [AuditFd]);
        Assert.Single(tree.Writes);
        Assert.Equal([AuditDirId], tree.Objs["a"].Sacl);
        Assert.Equal([AuditFileId], tree.Objs["a/f.txt"].Sacl);
        Assert.Equal([AuditDirId], tree.Objs["a/b"].Sacl);
        Assert.Equal([AuditFileId], tree.Objs["a/b/g.txt"].Sacl);
        var d = Read(tree, "a/f.txt");
        Assert.NotEqual(0, d.Control & Control.SaclAutoInherited);
        Assert.Equal(0, d.Control & Control.SaclProtected);
    }

    [Fact]
    public void ChildrenThatFollowedOnceFollowLaterChangesToo()
    {
        // K10: objects that picked up a parent's first write follow two later parent changes,
        // as long as their ID part matches what the parent passed down.
        var tree = NeverWrittenTree();
        WriteSacl(tree, "", prot: false, [AuditFd]);
        WriteSacl(tree, "", prot: false, [AuditFdOther]);
        Assert.Equal(2, tree.Writes.Count);
        Assert.Equal([AuditFdOther with { Flags = (byte)(OI | CI | SA | FA | ID) }], tree.Objs["a"].Sacl);
        Assert.Equal([AuditFdOther with { Flags = (byte)(SA | FA | ID) }], tree.Objs["a/b/g.txt"].Sacl);
    }

    [Fact]
    public void AProtectedSaclDoesNotFollowAndBlocksItsChildren()
    {
        // K10: a protected SACL (S:P) does not follow, and blocks its children from a later
        // ancestor change until it is itself written.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirInherited, false, Sacl: [new Ace(AceTypes.Audit, SA, 0x2, Admins)], SaclProtected: true),
            ["a/f.txt"] = new(false, FileInherited, false),
        });
        var before = tree.Objs["a"].Sacl;
        WriteSacl(tree, "", prot: false, [AuditFd]);
        Assert.Equal(before, tree.Objs["a"].Sacl);
        Assert.True(tree.Objs["a"].SaclProtected);
        Assert.Null(tree.Objs["a/f.txt"].Sacl);          // still never written; the write never reached it
    }

    [Fact]
    public void AMismatchingIdPartStaysFrozen()
    {
        // K10's limit: a child whose ID part does not match what its parent passes down keeps its
        // copy through the parent's change (a frozen copy that looks normal in a raw read).
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditFdOther], SaclEverWritten: true),
            ["f.txt"] = new(false, FileInherited, false),   // S:AI empty under a parent already passing ACEs
        });
        WriteSacl(tree, "", prot: false, [AuditFd]);
        Assert.Null(tree.Objs["f.txt"].Sacl);
    }

    [Fact]
    public void AnExplicitOnlySaclDoesNotFollow()
    {
        // No record says an unprotected SACL with explicit audit ACEs and no ID part follows its
        // parent (K10 covers S:AI empty and matching ID parts; the DACL's explicit-only objects do
        // not, Q-EXP). Set-SaclOnly leaves this shape on never-audited objects it touched.
        var own = new Ace(AceTypes.Audit, SA | FA, 0x1, Other);
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["f.txt"] = new(false, FileInherited, false, Sacl: [own], SaclEverWritten: true, ExtraControl: Control.SaclAutoInherited),
        });
        WriteSacl(tree, "", prot: false, [AuditFd]);
        Assert.Equal([own], tree.Objs["f.txt"].Sacl);
    }

    [Fact]
    public void AnNfsAclWrittenObjectDoesNotFollowAndNeitherDoesItsSubtree()
    {
        // K3, K16: an NFS ACL write leaves the object S:P; it and its NFS-ACL-written children
        // stay frozen through a parent change, each needing its own conversion.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirInherited, false, Sacl: [new Ace(AceTypes.Audit, SA, 0x1, Users)]),
            ["a/f.txt"] = new(false, FileInherited, false),
        });
        tree.MarkNfsAclWritten("a");
        var d = Read(tree, "a");
        Assert.NotEqual(0, d.Control & Control.SaclProtected);
        Assert.Equal(0, d.Control & Control.SaclAutoInherited);
        WriteSacl(tree, "", prot: false, [AuditFd]);
        Assert.Single(tree.Writes);
        Assert.Equal([new Ace(AceTypes.Audit, SA, 0x1, Users)], tree.Objs["a"].Sacl);
        Assert.True(tree.Objs["a"].SaclProtected);
        Assert.Null(tree.Objs["a/f.txt"].Sacl);
    }

    [Fact]
    public void AnObjectCreatedUnderTheNewPolicyFollowsLaterChanges()
    {
        // K10, K18: an object created over SMB, and an NFS mode-only create's twin, store the
        // parent's inheritable audit ACEs as ID and follow later parent changes.
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true, Sacl: [AuditFd], SaclEverWritten: true),
        });
        tree.CreateFile("n.txt");
        Assert.Equal([AuditFileId], tree.Objs["n.txt"].Sacl);
        Assert.False(tree.Objs["n.txt"].SaclEverWritten);
        WriteSacl(tree, "", prot: false, [AuditFdOther]);
        Assert.Single(tree.Writes);
        Assert.Equal([AuditFdOther with { Flags = (byte)(SA | FA | ID) }], tree.Objs["n.txt"].Sacl);
    }

    // ---- K13: success is not proof of what was stored ----------------------------------------------

    [Fact]
    public void AWriteThatReturnsSuccessAndDropsAcesIsCaughtByTheReadBack()
    {
        // K13: the array can return success and store nothing of the write; only the read-back
        // tells the truth, so G2's comparison is mandatory.
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true) });
        tree.DropSaclAceTypes.Add(AceTypes.Audit);
        var aces = new[] { new Ace(AceTypes.Audit, SA, 0x1, Users), new Ace(AceTypes.Audit, FA, 0x2, Admins) };
        var before = Descriptor.Decode(tree.Read("", withSacl: true).Descriptor);
        WriteSacl(tree, "", prot: true, aces);          // returns success
        var after = Read(tree, "");
        var d = SaclModel.ReadbackDiff(new Desired(Form.Protected, aces, true), before, after);
        Assert.Contains("stored ACL has 0 ACE(s), want 2", d);
    }

    [Fact]
    public void ObjectAndCallbackAcesVanishSilentlyAcrossAWrite()
    {
        // K13's exact case: object and callback ACEs return rc 0 and are missing on read-back.
        var tree = new FakeTree(new() { [""] = new(true, DirWant, true) });
        tree.DropSaclAceTypes.Add(9);
        var audit = new Ace(AceTypes.Audit, SA, 0x1, Users);
        WriteSacl(tree, "", prot: true, [audit, new Ace(9, 0, 0x1, Users)]);   // a callback-shaped ACE
        Assert.Equal([audit], tree.Objs[""].Sacl);
    }

    // ---- G2 for a SACL write (4.4) -------------------------------------------------------------------

    static Descriptor Sd(ushort control, string? owner = null, string? group = null, IReadOnlyList<Ace>? sacl = null, IReadOnlyList<Ace>? dacl = null) =>
        Descriptor.Decode(DescriptorBuilder.Build((ushort)(control | Control.SelfRelative), owner, group, sacl, dacl));

    [Fact]
    public void ReadbackDiffHoldsTheWholeRestOfTheDescriptor()
    {
        // 4.4/K2: the SACL must read back as written with S:AI per K11, and owner, group, the
        // DACL bytes and every non-SACL control bit must equal the read before.
        var dacAce = new Ace(AceTypes.Allow, 0, 0x1f01ff, Users);
        var prot = new Desired(Form.Protected, [new Ace(AceTypes.Audit, SA, 0x1, Users)], true);
        var before = Sd(Control.DaclAutoInherited, owner: Users, group: Admins, sacl: [], dacl: [dacAce]);
        var after = Sd(Control.SaclProtected | Control.DaclAutoInherited, owner: Users, group: Admins, sacl: prot.Aces, dacl: [dacAce]);
        Assert.Null(SaclModel.ReadbackDiff(prot, before, after));

        Assert.Contains("the DACL changed", SaclModel.ReadbackDiff(prot, before, Sd(Control.SaclProtected | Control.DaclAutoInherited,
            owner: Users, group: Admins, sacl: prot.Aces, dacl: [dacAce with { Mask = 0x1200a9 }])));

        Assert.Contains("owner changed", SaclModel.ReadbackDiff(prot, before, Sd(Control.SaclProtected | Control.DaclAutoInherited,
            owner: Other, group: Admins, sacl: prot.Aces, dacl: [dacAce])));

        Assert.Contains("SaclAutoInherited is set after a protected SACL write", SaclModel.ReadbackDiff(prot, before,
            Sd(Control.SaclProtected | Control.SaclAutoInherited | Control.DaclAutoInherited, owner: Users, group: Admins, sacl: prot.Aces, dacl: [dacAce])));

        Assert.Contains("control changed", SaclModel.ReadbackDiff(prot, before, Sd(Control.SaclProtected | Control.DaclProtected,
            owner: Users, group: Admins, sacl: prot.Aces, dacl: [dacAce])));
    }
}
