using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

// The per-object SACL part verdict (smb/DESIGN-sacl-write.md, sections 3, 3.2, 4.4, 4.5 and 4.6):
// the three-form desired SACL, the follows model with its FlashArray carve-outs (never-written
// objects follow, protected and mismatching-ID ones do not), the pre-run freeze against G1-SACL,
// the opaque per-part refusal, Keep under no sacl: key, and the two-part merge.
public class SaclClassifierTests
{
    const string Users = "S-1-5-21-1-2-3-1001", Admins = "S-1-5-21-1-2-3-1002", Other = "S-1-5-21-1-2-3-1003";
    const byte OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, ID = AceFlags.Inherited,
        SA = AceFlags.SuccessfulAccess, FA = AceFlags.FailedAccess;

    static Ace AU(byte flags, string sid, uint mask = 0x1) => new(AceTypes.Audit, flags, mask, sid);

    // A directory rule's fd audit ACE and what a file under it wants and inherits.
    static readonly Ace AuditFd = AU(OI | CI | SA | FA, Users);
    static readonly Ace AuditFile = AU(SA | FA, Users);
    static readonly Ace[] FileInherited = [AU(ID | SA | FA, Users)];

    static AclView View(params Ace[] aces) =>
        new(2, aces.Select(a => new AceView("Audit", (byte)a.Type, a.Flags, AceView.DescribeFlags(a.Flags), a.Mask, a.Sid, null)).ToList());

    static readonly AclView CallbackAce = new(2, [new AceView("0x09", 0x09, 0, [], null, null, "AAAA")]);

    static SaclPart Classify(bool apply, IReadOnlyList<Ace>? want, IReadOnlyList<Ace> inherited,
        IReadOnlyList<Ace>? now = null, IReadOnlyList<Ace>? atCompare = null,
        AclView? stored = null, bool storedProtected = false, bool ancestorWrites = false,
        bool isRoot = false, bool rootSaclProtected = false) =>
        SaclClassifier.Classify(isRoot, apply, rootSaclProtected, want, inherited,
            now ?? atCompare ?? [], atCompare ?? now ?? [], stored, storedProtected, ancestorWrites);

    // ---- the three forms (section 3; the DACL model's F-shape analogues) -----------------------------

    [Fact]
    public void InheritsMatchesReadsOkAndAProtectionMismatchIsAWrite()
    {
        var ok = Classify(apply: false, [AuditFile], FileInherited, stored: View(AU(ID | SA | FA, Users)));
        Assert.Equal(Form.Inherits, ok.Form);
        Assert.Equal(Outcome.Ok, ok.Outcome);
        var wrong = Classify(apply: false, [AuditFile], FileInherited, stored: View(AU(ID | SA | FA, Users)), storedProtected: true);
        Assert.Equal(Outcome.Write, wrong.Outcome);
        Assert.Contains("want unprotected", wrong.Detail);
        // A flag difference is compared raw, ID included (3.1).
        var explicitStored = Classify(apply: false, [AuditFile], FileInherited, stored: View(AU(SA | FA, Users)));
        Assert.Equal(Outcome.Write, explicitStored.Outcome);
        Assert.Contains("ACE 0", explicitStored.Detail);
    }

    [Fact]
    public void ExplicitPlusInheritsAndProtectedForms()
    {
        var leading = AU(SA, Other);
        var epi = Classify(apply: false, [leading, AuditFile], FileInherited, stored: View(leading, AU(ID | SA | FA, Users)));
        Assert.Equal(Form.ExplicitPlusInherits, epi.Form);
        Assert.Equal(Outcome.Ok, epi.Outcome);
        // A rule that differs from what it would inherit is Protected (section 3, as on the DACL).
        var prot = Classify(apply: false, [AU(SA | FA, Admins)], FileInherited, stored: View(AU(SA | FA, Admins)), storedProtected: true);
        Assert.Equal(Form.Protected, prot.Form);
        Assert.Equal(Outcome.Ok, prot.Outcome);
        Assert.Equal(Outcome.Write, Classify(apply: false, [AU(SA | FA, Admins)], FileInherited, stored: View(AU(SA | FA, Admins))).Outcome);
    }

    [Fact]
    public void SaclEmptyIsAlwaysProtectedEmptyAndAbsentDiffers()
    {
        // 2.3, decision 2: sacl: [] is always present-empty S:P, whatever the parent passes.
        var d = SaclModel.DesiredForSacl([], FileInherited, isRoot: false, rootSaclProtected: false);
        Assert.Equal(Form.Protected, d.Form);
        Assert.Empty(d.Aces);
        Assert.True(d.Protected);
        // A never-audited SACL (S:AI empty, K9) is written once (3.1); a stored S:P empty is right.
        var write = Classify(apply: false, [], FileInherited, stored: View());
        Assert.Equal(Form.Protected, write.Form);
        Assert.Equal(Outcome.Write, write.Outcome);
        Assert.Contains("want protected", write.Detail);
        Assert.Equal(Outcome.Ok, Classify(apply: false, [], FileInherited, stored: View(), storedProtected: true).Outcome);
        var absent = Classify(apply: false, [], FileInherited, stored: null);
        Assert.Equal(Outcome.Write, absent.Outcome);
        Assert.Contains("present, empty, protected", absent.Detail);
    }

    [Fact]
    public void RootSaclProtectedForcesTheRootsForm()
    {
        // 3.2, decision 4: --root-sacl-protected forces Protected, independent of --root-protected.
        var r = Classify(apply: false, [AuditFile], FileInherited, isRoot: true, rootSaclProtected: true,
            stored: View(AuditFile), storedProtected: true);
        Assert.Equal(Form.Protected, r.Form);
        Assert.Equal(Outcome.Ok, r.Outcome);
    }

    // ---- following (3.2, K10, K16) ----------------------------------------------------------------

    [Fact]
    public void ANeverWrittenSaclFollowsOnceItsParentPassesAces()
    {
        // 3.2: an absent SACL, or S:AI empty under a parent whose compare-time SACL passes nothing
        // down, counts as following when the object's form is Inherits and the parent will pass
        // ACEs down (K10).
        Assert.Equal(Outcome.Follows, Classify(apply: false, [AuditFile], FileInherited, atCompare: [], stored: View(), ancestorWrites: true).Outcome);
        Assert.Equal(Outcome.Follows, Classify(apply: false, [AuditFile], FileInherited, atCompare: [], stored: null, ancestorWrites: true).Outcome);
        // No ancestor write, nothing to follow: the object itself differs.
        Assert.Equal(Outcome.Write, Classify(apply: false, [AuditFile], FileInherited, atCompare: [], stored: View()).Outcome);
        // In apply, after the parent's write, it is read already right (K10's propagation).
        Assert.Equal(Outcome.Ok, Classify(apply: true, [AuditFile], FileInherited, atCompare: [], stored: View(AU(ID | SA | FA, Users))).Outcome);
    }

    [Fact]
    public void AProtectedOrMismatchingSaclNeverFollows()
    {
        // K10: a protected SACL does not follow; under a sacl: rule it is a Write. A mismatching
        // ID part is a frozen copy.
        var prot = Classify(apply: false, [AuditFile], FileInherited, atCompare: [], stored: View(), storedProtected: true, ancestorWrites: true);
        Assert.Equal(Outcome.Write, prot.Outcome);
        var frozen = Classify(apply: false, [AuditFile], FileInherited, atCompare: [AU(ID | SA | FA, Admins)],
            stored: View(AU(ID | SA | FA, Other)), ancestorWrites: true);
        Assert.Equal(Outcome.Write, frozen.Outcome);
        Assert.Contains("frozen copy", frozen.Detail);
    }

    [Fact]
    public void AMatchingIdPartFollowsTheParentsChange()
    {
        // K10: an object whose ID part matches what its parent passed down at compare time follows
        // the parent's change, no write needed.
        var id = AU(ID | OI | CI | SA | FA, Admins);
        Assert.Equal(Outcome.Follows, Classify(apply: false, [AuditFile], FileInherited, atCompare: [id], stored: View(id), ancestorWrites: true).Outcome);
    }

    // ---- the pre-run freeze against G1-SACL (3.2, 4.4) ------------------------------------------------

    static readonly Ace[] ParentPassed = [AU(ID | SA | FA, Admins)];

    [Fact]
    public void AnSaiEmptySaclUnderAnAlreadyAuditedParentIsAPlainWrite()
    {
        // 3.2: S:AI empty under a parent whose compare-time SACL already passed ACEs down is a
        // pre-run freeze, not a failure of this run's propagation: under a sacl: rule a plain
        // Write, in check and in apply, and the run does not stop (no guard).
        var check = Classify(apply: false, [AuditFile], FileInherited, atCompare: ParentPassed, stored: View());
        Assert.Equal(Outcome.Write, check.Outcome);
        Assert.Contains("frozen copy from before this run", check.Detail);
        var apply = Classify(apply: true, [AuditFile], FileInherited, atCompare: ParentPassed, stored: View());
        Assert.Equal(Outcome.Write, apply.Outcome);
        Assert.False(apply.Guard);
        Assert.Contains("frozen copy from before this run", apply.Detail);
    }

    [Fact]
    public void AnSaiEmptySaclThatShouldHaveFollowedThisRunIsG1()
    {
        // 4.4: the parent's compare-time SACL passed nothing down, this run wrote the parent, and
        // the child still reads S:AI empty — it should have followed (K10). G1-SACL, no override.
        var r = Classify(apply: true, [AuditFile], FileInherited, atCompare: [], stored: View());
        Assert.Equal(Outcome.Error, r.Outcome);
        Assert.True(r.Guard);
        Assert.Contains("G1-SACL", r.Detail);
    }

    [Fact]
    public void AFrozenIdCopyIsG1InApply()
    {
        // 4.4: a non-empty frozen ID copy, one that predates the run included, stops apply.
        var r = Classify(apply: true, [AuditFile], FileInherited, atCompare: ParentPassed, stored: View(ParentPassed));
        Assert.Equal(Outcome.Error, r.Outcome);
        Assert.True(r.Guard);
        Assert.Contains("G1-SACL", r.Detail);
        Assert.Contains("frozen copy", r.Detail);
    }

    // ---- kept SACLs: a rule with no sacl: key (2.3, 3.2, decision 14) ----------------------------------

    [Fact]
    public void AProtectedSaclUnderNoSaclKeyIsKeep()
    {
        // Decision 14: a protected SACL with explicit ACEs under a rule with no sacl: key is Keep,
        // never a Write.
        var r = Classify(apply: false, want: null, FileInherited, stored: View(AU(SA | FA, Admins, 0x2)), storedProtected: true);
        Assert.Equal(Outcome.Keep, r.Outcome);
        Assert.Null(r.Form);
    }

    [Fact]
    public void ATrackingKeptSaclIsOkOrFollows()
    {
        // 2.3: an object whose SACL tracks what its parent passes down is Follows (dry run) or Ok
        // (after the parent's write).
        var dirId = AU(ID | OI | CI | SA | FA, Users);
        Assert.Equal(Outcome.Ok, Classify(apply: false, want: null, [dirId], now: [dirId], stored: View(dirId)).Outcome);
        Assert.Equal(Outcome.Follows, Classify(apply: false, want: null, [AuditFdOther], now: [dirId], atCompare: [dirId], stored: View(dirId), ancestorWrites: true).Outcome);
        Assert.Equal(Outcome.Ok, Classify(apply: true, want: null, [dirId], now: [dirId], atCompare: [dirId], stored: View(dirId)).Outcome);
        // S:AI empty under a parent that passes nothing tracks too (K10).
        Assert.Equal(Outcome.Ok, Classify(apply: false, want: null, [], now: [], stored: View()).Outcome);
        Assert.Equal(Outcome.Follows, Classify(apply: false, want: null, FileInherited, now: [], atCompare: [], stored: View(), ancestorWrites: true).Outcome);
    }

    [Fact]
    public void AFrozenKeptSaclIsAnErrorAndG1Applies()
    {
        // 2.3: an object holding a frozen ID audit copy is an error; 4.4's G1-SACL fires on it in
        // apply, on no-sacl: objects too. The S:AI-empty pre-run freeze is an error in check and
        // apply, and the run does not stop (3.2).
        var frozen = Classify(apply: false, want: null, [AuditFd], now: [AU(SA | FA, Users)], stored: View(AU(ID | SA | FA, Admins)));
        Assert.Equal(Outcome.Error, frozen.Outcome);
        Assert.False(frozen.Guard);
        Assert.Contains("frozen copy", frozen.Detail);
        Assert.True(Classify(apply: true, want: null, [AuditFd], now: [AuditFd], stored: View(AU(ID | SA | FA, Admins))).Guard);
        var empty = Classify(apply: true, want: null, [AuditFd], now: [AuditFd], atCompare: [AuditFd], stored: View());
        Assert.Equal(Outcome.Error, empty.Outcome);
        Assert.False(empty.Guard);
        var g1 = Classify(apply: true, want: null, FileInherited, now: FileInherited, atCompare: [], stored: View());
        Assert.Equal(Outcome.Error, g1.Outcome);
        Assert.True(g1.Guard);
    }

    // ---- the opaque per-part refusal (4.5, K8, decision 16) --------------------------------------------

    static readonly Ace[] FileInheritedUsers = [AU(ID | SA | FA, Users)];

    [Fact]
    public void AnOpaqueAceErrorsTheSaclPartOnly()
    {
        // 4.5, decision 16: a stored ACE type the model does not handle refuses the write and
        // errors the SACL part only — the object's DACL part is classified on its own and still
        // proceeds, so the refusal never mentions the DACL and never comes back as a Write.
        var r = Classify(apply: false, [AuditFile], FileInheritedUsers, stored: CallbackAce);
        Assert.Equal(Outcome.Error, r.Outcome);
        Assert.Contains("0x09", r.Detail);
        Assert.False(r.Guard);
        // One opaque entry among modelled ones still refuses the whole SACL write.
        var mixed = new AclView(2, [.. View(AU(ID | SA | FA, Users)).Aces, .. CallbackAce.Aces]);
        Assert.Equal(Outcome.Error, Classify(apply: true, [AuditFile], FileInheritedUsers, stored: mixed).Outcome);
        // Mandatory label & co. are recognised by Descriptor but not modelled (K8).
        var label = new AclView(2, [new AceView("MandatoryLabel", 0x11, 0, [], 0x3, "S-1-16-4096", null)]);
        Assert.Equal(Outcome.Error, Classify(apply: false, [AuditFile], FileInheritedUsers, stored: label).Outcome);
    }

    // ---- merging the two part verdicts (4.6) ------------------------------------------------------------

    [Theory]
    [InlineData(Outcome.Ok, Outcome.Keep, Outcome.Ok)]
    [InlineData(Outcome.Keep, Outcome.Ok, Outcome.Ok)]
    [InlineData(Outcome.Write, Outcome.Follows, Outcome.Write)]
    [InlineData(Outcome.Written, Outcome.Follows, Outcome.Follows)]
    [InlineData(Outcome.Stopped, Outcome.Write, Outcome.Stopped)]
    [InlineData(Outcome.Error, Outcome.Ok, Outcome.Error)]
    [InlineData(Outcome.Ok, Outcome.Error, Outcome.Error)]
    [InlineData(Outcome.Keep, Outcome.Keep, Outcome.Keep)]
    public void TheWorsePartVerdictWins(Outcome dacl, Outcome sacl, Outcome want) =>
        Assert.Equal(want, SaclClassifier.MergeOutcome(dacl, sacl));

    static readonly Ace AuditFdOther = AU(OI | CI | SA | FA, Other);
}
