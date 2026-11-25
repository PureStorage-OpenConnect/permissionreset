namespace PermissionReset.Smb.Core;

// SaclModel is the SACL half of the three-form model (smb/DESIGN-sacl-write.md, sections 3, 4.1,
// 4.3, 4.4 and 4.5): the desired form for a rule's sacl:, the comparison with what is stored, the
// write's flags and control word, the G2 read-back comparison for a SACL write, and the refusal of
// stored ACE types the model does not handle. The desired form itself is Desired.Classify, reused
// unchanged (section 3: the design's 2.1 applies with want set to the rule's sacl).
public static class SaclModel
{
    // DesiredForSacl picks the stored form for an object whose rule sets sacl:, with
    // --root-sacl-protected forcing the root's SACL to Protected (3.2; a frozen ID copy on the
    // root cannot be detected, and the flag is independent of --root-protected, decision 4).
    // sacl: [] classifies to Protected with no ACEs by itself: Classify matches an empty want
    // against nothing, so it is always present-empty S:P (2.3, section 11 decision 2).
    public static Desired DesiredForSacl(IReadOnlyList<Ace> want, IReadOnlyList<Ace> inherited, bool isRoot, bool rootSaclProtected) =>
        isRoot && rootSaclProtected ? new Desired(Form.Protected, want.ToList(), true) : Desired.Classify(want, inherited);

    // Matches compares a stored SACL with the desired form (3.1). It is Desired.Matches with the
    // SACL's null semantics spelled out: FlashArray never reports an absent SACL (K9: a
    // never-written object reads S:AI empty), but other servers can, and a read may omit the SACL,
    // so an absent stored SACL is spelled out rather than falling into the DACL's "everyone has
    // full control" reading. Absent never matches, present-empty S:P included: neither a
    // never-audited SACL nor an absent one equals what sacl: [] writes, which is why sacl: []
    // writes every never-audited object in its scope once (2.3). A present SACL compares raw:
    // count, order, type, flags (ID included), mask, SID and S:P (3.1), which Desired.Matches does.
    public static string? Matches(Desired desired, AclView? stored, bool storedProtected)
    {
        if (stored is null)
            return desired.Protected && desired.Aces.Count == 0
                ? "the stored SACL is absent, and sacl: [] wants a present, empty, protected SACL"
                : "the stored SACL is absent";
        return desired.Matches(stored, storedProtected);
    }

    // ExpectedAutoInherited is K11's rule for the SACL (4.3): the array decides the AI bit from
    // protection, whatever the write sent — a protected SACL is stored with S:AI clear, an
    // unprotected one with S:AI set. G2 expects exactly this after a SACL write; the preflight
    // confirms it on the probe for each run and refuses on disagreement.
    public static bool ExpectedAutoInherited(bool saclProtected) => !saclProtected;

    // WriteInfo is the SECURITY_INFORMATION of a SACL write (4.1): SACL_SECURITY_INFORMATION with
    // exactly one of the protection flags, always stated, never left to the server.
    public static uint WriteInfo(bool saclProtected) =>
        SecurityInformation.Sacl | (saclProtected ? SecurityInformation.ProtectedSacl : SecurityInformation.UnprotectedSacl);

    // WriteControl is the control word a SACL write sends (4.1), stated as phase 2 states the
    // DACL's: SE_SACL_PRESENT | SE_SACL_PROTECTED for a protected SACL, with S:AI clear;
    // SE_SACL_PRESENT | SE_SACL_AUTO_INHERITED for an unprotected one. The array decides the
    // stored AI bit from protection either way (K11).
    public static ushort WriteControl(bool saclProtected) =>
        (ushort)(Control.SaclPresent | (saclProtected ? Control.SaclProtected : Control.SaclAutoInherited));

    // IsOpaqueAce reports whether a stored SACL ACE is a type the model does not handle (K8, 4.5,
    // section 11 decision 16): the object and callback types 5, 7 and 9, mandatory label (0x11),
    // resource attribute (0x12), scoped policy id (0x13), or anything Descriptor does not decode.
    // A rebuilt audit-only list would silently delete such an ACE, so an object whose stored SACL
    // holds one is never written; its SACL part is an error while its DACL part proceeds.
    // DESIGN-Q: a simple Allow or Deny ACE (type 0 or 1) in a stored SACL is treated as opaque
    // too — 4.5 does not name it, but the model only ever writes audit ACEs, so rebuilding would
    // drop it the same way.
    public static bool IsOpaqueAce(AceView v) => v.TypeCode != AceTypes.Audit || v.Mask is null || v.Sid is null;

    // OpaqueReason names the first opaque ACE in a stored SACL, or null (4.5). The walk also uses
    // it for kept directories: an opaque ACE in a kept directory's stored SACL means its
    // children's SACL parts cannot be classified (3.2).
    public static string? OpaqueReason(AclView? stored)
    {
        if (stored is null) return null;
        for (int i = 0; i < stored.Aces.Count; i++)
            if (IsOpaqueAce(stored.Aces[i]))
                return $"ACE {i} is type {stored.Aces[i].Type}, which the SACL model does not handle";
        return null;
    }

    // KeptAcrossSaclWrite is every control bit outside the SACL's own three. A SACL-only write
    // leaves everything else alone, S:P changes included (K2), so G2 compares these bits with the
    // read before: the DACL's bits, D:AI included.
    const ushort KeptAcrossSaclWrite = unchecked((ushort)~(Control.SaclPresent | Control.SaclProtected | Control.SaclAutoInherited));

    // ReadbackDiff is G2 for a SACL write (4.4): a fresh read with the SACL after the write,
    // compared raw. The SACL ACEs (type, flags including ID, mask, SID, order), S:P and
    // SaclPresent must equal the desired form; S:AI must be what K11's rule says for that
    // protection; owner, group, the DACL bytes and every non-SACL control bit must equal the read
    // before (K2). The return code is never proof of what was stored (K13: the array returned
    // success while dropping ACEs it doesn't store), so this comparison runs after every write,
    // with no mode that skips it. Null when everything agrees.
    public static string? ReadbackDiff(Desired desired, Descriptor before, Descriptor after)
    {
        bool afterProtected = (after.Control & Control.SaclProtected) != 0;
        var d = Matches(desired, after.Sacl, afterProtected);
        if (d is not null) return $"the SACL read back differs: {d}";
        bool wantAI = ExpectedAutoInherited(desired.Protected), gotAI = (after.Control & Control.SaclAutoInherited) != 0;
        if (gotAI != wantAI)
            return $"SaclAutoInherited is {(gotAI ? "set" : "clear")} after {(desired.Protected ? "a protected" : "an unprotected")} SACL write; this array was measured to store it {(wantAI ? "set" : "clear")} (K11)";
        if (after.Owner != before.Owner) return $"owner changed from {before.Owner ?? "absent"} to {after.Owner ?? "absent"}";
        if (after.Group != before.Group) return $"group changed from {before.Group ?? "absent"} to {after.Group ?? "absent"}";
        if (AclKey(after.Dacl) != AclKey(before.Dacl)) return "the DACL changed";
        if ((after.Control & KeptAcrossSaclWrite) != (before.Control & KeptAcrossSaclWrite))
            return $"control changed from {string.Join("|", Descriptor.DescribeControl((ushort)(before.Control & KeptAcrossSaclWrite)))} to {string.Join("|", Descriptor.DescribeControl((ushort)(after.Control & KeptAcrossSaclWrite)))}";
        return null;
    }

    // AclKey renders every stored field of an ACL, in order, for an exact comparison (Checker's
    // same private rendering, repeated here so the read-back compares the DACL bytes by value).
    static string AclKey(AclView? a) =>
        a is null ? "absent" : $"{a.Revision}:" + string.Join("|", a.Aces.Select(x => $"{x.TypeCode},{x.Flags},{x.Mask},{x.Sid},{x.Body}"));
}
