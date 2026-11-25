namespace PermissionReset.Smb.Core;

// SaclPart is one object's SACL part verdict (smb/DESIGN-sacl-write.md, 4.6: an object now has two
// part verdicts; MergeOutcome gives the record's single Outcome as the worse of the two). Form is
// the desired form when the rule sets sacl:, null when it does not (a kept SACL has no desired
// form, 2.3). Guard marks a G1-SACL failure (4.4): during apply the run stops, with no override,
// as for the DACL's G1. The classifier produces Ok, Write, Follows, Keep and Error; Written and
// Stopped come from the write path.
public sealed record SaclPart(Form? Form, Outcome Outcome, string? Detail, bool Guard = false);

// SaclClassifier judges one object's SACL part against its rule and its parent (sections 3, 3.1,
// 3.2 and 4.4). It is deliberately standalone: the walk hands it what the object stores and what
// the parent passes down, and it hands back the part verdict. No read, write or stop happens here.
public static class SaclClassifier
{
    // Classify one object's SACL part.
    //
    // want: the rule's audit ACEs with SIDs resolved, or null when the rule has no sacl: key. The
    // consumer keys off sacl_set, never off sacl being empty (2.3): an empty list is sacl: [],
    // a present-empty S:P, never a Keep.
    //
    // inherited: what the object would inherit once the run's parents are right —
    // Inheritance.Inherit over the parent's desired SACL (over its stored one for a kept
    // directory, 3.2), or, for the root, the root's stored ID audit ACEs (3.2, as for the DACL).
    // --root-sacl-protected forces the root's form to Protected, independent of --root-protected
    // (decision 4).
    //
    // parentPropagatesNow / parentPropagatedAtCompare: Inheritance.Inherit over the parent's
    // stored SACL. The compare-time value is the read before any write of this run (3.2's "now");
    // it tells a pre-run freeze from a G1-SACL failure (3.2, 4.4). The "now" value is the same
    // read on check; on apply it is what the parent passes after this run's write of it, so a
    // child that followed its parent reads as tracking, not frozen.
    //
    // ancestorWrites: an ancestor's SACL will be written this run. Only check predicts Follows; in
    // apply the parent is already right when the child is read.
    public static SaclPart Classify(
        bool isRoot, bool apply, bool rootSaclProtected,
        IReadOnlyList<Ace>? want,
        IReadOnlyList<Ace> inherited,
        IReadOnlyList<Ace> parentPropagatesNow,
        IReadOnlyList<Ace> parentPropagatedAtCompare,
        AclView? storedSacl, bool storedProtected,
        bool ancestorWrites)
    {
        if (want is null)
            return ClassifyKept(apply, storedSacl, storedProtected, inherited, parentPropagatesNow, parentPropagatedAtCompare, ancestorWrites);

        var desired = SaclModel.DesiredForSacl(want, inherited, isRoot, rootSaclProtected);
        var diff = SaclModel.Matches(desired, storedSacl, storedProtected);
        if (diff is null) return new SaclPart(desired.Form, Outcome.Ok, null);

        // 4.5 (section 11, decision 16): a stored opaque ACE type refuses the write and errors the
        // SACL part only; a rebuilt audit-only list would delete it (K8). The DACL part is
        // classified on its own and still proceeds.
        var opaque = SaclModel.OpaqueReason(storedSacl);
        if (opaque is not null)
            return new SaclPart(desired.Form, Outcome.Error, $"an opaque ACE refuses the SACL write: {opaque}");

        var stored = (storedSacl?.Aces ?? []).Select(Ace.FromView).ToList();
        bool unprotectedShape = !desired.Protected && !storedProtected && TrackableWide(desired, stored);
        List<Ace> remainder = unprotectedShape ? stored.Skip(desired.Aces.Count(a => !a.Inherited)).Select(a => a!.Value).ToList() : [];
        // What the array re-derives (3.2, K10): an absent SACL, or an unprotected one with the
        // right explicit part whose ID part equals what the parent's stored SACL passed down at
        // compare time (0 ACEs included), counts as following when the parent will pass ACEs down.
        bool follows = unprotectedShape && inherited.Count > 0 &&
            (storedSacl is null || remainder.SequenceEqual(parentPropagatedAtCompare));

        if (!apply)
        {
            if (ancestorWrites && follows) return new SaclPart(desired.Form, Outcome.Follows, diff);
            // As on the DACL, a non-empty frozen ID copy is a Write with a note; the S:AI-empty
            // pre-run freeze (3.2: empty under a parent that already passed ACEs down at compare
            // time) is a plain Write, and the write makes the object dynamic (K10).
            if (unprotectedShape && storedSacl is not null && !follows)
            {
                if (remainder.Count > 0)
                    diff += "; its inherited audit part does not follow its parent (a frozen copy)";
                else if (parentPropagatedAtCompare.Count > 0)
                    diff += "; a frozen copy from before this run: its parent already passes audit ACEs down, and the write makes it dynamic (K10)";
            }
            return new SaclPart(desired.Form, Outcome.Write, diff);
        }

        // Apply: the parent is already right when the child is read.
        if (unprotectedShape)
        {
            if (storedSacl is not null && remainder.Count > 0)
                // G1-SACL (4.4): unprotected, the right explicit part, only ID ACEs after it, and
                // the ID part is not inh(desired(parent).sacl). Fires on a frozen copy that
                // predates the run too; there is no override, as for the DACL's G1.
                return new SaclPart(desired.Form, Outcome.Error,
                    $"G1-SACL: its inherited audit part is not what its parent passes down ({diff}); either the inheritance function disagrees with the array or this object holds a frozen copy",
                    Guard: true);
            // An absent SACL or an S:AI empty one. The parent's compare-time read tells a pre-run
            // freeze (it already passed ACEs down: a plain Write, 3.2 bullet 2) from a child that
            // should have followed this run's parent write (it passed nothing: G1-SACL, 4.4).
            if (parentPropagatedAtCompare.Count > 0)
                return new SaclPart(desired.Form, Outcome.Write,
                    diff + "; a frozen copy from before this run: its parent already passed audit ACEs down at compare time, and the write makes it dynamic (K10)");
            return new SaclPart(desired.Form, Outcome.Error,
                "G1-SACL: its SACL should have followed this run's parent write (the parent's compare-time SACL passed nothing down) and did not (K10)",
                Guard: true);
        }
        return new SaclPart(desired.Form, Outcome.Write, diff);
    }

    // ClassifyKept is an object whose rule has no sacl: key: never written (2.3), but still
    // classified whenever any rule sets sacl:. A protected SACL is Keep, never a Write (2.3,
    // decision 14). An unprotected one is Follows (check) or Ok (apply) when it tracks what its
    // parent passes down, and an error when it holds a frozen audit copy (2.3, 3.2, 4.4).
    static SaclPart ClassifyKept(bool apply, AclView? storedSacl, bool storedProtected,
        IReadOnlyList<Ace> inherited, IReadOnlyList<Ace> parentPropagatesNow, IReadOnlyList<Ace> parentPropagatedAtCompare,
        bool ancestorWrites)
    {
        if (storedProtected) return new SaclPart(null, Outcome.Keep, null);

        var stored = (storedSacl?.Aces ?? []).Select(Ace.FromView).ToList();
        var idPart = stored.Where(a => a is { Inherited: true }).Select(a => a!.Value).ToList();
        bool tracks = idPart.SequenceEqual(parentPropagatesNow);
        if (idPart.Count > 0 && !tracks)
            // A frozen ID audit copy is an error (2.3). G1-SACL fires on it in apply, with no
            // override, on no-sacl: objects too (4.4); in check it is reported and the run goes on.
            // This runs before the opaque check, so an opaque ACE does not hide a frozen copy.
            return new SaclPart(null, Outcome.Error,
                "it holds a frozen copy of inherited audit ACEs: its inherited part does not follow its parent",
                Guard: apply);

        // The object itself is never written, so an opaque ACE type is no refusal here (4.5 is
        // about writes); a kept directory holding one feeds the walk an unclassifiable parent and
        // its children's SACL parts error instead (3.2).
        if (SaclModel.OpaqueReason(storedSacl) is not null) return new SaclPart(null, Outcome.Keep, null);

        if (stored.Count > 0 && idPart.Count == 0)
        {
            // Explicit audit ACEs only. No record says such a SACL follows its parent (K10 covers
            // S:AI empty and matching ID parts; the DACL's explicit-only objects do not follow,
            // Q-EXP), so it is no G1-SACL case. When its parent passes audit ACEs down it lacks
            // them, and a rule with no sacl: key may not write it: an error, and the run goes on.
            return inherited.Count == 0
                ? new SaclPart(null, Outcome.Ok, null)
                : new SaclPart(null, Outcome.Error,
                    "it holds explicit audit ACEs only, which do not follow its parent's audit ACEs; a rule with no sacl: key may not write it");
        }

        if (tracks)
        {
            // It tracks its parent (K10, S:AI empty under a parent that passes nothing included).
            // Check predicts Follows when an ancestor's write will change what the parent passes;
            // apply reads it after the parent's write, already right.
            return apply || !ancestorWrites || inherited.Count == 0
                ? new SaclPart(null, Outcome.Ok, null)
                : new SaclPart(null, Outcome.Follows, null);
        }
        // An absent SACL or an S:AI empty one that does not track its parent. Under a parent that
        // already passed ACEs down at compare time it is a pre-run freeze (3.2): an error in check
        // and apply, and the run does not stop. Under a parent that passed nothing, in apply, it
        // should have followed this run's parent write: G1-SACL (4.4), no sacl: key included.
        if (apply && inherited.Count > 0 && parentPropagatedAtCompare.Count == 0)
            return new SaclPart(null, Outcome.Error,
                "G1-SACL: its SACL should have followed this run's parent write (the parent's compare-time SACL passed nothing down) and did not (K10)",
                Guard: true);
        return new SaclPart(null, Outcome.Error,
            "its SACL is empty while its parent passed audit ACEs down at compare time (a frozen copy from before this run); a rule with no sacl: key may not write it");
    }

    // TrackableWide is the shape the array keeps in step with its parent (3.2), one step wider
    // than the DACL's TrackableShape: an unprotected desired form, an unprotected stored SACL, the
    // desired explicit part stored first, and a remainder that is all inherited. The remainder may
    // be empty only when there is no explicit part: an S:AI empty SACL under a parent that passes
    // nothing down still follows a later parent SACL (K10), but no record says an explicit-only
    // SACL does, and the DACL's explicit-only objects do not (Q-EXP, TrackableShape). An
    // explicit-only SACL is a plain Write. A protected SACL never follows (K10).
    static bool TrackableWide(Desired d, List<Ace?> stored)
    {
        if (stored.Any(a => a is null)) return false;
        var explicitWant = d.Aces.Where(a => !a.Inherited).ToList();
        if (stored.Count < explicitWant.Count) return false;
        if (explicitWant.Count > 0 && stored.Count == explicitWant.Count) return false;
        for (int i = 0; i < explicitWant.Count; i++)
            if (stored[i]!.Value != explicitWant[i]) return false;
        return stored.Skip(explicitWant.Count).All(a => a!.Value.Inherited);
    }

    // MergeOutcome is the record's single Outcome from its two part verdicts (4.6), the worse in
    // the order Error > Stopped > Write > Follows > Written > Ok > Keep, which keeps exit codes,
    // the checkpoint's done(ok) and the evidence vocabulary unchanged. Excluded and Reparse are
    // whole-object verdicts, not part verdicts; they lose to any part verdict.
    public static Outcome MergeOutcome(Outcome daclPart, Outcome saclPart)
    {
        static int Rank(Outcome o) => o switch
        {
            Outcome.Error => 6,
            Outcome.Stopped => 5,
            Outcome.Write => 4,
            Outcome.Follows => 3,
            Outcome.Written => 2,
            Outcome.Ok => 1,
            Outcome.Keep => 0,
            _ => -1,
        };
        return Rank(daclPart) >= Rank(saclPart) ? daclPart : saclPart;
    }
}
