namespace PermissionReset.Smb.Core;

// Ace is one simple ACE (allow, deny or audit: type, flags, mask, SID), the unit the write path
// compares and computes with. Object, callback and other ACE types have no Ace form; an ACL that
// holds one can only be compared as "differs" (see FromView).
public readonly record struct Ace(int Type, byte Flags, uint Mask, string Sid)
{
    public bool Inherited => (Flags & AceFlags.Inherited) != 0;

    // SameIgnoringInherited compares type, flags without ID, mask and SID: the comparison the
    // three-form classifier uses (smb/DESIGN-write-path.md, 2.1).
    public bool SameIgnoringInherited(Ace o) =>
        Type == o.Type && (Flags & ~AceFlags.Inherited) == (o.Flags & ~AceFlags.Inherited) && Mask == o.Mask && Sid == o.Sid;

    // FromView converts a decoded stored ACE, or returns null for a type this code does not model.
    public static Ace? FromView(AceView v) =>
        v.TypeCode is AceTypes.Allow or AceTypes.Deny or AceTypes.Audit && v.Mask is uint m && v.Sid is string s
            ? new Ace(v.TypeCode, v.Flags, m, s)
            : null;

    public override string ToString() =>
        $"{(Type switch { AceTypes.Allow => "A", AceTypes.Deny => "D", AceTypes.Audit => "AU", _ => Type.ToString() })};" +
        $"{string.Concat(AceView.DescribeFlags(Flags))};0x{Mask:x};{Sid}";
}

// Inheritance computes the ACEs a child receives from its parent's ACL, following MS-DTYP's
// inheritance rules for the ACEs a plan can hold (smb/DESIGN-write-path.md, 2.4). It is the
// riskiest piece of the write path: if it disagrees with what FlashArray derives, a written child
// freezes (decision record, section 8, question 1). Guard G1 checks it against the array at run
// time, and hardware question Q-INH checks every flag combination.
public static class Inheritance
{
    // Creator SIDs are replaced by the creating account's SID when they are inherited; the result
    // depends on who created the object, so it cannot be computed here. Plan.CheckAces refuses
    // every one in a sacl list (smb/DESIGN-sacl-write.md, 2.2 item 3).
    public static readonly IReadOnlySet<string> CreatorSids = new HashSet<string> { "S-1-3-0", "S-1-3-1", "S-1-3-2", "S-1-3-3" };

    const byte AuditFlags = AceFlags.SuccessfulAccess | AceFlags.FailedAccess;

    // Inherit returns, in parent order, the ACEs a child inherits from parent, each with ID set.
    // Throws NotSupportedException when a creator SID would be inherited.
    public static List<Ace> Inherit(IReadOnlyList<Ace> parent, bool childIsDir)
    {
        var o = new List<Ace>();
        foreach (var p in parent)
        {
            byte keep = (byte)((p.Flags & AuditFlags) | AceFlags.Inherited);
            bool oi = (p.Flags & AceFlags.ObjectInherit) != 0, ci = (p.Flags & AceFlags.ContainerInherit) != 0;
            bool np = (p.Flags & AceFlags.NoPropagate) != 0;
            byte? flags;
            if (!childIsDir)
                flags = oi ? keep : null;
            else if (ci)
                flags = np ? keep : (byte)(keep | (p.Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit)));
            else if (oi)
                flags = np ? null : (byte)(keep | AceFlags.InheritOnly | AceFlags.ObjectInherit);
            else
                flags = null;
            if (flags is null) continue;
            if (CreatorSids.Contains(p.Sid))
                throw new NotSupportedException($"inheriting {p} needs the creating account's SID, which a reset cannot know");
            o.Add(p with { Flags = flags.Value });
        }
        return o;
    }
}

// Form is the stored shape the classifier picks for an object (smb/DESIGN-write-path.md, 2.1).
public enum Form { Inherits, ExplicitPlusInherits, Protected }

// Desired is what an object's ACL should hold: its form, the ACEs exactly as they should be stored
// (ID set on the inherited part), and whether the ACL is protected (D:P or S:P).
public sealed record Desired(Form Form, IReadOnlyList<Ace> Aces, bool Protected)
{
    // Classify picks the form for an object whose rule wants `want` and which would inherit
    // `inherited` (Inheritance.Inherit of its parent's desired ACL; for the root, its stored ID
    // ACEs). want must hold no ID ACE; the plan refuses them.
    public static Desired Classify(IReadOnlyList<Ace> want, IReadOnlyList<Ace> inherited)
    {
        if (want.Any(a => a.Inherited))
            throw new ArgumentException("a wanted ACL holds an ID ACE; inheritance is computed, not planned", nameof(want));
        if (inherited.Count > 0)
        {
            int e = want.Count - inherited.Count;
            if (e >= 0 && SuffixMatches(want, inherited, e))
            {
                var aces = want.Take(e).Concat(inherited).ToList();
                return new Desired(e == 0 ? Form.Inherits : Form.ExplicitPlusInherits, aces, false);
            }
        }
        // An object whose parent passes nothing down is Protected, not "explicit + inherits" with
        // an empty inherited part: the rule's ACL is complete, and an unprotected explicit-only ACL
        // would pick up whatever the parent passes down later (hardware question Q-EXP).
        return new Desired(Form.Protected, want.ToList(), true);
    }

    static bool SuffixMatches(IReadOnlyList<Ace> want, IReadOnlyList<Ace> inherited, int from)
    {
        for (int i = 0; i < inherited.Count; i++)
            if (!want[from + i].SameIgnoringInherited(inherited[i])) return false;
        return true;
    }

    // Matches compares a stored ACL with this desired one, raw: ACE count, order, type, flags
    // (ID included), mask and SID, and the protected bit (3.2). It returns null when they match,
    // else the first difference. A stored ACE this code does not model is always a difference.
    // A null stored ACL (no DACL: everyone has full control) is always a difference, never an
    // empty ACL (which denies everyone): a reset always writes a DACL.
    public string? Matches(AclView? stored, bool storedProtected)
    {
        if (stored is null) return "stored descriptor has no DACL (everyone has full control)";
        if (storedProtected != Protected)
            return storedProtected ? "stored ACL is protected, want unprotected" : "stored ACL is unprotected, want protected";
        var s = stored.Aces;
        if (s.Count != Aces.Count) return $"stored ACL has {s.Count} ACE(s), want {Aces.Count}";
        for (int i = 0; i < s.Count; i++)
        {
            var a = Ace.FromView(s[i]);
            if (a is null) return $"ACE {i} is type {s[i].Type}, which a reset does not write";
            if (a.Value != Aces[i]) return $"ACE {i} is {a.Value}, want {Aces[i]}";
        }
        return null;
    }
}
