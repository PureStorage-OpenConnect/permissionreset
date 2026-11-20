namespace PermissionReset.Smb.Core;

// RuleSelector is permissionreset's rule selection, over a plan: Spec.MatchRule (the first rule
// whose type and base-name pattern match, else the default) and Excluder.Match (a pattern without
// '/' against the base name, one with '/' against the path relative to the root; the root is
// never excluded). Same semantics as tools/set-saclonly's SaclRules.
//
// rootName is the root's own base name (RootName of the ROOT argument). Rules match the root by
// it, as Go's MatchRule does with filepath.Base of the full root path and Set-SaclOnly's ActionFor
// does with BaseName(RootLong); without it no named pattern could select the root.
public sealed class RuleSelector(Plan plan, string rootName)
{
    // Selection is one of: excluded, or the rule that applies (the plan's default when none matched).
    public readonly record struct Selection(bool Excluded, PlanRule? Rule, int Index)
    {
        public const int DefaultIndex = -1;
    }

    // rel is the path below the root with '/' separators, "" for the root itself.
    public bool IsExcluded(string rel)
    {
        if (rel.Length == 0) return false;
        var b = BaseOf(rel);
        foreach (var g in plan.Exclude.Base) if (GoGlob.Match(g, b)) return true;
        foreach (var g in plan.Exclude.Path) if (GoGlob.Match(g, rel)) return true;
        return false;
    }

    public Selection Select(string rel, bool isDir)
    {
        if (IsExcluded(rel)) return new Selection(true, null, Selection.DefaultIndex);
        var b = rel.Length == 0 ? rootName : BaseOf(rel);
        for (int i = 0; i < plan.Rules.Count; i++)
        {
            var r = plan.Rules[i];
            if (r.Match.Type == "directory" && !isDir) continue;
            if (r.Match.Type == "file" && isDir) continue;
            if (r.Match.Pattern.Length > 0 && !GoGlob.Match(r.Match.Pattern, b)) continue;
            return new Selection(false, r, i);
        }
        return new Selection(false, plan.Default, Selection.DefaultIndex);
    }

    // RootName is the last component of a root path as the operator gave it, trailing separators
    // ('\' or '/') trimmed: \\array\share\dept gives "dept", a bare share root \\array\share gives
    // "share" and C:\ gives "C:", which is what Set-SaclOnly's BaseName gives for the same root.
    // A root that is only separators gives "".
    public static string RootName(string root)
    {
        var t = root.TrimEnd('\\', '/');
        int i = t.LastIndexOfAny(['\\', '/']);
        return i < 0 ? t : t[(i + 1)..];
    }

    public static string BaseOf(string rel)
    {
        int i = rel.LastIndexOf('/');
        return i < 0 ? rel : rel[(i + 1)..];
    }
}
