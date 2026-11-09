namespace PermissionReset.Smb.Core;

// RuleSelector is permissionreset's rule selection, over a plan: Spec.MatchRule (the first rule
// whose type and base-name pattern match, else the default) and Excluder.Match (a pattern without
// '/' against the base name, one with '/' against the path relative to the root; the root is
// never excluded). Same semantics as tools/set-saclonly's SaclRules.
public sealed class RuleSelector(Plan plan)
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
        var b = BaseOf(rel);
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

    public static string BaseOf(string rel)
    {
        int i = rel.LastIndexOf('/');
        return i < 0 ? rel : rel[(i + 1)..];
    }
}
