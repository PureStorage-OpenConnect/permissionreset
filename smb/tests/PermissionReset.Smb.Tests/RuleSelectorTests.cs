using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class RuleSelectorTests
{
    static PlanRule Rule(string label, string type, string pattern) =>
        new(label, new PlanMatch(type, pattern), true, true, false, false, false, "", "", []);

    static readonly Plan P = new(1, "t.yaml", "nfsv4",
        new PlanExclude([".snapshot", "./logs/*.gz"], [".snapshot"], ["logs/*.gz"]),
        Rule("default", "", ""),
        [Rule("rule[0]", "directory", "audit*"), Rule("rule[1]", "file", "*.log"), Rule("rule[2]", "", "audit*")]);

    [Theory]
    [InlineData("", true, false, -1)]                      // the root is never excluded
    [InlineData(".snapshot", true, true, -1)]               // base-name exclude
    [InlineData("a/b/.snapshot", true, true, -1)]           // base-name exclude at any depth
    [InlineData("logs/x.gz", false, true, -1)]              // path exclude, anchored at the root
    [InlineData("sub/logs/x.gz", false, false, -1)]         // ... and only there
    [InlineData("audit1", true, false, 0)]                  // directory rule
    [InlineData("audit1", false, false, 2)]                 // a file skips the directory rule
    [InlineData("x/app.log", false, false, 1)]              // patterns match the base name
    [InlineData("app.log", true, false, -1)]                // a directory skips the file rule
    [InlineData("other", false, false, -1)]                 // default
    public void SelectsAsPermissionResetDoes(string rel, bool isDir, bool excluded, int index)
    {
        var s = new RuleSelector(P, "root").Select(rel, isDir);
        Assert.Equal(excluded, s.Excluded);
        if (!excluded) Assert.Equal(index, s.Index);
    }

    // The root is matched by its own name, as Go's MatchRule (filepath.Base of the root path) and
    // Set-SaclOnly's ActionFor (BaseName of the root) do, and is still never excluded.
    [Theory]
    [InlineData("audit7", true, 0)]                         // a directory rule naming the root
    [InlineData("app.log", true, -1)]                       // a file rule never selects the root
    [InlineData(".snapshot", true, -1)]                     // an excluded name does not exclude the root
    [InlineData("other", true, -1)]
    public void SelectsTheRootByItsName(string rootName, bool isDir, int index)
    {
        var s = new RuleSelector(P, rootName).Select("", isDir);
        Assert.False(s.Excluded);
        Assert.Equal(index, s.Index);
    }

    [Theory]
    [InlineData(@"\\array\share\dept", "dept")]
    [InlineData(@"\\array\share\dept\", "dept")]
    [InlineData(@"\\array\share", "share")]                 // a bare share root: Set-SaclOnly's BaseName
    [InlineData(@"\\?\UNC\array\share\dept", "dept")]
    [InlineData(@"D:\data\dept", "dept")]
    [InlineData(@"C:\", "C:")]                               // a drive root: Set-SaclOnly's BaseName
    [InlineData("/mnt/share/dept/", "dept")]
    [InlineData("dept", "dept")]
    [InlineData(@"\\", "")]
    public void RootNameIsTheLastComponent(string root, string name) =>
        Assert.Equal(name, RuleSelector.RootName(root));
}
