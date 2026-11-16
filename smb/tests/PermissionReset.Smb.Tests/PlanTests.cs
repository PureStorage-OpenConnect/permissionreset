using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class PlanTests
{
    static string SmbGolden => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "testdata", "smbplan.golden.json"));
    static string Golden => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "testdata", "saclplan.golden.json"));

    [Fact]
    public void LoadsTheBuildSpecGolden()
    {
        var p = Plan.Parse(Golden);
        Assert.Equal(1, p.Schema);
        Assert.Equal("nfsv4", p.Protocol);
        Assert.Equal("default", p.Default.Label);
        Assert.True(p.Default.KeepDacl);
        var ace = Assert.Single(p.Default.Sacl!);
        Assert.Equal("S-1-1-0", ace.Sid);
        Assert.Equal(2, ace.WindowsType);
        Assert.Equal(0xC3, ace.WindowsFlags);
        Assert.NotEmpty(p.Rules);
        Assert.Contains(".snapshot", p.Exclude.Base);
    }

    [Theory]
    [InlineData("\"schema\": 1", "\"schema\": 3", "schema 3 is not supported")]
    [InlineData("\"sacl\": [", "\"dacl\": [], \"sacl\": [", "schema 1 plan has no dacl")]
    [InlineData("\"protocol\": \"nfsv4\"", "\"protocol\": \"posix\"", "protocol \"posix\"")]
    [InlineData("\"schema\": 1,", "\"schema\": 1, \"surprise\": true,", "not valid JSON")]
    [InlineData("\"type\": \"directory\"", "\"type\": \"dir\"", "unknown match type \"dir\"")]
    public void RefusesWhatItWouldMisread(string from, string to, string want)
    {
        Assert.Contains(from, Golden);
        var e = Assert.Throws<PlanException>(() => Plan.Parse(ReplaceFirst(Golden, from, to)));
        Assert.Contains(want, e.Message);
    }

    [Fact]
    public void LoadsTheSmbPlanGolden()
    {
        var p = Plan.Parse(SmbGolden);
        Assert.Equal(Plan.SmbSchema, p.Schema);
        Assert.True(p.Default.HasAcl);
        Assert.Equal(2, p.Default.Dacl!.Count);
        Assert.Equal(AceTypes.Allow, p.Default.Dacl[0].WindowsType);
        Assert.Equal("S-1-1-0", p.Default.Dacl[0].Sid);
        Assert.Null(p.Rules[0].Dacl);                       // sacl:-only rule
        Assert.Equal(AceTypes.Deny, p.Rules[1].Dacl![0].WindowsType);
        Assert.Empty(p.Rules[1].Sacl!);                     // sacl: []
    }

    [Theory]
    [InlineData("\"has_acl\": true", "\"has_acl\": false", "has_acl is false but dacl is present")]
    [InlineData("\"windows_type\": 0", "\"windows_type\": 2", "want allow (0) or deny (1)")]
    [InlineData("\"windows_flags\": 3", "\"windows_flags\": 19", "carries ID")]
    public void RefusesAMisshapedSmbPlan(string from, string to, string want)
    {
        Assert.Contains(from, SmbGolden);
        var e = Assert.Throws<PlanException>(() => Plan.Parse(ReplaceFirst(SmbGolden, from, to)));
        Assert.Contains(want, e.Message);
    }

    [Fact]
    public void RefusesNotJson() => Assert.Throws<PlanException>(() => Plan.Parse("schema: 1"));

    static string ReplaceFirst(string s, string from, string to)
    {
        int i = s.IndexOf(from, StringComparison.Ordinal);
        return s[..i] + to + s[(i + from.Length)..];
    }
}
