using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class PlanTests
{
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
    [InlineData("\"schema\": 1", "\"schema\": 2", "schema 2 is not supported")]
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
    public void RefusesNotJson() => Assert.Throws<PlanException>(() => Plan.Parse("schema: 1"));

    static string ReplaceFirst(string s, string from, string to)
    {
        int i = s.IndexOf(from, StringComparison.Ordinal);
        return s[..i] + to + s[(i + from.Length)..];
    }
}
