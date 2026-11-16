using System.ComponentModel;
using System.Text.Json;
using PermissionReset.Smb.Core;
using static PermissionReset.Smb.Tests.CheckerTests;

namespace PermissionReset.Smb.Tests;

// check's records, summary and exit codes, through a fake tree. The walk's logic is in
// CheckerTests; these pin what the CLI does with its results.
public class CheckCliTests
{
    static string PlanFile(Plan p)
    {
        var f = Path.Combine(Path.GetTempPath(), $"smbplan-{Guid.NewGuid():N}.json");
        File.WriteAllText(f, JsonSerializer.Serialize(p));
        return f;
    }

    static (int Code, string Out, string Err) Run(FakeTree tree, string? missingPrivilege, params string[] args)
    {
        var deps = new CheckDeps(
            n => { if (n == missingPrivilege) throw new Win32Exception(1300, $"this account does not hold {n}; run elevated as an account that does"); },
            _ => tree,
            _ => null);
        var o = new StringWriter();
        var e = new StringWriter();
        int code = Cli.Run(args, o, e, check: deps);
        return (code, o.ToString(), e.ToString());
    }

    static FakeTree RightTree() => new(new()
    {
        [""] = new(true, DirWant, true),
        ["f.txt"] = new(false, FileInherited, false),
    });

    static FakeTree WrongTree() => new(new()
    {
        [""] = new(true, [A(AceFlags.ObjectInherit | AceFlags.ContainerInherit, "S-1-5-21-9-9-9-9")], true),
        ["f.txt"] = new(false, [A(AceFlags.Inherited, "S-1-5-21-9-9-9-9")], false),
    });

    [Fact]
    public void DryRunPrintsARecordPerObjectAndExitsZeroEvenWhenWrong()
    {
        var plan = PlanFile(Usual);
        var (code, o, e) = Run(WrongTree(), null, "check", plan, @"\\array\share\dept");
        Assert.Equal(0, code);
        var lines = o.Trim().Split('\n');
        Assert.Equal(2, lines.Length);
        using var root = JsonDocument.Parse(lines.First(l => l.Contains("\"write\"")));
        Assert.Equal(@"\\array\share\dept", root.RootElement.GetProperty("path").GetString());
        Assert.Equal("protected", root.RootElement.GetProperty("form").GetString());
        Assert.Contains("\"outcome\":\"follows\"", o);
        Assert.Contains("write 1", e);
        Assert.Contains("follows 1", e);
        Assert.Contains("dry run; nothing was written", e);
    }

    [Fact]
    public void ValidateExitsOneOnAnyDifference()
    {
        var plan = PlanFile(Usual);
        Assert.Equal(1, Run(WrongTree(), null, "check", "--validate", plan, "R").Code);
        Assert.Equal(0, Run(RightTree(), null, "check", "--validate", plan, "R").Code);
    }

    [Fact]
    public void AReadErrorExitsOne()
    {
        var tree = RightTree();
        tree.ReadFails.Add("f.txt");
        var (code, o, _) = Run(tree, null, "check", PlanFile(Usual), "R");
        Assert.Equal(1, code);
        Assert.Contains("\"outcome\":\"error\"", o);
    }

    [Fact]
    public void MissingBackupPrivilegeReadsNothing()
    {
        var (code, o, e) = Run(RightTree(), "SeBackupPrivilege", "check", PlanFile(Usual), "R");
        Assert.Equal(1, code);
        Assert.Empty(o);
        Assert.Contains("SeBackupPrivilege", e);
    }

    [Fact]
    public void ASchema1PlanIsRefused()
    {
        var (code, o, e) = Run(RightTree(), null, "check", PlanFile(Usual with { Schema = Plan.SaclSchema, Default = Usual.Default with { Dacl = null, HasAcl = false }, Rules = [] }), "R");
        Assert.Equal(1, code);
        Assert.Empty(o);
        Assert.Contains("schema 2", e);
    }

    [Theory]
    [InlineData("check")]
    [InlineData("check", "plan.json")]
    [InlineData("check", "--workers", "0", "plan.json", "R")]
    [InlineData("check", "--frobnicate", "plan.json", "R")]
    public void UsageErrorsExitTwo(params string[] args) =>
        Assert.Equal(2, Run(RightTree(), null, args).Code);
}
