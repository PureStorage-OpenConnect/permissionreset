using System.ComponentModel;
using System.Text.Json;
using PermissionReset.Smb.Core;
using static PermissionReset.Smb.Tests.CheckerTests;

namespace PermissionReset.Smb.Tests;

// check's records, summary and exit codes, through a fake tree. The walk's logic is in
// CheckerTests; these pin what the CLI does with its results. xUnit makes an instance per test and
// disposes it afterwards, so each test's plan files are deleted when it ends.
public sealed class CheckCliTests : IDisposable
{
    readonly List<string> _planFiles = [];

    string PlanFile(Plan p)
    {
        var f = Path.Combine(Path.GetTempPath(), $"smbplan-{Guid.NewGuid():N}.json");
        _planFiles.Add(f);
        File.WriteAllText(f, JsonSerializer.Serialize(p));
        return f;
    }

    public void Dispose()
    {
        foreach (var f in _planFiles) File.Delete(f);
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
    public void AnUnreadableDirectoryMakesTheCheckIncomplete()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirInherited, false),
            ["a/f.txt"] = new(false, FileInherited, false),
        });
        tree.ReadFails.Add("a");
        var (code, o, e) = Run(tree, null, "check", PlanFile(Usual), "R");
        Assert.Equal(1, code);
        Assert.DoesNotContain("f.txt", o);
        Assert.Contains("1 director(ies) could not be read, listed or classified", e);
        Assert.Contains("the check is incomplete", e);
    }

    [Fact]
    public void PathsUseTheRootsSeparators()
    {
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirInherited, false),
            ["a/f.txt"] = new(false, FileInherited, false),
        });
        var plan = PlanFile(Usual);
        string[] Paths(string root) => Run(tree, null, "check", plan, root).Out.Trim().Split('\n')
            .Select(l => JsonDocument.Parse(l).RootElement.GetProperty("path").GetString()!).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal([@"\\array\share\dept", @"\\array\share\dept\a", @"\\array\share\dept\a\f.txt"], Paths(@"\\array\share\dept"));
        Assert.Equal([@"C:\", @"C:\a", @"C:\a\f.txt"], Paths(@"C:\"));
        Assert.Equal(["/mnt/x", "/mnt/x/a", "/mnt/x/a/f.txt"], Paths("/mnt/x"));
    }

    [Fact]
    public void ARuleNamingTheRootAppliesToIt()
    {
        // Usual plus a directory rule named for the root that wants something else: it must be the
        // root's rule, so the (otherwise right) root is a write.
        var plan = Usual with { Rules = [new PlanRule("rule[0]", new PlanMatch("directory", "dept"), false, false, true, false, false, "", "", [],
            [new PlanAce("line", 0, 0, AceTypes.Allow, AceFlags.ObjectInherit | AceFlags.ContainerInherit, 0x1200a9, "", false, "S-1-5-21-9-9-9-9", "")]), .. Usual.Rules] };
        var (_, o, _) = Run(RightTree(), null, "check", PlanFile(plan), @"\\array\share\dept\");
        using var root = JsonDocument.Parse(o.Trim().Split('\n').First(l => l.Contains("\"rule\":\"rule[0]\"")));
        Assert.Equal(@"\\array\share\dept\", root.RootElement.GetProperty("path").GetString());
        Assert.Equal("write", root.RootElement.GetProperty("outcome").GetString());
    }

    sealed class FailingWriter : StringWriter
    {
        public override void WriteLine(string? value) => throw new IOException("the pipe is broken");
    }

    [Fact]
    public void AFaultWhileEmittingStopsWithExitOne()
    {
        var deps = new CheckDeps(_ => { }, _ => RightTree(), _ => null);
        var e = new StringWriter();
        int code = Cli.Run(["check", "--workers", "4", PlanFile(Usual), "R"], new FailingWriter(), e, check: deps);
        Assert.Equal(1, code);
        Assert.Contains("check: stopped: ", e.ToString());
        Assert.Contains("the pipe is broken", e.ToString());
        Assert.Contains("the check is incomplete", e.ToString());
    }

    [Fact]
    public void AKeepOwnerDifferenceFailsValidateButNotADryRun()
    {
        // The keep* rule has no acl: but names an owner; ownership is checked independently of the
        // kept DACL, so --validate must exit 1 on the difference.
        var plan = Usual with { Rules = [new PlanRule("rule[0]", new PlanMatch("directory", "keep*"),
            false, false, false, false, false, "owner@example.net", "", [], null), .. Usual.Rules] };
        var tree = new FakeTree(new()
        {
            [""] = new(true, DirWant, true),
            ["keepme"] = new(true, [A(AceFlags.ObjectInherit | AceFlags.ContainerInherit, "S-1-5-21-1-2-3-1003")], true, Owner: "S-1-5-21-1-2-3-1001"),
        });
        var deps = new CheckDeps(_ => { }, _ => tree, n => n == "owner@example.net" ? "S-1-5-21-1-2-3-1002" : null);
        var o = new StringWriter();
        var e = new StringWriter();
        Assert.Equal(0, Cli.Run(["check", PlanFile(plan), "R"], o, e, check: deps));
        o = new StringWriter();
        e = new StringWriter();
        Assert.Equal(1, Cli.Run(["check", "--validate", PlanFile(plan), "R"], o, e, check: deps));
        Assert.Contains("\"outcome\":\"write\"", o.ToString());
    }

    [Fact]
    public void AThrownPrincipalLookupIsAPreflightRefusalExitOne()
    {
        // NTAccount.Translate throws more than IdentityNotMappedException (domain and trust
        // errors). A thrown lookup is still a refusal naming the principal, before any tree read.
        var plan = Usual with { Default = Usual.Default with { Owner = "owner@example.net" } };
        var tree = RightTree();
        tree.ReadFails.Add("");
        tree.ReadFails.Add("f.txt");   // a read attempted anyway would be an error record, not silent
        var deps = new CheckDeps(_ => { }, _ => tree,
            _ => throw new SystemException("The trust relationship between this workstation and the primary domain failed."));
        var o = new StringWriter();
        var e = new StringWriter();
        var code = Cli.Run(["check", PlanFile(plan), "R"], o, e, check: deps);
        Assert.Equal(1, code);
        Assert.Empty(o.ToString());
        Assert.Contains("owner@example.net", e.ToString());
        Assert.Contains("do not resolve", e.ToString());
    }

    [Fact]
    public void MissingBackupPrivilegeReadsNothing()
    {
        var (code, o, e) = Run(RightTree(), "SeBackupPrivilege", "check", PlanFile(Usual), "R");
        Assert.Equal(1, code);
        Assert.Empty(o);
        Assert.Contains("SeBackupPrivilege", e);
    }

    // #78: check prints the resolved principal -> SID table, as apply does.
    [Fact]
    public void PrintsTheResolvedPrincipalTable()
    {
        var named = Usual with
        {
            Default = new PlanRule("default", new PlanMatch("", ""), false, false, true, false, false, "", "", [],
                [PA(A(0, ""), "user@example.net")]),
            Rules = [],
        };
        var deps = new CheckDeps(_ => { }, _ => RightTree(), n => n == "user@example.net" ? Users : null);
        var o = new StringWriter();
        var e = new StringWriter();
        int code = Cli.Run(["check", PlanFile(named), "R"], o, e, check: deps);
        Assert.Equal(0, code);
        Assert.Contains($"check: principal user@example.net = {Users}", e.ToString());
    }

    [Fact]
    public void ASchema1PlanIsRefused()
    {
        var (code, o, e) = Run(RightTree(), null, "check", PlanFile(Usual with { Schema = Plan.SaclSchema, Default = Usual.Default with { Dacl = null, HasAcl = false }, Rules = [] }), "R");
        Assert.Equal(1, code);
        Assert.Empty(o);
        Assert.Contains("schema 2", e);
    }

    // A plan file that can't be read is a message and exit 1, from check (before any privilege or
    // tree use) and from plan alike, never an unhandled exception.
    [Theory]
    [InlineData("check")]
    [InlineData("plan")]
    [InlineData("apply")]
    public void AnUnreadablePlanExitsOneWithAMessage(string cmd)
    {
        var missing = Path.Combine(Path.GetTempPath(), $"smbplan-missing-{Guid.NewGuid():N}.json");
        string[] args = cmd == "plan" ? ["plan", missing] : [cmd, missing, "R"];
        var (code, o, e) = Run(RightTree(), "SeBackupPrivilege", args);
        Assert.Equal(1, code);
        Assert.Empty(o);
        Assert.Contains($"cannot read plan {missing}", e);
        Assert.DoesNotContain("SeBackupPrivilege", e);
        Assert.DoesNotContain("--help", e);
    }

    [Theory]
    [InlineData("check")]
    [InlineData("check", "plan.json")]
    [InlineData("check", "--workers", "0", "plan.json", "R")]
    [InlineData("check", "--frobnicate", "plan.json", "R")]
    public void UsageErrorsExitTwo(params string[] args) =>
        Assert.Equal(2, Run(RightTree(), null, args).Code);

    // smb/DESIGN-sacl-write.md 6: a plan with a sacl: rule is no longer refused; check runs the
    // probe's bypass proof first, and no tree SACL is read before the probe's step 2 write.
    [Fact]
    public void APlanThatSetsSaclRunsTheProbeBeforeAnyTreeSaclRead()
    {
        var plan = Usual with { Schema = Plan.SmbSaclSchema, Default = Usual.Default with { SaclSet = true } };
        var tree = WrongTree();
        int writesBeforeRootSaclRead = -1;
        tree.BeforeSaclRead = rel => { if (rel == "" && writesBeforeRootSaclRead < 0) writesBeforeRootSaclRead = tree.Writes.Count; };
        var (code, _, err) = Run(tree, null, "check", PlanFile(plan), @"\\array\share\dept");
        Assert.Equal(0, code);
        Assert.DoesNotContain("set sacl:", err);
        Assert.True(writesBeforeRootSaclRead > 0);
        // Before that read, the probe's step 2 proof had already gone out: a SACL write on a
        // probe object, never on the root (decision 17).
        Assert.Contains(tree.Writes[..writesBeforeRootSaclRead],
            w => w.Rel.StartsWith(Preflight.Prefix, StringComparison.Ordinal) && (w.Info & SecurityInformation.Sacl) != 0);
    }
}
