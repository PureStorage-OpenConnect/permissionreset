using System.ComponentModel;
using System.Text.Json;
using PermissionReset.Smb.Core;
using static PermissionReset.Smb.Tests.CheckerTests;

namespace PermissionReset.Smb.Tests;

// apply's records, evidence, privileges and exit codes, through FakeTree. The walk and its guards
// are in ApplyTests; these pin what the CLI does around them.
public sealed class ApplyCliTests : IDisposable
{
    readonly List<string> _temp = [];

    string Temp(string kind)
    {
        var p = Path.Combine(Path.GetTempPath(), $"smb{kind}-{Guid.NewGuid():N}");
        _temp.Add(p);
        return p;
    }

    string PlanFile(Plan p)
    {
        var f = Temp("plan") + ".json";
        _temp.Add(f);
        File.WriteAllText(f, JsonSerializer.Serialize(p));
        return f;
    }

    public void Dispose()
    {
        foreach (var p in _temp)
        {
            if (File.Exists(p)) File.Delete(p);
            else if (Directory.Exists(p)) Directory.Delete(p, true);
        }
    }

    sealed record Result(int Code, string Out, string Err, List<string> Enabled, List<string> Disabled);

    static Result RunWith(FakeTree tree, string? missingPrivilege, Func<string, string?>? resolve, params string[] args)
    {
        var enabled = new List<string>();
        var disabled = new List<string>();
        var deps = new CheckDeps(
            n =>
            {
                if (n == missingPrivilege) throw new Win32Exception(1300, $"this account does not hold {n}; run elevated as an account that does");
                enabled.Add(n);
            },
            _ => tree,
            resolve ?? (_ => null),
            disabled.Add);
        var o = new StringWriter();
        var e = new StringWriter();
        int code = Cli.Run(args, o, e, check: deps);
        return new Result(code, o.ToString(), e.ToString(), enabled, disabled);
    }

    static Result Run(FakeTree tree, params string[] args) => RunWith(tree, null, null, args);

    static FakeTree Flattened() => new(new()
    {
        [""] = new(true, DirWant, true),
        ["a"] = new(true, DirWant, true),
        ["a/f.txt"] = new(false, FileWant, true),
    });

    static bool TreeWritten(FakeTree t) => t.Writes.Any(w => !w.Rel.StartsWith(Preflight.Prefix, StringComparison.Ordinal));

    [Fact]
    public void ApplyConvergesAndRecordsEvidence()
    {
        var tree = Flattened();
        var ev = Temp("ev");
        var r = Run(tree, "apply", "--evidence-dir", ev, PlanFile(Usual), @"\\array\share\dept");
        Assert.Equal(0, r.Code);
        Assert.Equal(["SeBackupPrivilege", "SeSecurityPrivilege"], r.Enabled);
        Assert.Equal(["SeRestorePrivilege"], r.Disabled);
        Assert.Contains("preflight passed", r.Err);
        Assert.Contains("written 2", r.Err);
        Assert.Contains("apply: complete", r.Err);
        Assert.Contains("\"outcome\":\"written\"", r.Out);
        Assert.DoesNotContain("before", r.Out);                       // raw descriptors go to the evidence only

        var lines = File.ReadAllLines(Path.Combine(ev, Evidence.ShardName));
        Assert.Equal(3, lines.Length);
        Assert.Contains(lines, l => l.StartsWith(@"OK: set dacl \\array\share\dept") && l.Contains("\tbefore=") && l.Contains("\tafter="));
        Assert.Contains(lines, l => l.StartsWith("SAME: "));
        using var m = JsonDocument.Parse(File.ReadAllText(Path.Combine(ev, "manifest.json")));
        Assert.Equal("complete", m.RootElement.GetProperty("status").GetString());
        Assert.Equal(3, m.RootElement.GetProperty("records").GetInt64());
        var shard = m.RootElement.GetProperty("shards")[0];
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Path.Combine(ev, Evidence.ShardName)))).ToLowerInvariant(),
            shard.GetProperty("sha256").GetString());
        Assert.StartsWith("preflight passed", m.RootElement.GetProperty("preflight").GetString());
    }

    [Fact]
    public void APlanThatSetsAnOwnerEnablesRestoreAndPrintsThePrincipalTable()
    {
        var plan = Usual with { Rules = [.. Usual.Rules.Select(r => r.Match.Type == "file" ? r with { Owner = "owner@example.net" } : r)] };
        var tree = Flattened();
        var r = RunWith(tree, null, n => n == "owner@example.net" ? Admins : null, "apply", PlanFile(plan), "R");
        Assert.Equal(0, r.Code);
        Assert.Contains("SeRestorePrivilege", r.Enabled);
        Assert.Empty(r.Disabled);
        Assert.Contains($"apply: principal owner@example.net = {Admins}", r.Err);
    }

    [Fact]
    public void ARefusedPreflightWritesNothingInTheTree()
    {
        var tree = Flattened();
        tree.DropSacl = true;
        var ev = Temp("ev");
        var r = Run(tree, "apply", "--evidence-dir", ev, PlanFile(Usual), "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("preflight refused", r.Err);
        Assert.Contains("nothing in the tree was written", r.Err);
        Assert.Empty(r.Out);
        Assert.False(TreeWritten(tree));
        Assert.DoesNotContain(tree.Objs.Keys, k => k.StartsWith(Preflight.Prefix));
        using var m = JsonDocument.Parse(File.ReadAllText(Path.Combine(ev, "manifest.json")));
        Assert.Equal("incomplete", m.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public void ARefusedPreflightLeavesNoCheckpointSoTheSameCommandCanBeRerun()
    {
        var tree = Flattened();
        tree.DropSacl = true;
        var cp = Temp("cp");
        var plan = PlanFile(Usual);
        var r = Run(tree, "apply", "--checkpoint", cp, plan, "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("preflight refused", r.Err);
        Assert.False(File.Exists(cp));

        tree.DropSacl = false;                                         // the operator fixes the array
        r = Run(tree, "apply", "--checkpoint", cp, plan, "R");
        Assert.Equal(0, r.Code);
        Assert.Contains("apply: complete", r.Err);
        Assert.StartsWith("permissionreset-smb checkpoint v1 ", File.ReadLines(cp).First());
    }

    [Fact]
    public void APlanWithAByteOrderMarkAppliesAsItChecks()
    {
        var plan = PlanFile(Usual);
        File.WriteAllText(plan, File.ReadAllText(plan), new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        Assert.Equal(0xEF, File.ReadAllBytes(plan)[0]);
        var r = Run(Flattened(), "apply", plan, "R");
        Assert.Equal(0, r.Code);
        Assert.Contains("apply: complete", r.Err);
    }

    [Fact]
    public void AMissingSecurityPrivilegeWritesNothing()
    {
        var tree = Flattened();
        var cp = Temp("cp");
        var r = RunWith(tree, "SeSecurityPrivilege", null, "apply", "--checkpoint", cp, PlanFile(Usual), "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("SeSecurityPrivilege", r.Err);
        Assert.Empty(tree.Writes);
        Assert.False(File.Exists(cp));
    }

    [Fact]
    public void AGuardStopExitsOneAndTheManifestSaysWhy()
    {
        var tree = Flattened();
        tree.AfterWrite = rel => { if (rel == "a") tree.Objs[rel] = tree.Objs[rel] with { Protected = true }; };
        var ev = Temp("ev");
        var r = Run(tree, "apply", "--evidence-dir", ev, PlanFile(Usual), "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("apply: G2:", r.Err);
        Assert.Contains("apply: incomplete", r.Err);
        using var m = JsonDocument.Parse(File.ReadAllText(Path.Combine(ev, "manifest.json")));
        Assert.StartsWith("G2:", m.RootElement.GetProperty("stop").GetString());
        Assert.Contains(File.ReadAllLines(Path.Combine(ev, Evidence.ShardName)), l => l.StartsWith("ERR: ") && l.Contains("\tafter="));
    }

    [Fact]
    public void ACheckpointResumesAndAStaleOneIsRefused()
    {
        var cp = Temp("cp");
        var plan = PlanFile(Usual);
        Assert.Equal(0, Run(Flattened(), "apply", "--checkpoint", cp, plan, "R").Code);
        var ev = Temp("ev");
        var again = Run(Flattened(), "apply", "--checkpoint", cp, "--evidence-dir", ev, plan, "R");
        Assert.Equal(1, again.Code);
        Assert.Contains("--resume", again.Err);
        Assert.False(Directory.Exists(ev));                            // a refused checkpoint leaves no evidence
        var resumed = Run(Flattened(), "apply", "--checkpoint", cp, "--resume", plan, "R");
        Assert.Equal(0, resumed.Code);
        Assert.Contains("2 director(ies) already complete", resumed.Err);
        Assert.Equal(1, Run(Flattened(), "apply", "--checkpoint", cp, "--resume", plan, "OTHER").Code);
    }

    [Fact]
    public void ANonEmptyEvidenceDirIsRefusedBeforeACheckpointIsMade()
    {
        var ev = Temp("ev");
        Directory.CreateDirectory(ev);
        File.WriteAllText(Path.Combine(ev, "x"), "");
        var cp = Temp("cp");
        var tree = Flattened();
        var r = Run(tree, "apply", "--evidence-dir", ev, "--checkpoint", cp, PlanFile(Usual), "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("not empty", r.Err);
        Assert.False(File.Exists(cp));
        Assert.Empty(tree.Writes);
    }

    [Fact]
    public void AnUnresolvedPrincipalLeavesNoCheckpointOrEvidence()
    {
        var plan = Usual with { Rules = [.. Usual.Rules.Select(r => r with { Owner = "nobody@example.net" })] };
        var cp = Temp("cp");
        var ev = Temp("ev");
        var r = Run(Flattened(), "apply", "--checkpoint", cp, "--evidence-dir", ev, PlanFile(plan), "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("nobody@example.net", r.Err);
        Assert.False(File.Exists(cp));
        Assert.False(Directory.Exists(ev));
    }

    [Fact]
    public void APlanThatSetsSaclIsRefused()
    {
        var plan = Usual with { Schema = Plan.SmbSaclSchema, Default = Usual.Default with { SaclSet = true } };
        var tree = Flattened();
        var r = Run(tree, "apply", PlanFile(plan), "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("writes no SACL", r.Err);
        Assert.Empty(tree.Writes);
    }

    // smb/DESIGN-sacl-write.md 2.1: a schema 2 plan with a sacl rule predates this tool and is
    // refused at load, not reinterpreted.
    [Fact]
    public void ASchema2PlanThatSetsSaclIsRefusedWithARebuildMessage()
    {
        var plan = Usual with { Default = Usual.Default with { SaclSet = true } };
        var tree = Flattened();
        var r = Run(tree, "apply", PlanFile(plan), "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("rebuild", r.Err);
        Assert.Empty(tree.Writes);
    }

    [Fact]
    public void CheckTakesRootProtected()
    {
        var tree = new FakeTree(new() { [""] = new(true, DirInherited, false) });
        var plan = PlanFile(Usual);
        Assert.Equal(0, Run(tree, "check", "--validate", plan, "R").Code);
        Assert.Equal(1, Run(tree, "check", "--validate", "--root-protected", plan, "R").Code);
    }

    [Theory]
    [InlineData("apply")]
    [InlineData("apply", "plan.json")]
    [InlineData("apply", "--resume", "plan.json", "R")]
    [InlineData("apply", "--workers", "0", "plan.json", "R")]
    [InlineData("apply", "--probe-dir")]
    [InlineData("apply", "--frobnicate", "plan.json", "R")]
    public void UsageErrorsExitTwo(params string[] args) =>
        Assert.Equal(2, Run(Flattened(), args).Code);
}
