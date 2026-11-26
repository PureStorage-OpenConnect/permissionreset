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
        Assert.Single(m.RootElement.GetProperty("shards").EnumerateArray());   // a phase 2 manifest is unchanged
        Assert.False(m.RootElement.TryGetProperty("sacl_forms", out _));
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
        Assert.StartsWith("permissionreset-smb checkpoint v2 ", File.ReadLines(cp).First());
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

    // ---- phase 3: sacl: plans (smb/DESIGN-sacl-write.md sections 4.2, 5, 6, 7.2) ------------------

    const byte OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, ID = AceFlags.Inherited,
        SA = AceFlags.SuccessfulAccess, FA = AceFlags.FailedAccess;

    static Ace AU(byte flags, string sid) => new(AceTypes.Audit, flags, 0x1, sid);
    static readonly Ace AuditDir = AU(OI | CI | SA | FA, Users);
    static readonly Ace AuditFile = AU(SA | FA, Users);

    // A schema 3 plan: phase 2's DACLs plus one ambient audit ACE per kind.
    static Plan AuditedPlan()
    {
        static PlanAce AUP(Ace a) => new("line", 0, 0, a.Type, a.Flags, a.Mask, "", false, a.Sid, "");
        PlanRule R(string label, string type, Ace[] dacl, Ace[] sacl) =>
            new(label, new PlanMatch(type, ""), true, false, true, false, false, "", "",
                sacl.Select(AUP).ToList(), dacl.Select(a => PA(a)).ToList());
        return new Plan(Plan.SmbSaclSchema, "t.yaml", "nfsv4", new PlanExclude(["skip"], ["skip"], []),
            new PlanRule("default", new PlanMatch("", ""), false, false, true, false, false, "", "", [],
                FileWant.Select(a => PA(a)).ToList()),
            [R("rule[0]", "directory", DirWant, [AuditDir]), R("rule[1]", "file", FileWant, [AuditFile])]);
    }

    // DACLs right, SACLs never audited (S:AI empty, K9).
    static FakeTree NeverAudited() => new(new()
    {
        [""] = new(true, DirWant, true),
        ["a"] = new(true, DirInherited, false),
        ["a/f.txt"] = new(false, FileInherited, false),
    });

    // x.txt needs both parts: its DACL is explicit-only and its SACL is S:P with an audit ACE the
    // rule does not name.
    static FakeTree TwoPart() => new(new()
    {
        [""] = new(true, DirWant, true, Sacl: [AuditDir], SaclProtected: true, SaclEverWritten: true),
        ["x.txt"] = new(false, [A(0, Other)], false, Sacl: [AU(SA | FA, Other)], SaclProtected: true, SaclEverWritten: true),
    });

    [Fact]
    public void ApplyWithASaclPlanRunsTheProbeThenWritesTheRootSaclOnce()
    {
        // The wired apply end to end: design 6's full preflight runs (the decision-18 shard lands
        // in the evidence directory), the root's SACL is written once, and the never-written
        // children follow it (K10).
        var tree = NeverAudited();
        int writesBeforeRootSaclRead = -1;
        tree.BeforeSaclRead = rel => { if (rel == "" && writesBeforeRootSaclRead < 0) writesBeforeRootSaclRead = tree.Writes.Count; };
        var ev = Temp("ev");
        var r = Run(tree, "apply", "--evidence-dir", ev, PlanFile(AuditedPlan()), @"\\array\share\dept");
        Assert.True(r.Code == 0, r.Err);
        Assert.Contains("preflight passed", r.Err);
        Assert.Contains("apply: complete", r.Err);
        Assert.DoesNotContain(tree.Objs.Keys, k => k.StartsWith(Preflight.Prefix));
        // checker.RootSacl ran only inside the probe, after step 2's bypass proof.
        Assert.True(writesBeforeRootSaclRead > 0);
        Assert.Contains(tree.Writes[..writesBeforeRootSaclRead],
            w => w.Rel.StartsWith(Preflight.Prefix, StringComparison.Ordinal) && (w.Info & SecurityInformation.Sacl) != 0);
        var w = Assert.Single(tree.Writes.Where(x => !x.Rel.StartsWith(Preflight.Prefix, StringComparison.Ordinal)));
        Assert.Equal("", w.Rel);
        Assert.Equal(SecurityInformation.Sacl | SecurityInformation.ProtectedSacl, w.Info);
        Assert.Contains("\"sacl_outcome\":\"written\"", r.Out);
        var shard = File.ReadAllText(Path.Combine(ev, ProbeShard.ShardName));
        Assert.Contains("PROBE-WRITE", shard);
        Assert.Contains("PROBE-REMOVE", shard);
        using var m = JsonDocument.Parse(File.ReadAllText(Path.Combine(ev, "manifest.json")));
        Assert.Equal("complete", m.RootElement.GetProperty("status").GetString());
        Assert.Equal("sacl-first", m.RootElement.GetProperty("write_order").GetString());
        // 7.2: the preflight shard is bound in the manifest beside the walk's shard.
        var shards = m.RootElement.GetProperty("shards").EnumerateArray().ToList();
        Assert.Equal(2, shards.Count);
        var pre = shards[0];
        Assert.Equal(ProbeShard.ShardName, pre.GetProperty("name").GetString());
        var bytes = File.ReadAllBytes(Path.Combine(ev, ProbeShard.ShardName));
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant(), pre.GetProperty("sha256").GetString());
        Assert.Equal(bytes.Length, pre.GetProperty("size").GetInt64());
        Assert.Equal(shard.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length, pre.GetProperty("records").GetInt64());
        Assert.Equal(Evidence.ShardName, shards[1].GetProperty("name").GetString());
        // 7.2: sacl_forms counts on a sacl: plan.
        var sf = m.RootElement.GetProperty("sacl_forms");
        Assert.True(sf.GetProperty("protected").GetInt64() >= 1);       // the root
        Assert.True(sf.GetProperty("inherits").GetInt64() >= 1);        // its never-written children
        // Decision 18: with an evidence directory the probe is not also printed to stdout.
        Assert.DoesNotContain("\"probe\":", r.Out);
    }

    [Fact]
    public void ApplyWithASaclPlanAndNoEvidenceDirPrintsTheProbeEventsAsNotes()
    {
        // Decision 18: without an evidence directory the probe's writes, read-backs and removals
        // still reach the operator, as NOTE lines.
        var r = Run(NeverAudited(), "apply", PlanFile(AuditedPlan()), @"\\array\share\dept");
        Assert.True(r.Code == 0, r.Err);
        Assert.Contains("apply: NOTE: the preflight probe events", r.Err);
        Assert.Contains("PROBE-WRITE", r.Err);
        Assert.Contains("PROBE-REMOVE", r.Err);
        // ...and to one machine-readable probe record on stdout, ahead of the walk's records.
        var first = r.Out.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0];
        using var p = JsonDocument.Parse(first);
        var probe = p.RootElement.GetProperty("probe");
        Assert.True(probe.GetProperty("passed").GetBoolean());
        var kinds = probe.GetProperty("events").EnumerateArray().Select(e => e.GetProperty("kind").GetString()).ToList();
        Assert.Contains("write", kinds, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("remove", kinds, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void WriteOrderDaclFirstPrintsTheNoteOnceAndWritesAccessBeforeAuditing()
    {
        // 4.2: the switch orders one two-part object's two writes; dacl-first says what it risks,
        // once, before any write (decision 11).
        int Notes(Result r) => r.Err.Split('\n').Count(l => l.Contains("NOTE: --write-order dacl-first"));
        var daclFirst = TwoPart();
        var r1 = Run(daclFirst, "apply", "--write-order", "dacl-first", PlanFile(AuditedPlan()), "R");
        Assert.Equal(0, r1.Code);
        Assert.Equal(1, Notes(r1));
        Assert.Equal(SecurityInformation.Dacl | SecurityInformation.UnprotectedDacl,
            daclFirst.Writes.First(w => w.Rel == "x.txt").Info);

        var saclFirst = TwoPart();
        var r2 = Run(saclFirst, "apply", PlanFile(AuditedPlan()), "R");
        Assert.Equal(0, r2.Code);
        Assert.Equal(0, Notes(r2));
        Assert.Equal(SecurityInformation.Sacl | SecurityInformation.UnprotectedSacl,
            saclFirst.Writes.First(w => w.Rel == "x.txt").Info);
    }

    [Theory]
    [InlineData("apply")]
    [InlineData("check")]
    public void WriteOrderRejectsAnUnknownValue(string cmd) =>
        Assert.Equal(2, Run(Flattened(), cmd, "--write-order", "bogus", "plan.json", "R").Code);

    [Fact]
    public void ApplyRefusesWhenTheProbeFindsNoAuditBypass()
    {
        // K12/design 5 layer 2 on the wired path: the full preflight stops at step 2, and nothing
        // in the tree is written.
        var tree = NeverAudited();
        tree.RefuseSaclAccess = true;
        var r = Run(tree, "apply", PlanFile(AuditedPlan()), "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("audit bypass", r.Err);
        Assert.Contains("nothing in the tree was written", r.Err);
        // No walk record; only decision 18's probe record (no --evidence-dir), which says it failed.
        using (var p = JsonDocument.Parse(Assert.Single(r.Out.Split('\n', StringSplitOptions.RemoveEmptyEntries))))
            Assert.False(p.RootElement.GetProperty("probe").GetProperty("passed").GetBoolean());
        Assert.False(TreeWritten(tree));
        Assert.DoesNotContain(tree.Writes, w => (w.Info & SecurityInformation.Sacl) != 0);   // K12: no SACL was stored
        Assert.DoesNotContain(tree.Objs.Keys, k => k.StartsWith(Preflight.Prefix));
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

    // ---- phase 3: checkpoint v2 (smb/DESIGN-sacl-write.md 7.1) -----------------------------------------

    [Fact]
    public void ASaclPlanCheckpointResumesAndItsHeaderBindsTheRun()
    {
        var cp = Temp("cp");
        var plan = PlanFile(AuditedPlan());
        var tree = NeverAudited();
        Assert.Equal(0, Run(tree, "apply", "--checkpoint", cp, plan, "R").Code);
        var header = File.ReadLines(cp).First();
        Assert.Contains("checkpoint v2 ", header);
        Assert.Contains("root-sacl-protected=False", header);
        Assert.Contains("principals=", header);
        Assert.Contains("sai-rule=protected-clear,unprotected-set", header);
        Assert.Contains(File.ReadLines(cp), l => l.StartsWith("{\"dir\":"));   // the per-directory records

        var resumed = Run(tree, "apply", "--checkpoint", cp, "--resume", plan, "R");
        Assert.Equal(0, resumed.Code);
        Assert.Contains("apply: complete", resumed.Err);
    }

    [Fact]
    public void AV1CheckpointIsRefusedOnResumeAndNothingIsWritten()
    {
        var cp = Temp("cp");
        File.WriteAllText(cp, "permissionreset-smb checkpoint v1 plan=x root=R root-protected=False\n\"\"\n");
        var tree = NeverAudited();
        var r = Run(tree, "apply", "--checkpoint", cp, "--resume", PlanFile(AuditedPlan()), "R");
        Assert.Equal(1, r.Code);
        Assert.Contains("checkpoint v1", r.Err);
        Assert.Contains("never resumes a v1 checkpoint", r.Err);
        Assert.False(TreeWritten(tree));
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
