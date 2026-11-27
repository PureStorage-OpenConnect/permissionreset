using System.ComponentModel;
using System.Text.Json;
using PermissionReset.Smb.Core;
using static PermissionReset.Smb.Tests.CheckerTests;

namespace PermissionReset.Smb.Tests;

// The SACL preflight of smb/DESIGN-sacl-write.md section 6, against FakeTree. FakeTree models what
// FlashArray was measured to do (K9/K10/K11/K13 in section 1), so a wrong SACL model fails here
// first. The CLI's check-probe plumbing is covered at the bottom: the probe runs before the
// schema 3 walk, its events recorded and no tree SACL read before the proof.
public class SaclPreflightTests : IDisposable
{
    const byte OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, ID = AceFlags.Inherited;
    const byte SA = AceFlags.SuccessfulAccess, FA = AceFlags.FailedAccess;

    static Ace Au(byte flags, string sid, uint mask = 0x1f01ff) => new(AceTypes.Audit, flags, mask, sid);

    // The probe's DACL steps get the usual dir-shaped ACEs.
    static readonly List<Ace> RootDacl = [A(OI | CI, Users), A(OI | CI, Admins, 0x1f01ff)];

    static FakeTree Tree() => new(new() { [""] = new(true, DirWant, true) });

    [Fact]
    public void ApplyModeHappyPathRootPassesNothingDown()
    {
        // The root passes nothing, so step 4 writes the inheritable placeholder instead (design 6,
        // step 4), and the children still must hold its inh ID part.
        var tree = Tree();
        int calls = 0;
        var events = new List<ProbeEvent>();
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => { calls++; return []; }, ProbeMode.Apply, events.Add), name: "px");
        Assert.True(r.Passed, r.Detail);
        Assert.Equal(1, calls);
        Assert.Single(tree.Objs.Keys);          // the probe is removed; only the tree root remains
        Assert.Contains("K11", r.Detail);       // the line names the confirmed S:AI rule (7.2)
    }

    [Fact]
    public void ApplyModeHappyPathRootPassesAcesDown()
    {
        var tree = Tree();
        var events = new List<ProbeEvent>();
        var rootSacl = new List<Ace> { Au(OI | CI | SA | FA, Users) };
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => [.. rootSacl], ProbeMode.Apply, events.Add), name: "px");
        Assert.True(r.Passed, r.Detail);
        Assert.Single(tree.Objs.Keys);
        // The last write of the subdir is step 5's AI-clear unprotected write: the control word it
        // sent has S:AI clear, and the run passed, so the array stored S:AI set anyway (K11).
        Assert.Equal(0, tree.SentControl["px/d"] & Control.SaclAutoInherited);
        // 5a's write carried one explicit audit ACE, then the inherited part of step 4's ACEs.
        Assert.Contains(tree.Writes, w => w.Rel == "px/f");
    }

    [Fact]
    public void CheckModeRunsOnlySteps1And2AndCleanup()
    {
        var tree = Tree();
        int calls = 0;
        var events = new List<ProbeEvent>();
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => { calls++; return []; }, ProbeMode.Check, events.Add), name: "px");
        Assert.True(r.Passed, r.Detail);
        Assert.Equal(0, calls);                                     // steps 3-6 skipped: the root's SACL is never asked for
        // Exactly two writes: step 2's placeholder SACL and cleanup's DACL. The DACL steps (step
        // 7) are apply's; check runs steps 1, 2 and 7's cleanup (design 6).
        Assert.Equal(2, tree.Writes.Count);
        Assert.Single(tree.Writes, w => (w.Info & SecurityInformation.Sacl) != 0);
        Assert.Single(tree.Writes, w => (w.Info & SecurityInformation.Dacl) != 0);
        Assert.Single(tree.Objs.Keys);
    }

    [Fact]
    public void CheckModeRecordsStep1First()
    {
        // Finding b in check mode, the mode the bypass proof runs in: the shard opens with step 1.
        var tree = Tree();
        var events = new List<ProbeEvent>();
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => [], ProbeMode.Check, events.Add), name: "px");
        Assert.True(r.Passed, r.Detail);
        Assert.Equal(["px", "px/d", "px/f"], events.Where(e => e.Kind == "create").Select(e => e.Rel).ToList());
        Assert.Equal("create", events[0].Kind);
    }

    [Fact]
    public void NoBypassRefusesAndRemovesTheProbe()
    {
        // K12, design 5 layer 2: error 5 on the SACL write is "no audit bypass".
        var tree = Tree();
        tree.RefuseSaclAccess = true;
        int calls = 0;
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => { calls++; return []; }, ProbeMode.Apply), name: "px");
        Assert.False(r.Passed);
        Assert.Contains("audit bypass", r.Detail);
        Assert.Equal(0, calls);                                     // the proxy never got as far as the root's SACL
        Assert.Single(tree.Objs.Keys);                              // the probe was removed
        Assert.Empty(tree.SaclReads);                               // no SACL read succeeded anywhere, tree or probe
    }

    [Fact]
    public void APlaceholderThatDoesNotReadBackRefusesAndRemovesTheProbe()
    {
        // Design 5 layer 3 / K5: the write is accepted but nothing is stored.
        var tree = Tree();
        tree.DropSacl = true;
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => [], ProbeMode.Apply), name: "px");
        Assert.False(r.Passed);
        Assert.Contains("did not keep", r.Detail);
        Assert.Single(tree.Objs.Keys);
    }

    [Fact]
    public void AnSaiRuleMismatchRefuses()
    {
        // Model an array that stores S:AI set on a protected SACL, against K11: step 5b's reading
        // disagrees with the rule in 4.3, and the run refuses.
        var tree = Tree();
        tree.AfterWrite = rel =>
        {
            if (rel == "px/f" && tree.Objs[rel].SaclProtected)
                tree.Objs[rel] = tree.Objs[rel] with { ExtraControl = (ushort)(tree.Objs[rel].ExtraControl | Control.SaclAutoInherited) };
        };
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => [], ProbeMode.Apply), name: "px");
        Assert.False(r.Passed);
        Assert.Contains("K11", r.Detail);
        Assert.Contains("protected", r.Detail);
        Assert.Single(tree.Objs.Keys);
    }

    [Fact]
    public void AChangedDaclAcrossTheSaclStepsRefuses()
    {
        // Design 6 step 6 / K2: the SACL steps must leave owner, group, DACL bytes and DACL
        // control bits alone. Here a SACL write flips D:P on the probe dir.
        var tree = Tree();
        tree.AfterWrite = rel =>
        {
            if (rel == "px" && tree.Objs[rel].SaclEverWritten)
                tree.Objs[rel] = tree.Objs[rel] with { Protected = true };
        };
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => [], ProbeMode.Apply), name: "px");
        Assert.False(r.Passed);
        Assert.Contains("K2", r.Detail);
        Assert.Single(tree.Objs.Keys);
    }

    [Fact]
    public void AChangedDaclOnTheProbeFileAcrossTheSaclStepsRefuses()
    {
        // Step 6 covers the whole probe: step 5 writes the subdirectory and the file too.
        var tree = Tree();
        tree.AfterWrite = rel =>
        {
            if (rel == "px/f" && tree.Objs[rel].SaclEverWritten)
                tree.Objs[rel] = tree.Objs[rel] with { Protected = true };
        };
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => [], ProbeMode.Apply), name: "px");
        Assert.False(r.Passed);
        Assert.Contains("px/f", r.Detail);
        Assert.Contains("K2", r.Detail);
    }

    [Fact]
    public void ACleanupFailureRefuses()
    {
        var tree = Tree();
        tree.DeleteFails.Add("px/f");
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => [], ProbeMode.Apply), name: "px");
        Assert.False(r.Passed);
        Assert.Contains("could not be removed", r.Detail);
        Assert.Contains("px", tree.Objs.Keys);                       // the probe was left behind, as said
    }

    [Fact]
    public void TheRootsSaclIsReadOnlyAfterTheBypassIsProven()
    {
        // Design 6's ordering: no tree object's SACL is read before step 2 succeeds. The only path
        // to the root's SACL is the delegate, so it must be called exactly once, and only after
        // the probe's step 2 placeholder SACL write.
        var tree = Tree();
        int calls = 0, writesAtCall = -1;
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() =>
        {
            calls++;
            writesAtCall = tree.Writes.Count;
            return [];
        }, ProbeMode.Apply), name: "px");
        Assert.True(r.Passed, r.Detail);
        Assert.Equal(1, calls);
        Assert.True(writesAtCall > 0);
        Assert.Contains(tree.Writes[..writesAtCall], w => w.Rel == "px" && (w.Info & SecurityInformation.Sacl) != 0);
        // The probe never reads or writes the tree root itself ("px*" only): decision 17.
        Assert.DoesNotContain(tree.SaclReads, rel => rel == "");
        Assert.DoesNotContain(tree.Writes, w => w.Rel == "");
        Assert.All(tree.Writes, w => Assert.StartsWith("px", w.Rel));
    }

    [Fact]
    public void EveryProbeWriteReadbackAndRemovalIsRecorded()
    {
        // Decision 18: the sink sees a write (with its read-back), the check reads, and each removal.
        var tree = Tree();
        var events = new List<ProbeEvent>();
        var r = Preflight.Run(tree, "", RootDacl, new SaclProbe(() => [], ProbeMode.Apply, events.Add), name: "px");
        Assert.True(r.Passed, r.Detail);
        Assert.Contains(events, e => e.Kind == "write" && e.Rel == "px");
        Assert.Contains(events, e => e.Kind == "write" && e.Rel == "px/d");
        Assert.Contains(events, e => e.Kind == "write" && e.Rel == "px/f");
        Assert.Contains(events, e => e.Kind == "read");
        Assert.Contains(events, e => e.Kind == "remove" && e.Rel == "px/f");
        Assert.Contains(events, e => e.Kind == "remove" && e.Rel == "px/d");
        Assert.Contains(events, e => e.Kind == "remove" && e.Rel == "px");
        // Step 1 (win01-lab's #93 probe, finding b): the three creations come first, in order.
        Assert.Equal([("create", "px"), ("create", "px/d"), ("create", "px/f")],
            events.Take(3).Select(e => (e.Kind, e.Rel)).ToList());
        Assert.Equal(3, events.Count(e => e.Kind == "create"));
        Assert.StartsWith("PROBE-CREATE: px: step 1:", ProbeShard.Line(events[0]));
        Assert.All(events.Where(e => e.Kind == "write"), e => Assert.False(string.IsNullOrEmpty(e.AfterB64)));
        Assert.Equal(events.Count, events.Select(e => ProbeShard.Line(e)).Distinct().Count());   // every line renders
    }

    // ---- the check CLI's probe plumbing (design 6, wired in phase 3 S-D) -----------------------

    // A schema 3 plan: the default rule plus one directory rule with sacl: set on an audit ACE.
    static Plan SaclPlan()
    {
        var audit = new PlanAce("line", 0, 0, AceTypes.Audit, SA, 0x1f01ff, "", false, "S-1-1-0", "");
        var saclRule = new PlanRule("rule[sacl]", new PlanMatch("directory", ""), true, false, true, false, false, "", "", [audit],
            DirWant.Select(a => PA(a)).ToList());
        return Usual with { Schema = Plan.SmbSaclSchema, Rules = [saclRule, .. Usual.Rules] };
    }

    string PlanFile(Plan? plan = null)
    {
        var f = Path.Combine(Path.GetTempPath(), $"smbplan-{Guid.NewGuid():N}.json");
        File.WriteAllText(f, JsonSerializer.Serialize(plan ?? SaclPlan()));
        _planFiles.Add(f);
        return f;
    }

    readonly List<string> _planFiles = [];
    readonly List<string> _dirs = [];

    string NewDir() { var d = Path.Combine(Path.GetTempPath(), $"smbpf-{Guid.NewGuid():N}"); _dirs.Add(d); return d; }

    static (int Code, string Out, string Err) Run(FakeTree tree, Action<string> enablePrivilege, params string[] args)
    {
        var deps = new CheckDeps(enablePrivilege, _ => tree, _ => null);
        var o = new StringWriter();
        var e = new StringWriter();
        int code = Cli.Run(args, o, e, check: deps);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public void CheckRunsTheProbeThenWalksWithSaclOutcomes()
    {
        // The wired check: privilege, probe, events, then the schema 3 walk. The probe proves the
        // bypass on throwaway objects only; the walk then reads the root's SACL itself.
        var tree = Tree();
        var evidence = NewDir();
        var (code, o, e) = Run(tree, _ => { }, "check", "--evidence-dir", evidence, PlanFile(), @"\\array\share\dept");
        Assert.Equal(0, code);
        Assert.Contains("preflight passed", e);
        Assert.DoesNotContain(tree.Writes, w => !w.Rel.StartsWith(Preflight.Prefix, StringComparison.Ordinal));
        Assert.Single(tree.Objs.Keys);                                 // the probe was removed
        Assert.DoesNotContain(tree.SaclReads, rel => !rel.StartsWith(Preflight.Prefix, StringComparison.Ordinal) && rel != "");
        Assert.Single(tree.SaclReads, rel => rel == "");               // the walk's compare read, after the proof
        var shard = File.ReadAllText(Path.Combine(evidence, ProbeShard.ShardName));
        Assert.Contains("PROBE-WRITE", shard);
        Assert.Contains("PROBE-REMOVE", shard);
        // The walk ran saclMode: the root's record carries the two part verdicts (4.6).
        Assert.Contains("\"sacl_outcome\":\"write\"", o);
        Assert.Contains("\"dacl_outcome\":\"ok\"", o);
        Assert.Contains("\"sacl_form\":\"protected\"", o);
    }

    [Fact]
    public void CheckAcceptUnprovenReadSkipsTheProbeWithANote()
    {
        var tree = Tree();
        var (code, o, e) = Run(tree, _ => { }, "check", "--accept-unproven-read", PlanFile(), @"\\array\share\dept");
        Assert.Equal(0, code);
        Assert.Contains("NOTE", e);
        Assert.Contains("unproven", e);
        Assert.DoesNotContain("preflight passed", e);
        Assert.Empty(tree.Writes);                                     // no probe was created
        Assert.Single(tree.SaclReads, rel => rel == "");               // the tree's SACLs are read, unproven
        Assert.Contains("\"sacl_outcome\":\"write\"", o);
    }

    [Fact]
    public void APrincipalResolvingToACreatorSidIsRefusedWithNoProbeAndNoTreeRead()
    {
        // Design 2.2's order: every plan and principal check comes before any probe or read. The
        // refusal fires in the Checker's constructor, so no probe is created and nothing is read.
        var ace = new PlanAce("line", 0, 0, AceTypes.Audit, (byte)(OI | CI | SA | FA), 0x1, "creator@example.net", false, "", "");
        var basePlan = SaclPlan();
        var plan = basePlan with { Rules = [basePlan.Rules[0] with { Sacl = [ace] }, .. basePlan.Rules.Skip(1)] };
        var tree = Tree();
        var deps = new CheckDeps(_ => { }, _ => tree, n => n == "creator@example.net" ? "S-1-3-0" : null);
        var e = new StringWriter();
        var code = Cli.Run(["check", PlanFile(plan), @"\\array\share\dept"], new StringWriter(), e, check: deps);
        Assert.Equal(1, code);
        Assert.Contains("creator@example.net", e.ToString());
        Assert.Contains("creator SID", e.ToString());
        Assert.Empty(tree.Writes);                                     // no probe
        Assert.Empty(tree.SaclReads);                                  // and no tree read
    }

    [Fact]
    public void CheckExits1NamingSeSecurityPrivilegeBeforeEvidenceOrProbeExist()
    {
        var tree = Tree();
        var evidence = NewDir();
        var (code, _, e) = Run(tree, n =>
        {
            if (n == "SeSecurityPrivilege") throw new Win32Exception(1300, $"this account does not hold {n}; run elevated as an account that does");
        }, "check", "--evidence-dir", evidence, PlanFile(), @"\\array\share\dept");
        Assert.Equal(1, code);
        Assert.Contains("SeSecurityPrivilege", e);
        Assert.False(Directory.Exists(evidence));                      // the evidence dir did not appear
        Assert.Empty(tree.Writes);                                     // no probe was created
        Assert.Empty(tree.SaclReads);
    }

    [Fact]
    public void CheckWithoutAWritableProbeLocationExits1BeforeReadingTheTree()
    {
        // A probe location whose parent does not exist refuses creation: nothing is created, and
        // the tree's SACLs are never read.
        var tree = Tree();
        var nowhere = new FakeTree([]);
        var deps = new CheckDeps(_ => { }, root => root == "nowhere" ? nowhere : tree, _ => null);
        var e = new StringWriter();
        var code = Cli.Run(["check", "--probe-dir", "nowhere", PlanFile(), @"\\array\share\dept"], new StringWriter(), e, check: deps);
        Assert.Equal(1, code);
        Assert.Contains("preflight refused", e.ToString());
        Assert.Empty(nowhere.Objs);                                    // nothing left behind
        Assert.Empty(tree.SaclReads);
    }

    public void Dispose()
    {
        foreach (var f in _planFiles) File.Delete(f);
        foreach (var d in _dirs.Where(Directory.Exists)) Directory.Delete(d, true);
    }
}
