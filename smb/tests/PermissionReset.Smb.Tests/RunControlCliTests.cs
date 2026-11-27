using System.Runtime.InteropServices;
using System.Text.Json;
using PermissionReset.Smb.Core;
using static PermissionReset.Smb.Tests.CheckerTests;

namespace PermissionReset.Smb.Tests;

// check's run control (docs/plan-smb-run-control.md, section 7): --state-dir, STOP, --resume,
// status.json and exit code 3, all offline on FakeTree through the CLI. The stop is the test seam
// of CheckDeps.Stop, cancelled from a FakeTree read hook after N object reads (deterministic with
// --workers 1), except StopFileStopsAndIsDeleted, which uses the real STOP file. xUnit makes an
// instance per test and disposes it afterwards, so each test's plan files and state dirs are
// deleted when it ends.
public sealed class RunControlCliTests : IDisposable
{
    readonly List<string> _planFiles = [];
    readonly List<string> _dirs = [];

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
        foreach (var d in _dirs)
            try { Directory.Delete(d, recursive: true); } catch (IOException) { }
    }

    // FlatTree is dirs directories of filesPer files each, all right: objects total is
    // 1 + dirs * (1 + filesPer), every outcome ok.
    static FakeTree FlatTree(int dirs, int filesPer)
    {
        var objs = new Dictionary<string, Obj> { [""] = new(true, DirWant, true) };
        for (int d = 0; d < dirs; d++)
        {
            objs[$"d{d}"] = new(true, DirInherited, false);
            for (int f = 0; f < filesPer; f++) objs[$"d{d}/f{f}"] = new(false, FileInherited, false);
        }
        return new FakeTree(objs);
    }

    static (int Code, string Out, string Err) RunCli(FakeTree tree, CheckDeps deps, params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = Cli.Run(["check", .. args], o, e, check: deps);
        return (code, o.ToString(), e.ToString());
    }

    // Deps is the fake OS surface. Identity and Elevated are pinned (run.json must not depend on
    // the host the tests run on), Alive stubs the resume's liveness check.
    CheckDeps Deps(FakeTree tree, CancellationToken stop = default, Func<int, DateTime, bool>? alive = null) =>
        new(_ => { }, _ => tree, _ => null,
            Stop: stop, Alive: alive,
            Identity: () => @"TESTDOMAIN\testuser", Elevated: () => false);

    string FreshDir()
    {
        var d = Path.Combine(Path.GetTempPath(), $"smbstate-{Guid.NewGuid():N}");
        _dirs.Add(d);
        return d;
    }

    // StopAfterReads returns a token cancelled when the tree's Nth read starts (the object in
    // progress finishes, plan 5.1). stopAfter 0 stops before the walk.
    static CancellationTokenSource StopAfterReads(FakeTree tree, int stopAfter)
    {
        var cts = new CancellationTokenSource();
        if (stopAfter <= 0) { cts.Cancel(); return cts; }
        long reads = 0;
        tree.BeforeRead = _ => { if (Interlocked.Increment(ref reads) == stopAfter) cts.Cancel(); };
        return cts;
    }

    static Dictionary<string, string> LastRecords(params string[] outputs)
    {
        // A resume re-checks objects of incomplete directories, so combined stdout repeats paths;
        // the last line per path is the record (plan 4.3).
        var m = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var o in outputs)
            foreach (var line in o.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                using var doc = JsonDocument.Parse(line);
                m[doc.RootElement.GetProperty("path").GetString()!] = line;
            }
        return m;
    }

    static string SummaryLine(string err) =>
        err.Split('\n', StringSplitOptions.RemoveEmptyEntries).First(l => l.StartsWith("check: ok ", StringComparison.Ordinal));

    JsonElement StatusDoc(string dir)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "status.json")));
        return doc.RootElement.Clone();
    }

    static JsonElement RunDoc(string dir)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "run.json")));
        return doc.RootElement.Clone();
    }

    static Dictionary<string, long> Counts(JsonElement el, string name) =>
        el.GetProperty(name).EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetInt64(), StringComparer.Ordinal);

    string PlanSha(string planFile) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(planFile))).ToLowerInvariant();

    // TotalObjects counts the plan's check on a right flat tree.
    static long TotalObjects(int dirs, int filesPer) => 1 + dirs * (1L + filesPer);

    // ---- usage errors (run control spec, decision 1) -------------------------------------------

    [Fact]
    public void ResumeAndStatusIntervalNeedStateDir()
    {
        var tree = FlatTree(2, 2);
        var plan = PlanFile(Usual);
        Assert.Equal(2, RunCli(tree, Deps(tree), "--resume", plan, "R").Code);
        Assert.Equal(2, RunCli(tree, Deps(tree), "--status-interval", "0.5", plan, "R").Code);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("garbage")]
    public void ABadStatusIntervalIsAUsageError(string value)
    {
        var tree = FlatTree(2, 2);
        Assert.Equal(2, RunCli(tree, Deps(tree), "--state-dir", FreshDir(), "--status-interval", value, PlanFile(Usual), "R").Code);
    }

    [Fact]
    public void ADecimalStatusIntervalIsAccepted()
    {
        var tree = FlatTree(2, 2);
        var dir = FreshDir();
        var (code, _, err) = RunCli(tree, Deps(tree), "--state-dir", dir, "--status-interval", "0.05", PlanFile(Usual), "R");
        Assert.True(code == 0, err);
        Assert.Equal("completed", RunDoc(dir).GetProperty("state").GetString());
        Assert.False(StatusDoc(dir).TryGetProperty("sacl_forms", out _), "no sacl_forms without a sacl: rule");
    }

    [Fact]
    public void ANonEmptyStateDirWithoutResumeIsRefused()
    {
        var dir = FreshDir();
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "junk"), "x");
        var tree = FlatTree(2, 2);
        Assert.Equal(2, RunCli(tree, Deps(tree), "--state-dir", dir, PlanFile(Usual), "R").Code);
    }

    [Fact]
    public void ResumeWithoutRunJsonIsRefused()
    {
        var dir = FreshDir();
        Directory.CreateDirectory(dir);
        var tree = FlatTree(2, 2);
        var (code, _, err) = RunCli(tree, Deps(tree), "--state-dir", dir, "--resume", PlanFile(Usual), "R");
        Assert.Equal(2, code);
        Assert.Contains("run.json", err);
    }

    [Fact]
    public void ApplyStillRefusesTheRunControlOptions()
    {
        var tree = FlatTree(2, 2);
        var plan = PlanFile(Usual);
        var o = new StringWriter();
        var e = new StringWriter();
        Assert.Equal(2, Cli.Run(["apply", "--state-dir", FreshDir(), plan, "R"], o, e, check: Deps(tree)));
        Assert.Equal(2, Cli.Run(["apply", "--status-interval", "1", plan, "R"], o, e, check: Deps(tree)));
    }

    // ---- a stop without a state dir (plan 5.1) --------------------------------------------------

    [Fact]
    public void AStopWithoutStateDirExitsThreeWithTheExactMessage()
    {
        var tree = FlatTree(10, 5);
        var cts = StopAfterReads(tree, 1);
        var (code, _, err) = RunCli(tree, Deps(tree, cts.Token), PlanFile(Usual), "R");
        Assert.Equal(3, code);
        Assert.Contains("check: stopped; nothing to resume (no --state-dir)", err);
        // A requested stop is not a failure: the directories it left are not "could not be read".
        Assert.DoesNotContain("could not be read", err);
    }

    // ---- stop and resume equals one run (plan 7.2) ----------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(34)]   // mid-walk
    [InlineData(100)]  // the last object of the 100-object tree: the stop lands on a finished walk
    public void StopResumeEqualsOneRun(int stopAfter)
    {
        const int dirs = 33, filesPer = 2;
        var plan = PlanFile(Usual);

        var baseTree = FlatTree(dirs, filesPer);
        var baseDir = FreshDir();
        // --workers 1: the stop-after-N-reads hook is deterministic only when one worker reads.
        var one = RunCli(baseTree, Deps(baseTree), "--workers", "1", "--state-dir", baseDir, plan, "R");
        Assert.Equal(0, one.Code);

        var tree = FlatTree(dirs, filesPer);
        var dir = FreshDir();
        var cts = StopAfterReads(tree, stopAfter);
        var seg1 = RunCli(tree, Deps(tree, cts.Token), "--workers", "1", "--state-dir", dir, "--status-interval", "0.05", plan, "R");
        if (seg1.Code == 0)
        {
            // The stop landed after the walk had already reached everything: a completed run,
            // nothing to resume (and --resume is refused on it).
            Assert.Equal("completed", RunDoc(dir).GetProperty("state").GetString());
            Assert.Equal(one.Out, seg1.Out);
            Assert.Equal(2, RunCli(tree, Deps(tree), "--state-dir", dir, "--resume", plan, "R").Code);
            return;
        }
        Assert.Equal(3, seg1.Code);
        Assert.Contains($"check: stopped; resume with --resume --state-dir {dir}", seg1.Err);
        Assert.Equal("stopped", RunDoc(dir).GetProperty("state").GetString());

        var resume = RunCli(tree, Deps(tree), "--workers", "1", "--state-dir", dir, "--resume", "--status-interval", "0.05", plan, "R");
        Assert.Equal(0, resume.Code);

        // Last record per path across both segments equals the single run's records (plan 7.2).
        Assert.Equal(LastRecords(one.Out), LastRecords(seg1.Out, resume.Out));

        // The final counts equal the single run's, as printed and as status.json reports them.
        Assert.Equal(SummaryLine(one.Err), SummaryLine(resume.Err));
        Assert.Equal(TotalObjects(dirs, filesPer), StatusDoc(dir).GetProperty("objects").GetInt64());
        Assert.Equal(Counts(StatusDoc(baseDir), "outcomes"), Counts(StatusDoc(dir), "outcomes"));
        Assert.Equal(Counts(StatusDoc(baseDir), "forms"), Counts(StatusDoc(dir), "forms"));

        // records.jsonl is exactly the concatenated stdout of both segments.
        var lines = File.ReadAllLines(Path.Combine(dir, "records.jsonl"));
        Assert.Equal(seg1.Out.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Concat(resume.Out.Split('\n', StringSplitOptions.RemoveEmptyEntries)), lines);
    }

    [Fact]
    public void TwoStopsEqualOneRun()
    {
        const int dirs = 12, filesPer = 2;
        var plan = PlanFile(Usual);
        var baseTree = FlatTree(dirs, filesPer);
        var one = RunCli(baseTree, Deps(baseTree), plan, "R");
        Assert.Equal(0, one.Code);

        var tree = FlatTree(dirs, filesPer);
        var dir = FreshDir();
        var cts1 = StopAfterReads(tree, 3);
        var seg1 = RunCli(tree, Deps(tree, cts1.Token), "--state-dir", dir, plan, "R");
        Assert.Equal(3, seg1.Code);
        var cts2 = StopAfterReads(tree, 15);   // stop 15 reads into the resumed segment
        var seg2 = RunCli(tree, Deps(tree, cts2.Token), "--state-dir", dir, "--resume", plan, "R");
        Assert.Equal(3, seg2.Code);
        var seg3 = RunCli(tree, Deps(tree), "--state-dir", dir, "--resume", plan, "R");
        Assert.Equal(0, seg3.Code);
        Assert.Equal(LastRecords(one.Out), LastRecords(seg1.Out, seg2.Out, seg3.Out));
        Assert.Equal(SummaryLine(one.Err), SummaryLine(seg3.Err));
        var run = RunDoc(dir);
        Assert.Equal(3, run.GetProperty("segments").GetArrayLength());
        Assert.Equal("completed", run.GetProperty("state").GetString());
    }

    [Fact]
    public void AStopWithTwoWorkersEqualsOneRunInCountsAndLastRecords()
    {
        const int dirs = 12, filesPer = 5;
        var plan = PlanFile(Usual);
        var baseTree = FlatTree(dirs, filesPer);
        var one = RunCli(baseTree, Deps(baseTree), plan, "R");
        Assert.Equal(0, one.Code);

        var tree = FlatTree(dirs, filesPer);
        var dir = FreshDir();
        var cts = StopAfterReads(tree, 17);
        var seg1 = RunCli(tree, Deps(tree, cts.Token), "--workers", "4", "--state-dir", dir, plan, "R");
        Assert.Equal(3, seg1.Code);
        var resume = RunCli(tree, Deps(tree), "--workers", "4", "--state-dir", dir, "--resume", plan, "R");
        Assert.Equal(0, resume.Code);
        Assert.Equal(LastRecords(one.Out), LastRecords(seg1.Out, resume.Out));
        Assert.Equal(SummaryLine(one.Err), SummaryLine(resume.Err));
    }

    // ---- resume refusals (plan 7.4, 4.1) ---------------------------------------------------------

    [Fact]
    public void ResumeRefusesAChangedPlanRootAndCommand()
    {
        var plan = PlanFile(Usual);
        var tree = FlatTree(4, 2);
        var cts = StopAfterReads(tree, 1);
        var dir = FreshDir();
        Assert.Equal(3, RunCli(tree, Deps(tree, cts.Token), "--state-dir", dir, plan, "R").Code);

        // A changed plan hash.
        var other = PlanFile(Usual with { Source = "other.yaml" });
        var (code1, _, err1) = RunCli(tree, Deps(tree), "--state-dir", dir, "--resume", other, "R");
        Assert.Equal(2, code1);
        Assert.Contains("plan_sha256", err1);

        // A changed root.
        var (code2, _, err2) = RunCli(tree, Deps(tree), "--state-dir", dir, "--resume", plan, "OTHER");
        Assert.Equal(2, code2);
        Assert.Contains("root", err2);

        // A changed command.
        var runPath = Path.Combine(dir, "run.json");
        var run = RunDoc(dir);
        var asApply = JsonSerializer.Deserialize<RunManifest>(run.GetRawText(), Cli.Json)! with { Command = "apply" };
        File.WriteAllText(runPath, JsonSerializer.Serialize(asApply, Cli.Json));
        var (code3, _, err3) = RunCli(tree, Deps(tree), "--state-dir", dir, "--resume", plan, "R");
        Assert.Equal(2, code3);
        Assert.Contains("command", err3);
    }

    [Fact]
    public void ResumeRefusesALiveProcessAndAcceptsADeadOne()
    {
        var plan = PlanFile(Usual);
        var tree = FlatTree(4, 2);
        var dir = FreshDir();
        Directory.CreateDirectory(Path.Combine(dir, "segments"));
        var runPath = Path.Combine(dir, "run.json");
        File.WriteAllText(runPath, JsonSerializer.Serialize(new RunManifest(1, "2026-11-27T10-00-00Z-ab12", "check",
            "0.1.0", ".NET 10.0.0", plan, PlanSha(plan), "R", 16, @"TESTDOMAIN\testuser", false, ["SeBackupPrivilege"],
            [new RunSegment(1, "2026-11-27T10:00:00Z", null, null, null, 4242, "2026-11-27T10:00:00.000Z")], "running"), Cli.Json));

        var (live, _, liveErr) = RunCli(tree, Deps(tree, alive: (_, _) => true), "--state-dir", dir, "--resume", plan, "R");
        Assert.Equal(2, live);
        Assert.Contains("pid 4242", liveErr);

        var (dead, _, _) = RunCli(tree, Deps(tree, alive: (_, _) => false), "--state-dir", dir, "--resume", plan, "R");
        Assert.Equal(0, dead);
        Assert.Equal(2, RunDoc(dir).GetProperty("segments").GetArrayLength());
    }

    [Fact]
    public void ResumeOfACompletedRunIsRefused()
    {
        var plan = PlanFile(Usual);
        var tree = FlatTree(4, 2);
        var dir = FreshDir();
        Assert.Equal(0, RunCli(tree, Deps(tree), "--state-dir", dir, plan, "R").Code);
        var (code, _, err) = RunCli(tree, Deps(tree), "--state-dir", dir, "--resume", plan, "R");
        Assert.Equal(2, code);
        Assert.Contains("already completed", err);
    }

    // ---- atomic files (plan 7.5) -----------------------------------------------------------------

    [Fact]
    public async Task ATightLoopReaderNeverSeesABrokenStatusJson()
    {
        const int dirs = 50, filesPer = 50;   // 2,501 objects
        var tree = FlatTree(dirs, filesPer);
        var dir = FreshDir();
        var plan = PlanFile(Usual);
        string? failure = null;
        var stop = false;
        var reader = Task.Run(() =>
        {
            var p = Path.Combine(dir, "status.json");
            while (!Volatile.Read(ref stop))
            {
                if (!File.Exists(p)) continue;
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(p));
                    _ = doc.RootElement.GetProperty("objects").GetInt64();
                }
                catch (Exception e) when (e is JsonException or IOException) { Volatile.Write(ref failure, $"{e.GetType().Name}: {e.Message}"); return; }
            }
        });
        var (code, _, _) = RunCli(tree, Deps(tree), "--state-dir", dir, "--status-interval", "0.005", plan, "R");
        Volatile.Write(ref stop, true);
        Assert.Same(reader, await Task.WhenAny(reader, Task.Delay(TimeSpan.FromSeconds(30))));
        Assert.Equal(0, code);
        Assert.Null(failure);
    }

    // ---- checkpoint compaction (plan 7.6) ---------------------------------------------------------

    [Fact]
    public void ACompletedRunsCheckpointLoadsToOneEntryTheRoot()
    {
        const int dirs = 8, filesPer = 3;
        var tree = FlatTree(dirs, filesPer);
        var dir = FreshDir();
        Assert.Equal(0, RunCli(tree, Deps(tree), "--state-dir", dir, "--status-interval", "0.005", PlanFile(Usual), "R").Code);

        // The load keeps the outermost entries (plan 4.4); after a completed run that is the root,
        // its line the run's whole counts. Interval flushes may have written covered lines first.
        static JsonElement Line(string l) { using var d = JsonDocument.Parse(l); return d.RootElement.Clone(); }
        var entries = File.ReadLines(Path.Combine(dir, "checkpoint.jsonl")).Select(Line).ToList();
        var root = entries[^1];
        Assert.Equal("", root.GetProperty("dir").GetString());
        Assert.Equal(TotalObjects(dirs, filesPer), root.GetProperty("objects").GetInt64());
        var outermost = entries.Where(e =>
        {
            var d = e.GetProperty("dir").GetString()!;
            for (var p = d.Contains('/') ? d[..d.LastIndexOf('/')] : (d.Length > 0 ? "" : null);
                 p is not null;
                 p = p.Contains('/') ? p[..p.LastIndexOf('/')] : (p.Length > 0 ? "" : null))
                if (entries.Any(x => x.GetProperty("dir").GetString() == p)) return false;
            return true;
        }).ToList();
        var only = Assert.Single(outermost);
        Assert.Equal("", only.GetProperty("dir").GetString());
    }

    // ---- errors keep directories incomplete (plan 7.7) -------------------------------------------

    [Fact]
    public void AFailedListingStaysIncompleteAndResumeVisitsItAgain()
    {
        var objs = new Dictionary<string, Obj>
        {
            [""] = new(true, DirWant, true),
            ["a"] = new(true, DirInherited, false),
            ["a/f.txt"] = new(false, FileInherited, false),
            ["locked"] = new(true, DirInherited, false),
            ["locked/g.txt"] = new(false, FileInherited, false),
        };
        var tree = new FakeTree(objs);
        tree.ListFails.Add("locked");
        var plan = PlanFile(Usual);
        var dir = FreshDir();
        var (code, _, err) = RunCli(tree, Deps(tree), "--state-dir", dir, plan, "R");
        Assert.Equal(1, code);
        Assert.Contains("could not be read, listed or classified", err);
        var dirs = File.ReadLines(Path.Combine(dir, "checkpoint.jsonl"))
            .Select(l => { using var d = JsonDocument.Parse(l); return d.RootElement.GetProperty("dir").GetString()!; }).ToList();
        Assert.DoesNotContain("locked", dirs);
        Assert.DoesNotContain("", dirs);   // the root never completed either

        tree.ListFails.Clear();
        var oneTree = new FakeTree(objs.Select(kv => KeyValuePair.Create(kv.Key, kv.Value)).ToDictionary(kv => kv.Key, kv => kv.Value));
        var one = RunCli(oneTree, Deps(oneTree), plan, "R");
        var (code2, out2, err2) = RunCli(tree, Deps(tree), "--state-dir", dir, "--resume", plan, "R");
        Assert.Equal(0, code2);
        Assert.Contains("locked/g.txt", out2);
        // records.jsonl holds both segments; the last record per path equals the one-shot run.
        Assert.Equal(LastRecords(one.Out), LastRecords(File.ReadAllText(Path.Combine(dir, "records.jsonl"))));
        Assert.Equal(SummaryLine(one.Err), SummaryLine(err2));
    }

    // ---- the real STOP file (plan 5.1, 7.2's stop) -------------------------------------------------

    [Fact]
    public void StopFileStopsAndIsDeleted()
    {
        const int dirs = 40, filesPer = 20;   // 821 objects, ~1 ms per read: seconds of headroom
        var tree = FlatTree(dirs, filesPer);
        var dir = FreshDir();
        var plan = PlanFile(Usual);
        long reads = 0;
        tree.BeforeRead = rel =>
        {
            if (Interlocked.Increment(ref reads) == 10 && !File.Exists(Path.Combine(dir, "STOP")))
                File.WriteAllText(Path.Combine(dir, "STOP"), "stop\n");
            Thread.Sleep(1);
        };
        var (code, _, err) = RunCli(tree, Deps(tree), "--workers", "1", "--state-dir", dir, "--status-interval", "0.05", plan, "R");
        Assert.Equal(3, code);
        Assert.Contains($"check: stopped; resume with --resume --state-dir {dir}", err);
        Assert.False(File.Exists(Path.Combine(dir, "STOP")), "the CLI deletes STOP at a clean stop");
        Assert.Equal("stopped", RunDoc(dir).GetProperty("state").GetString());

        var baseTree = FlatTree(dirs, filesPer);
        var one = RunCli(baseTree, Deps(baseTree), plan, "R");
        var tree2 = FlatTree(dirs, filesPer);
        var seg2 = RunCli(tree2, Deps(tree2), "--workers", "1", "--state-dir", dir, "--resume", "--status-interval", "0.05", plan, "R");
        Assert.Equal(0, seg2.Code);
        Assert.Equal(LastRecords(one.Out), LastRecords(File.ReadAllText(Path.Combine(dir, "records.jsonl"))));
        Assert.Equal(SummaryLine(one.Err), SummaryLine(seg2.Err));
    }

    // ---- previous_total (plan 4.2) -----------------------------------------------------------------

    [Fact]
    public void PreviousTotalNamesTheMatchingCompletedSibling()
    {
        const int dirs = 4, filesPer = 2;
        var plan = PlanFile(Usual);
        var parent = FreshDir();
        Directory.CreateDirectory(parent);
        var a = Path.Combine(parent, "A");
        var b = Path.Combine(parent, "B");
        _dirs.Add(b);

        var treeA = FlatTree(dirs, filesPer);
        Assert.Equal(0, RunCli(treeA, Deps(treeA), "--state-dir", a, plan, "R").Code);
        _dirs.Add(a);
        var statusA = StatusDoc(a);
        Assert.Equal(TotalObjects(dirs, filesPer), statusA.GetProperty("objects").GetInt64());
        Assert.False(statusA.TryGetProperty("previous_total", out _), "a first run has no previous run");

        var treeB = FlatTree(dirs, filesPer);
        Assert.Equal(0, RunCli(treeB, Deps(treeB), "--state-dir", b, plan, "R").Code);
        Assert.Equal(TotalObjects(dirs, filesPer), StatusDoc(b).GetProperty("previous_total").GetInt64());
    }

    [Fact]
    public void NoPreviousTotalWithoutAMatchingSibling()
    {
        var plan = PlanFile(Usual);
        var tree = FlatTree(3, 2);
        var dir = FreshDir();
        Assert.Equal(0, RunCli(tree, Deps(tree), "--state-dir", dir, plan, "R").Code);
        Assert.False(StatusDoc(dir).TryGetProperty("previous_total", out _));
    }

    // ---- run.json content (plan 4.1) -----------------------------------------------------------------

    [Fact]
    public void RunJsonRecordsIdentityPlanRootAndSegments()
    {
        var plan = PlanFile(Usual);
        var tree = FlatTree(4, 2);
        var dir = FreshDir();
        var cts = StopAfterReads(tree, 2);
        Assert.Equal(3, RunCli(tree, Deps(tree, cts.Token), "--state-dir", dir, plan, "R").Code);
        var run = RunDoc(dir);
        Assert.Equal(1, run.GetProperty("schema").GetInt32());
        Assert.Equal("check", run.GetProperty("command").GetString());
        Assert.Equal("R", run.GetProperty("root").GetString());
        Assert.Equal(PlanSha(plan), run.GetProperty("plan_sha256").GetString());
        Assert.Equal(@"TESTDOMAIN\testuser", run.GetProperty("identity").GetString());
        Assert.False(run.GetProperty("elevated").GetBoolean());
        Assert.Contains("SeBackupPrivilege", run.GetProperty("privileges").EnumerateArray().Select(p => p.GetString()));
        Assert.Equal(RuntimeInformation.FrameworkDescription, run.GetProperty("runtime").GetString());
        var seg = run.GetProperty("segments")[0];
        Assert.Equal("stopped", seg.GetProperty("end").GetString());
        Assert.Equal(3, seg.GetProperty("exit").GetInt32());
        Assert.True(seg.GetProperty("pid").GetInt32() > 0);
        Assert.NotEqual(JsonValueKind.Null, seg.GetProperty("process_start").ValueKind);
        Assert.NotEqual(JsonValueKind.Null, seg.GetProperty("ended").ValueKind);

        Assert.Equal(0, RunCli(tree, Deps(tree), "--state-dir", dir, "--resume", plan, "R").Code);
        var after = RunDoc(dir);
        Assert.Equal("completed", after.GetProperty("state").GetString());
        Assert.Equal(2, after.GetProperty("segments").GetArrayLength());
        Assert.Equal(0, after.GetProperty("segments")[1].GetProperty("exit").GetInt32());
        // The segment log tee'd this segment's stderr (plan 4, segments/).
        var log = File.ReadAllText(Path.Combine(dir, "segments", "002.log"));
        Assert.Contains("check: dry run", log);
    }

    // ---- saclMode: checkpoint and status carry sacl_forms (plan 4.4, decision 2) ----------------------

    [Fact]
    public void SaclModeStateDirCarriesSaclForms()
    {
        var plan = Usual with { Schema = Plan.SmbSaclSchema, Default = Usual.Default with { SaclSet = true } };
        var tree = new FakeTree(new()
        {
            [""] = new Obj(true, [A(AceFlags.ObjectInherit | AceFlags.ContainerInherit, "S-1-5-21-9-9-9-9")], true),
            ["f.txt"] = new Obj(false, [A(AceFlags.Inherited, "S-1-5-21-9-9-9-9")], false),
        });
        var dir = FreshDir();
        var (code, _, err) = RunCli(tree, Deps(tree), "--state-dir", dir, PlanFile(plan), @"\\array\share\dept");
        Assert.True(code == 0, err);
        Assert.True(StatusDoc(dir).TryGetProperty("sacl_forms", out _));
        static JsonElement Line(string l) { using var d = JsonDocument.Parse(l); return d.RootElement.Clone(); }
        var root = File.ReadLines(Path.Combine(dir, "checkpoint.jsonl")).Select(Line).Last();
        Assert.Equal("", root.GetProperty("dir").GetString());
        Assert.True(root.TryGetProperty("sacl_forms", out _));
    }

    // ---- exit 3 wins over other failures (plan 5.3) ---------------------------------------------------

    [Fact]
    public void AStopWinsOverAnObjectError()
    {
        var tree = FlatTree(6, 2);
        tree.ReadFails.Add("d0/f0");
        var cts = StopAfterReads(tree, 3);
        var (code, _, err) = RunCli(tree, Deps(tree, cts.Token), "--state-dir", FreshDir(), PlanFile(Usual), "R");
        Assert.Equal(3, code);
        Assert.Contains("stopped", err);
    }
}
