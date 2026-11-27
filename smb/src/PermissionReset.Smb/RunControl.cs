using System.Text.Json;
using PermissionReset.Smb.Core;

namespace PermissionReset.Smb;

// Run-control state refused at open time (a resume mismatch, a live second process, a completed
// run): the CLI reports it as a usage error, exit 2 (docs/plan-smb-run-control.md 5.3).
sealed class RunControlException(string message) : Exception(message);

// One segment of a run (plan 4.1): one process. pid and process_start are what a resume tells a
// live second process from a dead one; end, ended and exit are set when the segment closes.
sealed record RunSegment(int N, string Started, string? Ended, string? End, int? Exit, int Pid, string ProcessStart);

// RunManifest is run.json (plan 4.1), rewritten at the start and end of each segment.
sealed record RunManifest(int Schema, string RunId, string Command, string ToolVersion, string Runtime,
    string PlanPath, string PlanSha256, string Root, int Workers, string Identity, bool Elevated,
    IReadOnlyList<string> Privileges, List<RunSegment> Segments, string State);

// RunControlState owns the files of a check run's --state-dir (docs/plan-smb-run-control.md,
// section 4): run.json, records.jsonl, checkpoint.jsonl, status.json, the segments log and the
// STOP file. Every file that is rewritten (run.json, status.json) goes through a temp name in the
// same directory and a rename (plan 2), so a reader never sees half a file. records.jsonl is
// flushed before any checkpoint.jsonl line that covers those records, both at least once per
// status interval and at a clean end (crash-safety ordering, resume step: a killed process never
// leaves a checkpoint entry whose records were lost).
sealed class RunControlState : IDisposable
{
    // Outcome and form keys are the ones of the stderr summary and status.json (plan 4.2, 4.4).
    static readonly (string Key, Outcome O)[] OutcomeKeys =
    [
        ("ok", Outcome.Ok), ("write", Outcome.Write), ("follows", Outcome.Follows), ("keep", Outcome.Keep),
        ("excluded", Outcome.Excluded), ("reparse", Outcome.Reparse), ("error", Outcome.Error),
    ];
    static readonly (string Key, Form F)[] FormKeys =
        [("inherits", Form.Inherits), ("explicit_plus_inherits", Form.ExplicitPlusInherits), ("protected", Form.Protected)];

    readonly string dir;
    readonly bool saclMode;
    readonly Func<int, DateTime, bool> alive;
    readonly object gate = new();
    readonly List<(string Dir, SubtreeCounts Counts)> pendingCompleted = [];
    bool finished;
    readonly System.Diagnostics.Stopwatch segmentClock = System.Diagnostics.Stopwatch.StartNew();
    readonly long seededObjects;
    RunManifest manifest;
    readonly StreamWriter records, checkpoint;
    readonly TextWriter segmentLog;
    bool stoppingMarked;

    public string StopPath { get; }
    public int Segment { get; }
    readonly long? previousTotal;

    RunControlState(string dir, RunManifest manifest, int segment, long? previousTotal, bool saclMode,
        Func<int, DateTime, bool> alive, Dictionary<string, SubtreeCounts> completed,
        StreamWriter records, StreamWriter checkpoint, TextWriter segmentLog)
    {
        this.dir = dir;
        this.manifest = manifest;
        Segment = segment;
        this.previousTotal = previousTotal;
        this.saclMode = saclMode;
        this.alive = alive;
        Completed = completed;
        Seeded = new SubtreeCounts();
        foreach (var c in completed.Values) Seeded.Add(c);
        seededObjects = Seeded.Objects;
        this.records = records;
        this.checkpoint = checkpoint;
        this.segmentLog = segmentLog;
        StopPath = Path.Combine(dir, "STOP");
    }

    // Completed is the loaded set of complete subtrees (outermost checkpoint.jsonl entries), each
    // with its subtree counts (plan 4.4, 5.2): a resume prunes them against it, and their counts
    // seed the summary so the run's totals span every segment.
    public Dictionary<string, SubtreeCounts> Completed { get; }
    public SubtreeCounts Seeded { get; }

    static string Now() => DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    static string NowMs() => DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);

    // Open creates or resumes the run's state directory. Every refusal is a RunControlException.
    // identity and elevated come from CheckDeps so tests anywhere get stable values; privileges is
    // the set the check enabled. On a resume, segments that died mid-run (state running or
    // stopping) are accepted when their process is gone; a live one (same pid and process start)
    // is refused, since two processes must never share a state dir (plan 5.2, step 1).
    public static RunControlState Open(string dir, bool resume, Plan plan, string planPath, string planSha256,
        string root, int workers, IReadOnlyList<string> privileges, bool saclMode, CheckDeps deps)
    {
        var alive = deps.ProcessAlive;
        var segDir = Path.Combine(dir, "segments");
        var runPath = Path.Combine(dir, "run.json");
        RunManifest manifest;
        int segment;
        var completed = new Dictionary<string, SubtreeCounts>(StringComparer.Ordinal);
        long? previousTotal = null;
        if (!resume)
        {
            if (Directory.Exists(dir) && Directory.EnumerateFileSystemEntries(dir).Any())
                throw new RunControlException($"--state-dir {dir} is not empty; pass --resume to continue the run there, or use an empty directory");
            Directory.CreateDirectory(segDir);
            segment = 1;
            manifest = new RunManifest(1, NewRunId(), "check", ToolVersion(),
                System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                planPath, planSha256, root, workers, deps.UserIdentity(), deps.IsElevated(), privileges, [], "running");
        }
        else
        {
            RunManifest? old;
            try { old = File.Exists(runPath) ? JsonSerializer.Deserialize<RunManifest>(File.ReadAllText(runPath), Cli.Json) : null; }
            catch (JsonException e) { throw new RunControlException($"--resume: run.json in {dir} is malformed: {e.Message}"); }
            if (old is null)
                throw new RunControlException($"--resume: {dir} has no run.json; without one there is nothing to resume");
            if (old.Segments is null || old.Segments.Count == 0)
                throw new RunControlException($"--resume: run.json in {dir} is malformed: it has no run segment");
            if (old.Command is not "check")
                throw new RunControlException($"--resume: the run in {dir} is a \"{old.Command}\" run, not \"check\" (run.json command)");
            if (old.PlanSha256 != planSha256)
                throw new RunControlException($"--resume: the plan in {dir} does not match PLAN.json (run.json plan_sha256 {old.PlanSha256}, the plan's {planSha256})");
            if (old.Root != root)
                throw new RunControlException($"--resume: the run in {dir} is rooted at {old.Root}, not {root} (run.json root)");
            if (old.State is "completed")
                throw new RunControlException($"--resume: the run in {dir} already completed; there is nothing to resume");
            var last = old.Segments[^1];
            if (old.State is "running" or "stopping" && last.End is null && last.ProcessStart is not null
                && TryParseTime(last.ProcessStart, out var start) && alive(last.Pid, start))
                throw new RunControlException($"--resume: the run in {dir} is still running: its last segment's process (pid {last.Pid}, started {last.ProcessStart}) is alive; two processes must not share a state dir");
            LoadCheckpoint(Path.Combine(dir, "checkpoint.jsonl"), completed);
            segment = old.Segments.Count + 1;
            manifest = old;
        }

        previousTotal = PreviousCompletedTotal(dir, manifest.Root, manifest.PlanSha256);

        manifest.Segments.Add(new RunSegment(segment, Now(), null, null, null,
            Environment.ProcessId, NowMs()));
        manifest = manifest with { State = "running" };
        AtomicWrite(runPath, JsonSerializer.Serialize(manifest, Cli.Json));

        // records.jsonl and checkpoint.jsonl are appended across segments; the segment's log is
        // new (segments/NNN.log, one per segment, plan 4).
        var recordsW = new StreamWriter(new FileStream(Path.Combine(dir, "records.jsonl"),
            FileMode.Append, FileAccess.Write, FileShare.Read));
        var checkpointW = new StreamWriter(new FileStream(Path.Combine(dir, "checkpoint.jsonl"),
            FileMode.Append, FileAccess.Write, FileShare.Read));
        var logW = new StreamWriter(new FileStream(Path.Combine(segDir, $"{segment:D3}.log"),
            FileMode.Create, FileAccess.Write, FileShare.Read));
        return new RunControlState(dir, manifest, segment, previousTotal, saclMode, alive, completed, recordsW, checkpointW, logW);
    }

    static string NewRunId() =>
        $"{DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH-mm-ss'Z'", System.Globalization.CultureInfo.InvariantCulture)}-{Random.Shared.Next(0x10000):x4}";

    static string ToolVersion() => typeof(Cli).Assembly.GetName().Version?.ToString(3) ?? "unknown";

    static bool TryParseTime(string s, out DateTime t) =>
        DateTime.TryParse(s, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out t);

    // LoadCheckpoint reads checkpoint.jsonl: one line per completed subtree, its dir and subtree
    // counts (plan 4.4). A torn or malformed last line (the run died mid-flush) is dropped, that
    // subtree is redone; a repeated dir keeps its last line. Only the outermost entries survive: a
    // line whose directory is under another line's subtree is already covered.
    static void LoadCheckpoint(string path, Dictionary<string, SubtreeCounts> completed)
    {
        if (!File.Exists(path)) return;
        var entries = new Dictionary<string, SubtreeCounts>(StringComparer.Ordinal);
        foreach (var line in File.ReadLines(path))
        {
            if (line.Length == 0 || line[0] != '{') continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                if (ParseCheckpointLine(doc.RootElement) is not { } l) continue;
                entries[l.Dir] = l.Counts;
            }
            catch (JsonException) { }
        }
        foreach (var d in entries.Keys)
        {
            // A dir is outermost when no other entry is its ancestor.
            bool covered = false;
            for (var p = Parent(d); p is not null; p = Parent(p))
                if (entries.ContainsKey(p)) { covered = true; break; }
            if (!covered) completed[d] = entries[d];
        }
    }

    static string? Parent(string rel) => rel.Contains('/') ? rel[..rel.LastIndexOf('/')] : rel.Length > 0 ? "" : null;

    // ParseCheckpointLine reads one {"dir": …, "objects": N, "outcomes": {…}, "forms": {…},
    // "sacl_forms": {…}} line; null on any malformed field (the line is dropped, as a torn one).
    static (string Dir, SubtreeCounts Counts)? ParseCheckpointLine(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object
            || !el.TryGetProperty("dir", out var d) || d.ValueKind != JsonValueKind.String || d.GetString() is not string dir)
            return null;
        var counts = new SubtreeCounts();
        if (!el.TryGetProperty("objects", out var objs) || objs.ValueKind != JsonValueKind.Number || !objs.TryGetInt64(out long nObjects))
            return null;
        counts.AddObjects(nObjects);
        if (!AddCounts(el, "outcomes", (k, v) =>
            {
                foreach (var (key, o) in OutcomeKeys) if (k == key) { counts.AddOutcome(o, v); return; }
            })
            || !AddCounts(el, "forms", (k, v) =>
            {
                foreach (var (key, f) in FormKeys) if (k == key) { counts.AddForm(f, v); return; }
            })
            || (el.TryGetProperty("sacl_forms", out _) && !AddCounts(el, "sacl_forms", (k, v) =>
            {
                foreach (var (key, f) in FormKeys) if (k == key) { counts.AddSaclForm(f, v); return; }
            })))
            return null;
        return (dir, counts);
    }

    static bool AddCounts(JsonElement el, string name, Action<string, long> add)
    {
        if (!el.TryGetProperty(name, out var o) || o.ValueKind != JsonValueKind.Object) return false;
        foreach (var p in o.EnumerateObject())
        {
            if (p.Value.ValueKind != JsonValueKind.Number || !p.Value.TryGetInt64(out long v) || v < 0) return false;
            add(p.Name, v);
        }
        return true;
    }

    // PreviousCompletedTotal is plan 4.2's previous_total: the objects of the most recent
    // completed sibling state dir (same parent directory) with the same root and plan hash. The
    // CLI never estimates a total itself; absent siblings or ones that don't parse mean absent.
    static long? PreviousCompletedTotal(string dir, string root, string planSha256)
    {
        var parent = Path.GetDirectoryName(Path.GetFullPath(dir));
        if (parent is null) return null;
        long? best = null;
        string bestEnded = "";
        IEnumerable<string> siblings;
        try { siblings = Directory.EnumerateDirectories(parent); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
        foreach (var sib in siblings)
        {
            if (string.Equals(Path.GetFullPath(sib), Path.GetFullPath(dir), StringComparison.OrdinalIgnoreCase)) continue;
            var runPath = Path.Combine(sib, "run.json");
            RunManifest? old;
            try { old = File.Exists(runPath) ? JsonSerializer.Deserialize<RunManifest>(File.ReadAllText(runPath), Cli.Json) : null; }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException) { continue; }
            if (old?.State is not "completed" || old.Root != root || old.PlanSha256 != planSha256 || old.Segments is not { Count: > 0 }) continue;
            var ended = old.Segments[^1].Ended ?? "";
            if (best is not null && string.CompareOrdinal(ended, bestEnded) <= 0) continue;
            // A completed run's final status.json is its counts.
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(sib, "status.json")));
                if (doc.RootElement.TryGetProperty("objects", out var o) && o.ValueKind == JsonValueKind.Number && o.TryGetInt64(out long v))
                {
                    best = v;
                    bestEnded = ended;
                }
            }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException) { continue; }
        }
        return best;
    }

    // Tee returns the stderr writer for the run segment: everything the check prints to stderr
    // also goes to segments/NNN.log (plan 4, decision 10).
    public TextWriter Tee(TextWriter stderr) => new TeeWriter(stderr, segmentLog);

    // Hooks builds the walk's run-control surface (plan 6): the resume pruning set and the
    // completion report. A completed subtree is held back until the next flush; when a parent
    // completes while its children are still held, its line covers them, so checkpoint.jsonl never
    // holds a line a later line makes redundant (plan 4.4).
    public RunHooks Hooks() => new()
    {
        IsComplete = rel => rel.Length > 0 && Completed.ContainsKey(rel),
        PrunedCounts = rel => Completed.GetValueOrDefault(rel),
        Seed = s =>
        {
            foreach (var (k, v) in Seeded.Outcomes) s.SeedOutcome(k, v);
            foreach (var (k, v) in Seeded.Forms) s.SeedForm(k, v);
            foreach (var (k, v) in Seeded.SaclForms) s.SeedSaclForm(k, v);
        },
        SubtreeComplete = (rel, counts) =>
        {
            lock (gate)
            {
                pendingCompleted.RemoveAll(c => c.Dir == rel || c.Dir.StartsWith(rel.Length == 0 ? "" : rel + "/", StringComparison.Ordinal));
                pendingCompleted.Add((rel, counts));
            }
        },
    };

    // Record appends one stdout line to records.jsonl (plan 4.3: the same line, so the two never
    // differ). Buffered; the interval flush or the run's end makes it durable before any covering
    // checkpoint line.
    public void Record(string line)
    {
        lock (gate) records.WriteLine(line);
    }

    // Flush makes records durable first, then writes the held checkpoint lines (after the records
    // they cover) and makes those durable: the records-before-checkpoint order (crash safety).
    public void Flush()
    {
        lock (gate)
        {
            records.Flush();
            foreach (var (d, counts) in pendingCompleted) checkpoint.WriteLine(CheckpointLine(d, counts));
            pendingCompleted.Clear();
            checkpoint.Flush();
            segmentLog.Flush();
        }
    }

    string CheckpointLine(string dir, SubtreeCounts counts) => JsonSerializer.Serialize(new
    {
        dir,
        objects = counts.Objects,
        outcomes = OutcomeDict(counts),
        forms = FormDict(false, counts),
        sacl_forms = saclMode ? FormDict(true, counts) : null,
    }, Cli.Json);

    static Dictionary<string, long> OutcomeDict(SubtreeCounts c) =>
        OutcomeKeys.ToDictionary(kv => kv.Key, kv => c.Outcomes.GetValueOrDefault(kv.O));

    static Dictionary<string, long> FormDict(bool sacl, SubtreeCounts c) =>
        FormKeys.ToDictionary(kv => kv.Key, kv => (sacl ? c.SaclForms : c.Forms).GetValueOrDefault(kv.F));

    // MarkStopping flips run.json's state to stopping (plan 5.1, step 1) the first time a stop
    // request is seen; true when it did.
    public bool MarkStopping()
    {
        lock (gate)
        {
            if (stoppingMarked) return false;
            stoppingMarked = true;
            manifest = manifest with { State = "stopping" };
            AtomicWrite(Path.Combine(dir, "run.json"), JsonSerializer.Serialize(manifest, Cli.Json));
            return true;
        }
    }

    // WriteStatus rewrites status.json atomically (plan 2, 4.2): counts span every segment (the
    // loaded subtree counts were seeded into the summary), current lists up to 8 directories the
    // workers are in, and previous_total is present only with a matching completed sibling.
    public void WriteStatus(string state, CheckSummary s, RunHooks hooks)
    {
        lock (gate)
        {
            var elapsed = segmentClock.Elapsed.TotalSeconds;
            var objects = s.Objects();
            var current = hooks.ActiveDirs.Keys.Order(StringComparer.Ordinal).Take(8).ToArray();
            var status = new
            {
                run_id = manifest.RunId,
                segment = Segment,
                state,
                updated = Now(),
                objects,
                outcomes = OutcomeKeys.ToDictionary(kv => kv.Key, kv => s.Count(kv.O)),
                forms = FormKeys.ToDictionary(kv => kv.Key, kv => s.Count(kv.F)),
                sacl_forms = saclMode ? FormKeys.ToDictionary(kv => kv.Key, kv => s.CountSacl(kv.F)) : null,
                not_processed = s.NotProcessed,
                dirs_queued = Interlocked.Read(ref hooks.DirsQueued),
                dirs_done = Interlocked.Read(ref hooks.DirsDone),
                rate_per_sec = elapsed > 0 ? (long)Math.Round((objects - seededObjects) / elapsed) : 0L,
                current,
                previous_total = previousTotal,
            };
            AtomicWrite(Path.Combine(dir, "status.json"), JsonSerializer.Serialize(status, Cli.Json));
        }
    }

    // Tick is one status interval (plan 4.2, 4.4, 5.1): poll STOP, then flush and rewrite
    // status.json. stopRequested cancels the segment; the run's end does the final flush itself.
    public void Tick(CheckSummary? s, RunHooks hooks, bool stopRequested)
    {
        // The whole tick holds the gate and is a no-op once Finish has run: a timer callback
        // already in flight must not rewrite the final status.json or run.json as running.
        lock (gate)
        {
            if (finished) return;
            if (stopRequested) MarkStopping();
            Flush();
            if (s is not null) WriteStatus(stoppingMarked ? "stopping" : "running", s, hooks);
        }
    }

    // Finish closes the segment (plan 4.1, 5.1): the final flush and status.json, run.json with
    // end and exit, and a clean stop deletes STOP. end is "completed", "failed" or "stopped".
    public void Finish(string end, int exitCode, CheckSummary s, RunHooks hooks)
    {
        lock (gate)
        {
            finished = true;
            Flush();
            WriteStatus(end, s, hooks);
            manifest = manifest with
            {
                State = end,
                Segments = [.. manifest.Segments.Take(manifest.Segments.Count - 1),
                    manifest.Segments[^1] with { Ended = Now(), End = end, Exit = exitCode }],
            };
            AtomicWrite(Path.Combine(dir, "run.json"), JsonSerializer.Serialize(manifest, Cli.Json));
            if (end == "stopped" && File.Exists(StopPath))
            {
                try { File.Delete(StopPath); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            }
            segmentLog.Flush();
        }
    }

    // AtomicWrite is plan 2's temp-then-rename in the same directory: a reader of run.json or
    // status.json never sees half a file.
    // On Windows the rename is refused while a reader holds the old file open without
    // FILE_SHARE_DELETE, or catches it mid-delete, so the rename is retried briefly; a reader that
    // opens with FileShare.Delete (README) never blocks it.
    static void AtomicWrite(string path, string content)
    {
        var tmp = $"{path}.{Environment.ProcessId}.tmp";
        File.WriteAllText(tmp, content);
        for (int attempt = 1; ; attempt++)
        {
            try { File.Move(tmp, path, overwrite: true); return; }
            catch (Exception e) when (attempt < 50 && e is IOException or UnauthorizedAccessException) { Thread.Sleep(10); }
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            records.Dispose();
            checkpoint.Dispose();
            segmentLog.Dispose();
        }
    }
}

// TeeWriter is one writer in front of two: the operator's stderr and the segment log.
sealed class TeeWriter(TextWriter inner, TextWriter log) : TextWriter
{
    public override System.Text.Encoding Encoding => inner.Encoding;
    public override void WriteLine(string? value)
    {
        inner.WriteLine(value);
        log.WriteLine(value);
    }
    public override void Write(char value)
    {
        inner.Write(value);
        log.Write(value);
    }
    public override void Flush()
    {
        inner.Flush();
        log.Flush();
    }
}
