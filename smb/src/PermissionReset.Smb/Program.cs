using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Serialization;
using PermissionReset.Smb;
using PermissionReset.Smb.Core;

return Cli.Run(args, Console.Out, Console.Error);

static class Cli
{
    const string Usage = """
        usage: permissionreset-smb <command> [options]

        commands:
          inspect [--no-sacl] PATH...   print each object's raw security descriptor as JSON, one line
                                        per path: owner, group, control flags, DACL and SACL as
                                        stored, and the raw bytes. Read-only.
          check [--validate] [--workers N] [--root-protected] PLAN.json ROOT
                                        walk ROOT and say, per object, whether its DACL is what the
                                        schema 2 plan wants (ok), needs its own write (write), or
                                        will be right once an ancestor is written (follows). JSON
                                        lines on stdout, a summary on stderr. Writes nothing.
                                        --validate exits 1 on any object that isn't ok.
          apply [--workers N] [--root-protected] [--probe-dir DIR] [--checkpoint FILE [--resume]]
                [--evidence-dir DIR] PLAN.json ROOT
                                        the same walk, writing each object whose DACL (or named
                                        owner/group) differs, top-down, and reading every write
                                        back. A disposable probe proves the write path first.
                                        Stops on the first guard failure (G1, G2).
          plan PLAN.json                validate a `build-spec --smb-plan` (or --sacl-plan) file and summarize it.
          version                       print the version.

        inspect needs an elevated shell with SeBackupPrivilege, and SeSecurityPrivilege unless
        --no-sacl. On FlashArray the identity also needs the array's audit bypass. check needs
        SeBackupPrivilege. apply needs SeBackupPrivilege and SeSecurityPrivilege (and the audit
        bypass on FlashArray), and SeRestorePrivilege only when the plan sets an owner or group.
        """;

    internal static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    // reader is the descriptor source for inspect; null means the Win32 reader (Windows only).
    // Tests pass a fake so the CLI's output and exit codes are checked on any OS.
    public static int Run(string[] args, TextWriter stdout, TextWriter stderr, IDescriptorReader? reader = null, CheckDeps? check = null)
    {
        if (args.Length == 0) { stderr.WriteLine(Usage); return 2; }
        try
        {
            return args[0] switch
            {
                "inspect" => Inspect(args[1..], stdout, stderr, reader),
                "plan" => PlanCmd(args[1..], stdout, stderr),
                "check" => Check(args[1..], stdout, stderr, check),
                "apply" => Apply(args[1..], stdout, stderr, check),
                "version" => Version(stdout),
                "-h" or "--help" or "help" => Help(stdout),
                _ => Fail(stderr, $"unknown command \"{args[0]}\""),
            };
        }
        catch (PlanException e) { return Fail(stderr, e.Message, 1); }
    }

    static int Help(TextWriter o) { o.WriteLine(Usage); return 0; }

    static int Fail(TextWriter e, string msg, int code = 2)
    {
        e.WriteLine($"permissionreset-smb: {msg}");
        if (code == 2) e.WriteLine("run 'permissionreset-smb --help' for usage");
        return code;
    }

    static int Version(TextWriter o)
    {
        var v = typeof(Cli).Assembly.GetName().Version;
        o.WriteLine($"permissionreset-smb {v?.ToString(3) ?? "unknown"}");
        return 0;
    }

    // Inspect exits 0 when every path was read, 1 when the privileges could not be enabled (nothing
    // is read) or when any path failed (each failure still gets its own record), 2 on usage.
    static int Inspect(string[] args, TextWriter stdout, TextWriter stderr, IDescriptorReader? reader)
    {
        bool withSacl = true;
        var paths = new List<string>();
        foreach (var a in args)
        {
            if (a == "--no-sacl") withSacl = false;
            else if (a.StartsWith('-')) return Fail(stderr, $"inspect: unknown option {a}");
            else paths.Add(a);
        }
        if (paths.Count == 0) return Fail(stderr, "inspect: needs at least one PATH");
        if (reader is null)
        {
            if (!OperatingSystem.IsWindows()) return Fail(stderr, "inspect reads descriptors over SMB and runs only on Windows", 1);
            reader = new Win32DescriptorReader();
        }

        // A missing privilege is a fact about the shell, not about any path: say so once, read
        // nothing, and exit 1 rather than let the exception escape.
        try
        {
            reader.EnablePrivilege("SeBackupPrivilege");
            if (withSacl) reader.EnablePrivilege("SeSecurityPrivilege");
        }
        catch (Win32Exception e)
        {
            return Fail(stderr, $"inspect: {e.Message} (Win32 error {e.NativeErrorCode})", 1);
        }

        int failed = 0;
        foreach (var p in paths)
        {
            InspectLine line;
            try { line = new InspectLine(p, Descriptor.Decode(reader.Read(p, withSacl)), withSacl, null, null); }
            catch (Exception e) when (e is Win32Exception or DescriptorFormatException)
            {
                failed++;
                // No descriptor came back, so nothing was read: sacl_read is left out.
                line = new InspectLine(p, null, null, e.Message, (e as Win32Exception)?.NativeErrorCode);
            }
            stdout.WriteLine(JsonSerializer.Serialize(line, Json));
        }
        return failed == 0 ? 0 : 1;
    }

    // Check exits 0 when every object was checked (and, with --validate, every one is ok), 1 when
    // any object or directory failed, a privilege is missing, or --validate found a difference,
    // and 2 on a usage error.
    static int Check(string[] args, TextWriter stdout, TextWriter stderr, CheckDeps? deps)
    {
        bool validate = false, rootProtected = false;
        int workers = 16;
        var pos = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a == "--validate") validate = true;
            else if (a == "--root-protected") rootProtected = true;
            else if (a == "--workers")
            {
                if (i + 1 >= args.Length || !int.TryParse(args[++i], out workers) || workers < 1)
                    return Fail(stderr, "check: --workers needs a positive number");
            }
            else if (a.StartsWith('-')) return Fail(stderr, $"check: unknown option {a}");
            else pos.Add(a);
        }
        if (pos.Count != 2) return Fail(stderr, "check: needs PLAN.json and ROOT");
        if (deps is null)
        {
            if (!OperatingSystem.IsWindows()) return Fail(stderr, "check reads descriptors over SMB and runs only on Windows", 1);
            deps = CheckDeps.Windows();
        }

        var plan = Plan.Load(pos[0]);
        try { deps.EnablePrivilege("SeBackupPrivilege"); }
        catch (Win32Exception e) { return Fail(stderr, $"check: {e.Message} (Win32 error {e.NativeErrorCode})", 1); }
        var checker = new Checker(plan, deps.Tree(pos[1]), deps.Resolve, new WalkOptions(RootProtected: rootProtected));

        var summary = checker.Run(r => stdout.WriteLine(JsonSerializer.Serialize(r with { Path = FullPath(pos[1], r.Path) }, Json)), workers);

        PrintSummary(stderr, "check", summary);
        if (summary.NotProcessed > 0) stderr.WriteLine($"check: {summary.NotProcessed} director(ies) could not be listed; the check is incomplete");
        stderr.WriteLine(validate ? "check: validate; nothing was written" : "check: dry run; nothing was written");

        bool failed = summary.Count(Outcome.Error) > 0 || summary.NotProcessed > 0;
        bool differs = summary.Count(Outcome.Write) + summary.Count(Outcome.Follows) > 0;
        return failed || (validate && differs) ? 1 : 0;
    }

    static string FullPath(string root, string rel) => rel.Length == 0 ? root : Path.Join(root, rel);

    static IReadOnlyDictionary<string, long> OutcomeCounts(CheckSummary s) =>
        Enum.GetValues<Outcome>().ToDictionary(o => o.ToString().ToLowerInvariant(), s.Count);

    static IReadOnlyDictionary<string, long> FormCounts(CheckSummary s) => new Dictionary<string, long>
    {
        ["inherits"] = s.Count(Form.Inherits),
        ["explicit+inherits"] = s.Count(Form.ExplicitPlusInherits),
        ["protected"] = s.Count(Form.Protected),
    };

    static void PrintSummary(TextWriter stderr, string cmd, CheckSummary s)
    {
        stderr.WriteLine($"{cmd}: {string.Join(", ", OutcomeCounts(s).Select(kv => $"{kv.Key} {kv.Value}"))}");
        stderr.WriteLine($"{cmd}: forms: {string.Join(", ", FormCounts(s).Select(kv => $"{kv.Key} {kv.Value}"))}");
    }

    // Apply exits 0 when the preflight passed and every object was reached and is right (written
    // and read back, or found right); 1 on a refused preflight, a missing privilege, any error, a
    // guard stop or an incomplete walk; 2 on a usage error.
    static int Apply(string[] args, TextWriter stdout, TextWriter stderr, CheckDeps? deps)
    {
        bool rootProtected = false, resume = false;
        int workers = 16;
        string? probeDir = null, checkpointPath = null, evidenceDir = null;
        var pos = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            string? Value() => i + 1 < args.Length ? args[++i] : null;
            if (a == "--root-protected") rootProtected = true;
            else if (a == "--resume") resume = true;
            else if (a == "--workers")
            {
                if (!int.TryParse(Value(), out workers) || workers < 1) return Fail(stderr, "apply: --workers needs a positive number");
            }
            else if (a == "--probe-dir") { if ((probeDir = Value()) is null) return Fail(stderr, "apply: --probe-dir needs a directory"); }
            else if (a == "--checkpoint") { if ((checkpointPath = Value()) is null) return Fail(stderr, "apply: --checkpoint needs a file"); }
            else if (a == "--evidence-dir") { if ((evidenceDir = Value()) is null) return Fail(stderr, "apply: --evidence-dir needs a directory"); }
            else if (a.StartsWith('-')) return Fail(stderr, $"apply: unknown option {a}");
            else pos.Add(a);
        }
        if (pos.Count != 2) return Fail(stderr, "apply: needs PLAN.json and ROOT");
        if (resume && checkpointPath is null) return Fail(stderr, "apply: --resume needs --checkpoint");
        if (deps is null)
        {
            if (!OperatingSystem.IsWindows()) return Fail(stderr, "apply writes descriptors over SMB and runs only on Windows", 1);
            deps = CheckDeps.Windows();
        }
        string planPath = pos[0], root = pos[1];
        var planBytes = File.ReadAllBytes(planPath);
        var planSha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(planBytes)).ToLowerInvariant();
        var plan = Plan.Parse(System.Text.Encoding.UTF8.GetString(planBytes));

        // Phase 2 writes DACLs (and named owners/groups) only. A rule with sacl: would have its audit
        // ACEs silently not applied, so the plan is refused (design 8, phase 3).
        var withSacl = plan.Rules.Prepend(plan.Default).Where(r => r.SaclSet).Select(r => r.Label).ToList();
        if (withSacl.Count > 0)
            return Fail(stderr, $"apply: rule(s) {string.Join(", ", withSacl)} set sacl:, and this build writes no SACL (phase 3); use Set-SaclOnly for audit ACEs, and a plan without sacl: here", 1);

        var tree = deps.Tree(root);
        var checker = new Checker(plan, tree, deps.Resolve, new WalkOptions(Apply: true, RootProtected: rootProtected));
        var privileges = new List<string> { "SeBackupPrivilege", "SeSecurityPrivilege" };
        try
        {
            foreach (var p in privileges) deps.EnablePrivilege(p);
            if (checker.SetsOwnerOrGroup)
            {
                deps.EnablePrivilege("SeRestorePrivilege");
                privileges.Add("SeRestorePrivilege");
            }
            else deps.DisablePrivilege("SeRestorePrivilege");
        }
        catch (Win32Exception e) { return Fail(stderr, $"apply: {e.Message} (Win32 error {e.NativeErrorCode}); nothing was written", 1); }

        // Only once the plan has resolved and the privileges are held, so a refusal leaves no
        // evidence or checkpoint behind. The evidence dir is checked first and created last, so a
        // refused checkpoint leaves no evidence, and a refused evidence dir no checkpoint.
        if (evidenceDir is not null) Evidence.CheckDir(evidenceDir);
        using var checkpoint = checkpointPath is null ? null : new FileCheckpoint(checkpointPath, $"plan={planSha} root={root} root-protected={rootProtected}", resume);
        using var evidence = evidenceDir is null ? null : new Evidence(evidenceDir);

        foreach (var (name, sid) in checker.Principals) stderr.WriteLine($"apply: principal {name} = {sid}");
        if (checkpoint is not null && resume) stderr.WriteLine($"apply: resuming; {checkpoint.Loaded} director(ies) already complete");

        Manifest Manifest(string preflight, CheckSummary s, IReadOnlyList<string> reasons) => new(
            Guid.NewGuid().ToString("N"), "permissionreset-smb", typeof(Cli).Assembly.GetName().Version?.ToString(3) ?? "unknown",
            root, planPath, planSha, rootProtected, checker.Principals, privileges, preflight,
            OutcomeCounts(s), FormCounts(s), s.NotProcessed, s.Resumed, s.Stop, reasons);

        // Preflight (design 4): the probe, before anything in the tree is written or has its SACL read.
        ProbeResult probe;
        try
        {
            var probeTree = probeDir is null ? tree : deps.Tree(probeDir);
            probe = Preflight.Run(probeTree, "", checker.RootAcl());
        }
        catch (Exception e) when (e is not OutOfMemoryException) { probe = new ProbeResult(false, $"read the root: {e.Message}", ""); }
        if (!probe.Passed)
        {
            var why = $"preflight refused: {probe.Detail}";
            stderr.WriteLine($"apply: {why}; nothing in the tree was written");
            evidence?.Close(Manifest(why, new CheckSummary(), [why]));
            return 1;
        }
        stderr.WriteLine($"apply: {probe.Detail}");

        var summary = checker.Run(r =>
        {
            var path = FullPath(root, r.Path);
            stdout.WriteLine(JsonSerializer.Serialize(r with { Path = path, Before = null, After = null }, Json));
            evidence?.Record(r, path);
        }, workers, checkpoint);

        PrintSummary(stderr, "apply", summary);
        var reasons = new List<string>();
        if (summary.Stop is not null) reasons.Add(summary.Stop);
        if (summary.Count(Outcome.Error) > 0) reasons.Add($"{summary.Count(Outcome.Error)} object(s) failed");
        if (summary.Count(Outcome.Stopped) > 0) reasons.Add($"{summary.Count(Outcome.Stopped)} object(s) needed a write the stopped run did not make");
        if (summary.NotProcessed > 0) reasons.Add($"{summary.NotProcessed} director(ies) were not processed");
        foreach (var r in reasons) stderr.WriteLine($"apply: {r}");
        if (summary.Resumed > 0) stderr.WriteLine($"apply: {summary.Resumed} file(s) skipped, their directories complete in the checkpoint");
        stderr.WriteLine(reasons.Count == 0 ? "apply: complete" : "apply: incomplete");
        evidence?.Close(Manifest(probe.Detail, summary, reasons));
        return reasons.Count == 0 ? 0 : 1;
    }

    static int PlanCmd(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (args.Length != 1) return Fail(stderr, "plan: needs exactly one PLAN.json");
        var plan = Plan.Load(args[0]);
        stdout.WriteLine($"plan schema {plan.Schema}, source {plan.Source}, {plan.Rules.Count} rule(s) plus default");
        foreach (var r in plan.Rules.Prepend(plan.Default))
        {
            var match = r.Match.Type.Length == 0 && r.Match.Pattern.Length == 0 ? "everything else" : $"{(r.Match.Type.Length == 0 ? "any" : r.Match.Type)} {r.Match.Pattern}".Trim();
            var dacl = r.Dacl is not null ? $"; dacl {r.Dacl.Count} ACE(s)" : "";
            stdout.WriteLine($"  {r.Label}: {match}{dacl}; sacl {(r.SaclSet ? (r.Sacl?.Count ?? 0) + " ACE(s)" : "untouched")}{(r.KeepDacl ? ", keeps DACL" : "")}");
        }
        if (plan.Exclude.Patterns.Count > 0) stdout.WriteLine($"  exclude: {string.Join(", ", plan.Exclude.Patterns)}");
        return 0;
    }
}

// On a read, sacl_read records whether the SACL was requested: with --no-sacl an absent SACL means
// "not read", not "empty". On a failure there is no descriptor and no sacl_read; error says which
// step failed and why, and win32_error carries the Win32 code when there is one.
sealed record InspectLine(string Path, Descriptor? Descriptor, bool? SaclRead, string? Error, int? Win32Error);

// CheckDeps is what check and apply need from the OS. Tests pass fakes so the CLI's records and
// exit codes are checked on any OS; Windows() is the real thing.
sealed record CheckDeps(Action<string> EnablePrivilege, Func<string, IWritableTree> Tree, Func<string, string?> Resolve, Action<string>? Disable = null)
{
    public void DisablePrivilege(string name) => Disable?.Invoke(name);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static CheckDeps Windows() => new(Win32Security.EnablePrivilege, root => new Win32Tree(root), Win32Tree.Resolve, Win32Security.DisablePrivilege);
}
