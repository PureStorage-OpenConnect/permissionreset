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
          check [--validate] [--workers N] [--root-protected] [--root-sacl-protected]
                [--write-order sacl-first|dacl-first] [--probe-dir DIR] [--evidence-dir DIR]
                [--accept-unproven-read] PLAN.json ROOT
                                        walk ROOT and say, per object, whether its DACL (and SACL,
                                        when a rule sets sacl:) is what the plan wants (ok), needs
                                        its own write (write), or will be right once an ancestor is
                                        written (follows). JSON lines on stdout, a summary on
                                        stderr. Writes nothing to any object in the tree.
                                        --validate exits 1 on any object that isn't ok.
                                        A plan with a sacl: rule also enables SeSecurityPrivilege
                                        and proves the audit bypass on a disposable probe it
                                        creates and removes under --probe-dir, or under ROOT when
                                        --probe-dir is not given, before any tree object is read;
                                        --accept-unproven-read skips that proof with a NOTE. The
                                        probe's events go to --evidence-dir, else to NOTE lines and
                                        a "probe" JSON line on stdout. --write-order has no effect
                                        on check (a NOTE says so). --root-sacl-protected forces the
                                        root's SACL form to protected.
          apply [--workers N] [--root-protected] [--root-sacl-protected]
                [--write-order sacl-first|dacl-first] [--probe-dir DIR] [--checkpoint FILE [--resume]]
                [--evidence-dir DIR] PLAN.json ROOT
                                        the same walk, writing each object whose DACL (or named
                                        owner/group, or SACL when a rule sets sacl:) differs,
                                        top-down, and reading every write back. A disposable probe
                                        proves the write path first, including the audit bypass on
                                        a sacl: plan. --write-order dacl-first writes access before
                                        auditing on a two-part object; a NOTE says what that risks.
                                        --root-sacl-protected forces the root's SACL form to
                                        protected, independently of --root-protected. Without
                                        --evidence-dir the probe's events go to NOTE lines and a
                                        "probe" JSON line on stdout.
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

    // Version names the .NET runtime too ("permissionreset-smb 0.1.0 (.NET 10.0.15)"). The release
    // exe is self-contained and carries its runtime, which Windows Update never patches, so an
    // operator, an auditor or a scanner report can tie a binary to the runtime inside it
    // (docs/plan-smb-dotnet10.md, 3.3 and 5).
    static int Version(TextWriter o)
    {
        var v = typeof(Cli).Assembly.GetName().Version;
        o.WriteLine($"permissionreset-smb {v?.ToString(3) ?? "unknown"} ({System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription})");
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
            // A path the reader can't name (Path.GetFullPath or the long-path prefix rejects it:
            // illegal characters, unsupported form, too long) is that path's failure, not the run's.
            // Anything else is a bug and still escapes.
            catch (Exception e) when (e is Win32Exception or DescriptorFormatException or ArgumentException
                                          or NotSupportedException or IOException)
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
        bool validate = false, rootProtected = false, rootSaclProtected = false, acceptUnprovenRead = false;
        WriteOrder order = WriteOrder.SaclFirst;
        bool orderGiven = false;
        int workers = 16;
        string? probeDir = null, evidenceDir = null;
        var pos = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            string? Value() => i + 1 < args.Length ? args[++i] : null;
            if (a == "--validate") validate = true;
            else if (a == "--root-protected") rootProtected = true;
            else if (a == "--root-sacl-protected") rootSaclProtected = true;   // independent of --root-protected (decision 4)
            else if (a == "--accept-unproven-read") acceptUnprovenRead = true;
            else if (a == "--write-order")
            {
                if (Value() is not ("sacl-first" or "dacl-first")) return Fail(stderr, "check: --write-order needs sacl-first or dacl-first");
                order = args[i] == "dacl-first" ? WriteOrder.DaclFirst : WriteOrder.SaclFirst;
                orderGiven = true;
            }
            else if (a == "--workers")
            {
                if (i + 1 >= args.Length || !int.TryParse(args[++i], out workers) || workers < 1)
                    return Fail(stderr, "check: --workers needs a positive number");
            }
            else if (a == "--probe-dir") { if ((probeDir = Value()) is null) return Fail(stderr, "check: --probe-dir needs a directory"); }
            else if (a == "--evidence-dir") { if ((evidenceDir = Value()) is null) return Fail(stderr, "check: --evidence-dir needs a directory"); }
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
        // The order picks which of a two-part object's writes goes first, and check writes none,
        // so a check run says nothing about an order (#93 review, 6).
        if (orderGiven)
            stderr.WriteLine("check: NOTE: --write-order has no effect on check; it orders apply's two writes, and check validates no order");
        try { deps.EnablePrivilege("SeBackupPrivilege"); }
        catch (Win32Exception e) { return Fail(stderr, $"check: {e.Message} (Win32 error {e.NativeErrorCode})", 1); }
        var root = pos[1];
        // Every plan and principal check comes before any probe or read (design 2.2): principal
        // resolution and the creator-SID refusal happen inside the Checker's constructor, before
        // any tree read. A lookup failure that the Checker could not classify as an unresolved
        // principal (a thrown domain/trust error is folded in; this is the belt for anything else)
        // is still refused, never a crash.
        Checker checker;
        try { checker = new Checker(plan, deps.Tree(root), RuleSelector.RootName(root), deps.Resolve, new WalkOptions(RootProtected: rootProtected, Order: order, RootSaclProtected: rootSaclProtected)); }
        catch (PlanException) { throw; }   // the outer handler prints it and exits 1
        catch (Exception e) { return Fail(stderr, $"check: the plan's principals could not be prepared: {e.Message}", 1); }
        // Phase 3 plumbing (design 5 and 6), after the plan checks and before the walk: a plan
        // with a sacl: rule needs SeSecurityPrivilege and the probe's bypass proof before any
        // tree object's SACL is read.
        if (CheckSaclPreflight(plan, deps, root, probeDir, evidenceDir, acceptUnprovenRead, stdout, stderr) is { } refusedCheck)
            return refusedCheck;

        foreach (var (name, sid) in checker.Principals) stderr.WriteLine($"check: principal {name} = {sid}");
        var summary = checker.Run(r => stdout.WriteLine(JsonSerializer.Serialize(r with { Path = FullPath(root, r.Path) }, Json)), workers);

        PrintSummary(stderr, "check", summary, checker.SaclMode);
        if (summary.Stop is not null) stderr.WriteLine($"check: stopped: {summary.Stop}; the check is incomplete");
        if (summary.NotProcessed > 0) stderr.WriteLine($"check: {summary.NotProcessed} director(ies) could not be read, listed or classified, so what is below them was not checked; the check is incomplete");
        var nothing = checker.SaclMode && !acceptUnprovenRead
            ? "nothing in the tree was written (the preflight probe was created and removed)"
            : "nothing was written";
        stderr.WriteLine(validate ? $"check: validate; {nothing}" : $"check: dry run; {nothing}");

        bool failed = summary.Count(Outcome.Error) > 0 || summary.NotProcessed > 0 || summary.Stop is not null;
        bool differs = summary.Count(Outcome.Write) + summary.Count(Outcome.Follows) > 0;
        return failed || (validate && differs) ? 1 : 0;
    }

    // CheckSaclPreflight is the phase 3 check preflight for a plan whose rules set sacl: (design 5
    // and 6). Layer 1 enables SeSecurityPrivilege, exit 1 naming it, before any evidence directory
    // or probe exists. Layers 2 and 3 are the check-mode probe (design 6, steps 1, 2 and 7's
    // cleanup): the bypass proof on a disposable probe, before any tree read. Without a writable
    // probe location the refusal exits 1 with nothing left behind; --accept-unproven-read skips
    // the proof with a NOTE. The probe's events go to --evidence-dir as a preflight shard, else to
    // NOTE lines plus a probe JSON line on stdout (decision 18). A plan with no sacl: rule does
    // none of this. Null to proceed with the walk; an exit code otherwise.
    static int? CheckSaclPreflight(Plan plan, CheckDeps deps, string root, string? probeDir, string? evidenceDir, bool acceptUnprovenRead, TextWriter stdout, TextWriter stderr)
    {
        if (!plan.Rules.Prepend(plan.Default).Any(r => r.SaclSet)) return null;
        try { deps.EnablePrivilege("SeSecurityPrivilege"); }
        catch (Win32Exception e) { return Fail(stderr, $"check: {e.Message} (Win32 error {e.NativeErrorCode}); nothing was read", 1); }
        if (acceptUnprovenRead)
        {
            stderr.WriteLine("check: NOTE: --accept-unproven-read: the tree's SACLs are read without a proven audit bypass; a read the array mishandles is not caught (design 6, PS-02)");
            return null;
        }
        List<ProbeEvent>? collected = evidenceDir is null ? [] : null;
        using var shard = evidenceDir is null ? null : new ProbeShard(evidenceDir);
        ProbeResult probe;
        // Check mode never calls RootSacl (steps 3 to 6 are apply's): the delegate makes any such
        // call an explicit failure, so no tree SACL can be read before the proof. rootAces is
        // unused the same way (the DACL steps are apply's too).
        try
        {
            var probeTree = probeDir is null ? deps.Tree(root) : deps.Tree(probeDir);
            probe = Preflight.Run(probeTree, "", [],
                new SaclProbe(() => throw new InvalidOperationException("check runs the bypass proof only; the root's SACL is never read here (design 6)"),
                    ProbeMode.Check, shard is not null ? shard.Record : collected!.Add));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            probe = new ProbeResult(false, $"the probe location {probeDir ?? root}: {e.Message}", "");
        }
        if (collected is not null) ReportProbe("check", collected, probe, stdout, stderr);
        if (!probe.Passed)
        {
            stderr.WriteLine($"permissionreset-smb: check: preflight refused: probe {probe.Probe}: {probe.Detail}; nothing in the tree was read");
            return 1;
        }
        stderr.WriteLine($"check: {probe.Detail}");
        return null;
    }

    // ReportProbe is decision 18 without --evidence-dir: the probe's write, read-back and removal
    // go to NOTE lines for the operator and to one machine-readable probe record, a JSON line on
    // stdout ahead of the walk's records, keyed "probe" where every walk record has "path".
    static void ReportProbe(string cmd, List<ProbeEvent> events, ProbeResult probe, TextWriter stdout, TextWriter stderr)
    {
        stderr.WriteLine($"{cmd}: NOTE: the preflight probe events (no --evidence-dir; decision 18):");
        foreach (var ev in events) stderr.WriteLine($"{cmd}: NOTE:   {ProbeShard.Line(ev)}");
        stdout.WriteLine(JsonSerializer.Serialize(new ProbeRecord(new ProbeSummary(probe.Passed, probe.Detail, events)), Json));
    }

    sealed record ProbeSummary(bool Passed, string Detail, IReadOnlyList<ProbeEvent> Events);
    sealed record ProbeRecord(ProbeSummary Probe);

    // FullPath names an object in the root's own separator style, so \\array\share\dept gives
    // \\array\share\dept\a\f.txt, not \\array\share\dept\a/f.txt.
    static string FullPath(string root, string rel)
    {
        if (rel.Length == 0) return root;
        char sep = root.Contains('\\') ? '\\' : root.Contains('/') ? '/' : Path.DirectorySeparatorChar;
        var r = sep == '/' ? rel : rel.Replace('/', sep);
        return root.EndsWith('\\') || root.EndsWith('/') ? root + r : root + sep + r;
    }

    static IReadOnlyDictionary<string, long> OutcomeCounts(CheckSummary s) =>
        Enum.GetValues<Outcome>().ToDictionary(o => o.ToString().ToLowerInvariant(), s.Count);

    static IReadOnlyDictionary<string, long> FormCounts(CheckSummary s) => new Dictionary<string, long>
    {
        ["inherits"] = s.Count(Form.Inherits),
        ["explicit+inherits"] = s.Count(Form.ExplicitPlusInherits),
        ["protected"] = s.Count(Form.Protected),
    };

    static IReadOnlyDictionary<string, long> SaclFormCounts(CheckSummary s) => new Dictionary<string, long>
    {
        ["inherits"] = s.CountSacl(Form.Inherits),
        ["explicit+inherits"] = s.CountSacl(Form.ExplicitPlusInherits),
        ["protected"] = s.CountSacl(Form.Protected),
    };

    // PrintSummary's forms: line counts the desired DACL forms, as in phase 2. On a plan with a
    // sacl: rule a sacl forms: line follows with the desired SACL forms, so a keep_dacl run, whose
    // DACL forms are all zero, still shows what it wrote (win01-lab's #93 probe, finding a).
    static void PrintSummary(TextWriter stderr, string cmd, CheckSummary s, bool saclMode)
    {
        stderr.WriteLine($"{cmd}: {string.Join(", ", OutcomeCounts(s).Select(kv => $"{kv.Key} {kv.Value}"))}");
        stderr.WriteLine($"{cmd}: forms: {string.Join(", ", FormCounts(s).Select(kv => $"{kv.Key} {kv.Value}"))}");
        if (saclMode)
            stderr.WriteLine($"{cmd}: sacl forms: {string.Join(", ", SaclFormCounts(s).Select(kv => $"{kv.Key} {kv.Value}"))}");
    }

    // Apply exits 0 when the preflight passed and every object was reached and is right (written
    // and read back, or found right); 1 on a refused preflight, a missing privilege, any error, a
    // guard stop or an incomplete walk; 2 on a usage error.
    static int Apply(string[] args, TextWriter stdout, TextWriter stderr, CheckDeps? deps)
    {
        bool rootProtected = false, rootSaclProtected = false, resume = false;
        WriteOrder order = WriteOrder.SaclFirst;
        int workers = 16;
        string? probeDir = null, checkpointPath = null, evidenceDir = null;
        var pos = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            string? Value() => i + 1 < args.Length ? args[++i] : null;
            if (a == "--root-protected") rootProtected = true;
            else if (a == "--root-sacl-protected") rootSaclProtected = true;   // independent of --root-protected (decision 4)
            else if (a == "--write-order")
            {
                if (Value() is not ("sacl-first" or "dacl-first")) return Fail(stderr, "apply: --write-order needs sacl-first or dacl-first");
                order = args[i] == "dacl-first" ? WriteOrder.DaclFirst : WriteOrder.SaclFirst;
            }
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
        var planBytes = Plan.ReadBytes(planPath);
        var planSha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(planBytes)).ToLowerInvariant();
        var plan = Plan.Parse(planBytes);

        var tree = deps.Tree(root);
        var checker = new Checker(plan, tree, RuleSelector.RootName(root), deps.Resolve,
            new WalkOptions(Apply: true, RootProtected: rootProtected, Order: order, RootSaclProtected: rootSaclProtected));
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
        // refused checkpoint leaves no evidence, and a refused evidence dir no checkpoint. The
        // checkpoint is only checked (and, with --resume, loaded) here; its file is written once the
        // preflight passes, so a refused preflight leaves none and the same command can be rerun.
        if (evidenceDir is not null) Evidence.CheckDir(evidenceDir);
        // Checkpoint v2 binds the run's identity (7.1): the plan digest, the root, both root
        // protection flags, the resolved principal table (a name resolving differently on resume
        // refuses the resume, decision 20) and the S:AI rule the preflight confirms (4.3). The
        // checker exists at this point, so the table is resolved; Principals is a sorted
        // dictionary, and its ordinal key order is what is hashed. --write-order is deliberately
        // not bound (decision 11): a resume re-reads everything it does not skip.
        var principalsHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(string.Join("", checker.Principals.Select(kv => $"{kv.Key}={kv.Value}\n"))))).ToLowerInvariant();
        using var checkpoint = checkpointPath is null ? null : new FileCheckpoint(checkpointPath,
            $"plan={planSha} root={root} root-protected={rootProtected} root-sacl-protected={rootSaclProtected} principals={principalsHash} sai-rule={(checker.SaclMode ? "protected-clear,unprotected-set" : "none")}", resume);
        using var evidence = evidenceDir is null ? null : new Evidence(evidenceDir);

        foreach (var (name, sid) in checker.Principals) stderr.WriteLine($"apply: principal {name} = {sid}");
        if (checkpoint is not null && resume) stderr.WriteLine($"apply: resuming; {checkpoint.Loaded} director(ies) already complete");

        ManifestShard? preflightShard = null;
        Manifest Manifest(string preflight, CheckSummary s, IReadOnlyList<string> reasons) => new(
            Guid.NewGuid().ToString("N"), "permissionreset-smb", typeof(Cli).Assembly.GetName().Version?.ToString(3) ?? "unknown",
            root, planPath, planSha, rootProtected, checker.Principals, privileges, preflight,
            OutcomeCounts(s), FormCounts(s), s.NotProcessed, s.Resumed, s.Stop, reasons,
            Shards: preflightShard is null ? null : [preflightShard],
            WriteOrder: order == WriteOrder.DaclFirst ? "dacl-first" : "sacl-first",
            SaclForms: checker.SaclMode ? SaclFormCounts(s) : null);

        // dacl-first's NOTE, once, before any write (design 4.2, decision 11): the probe below
        // writes only the disposable object, but the flag orders the walk's tree writes.
        if (order == WriteOrder.DaclFirst)
            stderr.WriteLine("apply: NOTE: --write-order dacl-first: each two-part object's access policy is written before its auditing, so if its SACL write fails after its DACL write, new access can go unaudited");

        // Preflight (design 4): the probe, before anything in the tree is written or has its SACL read.
        // On a sacl: plan it runs section 6's full SACL preflight: the bypass proof, the root's
        // desired SACL only after step 2 (checker.RootSacl runs inside the probe), and the
        // decision-18 preflight shard in the evidence directory. A plan without a sacl: rule runs
        // phase 2's preflight unchanged.
        ProbeResult probe;
        try
        {
            var probeTree = probeDir is null ? tree : deps.Tree(probeDir);
            if (checker.SaclMode)
            {
                // Without an evidence directory the events still reach the operator, as NOTE lines
                // (decision 18), the way check prints them.
                using var probeShard = evidenceDir is null ? null : new ProbeShard(evidenceDir, checkDir: false);
                List<ProbeEvent>? collected = probeShard is null ? [] : null;
                // The shard's entry is taken even when the probe throws, so a refused preflight's
                // manifest still binds what the probe recorded (7.2).
                try
                {
                    probe = Preflight.Run(probeTree, "", checker.RootAcl(),
                        new SaclProbe(checker.RootSacl, ProbeMode.Apply, probeShard is not null ? probeShard.Record : collected!.Add));
                }
                finally { preflightShard = probeShard?.Entry(); }
                if (collected is not null) ReportProbe("apply", collected, probe, stdout, stderr);
            }
            else
                probe = Preflight.Run(probeTree, "", checker.RootAcl());
        }
        catch (Exception e) when (e is not OutOfMemoryException) { probe = new ProbeResult(false, $"preflight: {e.Message}", ""); }
        if (!probe.Passed)
        {
            var why = $"preflight refused: {probe.Detail}";
            stderr.WriteLine($"apply: {why}; nothing in the tree was written");
            evidence?.Close(Manifest(why, new CheckSummary(), [why]));
            return 1;
        }
        stderr.WriteLine($"apply: {probe.Detail}");
        try { checkpoint?.Start(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            var why = $"checkpoint {checkpointPath}: {e.Message}";
            stderr.WriteLine($"apply: {why}; nothing in the tree was written");
            evidence?.Close(Manifest(probe.Detail, new CheckSummary(), [why]));
            return 1;
        }

        var summary = checker.Run(r =>
        {
            var path = FullPath(root, r.Path);
            stdout.WriteLine(JsonSerializer.Serialize(r with { Path = path, Before = null, After = null }, Json));
            evidence?.Record(r, path);
        }, workers, checkpoint);

        PrintSummary(stderr, "apply", summary, checker.SaclMode);
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
