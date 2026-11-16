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
          check [--validate] [--workers N] PLAN.json ROOT
                                        walk ROOT and say, per object, whether its DACL is what the
                                        schema 2 plan wants (ok), needs its own write (write), or
                                        will be right once an ancestor is written (follows). JSON
                                        lines on stdout, a summary on stderr. Writes nothing.
                                        --validate exits 1 on any object that isn't ok.
          plan PLAN.json                validate a `build-spec --smb-plan` (or --sacl-plan) file and summarize it.
          version                       print the version.

        inspect needs an elevated shell with SeBackupPrivilege, and SeSecurityPrivilege unless
        --no-sacl. On FlashArray the identity also needs the array's audit bypass. check needs
        SeBackupPrivilege.
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
        bool validate = false;
        int workers = 16;
        var pos = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a == "--validate") validate = true;
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
        var checker = new Checker(plan, deps.Tree(pos[1]), deps.Resolve);

        var summary = checker.Run(r =>
        {
            var path = r.Path.Length == 0 ? pos[1] : Path.Join(pos[1], r.Path);
            stdout.WriteLine(JsonSerializer.Serialize(r with { Path = path }, Json));
        }, workers);

        var outcomes = string.Join(", ", Enum.GetValues<Outcome>().Select(o => $"{o.ToString().ToLowerInvariant()} {summary.Count(o)}"));
        var forms = $"inherits {summary.Count(Form.Inherits)}, explicit+inherits {summary.Count(Form.ExplicitPlusInherits)}, protected {summary.Count(Form.Protected)}";
        stderr.WriteLine($"check: {outcomes}");
        stderr.WriteLine($"check: forms: {forms}");
        if (summary.NotProcessed > 0) stderr.WriteLine($"check: {summary.NotProcessed} director(ies) could not be listed; the check is incomplete");
        stderr.WriteLine(validate ? "check: validate; nothing was written" : "check: dry run; nothing was written");

        bool failed = summary.Count(Outcome.Error) > 0 || summary.NotProcessed > 0;
        bool differs = summary.Count(Outcome.Write) + summary.Count(Outcome.Follows) > 0;
        return failed || (validate && differs) ? 1 : 0;
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

// CheckDeps is what check needs from the OS. Tests pass fakes so the CLI's records and exit codes
// are checked on any OS; Windows() is the real thing.
sealed record CheckDeps(Action<string> EnablePrivilege, Func<string, ITree> Tree, Func<string, string?> Resolve)
{
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static CheckDeps Windows() => new(Win32Security.EnablePrivilege, root => new Win32Tree(root), Win32Tree.Resolve);
}
