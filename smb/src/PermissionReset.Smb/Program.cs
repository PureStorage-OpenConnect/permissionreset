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
          plan PLAN.json                validate a `build-spec --sacl-plan` file and summarize it.
          version                       print the version.

        inspect needs an elevated shell with SeBackupPrivilege, and SeSecurityPrivilege unless
        --no-sacl. On FlashArray the identity also needs the array's audit bypass.
        """;

    internal static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public static int Run(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (args.Length == 0) { stderr.WriteLine(Usage); return 2; }
        try
        {
            return args[0] switch
            {
                "inspect" => Inspect(args[1..], stdout, stderr),
                "plan" => PlanCmd(args[1..], stdout, stderr),
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

    static int Inspect(string[] args, TextWriter stdout, TextWriter stderr)
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
        if (!OperatingSystem.IsWindows()) return Fail(stderr, "inspect reads descriptors over SMB and runs only on Windows", 1);

        Win32Security.EnablePrivilege("SeBackupPrivilege");
        if (withSacl) Win32Security.EnablePrivilege("SeSecurityPrivilege");

        int failed = 0;
        foreach (var p in paths)
        {
            InspectLine line;
            try { line = new InspectLine(p, Descriptor.Decode(Win32Security.ReadDescriptor(p, withSacl)), withSacl, null); }
            catch (Exception e) when (e is System.ComponentModel.Win32Exception or DescriptorFormatException)
            {
                failed++;
                line = new InspectLine(p, null, withSacl, e.Message);
            }
            stdout.WriteLine(JsonSerializer.Serialize(line, Json));
        }
        return failed == 0 ? 0 : 1;
    }

    static int PlanCmd(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (args.Length != 1) return Fail(stderr, "plan: needs exactly one PLAN.json");
        var plan = Plan.Load(args[0]);
        stdout.WriteLine($"plan schema {plan.Schema}, source {plan.Source}, {plan.Rules.Count} rule(s) plus default");
        foreach (var r in plan.Rules.Prepend(plan.Default))
        {
            var match = r.Match.Type.Length == 0 && r.Match.Pattern.Length == 0 ? "everything else" : $"{(r.Match.Type.Length == 0 ? "any" : r.Match.Type)} {r.Match.Pattern}".Trim();
            stdout.WriteLine($"  {r.Label}: {match}; sacl {(r.SaclSet ? (r.Sacl?.Count ?? 0) + " ACE(s)" : "untouched")}{(r.KeepDacl ? ", keeps DACL" : "")}");
        }
        if (plan.Exclude.Patterns.Count > 0) stdout.WriteLine($"  exclude: {string.Join(", ", plan.Exclude.Patterns)}");
        return 0;
    }
}

// sacl_read records whether the SACL was requested: with --no-sacl an absent SACL means "not read",
// not "empty".
sealed record InspectLine(string Path, Descriptor? Descriptor, bool SaclRead, string? Error);
