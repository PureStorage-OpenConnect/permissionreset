using System.Text.Json;
using System.Text.Json.Serialization;

namespace PermissionReset.Smb.Core;

// Plan is the JSON that `build-spec --sacl-plan` emits (internal/saclplan). The spec has one
// parser, in Go; this tool never reads YAML. Field names and meanings are owned by
// internal/saclplan/saclplan.go, and a schema bump there must be matched here.
public sealed record Plan(
    [property: JsonPropertyName("schema")] int Schema,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("protocol")] string Protocol,
    [property: JsonPropertyName("exclude")] PlanExclude Exclude,
    [property: JsonPropertyName("default")] PlanRule Default,
    [property: JsonPropertyName("rules")] IReadOnlyList<PlanRule> Rules)
{
    // Schema 1 is what `build-spec --sacl-plan` writes (SACLs only, for Set-SaclOnly); schema 2 is
    // `build-spec --smb-plan`, which adds each rule's DACL. A schema 1 plan is still read, by `plan`.
    public const int SaclSchema = 1, SmbSchema = 2;

    public static Plan Parse(string json)
    {
        Plan? p;
        try
        {
            p = JsonSerializer.Deserialize<Plan>(json, Options);
        }
        catch (JsonException e)
        {
            throw new PlanException($"plan is not valid JSON: {e.Message}", e);
        }
        if (p is null) throw new PlanException("plan is empty");
        if (p.Schema is not (SaclSchema or SmbSchema))
            throw new PlanException($"plan schema {p.Schema} is not supported (this build reads schemas {SaclSchema} and {SmbSchema}); use a matching build-spec");
        if (p.Protocol != "nfsv4")
            throw new PlanException($"plan protocol \"{p.Protocol}\" is not supported; only nfsv4 specs translate to SMB");
        CheckPresent(p);
        foreach (var r in p.Rules.Prepend(p.Default))
        {
            if (r.Match.Type is not ("" or "file" or "directory"))
                throw new PlanException($"plan rule {r.Label}: unknown match type \"{r.Match.Type}\"");
            CheckAces(p.Schema, r);
        }
        return p;
    }

    // CheckPresent refuses a plan in which a field this tool reads is missing or null.
    // System.Text.Json leaves an absent field null even where the type says it can't be, and
    // internal/saclplan always writes every one of these (only dacl is omitempty), so an absent one
    // is a malformed plan: refused here, not defaulted or left to fail later as a null dereference.
    static void CheckPresent(Plan p)
    {
        if (p.Source is null) throw new PlanException("plan has no source");
        if (p.Exclude is null) throw new PlanException("plan has no exclude");
        foreach (var (name, list) in new[] { ("patterns", p.Exclude.Patterns), ("base", p.Exclude.Base), ("path", p.Exclude.Path) })
        {
            if (list is null) throw new PlanException($"plan exclude has no {name}");
            if (list.Any(x => x is null)) throw new PlanException($"plan exclude {name} has a null entry");
        }
        if (p.Default is null) throw new PlanException("plan has no default rule");
        if (p.Rules is null) throw new PlanException("plan has no rules");
        CheckRulePresent(p.Default, "default");
        for (int i = 0; i < p.Rules.Count; i++)
        {
            if (p.Rules[i] is null) throw new PlanException($"plan rule[{i}] is null");
            CheckRulePresent(p.Rules[i], $"rule[{i}]");
        }
    }

    // where names the rule by its place in the plan, since a rule with no label has nothing else.
    static void CheckRulePresent(PlanRule r, string where)
    {
        if (r.Label is null) throw new PlanException($"plan {where} has no label");
        var name = $"plan rule {r.Label}";
        if (r.Match is null) throw new PlanException($"{name}: has no match");
        if (r.Match.Type is null) throw new PlanException($"{name}: match has no type");
        if (r.Match.Pattern is null) throw new PlanException($"{name}: match has no pattern");
        if (r.Owner is null) throw new PlanException($"{name}: has no owner");
        if (r.Group is null) throw new PlanException($"{name}: has no group");
        foreach (var (field, aces) in new[] { ("sacl", r.Sacl), ("dacl", r.Dacl) })
        {
            if (aces is null) continue;
            for (int j = 0; j < aces.Count; j++)
            {
                var a = aces[j];
                if (a is null) throw new PlanException($"{name}: {field}[{j}] is null");
                foreach (var (f, v) in new[] { ("line", a.Line), ("principal", a.Principal), ("sid", a.Sid), ("sddl", a.Sddl) })
                    if (v is null) throw new PlanException($"{name}: {field}[{j}] has no {f}");
            }
        }
    }

    // CheckAces refuses a rule whose ACEs don't fit its schema. build-spec never writes such a plan;
    // the check is here so that a hand-edited or mismatched one is refused, not misread.
    static void CheckAces(int schema, PlanRule r)
    {
        if (schema == SaclSchema)
        {
            if (r.Dacl is not null) throw new PlanException($"plan rule {r.Label}: a schema 1 plan has no dacl");
            return;
        }
        if (r.HasAcl != r.Dacl is not null)
            throw new PlanException($"plan rule {r.Label}: has_acl is {r.HasAcl.ToString().ToLowerInvariant()} but dacl is {(r.Dacl is null ? "absent" : "present")}");
        foreach (var a in r.Dacl ?? [])
        {
            if (a.WindowsType is not (AceTypes.Allow or AceTypes.Deny))
                throw new PlanException($"plan rule {r.Label}: dacl ACE \"{a.Line}\" has type {a.WindowsType}, want allow (0) or deny (1)");
            if ((a.WindowsFlags & AceFlags.Inherited) != 0)
                throw new PlanException($"plan rule {r.Label}: dacl ACE \"{a.Line}\" carries ID; inheritance is computed, not planned");
        }
        foreach (var a in r.Sacl ?? [])
        {
            if (a.WindowsType != AceTypes.Audit)
                throw new PlanException($"plan rule {r.Label}: sacl ACE \"{a.Line}\" has type {a.WindowsType}, want audit (2)");
            if ((a.WindowsFlags & AceFlags.Inherited) != 0)
                throw new PlanException($"plan rule {r.Label}: sacl ACE \"{a.Line}\" carries ID; inheritance is computed, not planned");
        }
    }

    // Load reads and parses the plan at path. A file that can't be read is a PlanException naming
    // the path, so the CLI reports it as a message rather than a stack trace.
    public static Plan Load(string path)
    {
        string json;
        try
        {
            json = File.ReadAllText(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            throw new PlanException($"cannot read plan {path}: {e.Message}", e);
        }
        return Parse(json);
    }

    // Parse(bytes) decodes the way File.ReadAllText does (UTF-8 by default, a byte-order mark
    // honored and dropped), so apply, which hashes the exact bytes, reads the same plan as check.
    public static Plan Parse(byte[] bytes)
    {
        using var r = new StreamReader(new MemoryStream(bytes), System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return Parse(r.ReadToEnd());
    }

    // Unknown fields are refused: a field this build does not know means a plan it would misread.
    static readonly JsonSerializerOptions Options = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
}

public sealed record PlanExclude(
    [property: JsonPropertyName("patterns")] IReadOnlyList<string> Patterns,
    [property: JsonPropertyName("base")] IReadOnlyList<string> Base,
    [property: JsonPropertyName("path")] IReadOnlyList<string> Path);

public sealed record PlanRule(
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("match")] PlanMatch Match,
    [property: JsonPropertyName("sacl_set")] bool SaclSet,
    [property: JsonPropertyName("keep_dacl")] bool KeepDacl,
    [property: JsonPropertyName("has_acl")] bool HasAcl,
    [property: JsonPropertyName("has_dacl")] bool HasDacl,
    [property: JsonPropertyName("has_mode")] bool HasMode,
    [property: JsonPropertyName("owner")] string Owner,
    [property: JsonPropertyName("group")] string Group,
    [property: JsonPropertyName("sacl")] IReadOnlyList<PlanAce>? Sacl,
    // Schema 2 only: the rule's DACL, present exactly when HasAcl.
    [property: JsonPropertyName("dacl")] IReadOnlyList<PlanAce>? Dacl = null);

public sealed record PlanMatch(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("pattern")] string Pattern);

public sealed record PlanAce(
    [property: JsonPropertyName("line")] string Line,
    [property: JsonPropertyName("nfs4_flags")] uint Nfs4Flags,
    [property: JsonPropertyName("nfs4_mask")] uint Nfs4Mask,
    [property: JsonPropertyName("windows_type")] int WindowsType,
    [property: JsonPropertyName("windows_flags")] byte WindowsFlags,
    [property: JsonPropertyName("windows_mask")] uint WindowsMask,
    [property: JsonPropertyName("principal")] string Principal,
    [property: JsonPropertyName("group")] bool Group,
    [property: JsonPropertyName("sid")] string Sid,
    [property: JsonPropertyName("sddl")] string Sddl);

public sealed class PlanException(string message, Exception? inner = null) : Exception(message, inner);

// MS-DTYP ACE header values the plan and the inheritance code use.
public static class AceTypes
{
    public const int Allow = 0, Deny = 1, Audit = 2;
}

public static class AceFlags
{
    public const byte ObjectInherit = 0x01, ContainerInherit = 0x02, NoPropagate = 0x04, InheritOnly = 0x08,
        Inherited = 0x10, SuccessfulAccess = 0x40, FailedAccess = 0x80;
    public const byte InheritanceMask = ObjectInherit | ContainerInherit | NoPropagate | InheritOnly;
}
