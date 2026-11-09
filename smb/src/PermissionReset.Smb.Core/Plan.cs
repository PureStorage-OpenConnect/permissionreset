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
    public const int SupportedSchema = 1;

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
        if (p.Schema != SupportedSchema)
            throw new PlanException($"plan schema {p.Schema} is not supported (this build reads schema {SupportedSchema}); use a matching build-spec");
        if (p.Protocol != "nfsv4")
            throw new PlanException($"plan protocol \"{p.Protocol}\" is not supported; only nfsv4 specs translate to SMB");
        if (p.Default is null) throw new PlanException("plan has no default rule");
        foreach (var r in (p.Rules ?? []).Prepend(p.Default))
            if (r.Match.Type is not ("" or "file" or "directory"))
                throw new PlanException($"plan rule {r.Label}: unknown match type \"{r.Match.Type}\"");
        return p with { Rules = p.Rules ?? [], Exclude = p.Exclude ?? new PlanExclude([], [], []) };
    }

    public static Plan Load(string path) => Parse(File.ReadAllText(path));

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
    [property: JsonPropertyName("sacl")] IReadOnlyList<PlanAce>? Sacl);

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
