using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PermissionReset.Smb.Core;

// Evidence is apply's --evidence-dir (smb/DESIGN-write-path.md, section 6; docs/evidence.md). It
// writes the records, one line per object in permissionreset's vocabulary, to one uncompressed
// shard, and closes with manifest.json: whether the record is complete, why not, and the shard's
// SHA-256, size and record count. Every written object's line carries its raw descriptor before
// and after the write, base64, as inspect prints it; there is one profile.
public sealed class Evidence : IDisposable
{
    public const string ShardName = "shard-000001.log";

    readonly string dir;
    readonly FileStream shard;
    readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    readonly object gate = new();
    long records, size;

    // CheckDir refuses a directory that is not new or empty, so two runs never share a manifest.
    // It creates nothing, so a caller can check before it commits to anything else.
    public static void CheckDir(string dir)
    {
        if (File.Exists(dir)) throw new PlanException($"--evidence-dir {dir} is a file");
        if (Directory.Exists(dir) && Directory.EnumerateFileSystemEntries(dir).Any())
            throw new PlanException($"--evidence-dir {dir} is not empty; give every run its own new or empty directory");
    }

    public Evidence(string dir)
    {
        CheckDir(dir);
        Directory.CreateDirectory(dir);
        this.dir = dir;
        shard = new FileStream(Path.Combine(dir, ShardName), FileMode.CreateNew, FileAccess.Write);
    }

    // Line renders one record (path is the full path the operator sees).
    public static string Line(CheckRecord r, string path)
    {
        var form = r.Form switch { Form.Inherits => "inherits", Form.ExplicitPlusInherits => "explicit+inherits", Form.Protected => "protected", _ => null };
        var f = form is null ? "" : $" ({form})";
        return r.Outcome switch
        {
            Outcome.Written => $"OK: set {r.Parts} {path}{f}\tbefore={r.Before}\tafter={r.After}",
            Outcome.Ok => $"SAME: {path}{f}",
            Outcome.Write => $"WOULD: set {path}{f}: {r.Detail}",
            Outcome.Follows => $"WOULD: follow {path}{f}: {r.Detail}",
            Outcome.Stopped => $"SKIP: stopped {path}{f}: {r.Detail}",
            Outcome.Keep => $"SKIP: keep {path}",
            Outcome.Reparse => $"SKIP: reparse {path}",
            Outcome.Excluded => $"EXCLUDE: {path}",
            _ => $"ERR: {path}{f}: {r.Detail}" + (r.Before is null ? "" : $"\tbefore={r.Before}") + (r.After is null ? "" : $"\tafter={r.After}"),
        };
    }

    public void Record(CheckRecord r, string path)
    {
        var b = Encoding.UTF8.GetBytes(Line(r, path).Replace("\n", " ") + "\n");
        lock (gate)
        {
            shard.Write(b);
            hash.AppendData(b);
            records++;
            size += b.Length;
        }
    }

    // Close flushes the shard and writes the manifest. reasons empty means complete.
    public void Close(Manifest m)
    {
        lock (gate)
        {
            shard.Flush(true);
            shard.Dispose();
            var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            var full = m with
            {
                Status = m.Reasons.Count == 0 ? "complete" : "incomplete",
                Records = records,
                Shards = [new ManifestShard(ShardName, digest, size, records)],
            };
            File.WriteAllText(Path.Combine(dir, "manifest.json"), JsonSerializer.Serialize(full, Json) + "\n");
        }
    }

    public void Dispose()
    {
        lock (gate) shard.Dispose();
        hash.Dispose();
    }

    static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

// ProbeShard is the preflight shard of smb/DESIGN-sacl-write.md section 6 (section 11, decision
// 18): one line per probe event in preflight-shard-000001.log, in an evidence directory
// Evidence.CheckDir allows. It writes no manifest: the run's own manifest (apply) or summary
// (check) carries the preflight line. Each line is flushed to stable storage right away, the 7.2
// rule applied to the probe.
public sealed class ProbeShard : IDisposable
{
    public const string ShardName = "preflight-shard-000001.log";

    readonly FileStream shard;

    public ProbeShard(string dir)
    {
        Evidence.CheckDir(dir);
        Directory.CreateDirectory(dir);
        shard = new FileStream(Path.Combine(dir, ShardName), FileMode.CreateNew, FileAccess.Write);
    }

    public static string Line(ProbeEvent e) =>
        $"PROBE-{e.Kind.ToUpperInvariant()}: {e.Rel}{(e.Detail is null ? "" : $": {e.Detail}")}" +
        (e.BeforeB64 is null ? "" : $"\tbefore={e.BeforeB64}") + (e.AfterB64 is null ? "" : $"\tafter={e.AfterB64}");

    public void Record(ProbeEvent e)
    {
        var b = Encoding.UTF8.GetBytes(Line(e).Replace("\n", " ") + "\n");
        shard.Write(b);
        shard.Flush(true);
    }

    public void Dispose() => shard.Dispose();
}

public sealed record ManifestShard(string Name, string Sha256, long Size, long Records);

public sealed record Manifest(
    string RunId,
    string Tool,
    string Version,
    string Root,
    string Plan,
    string PlanSha256,
    bool RootProtected,
    IReadOnlyDictionary<string, string> Principals,
    IReadOnlyList<string> Privileges,
    string Preflight,
    IReadOnlyDictionary<string, long> Outcomes,
    IReadOnlyDictionary<string, long> Forms,
    long NotProcessed,
    long Resumed,
    string? Stop,
    IReadOnlyList<string> Reasons,
    string Status = "",
    long Records = 0,
    IReadOnlyList<ManifestShard>? Shards = null,
    // --write-order as apply ran it (design 4.2: the order is recorded in the manifest; it is not
    // bound in the checkpoint, decision 11).
    string? WriteOrder = null);
