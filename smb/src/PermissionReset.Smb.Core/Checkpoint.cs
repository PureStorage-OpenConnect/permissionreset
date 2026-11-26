using System.Text.Json;

namespace PermissionReset.Smb.Core;

// FileCheckpoint is apply's directory-level checkpoint (smb/DESIGN-write-path.md, 3.4), v2 format
// (smb/DESIGN-sacl-write.md, 7.1, decision 13): a text file whose first line, "checkpoint v2",
// binds the run it belongs to (the plan digest, the root, both root protection flags, the resolved
// principal table and the S:AI rule) and whose other lines are complete directories (one JSON
// string each) and per-directory compare-time SACL records (one JSON object each,
// {"dir": …, "sacl": [ACEs]}), appended and flushed as they finish. Rewalking a complete
// directory is safe, since the compare finds it right and writes nothing, so a lost last line
// costs time, not correctness. The first compare-time SACL record for a directory wins: it holds
// the earliest run's pre-write state, which is the truth on every later resume.
public sealed class FileCheckpoint : ICheckpoint, IDisposable
{
    readonly HashSet<string> done = new(StringComparer.Ordinal);
    readonly Dictionary<string, IReadOnlyList<Ace>> compareSacl = new(StringComparer.Ordinal);
    readonly string path, header;
    readonly bool resume;
    readonly object gate = new();
    bool needsNewline;
    StreamWriter? w;

    static readonly JsonSerializerOptions Camel = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public int Loaded => done.Count;

    // The constructor checks the file against identity and, with resume, loads it, but writes
    // nothing: Start does, once the caller is committed to the run (apply starts it after the
    // preflight passes), so a refused run leaves no checkpoint behind. Without resume, an existing
    // file is refused, so a stale checkpoint never skips work silently. With resume, its identity
    // line must match. A v1 file is refused outright (7.1): a SACL-capable build never resumes it,
    // whatever the plan's schema, since v1's done lines say nothing about SACL parts.
    public FileCheckpoint(string path, string identity, bool resume)
    {
        this.path = path;
        this.resume = resume;
        header = "permissionreset-smb checkpoint v2 " + identity;
        if (!File.Exists(path))
        {
            if (resume) throw new PlanException($"--resume: checkpoint {path} does not exist");
            return;
        }
        if (!resume) throw new PlanException($"checkpoint {path} already exists; pass --resume to continue that run, or remove it");
        using (var r = new StreamReader(path))
        {
            var first = r.ReadLine();
            if (first?.StartsWith("permissionreset-smb checkpoint v1 ", StringComparison.Ordinal) == true)
                throw new PlanException($"checkpoint {path} was written by an earlier build (checkpoint v1); a SACL-capable build never resumes a v1 checkpoint (smb/DESIGN-sacl-write.md 7.1): remove it and rerun without --resume (a fresh run re-reads everything and writes only what differs)");
            if (first != header)
                throw new PlanException($"checkpoint {path} belongs to another run (the plan, root, --root-protected, --root-sacl-protected, resolved principal table or S:AI rule differs); remove it or use another file");
            string? line;
            while ((line = r.ReadLine()) is not null)
            {
                // A torn last line (the run died mid-write) is dropped; that directory is redone.
                // A JSON string is a complete directory, a JSON object with dir its compare-time
                // SACL record; the first record for a directory wins.
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var el = doc.RootElement;
                    if (el.ValueKind == JsonValueKind.String)
                    {
                        if (el.GetString() is string rel) done.Add(rel);
                    }
                    else if (el.ValueKind == JsonValueKind.Object && TryReadRecord(el, out var dir, out var sacl))
                        compareSacl.TryAdd(dir, sacl);
                }
                catch (JsonException) { }
            }
        }
        // A torn last line has no newline; Start ends it first, so the next entry gets a line of
        // its own instead of being glued onto the fragment.
        using var f = File.OpenRead(path);
        if (f.Length > 0)
        {
            f.Seek(-1, SeekOrigin.End);
            needsNewline = f.ReadByte() != '\n';
        }
    }

    // TryReadRecord reads one {"dir": …, "sacl": [ACEs]} line, false on any malformed field; the
    // caller drops the line, as it does a torn one.
    static bool TryReadRecord(JsonElement el, out string dir, out IReadOnlyList<Ace> sacl)
    {
        dir = ""; sacl = [];
        if (!el.TryGetProperty("dir", out var d) || d.ValueKind != JsonValueKind.String || d.GetString() is not string dv
            || !el.TryGetProperty("sacl", out var sa) || sa.ValueKind != JsonValueKind.Array)
            return false;
        var aces = new List<Ace>();
        foreach (var e in sa.EnumerateArray())
        {
            // Each number is checked for kind first: TryGet* throws InvalidOperationException, not
            // JsonException, on a value that is not a number (a damaged "flags": null), and the line
            // must be dropped, not crash the load.
            if (e.ValueKind != JsonValueKind.Object
                || !e.TryGetProperty("type", out var t) || t.ValueKind != JsonValueKind.Number || !t.TryGetInt32(out int type)
                || !e.TryGetProperty("flags", out var f) || f.ValueKind != JsonValueKind.Number || !f.TryGetByte(out byte flags)
                || !e.TryGetProperty("mask", out var m) || m.ValueKind != JsonValueKind.Number || !m.TryGetUInt32(out uint mask)
                || !e.TryGetProperty("sid", out var s) || s.ValueKind != JsonValueKind.String || s.GetString() is not string sid)
                return false;
            aces.Add(new Ace(type, flags, mask, sid));
        }
        dir = dv; sacl = aces;
        return true;
    }

    // Start opens the file for writing: a new file gets its identity line (and is refused if one
    // appeared since the constructor checked), a resumed one is appended to. Done and
    // RecordCompareSacl before Start throw.
    public void Start()
    {
        lock (gate)
        {
            if (w is not null) return;
            if (resume)
            {
                w = new StreamWriter(path, append: true);
                if (needsNewline) w.WriteLine();
            }
            else
            {
                w = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write));
                w.WriteLine(header);
            }
            w.Flush();
        }
    }

    public bool IsDone(string rel) => done.Contains(rel);

    public void Done(string rel)
    {
        lock (gate)
        {
            if (w is null) throw new InvalidOperationException("checkpoint not started");
            w.WriteLine(JsonSerializer.Serialize(rel));
            w.Flush();
        }
    }

    public bool TryGetCompareSacl(string rel, out IReadOnlyList<Ace> sacl)
    {
        lock (gate) return compareSacl.TryGetValue(rel, out sacl!);
    }

    public void RecordCompareSacl(string rel, IReadOnlyList<Ace> sacl)
    {
        lock (gate)
        {
            if (w is null) throw new InvalidOperationException("checkpoint not started");
            // First wins: an earlier run's pre-write state is the truth.
            if (!compareSacl.TryAdd(rel, sacl)) return;
            w.WriteLine(JsonSerializer.Serialize(new { dir = rel, sacl }, Camel));
            // Unlike a lost done line, which costs only a rewalk, a lost record is a wrong verdict:
            // the array keeps the directory's write while a resume falls back to its fresh read and
            // can take a child that failed to follow for a pre-run freeze. So the record goes to
            // stable storage before the write it precedes, the 7.2 rule for evidence lines.
            w.Flush();
            if (w.BaseStream is FileStream fs) fs.Flush(flushToDisk: true);
        }
    }

    public void Dispose()
    {
        lock (gate) w?.Dispose();
    }
}
