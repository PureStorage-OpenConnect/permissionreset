using System.Text.Json;

namespace PermissionReset.Smb.Core;

// FileCheckpoint is apply's directory-level checkpoint (smb/DESIGN-write-path.md, 3.4): a text
// file whose first line names the run it belongs to (plan digest, root, root form) and whose other
// lines are complete directories, one JSON string each, appended and flushed as they finish.
// Rewalking a complete directory is safe, since the compare finds it right and writes nothing, so
// a lost last line costs time, not correctness.
public sealed class FileCheckpoint : ICheckpoint, IDisposable
{
    readonly HashSet<string> done = new(StringComparer.Ordinal);
    readonly string path, header;
    readonly bool resume;
    readonly object gate = new();
    bool needsNewline;
    StreamWriter? w;

    public int Loaded => done.Count;

    // The constructor checks the file against identity and, with resume, loads it, but writes
    // nothing: Start does, once the caller is committed to the run (apply starts it after the
    // preflight passes), so a refused run leaves no checkpoint behind. Without resume, an existing
    // file is refused, so a stale checkpoint never skips work silently. With resume, its identity
    // line must match.
    public FileCheckpoint(string path, string identity, bool resume)
    {
        this.path = path;
        this.resume = resume;
        header = "permissionreset-smb checkpoint v1 " + identity;
        if (!File.Exists(path))
        {
            if (resume) throw new PlanException($"--resume: checkpoint {path} does not exist");
            return;
        }
        if (!resume) throw new PlanException($"checkpoint {path} already exists; pass --resume to continue that run, or remove it");
        using (var r = new StreamReader(path))
        {
            var first = r.ReadLine();
            if (first != header)
                throw new PlanException($"checkpoint {path} belongs to another run (plan, root or --root-protected differ); remove it or use another file");
            string? line;
            while ((line = r.ReadLine()) is not null)
            {
                // A torn last line (the run died mid-write) is dropped; that directory is redone.
                try { if (JsonSerializer.Deserialize<string>(line) is string rel) done.Add(rel); }
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

    // Start opens the file for writing: a new file gets its identity line (and is refused if one
    // appeared since the constructor checked), a resumed one is appended to. Done before Start
    // throws.
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

    public void Dispose()
    {
        lock (gate) w?.Dispose();
    }
}
