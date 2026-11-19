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
    readonly StreamWriter w;
    readonly object gate = new();

    public int Loaded => done.Count;

    // Open starts a checkpoint for identity. Without resume, an existing file is refused, so a
    // stale checkpoint never skips work silently. With resume, its identity line must match.
    public FileCheckpoint(string path, string identity, bool resume)
    {
        var header = "permissionreset-smb checkpoint v1 " + identity;
        if (File.Exists(path))
        {
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
            w = new StreamWriter(path, append: true);
            return;
        }
        if (resume) throw new PlanException($"--resume: checkpoint {path} does not exist");
        w = new StreamWriter(path, append: false);
        w.WriteLine(header);
        w.Flush();
    }

    public bool IsDone(string rel) => done.Contains(rel);

    public void Done(string rel)
    {
        lock (gate)
        {
            w.WriteLine(JsonSerializer.Serialize(rel));
            w.Flush();
        }
    }

    public void Dispose()
    {
        lock (gate) w.Dispose();
    }
}
