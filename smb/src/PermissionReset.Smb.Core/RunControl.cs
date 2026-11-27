using System.Collections.Concurrent;

namespace PermissionReset.Smb.Core;

// SubtreeCounts is what one completed subtree contributes to the run's counts
// (docs/plan-smb-run-control.md 4.4): the directory's own record plus every record below it. A
// parent's counts aggregate those of its completed children, so the root's counts are the run's.
public sealed class SubtreeCounts
{
    public long Objects { get; private set; }
    readonly Dictionary<Outcome, long> outcomes = new();
    readonly Dictionary<Form, long> forms = new();
    readonly Dictionary<Form, long> saclForms = new();

    public IReadOnlyDictionary<Outcome, long> Outcomes => outcomes;
    public IReadOnlyDictionary<Form, long> Forms => forms;
    public IReadOnlyDictionary<Form, long> SaclForms => saclForms;

    public void Add(CheckRecord r)
    {
        Objects++;
        AddOutcome(r.Outcome, 1);
        if (r.Form is Form f) AddForm(f, 1);
        if (r.SaclForm is Form sf) AddSaclForm(sf, 1);
    }

    public void AddOutcome(Outcome o, long n) => outcomes[o] = outcomes.GetValueOrDefault(o) + n;
    public void AddForm(Form f, long n) => forms[f] = forms.GetValueOrDefault(f) + n;
    public void AddSaclForm(Form f, long n) => saclForms[f] = saclForms.GetValueOrDefault(f) + n;
    // AddObjects sets the subtree object count when counts come from a checkpoint line (plan 4.4),
    // which carries its own "objects" rather than a record at a time.
    public void AddObjects(long n) => Objects += n;

    public void Add(SubtreeCounts child)
    {
        Objects += child.Objects;
        foreach (var (k, v) in child.outcomes) outcomes[k] = outcomes.GetValueOrDefault(k) + v;
        foreach (var (k, v) in child.forms) forms[k] = forms.GetValueOrDefault(k) + v;
        foreach (var (k, v) in child.saclForms) saclForms[k] = saclForms.GetValueOrDefault(k) + v;
    }
}

// RunHooks is the walk's run-control surface (docs/plan-smb-run-control.md, sections 4.4 and 6).
// The CLI fills IsComplete with its loaded completed-subtree set (a completed subtree is pruned on
// resume: not visited, not queued, its counts already seeded) and SubtreeComplete with the writer
// of checkpoint.jsonl lines. The counters and ActiveDirs are what status.json's progress fields
// (4.2) read; Summary is the run's live counts for the same. All of this is display and resume
// state; the walk's records and exit codes are unchanged without it.
public sealed class RunHooks
{
    public Func<string, bool>? IsComplete;
    // PrunedCounts gives a pruned subtree's loaded counts, so its parent's checkpoint line keeps
    // covering the whole run (a resumed segment re-checks only what it visits).
    public Func<string, SubtreeCounts?>? PrunedCounts;
    public Action<string, SubtreeCounts>? SubtreeComplete;
    public ConcurrentDictionary<string, byte> ActiveDirs { get; } = new(StringComparer.Ordinal);
    public long DirsQueued;     // Interlocked: directories queued this segment, the root counted
    public long DirsDone;       // Interlocked: directories whose entries were all visited, pruned subtrees counted
    public CheckSummary? Summary;   // set by Run, so a status reader sees live counts (4.2)
    // Seed runs in Run before the walk: a resume's loaded subtree counts enter the summary there,
    // so the run's counts and every status.json span every segment.
    public Action<CheckSummary>? Seed;
}
