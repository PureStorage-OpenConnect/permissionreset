using System.Collections.Concurrent;

namespace PermissionReset.Smb.Core;

// ITree is what the read-only walk needs from a file system: list one directory and read one
// object's descriptor, both by path relative to the root ("" is the root, '/' separates). The
// Windows implementation opens every handle with backup intent and never follows a reparse point.
// Failures throw; the message names the failed step.
public interface ITree
{
    IReadOnlyList<TreeEntry> List(string rel);
    byte[] Read(string rel);
}

public readonly record struct TreeEntry(string Name, bool IsDir, bool IsReparse);

// Outcome of checking one object (smb/DESIGN-write-path.md, 3.3):
//   Ok        stored DACL is the desired one;
//   Write     the object itself needs a write;
//   Follows   it differs now, but only because an ancestor will be written: once that ancestor is
//             right, the array re-derives this object's inherited part and it is right too;
//   Keep      the rule has no acl:, so the DACL is not the reset's to change;
//   Excluded, Reparse (skipped, never followed), Error.
public enum Outcome { Ok, Write, Follows, Keep, Excluded, Reparse, Error }

public sealed record CheckRecord(string Path, bool IsDir, string? Rule, Form? Form, Outcome Outcome, string? Detail);

public sealed class CheckSummary
{
    readonly ConcurrentDictionary<Outcome, long> outcomes = new();
    readonly ConcurrentDictionary<Form, long> forms = new();
    public long NotProcessed;

    public void Add(CheckRecord r)
    {
        outcomes.AddOrUpdate(r.Outcome, 1, (_, n) => n + 1);
        if (r.Form is Form f) forms.AddOrUpdate(f, 1, (_, n) => n + 1);
    }

    public long Count(Outcome o) => outcomes.GetValueOrDefault(o);
    public long Count(Form f) => forms.GetValueOrDefault(f);
}

// Checker is phase 1 of the write path: the top-down read-compare walk with no writes
// (smb/DESIGN-write-path.md, sections 2 and 3). For every object it picks the desired DACL from
// the plan and the parent's desired DACL, reads what is stored, and says whether the object is
// right, needs its own write, or will be right once an ancestor is written.
public sealed class Checker
{
    readonly Plan plan;
    readonly RuleSelector rules;
    readonly ITree tree;
    readonly Dictionary<PlanRule, List<Ace>?> want = new(ReferenceEqualityComparer.Instance);
    readonly Dictionary<PlanRule, (string? Owner, string? Group)> ownerGroup = new(ReferenceEqualityComparer.Instance);

    // resolve maps a principal the plan names without a SID (name@domain, DOMAIN\name) to its SID,
    // or null when it does not resolve. Every principal is resolved here, before any read, and an
    // unresolved one refuses the whole check.
    public Checker(Plan plan, ITree tree, Func<string, string?> resolve)
    {
        if (plan.Schema != Plan.SmbSchema)
            throw new PlanException($"check needs a schema {Plan.SmbSchema} plan (build-spec --smb-plan); this one is schema {plan.Schema}");
        this.plan = plan;
        this.tree = tree;
        rules = new RuleSelector(plan);
        var unresolved = new SortedSet<string>(StringComparer.Ordinal);
        string? Sid(string principal, string planSid)
        {
            if (planSid.Length > 0) return planSid;
            var s = resolve(principal);
            if (s is null) unresolved.Add(principal);
            return s;
        }
        foreach (var r in plan.Rules.Prepend(plan.Default))
        {
            want[r] = r.Dacl?.Select(a => new Ace(a.WindowsType, a.WindowsFlags, a.WindowsMask, Sid(a.Principal, a.Sid) ?? "")).ToList();
            ownerGroup[r] = (r.Owner.Length > 0 ? Sid(r.Owner, "") : null, r.Group.Length > 0 ? Sid(r.Group, "") : null);
        }
        if (unresolved.Count > 0)
            throw new PlanException($"these principals do not resolve to a SID on this host: {string.Join(", ", unresolved)}");
    }

    // Node is a directory waiting to be listed, with what its children need from it: its desired
    // DACL (the input to their inheritance) and whether it or an ancestor will be written.
    sealed record Node(string Rel, List<Ace> Acl, bool AncestorWrites);

    // Run walks the tree. emit is called once per object, from worker threads, under a lock.
    public CheckSummary Run(Action<CheckRecord> emit, int workers = 1)
    {
        var summary = new CheckSummary();
        var gate = new object();
        void Emit(CheckRecord r)
        {
            summary.Add(r);
            lock (gate) emit(r);
        }

        var root = Visit("", isDir: true, parent: null, Emit);
        if (root is null) return summary;

        var queue = new BlockingCollection<Node>();
        int pending = 1;
        queue.Add(root);
        void Work()
        {
            foreach (var n in queue.GetConsumingEnumerable())
            {
                try
                {
                    IReadOnlyList<TreeEntry> entries;
                    try { entries = tree.List(n.Rel); }
                    catch (Exception e)
                    {
                        Emit(new CheckRecord(n.Rel, true, null, null, Outcome.Error, $"list: {e.Message}"));
                        Interlocked.Increment(ref summary.NotProcessed);
                        continue;
                    }
                    foreach (var e in entries)
                    {
                        var rel = n.Rel.Length == 0 ? e.Name : n.Rel + "/" + e.Name;
                        if (e.IsReparse) { Emit(new CheckRecord(rel, e.IsDir, null, null, Outcome.Reparse, null)); continue; }
                        if (rules.IsExcluded(rel)) { Emit(new CheckRecord(rel, e.IsDir, null, null, Outcome.Excluded, null)); continue; }
                        var child = Visit(rel, e.IsDir, n, Emit);
                        if (child is not null)
                        {
                            Interlocked.Increment(ref pending);
                            queue.Add(child);
                        }
                    }
                }
                finally
                {
                    if (Interlocked.Decrement(ref pending) == 0) queue.CompleteAdding();
                }
            }
        }
        var threads = Enumerable.Range(0, Math.Max(1, workers)).Select(_ => Task.Run(Work)).ToArray();
        Task.WaitAll(threads);
        return summary;
    }

    // Visit checks one object and, for a directory, returns the node its children need (null when
    // it is not a directory or its children cannot be classified).
    Node? Visit(string rel, bool isDir, Node? parent, Action<CheckRecord> emit)
    {
        var sel = rules.Select(rel, isDir);
        var rule = sel.Rule!;
        Descriptor stored;
        try { stored = Descriptor.Decode(tree.Read(rel)); }
        catch (Exception e)
        {
            emit(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error, $"read: {e.Message}"));
            return null;
        }
        bool storedProtected = (stored.Control & 0x1000) != 0;
        var storedAces = (stored.Dacl?.Aces ?? []).Select(Ace.FromView).ToList();

        // What this object would inherit: from its parent's desired DACL, or for the root, what the
        // array says it inherits now (its stored ID ACEs; design 2.2).
        List<Ace> inherited;
        try
        {
            inherited = parent is null
                ? storedAces.Where(a => a is { Inherited: true }).Select(a => a!.Value).ToList()
                : Inheritance.Inherit(parent.Acl, isDir);
        }
        catch (NotSupportedException e)
        {
            emit(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error, e.Message));
            return null;
        }
        bool ancestorWrites = parent?.AncestorWrites ?? false;

        var wanted = want[rule];
        if (wanted is null)
        {
            // No acl: here. The DACL is left alone, but its children still inherit from it: from
            // its stored ACEs, with the inherited part re-derived if it is unprotected (F3).
            emit(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Keep, null));
            if (!isDir) return null;
            if (storedAces.Any(a => a is null))
            {
                emit(new CheckRecord(rel, true, rule.Label, null, Outcome.Error, "its DACL holds an ACE type a reset does not model, so its children cannot be classified"));
                return null;
            }
            var acl = storedAces.Select(a => a!.Value).ToList();
            if (!storedProtected) acl = acl.Where(a => !a.Inherited).Concat(inherited).ToList();
            return new Node(rel, acl, ancestorWrites);
        }

        var desired = Desired.Classify(wanted, inherited);
        var diff = desired.Matches(stored.Dacl, storedProtected);
        diff ??= OwnerGroupDiff(rule, stored);
        Outcome outcome;
        if (diff is null) outcome = Outcome.Ok;
        else if (ancestorWrites && Follows(desired, storedAces, storedProtected) && OwnerGroupDiff(rule, stored) is null) outcome = Outcome.Follows;
        else
        {
            outcome = Outcome.Write;
            if (desired.Form != Form.Protected && Follows(desired, storedAces, storedProtected))
                diff += "; its inherited part does not follow its parent (a frozen copy)";
        }
        emit(new CheckRecord(rel, isDir, rule.Label, desired.Form, outcome, diff));
        return isDir ? new Node(rel, desired.Aces.ToList(), ancestorWrites || outcome == Outcome.Write) : null;
    }

    // Follows reports whether the stored DACL has the shape that the array re-derives when an
    // ancestor changes: unprotected, its explicit part exactly the desired explicit part, and
    // everything after it inherited.
    static bool Follows(Desired d, List<Ace?> stored, bool storedProtected)
    {
        if (storedProtected || d.Protected || stored.Any(a => a is null)) return false;
        var explicitWant = d.Aces.Where(a => !a.Inherited).ToList();
        if (stored.Count < explicitWant.Count) return false;
        for (int i = 0; i < explicitWant.Count; i++)
            if (stored[i]!.Value != explicitWant[i]) return false;
        return stored.Skip(explicitWant.Count).All(a => a!.Value.Inherited);
    }

    string? OwnerGroupDiff(PlanRule rule, Descriptor stored)
    {
        var (owner, group) = ownerGroup[rule];
        if (owner is not null && owner != stored.Owner) return $"owner is {stored.Owner}, want {owner}";
        if (group is not null && group != stored.Group) return $"group is {stored.Group}, want {group}";
        return null;
    }
}
