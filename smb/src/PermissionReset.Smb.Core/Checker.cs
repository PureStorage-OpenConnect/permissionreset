using System.Collections.Concurrent;

namespace PermissionReset.Smb.Core;

// ITree is what the read-only walk needs from a file system: list one directory and read one
// object's descriptor, both by path relative to the root ("" is the root, '/' separates). The
// Windows implementation opens every handle with backup intent and never follows a reparse point.
// Failures throw; the message names the failed step.
public interface ITree
{
    IReadOnlyList<TreeEntry> List(string rel);
    TreeObject Read(string rel);
}

public readonly record struct TreeEntry(string Name, bool IsDir, bool IsReparse);

// TreeObject is one Read's result: the raw descriptor and the attributes of the object the open
// handle actually refers to. The attributes matter because the object may have changed between
// the listing and the open (smb/DESIGN-write-path.md, 5.3): a file that became a directory would
// otherwise leave a new subtree unwalked and still be reported on.
public readonly record struct TreeObject(byte[] Descriptor, bool IsDir, bool IsReparse);

// Outcome of checking one object (smb/DESIGN-write-path.md, 3.3):
//   Ok        stored DACL is the desired one;
//   Write     the object itself needs a write;
//   Follows   it differs now, but only because an ancestor will be written: once that ancestor is
//             right, the array re-derives this object's inherited part and it is right too;
//   Keep      the rule has no acl:, so the DACL is not the reset's to change (a named owner or
//             group that differs is still a Write);
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
    // unresolved one refuses the whole check. rootName is the root's own base name
    // (RuleSelector.RootName of the ROOT argument), which the rules match the root by.
    public Checker(Plan plan, ITree tree, string rootName, Func<string, string?> resolve)
    {
        if (plan.Schema != Plan.SmbSchema)
            throw new PlanException($"check needs a schema {Plan.SmbSchema} plan (build-spec --smb-plan); this one is schema {plan.Schema}");
        this.plan = plan;
        this.tree = tree;
        rules = new RuleSelector(plan, rootName);
        var unresolved = new SortedSet<string>(StringComparer.Ordinal);
        string? Sid(string principal, string planSid)
        {
            if (planSid.Length > 0) return planSid;
            // A lookup that throws (a domain or trust failure, not just an unknown name) is an
            // unresolved principal too: refused here, named in the message below, before any read.
            string? s;
            try { s = resolve(principal); }
            catch { s = null; }
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
    // DACL (the input to their inheritance after the run's writes), its stored DACL (the input to
    // their dynamic-tracking evidence), and whether it or an ancestor will be written.
    sealed record Node(string Rel, List<Ace> Acl, List<Ace> StoredAcl, bool AncestorWrites);

    // Run walks the tree. emit is called once per object, from worker threads, under a lock.
    //
    // A directory whose subtree is not walked (it could not be read, listed or classified) counts
    // in NotProcessed. Anything that escapes a worker (emit threw, or a bug) stops the whole run:
    // the other workers stop taking directories, and Run throws CheckFaultException once they have
    // all returned, rather than finish a walk whose output is already incomplete.
    public CheckSummary Run(Action<CheckRecord> emit, int workers = 1)
    {
        var summary = new CheckSummary();
        var gate = new object();
        void Emit(CheckRecord r)
        {
            summary.Add(r);
            lock (gate) emit(r);
        }

        Node? root;
        try { root = Visit("", isDir: true, parent: null, Emit, summary); }
        catch (Exception e) { throw new CheckFaultException(e); }
        if (root is null) return summary;

        var queue = new BlockingCollection<Node>();
        using var stop = new CancellationTokenSource();
        Exception? fault = null;
        int pending = 1;
        queue.Add(root);
        void Work()
        {
            try
            {
                foreach (var n in queue.GetConsumingEnumerable(stop.Token))
                {
                    try
                    {
                        IReadOnlyList<TreeEntry> entries;
                        try { entries = tree.List(n.Rel); }
                        catch (Exception e)
                        {
                            Interlocked.Increment(ref summary.NotProcessed);
                            Emit(new CheckRecord(n.Rel, true, null, null, Outcome.Error, $"list: {e.Message}"));
                            continue;
                        }
                        foreach (var e in entries)
                        {
                            if (stop.IsCancellationRequested) break;
                            var rel = n.Rel.Length == 0 ? e.Name : n.Rel + "/" + e.Name;
                            if (e.IsReparse) { Emit(new CheckRecord(rel, e.IsDir, null, null, Outcome.Reparse, null)); continue; }
                            if (rules.IsExcluded(rel)) { Emit(new CheckRecord(rel, e.IsDir, null, null, Outcome.Excluded, null)); continue; }
                            var child = Visit(rel, e.IsDir, n, Emit, summary);
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
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (Exception e)
            {
                Interlocked.CompareExchange(ref fault, e, null);
                stop.Cancel();
            }
        }
        var threads = Enumerable.Range(0, Math.Max(1, workers)).Select(_ => Task.Run(Work)).ToArray();
        Task.WaitAll(threads);
        if (fault is not null) throw new CheckFaultException(fault);
        return summary;
    }

    // Visit checks one object and, for a directory, returns the node its children need (null when
    // it is not a directory or its children cannot be classified; a directory dropped that way
    // counts in summary.NotProcessed, since its subtree is not walked).
    Node? Visit(string rel, bool isDir, Node? parent, Action<CheckRecord> emit, CheckSummary summary)
    {
        var sel = rules.Select(rel, isDir);
        var rule = sel.Rule!;
        Node? Dropped(string detail)
        {
            if (isDir) Interlocked.Increment(ref summary.NotProcessed);
            emit(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error, detail));
            return null;
        }
        TreeObject read;
        Descriptor stored;
        try { read = tree.Read(rel); stored = Descriptor.Decode(read.Descriptor); }
        catch (Exception e) { return Dropped($"read: {e.Message}"); }
        // The open handle says what the object is now. An object whose type changed between the
        // listing and the open, or that became a reparse point, is skipped and counted (design
        // 5.3): what listed as a file may be a new directory whose subtree was never walked.
        if (read.IsReparse || read.IsDir != isDir)
        {
            var became = read.IsReparse ? "a reparse point" : read.IsDir ? "a directory" : "a file";
            if (read.IsDir) Interlocked.Increment(ref summary.NotProcessed);
            return Dropped($"its type changed between listing and open: it is now {became}; it was not checked");
        }
        bool storedProtected = (stored.Control & 0x1000) != 0;
        var storedAces = (stored.Dacl?.Aces ?? []).Select(Ace.FromView).ToList();
        var storedAcl = storedAces.Where(a => a is not null).Select(a => a!.Value).ToList();

        // What the stored parent currently passes down (the dynamic-tracking evidence of F2), and
        // what this object would inherit once the run's parents are written: from its parent's
        // desired DACL, or for the root, what the array says it inherits now (its stored ID ACEs;
        // design 2.2).
        List<Ace>? parentPropagates = null;
        List<Ace> inherited;
        try
        {
            if (parent is not null) parentPropagates = Inheritance.Inherit(parent.StoredAcl, isDir);
            inherited = parent is null
                ? storedAces.Where(a => a is { Inherited: true }).Select(a => a!.Value).ToList()
                : Inheritance.Inherit(parent.Acl, isDir);
        }
        catch (NotSupportedException e) { return Dropped(e.Message); }
        bool ancestorWrites = parent?.AncestorWrites ?? false;

        var og = OwnerGroupDiff(rule, stored);
        var wanted = want[rule];
        if (wanted is null)
        {
            // No acl: here. The DACL is left alone, but a named owner or group is still the
            // reset's to check, independently of the DACL (a rule can name owner:/group: alone).
            emit(new CheckRecord(rel, isDir, rule.Label, null, og is null ? Outcome.Keep : Outcome.Write, og));
            if (!isDir) return null;
            // An absent DACL (everyone full control) is not an empty one: there is nothing for the
            // children to inherit from that a reset models.
            if (stored.Dacl is null) return Dropped("its DACL is absent, so its children cannot be classified");
            if (storedAces.Any(a => a is null))
                return Dropped("its DACL holds an ACE type a reset does not model, so its children cannot be classified");
            // The children inherit what is actually stored. The inherited part is substituted for
            // the re-derived one only when this directory provably tracks its parent and an
            // ancestor will be written (F2, F3); otherwise nothing above changes it.
            var acl = storedAces.Select(a => a!.Value).ToList();
            if (!storedProtected && ancestorWrites && Tracks(acl, parentPropagates))
                acl = acl.Where(a => !a.Inherited).Concat(inherited).ToList();
            return new Node(rel, acl, storedAcl, ancestorWrites);
        }

        var desired = Desired.Classify(wanted, inherited);
        var daclDiff = desired.Matches(stored.Dacl, storedProtected);
        var diff = daclDiff ?? og;
        // An absent DACL never follows: the array has no inherited part to re-derive.
        bool follows = stored.Dacl is not null && Follows(desired, storedAces, storedProtected, parentPropagates);
        Outcome outcome;
        if (diff is null) outcome = Outcome.Ok;
        else if (ancestorWrites && follows && og is null) outcome = Outcome.Follows;
        else
        {
            outcome = Outcome.Write;
            // The frozen-copy note explains a DACL difference; it says nothing about an owner or
            // group difference on a DACL that matched.
            if (daclDiff is not null && desired.Form != Form.Protected && TrackableShape(desired, storedAces, storedProtected))
                diff += "; its inherited part does not follow its parent (a frozen copy)";
        }
        emit(new CheckRecord(rel, isDir, rule.Label, desired.Form, outcome, diff));
        return isDir ? new Node(rel, desired.Aces.ToList(), storedAcl, ancestorWrites || outcome == Outcome.Write) : null;
    }

    // TrackableShape reports whether the stored DACL has the shape the array re-derives when a
    // parent changes: unprotected, its explicit part exactly the desired explicit part, and a
    // non-empty remainder that is all inherited. An explicit-only remainder is empty, and Q-EXP
    // found that explicit-only objects do not pick up parent changes, so it does not count.
    static bool TrackableShape(Desired d, List<Ace?> stored, bool storedProtected)
    {
        if (storedProtected || d.Protected || stored.Any(a => a is null)) return false;
        var explicitWant = d.Aces.Where(a => !a.Inherited).ToList();
        if (stored.Count <= explicitWant.Count) return false;
        for (int i = 0; i < explicitWant.Count; i++)
            if (stored[i]!.Value != explicitWant[i]) return false;
        return stored.Skip(explicitWant.Count).All(a => a!.Value.Inherited);
    }

    // Follows is TrackableShape plus the evidence the object is dynamically tracking its parent
    // (F2): the inherited remainder equals what the stored parent currently passes down. A frozen
    // copy looks inherited but no longer follows the parent, so it predicts a write of its own.
    static bool Follows(Desired d, List<Ace?> stored, bool storedProtected, List<Ace>? parentPropagates)
    {
        if (parentPropagates is not { Count: > 0 } || !TrackableShape(d, stored, storedProtected)) return false;
        var explicitCount = d.Aces.Count(a => !a.Inherited);
        return stored.Skip(explicitCount).Select(a => a!.Value).SequenceEqual(parentPropagates);
    }

    // Tracks is the same evidence for a directory whose own DACL is kept: its stored inherited
    // part equals what its stored parent currently passes down.
    static bool Tracks(List<Ace> acl, List<Ace>? parentPropagates)
    {
        if (parentPropagates is null || parentPropagates.Count == 0) return false;
        var inheritedPart = acl.Where(a => a.Inherited).ToList();
        return inheritedPart.Count > 0 && inheritedPart.SequenceEqual(parentPropagates);
    }

    string? OwnerGroupDiff(PlanRule rule, Descriptor stored)
    {
        var (owner, group) = ownerGroup[rule];
        if (owner is not null && owner != stored.Owner) return $"owner is {stored.Owner}, want {owner}";
        if (group is not null && group != stored.Group) return $"group is {stored.Group}, want {group}";
        return null;
    }
}

// CheckFaultException is what Checker.Run throws when something escapes the walk itself (the emit
// callback threw, or a bug): the run was stopped and its records are incomplete.
public sealed class CheckFaultException(Exception inner)
    : Exception($"check stopped: {inner.Message}", inner);
