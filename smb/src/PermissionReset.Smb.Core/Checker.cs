using System.Collections.Concurrent;

namespace PermissionReset.Smb.Core;

// ITree is what the walk needs from a file system: list one directory and read one object's
// descriptor, both by path relative to the root ("" is the root, '/' separates). The Windows
// implementation opens every handle with backup intent and never follows a reparse point.
// Failures throw; the message names the failed step.
public interface ITree
{
    IReadOnlyList<TreeEntry> List(string rel);

    // Read returns the self-relative descriptor: owner, group and DACL, and the SACL when withSacl.
    byte[] Read(string rel, bool withSacl);
}

// IWritableTree adds what apply needs: a security write that names its SECURITY_INFORMATION
// parts, and the create/delete calls the disposable preflight probe uses (design 4).
public interface IWritableTree : ITree
{
    void Write(string rel, uint securityInformation, byte[] descriptor);
    void CreateDirectory(string rel);
    void CreateFile(string rel);
    void Delete(string rel, bool isDir);
}

// ICheckpoint records directories that are complete: the directory and every file in it are right
// (design 3.4). On resume, a complete directory is still read and listed, so its subdirectories
// are found and its children get its desired DACL, but its files are not read again.
public interface ICheckpoint
{
    bool IsDone(string rel);
    void Done(string rel);
}

public readonly record struct TreeEntry(string Name, bool IsDir, bool IsReparse);

// Outcome of one object (smb/DESIGN-write-path.md, 3.3):
//   Ok        stored DACL (and owner/group, when named) is the desired one;
//   Write     dry run: the object itself needs a write;
//   Follows   dry run: it differs now, but only because an ancestor will be written: once that
//             ancestor is right, the array re-derives this object's inherited part;
//   Written   apply: the object was written and read back right (G2);
//   Stopped   apply: it needed a write, but the run had stopped, so it was not written;
//   Keep      the rule has no acl:, so the DACL is not the reset's to change;
//   Excluded, Reparse (skipped, never followed), Error.
public enum Outcome { Ok, Write, Follows, Written, Stopped, Keep, Excluded, Reparse, Error }

// Parts names what a write set ("dacl", "dacl,owner"); Before and After are the raw descriptors,
// base64, around a write. Only Written records carry them.
public sealed record CheckRecord(string Path, bool IsDir, string? Rule, Form? Form, Outcome Outcome, string? Detail,
    string? Parts = null, string? Before = null, string? After = null);

public sealed class CheckSummary
{
    readonly ConcurrentDictionary<Outcome, long> outcomes = new();
    readonly ConcurrentDictionary<Form, long> forms = new();
    public long NotProcessed;   // directories whose children were not reached
    public long Resumed;        // files skipped because the checkpoint had their directory complete
    public string? Stop;        // why an apply stopped (G1, G2), or null

    public void Add(CheckRecord r)
    {
        outcomes.AddOrUpdate(r.Outcome, 1, (_, n) => n + 1);
        if (r.Form is Form f) forms.AddOrUpdate(f, 1, (_, n) => n + 1);
    }

    public long Count(Outcome o) => outcomes.GetValueOrDefault(o);
    public long Count(Form f) => forms.GetValueOrDefault(f);

    // Complete is true when every object was reached, none failed and nothing stopped the run.
    public bool Complete => Stop is null && NotProcessed == 0 && Count(Outcome.Error) == 0 && Count(Outcome.Stopped) == 0;
}

// Options for a walk. Apply needs an IWritableTree. RootProtected forces the root's form to
// Protected (design 2.2: a frozen ID copy on the root cannot be detected).
public sealed record WalkOptions(bool Apply = false, bool RootProtected = false);

// Checker is the top-down walk of the write path (smb/DESIGN-write-path.md, sections 2, 3 and 5).
// For every object it picks the desired DACL from the plan and the parent's desired DACL, reads
// what is stored, and says whether the object is right. A dry run (check) stops there. Apply
// (phase 2) writes each object that differs, the DACL only, plus owner and group when the rule
// names them, and reads it back; a directory is finished before its children are read, so each
// child is compared with a parent that is already right.
public sealed class Checker
{
    readonly Plan plan;
    readonly RuleSelector rules;
    readonly ITree tree;
    readonly WalkOptions opt;
    readonly Dictionary<PlanRule, List<Ace>?> want = new(ReferenceEqualityComparer.Instance);
    readonly Dictionary<PlanRule, (string? Owner, string? Group)> ownerGroup = new(ReferenceEqualityComparer.Instance);

    // Principals is every name the plan gives without a SID, with the SID it resolved to on this
    // host (design 2.3: printed and recorded in the evidence).
    public IReadOnlyDictionary<string, string> Principals { get; }

    // SetsOwnerOrGroup is true when any rule names an owner or group, which apply writes with
    // SeRestorePrivilege (design 4).
    public bool SetsOwnerOrGroup { get; }

    // resolve maps a principal the plan names without a SID (name@domain, DOMAIN\name) to its SID,
    // or null when it does not resolve. Every principal is resolved here, before any read, and an
    // unresolved one refuses the whole walk.
    public Checker(Plan plan, ITree tree, Func<string, string?> resolve, WalkOptions? options = null)
    {
        if (plan.Schema != Plan.SmbSchema)
            throw new PlanException($"check needs a schema {Plan.SmbSchema} plan (build-spec --smb-plan); this one is schema {plan.Schema}");
        opt = options ?? new WalkOptions();
        if (opt.Apply && tree is not IWritableTree)
            throw new ArgumentException("apply needs a writable tree", nameof(tree));
        this.plan = plan;
        this.tree = tree;
        rules = new RuleSelector(plan);
        var unresolved = new SortedSet<string>(StringComparer.Ordinal);
        var resolved = new SortedDictionary<string, string>(StringComparer.Ordinal);
        string? Sid(string principal, string planSid)
        {
            if (planSid.Length > 0) return planSid;
            if (resolved.TryGetValue(principal, out var known)) return known;
            var s = resolve(principal);
            if (s is null) unresolved.Add(principal);
            else resolved[principal] = s;
            return s;
        }
        foreach (var r in plan.Rules.Prepend(plan.Default))
        {
            want[r] = r.Dacl?.Select(a => new Ace(a.WindowsType, a.WindowsFlags, a.WindowsMask, Sid(a.Principal, a.Sid) ?? "")).ToList();
            ownerGroup[r] = (r.Owner.Length > 0 ? Sid(r.Owner, "") : null, r.Group.Length > 0 ? Sid(r.Group, "") : null);
            SetsOwnerOrGroup |= r.Owner.Length > 0 || r.Group.Length > 0;
        }
        if (unresolved.Count > 0)
            throw new PlanException($"these principals do not resolve to a SID on this host: {string.Join(", ", unresolved)}");
        Principals = resolved;
    }

    // Node is a directory waiting to be listed, with what its children need from it: its desired
    // DACL (the input to their inheritance) and, in a dry run, whether it or an ancestor would be
    // written.
    sealed record Node(string Rel, List<Ace> Acl, bool AncestorWrites);

    // stop is set once, by the first G1 or G2 failure; after it no new write starts and no new
    // directory is listed. A write already past its check finishes and is read back.
    string? stop;
    readonly object stopGate = new();

    bool Stopped => Volatile.Read(ref stop) is not null;

    void Stop(CheckSummary s, string why)
    {
        lock (stopGate)
        {
            if (stop is not null) return;
            stop = why;
            s.Stop = why;
        }
    }

    // Run walks the tree. emit is called once per object, from worker threads, under a lock.
    // checkpoint is used only by apply. Nothing thrown inside the walk escapes Run: a record or
    // checkpoint line that cannot be written (a full evidence volume, a closed stdout), or any
    // unexpected failure, stops the run the way a guard does, so the caller still gets a summary
    // and can close its evidence with the reason.
    public CheckSummary Run(Action<CheckRecord> emit, int workers = 1, ICheckpoint? checkpoint = null)
    {
        var summary = new CheckSummary();
        var gate = new object();
        void Emit(CheckRecord r)
        {
            summary.Add(r);
            try { lock (gate) emit(r); }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                Stop(summary, $"could not record {Show(r.Path)} ({r.Outcome.ToString().ToLowerInvariant()}): {e.Message}. No further writes were started.");
            }
        }
        void Unexpected(string rel, Exception e)
        {
            var why = $"{Show(rel)}: unexpected failure: {e.GetType().Name}: {e.Message}. No further writes were started.";
            Stop(summary, why);
            Emit(new CheckRecord(rel, true, null, null, Outcome.Error, why));
            Interlocked.Increment(ref summary.NotProcessed);
        }

        Node? root;
        try { root = Visit("", isDir: true, parent: null, Emit, summary); }
        catch (Exception e) when (e is not OutOfMemoryException) { Unexpected("", e); return summary; }
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
                    if (Stopped) { Interlocked.Increment(ref summary.NotProcessed); continue; }
                    IReadOnlyList<TreeEntry> entries;
                    try { entries = tree.List(n.Rel); }
                    catch (Exception e)
                    {
                        Emit(new CheckRecord(n.Rel, true, null, null, Outcome.Error, $"list: {e.Message}"));
                        Interlocked.Increment(ref summary.NotProcessed);
                        continue;
                    }
                    bool resumed = opt.Apply && checkpoint?.IsDone(n.Rel) == true;
                    bool filesRight = true;
                    foreach (var e in entries)
                    {
                        if (Stopped) { filesRight = false; Interlocked.Increment(ref summary.NotProcessed); break; }
                        var rel = n.Rel.Length == 0 ? e.Name : n.Rel + "/" + e.Name;
                        if (e.IsReparse) { Emit(new CheckRecord(rel, e.IsDir, null, null, Outcome.Reparse, null)); continue; }
                        if (rules.IsExcluded(rel)) { Emit(new CheckRecord(rel, e.IsDir, null, null, Outcome.Excluded, null)); continue; }
                        if (resumed && !e.IsDir) { Interlocked.Increment(ref summary.Resumed); continue; }
                        var child = Visit(rel, e.IsDir, n, Emit, summary, ok => { if (!e.IsDir && !ok) filesRight = false; });
                        if (child is not null)
                        {
                            Interlocked.Increment(ref pending);
                            queue.Add(child);
                        }
                    }
                    if (opt.Apply && filesRight && !resumed && !Stopped)
                    {
                        try { checkpoint?.Done(n.Rel); }
                        catch (Exception e) when (e is not OutOfMemoryException)
                        {
                            Stop(summary, $"could not record {Show(n.Rel)} as complete in the checkpoint: {e.Message}. No further writes were started.");
                        }
                    }
                }
                catch (Exception e) when (e is not OutOfMemoryException) { Unexpected(n.Rel, e); }
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

    // RootAcl is the DACL the root's children will inherit from once the root is right, from a
    // DACL-only read: its desired DACL (its rule, the ID ACEs it stores now, design 2.2, and
    // --root-protected), or its stored one when its rule has no acl:. The preflight probe uses it
    // before anything in the tree is written or has its SACL read.
    public List<Ace> RootAcl()
    {
        var stored = Descriptor.Decode(tree.Read("", withSacl: false));
        var wanted = want[rules.Select("", true).Rule!];
        if (wanted is not null) return DesiredFor(wanted, StoredInherited(stored), isRoot: true).Aces.ToList();
        var aces = (stored.Dacl?.Aces ?? []).Select(Ace.FromView).ToList();
        if (aces.Any(a => a is null)) throw new NotSupportedException("the root's DACL holds an ACE type a reset does not model");
        return aces.Select(a => a!.Value).ToList();
    }

    Desired DesiredFor(List<Ace> wanted, List<Ace> inherited, bool isRoot) =>
        isRoot && opt.RootProtected ? new Desired(Form.Protected, wanted.ToList(), true) : Desired.Classify(wanted, inherited);

    static List<Ace> StoredInherited(Descriptor d) =>
        (d.Dacl?.Aces ?? []).Select(Ace.FromView).Where(a => a is { Inherited: true }).Select(a => a!.Value).ToList();

    static bool IsProtected(Descriptor d) => (d.Control & Control.DaclProtected) != 0;

    // Visit handles one object and, for a directory, returns the node its children need (null when
    // it is not a directory or its children cannot be reached). done(ok) reports whether the object
    // ended right, for the checkpoint.
    Node? Visit(string rel, bool isDir, Node? parent, Action<CheckRecord> emit, CheckSummary summary, Action<bool>? done = null)
    {
        var sel = rules.Select(rel, isDir);
        var rule = sel.Rule!;
        Node? Fail(CheckRecord r)
        {
            emit(r);
            done?.Invoke(false);
            if (isDir) Interlocked.Increment(ref summary.NotProcessed);
            return null;
        }

        Descriptor stored;
        try { stored = Descriptor.Decode(tree.Read(rel, withSacl: opt.Apply)); }
        catch (Exception e)
        {
            return Fail(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error, $"read: {e.Message}"));
        }
        bool storedProtected = IsProtected(stored);
        var storedAces = (stored.Dacl?.Aces ?? []).Select(Ace.FromView).ToList();

        // What this object would inherit: from its parent's desired DACL, or for the root, what the
        // array says it inherits now (its stored ID ACEs; design 2.2).
        List<Ace> inherited;
        try
        {
            inherited = parent is null ? StoredInherited(stored) : Inheritance.Inherit(parent.Acl, isDir);
        }
        catch (NotSupportedException e)
        {
            return Fail(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error, e.Message));
        }
        bool ancestorWrites = parent?.AncestorWrites ?? false;

        var wanted = want[rule];
        if (wanted is null)
        {
            // No acl: here. The DACL is left alone, but its children still inherit from it: from
            // its stored ACEs, with the inherited part re-derived if it is unprotected (F3).
            emit(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Keep, null));
            done?.Invoke(true);
            if (!isDir) return null;
            if (storedAces.Any(a => a is null))
                return Fail(new CheckRecord(rel, true, rule.Label, null, Outcome.Error, "its DACL holds an ACE type a reset does not model, so its children cannot be classified"));
            var acl = storedAces.Select(a => a!.Value).ToList();
            if (!storedProtected) acl = acl.Where(a => !a.Inherited).Concat(inherited).ToList();
            return new Node(rel, acl, ancestorWrites);
        }

        var desired = DesiredFor(wanted, inherited, parent is null);
        var daclDiff = desired.Matches(stored.Dacl, storedProtected);
        var ogDiff = OwnerGroupDiff(rule, stored);
        var diff = daclDiff ?? ogDiff;
        bool follows = Follows(desired, storedAces, storedProtected);
        Outcome outcome;
        string? parts = null, before = null, after = null;
        if (diff is null) outcome = Outcome.Ok;
        else if (!opt.Apply)
        {
            if (ancestorWrites && follows && ogDiff is null) outcome = Outcome.Follows;
            else
            {
                outcome = Outcome.Write;
                if (daclDiff is not null && desired.Form != Form.Protected && follows)
                    diff += "; its inherited part does not follow its parent (a frozen copy)";
            }
        }
        else
        {
            // Apply. The parent is already right (written and read back, or found right), so an
            // object whose stored DACL has the shape the array keeps in step with its parent, yet
            // whose inherited part differs from what this run computes, means Inheritance.Inherit
            // disagrees with the array or the parent is not what the run thinks. Writing it would
            // freeze it with no visible sign (F2). G1 (design 5.1): stop, no override.
            if (daclDiff is not null && desired.Form != Form.Protected && follows)
            {
                var why = $"G1: {Show(rel)}: its inherited part is not what its parent passes down ({daclDiff}); " +
                    "either the inheritance function disagrees with the array or this object holds a frozen copy. No further writes were started.";
                Stop(summary, why);
                return Fail(new CheckRecord(rel, isDir, rule.Label, desired.Form, Outcome.Error, why));
            }
            if (Stopped)
                return Fail(new CheckRecord(rel, isDir, rule.Label, desired.Form, Outcome.Stopped, $"not written, the run stopped: {diff}"));

            var w = Write(rel, rule, desired, stored, daclDiff is not null);
            if (w.Error is not null)
            {
                if (w.Guard) Stop(summary, w.Error);
                return Fail(new CheckRecord(rel, isDir, rule.Label, desired.Form, Outcome.Error, w.Error, w.Parts, stored.Raw, w.After));
            }
            outcome = Outcome.Written;
            (parts, before, after) = (w.Parts, stored.Raw, w.After);
        }
        emit(new CheckRecord(rel, isDir, rule.Label, desired.Form, outcome, diff, parts, before, after));
        done?.Invoke(outcome is Outcome.Ok or Outcome.Written);
        return isDir ? new Node(rel, desired.Aces.ToList(), !opt.Apply && (ancestorWrites || outcome == Outcome.Write)) : null;
    }

    static string Show(string rel) => rel.Length == 0 ? "the root" : rel;

    readonly record struct WriteResult(string? Parts, string? After, string? Error, bool Guard);

    // Write sets what differs, then reads the object back raw (G2, design 5.2). The DACL is written
    // with DACL_SECURITY_INFORMATION and its protection stated both in the control word and as
    // (UN)PROTECTED_DACL_SECURITY_INFORMATION; the stored DaclAutoInherited bit is carried over, so
    // only the ACEs and P change. Owner and group go in the same call when the rule names them and
    // they differ. G2 then checks the written parts are what was wanted and every other part (the
    // other of owner/group, the SACL, both AI bits, S:P) is what it was before.
    WriteResult Write(string rel, PlanRule rule, Desired desired, Descriptor before, bool dacl)
    {
        var (wantOwner, wantGroup) = ownerGroup[rule];
        bool owner = wantOwner is not null && wantOwner != before.Owner;
        bool group = wantGroup is not null && wantGroup != before.Group;
        uint info = 0;
        var parts = new List<string>();
        if (dacl)
        {
            info |= SecurityInformation.Dacl | (desired.Protected ? SecurityInformation.ProtectedDacl : SecurityInformation.UnprotectedDacl);
            parts.Add("dacl");
        }
        if (owner) { info |= SecurityInformation.Owner; parts.Add("owner"); }
        if (group) { info |= SecurityInformation.Group; parts.Add("group"); }
        var partList = string.Join(",", parts);
        ushort control = (ushort)((desired.Protected ? Control.DaclProtected : 0) | (before.Control & Control.DaclAutoInherited));
        // Encoding happens before anything is sent, so a SID it cannot encode or a DACL past the
        // 64 KiB ACL limit fails this object and writes nothing.
        byte[] sd;
        try { sd = DescriptorBuilder.Build(control, owner ? wantOwner : null, group ? wantGroup : null, null, dacl ? desired.Aces : null); }
        catch (Exception e) when (e is not OutOfMemoryException) { return new WriteResult(partList, null, $"encode {partList}: {e.Message}; nothing was written", false); }

        try { ((IWritableTree)tree).Write(rel, info, sd); }
        catch (Exception e) { return new WriteResult(partList, null, $"write {partList}: {e.Message}", false); }

        Descriptor after;
        try { after = Descriptor.Decode(tree.Read(rel, withSacl: true)); }
        catch (Exception e)
        {
            return new WriteResult(partList, null, $"G2: {Show(rel)}: written ({partList}) but could not be read back: {e.Message}. No further writes were started.", true);
        }
        var g2 = ReadbackDiff(desired, before, after, owner ? wantOwner : before.Owner, group ? wantGroup : before.Group);
        if (g2 is not null)
            return new WriteResult(partList, after.Raw, $"G2: {Show(rel)}: after writing {partList}, {g2}. No further writes were started.", true);
        return new WriteResult(partList, after.Raw, null, false);
    }

    const ushort KeptControl = Control.DaclAutoInherited | Control.SaclAutoInherited | Control.SaclProtected | Control.SaclPresent;

    // ReadbackDiff compares a read after a write with what it should hold, raw (3.2): the desired
    // DACL and protection, the expected owner and group, and the SACL and kept control bits
    // unchanged from the read before. Null when everything agrees.
    public static string? ReadbackDiff(Desired desired, Descriptor before, Descriptor after, string? owner, string? group)
    {
        var d = desired.Matches(after.Dacl, IsProtected(after));
        if (d is not null) return $"the DACL read back differs: {d}";
        if (after.Owner != owner) return $"owner read back is {after.Owner ?? "absent"}, want {owner ?? "absent"}";
        if (after.Group != group) return $"group read back is {after.Group ?? "absent"}, want {group ?? "absent"}";
        if ((after.Control & KeptControl) != (before.Control & KeptControl))
            return $"control changed from {string.Join("|", Descriptor.DescribeControl((ushort)(before.Control & KeptControl)))} to {string.Join("|", Descriptor.DescribeControl((ushort)(after.Control & KeptControl)))}";
        if (AclKey(after.Sacl) != AclKey(before.Sacl)) return "the SACL changed";
        return null;
    }

    // AclKey renders every stored field of an ACL, in order, for an exact comparison.
    static string AclKey(AclView? a) =>
        a is null ? "absent" : $"{a.Revision}:" + string.Join("|", a.Aces.Select(x => $"{x.TypeCode},{x.Flags},{x.Mask},{x.Sid},{x.Body}"));

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
