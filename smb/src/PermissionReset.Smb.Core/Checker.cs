using System.Collections.Concurrent;

namespace PermissionReset.Smb.Core;

// ITree is what the walk needs from a file system: list one directory and read one object's
// descriptor, both by path relative to the root ("" is the root, '/' separates). The Windows
// implementation opens every handle with backup intent and never follows a reparse point.
// Failures throw; the message names the failed step.
public interface ITree
{
    IReadOnlyList<TreeEntry> List(string rel);

    // Read returns the self-relative descriptor (owner, group and DACL, and the SACL when withSacl)
    // with the attributes of the object the open handle refers to.
    TreeObject Read(string rel, bool withSacl);
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

// TreeObject is one Read's result: the raw descriptor and the attributes of the object the open
// handle actually refers to. The attributes matter because the object may have changed between
// the listing and the open (smb/DESIGN-write-path.md, 5.3): a file that became a directory would
// otherwise leave a new subtree unwalked and still be reported on.
public readonly record struct TreeObject(byte[] Descriptor, bool IsDir, bool IsReparse);

// Outcome of one object (smb/DESIGN-write-path.md, 3.3):
//   Ok        stored DACL (and owner/group, when named) is the desired one;
//   Write     dry run: the object itself needs a write;
//   Follows   dry run: it differs now, but only because an ancestor will be written: once that
//             ancestor is right, the array re-derives this object's inherited part;
//   Written   apply: the object was written and read back right (G2);
//   Stopped   apply: it needed a write, but the run had stopped, so it was not written;
//   Keep      the rule has no acl:, so the DACL is not the reset's to change (a named owner or
//             group that differs is still a Write in a dry run, and an Error in apply, which does
//             not write owner or group on a rule without acl:);
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
    // unresolved one refuses the whole walk. rootName is the root's own base name
    // (RuleSelector.RootName of the ROOT argument), which the rules match the root by.
    public Checker(Plan plan, ITree tree, string rootName, Func<string, string?> resolve, WalkOptions? options = null)
    {
        // DESIGN-Q: smb/DESIGN-sacl-write.md 2.1 has phase 3 accept schema 3, but this slice
        // builds only its plan checks (#78, 2.2); SACL classification and writes are another
        // slice, and running a schema 3 plan under DACL-only meaning would misreport. Refused
        // here until that slice lands.
        if (plan.Schema != Plan.SmbSchema)
            throw new PlanException($"check needs a schema {Plan.SmbSchema} plan (a DACL-only build-spec --smb-plan; schema 3 SACL plans are not walkable yet); this one is schema {plan.Schema}");
        opt = options ?? new WalkOptions();
        if (opt.Apply && tree is not IWritableTree)
            throw new ArgumentException("apply needs a writable tree", nameof(tree));
        this.plan = plan;
        this.tree = tree;
        rules = new RuleSelector(plan, rootName);
        var unresolved = new SortedSet<string>(StringComparer.Ordinal);
        var resolved = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var failed = new HashSet<string>(StringComparer.Ordinal);
        // Every distinct principal the plan names is resolved exactly once here, the miss cached
        // too (#78); the plan's principal string is the cache key. A lookup that throws (a domain
        // or trust failure, not just an unknown name) is an unresolved principal too: refused
        // before any read, named in the message below.
        string? Sid(string principal, string planSid)
        {
            if (planSid.Length > 0) return planSid;
            if (resolved.TryGetValue(principal, out var known)) return known;
            if (failed.Contains(principal)) return null;
            string? s;
            try { s = resolve(principal); }
            catch { s = null; }
            if (s is null) { unresolved.Add(principal); failed.Add(principal); }
            else resolved[principal] = s;
            return s;
        }
        foreach (var r in plan.Rules.Prepend(plan.Default))
        {
            want[r] = r.Dacl?.Select(a => new Ace(a.WindowsType, a.WindowsFlags, a.WindowsMask, Sid(a.Principal, a.Sid) ?? "")).ToList();
            // Principals that appear only in sacl: entries resolve here too (#78). Nothing is
            // built from them yet: the SACL classification slice turns planRule.Sacl into per-rule
            // lists, the way want holds the DACL ones.
            foreach (var a in r.Sacl ?? []) Sid(a.Principal, a.Sid);
            ownerGroup[r] = (r.Owner.Length > 0 ? Sid(r.Owner, "") : null, r.Group.Length > 0 ? Sid(r.Group, "") : null);
            SetsOwnerOrGroup |= r.Owner.Length > 0 || r.Group.Length > 0;
        }
        if (unresolved.Count > 0)
            throw new PlanException($"these principals do not resolve to a SID on this host: {string.Join(", ", unresolved)}");
        Principals = resolved;
    }

    // Node is a directory waiting to be listed, with what its children need from it: its desired
    // DACL (the input to their inheritance after the run's writes), its stored DACL (the input to
    // their dynamic-tracking evidence), and whether it or an ancestor will be written.
    sealed record Node(string Rel, List<Ace> Acl, List<Ace> StoredAcl, bool AncestorWrites);

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
        var stored = Descriptor.Decode(tree.Read("", withSacl: false).Descriptor);
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

        TreeObject read;
        Descriptor stored;
        // A DACL-only read for the compare, in apply too: most objects need no write, and the SACL
        // (G2's before-image) is read only for those that do, just before the write (Write).
        try { read = tree.Read(rel, withSacl: false); stored = Descriptor.Decode(read.Descriptor); }
        catch (Exception e)
        {
            return Fail(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error, $"read: {e.Message}"));
        }
        // The open handle says what the object is now. An object whose type changed between the
        // listing and the open, or that became a reparse point, is skipped and counted (design
        // 5.3): what listed as a file may be a new directory whose subtree was never walked.
        if (read.IsReparse || read.IsDir != isDir)
        {
            var became = read.IsReparse ? "a reparse point" : read.IsDir ? "a directory" : "a file";
            // Fail already counts a listed directory; count only a file that opened as one.
            if (read.IsDir && !isDir) Interlocked.Increment(ref summary.NotProcessed);
            return Fail(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error,
                $"its type changed between listing and open: it is now {became}; it was not checked"));
        }
        bool storedProtected = IsProtected(stored);
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
            inherited = parent is null ? StoredInherited(stored) : Inheritance.Inherit(parent.Acl, isDir);
        }
        catch (NotSupportedException e)
        {
            return Fail(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error, e.Message));
        }
        bool ancestorWrites = parent?.AncestorWrites ?? false;

        var og = OwnerGroupDiff(rule, stored);
        var wanted = want[rule];
        if (wanted is null)
        {
            // No acl: here. The DACL is left alone, but a named owner or group is still the
            // reset's to check, independently of the DACL (a rule can name owner:/group: alone).
            // Apply writes nothing on a rule without acl:, so a difference there is an error the
            // operator sees, not a silent Keep.
            if (og is null) emit(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Keep, null));
            else if (!opt.Apply) emit(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Write, og));
            else emit(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error,
                $"{og}; apply does not write owner or group on a rule without acl:, so it was not written"));
            done?.Invoke(og is null);
            if (!isDir) return null;
            // An absent DACL (everyone full control) is not an empty one: there is nothing for the
            // children to inherit from that a reset models.
            if (stored.Dacl is null)
                return Fail(new CheckRecord(rel, true, rule.Label, null, Outcome.Error, "its DACL is absent, so its children cannot be classified"));
            if (storedAces.Any(a => a is null))
                return Fail(new CheckRecord(rel, true, rule.Label, null, Outcome.Error, "its DACL holds an ACE type a reset does not model, so its children cannot be classified"));
            // The children inherit what is actually stored. The inherited part is substituted for
            // the re-derived one only when this directory provably tracks its parent and an
            // ancestor will be written (F2, F3); otherwise nothing above changes it.
            var acl = storedAces.Select(a => a!.Value).ToList();
            if (!storedProtected && ancestorWrites && Tracks(acl, parentPropagates))
                acl = acl.Where(a => !a.Inherited).Concat(inherited).ToList();
            return new Node(rel, acl, storedAcl, ancestorWrites);
        }

        var desired = DesiredFor(wanted, inherited, parent is null);
        var daclDiff = desired.Matches(stored.Dacl, storedProtected);
        var diff = daclDiff ?? og;
        // An absent DACL never follows: the array has no inherited part to re-derive.
        bool follows = stored.Dacl is not null && Follows(desired, storedAces, storedProtected, parentPropagates);
        Outcome outcome;
        string? parts = null, before = null, after = null;
        if (diff is null) outcome = Outcome.Ok;
        else if (!opt.Apply)
        {
            if (ancestorWrites && follows && og is null) outcome = Outcome.Follows;
            else
            {
                outcome = Outcome.Write;
                // The frozen-copy note explains a DACL difference; it says nothing about an owner or
                // group difference on a DACL that matched.
                if (daclDiff is not null && desired.Form != Form.Protected && TrackableShape(desired, storedAces, storedProtected))
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
            if (daclDiff is not null && desired.Form != Form.Protected && TrackableShape(desired, storedAces, storedProtected))
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
                return Fail(new CheckRecord(rel, isDir, rule.Label, desired.Form, Outcome.Error, w.Error, w.Parts, w.Before, w.After));
            }
            outcome = Outcome.Written;
            (parts, before, after) = (w.Parts, w.Before, w.After);
        }
        emit(new CheckRecord(rel, isDir, rule.Label, desired.Form, outcome, diff, parts, before, after));
        done?.Invoke(outcome is Outcome.Ok or Outcome.Written);
        return isDir ? new Node(rel, desired.Aces.ToList(), outcome == Outcome.Written ? desired.Aces.ToList() : storedAcl, !opt.Apply && (ancestorWrites || outcome == Outcome.Write)) : null;
    }

    static string Show(string rel) => rel.Length == 0 ? "the root" : rel;

    readonly record struct WriteResult(string? Parts, string? Before, string? After, string? Error, bool Guard);

    // Write sets what differs, then reads the object back raw (G2, design 5.2). The DACL is written
    // with DACL_SECURITY_INFORMATION and its protection stated both in the control word and as
    // (UN)PROTECTED_DACL_SECURITY_INFORMATION, and D:AI sent as FlashArray stores it (F5). Owner and
    // group go in the same call when the rule names them and they differ. G2 then checks the written
    // parts are what was wanted, D:AI is what F5 says, and every other part (the other of
    // owner/group, the SACL, S:AI, S:P) is what it was before.
    //
    // seen is the DACL-only read the compare used. Write first reads the object again with its SACL,
    // as G2's before-image, and writes nothing if the DACL, owner, group or DACL control bits moved
    // between the two reads, since the decision to write was made on the first.
    WriteResult Write(string rel, PlanRule rule, Desired desired, Descriptor seen, bool dacl)
    {
        Descriptor before;
        try { before = Descriptor.Decode(tree.Read(rel, withSacl: true).Descriptor); }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return new WriteResult(null, null, null, $"read with SACL before writing: {e.Message}; nothing was written", false);
        }
        const ushort daclControl = Control.DaclProtected | Control.DaclAutoInherited;
        if (AclKey(before.Dacl) != AclKey(seen.Dacl) || before.Owner != seen.Owner || before.Group != seen.Group
            || (before.Control & daclControl) != (seen.Control & daclControl))
            return new WriteResult(null, before.Raw, null, $"{Show(rel)} changed between the compare and the write; nothing was written, rerun to pick it up", false);

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
        // The control word states what the array stores (F5): an unprotected DACL with D:AI, a
        // protected one without it. When only owner or group is written, the control word is
        // ignored and the stored DACL bits are expected unchanged.
        ushort control = desired.Protected ? Control.DaclProtected : Control.DaclAutoInherited;
        // Encoding happens before anything is sent, so a SID it cannot encode or a DACL past the
        // 64 KiB ACL limit fails this object and writes nothing.
        byte[] sd;
        try { sd = DescriptorBuilder.Build(control, owner ? wantOwner : null, group ? wantGroup : null, null, dacl ? desired.Aces : null); }
        catch (Exception e) when (e is not OutOfMemoryException) { return new WriteResult(partList, before.Raw, null, $"encode {partList}: {e.Message}; nothing was written", false); }

        try { ((IWritableTree)tree).Write(rel, info, sd); }
        catch (Exception e) { return new WriteResult(partList, before.Raw, null, $"write {partList}: {e.Message}", false); }

        Descriptor after;
        try { after = Descriptor.Decode(tree.Read(rel, withSacl: true).Descriptor); }
        catch (Exception e)
        {
            return new WriteResult(partList, before.Raw, null, $"G2: {Show(rel)}: written ({partList}) but could not be read back: {e.Message}. No further writes were started.", true);
        }
        var g2 = ReadbackDiff(desired, before, after, owner ? wantOwner : before.Owner, group ? wantGroup : before.Group, dacl);
        if (g2 is not null)
            return new WriteResult(partList, before.Raw, after.Raw, $"G2: {Show(rel)}: after writing {partList}, {g2}. No further writes were started.", true);
        return new WriteResult(partList, before.Raw, after.Raw, null, false);
    }

    const ushort KeptControl = Control.SaclAutoInherited | Control.SaclProtected | Control.SaclPresent;

    // ReadbackDiff compares a read after a write with what it should hold, raw (3.2): the desired
    // DACL and protection, the expected owner and group, the SACL and its control bits unchanged
    // from the read before, and D:AI. After a DACL write, D:AI is what FlashArray was measured to
    // store (F5): set on an unprotected DACL, clear on a protected one, whatever it was before.
    // Without a DACL write it is unchanged. Null when everything agrees.
    public static string? ReadbackDiff(Desired desired, Descriptor before, Descriptor after, string? owner, string? group, bool daclWritten)
    {
        var d = desired.Matches(after.Dacl, IsProtected(after));
        if (d is not null) return $"the DACL read back differs: {d}";
        if (after.Owner != owner) return $"owner read back is {after.Owner ?? "absent"}, want {owner ?? "absent"}";
        if (after.Group != group) return $"group read back is {after.Group ?? "absent"}, want {group ?? "absent"}";
        if ((after.Control & KeptControl) != (before.Control & KeptControl))
            return $"control changed from {string.Join("|", Descriptor.DescribeControl((ushort)(before.Control & KeptControl)))} to {string.Join("|", Descriptor.DescribeControl((ushort)(after.Control & KeptControl)))}";
        bool wantAI = daclWritten ? !desired.Protected : (before.Control & Control.DaclAutoInherited) != 0;
        bool gotAI = (after.Control & Control.DaclAutoInherited) != 0;
        if (gotAI != wantAI)
            return daclWritten
                ? $"DaclAutoInherited is {(gotAI ? "set" : "clear")} after {(desired.Protected ? "a protected" : "an unprotected")} DACL write; this array was measured to store it {(wantAI ? "set" : "clear")} (F5)"
                : $"DaclAutoInherited changed from {(wantAI ? "set" : "clear")} to {(gotAI ? "set" : "clear")} across a write that did not set the DACL";
        if (AclKey(after.Sacl) != AclKey(before.Sacl)) return "the SACL changed";
        return null;
    }

    // AclKey renders every stored field of an ACL, in order, for an exact comparison.
    static string AclKey(AclView? a) =>
        a is null ? "absent" : $"{a.Revision}:" + string.Join("|", a.Aces.Select(x => $"{x.TypeCode},{x.Flags},{x.Mask},{x.Sid},{x.Body}"));

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
