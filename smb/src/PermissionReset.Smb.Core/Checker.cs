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
// (design 3.4), on every part the plan names (smb/DESIGN-sacl-write.md, 7.1). On resume, a
// complete directory is still read and listed, so its subdirectories are found and its children
// get its desired DACL, but its files are not read again. The compare-time SACL record is v2's
// per-directory trace of what the directory passed down before any write of this run (7.1,
// decision 13); on a resume it takes the place of the in-memory compare-time read.
public interface ICheckpoint
{
    bool IsDone(string rel);
    void Done(string rel);
    bool TryGetCompareSacl(string rel, out IReadOnlyList<Ace> sacl);
    void RecordCompareSacl(string rel, IReadOnlyList<Ace> sacl);
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

// Parts names what a write set ("dacl", "dacl,owner"; in saclMode "sacl" and the two-write
// combinations like "sacl,dacl", smb/DESIGN-sacl-write.md 4.2), Before and After are the raw
// descriptors, base64, around a write. SaclForm is the desired SACL form, DaclOutcome and
// SaclOutcome the two part verdicts (saclMode only, 4.6; a wholly excluded, reparse or failed
// object has no parts). Only in saclMode do records carry the SACL fields.
public sealed record CheckRecord(string Path, bool IsDir, string? Rule, Form? Form, Outcome Outcome, string? Detail,
    string? Parts = null, string? Before = null, string? After = null,
    Form? SaclForm = null, Outcome? DaclOutcome = null, Outcome? SaclOutcome = null);

public sealed class CheckSummary
{
    readonly ConcurrentDictionary<Outcome, long> outcomes = new();
    readonly ConcurrentDictionary<Form, long> forms = new();
    readonly ConcurrentDictionary<Form, long> saclForms = new();
    public long NotProcessed;   // directories whose children were not reached
    public long Resumed;        // files skipped because the checkpoint had their directory complete
    public string? Stop;        // why an apply stopped (G1, G1-SACL, G2), or null

    public void Add(CheckRecord r)
    {
        outcomes.AddOrUpdate(r.Outcome, 1, (_, n) => n + 1);
        if (r.Form is Form f) forms.AddOrUpdate(f, 1, (_, n) => n + 1);
        if (r.SaclForm is Form sf) saclForms.AddOrUpdate(sf, 1, (_, n) => n + 1);
    }

    public long Count(Outcome o) => outcomes.GetValueOrDefault(o);
    public long Count(Form f) => forms.GetValueOrDefault(f);
    public long CountSacl(Form f) => saclForms.GetValueOrDefault(f);

    // Complete is true when every object was reached, none failed and nothing stopped the run.
    public bool Complete => Stop is null && NotProcessed == 0 && Count(Outcome.Error) == 0 && Count(Outcome.Stopped) == 0;
}

// WriteOrder picks which of a two-part object's writes goes first when both its DACL and its SACL
// differ (smb/DESIGN-sacl-write.md, 4.2): the right order is customer-specific, so it is a switch.
// SaclFirst is the default because a failed run should not leave newly granted access unaudited.
public enum WriteOrder { SaclFirst, DaclFirst }

// Options for a walk. Apply needs an IWritableTree. RootProtected forces the root's DACL form to
// Protected (design 2.2: a frozen ID copy on the root cannot be detected); RootSaclProtected does
// the same for its SACL, independently (3.2, decision 4). Order applies only to objects whose two
// parts are both written.
public sealed record WalkOptions(bool Apply = false, bool RootProtected = false,
    WriteOrder Order = WriteOrder.SaclFirst, bool RootSaclProtected = false);

// Checker is the top-down walk of the write path (smb/DESIGN-write-path.md, sections 2, 3 and 5;
// the SACL half is smb/DESIGN-sacl-write.md). For every object it picks the desired DACL from the
// plan and the parent's desired DACL, reads what is stored, and says whether the object is right.
// A dry run (check) stops there. Apply (phase 2) writes each object that differs, the DACL only,
// plus owner and group when the rule names them, and reads it back; a directory is finished before
// its children are read, so each child is compared with a parent that is already right. When any
// rule sets sacl: (saclMode, smb/DESIGN-sacl-write.md 2.3) every object's SACL is classified too,
// both parts are written (each as its own call, 4.1) and the record carries the two part verdicts.
public sealed class Checker
{
    readonly Plan plan;
    readonly RuleSelector rules;
    readonly ITree tree;
    readonly WalkOptions opt;
    readonly Dictionary<PlanRule, List<Ace>?> want = new(ReferenceEqualityComparer.Instance);
    readonly Dictionary<PlanRule, List<Ace>?> wantSacl = new(ReferenceEqualityComparer.Instance);
    readonly Dictionary<PlanRule, (string? Owner, string? Group)> ownerGroup = new(ReferenceEqualityComparer.Instance);

    // saclMode is "any rule sets sacl:" (2.3): the compare read then covers the SACL and every
    // object's SACL is classified, rules without a sacl: key included (a kept SACL is still a
    // follower, a frozen copy an error, never a write). Keyed off sacl_set, never off the list
    // being empty: sacl: [] is a present-empty S:P write, not an absent key.
    public bool SaclMode { get; }

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
        // Phase 3 accepts schema 3 (the plan-side SACL fields it needs were checked at load) and
        // keeps reading schema 2 with its phase 2 meaning: schema 2 with a sacl: rule is refused
        // at load (2.1), so here schema 2 means DACL-only.
        if (plan.Schema is not (Plan.SmbSchema or Plan.SmbSaclSchema))
            throw new PlanException($"check needs a schema {Plan.SmbSchema} or {Plan.SmbSaclSchema} plan (a build-spec --smb-plan; schema 3 when any rule sets sacl:); this one is schema {plan.Schema}");
        opt = options ?? new WalkOptions();
        if (opt.Apply && tree is not IWritableTree)
            throw new ArgumentException("apply needs a writable tree", nameof(tree));
        this.plan = plan;
        this.tree = tree;
        rules = new RuleSelector(plan, rootName);
        var unresolved = new SortedSet<string>(StringComparer.Ordinal);
        var resolved = new SortedDictionary<string, string>(StringComparer.Ordinal);
        // Every distinct principal the plan names is resolved exactly once here, the miss cached
        // too (#78); the plan's principal string is the cache key. A lookup that throws (a domain
        // or trust failure, not just an unknown name) is an unresolved principal too: refused
        // before any read, named in the message below.
        string? Sid(string principal, string planSid)
        {
            if (planSid.Length > 0) return planSid;
            if (resolved.TryGetValue(principal, out var known)) return known;
            if (unresolved.Contains(principal)) return null;
            string? s;
            try { s = resolve(principal); }
            catch { s = null; }
            if (s is null) unresolved.Add(principal);
            else resolved[principal] = s;
            return s;
        }
        var creatorRefused = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var r in plan.Rules.Prepend(plan.Default))
        {
            want[r] = r.Dacl?.Select(a => new Ace(a.WindowsType, a.WindowsFlags, a.WindowsMask, Sid(a.Principal, a.Sid) ?? "")).ToList();
            wantSacl[r] = r.SaclSet
                ? (r.Sacl ?? []).Select(a => new Ace(a.WindowsType, a.WindowsFlags, a.WindowsMask, Sid(a.Principal, a.Sid) ?? "")).ToList()
                : null;
            // smb/DESIGN-sacl-write.md 2.2 item 3 (decision 11): a name that *resolves* to one of
            // the four creator SIDs is refused the way Plan.CheckAces refuses the literal SIDs —
            // what a creator SID inherits as depends on who created each object, so a directory
            // whose desired SACL names one would leave every child unclassifiable.
            foreach (var a in r.Sacl ?? [])
            {
                var sid = Sid(a.Principal, a.Sid);
                if (sid is not null && Inheritance.CreatorSids.Contains(sid))
                    creatorRefused.Add(a.Principal.Length > 0 ? a.Principal : sid);
            }
            ownerGroup[r] = (r.Owner.Length > 0 ? Sid(r.Owner, "") : null, r.Group.Length > 0 ? Sid(r.Group, "") : null);
            SetsOwnerOrGroup |= r.Owner.Length > 0 || r.Group.Length > 0;
        }
        if (unresolved.Count > 0)
            throw new PlanException($"these principals do not resolve to a SID on this host: {string.Join(", ", unresolved)}");
        if (creatorRefused.Count > 0)
            throw new PlanException($"these sacl: principals resolve to a creator SID (S-1-3-0 to S-1-3-3), which is refused (smb/DESIGN-sacl-write.md 2.2): {string.Join(", ", creatorRefused)}");
        Principals = resolved;
        SaclMode = plan.Rules.Prepend(plan.Default).Any(r => r.SaclSet);
    }

    // Node is a directory waiting to be listed, with what its children need from it: its desired
    // DACL (the input to their inheritance after the run's writes), its stored DACL (the input to
    // their dynamic-tracking evidence), and whether it or an ancestor will be written. In saclMode
    // the SACL counterparts join them (2.4, 3.2): Sacl is the SACL the children inherit from (its
    // desired one, or its stored one for a kept directory), StoredSaclNow what it passes down
    // after this run's write of it, StoredSaclAtCompare the read before any write of this run —
    // the state that tells a pre-run freeze from G1-SACL (3.2, 4.4) —, SaclAncestorWrites whether
    // an ancestor's SACL will be written, and SaclOpaqueReason why the children's SACL parts
    // cannot be classified (an opaque ACE in an unwritten stored SACL above them, 3.2).
    sealed record Node(string Rel, List<Ace> Acl, List<Ace> StoredAcl, bool AncestorWrites,
        List<Ace>? Sacl = null, List<Ace>? StoredSaclNow = null, List<Ace>? StoredSaclAtCompare = null,
        bool SaclAncestorWrites = false, string? SaclOpaqueReason = null);

    // stop is set once, by the first G1 or G2 failure; after it no new write starts and no new
    // directory is listed. A write already past its check finishes and is read back.
    string? stop;
    readonly object stopGate = new();

    // apply's checkpoint, set by Run so Visit can read and write the per-directory compare-time
    // SACL records (7.1, decision 13).
    ICheckpoint? walkCheckpoint;

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
        walkCheckpoint = checkpoint;
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
                    // Checkpoint v2 (7.1, decision 13): a done directory is right on every part the
                    // plan names — done(ok) already requires both part verdicts right — so in
                    // saclMode too its files are skipped as phase 2 skips them. Every object the
                    // resume still reads tells a pre-run freeze from G1-SACL against the directory's
                    // compare-time SACL record. G8 (decision 19): a file with a persistent error
                    // keeps its directory incomplete (filesRight already counts it), so the resume
                    // re-reads it.
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

    // RootSacl is the SACL the root's children will inherit from once the root is right: its
    // desired SACL (its rule's sacl:, the ID audit ACEs it stores now as the inherited input, and
    // --root-sacl-protected), or its stored SACL when its rule has no sacl: key (2.3: a kept SACL
    // still passes to the children). Unlike RootAcl it reads the root WITH its SACL, so the
    // preflight calls it only after step 2 has proven the audit bypass (3.2; design 6, step 3).
    public List<Ace> RootSacl()
    {
        var stored = Descriptor.Decode(tree.Read("", withSacl: true).Descriptor);
        var wanted = wantSacl[rules.Select("", true).Rule!];
        if (wanted is not null)
            return SaclModel.DesiredForSacl(wanted, StoredInheritedSacl(stored), isRoot: true, opt.RootSaclProtected).Aces.ToList();
        var aces = (stored.Sacl?.Aces ?? []).Select(Ace.FromView).ToList();
        if (aces.Any(a => a is null)) throw new NotSupportedException("the root's SACL holds an ACE type a reset does not model (smb/DESIGN-sacl-write.md 4.5)");
        return aces.Select(a => a!.Value).ToList();
    }

    Desired DesiredFor(List<Ace> wanted, List<Ace> inherited, bool isRoot) =>
        isRoot && opt.RootProtected ? new Desired(Form.Protected, wanted.ToList(), true) : Desired.Classify(wanted, inherited);

    static List<Ace> StoredInherited(Descriptor d) =>
        (d.Dacl?.Aces ?? []).Select(Ace.FromView).Where(a => a is { Inherited: true }).Select(a => a!.Value).ToList();

    static List<Ace> StoredInheritedSacl(Descriptor d) =>
        (d.Sacl?.Aces ?? []).Select(Ace.FromView).Where(a => a is { Inherited: true }).Select(a => a!.Value).ToList();

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
        // saclMode's compare read covers the SACL (2.3: every object is classified on both parts,
        // and the compare-time SACL is what a pre-run freeze is told from G1-SACL against, 3.2).
        // Without a sacl: rule the DACL-only compare read of phase 2 stands, and the SACL is read
        // only just before a write, as G2's before-image.
        try { read = tree.Read(rel, withSacl: SaclMode); stored = Descriptor.Decode(read.Descriptor); }
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
        // design 2.2). In saclMode the SACL halves are computed alongside.
        List<Ace>? parentPropagates = null;
        List<Ace> inherited;
        AclView? storedSacl = null;
        bool storedSaclProtected = false;
        List<Ace> storedSaclAces = [], inheritedSacl = [], parentSaclNow = [], parentSaclCompare = [];
        try
        {
            if (parent is not null) parentPropagates = Inheritance.Inherit(parent.StoredAcl, isDir);
            inherited = parent is null ? StoredInherited(stored) : Inheritance.Inherit(parent.Acl, isDir);
            if (SaclMode)
            {
                storedSacl = stored.Sacl;
                storedSaclProtected = (stored.Control & Control.SaclProtected) != 0;
                storedSaclAces = (stored.Sacl?.Aces ?? []).Select(Ace.FromView).Where(a => a is not null).Select(a => a!.Value).ToList();
                inheritedSacl = parent is null ? StoredInheritedSacl(stored) : Inheritance.Inherit(parent.Sacl!, isDir);
                // The root has no in-walk parent to compare its inherited part against: its stored
                // ID audit ACEs stand in, so a kept root reads as tracking by construction, as the
                // DACL side takes the root's stored ID DACL ACEs for its desired inherited part.
                parentSaclNow = parent is null ? inheritedSacl : Inheritance.Inherit(parent.StoredSaclNow!, isDir);
                parentSaclCompare = parent is null ? inheritedSacl : Inheritance.Inherit(parent.StoredSaclAtCompare!, isDir);
            }
        }
        catch (NotSupportedException e)
        {
            return Fail(new CheckRecord(rel, isDir, rule.Label, null, Outcome.Error, e.Message));
        }
        // The directory's pre-run SACL (7.1, decision 13): what it passed down before any write of
        // this run. Its own compare read is that already on a resume (a checkpoint record wins, and
        // is the only compare-time read a resume has) and on a parent that was not written; under a
        // parent written this run, a directory that followed the write by propagation now stores
        // the parent's post-write output, so what it passed at compare time is reconstructed as its
        // explicit part plus the parent's compare-time output — otherwise a grandchild that should
        // have followed this run and did not reads as a plain Write instead of G1-SACL (#92 review
        // question Q1, closed here; the DESIGN-Q that opened it stood at the Classify call below).
        // A frozen copy that equals the parent's post-write output reads the same as a follower and
        // is taken for one; its S:AI empty child then stops on G1-SACL rather than being written as a
        // pre-run freeze. The error is toward the stop, and a fresh run converges (7.1).
        // A directory holding an opaque SACL ACE (4.5) is recorded with its modeled ACEs only —
        // storedSaclAces skips them — and is never written, so its fresh read on resume is
        // unchanged and matches the record.
        IReadOnlyList<Ace>? recordedSacl = null;
        List<Ace>? preRunSacl = null;
        if (isDir && SaclMode)
        {
            if (walkCheckpoint?.TryGetCompareSacl(rel, out recordedSacl) == true)
                preRunSacl = recordedSacl.ToList();
            else if (opt.Apply && parent is not null && storedSacl is not null && !storedSaclProtected
                && storedSaclAces.Where(a => a.Inherited).SequenceEqual(parentSaclNow)
                && !parentSaclNow.SequenceEqual(parentSaclCompare))
                preRunSacl = storedSaclAces.Where(a => !a.Inherited).Concat(parentSaclCompare).ToList();
            else
                preRunSacl = storedSaclAces;
        }
        bool ancestorWrites = parent?.AncestorWrites ?? false;
        bool saclAncestorWrites = parent?.SaclAncestorWrites ?? false;

        var og = OwnerGroupDiff(rule, stored);
        var wanted = want[rule];

        // ---- the DACL part verdict (phase 2's logic, unchanged) ---------------------------------
        Outcome dacOutcome;
        string? dacDetail;
        Form? dacForm = null;
        Desired? daclDesired = null;
        string? daclDiff = null, diff, g1Dacl = null;
        bool daclNeedsWrite = false;
        if (wanted is null)
        {
            // No acl: here. The DACL is left alone, but a named owner or group is still the
            // reset's to check, independently of the DACL (a rule can name owner:/group: alone).
            // Apply writes nothing on a rule without acl:, so a difference there is an error the
            // operator sees, not a silent Keep.
            dacOutcome = og is null ? Outcome.Keep : (!opt.Apply ? Outcome.Write : Outcome.Error);
            dacDetail = og is null || !opt.Apply ? og
                : $"{og}; apply does not write owner or group on a rule without acl:, so it was not written";
            diff = og;
        }
        else
        {
            daclDesired = DesiredFor(wanted, inherited, parent is null);
            dacForm = daclDesired.Form;
            daclDiff = daclDesired.Matches(stored.Dacl, storedProtected);
            diff = daclDiff ?? og;
            bool follows = stored.Dacl is not null && Follows(daclDesired, storedAces, storedProtected, parentPropagates);
            if (diff is null) { dacOutcome = Outcome.Ok; dacDetail = null; }
            else if (!opt.Apply)
            {
                if (ancestorWrites && follows && og is null) { dacOutcome = Outcome.Follows; dacDetail = diff; }
                else
                {
                    dacOutcome = Outcome.Write;
                    dacDetail = diff;
                    // The frozen-copy note explains a DACL difference; it says nothing about an
                    // owner or group difference on a DACL that matched.
                    if (daclDiff is not null && daclDesired.Form != Form.Protected && TrackableShape(daclDesired, storedAces, storedProtected))
                        dacDetail += "; its inherited part does not follow its parent (a frozen copy)";
                }
            }
            else
            {
                // Apply. The parent is already right (written and read back, or found right), so an
                // object whose stored DACL has the shape the array keeps in step with its parent,
                // yet whose inherited part differs from what this run computes, means
                // Inheritance.Inherit disagrees with the array or the parent is not what the run
                // thinks. Writing it would freeze it with no visible sign (F2). G1 (design 5.1):
                // stop, no override.
                if (daclDiff is not null && daclDesired.Form != Form.Protected && TrackableShape(daclDesired, storedAces, storedProtected))
                {
                    g1Dacl = $"G1: {Show(rel)}: its inherited part is not what its parent passes down ({daclDiff}); " +
                        "either the inheritance function disagrees with the array or this object holds a frozen copy. No further writes were started.";
                }
                dacOutcome = Outcome.Write;
                dacDetail = diff;
                daclNeedsWrite = true;
            }
        }

        // ---- the SACL part verdict (4.6) --------------------------------------------------------
        SaclPart? sp = null;
        Desired? saclDesired = null;
        var wantedSacl = SaclMode ? wantSacl[rule] : null;
        if (SaclMode)
        {
            if (parent?.SaclOpaqueReason is not null)
                // 3.2: an opaque ACE in a stored SACL above makes the children's SACL parts
                // unclassifiable; the DACL part stands on its own.
                sp = new SaclPart(null, Outcome.Error, "parent's SACL holds an opaque ACE; cannot classify");
            else
                // The compare-time SACL the classifier tells a pre-run freeze from G1-SACL against
                // is each directory's pre-run SACL (7.1): reconstructed in memory under a parent
                // written this run, read from the checkpoint on a resume. That closes #92 review
                // question Q1 — a grandchild of a directory written this run that should have
                // followed and did not stops on G1-SACL in the first run, not only on a resume.
                sp = SaclClassifier.Classify(parent is null, opt.Apply, opt.RootSaclProtected, wantedSacl,
                    inheritedSacl, parentSaclNow, parentSaclCompare, storedSacl, storedSaclProtected, saclAncestorWrites);
            if (wantedSacl is not null && sp is { Form: not null })
                saclDesired = SaclModel.DesiredForSacl(wantedSacl, inheritedSacl, parent is null, opt.RootSaclProtected);
        }

        // The record carries the two part verdicts in saclMode, and is byte-identical to phase 2
        // otherwise.
        CheckRecord Rec(Outcome outcome, string? detail, string? parts = null, string? before = null, string? after = null,
            Outcome? dacOut = null, Outcome? sacOut = null) =>
            sp is null
                ? new CheckRecord(rel, isDir, rule.Label, dacForm, outcome, detail, parts, before, after)
                : new CheckRecord(rel, isDir, rule.Label, dacForm, outcome, detail, parts, before, after,
                    sp.Form, dacOut ?? dacOutcome, sacOut ?? sp.Outcome);

        static string? Both(string? d, string? s) => (d, s) switch
        {
            (null, null) => null,
            (string dd, null) => $"dacl: {dd}",
            (null, string ss) => $"sacl: {ss}",
            (string dd, string ss) => $"dacl: {dd}; sacl: {ss}",
        };
        string? Detail(string? d, string? s) => sp is null ? d : Both(d, s);

        bool Right(Outcome o) => o is Outcome.Ok or Outcome.Written or Outcome.Keep;

        // The node the directory's children need. BuildNode is reached only when every part that
        // needed a write was written (or none needed one); every part failure, an encode refusal
        // included, drops the subtree through Fail instead.
        Node? BuildNode(bool daclWritten, bool saclWritten)
        {
            if (!isDir) return null;
            List<Ace> acl, storedNowAcl;
            if (wanted is not null)
            {
                acl = daclDesired!.Aces.ToList();
                storedNowAcl = daclWritten ? daclDesired!.Aces.ToList() : storedAcl;
            }
            else
            {
                // The children inherit what is actually stored. The inherited part is substituted
                // for the re-derived one only when this directory provably tracks its parent and an
                // ancestor will be written (F2, F3); otherwise nothing above changes it.
                acl = storedAces.Select(a => a!.Value).ToList();
                if (!storedProtected && ancestorWrites && Tracks(acl, parentPropagates))
                    acl = acl.Where(a => !a.Inherited).Concat(inherited).ToList();
                storedNowAcl = storedAcl;
            }
            var aw = !opt.Apply && (ancestorWrites || dacOutcome == Outcome.Write);
            if (sp is null) return new Node(rel, acl, storedNowAcl, aw);

            string? saclOpaque = parent?.SaclOpaqueReason;
            if (saclOpaque is null && !saclWritten)
                saclOpaque = SaclModel.OpaqueReason(storedSacl);
            List<Ace> saclForChildren, storedNowSacl;
            if (saclOpaque is null && wantedSacl is not null && saclDesired is not null)
            {
                saclForChildren = saclDesired.Aces.ToList();
                storedNowSacl = saclWritten ? saclDesired.Aces.ToList() : storedSaclAces;
            }
            else
            {
                // A kept directory (3.2): the stored SACL is passed down as it is, the inherited
                // part substituted for the re-derived one only when the directory provably tracks
                // its parent and an ancestor's SACL will be written. The same stored-as-is stands
                // when an opaque ACE made the desired form untrustworthy.
                saclForChildren = storedSaclAces;
                if (saclOpaque is null && !storedSaclProtected && saclAncestorWrites && TracksSacl(storedSaclAces, parentSaclNow))
                    saclForChildren = storedSaclAces.Where(a => !a.Inherited).Concat(inheritedSacl).ToList();
                storedNowSacl = storedSaclAces;
            }
            var saw = !opt.Apply && (saclAncestorWrites || sp!.Outcome == Outcome.Write);
            return new Node(rel, acl, storedNowAcl, aw, saclForChildren, storedNowSacl, preRunSacl!, saw, saclOpaque);
        }

        // ---- apply: guards, then the writes ------------------------------------------------------
        if (opt.Apply)
        {
            // Decision 13, 7.1: classification is done, and this directory's pre-run SACL goes to
            // the checkpoint before the G1/G1-SACL guards and before any write of the directory —
            // its children are only written later, so every write inside the directory comes after
            // its record too. First record wins, so a resume never overwrites an earlier run's
            // state. A record that cannot be written stops the run the way a failed Done does:
            // refuse later, when a resume would misread a freeze, beats writing now without the
            // record behind it.
            if (isDir && SaclMode && walkCheckpoint is not null && recordedSacl is null)
            {
                try { walkCheckpoint.RecordCompareSacl(rel, preRunSacl!); }
                catch (Exception e) when (e is not OutOfMemoryException)
                {
                    var why = $"could not record {Show(rel)}'s compare-time SACL in the checkpoint: {e.Message}. No further writes were started.";
                    Stop(summary, why);
                    return Fail(Rec(Outcome.Error, Detail(why, why), dacOut: Outcome.Error, sacOut: Outcome.Error));
                }
            }
            if (g1Dacl is not null)
            {
                Stop(summary, g1Dacl);
                return Fail(Rec(Outcome.Error, Detail(g1Dacl, sp?.Detail), dacOut: Outcome.Error));
            }
            if (sp is { Guard: true })
            {
                // G1-SACL (4.4): a child that should have followed this run's parent write and did
                // not, or a frozen ID audit copy. No override, as for the DACL's G1.
                const string prefix = "G1-SACL: ";
                var why = $"G1-SACL: {Show(rel)}: {(sp.Detail!.StartsWith(prefix, StringComparison.Ordinal) ? sp.Detail[prefix.Length..] : sp.Detail)}. No further writes were started.";
                Stop(summary, why);
                return Fail(Rec(Outcome.Error, Detail(dacDetail, why), sacOut: Outcome.Error));
            }

            bool saclNeedsWrite = sp is { Outcome: Outcome.Write };
            if (Stopped && (daclNeedsWrite || saclNeedsWrite))
            {
                return Fail(Rec(Outcome.Stopped,
                    Detail(daclNeedsWrite ? $"not written, the run stopped: {diff}" : dacDetail,
                        saclNeedsWrite ? $"not written, the run stopped: {sp!.Detail}" : sp?.Detail),
                    dacOut: daclNeedsWrite ? Outcome.Stopped : dacOutcome,
                    sacOut: saclNeedsWrite ? Outcome.Stopped : sp!.Outcome));
            }

            // A directory with no acl: hands its stored DACL to its children, so phase 2's two
            // refusals (an absent DACL, an ACE type a reset does not model) come before any write:
            // a SACL-only write must not go out on a directory whose subtree is then dropped.
            if (saclNeedsWrite && KeptDirDaclRefusal() is string refusal)
                return Fail(Rec(Outcome.Error, Detail(og is null ? refusal : $"{og}; {refusal}", $"not written: {refusal}"),
                    dacOut: Outcome.Error, sacOut: Outcome.Error));

            if (daclNeedsWrite || saclNeedsWrite)
            {
                if (sp is null)
                {
                    // Phase 2's DACL-only write path, unchanged.
                    var w = Write(rel, rule, daclDesired!, stored, daclDiff is not null);
                    if (w.Error is not null)
                    {
                        if (w.Guard) Stop(summary, w.Error);
                        return Fail(new CheckRecord(rel, isDir, rule.Label, daclDesired!.Form, Outcome.Error, w.Error, w.Parts, w.Before, w.After));
                    }
                    emit(new CheckRecord(rel, isDir, rule.Label, daclDesired!.Form, Outcome.Written, diff, w.Parts, w.Before, w.After));
                    done?.Invoke(true);
                    return isDir ? BuildNode(daclWritten: true, saclWritten: false) : null;
                }

                var wr = WriteParts(rel, rule, daclDesired, daclNeedsWrite, daclDiff is not null, saclDesired, saclNeedsWrite, stored);
                var dacFinal = wr.Dacl ?? dacOutcome;
                var sacFinal = wr.Sacl ?? sp.Outcome;
                var rec = Rec(SaclClassifier.MergeOutcome(dacFinal, sacFinal),
                    Detail(wr.DaclDetail ?? dacDetail, wr.SaclDetail ?? sp.Detail),
                    wr.Parts, wr.Before, wr.After, dacFinal, sacFinal);
                if (wr.Guard && wr.Error is not null)
                {
                    Stop(summary, wr.Error);
                    return Fail(rec);
                }
                if (wr.DropSubtree)
                    // A directory whose SACL or two-part write failed, an encode refusal included,
                    // drops its subtree, as phase 2 does on a single-write failure (the record
                    // carries which parts were written, and its parent directory is not
                    // checkpointed).
                    return Fail(rec);
                emit(rec);
                done?.Invoke(Right(dacFinal) && Right(sacFinal));
                return BuildNode(daclWritten: wr.Dacl is Outcome.Written, saclWritten: wr.Sacl is Outcome.Written);
            }
        }

        // No write: check, or apply with nothing to change. The record merges the two part verdicts;
        // in phase 2 shape it is exactly what it was.
        var merged = sp is null ? dacOutcome : SaclClassifier.MergeOutcome(dacOutcome, sp.Outcome);
        emit(Rec(merged, Detail(dacDetail, sp?.Detail)));
        done?.Invoke(Right(dacOutcome) && (sp is null || Right(sp.Outcome)));
        if (KeptDirDaclRefusal() is string keptRefusal)
            return Fail(new CheckRecord(rel, true, rule.Label, null, Outcome.Error, keptRefusal));
        return BuildNode(daclWritten: false, saclWritten: false);

        // An absent DACL (everyone full control) is not an empty one: there is nothing for the
        // children to inherit from that a reset models.
        string? KeptDirDaclRefusal() =>
            wanted is not null || !isDir ? null
            : stored.Dacl is null ? "its DACL is absent, so its children cannot be classified"
            : storedAces.Any(a => a is null) ? "its DACL holds an ACE type a reset does not model, so its children cannot be classified"
            : null;
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
        // Encoding happens before anything is sent, so a SID it cannot encode or a descriptor past the
        // array's 65,536-byte limit fails this object and writes nothing.
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

    // Dacl and Sacl are each part's final outcome (null: the part had no call), Parts what was
    // actually written in write order. DropSubtree marks failures after which the walk can no
    // longer trust what the object holds (a write error, a G2 failure, a changed object): below a
    // directory the part failure becomes a dropped subtree, as phase 2 does. Guard marks a
    // run-stopper (G2, or a write whose result is unknowable, 4.4). An encode refusal is not a
    // run-stopper, but it drops the subtree too: the part was not written, so the directory does
    // not hold what its children would be classified against.
    readonly record struct TwoPartWrite(Outcome? Dacl, string? DaclDetail, Outcome? Sacl, string? SaclDetail,
        string? Parts, string? Before, string? After, string? Error, bool Guard, bool DropSubtree);

    // WriteParts is the saclMode write path (smb/DESIGN-sacl-write.md, 4.1, 4.2, 4.4 and 4.5). Each
    // part is its own Write call, never a combined DACL|SACL one (Q-SACL-COMBINED): the DACL call
    // carries owner and group when the rule names them and they differ (4.1, decision 15) and never
    // names the SACL; the SACL call carries the SACL with exactly one protection flag stated and
    // the control word of 4.1, and never names anything else. When both parts differ the order is
    // opt.Order (4.2). compareSeen is the compare-time read, with the SACL.
    //
    // The first write's pre-write check covers every part against the compare-time read; before
    // the second write the part the first write changed is compared against the first write's
    // read-back and every other part against the compare-time read. Both descriptors are encoded
    // and size-checked before either is sent (4.5): an encode failure errors that part only. Every
    // write is followed by its own G2 read-back (4.1, K13); a G2 failure stops the run.
    TwoPartWrite WriteParts(string rel, PlanRule rule, Desired? daclDesired, bool daclCall, bool daclInCall,
        Desired? saclDesired, bool saclCall, Descriptor compareSeen)
    {
        Descriptor before;
        try { before = Descriptor.Decode(tree.Read(rel, withSacl: true).Descriptor); }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return WholeError(null, null, $"read with SACL before writing: {e.Message}; nothing was written");
        }
        const ushort daclControlBits = Control.DaclProtected | Control.DaclAutoInherited;
        const ushort saclControlBits = Control.SaclPresent | Control.SaclProtected | Control.SaclAutoInherited;
        if (AclKey(before.Dacl) != AclKey(compareSeen.Dacl) || before.Owner != compareSeen.Owner || before.Group != compareSeen.Group
            || (before.Control & daclControlBits) != (compareSeen.Control & daclControlBits)
            || AclKey(before.Sacl) != AclKey(compareSeen.Sacl)
            || (before.Control & saclControlBits) != (compareSeen.Control & saclControlBits))
            return WholeError(null, before.Raw, $"{Show(rel)} changed between the compare and the write; nothing was written, rerun to pick it up");

        var (wantOwner, wantGroup) = ownerGroup[rule];
        bool owner = daclCall && wantOwner is not null && wantOwner != before.Owner;
        bool group = daclCall && wantGroup is not null && wantGroup != before.Group;

        // 4.5: both descriptors are encoded and size-checked before either is sent, so a SID the
        // encoder rejects or a descriptor past the 65,536-byte limit errors one part and writes nothing for it.
        uint daclInfo = 0;
        byte[]? daclSd = null;
        string? daclEncode = null;
        var daclParts = new List<string>();
        if (daclCall)
        {
            if (daclInCall)
            {
                daclInfo |= SecurityInformation.Dacl | (daclDesired!.Protected ? SecurityInformation.ProtectedDacl : SecurityInformation.UnprotectedDacl);
                daclParts.Add("dacl");
            }
            if (owner) { daclInfo |= SecurityInformation.Owner; daclParts.Add("owner"); }
            if (group) { daclInfo |= SecurityInformation.Group; daclParts.Add("group"); }
            // The control word states what the array stores (F5); with no DACL in the call it is
            // ignored, as phase 2 does for an owner-only write.
            ushort control = daclDesired!.Protected ? Control.DaclProtected : Control.DaclAutoInherited;
            try { daclSd = DescriptorBuilder.Build(control, owner ? wantOwner : null, group ? wantGroup : null, null, daclInCall ? daclDesired.Aces : null); }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                daclEncode = $"encode {string.Join(",", daclParts)}: {e.Message}; that part was not written";
            }
        }
        uint saclInfo = 0;
        byte[]? saclSd = null;
        string? saclEncode = null;
        if (saclCall)
        {
            saclInfo = SaclModel.WriteInfo(saclDesired!.Protected);
            try { saclSd = DescriptorBuilder.Build(SaclModel.WriteControl(saclDesired.Protected), null, null, saclDesired.Aces, null); }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                saclEncode = $"encode sacl: {e.Message}; that part was not written";
            }
        }

        var calls = (daclCall, saclCall) switch
        {
            (true, true) => opt.Order == WriteOrder.DaclFirst ? new[] { "dacl", "sacl" } : new[] { "sacl", "dacl" },
            (true, false) => new[] { "dacl" },
            _ => new[] { "sacl" },
        };

        var parts = new List<string>();
        Descriptor lastRead = before;
        bool anyReadBack = false;
        Outcome? daclFinal = null, saclFinal = null;
        string? daclDetail = null, saclDetail = null, error = null;
        bool guard = false, drop = false;

        for (int i = 0; i < calls.Length; i++)
        {
            bool isDacl = calls[i] == "dacl";
            var encode = isDacl ? daclEncode : saclEncode;
            var callParts = isDacl ? daclParts : new List<string> { "sacl" };
            void Failed(Outcome o, string detail)
            {
                if (isDacl) { daclFinal = o; daclDetail = detail; }
                else { saclFinal = o; saclDetail = detail; }
            }
            if (encode is not null)
            {
                // The part was never sent, but the directory does not hold what its children
                // would be classified against, so its subtree is dropped as phase 2 drops it on
                // any write error (4.2: children are queued only after every part passed G2).
                Failed(Outcome.Error, encode);
                drop = true;
                continue;
            }
            Descriptor preThis = before;
            if (i == 1)
            {
                // 4.2's second pre-write check: the part the first write changed is compared with
                // the first write's read-back, every other part with the compare-time read.
                bool firstDacl = calls[0] == "dacl";
                try { preThis = Descriptor.Decode(tree.Read(rel, withSacl: true).Descriptor); }
                catch (Exception e) when (e is not OutOfMemoryException)
                {
                    error = $"read with SACL before writing the {calls[1]} part: {e.Message}; nothing more was written";
                    Failed(Outcome.Error, error);
                    drop = true;
                    break;
                }
                var daclBase = firstDacl ? lastRead : compareSeen;
                var saclBase = firstDacl ? compareSeen : lastRead;
                if (AclKey(preThis.Dacl) != AclKey(daclBase.Dacl)
                    || (preThis.Control & daclControlBits) != (daclBase.Control & daclControlBits)
                    || AclKey(preThis.Sacl) != AclKey(saclBase.Sacl)
                    || (preThis.Control & saclControlBits) != (saclBase.Control & saclControlBits)
                    || (firstDacl && owner ? preThis.Owner != lastRead.Owner : preThis.Owner != compareSeen.Owner)
                    || (firstDacl && group ? preThis.Group != lastRead.Group : preThis.Group != compareSeen.Group))
                {
                    error = $"{Show(rel)} changed between the first write and the second ({calls[0]} written); nothing more was written, rerun to pick it up";
                    Failed(Outcome.Error, error);
                    drop = true;
                    break;
                }
            }
            uint info = isDacl ? daclInfo : saclInfo;
            byte[] sd = (isDacl ? daclSd : saclSd)!;
            var partList = string.Join(",", callParts);

            try { ((IWritableTree)tree).Write(rel, info, sd); }
            catch (Exception e)
            {
                // A write API error is not proof that nothing changed, any more than success is
                // proof of what was stored (K13, 4.4): read the object back.
                try
                {
                    lastRead = Descriptor.Decode(tree.Read(rel, withSacl: true).Descriptor);
                    anyReadBack = true;
                    error = $"write {partList}: {e.Message}; the read back shows what is stored in the after image";
                }
                catch (Exception e2)
                {
                    // The stored state is unknowable: 4.4 records it as unknown and stops the run.
                    error = $"write {partList}: {e.Message}; the read back to learn what is stored failed too ({e2.Message}), so what is stored of {Show(rel)} is unknown. No further writes were started.";
                    guard = true;
                }
                Failed(Outcome.Error, error);
                drop = true;
                break;
            }
            Descriptor afterThis;
            try { afterThis = Descriptor.Decode(tree.Read(rel, withSacl: true).Descriptor); }
            catch (Exception e)
            {
                error = $"G2: {Show(rel)}: written ({partList}) but could not be read back: {e.Message}. No further writes were started.";
                guard = true;
                parts.AddRange(callParts);
                Failed(Outcome.Error, error);
                drop = true;
                break;
            }
            // The read-back is the evidence of what is stored, failure included (K13): it is the
            // record's after image even when the comparison below fails.
            lastRead = afterThis;
            anyReadBack = true;
            var g2 = isDacl
                ? ReadbackDiff(daclDesired!, preThis, afterThis, owner ? wantOwner : preThis.Owner, group ? wantGroup : preThis.Group, daclInCall)
                : SaclModel.ReadbackDiff(saclDesired!, preThis, afterThis);
            if (g2 is not null)
            {
                error = $"G2: {Show(rel)}: after writing {partList}, {g2}. No further writes were started.";
                guard = true;
                parts.AddRange(callParts);
                Failed(Outcome.Error, error);
                drop = true;
                break;
            }
            parts.AddRange(callParts);
            if (isDacl) daclFinal = Outcome.Written; else saclFinal = Outcome.Written;
        }
        return new TwoPartWrite(daclFinal, daclDetail, saclFinal, saclDetail,
            parts.Count > 0 ? string.Join(",", parts) : null, before.Raw, anyReadBack ? lastRead.Raw : null,
            error, guard, drop);

        // A failure that touched nothing readable past the first read: both called parts are errors
        // and the run keeps going below only when nothing was written.
        TwoPartWrite WholeError(string? parts0, string? before0, string msg) => new(
            daclCall ? Outcome.Error : null, msg, saclCall ? Outcome.Error : null, msg,
            parts0, before0, null, msg, false, true);
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

    // TracksSacl is Tracks for a kept directory's SACL (3.2, K10), one step wider: an S:AI empty
    // SACL under a parent that passes nothing down tracks too, and picks up a later parent SACL.
    // An explicit-only SACL does not (decision 22; Q-EXP for the DACL), and a mismatching ID part
    // is a frozen copy.
    static bool TracksSacl(List<Ace> sacl, List<Ace> parentPropagates)
    {
        var inheritedPart = sacl.Where(a => a.Inherited).ToList();
        if (inheritedPart.Count == 0 && sacl.Count > 0) return false;
        return inheritedPart.SequenceEqual(parentPropagates);
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
