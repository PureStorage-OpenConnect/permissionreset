# internal/walk

Parallel directory enumeration with fused pre-pass for permission repair.

## Files

- `walk.go` — Entry type, ParallelWalk, Pfind, Walk (sequential), Prepass

## Key types

- `Entry` — path, dir/symlink flags, mode, FH (filehandle), NeedStat flag, DirPath (parent for checkpoint), ACLApplied, Fix (see below)
- `FixResult` — `{Done, Applied, LogMsg}`, carried on a directory `Entry.Fix`. See "Fix outcome threading" below.
- `WalkErrors` — atomic error counter for detecting incomplete walks
- `PrepassResult` — fixed/error counts, readdir/fix time breakdowns
- `PrepassOptions` — transport, fix func, log, skip, exclude, workers, RootFSID

## Key functions

- `Prepass(root, ch, errs, opts)` — THE primary enumerator. Fixes dirs top-down, streams entries, reads tree once. Pass ch=nil for fix-only (pfind path).
- `ParallelWalk(root, ch, concurrency, errs, opts)` — concurrent readdir-only walk. Used as pfind fallback.
- `Pfind(root, ch, errs, exclude)` — streams from external pfind process; falls back to ParallelWalk.
- `Entry.Ref()` — builds transport.Ref with path+FH. Single source of truth for filehandle forwarding.
- `Entry.Stat()` — fills IsDir/IsSymlink/Mode for pfind entries (NeedStat=true).

## Prepass design (critical)

- Each directory: try readdir first (fast path if already traversable), fix only on failure, then readdir again.
- A transport implementing `transport.DirBatcher` (kernel) is listed `ReadDirBatch` children at a time
  (default `DefaultReadDirBatch`, 1,024), so one wide directory costs a bounded buffer (PS-11). Its
  `DirACL` write happens after the whole listing, as `Kernel.ReadDirSetACL` did. A listing that
  fails after delivering children is NOT fixed and retried (children would go out twice): it counts
  a readdir error and the directory is left unregistered. Batched order is getdents order, unsorted.
- Out-of-scope children (excluded, other filesystem) are not counted in `entryCount`: they never
  signal, so counting them kept the parent from ever completing.
- Bounds and what still grows (subdirectory refs, depth, userspace listings): `docs/CHECKPOINT_SCALE.md`.
  Tests: `bounded_test.go`; `WALK_WIDE_MEASURE=1` runs the heap measurement.
- Children collected into `[]childDir` before descent — frees dirent slice memory before recursion.
- Token pool bounds concurrency. When no token free, recurses inline (never blocks).
- Directory emitted AFTER its readdir (all batches) and after dispatching its children, but possibly before spawned children finish — so a consumer removing *read* cannot lock out its listing, while one removing *traverse* still could (see Ordering hazards).
- `sameFilesystem()` checks FSID: free on userspace transport (AttrsKnown), costs one Stat on kernel.

## Fix outcome threading (`Entry.Fix`)

`FixFunc` returns `(ok bool, msg string, FixResult)`, not just `(bool, string)`. The fast path
(readdir succeeds without calling `FixFunc` at all) is the common steady-state case and leaves a
directory's `Entry.Fix` at the zero value. The failure path — readdir fails, `FixFunc` runs to
restore traversability, readdir is retried — is where `FixResult` matters: `run.go`'s `Fix` closure
wraps `apply.FixDirPerms`, whose real spec apply (`ProcessPath`) already ran as part of fixing the
directory. Without this, the directory's `Entry` still flows into `entryCh` like any other
directory and the apply worker calls `ProcessPath` on it a second time — a second GETATTR+SETATTR
(or chmod) with the identical result, doubling RPCs on every directory a real repair run actually
needed to touch (which, on a tree with broken permissions, is most of them). `FixResult.Done` tells
the consumer the real apply already happened and reprocessing would be redundant; `Applied` and
`LogMsg` carry what to count and log instead of a second `ProcessPath` call. `Done` is deliberately
false for the posix chmod-755 fallback (`FixDirPerms`'s last resort when the spec apply itself
fails) — that write only restores traversability, not the spec's real mode, so the directory still
needs the ordinary apply path afterward. See `internal/apply/CLAUDE.md`'s `FixDirPerms`/`FixOutcome`
section and `internal/run/CLAUDE.md`'s "Directory processed exactly once" section.

## Entry.Ref() invariant

- Must always carry both Path and FH. Dropping FH is invisible (run succeeds with extra LOOKUP round trips).
- Structural test in run_test.go enforces `ValidatePath` and `ProcessPath` calls pass `.Ref()`.

## Ordering hazards

- Directory's own Entry goes to apply workers asynchronously while subtree is still walking. A spec that removes traverse can lock out unread children. Mitigated by CheckTraversePreserved in apply package.
- ParallelWalk emits dirs bottom-up relative to their own readdir but top-down relative to the tree — same race.

## Gotchas

- `WalkOptions.Exclude` is called once per path — caller can count inside the predicate.
- Excluded entries are NOT counted in RegisterDir's entryCount (checkpoint calibration).
- `childDir` struct exists to avoid retaining full Dirent slices during recursion (OOM fix from PR #18).
- Descriptor exhaustion (EMFILE/ENFILE) is detected and logged with ulimit guidance, not retried.
- `os.ReadDir` (kernel) sorts by name; userspace transport must sort explicitly for deterministic output.
