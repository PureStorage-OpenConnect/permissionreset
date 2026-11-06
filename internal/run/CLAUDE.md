# run

One complete permission-repair or validation run, independent of the CLI.

## What this package does

`Run()` is the single entry point. It constructs the transport, sets up the walker,
dispatches batches of entries to worker goroutines, and collects results into `Result`.
The CLI (`cmd/permissionreset/main.go`) handles flags and rendering; this package owns
the orchestration.

## Key functions

- `Run(ctx, Config, out) (Result, error)` — the main entry point. Branches early
  on `cfg.Validate` to `runValidate`, otherwise runs the apply path.
- `runValidate(...)` — read-only validation. Enumerates via `walk.Prepass` with a
  no-op fix (so it works under userspace). Batches ACL reads via `GetACLBatch`
  for NFSv4 (4 per COMPOUND).
- `processBatch` (closure in both paths) — the per-batch worker. Apply path calls
  `apply.ProcessPath`; validate path pre-fetches ACLs then calls `apply.ValidatePath`.
- `lingerVerdict(lingerInputs) []string` — pure function that decides whether adding
  a deliberate write-gather linger would help. Uses Little's law on the run's own
  counters. Reports to stdout under `--rpc-stats`.
- `defaultWorkers(transport, platform) int` — measured defaults (1024 for userspace
  on FlashBlade, 64 measured for userspace on FlashArray, 128 fallback).

## Data flow

```
Config -> transport (kernel or nfs41) -> walk.Prepass (producer goroutine)
  -> entryCh -> batching loop -> processBatch goroutines (semaphore-capped)
  -> stats.Stats (atomic counters) -> Result
```

## Two paths, one shape

Apply and validate share the same batch-dispatch shape (semaphore, WaitGroup, copy-on-dispatch)
but are separate functions because validate has no checkpoint, no traverse-lockout check, no
compare mode, and uses `GetACLBatch` for pre-fetching. Validate reads every object, so an nfsv4
validate always proves the audit bypass first (`needsAuditBypassProof`): a spec with `sacl:` runs the
full `runPreflight`, because a privilege or retention failure would otherwise never surface on a
read-only run; any other nfsv4 spec runs only `proveAuditBypass`. A posix validate has no probe.

## sacl: preflight

`runPreflight` proves audit-bypass privilege (`apply.ProveAuditBypass`, PS-02/#71) on a disposable
probe target BEFORE any live ACL read: the root check (`apply.CheckKeepDACLTarget`) for a
DACL-keeping spec, and every object's read for a DACL reset that keeps auditing (PS-04: an `acl:`
rule with no `sacl:` key, without `--sacl`). An unprivileged read has been observed on at least one
array to empty inherited auditing, so without this ordering the read meant to protect a SACL could
itself destroy it. A failure from
`ProveAuditBypass` (including `ErrAuditPrivilege`/`ErrAuditNotRetained`) fails the run closed without
ever touching root. This must stay the first thing `runPreflight` does; see
`TestPreflightProvesAuditBypassBeforeAnyLiveRootRead` and
`TestPreflightRefusesWithoutTouchingLiveRootWhenBypassProofFails` in `unmapped_test.go`.

`runPreflight(tr, cfg, errOut)` is the one call site for `apply.ProbePreflight`, used by both the
apply path (`!cfg.DryRun`) and `runValidate` (gated on any `sacl:` key, `sacl: []` included, via
`cfg.Spec.SaclRules()`; a spec whose only `sacl:` keys are empty is probed with a placeholder `U`). It renders
`apply.ErrAuditPrivilege` and `apply.ErrAuditNotRetained` with their own operator text before
falling back to the generic "preflight probe failed" message. After a passing probe on an nfsv4
apply (not `--validate`), `unmappedReadBackWarning` runs `apply.ProbeUnmappedPrincipals` and prints a
WARNING naming any spec principal the array reads back as nobody. It never fails the run, and a
failed probe is itself only a WARNING. `Run` prints the audit-policy NOTE
unconditionally, before the transport is even constructed, whenever `cfg.Spec.UsesSacl()` -- dry
run and `--validate` included, since the NOTE is true regardless of what the preflight finds.

## DACL-keeping rules (`sacl:` with no `acl:`)

A rule with `sacl:` and no `acl:` (`spec.RulePerms.KeepDACL()`) used to be refused here before the
walk even started (plan v3 commit 1's interim guard, since the per-object apply did not exist yet).
That refusal is gone as of commit 4: `apply.applyNFSv4` now really implements it
(`internal/apply/CLAUDE.md`'s "DACL-keeping apply" section), so `Run` walks a DACL-keeping spec like
any other NFSv4 spec. Directories need no special casing here either: `popts.DirACL` already returns
`nil` for a KeepDACL rule (its `perms.ACL` is empty by definition), so the fused `ReadDirSetACL`
path never fires and every KeepDACL directory flows through the same `entryCh` -> `apply.ProcessPath`
route a file does. Two throughput issues specific to a large KeepDACL run (every directory an extra
apply call, every file a per-object GetACL) are covered below, in "Directory processed exactly once"
and "KeepDACL batch GetACL pre-fetch" -- both are general run.go behavior, not KeepDACL-specific
code paths, but KeepDACL is what made them visible at 78M-object scale.

## DACL reset that keeps auditing (PS-04)

An `acl:` rule with no `sacl:` key (`RulePerms.PreserveSACL()`) reads each object before writing
(`apply.applyPreserveSACL`), so it is left out of the fused `DirACL` READDIR write and joins the
apply path's `GetACLBatch` pre-fetch alongside `KeepDACL()` rules. `Result.AuditKept` counts objects
whose audit ACEs were carried forward, including directories the pre-pass fixed.

## Directory processed exactly once

`popts.Fix` (the closure passed to `walk.Prepass`) wraps `apply.FixDirPerms`, which runs the real
spec apply (`ProcessPath`) as part of restoring a non-traversable directory. Before this, that
directory's `Entry` still flowed into `entryCh` unflagged and the apply worker called `ProcessPath`
on it again -- a second GETATTR+SETATTR (or chmod) with the identical result. On a tree being
repaired for the first time this is the common case, not the edge case: most directories fail their
initial readdir, so most directories used to be processed twice.

The fix threads `apply.FixOutcome.RealApply` through as `walk.FixResult` on the directory's `Entry`
(`Entry.Fix`), and the worker checks `e.IsDir && e.Fix.Done` right next to the existing
`e.ACLApplied && e.IsDir` check -- same shape, same place, same checkpoint/stats handling
(`st.IncApplied`/`IncSkipped`, `ckpt.DirApplyDone`), no second `ProcessPath` call. The real apply's
own audit line was already written through `Prepass`'s `logFunc` (routed to `writeAudit` via
`routeLog`, unchanged); the worker only writes its own line for the one case `FixDirPerms` leaves
silent -- an already-correct directory, where `Fix.LogMsg` is empty.

`Fix.Done` is false (so the worker still does its own `ProcessPath` call, unchanged) in exactly two
cases: the fast path never called `Fix` at all (directory was already traversable -- the common
steady-state case on a second run), or `Fix` only ran the posix chmod-755 fallback (restores
traversability, not the spec's real mode). Both are the same number of apply calls as before this
change; only the failure-then-repair case loses its second call.

## KeepDACL batch GetACL pre-fetch

`processBatch` (the apply path's, not validate's) now does a second pass over each batch after the
lstat/symlink/already-applied-dir filtering: it collects every remaining entry whose
`cfg.Spec.EffectivePerms(path, isDir).KeepDACL()` is true (a `sacl:`-with-no-`acl:` rule, the one
apply that reads the object's current ACL before writing) and reads them with one `tr.GetACLBatch`
call, the same batching `runValidate` already does for `--validate`. The result is handed to
`apply.ProcessPath` through a per-entry copy of `opts` with `CachedACL` set, so `applyKeepDACL` uses
it instead of its own `GetACL`. Entries whose rule is not `KeepDACL()` are left out of the batch --
their apply never reads before writing, so there is nothing for a cached read to save. A dry run
skips the pre-fetch entirely (`useACLBatch` is false), since `applyKeepDACL` does not read on a dry
run (review item 7); `Run` prints a NOTE saying so when the spec has any KeepDACL rule.

A failed `GetACLBatch` is logged (`"ERR: batch GetACL (%d entries): ..."`) and `cachedACLs` is left
empty for that batch: every affected entry falls through to `apply.ProcessPath` with no
`CachedACL`, so `applyKeepDACL` does its own per-object `GetACL` (and fails that object on its own
if the transport itself is the problem) rather than ever writing from a read that never happened.

## Evidence (PS-09)

`Config.Evidence` is an `*evidence.Sink` the caller opens; `Run` closes it in a defer registered
before anything else (so it runs after the checkpoint close) and puts the manifest in
`Result.Evidence`. Every record goes there -- per-object lines from `writeAudit` and the `ERR:`
lines `writeLog` also sends to `Config.Log` -- so the evidence is one ordered stream.

A refused `Sink.Write` or a failed `Config.Log` write sets `stopMutations`. All three write sites
consult it: `walk.PrepassOptions.Stop` (no further readdir, fix or fused READDIR+SETATTR), the
main loop (drains the channel, counts `NotAttempted`) and `processBatch` (skips `ProcessPath`).
Cancellation does NOT do this -- Prepass keeps fixing directories while a cancelled run drains --
so the two are separate flags. The run then fails, `Result.EvidenceStopped` is set and the summary
marks enumeration incomplete. Changes in flight when the sink failed are bounded by the queue plus
two per worker and counted as `records_in_flight` in the manifest; see
`TestEvidenceFailureStopsMutation`.

The evidence is `complete` only when `reachedEnd` was set (the apply path finished, or
`runValidate` returned) with no stop and no interruption. Apply errors do not make it incomplete:
they are recorded. The detailed profile widens the nfsv4 `GetACLBatch` pre-fetch to every entry
and appends `before=<ACL>`, but hands `CachedACL` to the apply only for rules that read anyway
(`applyReads`), so the write is unchanged.

## Partition hooks (PS-12)

`Config.Handoff` (absolute dirs another partition owns) is compiled by `newHandoff` (`handoff.go`)
into an exact-path set consulted first in both `countingExclude` predicates: a hit prunes the dir,
writes `HANDOFF:` to evidence and lands in `Result.HandedOff`, never in `Stats.Excluded`. Refused
with `--pfind`. `Config.ExcludeRoot` anchors slash excludes (default `Root`). Both enter the
checkpoint binding via `handoffSet.binding`, which returns the exclude list unchanged when neither
is set, so existing checkpoints stay valid.

## Invariants and gotchas

- `processBatch` copies the batch slice before dispatch (`b := make; copy`). The
  reusable `batch` slice is reset to `[:0]` immediately.
- Cancellation drains `entryCh` without processing, so the producer goroutine
  always finishes and Run always owns all goroutines that touch the transport.
- Transport close is advisory (WARNING not ERROR). Checkpoint close is fatal
  (ErrCheckpointUnflushed) because a stale checkpoint causes silent wrong answers
  on resume.
- `--resume` forces `--compare` on. This is set in Run, not the CLI.
- The `closeTransport` and `closeCheckpoint` package vars are test seams — tests
  replace them to inject close errors.
- `TestApplyCallSitesCarryTheFilehandle` is a regex-based structural test that
  reads run.go source and asserts that apply call sites pass `.Ref()` not
  `transport.Ref{Path: e.Path}`. Update the regex if loop variables are renamed.

## Test seams

- `closeTransport` / `closeCheckpoint` — package-level vars replaced by tests
- `processCPU()` — platform-gated (`rusage_unix.go` / `rusage_other.go`)
- Tests use `writeSpec()` to create a loaded spec for Run calls

## Related packages

- `apply` — `ProcessPath`, `ValidatePath`, `ProbePreflight`, `CheckTraversePreserved`
- `walk` — `Prepass`, `ParallelWalk`, `Pfind`; producer side of entryCh
- `stats` — atomic counters and progress reporter
- `checkpoint` — directory-level resume
- `nfs41` — userspace transport, `GetACLBatch`, platform detection
- `transport` — `Transport` interface (kernel or nfs41)
