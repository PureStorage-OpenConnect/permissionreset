# internal/partition

Partition manifests for `permissionreset --partitions` (PS-12, #81). Operator doc: `docs/partitions.md`.

## Files

- `manifest.go` — `Manifest`/`Plan`/`Job`, `Load` (parse with KnownFields, resolve paths, validate),
  `cleanRel`, `checkOverlap`; builds the implicit `residual` job first
- `identity.go` — `CheckIdentity`: kernel-only lstat of every root (symlink, alias by dev/ino,
  `--one-filesystem` boundary); `lstat` is a test seam
- `state.go` — `State`/`PartState`/`Attempt`/`Counts`, atomic `save`, `lockDir` (flock)
- `runner.go` — `Execute` (serial driver), `RunFunc` seam, `recordAttempt`, `aggregate` → `Report`

## Invariants

- Jobs are residual first, then manifest order. The residual's `Handoff` is every partition root;
  `internal/run` prunes those and reports them in `Result.HandedOff` (not `Stats.Excluded`).
- `Load` reads nothing under the root; `CheckIdentity` is the only tree access and is kernel-only.
- A partition path is relative, already clean, strictly under root, glob-free, and not excluded.
  Overlap check compares each sorted path with every later one sharing its prefix ("a-b" sorts
  between "a" and "a/b").
- State without `--resume` is refused, never overwritten. Resume refuses a changed manifest digest,
  mode, tool version, transport (identities present/absent) or partition root dev/ino.
- Checkpoint is per partition (shared by attempts); evidence and error log are per attempt
  (`attempt-N/`), because an evidence dir must be new.
- Reachability is judged across residual attempts in `aggregate` (a resumed residual may skip a
  completed ancestor and with it a handoff).
- Dry run: no state, no checkpoint, no evidence, nothing created under `state_dir`.
- The command (`cmd/permissionreset/partitions.go`) owns flag conflicts, per-root canonicalization, and
  setting aside an `ErrCheckpointUnflushed` checkpoint as `checkpoint.untrusted-<unix>`.
