# internal/checkpoint

Directory-level checkpoint for resume support. SIGKILL-safe, append-only binary file.

## Files

- `checkpoint.go` — Checkpoint type, binary format, completion tracking
- `checkpoint_test.go` — core tests
- `duplicate_test.go` — duplicate completion detection tests
- `load_test.go` — resume-load equivalence with the pre-PS-10 loader (`legacyLoad`), read batching, `BenchmarkResumeLoad`

## Binary format

- 48-byte header: magic "CKPT", version u16, flags u16, 32-byte spec hash, 8 reserved
- Records: 16-byte FNV-128 hashes of completed directory paths, append-only
- On resume: reads records 4,096 at a time (64 KiB), sorts with `slices.SortFunc`/`cmp128` for binary search, truncates any partial trailing record

## Key types

- `Checkpoint` — file handle, buffered writer, completed set, pending map, duplicate detector
- `dirState` — per-directory: children counter (atomic), selfDone flag (atomic), completed guard

## Key functions

- `Open(path, specHash, resume)` — create new or resume existing checkpoint
- `RunHash(specPath, target, protocol, version, excludes)` — SHA-256 binding; change invalidates checkpoint
- `RegisterDir(dirPath, entryCount)` — register directory with expected child count
- `EntryDone(dirPath)` — one child (file/symlink) completed
- `DirApplyDone(dirPath)` — directory's own permission apply completed
- `ChildDirDone(parentDir)` — child directory completed, notifies parent
- `DirCompleted(dirPath)` — binary search for path in loaded set (resume skip check)

## Completion model (critical)

Directory complete when: children count == 0 AND selfDone == true. These are tracked SEPARATELY:

- `children` atomic counter decremented by EntryDone/ChildDirDone
- `selfDone` atomic bool set by DirApplyDone
- `completed` atomic bool guards the transition so exactly one goroutine fires it

Split tracking is THE defense against duplicate completion reports. With a single counter, a duplicate child drives it to zero early, directory is marked complete while a child is outstanding, and resume skips the subtree silently.

With split tracking, a duplicate drives children NEGATIVE — detected on the spot, directory stays incomplete (re-done on next run), and the run reports it.

## Early child handling

The walk emits a directory's children and the directory itself before it calls RegisterDir, so any
completion (EntryDone, ChildDirDone, DirApplyDone) can arrive first. `lookupOrBank` banks it in
`early` under `earlyMu`; RegisterDir publishes to `pending` and drains the bank under the same lock,
so a completion is never lost between the two. Before PS-11 (#80) early EntryDone/DirApplyDone were
dropped, leaving the directory and every ancestor pending forever. A run always ends with one bank:
the walk root's parent, notified by the root's completion and never registered. `PendingDirs()`
reports both counts for tests.

`SkipCompleted` is the resume `SkipDir` hook: DirCompleted plus a ChildDirDone to the parent, so a
skipped subtree still lets its parent complete.

## Gotchas

- `hash128` uses two independent FNV-64 hashes (FNV-64a + FNV-64), not a cryptographic hash. Collision probability is acceptable for checkpoint skip decisions.
- Background flusher runs every 5s, fsync on flush. Close stops flusher and does final flush.
- `parentPath` is string manipulation (finds last `/`), not `filepath.Dir` — no cleaning.
- `DuplicateCompletions()` returns count + first offending path. Non-zero is always an internal error, never a tree property.
- Run binding includes excludes because they change what "complete" means — a directory completed under one exclude set was walked with pruned subtrees.
- `completed` slice is sorted and read-only after Open — no lock needed for DirCompleted.
