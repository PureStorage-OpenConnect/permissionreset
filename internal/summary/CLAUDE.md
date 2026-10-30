# summary

Machine-readable JSON summary of a permissionreset run.

## What this package does

Defines the `RunSummary` struct and writes it as indented JSON. The stdout output
is human-readable and changes across releases; this is the stable, versioned artifact
for automation harnesses and support bundle analysis.

## Key types

- `RunSummary` — top-level struct with `SchemaVersion`, tool identity, target,
  transport, spec digest, options, object counts, errors, pre-pass stats, phases,
  and wall-clock timestamps.
- `Tool`, `Trans`, `Spec`, `Opts`, `Counts`, `Errs`, `Pre`, `Phase` — nested
  sub-structs, each with JSON tags.
- `Verification`, `DimensionResult`, `Coverage`, `Accounting`, `ShardRef`
  (`verification.go`) — the evidence contract: a closed set of dimensions, each
  with fixed `proves`/`does_not_prove` text, a state derived from coverage, and
  one verdict derived from the required dimensions.

## Key functions

- `WriteFile(path)` — atomic write: temp file in same dir, fsync, rename. Avoids
  a polling harness reading a partial JSON file.
- `FileDigest(path) (string, error)` — streaming SHA-256 of a file (used for spec
  identity).
- `Stamp(start, end)` — records UTC RFC 3339 timestamps.
- `NewDimension`, `NewVerification`, `DeriveState`, `DeriveVerdict` — build a
  verification record; `NewVerification` lists unsupplied dimensions as `not_checked`.
- `Check()` / `Decode(b)` — consistency check (also run by `WriteFile`, which
  refuses an inconsistent summary) and a decoder that migrates v1.

## Invariants

- `SchemaVersion` (const 2) bumps only when a field changes meaning or disappears.
  Adding a new field does not bump it. v2 bumped because `verification.verdict`
  became the answer to "did this run verify"; every v1 field is unchanged, and
  a migrated v1 file is never `verified` (it has no unreadable count).
- `verified` requires every required dimension `matched`: full, unsampled
  coverage of a completely enumerated scope. A repair run is `not_requested`.
- Size is bounded by the dimension list and config, never object count;
  per-object evidence goes in shards referenced by `records`.
- Fixtures: `testdata/valid` (one per outcome) and `testdata/invalid` (one per
  rejection rule); regenerate with `go test ./internal/summary -update`.
- Every field is filled by `cmd/permissionreset`; this package never touches the
  filesystem except in `FileDigest` and `WriteFile`.
- `FilesystemID` is st_dev (kernel) or FATTR4_FSID (userspace); `FilesystemIDSource`
  labels which. The two are not comparable across transports.

## Consumer

- `cmd/permissionreset/main.go` — constructs and writes the summary at run end
