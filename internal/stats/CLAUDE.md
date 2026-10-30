# stats

Atomic counters and live progress reporter for permission repair runs.

## What this package does

Provides lock-free counters (`sync/atomic.Int64`) for applied, skipped, errors,
enumerated, symlinks, and excluded. Used by `internal/run` and read by
`cmd/permissionreset` for JSON summary output.

## Key types

- `Stats` — struct of `atomic.Int64` fields. Increment with `Inc*()` methods.
- `Snapshot` — plain `int64` struct. Taken with `Stats.Snapshot()` for reading
  consistent values.
- `Reporter(w, interval, stop)` — goroutine that prints a carriage-return progress
  line every `interval` until `stop` channel closes.

## Gotchas

- `Enumerated` counts entries dispatched from the main loop, not entries processed
  by workers. An interrupted run's Enumerated may exceed Applied+Skipped+Errors.
- `Excluded` counts excluded directories once; their subtrees are never enumerated.
- `Reporter` writes `\r` (carriage return) for in-place updates. Redirect stdout
  to a file and you get one long line.
- No `IncValidated` — validate path reuses `IncEnumerated` and tracks match/mismatch
  counts in `internal/run` directly.

## Consumers

- `internal/run` — owns the `Stats` instance, passes `Snapshot` into `Result`
- `cmd/permissionreset` — reads `Result.Stats` for JSON summary
