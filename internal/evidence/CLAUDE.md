# internal/evidence

Per-object evidence for one run (PS-09, #78): a bounded queue in front of one writer goroutine,
size-bounded shards (optionally gzipped) with a SHA-256 each, and a manifest that says whether the
evidence is complete. Operator-facing description: `docs/evidence.md`.

## Files

- `evidence.go` — `Sink`, `Options`, `Manifest`, `Shard`, profiles
- `evidence_test.go` — fault injection (ENOSPC, short write, sync, close, second-shard failure), cancellation, rotation and digest round-trip, backpressure

## Contract

- `Write` blocks while the queue is full (backpressure; RAM is the queue plus a 1 MiB buffer and
  gzip state, not tree size). It returns false once the sink failed or closed; the caller must not
  make the change that record describes. `internal/run` stops the whole run on the first false.
- Every write, flush, gzip close, `Sync` and `Close` error is checked. The first one fails the
  sink. The shard it happened in is left out of the manifest and its records count as dropped,
  because a reader cannot trust a file whose write failed partway.
- `RecordsSubmitted == RecordsWritten + RecordsDropped` always. `RecordsInFlight` is the subset of
  dropped records that never reached a shard (queued at failure or submitted after).
- `Close(runComplete, reasons...)` drains, closes the last shard, and writes `manifest.json`
  atomically (temp, fsync, rename). Status is `complete` only with no sink error, `runComplete`
  true and no reasons.
- `Open` refuses a non-empty directory, and shards are created `O_EXCL`, so two runs never share a
  manifest.

## Not promised

No per-record fsync. A crash loses whatever sat in the queue and buffers, and every record in a
shard not yet rotated may be unsynced. Durable recovery evidence is PS-17.

## Test seam

`Options.Create` replaces the shard file opener; `internal/run` tests use it too.
