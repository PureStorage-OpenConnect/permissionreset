# internal/restore

`--restore-from REF TARGET`: write each object's raw `system.nfs4_acl` from a reference tree onto
the live object at the same relative path, byte for byte, only where it differs (#56). Design and
as-built deviations: `docs/design-acl-restore.md` (section 10).

## Shape

- `Run(ctx, Config, out, errOut) (Result, error)`. A non-nil error is a refusal to start (writable
  reference, failed audit-bypass proof) or a bookkeeping failure; per-object failures are counted
  in `Result.Counts` and `Result.OK()` says whether the run did everything.
- Jobs on one LIFO stack served by `Workers` goroutines: `jobList` (list a directory pair, merge-join
  the sorted listings, record skips, push children), `jobFile` (one pair), `jobSelf` (a directory's
  own ACL). `dirNode.pending` = 1 for the listing + 1 per pushed child; at zero, `jobSelf` is pushed.
  That is the post-order guarantee: a directory is written after its subtree, the root last.
- A listing failure abandons the directory (no write, not registered, nothing below touched) and
  still lets its parent proceed.

## Invariants

- Apply and validate call `Config.Prove` (default `auditproof.Prove` on `Live` at `Target`) before
  any ACL read on either side. Dry run reads no live ACL, and no reference ACL when
  `ReferenceWritable`.
- Compare is raw `bytes.Equal`, never structural: the bytes on both sides came from the array.
- Guards run only when the bytes differ: `apply.CheckRestorable` on the reference bytes, then
  `ErrAuditVanished` (live has audit, reference none; lifted by `AllowAuditRemoval`), then
  `ErrAuditedObject` (either side has audit; lifted by `AllowAuditedDACLReset`).
- Checkpoint keyed on live paths, bound by `checkpoint.RestoreHash`. Skipped pairs and successful
  pairs signal completion; refused and failed ones do not, so their directory is revisited on resume.
  Created-since and excluded children are not counted in `RegisterDir`.
- A failed evidence or log write stops further writes (`stopped`), as in `internal/run`.

## Tests

`restore_test.go`: two tmpdir trees, `aclFS` = kernel transport with ACLs in a map (tmpfs has no
`system.nfs4_acl`). One test per pairing row, per guard, post-order, proof-first, dry run,
validate, writable reference, resume, listing failure.
