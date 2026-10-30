# xlarge DACL-keeping apply on lab array A (Purity//FA 6.10.6), 2026-10-16

Requirement 2 on 6.10.6, with array load recorded. Same harness as the lab array B xlarge run
(`lab.sh /mnt/sacl-data 198.51.100.242 /sacl-data xlarge`), spec
`examples/nfsv4_sacl_keep_dacl.yaml`, kernel transport as root, 64 workers.

- Binary: `permissionreset v0.9.1-sacl-12-g3ad724e` (`3ad724e`).
- Tree: `/lab/r20261016-032223` on lab array A, 1,135,009 objects (135,009 dirs, 1,000,000 files).
- Outputs: `out-sacl-data-r20261016-032223/`, run log `xlarge-f06-20261016-032223.log`,
  client `vmstat` `xlarge-f06-20261016-032223.vmstat`, array samples
  `xlarge-f06-20261016-032223.faperf` (`fa-perf-poll.sh`, read-only REST 2.54, every ~5 s).

## Correctness

| Check | Result |
|---|---|
| apply | 1,135,009 applied, 0 errors |
| before/after dump | 0 objects missing or extra, **0 DACLs changed**, 0 SACLs off spec |
| `--apply --compare` rerun | 0 applied, 1,135,009 skipped, 15.4 s |
| `--validate` as root | 1,135,009 checked, 0 mismatch |
| `--validate` as juser (1445) | refused at preflight (`create probe file ... permission denied`: juser cannot write the tree root) |

## Throughput

| | lab array A (6.10.6) | lab array B (6.12.1), 2026-10-15 |
|---|---|---|
| apply wall time | 62.3 s | 55.4 s |
| objects/s | **~18,200** | ~20,500 |
| 78M objects at that rate (extrapolated) | ~71 min | ~63 min |

lab array A is about 11% slower than lab array B on this tree. Both arrays clear the ~900 objects/s target
by a factor of ~20.

## Load during the apply (03:30:43–03:31:45 UTC)

Array, `arrays/performance?protocol=nfs` (the managed directory `sacl-test:data` shows the
same numbers: nothing else was using file services):

- NFS ops: 72,000–81,000/s for the whole apply (mean 75,500/s over the 11 full samples), one dip
  to 57,800/s. About 4.2 NFS ops per object.
- Latency per op: 420–530 µs (one sample 753 µs; the tail sample 1,475 µs), against 3–5 µs during
  the single-threaded dumps before and after.
- Block side unchanged: ~100–600 mirrored writes/s, ~180–260 µs per write, same as idle.

Client (`vmstat`, 5 s): 80–81% idle, 16–17% sys, ~155,000 interrupts/s, no I/O wait. The client is
not the limit.

**Reading:** the op rate is flat while latency is ~100× idle, which is what a saturated server
looks like. By Little's law, 75,500 ops/s × 490 µs ≈ 37 ops in flight, below the 64 workers, so
part of each worker's time is client-side. Controller CPU is not exposed over REST on this
release (`controllers/performance` is "Not found"), so saturation is inferred, not measured. A
workers sweep (32/64/128) would settle whether 64 is past the knee.

**Update (2026-10-16, `workers-f06-20261016-111914/RESULTS.md`):** the sweep puts the knee at 64
workers and shows ~25 ops in flight at the array whatever the worker count, with flat latency.
An nconnect sweep then showed more ops in flight with no more throughput and rising latency, so
the array is the limit after all (`nconnect-f06-20261016-125210/RESULTS.md`).
