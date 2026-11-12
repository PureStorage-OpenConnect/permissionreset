# Performance

**Every number below is labeled measured or extrapolated.** Measured numbers state the array model, client CPU count, and cache state they were taken under; numbers from a different environment or scale are not directly comparable. Full detail, methodology, and raw logs: `../benchmarks/PERFORMANCE.md`, `../benchmarks/METHODOLOGY.md`, and the dated files under `../benchmarks/`.

## Measured: transport comparison (S500R1, 12-CPU client, cold cache)

At 8 connections (`--connections 8`), FlashBlade S500R1, 12-CPU client, cold cache, `vers=4.1,nconnect=16,noatime,nodiratime`, 1,104,409-object tree: source `../benchmarks/control-s500r1-fastencode-20260822/results.tsv`.

| Transport | ops/sec | Speedup over kernel |
|---|---|---|
| kernel | 118,080 | 1x |
| userspace | 177,448 | **1.50x** |

Earlier same-day runs in `../benchmarks/control-s500r1-20260822/` and the `fastdecode-run*` directories measured lower userspace rates (55K–152K at c8) before the encoder/decoder wiring in this run — do not average across those directories, they are different points in the tool's own development, not repeats of the same measurement.

## Measured: transport comparison (S200, 4-vCPU client)

On an S200 array with a 4-vCPU client, `examples/nfsv4_basic.yaml`, 1,135,009-object tree, cold cache, 16 connections: kernel 33,558/33,273 ops/sec, userspace 54,635/55,305 ops/sec (two interleaved passes each) — userspace is **1.64x** the kernel transport. Source: `../benchmarks/decoder-wiring-s200.md`, which explicitly supersedes the *cold-cache* userspace numbers in `../benchmarks/userspace-transport-control-s200.md`: that earlier control run (before GETATTR/SETATTR were wired into the hand-written decoder) measured userspace as *slower* than kernel on the same S200/4-vCPU client (~31–33K userspace vs. 34,369 kernel cold, 43,212 kernel warm). Both files matter: the later one is the current transport's real number, the earlier one is why "S200" alone is not enough context — it also depends which commit was benchmarked.

These two speedup ratios (1.50x on S500R1/12-CPU, 1.64x on S200/4-vCPU) are the only cross-transport comparisons in this document that are directly measured end-to-end; do not average them into a single number without checking the source files for concurrency, cache-state, and commit differences. Per `../benchmarks/decoder-wiring-s200.md`'s own caveat, the S200 result does not say what the same decoder change is worth on the 12-CPU S500R1 client — that client showed 38% idle in the userspace arm, meaning something other than client CPU may be the limiter there.

## Measured: large-scale apply (1.1M objects, S500, 12-core client)

Dataset: 1,104,409 objects (104,409 directories, 1,000,000 files), FlashBlade S500, `vers=4.1,nconnect=16,noatime,nodiratime`. Cache state (cold/warm) not recorded for this run — see `../benchmarks/PERFORMANCE.md`.

| Protocol | Main pass ops/sec | Overall ops/sec | Elapsed |
|---|---|---|---|
| NFSv4 ACL (setxattr) | 105,873 | 81,886 | 13.5s (pre-pass 3.1s) |
| POSIX mode bits (chmod) | 116,754 | 86,209 | 11.6s (pre-pass 3.0s) |

`--validate` (kernel): 98,403 overall ops/sec, 1,104,409/1,104,409 match, 11.2s. `--validate` (userspace, S500R1, with 4× GETATTR COMPOUND batching): 133–140K checks/sec on 1,135,010 objects, 8.1–8.5s. `--compare` (all match, 0 applied): ~13s.

## Measured: 110M objects (S500, 12-core client)

The one benchmark that actually ran at large scale: 109,650,011 objects (~13.5M directories, ~96M files) on FlashBlade S500, 12-core client. Apply (first run): 82,628 main-pass ops/sec, 65,638 overall ops/sec, 27.8 minutes total (pre-pass 343.5s across 13.5M directories). Zero errors. Source: `../benchmarks/PERFORMANCE.md`.

## Measured: FlashArray SACL mode (1.1M objects)

`--sacl` on one FlashArray: 1.1M objects in about a minute (18,000–20,500 objects/s, kernel
transport, 64 workers). More workers or `nconnect` do not help; the array is the limit. See
[spec-guide.md](spec-guide.md#audit-aces-sacl-on-flasharray).

## Extrapolated: 1B and 10B objects — NOT measured

The following are **extrapolations only**, carrying the measured 110M overall rate (65,638–66,000 ops/sec) forward under the assumption of linear scaling and an unsaturated array. Neither assumption has been tested past 110M objects.

| Scale | Apply | Validate |
|---|---|---|
| 1B (extrapolated) | ~4.2 hours | ~3.2 hours |
| 10B (extrapolated) | ~42 hours | ~32 hours |

Do not treat these as SLAs or capacity-planning commitments — they are back-of-envelope projections from a single 110M data point, not a second measured benchmark.

## Historical note: 1B/pre-fusion numbers

Earlier revisions of the README and `../benchmarks/PERFORMANCE.md` carried an "Extrapolation to 1 Billion Objects" table computed before the walk and pre-pass were fused into one sweep, and before the 110M run existed. That table is superseded by the 110M measured result and the extrapolation table above; treat any older 1B figure you find elsewhere in this repo's history as stale.

## System resource usage (1.1M objects, NFSv4, S500)

| Metric | Value |
|--------|-------|
| CPU | 728% of one core (12.9s user, 85.2s system) |
| Memory (RSS) | 26 MB |
| Context switches | 4.1M total (3.8M voluntary) |
| Errors / NFS retransmits | 0 |

Memory is flat in tree size: the pre-pass streams directories instead of materializing each level, so 1.1M objects cost 26 MB, and the 110M run's peak RSS is expected (not separately re-measured) to be similarly flat.

## What Limits Throughput

Client CPU in the kernel syscall path — for the kernel-transport 1.1M run, 85s system time against 13s user time. A standalone microbenchmark drove `setxattr` to 190K ops/sec at 256-way concurrency on the same S500 array, so the array and network were not the bottleneck in that test; headroom remained above what the full kernel-transport pipeline reached. The userspace transport's 1.50x–1.64x gain over kernel is consistent with the kernel syscall path being a real, removable cost. More client CPU or multiple clients should scale further, but that has not been measured beyond the single-client numbers above.

## Mount Recommendations

```bash
mount -t nfs -o vers=4.1,nconnect=16,noatime,nodiratime 192.0.2.50:/share /mnt/fb
```

- `nconnect=16` — opens 16 TCP connections to FlashBlade, distributing metadata ops across blades via FIOM/XFM
- `noatime,nodiratime` — prevents atime updates on stat calls. Measured on an earlier 4-core/4GB client at 46K objects: +64% for POSIX chmod (which reads current mode before writing), +5% for NFSv4 setxattr (which always writes). Not re-measured on the current 12-core client or since the stat-in-worker change; treat the percentages as directional, not current.
