# Live tuning sweep — S200, userspace, calibration-chosen tree (2026-08-24)

First live sweep recorded as data rather than transcribed from terminal scrollback. The raw
records are in `tuning-sweeper-live-s200-20260824/`:

- `trials.jsonl` — the Task 9b sidecar, 33 trial records plus one summary record
- `sweep-output.log` — the sweeper's terminal output
- `permissionreset-tuning.yaml` — the entry the sweep persisted

## What this run was for

To prove that `--copies 0` — the default, where calibration chooses the copy count instead of
the operator naming one — completes a userspace sweep end to end against a real FlashBlade.
Every other gate on the sweeper is offline: local tmpdir, injected seams, fake trial runners.
Nothing until this run had exercised probe → calibrate → generate → grow → sweep → confirm
against hardware.

## Setup

| | |
|---|---|
| Client | `client-b.example.net` (`198.51.100.78`), CentOS Stream 9, 4 vCPU / 16 GiB |
| Array | `lab-s200`, S200, Purity//FB 4.8.0, data VIP `198.51.100.54` |
| Export | `/bench-perms`, NFSv4.1-only, 1 TiB |
| Transport | `userspace` |
| Sweep commit | `b9179ac` |
| Spec / principals | `examples/nfsv4_complex.yaml`, `examples/principals_numeric.json`, `--safety-principal 1000@example.net` |

Invocation:

```bash
./sweep --scratch /mnt/bench-perms/sweep-9b-smoke \
  --server 198.51.100.54 --export /bench-perms --transport userspace \
  --spec examples/nfsv4_complex.yaml \
  --principals examples/principals_numeric.json \
  --safety-principal 1000@example.net \
  --scale small --copies 0 --trial-duration 10s --regenerate-scratch
```

Two deliberate deviations from the defaults, both chosen to keep load on a shared array down:
`--scale small` rather than `large`, and `--trial-duration 10s` (the floor) rather than 30s.
Neither weakens the result — see "tree growth" below, where the calibrated tree ended up at
688,141 paths regardless, an order of magnitude past what `large` nominally asks for.

## Result: success, exit 0

Winner: `connections=32 slots=0 workers=1024 batch-size=10 max-ops-per-compound=16` at
**65,814 paths/s** confirmed median.

Baseline drift 2.5% (opening 66,063, closing 64,396) → `confidence: high`. Zero errors across
every trial; no trial was rejected by the completeness floor.

## Tree growth — calibration did the thing it exists to do

The probe sized the tree at 597 copies. The opening baseline then measured 62,270 paths/s
against it, which made the tree too small to fill a 10s trial, so the sweeper grew it to 9,103
copies (688,141 paths) and re-took the baseline. That growth path — the one that reads a
measured rate and corrects its own calibration — had never run against real hardware before.

The lesson for operators: on an array this fast, `--scale` is close to advisory. The scale name
sets the probe's starting point; the measured rate decides the tree.

## Ladder

Full records in `trials.jsonl`. `cpu` is the client sample, whole-host percent.

| seq | phase | knob | value | paths/s | cpu |
|---:|---|---|---:|---:|---:|
| 1 | calibration | | | 4,485 | 6.7 |
| 2 | opening_baseline | | | 62,270 | 67.7 |
| 3 | opening_baseline | (after growth) | | 66,063 | 80.0 |
| 4 | ladder | connections | 1 | 31,441 | 89.1 |
| 5 | ladder | connections | 2 | 47,803 | 92.3 |
| 6 | ladder | connections | 4 | 59,853 | 93.9 |
| 7 | ladder | connections | 8 | 63,897 | 85.3 |
| 8 | ladder | connections | 16 | 65,803 | 80.5 |
| 9 | ladder | connections | **32** | **67,903** | 79.9 |
| 10 | ladder | connections | 64 | 65,974 | 79.9 |
| 11 | ladder | connections | 128 | 65,055 | 78.1 |
| 12 | ladder | slots | **0** | 65,090 | 79.7 |
| 13 | ladder | slots | 8 | 55,496 | 84.2 |
| 14 | ladder | slots | 16 | 62,600 | 81.6 |
| 15 | ladder | workers | 64 | 45,105 | 58.3 |
| 16 | ladder | workers | 128 | 58,391 | 72.9 |
| 17 | ladder | workers | 256 | 59,379 | 76.4 |
| 18 | ladder | workers | 512 | 62,934 | 80.4 |
| 19 | ladder | workers | **1024** | 63,219 | 81.2 |
| 20 | ladder | workers | 2048 | 58,988 | 90.4 |
| 21 | ladder | workers | 4096 | 58,031 | 94.9 |
| 22 | ladder | batch-size | **10** | 66,423 | 83.4 |
| 23 | ladder | batch-size | 50 | 61,894 | 78.4 |
| 24 | ladder | batch-size | 100 | 64,040 | 78.0 |
| 25 | ladder | max-ops-per-compound | 0 | 63,653 | 82.6 |
| 26 | ladder | max-ops-per-compound | 8 | 66,947 | 85.1 |
| 27 | ladder | max-ops-per-compound | **16** | 67,281 | 85.2 |
| 28 | ladder | max-ops-per-compound | 32 | 64,881 | 84.0 |
| 29 | ladder | max-ops-per-compound | 64 | 60,595 | 79.8 |
| 30 | confirmation | | | 65,814 | 79.9 |
| 31 | confirmation | | | 65,331 | 81.3 |
| 32 | confirmation | | | 67,594 | 81.9 |
| 33 | closing_baseline | | | 64,396 | 85.3 |

## What the CPU column is worth, and what it is not

This is the first sweep with a per-trial client CPU sample, so the CPU-against-throughput
comparison the open client-ceiling question needs is now possible from a file rather than from
scrollback. Two shapes are visible, and both should be read as leads, not conclusions:

- **`workers` past 1024 is client-bound.** 2048 and 4096 both cost throughput while pushing CPU
  to 90.4% and 94.9%. More client threads, less work done.
- **`connections` 1→4 sits at 89–94% CPU while delivering the *worst* throughput** of the ladder,
  then CPU *falls* to ~80% as throughput climbs to the peak at 32. High CPU at low concurrency
  with low throughput is the signature of spinning rather than of saturation, and it is the
  opposite of the pattern the `workers` tail shows.

The persisted entry records `client_bound: false`. That verdict is about the *winner's*
operating point, and at 79.9% CPU on 4 vCPU it is defensible — but this host is close enough to
its ceiling that the same sweep on a wider client could plausibly choose a different winner.
Worth re-running on more vCPU before treating `connections=32` as a property of the array.

A caveat on the whole column: samples are whole-host, 4 vCPU, and a sweep is the only load on
this VM. Do not compare these percentages against a run on different hardware.

## What was left on the array

`/mnt/bench-perms/sweep-9b-smoke` — the 688,141-path trial tree, **left in place**, not
cleaned up. The sweeper created it and can prove it; a later run can reuse it by dropping
`--regenerate-scratch`, or replace it by keeping the flag. Nothing pre-existing on the array was
touched: no deletes, no renames, no reconfiguration, no snapshots. The pre-existing trees listed
in the lab inventory are all still there.

Binaries and the sidecar also remain on the client at `/tmp/sweep-9b/`.
