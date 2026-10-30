# PS-09 evidence A/B — a lab S200, 2026-10-29

The same `--apply` over the same tree, five evidence modes, three rounds with the
order rotated each round (`ab.sh`). Branch `feat/ps-09-sharded-evidence`, built
from `1ae8796` plus the uncommitted PS-09 change (`v0.9.7-sacl-dirty`).

- **Client:** linux01, 12 vCPU, 7 GiB, kernel 6.8.0-142, kernel NFS transport, 128 workers, batch 50.
  Not root, so caches were not dropped between runs: every run after the first is warm.
- **Array:** example.net FlashBlade c09-33 (Purity//FB 4.8.7), `jdoe-fs01` over `s200-datavip0`,
  NFSv4.1, rsize/wsize 512 KiB, no nconnect.
- **Trees:** `generate-tree --principals examples/principals_numeric.json`, in
  `jdoe-fs01/jdoe-ps09-ab` (`--scale large`, 45,410 objects) and
  `jdoe-fs01/jdoe-ps09-ab-xl` (`--scale xlarge`, 1,135,010 objects).
- **Spec:** `ab-spec.yaml`, six ACEs per object, numeric example.net principals.
- **Evidence written to** local disk (`/var/tmp`, LVM on the boot disk).

## 1.1M objects (`xl/trials.tsv`)

| Mode | Elapsed, median [range] | CPU user+sys | Peak RSS | Record bytes/object | On disk/object |
|---|---|---|---|---|---|
| off | 40.7 s [40.1–46.3] | 159 s | 126 MiB | — | — |
| `--log` only | 40.8 s [40.3–41.8] | 159 s | 127 MiB | — | 0 (nothing failed) |
| compact | 40.8 s [40.1–43.4] | 166 s | 136 MiB | 127.6 | 6.59 (gzip) |
| compact, `--evidence-gzip=false` | 41.2 s [40.2–42.9] | 166 s | 134 MiB | 127.6 | 127.6 |
| detailed | 41.0 s [40.2–41.8] | 169 s | 136 MiB | 246.9 | 7.68 (gzip) |

- The elapsed differences are inside the run-to-run spread. The 46.3 s outlier is
  round 1's first run, the only cold one.
- Evidence costs CPU, not time here: +4% (compact) and +6% (detailed) user+sys,
  all on the client. RSS grows about 10 MiB, which is the queue and the write buffer.
- Zero queue stalls in every run: local disk kept up. Backpressure under slow
  storage is shown by `TestSlowStorageAppliesBackpressure`, not by this run.
- Every manifest says `complete` and reconciles: 1,135,010 records, none dropped.
- gzip compresses compact records 19× and detailed records 32×, because paths and
  ACLs repeat.

## 45K objects (`large/trials.tsv`)

Same picture at 1.6–1.9 s per run, which is too short to separate the modes: compact
124 bytes/object raw and 6.6 gzipped, detailed 243 and 7.6.

## What this does not show

- **The cold-cache cost of `detailed`.** Its extra ACL read per object was free here,
  most likely because the client's ACL cache was warm from the previous runs. A
  cold run (root, `drop_caches`, remount) has not been measured.
- **Userspace transport.** Only the kernel transport was measured.
- **Byte counts on other trees.** Bytes per object track path length. These trees
  have paths of about 100 characters (`detailed-sample.txt`). Scale accordingly.
- **Failure behavior.** The disk-full and other failure paths are tested offline
  (`internal/evidence`, `internal/run`), not on the array.
