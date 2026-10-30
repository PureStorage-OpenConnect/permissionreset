# PS-11 bounded listing A/B on a lab S200, 2026-10-29

This compares the same `--apply` over the same tree, using a `main` binary (`b4d33eb`) and the
PS-11 branch binary. Each round ran both binaries, alternating which went first, for 3 rounds
(`ab11.sh`).

- **Client:** linux01, 12 vCPU, kernel NFS transport, 128 workers. Not root, so caches were warm
  after the first run.
- **Array:** Purity//FB 4.8.7, `jdoe-fs01` over `s200-datavip0`, NFSv4.1.
- **Tree:** `jdoe-fs01/jdoe-ps09-ab-xl`, 1,135,010 objects (`generate-tree --scale xlarge`).
  Spec: six ACEs per object (`benchmarks/evidence-ab-20261029/`'s `ab-spec.yaml`).

## Round 2: final branch code (`round2/trials.tsv`)

| Binary | Elapsed, median [range] | User CPU, median | Peak RSS |
|---|---|---|---|
| main | 41.1 s [40.5–41.7] | 22.2 s | 131 MiB |
| PS-11 | 41.0 s [40.8–41.3] | 22.6 s | 133 MiB |

Throughput is unchanged within noise. User CPU is about 2% higher, and RSS is 2 MiB higher. Every
run applied all 1,135,010 objects with no errors. The trees in this fixture have small directories,
so this measures what batching costs, not what it saves. The savings show on wide directories:
peak heap for a single 200,000-file directory was 3.6 MiB batched vs 67.1 MiB whole
(`TestWideDirectoryHeapMeasure`, `docs/CHECKPOINT_SCALE.md`).

## Round 1: first branch build (`round1-prealloc/trials.tsv`)

The first build allocated a full 1,024-entry buffer for every directory. On this tree of small
directories, that cost about +3% elapsed (41.5 s vs 40.1 s, excluding the cold first run), +18%
user CPU and +17 MiB RSS. Round 2 sizes the buffer to what each read returns, which removed all
three costs.

## Not measured

- Wide directories on the array. The live tree has no directory near 200K entries, so the
  bounded-memory result is from local disk only.
- The userspace transport, which this change does not touch.
