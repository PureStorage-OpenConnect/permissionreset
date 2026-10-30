# Checkpoint size and memory at scale

Source: `internal/checkpoint/checkpoint.go`. Resume load time and memory at 1M, 10M
and 100M directory records are measured by `BenchmarkResumeLoad`
(`internal/checkpoint/load_test.go`, PS-10, #79); everything at larger scale is
extrapolated from those, and none of it is from a live million/billion-object run.
See "What was measured" at the bottom.

## Format, as it actually is

The checkpoint file records **completed directories only**. It does not have
one record per file. This is the single fact that makes the rest of the math
tractable: checkpoint size tracks directory count, not total object count.

```
[ 48-byte header ][ 16-byte record ][ 16-byte record ] ... (append-only)
```

- **Header** (`headerSize = 48`): 4-byte magic `"CKPT"`, 2-byte version,
  2-byte flags, 32-byte SHA-256 of the spec+run-binding hash, 8 bytes
  reserved. Written once at `Open()` for a fresh run.
- **Record** (`recordSize = 16`): a 128-bit hash of the directory's path
  (`hash128`: two independent 64-bit FNV hashes, not a cryptographic hash).
  **Fixed size regardless of path length or depth** — a path is hashed down
  to 16 bytes before it ever reaches disk, so there is no path-length
  dependence and no string dedup to reason about. One record is appended
  per directory the moment it is marked complete (`markComplete`,
  `completeDir`); files/symlinks never get a record — their completion only
  decrements an in-memory counter (`EntryDone` → `childDone` → `dirState.children`).
- **Write pattern**: strictly append-only, buffered through a 64KB
  `bufio.Writer`, flushed+fsynced every `flushInterval = 5s` by a background
  goroutine, plus a final flush in `Close()`. No rewrite, no compaction, no
  in-place update — a directory is written exactly once, when it first
  completes.
- **No path/string storage on disk** — since only the hash is stored, the
  file cannot answer "which directories are done," only "is this specific
  path done" (via re-hash + binary search). There is no reverse index and
  none is needed for the tool's access pattern.

## In-memory structures

- `completed [][16]byte` — loaded once at resume, **one 16-byte fixed-size
  array per completed directory**, in a slice pre-sized to the exact record
  count (`make([][16]byte, completeRecords)`), so there is no
  append-growth doubling overhead. It is filled through one fixed 64 KiB
  read buffer, so loading adds no second full-size copy. This is the
  dominant, scale-sensitive memory structure and it is **read-only for the
  rest of the run** — it's sorted once (`slices.SortFunc` with `cmp128`)
  and then only binary-searched (`DirCompleted`). This is what determines
  RSS at resume.
- **Resume memory is not streaming memory.** The walk and apply stages
  stream: what they hold is bounded by worker and queue settings, not by
  tree size (see "Walk and checkpoint memory bounds" below). The `completed`
  slice is the opposite: a resumed run holds `16·D` bytes for every
  directory any earlier run finished, for the whole run, and a fresh run
  holds none. A resume of a 1B-directory checkpoint needs ~16 GB resident
  however small the remaining work is. Partitioning (`--partitions`,
  PS-12, #81) is what bounds it, to the failed partition's directories; a
  faster load does not.
- `pending sync.Map` (path → `*dirState`) holds directories registered but
  not yet complete, and `early` (path → banked counts, under a mutex) holds
  completions that arrived before their directory registered. Both are
  bounded by work in flight, not by tree size; the next section gives the
  bounds. Before PS-11 (#80) that was not true: a completion that beat
  `RegisterDir` was dropped, the directory stayed in `pending` for the rest
  of the run and was never recorded, and neither were its ancestors, so
  `pending` grew with the tree and the root was never written.

## Walk and checkpoint memory bounds (PS-11)

What a run holds at once, for `W` workers, batch size `B`
(`walk.DefaultReadDirBatch`, 1,024) and tree depth `H`:

| Structure | Bound | Grows with |
|---|---|---|
| Listing buffer (kernel transport) | `B` Dirents per directory being listed, at most `W + 1` listings | nothing in the tree |
| Open directory handles | `W + 1`: one per listing, closed before descending | nothing in the tree |
| Walk goroutines | `W` plus the producer | nothing in the tree |
| `entryCh` queue | `100·W` entries | nothing in the tree |
| Child directory refs | one per *subdirectory* of each directory still being descended | a directory's subdirectory count, and `W·H` frames of inline recursion |
| `pending` | directories with an entry queued or in flight, plus their ancestors | `H`, and the queue |
| `early` | directories emitted but not yet registered (one per frame still descending), plus one for the walk root's parent | `W·H` |

The listing buffer is the one PS-11 bounded. Measured on linux01 (local
disk, one directory, ~100-byte paths, `TestWideDirectoryHeapMeasure`):

| Files in the directory | Whole listing (before) | Batched (after) |
|---|---|---|
| 20,000 | 6.8 MiB peak heap, 18 ms | 3.2 MiB, 12 ms |
| 200,000 | 67.1 MiB, 242 ms | 3.6 MiB, 117 ms |

Batching is also faster here because it no longer sorts the listing. On
the array (c09-33, 1.1M objects in small directories, kernel transport) a
full `--apply` was unchanged: 41.0 s vs 41.1 s median, user CPU +2%, RSS
+2 MiB (`benchmarks/walk-bounded-ab-20261029/`).
What is still not constant:

- **Subdirectory refs.** A directory's child *directories* are collected and
  descended after its listing closes. Descending while listing would hold
  the handle open across the recursion, trading this memory for handles that
  grow with depth. A directory of 1M subdirectories still holds 1M refs
  (~130 bytes each on the kernel transport) until they are all dispatched.
- **Depth.** Inline recursion (no free worker token) stacks frames, and each
  keeps its remaining subdirectory refs and an `early` entry: `W·H` frames.
- **The userspace transport.** It still materializes and sorts each listing
  (`nfs41.Client.ReadDir`); it does not implement `transport.DirBatcher`.
- **Order.** Batched listings are in getdents order, not sorted. Nothing
  depends on per-directory order: the checkpoint counts children, and
  parallel workers interleave output anyway.

Completion fixes made by the same audit, all of which used to leave a
directory and its ancestors permanently pending (safe, since a resume redid
them, but unbounded):

- completions arriving before `RegisterDir` are banked, not dropped;
- a resume's skip of a completed directory reports it done to its parent
  (`Checkpoint.SkipCompleted`);
- a child directory on another filesystem (`--one-filesystem`) is no longer
  counted among its parent's children, matching excludes;
- a listing that fails partway is an error and its directory is left
  unregistered, so it is never recorded complete.

## The math

Two unknowns need assumptions, stated explicitly:

- **Directory fraction of the namespace.** `internal/treegen` doesn't
  publish an exact dir:file ratio — its scale table
  (`small: 10 copies × 50 seed files`, ..., `huge: 50000 copies × 2000 seed
  files`, max depth 6–14, 15 scenarios of which 11 are directory scenarios)
  implies a moderately bushy tree (10–15 subdir names per level) but doesn't
  hand back a clean percentage. Following the task's own guidance, this doc
  assumes **10% of namespace objects are directories** (i.e. for every 9
  files there is 1 directory) as the planning figure. This is an assumption,
  not a measurement — real ratios in flat-heavy or deeply-nested trees will
  shift the numbers roughly linearly with dir fraction.
- **Path length** doesn't matter for on-disk/in-memory size (fixed 16-byte
  hash), so it doesn't affect the load either: records are read 4,096 at a
  time whatever the paths were. It's carried in the table only to make clear that it
  changes nothing.

Let `N` = total objects (files + dirs), `D = 0.10 × N` = directory count.

- **File size** = `48 + 16·D` bytes
- **Resident memory at resume** ≈ `16·D` bytes for the `completed` slice
  (essentially identical to file size, since it's the same 16-byte records
  held flat in memory) + negligible fixed overhead. No 2x/3x slice-growth
  multiplier because the slice is exactly pre-sized before filling.

| N (objects) | D = dirs (10%) | Checkpoint file size | Resume RSS (completed slice) |
|---|---|---|---|
| 1,000,000 | 100,000 | ~1.6 MB | ~1.6 MB |
| 100,000,000 | 10,000,000 | ~160 MB | ~160 MB |
| 1,000,000,000 | 100,000,000 | ~1.6 GB | ~1.6 GB |
| 10,000,000,000 | 1,000,000,000 | ~16 GB | ~16 GB |

(Path length columns are omitted from this table because — unlike a naive
"one record per file with embedded path" design — this format's size is
path-length-invariant. If the format ever changes to store paths, sizes
would scale with `48 + D×(16 + avg_path_len)`, e.g. at 128-byte average
paths at D=1e9 that becomes ~144 GB instead of ~16 GB — worth remembering
if this format is ever revisited.)

## Structural limits — what breaks before size does

1. **Sorting is the load-time cost; reading no longer is.** Until PS-10 the
   load made one 16-byte `read(2)` per record on the raw `*os.File` and
   then sorted with the reflection-based `sort.Slice`. It now reads
   `loadChunkRecords` = 4,096 records (64 KiB) per call into one reused
   buffer, and sorts with `slices.SortFunc` on `cmp128`, which compares the
   two 64-bit halves big-endian (the same order as comparing bytes).
   Measured at 10M records: the old load took 10.7 s, the new one 3.1 s, of
   which the sort is about 3.0 s. Reading is now a fraction of a second.
   The sort is still `O(D log D)` comparisons, so it is what grows fastest.

2. **Memory is unchanged by PS-10, by design.** Old and new loaders both
   keep exactly `16·D` bytes (152.7 MiB at 10M records, measured); the new
   one adds a 64 KiB buffer and no full-size copy. A radix sort could be
   several times faster but needs either a second `16·D` buffer or an
   in-place variant; it was not done, since the issue rules out a second
   copy without measured justification and the load at 100M (38.5 s,
   measured) does not yet justify one.

3. **No structural ceiling from the format itself.** There's no map that
   grows with total tree size (`pending`/`early` are bounded by
   work in flight, not N), no per-file record, no string storage, and the
   append-only write path has no compaction or rewrite cost — one
   `bufio.Writer` handles arbitrarily many appends at the same fixed
   64KB-flush cadence regardless of D. So the format itself scales cleanly
   to billions of directories; the two items above are implementation
   details in the load path, not format limits.

4. **Binary search for `DirCompleted`** during the run itself is
   `O(log D)` per lookup against the in-memory sorted slice — at D=1e9 that
   is ~30 comparisons per directory visited, negligible per-call cost, but
   it does mean every directory visited during a resumed run pays a cache
   trip through a gigabytes-large slice; not a bottleneck, just noted for
   completeness.

## Resume load time summary

Measured rows are `BenchmarkResumeLoad` on linux01 (Xeon Gold 6338, 12 vCPU,
warm page cache), Go 1.25: `-benchtime 3x` for 1M and 10M records,
`-benchtime 1x` for 100M (`CHECKPOINT_BENCH_100M=1`, fixture under
`TMPDIR=/var/tmp`, since the 1.6 GB file does not fit this host's `/tmp`). The
1B row scales the measured 100M load by `D log D`; it is an estimate and was
not run.

| N (objects) | D (dir records) | Old load (per-record read + `sort.Slice`) | New load (64 KiB reads + `slices.SortFunc`) | Resident `completed` |
|---|---|---|---|---|
| 10,000,000 | 1,000,000 | 1.01 s (measured) | 0.27 s (measured) | 15.3 MiB (measured) |
| 100,000,000 | 10,000,000 | 10.7 s (measured) | 3.1 s (measured) | 152.7 MiB (measured) |
| 1,000,000,000 | 100,000,000 | 121.9 s (measured) | 38.5 s (measured) | 1,526 MiB (measured) |
| 10,000,000,000 | 1,000,000,000 | not run | ~7 min (est.) | ~15 GiB |

The new load allocates 14–16 times per load regardless of D (the set, the
read buffer, the file); the old one 8.

## Practical guidance

- **Disk space to provision for the checkpoint file**: budget roughly
  `16 bytes × (10% of expected object count)` plus the 48-byte header —
  effectively negligible (single-digit GB) even at billion-object scale,
  since only directories get records. At 1B objects, ~1.6 GB; at 10B
  objects, ~16 GB. This is small compared to almost any other artifact of
  a run this size, so checkpoint file size is not a reason to provision
  more disk — it's a rounding error next to logs or FlashBlade snapshots.
- **When to split a run instead of relying on one checkpoint/resume
  cycle**: the constraint is not file size, it's **resume latency**. Once
  the directory count approaches 1B, resume itself (now mostly the sort)
  costs minutes and ~16 GB of resident memory, before any real work
  resumes.
  If a namespace is expected to reach 1B+ directories (i.e. ~10B total
  objects at the 10% assumption), partition the run with a manifest
  (`--partitions`, `docs/partitions.md`, PS-12): one checkpoint per
  subtree, so a resume loads and sorts only the failed partition's
  `16·D_p` bytes.
- **The load-path fixes this document used to recommend are done** (PS-10,
  #79): buffered reads and a typed sort, with no format change. What is left
  is the sort's `D log D` and the `16·D` resident set, which partitioning
  addresses.

## What was measured vs. estimated

- **Read from the code**: record size (16 bytes, fixed), header size (48
  bytes), append-only write pattern, 5-second flush cadence, the exactly
  pre-sized `completed` slice, the 64 KiB read chunk and the typed sort.
- **Measured** (`BenchmarkResumeLoad`, `go test ./internal/checkpoint -run '^$'
  -bench ResumeLoad -benchtime 3x`): load time, resident heap, bytes and
  allocations per load at 1M, 10M and 100M records, for both the current loader
  and the pre-PS-10 one, which the test file keeps as `legacyLoad`.
  `TestReadRecordsBatches` checks the read count: one per 4,096 records.
  The 100M size is opt-in: `CHECKPOINT_BENCH_100M=1`, with `TMPDIR` on a
  filesystem that holds the 1.6 GB fixture. The 100M estimate this document
  used to carry (~35 s) came in about 10% low.
- **Estimated**: the 10% directory ratio (not measured on any treegen tree),
  and the 1B-record row, scaled from the 100M load.
- **Not run**: 1B records (16 GB fixture and resident set).
