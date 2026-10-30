# Partitioned runs (`--partitions`)

One run over a billion-object namespace has one checkpoint and one evidence
stream. Resuming it loads every completed directory (16 bytes each, sorted,
for the whole run), and inspecting it means
reading all of it. A partition manifest splits the run into stable,
nonoverlapping subtree jobs, each with its own checkpoint, evidence and error
log. A restart then loads only the failed partition's checkpoint, and each
partition's result can be checked by itself.

Partitions run one at a time. Running them concurrently is not supported yet:
whether more concurrent walks make a FlashBlade go faster is a measurement
question, and it has not been answered.

## Manifest

```yaml
version: 1
root: /mnt/fb/data              # kernel: local path; userspace: server-side path
spec: permspec.yaml             # relative to the manifest file
exclude:                        # optional; unioned with the spec's exclude:
  - .snapshot
state_dir: partitions.state     # relative to the manifest file
evidence: true                  # default
partitions:
  - name: projects
    path: projects              # relative to root
  - name: home-a-m
    path: home/a-m
```

`examples/partitions/manifest.yaml` is a full example.

The manifest is checked when it is loaded, before anything under `root` is read.
A manifest is refused if:

- **Two partitions overlap.** That covers two partitions naming the same path,
  and one partition inside another (`home` and `home/a`). Sibling paths that
  only share a prefix (`home` and `home-old`) are fine.
- **A path is not plain.** It must be relative, already clean (no `.`, `..` or
  doubled slashes), strictly under `root`, and free of glob characters
  (`*?[]\`).
- **A name is not unique.** Names are compared case-insensitively. They are
  1–64 characters of letters, digits, `.`, `_` and `-`, and `residual` is
  reserved.
- **A partition is excluded.** That means its path, or an ancestor of it,
  matches the spec's or the manifest's exclude list. The operator asked for
  that subtree to be left alone, so no partition can repair it.

## The residual partition: full coverage

Every manifest has one more partition than it lists. The implicit `residual`
walks `root` itself and **hands off** each listed partition root rather than
descending into it. It owns everything the listed partitions do not: the root,
the ancestors of each partition root, and their other entries. So every object
the walk reaches belongs to exactly one partition, and the manifest has no
regions left unverified.

A handoff is pruned like an excluded directory: it is not fixed and not
descended, and it is left out of its parent's checkpoint child count. It is
**not** counted as an exclusion. Each one is recorded instead: a `HANDOFF:` line
in the residual's evidence and the path in the residual's `handed_off` list. The
report requires every partition root to appear in some residual attempt's
`handed_off`. A partition root the residual never reached is listed under
`unreached` and makes the run incomplete, however clean that partition's own run
was. That happens when something stopped the residual above the partition root:
an unreadable ancestor, or a mount boundary under `--one-filesystem`.

## Who writes the boundary

| Object | Owner |
| --- | --- |
| `root` and everything not under a partition | residual |
| A partition root's parent | residual |
| A partition root itself (its own apply) | that partition |
| Everything under a partition root | that partition |

The residual runs first, so it fixes any non-traversable ancestor before a
partition has to cross it. Then the listed partitions run in manifest order.
Each run is the same repair a single `TARGET` gets, and no two
runs ever write the same directory. A second `permissionreset --partitions` on the
same state directory is refused (an exclusive `flock` on `state_dir/lock`), so
two drivers can never run the same partition at once.

Slash exclude patterns are anchored at the manifest `root` in every partition.
`logs/*.gz` names the same objects whichever partition reaches them. Base-name
patterns match at any depth, as always.

## Running

```bash
permissionreset --partitions m.yaml                          # dry run: no state, nothing written
permissionreset --partitions m.yaml --apply                  # repair
permissionreset --partitions m.yaml --apply --resume         # continue after a failure or interruption
permissionreset --partitions m.yaml --apply --resume --partition home-a-m   # retry one partition only
permissionreset --partitions m.yaml --validate               # verify; same state rules, no checkpoint
```

All other flags work as they do for a single `TARGET` and apply to every
partition: transport, workers, `--sacl`, `--one-filesystem`, the
`--evidence-profile` options, `--json-summary` (which writes the aggregate
report) and the rest. Flags the manifest replaces are refused, not ignored:
`TARGET`, `--spec`, `--exclude`, `--checkpoint`, `--evidence-dir`,
`--audit-log`, `--log` and `--pfind`. pfind cannot prune a handoff.

### State directory

```
state_dir/
  lock
  state.json                 # status and every attempt, rewritten atomically after each change
  report.json                # the aggregate, after every invocation
  residual/
    checkpoint               # shared by the partition's attempts (apply only)
    attempt-1/{errors.log, summary.json, evidence/}
  projects/
    checkpoint
    attempt-1/...
    attempt-2/...            # a retry: new evidence dir, same checkpoint, resumed
```

### Restart semantics

- **Without `--resume`, an existing `state.json` is refused.** It is never
  overwritten. Use `--resume` to continue it, or give the manifest a new
  `state_dir`.
- **With `--resume`, completed partitions are skipped**, not replayed. Every
  other partition runs again. In apply mode a partition resumes its own
  checkpoint, so directories it finished are skipped. A partition's unfinished
  descendants are not dropped: a directory is recorded complete only when
  everything under it is.
- **A resume is refused when the run's binding has changed.** That means a
  different manifest (by SHA-256), mode (`apply` vs `validate`), tool version,
  or transport, or, on the kernel transport, a partition root that is no longer
  the same device and inode. A changed manifest redraws the partitions, and
  checkpoints written under the old ones mean something else.
- **A failure in one partition does not stop the others.** Cancellation
  (SIGINT/SIGTERM) does: the partition in flight is recorded as failed, and
  nothing after it starts. A driver that dies mid-partition leaves it
  `running`, and the next `--resume` marks it failed and retries it.
- **An untrusted checkpoint is set aside.** If a partition's checkpoint flush
  fails (`ErrCheckpointUnflushed`, exit 3 for a single run), the file is
  renamed to `checkpoint.untrusted-<time>` and the next attempt starts that
  partition fresh, rather than resuming from a file that no longer describes
  it.

### What "complete" means

An attempt completes its partition when all of these hold: the run returned no
error, it exited 0, enumeration was complete (no walk or readdir errors, no
interruption, no duplicate completions, no evidence stop), it had no errors or
mismatches, and its evidence closed `complete` (when evidence is on). Every
failed condition is recorded in the attempt's `reasons`.

The report's `complete` is true when every partition is complete and every
partition root was reached by the residual. `totals` is the sum of every
attempt's counts, so it reconciles exactly with the per-attempt figures in
`state.json`. An object that a resumed attempt examined again appears in two
attempts' counts, because it was in two runs. `evidence_complete` needs every
partition's final attempt to have closed its evidence `complete`.
`incomplete_evidence_attempts` counts every attempt whose evidence did not.
Superseded attempts are kept, because their records are what those attempts
changed.

The exception is a driver that was killed (SIGKILL, a host crash). It never
records its in-flight attempt's counts, so `--resume` marks that attempt
`uncounted` and the report lists it in `uncounted_attempts`. `totals` is then
a lower bound: the objects the killed attempt finished before it died are in
the tree and in its partial evidence, but not in any count, and the resumed
attempt does not enumerate directories the checkpoint already completed. For
exact per-object coverage after a kill, run `--validate` over the manifest. On a
lab FlashBlade, a SIGKILL during one 141,876-object partition left totals 34,211
objects short, and the `--validate` that followed matched all 1,135,010
(`benchmarks/partitions-ab-20261029/`).

## What path disjointness does not prove

Partitions are disjoint **by path**. That is not the same as disjoint by
inode, and the tool does not claim it is:

- **Hard links.** A file with names in two partitions is stamped by both.
  Within one run it is stamped once per name.
  The writes are idempotent, and the counts follow names, not inodes.
- **Bind mounts and second mounts of one export.** These can make one directory
  appear under two names. On the kernel transport, two partition roots with the
  same device and inode are refused, and so is a partition root that is a
  symlink. An alias deeper than a partition root cannot be found without
  walking the tree, so it is not detected. It behaves like a hard-linked
  subtree: written twice, idempotently.
- **Nested mounts.** Without `--one-filesystem`, mounts are crossed, as in a
  single run. With it, a partition root on a different filesystem from `root`
  is refused at load time, because the residual would have stopped at it. A
  mount deeper inside a partition is skipped by that partition's own
  `--one-filesystem` check.
- **Renames during the run.** The trusted-tree model applies: permissionreset
  assumes it has exclusive write access to `root`. A partition root renamed away and replaced between attempts
  is caught on the kernel transport by its device and inode. A rename inside a
  partition, or across partitions, behaves as it does in a single run. Take a
  FlashBlade snapshot first.
- **Userspace transport.** There is no local view of the tree, so none of the
  device/inode checks run. The run prints a NOTE saying so.

## Performance and space

Each partition's checkpoint holds only that partition's directories. A resume
loads and sorts `16·D_p` bytes for the failed partition `p`, not for the whole
namespace. Per-partition limits on RAM and checkpoint size follow from how the
manifest is drawn: split a partition that is too big.

Measured on a lab FlashBlade (kernel NFS, 1.1M objects, 3 alternating rounds,
`benchmarks/partitions-ab-20261029/`): a single run took a median of 41.7 s,
and 4 partitions plus the residual took 41.6 s, with CPU and RSS within noise.
Running partitions serially costs nothing measurable, and gains nothing either.
Running them concurrently has not been measured.
