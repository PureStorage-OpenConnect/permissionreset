# Tuning sweep

`sweep` measures the transport tunables against one client/server/export/transport pair and
writes the winner to `permissionreset-tuning.yaml`. `permissionreset` loads that file as new defaults, so
the sweep replaces guessing at `--connections`, `--slots`, `--workers`, `--batch-size` and
`--max-ops-per-compound`.

```bash
# Build both binaries into the same directory
make build

# Userspace transport, first run: generate the trial tree, then sweep
./sweep --scratch /mnt/fb-perms/sweep \
        --server 192.0.2.50 --export /fb-perms --transport userspace \
        --spec examples/nfsv4_complex.yaml \
        --principals examples/principals_example_nfs.json \
        --scale large --regenerate-scratch

# Kernel transport: --server and --export are read from the mount, not from flags
sudo ./sweep --scratch /mnt/fb-perms/sweep \
        --spec examples/nfsv4_complex.yaml \
        --principals examples/principals_example_nfs.json \
        --scale large --regenerate-scratch
```

## Prerequisites

- **A kernel NFS mount is required even for a userspace sweep.** The tree generator is a POSIX
  backend: it creates and stamps the trial tree through a mounted path. `--scratch` must therefore
  name a directory *under* an NFS mount — never the mount point itself, and never the export root.
  `--scratch-server-path` alone is only usable when nothing needs a local path, which no shipped
  configuration currently is.
- The spec (`--spec`) is mandatory: every trial applies it, and a sweep of a different spec measures
  different work.
- The principal roster (`--principals`) is mandatory unless the invocation both reuses a tree and
  passes `--force` — the one combination that adopts a tree without generating anything.
- Run as **root for a kernel sweep**. As root, each trial syncs, writes `3` to
  `/proc/sys/vm/drop_caches` and remounts the target, so every trial starts equally cold. Without
  root the sweep still runs but prints one warning: later trials inherit cache warmth from earlier
  ones, so the measured ladder may be flatter than the real one. A userspace sweep never drops
  caches and does not need root — each trial builds and closes a fresh session, so no filehandle
  or attribute cache survives, and the userspace transport never consults the client's page cache
  in the first place. (It is not that the tree is absent from that cache: a `--regenerate-scratch`
  run just wrote the tree through the kernel mount, so much of it is warm there. The userspace
  transport simply does not read through it.)

## Trial sizing

`--trial-duration` (default `30s`) is the target amount of work per trial, and `10s` is a hard
floor. The floor's rationale — that below it session setup and the first round trips are a large
enough share of the measurement to drown out the knob effect — is design reasoning, not something
that has been measured; the number is deliberately conservative rather than derived. The tree is
capped by `--max-trial-files`; when that is `0` the cap is derived from `--max-generate-time`
(default `20m`) at a deliberately conservative assumed 2,000 generated paths/sec, giving a default
ceiling of 2.4M paths. If the ceiling forces a shorter trial than requested, the sweep says so and
continues with the capped tree; if even the capped tree cannot reach the 10-second floor, it refuses
rather than measuring noise.

Sizing runs a **four-copy probe tree, measures one stock trial against it, computes the copy count,
tears the probe down, and only then generates the full tree.** This is deliberately the opposite
order from the original design text, which generated first and calibrated afterwards. `permissionreset`
has no first-N-files operation, so there is nothing to calibrate against inside a finished tree
without subsetting it by path — and repeated copy-root invocations would bias the userspace numbers
with repeated session setup. The probe still supplies the tree's paths-per-copy shape, but its rate
can be dominated by startup. If the full-tree baseline proves an automatically sized tree is below
the 10-second floor, the sweep recalculates from that measured rate and clamps to
`--max-trial-files`. It tears the first tree down and rebuilds once only when the replacement can be
larger; if the ceiling already holds the current tree, it reports that the ceiling prevents growth
and refuses without a no-op rebuild. A fresh baseline over a rebuilt tree becomes both the persisted
opening rate and the value compared with the closing baseline; if that one growth round is still too
short, the sweep refuses rather than rebuilding indefinitely.

`--copies` overrides sizing: a positive value is a hard override that still has to satisfy the
file ceiling and the 10-second floor (it fails rather than being silently adjusted), and `0`
requests calibration. It applies to generation only — under reuse nothing is built, so `--copies`
is ignored and the tree's own recorded copy count stands.

## Tree shape flags

These describe the tree that generation builds, and are ignored under reuse except where reuse
compares them against what the existing tree recorded:

| Flag | Meaning and default |
|------|---------------------|
| `--scale` | Named size: `small`, `medium`, `large`, `xlarge`, `huge` (default `large`). Supplies the seed-file count, depth and nominal copy count. |
| `--seed-files` | Seed file count; `0` uses the scale's value. Compared on reuse. |
| `--max-depth` | Maximum tree depth; `0` uses the scale's value. Compared on reuse. |
| `--seed` | Generation seed (default `42`). A reused tree must record this same value, or reuse refuses (warns under `--force`). |
| `--files-per-subtree` | Explicit-ACE file outliers per project subtree (default `4`). Compared on reuse. |
| `--safety-principal` | Overrides the safety ACE principal. Default is the running user, detected by the generator. |
| `--tree-workers` | Concurrent workers for tree *generation* only (default `128`). This is not the swept `workers` knob, which the ladders choose. |

## Userspace trial flags

These are passed through to every trial but are neither swept nor written into the saved entry. A
sweep measures the swept knobs against whatever fixed values these hold, so a repair run later with
materially different values is not running under the conditions that were measured.

| Flag | Meaning and default |
|------|---------------------|
| `--rpc-timeout` | Per-COMPOUND deadline (default `30s`). `0` is refused rather than silently meaning the transport's own 30s default. |
| `--retry-budget` | Attempts before an object is failed (default `5`); must be at least 1. |
| `--retry-base-delay` | Exponential backoff base (default `100ms`). `0` is refused for the same reason as `--rpc-timeout 0`. |

`--version` prints the sweeper's version, commit and build date and exits. The commit it prints is
the same one recorded in every entry the sweeper writes, so an entry can be traced to the binary
that measured it.

## Reusing a tree

`--reuse-scratch` defaults to **true**, so by default the sweep measures a tree that already
exists and never generates into the operator's directory. Pass `--regenerate-scratch` to build the
trial tree — including the first time, when the scratch directory is still empty — or to clear and
rebuild an existing tree whose `acl_manifest.json` names that exact root. A non-empty root without
that proof is refused rather than removed. Setting it with either `--reuse-scratch` or `--force` is
an error: both of those flags ask to adopt a tree read-only, while `--regenerate-scratch` asks to
replace it.

Reuse reads `acl_manifest.json` under the scratch root as evidence about the tree, never as
permission to replace it. Reuse checks the recorded seed files, max depth, seed and
files-per-subtree against what was requested, and warns loudly if the tree records no more than the
four copies an aborted run leaves behind. `--force` sweeps a tree `permissionreset` cannot prove it
generated: it downgrades those refusals to warnings and authorizes a read-only local entry count
when no usable manifest count exists. It never authorizes generation, replacement or removal.

A reused or forced tree is never calibrated, so nothing knows how long a trial over it lasts until
one has run. The 10-second floor is therefore enforced *after* the opening baseline, and a tree too
small to carry signal is refused without modification. The same refusal applies to an explicit
`--copies` override: only the automatically sized tree gets the single growth round described
above.

## Interruption

The sweep prints each ladder point as it is measured, because a full sweep runs for hours and an
interrupted one must still show its work. On SIGINT or SIGTERM:

- If at least one trial produced a rate, the best point so far is written with
  `confidence: partial` and the sweep exits `130`. No winner-confirmation ran, so no winner rate is
  recorded for it.
- If **no** trial ever produced a rate, nothing is written at all: the sweep prints that nothing
  was measured, leaves the tuning file untouched, and exits `130`. Losing an interrupted sweep is
  the acceptable direction; inventing one is not.

Tree generation is cancellable too, and an interrupt during it is treated identically: generation
stops, the sweep prints that nothing was measured, the tuning file is left untouched, and it exits
`130`. This matters because preparation is the longest phase of a `--regenerate-scratch` run and is
where Ctrl-C is most likely to land.

One caveat comes with it. An interrupted generation leaves whatever it had built at the scratch
root, and — depending on which phase was interrupted — the tree may carry an `acl_manifest.json`
describing that partial state as if it were complete. A later default (reuse) sweep would then
adopt the truncated tree without complaint. Regenerate the scratch tree before sweeping it again;
the interrupt message warns only a run that was generating. A reuse run (including
`--reuse-scratch --force`) creates nothing, so it is never told to replace a directory whose tree it
did not build and, without `--principals`, could not rebuild.

A timeout is not an interrupt. An expired deadline is reported as an ordinary failure with exit `1`,
not as the operator's own Ctrl-C. Note that `--max-generate-time` is not that deadline: it is
converted into a file ceiling, not into a clock that fires.

## Output

A successful sweep prints the drift line and then the entry it persisted:

```
baseline drift 3.2% (opening 41200, closing 39900): confidence high
winner: connections=32 slots=0 workers=1024 batch-size=50 max-ops-per-compound=0 at 63100 paths/s
wrote /usr/local/bin/permissionreset-tuning.yaml
```

The `winner:` line reports the parameters and rate actually written, so the file can be
cross-checked against the run that was watched. Note that the kernel transport zeroes
`connections`, `slots` and `max-ops-per-compound` in the saved entry: its ladders never measure
them.

## Trial sidecar

Every completed trial is appended immediately as one JSON object per line to a sidecar beside the
tuning file. Its default name is
`permissionreset-trials-<sanitized-key>-<key-hash>-<UTC-start>.jsonl`; the key hash keeps two keys that
sanitize to the same text distinct, and the nanosecond UTC start keeps repeated sweeps from
overwriting each other. The resolved path is printed when the sweep starts, so it remains findable
if the run is interrupted. Override it with `--trial-log <path>`. Pass `--trial-log=""` to disable
recording entirely.

A `type: "trial"` record has these fields:

| Field | Meaning |
|---|---|
| `seq` | Monotonic trial number across the entire sweep. |
| `t`, `duration_s` | Trial start in UTC and elapsed seconds. |
| `phase` | Search stage: currently `calibration`, `opening_baseline`, `ladder`, `confirmation`, or `closing_baseline`. This is an open string set; later writers may add phases without invalidating readers. |
| `knob`, `value` | The swept knob and value for a `ladder` trial; `null` in every other phase. |
| `params` | The complete five-tuple in effect: `connections`, `slots`, `workers`, `batch_size`, and `max_ops_per_compound`. Earlier ladder winners therefore remain visible after they are frozen into later trials. |
| `ops_per_sec`, `files`, `error` | The measured rate and tree path count. A failed trial is retained with `ops_per_sec: null` and its error text rather than omitted. |
| `client` | The trial's CPU sample (`cpu_pct`, `cpu_user_pct`, `cpu_sys_pct`, `cpu_softirq_pct`) when the runner obtained one; otherwise `null`. |

After a successful confirmation and closing baseline, one final `type: "summary"` record makes the
sidecar independently interpretable: it carries the full tuning key and transport, sweep commit,
tree shape and trial path count, winning params, confirmed median, both baselines and their drift,
confidence, and exit disposition. An interrupted sweep deliberately has no summary; all complete
trial lines written before the interrupt remain parseable. Sidecar open or write failures warn once
on stderr and never change the sweep's exit status or tuning-file result.

`permissionreset-tuning.yaml` is written **beside the running binary**, and `permissionreset` looks for it
beside *its* own binary. Keep `sweep` and `permissionreset` in the same directory, or copy the file
across after a sweep. The file schema is version-locked to the binary beside it: readers reject a
different version rather than guessing at field meanings. A binary update that bumps the tuning
version therefore requires re-sweeping that binary; in a mixed-version fleet, keep each binary with
its own same-version file instead of sharing one file across deployments. Re-sweeping the same key
replaces that entry in place; a different key is appended. An existing file that cannot be parsed
is never overwritten — it may hold entries for
other host/target pairs.

## Keys and precedence

An entry is keyed by `clients@server:export/transport` — for example
`client01@192.0.2.50:/fb-perms/userspace`. Both tools build a solo-client key from
`os.Hostname()`; kernel takes server and export from the resolved mount, userspace from
`--server` and `--export`.

**Mount options are not part of the key.** Two mounts of the same export whose options make them
perform very differently (`nconnect`, `noatime`, protocol minor version) share one tuned entry, and
the last sweep to run wins. If mount options change materially, re-sweep.

When `permissionreset` finds a match it announces it on stderr:

```
tuning: client01@192.0.2.50:/fb-perms/userspace from /usr/local/bin/permissionreset-tuning.yaml confidence=high (connections=32 slots=0 workers=1024 batch-size=50 max-ops-per-compound=0)
```

The confidence values mean:

| Confidence | Meaning |
|---|---|
| `high` | Opening-to-closing baseline drift was 10% or less: the array behaved the same at both ends of the sweep, so the ladders were compared against a stable target. |
| `low` | Drift was above 10%. The numbers are real, but the server was not in a steady state, so the winner may be an artifact of when it was measured. |
| `partial` | The sweep was interrupted. This is the best point measured so far, with no winner confirmation. |
| `unknown` | The entry records no confidence at all (hand-written or from an older writer). |

**Every confidence is applied, including `partial` and `low`.** A measured point beats an
unmeasured built-in default even when the sweep behind it was cut short, so the value is reported
rather than enforced. If you do not want a `partial` entry in force, re-sweep it or delete the
entry — `permissionreset` will not second-guess it for you.

The values in parentheses are the **effective** ones, after precedence. A value a command-line
flag supplied is marked with the value the file held instead:

```
tuning: client01@192.0.2.50:/fb-perms/userspace from /usr/local/bin/permissionreset-tuning.yaml confidence=high (connections=32 slots=0 workers=256[flag, file 1024] batch-size=50 max-ops-per-compound=0)
```

Here the file asked for 1024 workers and `--workers 256` overrode it. The marker appears whenever
the flag was typed, even if it happens to match the file, because what the line would otherwise
get wrong is attribution: it names the tuning file, so an unmarked value reads as one the file
supplied.

A flag typed on the `permissionreset` command line always beats a tuned value, even when the typed value
equals the built-in default. A tuned entry whose parameters anything downstream would reject is
discarded with a warning and the built-in defaults are used instead: a tuning file can never end a
repair, and `permissionreset` runs normally when `permissionreset-tuning.yaml` is missing or malformed.

`--pfind` has no sweeper flag, deliberately. An external enumerator cannot be fused with the fix,
so a swept `pfind` number would describe a path no repair takes.
