# PS-12 #81 partition manifests — c09-33 live evidence (2026-10-29)

- Array: example.net lab-s200 (FlashBlade), `jdoe-fs01` over kernel NFSv4.1 from linux01.
- Tree: `jdoe-fs01/jdoe-ps09-ab-xl`, 1,135,010 objects (root plus 8 top-level dirs of 141,876 each).
- Binary: `feat/ps-12-partition-manifests` `5ce5af9`, `--apply --quiet --skip-identity-check`.
- Spec: `ab-spec.yaml` (six ACEs per object, the same spec as PS-09/PS-11).
- Manifest: `manifest.yaml` has 4 partitions (data, engineering, finance, hr). The residual owns the
  root and infra/legal/marketing/ops (567,506 objects).
- Both modes keep a checkpoint and evidence. State and evidence were written to local scratch, never to the array.

## A/B: one run vs 4 partitions (`ab12.sh`, `trials.tsv`)

| round | mode | elapsed s | user s | sys s | max RSS KiB | applied | errors |
|---|---|---|---|---|---|---|---|
| 1 | single | 54.30 | 28.20 | 142.75 | 124304 | 1135010 | 0 |
| 1 | part4 | 41.91 | 27.44 | 142.50 | 139672 | 1135010 | 0 |
| 2 | part4 | 41.63 | 26.89 | 135.63 | 146144 | 1135010 | 0 |
| 2 | single | 41.67 | 26.75 | 138.04 | 145948 | 1135010 | 0 |
| 3 | single | 41.35 | 26.94 | 140.22 | 144492 | 1135010 | 0 |
| 3 | part4 | 41.14 | 26.98 | 141.05 | 147008 | 1135010 | 0 |

Median: single 41.67 s, part4 41.63 s. Round 1's single run was the first run of the session
(cold caches), the same pattern seen in earlier A/Bs. Every partitioned report came back
`complete`, `evidence_complete`, with no unreached roots, and totals reconcile with the tree exactly.
Serial partitioning neither costs nor gains measurable throughput. Concurrency was not measured.

## Kill and resume (`kill-*.json`, `kill-state.json`)

1. A partitioned `--apply` was SIGKILLed 2 s after `finance` entered `running`. At that point the
   residual, data and engineering were complete, and hr was pending.
2. `--apply --resume` took 7.08 s and exited 0. The residual, data and engineering were skipped
   ("complete in attempt 1, skipped"), so no completed sibling was replayed. `finance` attempt 2
   resumed its checkpoint (4,096 dirs completed), enumerated the remaining 107,665 objects (all
   already correct, skipped by compare), and hr ran in full.
3. `--validate` over the manifest (`kill-validate.json`) matched 1,135,010 of 1,135,010, with 0
   mismatches and 0 unreadable. No unfinished descendant was dropped.

**Gap found and fixed:** the killed attempt never recorded counts, so the resumed report's totals
came to 1,100,799, which is 34,211 short: the objects finance#1 finished before the kill. The fix
marks such an attempt `uncounted` and lists it in the report's `uncounted_attempts`, and the CLI
prints a NOTE that totals are a lower bound and that `--validate` gives exact coverage. This run
predates the fix, so `kill-2.json` has no `uncounted_attempts` field.
