# SACL plan v3 commit 8 — DACL-keeping apply on FlashArray, 2026-10-15

Steps 2–4 of commit 8 of the SACL implementation plan (kept in the private lab repository), run
on both lab arrays at `c2a56aa` (commits 1–4 plus the throughput fix).

## How

`lab.sh <mount> <server> <export>` does the following on each array:

1. Creates a fresh `<mount>/lab/<run>/tree` with `generate-tree --scale medium`. The tree uses
   15 scenarios: deny, non-canonical order, inherit-only, protected, six-way principal split and
   others. Principals come from a lab roster (`jdoe`, `juser`, `rp-*`; no
   colleagues' accounts).
2. Dumps every object's raw ACL as root after a remount (`acldump.py`): DACL as raw bytes, audit
   ACEs parsed.
3. Runs `permissionreset --spec examples/nfsv4_sacl_keep_dacl.yaml --apply` as root, kernel
   transport.
4. Remounts, dumps again and diffs. Then reruns with `--compare`, runs `--validate` as root, and
   runs `--validate` as `juser` (uid 1445, no bypass).

## Results

| | lab array A, 6.10.6 | lab array B, 6.12.1 |
|---|---|---|
| Objects (1006 dirs, 5000 files) | 6006 | 6006 |
| Apply: applied / failed | 6006 / 0, 0.37 s | 6006 / 0, 0.36 s |
| **DACL bytes changed** (requirement 4) | **0** | **0** |
| SACL not exactly the spec's (requirement 3) | 0 | 0 |
| Rerun `--compare`: applied / skipped | 0 / 6006 | 0 / 6006 |
| `--validate` as root: mismatches | 0 | 0 |
| `--validate` as `juser` | refused at preflight, before the walk | same |

After the run, every directory carries exactly `U:fdSF:EVERYONE@:rwadxTNcCoy` and every file
`U:SF:EVERYONE@:rwadxTNcCoy`, after the DACL. Raw dumps (gzipped) and run summaries are in
`out-*`.

## Findings

- **Requirement 4 holds on both releases:** the DACL bytes of all 12,012 objects are unchanged,
  including deny entries, non-canonical order and protected DACLs.
- **The userspace transport refuses FlashArray** ("--transport=userspace does not support
  FlashArray File"). FA runs are kernel-only today, so the userspace batching and commit 5's
  conditional write do not help on FA until that gate is lifted and the transport is verified there.
- **The `juser` refusal uses the generic message.** `juser` cannot create the kernel probe file in
  the tree root, so the preflight stops before the audit write and prints "create probe file …
  permission denied", not the audit-bypass text. It refuses, which is correct, but the message
  does not say why the bypass matters. Follow-up: when `sacl:` is in use, give the audit-bypass
  hint on this error too.
- Speed is not measured here: medium trees are too small, and 0.4 s is mostly setup. Requirement 2
  needs commit 8 step 6 (`--scale xlarge`).

## Left on the arrays

`/lab/r20261015-144602` (lab array B) and `/lab/r20261015-144638` (lab array A) hold the trees. Two empty or
partial directories, `/lab/r20261015-144540` and `/lab/r20261015-144553` (lab array B), are left over
from aborted script runs.

## Rerun after `--sacl` became opt-in (`de1775b`, lab array B 6.12.1, medium)

`lab.sh` with `--sacl` on every call, run `r20261015-231745`
(`out-sacl-f07-r20261015-231745/`):

| | Result |
|---|---|
| Apply: applied / errors | 6006 / 0, 0.3 s |
| DACL bytes changed / SACL not the spec's | 0 / 0 |
| Rerun `--compare`: applied / skipped | 0 / 6006 |
| `--validate` as root | 6006 checked, 0 mismatches |
| `--validate` as `juser` | refused at preflight |
| SACL spec without `--sacl` | refused before the transport (`Pass --sacl`), rc 1 |
| `nfsv4_basic.yaml` with `--sacl` | refused: default and rules 0–2 have `acl:` with no `sacl:` key, rc 1 |

`refusals.out` holds the two refusals. A `--validate` afterwards still reported 0 mismatches.
