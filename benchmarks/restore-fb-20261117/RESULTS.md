# `--restore-from` on FlashBlade: first lab run (2026-11-17)

The hardware scenarios of [design-acl-restore.md](../../docs/design-acl-restore.md) section 8, for
issue #56, run on one lab FlashBlade.

**This qualifies no release.** It is evidence for candidate `fdedaf7` only. The next candidate adds
the `replaced_since` check, which changes pairing, so scenarios 1, 2 and 5 must be rerun on it.
Scenarios 3 (identity without the bypass) and 4 (lockout ordering) were not run. The SMB view of the
restored masks was not checked.

| | |
|---|---|
| Candidate | `fdedaf7d5281e501dd968f58768cbec167b99e7c`, unmodified, built with `make build` in the lab: `permissionreset v0.10.0-rc4-16-gfdedaf7`, SHA-256 `30d4d2cbf1f1716bd079e15b21b56387bba2a18589872eeb1ce2216f9158cf7a` (differs from the developer's build of the same commit by the embedded build date only) |
| Array | A lab FlashBlade, Purity//FB 4.8.7. A throwaway file system created for these runs |
| Client | Linux 6.8.0, 12 vCPU, kernel NFSv4.1 (`sec=sys`, 512 KiB rsize/wsize), `--workers 128` |
| Identity | An ordinary directory user over AUTH_SYS that holds the array's audit bypass, not root. The identity checklist passed, and the audit-bypass proof passed on every apply and validate |
| Reference | A FlashBlade snapshot of the fixture, read through `.snapshot`, except where a writable copy is named |
| Byte check | `getfattr -n system.nfs4_acl --only-values` piped through `sha256sum`, live against reference, per object |

An earlier candidate, `26a3a38`, found two defects, both fixed in `fdedaf7`: a FlashBlade snapshot
was judged writable (`access(W_OK)` says yes there, while every write fails EROFS), and flags placed
after TARGET were not parsed. Its runs are kept as history only; every scenario below was rerun on
`fdedaf7`.

## Design question 1: file ids in `.snapshot`

| Check | Result |
|---|---|
| Unchanged objects keep their file id in the snapshot | **Yes**, 13/13, two snapshots |
| A file deleted and recreated under the same name gets a new file id | **Yes** |

So `replaced_since` is built and on by default (design section 9, decision 1).

## Verdict

| # | Scenario | Result |
|---|---|---|
| 1 | #56 end to end (`DELETE_CHILD` on file ACEs, audit ACEs) | **PASS** |
| 2 | Every pairing case | **PASS** |
| 3 | Guards | **PASS**, except identity without the bypass: **not run** |
| 4 | Lockout ordering | **Not run** as specified; fails safe (below) |
| 5 | Resume after SIGKILL | **PASS** |
| 6 | Rate | Measured |

## Results

**1. #56 end to end.** 674 objects: 491 files whose ACEs carry `D` (`0x40`), 126 objects with audit
ACEs. The fixture was snapshotted, then repaired with the candidate.

- `--validate`: exit 1, 674 mismatches, each naming the differing ACE (the `0x40` shows).
- `--apply --allow-audited-dacl-reset`, with no `--allow-writable-reference`: exit 0, 674 restored,
  0 refused. The reference probe reported `read-only (EROFS)` and left no file in the snapshot.
  Evidence `complete`.
- `--validate` again: exit 0, 674 same.
- Raw `system.nfs4_acl` equals the snapshot's on 674/674, audit entries included. The snapshot and
  all file contents were unchanged.

**2. Pairing.** Exit 0: 7 compared, 7 restored, 0 errors.

- Each case counted on its own line: deleted since 2 (a file and a directory), created since 1,
  symlinks 2 (one became a symlink, one was one), type changed 2 (file to directory and back),
  excluded 1.
- The objects whose raw ACL changed are exactly the 7 compared pairs. Nothing was written under
  the excluded directory or the type-changed directory, and no created object was written.
- A file deleted and recreated under the same name got the old object's ACL, as expected for a
  candidate without `replaced_since`.
- The dry run read no ACL, reported 7 pairs as `WOULD` compare, and wrote nothing. `--validate`
  afterwards: exit 0.

**3. Guards.** Each refused with the object's raw ACL unchanged and exit 1:

- A reference naming an unmapped principal: `unmapped_principal`.
- A reference naming an id at or above 1000000000: `synthetic_range_principal`, also with
  `--allow-high-ids`. That flag had no effect, and is refused with `--restore-from` from the next
  candidate on.
- A live ACL with audit ACEs the reference lacks: `audit_vanished`. With `--allow-audit-removal`
  the object was written, and matches the snapshot.
- Audit ACEs without `--allow-audited-dacl-reset`: `audited_object`. With the flag the object was
  written, and matches the snapshot.
- A writable copy of the tree as the reference under `--apply`: the probe reported that a file
  could be created, and the run was refused. With `--allow-writable-reference` it restored, and the
  raw ACLs equal the copy's. No probe file was left in the copy either time. `--validate` against
  the copy ran no writability check.
- The snapshot as the reference was never refused; the probe reported EROFS.
- **Not run:** an identity without the audit bypass. The array has none set up.

**4. Lockout ordering: not run as specified.** The reference directory that denies the running
identity list and traverse is equally unreadable in the snapshot, so a non-root identity cannot
reach its children. Exercising children-then-directory needs root with the bypass, which was not
authorized for this run. What was observed instead: the reference listing failed with permission
denied, 1 listing error, exit 1, nothing written, and the restrictive directory ACL was not applied
either. That is safe, but the post-order write is not hardware-tested.

**5. Resume.** A 127,306-object tree, killed with SIGKILL 1.5 s into `--apply --checkpoint`
(about 36,000 objects already restored). `--resume`: 228 directories resumed, 99,968 compared,
91,098 restored, 8,870 same (logged `SAME:`, not rewritten), 0 errors. Final `--validate`: 127,306
same. The killed run left evidence shards and no `manifest.json`; `docs/evidence.md` now says how to
read that.

**6. Rate.** Same 127,306-object tree, 0 errors:

| Operation | Time | Rate |
|---|---|---|
| Repair (`--spec … --apply`) | 5.3 s | |
| Restore `--apply` | 4.5 s | 28.1k pairs/s |
| Restore `--validate` | 3.8 s | |

On a 15,913-object subtree, the snapshot runbook's `nfs4_getfacl`/`nfs4_setfacl` loop, run verbatim,
took 69.4 s (4.36 ms per object). The restore took 0.83 s on the same subtree, about 80 times
faster.

## Observations

- **Extra ACEs under an audited directory.** On this file system, a file created over NFS in a
  directory whose ACL carries an inheritable audit ACE came back with three extra ALLOW entries
  naming ids that resolve to nothing, two of them at or above 1000000000. Without the audit ACE the
  child was clean. The restore refuses those objects as `synthetic_range_principal`, which is
  correct, so a tree built this way cannot be restored completely (6 of 670 objects on an earlier
  fixture). The array-side cause is an open question.

## Not covered

- The SMB view of the restored masks (the #56 symptom). The throwaway file system serves NFSv4.1
  only, and adding SMB and a share is array configuration that was not approved.
- FlashArray, the userspace transport, and any other Purity//FB release.
- Effective access, delivered audit events, and SMB descriptor or inheritance fidelity. This run
  checks stored NFS ACL bytes only.

Raw evidence is kept in the internal lab record.
