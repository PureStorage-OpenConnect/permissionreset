# `--restore-from` on FlashBlade: lab runs (2026-11-17)

The hardware scenarios of [design-acl-restore.md](../../docs/design-acl-restore.md) section 8, for
issue #56, run on one lab FlashBlade.

**This qualifies no release.** It is evidence for two candidates. `fdedaf7` ran every scenario that
could run. `8e7667b` added the `replaced_since` check, so scenarios 1, 2 and 5 were rerun on it
([rerun section](#rerun-on-8e7667b)); scenario 3's guards and scenario 6's rate are carried forward
from `fdedaf7`, because the code they exercise did not change. `cebd265` changed only where
`replaced-since` paths are printed; scenario 2 was rerun on it ([section](#rerun-on-cebd265)). Scenarios 3a (identity without the
bypass, precondition unmet) and 4 (lockout ordering) were not run. The SMB view of the restored
ACLs was checked on `cebd265` and **failed on 1 of 664 objects**: a restore over NFS cannot bring
back an ACE's SMB INHERITED flag ([section](#smb-view-on-cebd265)).

| | |
|---|---|
| Candidate | `fdedaf7d5281e501dd968f58768cbec167b99e7c`, unmodified, built with `make build` in the lab: `permissionreset v0.10.0-rc4-16-gfdedaf7`, SHA-256 `30d4d2cbf1f1716bd079e15b21b56387bba2a18589872eeb1ce2216f9158cf7a` (differs from the developer's build of the same commit by the embedded build date only) |
| Array | A lab FlashBlade, Purity//FB 4.8.7. A throwaway file system created for these runs |
| Client | Linux 6.8.0, 12 vCPU, kernel NFSv4.1 (`sec=sys`, 512 KiB rsize/wsize), `--workers 128` |
| Identity | An ordinary directory user over AUTH_SYS that holds the array's audit bypass, not root. The identity checklist passed, and the audit-bypass proof passed on every apply and validate |
| Reference | A FlashBlade snapshot of the fixture, read through `.snapshot`, except where a writable copy is named |
| Byte check | The raw `system.nfs4_acl` xattr, read directly (Python `os.getxattr`), SHA-256 per object, live against reference |

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
| 1, SMB | #56 symptom read over SMB | `DELETE_CHILD` back on 418/418. **FAIL**: DACL equals baseline on 663/664; the inherited flag is lost (below) |

## Results

**1. #56 end to end.** 674 objects: 491 files, most of them carrying `D` (`0x40`) in their ACEs (the
count was not taken on this fixture; equivalent fixtures had 410 of 491 and 418 of 501), and 126
objects with audit ACEs. The fixture was snapshotted, then repaired with the candidate.

- `--validate`: exit 1, 674 mismatches, each naming the differing ACE (the `0x40` shows).
- `--apply --allow-audited-dacl-reset`, with no `--allow-writable-reference`: exit 0, 674 restored,
  0 refused. The reference probe reported `read-only (EROFS)` and left no file in the snapshot.
  Evidence `complete`.
- `--validate` again: exit 0, 674 same.
- Raw `system.nfs4_acl` equals the snapshot's on 674/674, audit entries included. The snapshot and
  all file contents were unchanged.

**2. Pairing.** Exit 0: 7 compared, 7 restored, 0 errors.

- Each case counted on its own line: deleted since 2 (a file and a directory), created since 1,
  symlinks 2 (one became a symlink, one was one), type changed 2 (two objects: one file that became
  a directory, one directory that became a file), excluded 1.
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
- **Not run:** an identity without the audit bypass. Precondition unmet: on this FlashBlade an
  ordinary non-admin directory user passes the audit-bypass proof, so no identity was available
  to reach the refusal (retried on `cebd265`, [below](#scenario-3a-on-cebd265)). The refusal path is
  covered by unit tests only.

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

## Rerun on `8e7667b`

`8e7667b` adds `replaced_since`: file ids from `getdents64`, a mismatch confirmed by `lstat` on both
sides, the pair skipped and a replaced directory not descended. It also refuses `--allow-high-ids`
with `--restore-from`. Same array, file system, client and identity as above.

| | |
|---|---|
| Candidate | `8e7667b23d13a735aaa3655d2f9fc18489ab52cb`, unmodified, built with `make build` in the lab: `permissionreset v0.10.0-rc4-17-g8e7667b`, SHA-256 `167e3fb26da1b98eb99d9c5a5fb86091fc5803c0926fcdf247fd877fb4d87251` |

| Check | Result |
|---|---|
| READDIR `d_ino` equals `lstat` `st_ino` | **PASS**, 33,170 of 33,170 entries, live and snapshot (the scenario 1 fixture and a 15,912-entry subtree of the 127k tree) |
| 1. #56 end to end, fresh fixture | **PASS** |
| 2. Pairing, plus a recreated directory | **PASS** |
| 5. Resume after SIGKILL | **PASS** |
| `--allow-high-ids` with `--restore-from` | **Refused**, exit 1, as intended |

**1.** A fresh 644-object fixture: 501 files, 418 of them carrying `0x40`; 118 objects with audit
ACEs. Replaced since 0, so no false positive. `--validate`: exit 1, 644 mismatches. `--apply`
without `--allow-writable-reference`: exit 0, 644 restored, the probe reported EROFS, evidence
complete. `--validate` again: exit 0, 644 same. Raw ACLs equal the snapshot's on 644/644, audit
entries included. The snapshot and file contents were unchanged.

**2.** The scenario 2 fixture plus a directory (containing a file and a subdirectory with a file),
deleted and recreated under the same names after the snapshot. Dry run and apply: 6 compared and
6 restored, deleted since 2, created since 1, symlinks 2, type changed 2, replaced since 2 (the
recreated file and the recreated directory, each counted once), excluded 1, 0 errors, exit 0. The
recreated directory was not descended: its children are counted nowhere and named in no record. The
raw ACLs of all 5 recreated objects were unchanged, so the recreated file keeps its new ACL. The
objects whose raw ACL changed are exactly the 6 pairs. `--validate`: exit 0.

**5.** The 127,306-object tree, replaced since 0. Killed with SIGKILL 1.5 s in (61,639 `OK:`
records in the killed run's evidence). `--resume`: 330 directories resumed, 71,938 compared,
65,412 restored, 6,526 same (logged `SAME:`, not rewritten), 0 errors. `--validate`: 127,306 same.

## Rerun on `cebd265`

`cebd265` sends each `SKIP: replaced-since` line to `--log` as well, or without it, the first 20
to stderr followed by a count, on a cap apart from errors. Nothing else changed. Same array, file
system, client and identity.

| | |
|---|---|
| Candidate | `cebd2659ca820ec4ea9b140227f43b4bf71e328d`, unmodified, built with `make build` in the lab: `permissionreset v0.10.0-rc4-19-gcebd265`, SHA-256 `551655c3ee34501f1baa3470ad41f9abdc7382371a9b318551d18df6148aecde` |

The scenario 2 fixture plus the recreated directory, rebuilt with the same scripts under a new
snapshot (the `8e7667b` copy was already restored).

| Check | Result |
|---|---|
| `--apply`, no `--log` | **PASS**. Exit 0. stderr holds exactly 2 `SKIP: replaced-since` lines (the recreated directory and the recreated file), no other `SKIP:` or `EXCLUDE:` line, nothing for the directory's children, no "more not shown" line. Counts identical to `8e7667b`: 6 compared, 6 restored, deleted since 2, created since 1, symlinks 2, type changed 2, replaced since 2, excluded 1, 0 refused, 0 errors. Raw ACL changed on exactly the 6 pairs; all 5 recreated objects unchanged |
| `--validate --log FILE` | **PASS**. Exit 0, 6 same, 0 mismatches. FILE holds exactly the 2 lines; stderr has only the audit-bypass NOTE |
| Evidence | **PASS**. Both runs complete, the same 2 `SKIP: replaced-since` records as on `8e7667b`, none naming a child of the recreated directory |
| Scenario 1 dry run (644 objects) | **PASS**. Exit 0, 644 would compare, replaced since 0, stderr only the dry-run NOTE |

Not exercised on hardware: the 20-line stderr cap and its count line (unit-tested only).

### Scenario 3a on `cebd265`

**Not run, precondition unmet.** An ordinary directory user with no administrative groups, over
AUTH_SYS, ran `--validate` against a 670-object fixture with audit ACEs on a new throwaway file
system (NFSv4.1 and SMB), with a snapshot as the reference. The audit-bypass proof **passed**: the
array kept the audit ACE that user wrote to the disposable probe. So this FlashBlade gives an
ordinary identity what the proof tests for, and the refusal before any read cannot be reached here.

What the run did show: the only ACL write was to the proof's own probe file (`strace`); ACL reads
came after the proof, as a validate does; raw ACLs and contents on the target were identical before
and after (670/670); no probe file was left on either side. The fixture's restrictive directories
denied that user listing in the reference, so the run ended with 2 list errors and exit 1. No apply
was run as that user, and no array setting was changed to withhold the bypass.

### SMB view on `cebd265`

The #56 symptom is what an SMB client sees, so the masks were also read over SMB from a Windows
client, on the new NFSv4.1 and SMB throwaway file system (the 670-object fixture of the 3a run).
Each object's security descriptor was read three times: at baseline, after a repair that drops
`DELETE_CHILD` (`0x40`) from file ACEs, and after `--restore-from` the snapshot. Pass criteria, set
before the last read: the 664 restorable objects' DACLs equal baseline, and the 6 objects the
restore refuses (`synthetic_range_principal`, see Observations) equal their state after the repair.

| Check | Result |
|---|---|
| Reads | 670 per point, 0 errors, none missing or extra |
| `FILE_DELETE_CHILD` | **PASS**. Back on 418/418 restorable files that had it at baseline, added to none |
| The 6 refused objects | **PASS**. Whole descriptor byte-equal to its state after the repair: the refusal wrote nothing |
| DACL of the 664 equals baseline | **FAIL**, 663/664 |
| SACL, P/AI control flags of the 664 | Equal to baseline, 664/664 |
| Owner and group | Equal to baseline, 670/670 |

**The failure.** One file (the fixture generator's manifest at the root) has the same 4 ACEs in the
same order, with the same types, masks and principals, but one full-control ACE carried the SMB
INHERITED flag (`0x10`) at baseline and is explicit after the restore. The NFS ACL bytes of that file
are identical at baseline, in the snapshot and after the restore, so `--validate` reports it `SAME`.
The array does not expose the flag over NFS, so there is nothing in the reference bytes for the
restore to write back. Exactly 7 objects carried an inherited ACE at baseline: this file and the 6
refused ones. Every restorable object without one came back byte-exact over SMB.

This is the mechanism RISKS.md #11 records on FlashArray, seen here on FlashBlade: an ACL written
over NFS reads back over SMB with INHERITED cleared. The repair did the same to the 6 refused
objects' audit ACEs (`0xd3`→`0xc3` on directories, `0xd0`→`0xc0` on files) and marked their DACLs
protected. No change to the restore can fix it over NFS; it is a limit of restoring an SMB-consumed
tree through NFS.

## Observations

- **Extra ACEs under an audited directory.** On this file system, a file created over NFS in a
  directory whose ACL carries an inheritable audit ACE came back with three extra ALLOW entries
  naming ids that resolve to nothing, two of them at or above 1000000000. Without the audit ACE the
  child was clean. The restore refuses those objects as `synthetic_range_principal`, which is
  correct, so a tree built this way cannot be restored completely (6 of 670 objects on an earlier
  fixture). The array-side cause is an open question.

- **Skips are visible only in the evidence.** `SKIP:` lines, `replaced-since` included, and
  `EXCLUDE:` lines go to the evidence records only. The terminal and `--log` show the counts, not
  the paths. An operator who runs without `--evidence-dir` cannot see which objects were replaced.
  Addressed in `cebd265`: `SKIP: replaced-since` lines now also go to `--log`, or the first 20 to
  stderr ([rerun](#rerun-on-cebd265)).

## Not covered

- FlashArray, the userspace transport, and any other Purity//FB release.
- Effective access and delivered audit events. SMB descriptor fidelity was checked once, on
  `cebd265` (above); the other runs check stored NFS ACL bytes only.

Raw evidence is kept in the internal lab record.
