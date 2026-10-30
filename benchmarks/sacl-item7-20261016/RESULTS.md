# Review item 7 on lab array A (Purity//FA 6.10.6), 2026-10-16

**Question:** does a dry run of a DACL-keeping (`sacl:`-only) spec, run as a user without the
audit bypass, freeze inherited SACLs (`FA-BUG-unprivileged-acl-read-wipes-sacl.md`)? And does the
item 7 fix (no read on a dry run) prevent it?

**Answer: inconclusive.** The bug did not reproduce today, so neither binary could be shown to
cause or prevent it. The array is still on 6.10.6 (confirmed by the user).

## Setup

- Export `sacl-data` (`198.51.100.242`), private `vers=4.1,nosharecache` mount at `/mnt/t7`,
  remounted between every step so the client's ACL cache cannot hide a change.
- Privileged actor `jdoe` (uid 1402); unprivileged actor `juser` (uid 1445).
- `rp-new`: this branch with the item 7 fix. `rp-old`: HEAD before it (`057f23c`), which reads every
  object on a dry run. Spec: `examples/nfsv4_sacl_keep_dacl.yaml`. Both staged in `/var/tmp/rp-t7`
  so uid 1445 can run them.
- `item7.sh`: parent `P` with `A:fd:EVERYONE@:rxtncy` and `U:fdSF:jdoe@example.net:w`; subtrees `new/`
  (juser dry run, rp-new), `old/` (juser dry run, rp-old), `raw/` (juser `nfs4_getfacl`, the bug
  doc's repro), `ctl/` (untouched); direct children `victim` (juser `nfs4_getfacl`) and `control`.
  Then the parent's `U` is changed to `:r` and every object is read back.

## Runs

| Tree | ACE order | Result |
|---|---|---|
| `/item7/r20261016-025446` | `U` on parent before children | all objects show `U:SF:1402:r` / `U:fdSF:1402:r` |
| `/item7/r20261016-025456` | same, plus `raw/` | all follow the parent |
| `/item7/r20261016-025509` | children first (as in the bug doc), plus `victim`/`control` | all follow the parent |
| `/i7p-030947` | bug doc repro verbatim, `p` at the export root | `victim` and `control` both `U:SF:1402:r` |

- rp-new: NOTE printed, 4 WOULD, 0 errors as juser. rp-old: 4 applied (reads succeeded), 0 errors.
- juser still cannot write a `U` ACE (EACCES).
- In the nested trees juser's read of `control` (after the parent change) returned
  `U:SF:1402:r`; in the verbatim repro juser's read of `victim` returned no `U` entries, as on
  2026-10-15. Not explained.
- The audit policy is attached and logging: today's creates under `/item7/` appear in
  `/mnt/sacl-logs/2026-10-16/` (`alog.py`).

## What changed since 2026-10-15

Unknown. Same release, same audit policy, same client-side identity for juser. Not checked: AD
group changes for juser on the array side, a controller failover or reboot, and array-side state
from the 2026-10-15 sessions. The bug doc reported 3/3 on 2026-10-15; 0/1 verbatim today.

## Consequence for item 7

The fix stays: a dry run should not change anything, and the bug was reproduced 3/3 on 6.10.6
the day before. What is not shown is that it is currently reachable on lab array A.

## Follow-up: why it no longer reproduces (2026-10-16, read-only)

Checked through the array's REST API (read-only token, `api/2.54`) and NFS reads only.

- **The 2026-10-15 freezes are real and persistent.** `/repro/r1..r3/p/victim` still have no `U`
  entries while `p` (`U:fdSF:1402:r`) and `control` (`U:SF:1402:r`) do.
- **Controller roles swapped after the repro.** The `/repro` objects date from 2026-10-15 03:04 UTC.
  CT1 became primary at 06:10:03 UTC that day (CT0 secondary at 06:10:48), and has been since.
  Every test that failed to reproduce ran after that. Strongest lead, not proven.
- **Configuration unchanged:** `sacl-pol` (audit-file, enabled, target `sacl-local`),
  `jdoe-file-pod-nfs` (`*`, rw, no-root-squash, auth_sys, v3+v4) and `jdoe-file-pod-smb` are
  attached to `sacl-test:data`, as in the bug doc. Purity 6.10.6 on both controllers.
- **Admin history not available:** the audit endpoint keeps only the newest 1,000 entries, which on
  this shared array (vVol and DR traffic) reach back only to 2026-10-16 06:14 UTC. Whether anyone
  changed file services or directory services on the 15th cannot be read this way.
- **juser:** client side unchanged (uid 1445, `adusers` only). Its array-side AD resolution is not
  exposed over REST.

Possible explanations, in order: per-controller state (the failover started a fresh file-services
instance whose behavior differs, e.g. a cache that the first read populates); something cleared by
the failover itself; an unlogged change on the 15th. Testing the first means failing back to CT0,
which is an array change; not done. The lab array B "does not reproduce on 6.12.1" result is weaker
in this light: it was never checked against controller state either.
