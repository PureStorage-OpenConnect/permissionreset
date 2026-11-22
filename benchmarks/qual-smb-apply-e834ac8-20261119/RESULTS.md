# Qualification: permissionreset-smb phase 2 (`apply`) on FlashArray SMB, candidate e834ac8 (2026-11-19)

Phase 2 of [the write-path design](../../smb/DESIGN-write-path.md) (section 8; as built, section 10):
DACL writes with the preflight probe, G1, G2, checkpoint and evidence, on one lab FlashArray over SMB.

**This qualifies no release.** There is no `smb-v*` tag. This is evidence for `apply` at this
candidate's artifact only. A release is built from its tag and qualified on its own assets; a later
change to the write path needs its own hardware run.

## Candidate and environment

| | |
|---|---|
| Commit | `permissionreset` @ `e834ac825f39088f4fa20c25d781fdc7745654ca` (PR #73) |
| Artifact | `smb/release/pack.ps1`, run from `smb/` with .NET SDK 8.0.427 (pinned by `smb/global.json`). Zip SHA-256 `6dda6c2cc395300eb8ee06825a5fab101404bc448b30e85944e94ded574e90a6`; `permissionreset-smb.exe` SHA-256 `1238caed13cc96391cfd196cbab16af57fbf01a24ff1a40b25c5356046a4909a` |
| Unit tests | `dotnet test -c Release` at the candidate: 1709/1709 pass |
| Plans | `build-spec --smb-plan` at the same commit (`v0.10.0-rc4-21-ge834ac8`) |
| Array | FlashArray, Purity//FA 6.10.7 (last read 2026-11-17 for phase 1, the same array and share; not re-read for this run) |
| Client | Windows Server 2022 Standard 21H2, build 20348.5386, SMB 3.1.1 (same client and share as phase 1). Domain operator account, elevated, holding SeBackupPrivilege, SeSecurityPrivilege and SeRestorePrivilege |
| NFS side | The NFS-flattened subtree was written over the array's NFS export from a Linux client |

Principals are labels: R is the operator, J is another user, G is a group. X is `R FA (OICI)` + `G RX (OICI)`.
The fixture pre-states were written by the harness with `SetFileSecurityW`. Only the tool wrote DACLs under test.

There was no G1 or G2 stop. Five runs reach preflight (7a refuses before preflight). Each of them printed the new line ending "…an unprotected explicit+inherited write read back exactly, and the probe was removed".

## Passed

| Step | Result |
|---|---|
| 1 | `check` dry run on `app`: ok 1, write 9, follows 16, nothing written. `inspect` took before-images of all 26 objects |
| 2 | `apply --evidence-dir --checkpoint` exited 0. Preflight passed, including the new unprotected step. Written 9, probe removed (none left in `app`), manifest `complete`, shard SHA-256 matches the manifest |
| 3 | Rerunning `apply` exited 0: ok 26, written 0, manifest complete, SHA matches. `check --validate` exited 0 with ok 26 |
| 4 | Audited subtree (`aud` plus 3 children) and NFS subtree: SACL bytes identical before and after, and S:AI and S:P unchanged on every object. No SACL in `app` changed |
| 5 | `inspect` after-images are byte-equal to an independent `GetFileSecurityW` reader on 26/26 objects; the reader used a backup-intent handle for the deny-only subtree. Every object is in its expected form (see below) |
| 6 | `res` (60 dirs, 1200 files). Run 1 was killed after 8 recorded writes, with 0 dirs checkpointed. `--resume` completed: written 51, preflight passed, manifest complete, SHA matches, `check --validate` exited 0. Every checkpoint record line (62 lines) parses on its own; the header line is plain text by design |
| 7a | A plan with `sacl:` on `ref7` exited 1 naming rule[10]. No evidence dir and no checkpoint were created, and all 3 descriptors are byte-identical |

## Q7, Q8, Q10

**Q7: the write succeeds.** `q7r\q7` is owned by J, and its DACL is `D:P(A;OICI;FA;;;J)`. The operator therefore gets WRITE_DAC neither from the DACL nor from ownership. A DACL-only `apply` (manifest privileges SeBackup and SeSecurity, no SeRestore) wrote it and exited 0, and G2 passed: `0x9814 D:P(J FA)` → `0x8c14 D:AI(A;OICIID;FA;;;R)(A;OICIID;RX;;;G)`. The client can't tell why the array allows this write (server-side admin handling or backup handling).

**Q8: yes, both forms are stored exactly and in order.** Before/after are from the tool's step 2 evidence:
- Inherits, `inh`: `0x9814 D:P(A;OICI;FA;;;R)` → `0x8c14 D:AI(A;OICIID;FA;;;R)(A;OICIID;RX;;;G)`
- Explicit+inherits, `xpi`: `0x9814 D:P(A;OICI;FA;;;R)` → `0x8c14 D:AI(D;OICI;0x2;;;J)(A;OICIID;FA;;;R)(A;OICIID;RX;;;G)`. The explicit deny comes first, then the inherited part in order. Its children follow, for example `e1.txt` `(D;ID;0x2;;;J)(A;ID;FA;;;R)(A;ID;RX;;;G)`.

**Q10: D:AI reads back exactly as F5 says**, and G2 accepted every write:

| Write | Object (pre-state) | Before | After |
|---|---|---|---|
| unprotected, inherits | `inh` (SMB `D:P`) | `0x9814` (P, no AI) | `0x8c14` (AI) |
| unprotected, inherits | `nfs`, `nfs\sub2`, `nfs\f4.txt`, `nfs\sub2\f5.txt` (NFS-written, explicit, no D:AI) | `0xb014` (D:P, S:P) | `0xa414` (D:AI, S:P kept) |
| unprotected, inherits | `aud` (SMB `D:P`, SACL `S:P`) | `0xb014` | `0xa414` |
| unprotected, explicit+inherits | `xpi` | `0x9814` | `0x8c14` |
| protected | `prt` (was inheriting, D:AI) | `0x8c14` | `0x9814` (P, AI clear) |
| protected | `den` (deny-only) | `0x9814` | `0x9814` |

Every unprotected write in `res` (51+9 inherits writes) and in `q7r\q7` also read back `0x8c14`.

## Expected forms after apply (step 5)

- `app`: `D:P` X (the root, untouched).
- `inh`, `inh\sub`, `aud`, `asub`, `nfs`, `nfs\sub2`: `D:AI`, inherited X. Files under them: `D:AI`, `ID` X.
- `xpi`, `esub`: `D:AI`, deny J w, then inherited X.
- `prt`: `D:P` R FA, J MOD. `psub` and the files inherit it.
- `den`: `D:P` deny J FA. `dsub` and the files inherit it.

## Observation (not a guard stop)

**A hard kill loses evidence records for writes already made.** In step 6, run 1 wrote 9 dirs, but its shard holds 8 records. The resume found the ninth dir already correct and recorded it as SAME. The end state is evidenced, but that write's before-image is lost. A superseded candidate (`8eeda02`, also `--workers 1`) lost 5. The cause is the shard's write buffer: records that have not been flushed to the file are lost on a forced kill, so the count depends on line sizes, not on the worker count. Decision (2026-11-19): accepted and documented in `DESIGN-write-path.md` §10, with no code change.

## Unverified

- 7b (missing audit bypass) needs an array-side change, which is out of scope (maintainer decision, 2026-11-19).

## Changes from the brief

- Q7 is in its own root `q7r` (`D:P X`) rather than `app\q7`, so an access-denied couldn't decide step 2's exit code.
- Step 6's kill is triggered by write count. A checkpoint-count kill, tried on `8eeda02`, landed after the last write, because the walk writes every dir before it checkpoints many.

Evidence (kept in the private lab repository): raw captures, harness and per-step logs.
