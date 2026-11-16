# FlashArray over SMB: dynamic inheritance and audited DACL writes (2026-11-12)

Answers to questions 1 and 3 of the FlashArray SMB decision record
([section 8](../../docs/decision-flasharray-smb-20261107.md#8-open-questions-resolve-before-design-1-and-3-answered)).

**This is a test of array behavior, not a product qualification.** `permissionreset-smb` had no write
path, so no product binary was involved. Every write and read came from a lab harness that calls the
Win32 security APIs directly. Nothing here qualifies a build of either tool.

| | |
|---|---|
| Array | A lab FlashArray, Purity//FA 6.10.7 (from the 2026-11-03 record, not re-read on the day; confirmed as 6.10.7 when re-read on 2026-11-16) |
| Client | A lab Windows Server 2022 host, SMB 3.1.1, elevated, as a mapped domain account holding `SeSecurityPrivilege` and `SeBackupPrivilege` |
| Share | One SMB share already used for earlier permissionreset tests. Each run worked in a new directory, deleted afterwards. No array or infrastructure changes |
| Principals | Mapped principals only, no new accounts |
| Harness | Lab scripts kept in the private lab repository: `Run-Q1Q3.ps1` and `Check.ps1` at revision `065a6cf` (Q1a, Q3), and `Run-Q1b.ps1` at `def8f99` (Q1b) |
| Write | One `SetFileSecurityW` call per step, `DACL_SECURITY_INFORMATION` only, on one object |
| Read | `GetFileSecurityW` with owner, group, DACL and SACL. The full descriptor bytes were kept. No second reader. `Get-Acl` was not used, because it sorts and merges ACEs |
| Control | On local NTFS, the same scripts change no descendant: Windows' client-side propagation is not involved, so whatever changed below a written object on the array, the array changed |

## Verdict

| Case | Question | Result |
|---|---|---|
| Q1a, steps 1–4 | Does a child written with its parent's inheritable ACEs in inherited form (`ID`) keep following the parent? | **Yes, dynamic** |
| Q1a, step 5 | The same, with one explicit ACE added? | **Yes:** explicit ACE kept first, inherited part dynamic |
| Q1a, extra case | A child written with `ID` ACEs its parent does not grant | **Unexpected:** stored as written and frozen (below) |
| Q1b | Does one root write on a large tree return before the descendants change? | **No lag observed:** 3–4 ms, 0 of 51,100 stale |
| Q3 | Does a DACL-only write on an audited object leave `S:AI`, `D:AI` and the SACL alone? | **Pass,** directory and file |

## Q1a: do client-written inherited ACEs stay dynamic?

Fixture: `R/A/B/f`. `R` carries inheritable ACEs X. `A` is unprotected and its DACL is written once in
inherited form: X with `ID` set. `B` and `f` are never written. Then `R` is changed with one write
(X → Y), and again (Y → a third DACL). The trees held 10–19 objects.

- **Steps 1–4:** `A`, `B` and `f` showed Y after the first root write, then the third DACL after the
  second. Reads 16 ms after the call returned and 60 s later were byte-identical, so the change is
  synchronous on a small tree.
- **Step 5:** with one explicit ACE written alongside the inherited-form ACEs, the explicit ACE stayed
  first and the inherited part followed both root changes.
- Steps 1–4 wrote to `A` what it already had from creation, so on their own they cannot tell
  "dynamic" apart from "write ignored". The extra case is what separates the two.
- **Extra case (unexpected):** `A` written with `ID` ACEs that `R` does not grant. The array stored
  them as written, without correcting them. They stayed unchanged through both root changes, and
  `A`'s children followed `A`, not `R`. A raw read of `A` looks like an ordinary inherited DACL;
  nothing in the descriptor shows that it is frozen. One rewrite of `A` with `R`'s current inheritable
  ACEs in inherited form made it follow the next root change again. **This rests on one case.**

The reading the results support, not yet tested beyond that one case: written `ID` ACEs stay dynamic
only when they match what the parent passes down at the time of the write.

## Q1b: one root write on a large tree

Fixture: 51,100 objects created over SMB with no ACL writes below the root (50 × 10 × 100 files, plus
5 chains of directories 10 deep; the deepest leaf is 11 levels down), built in 9 s. Before the writes,
500 of 500 sampled objects carried the root's ACEs as inherited. After each root write the harness
polled the deepest leaf from the moment the call returned, swept the 500 samples until they agreed,
re-checked at 60 s, and finished with a full read of every object.

| Root write | Call | Deepest leaf | 500-object sweep (from t+19 ms) | t+60 s | Full read |
|---|---|---|---|---|---|
| v1 → v2 | 4.0 ms | new DACL at its first read, 5.5 ms after return | 0 stale | 0 stale | 0 / 51,100 mismatches, 0 errors |
| v2 → v1 | 3.2 ms | new DACL at its first read, 3.5 ms after return | 0 stale | 0 stale | 0 / 51,100 mismatches |

No read taken after a call returned ever saw the old DACL. Call time did not grow with the tree: 3–4 ms
here, against 3–15 ms on the 10–19 object trees of Q1a. That is consistent with the array resolving
inheritance by reference or when an object is read, rather than rewriting descendants, which would
also explain the frozen copy in Q1a. That explanation is an inference; nothing here observed the
mechanism.

## Q3: a DACL-only write on an audited object

Fixture: a directory and a file whose control word showed `S:AI` and `D:AI`, each with an inherited
audit ACE and inherited DACL ACEs. Each took two DACL-only writes: first the same bytes it already
had, then the DACL with one explicit ACE prepended.

| | Before | After both writes |
|---|---|---|
| Control word | `0x8C14` | `0x8C14` |
| `SE_DACL_AUTO_INHERITED`, `SE_SACL_AUTO_INHERITED` | set | set |
| `SE_DACL_PROTECTED`, `SE_SACL_PROTECTED` | clear | clear |
| SACL (44 bytes) | | identical |
| Owner, group | | unchanged |
| Inherited ACEs | `ID` | kept `ID`; the new explicit ACE has none |

An unwritten child of the directory picked up the new ACE as inherited. Over NFS, by contrast, an ACL
write on FlashArray turns `S:AI`/`D:AI` into `S:P`/`D:P` ([RISKS.md](../../RISKS.md) #11), which is
the reason for the move to SMB.

## What it means for the design

Objects that only inherit need no write. An object that has to be written and should inherit must
take its `ID` ACEs from its parent's stored DACL, and parents must be written before children;
otherwise the object freezes and its descriptor shows no sign of it. `smb/DESIGN-write-path.md`
builds on this.

## Limits

- One array, one client, one account. Small trees for Q1a and Q3; one tree size (51,100) for Q1b.
- The frozen-copy result in Q1a comes from one case.
- Q1b was not a timing hold: other work may have shared the array, and array load was not captured.
  The timings are indicative.
- Q3 covers stored audit rules only, not delivered audit events.
- Raw descriptors were read with one reader; `permissionreset-smb inspect` was not used as a second.
- None of this qualifies `permissionreset-smb`'s own write path, which has to be qualified on its
  exact candidate (decision record, question 3).
- The later inheritance questions (Q-INH, Q-EXP, Q-PROT in `smb/DESIGN-write-path.md`) are a separate
  run and not summarized here.

Evidence (kept in the private lab repository): the brief, the harness scripts, per-case raw
descriptor captures, and the per-run results files.
