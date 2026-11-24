# `permissionreset-smb` phase 1 and FlashArray inheritance (2026-11-16)

Two things, run together on one lab FlashArray over SMB:

- **A. Phase 1 qualification** of `permissionreset-smb`'s read-only commands, `inspect` and `check`,
  on an exact candidate ([DESIGN-write-path.md](../../smb/DESIGN-write-path.md) section 8, phase 1).
- **B. Platform tests** Q-INH, Q-EXP and Q-PROT (the same design, section 7), which block the write
  path. B is a test of array behavior through a lab harness, not a qualification of any write path:
  the tool has none.

**This qualifies no release.** There is no `smb-v*` tag. A is evidence for the read-only commands at
this candidate only. B answers design questions; the write path still needs its own qualification on
its own candidate (phase 2).

| | |
|---|---|
| Candidate (A) | `700630b40395ce248e2b4a4ca80dd22cf16ebd4f` (`main`), unmodified, tool version 0.1.0. Built with `smb/release/pack.ps1` from `smb/`, so `global.json` selected .NET SDK 8.0.427 as CI does. `permissionreset-smb.exe` SHA-256 `A5775B6CF42C4CF28B96B5DE907D08B497B087CF9808DD1B693F4DDE60258054`. Unit tests at the candidate: 1641/1641 |
| Other builds | The same pack run from the repo root picked the host's SDK 10.0.403 and produced a different exe; it was recorded and not used. `build-spec` built at the same commit with the Makefile flags (Go 1.25.0); its `--smb-plan` output equals `smbplan.golden.json` apart from the source path |
| Array | A lab FlashArray, Purity//FA 6.10.7 (read 2026-11-16, re-read unchanged 2026-11-17) |
| Client | A lab Windows Server 2022 host (build 20348.5386), SMB 3.1.1 |
| Identity | Elevated, a mapped domain account holding `SeBackupPrivilege`, `SeSecurityPrivilege` and the array's audit bypass, as in the [2026-11-09 inspect run](../qual-smb-inspect-20261109/RESULTS.md). Mapped principals only |
| Share | One existing lab SMB share. Each run worked in a new directory, deleted afterwards. No array, share or configuration change |
| Reference reader | `GetFileSecurityW` (owner, group, DACL, SACL), raw bytes kept, independent of the tool's handle-based reads |

## Verdict

| Part | Check | Result |
|---|---|---|
| A1 | `inspect` failure handling, three cases | **PASS 3/3** |
| A2 | `check` case classification and right/differs verdict | **PASS**, 81/81 records agree across three stages |
| A2 | `check --validate` exit codes | **PASS** |
| B | Q-INH: does the tool's inheritance function match the array? | **Matches**, 280/280 objects, 0 differences |
| B | Q-EXP: does an unprotected, explicit-only object pick up later parent changes? | **No** |
| B | Q-PROT: does a flattened object, rewritten in inherited form, become dynamic? | **Yes** |

## A1. `inspect` reruns

Three cases that the 2026-11-09 run found or did not cover. Passed 3, failed 0, skipped 0,
unverified 0.

- **A missing path mixed with a good one.** Exit 1, one record per path. The failed record's `error`
  names the step and the reason (`open: …`) with `win32_error` 2 for a missing file and 3 for a
  missing directory, and carries no descriptor and no `sacl_read`. The good record's raw bytes equal
  a fresh `GetFileSecurityW` read.
- **No `SeBackupPrivilege`.** `inspect`, `inspect --no-sacl` and `check` each exit 1 with one line
  naming the privilege. No exception, nothing read. (This was the 2026-11-09 failure, an unhandled
  exception.) Also checked: without `SeSecurityPrivilege`, `inspect` exits 1 naming it, while
  `--no-sacl` and `check`, which read no SACL, exit 0 as documented.
- **Medium integrity.** UAC is off on this host, so no shell gets a UAC-filtered token. The run used
  an equivalent built by hand: a Safer `NormalUser` token (Administrators deny-only, privileges
  stripped to `SeChangeNotifyPrivilege`) at the Medium label. All three commands exit 1 naming
  `SeBackupPrivilege`. **This is not a UAC split token**, and a real one is still untested.

## A2. `check` accuracy

One fixture covering each case (inherits, explicit + inherits, protected), an NFS-flattened tree
(`D:P`, every ACE explicit), an audited subtree, a protected subtree, and a deny-only directory read
under backup intent. The plan came from `build-spec --smb-plan`. `check` (dry run) and
`check --validate` were compared with an independent classifier written from the design text, which
reads raw `GetFileSecurityW` and walks the fixture builder's manifest, not `check`'s listing.

| Stage | Objects agree | `check` / `--validate` | Notes |
|---|---|---|---|
| 1. Conforming tree | 25/25 | 0 / 0 | inherits 19, explicit + inherits 1, protected 3, keep 1, excluded 1 |
| 2. One file changed | 25/25 | — / 1 | the only non-ok record is that file: "stored ACL has 3 ACE(s), want 2" |
| 3. Adds an NFS-flattened tree and a frozen inherited-form copy | 31/31 | — | ok 22; write 6 (the 4 flattened objects "protected, want unprotected", the changed file, the frozen directory); follows 1 (the frozen directory's child). Inherits 25, explicit + inherits 1, protected 3 |

- `check` reads no SACL, so the audited subtree tests that audit ACEs don't disturb DACL
  classification, nothing more.
- The deny-only directory's children refused a plain `GetFileSecurityW` (error 5). `check` read them
  with backup intent, and so did the reference reader for those 3 objects. Listing the deny-only
  directory itself worked without backup intent on this array (likely because the identity owns it),
  so this case exercises backup-intent descriptor reads, not backup-intent listing.
- **Unverified:** the reparse-point outcome. The fixture had no reparse points.

## B. Platform behavior

Every write was one DACL-only `SetFileSecurityW` from the lab harness; every read a raw
`GetFileSecurityW`. The fixture was built over SMB. Earlier partial runs (2026-11-15 and 2026-11-16)
had answered most Q-INH allow rows and Q-EXP/Q-PROT with one parent change. This run checks the
candidate's own `Inheritance.Inherit`, and adds the `OI|CI|NP|IO` row, deny and audit for every row,
and two parent changes.

> **Correction (2026-11-24).** The first sentence above is inaccurate for the audit rows. Per the
> lab record of this run, the parents' audit ACEs in Q-INH were written by SACL-only
> `SetFileSecurityW` (`SACL|PROTECTED_SACL`). The DACL rows were DACL-only writes, as stated. See
> `smb/DESIGN-sacl-write.md`, K4.

**Q-INH: matches.** All 11 rows of the table in
`smb/tests/PermissionReset.Smb.Tests/InheritanceTests.cs`, each as allow, deny and audit (SA and FA;
SA-only and FA-only too for `OICI`). Every case has file and directory children and grandchildren,
created both before the parent's one write (propagated) and after it (created then). 35 parents, 280
objects, 0 differences from the prediction. The prediction is the candidate's `Inheritance.Inherit`,
which equals the table on every row. Children's control word was `D:AI S:AI` throughout.

**Q-EXP: no.** An unprotected object holding only explicit ACEs gained nothing from either of two
parent changes, and its children followed it, not the parent. A never-written control followed both
changes. This rests on 1 object, 2 children, 1 control and 2 changes.

**Q-PROT: yes.** A `D:P` object with all-explicit ACEs was written once with its parent's inheritable
ACEs in inherited (`ID`) form and `D:P` cleared. It then followed both parent changes like the
never-protected control, and so did its 3 unwritten children (a file, a directory, a file in that
directory). Here the protected object was built over SMB. The variant flattened by a real NFS reset
passed on 2026-11-16 with one parent change.

**Stability.** All 365 objects were re-read about 20 s after the last write; the 330 platform
objects were byte-identical to their last capture.

## What this means for the design

- **Q-INH** unblocks every release on the inheritance function; G1 still guards it at runtime.
- **Q-PROT** confirms the main use: a tree flattened by an NFS reset can be made dynamic again by
  writing the parent's inheritable ACEs in inherited form with `D:P` cleared.
- **Q-EXP** answers the opposite of what the design assumed. Section 2.1 makes an object whose parent
  passes nothing down **Protected**, partly because an unprotected explicit-only ACL "would take on
  whatever the parent passes down later". On this array it does not. **Protected** remains the right
  case: it states the rule's intent in the descriptor, and doesn't depend on that behavior.

## Limits

- One array, one client, one account; small fixtures. No `CREATOR OWNER` ACEs, no generic masks, no
  timing.
- Q-EXP rests on one object.
- The audit rows cover how stored audit ACEs are inherited, not delivered audit events.
- Claims are kept apart: read fidelity (A1), case classification (A2), inheritance behavior (B), and
  stored audit rules (B's audit rows).

Evidence (kept in the private lab repository): the brief, the harness, per-case raw descriptor
captures, and the per-host results file.
