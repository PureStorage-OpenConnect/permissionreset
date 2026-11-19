# permissionreset-smb write path: design

| | |
|---|---|
| Date | 2026-11-15 |
| Status | **Draft for review.** The three-form model (section 2.1) was chosen by the maintainer on 2026-11-15, over writing every object explicit and protected. Phase 1 (section 8) is built: plan schema 2 (`build-spec --smb-plan`), `Inheritance`, `Desired` and `check`, and was qualified read-only at `700630b` on FlashArray (2026-11-16, `benchmarks/qual-smb-check-700630b-20261116/`). The same run answered Q-INH (matches), Q-EXP (no) and Q-PROT (yes) (section 7). Phase 2 (DACL apply) is built (2026-11-19, section 10) and **not yet qualified on hardware**. No release is qualified. |
| Builds on | `docs/decision-flasharray-smb-20261107.md` (sections 4–8), and the read-only scaffold in this directory |

This is how `permissionreset-smb` will reset DACLs and SACLs on FlashArray over SMB. It takes the
same spec as `permissionreset` and writes the array's native model. Inheritance stays dynamic, and
it writes only the objects whose stored descriptor is wrong.

## 1. What the hardware answers mean for the design

Section 8 of the decision record answered questions 1 and 3 on one lab FlashArray (2026-11-12):

- **F1.** The array stores exactly the DACL written to an object. It does not merge in the
  parent's inheritable ACEs.
- **F2.** An object's inherited (`ID`) ACEs follow later changes to its parent, with no write to the
  object, as long as they matched what the parent passed down when they were written. If they
  didn't match, they become a frozen copy that looks normal in a raw read.
- **F3.** A DACL write to a directory changes every unprotected descendant that only inherits. It is
  one synchronous call (3–4 ms on 51,100 objects). No later read saw the old DACL.
- **F4.** A DACL-only write (`DACL_SECURITY_INFORMATION`) leaves `S:AI`, the SACL bytes, owner and
  group as they were. (It was first recorded as leaving `D:AI` too; F5 corrects that.)
- **F5.** The array decides `D:AI` itself on a DACL write (phase 2 qualification run on `7ac90d8`,
  2026-11-19, which stopped on G2 because of it). An unprotected DACL write is stored with `D:AI`
  even when the control word sent has it clear, and a protected one is stored without it (a `D:PAI`
  written over SMB reads back as `D:P`), so no protected object on the array carries `D:AI`. The
  first Protected → Inherits or Explicit + inherits conversion therefore changes `D:AI` on every
  real tree, not only on NFS-flattened ones.

So:

1. **Objects that only inherit get no write.** After their parent is right, they are right (F3).
2. **When an object that should inherit must be written, its `ID` ACEs are computed from its
   parent's *desired* DACL, and the parent is written first** (F2). Otherwise the object freezes
   with no visible sign.
3. **The walk is top-down**: a directory is read, compared and if needed written before its
   children are read. That is the same fused walk the NFSv4 tool uses (CLAUDE.md, "Key design
   rules").
4. **DACL and SACL are separate writes**, each with only its own `SECURITY_INFORMATION` bit (F4).
   The NFSv4 tool's "an `acl:` rule with no `sacl:` key deletes the audit ACEs" problem does not
   exist here, and neither does its `ErrAuditedObject` refusal.

## 2. From spec to desired descriptor

### 2.1 What a spec rule means over SMB

A spec rule gives each object it matches a complete ACL ("rules replace, they do not merge",
`docs/spec-guide.md`). The spec guide already describes a matching rule as the Windows Security tab
with "Include inheritable permissions from this object's parent" unchecked. Writing every object
that way (explicit ACEs, `D:P`) is the literal reading. It is what the NFSv4 path produces on
FlashArray, and it is the flattening this tool exists to avoid.

The tool instead finds, for each object, the stored form that gives the spec's ACL **and** keeps
inheritance where the spec allows it. Let `want(o)` be the spec rule's ACL for object `o`,
translated to Windows ACEs (2.3), and `inh(p, isDir)` the ACEs that the MS-DTYP inheritance
algorithm passes from a parent DACL `p` to a child (2.4), with `ID` set. Comparing ACEs means
comparing type, flags without `ID`, mask and SID.

| Case | Condition | Desired stored DACL | Control |
|---|---|---|---|
| **Inherits** | `want(o) == inh(desired(parent), isDir)` | `inh(desired(parent), isDir)` | unprotected |
| **Explicit + inherits** | `want(o) == E ++ inh(desired(parent), isDir)`, with `E` and `inh(…)` both non-empty and no `ID` in `E` | `E ++ inh(…)` | unprotected |
| **Protected** | anything else | `want(o)`, every ACE explicit | `D:P` |

When the parent passes nothing down, the object is **Protected**, not **Explicit + inherits** with
an empty inherited part. The rule's ACL is complete, and **Protected** says so in the descriptor.
(This was first argued from the risk that an unprotected explicit-only ACL would take on whatever
the parent passes down later. Q-EXP found that FlashArray does not do that, but the choice stands:
it doesn't depend on that behavior.)

`desired(parent)` is the parent's desired DACL from this table, not its stored one, so the result
depends only on the spec and the tree shape. The run is deterministic and a rerun writes nothing.

For the spec guide's usual shape, a directory rule with `fd` ACEs and a file rule with the same
principals and no flags, most files are **Inherits**, and they need no write once their directory
is right. Directories whose rule repeats the parent's `fd` ACEs are **Inherits** too. A rule that
differs from what it would inherit gets **Protected**, which is what "rules replace" says.

### 2.2 The root

The root has no parent in the run. Its `desired(parent)` is read from the array: the root's stored
`ID` ACEs are taken as what it currently inherits. If `want(root)` equals them, the root is
**Inherits** and keeps following its real parent. If not, it is **Explicit + inherits** or
**Protected** as above. A frozen `ID` copy on the root (F2) can't be detected; the operator docs must say
so, and `--root-protected` forces **Protected** for the root.

### 2.3 Translating the spec's ACEs

`build-spec` does the translation, as it already does for SACLs (`internal/saclplan`), so the spec
keeps one parser. Plan schema 2 adds, per rule, `dacl: [ACE]` with the same ACE shape as `sacl`
(type, Windows flags, mask, principal, SID or empty, SDDL). This changes:

- `A`/`D` translate to `ACCESS_ALLOWED` (0) and `ACCESS_DENIED` (1). Flags and masks translate as
  `TranslateFlags`/`TranslateMask` already do.
- **`I` (inherited) in a spec ACE is refused** for the SMB plan. Inheritance is computed (2.1), and
  writing a hand-made `ID` ACE is exactly the F2 freeze.
- **`OWNER@` and `GROUP@` in a DACL are refused** until question Q-OWN (section 7) is answered.
  In NFSv4 they mean the object's current owner and group. On Windows, `CREATOR OWNER`
  (`S-1-3-0`) on an effective ACE grants nothing, and on an inheritable ACE it is replaced by the
  creating user's SID at inheritance time. The translation is not equivalent, and how FlashArray
  maps them over NFS is unknown. Set-SaclOnly maps them to `CO`/`CG` for audit ACEs, which keeps
  working.
- **A numeric id is refused**, as in Set-SaclOnly: an SMB ACE needs a SID.
- `name@domain` and `DOMAIN\name` are resolved to a SID on the Windows host at start, once per
  principal, and the run refuses before any write if one does not resolve. The resolved
  principal → SID table is printed and recorded in the evidence.
- `owner:`/`group:` are resolved the same way and written with `OWNER_`/`GROUP_SECURITY_INFORMATION`,
  which needs `SeRestorePrivilege` (section 4).
- `mode:` (posix) is refused; a plan from a posix spec already is.

### 2.4 The inheritance function

`inh(p, isDir)` follows the MS-DTYP inheritance rules for the cases the plan allows (no `CREATOR OWNER`):

- To a **file**: each ACE in `p` with `OI`, flags reduced to `ID`.
- To a **directory**: each ACE in `p` with `CI` or `OI`:
  - with `NP`: only if it has `CI`; flags become `ID` (effective on the directory, not passed on);
  - with `CI`: flags become `ID` plus the original `OI`/`CI` (`IO` cleared);
  - with `OI` and no `CI`: flags become `ID|IO|OI` (passed to files below, not effective here).
- Order is kept. Deny-before-allow canonical order is not imposed; the array keeps the order written.

This function is the riskiest part of the design: if it disagrees with what FlashArray derives, a
written object freezes (F2). It lives in `PermissionReset.Smb.Core` with table tests, and section
5 adds two guards and a hardware check of every flag combination before any release.

### 2.5 SACLs

The same three cases and the same `inh` apply to the SACL, with `S:P` instead of `D:P`, written
with `SACL_SECURITY_INFORMATION` only.

- A `sacl:`-only rule never touches the DACL. That is Set-SaclOnly's job, and this tool takes
  over its strict checks: owner, group and DACL are compared before and after.
- An `acl:` rule with no `sacl:` key leaves the SACL as it is.
- `sacl: []` means no audit ACEs: **Inherits** when the parent's SACL passes nothing down, else
  **Protected** and empty.

This is a change from Set-SaclOnly, which keeps each object's `S:P` flag and writes the plan's
ACEs as given. Moving SACLs to computed inheritance is phase 3 (section 8). Until then the SACL
path keeps Set-SaclOnly's behavior, so the two tools can be compared object for object.

## 3. The run

### 3.1 Walk

- Same selection as today (`RuleSelector`: first matching rule, base-name and anchored excludes;
  an excluded directory is pruned whole; the root is never excluded). Reparse points are opened as
  themselves, never followed, and skipped.
- A worker pool over directories. A directory's own read-compare-write finishes before its
  children are queued, so every child is compared against a parent that is already right (F2, F3).
  Siblings and subtrees run in parallel.
- Per object: open with backup intent (`FILE_FLAG_BACKUP_SEMANTICS`, `READ_CONTROL`, plus
  `ACCESS_SYSTEM_SECURITY` when the SACL is in play, `WRITE_DAC` when writing). One
  `GetKernelObjectSecurity` with every part the run checks, compare with the desired form, and write
  only what differs, with `SetKernelObjectSecurity` and only the bits that differ.
- `(UN)PROTECTED_DACL_SECURITY_INFORMATION` is always passed explicitly, so the control word is
  stated, never left to the server's default.

### 3.2 What "differs" means

Raw comparison: ACE count, order, type, flags (including `ID`), mask, SID, and the `P` bit. `AI` is
not part of the desired form: the array sets it itself (F4 recorded it unchanged), and a rule
never needs to change it. The descriptor is never normalized, sorted or SDDL-round-tripped (smb/
CLAUDE.md).

### 3.3 Modes

| Mode | Reads | Writes | Reports |
|---|---|---|---|
| dry run (default) | every object | nothing | per object: case, would-write parts |
| `--apply` | every object | only what differs | per object: written parts, before/after |
| `--validate` | every object | nothing | per object: mismatch against the desired form; exit 1 on any |

A dry run must read every object, since whether an object needs a write depends on what is stored.
It can't predict F3 propagation exactly: a child that differs only because its parent is about to
change is reported as "would write" in a dry run, and is found already right in the apply. The dry
run reports both counts: objects that differ now, and objects that would still differ after their
ancestors are written (computed, not read).

### 3.4 Checkpoint and resume

Directory-level, like the NFSv4 tool: a directory is recorded complete after it and its files are
done. Resume restarts from the last incomplete directories. Rewalking a completed part is safe,
because the compare finds it right and writes nothing.

## 4. Privileges, identity and preflight

- Required: an elevated process with `SeBackupPrivilege` (reads, listing), `SeSecurityPrivilege`
  (SACL), `SeRestorePrivilege` only when the plan sets owner or group. `SeRestorePrivilege` is
  turned off otherwise, as Set-SaclOnly does. On FlashArray the identity needs the audit bypass.
- **Preflight, before any object in the tree is written:**
  1. All principals resolve (2.3).
  2. A disposable probe directory under the root (or `--probe-dir`), with one subdirectory and one
     file: write the root's desired DACL and SACL to the probe, read them back raw, and check that
     the probe's two children inherited exactly `inh(…)` of it. This is guard G1 (5.1) on known
     data, and it proves the audit bypass the way `internal/auditproof` does for NFS. Refuse on any
     difference, delete the probe, write nothing else.
  3. The root's read, and its write if it differs, are next, then the walk.
- A missing privilege exits 1 and names it, as `inspect` does now.

## 5. Guards

### 5.1 G1: the inheritance canary

During the walk, an object that the run did **not** write, and whose case is **Inherits** or
**Explicit + inherits**, must show exactly `inh(desired(parent))` as its `ID` part once its parent
is right. A mismatch means `inh` disagrees with the array, or the parent's stored DACL is not what
the run thinks. Either way the run stops (no new writes; in-flight writes finish and are checked),
like Set-SaclOnly's strict policy. There is no override.

### 5.2 G2: read back every write

Every write is followed by a raw read, compared with the desired form, and with the parts that were
not written (owner, group, the other ACL, both `AI` bits) compared with the read before. Any
difference stops the run. That includes the case F4 says doesn't happen. `--no-readback` is not
offered in phase 1.

### 5.3 Other refusals

- Unresolved principals, `OWNER@`/`GROUP@` in a DACL, numeric ids, `I` in a spec ACE (2.3): refused
  before any write.
- An object whose descriptor can't be read or decoded is not written and is counted as an error.
- The children of a directory the run failed to write are not compared against its desired DACL,
  which it doesn't have. They are reported as not processed, and the run is incomplete.
- A file or directory whose type changed between listing and open is skipped and counted.

## 6. Output and evidence

- Per-object lines in the NFSv4 tool's vocabulary (`OK:`, `WOULD:`, `SKIP:`, `EXCLUDE:`, `ERR:`),
  plus the case (`inherits`, `explicit+inherits`, `protected`) and which parts were written.
- `--evidence-dir` writes `docs/evidence.md` records. The detailed profile adds the raw descriptor
  before and after, base64, as `inspect` prints it. New fields are added to that format, not forked
  (decision record, section 5).
- JSON summary: counts per case, writes per part, objects found right, G1/G2 stops, the principal
  table, privileges held, preflight result.

## 7. Open questions this design needs answered on hardware

| Id | Question | Blocks |
|---|---|---|
| Q-INH | Does `inh` (2.4) match FlashArray for every allowed flag combination (`OI`, `CI`, `NP`, `IO`, and pairs), on files and directories, allow and deny, DACL and SACL? | any release; G1 guards it at runtime |
| Q-OWN | How does FlashArray map `OWNER@`/`GROUP@` written over NFS to SMB, and is there an SMB form with the same meaning? | lifting the 2.3 refusal |
| Q-EXP | Does an **unprotected** object with only explicit ACEs gain inherited ACEs when its parent changes? (F1 shows it doesn't when written; later parent changes are untested.) | **Explicit + inherits** correctness when `E` is all there is |
| Q-PROT | Does clearing `D:P` with a write of `ID` ACEs (**Protected** → **Inherits**) leave the object dynamic (F2) the same as one that was never protected? | converting flattened (NFS-written) trees |
| Q2 | Throughput: parallel read-compare over SMB from one Windows host, then with writes, on the same tree as the NFSv4 numbers. | performance claims only |

Q-PROT matters most in practice: trees that were reset over NFS are `D:P` with explicit ACEs on
every object (RISKS.md #11), and converting them back to dynamic inheritance is the main use.

**Answered on FlashArray (Purity//FA 6.10.7, 2026-11-16,
[benchmarks/qual-smb-check-700630b-20261116](../benchmarks/qual-smb-check-700630b-20261116/RESULTS.md)):**
Q-INH **matches** (all 11 rows, allow, deny and audit, 280 objects, 0 differences). Q-EXP **no**
(an unprotected explicit-only object ignores later parent changes; one object). Q-PROT **yes** (a
`D:P` object rewritten with `ID` ACEs and `D:P` cleared follows later parent changes, and so do its
unwritten children). Q-OWN and Q2 remain open.

## 8. Phases

1. **DACL, read-compare, dry run and validate.** Plan schema 2 in `build-spec` and `Plan.cs`,
   `inh` and the case function in Core with table tests, the walk, `--validate`. No writes. Can be
   qualified for read accuracy and case classification against `inspect`.
2. **DACL apply.** Writes, preflight with probe, G1, G2, checkpoint, evidence. Needed Q-INH, Q-EXP
   and Q-PROT answered first (done on FlashArray, 2026-11-16), then a hardware qualification on the exact candidate (raw before/after
   on a fixture covering every case, an NFS-flattened tree, an audited subtree, a protected
   subtree, and a deny-only directory under backup intent). **Built 2026-11-19** (section 10);
   the hardware qualification is pending.
3. **SACL**, first with Set-SaclOnly's behavior and its strict checks (a parity run against
   Set-SaclOnly on the same fixture), then computed SACL inheritance. Set-SaclOnly is retired only
   after a release is qualified for SACL writes on FlashArray and on FlashBlade (decision record,
   section 2.5), so this phase includes a FlashBlade SACL design and qualification.
4. **`smb-v0.1.0`** when phase 2 is qualified: the tag (the `smb-v*` release workflow is built), a
   COMPATIBILITY.md row, and the platform-to-tool split in the operator docs.

## 9. What this design leaves out

- Repairing ownership of objects the spec does not name an owner for.
- Concurrency limits or pacing for the array's controller. Q2 decides whether that is needed.
- FlashBlade DACLs. FlashBlade stays on the NFSv4 tool for DACLs (decision record, section 2);
  running this tool's DACL path on FlashBlade is not designed or tested. FlashBlade SACLs are not
  left out: Set-SaclOnly's retirement waits on them (phase 3, decision record section 2.5), and
  their design comes with phase 3.
- `CREATOR OWNER` and `CREATOR GROUP` placeholders, object-type ACEs, and conditional ACEs: refused
  if the plan names them, and preserved byte for byte only where the tool does not write.

## 10. Phase 2 as built (2026-11-19)

`permissionreset-smb apply PLAN.json ROOT` (`Checker` with `WalkOptions.Apply`, `Preflight`,
`FileCheckpoint`, `Evidence`, `DescriptorBuilder` in Core; `Win32Security.WriteDescriptor` and the
probe's create/delete calls in the CLI). Offline tests run it against `CheckerTests.FakeTree`, which
models F1-F3. Where it departs from or settles the text above:

- **Modes.** The dry run and `--validate` stay `check` (3.3); writing is a separate command,
  `apply`, rather than a flag. `--root-protected` (2.2) is on both.
- **The write call (3.1).** One `SetKernelObjectSecurity` per written object, on a handle opened
  with backup intent, no reparse following, and only the access the parts need (`WRITE_DAC`,
  `WRITE_OWNER`). It is the handle form of the `SetFileSecurityW` the section 7 runs used; nothing
  goes through `SetSecurityInfo`, which would do inheritance work on the client. The protection is
  stated twice: `PROTECTED_`/`UNPROTECTED_DACL_SECURITY_INFORMATION` and `SE_DACL_PROTECTED` in the
  control word. `SE_DACL_AUTO_INHERITED` is sent as the array stores it (F5): set on an unprotected
  DACL, clear on a protected one. Before F5 the stored bit was copied, which the array overrode. The read that decides and the write are separate opens, so an
  object that is already right never needs `WRITE_DAC`.
- **Privileges (4).** SeBackupPrivilege and SeSecurityPrivilege always (an object that needs a
  write is read again with its SACL just before the write, as G2's before-image, and read back with
  it; the compare itself reads the DACL only); SeRestorePrivilege only when a rule names an owner or group, and
  explicitly disabled otherwise. A DACL write therefore needs `WRITE_DAC` from the object's own DACL
  or from owning it. The probe, which the identity creates and owns, does not prove that for live
  objects; a live object that refuses it is an `ERR:` (`write dacl: open for write: …`), not a stop.
- **Preflight (4, step 2).** The probe directory gets the root's desired ACEs (ID cleared) as a
  protected DACL, and one placeholder audit ACE (Everyone, success and failure, `FILE_READ_DATA`) as
  a protected SACL. It must read back exactly, owner and group unchanged, and keep the audit ACE; its
  subdirectory and file, created before the write, must hold exactly `inh(…)` as their inherited
  part. If the root's DACL passes nothing down, that last check only shows nothing was inherited, and
  the preflight line says so. The subdirectory then takes the write most of the walk makes, an
  unprotected DACL (one explicit `OWNER RIGHTS` read-and-execute ACE, then its inherited part, `D:AI`
  set per F5), and must pass G2's own read-back comparison, so an array that drops, reorders or
  re-derives such a write, or handles `D:AI` differently, refuses the preflight before the root is
  written. Before removal the probe's DACL is rewritten to `OWNER RIGHTS` full
  control, inheritable, so the creating identity can delete it whatever the root's ACEs grant. A
  probe that cannot be removed fails the preflight. `--probe-dir` must already exist.
- **G1 (5.1)** is checked where the run would otherwise write: an object of form **Inherits** or
  **Explicit + inherits** whose stored DACL is unprotected, has the right explicit part, and is
  inherited after it, but whose inherited part differs from `inh(desired(parent))`. In `apply` the
  parent is already right when the child is read, so in a tree the array keeps dynamic this is
  exactly the disagreement G1 exists for. **It also fires on a frozen copy (F2) that predates the
  run**, which one read cannot tell apart; `check` reports those as `write … (a frozen copy)`, and
  `apply` stops on them with no override, as the text says. **Open for the maintainer:** whether a
  frozen copy found under a parent the run did not write should be rewritten instead (the probe
  having already checked `inh` against this array), and what evidence would justify it.
- **G2 (5.2)** reads back through a fresh open and compares, raw: the DACL and its protection with
  the desired form; owner and group with what was written or, if not written, the read before; the
  SACL ACE for ACE; `SaclAutoInherited`, `SaclProtected` and `SaclPresent` with the read before; and
  `DaclAutoInherited` with F5's measured value after a DACL write (set when unprotected, clear when
  protected) or, when only owner or group was written, with the read before. G2 still stops on any
  other `D:AI` result, so an array that handles it differently is caught rather than accepted.
- **Stopping.** On the first G1 or G2 failure no new write or directory listing starts. A write
  already past its check finishes and is read back. Objects that needed a write after the stop are
  `stopped`; unreached directories count as not processed. Exit 1.
- **Not built from 5.3:** a file or directory whose type changed between listing and open is not
  detected; it is read and judged as the type the listing gave.
- **SACLs.** A plan whose rules set `sacl:` is refused by `apply` rather than applied without its
  audit ACEs (phase 3). `build-spec --smb-plan`'s golden plan has such rules, so qualification needs a
  DACL-only spec.
- **Checkpoint (3.4).** `--checkpoint FILE`: a header naming the plan's SHA-256, the root and
  `--root-protected`, then one JSON string per complete directory (the directory and every file in
  it right). `--resume` requires the header to match; without it an existing file is refused. A
  complete directory is still read and listed (its children need its desired DACL, and its
  subdirectories are not covered), but its files are skipped.
- **Evidence (6).** `--evidence-dir` (new or empty) holds one uncompressed `shard-000001.log` and
  `manifest.json`, in docs/evidence.md's shape (status and reasons, shard name, SHA-256, size and
  record count), plus run id, version, root, plan path and SHA-256, the principal table, privileges,
  the preflight line, and counts per outcome and form. There is one profile: every `OK:` (written)
  line and every `ERR:` after a write carries `before=` and `after=`, the raw descriptors in base64.
  No `--json-summary`; the manifest carries the summary, and stderr prints it. Stdout keeps
  `check`'s JSON lines (outcomes `written` and `stopped` added, raw descriptors left out).
- **Ordering of refusals.** The plan is parsed and resolved, privileges are enabled, the evidence
  directory is checked, the checkpoint opened, and only then are evidence files created, so a refusal
  at any of those steps leaves no checkpoint or evidence behind.
