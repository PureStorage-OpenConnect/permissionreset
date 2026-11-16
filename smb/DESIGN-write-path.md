# permissionreset-smb write path: design

| | |
|---|---|
| Date | 2026-11-15 |
| Status | **Draft for review.** The three-form model (section 2.1) was chosen by the maintainer on 2026-11-15, over writing every object explicit and protected. Phase 1 (section 8) is built: plan schema 2 (`build-spec --smb-plan`), `Inheritance`, `Desired` and `check`. No write code exists. Nothing here is qualified. |
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
- **F4.** A DACL-only write (`DACL_SECURITY_INFORMATION`) leaves `S:AI`, `D:AI`, the SACL bytes,
  owner and group as they were.

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
an empty inherited part. The rule's ACL is complete, and an unprotected explicit-only ACL would take
on whatever the parent passes down later (hardware question Q-EXP).

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

## 8. Phases

1. **DACL, read-compare, dry run and validate.** Plan schema 2 in `build-spec` and `Plan.cs`,
   `inh` and the case function in Core with table tests, the walk, `--validate`. No writes. Can be
   qualified for read accuracy and case classification against `inspect`.
2. **DACL apply.** Writes, preflight with probe, G1, G2, checkpoint, evidence. Needs Q-INH, Q-EXP
   and Q-PROT answered first, then a hardware qualification on the exact candidate (raw before/after
   on a fixture covering every case, an NFS-flattened tree, an audited subtree, a protected
   subtree, and a deny-only directory under backup intent).
3. **SACL**, first with Set-SaclOnly's behavior and its strict checks (a parity run against
   Set-SaclOnly on the same fixture), then computed SACL inheritance. Set-SaclOnly is retired after
   a qualified release covers it (decision record, section 2).
4. **`smb-v0.1.0`** when phase 2 is qualified: the `smb-v*` release workflow, a COMPATIBILITY.md
   row, and the platform-to-tool split in the operator docs.

## 9. What this design leaves out

- Repairing ownership of objects the spec does not name an owner for.
- Concurrency limits or pacing for the array's controller. Q2 decides whether that is needed.
- FlashBlade. FlashBlade stays on the NFSv4 tool (decision record, section 2); running this tool on
  FlashBlade is not designed or tested.
- `CREATOR OWNER` and `CREATOR GROUP` placeholders, object-type ACEs, and conditional ACEs: refused
  if the plan names them, and preserved byte for byte only where the tool does not write.
