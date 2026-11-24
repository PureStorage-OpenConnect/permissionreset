# permissionreset-smb phase 3: SACL writes on FlashArray over SMB

| | |
|---|---|
| Date | 2026-11-20 |
| Status | **Draft for review. Design only; nothing here is built or qualified.** This extends `smb/DESIGN-write-path.md` (sections 2.5 and 8, phase 3). The maintainer's decisions of 2026-11-23 are recorded in section 11; the rest of the text follows them. |
| Scope | FlashArray only. FlashBlade is out of scope (section 11, decision 9). Set-SaclOnly's retirement still needs FlashBlade covered (`docs/decision-flasharray-smb-20261107.md:66-71`), so this phase does not retire it. |
| Base | The phase 2 DACL apply in PR #73 (`smb-phase2-apply` @ `632cfc0`), not `main` alone. Citations marked **P2:** are paths and lines at that commit. Other citations are against `main` @ `d91cf0d`. |
| Builds on | `smb/DESIGN-write-path.md`, `tools/set-saclonly/`, `benchmarks/qual-smb-check-700630b-20261116/`, `benchmarks/qual-smb-apply-e834ac8-20261119/` (on P2) |

**ASSUMPTION** marks what is inferred rather than read. **UNVERIFIED** marks Windows API or array
behaviour that no record in this repository establishes. Section 12 says how this text was written
and which claims were checked by hand.

## 0. Summary

The SACL gets the DACL's three-form model (`Inherits`, `Explicit + inherits`, `Protected`), the same
`inh` function and its own G1 and G2 guards. It is written by its own `SetKernelObjectSecurity`
call carrying `SACL_SECURITY_INFORMATION` and an explicit SACL protection bit. The JSON plan shape
does not change, since schema 2 already carries `sacl_set`, `keep_dacl` and `sacl`. But a plan that
sets `sacl:` moves to **schema 3**, to mark the new write semantics. The producer gets one new
refusal and the consumer four new checks. `check` and `apply` read the SACL on every object
whenever any rule sets `sacl:`, so both need `SeSecurityPrivilege`. The preflight probe proves SACL
behaviour on data that is not the tree's before any tree SACL is read. The tool promises end-state
evidence, not rollback. Twelve hardware questions (section 8) block the release. One record that
looked like an answer (audit rows in Q-INH) does not settle the SACL side, because every write in it
was DACL-only.

## 1. What is known

| Id | Fact | Source |
|---|---|---|
| K1 | A DACL-only SMB write leaves the SACL bytes and the SACL control bits unchanged. Phase 2's G2 enforces this on every write. | `smb/DESIGN-write-path.md:24-25`; P2:`smb/src/PermissionReset.Smb.Core/Checker.cs:435-456` |
| K2 | A SACL-only SMB write that **copies** the object's own `S:P`/`S:AI` leaves owner, group, every DACL ACE and every DACL control flag unchanged on FlashArray. That is Set-SaclOnly's write. Whether a write that **changes** `S:P` does the same is unknown. | `tools/set-saclonly/SaclOnly.cs:294-307`; `RISKS.md:134-139`; `benchmarks/sacl-ps07-20261026/RESULTS.md` |
| K3 | Over NFS, any FlashArray ACL write marks `S:AI` to `S:P` and `D:AI` to `D:P`. Objects written that way read back over SMB as `S:P` and `D:P`. | `CLAUDE.md` (SACL mode); P2:`benchmarks/qual-smb-apply-e834ac8-20261119/RESULTS.md:49-58` |
| K4 | The phase 1 hardware run reports audit rows for Q-INH (`SA`, `FA`, both), with children inheriting as `inh` predicts. The same record says "every write was one DACL-only `SetFileSecurityW`". How audit ACEs reached the parents is therefore not recorded. **K4 is not evidence for SACL writes**; see Q-SACL-INH. | `benchmarks/qual-smb-check-700630b-20261116/RESULTS.md:78-90` |
| K5 | The phase 2 preflight writes one protected, non-inheritable placeholder audit ACE to the probe and requires it to read back. This proves the array kept a SACL write on the probe. It proves nothing about SACL inheritance. | P2:`smb/src/PermissionReset.Smb.Core/Preflight.cs:71-87` |
| K6 | Phase 2 `apply` refuses any plan with a `sacl_set` rule. | P2:`smb/src/PermissionReset.Smb/Program.cs:229-233` |
| K7 | The spec guide says an NFS read by an identity without the bypass emptied an inheriting object's SACL on Purity//FA 6.10.6, and that "SMB reads do not do this". No benchmark record backs the SMB half. | `docs/spec-guide.md:736-739` |
| K8 | `Descriptor` recognises SACL ACE types it does not model: mandatory label (0x11), resource attribute (0x12) and scoped policy id (0x13). | P2:`smb/src/PermissionReset.Smb.Core/Descriptor.cs:113-117` |

The largest gaps:
- whether a SACL written in inherited form stays dynamic or freezes (the DACL's F2);
- whether the array decides `S:AI` itself, as it does `D:AI` (F5);
- whether a SACL write that changes `S:P` disturbs the DACL;
- whether audit events are delivered at all for what is stored.

## 2. Plan schema

### 2.1 What exists

The producer is `saclplan.BuildSMB` (`internal/saclplan/saclplan.go`). The consumer is `Plan.Parse`
(P2:`smb/src/PermissionReset.Smb.Core/Plan.cs`). Per rule, schema 2 already carries:

| Field | Producer | Consumer today |
|---|---|---|
| `sacl_set` | true when the spec names a `sacl:` key, `sacl: []` included (`internal/spec/spec.go`, `SaclSet`) | parsed; `apply` refuses it (K6) |
| `keep_dacl` | `sacl:` given and no `acl:` (`KeepDACL`) | parsed; printed by `plan` only |
| `has_acl` | `len(rp.ACL) > 0` (`saclplan.go:300`) | must equal `dacl` present (P2:`Plan.cs:56-57`) |
| `sacl` | **always present**; `[]` both when the key is absent and when it is `sacl: []` (`saclplan.go:305-309`) | each ACE must be type 2 with no `ID` (P2:`Plan.cs:65-70`) |
| `dacl` | `omitempty`; present exactly when `has_acl` (`saclplan.go:113-115`) | as phase 2 |

Audit ACE flags come from the same translation as the DACL's: `S` becomes `SA` (0x40), `F` becomes
`FA` (0x80), and `f`/`d`/`n`/`i` become `OI`/`CI`/`NP`/`IO`. `I` is refused in both lists, and so
are numeric principals (`saclplan.go:244-253`). `OWNER@` and `GROUP@` map to `CO`/`CG`
(`saclplan.go:79-83`) and are refused only in the DACL (`saclplan.go:248-249`).

**The JSON shape does not change, but the schema version does** (section 11, decision 7). Schema 3
marks the change in write semantics: in schema 2, `sacl_set` is a rule the consumer refuses (K6); in
schema 3 it is a SACL write. Proposed compatibility rule, **for the maintainer to confirm**:

| Build | `--smb-plan` emits | `check`/`apply` accept |
|---|---|---|
| phase 2 (`smb-v0.1.x`) | schema 2 | schema 2; a `sacl_set` rule is refused (K6). Schema 3 is refused as an unknown version. |
| phase 3 | schema 3 when any rule sets `sacl:` (`sacl: []` included); schema 2 otherwise | schema 2 with no `sacl_set` rule (a DACL-only plan, unchanged meaning); schema 3. A schema 2 plan with a `sacl_set` rule is refused, with a message to rebuild it. |

So a DACL-only plan stays schema 2 and still loads in a qualified phase 2 build. A plan that writes
SACLs can't reach a build that would refuse it only rule by rule, and an old schema 2 SACL plan is
never reinterpreted. `--sacl-plan` stays schema 1 (Set-SaclOnly's), and `plan` keeps reading it for
display only.

### 2.2 What must be added

Producer (`BuildSMB`):

1. **Refuse `OWNER@` and `GROUP@` in `sacl:`.** `Inheritance.Inherit` throws on creator SIDs because
   the inherited SID depends on who created the child (P2:`Inheritance.cs`, `CreatorSids`). A
   directory whose desired SACL names `CO`/`CG` with any inheritance flag would leave every child
   unclassifiable. Set-SaclOnly accepts them, so `--smb-plan` becomes stricter than `--sacl-plan`
   here (section 11, decision 6). `--sacl-plan` (schema 1) is unchanged.

Consumer (`Plan.CheckAces`), all checked before any probe or read:

2. **Every audit ACE carries `SA`, `FA` or both.** The spec parser already requires it, but the
   consumer does not (P2:`Plan.cs:65-70`), so a hand-edited plan could write an ACE that audits
   nothing.
3. **Refuse `CO`/`CG` (`S-1-3-0`, `S-1-3-1`) in `sacl`**, mirroring item 1, so a plan from an older
   build-spec is refused up front rather than failing child by child.
4. **Refuse `sacl_set: false` with a non-empty `sacl`.** build-spec cannot produce it, and it is the
   only inconsistent pair the two fields allow.
5. **Refuse a missing or null `sacl`.** Today the consumer accepts null (P2:`Plan.cs:106`,
   `IReadOnlyList<PlanAce>? Sacl`).

### 2.3 Absent, empty and listed

| Spec text | `sacl_set` | `sacl` | SACL outcome for a matched object |
|---|---|---|---|
| no `sacl:` key | false | `[]` | **Left alone**: not compared, never written. G2 still proves it did not change across any other write (K1). |
| `sacl: []` | true | `[]` | The desired SACL has **no audit ACEs**. It is classified (section 3) and written when the stored SACL differs. |
| `sacl: [U…]` | true | `[…]` | The desired SACL is those ACEs, classified. |

**The consumer keys off `sacl_set`, never off `sacl` being empty**, because both of the first two
rows carry `[]`. The only way to set `SACL_SECURITY_INFORMATION` is a `sacl_set` rule.

An empty desired SACL is sent as a **present, empty** ACL, never as a NULL SACL. What the array does
with a NULL SACL is **UNVERIFIED**, and the tool never sends one.

**`sacl: []` is always Protected and empty** (`S:P`, no audit ACEs; section 11, decision 2). This
matches the classifier, which says "the rule's ACL is complete, and an unprotected explicit-only ACL
would pick up whatever the parent passes down later" (P2:`Inheritance.cs`, `Classify`). It is also
the Windows way to guarantee no auditing: disable inheritance and remove every entry.
`smb/DESIGN-write-path.md` 2.5 said **Inherits** when the parent passes nothing down. It is
corrected in the same change. How a present, empty, protected SACL reads back on FlashArray is
Q-SACL-CONTROL.

### 2.4 SACL-only rules and rules with both

| Rule | DACL part | SACL part |
|---|---|---|
| `acl:` only | as phase 2 | left alone; G2 proves it unchanged |
| `sacl:` only | **kept**; children inherit from the stored DACL, as the `Keep` branch does now | desired form |
| both | desired form | desired form, independent of the DACL's |
| neither (owner/group only, or nothing) | as phase 2 | left alone |

The two parts are independent. An object can be `Inherits` on the DACL and `Protected` on the SACL.
`Node` carries the parent's desired DACL **and** desired SACL, and a separate `AncestorWrites` for
each, because a DACL write above a child does not make the child's SACL follow.

## 3. Desired SACL

The design's section 2.1 applies unchanged, with `want(o)` set to the rule's `sacl` and `inh` taken
over the parent's desired SACL:

| Form | Condition | Stored SACL | Control |
|---|---|---|---|
| **Inherits** | `want == inh(parent.sacl)`, non-empty | `inh(…)`, all `ID` | unprotected |
| **Explicit + inherits** | `want == E ++ inh(…)`, both non-empty | `E` explicit, then `ID` | unprotected |
| **Protected** | anything else, including `sacl: []` | `want`, all explicit, possibly empty | `S:P` |

`Desired.Classify` and `Desired.Matches` are type-agnostic and are reused as they are.

**Kept directory SACLs.** A directory whose rule has no `sacl:` key still feeds its children's
inherited audit part from its **stored** SACL. The phase 1 fix applies to the SACL too: the stored
inherited part is replaced by the re-derived one only when the directory provably tracks its parent
and an ancestor's SACL will be written. Otherwise the stored SACL is passed down as it is. If the
stored SACL holds an ACE type the model does not handle (K8), its children are not classified; they
are reported as errors and not written.

**The root.** Its `desired(parent).sacl` is read from the array as its stored `ID` audit ACEs, as
for the DACL. A frozen `ID` copy on the root cannot be detected, so **`--root-sacl-protected`**
forces the root's SACL to Protected. It is separate from `--root-protected` (#76) and independent
of it (section 11, decision 4): nothing shows that the two ACLs of one root freeze together.

**The main use.** Trees audited over NFS are `S:P` with every audit ACE explicit (K3). Converting
them to Inherits writes the parent's inheritable audit ACEs in `ID` form with `S:P` cleared. That is
the DACL's Q-PROT conversion; whether it makes the SACL dynamic is Q-SACL-DYNAMIC.

## 4. The write

### 4.1 Call

Each SACL write is its own `SetKernelObjectSecurity`, through `Win32Security.WriteDescriptor`, with:
- `SACL_SECURITY_INFORMATION` (0x8);
- **exactly one** of `PROTECTED_SACL_SECURITY_INFORMATION` (0x40000000) and
  `UNPROTECTED_SACL_SECURITY_INFORMATION` (0x10000000), always stated, never left to the server;
- the matching `SE_SACL_PROTECTED` bit in the descriptor's control word.

The protection is stated twice, by the flag and by the control word, as phase 2 does for the DACL
and as Set-SaclOnly does for the SACL (`tools/set-saclonly/SaclOnly.cs:294-307`). The handle is
opened with `ACCESS_SYSTEM_SECURITY` and backup intent. Nothing goes through `SetSecurityInfo` or
`SetNamedSecurityInfo`, because those start client-side propagation.

A combined `DACL|SACL` call would save one round trip on objects that need both. How the array treats
a combined write is **UNVERIFIED** (Q-SACL-COMBINED), so phase 3 does not use one.

### 4.2 Order when both parts differ

The order is a switch, because the right one is customer-specific (section 11, decision 3):
**`--write-order=sacl-first|dacl-first`**, default **`sacl-first`**. Each write is followed by its
own G2 read-back. Neither order is atomic, and each leaves a window:

| Order | Window if the second write fails |
|---|---|
| `sacl-first` (default) | Auditing is already the new policy while access is still the old one. |
| `dacl-first` | Access is already the new policy, possibly wider, with the old auditing. New access can go unaudited. |

`sacl-first` is the default because a failed run should not leave newly granted access unaudited.
It costs one extra read: the SACL write's read-back becomes the DACL write's before-image, and the
DACL write re-reads that before-image immediately before it writes.

`dacl-first` **must keep the qualified phase 2 DACL step byte-identical**: the same before-read, the
same `SetKernelObjectSecurity` call and descriptor bytes, and the same G2. The SACL write follows,
and its G2 compares the DACL against the DACL write's read-back. A test asserts that the DACL step
under `dacl-first` sends the bytes phase 2 sends for the same object.

The order applies only to objects where both parts differ. It is recorded in the manifest and
bound in the checkpoint (7.1), so a resume cannot switch it.

A directory's children are queued only after **every** selected part of the directory has passed G2.

### 4.3 `S:P` and `S:AI`

`S:P` belongs to the desired form and is compared raw, like `D:P`.

`S:AI` is unknown. Phase 2 learned on hardware that the array sets `D:AI` itself (F5): set on an
unprotected DACL write, clear on a protected one. Nothing shows the SACL behaves the same way. The
records that look consistent with it (K3) were not produced by SACL writes.

So the expected `S:AI` is **measured, not assumed**. The preflight (section 6, step 5) writes
protected and unprotected SACLs to the probe and records what `S:AI` reads back. G2 then expects that
measured value for the rest of the run. If the probe's readings do not form a rule (protected gives
one value and unprotected the other, or both give the same value), the run refuses. Q-SACL-CONTROL
settles it once on hardware; until then, every run measures it.

### 4.4 Guards

**G1 for the SACL.** During `apply`, a child of form Inherits or Explicit + inherits whose stored
SACL is unprotected, has the right explicit part and only `ID` ACEs after it, but whose `ID` part
differs from `inh(desired(parent).sacl)`, stops the run. There is no override, as for the DACL G1. It
fires on a frozen copy that predates the run too. Whether SACL frozen copies exist is
Q-SACL-DYNAMIC. The guard stays until that is answered, because a false stop costs a rerun while a
missed freeze is silent.

**G2 for a SACL write.** A fresh read with the SACL after every write, compared raw:

| Part | Must equal |
|---|---|
| SACL ACEs (type, flags including `ID`, mask, SID, order), `S:P`, `SaclPresent` | the desired form |
| `S:AI` | the value measured by the preflight for that protection |
| owner, group | the read before |
| DACL bytes, `DaclPresent`, `D:P`, `D:AI` and every other control bit | the read before |

The last row is Set-SaclOnly's strict policy, made a stop with no `-Accept`. Set-SaclOnly compares
through SDDL and ignores `S:AI` drift (`SaclOnly.cs:329-348`). Phase 3 compares bytes and all
control bits instead. FlashBlade's known `D:P` loss on SMB SACL writes (`dacl-unprotected`) is
**not** carried over to FlashArray.

**G2 for a DACL write** is phase 2's (P2:`Checker.cs:435-456`). When the same object's SACL was just
written, the SACL is compared against that write's read-back rather than the original before-image.

**Stops.** A G1 or G2 failure stops new writes and listings. Writes already in flight finish and are
checked. A write API error is **not** proof that nothing changed: the tool reads the object back.
- If the read succeeds, the record shows what is stored.
- If it fails, the object is recorded as `unknown` and the run stops.

An object where the first of two writes succeeded and the second failed is recorded with the parts
that were written, and its directory is not checkpointed.

### 4.5 Refusals before a write

The SACL write is refused, and the object recorded as an error, when its stored SACL:
- holds an ACE type the model does not handle (K8, mandatory label and the others). A rebuilt
  audit-only list would delete it. Whether FlashArray stores these over SMB at all is Q-SACL-OPAQUE;
- would exceed 65,535 bytes once encoded, the encoder's limit. The array's own limit is Q-SACL-SIZE.

Both the DACL and the SACL are encoded and size-checked before either is written.

### 4.6 Check and classify

An object now has two part verdicts. `CheckRecord` gains `SaclForm` and per-part outcomes. The
record's single `Outcome` is the worse of the two, in the order
`Error > Stopped > Write > Follows > Written > Ok > Keep`. That keeps exit codes, the checkpoint's
`done(ok)` and the evidence vocabulary unchanged. `Keep` means both parts are kept and ownership is
right. Phase 1's rule that a named owner or group difference is a `Write` even under `Keep` still
applies (#79).

## 5. Privileges

| Privilege | Phase 3 use |
|---|---|
| `SeSecurityPrivilege` | needed for SACL reads and writes (`ACCESS_SYSTEM_SECURITY`). `apply` already enables it (P2:`Program.cs:236`). **`check` enables it too whenever any rule sets `sacl:`**, and then reads every object with its SACL in the same `GetKernelObjectSecurity` call. Without such a rule, `check` is unchanged. |
| `SeBackupPrivilege` | unchanged: listing and reads under backup intent |
| `SeRestorePrivilege` | unchanged: enabled only when a rule names an owner or group, explicitly disabled otherwise. A SACL write needs nothing from it; Set-SaclOnly turns it off because it widens what a backup-intent open can do. |

Refusal before any write, in three layers:
1. **Token.** Enabling the privilege fails with `ERROR_NOT_ALL_ASSIGNED`. The command exits 1 naming
   the privilege, before the evidence directory, checkpoint or probe exist.
2. **Array refuses the SACL open.** The probe's first SACL write fails (access denied). The preflight
   refuses and removes the probe.
3. **Array accepts the write but does not keep it** (no audit bypass). The probe's placeholder does
   not read back (K5). The preflight refuses.

Phase 2 left layer 3 unverified on hardware (P2 qualification record, "Unverified"). Phase 3 cannot
ship with it unverified (section 9, step S1).

## 6. Preflight

The probe is extended and reordered so that **no tree object's SACL is read before the bypass is
proven**. This matters in case an SMB SACL read without the bypass has a side effect, as an NFS read
did (K7, Q-SACL-AUTH).

1. Create the probe directory, subdirectory and file (as phase 2).
2. Write a protected SACL with the placeholder audit ACE and require it back (as phase 2, K5). The
   bypass is now proven on data that is not the tree's.
3. **Only now**, read the root with its SACL and compute `desired(root).sacl`. Phase 2 computes the
   root's desired DACL before the probe; the SACL half moves here.
4. Write the root's desired audit ACEs to the probe directory as a protected SACL, with `ID` cleared.
   If the root passes nothing down, use an inheritable placeholder (`OI|CI|SA|FA`) instead, so the
   check below is never vacuous. Read back, and require the children's `ID` audit part to equal
   `inh(…)`. This is G1 on known data.
5. **Measure `S:AI`:** write an unprotected SACL (one explicit audit ACE, then its inherited part) to
   the subdirectory and a protected one to the file, and read both back. The two readings fix G2's
   `S:AI` expectation for the run (4.3). Also write `SA`-only and `FA`-only ACEs and a present, empty
   protected SACL, and require each back exactly.
6. Require the probe's owner, group, DACL bytes and DACL control bits unchanged across steps 2 to 5.
   This is the `sacl:`-only strict check on known data.
7. Phase 2's DACL steps and cleanup. If the cleanup fails, the run refuses.

A plan with no `sacl_set` rule runs phase 2's preflight unchanged.

**What the probe does not prove:**
- that a written SACL stays dynamic after later parent changes (Q-SACL-DYNAMIC);
- that the target share behaves like the probe's directory, unless the probe is inside the target
  share, which phase 2 already requires;
- that audit events are delivered (Q-SACL-EVENTS).

## 7. Checkpoint, evidence and recovery

### 7.1 Checkpoint

The checkpoint header moves to **v2**. A v1 checkpoint is never resumed by a SACL-capable build. The
v2 header binds:
- the plan's SHA-256 (already bound in v1);
- the root;
- `--root-protected`, `--root-sacl-protected` and `--write-order`;
- a SHA-256 of the resolved principal-to-SID table, so a name that resolves differently on resume
  refuses the resume;
- the `S:AI` measurement from the preflight.

A directory is complete only when it and every file in it are right on **every** part the plan
names. A directory with a two-write object that stopped half way is not complete; a resume rereads
it and writes only what still differs.

Resume still skips the files of a complete directory without reading them, as phase 2 does. That
assumes the tree did not change between the runs. The assumption is stated in the operator docs, and
`check --validate` after a resume is the independent proof.

### 7.2 Evidence

Phase 2's shard format is kept. Its before- and after-images are already read with the SACL, so phase
2 evidence already holds raw SACL bytes. Phase 3 adds:
- `parts` values `sacl`, `sacl,dacl`, `sacl,dacl,owner`, in write order;
- both forms in the note, for example `(sacl protected, dacl inherits)`;
- `unknown` and partial outcomes as their own counts;
- `sacl_forms` counts in the manifest, and the preflight line naming the SACL steps and the measured
  `S:AI`.

### 7.3 Recovery

**Phase 3 promises end-state evidence, not rollback.** Phase 2's shard is written after each write
and is buffered, and a hard kill already lost one before-image in qualification (P2 qualification
record). Objects that change only by inheritance from a written parent have no before-image at all.

**The phase 3 operator docs require an array snapshot before `apply`.** A per-object undo needs a
durable intent journal, flushed before each write. It is not in phase 3; a separate design covers
it for both the DACL and the SACL (#87; section 11, decision 8).

Any future restore writes parents before children and rechecks every `ID` ACE against its parent;
otherwise a restored child becomes a frozen copy. The NFS `--restore-from` path does not apply:
it is Linux only and loses SMB inherited flags.

### 7.4 Public safety

Evidence holds full paths, raw descriptors (every SID in every ACL) and the principal-to-SID table.
Encoded descriptors are not sanitized by hiding names. Evidence stays in the private lab repository.
Public `RESULTS.md` files use labels for principals and fixtures, quote control words and SDDL with
labels substituted, and never quote a shard line. `tools/public-scan/scan.sh` is the gate.

## 8. FlashArray questions for hardware

Each is a harness test of array behaviour (raw `SetFileSecurityW` / `GetFileSecurityW`), not a
product qualification. They are ranked by the damage a wrong assumption would do.

| Id | Question | Known | Blocks |
|---|---|---|---|
| Q-SACL-ISOLATION | Does a SACL-only write, **including one that changes `S:P`**, leave owner, group, DACL bytes, `DaclPresent`, `D:P`, `D:AI` and other control bits unchanged? Test every DACL form, SMB-written and NFS-written objects, and `SeRestorePrivilege` both on and off. | K2 covers writes that copy `S:P` | `sacl:`-only rules; G2's DACL row |
| Q-SACL-PARTIAL | After the first of two writes, a failed second write, or a disconnect after the server committed: what is stored, and does the read-back tell the truth? | nothing | the two-write order (4.2); the `unknown` outcome |
| Q-SACL-DYNAMIC | Is a child written with `ID` audit ACEs that match its parent dynamic, and is one that does not match a frozen copy? After an `S:P` to unprotected conversion, does the object and its unwritten subtree follow **two** later parent SACL changes? Test SMB-born and genuinely NFS-flattened objects. | DACL only (F2, Q-PROT) | G1-SACL; the main use (section 3) |
| Q-SACL-EVENTS | Do `SA`-only, `FA`-only and combined ACEs deliver events for allowed and denied SMB access by non-bypass identities, at the final sink, with and without an audit policy on the managed directory? | NFS only (`benchmarks/sacl-fa-20261015/AUDITLOG-RESULTS.md`) | any claim about audit coverage, as opposed to stored rules |
| Q-SACL-AUTH | With `SeSecurityPrivilege` but no array audit bypass: is an SMB SACL read refused, empty or returned, and does it change the object (K7)? Is the SACL write refused or dropped? | one refusal path in `benchmarks/sacl-ps07-20261026/` | preflight order (section 6); the spec-guide sentence |
| Q-SACL-INH | Do audit ACE flags (`OI`, `CI`, `NP`, `IO` and combinations, with `SA`, `FA`, both) inherit as `inh` predicts **when the parent's SACL is written with `SACL_SECURITY_INFORMATION`**? Include the two missing rows from #77. | K4, which does not say how the audit ACEs were written | release; G1 |
| Q-SACL-CONTROL | What do protected, unprotected, present-empty and NULL SACL writes read back as (`S:P`, `S:AI`, `SaclPresent`)? In particular, how does `sacl: []` (protected, present, empty) read back? What happens to children of an empty protected SACL when their parent later gains auditing? | nothing | G2's `S:AI` row; `sacl: []` |
| Q-SACL-IDENTITY | Are audit ACEs naming unmapped, deleted, foreign-domain or array-local SIDs stored unchanged? Does a SACL-only write on an object whose DACL names such SIDs leave the DACL byte-identical? | the DACL half for Set-SaclOnly's write (`benchmarks/sacl-unmapped-sid-20261020/`) | `sacl:`-only rules on damaged trees |
| Q-SACL-SCOPE | Does a parent SACL change reach excluded subtrees and `Keep` subtrees under it? | DACL propagation is recorded; SACL is not | the operator docs' statement of what exclusions mean |
| Q-SACL-OPAQUE | Does FlashArray store mandatory label, resource attribute or scoped policy ACEs over SMB? | nothing | whether 4.5's refusal can fire in practice |
| Q-SACL-SIZE | The largest SACL and the largest combined descriptor the array accepts. Is an over-size write refused cleanly, with both ACLs unchanged? | encoder limit 65,535 bytes | the error path |
| Q-SACL-COMBINED | Is one `DACL|SACL` write equivalent to two single-part writes, including when it fails? | nothing | nothing in phase 3; a later optimisation |

Q-OWN (design section 7) also gates `OWNER@`/`GROUP@` in `sacl:` now.

## 9. Relationship to existing tools

### 9.1 Set-SaclOnly

Its retirement stays held until a `permissionreset-smb` release is qualified for SACL writes on
FlashArray **and** FlashBlade. The FlashArray half does not retire it.

| Set-SaclOnly behaviour | Phase 3 |
|---|---|
| SACL-only `SetKernelObjectSecurity` through a backup-intent handle, protection stated by flag | **kept** (4.1) |
| `SeSecurityPrivilege` on, `SeRestorePrivilege` off | **kept** (section 5) |
| root preflight on the first object | **replaced** by the disposable probe (section 6) |
| strict owner/group/DACL comparison, stop on change | **kept and tightened**: raw bytes and all control bits (4.4) |
| `-Accept dacl-unprotected` (FlashBlade) | **not applicable** on FlashArray |
| `S:P`/`S:AI` copied from the object, ACEs written as given | **replaced** by computed forms (section 3). This is the behavioural difference. There is no parity mode; scenario S-PAR compares the two tools (section 11, decision 1). |
| skip when ACEs equal, control ignored | **replaced** by a raw compare including `S:P` |
| `OWNER@`/`GROUP@` written as `CO`/`CG` | **refused** (2.2) |
| `sacl: []` clears, absent key leaves alone | **kept** (2.3) |

Separately, `tools/set-saclonly/README.md:5-6` says an `acl:` run without `--sacl` deletes SACLs.
That is out of date: the Go tool keeps each object's audit ACEs without `--sacl` (PS-04, root
`CLAUDE.md`). The README should be corrected in its own change.

### 9.2 The Go `--sacl` mode and its guards

| Guard | Why it exists over NFS | Over SMB |
|---|---|---|
| `--sacl` opt-in; an `acl:` rule with no `sacl:` key refused | one NFS ACL holds both lists, so a DACL write without audit entries deletes them | the hazard does not exist: the parts are separate (K1). **No `--sacl` flag**: the plan's `sacl_set` is the intent, `sacl: []` included (section 11, decision 5). |
| `ErrAuditedObject` | an NFS write flips `S:AI`/`D:AI` to protected | not applicable; G2 catches any cross-part change |
| `ErrDACLFlattening` | NFS has no `ID`, so a kept DACL is stored flat | not applicable: a `sacl:`-only write never names the DACL. G2 proves it per object. |
| `ErrUnmappedPrincipal`, `ErrSyntheticRangePrincipal` | NFS translates ids to SIDs on write | not applicable: SIDs are written natively. No numeric RID threshold is imposed. Stored SIDs the tool does not write are never re-encoded. |
| `ErrHighIDPrincipal` | the spec names an id >= 1e9 | superseded: SMB plans refuse every numeric principal |
| `ErrUnpreservableAudit` | kept audit ACEs must be re-written over NFS | not applicable: a kept SACL is not written |
| audit-bypass preflight | a write without the bypass is dropped | **kept** (section 6) |
| audit-policy NOTE | stored rules do not log without a policy | **kept**, with the tool name changed |

Every `apply` and `check` with a `sacl_set` rule prints, once:

```
NOTE: sacl: writes audit ACEs, but logging them still needs an audit policy turned
      on for the managed directory -- permissionreset-smb cannot check that over SMB.
```

## 10. Qualification plan

Following `MAINTAINERS.md` and design section 8.

**Implementation done** means:
- sections 2 to 7 built;
- offline tests green, with `FakeTree` extended so a wrong SACL model fails a unit test first: SACL
  analogues of F1 to F3, the F5 question, partial writes and `unknown` outcomes;
- the CLI refusals tested through fakes;
- the `--smb-plan` golden file updated, with golden cases for absent, empty, listed, contradictory
  and malformed `sacl`. It also covers the schema rule in 2.1: schema 2 for a DACL-only spec,
  schema 3 when any rule sets `sacl:`, and a schema 2 plan with `sacl_set` refused by the consumer;
- a unit test that the DACL step under `--write-order=dacl-first` sends phase 2's bytes (4.2).

**Qualification pending** means every row below passed on one exact candidate. The candidate is
recorded as phase 2's was: commit, artifact SHA-256s, unit test count, `build-spec` at the same
commit, Purity version re-read on the day, client build, identity and privileges.

The platform questions come first. An answer that contradicts an **ASSUMPTION** here changes the
design before the product run.

| Step | Scenario | Pass condition |
|---|---|---|
| P1 | Section 8, by harness | each answered with raw before/after captures, or recorded as unanswered with the reason |
| S0 | `check` with a `sacl:` plan, no `SeSecurityPrivilege` | exit 1 naming it; nothing read |
| S1 | `apply` as an identity with the token privilege but **without** the array bypass | preflight refuses; no evidence directory, no checkpoint, probe removed, tree byte-identical |
| S2 | preflight on a conforming root | passes; its line names the SACL steps and the measured `S:AI` |
| S3 | A fixture covering every SACL form under every rule kind in 2.4, including: `sacl: []` under parents that do and do not pass auditing down; an NFS-audited subtree written by a real `permissionreset --sacl` run; an SMB-audited subtree; a deny-only directory; unmapped and array-local SIDs in the DACL under a `sacl:`-only rule | `check` agrees with an independent classifier written from this text; `apply` exits 0 with no stop; every written object's after-image equals an independent raw read; every `sacl:`-only object's owner, group, DACL bytes and DACL control bits are identical before and after |
| S4 | Rerun `apply`, then `check --validate` | 0 writes; exit 0 |
| S5 | A frozen SACL copy planted under a parent the run does not write | `check` reports it; `apply` stops on G1, exit 1 |
| S6 | Kill mid-run on a tree large enough to checkpoint; `--resume` | completes; `check --validate` exits 0; partial records as documented |
| S7 | A rule with both, on objects where only the SACL, only the DACL, or both differ; a fault injected between the two writes. **Run once under each `--write-order`.** | `parts` recorded correctly, in the chosen order; the half-written object is not checkpointed; a rerun converges. Under `dacl-first`, each DACL step's call and descriptor bytes equal phase 2's for the same object. |
| S7b | S3's fixture again under the order S3 did not use | the same pass conditions as S3; the end state equals S3's |
| S8 | **After** a successful run: two independent parent SACL changes, plus new files and directories created under written directories | unwritten and newly created descendants follow both changes. A matching state right after the run is not enough. |
| S-PAR | One spec on two copies of one fixture: Set-SaclOnly on one, `permissionreset-smb apply` on the other | every object's **effective** audit ACEs (its explicit ACEs plus what it inherits) are equal on the two copies. Bytes, `ID` flags and `S:P` are expected to differ wherever the computed form differs from Set-SaclOnly's copied form; each such difference is listed. |
| S9 | Events, if the lab array has an audit policy: allowed and denied SMB access by non-bypass identities, for `SA`-only, `FA`-only and both | events observed at the sink. Stored rules and delivered events are reported as separate verdicts. With no policy available, this is recorded as **unverified**, not skipped silently. |

Deliverables:
- `benchmarks/qual-smb-sacl-<commit>-<date>/RESULTS.md`, with passed, failed, skipped and unverified
  listed separately;
- a `COMPATIBILITY.md` row for SMB SACL writes;
- operator docs that require an array snapshot before `apply` (7.3) and describe `--write-order`;
- the design's as-built section extended.

The `smb-v0.1.0` tag is not affected by this phase.

## 11. Maintainer decisions (2026-11-23)

Robert decided these on 2026-11-23, after reviewing the open choices in the first draft. The rest
of this text follows them.

| # | Topic | Decision | Where it applies |
|---|---|---|---|
| 1 | Set-SaclOnly parity mode | **Computed inheritance only. No stamp mode.** The comparison with Set-SaclOnly is qualification scenario S-PAR: one spec on two copies of one fixture, compared on effective audit ACEs, not bytes. | section 3; 9.1; 10 (S-PAR); `DESIGN-write-path.md` 2.5 and 8 |
| 2 | `sacl: []` | **Always Protected and empty** (`S:P`, no audit ACEs). It matches the Windows way to guarantee no auditing: disable inheritance and remove every entry. `DESIGN-write-path.md` 2.5 is corrected to match. | 2.3; 3; Q-SACL-CONTROL |
| 3 | Write order when both parts differ | **A switch**, because the right order is customer-specific: `--write-order=sacl-first\|dacl-first`, default `sacl-first`. `dacl-first` keeps the qualified phase 2 DACL step byte-identical. Qualification covers both orders. | 4.2; 7.1; 10 (S7, S7b) |
| 4 | Root SACL | **A separate `--root-sacl-protected`**, independent of `--root-protected` (#76). | section 3; 7.1 |
| 5 | Opt-in | **No `--sacl` flag** on the SMB tool. The plan's `sacl_set` is the intent. | 9.2 |
| 6 | `OWNER@`/`GROUP@` in `sacl:` | **Refused** by `--smb-plan` and by the consumer, as 2.2 says. | 2.2 |
| 7 | Schema | **Schema 3** for this change in write semantics. The compatibility rule (which schemas each build emits and accepts) is proposed in 2.1, and **Robert confirms it**. | 0; 2.1; 10 |
| 8 | Rollback journal | **Not in phase 3.** A separate design covers a durable intent journal for both the DACL and the SACL (#87). Phase 3 docs require an operator snapshot. | 7.3; 10 |
| 9 | FlashBlade | **Out of scope.** FlashBlade over SMB comes last, if at all. | header; 9.1 |

Still open: Robert's confirmation of the schema compatibility rule in 2.1.

For reference, what the first draft knew about FlashBlade when this was decided:
- Set-SaclOnly's SMB SACL write clears `D:P` on NFS-written FlashBlade objects
  (`tools/set-saclonly/README.md`).
- FlashBlade stores an `S:AI` write as `S:`.

## 12. How this text was written

Three model outputs were produced with spillway from one shared brief, then merged and edited by
hand:

| Model | Role | Main contributions kept |
|---|---|---|
| claude-fable-5-1 | independent draft | the structure; the schema analysis (no shape change, new producer and consumer checks); the three-form model applied to the SACL; the preflight reordering so no tree SACL is read before the bypass is proven; the Set-SaclOnly and Go guard tables; most of the qualification table |
| gpt-6-sol | independent draft | the `stamp` versus `computed` option (decided: computed only, section 11, decision 1); SACL-first ordering; the separate root flag; checkpoint v2 binding the principal table; `unknown` outcomes on write errors; the stale Set-SaclOnly README line |
| gpt-6-astra | adversarial review: failure analysis and testable requirements | the finding that K4's audit rows came from a record of DACL-only writes; the refusal of unmodelled SACL ACE types (K8); no rollback promise; the post-run parent-change requirement (S8); separating stored rules from delivered events; ranking hardware questions by damage |

**Model output is not evidence.** The following were checked by hand against the code and records
cited:
- the plan fields and the always-present `sacl` (`saclplan.go:110-116`, `:300-310`);
- the `OWNER@`/`GROUP@` mapping and its DACL-only refusal;
- the consumer's SACL checks, and that it does not require `SA`/`FA`;
- phase 2's `sacl_set` refusal;
- `Classify` returning Protected for an empty inherited part, and the creator-SID refusal;
- the 2.5 sentence on `sacl: []`;
- the placeholder audit ACE in the phase 2 preflight;
- phase 2's `ReadbackDiff` SACL checks;
- the opaque ACE types in `Descriptor`;
- K4's "DACL-only" wording;
- K7's spec-guide sentence;
- Set-SaclOnly's control-word copy and its SDDL-based diff;
- the stale README line.

Other line references come from the drafts and were not each re-read. The reviewer should treat
them as pointers, not as proof.
