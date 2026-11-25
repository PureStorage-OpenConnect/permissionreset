# permissionreset-smb phase 3: SACL writes on FlashArray over SMB

| | |
|---|---|
| Date | 2026-11-20, revised 2026-11-24 |
| Status | **Draft for review. Design only; nothing here is built or qualified.** This extends `smb/DESIGN-write-path.md` (sections 2.5 and 8, phase 3). Section 11 records the maintainer's decisions of 2026-11-23 and 2026-11-24, and the rest of the text follows them. Section 13 lists the review findings on `e475693` and `1c5ca96`, the maintainer's round 3 decisions of 2026-11-24, and how each was handled. |
| Scope | FlashArray only. FlashBlade is out of scope: FlashBlade over SMB comes last, if at all (section 11, decision 9). Set-SaclOnly retires for FlashArray once this phase is released (`smb-v0.2.0`), and stays supported, frozen (fixes only), for SMB-written FlashBlade data until FlashBlade over SMB is decided (`docs/decision-flasharray-smb-20261107.md:69-77`, section 2.5 as amended). |
| Base | `main` @ `cd4ed1e`, which holds phase 2 (#73) and the walk changes in #74, #79 and #80. Code citations are paths and lines at that commit. |
| Builds on | `smb/DESIGN-write-path.md`, `tools/set-saclonly/`, `benchmarks/qual-smb-check-700630b-20261116/`, `benchmarks/qual-smb-apply-e834ac8-20261119/`, and the private lab records named in section 1 |

**ASSUMPTION** marks what is inferred rather than read. **UNVERIFIED** marks Windows API or array
behaviour that no record establishes. A **lab record** is a private record in the lab repository. It
is cited by name only, and its facts are restated here without principals, hosts or paths. Section
12 says how this text was written.

## 0. Summary

The SACL gets the DACL's three-form model (`Inherits`, `Explicit + inherits`, `Protected`), the same
`inh` function, and its own G1 and G2 guards. A SACL-aware comparison treats an absent SACL as "no
auditing" (FlashArray never reports one; a never-audited object reads `S:AI` empty), and a SACL-aware
follows model lets a never-audited child follow its parent instead of being written. Each SACL write is its own `SetKernelObjectSecurity` call, carrying
`SACL_SECURITY_INFORMATION`, an explicit SACL protection flag and a stated control word. The JSON
plan shape does not change. A plan that sets `sacl:` moves to **schema 3**, under a compatibility
rule the maintainer confirmed (2.1). The producer and the consumer refuse all four creator SIDs in
`sacl:`, and the consumer gets four more checks.

Whenever any rule sets `sacl:`, `check` and `apply` read and classify every object's SACL. Neither
reads a tree SACL before a disposable probe proves the audit bypass. `check` can skip that proof
only with `--accept-unproven-read`. When both parts of an object differ, `--write-order` picks which
is written first. The tool promises end-state evidence, not rollback; the operator docs require an
array snapshot.

Lab records already answer most hardware questions: SACL inheritance, the control word, SACL-only
write isolation, whether written and converted SACLs stay dynamic (SMB- and NFS-written), and
whether never-audited children follow their parent. Section 8 marks what remains open.

## 1. What is known

All facts are from FlashArray over SMB, with raw `SetFileSecurityW`/`GetFileSecurityW`, unless the
row says otherwise.

| Id | Fact | Source |
|---|---|---|
| K1 | A DACL-only SMB write leaves the SACL bytes and the SACL control bits unchanged. Phase 2's G2 enforces this on every write. | `smb/DESIGN-write-path.md:24-25`; `smb/src/PermissionReset.Smb.Core/Checker.cs:482-503` |
| K2 | **SACL-only writes leave everything else alone, including writes that change `S:P`.** 96 SACL-only writes changed nothing outside the SACL: owner, group, DACL bytes, `D:P` and `D:AI` were identical before and after on every one. The writes covered six SMB DACL forms (Protected, Inherits and Explicit + inherits, on directories and files) and raw-NFS-written directories and files, flipped `S:P` to unprotected and back, and ran with `SeRestorePrivilege` off and then on. Earlier runs (13 of 13 and 15 of 15, in an interval that also held DACL writes) agree. Set-SaclOnly's write, which copies the object's own `S:P`/`S:AI`, is the same call shape. | lab record `fa-smb-saclq-20261123`; `tools/set-saclonly/SaclOnly.cs:294-307`; `RISKS.md:134-139`; `benchmarks/sacl-ps07-20261026/RESULTS.md`; lab records `fa-smb-saclconv-20261116`, `fa-smb-saclnone-20261116` |
| K3 | Over NFS, any FlashArray ACL write marks `S:AI` to `S:P` and `D:AI` to `D:P`. Objects written that way read back over SMB as `S:P` and `D:P`. | `CLAUDE.md` (SACL mode); `benchmarks/qual-smb-apply-e834ac8-20261119/RESULTS.md` (Q10) |
| K4 | **SACL inheritance matches `inh`.** 304 of 304 children matched `inh` exactly, under 38 parents whose SACL was written with `SACL_SECURITY_INFORMATION`: all 12 flag sets (including `OI\|NP\|IO` and `CI\|NP\|IO`, #77) as `SA`, `FA` and both, a five-ACE order case and an unprotected parent, for children that existed at the write and children created after it. The phase 1 Q-INH run agrees (280 objects, 0 differences; its parents' audit ACEs were SACL-only writes, `SACL\|PROTECTED_SACL`, and its public record now carries a correction saying so). | lab record `fa-smb-saclq-20261123`; `benchmarks/qual-smb-check-700630b-20261116/RESULTS.md` (B, Q-INH); lab records `fa-smb-inh-20261115`, `qual-smb-check-700630b` |
| K5 | The phase 2 preflight writes one protected, non-inheritable placeholder audit ACE to the probe and requires it to read back. This proves the array kept a SACL write on the probe. It proves nothing about SACL inheritance. | `smb/src/PermissionReset.Smb.Core/Preflight.cs:73-86` |
| K6 | Phase 2 `apply` refuses any plan with a `sacl_set` rule. | `smb/src/PermissionReset.Smb/Program.cs:250-254` |
| K7 | An NFS read by an identity without the bypass emptied an inheriting object's SACL (Purity//FA 6.10.6). This was reproduced again in the week of 2026-11-23. **Over SMB it does not happen** (Purity//FA 6.10.7): an identity without the bypass changed no object by reads without the SACL bit, refused SACL reads, a directory listing, refused SACL writes or a DACL write, and all 20 inheriting children followed a later parent change. This backs the spec guide's "SMB reads do not do this". | `docs/spec-guide.md:736-739`; lab record `fa-smb-saclauth-20261124`; lab records |
| K8 | `Descriptor` recognises SACL ACE types it does not model: mandatory label (0x11), resource attribute (0x12) and scoped policy id (0x13). It decodes nothing for object and callback ACE types. | `smb/src/PermissionReset.Smb.Core/Descriptor.cs:114-118` |
| K9 | **FlashArray always stores a present SACL.** Present-empty, NULL and absent SACL writes all read back as a present, 0-ACE SACL, protected or not as the protection flag says. So a SACL write with no ACEs clears auditing, and `sacl: []` reads back `S:P` with 0 ACEs. The array never reports an absent SACL: an object whose SACL was never written reads `S:AI` empty (local NTFS can store NULL; FlashArray does not). | lab record `fa-smb-saclq-20261123`; lab records `fa-smb-saclnone-20261116`, `fa-smb-saclconv-20261116` |
| K10 | **A SACL follows its parent when its `ID` part matches what the parent passes down, and only then.** Never-written objects (`S:AI` empty), children and grandchildren included, picked up a parent's first SACL write as `ID` ACEs: one write, not one per object. Objects written with a matching `ID` part, and `S:P` objects converted to unprotected with a matching `ID` part, followed **two** later parent changes together with their unwritten subtrees. An `S:AI` empty SACL under a parent that passes nothing down follows a later parent SACL too. Limits: an object whose `ID` part does not match what its parent passes (an `S:AI` empty SACL under a parent that passes ACEs down included) stays frozen through both changes, and a protected SACL (`S:P`, `sacl: []` included) does not follow and blocks its children from a later ancestor change until it is itself written. A re-read 30 s later was byte-identical. | lab record `fa-smb-saclq-20261123`; lab records `fa-smb-inh-20261115`, `fa-smb-saclnone-20261116`, `qual-smb-check-700630b` |
| K11 | **The array decides the auto-inherit bit from protection, for both ACLs.** DACL: an unprotected write sent with `D:AI` **clear** was stored with `D:AI` set (`7ac90d8` run), so F5 is not an echo of what phase 2 sends. SACL: the protection flag alone decides; `S:AI` sent with a protected SACL is stored `S:P` with AI clear, and an unprotected SACL sent with `S:AI` clear is stored `S:AI`. | `smb/DESIGN-write-path.md:26-29`; lab record `fa-smb-saclq-20261123`; lab records `fa-smb-apply-7ac90d8` (STOP record), `fa-smb-inh-20261115`, `fa-smb-saclconv-20261116` |
| K12 | **Without the array's audit bypass, SMB SACL access is refused with error 5 and changes nothing.** On Purity//FA 6.10.7, a mapped identity outside Audit Operators, with no bypass, a non-elevated token and full control in the DACL got access denied (5) for SACL-only and all-four reads (nothing returned, not even an empty SACL) and for protected-empty, unprotected and protected-with-ACE SACL writes (nothing stored). Its reads without the SACL bit and its DACL write succeeded. Local NTFS refuses the same SACL read with 1314 instead. A sandbox array (Purity//FA 6.12.2) refused the SACL open the same way. Untested: that identity holding `SeSecurityPrivilege` (a host policy change). | lab record `fa-smb-saclauth-20261124`; `benchmarks/sacl-ps07-20261026/` |
| K13 | **The array can return success and still drop what it doesn't store.** A write carrying object or callback ACEs returned rc 0, and those ACEs were missing on read-back. Only a read-back shows what was stored. | lab record `fa-smb-saclq-20261123` |
| K14 | **The client token's `SeSecurityPrivilege` is not the array's gate.** A SACL write succeeded with `SeSecurityPrivilege` disabled in the client token. On FlashArray, what admits a SACL write is the array side (the audit bypass), not the client privilege. | lab record `fa-smb-saclq-20261123` |
| K15 | On FlashArray, an object with no explicit audit ACE shows its parent's inheritable ones (`ID`). So an excluded or left-alone object under a directory with an inheritable SACL is audited anyway. | `tools/set-saclonly/README.md:58-60` |
| K16 | **What decides following is whether the object's ACL was ever written, not the protocol that created it.** An NFS-created object whose ACL was never written (mode only) reads `S:AI` empty and picked up a parent's new audit ACE as `ID`, as an SMB-created one does. An NFS ACL write leaves the SACL `S:P` (K3), so it does not follow. After one matching-`ID` unprotected SACL write, such an object followed two parent changes. Its own NFS-ACL-written children stayed `S:P`, frozen: **each NFS-ACL-written object needs its own conversion.** | lab record `fa-smb-saclq-20261123` |
| K17 | **A failed second write leaves the first one stored, and the read-back tells the truth.** SACL written first, then a DACL write denied (error 5, two variants): the new SACL was stored and the old DACL unchanged, and the immediate read-back, a second read and a 30 s re-read all agreed with that. Untested: a failing first SACL write (none could be produced in scope), so the `dacl-first` failure case. Unanswered: a disconnect after the server committed, which needs fault injection. | lab record `fa-smb-saclq-20261123` |
| K18 | **A mode-only NFS create under an audited parent stores what the same SMB create stores.** 16 files and directories created over NFS (mode only) under parents passing inheritable audit ACEs, non-inheritable ones and none were byte-identical to their SMB-created twins, full security descriptor included. Under a parent passing ACEs they read `S:AI` with those ACEs as `ID`; under the others, `S:AI` with 0 ACEs. None read `S:P` or lacked a SACL, and the DACL was inherited from the parent, not built from the mode bits. After a parent SACL change all 33 children, the 16 NFS-created ones included, followed; a 30 s re-read was identical. So an NFS create is not a source of `S:AI` empty under a parent that passes ACEs (3.2). | lab record `fa-smb-saclcreate-20261124` |

What remains open (section 8):
- a failing first SACL write, and a disconnect after the server committed (Q-SACL-PARTIAL);
- whether audit events are delivered for what is stored (Q-SACL-EVENTS).

## 2. Plan schema

### 2.1 What exists, and the schema rule

The producer is `saclplan.BuildSMB` (`internal/saclplan/saclplan.go`). The consumer is `Plan.Parse`
(`smb/src/PermissionReset.Smb.Core/Plan.cs`). Per rule, schema 2 already carries:

| Field | Producer | Consumer today |
|---|---|---|
| `sacl_set` | true when the spec names a `sacl:` key, `sacl: []` included (`internal/spec/spec.go`, `SaclSet`) | parsed; `apply` refuses it (K6) |
| `keep_dacl` | `sacl:` given and no `acl:` (`KeepDACL`) | parsed; printed by `plan` only |
| `has_acl` | `len(rp.ACL) > 0` (`saclplan.go:300`) | must equal `dacl` present (`Plan.cs:102-103`) |
| `sacl` | **always present**; `[]` both when the key is absent and when it is `sacl: []` (`saclplan.go:305-309`) | each ACE must be type 2 with no `ID` (`Plan.cs:111-117`) |
| `dacl` | `omitempty`; present exactly when `has_acl` (`saclplan.go:113-115`) | as phase 2 |

Audit ACE flags come from the same translation as the DACL's: `S` becomes `SA` (0x40), `F` becomes
`FA` (0x80), and `f`/`d`/`n`/`i` become `OI`/`CI`/`NP`/`IO`. `I` is refused in both lists, and so
are numeric principals (`saclplan.go:244-253`). `OWNER@` and `GROUP@` map to `CO`/`CG`
(`saclplan.go:79-83`) and are refused only in the DACL (`saclplan.go:248-249`).

**The JSON shape does not change, but the schema version does** (section 11, decision 7). Schema 3
marks the change in write semantics. In schema 2, `sacl_set` is a rule the consumer refuses (K6). In
schema 3 it is a SACL write. The compatibility rule, **confirmed by the maintainer on 2026-11-24**
(section 11, decision 10):

| Build | `--smb-plan` emits | `check`/`apply` accept |
|---|---|---|
| phase 2 (`smb-v0.1.x`) | schema 2 | schema 2; a `sacl_set` rule is refused (K6). Schema 3 is refused as an unknown version (`Plan.cs:33-34`). |
| phase 3 | schema 3 when any rule sets `sacl:` (`sacl: []` included); schema 2 otherwise | schema 2 with no `sacl_set` rule (a DACL-only plan, unchanged meaning); schema 3. A schema 2 plan with a `sacl_set` rule is refused, with a message to rebuild it. |

So a DACL-only plan stays schema 2 and still loads in the released `smb-v0.1.0`. That build refuses
only what it can't do, as it does today. An old schema 2 SACL plan is never reinterpreted.
`--sacl-plan` stays schema 1 (Set-SaclOnly's), and `plan` keeps reading it for display only.

### 2.2 What must be added

**Prerequisite: #78** (section 11, decision 20).

Producer (`BuildSMB`):

1. **Refuse the creator SIDs in `sacl:`: `OWNER@`, `GROUP@`, and anything that resolves to
   `S-1-3-0` to `S-1-3-3`** (creator owner and creator group, and the two creator server SIDs).
   `Inheritance.Inherit` throws on all four, because the inherited SID depends on who created the
   child (`Inheritance.cs:35`, `CreatorSids`). A directory whose desired SACL names one with any
   inheritance flag would leave every child unclassifiable. Set-SaclOnly accepts `OWNER@` and
   `GROUP@`, so `--smb-plan` becomes stricter than `--sacl-plan` here (section 11, decisions 6
   and 11). `--sacl-plan` (schema 1) is unchanged.

Consumer (`Plan.CheckAces`), all checked before any probe or read:

2. **Every audit ACE carries `SA`, `FA` or both.** The spec parser already requires it, but the
   consumer does not (`Plan.cs:111-117`), so a hand-edited plan could write an ACE that audits
   nothing.
3. **Refuse all four creator SIDs (`S-1-3-0` to `S-1-3-3`) in `sacl`**, mirroring item 1, so a
   hand-edited plan, or one from an older build-spec, is refused up front rather than failing child
   by child.
4. **Refuse `sacl_set: false` with a non-empty `sacl`.** build-spec cannot produce it, and it is the
   only inconsistent pair the two fields allow.
5. **Refuse a missing or null `sacl`.** Today the consumer accepts null (`Plan.cs:168`,
   `IReadOnlyList<PlanAce>? Sacl`).
6. **The schema rule in 2.1**: a schema 2 plan with a `sacl_set` rule is refused, with a message to
   rebuild it.

### 2.3 Absent, empty and listed

| Spec text | `sacl_set` | `sacl` | SACL outcome for a matched object |
|---|---|---|---|
| no `sacl:` key | false | `[]` | **Never written.** In a plan where no rule sets `sacl:`, the SACL is not classified or written; the before- and after-images read it, and G2 proves it did not change across any other write (K1). In a plan where some rule sets `sacl:`, it is still **classified**: see below. |
| `sacl: []` | true | `[]` | The desired SACL has **no audit ACEs**. It is classified (section 3) and written when the stored SACL differs. |
| `sacl: [U…]` | true | `[…]` | The desired SACL is those ACEs, classified. |

**The consumer keys off `sacl_set`, never off `sacl` being empty**, because both of the first two
rows carry `[]`. The only way to set `SACL_SECURITY_INFORMATION` is a `sacl_set` rule.

**"Never written" is not "unchanged".** An object with no `sacl:` key, under a directory whose SACL
this run writes, has its stored SACL changed by inheritance (K10, K15, K16). When any rule sets `sacl:`,
`check` and `apply` therefore classify every object's SACL, the way the DACL side handles a kept
directory's children:
- An object whose SACL tracks what its parent passes down is reported `Follows` (dry run) or `Ok`
  (after the parent's write).
- An object holding a frozen `ID` audit copy is an error, and G1-SACL applies to it (4.4).
- The object itself is never written.

**A protected SACL with explicit ACEs under a rule with no `sacl:` key is `Keep`, never a
`Write`.** A rule with no `sacl:` key leaves the SACL alone, as Set-SaclOnly does
(`tools/set-saclonly/README.md:57-58`; section 11, decision 14), and, for rules with no `sacl:`
key (decision 14's scope), the maintainer's decision of 2026-10-21 stands: keep the protection
flags, change only the ACEs. A rule with no `sacl:` key
names no audit ACEs, so nothing about the SACL changes.

The operator docs say plainly that a rule without `sacl:` doesn't mean "not audited" on FlashArray.

An empty desired SACL is sent as a **present, empty** ACL, never as a NULL SACL. FlashArray stores a
present, empty SACL as written, and stores a NULL or absent SACL write the same way (K9). The tool
still never sends a NULL SACL, because other servers need not behave alike.

**`sacl: []` is always Protected and empty** (`S:P`, no audit ACEs; section 11, decision 2). This
matches the classifier, which says "the rule's ACL is complete, and an unprotected explicit-only ACL
would pick up whatever the parent passes down later" (`Inheritance.cs`, `Classify`). It is also the
Windows way to guarantee no auditing: disable inheritance and remove every entry.
`smb/DESIGN-write-path.md` 2.5 was corrected to match.

**What `sacl: []` costs** (section 11, decision 11). A never-audited object reads `S:AI` empty on
FlashArray (K9), and an absent SACL elsewhere; neither equals present-empty `S:P` (3.1). So a
`sacl: []` rule **writes every never-audited object in its scope once**. On a large tree that is one write per object. The dry run shows that count, and
before any write `apply` prints how many objects will lose audit ACEs, so the operator sees both
numbers before anything changes. Since there is no opt-in flag (decision 5), those counts are the
operator's warning.

**The loss count** is the number of objects whose effective audit ACEs (as defined for S-PAR, section
10) lose at least one entry between the stored state and the predicted end state, **whether the
object is written or only follows a written parent**. A `sacl: []` directory, or any write that
narrows what a directory passes down, removes `ID` audit ACEs from every child that follows it,
children with no `sacl:` key included, and those children have no before-image (7.3). So the count
is shown in two parts, written objects and following objects, in the dry run and before `apply`
writes. S3 checks both parts.

### 2.4 SACL-only rules and rules with both

| Rule | DACL part | SACL part |
|---|---|---|
| `acl:` only | as phase 2 | never written; classified when any rule sets `sacl:` (2.3) |
| `sacl:` only | **kept**; children inherit from the stored DACL, as the `Keep` branch does now | desired form |
| both | desired form | desired form, independent of the DACL's |
| neither (owner/group only, or nothing) | as phase 2 | never written; classified when any rule sets `sacl:` (2.3) |

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

`Desired.Classify` is type-agnostic and is reused as it is.

### 3.1 Comparing a SACL

`Desired.Matches` is **not** reused as it is. It treats a null stored ACL as "no DACL (everyone has
full control)", which is always a difference (`Inheritance.cs:103`). For the SACL, absent is the
normal state, and it means no auditing. Phase 3 adds a SACL comparison with its null semantics
spelled out:

| Stored | Desired | Result |
|---|---|---|
| absent (`SaclPresent` clear) | Protected, empty (`sacl: []`) | **differs**: written once to present-empty `S:P` (2.3) |
| absent | Inherits, where the parent passes ACEs down | **follows** once the parent is right (3.2), never a "no SACL" error |
| `S:AI` empty (FlashArray's never-audited state, K9) | Inherits, where the parent passes ACEs down | **follows** once the parent is right, when the parent's compare-time SACL passes nothing down (3.2); otherwise a frozen copy that predates the run: a `Write` under a `sacl:` rule, an error with no `sacl:` key (3.2) |
| absent | anything else | differs |
| present | any | compared raw, as `Matches` does: count, order, type, flags (`ID` included), mask, SID, and `S:P` |

G2's `SaclPresent` row compares raw. A present, empty SACL reads back present (K9), so `sacl: []`
converges. FlashArray never returns an absent SACL (K9); the absent rows are kept for other servers
and for a read that omits the SACL.

### 3.2 Following

`TrackableShape` and `Follows` (`Checker.cs:511-540`) need a SACL variant. On the DACL, an object
follows only when its stored ACL has the right explicit part and a non-empty inherited remainder.
On the SACL, **an absent SACL, or an unprotected SACL with no explicit part whose `ID` part equals
what the parent's stored SACL passes down now (0 ACEs included), also counts as following** when the
object's desired form is Inherits and its parent will pass ACEs down. "Now" is the parent's
compare-time read, before any write of this run. On FlashArray that is the never-audited state,
`S:AI` empty under a parent that passes nothing. Such objects pick up the parent's audit ACEs,
existing SMB- and NFS-created ones whose ACL was never written (K10, K16) and new ones created over
SMB (K10) or over NFS with mode only (K18). Without this, every descendant of a newly audited directory is
predicted, and written, as its own `Write`: N writes instead of one parent write plus the array's
propagation.

This does not cover:
- **A protected SACL**: it does not follow (K10). Under a `sacl:` rule it is a `Write`; under a
  rule with no `sacl:` key it is `Keep` (2.3).
- **An unprotected, empty SACL (`S:AI` empty) under a parent whose compare-time SACL already passes
  ACEs down.** It is a mismatch freeze (K10) that **predates the run**: the parent got its ACEs by a
  path that did not propagate, mainly an NFS ACL write (K3) on a directory whose children were
  never ACL-written, the main use below. A mode-only NFS create under the audited parent does not
  produce it (K18). It is not a sign that `inh` or propagation failed in this
  run. As on the DACL, where an empty inherited remainder is not a trackable shape
  (`Checker.cs:515-523`), it is a plain `Write` under a `sacl:` rule, and the write makes the
  object dynamic (K10). Under a rule with no `sacl:` key it is reported as an error in `check` and
  `apply` (it is frozen, and the tool may not write it), and the run does not stop.
- **The same state after this run's parent write**, where the parent passed nothing at compare time:
  the child should have followed. That is G1-SACL (4.4).
- **NFS-ACL-written objects**: their SACL is `S:P` (K3, K16), so each is a `Write` of its own, and
  its NFS-ACL-written children are too. `apply` still reads each child after its parent is written
  (as phase 2 does), so a child that hasn't followed is written as its own `Write`, never assumed.

**Kept directory SACLs.** A directory whose rule has no `sacl:` key still feeds its children's
inherited audit part from its **stored** SACL. The phase 1 fix applies to the SACL too: the stored
inherited part is replaced by the re-derived one only when the directory provably tracks its parent
and an ancestor's SACL will be written. Otherwise the stored SACL is passed down as it is. If the
stored SACL holds an opaque ACE type the model does not handle (K8), its children's SACL parts are
not classified; each such child's SACL part is reported as an error and not written, while its
DACL part is classified and written on its own. The refusal is per part, as in 4.5 (section 11,
decision 16).

**The root.** Its `desired(parent).sacl` is read from the array as its stored `ID` audit ACEs, as
for the DACL. A frozen `ID` copy on the root cannot be detected, so **`--root-sacl-protected`**
forces the root's SACL to Protected. It is separate from `--root-protected` (#76) and independent
of it (section 11, decision 4), because nothing shows that the two ACLs of one root freeze together.

**The main use.** Trees audited over NFS are `S:P` with every audit ACE explicit (K3). Converting
them to Inherits writes the parent's inheritable audit ACEs in `ID` form with `S:P` cleared. That is
the DACL's Q-PROT conversion, and it makes the SACL dynamic: a converted object follows later parent
changes (K10, K16). It does not convert the object's children. **Every object whose ACL was written
over NFS needs its own write**, so the write count for such a tree is the number of NFS-ACL-written
objects, not the number of directories; the dry run shows it. A tree whose ACLs were never written,
SMB- or NFS-created, the more common start, needs only the parents written (K10, K16).

## 4. The write

### 4.1 Call

Each SACL write is its own `SetKernelObjectSecurity`, through `Win32Security.WriteDescriptor`, with:
- `SACL_SECURITY_INFORMATION` (0x8);
- **exactly one** of `PROTECTED_SACL_SECURITY_INFORMATION` (0x40000000) and
  `UNPROTECTED_SACL_SECURITY_INFORMATION` (0x10000000), always stated, never left to the server;
- **a stated control word**, as phase 2 sends for the DACL (`Checker.cs:460`):
  - for a protected SACL: `SE_SACL_PRESENT | SE_SACL_PROTECTED`, with `SE_SACL_AUTO_INHERITED`
    clear;
  - for an unprotected one: `SE_SACL_PRESENT | SE_SACL_AUTO_INHERITED`.

The protection is stated twice, by the flag and by the control word, as phase 2 does for the DACL
and as Set-SaclOnly does for the SACL (`tools/set-saclonly/SaclOnly.cs:294-307`). The array decides
the stored auto-inherit bit from protection either way (K11). The handle is opened with
`ACCESS_SYSTEM_SECURITY` and backup intent. Nothing goes through `SetSecurityInfo` or
`SetNamedSecurityInfo`, because those start client-side propagation.

The return code is never taken as proof of what was stored. The array returned success while
dropping ACEs it doesn't store (K13), so **every write is followed by its G2 read-back**, with no
mode that skips it.

**Owner and group travel in the DACL call, never alone** (#79; section 11, decision 15). When a
rule names an owner or a group, the object's DACL write call sets them together with the DACL.
There is no owner-only or group-only write, so `--write-order` (4.2) orders that DACL call, owner
and group included, against the SACL call.

A combined `DACL|SACL` call would save one round trip on objects that need both. How the array treats
a combined write is **UNVERIFIED** (Q-SACL-COMBINED), so phase 3 does not use one.

### 4.2 Order when both parts differ

The order is a switch, because the right one is customer-specific (section 11, decision 3):
**`--write-order=sacl-first|dacl-first`**, default **`sacl-first`**. When a rule names an owner or
a group, they travel in the DACL call (4.1, per #79), and the switch orders that call, owner and
group included, against the SACL call (section 11, decision 15). Each write is followed by its
own G2 read-back. Neither order is atomic, and each leaves a window:

| Order | Window if the second write fails |
|---|---|
| `sacl-first` (default) | Auditing is already the new policy while access is still the old one. |
| `dacl-first` | Access is already the new policy, possibly wider, with the old auditing. New access can go unaudited. |

`sacl-first` is the default because a failed run should not leave newly granted access unaudited.
**`--write-order=dacl-first` prints a NOTE**, once, before any write, that new access can go
unaudited if a SACL write fails after its DACL write (section 11, decision 11).

**Pre-write check.** Phase 2 re-reads each object immediately before writing, and refuses if the
DACL, owner, group or DACL control bits moved since the compare (`Checker.cs:434-458`). In phase 3,
that re-read is taken with the SACL, and the check also covers the SACL bytes and SACL control bits.
In both orders, each part is compared with the **compare-time** read its decision was made on:
- The first write's pre-write check covers every part.
- The second write gets its own pre-write check. The part the first write just changed is compared
  against the first write's read-back. Every other part is compared against the compare-time read.

So under `sacl-first`, the DACL write compares the DACL against the compare-time read and the SACL
against the SACL write's read-back. Under `dacl-first`, the SACL write compares the SACL against the
compare-time read and the DACL against the DACL write's read-back.

**`dacl-first` keeps the qualified phase 2 DACL write byte-identical**: the same
`SetKernelObjectSecurity` call, flags and descriptor bytes. Its pre-write check and G2 gain the SACL
rows above, in both orders. A unit test asserts that the DACL write under `dacl-first` sends the
bytes phase 2 sends for the same object.

The order applies only to objects where both parts differ. It is recorded in the manifest. It is
**not** bound in the checkpoint: a resume re-reads and writes only what still differs (7.1).

A directory's children are queued only after **every** selected part of the directory has passed G2.

### 4.3 `S:P` and `S:AI`

`S:P` belongs to the desired form and is compared raw, like `D:P`.

`S:AI` follows the rule recorded on hardware (K11): **a protected SACL is stored with `S:AI` clear,
and an unprotected one with `S:AI` set**, whatever the write sent. G2 expects exactly that. The
preflight confirms the rule on the probe for each run (section 6, step 5). It refuses if:
- the probe's readings disagree with the rule; or
- the same write, repeated, reads back differently.

The lab answered the unprotected write sent with `S:AI` clear (K11). The probe measures it again
on each run, since 4.1 never sends that combination.

### 4.4 Guards

**G1 for the SACL.** During `apply`, a child of form Inherits or Explicit + inherits stops the run
when its stored SACL is unprotected and has the right explicit part with only `ID` ACEs after it,
but its `ID` part differs from `inh(desired(parent).sacl)`. So does an `S:AI` empty SACL read after
this run wrote its parent, when the parent's compare-time SACL passed nothing down: it should have
followed (K10). An `S:AI` empty SACL under a parent that **already** passed ACEs down at compare time
is not G1; it is a frozen copy from before the run (3.2). The parent's compare-time read tells the
two apart; no second read is needed. On a `check` run or the first pass of `apply` that read is in
memory; on a resume it is gone, and the checkpoint's record of each directory's compare-time
SACL (7.1) tells the two apart instead (section 11, decision 13). This applies to
every classified object, including those with
no `sacl:` key (2.3). There is no override, as for the DACL G1. It fires on a non-empty frozen
`ID` copy that predates the run too. A written or converted SACL with a matching `ID` part stays dynamic, and one with a mismatching
`ID` part stays frozen (K10), so the guard is needed: a false stop costs a rerun while a missed
freeze is silent.

**G2 for a SACL write.** A fresh read with the SACL after every write, compared raw:

| Part | Must equal |
|---|---|
| SACL ACEs (type, flags including `ID`, mask, SID, order), `S:P`, `SaclPresent` | the desired form |
| `S:AI` | the rule in 4.3 for that protection |
| owner, group | the read before |
| DACL bytes, `DaclPresent`, `D:P`, `D:AI` and every other control bit | the read before |

The last row is Set-SaclOnly's strict policy, made a stop with no `-Accept`. Set-SaclOnly compares
through SDDL and ignores `S:AI` drift (`SaclOnly.cs:329-348`). Phase 3 compares bytes and all
control bits instead. FlashBlade's known `D:P` loss on SMB SACL writes (`dacl-unprotected`) is
**not** carried over to FlashArray.

**G2 for a DACL write** is phase 2's (`Checker.cs:482-503`). When the same object's SACL was just
written, the SACL is compared against that write's read-back rather than the original before-image.

**Stops.** A G1 or G2 failure stops new writes and listings. Writes already in flight finish and are
checked. A write API error is **not** proof that nothing changed, any more than success is proof of
what was stored (K13), so the tool reads the object back.
- If the read succeeds, the record shows what is stored.
- If it fails, the object is recorded as `unknown` and the run stops.

An object where the first of two writes succeeded and the second failed is recorded with the parts
that were written, and its directory is not checkpointed.

### 4.5 Refusals before a write

The SACL write is refused, and the object's SACL part recorded as an error, when its stored SACL:
- holds an opaque ACE type the model does not handle (K8: mandatory label and the others, the
  SACL object and callback types 7, 0xD and 0xF, or any type `Descriptor` doesn't decode). A rebuilt
  audit-only list would delete it. FlashArray drops object and callback ACEs on write (K13), so
  these types may never be stored there. Whether the other types can be stored is Q-SACL-OPAQUE;
- holds an Allow or Deny ACE (type 0 or 1), or any other non-audit type. The model writes audit
  ACEs only, so a rebuilt list would delete it the same way; it is refused as opaque;
- would exceed 65,535 bytes once encoded, the encoder's limit. The array's own limit is Q-SACL-SIZE.

**The refusal is per part** (section 11, decision 16): an opaque ACE type errors the SACL part
only, and the object's DACL part still proceeds: it is written if it differs. A rebuilt DACL
cannot delete an ACE it never names, and the SACL's opaque ACE is outside the DACL write. The
object's recorded outcome is `Error`, since the SACL part is one of its two part verdicts (4.6).

Both the DACL and the SACL are encoded and size-checked before either is written.

### 4.6 Check and classify

An object now has two part verdicts. `CheckRecord` gains `SaclForm` and per-part outcomes. The
record's single `Outcome` is the worse of the two, in the order
`Error > Stopped > Write > Follows > Written > Ok > Keep`. That keeps exit codes, the checkpoint's
`done(ok)` and the evidence vocabulary unchanged. `Keep` means both parts are kept and ownership is
right. Phase 1's rule that a named owner or group difference is a `Write` even under `Keep` still
applies (#79).

## 5. Privileges

**Prerequisite: #78** (section 11, decision 20).

| Privilege | Phase 3 use |
|---|---|
| `SeSecurityPrivilege` | requested for SACL reads and writes (`ACCESS_SYSTEM_SECURITY`). `apply` already enables it (`Program.cs:261`). **`check` enables it too whenever any rule sets `sacl:`**, and then reads every object with its SACL in the same `GetKernelObjectSecurity` call. Without such a rule, `check` is unchanged. On FlashArray it is **not** what admits a SACL write (K14); see below. |
| `SeBackupPrivilege` | unchanged: listing and reads under backup intent |
| `SeRestorePrivilege` | unchanged: enabled only when a rule names an owner or group, explicitly disabled otherwise. A SACL write needs nothing from it; Set-SaclOnly turns it off because it widens what a backup-intent open can do. |

**What gates a SACL write.** On FlashArray, a SACL write succeeded with `SeSecurityPrivilege`
disabled in the client token (K14). The client privilege is therefore a precondition the tool
checks, not a protection. The array's audit bypass decides, and only the probe proves it. Refusal
before any write, in three layers:

1. **Token (local precondition).** The tool enables `SeSecurityPrivilege`. If that fails with
   `ERROR_NOT_ALL_ASSIGNED`, the command exits 1 naming the privilege, before the evidence
   directory, checkpoint or probe exist. Windows servers need the privilege. On FlashArray, this
   layer proves nothing about the array, and passing it is never reported as proof of anything.
2. **Array refuses the SACL open.** Without the bypass, SACL reads and writes are refused with
   error 5 and nothing changes (K12, K7). On a probe whose DACL the tool just wrote, error 5 on a
   SACL-bit open means "no audit bypass", not a DACL denial, and the preflight says so (local NTFS
   gives 1314 for the same case). The preflight refuses and removes the probe.
3. **Array accepts the write but does not keep it.** The probe's placeholder does not read back
   (K5). The preflight refuses.

Layers 2 and 3 are the gate. Phase 2 left the missing-bypass refusal unverified on hardware (A7b).
The array side is now recorded by harness with the provisioned identity (section 11, decision 12;
K12). Phase 3 cannot ship until the product's own refusal is shown too (scenario S1).

## 6. Preflight

The probe is extended and reordered so that **no tree object's SACL is read before the bypass is
proven**, for `apply` and for `check`. An NFS read without the bypass had a side effect (K7). Over SMB
on Purity//FA 6.10.7 it has none (K7, K12), so the order is a safeguard for other versions and
arrays, not a known hazard over SMB. (`inspect` reads SACLs today without a probe; it is a
diagnostic, and its README says so.)

**The probe is a throwaway object, never the root** (section 11, decision 17), as in
`internal/auditproof` (PS-02). It is the directory, subdirectory and file the preflight creates in
step 1 under `--probe-dir` (or ROOT) and removes at the end. Its placeholder audit ACE names
`EVERYONE@`. No write the probe needs ever touches the root or any other tree object.

`apply` runs every step. `check` with a `sacl_set` rule runs steps 1, 2 and 7, the SACL bypass
proof on a disposable probe, before any tree read, in the same way build-spec proves the bypass
(PS-02, `internal/auditproof`). It uses `--probe-dir` or ROOT, as `apply` does. `check
--accept-unproven-read` skips the probe and reads the tree's SACLs unproven, with a NOTE.
`check` with no `sacl_set` rule needs no probe, as today.

**This changes `check`'s contract.** Phase 1 was qualified read-only (`700630b`). With a
`sacl_set` rule, `check` creates, writes and removes a probe, so it needs a writable probe location
(`--probe-dir` or ROOT) and, without one, exits 1 before reading the tree, with nothing left behind.
`--accept-unproven-read` is the read-only way. The README status and the operator docs state this,
and scenario S2b tests it.

1. Create the probe directory, subdirectory and file (as phase 2).
2. Write a protected SACL with the `EVERYONE@` placeholder audit ACE and require it back (as
   phase 2, K5). The bypass is now proven on data that is not the tree's.
3. **Only now**, read the root with its SACL and compute `desired(root).sacl`. Phase 2 computes the
   root's desired DACL before the probe; the SACL half moves here.
4. Write the root's desired audit ACEs to the probe directory as an unprotected SACL, with `ID`
   cleared. If the root passes nothing down, use an inheritable placeholder (`OI|CI|SA|FA`) instead,
   so the check below is never vacuous. Read back, and require the subdirectory's and file's `ID`
   audit part to equal `inh(…)`. **This step depends on the probe's children following their
   parent.** Which recorded path applies depends on the root. If the root passes nothing down, the
   children were created in step 1 with no audit ACEs and follow as never-written objects (K10,
   K16). If the root passes audit ACEs down, the children were created holding them as `ID`
   ACEs, and step 2's protected placeholder on the probe directory then changed what it passes;
   the children follow on K10's matching-`ID` path. Both paths are recorded. This is G1 on known
   data.
5. **Confirm the `S:AI` rule (4.3):** write an unprotected SACL (one explicit audit ACE, then its
   inherited part) to the subdirectory and a protected one to the file, each with the control word
   of 4.1, and read both back. Then write the subdirectory once more, unprotected, with `S:AI`
   **clear** in the control word. Require all three to match the rule in 4.3. Also write `SA`-only
   and `FA`-only ACEs and a present, empty, protected SACL, and require each back exactly (K9).
6. Require the probe's owner, group, DACL bytes and DACL control bits unchanged across steps 2 to 5.
   This is the `sacl:`-only strict check on known data.
7. Phase 2's DACL steps (`apply` only) and cleanup. If the cleanup fails, the run refuses.

A plan with no `sacl_set` rule runs phase 2's preflight unchanged.

**The probe's writes, read-backs and removal are recorded** (section 11, decision 18). `apply`
puts them in its evidence directory as a preflight shard. `check` takes an optional
**`--evidence-dir`** for the same shard; without it, they go to a NOTE line plus the summary JSON
(7.2).

**What the probe does not prove:**
- that a written SACL stays dynamic after later parent changes (Q-SACL-DYNAMIC);
- that the tree's objects are in the never-written state the probe's children are in: an
  NFS-ACL-written object in the tree is `S:P` and is written, not followed (K16);
- that the target share behaves like the probe's directory, unless the probe is inside the target
  share, which phase 2 already requires;
- that audit events are delivered (Q-SACL-EVENTS).

## 7. Checkpoint, evidence and recovery

### 7.1 Checkpoint

The checkpoint header moves to **v2**. A v1 checkpoint is never resumed by a SACL-capable build. The
v2 header binds:
- the plan's SHA-256 (already bound in v1);
- the root;
- `--root-protected` and `--root-sacl-protected`;
- a SHA-256 of the resolved principal-to-SID table, so a name that resolves differently on resume
  refuses the resume (**prerequisite: #78**; section 11, decision 20);
- the `S:AI` rule as the preflight confirmed it.

Beyond the header, checkpoint **v2 records each directory's compare-time SACL**, or its
classification where the raw form cannot be recorded, before any write in that directory
(section 11, decision 13). In memory, the parent's compare-time read tells a pre-run freeze (3.2) from a
G1-SACL failure (4.4); on a resume that read is gone, and the record does it instead for every
object the resume re-reads.

`--write-order` is **not** bound (section 11, decision 11). A resume re-reads every object it does
not skip and writes only what still differs, so a changed order affects only objects that still
need both parts.

A directory is complete only when it and every file in it are right on **every** part the plan
names. A directory with a two-write object that stopped half way is not complete; a resume rereads
it and writes only what still differs. A persistent per-child error keeps its directory incomplete,
and a resume re-reads the child (section 11, decision 19), following the Go tool's PS-11 rule.

Resume still skips the files of a complete directory without reading them, as phase 2 does. That
assumes the tree did not change between the runs. The assumption is stated in the operator docs, and
`check --validate` after a resume is the independent proof.

### 7.2 Evidence

Phase 2's shard format is kept. Its before- and after-images are already read with the SACL, so phase
2 evidence already holds raw SACL bytes. Phase 3 adds:
- `parts` values `sacl`, `sacl,dacl`, `dacl,sacl`, `sacl,dacl,owner` and so on, in write order;
- both forms in the note, for example `(sacl protected, dacl inherits)`;
- `unknown` and partial outcomes as their own counts;
- `sacl_forms` counts in the manifest, the `--write-order`, and the preflight line naming the SACL
  steps and the confirmed `S:AI` rule;
- the preflight shard: the probe's write, read-back and removal (section 6). `apply` records it in
  its evidence directory. `check` takes an optional `--evidence-dir`; with it, the shard goes
  there, and without it the probe goes to a NOTE line plus the summary JSON (section 11, decision
  18);
- **each evidence line is flushed to stable storage before the next write starts.** Phase 2's shard
  is buffered, and a hard kill in qualification lost one before-image. For audit changes, which are
  compliance-sensitive, one flush per written object costs little next to two SMB round trips and a
  read-back. It closes that gap for every directly written object.

### 7.3 Recovery

**Phase 3 promises end-state evidence, not rollback.** The flush in 7.2 keeps every directly written
object's before-image. Objects that change only by inheritance from a written parent still have no
before-image at all.

**The phase 3 operator docs require an array snapshot before `apply`.** A per-object undo needs a
durable intent journal, flushed before each write. It is not in phase 3; a separate design covers
it for both the DACL and the SACL (#87; section 11, decision 8).

**Resume.** The checkpoint's record of each directory's compare-time SACL (7.1) lets a
resume tell a pre-run freeze (3.2) from a G1-SACL failure (4.4) on the objects it re-reads. A
persistent per-child error keeps its directory incomplete, so the resume re-reads the child
(7.1, PS-11).

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
product qualification. They are ranked by the damage a wrong assumption would do. **Status** is what
the records in section 1 settle. **Blocks** is what stays blocked until the open part is answered.

| Id | Question | Status | Blocks |
|---|---|---|---|
| Q-SACL-ISOLATION | Does a SACL-only write, **including one that changes `S:P`**, leave owner, group, DACL bytes, `DaclPresent`, `D:P`, `D:AI` and other control bits unchanged? Test every DACL form, SMB-written and NFS-written objects, and `SeRestorePrivilege` both on and off. | **Answered: yes** (K2): 96 SACL-only writes, 0 changes outside the SACL, over six SMB DACL forms and raw-NFS-written objects, `S:P` flipped both ways, `SeRestorePrivilege` off and on. | nothing; G2's DACL row stays regardless |
| Q-SACL-PARTIAL | After the first of two writes, a failed second write, or a disconnect after the server committed: what is stored, and does the read-back tell the truth? | **Partly answered** (K17): SACL first, DACL write failed: the SACL write is stored and the read-back, a second read and a 30 s re-read agree. Open: a failing first SACL write (so `dacl-first`'s failure case), and a disconnect after commit (needs fault injection). | `dacl-first`'s failure handling; the `unknown` outcome |
| Q-SACL-DYNAMIC | Is a child **written** with `ID` audit ACEs that match its parent dynamic, and is one that does not match a frozen copy? After an `S:P` to unprotected conversion, does the object and its unwritten subtree follow **two** later parent SACL changes? Test SMB-born and genuinely NFS-flattened objects. | **Answered** (K10, K16): matching-`ID` written objects, `S:P`-to-unprotected conversions and never-written objects follow two parent changes with their unwritten subtrees; a mismatching `ID` part stays frozen. Genuinely NFS-written objects follow after their own conversion; their unconverted NFS-ACL-written children stay `S:P`. | nothing; G1-SACL stays (4.4) |
| Q-SACL-ABSENT | Does a never-audited child (SACL absent) pick up a parent's newly written inheritable audit ACEs, existing children and ones created later? What does an object **created over NFS** store under a parent that already passes audit ACEs: inherited `ID` ACEs, or `S:AI` empty? | **Answered: yes, when the child's ACL was never written** (K9, K10, K16, K18), SMB- or NFS-created, existing or created later. FlashArray never reports an absent SACL; such a child reads `S:AI` empty. An NFS-ACL-written child is `S:P` and does not follow. Objects created over NFS (mode only) under an already-audited parent store what an SMB create stores: the parent's inheritable ACEs as `ID`, and they follow later parent changes (K18). Not covered: other NFS identities and Kerberos, parents whose audit ACEs were written over NFS, FlashBlade and other Purity versions. | the predicted write count for NFS-used trees; `apply` writes any such child under a `sacl:` rule either way |
| Q-SACL-EVENTS | Do `SA`-only, `FA`-only and combined ACEs deliver events for allowed and denied SMB access by non-bypass identities, at the final sink, with and without an audit policy on the managed directory? | open over SMB; NFS only (`benchmarks/sacl-fa-20261015/AUDITLOG-RESULTS.md`) | any claim about audit coverage, as opposed to stored rules |
| Q-SACL-AUTH | With `SeSecurityPrivilege` but no array audit bypass: is an SMB SACL read refused, empty or returned, and does it change the object (K7)? Is the SACL write refused or dropped? | **Answered** (K7, K12, K14): SACL reads and writes are refused with error 5, nothing is returned or stored, and nothing changes; the client privilege neither grants nor blocks SACL access. Untested: the non-bypass identity holding `SeSecurityPrivilege` (a host policy change). | nothing in the design; S1 still owed for the product's refusal |
| Q-SACL-INH | Do audit ACE flags (`OI`, `CI`, `NP`, `IO` and combinations, with `SA`, `FA`, both) inherit as `inh` predicts **when the parent's SACL is written with `SACL_SECURITY_INFORMATION`**? | **Answered: yes** (K4): 304/304 children under 38 parents, every flag set as `SA`, `FA` and both. | nothing |
| Q-SACL-CONTROL | What do protected, unprotected, present-empty and NULL SACL writes read back as (`S:P`, `S:AI`, `SaclPresent`)? In particular, how does `sacl: []` (protected, present, empty) read back? What happens to children of an empty protected SACL when their parent later gains auditing? | **Answered** (K9, K10, K11): the protection flag alone decides `S:P`/`S:AI`, whatever AI bit is sent; present-empty, NULL and absent writes all store a present 0-ACE SACL; `sacl: []` reads `S:P` with 0 ACEs and blocks a later ancestor change until written. | nothing beyond the preflight's check |
| Q-SACL-IDENTITY | Are audit ACEs naming unmapped, deleted, foreign-domain or array-local SIDs stored unchanged? Does a SACL-only write on an object whose DACL names such SIDs leave the DACL byte-identical? | the DACL half for Set-SaclOnly's write (`benchmarks/sacl-unmapped-sid-20261020/`) | `sacl:`-only rules on damaged trees |
| Q-SACL-SCOPE | Does a parent SACL change reach excluded subtrees and `Keep` subtrees under it? | **Answered for what is stored** (K15): excluded and left objects show the parent's inheritable ACEs. Open: nothing for the design; the operator docs state it. | nothing |
| Q-SACL-OPAQUE | Does FlashArray store mandatory label, resource attribute or scoped policy ACEs over SMB? | **Partly answered** (K13): object and callback ACEs are dropped on write. Open: the three K8 types. | whether 4.5's refusal can fire in practice |
| Q-SACL-SIZE | The largest SACL and the largest combined descriptor the array accepts. Is an over-size write refused cleanly, with both ACLs unchanged? | encoder limit 65,535 bytes | the error path |
| Q-SACL-COMBINED | Is one `DACL\|SACL` write equivalent to two single-part writes, including when it fails? | open | nothing in phase 3; a later optimisation |

Q-OWN (design section 7) also gates the creator SIDs in `sacl:`, which stay refused until it is
answered.

## 9. Relationship to existing tools

### 9.1 Set-SaclOnly

It retires **for FlashArray** once this phase is released (`smb-v0.2.0`, qualified on FlashArray);
from then on `permissionreset-smb` is the supported SMB SACL path there. It stays supported,
frozen (fixes only), for SMB-written FlashBlade data until FlashBlade over SMB is decided
(decision record, section 2.5, as amended). FlashBlade over SMB comes last, if at all, so
Set-SaclOnly may stay in service for FlashBlade indefinitely.

| Set-SaclOnly behaviour | Phase 3 |
|---|---|
| SACL-only `SetKernelObjectSecurity` through a backup-intent handle, protection stated by flag | **kept** (4.1) |
| `SeSecurityPrivilege` on, `SeRestorePrivilege` off | **kept** (section 5) |
| root preflight on the first object | **replaced** by the disposable probe (section 6) |
| strict owner/group/DACL comparison, stop on change | **kept and tightened**: raw bytes and all control bits (4.4) |
| `-Accept dacl-unprotected` (FlashBlade) | **not applicable** on FlashArray |
| `S:P`/`S:AI` copied from the object, ACEs written as given | **replaced** by computed forms (section 3). This is the behavioural difference. There is no parity mode; scenario S-PAR compares the two tools (section 11, decision 1). |
| skip when ACEs equal, control ignored | **replaced** by a raw compare including `S:P` |
| `OWNER@`/`GROUP@` written as `CO`/`CG` | **refused**, with the other two creator SIDs (2.2) |
| `sacl: []` clears, absent key leaves alone | **kept**, with `sacl: []` always `S:P` (2.3) |

Two differences from Set-SaclOnly are intended, not qualifications to close (section 11, decision
21). First, `sacl: []` on an unprotected object: Set-SaclOnly copies the object's own `S:P`/`S:AI`,
so its empty SACL stays unprotected, while this design always writes present-empty `S:P` (2.3).
Second, `OWNER@`/`GROUP@`: Set-SaclOnly maps them to `CO`/`CG`, while this design refuses them,
with the other two creator SIDs (2.2). S-PAR's spec therefore excludes both cases; other scenarios
cover them against this design's rules (section 10).

Separately, `tools/set-saclonly/README.md:5-6` says an `acl:` run without `--sacl` deletes SACLs.
That is out of date: the Go tool keeps each object's audit ACEs without `--sacl` (PS-04, root
`CLAUDE.md`). The README should be corrected in its own change.

### 9.2 The Go `--sacl` mode and its guards

| Guard | Why it exists over NFS | Over SMB |
|---|---|---|
| `--sacl` opt-in; an `acl:` rule with no `sacl:` key refused | one NFS ACL holds both lists, so a DACL write without audit entries deletes them | the hazard does not exist: the parts are separate (K1). **No `--sacl` flag**: the plan's `sacl_set` is the intent, `sacl: []` included (section 11, decision 5). The counts in 2.3 are the operator's warning. |
| `ErrAuditedObject` | an NFS write flips `S:AI`/`D:AI` to protected | not applicable; G2 catches any cross-part change |
| `ErrDACLFlattening` | NFS has no `ID`, so a kept DACL is stored flat | not applicable: a `sacl:`-only write never names the DACL. G2 proves it per object. |
| `ErrUnmappedPrincipal`, `ErrSyntheticRangePrincipal` | NFS translates ids to SIDs on write | not applicable: SIDs are written natively. No numeric RID threshold is imposed. Stored SIDs the tool does not write are never re-encoded. |
| `ErrHighIDPrincipal` | the spec names an id >= 1e9 | superseded: SMB plans refuse every numeric principal |
| `ErrUnpreservableAudit` | kept audit ACEs must be re-written over NFS | not applicable: a kept SACL is not written |
| audit-bypass preflight | a write without the bypass is dropped | **kept**, for `check` too (section 6) |
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
- offline tests green, with `FakeTree` extended so a wrong SACL model fails a unit test first:
  - SACL analogues of F1 to F3;
  - never-written SACLs (absent, or `S:AI` empty under a parent that passes nothing) following,
    and protected ones and mismatching `ID` parts not following (K10, K16);
  - K9's present-empty behaviour and K11's `S:AI` rule;
  - a write that returns success and drops ACEs (K13);
  - partial writes and `unknown` outcomes;
- the CLI refusals tested through fakes, including the `sacl: []` counts, the `dacl-first` NOTE,
  `check`'s probe and `--accept-unproven-read`;
- the `--smb-plan` golden file updated, with golden cases for absent, empty, listed, contradictory
  and malformed `sacl`, and for all four creator SIDs refused. It also covers the schema rule in
  2.1: schema 2 for a DACL-only spec, schema 3 when any rule sets `sacl:`, and a schema 2 plan with
  `sacl_set` refused by the consumer;
- a unit test that the DACL write under `--write-order=dacl-first` sends phase 2's bytes (4.2).

**Qualification pending** means every row below passed on one exact candidate. The candidate is
recorded as phase 2's was: commit, artifact SHA-256s, unit test count, `build-spec` at the same
commit, Purity version re-read on the day, client build, identity and privileges.

The open platform questions come first. An answer that contradicts an **ASSUMPTION** here changes
the design before the product run.

| Step | Scenario | Pass condition |
|---|---|---|
| P1 | The open parts of section 8, by harness | each answered with raw before/after captures, or recorded as unanswered with the reason |
| S0 | `check` with a `sacl:` plan, `SeSecurityPrivilege` not assignable to the token | exit 1 naming it; nothing read |
| S1 | `apply`, and `check` without `--accept-unproven-read`, as the provisioned identity: `SeSecurityPrivilege` in the token, **no** array bypass, not in Audit Operators (section 11, decision 12). The identity as provisioned has no `SeSecurityPrivilege` in its token; granting it is a host policy change, and without it S0's refusal fires first, so S1 runs only once that grant is made | preflight refuses at layer 2, naming the missing bypass; no evidence directory, no checkpoint, probe removed, tree byte-identical (raw reads before and after with a bypass identity) |
| S2 | preflight on a conforming root, for `apply` and for `check` | passes; its line names the SACL steps and the confirmed `S:AI` rule |
| S2b | `check` with a `sacl:` plan and no writable probe location (read-only `--probe-dir`, read-only ROOT) | exit 1 before any tree read, naming the probe location; nothing left behind. With `--accept-unproven-read`: no probe created, the NOTE printed |
| S3 | A fixture covering every SACL form under every rule kind in 2.4, including: `sacl: []` under parents that do and do not pass auditing down; a never-audited subtree under a newly audited directory, SMB-created and NFS-created (mode only); an NFS-ACL-written subtree under it; files and directories created over NFS under a directory that already passes audit ACEs (they hold the parent's ACEs as `ID` and follow, K18); an NFS-audited subtree written by a real `permissionreset --sacl` run; an SMB-audited subtree; a deny-only directory; unmapped and array-local SIDs in the DACL under a `sacl:`-only rule; `acl:`-only objects under a directory whose SACL is written | `check` agrees with an independent classifier written from this text, including its write count and both parts of its loss count (2.3); `apply` exits 0 with no stop; every written object's after-image equals an independent raw read; every `sacl:`-only object's owner, group, DACL bytes and DACL control bits are identical before and after; never-written descendants (SMB- or NFS-created) are followers, not writes; each NFS-ACL-written object is a write of its own |
| S4 | Rerun `apply`, then `check --validate` | 0 writes; exit 0 |
| S5 | A frozen SACL copy planted under a parent the run does not write, and one under an `acl:`-only rule | `check` reports both; `apply` stops on G1, exit 1 |
| S6 | Kill mid-run on a tree large enough to checkpoint; `--resume` | completes; `check --validate` exits 0; partial records as documented; every directly written object has its before-image in the evidence |
| S7 | A rule with both, on objects where only the SACL, only the DACL, or both differ; a fault injected between the two writes. **Run once under each `--write-order`.** | `parts` recorded correctly, in the chosen order; the half-written object is not checkpointed; a rerun converges. Under `dacl-first`, each DACL write's call and descriptor bytes equal phase 2's for the same object, and the NOTE was printed. |
| S7b | S3's fixture again under the order S3 did not use | the same pass conditions as S3; the end state equals S3's |
| S8 | **After** a successful run: two independent parent SACL changes, plus new files and directories created under written directories, **over SMB and over NFS** | unwritten and newly created descendants follow both changes. A matching state right after the run is not enough. |
| S-PAR | One spec on two copies of one fixture: Set-SaclOnly on one, `permissionreset-smb apply` on the other. The spec excludes `sacl: []` on unprotected objects and `OWNER@`/`GROUP@`: Set-SaclOnly differs from this design on both by design (9.1; section 11, decision 21). Other scenarios cover those cases against this design's rules: S3 for `sacl: []`, the `--smb-plan` golden cases and the consumer tests for the creator SIDs. | the **effective audit ACEs** are equal on the two copies (definition below). Bytes, `ID` flags and `S:P` are expected to differ wherever the computed form differs from Set-SaclOnly's copied form; each such difference is listed. |
| S9 | Events, if the lab array has an audit policy: allowed and denied SMB access by non-bypass identities, for `SA`-only, `FA`-only and both | events observed at the sink. Stored rules and delivered events are reported as separate verdicts. With no policy available, this is recorded as **unverified**, not skipped silently. |

**Effective audit ACEs** (S-PAR; section 11, decision 11):
- per object, the set of (type, `SA`/`FA`, mask, SID) of the ACEs that apply to the object itself,
  with inherit-only ACEs excluded;
- plus, per directory, the set it passes to children: for each kind of child (file, directory), the
  (type, `SA`/`FA`, mask, SID) of the ACEs that child would inherit and that apply to it.

Order, the `ID` flag, `S:P`/`S:AI` and the inheritance flags themselves are not compared.

Deliverables:
- `benchmarks/qual-smb-sacl-<commit>-<date>/RESULTS.md`, with passed, failed, skipped and unverified
  listed separately;
- a `COMPATIBILITY.md` row for SMB SACL writes;
- operator docs that:
  - require an array snapshot before `apply` (7.3);
  - describe `--write-order` and its NOTE, and the `sacl: []` counts;
  - say that a rule without `sacl:` is not "not audited" on FlashArray (2.3);
- the design's as-built section extended.

The `smb-v0.1.0` tag is not affected by this phase. #80 changed SMB rule matching after that tag, so
the next `smb-v*` release is qualified on its own assets in any case.

## 11. Maintainer decisions

Robert decided these on 2026-11-23 (1 to 9) and 2026-11-24 (10 to 12, and the round 3 review
decisions 13 to 21), after reviewing the open choices in the first draft and the reviews of
`e475693` and `1c5ca96`. The rest of this text follows them.

| # | Topic | Decision | Where it applies |
|---|---|---|---|
| 1 | Set-SaclOnly parity mode | **Computed inheritance only. No stamp mode.** The comparison with Set-SaclOnly is qualification scenario S-PAR: one spec on two copies of one fixture, compared on effective audit ACEs, not bytes. | section 3; 9.1; 10 (S-PAR); `DESIGN-write-path.md` 2.5 and 8 |
| 2 | `sacl: []` | **Always Protected and empty** (`S:P`, no audit ACEs). This matches the Windows way to guarantee no auditing: disable inheritance and remove every entry. `DESIGN-write-path.md` 2.5 is corrected to match. | 2.3; 3; Q-SACL-CONTROL |
| 3 | Write order when both parts differ | **A switch**, because the right order is customer-specific: `--write-order=sacl-first\|dacl-first`, default `sacl-first`. `dacl-first` keeps the qualified phase 2 DACL write byte-identical. Qualification covers both orders. | 4.2; 10 (S7, S7b) |
| 4 | Root SACL | **A separate `--root-sacl-protected`**, independent of `--root-protected` (#76). | 3.2; 7.1 |
| 5 | Opt-in | **No `--sacl` flag** on the SMB tool. The plan's `sacl_set` is the intent. | 9.2 |
| 6 | `OWNER@`/`GROUP@` in `sacl:` | **Refused** by `--smb-plan` and by the consumer. Decision 11 widens this to all four creator SIDs. | 2.2 |
| 7 | Schema | **Schema 3** for this change in write semantics, with the compatibility rule proposed in 2.1 (confirmed by decision 10). | 0; 2.1; 10 |
| 8 | Rollback journal | **Not in phase 3.** A separate design covers a durable intent journal for both the DACL and the SACL (#87). Phase 3 docs require an operator snapshot. | 7.3; 10 |
| 9 | FlashBlade | **Out of scope.** FlashBlade over SMB comes last, if at all. | header; 9.1 |
| 10 | Schema compatibility rule | **Confirmed as proposed:** `--smb-plan` emits schema 3 only when some rule sets `sacl:` (`[]` included), otherwise 2. Phase 3 builds accept schema 2 without `sacl_set`, plus schema 3. A schema 2 plan with `sacl_set` is refused with a "rebuild it" message. `smb-v0.1.0` refuses schema 3 as unknown. | 2.1; 2.2 item 6; 10 |
| 11 | linux01-public's flags on decisions 1 to 9 | **Accepted:** (a) the design states that `sacl: []` writes every never-audited object in scope once. The dry run shows that count, and `apply` prints how many objects will lose audit ACEs. (b) `--write-order=dacl-first` prints a NOTE that new access can go unaudited if the SACL write fails, and the write order is **not** bound in the checkpoint. (c) All four creator SIDs (`S-1-3-0` to `S-1-3-3`) are refused in `sacl:`, in the producer and the consumer. (d) S-PAR's "effective audit ACEs" is defined as in section 10. | 2.2; 2.3; 4.2; 7.1; 10 |
| 12 | Identity without the bypass | **Provision one.** win01-lab owns it and keeps it for future qualification runs. It is recorded in the lab repository only. | section 5; Q-SACL-AUTH; S1 |
| 13 | Resume freeze detection (G1) | Robert, 2026-11-24: checkpoint v2 records each directory's compare-time SACL, or its classification, before any write in that directory. A resume uses that record to tell a pre-run freeze (3.2) from a G1-SACL failure (4.4). | 4.4; 7.1; 7.3 |
| 14 | Protected SACL under no `sacl:` key (G2) | Robert, 2026-11-24: a protected SACL with explicit ACEs under a rule with no `sacl:` key is `Keep`, as in Set-SaclOnly (`tools/set-saclonly/README.md:57-58`). The 2026-10-21 decision stands: keep the protection flags, change only the ACEs, and where the rule names no ACEs the SACL does not change. | 2.3; 3.2 |
| 15 | Owner and group in the DACL call (G3) | Robert, 2026-11-24: owner and group travel in the DACL call, never alone (per #79). `--write-order` orders that call, owner and group included, against the SACL call. | 4.1; 4.2 |
| 16 | Opaque ACE types (G4) | Robert, 2026-11-24: an opaque ACE type (the object and callback types, which in a SACL are 7, 0xD and 0xF, or any type `Descriptor` doesn't decode) errors the object's SACL part only. The DACL part proceeds and is written if it differs. | 3.2; 4.5 |
| 17 | Probe object (G5) | Robert, 2026-11-24: the preflight probe is a throwaway object with an `EVERYONE@` placeholder audit ACE, never the root, as in `internal/auditproof` (PS-02). | 6 |
| 18 | Probe evidence (G6) | Robert, 2026-11-24: `check` takes an optional `--evidence-dir`; the probe's write, read-back and removal go there as a preflight shard. Without it they go to a NOTE line plus the summary JSON. | 6; 7.2 |
| 19 | Persistent per-child errors (G8) | Robert, 2026-11-24: a persistent per-child error keeps its directory incomplete, and a resume re-reads the child, following the Go tool's PS-11 rule. | 7.1; 7.3 |
| 20 | #78 as prerequisite | Robert, 2026-11-24: #78 is a prerequisite for the producer and consumer checks (2.2), the privilege rules (5) and the checkpoint's principal table hash (7.1). | 2.2; 5; 7.1 |
| 21 | S-PAR scope | Robert, 2026-11-24: S-PAR's spec excludes `sacl: []` on unprotected objects and `OWNER@`/`GROUP@`, because Set-SaclOnly differs from this design on both by design. Other scenarios cover those cases against this design's rules. | 9.1; 10 |

The review findings on `e475693`, the lab findings and the K1 to K8 and section 8 rebuild were folded
in as part of decision round 2. Section 13 lists them.

## 12. How this text was written

The first draft merged three model outputs, produced with spillway from one shared brief, and was
edited by hand:

| Model | Role | Main contributions kept |
|---|---|---|
| claude-fable-5-1 | independent draft | the structure; the schema analysis (no shape change, new producer and consumer checks); the three-form model applied to the SACL; the preflight reordering so no tree SACL is read before the bypass is proven; the Set-SaclOnly and Go guard tables; most of the qualification table |
| gpt-6-sol | independent draft | the `stamp` versus `computed` option (decided: computed only, section 11, decision 1); SACL-first ordering; the separate root flag; checkpoint v2 binding the principal table; `unknown` outcomes on write errors; the stale Set-SaclOnly README line |
| gpt-6-astra | adversarial review: failure analysis and testable requirements | the refusal of unmodelled SACL ACE types (K8); no rollback promise; the post-run parent-change requirement (S8); separating stored rules from delivered events; ranking hardware questions by damage |

The 2026-11-24 revision applied the maintainer's decisions and linux01-public's review, and rebuilt
section 1 and section 8 from the lab records that linux01-public's correction cites (PR #82 comment
7121027669) and from win01-lab's findings. That correction retired the first draft's K4 claim (that
the Q-INH audit rows came from DACL-only writes), which an earlier reviewer had raised.

**Model output is not evidence.** The following were checked by hand against code on `main` @
`cd4ed1e`:
- the plan fields and the always-present `sacl` (`saclplan.go:110-116`, `:300-310`);
- the `OWNER@`/`GROUP@` mapping and its DACL-only refusal;
- the consumer's SACL checks (`Plan.cs:111-117`), and that it does not require `SA`/`FA`;
- the schema check (`Plan.cs:33-34`);
- phase 2's `sacl_set` refusal (`Program.cs:250-254`);
- `CreatorSids` holding all four creator SIDs (`Inheritance.cs:35`);
- `Matches` and its null semantics (`Inheritance.cs:103`), and `TrackableShape` and `Follows`
  (`Checker.cs:511-540`);
- the DACL control word phase 2 sends (`Checker.cs:460`) and the F5 check (`Checker.cs:497-502`);
- the placeholder audit ACE in the phase 2 preflight (`Preflight.cs:73-86`);
- the opaque ACE types in `Descriptor` (`Descriptor.cs:114-118`);
- Set-SaclOnly's README on FlashArray's untouched-but-audited objects (`README.md:58-60`).

The lab facts in section 1 are restated from the cited records and findings, and were not re-run.
Other line references come from the drafts and were not each re-read. The reviewer should treat
them as pointers, not as proof.

## 13. Review findings on `e475693`

linux01-public's adversarial review (PR #82), as corrected by its comment 7121027669, and win01-lab's
FlashArray findings:

| # | Finding | Handling |
|---|---|---|
| 1 | `Matches` treats an absent ACL as a difference, which is wrong for the SACL | **Fixed**: a SACL comparison with its null semantics spelled out (3.1). K9 retires the present-empty risk. `sacl: []`'s one-write-per-object cost is stated, with counts (2.3). |
| 2 | Missing question: does a never-audited child pick up a parent's audit ACEs? | **Fixed**: Q-SACL-ABSENT added, answered for SMB-created children (K10). The SACL follows model counts an absent SACL as following (3.2). NFS-created children were open at `e475693`; win01-lab's final run answered them (K16): mode-only children follow, NFS-ACL-written ones are `S:P` and need their own write. |
| 3 | The SACL control word is unspecified, and F5 looked confounded | **Fixed**: 4.1 states the control word. **Argued** on the confound: F5 is not confounded (K11, `7ac90d8`), so 4.3 expects the recorded rule. The one untested combination is measured by the preflight (step 5). |
| 4 | `check` reads tree SACLs with no bypass proof | **Fixed**: `check` runs the probe's bypass proof before any tree SACL read, or needs `--accept-unproven-read` (section 6). |
| 5 | "Left alone" fails across the run | **Fixed**: every object's SACL is classified when any rule sets `sacl:`; followers are reported, frozen copies are errors and hit G1-SACL (2.3, 4.4, S5). |
| 6 | 4.3's `S:AI` rule refuses every run | **Fixed**: 4.3 states the accepted rule and refuses only on disagreement or non-repeatability. |
| 7 | Preflight step 4 depends on finding 2 | **Fixed**: the dependency is stated; it holds for the probe's SMB-created children (K10). |
| 8 | The pre-write check needs the SACL | **Fixed**: 4.2 states the pre-write check for both writes, in both orders. |
| 9 | S1 needs an identity the lab doesn't have | **Fixed** by decision 12: one is provisioned; S1 uses it. |
| 10 | Refuse all four creator SIDs | **Fixed** (2.2; decision 11). |
| 11 | Flush each evidence line before the next write | **Fixed** (7.2). |
| 12 | Base, citations and FlashBlade scope stale; the question count is wrong | **Fixed**: base and citations move to `main` @ `cd4ed1e`; FlashBlade is out of scope in the header and 9.1; the summary no longer gives a count, and section 8 marks each question's status. |
| W1 | win01-lab: FlashArray returns rc 0 but drops object and callback ACEs | **Fixed**: K13; G2's read-back is mandatory on every write (4.1); 4.5 and Q-SACL-OPAQUE updated. |
| W2 | win01-lab: a SACL write succeeded with `SeSecurityPrivilege` disabled in the client token | **Fixed**: K14; section 5's layer 1 is a local precondition, not a gate; layers 2 and 3 are the gate. |

### 13.1 Round 2, on `1c5ca96`

linux01-public's re-review (R2-1 to R2-7) and win01-lab's AUTH run:

| # | Finding | Handling |
|---|---|---|
| R2-1 | G1-SACL stops, with no override, on an `S:AI` empty SACL whose parent already passed ACEs down before the run; NFS creates under an audited parent are unrecorded | **Fixed**: the parent's compare-time read separates the two. A pre-run freeze is a `Write` under a `sacl:` rule and an error without one; G1 fires only when the child should have followed this run's write (3.1, 3.2, 4.4). The NFS-create state is a new open part of Q-SACL-ABSENT, with an S3 fixture item. |
| R2-2 | #88 already corrected the 700630b sentence on `main`; the blockquote contradicts it after the merge | **Fixed**: the hunk is dropped; #82 no longer touches that file. |
| R2-3 | The "will lose audit ACEs" count must include objects that lose ACEs by following | **Fixed**: defined on effective audit ACEs, written and following objects shown separately, in the dry run too (2.3); S3 checks both parts. |
| R2-4 | Step 4's "created with no SACL" holds only when the root passes nothing | **Fixed**: step 4 names which recorded path applies for each root (6). |
| R2-5 | "new ones, whether SMB- or NFS-created" goes beyond K16 | **Fixed**: 3.2 says new SMB-created ones; S8 creates new objects over SMB and NFS. |
| R2-6 | Phase 2 does read the SACL | **Fixed**: "not classified or written" (2.3). |
| R2-7 | `check` with a `sacl_set` rule now writes a probe | **Fixed**: stated as a contract change in 6, for the README status and operator docs; scenario S2b. |
| W3 | win01-lab: without the bypass, SMB SACL reads and writes are refused with error 5 and change nothing | **Fixed**: K7, K12 and Q-SACL-AUTH answered; section 5's layer 2 reads error 5 on a SACL-bit open as "no bypass"; section 6's order is kept as a safeguard; S1 notes the identity's missing privilege. |
| W4 | win01-lab and linux01-lab: R2-1's open item, NFS create under an already-audited parent | **Answered**: K18. Mode-only NFS creates match their SMB twins byte for byte and follow, so Q-SACL-ABSENT is closed and an NFS create is not a third cause of the pre-run freeze (3.2). S3's item is now a following check. |

### 13.2 Round 3, Robert's decisions on 2026-11-24

| # | Finding | Handling |
|---|---|---|
| G1 | Resume: telling a pre-run freeze from a G1-SACL failure | **Fixed**: checkpoint v2 records each directory's compare-time SACL (or its classification) before the write, and the resume uses that record (4.4, 7.1, 7.3). |
| G2 | A protected SACL with explicit ACEs under a rule with no `sacl:` key | **Fixed**: it is `Keep` (`tools/set-saclonly/README.md:57-58`; Robert's 2026-10-21 decision: keep the protection flags, change only the ACEs) (2.3, 3.2). |
| G3 | Where owner and group go in the two-write order | **Fixed**: owner and group travel in the DACL call, never alone (per #79), and `--write-order` orders that call against the SACL call (4.1, 4.2). |
| G4 | An opaque ACE type (object or callback) in the stored SACL | **Fixed**: the refusal is per part; the DACL part proceeds and only the SACL part errors (3.2, 4.5). |
| G5 | What the preflight probe writes to | **Fixed**: the probe is a throwaway object with an `EVERYONE@` placeholder audit ACE, never the root, as in `internal/auditproof` (6). |
| G6 | Where `check` records the probe | **Fixed**: `check` takes an optional `--evidence-dir`; the probe's write, read-back and removal go there as a preflight shard, else to a NOTE line plus the summary JSON (6, 7.2). |
| G8 | A persistent per-child error and the checkpoint | **Fixed**: it keeps its directory incomplete, and a resume re-reads the child (PS-11) (7.1, 7.3). |
| #78 | #78 as a prerequisite | **Fixed**: #78 is cited as a prerequisite for 2.2, section 5 and the checkpoint principal table (7.1). |
| S-PAR | S-PAR's intended differences from Set-SaclOnly | **Fixed**: it excludes `sacl: []` on unprotected objects and `OWNER@`/`GROUP@` because Set-SaclOnly differs on both by design; other scenarios cover them against this design's rules (9.1, 10). |
