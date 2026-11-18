# Design: restore ACLs byte for byte from a reference tree (#56)

| | |
|---|---|
| Date | 2026-11-16 |
| Status | **Built, not release-qualified.** Implemented in `internal/restore` (2026-11-17). FlashBlade lab runs on `fdedaf7`, `8e7667b` (which adds `replaced_since`) and `cebd265` (which prints replaced paths) passed every NFS scenario they ran (`benchmarks/restore-fb-20261117/`). The SMB check found the masks restored but the SMB INHERITED flag lost on written objects, which NFS cannot carry. Scenarios 3a (no-bypass identity; precondition unmet) and 4 (lockout) were not run. Deviations from this text are listed in section 10. |
| Issue | [#56](https://github.com/PureStorage-OpenConnect/permissionreset/issues/56) |
| Scope | A `permissionreset` mode that writes each object's raw `system.nfs4_acl` from a reference tree (a snapshot path, usually) onto the live object at the same relative path. Kernel transport, Linux, FlashBlade first. |

## 1. Problem

Undoing a repair today means the shell loop in
[snapshot-runbook.md](field-preview/snapshot-runbook.md#put-back-only-the-acls): `nfs4_getfacl` from
the snapshot, `nfs4_setfacl -S` onto the live object. On a FlashBlade check (issue #56) that loop
reported no failures, yet 421 of 673 objects came back different: `nfs4-acl-tools` drops
`ACE4_DELETE_CHILD` (`0x40`) from file ACEs, which an SMB client then sees as a different mask. The
loop's own `nfs4_getfacl` comparison cannot see the loss. It also runs two processes per object
(about 5 ms per object), which suits a canary and not a large tree. `cp -a` carries the bytes but
also copies file contents, which an ACL-only restore must not do.

## 2. Goals and non-goals

Goals:

- Write the reference's **raw `system.nfs4_acl` bytes** onto each live object at the same relative
  path. No decode, no re-encode, no text round trip.
- Never touch file contents, never follow a symlink on either side, never create or delete an
  object.
- Write only objects whose live ACL differs from the reference (section 4.3).
- Prove the audit bypass first, so the reference read sees audit entries and the write keeps them.
- Refuse objects whose bytes an NFS write would not preserve (the existing principal guards).
- Dry run, validate, checkpoint and resume, evidence, and a summary that counts every skip reason
  apart.
- Throughput close to a repair: a handful of round trips per object, in parallel.

Non-goals (for the first version):

- Owner, group and mode. `system.nfs4_acl` carries none of them, and a repair that used `owner:` or
  `group:` is not undone by this mode. The server recomputes mode bits from the ACL it stores.
- The userspace transport, `--partitions`, `--pfind`, macOS. Each is refused with a message
  (`internal/cmdflags`).
- Restoring onto a different filesystem or array than the reference came from. It is not refused,
  but it is not designed for: principal strings go through idmapd on both sides (section 4.5).
- FlashArray SMB-written data. An NFS ACL write on FlashArray flattens SMB inheritance
  (RISKS.md #11), so a restore over NFS cannot put that data back as it was. Those trees belong to
  `permissionreset-smb` (decision record, section 2).

## 3. Command shape

```bash
permissionreset --restore-from /mnt/fb/.snapshot/pre-repair/projects/target /mnt/fb/projects/target           # dry run
permissionreset --restore-from /mnt/fb/.snapshot/pre-repair/projects/target --apply \
    --checkpoint restore.ckpt --evidence-dir restore-evidence /mnt/fb/projects/target
permissionreset --restore-from /mnt/fb/.snapshot/pre-repair/projects/target --validate /mnt/fb/projects/target
```

- `--restore-from REF` replaces `--spec`; the two are mutually exclusive. `REF` and the positional
  root name the same subtree in the reference and in the live tree. Both roots are included.
- Allowed with it: `--apply`, `--validate`, `--exclude`, `--checkpoint`/`--resume`,
  `--evidence-dir`, `--workers`, `--one-filesystem`, `--quiet`,
  `--allow-audited-dacl-reset` and `--allow-audit-removal` (section 4.4), `--allow-writable-reference`
  (section 7).
- Refused with it: `--spec`, `--sacl`, `--set-owner`, `--compare` (always on, section 4.3),
  `--partitions`, `--pfind`, `--transport userspace`.
- Refused at start: `REF` and the root resolve to the same directory, or one contains the other
  (`filepath.EvalSymlinks` on both, then a prefix check). Either root is not a directory, or its
  ACL cannot be read.

## 4. Behavior

### 4.1 The paired walk

The walk descends **both trees together**, one directory pair at a time. For each pair it lists the
reference directory and the live directory, and joins the two listings by name. That gives each
child's type on both sides from READDIR, with no per-object `lstat`:

| Reference | Live | Outcome | Counted as |
|---|---|---|---|
| file | file | compare, write if different | `restored` or `same` |
| dir | dir | compare, write if different; descend | `restored` or `same` |
| any | missing | nothing; a directory's subtree is not walked | `deleted_since` |
| missing | any | nothing | `created_since` |
| symlink | any | nothing | `symlink` |
| any | symlink | nothing | `symlink` |
| file | dir | nothing | `type_changed` |
| dir | file | nothing; not descended | `type_changed` |
| excluded | | nothing | `excluded` |

Joining needs one side's names in memory. The live listing goes into a name → type map per
directory. A live directory wider than a cap (say 100,000 entries) falls back to an `lstat` per
reference child instead, so memory stays bounded (the same concern PS-11 addresses for the
repair's walk).

This replaces walking the reference alone and `lstat`-ing each live counterpart. That is one round
trip per object, against one extra READDIR per directory here, and the join also yields the
`created_since` count for free.

### 4.2 Per object

With the pair known to be the same non-symlink type:

1. Read the reference ACL (`getxattr`, raw bytes). Reading a snapshot cannot change it.
2. Run the preservation guards on those bytes (section 4.4). A refusal is an error for that object,
   with no write.
3. Read the live ACL. If it is **byte-equal** to the reference, count `same` and stop.
4. Otherwise write the reference bytes to the live object (`setxattr`, the existing
   `transport.SetACL`).

Round trips per object: two reads, plus one write where the bytes differ. The repair needs one write
and, with `--compare`, one read, so a restore should run at a similar rate. The rate is to be
measured, not assumed (section 8).

**Directories are written after their subtree, not before.** The reference ACL of a directory may
deny the running identity list or traverse rights. A repair guards against that with
`CheckTraversePreserved`, but a restore writes whatever the reference holds, so it cannot check. If
it wrote the directory first, it could lock itself out of the children it still has to restore.
The checkpoint already counts a directory's children and child directories to completion
(`RegisterDir`, `EntryDone`, `ChildDirDone`). A directory's own write hangs off that completion, so
it runs once everything under it is done, and the directory is recorded complete only after its
own write. The root is written last.

### 4.3 Compare is always on

Unlike a repair, the restore compares **bytes**, not structure. A repair compares structurally
because the bytes it writes come from the spec, and the array normalizes them. A restore writes
bytes the array itself produced on a read, so an object that already matches reads back
byte-identical. That is what `cp -a` showed on FlashBlade (675 of 675).

Compare-before-write is not an option here but the behavior, for three reasons:

- **Fewer writes.** Most objects in a typical restore were never changed, or have already
  converged on a resume.
- **No new header damage.** On FlashArray any NFS ACL write flattens SMB inheritance, even with
  identical bytes (RISKS.md #11). A blind restore would also flatten every object the repair
  refused or left alone.
- **It enables the audit check below**, which needs the live ACL anyway.

**Audit check.** If the live ACL has audit entries and the reference's has none, the object is
refused (`ErrAuditVanished`) rather than written. Two causes produce that, and neither should be
written over silently: auditing added since the snapshot, or a reference read that lost the
entries. `--allow-audit-removal` writes it anyway.

### 4.4 Guards

All are reused from the repair path, applied to the **reference** bytes, because those are what get
written:

- **Audit bypass, first.** `auditproof.Prove` on a disposable probe in the live tree, before any
  live or reference read, and a failure fails the run closed (PS-02). The snapshot is read-only, so
  the proof cannot run there. The run reports that the proof was made on the live filesystem.
- **Unmapped principals.** `checkMappedDACL` on the DACL region and `checkPreservableSACL` on the
  audit region. A principal shown as nobody, or an id at or above 1e9 (numeric or behind a name),
  refuses the object (`ErrUnmappedPrincipal`, `ErrSyntheticRangePrincipal`,
  `ErrUnpreservableAudit`). An NFS write would replace that SID (FB #52; FA
  benchmarks/sacl-unmapped-sid-20261020).
- **High ids at the run level.** A restore has no spec to scan ahead of time, so
  `ErrHighIDPrincipal`'s run-level refusal becomes the per-object guard above. `--allow-high-ids` is
  accepted for parity but does not lift a per-object refusal, because that refusal protects a SID.
- **Audited objects.** An object to be written whose live or reference ACL has audit entries is
  refused with `ErrAuditedObject` unless `--allow-audited-dacl-reset`. The reason is the same as for
  a repair: on FlashArray the write marks the SACL and DACL protected, and the kernel transport
  cannot tell the arrays apart. On FlashBlade the flag is expected on every restore of audited
  data. The flag stays the same as the repair's (section 9 decision 2).
- **Unparseable ACL** on either side: an error, with no write.

### 4.5 Identity

Raw bytes are byte-for-byte at the xattr boundary, not necessarily on the array. On the kernel
transport, the client renders each principal on read and parses it back on write through idmapd. A
restore therefore puts back the identity the array stored only when the host resolves names the
same way on both legs. In practice that means the same host and the same identity configuration as
the repair. The [identity checklist](field-preview/identity-checklist.md) applies before a restore,
as before a repair. The principal guards in 4.4 catch the failure modes that can be seen in the
bytes (nobody, synthetic-range ids). They do not catch a name that resolves to a different id
today than it did when the snapshot was taken.

### 4.6 Same path, different object

An object deleted and recreated under the same name since the snapshot gets the old object's ACL.
If the array keeps file ids across snapshots, a mismatch between the reference's and the live
object's file id identifies such an object, which would then count as `replaced_since` and stay
untouched. Section 9 decision 1 turns the check on by default if FlashBlade keeps file ids in `.snapshot`; whether it does is still open. READDIR returns the id on
both sides (`d_ino`), so the check needs no extra round trip if it holds. `transport.Dirent` does
not carry the id today and would gain a field.

### 4.7 Dry run and validate

- **Dry run** (the default without `--apply`): the paired walk and reference reads only. It reports
  `WOULD` for every pair it would compare, and every skip with its reason. It reads no live ACL: a
  dry run has no preflight, and a live read without the proven bypass can empty inherited auditing
  (PS-02). Reading the reference is safe, because a snapshot cannot change.
- **`--validate`**: the bypass proof, then every pair compared byte for byte, with no writes. Each
  mismatch is reported with a decoded diff of both sides (`describeACLMismatch`), where the diff
  covers masks and flags, so a missing `0x40` is visible. It exits non-zero on any mismatch.

### 4.8 Checkpoint, evidence, summary

- **Checkpoint:** keyed on the relative directory path, which is the same on both sides. The binding
  replaces the spec hash with a hash over `restore`, both resolved roots, the tool version and the
  effective excludes (`checkpoint.RunHash`, given a mode and no spec file). Resume skips completed
  directory pairs, as a repair does.
- **Evidence:** the existing record format, with these reasons: `OK:` restored, `SAME:`,
  `WOULD:`, and `SKIP:` with `deleted-since`, `created-since`, `symlink`, `type-changed` or
  `replaced-since`, plus `EXCLUDE:`, and `ERR:` with the guard's error. `docs/evidence.md` gains the
  reasons and a `restore` profile.
- **Summary:** every count from 4.1 apart, plus `refused` by guard, read errors and write errors. The
  JSON summary names the mode and both roots.

## 5. Where the code goes

`internal/run` is built around a spec, from the preflight and the fused directory path down to
validate, and threading a second source of truth through it would touch most of its 1,700 lines.
The restore gets its own driver and shares the parts that are not spec-shaped:

| Piece | Reused | New |
|---|---|---|
| `internal/restore` | | The driver: the paired walk, per-object compare and write, post-order directory writes, and counts |
| `internal/walk` | Its worker pool and descriptor-exhaustion handling | A paired variant that lists two directories per step |
| `internal/transport` (kernel) | `ReadDir`, `GetACL`, `SetACL` | Nothing |
| `internal/apply` | `checkMappedDACL`, `checkPreservableSACL`, `ErrAuditedObject`, `describeACLMismatch`, `ProveAuditBypass` | Exported wrappers where needed; `ErrAuditVanished` |
| `internal/checkpoint` | Directory completion | `RunHash` for a mode without a spec file |
| `internal/evidence`, `internal/summary`, `internal/stats` | Sinks and rendering | Restore reasons and counts |
| `cmd/permissionreset` | Flag parsing, signals, exit codes | `--restore-from`, its exclusions, and dispatch to `internal/restore` |
| `internal/cmdflags` | Platform refusals | `--restore-from` needs the kernel transport on Linux |

Tests are offline, like the rest of the suite. Two tmpdir trees stand in for reference and live, and
a fake transport scripts ACL bytes, so `0x40` on file ACEs, audit regions, nobody and high-id
principals, read and write failures can be set up without a mount. One test per row of the table in
4.1, and one per guard. A post-order test checks that a directory denying traverse is written only
after its children, and a resume test interrupts mid-tree. A byte-fidelity test restores an ACL
carrying `DELETE_CHILD` on a file ACE, which is the issue's case.

## 6. Runbook change

Once the mode qualifies, `snapshot-runbook.md` "Put back only the ACLs" becomes a `--validate`,
`--apply`, `--validate` sequence with `--restore-from`. The shell loop stays only as a fallback for
hosts without the binary, with its `DELETE_CHILD` warning.

## 7. Risks

- **Restoring the wrong way round.** The bytes go from `REF` to the root. A swapped command writes
  live ACLs into a reference. A snapshot is read-only, so that fails at the first write. Any other
  reference tree would be overwritten. The dry run names both roots and the direction, and the
  containment check catches overlapping roots. `--apply` refuses a writable `REF` unless
  `--allow-writable-reference` is given (section 9 decision 3).
- **Path swap races.** An object replaced by a symlink between READDIR and the write is followed by
  `setxattr`, as it is in a repair today. The window is the same, and so is the exposure.
- **Hard links.** A file with several links is written once per path, with the same bytes. Harmless.
- **ACL size.** `GetACL` already grows its buffer on `ERANGE`, so large ACLs are read whole.

## 8. Qualification (before any release that includes it)

A new ACL write path, so MAINTAINERS.md section 4 applies: hardware qualification on the exact
candidate. FlashBlade, kernel NFSv4.1, as the identity that ran the repair with the audit bypass:

1. **Issue #56's case.** Repair a subtree with the candidate, then restore it from the pre-repair
   snapshot. Pass: every object present on both sides matches the snapshot as raw
   `system.nfs4_acl` bytes, file ACEs with `0x40` included, audit entries included. Then check the
   affected file masks from an SMB client.
2. **Every row of 4.1** on a fixture built for it: deleted, created, now a symlink, was a symlink,
   type changed, excluded, and the same name recreated (with the answer to section 9's open question).
3. **Guards:** an identity without the bypass is refused before any read. A reference naming an
   unmapped principal, a high id, and audit entries the live side lacks or has extra.
4. **Lockout ordering:** a reference directory that denies the running identity traverse. Its
   children are restored, then it is.
5. **Resume:** kill mid-run, then resume. Pass: no object written twice where already the same,
   and a final `--validate` clean.
6. **Rate:** objects per second on a tree of at least 100,000 objects, against the shell loop's
   roughly 5 ms per object and a repair's rate on the same tree.

FlashArray is not part of the first qualification (section 2). Record it in COMPATIBILITY.md as not
qualified.

## 9. Decisions and the open question

Decided 2026-11-16 by the maintainer, as proposed:

1. **Same name, recreated object (4.6).** If FlashBlade keeps file ids in `.snapshot`, the
   `replaced_since` check is on by default. If it does not, the limit is documented in the operator
   docs and the check is left out. **Still open:** whether FlashBlade keeps them, which needs one
   read-only lab check of a snapshot, with no writes.
2. **Audited objects keep `--allow-audited-dacl-reset`**, the same flag as the repair, for parity.
   Its help text and the restore docs say why it is needed on FlashBlade too: the kernel transport
   cannot tell FlashBlade from FlashArray, where the write marks the SACL and DACL protected.
3. **A writable reference is refused under `--apply`** unless `--allow-writable-reference` is
   given. A snapshot is read-only, so the usual restore never needs the flag.
4. **The command is the `--restore-from` flag** on `permissionreset`, a mode like `--partitions`,
   not a subcommand.

## 10. As built (2026-11-17)

Where the implementation differs from the text above, and why:

- **Guards run only on an object about to be written.** Section 4.2 ran the principal guards
  before the live read. The build compares first and applies every guard only when the bytes
  differ, so a pair that already matches is never refused for what it names. Otherwise such a pair
  would be refused on every run, and its directory would never complete in the checkpoint.
- **No wide-directory fallback.** Section 4.1 proposed a name → type map with an `lstat` fallback
  above a cap. Both listings are already sorted by name (the `Transport` contract), so the build
  merge-joins them and holds no map. One directory pair in flight costs its two listings, as a
  userspace repair's walk does; the kernel repair's batched listing (PS-11) is not used here.
- **The driver has its own work stack** rather than a paired variant of `internal/walk`: listing,
  file pairs and each directory's own write are jobs on one LIFO stack served by `--workers`
  goroutines, and a directory's write is pushed when its last child finishes.
- **A failed child does not hold back its parent's write.** A directory whose listing fails is not
  written and not recorded complete, and nothing under it is touched. Its parent is still written
  once all its children are handled, failed or not, and is recorded complete in the checkpoint only
  when every child succeeded, so a resume revisits it.
- **`ErrAuditVanished` and the restore's `ErrAuditedObject`** live in `internal/restore`, with
  restore wording. The flag is the repair's `--allow-audited-dacl-reset` (decision 2).
- **Writable reference** is decided by trying a write, under `--apply` only: create an empty probe
  file in the reference root and remove it. Only EROFS counts as read-only; any other failure is
  treated as writable. The first build used `access(REF, W_OK)`, and the lab found it wrong on
  FlashBlade (Purity//FB 4.8.7, 2026-11-17): NFS ACCESS is answered from the ACL, so `access(2)`
  says a snapshot is writable, and each snapshot is its own read-write submount (`ST_RDONLY` clear),
  yet `touch` and `setxattr` on it fail EROFS. A same-bytes ACL write was rejected as the probe:
  on a reference that is in fact writable, and on FlashArray, it would flatten SMB inheritance.
- **A dry run reads no ACL on either side** (section 4.7 had it read the reference). It runs no
  proof, and it no longer probes the reference, so it cannot know the reference is a snapshot that
  is safe to read without one. It pairs the trees and reports `WOULD` per pair; `--validate` is the
  read-only comparison.
- **Flags go before TARGET.** Go's flag parsing stops at the first positional argument, so
  `--restore-from REF TARGET --validate` is refused with a message naming the stray flag. The
  examples in section 3 were corrected.
- **`replaced_since` is built and on** (section 9, question 1 answered yes on a lab FlashBlade,
  Purity//FB 4.8.7: unchanged objects keep their file id in `.snapshot`, 13/13 across two
  snapshots, and a file recreated under the same name gets a new one). The ids come from
  `getdents64` (`transport.InoLister`; `os.ReadDir` does not expose them), so the check costs no
  round trip; a mismatch is confirmed with `lstat` on both sides before the pair is skipped. A
  replaced directory is not descended. There is no flag to turn it off. Each `SKIP: replaced-since`
  line also goes to `--log`, or without it, the first 20 to stderr, capped apart from errors: the
  lab found an operator without `--evidence-dir` could not tell which objects kept their new ACL.
  The other skips stay evidence-only.
- **`--allow-high-ids` is refused** with `--restore-from`, not accepted for parity (section 4.4):
  it could lift nothing, and the lab found accepting it misleading.
