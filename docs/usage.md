# Using permissionreset

Common invocations of the `permissionreset` command. Before a real run, follow the
[getting-started guide](field-preview/getting-started.md) and the [field runbook](field-preview/runbook.md);
`--apply` replaces the ACL of every object under the target, and the tool has no undo.
`permissionreset --help` lists every flag.

```bash
# Defaults to 128 workers and the built-in parallel walk
permissionreset --spec permspec.yaml /mnt/fb/data

# Dry run
permissionreset --spec permspec.yaml --dry-run /mnt/fb/data

# With error logging, and a worker count tuned to the client
permissionreset --spec permspec.yaml --workers 256 --log errors.log /mnt/fb/data

# Add per-object evidence: gzipped record shards plus a manifest.json that says
# whether the record is complete. About 130 bytes per object before gzip and 7
# after, measured on 100-character paths (evidence.md). --log alone stays small: it records only
# failures. If evidence cannot be written, the run stops making changes.
permissionreset --spec permspec.yaml --log errors.log --evidence-dir evidence-run1 /mnt/fb/data

# Enumerate with pfind (RFT) instead of the built-in walk — measured ~30% slower
permissionreset --spec permspec.yaml --pfind /mnt/fb/data

# Skip writes for objects whose ACL/mode already matches the spec (structural compare)
permissionreset --spec permspec.yaml --compare /mnt/fb/data

# Validate permissions match spec after a run, without writing anything
permissionreset --spec permspec.yaml --validate /mnt/fb/data

# Skip paths: base-name glob unless it contains a slash; matched dirs are pruned
permissionreset --spec permspec.yaml --exclude .snapshot --exclude '*.tmp' /mnt/fb/data

# Reach the server directly, no local mount (userspace transport)
permissionreset --spec permspec.yaml --transport userspace --server 192.0.2.50 --export /fb-perms /remote/path

# FlashArray: add audit ACEs and keep every object's DACL (SACL mode, needs the audit bypass).
# Inherited ACEs come back explicit (RISKS.md #11); the apply needs --accept-dacl-flattening.
permissionreset --sacl --accept-dacl-flattening --spec examples/nfsv4_sacl_keep_dacl.yaml --apply /mnt/fa/data

# Checkpoint progress and resume an interrupted run
permissionreset --spec permspec.yaml --checkpoint run.ckpt /mnt/fb/data
permissionreset --spec permspec.yaml --checkpoint run.ckpt --resume /mnt/fb/data

# Very large trees: split into disjoint subtrees named in a manifest (root, spec and
# state_dir come from the manifest). Each partition gets its own checkpoint and
# evidence; --resume reruns only partitions that did not complete.
permissionreset --partitions examples/partitions/manifest.yaml               # dry run
permissionreset --partitions examples/partitions/manifest.yaml --apply
permissionreset --partitions examples/partitions/manifest.yaml --apply --resume

# Put ACLs back from a snapshot, byte for byte, only where they differ (no spec).
# Not yet hardware-qualified; see "Restore from a reference tree" below.
# Every flag goes before TARGET.
permissionreset --restore-from /mnt/fb/.snapshot/pre-repair/projects --validate /mnt/fb/projects
permissionreset --restore-from /mnt/fb/.snapshot/pre-repair/projects --apply \
    --checkpoint restore.ckpt --evidence-dir restore-evidence /mnt/fb/projects
```

## Compare and validate

`--validate` and `--compare` both support the `posix` and `nfsv4` protocols. Both decode the
on-disk ACL structurally (`internal/nfs4acl.DecodeACL` + `ACLEqual`) rather than doing a raw byte
comparison, so identity-casing differences introduced by idmapd do not produce false mismatches
(see [RISKS.md](../RISKS.md) item 9). `smb` is not supported by either.

`--validate` reporting zero mismatches means the stored ACLs match the spec. It does not show that
the spec grants the access you intended: check that as ordinary users before the full run.
`--apply` and `--validate` write and remove a small disposable probe first
([live-read-contract.md](live-read-contract.md)).

## Checkpoints

`--checkpoint` records completed directories as the walk progresses, keyed to a hash of spec +
target + protocol + tool version + the effective exclude patterns, so resuming with a mismatched
spec is rejected rather than silently applied. Growth at scale: [CHECKPOINT_SCALE.md](CHECKPOINT_SCALE.md).

## Partitions

`--partitions` runs the partitions one at a time. An implicit `residual` partition covers
everything outside them, so every object belongs to exactly one partition. Overlapping or nested
partitions are refused, and a run is reported complete only when every partition completed and the
residual reached every partition root. On a 1.1M-object FlashBlade tree, four partitions ran in the
same time as one run (41.6 s vs 41.7 s), so splitting buys restart granularity and smaller
per-partition state, not speed. Details and what path disjointness does not prove:
[partitions.md](partitions.md).

## Restore from a reference tree

`--restore-from REF TARGET` writes each object's raw `system.nfs4_acl` from `REF` (usually a
`.snapshot` path) onto the object at the same relative path under `TARGET`. It takes no spec. It
compares raw bytes and writes only where they differ, so a pair that already matches is never
rewritten. It never changes file contents, owner, group or mode, never follows a symlink, and
creates no object except two disposable probe files, each removed at once: the audit-bypass proof's
under `TARGET` (apply and validate), and, on `--apply` without `--allow-writable-reference`, the
read-only check's in the root of `REF`. Design: [design-acl-restore.md](design-acl-restore.md).

**Status: built, not release-qualified.** FlashBlade lab runs passed every NFS scenario they ran
(`benchmarks/restore-fb-20261117/`); the no-bypass identity and lockout ordering were not run. Until
it is qualified, use it on a canary subtree and check the result with `--validate` and from an
SMB client.

- **Modes.** Without `--apply` it is a dry run: it pairs the two trees, reads no ACL on either side,
  and reports `WOULD` per pair with every skip counted. `--validate` and `--apply` first prove the
  audit bypass on a disposable probe under `TARGET`, then compare every pair. `--validate` writes
  nothing and exits 1 on any mismatch, naming the first differing ACE (so a missing `0x40` shows).
- **Pairing.** Both trees are listed together. An object only in the reference (`deleted-since`),
  only in the target (`created-since`), a symlink on either side, or a changed type is skipped and
  counted apart. A directory is written after everything under it, and `TARGET` itself last, so a
  reference ACL that denies the running identity cannot lock the walk out.
- **Guards**, on objects about to be written: a reference naming nobody or an id at or above
  1000000000 is refused (the write would replace that SID). An object with audit ACEs on either side
  needs `--allow-audited-dacl-reset`, as a repair does, and on FlashBlade that flag is expected: the
  kernel transport cannot tell FlashBlade from FlashArray, where the write marks the SACL and DACL
  protected. A live ACL with audit ACEs the reference lacks is refused unless `--allow-audit-removal`.
- **Wrong way round.** `--apply` refuses a reference that accepts writes unless
  `--allow-writable-reference`. It finds out by creating and removing an empty probe file in the
  reference root: a snapshot answers EROFS. Any other failure (no permission, say) cannot tell, so
  the reference is treated as writable. The same directory, or one inside the other, is
  refused outright.
- **Allowed:** `--apply`, `--validate`, `--exclude` (matched on target paths), `--checkpoint` and
  `--resume` (with `--apply`), `--evidence-dir`, `--log`, `--json-summary`, `--workers`,
  `--one-filesystem`. **Refused:** `--spec`, `--sacl`, `--compare`, `--set-owner`, `--partitions`,
  `--pfind`, `--allow-high-ids` (no flag lifts the per-object high-id refusal), and the userspace
  transport and its flags. Linux, kernel transport only.
- **Not FlashArray SMB-written data**: an NFS write flattens its inheritance (RISKS.md #11). Use
  `permissionreset-smb` for those trees.
- **SMB inheritance is not restored on FlashBlade either.** An object the restore writes loses the
  SMB INHERITED flag on its ACEs: they read back over SMB as explicit, with the same masks and
  principals. The NFS bytes carry no such flag, so `--validate` reports these objects `SAME`. Objects
  already byte-identical are not written and keep it. One lab check, Purity//FB 4.8.7
  (`benchmarks/restore-fb-20261117/`). This is a documented limit, not a refusal: `--apply` prints
  a NOTE saying so, once per run.
- **Same name, new object.** An object deleted and recreated under the same name since the snapshot
  has a different file id, so it is skipped and counted as `replaced-since` rather than given the
  old object's ACL. A replaced directory is not descended. The ids come from READDIR, and a
  mismatch is confirmed with `lstat` on both sides before the object is skipped. FlashBlade keeps
  file ids in `.snapshot` (one lab check, Purity//FB 4.8.7). Each replaced object keeps its new ACL
  and is named on a `SKIP: replaced-since PATH` line, in `--log` or, without it, on stderr (the
  first 20, then a count), since it may need restoring by hand. The other skips (deleted, created,
  symlink, type changed, excluded) are counted on the terminal and named only in the evidence.
- **Objects created under audited directories may not restore.** On one lab FlashBlade (Purity//FB
  4.8.7), a file created over NFS in a directory whose ACL carries an inheritable audit ACE came back
  with three extra ALLOW entries naming ids that resolve to nothing, two of them at or above
  1000000000. The restore refuses such an object (`synthetic_range_principal`), since writing those
  ids back over NFS would land on different SIDs. Expect a few refusals on trees built that way; the
  array-side cause is not yet explained.

## See also

- [spec-guide.md](spec-guide.md) — writing the spec, including audit ACEs (`--sacl`)
- [transports.md](transports.md) — transport selection and the userspace tunables
- [NAMESPACE_SEMANTICS.md](NAMESPACE_SEMANTICS.md) — nested mounts, special files, hard links,
  symlinks, renames and exclude patterns
- [evidence.md](evidence.md) — `--evidence-dir` record format and overhead
- [tuning-sweep.md](tuning-sweep.md) — measuring tunables and the `permissionreset-tuning.yaml` file
