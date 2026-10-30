# Known Limitations

Current as of v0.1.0 (2026-08-27).

## By design

- **SMB backend is not supported.** FlashBlade translates NFSv4 ACLs to NTFS security descriptors at evaluation time, so NFSv4-written ACLs are authoritative for SMB clients. There is no need for an SMB-side repair path, and SMB on FlashBlade has no multichannel, so an SMB repair could never perform. The `protocol: smb` spec field is rejected at load time.

- **FlashArray is not supported on the userspace transport.** The `--transport=userspace` gate refuses FlashArray by design. FlashArray's one-mutating-operation-per-COMPOUND rule does not apply (it accepts batched mutations), but the gate is a product-identity check, not a capability check. Use `--transport=kernel` (the default) for FlashArray.

- **Checkpoint is bound to tool version.** Upgrading permissionreset invalidates any in-progress checkpoint. This is intentional — it prevents resuming a run that may have different behavior. Finish the current run before upgrading, or delete the checkpoint and restart.

- **Audit ACEs (SACL) are opt-in with `--sacl`.** Without it, a spec with `sacl:` is refused, and an `acl:` spec is refused only when the target root carries audit ACEs (or, under `--compare`, an object does). Audit ACEs deeper in the tree are deleted by that run, on FlashArray and FlashBlade alike. On any tree that uses auditing, always pass `--sacl`. See sacl-runbook.md.

## FlashArray audit ACEs (SACL)

- **Needs the audit bypass:** root over AUTH_SYS with root squash off, or an AD identity the array grants it. Domain Admins is not enough. The preflight refuses to start without it.
- **Kernel transport only**, because the userspace transport refuses FlashArray.
- **New objects are not protected on Purity//FA 6.10.6 and 6.11.x.** One NFSv4.1 ACL read by a user without the bypass empties an inheriting object's SACL. 6.12.1 fixed it. Rerun on a schedule until then.
- **Parent SACL edits do not reach stamped children.** Change the spec and rerun.
- **Logging needs an audit policy** on the managed directory. permissionreset cannot check this over NFS.
- **64 KB ACL size.** A very large DACL plus SACL fails that object with `E2BIG`.
- **Read-write gap.** A DACL change made between permissionreset' read and write of an object is lost. Run in a quiet window.
- **Replacing a file avoids its SACL.** A file copied and renamed over the original carries only the parent's inherited SACL.

## Partitioned runs (`-partitions`)

- **Partitions run one at a time.** Concurrent partitions are not supported. On a measured 1.1M-object tree, four partitions took the same time as one run, so partitioning buys restart granularity and smaller per-partition state, not speed.
- **Partitions are disjoint by path, not by inode.** A hard-linked file with names in two partitions is written by both, idempotently. An alias deeper than a partition root (a bind mount inside the tree) is not detected. On the userspace transport, none of the device/inode checks on partition roots run. See `docs/partitions.md`.
- **Totals after a killed run are a lower bound.** A driver killed with SIGKILL, or lost in a host crash, never records the counts of the partition it was running. The report lists that attempt under `uncounted_attempts`. Run `-validate` over the manifest for exact coverage.

## Untested

- **arm64:** cross-compiles and passes CI, but has never run on arm64 hardware.
- **sec=krb5:** identity mapping behavior may differ from `sec=sys`. All testing has been at `sec=sys`.
- **FlashArray on kernel transport:** tested only for DACL-keeping SACL specs (Purity//FA 6.10.6 and 6.12.1, up to 1.1M objects). No spec-DACL apply/validate cycle has been run against FlashArray.
- **POSIX mode on NFS mounts:** POSIX-mode repair (`protocol: posix`) is tested on local filesystems only. It should work over NFS but is not validated on FlashBlade.

## Operational constraints

- **Owner/group setting requires root or CAP_CHOWN.** The `--set-owner` flag gates `chown` calls. Without it, owner/group fields in the spec are ignored with a warning.

- **Descriptor usage scales with `--workers`.** Peak file descriptors are approximately `workers + 5`. At low `ulimit -n` values, the walk is silently truncated (see troubleshooting.md). Set `ulimit -n` to at least `workers + 10`.

- **Evidence takes space, and running out of it stops the run.** `-evidence-dir` writes about 130 bytes per object before gzip, or 250 with `-evidence-profile detailed`. Shards are gzipped by default, to about 7-8 bytes per object on a measured 1.1M-object tree; see `docs/evidence.md`. If it cannot write, the run makes no further changes. Use `-log` (errors only) for routine runs.
- **Evidence is not a crash-safe journal.** Records are buffered and synced per shard, not per object: a crash or power loss can lose the records of the last changes made. The manifest is written only at the end, so a run that never wrote one did not finish. See `docs/evidence.md`.

- **No rollback.** permissionreset modifies ACLs in place. The only undo path is restoring a FlashBlade snapshot taken before the run. Always snapshot first (see snapshot-runbook.md).
