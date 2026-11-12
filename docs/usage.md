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

## See also

- [spec-guide.md](spec-guide.md) — writing the spec, including audit ACEs (`--sacl`)
- [transports.md](transports.md) — transport selection and the userspace tunables
- [NAMESPACE_SEMANTICS.md](NAMESPACE_SEMANTICS.md) — nested mounts, special files, hard links,
  symlinks, renames and exclude patterns
- [evidence.md](evidence.md) — `--evidence-dir` record format and overhead
- [tuning-sweep.md](tuning-sweep.md) — measuring tunables and the `permissionreset-tuning.yaml` file
