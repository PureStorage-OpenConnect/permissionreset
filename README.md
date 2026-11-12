# permissionreset

**Reset permissions on 100 million files in under 30 minutes, not days.**

Parallel NFSv4 ACL and permission repair for FlashBlade and FlashArray. The jobs that take days
with `chmod -R` or `find | xargs nfs4_setfacl` finish in minutes: a 110M-object tree was repaired
in 27.8 minutes ([measurements](docs/performance.md)). FlashBlade has no equivalent to OneFS
PermissionRepair; this tool fills that gap.

## Support Statement

This tool is provided under Best Efforts support by the Pure Portfolio Solutions Group, Open Source Integrations team.
For feature requests and bugs please use GitHub Issues.
We will address these as soon as we can, but there are no specific SLAs.

## Quick start

`--apply` replaces the ACL of every object under the target, and the tool has no undo. Before a real
run, follow the [getting-started guide](docs/field-preview/getting-started.md) and the
[field runbook](docs/field-preview/runbook.md): take a restorable snapshot
([snapshot runbook](docs/field-preview/snapshot-runbook.md)), check identities, and try the spec on
a small canary tree first. The outline:

```bash
# 1. Capture a spec from an approved template directory and file (outside the target)
build-spec --output spec.yaml --probe-dir /mnt/fb/scratch \
  /mnt/fb/templates/folder /mnt/fb/templates/file.txt
# 2. Dry run on a small disposable canary tree: reads no ACL and writes nothing
permissionreset --spec spec.yaml /mnt/fb/canary
# 3. Apply to the canary, then compare what is stored with the spec
permissionreset --spec spec.yaml --apply /mnt/fb/canary
permissionreset --spec spec.yaml --validate /mnt/fb/canary
```

`--validate` reporting zero mismatches means the stored ACLs match the spec. It does not show that
the spec grants the access you intended: check that as ordinary users before the full run.
`--apply` and `--validate` write and remove a small disposable probe first
([docs/live-read-contract.md](docs/live-read-contract.md)). Write a
spec by hand with [docs/spec-guide.md](docs/spec-guide.md); `examples/` holds demonstration specs,
not policies to apply as they stand. Install from a release archive or from source:
[INSTALL.md](INSTALL.md).

## Why it is fast

It is not magic or secret information. It is three clever ideas working together:

1. **One ACL, both protocols.** FlashArray and FlashBlade keep one NFSv4 ACL per object, and SMB
   clients see it as an NTFS ACL. An ACL changed from Linux over NFSv4.1 shows up in Windows over
   SMB, so the faster protocol can do the work for both.
2. **Every blade at once.** FlashBlade spreads the work across all its blades when the client opens
   many connections (`nconnect`) and keeps many requests in flight. Go goroutines make thousands of
   parallel workers cheap.
3. **Direct RPCs, nothing extra.** The userspace transport speaks NFSv4.1 to the array itself. It
   sends only the RPCs the repair needs, and folds the read and the write of a directory into one
   pass, so the kernel client's extra lookups and attribute traffic are gone.

How the walk and apply stages fit together is in [DESIGN.md](DESIGN.md).

## What's in the box

| Binary | Purpose | Docs |
|---|---|---|
| `permissionreset` | Apply, dry-run, compare, validate, checkpoint/resume, partitions | [docs/usage.md](docs/usage.md) |
| `build-spec` | Capture a spec from one template directory and one file | [docs/build-spec.md](docs/build-spec.md) |
| `sweep` | Measure transport tunables and write `permissionreset-tuning.yaml` | [docs/tuning-sweep.md](docs/tuning-sweep.md) |
| `generate-tree` | Build test trees with named-principal NFSv4 ACLs | `cmd/generate_tree/` |

## Documentation

| Document | Contents |
|---|---|
| [docs/field-preview/getting-started.md](docs/field-preview/getting-started.md) | **Start here:** template capture to verified repair, step by step |
| [docs/field-preview/](docs/field-preview/) | Operator runbooks: apply/validate procedure, snapshots, identity checklist, SACL runbook, troubleshooting |
| [docs/usage.md](docs/usage.md) | Common `permissionreset` invocations; compare, validate, checkpoint and partition behavior |
| [docs/spec-guide.md](docs/spec-guide.md) | Writing a spec file — ACE syntax, inheritance, the rules engine, audit ACEs (`--sacl`), worked examples, common mistakes |
| [docs/build-spec.md](docs/build-spec.md) | Capturing a spec from templates; the audit-bypass probe; `--sacl-plan` |
| [docs/transports.md](docs/transports.md) | `--transport kernel` vs `userspace`, userspace tunables, what each transport rejects |
| [docs/tuning-sweep.md](docs/tuning-sweep.md) | The `sweep` tool: prerequisites, trial sizing, tree reuse, sidecar format, tuning-file keys and precedence |
| [docs/performance.md](docs/performance.md) | Measured and extrapolated numbers, resource usage, throughput limits, mount recommendations |
| [docs/evidence.md](docs/evidence.md) | `--evidence-dir`: record and manifest format, profiles, measured size and overhead, failure behavior |
| [docs/partitions.md](docs/partitions.md) | `--partitions`: splitting a very large tree into disjoint subtrees, restart and coverage rules |
| [docs/NAMESPACE_SEMANTICS.md](docs/NAMESPACE_SEMANTICS.md) | Nested mounts, special files, hard links, symlinks, renames, exclude patterns |
| [docs/limitations.md](docs/limitations.md) | Technical limitations of the current implementation |
| [INSTALL.md](INSTALL.md) | Install, platforms, upgrade, downgrade, checkpoint compatibility |
| [COMPATIBILITY.md](COMPATIBILITY.md) | Tested array/client combinations |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, test and development workflow |
| [DESIGN.md](DESIGN.md), [RISKS.md](RISKS.md), [RFC-Deviations.md](RFC-Deviations.md) | Architecture, known risks, protocol deviations |

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
