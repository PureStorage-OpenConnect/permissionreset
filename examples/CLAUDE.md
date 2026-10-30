# examples/

Spec files and principal rosters used by permissionreset, generate-tree, and benchmarks.

## Spec files (YAML)

All specs are loadable by `internal/spec` and validated at parse time.

| File | Protocol | Use case |
|---|---|---|
| `nfsv4_basic.yaml` | nfsv4 | Minimal spec using only special principals (OWNER@, GROUP@, EVERYONE@) |
| `nfsv4_complex.yaml` | nfsv4 | Matches Windows-written ACE count; uses numeric IDs from CORP domain |
| `nfsv4_ediscovery.yaml` | nfsv4 | Production eDiscovery spec with named principals (arraysvc, storageadmins, etc.) |
| `nfsv4_ediscovery_test.yaml` | nfsv4 | Test variant of ediscovery using principals that resolve on the dev array |
| `nfsv4_project.yaml` | nfsv4 | Shared project directory with inheritable dir ACEs |
| `nfsv4_sacl_keep_dacl.yaml` | nfsv4 | FlashArray audit ACEs: `sacl:`-only rules that keep each object's DACL. Needs `permissionreset --sacl` and the audit bypass |
| `posix_shared.yaml` | posix | Standard shared directory (2775 dirs, 0664 files, 0775 scripts) |

## Partition manifests

`partitions/manifest.yaml` is an example `permissionreset --partitions` manifest (`docs/partitions.md`).
It lives in a subdirectory because `TestShippedExampleSpecsLoad` loads every `examples/*.yaml` as a
spec; `internal/partition`'s `TestShippedExampleManifestLoads` loads it instead.

## Principal rosters (JSON)

Used by `generate-tree` and `tools/generate_tree_windows.py` to stamp test ACLs.

| File | Domain | Transport | Notes |
|---|---|---|---|
| `principals_example.json` | CORP | Windows/SMB | Domain accounts with SIDs; for generate_tree_windows.py |
| `principals_example_nfs.json` | corp.example.com | Linux/NFS | name@domain principals; for generate-tree (Go) |
| `principals_numeric.json` | example.net | Linux/NFS | Numeric UID principals; for FSA lab testing |

## Conventions

- Spec filenames: `<protocol>_<description>.yaml`
- Principal filenames: `principals_<domain>_<transport>.json`
- Do not add `sacl: []` to the DACL examples: copied to a FlashArray run with `--sacl`, it would delete the audit ACEs
- All NFSv4 specs must produce non-POSIX-representable ACLs (otherwise the test defeats its purpose)
- Test specs (`_test.yaml`) substitute principals that resolve on the current dev environment
