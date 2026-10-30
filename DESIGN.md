# permissionreset — Design

## Problem

FlashBlade customers who need to set or repair ACLs recursively across large namespaces have no purpose-built tool. Their options today:

- `chmod -R` or `chown -R` — single-threaded, single NFS connection. Days on large trees.
- `find | xargs nfs4_setfacl` — single-threaded enumerate, single-threaded apply. Same problem.
- `pchmod` (RFT) — parallel and fast (38x over `chmod`), but mode bits only. No ACL support.
- Windows Explorer "Replace all child object permissions" — single-threaded over SMB, no progress, no resume.

OneFS has PermissionRepair — a cluster-side job engine that walks /ifs locally across all nodes in parallel. We cannot match that; it has kernel-level filesystem access from every node, no network transit, no data protocol overhead. But FlashBlade customers don't have anything equivalent, and that's the gap.

## Goal

Mitigate the pain of single-threaded recursive ACL operations on FlashBlade. Fuse enumeration with directory-permission repair so the tree is read once, and apply permissions in parallel across a worker pool. Support NFSv4 ACLs and POSIX mode bits as input. SMB repair is out of scope by design: FlashBlade translates NFSv4 ACLs to NTFS security descriptors at evaluation time, so NFSv4-written ACLs are authoritative for SMB clients too, and SMB on FlashBlade has no multichannel — an NFS-side repair is the multiprotocol answer.

Not a competitor to OneFS PermissionRepair — it runs over the wire, consumes client CPU/RAM, and uses data protocols. But it turns a multi-day operation into hours, which is the bar that matters.

## Architecture

```
                          ┌─────────────────────┐
                          │   ACL Spec (YAML)    │
                          │                      │
                          │  default: {...}      │
                          │  rules:               │
                          │   - match: {...}      │
                          │     acl/mode: [...]   │
                          └──────────┬──────────┘
                                     │  spec.Load() — validated at load time
                                     │
                    ┌────────────────┴────────────────┐
                    │         permissionreset CLI          │
                    │      (cmd/permissionreset/main.go)   │
                    │                                 │
                    │  1. Load + validate spec        │
                    │  2. Select transport            │
                    │     (kernel | userspace)        │
                    │  3. Fused walk + apply           │
                    │  4. Progress, checkpoint, stats │
                    └────────┬───────────┬────────────┘
                             │           │
                    ┌────────┘           └────────┐
                    │                             │
           ┌────────┴────────┐           ┌────────┴────────┐
           │  internal/walk  │           │  internal/apply │
           │                 │           │                 │
           │  Parallel       │──paths──▶ │  Goroutine pool │
           │  top-down walk, │           │  setxattr /     │
           │  fixes each dir │           │  chmod / lchown │
           │  then reads it  │           │  per path       │
           └─────────────────┘           └─────────────────┘
                    │                             │
           ┌────────┴────────┐           ┌────────┴────────┐
           │ internal/       │           │ internal/       │
           │ transport       │           │ nfs4acl         │
           │ (kernel:        │           │ RFC 7530 ACE    │
           │  local syscalls;│           │ parse + binary  │
           │  userspace:     │           │ encode          │
           │  internal/nfs41)│           │                 │
           └─────────────────┘           └─────────────────┘
```

### Fused walk (`internal/walk`)

The walk is a parallel top-down traversal, not a separate enumerate-then-apply pipeline. Each directory is made traversable (fixed) as soon as it is discovered — even if its current mode is 000 — and then immediately read, so its children are queued as independent tasks in the same pass. There is no level-by-level barrier and no second read of the tree: the `readdir` that discovers a directory's children *is* the enumeration.

A directory is only emitted after its own fix-and-read completes, so the apply stage can never make a directory unreadable before its children have been discovered from it.

`--pfind` is the one path that keeps the historical two-phase behavior: an external enumerator (RFT's `pfind`) cannot be fused with the fix, so a pre-pass repairs directory permissions top-down and `pfind` then reads the tree a second time to enumerate. This is why `--pfind` is no longer the default — the built-in walk reads the tree once and is faster (see benchmarks/PERFORMANCE.md).

Symlinks are detected during enumeration (via `DirEntry.Type()` in the parallel walk, `Lstat` in the pfind/sequential and prepass paths) and are skipped, never followed, before reaching the apply stage.

### Apply (`internal/apply`)

A goroutine pool applies permissions in batches. Each worker stats its own path rather than the enumerator doing it, because `setxattr` invalidates the NFS attribute cache — a single serialized `lstat` in the enumerator would turn every write into a blocking round-trip and cap throughput regardless of worker count (this was a real bug found via benchmarking; see benchmarks/PERFORMANCE.md's "Optimization Journey").

Backends per protocol:
- **NFSv4 ACL**: direct `setxattr("system.nfs4_acl", ...)` with an RFC 7530 binary-encoded ACL (`internal/nfs4acl`). No subprocess, no `nfs4_setfacl`, no cgo.
- **POSIX mode bits**: `syscall.Chmod`.
- **Owner/group**: `syscall.Lchown`, gated behind `--set-owner` (uses `Lchown` so it never follows a symlink).
- **SMB DACL**: out of scope by design — NFSv4 ACLs are authoritative for SMB clients on FlashBlade (see Goal). `protocol: smb` rejected at spec load.

`--compare` (apply-time) and `--validate` (standalone pass) both decode the on-disk ACL and compare it structurally against the spec (with identity normalization for domain-casing differences from idmapd), rather than relying on writing unconditionally.

### Transports (`internal/transport`, `internal/nfs41`)

Two transports select how permissionreset reaches the target:

- **kernel** (default): operates through a local NFS mount. `TARGET` is a local path; syscalls (`setxattr`, `Chmod`, `Lchown`, `readdir`) go through the kernel's NFS client.
- **userspace** (`internal/nfs41`): a from-scratch NFSv4.1 client that talks RPC/XDR directly to a FlashBlade data VIP, without a local mount. `TARGET` is interpreted as a server-side path. Multiple TCP connections (`--connections`, default 16) each register as an independent NFSv4.1 client (a FlashBlade permits one session per client ID), each requesting session slots (`--slots`) for in-flight capacity. Includes retry with exponential backoff (`--retry-budget`, `--retry-base-delay`) and a per-COMPOUND deadline (`--rpc-timeout`).

The userspace transport rejects `--pfind`, because pfind enumerates through a mounted path that userspace does not have. `--validate` is fully supported under userspace, with `GetACLBatch` packing up to 4 PUTFH+GETATTR(ACL) pairs per COMPOUND (the FlashBlade cap, confirmed on S200 and S500R1). Measured at 133–140K checks/sec on 1.13M objects.

### Checkpoint / resume (`internal/checkpoint`)

`--checkpoint <file>` records completed directories as the walk progresses. `--resume` (with the same checkpoint file) skips subtrees whose directories are already marked complete, re-descending only to the checkpoint frontier. The checkpoint is keyed by a hash of the run's spec + target + protocol + tool version, so resuming with a different spec is rejected rather than silently applying the wrong rules.

Under the userspace transport, resuming re-resolves directory filehandles by `LOOKUP` while descending to the frontier (there is no persisted filehandle cache), so resume cost is proportional to tree depth, not tree size.

### Spec loading and validation (`internal/spec`)

`spec.Load()` parses the YAML spec and validates it fully before any traversal begins:
- `protocol` must be `posix`, `nfsv4`, or `smb`.
- POSIX modes must be valid octal.
- NFSv4 ACE lines are parsed and rejected on invalid type, flags, or permission characters.
- Glob patterns in `match.pattern` are validated.
- `match.type` must be `file` or `directory`.
- Cross-protocol fields are rejected (e.g., `acl` in a `posix` spec, `mode` in an `nfsv4` spec).
- Unknown keys at any nesting level are rejected.
- `smb` protocol requires `server` and `share`, and is always rejected post-validation — SMB repair is out of scope by design (see Goal).

A malformed spec is a fatal, immediate error — never a per-object failure discovered mid-run.

### Rule matching — replace semantics

Rules are evaluated in order; the first matching rule wins. A matching rule **replaces** the default entirely — fields are not merged field-by-field between the default and the matched rule. An omitted field in a matched rule is zero-valued, which means "do not set this property" for that object, not "fall back to the default's value." See README.md for a worked YAML example.

### Progress and stats (`internal/stats`)

Atomic counters track objects walked, fixed, applied, skipped (symlinks), and errored (broken down by walk vs. fix vs. apply phase), with a periodic progress reporter during long runs. The process exits 1 if any errors occurred in any phase, so automation can detect partial repairs from the exit code alone.

### Test tree generation (`internal/treegen`, `cmd/generate_tree`)

`generate-tree` builds large test trees directly on FlashBlade over NFS with named-principal NFSv4 ACLs, reusing `internal/nfs4acl` for encoding — no dependency on the older `generate_tree_windows.py`, which requires a domain-joined Windows client and SMB. Scales from `small` (~500 objects) to `huge` (~100M objects); 15 ACL scenarios (11 directory, 4 file) covering deny ACEs, non-canonical ordering, inherit-only, no-propagate, append-only, delegated admin, owner-with-no-ACE, protected DACLs, and mixed named/well-known principals.

## Context: OneFS PermissionRepair

For reference, not as a competitive target. OneFS PermissionRepair is a cluster-side job engine operation that walks /ifs locally across all nodes. It has structural advantages we cannot match (no network, no protocol overhead, kernel-level access). Its main limitation — uniform ACL stamp on entire subtree, no file/dir differentiation — is worth noting because our rules engine can do better there, but that's a nice-to-have, not the selling point.

Our selling point: FlashBlade customers have nothing. This gives them something.

## Implementation Language

Go. `permissionreset` and `generate-tree` are both single, statically linked binaries (`CGO_ENABLED=0`) with no runtime dependencies — no Python, no `nfs4-acl-tools`, no `nfs4_setfacl`/`smbcacls` subprocess. Permission writes go directly through `setxattr`/`Chmod`/`Lchown` syscalls (kernel transport) or a hand-written NFSv4.1 RPC/XDR client (userspace transport). An earlier Python prototype exists in `archive/python/` and is unsupported; `generate_tree_windows.py` remains in use only for generating test trees with real Windows/SMB-stamped ACLs, since it is a test-data generator, not part of the repair tool itself.

## CLI Interface

```bash
# Apply permissions from spec file
permissionreset --spec permspec.yaml /mnt/fb/data

# Dry run
permissionreset --spec permspec.yaml --dry-run /mnt/fb/data

# Tune workers and log to a file
permissionreset --spec permspec.yaml --workers 256 --log errors.log /mnt/fb/data

# Skip writes that already match (structural compare)
permissionreset --spec permspec.yaml --compare /mnt/fb/data

# Checkpoint and resume
permissionreset --spec permspec.yaml --checkpoint run.ckpt /mnt/fb/data
permissionreset --spec permspec.yaml --checkpoint run.ckpt --resume /mnt/fb/data

# Validate without applying
permissionreset --spec permspec.yaml --validate /mnt/fb/data

# Reach the server directly, no local mount
permissionreset --spec permspec.yaml --transport userspace --server 192.0.2.50 --export /fb-perms /remote/path
```

See README.md for the full flag reference.

## Dependencies

- **Runtime**: none. Single static binary.
- **Build**: Go toolchain only (no cgo).
- **Optional**: RFT (`pfind`) if `--pfind` is used for enumeration; falls back to the built-in walk otherwise. `nfs4-acl-tools` is not required — ACL encoding is native.

## Open Questions

1. **NFSv4-to-SMB rendering verification**: SMB repair itself is settled — out of scope by design, NFSv4 ACLs are authoritative for SMB clients. What remains open is verification: confirming from a Windows SMB client that NFSv4-written ACLs render and enforce as intended across the generator's scenarios.

2. **Inheritance-only mode?** OneFS PermissionRepair's `inherit` mode re-establishes the inheritance chain from a template. permissionreset could do the same: set inheritable ACEs on the root, then walk the tree and remove explicit ACEs from children, letting inheritance take over. Fewer ACE writes, but only works when inheritance is the desired model. Not implemented.

3. **`--max-ops-per-compound` is accepted but only partially enforced**: the userspace transport issues fixed two- and three-operation COMPOUNDs for apply, and 4×(PUTFH+GETATTR) batched COMPOUNDs for validate. The flag is validated but does not yet cap the validate batch size.

4. **Identity mapping for `--compare`/`--validate`**: correctness of the apply path is unaffected, but ACL comparison depends on the spec using principal forms the server's `getxattr` actually returns. See RISKS.md item 9 for the full chain.
