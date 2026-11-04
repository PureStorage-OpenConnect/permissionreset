# permissionreset

**Reset permissions on 100 million files in under 30 minutes, not days.**

Parallel NFSv4 ACL and permission repair for FlashBlade and FlashArray. The jobs that take days
with `chmod -R` or `find | xargs nfs4_setfacl` finish in minutes: a 110M-object tree was repaired
in 27.8 minutes. See [Performance](#performance) for the measurements.

## Support Statement

This tool is provided under Best Efforts support by the Pure Portfolio Solutions Group, Open Source Integrations team.
For feature requests and bugs please use GitHub Issues.
We will address these as soon as we can, but there are no specific SLAs.

## Quick start

`--apply` replaces the ACL of every object under the target, and the tool has no undo. Before a real
run, follow the [field runbook](docs/field-preview/runbook.md): take a restorable snapshot
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
([docs/live-read-contract.md](docs/live-read-contract.md)). Write a spec by hand with
[docs/spec-guide.md](docs/spec-guide.md); `examples/` holds demonstration specs, not policies to apply
as they stand.

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

## Documentation

| Document | Contents |
|---|---|
| [docs/spec-guide.md](docs/spec-guide.md) | Writing a spec file — ACE syntax, inheritance, the rules engine, worked examples, common mistakes |
| [docs/transports.md](docs/transports.md) | `--transport kernel` vs `userspace`, userspace tunables, what each transport rejects |
| [docs/tuning-sweep.md](docs/tuning-sweep.md) | The `sweep` tool: prerequisites, trial sizing, tree reuse, sidecar format, tuning-file keys and precedence |
| [docs/performance.md](docs/performance.md) | Measured and extrapolated numbers, resource usage, throughput limits, mount recommendations |
| [docs/limitations.md](docs/limitations.md) | Technical limitations of the current implementation |
| [docs/evidence.md](docs/evidence.md) | `--evidence-dir`: record and manifest format, profiles, measured size and overhead, failure behavior |
| [docs/partitions.md](docs/partitions.md) | `--partitions`: splitting a very large tree into disjoint subtrees, each with its own checkpoint and evidence, restart and coverage rules |
| [docs/NAMESPACE_SEMANTICS.md](docs/NAMESPACE_SEMANTICS.md) | Nested mounts, special files, hard links, symlinks, renames, exclude patterns |
| [docs/field-preview/](docs/field-preview/) | Operator runbooks: apply/validate procedure, snapshots, identity checklist, troubleshooting |
| [INSTALL.md](INSTALL.md) | Install, upgrade, downgrade, checkpoint compatibility |
| [COMPATIBILITY.md](COMPATIBILITY.md) | Tested array/client combinations |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development workflow |
| [DESIGN.md](DESIGN.md), [RISKS.md](RISKS.md), [RFC-Deviations.md](RFC-Deviations.md) | Architecture, known risks, protocol deviations |

## Problem

Recursive permission fixes on FlashBlade are painfully slow with standard tools:

- `chmod -R` / `chown -R` — single-threaded, single NFS connection. Days on large trees.
- `find | xargs nfs4_setfacl` — single-threaded enumerate, single-threaded apply. ~200 ops/sec.
- `pchmod` (RFT) — parallel and fast (38x over `chmod`), but mode bits only. No ACL support.
- Windows Explorer "Replace all child object permissions" — single-threaded over SMB, no progress.

FlashBlade has no equivalent to OneFS PermissionRepair. This tool fills that gap.

## How It Works

1. **Fix and enumerate, in one sweep**: a parallel top-down walk makes each directory traversable — even at mode 000 — then immediately reads it, queueing its children as independent tasks and streaming everything it finds to the apply stage. No level-by-level barriers, and the tree is read once rather than twice: the readdir that discovers a directory's children *is* the enumeration.
2. **Apply**: Goroutine pool applies permissions in batches via the appropriate backend. Each worker stats its own paths, so no metadata lookup is serialized in the enumerator.

A directory is emitted only after its own readdir, so the apply stage cannot make it unreadable before its children have been discovered.

`--pfind` still runs two phases, because an external enumerator cannot be fused with the fix: the pre-pass reads the tree to fix it, then `pfind` reads it again to enumerate.

### Protocol Backends

| Protocol | Backend | Status |
|----------|---------|--------|
| NFSv4 ACL | Direct `setxattr` syscall (RFC 7530 binary encoding) | Supported (apply, `--compare`, `--validate`) |
| POSIX mode bits | `syscall.Chmod` | Supported (apply, `--compare`, `--validate`) |
| Owner/group | `syscall.Lchown`, gated behind `--set-owner` | Supported |
| SMB DACL | Not needed — repair over NFSv4 | Out of scope by design: NFSv4 ACLs are authoritative for SMB clients too (see below); `protocol: smb` rejected at spec load |

### Multiprotocol (SMB)

FlashBlade is inherently multiprotocol: an NFSv4 ACL written via `setxattr` is the authoritative ACL, translated to an NTFS security descriptor at evaluation time, so it is exactly what SMB clients see and enforce. An SMB-side repair backend is deliberately not implemented — SMB on FlashBlade has no multichannel, so it could never approach NFS-side throughput, and it would set the same underlying ACL anyway. The Windows tree generator exists to prove ACL fidelity (SMB-written and NFSv4-written ACLs are equivalent), not as a repair path.

## Performance

The Go implementation applies NFSv4 ACLs via direct `setxattr` syscall — no subprocess per file. Measured throughput: 118K ops/sec (kernel transport) and 200K ops/sec (userspace transport with READDIR+SETATTR fold) on a FlashBlade S500R1 with a 12-CPU client, cold cache, on the 1.1M-object dataset — **1.70× over kernel**; this 200K figure does not carry to the 110M-object scale below. 110M-object dataset validated at 82,628 main-pass ops/sec / 65,638 overall ops/sec (27.8 min; overall includes the 343.5s pre-pass). See [benchmarks/PERFORMANCE.md](benchmarks/PERFORMANCE.md) for full detail and caveats.

## Deployment

The Go binary is a single static file with zero runtime dependencies — no Go runtime, no Python, no `nfs4-acl-tools` package. Just the binary plus a YAML spec file.

```bash
# Build
CGO_ENABLED=0 go build -o permissionreset ./cmd/permissionreset/

# Deploy — copy to any Linux box and run
scp permissionreset user@client:/usr/local/bin/
```

`make build` produces `permissionreset`, `generate-tree` and `sweep` for the host platform. Linux and macOS both build and both ship; **Windows does not build yet** and is tracked as a follow-up. There is no cgo, so `GOOS`/`GOARCH` cross-compilation is straightforward, and CI cross-builds and vets `linux/arm64`, `darwin/amd64` and `darwin/arm64` on every change. Repair over the kernel transport requires Linux (`setxattr("system.nfs4_acl", ...)` is a Linux NFS client feature); the userspace transport works on both and is the only transport on macOS. `generate-tree` and `sweep` still need a mounted export, so they remain Linux-only in practice. The offline test suite runs on Linux and macOS.

`make release` builds all three static binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64` and `darwin/arm64`; `make release-archive` packs each platform into `dist/permissionreset_<version>_<goos>_<goarch>.tar.gz`, one top-level directory per archive carrying the three binaries plus `README.md`, `LICENSE` and `INSTALL.md`. Pushing a `v*` tag runs both, computes `SHA256SUMS` and an SBOM, and publishes the archives to a GitHub release.

If a tuning file is in use, deploy `permissionreset` and `permissionreset-tuning.yaml` into the same directory — see [docs/tuning-sweep.md](docs/tuning-sweep.md).

## Usage

```bash
# Go binary (recommended) — defaults to 128 workers and the built-in parallel walk
permissionreset --spec permspec.yaml /mnt/fb/data

# Dry run
permissionreset --spec permspec.yaml --dry-run /mnt/fb/data

# With error logging, and a worker count tuned to the client
permissionreset --spec permspec.yaml --workers 256 --log errors.log /mnt/fb/data

# Add per-object evidence: gzipped record shards plus a manifest.json that says
# whether the record is complete. About 130 bytes per object before gzip and 7
# after, measured on 100-character paths (docs/evidence.md). --log alone stays small: it records only
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

`--validate` and `--compare` both support the `posix` and `nfsv4` protocols. Both decode the on-disk ACL structurally (`internal/nfs4acl.DecodeACL` + `ACLEqual`) rather than doing a raw byte comparison, so identity-casing differences introduced by idmapd no longer produce false mismatches (see [RISKS.md](RISKS.md) item 9). `smb` is not supported by either.

`--checkpoint` records completed directories as the walk progresses, keyed to a hash of spec + target + protocol + tool version + the effective exclude patterns, so resuming with a mismatched spec is rejected rather than silently applied.

`--partitions` runs the partitions one at a time. An implicit `residual` partition covers everything outside them, so every object belongs to exactly one partition. Overlapping or nested partitions are refused, and a run is reported complete only when every partition completed and the residual reached every partition root. On a 1.1M-object FlashBlade tree, four partitions ran in the same time as one run (41.6 s vs 41.7 s), so splitting buys restart granularity and smaller per-partition state, not speed. Details and what path disjointness does not prove: [docs/partitions.md](docs/partitions.md).

How the walk treats nested mounts, special files, hard links, symlinks, renames and exclude patterns is documented in [docs/NAMESPACE_SEMANTICS.md](docs/NAMESPACE_SEMANTICS.md). Transport selection and the userspace tunables are in [docs/transports.md](docs/transports.md).

## ACL Specification Format

A YAML file defines target permissions with a rules engine. First matching rule wins, and a matching rule **replaces** the default entirely — it does not merge onto it. If a rule sets only `mode`, the default's `owner` and `group` are *not* inherited; set every needed field in each rule. Cross-protocol fields are rejected (`acl` in a `posix` spec, `mode` in an `nfsv4` spec), as are unknown keys at any nesting level.

```yaml
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
    - "A:g:GROUP@:rxtncy"
    - "A::EVERYONE@:rxtncy"
rules:
  - match:
      type: directory
    acl:
      - "A:fd:OWNER@:rwaDxtTcCoy"
      - "A:fdg:GROUP@:rwaDxtTcCoy"
      - "A:fd:EVERYONE@:rxtncy"
  - match:
      type: file
    acl:
      - "A::OWNER@:rwaTcCoy"
      - "A:g:GROUP@:rncy"
      - "A::EVERYONE@:rncy"
```

Allow and Deny ACEs (in `acl:`), Audit ACEs (in `sacl:`, see below), all inheritance flags, all 14 permission bits, and arbitrary principals (`OWNER@`, `GROUP@`, `EVERYONE@`, `user@domain.com`) are supported.

### Audit ACEs (SACL)

Both FlashArray and FlashBlade (multiprotocol file systems) return audit ACEs inside the ACL permissionreset
writes. `--sacl` turns on SACL mode, and `sacl:` writes `U` (audit) ACEs with the `S`/`F` flags. A rule with `sacl:` and no
`acl:` **keeps each object's own DACL** byte for byte and replaces only its SACL, which is what a
migrated tree with per-object DACLs needs; a rule with both writes the spec's DACL and SACL. A run
needs the array's audit bypass (root over AUTH_SYS with root squash off, or an AD identity the
array grants it — Domain Admins is not enough), and a preflight refuses to start without it.
Without `--sacl`, a spec with `sacl:` is refused, and an `acl:` spec replaces each object's DACL and
keeps that object's existing audit ACEs as the NFS view shows them, on FlashArray and FlashBlade
alike (PS-04). An object whose audit ACEs cannot be kept exactly is refused, not written. With
`--sacl`, an `acl:` rule with no `sacl:` key is refused, since that write would delete the object's
audit ACEs.
Logging also needs an audit policy on the managed directory, which permissionreset cannot check. A
dry run does not read objects under a `sacl:`-only rule (a read without the bypass emptied
inheriting SACLs on lab array A, Purity//FA 6.10.6, 3/3 on 2026-10-15; the same repro did not reproduce
on 6.10.6 the next day after an unplanned controller role change, so "fixed in 6.12.1" is not
confirmed as a version-only boundary — see
[benchmarks/sacl-item7-20261016/RESULTS.md](benchmarks/sacl-item7-20261016/RESULTS.md)); use
`--validate` to check them. Measured on one
FlashArray: 1.1M objects in about a minute (18,000–20,500 objects/s, kernel transport, 64 workers);
more workers or `nconnect` do not help, the array is the limit. See
`examples/nfsv4_sacl_keep_dacl.yaml` and the
[SACL section of the spec guide](docs/spec-guide.md#audit-aces-sacl-on-flasharray), including its
limits.

**SMB-written data.** FlashArray translates each DACL principal back to a SID when the DACL is
written over NFS, and a SID with no RFC 2307 id does not survive: it reads as `65534` and comes back
as the array's local nobody account. A `sacl:`-only rule therefore refuses any object whose DACL
names an unmapped principal, and refuses the whole run if the root does. Even with every principal
mapped, FlashArray's NFS view has no inherited marker, so the write-back stores every inherited ACE
as explicit and marks the DACL protected (`D:P`). ACE order and every ACE are kept, so effective access is kept, but Windows inheritance is
not, so an apply with a `sacl:`-only rule is refused unless `--accept-dacl-flattening` is passed. Nothing is written to a
refused object. Give those principals a uidNumber/gidNumber, or add the SACL from the SMB side. For a
tree written over SMB, check DACLs from SMB after a pilot run, because the NFS view does
not show this (RISKS.md #11). `Get-Acl` is fine for SIDs and masks, but it re-sorts a canonical
DACL by SID and merges ACEs for the same SID. On FlashBlade, `Get-Acl`, `icacls` and Explorer
(all `GetNamedSecurityInfoW`) also compute `P` and inherited (`ID`) flags from the parent instead
of reporting what the array stores. Do not use them to check ACE order, ACE count, inheritance
flags or `D:P`; read the raw descriptor (`GetFileSecurityW`) for that
(`benchmarks/sacl-ps07-20261026/RESULTS.md`).

Full syntax reference, replace-vs-merge worked examples, POSIX specs, exclude patterns and common mistakes: [docs/spec-guide.md](docs/spec-guide.md). More complete specs in `examples/`.

## Tools

| File | Purpose |
|------|---------|
| `cmd/permissionreset/` | Go CLI — apply, validate, dry-run, compare, checkpoint/resume |
| `cmd/build_spec/` | Spec capture — read ACLs from one directory and one file, emit a `permissionreset` YAML spec |
| `cmd/generate_tree/` | Go test tree generator with named-principal NFSv4 ACLs |
| `cmd/sweep/` | Tuning sweeper — measures transport tunables and writes `permissionreset-tuning.yaml` |
| `archive/python/` | Archived Python implementation (unsupported) |
| `tools/monitor.sh` | Client-side system stats collector for benchmarking |

## build-spec

`build-spec` captures the NFSv4 ACLs from exactly one directory and one file and writes a
`permissionreset`-compatible YAML spec. It never writes the templates, but it does write to the
array: before reading, it writes and removes a disposable probe under `--probe-dir` to prove the
audit bypass, and `--verify-write` also writes and reads back the captured ACLs on scratch objects
to confirm round-trip fidelity.
It refuses to overwrite an existing output file.

A desktop front end is documented in [docs/build-spec-gui.md](docs/build-spec-gui.md).

The identity report on stderr shows the principal strings as read from the array; stdout carries
only YAML, and only with `--output -`. "write verification: not performed" means `--verify-write`
was not passed. It does not mean nothing was written: see the probe below.

Put every flag before the two paths. Go's flag parser stops at the first positional argument, so
a flag after the paths is not parsed and the command fails (for a trailing `--output`, with
`--output is required`).

Before it reads the exemplars, `build-spec` writes and removes one disposable probe in
`--probe-dir` (a scratch directory on the same mount; for the userspace transport a server path
inside the export) to prove the identity has the audit bypass. Without `--probe-dir` or
`--verify-write` it refuses and reads nothing. `--accept-unproven-read` skips the proof instead;
on an array where an unprivileged read empties inherited auditing, that read can change the
exemplars.

**Usage:**

```bash
# Linux (kernel NFSv4.1 mount)
build-spec --output project-permissions.yaml \
  --probe-dir /mnt/fb/templates/scratch \
  /mnt/fb/templates/folder /mnt/fb/templates/file.txt
```

```bash
# macOS / Windows — direct NFSv4.1 (userspace transport)
build-spec --server 192.0.2.50 --export /data \
  --auth-uid 10010 --auth-gid 10000 \
  --output project-permissions.yaml \
  --probe-dir /data/templates/scratch \
  /data/templates/folder /data/templates/file.txt
```

```powershell
# Windows PowerShell
.\build-spec.exe --server 192.0.2.50 --export /data `
  --auth-uid 10010 --auth-gid 10000 `
  --output project-permissions.yaml `
  --probe-dir /data/templates/scratch `
  /data/templates/folder /data/templates/file.txt
```

If the exemplars carry audit (`U`) ACEs, the spec has DACL-keeping `sacl:`-only rules (an
exemplar with none gets `sacl: []`) that run with `permissionreset --sacl`; `--with-dacl` adds the DACLs as `acl:` too. Without audit
ACEs the output is a plain DACL spec with no `sacl:` key, which runs without `--sacl`. Alarm (`L`)
ACEs are dropped with a NOTE. Capture FlashArray exemplars with the audit bypass: without it the
array returns no audit ACEs.

Pass `--output -` to write YAML to stdout. `--transport kernel|userspace` defaults to
`kernel` on Linux and `userspace` on macOS/Windows.

`build-spec --sacl-plan SPEC.yaml` is a separate mode for `tools/set-saclonly/Set-SaclOnly.ps1`, which
writes SACLs over SMB. It loads a `permissionreset` spec with the same validation `permissionreset` uses and
prints JSON on stdout: each rule's label and match, its `sacl:` lines translated to Windows audit ACEs
(flags, mask, and SID and SDDL for `EVERYONE@`, `OWNER@` and `GROUP@`), and the exclude list split
into base-name and path patterns. It reads only the spec, takes no other flag or argument, and exits
non-zero for an invalid or non-`nfsv4` spec.

### Live differential test

`tools/build-spec-differential.sh` verifies that kernel and userspace transports produce
identical specs from the same exemplars, then validates both specs with `permissionreset --validate`
against a small test tree. Run on a lab host with FlashBlade mounted; exemplars and scratch
space are on the mount.

```bash
MOUNT=/mnt/fb SERVER=192.0.2.50 EXPORT=/fb-perms tools/build-spec-differential.sh \
  /mnt/fb/template_dir \
  /mnt/fb/template_file.txt
```

## Testing

```bash
PATH="/usr/local/go/bin:$PATH" go test ./...
```

Run `grep -rc '^func Test' --include='*_test.go' .` for the current count — it changes with every commit. All packages report `ok` in a bare local run on Linux or macOS; a subset of `internal/nfs41`'s tests are named `*_live_test.go` and exercise a real FlashBlade/NFS server rather than local tmpdir fakes. CI (`.github/workflows/ci.yml`) runs `gofmt`, `go vet`, `staticcheck`, `go test -race` with a per-package coverage floor on every push and PR.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
