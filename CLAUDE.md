# permissionreset

## Required maintenance covenant

Read and follow [MAINTAINERS.md](MAINTAINERS.md) before starting development, verification,
publication, or release work. It is the authoritative maintenance policy, including product
ownership, public-safe history, candidate-specific evidence, identity checks, and release gates.
Follow `CLAUDE.local.md`, when present, for environment-specific coordination; never copy its
contents into tracked files. At completion, distinguish implementation done from qualification
pending. Do not infer external or publication authorization from the existence of credentials.

Lab-specific instructions (hosts, mounts, array access rules, chat channels) live in
`CLAUDE.local.md`, which is gitignored and never published. Never copy anything from it into a
tracked file; `tools/public-scan/scan.sh` checks for that.

## Build

```bash
PATH="/usr/local/go/bin:$PATH" go build -o permissionreset ./cmd/permissionreset/
```

Produces a single static binary with zero dependencies.

`make build` builds all three binaries — `permissionreset`, `generate-tree` and `sweep` — with the
same `main.version`/`main.commit`/`main.date` ldflags. `sweep` records `main.commit` in every
tuning entry it writes, so build it through the Makefile rather than a bare `go build` whenever
the entry's provenance matters.

## Test

```bash
PATH="/usr/local/go/bin:$PATH" go test ./...
```

Unit tests cover `internal/apply`, `internal/nfs4acl`, `internal/spec`, `internal/walk`,
`internal/checkpoint`, `internal/partition`, `internal/run`, `internal/tuning` and `cmd/sweep`. Use `go test ./...` for
the current count rather than trusting a number written here — a count in prose goes stale by
construction.

The default run is offline: every test uses a local tmpdir or an injected seam (fake provisioners,
scripted trial runners) rather than a mount, an array or a real sweep, and nothing drops caches or
needs root. The exception is `cmd/sweep/scratch_live_test.go`, an environment-gated live harness
that stays skipped unless `PERMISSIONRESET_LIVE_SCRATCH` and `PERMISSIONRESET_LIVE_PRINCIPALS` are set. Full live sweeper verification remains a manual
lab exercise; `benchmarks/` holds the published summaries.

## Architecture

```
cmd/permissionreset/main.go        — CLI, orchestration, progress reporting
cmd/build_spec/               — spec capture: read one dir + one file ACL, emit permissionreset YAML
cmd/generate_tree/main.go     — Go tree generator CLI
cmd/sweep/                    — tuning sweeper: flag surface, scratch sizing, knob ladders, trials
internal/run/                  — one repair invocation, shared by permissionreset and every sweep trial
internal/tuning/               — tuning file schema, key construction, mount resolution, precedence
internal/spec/spec.go          — YAML spec loader, rule matching, validation
internal/apply/apply.go        — permission application (posix/nfsv4/smb backends)
internal/nfs4acl/nfs4acl.go    — RFC 7530 ACE parser + binary encoder + setxattr/getxattr
internal/walk/walk.go          — parallel readdir, pfind integration, pre-pass, symlink detection
internal/stats/stats.go        — atomic counters, progress reporter
internal/checkpoint/           — directory-level checkpoint for resume
internal/partition/            — partition manifests: validation, residual handoff, serial driver, state, aggregate report
internal/evidence/             — per-object evidence: bounded queue, checked sharded writes, manifest
internal/treegen/              — test tree generation: scenarios, fan-out, ACL stamping, manifest
internal/platform/             — build-tagged capability constants; the Linux()/Darwin() matrices
internal/cmdflags/             — shared flag gating (hide-and-refuse, refuse-by-value) and --auth-*
internal/speccapture/          — ACL read, identity classification, YAML spec generation for build-spec
```

Platform decisions have one canonical home: `internal/platform` owns the capability constants and
`internal/cmdflags` owns how a command refuses what this build cannot do. Do not reintroduce
scattered `runtime.GOOS` checks.

## Partitioned runs (`--partitions`)

`permissionreset --partitions m.yaml` runs a manifest of disjoint subtrees serially, each with its own
checkpoint, evidence and log under `state_dir` (`docs/partitions.md`, PS-12). An implicit `residual`
partition walks the root first and hands off each partition root (`run.Config.Handoff`, counted
apart from excludes); a root it never reaches makes the run incomplete. Slash excludes stay
anchored at the manifest root (`run.Config.ExcludeRoot`). Restart is `--resume`: completed
partitions are skipped, the rest resume their checkpoints. Concurrency is deliberately absent until
measured.

## build-spec

`build-spec` (binary) / `cmd/build_spec/` reads the NFSv4 ACL from one directory and one file and emits a `permissionreset`-compatible YAML spec. It never writes the exemplars. Before it reads them it proves the audit bypass on a disposable probe under `--probe-dir` (default: the `--verify-write` folder; `internal/auditproof`), or refuses unless `--accept-unproven-read` (PS-02). `--verify-write` and the probe are its only writes.

Audit (`U`) ACEs decide the output: none → the plain DACL spec, no `sacl:` key; any → DACL-keeping
`sacl:`-only rules (`sacl: []` for an exemplar with none), with `acl:` added only under
`--with-dacl`. `L` is dropped with a NOTE.

## SACL mode (`--sacl`)

Audit ACEs are opt-in. FlashBlade stores them over NFS too (#51), so the DACL-reset guard below is
platform-independent. Without `--sacl`, `internal/run` refuses any spec that
names `sacl:`, and an `acl:` rule (which can have no `sacl:` key) keeps each object's existing audit
ACEs (PS-04: read, then write spec DACL + those entries byte for byte). With it, an `acl:` rule with no `sacl:` key is
refused (the write would delete the object's audit ACEs), and the audit-bypass preflight and
audit-policy NOTE apply. `sweep` never sets it.

Two guards protect SMB-written FlashArray data (RISKS.md #11). A `sacl:`-only (DACL-keeping) object
whose DACL names `65534`/`nobody` is refused with `ErrUnmappedPrincipal`, and the root and the
preflight probe are checked first. An `--apply` with any `sacl:`-only rule needs
`--accept-dacl-flattening` (`ErrDACLFlattening`), because FA stores inherited ACEs it gets back
over NFS as explicit ones. A DACL-keeping object naming an id >= 1e9 (numeric or a name that resolves
to one) is refused with `ErrSyntheticRangePrincipal` (FB #52), and an apply whose spec names one is
refused with `ErrHighIDPrincipal` unless `--allow-high-ids` (FB #50; dry run and `--validate` warn). Without `--sacl`, a DACL reset keeps auditing per object rather than
refusing an audited root (#51, PS-04), but each object that carries audit ACEs is refused with
`ErrAuditedObject` unless `--allow-audited-dacl-reset`: FA marks the SACL and DACL protected
(`S:AI`→`S:P`, `D:AI`→`D:P`) on any NFS ACL write. The disposable preflight probe is exempt. An object whose ACL can't be read or parsed is not written,
and neither is one whose audit ACEs name nobody or an id >= 1e9 (`ErrUnpreservableAudit`). Check DACL fidelity from SMB, never from the NFS view
(`benchmarks/sacl-unmapped-sid-20261020/`).

### Build

```bash
PATH="/usr/local/go/bin:$PATH" go build -o build-spec ./cmd/build_spec/
```

## Go test tree generator

`generate-tree` (binary) / `cmd/generate_tree/` generates million-file test trees on FlashBlade over NFS with named-principal NFSv4 ACLs. Replaces `generate_tree_windows.py` for large scale.

### Build

```bash
PATH="/usr/local/go/bin:$PATH" go build -o generate-tree ./cmd/generate_tree/
```

### Usage

```bash
./generate-tree /mnt/fb/bigdata_named --principals examples/principals_example_nfs.json --scale medium
./generate-tree /mnt/fb/bigdata_named --principals examples/principals_example_nfs.json --acls-only   # re-stamp existing tree
./generate-tree /mnt/fb/bigdata_named --principals examples/principals_example_nfs.json --no-acls     # tree only, no setxattr
./generate-tree /mnt/fb/bigdata_named --principals examples/principals_example_nfs.json --dry-run     # print plan
```

Scales: `small` (~500), `medium` (~5K), `large` (~40K), `xlarge` (~1M), `huge` (~100M, est. ~7 hrs), `colossal` (~1B+). Override with `--copies`, `--seed-files`, `--max-depth`.

### Key behaviors

- Reuses `internal/nfs4acl` for ACE encoding and setxattr — no new dependencies
- Group principals carry the NFSv4 `g` flag (required for kernel group lookup)
- All files stamped explicitly — NFSv4 inheritance does not apply retroactively to existing files
- Safety ACE auto-detected from running user (`--safety-principal` to override)
- Principal validation at startup via probe setxattr (catches idmapd misconfiguration early)
- 15 scenarios (11 dir, 4 file): deny, non-canonical order, inherit-only, no-propagate, append-only, delegated admin, owner-with-no-ACE, protected DACLs, six-way principal split, mixed named+wellknown
- Writes `acl_manifest.json` recording intended ACL per path (`--manifest` for custom local path on userspace)
- Userspace transport (`--transport userspace`): `planSeedEntries()` generates seed in memory — no writable mount needed. Path resolved via `/proc/mounts` + `tuning.ServerPath`

### NFS principal roster

`examples/principals_example_nfs.json` — maps roles to `name@domain` NFSv4 principals (fictional
`corp.example.com` accounts; replace them with real ones in your domain). Requires idmapd
configured for that domain **on the kernel transport only** — the
userspace transport sends the principal string verbatim and the array resolves it, so no client-side
ID mapping is involved, and a name this host cannot resolve is a warning rather than a refusal.

## Tuning sweeper

`sweep` / `cmd/sweep/` measures the transport tunables against one client/server/export/transport
pair and writes the winner to `permissionreset-tuning.yaml`, which `permissionreset` then loads as defaults.
Operator-facing detail lives in `docs/tuning-sweep.md`; the essentials for working here:

### Build and run

```bash
PATH="/usr/local/go/bin:$PATH" go build -o sweep ./cmd/sweep/
./sweep --scratch /mnt/fb/sweep --server 192.0.2.50 --export /fb --transport userspace --spec examples/nfsv4_complex.yaml --principals examples/principals_example_nfs.json --scale large --regenerate-scratch
```

`--regenerate-scratch` is needed on a first run: `--reuse-scratch` defaults to true, so without it
the sweeper looks for an existing `acl_manifest.json` under `--scratch` and refuses when there is
none. Drop it on later runs to re-measure the same tree.

A kernel NFS mount is required even for a userspace sweep — tree generation goes through the POSIX
provisioner, so `--scratch` must be a directory under a mount (not the mount point, not the export
root). A kernel sweep additionally wants root, so each trial can `drop_caches` and remount; without
root it warns once and continues with warm caches.

### Tuning file location

`permissionreset-tuning.yaml` is written beside the *running* binary (`os.Executable`) and read beside
the running `permissionreset` binary. In this repo that means the repo root for both, since `make build`
puts `sweep` and `permissionreset` there. Deployments must keep the binary and the file together.

An entry is keyed `clients@server:export/transport`. Mount options are outside that identity, so
re-mounting an export with different options does not invalidate the entry — re-sweep by hand.

## Key design rules

- Direct `setxattr("system.nfs4_acl", ...)` with RFC 7530 binary encoding — no cgo, no `nfs4_setfacl` subprocess.
- Stat in apply workers, never in enumerator — setxattr invalidates NFS attr cache, serial lstat becomes a round-trip bottleneck.
- Dirs are fixed top-down by the same walk that enumerates them, so a single pass converges and the tree is read once. `--pfind` is the exception — an external enumerator cannot be fused with the fix, so it keeps the two-phase behavior.
- Spec validation at load time — bad specs fail before traversal.
- Symlinks detected at enumeration and skipped, never followed.
- The sweeper calibrates *before* generating the full tree — four-copy probe, one stock trial, copy count, tear down, generate — even though the original design text ordered it the other way. `permissionreset` has no first-N-files operation, and repeated copy-root invocations would bias userspace numbers with repeated session setup, so a throwaway probe is the only calibration that measures the command operators actually run.
- Every sweep trial goes through `internal/run` with `--compare`, `--validate` and `--pfind` forced off, so a trial is the repair and not a rehearsal of it.
