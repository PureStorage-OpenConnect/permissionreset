# cmd/generate_tree

CLI wrapper for `internal/treegen`. Generates million-file test trees on
FlashBlade over NFS with named-principal NFSv4 ACLs.

## Files

- `main.go` — flag parsing, roster loading, signal handling; delegates to `treegen.RunContext`
- `main_test.go` — built-binary smoke tests (help, missing args, dry-run, bad inputs)

## Key functions

- `main()` — parses flags, loads principal roster JSON, builds `treegen.Config`, calls `treegen.RunContext`

## Flags

- `--principals` (required) — JSON roster mapping roles to `name@domain` NFSv4 principals
- `--scale` — small/medium/large/xlarge/huge; overridable with `--copies`, `--seed-files`, `--max-depth`
- `--acls-only` — re-stamp ACLs on existing tree without creating files
- `--no-acls` — create tree structure without ACL stamping
- `--dry-run` — print plan only
- `--beastmode` — auto-tune workers to `NumCPU * 3`
- `--safety-principal` — override safety ACE principal (default: running user)

## Invariants and gotchas

- Requires `idmapd` configured for the roster's domain — principal validation happens at startup via probe `setxattr`
- Group principals must carry the NFSv4 `g` flag in ACE definitions
- Writes `acl_manifest.json` recording intended ACL per path — used by sweep for tree validation
- Signal handling: SIGINT produces exit 130 with "partial tree left in place"
- The binary is `generate-tree` (hyphen), the package is `cmd/generate_tree` (underscore)

## Test patterns

- Built-binary tests via `generateTreeBinary()` with `sync.Once`
- `minimalPrincipals()` creates a valid but unresolvable roster for offline tests
- `binaryTimeout` (30s) bounds every subprocess

## Dependencies

- `internal/treegen` — all generation logic (scenarios, fan-out, ACL stamping, manifest)

## Overview (moved from root CLAUDE.md)

`generate-tree` (binary) / `cmd/generate_tree/` generates million-file test trees on FlashBlade over NFS with named-principal NFSv4 ACLs. Replaces `generate_tree_windows.py` for large scale.

#### Usage

```bash
./generate-tree /mnt/fb/bigdata_named --principals examples/principals_example_nfs.json --scale medium
./generate-tree /mnt/fb/bigdata_named --principals examples/principals_example_nfs.json --acls-only   # re-stamp existing tree
./generate-tree /mnt/fb/bigdata_named --principals examples/principals_example_nfs.json --no-acls     # tree only, no setxattr
./generate-tree /mnt/fb/bigdata_named --principals examples/principals_example_nfs.json --dry-run     # print plan
```

Scales: `small` (~500), `medium` (~5K), `large` (~40K), `xlarge` (~1M), `huge` (~100M, est. ~7 hrs), `colossal` (~1B+). Override with `--copies`, `--seed-files`, `--max-depth`.

#### Key behaviors

- Reuses `internal/nfs4acl` for ACE encoding and setxattr — no new dependencies
- Group principals carry the NFSv4 `g` flag (required for kernel group lookup)
- All files stamped explicitly — NFSv4 inheritance does not apply retroactively to existing files
- Safety ACE auto-detected from running user (`--safety-principal` to override)
- Principal validation at startup via probe setxattr (catches idmapd misconfiguration early)
- 15 scenarios (11 dir, 4 file): deny, non-canonical order, inherit-only, no-propagate, append-only, delegated admin, owner-with-no-ACE, protected DACLs, six-way principal split, mixed named+wellknown
- Writes `acl_manifest.json` recording intended ACL per path (`--manifest` for custom local path on userspace)
- Userspace transport (`--transport userspace`): `planSeedEntries()` generates seed in memory — no writable mount needed. Path resolved via `/proc/mounts` + `tuning.ServerPath`

#### NFS principal roster

`examples/principals_example_nfs.json` — maps roles to `name@domain` NFSv4 principals (fictional
`corp.example.com` accounts; replace them with real ones in your domain). Requires idmapd
configured for that domain **on the kernel transport only** — the
userspace transport sends the principal string verbatim and the array resolves it, so no client-side
ID mapping is involved, and a name this host cannot resolve is a warning rather than a refusal.
