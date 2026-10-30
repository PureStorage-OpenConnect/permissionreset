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
