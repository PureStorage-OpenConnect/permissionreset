# treegen

Test tree generation with named-principal NFSv4 ACLs.

## What this package does

Generates million-file test trees on FlashBlade over NFS with realistic, deliberately
non-POSIX-representable NFSv4 ACLs. Used by `cmd/generate_tree/` and `cmd/sweep/`
(scratch provisioning). Replaces the Python `generate_tree_windows.py` for NFS scale.

## Key files

- `treegen.go` — main generation logic: `Generate(ctx, Config)`, worker pool,
  file/dir creation, ACL stamping via `setxattr`
- `scenarios.go` — 15 ACL scenarios (11 dir, 4 file): deny, non-canonical order,
  inherit-only, no-propagate, append-only, delegated admin, owner-with-no-ACE,
  protected DACLs, six-way principal split, mixed named+wellknown
- `manifest.go` — `acl_manifest.json` / `.jsonl` recording intended ACL per path

## Key types

- `Config` — target path, principal roster, scale, workers, flags (acls-only, no-acls, dry-run)
- `Roster` — JSON `{"domain": "...", "roles": {"role": "name"}}` mapping roles to
  `name@domain` NFSv4 principals
- `Scale` — copies, seed files, max depth. Presets: small (~500), medium (~5K),
  large (~40K), xlarge (~1M), huge (~100M)
- `Scenario` — name, description, ACE builder function, file-vs-dir flag, owner/group roles

## Key behaviors

- Group principals carry the `g` flag via `aceG()` — required for kernel group lookup
- Safety ACE auto-detected from running user (`detectSafetyPrincipal`)
- Principal validation at startup via probe setxattr (catches idmapd misconfiguration)
- All files stamped explicitly — NFSv4 inheritance does not apply retroactively
- Writes `acl_manifest.json` (compact, for programmatic use) and
  `acl_manifest.jsonl` (streaming, one line per entry)

## Gotchas

- `Generate` needs a real NFS mount with NFSv4 ACL support and working idmapd.
  Tests use offline manifest round-trip testing only.
- `--acls-only` re-stamps an existing tree without recreating files. Useful for
  re-running with different principals.
- Scenario ACE builders take `map[string]string` (role to `who@domain`), built
  from the roster. Missing roles panic.

## Consumers

- `cmd/generate_tree/` — CLI wrapper
- `cmd/sweep/` — uses `Generate` for scratch tree provisioning
- `internal/nfs4acl` — `Encode` called for every setxattr
