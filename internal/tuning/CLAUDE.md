# tuning

Persisted transport tunables measured by `sweep` and loaded by `permissionreset`.

## What this package does

Manages `permissionreset-tuning.yaml` — a file written beside the binary that records
optimal transport settings (connections, slots, workers, batch-size, max-ops-per-compound)
for a specific client/server/export/transport combination.

## Key files

- `tuning.go` — `Key`, `Params`, `Entry`, file read/write, YAML unmarshaling with
  strict validation (plain base-10 integers only, no octal/hex/aliases)
- `precedence.go` — `Explicit()` (which flags were typed), `Apply()` (overlay
  tuned values on unset flags)
- `validation.go` — `ValidateParams()` with range checks and descriptor budget
- `mounts.go` — `/proc/mounts` parsing for mount-point resolution

## Key types

- `Key` — `clients@server:export/transport`. Clients are sorted/deduped by `NewKey`.
  Contains a slice so not comparable with `==` — use `Key.Equal()`.
- `Params` — per-client values (not cluster totals). Custom `UnmarshalYAML` rejects
  quoted strings, YAML aliases, octal, hex, and grouped digits.
- `Entry` — `Key` + `Params` + metadata (confidence, commit, measured-at, notes)

## Invariants

- `Key` must be built with `NewKey` — raw construction leaves clients unsorted
  and causes silent lookup misses.
- Tuning file lives beside the running binary (`os.Executable()`). Deployments
  must keep binary and tuning file together.
- Mount options are outside the key identity. Re-mounting with different options
  does not invalidate the entry — re-sweep manually.
- `DescriptorReserve` (64) is deliberately over-sized. The actual non-budgeted
  floor is 5-7 fds. Tightening it risks silent walk truncation from EMFILE
  (issue #16). `LiveDescriptorReserve()` uses the actual open fd count when
  `/proc/self/fd` is available.

## Descriptor budget

The validation checks whether the tuned value (workers on kernel, connections on
userspace) plus the descriptor reserve fits within the soft RLIMIT_NOFILE. If not,
the entry is rejected and permissionreset falls back to built-in defaults with a warning.

## Consumers

- `cmd/permissionreset/` — loads tuning file, calls `Apply` to overlay on CLI flags
- `cmd/sweep/` — writes tuning file after measuring
