# Contributing to permissionreset

Thanks for helping. Bug reports, fixes and documentation improvements are all welcome. Everyone
taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Issues

- **Bugs:** open an issue with the `permissionreset -version` output, the command, the spec and
  the error log. Replace real hostnames, addresses and account names with placeholders first.
- **Security problems** (including any apply that writes the wrong permissions): do not open an
  issue. Follow [SECURITY.md](SECURITY.md).
- **Larger changes:** open an issue to discuss the approach before writing the code.

## Prerequisites

- Go (version in `go.mod`)
- Linux for repair operations (setxattr, NFS mounts). macOS and Windows can build all binaries and run the full offline test suite — only the `sweep` cache-drop path and actual NFS repair require Linux.
- For live tests: FlashBlade with NFSv4.1 mount and idmapd configured

## Build

```bash
make build
```

Produces `permissionreset`, `generate-tree`, and `sweep` with version/commit/date ldflags.

For a quick single-binary build:

```bash
go build -o permissionreset ./cmd/permissionreset/
```

PGO is enabled by default via `cmd/permissionreset/default.pgo`. Pass `-pgo=off` to disable.

## Test

```bash
go test ./...
```

All tests run offline against local tmpdirs — no FlashBlade, no root, no network. Live tests
(gated by `PERMISSIONRESET_TEST_SERVER` and similar env vars) exist for protocol-level probing but
are not required for contribution.

CI runs `gofmt`, `go vet`, `staticcheck`, `go test -race`, and a per-package coverage floor.
Run these locally before pushing:

```bash
gofmt -l .
go vet ./...
go test -race -count=1 ./...
```

## Pull requests

- Fork the repository and open the PR against `main`.
- PRs are merged with **merge commits** (not squash), so keep each commit focused on one logical
  change. Commit messages should explain *why*, not *what*.
- CI must pass. It runs on GitHub-hosted Linux and macOS runners and needs no array.
- Add or update tests for any behavior change. Changes to what gets written to an ACL need a test
  that shows the exact ACEs before and after.
- Do not commit real lab or customer details: hostnames, IP addresses, array names, domains or
  account names. Use `example.com`, `192.0.2.0/24` and names like `alice`. CI checks for internal
  identifiers on pushes to `main`.

## Code style

- `gofmt` is enforced by CI. No exceptions.
- No comments unless the *why* is non-obvious.
- No error handling for impossible cases. Trust internal code; validate at boundaries.
- No abstractions ahead of need.

## Architecture

See `CLAUDE.md` for the full module layout. Key rules:

- Direct `setxattr("system.nfs4_acl", ...)` with RFC 7530 binary encoding — no cgo, no
  `nfs4_setfacl` subprocess.
- Stat in apply workers, never in enumerator.
- Dirs fixed top-down in the same walk that enumerates them (single fused pass).
- Spec validation at load time — bad specs fail before traversal.
- Symlinks detected at enumeration and skipped, never followed.

## Live testing

Protocol probes run against real hardware and are skipped unless their environment variables
are set. You do not need them to contribute. Point them at a non-production export:

```bash
PERMISSIONRESET_TEST_SERVER=192.0.2.50 \
PERMISSIONRESET_TEST_EXPORT=/fb-perms \
PERMISSIONRESET_TRAVERSE_DIR=/fb-perms/treegen_small \
go test ./internal/nfs41/ -run TestMultiGetATTRShapes -v -count=1
```

Take a snapshot of the file system before a live run that writes ACLs
(`docs/field-preview/snapshot-runbook.md`). `benchmarks/` holds the published summaries of lab
measurements; see `benchmarks/README.md`.

## Updating the PGO profile

After a significant change to hot paths, re-profile and merge:

```bash
# Collect profiles (userspace and kernel, on representative workload)
./permissionreset --cpuprofile=userspace.pprof --transport=userspace ...
./permissionreset --cpuprofile=kernel.pprof ...

# Merge (weight toward userspace)
go tool pprof -proto userspace.pprof kernel.pprof > cmd/permissionreset/default.pgo
```

## Security

See `SECURITY.md` for reporting vulnerabilities.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0, the
same license as the project. See `LICENSE`.
