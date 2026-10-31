# cmd/permissionreset

CLI and orchestration for the `permissionreset` binary. Parses flags, resolves tuning
defaults, and delegates to `internal/run.Run`.

## Files

- `main.go` — flag parsing, tuning lookup, signal handling, summary output, exit codes
- `bundle.go` — `--support-bundle` mode: collects spec, logs, checkpoint metadata, system facts into tar.gz with principal redaction

## Key functions

- `run()` / `runWithFlagSet()` — main entry; returns exit code so defers run before `os.Exit`
- `applyTuningDefaults()` — loads `permissionreset-tuning.yaml` beside the binary, matches by host/server/export/transport key
- `announceParams()` — renders the tuning line with `[flag, file N]` markers for operator-typed values
- `validateTuningParams()` — range + descriptor-budget check against live `RLIMIT_NOFILE`
- `targetForKernel()` — `EvalSymlinks` + `Abs` + `Stat`; rejects `/` and non-directories
- `targetForUserspace()` — lexical `filepath.Clean` only; no local syscalls on a server-side path
- `exitCodeFor()` — 0 success, 1 failure/mismatch, 2 flag parse, 3 unflushed checkpoint
- `writeSupportBundle()` / `collectBundle()` — tar.gz assembly with redaction
- `redactSpec()` — text-level rewrite preserving comments, key order, and structure; salted SHA-256 placeholders
- `tailFile()` — ring-buffer tail of error log (bounded memory regardless of file size)

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Failure, mismatch, or pre-flight refusal |
| 2 | Flag parse error |
| 3 | Repair succeeded but checkpoint is untrustworthy |

## Invariants and gotchas

- `run()` returns int, `main()` calls `os.Exit(run())` — all defers in `run()` execute
- `--apply` required to make changes; without it, defaults to dry-run
- `--cpuprofile`, `--memprofile`, `--rpc-stats` are hidden flags (empty usage string)
- Tuning file read from beside `os.Executable()`, not cwd
- `--workers` default differs by transport: 128 kernel, 1024 userspace (when tuning matched)
- Descriptor budget charges `connections` on userspace, `workers` on kernel — not both
- Support bundle never copies credential-named files, never includes checkpoint body
- Redaction is per-bundle salted — same name maps to same placeholder within one bundle but not across bundles
- Well-known NFSv4 principals (`OWNER@`, `GROUP@`, etc.) are never redacted

## Test patterns

- `runWithFlagSet()` for in-process tests; built binary via `permissionresetBinary()` for end-to-end
- `runCommand`, `executablePath`, `openMounts`, `hostname`, `getRlimit` — package-level vars swapped in tests
- `captureRunConfig()` replaces `runCommand` to inspect the `Config` that would reach `Run`
- `binaryTimeout` (60s) kills subprocess tests that regress the `/` guard
- Bundle tests use `readBundle()` to unpack and inspect tar.gz members

## Dependencies

- `internal/run` — the actual repair/validate engine
- `internal/spec` — spec loading, plan printing, exclude validation
- `internal/nfs41` — transport error sentinels (`ErrNotPureServer`, `ErrFlashArrayNotSupported`)
- `internal/tuning` — tuning file load/save, key construction, param validation
- `internal/summary` — JSON summary schema and file digest
- `internal/signals` — signal watch loop, escalation
