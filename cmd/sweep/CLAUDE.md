# cmd/sweep

Tuning sweeper: measures transport tunables against one client/server/export/transport
pair and writes the winner to `permissionreset-tuning.yaml`.

## Files

- `main.go` — flag parsing, orchestration, signal handling, entry persistence
- `scratch.go` — trial tree lifecycle: calibration probe, sizing, generation, reuse, growth
- `search.go` — coordinate-ascent search: knob ladders, early stopping, confirmation
- `trial.go` — single trial execution via `run.Run`, CPU sampling, trial runner, the `cacheController` interface and `noCacheControl()` (only `dropCaches` and `newCacheController` are platform-split)
- `cache_linux.go` — Linux cache control: `dropCaches` (drop_caches + MS_REMOUNT), `newCacheController`
- `cache_other.go` — non-Linux stub: `newCacheController` returns noop with warning for kernel transport
- `cache_linux_test.go` — tests for `dropCaches` (Linux-only: uses `dropCachesPath` seam and `unix.Mount`)
- `triallog.go` — JSON Lines sidecar recording every trial with metadata

## Architecture

0. **Refuse where no scratch backend can work** — `posixProvisioner` is the only backend built today and its `NeedsLocalMount()` is true, so on a build without the kernel transport (macOS) `execute()` refuses at startup with "sweep needs a kernel NFSv4.1 mount to read its trial tree". `--reuse-scratch` and `--force` do not help. **`sweep` therefore has no working macOS invocation**, even though it cross-compiles and is vetted for darwin. The refusal is keyed on the provisioner, not on `GOOS`.
1. **Resolve roots** — map `--scratch` (local mount path) and/or `--scratch-server-path` to local and server-side roots. `/proc/mounts` is read **only when `--scratch` is given**, and that path is Linux-only; `--scratch-server-path` alone never opens it. The startup refusal above exists so an operator on a mountless build never meets a `/proc/mounts` error, which names a Linux kernel path and explains nothing.
2. **Prepare scratch** — calibrate with a 4-copy probe tree, size the real tree from measured rate, generate
3. **Opening baseline** — stock-parameter trial establishing the reference rate
4. **Ladder search** — sweep each knob (connections, slots, workers, batch-size, max-ops-per-compound) independently; coordinate ascent freezes each winner before sweeping the next
5. **Confirmation** — 3 trials at the winner, median reported
6. **Closing baseline** — drift detection; >10% drift degrades confidence from "high" to "low"
7. **Persist** — upsert entry into `permissionreset-tuning.yaml` beside the binary

## Key functions

- `execute()` — main logic; returns exit code
- `prepareScratch()` — dispatches to `reuseScratch()` or `generateScratch()`
- `generateScratch()` — probe + calibrate + size copies + generate full tree
- `growScratch()` — rebuild with more copies when calibrated tree is too small for `minTrialDuration`
- `reuseScratch()` — adopt existing tree; validates manifest shape
- `newSearchPlan()` — builds ladder values per transport, filters by `RLIMIT_NOFILE`
- `runSearchPlan()` — runs all ladders, then 3 confirmation trials
- `sweepKnob()` — single knob ladder with early stopping (2 consecutive below-peak)
- `runTrialRunner.Trial()` — one `run.Run` call with cache drop, CPU sampling, path-count floor
- `persist()` — load-upsert-save with validation against live descriptor limit
- `entryFor()` — zeros kernel-irrelevant fields (connections, slots, max-ops-per-compound)

## Interfaces

- `ScratchProvisioner` — generation seam: `Probe`, `Provision`, `Inspect`, `EnumerateCount`, `Remove`, `NeedsLocalMount`
- `TrialRunner` — `Trial(ctx, params) (rate, error)`; extended by `measuringRunner` for CPU samples
- `cacheController` — `BeforeTrial(ctx)`: drops caches + remounts (Linux kernel+root), noop otherwise. Platform-split: `cache_linux.go` / `cache_other.go`

## Constants

- `minTrialDuration` = 10s — trials shorter than this are rejected
- `probeCopies` = 4 — calibration tree size
- `driftHighConfidence` = 0.10 — max acceptable baseline drift
- `clientBoundCPUPct` = 90.0 — above this, trial is marked client-bound
- `assumedGenerateOpsPerSec` = 2000 — conservative rate for file ceiling derivation

## Invariants and gotchas

- Every trial goes through `internal/run` with `--compare`, `--validate`, and `--pfind` forced off
- Kernel without root: warns once and continues with warm caches; does not refuse
- `--transport=kernel` is refused BY VALUE through `cmdflags.Gate.Value` where the build has no kernel transport; the flag itself stays visible because `userspace` works everywhere
- The four `cmdflags` `--auth-*` flags are registered here too, and `AuthFlags.Resolve` warns only under `--transport=userspace`
- Principal pre-resolution is advisory whenever the selected transport is not kernel (`LocalIdentityAuthoritative: *transportName == "kernel"`), on Linux as much as on macOS
- Separate baseline and search runners — prevents winner sample confusion
- Manifest `generated_target` must match before `Remove()` is allowed — prevents deleting foreign trees
- `--reuse-scratch` defaults true; first run needs `--regenerate-scratch`
- `--force` adopts foreign trees read-only; never combined with `--regenerate-scratch`
- Trial path-count floor: 95% of expected paths; below that, trial is failed (catches descriptor starvation)
- Interrupted sweep with no measured data: exit 130, tuning file unchanged
- Interrupted with data: saves best-so-far with `confidence=partial`
- `commit` recorded in every entry via `-ldflags`; always build through Makefile

## Test patterns

- `commandDeps` struct injects all I/O: provisioner, runner, tuning load/save, hostname, time, rlimit, mounts
- `productionDeps()` wires real implementations
- `sweepProcess` struct injects signal handling for process-level tests
- `scratch_live_test.go` — environment-gated live harness (`PERMISSIONRESET_LIVE_SCRATCH` + `PERMISSIONRESET_LIVE_PRINCIPALS`)
- Trial log tests verify JSONL structure and sequence numbering

## Dependencies

- `internal/run` — trial execution (the same `Run` operators use)
- `internal/treegen` — tree generation, manifest reading, scale definitions
- `internal/tuning` — file schema, key construction, param validation, mount resolution
- `internal/spec` — spec loading for trial configuration
- `internal/signals` — signal watch, escalation
