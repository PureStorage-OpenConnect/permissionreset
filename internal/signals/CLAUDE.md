# signals

Two-stage signal handling for graceful shutdown.

## What this package does

Implements the pattern: first signal cancels context (drain in-flight work),
second signal restores default disposition and resends (immediate exit).

## Key functions

- `Watch(sigCh, runDone, errOut, escalate)` — blocks until either a signal arrives
  or the run finishes. On first signal, prints a message and waits for a second
  signal or run completion. On second signal, calls `escalate`.
- `Escalate(sig, stop, channels...)` — stops all registered signal channels, resets
  the signal to default, and resends it to the current process. The process then
  exits with the signal's default action (e.g., SIGINT exits 130).

## Gotchas

- `Escalate` calls `signal.Stop` on all channels BEFORE `signal.Reset`. This
  ordering is required — otherwise another registered channel can swallow the
  resent signal.
- `Watch` runs in a goroutine in the CLI. It selects on the signal channel vs
  `runDone`. The CLI closes `runDone` after `Run` returns.

## Consumer

- `cmd/permissionreset/main.go` — the only caller
