# docs/

Operator-facing documentation, design documents, and field deployment materials.

## Root-level docs

| File | Audience | Content |
|---|---|---|
| `spec-guide.md` / `spec-guide.html` | Operators | Full spec-file reference: ACE syntax, inheritance, rules engine, worked examples |
| `build-spec-gui.md` | Operators | Building and using the build-spec desktop app |
| `transports.md` | Operators | `--transport kernel` vs `userspace`, userspace tunables, per-transport restrictions, platform availability and flag gating, the AUTH_SYS credential, Kerberos |
| `tuning-sweep.md` | Operators | The `sweep` tool: prerequisites, trial sizing, tree reuse, sidecar format, key precedence |
| `performance.md` | Operators | Measured and extrapolated throughput, resource usage, mount recommendations |
| `limitations.md` | Developers | Technical limitations of the current implementation |
| `CHECKPOINT_SCALE.md` | Developers | Checkpoint file growth analysis and scaling characteristics |
| `evidence.md` | Operators | `--evidence-dir`: record and manifest format, profiles, measured bytes per object and overhead, failure behavior, crash-loss window |
| `partitions.md` | Operators | `--partitions` manifests: validation, the residual partition, boundary ownership, state directory, restart semantics, what path disjointness does not prove |
| `release-acceptance.md` | Maintainers | Per-candidate release gate: offline checks (`tools/release/acceptance-offline.sh`), lab matrix, external-reader trial, evidence record |
| `live-read-contract.md` | Operators, developers | When each tool reads a live ACL and the audit-bypass proof it runs first (PS-02) |
| `NAMESPACE_SEMANTICS.md` | Developers | How path resolution and identity mapping interact across transports |
| `rfc8881-one-session-violation.md` | Developers | Analysis of the one-session-per-client-ID constraint |
| `plan-readdir-bundling.md` | Developers | Design notes on READDIR operation bundling |

`transports.md`, `tuning-sweep.md`, `performance.md` and `limitations.md` were split out of the
README in the `docs/readme-restructure` work. The README keeps the overview and links here; do not
re-inline these sections into it.

## field-preview/

Operator-facing runbooks for field deployment. Written for SEs and support engineers.

| File | Content |
|---|---|
| `getting-started.md` | Beginner journey: route, prerequisites, snapshot, template capture, canary, verification, full run, recovery |
| `runbook.md` | Step-by-step procedure: pre-flight, apply, validate, troubleshoot |
| `snapshot-runbook.md` | FlashBlade snapshot workflow for safe rollback |
| `identity-checklist.md` | Pre-run identity verification, split by transport: idmapd/sssd/nsswitch for `--transport=kernel`, array-side resolution and the AUTH_SYS credential for `--transport=userspace` |
| `sacl-runbook.md` | FlashArray audit ACEs: snapshot, preflight, canary, full run with `--sacl`, scheduled reruns pending confirmation of the 6.12.1 fix boundary |
| `known-limitations.md` | What permissionreset does not do; edge cases operators should know |
| `troubleshooting.md` | Common errors and their fixes |

## Conventions

- Operator docs go in `field-preview/`
- Public-safe design plans and reviews may live here; sensitive investigation and coordination
  material stays outside the public tree. Follow [the maintenance covenant](../MAINTAINERS.md).
- Dated investigation notes use `<topic>-YYYYMMDD.md` naming
- All docs are markdown, no external dependencies
