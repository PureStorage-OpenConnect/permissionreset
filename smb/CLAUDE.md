# smb/ — permissionreset-smb

.NET 8 solution for the SMB-native tool. Read `README.md` and
`../docs/decision-flasharray-smb-20261107.md` (sections 4–8) first.

- `src/PermissionReset.Smb.Core/` — portable logic only, no Win32: `Plan` (build-spec
  `--smb-plan` JSON, schema 2 DACL-only or schema 3 with `sacl:`, or `--sacl-plan`, schema 1; strict), `RuleSelector` (permissionreset's rule and exclude
  semantics), `GoGlob` (Go `path.Match`), `Descriptor` (managed MS-DTYP decoder), `Inheritance` and
  `Desired` (the inheritance function and three-form classifier, design 2.1 and 2.4), `Checker`
  (the top-down walk behind `check` and `apply`, over an `ITree`/`IWritableTree`, with guards G1
  and G2), `DescriptorBuilder` (the descriptor encoder a write sends), `Preflight` (apply's
  disposable probe), `FileCheckpoint` and `Evidence`.
- `src/PermissionReset.Smb/` — the `permissionreset-smb` CLI, `Win32Security` (handle-based
  descriptor reads and directory listing with backup intent, privilege enabling) and `Win32Tree`
  (the Windows `IWritableTree`, and principal lookup). Windows-only paths are guarded with
  `OperatingSystem.IsWindows()` and `[SupportedOSPlatform("windows")]`.
- `release/pack.ps1` — builds, packs and smoke-checks the release zip and `SHA256SUMS`; run by the
  `smb-windows` CI job and by `.github/workflows/release-smb.yml` on `smb-v*` tags (draft only).
  The exe is reproducible: keep the SDK pinned exactly in `global.json`, and keep the publish on
  the script's private SDK copy with multilevel lookup off. Roslyn records the runtime it ran on in
  the PDB, so a newer 8.0 patch on the machine changes the exe. Keep `ContinuousIntegrationBuild`
  on and SourceLink off too. The `smb-windows` job builds the PR head, not the merge commit,
  because the commit SHA is in the informational version. A local pack and the workflow's must
  give the same exe SHA-256 for one commit.
- `tests/PermissionReset.Smb.Tests/` — xUnit; runs on Linux too (`dotnet test`). The CLI's records
  and exit codes are tested through a fake `IDescriptorReader`; the Win32 reads are checked on
  hardware only. `CheckerTests.FakeTree` is writable and models the array's measured inheritance
  (F1-F3: an inherited part follows its parent only while it matches what the parent passed down;
  F5: a DACL write stores `D:AI` set when unprotected, clear when protected);
  keep it in step with what hardware shows.

Rules:
- Phase 1 (`check`) is qualified read-only at `700630b` (`benchmarks/qual-smb-check-700630b-20261116/`).
  Phase 2 (`apply`, DACL writes, `DESIGN-write-path.md` section 10) is qualified on FlashArray at
  `e834ac8` (`benchmarks/qual-smb-apply-e834ac8-20261119/`; A7b, the missing-audit-bypass refusal, unverified).
  `smb-v0.1.0` is released (tag on `959c505`), qualified with a run at `2e0ad61` and targeted
  reruns at `959c505` and on the released exe (`README.md` status). A change to the write path
  after `959c505` needs its own hardware run before the next `smb-v*` tag. Every
  write goes through G1 and G2 (section 5); never add a path that writes without them, and never add
  an override for either. SACL writes are phase 3: `apply` refuses plans with `sacl:` until then.
- `Inheritance.Inherit`'s table test is the prediction the Q-INH hardware run checks. If the array
  disagrees, change the function and the table together, and record why.
- Never parse YAML here. Spec meaning lives in Go (`internal/saclplan`); extend the plan schema
  there (`SchemaSMB` for this tool; schema 1 stays Set-SaclOnly's), and match it in `Plan`.
- `GoGlob` and `RuleSelector` must stay equivalent to `tools/set-saclonly/SaclOnly.cs` and to
  `internal/spec`; both are tested against the shared vectors, so change the vectors, not one side.
- Verification reads raw descriptors only. Do not normalize, canonicalize or SDDL-round-trip what
  the array returned.
- `TreatWarningsAsErrors` is on; keep it.
