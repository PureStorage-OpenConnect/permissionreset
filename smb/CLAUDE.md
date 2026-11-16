# smb/ — permissionreset-smb

.NET 8 solution for the SMB-native tool. Read `README.md` and
`../docs/decision-flasharray-smb-20261107.md` (sections 4–8) first.

- `src/PermissionReset.Smb.Core/` — portable logic only, no Win32: `Plan` (build-spec
  `--smb-plan` JSON, schema 2, or `--sacl-plan`, schema 1; strict), `RuleSelector` (permissionreset's rule and exclude
  semantics), `GoGlob` (Go `path.Match`), `Descriptor` (managed MS-DTYP decoder), `Inheritance` and
  `Desired` (the inheritance function and three-form classifier, design 2.1 and 2.4), `Checker`
  (the read-only top-down walk behind `check`, over an `ITree`).
- `src/PermissionReset.Smb/` — the `permissionreset-smb` CLI, `Win32Security` (handle-based
  descriptor reads and directory listing with backup intent, privilege enabling) and `Win32Tree`
  (the Windows `ITree`, and principal lookup). Windows-only paths are guarded with
  `OperatingSystem.IsWindows()` and `[SupportedOSPlatform("windows")]`.
- `release/pack.ps1` — builds, packs and smoke-checks the release zip and `SHA256SUMS`; run by the
  `smb-windows` CI job and by `.github/workflows/release-smb.yml` on `smb-v*` tags (draft only).
- `tests/PermissionReset.Smb.Tests/` — xUnit; runs on Linux too (`dotnet test`). The CLI's records
  and exit codes are tested through a fake `IDescriptorReader`; the Win32 reads are checked on
  hardware only.

Rules:
- The tool writes nothing yet. Phase 1 of `DESIGN-write-path.md` (plan schema 2, `Inheritance`,
  `Desired`, `check`) is built; phase 2 (writes) waits on Q-INH, Q-EXP and Q-PROT. Do not write
  before the phase that allows it, and never without G1 and G2 (its section 5).
- `Inheritance.Inherit`'s table test is the prediction the Q-INH hardware run checks. If the array
  disagrees, change the function and the table together, and record why.
- Never parse YAML here. Spec meaning lives in Go (`internal/saclplan`); extend the plan schema
  there (`SchemaSMB` for this tool; schema 1 stays Set-SaclOnly's), and match it in `Plan`.
- `GoGlob` and `RuleSelector` must stay equivalent to `tools/set-saclonly/SaclOnly.cs` and to
  `internal/spec`; both are tested against the shared vectors, so change the vectors, not one side.
- Verification reads raw descriptors only. Do not normalize, canonicalize or SDDL-round-trip what
  the array returned.
- `TreatWarningsAsErrors` is on; keep it.
