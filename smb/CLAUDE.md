# smb/ — permissionreset-smb

.NET 8 solution for the SMB-native tool. Read `README.md` and
`../docs/decision-flasharray-smb-20261107.md` (sections 4–8) first.

- `src/PermissionReset.Smb.Core/` — portable logic only, no Win32: `Plan` (build-spec
  `--smb-plan` JSON, schema 2, or `--sacl-plan`, schema 1; strict), `RuleSelector` (permissionreset's rule and exclude
  semantics), `GoGlob` (Go `path.Match`), `Descriptor` (managed MS-DTYP decoder).
- `src/PermissionReset.Smb/` — the `permissionreset-smb` CLI and `Win32Security` (handle-based
  descriptor reads with backup intent, privilege enabling). Windows-only paths are guarded with
  `OperatingSystem.IsWindows()` and `[SupportedOSPlatform("windows")]`.
- `tests/PermissionReset.Smb.Tests/` — xUnit; runs on Linux too (`dotnet test`). The CLI's records
  and exit codes are tested through a fake `IDescriptorReader`; the Win32 reads are checked on
  hardware only.

Rules:
- The tool writes nothing yet. Section 8 questions 1 and 3 are answered; the write path follows
  `DESIGN-write-path.md` once that is accepted, phase by phase (its section 8). Do not write before
  the phase that allows it, and never without G1 and G2 (its section 5).
- Never parse YAML here. Spec meaning lives in Go (`internal/saclplan`); extend the plan schema
  there (`SchemaSMB` for this tool; schema 1 stays Set-SaclOnly's), and match it in `Plan`.
- `GoGlob` and `RuleSelector` must stay equivalent to `tools/set-saclonly/SaclOnly.cs` and to
  `internal/spec`; both are tested against the shared vectors, so change the vectors, not one side.
- Verification reads raw descriptors only. Do not normalize, canonicalize or SDDL-round-trip what
  the array returned.
- `TreatWarningsAsErrors` is on; keep it.
