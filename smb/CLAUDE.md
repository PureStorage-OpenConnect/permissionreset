# smb/ — permissionreset-smb

.NET 8 solution for the SMB-native tool. Read `README.md` and
`../docs/decision-flasharray-smb-20261107.md` (sections 4–8) first.

- `src/PermissionReset.Smb.Core/` — portable logic only, no Win32: `Plan` (build-spec
  `--sacl-plan` JSON, schema 1, strict), `RuleSelector` (permissionreset's rule and exclude
  semantics), `GoGlob` (Go `path.Match`), `Descriptor` (managed MS-DTYP decoder).
- `src/PermissionReset.Smb/` — the `permissionreset-smb` CLI and `Win32Security` (handle-based
  descriptor reads with backup intent, privilege enabling). Windows-only paths are guarded with
  `OperatingSystem.IsWindows()` and `[SupportedOSPlatform("windows")]`.
- `tests/PermissionReset.Smb.Tests/` — xUnit; runs on Linux too (`dotnet test`).

Rules:
- The tool writes nothing yet. Do not add a write path until section 8 questions 1 and 3 are
  answered on hardware; record the answers in the decision record first.
- Never parse YAML here. Spec meaning lives in Go (`internal/saclplan`); extend the plan schema
  there, bump `Schema`, and match it in `Plan.SupportedSchema`.
- `GoGlob` and `RuleSelector` must stay equivalent to `tools/set-saclonly/SaclOnly.cs` and to
  `internal/spec`; both are tested against the shared vectors, so change the vectors, not one side.
- Verification reads raw descriptors only. Do not normalize, canonicalize or SDDL-round-trip what
  the array returned.
- `TreatWarningsAsErrors` is on; keep it.
