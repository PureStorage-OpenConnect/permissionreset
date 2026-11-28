# Plan: move permissionreset-smb from .NET 8 to .NET 10

Status: sections 3 and 4.1 are implemented on branch `smb/dotnet10` (SDK `10.0.115`, runtime
10.0.15). Sections 4.2, 4.3 and 4.4 are pending. Written against `main` at `2980615`.

Owner of the code work: the developer who takes this plan. Hardware qualification of the result
is arranged by the maintainers ([MAINTAINERS.md](../MAINTAINERS.md), section 4).

## 1. Why

- .NET 8 reached end of support on 2026-11-10. After that date it gets no security fixes.
- `permissionreset-smb.exe` is published self-contained (`smb/release/pack.ps1`), so every release
  carries the .NET runtime inside the exe. A release built today carries a runtime that is no longer
  patched. Vulnerability scanners can find a runtime inside a self-contained exe from the versions
  of its DLLs, and a conservative customer's security review rejects an end-of-life component.
- .NET 10 is the current LTS release, supported until November 2028. Confirm both dates on
  Microsoft's .NET support policy page when you start; this plan did not re-check them.
- The planned Windows GUI ([plan-smb-gui.md](plan-smb-gui.md)) is WPF on .NET 10. The CLI and the
  GUI share `PermissionReset.Smb.Core`, so they must target the same framework.

## 2. Scope

In scope: the `smb/` solution (`PermissionReset.Smb.Core`, `PermissionReset.Smb`,
`PermissionReset.Smb.Tests`), its CI job, its release workflow and its docs.

Out of scope:

- `tools/set-saclonly/`. Set-SaclOnly compiles `SaclOnly.cs` with PowerShell's `Add-Type`, which
  uses the PowerShell host's runtime, not `smb/global.json`. Its Pester CI job is not affected.
  Confirm this by a CI run; do not change it.
- The Go tools. They do not use .NET.
- New features. Keep this change a framework move only, so that a behavior difference can only come
  from the runtime.

## 3. Changes

### 3.1 Build files

| File | Now | Change to |
|---|---|---|
| `smb/global.json` | `"version": "8.0.400"`, `rollForward: latestFeature` | the first .NET 10 SDK feature band, for example `"10.0.100"`, with the same `rollForward` |
| `smb/Directory.Build.props` | `<TargetFramework>net8.0</TargetFramework>`, `<LangVersion>12</LangVersion>` | `net10.0`; `LangVersion` 14 (the .NET 10 default), or remove the element |
| `smb/tests/PermissionReset.Smb.Tests/PermissionReset.Smb.Tests.csproj` | `Microsoft.NET.Test.Sdk` 17.8.0, `xunit` 2.5.3, `xunit.runner.visualstudio` 2.5.3 | the current stable 2.x-compatible versions that support `net10.0`. Do not move to xUnit v3 in this change |

Keep `TreatWarningsAsErrors`, `AnalysisLevel latest`, `Nullable` and `Deterministic` as they are.

### 3.2 New analyzer warnings

`AnalysisLevel latest` turns on the .NET 10 analyzer rules, and `TreatWarningsAsErrors` makes each
one a build error. Expect some.

1. Fix each warning in the code.
2. Suppress a rule only when the fix would change behavior. Put the suppression in an
   `.editorconfig` under `smb/`, one rule per line, with a comment that says why.
3. Do not lower `AnalysisLevel` and do not turn off `TreatWarningsAsErrors`.

### 3.3 Runtime version in `version`

Add the runtime version to the `version` command output, so an operator, an auditor or a scanner
report can tie a binary to its runtime:

```text
permissionreset-smb 0.1.0 (.NET 10.0.x)
```

Use `System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription`. Update the CLI test
that checks `version`. This is the only output change in this plan.

### 3.4 CI and release

- `.github/workflows/ci.yml`, job `smb-windows`: `actions/setup-dotnet@v4` reads
  `global-json-file: smb/global.json`, so the SDK follows `global.json` without a workflow edit.
  Confirm on the first CI run that the job installs a 10.0 SDK.
- `.github/workflows/release-smb.yml`: same. No edit expected.
- `smb/release/pack.ps1`: `dotnet publish ... -r win-x64 --self-contained true
  -p:PublishSingleFile=true` does not name a framework, so it follows `Directory.Build.props`.
  Confirm that the smoke check still passes and record the new exe size in the PR.
- Runner image: both workflows use `windows-2022`. Keep it. That image matches the oldest target OS.

### 3.5 Docs

| File | Change |
|---|---|
| `CLAUDE.md` (line with "the SMB-native .NET 8 tool") | ".NET 10" |
| `smb/CLAUDE.md` (first line) | ".NET 10 solution" |
| `smb/README.md` ("Needs the .NET 8 SDK") | ".NET 10 SDK" |
| `smb/README.md`, Versions section | say the release carries the .NET runtime, that a release is rebuilt for each applicable .NET security release, and that `version` prints the runtime version |

Do not edit `benchmarks/qual-smb-*`. Those records name the SDK of their own candidate and stay true.

## 4. Checks

### 4.1 Offline (the PR)

1. `dotnet build smb/PermissionResetSmb.sln -c Release` has no warnings.
2. `dotnet test smb/PermissionResetSmb.sln -c Release` passes on Linux and in the `smb-windows`
   job. The test count must be the same as on `main`; report both counts.
3. The golden-file tests (`smbplan.golden.json`, `saclplan.golden.json`, `glob-vectors.json`)
   pass with no edit to the golden files. An edit to a golden file is a behavior change and is out
   of scope.
4. `smb/release/pack.ps1` runs, and its smoke check of the extracted archive passes.

### 4.2 Output identity (on the Windows VM)

The JSON output must be byte-identical between the .NET 8 build and the .NET 10 build on the same
objects. `System.Text.Json` defaults can change between major versions.

1. Build `main` (.NET 8) and the candidate (.NET 10) with `pack.ps1`.
2. Run `inspect` with both exes on the same set of paths, including one that fails with access
   denied.
3. Run `check` with both exes on the same plan and root, with `--workers 1` so the record order is
   stable.
4. Compare stdout byte for byte, and compare the stderr summary lines.

Any difference stops the change until it is explained and fixed.

### 4.3 Hardware qualification (maintainers)

The binary changes, so the read-only qualification at `700630b`
(`benchmarks/qual-smb-check-700630b-20261116/`) does not carry over to the new candidate
(MAINTAINERS.md, sections 4 and 5). Request a rerun of the `inspect` and `check` scenarios against
the exact new candidate, with its exe SHA-256. Record which earlier evidence still applies.

Until that run passes, label the state as "implementation done, qualification pending".

### 4.4 Clean server

On a Windows Server 2022 VM with no .NET installed:

1. Extract the release zip.
2. Run `permissionreset-smb version`. It must print the .NET 10 runtime version.
3. Run `inspect` on one path.

## 5. Security patch cadence after the move

The exe includes the runtime, so Windows Update and Microsoft Update never patch it.

- Each month, check the .NET 10 servicing release notes for security fixes.
- When a fix applies to code paths this tool uses (file I/O, `System.Text.Json`, P/Invoke
  marshalling, the runtime itself), rebuild with the patched SDK and publish a new patch release.
- Each release record names the .NET runtime version it carries (MAINTAINERS.md, section 5).
- The security scans in the release workflow (added by the maintainers) run on the published exe,
  not only on the source.

## 6. Done means

- The PR merges with every check in 4.1 passing, and with the 4.2 comparison recorded in the PR.
- The docs in 3.5 are updated.
- Hardware qualification (4.3) is requested with the exact candidate, and is reported as pending
  until it passes.
