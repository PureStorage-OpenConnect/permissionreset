# build-spec desktop GUI

A desktop application front end for `build-spec`, capturing the same NFSv4 ACLs from a directory and file and emitting the same YAML spec as the CLI. The output is byte-identical to the command-line tool.

## What it is

The GUI connects to a FlashBlade export over NFSv4, browses the filesystem, marks one directory and one file, and runs the capture through the same internal code path as the CLI. Outputs match exactly — there is no transcription, no serialization difference, no GUI-specific quirks. The interface handles server connection, export discovery, filtering, and path navigation; the capture backend is reused from the CLI.

## Prerequisites

- Go 1.25.0 or later
- Wails v2.15.0 CLI: `go install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0`
- A C compiler. On macOS, Xcode Command Line Tools. On Windows, mingw-w64 — a stock
  Windows Server image has no compiler, so install MSYS2 and
  `pacman -S mingw-w64-x86_64-gcc`, then put `C:\msys64\mingw64\bin` on `PATH`.
- On Linux, the Ubuntu build packages `build-essential`, `pkg-config`, `libgtk-3-dev` and
  `libwebkit2gtk-4.0-dev`: `sudo apt-get install -y --no-install-recommends build-essential
  pkg-config libgtk-3-dev libwebkit2gtk-4.0-dev`
- Run `make gui-doctor` to verify the build environment

The frontend is static files, not a bundled JavaScript app. `gui/buildspec/wails.json` leaves its
frontend install and build hooks empty on purpose, so there is no npm install or npm build phase.
Do not add one.

## Build

```bash
make gui-buildspec
```

Produces `gui/buildspec/build/bin/buildspec.app` on macOS and `gui/buildspec/build/bin/buildspec` on Linux. To cross-compile for Windows from macOS with the WebView2 runtime embedded:

```bash
make gui-buildspec-windows
```

Output is `gui/buildspec/build/bin/buildspec.exe`. Building natively on Windows works too — run `wails build` from `gui/buildspec/` once the mingw-w64 toolchain is on `PATH`.

## Platform status

- **Native Linux**: `make gui-buildspec` was verified on 2026-09-07; it produces a stripped
  dynamically-linked x86-64 ELF executable at `gui/buildspec/build/bin/buildspec`. `make gui-doctor`
  reports the system ready.
- **Native Windows**: build, live capture, and verify-by-replay were validated on 2026-09-06. On
  2026-10-21 the SACL build (`wails build -webview2 embed`, Wails v2.16.0, Go 1.25.0) built natively
  without a C compiler, and `go test` passes in `gui/buildspec`. The SACL views were checked against the
  browser mock only; no live capture of audit ACEs has been run from the app yet.
- **Native macOS**: not validated.
- **Linux-to-Windows**: compile-only. `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...` and
  `go test -c` both succeed from `gui/buildspec`, which proves compilation only, not execution. A
  Linux-to-Windows Wails build is not release evidence. macOS-to-Windows Wails cross-build is
  untested.

## Using it

1. Start the app
2. Enter server hostname or IP, export path, and on Windows (where the userspace transport has no kernel identity), uid and gid
3. Click "Connect" — the export list is populated from the NFSv4 pseudo-root READDIR; if the server lists no exports, a free-text "Export" field appears for manual entry
4. Browse the export filesystem using the directory tree and filter box (2000 entry cap per directory, 5000 maximum)
5. Click on a directory to mark it for capture
6. Click on a file to mark it for capture
7. Click "Capture" to emit the YAML spec to stdout. To check round-trip fidelity instead, turn on "Verify by replay", click "Pick folder…" and choose a scratch directory from the same tree — the ACLs are written into two temporary probes there, read back, and the probes removed. The scratch directory must be writable by the AUTH_SYS credential and must not be either exemplar
8. Click "Save" to write the output to a file — never overwrites an existing file
9. The footer displays the equivalent CLI command

## Audit ACEs (SACL)

When either exemplar carries audit (`U`) ACEs, the capture routes them to `sacl:`, exactly as the CLI
does, and the inspector says which kind of spec it produced:

- **SACL only, DACLs kept** (the default): the rules are `sacl:` with no `acl:`, so applying the spec
  replaces each object's SACL and leaves its own DACL in place.
- **SACL and DACL**: turn on "Also write the DACL" in the footer (`--with-dacl`) before capturing. The
  rules then carry the exemplars' DACLs as `acl:` too, and applying the spec replaces every object's DACL.

Either kind is applied with `permissionreset --sacl` as an identity that has the array's audit bypass. A
DACL-keeping spec can also be applied over SMB with `tools/set-saclonly/Set-SaclOnly.ps1 -Spec`. The
switch has no effect when neither exemplar has an audit ACE, and changing it clears the last result.

"SACL plan from spec…" in the title bar is `build-spec --sacl-plan`. It opens a permissionreset spec, validates
it, and shows the JSON plan that `Set-SaclOnly.ps1 -Plan` reads, with Copy and Save. If any rule carries
`acl:` or `dacl:`, the banner names it, since Set-SaclOnly refuses such a spec. The plan reads only the spec
file, so it works without connecting.

## Windows notes

The kernel NFSv4 transport is not available on Windows; the userspace transport is the only option. Both `uid` and `gid` are required fields and have no defaults — the kernel provides the authenticated identity on Linux, but Windows must supply it explicitly.

## Limits

Directory listings are capped at 2000 entries with a filter box for navigation. The hard maximum is 5000 entries. A session expires after 15 minutes of idle time; the UI returns to the connection rail with server, export, uid and gid fields intact so the user can reconnect.

## Not in this phase

The binary is unsigned and unnotarized. On macOS, Gatekeeper will refuse to open it; right-click and choose "Open", or run `xattr -d com.apple.quarantine buildspec.app` beforehand. Developer ID signing, notarization and a DMG installer are Phase 2. On Windows, MSIX or MSI packaging and Azure Trusted Signing are also Phase 2. A frameless window is deferred.
