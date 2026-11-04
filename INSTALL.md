# Installation

## build-spec

`build-spec` captures an NFSv4 ACL from one directory and one file and writes a
`permissionreset`-compatible YAML spec. It is in every release archive: the Linux and macOS
`.tar.gz` archives and the Windows `.zip` (see [Install from a release](#install-from-a-release)).

**Linux** (kernel NFSv4.1 mount):

```bash
build-spec --output project-permissions.yaml \
  --probe-dir /mnt/fb/templates/scratch \
  /mnt/fb/templates/folder /mnt/fb/templates/file.txt
```

**macOS** (userspace transport — no kernel NFS client required):

```bash
build-spec --server 192.0.2.50 --export /data \
  --auth-uid 10010 --auth-gid 10000 \
  --output project-permissions.yaml \
  --probe-dir /data/templates/scratch \
  /data/templates/folder /data/templates/file.txt
```

**Windows PowerShell** (userspace transport — from the unzipped `permissionreset_<version>_windows_amd64` directory):

```powershell
.\build-spec.exe --server 192.0.2.50 --export /data `
  --auth-uid 10010 --auth-gid 10000 `
  --output project-permissions.yaml `
  --probe-dir /data/templates/scratch `
  /data/templates/folder /data/templates/file.txt
```

`--auth-uid` and `--auth-gid` are required on Windows and macOS. On Linux with a kernel
mount they are optional (the process UID/GID is used). Pass `--output -` to write YAML to
stdout. Put every flag before the two paths: a flag after them is not parsed and the command fails.

`build-spec` never writes the exemplars, but it is not read-only. Before reading them it writes
and removes a disposable probe in `--probe-dir` (or the `--verify-write` directory) to prove the
audit bypass, and refuses without one unless `--accept-unproven-read` is given.
`--verify-write SCRATCH_DIR` also writes probes there to check the spec round-trips.

## Prerequisites

- Linux amd64/arm64, or macOS amd64/arm64
- On macOS, `--transport=userspace` is the only transport (see below)
- NFSv4.1 mount of a FlashBlade export (for NFSv4 ACL repair over `--transport=kernel`)
- No runtime dependencies — the binary is statically linked
- FlashArray audit ACEs (`--sacl`): a kernel NFSv4.1 mount of the FlashArray export (the userspace
  transport refuses FlashArray), and an identity with the array's audit bypass — root over AUTH_SYS
  with root squash off on the export, or an AD identity the array grants the bypass. Domain Admins
  membership is not enough. The preflight refuses to start without it. See
  [docs/spec-guide.md](docs/spec-guide.md#audit-aces-sacl-on-flasharray).

Building from source works on Linux and macOS; both are shipped as release archives and both are
tested in CI (`go test -race` on Linux and on a GitHub-hosted macOS runner). Only `build-spec` builds
for Windows (capture, shipped as a `.zip`); **`permissionreset`, `sweep` and `generate-tree` do not** — `internal/walk`, `internal/apply`,
`internal/nfs4acl`, `internal/transport` and `internal/treegen` use Linux syscalls that have no
Windows equivalent, and `internal/platform` carries no Windows capability file; porting them is
tracked as a follow-up. CI tests are offline: they do not show behavior on an array.

The kernel transport (`--transport=kernel`, the Linux default) reaches ACLs through
`setxattr("system.nfs4_acl", ...)` on a mounted export — a Linux NFS client feature that exists on
no other operating system. The userspace transport (`--transport=userspace`, and on macOS the only
option and the default) speaks NFSv4.1 straight to the array over TCP and needs no mount at all,
only `--server` and `--export`. Apple's `mount_nfs` tops out at NFSv4.0 with no minor-version
support and cannot mount a 4.1 export, which is why the userspace client is the answer on macOS
rather than a workaround.

The userspace repair path needs no mount: enumeration, the preflight ACL probe and every ACL write
go over the same direct TCP session. The two companion binaries are not there yet — `generate-tree`
writes its tree through an ordinary mounted path, and `sweep` reads its trial tree the same way, so
both still require a Linux host with the export mounted.

## Install from a release

Download the archive for your platform from the
[releases page](https://github.com/PureStorage-OpenConnect/permissionreset/releases/latest) and
unpack it. Each archive unpacks into a single top-level directory named after itself.

| Your machine | Archive | Contains |
|---|---|---|
| Linux x86-64 | `permissionreset_<version>_linux_amd64.tar.gz` | all four binaries |
| Linux ARM64 | `permissionreset_<version>_linux_arm64.tar.gz` | all four binaries |
| macOS Intel | `permissionreset_<version>_darwin_amd64.tar.gz` | all four binaries |
| macOS Apple silicon | `permissionreset_<version>_darwin_arm64.tar.gz` | all four binaries |
| Windows x86-64 | `permissionreset_<version>_windows_amd64.zip` | `build-spec.exe` only (capture, no repair) |

`uname -sm` prints which Linux or macOS row applies. For a repair you need `permissionreset` and,
to capture a template, `build-spec`; `generate-tree` and `sweep` are companion tools for test trees
and tuning. Every archive also carries `LICENSE`, `THIRD-PARTY-NOTICES`, this guide, the README and
the documents it links to (`docs/`, `examples/`, `COMPATIBILITY.md`, `RISKS.md` and others) at their
repository paths, so the links work offline, and `tools/set-saclonly/` with its own `build-spec.exe`.

```bash
# Linux amd64
curl -LO https://github.com/PureStorage-OpenConnect/permissionreset/releases/download/<version>/permissionreset_<version>_linux_amd64.tar.gz
tar xzf permissionreset_<version>_linux_amd64.tar.gz
sudo install permissionreset_<version>_linux_amd64/permissionreset /usr/local/bin/

# macOS Apple silicon
curl -LO https://github.com/PureStorage-OpenConnect/permissionreset/releases/download/<version>/permissionreset_<version>_darwin_arm64.tar.gz
tar xzf permissionreset_<version>_darwin_arm64.tar.gz
sudo install permissionreset_<version>_darwin_arm64/permissionreset /usr/local/bin/
```

macOS ships both architectures because Go emits single-architecture binaries. `SHA256SUMS` covers
all five archives.

If a tuning file is in use, keep `permissionreset-tuning.yaml` in the same directory as the binary —
`permissionreset` reads it beside `os.Executable`.

Verify the checksum:

```bash
# Linux (run beside the downloaded SHA256SUMS; prints OK for the archive you have)
sha256sum --ignore-missing -c SHA256SUMS
# macOS (no sha256sum by default)
shasum -a 256 --ignore-missing -c SHA256SUMS
```

```powershell
# Windows: compare this with the windows_amd64.zip line in SHA256SUMS
(Get-FileHash .\permissionreset_<version>_windows_amd64.zip -Algorithm SHA256).Hash.ToLower()
```

Verify the version:

```bash
permissionreset -version
```

## Install from source

Requires Go 1.25.0 or later.

```bash
git clone https://github.com/PureStorage-OpenConnect/permissionreset.git
cd permissionreset
make build
# Produces: permissionreset, generate-tree, sweep, build-spec
```

For release-quality binaries with version/commit/date stamped:

```bash
make release          # dist/permissionreset_<version>_<goos>_<goarch>/ staging directories (Linux, macOS, Windows)
make release-archive  # packs each: .tar.gz for Linux and macOS, .zip for Windows
make release-smoke    # extracts each archive in a temp directory and checks it (tools/release/smoke.sh)
```

## Deploy

Copy the binary and a YAML spec to the target client:

```bash
scp permissionreset user@client:/usr/local/bin/permissionreset
scp examples/nfsv4_complex.yaml user@client:/etc/permissionreset/spec.yaml
```

If using the tuning sweeper, deploy `permissionreset-tuning.yaml` alongside the binary — it is read from the same directory as the executable.

## Upgrade

Replace the binary:

```bash
cp /usr/local/bin/permissionreset /usr/local/bin/permissionreset.prev
cp permissionreset_<version>_linux_amd64/permissionreset /usr/local/bin/permissionreset
chmod +x /usr/local/bin/permissionreset
permissionreset -version   # verify
```

### Checkpoint compatibility on upgrade

Checkpoints are bound to the tool version. Upgrading `permissionreset` invalidates any in-progress checkpoint because the version string changes the run hash. This is intentional — it prevents resuming a run that may have different behavior.

If you are mid-run with a checkpoint:

1. **Finish the run with the old binary first**, then start fresh with the new one.
2. Or **delete the checkpoint file** and restart. The new run re-enumerates from scratch.

There is no checkpoint migration path. The cost of re-enumeration is minutes, not hours — it is the apply phase that dominates runtime.

### Spec compatibility on upgrade

YAML specs are forward-compatible: a spec written for an older version works on a newer one. New fields may be added in future versions but unknown fields are rejected at load time, so a spec written for a newer version fails cleanly on an older binary rather than silently ignoring fields.

### Upgrading from v0.9.1-sacl

v0.9.1-sacl refused every NFSv4 spec with `acl:` and no `sacl:` key unless `--no-sacl` was passed.
That flag is gone: `acl:` specs run without it again, and passing `--no-sacl` is now a flag error
(exit 2). Remove it from scripts. Audit ACEs are opt-in with `--sacl`; a spec with `sacl:` is refused
without it. Specs written for v0.9.0 and earlier need no change.

Use v0.9.2-sacl or later for `build-spec` on a FlashArray exemplar with audit ACEs. v0.9.1-sacl put
the `U` entries in `acl:`, which the spec loader rejects.

### Tuning file compatibility on upgrade

`permissionreset-tuning.yaml` entries are keyed by `clients@server:export/transport`. The file is not version-bound — entries written by an older `sweep` are still read by a newer `permissionreset`. Re-sweep after an upgrade if you want to re-measure with the new binary's behavior.

## Downgrade

Replace the binary with the previous version:

```bash
cp /usr/local/bin/permissionreset.prev /usr/local/bin/permissionreset
permissionreset -version   # verify
```

Same checkpoint rules apply: a checkpoint from the newer version will not resume on the older binary. Delete and restart if needed.

## Uninstall

```bash
rm /usr/local/bin/permissionreset
rm /etc/permissionreset/spec.yaml          # if you put it there
rm /path/to/permissionreset-tuning.yaml    # if using the sweeper
rm /path/to/checkpoint.dat            # if a checkpoint exists
```

No system services, no config files outside what you placed, no daemons.
